/*
 * Copyright 2026 Julien Bombled
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::config::RuleAction;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const IPV4_VERSION: u8 = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const TCP_MIN_HEADER_LEN: usize = 20;
const IPPROTO_TCP: u8 = 6;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const SOCKET_CACHE_TTL_SECS: u64 = 30;

/// Indicates which mechanism resolved the owning PID for an outbound TCP SYN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PidResolutionSource {
    /// Resolved via a prior `WINDIVERT_LAYER_SOCKET` event.
    SocketLayer,
    /// Resolved by holding the SYN briefly and querying `GetExtendedTcpTable`.
    TcpTableFallback,
}

impl PidResolutionSource {
    /// Returns the canonical log identifier for this resolution path.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SocketLayer => "socket_layer",
            Self::TcpTableFallback => "tcp_table_fallback",
        }
    }
}

/// Active NAT redirection entry keyed by the originating client TCP port.
#[derive(Debug, Clone)]
pub struct NatSessionEntry {
    pub client_ip: Ipv4Addr,
    pub client_port: u16,
    pub orig_dst_ip: Ipv4Addr,
    pub orig_dst_port: u16,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub resolution_source: PidResolutionSource,
    pub action: RuleAction,
    pub matched_rule_name: String,
    pub created_at: Instant,
}

/// Parsed IPv4 + TCP packet header metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4TcpPacketMeta {
    pub ip_header_len: usize,
    pub total_len: usize,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
}

impl Ipv4TcpPacketMeta {
    /// Returns `true` if this packet is an initial TCP SYN (SYN set, ACK not set).
    pub fn is_syn_only(&self) -> bool {
        (self.tcp_flags & TCP_FLAG_SYN) != 0 && (self.tcp_flags & TCP_FLAG_ACK) == 0
    }

    /// Returns `true` if the FIN or RST flag is set.
    pub fn is_fin_or_rst(&self) -> bool {
        (self.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) != 0
    }
}

/// Thread-safe NAT state table and loop-prevention registry for transparent TCP redirection.
#[derive(Clone)]
pub struct TransparentNatTable {
    socket_pid_cache: Arc<DashMap<u16, (u32, Instant)>>,
    sessions: Arc<DashMap<u16, NatSessionEntry>>,
    self_pid: u32,
    transparent_relay_port: u16,
    local_socks_port: u16,
    local_http_port: u16,
    upstream_endpoints: Arc<RwLock<Vec<(Ipv4Addr, u16)>>>,
}

impl TransparentNatTable {
    /// Creates a new `TransparentNatTable` protecting `self_pid` and local relay ports.
    pub fn new(
        self_pid: u32,
        transparent_relay_port: u16,
        local_socks_port: u16,
        local_http_port: u16,
    ) -> Self {
        Self {
            socket_pid_cache: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            self_pid,
            transparent_relay_port,
            local_socks_port,
            local_http_port,
            upstream_endpoints: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Updates the list of upstream proxy IPv4 endpoints excluded from interception to avoid loops.
    pub fn set_upstream_endpoints(&self, endpoints: Vec<(Ipv4Addr, u16)>) {
        *self.upstream_endpoints.write() = endpoints;
    }

    /// Records a `(local_port -> pid)` mapping observed on `WINDIVERT_LAYER_SOCKET`.
    pub fn record_socket_event(&self, local_port: u16, pid: u32) {
        if local_port != 0 && pid != 0 {
            self.socket_pid_cache
                .insert(local_port, (pid, Instant::now()));
        }
    }

    /// Resolves the owning PID for `local_port`, handling the race between `SOCKET` and `NETWORK` layers.
    ///
    /// First checks the `SOCKET` layer cache; if absent, holds the SYN briefly and queries `fallback_fn`
    /// (`GetExtendedTcpTable`) up to `max_retries` times.
    pub fn resolve_pid_with_fallback<F>(
        &self,
        local_port: u16,
        max_retries: u32,
        retry_delay: Duration,
        fallback_fn: F,
    ) -> Option<(u32, PidResolutionSource)>
    where
        F: Fn(u16) -> Option<u32>,
    {
        if let Some(entry) = self.socket_pid_cache.get(&local_port) {
            if entry.value().1.elapsed() <= Duration::from_secs(SOCKET_CACHE_TTL_SECS) {
                return Some((entry.value().0, PidResolutionSource::SocketLayer));
            }
        }

        let attempts = max_retries.max(1);
        for attempt in 0..attempts {
            if let Some(pid) = fallback_fn(local_port) {
                if pid != 0 {
                    self.record_socket_event(local_port, pid);
                    return Some((pid, PidResolutionSource::TcpTableFallback));
                }
            }

            if let Some(entry) = self.socket_pid_cache.get(&local_port) {
                return Some((entry.value().0, PidResolutionSource::SocketLayer));
            }

            if attempt + 1 < attempts && !retry_delay.is_zero() {
                std::thread::sleep(retry_delay);
            }
        }

        None
    }

    /// Checks whether a connection must bypass interception to prevent routing loops.
    ///
    /// Excludes:
    /// - Traffic originating from RouteWard itself (`pid == self_pid`).
    /// - Loopback, broadcast, multicast, or unspecified addresses.
    /// - Traffic targeting RouteWard's own relay listeners (`transparent_relay_port`, `local_socks_port`, `local_http_port`).
    /// - Traffic targeting any configured upstream proxy endpoint `(ip, port)`.
    pub fn is_loop_or_excluded(
        &self,
        pid: Option<u32>,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> bool {
        if pid == Some(self.self_pid) {
            return true;
        }
        if src_ip.is_loopback()
            || dst_ip.is_loopback()
            || dst_ip.is_broadcast()
            || dst_ip.is_multicast()
            || dst_ip.is_unspecified()
        {
            return true;
        }
        if src_port == self.transparent_relay_port
            || dst_port == self.transparent_relay_port
            || dst_port == self.local_socks_port
            || dst_port == self.local_http_port
        {
            return true;
        }

        let upstreams = self.upstream_endpoints.read();
        upstreams
            .iter()
            .any(|(up_ip, up_port)| *up_ip == dst_ip && *up_port == dst_port)
    }

    /// Inserts or updates a NAT session entry keyed by `entry.client_port`.
    pub fn insert_session(&self, entry: NatSessionEntry) {
        self.sessions.insert(entry.client_port, entry);
    }

    /// Retrieves a cloned NAT session entry for `client_port`.
    pub fn get_session(&self, client_port: u16) -> Option<NatSessionEntry> {
        self.sessions.get(&client_port).map(|e| e.value().clone())
    }

    /// Removes the NAT session entry for `client_port`.
    pub fn remove_session(&self, client_port: u16) -> Option<NatSessionEntry> {
        self.sessions.remove(&client_port).map(|(_, v)| v)
    }

    /// Returns the transparent relay TCP port.
    pub fn transparent_relay_port(&self) -> u16 {
        self.transparent_relay_port
    }
}

/// Parses an IPv4 + TCP packet buffer and returns its 5-tuple and TCP flags.
pub fn parse_ipv4_tcp_meta(packet: &[u8]) -> Option<Ipv4TcpPacketMeta> {
    if packet.len() < IPV4_MIN_HEADER_LEN + TCP_MIN_HEADER_LEN {
        return None;
    }
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || packet.len() < ihl + TCP_MIN_HEADER_LEN {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl + TCP_MIN_HEADER_LEN || total_len > packet.len() {
        return None;
    }
    if packet[9] != IPPROTO_TCP {
        return None;
    }

    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let tcp_flags = packet[ihl + 13];

    Some(Ipv4TcpPacketMeta {
        ip_header_len: ihl,
        total_len,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
    })
}

/// Rewrites an outbound client TCP packet (`A:C -> B:D`) using the WinDivert `streamdump`
/// reflection technique (`B:C -> A:relay_port`) and updates RFC 1071 IPv4 and TCP checksums.
///
/// When reinjected with `Outbound = 0` (inbound), the Windows TCP stack delivers the packet
/// directly to the local transparent listener bound to `0.0.0.0:relay_port`.
pub fn reflect_outbound_to_local_relay(packet: &mut [u8], relay_port: u16) -> bool {
    let Some(meta) = parse_ipv4_tcp_meta(packet) else {
        return false;
    };
    let ihl = meta.ip_header_len;

    let src_octets = meta.src_ip.octets();
    let dst_octets = meta.dst_ip.octets();

    // Swap IPv4 source and destination addresses (streamdump reflect technique)
    packet[12..16].copy_from_slice(&dst_octets);
    packet[16..20].copy_from_slice(&src_octets);

    // Redirect TCP destination port to the local transparent relay listener
    packet[ihl + 2..ihl + 4].copy_from_slice(&relay_port.to_be_bytes());

    recompute_ipv4_and_tcp_checksums(&mut packet[..meta.total_len], ihl);
    true
}

/// Rewrites an outbound reply packet from the local transparent relay (`A:relay_port -> B:C`)
/// back into a reflected inbound packet (`B:D -> A:C`) addressed to the original client socket,
/// updating RFC 1071 IPv4 and TCP checksums.
pub fn reflect_relay_reply_to_client(packet: &mut [u8], entry: &NatSessionEntry) -> bool {
    let Some(meta) = parse_ipv4_tcp_meta(packet) else {
        return false;
    };
    let ihl = meta.ip_header_len;

    // Restore original server IPv4 as source and client IPv4 as destination
    packet[12..16].copy_from_slice(&entry.orig_dst_ip.octets());
    packet[16..20].copy_from_slice(&entry.client_ip.octets());

    // Restore original destination port as TCP source port and client port as destination
    packet[ihl..ihl + 2].copy_from_slice(&entry.orig_dst_port.to_be_bytes());
    packet[ihl + 2..ihl + 4].copy_from_slice(&entry.client_port.to_be_bytes());

    recompute_ipv4_and_tcp_checksums(&mut packet[..meta.total_len], ihl);
    true
}

/// Computes and writes RFC 1071 IPv4 header and TCP segment checksums in place.
pub fn recompute_ipv4_and_tcp_checksums(packet: &mut [u8], ihl: usize) {
    // 1. IPv4 header checksum
    packet[10] = 0;
    packet[11] = 0;
    let ip_csum = ones_complement_checksum(&packet[..ihl], 0);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // 2. TCP checksum (with IPv4 pseudo-header)
    let tcp_len = packet.len() - ihl;
    packet[ihl + 16] = 0;
    packet[ihl + 17] = 0;

    let mut sum: u32 = 0;
    // Pseudo-header: src_ip (4B), dst_ip (4B), zero + protocol (2B), tcp_len (2B)
    for chunk in packet[12..20].chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += IPPROTO_TCP as u32;
    sum += tcp_len as u32;

    let tcp_csum = ones_complement_checksum(&packet[ihl..], sum);
    packet[ihl + 16..ihl + 18].copy_from_slice(&tcp_csum.to_be_bytes());
}

fn ones_complement_checksum(bytes: &[u8], initial_sum: u32) -> u16 {
    let mut sum = initial_sum;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += u16::from_be_bytes([rem, 0]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sample_ipv4_tcp_syn(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = IPPROTO_TCP;
        pkt[12..16].copy_from_slice(&src_ip.octets());
        pkt[16..20].copy_from_slice(&dst_ip.octets());

        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 0x50; // Data offset = 5 (20 bytes)
        pkt[33] = TCP_FLAG_SYN;
        pkt[34..36].copy_from_slice(&64240u16.to_be_bytes());

        recompute_ipv4_and_tcp_checksums(&mut pkt, 20);
        pkt
    }

    #[test]
    fn resolves_pid_from_socket_layer_and_tcp_table_fallback() {
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);

        // 1. Direct hit from SOCKET layer cache
        nat.record_socket_event(51000, 4242);
        let res_socket =
            nat.resolve_pid_with_fallback(51000, 3, Duration::from_millis(1), |_| Some(1111));
        assert_eq!(res_socket, Some((4242, PidResolutionSource::SocketLayer)));

        // 2. Race condition: SYN arrives before SOCKET event -> resolved via GetExtendedTcpTable fallback
        let res_fallback =
            nat.resolve_pid_with_fallback(52000, 3, Duration::from_millis(1), |port| {
                if port == 52000 {
                    Some(7777)
                } else {
                    None
                }
            });
        assert_eq!(
            res_fallback,
            Some((7777, PidResolutionSource::TcpTableFallback))
        );
    }

    #[test]
    fn excludes_self_pid_loopback_and_upstream_proxy_from_interception() {
        let self_pid = 1234;
        let nat = TransparentNatTable::new(self_pid, 10810, 10808, 10809);
        let upstream_ip = Ipv4Addr::new(198, 51, 100, 10);
        nat.set_upstream_endpoints(vec![(upstream_ip, 1080)]);

        let client_ip = Ipv4Addr::new(192, 168, 1, 50);
        let external_ip = Ipv4Addr::new(93, 184, 215, 14);

        // RouteWard's own PID must be excluded
        assert!(nat.is_loop_or_excluded(Some(self_pid), client_ip, 50000, external_ip, 443));

        // Loopback destination must be excluded
        assert!(nat.is_loop_or_excluded(
            Some(4321),
            client_ip,
            50000,
            Ipv4Addr::new(127, 0, 0, 1),
            443
        ));

        // Upstream SOCKS5 server IP:port must be excluded
        assert!(nat.is_loop_or_excluded(Some(4321), client_ip, 50000, upstream_ip, 1080));

        // Normal external connection from curl.exe (PID 4321) must NOT be excluded
        assert!(!nat.is_loop_or_excluded(Some(4321), client_ip, 50000, external_ip, 443));
    }

    #[test]
    fn streamdump_reflection_rewrites_addresses_ports_and_valid_checksums() {
        let client_ip = Ipv4Addr::new(10, 0, 0, 15);
        let orig_dst_ip = Ipv4Addr::new(93, 184, 215, 14);
        let client_port = 54321;
        let orig_dst_port = 443;
        let relay_port = 10810;

        let mut syn_pkt =
            build_sample_ipv4_tcp_syn(client_ip, orig_dst_ip, client_port, orig_dst_port);
        let meta_before = parse_ipv4_tcp_meta(&syn_pkt).expect("valid IPv4 TCP packet");
        assert!(meta_before.is_syn_only());

        // 1. Outbound reflection toward local transparent relay
        assert!(reflect_outbound_to_local_relay(&mut syn_pkt, relay_port));
        let meta_reflected = parse_ipv4_tcp_meta(&syn_pkt).expect("valid reflected packet");
        assert_eq!(meta_reflected.src_ip, orig_dst_ip);
        assert_eq!(meta_reflected.dst_ip, client_ip);
        assert_eq!(meta_reflected.src_port, client_port);
        assert_eq!(meta_reflected.dst_port, relay_port);
        // Verify IPv4 header checksum validates to 0
        assert_eq!(ones_complement_checksum(&syn_pkt[..20], 0), 0);

        // 2. Return path reflection from local relay back to client
        let session = NatSessionEntry {
            client_ip,
            client_port,
            orig_dst_ip,
            orig_dst_port,
            pid: 8888,
            process_name: "curl.exe".to_string(),
            process_path: "C:\\Windows\\System32\\curl.exe".to_string(),
            resolution_source: PidResolutionSource::SocketLayer,
            action: RuleAction::Proxy {
                target_id: "proxy-socks5-primary".to_string(),
            },
            matched_rule_name: "CLI Tools via SOCKS5 Proxy".to_string(),
            created_at: Instant::now(),
        };

        let mut reply_pkt =
            build_sample_ipv4_tcp_syn(client_ip, orig_dst_ip, relay_port, client_port);
        assert!(reflect_relay_reply_to_client(&mut reply_pkt, &session));
        let meta_restored = parse_ipv4_tcp_meta(&reply_pkt).expect("valid restored packet");
        assert_eq!(meta_restored.src_ip, orig_dst_ip);
        assert_eq!(meta_restored.dst_ip, client_ip);
        assert_eq!(meta_restored.src_port, orig_dst_port);
        assert_eq!(meta_restored.dst_port, client_port);
        assert_eq!(ones_complement_checksum(&reply_pkt[..20], 0), 0);
    }
}
