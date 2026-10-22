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
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    /// Resolved via `GetExtendedTcpTable`.
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

/// Full 4-tuple key identifying an outbound IPv4 TCP connection from the local host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboundFlowKey {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
}

/// Active NAT redirection entry keyed by the outbound 4-tuple and indexed by the reflected relay peer tuple.
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

impl NatSessionEntry {
    /// Returns the outbound 4-tuple key `(local_ip, local_port, remote_ip, remote_port)` for this session.
    pub fn outbound_flow_key(&self) -> OutboundFlowKey {
        OutboundFlowKey {
            local_ip: self.client_ip,
            local_port: self.client_port,
            remote_ip: self.orig_dst_ip,
            remote_port: self.orig_dst_port,
        }
    }

    /// Returns the `(peer_ip, peer_port)` tuple seen by the local transparent relay after `streamdump` reflection.
    pub fn relay_peer_key(&self) -> (Ipv4Addr, u16) {
        (self.orig_dst_ip, self.client_port)
    }
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
    /// Returns the outbound 4-tuple key `(src_ip, src_port, dst_ip, dst_port)` for this packet.
    pub fn outbound_flow_key(&self) -> OutboundFlowKey {
        OutboundFlowKey {
            local_ip: self.src_ip,
            local_port: self.src_port,
            remote_ip: self.dst_ip,
            remote_port: self.dst_port,
        }
    }

    /// Returns `true` if this packet is an initial TCP SYN (SYN set, ACK not set).
    pub fn is_syn_only(&self) -> bool {
        (self.tcp_flags & TCP_FLAG_SYN) != 0 && (self.tcp_flags & TCP_FLAG_ACK) == 0
    }

    /// Returns `true` if the FIN or RST flag is set.
    pub fn is_fin_or_rst(&self) -> bool {
        (self.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) != 0
    }
}

/// Queued outbound SYN packet awaiting asynchronous PID resolution outside the network receive loop.
#[derive(Debug, Clone)]
pub struct PendingSynEntry<T> {
    pub payload: T,
    pub meta: Ipv4TcpPacketMeta,
    pub enqueued_at: Instant,
}

/// Outcome of polling a queued SYN packet in `PendingSynQueue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingSynOutcome<T> {
    /// PID was resolved before timeout via `SocketLayer` or `TcpTableFallback`.
    Resolved {
        payload: T,
        meta: Ipv4TcpPacketMeta,
        pid: u32,
        source: PidResolutionSource,
    },
    /// Timeout expired without resolving a PID; caller must reinject the SYN unmodified (fail-open).
    TimedOutFailOpen {
        payload: T,
        meta: Ipv4TcpPacketMeta,
        elapsed_ms: u64,
    },
}

/// Non-blocking queue holding unresolved outbound SYN packets so the main `NETWORK` receive loop never sleeps.
#[derive(Clone)]
pub struct PendingSynQueue<T> {
    inner: Arc<Mutex<VecDeque<PendingSynEntry<T>>>>,
}

impl<T> Default for PendingSynQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> PendingSynQueue<T> {
    /// Creates an empty `PendingSynQueue`.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Enqueues an unresolved SYN packet with the current timestamp.
    pub fn enqueue(&self, payload: T, meta: Ipv4TcpPacketMeta) {
        self.inner.lock().push_back(PendingSynEntry {
            payload,
            meta,
            enqueued_at: Instant::now(),
        });
    }

    /// Returns the number of currently queued SYN packets.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Returns `true` if no SYN packets are waiting in the queue.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Polls all queued SYN packets without sleeping, returning resolved or timed-out (fail-open) outcomes
    /// and keeping still-pending entries in the queue.
    pub fn poll_ready<F>(
        &self,
        nat: &TransparentNatTable,
        timeout: Duration,
        fallback_fn: F,
    ) -> Vec<PendingSynOutcome<T>>
    where
        F: Fn(u16) -> Option<u32>,
    {
        let mut queue = self.inner.lock();
        let count = queue.len();
        let mut outcomes = Vec::new();

        for _ in 0..count {
            let Some(entry) = queue.pop_front() else {
                break;
            };
            if let Some((pid, source)) =
                nat.try_resolve_pid_nonblocking(entry.meta.src_port, &fallback_fn)
            {
                outcomes.push(PendingSynOutcome::Resolved {
                    payload: entry.payload,
                    meta: entry.meta,
                    pid,
                    source,
                });
            } else {
                let elapsed = entry.enqueued_at.elapsed();
                if elapsed >= timeout {
                    outcomes.push(PendingSynOutcome::TimedOutFailOpen {
                        payload: entry.payload,
                        meta: entry.meta,
                        elapsed_ms: elapsed.as_millis() as u64,
                    });
                } else {
                    queue.push_back(entry);
                }
            }
        }

        outcomes
    }
}

/// Thread-safe NAT state table and loop-prevention registry for transparent TCP redirection.
#[derive(Clone)]
pub struct TransparentNatTable {
    socket_pid_cache: Arc<DashMap<u16, (u32, Instant)>>,
    sessions_by_flow: Arc<DashMap<OutboundFlowKey, NatSessionEntry>>,
    peer_to_flow: Arc<DashMap<(Ipv4Addr, u16), OutboundFlowKey>>,
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
            sessions_by_flow: Arc::new(DashMap::new()),
            peer_to_flow: Arc::new(DashMap::new()),
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

    /// Attempts to resolve the owning PID for `local_port` immediately without sleeping.
    ///
    /// First checks the `SOCKET` layer cache; if absent, performs a single non-blocking call to `fallback_fn`.
    pub fn try_resolve_pid_nonblocking<F>(
        &self,
        local_port: u16,
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

        if let Some(pid) = fallback_fn(local_port) {
            if pid != 0 {
                self.record_socket_event(local_port, pid);
                return Some((pid, PidResolutionSource::TcpTableFallback));
            }
        }

        None
    }

    /// Checks whether a connection must bypass interception to prevent routing loops.
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

    /// Inserts a NAT session entry keyed by its full outbound 4-tuple and indexed by its reflected relay peer tuple.
    pub fn insert_session(&self, entry: NatSessionEntry) {
        let flow_key = entry.outbound_flow_key();
        let peer_key = entry.relay_peer_key();
        self.peer_to_flow.insert(peer_key, flow_key);
        self.sessions_by_flow.insert(flow_key, entry);
    }

    /// Retrieves a cloned NAT session entry by its full outbound 4-tuple `(local_ip, local_port, remote_ip, remote_port)`.
    pub fn get_session_by_flow(&self, flow_key: &OutboundFlowKey) -> Option<NatSessionEntry> {
        self.sessions_by_flow
            .get(flow_key)
            .map(|e| e.value().clone())
    }

    /// Retrieves a cloned NAT session entry by the reflected `(peer_ip, peer_port)` tuple seen by the relay.
    pub fn get_session_by_relay_peer(
        &self,
        peer_ip: Ipv4Addr,
        peer_port: u16,
    ) -> Option<NatSessionEntry> {
        let flow_key = *self.peer_to_flow.get(&(peer_ip, peer_port))?.value();
        self.get_session_by_flow(&flow_key)
    }

    /// Validates a peer `SocketAddr` accepted by the transparent TCP relay against live NAT sessions.
    pub fn validate_relay_peer_addr(&self, peer_addr: SocketAddr) -> Option<NatSessionEntry> {
        match peer_addr.ip() {
            IpAddr::V4(peer_ipv4) => self.get_session_by_relay_peer(peer_ipv4, peer_addr.port()),
            IpAddr::V6(_) => None,
        }
    }

    /// Removes the NAT session entry associated with the reflected relay peer `(peer_ip, peer_port)`.
    pub fn remove_session_by_relay_peer(
        &self,
        peer_ip: Ipv4Addr,
        peer_port: u16,
    ) -> Option<NatSessionEntry> {
        let (_, flow_key) = self.peer_to_flow.remove(&(peer_ip, peer_port))?;
        self.sessions_by_flow.remove(&flow_key).map(|(_, v)| v)
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
    let mut addr_idx = 12;
    while addr_idx < 20 {
        sum += u16::from_be_bytes([packet[addr_idx], packet[addr_idx + 1]]) as u32;
        addr_idx += 2;
    }
    sum += IPPROTO_TCP as u32;
    sum += tcp_len as u32;

    let tcp_csum = ones_complement_checksum(&packet[ihl..], sum);
    packet[ihl + 16..ihl + 18].copy_from_slice(&tcp_csum.to_be_bytes());
}

fn ones_complement_checksum(bytes: &[u8], initial_sum: u32) -> u16 {
    let mut sum = initial_sum;
    let mut idx = 0;
    while idx + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[idx], bytes[idx + 1]]) as u32;
        idx += 2;
    }
    if idx < bytes.len() {
        sum += u16::from_be_bytes([bytes[idx], 0]) as u32;
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
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IPPROTO_TCP;
        pkt[12..16].copy_from_slice(&src_ip.octets());
        pkt[16..20].copy_from_slice(&dst_ip.octets());

        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = TCP_FLAG_SYN;
        pkt[34..36].copy_from_slice(&64240u16.to_be_bytes());

        recompute_ipv4_and_tcp_checksums(&mut pkt, 20);
        pkt
    }

    #[test]
    fn nonblocking_pending_syn_queue_resolves_or_times_out_fail_open() {
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        let queue: PendingSynQueue<Vec<u8>> = PendingSynQueue::new();

        let client_ip = Ipv4Addr::new(192, 168, 31, 136);
        let dst_ip = Ipv4Addr::new(93, 184, 215, 14);
        let pkt_resolved = build_sample_ipv4_tcp_syn(client_ip, dst_ip, 51001, 80);
        let meta_resolved = parse_ipv4_tcp_meta(&pkt_resolved).unwrap();

        let pkt_timeout = build_sample_ipv4_tcp_syn(client_ip, dst_ip, 51002, 80);
        let meta_timeout = parse_ipv4_tcp_meta(&pkt_timeout).unwrap();

        // Both SYNs arrive before SOCKET event or TCP table entry exists
        assert!(nat.try_resolve_pid_nonblocking(51001, |_| None).is_none());
        queue.enqueue(pkt_resolved.clone(), meta_resolved);
        queue.enqueue(pkt_timeout.clone(), meta_timeout);
        assert_eq!(queue.len(), 2);

        // Poll 1: neither is resolved yet, timeout (50 ms) has not elapsed -> both remain queued
        let outcomes_1 = queue.poll_ready(&nat, Duration::from_millis(50), |_| None);
        assert!(outcomes_1.is_empty());
        assert_eq!(queue.len(), 2);

        // Late SOCKET event arrives for port 51001
        nat.record_socket_event(51001, 4632);
        let outcomes_2 = queue.poll_ready(&nat, Duration::from_millis(50), |_| None);
        assert_eq!(outcomes_2.len(), 1);
        assert_eq!(
            outcomes_2[0],
            PendingSynOutcome::Resolved {
                payload: pkt_resolved,
                meta: meta_resolved,
                pid: 4632,
                source: PidResolutionSource::SocketLayer,
            }
        );
        assert_eq!(queue.len(), 1);

        // Poll 3 with 0ms timeout: remaining unresolved SYN (port 51002) times out and triggers fail-open
        let outcomes_3 = queue.poll_ready(&nat, Duration::ZERO, |_| None);
        assert_eq!(outcomes_3.len(), 1);
        match &outcomes_3[0] {
            PendingSynOutcome::TimedOutFailOpen { payload, meta, .. } => {
                assert_eq!(payload, &pkt_timeout);
                assert_eq!(meta.src_port, 51002);
            }
            other => panic!("Expected TimedOutFailOpen, got {other:?}"),
        }
        assert!(queue.is_empty());
    }

    #[test]
    fn nat_sessions_keyed_by_4_tuple_and_validated_by_relay_peer_tuple() {
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        let local_ip = Ipv4Addr::new(192, 168, 31, 136);
        let remote_ip_a = Ipv4Addr::new(93, 184, 215, 14);
        let remote_ip_b = Ipv4Addr::new(1, 1, 1, 1);

        let entry_a = NatSessionEntry {
            client_ip: local_ip,
            client_port: 55000,
            orig_dst_ip: remote_ip_a,
            orig_dst_port: 80,
            pid: 4632,
            process_name: "curl.exe".to_string(),
            process_path: "C:\\Windows\\System32\\curl.exe".to_string(),
            resolution_source: PidResolutionSource::SocketLayer,
            action: RuleAction::Proxy {
                target_id: "proxy-socks5-primary".to_string(),
            },
            matched_rule_name: "CLI Tools via SOCKS5 Proxy".to_string(),
            created_at: Instant::now(),
        };
        nat.insert_session(entry_a);

        // Exact 4-tuple lookup succeeds
        let key_a = OutboundFlowKey {
            local_ip,
            local_port: 55000,
            remote_ip: remote_ip_a,
            remote_port: 80,
        };
        assert!(nat.get_session_by_flow(&key_a).is_some());

        // Different remote IP or remote port on the same local port does NOT falsely match
        let key_different_remote = OutboundFlowKey {
            local_ip,
            local_port: 55000,
            remote_ip: remote_ip_b,
            remote_port: 443,
        };
        assert!(nat.get_session_by_flow(&key_different_remote).is_none());

        // Relay peer validation accepts the matching reflected peer tuple (remote_ip_a:55000)
        let valid_peer = SocketAddr::new(IpAddr::V4(remote_ip_a), 55000);
        let validated = nat
            .validate_relay_peer_addr(valid_peer)
            .expect("matching live NAT session");
        assert_eq!(validated.pid, 4632);
        assert_eq!(validated.orig_dst_port, 80);

        // Relay peer validation rejects unknown/unauthorized LAN connections to 0.0.0.0:10810
        let unauthorized_peer_wrong_ip = SocketAddr::new(IpAddr::V4(remote_ip_b), 55000);
        assert!(nat
            .validate_relay_peer_addr(unauthorized_peer_wrong_ip)
            .is_none());
        let unauthorized_peer_wrong_port = SocketAddr::new(IpAddr::V4(remote_ip_a), 55001);
        assert!(nat
            .validate_relay_peer_addr(unauthorized_peer_wrong_port)
            .is_none());

        // Removing session cleans up both maps
        assert!(nat
            .remove_session_by_relay_peer(remote_ip_a, 55000)
            .is_some());
        assert!(nat.get_session_by_flow(&key_a).is_none());
        assert!(nat.validate_relay_peer_addr(valid_peer).is_none());
    }

    #[test]
    fn excludes_self_pid_loopback_and_upstream_proxy_from_interception() {
        let self_pid = 1234;
        let nat = TransparentNatTable::new(self_pid, 10810, 10808, 10809);
        let upstream_ip = Ipv4Addr::new(198, 51, 100, 10);
        nat.set_upstream_endpoints(vec![(upstream_ip, 1080)]);

        let client_ip = Ipv4Addr::new(192, 168, 1, 50);
        let external_ip = Ipv4Addr::new(93, 184, 215, 14);

        assert!(nat.is_loop_or_excluded(Some(self_pid), client_ip, 50000, external_ip, 443));
        assert!(nat.is_loop_or_excluded(
            Some(4321),
            client_ip,
            50000,
            Ipv4Addr::new(127, 0, 0, 1),
            443
        ));
        assert!(nat.is_loop_or_excluded(Some(4321), client_ip, 50000, upstream_ip, 1080));
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

        assert!(reflect_outbound_to_local_relay(&mut syn_pkt, relay_port));
        let meta_reflected = parse_ipv4_tcp_meta(&syn_pkt).expect("valid reflected packet");
        assert_eq!(meta_reflected.src_ip, orig_dst_ip);
        assert_eq!(meta_reflected.dst_ip, client_ip);
        assert_eq!(meta_reflected.src_port, client_port);
        assert_eq!(meta_reflected.dst_port, relay_port);
        assert_eq!(ones_complement_checksum(&syn_pkt[..20], 0), 0);

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
