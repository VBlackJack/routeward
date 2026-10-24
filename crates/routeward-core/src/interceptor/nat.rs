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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const IPV4_VERSION: u8 = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const IPV6_VERSION: u8 = 6;
const IPV6_HEADER_LEN: usize = 40;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const ICMPV4_TYPE_DEST_UNREACHABLE: u8 = 3;
pub const ICMPV4_CODE_PORT_UNREACHABLE: u8 = 3;
const ICMPV4_HEADER_LEN: usize = 8;
const IPV4_FRAG_MORE_OR_OFFSET_MASK: u16 = 0x3FFF;
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

/// Parsed IPv4 + UDP packet header and payload slice metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4UdpPacketMeta {
    pub ip_header_len: usize,
    pub total_len: usize,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}

/// Parsed IPv6 + TCP/UDP packet header metadata (used for DNS/DoT IPv6 leak prevention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6TransportPacketMeta {
    pub next_header: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// RAII guard that unregisters a self-owned local UDP or TCP port from [`TransparentNatTable`] when dropped.
pub struct SelfPortGuard {
    map: Arc<DashMap<u16, Instant>>,
    port: u16,
}

impl Drop for SelfPortGuard {
    fn drop(&mut self) {
        self.map.remove(&self.port);
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
    /// Timeout expired without resolving a PID while `killSwitchEnabled=true`; the SYN payload is
    /// dropped without response so the client retransmits the SYN (~1 s later) after attribution succeeds.
    TimedOutDropped {
        meta: Ipv4TcpPacketMeta,
        elapsed_ms: u64,
        drop_count: u64,
    },
    /// Timeout expired without resolving a PID while `killSwitchEnabled=false`; caller reinjects the SYN unmodified (fail-open).
    TimedOutReinject {
        payload: T,
        meta: Ipv4TcpPacketMeta,
        elapsed_ms: u64,
        reinject_count: u64,
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

    /// Polls all queued SYN packets without sleeping, returning resolved, dropped (`killSwitchEnabled=true`),
    /// or reinjected (`killSwitchEnabled=false`) outcomes and keeping still-pending entries in the queue.
    pub fn poll_ready<F>(
        &self,
        nat: &TransparentNatTable,
        timeout: Duration,
        kill_switch_enabled: bool,
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
                    let elapsed_ms = elapsed.as_millis() as u64;
                    if kill_switch_enabled {
                        let drop_count = nat.record_dropped_unattributed_syn();
                        outcomes.push(PendingSynOutcome::TimedOutDropped {
                            meta: entry.meta,
                            elapsed_ms,
                            drop_count,
                        });
                    } else {
                        let reinject_count = nat.record_reinjected_unattributed_syn();
                        outcomes.push(PendingSynOutcome::TimedOutReinject {
                            payload: entry.payload,
                            meta: entry.meta,
                            elapsed_ms,
                            reinject_count,
                        });
                    }
                } else {
                    queue.push_back(entry);
                }
            }
        }

        outcomes
    }
}

/// Queued outbound UDP packet awaiting asynchronous PID resolution outside the network receive loop.
#[derive(Debug, Clone)]
pub struct PendingUdpEntry<T> {
    pub payload: T,
    pub meta: Ipv4UdpPacketMeta,
    pub is_fragmented: bool,
    pub enqueued_at: Instant,
}

/// Outcome of polling or evicting a queued UDP packet in [`PendingUdpQueue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingUdpOutcome<T> {
    /// PID was resolved before timeout via `SocketLayer` or `GetExtendedUdpTable` (`TcpTableFallback`).
    Resolved {
        payload: T,
        meta: Ipv4UdpPacketMeta,
        is_fragmented: bool,
        pid: u32,
        source: PidResolutionSource,
    },
    /// Timeout expired or bounded queue overflowed while `killSwitchEnabled=true`; datagram is dropped.
    TimedOutDropped {
        meta: Ipv4UdpPacketMeta,
        elapsed_ms: u64,
        drop_count: u64,
    },
    /// Timeout expired or bounded queue overflowed while `killSwitchEnabled=false`; caller reinjects datagram unmodified.
    TimedOutReinject {
        payload: T,
        meta: Ipv4UdpPacketMeta,
        elapsed_ms: u64,
        reinject_count: u64,
    },
}

/// Bounded non-blocking queue holding unresolved first outbound UDP datagrams so the main `NETWORK` receive loop never sleeps.
#[derive(Clone)]
pub struct PendingUdpQueue<T> {
    inner: Arc<Mutex<VecDeque<PendingUdpEntry<T>>>>,
    max_capacity: usize,
}

impl<T> Default for PendingUdpQueue<T> {
    fn default() -> Self {
        Self::new(256)
    }
}

impl<T> PendingUdpQueue<T> {
    /// Creates an empty `PendingUdpQueue` bounded to `max_capacity` entries.
    pub fn new(max_capacity: usize) -> Self {
        let cap = max_capacity.max(1);
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(cap))),
            max_capacity: cap,
        }
    }

    /// Enqueues an unresolved UDP packet. If the queue is at `max_capacity`, evicts the oldest entry
    /// and returns its drop/reinject outcome according to `kill_switch_enabled`.
    pub fn enqueue(
        &self,
        nat: &TransparentNatTable,
        payload: T,
        meta: Ipv4UdpPacketMeta,
        is_fragmented: bool,
        kill_switch_enabled: bool,
    ) -> Option<PendingUdpOutcome<T>> {
        let mut queue = self.inner.lock();
        let evicted = if queue.len() >= self.max_capacity {
            queue.pop_front().map(|oldest| {
                let elapsed_ms = oldest.enqueued_at.elapsed().as_millis() as u64;
                if kill_switch_enabled {
                    let drop_count = nat.record_dropped_unattributed_udp();
                    PendingUdpOutcome::TimedOutDropped {
                        meta: oldest.meta,
                        elapsed_ms,
                        drop_count,
                    }
                } else {
                    let reinject_count = nat.record_reinjected_unattributed_udp();
                    PendingUdpOutcome::TimedOutReinject {
                        payload: oldest.payload,
                        meta: oldest.meta,
                        elapsed_ms,
                        reinject_count,
                    }
                }
            })
        } else {
            None
        };

        queue.push_back(PendingUdpEntry {
            payload,
            meta,
            is_fragmented,
            enqueued_at: Instant::now(),
        });
        evicted
    }

    /// Returns the number of currently queued UDP datagrams.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Returns `true` if no UDP datagrams are waiting in the queue.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Polls all queued UDP datagrams without sleeping, returning resolved, dropped (`killSwitchEnabled=true`),
    /// or reinjected (`killSwitchEnabled=false`) outcomes and keeping still-pending entries in the queue.
    pub fn poll_ready<F>(
        &self,
        nat: &TransparentNatTable,
        timeout: Duration,
        kill_switch_enabled: bool,
        fallback_fn: F,
    ) -> Vec<PendingUdpOutcome<T>>
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
                outcomes.push(PendingUdpOutcome::Resolved {
                    payload: entry.payload,
                    meta: entry.meta,
                    is_fragmented: entry.is_fragmented,
                    pid,
                    source,
                });
            } else {
                let elapsed = entry.enqueued_at.elapsed();
                if elapsed >= timeout {
                    let elapsed_ms = elapsed.as_millis() as u64;
                    if kill_switch_enabled {
                        let drop_count = nat.record_dropped_unattributed_udp();
                        outcomes.push(PendingUdpOutcome::TimedOutDropped {
                            meta: entry.meta,
                            elapsed_ms,
                            drop_count,
                        });
                    } else {
                        let reinject_count = nat.record_reinjected_unattributed_udp();
                        outcomes.push(PendingUdpOutcome::TimedOutReinject {
                            payload: entry.payload,
                            meta: entry.meta,
                            elapsed_ms,
                            reinject_count,
                        });
                    }
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
    self_udp_ports: Arc<DashMap<u16, Instant>>,
    self_tcp_ports: Arc<DashMap<u16, Instant>>,
    sessions_by_flow: Arc<DashMap<OutboundFlowKey, NatSessionEntry>>,
    peer_to_flow: Arc<DashMap<(Ipv4Addr, u16), OutboundFlowKey>>,
    self_pid: u32,
    transparent_relay_port: u16,
    local_socks_port: u16,
    local_http_port: u16,
    upstream_endpoints: Arc<RwLock<Vec<(Ipv4Addr, u16)>>>,
    dropped_unattributed_syn_count: Arc<AtomicU64>,
    reinjected_unattributed_syn_count: Arc<AtomicU64>,
    dropped_unattributed_udp_count: Arc<AtomicU64>,
    reinjected_unattributed_udp_count: Arc<AtomicU64>,
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
            self_udp_ports: Arc::new(DashMap::new()),
            self_tcp_ports: Arc::new(DashMap::new()),
            sessions_by_flow: Arc::new(DashMap::new()),
            peer_to_flow: Arc::new(DashMap::new()),
            self_pid,
            transparent_relay_port,
            local_socks_port,
            local_http_port,
            upstream_endpoints: Arc::new(RwLock::new(Vec::new())),
            dropped_unattributed_syn_count: Arc::new(AtomicU64::new(0)),
            reinjected_unattributed_syn_count: Arc::new(AtomicU64::new(0)),
            dropped_unattributed_udp_count: Arc::new(AtomicU64::new(0)),
            reinjected_unattributed_udp_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Registers a local UDP port bound by RouteWard itself so `WinDivert` passes its packets through without interception.
    pub fn register_self_udp_port(&self, port: u16) -> SelfPortGuard {
        let now = Instant::now();
        self.self_udp_ports.insert(port, now);
        self.socket_pid_cache.insert(port, (self.self_pid, now));
        SelfPortGuard {
            map: Arc::clone(&self.self_udp_ports),
            port,
        }
    }

    /// Returns `true` if `port` is currently registered as a RouteWard-owned local UDP socket port.
    pub fn is_self_udp_port(&self, port: u16) -> bool {
        self.self_udp_ports.contains_key(&port)
    }

    /// Registers a local TCP port bound by RouteWard itself so `WinDivert` passes its packets through without interception.
    pub fn register_self_tcp_port(&self, port: u16) -> SelfPortGuard {
        let now = Instant::now();
        self.self_tcp_ports.insert(port, now);
        self.socket_pid_cache.insert(port, (self.self_pid, now));
        SelfPortGuard {
            map: Arc::clone(&self.self_tcp_ports),
            port,
        }
    }

    /// Returns `true` if `port` is currently registered as a RouteWard-owned local TCP socket port.
    pub fn is_self_tcp_port(&self, port: u16) -> bool {
        self.self_tcp_ports.contains_key(&port)
    }

    /// Increments and returns the 1-based counter of timed-out Pending SYNs dropped while `killSwitchEnabled=true`.
    pub fn record_dropped_unattributed_syn(&self) -> u64 {
        self.dropped_unattributed_syn_count
            .fetch_add(1, Ordering::SeqCst)
            + 1
    }

    /// Returns the total number of timed-out Pending SYNs dropped while `killSwitchEnabled=true`.
    pub fn dropped_unattributed_syn_count(&self) -> u64 {
        self.dropped_unattributed_syn_count.load(Ordering::SeqCst)
    }

    /// Increments and returns the 1-based counter of timed-out Pending SYNs reinjected while `killSwitchEnabled=false`.
    pub fn record_reinjected_unattributed_syn(&self) -> u64 {
        self.reinjected_unattributed_syn_count
            .fetch_add(1, Ordering::SeqCst)
            + 1
    }

    /// Returns the total number of timed-out Pending SYNs reinjected while `killSwitchEnabled=false`.
    pub fn reinjected_unattributed_syn_count(&self) -> u64 {
        self.reinjected_unattributed_syn_count
            .load(Ordering::SeqCst)
    }

    /// Increments and returns the 1-based counter of timed-out Pending UDP datagrams dropped while `killSwitchEnabled=true`.
    pub fn record_dropped_unattributed_udp(&self) -> u64 {
        self.dropped_unattributed_udp_count
            .fetch_add(1, Ordering::SeqCst)
            + 1
    }

    /// Returns the total number of timed-out Pending UDP datagrams dropped while `killSwitchEnabled=true`.
    pub fn dropped_unattributed_udp_count(&self) -> u64 {
        self.dropped_unattributed_udp_count.load(Ordering::SeqCst)
    }

    /// Increments and returns the 1-based counter of timed-out Pending UDP datagrams reinjected while `killSwitchEnabled=false`.
    pub fn record_reinjected_unattributed_udp(&self) -> u64 {
        self.reinjected_unattributed_udp_count
            .fetch_add(1, Ordering::SeqCst)
            + 1
    }

    /// Returns the total number of timed-out Pending UDP datagrams reinjected while `killSwitchEnabled=false`.
    pub fn reinjected_unattributed_udp_count(&self) -> u64 {
        self.reinjected_unattributed_udp_count
            .load(Ordering::SeqCst)
    }

    /// Updates the list of upstream proxy IPv4 endpoints excluded from interception to avoid loops.
    pub fn set_upstream_endpoints(&self, endpoints: Vec<(Ipv4Addr, u16)>) {
        *self.upstream_endpoints.write() = endpoints;
    }

    /// Returns a snapshot of the upstream proxy IPv4 endpoints excluded from interception.
    pub fn upstream_endpoints(&self) -> Vec<(Ipv4Addr, u16)> {
        self.upstream_endpoints.read().clone()
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
        if pid == Some(self.self_pid)
            || self.is_self_tcp_port(src_port)
            || self.is_self_udp_port(src_port)
        {
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

/// Parses an IPv4 + UDP packet buffer and returns its 5-tuple and UDP payload slice bounds.
pub fn parse_ipv4_udp_meta(packet: &[u8]) -> Option<Ipv4UdpPacketMeta> {
    if packet.len() < IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN {
        return None;
    }
    let version = packet[0] >> 4;
    if version != IPV4_VERSION {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || packet.len() < ihl + UDP_HEADER_LEN {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl + UDP_HEADER_LEN || total_len > packet.len() {
        return None;
    }
    if packet[9] != IPPROTO_UDP {
        return None;
    }

    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
    if udp_len < UDP_HEADER_LEN || ihl + udp_len > total_len {
        return None;
    }

    Some(Ipv4UdpPacketMeta {
        ip_header_len: ihl,
        total_len,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload_offset: ihl + UDP_HEADER_LEN,
        payload_len: udp_len - UDP_HEADER_LEN,
    })
}

/// Parses an IPv6 packet with a TCP or UDP transport header, skipping standard IPv6 extension headers.
pub fn parse_ipv6_transport_meta(packet: &[u8]) -> Option<Ipv6TransportPacketMeta> {
    if packet.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN {
        return None;
    }
    if (packet[0] >> 4) != IPV6_VERSION {
        return None;
    }

    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&packet[8..24]);
    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&packet[24..40]);

    let mut next_header = packet[6];
    let mut offset = IPV6_HEADER_LEN;

    // Walk up to 6 standard IPv6 extension headers (Hop-by-Hop=0, Routing=43, Fragment=44, DestOpts=60)
    for _ in 0..6 {
        match next_header {
            IPPROTO_TCP => {
                if packet.len() < offset + TCP_MIN_HEADER_LEN {
                    return None;
                }
                let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
                let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                return Some(Ipv6TransportPacketMeta {
                    next_header,
                    src_ip: Ipv6Addr::from(src_octets),
                    dst_ip: Ipv6Addr::from(dst_octets),
                    src_port,
                    dst_port,
                });
            }
            IPPROTO_UDP => {
                if packet.len() < offset + UDP_HEADER_LEN {
                    return None;
                }
                let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
                let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                return Some(Ipv6TransportPacketMeta {
                    next_header,
                    src_ip: Ipv6Addr::from(src_octets),
                    dst_ip: Ipv6Addr::from(dst_octets),
                    src_port,
                    dst_port,
                });
            }
            0 | 43 | 60 => {
                let hdr = packet.get(offset..offset + 2)?;
                let ext_len = ((hdr[1] as usize) + 1) * 8;
                next_header = hdr[0];
                offset = offset.checked_add(ext_len)?;
            }
            44 => {
                let hdr = packet.get(offset..offset + 8)?;
                next_header = hdr[0];
                offset = offset.checked_add(8)?;
            }
            _ => return None,
        }
    }

    None
}

/// Builds a complete IPv4 + UDP reply packet (`src_ip:src_port -> dst_ip:dst_port`) with valid
/// RFC 1071 IPv4 header and UDP checksums for inbound injection via `WinDivertSend`.
pub fn build_forged_ipv4_udp_reply(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    udp_payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN.checked_add(udp_payload.len())?;
    let total_len = IPV4_MIN_HEADER_LEN.checked_add(udp_len)?;
    if total_len > u16::MAX as usize {
        return None;
    }

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&[0x40, 0x00]); // Don't Fragment
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_UDP;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    let ihl = IPV4_MIN_HEADER_LEN;
    pkt[ihl..ihl + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[ihl + 2..ihl + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[ihl + 4..ihl + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[ihl + UDP_HEADER_LEN..].copy_from_slice(udp_payload);

    recompute_ipv4_and_udp_checksums(&mut pkt, ihl);
    Some(pkt)
}

/// Computes and writes RFC 1071 IPv4 header and UDP datagram checksums in place.
pub fn recompute_ipv4_and_udp_checksums(packet: &mut [u8], ihl: usize) {
    packet[10] = 0;
    packet[11] = 0;
    let ip_csum = ones_complement_checksum(&packet[..ihl], 0);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let udp_len = packet.len() - ihl;
    packet[ihl + 6] = 0;
    packet[ihl + 7] = 0;

    let mut sum: u32 = 0;
    let mut addr_idx = 12;
    while addr_idx < 20 {
        sum += u16::from_be_bytes([packet[addr_idx], packet[addr_idx + 1]]) as u32;
        addr_idx += 2;
    }
    sum += IPPROTO_UDP as u32;
    sum += udp_len as u32;

    let mut udp_csum = ones_complement_checksum(&packet[ihl..], sum);
    if udp_csum == 0 {
        udp_csum = 0xFFFF;
    }
    packet[ihl + 6..ihl + 8].copy_from_slice(&udp_csum.to_be_bytes());
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

/// Returns `true` if `packet` is a fragmented IPv4 packet (`MF` bit `0x2000` set or non-zero fragment offset `0x1FFF`).
pub fn is_ipv4_packet_fragmented(packet: &[u8]) -> bool {
    if packet.len() < IPV4_MIN_HEADER_LEN || (packet[0] >> 4) != IPV4_VERSION {
        return false;
    }
    let frag_field = u16::from_be_bytes([packet[6], packet[7]]);
    (frag_field & IPV4_FRAG_MORE_OR_OFFSET_MASK) != 0
}

/// Returns `true` if `ip` is a local, RFC 1918 private, link-local, multicast, or broadcast IPv4 address
/// (used to restrict NetBIOS-NS `UDP 137` to local networks and block public IP destinations).
pub fn is_private_or_local_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
}

/// Parses a raw 8-byte (or 16-byte) `sockaddr_in` payload from a Linux `IP_ORIGDSTADDR` (`SOL_IP`, `20`)
/// ancillary control message (`CMSG_DATA`) into `SocketAddrV4`.
pub fn parse_ipv4_origdstaddr_bytes(cmsg_data: &[u8]) -> Option<SocketAddrV4> {
    if cmsg_data.len() < 8 {
        return None;
    }
    let family = u16::from_ne_bytes([cmsg_data[0], cmsg_data[1]]);
    if family != 2 {
        return None;
    }
    let port = u16::from_be_bytes([cmsg_data[2], cmsg_data[3]]);
    if port == 0 {
        return None;
    }
    let ip = Ipv4Addr::new(cmsg_data[4], cmsg_data[5], cmsg_data[6], cmsg_data[7]);
    Some(SocketAddrV4::new(ip, port))
}

/// Builds a forged RFC 792 ICMPv4 Destination Unreachable / Port Unreachable (`Type = 3`, `Code = 3`)
/// packet in response to `original_ipv4_packet`, swapping source and destination IPv4 addresses and
/// embedding the original IPv4 header plus the first 8 bytes of the transport header.
pub fn build_forged_ipv4_icmp_port_unreachable(original_ipv4_packet: &[u8]) -> Option<Vec<u8>> {
    if original_ipv4_packet.len() < IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN {
        return None;
    }
    if (original_ipv4_packet[0] >> 4) != IPV4_VERSION {
        return None;
    }
    let orig_ihl = ((original_ipv4_packet[0] & 0x0F) as usize) * 4;
    if orig_ihl < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let quoted_len = orig_ihl.checked_add(UDP_HEADER_LEN)?;
    if original_ipv4_packet.len() < quoted_len {
        return None;
    }

    let orig_src_ip = Ipv4Addr::new(
        original_ipv4_packet[12],
        original_ipv4_packet[13],
        original_ipv4_packet[14],
        original_ipv4_packet[15],
    );
    let orig_dst_ip = Ipv4Addr::new(
        original_ipv4_packet[16],
        original_ipv4_packet[17],
        original_ipv4_packet[18],
        original_ipv4_packet[19],
    );

    let icmp_len = ICMPV4_HEADER_LEN.checked_add(quoted_len)?;
    let total_len = IPV4_MIN_HEADER_LEN.checked_add(icmp_len)?;
    if total_len > u16::MAX as usize {
        return None;
    }

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&[0x40, 0x00]); // Don't Fragment
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_ICMP;
    pkt[12..16].copy_from_slice(&orig_dst_ip.octets());
    pkt[16..20].copy_from_slice(&orig_src_ip.octets());

    let ip_csum = ones_complement_checksum(&pkt[..IPV4_MIN_HEADER_LEN], 0);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let icmp_offset = IPV4_MIN_HEADER_LEN;
    pkt[icmp_offset] = ICMPV4_TYPE_DEST_UNREACHABLE;
    pkt[icmp_offset + 1] = ICMPV4_CODE_PORT_UNREACHABLE;
    // Bytes 2..4 = checksum (0 initially), Bytes 4..8 = unused (0)
    let inner_ip_start = icmp_offset + ICMPV4_HEADER_LEN;
    pkt[inner_ip_start..].copy_from_slice(&original_ipv4_packet[..quoted_len]);

    // Ensure the quoted inner IPv4 header (and UDP checksum if TX checksum offload left a pseudo-header seed)
    // has valid RFC 1071 checksums before computing the outer ICMPv4 checksum.
    pkt[inner_ip_start + 10] = 0;
    pkt[inner_ip_start + 11] = 0;
    let inner_ip_csum =
        ones_complement_checksum(&pkt[inner_ip_start..inner_ip_start + orig_ihl], 0);
    pkt[inner_ip_start + 10..inner_ip_start + 12].copy_from_slice(&inner_ip_csum.to_be_bytes());
    if original_ipv4_packet[9] == IPPROTO_UDP {
        let orig_total_len =
            u16::from_be_bytes([original_ipv4_packet[2], original_ipv4_packet[3]]) as usize;
        if orig_total_len >= quoted_len && original_ipv4_packet.len() >= orig_total_len {
            let mut full_copy = original_ipv4_packet[..orig_total_len].to_vec();
            recompute_ipv4_and_udp_checksums(&mut full_copy, orig_ihl);
            pkt[inner_ip_start + orig_ihl..inner_ip_start + quoted_len]
                .copy_from_slice(&full_copy[orig_ihl..quoted_len]);
        }
    }

    let icmp_csum = ones_complement_checksum(&pkt[icmp_offset..], 0);
    pkt[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    Some(pkt)
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
        let outcomes_1 = queue.poll_ready(&nat, Duration::from_millis(50), true, |_| None);
        assert!(outcomes_1.is_empty());
        assert_eq!(queue.len(), 2);

        // Late SOCKET event arrives for port 51001
        nat.record_socket_event(51001, 4632);
        let outcomes_2 = queue.poll_ready(&nat, Duration::from_millis(50), true, |_| None);
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

        // Poll 3 with 0ms timeout and killSwitchEnabled=true: unresolved SYN is dropped (not reinjected)
        let outcomes_3 = queue.poll_ready(&nat, Duration::ZERO, true, |_| None);
        assert_eq!(outcomes_3.len(), 1);
        match &outcomes_3[0] {
            PendingSynOutcome::TimedOutDropped {
                meta, drop_count, ..
            } => {
                assert_eq!(meta.src_port, 51002);
                assert_eq!(*drop_count, 1);
            }
            other => panic!("Expected TimedOutDropped, got {other:?}"),
        }
        assert_eq!(nat.dropped_unattributed_syn_count(), 1);
        assert_eq!(nat.reinjected_unattributed_syn_count(), 0);
        assert!(queue.is_empty());

        // Poll 4 with 0ms timeout and killSwitchEnabled=false: unresolved SYN is returned for reinjection
        queue.enqueue(pkt_timeout.clone(), meta_timeout);
        let outcomes_4 = queue.poll_ready(&nat, Duration::ZERO, false, |_| None);
        assert_eq!(outcomes_4.len(), 1);
        match &outcomes_4[0] {
            PendingSynOutcome::TimedOutReinject {
                payload,
                meta,
                reinject_count,
                ..
            } => {
                assert_eq!(payload, &pkt_timeout);
                assert_eq!(meta.src_port, 51002);
                assert_eq!(*reinject_count, 1);
            }
            other => panic!("Expected TimedOutReinject, got {other:?}"),
        }
        assert_eq!(nat.reinjected_unattributed_syn_count(), 1);
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

    #[test]
    fn builds_and_parses_forged_ipv4_udp_dns_reply_and_ipv6_meta() {
        let server_ip = Ipv4Addr::new(1, 1, 1, 1);
        let client_ip = Ipv4Addr::new(10, 0, 0, 15);
        let payload = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00";

        let pkt = build_forged_ipv4_udp_reply(server_ip, 53, client_ip, 53111, payload)
            .expect("build forged UDP packet");
        let meta = parse_ipv4_udp_meta(&pkt).expect("parse forged UDP packet");
        assert_eq!(meta.src_ip, server_ip);
        assert_eq!(meta.dst_ip, client_ip);
        assert_eq!(meta.src_port, 53);
        assert_eq!(meta.dst_port, 53111);
        assert_eq!(
            &pkt[meta.payload_offset..meta.payload_offset + meta.payload_len],
            payload
        );
        assert_eq!(ones_complement_checksum(&pkt[..20], 0), 0);

        // SelfPortGuard registration and drop cleanup
        let nat = TransparentNatTable::new(1234, 10810, 10808, 10809);
        {
            let _udp_guard = nat.register_self_udp_port(61234);
            assert!(nat.is_self_udp_port(61234));
            let _tcp_guard = nat.register_self_tcp_port(61235);
            assert!(nat.is_self_tcp_port(61235));
            assert!(nat.is_loop_or_excluded(None, client_ip, 61235, server_ip, 53));
        }
        assert!(!nat.is_self_udp_port(61234));
        assert!(!nat.is_self_tcp_port(61235));

        // IPv6 UDP 53 packet parsing
        let mut v6_pkt = vec![0u8; 48];
        v6_pkt[0] = 0x60;
        v6_pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
        v6_pkt[6] = IPPROTO_UDP;
        v6_pkt[7] = 64;
        v6_pkt[40..42].copy_from_slice(&54321u16.to_be_bytes());
        v6_pkt[42..44].copy_from_slice(&53u16.to_be_bytes());
        v6_pkt[44..46].copy_from_slice(&8u16.to_be_bytes());
        let v6_meta = parse_ipv6_transport_meta(&v6_pkt).expect("parse IPv6 UDP meta");
        assert_eq!(v6_meta.next_header, IPPROTO_UDP);
        assert_eq!(v6_meta.src_port, 54321);
        assert_eq!(v6_meta.dst_port, 53);
    }

    #[test]
    fn builds_valid_icmpv4_port_unreachable_and_detects_ipv4_fragmentation() {
        let client_ip = Ipv4Addr::new(192, 168, 1, 25);
        let target_ip = Ipv4Addr::new(93, 184, 215, 14);
        let quic_payload = b"\xc0\x00\x00\x00\x01\x08\x01\x02\x03\x04\x05\x06\x07\x08";

        let orig_udp = build_forged_ipv4_udp_reply(client_ip, 55443, target_ip, 443, quic_payload)
            .expect("build outbound QUIC UDP packet");
        assert!(!is_ipv4_packet_fragmented(&orig_udp));

        let icmp_pkt = build_forged_ipv4_icmp_port_unreachable(&orig_udp)
            .expect("build ICMPv4 Port Unreachable");
        // Total length: 20 (outer IPv4) + 8 (ICMP header) + 20 (orig IPv4) + 8 (orig UDP header) = 56 bytes
        assert_eq!(icmp_pkt.len(), 56);
        assert_eq!(icmp_pkt[0], 0x45);
        assert_eq!(icmp_pkt[9], IPPROTO_ICMP);
        assert_eq!(&icmp_pkt[12..16], &target_ip.octets());
        assert_eq!(&icmp_pkt[16..20], &client_ip.octets());
        // Outer IPv4 header checksum verifies to 0
        assert_eq!(ones_complement_checksum(&icmp_pkt[..20], 0), 0);

        // ICMPv4 Type = 3 (Dest Unreachable), Code = 3 (Port Unreachable), checksum verifies to 0
        assert_eq!(icmp_pkt[20], ICMPV4_TYPE_DEST_UNREACHABLE);
        assert_eq!(icmp_pkt[21], ICMPV4_CODE_PORT_UNREACHABLE);
        assert_eq!(ones_complement_checksum(&icmp_pkt[20..], 0), 0);
        // Embedded payload matches original IPv4 header + first 8 bytes of UDP header
        assert_eq!(&icmp_pkt[28..56], &orig_udp[..28]);

        // Fragmentation detection: More Fragments (MF = 0x2000) and non-zero fragment offset
        let mut frag_mf = orig_udp.clone();
        frag_mf[6] = 0x20;
        frag_mf[7] = 0x00;
        assert!(is_ipv4_packet_fragmented(&frag_mf));

        let mut frag_offset = orig_udp.clone();
        frag_offset[6] = 0x00;
        frag_offset[7] = 0x10;
        assert!(is_ipv4_packet_fragmented(&frag_offset));

        // Private / local IPv4 check for NetBIOS-NS 137 filtering
        assert!(is_private_or_local_ipv4(Ipv4Addr::new(192, 168, 1, 255)));
        assert!(is_private_or_local_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_or_local_ipv4(Ipv4Addr::new(169, 254, 10, 20)));
        assert!(is_private_or_local_ipv4(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(!is_private_or_local_ipv4(target_ip));
    }

    #[test]
    fn parses_ip_origdstaddr_cmsg_bytes_and_verifies_raw_udp_checksum() {
        let mut raw_sockaddr_in = [0u8; 16];
        raw_sockaddr_in[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        raw_sockaddr_in[2..4].copy_from_slice(&8853u16.to_be_bytes());
        raw_sockaddr_in[4..8].copy_from_slice(&[198, 18, 0, 42]);

        let parsed = parse_ipv4_origdstaddr_bytes(&raw_sockaddr_in).expect("valid IP_ORIGDSTADDR");
        assert_eq!(parsed.ip(), &Ipv4Addr::new(198, 18, 0, 42));
        assert_eq!(parsed.port(), 8853);

        // Wrong family (AF_INET6 = 10) or port 0 or truncated slice must return None
        let mut bad_family = raw_sockaddr_in;
        bad_family[0..2].copy_from_slice(&10u16.to_ne_bytes());
        assert!(parse_ipv4_origdstaddr_bytes(&bad_family).is_none());
        assert!(parse_ipv4_origdstaddr_bytes(&raw_sockaddr_in[..4]).is_none());

        // Verify RFC 768 UDP pseudo-header + payload checksum on raw forged IPv4+UDP reply
        let src_ip = Ipv4Addr::new(198, 18, 0, 42);
        let dst_ip = Ipv4Addr::new(10, 200, 1, 2);
        let payload = b"TPROXY-RAW-REPLY-PAYLOAD-42";
        let raw_pkt =
            build_forged_ipv4_udp_reply(src_ip, 8853, dst_ip, 54321, payload).expect("raw pkt");
        assert_eq!(ones_complement_checksum(&raw_pkt[..20], 0), 0);
        let udp_len = (raw_pkt.len() - 20) as u32;
        let mut pseudo_sum: u32 = 0;
        let mut addr_idx = 12;
        while addr_idx < 20 {
            pseudo_sum += u16::from_be_bytes([raw_pkt[addr_idx], raw_pkt[addr_idx + 1]]) as u32;
            addr_idx += 2;
        }
        pseudo_sum += (IPPROTO_UDP as u32) + udp_len;
        assert_eq!(ones_complement_checksum(&raw_pkt[20..], pseudo_sum), 0);
    }

    #[test]
    fn bounded_pending_udp_queue_resolves_evicts_and_times_out_per_killswitch() {
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        let queue: PendingUdpQueue<Vec<u8>> = PendingUdpQueue::new(2);

        let client_ip = Ipv4Addr::new(192, 168, 31, 136);
        let dst_ip = Ipv4Addr::new(162, 159, 200, 1);

        let pkt1 = build_forged_ipv4_udp_reply(client_ip, 52001, dst_ip, 123, b"ntp1").unwrap();
        let meta1 = parse_ipv4_udp_meta(&pkt1).unwrap();
        let pkt2 = build_forged_ipv4_udp_reply(client_ip, 52002, dst_ip, 123, b"ntp2").unwrap();
        let meta2 = parse_ipv4_udp_meta(&pkt2).unwrap();
        let pkt3 = build_forged_ipv4_udp_reply(client_ip, 52003, dst_ip, 123, b"ntp3").unwrap();
        let meta3 = parse_ipv4_udp_meta(&pkt3).unwrap();

        assert!(queue
            .enqueue(&nat, pkt1.clone(), meta1, false, true)
            .is_none());
        assert!(queue
            .enqueue(&nat, pkt2.clone(), meta2, false, true)
            .is_none());
        assert_eq!(queue.len(), 2);

        // Enqueuing a 3rd packet into a capacity-2 queue evicts the oldest packet (52001)
        let evicted = queue
            .enqueue(&nat, pkt3.clone(), meta3, false, true)
            .expect("oldest packet evicted when capacity exceeded");
        match evicted {
            PendingUdpOutcome::TimedOutDropped {
                meta, drop_count, ..
            } => {
                assert_eq!(meta.src_port, 52001);
                assert_eq!(drop_count, 1);
            }
            other => panic!("Expected TimedOutDropped on overflow, got {other:?}"),
        }
        assert_eq!(queue.len(), 2);

        // Late SOCKET event resolves 52002
        nat.record_socket_event(52002, 7744);
        let outcomes = queue.poll_ready(&nat, Duration::from_millis(50), true, |_| None);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0],
            PendingUdpOutcome::Resolved {
                payload: pkt2,
                meta: meta2,
                is_fragmented: false,
                pid: 7744,
                source: PidResolutionSource::SocketLayer,
            }
        );
        assert_eq!(queue.len(), 1);

        // Remaining packet (52003) expires: with killSwitchEnabled=true it is dropped
        let expired_drop = queue.poll_ready(&nat, Duration::ZERO, true, |_| None);
        assert_eq!(expired_drop.len(), 1);
        assert!(matches!(
            expired_drop[0],
            PendingUdpOutcome::TimedOutDropped { drop_count: 2, .. }
        ));
        assert_eq!(nat.dropped_unattributed_udp_count(), 2);

        // With killSwitchEnabled=false, expired packet is returned for reinjection
        queue.enqueue(&nat, pkt3.clone(), meta3, false, false);
        let expired_reinject = queue.poll_ready(&nat, Duration::ZERO, false, |_| None);
        assert_eq!(expired_reinject.len(), 1);
        match &expired_reinject[0] {
            PendingUdpOutcome::TimedOutReinject {
                payload,
                meta,
                reinject_count,
                ..
            } => {
                assert_eq!(payload, &pkt3);
                assert_eq!(meta.src_port, 52003);
                assert_eq!(*reinject_count, 1);
            }
            other => panic!("Expected TimedOutReinject, got {other:?}"),
        }
        assert_eq!(nat.reinjected_unattributed_udp_count(), 1);
    }
}
