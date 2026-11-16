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
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const IPV4_VERSION: u8 = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const IPV6_VERSION: u8 = 6;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_MIN_MTU: usize = 1280;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const ICMPV4_TYPE_DEST_UNREACHABLE: u8 = 3;
pub const ICMPV4_CODE_PORT_UNREACHABLE: u8 = 3;
const ICMPV4_HEADER_LEN: usize = 8;
pub const ICMPV6_TYPE_DEST_UNREACHABLE: u8 = 1;
pub const ICMPV6_CODE_PORT_UNREACHABLE: u8 = 4;
const ICMPV6_HEADER_LEN: usize = 8;
const IPV4_FRAG_MORE_OR_OFFSET_MASK: u16 = 0x3FFF;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const IPV6_EXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
const IPV6_FRAG_OFFSET_MASK: u16 = 0xFFF8;
const IPV6_FRAG_MORE_FLAG: u16 = 0x0001;
const IPV4_FRAG_OFFSET_MASK: u16 = 0x1FFF;
/// Maximum number of IPv6 extension headers walked while looking for a fragment header.
const IPV6_MAX_EXT_HEADERS: usize = 8;
/// Bytes of the UDP header needed to read the source and destination ports.
const UDP_PORTS_LEN: usize = 4;

/// Fallback `socket_pid_cache` TTL used until the daemon applies `socketPidCacheTtlMs` through
/// [`TransparentNatTable::configure`]. Mirrors the `system_constants.json` default.
const DEFAULT_SOCKET_PID_CACHE_TTL_MS: u64 = 5_000;
/// Fallback half-open NAT session TTL (mirrors `natHalfOpenSessionTtlSecs`).
const DEFAULT_NAT_HALF_OPEN_SESSION_TTL_SECS: u64 = 60;
/// Fallback UDP fragment verdict TTL (mirrors `udpFragmentVerdictTtlMs`).
const DEFAULT_UDP_FRAGMENT_VERDICT_TTL_MS: u64 = 10_000;
/// Fallback UDP fragment verdict capacity (mirrors `maxUdpFragmentVerdicts`).
const DEFAULT_MAX_UDP_FRAGMENT_VERDICTS: usize = 4_096;
/// Default bound of a [`PendingSynQueue`] built with [`PendingSynQueue::new`].
const DEFAULT_PENDING_SYN_QUEUE_CAPACITY: usize = 1_024;

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

/// Full 4-tuple key identifying an outbound IPv4 or IPv6 TCP connection from the local host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboundFlowKey {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

/// Key of the socket-to-PID cache: a local port only identifies one socket within a transport
/// protocol and an address family, so TCP/UDP and IPv4/IPv6 sockets sharing a port number never
/// inherit each other's owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketKey {
    /// IP protocol number (`IPPROTO_TCP` or `IPPROTO_UDP`).
    pub protocol: u8,
    /// `true` for an IPv6 socket, `false` for IPv4.
    pub ipv6: bool,
    pub local_port: u16,
}

impl SocketKey {
    pub fn new(protocol: u8, ipv6: bool, local_port: u16) -> Self {
        Self {
            protocol,
            ipv6,
            local_port,
        }
    }
}

/// Active NAT redirection entry keyed by the outbound 4-tuple and indexed by the reflected relay peer tuple.
#[derive(Debug, Clone)]
pub struct NatSessionEntry {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub orig_dst_ip: IpAddr,
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
    pub fn relay_peer_key(&self) -> (IpAddr, u16) {
        (self.orig_dst_ip, self.client_port)
    }
}

/// Trait exposing the source transport port and 4-tuple endpoints of a parsed L3/L4 packet metadata struct.
pub trait PacketSourcePort {
    /// Returns the packet's TCP or UDP source port.
    fn src_port(&self) -> u16;

    /// Returns `(src_ip, src_port, dst_ip, dst_port)` for logging and flow inspection.
    fn flow_endpoints(&self) -> (IpAddr, u16, IpAddr, u16);

    /// Returns the protocol, address family and source port identifying the sending socket.
    fn socket_key(&self) -> SocketKey;
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

impl PacketSourcePort for Ipv4TcpPacketMeta {
    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn flow_endpoints(&self) -> (IpAddr, u16, IpAddr, u16) {
        (
            IpAddr::V4(self.src_ip),
            self.src_port,
            IpAddr::V4(self.dst_ip),
            self.dst_port,
        )
    }

    fn socket_key(&self) -> SocketKey {
        SocketKey::new(IPPROTO_TCP, false, self.src_port)
    }
}

impl Ipv4TcpPacketMeta {
    /// Returns the outbound 4-tuple key `(src_ip, src_port, dst_ip, dst_port)` for this packet.
    pub fn outbound_flow_key(&self) -> OutboundFlowKey {
        OutboundFlowKey {
            local_ip: IpAddr::V4(self.src_ip),
            local_port: self.src_port,
            remote_ip: IpAddr::V4(self.dst_ip),
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

impl PacketSourcePort for Ipv4UdpPacketMeta {
    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn flow_endpoints(&self) -> (IpAddr, u16, IpAddr, u16) {
        (
            IpAddr::V4(self.src_ip),
            self.src_port,
            IpAddr::V4(self.dst_ip),
            self.dst_port,
        )
    }

    fn socket_key(&self) -> SocketKey {
        SocketKey::new(IPPROTO_UDP, false, self.src_port)
    }
}

/// Parsed IPv6 + TCP/UDP packet header and payload slice metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6TransportPacketMeta {
    pub next_header: u8,
    pub ip_header_len: usize,
    pub total_len: usize,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub tcp_flags: u8,
}

impl PacketSourcePort for Ipv6TransportPacketMeta {
    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn flow_endpoints(&self) -> (IpAddr, u16, IpAddr, u16) {
        (
            IpAddr::V6(self.src_ip),
            self.src_port,
            IpAddr::V6(self.dst_ip),
            self.dst_port,
        )
    }

    fn socket_key(&self) -> SocketKey {
        SocketKey::new(self.next_header, true, self.src_port)
    }
}

impl Ipv6TransportPacketMeta {
    /// Returns the outbound 4-tuple key `(src_ip, src_port, dst_ip, dst_port)` for this packet.
    pub fn outbound_flow_key(&self) -> OutboundFlowKey {
        OutboundFlowKey {
            local_ip: IpAddr::V6(self.src_ip),
            local_port: self.src_port,
            remote_ip: IpAddr::V6(self.dst_ip),
            remote_port: self.dst_port,
        }
    }

    /// Returns `true` if this packet is an initial TCP SYN (SYN set, ACK not set).
    pub fn is_syn_only(&self) -> bool {
        self.next_header == IPPROTO_TCP
            && (self.tcp_flags & TCP_FLAG_SYN) != 0
            && (self.tcp_flags & TCP_FLAG_ACK) == 0
    }

    /// Returns `true` if the FIN or RST flag is set on a TCP packet.
    pub fn is_fin_or_rst(&self) -> bool {
        self.next_header == IPPROTO_TCP && (self.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) != 0
    }
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
pub struct PendingSynEntry<T, M = Ipv4TcpPacketMeta> {
    pub payload: T,
    pub meta: M,
    pub enqueued_at: Instant,
}

/// Outcome of polling a queued SYN packet in `PendingSynQueue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingSynOutcome<T, M = Ipv4TcpPacketMeta> {
    /// PID was resolved before timeout via `SocketLayer` or `TcpTableFallback`.
    Resolved {
        payload: T,
        meta: M,
        pid: u32,
        source: PidResolutionSource,
    },
    /// Timeout expired without resolving a PID while `killSwitchEnabled=true`; the SYN payload is
    /// dropped without response so the client retransmits the SYN (~1 s later) after attribution succeeds.
    TimedOutDropped {
        meta: M,
        elapsed_ms: u64,
        drop_count: u64,
    },
    /// Timeout expired without resolving a PID while `killSwitchEnabled=false`; caller reinjects the SYN unmodified (fail-open).
    TimedOutReinject {
        payload: T,
        meta: M,
        elapsed_ms: u64,
        reinject_count: u64,
    },
}

/// Non-blocking queue holding unresolved outbound SYN packets so the main `NETWORK` receive loop never sleeps.
#[derive(Clone)]
pub struct PendingSynQueue<T, M = Ipv4TcpPacketMeta> {
    inner: Arc<Mutex<VecDeque<PendingSynEntry<T, M>>>>,
    max_capacity: usize,
}

impl<T, M> Default for PendingSynQueue<T, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, M> PendingSynQueue<T, M> {
    /// Creates an empty `PendingSynQueue` bounded to the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_PENDING_SYN_QUEUE_CAPACITY)
    }

    /// Creates an empty `PendingSynQueue` bounded to `max_capacity` entries (at least one).
    pub fn with_capacity(max_capacity: usize) -> Self {
        let cap = max_capacity.max(1);
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(cap.min(256)))),
            max_capacity: cap,
        }
    }

    /// Enqueues an unresolved SYN packet with the current timestamp. When the queue is full the
    /// oldest entry is evicted and returned so the caller can log it: the client retransmits the
    /// SYN, so dropping the oldest never lets a connection bypass attribution.
    pub fn enqueue(&self, payload: T, meta: M) -> Option<PendingSynEntry<T, M>> {
        let mut queue = self.inner.lock();
        let evicted = if queue.len() >= self.max_capacity {
            queue.pop_front()
        } else {
            None
        };
        queue.push_back(PendingSynEntry {
            payload,
            meta,
            enqueued_at: Instant::now(),
        });
        evicted
    }

    /// Returns the number of currently queued SYN packets.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Returns `true` if no SYN packets are waiting in the queue.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl<T, M: PacketSourcePort> PendingSynQueue<T, M> {
    /// Polls all queued SYN packets without sleeping, returning resolved, dropped (`killSwitchEnabled=true`),
    /// or reinjected (`killSwitchEnabled=false`) outcomes and keeping still-pending entries in the queue.
    pub fn poll_ready<F>(
        &self,
        nat: &TransparentNatTable,
        timeout: Duration,
        kill_switch_enabled: bool,
        fallback_fn: F,
    ) -> Vec<PendingSynOutcome<T, M>>
    where
        F: Fn(u16) -> Option<u32>,
    {
        // Take the snapshot under the lock and resolve outside it: the PID fallback walks the OS
        // socket table, which must never block the receive loop enqueueing new SYNs.
        let snapshot: VecDeque<PendingSynEntry<T, M>> = std::mem::take(&mut *self.inner.lock());
        let mut outcomes = Vec::new();
        let mut still_pending = VecDeque::new();
        let memo = memoize_fallback(fallback_fn);

        for entry in snapshot {
            if let Some((pid, source)) =
                nat.try_resolve_pid_nonblocking(entry.meta.socket_key(), &memo)
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
                    still_pending.push_back(entry);
                }
            }
        }

        if !still_pending.is_empty() {
            // Entries enqueued while resolving are newer: keep the pending ones in front.
            let mut queue = self.inner.lock();
            while let Some(entry) = still_pending.pop_back() {
                queue.push_front(entry);
            }
        }

        outcomes
    }
}

/// Wraps a PID fallback lookup so each distinct local port is resolved at most once per poll cycle.
fn memoize_fallback<F: Fn(u16) -> Option<u32>>(fallback_fn: F) -> impl Fn(u16) -> Option<u32> {
    let cache: std::cell::RefCell<HashMap<u16, Option<u32>>> =
        std::cell::RefCell::new(HashMap::new());
    move |port| {
        if let Some(hit) = cache.borrow().get(&port) {
            return *hit;
        }
        let resolved = fallback_fn(port);
        cache.borrow_mut().insert(port, resolved);
        resolved
    }
}

/// Queued outbound UDP packet awaiting asynchronous PID resolution outside the network receive loop.
#[derive(Debug, Clone)]
pub struct PendingUdpEntry<T, M = Ipv4UdpPacketMeta> {
    pub payload: T,
    pub meta: M,
    pub is_fragmented: bool,
    pub enqueued_at: Instant,
}

/// Outcome of polling or evicting a queued UDP packet in [`PendingUdpQueue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingUdpOutcome<T, M = Ipv4UdpPacketMeta> {
    /// PID was resolved before timeout via `SocketLayer` or `GetExtendedUdpTable` (`TcpTableFallback`).
    Resolved {
        payload: T,
        meta: M,
        is_fragmented: bool,
        pid: u32,
        source: PidResolutionSource,
    },
    /// Timeout expired or bounded queue overflowed while `killSwitchEnabled=true`; datagram is dropped.
    TimedOutDropped {
        meta: M,
        elapsed_ms: u64,
        drop_count: u64,
    },
    /// Timeout expired or bounded queue overflowed while `killSwitchEnabled=false`; caller reinjects datagram unmodified.
    TimedOutReinject {
        payload: T,
        meta: M,
        elapsed_ms: u64,
        reinject_count: u64,
    },
}

/// Bounded non-blocking queue holding unresolved first outbound UDP datagrams so the main `NETWORK` receive loop never sleeps.
#[derive(Clone)]
pub struct PendingUdpQueue<T, M = Ipv4UdpPacketMeta> {
    inner: Arc<Mutex<VecDeque<PendingUdpEntry<T, M>>>>,
    max_capacity: usize,
}

impl<T, M> Default for PendingUdpQueue<T, M> {
    fn default() -> Self {
        Self::new(256)
    }
}

impl<T, M> PendingUdpQueue<T, M> {
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
        meta: M,
        is_fragmented: bool,
        kill_switch_enabled: bool,
    ) -> Option<PendingUdpOutcome<T, M>> {
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
}

impl<T, M: PacketSourcePort> PendingUdpQueue<T, M> {
    /// Polls all queued UDP datagrams without sleeping, returning resolved, dropped (`killSwitchEnabled=true`),
    /// or reinjected (`killSwitchEnabled=false`) outcomes and keeping still-pending entries in the queue.
    pub fn poll_ready<F>(
        &self,
        nat: &TransparentNatTable,
        timeout: Duration,
        kill_switch_enabled: bool,
        fallback_fn: F,
    ) -> Vec<PendingUdpOutcome<T, M>>
    where
        F: Fn(u16) -> Option<u32>,
    {
        // Snapshot under the lock, resolve outside it (see `PendingSynQueue::poll_ready`).
        let snapshot: VecDeque<PendingUdpEntry<T, M>> = std::mem::take(&mut *self.inner.lock());
        let mut outcomes = Vec::new();
        let mut still_pending = VecDeque::new();
        let memo = memoize_fallback(fallback_fn);

        for entry in snapshot {
            if let Some((pid, source)) =
                nat.try_resolve_pid_nonblocking(entry.meta.socket_key(), &memo)
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
                    still_pending.push_back(entry);
                }
            }
        }

        if !still_pending.is_empty() {
            let mut queue = self.inner.lock();
            while let Some(entry) = still_pending.pop_back() {
                queue.push_front(entry);
            }
        }

        outcomes
    }
}

/// Thread-safe NAT state table and loop-prevention registry for transparent TCP redirection.
#[derive(Clone)]
pub struct TransparentNatTable {
    socket_pid_cache: Arc<DashMap<SocketKey, (u32, Instant)>>,
    socket_cache_ttl_ms: Arc<AtomicU64>,
    half_open_session_ttl_secs: Arc<AtomicU64>,
    fragment_verdict_ttl_ms: Arc<AtomicU64>,
    fragment_verdict_capacity: Arc<AtomicUsize>,
    udp_fragment_verdicts: Arc<DashMap<UdpFragmentKey, (UdpFragmentVerdict, Instant)>>,
    /// Flows whose reflected SYN has been accepted by the local relay; the sweep never expires them.
    adopted_flows: Arc<DashMap<OutboundFlowKey, ()>>,
    self_udp_ports: Arc<DashMap<u16, Instant>>,
    self_tcp_ports: Arc<DashMap<u16, Instant>>,
    sessions_by_flow: Arc<DashMap<OutboundFlowKey, NatSessionEntry>>,
    peer_to_flow: Arc<DashMap<(IpAddr, u16), OutboundFlowKey>>,
    self_pid: u32,
    transparent_relay_port: u16,
    local_socks_port: u16,
    local_http_port: u16,
    upstream_endpoints: Arc<RwLock<Vec<(IpAddr, u16)>>>,
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
            socket_cache_ttl_ms: Arc::new(AtomicU64::new(DEFAULT_SOCKET_PID_CACHE_TTL_MS)),
            half_open_session_ttl_secs: Arc::new(AtomicU64::new(
                DEFAULT_NAT_HALF_OPEN_SESSION_TTL_SECS,
            )),
            fragment_verdict_ttl_ms: Arc::new(AtomicU64::new(DEFAULT_UDP_FRAGMENT_VERDICT_TTL_MS)),
            fragment_verdict_capacity: Arc::new(AtomicUsize::new(
                DEFAULT_MAX_UDP_FRAGMENT_VERDICTS,
            )),
            udp_fragment_verdicts: Arc::new(DashMap::new()),
            adopted_flows: Arc::new(DashMap::new()),
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

    /// Applies the tunable lifetimes of the socket-to-PID cache, half-open NAT sessions and UDP
    /// fragment verdicts (`socketPidCacheTtlMs`, `natHalfOpenSessionTtlSecs`,
    /// `udpFragmentVerdictTtlMs`, `maxUdpFragmentVerdicts`). Clones of the table share the values.
    pub fn configure(
        &self,
        socket_cache_ttl: Duration,
        half_open_session_ttl: Duration,
        fragment_verdict_ttl: Duration,
        fragment_verdict_capacity: usize,
    ) {
        self.socket_cache_ttl_ms
            .store(socket_cache_ttl.as_millis() as u64, Ordering::Relaxed);
        self.half_open_session_ttl_secs
            .store(half_open_session_ttl.as_secs(), Ordering::Relaxed);
        self.fragment_verdict_ttl_ms
            .store(fragment_verdict_ttl.as_millis() as u64, Ordering::Relaxed);
        self.fragment_verdict_capacity
            .store(fragment_verdict_capacity.max(1), Ordering::Relaxed);
    }

    fn socket_cache_ttl(&self) -> Duration {
        Duration::from_millis(self.socket_cache_ttl_ms.load(Ordering::Relaxed))
    }

    /// Returns the configured half-open NAT session TTL.
    pub fn half_open_session_ttl(&self) -> Duration {
        Duration::from_secs(self.half_open_session_ttl_secs.load(Ordering::Relaxed))
    }

    /// Records the verdict applied to the first fragment of a UDP datagram so later fragments of
    /// the same datagram (same addresses, protocol and identification) receive the same verdict.
    pub fn record_udp_fragment_verdict(&self, key: UdpFragmentKey, verdict: UdpFragmentVerdict) {
        let capacity = self.fragment_verdict_capacity.load(Ordering::Relaxed);
        if self.udp_fragment_verdicts.len() >= capacity {
            let ttl = Duration::from_millis(self.fragment_verdict_ttl_ms.load(Ordering::Relaxed));
            self.udp_fragment_verdicts
                .retain(|_, (_, at)| at.elapsed() < ttl);
            if self.udp_fragment_verdicts.len() >= capacity {
                let victim = self.udp_fragment_verdicts.iter().next().map(|e| *e.key());
                if let Some(victim) = victim {
                    self.udp_fragment_verdicts.remove(&victim);
                }
            }
        }
        self.udp_fragment_verdicts
            .insert(key, (verdict, Instant::now()));
    }

    /// Returns the cached verdict for a fragment's datagram, if one was recorded within the TTL.
    pub fn lookup_udp_fragment_verdict(&self, key: &UdpFragmentKey) -> Option<UdpFragmentVerdict> {
        let ttl = Duration::from_millis(self.fragment_verdict_ttl_ms.load(Ordering::Relaxed));
        let entry = self.udp_fragment_verdicts.get(key)?;
        let (verdict, at) = *entry.value();
        drop(entry);
        if at.elapsed() < ttl {
            Some(verdict)
        } else {
            self.udp_fragment_verdicts.remove(key);
            None
        }
    }

    /// Removes expired socket-to-PID cache entries, half-open NAT sessions that never reached the
    /// local relay and expired UDP fragment verdicts. Returns the number of removed NAT sessions.
    pub fn sweep_expired(&self) -> usize {
        let socket_ttl = self.socket_cache_ttl();
        self.socket_pid_cache
            .retain(|_, (_, at)| at.elapsed() < socket_ttl);
        let verdict_ttl =
            Duration::from_millis(self.fragment_verdict_ttl_ms.load(Ordering::Relaxed));
        self.udp_fragment_verdicts
            .retain(|_, (_, at)| at.elapsed() < verdict_ttl);
        self.sweep_expired_sessions(self.half_open_session_ttl())
    }

    /// Removes NAT sessions older than `ttl` whose reflected SYN was never accepted by the local
    /// relay (half-open). Sessions adopted by a live relay connection are removed by the relay on
    /// close and are never expired here, so long-lived connections keep working.
    pub fn sweep_expired_sessions(&self, ttl: Duration) -> usize {
        let expired: Vec<OutboundFlowKey> = self
            .sessions_by_flow
            .iter()
            .filter(|e| {
                e.value().created_at.elapsed() >= ttl && !self.adopted_flows.contains_key(e.key())
            })
            .map(|e| *e.key())
            .collect();
        let mut removed = 0;
        for flow_key in expired {
            if let Some((_, entry)) = self.sessions_by_flow.remove(&flow_key) {
                let peer_key = entry.relay_peer_key();
                // Only unlink the peer index when it still points at this flow.
                self.peer_to_flow
                    .remove_if(&peer_key, |_, mapped| *mapped == flow_key);
                removed += 1;
            }
        }
        self.adopted_flows
            .retain(|flow, _| self.sessions_by_flow.contains_key(flow));
        removed
    }

    /// Returns the number of tracked NAT sessions.
    pub fn session_count(&self) -> usize {
        self.sessions_by_flow.len()
    }

    /// Registers a local UDP port bound by RouteWard itself so `WinDivert` passes its packets through without interception.
    pub fn register_self_udp_port(&self, port: u16) -> SelfPortGuard {
        let now = Instant::now();
        self.self_udp_ports.insert(port, now);
        for ipv6 in [false, true] {
            self.socket_pid_cache.insert(
                SocketKey::new(IPPROTO_UDP, ipv6, port),
                (self.self_pid, now),
            );
        }
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
        for ipv6 in [false, true] {
            self.socket_pid_cache.insert(
                SocketKey::new(IPPROTO_TCP, ipv6, port),
                (self.self_pid, now),
            );
        }
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

    /// Updates the list of upstream proxy endpoints excluded from interception to avoid loops.
    pub fn set_upstream_endpoints(&self, endpoints: Vec<(IpAddr, u16)>) {
        *self.upstream_endpoints.write() = endpoints;
    }

    /// Returns a snapshot of the upstream proxy endpoints excluded from interception.
    pub fn upstream_endpoints(&self) -> Vec<(IpAddr, u16)> {
        self.upstream_endpoints.read().clone()
    }

    /// Records a `(protocol, family, local_port) -> pid` mapping observed on `WINDIVERT_LAYER_SOCKET`.
    pub fn record_socket_event(&self, key: SocketKey, pid: u32) {
        if key.local_port != 0 && pid != 0 {
            self.socket_pid_cache.insert(key, (pid, Instant::now()));
        }
    }

    /// Forgets the owner of a socket that has been closed so a process reusing the port number
    /// never inherits the previous owner's rule. Only an entry recorded for the closing `pid` is removed.
    pub fn record_socket_close(&self, key: SocketKey, pid: u32) {
        self.socket_pid_cache
            .remove_if(&key, |_, (cached_pid, _)| pid == 0 || *cached_pid == pid);
    }

    /// Attempts to resolve the owning PID for a socket immediately without sleeping.
    ///
    /// First checks the `SOCKET` layer cache; if absent, performs a single non-blocking call to `fallback_fn`.
    pub fn try_resolve_pid_nonblocking<F>(
        &self,
        key: SocketKey,
        fallback_fn: F,
    ) -> Option<(u32, PidResolutionSource)>
    where
        F: Fn(u16) -> Option<u32>,
    {
        if let Some(entry) = self.socket_pid_cache.get(&key) {
            if entry.value().1.elapsed() <= self.socket_cache_ttl() {
                return Some((entry.value().0, PidResolutionSource::SocketLayer));
            }
        }

        if let Some(pid) = fallback_fn(key.local_port) {
            if pid != 0 {
                self.record_socket_event(key, pid);
                return Some((pid, PidResolutionSource::TcpTableFallback));
            }
        }

        None
    }

    /// Returns `true` when `pid` matches RouteWard's own process ID.
    pub fn is_self_pid(&self, pid: Option<u32>) -> bool {
        pid == Some(self.self_pid)
    }

    /// Checks whether a connection must bypass interception to prevent routing loops.
    pub fn is_loop_or_excluded(
        &self,
        pid: Option<u32>,
        src_ip: impl Into<IpAddr>,
        src_port: u16,
        dst_ip: impl Into<IpAddr>,
        dst_port: u16,
    ) -> bool {
        if pid == Some(self.self_pid)
            || self.is_self_tcp_port(src_port)
            || self.is_self_udp_port(src_port)
        {
            return true;
        }
        let src_ip = src_ip.into();
        let dst_ip = dst_ip.into();
        let addr_excluded = |ip: IpAddr| match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_multicast()
                    || v6.is_unspecified()
                    || v6.is_unicast_link_local()
            }
        };
        if addr_excluded(src_ip) || addr_excluded(dst_ip) {
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
        // A re-inserted flow (new SYN on a reused 4-tuple) starts half-open again.
        self.adopted_flows.remove(&flow_key);
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
        peer_ip: impl Into<IpAddr>,
        peer_port: u16,
    ) -> Option<NatSessionEntry> {
        let flow_key = *self.peer_to_flow.get(&(peer_ip.into(), peer_port))?.value();
        self.get_session_by_flow(&flow_key)
    }

    /// Validates a peer `SocketAddr` accepted by the transparent TCP relay against live NAT sessions.
    ///
    /// A validated peer has reached the local relay, so its session is marked as adopted and is no
    /// longer subject to the half-open expiry sweep.
    pub fn validate_relay_peer_addr(&self, peer_addr: SocketAddr) -> Option<NatSessionEntry> {
        let session = self.get_session_by_relay_peer(peer_addr.ip(), peer_addr.port())?;
        self.adopted_flows.insert(session.outbound_flow_key(), ());
        Some(session)
    }

    /// Removes the NAT session entry associated with the reflected relay peer `(peer_ip, peer_port)`.
    pub fn remove_session_by_relay_peer(
        &self,
        peer_ip: impl Into<IpAddr>,
        peer_port: u16,
    ) -> Option<NatSessionEntry> {
        let (_, flow_key) = self.peer_to_flow.remove(&(peer_ip.into(), peer_port))?;
        self.adopted_flows.remove(&flow_key);
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

    let ipv6_payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = IPV6_HEADER_LEN.checked_add(ipv6_payload_len)?;
    if packet.len() < total_len {
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
                if total_len < offset + TCP_MIN_HEADER_LEN {
                    return None;
                }
                let data_offset = ((packet[offset + 12] >> 4) as usize) * 4;
                if data_offset < TCP_MIN_HEADER_LEN || offset + data_offset > total_len {
                    return None;
                }
                let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
                let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                let tcp_flags = packet[offset + 13];
                let payload_offset = offset + data_offset;
                let payload_len = total_len - payload_offset;
                return Some(Ipv6TransportPacketMeta {
                    next_header,
                    ip_header_len: offset,
                    total_len,
                    src_ip: Ipv6Addr::from(src_octets),
                    dst_ip: Ipv6Addr::from(dst_octets),
                    src_port,
                    dst_port,
                    payload_offset,
                    payload_len,
                    tcp_flags,
                });
            }
            IPPROTO_UDP => {
                if total_len < offset + UDP_HEADER_LEN {
                    return None;
                }
                let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
                let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                let udp_len = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]) as usize;
                if udp_len < UDP_HEADER_LEN || offset + udp_len > total_len {
                    return None;
                }
                let payload_offset = offset + UDP_HEADER_LEN;
                let payload_len = udp_len - UDP_HEADER_LEN;
                return Some(Ipv6TransportPacketMeta {
                    next_header,
                    ip_header_len: offset,
                    total_len,
                    src_ip: Ipv6Addr::from(src_octets),
                    dst_ip: Ipv6Addr::from(dst_octets),
                    src_port,
                    dst_port,
                    payload_offset,
                    payload_len,
                    tcp_flags: 0,
                });
            }
            0 | 43 | 60 => {
                let hdr = packet.get(offset..offset + 2)?;
                let ext_len = ((hdr[1] as usize) + 1) * 8;
                next_header = hdr[0];
                offset = offset.checked_add(ext_len)?;
                if offset > total_len {
                    return None;
                }
            }
            44 => {
                let hdr = packet.get(offset..offset + 8)?;
                let frag_offset = u16::from_be_bytes([hdr[2], hdr[3]]) & 0xFFF8;
                if frag_offset != 0 {
                    return None;
                }
                next_header = hdr[0];
                offset = offset.checked_add(8)?;
                if offset > total_len {
                    return None;
                }
            }
            _ => return None,
        }
    }

    None
}

/// Parses an IPv6 + TCP packet buffer and returns its metadata.
pub fn parse_ipv6_tcp_meta(packet: &[u8]) -> Option<Ipv6TransportPacketMeta> {
    let meta = parse_ipv6_transport_meta(packet)?;
    (meta.next_header == IPPROTO_TCP).then_some(meta)
}

/// Parses an IPv6 + UDP packet buffer and returns its metadata.
pub fn parse_ipv6_udp_meta(packet: &[u8]) -> Option<Ipv6TransportPacketMeta> {
    let meta = parse_ipv6_transport_meta(packet)?;
    (meta.next_header == IPPROTO_UDP).then_some(meta)
}

/// Position of a packet inside a fragmented UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpFragmentKind {
    /// Fragment offset 0: carries the UDP header, so ports are known.
    First,
    /// Fragment offset > 0: carries no UDP header; ports are unknown (reported as 0).
    NonFirst,
}

/// Identifies one fragmented datagram: addresses, IP protocol and the IPv4 identification
/// (zero-extended) or IPv6 fragment identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpFragmentKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: u8,
    pub fragment_id: u32,
}

/// Metadata of a fragmented IPv4 or IPv6 UDP packet, parsed without requiring the UDP length to
/// fit inside this fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpFragmentMeta {
    pub kind: UdpFragmentKind,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    /// Source port; 0 for [`UdpFragmentKind::NonFirst`].
    pub src_port: u16,
    /// Destination port; 0 for [`UdpFragmentKind::NonFirst`].
    pub dst_port: u16,
    pub fragment_id: u32,
}

impl UdpFragmentMeta {
    /// Returns the datagram key shared by every fragment of this datagram.
    pub fn key(&self) -> UdpFragmentKey {
        UdpFragmentKey {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            protocol: IPPROTO_UDP,
            fragment_id: self.fragment_id,
        }
    }
}

/// Action applied to every fragment of a UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpFragmentVerdict {
    /// Reinject the fragment unmodified (the datagram leaves directly).
    Reinject,
    /// Discard the fragment.
    Drop,
}

/// Decides what happens to a fragmented UDP datagram whose rule evaluated to `action`.
///
/// Fragments cannot be reassembled for relaying, so a proxied or chained flow is dropped when the
/// kill switch is on (never leaked in clear) and released directly when it is off; `Direct` rules
/// pass and `Block` rules are dropped.
pub fn decide_udp_fragment_verdict(
    action: &RuleAction,
    kill_switch_enabled: bool,
) -> UdpFragmentVerdict {
    match action {
        RuleAction::Direct => UdpFragmentVerdict::Reinject,
        RuleAction::Block => UdpFragmentVerdict::Drop,
        RuleAction::Proxy { .. } | RuleAction::Chain { .. } => {
            if kill_switch_enabled {
                UdpFragmentVerdict::Drop
            } else {
                UdpFragmentVerdict::Reinject
            }
        }
    }
}

/// Detects a fragmented UDP packet (IPv4 `MF` flag or non-zero offset, IPv6 fragment header with
/// `M` flag or non-zero offset) and returns its metadata, or `None` for unfragmented or non-UDP
/// packets. Unlike [`parse_ipv4_udp_meta`], a first fragment whose UDP length exceeds the
/// fragment size is accepted: only the four port bytes of the UDP header are required.
pub fn parse_udp_fragment_meta(packet: &[u8]) -> Option<UdpFragmentMeta> {
    match packet.first()? >> 4 {
        IPV4_VERSION => parse_ipv4_udp_fragment_meta(packet),
        IPV6_VERSION => parse_ipv6_udp_fragment_meta(packet),
        _ => None,
    }
}

fn read_udp_ports(packet: &[u8], offset: usize) -> Option<(u16, u16)> {
    let ports = packet.get(offset..offset.checked_add(UDP_PORTS_LEN)?)?;
    Some((
        u16::from_be_bytes([ports[0], ports[1]]),
        u16::from_be_bytes([ports[2], ports[3]]),
    ))
}

fn parse_ipv4_udp_fragment_meta(packet: &[u8]) -> Option<UdpFragmentMeta> {
    if packet.len() < IPV4_MIN_HEADER_LEN || packet[9] != IPPROTO_UDP {
        return None;
    }
    let frag_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (frag_field & IPV4_FRAG_MORE_OR_OFFSET_MASK) == 0 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || packet.len() < ihl {
        return None;
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let fragment_id = u16::from_be_bytes([packet[4], packet[5]]) as u32;
    if (frag_field & IPV4_FRAG_OFFSET_MASK) != 0 {
        return Some(UdpFragmentMeta {
            kind: UdpFragmentKind::NonFirst,
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            fragment_id,
        });
    }
    let (src_port, dst_port) = read_udp_ports(packet, ihl)?;
    Some(UdpFragmentMeta {
        kind: UdpFragmentKind::First,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        fragment_id,
    })
}

/// Where the UDP header sits inside the first fragment of an IPv6 datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv6FragmentPayload {
    /// The UDP header starts at this packet offset.
    Udp(usize),
    /// The datagram carries another transport protocol.
    NotUdp,
    /// The datagram may be UDP but its header cannot be located (further extension headers that
    /// are truncated or too numerous).
    Unparseable,
}

/// Returns true for extension headers that share the generic `next header, length` layout.
fn is_ipv6_walkable_ext_header(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 60)
}

/// Walks the extension headers that follow an IPv6 fragment header (starting at `offset` with
/// `next_header`) to find the UDP header of a first fragment.
fn locate_ipv6_fragment_udp_header(
    packet: &[u8],
    mut offset: usize,
    mut next_header: u8,
    total_len: usize,
) -> Ipv6FragmentPayload {
    for _ in 0..IPV6_MAX_EXT_HEADERS {
        if next_header == IPPROTO_UDP {
            return Ipv6FragmentPayload::Udp(offset);
        }
        if !is_ipv6_walkable_ext_header(next_header) {
            return Ipv6FragmentPayload::NotUdp;
        }
        let Some(hdr) = packet.get(offset..offset.saturating_add(2)) else {
            return Ipv6FragmentPayload::Unparseable;
        };
        next_header = hdr[0];
        offset = offset.saturating_add(((hdr[1] as usize) + 1) * 8);
        if offset > total_len {
            return Ipv6FragmentPayload::Unparseable;
        }
    }
    if next_header == IPPROTO_UDP {
        Ipv6FragmentPayload::Udp(offset)
    } else {
        Ipv6FragmentPayload::Unparseable
    }
}

fn parse_ipv6_udp_fragment_meta(packet: &[u8]) -> Option<UdpFragmentMeta> {
    if packet.len() < IPV6_HEADER_LEN {
        return None;
    }
    let total_len =
        IPV6_HEADER_LEN.checked_add(u16::from_be_bytes([packet[4], packet[5]]) as usize)?;
    if packet.len() < total_len {
        return None;
    }
    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&packet[8..24]);
    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&packet[24..40]);

    let mut next_header = packet[6];
    let mut offset = IPV6_HEADER_LEN;
    for _ in 0..IPV6_MAX_EXT_HEADERS {
        match next_header {
            0 | 43 | 60 => {
                let hdr = packet.get(offset..offset.checked_add(2)?)?;
                next_header = hdr[0];
                offset = offset.checked_add(((hdr[1] as usize) + 1) * 8)?;
                if offset > total_len {
                    return None;
                }
            }
            IPV6_EXT_HEADER_FRAGMENT => {
                let hdr = packet.get(offset..offset.checked_add(IPV6_FRAGMENT_HEADER_LEN)?)?;
                let frag_field = u16::from_be_bytes([hdr[2], hdr[3]]);
                let frag_offset = frag_field & IPV6_FRAG_OFFSET_MASK;
                let more = (frag_field & IPV6_FRAG_MORE_FLAG) != 0;
                if frag_offset == 0 && !more {
                    // An atomic fragment that the regular parser handles.
                    return None;
                }
                let payload_start = offset.checked_add(IPV6_FRAGMENT_HEADER_LEN)?;
                let payload = if frag_offset == 0 {
                    locate_ipv6_fragment_udp_header(packet, payload_start, hdr[0], total_len)
                } else if hdr[0] == IPPROTO_UDP || is_ipv6_walkable_ext_header(hdr[0]) {
                    // Later fragments carry no transport header: the next-header value of the
                    // fragment header is all that identifies the datagram.
                    Ipv6FragmentPayload::Unparseable
                } else {
                    Ipv6FragmentPayload::NotUdp
                };
                if matches!(payload, Ipv6FragmentPayload::NotUdp) {
                    return None;
                }
                let fragment_id = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
                let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets));
                let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_octets));
                if frag_offset != 0 {
                    return Some(UdpFragmentMeta {
                        kind: UdpFragmentKind::NonFirst,
                        src_ip,
                        dst_ip,
                        src_port: 0,
                        dst_port: 0,
                        fragment_id,
                    });
                }
                // A first fragment that is detected but whose UDP header cannot be located is
                // reported with ports 0, so it is treated as unattributed (unknown-process policy
                // and kill switch apply) instead of being reinjected unevaluated.
                let (src_port, dst_port) = match payload {
                    Ipv6FragmentPayload::Udp(udp_offset) => {
                        read_udp_ports(packet, udp_offset).unwrap_or((0, 0))
                    }
                    _ => (0, 0),
                };
                return Some(UdpFragmentMeta {
                    kind: UdpFragmentKind::First,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    fragment_id,
                });
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
    let (IpAddr::V4(orig_dst_ip), IpAddr::V4(client_ip)) = (entry.orig_dst_ip, entry.client_ip)
    else {
        return false;
    };
    let Some(meta) = parse_ipv4_tcp_meta(packet) else {
        return false;
    };
    let ihl = meta.ip_header_len;

    // Restore original server IPv4 as source and client IPv4 as destination
    packet[12..16].copy_from_slice(&orig_dst_ip.octets());
    packet[16..20].copy_from_slice(&client_ip.octets());

    // Restore original destination port as TCP source port and client port as destination
    packet[ihl..ihl + 2].copy_from_slice(&entry.orig_dst_port.to_be_bytes());
    packet[ihl + 2..ihl + 4].copy_from_slice(&entry.client_port.to_be_bytes());

    recompute_ipv4_and_tcp_checksums(&mut packet[..meta.total_len], ihl);
    true
}

fn ipv6_pseudo_header_sum(packet: &[u8], upper_layer_len: u32, next_header: u8) -> u32 {
    let mut sum: u32 = 0;
    let mut idx = 8;
    while idx < 40 {
        sum += u16::from_be_bytes([packet[idx], packet[idx + 1]]) as u32;
        idx += 2;
    }
    sum += upper_layer_len >> 16;
    sum += upper_layer_len & 0xFFFF;
    sum += next_header as u32;
    sum
}

/// Computes and writes RFC 8200 / RFC 9293 IPv6 pseudo-header TCP checksum in place.
pub fn recompute_ipv6_and_tcp_checksums(packet: &mut [u8], tcp_offset: usize) {
    let tcp_len = packet.len() - tcp_offset;
    packet[tcp_offset + 16] = 0;
    packet[tcp_offset + 17] = 0;
    let sum = ipv6_pseudo_header_sum(packet, tcp_len as u32, IPPROTO_TCP);
    let tcp_csum = ones_complement_checksum(&packet[tcp_offset..], sum);
    packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_csum.to_be_bytes());
}

/// Computes and writes RFC 8200 IPv6 pseudo-header UDP checksum (`0x0000 -> 0xFFFF`) in place.
pub fn recompute_ipv6_and_udp_checksums(packet: &mut [u8], udp_offset: usize) {
    let udp_len = packet.len() - udp_offset;
    packet[udp_offset + 6] = 0;
    packet[udp_offset + 7] = 0;
    let sum = ipv6_pseudo_header_sum(packet, udp_len as u32, IPPROTO_UDP);
    let mut udp_csum = ones_complement_checksum(&packet[udp_offset..], sum);
    if udp_csum == 0 {
        udp_csum = 0xFFFF;
    }
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_csum.to_be_bytes());
}

/// Rewrites an outbound IPv6 client TCP packet (`A:C -> B:D`) using WinDivert `streamdump`
/// reflection (`B:C -> A:relay_port`) and updates the IPv6 TCP checksum.
pub fn reflect_outbound_ipv6_to_local_relay(packet: &mut [u8], relay_port: u16) -> bool {
    let Some(meta) = parse_ipv6_tcp_meta(packet) else {
        return false;
    };
    let tcp_offset = meta.ip_header_len;
    packet[8..24].copy_from_slice(&meta.dst_ip.octets());
    packet[24..40].copy_from_slice(&meta.src_ip.octets());
    packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&relay_port.to_be_bytes());
    recompute_ipv6_and_tcp_checksums(&mut packet[..meta.total_len], tcp_offset);
    true
}

/// Rewrites an outbound IPv6 reply packet from the local transparent relay (`A:relay_port -> B:C`)
/// back into a reflected inbound packet (`B:D -> A:C`) addressed to the original client socket.
pub fn reflect_relay_reply_ipv6_to_client(packet: &mut [u8], entry: &NatSessionEntry) -> bool {
    let (IpAddr::V6(orig_dst_ip), IpAddr::V6(client_ip)) = (entry.orig_dst_ip, entry.client_ip)
    else {
        return false;
    };
    let Some(meta) = parse_ipv6_tcp_meta(packet) else {
        return false;
    };
    let tcp_offset = meta.ip_header_len;
    packet[8..24].copy_from_slice(&orig_dst_ip.octets());
    packet[24..40].copy_from_slice(&client_ip.octets());
    packet[tcp_offset..tcp_offset + 2].copy_from_slice(&entry.orig_dst_port.to_be_bytes());
    packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&entry.client_port.to_be_bytes());
    recompute_ipv6_and_tcp_checksums(&mut packet[..meta.total_len], tcp_offset);
    true
}

/// Builds a complete IPv6 + UDP reply packet (`src_ip:src_port -> dst_ip:dst_port`) with a valid
/// RFC 8200 IPv6 pseudo-header UDP checksum (`0x0000 -> 0xFFFF`).
pub fn build_forged_ipv6_udp_reply(
    src_ip: Ipv6Addr,
    src_port: u16,
    dst_ip: Ipv6Addr,
    dst_port: u16,
    udp_payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN.checked_add(udp_payload.len())?;
    if udp_len > u16::MAX as usize {
        return None;
    }
    let total_len = IPV6_HEADER_LEN.checked_add(udp_len)?;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = IPPROTO_UDP;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());

    let udp_offset = IPV6_HEADER_LEN;
    pkt[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[udp_offset + UDP_HEADER_LEN..].copy_from_slice(udp_payload);

    recompute_ipv6_and_udp_checksums(&mut pkt, udp_offset);
    Some(pkt)
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

/// Parses a raw 28-byte Linux `sockaddr_in6` payload from an `IPV6_ORIGDSTADDR` (`SOL_IPV6`, `74`)
/// ancillary control message (`CMSG_DATA`) into `SocketAddrV6`.
pub fn parse_ipv6_origdstaddr_bytes(cmsg_data: &[u8]) -> Option<SocketAddrV6> {
    if cmsg_data.len() < 28 {
        return None;
    }
    let family = u16::from_ne_bytes([cmsg_data[0], cmsg_data[1]]);
    if family != 10 {
        return None;
    }
    let port = u16::from_be_bytes([cmsg_data[2], cmsg_data[3]]);
    if port == 0 {
        return None;
    }
    let flowinfo = u32::from_ne_bytes([cmsg_data[4], cmsg_data[5], cmsg_data[6], cmsg_data[7]]);
    let mut addr_bytes = [0u8; 16];
    addr_bytes.copy_from_slice(&cmsg_data[8..24]);
    let scope_id = u32::from_ne_bytes([cmsg_data[24], cmsg_data[25], cmsg_data[26], cmsg_data[27]]);
    Some(SocketAddrV6::new(
        Ipv6Addr::from(addr_bytes),
        port,
        flowinfo,
        scope_id,
    ))
}

/// Builds a forged RFC 4443 ICMPv6 Destination Unreachable / Port Unreachable (`Type = 1`, `Code = 4`)
/// packet in response to `original_ipv6_packet`, quoting as much of the invoking packet as fits within 1280 bytes.
pub fn build_forged_ipv6_icmpv6_port_unreachable(original_ipv6_packet: &[u8]) -> Option<Vec<u8>> {
    if original_ipv6_packet.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN
        || (original_ipv6_packet[0] >> 4) != IPV6_VERSION
    {
        return None;
    }
    let mut orig_src = [0u8; 16];
    orig_src.copy_from_slice(&original_ipv6_packet[8..24]);
    let mut orig_dst = [0u8; 16];
    orig_dst.copy_from_slice(&original_ipv6_packet[24..40]);

    let max_quoted = IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMPV6_HEADER_LEN;
    let quoted_len = original_ipv6_packet.len().min(max_quoted);
    let icmp_len = ICMPV6_HEADER_LEN + quoted_len;
    let total_len = IPV6_HEADER_LEN + icmp_len;

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    pkt[6] = IPPROTO_ICMPV6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&orig_dst);
    pkt[24..40].copy_from_slice(&orig_src);

    let icmp_offset = IPV6_HEADER_LEN;
    pkt[icmp_offset] = ICMPV6_TYPE_DEST_UNREACHABLE;
    pkt[icmp_offset + 1] = ICMPV6_CODE_PORT_UNREACHABLE;
    pkt[icmp_offset + ICMPV6_HEADER_LEN..].copy_from_slice(&original_ipv6_packet[..quoted_len]);

    let sum = ipv6_pseudo_header_sum(&pkt, icmp_len as u32, IPPROTO_ICMPV6);
    let icmp_csum = ones_complement_checksum(&pkt[icmp_offset..], sum);
    pkt[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    Some(pkt)
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
        assert!(nat
            .try_resolve_pid_nonblocking(SocketKey::new(IPPROTO_TCP, false, 51001), |_| None)
            .is_none());
        queue.enqueue(pkt_resolved.clone(), meta_resolved);
        queue.enqueue(pkt_timeout.clone(), meta_timeout);
        assert_eq!(queue.len(), 2);

        // Poll 1: neither is resolved yet, timeout (50 ms) has not elapsed -> both remain queued
        let outcomes_1 = queue.poll_ready(&nat, Duration::from_millis(50), true, |_| None);
        assert!(outcomes_1.is_empty());
        assert_eq!(queue.len(), 2);

        // Late SOCKET event arrives for port 51001
        nat.record_socket_event(SocketKey::new(IPPROTO_TCP, false, 51001), 4632);
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
            client_ip: IpAddr::V4(local_ip),
            client_port: 55000,
            orig_dst_ip: IpAddr::V4(remote_ip_a),
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
            local_ip: IpAddr::V4(local_ip),
            local_port: 55000,
            remote_ip: IpAddr::V4(remote_ip_a),
            remote_port: 80,
        };
        assert!(nat.get_session_by_flow(&key_a).is_some());

        // Different remote IP or remote port on the same local port does NOT falsely match
        let key_different_remote = OutboundFlowKey {
            local_ip: IpAddr::V4(local_ip),
            local_port: 55000,
            remote_ip: IpAddr::V4(remote_ip_b),
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
        nat.set_upstream_endpoints(vec![(IpAddr::V4(upstream_ip), 1080)]);

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
            client_ip: IpAddr::V4(client_ip),
            client_port,
            orig_dst_ip: IpAddr::V4(orig_dst_ip),
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
        nat.record_socket_event(SocketKey::new(IPPROTO_UDP, false, 52002), 7744);
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

    #[test]
    fn ipv6_reflection_udp_checksum_and_icmpv6_unreachable_work_cleanly() {
        let client_ip: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let server_ip: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let client_port = 51234u16;
        let server_port = 443u16;
        let relay_port = 10810u16;

        // IPv6 + Hop-by-Hop ext (8 bytes) + TCP SYN
        let mut syn_v6 = vec![0u8; 40 + 8 + 20];
        syn_v6[0] = 0x60;
        syn_v6[4..6].copy_from_slice(&28u16.to_be_bytes());
        syn_v6[6] = 0; // Hop-by-Hop Options
        syn_v6[7] = 64;
        syn_v6[8..24].copy_from_slice(&client_ip.octets());
        syn_v6[24..40].copy_from_slice(&server_ip.octets());
        syn_v6[40] = IPPROTO_TCP;
        syn_v6[41] = 0; // 8 bytes total
        syn_v6[48..50].copy_from_slice(&client_port.to_be_bytes());
        syn_v6[50..52].copy_from_slice(&server_port.to_be_bytes());
        syn_v6[60] = 0x50;
        syn_v6[61] = TCP_FLAG_SYN;
        recompute_ipv6_and_tcp_checksums(&mut syn_v6, 48);

        let meta = parse_ipv6_tcp_meta(&syn_v6).expect("parse IPv6 TCP SYN with ext header");
        assert!(meta.is_syn_only());
        assert_eq!(meta.ip_header_len, 48);

        assert!(reflect_outbound_ipv6_to_local_relay(
            &mut syn_v6,
            relay_port
        ));
        let reflected = parse_ipv6_tcp_meta(&syn_v6).expect("reflected IPv6 TCP");
        assert_eq!(reflected.src_ip, server_ip);
        assert_eq!(reflected.dst_ip, client_ip);
        assert_eq!(reflected.src_port, client_port);
        assert_eq!(reflected.dst_port, relay_port);

        let session = NatSessionEntry {
            client_ip: IpAddr::V6(client_ip),
            client_port,
            orig_dst_ip: IpAddr::V6(server_ip),
            orig_dst_port: server_port,
            pid: 9001,
            process_name: "curl".to_string(),
            process_path: "/usr/bin/curl".to_string(),
            resolution_source: PidResolutionSource::SocketLayer,
            action: RuleAction::Direct,
            matched_rule_name: "Direct".to_string(),
            created_at: Instant::now(),
        };
        let nat = TransparentNatTable::new(1, relay_port, 10808, 10809);
        nat.insert_session(session.clone());
        assert!(nat
            .validate_relay_peer_addr(SocketAddr::new(IpAddr::V6(server_ip), client_port))
            .is_some());

        assert!(reflect_relay_reply_ipv6_to_client(&mut syn_v6, &session));
        let restored = parse_ipv6_tcp_meta(&syn_v6).expect("restored IPv6 TCP");
        assert_eq!(restored.src_ip, server_ip);
        assert_eq!(restored.dst_ip, client_ip);
        assert_eq!(restored.src_port, server_port);
        assert_eq!(restored.dst_port, client_port);

        // IPv6 UDP forged reply & ICMPv6 Port Unreachable
        let udp_pkt = build_forged_ipv6_udp_reply(client_ip, 55000, server_ip, 443, b"QUIC-V6")
            .expect("forged IPv6 UDP");
        let udp_meta = parse_ipv6_udp_meta(&udp_pkt).expect("parse IPv6 UDP");
        assert_eq!(
            &udp_pkt[udp_meta.payload_offset..udp_meta.payload_offset + udp_meta.payload_len],
            b"QUIC-V6"
        );
        let icmp6 = build_forged_ipv6_icmpv6_port_unreachable(&udp_pkt)
            .expect("build ICMPv6 Port Unreachable");
        assert_eq!(icmp6[6], IPPROTO_ICMPV6);
        assert_eq!(icmp6[40], ICMPV6_TYPE_DEST_UNREACHABLE);
        assert_eq!(icmp6[41], ICMPV6_CODE_PORT_UNREACHABLE);
        let sum = ipv6_pseudo_header_sum(&icmp6, (icmp6.len() - 40) as u32, IPPROTO_ICMPV6);
        assert_eq!(ones_complement_checksum(&icmp6[40..], sum), 0);

        // IPV6_ORIGDSTADDR decoding
        let mut raw_sa6 = [0u8; 28];
        raw_sa6[0..2].copy_from_slice(&10u16.to_ne_bytes());
        raw_sa6[2..4].copy_from_slice(&8853u16.to_be_bytes());
        raw_sa6[8..24].copy_from_slice(&server_ip.octets());
        let sa6 = parse_ipv6_origdstaddr_bytes(&raw_sa6).expect("parse IPV6_ORIGDSTADDR");
        assert_eq!(*sa6.ip(), server_ip);
        assert_eq!(sa6.port(), 8853);
    }

    /// Builds a first IPv4 UDP fragment: 20-byte IP header + 1480 bytes of a 3000-byte datagram.
    fn build_ipv4_first_udp_fragment(src_port: u16, dst_port: u16, ident: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 1480];
        pkt[0] = 0x45;
        let total_len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[4..6].copy_from_slice(&ident.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IPPROTO_UDP;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 25]);
        pkt[16..20].copy_from_slice(&[93, 184, 215, 14]);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&3000u16.to_be_bytes());
        pkt
    }

    #[test]
    fn first_ipv4_udp_fragment_is_detected_and_gets_the_kill_switch_decision() {
        let first = build_ipv4_first_udp_fragment(50123, 9999, 0xBEEF);
        // The regular parser rejects it (UDP length exceeds the fragment): this was the leak.
        assert!(parse_ipv4_udp_meta(&first).is_none());

        let meta = parse_udp_fragment_meta(&first).expect("first fragment detected");
        assert_eq!(meta.kind, UdpFragmentKind::First);
        assert_eq!(meta.src_port, 50123);
        assert_eq!(meta.dst_port, 9999);
        assert_eq!(meta.fragment_id, 0xBEEF);

        let proxy = RuleAction::Proxy {
            target_id: "p".to_string(),
        };
        let chain = RuleAction::Chain {
            target_id: "c".to_string(),
        };
        assert_eq!(
            decide_udp_fragment_verdict(&proxy, true),
            UdpFragmentVerdict::Drop
        );
        assert_eq!(
            decide_udp_fragment_verdict(&chain, true),
            UdpFragmentVerdict::Drop
        );
        assert_eq!(
            decide_udp_fragment_verdict(&proxy, false),
            UdpFragmentVerdict::Reinject
        );
        assert_eq!(
            decide_udp_fragment_verdict(&RuleAction::Direct, true),
            UdpFragmentVerdict::Reinject
        );
        assert_eq!(
            decide_udp_fragment_verdict(&RuleAction::Block, false),
            UdpFragmentVerdict::Drop
        );

        // A later fragment of the same datagram has no ports but shares the cached verdict.
        let mut second = first.clone();
        second[6..8].copy_from_slice(&0x00B9u16.to_be_bytes());
        let later = parse_udp_fragment_meta(&second).expect("non-first fragment detected");
        assert_eq!(later.kind, UdpFragmentKind::NonFirst);
        assert_eq!(later.key(), meta.key());

        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        assert!(nat.lookup_udp_fragment_verdict(&later.key()).is_none());
        nat.record_udp_fragment_verdict(meta.key(), UdpFragmentVerdict::Drop);
        assert_eq!(
            nat.lookup_udp_fragment_verdict(&later.key()),
            Some(UdpFragmentVerdict::Drop)
        );
        // A different identification is a different datagram.
        let other = parse_udp_fragment_meta(&build_ipv4_first_udp_fragment(50123, 9999, 0xBEF0))
            .expect("other datagram");
        assert!(nat.lookup_udp_fragment_verdict(&other.key()).is_none());
    }

    #[test]
    fn unfragmented_and_non_udp_packets_are_not_fragments() {
        let whole = build_forged_ipv4_udp_reply(
            Ipv4Addr::new(10, 0, 0, 1),
            1000,
            Ipv4Addr::new(10, 0, 0, 2),
            2000,
            b"x",
        )
        .unwrap();
        assert!(parse_udp_fragment_meta(&whole).is_none());
        let mut tcp_frag = build_ipv4_first_udp_fragment(1, 2, 3);
        tcp_frag[9] = IPPROTO_TCP;
        assert!(parse_udp_fragment_meta(&tcp_frag).is_none());
        assert!(parse_udp_fragment_meta(&[]).is_none());
    }

    #[test]
    fn ipv6_first_and_later_udp_fragments_are_detected() {
        let mut pkt = vec![0u8; 40 + 8 + 8];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&16u16.to_be_bytes());
        pkt[6] = IPV6_EXT_HEADER_FRAGMENT;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        pkt[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        pkt[40] = IPPROTO_UDP;
        pkt[42..44].copy_from_slice(&0x0001u16.to_be_bytes()); // offset 0, M=1
        pkt[44..48].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        pkt[48..50].copy_from_slice(&40000u16.to_be_bytes());
        pkt[50..52].copy_from_slice(&5000u16.to_be_bytes());
        pkt[52..54].copy_from_slice(&4000u16.to_be_bytes()); // UDP length > fragment
                                                             // The regular IPv6 parser rejects the truncated first fragment.
        assert!(parse_ipv6_udp_meta(&pkt).is_none());

        let first = parse_udp_fragment_meta(&pkt).expect("IPv6 first fragment");
        assert_eq!(first.kind, UdpFragmentKind::First);
        assert_eq!((first.src_port, first.dst_port), (40000, 5000));
        assert_eq!(first.fragment_id, 0xCAFEBABE);

        pkt[42..44].copy_from_slice(&0x00B9u16.to_be_bytes()); // offset 184, M=1
        let later = parse_udp_fragment_meta(&pkt).expect("IPv6 later fragment");
        assert_eq!(later.kind, UdpFragmentKind::NonFirst);
        assert_eq!(later.key(), first.key());

        // Atomic fragment (offset 0, M=0) is left to the regular parser.
        pkt[42..44].copy_from_slice(&0u16.to_be_bytes());
        assert!(parse_udp_fragment_meta(&pkt).is_none());
    }

    #[test]
    fn ipv6_first_fragment_followed_by_extension_header_is_never_reinjected_unevaluated() {
        // IPv6 header, fragment header (next = destination options), destination options
        // (next = UDP), UDP ports.
        let mut pkt = vec![0u8; 40 + 8 + 8 + 8];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&24u16.to_be_bytes());
        pkt[6] = IPV6_EXT_HEADER_FRAGMENT;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        pkt[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        pkt[40] = 60;
        pkt[42..44].copy_from_slice(&0x0001u16.to_be_bytes()); // offset 0, M=1
        pkt[44..48].copy_from_slice(&0x0BADF00Du32.to_be_bytes());
        pkt[48] = IPPROTO_UDP; // destination options: next header
        pkt[49] = 0; // 8 bytes long
        pkt[56..58].copy_from_slice(&40000u16.to_be_bytes());
        pkt[58..60].copy_from_slice(&5000u16.to_be_bytes());

        let first = parse_udp_fragment_meta(&pkt).expect("first fragment with extension header");
        assert_eq!(first.kind, UdpFragmentKind::First);
        assert_eq!((first.src_port, first.dst_port), (40000, 5000));

        // Extension header running past the packet: still detected, reported unattributed.
        pkt[49] = 100;
        let unparsed = parse_udp_fragment_meta(&pkt).expect("detected but unparseable");
        assert_eq!(unparsed.kind, UdpFragmentKind::First);
        assert_eq!((unparsed.src_port, unparsed.dst_port), (0, 0));
        assert_eq!(unparsed.fragment_id, 0x0BADF00D);

        // Later fragment of the same datagram shares the key.
        pkt[42..44].copy_from_slice(&0x00B9u16.to_be_bytes());
        let later = parse_udp_fragment_meta(&pkt).expect("later fragment");
        assert_eq!(later.kind, UdpFragmentKind::NonFirst);
        assert_eq!(later.key(), unparsed.key());

        // A non-UDP payload behind the extension header is not a UDP fragment.
        pkt[42..44].copy_from_slice(&0x0001u16.to_be_bytes());
        pkt[49] = 0;
        pkt[48] = IPPROTO_TCP;
        assert!(parse_udp_fragment_meta(&pkt).is_none());
    }

    #[test]
    fn fragment_verdicts_expire_and_stay_bounded() {
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        nat.configure(
            Duration::from_secs(5),
            Duration::from_secs(60),
            Duration::from_millis(30),
            2,
        );
        let key = |id: u32| UdpFragmentKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            protocol: IPPROTO_UDP,
            fragment_id: id,
        };
        nat.record_udp_fragment_verdict(key(1), UdpFragmentVerdict::Drop);
        assert_eq!(
            nat.lookup_udp_fragment_verdict(&key(1)),
            Some(UdpFragmentVerdict::Drop)
        );
        std::thread::sleep(Duration::from_millis(60));
        assert!(nat.lookup_udp_fragment_verdict(&key(1)).is_none());

        for id in 10..20 {
            nat.record_udp_fragment_verdict(key(id), UdpFragmentVerdict::Reinject);
        }
        assert!(nat.udp_fragment_verdicts.len() <= 2);
    }

    #[test]
    fn socket_pid_cache_is_keyed_by_protocol_family_and_port_and_forgets_closed_sockets() {
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        let tcp4 = SocketKey::new(IPPROTO_TCP, false, 40000);
        let udp4 = SocketKey::new(IPPROTO_UDP, false, 40000);
        let tcp6 = SocketKey::new(IPPROTO_TCP, true, 40000);
        nat.record_socket_event(tcp4, 111);

        assert_eq!(
            nat.try_resolve_pid_nonblocking(tcp4, |_| None),
            Some((111, PidResolutionSource::SocketLayer))
        );
        // Same port number, other protocol or address family: no inherited owner.
        assert!(nat.try_resolve_pid_nonblocking(udp4, |_| None).is_none());
        assert!(nat.try_resolve_pid_nonblocking(tcp6, |_| None).is_none());

        // A Close event of another PID must not evict the owner; the owner's Close does.
        nat.record_socket_close(tcp4, 222);
        assert!(nat.try_resolve_pid_nonblocking(tcp4, |_| None).is_some());
        nat.record_socket_close(tcp4, 111);
        assert!(nat.try_resolve_pid_nonblocking(tcp4, |_| None).is_none());
    }

    #[test]
    fn socket_pid_cache_entries_expire_after_the_configured_ttl() {
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        nat.configure(
            Duration::from_millis(20),
            Duration::from_secs(60),
            Duration::from_secs(10),
            16,
        );
        let key = SocketKey::new(IPPROTO_UDP, false, 41000);
        nat.record_socket_event(key, 77);
        assert!(nat.try_resolve_pid_nonblocking(key, |_| None).is_some());
        std::thread::sleep(Duration::from_millis(50));
        assert!(nat.try_resolve_pid_nonblocking(key, |_| None).is_none());
        nat.sweep_expired();
        assert!(nat.socket_pid_cache.is_empty());
    }

    fn sample_session(client_port: u16, created_at: Instant) -> NatSessionEntry {
        NatSessionEntry {
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25)),
            client_port,
            orig_dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)),
            orig_dst_port: 443,
            pid: 1,
            process_name: "x.exe".to_string(),
            process_path: "x.exe".to_string(),
            resolution_source: PidResolutionSource::SocketLayer,
            action: RuleAction::Direct,
            matched_rule_name: "r".to_string(),
            created_at,
        }
    }

    #[test]
    fn half_open_sessions_expire_but_sessions_adopted_by_the_relay_survive() {
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        let old = Instant::now() - Duration::from_secs(120);
        nat.insert_session(sample_session(50001, old));
        nat.insert_session(sample_session(50002, old));
        nat.insert_session(sample_session(50003, Instant::now()));
        assert_eq!(nat.session_count(), 3);

        // The relay accepted 50002: it is a live connection, however old.
        let peer = (IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)), 50002);
        assert!(nat
            .validate_relay_peer_addr(SocketAddr::new(peer.0, peer.1))
            .is_some());

        assert_eq!(nat.sweep_expired(), 1);
        assert_eq!(nat.session_count(), 2);
        assert!(nat
            .get_session_by_relay_peer(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)), 50001)
            .is_none());
        assert!(nat
            .get_session_by_relay_peer(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)), 50002)
            .is_some());

        // Closing the adopted session removes it for good.
        assert!(nat.remove_session_by_relay_peer(peer.0, peer.1).is_some());
        assert_eq!(nat.session_count(), 1);
    }

    #[test]
    fn pending_syn_queue_is_bounded_and_evicts_the_oldest_entry() {
        let queue: PendingSynQueue<Vec<u8>> = PendingSynQueue::with_capacity(2);
        let client_ip = Ipv4Addr::new(192, 168, 31, 136);
        let dst_ip = Ipv4Addr::new(93, 184, 215, 14);
        let mut metas = Vec::new();
        for port in [51101u16, 51102, 51103] {
            let pkt = build_sample_ipv4_tcp_syn(client_ip, dst_ip, port, 80);
            metas.push((pkt.clone(), parse_ipv4_tcp_meta(&pkt).unwrap()));
        }
        assert!(queue.enqueue(metas[0].0.clone(), metas[0].1).is_none());
        assert!(queue.enqueue(metas[1].0.clone(), metas[1].1).is_none());
        let evicted = queue
            .enqueue(metas[2].0.clone(), metas[2].1)
            .expect("oldest SYN evicted at capacity");
        assert_eq!(evicted.meta.src_port, 51101);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn poll_ready_resolves_outside_the_lock_and_memoizes_the_fallback_per_port() {
        use std::sync::atomic::AtomicUsize;
        let nat = TransparentNatTable::new(9999, 10810, 10808, 10809);
        let queue: PendingSynQueue<Vec<u8>> = PendingSynQueue::new();
        let client_ip = Ipv4Addr::new(192, 168, 31, 136);
        let dst_ip = Ipv4Addr::new(93, 184, 215, 14);
        // Three SYNs from the same local port (retransmissions) and one from another.
        for port in [51201u16, 51201, 51201, 51202] {
            let pkt = build_sample_ipv4_tcp_syn(client_ip, dst_ip, port, 80);
            queue.enqueue(pkt.clone(), parse_ipv4_tcp_meta(&pkt).unwrap());
        }
        let calls = AtomicUsize::new(0);
        let outcomes = queue.poll_ready(&nat, Duration::from_secs(5), true, |port| {
            calls.fetch_add(1, Ordering::SeqCst);
            (port == 51201).then_some(4321)
        });
        assert_eq!(outcomes.len(), 3);
        // One table lookup per distinct port, never one per queued entry.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // The unresolved SYN stays queued, and enqueueing remains possible afterwards.
        assert_eq!(queue.len(), 1);
    }
}
