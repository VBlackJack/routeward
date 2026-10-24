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

use crate::config::{ChainStrategy, ProtocolConstants, ProxyNode, ProxyProtocol, SystemConstants};
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_CHAIN_EMPTY, ERR_KEY_CONNECTION_TIMEOUT,
    ERR_KEY_HANDSHAKE_FAILED, ERR_KEY_UDP_NOT_SUPPORTED,
};
use crate::interceptor::nat::{SelfPortGuard, TransparentNatTable};
use crate::proxy::ProxyConnector;
use dashmap::DashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::timeout;

const SOCKS5_UDP_MIN_HEADER_LEN: usize = 4;
const SOCKS5_UDP_IPV4_HEADER_LEN: usize = 10;
const SOCKS5_UDP_IPV6_HEADER_LEN: usize = 22;
const DEFAULT_UDP_DATAGRAM_READ_TIMEOUT_MS: u64 = 3500;
const MAX_UDP_DATAGRAM_BYTES: usize = 65535;

/// Target endpoint carried inside an RFC 1928 §7 SOCKS5 UDP request/reply header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5UdpTarget {
    /// `ATYP = 0x01`: IPv4 address and 16-bit port.
    Ipv4(Ipv4Addr, u16),
    /// `ATYP = 0x03`: Domain name (1..=255 bytes) and 16-bit port.
    Domain(String, u16),
    /// `ATYP = 0x04`: IPv6 address and 16-bit port.
    Ipv6(Ipv6Addr, u16),
}

impl Socks5UdpTarget {
    /// Constructs a [`Socks5UdpTarget`] from a host or IP literal string and port.
    pub fn from_host_and_port(host: &str, port: u16) -> Self {
        let trimmed = host.trim();
        if let Ok(ip) = IpAddr::from_str(trimmed) {
            match ip {
                IpAddr::V4(v4) => Self::Ipv4(v4, port),
                IpAddr::V6(v6) => Self::Ipv6(v6, port),
            }
        } else {
            Self::Domain(trimmed.to_string(), port)
        }
    }

    /// Returns the host or IP string representation of this target.
    pub fn host_string(&self) -> String {
        match self {
            Self::Ipv4(ip, _) => ip.to_string(),
            Self::Domain(d, _) => d.clone(),
            Self::Ipv6(ip, _) => ip.to_string(),
        }
    }

    /// Returns the destination or source port of this target.
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, port) | Self::Domain(_, port) | Self::Ipv6(_, port) => *port,
        }
    }
}

/// Errors returned when encoding or decoding an RFC 1928 §7 SOCKS5 UDP datagram header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5UdpCodecError {
    PacketTooShort,
    NonZeroReservedField(u16),
    FragmentationNotSupported(u8),
    UnsupportedAddressType(u8),
    InvalidDomainLength,
    InvalidDomainUtf8,
}

impl fmt::Display for Socks5UdpCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "SOCKS5 UDP packet shorter than header"),
            Self::NonZeroReservedField(rsv) => {
                write!(f, "SOCKS5 UDP reserved field RSV is non-zero (0x{rsv:04x})")
            }
            Self::FragmentationNotSupported(frag) => {
                write!(f, "SOCKS5 UDP fragmentation is not supported (FRAG={frag})")
            }
            Self::UnsupportedAddressType(atyp) => {
                write!(f, "unsupported SOCKS5 UDP ATYP 0x{atyp:02x}")
            }
            Self::InvalidDomainLength => {
                write!(
                    f,
                    "SOCKS5 UDP domain length must be between 1 and 255 bytes"
                )
            }
            Self::InvalidDomainUtf8 => write!(f, "SOCKS5 UDP domain is not valid UTF-8"),
        }
    }
}

impl std::error::Error for Socks5UdpCodecError {}

/// Encapsulates a raw UDP payload into an RFC 1928 §7 SOCKS5 UDP datagram (`RSV=0x0000`, `FRAG=0x00`).
pub fn encode_socks5_udp_datagram(
    target: &Socks5UdpTarget,
    payload: &[u8],
    proto: &ProtocolConstants,
) -> Result<Vec<u8>, Socks5UdpCodecError> {
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV (2 bytes) = 0, FRAG (1 byte) = 0

    match target {
        Socks5UdpTarget::Ipv4(ip, port) => {
            out.push(proto.socks5_atyp_ipv4);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5UdpTarget::Domain(domain, port) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(Socks5UdpCodecError::InvalidDomainLength);
            }
            out.push(proto.socks5_atyp_domain);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5UdpTarget::Ipv6(ip, port) => {
            out.push(proto.socks5_atyp_ipv6);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }

    out.extend_from_slice(payload);
    Ok(out)
}

/// Decapsulates an RFC 1928 §7 SOCKS5 UDP datagram, rejecting `RSV != 0`, `FRAG != 0`, and malformed headers without panic.
pub fn decode_socks5_udp_datagram<'a>(
    packet: &'a [u8],
    proto: &ProtocolConstants,
) -> Result<(Socks5UdpTarget, &'a [u8]), Socks5UdpCodecError> {
    if packet.len() < SOCKS5_UDP_MIN_HEADER_LEN {
        return Err(Socks5UdpCodecError::PacketTooShort);
    }

    let rsv = u16::from_be_bytes([packet[0], packet[1]]);
    if rsv != 0 {
        return Err(Socks5UdpCodecError::NonZeroReservedField(rsv));
    }

    let frag = packet[2];
    if frag != 0 {
        return Err(Socks5UdpCodecError::FragmentationNotSupported(frag));
    }

    let atyp = packet[3];
    if atyp == proto.socks5_atyp_ipv4 {
        if packet.len() < SOCKS5_UDP_IPV4_HEADER_LEN {
            return Err(Socks5UdpCodecError::PacketTooShort);
        }
        let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
        let port = u16::from_be_bytes([packet[8], packet[9]]);
        Ok((Socks5UdpTarget::Ipv4(ip, port), &packet[10..]))
    } else if atyp == proto.socks5_atyp_domain {
        let Some(&domain_len_u8) = packet.get(4) else {
            return Err(Socks5UdpCodecError::PacketTooShort);
        };
        let domain_len = domain_len_u8 as usize;
        if domain_len == 0 {
            return Err(Socks5UdpCodecError::InvalidDomainLength);
        }
        let header_end = 5usize.saturating_add(domain_len).saturating_add(2);
        if packet.len() < header_end {
            return Err(Socks5UdpCodecError::PacketTooShort);
        }
        let domain_slice = &packet[5..5 + domain_len];
        let domain_str = std::str::from_utf8(domain_slice)
            .map_err(|_| Socks5UdpCodecError::InvalidDomainUtf8)?
            .to_string();
        let port_offset = 5 + domain_len;
        let port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        Ok((
            Socks5UdpTarget::Domain(domain_str, port),
            &packet[header_end..],
        ))
    } else if atyp == proto.socks5_atyp_ipv6 {
        if packet.len() < SOCKS5_UDP_IPV6_HEADER_LEN {
            return Err(Socks5UdpCodecError::PacketTooShort);
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&packet[4..20]);
        let ip = Ipv6Addr::from(octets);
        let port = u16::from_be_bytes([packet[20], packet[21]]);
        Ok((Socks5UdpTarget::Ipv6(ip, port), &packet[22..]))
    } else {
        Err(Socks5UdpCodecError::UnsupportedAddressType(atyp))
    }
}

#[derive(Debug, Clone)]
struct UnsupportedNodeEntry {
    expires_at: Instant,
    warn_logged: bool,
}

/// Per-proxy-node cache memorizing `UDP ASSOCIATE` refusal (`REP = 0x07` or unsupported protocol)
/// with a configurable TTL and guaranteeing at most one `WARN` log per node while cached.
#[derive(Clone)]
pub struct UdpCapabilityCache {
    entries: Arc<DashMap<String, UnsupportedNodeEntry>>,
    ttl: Duration,
}

impl UdpCapabilityCache {
    /// Creates a new `UdpCapabilityCache` with the given retention `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            ttl,
        }
    }

    /// Returns `true` if `proxy_id` is currently memorized as not supporting `UDP ASSOCIATE`.
    pub fn is_marked_unsupported(&self, proxy_id: &str) -> bool {
        if let Some(entry) = self.entries.get(proxy_id) {
            if Instant::now() < entry.expires_at {
                return true;
            }
        }
        self.entries.remove(proxy_id);
        false
    }

    /// Marks `proxy_id` as not supporting `UDP ASSOCIATE` for `self.ttl`.
    ///
    /// Returns `true` if the caller should emit the single `WARN` log for this node, or `false`
    /// if a `WARN` has already been emitted during the active TTL window.
    pub fn mark_unsupported(&self, proxy_id: &str) -> bool {
        let now = Instant::now();
        let next_expiry = now + self.ttl;

        if let Some(mut existing) = self.entries.get_mut(proxy_id) {
            if now < existing.expires_at && existing.warn_logged {
                return false;
            }
            existing.expires_at = next_expiry;
            existing.warn_logged = true;
            return true;
        }

        self.entries.insert(
            proxy_id.to_string(),
            UnsupportedNodeEntry {
                expires_at: next_expiry,
                warn_logged: true,
            },
        );
        true
    }

    /// Clears all cached capability entries.
    pub fn clear(&self) {
        self.entries.clear();
    }
}

/// Key indexing a SOCKS5 `UDP ASSOCIATE` session by `(client_socket, proxy_node_id)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpAssociationKey {
    pub client_addr: SocketAddr,
    pub proxy_id: String,
}

/// Active SOCKS5 `UDP ASSOCIATE` session bound to a single `(client_addr, proxy_id)` pair.
pub struct UdpAssociationSession {
    pub key: UdpAssociationKey,
    pub proxy_name: String,
    pub relay_udp_addr: SocketAddr,
    pub udp_socket: Arc<UdpSocket>,
    io_lock: tokio::sync::Mutex<()>,
    control_alive: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    last_activity_ms: AtomicU64,
    _udp_port_guard: Option<SelfPortGuard>,
    _tcp_port_guard: Option<SelfPortGuard>,
}

impl UdpAssociationSession {
    /// Returns `true` if the underlying SOCKS5 TCP control connection is still open.
    pub fn is_control_alive(&self) -> bool {
        self.control_alive.load(Ordering::Acquire)
    }

    fn touch(&self, now_ms: u64) {
        self.last_activity_ms.store(now_ms, Ordering::Release);
    }

    fn last_activity_ms(&self) -> u64 {
        self.last_activity_ms.load(Ordering::Acquire)
    }
}

impl Drop for UdpAssociationSession {
    fn drop(&mut self) {
        self.control_alive.store(false, Ordering::Release);
        self.shutdown_notify.notify_waiters();
    }
}

/// Result of exchanging a single UDP datagram through a SOCKS5 `UDP ASSOCIATE` session.
#[derive(Debug, Clone)]
pub struct UdpProxiedDatagramReply {
    pub payload: Vec<u8>,
    pub remote_source: Socks5UdpTarget,
    pub proxy_id: String,
    pub proxy_name: String,
}

/// Manages active SOCKS5 `UDP ASSOCIATE` sessions indexed by `(client_socket, proxy_node_id)`,
/// enforcing idle expiration, maximum table capacity with oldest-idle eviction, TCP control channel
/// monitoring, and per-node `UDP ASSOCIATE` refusal caching.
#[derive(Clone)]
pub struct UdpAssociationManager {
    sessions: Arc<DashMap<UdpAssociationKey, Arc<UdpAssociationSession>>>,
    capability_cache: UdpCapabilityCache,
    epoch: Instant,
    idle_timeout_ms: u64,
    max_associations: usize,
}

impl UdpAssociationManager {
    /// Creates a new `UdpAssociationManager` from the given `SystemConstants`.
    pub fn new(constants: &SystemConstants) -> Self {
        Self::with_limits(
            Duration::from_secs(constants.network.udp_association_idle_timeout_secs.max(1)),
            constants.network.max_udp_associations.max(1),
            Duration::from_secs(constants.network.udp_capability_cache_secs.max(1)),
        )
    }

    /// Creates a `UdpAssociationManager` with explicit timeout and capacity parameters (used by unit tests).
    pub fn with_limits(
        idle_timeout: Duration,
        max_associations: usize,
        capability_cache_ttl: Duration,
    ) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            capability_cache: UdpCapabilityCache::new(capability_cache_ttl),
            epoch: Instant::now(),
            idle_timeout_ms: idle_timeout.as_millis().max(1) as u64,
            max_associations: max_associations.max(1),
        }
    }

    /// Returns a reference to the per-node `UDP ASSOCIATE` capability cache.
    pub fn capability_cache(&self) -> &UdpCapabilityCache {
        &self.capability_cache
    }

    /// Returns the number of currently active associations after evicting dead or expired entries.
    pub fn active_count(&self) -> usize {
        self.evict_expired_and_dead();
        self.sessions.len()
    }

    /// Clears all active UDP associations and closes their TCP control channels.
    pub fn clear_all(&self) {
        self.sessions.clear();
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Evicts any association whose TCP control channel closed or whose idle time exceeded `idle_timeout_ms`.
    pub fn evict_expired_and_dead(&self) -> usize {
        let now_ms = self.now_ms();
        let idle_limit = self.idle_timeout_ms;
        let stale_keys: Vec<UdpAssociationKey> = self
            .sessions
            .iter()
            .filter(|entry| {
                let s = entry.value();
                !s.is_control_alive() || now_ms.saturating_sub(s.last_activity_ms()) >= idle_limit
            })
            .map(|entry| entry.key().clone())
            .collect();

        let count = stale_keys.len();
        for key in stale_keys {
            self.sessions.remove(&key);
        }
        count
    }

    fn evict_oldest_idle(&self) -> bool {
        let oldest_key = self
            .sessions
            .iter()
            .min_by_key(|entry| entry.value().last_activity_ms())
            .map(|entry| entry.key().clone());

        if let Some(key) = oldest_key {
            self.sessions.remove(&key);
            true
        } else {
            false
        }
    }

    /// Inserts an established `UdpAssociationSession` into the table, evicting expired/dead entries
    /// first and evicting the oldest idle session if the table is at `max_associations`.
    pub fn insert_session(&self, session: Arc<UdpAssociationSession>) {
        self.evict_expired_and_dead();
        while self.sessions.len() >= self.max_associations {
            if !self.evict_oldest_idle() {
                break;
            }
        }
        self.sessions.insert(session.key.clone(), session);
    }

    /// Retrieves a live, non-expired association for `(client_addr, proxy_id)` if one exists,
    /// updating its last-activity timestamp.
    pub fn get_live_session(
        &self,
        client_addr: SocketAddr,
        proxy_id: &str,
    ) -> Option<Arc<UdpAssociationSession>> {
        self.evict_expired_and_dead();
        let key = UdpAssociationKey {
            client_addr,
            proxy_id: proxy_id.to_string(),
        };
        let session = self.sessions.get(&key).map(|e| Arc::clone(e.value()))?;
        if !session.is_control_alive() {
            self.sessions.remove(&key);
            return None;
        }
        session.touch(self.now_ms());
        Some(session)
    }

    /// Binds a local UDP socket configured with `SO_MARK` on Linux and registered in `nat_table`
    /// so RouteWard's own UDP relay packets bypass transparent interception.
    pub async fn bind_marked_udp_socket(
        fwmark: u32,
        nat_table: Option<&TransparentNatTable>,
    ) -> std::io::Result<(UdpSocket, Option<SelfPortGuard>)> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        #[cfg(target_os = "linux")]
        if fwmark != 0 {
            use std::os::fd::AsRawFd;
            let mark: libc::c_uint = fwmark;
            unsafe {
                let _ = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const libc::c_uint as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = fwmark;

        let guard = match (nat_table, socket.local_addr()) {
            (Some(nat), Ok(addr)) => Some(nat.register_self_udp_port(addr.port())),
            _ => None,
        };
        Ok((socket, guard))
    }

    /// Retrieves an existing live `UDP ASSOCIATE` session for `(client_addr, node.id)` or negotiates
    /// a new one with `node`.
    ///
    /// If `node` is not a SOCKS5 proxy, has `udp_enabled == false`, or refuses `UDP ASSOCIATE` (`REP = 0x07`),
    /// the refusal is memorized in `capability_cache` and `on_first_unsupported_warn` is called at most once
    /// per node TTL window.
    pub async fn get_or_create_for_node<F>(
        &self,
        client_addr: SocketAddr,
        node: &ProxyNode,
        constants: &SystemConstants,
        nat_table: Option<&TransparentNatTable>,
        mut on_first_unsupported_warn: F,
    ) -> RouteWardResult<Arc<UdpAssociationSession>>
    where
        F: FnMut(&ProxyNode, &str),
    {
        if self.capability_cache.is_marked_unsupported(&node.id) {
            return Err(RouteWardError::UdpAssociateUnsupported {
                key: ERR_KEY_UDP_NOT_SUPPORTED,
                proxy_id: node.id.clone(),
            });
        }

        if !node.udp_enabled || node.protocol != ProxyProtocol::Socks5 {
            let reason = if node.protocol != ProxyProtocol::Socks5 {
                "protocol is not SOCKS5"
            } else {
                "udpEnabled is false in profile"
            };
            if self.capability_cache.mark_unsupported(&node.id) {
                on_first_unsupported_warn(node, reason);
            }
            return Err(RouteWardError::UdpAssociateUnsupported {
                key: ERR_KEY_UDP_NOT_SUPPORTED,
                proxy_id: node.id.clone(),
            });
        }

        if let Some(existing) = self.get_live_session(client_addr, &node.id) {
            return Ok(existing);
        }

        let connect_timeout = Duration::from_millis(constants.network.tcp_connect_timeout_ms);
        let handshake_timeout = Duration::from_millis(constants.network.proxy_handshake_timeout_ms);
        let fwmark = constants.network.linux_fwmark;

        let proxy_addr = format!("{}:{}", node.host, node.port);
        let mut control_stream = timeout(
            connect_timeout,
            ProxyConnector::connect_tcp_marked(&proxy_addr, fwmark),
        )
        .await
        .map_err(|_| RouteWardError::ConnectionTimeout {
            key: ERR_KEY_CONNECTION_TIMEOUT,
        })?
        .map_err(RouteWardError::Io)?;

        let tcp_port_guard = match (nat_table, control_stream.local_addr()) {
            (Some(nat), Ok(local_sa)) => Some(nat.register_self_tcp_port(local_sa.port())),
            _ => None,
        };
        let control_peer_ip = control_stream
            .peer_addr()
            .map(|sa| sa.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let bound_opt = match timeout(
            handshake_timeout,
            ProxyConnector::negotiate_socks5(
                &mut control_stream,
                node,
                "0.0.0.0",
                0,
                constants.protocols.socks5_cmd_udp_associate,
                &constants.protocols,
            ),
        )
        .await
        {
            Ok(Ok(bound)) => bound,
            Ok(Err(RouteWardError::UdpAssociateUnsupported { key, proxy_id })) => {
                if self.capability_cache.mark_unsupported(&node.id) {
                    on_first_unsupported_warn(
                        node,
                        "SOCKS5 server replied REP=0x07 (Command not supported)",
                    );
                }
                return Err(RouteWardError::UdpAssociateUnsupported { key, proxy_id });
            }
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err(RouteWardError::ConnectionTimeout {
                    key: ERR_KEY_CONNECTION_TIMEOUT,
                });
            }
        };

        let Some(mut relay_udp_addr) = bound_opt else {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: "SOCKS5 UDP ASSOCIATE reply did not return a valid BND.ADDR".to_string(),
            });
        };

        // RFC 1928: if the server returns 0.0.0.0 or :: as BND.ADDR, use the TCP control peer IP.
        if relay_udp_addr.ip().is_unspecified() {
            relay_udp_addr.set_ip(control_peer_ip);
        }

        let (udp_socket, udp_port_guard) = Self::bind_marked_udp_socket(fwmark, nat_table)
            .await
            .map_err(RouteWardError::Io)?;

        let control_alive = Arc::new(AtomicBool::new(true));
        let shutdown_notify = Arc::new(Notify::new());
        let alive_clone = Arc::clone(&control_alive);
        let notify_clone = Arc::clone(&shutdown_notify);

        tokio::spawn(async move {
            let mut probe_buf = [0u8; 1];
            tokio::select! {
                _ = control_stream.read(&mut probe_buf) => {
                    alive_clone.store(false, Ordering::Release);
                }
                _ = notify_clone.notified() => {
                    alive_clone.store(false, Ordering::Release);
                }
            }
        });

        let session = Arc::new(UdpAssociationSession {
            key: UdpAssociationKey {
                client_addr,
                proxy_id: node.id.clone(),
            },
            proxy_name: node.name.clone(),
            relay_udp_addr,
            udp_socket: Arc::new(udp_socket),
            io_lock: tokio::sync::Mutex::new(()),
            control_alive,
            shutdown_notify,
            last_activity_ms: AtomicU64::new(self.now_ms()),
            _udp_port_guard: udp_port_guard,
            _tcp_port_guard: tcp_port_guard,
        });

        self.insert_session(Arc::clone(&session));
        Ok(session)
    }

    /// Sends a single UDP datagram through `session` and awaits a reply datagram from the SOCKS5 UDP relay.
    pub async fn send_and_recv_on_session(
        &self,
        session: &Arc<UdpAssociationSession>,
        target: &Socks5UdpTarget,
        payload: &[u8],
        read_timeout: Duration,
        proto: &ProtocolConstants,
    ) -> RouteWardResult<UdpProxiedDatagramReply> {
        let _io_guard = session.io_lock.lock().await;
        if !session.is_control_alive() {
            self.sessions.remove(&session.key);
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: "SOCKS5 UDP control connection closed".to_string(),
            });
        }

        let wire_pkt = encode_socks5_udp_datagram(target, payload, proto).map_err(|err| {
            RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: err.to_string(),
            }
        })?;

        session.touch(self.now_ms());
        session
            .udp_socket
            .send_to(&wire_pkt, session.relay_udp_addr)
            .await
            .map_err(RouteWardError::Io)?;

        let mut recv_buf = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
        let (n, _from_addr) = timeout(read_timeout, session.udp_socket.recv_from(&mut recv_buf))
            .await
            .map_err(|_| RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            })?
            .map_err(RouteWardError::Io)?;

        if !session.is_control_alive() {
            self.sessions.remove(&session.key);
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: "SOCKS5 UDP control connection closed during receive".to_string(),
            });
        }

        session.touch(self.now_ms());
        let (remote_source, decoded_payload) = decode_socks5_udp_datagram(&recv_buf[..n], proto)
            .map_err(|err| RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: err.to_string(),
            })?;

        Ok(UdpProxiedDatagramReply {
            payload: decoded_payload.to_vec(),
            remote_source,
            proxy_id: session.key.proxy_id.clone(),
            proxy_name: session.proxy_name.clone(),
        })
    }

    /// Exchanges a single UDP datagram with `target` via a single SOCKS5 `node`.
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange_datagram_via_node<F>(
        &self,
        client_addr: SocketAddr,
        node: &ProxyNode,
        target: &Socks5UdpTarget,
        payload: &[u8],
        constants: &SystemConstants,
        nat_table: Option<&TransparentNatTable>,
        on_first_unsupported_warn: F,
    ) -> RouteWardResult<UdpProxiedDatagramReply>
    where
        F: FnMut(&ProxyNode, &str),
    {
        let session = self
            .get_or_create_for_node(
                client_addr,
                node,
                constants,
                nat_table,
                on_first_unsupported_warn,
            )
            .await?;

        let read_timeout = Duration::from_millis(
            constants
                .checker
                .probe_timeout_ms
                .clamp(500, DEFAULT_UDP_DATAGRAM_READ_TIMEOUT_MS),
        );
        self.send_and_recv_on_session(
            &session,
            target,
            payload,
            read_timeout,
            &constants.protocols,
        )
        .await
    }

    /// Exchanges a single UDP datagram via a proxy group (`Failover`, `LowestLatency`, `LoadBalance`, or single-hop `Sequence`).
    ///
    /// Nodes that refuse `UDP ASSOCIATE` (`REP = 0x07`), are TCP-only, or are already cached as unsupported
    /// are skipped in favor of the remaining enabled nodes in the group.
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange_datagram_via_group<F>(
        &self,
        client_addr: SocketAddr,
        strategy: ChainStrategy,
        hops: &[ProxyNode],
        round_robin_index: usize,
        target: &Socks5UdpTarget,
        payload: &[u8],
        constants: &SystemConstants,
        nat_table: Option<&TransparentNatTable>,
        mut on_first_unsupported_warn: F,
    ) -> RouteWardResult<UdpProxiedDatagramReply>
    where
        F: FnMut(&ProxyNode, &str),
    {
        let enabled_hops: Vec<ProxyNode> = hops.iter().filter(|n| n.enabled).cloned().collect();
        if enabled_hops.is_empty() {
            return Err(RouteWardError::EmptyProxyChain {
                key: ERR_KEY_CHAIN_EMPTY,
            });
        }

        // Standard RFC 1928 UDP ASSOCIATE uses a direct UDP relay socket and cannot be chained across multiple sequential hops.
        if strategy == ChainStrategy::Sequence && enabled_hops.len() > 1 {
            return Err(RouteWardError::UdpAssociateUnsupported {
                key: ERR_KEY_UDP_NOT_SUPPORTED,
                proxy_id: format!("sequence({})", enabled_hops.len()),
            });
        }

        let ordered_candidates: Vec<ProxyNode> = match strategy {
            ChainStrategy::Sequence | ChainStrategy::Failover => enabled_hops,
            ChainStrategy::LowestLatency => {
                let mut sorted = enabled_hops;
                sorted.sort_by_key(|n| n.last_latency_ms.unwrap_or(u64::MAX));
                sorted
            }
            ChainStrategy::LoadBalance => {
                let count = enabled_hops.len();
                (0..count)
                    .map(|offset| enabled_hops[(round_robin_index + offset) % count].clone())
                    .collect()
            }
        };

        let mut last_err: Option<RouteWardError> = None;
        for candidate in &ordered_candidates {
            match self
                .exchange_datagram_via_node(
                    client_addr,
                    candidate,
                    target,
                    payload,
                    constants,
                    nat_table,
                    &mut on_first_unsupported_warn,
                )
                .await
            {
                Ok(reply) => return Ok(reply),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(RouteWardError::UdpAssociateUnsupported {
            key: ERR_KEY_UDP_NOT_SUPPORTED,
            proxy_id: "group".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SystemConstants;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn encodes_and_decodes_socks5_udp_datagrams_for_ipv4_domain_and_ipv6() {
        let constants = SystemConstants::load_embedded().unwrap();
        let proto = &constants.protocols;
        let payload = b"routeward-udp-test-payload";

        // 1. ATYP = IPv4 (0x01)
        let target_v4 = Socks5UdpTarget::Ipv4(Ipv4Addr::new(93, 184, 215, 14), 4433);
        let wire_v4 = encode_socks5_udp_datagram(&target_v4, payload, proto).unwrap();
        assert_eq!(&wire_v4[..4], &[0x00, 0x00, 0x00, 0x01]);
        let (dec_target_v4, dec_payload_v4) = decode_socks5_udp_datagram(&wire_v4, proto).unwrap();
        assert_eq!(dec_target_v4, target_v4);
        assert_eq!(dec_payload_v4, payload);

        // 2. ATYP = Domain (0x03)
        let target_dom = Socks5UdpTarget::Domain("echo.routeward.test".to_string(), 9999);
        let wire_dom = encode_socks5_udp_datagram(&target_dom, payload, proto).unwrap();
        assert_eq!(&wire_dom[..4], &[0x00, 0x00, 0x00, 0x03]);
        assert_eq!(wire_dom[4] as usize, "echo.routeward.test".len());
        let (dec_target_dom, dec_payload_dom) =
            decode_socks5_udp_datagram(&wire_dom, proto).unwrap();
        assert_eq!(dec_target_dom, target_dom);
        assert_eq!(dec_payload_dom, payload);

        // 3. ATYP = IPv6 (0x04)
        let v6_addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001);
        let target_v6 = Socks5UdpTarget::Ipv6(v6_addr, 5353);
        let wire_v6 = encode_socks5_udp_datagram(&target_v6, payload, proto).unwrap();
        assert_eq!(&wire_v6[..4], &[0x00, 0x00, 0x00, 0x04]);
        let (dec_target_v6, dec_payload_v6) = decode_socks5_udp_datagram(&wire_v6, proto).unwrap();
        assert_eq!(dec_target_v6, target_v6);
        assert_eq!(dec_payload_v6, payload);
    }

    #[test]
    fn rejects_malformed_socks5_udp_headers_and_nonzero_frag_without_panic() {
        let constants = SystemConstants::load_embedded().unwrap();
        let proto = &constants.protocols;

        // 1. Shorter than 4-byte minimum header
        for len in 0..4 {
            let buf = vec![0u8; len];
            assert_eq!(
                decode_socks5_udp_datagram(&buf, proto),
                Err(Socks5UdpCodecError::PacketTooShort)
            );
        }

        // 2. Non-zero RSV field
        let bad_rsv = [0x00, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35];
        assert_eq!(
            decode_socks5_udp_datagram(&bad_rsv, proto),
            Err(Socks5UdpCodecError::NonZeroReservedField(1))
        );

        // 3. Non-zero FRAG byte (fragmentation unsupported)
        let bad_frag = [0x00, 0x00, 0x02, 0x01, 127, 0, 0, 1, 0x00, 0x35];
        assert_eq!(
            decode_socks5_udp_datagram(&bad_frag, proto),
            Err(Socks5UdpCodecError::FragmentationNotSupported(2))
        );

        // 4. Unknown ATYP
        let bad_atyp = [0x00, 0x00, 0x00, 0x99, 1, 2, 3, 4, 5, 6];
        assert_eq!(
            decode_socks5_udp_datagram(&bad_atyp, proto),
            Err(Socks5UdpCodecError::UnsupportedAddressType(0x99))
        );

        // 5. Truncated IPv4, Domain (len=0 and len > packet), and IPv6 headers
        let trunc_v4 = [0x00, 0x00, 0x00, 0x01, 127, 0, 0];
        assert_eq!(
            decode_socks5_udp_datagram(&trunc_v4, proto),
            Err(Socks5UdpCodecError::PacketTooShort)
        );
        let zero_dom = [0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50];
        assert_eq!(
            decode_socks5_udp_datagram(&zero_dom, proto),
            Err(Socks5UdpCodecError::InvalidDomainLength)
        );
        let trunc_dom = [0x00, 0x00, 0x00, 0x03, 50, b'a', b'b'];
        assert_eq!(
            decode_socks5_udp_datagram(&trunc_dom, proto),
            Err(Socks5UdpCodecError::PacketTooShort)
        );
        let trunc_v6 = [0x00, 0x00, 0x00, 0x04, 0, 1, 2, 3, 4];
        assert_eq!(
            decode_socks5_udp_datagram(&trunc_v6, proto),
            Err(Socks5UdpCodecError::PacketTooShort)
        );
    }

    #[tokio::test]
    async fn memorizes_rep_0x07_refusal_per_node_with_single_warn_and_fails_over_in_group() {
        let constants = SystemConstants::load_embedded().unwrap();

        // Spawn a mock SOCKS5 server that refuses UDP ASSOCIATE with REP = 0x07 (like ssh -D)
        let refusing_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refusing_port = refusing_listener.local_addr().unwrap().port();
        let accept_count = Arc::new(AtomicU64::new(0));
        let accept_count_clone = Arc::clone(&accept_count);

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = refusing_listener.accept().await {
                accept_count_clone.fetch_add(1, Ordering::SeqCst);
                let mut greeting = [0u8; 2];
                if stream.read_exact(&mut greeting).await.is_err() {
                    continue;
                }
                let nmethods = greeting[1] as usize;
                let mut methods = vec![0u8; nmethods];
                let _ = stream.read_exact(&mut methods).await;
                let _ = stream.write_all(&[0x05, 0x00]).await;

                let mut req = [0u8; 10];
                if stream.read_exact(&mut req).await.is_ok() {
                    // Reply REP = 0x07 (Command not supported)
                    let _ = stream
                        .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                }
            }
        });

        let refusing_node = ProxyNode {
            id: "node-ssh-d".to_string(),
            name: "SSH Dynamic Tunnel".to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port: refusing_port,
            auth: None,
            udp_enabled: true,
            tls: false,
            sni: None,
            enabled: true,
            last_latency_ms: Some(5),
            exit_ip: None,
        };

        let manager = UdpAssociationManager::with_limits(
            Duration::from_secs(60),
            16,
            Duration::from_secs(300),
        );
        let client_addr: SocketAddr = "127.0.0.1:54000".parse().unwrap();
        let mut warn_count = 0usize;

        // First attempt: connects to refusing_listener, receives REP=0x07, logs 1 WARN, caches refusal
        let res1 = manager
            .get_or_create_for_node(client_addr, &refusing_node, &constants, None, |_, _| {
                warn_count += 1;
            })
            .await;
        assert!(matches!(
            res1,
            Err(RouteWardError::UdpAssociateUnsupported { .. })
        ));
        assert_eq!(warn_count, 1);
        assert_eq!(accept_count.load(Ordering::SeqCst), 1);
        assert!(manager
            .capability_cache()
            .is_marked_unsupported("node-ssh-d"));

        // Second attempt on the same node: rejected immediately from cache without new TCP connection or second WARN
        let res2 = manager
            .get_or_create_for_node(client_addr, &refusing_node, &constants, None, |_, _| {
                warn_count += 1;
            })
            .await;
        assert!(matches!(
            res2,
            Err(RouteWardError::UdpAssociateUnsupported { .. })
        ));
        assert_eq!(
            warn_count, 1,
            "At most one WARN must be emitted per node while cached"
        );
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            1,
            "Cached unsupported node must not be re-probed before TTL expiry"
        );
    }

    #[tokio::test]
    async fn expires_idle_associations_and_evicts_oldest_when_max_capacity_reached() {
        let manager = UdpAssociationManager::with_limits(
            Duration::from_millis(60),
            2,
            Duration::from_secs(60),
        );

        let make_dummy_session = |port: u16, now_ms: u64| -> Arc<UdpAssociationSession> {
            let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            std_sock.set_nonblocking(true).unwrap();
            let tokio_sock = UdpSocket::from_std(std_sock).unwrap();
            Arc::new(UdpAssociationSession {
                key: UdpAssociationKey {
                    client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    proxy_id: "proxy-1".to_string(),
                },
                proxy_name: "Proxy 1".to_string(),
                relay_udp_addr: "127.0.0.1:1080".parse().unwrap(),
                udp_socket: Arc::new(tokio_sock),
                control_alive: Arc::new(AtomicBool::new(true)),
                shutdown_notify: Arc::new(Notify::new()),
                last_activity_ms: AtomicU64::new(now_ms),
                _udp_port_guard: None,
                _tcp_port_guard: None,
                io_lock: tokio::sync::Mutex::new(()),
            })
        };

        let s1 = make_dummy_session(50001, manager.now_ms());
        manager.insert_session(s1);
        tokio::time::sleep(Duration::from_millis(5)).await;

        let s2 = make_dummy_session(50002, manager.now_ms());
        manager.insert_session(s2);
        assert_eq!(manager.active_count(), 2);

        // Touch 50001 so 50002 becomes the oldest idle association
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(manager
            .get_live_session("127.0.0.1:50001".parse().unwrap(), "proxy-1")
            .is_some());

        // Inserting a 3rd session when max_associations == 2 evicts the oldest idle (50002)
        let s3 = make_dummy_session(50003, manager.now_ms());
        manager.insert_session(s3);
        assert_eq!(manager.active_count(), 2);
        assert!(manager
            .get_live_session("127.0.0.1:50001".parse().unwrap(), "proxy-1")
            .is_some());
        assert!(
            manager
                .get_live_session("127.0.0.1:50002".parse().unwrap(), "proxy-1")
                .is_none(),
            "Oldest idle association (50002) must be evicted at capacity"
        );
        assert!(manager
            .get_live_session("127.0.0.1:50003".parse().unwrap(), "proxy-1")
            .is_some());

        // Wait past the 60ms idle timeout -> all associations expire
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(manager.active_count(), 0);
    }
}
