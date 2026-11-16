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

pub mod http_host;
pub mod ntlm;
pub mod sni;
pub mod tls;
pub mod udp;
pub mod uri;

use crate::config::{ChainStrategy, ProtocolConstants, ProxyNode, ProxyProtocol, SystemConstants};
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_AUTH_REJECTED, ERR_KEY_CHAIN_EMPTY,
    ERR_KEY_CONNECTION_TIMEOUT, ERR_KEY_HANDSHAKE_FAILED, ERR_KEY_UDP_NOT_SUPPORTED,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ntlm::{
    extract_challenge_token, select_sspi_scheme, sspi_step_async, SspiClientSession, SspiScheme,
};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const HTTP_HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";
const MAX_HTTP_RESPONSE_HEADER_BYTES: usize = 8192;
const MAX_HTTP_BODY_DRAIN_BYTES: usize = 65536;
const MAX_HTTP_AUTH_ATTEMPTS: usize = 4;
const SOCKS4A_SENTINEL_IPV4: [u8; 4] = [0, 0, 0, 1];
const MAX_SOCKS4A_DOMAIN_LEN: usize = 255;
/// Maximum length of a textual host name (RFC 1035, without the root label).
const MAX_HOSTNAME_BYTES: usize = 253;
/// Maximum length of one host name label (RFC 1035).
const MAX_HOSTNAME_LABEL_BYTES: usize = 63;
/// Maximum length of a SOCKS5 domain name (one length byte on the wire).
const MAX_SOCKS5_DOMAIN_BYTES: usize = u8::MAX as usize;
/// Prefix of a Basic `Proxy-Authorization` header line.
const BASIC_AUTH_HEADER_PREFIX: &str = "Proxy-Authorization: Basic ";
/// Authentication scheme name offered by Basic proxies in `Proxy-Authenticate`.
const BASIC_SCHEME_NAME: &str = "Basic";

pub trait AsyncTunnelStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncTunnelStream for T {}

pub struct ProxyConnector;

enum HttpConnectOutcome {
    Connected,
    ContinueSameStream,
    ReconnectRequired,
}

struct ParsedHttpResponse {
    status_code: u16,
    status_line: String,
    proxy_auth_challenges: Vec<String>,
    content_length: Option<usize>,
    is_chunked: bool,
    connection_close: bool,
}

/// Returns true when `name` is safe to embed in a text protocol request line (HTTP CONNECT) or a
/// SOCKS5 domain field: non-empty, at most 253 bytes, labels at most 63 bytes, and no ASCII
/// control characters, whitespace or non-printable characters. Underscores and other printable
/// characters stay accepted (no strict LDH enforcement).
pub fn is_safe_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_HOSTNAME_BYTES {
        return false;
    }
    if name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    name.split('.')
        .all(|label| label.len() <= MAX_HOSTNAME_LABEL_BYTES)
}

fn ensure_safe_target_host(host: &str) -> RouteWardResult<()> {
    if is_safe_hostname(host) {
        Ok(())
    } else {
        Err(RouteWardError::ProtocolHandshake {
            key: ERR_KEY_HANDSHAKE_FAILED,
            detail: "Refusing target host with control characters, whitespace or invalid length"
                .to_string(),
        })
    }
}

/// In-memory set of proxy endpoints that already accepted Basic credentials, so later connections
/// to a known Basic-only proxy skip the extra 407 round trip. Keyed by id, host and port so an
/// edited node never inherits the verdict of a previous configuration.
fn basic_accepted_nodes() -> &'static Mutex<HashSet<String>> {
    static CACHE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Cache key of a node: id, endpoint and a hash of the username, so changing the credentials of a
/// node does not inherit the previous Basic verdict. Only a hash of the username is kept in
/// memory; the password never enters the key.
fn basic_cache_key(node: &ProxyNode) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    node.auth
        .as_ref()
        .map(|creds| creds.username.as_str())
        .unwrap_or("")
        .hash(&mut hasher);
    format!(
        "{}|{}:{}|{:016x}",
        node.id,
        node.host,
        node.port,
        hasher.finish()
    )
}

fn remember_basic_accepted(node: &ProxyNode) {
    if let Ok(mut set) = basic_accepted_nodes().lock() {
        set.insert(basic_cache_key(node));
    }
}

fn forget_basic_accepted(node: &ProxyNode) {
    if let Ok(mut set) = basic_accepted_nodes().lock() {
        set.remove(&basic_cache_key(node));
    }
}

fn is_basic_known_accepted(node: &ProxyNode) -> bool {
    basic_accepted_nodes()
        .lock()
        .map(|set| set.contains(&basic_cache_key(node)))
        .unwrap_or(false)
}

/// Header sent on the first CONNECT. Basic credentials are pre-emptive only when the hop to the
/// proxy is TLS (or the node is already known to accept Basic); otherwise nothing is sent until
/// the proxy challenges with a 407.
fn initial_basic_auth_header(node: &ProxyNode) -> Option<String> {
    if !ProxyConnector::requires_tls(node) && !is_basic_known_accepted(node) {
        return None;
    }
    basic_auth_header(node)
}

fn basic_auth_header(node: &ProxyNode) -> Option<String> {
    let creds = node.auth.as_ref()?;
    let pass = creds.password_str();
    if creds.username.is_empty() && pass.is_empty() {
        return None;
    }
    let token = BASE64_STANDARD.encode(format!("{}:{pass}", creds.username));
    Some(format!("{BASIC_AUTH_HEADER_PREFIX}{token}\r\n"))
}

fn challenges_offer_basic(challenges: &[String]) -> bool {
    challenges.iter().any(|value| {
        value.split(',').any(|raw| {
            raw.split_whitespace()
                .next()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case(BASIC_SCHEME_NAME))
        })
    })
}

async fn read_http_response_headers<S: AsyncTunnelStream>(
    stream: &mut S,
) -> RouteWardResult<ParsedHttpResponse> {
    let mut response_buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    let mut header_complete = false;
    while response_buf.len() < MAX_HTTP_RESPONSE_HEADER_BYTES {
        stream.read_exact(&mut byte).await?;
        response_buf.push(byte[0]);
        if response_buf.ends_with(HTTP_HEADER_TERMINATOR) {
            header_complete = true;
            break;
        }
    }
    if !header_complete {
        return Err(RouteWardError::ProtocolHandshake {
            key: ERR_KEY_HANDSHAKE_FAILED,
            detail: "HTTP CONNECT response header exceeded maximum allowed size".to_string(),
        });
    }

    let response_str = String::from_utf8_lossy(&response_buf);
    let mut lines = response_str.split("\r\n");
    let status_line = lines.next().unwrap_or("HTTP Error").trim().to_string();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);

    let mut proxy_auth_challenges = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    let mut connection_close = false;

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, val)) = line.split_once(':') {
            let trimmed_name = name.trim();
            let trimmed_val = val.trim();
            if trimmed_name.eq_ignore_ascii_case("Proxy-Authenticate") {
                proxy_auth_challenges.push(trimmed_val.to_string());
            } else if trimmed_name.eq_ignore_ascii_case("Content-Length") {
                if let Ok(len) = trimmed_val.parse::<usize>() {
                    content_length = Some(len);
                }
            } else if trimmed_name.eq_ignore_ascii_case("Transfer-Encoding")
                && trimmed_val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            } else if (trimmed_name.eq_ignore_ascii_case("Connection")
                || trimmed_name.eq_ignore_ascii_case("Proxy-Connection"))
                && trimmed_val.to_ascii_lowercase().contains("close")
            {
                connection_close = true;
            }
        }
    }

    Ok(ParsedHttpResponse {
        status_code,
        status_line,
        proxy_auth_challenges,
        content_length,
        is_chunked,
        connection_close,
    })
}

async fn read_crlf_line<S: AsyncTunnelStream>(stream: &mut S) -> RouteWardResult<String> {
    let mut line = Vec::with_capacity(64);
    let mut b = [0u8; 1];
    while line.len() < 1024 {
        stream.read_exact(&mut b).await?;
        line.push(b[0]);
        if line.ends_with(b"\r\n") {
            return Ok(String::from_utf8_lossy(&line[..line.len() - 2]).to_string());
        }
    }
    Err(RouteWardError::ProtocolHandshake {
        key: ERR_KEY_HANDSHAKE_FAILED,
        detail: "HTTP chunked response line exceeded limit".to_string(),
    })
}

async fn drain_http_body<S: AsyncTunnelStream>(
    stream: &mut S,
    parsed: &ParsedHttpResponse,
) -> RouteWardResult<()> {
    if parsed.is_chunked {
        let mut total_drained = 0usize;
        loop {
            let size_line = read_crlf_line(stream).await?;
            let size_hex = size_line.split(';').next().unwrap_or("").trim();
            let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| {
                RouteWardError::ProtocolHandshake {
                    key: ERR_KEY_HANDSHAKE_FAILED,
                    detail: "Invalid chunked body size in 407 response".to_string(),
                }
            })?;
            if chunk_len == 0 {
                // Consume trailing headers until empty line
                loop {
                    let trailer = read_crlf_line(stream).await?;
                    if trailer.is_empty() {
                        break;
                    }
                }
                break;
            }
            total_drained = total_drained.saturating_add(chunk_len);
            if total_drained > MAX_HTTP_BODY_DRAIN_BYTES {
                return Err(RouteWardError::ProtocolHandshake {
                    key: ERR_KEY_HANDSHAKE_FAILED,
                    detail: "407 chunked response body exceeded maximum drain size".to_string(),
                });
            }
            let mut sink = vec![0u8; chunk_len];
            stream.read_exact(&mut sink).await?;
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).await?;
        }
    } else if let Some(len) = parsed.content_length {
        if len > MAX_HTTP_BODY_DRAIN_BYTES {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: "407 Content-Length exceeded maximum drain size".to_string(),
            });
        }
        if len > 0 {
            let mut sink = vec![0u8; len];
            stream.read_exact(&mut sink).await?;
        }
    }
    Ok(())
}

fn format_sspi_auth_header(scheme: SspiScheme, token_b64: &str) -> String {
    format!(
        "Proxy-Authorization: {} {token_b64}\r\n",
        scheme.as_header_scheme()
    )
}

impl ProxyConnector {
    /// Applies `SO_MARK` (`fwmark`) to an existing `UdpSocket` on Linux (no-op on other platforms)
    /// so RouteWard's own UDP sockets bypass transparent `nftables` interception.
    pub fn apply_platform_mark_udp(socket: &tokio::net::UdpSocket, fwmark: u32) {
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
        {
            let _ = socket;
            let _ = fwmark;
        }
    }

    /// Opens an outbound TCP stream, setting `SO_MARK` (`fwmark`) prior to `connect()` on Linux
    /// so RouteWard's own outbound traffic bypasses the `nftables` `output` NAT hook.
    pub async fn connect_tcp_marked(addr: &str, fwmark: u32) -> std::io::Result<TcpStream> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            use tokio::net::{lookup_host, TcpSocket};

            let mut last_err = None;
            for sock_addr in lookup_host(addr).await? {
                let socket = match &sock_addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => TcpSocket::new_v6()?,
                };
                if fwmark != 0 {
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
                match socket.connect(sock_addr).await {
                    Ok(stream) => return Ok(stream),
                    Err(err) => last_err = Some(err),
                }
            }
            Err(last_err.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "could not resolve any socket address",
                )
            }))
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = fwmark;
            TcpStream::connect(addr).await
        }
    }

    pub fn requires_tls(node: &ProxyNode) -> bool {
        node.tls || matches!(node.protocol, ProxyProtocol::Https)
    }

    pub async fn connect_single(
        node: &ProxyNode,
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        Self::connect_single_with_spn(node, None, target_host, target_port, constants).await
    }

    pub async fn connect_single_with_spn(
        node: &ProxyNode,
        spn_host_override: Option<&str>,
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        let connect_timeout = Duration::from_millis(constants.network.tcp_connect_timeout_ms);
        let handshake_timeout = Duration::from_millis(constants.network.proxy_handshake_timeout_ms);
        let fwmark = constants.network.linux_fwmark;
        let proxy_addr = Self::format_host_port(&node.host, node.port);
        let effective_spn = spn_host_override
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| node.sni.as_deref().map(str::trim).filter(|s| !s.is_empty()))
            .unwrap_or(node.host.as_str());

        if matches!(node.protocol, ProxyProtocol::Http | ProxyProtocol::Https) {
            return Self::connect_http_single_with_reconnect(
                node,
                &proxy_addr,
                effective_spn,
                target_host,
                target_port,
                constants,
            )
            .await;
        }

        let mut stream: Box<dyn AsyncTunnelStream> = Box::new(
            timeout(
                connect_timeout,
                Self::connect_tcp_marked(&proxy_addr, fwmark),
            )
            .await
            .map_err(|_| RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            })?
            .map_err(RouteWardError::Io)?,
        );

        if Self::requires_tls(node) {
            let sni_host = tls::resolve_tls_server_name(node, spn_host_override);
            stream = timeout(
                handshake_timeout,
                tls::wrap_client_stream(stream, &sni_host, node.tls_skip_verify),
            )
            .await
            .map_err(|_| RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            })??;
        }

        timeout(
            handshake_timeout,
            Self::negotiate_hop_with_spn(
                &mut stream,
                node,
                Some(effective_spn),
                target_host,
                target_port,
                &constants.protocols,
            ),
        )
        .await
        .map_err(|_| RouteWardError::ConnectionTimeout {
            key: ERR_KEY_CONNECTION_TIMEOUT,
        })??;

        Ok(stream)
    }

    async fn open_single_transport(
        node: &ProxyNode,
        proxy_addr: &str,
        spn_host_override: Option<&str>,
        constants: &SystemConstants,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        let (stream, _local, _peer) =
            Self::open_transport_with_addrs(node, proxy_addr, spn_host_override, constants).await?;
        Ok(stream)
    }

    /// Opens the TCP (and TLS, when the node requires it) transport to `node` and also returns the
    /// local and peer socket addresses of the underlying TCP connection.
    pub(crate) async fn open_transport_with_addrs(
        node: &ProxyNode,
        proxy_addr: &str,
        spn_host_override: Option<&str>,
        constants: &SystemConstants,
    ) -> RouteWardResult<(
        Box<dyn AsyncTunnelStream>,
        Option<SocketAddr>,
        Option<SocketAddr>,
    )> {
        let connect_timeout = Duration::from_millis(constants.network.tcp_connect_timeout_ms);
        let handshake_timeout = Duration::from_millis(constants.network.proxy_handshake_timeout_ms);
        let tcp_stream = timeout(
            connect_timeout,
            Self::connect_tcp_marked(proxy_addr, constants.network.linux_fwmark),
        )
        .await
        .map_err(|_| RouteWardError::ConnectionTimeout {
            key: ERR_KEY_CONNECTION_TIMEOUT,
        })?
        .map_err(RouteWardError::Io)?;
        let local_addr = tcp_stream.local_addr().ok();
        let peer_addr = tcp_stream.peer_addr().ok();
        let mut stream: Box<dyn AsyncTunnelStream> = Box::new(tcp_stream);

        if Self::requires_tls(node) {
            let sni_host = tls::resolve_tls_server_name(node, spn_host_override);
            stream = timeout(
                handshake_timeout,
                tls::wrap_client_stream(stream, &sni_host, node.tls_skip_verify),
            )
            .await
            .map_err(|_| RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            })??;
        }

        Ok((stream, local_addr, peer_addr))
    }

    async fn connect_http_single_with_reconnect(
        node: &ProxyNode,
        proxy_addr: &str,
        effective_spn: &str,
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        let handshake_timeout = Duration::from_millis(constants.network.proxy_handshake_timeout_ms);
        let mut sspi_session: Option<SspiClientSession> = None;
        let mut pending_auth_header: Option<String> = initial_basic_auth_header(node);

        for _attempt in 0..MAX_HTTP_AUTH_ATTEMPTS {
            let mut stream =
                Self::open_single_transport(node, proxy_addr, Some(effective_spn), constants)
                    .await?;
            let mut should_reconnect = false;
            for _step in 0..MAX_HTTP_AUTH_ATTEMPTS {
                match timeout(
                    handshake_timeout,
                    Self::negotiate_http_connect_step(
                        &mut stream,
                        node,
                        effective_spn,
                        target_host,
                        target_port,
                        &mut pending_auth_header,
                        &mut sspi_session,
                    ),
                )
                .await
                .map_err(|_| RouteWardError::ConnectionTimeout {
                    key: ERR_KEY_CONNECTION_TIMEOUT,
                })?? {
                    HttpConnectOutcome::Connected => return Ok(stream),
                    HttpConnectOutcome::ContinueSameStream => continue,
                    HttpConnectOutcome::ReconnectRequired => {
                        should_reconnect = true;
                        break;
                    }
                }
            }
            if !should_reconnect {
                break;
            }
        }

        Err(RouteWardError::AuthenticationRejected {
            key: ERR_KEY_AUTH_REJECTED,
        })
    }

    pub async fn connect_chain(
        hops: &[ProxyNode],
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        let with_spns: Vec<(ProxyNode, Option<String>)> =
            hops.iter().map(|h| (h.clone(), None)).collect();
        Self::connect_chain_with_spns(&with_spns, target_host, target_port, constants).await
    }

    pub async fn connect_chain_with_spns(
        hops: &[(ProxyNode, Option<String>)],
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        if hops.is_empty() {
            return Err(RouteWardError::EmptyProxyChain {
                key: ERR_KEY_CHAIN_EMPTY,
            });
        }

        let connect_timeout = Duration::from_millis(constants.network.tcp_connect_timeout_ms);
        let handshake_timeout = Duration::from_millis(constants.network.proxy_handshake_timeout_ms);
        let fwmark = constants.network.linux_fwmark;

        let (first_hop, first_spn) = &hops[0];
        let entry_addr = Self::format_host_port(&first_hop.host, first_hop.port);
        let mut stream: Box<dyn AsyncTunnelStream> = Box::new(
            timeout(
                connect_timeout,
                Self::connect_tcp_marked(&entry_addr, fwmark),
            )
            .await
            .map_err(|_| RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            })?
            .map_err(RouteWardError::Io)?,
        );

        if Self::requires_tls(first_hop) {
            let sni_host = tls::resolve_tls_server_name(first_hop, first_spn.as_deref());
            stream = timeout(
                handshake_timeout,
                tls::wrap_client_stream(stream, &sni_host, first_hop.tls_skip_verify),
            )
            .await
            .map_err(|_| RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            })??;
        }

        for idx in 0..hops.len() {
            let (current_hop, current_spn) = &hops[idx];
            let (next_host, next_port, next_hop_opt) = if idx + 1 < hops.len() {
                let (next_node, next_spn) = &hops[idx + 1];
                let connect_target = next_spn.as_deref().unwrap_or(&next_node.host);
                (connect_target, next_node.port, Some((next_node, next_spn)))
            } else {
                (target_host, target_port, None)
            };

            timeout(
                handshake_timeout,
                Self::negotiate_hop_with_spn(
                    &mut stream,
                    current_hop,
                    current_spn.as_deref(),
                    next_host,
                    next_port,
                    &constants.protocols,
                ),
            )
            .await
            .map_err(|_| RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            })??;

            if let Some((next_hop, next_spn)) = next_hop_opt {
                if Self::requires_tls(next_hop) {
                    let sni_host = tls::resolve_tls_server_name(next_hop, next_spn.as_deref());
                    stream = timeout(
                        handshake_timeout,
                        tls::wrap_client_stream(stream, &sni_host, next_hop.tls_skip_verify),
                    )
                    .await
                    .map_err(|_| RouteWardError::ConnectionTimeout {
                        key: ERR_KEY_CONNECTION_TIMEOUT,
                    })??;
                }
            }
        }

        Ok(stream)
    }

    pub async fn connect_group(
        strategy: ChainStrategy,
        hops: &[ProxyNode],
        round_robin_index: usize,
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        let with_spns: Vec<(ProxyNode, Option<String>)> =
            hops.iter().map(|h| (h.clone(), None)).collect();
        Self::connect_group_with_spns(
            strategy,
            &with_spns,
            round_robin_index,
            target_host,
            target_port,
            constants,
        )
        .await
    }

    pub async fn connect_group_with_spns(
        strategy: ChainStrategy,
        hops: &[(ProxyNode, Option<String>)],
        round_robin_index: usize,
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        let enabled_hops: Vec<(ProxyNode, Option<String>)> =
            hops.iter().filter(|(n, _)| n.enabled).cloned().collect();
        if enabled_hops.is_empty() {
            return Err(RouteWardError::EmptyProxyChain {
                key: ERR_KEY_CHAIN_EMPTY,
            });
        }

        match strategy {
            ChainStrategy::Sequence => {
                Self::connect_chain_with_spns(&enabled_hops, target_host, target_port, constants)
                    .await
            }
            ChainStrategy::Failover => {
                let mut last_err = None;
                for (node, spn) in &enabled_hops {
                    match Self::connect_single_with_spn(
                        node,
                        spn.as_deref(),
                        target_host,
                        target_port,
                        constants,
                    )
                    .await
                    {
                        Ok(stream) => return Ok(stream),
                        Err(err) => last_err = Some(err),
                    }
                }
                Err(last_err.unwrap_or(RouteWardError::ConnectionTimeout {
                    key: ERR_KEY_CONNECTION_TIMEOUT,
                }))
            }
            ChainStrategy::LowestLatency => {
                let mut sorted = enabled_hops;
                sorted.sort_by_key(|(n, _)| n.last_latency_ms.unwrap_or(u64::MAX));
                let mut last_err = None;
                for (node, spn) in &sorted {
                    match Self::connect_single_with_spn(
                        node,
                        spn.as_deref(),
                        target_host,
                        target_port,
                        constants,
                    )
                    .await
                    {
                        Ok(stream) => return Ok(stream),
                        Err(err) => last_err = Some(err),
                    }
                }
                Err(last_err.unwrap_or(RouteWardError::ConnectionTimeout {
                    key: ERR_KEY_CONNECTION_TIMEOUT,
                }))
            }
            ChainStrategy::LoadBalance => {
                let count = enabled_hops.len();
                let mut last_err = None;
                for offset in 0..count {
                    let idx = (round_robin_index + offset) % count;
                    let (ref node, ref spn) = enabled_hops[idx];
                    match Self::connect_single_with_spn(
                        node,
                        spn.as_deref(),
                        target_host,
                        target_port,
                        constants,
                    )
                    .await
                    {
                        Ok(stream) => return Ok(stream),
                        Err(err) => last_err = Some(err),
                    }
                }
                Err(last_err.unwrap_or(RouteWardError::ConnectionTimeout {
                    key: ERR_KEY_CONNECTION_TIMEOUT,
                }))
            }
        }
    }

    pub async fn negotiate_hop<S: AsyncTunnelStream>(
        stream: &mut S,
        node: &ProxyNode,
        target_host: &str,
        target_port: u16,
        proto: &ProtocolConstants,
    ) -> RouteWardResult<()> {
        Self::negotiate_hop_with_spn(stream, node, None, target_host, target_port, proto).await
    }

    pub async fn negotiate_hop_with_spn<S: AsyncTunnelStream>(
        stream: &mut S,
        node: &ProxyNode,
        spn_host: Option<&str>,
        target_host: &str,
        target_port: u16,
        proto: &ProtocolConstants,
    ) -> RouteWardResult<()> {
        match node.protocol {
            ProxyProtocol::Socks5 => Self::negotiate_socks5(
                stream,
                node,
                target_host,
                target_port,
                proto.socks5_cmd_connect,
                proto,
            )
            .await
            .map(|_| ()),
            ProxyProtocol::Socks4 => {
                Self::negotiate_socks4(stream, node, target_host, target_port, proto).await
            }
            ProxyProtocol::Http | ProxyProtocol::Https => {
                let effective_spn = spn_host
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .or(node.sni.as_deref())
                    .unwrap_or(node.host.as_str());
                Self::negotiate_http_connect_with_spn(
                    stream,
                    node,
                    effective_spn,
                    target_host,
                    target_port,
                    proto,
                )
                .await
            }
        }
    }

    pub async fn negotiate_socks4<S: AsyncTunnelStream>(
        stream: &mut S,
        node: &ProxyNode,
        target_host: &str,
        target_port: u16,
        proto: &ProtocolConstants,
    ) -> RouteWardResult<()> {
        let clean_host = target_host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        if clean_host.is_empty() || clean_host.as_bytes().contains(&0) {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: "Invalid SOCKS4 target host".to_string(),
            });
        }
        if IpAddr::from_str(clean_host).is_err() {
            ensure_safe_target_host(clean_host)?;
        }

        let userid = node
            .auth
            .as_ref()
            .map(|a| a.username.as_str())
            .unwrap_or("");
        if userid.as_bytes().contains(&0) {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: "SOCKS4 user ID must not contain NUL bytes".to_string(),
            });
        }

        if let Some(creds) = &node.auth {
            if !creds.password_str().is_empty() {
                tracing::warn!(
                    target: "routeward::proxy::socks4",
                    "SOCKS4/4a ignores proxy password field; only USERID is sent on the wire"
                );
            }
        }

        let parsed_ip = IpAddr::from_str(clean_host).ok();
        if matches!(parsed_ip, Some(IpAddr::V6(_))) {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!("SOCKS4 does not support IPv6 targets ({clean_host})"),
            });
        }

        let mut req = Vec::with_capacity(16 + userid.len() + clean_host.len());
        req.push(proto.socks4_version);
        req.push(proto.socks4_cmd_connect);
        req.extend_from_slice(&target_port.to_be_bytes());

        match parsed_ip {
            Some(IpAddr::V4(v4)) => {
                req.extend_from_slice(&v4.octets());
                req.extend_from_slice(userid.as_bytes());
                req.push(0);
            }
            None => {
                if clean_host.len() > MAX_SOCKS4A_DOMAIN_LEN {
                    return Err(RouteWardError::ProtocolHandshake {
                        key: ERR_KEY_HANDSHAKE_FAILED,
                        detail: "SOCKS4a domain exceeds 255 bytes".to_string(),
                    });
                }
                req.extend_from_slice(&SOCKS4A_SENTINEL_IPV4);
                req.extend_from_slice(userid.as_bytes());
                req.push(0);
                req.extend_from_slice(clean_host.as_bytes());
                req.push(0);
            }
            Some(IpAddr::V6(_)) => unreachable!(),
        }

        stream.write_all(&req).await?;
        let mut resp = [0u8; 8];
        stream.read_exact(&mut resp).await?;
        if resp[0] != proto.socks4_reply_version {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!("Unexpected SOCKS4 reply version 0x{:02X}", resp[0]),
            });
        }
        if resp[1] != proto.socks4_reply_granted {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!("SOCKS4 request rejected with code {}", resp[1]),
            });
        }
        Ok(())
    }

    pub async fn negotiate_socks5<S: AsyncTunnelStream>(
        stream: &mut S,
        node: &ProxyNode,
        target_host: &str,
        target_port: u16,
        command: u8,
        proto: &ProtocolConstants,
    ) -> RouteWardResult<Option<SocketAddr>> {
        if IpAddr::from_str(target_host).is_err() {
            ensure_safe_target_host(target_host)?;
        }
        let has_auth = node
            .auth
            .as_ref()
            .map(|a| !a.username.is_empty() || !a.password_str().is_empty())
            .unwrap_or(false);

        let greeting = if has_auth {
            vec![
                proto.socks5_version,
                2,
                proto.socks5_auth_none,
                proto.socks5_auth_password,
            ]
        } else {
            vec![proto.socks5_version, 1, proto.socks5_auth_none]
        };

        stream.write_all(&greeting).await?;

        let mut choice = [0u8; 2];
        stream.read_exact(&mut choice).await?;

        if choice[0] != proto.socks5_version {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!("Invalid SOCKS5 version: {}", choice[0]),
            });
        }

        if choice[1] == proto.socks5_auth_password {
            let creds = node
                .auth
                .as_ref()
                .ok_or(RouteWardError::AuthenticationRejected {
                    key: ERR_KEY_AUTH_REJECTED,
                })?;
            let user_bytes = creds.username.as_bytes();
            let pass_bytes = creds.password_str().as_bytes();
            if user_bytes.is_empty()
                || user_bytes.len() > u8::MAX as usize
                || pass_bytes.len() > u8::MAX as usize
            {
                return Err(RouteWardError::ProtocolHandshake {
                    key: ERR_KEY_HANDSHAKE_FAILED,
                    detail: "SOCKS5 RFC 1929 credentials must fit within 1..=255 bytes".to_string(),
                });
            }

            let mut auth_pkt = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
            auth_pkt.push(proto.socks5_password_auth_version);
            auth_pkt.push(user_bytes.len() as u8);
            auth_pkt.extend_from_slice(user_bytes);
            auth_pkt.push(pass_bytes.len() as u8);
            auth_pkt.extend_from_slice(pass_bytes);

            stream.write_all(&auth_pkt).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != proto.socks5_reply_succeeded {
                return Err(RouteWardError::AuthenticationRejected {
                    key: ERR_KEY_AUTH_REJECTED,
                });
            }
        } else if choice[1] != proto.socks5_auth_none {
            return Err(RouteWardError::AuthenticationRejected {
                key: ERR_KEY_AUTH_REJECTED,
            });
        }

        let mut req = vec![proto.socks5_version, command, 0x00];
        Self::encode_socks5_address(&mut req, target_host, target_port, proto)?;
        stream.write_all(&req).await?;

        let mut reply_head = [0u8; 4];
        stream.read_exact(&mut reply_head).await?;
        if reply_head[1] != proto.socks5_reply_succeeded {
            if command == proto.socks5_cmd_udp_associate
                && reply_head[1] == proto.socks5_reply_command_not_supported
            {
                return Err(RouteWardError::UdpAssociateUnsupported {
                    key: ERR_KEY_UDP_NOT_SUPPORTED,
                    proxy_id: node.id.clone(),
                });
            }
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!("SOCKS5 reply code: {}", reply_head[1]),
            });
        }

        let bound_addr = match reply_head[3] {
            atyp if atyp == proto.socks5_atyp_ipv4 => {
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await?;
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).await?;
                Some(SocketAddr::new(
                    IpAddr::from(ip_bytes),
                    u16::from_be_bytes(port_bytes),
                ))
            }
            atyp if atyp == proto.socks5_atyp_ipv6 => {
                let mut ip_bytes = [0u8; 16];
                stream.read_exact(&mut ip_bytes).await?;
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).await?;
                Some(SocketAddr::new(
                    IpAddr::from(ip_bytes),
                    u16::from_be_bytes(port_bytes),
                ))
            }
            atyp if atyp == proto.socks5_atyp_domain => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain_buf = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut domain_buf).await?;
                None
            }
            _ => None,
        };

        Ok(bound_addr)
    }

    pub async fn negotiate_http_connect<S: AsyncTunnelStream>(
        stream: &mut S,
        node: &ProxyNode,
        target_host: &str,
        target_port: u16,
        _proto: &ProtocolConstants,
    ) -> RouteWardResult<()> {
        let spn = node.sni.as_deref().unwrap_or(&node.host);
        Self::negotiate_http_connect_with_spn(stream, node, spn, target_host, target_port, _proto)
            .await
    }

    pub async fn negotiate_http_connect_with_spn<S: AsyncTunnelStream>(
        stream: &mut S,
        node: &ProxyNode,
        effective_spn: &str,
        target_host: &str,
        target_port: u16,
        _proto: &ProtocolConstants,
    ) -> RouteWardResult<()> {
        let mut sspi_session: Option<SspiClientSession> = None;
        let mut pending_auth_header = initial_basic_auth_header(node);

        for _ in 0..MAX_HTTP_AUTH_ATTEMPTS {
            match Self::negotiate_http_connect_step(
                stream,
                node,
                effective_spn,
                target_host,
                target_port,
                &mut pending_auth_header,
                &mut sspi_session,
            )
            .await?
            {
                HttpConnectOutcome::Connected => return Ok(()),
                HttpConnectOutcome::ContinueSameStream => continue,
                HttpConnectOutcome::ReconnectRequired => {
                    return Err(RouteWardError::AuthenticationRejected {
                        key: ERR_KEY_AUTH_REJECTED,
                    });
                }
            }
        }

        Err(RouteWardError::AuthenticationRejected {
            key: ERR_KEY_AUTH_REJECTED,
        })
    }

    async fn negotiate_http_connect_step<S: AsyncTunnelStream>(
        stream: &mut S,
        node: &ProxyNode,
        effective_spn: &str,
        target_host: &str,
        target_port: u16,
        pending_auth_header: &mut Option<String>,
        sspi_session: &mut Option<SspiClientSession>,
    ) -> RouteWardResult<HttpConnectOutcome> {
        ensure_safe_target_host(target_host)?;
        let host_port = Self::format_host_port(target_host, target_port);
        let auth_hdr = pending_auth_header.take().unwrap_or_default();
        let sent_basic = auth_hdr.starts_with(BASIC_AUTH_HEADER_PREFIX);
        let request = format!(
            "CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n{auth_hdr}Proxy-Connection: Keep-Alive\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;

        let parsed = read_http_response_headers(stream).await?;
        if (200..300).contains(&parsed.status_code) {
            if sent_basic {
                remember_basic_accepted(node);
            }
            return Ok(HttpConnectOutcome::Connected);
        }

        if parsed.status_code == 407 {
            if sent_basic {
                forget_basic_accepted(node);
            }
            let Some(scheme) = select_sspi_scheme(&parsed.proxy_auth_challenges) else {
                // Reactive Basic: only when the proxy offers it, nothing stronger was available
                // and Basic was not already rejected on this attempt.
                if !sent_basic && challenges_offer_basic(&parsed.proxy_auth_challenges) {
                    if let Some(header) = basic_auth_header(node) {
                        if !parsed.connection_close {
                            drain_http_body(stream, &parsed).await?;
                        }
                        *pending_auth_header = Some(header);
                        return Ok(if parsed.connection_close {
                            HttpConnectOutcome::ReconnectRequired
                        } else {
                            HttpConnectOutcome::ContinueSameStream
                        });
                    }
                }
                tracing::warn!(
                    target: "routeward::proxy::http_connect",
                    "HTTP proxy rejected CONNECT with 407: {}",
                    parsed.status_line
                );
                return Err(RouteWardError::AuthenticationRejected {
                    key: ERR_KEY_AUTH_REJECTED,
                });
            };

            let challenge_token = extract_challenge_token(&parsed.proxy_auth_challenges, scheme);
            if !parsed.connection_close {
                drain_http_body(stream, &parsed).await?;
            }

            let spn_owned = effective_spn.to_string();
            let creds_opt = node.auth.clone();
            let sess = match sspi_session.take() {
                Some(existing) if !parsed.connection_close || challenge_token.is_some() => existing,
                _ => {
                    tokio::task::spawn_blocking(move || {
                        SspiClientSession::acquire(scheme, &spn_owned, creds_opt.as_ref())
                    })
                    .await
                    .map_err(|err| {
                        tracing::warn!(target: "routeward::proxy::sspi", "SSPI acquire join error: {err}");
                        RouteWardError::AuthenticationRejected {
                            key: ERR_KEY_AUTH_REJECTED,
                        }
                    })??
                }
            };

            let had_challenge = challenge_token.is_some();
            let (updated_sess, token_b64, _complete) =
                sspi_step_async(sess, challenge_token).await?;

            if parsed.connection_close {
                if had_challenge {
                    // Proxy dropped the connection during/after a Type 2 challenge: do not replay
                    // a Type 3 token on a new TCP socket; reset state for a clean retry.
                    *sspi_session = None;
                    *pending_auth_header = None;
                } else {
                    // Proxy closed the unauthenticated 407 socket right before accepting Type 1:
                    // keep the SSPI context and Type 1 token so Type 2 completes on the next socket.
                    *sspi_session = Some(updated_sess);
                    *pending_auth_header = Some(format_sspi_auth_header(scheme, &token_b64));
                }
                return Ok(HttpConnectOutcome::ReconnectRequired);
            }

            *sspi_session = Some(updated_sess);
            *pending_auth_header = Some(format_sspi_auth_header(scheme, &token_b64));
            return Ok(HttpConnectOutcome::ContinueSameStream);
        }

        Err(RouteWardError::ProtocolHandshake {
            key: ERR_KEY_HANDSHAKE_FAILED,
            detail: parsed.status_line,
        })
    }

    pub fn format_host_port(host: &str, port: u16) -> String {
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }

    pub fn encode_socks5_address(
        buf: &mut Vec<u8>,
        target_host: &str,
        target_port: u16,
        proto: &ProtocolConstants,
    ) -> RouteWardResult<()> {
        if let Ok(ip) = IpAddr::from_str(target_host) {
            match ip {
                IpAddr::V4(v4) => {
                    buf.push(proto.socks5_atyp_ipv4);
                    buf.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    buf.push(proto.socks5_atyp_ipv6);
                    buf.extend_from_slice(&v6.octets());
                }
            }
        } else {
            let domain_bytes = target_host.as_bytes();
            if domain_bytes.len() > MAX_SOCKS5_DOMAIN_BYTES {
                return Err(RouteWardError::ProtocolHandshake {
                    key: ERR_KEY_HANDSHAKE_FAILED,
                    detail: "SOCKS5 domain name exceeds 255 bytes".to_string(),
                });
            }
            buf.push(proto.socks5_atyp_domain);
            buf.push(domain_bytes.len() as u8);
            buf.extend_from_slice(domain_bytes);
        }
        buf.extend_from_slice(&target_port.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyCredentials, ProxyNode, ProxyProtocol, SystemConstants};
    use tokio::io::{duplex, AsyncWriteExt};

    #[tokio::test]
    async fn socks5_rejects_credentials_longer_than_255_bytes() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = ProxyNode {
            id: "test-socks5".to_string(),
            name: "Test".to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port: 1080,
            auth: Some(ProxyCredentials::new("u".repeat(256), "secret")),
            tls: false,
            tls_skip_verify: false,
            sni: None,
            udp_enabled: false,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        };
        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut req = [0u8; 4];
            let _ = tokio::io::AsyncReadExt::read_exact(&mut server, &mut req).await;
            let _ = server
                .write_all(&[proto.socks5_version, proto.socks5_auth_password])
                .await;
        });

        let err = ProxyConnector::negotiate_socks5(
            &mut client,
            &node,
            "example.com",
            443,
            proto.socks5_cmd_connect,
            &proto,
        )
        .await
        .expect_err("username >255 bytes must fail RFC 1929 validation");
        assert!(err.to_string().contains("1..=255"));
    }

    #[tokio::test]
    async fn http_connect_rejects_oversized_unterminated_header() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = ProxyNode {
            id: "test-http".to_string(),
            name: "HTTP".to_string(),
            protocol: ProxyProtocol::Http,
            host: "127.0.0.1".to_string(),
            port: 8080,
            auth: None,
            tls: false,
            tls_skip_verify: false,
            sni: None,
            udp_enabled: false,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        };
        let (mut client, mut server) = duplex(16384);
        tokio::spawn(async move {
            let mut drain = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut server, &mut drain).await;
            let payload = vec![b'X'; MAX_HTTP_RESPONSE_HEADER_BYTES + 16];
            let _ = server.write_all(&payload).await;
        });

        let err =
            ProxyConnector::negotiate_http_connect(&mut client, &node, "example.com", 443, &proto)
                .await
                .expect_err("unterminated header exceeding limit must error");
        assert!(err.to_string().contains("exceeded maximum allowed size"));
    }

    #[tokio::test]
    async fn brackets_ipv6_literals_in_proxy_addrs_and_http_connect() {
        assert_eq!(ProxyConnector::format_host_port("::1", 1080), "[::1]:1080");
        assert_eq!(
            ProxyConnector::format_host_port("[::1]", 1080),
            "[::1]:1080"
        );
        assert_eq!(
            ProxyConnector::format_host_port("127.0.0.1", 1080),
            "127.0.0.1:1080"
        );

        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = ProxyNode {
            id: "test-http-v6".to_string(),
            name: "HTTPv6".to_string(),
            protocol: ProxyProtocol::Http,
            host: "::1".to_string(),
            port: 8080,
            auth: None,
            tls: false,
            tls_skip_verify: false,
            sni: None,
            udp_enabled: false,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        };
        let (mut client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let n = tokio::io::AsyncReadExt::read(&mut server, &mut buf)
                .await
                .unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            req
        });

        ProxyConnector::negotiate_http_connect(&mut client, &node, "2001:db8::1", 443, &proto)
            .await
            .expect("HTTP CONNECT over IPv6 target literal should succeed");
        let sent_req = server_task.await.unwrap();
        assert!(sent_req
            .starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n"));
    }

    #[tokio::test]
    async fn socks4_and_socks4a_wire_handshake_and_ipv6_rejection() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = ProxyNode {
            id: "test-socks4".to_string(),
            name: "SOCKS4".to_string(),
            protocol: ProxyProtocol::Socks4,
            host: "127.0.0.1".to_string(),
            port: 1080,
            auth: Some(ProxyCredentials::new("edgeuser", "")),
            tls: false,
            tls_skip_verify: false,
            sni: None,
            udp_enabled: false,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        };

        let (mut client, mut server) = duplex(256);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let n = tokio::io::AsyncReadExt::read(&mut server, &mut buf)
                .await
                .unwrap();
            server
                .write_all(&[0x00, 90, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            buf[..n].to_vec()
        });

        ProxyConnector::negotiate_socks4(&mut client, &node, "edge.example.com", 443, &proto)
            .await
            .expect("SOCKS4a domain connect should succeed");
        let packet = server_task.await.unwrap();
        assert_eq!(packet[0], 4);
        assert_eq!(packet[1], 1);
        assert_eq!(&packet[2..4], &443u16.to_be_bytes());
        assert_eq!(&packet[4..8], &[0, 0, 0, 1]);
        assert!(packet[8..].starts_with(b"edgeuser\0edge.example.com\0"));

        let (mut c6, _) = duplex(64);
        let err = ProxyConnector::negotiate_socks4(&mut c6, &node, "2001:db8::1", 443, &proto)
            .await
            .expect_err("SOCKS4 must reject IPv6 targets");
        assert!(err.to_string().contains("IPv6"));
    }

    #[tokio::test]
    async fn http_connect_drains_407_chunked_body_and_handles_200_keepalive() {
        let resp = ParsedHttpResponse {
            status_code: 407,
            status_line: "HTTP/1.1 407 Proxy Authentication Required".to_string(),
            proxy_auth_challenges: vec!["NTLM".to_string()],
            content_length: None,
            is_chunked: true,
            connection_close: false,
        };
        let (mut client, mut server) = duplex(512);
        tokio::spawn(async move {
            let _ = server.write_all(b"5\r\nhello\r\n0\r\n\r\nNEXT").await;
        });
        drain_http_body(&mut client, &resp)
            .await
            .expect("drain chunked 407 body cleanly");
        let mut tail = [0u8; 4];
        client.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"NEXT");
    }

    fn http_test_node(id: &str, tls: bool, with_auth: bool) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            name: "HTTP".to_string(),
            protocol: ProxyProtocol::Http,
            host: "127.0.0.1".to_string(),
            port: 8080,
            auth: with_auth.then(|| ProxyCredentials::new("alice", "secret")),
            tls,
            tls_skip_verify: false,
            sni: None,
            udp_enabled: false,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        }
    }

    async fn read_request_head<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> String {
        let mut collected = Vec::new();
        let mut byte = [0u8; 1];
        while !collected.ends_with(b"\r\n\r\n") {
            if reader.read_exact(&mut byte).await.is_err() {
                break;
            }
            collected.push(byte[0]);
        }
        String::from_utf8_lossy(&collected).into_owned()
    }

    #[tokio::test]
    async fn plaintext_proxy_receives_no_authorization_on_first_request() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = http_test_node("plain-first-request", false, true);
        let (mut client, mut server) = duplex(2048);
        let server_task = tokio::spawn(async move {
            let head = read_request_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            head
        });

        ProxyConnector::negotiate_http_connect(&mut client, &node, "example.com", 443, &proto)
            .await
            .expect("CONNECT without challenge succeeds");
        let head = server_task.await.unwrap();
        assert!(head.starts_with("CONNECT example.com:443 HTTP/1.1"));
        assert!(
            !head.to_ascii_lowercase().contains("proxy-authorization"),
            "no credentials may be sent before a 407 challenge: {head}"
        );
    }

    #[tokio::test]
    async fn basic_only_407_is_answered_with_basic_and_succeeds() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = http_test_node("basic-only-reactive", false, true);
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let first = read_request_head(&mut server).await;
            server
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
            let second = read_request_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            (first, second)
        });

        ProxyConnector::negotiate_http_connect(&mut client, &node, "example.com", 443, &proto)
            .await
            .expect("Basic-only proxy must be served after the 407");
        let (first, second) = server_task.await.unwrap();
        assert!(!first.to_ascii_lowercase().contains("proxy-authorization"));
        let expected_token = BASE64_STANDARD.encode("alice:secret");
        assert!(
            second.contains(&format!("Proxy-Authorization: Basic {expected_token}")),
            "second request must carry Basic credentials: {second}"
        );
    }

    #[tokio::test]
    async fn basic_rejected_after_basic_does_not_loop() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = http_test_node("basic-rejected", false, true);
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let _ = read_request_head(&mut server).await;
                server
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
        });

        let err =
            ProxyConnector::negotiate_http_connect(&mut client, &node, "example.com", 443, &proto)
                .await
                .expect_err("wrong Basic credentials must be rejected");
        assert!(matches!(err, RouteWardError::AuthenticationRejected { .. }));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn ntlm_challenge_never_triggers_basic() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = http_test_node("ntlm-never-basic", false, true);
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut seen = read_request_head(&mut server).await;
            server
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
            // Whatever follows (an NTLM Type 1 token, or nothing when SSPI is unavailable) is
            // recorded; the stream is then closed.
            let mut rest = Vec::new();
            let _ = tokio::time::timeout(Duration::from_millis(500), server.read_to_end(&mut rest))
                .await;
            seen.push_str(&String::from_utf8_lossy(&rest));
            seen
        });

        let _ =
            ProxyConnector::negotiate_http_connect(&mut client, &node, "example.com", 443, &proto)
                .await;
        drop(client);
        let seen = server_task.await.unwrap();
        assert!(
            !seen.contains("Basic "),
            "Basic credentials must never answer an NTLM challenge: {seen}"
        );
    }

    #[tokio::test]
    async fn basic_offered_alongside_ntlm_prefers_ntlm() {
        let challenges = vec!["Basic realm=\"x\"".to_string(), "NTLM".to_string()];
        assert!(select_sspi_scheme(&challenges).is_some());
        assert!(challenges_offer_basic(&challenges));
        assert!(!challenges_offer_basic(&["NTLM".to_string()]));
        assert!(challenges_offer_basic(&["basic realm=\"y\"".to_string()]));
    }

    #[test]
    fn tls_hop_keeps_preemptive_basic_and_plaintext_does_not() {
        let tls_node = http_test_node("preemptive-tls", true, true);
        let header = initial_basic_auth_header(&tls_node).expect("TLS keeps pre-emptive Basic");
        assert!(header.starts_with(BASIC_AUTH_HEADER_PREFIX));

        let plain_node = http_test_node("preemptive-plain", false, true);
        assert!(initial_basic_auth_header(&plain_node).is_none());

        remember_basic_accepted(&plain_node);
        assert!(initial_basic_auth_header(&plain_node).is_some());
        forget_basic_accepted(&plain_node);
        assert!(initial_basic_auth_header(&plain_node).is_none());
    }

    #[test]
    fn basic_cache_key_changes_with_username_and_never_contains_credentials() {
        let alice = http_test_node("key-user", false, true);
        let mut bob = alice.clone();
        bob.auth = Some(ProxyCredentials::new("bob", "secret"));
        let mut other_password = alice.clone();
        other_password.auth = Some(ProxyCredentials::new("alice", "different"));

        assert_ne!(basic_cache_key(&alice), basic_cache_key(&bob));
        assert_eq!(basic_cache_key(&alice), basic_cache_key(&other_password));
        let key = basic_cache_key(&alice);
        assert!(!key.contains("alice") && !key.contains("secret"));

        remember_basic_accepted(&alice);
        assert!(is_basic_known_accepted(&alice));
        assert!(!is_basic_known_accepted(&bob));
        forget_basic_accepted(&alice);
    }

    #[tokio::test]
    async fn known_basic_proxy_skips_the_extra_round_trip() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = http_test_node("basic-cache-hit", false, true);
        remember_basic_accepted(&node);
        let (mut client, mut server) = duplex(2048);
        let server_task = tokio::spawn(async move {
            let head = read_request_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            head
        });
        ProxyConnector::negotiate_http_connect(&mut client, &node, "example.com", 443, &proto)
            .await
            .expect("cached Basic proxy succeeds first try");
        let head = server_task.await.unwrap();
        assert!(head.contains(BASIC_AUTH_HEADER_PREFIX));
        forget_basic_accepted(&node);
    }

    #[test]
    fn hostname_validation_rejects_injection_and_oversize_but_keeps_underscores() {
        assert!(is_safe_hostname("_dmarc.example.com"));
        assert!(is_safe_hostname("2001:db8::1"));
        assert!(!is_safe_hostname(""));
        assert!(!is_safe_hostname("a.com\r\nHost: evil"));
        assert!(!is_safe_hostname("a b.com"));
        assert!(!is_safe_hostname("a\u{7f}.com"));
        assert!(!is_safe_hostname("a\u{0}.com"));
        let label_63 = "a".repeat(63);
        let label_64 = "a".repeat(64);
        assert!(is_safe_hostname(&format!("{label_63}.com")));
        assert!(!is_safe_hostname(&format!("{label_64}.com")));
        let name_253 = format!("{label_63}.{label_63}.{label_63}.{}", "a".repeat(61));
        assert_eq!(name_253.len(), 253);
        assert!(is_safe_hostname(&name_253));
        assert!(!is_safe_hostname(&format!("{name_253}a")));
    }

    #[tokio::test]
    async fn http_connect_refuses_target_with_crlf_injection() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let node = http_test_node("crlf-target", false, false);
        let (mut client, _server) = duplex(1024);
        let err = ProxyConnector::negotiate_http_connect(
            &mut client,
            &node,
            "a.com HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET /",
            443,
            &proto,
        )
        .await
        .expect_err("CRLF in target host must be refused");
        assert!(err.to_string().contains("Refusing target host"));
    }

    #[tokio::test]
    async fn socks5_refuses_domains_over_255_bytes_instead_of_truncating() {
        let proto = SystemConstants::load_embedded().unwrap().protocols;
        let mut buf = Vec::new();
        let long = "a".repeat(300);
        assert!(ProxyConnector::encode_socks5_address(&mut buf, &long, 443, &proto).is_err());
        assert!(buf.is_empty());

        let mut ok_buf = Vec::new();
        ProxyConnector::encode_socks5_address(&mut ok_buf, &"b".repeat(255), 443, &proto)
            .expect("255 bytes fits the one-byte length");
        assert_eq!(ok_buf[1], 255);

        let node = http_test_node("socks5-long", false, false);
        let (mut client, _server) = duplex(1024);
        let err = ProxyConnector::negotiate_socks5(
            &mut client,
            &node,
            &long,
            443,
            proto.socks5_cmd_connect,
            &proto,
        )
        .await
        .expect_err("overlong SOCKS5 domain must be refused before any write");
        assert!(err.to_string().contains("Refusing target host"));

        let (mut client2, _server2) = duplex(1024);
        let err = ProxyConnector::negotiate_socks5(
            &mut client2,
            &node,
            "evil.com\r\nx",
            443,
            proto.socks5_cmd_connect,
            &proto,
        )
        .await
        .expect_err("control characters in SOCKS5 domain must be refused");
        assert!(err.to_string().contains("Refusing target host"));
    }
}
