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

pub mod sni;
pub mod udp;
pub mod uri;

use crate::config::{ChainStrategy, ProtocolConstants, ProxyNode, ProxyProtocol, SystemConstants};
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_AUTH_REJECTED, ERR_KEY_CHAIN_EMPTY,
    ERR_KEY_CONNECTION_TIMEOUT, ERR_KEY_HANDSHAKE_FAILED, ERR_KEY_UDP_NOT_SUPPORTED,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const HTTP_HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";
const MAX_HTTP_RESPONSE_HEADER_BYTES: usize = 4096;

pub trait AsyncTunnelStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncTunnelStream for T {}

pub struct ProxyConnector;

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

    pub async fn connect_single(
        node: &ProxyNode,
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<TcpStream> {
        let connect_timeout = Duration::from_millis(constants.network.tcp_connect_timeout_ms);
        let handshake_timeout = Duration::from_millis(constants.network.proxy_handshake_timeout_ms);
        let fwmark = constants.network.linux_fwmark;

        let proxy_addr = format!("{}:{}", node.host, node.port);
        let mut stream = timeout(
            connect_timeout,
            Self::connect_tcp_marked(&proxy_addr, fwmark),
        )
        .await
        .map_err(|_| RouteWardError::ConnectionTimeout {
            key: ERR_KEY_CONNECTION_TIMEOUT,
        })?
        .map_err(RouteWardError::Io)?;

        timeout(
            handshake_timeout,
            Self::negotiate_hop(
                &mut stream,
                node,
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

    pub async fn connect_chain(
        hops: &[ProxyNode],
        target_host: &str,
        target_port: u16,
        constants: &SystemConstants,
    ) -> RouteWardResult<TcpStream> {
        if hops.is_empty() {
            return Err(RouteWardError::EmptyProxyChain {
                key: ERR_KEY_CHAIN_EMPTY,
            });
        }

        let connect_timeout = Duration::from_millis(constants.network.tcp_connect_timeout_ms);
        let handshake_timeout = Duration::from_millis(constants.network.proxy_handshake_timeout_ms);
        let fwmark = constants.network.linux_fwmark;

        let first_hop = &hops[0];
        let entry_addr = format!("{}:{}", first_hop.host, first_hop.port);
        let mut stream = timeout(
            connect_timeout,
            Self::connect_tcp_marked(&entry_addr, fwmark),
        )
        .await
        .map_err(|_| RouteWardError::ConnectionTimeout {
            key: ERR_KEY_CONNECTION_TIMEOUT,
        })?
        .map_err(RouteWardError::Io)?;

        for idx in 0..hops.len() {
            let current_hop = &hops[idx];
            let (next_host, next_port) = if idx + 1 < hops.len() {
                (hops[idx + 1].host.as_str(), hops[idx + 1].port)
            } else {
                (target_host, target_port)
            };

            timeout(
                handshake_timeout,
                Self::negotiate_hop(
                    &mut stream,
                    current_hop,
                    next_host,
                    next_port,
                    &constants.protocols,
                ),
            )
            .await
            .map_err(|_| RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            })??;
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
    ) -> RouteWardResult<TcpStream> {
        let enabled_hops: Vec<ProxyNode> = hops.iter().filter(|n| n.enabled).cloned().collect();
        if enabled_hops.is_empty() {
            return Err(RouteWardError::EmptyProxyChain {
                key: ERR_KEY_CHAIN_EMPTY,
            });
        }

        match strategy {
            ChainStrategy::Sequence => {
                Self::connect_chain(&enabled_hops, target_host, target_port, constants).await
            }
            ChainStrategy::Failover => {
                let mut last_err = None;
                for node in &enabled_hops {
                    match Self::connect_single(node, target_host, target_port, constants).await {
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
                sorted.sort_by_key(|n| n.last_latency_ms.unwrap_or(u64::MAX));
                let mut last_err = None;
                for node in &sorted {
                    match Self::connect_single(node, target_host, target_port, constants).await {
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
                    match Self::connect_single(
                        &enabled_hops[idx],
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
            ProxyProtocol::Http | ProxyProtocol::Https => {
                Self::negotiate_http_connect(stream, node, target_host, target_port, proto).await
            }
        }
    }

    pub async fn negotiate_socks5<S: AsyncTunnelStream>(
        stream: &mut S,
        node: &ProxyNode,
        target_host: &str,
        target_port: u16,
        command: u8,
        proto: &ProtocolConstants,
    ) -> RouteWardResult<Option<SocketAddr>> {
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
        Self::encode_socks5_address(&mut req, target_host, target_port, proto);
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
        proto: &ProtocolConstants,
    ) -> RouteWardResult<()> {
        let auth_header = if let Some(creds) = &node.auth {
            let pass = creds.password_str();
            if !creds.username.is_empty() || !pass.is_empty() {
                let token = BASE64_STANDARD.encode(format!("{}:{pass}", creds.username));
                format!("Proxy-Authorization: Basic {token}\r\n")
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let request = format!(
            "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;

        let mut response_buf = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while response_buf.len() < MAX_HTTP_RESPONSE_HEADER_BYTES {
            stream.read_exact(&mut byte).await?;
            response_buf.push(byte[0]);
            if response_buf.ends_with(HTTP_HEADER_TERMINATOR) {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&response_buf);
        if response_str.starts_with(&proto.http_success_status_prefix)
            || response_str.starts_with(&proto.http_alt_success_status_prefix)
        {
            Ok(())
        } else {
            let status_line = response_str.lines().next().unwrap_or("HTTP Error");
            Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: status_line.to_string(),
            })
        }
    }

    pub fn encode_socks5_address(
        buf: &mut Vec<u8>,
        target_host: &str,
        target_port: u16,
        proto: &ProtocolConstants,
    ) {
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
            let len = domain_bytes.len().min(u8::MAX as usize);
            buf.push(proto.socks5_atyp_domain);
            buf.push(len as u8);
            buf.extend_from_slice(&domain_bytes[..len]);
        }
        buf.extend_from_slice(&target_port.to_be_bytes());
    }
}
