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

//! Minimal SOCKS5 TCP (`CONNECT`) + UDP (`UDP ASSOCIATE`, RFC 1928 §7) test server and UDP echo server
//! used exclusively by automated integration test suites.

use parking_lot::Mutex;
use routeward_core::config::{ProtocolConstants, SystemConstants};
use routeward_core::proxy::udp::{
    decode_socks5_udp_datagram, encode_socks5_udp_datagram, Socks5UdpTarget,
};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:1080";
const UDP_RELAY_RECV_TIMEOUT_MS: u64 = 2000;
const UDP_BUFFER_SIZE: usize = 65535;

#[derive(Default)]
struct ServerStats {
    tcp_connect_requests: AtomicUsize,
    udp_associate_requests: AtomicUsize,
    udp_associate_refused: AtomicUsize,
    udp_datagrams_relayed: AtomicUsize,
    udp_echo_received: AtomicUsize,
    last_udp_target: Mutex<String>,
    stats_file: Option<String>,
}

impl ServerStats {
    fn flush(&self) {
        let Some(ref path) = self.stats_file else {
            return;
        };
        let last_target = self.last_udp_target.lock().clone();
        let json = serde_json::json!({
            "tcp_connect_requests": self.tcp_connect_requests.load(Ordering::SeqCst),
            "udp_associate_requests": self.udp_associate_requests.load(Ordering::SeqCst),
            "udp_associate_refused": self.udp_associate_refused.load(Ordering::SeqCst),
            "udp_datagrams_relayed": self.udp_datagrams_relayed.load(Ordering::SeqCst),
            "udp_echo_received": self.udp_echo_received.load(Ordering::SeqCst),
            "last_udp_target": last_target,
        });
        if let Ok(serialized) = serde_json::to_string(&json) {
            let _ = fs::write(path, serialized);
        }
    }
}

struct ServerConfig {
    bind_addr: SocketAddr,
    udp_echo_bind: Option<SocketAddr>,
    echo_prefix: String,
    disable_udp_associate: bool,
    domain_map: Arc<HashMap<String, IpAddr>>,
    stats: Arc<ServerStats>,
}

fn parse_args() -> ServerConfig {
    let mut bind_addr: SocketAddr = DEFAULT_BIND_ADDR.parse().expect("valid default bind");
    let mut udp_echo_bind: Option<SocketAddr> = None;
    let mut echo_prefix = String::new();
    let mut disable_udp_associate = false;
    let mut domain_map = HashMap::new();
    let mut stats_file = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                if let Some(val) = args.next() {
                    bind_addr = val.parse().expect("valid --bind SocketAddr");
                }
            }
            "--udp-echo-bind" => {
                if let Some(val) = args.next() {
                    udp_echo_bind = Some(val.parse().expect("valid --udp-echo-bind SocketAddr"));
                }
            }
            "--echo-prefix" => {
                if let Some(val) = args.next() {
                    echo_prefix = val;
                }
            }
            "--disable-udp-associate" | "--refuse-udp-associate" => {
                disable_udp_associate = true;
            }
            "--map-domain" => {
                if let Some(val) = args.next() {
                    if let Some((dom, ip_str)) = val.split_once('=') {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            domain_map.insert(dom.trim().to_ascii_lowercase(), ip);
                        }
                    }
                }
            }
            "--stats-file" => {
                stats_file = args.next();
            }
            _ => {}
        }
    }

    let stats = Arc::new(ServerStats {
        stats_file,
        ..Default::default()
    });
    stats.flush();

    ServerConfig {
        bind_addr,
        udp_echo_bind,
        echo_prefix,
        disable_udp_associate,
        domain_map: Arc::new(domain_map),
        stats,
    }
}

async fn resolve_target_addr(
    host: &str,
    port: u16,
    domain_map: &HashMap<String, IpAddr>,
) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(&mapped_ip) = domain_map.get(&normalized) {
        return Some(SocketAddr::new(mapped_ip, port));
    }
    lookup_host((normalized.as_str(), port))
        .await
        .ok()
        .and_then(|mut iter| iter.next())
}

async fn read_socks5_address(stream: &mut TcpStream, atyp: u8) -> std::io::Result<(String, u16)> {
    let host = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut dom = vec![0u8; len_buf[0] as usize];
            stream.read_exact(&mut dom).await?;
            String::from_utf8_lossy(&dom).into_owned()
        }
        SOCKS5_ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported ATYP",
            ));
        }
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);
    Ok((host, port))
}

async fn handle_client(
    mut stream: TcpStream,
    disable_udp_associate: bool,
    domain_map: Arc<HashMap<String, IpAddr>>,
    stats: Arc<ServerStats>,
    proto: Arc<ProtocolConstants>,
) {
    let mut greeting = [0u8; 2];
    if stream.read_exact(&mut greeting).await.is_err() || greeting[0] != SOCKS5_VERSION {
        return;
    }
    let nmethods = greeting[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if stream.read_exact(&mut methods).await.is_err() {
        return;
    }
    if stream
        .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])
        .await
        .is_err()
    {
        return;
    }

    let mut req_head = [0u8; 4];
    if stream.read_exact(&mut req_head).await.is_err() || req_head[0] != SOCKS5_VERSION {
        return;
    }
    let cmd = req_head[1];
    let atyp = req_head[3];
    let Ok((target_host, target_port)) = read_socks5_address(&mut stream, atyp).await else {
        return;
    };

    match cmd {
        SOCKS5_CMD_CONNECT => {
            stats.tcp_connect_requests.fetch_add(1, Ordering::SeqCst);
            stats.flush();
            let Some(target_addr) =
                resolve_target_addr(&target_host, target_port, &domain_map).await
            else {
                let _ = stream
                    .write_all(&[
                        SOCKS5_VERSION,
                        SOCKS5_REP_GENERAL_FAILURE,
                        0x00,
                        SOCKS5_ATYP_IPV4,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ])
                    .await;
                return;
            };
            match TcpStream::connect(target_addr).await {
                Ok(mut outbound) => {
                    if stream
                        .write_all(&[
                            SOCKS5_VERSION,
                            SOCKS5_REP_SUCCESS,
                            0x00,
                            SOCKS5_ATYP_IPV4,
                            127,
                            0,
                            0,
                            1,
                            0,
                            0,
                        ])
                        .await
                        .is_ok()
                    {
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut outbound).await;
                    }
                }
                Err(_) => {
                    let _ = stream
                        .write_all(&[
                            SOCKS5_VERSION,
                            SOCKS5_REP_GENERAL_FAILURE,
                            0x00,
                            SOCKS5_ATYP_IPV4,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ])
                        .await;
                }
            }
        }
        SOCKS5_CMD_UDP_ASSOCIATE => {
            stats.udp_associate_requests.fetch_add(1, Ordering::SeqCst);
            if disable_udp_associate {
                stats.udp_associate_refused.fetch_add(1, Ordering::SeqCst);
                stats.flush();
                let _ = stream
                    .write_all(&[
                        SOCKS5_VERSION,
                        SOCKS5_REP_COMMAND_NOT_SUPPORTED,
                        0x00,
                        SOCKS5_ATYP_IPV4,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ])
                    .await;
                return;
            }
            stats.flush();

            let local_ip = stream
                .local_addr()
                .map(|a| a.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let Ok(udp_relay) = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await else {
                return;
            };
            let Ok(relay_addr) = udp_relay.local_addr() else {
                return;
            };

            let ip_octets = match relay_addr.ip() {
                IpAddr::V4(v4) => v4.octets(),
                IpAddr::V6(_) => [127, 0, 0, 1],
            };
            let port_bytes = relay_addr.port().to_be_bytes();
            if stream
                .write_all(&[
                    SOCKS5_VERSION,
                    SOCKS5_REP_SUCCESS,
                    0x00,
                    SOCKS5_ATYP_IPV4,
                    ip_octets[0],
                    ip_octets[1],
                    ip_octets[2],
                    ip_octets[3],
                    port_bytes[0],
                    port_bytes[1],
                ])
                .await
                .is_err()
            {
                return;
            }

            let udp_relay = Arc::new(udp_relay);
            let udp_relay_worker = udp_relay.clone();
            let stats_worker = stats.clone();
            let domain_map_worker = domain_map.clone();

            let relay_task = tokio::spawn(async move {
                let Ok(outbound_udp) = UdpSocket::bind("0.0.0.0:0").await else {
                    return;
                };
                let mut buf = vec![0u8; UDP_BUFFER_SIZE];
                let mut reply_buf = vec![0u8; UDP_BUFFER_SIZE];
                while let Ok((n, client_peer)) = udp_relay_worker.recv_from(&mut buf).await {
                    let Ok((socks_target, payload)) = decode_socks5_udp_datagram(&buf[..n], &proto)
                    else {
                        continue;
                    };

                    let (target_label, resolved_dst) = match &socks_target {
                        Socks5UdpTarget::Ipv4(ip, port) => (
                            format!("Ipv4({ip}:{port})"),
                            Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
                        ),
                        Socks5UdpTarget::Ipv6(ip, port) => (
                            format!("Ipv6({ip}:{port})"),
                            Some(SocketAddr::new(IpAddr::V6(*ip), *port)),
                        ),
                        Socks5UdpTarget::Domain(dom, port) => (
                            format!("Domain({dom}:{port})"),
                            resolve_target_addr(dom, *port, &domain_map_worker).await,
                        ),
                    };

                    *stats_worker.last_udp_target.lock() = target_label;
                    stats_worker
                        .udp_datagrams_relayed
                        .fetch_add(1, Ordering::SeqCst);
                    stats_worker.flush();

                    let Some(dst_addr) = resolved_dst else {
                        continue;
                    };
                    if outbound_udp.send_to(payload, dst_addr).await.is_err() {
                        continue;
                    }
                    if let Ok(Ok((resp_len, resp_from))) = tokio::time::timeout(
                        Duration::from_millis(UDP_RELAY_RECV_TIMEOUT_MS),
                        outbound_udp.recv_from(&mut reply_buf),
                    )
                    .await
                    {
                        let reply_target = match resp_from {
                            SocketAddr::V4(v4) => Socks5UdpTarget::Ipv4(*v4.ip(), v4.port()),
                            SocketAddr::V6(v6) => Socks5UdpTarget::Ipv6(*v6.ip(), v6.port()),
                        };
                        if let Ok(encoded_reply) = encode_socks5_udp_datagram(
                            &reply_target,
                            &reply_buf[..resp_len],
                            &proto,
                        ) {
                            let _ = udp_relay_worker.send_to(&encoded_reply, client_peer).await;
                        }
                    }
                }
            });

            // RFC 1928 §7: The UDP association terminates when the TCP control connection closes.
            let mut eof_buf = [0u8; 16];
            let _ = stream.read(&mut eof_buf).await;
            relay_task.abort();
        }
        _ => {
            let _ = stream
                .write_all(&[
                    SOCKS5_VERSION,
                    SOCKS5_REP_COMMAND_NOT_SUPPORTED,
                    0x00,
                    SOCKS5_ATYP_IPV4,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await;
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cfg = parse_args();

    if let Some(echo_addr) = cfg.udp_echo_bind {
        let echo_sock = UdpSocket::bind(echo_addr).await?;
        let prefix = cfg.echo_prefix.clone();
        let stats_echo = cfg.stats.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_BUFFER_SIZE];
            while let Ok((n, peer)) = echo_sock.recv_from(&mut buf).await {
                stats_echo.udp_echo_received.fetch_add(1, Ordering::SeqCst);
                stats_echo.flush();
                let mut out = prefix.as_bytes().to_vec();
                out.extend_from_slice(&buf[..n]);
                let _ = echo_sock.send_to(&out, peer).await;
            }
        });
    }

    let proto = Arc::new(
        SystemConstants::load_embedded()
            .expect("SystemConstants")
            .protocols,
    );
    let listener = TcpListener::bind(cfg.bind_addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let domain_map = cfg.domain_map.clone();
        let stats = cfg.stats.clone();
        let disable_udp = cfg.disable_udp_associate;
        let proto_clone = proto.clone();
        tokio::spawn(async move {
            handle_client(stream, disable_udp, domain_map, stats, proto_clone).await;
        });
    }
}
