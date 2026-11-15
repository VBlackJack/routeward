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

use super::{
    RouteWardController, SystemDiagnostics, WarnRateLimiter, COMPONENT_DNS, COMPONENT_ENGINE,
    COMPONENT_PROXY, COMPONENT_RULE, COMPONENT_TRANSPARENT, COMPONENT_WINDIVERT, ROUTE_BLOCK_LABEL,
    SIMULATED_DEFAULT_LATENCY_MS, SIMULATED_DEFAULT_RX_BYTES, SIMULATED_DEFAULT_TX_BYTES,
};
use crate::checker::{ProxyChecker, ProxyHealthReport};
use crate::config::security::{
    apply_secure_profile_file_permissions, create_secure_profile_dir, verify_profile_path_security,
};
use crate::config::{
    is_valid_profile_slug, slugify_profile_id, InterceptionMode, ProfileConfig, ProfileSummary,
    ProxyChain, ProxyNode, RoutingRule, RuleAction, SystemConstants, TransportProtocol,
};
use crate::dns::FakeIpEngine;
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_CONFIG_LOAD, ERR_KEY_DAEMON_INSECURE_PROFILE,
    ERR_KEY_PROXY_NOT_FOUND, ERR_KEY_RULE_BLOCKED,
};
use crate::i18n::I18nRegistry;
use crate::interceptor::backend::Interceptor;
use crate::interceptor::nat::{
    PendingSynOutcome, PendingSynQueue, PendingUdpOutcome, PendingUdpQueue, TransparentNatTable,
};
use crate::interceptor::nftables::NftablesInterceptor;
#[cfg(target_os = "linux")]
use crate::interceptor::nftables::TproxyRoutingSpec;
#[cfg(windows)]
use crate::interceptor::windivert::WinDivertInterceptor;
use crate::process::{ProcessAttribution, ProcessResolver};
use crate::proxy::sni::TlsSniExtractor;
use crate::proxy::udp::UdpAssociationManager;
use crate::proxy::uri::ProxyUriCodec;
use crate::proxy::ProxyConnector;
use crate::rules::{ConnectionRequest, RuleEngine, RuleEvaluationResult};
use crate::telemetry::{ConnectionStatus, LogLevel, TelemetryHub, TrackedConnection};
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use uuid::Uuid;

impl RouteWardController {
    pub fn new(constants: SystemConstants, profile: ProfileConfig, locale: &str) -> Self {
        let log_dir = constants.telemetry.resolve_process_log_dir();
        Self::new_with_log_dir(constants, profile, locale, log_dir)
    }

    pub fn new_daemon(constants: SystemConstants, profile: ProfileConfig, locale: &str) -> Self {
        let log_dir = constants.telemetry.resolve_daemon_log_dir();
        Self::new_with_log_dir(constants, profile, locale, log_dir)
    }

    pub fn new_user_cli(constants: SystemConstants, profile: ProfileConfig, locale: &str) -> Self {
        let log_dir = constants.telemetry.resolve_user_log_dir();
        Self::new_with_log_dir(constants, profile, locale, log_dir)
    }

    pub fn new_with_log_dir(
        constants: SystemConstants,
        profile: ProfileConfig,
        locale: &str,
        log_dir: std::path::PathBuf,
    ) -> Self {
        let i18n = I18nRegistry::new(locale);
        let dns = FakeIpEngine::new(&profile.dns_config, &constants.dns);
        let process_resolver = ProcessResolver::new(constants.telemetry.process_cache_ttl_ms);
        let telemetry =
            TelemetryHub::new_with_log_dir(&constants.telemetry, log_dir, profile.enable_logging);

        let nat_table = TransparentNatTable::new(
            std::process::id(),
            constants.network.default_transparent_tcp_port,
            constants.network.default_relay_tcp_port,
            constants.network.default_relay_http_port,
        );
        let upstream_endpoints: Vec<(IpAddr, u16)> = profile
            .proxies
            .iter()
            .filter_map(|p| p.host.parse::<IpAddr>().ok().map(|ip| (ip, p.port)))
            .collect();
        nat_table.set_upstream_endpoints(upstream_endpoints);

        #[cfg(windows)]
        let interceptor_backend: Arc<dyn Interceptor> = Arc::new(WinDivertInterceptor::new());
        #[cfg(not(windows))]
        let interceptor_backend: Arc<dyn Interceptor> = Arc::new(NftablesInterceptor::new());

        let udp_manager = UdpAssociationManager::new(&constants);
        let warn_rate_limiter = WarnRateLimiter::new(Duration::from_secs(
            constants.network.udp_warn_rate_limit_secs.max(1),
        ));

        let controller = Self {
            constants: Arc::new(constants),
            profile: Arc::new(RwLock::new(profile)),
            i18n,
            dns,
            process_resolver,
            telemetry,
            nat_table,
            udp_manager,
            warn_rate_limiter,
            fragmented_udp_drop_count: Arc::new(AtomicU64::new(0)),
            last_seen_orig_resolver: Arc::new(RwLock::new(None)),
            system_resolvers_override: Arc::new(RwLock::new(None)),
            bootstrapped_proxy_endpoints: Arc::new(DashMap::new()),
            direct_udp_pool: Arc::new(parking_lot::Mutex::new(Vec::new())),
            direct_udp_v6_pool: Arc::new(parking_lot::Mutex::new(Vec::new())),
            conntrack_cache: Arc::new(parking_lot::Mutex::new(None)),
            interceptor_backend,
            running: Arc::new(AtomicBool::new(false)),
        };

        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            controller.i18n.t("cli.engine.startup.loaded_profile"),
        );

        controller
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn start_engine(&self) {
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            self.i18n.t("cli.engine.startup.banner"),
        );
        self.flush_os_dns_cache("startup");

        let ticker_ctrl = self.clone();
        tokio::spawn(async move {
            let interval =
                Duration::from_millis(ticker_ctrl.constants.telemetry.sampling_interval_ms);
            while ticker_ctrl.is_running() {
                ticker_ctrl.telemetry.tick_bandwidth_sample();
                tokio::time::sleep(interval).await;
            }
        });

        let relay_ctrl = self.clone();
        tokio::spawn(async move {
            let bind_addr = format!(
                "{}:{}",
                relay_ctrl.constants.network.local_bind_host,
                relay_ctrl.constants.network.default_relay_tcp_port
            );
            if let Ok(listener) = TcpListener::bind(&bind_addr).await {
                relay_ctrl.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_ENGINE,
                    format!(
                        "{}: {}",
                        relay_ctrl.i18n.t("cli.engine.startup.listening_socks"),
                        bind_addr
                    ),
                );

                while relay_ctrl.is_running() {
                    if let Ok((client_stream, peer_addr)) = listener.accept().await {
                        let conn_ctrl = relay_ctrl.clone();
                        tokio::spawn(async move {
                            let _ = conn_ctrl
                                .handle_local_socks5_client(client_stream, peer_addr.port())
                                .await;
                        });
                    }
                }
            }
        });

        let trans_ctrl = self.clone();
        tokio::spawn(async move {
            let bind_addr = format!(
                "{}:{}",
                trans_ctrl.constants.network.transparent_bind_host,
                trans_ctrl.constants.network.default_transparent_tcp_port
            );
            if let Ok(listener) = TcpListener::bind(&bind_addr).await {
                trans_ctrl.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_TRANSPARENT,
                    format!(
                        "{}: {}",
                        trans_ctrl
                            .i18n
                            .t("cli.engine.startup.listening_transparent"),
                        bind_addr
                    ),
                );
                RouteWardController::accept_transparent_tcp_loop(trans_ctrl.clone(), listener)
                    .await;
            }
        });

        if let Some(v6_ip) = Self::ipv6_counterpart(&self.constants.network.transparent_bind_host) {
            let trans_v6_ctrl = self.clone();
            tokio::spawn(async move {
                let port = trans_v6_ctrl.constants.network.default_transparent_tcp_port;
                match Self::bind_tcp_v6_only(v6_ip, port) {
                    Ok(listener) => {
                        trans_v6_ctrl.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "{}: [{}]:{}",
                                trans_v6_ctrl
                                    .i18n
                                    .t("cli.engine.startup.listening_transparent"),
                                v6_ip,
                                port
                            ),
                        );
                        RouteWardController::accept_transparent_tcp_loop(
                            trans_v6_ctrl.clone(),
                            listener,
                        )
                        .await;
                    }
                    Err(err) => {
                        trans_v6_ctrl.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "IPv6 transparent TCP listener disabled on [{v6_ip}]:{port}: {err}"
                            ),
                        );
                    }
                }
            });
        }

        let dns_udp_ctrl = self.clone();
        tokio::spawn(async move {
            let bind_addr = format!(
                "{}:{}",
                dns_udp_ctrl.constants.network.transparent_bind_host,
                dns_udp_ctrl.constants.network.default_dns_listen_port
            );
            if let Ok(socket) = UdpSocket::bind(&bind_addr).await {
                ProxyConnector::apply_platform_mark_udp(
                    &socket,
                    dns_udp_ctrl.constants.network.linux_fwmark,
                );
                NftablesInterceptor::enable_udp_pktinfo(&socket);
                let socket = Arc::new(socket);
                dns_udp_ctrl.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_ENGINE,
                    format!("Listening for local/redirected UDP DNS queries on {bind_addr}"),
                );
                let mut buf = vec![0u8; 4096];
                while dns_udp_ctrl.is_running() {
                    if let Ok((len, peer_addr, local_dst_ip)) =
                        NftablesInterceptor::recv_udp_with_local_ip(&socket, &mut buf).await
                    {
                        let query_bytes = buf[..len].to_vec();
                        let sock_reply = Arc::clone(&socket);
                        let ctrl_query = dns_udp_ctrl.clone();
                        tokio::spawn(async move {
                            let orig_resolver = ctrl_query.lookup_udp_orig_dns_resolver(peer_addr);
                            let resp = ctrl_query
                                .resolve_dns_query_async(&query_bytes, orig_resolver, true)
                                .await;
                            if !resp.is_empty() {
                                let _ = NftablesInterceptor::send_udp_from_local_ip(
                                    &sock_reply,
                                    &resp,
                                    peer_addr,
                                    local_dst_ip,
                                )
                                .await;
                            }
                        });
                    }
                }
            }
        });

        if let Some(v6_ip) = Self::ipv6_counterpart(&self.constants.network.transparent_bind_host) {
            let dns_udp_v6_ctrl = self.clone();
            tokio::spawn(async move {
                let port = dns_udp_v6_ctrl.constants.network.default_dns_listen_port;
                match Self::bind_udp_v6_only(v6_ip, port) {
                    Ok(socket) => {
                        ProxyConnector::apply_platform_mark_udp(
                            &socket,
                            dns_udp_v6_ctrl.constants.network.linux_fwmark,
                        );
                        NftablesInterceptor::enable_ipv6_udp_pktinfo(&socket);
                        let socket = Arc::new(socket);
                        dns_udp_v6_ctrl.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_ENGINE,
                            format!("Listening for IPv6 UDP DNS queries on [{v6_ip}]:{port}"),
                        );
                        let mut buf = vec![0u8; 4096];
                        while dns_udp_v6_ctrl.is_running() {
                            if let Ok((len, peer_addr, local_dst_ip)) =
                                NftablesInterceptor::recv_udp_v6_with_local_ip(&socket, &mut buf)
                                    .await
                            {
                                let query_bytes = buf[..len].to_vec();
                                let sock_reply = Arc::clone(&socket);
                                let ctrl_query = dns_udp_v6_ctrl.clone();
                                tokio::spawn(async move {
                                    let orig_resolver =
                                        ctrl_query.lookup_udp_orig_dns_resolver(peer_addr);
                                    let resp = ctrl_query
                                        .resolve_dns_query_async(&query_bytes, orig_resolver, true)
                                        .await;
                                    if !resp.is_empty() {
                                        let _ = NftablesInterceptor::send_udp_v6_from_local_ip(
                                            &sock_reply,
                                            &resp,
                                            peer_addr,
                                            local_dst_ip,
                                        )
                                        .await;
                                    }
                                });
                            }
                        }
                    }
                    Err(err) => {
                        dns_udp_v6_ctrl.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_ENGINE,
                            format!("IPv6 UDP DNS listener disabled on [{v6_ip}]:{port}: {err}"),
                        );
                    }
                }
            });
        }

        let dns_tcp_ctrl = self.clone();
        tokio::spawn(async move {
            let dns_port = dns_tcp_ctrl.constants.network.default_dns_listen_port;
            let bind_addr = format!(
                "{}:{}",
                dns_tcp_ctrl.constants.network.transparent_bind_host, dns_port
            );
            if let Ok(listener) = TcpListener::bind(&bind_addr).await {
                dns_tcp_ctrl.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_ENGINE,
                    format!("Listening for local/redirected TCP DNS queries on {bind_addr}"),
                );
                RouteWardController::accept_dns_tcp_loop(dns_tcp_ctrl.clone(), listener, dns_port)
                    .await;
            }
        });

        if let Some(v6_ip) = Self::ipv6_counterpart(&self.constants.network.transparent_bind_host) {
            let dns_tcp_v6_ctrl = self.clone();
            tokio::spawn(async move {
                let dns_port = dns_tcp_v6_ctrl.constants.network.default_dns_listen_port;
                match Self::bind_tcp_v6_only(v6_ip, dns_port) {
                    Ok(listener) => {
                        dns_tcp_v6_ctrl.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_ENGINE,
                            format!("Listening for IPv6 TCP DNS queries on [{v6_ip}]:{dns_port}"),
                        );
                        RouteWardController::accept_dns_tcp_loop(
                            dns_tcp_v6_ctrl.clone(),
                            listener,
                            dns_port,
                        )
                        .await;
                    }
                    Err(err) => {
                        dns_tcp_v6_ctrl.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_ENGINE,
                            format!(
                                "IPv6 TCP DNS listener disabled on [{v6_ip}]:{dns_port}: {err}"
                            ),
                        );
                    }
                }
            });
        }

        let local_name_ctrl = self.clone();
        tokio::spawn(async move {
            let inspect_port = local_name_ctrl
                .constants
                .network
                .default_local_name_inspect_port;
            let bind_addr = format!(
                "{}:{}",
                local_name_ctrl.constants.network.transparent_bind_host, inspect_port
            );
            if let Ok(socket) = UdpSocket::bind(&bind_addr).await {
                ProxyConnector::apply_platform_mark_udp(
                    &socket,
                    local_name_ctrl.constants.network.linux_fwmark,
                );
                if let Err(err) = NftablesInterceptor::enable_udp_tproxy_options(&socket) {
                    local_name_ctrl.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!("Could not enable IP_TRANSPARENT/IP_RECVORIGDSTADDR on {bind_addr}: {err}"),
                    );
                }
                NftablesInterceptor::enable_udp_pktinfo(&socket);
                let socket = Arc::new(socket);
                local_name_ctrl.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_ENGINE,
                    format!("Listening for TPROXY UDP and LLMNR/mDNS inspection on {bind_addr}"),
                );
                let mut buf = vec![0u8; 65535];
                while local_name_ctrl.is_running() {
                    if let Ok((len, client_addr, orig_dst)) =
                        NftablesInterceptor::recv_udp_tproxy_orig_dst(&socket, &mut buf).await
                    {
                        let pkt_bytes = buf[..len].to_vec();
                        let sock_reply = Arc::clone(&socket);
                        let ctrl_inspect = local_name_ctrl.clone();
                        tokio::spawn(async move {
                            ctrl_inspect
                                .handle_tproxy_udp_datagram(
                                    &pkt_bytes,
                                    SocketAddr::V4(client_addr),
                                    orig_dst.map(SocketAddr::V4),
                                    &sock_reply,
                                )
                                .await;
                        });
                    }
                }
            }
        });

        if let Some(v6_ip) = Self::ipv6_counterpart(&self.constants.network.transparent_bind_host) {
            let local_name_v6_ctrl = self.clone();
            tokio::spawn(async move {
                let inspect_port = local_name_v6_ctrl
                    .constants
                    .network
                    .default_local_name_inspect_port;
                match Self::bind_udp_v6_only(v6_ip, inspect_port) {
                    Ok(socket) => {
                        ProxyConnector::apply_platform_mark_udp(
                            &socket,
                            local_name_v6_ctrl.constants.network.linux_fwmark,
                        );
                        if let Err(err) = NftablesInterceptor::enable_udp_tproxy_v6_options(&socket)
                        {
                            local_name_v6_ctrl.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_ENGINE,
                                format!("Could not enable IPv6 TPROXY/IPV6_RECVORIGDSTADDR on [{v6_ip}]:{inspect_port}: {err}"),
                            );
                        }
                        let socket = Arc::new(socket);
                        local_name_v6_ctrl.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_ENGINE,
                            format!(
                                "Listening for IPv6 TPROXY UDP inspection on [{v6_ip}]:{inspect_port}"
                            ),
                        );
                        let mut buf = vec![0u8; 65535];
                        while local_name_v6_ctrl.is_running() {
                            if let Ok((len, client_addr, orig_dst)) =
                                NftablesInterceptor::recv_udp_tproxy_v6_orig_dst(&socket, &mut buf)
                                    .await
                            {
                                let pkt_bytes = buf[..len].to_vec();
                                let sock_reply = Arc::clone(&socket);
                                let ctrl_inspect = local_name_v6_ctrl.clone();
                                tokio::spawn(async move {
                                    ctrl_inspect
                                        .handle_tproxy_udp_datagram(
                                            &pkt_bytes,
                                            SocketAddr::V6(client_addr),
                                            orig_dst.map(SocketAddr::V6),
                                            &sock_reply,
                                        )
                                        .await;
                                });
                            }
                        }
                    }
                    Err(err) => {
                        local_name_v6_ctrl.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_ENGINE,
                            format!("IPv6 TPROXY UDP listener disabled on [{v6_ip}]:{inspect_port}: {err}"),
                        );
                    }
                }
            });
        }

        let bootstrap_ctrl = self.clone();
        tokio::spawn(async move {
            bootstrap_ctrl.bootstrap_resolve_proxy_hosts().await;
        });
    }

    pub(super) fn ipv6_counterpart(bind_host: &str) -> Option<Ipv6Addr> {
        match bind_host.trim() {
            "0.0.0.0" => Some(Ipv6Addr::UNSPECIFIED),
            "127.0.0.1" => Some(Ipv6Addr::LOCALHOST),
            _ => None,
        }
    }

    pub(super) fn bind_tcp_v6_only(ip: Ipv6Addr, port: u16) -> std::io::Result<TcpListener> {
        let sock = tokio::net::TcpSocket::new_v6()?;
        sock.set_reuseaddr(true)?;
        Self::set_ipv6_only_tcp(&sock)?;
        sock.bind(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))?;
        sock.listen(1024)
    }

    pub(super) fn bind_udp_v6_only(ip: Ipv6Addr, port: u16) -> std::io::Result<UdpSocket> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::FromRawFd;
            let fd =
                unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            let on: libc::c_int = 1;
            unsafe {
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &on as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &on as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let addr = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: ip.octets(),
                    },
                    sin6_scope_id: 0,
                };
                if libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            std_sock.set_nonblocking(true)?;
            UdpSocket::from_std(std_sock)
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawSocket, FromRawSocket};
            use windows_sys::Win32::Networking::WinSock::{
                bind, setsockopt, socket, AF_INET6, IN6_ADDR, IN6_ADDR_0, INVALID_SOCKET,
                IPPROTO_IPV6, IPPROTO_UDP, IPV6_V6ONLY, SOCKADDR, SOCKADDR_IN6, SOCKADDR_IN6_0,
                SOCKET_ERROR, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR,
            };
            // Trigger Rust std Winsock initialization before raw socket() calls.
            let _ = tokio::net::TcpSocket::new_v6();
            let raw = unsafe { socket(AF_INET6 as i32, SOCK_DGRAM, IPPROTO_UDP) };
            if raw == INVALID_SOCKET {
                return Err(std::io::Error::last_os_error());
            }
            let std_sock = unsafe { std::net::UdpSocket::from_raw_socket(raw as _) };
            let on: i32 = 1;
            let raw_handle = std_sock.as_raw_socket() as _;
            unsafe {
                let _ = setsockopt(
                    raw_handle,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    &on as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
                let rc = setsockopt(
                    raw_handle,
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    &on as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
                if rc == SOCKET_ERROR {
                    return Err(std::io::Error::last_os_error());
                }
                let addr = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip.octets() },
                    },
                    Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
                };
                let brc = bind(
                    raw_handle,
                    &addr as *const SOCKADDR_IN6 as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN6>() as i32,
                );
                if brc == SOCKET_ERROR {
                    return Err(std::io::Error::last_os_error());
                }
            }
            std_sock.set_nonblocking(true)?;
            UdpSocket::from_std(std_sock)
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let std_sock =
                std::net::UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))?;
            std_sock.set_nonblocking(true)?;
            UdpSocket::from_std(std_sock)
        }
    }

    pub(super) fn set_ipv6_only_tcp(sock: &tokio::net::TcpSocket) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &on as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                setsockopt, IPPROTO_IPV6, IPV6_V6ONLY, SOCKET_ERROR,
            };
            let on: i32 = 1;
            let rc = unsafe {
                setsockopt(
                    sock.as_raw_socket() as usize,
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    &on as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                )
            };
            if rc == SOCKET_ERROR {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = sock;
            Ok(())
        }
    }

    pub(super) async fn accept_transparent_tcp_loop(
        ctrl: RouteWardController,
        listener: TcpListener,
    ) {
        while ctrl.is_running() {
            if let Ok((client_stream, peer_addr)) = listener.accept().await {
                let conn_ctrl = ctrl.clone();
                tokio::spawn(async move {
                    let _ = conn_ctrl
                        .handle_transparent_tcp_client(client_stream, peer_addr)
                        .await;
                });
            }
        }
    }

    pub(super) async fn accept_dns_tcp_loop(
        ctrl: RouteWardController,
        listener: TcpListener,
        dns_port: u16,
    ) {
        while ctrl.is_running() {
            if let Ok((stream, _peer_addr)) = listener.accept().await {
                let ctrl_query = ctrl.clone();
                tokio::spawn(async move {
                    #[cfg(not(windows))]
                    let orig_resolver =
                        NftablesInterceptor::query_original_dst_any(&stream, dns_port);
                    #[cfg(windows)]
                    let orig_resolver: Option<SocketAddr> = {
                        let _ = dns_port;
                        None
                    };
                    let _ = ctrl_query
                        .handle_dns_tcp_stream(stream, orig_resolver)
                        .await;
                });
            }
        }
    }

    pub(super) fn is_in_fake_subnet_any(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.dns.is_in_fake_subnet(v4),
            IpAddr::V6(_) => false,
        }
    }

    pub(super) fn resolve_fake_ip_any(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) => self.dns.resolve_fake_ip(v4),
            IpAddr::V6(_) => None,
        }
    }

    /// Starts the OS-level transparent packet interceptor (`Interceptor` trait backend).
    pub fn start_transparent_interceptor(&self) -> RouteWardResult<&'static str> {
        let backend_name = self.interceptor_backend.name();
        self.interceptor_backend.start(self.clone())?;
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            format!(
                "{}: {backend_name}",
                self.i18n.t("cli.engine.startup.interception_active")
            ),
        );
        Ok(backend_name)
    }

    pub fn stop_engine(&self) {
        let was_active = self.interceptor_backend.is_active();
        self.interceptor_backend.stop();
        self.udp_manager.clear_all();
        let was_running = self.running.swap(false, Ordering::SeqCst);
        if was_running || was_active {
            self.flush_os_dns_cache("shutdown");
        }
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            self.i18n.t("app.header.engine.stopped"),
        );
        self.telemetry.flush_file_logger();
    }

    /// Flushes the OS client DNS resolver cache (`dnsapi.dll!DnsFlushResolverCache` / `ipconfig /flushdns`
    /// on Windows; `resolvectl flush-caches` on Linux if `systemd-resolved` is active).
    pub fn flush_os_dns_cache(&self, stage: &str) {
        match crate::dns::flush_os_dns_cache() {
            Ok(method) => {
                self.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_DNS,
                    format!(
                        "{} ({stage} via {method})",
                        self.i18n.t("cli.engine.startup.dns_cache_flushed")
                    ),
                );
            }
            Err(detail) => {
                self.telemetry.push_log(
                    LogLevel::Debug,
                    COMPONENT_DNS,
                    format!("Skipped OS DNS cache flush on {stage}: {detail}"),
                );
            }
        }
    }

    /// Records the most recently observed non-loopback (or non-53/10853 safe loopback) original DNS resolver targeted by the OS.
    pub fn record_orig_dns_resolver(&self, addr: SocketAddr) {
        if let IpAddr::V4(v4) = addr.ip() {
            if self.dns.is_in_fake_subnet(&v4) {
                return;
            }
        }
        let dns_port = self.constants.dns.dns_standard_port;
        let local_dns_listen_port = self.constants.network.default_dns_listen_port;
        let is_safe_loopback = addr.ip().is_loopback()
            && addr.port() != dns_port
            && addr.port() != local_dns_listen_port;
        if (!addr.ip().is_loopback() || is_safe_loopback) && !addr.ip().is_unspecified() {
            *self.last_seen_orig_resolver.write() = Some(addr);
        }
    }

    /// Final egress guard ensuring no outbound TCP or UDP connection or datagram is ever emitted
    /// toward an untranslated IPv4 address belonging to the configured Fake-IP pool (`198.18.0.0/15`).
    /// Logs a rate-limited `WARN` and records a `Blocked` `TrackedConnection` when triggered.
    pub fn ensure_not_fake_ip_egress(
        &self,
        target_ip: IpAddr,
        target_port: u16,
        protocol: TransportProtocol,
        context: &str,
    ) -> RouteWardResult<()> {
        if let IpAddr::V4(v4) = target_ip {
            if self.dns.is_in_fake_subnet(&v4) {
                let mapped_domain = self.dns.resolve_fake_ip(&v4);
                self.push_rate_limited_warn(
                    "fake_ip_egress_guard",
                    COMPONENT_ENGINE,
                    format!(
                        "Final Fake-IP egress guard blocked untranslated {:?} destination {}:{} (domain={:?}, context={})",
                        protocol, v4, target_port, mapped_domain, context
                    ),
                );
                self.telemetry.record_connection(
                    TrackedConnection {
                        id: Uuid::new_v4().to_string(),
                        pid: 0,
                        process_name: "fake-ip-guard".to_string(),
                        process_path: context.to_string(),
                        target_host: v4.to_string(),
                        resolved_domain: mapped_domain,
                        target_port,
                        protocol,
                        matched_rule: "SecurityPolicy:FakeIpEgressGuard".to_string(),
                        route_label: ROUTE_BLOCK_LABEL.to_string(),
                        latency_ms: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        status: ConnectionStatus::Blocked,
                        started_at: Utc::now(),
                        error_detail: None,
                    },
                    false,
                );
                return Err(RouteWardError::BlockedByPolicy {
                    key: ERR_KEY_RULE_BLOCKED,
                    rule_name: "SecurityPolicy:FakeIpEgressGuard".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Inspects a raw IPv4 packet before outbound driver reinjection (`WinDivert`) and blocks it
    /// with a `WARN` log and `Blocked` connection record if `is_outbound` is `true` and its destination
    /// IPv4 address belongs to the Fake-IP pool (`198.18.0.0/15`).
    pub fn check_and_block_outbound_fake_ip_packet(
        &self,
        packet: &[u8],
        is_outbound: bool,
        component: &str,
    ) -> bool {
        if !is_outbound || packet.len() < 20 || (packet[0] >> 4) != 4 {
            return false;
        }
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        if !self.dns.is_in_fake_subnet(&dst_ip) {
            return false;
        }
        let proto_byte = packet[9];
        let protocol = match proto_byte {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            _ => TransportProtocol::Any,
        };
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        let dst_port = if packet.len() >= ihl + 4 {
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]])
        } else {
            0
        };
        let mapped_domain = self.dns.resolve_fake_ip(&dst_ip);
        self.push_rate_limited_warn(
            "fake_ip_packet_egress_guard",
            component,
            format!(
                "Final Fake-IP egress guard dropped outbound {:?} packet to untranslated Fake-IP {}:{} (domain={:?})",
                protocol, dst_ip, dst_port, mapped_domain
            ),
        );
        self.telemetry.record_connection(
            TrackedConnection {
                id: Uuid::new_v4().to_string(),
                pid: 0,
                process_name: "fake-ip-guard".to_string(),
                process_path: component.to_string(),
                target_host: dst_ip.to_string(),
                resolved_domain: mapped_domain,
                target_port: dst_port,
                protocol,
                matched_rule: "SecurityPolicy:FakeIpEgressGuard".to_string(),
                route_label: ROUTE_BLOCK_LABEL.to_string(),
                latency_ms: 0,
                rx_bytes: 0,
                tx_bytes: packet.len() as u64,
                status: ConnectionStatus::Blocked,
                started_at: Utc::now(),
                error_detail: None,
            },
            false,
        );
        true
    }

    /// Returns `true` if the active profile has at least one enabled rule with non-empty `domainPatterns`.
    pub fn has_enabled_domain_rules(&self) -> bool {
        let prof = self.profile.read();
        prof.rules
            .iter()
            .any(|r| r.enabled && !r.domain_patterns.is_empty())
    }

    /// Checks whether `cleanup` is allowed to run (refusing if a daemon is active unless `force` is true).
    pub fn check_cleanup_allowed(&self, force: bool) -> RouteWardResult<()> {
        if !force && crate::ipc::transport::is_daemon_ipc_active(&self.constants.ipc) {
            let msg = self
                .i18n
                .t(crate::error::ERR_KEY_CLEANUP_DAEMON_ACTIVE)
                .to_string();
            self.telemetry
                .push_log(LogLevel::Warn, COMPONENT_ENGINE, msg.clone());
            self.telemetry.flush_file_logger();
            return Err(RouteWardError::DaemonError {
                key: crate::error::ERR_KEY_CLEANUP_DAEMON_ACTIVE,
                detail: msg,
            });
        }
        Ok(())
    }

    /// Removes orphaned OS interception rules (Linux `nftables` table or Windows firewall rule).
    /// Refuses to run while a `routeward daemon` instance is active unless `force` is `true`.
    pub fn cleanup_orphaned_rules(&self, force: bool) -> RouteWardResult<()> {
        self.check_cleanup_allowed(force)?;

        #[cfg(windows)]
        {
            let rule_name = format!(
                "RouteWard_TransparentRelay_{}",
                self.constants.network.default_transparent_tcp_port
            );
            WinDivertInterceptor::remove_scoped_firewall_rule(&rule_name, &self.telemetry);
        }
        #[cfg(not(windows))]
        {
            let net = &self.constants.network;
            let spec = TproxyRoutingSpec {
                fwmark: net.linux_tproxy_fwmark,
                route_table: net.linux_tproxy_route_table,
                rule_priority: net.linux_tproxy_rule_priority,
                tproxy_port: net.default_local_name_inspect_port,
            };
            NftablesInterceptor::delete_nft_table(
                &net.linux_nft_binary,
                &net.linux_nft_table_name,
                &self.telemetry,
            )?;
            NftablesInterceptor::delete_tproxy_routing(&net.linux_ip_binary, spec, &self.telemetry);
        }
        self.telemetry.flush_file_logger();
        Ok(())
    }

    pub fn set_enable_logging(&self, enable: bool) {
        {
            let mut prof = self.profile.write();
            prof.enable_logging = enable;
        }
        self.telemetry.set_file_logging_enabled(enable);
    }

    pub fn diagnostics(&self) -> SystemDiagnostics {
        let prof = self.profile.read();
        let net = &self.constants.network;
        SystemDiagnostics {
            daemon_connected: true,
            running: self.is_running(),
            os_name: std::env::consts::OS.to_uppercase(),
            interception_mode: prof.interception_mode,
            elevated_privileges: Self::detect_elevated_privileges(),
            relay_tcp_endpoint: format!("{}:{}", net.local_bind_host, net.default_relay_tcp_port),
            relay_http_endpoint: format!("{}:{}", net.local_bind_host, net.default_relay_http_port),
            dns_endpoint: format!("{}:{}", net.local_bind_host, net.default_dns_listen_port),
            fake_ip_cidr: prof.dns_config.fake_ip_cidr.clone(),
            active_locale: self.i18n.get_locale(),
        }
    }

    pub fn evaluate_rule(&self, req: &ConnectionRequest) -> RuleEvaluationResult {
        let prof = self.profile.read();
        let parsed_v4 = req
            .target_ip
            .as_deref()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .or_else(|| req.target_host.parse::<Ipv4Addr>().ok());
        if prof.dns_config.enable_fake_ip {
            if let Some(v4) = parsed_v4 {
                if self.dns.is_in_fake_subnet(&v4) && self.dns.resolve_fake_ip(&v4).is_none() {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_DNS,
                        format!(
                            "Blocked connection to unmapped or expired Fake-IP {}:{} for process=\"{}\"",
                            v4, req.target_port, req.process_name
                        ),
                    );
                    return RuleEvaluationResult {
                        matched_rule_id: "fake-ip-unmapped".to_string(),
                        matched_rule_name: "FakeIP:UnmappedOrExpired".to_string(),
                        action: RuleAction::Block,
                        effective_domain: None,
                        resolved_from_fake_ip: false,
                    };
                }
            }
        }
        RuleEngine::evaluate(req, &prof.rules, &prof.default_action, Some(&self.dns))
    }

    /// Polls `PendingSynQueue` using the active `securityPolicy.killSwitchEnabled` setting and logs
    /// timed-out unattributed SYNs (`INFO` with drop counter when dropped, `WARN` with reinject counter when released).
    pub fn poll_pending_syns<T, M, F>(
        &self,
        queue: &PendingSynQueue<T, M>,
        timeout: Duration,
        fallback_fn: F,
    ) -> Vec<PendingSynOutcome<T, M>>
    where
        M: crate::interceptor::nat::PacketSourcePort,
        F: Fn(u16) -> Option<u32>,
    {
        let kill_switch_enabled = self.profile.read().security_policy.kill_switch_enabled;
        let outcomes = queue.poll_ready(&self.nat_table, timeout, kill_switch_enabled, fallback_fn);
        for outcome in &outcomes {
            match outcome {
                PendingSynOutcome::Resolved { .. } => {}
                PendingSynOutcome::TimedOutDropped {
                    meta,
                    elapsed_ms,
                    drop_count,
                } => {
                    let (src_ip, src_port, dst_ip, dst_port) = meta.flow_endpoints();
                    self.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_WINDIVERT,
                        format!(
                            "Dropped unattributed Pending SYN #{} after {}ms for {}:{} -> {}:{} (killSwitchEnabled=true; awaiting client TCP SYN retransmission)",
                            drop_count, elapsed_ms, src_ip, src_port, dst_ip, dst_port
                        ),
                    );
                }
                PendingSynOutcome::TimedOutReinject {
                    meta,
                    elapsed_ms,
                    reinject_count,
                    ..
                } => {
                    let (src_ip, src_port, dst_ip, dst_port) = meta.flow_endpoints();
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_WINDIVERT,
                        format!(
                            "Released unattributed Pending SYN #{} after {}ms for {}:{} -> {}:{} (killSwitchEnabled=false; reinjecting unmodified fail-open)",
                            reinject_count, elapsed_ms, src_ip, src_port, dst_ip, dst_port
                        ),
                    );
                }
            }
        }
        outcomes
    }

    /// Logs a timed-out or capacity-evicted `PendingUdpOutcome` (`INFO` when dropped with `killSwitchEnabled=true`,
    /// `WARN` when reinjected with `killSwitchEnabled=false`).
    pub fn log_pending_udp_outcome<T, M>(&self, outcome: &PendingUdpOutcome<T, M>)
    where
        M: crate::interceptor::nat::PacketSourcePort,
    {
        match outcome {
            PendingUdpOutcome::Resolved { .. } => {}
            PendingUdpOutcome::TimedOutDropped {
                meta,
                elapsed_ms,
                drop_count,
            } => {
                let (src_ip, src_port, dst_ip, dst_port) = meta.flow_endpoints();
                self.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_WINDIVERT,
                    format!(
                        "Dropped unattributed Pending UDP datagram #{} after {}ms for {}:{} -> {}:{} (killSwitchEnabled=true)",
                        drop_count, elapsed_ms, src_ip, src_port, dst_ip, dst_port
                    ),
                );
            }
            PendingUdpOutcome::TimedOutReinject {
                meta,
                elapsed_ms,
                reinject_count,
                ..
            } => {
                let (src_ip, src_port, dst_ip, dst_port) = meta.flow_endpoints();
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_WINDIVERT,
                    format!(
                        "Released unattributed Pending UDP datagram #{} after {}ms for {}:{} -> {}:{} (killSwitchEnabled=false; reinjecting unmodified fail-open)",
                        reinject_count, elapsed_ms, src_ip, src_port, dst_ip, dst_port
                    ),
                );
            }
        }
    }

    /// Polls `PendingUdpQueue` using the active `securityPolicy.killSwitchEnabled` setting and logs
    /// timed-out unattributed UDP datagrams (`INFO` when dropped, `WARN` when released).
    pub fn poll_pending_udps<T, M, F>(
        &self,
        queue: &PendingUdpQueue<T, M>,
        timeout: Duration,
        fallback_fn: F,
    ) -> Vec<PendingUdpOutcome<T, M>>
    where
        M: crate::interceptor::nat::PacketSourcePort,
        F: Fn(u16) -> Option<u32>,
    {
        let kill_switch_enabled = self.profile.read().security_policy.kill_switch_enabled;
        let outcomes = queue.poll_ready(&self.nat_table, timeout, kill_switch_enabled, fallback_fn);
        for outcome in &outcomes {
            self.log_pending_udp_outcome(outcome);
        }
        outcomes
    }

    /// Resolves the effective `RuleAction` for an unattributed socket (`ProcessAttribution::Unknown`
    /// or unreadable process image), enforcing `RuleAction::Block` and logging `WARN` when
    /// `securityPolicy.killSwitchEnabled` is `true` and `unknownProcessAction` is `Direct`.
    pub fn resolve_unknown_process_action(
        &self,
        component: &str,
        client_port: u16,
        target_host: &str,
        target_port: u16,
        reason: &str,
    ) -> (RuleAction, String) {
        let (kill_switch_enabled, configured_action) = {
            let prof = self.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.unknown_process_action.clone(),
            )
        };

        if kill_switch_enabled && configured_action == RuleAction::Direct {
            self.telemetry.push_log(
                LogLevel::Warn,
                component,
                format!(
                    "Unattributed socket on client port {} -> {}:{} (reason={}); overriding unknownProcessAction=Direct to Block because killSwitchEnabled=true",
                    client_port, target_host, target_port, reason
                ),
            );
            (
                RuleAction::Block,
                "SecurityPolicy:unknownProcessAction(KillSwitchOverride)".to_string(),
            )
        } else {
            self.telemetry.push_log(
                LogLevel::Warn,
                component,
                format!(
                    "Unattributed socket on client port {} -> {}:{} (reason={}); applying unknownProcessAction={:?} (killSwitchEnabled={})",
                    client_port, target_host, target_port, reason, configured_action, kill_switch_enabled
                ),
            );
            (
                configured_action,
                "SecurityPolicy:unknownProcessAction".to_string(),
            )
        }
    }

    /// Evaluates process attribution for a transparent connection, applying `resolve_unknown_process_action`
    /// whenever the socket is `ProcessAttribution::Unknown` or its executable image could not be resolved.
    pub fn attribute_or_apply_unknown_policy(
        &self,
        attribution: ProcessAttribution,
        client_port: u16,
        target_host: &str,
        target_port: u16,
        orig_dst_ip: Option<&IpAddr>,
    ) -> (
        u32,
        String,
        String,
        RuleAction,
        String,
        Option<String>,
        &'static str,
    ) {
        self.attribute_or_apply_unknown_policy_with_proto(
            attribution,
            client_port,
            target_host,
            target_port,
            orig_dst_ip,
            TransportProtocol::Tcp,
        )
    }

    /// Evaluates process attribution for a transparent TCP or UDP connection, applying
    /// `resolve_unknown_process_action` whenever the socket is `ProcessAttribution::Unknown`
    /// or its executable image could not be resolved.
    pub fn attribute_or_apply_unknown_policy_with_proto(
        &self,
        attribution: ProcessAttribution,
        client_port: u16,
        target_host: &str,
        target_port: u16,
        orig_dst_ip: Option<&IpAddr>,
        protocol: TransportProtocol,
    ) -> (
        u32,
        String,
        String,
        RuleAction,
        String,
        Option<String>,
        &'static str,
    ) {
        match attribution {
            ProcessAttribution::Single(identity) if !identity.is_unattributed() => {
                let eval = self.evaluate_rule(&ConnectionRequest {
                    process_name: identity.name.clone(),
                    process_path: Some(identity.executable_path.clone()),
                    target_host: target_host.to_string(),
                    target_ip: Some(target_host.to_string()),
                    target_port,
                    protocol,
                });
                (
                    identity.pid,
                    identity.name,
                    identity.executable_path,
                    eval.action,
                    eval.matched_rule_name,
                    eval.effective_domain,
                    "procfs_single",
                )
            }
            ProcessAttribution::Shared {
                primary,
                candidate_pids,
            } if !primary.is_unattributed() => {
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_TRANSPARENT,
                    format!(
                        "Shared socket across forked PIDs {:?} on client port {}; attributing to primary PID={} process=\"{}\" exe=\"{}\"",
                        candidate_pids,
                        client_port,
                        primary.pid,
                        primary.name,
                        primary.executable_path
                    ),
                );
                let eval = self.evaluate_rule(&ConnectionRequest {
                    process_name: primary.name.clone(),
                    process_path: Some(primary.executable_path.clone()),
                    target_host: target_host.to_string(),
                    target_ip: Some(target_host.to_string()),
                    target_port,
                    protocol,
                });
                (
                    primary.pid,
                    primary.name,
                    primary.executable_path,
                    eval.action,
                    eval.matched_rule_name,
                    eval.effective_domain,
                    "procfs_shared_fork",
                )
            }
            ProcessAttribution::Single(identity) => {
                let reason = format!(
                    "process image unavailable for PID={} ({})",
                    identity.pid, identity.executable_path
                );
                let (unknown_action, rule_name) = self.resolve_unknown_process_action(
                    COMPONENT_TRANSPARENT,
                    client_port,
                    target_host,
                    target_port,
                    &reason,
                );
                let resolved_dom = orig_dst_ip.and_then(|ip| self.resolve_fake_ip_any(ip));
                (
                    identity.pid,
                    "unknown".to_string(),
                    "unknown".to_string(),
                    unknown_action,
                    rule_name,
                    resolved_dom,
                    "procfs_unknown",
                )
            }
            ProcessAttribution::Shared { primary, .. } => {
                let reason = format!(
                    "process image unavailable for shared primary PID={} ({})",
                    primary.pid, primary.executable_path
                );
                let (unknown_action, rule_name) = self.resolve_unknown_process_action(
                    COMPONENT_TRANSPARENT,
                    client_port,
                    target_host,
                    target_port,
                    &reason,
                );
                let resolved_dom = orig_dst_ip.and_then(|ip| self.resolve_fake_ip_any(ip));
                (
                    primary.pid,
                    "unknown".to_string(),
                    "unknown".to_string(),
                    unknown_action,
                    rule_name,
                    resolved_dom,
                    "procfs_unknown",
                )
            }
            ProcessAttribution::Unknown { reason } => {
                let (unknown_action, rule_name) = self.resolve_unknown_process_action(
                    COMPONENT_TRANSPARENT,
                    client_port,
                    target_host,
                    target_port,
                    &reason,
                );
                let resolved_dom = orig_dst_ip.and_then(|ip| self.resolve_fake_ip_any(ip));
                (
                    0,
                    "unknown".to_string(),
                    "unknown".to_string(),
                    unknown_action,
                    rule_name,
                    resolved_dom,
                    "procfs_unknown",
                )
            }
        }
    }

    pub fn simulate_connection(&self, req: ConnectionRequest) -> TrackedConnection {
        let eval = self.evaluate_rule(&req);
        let route_label = self.format_action_label(&eval.action);
        let is_proxied = matches!(
            eval.action,
            RuleAction::Proxy { .. } | RuleAction::Chain { .. }
        );
        let status = if eval.action == RuleAction::Block {
            ConnectionStatus::Blocked
        } else {
            ConnectionStatus::Active
        };

        let (rx_bytes, tx_bytes) = if status == ConnectionStatus::Blocked {
            (0, 0)
        } else {
            (SIMULATED_DEFAULT_RX_BYTES, SIMULATED_DEFAULT_TX_BYTES)
        };

        let resolved_domain = eval.effective_domain.clone().or_else(|| {
            if req.target_host.parse::<IpAddr>().is_err() {
                let _ = self.dns.allocate_or_get(&req.target_host);
                Some(req.target_host.clone())
            } else {
                None
            }
        });

        let tracked = TrackedConnection {
            id: Uuid::new_v4().to_string(),
            pid: 4210,
            process_name: ProcessResolver::extract_basename(&req.process_name),
            process_path: req.process_path.unwrap_or_else(|| req.process_name.clone()),
            target_host: req.target_host.clone(),
            resolved_domain,
            target_port: req.target_port,
            protocol: req.protocol,
            matched_rule: eval.matched_rule_name.clone(),
            route_label: route_label.clone(),
            latency_ms: SIMULATED_DEFAULT_LATENCY_MS,
            rx_bytes,
            tx_bytes,
            status,
            started_at: Utc::now(),
            error_detail: None,
        };

        let log_level = if status == ConnectionStatus::Blocked {
            LogLevel::Warn
        } else {
            LogLevel::Info
        };
        self.telemetry.push_log(
            log_level,
            COMPONENT_RULE,
            format!(
                "[{}] {}:{} -> {} ({})",
                tracked.process_name,
                tracked.target_host,
                tracked.target_port,
                route_label,
                tracked.matched_rule
            ),
        );

        self.telemetry
            .record_connection(tracked.clone(), is_proxied);
        tracked
    }

    pub fn scan_and_ingest_os_sockets(&self, max_entries: usize) -> Vec<TrackedConnection> {
        let os_sockets = self
            .process_resolver
            .scan_established_tcp_sockets(max_entries);
        let mut ingested = Vec::with_capacity(os_sockets.len());

        for sock in os_sockets {
            let conn_id = format!(
                "os-{}-{}-{}:{}",
                sock.pid, sock.local_port, sock.remote_ip, sock.remote_port
            );
            let eval = self.evaluate_rule(&ConnectionRequest {
                process_name: sock.process_name.clone(),
                process_path: Some(sock.process_path.clone()),
                target_host: sock.remote_ip.clone(),
                target_ip: Some(sock.remote_ip.clone()),
                target_port: sock.remote_port,
                protocol: TransportProtocol::Tcp,
            });

            let route_label = self.format_action_label(&eval.action);
            let is_proxied = matches!(
                eval.action,
                RuleAction::Proxy { .. } | RuleAction::Chain { .. }
            );
            let status = if eval.action == RuleAction::Block {
                ConnectionStatus::Blocked
            } else {
                ConnectionStatus::Active
            };

            let tracked = TrackedConnection {
                id: conn_id,
                pid: sock.pid,
                process_name: sock.process_name,
                process_path: sock.process_path,
                target_host: sock.remote_ip,
                resolved_domain: eval.effective_domain,
                target_port: sock.remote_port,
                protocol: TransportProtocol::Tcp,
                matched_rule: eval.matched_rule_name,
                route_label,
                latency_ms: 0,
                rx_bytes: SIMULATED_DEFAULT_RX_BYTES,
                tx_bytes: SIMULATED_DEFAULT_TX_BYTES,
                status,
                started_at: Utc::now(),
                error_detail: None,
            };

            self.telemetry
                .record_connection(tracked.clone(), is_proxied);
            ingested.push(tracked);
        }
        ingested
    }

    pub async fn test_proxy(&self, proxy_id: &str) -> RouteWardResult<ProxyHealthReport> {
        let node = {
            let prof = self.profile.read();
            prof.proxies
                .iter()
                .find(|p| p.id == proxy_id)
                .cloned()
                .ok_or_else(|| RouteWardError::ProxyNotFound {
                    key: ERR_KEY_PROXY_NOT_FOUND,
                    proxy_id: proxy_id.to_string(),
                })?
        };

        let report = ProxyChecker::test_proxy(&node, &self.constants).await;

        {
            let mut prof = self.profile.write();
            if let Some(target) = prof.proxies.iter_mut().find(|p| p.id == proxy_id) {
                target.last_latency_ms = report.latency_ms;
                target.exit_ip = report.exit_ip.clone();
            }
        }

        let msg = if report.reachable {
            format!(
                "{}: {} ({} ms)",
                self.i18n.t("cli.engine.check.result_online"),
                node.name,
                report.latency_ms.unwrap_or(0)
            )
        } else {
            format!(
                "{}: {}",
                self.i18n.t("cli.engine.check.result_offline"),
                node.name
            )
        };
        self.telemetry.push_log(
            if report.reachable {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            COMPONENT_PROXY,
            msg,
        );

        Ok(report)
    }

    pub async fn test_all_proxies(&self) -> Vec<ProxyHealthReport> {
        let ids: Vec<String> = {
            let prof = self.profile.read();
            prof.proxies.iter().map(|p| p.id.clone()).collect()
        };

        let mut reports = Vec::with_capacity(ids.len());
        for id in ids {
            if let Ok(rep) = self.test_proxy(&id).await {
                reports.push(rep);
            }
        }
        reports
    }

    pub fn upsert_proxy(&self, mut node: ProxyNode) {
        {
            let mut prof = self.profile.write();
            if let Some(existing) = prof.proxies.iter_mut().find(|p| p.id == node.id) {
                if let Some(ref mut incoming_creds) = node.auth {
                    if incoming_creds.password.is_none() {
                        if let Some(ref existing_creds) = existing.auth {
                            incoming_creds.password = existing_creds.password.clone();
                        }
                    }
                    incoming_creds.has_password = incoming_creds.has_password();
                }
                *existing = node;
            } else {
                if let Some(ref mut incoming_creds) = node.auth {
                    incoming_creds.has_password = incoming_creds.has_password();
                }
                prof.proxies.push(node);
            }
        }
        self.sync_upstream_proxy_exclusions();
    }

    pub fn import_proxy_uris(&self, text: &str) -> Vec<ProxyNode> {
        let nodes = ProxyUriCodec::parse_batch(text);
        for node in &nodes {
            self.upsert_proxy(node.clone());
        }
        nodes
    }

    pub fn remove_proxy(&self, proxy_id: &str) {
        {
            let mut prof = self.profile.write();
            prof.proxies.retain(|p| p.id != proxy_id);
        }
        self.bootstrapped_proxy_endpoints.remove(proxy_id);
        self.sync_upstream_proxy_exclusions();
    }

    pub(super) fn sync_upstream_proxy_exclusions(&self) {
        let (mut upstream_endpoints, active_ids): (Vec<(IpAddr, u16)>, Vec<String>) = {
            let prof = self.profile.read();
            let endpoints = prof
                .proxies
                .iter()
                .filter_map(|p| p.host.parse::<IpAddr>().ok().map(|ip| (ip, p.port)))
                .collect();
            let ids = prof.proxies.iter().map(|p| p.id.clone()).collect();
            (endpoints, ids)
        };
        self.bootstrapped_proxy_endpoints
            .retain(|id, _| active_ids.contains(id));
        for entry in self.bootstrapped_proxy_endpoints.iter() {
            for pair in entry.value() {
                if !upstream_endpoints.contains(pair) {
                    upstream_endpoints.push(*pair);
                }
            }
        }
        self.nat_table.set_upstream_endpoints(upstream_endpoints);
    }

    /// Replaces the active in-memory profile, synchronizes logging and upstream loop exclusions,
    /// and if the engine is running when `securityPolicy`, `dnsConfig`, or `proxies` changed,
    /// atomically reapplies active interception rules and re-runs proxy bootstrap.
    pub fn replace_profile(&self, mut new_profile: ProfileConfig) {
        self.telemetry
            .set_file_logging_enabled(new_profile.enable_logging);
        self.dns
            .update_bypass_domains(new_profile.dns_config.bypass_domains.clone());

        let (security_changed, dns_changed, proxies_changed) = {
            let mut prof = self.profile.write();
            for incoming_node in &mut new_profile.proxies {
                if let Some(ref mut incoming_creds) = incoming_node.auth {
                    if incoming_creds.password.is_none() {
                        if let Some(existing_node) =
                            prof.proxies.iter().find(|p| p.id == incoming_node.id)
                        {
                            if let Some(ref existing_creds) = existing_node.auth {
                                incoming_creds.password = existing_creds.password.clone();
                            }
                        }
                    }
                    incoming_creds.has_password = incoming_creds.has_password();
                }
            }
            let sec_diff = prof.security_policy != new_profile.security_policy;
            let dns_diff = prof.dns_config != new_profile.dns_config;
            let prx_diff = prof.proxies != new_profile.proxies;
            *prof = new_profile;
            (sec_diff, dns_diff, prx_diff)
        };

        if proxies_changed {
            self.udp_manager.capability_cache().clear();
            self.udp_manager.clear_all();
            self.bootstrapped_proxy_endpoints.clear();
        }
        self.sync_upstream_proxy_exclusions();

        if self.is_running() && (security_changed || dns_changed || proxies_changed) {
            self.reapply_active_interception_rules(security_changed, dns_changed);
            if let Ok(rt_handle) = tokio::runtime::Handle::try_current() {
                let ctrl_boot = self.clone();
                rt_handle.spawn(async move {
                    let before = ctrl_boot.nat_table.upstream_endpoints();
                    ctrl_boot.bootstrap_resolve_proxy_hosts().await;
                    let after = ctrl_boot.nat_table.upstream_endpoints();
                    if before != after && ctrl_boot.interceptor_backend.is_active() {
                        let _ = ctrl_boot.interceptor_backend.reload(ctrl_boot.clone());
                    }
                });
            }
        }
    }

    pub(super) fn reapply_active_interception_rules(
        &self,
        security_changed: bool,
        dns_changed: bool,
    ) {
        if self.interceptor_backend.is_active() {
            if let Err(err) = self.interceptor_backend.reload(self.clone()) {
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_ENGINE,
                    format!("Failed to reload active interception backend rules: {err}"),
                );
            }
        }
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            format!(
                "{} (securityPolicyChanged={security_changed}, dnsConfigChanged={dns_changed})",
                self.i18n.t("cli.engine.startup.reloaded_live")
            ),
        );
    }

    fn reject_if_symlink(path: &std::path::Path) -> RouteWardResult<()> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!("Refusing symlinked profile path {}", path.display()),
            }),
            _ => Ok(()),
        }
    }

    fn apply_and_verify_secure_file_if_elevated(path: &std::path::Path) -> RouteWardResult<()> {
        if Self::detect_elevated_privileges() {
            apply_secure_profile_file_permissions(path, true)?;
            verify_profile_path_security(path)?;
        }
        #[cfg(all(windows, test))]
        if !Self::detect_elevated_privileges() && path.starts_with(std::env::temp_dir()) {
            let _ = crate::config::security::apply_windows_sddl_dacl(path, "D:(A;;FA;;;WD)");
        }
        Ok(())
    }

    /// Atomically saves the active profile to `path`.
    pub fn save_profile_to_path(&self, path: impl AsRef<std::path::Path>) -> RouteWardResult<()> {
        let target = path.as_ref();
        Self::reject_if_symlink(target)?;
        let prof = self.profile.read().clone();
        prof.save_to_path(target)?;
        Self::apply_and_verify_secure_file_if_elevated(target)?;
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            format!("Saved profile \"{}\" to {}", prof.name, target.display()),
        );
        Ok(())
    }

    /// Atomically saves the active profile to the daemon's fixed system profile path.
    pub fn save_profile_default(&self) -> RouteWardResult<()> {
        let profile_path = self.constants.ipc.resolve_daemon_profile_path()?;
        self.save_profile_to_path(&profile_path)?;
        if let Ok(dir) = self.constants.ipc.resolve_daemon_profiles_dir() {
            let active_id = self.profile.read().profile_id.clone();
            if is_valid_profile_slug(&active_id) {
                let named_path = dir.join(format!("{active_id}.json"));
                if named_path.exists() {
                    self.save_profile_to_path(&named_path)?;
                }
            }
        }
        Ok(())
    }

    fn ensure_profiles_dir(&self) -> RouteWardResult<std::path::PathBuf> {
        let dir = self.constants.ipc.resolve_daemon_profiles_dir()?;
        Self::reject_if_symlink(&dir)?;
        if Self::detect_elevated_privileges() {
            if dir.exists() {
                verify_profile_path_security(&dir)?;
            } else {
                create_secure_profile_dir(&dir, true)?;
                verify_profile_path_security(&dir)?;
            }
        } else if !dir.exists() {
            #[cfg(windows)]
            if let Ok(program_data) = crate::config::security::resolve_windows_program_data_dir() {
                if dir.starts_with(program_data.join("RouteWard")) {
                    return Err(RouteWardError::DaemonError {
                        key: crate::error::ERR_KEY_DAEMON_NOT_ELEVATED,
                        detail: format!(
                            "Refusing unprivileged creation of system profile directory {}",
                            dir.display()
                        ),
                    });
                }
            }
            #[cfg(not(windows))]
            if dir.starts_with("/etc/routeward") {
                return Err(RouteWardError::DaemonError {
                    key: crate::error::ERR_KEY_DAEMON_NOT_ELEVATED,
                    detail: format!(
                        "Refusing unprivileged creation of system profile directory {}",
                        dir.display()
                    ),
                });
            }
            std::fs::create_dir_all(&dir).map_err(|err| RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!(
                    "Failed to create profiles directory {}: {err}",
                    dir.display()
                ),
            })?;
        }
        Ok(dir)
    }

    pub fn list_named_profiles(&self) -> RouteWardResult<Vec<ProfileSummary>> {
        let dir = self.ensure_profiles_dir()?;
        let active_prof = self.profile.read().clone();
        let active_id = if is_valid_profile_slug(&active_prof.profile_id) {
            active_prof.profile_id.clone()
        } else {
            slugify_profile_id(&active_prof.name)
        };

        let active_named_path = dir.join(format!("{active_id}.json"));
        Self::reject_if_symlink(&active_named_path)?;
        if !active_named_path.exists() {
            let mut normalized = active_prof.clone();
            normalized.profile_id = active_id.clone();
            normalized.save_to_path(&active_named_path)?;
            Self::apply_and_verify_secure_file_if_elevated(&active_named_path)?;
        }

        let elevated = Self::detect_elevated_privileges();
        let mut summaries = Vec::new();
        let entries = std::fs::read_dir(&dir).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_LOAD,
            detail: format!("Failed to read profiles directory {}: {err}", dir.display()),
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if !is_valid_profile_slug(stem) {
                continue;
            }
            if Self::reject_if_symlink(&path).is_err() {
                continue;
            }
            if elevated {
                if let Err(err) = verify_profile_path_security(&path) {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!("Skipping insecure named profile {}: {err}", path.display()),
                    );
                    continue;
                }
            }
            if let Ok(loaded) = ProfileConfig::load_from_path(&path) {
                summaries.push(ProfileSummary {
                    profile_id: stem.to_string(),
                    name: loaded.name,
                    proxy_count: loaded.proxies.len(),
                    rule_count: loaded.rules.len(),
                    active: stem == active_id,
                });
            }
        }

        summaries.sort_by(|a, b| {
            b.active.cmp(&a.active).then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
        });
        Ok(summaries)
    }

    pub fn save_named_profile(
        &self,
        profile_id: Option<&str>,
        name: Option<&str>,
    ) -> RouteWardResult<Vec<ProfileSummary>> {
        let dir = self.ensure_profiles_dir()?;
        let mut updated = self.profile.read().clone();
        if let Some(new_name) = name.map(str::trim).filter(|s| !s.is_empty()) {
            updated.name = new_name.to_string();
        }
        let target_slug = match profile_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(id) if is_valid_profile_slug(id) => id.to_string(),
            Some(_) => {
                return Err(RouteWardError::ConfigError {
                    key: ERR_KEY_CONFIG_LOAD,
                    detail: "Invalid profile identifier (expected [a-z0-9_-]{1,48})".to_string(),
                });
            }
            None => slugify_profile_id(&updated.name),
        };
        updated.profile_id = target_slug.clone();
        *self.profile.write() = updated.clone();

        let named_path = dir.join(format!("{target_slug}.json"));
        Self::reject_if_symlink(&named_path)?;
        updated.save_to_path(&named_path)?;
        Self::apply_and_verify_secure_file_if_elevated(&named_path)?;
        self.save_profile_default()?;
        self.list_named_profiles()
    }

    pub fn switch_named_profile(&self, profile_id: &str) -> RouteWardResult<ProfileConfig> {
        let slug = profile_id.trim();
        if !is_valid_profile_slug(slug) {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!("Invalid profile identifier \"{profile_id}\""),
            });
        }
        let dir = self.ensure_profiles_dir()?;
        let named_path = dir.join(format!("{slug}.json"));
        Self::reject_if_symlink(&named_path)?;
        if !named_path.exists() {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!("Profile \"{slug}\" not found"),
            });
        }
        if Self::detect_elevated_privileges() {
            verify_profile_path_security(&named_path)?;
        }
        let mut loaded = ProfileConfig::load_from_path(&named_path)?;
        loaded.profile_id = slug.to_string();
        self.replace_profile(loaded);
        self.save_profile_default()?;
        Ok(self.profile.read().redacted_for_ipc())
    }

    pub fn delete_named_profile(&self, profile_id: &str) -> RouteWardResult<Vec<ProfileSummary>> {
        let slug = profile_id.trim();
        if !is_valid_profile_slug(slug) {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!("Invalid profile identifier \"{profile_id}\""),
            });
        }
        let active_id = self.profile.read().profile_id.clone();
        if slug == "default" || slug == active_id {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: "Cannot delete the default or currently active profile".to_string(),
            });
        }
        let dir = self.ensure_profiles_dir()?;
        let named_path = dir.join(format!("{slug}.json"));
        Self::reject_if_symlink(&named_path)?;
        if named_path.exists() {
            std::fs::remove_file(&named_path).map_err(|err| RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!(
                    "Failed to delete profile \"{}\": {err}",
                    named_path.display()
                ),
            })?;
        }
        self.list_named_profiles()
    }

    /// Actively terminates an in-flight relayed connection by its identifier.
    pub fn terminate_connection(&self, connection_id: &str) -> bool {
        let terminated = self.telemetry.terminate_connection(connection_id);
        if terminated {
            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_TRANSPARENT,
                format!("Terminated active connection id={connection_id}"),
            );
        }
        terminated
    }

    pub fn upsert_chain(&self, chain: ProxyChain) {
        let mut prof = self.profile.write();
        if let Some(existing) = prof.chains.iter_mut().find(|c| c.id == chain.id) {
            *existing = chain;
        } else {
            prof.chains.push(chain);
        }
    }

    pub fn remove_chain(&self, chain_id: &str) {
        let mut prof = self.profile.write();
        prof.chains.retain(|c| c.id != chain_id);
    }

    pub fn upsert_rule(&self, rule: RoutingRule) {
        let mut prof = self.profile.write();
        if let Some(existing) = prof.rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule;
        } else {
            prof.rules.push(rule);
        }
        prof.rules.sort_by_key(|r| r.priority);
    }

    pub fn remove_rule(&self, rule_id: &str) {
        let mut prof = self.profile.write();
        prof.rules.retain(|r| r.id != rule_id);
    }

    pub fn set_interception_mode(&self, mode: InterceptionMode) {
        let mut prof = self.profile.write();
        prof.interception_mode = mode;
    }

    pub fn set_theme_config(&self, theme: String, accent: String) {
        let mut prof = self.profile.write();
        prof.theme_config.theme = theme;
        prof.theme_config.accent = accent;
    }

    pub fn allocate_fake_ip(&self, domain: &str) -> Option<String> {
        let ip = self.dns.allocate_or_get(domain)?;
        self.telemetry
            .push_log(LogLevel::Debug, COMPONENT_DNS, format!("{domain} -> {ip}"));
        Some(ip.to_string())
    }

    pub fn extract_sni_from_payload(&self, packet: &[u8]) -> Option<String> {
        TlsSniExtractor::extract_sni(packet)
    }

    /// Emits a rate-limited `WARN` log entry and returns the total hit count for `category_key`.
    pub fn push_rate_limited_warn(
        &self,
        category_key: &str,
        component: &str,
        message: impl Into<String>,
    ) -> u64 {
        let (should_log, count) = self.warn_rate_limiter.should_log(category_key);
        if should_log {
            self.telemetry.push_log(
                LogLevel::Warn,
                component,
                format!("{} [count=#{count}]", message.into()),
            );
        }
        count
    }

    /// Returns the total number of fragmented UDP datagrams dropped by the proxy fragmentation guard.
    pub fn fragmented_udp_drop_count(&self) -> u64 {
        self.fragmented_udp_drop_count.load(Ordering::SeqCst)
    }
}
