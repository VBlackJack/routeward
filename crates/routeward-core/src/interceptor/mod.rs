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

pub mod backend;
pub mod nat;
pub mod nftables;
pub mod windivert;

use crate::checker::{ProxyChecker, ProxyHealthReport};
use crate::config::{
    InterceptionMode, ProfileConfig, ProxyChain, ProxyNode, RoutingRule, RuleAction,
    SystemConstants, TransportProtocol,
};
use crate::dns::codec::{
    build_a_query, build_a_response, build_nodata_response, build_ptr_response,
    build_rcode_response, build_rcode_response_from_raw, encode_tcp_dns_frame,
    enforce_udp_truncation, extract_ipv4_answers, parse_dns_message, parse_dns_query,
    parse_ipv4_ptr_qname, rewrite_transaction_id, DnsQueryPacket, DNS_MAX_TCP_MESSAGE_BYTES,
    QTYPE_A, QTYPE_AAAA, QTYPE_PTR, RCODE_FORMERR, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL,
};
use crate::dns::{FakeIpEngine, LocalNameQueryDecision};
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_HANDSHAKE_FAILED, ERR_KEY_PROXY_NOT_FOUND,
    ERR_KEY_RULE_BLOCKED, ERR_KEY_UDP_NOT_SUPPORTED,
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
use crate::proxy::udp::{
    decode_socks5_udp_datagram, encode_socks5_udp_datagram, Socks5UdpTarget, UdpAssociationManager,
};
use crate::proxy::uri::ProxyUriCodec;
use crate::proxy::ProxyConnector;
use crate::rules::{ConnectionRequest, RuleEngine, RuleEvaluationResult};
use crate::telemetry::{ConnectionStatus, LogLevel, TelemetryHub, TrackedConnection};
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use uuid::Uuid;

const COMPONENT_ENGINE: &str = "InterceptorEngine";
const COMPONENT_TRANSPARENT: &str = "TransparentRelay";
const COMPONENT_WINDIVERT: &str = "WinDivert";
const COMPONENT_RULE: &str = "RuleEngine";
const COMPONENT_PROXY: &str = "ProxyConnector";
const COMPONENT_DNS: &str = "FakeIpDNS";
const ROUTE_DIRECT_LABEL: &str = "DIRECT";
const ROUTE_BLOCK_LABEL: &str = "BLOCKED";
const SIMULATED_DEFAULT_RX_BYTES: u64 = 18432;
const SIMULATED_DEFAULT_TX_BYTES: u64 = 4096;
const SIMULATED_DEFAULT_LATENCY_MS: u64 = 18;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemDiagnostics {
    #[serde(default = "default_daemon_connected")]
    pub daemon_connected: bool,
    pub running: bool,
    pub os_name: String,
    pub interception_mode: InterceptionMode,
    pub elevated_privileges: bool,
    pub relay_tcp_endpoint: String,
    pub relay_http_endpoint: String,
    pub dns_endpoint: String,
    pub fake_ip_cidr: String,
    pub active_locale: String,
}

fn default_daemon_connected() -> bool {
    true
}

/// Policy controlling which DNS resolvers `candidate_dns_resolvers` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolverMode {
    /// Bypassed domain (`bypassDomains`, AD suffixes, single-label, `.local`, private reverse zones):
    /// ONLY `orig_resolver`, active system resolvers, and `last_seen_orig_resolver`.
    /// NEVER `upstreamDns`, `default_upstream`, or `fallback_dns_server`.
    BypassOnlySystem,
    /// Direct flow resolution (non-bypassed domain):
    /// `orig_resolver`, active system resolvers, and `last_seen_orig_resolver` first;
    /// `upstreamDns` (and `default_upstream`/`fallback_dns_server`) ONLY if nothing else exists.
    DirectPreferSystem,
    /// Remote DNS-over-TCP via Proxy or Chain:
    /// configured `upstreamDns`, `orig_resolver`, `default_upstream`, `fallback_dns_server`.
    RemoteViaProxy,
}

/// Rate limiter for repetitive UDP/QUIC/LLMNR/mDNS/NetBIOS-NS `WARN` logs with per-category hit counters.
#[derive(Clone)]
pub struct WarnRateLimiter {
    entries: Arc<DashMap<String, (Instant, u64)>>,
    interval: Duration,
}

impl WarnRateLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            interval,
        }
    }

    /// Increments the hit counter for `category_key` and returns `(should_emit_warn_now, total_count)`.
    pub fn should_log(&self, category_key: &str) -> (bool, u64) {
        let now = Instant::now();
        if let Some(mut entry) = self.entries.get_mut(category_key) {
            let (last_logged, count) = *entry.value();
            let next_count = count + 1;
            if now.duration_since(last_logged) >= self.interval {
                *entry.value_mut() = (now, next_count);
                return (true, next_count);
            }
            entry.value_mut().1 = next_count;
            return (false, next_count);
        }
        self.entries.insert(category_key.to_string(), (now, 1));
        (true, 1)
    }
}

#[derive(Clone)]
pub struct RouteWardController {
    pub constants: Arc<SystemConstants>,
    pub profile: Arc<RwLock<ProfileConfig>>,
    pub i18n: I18nRegistry,
    pub dns: FakeIpEngine,
    pub process_resolver: ProcessResolver,
    pub telemetry: TelemetryHub,
    pub nat_table: TransparentNatTable,
    pub udp_manager: UdpAssociationManager,
    warn_rate_limiter: WarnRateLimiter,
    fragmented_udp_drop_count: Arc<AtomicU64>,
    last_seen_orig_resolver: Arc<RwLock<Option<SocketAddr>>>,
    system_resolvers_override: Arc<RwLock<Option<Vec<SocketAddr>>>>,
    interceptor_backend: Arc<dyn Interceptor>,
    running: Arc<AtomicBool>,
}

impl RouteWardController {
    pub fn new(constants: SystemConstants, profile: ProfileConfig, locale: &str) -> Self {
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
        let upstream_endpoints: Vec<(Ipv4Addr, u16)> = profile
            .proxies
            .iter()
            .filter_map(|p| p.host.parse::<Ipv4Addr>().ok().map(|ip| (ip, p.port)))
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

                while trans_ctrl.is_running() {
                    if let Ok((client_stream, peer_addr)) = listener.accept().await {
                        let conn_ctrl = trans_ctrl.clone();
                        tokio::spawn(async move {
                            let _ = conn_ctrl
                                .handle_transparent_tcp_client(client_stream, peer_addr)
                                .await;
                        });
                    }
                }
            }
        });

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
                while dns_tcp_ctrl.is_running() {
                    if let Ok((stream, _peer_addr)) = listener.accept().await {
                        let ctrl_query = dns_tcp_ctrl.clone();
                        tokio::spawn(async move {
                            #[cfg(not(windows))]
                            let orig_resolver =
                                NftablesInterceptor::query_original_dst(&stream, dns_port)
                                    .map(SocketAddr::V4);
                            #[cfg(windows)]
                            let orig_resolver: Option<SocketAddr> = None;
                            let _ = ctrl_query
                                .handle_dns_tcp_stream(stream, orig_resolver)
                                .await;
                        });
                    }
                }
            }
        });

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
                                    client_addr,
                                    orig_dst,
                                    &sock_reply,
                                )
                                .await;
                        });
                    }
                }
            }
        });

        let bootstrap_ctrl = self.clone();
        tokio::spawn(async move {
            bootstrap_ctrl.bootstrap_resolve_proxy_hosts().await;
        });
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
        let dns_port = self.constants.dns.dns_standard_port;
        let local_dns_listen_port = self.constants.network.default_dns_listen_port;
        let is_safe_loopback = addr.ip().is_loopback()
            && addr.port() != dns_port
            && addr.port() != local_dns_listen_port;
        if (!addr.ip().is_loopback() || is_safe_loopback) && !addr.ip().is_unspecified() {
            *self.last_seen_orig_resolver.write() = Some(addr);
        }
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
    pub fn poll_pending_syns<T, F>(
        &self,
        queue: &PendingSynQueue<T>,
        timeout: Duration,
        fallback_fn: F,
    ) -> Vec<PendingSynOutcome<T>>
    where
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
                    self.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_WINDIVERT,
                        format!(
                            "Dropped unattributed Pending SYN #{} after {}ms for {}:{} -> {}:{} (killSwitchEnabled=true; awaiting client TCP SYN retransmission)",
                            drop_count, elapsed_ms, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port
                        ),
                    );
                }
                PendingSynOutcome::TimedOutReinject {
                    meta,
                    elapsed_ms,
                    reinject_count,
                    ..
                } => {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_WINDIVERT,
                        format!(
                            "Released unattributed Pending SYN #{} after {}ms for {}:{} -> {}:{} (killSwitchEnabled=false; reinjecting unmodified fail-open)",
                            reinject_count, elapsed_ms, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port
                        ),
                    );
                }
            }
        }
        outcomes
    }

    /// Logs a timed-out or capacity-evicted `PendingUdpOutcome` (`INFO` when dropped with `killSwitchEnabled=true`,
    /// `WARN` when reinjected with `killSwitchEnabled=false`).
    pub fn log_pending_udp_outcome<T>(&self, outcome: &PendingUdpOutcome<T>) {
        match outcome {
            PendingUdpOutcome::Resolved { .. } => {}
            PendingUdpOutcome::TimedOutDropped {
                meta,
                elapsed_ms,
                drop_count,
            } => {
                self.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_WINDIVERT,
                    format!(
                        "Dropped unattributed Pending UDP datagram #{} after {}ms for {}:{} -> {}:{} (killSwitchEnabled=true)",
                        drop_count, elapsed_ms, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port
                    ),
                );
            }
            PendingUdpOutcome::TimedOutReinject {
                meta,
                elapsed_ms,
                reinject_count,
                ..
            } => {
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_WINDIVERT,
                    format!(
                        "Released unattributed Pending UDP datagram #{} after {}ms for {}:{} -> {}:{} (killSwitchEnabled=false; reinjecting unmodified fail-open)",
                        reinject_count, elapsed_ms, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port
                    ),
                );
            }
        }
    }

    /// Polls `PendingUdpQueue` using the active `securityPolicy.killSwitchEnabled` setting and logs
    /// timed-out unattributed UDP datagrams (`INFO` when dropped, `WARN` when released).
    pub fn poll_pending_udps<T, F>(
        &self,
        queue: &PendingUdpQueue<T>,
        timeout: Duration,
        fallback_fn: F,
    ) -> Vec<PendingUdpOutcome<T>>
    where
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
        orig_dst_ip: Option<&Ipv4Addr>,
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
        orig_dst_ip: Option<&Ipv4Addr>,
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
                let resolved_dom = orig_dst_ip.and_then(|ip| self.dns.resolve_fake_ip(ip));
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
                let resolved_dom = orig_dst_ip.and_then(|ip| self.dns.resolve_fake_ip(ip));
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
                let resolved_dom = orig_dst_ip.and_then(|ip| self.dns.resolve_fake_ip(ip));
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
                latency_ms: 8,
                rx_bytes: SIMULATED_DEFAULT_RX_BYTES,
                tx_bytes: SIMULATED_DEFAULT_TX_BYTES,
                status,
                started_at: Utc::now(),
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
        self.sync_upstream_proxy_exclusions();
    }

    fn sync_upstream_proxy_exclusions(&self) {
        let mut upstream_endpoints: Vec<(Ipv4Addr, u16)> = {
            let prof = self.profile.read();
            prof.proxies
                .iter()
                .filter_map(|p| p.host.parse::<Ipv4Addr>().ok().map(|ip| (ip, p.port)))
                .collect()
        };
        for existing in self.nat_table.upstream_endpoints() {
            if !upstream_endpoints.contains(&existing) {
                upstream_endpoints.push(existing);
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
            let literal_endpoints: Vec<(Ipv4Addr, u16)> = {
                let prof = self.profile.read();
                prof.proxies
                    .iter()
                    .filter_map(|p| p.host.parse::<Ipv4Addr>().ok().map(|ip| (ip, p.port)))
                    .collect()
            };
            self.nat_table.set_upstream_endpoints(literal_endpoints);
        } else {
            self.sync_upstream_proxy_exclusions();
        }

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

    fn reapply_active_interception_rules(&self, security_changed: bool, dns_changed: bool) {
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

    /// Atomically saves the active profile to `path`.
    pub fn save_profile_to_path(&self, path: impl AsRef<std::path::Path>) -> RouteWardResult<()> {
        let target = path.as_ref();
        let prof = self.profile.read().clone();
        prof.save_to_path(target)?;
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
        self.save_profile_to_path(&profile_path)
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

    /// Evaluates routing rules for a single UDP datagram and forwards it through a SOCKS5 `UDP ASSOCIATE`
    /// session (`Proxy` / `Chain`) or directly (`Direct`), enforcing per-datagram rule evaluation,
    /// Fake-IP reverse lookup (`ATYP = 0x03`), QUIC (`UDP 443`) and DoQ (`UDP 853`) blocking,
    /// fragmentation blocking, and Kill-Switch enforcement.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_udp_datagram(
        &self,
        client_addr: SocketAddr,
        process_name: &str,
        process_path: Option<&str>,
        pid: u32,
        target: &Socks5UdpTarget,
        payload: &[u8],
        is_fragmented: bool,
    ) -> RouteWardResult<Vec<u8>> {
        let raw_host = target.host_string();
        let target_port = target.port();
        let target_ip_str = match target {
            Socks5UdpTarget::Ipv4(ip, _) => Some(ip.to_string()),
            Socks5UdpTarget::Ipv6(ip, _) => Some(ip.to_string()),
            Socks5UdpTarget::Domain(_, _) => None,
        };

        let mut eval = self.evaluate_rule(&ConnectionRequest {
            process_name: process_name.to_string(),
            process_path: process_path.map(|s| s.to_string()),
            target_host: raw_host.clone(),
            target_ip: target_ip_str,
            target_port,
            protocol: TransportProtocol::Udp,
        });

        let (kill_switch_enabled, block_udp_on_tcp_only, block_quic_443, block_encrypted_dns) = {
            let prof = self.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_udp_on_tcp_only_proxy,
                prof.security_policy.block_quic_udp_443,
                prof.security_policy.block_encrypted_dns_bypass,
            )
        };

        if target_port == self.constants.network.quic_default_port && block_quic_443 {
            self.push_rate_limited_warn(
                "quic_udp_443",
                COMPONENT_ENGINE,
                format!(
                    "Blocked QUIC UDP/{} datagram from PID={} process=\"{}\" -> {}:{} (blockQuicUdp443=true)",
                    target_port, pid, process_name, raw_host, target_port
                ),
            );
            eval.matched_rule_name = "SecurityPolicy:blockQuicUdp443".to_string();
            eval.action = RuleAction::Block;
        } else if target_port == self.constants.dns.dns_over_tls_port && block_encrypted_dns {
            self.push_rate_limited_warn(
                "doq_udp_853",
                COMPONENT_DNS,
                format!(
                    "Blocked encrypted DNS (UDP/{}) datagram from PID={} process=\"{}\" -> {}:{}",
                    target_port, pid, process_name, raw_host, target_port
                ),
            );
            eval.matched_rule_name = "SecurityPolicy:blockEncryptedDnsBypass".to_string();
            eval.action = RuleAction::Block;
        }

        // Decision 3: Fragmented UDP datagram whose rule is Proxy/Chain is blocked when kill switch is active.
        if is_fragmented
            && matches!(
                eval.action,
                RuleAction::Proxy { .. } | RuleAction::Chain { .. }
            )
        {
            let drop_count = self
                .fragmented_udp_drop_count
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            self.push_rate_limited_warn(
                "udp_fragmented_proxy",
                COMPONENT_ENGINE,
                format!(
                    "Fragmented UDP datagram #{drop_count} from PID={} process=\"{}\" -> {}:{} matched proxied rule \"{}\" (v1 does not reassemble IPv4 UDP fragments; killSwitchEnabled={})",
                    pid, process_name, raw_host, target_port, eval.matched_rule_name, kill_switch_enabled
                ),
            );
            if kill_switch_enabled {
                eval.matched_rule_name = "SecurityPolicy:FragmentedUdpBlocked".to_string();
                eval.action = RuleAction::Block;
            } else {
                eval.action = RuleAction::Direct;
            }
        }

        let effective_target = if let Some(ref dom) = eval.effective_domain {
            Socks5UdpTarget::Domain(dom.clone(), target_port)
        } else {
            target.clone()
        };

        let proc_basename = ProcessResolver::extract_basename(process_name);
        let proc_path_str = process_path.unwrap_or(process_name).to_string();

        match &eval.action {
            RuleAction::Block => {
                self.telemetry.record_connection(
                    TrackedConnection {
                        id: Uuid::new_v4().to_string(),
                        pid,
                        process_name: proc_basename,
                        process_path: proc_path_str,
                        target_host: raw_host,
                        resolved_domain: eval.effective_domain,
                        target_port,
                        protocol: TransportProtocol::Udp,
                        matched_rule: eval.matched_rule_name.clone(),
                        route_label: ROUTE_BLOCK_LABEL.to_string(),
                        latency_ms: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        status: ConnectionStatus::Blocked,
                        started_at: Utc::now(),
                    },
                    false,
                );
                Err(RouteWardError::BlockedByPolicy {
                    key: ERR_KEY_RULE_BLOCKED,
                    rule_name: eval.matched_rule_name,
                })
            }
            RuleAction::Direct => {
                let dst_addr: SocketAddr = match &effective_target {
                    Socks5UdpTarget::Ipv4(ip, port) => SocketAddr::new(IpAddr::V4(*ip), *port),
                    Socks5UdpTarget::Ipv6(ip, port) => SocketAddr::new(IpAddr::V6(*ip), *port),
                    Socks5UdpTarget::Domain(dom, port) => {
                        let ip = self.resolve_host_direct_ipv4(dom).await?;
                        SocketAddr::new(IpAddr::V4(ip), *port)
                    }
                };
                let timeout_dur = Duration::from_millis(
                    self.constants
                        .network
                        .tcp_connect_timeout_ms
                        .clamp(300, 1500),
                );
                let resp = self
                    .send_and_optional_recv_udp_direct_protected(payload, dst_addr, timeout_dur)
                    .await
                    .map_err(RouteWardError::Io)?;
                self.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_TRANSPARENT,
                    format!(
                        "Routed UDP PID={} process=\"{}\" exe=\"{}\" -> {}:{} via {} [rule=\"{}\"]",
                        pid,
                        proc_basename,
                        proc_path_str,
                        raw_host,
                        target_port,
                        ROUTE_DIRECT_LABEL,
                        eval.matched_rule_name
                    ),
                );
                self.telemetry.record_connection(
                    TrackedConnection {
                        id: Uuid::new_v4().to_string(),
                        pid,
                        process_name: proc_basename,
                        process_path: proc_path_str,
                        target_host: raw_host,
                        resolved_domain: eval.effective_domain,
                        target_port,
                        protocol: TransportProtocol::Udp,
                        matched_rule: eval.matched_rule_name,
                        route_label: ROUTE_DIRECT_LABEL.to_string(),
                        latency_ms: 4,
                        rx_bytes: resp.len() as u64,
                        tx_bytes: payload.len() as u64,
                        status: ConnectionStatus::Active,
                        started_at: Utc::now(),
                    },
                    false,
                );
                Ok(resp)
            }
            RuleAction::Proxy { target_id } => {
                let node = {
                    let prof = self.profile.read();
                    prof.proxies
                        .iter()
                        .find(|p| &p.id == target_id)
                        .cloned()
                        .ok_or_else(|| RouteWardError::ProxyNotFound {
                            key: ERR_KEY_PROXY_NOT_FOUND,
                            proxy_id: target_id.clone(),
                        })?
                };
                let resolved_node = self.prepare_proxy_node_with_bootstrap(node).await?;
                let _self_guard = self.register_self_proxy_connect_hint(&resolved_node);

                let ctrl_warn = self.clone();
                let res = self
                    .udp_manager
                    .exchange_datagram_via_node(
                        client_addr,
                        &resolved_node,
                        &effective_target,
                        payload,
                        &self.constants,
                        Some(&self.nat_table),
                        |unsupported_node, reason| {
                            ctrl_warn.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_PROXY,
                                format!(
                                    "{}: node=\"{}\" (id={}, reason={}; cached for {}s)",
                                    ctrl_warn.i18n.t(ERR_KEY_UDP_NOT_SUPPORTED),
                                    unsupported_node.name,
                                    unsupported_node.id,
                                    reason,
                                    ctrl_warn.constants.network.udp_capability_cache_secs
                                ),
                            );
                        },
                    )
                    .await;

                match res {
                    Ok(reply) => {
                        let route_label = format!("{} (SOCKS5 UDP)", reply.proxy_name);
                        self.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Routed UDP PID={} process=\"{}\" exe=\"{}\" -> {}:{} (domain={:?}) via {} [rule=\"{}\"]",
                                pid,
                                proc_basename,
                                proc_path_str,
                                raw_host,
                                target_port,
                                eval.effective_domain,
                                route_label,
                                eval.matched_rule_name
                            ),
                        );
                        self.telemetry.record_connection(
                            TrackedConnection {
                                id: Uuid::new_v4().to_string(),
                                pid,
                                process_name: proc_basename,
                                process_path: proc_path_str,
                                target_host: raw_host,
                                resolved_domain: eval.effective_domain,
                                target_port,
                                protocol: TransportProtocol::Udp,
                                matched_rule: eval.matched_rule_name,
                                route_label,
                                latency_ms: 8,
                                rx_bytes: reply.payload.len() as u64,
                                tx_bytes: payload.len() as u64,
                                status: ConnectionStatus::Active,
                                started_at: Utc::now(),
                            },
                            true,
                        );
                        Ok(reply.payload)
                    }
                    Err(err) => {
                        // Decision 7: Proxy refusing UDP ASSOCIATE or failing with Kill-Switch / blockUdpOnTcpOnlyProxy -> Block, never Direct
                        if kill_switch_enabled
                            || block_udp_on_tcp_only
                            || matches!(err, RouteWardError::UdpAssociateUnsupported { .. })
                        {
                            self.push_rate_limited_warn(
                                "udp_proxy_killswitch",
                                COMPONENT_ENGINE,
                                format!(
                                    "Kill-Switch blocked UDP datagram PID={} process=\"{}\" -> {}:{} [rule=\"{}\"]: {}",
                                    pid, proc_basename, raw_host, target_port, eval.matched_rule_name, err
                                ),
                            );
                            self.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid,
                                    process_name: proc_basename,
                                    process_path: proc_path_str,
                                    target_host: raw_host,
                                    resolved_domain: eval.effective_domain,
                                    target_port,
                                    protocol: TransportProtocol::Udp,
                                    matched_rule: eval.matched_rule_name,
                                    route_label: ROUTE_BLOCK_LABEL.to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
                            );
                        }
                        Err(err)
                    }
                }
            }
            RuleAction::Chain { target_id } => {
                let (strategy, hops) = {
                    let prof = self.profile.read();
                    let chain =
                        prof.chains
                            .iter()
                            .find(|c| &c.id == target_id)
                            .ok_or_else(|| RouteWardError::ProxyNotFound {
                                key: ERR_KEY_PROXY_NOT_FOUND,
                                proxy_id: target_id.clone(),
                            })?;
                    let mut nodes = Vec::new();
                    for pid in &chain.proxy_ids {
                        if let Some(n) = prof.proxies.iter().find(|p| &p.id == pid) {
                            nodes.push(n.clone());
                        }
                    }
                    (chain.strategy, nodes)
                };
                let mut resolved_hops = Vec::with_capacity(hops.len());
                for hop in hops {
                    match self.prepare_proxy_node_with_bootstrap(hop.clone()).await {
                        Ok(resolved) => {
                            let _ = self.register_self_proxy_connect_hint(&resolved);
                            resolved_hops.push(resolved);
                        }
                        Err(_) => resolved_hops.push(hop),
                    }
                }

                let ctrl_warn = self.clone();
                let res = self
                    .udp_manager
                    .exchange_datagram_via_group(
                        client_addr,
                        strategy,
                        &resolved_hops,
                        0,
                        &effective_target,
                        payload,
                        &self.constants,
                        Some(&self.nat_table),
                        |unsupported_node, reason| {
                            ctrl_warn.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_PROXY,
                                format!(
                                    "{}: node=\"{}\" (id={}, reason={}; cached for {}s)",
                                    ctrl_warn.i18n.t(ERR_KEY_UDP_NOT_SUPPORTED),
                                    unsupported_node.name,
                                    unsupported_node.id,
                                    reason,
                                    ctrl_warn.constants.network.udp_capability_cache_secs
                                ),
                            );
                        },
                    )
                    .await;

                match res {
                    Ok(reply) => {
                        self.telemetry.record_connection(
                            TrackedConnection {
                                id: Uuid::new_v4().to_string(),
                                pid,
                                process_name: proc_basename,
                                process_path: proc_path_str,
                                target_host: raw_host,
                                resolved_domain: eval.effective_domain,
                                target_port,
                                protocol: TransportProtocol::Udp,
                                matched_rule: eval.matched_rule_name,
                                route_label: format!("Group -> {} (SOCKS5 UDP)", reply.proxy_name),
                                latency_ms: 8,
                                rx_bytes: reply.payload.len() as u64,
                                tx_bytes: payload.len() as u64,
                                status: ConnectionStatus::Active,
                                started_at: Utc::now(),
                            },
                            true,
                        );
                        Ok(reply.payload)
                    }
                    Err(err) => {
                        if kill_switch_enabled
                            || block_udp_on_tcp_only
                            || matches!(err, RouteWardError::UdpAssociateUnsupported { .. })
                        {
                            self.push_rate_limited_warn(
                                "udp_group_killswitch",
                                COMPONENT_ENGINE,
                                format!(
                                    "Kill-Switch blocked group UDP datagram PID={} process=\"{}\" -> {}:{} [rule=\"{}\"]: {}",
                                    pid, proc_basename, raw_host, target_port, eval.matched_rule_name, err
                                ),
                            );
                            self.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid,
                                    process_name: proc_basename,
                                    process_path: proc_path_str,
                                    target_host: raw_host,
                                    resolved_domain: eval.effective_domain,
                                    target_port,
                                    protocol: TransportProtocol::Udp,
                                    matched_rule: eval.matched_rule_name,
                                    route_label: ROUTE_BLOCK_LABEL.to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
                            );
                        }
                        Err(err)
                    }
                }
            }
        }
    }

    async fn handle_tproxy_udp_datagram(
        &self,
        payload: &[u8],
        client_addr: std::net::SocketAddrV4,
        orig_dst_opt: Option<std::net::SocketAddrV4>,
        reply_sock: &UdpSocket,
    ) {
        let peer_addr = SocketAddr::V4(client_addr);
        let llmnr_port = self.constants.network.llmnr_standard_port;
        let mdns_port = self.constants.network.mdns_standard_port;
        let fwmark = self.constants.network.linux_fwmark;

        let resolved_orig_dst = orig_dst_opt.or_else(|| {
            self.lookup_udp_conntrack_orig_dst(peer_addr, &[llmnr_port, mdns_port])
                .and_then(|sa| match sa {
                    SocketAddr::V4(v4) => Some(v4),
                    SocketAddr::V6(_) => None,
                })
        });

        let Some(orig_dst) = resolved_orig_dst else {
            return;
        };

        // Priority 1: Local name resolution protocols (LLMNR 5355 and mDNS 5353)
        // Forwarded via raw socket preserving the client's original IP and source port (Point 4 / Leak #7 fix).
        if orig_dst.port() == llmnr_port || orig_dst.port() == mdns_port {
            match self.dns.classify_local_name_query(payload) {
                LocalNameQueryDecision::BlockPublicFqdn { qname } => {
                    self.push_rate_limited_warn(
                        "local_name_public_fqdn",
                        COMPONENT_DNS,
                        format!(
                            "Blocked public FQDN \"{qname}\" on local name resolution protocol (LLMNR/mDNS) from {peer_addr}"
                        ),
                    );
                    self.telemetry.record_connection(
                        TrackedConnection {
                            id: Uuid::new_v4().to_string(),
                            pid: 0,
                            process_name: "local-name-proto".to_string(),
                            process_path: "local-name-proto".to_string(),
                            target_host: qname.clone(),
                            resolved_domain: Some(qname),
                            target_port: orig_dst.port(),
                            protocol: TransportProtocol::Udp,
                            matched_rule: "SecurityPolicy:LocalNamePublicFqdnBlocked".to_string(),
                            route_label: ROUTE_BLOCK_LABEL.to_string(),
                            latency_ms: 0,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            status: ConnectionStatus::Blocked,
                            started_at: Utc::now(),
                        },
                        false,
                    );
                }
                LocalNameQueryDecision::BlockMalformed => {}
                LocalNameQueryDecision::AllowLocal { qname } => {
                    self.telemetry.push_log(
                        LogLevel::Debug,
                        COMPONENT_DNS,
                        format!(
                            "Forwarding allowed local name query \"{qname}\" from {client_addr} directly to {orig_dst} (preserving source port {})",
                            client_addr.port()
                        ),
                    );
                    if NftablesInterceptor::send_raw_ipv4_udp_packet(
                        client_addr,
                        orig_dst,
                        payload,
                        fwmark,
                    )
                    .is_err()
                    {
                        if let Ok(resp) = self
                            .query_dns_udp_direct_protected(
                                payload,
                                SocketAddr::V4(orig_dst),
                                Duration::from_millis(300),
                            )
                            .await
                        {
                            if !resp.is_empty() {
                                let _ = NftablesInterceptor::send_udp_from_local_ip(
                                    reply_sock,
                                    &resp,
                                    peer_addr,
                                    Some(*orig_dst.ip()),
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            return;
        }

        // Priority 2: General transparent UDP interception via TPROXY
        let target_host = orig_dst.ip().to_string();
        let target_port = orig_dst.port();
        let attribution = self
            .process_resolver
            .resolve_udp_port_attribution(client_addr.port());
        let (
            pid,
            proc_name,
            proc_path,
            eval_action,
            matched_rule_name,
            effective_domain,
            _res_source,
        ) = self.attribute_or_apply_unknown_policy_with_proto(
            attribution,
            client_addr.port(),
            &target_host,
            target_port,
            Some(orig_dst.ip()),
            TransportProtocol::Udp,
        );

        if proc_name == "unknown" && eval_action == RuleAction::Block {
            self.telemetry.record_connection(
                TrackedConnection {
                    id: Uuid::new_v4().to_string(),
                    pid,
                    process_name: proc_name,
                    process_path: proc_path,
                    target_host,
                    resolved_domain: effective_domain,
                    target_port,
                    protocol: TransportProtocol::Udp,
                    matched_rule: matched_rule_name,
                    route_label: ROUTE_BLOCK_LABEL.to_string(),
                    latency_ms: 0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    status: ConnectionStatus::Blocked,
                    started_at: Utc::now(),
                },
                false,
            );
            return;
        }

        let target = Socks5UdpTarget::Ipv4(*orig_dst.ip(), target_port);
        if let Ok(reply_payload) = self
            .forward_udp_datagram(
                peer_addr,
                &proc_name,
                Some(&proc_path),
                pid,
                &target,
                payload,
                false,
            )
            .await
        {
            if !reply_payload.is_empty() {
                let _ = NftablesInterceptor::send_raw_ipv4_udp_packet(
                    orig_dst,
                    client_addr,
                    &reply_payload,
                    fwmark,
                );
            }
        }
    }

    async fn handle_local_socks5_client(
        &self,
        mut client: TcpStream,
        client_port: u16,
    ) -> RouteWardResult<()> {
        let proto = &self.constants.protocols;
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await?;
        if header[0] != proto.socks5_version {
            return Ok(());
        }
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        client.read_exact(&mut methods).await?;
        client
            .write_all(&[proto.socks5_version, proto.socks5_auth_none])
            .await?;

        let mut req_head = [0u8; 4];
        client.read_exact(&mut req_head).await?;
        let target_host = match req_head[3] {
            atyp if atyp == proto.socks5_atyp_ipv4 => {
                let mut ip = [0u8; 4];
                client.read_exact(&mut ip).await?;
                IpAddr::from(ip).to_string()
            }
            atyp if atyp == proto.socks5_atyp_domain => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                let mut dom = vec![0u8; len[0] as usize];
                client.read_exact(&mut dom).await?;
                String::from_utf8_lossy(&dom).to_string()
            }
            atyp if atyp == proto.socks5_atyp_ipv6 => {
                let mut ip = [0u8; 16];
                client.read_exact(&mut ip).await?;
                IpAddr::from(ip).to_string()
            }
            _ => return Ok(()),
        };

        let mut port_bytes = [0u8; 2];
        client.read_exact(&mut port_bytes).await?;
        let target_port = u16::from_be_bytes(port_bytes);

        let proc_id = self.process_resolver.resolve_by_local_tcp_port(client_port);

        if req_head[1] == proto.socks5_cmd_udp_associate {
            let udp_relay =
                UdpSocket::bind(format!("{}:0", self.constants.network.local_bind_host)).await?;
            let relay_addr = udp_relay.local_addr()?;
            let bind_ip = match relay_addr.ip() {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
            };
            let bind_port = relay_addr.port().to_be_bytes();
            let ip_octets = bind_ip.octets();
            let assoc_reply = [
                proto.socks5_version,
                proto.socks5_reply_succeeded,
                0x00,
                proto.socks5_atyp_ipv4,
                ip_octets[0],
                ip_octets[1],
                ip_octets[2],
                ip_octets[3],
                bind_port[0],
                bind_port[1],
            ];
            client.write_all(&assoc_reply).await?;

            let mut tcp_probe = [0u8; 1];
            let mut udp_buf = vec![0u8; 65535];
            while self.is_running() {
                tokio::select! {
                    read_res = client.read(&mut tcp_probe) => {
                        match read_res {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    recv_res = udp_relay.recv_from(&mut udp_buf) => {
                        let Ok((n, udp_peer)) = recv_res else {
                            break;
                        };
                        let Ok((target, payload)) = decode_socks5_udp_datagram(&udp_buf[..n], proto) else {
                            continue;
                        };
                        if let Ok(reply_payload) = self
                            .forward_udp_datagram(
                                udp_peer,
                                &proc_id.name,
                                Some(&proc_id.executable_path),
                                proc_id.pid,
                                &target,
                                payload,
                                false,
                            )
                            .await
                        {
                            if let Ok(encoded_reply) = encode_socks5_udp_datagram(&target, &reply_payload, proto) {
                                let _ = udp_relay.send_to(&encoded_reply, udp_peer).await;
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        let target_ip_str = target_host
            .parse::<Ipv4Addr>()
            .ok()
            .map(|ip| ip.to_string());
        let mut eval = self.evaluate_rule(&ConnectionRequest {
            process_name: proc_id.name.clone(),
            process_path: Some(proc_id.executable_path.clone()),
            target_host: target_host.clone(),
            target_ip: target_ip_str,
            target_port,
            protocol: TransportProtocol::Tcp,
        });
        if proc_id.is_unattributed() && eval.action == RuleAction::Direct {
            let (action, matched_rule_name) = self.resolve_unknown_process_action(
                COMPONENT_ENGINE,
                client_port,
                &target_host,
                target_port,
                "local SOCKS5 client PID or executable image unavailable",
            );
            eval.matched_rule_id = "unknown-process-action".to_string();
            eval.matched_rule_name = matched_rule_name;
            eval.action = action;
        }

        let effective_host = eval
            .effective_domain
            .clone()
            .unwrap_or_else(|| target_host.clone());

        if target_port == self.constants.dns.dns_over_tls_port
            && self
                .profile
                .read()
                .security_policy
                .block_encrypted_dns_bypass
        {
            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_DNS,
                format!(
                    "Blocked encrypted DNS bypass (DoT TCP port {}) via local SOCKS5 for PID={} process=\"{}\" -> {}",
                    target_port, proc_id.pid, proc_id.name, effective_host
                ),
            );
            eval.matched_rule_name = "SecurityPolicy:blockEncryptedDnsBypass".to_string();
            eval.action = RuleAction::Block;
        }

        if eval.action == RuleAction::Block {
            let blocked_conn = TrackedConnection {
                id: Uuid::new_v4().to_string(),
                pid: proc_id.pid,
                process_name: proc_id.name,
                process_path: proc_id.executable_path,
                target_host,
                resolved_domain: eval.effective_domain,
                target_port,
                protocol: TransportProtocol::Tcp,
                matched_rule: eval.matched_rule_name,
                route_label: ROUTE_BLOCK_LABEL.to_string(),
                latency_ms: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                status: ConnectionStatus::Blocked,
                started_at: Utc::now(),
            };
            self.telemetry.record_connection(blocked_conn, false);
            Self::send_socks5_failure_and_close(&mut client, proto).await;
            return Ok(());
        }

        let is_proxied_rule = matches!(
            eval.action,
            RuleAction::Proxy { .. } | RuleAction::Chain { .. }
        );
        let kill_switch_enabled = self.profile.read().security_policy.kill_switch_enabled;

        let (mut outbound, effective_action) = match self
            .open_outbound_stream(&eval.action, &effective_host, target_port)
            .await
        {
            Ok(stream) => (stream, eval.action.clone()),
            Err(err) => {
                if is_proxied_rule && kill_switch_enabled {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!(
                            "Kill-Switch blocked local SOCKS5 connection PID={} process=\"{}\" exe=\"{}\" -> {}:{} [rule=\"{}\", killSwitchEnabled=true]: {}",
                            proc_id.pid,
                            proc_id.name,
                            proc_id.executable_path,
                            effective_host,
                            target_port,
                            eval.matched_rule_name,
                            err
                        ),
                    );
                    self.telemetry.record_connection(
                        TrackedConnection {
                            id: Uuid::new_v4().to_string(),
                            pid: proc_id.pid,
                            process_name: proc_id.name,
                            process_path: proc_id.executable_path,
                            target_host,
                            resolved_domain: eval.effective_domain,
                            target_port,
                            protocol: TransportProtocol::Tcp,
                            matched_rule: eval.matched_rule_name,
                            route_label: ROUTE_BLOCK_LABEL.to_string(),
                            latency_ms: 0,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            status: ConnectionStatus::Blocked,
                            started_at: Utc::now(),
                        },
                        false,
                    );
                    Self::send_socks5_failure_and_close(&mut client, proto).await;
                    return Err(err);
                } else if is_proxied_rule {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!(
                            "Upstream proxy failed for local SOCKS5 connection PID={} process=\"{}\" exe=\"{}\" -> {}:{} ({}); falling back to DIRECT because killSwitchEnabled=false",
                            proc_id.pid,
                            proc_id.name,
                            proc_id.executable_path,
                            effective_host,
                            target_port,
                            err
                        ),
                    );
                    match self
                        .open_outbound_stream(&RuleAction::Direct, &effective_host, target_port)
                        .await
                    {
                        Ok(direct_stream) => (direct_stream, RuleAction::Direct),
                        Err(direct_err) => {
                            Self::send_socks5_failure_and_close(&mut client, proto).await;
                            return Err(direct_err);
                        }
                    }
                } else {
                    Self::send_socks5_failure_and_close(&mut client, proto).await;
                    return Err(err);
                }
            }
        };

        let success_reply = [
            proto.socks5_version,
            proto.socks5_reply_succeeded,
            0x00,
            proto.socks5_atyp_ipv4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        client.write_all(&success_reply).await?;

        let conn_id = Uuid::new_v4().to_string();
        let is_proxied = !matches!(effective_action, RuleAction::Direct);
        let tracked = TrackedConnection {
            id: conn_id.clone(),
            pid: proc_id.pid,
            process_name: proc_id.name,
            process_path: proc_id.executable_path,
            target_host,
            resolved_domain: eval.effective_domain,
            target_port,
            protocol: TransportProtocol::Tcp,
            matched_rule: eval.matched_rule_name,
            route_label: self.format_action_label(&effective_action),
            latency_ms: 12,
            rx_bytes: 0,
            tx_bytes: 0,
            status: ConnectionStatus::Active,
            started_at: Utc::now(),
        };
        self.telemetry.record_connection(tracked, is_proxied);
        let _ = self
            .telemetry
            .relay_bidirectional_with_telemetry(&conn_id, &mut client, &mut outbound)
            .await;

        Ok(())
    }

    async fn send_socks5_failure_and_close(
        client: &mut TcpStream,
        proto: &crate::config::ProtocolConstants,
    ) {
        let failure_reply = [
            proto.socks5_version,
            proto.socks5_reply_general_failure,
            0x00,
            proto.socks5_atyp_ipv4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let _ = client.write_all(&failure_reply).await;
        let _ = client.shutdown().await;
    }

    /// Peeks at the initial bytes of an accepted TCP stream on port 443 (with a bounded timeout
    /// and maximum buffer size) to extract the TLS `ClientHello` SNI hostname without consuming
    /// bytes from the socket receive buffer.
    async fn peek_tls_client_hello_sni(&self, client: &TcpStream) -> Option<String> {
        let max_bytes = self.constants.network.tls_sni_max_bytes.clamp(64, 16384);
        let timeout_dur =
            Duration::from_millis(self.constants.network.tls_sni_peek_timeout_ms.max(10));
        let deadline = tokio::time::Instant::now() + timeout_dur;
        let mut buf = vec![0u8; max_bytes];

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline - now;
            let peeked = match tokio::time::timeout(remaining, client.peek(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
                Ok(Ok(n)) => n,
            };

            // A TLS Handshake record always starts with 0x16. Abort immediately on any non-TLS byte.
            if buf[0] != 0x16 {
                return None;
            }

            if let Some(sni) = TlsSniExtractor::extract_sni(&buf[..peeked]) {
                return Some(sni);
            }

            if peeked >= 5 {
                let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                let total_needed = (5 + record_len).min(max_bytes);
                if peeked >= total_needed {
                    return None;
                }
            }

            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    pub async fn handle_transparent_tcp_client(
        &self,
        mut client: TcpStream,
        peer_addr: SocketAddr,
    ) -> RouteWardResult<()> {
        if let Some(mut session) = self.nat_table.validate_relay_peer_addr(peer_addr) {
            let target_host = session.orig_dst_ip.to_string();
            let target_port = session.orig_dst_port;
            if target_port == self.constants.dns.dns_standard_port {
                let res = self
                    .handle_dns_tcp_stream(
                        client,
                        Some(SocketAddr::new(
                            IpAddr::V4(session.orig_dst_ip),
                            target_port,
                        )),
                    )
                    .await;
                self.nat_table
                    .remove_session_by_relay_peer(session.orig_dst_ip, session.client_port);
                return res;
            }
            let is_fake_ip = self.dns.is_in_fake_subnet(&session.orig_dst_ip);
            let mut resolved_domain = self.dns.resolve_fake_ip(&session.orig_dst_ip);

            // Point 5: When destination is not a Fake-IP and port is 443, extract TLS ClientHello SNI
            // and re-evaluate domain routing rules.
            if !is_fake_ip
                && resolved_domain.is_none()
                && target_port == self.constants.network.tls_sni_default_port
            {
                if let Some(sni_domain) = self.peek_tls_client_hello_sni(&client).await {
                    let eval = self.evaluate_rule(&ConnectionRequest {
                        process_name: session.process_name.clone(),
                        process_path: Some(session.process_path.clone()),
                        target_host: sni_domain.clone(),
                        target_ip: Some(target_host.clone()),
                        target_port,
                        protocol: TransportProtocol::Tcp,
                    });
                    session.action = eval.action;
                    session.matched_rule_name = eval.matched_rule_name;
                    resolved_domain = Some(sni_domain);
                }
            }

            if session.action == RuleAction::Block {
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_TRANSPARENT,
                    format!(
                        "Blocked connection PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} (domain={:?}) [rule=\"{}\"]",
                        session.pid,
                        session.process_name,
                        session.process_path,
                        session.resolution_source.as_str(),
                        target_host,
                        target_port,
                        resolved_domain,
                        session.matched_rule_name
                    ),
                );
                self.telemetry.record_connection(
                    TrackedConnection {
                        id: Uuid::new_v4().to_string(),
                        pid: session.pid,
                        process_name: session.process_name.clone(),
                        process_path: session.process_path.clone(),
                        target_host,
                        resolved_domain,
                        target_port,
                        protocol: TransportProtocol::Tcp,
                        matched_rule: session.matched_rule_name.clone(),
                        route_label: ROUTE_BLOCK_LABEL.to_string(),
                        latency_ms: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        status: ConnectionStatus::Blocked,
                        started_at: Utc::now(),
                    },
                    false,
                );
                let _ = client.shutdown().await;
                self.nat_table
                    .remove_session_by_relay_peer(session.orig_dst_ip, session.client_port);
                return Ok(());
            }

            let is_proxied_rule = matches!(
                session.action,
                RuleAction::Proxy { .. } | RuleAction::Chain { .. }
            );
            let effective_host = if is_proxied_rule || is_fake_ip {
                resolved_domain
                    .clone()
                    .unwrap_or_else(|| target_host.clone())
            } else {
                target_host.clone()
            };
            let direct_fallback_host = if is_fake_ip {
                effective_host.clone()
            } else {
                target_host.clone()
            };
            let kill_switch_enabled = self.profile.read().security_policy.kill_switch_enabled;

            let (mut outbound, effective_action) = match self
                .open_outbound_stream(&session.action, &effective_host, target_port)
                .await
            {
                Ok(stream) => (stream, session.action.clone()),
                Err(err) => {
                    if is_proxied_rule && kill_switch_enabled {
                        self.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Kill-Switch blocked connection PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} [rule=\"{}\", killSwitchEnabled=true]: {}",
                                session.pid,
                                session.process_name,
                                session.process_path,
                                session.resolution_source.as_str(),
                                target_host,
                                target_port,
                                session.matched_rule_name,
                                err
                            ),
                        );
                        self.telemetry.record_connection(
                            TrackedConnection {
                                id: Uuid::new_v4().to_string(),
                                pid: session.pid,
                                process_name: session.process_name.clone(),
                                process_path: session.process_path.clone(),
                                target_host,
                                resolved_domain,
                                target_port,
                                protocol: TransportProtocol::Tcp,
                                matched_rule: session.matched_rule_name.clone(),
                                route_label: ROUTE_BLOCK_LABEL.to_string(),
                                latency_ms: 0,
                                rx_bytes: 0,
                                tx_bytes: 0,
                                status: ConnectionStatus::Blocked,
                                started_at: Utc::now(),
                            },
                            false,
                        );
                        let _ = client.shutdown().await;
                        self.nat_table
                            .remove_session_by_relay_peer(session.orig_dst_ip, session.client_port);
                        return Err(err);
                    } else if is_proxied_rule {
                        self.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Upstream proxy failed for PID={} process=\"{}\" exe=\"{}\" -> {}:{} ({}); falling back to DIRECT because killSwitchEnabled=false",
                                session.pid,
                                session.process_name,
                                session.process_path,
                                target_host,
                                target_port,
                                err
                            ),
                        );
                        match self
                            .open_outbound_stream(
                                &RuleAction::Direct,
                                &direct_fallback_host,
                                target_port,
                            )
                            .await
                        {
                            Ok(direct_stream) => (direct_stream, RuleAction::Direct),
                            Err(direct_err) => {
                                let _ = client.shutdown().await;
                                self.nat_table.remove_session_by_relay_peer(
                                    session.orig_dst_ip,
                                    session.client_port,
                                );
                                return Err(direct_err);
                            }
                        }
                    } else {
                        self.telemetry.push_log(
                            LogLevel::Error,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Failed upstream connect for PID={} process=\"{}\" exe=\"{}\" -> {}:{}: {}",
                                session.pid,
                                session.process_name,
                                session.process_path,
                                target_host,
                                target_port,
                                err
                            ),
                        );
                        let _ = client.shutdown().await;
                        self.nat_table
                            .remove_session_by_relay_peer(session.orig_dst_ip, session.client_port);
                        return Err(err);
                    }
                }
            };

            let route_label = self.format_action_label(&effective_action);
            self.telemetry.push_log(
                LogLevel::Info,
                COMPONENT_TRANSPARENT,
                format!(
                    "Routed PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} via {} [rule=\"{}\"]",
                    session.pid,
                    session.process_name,
                    session.process_path,
                    session.resolution_source.as_str(),
                    target_host,
                    target_port,
                    route_label,
                    session.matched_rule_name
                ),
            );

            let conn_id = Uuid::new_v4().to_string();
            let is_proxied = !matches!(effective_action, RuleAction::Direct);
            let tracked = TrackedConnection {
                id: conn_id.clone(),
                pid: session.pid,
                process_name: session.process_name,
                process_path: session.process_path,
                target_host,
                resolved_domain,
                target_port,
                protocol: TransportProtocol::Tcp,
                matched_rule: session.matched_rule_name,
                route_label,
                latency_ms: 10,
                rx_bytes: 0,
                tx_bytes: 0,
                status: ConnectionStatus::Active,
                started_at: Utc::now(),
            };
            self.telemetry.record_connection(tracked, is_proxied);

            let _ = self
                .telemetry
                .relay_bidirectional_with_telemetry(&conn_id, &mut client, &mut outbound)
                .await;
            self.nat_table
                .remove_session_by_relay_peer(session.orig_dst_ip, session.client_port);

            return Ok(());
        }

        #[cfg(not(windows))]
        {
            let relay_port = self.constants.network.default_transparent_tcp_port;
            if let Some(orig_dst) = NftablesInterceptor::query_original_dst(&client, relay_port) {
                let target_host = orig_dst.ip().to_string();
                let target_port = orig_dst.port();
                let client_port = peer_addr.port();

                if target_port == self.constants.dns.dns_standard_port {
                    return self
                        .handle_dns_tcp_stream(client, Some(SocketAddr::V4(orig_dst)))
                        .await;
                }

                let is_fake_ip = self.dns.is_in_fake_subnet(orig_dst.ip());
                let sni_domain =
                    if !is_fake_ip && target_port == self.constants.network.tls_sni_default_port {
                        self.peek_tls_client_hello_sni(&client).await
                    } else {
                        None
                    };

                let attribution = self
                    .process_resolver
                    .resolve_tcp_port_attribution(client_port);

                let (
                    pid,
                    proc_name,
                    proc_path,
                    mut eval_action,
                    mut matched_rule_name,
                    mut effective_domain,
                    res_source,
                ) = self.attribute_or_apply_unknown_policy(
                    attribution,
                    client_port,
                    &target_host,
                    target_port,
                    Some(orig_dst.ip()),
                );

                if let Some(ref sni) = sni_domain {
                    if proc_name != "unknown" {
                        let sni_eval = self.evaluate_rule(&ConnectionRequest {
                            process_name: proc_name.clone(),
                            process_path: Some(proc_path.clone()),
                            target_host: sni.clone(),
                            target_ip: Some(target_host.clone()),
                            target_port,
                            protocol: TransportProtocol::Tcp,
                        });
                        eval_action = sni_eval.action;
                        matched_rule_name = sni_eval.matched_rule_name;
                    }
                    effective_domain = Some(sni.clone());
                }

                if target_port == self.constants.dns.dns_over_tls_port
                    && self
                        .profile
                        .read()
                        .security_policy
                        .block_encrypted_dns_bypass
                {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_DNS,
                        format!(
                            "Blocked encrypted DNS bypass (DoT TCP port {}) PID={} process=\"{}\" -> {}:{}",
                            target_port, pid, proc_name, target_host, target_port
                        ),
                    );
                    eval_action = RuleAction::Block;
                    matched_rule_name = "SecurityPolicy:blockEncryptedDnsBypass".to_string();
                }

                let is_proxied_rule = matches!(
                    eval_action,
                    RuleAction::Proxy { .. } | RuleAction::Chain { .. }
                );
                let effective_host = if is_proxied_rule || is_fake_ip {
                    effective_domain
                        .clone()
                        .unwrap_or_else(|| target_host.clone())
                } else {
                    target_host.clone()
                };
                let direct_fallback_host = if is_fake_ip {
                    effective_host.clone()
                } else {
                    target_host.clone()
                };

                if eval_action == RuleAction::Block {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_TRANSPARENT,
                        format!(
                            "Blocked connection PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} [rule=\"{}\"] (TCP RST)",
                            pid,
                            proc_name,
                            proc_path,
                            res_source,
                            target_host,
                            target_port,
                            matched_rule_name
                        ),
                    );
                    self.telemetry.record_connection(
                        TrackedConnection {
                            id: Uuid::new_v4().to_string(),
                            pid,
                            process_name: proc_name,
                            process_path: proc_path,
                            target_host,
                            resolved_domain: effective_domain,
                            target_port,
                            protocol: TransportProtocol::Tcp,
                            matched_rule: matched_rule_name,
                            route_label: ROUTE_BLOCK_LABEL.to_string(),
                            latency_ms: 0,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            status: ConnectionStatus::Blocked,
                            started_at: Utc::now(),
                        },
                        false,
                    );
                    NftablesInterceptor::reset_and_close_tcp_stream(client);
                    return Ok(());
                }

                let kill_switch_enabled = self.profile.read().security_policy.kill_switch_enabled;

                let (mut outbound, effective_action) = match self
                    .open_outbound_stream(&eval_action, &effective_host, target_port)
                    .await
                {
                    Ok(stream) => (stream, eval_action.clone()),
                    Err(err) => {
                        if is_proxied_rule && kill_switch_enabled {
                            self.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_TRANSPARENT,
                                format!(
                                    "Kill-Switch blocked connection PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} [rule=\"{}\", killSwitchEnabled=true]: {}",
                                    pid,
                                    proc_name,
                                    proc_path,
                                    res_source,
                                    target_host,
                                    target_port,
                                    matched_rule_name,
                                    err
                                ),
                            );
                            self.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid,
                                    process_name: proc_name,
                                    process_path: proc_path,
                                    target_host,
                                    resolved_domain: effective_domain,
                                    target_port,
                                    protocol: TransportProtocol::Tcp,
                                    matched_rule: matched_rule_name,
                                    route_label: ROUTE_BLOCK_LABEL.to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
                            );
                            NftablesInterceptor::reset_and_close_tcp_stream(client);
                            return Err(err);
                        } else if is_proxied_rule {
                            self.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_TRANSPARENT,
                                format!(
                                    "Upstream proxy failed for PID={} process=\"{}\" exe=\"{}\" -> {}:{} ({}); falling back to DIRECT because killSwitchEnabled=false",
                                    pid, proc_name, proc_path, target_host, target_port, err
                                ),
                            );
                            match self
                                .open_outbound_stream(
                                    &RuleAction::Direct,
                                    &direct_fallback_host,
                                    target_port,
                                )
                                .await
                            {
                                Ok(direct_stream) => (direct_stream, RuleAction::Direct),
                                Err(direct_err) => {
                                    NftablesInterceptor::reset_and_close_tcp_stream(client);
                                    return Err(direct_err);
                                }
                            }
                        } else {
                            self.telemetry.push_log(
                                LogLevel::Error,
                                COMPONENT_TRANSPARENT,
                                format!(
                                    "Failed upstream connect for PID={} process=\"{}\" exe=\"{}\" -> {}:{}: {}",
                                    pid, proc_name, proc_path, target_host, target_port, err
                                ),
                            );
                            NftablesInterceptor::reset_and_close_tcp_stream(client);
                            return Err(err);
                        }
                    }
                };

                let route_label = self.format_action_label(&effective_action);
                self.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_TRANSPARENT,
                    format!(
                        "Routed PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} via {} [rule=\"{}\"]",
                        pid,
                        proc_name,
                        proc_path,
                        res_source,
                        target_host,
                        target_port,
                        route_label,
                        matched_rule_name
                    ),
                );

                let conn_id = Uuid::new_v4().to_string();
                let is_proxied = !matches!(effective_action, RuleAction::Direct);
                let tracked = TrackedConnection {
                    id: conn_id.clone(),
                    pid,
                    process_name: proc_name,
                    process_path: proc_path,
                    target_host,
                    resolved_domain: effective_domain,
                    target_port,
                    protocol: TransportProtocol::Tcp,
                    matched_rule: matched_rule_name,
                    route_label,
                    latency_ms: 10,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    status: ConnectionStatus::Active,
                    started_at: Utc::now(),
                };
                self.telemetry.record_connection(tracked, is_proxied);
                let _ = self
                    .telemetry
                    .relay_bidirectional_with_telemetry(&conn_id, &mut client, &mut outbound)
                    .await;
                return Ok(());
            }
        }

        let _ = client.shutdown().await;
        self.telemetry.push_log(
            LogLevel::Warn,
            COMPONENT_TRANSPARENT,
            format!(
                "Rejected unauthorized connection on transparent relay from {peer_addr}: no matching live NAT session"
            ),
        );
        Ok(())
    }

    async fn open_outbound_stream(
        &self,
        action: &RuleAction,
        target_host: &str,
        target_port: u16,
    ) -> RouteWardResult<TcpStream> {
        match action {
            RuleAction::Direct => {
                if let Ok(ip) = target_host.parse::<IpAddr>() {
                    self.connect_direct_tcp_protected(SocketAddr::new(ip, target_port))
                        .await
                        .map_err(RouteWardError::Io)
                } else {
                    let resolved_ip = self.resolve_host_direct_ipv4(target_host).await?;
                    self.connect_direct_tcp_protected(SocketAddr::new(
                        IpAddr::V4(resolved_ip),
                        target_port,
                    ))
                    .await
                    .map_err(RouteWardError::Io)
                }
            }
            RuleAction::Proxy { target_id } => {
                let node = {
                    let prof = self.profile.read();
                    prof.proxies
                        .iter()
                        .find(|p| &p.id == target_id)
                        .cloned()
                        .ok_or_else(|| RouteWardError::ProxyNotFound {
                            key: ERR_KEY_PROXY_NOT_FOUND,
                            proxy_id: target_id.clone(),
                        })?
                };
                let resolved_node = self.prepare_proxy_node_with_bootstrap(node).await?;
                let _self_guard = self.register_self_proxy_connect_hint(&resolved_node);
                ProxyConnector::connect_single(
                    &resolved_node,
                    target_host,
                    target_port,
                    &self.constants,
                )
                .await
            }
            RuleAction::Chain { target_id } => {
                let (strategy, hops) = {
                    let prof = self.profile.read();
                    let chain =
                        prof.chains
                            .iter()
                            .find(|c| &c.id == target_id)
                            .ok_or_else(|| RouteWardError::ProxyNotFound {
                                key: ERR_KEY_PROXY_NOT_FOUND,
                                proxy_id: target_id.clone(),
                            })?;
                    let mut nodes = Vec::new();
                    for pid in &chain.proxy_ids {
                        if let Some(n) = prof.proxies.iter().find(|p| &p.id == pid) {
                            nodes.push(n.clone());
                        }
                    }
                    (chain.strategy, nodes)
                };
                let mut resolved_hops = Vec::with_capacity(hops.len());
                for hop in hops {
                    match self.prepare_proxy_node_with_bootstrap(hop.clone()).await {
                        Ok(resolved) => resolved_hops.push(resolved),
                        Err(_) => resolved_hops.push(hop),
                    }
                }
                ProxyConnector::connect_group(
                    strategy,
                    &resolved_hops,
                    0,
                    target_host,
                    target_port,
                    &self.constants,
                )
                .await
            }
            RuleAction::Block => Err(RouteWardError::BlockedByPolicy {
                key: crate::error::ERR_KEY_RULE_BLOCKED,
                rule_name: ROUTE_BLOCK_LABEL.to_string(),
            }),
        }
    }

    fn register_self_proxy_connect_hint(&self, node: &ProxyNode) -> Option<()> {
        if let Ok(ip) = node.host.parse::<Ipv4Addr>() {
            let mut endpoints = self.nat_table.upstream_endpoints();
            if !endpoints.contains(&(ip, node.port)) {
                endpoints.push((ip, node.port));
                self.nat_table.set_upstream_endpoints(endpoints);
            }
        }
        Some(())
    }

    /// Resolves any domain-named upstream proxy hosts directly (without Fake-IP, without loops)
    /// and registers their resolved IPv4 `(ip, port)` endpoints in `nat_table` for anti-loop exclusion.
    pub async fn bootstrap_resolve_proxy_hosts(&self) {
        let nodes: Vec<ProxyNode> = self.profile.read().proxies.clone();
        for node in nodes {
            if node.host.parse::<IpAddr>().is_err() {
                let _ = self.prepare_proxy_node_with_bootstrap(node).await;
            }
        }
    }

    async fn prepare_proxy_node_with_bootstrap(
        &self,
        mut node: ProxyNode,
    ) -> RouteWardResult<ProxyNode> {
        if node.host.parse::<IpAddr>().is_ok() {
            return Ok(node);
        }
        let orig_host = node.host.clone();
        let ips = self.resolve_host_direct_ipv4_all(&orig_host).await?;
        let Some(&first_ip) = ips.first() else {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!(
                    "Bootstrap DNS resolution returned no IPv4 records for proxy host \"{orig_host}\""
                ),
            });
        };

        let mut endpoints = self.nat_table.upstream_endpoints();
        let mut added = false;
        for ip in &ips {
            let pair = (*ip, node.port);
            if !endpoints.contains(&pair) {
                endpoints.push(pair);
                added = true;
            }
        }
        if added {
            self.nat_table.set_upstream_endpoints(endpoints);
            self.telemetry.push_log(
                LogLevel::Debug,
                COMPONENT_DNS,
                format!(
                    "Bootstrap-resolved proxy host \"{orig_host}\":{} -> {:?} (added to anti-loop exclusions)",
                    node.port, ips
                ),
            );
        }

        if node.tls && node.sni.is_none() {
            node.sni = Some(orig_host);
        }
        node.host = first_ip.to_string();
        Ok(node)
    }

    /// Fast synchronous DNS resolution path for in-memory Fake-IP (`A`), `AAAA` (`NODATA`),
    /// Fake-IP `PTR`, and DoH canary (`NXDOMAIN`) queries. Returns `None` when network I/O is required
    /// (bypassed domains, `enableFakeIp = false`, or non-A/AAAA record types).
    pub fn resolve_dns_query_fast(&self, raw_query: &[u8]) -> Option<Vec<u8>> {
        let query = match parse_dns_query(raw_query) {
            Ok(q) => q,
            Err(_) => {
                return build_rcode_response_from_raw(raw_query, RCODE_FORMERR);
            }
        };

        let (enable_fake_ip, block_encrypted_dns) = {
            let prof = self.profile.read();
            (
                prof.dns_config.enable_fake_ip,
                prof.security_policy.block_encrypted_dns_bypass,
            )
        };

        let qname = &query.question.qname;
        let qtype = query.question.qtype;

        // 1. DoH canary domain (use-application-dns.net): return NXDOMAIN and log WARN
        if block_encrypted_dns && self.dns.is_doh_canary(qname) {
            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_DNS,
                format!(
                    "Blocked DoH canary DNS query for \"{}\" (returning NXDOMAIN; blockEncryptedDnsBypass=true)",
                    qname
                ),
            );
            return Some(build_rcode_response(&query, RCODE_NXDOMAIN));
        }

        // 2. Reverse PTR lookup for a Fake-IP in our pool (198.18.0.0/15)
        if qtype == QTYPE_PTR {
            if let Some(ip) = parse_ipv4_ptr_qname(qname) {
                if self.dns.is_in_fake_subnet(&ip) {
                    if let Some(domain) = self.dns.resolve_fake_ip(&ip) {
                        self.telemetry.push_log(
                            LogLevel::Debug,
                            COMPONENT_DNS,
                            format!("Fake-IP PTR {qname} ({ip}) -> {domain}"),
                        );
                        if let Ok(pkt) =
                            build_ptr_response(&query, &domain, self.dns.os_response_ttl_seconds())
                        {
                            return Some(pkt);
                        }
                    }
                    return Some(build_rcode_response(&query, RCODE_NXDOMAIN));
                }
            }
        }

        // 3. Bypassed domains (AD suffixes, single-label, .local, .localhost, private reverse zones)
        // must always be resolved via the async direct network path.
        if self.dns.is_bypassed(qname) {
            return None;
        }

        // 4. When Fake-IP is enabled: A -> pool IP with 5s OS TTL; AAAA -> NODATA
        if enable_fake_ip {
            if qtype == QTYPE_A {
                if let Some(fake_ip) = self.dns.allocate_or_get(qname) {
                    self.telemetry.push_log(
                        LogLevel::Debug,
                        COMPONENT_DNS,
                        format!(
                            "Fake-IP A \"{}\" -> {} (os_ttl={}s, internal_ttl={}s)",
                            qname,
                            fake_ip,
                            self.dns.os_response_ttl_seconds(),
                            self.dns.internal_ttl_seconds()
                        ),
                    );
                    return Some(build_a_response(
                        &query,
                        fake_ip,
                        self.dns.os_response_ttl_seconds(),
                    ));
                }
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DNS,
                    format!(
                        "Fake-IP pool exhausted for \"{}\"; returning SERVFAIL without cleartext DNS fallback",
                        qname
                    ),
                );
                return Some(build_rcode_response(&query, RCODE_SERVFAIL));
            } else if qtype == QTYPE_AAAA {
                self.telemetry.push_log(
                    LogLevel::Debug,
                    COMPONENT_DNS,
                    format!("Fake-IP AAAA \"{}\" -> NODATA (RCODE=0, ANCOUNT=0)", qname),
                );
                return Some(build_nodata_response(&query));
            }
        }

        None
    }

    /// Resolves a DNS query wire message asynchronously, handling fast in-memory responses,
    /// direct bypass resolution toward the originally targeted DNS server, and real DNS-over-TCP
    /// resolution through the configured proxy.
    pub async fn resolve_dns_query_async(
        &self,
        raw_query: &[u8],
        orig_resolver: Option<SocketAddr>,
        is_udp: bool,
    ) -> Vec<u8> {
        if let Some(orig) = orig_resolver {
            self.record_orig_dns_resolver(orig);
        }

        if let Some(fast_resp) = self.resolve_dns_query_fast(raw_query) {
            if is_udp {
                if let Ok(parsed_q) = parse_dns_query(raw_query) {
                    return enforce_udp_truncation(
                        &fast_resp,
                        &parsed_q,
                        parsed_q.max_udp_payload_bytes,
                    );
                }
            }
            return fast_resp;
        }

        let query = match parse_dns_query(raw_query) {
            Ok(q) => q,
            Err(_) => {
                return build_rcode_response_from_raw(raw_query, RCODE_FORMERR).unwrap_or_default();
            }
        };

        let qname = &query.question.qname;

        // 1. Bypassed domain: resolve directly toward the DNS server that the OS originally targeted
        // or active system resolvers; never query upstreamDns, default_upstream, or fallback_dns_server.
        if self.dns.is_bypassed(qname) {
            let resolvers =
                self.candidate_dns_resolvers(orig_resolver, DnsResolverMode::BypassOnlySystem);
            for resolver_addr in &resolvers {
                match self
                    .forward_dns_query_direct(raw_query, &query, *resolver_addr, is_udp)
                    .await
                {
                    Ok(resp) => {
                        self.telemetry.push_log(
                            LogLevel::Debug,
                            COMPONENT_DNS,
                            format!(
                                "Resolved bypassed domain \"{}\" (qtype={}) directly via {}",
                                qname, query.question.qtype, resolver_addr
                            ),
                        );
                        return resp;
                    }
                    Err(err) => {
                        self.telemetry.push_log(
                            LogLevel::Debug,
                            COMPONENT_DNS,
                            format!(
                                "Direct bypass DNS query for \"{}\" via {} failed: {}",
                                qname, resolver_addr, err
                            ),
                        );
                    }
                }
            }

            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_DNS,
                format!(
                    "Direct DNS resolution failed for bypassed domain \"{}\" across {:?}; returning SERVFAIL without querying public upstream resolvers",
                    qname, resolvers
                ),
            );
            return build_rcode_response(&query, RCODE_SERVFAIL);
        }

        // 2. Real DNS resolution via DNS-over-TCP through the rule's proxy
        let dns_action = self.select_dns_resolution_action(qname);
        match &dns_action {
            RuleAction::Block => {
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DNS,
                    format!("Blocked DNS query for \"{}\" by routing rule", qname),
                );
                build_rcode_response(&query, RCODE_REFUSED)
            }
            RuleAction::Direct => {
                let resolvers = self
                    .candidate_dns_resolvers(orig_resolver, DnsResolverMode::DirectPreferSystem);
                for resolver_addr in &resolvers {
                    if let Ok(resp) = self
                        .forward_dns_query_direct(raw_query, &query, *resolver_addr, is_udp)
                        .await
                    {
                        return resp;
                    }
                }
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DNS,
                    format!(
                        "Direct DNS resolution failed for \"{}\" across {:?}; returning SERVFAIL",
                        qname, resolvers
                    ),
                );
                build_rcode_response(&query, RCODE_SERVFAIL)
            }
            RuleAction::Proxy { .. } | RuleAction::Chain { .. } => {
                let resolvers =
                    self.candidate_dns_resolvers(orig_resolver, DnsResolverMode::RemoteViaProxy);
                let mut last_err = String::from("no upstream DNS server configured");
                for resolver_addr in &resolvers {
                    match self
                        .forward_dns_over_tcp_via_action(
                            raw_query,
                            &query,
                            &dns_action,
                            *resolver_addr,
                            is_udp,
                        )
                        .await
                    {
                        Ok(resp) => {
                            self.telemetry.push_log(
                                LogLevel::Debug,
                                COMPONENT_DNS,
                                format!(
                                    "Resolved \"{}\" (qtype={}) via DNS-over-TCP through proxy ({})",
                                    qname, query.question.qtype, resolver_addr
                                ),
                            );
                            return resp;
                        }
                        Err(err) => {
                            last_err = err.to_string();
                        }
                    }
                }

                let (strict_no_fallback, kill_switch_enabled) = {
                    let prof = self.profile.read();
                    (
                        prof.security_policy.strict_dns_no_local_fallback,
                        prof.security_policy.kill_switch_enabled,
                    )
                };

                if strict_no_fallback || kill_switch_enabled {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_DNS,
                        format!(
                            "DNS-over-TCP via proxy failed for \"{}\" (strictDnsNoLocalFallback={}, killSwitchEnabled={}): {}; returning SERVFAIL without cleartext fallback",
                            qname, strict_no_fallback, kill_switch_enabled, last_err
                        ),
                    );
                    return build_rcode_response(&query, RCODE_SERVFAIL);
                }

                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DNS,
                    format!(
                        "DNS-over-TCP via proxy failed for \"{}\" ({}); falling back to direct DNS because strictDnsNoLocalFallback=false and killSwitchEnabled=false",
                        qname, last_err
                    ),
                );
                for resolver_addr in
                    self.candidate_dns_resolvers(orig_resolver, DnsResolverMode::DirectPreferSystem)
                {
                    if let Ok(resp) = self
                        .forward_dns_query_direct(raw_query, &query, resolver_addr, is_udp)
                        .await
                    {
                        return resp;
                    }
                }
                build_rcode_response(&query, RCODE_SERVFAIL)
            }
        }
    }

    fn select_dns_resolution_action(&self, qname: &str) -> RuleAction {
        let eval = self.evaluate_rule(&ConnectionRequest {
            process_name: "dns-resolver".to_string(),
            process_path: None,
            target_host: qname.to_string(),
            target_ip: None,
            target_port: self.constants.dns.dns_standard_port,
            protocol: TransportProtocol::Tcp,
        });

        if !matches!(eval.action, RuleAction::Direct) {
            return eval.action;
        }

        let prof = self.profile.read();
        if !prof.dns_config.remote_dns_resolution {
            return RuleAction::Direct;
        }

        if matches!(
            prof.default_action,
            RuleAction::Proxy { .. } | RuleAction::Chain { .. }
        ) {
            return prof.default_action.clone();
        }

        for rule in &prof.rules {
            if rule.enabled
                && matches!(
                    rule.action,
                    RuleAction::Proxy { .. } | RuleAction::Chain { .. }
                )
            {
                return rule.action.clone();
            }
        }

        if let Some(first_proxy) = prof.proxies.iter().find(|p| p.enabled) {
            return RuleAction::Proxy {
                target_id: first_proxy.id.clone(),
            };
        }

        RuleAction::Direct
    }

    /// Handles a DNS-over-TCP client connection (RFC 1035 2-byte big-endian length-prefixed frames).
    pub async fn handle_dns_tcp_stream(
        &self,
        mut client: TcpStream,
        orig_resolver: Option<SocketAddr>,
    ) -> RouteWardResult<()> {
        let timeout_dur = Duration::from_millis(self.constants.network.proxy_handshake_timeout_ms);
        loop {
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(timeout_dur, client.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                _ => break,
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 || msg_len > DNS_MAX_TCP_MESSAGE_BYTES {
                break;
            }
            let mut query_buf = vec![0u8; msg_len];
            if tokio::time::timeout(timeout_dur, client.read_exact(&mut query_buf))
                .await
                .is_err()
            {
                break;
            }

            let resp = self
                .resolve_dns_query_async(&query_buf, orig_resolver, false)
                .await;
            if resp.is_empty() {
                break;
            }
            let framed = encode_tcp_dns_frame(&resp);
            if tokio::time::timeout(timeout_dur, client.write_all(&framed))
                .await
                .is_err()
            {
                break;
            }
            let _ = client.flush().await;
        }
        let _ = client.shutdown().await;
        Ok(())
    }

    /// Resolves a domain name directly to its real IPv4 address (bypassing Fake-IP and the OS stub resolver).
    pub async fn resolve_host_direct_ipv4(&self, domain: &str) -> RouteWardResult<Ipv4Addr> {
        if let Ok(ip) = domain.parse::<Ipv4Addr>() {
            return Ok(ip);
        }
        let ips = self.resolve_host_direct_ipv4_all(domain).await?;
        ips.into_iter()
            .next()
            .ok_or_else(|| RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!("Direct DNS resolution returned no A records for \"{domain}\""),
            })
    }

    /// Resolves a domain name directly to all `A` record IPv4 addresses returned by the direct resolver.
    pub async fn resolve_host_direct_ipv4_all(
        &self,
        domain: &str,
    ) -> RouteWardResult<Vec<Ipv4Addr>> {
        if let Ok(ip) = domain.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }
        let trimmed = domain.trim().trim_end_matches('.');
        if trimmed.eq_ignore_ascii_case("localhost") {
            return Ok(vec![Ipv4Addr::LOCALHOST]);
        }

        let query_id: u16 = 0x5257;
        let raw_query =
            build_a_query(query_id, trimmed).map_err(|e| RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: e.to_string(),
            })?;
        let parsed_q =
            parse_dns_query(&raw_query).map_err(|e| RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: e.to_string(),
            })?;

        let resolver_mode = if self.dns.is_bypassed(trimmed) {
            DnsResolverMode::BypassOnlySystem
        } else {
            DnsResolverMode::DirectPreferSystem
        };
        let resolvers = self.candidate_dns_resolvers(None, resolver_mode);
        let mut last_err = String::from("no direct DNS resolver reachable");
        for resolver_addr in resolvers {
            match self
                .forward_dns_query_direct(&raw_query, &parsed_q, resolver_addr, false)
                .await
            {
                Ok(resp_wire) => {
                    if let Ok(addrs) = extract_ipv4_answers(&resp_wire) {
                        if !addrs.is_empty() {
                            return Ok(addrs);
                        }
                    }
                    last_err = format!("no A records in response from {resolver_addr}");
                }
                Err(err) => {
                    last_err = err.to_string();
                }
            }
        }

        Err(RouteWardError::ProtocolHandshake {
            key: ERR_KEY_HANDSHAKE_FAILED,
            detail: format!("Direct DNS resolution failed for \"{trimmed}\": {last_err}"),
        })
    }

    async fn forward_dns_over_tcp_via_action(
        &self,
        raw_query: &[u8],
        query: &DnsQueryPacket,
        action: &RuleAction,
        resolver_addr: SocketAddr,
        is_udp: bool,
    ) -> RouteWardResult<Vec<u8>> {
        let timeout_dur = Duration::from_millis(self.constants.network.proxy_handshake_timeout_ms);
        let mut stream = self
            .open_outbound_stream(
                action,
                &resolver_addr.ip().to_string(),
                resolver_addr.port(),
            )
            .await?;

        let framed = encode_tcp_dns_frame(raw_query);
        tokio::time::timeout(timeout_dur, stream.write_all(&framed))
            .await
            .map_err(|_| {
                RouteWardError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DNS-over-TCP write timed out",
                ))
            })?
            .map_err(RouteWardError::Io)?;
        let _ = stream.flush().await;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                RouteWardError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DNS-over-TCP response header timed out",
                ))
            })?
            .map_err(RouteWardError::Io)?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > DNS_MAX_TCP_MESSAGE_BYTES {
            return Err(RouteWardError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid DNS-over-TCP response length",
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| {
                RouteWardError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DNS-over-TCP response body timed out",
                ))
            })?
            .map_err(RouteWardError::Io)?;
        let _ = stream.shutdown().await;

        rewrite_transaction_id(&mut resp_buf, query.id);
        if is_udp {
            Ok(enforce_udp_truncation(
                &resp_buf,
                query,
                query.max_udp_payload_bytes,
            ))
        } else {
            Ok(resp_buf)
        }
    }

    async fn forward_dns_query_direct(
        &self,
        raw_query: &[u8],
        query: &DnsQueryPacket,
        resolver_addr: SocketAddr,
        is_udp: bool,
    ) -> std::io::Result<Vec<u8>> {
        let timeout_dur = Duration::from_millis(
            self.constants
                .network
                .tcp_connect_timeout_ms
                .clamp(500, 2500),
        );

        if let Ok(udp_resp) = self
            .query_dns_udp_direct_protected(raw_query, resolver_addr, timeout_dur)
            .await
        {
            if let Ok(msg) = parse_dns_message(&udp_resp) {
                if !msg.is_truncated() {
                    let mut out = udp_resp;
                    rewrite_transaction_id(&mut out, query.id);
                    if is_udp {
                        return Ok(enforce_udp_truncation(
                            &out,
                            query,
                            query.max_udp_payload_bytes,
                        ));
                    }
                    return Ok(out);
                }
            }
        }

        // Fallback to direct DNS-over-TCP (e.g. if UDP was truncated with TC=1 or UDP failed)
        let mut tcp_resp = self
            .query_dns_tcp_direct_protected(raw_query, resolver_addr, timeout_dur)
            .await?;
        rewrite_transaction_id(&mut tcp_resp, query.id);
        if is_udp {
            Ok(enforce_udp_truncation(
                &tcp_resp,
                query,
                query.max_udp_payload_bytes,
            ))
        } else {
            Ok(tcp_resp)
        }
    }

    async fn query_dns_udp_direct_protected(
        &self,
        raw_query: &[u8],
        resolver_addr: SocketAddr,
        timeout_dur: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        std_sock.set_nonblocking(true)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let fwmark = self.constants.network.linux_fwmark;
            if fwmark != 0 {
                let fd = std_sock.as_raw_fd();
                let _ = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &fwmark as *const u32 as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                };
            }
        }

        let local_port = std_sock.local_addr()?.port();
        let _port_guard = self.nat_table.register_self_udp_port(local_port);

        let sock = UdpSocket::from_std(std_sock)?;
        tokio::time::timeout(timeout_dur, sock.send_to(raw_query, resolver_addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP DNS send timeout")
            })??;

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(timeout_dur, sock.recv_from(&mut buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP DNS recv timeout")
            })??;
        buf.truncate(len);
        Ok(buf)
    }

    async fn send_and_optional_recv_udp_direct_protected(
        &self,
        payload: &[u8],
        target_addr: SocketAddr,
        recv_timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        std_sock.set_nonblocking(true)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let fwmark = self.constants.network.linux_fwmark;
            if fwmark != 0 {
                let fd = std_sock.as_raw_fd();
                let _ = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &fwmark as *const u32 as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                };
            }
        }

        let local_port = std_sock.local_addr()?.port();
        let _port_guard = self.nat_table.register_self_udp_port(local_port);

        let sock = UdpSocket::from_std(std_sock)?;
        tokio::time::timeout(recv_timeout, sock.send_to(payload, target_addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP send timeout"))??;

        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(recv_timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                buf.truncate(len);
                Ok(buf)
            }
            _ => Ok(Vec::new()),
        }
    }

    async fn query_dns_tcp_direct_protected(
        &self,
        raw_query: &[u8],
        resolver_addr: SocketAddr,
        timeout_dur: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let mut stream = tokio::time::timeout(
            timeout_dur,
            self.connect_direct_tcp_protected(resolver_addr),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS connect timeout")
        })??;

        let framed = encode_tcp_dns_frame(raw_query);
        tokio::time::timeout(timeout_dur, stream.write_all(&framed))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS write timeout")
            })??;
        let _ = stream.flush().await;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS read len timeout")
            })??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > DNS_MAX_TCP_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid TCP DNS response length",
            ));
        }

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS read body timeout")
            })??;
        let _ = stream.shutdown().await;
        Ok(resp_buf)
    }

    async fn connect_direct_tcp_protected(&self, target: SocketAddr) -> std::io::Result<TcpStream> {
        #[cfg(target_os = "linux")]
        {
            ProxyConnector::connect_tcp_marked(
                &target.to_string(),
                self.constants.network.linux_fwmark,
            )
            .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let sock = match target {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
            };
            let bind_addr: SocketAddr = match target {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => {
                    SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
                }
            };
            sock.bind(bind_addr)?;
            let local_port = sock.local_addr()?.port();
            let _port_guard = self.nat_table.register_self_tcp_port(local_port);
            sock.connect(target).await
        }
    }

    fn lookup_udp_orig_dns_resolver(&self, peer_addr: SocketAddr) -> Option<SocketAddr> {
        self.lookup_udp_conntrack_orig_dst(peer_addr, &[self.constants.dns.dns_standard_port])
    }

    fn lookup_udp_conntrack_orig_dst(
        &self,
        peer_addr: SocketAddr,
        candidate_dports: &[u16],
    ) -> Option<SocketAddr> {
        #[cfg(target_os = "linux")]
        {
            let sport_tag = format!("sport={}", peer_addr.port());
            if let Ok(content) = std::fs::read_to_string("/proc/net/nf_conntrack") {
                for line in content.lines() {
                    if !line.contains("udp") || !line.contains(&sport_tag) {
                        continue;
                    }
                    for &dport in candidate_dports {
                        let dport_tag = format!("dport={dport}");
                        if line.contains(&dport_tag) {
                            for token in line.split_whitespace() {
                                if let Some(ip_str) = token.strip_prefix("dst=") {
                                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                        if !ip.is_loopback() {
                                            return Some(SocketAddr::new(IpAddr::V4(ip), dport));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let _ = (peer_addr, candidate_dports);
        None
    }

    fn candidate_dns_resolvers(
        &self,
        orig_resolver: Option<SocketAddr>,
        mode: DnsResolverMode,
    ) -> Vec<SocketAddr> {
        let sys_resolvers = if let Some(ref ov) = *self.system_resolvers_override.read() {
            ov.clone()
        } else {
            crate::dns::detect_system_dns_resolvers(&self.constants.dns)
        };
        self.candidate_dns_resolvers_with_system(orig_resolver, mode, &sys_resolvers)
    }

    fn candidate_dns_resolvers_with_system(
        &self,
        orig_resolver: Option<SocketAddr>,
        mode: DnsResolverMode,
        system_resolvers: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        let mut list = Vec::new();
        let dns_port = self.constants.dns.dns_standard_port;
        let local_dns_listen_port = self.constants.network.default_dns_listen_port;
        let configured_upstream = self.profile.read().dns_config.upstream_dns.clone();
        let default_upstream = &self.constants.dns.upstream_dns_server;

        let push_unique = |out: &mut Vec<SocketAddr>, addr: SocketAddr| {
            let is_safe_loopback = addr.ip().is_loopback()
                && addr.port() != dns_port
                && addr.port() != local_dns_listen_port;
            if (!addr.ip().is_loopback() || is_safe_loopback)
                && addr.ip() != IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                && !out.contains(&addr)
            {
                out.push(addr);
            }
        };

        let parse_host_port = |raw: &str| -> Option<SocketAddr> {
            if let Ok(sa) = raw.parse::<SocketAddr>() {
                return Some(sa);
            }
            if let Ok(ip) = raw.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, dns_port));
            }
            None
        };

        match mode {
            DnsResolverMode::BypassOnlySystem => {
                if let Some(orig) = orig_resolver {
                    push_unique(&mut list, orig);
                }
                if let Some(last_orig) = *self.last_seen_orig_resolver.read() {
                    push_unique(&mut list, last_orig);
                }
                for sa in system_resolvers {
                    push_unique(&mut list, *sa);
                }
            }
            DnsResolverMode::DirectPreferSystem => {
                if let Some(orig) = orig_resolver {
                    push_unique(&mut list, orig);
                }
                if let Some(last_orig) = *self.last_seen_orig_resolver.read() {
                    push_unique(&mut list, last_orig);
                }
                for sa in system_resolvers {
                    push_unique(&mut list, *sa);
                }
                if list.is_empty() {
                    if let Some(sa) = parse_host_port(&configured_upstream) {
                        push_unique(&mut list, sa);
                    }
                    if let Some(sa) = parse_host_port(default_upstream) {
                        push_unique(&mut list, sa);
                    }
                    if let Some(sa) = parse_host_port(&self.constants.dns.fallback_dns_server) {
                        push_unique(&mut list, sa);
                    }
                }
            }
            DnsResolverMode::RemoteViaProxy => {
                if configured_upstream != *default_upstream {
                    if let Some(sa) = parse_host_port(&configured_upstream) {
                        push_unique(&mut list, sa);
                    }
                }
                if let Some(orig) = orig_resolver {
                    push_unique(&mut list, orig);
                }
                if let Some(sa) = parse_host_port(&configured_upstream) {
                    push_unique(&mut list, sa);
                }
                if let Some(sa) = parse_host_port(default_upstream) {
                    push_unique(&mut list, sa);
                }
                if let Some(sa) = parse_host_port(&self.constants.dns.fallback_dns_server) {
                    push_unique(&mut list, sa);
                }
            }
        }

        list
    }

    fn format_action_label(&self, action: &RuleAction) -> String {
        let prof = self.profile.read();
        match action {
            RuleAction::Direct => ROUTE_DIRECT_LABEL.to_string(),
            RuleAction::Block => ROUTE_BLOCK_LABEL.to_string(),
            RuleAction::Proxy { target_id } => prof
                .proxies
                .iter()
                .find(|p| &p.id == target_id)
                .map(|p| format!("{} ({:?})", p.name, p.protocol))
                .unwrap_or_else(|| target_id.clone()),
            RuleAction::Chain { target_id } => prof
                .chains
                .iter()
                .find(|c| &c.id == target_id)
                .map(|c| format!("Chain: {} ({} hops)", c.name, c.proxy_ids.len()))
                .unwrap_or_else(|| target_id.clone()),
        }
    }

    pub fn detect_elevated_privileges() -> bool {
        #[cfg(windows)]
        {
            use std::ptr::null_mut;
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            use windows_sys::Win32::Security::{
                GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            unsafe {
                let mut token: HANDLE = null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return false;
                }
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut ret_len: u32 = 0;
                let ok = GetTokenInformation(
                    token,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut _,
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut ret_len,
                );
                let _ = CloseHandle(token);
                ok != 0 && elevation.TokenIsElevated != 0
            }
        }
        #[cfg(target_os = "linux")]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChainStrategy, ProxyChain, ProxyCredentials, ProxyNode, ProxyProtocol};
    use crate::interceptor::nat::{NatSessionEntry, PidResolutionSource};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    fn allocate_closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.local_addr().expect("local_addr").port()
    }

    fn make_proxy_node(
        id: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
    ) -> ProxyNode {
        let auth = match (username, password) {
            (Some(u), Some(p)) => Some(ProxyCredentials::new(u, p)),
            _ => None,
        };
        ProxyNode {
            id: id.to_string(),
            name: id.to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port,
            auth,
            udp_enabled: false,
            tls: false,
            sni: None,
            enabled: true,
            last_latency_ms: Some(15),
            exit_ip: None,
        }
    }

    async fn run_transparent_session(
        controller: &Arc<RouteWardController>,
        target_port: u16,
        action: RuleAction,
        rule_name: &str,
    ) -> (RouteWardResult<()>, Vec<u8>) {
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let relay_addr = relay_listener.local_addr().expect("relay_addr");

        let client_stream = TcpStream::connect(relay_addr)
            .await
            .expect("client connect");
        let peer_addr = client_stream.local_addr().expect("client local_addr");
        let (server_stream, accepted_peer) = relay_listener.accept().await.expect("accept");
        assert_eq!(peer_addr, accepted_peer);

        controller.nat_table.insert_session(NatSessionEntry {
            client_ip: Ipv4Addr::LOCALHOST,
            client_port: peer_addr.port(),
            orig_dst_ip: Ipv4Addr::LOCALHOST,
            orig_dst_port: target_port,
            pid: 4242,
            process_name: "curl.exe".to_string(),
            process_path: "C:\\Windows\\System32\\curl.exe".to_string(),
            resolution_source: PidResolutionSource::SocketLayer,
            action,
            matched_rule_name: rule_name.to_string(),
            created_at: Instant::now(),
        });

        let client_task = tokio::spawn(async move {
            let mut client = client_stream;
            let mut buf = Vec::new();
            let _ = client.read_to_end(&mut buf).await;
            buf
        });

        let res = controller
            .handle_transparent_tcp_client(server_stream, accepted_peer)
            .await;
        let received = client_task.await.expect("client_task join");
        (res, received)
    }

    #[tokio::test]
    async fn transparent_relay_rejects_and_logs_unknown_peer_connection() {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        let controller = RouteWardController::new(constants, profile, "en");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.expect("connect");
            let mut buf = [0u8; 8];
            client.read(&mut buf).await.expect("read EOF")
        });

        let (server_stream, peer_addr) = listener.accept().await.expect("accept");
        controller
            .handle_transparent_tcp_client(server_stream, peer_addr)
            .await
            .expect("handled");

        let bytes_read = client_task.await.expect("join");
        assert_eq!(bytes_read, 0);

        let logs = controller.telemetry.list_logs();
        assert!(logs.iter().any(|l| l.level == LogLevel::Warn
            && l.component == COMPONENT_TRANSPARENT
            && l.message.contains("Rejected unauthorized connection")));
    }

    #[tokio::test]
    async fn kill_switch_blocks_transparent_and_socks5_when_upstream_proxy_refused() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
        let target_port = target_listener.local_addr().expect("target_addr").port();
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let direct_hits_bg = direct_hits.clone();
        let _target_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = target_listener.accept().await {
                direct_hits_bg.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(b"DIRECT_HIT").await;
                let _ = stream.shutdown().await;
            }
        });

        let dead_port = allocate_closed_port();
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = true;
        profile.proxies = vec![make_proxy_node("proxy-dead", dead_port, None, None)];
        profile.rules.clear();
        profile.default_action = RuleAction::Proxy {
            target_id: "proxy-dead".to_string(),
        };

        let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

        // 1. Transparent TCP relay: connection refused must be blocked, never direct
        let (res, client_bytes) = run_transparent_session(
            &controller,
            target_port,
            RuleAction::Proxy {
                target_id: "proxy-dead".to_string(),
            },
            "Rule-Proxy-Dead",
        )
        .await;
        assert!(res.is_err());
        assert!(client_bytes.is_empty());
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

        let conns = controller.telemetry.list_connections();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].status, ConnectionStatus::Blocked);
        assert_eq!(conns[0].route_label, ROUTE_BLOCK_LABEL);
        assert_eq!(conns[0].matched_rule, "Rule-Proxy-Dead");

        let logs = controller.telemetry.list_logs();
        assert!(logs.iter().any(|l| l.level == LogLevel::Warn
            && l.component == COMPONENT_TRANSPARENT
            && l.message.contains("Kill-Switch blocked connection")));

        // 2. Local SOCKS5 relay: connection refused must receive SOCKS5 general failure reply and be blocked
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks");
        let socks_addr = socks_listener.local_addr().expect("socks_addr");

        let client_task = tokio::spawn(async move {
            let mut s = TcpStream::connect(socks_addr).await.expect("connect socks");
            s.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
            let mut method_reply = [0u8; 2];
            s.read_exact(&mut method_reply).await.expect("method reply");
            assert_eq!(method_reply, [0x05, 0x00]);

            let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
            req.extend_from_slice(&target_port.to_be_bytes());
            s.write_all(&req).await.expect("connect req");

            let mut reply = [0u8; 10];
            s.read_exact(&mut reply).await.expect("failure reply");
            reply
        });

        let (socks_server_stream, socks_peer) = socks_listener.accept().await.expect("accept");
        let socks_res = controller
            .handle_local_socks5_client(socks_server_stream, socks_peer.port())
            .await;
        assert!(socks_res.is_err());

        let reply = client_task.await.expect("socks client join");
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x01); // general SOCKS server failure
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

        let conns = controller.telemetry.list_connections();
        assert_eq!(conns.len(), 2);
        assert!(conns
            .iter()
            .all(|c| c.status == ConnectionStatus::Blocked && c.route_label == ROUTE_BLOCK_LABEL));
        let logs = controller.telemetry.list_logs();
        assert!(logs.iter().any(|l| l.level == LogLevel::Warn
            && l.component == COMPONENT_ENGINE
            && l.message
                .contains("Kill-Switch blocked local SOCKS5 connection")));
    }

    #[tokio::test]
    async fn kill_switch_blocks_on_upstream_timeout_and_auth_failure() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
        let target_port = target_listener.local_addr().expect("target_addr").port();
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let direct_hits_bg = direct_hits.clone();
        let _target_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = target_listener.accept().await {
                direct_hits_bg.fetch_add(1, Ordering::SeqCst);
                let _ = stream.shutdown().await;
            }
        });

        // Hanging proxy that accepts TCP but never responds to SOCKS5 greeting
        let hanging_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hanging");
        let hanging_port = hanging_listener.local_addr().expect("hanging_addr").port();
        let _hanging_task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = hanging_listener.accept().await {
                held.push(stream);
            }
        });

        // Auth-rejecting SOCKS5 proxy
        let auth_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind auth");
        let auth_port = auth_listener.local_addr().expect("auth_addr").port();
        let _auth_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = auth_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 16];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(&[0x05, 0x02]).await;
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(&[0x01, 0x01]).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        constants.network.proxy_handshake_timeout_ms = 120;
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = true;
        profile.proxies = vec![
            make_proxy_node("proxy-timeout", hanging_port, None, None),
            make_proxy_node("proxy-bad-auth", auth_port, Some("user"), Some("wrong")),
        ];

        let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

        let (timeout_res, _) = run_transparent_session(
            &controller,
            target_port,
            RuleAction::Proxy {
                target_id: "proxy-timeout".to_string(),
            },
            "Rule-Proxy-Timeout",
        )
        .await;
        assert!(timeout_res.is_err());

        let (auth_res, _) = run_transparent_session(
            &controller,
            target_port,
            RuleAction::Proxy {
                target_id: "proxy-bad-auth".to_string(),
            },
            "Rule-Proxy-Auth",
        )
        .await;
        assert!(auth_res.is_err());

        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        let conns = controller.telemetry.list_connections();
        assert_eq!(conns.len(), 2);
        assert!(conns
            .iter()
            .all(|c| c.status == ConnectionStatus::Blocked && c.route_label == ROUTE_BLOCK_LABEL));
    }

    #[tokio::test]
    async fn kill_switch_blocks_broken_chain_and_all_down_groups_but_allows_healthy_group_failover()
    {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
        let target_port = target_listener.local_addr().expect("target_addr").port();
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let direct_hits_bg = direct_hits.clone();
        let _target_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = target_listener.accept().await {
                direct_hits_bg.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(b"DIRECT_LEAK").await;
                let _ = stream.shutdown().await;
            }
        });

        // Healthy SOCKS5 proxy that replies with "PROXIED_OK" when connecting to target_port,
        // or fails SOCKS5 CONNECT if asked to chain to a dead hop.
        let healthy_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind healthy");
        let healthy_port = healthy_listener.local_addr().expect("healthy_addr").port();
        let proxy_hits = Arc::new(AtomicUsize::new(0));
        let proxy_hits_bg = proxy_hits.clone();
        let _healthy_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = healthy_listener.accept().await {
                let proxy_hits_inner = proxy_hits_bg.clone();
                tokio::spawn(async move {
                    let mut greet = [0u8; 3];
                    if stream.read_exact(&mut greet).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&[0x05, 0x00]).await;

                    let mut hdr = [0u8; 4];
                    if stream.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let dst_port = match hdr[3] {
                        0x01 => {
                            let mut addr_port = [0u8; 6];
                            let _ = stream.read_exact(&mut addr_port).await;
                            u16::from_be_bytes([addr_port[4], addr_port[5]])
                        }
                        0x03 => {
                            let mut len = [0u8; 1];
                            let _ = stream.read_exact(&mut len).await;
                            let mut dom_port = vec![0u8; (len[0] as usize) + 2];
                            let _ = stream.read_exact(&mut dom_port).await;
                            u16::from_be_bytes([
                                dom_port[dom_port.len() - 2],
                                dom_port[dom_port.len() - 1],
                            ])
                        }
                        _ => return,
                    };

                    if dst_port == target_port {
                        proxy_hits_inner.fetch_add(1, Ordering::SeqCst);
                        let _ = stream
                            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                            .await;
                        let _ = stream.write_all(b"PROXIED_OK").await;
                        let _ = stream.shutdown().await;
                    } else {
                        // Next hop in chain is unreachable
                        let _ = stream
                            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                        let _ = stream.shutdown().await;
                    }
                });
            }
        });

        let dead_port_1 = allocate_closed_port();
        let dead_port_2 = allocate_closed_port();

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = true;
        profile.proxies = vec![
            make_proxy_node("proxy-dead-1", dead_port_1, None, None),
            make_proxy_node("proxy-dead-2", dead_port_2, None, None),
            make_proxy_node("proxy-healthy", healthy_port, None, None),
        ];
        profile.chains = vec![
            ProxyChain {
                id: "chain-seq-broken".to_string(),
                name: "Broken Sequence Chain".to_string(),
                strategy: ChainStrategy::Sequence,
                proxy_ids: vec!["proxy-healthy".to_string(), "proxy-dead-1".to_string()],
                enabled: true,
            },
            ProxyChain {
                id: "group-failover-recover".to_string(),
                name: "Failover Group With Healthy Secondary".to_string(),
                strategy: ChainStrategy::Failover,
                proxy_ids: vec!["proxy-dead-1".to_string(), "proxy-healthy".to_string()],
                enabled: true,
            },
            ProxyChain {
                id: "group-failover-all-down".to_string(),
                name: "Failover Group All Down".to_string(),
                strategy: ChainStrategy::Failover,
                proxy_ids: vec!["proxy-dead-1".to_string(), "proxy-dead-2".to_string()],
                enabled: true,
            },
            ProxyChain {
                id: "group-lowest-latency-all-down".to_string(),
                name: "LowestLatency Group All Down".to_string(),
                strategy: ChainStrategy::LowestLatency,
                proxy_ids: vec!["proxy-dead-1".to_string(), "proxy-dead-2".to_string()],
                enabled: true,
            },
        ];

        let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

        // 1. Sequence chain where hop 2 is down -> Blocked, 0 direct hits
        let (seq_res, seq_bytes) = run_transparent_session(
            &controller,
            target_port,
            RuleAction::Chain {
                target_id: "chain-seq-broken".to_string(),
            },
            "Rule-Broken-Seq",
        )
        .await;
        assert!(seq_res.is_err());
        assert!(seq_bytes.is_empty());

        // 2. Failover group where node 1 is down and node 2 is healthy -> Succeeds via node 2, 0 direct hits
        let (fo_ok_res, fo_ok_bytes) = run_transparent_session(
            &controller,
            target_port,
            RuleAction::Chain {
                target_id: "group-failover-recover".to_string(),
            },
            "Rule-Failover-Recover",
        )
        .await;
        assert!(fo_ok_res.is_ok());
        assert_eq!(fo_ok_bytes, b"PROXIED_OK");
        assert_eq!(proxy_hits.load(Ordering::SeqCst), 1);

        // 3. Failover group where all nodes are down -> Blocked, 0 direct hits
        let (fo_down_res, fo_down_bytes) = run_transparent_session(
            &controller,
            target_port,
            RuleAction::Chain {
                target_id: "group-failover-all-down".to_string(),
            },
            "Rule-Failover-All-Down",
        )
        .await;
        assert!(fo_down_res.is_err());
        assert!(fo_down_bytes.is_empty());

        // 4. LowestLatency group where all nodes are down -> Blocked, 0 direct hits
        let (ll_down_res, ll_down_bytes) = run_transparent_session(
            &controller,
            target_port,
            RuleAction::Chain {
                target_id: "group-lowest-latency-all-down".to_string(),
            },
            "Rule-LowestLatency-All-Down",
        )
        .await;
        assert!(ll_down_res.is_err());
        assert!(ll_down_bytes.is_empty());

        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);

        let conns = controller.telemetry.list_connections();
        let blocked: Vec<_> = conns
            .iter()
            .filter(|c| c.status == ConnectionStatus::Blocked)
            .collect();
        assert_eq!(blocked.len(), 3);
        assert!(blocked.iter().all(|c| c.route_label == ROUTE_BLOCK_LABEL));
    }

    #[tokio::test]
    async fn kill_switch_disabled_explicitly_falls_back_to_direct_with_warning() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
        let target_port = target_listener.local_addr().expect("target_addr").port();
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let direct_hits_bg = direct_hits.clone();
        let _target_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = target_listener.accept().await {
                direct_hits_bg.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(b"DIRECT_FALLBACK_OK").await;
                let _ = stream.shutdown().await;
            }
        });

        let dead_port = allocate_closed_port();
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = false;
        profile.proxies = vec![make_proxy_node("proxy-dead", dead_port, None, None)];

        let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

        let (res, received) = run_transparent_session(
            &controller,
            target_port,
            RuleAction::Proxy {
                target_id: "proxy-dead".to_string(),
            },
            "Rule-Proxy-Fallback",
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(received, b"DIRECT_FALLBACK_OK");
        assert_eq!(direct_hits.load(Ordering::SeqCst), 1);

        let conns = controller.telemetry.list_connections();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].route_label, ROUTE_DIRECT_LABEL);

        let logs = controller.telemetry.list_logs();
        assert!(logs.iter().any(|l| l.level == LogLevel::Warn
            && l.message
                .contains("falling back to DIRECT because killSwitchEnabled=false")));
    }

    #[test]
    fn controller_starts_with_empty_fake_ip_cache_and_saves_profile() {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        let controller = RouteWardController::new(constants, profile, "en");

        // No simulated Fake-IP entries or connections are seeded at startup
        assert!(controller.dns.list_entries().is_empty());
        assert!(controller.telemetry.list_connections().is_empty());

        let temp_path =
            std::env::temp_dir().join(format!("routeward_ctrl_prof_{}.json", Uuid::new_v4()));
        controller
            .save_profile_to_path(&temp_path)
            .expect("controller atomic profile save");
        assert!(temp_path.exists());
        #[cfg(windows)]
        let _ = crate::config::security::apply_windows_sddl_dacl(&temp_path, "D:(A;;FA;;;WD)");
        let _ = std::fs::remove_file(&temp_path);
    }

    #[test]
    fn expired_pending_syn_dropped_with_info_counter_when_kill_switch_enabled_and_reinjected_with_warn_when_disabled(
    ) {
        use crate::interceptor::nat::Ipv4TcpPacketMeta;

        let syn_meta = Ipv4TcpPacketMeta {
            ip_header_len: 20,
            total_len: 40,
            src_ip: Ipv4Addr::new(10, 0, 0, 5),
            dst_ip: Ipv4Addr::new(93, 184, 216, 34),
            src_port: 51111,
            dst_port: 443,
            tcp_flags: 0x02,
        };

        // 1. Kill switch enabled -> timed-out SYN is dropped (never reinjected), counter incremented, INFO log emitted
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile_ks_on = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile_ks_on.enable_logging = false;
        profile_ks_on.security_policy.kill_switch_enabled = true;
        let ctrl_ks_on = RouteWardController::new(constants.clone(), profile_ks_on, "en");

        let queue_on = PendingSynQueue::new();
        queue_on.enqueue(vec![0x45, 0x00, 0x00, 0x28], syn_meta);

        let outcomes_on = ctrl_ks_on.poll_pending_syns(&queue_on, Duration::ZERO, |_| None);
        assert_eq!(outcomes_on.len(), 1);
        assert!(matches!(
            outcomes_on[0],
            PendingSynOutcome::TimedOutDropped { drop_count: 1, .. }
        ));
        assert_eq!(ctrl_ks_on.nat_table.dropped_unattributed_syn_count(), 1);
        assert_eq!(ctrl_ks_on.nat_table.reinjected_unattributed_syn_count(), 0);

        let logs_on = ctrl_ks_on.telemetry.list_logs();
        assert!(logs_on.iter().any(|l| l.level == LogLevel::Info
            && l.component == COMPONENT_WINDIVERT
            && l.message.contains("Dropped unattributed Pending SYN #1")
            && l.message.contains("killSwitchEnabled=true")));

        // 2. Kill switch disabled -> timed-out SYN is reinjected, counter incremented, WARN log emitted
        let mut profile_ks_off = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile_ks_off.enable_logging = false;
        profile_ks_off.security_policy.kill_switch_enabled = false;
        let ctrl_ks_off = RouteWardController::new(constants, profile_ks_off, "en");

        let queue_off = PendingSynQueue::new();
        queue_off.enqueue(vec![0x45, 0x00, 0x00, 0x28], syn_meta);

        let outcomes_off = ctrl_ks_off.poll_pending_syns(&queue_off, Duration::ZERO, |_| None);
        assert_eq!(outcomes_off.len(), 1);
        assert!(matches!(
            outcomes_off[0],
            PendingSynOutcome::TimedOutReinject {
                reinject_count: 1,
                ..
            }
        ));
        assert_eq!(ctrl_ks_off.nat_table.dropped_unattributed_syn_count(), 0);
        assert_eq!(ctrl_ks_off.nat_table.reinjected_unattributed_syn_count(), 1);

        let logs_off = ctrl_ks_off.telemetry.list_logs();
        assert!(logs_off.iter().any(|l| l.level == LogLevel::Warn
            && l.component == COMPONENT_WINDIVERT
            && l.message.contains("Released unattributed Pending SYN #1")
            && l.message.contains("killSwitchEnabled=false")));
    }

    #[test]
    fn unknown_process_attribution_enforces_block_and_warns_with_kill_switch_and_defaults_to_block()
    {
        use crate::config::SecurityPolicyConfig;
        use crate::process::ProcessIdentity;

        // 1. Verify default_profile.json and SecurityPolicyConfig::default() default to Block
        let embedded_profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        assert_eq!(
            embedded_profile.security_policy.unknown_process_action,
            RuleAction::Block
        );
        assert_eq!(
            SecurityPolicyConfig::default().unknown_process_action,
            RuleAction::Block
        );

        // 2. When killSwitchEnabled = true and unknownProcessAction = Direct, override to Block with WARN
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = embedded_profile.clone();
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = true;
        profile.security_policy.unknown_process_action = RuleAction::Direct;
        let ctrl_ks_on = RouteWardController::new(constants.clone(), profile, "en");

        let (pid, proc_name, _, action, rule_name, _, source) = ctrl_ks_on
            .attribute_or_apply_unknown_policy(
                ProcessAttribution::Unknown {
                    reason: "socket closed before procfs scan".to_string(),
                },
                54321,
                "93.184.216.34",
                443,
                Some(&Ipv4Addr::new(93, 184, 216, 34)),
            );
        assert_eq!(pid, 0);
        assert_eq!(proc_name, "unknown");
        assert_eq!(action, RuleAction::Block);
        assert_eq!(
            rule_name,
            "SecurityPolicy:unknownProcessAction(KillSwitchOverride)"
        );
        assert_eq!(source, "procfs_unknown");

        let logs = ctrl_ks_on.telemetry.list_logs();
        assert!(logs.iter().any(|l| l.level == LogLevel::Warn
            && l.component == COMPONENT_TRANSPARENT
            && l.message
                .contains("overriding unknownProcessAction=Direct to Block")));

        // 3. Synthetic "pid:<n>" fallback identity is also treated as unattributed and blocked
        let (pid2, _, _, action2, _, _, source2) = ctrl_ks_on.attribute_or_apply_unknown_policy(
            ProcessAttribution::Single(ProcessIdentity {
                pid: 9999,
                name: "pid:9999".to_string(),
                executable_path: "pid:9999".to_string(),
            }),
            54322,
            "93.184.216.34",
            443,
            None,
        );
        assert_eq!(pid2, 9999);
        assert_eq!(action2, RuleAction::Block);
        assert_eq!(source2, "procfs_unknown");

        // 4. When killSwitchEnabled = false and unknownProcessAction = Direct, honors Direct and logs WARN
        let mut profile_ks_off = embedded_profile;
        profile_ks_off.enable_logging = false;
        profile_ks_off.security_policy.kill_switch_enabled = false;
        profile_ks_off.security_policy.unknown_process_action = RuleAction::Direct;
        let ctrl_ks_off = RouteWardController::new(constants, profile_ks_off, "en");

        let (_, _, _, action_off, rule_off, _, _) = ctrl_ks_off.attribute_or_apply_unknown_policy(
            ProcessAttribution::Unknown {
                reason: "ephemeral socket closed".to_string(),
            },
            54323,
            "93.184.216.34",
            443,
            None,
        );
        assert_eq!(action_off, RuleAction::Direct);
        assert_eq!(rule_off, "SecurityPolicy:unknownProcessAction");
    }

    #[test]
    fn unmapped_fake_ip_in_cidr_is_blocked_and_never_leaks_direct() {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.default_action = RuleAction::Direct;
        let controller = RouteWardController::new(constants, profile, "en");

        // Unallocated IP inside 198.18.0.0/15 Fake-IP pool must be blocked
        let eval = controller.evaluate_rule(&ConnectionRequest {
            process_name: "curl.exe".to_string(),
            process_path: Some("C:\\Windows\\System32\\curl.exe".to_string()),
            target_host: "198.18.9.99".to_string(),
            target_ip: Some("198.18.9.99".to_string()),
            target_port: 443,
            protocol: TransportProtocol::Tcp,
        });
        assert_eq!(eval.action, RuleAction::Block);
        assert_eq!(eval.matched_rule_name, "FakeIP:UnmappedOrExpired");

        let logs = controller.telemetry.list_logs();
        assert!(logs.iter().any(|l| l.level == LogLevel::Warn
            && l.message
                .contains("Blocked connection to unmapped or expired Fake-IP 198.18.9.99:443")));
    }

    #[test]
    fn dns_fake_ip_a_5s_ttl_aaaa_nodata_canary_nxdomain_and_no_info_log() {
        use crate::dns::codec::{
            build_query, extract_ipv4_answers, parse_dns_message, QTYPE_A, QTYPE_AAAA, QTYPE_PTR,
            RCODE_NOERROR, RCODE_NXDOMAIN,
        };

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.dns_config.enable_fake_ip = true;
        profile.security_policy.block_encrypted_dns_bypass = true;
        let controller = RouteWardController::new(constants, profile, "en");

        // 1. A query -> Fake-IP in 198.18.0.0/15 with 5s OS wire TTL, 300s internal TTL
        let raw_a = build_query(0x1111, "app.routeward.test", QTYPE_A).expect("build A query");
        let resp_a = controller
            .resolve_dns_query_fast(&raw_a)
            .expect("fast Fake-IP A response");
        let msg_a = parse_dns_message(&resp_a).expect("parse A response");
        assert_eq!(msg_a.rcode(), RCODE_NOERROR);
        assert_eq!(msg_a.answers.len(), 1);
        let ips = extract_ipv4_answers(&resp_a).expect("extract A IPv4");
        assert_eq!(ips.len(), 1);
        let fake_ip = ips[0];
        assert!(controller.dns.is_in_fake_subnet(&fake_ip));
        assert_eq!(msg_a.answers[0].ttl, 5, "OS wire TTL must be 5 seconds");
        let internal_entries = controller.dns.list_entries();
        assert_eq!(internal_entries.len(), 1);
        assert!(
            internal_entries[0].ttl_remaining_seconds > 290,
            "Internal Fake-IP table TTL must remain ~300s"
        );

        // 2. AAAA query -> NODATA (RCODE=0, ANCOUNT=0)
        let raw_aaaa =
            build_query(0x2222, "app.routeward.test", QTYPE_AAAA).expect("build AAAA query");
        let resp_aaaa = controller
            .resolve_dns_query_fast(&raw_aaaa)
            .expect("fast Fake-IP AAAA response");
        let msg_aaaa = parse_dns_message(&resp_aaaa).expect("parse AAAA response");
        assert_eq!(msg_aaaa.rcode(), RCODE_NOERROR);
        assert!(msg_aaaa.answers.is_empty());

        // 3. PTR query for the Fake-IP -> returns domain
        let octs = fake_ip.octets();
        let ptr_name = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octs[3], octs[2], octs[1], octs[0]
        );
        let raw_ptr = build_query(0x3333, &ptr_name, QTYPE_PTR).expect("build PTR query");
        let resp_ptr = controller
            .resolve_dns_query_fast(&raw_ptr)
            .expect("fast Fake-IP PTR response");
        let msg_ptr = parse_dns_message(&resp_ptr).expect("parse PTR response");
        assert_eq!(msg_ptr.rcode(), RCODE_NOERROR);
        assert_eq!(msg_ptr.answers.len(), 1);

        // Ordinary DNS queries must NEVER emit INFO/WARN/ERROR logs for DnsEngine
        let logs_after_ordinary = controller.telemetry.list_logs();
        assert!(
            !logs_after_ordinary
                .iter()
                .any(|l| l.component == COMPONENT_DNS),
            "Ordinary DNS queries must not emit INFO/WARN/ERROR telemetry logs, got: {:?}",
            logs_after_ordinary
        );

        // 4. DoH canary query (use-application-dns.net) -> NXDOMAIN + WARN log
        let raw_canary =
            build_query(0x4444, "use-application-dns.net", QTYPE_A).expect("build canary query");
        let resp_canary = controller
            .resolve_dns_query_fast(&raw_canary)
            .expect("fast canary response");
        let msg_canary = parse_dns_message(&resp_canary).expect("parse canary response");
        assert_eq!(msg_canary.rcode(), RCODE_NXDOMAIN);
        assert!(msg_canary.answers.is_empty());

        let logs_after_canary = controller.telemetry.list_logs();
        assert!(logs_after_canary.iter().any(|l| l.level == LogLevel::Warn
            && l.component == COMPONENT_DNS
            && l.message.contains("Blocked DoH canary DNS query")));
    }

    #[tokio::test]
    async fn dns_real_resolution_over_tcp_via_socks5_and_strict_servfail_when_proxy_down() {
        use crate::dns::codec::{
            build_a_query, build_a_response, encode_tcp_dns_frame, extract_ipv4_answers,
            parse_dns_message, parse_dns_query, RCODE_NOERROR, RCODE_SERVFAIL,
        };

        // Direct DNS trap server to verify 0 direct cleartext hits when proxy is used or down
        let direct_trap_udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind trap udp");
        let direct_trap_addr = direct_trap_udp.local_addr().expect("trap addr");
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let direct_hits_bg = direct_hits.clone();
        let _trap_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((_, _)) = direct_trap_udp.recv_from(&mut buf).await {
                direct_hits_bg.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Mock SOCKS5 server that speaks DNS-over-TCP once connected to the upstream DNS target
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks5");
        let socks_port = socks_listener.local_addr().expect("socks addr").port();
        let proxy_dns_hits = Arc::new(AtomicUsize::new(0));
        let proxy_dns_hits_bg = proxy_dns_hits.clone();
        let _socks_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = socks_listener.accept().await {
                let hits = proxy_dns_hits_bg.clone();
                tokio::spawn(async move {
                    let mut greet = [0u8; 3];
                    if stream.read_exact(&mut greet).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&[0x05, 0x00]).await;

                    let mut hdr = [0u8; 4];
                    if stream.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    match hdr[3] {
                        0x01 => {
                            let mut addr_port = [0u8; 6];
                            let _ = stream.read_exact(&mut addr_port).await;
                        }
                        0x03 => {
                            let mut len = [0u8; 1];
                            let _ = stream.read_exact(&mut len).await;
                            let mut dom_port = vec![0u8; (len[0] as usize) + 2];
                            let _ = stream.read_exact(&mut dom_port).await;
                        }
                        _ => return,
                    }
                    let _ = stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 53])
                        .await;

                    // Read DNS-over-TCP frame
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let qlen = u16::from_be_bytes(len_buf) as usize;
                    let mut qbuf = vec![0u8; qlen];
                    if stream.read_exact(&mut qbuf).await.is_err() {
                        return;
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    if let Ok(parsed_q) = parse_dns_query(&qbuf) {
                        let resp = build_a_response(&parsed_q, Ipv4Addr::new(203, 0, 113, 77), 60);
                        let framed = encode_tcp_dns_frame(&resp);
                        let _ = stream.write_all(&framed).await;
                        let _ = stream.flush().await;
                    }
                });
            }
        });

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.dns_config.enable_fake_ip = false;
        profile.dns_config.remote_dns_resolution = true;
        profile.dns_config.upstream_dns = direct_trap_addr.to_string();
        profile.security_policy.strict_dns_no_local_fallback = true;
        profile.security_policy.kill_switch_enabled = true;
        profile.proxies = vec![make_proxy_node("socks-dns", socks_port, None, None)];
        profile.default_action = RuleAction::Proxy {
            target_id: "socks-dns".to_string(),
        };

        let controller = RouteWardController::new(constants.clone(), profile.clone(), "en");
        let raw_query = build_a_query(0x7777, "real.routeward.test").expect("build query");
        let resp_wire = controller
            .resolve_dns_query_async(&raw_query, Some(direct_trap_addr), true)
            .await;
        let msg = parse_dns_message(&resp_wire).expect("parse DNS response");
        assert_eq!(msg.rcode(), RCODE_NOERROR);
        let answers = extract_ipv4_answers(&resp_wire).expect("extract A answers");
        assert_eq!(answers, vec![Ipv4Addr::new(203, 0, 113, 77)]);
        assert_eq!(proxy_dns_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            direct_hits.load(Ordering::SeqCst),
            0,
            "Zero direct cleartext DNS queries allowed"
        );

        // Now test with an unreachable proxy: must return SERVFAIL and never touch direct_trap_udp
        let dead_port = allocate_closed_port();
        profile.proxies = vec![make_proxy_node("socks-dead", dead_port, None, None)];
        profile.default_action = RuleAction::Proxy {
            target_id: "socks-dead".to_string(),
        };
        let controller_dead = RouteWardController::new(constants, profile, "en");
        let resp_fail = controller_dead
            .resolve_dns_query_async(&raw_query, Some(direct_trap_addr), true)
            .await;
        let msg_fail = parse_dns_message(&resp_fail).expect("parse SERVFAIL response");
        assert_eq!(msg_fail.rcode(), RCODE_SERVFAIL);
        assert_eq!(
            direct_hits.load(Ordering::SeqCst),
            0,
            "Strict DNS no-fallback must never fall back to cleartext DNS when proxy fails"
        );
        let warn_logs = controller_dead.telemetry.list_logs();
        assert!(warn_logs.iter().any(|l| l.level == LogLevel::Warn
            && l.component == COMPONENT_DNS
            && l.message
                .contains("returning SERVFAIL without cleartext fallback")));
    }

    #[tokio::test]
    async fn dns_bypass_domain_and_bootstrap_proxy_hostname_resolved_directly() {
        use crate::dns::codec::{
            build_a_query, build_a_response, extract_ipv4_answers, parse_dns_message,
            parse_dns_query, RCODE_NOERROR,
        };

        // Mock direct UDP DNS server responding for AD bypass domain and proxy bootstrap host
        let mock_dns_udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind mock dns udp");
        let mock_dns_addr = mock_dns_udp.local_addr().expect("mock dns addr");
        let _dns_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = mock_dns_udp.recv_from(&mut buf).await {
                if let Ok(q) = parse_dns_query(&buf[..len]) {
                    let ip = if q.question.qname == "dc01.corp.contoso.com" {
                        Ipv4Addr::new(10, 10, 1, 5)
                    } else if q.question.qname == "proxy.internal.test" {
                        Ipv4Addr::new(10, 10, 99, 88)
                    } else {
                        Ipv4Addr::new(192, 0, 2, 1)
                    };
                    let resp = build_a_response(&q, ip, 120);
                    let _ = mock_dns_udp.send_to(&resp, peer).await;
                }
            }
        });

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.dns_config.enable_fake_ip = true;
        profile.dns_config.upstream_dns = mock_dns_addr.to_string();
        profile.dns_config.bypass_domains = vec!["corp.contoso.com".to_string()];

        let mut domain_proxy = make_proxy_node("proxy-by-domain", 1080, None, None);
        domain_proxy.host = "proxy.internal.test".to_string();
        profile.proxies = vec![domain_proxy];

        let controller = RouteWardController::new(constants, profile, "en");

        // 1. Bypassed AD domain resolves directly to 10.10.1.5 (not a Fake-IP)
        let raw_bypass =
            build_a_query(0x8888, "dc01.corp.contoso.com").expect("build bypass query");
        assert!(
            controller.resolve_dns_query_fast(&raw_bypass).is_none(),
            "Bypassed domain must not be answered by Fake-IP fast path"
        );
        let resp_bypass = controller
            .resolve_dns_query_async(&raw_bypass, Some(mock_dns_addr), true)
            .await;
        let msg_bypass = parse_dns_message(&resp_bypass).expect("parse bypass response");
        assert_eq!(msg_bypass.rcode(), RCODE_NOERROR);
        let bypass_ips = extract_ipv4_answers(&resp_bypass).expect("extract bypass IP");
        assert_eq!(bypass_ips, vec![Ipv4Addr::new(10, 10, 1, 5)]);

        // 2. Bootstrap resolution of domain-named proxy populates anti-loop upstream_endpoints
        controller.bootstrap_resolve_proxy_hosts().await;
        let endpoints = controller.nat_table.upstream_endpoints();
        assert!(
            endpoints.contains(&(Ipv4Addr::new(10, 10, 99, 88), 1080)),
            "Bootstrap proxy resolution must register (10.10.99.88, 1080) in nat_table.upstream_endpoints, got {:?}",
            endpoints
        );
    }

    #[tokio::test]
    async fn bypassed_domains_never_query_public_upstream_and_return_servfail_when_internal_dns_silent(
    ) {
        use crate::dns::codec::{build_a_query, parse_dns_message, RCODE_SERVFAIL};

        // Simulated public upstream DNS trap server — must receive 0 queries for bypassed domains
        let public_trap_udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind public trap udp");
        let public_trap_addr = public_trap_udp.local_addr().expect("public trap addr");
        let public_hits = Arc::new(AtomicUsize::new(0));
        let public_hits_bg = public_hits.clone();
        let _trap_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((_, _)) = public_trap_udp.recv_from(&mut buf).await {
                public_hits_bg.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Silent / unreachable internal resolver
        let silent_internal_port = allocate_closed_port();
        let silent_internal_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), silent_internal_port);

        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        constants.network.tcp_connect_timeout_ms = 500;
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.dns_config.enable_fake_ip = true;
        profile.dns_config.upstream_dns = public_trap_addr.to_string();
        profile.dns_config.bypass_domains = vec!["corp.contoso.com".to_string()];

        let controller = RouteWardController::new(constants, profile, "en");
        *controller.system_resolvers_override.write() = Some(vec![silent_internal_addr]);

        // Verify candidate_dns_resolvers_with_system for BypassOnlySystem never includes public upstreams
        let candidates = controller.candidate_dns_resolvers_with_system(
            Some(silent_internal_addr),
            DnsResolverMode::BypassOnlySystem,
            &[],
        );
        assert_eq!(candidates, vec![silent_internal_addr]);
        assert!(!candidates.contains(&public_trap_addr));

        for bypassed_name in [
            "dc01.corp.contoso.com",
            "printer.local",
            "dc01",
            "1.0.0.10.in-addr.arpa",
        ] {
            let raw_q = build_a_query(0x9001, bypassed_name).expect("build query");
            let resp = controller
                .resolve_dns_query_async(&raw_q, Some(silent_internal_addr), true)
                .await;
            let msg = parse_dns_message(&resp).expect("parse SERVFAIL response");
            assert_eq!(
                msg.rcode(),
                RCODE_SERVFAIL,
                "Bypassed domain {bypassed_name} must return SERVFAIL when internal DNS is silent"
            );
        }

        assert_eq!(
            public_hits.load(Ordering::SeqCst),
            0,
            "Bypassed domains must NEVER query public upstreamDns"
        );
    }

    #[test]
    fn direct_flow_resolution_prefers_system_and_last_orig_resolver_before_upstream_dns() {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        let upstream_addr: SocketAddr = "198.51.100.53:53".parse().unwrap();
        profile.dns_config.upstream_dns = upstream_addr.to_string();

        let controller = RouteWardController::new(constants, profile, "en");
        let sys_ip = Ipv4Addr::new(10, 20, 30, 40);
        let sys_sock = SocketAddr::new(IpAddr::V4(sys_ip), 53);
        let orig_sock: SocketAddr = "10.20.30.1:53".parse().unwrap();

        controller.record_orig_dns_resolver(orig_sock);

        // When system resolvers or last_seen_orig_resolver exist, DirectPreferSystem uses them and NOT upstreamDns
        let direct_list = controller.candidate_dns_resolvers_with_system(
            None,
            DnsResolverMode::DirectPreferSystem,
            &[sys_sock],
        );
        assert_eq!(direct_list, vec![orig_sock, sys_sock]);
        assert!(!direct_list.contains(&upstream_addr));

        // When no orig_resolver, no last_seen_orig_resolver, and no system resolvers exist:
        // DirectPreferSystem falls back to upstreamDns, whereas BypassOnlySystem stays empty.
        *controller.last_seen_orig_resolver.write() = None;
        let direct_fallback = controller.candidate_dns_resolvers_with_system(
            None,
            DnsResolverMode::DirectPreferSystem,
            &[],
        );
        assert!(direct_fallback.contains(&upstream_addr));

        let bypass_empty = controller.candidate_dns_resolvers_with_system(
            None,
            DnsResolverMode::BypassOnlySystem,
            &[],
        );
        assert!(bypass_empty.is_empty());
    }

    fn build_sample_tls_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        // server_name extension payload: list_len(2) + name_type(1=0) + host_len(2) + host
        let mut sni_ext_data = Vec::new();
        let list_len = (1 + 2 + sni_bytes.len()) as u16;
        sni_ext_data.extend_from_slice(&list_len.to_be_bytes());
        sni_ext_data.push(0x00); // host_name type
        sni_ext_data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(sni_bytes);

        // Extension header: type(2=0x0000) + len(2) + data
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_data);

        // ClientHello body: client_version(2) + random(32) + session_id_len(1=0)
        // + cipher_suites_len(2=2) + cipher_suite(2) + comp_methods_len(1=1) + comp_method(1=0)
        // + extensions_len(2) + extensions
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        ch_body.extend_from_slice(&[0x11; 32]); // Random
        ch_body.push(0x00); // Session ID len = 0
        ch_body.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len = 2
        ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch_body.push(0x01); // Compression methods len = 1
        ch_body.push(0x00); // null compression
        ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&extensions);

        // Handshake message: msg_type(1=1 ClientHello) + len(3) + ch_body
        let ch_len = ch_body.len();
        let mut handshake = vec![
            0x01,
            ((ch_len >> 16) & 0xFF) as u8,
            ((ch_len >> 8) & 0xFF) as u8,
            (ch_len & 0xFF) as u8,
        ];
        handshake.extend_from_slice(&ch_body);

        // TLS record: content_type(1=22 Handshake) + version(2=0x0301) + len(2) + handshake
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[tokio::test]
    async fn transparent_relay_extracts_tls_sni_on_port_443_and_routes_literal_ip_via_socks5() {
        use crate::config::RoutingRule;

        let client_hello = build_sample_tls_client_hello("sni.routeward.test");
        let expected_hello_len = client_hello.len();

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks5");
        let socks_port = socks_listener.local_addr().expect("socks addr").port();
        let observed_domain = Arc::new(RwLock::new(String::new()));
        let observed_domain_bg = observed_domain.clone();
        let observed_hello_len = Arc::new(AtomicUsize::new(0));
        let observed_hello_len_bg = observed_hello_len.clone();

        let _socks_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = socks_listener.accept().await {
                let mut greet = [0u8; 3];
                if stream.read_exact(&mut greet).await.is_err() {
                    return;
                }
                let _ = stream.write_all(&[0x05, 0x00]).await;

                let mut hdr = [0u8; 4];
                if stream.read_exact(&mut hdr).await.is_err() {
                    return;
                }
                if hdr[3] == 0x03 {
                    let mut len = [0u8; 1];
                    let _ = stream.read_exact(&mut len).await;
                    let mut dom_port = vec![0u8; (len[0] as usize) + 2];
                    let _ = stream.read_exact(&mut dom_port).await;
                    let dom = String::from_utf8_lossy(&dom_port[..len[0] as usize]).to_string();
                    *observed_domain_bg.write() = dom;
                }
                let _ = stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB])
                    .await;

                let mut hello_buf = vec![0u8; expected_hello_len];
                if stream.read_exact(&mut hello_buf).await.is_ok() {
                    observed_hello_len_bg.store(hello_buf.len(), Ordering::SeqCst);
                    let _ = stream.write_all(b"SNI_PROXIED_OK").await;
                }
                let _ = stream.shutdown().await;
            }
        });

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.proxies = vec![make_proxy_node("proxy-sni", socks_port, None, None)];
        profile.default_action = RuleAction::Direct;
        profile.rules = vec![RoutingRule {
            id: "rule-sni-domain".to_string(),
            name: "Route SNI Domain Via Proxy".to_string(),
            enabled: true,
            priority: 1,
            process_patterns: Vec::new(),
            domain_patterns: vec!["*.routeward.test".to_string()],
            ip_cidrs: Vec::new(),
            port_ranges: Vec::new(),
            protocol: TransportProtocol::Tcp,
            action: RuleAction::Proxy {
                target_id: "proxy-sni".to_string(),
            },
        }];

        let controller = Arc::new(RouteWardController::new(constants, profile, "en"));

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let relay_addr = relay_listener.local_addr().expect("relay_addr");
        let mut client_stream = TcpStream::connect(relay_addr)
            .await
            .expect("client connect");
        let peer_addr = client_stream.local_addr().expect("client local_addr");
        let (server_stream, accepted_peer) = relay_listener.accept().await.expect("accept");

        // Insert a NAT session targeting a non-Fake-IP literal IPv4 address on port 443 initially marked Direct
        controller.nat_table.insert_session(NatSessionEntry {
            client_ip: Ipv4Addr::LOCALHOST,
            client_port: peer_addr.port(),
            orig_dst_ip: Ipv4Addr::LOCALHOST,
            orig_dst_port: 443,
            pid: 4242,
            process_name: "curl.exe".to_string(),
            process_path: "C:\\Windows\\System32\\curl.exe".to_string(),
            resolution_source: PidResolutionSource::SocketLayer,
            action: RuleAction::Direct,
            matched_rule_name: "Default".to_string(),
            created_at: Instant::now(),
        });

        let client_task = tokio::spawn(async move {
            client_stream
                .write_all(&client_hello)
                .await
                .expect("write ClientHello");
            let mut resp = Vec::new();
            let _ = client_stream.read_to_end(&mut resp).await;
            resp
        });

        let res = controller
            .handle_transparent_tcp_client(server_stream, accepted_peer)
            .await;
        assert!(res.is_ok());

        let reply = client_task.await.expect("client_task join");
        assert_eq!(reply, b"SNI_PROXIED_OK");
        assert_eq!(*observed_domain.read(), "sni.routeward.test");
        assert_eq!(
            observed_hello_len.load(Ordering::SeqCst),
            expected_hello_len,
            "Peeked TLS ClientHello bytes must be forwarded intact to upstream proxy"
        );
    }

    #[tokio::test]
    async fn full_fake_ip_pool_returns_servfail_without_real_dns_fallback() {
        use crate::dns::codec::{build_a_query, parse_dns_message, RCODE_SERVFAIL};

        let trap_udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind trap udp");
        let trap_addr = trap_udp.local_addr().expect("trap addr");
        let trap_hits = Arc::new(AtomicUsize::new(0));
        let trap_hits_bg = trap_hits.clone();
        let _trap_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((_, _)) = trap_udp.recv_from(&mut buf).await {
                trap_hits_bg.fetch_add(1, Ordering::SeqCst);
            }
        });

        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        constants.dns.max_cache_entries = 0; // Simulate an unallocatable full Fake-IP pool
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.dns_config.enable_fake_ip = true;
        profile.dns_config.upstream_dns = trap_addr.to_string();

        let controller = RouteWardController::new(constants, profile, "en");
        let raw_query = build_a_query(0x6161, "overflow.routeward.test").expect("build query");

        let resp = controller
            .resolve_dns_query_async(&raw_query, Some(trap_addr), true)
            .await;
        let msg = parse_dns_message(&resp).expect("parse SERVFAIL");
        assert_eq!(msg.rcode(), RCODE_SERVFAIL);
        assert_eq!(
            trap_hits.load(Ordering::SeqCst),
            0,
            "Full Fake-IP pool must return SERVFAIL and never fall back to real DNS"
        );
    }

    #[tokio::test]
    async fn live_profile_replacement_reapplies_interception_and_flushes_dns_cache_on_start_and_stop(
    ) {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        constants.network.default_relay_tcp_port = 0;
        constants.network.default_transparent_tcp_port = 0;
        constants.network.default_dns_listen_port = 0;
        constants.network.default_local_name_inspect_port = 0;
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = false;

        let controller = RouteWardController::new(constants, profile.clone(), "en");
        controller.start_engine();
        assert!(controller.is_running());

        let mut updated_profile = profile;
        updated_profile.security_policy.kill_switch_enabled = true;
        updated_profile.security_policy.block_encrypted_dns_bypass = false;
        controller.replace_profile(updated_profile);

        let logs = controller.telemetry.list_logs();
        assert!(
            logs.iter().any(|l| l.level == LogLevel::Info
                && l.component == COMPONENT_ENGINE
                && l.message
                    .contains("Reapplied active interception rules and proxy bootstrap")),
            "Expected live interception reload INFO log, got: {:?}",
            logs
        );

        controller.stop_engine();
        assert!(!controller.is_running());
    }

    #[tokio::test]
    async fn forward_udp_datagram_evaluates_rules_per_datagram_and_enforces_fragmentation_and_kill_switch(
    ) {
        use crate::config::{PortRange, ProxyProtocol, RoutingRule, RuleAction, TransportProtocol};
        use crate::proxy::udp::{decode_socks5_udp_datagram, encode_socks5_udp_datagram};

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let proto_consts = constants.protocols.clone();

        // 1. Direct UDP echo server
        let direct_echo = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind direct echo");
        let direct_echo_addr = direct_echo.local_addr().expect("direct echo addr");
        let _direct_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = direct_echo.recv_from(&mut buf).await {
                let mut reply = b"DIRECT:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                let _ = direct_echo.send_to(&reply, peer).await;
            }
        });

        // 2. Mock SOCKS5 UDP relay + TCP control server that records ATYP and echoes "PROXIED:" + payload
        let socks_udp = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind socks udp"),
        );
        let socks_udp_addr = socks_udp.local_addr().expect("socks udp addr");
        let last_atyp = Arc::new(parking_lot::Mutex::new(String::new()));
        let last_atyp_bg = last_atyp.clone();
        let socks_udp_bg = socks_udp.clone();
        let proto_bg = proto_consts.clone();
        let _socks_udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, peer)) = socks_udp_bg.recv_from(&mut buf).await {
                if let Ok((target, payload)) = decode_socks5_udp_datagram(&buf[..n], &proto_bg) {
                    *last_atyp_bg.lock() = match &target {
                        Socks5UdpTarget::Domain(dom, port) => format!("Domain({dom}:{port})"),
                        Socks5UdpTarget::Ipv4(ip, port) => format!("Ipv4({ip}:{port})"),
                        Socks5UdpTarget::Ipv6(ip, port) => format!("Ipv6({ip}:{port})"),
                    };
                    let mut echoed = b"PROXIED:".to_vec();
                    echoed.extend_from_slice(payload);
                    if let Ok(enc) = encode_socks5_udp_datagram(&target, &echoed, &proto_bg) {
                        let _ = socks_udp_bg.send_to(&enc, peer).await;
                    }
                }
            }
        });

        let socks_tcp = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind socks tcp");
        let socks_tcp_addr = socks_tcp.local_addr().expect("socks tcp addr");
        let _socks_tcp_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = socks_tcp.accept().await {
                let relay_port = socks_udp_addr.port();
                tokio::spawn(async move {
                    let mut g = [0u8; 2];
                    if stream.read_exact(&mut g).await.is_err() {
                        return;
                    }
                    let mut m = vec![0u8; g[1] as usize];
                    let _ = stream.read_exact(&mut m).await;
                    let _ = stream.write_all(&[0x05, 0x00]).await;

                    let mut h = [0u8; 4];
                    if stream.read_exact(&mut h).await.is_err() {
                        return;
                    }
                    let mut tail = [0u8; 6];
                    let _ = stream.read_exact(&mut tail).await;
                    let pb = relay_port.to_be_bytes();
                    let _ = stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, pb[0], pb[1]])
                        .await;
                    let mut eof = [0u8; 16];
                    let _ = stream.read(&mut eof).await;
                });
            }
        });

        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = true;
        profile.proxies = vec![ProxyNode {
            id: "socks-udp-1".to_string(),
            name: "SOCKS5 UDP Node".to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port: socks_tcp_addr.port(),
            auth: None,
            tls: false,
            sni: None,
            udp_enabled: true,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        }];
        profile.rules = vec![
            RoutingRule {
                id: "rule-udp-proxy-domain".to_string(),
                name: "Proxy UDP Domain".to_string(),
                enabled: true,
                priority: 1,
                process_patterns: vec![],
                domain_patterns: vec!["*.proxied.routeward.test".to_string()],
                ip_cidrs: vec![],
                port_ranges: vec![],
                protocol: TransportProtocol::Udp,
                action: RuleAction::Proxy {
                    target_id: "socks-udp-1".to_string(),
                },
            },
            RoutingRule {
                id: "rule-udp-direct".to_string(),
                name: "Direct UDP Port".to_string(),
                enabled: true,
                priority: 2,
                process_patterns: vec![],
                domain_patterns: vec![],
                ip_cidrs: vec![],
                port_ranges: vec![PortRange {
                    start: direct_echo_addr.port(),
                    end: direct_echo_addr.port(),
                }],
                protocol: TransportProtocol::Udp,
                action: RuleAction::Direct,
            },
        ];
        profile.default_action = RuleAction::Block;

        let controller = RouteWardController::new(constants, profile, "en");
        let fake_ip = controller
            .dns
            .allocate_or_get("echo.proxied.routeward.test")
            .expect("allocate fake ip");

        let client_sock: SocketAddr = "127.0.0.1:54321".parse().expect("client_sock");
        let proxied_target = Socks5UdpTarget::Ipv4(fake_ip, 9999);
        let direct_target = match direct_echo_addr {
            SocketAddr::V4(v4) => Socks5UdpTarget::Ipv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Socks5UdpTarget::Ipv6(*v6.ip(), v6.port()),
        };

        // Same client socket -> Destination 1 (Fake-IP for echo.proxied.routeward.test:9999) -> Proxied with ATYP=0x03 Domain
        let reply1 = controller
            .forward_udp_datagram(
                client_sock,
                "udp-client",
                Some("/bin/udp-client"),
                4242,
                &proxied_target,
                b"hello-proxy",
                false,
            )
            .await
            .expect("proxied datagram should succeed");
        assert_eq!(reply1, b"PROXIED:hello-proxy");
        assert_eq!(
            *last_atyp.lock(),
            "Domain(echo.proxied.routeward.test:9999)"
        );

        // Same client socket -> Destination 2 (direct_echo_addr) -> Direct
        let reply2 = controller
            .forward_udp_datagram(
                client_sock,
                "udp-client",
                Some("/bin/udp-client"),
                4242,
                &direct_target,
                b"hello-direct",
                false,
            )
            .await
            .expect("direct datagram should succeed");
        assert_eq!(reply2, b"DIRECT:hello-direct");

        // Fragmented datagram whose rule is Proxy -> Blocked when Kill-Switch is active, counter incremented
        let frag_proxy_res = controller
            .forward_udp_datagram(
                client_sock,
                "udp-client",
                Some("/bin/udp-client"),
                4242,
                &proxied_target,
                b"frag-proxy",
                true,
            )
            .await;
        assert!(frag_proxy_res.is_err());
        assert_eq!(controller.fragmented_udp_drop_count(), 1);

        // Fragmented datagram whose rule is Direct -> Passes
        let frag_direct_reply = controller
            .forward_udp_datagram(
                client_sock,
                "udp-client",
                Some("/bin/udp-client"),
                4242,
                &direct_target,
                b"frag-direct",
                true,
            )
            .await
            .expect("fragmented direct datagram should pass");
        assert_eq!(frag_direct_reply, b"DIRECT:frag-direct");
    }
}
