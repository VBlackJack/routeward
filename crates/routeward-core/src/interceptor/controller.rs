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

use super::dns_handler::{RelayCaches, MAX_UDP_DATAGRAM_BYTES};
use super::{
    RouteWardController, SystemDiagnostics, WarnRateLimiter, COMPONENT_DNS, COMPONENT_ENGINE,
    COMPONENT_PROXY, COMPONENT_RULE, COMPONENT_TRANSPARENT, COMPONENT_WINDIVERT,
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
    ERR_KEY_DAEMON_IPC_ERROR, ERR_KEY_PROXY_NOT_FOUND, ERR_KEY_RULE_BLOCKED,
};
use crate::i18n::I18nRegistry;
use crate::interceptor::backend::Interceptor;
use crate::interceptor::dns_server_exempt::{
    dns_server_block_verdict, DnsProto, DnsServerTracker, UidSets,
};
use crate::interceptor::nat::{
    PendingSynOutcome, PendingSynQueue, PendingUdpOutcome, PendingUdpQueue, TransparentNatTable,
};
use crate::interceptor::nftables::NftablesInterceptor;
#[cfg(target_os = "linux")]
use crate::interceptor::nftables::TproxyRoutingSpec;
use crate::interceptor::policy::{
    block_reason_for_rule, predict_from_evaluation, unknown_process_decision, PolicyPorts,
    FAKE_IP_UNMAPPED_RULE_ID,
};
#[cfg(windows)]
use crate::interceptor::windivert::WinDivertInterceptor;
use crate::process::{ProcessAttribution, ProcessIdentity, ProcessResolver};
use crate::proxy::sni::TlsSniExtractor;
use crate::proxy::udp::UdpAssociationManager;
use crate::proxy::uri::ProxyUriCodec;
use crate::proxy::ProxyConnector;
use crate::rules::{ConnectionRequest, RuleEngine, RuleEvaluationResult};
use crate::telemetry::{
    BlockReason, BlockedRecord, ConnectionStatus, LogContext, LogLevel, TelemetryHub,
    TrackedConnection, UnattributedDropCounters,
};
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Capacity of the channel announcing removed expired rules.
const RULE_EXPIRY_CHANNEL_CAPACITY: usize = 16;
/// Process name shown on records produced by the Fake-IP egress guard.
const FAKE_IP_GUARD_PROCESS_NAME: &str = "fake-ip-guard";
/// Rule name shown on records produced by the Fake-IP egress guard.
const FAKE_IP_GUARD_RULE_NAME: &str = "SecurityPolicy:FakeIpEgressGuard";

/// Upper bound of the wait, in `stop_engine`, for the listener tasks to drop their sockets.
const ENGINE_SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_millis(2000);

/// Receiving end of the per-start engine shutdown signal.
pub(super) type ShutdownSignal = watch::Receiver<bool>;

/// Shutdown signal and listener/ticker task handles of one `start_engine` call.
pub(crate) struct EngineRuntime {
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

/// Awaits `fut` unless the shutdown signal fires first, in which case `None` is returned and
/// `fut` is dropped. A dropped sender counts as a shutdown.
async fn or_shutdown<F: std::future::Future>(
    signal: &mut ShutdownSignal,
    fut: F,
) -> Option<F::Output> {
    tokio::select! {
        _ = signal.wait_for(|stopped| *stopped) => None,
        out = fut => Some(out),
    }
}

/// Listeners of the engine, bound before any task is spawned.
struct EngineListeners {
    relay: TcpListener,
    transparent: TcpListener,
    dns_udp: Arc<UdpSocket>,
    dns_tcp: TcpListener,
    local_name: Arc<UdpSocket>,
}

/// Upper bound of the established connections inspected by the start notice.
#[cfg(windows)]
const PREEXISTING_SCAN_LIMIT: usize = 8192;
/// Number of processes named in the start notice before the rest is summarised.
#[cfg(windows)]
const PREEXISTING_NOTICE_TOP_PROCESSES: usize = 5;

/// Builds the start notice from per-process counts of connections opened before the start, or
/// `None` when there are none.
#[cfg(windows)]
fn format_preexisting_connections_notice(
    per_process: std::collections::HashMap<String, usize>,
) -> Option<String> {
    let total: usize = per_process.values().sum();
    if total == 0 {
        return None;
    }
    let mut ranked: Vec<(String, usize)> = per_process.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let hidden = ranked
        .len()
        .saturating_sub(PREEXISTING_NOTICE_TOP_PROCESSES);
    let mut names: Vec<String> = ranked
        .iter()
        .take(PREEXISTING_NOTICE_TOP_PROCESSES)
        .map(|(name, count)| format!("{name} x{count}"))
        .collect();
    if hidden > 0 {
        names.push(format!("and {hidden} more"));
    }
    Some(format!(
        "{total} connections opened before start are not intercepted until they reconnect ({}); restart these apps",
        names.join(", ")
    ))
}

/// Runs `f`, which may block for a whole process scan plus a firewall sync, without stalling an
/// async worker: on a multi-thread tokio runtime the worker hands its queue over through
/// `block_in_place`; elsewhere (no runtime, or a current-thread runtime where `block_in_place`
/// would panic) `f` simply runs inline, as it always did.
fn run_blocking_section<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

impl RouteWardController {
    pub fn new(constants: SystemConstants, profile: ProfileConfig, locale: &str) -> Self {
        let log_dir = constants.telemetry.resolve_process_log_dir();
        Self::new_with_log_dir(constants, profile, locale, log_dir)
    }

    pub fn new_daemon(constants: SystemConstants, profile: ProfileConfig, locale: &str) -> Self {
        let log_dir = constants.telemetry.resolve_daemon_log_dir();
        let state_path = constants
            .ipc
            .resolve_daemon_profile_path()
            .ok()
            .map(|path| crate::system::protection_state::state_path_for_profile(&path));
        let controller = Self::new_with_log_dir(constants, profile, locale, log_dir);
        match state_path {
            Some(path) => controller.with_protection_state_path(path),
            None => controller,
        }
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
        let mut profile = profile;
        RuleEngine::sort_rules(&mut profile.rules);
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

        let dns_server_tracker = DnsServerTracker::new(telemetry.clone());
        dns_server_tracker.configure(
            &constants.dns.default_dns_server_processes,
            &profile.dns_config.dns_server_processes,
        );

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
            dns_server_tracker,
            fragmented_udp_drop_count: Arc::new(AtomicU64::new(0)),
            orphan_fragment_drop_count: Arc::new(AtomicU64::new(0)),
            last_seen_orig_resolver: Arc::new(RwLock::new(None)),
            system_resolvers_override: Arc::new(RwLock::new(None)),
            bootstrapped_proxy_endpoints: Arc::new(DashMap::new()),
            direct_udp_pool: Arc::new(parking_lot::Mutex::new(Vec::new())),
            direct_udp_v6_pool: Arc::new(parking_lot::Mutex::new(Vec::new())),
            relay_caches: Arc::new(RelayCaches::new()),
            interceptor_backend,
            running: Arc::new(AtomicBool::new(false)),
            engine_lifecycle: Arc::new(parking_lot::Mutex::new(())),
            engine_runtime: Arc::new(parking_lot::Mutex::new(None)),
            protection: Arc::new(super::protection::ProtectionRuntime::new(None)),
            proxy_health: Arc::new(RwLock::new(std::collections::HashMap::new())),
            rule_expiry_tx: tokio::sync::broadcast::channel(RULE_EXPIRY_CHANNEL_CAPACITY).0,
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

    /// Binds a TCP listener synchronously (so a failure is reported before anything is spawned).
    fn bind_tcp_listener_now(addr: &str) -> std::io::Result<TcpListener> {
        let std_listener = std::net::TcpListener::bind(addr)?;
        std_listener.set_nonblocking(true)?;
        TcpListener::from_std(std_listener)
    }

    /// Binds a UDP socket synchronously (so a failure is reported before anything is spawned).
    fn bind_udp_socket_now(addr: &str) -> std::io::Result<UdpSocket> {
        let std_socket = std::net::UdpSocket::bind(addr)?;
        std_socket.set_nonblocking(true)?;
        UdpSocket::from_std(std_socket)
    }

    /// Logs a listener bind failure at error level and converts it into the startup error.
    fn listener_bind_failure(
        &self,
        label: &str,
        addr: &str,
        err: std::io::Error,
    ) -> RouteWardError {
        let detail = format!("Failed to bind the {label} listener on {addr}: {err}");
        self.telemetry
            .push_log(LogLevel::Error, COMPONENT_ENGINE, detail.clone());
        RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail,
        }
    }

    /// Binds every mandatory IPv4 listener of the engine. Nothing is spawned before all of them
    /// are bound, so a failure leaves no half-started engine behind.
    fn bind_engine_listeners(&self) -> RouteWardResult<EngineListeners> {
        let net = &self.constants.network;
        let relay_addr = format!("{}:{}", net.local_bind_host, net.default_relay_tcp_port);
        let transparent_addr = format!(
            "{}:{}",
            net.transparent_bind_host, net.default_transparent_tcp_port
        );
        let dns_addr = format!(
            "{}:{}",
            net.transparent_bind_host, net.default_dns_listen_port
        );
        let local_name_addr = format!(
            "{}:{}",
            net.transparent_bind_host, net.default_local_name_inspect_port
        );

        let relay = Self::bind_tcp_listener_now(&relay_addr)
            .map_err(|e| self.listener_bind_failure("SOCKS5 relay", &relay_addr, e))?;
        let transparent = Self::bind_tcp_listener_now(&transparent_addr)
            .map_err(|e| self.listener_bind_failure("transparent TCP", &transparent_addr, e))?;
        let dns_udp = Self::bind_udp_socket_now(&dns_addr)
            .map_err(|e| self.listener_bind_failure("UDP DNS", &dns_addr, e))?;
        let dns_tcp = Self::bind_tcp_listener_now(&dns_addr)
            .map_err(|e| self.listener_bind_failure("TCP DNS", &dns_addr, e))?;
        let local_name = Self::bind_udp_socket_now(&local_name_addr)
            .map_err(|e| self.listener_bind_failure("TPROXY UDP", &local_name_addr, e))?;

        ProxyConnector::apply_platform_mark_udp(&dns_udp, net.linux_fwmark);
        NftablesInterceptor::enable_udp_pktinfo(&dns_udp);
        ProxyConnector::apply_platform_mark_udp(&local_name, net.linux_fwmark);
        if let Err(err) = NftablesInterceptor::enable_udp_tproxy_options(&local_name) {
            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_ENGINE,
                format!(
                    "Could not enable IP_TRANSPARENT/IP_RECVORIGDSTADDR on {local_name_addr}: {err}"
                ),
            );
        }
        NftablesInterceptor::enable_udp_pktinfo(&local_name);

        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            format!(
                "{}: {relay_addr}",
                self.i18n.t("cli.engine.startup.listening_socks")
            ),
        );
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_TRANSPARENT,
            format!(
                "{}: {transparent_addr}",
                self.i18n.t("cli.engine.startup.listening_transparent")
            ),
        );
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            format!("Listening for local/redirected UDP DNS queries on {dns_addr}"),
        );
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            format!("Listening for local/redirected TCP DNS queries on {dns_addr}"),
        );
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            format!("Listening for TPROXY UDP and LLMNR/mDNS inspection on {local_name_addr}"),
        );

        Ok(EngineListeners {
            relay,
            transparent,
            dns_udp: Arc::new(dns_udp),
            dns_tcp,
            local_name: Arc::new(local_name),
        })
    }

    /// Starts the relay, transparent and DNS listeners. Returns `Ok(())` when the engine is
    /// running afterwards (including when it already was) and the bind error when a listener could
    /// not be bound, in which case the engine stays stopped.
    pub fn start_engine(&self) -> RouteWardResult<()> {
        // Serialises with `stop_engine` so a concurrent stop can never run between the start of
        // this call and the storage of the shutdown handle. Listener tasks never take this lock.
        let _lifecycle = self.engine_lifecycle.lock();
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            self.i18n.t("cli.engine.startup.banner"),
        );

        // Bind first, spawn after: a listener that cannot be bound would otherwise leave the
        // interceptor reflecting traffic toward a dead port.
        let listeners = match self.bind_engine_listeners() {
            Ok(listeners) => listeners,
            Err(err) => {
                self.telemetry.push_log(
                    LogLevel::Error,
                    COMPONENT_ENGINE,
                    format!("Engine startup aborted, no listener was started: {err}"),
                );
                self.running.store(false, Ordering::SeqCst);
                return Err(err);
            }
        };

        self.flush_os_dns_cache("startup");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        let ticker_ctrl = self.clone();
        let mut ticker_signal = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let interval =
                Duration::from_millis(ticker_ctrl.constants.telemetry.sampling_interval_ms);
            while ticker_ctrl.is_running() {
                ticker_ctrl.telemetry.tick_bandwidth_sample();
                ticker_ctrl.sweep_expired_rules_and_save();
                if or_shutdown(&mut ticker_signal, tokio::time::sleep(interval))
                    .await
                    .is_none()
                {
                    break;
                }
            }
        }));

        // Read-only notice about connections opened before the engine started: they keep their
        // original route until the application reconnects. Runs once, off every packet path.
        #[cfg(windows)]
        {
            let notice_ctrl = self.clone();
            tasks.push(tokio::spawn(async move {
                let _ = tokio::task::spawn_blocking(move || {
                    notice_ctrl.report_preexisting_connections();
                })
                .await;
            }));
        }

        let dns_scan_ctrl = self.clone();
        let mut dns_scan_signal = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let interval = Duration::from_millis(
                dns_scan_ctrl
                    .constants
                    .dns
                    .dns_server_process_scan_interval_ms
                    .max(1),
            );
            while dns_scan_ctrl.is_running() {
                let scan_ctrl = dns_scan_ctrl.clone();
                let scan = tokio::task::spawn_blocking(move || {
                    scan_ctrl.refresh_dns_server_tracker();
                });
                if or_shutdown(&mut dns_scan_signal, scan).await.is_none() {
                    break;
                }
                if or_shutdown(&mut dns_scan_signal, tokio::time::sleep(interval))
                    .await
                    .is_none()
                {
                    break;
                }
            }
        }));

        let relay_ctrl = self.clone();
        let relay_listener = listeners.relay;
        let mut relay_signal = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            while relay_ctrl.is_running() {
                match or_shutdown(&mut relay_signal, relay_listener.accept()).await {
                    None => break,
                    Some(Ok((client_stream, peer_addr))) => {
                        let conn_ctrl = relay_ctrl.clone();
                        tokio::spawn(async move {
                            let _ = conn_ctrl
                                .handle_local_socks5_client(client_stream, peer_addr.port())
                                .await;
                        });
                    }
                    Some(Err(_)) => {}
                }
            }
        }));

        let trans_ctrl = self.clone();
        let trans_listener = listeners.transparent;
        let trans_signal = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            RouteWardController::accept_transparent_tcp_loop(
                trans_ctrl,
                trans_listener,
                trans_signal,
            )
            .await;
        }));

        if let Some(v6_ip) = Self::ipv6_counterpart(&self.constants.network.transparent_bind_host) {
            let port = self.constants.network.default_transparent_tcp_port;
            match Self::bind_tcp_v6_only(v6_ip, port) {
                Ok(listener) => {
                    self.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_TRANSPARENT,
                        format!(
                            "{}: [{}]:{}",
                            self.i18n.t("cli.engine.startup.listening_transparent"),
                            v6_ip,
                            port
                        ),
                    );
                    let trans_v6_ctrl = self.clone();
                    let trans_v6_signal = shutdown_rx.clone();
                    tasks.push(tokio::spawn(async move {
                        RouteWardController::accept_transparent_tcp_loop(
                            trans_v6_ctrl,
                            listener,
                            trans_v6_signal,
                        )
                        .await;
                    }));
                }
                Err(err) => {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_TRANSPARENT,
                        format!(
                            "IPv6 transparent TCP listener disabled on [{v6_ip}]:{port}: {err}"
                        ),
                    );
                }
            }
        }

        let dns_udp_ctrl = self.clone();
        let dns_udp_socket = listeners.dns_udp;
        let mut dns_udp_signal = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; dns_udp_ctrl.constants.dns.udp_response_buffer_bytes];
            let mut join_set = tokio::task::JoinSet::new();
            while dns_udp_ctrl.is_running() {
                while join_set.try_join_next().is_some() {}
                let received = or_shutdown(
                    &mut dns_udp_signal,
                    NftablesInterceptor::recv_udp_with_local_ip(&dns_udp_socket, &mut buf),
                )
                .await;
                match received {
                    None => break,
                    Some(Ok((len, peer_addr, local_dst_ip))) => {
                        let query_bytes = buf[..len].to_vec();
                        let sock_reply = Arc::clone(&dns_udp_socket);
                        let ctrl_query = dns_udp_ctrl.clone();
                        join_set.spawn(async move {
                            let work = async {
                                let orig_resolver =
                                    ctrl_query.lookup_udp_orig_dns_resolver(peer_addr).await;
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
                            };
                            work.await;
                        });
                    }
                    Some(Err(_)) => {}
                }
            }
            join_set.shutdown().await;
        }));

        if let Some(v6_ip) = Self::ipv6_counterpart(&self.constants.network.transparent_bind_host) {
            let port = self.constants.network.default_dns_listen_port;
            match Self::bind_udp_v6_only(v6_ip, port) {
                Ok(socket) => {
                    ProxyConnector::apply_platform_mark_udp(
                        &socket,
                        self.constants.network.linux_fwmark,
                    );
                    NftablesInterceptor::enable_ipv6_udp_pktinfo(&socket);
                    let socket = Arc::new(socket);
                    self.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_ENGINE,
                        format!("Listening for IPv6 UDP DNS queries on [{v6_ip}]:{port}"),
                    );
                    let dns_udp_v6_ctrl = self.clone();
                    let mut dns_udp_v6_signal = shutdown_rx.clone();
                    tasks.push(tokio::spawn(async move {
                        let mut buf =
                            vec![0u8; dns_udp_v6_ctrl.constants.dns.udp_response_buffer_bytes];
                        let mut join_set = tokio::task::JoinSet::new();
                        while dns_udp_v6_ctrl.is_running() {
                            while join_set.try_join_next().is_some() {}
                            let received = or_shutdown(
                                &mut dns_udp_v6_signal,
                                NftablesInterceptor::recv_udp_v6_with_local_ip(&socket, &mut buf),
                            )
                            .await;
                            match received {
                                None => break,
                                Some(Ok((len, peer_addr, local_dst_ip))) => {
                                    let query_bytes = buf[..len].to_vec();
                                    let sock_reply = Arc::clone(&socket);
                                    let ctrl_query = dns_udp_v6_ctrl.clone();
                                    join_set.spawn(async move {
                                        let work = async {
                                            let orig_resolver = ctrl_query
                                                .lookup_udp_orig_dns_resolver(peer_addr)
                                                .await;
                                            let resp = ctrl_query
                                                .resolve_dns_query_async(
                                                    &query_bytes,
                                                    orig_resolver,
                                                    true,
                                                )
                                                .await;
                                            if !resp.is_empty() {
                                                let _ =
                                                    NftablesInterceptor::send_udp_v6_from_local_ip(
                                                        &sock_reply,
                                                        &resp,
                                                        peer_addr,
                                                        local_dst_ip,
                                                    )
                                                    .await;
                                            }
                                        };
                                        work.await;
                                    });
                                }
                                Some(Err(_)) => {}
                            }
                        }
                        join_set.shutdown().await;
                    }));
                }
                Err(err) => {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!("IPv6 UDP DNS listener disabled on [{v6_ip}]:{port}: {err}"),
                    );
                }
            }
        }

        let dns_tcp_ctrl = self.clone();
        let dns_tcp_listener = listeners.dns_tcp;
        let dns_tcp_signal = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let dns_port = dns_tcp_ctrl.constants.network.default_dns_listen_port;
            RouteWardController::accept_dns_tcp_loop(
                dns_tcp_ctrl,
                dns_tcp_listener,
                dns_port,
                dns_tcp_signal,
            )
            .await;
        }));

        if let Some(v6_ip) = Self::ipv6_counterpart(&self.constants.network.transparent_bind_host) {
            let dns_port = self.constants.network.default_dns_listen_port;
            match Self::bind_tcp_v6_only(v6_ip, dns_port) {
                Ok(listener) => {
                    self.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_ENGINE,
                        format!("Listening for IPv6 TCP DNS queries on [{v6_ip}]:{dns_port}"),
                    );
                    let dns_tcp_v6_ctrl = self.clone();
                    let dns_tcp_v6_signal = shutdown_rx.clone();
                    tasks.push(tokio::spawn(async move {
                        RouteWardController::accept_dns_tcp_loop(
                            dns_tcp_v6_ctrl,
                            listener,
                            dns_port,
                            dns_tcp_v6_signal,
                        )
                        .await;
                    }));
                }
                Err(err) => {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!("IPv6 TCP DNS listener disabled on [{v6_ip}]:{dns_port}: {err}"),
                    );
                }
            }
        }

        let local_name_ctrl = self.clone();
        let local_name_socket = listeners.local_name;
        let mut local_name_signal = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
            let mut join_set = tokio::task::JoinSet::new();
            while local_name_ctrl.is_running() {
                while join_set.try_join_next().is_some() {}
                let received = or_shutdown(
                    &mut local_name_signal,
                    NftablesInterceptor::recv_udp_tproxy_orig_dst(&local_name_socket, &mut buf),
                )
                .await;
                match received {
                    None => break,
                    Some(Ok((len, client_addr, orig_dst))) => {
                        let pkt_bytes = buf[..len].to_vec();
                        let sock_reply = Arc::clone(&local_name_socket);
                        let ctrl_inspect = local_name_ctrl.clone();
                        join_set.spawn(async move {
                            let work = ctrl_inspect.handle_tproxy_udp_datagram(
                                &pkt_bytes,
                                SocketAddr::V4(client_addr),
                                orig_dst.map(SocketAddr::V4),
                                &sock_reply,
                            );
                            work.await;
                        });
                    }
                    Some(Err(_)) => {}
                }
            }
            join_set.shutdown().await;
        }));

        if let Some(v6_ip) = Self::ipv6_counterpart(&self.constants.network.transparent_bind_host) {
            let inspect_port = self.constants.network.default_local_name_inspect_port;
            match Self::bind_udp_v6_only(v6_ip, inspect_port) {
                Ok(socket) => {
                    ProxyConnector::apply_platform_mark_udp(
                        &socket,
                        self.constants.network.linux_fwmark,
                    );
                    if let Err(err) = NftablesInterceptor::enable_udp_tproxy_v6_options(&socket) {
                        self.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_ENGINE,
                            format!("Could not enable IPv6 TPROXY/IPV6_RECVORIGDSTADDR on [{v6_ip}]:{inspect_port}: {err}"),
                        );
                    }
                    let socket = Arc::new(socket);
                    self.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_ENGINE,
                        format!(
                            "Listening for IPv6 TPROXY UDP inspection on [{v6_ip}]:{inspect_port}"
                        ),
                    );
                    let local_name_v6_ctrl = self.clone();
                    let mut local_name_v6_signal = shutdown_rx.clone();
                    tasks.push(tokio::spawn(async move {
                        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
                        let mut join_set = tokio::task::JoinSet::new();
                        while local_name_v6_ctrl.is_running() {
                            while join_set.try_join_next().is_some() {}
                            let received = or_shutdown(
                                &mut local_name_v6_signal,
                                NftablesInterceptor::recv_udp_tproxy_v6_orig_dst(&socket, &mut buf),
                            )
                            .await;
                            match received {
                                None => break,
                                Some(Ok((len, client_addr, orig_dst))) => {
                                    let pkt_bytes = buf[..len].to_vec();
                                    let sock_reply = Arc::clone(&socket);
                                    let ctrl_inspect = local_name_v6_ctrl.clone();
                                    join_set.spawn(async move {
                                        let work = ctrl_inspect.handle_tproxy_udp_datagram(
                                            &pkt_bytes,
                                            SocketAddr::V6(client_addr),
                                            orig_dst.map(SocketAddr::V6),
                                            &sock_reply,
                                        );
                                        work.await;
                                    });
                                }
                                Some(Err(_)) => {}
                            }
                        }
                        join_set.shutdown().await;
                    }));
                }
                Err(err) => {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!(
                            "IPv6 TPROXY UDP listener disabled on [{v6_ip}]:{inspect_port}: {err}"
                        ),
                    );
                }
            }
        }

        let bootstrap_ctrl = self.clone();
        let mut bootstrap_signal = shutdown_rx;
        tasks.push(tokio::spawn(async move {
            let _ = or_shutdown(
                &mut bootstrap_signal,
                bootstrap_ctrl.bootstrap_resolve_proxy_hosts(),
            )
            .await;
        }));

        *self.engine_runtime.lock() = Some(EngineRuntime {
            shutdown: shutdown_tx,
            tasks,
        });
        // Defence in depth: should the engine have been flagged stopped meanwhile, do not leave
        // the freshly spawned tasks parked with an unfired signal.
        if !self.is_running() {
            self.shutdown_engine_tasks();
        }
        Ok(())
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
        mut signal: ShutdownSignal,
    ) {
        while ctrl.is_running() {
            match or_shutdown(&mut signal, listener.accept()).await {
                None => break,
                Some(Ok((client_stream, peer_addr))) => {
                    let conn_ctrl = ctrl.clone();
                    tokio::spawn(async move {
                        let _ = conn_ctrl
                            .handle_transparent_tcp_client(client_stream, peer_addr)
                            .await;
                    });
                }
                Some(Err(_)) => {}
            }
        }
    }

    pub(super) async fn accept_dns_tcp_loop(
        ctrl: RouteWardController,
        listener: TcpListener,
        dns_port: u16,
        mut signal: ShutdownSignal,
    ) {
        while ctrl.is_running() {
            match or_shutdown(&mut signal, listener.accept()).await {
                None => break,
                Some(Ok((stream, _peer_addr))) => {
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
                Some(Err(_)) => {}
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
    ///
    /// Refuses to start when the engine is not running: its listeners are what the interceptor
    /// reflects traffic to, so a failed listener bind must never end with an active interceptor
    /// (and a kill switch) pointing at a dead port. A backend that fails halfway is stopped so
    /// no driver handle or firewall rule stays applied.
    pub fn start_transparent_interceptor(&self) -> RouteWardResult<&'static str> {
        let backend_name = self.interceptor_backend.name();
        if !self.is_running() {
            let detail = format!(
                "Refusing to start the {backend_name} interceptor: the engine listeners are not bound"
            );
            self.telemetry
                .push_log(LogLevel::Error, COMPONENT_ENGINE, detail.clone());
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail,
            });
        }
        self.refresh_dns_server_tracker();
        if let Err(err) = self.interceptor_backend.start(self.clone()) {
            self.telemetry.push_log(
                LogLevel::Error,
                COMPONENT_ENGINE,
                format!("Failed to start the {backend_name} interceptor: {err}"),
            );
            self.interceptor_backend.stop();
            return Err(err);
        }
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
        let _lifecycle = self.engine_lifecycle.lock();
        let was_active = self.interceptor_backend.is_active();
        self.interceptor_backend.stop();
        self.dns_server_tracker
            .mark_uid_sets_applied(UidSets::default());
        self.udp_manager.clear_all();
        let was_running = self.running.swap(false, Ordering::SeqCst);
        self.shutdown_engine_tasks();
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

    /// Fires the shutdown signal of the current start so every listener task drops its socket,
    /// then waits (bounded) for those tasks to finish so the ports can be bound again at once.
    ///
    /// The wait only happens on a multi-thread runtime, where `block_in_place` hands the worker's
    /// queue to another thread; on a current-thread runtime the tasks cannot make progress while
    /// this thread blocks, so they finish at the caller's next await point instead.
    fn shutdown_engine_tasks(&self) {
        let Some(runtime) = self.engine_runtime.lock().take() else {
            return;
        };
        let _ = runtime.shutdown.send(true);
        let tasks = runtime.tasks;
        let multi_thread = tokio::runtime::Handle::try_current()
            .map(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        if !multi_thread {
            return;
        }
        let unfinished = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let deadline = tokio::time::Instant::now() + ENGINE_SHUTDOWN_JOIN_TIMEOUT;
                let mut unfinished = 0usize;
                for mut task in tasks {
                    if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                        task.abort();
                        unfinished += 1;
                    }
                }
                unfinished
            })
        });
        if unfinished > 0 {
            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_ENGINE,
                format!(
                    "{unfinished} engine task(s) did not stop within {} ms and were aborted",
                    ENGINE_SHUTDOWN_JOIN_TIMEOUT.as_millis()
                ),
            );
        }
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
                    TrackedConnection::blocked(
                        BlockedRecord::new(
                            BlockReason::FakeIpEgressGuard,
                            protocol,
                            FAKE_IP_GUARD_RULE_NAME,
                        )
                        .process(FAKE_IP_GUARD_PROCESS_NAME, context, 0)
                        .target(v4.to_string(), target_port)
                        .with_ip(Some(v4.to_string()))
                        .with_domain(mapped_domain),
                    ),
                    false,
                );
                return Err(RouteWardError::BlockedByPolicy {
                    key: ERR_KEY_RULE_BLOCKED,
                    rule_name: FAKE_IP_GUARD_RULE_NAME.to_string(),
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
            TrackedConnection::blocked(
                BlockedRecord::new(
                    BlockReason::FakeIpEgressGuard,
                    protocol,
                    FAKE_IP_GUARD_RULE_NAME,
                )
                .process(FAKE_IP_GUARD_PROCESS_NAME, component, 0)
                .target(dst_ip.to_string(), dst_port)
                .with_ip(Some(dst_ip.to_string()))
                .with_domain(mapped_domain)
                .with_tx_bytes(packet.len() as u64),
            ),
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
            let rule_name = crate::interceptor::windivert::scoped_firewall_rule_name(
                self.constants.network.default_transparent_tcp_port,
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
            paused_until_epoch_ms: self.paused_until_epoch_ms(),
            auto_start_error_key: self.auto_start_error_key(),
        }
    }

    /// Ports the security policy reacts to, from the controller's constants.
    pub fn policy_ports(&self) -> PolicyPorts {
        PolicyPorts::from_constants(&self.constants)
    }

    /// Latest known proxy health reports (filled by [`Self::test_proxy`]).
    pub fn proxy_health_snapshot(&self) -> Vec<ProxyHealthReport> {
        self.proxy_health.read().values().cloned().collect()
    }

    /// Counters of SYN / UDP packets dropped under the kill switch without a connection row.
    pub fn unattributed_drop_counters(&self) -> UnattributedDropCounters {
        UnattributedDropCounters {
            dropped_unattributed_syn: self.nat_table.dropped_unattributed_syn_count(),
            dropped_unattributed_udp: self.nat_table.dropped_unattributed_udp_count(),
        }
    }

    /// Logs `message` at WARN with the blocked connection as context, then records it.
    pub(super) fn log_and_record_blocked(
        &self,
        component: &str,
        message: String,
        conn: TrackedConnection,
    ) {
        self.telemetry.push_log_ctx(
            LogLevel::Warn,
            component,
            message,
            Some(LogContext::for_connection(&conn)),
        );
        self.telemetry.record_connection(conn, false);
    }

    /// Id of the first rule named `name`, for the paths that only carry the rule name.
    #[cfg(not(windows))]
    pub(super) fn rule_id_by_name(&self, name: &str) -> Option<String> {
        self.profile
            .read()
            .rules
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.id.clone())
    }

    /// Removes the rules whose `expiresAt` has passed at `now` from the active profile and returns
    /// their ids. Logs one INFO line, wakes the DNS server refresh and notifies
    /// [`Self::subscribe_rule_expiry`] subscribers. The caller persists the profile.
    pub fn sweep_expired_rules(&self, now: chrono::DateTime<Utc>) -> Vec<String> {
        let removed = {
            let mut prof = self.profile.write();
            let ids = RuleEngine::expired_rule_ids(&prof.rules, now);
            if !ids.is_empty() {
                prof.rules.retain(|r| !ids.contains(&r.id));
            }
            ids
        };
        if removed.is_empty() {
            return removed;
        }
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_RULE,
            format!(
                "Removed {} expired temporary rule(s): {}",
                removed.len(),
                removed.join(", ")
            ),
        );
        self.schedule_dns_server_refresh();
        let _ = self.rule_expiry_tx.send(removed.clone());
        removed
    }

    /// Periodic sweep: removes expired rules and saves the profile when any was removed.
    fn sweep_expired_rules_and_save(&self) {
        if self.sweep_expired_rules(Utc::now()).is_empty() {
            return;
        }
        if let Err(err) = self.save_profile_default() {
            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_RULE,
                format!("Could not save the profile after removing expired rules: {err}"),
            );
        }
    }

    /// Subscribes to the ids of the rules removed by the expiry sweeper.
    pub fn subscribe_rule_expiry(&self) -> tokio::sync::broadcast::Receiver<Vec<String>> {
        self.rule_expiry_tx.subscribe()
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
                        matched_rule_id: FAKE_IP_UNMAPPED_RULE_ID.to_string(),
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

        let decision = unknown_process_decision(&self.profile.read().security_policy);
        if kill_switch_enabled && configured_action == RuleAction::Direct {
            self.telemetry.push_log(
                LogLevel::Warn,
                component,
                format!(
                    "Unattributed socket on client port {} -> {}:{} (reason={}); overriding unknownProcessAction=Direct to Block because killSwitchEnabled=true",
                    client_port, target_host, target_port, reason
                ),
            );
            (decision.action, decision.rule_name.to_string())
        } else {
            self.telemetry.push_log(
                LogLevel::Warn,
                component,
                format!(
                    "Unattributed socket on client port {} -> {}:{} (reason={}); applying unknownProcessAction={:?} (killSwitchEnabled={})",
                    client_port, target_host, target_port, reason, configured_action, kill_switch_enabled
                ),
            );
            (decision.action, decision.rule_name.to_string())
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

    /// Predicts the outcome of `req` with the same policy functions the relays use (rules, QUIC,
    /// DoT / DoQ, unknown process, kill switch against the cached proxy health).
    fn predict_request(&self, req: &ConnectionRequest) -> super::policy::PredictedOutcome {
        let eval = self.evaluate_rule(req);
        let health = self.proxy_health_snapshot();
        let prof = self.profile.read();
        predict_from_evaluation(&prof, req, eval, &health, self.policy_ports())
    }

    pub fn simulate_connection(&self, req: ConnectionRequest) -> TrackedConnection {
        let outcome = self.predict_request(&req);
        let eval = outcome.evaluation.clone();
        let route_label = self.format_action_label(&eval.action);
        let is_proxied = matches!(
            eval.action,
            RuleAction::Proxy { .. } | RuleAction::Chain { .. }
        );
        let block_reason = outcome.block_reason();
        let blocked = block_reason.is_some();

        let resolved_domain = eval.effective_domain.clone().or_else(|| {
            if req.target_host.parse::<IpAddr>().is_err() {
                let _ = self.dns.allocate_or_get(&req.target_host);
                Some(req.target_host.clone())
            } else {
                None
            }
        });

        let process_name = ProcessResolver::extract_basename(&req.process_name);
        let process_path = req
            .process_path
            .clone()
            .unwrap_or_else(|| req.process_name.clone());
        let tracked = if let Some(reason) = block_reason {
            TrackedConnection::blocked(
                BlockedRecord::new(reason, req.protocol, eval.matched_rule_name.clone())
                    .process(process_name, process_path, 0)
                    .target(req.target_host.clone(), req.target_port)
                    .with_domain(resolved_domain)
                    .with_ip(req.target_ip.clone())
                    .with_rule_id(eval.matched_rule_id.clone())
                    .simulated(),
            )
        } else {
            TrackedConnection {
                id: Uuid::new_v4().to_string(),
                pid: 0,
                process_name,
                process_path,
                target_host: req.target_host.clone(),
                resolved_domain,
                target_port: req.target_port,
                protocol: req.protocol,
                matched_rule: eval.matched_rule_name.clone(),
                route_label: route_label.clone(),
                latency_ms: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                status: ConnectionStatus::Active,
                started_at: Utc::now(),
                error_detail: None,
                block_reason: None,
                matched_rule_id: Some(eval.matched_rule_id.clone()),
                proxy_id: None,
                target_ip: req.target_ip.clone(),
                simulated: true,
            }
        };

        let log_level = if blocked {
            LogLevel::Warn
        } else {
            LogLevel::Info
        };
        self.telemetry.push_log_ctx(
            log_level,
            COMPONENT_RULE,
            format!(
                "[{}] {}:{} -> {} ({})",
                tracked.process_name,
                tracked.target_host,
                tracked.target_port,
                tracked.route_label,
                tracked.matched_rule
            ),
            Some(LogContext::for_connection(&tracked)),
        );

        self.telemetry
            .record_connection(tracked.clone(), is_proxied);
        tracked
    }

    /// Logs one Info line counting the established TCP connections opened before the engine started
    /// whose process now matches a Proxy, Chain or Block rule. Windows redirects new connections
    /// only, so these keep their original route (and bypass Block rules) until the application
    /// reconnects. Read-only: one IP Helper table dump, nothing is reset.
    #[cfg(windows)]
    fn report_preexisting_connections(&self) {
        let own_pid = std::process::id();
        let sockets = self
            .process_resolver
            .scan_established_tcp_sockets(PREEXISTING_SCAN_LIMIT);
        let mut per_process: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        {
            let prof = self.profile.read();
            for sock in sockets.into_iter().filter(|sock| sock.pid != own_pid) {
                let req = ConnectionRequest {
                    process_name: sock.process_name.clone(),
                    process_path: Some(sock.process_path),
                    target_host: sock.remote_ip.clone(),
                    target_ip: Some(sock.remote_ip),
                    target_port: sock.remote_port,
                    protocol: TransportProtocol::Tcp,
                };
                let eval = RuleEngine::evaluate(&req, &prof.rules, &prof.default_action, None);
                if matches!(
                    eval.action,
                    RuleAction::Proxy { .. } | RuleAction::Chain { .. } | RuleAction::Block
                ) {
                    *per_process.entry(sock.process_name).or_insert(0) += 1;
                }
            }
        }
        if let Some(message) = format_preexisting_connections_notice(per_process) {
            self.telemetry
                .push_log(LogLevel::Info, COMPONENT_ENGINE, message);
        }
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

            let tracked = if eval.action == RuleAction::Block {
                let mut blocked = TrackedConnection::blocked(
                    BlockedRecord::new(
                        block_reason_for_rule(&eval.matched_rule_id),
                        TransportProtocol::Tcp,
                        eval.matched_rule_name,
                    )
                    .process(sock.process_name, sock.process_path, sock.pid)
                    .target(sock.remote_ip.clone(), sock.remote_port)
                    .with_ip(Some(sock.remote_ip))
                    .with_domain(eval.effective_domain)
                    .with_rule_id(eval.matched_rule_id)
                    .simulated(),
                );
                blocked.id = conn_id;
                blocked
            } else {
                TrackedConnection {
                    id: conn_id,
                    pid: sock.pid,
                    process_name: sock.process_name,
                    process_path: sock.process_path,
                    target_host: sock.remote_ip.clone(),
                    resolved_domain: eval.effective_domain,
                    target_port: sock.remote_port,
                    protocol: TransportProtocol::Tcp,
                    matched_rule: eval.matched_rule_name,
                    route_label,
                    latency_ms: 0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    status: ConnectionStatus::Active,
                    started_at: Utc::now(),
                    error_detail: None,
                    block_reason: None,
                    matched_rule_id: Some(eval.matched_rule_id),
                    proxy_id: None,
                    target_ip: Some(sock.remote_ip),
                    simulated: true,
                }
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
        self.proxy_health
            .write()
            .insert(proxy_id.to_string(), report.clone());

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
                    incoming_creds.has_password = incoming_creds.has_stored_password();
                }
                *existing = node;
            } else {
                if let Some(ref mut incoming_creds) = node.auth {
                    incoming_creds.has_password = incoming_creds.has_stored_password();
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

    /// Moves `proxy_id` to the front of the proxy list (making it primary) and enables it.
    /// Also promotes `proxy_id` to the front of any failover chain that references it.
    pub fn set_primary_proxy(&self, proxy_id: &str) -> bool {
        let mut prof = self.profile.write();
        let Some(pos) = prof.proxies.iter().position(|p| p.id == proxy_id) else {
            return false;
        };
        let mut node = prof.proxies.remove(pos);
        node.enabled = true;
        prof.proxies.insert(0, node);
        for chain in &mut prof.chains {
            if let Some(cpos) = chain.proxy_ids.iter().position(|id| id == proxy_id) {
                let id = chain.proxy_ids.remove(cpos);
                chain.proxy_ids.insert(0, id);
            }
        }
        drop(prof);
        self.sync_upstream_proxy_exclusions();
        true
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
        // Same lock as `register_self_proxy_connect_hint`: neither update may be lost.
        let _guard = self.relay_caches.upstream_endpoints.lock();
        self.nat_table.set_upstream_endpoints(upstream_endpoints);
    }

    /// Rebuilds the DNS server identity patterns from the built-in defaults and the profile list.
    fn configure_dns_server_tracker(&self) {
        let user = self.profile.read().dns_config.dns_server_processes.clone();
        self.dns_server_tracker
            .configure(&self.constants.dns.default_dns_server_processes, &user);
    }

    /// `true` when an explicit Block rule that names the process drops its DNS query to `dst`.
    /// The kill switch, the remote DNS option and the default policy never block a DNS server.
    pub fn dns_server_block_verdict(
        &self,
        identity: &ProcessIdentity,
        dst: IpAddr,
        proto: DnsProto,
    ) -> bool {
        let prof = self.profile.read();
        dns_server_block_verdict(&prof.rules, &prof.default_action, identity, dst, proto)
    }

    /// Rescans the DNS server processes and, on Linux, pushes the user id sets to the firewall.
    /// Blocking: run it from a blocking context.
    pub fn refresh_dns_server_tracker(&self) {
        // One scan + apply + firewall sync at a time, and never concurrently with a firewall
        // reload: an old-matcher scan must not land after a reload, and the applied-sets marker
        // must not go stale against it.
        let _sync = self.dns_server_tracker.lock_sync();
        // The firewall cannot tell UDP from TCP per user id in one set, so a uid is dropped only
        // when both protocols are blocked for the process.
        let is_blocked = |identity: &ProcessIdentity| {
            [DnsProto::Udp, DnsProto::Tcp].into_iter().all(|proto| {
                self.dns_server_block_verdict(identity, IpAddr::V4(Ipv4Addr::UNSPECIFIED), proto)
            })
        };
        self.dns_server_tracker.refresh(&is_blocked);
        self.sync_dns_server_uid_sets();
    }

    /// Refreshes the DNS server tracker after a change the block verdict depends on (a rule added
    /// or removed). Runs on the blocking pool when called from an async runtime, and does nothing
    /// while the engine is stopped.
    fn schedule_dns_server_refresh(&self) {
        if !self.is_running() {
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let ctrl = self.clone();
                handle.spawn_blocking(move || ctrl.refresh_dns_server_tracker());
            }
            Err(_) => self.refresh_dns_server_tracker(),
        }
    }

    fn sync_dns_server_uid_sets(&self) {
        let sets = self.dns_server_tracker.uid_sets();
        if sets == self.dns_server_tracker.applied_uid_sets()
            || !self.interceptor_backend.is_active()
        {
            return;
        }
        match self
            .interceptor_backend
            .sync_dns_server_uids(&sets.exempt, &sets.block)
        {
            Ok(()) => self.dns_server_tracker.mark_uid_sets_applied(sets),
            Err(err) => {
                self.push_rate_limited_warn(
                    "dns-server-uid-sync",
                    COMPONENT_ENGINE,
                    format!("Could not update the DNS server user id sets: {err}"),
                );
            }
        }
    }

    /// Replaces the active in-memory profile, synchronizes logging and upstream loop exclusions,
    /// and if the engine is running when `securityPolicy`, `dnsConfig`, or `proxies` changed,
    /// atomically reapplies active interception rules and re-runs proxy bootstrap.
    ///
    /// The profile is validated first (`dnsConfig.dnsServerProcesses`): an invalid one is refused
    /// and the active profile stays untouched, whichever entry point (IPC, CLI, desktop) sent it.
    pub fn replace_profile(&self, mut new_profile: ProfileConfig) -> RouteWardResult<()> {
        new_profile.dns_config.validate()?;
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
                    incoming_creds.has_password = incoming_creds.has_stored_password();
                }
            }
            let sec_diff = prof.security_policy != new_profile.security_policy;
            let dns_diff = prof.dns_config != new_profile.dns_config;
            let prx_diff = prof.proxies != new_profile.proxies;
            RuleEngine::sort_rules(&mut new_profile.rules);
            *prof = new_profile;
            (sec_diff, dns_diff, prx_diff)
        };

        if proxies_changed {
            self.udp_manager.capability_cache().clear();
            self.udp_manager.clear_all();
            self.bootstrapped_proxy_endpoints.clear();
        }
        self.sync_upstream_proxy_exclusions();
        self.configure_dns_server_tracker();
        if self.is_running() {
            run_blocking_section(|| self.refresh_dns_server_tracker());
        }

        if self.is_running() && (security_changed || dns_changed || proxies_changed) {
            run_blocking_section(|| {
                self.reapply_active_interception_rules(security_changed, dns_changed);
            });
            if let Ok(rt_handle) = tokio::runtime::Handle::try_current() {
                let ctrl_boot = self.clone();
                rt_handle.spawn(async move {
                    let before = ctrl_boot.nat_table.upstream_endpoints();
                    ctrl_boot.bootstrap_resolve_proxy_hosts().await;
                    let after = ctrl_boot.nat_table.upstream_endpoints();
                    if before != after && ctrl_boot.interceptor_backend.is_active() {
                        // The reload takes the tracker's sync lock and may run a firewall sync:
                        // keep it off the async worker.
                        let ctrl_reload = ctrl_boot.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let _ = ctrl_reload.interceptor_backend.reload(ctrl_reload.clone());
                        })
                        .await;
                    }
                });
            }
        }
        Ok(())
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
        self.replace_profile(loaded)?;
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
        {
            let mut prof = self.profile.write();
            if let Some(existing) = prof.rules.iter_mut().find(|r| r.id == rule.id) {
                *existing = rule;
            } else {
                prof.rules.push(rule);
            }
            RuleEngine::sort_rules(&mut prof.rules);
        }
        self.schedule_dns_server_refresh();
    }

    pub fn remove_rule(&self, rule_id: &str) {
        {
            let mut prof = self.profile.write();
            prof.rules.retain(|r| r.id != rule_id);
        }
        self.schedule_dns_server_refresh();
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

    /// Same as [`push_rate_limited_warn`](Self::push_rate_limited_warn) at INFO level, for
    /// repetitive informational events.
    pub fn push_rate_limited_info(
        &self,
        category_key: &str,
        component: &str,
        message: impl Into<String>,
    ) -> u64 {
        let (should_log, count) = self.warn_rate_limiter.should_log(category_key);
        if should_log {
            self.telemetry.push_log(
                LogLevel::Info,
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

    /// Returns the number of later UDP fragments dropped under the kill switch because the first
    /// fragment of their datagram was never seen (or its verdict had expired or been evicted).
    pub fn orphan_fragment_drop_count(&self) -> u64 {
        self.orphan_fragment_drop_count.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn preexisting_connections_notice_ranks_processes_and_caps_the_list() {
        assert!(format_preexisting_connections_notice(Default::default()).is_none());

        let mut counts = std::collections::HashMap::new();
        for (name, count) in [
            ("chrome.exe", 12),
            ("firefox.exe", 4),
            ("a.exe", 1),
            ("b.exe", 1),
            ("c.exe", 1),
            ("d.exe", 1),
        ] {
            counts.insert(name.to_string(), count);
        }
        let notice = format_preexisting_connections_notice(counts).expect("notice");
        assert!(notice.starts_with("20 connections opened before start"));
        assert!(notice.contains("chrome.exe x12, firefox.exe x4, a.exe x1"));
        assert!(notice.contains("and 1 more"));
        assert!(!notice.contains("d.exe"));
    }

    use super::*;
    use crate::config::PortRange;
    use std::sync::atomic::AtomicU16;

    fn test_constants() -> SystemConstants {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        constants.network.default_relay_tcp_port = 0;
        constants.network.default_transparent_tcp_port = 0;
        constants.network.default_dns_listen_port = 0;
        constants.network.default_local_name_inspect_port = 0;
        constants
    }

    fn test_profile() -> ProfileConfig {
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile
    }

    fn rule(id: &str, priority: i32) -> RoutingRule {
        RoutingRule {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            priority,
            process_patterns: Vec::new(),
            domain_patterns: Vec::new(),
            ip_cidrs: Vec::new(),
            port_ranges: Vec::<PortRange>::new(),
            protocol: TransportProtocol::Any,
            action: RuleAction::Direct,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn engine_start_fails_and_interceptor_is_refused_when_a_listener_port_is_taken() {
        let mut constants = test_constants();
        let blocker =
            std::net::TcpListener::bind(format!("{}:0", constants.network.transparent_bind_host))
                .expect("bind blocker");
        constants.network.default_transparent_tcp_port =
            blocker.local_addr().expect("blocker addr").port();
        let controller = RouteWardController::new(constants, test_profile(), "en");

        assert!(controller.start_engine().is_err());

        assert!(
            !controller.is_running(),
            "a failed listener bind must leave the engine stopped"
        );
        let logs = controller.telemetry.list_logs();
        assert!(
            logs.iter().any(|l| l.level == LogLevel::Error
                && l.component == COMPONENT_ENGINE
                && l.message
                    .contains("Failed to bind the transparent TCP listener")),
            "expected a bind error log, got: {logs:?}"
        );
        let result = controller.start_transparent_interceptor();
        assert!(
            result.is_err(),
            "the interceptor must never start without bound listeners"
        );
        assert!(!controller.interceptor_backend.is_active());
        drop(blocker);
    }

    #[tokio::test]
    async fn engine_start_succeeds_when_every_port_is_free() {
        let controller = RouteWardController::new(test_constants(), test_profile(), "en");
        controller.start_engine().expect("engine start");
        assert!(controller.is_running());
        controller.stop_engine();
        assert!(!controller.is_running());
    }

    /// Interleavings tried by the concurrent start/stop test.
    const CONCURRENT_LIFECYCLE_ROUNDS: usize = 20;

    /// Time given to the listener tasks to run until they are parked in accept/recv.
    const LISTENER_SETTLE_DELAY: Duration = Duration::from_millis(30);

    /// First port handed out to the tests that need fixed engine ports. It sits below every
    /// default ephemeral range (Linux 32768-60999, Windows and macOS 49152-65535), so the
    /// listeners and client sockets that other tests bind on port 0 can never be assigned one
    /// of these ports behind our back.
    const FIXED_PORT_RANGE_START: u16 = 20_000;

    /// Exclusive end of the range described by `FIXED_PORT_RANGE_START`.
    const FIXED_PORT_RANGE_END: u16 = 32_000;

    /// Next candidate port. Shared by the whole test process, so two tests running in parallel
    /// are never handed the same port, which a release-then-reuse reservation cannot guarantee.
    static NEXT_FIXED_PORT: AtomicU16 = AtomicU16::new(FIXED_PORT_RANGE_START);

    /// Reserves `count` distinct ports that are free for both TCP and UDP on `host`. Ports are
    /// unique across every test of the process and come from a range the OS never uses for
    /// ephemeral ports, so a port stays free from this call until the engine binds it.
    fn reserve_free_ports(host: &str, count: usize) -> Vec<u16> {
        let mut ports = Vec::with_capacity(count);
        while ports.len() < count {
            let port = NEXT_FIXED_PORT.fetch_add(1, Ordering::SeqCst);
            assert!(
                port < FIXED_PORT_RANGE_END,
                "fixed test port range exhausted"
            );
            let tcp_free = std::net::TcpListener::bind(format!("{host}:{port}")).is_ok();
            let udp_free = std::net::UdpSocket::bind(format!("{host}:{port}")).is_ok();
            if tcp_free && udp_free {
                ports.push(port);
            }
        }
        ports
    }

    /// Lets every listener task run until it is parked in accept/recv.
    async fn settle_listener_tasks() {
        tokio::time::sleep(LISTENER_SETTLE_DELAY).await;
    }

    /// Constants whose listener ports are fixed (not ephemeral) so a restart must rebind them.
    fn fixed_port_constants() -> SystemConstants {
        let mut constants = test_constants();
        let host = constants.network.transparent_bind_host.clone();
        let ports = reserve_free_ports(&host, 4);
        constants.network.default_relay_tcp_port = ports[0];
        constants.network.default_transparent_tcp_port = ports[1];
        constants.network.default_dns_listen_port = ports[2];
        constants.network.default_local_name_inspect_port = ports[3];
        constants
    }

    /// Pause between two attempts while waiting for the OS to release a port.
    const PORT_RELEASE_POLL_INTERVAL: Duration = Duration::from_millis(1);

    /// Starts the engine, retrying while a fixed port is still transiently held.
    ///
    /// Closing a socket does not release its port while a concurrent `fork` (any other test
    /// spawning a helper process, such as the DNS cache flush) still holds a copy of the
    /// descriptor until its `exec`. That window lasts well under a millisecond, whereas a leaked
    /// listener stays bound for good, so the waits in these tests are bounded by
    /// `ENGINE_SHUTDOWN_JOIN_TIMEOUT` and a real leak still fails the test.
    async fn start_engine_when_ports_release(controller: &RouteWardController) {
        let deadline = tokio::time::Instant::now() + ENGINE_SHUTDOWN_JOIN_TIMEOUT;
        loop {
            match controller.start_engine() {
                Ok(()) => return,
                Err(err) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "engine start kept failing: {err}"
                    );
                    tokio::time::sleep(PORT_RELEASE_POLL_INTERVAL).await;
                }
            }
        }
    }

    /// Asserts the relay port can be bound again once the engine is stopped (see
    /// `start_engine_when_ports_release` for why the wait is bounded rather than absent).
    async fn assert_relay_port_bindable(constants: &SystemConstants) {
        let addr = format!(
            "{}:{}",
            constants.network.local_bind_host, constants.network.default_relay_tcp_port
        );
        let deadline = tokio::time::Instant::now() + ENGINE_SHUTDOWN_JOIN_TIMEOUT;
        loop {
            match std::net::TcpListener::bind(&addr) {
                Ok(_) => return,
                Err(err) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "relay port {addr} must be free after stop: {err}"
                    );
                    tokio::time::sleep(PORT_RELEASE_POLL_INTERVAL).await;
                }
            }
        }
    }

    /// Polls until every fixed engine port can be bound again, yielding to the runtime between
    /// attempts; panics with the ports still in use once `ENGINE_SHUTDOWN_JOIN_TIMEOUT` elapses.
    async fn wait_until_engine_ports_bindable(constants: &SystemConstants) {
        let any_host = constants.network.transparent_bind_host.clone();
        let net = &constants.network;
        let tcp_ports = [
            net.default_relay_tcp_port,
            net.default_transparent_tcp_port,
            net.default_dns_listen_port,
        ];
        let udp_ports = [
            net.default_dns_listen_port,
            net.default_local_name_inspect_port,
        ];
        let deadline = tokio::time::Instant::now() + ENGINE_SHUTDOWN_JOIN_TIMEOUT;
        loop {
            let busy: Vec<String> = tcp_ports
                .iter()
                .filter(|port| std::net::TcpListener::bind(format!("{any_host}:{port}")).is_err())
                .map(|port| format!("tcp/{port}"))
                .chain(
                    udp_ports
                        .iter()
                        .filter(|port| {
                            std::net::UdpSocket::bind(format!("{any_host}:{port}")).is_err()
                        })
                        .map(|port| format!("udp/{port}")),
                )
                .collect();
            if busy.is_empty() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "engine ports still in use after stop: {busy:?}"
            );
            tokio::time::sleep(LISTENER_SETTLE_DELAY).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn engine_restart_rebinds_listeners_after_stop() {
        let constants = fixed_port_constants();
        let controller = RouteWardController::new(constants.clone(), test_profile(), "en");

        start_engine_when_ports_release(&controller).await;
        settle_listener_tasks().await;
        controller.stop_engine();
        assert_relay_port_bindable(&constants).await;

        start_engine_when_ports_release(&controller).await;
        assert!(controller.is_running());
        controller.stop_engine();
        assert_relay_port_bindable(&constants).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_start_and_stop_never_leave_listeners_bound() {
        let constants = fixed_port_constants();
        let controller = RouteWardController::new(constants.clone(), test_profile(), "en");
        for _ in 0..CONCURRENT_LIFECYCLE_ROUNDS {
            let starter = controller.clone();
            let stopper = controller.clone();
            let start = tokio::spawn(async move {
                let _ = starter.start_engine();
            });
            let stop = tokio::spawn(async move { stopper.stop_engine() });
            start.await.expect("start task");
            stop.await.expect("stop task");
            controller.stop_engine();
            assert_relay_port_bindable(&constants).await;
        }
    }

    #[tokio::test]
    async fn engine_restart_rebinds_listeners_on_a_current_thread_runtime() {
        let constants = fixed_port_constants();
        let controller = RouteWardController::new(constants.clone(), test_profile(), "en");

        start_engine_when_ports_release(&controller).await;
        settle_listener_tasks().await;
        controller.stop_engine();
        // On a current-thread runtime stop_engine cannot block, so the listener tasks drop their
        // sockets once this task yields; wait (bounded) until every engine port is free again.
        wait_until_engine_ports_bindable(&constants).await;
        assert_relay_port_bindable(&constants).await;

        start_engine_when_ports_release(&controller).await;
        controller.stop_engine();
    }

    #[test]
    fn upsert_rule_and_profile_replacement_keep_rules_sorted_by_priority() {
        let mut profile = test_profile();
        profile.rules = vec![rule("late", 30), rule("early", 10)];
        let controller = RouteWardController::new(test_constants(), profile.clone(), "en");
        let ids = |c: &RouteWardController| -> Vec<String> {
            c.profile
                .read()
                .rules
                .iter()
                .map(|r| r.id.clone())
                .collect()
        };
        assert_eq!(ids(&controller), ["early", "late"]);

        controller.upsert_rule(rule("middle", 20));
        assert_eq!(ids(&controller), ["early", "middle", "late"]);

        profile.rules = vec![rule("c", 3), rule("a", 1), rule("b", 2)];
        controller.replace_profile(profile).expect("valid profile");
        assert_eq!(ids(&controller), ["a", "b", "c"]);
    }

    #[test]
    fn simulated_connection_carries_no_fabricated_measurements() {
        let controller = RouteWardController::new(test_constants(), test_profile(), "en");
        let tracked = controller.simulate_connection(ConnectionRequest {
            process_name: "demo.exe".to_string(),
            process_path: None,
            target_host: "example.test".to_string(),
            target_ip: None,
            target_port: 443,
            protocol: TransportProtocol::Tcp,
        });
        assert_eq!(tracked.pid, 0);
        assert_eq!(tracked.latency_ms, 0);
        assert_eq!(tracked.rx_bytes, 0);
        assert_eq!(tracked.tx_bytes, 0);
    }

    /// A path that the built-in defaults of the running OS recognise as a DNS server, and the
    /// default entry that removes it.
    fn default_dns_server_sample() -> (String, String) {
        if cfg!(windows) {
            let root = crate::interceptor::dns_server_exempt::system_root_from_env();
            (
                format!(r"{root}\System32\dns.exe"),
                r"!%SystemRoot%\System32\dns.exe".to_string(),
            )
        } else {
            ("/usr/sbin/named".to_string(), "!named".to_string())
        }
    }

    #[test]
    fn profile_replacement_reconfigures_the_dns_server_identity_list() {
        let (sample, removal) = default_dns_server_sample();
        let controller = RouteWardController::new(test_constants(), test_profile(), "en");
        assert!(controller.dns_server_tracker.note_unknown_pid(11, &sample));

        let mut profile = test_profile();
        profile.dns_config.dns_server_processes = vec![removal];
        controller.replace_profile(profile).expect("valid profile");
        assert!(!controller.dns_server_tracker.note_unknown_pid(12, &sample));

        controller
            .replace_profile(test_profile())
            .expect("valid profile");
        assert!(controller.dns_server_tracker.note_unknown_pid(13, &sample));
    }

    #[test]
    fn profile_replacement_refuses_an_invalid_dns_server_list_and_keeps_the_active_profile() {
        let controller = RouteWardController::new(test_constants(), test_profile(), "en");
        let before = controller.profile.read().name.clone();

        for bad in ["*", "", "svchost.exe"] {
            let mut profile = test_profile();
            profile.name = "Rejected".to_string();
            profile.dns_config.dns_server_processes = vec![bad.to_string()];
            let err = controller
                .replace_profile(profile)
                .expect_err("invalid dnsServerProcesses entry must be refused");
            assert!(
                matches!(
                    err,
                    RouteWardError::ConfigError {
                        key: crate::error::ERR_KEY_CONFIG_JSON,
                        ..
                    }
                ),
                "unexpected error for {bad:?}: {err:?}"
            );
            assert_eq!(controller.profile.read().name, before);
        }

        let mut valid = test_profile();
        valid.dns_config.dns_server_processes = vec!["!dnsmasq".to_string()];
        controller
            .replace_profile(valid)
            .expect("a valid list is accepted");
    }

    #[test]
    fn controller_block_verdict_uses_only_explicit_block_rules_with_process_patterns() {
        let mut profile = test_profile();
        profile.default_action = RuleAction::Block;
        let mut block_named = rule("block-named", 5);
        block_named.action = RuleAction::Block;
        block_named.process_patterns = vec!["named".to_string()];
        profile.rules = vec![block_named];
        let controller = RouteWardController::new(test_constants(), profile, "en");
        let resolver = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
        let named = ProcessIdentity {
            pid: 5,
            name: "named".to_string(),
            executable_path: "/usr/sbin/named".to_string(),
        };
        let other = ProcessIdentity {
            pid: 6,
            name: "unbound".to_string(),
            executable_path: "/usr/sbin/unbound".to_string(),
        };
        assert!(controller.dns_server_block_verdict(&named, resolver, DnsProto::Udp));
        // The default policy is Block, yet it never blocks a DNS server.
        assert!(!controller.dns_server_block_verdict(&other, resolver, DnsProto::Udp));
    }

    #[cfg(windows)]
    #[test]
    fn windows_rescan_finds_the_sockets_of_a_matching_process() {
        let exe = std::env::current_exe().expect("current exe");
        let controller = RouteWardController::new(test_constants(), test_profile(), "en");
        controller
            .dns_server_tracker
            .configure(&[], &[exe.to_string_lossy().into_owned()]);
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp bind");
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("tcp bind");
        let udp_port = udp.local_addr().expect("udp addr").port();
        let tcp_port = tcp.local_addr().expect("tcp addr").port();

        assert!(controller.dns_server_tracker.is_empty());
        controller.refresh_dns_server_tracker();
        assert!(!controller.dns_server_tracker.is_empty());
        assert!(controller
            .dns_server_tracker
            .is_exempt_pid(std::process::id()));
        assert!(controller
            .dns_server_tracker
            .is_exempt_port(DnsProto::Udp, udp_port));
        assert!(controller
            .dns_server_tracker
            .is_exempt_port(DnsProto::Tcp, tcp_port));

        // Dropping the matching entry empties the tracker at the next rescan.
        controller.dns_server_tracker.configure(&[], &[]);
        controller.refresh_dns_server_tracker();
        assert!(controller.dns_server_tracker.is_empty());
    }
}
