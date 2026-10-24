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
use crate::dns::FakeIpEngine;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_PROXY_NOT_FOUND};
use crate::i18n::I18nRegistry;
use crate::interceptor::backend::Interceptor;
use crate::interceptor::nat::TransparentNatTable;
#[cfg(not(windows))]
use crate::interceptor::nftables::NftablesInterceptor;
#[cfg(windows)]
use crate::interceptor::windivert::WinDivertInterceptor;
#[cfg(not(windows))]
use crate::process::ProcessAttribution;
use crate::process::ProcessResolver;
use crate::proxy::sni::TlsSniExtractor;
use crate::proxy::uri::ProxyUriCodec;
use crate::proxy::ProxyConnector;
use crate::rules::{ConnectionRequest, RuleEngine, RuleEvaluationResult};
use crate::telemetry::{ConnectionStatus, LogLevel, TelemetryHub, TrackedConnection};
use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const COMPONENT_ENGINE: &str = "InterceptorEngine";
const COMPONENT_TRANSPARENT: &str = "TransparentRelay";
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

#[derive(Clone)]
pub struct RouteWardController {
    pub constants: Arc<SystemConstants>,
    pub profile: Arc<RwLock<ProfileConfig>>,
    pub i18n: I18nRegistry,
    pub dns: FakeIpEngine,
    pub process_resolver: ProcessResolver,
    pub telemetry: TelemetryHub,
    pub nat_table: TransparentNatTable,
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

        let controller = Self {
            constants: Arc::new(constants),
            profile: Arc::new(RwLock::new(profile)),
            i18n,
            dns,
            process_resolver,
            telemetry,
            nat_table,
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
        self.interceptor_backend.stop();
        self.running.store(false, Ordering::SeqCst);
        self.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_ENGINE,
            self.i18n.t("app.header.engine.stopped"),
        );
        self.telemetry.flush_file_logger();
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
            NftablesInterceptor::delete_nft_table(
                &self.constants.network.linux_nft_binary,
                &self.constants.network.linux_nft_table_name,
                &self.telemetry,
            )?;
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
        RuleEngine::evaluate(req, &prof.rules, &prof.default_action, Some(&self.dns))
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
        let upstream_endpoints: Vec<(Ipv4Addr, u16)> = {
            let prof = self.profile.read();
            prof.proxies
                .iter()
                .filter_map(|p| p.host.parse::<Ipv4Addr>().ok().map(|ip| (ip, p.port)))
                .collect()
        };
        self.nat_table.set_upstream_endpoints(upstream_endpoints);
    }

    /// Replaces the active in-memory profile and synchronizes logging and upstream loop exclusions.
    pub fn replace_profile(&self, mut new_profile: ProfileConfig) {
        self.telemetry
            .set_file_logging_enabled(new_profile.enable_logging);
        {
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
            *prof = new_profile;
        }
        self.sync_upstream_proxy_exclusions();
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
            .push_log(LogLevel::Info, COMPONENT_DNS, format!("{domain} -> {ip}"));
        Some(ip.to_string())
    }

    pub fn extract_sni_from_payload(&self, packet: &[u8]) -> Option<String> {
        TlsSniExtractor::extract_sni(packet)
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
        let eval = self.evaluate_rule(&ConnectionRequest {
            process_name: proc_id.name.clone(),
            process_path: Some(proc_id.executable_path.clone()),
            target_host: target_host.clone(),
            target_ip: None,
            target_port,
            protocol: TransportProtocol::Tcp,
        });

        let effective_host = eval
            .effective_domain
            .clone()
            .unwrap_or_else(|| target_host.clone());

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

    pub async fn handle_transparent_tcp_client(
        &self,
        mut client: TcpStream,
        peer_addr: SocketAddr,
    ) -> RouteWardResult<()> {
        if let Some(session) = self.nat_table.validate_relay_peer_addr(peer_addr) {
            let target_host = session.orig_dst_ip.to_string();
            let target_port = session.orig_dst_port;
            let resolved_domain = self.dns.resolve_fake_ip(&session.orig_dst_ip);
            let effective_host = resolved_domain
                .clone()
                .unwrap_or_else(|| target_host.clone());
            let is_proxied_rule = matches!(
                session.action,
                RuleAction::Proxy { .. } | RuleAction::Chain { .. }
            );
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
                            .open_outbound_stream(&RuleAction::Direct, &effective_host, target_port)
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

                let attribution = self
                    .process_resolver
                    .resolve_tcp_port_attribution(client_port);

                let (
                    pid,
                    proc_name,
                    proc_path,
                    eval_action,
                    matched_rule_name,
                    effective_domain,
                    res_source,
                ) = match attribution {
                    ProcessAttribution::Single(identity) => {
                        let eval = self.evaluate_rule(&ConnectionRequest {
                            process_name: identity.name.clone(),
                            process_path: Some(identity.executable_path.clone()),
                            target_host: target_host.clone(),
                            target_ip: Some(target_host.clone()),
                            target_port,
                            protocol: TransportProtocol::Tcp,
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
                    } => {
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
                            target_host: target_host.clone(),
                            target_ip: Some(target_host.clone()),
                            target_port,
                            protocol: TransportProtocol::Tcp,
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
                    ProcessAttribution::Unknown { reason } => {
                        let unknown_action = self
                            .profile
                            .read()
                            .security_policy
                            .unknown_process_action
                            .clone();
                        let resolved_dom = self.dns.resolve_fake_ip(orig_dst.ip());
                        self.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Unattributed socket on client port {} -> {}:{} (reason={}); applying unknownProcessAction={:?}",
                                client_port, target_host, target_port, reason, unknown_action
                            ),
                        );
                        (
                            0,
                            "unknown".to_string(),
                            "unknown".to_string(),
                            unknown_action,
                            "SecurityPolicy:unknownProcessAction".to_string(),
                            resolved_dom,
                            "procfs_unknown",
                        )
                    }
                };

                let effective_host = effective_domain
                    .clone()
                    .unwrap_or_else(|| target_host.clone());

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

                let is_proxied_rule = matches!(
                    eval_action,
                    RuleAction::Proxy { .. } | RuleAction::Chain { .. }
                );
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
                                    &effective_host,
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
                let addr = format!("{target_host}:{target_port}");
                ProxyConnector::connect_tcp_marked(&addr, self.constants.network.linux_fwmark)
                    .await
                    .map_err(RouteWardError::Io)
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
                ProxyConnector::connect_single(&node, target_host, target_port, &self.constants)
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
                ProxyConnector::connect_group(
                    strategy,
                    &hops,
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
}
