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

use parking_lot::RwLock;
use routeward_core::checker::ProxyHealthReport;
use routeward_core::config::{
    InterceptionMode, ProfileConfig, ProxyChain, ProxyNode, RoutingRule, SystemConstants,
    ThemeForgeCatalog,
};
use routeward_core::dns::FakeIpEntry;
use routeward_core::error::ERR_KEY_DAEMON_DISCONNECTED;
use routeward_core::i18n::I18nRegistry;
use routeward_core::interceptor::SystemDiagnostics;
use routeward_core::ipc::protocol::{
    read_bounded_line, DaemonFullState, IpcCommand, IpcRequest, IpcResponse, IpcStreamEvent,
    ReadLineOutcome,
};
use routeward_core::ipc::transport::connect_ipc_stream;
use routeward_core::ipc::{generate_ephemeral_token, IpcClient};
use routeward_core::rules::{ConnectionRequest, RuleEvaluationResult};
use routeward_core::system::{LaunchedProcessReport, SystemProxyManager};
use routeward_core::telemetry::{
    ConnectionStatus, LogEntry, LogLevel, TelemetryEvent, TelemetrySnapshot, TrackedConnection,
};
use serde::de::DeserializeOwned;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};

const COMPONENT_DESKTOP_BRIDGE: &str = "DesktopBridge";

#[derive(Clone)]
pub struct DesktopCommandBridge {
    constants: Arc<SystemConstants>,
    i18n: I18nRegistry,
    ipc_client: IpcClient,
    state: Arc<RwLock<DaemonFullState>>,
    daemon_connected: Arc<AtomicBool>,
}

impl DesktopCommandBridge {
    pub fn new(constants: SystemConstants, default_profile: ProfileConfig, locale: &str) -> Self {
        let i18n = I18nRegistry::new(locale);
        let ipc_client = IpcClient::new(constants.ipc.clone());
        let net = &constants.network;

        let initial_diagnostics = SystemDiagnostics {
            daemon_connected: false,
            running: false,
            os_name: std::env::consts::OS.to_uppercase(),
            interception_mode: default_profile.interception_mode,
            elevated_privileges: false,
            relay_tcp_endpoint: format!("{}:{}", net.local_bind_host, net.default_relay_tcp_port),
            relay_http_endpoint: format!("{}:{}", net.local_bind_host, net.default_relay_http_port),
            dns_endpoint: format!("{}:{}", net.local_bind_host, net.default_dns_listen_port),
            fake_ip_cidr: default_profile.dns_config.fake_ip_cidr.clone(),
            active_locale: i18n.get_locale(),
        };

        let initial_state = DaemonFullState {
            diagnostics: initial_diagnostics,
            profile: default_profile,
            telemetry: TelemetrySnapshot::default(),
            connections: Vec::new(),
            logs: Vec::new(),
            fake_ips: Vec::new(),
        };

        let bridge = Self {
            constants: Arc::new(constants),
            i18n,
            ipc_client,
            state: Arc::new(RwLock::new(initial_state)),
            daemon_connected: Arc::new(AtomicBool::new(false)),
        };

        bridge.mark_disconnected();
        bridge
    }

    /// Spawns the background IPC subscription and automatic reconnection task.
    pub fn spawn_background_sync(&self) {
        let bridge = self.clone();
        tokio::spawn(async move {
            let reconnect_delay = Duration::from_millis(bridge.constants.ipc.reconnect_interval_ms);
            loop {
                if bridge.run_subscription_session().await.is_err() {
                    bridge.mark_disconnected();
                }
                tokio::time::sleep(reconnect_delay).await;
            }
        });
    }

    async fn run_subscription_session(&self) -> Result<(), String> {
        let full_state: DaemonFullState = self
            .ipc_client
            .call_typed(IpcCommand::GetState)
            .await
            .map_err(|e| e.to_string())?;
        self.apply_full_state(full_state);

        let stream = connect_ipc_stream(&self.constants.ipc)
            .await
            .map_err(|e| e.to_string())?;
        let (read_half, mut write_half) = tokio::io::split(stream);

        let sub_req = IpcRequest {
            id: generate_ephemeral_token(),
            command: IpcCommand::Subscribe,
        };
        let mut req_bytes = serde_json::to_vec(&sub_req).map_err(|e| e.to_string())?;
        req_bytes.push(b'\n');
        write_half
            .write_all(&req_bytes)
            .await
            .map_err(|e| e.to_string())?;
        write_half.flush().await.map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(read_half);
        let max_line = self.constants.ipc.max_line_bytes;
        // Subscription stream stays open indefinitely while events arrive or until EOF
        let sub_timeout_ms = self.constants.ipc.idle_timeout_ms.max(60_000);

        match read_bounded_line(&mut reader, max_line, sub_timeout_ms).await {
            ReadLineOutcome::Line(line) => {
                let ack: IpcResponse = serde_json::from_str(&line).map_err(|e| e.to_string())?;
                if !ack.ok {
                    return Err(ack.error.unwrap_or_else(|| "subscribe failed".to_string()));
                }
            }
            other => return Err(format!("subscribe handshake failed: {other:?}")),
        }

        loop {
            match read_bounded_line(&mut reader, max_line, sub_timeout_ms).await {
                ReadLineOutcome::Line(line) => {
                    if let Ok(stream_ev) = serde_json::from_str::<IpcStreamEvent>(&line) {
                        match stream_ev {
                            IpcStreamEvent::Event(ev) => self.apply_telemetry_event(ev),
                            IpcStreamEvent::Resync { .. } => {
                                if let Ok(fresh) = self
                                    .ipc_client
                                    .call_typed::<DaemonFullState>(IpcCommand::GetState)
                                    .await
                                {
                                    self.apply_full_state(fresh);
                                }
                            }
                        }
                    }
                }
                ReadLineOutcome::IdleTimeout => {
                    // Heartbeat check via GetDiagnostics when stream is quiet
                    match self
                        .ipc_client
                        .call_typed::<SystemDiagnostics>(IpcCommand::GetDiagnostics)
                        .await
                    {
                        Ok(mut diag) => {
                            diag.daemon_connected = true;
                            self.state.write().diagnostics = diag;
                        }
                        Err(err) => return Err(err.to_string()),
                    }
                }
                ReadLineOutcome::Eof
                | ReadLineOutcome::LineTooLong
                | ReadLineOutcome::IoError(_) => {
                    return Err("IPC event stream closed".to_string());
                }
            }
        }
    }

    fn apply_full_state(&self, mut full_state: DaemonFullState) {
        full_state.diagnostics.daemon_connected = true;
        self.daemon_connected.store(true, Ordering::SeqCst);
        *self.state.write() = full_state;
    }

    fn apply_telemetry_event(&self, event: TelemetryEvent) {
        let mut st = self.state.write();
        match event {
            TelemetryEvent::Telemetry(snap) => {
                st.telemetry = snap;
            }
            TelemetryEvent::ConnectionUpdated(conn) => {
                if let Some(existing) = st.connections.iter_mut().find(|c| c.id == conn.id) {
                    *existing = conn;
                } else {
                    st.connections.insert(0, conn);
                }
            }
            TelemetryEvent::ConnectionsCleared => {
                st.connections
                    .retain(|c| c.status == ConnectionStatus::Active);
            }
            TelemetryEvent::Log(entry) => {
                st.logs.insert(0, entry);
            }
            TelemetryEvent::LogsCleared => {
                st.logs.clear();
            }
        }
    }

    fn mark_disconnected(&self) {
        let was_connected = self.daemon_connected.swap(false, Ordering::SeqCst);
        let mut st = self.state.write();
        st.diagnostics.daemon_connected = false;
        st.diagnostics.running = false;
        if was_connected || st.logs.is_empty() {
            st.logs.insert(
                0,
                LogEntry::new(
                    LogLevel::Warn,
                    COMPONENT_DESKTOP_BRIDGE,
                    self.i18n.t(ERR_KEY_DAEMON_DISCONNECTED),
                ),
            );
        }
    }

    async fn call_daemon<T: DeserializeOwned>(&self, command: IpcCommand) -> Result<T, String> {
        match self.ipc_client.call_typed::<T>(command).await {
            Ok(res) => {
                self.daemon_connected.store(true, Ordering::SeqCst);
                self.state.write().diagnostics.daemon_connected = true;
                Ok(res)
            }
            Err(err) => {
                self.mark_disconnected();
                Err(err.to_string())
            }
        }
    }

    pub fn is_daemon_connected(&self) -> bool {
        self.daemon_connected.load(Ordering::SeqCst)
    }

    pub async fn refresh_state(&self) -> DaemonFullState {
        if let Ok(fresh) = self
            .call_daemon::<DaemonFullState>(IpcCommand::GetState)
            .await
        {
            self.apply_full_state(fresh.clone());
            return fresh;
        }
        self.state.read().clone()
    }

    pub async fn scan_os_sockets(&self) -> Vec<TrackedConnection> {
        match self
            .call_daemon::<Vec<TrackedConnection>>(IpcCommand::ScanOsSockets)
            .await
        {
            Ok(sockets) => {
                self.state.write().connections = sockets.clone();
                sockets
            }
            Err(_) => Vec::new(),
        }
    }

    pub fn set_system_proxy(&self, enabled: bool) -> Result<bool, String> {
        let diag = self.get_diagnostics();
        SystemProxyManager::set_system_proxy(enabled, &diag.relay_tcp_endpoint)
            .map_err(|e| e.to_string())
    }

    pub fn launch_process_with_proxy(
        &self,
        executable_path: &str,
        args: &[String],
    ) -> Result<LaunchedProcessReport, String> {
        let diag = self.get_diagnostics();
        let command_line = if args.is_empty() {
            executable_path.to_string()
        } else {
            format!("{executable_path} {}", args.join(" "))
        };
        SystemProxyManager::spawn_process_with_proxy(
            &command_line,
            &diag.relay_tcp_endpoint,
            &diag.relay_http_endpoint,
        )
        .map_err(|e| e.to_string())
    }

    pub fn get_profile(&self) -> ProfileConfig {
        self.state.read().profile.clone()
    }

    pub fn get_themeforge_catalog(&self) -> Result<ThemeForgeCatalog, String> {
        ThemeForgeCatalog::load_embedded().map_err(|e| e.to_string())
    }

    pub async fn set_theme(&self, theme: String, accent: String) {
        {
            let mut st = self.state.write();
            st.profile.theme_config.theme = theme.clone();
            st.profile.theme_config.accent = accent.clone();
        }
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::SetTheme { theme, accent })
            .await;
    }

    pub fn get_diagnostics(&self) -> SystemDiagnostics {
        self.state.read().diagnostics.clone()
    }

    pub fn get_telemetry(&self) -> TelemetrySnapshot {
        self.state.read().telemetry.clone()
    }

    pub fn list_connections(&self) -> Vec<TrackedConnection> {
        self.state.read().connections.clone()
    }

    pub async fn terminate_connection(&self, connection_id: String) -> bool {
        #[derive(serde::Deserialize)]
        struct TerminateAck {
            terminated: bool,
        }
        match self
            .call_daemon::<TerminateAck>(IpcCommand::TerminateConnection { connection_id })
            .await
        {
            Ok(ack) => ack.terminated,
            Err(_) => false,
        }
    }

    pub async fn clear_closed_connections(&self) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::ClearClosedConnections)
            .await;
        self.state
            .write()
            .connections
            .retain(|c| c.status == ConnectionStatus::Active);
    }

    pub async fn simulate_connection(
        &self,
        request: ConnectionRequest,
    ) -> Result<TrackedConnection, String> {
        self.call_daemon::<TrackedConnection>(IpcCommand::SimulateConnection { request })
            .await
    }

    pub async fn evaluate_rule(
        &self,
        request: ConnectionRequest,
    ) -> Result<RuleEvaluationResult, String> {
        self.call_daemon::<RuleEvaluationResult>(IpcCommand::EvaluateRule { request })
            .await
    }

    pub async fn test_proxy(&self, proxy_id: String) -> Result<ProxyHealthReport, String> {
        self.call_daemon::<ProxyHealthReport>(IpcCommand::TestProxy { proxy_id })
            .await
    }

    pub async fn test_all_proxies(&self) -> Vec<ProxyHealthReport> {
        self.call_daemon::<Vec<ProxyHealthReport>>(IpcCommand::TestAllProxies)
            .await
            .unwrap_or_default()
    }

    pub async fn upsert_proxy(&self, node: ProxyNode) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::UpsertProxy { node })
            .await;
        let _ = self.refresh_state().await;
    }

    pub async fn remove_proxy(&self, proxy_id: String) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::RemoveProxy { proxy_id })
            .await;
        let _ = self.refresh_state().await;
    }

    pub async fn upsert_chain(&self, chain: ProxyChain) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::UpsertChain { chain })
            .await;
        let _ = self.refresh_state().await;
    }

    pub async fn remove_chain(&self, chain_id: String) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::RemoveChain { chain_id })
            .await;
        let _ = self.refresh_state().await;
    }

    pub async fn upsert_rule(&self, rule: RoutingRule) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::UpsertRule { rule })
            .await;
        let _ = self.refresh_state().await;
    }

    pub async fn remove_rule(&self, rule_id: String) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::RemoveRule { rule_id })
            .await;
        let _ = self.refresh_state().await;
    }

    pub async fn toggle_engine(&self, start: bool) -> SystemDiagnostics {
        if let Ok(mut diag) = self
            .call_daemon::<SystemDiagnostics>(IpcCommand::ToggleEngine { start })
            .await
        {
            diag.daemon_connected = true;
            self.state.write().diagnostics = diag.clone();
            return diag;
        }
        self.get_diagnostics()
    }

    pub async fn set_interception_mode(&self, mode: InterceptionMode) -> SystemDiagnostics {
        if let Ok(mut diag) = self
            .call_daemon::<SystemDiagnostics>(IpcCommand::SetInterceptionMode { mode })
            .await
        {
            diag.daemon_connected = true;
            self.state.write().diagnostics = diag.clone();
            return diag;
        }
        self.get_diagnostics()
    }

    pub fn list_fake_ip_entries(&self) -> Vec<FakeIpEntry> {
        self.state.read().fake_ips.clone()
    }

    pub async fn allocate_fake_ip(&self, domain: String) -> Option<String> {
        let allocated = self
            .call_daemon::<Option<String>>(IpcCommand::AllocateFakeIp { domain })
            .await
            .ok()
            .flatten();
        let _ = self.refresh_state().await;
        allocated
    }

    pub async fn flush_fake_ip_cache(&self) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::FlushFakeIps)
            .await;
        self.state.write().fake_ips.clear();
    }

    pub fn list_logs(&self) -> Vec<LogEntry> {
        self.state.read().logs.clone()
    }

    pub async fn clear_logs(&self) {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::ClearLogs)
            .await;
        self.state.write().logs.clear();
    }
}
