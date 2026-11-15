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

use crate::daemon_launcher::{self, DaemonLaunchError, DaemonStartGuard};
use crate::TrayStatusSnapshot;
use parking_lot::{Mutex, RwLock};
use routeward_core::checker::ProxyHealthReport;
use routeward_core::config::{
    InterceptionMode, ProfileConfig, ProfileSummary, ProxyChain, ProxyNode, RoutingRule,
    SystemConstants, ThemeForgeCatalog,
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
use routeward_core::logger::FileLogger;
use routeward_core::pac::FoxyProxyImportResult;
use routeward_core::process::{ProcessResolver, SystemApplicationEntry};
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
const BRIDGE_EVENT_CHANNEL_CAPACITY: usize = 256;
const DAEMON_START_POLL_ATTEMPTS: usize = 16;
const DAEMON_START_POLL_INTERVAL_MS: u64 = 250;

type TrayNotifyCallback = Arc<dyn Fn(TrayStatusSnapshot) + Send + Sync>;

#[derive(Clone)]
pub struct DesktopCommandBridge {
    constants: Arc<SystemConstants>,
    i18n: I18nRegistry,
    ipc_client: IpcClient,
    file_logger: FileLogger,
    state: Arc<RwLock<DaemonFullState>>,
    profiles: Arc<RwLock<Vec<ProfileSummary>>>,
    daemon_connected: Arc<AtomicBool>,
    event_tx: tokio::sync::broadcast::Sender<IpcStreamEvent>,
    daemon_start_guard: Arc<DaemonStartGuard>,
    tray_notify: Arc<Mutex<Option<TrayNotifyCallback>>>,
}

impl DesktopCommandBridge {
    pub fn new(constants: SystemConstants, default_profile: ProfileConfig, locale: &str) -> Self {
        let user_log_dir = constants.telemetry.resolve_user_log_dir();
        Self::new_with_log_dir(constants, default_profile, locale, user_log_dir)
    }

    pub fn new_with_log_dir(
        constants: SystemConstants,
        default_profile: ProfileConfig,
        locale: &str,
        log_dir: std::path::PathBuf,
    ) -> Self {
        let i18n = I18nRegistry::new(locale);
        let ipc_client = IpcClient::new(constants.ipc.clone());
        let file_logger = FileLogger::new(
            &log_dir,
            &constants.telemetry.log_app_name,
            default_profile.enable_logging,
        );
        let net = &constants.network;
        let (event_tx, _) = tokio::sync::broadcast::channel(BRIDGE_EVENT_CHANNEL_CAPACITY);

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

        let initial_profiles = vec![ProfileSummary {
            profile_id: default_profile.profile_id.clone(),
            name: default_profile.name.clone(),
            proxy_count: default_profile.proxies.len(),
            rule_count: default_profile.rules.len(),
            active: true,
        }];

        let initial_state = DaemonFullState {
            diagnostics: initial_diagnostics,
            profile: default_profile.redacted_for_ipc(),
            telemetry: TelemetrySnapshot::default(),
            connections: Vec::new(),
            logs: Vec::new(),
            fake_ips: Vec::new(),
        };

        let bridge = Self {
            constants: Arc::new(constants),
            i18n,
            ipc_client,
            file_logger,
            state: Arc::new(RwLock::new(initial_state)),
            profiles: Arc::new(RwLock::new(initial_profiles)),
            daemon_connected: Arc::new(AtomicBool::new(false)),
            event_tx,
            daemon_start_guard: Arc::new(DaemonStartGuard::default()),
            tray_notify: Arc::new(Mutex::new(None)),
        };

        bridge.log_info(format!(
            "Initialized routeward-desktop bridge (ipc_endpoint={}, log_dir={})",
            bridge.ipc_endpoint_label(),
            log_dir.display()
        ));
        bridge.mark_disconnected();
        bridge
    }

    pub fn ipc_endpoint_label(&self) -> &str {
        #[cfg(windows)]
        {
            &self.constants.ipc.windows_pipe_name
        }
        #[cfg(not(windows))]
        {
            &self.constants.ipc.unix_socket_path
        }
    }

    pub fn log_info(&self, message: impl AsRef<str>) {
        self.file_logger
            .log(LogLevel::Info, COMPONENT_DESKTOP_BRIDGE, message.as_ref());
    }

    pub fn log_warn(&self, message: impl AsRef<str>) {
        self.file_logger
            .log(LogLevel::Warn, COMPONENT_DESKTOP_BRIDGE, message.as_ref());
    }

    pub fn log_error(&self, message: impl AsRef<str>) {
        self.file_logger
            .log(LogLevel::Error, COMPONENT_DESKTOP_BRIDGE, message.as_ref());
    }

    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<IpcStreamEvent> {
        self.event_tx.subscribe()
    }

    pub fn tray_snapshot(&self) -> TrayStatusSnapshot {
        let st = self.state.read();
        let running = st.diagnostics.running;
        let active_profile_id = st.profile.profile_id.clone();
        drop(st);
        let profiles = self
            .profiles
            .read()
            .iter()
            .map(|p| (p.profile_id.clone(), p.name.clone()))
            .collect();
        TrayStatusSnapshot {
            daemon_connected: self.is_daemon_connected(),
            running,
            locale: self.i18n.get_locale(),
            active_profile_id,
            profiles,
        }
    }

    pub fn set_tray_callback(&self, cb: TrayNotifyCallback) {
        *self.tray_notify.lock() = Some(cb);
        self.notify_tray();
    }

    fn notify_tray(&self) {
        let snapshot = self.tray_snapshot();
        let cb = self.tray_notify.lock().clone();
        if let Some(cb) = cb {
            cb(snapshot);
        }
    }

    fn emit_resync(&self) {
        let _ = self
            .event_tx
            .send(IpcStreamEvent::Resync { skipped_events: 0 });
    }

    pub fn set_locale(&self, locale: &str) -> String {
        let normalized = if locale.trim().to_ascii_lowercase().starts_with("en") {
            "en"
        } else {
            "fr"
        };
        self.i18n.set_locale(normalized);
        self.state.write().diagnostics.active_locale = normalized.to_string();
        self.notify_tray();
        normalized.to_string()
    }

    /// Spawns the background IPC subscription and automatic reconnection task.
    pub fn spawn_background_sync(&self) {
        let bridge = self.clone();
        tokio::spawn(async move {
            let reconnect_delay = Duration::from_millis(bridge.constants.ipc.reconnect_interval_ms);
            loop {
                if let Err(err) = bridge.run_subscription_session().await {
                    bridge.log_warn(format!(
                        "Daemon IPC subscription session failed ({}): {err}",
                        bridge.ipc_endpoint_label()
                    ));
                    bridge.mark_disconnected();
                }
                tokio::time::sleep(reconnect_delay).await;
            }
        });
    }

    async fn run_subscription_session(&self) -> Result<(), String> {
        self.log_info(format!(
            "Attempting IPC connection to daemon ({})",
            self.ipc_endpoint_label()
        ));

        let stream = connect_ipc_stream(&self.constants.ipc)
            .await
            .map_err(|e| e.to_string())?;
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let max_line = self.constants.ipc.max_line_bytes;
        let idle_timeout_ms = self.constants.ipc.idle_timeout_ms;

        // 1. Fetch full initial state over the same stream before entering Subscribe mode
        let state_req = IpcRequest {
            id: generate_ephemeral_token(),
            command: IpcCommand::GetState,
        };
        let mut state_req_bytes = serde_json::to_vec(&state_req).map_err(|e| e.to_string())?;
        state_req_bytes.push(b'\n');
        write_half
            .write_all(&state_req_bytes)
            .await
            .map_err(|e| e.to_string())?;
        write_half.flush().await.map_err(|e| e.to_string())?;

        match read_bounded_line(&mut reader, max_line, idle_timeout_ms).await {
            ReadLineOutcome::Line(line) => {
                let resp: IpcResponse = serde_json::from_str(&line).map_err(|e| e.to_string())?;
                if !resp.ok {
                    return Err(resp
                        .error
                        .unwrap_or_else(|| "GetState handshake failed".to_string()));
                }
                let val = resp
                    .result
                    .ok_or_else(|| "GetState returned empty result".to_string())?;
                let full_state: DaemonFullState =
                    serde_json::from_value(val).map_err(|e| e.to_string())?;
                self.apply_full_state(full_state);
            }
            other => return Err(format!("GetState handshake failed: {other:?}")),
        }

        // 2. Subscribe to real-time events on the same stream
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

        // Subscription stream stays open indefinitely while events arrive or until EOF
        let sub_timeout_ms = idle_timeout_ms.max(60_000);

        match read_bounded_line(&mut reader, max_line, sub_timeout_ms).await {
            ReadLineOutcome::Line(line) => {
                let ack: IpcResponse = serde_json::from_str(&line).map_err(|e| e.to_string())?;
                if !ack.ok {
                    return Err(ack.error.unwrap_or_else(|| "subscribe failed".to_string()));
                }
            }
            other => return Err(format!("subscribe handshake failed: {other:?}")),
        }

        self.log_info(format!(
            "Connected and subscribed to daemon IPC event stream ({})",
            self.ipc_endpoint_label()
        ));

        loop {
            match read_bounded_line(&mut reader, max_line, sub_timeout_ms).await {
                ReadLineOutcome::Line(line) => {
                    if let Ok(stream_ev) = serde_json::from_str::<IpcStreamEvent>(&line) {
                        match stream_ev {
                            IpcStreamEvent::Event(ev) => self.apply_telemetry_event(ev),
                            IpcStreamEvent::Resync { skipped_events } => {
                                if let Ok(fresh) = self
                                    .ipc_client
                                    .call_typed::<DaemonFullState>(IpcCommand::GetState)
                                    .await
                                {
                                    self.apply_full_state(fresh);
                                }
                                let _ = self
                                    .event_tx
                                    .send(IpcStreamEvent::Resync { skipped_events });
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
        full_state.diagnostics.active_locale = self.i18n.get_locale();
        let new_running = full_state.diagnostics.running;
        let was_connected = self.daemon_connected.swap(true, Ordering::SeqCst);
        let prev_running = {
            let mut st = self.state.write();
            let prev = st.diagnostics.running;
            *st = full_state;
            prev
        };
        if !was_connected {
            self.log_info(format!(
                "Daemon connection established ({})",
                self.ipc_endpoint_label()
            ));
            let bridge_for_profiles = self.clone();
            tokio::spawn(async move {
                let _ = bridge_for_profiles.list_profiles().await;
            });
            self.emit_resync();
        } else if prev_running != new_running {
            self.emit_resync();
        }
        self.notify_tray();
    }

    fn apply_telemetry_event(&self, event: TelemetryEvent) {
        {
            let mut st = self.state.write();
            match &event {
                TelemetryEvent::Telemetry(snap) => {
                    st.telemetry = snap.clone();
                }
                TelemetryEvent::ConnectionUpdated(conn) => {
                    if let Some(existing) = st.connections.iter_mut().find(|c| c.id == conn.id) {
                        *existing = conn.clone();
                    } else {
                        st.connections.insert(0, conn.clone());
                    }
                }
                TelemetryEvent::ConnectionsCleared => {
                    st.connections
                        .retain(|c| c.status == ConnectionStatus::Active);
                }
                TelemetryEvent::Log(entry) => {
                    st.logs.insert(0, entry.clone());
                }
                TelemetryEvent::LogsCleared => {
                    st.logs.clear();
                }
            }
        }
        let _ = self.event_tx.send(IpcStreamEvent::Event(event));
    }

    fn mark_disconnected(&self) {
        let was_connected = self.daemon_connected.swap(false, Ordering::SeqCst);
        {
            let mut st = self.state.write();
            st.diagnostics.daemon_connected = false;
            st.diagnostics.running = false;
            st.telemetry.download_bytes_per_sec = 0;
            st.telemetry.upload_bytes_per_sec = 0;
            st.telemetry.active_connections = 0;
            for conn in &mut st.connections {
                if conn.status == ConnectionStatus::Active {
                    conn.status = ConnectionStatus::Closed;
                }
            }
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
        if was_connected {
            self.log_warn(format!(
                "Daemon connection lost ({})",
                self.ipc_endpoint_label()
            ));
            self.emit_resync();
        }
        self.notify_tray();
    }

    async fn call_daemon<T: DeserializeOwned>(&self, command: IpcCommand) -> Result<T, String> {
        if !self.is_daemon_connected() {
            self.log_info(format!(
                "Attempting IPC command to daemon ({})",
                self.ipc_endpoint_label()
            ));
        }
        match self.ipc_client.call_typed::<T>(command).await {
            Ok(res) => {
                let was_connected = self.daemon_connected.swap(true, Ordering::SeqCst);
                self.state.write().diagnostics.daemon_connected = true;
                if !was_connected {
                    self.log_info(format!(
                        "Connected to daemon via IPC command ({})",
                        self.ipc_endpoint_label()
                    ));
                    let _ = self
                        .event_tx
                        .send(IpcStreamEvent::Resync { skipped_events: 0 });
                }
                Ok(res)
            }
            Err(err) => {
                let err_msg = err.to_string();
                self.log_warn(format!(
                    "Daemon IPC command failed ({}): {err_msg}",
                    self.ipc_endpoint_label()
                ));
                self.mark_disconnected();
                Err(err_msg)
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
            self.apply_full_state(fresh);
            return self.state.read().clone();
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

    pub fn pac_url(&self) -> String {
        format!(
            "http://{}:{}/proxy.pac",
            self.constants.network.local_bind_host, self.constants.network.default_pac_port
        )
    }

    pub fn get_system_pac_status(&self) -> (bool, String) {
        let expected = self.pac_url();
        let active = SystemProxyManager::get_system_pac_url()
            .map(|url| url.eq_ignore_ascii_case(&expected))
            .unwrap_or(false);
        (active, expected)
    }

    pub fn set_system_pac(&self, enabled: bool) -> Result<(bool, String), String> {
        let expected = self.pac_url();
        SystemProxyManager::set_system_pac(enabled, &expected)
            .map(|res| (res, expected))
            .map_err(|e| e.to_string())
    }

    pub fn get_autostart_status(&self) -> bool {
        SystemProxyManager::is_autostart_enabled()
    }

    pub fn set_autostart(&self, enabled: bool) -> Result<bool, String> {
        let exe_path = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        SystemProxyManager::set_autostart(enabled, &exe_path).map_err(|e| e.to_string())
    }

    pub async fn import_foxyproxy_json(
        &self,
        json: String,
        process_patterns: Vec<String>,
    ) -> Result<FoxyProxyImportResult, String> {
        let report = self
            .call_daemon::<FoxyProxyImportResult>(IpcCommand::ImportFoxyProxyJson {
                json,
                process_patterns,
            })
            .await?;
        let _ = self.refresh_state().await;
        Ok(report)
    }

    pub async fn list_profiles(&self) -> Vec<ProfileSummary> {
        if let Ok(list) = self
            .call_daemon::<Vec<ProfileSummary>>(IpcCommand::ListProfiles)
            .await
        {
            *self.profiles.write() = list.clone();
            self.notify_tray();
            return list;
        }
        self.profiles.read().clone()
    }

    pub async fn save_named_profile(
        &self,
        profile_id: Option<String>,
        name: Option<String>,
    ) -> Result<Vec<ProfileSummary>, String> {
        let list = self
            .call_daemon::<Vec<ProfileSummary>>(IpcCommand::SaveNamedProfile { profile_id, name })
            .await?;
        *self.profiles.write() = list.clone();
        let _ = self.refresh_state().await;
        Ok(list)
    }

    pub async fn switch_profile(&self, profile_id: String) -> Result<ProfileConfig, String> {
        let prof = self
            .call_daemon::<ProfileConfig>(IpcCommand::SwitchProfile { profile_id })
            .await?;
        let _ = self.list_profiles().await;
        let _ = self.refresh_state().await;
        self.emit_resync();
        Ok(prof)
    }

    pub async fn switch_profile_by_index(&self, index: usize) {
        let target_id = self
            .profiles
            .read()
            .get(index)
            .map(|p| p.profile_id.clone());
        if let Some(id) = target_id {
            let _ = self.switch_profile(id).await;
        }
    }

    pub async fn delete_profile(&self, profile_id: String) -> Result<Vec<ProfileSummary>, String> {
        let list = self
            .call_daemon::<Vec<ProfileSummary>>(IpcCommand::DeleteProfile { profile_id })
            .await?;
        *self.profiles.write() = list.clone();
        self.notify_tray();
        Ok(list)
    }

    pub async fn list_system_applications(&self) -> Vec<SystemApplicationEntry> {
        let ttl = self.constants.telemetry.process_cache_ttl_ms;
        tokio::task::spawn_blocking(move || {
            let resolver = ProcessResolver::new(ttl);
            resolver.list_system_applications()
        })
        .await
        .unwrap_or_default()
    }

    pub fn launch_process_with_proxy(
        &self,
        executable_path: &str,
        args: &[String],
    ) -> Result<LaunchedProcessReport, String> {
        let diag = self.get_diagnostics();
        SystemProxyManager::spawn_process_with_proxy(
            executable_path,
            args,
            &diag.relay_tcp_endpoint,
            &diag.relay_http_endpoint,
        )
        .map_err(|e| e.to_string())
    }

    pub fn get_profile(&self) -> ProfileConfig {
        self.state.read().profile.clone()
    }

    pub async fn replace_profile(&self, profile: ProfileConfig) -> Result<ProfileConfig, String> {
        let updated = self
            .call_daemon::<ProfileConfig>(IpcCommand::ReplaceProfile { profile })
            .await?;
        let _ = self.refresh_state().await;
        Ok(updated)
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

    pub async fn upsert_proxy(&self, node: ProxyNode) -> ProfileConfig {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::UpsertProxy { node })
            .await;
        self.refresh_state().await.profile
    }

    pub async fn remove_proxy(&self, proxy_id: String) -> ProfileConfig {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::RemoveProxy { proxy_id })
            .await;
        self.refresh_state().await.profile
    }

    pub async fn upsert_chain(&self, chain: ProxyChain) -> ProfileConfig {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::UpsertChain { chain })
            .await;
        self.refresh_state().await.profile
    }

    pub async fn remove_chain(&self, chain_id: String) -> ProfileConfig {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::RemoveChain { chain_id })
            .await;
        self.refresh_state().await.profile
    }

    pub async fn upsert_rule(&self, rule: RoutingRule) -> ProfileConfig {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::UpsertRule { rule })
            .await;
        self.refresh_state().await.profile
    }

    pub async fn remove_rule(&self, rule_id: String) -> ProfileConfig {
        let _ = self
            .call_daemon::<serde_json::Value>(IpcCommand::RemoveRule { rule_id })
            .await;
        self.refresh_state().await.profile
    }

    pub async fn toggle_engine(&self, start: bool) -> SystemDiagnostics {
        if let Ok(mut diag) = self
            .call_daemon::<SystemDiagnostics>(IpcCommand::ToggleEngine { start })
            .await
        {
            diag.daemon_connected = true;
            diag.active_locale = self.i18n.get_locale();
            self.state.write().diagnostics = diag.clone();
            self.emit_resync();
            self.notify_tray();
            return diag;
        }
        self.notify_tray();
        self.get_diagnostics()
    }

    pub async fn set_interception_mode(&self, mode: InterceptionMode) -> SystemDiagnostics {
        if let Ok(mut diag) = self
            .call_daemon::<SystemDiagnostics>(IpcCommand::SetInterceptionMode { mode })
            .await
        {
            diag.daemon_connected = true;
            diag.active_locale = self.i18n.get_locale();
            self.state.write().diagnostics = diag.clone();
            self.emit_resync();
            self.notify_tray();
            return diag;
        }
        self.notify_tray();
        self.get_diagnostics()
    }

    pub async fn start_privileged_daemon(&self) -> Result<DaemonFullState, DaemonLaunchError> {
        if self.is_daemon_connected() {
            return Ok(self.refresh_state().await);
        }

        let release = self
            .daemon_start_guard
            .try_acquire()
            .ok_or(DaemonLaunchError::AlreadyInFlight)?;
        let locale = self.i18n.get_locale();
        daemon_launcher::start_privileged_daemon_with_release(&release, &locale).await?;

        for _ in 0..DAEMON_START_POLL_ATTEMPTS {
            let state = self.refresh_state().await;
            if state.diagnostics.daemon_connected {
                return Ok(state);
            }
            tokio::time::sleep(Duration::from_millis(DAEMON_START_POLL_INTERVAL_MS)).await;
        }

        Ok(self.refresh_state().await)
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
