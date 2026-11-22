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
use routeward_core::error::{
    RouteWardError, RouteWardResult, ERR_KEY_DAEMON_DISCONNECTED, ERR_KEY_SYSTEM_PATH_EMPTY,
};
use routeward_core::i18n::I18nRegistry;
use routeward_core::interceptor::SystemDiagnostics;
use routeward_core::ipc::protocol::{
    read_bounded_line, DaemonFullState, IpcCommand, IpcRequest, IpcResponse, IpcStreamEvent,
    ReadLineOutcome,
};
use routeward_core::ipc::transport::connect_ipc_stream;
use routeward_core::ipc::{generate_ephemeral_token, IpcCallError, IpcClient};
use routeward_core::logger::FileLogger;
use routeward_core::pac::FoxyProxyImportResult;
use routeward_core::process::{ProcessResolver, SystemApplicationEntry};
use routeward_core::rules::{ConnectionRequest, RuleEvaluationResult};
use routeward_core::system::{local_pac_url, LaunchedProcessReport, SystemProxyManager};
use routeward_core::telemetry::{
    ConnectionStatus, LogEntry, LogLevel, TelemetryEvent, TelemetrySnapshot, TrackedConnection,
};
use serde::de::DeserializeOwned;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};

const COMPONENT_DESKTOP_BRIDGE: &str = "DesktopBridge";
const BRIDGE_EVENT_CHANNEL_CAPACITY: usize = 256;
const DAEMON_START_POLL_ATTEMPTS: usize = 16;
const DAEMON_START_POLL_INTERVAL_MS: u64 = 250;
const OUTAGE_ALERT_COOLDOWN_SECS: u64 = 60;
const TRAY_KEY_OUTAGE_TITLE: &str = "tray.alert.outage_title";
const TRAY_KEY_OUTAGE_BODY: &str = "tray.alert.outage_body";

type TrayNotifyCallback = Arc<dyn Fn(TrayStatusSnapshot) + Send + Sync>;
type TrayAlertCallback = Arc<dyn Fn(String, String) + Send + Sync>;

/// A failed system operation (registry tools, process spawn): the localized message plus the
/// stable i18n key the UI uses to translate it again in its own locale.
///
/// It derefs to the message and compares equal to a `String`, so callers that only care about
/// the text keep working.
#[derive(Debug, Clone)]
pub struct SystemOpError {
    key: Option<&'static str>,
    message: String,
}

impl SystemOpError {
    /// The i18n key of the failure; absent when the blocking task itself could not complete.
    pub fn key(&self) -> Option<&'static str> {
        self.key
    }

    /// The message localized in the bridge locale.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for SystemOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::ops::Deref for SystemOpError {
    type Target = str;

    fn deref(&self) -> &str {
        &self.message
    }
}

impl PartialEq<String> for SystemOpError {
    fn eq(&self, other: &String) -> bool {
        &self.message == other
    }
}

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
    tray_alert: Arc<Mutex<Option<TrayAlertCallback>>>,
    pause_timer_generation: Arc<AtomicU64>,
    last_outage_alert_epoch_secs: Arc<AtomicU64>,
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
            paused_until_epoch_ms: None,
            auto_start_error_key: None,
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
            tray_alert: Arc::new(Mutex::new(None)),
            pause_timer_generation: Arc::new(AtomicU64::new(0)),
            last_outage_alert_epoch_secs: Arc::new(AtomicU64::new(0)),
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

    pub fn webview_data_dir(&self) -> std::path::PathBuf {
        self.constants.telemetry.resolve_user_webview_dir()
    }

    pub fn translate(&self, key: &str) -> String {
        self.i18n.t(key)
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

    pub fn set_tray_alert_callback(&self, cb: TrayAlertCallback) {
        *self.tray_alert.lock() = Some(cb);
    }

    fn maybe_notify_proxy_outage(&self, conn: &TrackedConnection) {
        if conn.status != ConnectionStatus::Blocked {
            return;
        }
        let Some(detail) = conn.error_detail.as_deref() else {
            return;
        };
        let lower = detail.to_ascii_lowercase();
        let is_outage = lower.contains("kill-switch")
            || lower.contains("killswitch")
            || lower.contains("unreachable")
            || lower.contains("timeout")
            || lower.contains("upstream")
            || lower.contains("proxy");
        if !is_outage {
            return;
        }
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let prev = self.last_outage_alert_epoch_secs.load(Ordering::SeqCst);
        if prev != 0 && now_secs.saturating_sub(prev) < OUTAGE_ALERT_COOLDOWN_SECS {
            return;
        }
        if self
            .last_outage_alert_epoch_secs
            .compare_exchange(prev, now_secs, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let cb = self.tray_alert.lock().clone();
        if let Some(cb) = cb {
            cb(
                self.i18n.t(TRAY_KEY_OUTAGE_TITLE),
                self.i18n.t(TRAY_KEY_OUTAGE_BODY),
            );
        }
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
                        let max_conns = self
                            .constants
                            .telemetry
                            .max_connection_history_entries
                            .max(1);
                        trim_cached_connections(&mut st.connections, max_conns);
                    }
                }
                TelemetryEvent::ConnectionsCleared => {
                    st.connections
                        .retain(|c| c.status == ConnectionStatus::Active);
                }
                TelemetryEvent::Log(entry) => {
                    st.logs.insert(0, entry.clone());
                    let max_logs = self.constants.telemetry.max_log_ring_buffer_entries.max(1);
                    st.logs.truncate(max_logs);
                }
                TelemetryEvent::LogsCleared => {
                    st.logs.clear();
                }
            }
        }
        if let TelemetryEvent::ConnectionUpdated(conn) = &event {
            self.maybe_notify_proxy_outage(conn);
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

    async fn call_daemon_detailed<T: DeserializeOwned>(
        &self,
        command: IpcCommand,
    ) -> Result<T, IpcCallError> {
        if !self.is_daemon_connected() {
            self.log_info(format!(
                "Attempting IPC command to daemon ({})",
                self.ipc_endpoint_label()
            ));
        }
        match self.ipc_client.call_typed_detailed::<T>(command).await {
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
                self.log_warn(format!(
                    "Daemon IPC command failed ({}): {err}",
                    self.ipc_endpoint_label()
                ));
                // Only treat actual pipe/socket loss as daemon disconnection; keep alive on remote errors.
                if err.is_transport() {
                    self.mark_disconnected();
                } else {
                    self.daemon_connected.store(true, Ordering::SeqCst);
                    self.state.write().diagnostics.daemon_connected = true;
                }
                Err(err)
            }
        }
    }

    async fn call_daemon<T: DeserializeOwned>(&self, command: IpcCommand) -> Result<T, String> {
        self.call_daemon_detailed(command)
            .await
            .map_err(|err| err.to_string())
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

    /// Runs a blocking system call (registry tools, process spawn) off the async worker.
    ///
    /// A failure is logged with its English detail and handed to the UI as the message of its
    /// i18n key in the active locale, so the user never sees a raw OS error text.
    async fn run_system_blocking<T, F>(&self, task: F) -> Result<T, SystemOpError>
    where
        T: Send + 'static,
        F: FnOnce() -> RouteWardResult<T> + Send + 'static,
    {
        match tokio::task::spawn_blocking(task).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => {
                self.log_warn(format!("System operation failed: {err}"));
                Err(SystemOpError {
                    key: Some(err.i18n_key()),
                    message: self.i18n.t(err.i18n_key()),
                })
            }
            Err(join_err) => Err(SystemOpError {
                key: None,
                message: join_err.to_string(),
            }),
        }
    }

    pub async fn set_system_proxy(&self, enabled: bool) -> Result<bool, SystemOpError> {
        let endpoint = self.get_diagnostics().relay_tcp_endpoint;
        self.run_system_blocking(move || SystemProxyManager::set_system_proxy(enabled, &endpoint))
            .await
    }

    /// True when the system proxy is on and points to RouteWard's relay; a proxy configured by
    /// someone else does not count.
    pub async fn get_system_proxy_status(&self) -> bool {
        let endpoint = self.get_diagnostics().relay_tcp_endpoint;
        tokio::task::spawn_blocking(move || {
            SystemProxyManager::is_routeward_proxy_active(&endpoint)
        })
        .await
        .unwrap_or(false)
    }

    /// Gives the system proxy and PAC settings back when the app exits, if RouteWard set them
    /// and they still are RouteWard's. Blocking and best effort: a failure is only logged.
    pub fn restore_system_settings_on_exit(&self) {
        let endpoint = self.get_diagnostics().relay_tcp_endpoint;
        match SystemProxyManager::restore_owned_settings(&endpoint, &self.pac_url()) {
            Ok(report) if report.proxy_restored || report.pac_restored => {
                self.log_info("Restored the system proxy settings on exit");
            }
            Ok(_) => {}
            Err(err) => {
                self.log_warn(format!(
                    "Could not restore system proxy settings on exit: {err}"
                ));
            }
        }
    }

    pub fn pac_url(&self) -> String {
        local_pac_url(
            &self.constants.network.local_bind_host,
            self.constants.network.default_pac_port,
        )
    }

    pub async fn get_system_pac_status(&self) -> (bool, String) {
        let expected = self.pac_url();
        let expected_for_task = expected.clone();
        let active = tokio::task::spawn_blocking(move || {
            SystemProxyManager::get_system_pac_url()
                .map(|url| url.eq_ignore_ascii_case(&expected_for_task))
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        (active, expected)
    }

    pub async fn set_system_pac(&self, enabled: bool) -> Result<(bool, String), SystemOpError> {
        let expected = self.pac_url();
        let expected_for_task = expected.clone();
        self.run_system_blocking(move || {
            SystemProxyManager::set_system_pac(enabled, &expected_for_task)
        })
        .await
        .map(|res| (res, expected))
    }

    pub async fn get_autostart_status(&self) -> bool {
        tokio::task::spawn_blocking(SystemProxyManager::is_autostart_enabled)
            .await
            .unwrap_or(false)
    }

    pub async fn set_autostart(&self, enabled: bool) -> Result<bool, SystemOpError> {
        self.run_system_blocking(move || {
            let exe_path = std::env::current_exe().map_err(|err| RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_PATH_EMPTY,
                detail: format!("cannot resolve the current executable: {err}"),
            })?;
            SystemProxyManager::set_autostart(enabled, &exe_path.to_string_lossy())
        })
        .await
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

    pub async fn detect_existing_proxies(
        &self,
    ) -> Vec<routeward_core::system::DetectedProxyCandidate> {
        tokio::task::spawn_blocking(routeward_core::system::detect_existing_proxies)
            .await
            .unwrap_or_default()
    }

    pub async fn get_current_network_info(&self) -> routeward_core::system::CurrentNetworkInfo {
        tokio::task::spawn_blocking(routeward_core::system::detect_current_network)
            .await
            .unwrap_or(routeward_core::system::CurrentNetworkInfo {
                network_name: None,
                kind: "unknown".to_string(),
            })
    }

    pub async fn get_direct_ip(&self) -> Option<String> {
        routeward_core::checker::ProxyChecker::probe_direct_ip(&self.constants).await
    }

    pub async fn launch_process_with_proxy(
        &self,
        executable_path: &str,
        args: &[String],
    ) -> Result<LaunchedProcessReport, SystemOpError> {
        let diag = self.get_diagnostics();
        let executable_path = executable_path.to_string();
        let args = args.to_vec();
        self.run_system_blocking(move || {
            SystemProxyManager::spawn_process_with_proxy(
                &executable_path,
                &args,
                &diag.relay_tcp_endpoint,
                &diag.relay_http_endpoint,
            )
        })
        .await
    }

    pub fn get_profile(&self) -> ProfileConfig {
        self.state.read().profile.clone()
    }

    pub async fn replace_profile(
        &self,
        profile: ProfileConfig,
    ) -> Result<ProfileConfig, IpcCallError> {
        let updated = self
            .call_daemon_detailed::<ProfileConfig>(IpcCommand::ReplaceProfile { profile })
            .await?;
        let _ = self.refresh_state().await;
        Ok(updated)
    }

    pub fn get_themeforge_catalog(&self) -> Result<ThemeForgeCatalog, String> {
        ThemeForgeCatalog::load_embedded().map_err(|e| e.to_string())
    }

    pub async fn set_theme(&self, theme: String, accent: String) -> Result<(), IpcCallError> {
        {
            let mut st = self.state.write();
            st.profile.theme_config.theme = theme.clone();
            st.profile.theme_config.accent = accent.clone();
        }
        if self.is_daemon_connected() {
            self.call_daemon_detailed::<serde_json::Value>(IpcCommand::SetTheme { theme, accent })
                .await?;
        }
        Ok(())
    }

    pub fn initial_window_theme(&self) -> crate::WindowThemeAppearance {
        let theme_name = self.state.read().profile.theme_config.theme.clone();
        crate::resolve_palette_window_appearance(&theme_name)
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

    pub async fn terminate_connection(&self, connection_id: String) -> Result<bool, IpcCallError> {
        #[derive(serde::Deserialize)]
        struct TerminateAck {
            terminated: bool,
        }
        self.call_daemon_detailed::<TerminateAck>(IpcCommand::TerminateConnection { connection_id })
            .await
            .map(|ack| ack.terminated)
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

    pub async fn upsert_proxy(&self, node: ProxyNode) -> Result<ProfileConfig, IpcCallError> {
        let outcome = self
            .call_daemon_detailed::<serde_json::Value>(IpcCommand::UpsertProxy { node })
            .await;
        // Always resync, so the UI sees the real profile even when the daemon rejected the change.
        let profile = self.refresh_state().await.profile;
        outcome.map(|_| profile)
    }

    pub async fn remove_proxy(&self, proxy_id: String) -> Result<ProfileConfig, IpcCallError> {
        let outcome = self
            .call_daemon_detailed::<serde_json::Value>(IpcCommand::RemoveProxy { proxy_id })
            .await;
        // Always resync, so the UI sees the real profile even when the daemon rejected the change.
        let profile = self.refresh_state().await.profile;
        outcome.map(|_| profile)
    }

    pub async fn set_primary_proxy(&self, proxy_id: String) -> Result<ProfileConfig, IpcCallError> {
        let outcome = self
            .call_daemon_detailed::<serde_json::Value>(IpcCommand::SetPrimaryProxy { proxy_id })
            .await;
        let profile = self.refresh_state().await.profile;
        outcome.map(|_| profile)
    }

    pub async fn upsert_chain(&self, chain: ProxyChain) -> Result<ProfileConfig, IpcCallError> {
        let outcome = self
            .call_daemon_detailed::<serde_json::Value>(IpcCommand::UpsertChain { chain })
            .await;
        // Always resync, so the UI sees the real profile even when the daemon rejected the change.
        let profile = self.refresh_state().await.profile;
        outcome.map(|_| profile)
    }

    pub async fn remove_chain(&self, chain_id: String) -> Result<ProfileConfig, IpcCallError> {
        let outcome = self
            .call_daemon_detailed::<serde_json::Value>(IpcCommand::RemoveChain { chain_id })
            .await;
        // Always resync, so the UI sees the real profile even when the daemon rejected the change.
        let profile = self.refresh_state().await.profile;
        outcome.map(|_| profile)
    }

    pub async fn upsert_rule(&self, rule: RoutingRule) -> Result<ProfileConfig, IpcCallError> {
        let outcome = self
            .call_daemon_detailed::<serde_json::Value>(IpcCommand::UpsertRule { rule })
            .await;
        // Always resync, so the UI sees the real profile even when the daemon rejected the change.
        let profile = self.refresh_state().await.profile;
        outcome.map(|_| profile)
    }

    pub async fn remove_rule(&self, rule_id: String) -> Result<ProfileConfig, IpcCallError> {
        let outcome = self
            .call_daemon_detailed::<serde_json::Value>(IpcCommand::RemoveRule { rule_id })
            .await;
        // Always resync, so the UI sees the real profile even when the daemon rejected the change.
        let profile = self.refresh_state().await.profile;
        outcome.map(|_| profile)
    }

    pub async fn toggle_engine(&self, start: bool) -> Result<SystemDiagnostics, IpcCallError> {
        self.pause_timer_generation.fetch_add(1, Ordering::SeqCst);
        match self
            .call_daemon_detailed::<SystemDiagnostics>(IpcCommand::ToggleEngine { start })
            .await
        {
            Ok(mut diag) => {
                diag.daemon_connected = true;
                diag.active_locale = self.i18n.get_locale();
                self.state.write().diagnostics = diag.clone();
                self.emit_resync();
                self.notify_tray();
                Ok(diag)
            }
            Err(err) => {
                self.notify_tray();
                Err(err)
            }
        }
    }

    /// Pauses protection for `duration`, then automatically re-enables it unless cancelled by a manual toggle.
    pub async fn pause_engine_for(&self, duration: Duration) -> Result<(), IpcCallError> {
        self.toggle_engine(false).await?;
        let expected_gen = self.pause_timer_generation.load(Ordering::SeqCst);
        let bridge = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            if bridge.pause_timer_generation.load(Ordering::SeqCst) == expected_gen
                && bridge.is_daemon_connected()
                && !bridge.get_diagnostics().running
            {
                if let Err(err) = bridge.toggle_engine(true).await {
                    bridge.log_warn(format!("Timed tray auto-resume failed: {err}"));
                }
            }
        });
        Ok(())
    }

    pub async fn set_interception_mode(
        &self,
        mode: InterceptionMode,
    ) -> Result<SystemDiagnostics, IpcCallError> {
        match self
            .call_daemon_detailed::<SystemDiagnostics>(IpcCommand::SetInterceptionMode { mode })
            .await
        {
            Ok(mut diag) => {
                diag.daemon_connected = true;
                diag.active_locale = self.i18n.get_locale();
                self.state.write().diagnostics = diag.clone();
                self.emit_resync();
                self.notify_tray();
                Ok(diag)
            }
            Err(err) => {
                self.notify_tray();
                Err(err)
            }
        }
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
        let proc_handle =
            match daemon_launcher::start_privileged_daemon_with_release(&release, &locale).await {
                Ok(handle) => handle,
                Err(err) => {
                    self.log_error(format!(
                        "Failed to launch privileged daemon: {}",
                        err.detail()
                    ));
                    return Err(err);
                }
            };

        for _ in 0..DAEMON_START_POLL_ATTEMPTS {
            let state = self.refresh_state().await;
            if state.diagnostics.daemon_connected {
                return Ok(state);
            }
            if let Some(exit_code) = proc_handle.as_ref().and_then(|h| h.try_exit_code()) {
                if exit_code != 0 {
                    let err = DaemonLaunchError::from_daemon_exit_code(exit_code);
                    self.log_error(format!(
                        "Elevated daemon exited early before IPC connection: {}",
                        err.detail()
                    ));
                    return Err(err);
                }
            }
            tokio::time::sleep(Duration::from_millis(DAEMON_START_POLL_INTERVAL_MS)).await;
        }

        self.log_warn("Timed out waiting for elevated daemon IPC connection after launch");
        Ok(self.refresh_state().await)
    }

    pub fn list_fake_ip_entries(&self) -> Vec<FakeIpEntry> {
        self.state.read().fake_ips.clone()
    }

    pub async fn allocate_fake_ip(&self, domain: String) -> Result<Option<String>, IpcCallError> {
        let outcome = self
            .call_daemon_detailed::<Option<String>>(IpcCommand::AllocateFakeIp { domain })
            .await;
        let _ = self.refresh_state().await;
        outcome
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

fn trim_cached_connections(connections: &mut Vec<TrackedConnection>, max_len: usize) {
    while connections.len() > max_len {
        if let Some(pos) = connections
            .iter()
            .rposition(|c| c.status != ConnectionStatus::Active)
        {
            connections.remove(pos);
        } else {
            break;
        }
    }
}
