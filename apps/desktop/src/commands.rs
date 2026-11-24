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

use crate::daemon_launcher::{self, DaemonLaunchError, DaemonStartGuard, LaunchMode};
use crate::notices::{NoticeFlags, NOTICE_CLOSE_TO_TRAY, NOTICE_EXIT_BACKGROUND};
use crate::{TrayBalloon, TrayBalloonLevel, TrayStatusSnapshot};
use parking_lot::{Mutex, RwLock};
use routeward_core::checker::ProxyHealthReport;
use routeward_core::config::{
    InterceptionMode, ProfileConfig, ProfileSummary, ProxyChain, ProxyNode, RoutingRule,
    SystemConstants, ThemeForgeCatalog,
};
use routeward_core::diagnostics::bundle::{BundleLimits, CollectOptions};
use routeward_core::diagnostics::logs::{QueryLogsRequest, QueryLogsResponse};
use routeward_core::diagnostics::redact::Redactor;
use routeward_core::diagnostics::{AnalyzeResponse, BlockedResponse, PreviewRuleChangeRequest};
use routeward_core::dns::FakeIpEntry;
use routeward_core::error::{
    RouteWardError, RouteWardResult, ERR_KEY_DAEMON_DISCONNECTED, ERR_KEY_SYSTEM_PATH_EMPTY,
};
use routeward_core::i18n::I18nRegistry;
use routeward_core::interceptor::policy::PredictedOutcome;
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
/// Polls for the daemon after a launch (a freshly installed service needs a few seconds).
const DAEMON_START_POLL_ATTEMPTS: usize = 40;
const DAEMON_START_POLL_INTERVAL_MS: u64 = 250;
const OUTAGE_ALERT_COOLDOWN_SECS: u64 = 60;
/// How long the daemon may stay unreachable before the desktop gives the proxy settings back.
const DAEMON_UNREACHABLE_GRACE_SECS: u64 = 5;
/// Longest wait for the engine to stop when the app exits while it runs its own daemon.
const EXIT_STOP_ENGINE_TIMEOUT_SECS: u64 = 5;
const TRAY_KEY_OUTAGE_TITLE: &str = "tray.alert.outage_title";
const TRAY_KEY_OUTAGE_BODY_KILL_SWITCH: &str = "tray.alert.outage_body";
const TRAY_KEY_OUTAGE_BODY_OPEN: &str = "tray.alert.outage_body_open";
const TRAY_KEY_NOTICE_TITLE: &str = "tray.notice.title";
const TRAY_KEY_NOTICE_RESTORED_BODY: &str = "tray.notice.restored_body";
const TRAY_KEY_NOTICE_EXIT_TITLE: &str = "tray.notice.exit_background_title";
const TRAY_KEY_NOTICE_EXIT_BODY: &str = "tray.notice.exit_background_body";
const TRAY_KEY_NOTICE_CLOSE_TITLE: &str = "tray.notice.close_to_tray_title";
const TRAY_KEY_NOTICE_CLOSE_BODY: &str = "tray.notice.close_to_tray_body";
const TRAY_KEY_NOTICE_TOGGLE_FAILED: &str = "tray.notice.toggle_failed";
const TRAY_KEY_NOTICE_PAUSE_FAILED: &str = "tray.notice.pause_failed";
const TRAY_KEY_NOTICE_START_FAILED: &str = "tray.notice.start_failed";

type TrayNotifyCallback = Arc<dyn Fn(TrayStatusSnapshot) + Send + Sync>;
type TrayAlertCallback = Arc<dyn Fn(TrayBalloon) + Send + Sync>;

/// What happens to protection when the app exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDisposition {
    /// The background service keeps protecting: the proxy settings are left as they are.
    /// `announce` is true when a notice was shown (and must stay visible a moment).
    ProtectionContinues { announce: bool },
    /// Nothing keeps running: the proxy settings are given back.
    Stopped,
}

/// A daemon start: the resulting state, and why the background service was not used.
pub struct DaemonStartReport {
    pub state: DaemonFullState,
    /// Locale key explaining why a plain daemon runs instead of the service.
    pub fallback_reason_key: Option<&'static str>,
}

/// True when a connection update shows the proxy failed to carry the traffic: the connection
/// was blocked for a kill-switch proxy reason and is not a simulation. A block decided by a rule
/// never raises the outage alert. A record without a reason (older daemon) falls back to the
/// former heuristic: blocked with the detail of an upstream failure.
pub fn is_proxy_outage(conn: &TrackedConnection) -> bool {
    if conn.status != ConnectionStatus::Blocked || conn.simulated {
        return false;
    }
    match conn.block_reason {
        Some(reason) => reason.is_kill_switch_proxy(),
        None => conn.error_detail.is_some(),
    }
}

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

/// RouteWard-owned system settings the self-heal gave back, to be put back once the background
/// protection answers again with the engine running.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HealedSettings {
    pub proxy: bool,
    pub pac: bool,
}

impl HealedSettings {
    fn is_empty(self) -> bool {
        !self.proxy && !self.pac
    }
}

/// What to do with the remembered healed settings when a fresh daemon state arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealFollowUp {
    /// Nothing was given back: nothing to do.
    Nothing,
    /// The engine runs again: put back exactly these settings.
    Reapply(HealedSettings),
    /// The engine is off or paused: the user's choice wins, forget the memory.
    Forget,
}

/// Pure decision of the self-heal state machine, called on every daemon state.
pub(crate) fn plan_heal_followup(healed: HealedSettings, engine_running: bool) -> HealFollowUp {
    if healed.is_empty() {
        HealFollowUp::Nothing
    } else if engine_running {
        HealFollowUp::Reapply(healed)
    } else {
        HealFollowUp::Forget
    }
}

/// True when leaving the app must stop the engine of a daemon this app started: it runs, or it
/// is paused (stopping cancels the pause and records the choice as off, so it cannot come back).
pub(crate) fn exit_must_stop_engine(running: bool, paused_until_epoch_ms: Option<u64>) -> bool {
    running || paused_until_epoch_ms.is_some()
}

#[derive(Clone)]
pub struct DesktopCommandBridge {
    constants: Arc<SystemConstants>,
    i18n: I18nRegistry,
    ipc_client: IpcClient,
    file_logger: FileLogger,
    /// The desktop's own log directory (added to the diagnostic bundle).
    log_dir: std::path::PathBuf,
    state: Arc<RwLock<DaemonFullState>>,
    profiles: Arc<RwLock<Vec<ProfileSummary>>>,
    daemon_connected: Arc<AtomicBool>,
    subscription_active: Arc<AtomicBool>,
    event_tx: tokio::sync::broadcast::Sender<IpcStreamEvent>,
    daemon_start_guard: Arc<DaemonStartGuard>,
    tray_notify: Arc<Mutex<Option<TrayNotifyCallback>>>,
    tray_alert: Arc<Mutex<Option<TrayAlertCallback>>>,
    last_outage_alert_epoch_secs: Arc<AtomicU64>,
    notice_flags: Arc<NoticeFlags>,
    /// Since when the daemon has been unreachable (cleared as soon as it answers).
    unreachable_since: Arc<Mutex<Option<std::time::Instant>>>,
    /// True once the proxy settings were given back for the current unreachable period.
    self_heal_done: Arc<AtomicBool>,
    /// Set when the app exits while the background service keeps protecting.
    keep_settings_on_exit: Arc<AtomicBool>,
    /// Settings the self-heal gave back, waiting for the protection to run again.
    healed_settings: Arc<Mutex<HealedSettings>>,
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
        file_logger.set_retention_days(constants.telemetry.log_retention_days);
        let net = &constants.network;
        let (event_tx, _) = tokio::sync::broadcast::channel(BRIDGE_EVENT_CHANNEL_CAPACITY);
        // Next to the other per-user state (the WebView data lives in a sub-directory of it).
        let webview_dir = constants.telemetry.resolve_user_webview_dir();
        let notice_flags_path = webview_dir
            .parent()
            .unwrap_or(&webview_dir)
            .join(crate::notices::NOTICE_FLAGS_FILE_NAME);

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
            log_dir: log_dir.clone(),
            state: Arc::new(RwLock::new(initial_state)),
            profiles: Arc::new(RwLock::new(initial_profiles)),
            daemon_connected: Arc::new(AtomicBool::new(false)),
            subscription_active: Arc::new(AtomicBool::new(false)),
            event_tx,
            daemon_start_guard: Arc::new(DaemonStartGuard::default()),
            tray_notify: Arc::new(Mutex::new(None)),
            tray_alert: Arc::new(Mutex::new(None)),
            last_outage_alert_epoch_secs: Arc::new(AtomicU64::new(0)),
            notice_flags: Arc::new(NoticeFlags::new(notice_flags_path)),
            unreachable_since: Arc::new(Mutex::new(None)),
            self_heal_done: Arc::new(AtomicBool::new(false)),
            healed_settings: Arc::new(Mutex::new(HealedSettings::default())),
            keep_settings_on_exit: Arc::new(AtomicBool::new(false)),
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
        let paused_until_epoch_ms = st.diagnostics.paused_until_epoch_ms;
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
            paused_until_epoch_ms,
        }
    }

    /// Stores the one-time notice flags at `path` (tests use a temporary directory).
    pub fn with_notice_flags_path(mut self, path: std::path::PathBuf) -> Self {
        self.notice_flags = Arc::new(NoticeFlags::new(path));
        self
    }

    pub fn set_tray_callback(&self, cb: TrayNotifyCallback) {
        *self.tray_notify.lock() = Some(cb);
        self.notify_tray();
    }

    pub fn set_tray_alert_callback(&self, cb: TrayAlertCallback) {
        *self.tray_alert.lock() = Some(cb);
    }

    /// Shows a balloon from the tray icon, when the tray is up.
    fn show_balloon(&self, title: String, body: String, level: TrayBalloonLevel) {
        let cb = self.tray_alert.lock().clone();
        if let Some(cb) = cb {
            cb(TrayBalloon { title, body, level });
        }
    }

    /// Shows the app-titled notice whose text is the locale key `body_key`.
    fn show_notice(&self, body_key: &str, level: TrayBalloonLevel) {
        self.show_balloon(
            self.i18n.t(TRAY_KEY_NOTICE_TITLE),
            self.i18n.t(body_key),
            level,
        );
    }

    /// Text of a failed daemon call for a balloon: the translated message of its error key, or
    /// the generic text `generic_key` when the failure carries none (never the raw OS detail).
    fn describe_ipc_failure(&self, err: &IpcCallError, generic_key: &str) -> String {
        if let Some(key) = err.error_key() {
            let text = self.i18n.t(key);
            if text != key {
                return text;
            }
        }
        self.i18n.t(generic_key)
    }

    fn maybe_notify_proxy_outage(&self, conn: &TrackedConnection) {
        if !is_proxy_outage(conn) {
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
        // Only the safety cutoff blocks the other traffic: without it the text must not say so.
        let kill_switch_on = self
            .state
            .read()
            .profile
            .security_policy
            .kill_switch_enabled;
        let body_key = if kill_switch_on {
            TRAY_KEY_OUTAGE_BODY_KILL_SWITCH
        } else {
            TRAY_KEY_OUTAGE_BODY_OPEN
        };
        self.show_balloon(
            self.i18n.t(TRAY_KEY_OUTAGE_TITLE),
            self.i18n.t(body_key),
            TrayBalloonLevel::Warning,
        );
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
                bridge.self_heal_if_daemon_unreachable().await;
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

        self.subscription_active.store(true, Ordering::SeqCst);
        self.log_info(format!(
            "Connected and subscribed to daemon IPC event stream ({})",
            self.ipc_endpoint_label()
        ));

        let loop_res = loop {
            match read_bounded_line(&mut reader, max_line, sub_timeout_ms).await {
                ReadLineOutcome::Line(line) => {
                    match serde_json::from_str::<IpcStreamEvent>(&line) {
                        Ok(IpcStreamEvent::Event(ev)) => self.apply_telemetry_event(ev),
                        Ok(IpcStreamEvent::Resync { skipped_events }) => {
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
                        Err(err) => {
                            self.log_warn(format!("Ignored malformed IPC stream event: {err}"));
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
                            self.notify_tray();
                        }
                        Err(err) => break Err(err.to_string()),
                    }
                }
                ReadLineOutcome::Eof
                | ReadLineOutcome::LineTooLong
                | ReadLineOutcome::IoError(_) => {
                    break Err("IPC event stream closed".to_string());
                }
            }
        };
        self.subscription_active.store(false, Ordering::SeqCst);
        loop_res
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
            self.note_daemon_reachable();
            let bridge_for_profiles = self.clone();
            tokio::spawn(async move {
                let _ = bridge_for_profiles.list_profiles().await;
            });
            self.emit_resync();
        } else if prev_running != new_running {
            self.emit_resync();
        }
        self.reapply_healed_settings_if_protecting(new_running);
        self.notify_tray();
    }

    /// Once the protection answers again with the engine running, puts back exactly the
    /// settings the self-heal gave back, silently. Needs a Tokio runtime.
    fn reapply_healed_settings_if_protecting(&self, engine_running: bool) {
        let followup = {
            let mut healed = self.healed_settings.lock();
            let plan = plan_heal_followup(*healed, engine_running);
            if plan != HealFollowUp::Nothing {
                *healed = HealedSettings::default();
            }
            plan
        };
        let HealFollowUp::Reapply(settings) = followup else {
            return;
        };
        let bridge = self.clone();
        tokio::spawn(async move {
            if settings.proxy {
                if let Err(err) = bridge.set_system_proxy(true).await {
                    bridge.log_warn(format!(
                        "Could not put the system proxy back after the self-heal: {}",
                        err.message
                    ));
                }
            }
            if settings.pac {
                if let Err(err) = bridge.set_system_pac(true).await {
                    bridge.log_warn(format!(
                        "Could not put the PAC settings back after the self-heal: {}",
                        err.message
                    ));
                }
            }
            bridge.log_info("Protection is running again: put the system settings back");
        });
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
                    self.note_daemon_reachable();
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

    #[cfg(test)]
    pub fn is_subscription_active(&self) -> bool {
        self.subscription_active.load(Ordering::SeqCst)
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

    pub async fn scan_os_sockets(&self) -> Result<Vec<TrackedConnection>, IpcCallError> {
        let sockets = self
            .call_daemon_detailed::<Vec<TrackedConnection>>(IpcCommand::ScanOsSockets)
            .await?;
        self.state.write().connections = sockets.clone();
        Ok(sockets)
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

    /// Exit path of the app: gives the proxy settings back unless the background service keeps
    /// protecting (then they must stay, or the protection would silently stop).
    pub fn restore_system_settings_unless_protected(&self) {
        if self.keep_settings_on_exit.load(Ordering::SeqCst) {
            self.log_info(
                "Leaving the system proxy settings: protection continues in the background",
            );
            return;
        }
        self.restore_system_settings_on_exit();
    }

    /// The daemon answered: the next unreachable period starts from zero.
    fn note_daemon_reachable(&self) {
        *self.unreachable_since.lock() = None;
        self.self_heal_done.store(false, Ordering::SeqCst);
    }

    /// When the daemon has been unreachable for a while, gives the proxy settings back (only the
    /// values still owned by RouteWard) so the user's normal connection works, and says so once.
    ///
    /// Called at startup and each time the connection attempt fails; it does nothing while a
    /// start is in progress or once the settings were given back for this unreachable period.
    async fn self_heal_if_daemon_unreachable(&self) {
        if self.is_daemon_connected() {
            self.note_daemon_reachable();
            return;
        }
        let since = *self
            .unreachable_since
            .lock()
            .get_or_insert_with(std::time::Instant::now);
        if since.elapsed() < Duration::from_secs(DAEMON_UNREACHABLE_GRACE_SECS) {
            return;
        }
        if self.daemon_start_guard.is_in_flight()
            || self.self_heal_done.swap(true, Ordering::SeqCst)
        {
            return;
        }
        let endpoint = self.get_diagnostics().relay_tcp_endpoint;
        let pac_url = self.pac_url();
        let outcome = tokio::task::spawn_blocking(move || {
            SystemProxyManager::restore_owned_settings(&endpoint, &pac_url)
        })
        .await;
        match outcome {
            Ok(Ok(report)) if report.proxy_restored || report.pac_restored => {
                {
                    let mut healed = self.healed_settings.lock();
                    healed.proxy |= report.proxy_restored;
                    healed.pac |= report.pac_restored;
                }
                self.log_info("RouteWard is not running: restored the system proxy settings");
                self.show_notice(TRAY_KEY_NOTICE_RESTORED_BODY, TrayBalloonLevel::Info);
            }
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                self.log_warn(format!(
                    "Could not restore the system proxy settings while the daemon is unreachable: {err}"
                ));
            }
            Err(join_err) => {
                self.log_warn(format!("Self-heal task failed: {join_err}"));
            }
        }
    }

    /// Decides what happens to protection when the app exits, and does what it takes.
    ///
    /// - Background service installed and protection active (or about to resume): it keeps
    ///   running; the proxy settings stay; the first time a notice explains it.
    /// - No service (a daemon this app started): the engine is stopped first.
    pub async fn prepare_exit(&self) -> ExitDisposition {
        if !self.is_daemon_connected() {
            return ExitDisposition::Stopped;
        }
        let diag = self.get_diagnostics();
        let service_installed = tokio::task::spawn_blocking(daemon_launcher::is_service_installed)
            .await
            .unwrap_or(false);
        if service_installed {
            if !(diag.running || diag.paused_until_epoch_ms.is_some()) {
                return ExitDisposition::Stopped;
            }
            self.keep_settings_on_exit.store(true, Ordering::SeqCst);
            let announce = self.notice_flags.claim(NOTICE_EXIT_BACKGROUND);
            if announce {
                self.show_balloon(
                    self.i18n.t(TRAY_KEY_NOTICE_EXIT_TITLE),
                    self.i18n.t(TRAY_KEY_NOTICE_EXIT_BODY),
                    TrayBalloonLevel::Info,
                );
            }
            return ExitDisposition::ProtectionContinues { announce };
        }
        if exit_must_stop_engine(diag.running, diag.paused_until_epoch_ms) {
            let stop = tokio::time::timeout(
                Duration::from_secs(EXIT_STOP_ENGINE_TIMEOUT_SECS),
                self.toggle_engine(false),
            )
            .await;
            match stop {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => self.log_warn(format!("Could not stop the engine on exit: {err}")),
                Err(_) => self.log_warn("Timed out stopping the engine on exit"),
            }
        }
        ExitDisposition::Stopped
    }

    /// First time the window is closed into the tray: says the app is still running there.
    pub fn notify_close_to_tray_once(&self) {
        if self.notice_flags.claim(NOTICE_CLOSE_TO_TRAY) {
            self.show_balloon(
                self.i18n.t(TRAY_KEY_NOTICE_CLOSE_TITLE),
                self.i18n.t(TRAY_KEY_NOTICE_CLOSE_BODY),
                TrayBalloonLevel::Info,
            );
        }
    }

    /// Tray "Start protection": brings the daemon up (installing the background service when
    /// there is none), then turns the engine on. Every failure ends in a balloon.
    pub async fn tray_start_protection(&self) {
        match self.start_privileged_daemon_detailed().await {
            Ok(report) => {
                if let Some(reason_key) = report.fallback_reason_key {
                    self.show_notice(reason_key, TrayBalloonLevel::Warning);
                }
                let diag = &report.state.diagnostics;
                if diag.daemon_connected && !diag.running {
                    if let Err(err) = self.toggle_engine(true).await {
                        self.log_warn(format!("Tray auto-enable after daemon start failed: {err}"));
                        self.show_balloon(
                            self.i18n.t(TRAY_KEY_NOTICE_TITLE),
                            self.describe_ipc_failure(&err, TRAY_KEY_NOTICE_START_FAILED),
                            TrayBalloonLevel::Warning,
                        );
                    }
                }
            }
            Err(DaemonLaunchError::AlreadyInFlight) => {}
            Err(err) => {
                self.log_warn(format!("Tray daemon start failed: {err:?}"));
                self.show_notice(err.tray_notice_key(), TrayBalloonLevel::Warning);
            }
        }
    }

    /// Tray "Turn protection on/off" and "Resume now".
    pub async fn tray_toggle_engine(&self) {
        let running = self.get_diagnostics().running;
        if let Err(err) = self.toggle_engine(!running).await {
            self.log_warn(format!("Tray engine toggle failed: {err}"));
            self.show_balloon(
                self.i18n.t(TRAY_KEY_NOTICE_TITLE),
                self.describe_ipc_failure(&err, TRAY_KEY_NOTICE_TOGGLE_FAILED),
                TrayBalloonLevel::Warning,
            );
        }
    }

    /// Tray "Pause 15 min": the daemon keeps the deadline and resumes by itself.
    pub async fn tray_pause(&self, seconds: u64) {
        if let Err(err) = self.pause_engine(seconds).await {
            self.log_warn(format!("Tray timed pause failed: {err}"));
            self.show_balloon(
                self.i18n.t(TRAY_KEY_NOTICE_TITLE),
                self.describe_ipc_failure(&err, TRAY_KEY_NOTICE_PAUSE_FAILED),
                TrayBalloonLevel::Warning,
            );
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
    ) -> Result<FoxyProxyImportResult, IpcCallError> {
        let report = self
            .call_daemon_detailed::<FoxyProxyImportResult>(IpcCommand::ImportFoxyProxyJson {
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
    ) -> Result<Vec<ProfileSummary>, IpcCallError> {
        let list = self
            .call_daemon_detailed::<Vec<ProfileSummary>>(IpcCommand::SaveNamedProfile {
                profile_id,
                name,
            })
            .await?;
        *self.profiles.write() = list.clone();
        let _ = self.refresh_state().await;
        Ok(list)
    }

    pub async fn switch_profile(&self, profile_id: String) -> Result<ProfileConfig, IpcCallError> {
        let prof = self
            .call_daemon_detailed::<ProfileConfig>(IpcCommand::SwitchProfile { profile_id })
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
            if let Err(err) = self.switch_profile(id.clone()).await {
                self.log_warn(format!(
                    "Tray profile switch to '{id}' failed: {}",
                    err.message()
                ));
            }
        }
    }

    pub async fn delete_profile(
        &self,
        profile_id: String,
    ) -> Result<Vec<ProfileSummary>, IpcCallError> {
        let list = self
            .call_daemon_detailed::<Vec<ProfileSummary>>(IpcCommand::DeleteProfile { profile_id })
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

    pub async fn clear_closed_connections(&self) -> Result<(), IpcCallError> {
        self.call_daemon_detailed::<serde_json::Value>(IpcCommand::ClearClosedConnections)
            .await?;
        self.state
            .write()
            .connections
            .retain(|c| c.status == ConnectionStatus::Active);
        Ok(())
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
    ) -> Result<RuleEvaluationResult, IpcCallError> {
        self.call_daemon_detailed::<RuleEvaluationResult>(IpcCommand::EvaluateRule { request })
            .await
    }

    pub async fn test_proxy(&self, proxy_id: String) -> Result<ProxyHealthReport, IpcCallError> {
        self.call_daemon_detailed::<ProxyHealthReport>(IpcCommand::TestProxy { proxy_id })
            .await
    }

    pub async fn test_all_proxies(&self) -> Result<Vec<ProxyHealthReport>, IpcCallError> {
        self.call_daemon_detailed::<Vec<ProxyHealthReport>>(IpcCommand::TestAllProxies)
            .await
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

    /// Applies the diagnostics a daemon call returned to the cached state and the tray.
    fn apply_engine_result(
        &self,
        result: Result<SystemDiagnostics, IpcCallError>,
    ) -> Result<SystemDiagnostics, IpcCallError> {
        match result {
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

    /// Starts or stops the engine. Either choice cancels a pending pause (the daemon decides).
    pub async fn toggle_engine(&self, start: bool) -> Result<SystemDiagnostics, IpcCallError> {
        let result = self
            .call_daemon_detailed::<SystemDiagnostics>(IpcCommand::ToggleEngine { start })
            .await;
        self.apply_engine_result(result)
    }

    /// Pauses protection for `duration_secs`. The daemon keeps the deadline and resumes by
    /// itself, so the pause survives this app being closed.
    pub async fn pause_engine(
        &self,
        duration_secs: u64,
    ) -> Result<SystemDiagnostics, IpcCallError> {
        let result = self
            .call_daemon_detailed::<SystemDiagnostics>(IpcCommand::PauseEngine { duration_secs })
            .await;
        self.apply_engine_result(result)
    }

    pub async fn set_interception_mode(
        &self,
        mode: InterceptionMode,
    ) -> Result<SystemDiagnostics, IpcCallError> {
        let result = self
            .call_daemon_detailed::<SystemDiagnostics>(IpcCommand::SetInterceptionMode { mode })
            .await;
        self.apply_engine_result(result)
    }

    pub async fn start_privileged_daemon(&self) -> Result<DaemonFullState, DaemonLaunchError> {
        self.start_privileged_daemon_detailed()
            .await
            .map(|report| report.state)
    }

    /// Brings the daemon up. Without the background service, one elevated command installs it,
    /// starts it and turns on the sign-in autostart (minimized); when that fails, a plain
    /// elevated daemon runs instead and the report says why.
    pub async fn start_privileged_daemon_detailed(
        &self,
    ) -> Result<DaemonStartReport, DaemonLaunchError> {
        if self.is_daemon_connected() {
            return Ok(DaemonStartReport {
                state: self.refresh_state().await,
                fallback_reason_key: None,
            });
        }

        let release = self
            .daemon_start_guard
            .try_acquire()
            .ok_or(DaemonLaunchError::AlreadyInFlight)?;
        let locale = self.i18n.get_locale();
        let outcome =
            match daemon_launcher::start_privileged_daemon_with_release(&release, &locale).await {
                Ok(outcome) => outcome,
                Err(err) => {
                    self.log_error(format!(
                        "Failed to launch privileged daemon: {}",
                        err.detail()
                    ));
                    return Err(err);
                }
            };
        let fallback_reason_key = outcome.fallback_reason_key;
        if let Some(reason_key) = fallback_reason_key {
            self.log_warn(format!(
                "Background service not installed, running a plain daemon instead ({reason_key})"
            ));
        }
        if outcome.mode == LaunchMode::ServiceInstalled {
            // First successful install of the service: protection also comes back at sign-in.
            self.log_info("Background service installed; enabling the sign-in autostart");
            if let Err(err) = self.set_autostart(true).await {
                self.log_warn(format!("Could not enable the sign-in autostart: {err}"));
            }
        }
        let proc_handle = outcome.handle;

        for _ in 0..DAEMON_START_POLL_ATTEMPTS {
            let state = self.refresh_state().await;
            if state.diagnostics.daemon_connected {
                return Ok(DaemonStartReport {
                    state,
                    fallback_reason_key,
                });
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
        Ok(DaemonStartReport {
            state: self.refresh_state().await,
            fallback_reason_key,
        })
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

    pub async fn flush_fake_ip_cache(&self) -> Result<(), IpcCallError> {
        self.call_daemon_detailed::<serde_json::Value>(IpcCommand::FlushFakeIps)
            .await?;
        self.state.write().fake_ips.clear();
        Ok(())
    }

    /// Flushes the operating system DNS resolver cache through the daemon (not the Fake-IP
    /// table). Returns whether the daemon reported success.
    pub async fn flush_os_dns_cache(&self) -> Result<bool, IpcCallError> {
        let reply: serde_json::Value = self
            .call_daemon_detailed(IpcCommand::FlushOsDnsCache)
            .await?;
        Ok(reply
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
    }

    /// Aggregated blocked connections from the daemon (`since` in epoch milliseconds).
    pub async fn list_blocked(
        &self,
        since: Option<i64>,
        limit: Option<usize>,
    ) -> Result<BlockedResponse, IpcCallError> {
        self.call_daemon_detailed(IpcCommand::ListBlocked { since, limit })
            .await
    }

    /// One page of the daemon's logs (memory ring or a daily file).
    pub async fn query_logs(
        &self,
        query: QueryLogsRequest,
    ) -> Result<QueryLogsResponse, IpcCallError> {
        self.call_daemon_detailed(IpcCommand::QueryLogs {
            source: query.source,
            min_level: query.min_level,
            components: query.components,
            text: query.text,
            pid: query.pid,
            connection_id: query.connection_id,
            since: query.since,
            until: query.until,
            limit: query.limit,
            cursor: query.cursor,
        })
        .await
    }

    /// The daemon's check-up findings.
    pub async fn analyze_diagnostics(&self) -> Result<AnalyzeResponse, IpcCallError> {
        self.call_daemon_detailed(IpcCommand::Analyze).await
    }

    /// What a connection would do after a rule change, without applying it.
    pub async fn preview_rule_change(
        &self,
        preview: PreviewRuleChangeRequest,
    ) -> Result<PredictedOutcome, IpcCallError> {
        self.call_daemon_detailed(IpcCommand::PreviewRuleChange {
            upserts: preview.upserts,
            remove_ids: preview.remove_ids,
            request: preview.request,
        })
        .await
    }

    /// The daemon's redacted diagnostic bundle, plus the desktop's own redacted log files.
    pub async fn collect_diagnostics(
        &self,
        options: CollectOptions,
    ) -> Result<serde_json::Value, IpcCallError> {
        let mut bundle: serde_json::Value = self
            .call_daemon_detailed(IpcCommand::CollectDiagnostics {
                log_days: options.log_days,
                include_connections: options.include_connections,
                include_profile: options.include_profile,
                mask_domains: options.mask_domains,
            })
            .await?;
        let telemetry = &self.constants.telemetry;
        // Same directory as the daemon (a daemon run as the same user): already in the bundle.
        if telemetry.resolve_daemon_log_dir() != self.log_dir {
            let known_domains = if options.mask_domains {
                let state = self.state.read();
                state
                    .connections
                    .iter()
                    .flat_map(|c| {
                        std::iter::once(c.target_host.clone()).chain(c.resolved_domain.clone())
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let log_dir = self.log_dir.clone();
            let app_name = telemetry.log_app_name.clone();
            let limits = BundleLimits {
                max_log_days: telemetry.diagnostics_max_log_days,
                logs_max_bytes: telemetry.diagnostics_logs_max_bytes,
                bundle_max_bytes: telemetry.diagnostics_bundle_max_bytes,
                hard_max_bytes: self.constants.ipc.max_line_bytes,
            };
            let redactor =
                Redactor::from_environment().with_profile_credentials(&self.state.read().profile);
            if let Ok(merged) = tokio::task::spawn_blocking(move || {
                crate::desktop_logs::add_desktop_logs(
                    &mut bundle,
                    &crate::desktop_logs::DesktopLogSource {
                        log_dir: &log_dir,
                        app_name: &app_name,
                        options,
                        limits,
                        known_domains,
                        redactor,
                    },
                );
                bundle
            })
            .await
            {
                return Ok(merged);
            }
            return Err(IpcCallError::Remote {
                message: "diagnostic bundle assembly failed".to_string(),
                error_key: None,
            });
        }
        Ok(bundle)
    }

    pub fn list_logs(&self) -> Vec<LogEntry> {
        self.state.read().logs.clone()
    }

    pub async fn clear_logs(&self) -> Result<(), IpcCallError> {
        self.call_daemon_detailed::<serde_json::Value>(IpcCommand::ClearLogs)
            .await?;
        self.state.write().logs.clear();
        Ok(())
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
