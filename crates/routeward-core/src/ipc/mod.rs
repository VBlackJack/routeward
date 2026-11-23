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

pub mod protocol;
pub mod transport;

use crate::config::IpcConstants;
use crate::diagnostics::bundle::CollectOptions;
use crate::diagnostics::logs::{QueryLogsRequest, QueryLogsResponse};
use crate::diagnostics::{self, AnalyzeResponse, BlockedResponse, PreviewRuleChangeRequest};
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_DAEMON_IPC_ERROR};
use crate::interceptor::policy::PredictedOutcome;
use crate::interceptor::RouteWardController;
use crate::ipc::protocol::{
    parse_ipc_request, read_bounded_line, recv_next_stream_event, DaemonFullState, IpcCommand,
    IpcRequest, IpcResponse, ReadLineOutcome,
};
use crate::ipc::transport::{connect_ipc_stream, IpcServer, IpcStream, PeerIdentity};
use crate::pac::FoxyProxyImporter;
use crate::telemetry::LogLevel;
use serde::de::DeserializeOwned;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use uuid::Uuid;

const COMPONENT_DAEMON_IPC: &str = "DaemonIpc";
const DEFAULT_OS_SCAN_LIMIT: usize = 48;

pub async fn wait_for_shutdown_signal(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

pub fn generate_ephemeral_token() -> String {
    Uuid::new_v4().to_string()
}

pub struct DaemonIpcService {
    controller: RouteWardController,
    server: IpcServer,
}

impl DaemonIpcService {
    pub fn bind(controller: RouteWardController) -> RouteWardResult<Self> {
        Self::bind_with_allowed_sids(controller, &[])
    }

    pub fn bind_with_allowed_sids(
        controller: RouteWardController,
        allowed_sids: &[String],
    ) -> RouteWardResult<Self> {
        let server = IpcServer::bind_with_allowed_sids(&controller.constants.ipc, allowed_sids)?;
        Ok(Self { controller, server })
    }

    pub fn bind_for_test(controller: RouteWardController) -> RouteWardResult<Self> {
        let server = IpcServer::bind_for_test(&controller.constants.ipc)?;
        Ok(Self { controller, server })
    }

    #[cfg(windows)]
    pub fn bind_windows_custom_pipe(
        controller: RouteWardController,
        pipe_name: &str,
    ) -> RouteWardResult<Self> {
        let server = IpcServer::bind_windows(pipe_name)?;
        Ok(Self { controller, server })
    }

    pub async fn run_accept_loop(self) -> RouteWardResult<()> {
        let (_never_tx, never_rx) = watch::channel(false);
        self.run_accept_loop_until(never_rx).await
    }

    pub async fn run_accept_loop_until(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> RouteWardResult<()> {
        let mut client_tasks = tokio::task::JoinSet::new();
        // Expired temporary rules are swept and persisted by the daemon, whatever the engine
        // state. The task is aborted with the accept loop.
        let sweep_interval = Duration::from_millis(
            self.controller
                .constants
                .ipc
                .rule_expiry_sweep_interval_ms
                .max(1),
        );
        let expiry_task = tokio::spawn(run_rule_expiry_persistence(
            self.controller.clone(),
            sweep_interval,
            shutdown.clone(),
            |ctrl: &RouteWardController| {
                let _ = ctrl.persist_after_rule_expiry();
            },
        ));
        let _expiry_guard = AbortOnDrop(expiry_task);
        loop {
            while client_tasks.try_join_next().is_some() {}
            tokio::select! {
                _ = wait_for_shutdown_signal(&mut shutdown) => {
                    client_tasks.abort_all();
                    while client_tasks.join_next().await.is_some() {}
                    return Ok(());
                }
                accept_res = self.server.accept() => {
                    match accept_res {
                        Ok((stream, peer)) => {
                            log_peer_connection(&self.controller, &peer);
                            let ctrl = self.controller.clone();
                            client_tasks.spawn(async move {
                                handle_client_stream(stream, ctrl).await;
                            });
                        }
                        Err(err) => {
                            self.controller.telemetry.push_log(
                                LogLevel::Error,
                                COMPONENT_DAEMON_IPC,
                                format!("IPC accept error: {err}"),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Aborts the wrapped task when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sweeps expired rules every `interval` (the first sweep runs at once, which covers a profile
/// loaded with expired rules) and calls `persist` each time rules were removed, by this timer or
/// by the engine ticker. Returns on shutdown.
async fn run_rule_expiry_persistence<F>(
    controller: RouteWardController,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
    persist: F,
) where
    F: Fn(&RouteWardController),
{
    let mut notices = controller.subscribe_rule_expiry();
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = wait_for_shutdown_signal(&mut shutdown) => return,
            _ = timer.tick() => {
                controller.sweep_expired_rules(chrono::Utc::now());
            }
            notice = notices.recv() => match notice {
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    persist(&controller);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    }
}

fn log_peer_connection(controller: &RouteWardController, peer: &PeerIdentity) {
    if let (Some(uid), Some(gid)) = (peer.uid, peer.gid) {
        let pid_label = peer
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_DAEMON_IPC,
            format!("Accepted IPC client via SO_PEERCRED: pid={pid_label} uid={uid} gid={gid}"),
        );
    }
}

pub async fn handle_client_stream(stream: IpcStream, controller: RouteWardController) {
    let max_line_bytes = controller.constants.ipc.max_line_bytes;
    let idle_timeout_ms = controller.constants.ipc.idle_timeout_ms;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    loop {
        match read_bounded_line(&mut reader, max_line_bytes, idle_timeout_ms).await {
            ReadLineOutcome::Line(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                let req = match parse_ipc_request(&line) {
                    Ok(r) => r,
                    Err(err_resp) => {
                        if write_json_line(&mut write_half, &err_resp).await.is_err() {
                            break;
                        }
                        continue;
                    }
                };

                if matches!(req.command, IpcCommand::Subscribe) {
                    let mut rx = controller.telemetry.subscribe();
                    let ack =
                        IpcResponse::success(req.id, &serde_json::json!({ "subscribed": true }));
                    if write_json_line(&mut write_half, &ack).await.is_err() {
                        break;
                    }

                    // Stream events until client disconnects (EOF) or channel closes
                    loop {
                        tokio::select! {
                            maybe_ev = recv_next_stream_event(&mut rx, &controller.telemetry) => {
                                match maybe_ev {
                                    Some(stream_ev) => {
                                        if write_json_line(&mut write_half, &stream_ev).await.is_err() {
                                            break;
                                        }
                                    }
                                    None => break,
                                }
                            }
                            buf_res = reader.fill_buf() => {
                                match buf_res {
                                    Ok([]) | Err(_) => break,
                                    Ok(buf) => {
                                        let len = buf.len();
                                        reader.consume(len);
                                    }
                                }
                            }
                        }
                    }
                    break;
                }

                let response = dispatch_command(&controller, req).await;
                if write_json_line(&mut write_half, &response).await.is_err() {
                    break;
                }
            }
            ReadLineOutcome::Eof => break,
            ReadLineOutcome::LineTooLong => {
                controller.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DAEMON_IPC,
                    format!(
                        "Closing IPC client connection: line exceeded maxLineBytes ({max_line_bytes})"
                    ),
                );
                let err_resp = IpcResponse::error(
                    None,
                    format!("line_too_long: exceeded {max_line_bytes} bytes"),
                );
                let _ = write_json_line(&mut write_half, &err_resp).await;
                break;
            }
            ReadLineOutcome::IdleTimeout => {
                controller.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_DAEMON_IPC,
                    format!("Closing idle IPC client connection after {idle_timeout_ms} ms"),
                );
                break;
            }
            ReadLineOutcome::IoError(_) => break,
        }
    }
}

/// Builds a failed response that carries the error's i18n key, so the desktop bridge can classify
/// it (for example a failed profile save is a server-side fault, not a validation failure).
fn keyed_error_response(id: String, err: &RouteWardError) -> IpcResponse {
    IpcResponse::error_with_key(Some(id), Some(err.i18n_key().to_string()), err.to_string())
}

/// Persists the default profile off the Tokio async worker pool and maps errors to a keyed IPC
/// response.
async fn save_profile_default_async(
    controller: &RouteWardController,
    id: &str,
) -> Result<(), IpcResponse> {
    let ctrl = controller.clone();
    match run_blocking(move || ctrl.save_profile_default()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(keyed_error_response(id.to_string(), &err)),
        Err(detail) => Err(IpcResponse::error(Some(id.to_string()), detail)),
    }
}

/// Persists the default profile off the async worker pool and returns `{ "ok": true }` on success.
async fn save_profile_ok_response(controller: &RouteWardController, id: String) -> IpcResponse {
    match save_profile_default_async(controller, &id).await {
        Ok(()) => IpcResponse::success(id, &serde_json::json!({ "ok": true })),
        Err(resp) => resp,
    }
}

async fn dispatch_named_profile_command(
    controller: &RouteWardController,
    id: String,
    cmd: IpcCommand,
) -> IpcResponse {
    let ctrl = controller.clone();
    match cmd {
        IpcCommand::ListProfiles => match run_blocking(move || ctrl.list_named_profiles()).await {
            Ok(Ok(list)) => IpcResponse::success(id, &list),
            Ok(Err(err)) => keyed_error_response(id, &err),
            Err(detail) => IpcResponse::error(Some(id), detail),
        },
        IpcCommand::SaveNamedProfile { profile_id, name } => {
            match run_blocking(move || {
                ctrl.save_named_profile(profile_id.as_deref(), name.as_deref())
            })
            .await
            {
                Ok(Ok(list)) => IpcResponse::success(id, &list),
                Ok(Err(err)) => keyed_error_response(id, &err),
                Err(detail) => IpcResponse::error(Some(id), detail),
            }
        }
        IpcCommand::SwitchProfile { profile_id } => {
            match run_blocking(move || ctrl.switch_named_profile(&profile_id)).await {
                Ok(Ok(prof)) => IpcResponse::success(id, &prof),
                Ok(Err(err)) => keyed_error_response(id, &err),
                Err(detail) => IpcResponse::error(Some(id), detail),
            }
        }
        IpcCommand::DeleteProfile { profile_id } => {
            match run_blocking(move || ctrl.delete_named_profile(&profile_id)).await {
                Ok(Ok(list)) => IpcResponse::success(id, &list),
                Ok(Err(err)) => keyed_error_response(id, &err),
                Err(detail) => IpcResponse::error(Some(id), detail),
            }
        }
        _ => unreachable!("only named-profile commands are routed here"),
    }
}

async fn dispatch_diagnostics_command(
    controller: &RouteWardController,
    id: String,
    cmd: IpcCommand,
) -> IpcResponse {
    match cmd {
        IpcCommand::ListBlocked { since, limit } => {
            IpcResponse::success(id, &diagnostics::list_blocked(controller, since, limit))
        }
        IpcCommand::QueryLogs {
            source,
            min_level,
            components,
            text,
            pid,
            connection_id,
            since,
            until,
            limit,
            cursor,
        } => {
            let query = QueryLogsRequest {
                source,
                min_level,
                components,
                text,
                pid,
                connection_id,
                since,
                until,
                limit,
                cursor,
            };
            let ctrl = controller.clone();
            match run_blocking(move || diagnostics::query_logs(&ctrl, &query)).await {
                Ok(Ok(res)) => IpcResponse::success(id, &res),
                Ok(Err(err)) => IpcResponse::error(Some(id), err.to_string()),
                Err(detail) => IpcResponse::error(Some(id), detail),
            }
        }
        IpcCommand::Analyze => {
            let ctrl = controller.clone();
            match run_blocking(move || diagnostics::analyze(&ctrl)).await {
                Ok(res) => IpcResponse::success(id, &res),
                Err(detail) => IpcResponse::error(Some(id), detail),
            }
        }
        IpcCommand::CollectDiagnostics {
            log_days,
            include_connections,
            include_profile,
            mask_domains,
        } => {
            let options = CollectOptions {
                log_days,
                include_connections,
                include_profile,
                mask_domains,
            };
            let ctrl = controller.clone();
            match run_blocking(move || diagnostics::collect_diagnostics(&ctrl, options)).await {
                Ok(bundle) => IpcResponse::success(id, &bundle),
                Err(detail) => IpcResponse::error(Some(id), detail),
            }
        }
        IpcCommand::PreviewRuleChange {
            upserts,
            remove_ids,
            request,
        } => {
            let outcome = diagnostics::preview_rule_change(
                controller,
                &PreviewRuleChangeRequest {
                    upserts,
                    remove_ids,
                    request,
                },
            );
            IpcResponse::success(id, &outcome)
        }
        _ => unreachable!("only diagnostics commands are routed here"),
    }
}

async fn dispatch_command(controller: &RouteWardController, req: IpcRequest) -> IpcResponse {
    let id = req.id;
    match req.command {
        IpcCommand::GetState => {
            let state = DaemonFullState {
                diagnostics: controller.diagnostics(),
                profile: controller.profile.read().redacted_for_ipc(),
                telemetry: controller.telemetry.snapshot(),
                connections: controller.telemetry.list_connections(),
                logs: controller.telemetry.list_logs(),
                fake_ips: controller.dns.list_entries(),
            };
            IpcResponse::success(id, &state)
        }
        IpcCommand::GetDiagnostics => IpcResponse::success(id, &controller.diagnostics()),
        IpcCommand::GetTelemetry => IpcResponse::success(id, &controller.telemetry.snapshot()),
        IpcCommand::ToggleEngine { start } => {
            if start {
                if let Err(err) = controller.start_protection() {
                    return keyed_error_response(id, &err);
                }
            } else {
                controller.stop_engine();
            }
            controller.record_protection_choice(start);
            IpcResponse::success(id, &controller.diagnostics())
        }
        IpcCommand::PauseEngine { duration_secs } => {
            match controller.pause_protection(duration_secs) {
                Ok(_) => IpcResponse::success(id, &controller.diagnostics()),
                Err(err) => keyed_error_response(id, &err),
            }
        }
        IpcCommand::SetInterceptionMode { mode } => {
            controller.set_interception_mode(mode);
            if let Err(resp) = save_profile_default_async(controller, &id).await {
                return resp;
            }
            IpcResponse::success(id, &controller.diagnostics())
        }
        IpcCommand::SetTheme { theme, accent } => {
            controller.set_theme_config(theme, accent);
            save_profile_ok_response(controller, id).await
        }
        IpcCommand::GetProfile => {
            let prof = controller.profile.read().redacted_for_ipc();
            IpcResponse::success(id, &prof)
        }
        IpcCommand::ReplaceProfile { profile } => {
            if let Err(err) = controller.replace_profile(profile) {
                return keyed_error_response(id, &err);
            }
            if let Err(resp) = save_profile_default_async(controller, &id).await {
                return resp;
            }
            let prof = controller.profile.read().redacted_for_ipc();
            IpcResponse::success(id, &prof)
        }
        IpcCommand::UpsertRule { rule } => {
            controller.upsert_rule(rule);
            save_profile_ok_response(controller, id).await
        }
        IpcCommand::RemoveRule { rule_id } => {
            controller.remove_rule(&rule_id);
            save_profile_ok_response(controller, id).await
        }
        IpcCommand::UpsertProxy { node } => {
            controller.upsert_proxy(node);
            save_profile_ok_response(controller, id).await
        }
        IpcCommand::RemoveProxy { proxy_id } => {
            controller.remove_proxy(&proxy_id);
            save_profile_ok_response(controller, id).await
        }
        IpcCommand::SetPrimaryProxy { proxy_id } => {
            if !controller.set_primary_proxy(&proxy_id) {
                return IpcResponse::error_with_key(
                    Some(id),
                    Some(crate::error::ERR_KEY_PROXY_NOT_FOUND.to_string()),
                    "Proxy not found",
                );
            }
            save_profile_ok_response(controller, id).await
        }
        IpcCommand::UpsertChain { chain } => {
            controller.upsert_chain(chain);
            save_profile_ok_response(controller, id).await
        }
        IpcCommand::RemoveChain { chain_id } => {
            controller.remove_chain(&chain_id);
            save_profile_ok_response(controller, id).await
        }
        IpcCommand::EvaluateRule { request } => {
            let res = controller.evaluate_rule(&request);
            IpcResponse::success(id, &res)
        }
        IpcCommand::SimulateConnection { request } => {
            let tracked = controller.simulate_connection(request);
            IpcResponse::success(id, &tracked)
        }
        IpcCommand::ScanOsSockets => {
            let ctrl = controller.clone();
            match run_blocking(move || ctrl.scan_and_ingest_os_sockets(DEFAULT_OS_SCAN_LIMIT)).await
            {
                Ok(sockets) => IpcResponse::success(id, &sockets),
                Err(detail) => IpcResponse::error(Some(id), detail),
            }
        }
        IpcCommand::TestProxy { proxy_id } => match controller.test_proxy(&proxy_id).await {
            Ok(report) => IpcResponse::success(id, &report),
            Err(err) => keyed_error_response(id, &err),
        },
        IpcCommand::TestAllProxies => {
            let reports = controller.test_all_proxies().await;
            IpcResponse::success(id, &reports)
        }
        IpcCommand::ListConnections => {
            let conns = controller.telemetry.list_connections();
            IpcResponse::success(id, &conns)
        }
        IpcCommand::TerminateConnection { connection_id } => {
            let terminated = controller.terminate_connection(&connection_id);
            IpcResponse::success(id, &serde_json::json!({ "terminated": terminated }))
        }
        IpcCommand::ClearClosedConnections => {
            controller.telemetry.clear_closed_connections();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        IpcCommand::ListLogs => {
            let logs = controller.telemetry.list_logs();
            IpcResponse::success(id, &logs)
        }
        IpcCommand::ClearLogs => {
            controller.telemetry.clear_logs();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        cmd @ (IpcCommand::ListBlocked { .. }
        | IpcCommand::QueryLogs { .. }
        | IpcCommand::Analyze
        | IpcCommand::CollectDiagnostics { .. }
        | IpcCommand::PreviewRuleChange { .. }) => {
            dispatch_diagnostics_command(controller, id, cmd).await
        }
        IpcCommand::ListFakeIps => {
            let entries = controller.dns.list_entries();
            IpcResponse::success(id, &entries)
        }
        IpcCommand::AllocateFakeIp { domain } => {
            let ip = controller.allocate_fake_ip(&domain);
            IpcResponse::success(id, &ip)
        }
        IpcCommand::FlushFakeIps => {
            controller.dns.flush();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        IpcCommand::FlushOsDnsCache => {
            let ctrl = controller.clone();
            match run_blocking(move || ctrl.flush_os_dns_cache("ipc")).await {
                Ok(flushed) => IpcResponse::success(id, &serde_json::json!({ "ok": flushed })),
                Err(detail) => IpcResponse::error(Some(id), detail),
            }
        }
        IpcCommand::ImportFoxyProxyJson {
            json,
            process_patterns,
        } => {
            let next_priority = controller
                .profile
                .read()
                .rules
                .iter()
                .map(|r| r.priority)
                .min()
                .unwrap_or(20)
                .max(10);
            match FoxyProxyImporter::parse(&json, process_patterns, next_priority) {
                Ok(mut imported) => {
                    for proxy in &imported.proxies {
                        controller.upsert_proxy(proxy.clone());
                    }
                    for rule in &imported.rules {
                        controller.upsert_rule(rule.clone());
                    }
                    if let Err(resp) = save_profile_default_async(controller, &id).await {
                        return resp;
                    }
                    imported.proxies = imported
                        .proxies
                        .into_iter()
                        .map(|p| p.redacted_for_ipc())
                        .collect();
                    IpcResponse::success(id, &imported)
                }
                Err(err) => keyed_error_response(id, &err),
            }
        }
        cmd @ (IpcCommand::ListProfiles
        | IpcCommand::SaveNamedProfile { .. }
        | IpcCommand::SwitchProfile { .. }
        | IpcCommand::DeleteProfile { .. }) => {
            dispatch_named_profile_command(controller, id, cmd).await
        }
        IpcCommand::Subscribe => {
            IpcResponse::success(id, &serde_json::json!({ "subscribed": true }))
        }
    }
}

/// Runs file-reading work off the async workers.
async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| format!("task_failed: {err}"))
}

async fn write_json_line<W, T>(writer: &mut W, payload: &T) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize,
{
    let mut bytes = serde_json::to_vec(payload)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

/// Structured outcome failure when exchanging an IPC command with the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcCallError {
    /// Pipe/socket connection loss, write error, EOF, or idle timeout before a complete reply.
    Transport(String),
    /// Connected daemon responded cleanly with `ok: false`.
    Remote {
        message: String,
        error_key: Option<String>,
    },
    /// Daemon reply exceeded `max_line_bytes` or failed JSON decoding.
    Protocol(String),
}

impl IpcCallError {
    /// Returns `true` only when the IPC transport connection itself failed or dropped.
    pub fn is_transport(&self) -> bool {
        matches!(self, Self::Transport(_))
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Transport(msg) | Self::Protocol(msg) | Self::Remote { message: msg, .. } => msg,
        }
    }

    /// Localizable error key. A transport failure always maps to `errors.daemon.disconnected`,
    /// so callers show that text and keep [`Self::message`] (the raw OS detail) for logs only.
    pub fn error_key(&self) -> Option<&str> {
        match self {
            Self::Remote { error_key, .. } => error_key.as_deref(),
            Self::Transport(_) => Some(crate::error::ERR_KEY_DAEMON_DISCONNECTED),
            Self::Protocol(_) => None,
        }
    }
}

impl std::fmt::Display for IpcCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for IpcCallError {}

#[derive(Debug, Clone)]
pub struct IpcClient {
    ipc_config: IpcConstants,
}

impl IpcClient {
    pub fn new(ipc_config: IpcConstants) -> Self {
        Self { ipc_config }
    }

    pub async fn call_raw(&self, command: IpcCommand) -> RouteWardResult<IpcResponse> {
        let stream = connect_ipc_stream(&self.ipc_config).await?;
        Self::exchange_on_stream(
            stream,
            command,
            self.ipc_config.max_line_bytes,
            self.ipc_config.idle_timeout_ms,
        )
        .await
    }

    /// Calls `command` on the daemon, preserving whether any failure came from transport loss,
    /// protocol framing/decoding, or a live daemon application error (`ok: false`).
    pub async fn call_typed_detailed<T: DeserializeOwned>(
        &self,
        command: IpcCommand,
    ) -> Result<T, IpcCallError> {
        let stream = connect_ipc_stream(&self.ipc_config)
            .await
            .map_err(|err| IpcCallError::Transport(err.to_string()))?;
        let resp = Self::exchange_on_stream_detailed(
            stream,
            command,
            self.ipc_config.max_line_bytes,
            self.ipc_config.idle_timeout_ms,
        )
        .await?;
        if !resp.ok {
            return Err(IpcCallError::Remote {
                message: resp
                    .error
                    .unwrap_or_else(|| "Daemon returned error".to_string()),
                error_key: resp.error_key,
            });
        }
        let val = resp
            .result
            .ok_or_else(|| IpcCallError::Protocol("Daemon returned empty result".to_string()))?;
        serde_json::from_value(val).map_err(|err| {
            IpcCallError::Protocol(format!("Failed to decode daemon response: {err}"))
        })
    }

    /// Stops the engine on the daemon and restarts it after `duration_secs` (1 second to 24
    /// hours); the daemon keeps the deadline, so the pause outlives the caller.
    pub async fn pause_engine(
        &self,
        duration_secs: u64,
    ) -> Result<crate::interceptor::SystemDiagnostics, IpcCallError> {
        self.call_typed_detailed(IpcCommand::PauseEngine { duration_secs })
            .await
    }

    /// Aggregated blocked connections (`since` is epoch milliseconds).
    pub async fn list_blocked(
        &self,
        since: Option<i64>,
        limit: Option<usize>,
    ) -> Result<BlockedResponse, IpcCallError> {
        self.call_typed_detailed(IpcCommand::ListBlocked { since, limit })
            .await
    }

    /// Queries the daemon's logs (memory ring or one of its daily files).
    pub async fn query_logs(
        &self,
        query: QueryLogsRequest,
    ) -> Result<QueryLogsResponse, IpcCallError> {
        self.call_typed_detailed(IpcCommand::QueryLogs {
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

    /// Runs the check-up on the daemon.
    pub async fn analyze(&self) -> Result<AnalyzeResponse, IpcCallError> {
        self.call_typed_detailed(IpcCommand::Analyze).await
    }

    /// Asks the daemon for the redacted diagnostic bundle.
    pub async fn collect_diagnostics(
        &self,
        options: CollectOptions,
    ) -> Result<serde_json::Value, IpcCallError> {
        self.call_typed_detailed(IpcCommand::CollectDiagnostics {
            log_days: options.log_days,
            include_connections: options.include_connections,
            include_profile: options.include_profile,
            mask_domains: options.mask_domains,
        })
        .await
    }

    /// Predicts a connection's outcome under a rule change, without applying it.
    pub async fn preview_rule_change(
        &self,
        preview: PreviewRuleChangeRequest,
    ) -> Result<PredictedOutcome, IpcCallError> {
        self.call_typed_detailed(IpcCommand::PreviewRuleChange {
            upserts: preview.upserts,
            remove_ids: preview.remove_ids,
            request: preview.request,
        })
        .await
    }

    pub async fn call_typed<T: DeserializeOwned>(&self, command: IpcCommand) -> RouteWardResult<T> {
        self.call_typed_detailed(command).await.map_err(|err| {
            let key = match &err {
                IpcCallError::Transport(_) => crate::error::ERR_KEY_DAEMON_DISCONNECTED,
                IpcCallError::Remote { .. } | IpcCallError::Protocol(_) => ERR_KEY_DAEMON_IPC_ERROR,
            };
            RouteWardError::DaemonError {
                key,
                detail: err.to_string(),
            }
        })
    }

    pub async fn exchange_on_stream_detailed(
        stream: IpcStream,
        command: IpcCommand,
        max_line_bytes: usize,
        idle_timeout_ms: u64,
    ) -> Result<IpcResponse, IpcCallError> {
        let req_id = Uuid::new_v4().to_string();
        let req = IpcRequest {
            id: req_id,
            command,
        };

        let (read_half, mut write_half) = tokio::io::split(stream);
        write_json_line(&mut write_half, &req)
            .await
            .map_err(|err| IpcCallError::Transport(format!("Failed to send IPC request: {err}")))?;

        let mut reader = BufReader::new(read_half);
        match read_bounded_line(&mut reader, max_line_bytes, idle_timeout_ms).await {
            ReadLineOutcome::Line(line) => serde_json::from_str::<IpcResponse>(&line)
                .map_err(|err| IpcCallError::Protocol(format!("Invalid IPC response JSON: {err}"))),
            ReadLineOutcome::LineTooLong => Err(IpcCallError::Protocol(format!(
                "Unexpected IPC read outcome: {:?}",
                ReadLineOutcome::LineTooLong
            ))),
            other => Err(IpcCallError::Transport(format!(
                "Unexpected IPC read outcome: {other:?}"
            ))),
        }
    }

    pub async fn exchange_on_stream(
        stream: IpcStream,
        command: IpcCommand,
        max_line_bytes: usize,
        idle_timeout_ms: u64,
    ) -> RouteWardResult<IpcResponse> {
        Self::exchange_on_stream_detailed(stream, command, max_line_bytes, idle_timeout_ms)
            .await
            .map_err(|err| RouteWardError::DaemonError {
                key: if err.is_transport() {
                    crate::error::ERR_KEY_DAEMON_DISCONNECTED
                } else {
                    ERR_KEY_DAEMON_IPC_ERROR
                },
                detail: err.to_string(),
            })
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use crate::config::{ProfileConfig, SystemConstants};
    use crate::error::ERR_KEY_DAEMON_ALREADY_RUNNING;
    use crate::interceptor::SystemDiagnostics;
    use crate::ipc::transport::connect_windows_named_pipe;

    #[tokio::test]
    async fn named_pipe_same_user_connects_and_second_server_is_rejected() {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        let pipe_name = format!(r"\\.\pipe\routeward-test-{}", Uuid::new_v4());
        constants.ipc.windows_pipe_name = pipe_name.clone();

        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;

        let controller = RouteWardController::new(constants.clone(), profile, "en");
        let service = DaemonIpcService::bind_windows_custom_pipe(controller.clone(), &pipe_name)
            .expect("First NamedPipeServer instance should bind");

        // Attempting to bind a second server on the exact same pipe name with first_pipe_instance(true) must fail
        let second_attempt =
            DaemonIpcService::bind_windows_custom_pipe(controller.clone(), &pipe_name);
        match second_attempt {
            Err(RouteWardError::DaemonError { key, .. }) => {
                assert_eq!(key, ERR_KEY_DAEMON_ALREADY_RUNNING);
            }
            other => panic!(
                "Expected ERR_KEY_DAEMON_ALREADY_RUNNING, got {:?}",
                other.err()
            ),
        }

        tokio::spawn(async move {
            let _ = service.run_accept_loop().await;
        });

        let client_stream = connect_windows_named_pipe(&pipe_name)
            .await
            .expect("Same-user client should connect to Named Pipe");
        let resp = IpcClient::exchange_on_stream(
            client_stream,
            IpcCommand::GetDiagnostics,
            constants.ipc.max_line_bytes,
            constants.ipc.idle_timeout_ms,
        )
        .await
        .expect("Exchange GetDiagnostics over Named Pipe");

        assert!(resp.ok);
        let diag: SystemDiagnostics =
            serde_json::from_value(resp.result.expect("diagnostics payload"))
                .expect("deserialize SystemDiagnostics");
        assert!(diag.daemon_connected);
        assert!(!diag.running);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ProfileConfig, ProxyCredentials, ProxyNode, ProxyProtocol, SystemConstants,
    };

    #[tokio::test]
    async fn ipc_redacts_proxy_password_and_preserves_password_when_omitted_on_write() {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        let temp_file = std::env::temp_dir().join(format!(
            "routeward_ipc_test_{}\\active_profile.json",
            Uuid::new_v4()
        ));
        constants.ipc.windows_profile_path = temp_file.to_string_lossy().into_owned();
        constants.ipc.linux_profile_path = temp_file.to_string_lossy().into_owned();

        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;

        let controller = RouteWardController::new(constants, profile, "en");

        let initial_node = ProxyNode {
            id: "proxy-auth-test".to_string(),
            name: "Auth Proxy".to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "10.0.0.10".to_string(),
            port: 1080,
            auth: Some(ProxyCredentials::new("alice", "top_secret_pw_99")),
            udp_enabled: true,
            tls: false,
            tls_skip_verify: false,
            sni: None,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        };
        controller.upsert_proxy(initial_node);

        // 1. GetProfile and GetState over IPC must never include the cleartext password
        let get_prof_resp = dispatch_command(
            &controller,
            IpcRequest {
                id: "req-1".to_string(),
                command: IpcCommand::GetProfile,
            },
        )
        .await;
        assert!(get_prof_resp.ok);
        let serialized_prof = serde_json::to_string(&get_prof_resp).expect("serialize GetProfile");
        assert!(
            !serialized_prof.contains("top_secret_pw_99"),
            "IPC GetProfile response must never leak cleartext password"
        );
        let returned_prof: ProfileConfig =
            serde_json::from_value(get_prof_resp.result.expect("profile result"))
                .expect("deserialize ProfileConfig");
        let returned_proxy = returned_prof
            .proxies
            .iter()
            .find(|p| p.id == "proxy-auth-test")
            .expect("proxy present");
        let returned_auth = returned_proxy.auth.as_ref().expect("auth present");
        assert_eq!(returned_auth.username, "alice");
        assert!(returned_auth.password.is_none());
        assert!(returned_auth.has_password);

        let get_state_resp = dispatch_command(
            &controller,
            IpcRequest {
                id: "req-2".to_string(),
                command: IpcCommand::GetState,
            },
        )
        .await;
        let serialized_state = serde_json::to_string(&get_state_resp).expect("serialize GetState");
        assert!(
            !serialized_state.contains("top_secret_pw_99"),
            "IPC GetState response must never leak cleartext password"
        );

        // 2. Updating the proxy with an absent password (None, as returned by IPC) preserves existing password
        let mut updated_node = returned_proxy.clone();
        updated_node.name = "Renamed Auth Proxy".to_string();
        assert!(updated_node.auth.as_ref().unwrap().password.is_none());
        controller.upsert_proxy(updated_node);

        {
            let prof_guard = controller.profile.read();
            let stored = prof_guard
                .proxies
                .iter()
                .find(|p| p.id == "proxy-auth-test")
                .expect("stored proxy");
            assert_eq!(stored.name, "Renamed Auth Proxy");
            assert_eq!(
                stored.auth.as_ref().unwrap().password_str(),
                "top_secret_pw_99"
            );
            assert!(stored.auth.as_ref().unwrap().has_password);
        }

        // 3. Replacing the profile with a proxy whose password is None also preserves the existing password
        let mut replaced_prof = controller.profile.read().redacted_for_ipc();
        replaced_prof.name = "Updated Profile".to_string();
        controller
            .replace_profile(replaced_prof)
            .expect("valid profile");
        {
            let prof_guard = controller.profile.read();
            let stored = prof_guard
                .proxies
                .iter()
                .find(|p| p.id == "proxy-auth-test")
                .expect("stored proxy after replace_profile");
            assert_eq!(
                stored.auth.as_ref().unwrap().password_str(),
                "top_secret_pw_99"
            );
        }

        // 4. Providing a new password replaces the existing password
        let mut new_pw_node = returned_proxy.clone();
        new_pw_node.auth = Some(ProxyCredentials::new("alice", "rotated_pw_2026"));
        controller.upsert_proxy(new_pw_node);
        {
            let prof_guard = controller.profile.read();
            let stored = prof_guard
                .proxies
                .iter()
                .find(|p| p.id == "proxy-auth-test")
                .expect("stored proxy after password rotation");
            assert_eq!(
                stored.auth.as_ref().unwrap().password_str(),
                "rotated_pw_2026"
            );
        }
    }

    fn test_controller() -> RouteWardController {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;
        RouteWardController::new(constants, profile, "en")
    }

    fn expired_rule(id: &str) -> crate::config::RoutingRule {
        crate::config::RoutingRule {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            priority: 5,
            process_patterns: vec![],
            domain_patterns: vec![],
            ip_cidrs: vec![],
            port_ranges: vec![],
            protocol: crate::config::TransportProtocol::Any,
            action: crate::config::RuleAction::Direct,
            expires_at: Some(chrono::Utc::now() - chrono::Duration::seconds(5)),
        }
    }

    #[tokio::test]
    async fn the_daemon_sweeps_and_persists_expired_rules_with_the_engine_stopped() {
        let controller = test_controller();
        assert!(!controller.is_running());
        controller.upsert_rule(expired_rule("tmp-1"));
        let saves = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = saves.clone();
        let (stop_tx, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run_rule_expiry_persistence(
            controller.clone(),
            Duration::from_millis(10),
            stop_rx,
            move |_| {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        ));
        for _ in 0..200 {
            if saves.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(controller
            .profile
            .read()
            .rules
            .iter()
            .all(|r| r.id != "tmp-1"));
        // A later tick with nothing to remove never saves again.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 1);
        stop_tx.send(true).expect("stop");
        task.await.expect("task ends on shutdown");
    }

    #[test]
    fn only_the_daemon_controller_persists_after_a_rule_expiry() {
        // A plain engine (`routeward run --profile X`, user CLI, tests) never writes a profile.
        let controller = test_controller();
        controller.upsert_rule(expired_rule("tmp-2"));
        assert_eq!(
            controller.sweep_expired_rules(chrono::Utc::now()),
            vec!["tmp-2".to_string()]
        );
        assert!(controller.persist_after_rule_expiry().is_none());
    }

    #[test]
    fn replacing_a_profile_drops_the_rules_that_already_expired() {
        let controller = test_controller();
        let mut incoming = controller.profile.read().redacted_for_ipc();
        incoming.rules.push(expired_rule("tmp-3"));
        controller.replace_profile(incoming).expect("valid profile");
        assert!(controller
            .profile
            .read()
            .rules
            .iter()
            .all(|r| r.id != "tmp-3"));
    }

    fn proxy_with_auth(id: &str, auth: ProxyCredentials) -> ProxyNode {
        ProxyNode {
            id: id.to_string(),
            name: id.to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port: 1080,
            auth: Some(auth),
            udp_enabled: false,
            tls: false,
            tls_skip_verify: false,
            sni: None,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        }
    }

    fn stored_has_password(controller: &RouteWardController, id: &str) -> bool {
        let prof = controller.profile.read();
        prof.proxies
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.auth.as_ref())
            .expect("stored credentials")
            .has_password
    }

    #[test]
    fn forged_has_password_without_a_password_is_never_stored() {
        let controller = test_controller();
        let forged = || ProxyCredentials {
            username: "alice".to_string(),
            password: None,
            has_password: true,
        };

        // Insert with a claimed password that was never received.
        controller.upsert_proxy(proxy_with_auth("p-forged", forged()));
        assert!(!stored_has_password(&controller, "p-forged"));

        // Update of a proxy that has no stored password stays without one.
        controller.upsert_proxy(proxy_with_auth("p-forged", forged()));
        assert!(!stored_has_password(&controller, "p-forged"));

        // A real password is flagged, and survives an update that omits it.
        controller.upsert_proxy(proxy_with_auth(
            "p-real",
            ProxyCredentials::new("bob", "s3cret"),
        ));
        assert!(stored_has_password(&controller, "p-real"));
        controller.upsert_proxy(proxy_with_auth("p-real", forged()));
        assert!(stored_has_password(&controller, "p-real"));
        assert_eq!(
            controller
                .profile
                .read()
                .proxies
                .iter()
                .find(|p| p.id == "p-real")
                .and_then(|p| p.auth.as_ref())
                .map(|a| a.password_str().to_string()),
            Some("s3cret".to_string())
        );

        // The same rule applies when a whole profile is replaced.
        let mut replacement = controller.profile.read().clone();
        replacement
            .proxies
            .push(proxy_with_auth("p-replaced", forged()));
        controller.replace_profile(replacement).expect("replace");
        assert!(!stored_has_password(&controller, "p-replaced"));
        assert!(stored_has_password(&controller, "p-real"));
    }

    fn diagnostics_controller() -> (RouteWardController, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("routeward_ipc_diag_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = true;
        profile.rules = Vec::new();
        profile.default_action = crate::config::RuleAction::Direct;
        let controller =
            RouteWardController::new_with_log_dir(constants, profile, "en", dir.clone());
        (controller, dir)
    }

    async fn dispatch_json(
        controller: &RouteWardController,
        command: serde_json::Value,
    ) -> IpcResponse {
        let line = serde_json::json!({ "id": "req", "command": command }).to_string();
        let req = parse_ipc_request(&line).expect("valid request");
        dispatch_command(controller, req).await
    }

    #[test]
    fn diagnostics_commands_parse_from_the_documented_json() {
        let samples = [
            r#"{"id":"1","command":{"type":"list_blocked"}}"#,
            r#"{"id":"1","command":{"type":"flush_os_dns_cache"}}"#,
            r#"{"id":"1","command":{"type":"list_blocked","since":1,"limit":5}}"#,
            r#"{"id":"1","command":{"type":"query_logs","source":"memory","limit":10}}"#,
            r#"{"id":"1","command":{"type":"query_logs","source":{"daemonFile":{"date":"20261122"}},"minLevel":"WARN","components":["a"],"text":"x","pid":3,"connectionId":"abc","since":1,"until":2,"limit":10,"cursor":"5"}}"#,
            r#"{"id":"1","command":{"type":"analyze"}}"#,
            r#"{"id":"1","command":{"type":"collect_diagnostics","logDays":3,"includeConnections":true,"includeProfile":false,"maskDomains":true}}"#,
            r#"{"id":"1","command":{"type":"preview_rule_change","upserts":[],"removeIds":["a"],"request":{"processName":"a.exe","targetHost":"h","targetPort":1,"protocol":"tcp"}}}"#,
        ];
        for sample in samples {
            parse_ipc_request(sample).unwrap_or_else(|e| panic!("{sample}: {e:?}"));
        }
        // Strict like every other command: unknown fields are refused.
        let unknown = r#"{"id":"1","command":{"type":"list_blocked","extra":1}}"#;
        assert!(parse_ipc_request(unknown).is_err());
        let missing_limit = r#"{"id":"1","command":{"type":"query_logs","source":"memory"}}"#;
        assert!(parse_ipc_request(missing_limit).is_err());
    }

    #[tokio::test]
    async fn blocked_logs_analyze_collect_and_preview_round_trip_through_dispatch() {
        use crate::config::TransportProtocol;
        use crate::telemetry::{BlockReason, BlockedRecord, TrackedConnection};
        let (controller, dir) = diagnostics_controller();
        controller.telemetry.record_connection(
            TrackedConnection::blocked(
                BlockedRecord::new(
                    BlockReason::DefaultPolicyBlock,
                    TransportProtocol::Tcp,
                    "Default",
                )
                .process("slack.exe", "C:\\slack.exe", 9)
                .target("slack.com", 443),
            ),
            false,
        );
        controller
            .telemetry
            .push_log(LogLevel::Warn, "Round", "trip line");
        controller.telemetry.flush_file_logger();

        let blocked =
            dispatch_json(&controller, serde_json::json!({ "type": "list_blocked" })).await;
        assert!(blocked.ok);
        let blocked: crate::diagnostics::BlockedResponse =
            serde_json::from_value(blocked.result.expect("result")).expect("decode");
        assert_eq!(blocked.entries.len(), 1);
        assert_eq!(blocked.entries[0].process_name, "slack.exe");

        let memory = dispatch_json(
            &controller,
            serde_json::json!({ "type": "query_logs", "source": "memory", "components": ["Round"], "limit": 5 }),
        )
        .await;
        assert!(memory.ok);
        let memory: QueryLogsResponse =
            serde_json::from_value(memory.result.expect("result")).expect("decode");
        assert_eq!(memory.entries.len(), 1);
        assert_eq!(memory.available_dates.len(), 1);

        let file = dispatch_json(
            &controller,
            serde_json::json!({
                "type": "query_logs",
                "source": { "daemonFile": { "date": memory.available_dates[0] } },
                "text": "trip",
                "limit": 5
            }),
        )
        .await;
        assert!(file.ok);
        let file: QueryLogsResponse =
            serde_json::from_value(file.result.expect("result")).expect("decode");
        assert_eq!(file.entries[0].message, "trip line");

        // A date that is not eight digits is refused, whatever it tries to reach.
        let traversal = dispatch_json(
            &controller,
            serde_json::json!({
                "type": "query_logs",
                "source": { "daemonFile": { "date": "..\\..\\secret" } },
                "limit": 5
            }),
        )
        .await;
        assert!(!traversal.ok);
        assert!(traversal
            .error
            .unwrap_or_default()
            .contains("invalid_log_date"));

        let analysis = dispatch_json(&controller, serde_json::json!({ "type": "analyze" })).await;
        assert!(analysis.ok);
        let analysis: crate::diagnostics::AnalyzeResponse =
            serde_json::from_value(analysis.result.expect("result")).expect("decode");
        assert!(analysis
            .findings
            .iter()
            .any(|f| f.code == crate::diagnostics::analyzer::FindingCode::DefaultPolicyBlocking));

        let bundle = dispatch_json(
            &controller,
            serde_json::json!({
                "type": "collect_diagnostics",
                "logDays": 1,
                "includeConnections": true,
                "includeProfile": true,
                "maskDomains": false
            }),
        )
        .await;
        assert!(bundle.ok);
        let bundle = bundle.result.expect("result");
        let names: Vec<&str> = bundle["manifest"]["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .filter_map(|s| s["name"].as_str())
            .collect();
        assert_eq!(
            names,
            vec!["system", "profile", "connections", "blocked", "logs"]
        );

        let preview = dispatch_json(
            &controller,
            serde_json::json!({
                "type": "preview_rule_change",
                "upserts": [{
                    "id": "rule-unblock-app-slack", "name": "x", "enabled": true, "priority": 6,
                    "processPatterns": ["slack.exe"], "domainPatterns": [], "ipCidrs": [],
                    "portRanges": [], "protocol": "any", "action": { "type": "block" }
                }],
                "removeIds": [],
                "request": { "processName": "slack.exe", "targetHost": "slack.com", "targetPort": 443, "protocol": "tcp" }
            }),
        )
        .await;
        assert!(preview.ok);
        let preview = preview.result.expect("result");
        assert_eq!(
            preview["evaluation"]["matchedRuleId"],
            "rule-unblock-app-slack"
        );
        assert_eq!(preview["evaluation"]["action"]["type"], "block");
        assert!(preview.get("policyOverride").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transport_errors_carry_the_disconnected_key_and_keep_the_raw_detail() {
        let err = IpcCallError::Transport("os error 2".to_string());
        assert_eq!(
            err.error_key(),
            Some(crate::error::ERR_KEY_DAEMON_DISCONNECTED)
        );
        assert_eq!(err.message(), "os error 2");
        assert_eq!(IpcCallError::Protocol("x".to_string()).error_key(), None);
    }

    #[tokio::test]
    async fn pause_engine_is_bounded_reported_in_diagnostics_and_cancelled_by_a_toggle() {
        let controller = test_controller();
        let pause = |secs: u64| IpcRequest {
            id: "pause".to_string(),
            command: IpcCommand::PauseEngine {
                duration_secs: secs,
            },
        };

        for bad in [0, crate::system::protection_state::MAX_PAUSE_SECS + 1] {
            let resp = dispatch_command(&controller, pause(bad)).await;
            assert!(!resp.ok);
            assert_eq!(
                resp.error_key.as_deref(),
                Some(crate::error::ERR_KEY_DAEMON_INVALID_PAUSE)
            );
        }

        // Protection that is off cannot be paused; once the user chose "on" it can.
        let refused = dispatch_command(&controller, pause(600)).await;
        assert!(!refused.ok);
        assert_eq!(
            refused.error_key.as_deref(),
            Some(crate::error::ERR_KEY_DAEMON_PAUSE_NOT_ACTIVE)
        );
        controller.record_protection_choice(true);

        let resp = dispatch_command(&controller, pause(600)).await;
        assert!(resp.ok);
        let diag: crate::interceptor::SystemDiagnostics =
            serde_json::from_value(resp.result.expect("diagnostics")).expect("decode");
        let deadline = diag.paused_until_epoch_ms.expect("paused deadline");
        assert!(deadline > crate::system::protection_state::now_epoch_ms());
        assert!(!diag.running);

        let json = serde_json::to_value(&diag).expect("serialize");
        assert!(json.get("pausedUntilEpochMs").is_some_and(|v| v.is_u64()));

        // A stop (and equally a start) request cancels the pause.
        let stop = dispatch_command(
            &controller,
            IpcRequest {
                id: "stop".to_string(),
                command: IpcCommand::ToggleEngine { start: false },
            },
        )
        .await;
        assert!(stop.ok);
        assert!(controller.diagnostics().paused_until_epoch_ms.is_none());
        let json = serde_json::to_value(controller.diagnostics()).expect("serialize");
        assert!(json.get("pausedUntilEpochMs").is_some_and(|v| v.is_null()));
    }
}
