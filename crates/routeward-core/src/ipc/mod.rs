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

use crate::config::{InterceptionMode, IpcConstants};
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_DAEMON_IPC_ERROR};
use crate::interceptor::RouteWardController;
use crate::ipc::protocol::{
    parse_ipc_request, read_bounded_line, recv_next_stream_event, DaemonFullState, IpcCommand,
    IpcRequest, IpcResponse, ReadLineOutcome,
};
use crate::ipc::transport::{connect_ipc_stream, IpcServer, IpcStream, PeerIdentity};
use crate::telemetry::LogLevel;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

const COMPONENT_DAEMON_IPC: &str = "DaemonIpc";
const DEFAULT_OS_SCAN_LIMIT: usize = 48;

pub fn generate_ephemeral_token() -> String {
    Uuid::new_v4().to_string()
}

pub struct DaemonIpcService {
    controller: RouteWardController,
    server: IpcServer,
}

impl DaemonIpcService {
    pub fn bind(controller: RouteWardController) -> RouteWardResult<Self> {
        let server = IpcServer::bind(&controller.constants.ipc)?;
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

    pub async fn run_accept_loop(mut self) -> RouteWardResult<()> {
        let mut client_tasks = tokio::task::JoinSet::new();
        loop {
            while client_tasks.try_join_next().is_some() {}
            match self.server.accept().await {
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
                controller.start_engine();
                let mode = controller.profile.read().interception_mode;
                if mode != InterceptionMode::Relay {
                    if let Err(err) = controller.start_transparent_interceptor() {
                        controller.stop_engine();
                        return IpcResponse::error(Some(id), err.to_string());
                    }
                }
            } else {
                controller.stop_engine();
            }
            IpcResponse::success(id, &controller.diagnostics())
        }
        IpcCommand::SetInterceptionMode { mode } => {
            controller.set_interception_mode(mode);
            let _ = controller.save_profile_default();
            IpcResponse::success(id, &controller.diagnostics())
        }
        IpcCommand::SetTheme { theme, accent } => {
            controller.set_theme_config(theme, accent);
            let _ = controller.save_profile_default();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        IpcCommand::GetProfile => {
            let prof = controller.profile.read().redacted_for_ipc();
            IpcResponse::success(id, &prof)
        }
        IpcCommand::ReplaceProfile { profile } => {
            controller.replace_profile(profile);
            if let Err(err) = controller.save_profile_default() {
                return IpcResponse::error(Some(id), err.to_string());
            }
            let prof = controller.profile.read().redacted_for_ipc();
            IpcResponse::success(id, &prof)
        }
        IpcCommand::UpsertRule { rule } => {
            controller.upsert_rule(rule);
            let _ = controller.save_profile_default();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        IpcCommand::RemoveRule { rule_id } => {
            controller.remove_rule(&rule_id);
            let _ = controller.save_profile_default();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        IpcCommand::UpsertProxy { node } => {
            controller.upsert_proxy(node);
            let _ = controller.save_profile_default();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        IpcCommand::RemoveProxy { proxy_id } => {
            controller.remove_proxy(&proxy_id);
            let _ = controller.save_profile_default();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        IpcCommand::UpsertChain { chain } => {
            controller.upsert_chain(chain);
            let _ = controller.save_profile_default();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
        }
        IpcCommand::RemoveChain { chain_id } => {
            controller.remove_chain(&chain_id);
            let _ = controller.save_profile_default();
            IpcResponse::success(id, &serde_json::json!({ "ok": true }))
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
            let sockets = controller.scan_and_ingest_os_sockets(DEFAULT_OS_SCAN_LIMIT);
            IpcResponse::success(id, &sockets)
        }
        IpcCommand::TestProxy { proxy_id } => match controller.test_proxy(&proxy_id).await {
            Ok(report) => IpcResponse::success(id, &report),
            Err(err) => IpcResponse::error(Some(id), err.to_string()),
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
        IpcCommand::Subscribe => {
            IpcResponse::success(id, &serde_json::json!({ "subscribed": true }))
        }
    }
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

#[derive(Clone)]
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

    pub async fn call_typed<T: DeserializeOwned>(&self, command: IpcCommand) -> RouteWardResult<T> {
        let resp = self.call_raw(command).await?;
        if !resp.ok {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: resp
                    .error
                    .unwrap_or_else(|| "Daemon returned error".to_string()),
            });
        }
        let val = resp.result.ok_or_else(|| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: "Daemon returned empty result".to_string(),
        })?;
        serde_json::from_value(val).map_err(|err| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: format!("Failed to decode daemon response: {err}"),
        })
    }

    pub async fn exchange_on_stream(
        stream: IpcStream,
        command: IpcCommand,
        max_line_bytes: usize,
        idle_timeout_ms: u64,
    ) -> RouteWardResult<IpcResponse> {
        let req_id = Uuid::new_v4().to_string();
        let req = IpcRequest {
            id: req_id,
            command,
        };

        let (read_half, mut write_half) = tokio::io::split(stream);
        write_json_line(&mut write_half, &req)
            .await
            .map_err(|err| RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("Failed to send IPC request: {err}"),
            })?;

        let mut reader = BufReader::new(read_half);
        match read_bounded_line(&mut reader, max_line_bytes, idle_timeout_ms).await {
            ReadLineOutcome::Line(line) => {
                serde_json::from_str::<IpcResponse>(&line).map_err(|err| {
                    RouteWardError::DaemonError {
                        key: ERR_KEY_DAEMON_IPC_ERROR,
                        detail: format!("Invalid IPC response JSON: {err}"),
                    }
                })
            }
            other => Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("Unexpected IPC read outcome: {other:?}"),
            }),
        }
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
        controller.replace_profile(replaced_prof);
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
}
