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

use crate::commands::DesktopCommandBridge;
use crate::security::{extract_json_body, validate_loopback_http_request_with_method};
use crate::sse::stream_sse_events;
use crate::DesktopWindowCommand;
use routeward_core::config::{InterceptionMode, ProfileConfig, ProxyChain, ProxyNode, RoutingRule};
use routeward_core::rules::ConnectionRequest;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const HTTP_REQ_BUFFER_BYTES: usize = 65536;

#[derive(Debug, Deserialize)]
struct LaunchProcessRequest {
    executable: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SystemProxyRequest {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ToggleEngineRequest {
    start: bool,
}

#[derive(Debug, Deserialize)]
struct SetModeRequest {
    mode: InterceptionMode,
}

#[derive(Debug, Deserialize)]
struct SetThemeRequest {
    theme: String,
    accent: String,
}

#[derive(Debug, Deserialize)]
struct TerminateConnectionRequest {
    #[serde(rename = "connectionId")]
    connection_id: String,
}

#[derive(Debug, Deserialize)]
struct RemoveRuleRequest {
    #[serde(rename = "ruleId")]
    rule_id: String,
}

#[derive(Debug, Deserialize)]
struct ProxyIdRequest {
    #[serde(rename = "proxyId")]
    proxy_id: String,
}

#[derive(Debug, Deserialize)]
struct RemoveChainRequest {
    #[serde(rename = "chainId")]
    chain_id: String,
}

#[derive(Debug, Deserialize)]
struct AllocateFakeIpRequest {
    domain: String,
}

#[derive(Debug, Deserialize)]
struct SetLocaleRequest {
    locale: String,
}

fn require_post(method: &str, json_ct: &str) -> Option<(u16, String, Vec<u8>)> {
    if method != "POST" {
        return Some((
            405,
            json_ct.to_string(),
            b"{\"error\":\"method_not_allowed\"}".to_vec(),
        ));
    }
    None
}

pub async fn handle_api_route(
    method: &str,
    path: &str,
    body_str: &str,
    bridge: &DesktopCommandBridge,
    on_window_cmd: Option<&(dyn Fn(DesktopWindowCommand) + Send + Sync)>,
) -> Option<(u16, String, Vec<u8>)> {
    let json_ct = "application/json; charset=utf-8".to_string();

    if path.starts_with("/api/state") {
        let state = bridge.refresh_state().await;
        let json = serde_json::to_vec(&state).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/diagnostics") {
        let diag = bridge.get_diagnostics();
        let json = serde_json::to_vec(&diag).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/telemetry") {
        let snap = bridge.get_telemetry();
        let json = serde_json::to_vec(&snap).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/connections/terminate") {
        let parsed: Result<TerminateConnectionRequest, _> = serde_json::from_str(body_str);
        let terminated = match parsed {
            Ok(req) => bridge.terminate_connection(req.connection_id).await,
            Err(_) => false,
        };
        let json = serde_json::to_vec(&serde_json::json!({ "terminated": terminated }))
            .unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/connections/clear") {
        bridge.clear_closed_connections().await;
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/connections") {
        let conns = bridge.list_connections();
        let json = serde_json::to_vec(&conns).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/logs/clear") {
        bridge.clear_logs().await;
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/logs") {
        let logs = bridge.list_logs();
        let json = serde_json::to_vec(&logs).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/engine/toggle") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        let parsed: ToggleEngineRequest =
            serde_json::from_str(body_str).unwrap_or(ToggleEngineRequest { start: false });
        let diag = bridge.toggle_engine(parsed.start).await;
        let json = serde_json::to_vec(&diag).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/engine/mode") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<SetModeRequest>(body_str) {
            Ok(req) => {
                let diag = bridge.set_interception_mode(req.mode).await;
                let json = serde_json::to_vec(&diag).unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/daemon/start") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match bridge.start_privileged_daemon().await {
            Ok(state) => {
                let json = serde_json::to_vec(&serde_json::json!({
                    "started": true,
                    "connected": state.diagnostics.daemon_connected,
                    "state": state,
                }))
                .unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({
                    "errorKey": err.error_key(),
                    "error": err.detail(),
                }))
                .unwrap_or_default();
                return Some((err.status_code(), json_ct, json));
            }
        }
    }

    if path.starts_with("/api/locale") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<SetLocaleRequest>(body_str) {
            Ok(req) => {
                let active_locale = bridge.set_locale(&req.locale);
                let json = serde_json::to_vec(&serde_json::json!({
                    "ok": true,
                    "locale": active_locale,
                }))
                .unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/profile/replace") {
        match serde_json::from_str::<ProfileConfig>(body_str) {
            Ok(profile) => match bridge.replace_profile(profile).await {
                Ok(updated) => {
                    let json = serde_json::to_vec(&updated).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((500, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/theme") {
        if let Ok(req) = serde_json::from_str::<SetThemeRequest>(body_str) {
            bridge.set_theme(req.theme, req.accent).await;
        }
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/rules/upsert") {
        match serde_json::from_str::<RoutingRule>(body_str) {
            Ok(rule) => {
                let prof = bridge.upsert_rule(rule).await;
                let json = serde_json::to_vec(&prof).unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/rules/remove") {
        match serde_json::from_str::<RemoveRuleRequest>(body_str) {
            Ok(req) => {
                let prof = bridge.remove_rule(req.rule_id).await;
                let json = serde_json::to_vec(&prof).unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/rules/evaluate") {
        match serde_json::from_str::<ConnectionRequest>(body_str) {
            Ok(request) => match bridge.evaluate_rule(request).await {
                Ok(res) => {
                    let json = serde_json::to_vec(&res).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((503, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/proxies/upsert") {
        match serde_json::from_str::<ProxyNode>(body_str) {
            Ok(node) => {
                let prof = bridge.upsert_proxy(node).await;
                let json = serde_json::to_vec(&prof).unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/proxies/remove") {
        match serde_json::from_str::<ProxyIdRequest>(body_str) {
            Ok(req) => {
                let prof = bridge.remove_proxy(req.proxy_id).await;
                let json = serde_json::to_vec(&prof).unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/proxies/test-all") {
        let reports = bridge.test_all_proxies().await;
        let json = serde_json::to_vec(&reports).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/proxies/test") {
        match serde_json::from_str::<ProxyIdRequest>(body_str) {
            Ok(req) => match bridge.test_proxy(req.proxy_id).await {
                Ok(report) => {
                    let json = serde_json::to_vec(&report).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((503, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/chains/upsert") {
        match serde_json::from_str::<ProxyChain>(body_str) {
            Ok(chain) => {
                let prof = bridge.upsert_chain(chain).await;
                let json = serde_json::to_vec(&prof).unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/chains/remove") {
        match serde_json::from_str::<RemoveChainRequest>(body_str) {
            Ok(req) => {
                let prof = bridge.remove_chain(req.chain_id).await;
                let json = serde_json::to_vec(&prof).unwrap_or_default();
                return Some((200, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/dns/allocate") {
        let allocated = match serde_json::from_str::<AllocateFakeIpRequest>(body_str) {
            Ok(req) => bridge.allocate_fake_ip(req.domain).await,
            Err(_) => None,
        };
        let entries = bridge.list_fake_ip_entries();
        let json = serde_json::to_vec(&serde_json::json!({
            "allocated": allocated,
            "entries": entries,
        }))
        .unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/dns/flush") {
        bridge.flush_fake_ip_cache().await;
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/scan-os") {
        let sockets = bridge.scan_os_sockets().await;
        let json = serde_json::to_vec(&sockets).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/system-proxy") {
        match serde_json::from_str::<SystemProxyRequest>(body_str) {
            Ok(parsed) => match bridge.set_system_proxy(parsed.enabled) {
                Ok(status) => {
                    let json = serde_json::to_vec(&status).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((500, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/launch-process") {
        match serde_json::from_str::<LaunchProcessRequest>(body_str) {
            Ok(req) => match bridge.launch_process_with_proxy(&req.executable, &req.args) {
                Ok(res) => {
                    let json = serde_json::to_vec(&res).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((500, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/window/minimize") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        if let Some(cb) = on_window_cmd {
            cb(DesktopWindowCommand::Minimize);
        }
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/window/maximize") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        if let Some(cb) = on_window_cmd {
            cb(DesktopWindowCommand::ToggleMaximize);
        }
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/window/close") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        if let Some(cb) = on_window_cmd {
            cb(DesktopWindowCommand::Close);
        }
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/window/drag") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        if let Some(cb) = on_window_cmd {
            cb(DesktopWindowCommand::DragWindow);
        }
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    None
}

pub fn http_status_line(code: u16) -> &'static str {
    match code {
        200 => "HTTP/1.1 200 OK",
        400 => "HTTP/1.1 400 Bad Request",
        401 => "HTTP/1.1 401 Unauthorized",
        403 => "HTTP/1.1 403 Forbidden",
        404 => "HTTP/1.1 404 Not Found",
        405 => "HTTP/1.1 405 Method Not Allowed",
        409 => "HTTP/1.1 409 Conflict",
        501 => "HTTP/1.1 501 Not Implemented",
        503 => "HTTP/1.1 503 Service Unavailable",
        _ => "HTTP/1.1 500 Internal Server Error",
    }
}

pub async fn serve_loopback_http_connection<FStatic>(
    mut stream: TcpStream,
    bound_port: u16,
    expected_token: &str,
    bridge: &DesktopCommandBridge,
    on_window_cmd: Option<&(dyn Fn(DesktopWindowCommand) + Send + Sync)>,
    static_asset_handler: Option<FStatic>,
) where
    FStatic: FnOnce(&str) -> (&'static str, &'static [u8]),
{
    let _ = stream.set_nodelay(true);
    let mut buf = vec![0u8; HTTP_REQ_BUFFER_BYTES];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return;
    }
    let req = String::from_utf8_lossy(&buf[..n]);

    let (method, path) = match validate_loopback_http_request_with_method(
        &req,
        bound_port,
        expected_token,
    ) {
        Ok(valid) => valid,
        Err(rejection) => {
            let status = rejection.status_line();
            let body = b"{\"error\":\"forbidden\"}";
            let resp = format!(
                    "{status}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
                    body.len()
                );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.write_all(body).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return;
        }
    };

    if path.starts_with("/api/events") {
        stream_sse_events(stream, bound_port, bridge).await;
        return;
    }

    let body_str = extract_json_body(&req);
    let allowed_origin = format!("http://127.0.0.1:{bound_port}");

    if let Some((status_code, content_type, payload)) =
        handle_api_route(&method, &path, body_str, bridge, on_window_cmd).await
    {
        let status = http_status_line(status_code);
        let header = format!(
            "{status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: {allowed_origin}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&payload).await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        return;
    }

    if let Some(asset_fn) = static_asset_handler {
        let (content_type, body) = asset_fn(&path);
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
    }
}

pub async fn serve_loopback_api_connection(
    stream: TcpStream,
    bound_port: u16,
    expected_token: &str,
    bridge: &DesktopCommandBridge,
) {
    serve_loopback_http_connection(
        stream,
        bound_port,
        expected_token,
        bridge,
        None,
        None::<fn(&str) -> (&'static str, &'static [u8])>,
    )
    .await;
}
