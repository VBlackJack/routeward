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

pub mod commands;

use commands::DesktopCommandBridge;
use routeward_core::config::{
    InterceptionMode, ProfileConfig, ProxyChain, ProxyNode, RoutingRule, SystemConstants,
};
use routeward_core::ipc::protocol::IpcStreamEvent;
use routeward_core::rules::ConnectionRequest;
use serde::Deserialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_DESKTOP_LOCALE: &str = "fr";
pub const HEADER_ROUTEWARD_TOKEN: &str = "x-routeward-token";
pub const HTTP_REQ_BUFFER_BYTES: usize = 65536;
const SSE_KEEPALIVE_INTERVAL_SECS: u64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopWindowCommand {
    Minimize,
    ToggleMaximize,
    Close,
    DragWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpSecurityRejection {
    MalformedRequest,
    InvalidHost,
    InvalidOrigin,
    InvalidToken,
}

impl HttpSecurityRejection {
    pub fn status_line(&self) -> &'static str {
        match self {
            Self::MalformedRequest => "HTTP/1.1 400 Bad Request",
            Self::InvalidHost | Self::InvalidOrigin => "HTTP/1.1 403 Forbidden",
            Self::InvalidToken => "HTTP/1.1 401 Unauthorized",
        }
    }
}

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

pub fn create_desktop_bridge() -> Result<DesktopCommandBridge, String> {
    let constants = SystemConstants::load_embedded().map_err(|e| e.to_string())?;
    let profile = ProfileConfig::load_embedded_default().map_err(|e| e.to_string())?;
    let bridge = DesktopCommandBridge::new(constants, profile, DEFAULT_DESKTOP_LOCALE);
    bridge.spawn_background_sync();
    Ok(bridge)
}

/// Constant-time byte comparison to prevent timing side-channels when verifying the desktop loopback token.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut diff = a_bytes.len() ^ b_bytes.len();
    let max_len = a_bytes.len().max(b_bytes.len());
    for i in 0..max_len {
        let byte_a = a_bytes.get(i).copied().unwrap_or(0);
        let byte_b = b_bytes.get(i).copied().unwrap_or(0);
        diff |= (byte_a ^ byte_b) as usize;
    }
    diff == 0
}

/// Strictly validates the `Host`, `Origin`, and ephemeral token headers on incoming loopback HTTP requests.
/// Returns the request path if valid.
pub fn validate_loopback_http_request(
    raw_request: &str,
    expected_port: u16,
    expected_token: &str,
) -> Result<String, HttpSecurityRejection> {
    let header_section = raw_request
        .split("\r\n\r\n")
        .next()
        .or_else(|| raw_request.split("\n\n").next())
        .unwrap_or(raw_request);

    let mut lines = header_section.lines();
    let request_line = lines
        .next()
        .ok_or(HttpSecurityRejection::MalformedRequest)?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(HttpSecurityRejection::MalformedRequest)?
        .to_ascii_uppercase();
    let path = parts
        .next()
        .ok_or(HttpSecurityRejection::MalformedRequest)?
        .to_string();

    let expected_host = format!("127.0.0.1:{expected_port}");
    let expected_origin = format!("http://127.0.0.1:{expected_port}");

    let mut host_header: Option<String> = None;
    let mut origin_header: Option<String> = None;
    let mut token_header: Option<String> = None;

    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let key = name.trim().to_ascii_lowercase();
            let value = val.trim();
            match key.as_str() {
                "host" => host_header = Some(value.to_string()),
                "origin" => origin_header = Some(value.to_string()),
                HEADER_ROUTEWARD_TOKEN => token_header = Some(value.to_string()),
                "authorization" => {
                    if let Some(bearer) = value.strip_prefix("Bearer ") {
                        token_header = Some(bearer.trim().to_string());
                    }
                }
                _ => {}
            }
        }
    }

    if host_header.as_deref() != Some(expected_host.as_str()) {
        return Err(HttpSecurityRejection::InvalidHost);
    }

    if path.starts_with("/api/") {
        if method != "GET" {
            if origin_header.as_deref() != Some(expected_origin.as_str()) {
                return Err(HttpSecurityRejection::InvalidOrigin);
            }
        } else if let Some(ref origin) = origin_header {
            if origin != &expected_origin {
                return Err(HttpSecurityRejection::InvalidOrigin);
            }
        }

        match token_header {
            Some(ref provided) if constant_time_eq(provided, expected_token) => {}
            _ => return Err(HttpSecurityRejection::InvalidToken),
        }
    } else if let Some(ref origin) = origin_header {
        if origin != &expected_origin {
            return Err(HttpSecurityRejection::InvalidOrigin);
        }
    }

    Ok(path)
}

pub fn extract_json_body(raw_request: &str) -> &str {
    if let Some(idx) = raw_request.find("\r\n\r\n") {
        &raw_request[idx + 4..]
    } else if let Some(idx) = raw_request.find("\n\n") {
        &raw_request[idx + 2..]
    } else {
        ""
    }
}

pub async fn stream_sse_events(
    mut stream: TcpStream,
    bound_port: u16,
    bridge: &DesktopCommandBridge,
) {
    let allowed_origin = format!("http://127.0.0.1:{bound_port}");
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: {allowed_origin}\r\nConnection: keep-alive\r\n\r\n: connected\n\n"
    );
    if stream.write_all(header.as_bytes()).await.is_err() {
        return;
    }
    let _ = stream.flush().await;

    let mut rx = bridge.subscribe_events();
    let keepalive = Duration::from_secs(SSE_KEEPALIVE_INTERVAL_SECS);

    loop {
        match tokio::time::timeout(keepalive, rx.recv()).await {
            Ok(Ok(ev)) => {
                if let Ok(json) = serde_json::to_string(&ev) {
                    let frame = format!("data: {json}\n\n");
                    if stream.write_all(frame.as_bytes()).await.is_err()
                        || stream.flush().await.is_err()
                    {
                        break;
                    }
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped_events))) => {
                let resync = IpcStreamEvent::Resync { skipped_events };
                if let Ok(json) = serde_json::to_string(&resync) {
                    let frame = format!("data: {json}\n\n");
                    if stream.write_all(frame.as_bytes()).await.is_err()
                        || stream.flush().await.is_err()
                    {
                        break;
                    }
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => {
                if stream.write_all(b": keepalive\n\n").await.is_err()
                    || stream.flush().await.is_err()
                {
                    break;
                }
            }
        }
    }
}

pub async fn handle_api_route(
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
        let parsed: ToggleEngineRequest =
            serde_json::from_str(body_str).unwrap_or(ToggleEngineRequest { start: false });
        let diag = bridge.toggle_engine(parsed.start).await;
        let json = serde_json::to_vec(&diag).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/engine/mode") {
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
        let parsed: SystemProxyRequest =
            serde_json::from_str(body_str).unwrap_or(SystemProxyRequest { enabled: false });
        let result = bridge.set_system_proxy(parsed.enabled);
        let json = match result {
            Ok(status) => serde_json::to_vec(&status).unwrap_or_default(),
            Err(err) => {
                serde_json::to_vec(&serde_json::json!({ "error": err })).unwrap_or_default()
            }
        };
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/launch-process") {
        let parsed: Result<LaunchProcessRequest, _> = serde_json::from_str(body_str);
        let json = match parsed {
            Ok(req) => match bridge.launch_process_with_proxy(&req.executable, &req.args) {
                Ok(res) => serde_json::to_vec(&res).unwrap_or_default(),
                Err(err) => {
                    serde_json::to_vec(&serde_json::json!({ "error": err })).unwrap_or_default()
                }
            },
            Err(err) => serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                .unwrap_or_default(),
        };
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/window/minimize") {
        if let Some(cb) = on_window_cmd {
            cb(DesktopWindowCommand::Minimize);
        }
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/window/maximize") {
        if let Some(cb) = on_window_cmd {
            cb(DesktopWindowCommand::ToggleMaximize);
        }
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/window/close") {
        if let Some(cb) = on_window_cmd {
            cb(DesktopWindowCommand::Close);
        }
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/window/drag") {
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
        503 => "HTTP/1.1 503 Service Unavailable",
        _ => "HTTP/1.1 500 Internal Server Error",
    }
}

pub async fn serve_loopback_api_connection(
    mut stream: TcpStream,
    bound_port: u16,
    expected_token: &str,
    bridge: &DesktopCommandBridge,
) {
    let mut buf = vec![0u8; HTTP_REQ_BUFFER_BYTES];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return;
    }
    let req = String::from_utf8_lossy(&buf[..n]);

    let path = match validate_loopback_http_request(&req, bound_port, expected_token) {
        Ok(valid_path) => valid_path,
        Err(rejection) => {
            let status = rejection.status_line();
            let body = b"{\"error\":\"forbidden\"}";
            let resp = format!(
                "{status}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.write_all(body).await;
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
        handle_api_route(&path, body_str, bridge, None).await
    {
        let status = http_status_line(status_code);
        let header = format!(
            "{status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: {allowed_origin}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&payload).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeward_core::interceptor::RouteWardController;
    use routeward_core::ipc::protocol::DaemonFullState;
    use routeward_core::ipc::{generate_ephemeral_token, DaemonIpcService};
    use routeward_core::telemetry::LogLevel;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn validates_host_origin_and_token_on_api_routes() {
        let port = 54321;
        let token = "secret-ephemeral-token-123";

        let valid_api_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n{{}}"
        );
        let path = validate_loopback_http_request(&valid_api_req, port, token)
            .expect("Valid request should pass");
        assert_eq!(path, "/api/state");

        // Same-origin GET /api/state without Origin header (standard browser behavior) is accepted when Host and token match
        let valid_get_req = format!(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        let get_path = validate_loopback_http_request(&valid_get_req, port, token)
            .expect("Same-origin GET with valid token should pass");
        assert_eq!(get_path, "/api/state");

        // Wrong Host header (DNS rebinding attempt)
        let bad_host_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: attacker.example.com\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        assert_eq!(
            validate_loopback_http_request(&bad_host_req, port, token),
            Err(HttpSecurityRejection::InvalidHost)
        );

        // Wrong Origin header on GET /api/state (cross-origin browser request)
        let bad_origin_get_req = format!(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.local\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        assert_eq!(
            validate_loopback_http_request(&bad_origin_get_req, port, token),
            Err(HttpSecurityRejection::InvalidOrigin)
        );

        // Missing Origin header on POST /api/*
        let missing_origin_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        assert_eq!(
            validate_loopback_http_request(&missing_origin_req, port, token),
            Err(HttpSecurityRejection::InvalidOrigin)
        );

        // Wrong or missing token on /api/*
        let bad_token_req = format!(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: wrong-token\r\n\r\n"
        );
        assert_eq!(
            validate_loopback_http_request(&bad_token_req, port, token),
            Err(HttpSecurityRejection::InvalidToken)
        );
    }

    #[test]
    fn constant_time_token_comparison_is_exact() {
        let token = "550e8400-e29b-41d4-a716-446655440000";
        assert!(constant_time_eq(token, token));
        assert!(!constant_time_eq(
            token,
            "550e8400-e29b-41d4-a716-446655440001"
        ));
        assert!(!constant_time_eq(
            token,
            "450e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!constant_time_eq(token, "550e8400-e29b-41d4-a716"));
        assert!(!constant_time_eq(token, ""));
        assert!(constant_time_eq("", ""));
    }

    async fn send_raw_http(port: u16, raw_req: &str) -> String {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect to loopback server");
        stream
            .write_all(raw_req.as_bytes())
            .await
            .expect("write raw HTTP request");
        let mut resp = Vec::new();
        stream
            .read_to_end(&mut resp)
            .await
            .expect("read HTTP response");
        String::from_utf8_lossy(&resp).into_owned()
    }

    #[tokio::test]
    async fn bridge_loopback_end_to_end_token_state_sse_and_reconnection() {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        constants.ipc.reconnect_interval_ms = 120;
        let unique_id = generate_ephemeral_token();
        constants.ipc.windows_pipe_name = format!(r"\\.\pipe\routeward-e2e-{unique_id}");
        let temp_sock = std::env::temp_dir().join(format!("routeward-e2e-{unique_id}.sock"));
        constants.ipc.unix_socket_path = temp_sock.to_string_lossy().into_owned();

        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;

        // Start in-process test daemon #1
        let daemon_ctrl_1 = RouteWardController::new(constants.clone(), profile.clone(), "en");
        let service_1 =
            DaemonIpcService::bind_for_test(daemon_ctrl_1.clone()).expect("bind test daemon #1");
        let daemon_task_1 = tokio::spawn(async move {
            let _ = service_1.run_accept_loop().await;
        });

        // Start desktop bridge + loopback HTTP server
        let bridge = Arc::new(DesktopCommandBridge::new(
            constants.clone(),
            profile.clone(),
            "en",
        ));
        bridge.spawn_background_sync();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local_addr").port();
        let token = generate_ephemeral_token();
        let token_for_server = token.clone();
        let bridge_for_server = Arc::clone(&bridge);

        let server_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let b = Arc::clone(&bridge_for_server);
                let t = token_for_server.clone();
                tokio::spawn(async move {
                    serve_loopback_api_connection(stream, port, &t, &b).await;
                });
            }
        });

        // 1. HTTP requests without token or with wrong Host/Origin are rejected (401 / 403)
        let no_token_resp = send_raw_http(
            port,
            &format!("GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        )
        .await;
        assert!(
            no_token_resp.starts_with("HTTP/1.1 401 Unauthorized"),
            "Expected 401 without token, got: {no_token_resp}"
        );

        let bad_host_resp = send_raw_http(
            port,
            &format!(
                "GET /api/state HTTP/1.1\r\nHost: evil.example.com\r\nX-RouteWard-Token: {token}\r\n\r\n"
            ),
        )
        .await;
        assert!(
            bad_host_resp.starts_with("HTTP/1.1 403 Forbidden"),
            "Expected 403 with invalid Host, got: {bad_host_resp}"
        );

        let bad_origin_resp = send_raw_http(
            port,
            &format!(
                "POST /api/logs/clear HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example.com\r\nX-RouteWard-Token: {token}\r\n\r\n{{}}"
            ),
        )
        .await;
        assert!(
            bad_origin_resp.starts_with("HTTP/1.1 403 Forbidden"),
            "Expected 403 with invalid Origin, got: {bad_origin_resp}"
        );

        // 2. Request with valid token: GET /api/state returns daemonConnected == true
        let mut connected_state: Option<DaemonFullState> = None;
        for _ in 0..30 {
            let state_resp = send_raw_http(
                port,
                &format!(
                    "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
                ),
            )
            .await;
            assert!(state_resp.starts_with("HTTP/1.1 200 OK"));
            let body = extract_json_body(&state_resp);
            let parsed: DaemonFullState =
                serde_json::from_str(body).expect("deserialize DaemonFullState");
            if parsed.diagnostics.daemon_connected {
                connected_state = Some(parsed);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            connected_state.is_some(),
            "GET /api/state should report daemonConnected == true"
        );

        // Wait briefly for the bridge's background subscription stream to be established
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 3. Real-time event emitted on daemon is received over the bridge's SSE stream (/api/events)
        let mut sse_stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect SSE stream");
        let sse_req = format!(
            "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        sse_stream
            .write_all(sse_req.as_bytes())
            .await
            .expect("send SSE request");

        let mut sse_reader = BufReader::new(sse_stream);
        let mut status_line = String::new();
        sse_reader
            .read_line(&mut status_line)
            .await
            .expect("read SSE status line");
        assert!(status_line.starts_with("HTTP/1.1 200 OK"));

        // Emit a real-time log event on the daemon
        daemon_ctrl_1.telemetry.push_log(
            LogLevel::Info,
            "IntegrationTest",
            "live-sse-event-marker-3-3".to_string(),
        );

        let mut received_sse_marker = false;
        let sse_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < sse_deadline {
            let mut line = String::new();
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(500), sse_reader.read_line(&mut line))
                    .await
            {
                if n == 0 {
                    break;
                }
                if line.contains("live-sse-event-marker-3-3") {
                    received_sse_marker = true;
                    break;
                }
            }
        }
        assert!(
            received_sse_marker,
            "Expected daemon telemetry event to be streamed over GET /api/events"
        );

        // 4. Stop the daemon: bridge transitions to daemonConnected == false, then automatically reconnects when daemon restarts
        daemon_task_1.abort();
        let _ = daemon_task_1.await;
        drop(daemon_ctrl_1);

        let mut saw_disconnected = false;
        for _ in 0..30 {
            let state_resp = send_raw_http(
                port,
                &format!(
                    "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
                ),
            )
            .await;
            let body = extract_json_body(&state_resp);
            let parsed: DaemonFullState =
                serde_json::from_str(body).expect("deserialize state after daemon stop");
            if !parsed.diagnostics.daemon_connected {
                saw_disconnected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            saw_disconnected,
            "Bridge must report daemonConnected == false after daemon stops"
        );

        // Restart daemon on the same IPC endpoint
        let daemon_ctrl_2 = RouteWardController::new(constants.clone(), profile, "en");
        let mut service_2_opt = None;
        for _ in 0..20 {
            if let Ok(svc) = DaemonIpcService::bind_for_test(daemon_ctrl_2.clone()) {
                service_2_opt = Some(svc);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let service_2 = service_2_opt.expect("bind test daemon #2");
        let daemon_task_2 = tokio::spawn(async move {
            let _ = service_2.run_accept_loop().await;
        });

        // Verify automatic reconnection by the bridge's background task (without calling refresh_state first)
        let mut reconnected = false;
        for _ in 0..40 {
            if bridge.is_daemon_connected() && bridge.get_diagnostics().daemon_connected {
                reconnected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        assert!(
            reconnected,
            "Bridge must automatically reconnect when the daemon restarts"
        );

        daemon_task_2.abort();
        server_task.abort();
    }
}
