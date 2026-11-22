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

use crate::commands::{DesktopCommandBridge, SystemOpError};
use crate::security::{extract_json_body, validate_loopback_http_request_with_method};
use crate::sse::stream_sse_events;
use crate::{parse_hex_colorref, resolve_palette_window_appearance, DesktopWindowCommand};
use routeward_core::config::{InterceptionMode, ProfileConfig, ProxyChain, ProxyNode, RoutingRule};
use routeward_core::diagnostics::bundle::CollectOptions;
use routeward_core::diagnostics::logs::QueryLogsRequest;
use routeward_core::diagnostics::PreviewRuleChangeRequest;
use routeward_core::error::{
    ERR_KEY_CHAIN_EMPTY, ERR_KEY_CLEANUP_DAEMON_ACTIVE, ERR_KEY_CONFIG_JSON, ERR_KEY_CONFIG_SAVE,
    ERR_KEY_DAEMON_ALREADY_RUNNING, ERR_KEY_DAEMON_INSECURE_PROFILE, ERR_KEY_DAEMON_INVALID_PAUSE,
    ERR_KEY_INTERCEPTOR_NFT_FAILED, ERR_KEY_INTERCEPTOR_OPEN,
};
use routeward_core::ipc::IpcCallError;
use routeward_core::rules::ConnectionRequest;
use routeward_core::system::protection_state::MAX_PAUSE_SECS;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

pub const HTTP_REQ_BUFFER_BYTES: usize = 65536;
const HTTP_MAX_HEADER_BYTES: usize = 16384;
const HTTP_MAX_BODY_BYTES: usize = 1024 * 1024;
const HTTP_READ_TIMEOUT_MS: u64 = 2000;
/// Total time a client has to deliver the whole request (headers and body). A slow-drip client
/// that stays under the per-read timeout is still cut off when this elapses.
pub const HTTP_REQUEST_TOTAL_DEADLINE_MS: u64 = 5000;
/// HTTP status used when the total request deadline elapses.
const REQUEST_TIMEOUT_STATUS: u16 = 408;
/// HTTP status returned when a system operation (proxy, PAC, autostart, launch) fails.
const SYSTEM_ERROR_STATUS: u16 = 500;

/// Reads one request within [`HTTP_REQUEST_TOTAL_DEADLINE_MS`].
async fn read_bounded_http_request(stream: &mut TcpStream) -> Result<String, u16> {
    read_bounded_http_request_within(
        stream,
        std::time::Duration::from_millis(HTTP_REQUEST_TOTAL_DEADLINE_MS),
    )
    .await
}

/// Reads one request (headers and body) and gives up with `408` once `total` has elapsed.
async fn read_bounded_http_request_within(
    stream: &mut TcpStream,
    total: std::time::Duration,
) -> Result<String, u16> {
    tokio::time::timeout(total, read_http_request_parts(stream))
        .await
        .unwrap_or(Err(REQUEST_TIMEOUT_STATUS))
}

async fn read_http_request_parts(stream: &mut TcpStream) -> Result<String, u16> {
    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end;

    loop {
        let read_res = tokio::time::timeout(
            std::time::Duration::from_millis(HTTP_READ_TIMEOUT_MS),
            stream.read(&mut chunk),
        )
        .await;
        let n = match read_res {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => break,
        };
        if raw.len().saturating_add(n) > HTTP_MAX_HEADER_BYTES + HTTP_MAX_BODY_BYTES {
            return Err(413);
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos);
            let headers_text = String::from_utf8_lossy(&raw[..pos]);
            let content_length = headers_text
                .lines()
                .skip(1)
                .find_map(|line| {
                    let (name, val) = line.split_once(':')?;
                    if name.trim().eq_ignore_ascii_case("Content-Length") {
                        val.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if content_length > HTTP_MAX_BODY_BYTES {
                return Err(413);
            }
            let target_len = pos + 4 + content_length;
            while raw.len() < target_len {
                let body_read = tokio::time::timeout(
                    std::time::Duration::from_millis(HTTP_READ_TIMEOUT_MS),
                    stream.read(&mut chunk),
                )
                .await;
                match body_read {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(bn)) => {
                        raw.extend_from_slice(&chunk[..bn]);
                        if raw.len() > HTTP_MAX_HEADER_BYTES + HTTP_MAX_BODY_BYTES {
                            return Err(413);
                        }
                    }
                }
            }
            let _ = header_end;
            break;
        }
        if raw.len() > HTTP_MAX_HEADER_BYTES {
            return Err(413);
        }
    }

    if raw.is_empty() {
        return Err(400);
    }
    Ok(String::from_utf8_lossy(&raw).into_owned())
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
struct ImportFoxyProxyRequest {
    json: String,
    #[serde(default, rename = "processPatterns")]
    process_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SaveProfileRequest {
    #[serde(default, rename = "profileId")]
    profile_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProfileIdRequest {
    #[serde(rename = "profileId")]
    profile_id: String,
}

#[derive(Debug, Deserialize)]
struct ToggleEngineRequest {
    start: bool,
}

/// Body of `POST /api/engine/pause`. A negative, fractional or missing value fails to parse.
#[derive(Debug, Deserialize)]
struct PauseEngineRequest {
    seconds: u64,
}

#[derive(Debug, Deserialize)]
struct SetModeRequest {
    mode: InterceptionMode,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetThemeRequest {
    theme: String,
    accent: String,
    is_light: Option<bool>,
    surface_hex: Option<String>,
    text_primary_hex: Option<String>,
    border_hex: Option<String>,
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

/// Maps a daemon IPC failure to the HTTP status the UI should observe.
///
/// Transport loss is 503, protocol faults are 500, and a clean daemon rejection is classified by
/// its error key: conflicts 409, unusable stored configuration 422, server-side faults 500, and
/// everything else (validation failures) 400.
pub fn ipc_error_status(err: &IpcCallError) -> u16 {
    match err {
        IpcCallError::Transport(_) => 503,
        IpcCallError::Protocol(_) => 500,
        IpcCallError::Remote { error_key, .. } => match error_key.as_deref() {
            Some(ERR_KEY_DAEMON_ALREADY_RUNNING | ERR_KEY_CLEANUP_DAEMON_ACTIVE) => 409,
            Some(ERR_KEY_DAEMON_INSECURE_PROFILE | ERR_KEY_CONFIG_JSON | ERR_KEY_CHAIN_EMPTY) => {
                422
            }
            Some(
                ERR_KEY_CONFIG_SAVE | ERR_KEY_INTERCEPTOR_OPEN | ERR_KEY_INTERCEPTOR_NFT_FAILED,
            ) => 500,
            _ => 400,
        },
    }
}

/// Builds the `{error, errorKey}` JSON error response for a failed daemon call.
fn ipc_error_response(err: &IpcCallError, json_ct: String) -> (u16, String, Vec<u8>) {
    let json = serde_json::to_vec(&serde_json::json!({
        "error": err.message(),
        "errorKey": err.error_key(),
    }))
    .unwrap_or_default();
    (ipc_error_status(err), json_ct, json)
}

/// Builds the 500 `{error, errorKey}` response for a failed system operation, so the UI can
/// localize the failure by key in its own locale.
fn system_error_response(err: &SystemOpError, json_ct: String) -> (u16, String, Vec<u8>) {
    let json = serde_json::to_vec(&serde_json::json!({
        "error": err.message(),
        "errorKey": err.key(),
    }))
    .unwrap_or_default();
    (SYSTEM_ERROR_STATUS, json_ct, json)
}

/// Builds the 200 response carrying a serializable payload.
fn ok_json_response<T: serde::Serialize>(value: &T, json_ct: String) -> (u16, String, Vec<u8>) {
    (200, json_ct, serde_json::to_vec(value).unwrap_or_default())
}

/// Content type prefix of the embedded index page, the only response that carries a CSP.
const HTML_CONTENT_TYPE_PREFIX: &str = "text/html";

/// Policy applied to the embedded index page. The bundle is a single external script and
/// stylesheet served from the same loopback origin. The session token is injected by the
/// WebView initialization script (not an inline `<script>`), so `script-src 'self'` suffices.
/// `style-src` keeps `'unsafe-inline'` because the theme engine and React write inline styles.
pub const INDEX_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

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

/// Parses the optional `since` and `limit` of `GET /api/blocked`.
fn parse_blocked_query(path: &str) -> Result<(Option<i64>, Option<usize>), String> {
    let mut since = None;
    let mut limit = None;
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "since" => {
                since = Some(value.parse::<i64>().map_err(|e| format!("since: {e}"))?);
            }
            "limit" => {
                limit = Some(value.parse::<usize>().map_err(|e| format!("limit: {e}"))?);
            }
            _ => {}
        }
    }
    Ok((since, limit))
}

/// A POST route that parses a JSON body, forwards it to the daemon and relays the answer:
/// 405 for another method, 400 for a bad body, the mapped daemon error otherwise.
async fn post_json_route<Req, Res, Fut>(
    method: &str,
    body_str: &str,
    json_ct: String,
    call: impl FnOnce(Req) -> Fut,
) -> (u16, String, Vec<u8>)
where
    Req: serde::de::DeserializeOwned,
    Res: serde::Serialize,
    Fut: std::future::Future<Output = Result<Res, IpcCallError>>,
{
    if let Some(rejection) = require_post(method, &json_ct) {
        return rejection;
    }
    match serde_json::from_str::<Req>(body_str) {
        Ok(req) => match call(req).await {
            Ok(res) => ok_json_response(&res, json_ct),
            Err(err) => ipc_error_response(&err, json_ct),
        },
        Err(err) => {
            let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                .unwrap_or_default();
            (400, json_ct, json)
        }
    }
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

    if path == "/api/blocked" || path.starts_with("/api/blocked?") {
        let (since, limit) = match parse_blocked_query(path) {
            Ok(parsed) => parsed,
            Err(message) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": message }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        };
        return Some(match bridge.list_blocked(since, limit).await {
            Ok(res) => ok_json_response(&res, json_ct),
            Err(err) => ipc_error_response(&err, json_ct),
        });
    }

    if path.starts_with("/api/logs/query") {
        return Some(
            post_json_route(
                method,
                body_str,
                json_ct,
                |req: QueryLogsRequest| async move { bridge.query_logs(req).await },
            )
            .await,
        );
    }

    if path.starts_with("/api/diagnostics/analyze") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        return Some(match bridge.analyze_diagnostics().await {
            Ok(res) => ok_json_response(&res, json_ct),
            Err(err) => ipc_error_response(&err, json_ct),
        });
    }

    if path.starts_with("/api/diagnostics/collect") {
        return Some(
            post_json_route(
                method,
                body_str,
                json_ct,
                |req: CollectOptions| async move { bridge.collect_diagnostics(req).await },
            )
            .await,
        );
    }

    if path.starts_with("/api/rules/preview") {
        return Some(
            post_json_route(
                method,
                body_str,
                json_ct,
                |req: PreviewRuleChangeRequest| async move { bridge.preview_rule_change(req).await },
            )
            .await,
        );
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
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        let parsed: Result<TerminateConnectionRequest, _> = serde_json::from_str(body_str);
        return Some(match parsed {
            Ok(req) => match bridge.terminate_connection(req.connection_id).await {
                Ok(terminated) => {
                    ok_json_response(&serde_json::json!({ "terminated": terminated }), json_ct)
                }
                Err(err) => ipc_error_response(&err, json_ct),
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                (400, json_ct, json)
            }
        });
    }

    if path.starts_with("/api/connections/clear") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        bridge.clear_closed_connections().await;
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/connections") {
        let conns = bridge.list_connections();
        let json = serde_json::to_vec(&conns).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/logs/clear") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
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
        match serde_json::from_str::<ToggleEngineRequest>(body_str) {
            Ok(parsed) => match bridge.toggle_engine(parsed.start).await {
                Ok(diag) => {
                    let json = serde_json::to_vec(&diag).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let status = if err.is_transport() { 503 } else { 409 };
                    let json = serde_json::to_vec(&serde_json::json!({
                        "error": err.message(),
                        "errorKey": err.error_key(),
                    }))
                    .unwrap_or_default();
                    return Some((status, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/engine/pause") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<PauseEngineRequest>(body_str) {
            Ok(req) if (1..=MAX_PAUSE_SECS).contains(&req.seconds) => {
                return Some(match bridge.pause_engine(req.seconds).await {
                    Ok(diag) => ok_json_response(&diag, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Ok(req) => {
                let json = serde_json::to_vec(&serde_json::json!({
                    "error": format!(
                        "Pause duration {}s is outside 1..={MAX_PAUSE_SECS} seconds",
                        req.seconds
                    ),
                    "errorKey": ERR_KEY_DAEMON_INVALID_PAUSE,
                }))
                .unwrap_or_default();
                return Some((400, json_ct, json));
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/engine/mode") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<SetModeRequest>(body_str) {
            Ok(req) => {
                return Some(match bridge.set_interception_mode(req.mode).await {
                    Ok(diag) => ok_json_response(&diag, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
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
        match bridge.start_privileged_daemon_detailed().await {
            Ok(report) => {
                let state = report.state;
                let mut body = serde_json::json!({
                    "started": true,
                    "connected": state.diagnostics.daemon_connected,
                    "state": state,
                });
                // Present only when the background service could not be installed and a plain
                // daemon runs instead: a locale key the UI can translate.
                if let (Some(reason_key), Some(map)) =
                    (report.fallback_reason_key, body.as_object_mut())
                {
                    map.insert("fallbackReasonKey".to_string(), reason_key.into());
                }
                let json = serde_json::to_vec(&body).unwrap_or_default();
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
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<ProfileConfig>(body_str) {
            Ok(profile) => match bridge.replace_profile(profile).await {
                Ok(updated) => {
                    let json = serde_json::to_vec(&updated).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => return Some(ipc_error_response(&err, json_ct)),
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/theme") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<SetThemeRequest>(body_str) {
            Ok(req) => {
                let fallback = resolve_palette_window_appearance(&req.theme);
                let appearance = crate::WindowThemeAppearance {
                    is_light: req.is_light.unwrap_or(fallback.is_light),
                    caption_color: req
                        .surface_hex
                        .as_deref()
                        .and_then(parse_hex_colorref)
                        .or(fallback.caption_color),
                    text_color: req
                        .text_primary_hex
                        .as_deref()
                        .and_then(parse_hex_colorref)
                        .or(fallback.text_color),
                    border_color: req
                        .border_hex
                        .as_deref()
                        .and_then(parse_hex_colorref)
                        .or(fallback.border_color),
                };
                let outcome = bridge.set_theme(req.theme, req.accent).await;
                if let Some(cb) = on_window_cmd {
                    cb(DesktopWindowCommand::ApplyTheme(appearance));
                }
                return Some(match outcome {
                    Ok(()) => (200, json_ct, b"{\"ok\":true}".to_vec()),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/rules/upsert") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<RoutingRule>(body_str) {
            Ok(rule) => {
                return Some(match bridge.upsert_rule(rule).await {
                    Ok(prof) => ok_json_response(&prof, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/rules/remove") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<RemoveRuleRequest>(body_str) {
            Ok(req) => {
                return Some(match bridge.remove_rule(req.rule_id).await {
                    Ok(prof) => ok_json_response(&prof, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/rules/evaluate") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
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
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<ProxyNode>(body_str) {
            Ok(node) => {
                return Some(match bridge.upsert_proxy(node).await {
                    Ok(prof) => ok_json_response(&prof, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/proxies/set-primary") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<ProxyIdRequest>(body_str) {
            Ok(req) => {
                return Some(match bridge.set_primary_proxy(req.proxy_id).await {
                    Ok(prof) => ok_json_response(&prof, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/proxies/remove") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<ProxyIdRequest>(body_str) {
            Ok(req) => {
                return Some(match bridge.remove_proxy(req.proxy_id).await {
                    Ok(prof) => ok_json_response(&prof, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/proxies/test-all") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        let reports = bridge.test_all_proxies().await;
        let json = serde_json::to_vec(&reports).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/proxies/test") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
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
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<ProxyChain>(body_str) {
            Ok(chain) => {
                return Some(match bridge.upsert_chain(chain).await {
                    Ok(prof) => ok_json_response(&prof, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/chains/remove") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<RemoveChainRequest>(body_str) {
            Ok(req) => {
                return Some(match bridge.remove_chain(req.chain_id).await {
                    Ok(prof) => ok_json_response(&prof, json_ct),
                    Err(err) => ipc_error_response(&err, json_ct),
                });
            }
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/dns/allocate") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        return Some(
            match serde_json::from_str::<AllocateFakeIpRequest>(body_str) {
                Ok(req) => match bridge.allocate_fake_ip(req.domain).await {
                    Ok(allocated) => {
                        let entries = bridge.list_fake_ip_entries();
                        ok_json_response(
                            &serde_json::json!({
                                "allocated": allocated,
                                "entries": entries,
                            }),
                            json_ct,
                        )
                    }
                    Err(err) => ipc_error_response(&err, json_ct),
                },
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                        .unwrap_or_default();
                    (400, json_ct, json)
                }
            },
        );
    }

    if path.starts_with("/api/dns/flush") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        bridge.flush_fake_ip_cache().await;
        return Some((200, json_ct, b"{\"ok\":true}".to_vec()));
    }

    if path.starts_with("/api/scan-os") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        let sockets = bridge.scan_os_sockets().await;
        let json = serde_json::to_vec(&sockets).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/system/pac") {
        if method == "POST" {
            match serde_json::from_str::<SystemProxyRequest>(body_str) {
                Ok(parsed) => match bridge.set_system_pac(parsed.enabled).await {
                    Ok((enabled, pac_url)) => {
                        let json = serde_json::to_vec(&serde_json::json!({
                            "enabled": enabled,
                            "pacUrl": pac_url,
                        }))
                        .unwrap_or_default();
                        return Some((200, json_ct, json));
                    }
                    Err(err) => {
                        return Some(system_error_response(&err, json_ct));
                    }
                },
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                        .unwrap_or_default();
                    return Some((400, json_ct, json));
                }
            }
        }
        let (enabled, pac_url) = bridge.get_system_pac_status().await;
        let json = serde_json::to_vec(&serde_json::json!({
            "enabled": enabled,
            "pacUrl": pac_url,
        }))
        .unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/system/autostart") {
        if method == "POST" {
            match serde_json::from_str::<SystemProxyRequest>(body_str) {
                Ok(parsed) => match bridge.set_autostart(parsed.enabled).await {
                    Ok(enabled) => {
                        let json = serde_json::to_vec(&serde_json::json!({ "enabled": enabled }))
                            .unwrap_or_default();
                        return Some((200, json_ct, json));
                    }
                    Err(err) => {
                        return Some(system_error_response(&err, json_ct));
                    }
                },
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                        .unwrap_or_default();
                    return Some((400, json_ct, json));
                }
            }
        }
        let enabled = bridge.get_autostart_status().await;
        let json =
            serde_json::to_vec(&serde_json::json!({ "enabled": enabled })).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/import/foxyproxy") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<ImportFoxyProxyRequest>(body_str) {
            Ok(parsed) => match bridge
                .import_foxyproxy_json(parsed.json, parsed.process_patterns)
                .await
            {
                Ok(report) => {
                    let json = serde_json::to_vec(&report).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((400, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/profiles/save") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<SaveProfileRequest>(body_str) {
            Ok(parsed) => match bridge
                .save_named_profile(parsed.profile_id, parsed.name)
                .await
            {
                Ok(list) => {
                    let json = serde_json::to_vec(&list).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((400, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/profiles/switch") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<ProfileIdRequest>(body_str) {
            Ok(parsed) => match bridge.switch_profile(parsed.profile_id).await {
                Ok(prof) => {
                    let json = serde_json::to_vec(&prof).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((400, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/profiles/delete") {
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<ProfileIdRequest>(body_str) {
            Ok(parsed) => match bridge.delete_profile(parsed.profile_id).await {
                Ok(list) => {
                    let json = serde_json::to_vec(&list).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    let json = serde_json::to_vec(&serde_json::json!({ "error": err }))
                        .unwrap_or_default();
                    return Some((400, json_ct, json));
                }
            },
            Err(err) => {
                let json = serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                    .unwrap_or_default();
                return Some((400, json_ct, json));
            }
        }
    }

    if path.starts_with("/api/profiles") {
        let list = bridge.list_profiles().await;
        let json = serde_json::to_vec(&list).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/system/apps") {
        let apps = bridge.list_system_applications().await;
        let json = serde_json::to_vec(&apps).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/system/detect-proxies") {
        let detected = bridge.detect_existing_proxies().await;
        let json = serde_json::to_vec(&detected).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/system/network-info") {
        let info = bridge.get_current_network_info().await;
        let json = serde_json::to_vec(&info).unwrap_or_default();
        return Some((200, json_ct, json));
    }

    if path.starts_with("/api/system/direct-ip") {
        let direct_ip = bridge.get_direct_ip().await;
        return Some(ok_json_response(
            &serde_json::json!({ "directIp": direct_ip }),
            json_ct,
        ));
    }

    if path.starts_with("/api/system-proxy") {
        if method != "POST" {
            let enabled = bridge.get_system_proxy_status().await;
            return Some(ok_json_response(
                &serde_json::json!({ "enabled": enabled }),
                json_ct,
            ));
        }
        match serde_json::from_str::<SystemProxyRequest>(body_str) {
            Ok(parsed) => match bridge.set_system_proxy(parsed.enabled).await {
                Ok(status) => {
                    let json = serde_json::to_vec(&status).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    return Some(system_error_response(&err, json_ct));
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
        if let Some(rejection) = require_post(method, &json_ct) {
            return Some(rejection);
        }
        match serde_json::from_str::<LaunchProcessRequest>(body_str) {
            Ok(req) => match bridge
                .launch_process_with_proxy(&req.executable, &req.args)
                .await
            {
                Ok(res) => {
                    let json = serde_json::to_vec(&res).unwrap_or_default();
                    return Some((200, json_ct, json));
                }
                Err(err) => {
                    return Some(system_error_response(&err, json_ct));
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
        413 => "HTTP/1.1 413 Payload Too Large",
        422 => "HTTP/1.1 422 Unprocessable Entity",
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
    admission: Option<&Semaphore>,
) where
    FStatic: FnOnce(&str) -> (&'static str, &'static [u8]),
{
    let _ = stream.set_nodelay(true);
    let req = match read_bounded_http_request(&mut stream).await {
        Ok(r) => r,
        Err(413) => {
            let body = b"{\"error\":\"payload_too_large\"}";
            let resp = format!(
                "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.write_all(body).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return;
        }
        Err(_) => return,
    };

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

    // The serving permit is taken only once the request is validated, so connections that never
    // finish or never authenticate cannot use up the slots reserved for real requests.
    let _admitted = match admission {
        Some(slots) => match slots.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                let body = b"{\"error\":\"busy\"}";
                let resp = format!(
                    "{}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
                    http_status_line(503),
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
                return;
            }
        },
        None => None,
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
        let csp_header = if content_type.starts_with(HTML_CONTENT_TYPE_PREFIX) {
            format!("Content-Security-Policy: {INDEX_CONTENT_SECURITY_POLICY}\r\n")
        } else {
            String::new()
        };
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nX-Content-Type-Options: nosniff\r\n{csp_header}Connection: close\r\n\r\n",
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
        None,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeward_core::config::{ProfileConfig, SystemConstants};
    use routeward_core::error::ERR_KEY_SYSTEM_PATH_EMPTY;

    #[tokio::test]
    async fn system_failures_are_answered_with_their_error_key() {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;
        let bridge = DesktopCommandBridge::new(constants, profile, "fr");

        let err = bridge
            .launch_process_with_proxy("   ", &[])
            .await
            .expect_err("an empty executable path must be refused");
        let (status, content_type, body) =
            system_error_response(&err, "application/json".to_string());

        assert_eq!(status, SYSTEM_ERROR_STATUS);
        assert_eq!(content_type, "application/json");
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
        assert_eq!(payload["errorKey"], ERR_KEY_SYSTEM_PATH_EMPTY);
        assert_eq!(
            payload["error"],
            bridge.translate(ERR_KEY_SYSTEM_PATH_EMPTY)
        );
    }

    #[tokio::test]
    async fn a_slow_drip_request_is_cut_off_by_the_total_deadline() {
        const TOTAL_MS: u64 = 400;
        const DRIP_INTERVAL_MS: u64 = 100;
        const DRIP_COUNT: usize = 40;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let started = std::time::Instant::now();
            let result = read_bounded_http_request_within(
                &mut stream,
                std::time::Duration::from_millis(TOTAL_MS),
            )
            .await;
            (result, started.elapsed())
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        for _ in 0..DRIP_COUNT {
            // Each byte arrives well inside the per-read timeout, but never finishes the request.
            if client.write_all(b"G").await.is_err() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(DRIP_INTERVAL_MS)).await;
        }
        let (result, elapsed) = server.await.unwrap();
        assert_eq!(result, Err(REQUEST_TIMEOUT_STATUS));
        assert!(
            elapsed < std::time::Duration::from_millis(TOTAL_MS * 3),
            "the read must stop near the deadline, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_complete_request_inside_the_deadline_is_read_whole() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_bounded_http_request(&mut stream).await
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
            .await
            .unwrap();
        let text = server.await.unwrap().unwrap();
        assert!(text.ends_with("\r\n\r\n{}"));
    }
}
