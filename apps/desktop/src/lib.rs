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
pub mod daemon_launcher;
mod routes;
mod security;
mod sse;
#[cfg(test)]
mod tests;
#[cfg(target_os = "windows")]
pub mod tray;

use commands::DesktopCommandBridge;
use routeward_core::config::{ProfileConfig, SystemConstants};

pub use routes::{
    handle_api_route, http_status_line, serve_loopback_api_connection,
    serve_loopback_http_connection, HTTP_REQ_BUFFER_BYTES,
};
pub use security::{
    constant_time_eq, extract_json_body, validate_loopback_http_request,
    validate_loopback_http_request_with_method, HttpSecurityRejection, HEADER_ROUTEWARD_TOKEN,
};
pub use sse::stream_sse_events;

const DEFAULT_DESKTOP_LOCALE: &str = "fr";
const ENV_ROUTEWARD_LOCALE: &str = "ROUTEWARD_LOCALE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayStatusSnapshot {
    pub daemon_connected: bool,
    pub running: bool,
    pub locale: String,
    pub active_profile_id: String,
    pub profiles: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopWindowCommand {
    Minimize,
    ToggleMaximize,
    Close,
    DragWindow,
    ShowWindow,
    ToggleEngine,
    SwitchProfile(usize),
    Quit,
}

pub fn create_desktop_bridge() -> Result<DesktopCommandBridge, String> {
    let constants = SystemConstants::load_embedded().map_err(|e| e.to_string())?;
    let profile = ProfileConfig::load_embedded_default().map_err(|e| e.to_string())?;
    let locale = std::env::var(ENV_ROUTEWARD_LOCALE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_DESKTOP_LOCALE.to_string());
    let bridge = DesktopCommandBridge::new(constants, profile, &locale);
    bridge.spawn_background_sync();
    Ok(bridge)
}
