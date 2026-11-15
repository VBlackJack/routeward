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
use routeward_core::config::{ProfileConfig, SystemConstants, ThemeForgeCatalog};

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
pub struct WindowThemeAppearance {
    pub is_light: bool,
    pub caption_color: Option<u32>,
    pub text_color: Option<u32>,
    pub border_color: Option<u32>,
}

/// Parses `#RRGGBB` or `#AARRGGBB` CSS hex into Win32 `COLORREF` (`0x00BBGGRR`).
pub fn parse_hex_colorref(raw: &str) -> Option<u32> {
    let clean = raw.trim().trim_start_matches('#');
    let rgb = match clean.len() {
        6 => clean,
        8 => &clean[2..],
        _ => return None,
    };
    let r = u32::from_str_radix(&rgb[0..2], 16).ok()?;
    let g = u32::from_str_radix(&rgb[2..4], 16).ok()?;
    let b = u32::from_str_radix(&rgb[4..6], 16).ok()?;
    Some((b << 16) | (g << 8) | r)
}

/// Resolves native window chrome colors from the embedded ThemeForge catalog.
pub fn resolve_palette_window_appearance(theme_name: &str) -> WindowThemeAppearance {
    let Ok(catalog) = ThemeForgeCatalog::load_embedded() else {
        return WindowThemeAppearance {
            is_light: false,
            caption_color: None,
            text_color: None,
            border_color: None,
        };
    };

    let selected = catalog
        .palettes
        .iter()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(theme_name))
        .or_else(|| {
            catalog
                .palettes
                .iter()
                .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(&catalog.default_theme))
        })
        .or_else(|| catalog.palettes.first());

    let Some(pal) = selected else {
        return WindowThemeAppearance {
            is_light: false,
            caption_color: None,
            text_color: None,
            border_color: None,
        };
    };

    let is_light = pal
        .get("isLight")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let colors = pal.get("colors");
    let caption_color = colors
        .and_then(|c| c.get("Surface").and_then(|v| v.as_str()))
        .and_then(parse_hex_colorref);
    let text_color = colors
        .and_then(|c| c.get("TextPrimary").and_then(|v| v.as_str()))
        .and_then(parse_hex_colorref);
    let border_color = colors
        .and_then(|c| c.get("Border").and_then(|v| v.as_str()))
        .and_then(parse_hex_colorref);

    WindowThemeAppearance {
        is_light,
        caption_color,
        text_color,
        border_color,
    }
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
    ApplyTheme(WindowThemeAppearance),
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
