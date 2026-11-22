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
pub mod notices;
mod routes;
mod security;
#[cfg(target_os = "windows")]
pub mod single_instance;
mod sse;
#[cfg(test)]
mod tests;
#[cfg(target_os = "windows")]
pub mod tray;

use commands::DesktopCommandBridge;
use routeward_core::config::{ProfileConfig, SystemConstants, ThemeForgeCatalog};

pub use routes::{
    handle_api_route, http_status_line, serve_loopback_api_connection,
    serve_loopback_http_connection, HTTP_REQ_BUFFER_BYTES, INDEX_CONTENT_SECURITY_POLICY,
};
pub use security::{
    constant_time_eq, extract_json_body, validate_loopback_http_request,
    validate_loopback_http_request_with_method, HttpSecurityRejection, HEADER_ROUTEWARD_TOKEN,
};
pub use sse::stream_sse_events;

/// Locale used when neither `ROUTEWARD_LOCALE` nor the operating system gives a French one.
const DEFAULT_DESKTOP_LOCALE: &str = "en";
const FRENCH_DESKTOP_LOCALE: &str = "fr";
const FRENCH_LOCALE_PREFIX: &str = "fr";
const ENV_ROUTEWARD_LOCALE: &str = "ROUTEWARD_LOCALE";
#[cfg(not(target_os = "windows"))]
const ENV_OS_LANG: &str = "LANG";
/// Length of the buffer `GetUserDefaultLocaleName` fills (`LOCALE_NAME_MAX_LENGTH`).
#[cfg(target_os = "windows")]
const OS_LOCALE_NAME_MAX_LEN: usize = 85;

/// Duration of the tray "Pause 15 min" action, handed to the daemon (it keeps the deadline).
pub const TRAY_PAUSE_SECS: u64 = 15 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayStatusSnapshot {
    pub daemon_connected: bool,
    pub running: bool,
    pub locale: String,
    pub active_profile_id: String,
    pub profiles: Vec<(String, String)>,
    /// End of a timed pause (Unix milliseconds) kept by the daemon, when one is pending.
    pub paused_until_epoch_ms: Option<u64>,
}

/// How a tray balloon is flagged (icon next to the text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayBalloonLevel {
    Info,
    Warning,
}

/// A notification shown from the tray icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayBalloon {
    pub title: String,
    pub body: String,
    pub level: TrayBalloonLevel,
}

/// Maps an operating-system locale name (`fr-FR`, `en-US`, `fr_CA.UTF-8`) to a desktop locale:
/// any French variant gives French, everything else English.
pub fn locale_from_os_name(name: &str) -> &'static str {
    if name
        .trim()
        .to_ascii_lowercase()
        .starts_with(FRENCH_LOCALE_PREFIX)
    {
        FRENCH_DESKTOP_LOCALE
    } else {
        DEFAULT_DESKTOP_LOCALE
    }
}

/// The locale of the operating system user, as a desktop locale.
pub fn os_default_locale() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
        let mut buffer = [0u16; OS_LOCALE_NAME_MAX_LEN];
        // SAFETY: the buffer is valid for `OS_LOCALE_NAME_MAX_LEN` UTF-16 units, which is the
        // size passed; the function writes a NUL-terminated name and returns its length.
        let written =
            unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), OS_LOCALE_NAME_MAX_LEN as i32) };
        if written <= 0 {
            return DEFAULT_DESKTOP_LOCALE;
        }
        let len = buffer.iter().position(|&unit| unit == 0).unwrap_or(0);
        locale_from_os_name(&String::from_utf16_lossy(&buffer[..len]))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var(ENV_OS_LANG)
            .map(|lang| locale_from_os_name(&lang))
            .unwrap_or(DEFAULT_DESKTOP_LOCALE)
    }
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
    StartDaemon,
    ToggleEngine,
    /// Pause protection for that many seconds; the daemon keeps the deadline.
    PauseEngineSeconds(u64),
    SwitchProfile(usize),
    ApplyTheme(WindowThemeAppearance),
    /// The user asked to exit: decide what happens to protection, then exit.
    Quit,
    /// Exit now (sent once the decision taken for `Quit` is done).
    QuitNow,
}

pub fn create_desktop_bridge() -> Result<DesktopCommandBridge, String> {
    let constants = SystemConstants::load_embedded().map_err(|e| e.to_string())?;
    let profile = ProfileConfig::load_embedded_default().map_err(|e| e.to_string())?;
    let locale = std::env::var(ENV_ROUTEWARD_LOCALE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| os_default_locale().to_string());
    let bridge = DesktopCommandBridge::new(constants, profile, &locale);
    bridge.spawn_background_sync();
    Ok(bridge)
}
