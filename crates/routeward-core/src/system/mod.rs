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

pub mod purge;
pub mod user_state;
pub mod windows_service;

#[cfg(windows)]
use crate::error::ERR_KEY_SYSTEM_REGISTRY_WRITE;
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_SYSTEM_LAUNCH_FAILED, ERR_KEY_SYSTEM_PAC_URL_INVALID,
    ERR_KEY_SYSTEM_PATH_EMPTY,
};
use serde::{Deserialize, Serialize};
use std::process::Command;
#[cfg(windows)]
use user_state::{FileBackupStore, Win32RegistryStore};
use user_state::{RegValue, UserCleanupReport, PROXY_SERVER_PREFIX};

/// Serializes every read-modify-write of the saved previous settings: the desktop bridge runs the
/// proxy, PAC and exit handlers on separate blocking threads.
#[cfg(windows)]
static USER_STATE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(windows)]
const WINDOWS_SYSTEM_DIR_FALLBACK: &str = r"C:\Windows\System32";
/// Capacity (UTF-16 units) of the buffer handed to `GetSystemDirectoryW`; far above `MAX_PATH`.
#[cfg(windows)]
const WINDOWS_SYSTEM_DIR_BUF_LEN: usize = 520;

const ENV_ALL_PROXY: &str = "ALL_PROXY";
const ENV_HTTP_PROXY: &str = "HTTP_PROXY";
const ENV_HTTPS_PROXY: &str = "HTTPS_PROXY";
const ENV_NO_PROXY: &str = "NO_PROXY";
const DEFAULT_NO_PROXY_VALUE: &str = "localhost,127.0.0.1,::1";

#[cfg(windows)]
const WIN_RUN_REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const AUTOSTART_VALUE_NAME: &str = user_state::VALUE_AUTOSTART;
/// Token `reg query` prints for a DWORD value; it is not localized.
const REG_DWORD_TYPE_TOKEN: &str = "REG_DWORD";

/// Extracts the numeric data of a `reg query` DWORD value line, locale-independently.
///
/// Only the `REG_DWORD` type token and the `0x` hexadecimal data are inspected; the value name
/// and any surrounding text are ignored. Returns `None` when no DWORD line is present.
fn parse_reg_dword_value(stdout: &str) -> Option<u32> {
    stdout.lines().find_map(|line| {
        let idx = line.find(REG_DWORD_TYPE_TOKEN)?;
        let data = line[idx + REG_DWORD_TYPE_TOKEN.len()..].trim();
        let hex = data
            .strip_prefix("0x")
            .or_else(|| data.strip_prefix("0X"))?;
        u32::from_str_radix(hex.split_whitespace().next()?, 16).ok()
    })
}

/// Resolves `<System32>\<exe_name>` through `GetSystemDirectoryW`.
///
/// The elevated daemon and the LocalSystem service must never start `reg`, `netsh`, `ipconfig`
/// and similar tools by bare name: the Win32 search order looks in the application directory
/// first, so a binary planted next to `routeward.exe` would run with SYSTEM rights. The
/// directory is also never taken from an environment variable (`SystemRoot`, `windir`), which
/// a lower-privileged parent could have altered. Only if the API itself fails does this fall
/// back to the conventional `C:\Windows\System32`.
#[cfg(windows)]
pub fn windows_system_tool_path(exe_name: &str) -> std::path::PathBuf {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buf = [0u16; WINDOWS_SYSTEM_DIR_BUF_LEN];
    let written = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let dir = if written == 0 || written >= buf.len() {
        std::path::PathBuf::from(WINDOWS_SYSTEM_DIR_FALLBACK)
    } else {
        std::path::PathBuf::from(String::from_utf16_lossy(&buf[..written]))
    };
    dir.join(exe_name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchedProcessReport {
    pub pid: u32,
    pub command: String,
    pub proxy_endpoint: String,
}

/// Path under which the local PAC server publishes the script.
const PAC_URL_PATH: &str = "/proxy.pac";

/// URL of the local PAC script served by RouteWard on `host:port`.
pub fn local_pac_url(host: &str, port: u16) -> String {
    format!("http://{host}:{port}{PAC_URL_PATH}")
}

/// True when the proxy switch is on and the server is the one RouteWard writes for
/// `socks_endpoint`.
pub fn proxy_is_routeward(
    enable: Option<&RegValue>,
    server: Option<&RegValue>,
    socks_endpoint: &str,
) -> bool {
    let written = format!("{PROXY_SERVER_PREFIX}{socks_endpoint}");
    enable == Some(&RegValue::Dword(1))
        && server
            .and_then(RegValue::as_text)
            .is_some_and(|text| text.trim().eq_ignore_ascii_case(&written))
}

/// Quotes one argument for display when it is empty or contains whitespace or a double quote,
/// so that a logged command line is unambiguous. Embedded quotes are escaped with a backslash.
pub fn quote_display_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty() || arg.chars().any(|c| c.is_whitespace() || c == '"');
    if !needs_quotes {
        return arg.to_string();
    }
    format!("\"{}\"", arg.replace('"', "\\\""))
}

/// Joins an executable and its arguments into a display string, quoting each part that needs it.
pub fn format_display_command(executable: &str, args: &[String]) -> String {
    std::iter::once(executable)
        .chain(args.iter().map(String::as_str))
        .map(quote_display_arg)
        .collect::<Vec<_>>()
        .join(" ")
}

pub struct SystemProxyManager;

impl SystemProxyManager {
    #[cfg(windows)]
    pub(crate) fn run_reg_add(args: &[&str]) -> RouteWardResult<()> {
        let output = Command::new(windows_system_tool_path("reg.exe"))
            .args(args)
            .output()
            .map_err(|err| RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_REGISTRY_WRITE,
                detail: format!("cannot run reg add: {err}"),
            })?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_REGISTRY_WRITE,
                detail: if detail.is_empty() {
                    format!("reg add exited with status {}", output.status)
                } else {
                    format!("reg add failed: {detail}")
                },
            });
        }
        Ok(())
    }

    /// Deletes a registry value, treating "value not found" as success.
    ///
    /// `reg delete` reports every failure with exit code 1 and a localized message, so the
    /// "not found" case is told apart locale-independently: after a failed delete, a `reg query`
    /// of the same value must also fail for the value to count as already absent.
    #[cfg(windows)]
    pub(crate) fn run_reg_delete_value(key: &str, value_name: &str) {
        let reg = windows_system_tool_path("reg.exe");
        let deleted = Command::new(&reg)
            .args(["delete", key, "/v", value_name, "/f"])
            .output();
        match deleted {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let still_present = Command::new(&reg)
                    .args(["query", key, "/v", value_name])
                    .output()
                    .map(|q| q.status.success())
                    .unwrap_or(true);
                if still_present {
                    tracing::warn!(
                        key,
                        value_name,
                        status = %out.status,
                        stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                        "reg delete failed and the value is still present"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(key, value_name, error = %err, "failed to run reg delete");
            }
        }
    }

    /// Runs `task` with the per-user registry and the saved-settings file, serialized.
    #[cfg(windows)]
    fn with_user_state<T>(
        task: impl FnOnce(&Win32RegistryStore, &FileBackupStore) -> RouteWardResult<T>,
    ) -> RouteWardResult<T> {
        let backups = FileBackupStore::for_current_user()?;
        let _guard = USER_STATE_LOCK.lock();
        task(&Win32RegistryStore::current_user(), &backups)
    }

    /// Enables or disables RouteWard's system proxy for the current user.
    ///
    /// Enabling first saves the previous proxy settings; disabling restores them, but only while
    /// the proxy server is still RouteWard's. Returns the state after the call: after a disable
    /// that left a foreign proxy alone, that is `true`; otherwise it is `false`.
    pub fn set_system_proxy(enable: bool, socks_endpoint: &str) -> RouteWardResult<bool> {
        #[cfg(windows)]
        {
            Self::with_user_state(|settings, backups| {
                if enable {
                    user_state::enable_proxy(settings, backups, socks_endpoint)
                } else {
                    user_state::disable_proxy(settings, backups, socks_endpoint).map(|_| ())
                }
            })?;
            if enable {
                Ok(true)
            } else {
                // After a disable, "still on" means RouteWard's own proxy could not be removed. A
                // foreign proxy the user (or a policy) set is none of RouteWard's business and
                // must not make the call report failure.
                Ok(Self::is_routeward_proxy_active(socks_endpoint))
            }
        }
        #[cfg(not(windows))]
        {
            let _ = socks_endpoint;
            Ok(enable)
        }
    }

    /// Restores the proxy and PAC settings RouteWard changed, if they are still RouteWard's.
    /// Called when the desktop app exits. Idempotent; a no-op outside Windows.
    pub fn restore_owned_settings(
        socks_endpoint: &str,
        pac_url: &str,
    ) -> RouteWardResult<UserCleanupReport> {
        #[cfg(windows)]
        {
            Self::with_user_state(|settings, backups| {
                user_state::restore_owned_proxy_settings(settings, backups, socks_endpoint, pac_url)
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (socks_endpoint, pac_url);
            Ok(UserCleanupReport::default())
        }
    }

    /// Everything `routeward cleanup --user` does: restores the proxy and PAC settings that are
    /// still RouteWard's and removes the autostart entry if it starts a RouteWard executable.
    /// Idempotent; a no-op outside Windows.
    pub fn cleanup_current_user(
        socks_endpoint: &str,
        pac_url: &str,
    ) -> RouteWardResult<UserCleanupReport> {
        #[cfg(windows)]
        {
            Self::with_user_state(|settings, backups| {
                user_state::cleanup_user_settings(settings, backups, socks_endpoint, pac_url)
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (socks_endpoint, pac_url);
            Ok(UserCleanupReport::default())
        }
    }

    /// Everything `routeward cleanup --all-users` does: for every user hive currently loaded
    /// under `HKEY_USERS`, restores the proxy and PAC settings that are still RouteWard's and
    /// removes the autostart entry. Needs an elevated or SYSTEM caller. Users who are not logged
    /// on have no loaded hive and keep their values. A no-op outside Windows.
    pub fn cleanup_all_users(
        socks_endpoint: &str,
        pac_url: &str,
    ) -> RouteWardResult<user_state::AllUsersCleanupReport> {
        #[cfg(windows)]
        {
            user_state::cleanup_all_loaded_users(socks_endpoint, pac_url)
        }
        #[cfg(not(windows))]
        {
            let _ = (socks_endpoint, pac_url);
            Ok(user_state::AllUsersCleanupReport::default())
        }
    }

    /// True when the system proxy is switched on and points to RouteWard's relay.
    pub fn is_routeward_proxy_active(socks_endpoint: &str) -> bool {
        #[cfg(windows)]
        {
            use user_state::{RegLocation, UserSettingsStore};
            let read = |name| {
                Win32RegistryStore::current_user()
                    .read(RegLocation::InternetSettings, name)
                    .ok()
                    .flatten()
            };
            proxy_is_routeward(
                read(user_state::VALUE_PROXY_ENABLE).as_ref(),
                read(user_state::VALUE_PROXY_SERVER).as_ref(),
                socks_endpoint,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = socks_endpoint;
            false
        }
    }

    pub fn is_valid_local_pac_url(pac_url: &str) -> bool {
        let trimmed = pac_url.trim();
        let Some(rest) = trimmed.strip_prefix("http://") else {
            return false;
        };
        if trimmed.len() > 256
            || trimmed
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '@' | '?' | '#' | '\\'))
        {
            return false;
        }
        let authority = rest.split('/').next().unwrap_or("");
        let Some((host, port_str)) = authority.split_once(':') else {
            return false;
        };
        if !host.eq_ignore_ascii_case("127.0.0.1") && !host.eq_ignore_ascii_case("localhost") {
            return false;
        }
        matches!(port_str.parse::<u16>(), Ok(p) if p > 0)
    }

    pub fn set_system_pac(enable: bool, pac_url: &str) -> RouteWardResult<bool> {
        if enable && !Self::is_valid_local_pac_url(pac_url) {
            return Err(RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_PAC_URL_INVALID,
                detail: "PAC URL must use loopback http://127.0.0.1:<port>/...".to_string(),
            });
        }
        #[cfg(windows)]
        {
            let pac_url = pac_url.trim();
            Self::with_user_state(|settings, backups| {
                if enable {
                    user_state::enable_pac(settings, backups, pac_url)
                } else {
                    user_state::disable_pac(settings, backups, pac_url).map(|_| ())
                }
            })?;
            Ok(enable)
        }
        #[cfg(not(windows))]
        {
            let _ = pac_url;
            Ok(enable)
        }
    }

    /// Reads whether the per-user system proxy switch (`ProxyEnable`) is currently on.
    /// Any failure to query it (missing value, tool error) counts as off; always off elsewhere.
    pub fn is_system_proxy_enabled() -> bool {
        #[cfg(windows)]
        {
            use user_state::{RegLocation, UserSettingsStore};
            Win32RegistryStore::current_user()
                .read(
                    RegLocation::InternetSettings,
                    user_state::VALUE_PROXY_ENABLE,
                )
                .ok()
                .flatten()
                == Some(RegValue::Dword(1))
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    pub fn get_system_pac_url() -> Option<String> {
        #[cfg(windows)]
        {
            use user_state::{RegLocation, UserSettingsStore};
            Win32RegistryStore::current_user()
                .read(
                    RegLocation::InternetSettings,
                    user_state::VALUE_AUTO_CONFIG_URL,
                )
                .ok()
                .flatten()
                .and_then(|value| value.as_text().map(str::to_string))
                .filter(|url| !url.is_empty())
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    pub fn is_autostart_enabled() -> bool {
        #[cfg(windows)]
        {
            let Ok(output) = Command::new(windows_system_tool_path("reg.exe"))
                .args(["query", WIN_RUN_REG_PATH, "/v", AUTOSTART_VALUE_NAME])
                .output()
            else {
                return false;
            };
            output.status.success()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    pub fn set_autostart(enable: bool, exe_path: &str) -> RouteWardResult<bool> {
        #[cfg(windows)]
        {
            if enable {
                let trimmed = exe_path.trim().trim_matches('"');
                if trimmed.is_empty() {
                    return Err(RouteWardError::SystemError {
                        key: ERR_KEY_SYSTEM_PATH_EMPTY,
                        detail: "Autostart executable path cannot be empty".to_string(),
                    });
                }
                let quoted = format!("\"{trimmed}\"");
                Self::run_reg_add(&[
                    "add",
                    WIN_RUN_REG_PATH,
                    "/v",
                    AUTOSTART_VALUE_NAME,
                    "/t",
                    "REG_SZ",
                    "/d",
                    &quoted,
                    "/f",
                ])?;
            } else {
                Self::run_reg_delete_value(WIN_RUN_REG_PATH, AUTOSTART_VALUE_NAME);
            }
            Ok(enable)
        }
        #[cfg(not(windows))]
        {
            let _ = exe_path;
            Ok(enable)
        }
    }

    pub fn spawn_process_with_proxy(
        executable_path: &str,
        args: &[String],
        socks_endpoint: &str,
        http_endpoint: &str,
    ) -> RouteWardResult<LaunchedProcessReport> {
        let trimmed_exe = executable_path.trim();
        if trimmed_exe.is_empty() {
            return Err(RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_PATH_EMPTY,
                detail: "Executable path cannot be empty".to_string(),
            });
        }

        let socks_url = format!("socks5h://{socks_endpoint}");
        let http_url = format!("http://{http_endpoint}");

        let child = Command::new(trimmed_exe)
            .args(args)
            .env(ENV_ALL_PROXY, &socks_url)
            .env(ENV_HTTP_PROXY, &http_url)
            .env(ENV_HTTPS_PROXY, &http_url)
            .env(ENV_NO_PROXY, DEFAULT_NO_PROXY_VALUE)
            .spawn()
            .map_err(|err| RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_LAUNCH_FAILED,
                detail: format!("cannot start {trimmed_exe}: {err}"),
            })?;

        Ok(LaunchedProcessReport {
            pid: child.id(),
            command: format_display_command(trimmed_exe, args),
            proxy_endpoint: socks_endpoint.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_command_quotes_only_the_arguments_that_need_it() {
        assert_eq!(format_display_command("tool", &[]), "tool");
        assert_eq!(
            format_display_command(
                r"C:\Program Files\App\app.exe",
                &[
                    "--flag".to_string(),
                    "two words".to_string(),
                    String::new(),
                    r#"say "hi""#.to_string(),
                ]
            ),
            r#""C:\Program Files\App\app.exe" --flag "two words" "" "say \"hi\"""#
        );
    }

    #[test]
    fn detects_a_routeward_proxy_only_when_on_and_pointing_to_the_relay() {
        let on = RegValue::Dword(1);
        let off = RegValue::Dword(0);
        let ours = RegValue::Sz("socks=127.0.0.1:10808".to_string());
        let corp = RegValue::Sz("proxy.corp.example:3128".to_string());
        assert!(proxy_is_routeward(
            Some(&on),
            Some(&ours),
            "127.0.0.1:10808"
        ));
        assert!(!proxy_is_routeward(
            Some(&off),
            Some(&ours),
            "127.0.0.1:10808"
        ));
        assert!(!proxy_is_routeward(
            Some(&on),
            Some(&corp),
            "127.0.0.1:10808"
        ));
        assert!(!proxy_is_routeward(Some(&on), Some(&ours), "127.0.0.1:1"));
        assert!(!proxy_is_routeward(None, None, "127.0.0.1:10808"));
    }

    #[test]
    fn pac_enable_with_a_foreign_url_is_a_keyed_error() {
        let err = SystemProxyManager::set_system_pac(true, "https://evil.example/p.pac")
            .expect_err("foreign PAC URL must be refused");
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_PAC_URL_INVALID);
    }

    #[test]
    fn parses_reg_dword_enabled_and_disabled() {
        let on =
            "\r\nHKEY_CURRENT_USER\\Software\\X\r\n    ProxyEnable    REG_DWORD    0x1\r\n\r\n";
        let off = "    ProxyEnable    REG_DWORD    0x0";
        assert_eq!(parse_reg_dword_value(on), Some(1));
        assert_eq!(parse_reg_dword_value(off), Some(0));
    }

    #[test]
    fn parses_reg_dword_ignores_localized_text_and_rejects_other_types() {
        let fr = "Valeur ProxyEnable\n    ProxyEnable    REG_DWORD    0x00000001\n";
        assert_eq!(parse_reg_dword_value(fr), Some(1));
        assert_eq!(
            parse_reg_dword_value("    AutoConfigURL    REG_SZ    http://x"),
            None
        );
        assert_eq!(
            parse_reg_dword_value("    ProxyEnable    REG_DWORD    garbage"),
            None
        );
        assert_eq!(parse_reg_dword_value(""), None);
    }

    #[cfg(windows)]
    #[test]
    fn system_tool_path_resolves_into_the_system_directory() {
        let reg = windows_system_tool_path("reg.exe");
        assert!(reg.is_absolute());
        assert!(reg.ends_with("reg.exe"));
        assert!(
            reg.exists(),
            "{} should exist on a Windows host",
            reg.display()
        );
        let dir = reg
            .parent()
            .expect("parent dir")
            .to_string_lossy()
            .to_lowercase();
        assert!(dir.ends_with("system32"), "unexpected directory {dir}");
    }

    #[test]
    fn rejects_empty_executable_path_without_split_whitespace() {
        let err = SystemProxyManager::spawn_process_with_proxy(
            "   ",
            &["--flag".to_string()],
            "127.0.0.1:1080",
            "127.0.0.1:8080",
        )
        .expect_err("empty executable path must return error");
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn validates_loopback_pac_urls_strictly() {
        assert!(SystemProxyManager::is_valid_local_pac_url(
            "http://127.0.0.1:10811/proxy.pac"
        ));
        assert!(SystemProxyManager::is_valid_local_pac_url(
            "http://localhost:10811/proxy.pac"
        ));
        assert!(!SystemProxyManager::is_valid_local_pac_url(
            "https://evil.example/proxy.pac"
        ));
        assert!(!SystemProxyManager::is_valid_local_pac_url(
            "http://127.0.0.1:10811/proxy.pac\" & calc"
        ));
        assert!(!SystemProxyManager::is_valid_local_pac_url(
            "http://127.0.0.1:10811@evil.example/proxy.pac"
        ));
        assert!(!SystemProxyManager::is_valid_local_pac_url(
            "http://localhost:80.evil.example/proxy.pac"
        ));
        assert!(!SystemProxyManager::is_valid_local_pac_url(
            "http://127.0.0.1:0/proxy.pac"
        ));
    }
}
