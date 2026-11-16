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

pub mod windows_service;

use crate::error::RouteWardResult;
use serde::{Deserialize, Serialize};
use std::process::Command;

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
const WIN_INET_REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
#[cfg(windows)]
const WIN_RUN_REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const AUTOSTART_VALUE_NAME: &str = "RouteWardDesktop";

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

pub struct SystemProxyManager;

impl SystemProxyManager {
    #[cfg(windows)]
    fn run_reg_add(args: &[&str]) -> RouteWardResult<()> {
        let output = Command::new(windows_system_tool_path("reg.exe"))
            .args(args)
            .output()?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(std::io::Error::other(if detail.is_empty() {
                format!("reg add exited with status {}", output.status)
            } else {
                format!("reg add failed: {detail}")
            })
            .into());
        }
        Ok(())
    }

    /// Deletes a registry value, treating "value not found" as success.
    ///
    /// `reg delete` reports every failure with exit code 1 and a localized message, so the
    /// "not found" case is told apart locale-independently: after a failed delete, a `reg query`
    /// of the same value must also fail for the value to count as already absent.
    #[cfg(windows)]
    fn run_reg_delete_value(key: &str, value_name: &str) {
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

    pub fn set_system_proxy(enable: bool, socks_endpoint: &str) -> RouteWardResult<bool> {
        #[cfg(windows)]
        {
            let enable_val = if enable { "1" } else { "0" };
            Self::run_reg_add(&[
                "add",
                WIN_INET_REG_PATH,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                enable_val,
                "/f",
            ])?;

            if enable {
                let server_val = format!("socks={socks_endpoint}");
                Self::run_reg_add(&[
                    "add",
                    WIN_INET_REG_PATH,
                    "/v",
                    "ProxyServer",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &server_val,
                    "/f",
                ])?;
            }
            Ok(enable)
        }
        #[cfg(not(windows))]
        {
            let _ = socks_endpoint;
            Ok(enable)
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "PAC URL must use loopback http://127.0.0.1:<port>/...",
            )
            .into());
        }
        #[cfg(windows)]
        {
            if enable {
                Self::run_reg_add(&[
                    "add",
                    WIN_INET_REG_PATH,
                    "/v",
                    "AutoConfigURL",
                    "/t",
                    "REG_SZ",
                    "/d",
                    pac_url.trim(),
                    "/f",
                ])?;
            } else {
                Self::run_reg_delete_value(WIN_INET_REG_PATH, "AutoConfigURL");
            }
            Ok(enable)
        }
        #[cfg(not(windows))]
        {
            let _ = pac_url;
            Ok(enable)
        }
    }

    pub fn get_system_pac_url() -> Option<String> {
        #[cfg(windows)]
        {
            let output = Command::new(windows_system_tool_path("reg.exe"))
                .args(["query", WIN_INET_REG_PATH, "/v", "AutoConfigURL"])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(idx) = line.find("REG_SZ") {
                    let val = line[idx + "REG_SZ".len()..].trim();
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
            None
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
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Autostart executable path cannot be empty",
                    )
                    .into());
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Executable path cannot be empty",
            )
            .into());
        }

        let socks_url = format!("socks5h://{socks_endpoint}");
        let http_url = format!("http://{http_endpoint}");

        let child = Command::new(trimmed_exe)
            .args(args)
            .env(ENV_ALL_PROXY, &socks_url)
            .env(ENV_HTTP_PROXY, &http_url)
            .env(ENV_HTTPS_PROXY, &http_url)
            .env(ENV_NO_PROXY, DEFAULT_NO_PROXY_VALUE)
            .spawn()?;

        let display_command = if args.is_empty() {
            trimmed_exe.to_string()
        } else {
            format!("{trimmed_exe} {}", args.join(" "))
        };

        Ok(LaunchedProcessReport {
            pid: child.id(),
            command: display_command,
            proxy_endpoint: socks_endpoint.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
