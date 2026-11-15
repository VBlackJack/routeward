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

use crate::error::RouteWardResult;
use serde::{Deserialize, Serialize};
use std::process::Command;

const ENV_ALL_PROXY: &str = "ALL_PROXY";
const ENV_HTTP_PROXY: &str = "HTTP_PROXY";
const ENV_HTTPS_PROXY: &str = "HTTPS_PROXY";
const ENV_NO_PROXY: &str = "NO_PROXY";
const DEFAULT_NO_PROXY_VALUE: &str = "localhost,127.0.0.1,::1";

#[cfg(windows)]
const WIN_INET_REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

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
        let output = Command::new("reg").args(args).output()?;
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
}
