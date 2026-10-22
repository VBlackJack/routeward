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

use crate::error::ProxifierResult;
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
    pub fn set_system_proxy(enable: bool, socks_endpoint: &str) -> ProxifierResult<bool> {
        #[cfg(windows)]
        {
            let enable_val = if enable { "1" } else { "0" };
            let _ = Command::new("reg")
                .args([
                    "add",
                    WIN_INET_REG_PATH,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    enable_val,
                    "/f",
                ])
                .output()?;

            if enable {
                let server_val = format!("socks={socks_endpoint}");
                let _ = Command::new("reg")
                    .args([
                        "add",
                        WIN_INET_REG_PATH,
                        "/v",
                        "ProxyServer",
                        "/t",
                        "REG_SZ",
                        "/d",
                        &server_val,
                        "/f",
                    ])
                    .output()?;
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
        command_line: &str,
        socks_endpoint: &str,
        http_endpoint: &str,
    ) -> ProxifierResult<LaunchedProcessReport> {
        let parts: Vec<&str> = command_line.split_whitespace().collect();
        let program = parts.first().copied().unwrap_or(command_line);
        let args = if parts.len() > 1 { &parts[1..] } else { &[] };

        let socks_url = format!("socks5h://{socks_endpoint}");
        let http_url = format!("http://{http_endpoint}");

        let child = Command::new(program)
            .args(args)
            .env(ENV_ALL_PROXY, &socks_url)
            .env(ENV_HTTP_PROXY, &http_url)
            .env(ENV_HTTPS_PROXY, &http_url)
            .env(ENV_NO_PROXY, DEFAULT_NO_PROXY_VALUE)
            .spawn()?;

        Ok(LaunchedProcessReport {
            pid: child.id(),
            command: command_line.to_string(),
            proxy_endpoint: socks_endpoint.to_string(),
        })
    }
}
