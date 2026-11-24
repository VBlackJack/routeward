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

use crate::config::ProxyProtocol;
use crate::proxy::uri::ProxyUriCodec;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const LOCAL_PROBE_TIMEOUT_MS: u64 = 100;
const ROUTEWARD_RESERVED_PORTS: &[u16] = &[10808, 10809, 10810, 10811, 10853, 10854];
const ENV_PROXY_KEYS: &[&str] = &[
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
];

const WELL_KNOWN_LOCAL_PROXIES: &[(&str, ProxyProtocol, u16)] = &[
    ("Tor Browser SOCKS5", ProxyProtocol::Socks5, 9150),
    ("Tor Service SOCKS5", ProxyProtocol::Socks5, 9050),
    ("Local SOCKS5 / SSH Tunnel", ProxyProtocol::Socks5, 1080),
    ("Local HTTP Proxy (7890)", ProxyProtocol::Http, 7890),
    ("Local HTTP Proxy (8080)", ProxyProtocol::Http, 8080),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DetectedProxyCandidate {
    pub name: String,
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CurrentNetworkInfo {
    pub network_name: Option<String>,
    pub kind: String,
}

fn is_routeward_local_port(host: &str, port: u16) -> bool {
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]";
    is_loopback && ROUTEWARD_RESERVED_PORTS.contains(&port)
}

/// Parses a proxy string from an environment variable or Windows `ProxyServer` value
/// (`host:port`, `http://host:port`, or `http=host:port;socks=host:port`).
pub fn parse_proxy_spec_entries(raw: &str, source: &str) -> Vec<DetectedProxyCandidate> {
    let mut results = Vec::new();
    for segment in raw.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let (explicit_proto, addr_part) = if let Some((scheme, rest)) = segment.split_once('=') {
            let proto = match scheme.trim().to_ascii_lowercase().as_str() {
                "socks" | "socks5" => Some(ProxyProtocol::Socks5),
                "socks4" => Some(ProxyProtocol::Socks4),
                "https" => Some(ProxyProtocol::Https),
                "http" => Some(ProxyProtocol::Http),
                _ => None,
            };
            (proto, rest.trim())
        } else {
            (None, segment)
        };

        if addr_part.contains("://") {
            if let Ok(node) = ProxyUriCodec::parse_uri(addr_part) {
                if !is_routeward_local_port(&node.host, node.port) {
                    results.push(DetectedProxyCandidate {
                        name: node.name,
                        protocol: node.protocol,
                        host: node.host,
                        port: node.port,
                        source: source.to_string(),
                    });
                }
            }
            continue;
        }

        if let Some((host, port_str)) = addr_part.rsplit_once(':') {
            let clean_host = host.trim().trim_matches(&['[', ']'][..]);
            if let Ok(port) = port_str.trim().parse::<u16>() {
                if !clean_host.is_empty() && port > 0 && !is_routeward_local_port(clean_host, port)
                {
                    let protocol = explicit_proto.unwrap_or(ProxyProtocol::Http);
                    results.push(DetectedProxyCandidate {
                        name: format!("System Proxy ({clean_host}:{port})"),
                        protocol,
                        host: clean_host.to_string(),
                        port,
                        source: source.to_string(),
                    });
                }
            }
        }
    }
    results
}

#[cfg(windows)]
fn read_windows_registry_proxy() -> Vec<DetectedProxyCandidate> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const INTERNET_SETTINGS_KEY: &str =
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    let reg_exe = super::windows_system_tool_path("reg.exe");
    let enabled_out = Command::new(&reg_exe)
        .args(["query", INTERNET_SETTINGS_KEY, "/v", "ProxyEnable"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let Ok(enabled_out) = enabled_out else {
        return Vec::new();
    };
    if !enabled_out.status.success() {
        return Vec::new();
    }
    let enabled_text = String::from_utf8_lossy(&enabled_out.stdout);
    let is_enabled = enabled_text.lines().any(|line| {
        let mut parts = line.split_whitespace();
        let _name = parts.next();
        let kind = parts.next();
        let val = parts.next();
        kind == Some("REG_DWORD")
            && val
                .and_then(|v| {
                    v.strip_prefix("0x")
                        .or_else(|| v.strip_prefix("0X"))
                        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                        .or_else(|| v.parse::<u32>().ok())
                })
                .is_some_and(|n| n != 0)
    });
    if !is_enabled {
        return Vec::new();
    }

    let server_out = Command::new(&reg_exe)
        .args(["query", INTERNET_SETTINGS_KEY, "/v", "ProxyServer"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let Ok(server_out) = server_out else {
        return Vec::new();
    };
    if !server_out.status.success() {
        return Vec::new();
    }
    let server_text = String::from_utf8_lossy(&server_out.stdout);
    for line in server_text.lines() {
        if let Some(idx) = line.find("REG_SZ") {
            let value = line[idx + "REG_SZ".len()..].trim();
            if !value.is_empty() {
                return parse_proxy_spec_entries(value, "windows_registry");
            }
        }
    }
    Vec::new()
}

#[cfg(not(windows))]
fn read_windows_registry_proxy() -> Vec<DetectedProxyCandidate> {
    Vec::new()
}

/// Detects existing external or local proxies configured on the host (environment variables,
/// Windows Internet Settings, and well-known local proxy ports such as Tor or SSH tunnels).
pub fn detect_existing_proxies() -> Vec<DetectedProxyCandidate> {
    let mut candidates = Vec::new();
    let mut seen: HashSet<(String, String, u16)> = HashSet::new();

    let mut push_unique = |cand: DetectedProxyCandidate| {
        let key = (
            format!("{:?}", cand.protocol),
            cand.host.to_ascii_lowercase(),
            cand.port,
        );
        if seen.insert(key) {
            candidates.push(cand);
        }
    };

    for cand in read_windows_registry_proxy() {
        push_unique(cand);
    }

    for env_key in ENV_PROXY_KEYS {
        if let Ok(val) = std::env::var(env_key) {
            for cand in parse_proxy_spec_entries(&val, "env") {
                push_unique(cand);
            }
        }
    }

    let timeout = Duration::from_millis(LOCAL_PROBE_TIMEOUT_MS);
    for &(label, protocol, port) in WELL_KNOWN_LOCAL_PROXIES {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            push_unique(DetectedProxyCandidate {
                name: label.to_string(),
                protocol,
                host: "127.0.0.1".to_string(),
                port,
                source: "local_probe".to_string(),
            });
        }
    }

    candidates
}

/// Extracts the connected Wi-Fi SSID from `netsh wlan show interfaces` output.
pub fn parse_windows_netsh_ssid(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("bssid") {
            continue;
        }
        if lower.starts_with("ssid") {
            if let Some((_, val)) = trimmed.split_once(':') {
                let ssid = val.trim();
                if !ssid.is_empty() {
                    return Some(ssid.to_string());
                }
            }
        }
    }
    None
}

/// Detects the current active network name (e.g. Wi-Fi SSID) so profiles can switch automatically.
pub fn detect_current_network() -> CurrentNetworkInfo {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let netsh_exe = super::windows_system_tool_path("netsh.exe");
        if let Ok(output) = Command::new(netsh_exe)
            .args(["wlan", "show", "interfaces"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Some(ssid) = parse_windows_netsh_ssid(&text) {
                    return CurrentNetworkInfo {
                        network_name: Some(ssid),
                        kind: "wifi".to_string(),
                    };
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        if let Ok(output) = Command::new("iwgetid").arg("-r").output() {
            if output.status.success() {
                let ssid = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ssid.is_empty() {
                    return CurrentNetworkInfo {
                        network_name: Some(ssid),
                        kind: "wifi".to_string(),
                    };
                }
            }
        }
    }

    CurrentNetworkInfo {
        network_name: None,
        kind: "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_proxy_server_and_skips_routeward_local_relay() {
        let entries = parse_proxy_spec_entries(
            "http=10.0.0.5:8080;socks=127.0.0.1:9150;http=127.0.0.1:10809",
            "windows_registry",
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol, ProxyProtocol::Http);
        assert_eq!(entries[0].host, "10.0.0.5");
        assert_eq!(entries[0].port, 8080);
        assert_eq!(entries[1].protocol, ProxyProtocol::Socks5);
        assert_eq!(entries[1].host, "127.0.0.1");
        assert_eq!(entries[1].port, 9150);
    }

    #[test]
    fn parses_env_proxy_uri() {
        let entries = parse_proxy_spec_entries("socks5://corp-proxy.local:1080#Corp", "env");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, ProxyProtocol::Socks5);
        assert_eq!(entries[0].host, "corp-proxy.local");
        assert_eq!(entries[0].port, 1080);
    }

    #[test]
    fn extracts_ssid_from_netsh_output_and_ignores_bssid() {
        let sample = "\
    Name                   : Wi-Fi\n\
    State                  : connected\n\
    SSID                   : Cafe_Public_5G\n\
    BSSID                  : aa:bb:cc:dd:ee:ff\n";
        assert_eq!(
            parse_windows_netsh_ssid(sample),
            Some("Cafe_Public_5G".to_string())
        );
    }
}
