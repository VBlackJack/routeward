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

use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_CONFIG_JSON, ERR_KEY_CONFIG_LOAD, ERR_KEY_CONFIG_SAVE,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

const EMBEDDED_SYSTEM_CONSTANTS: &str = include_str!("../../../../configs/system_constants.json");
const EMBEDDED_DEFAULT_PROFILE: &str = include_str!("../../../../configs/default_profile.json");
const EMBEDDED_THEMEFORGE_PALETTES: &str =
    include_str!("../../../../configs/themeforge_palettes.json");
const DEFAULT_THEME_NAME: &str = "Drakul";
const DEFAULT_ACCENT_NAME: &str = "Default";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThemeConfig {
    pub theme: String,
    pub accent: String,
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            theme: DEFAULT_THEME_NAME.to_string(),
            accent: DEFAULT_ACCENT_NAME.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThemeForgeCatalog {
    pub version: u32,
    pub default_theme: String,
    pub default_accent: String,
    pub accents: Vec<String>,
    pub design_tokens: serde_json::Value,
    pub palettes: Vec<serde_json::Value>,
}

impl ThemeForgeCatalog {
    pub fn load_embedded() -> RouteWardResult<Self> {
        serde_json::from_str(EMBEDDED_THEMEFORGE_PALETTES).map_err(|err| {
            RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_JSON,
                detail: err.to_string(),
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemConstants {
    pub network: NetworkConstants,
    pub dns: DnsConstants,
    pub checker: CheckerConstants,
    pub telemetry: TelemetryConstants,
    pub protocols: ProtocolConstants,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConstants {
    pub local_bind_host: String,
    pub transparent_bind_host: String,
    pub default_relay_tcp_port: u16,
    pub default_relay_http_port: u16,
    pub default_transparent_tcp_port: u16,
    pub default_dns_listen_port: u16,
    pub tcp_connect_timeout_ms: u64,
    pub proxy_handshake_timeout_ms: u64,
    pub udp_association_timeout_ms: u64,
    pub relay_buffer_size_bytes: usize,
    pub max_concurrent_connections: usize,
    pub pid_fallback_retries: u32,
    pub pid_fallback_delay_ms: u64,
    pub pending_syn_timeout_ms: u64,
    pub windivert_priority: i16,
    pub windivert_dll_paths: Vec<String>,
    #[serde(default = "default_linux_fwmark")]
    pub linux_fwmark: u32,
    #[serde(default = "default_linux_nft_binary")]
    pub linux_nft_binary: String,
    #[serde(default = "default_linux_nft_table_name")]
    pub linux_nft_table_name: String,
    #[serde(default = "default_linux_nft_chain_name")]
    pub linux_nft_chain_name: String,
}

fn default_linux_fwmark() -> u32 {
    0x5257
}

fn default_linux_nft_binary() -> String {
    "nft".to_string()
}

fn default_linux_nft_table_name() -> String {
    "routeward".to_string()
}

fn default_linux_nft_chain_name() -> String {
    "output".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConstants {
    pub fake_ip_cidr: String,
    pub default_ttl_seconds: u64,
    pub max_cache_entries: usize,
    pub upstream_dns_server: String,
    pub fallback_dns_server: String,
    pub dns_query_packet_max_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckerConstants {
    pub probe_target_host: String,
    pub probe_target_port: u16,
    pub http_ip_echo_host: String,
    pub http_ip_echo_port: u16,
    pub http_ip_echo_path: String,
    pub udp_probe_dns_host: String,
    pub udp_probe_dns_port: u16,
    pub probe_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryConstants {
    pub max_log_ring_buffer_entries: usize,
    pub max_bandwidth_history_samples: usize,
    pub sampling_interval_ms: u64,
    pub process_cache_ttl_ms: u64,
    pub log_directory: String,
    pub log_app_name: String,
    pub log_flush_interval_ms: u64,
    #[serde(default = "default_event_broadcast_capacity")]
    pub event_broadcast_capacity: usize,
    #[serde(default = "default_profile_path")]
    pub default_profile_path: String,
}

fn default_event_broadcast_capacity() -> usize {
    256
}

fn default_profile_path() -> String {
    "configs/active_profile.json".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolConstants {
    pub socks5_version: u8,
    pub socks5_auth_none: u8,
    pub socks5_auth_password: u8,
    pub socks5_auth_no_acceptable: u8,
    pub socks5_password_auth_version: u8,
    pub socks5_cmd_connect: u8,
    pub socks5_cmd_udp_associate: u8,
    pub socks5_atyp_ipv4: u8,
    pub socks5_atyp_domain: u8,
    pub socks5_atyp_ipv6: u8,
    pub socks5_reply_succeeded: u8,
    pub http_success_status_prefix: String,
    pub http_alt_success_status_prefix: String,
}

impl SystemConstants {
    pub fn load_embedded() -> RouteWardResult<Self> {
        serde_json::from_str(EMBEDDED_SYSTEM_CONSTANTS).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: err.to_string(),
        })
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> RouteWardResult<Self> {
        let content = fs::read_to_string(path).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_LOAD,
            detail: err.to_string(),
        })?;
        serde_json::from_str(&content).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: err.to_string(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterceptionMode {
    Hybrid,
    Driver,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    Socks5,
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyNode {
    pub id: String,
    pub name: String,
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyCredentials>,
    pub udp_enabled: bool,
    pub tls: bool,
    pub sni: Option<String>,
    pub enabled: bool,
    pub last_latency_ms: Option<u64>,
    pub exit_ip: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainStrategy {
    #[default]
    Sequence,
    Failover,
    LowestLatency,
    LoadBalance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPolicyConfig {
    pub kill_switch_enabled: bool,
    pub block_udp_on_tcp_only_proxy: bool,
    pub strict_dns_no_local_fallback: bool,
    #[serde(default = "default_unknown_process_action")]
    pub unknown_process_action: RuleAction,
}

fn default_unknown_process_action() -> RuleAction {
    RuleAction::Direct
}

impl Default for SecurityPolicyConfig {
    fn default() -> Self {
        Self {
            kill_switch_enabled: true,
            block_udp_on_tcp_only_proxy: true,
            strict_dns_no_local_fallback: true,
            unknown_process_action: RuleAction::Direct,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyChain {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub strategy: ChainStrategy,
    pub proxy_ids: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleAction {
    Direct,
    Block,
    Proxy {
        #[serde(rename = "targetId")]
        target_id: String,
    },
    Chain {
        #[serde(rename = "targetId")]
        target_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub process_patterns: Vec<String>,
    pub domain_patterns: Vec<String>,
    pub ip_cidrs: Vec<String>,
    pub port_ranges: Vec<PortRange>,
    pub protocol: TransportProtocol,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfig {
    pub enable_fake_ip: bool,
    pub remote_dns_resolution: bool,
    pub fake_ip_cidr: String,
    pub upstream_dns: String,
    pub bypass_domains: Vec<String>,
}

fn default_enable_logging() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileConfig {
    pub profile_id: String,
    pub name: String,
    pub version: String,
    #[serde(default = "default_enable_logging")]
    pub enable_logging: bool,
    pub interception_mode: InterceptionMode,
    #[serde(default)]
    pub theme_config: ThemeConfig,
    #[serde(default)]
    pub security_policy: SecurityPolicyConfig,
    pub default_action: RuleAction,
    pub dns_config: DnsConfig,
    pub proxies: Vec<ProxyNode>,
    pub chains: Vec<ProxyChain>,
    pub rules: Vec<RoutingRule>,
}

impl ProfileConfig {
    pub fn load_embedded_default() -> RouteWardResult<Self> {
        serde_json::from_str(EMBEDDED_DEFAULT_PROFILE).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: err.to_string(),
        })
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> RouteWardResult<Self> {
        let content = fs::read_to_string(path).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_LOAD,
            detail: err.to_string(),
        })?;
        Self::from_json_str(&content)
    }

    pub fn from_json_str(json: &str) -> RouteWardResult<Self> {
        serde_json::from_str(json).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: err.to_string(),
        })
    }

    pub fn to_json_pretty(&self) -> RouteWardResult<String> {
        serde_json::to_string_pretty(self).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: err.to_string(),
        })
    }

    /// Atomically persists the profile configuration to `path` by writing to a temporary
    /// sibling file, syncing to disk, and renaming over the destination path.
    pub fn save_to_path(&self, path: impl AsRef<Path>) -> RouteWardResult<()> {
        let target_path = path.as_ref();
        let json = self.to_json_pretty()?;

        if let Some(parent) = target_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| RouteWardError::ConfigError {
                    key: ERR_KEY_CONFIG_SAVE,
                    detail: err.to_string(),
                })?;
            }
        }

        let file_name = target_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("profile.json");
        let tmp_path = target_path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4()));

        let write_result = (|| -> std::io::Result<()> {
            let mut file = fs::File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(err) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_SAVE,
                detail: err.to_string(),
            });
        }

        if let Err(err) = fs::rename(&tmp_path, target_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_SAVE,
                detail: err.to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_themeforge_catalog_and_default_profile() {
        let catalog = ThemeForgeCatalog::load_embedded().expect("ThemeForge catalog");
        assert_eq!(catalog.default_theme, "Drakul");
        assert_eq!(catalog.palettes.len(), 17);

        let profile = ProfileConfig::load_embedded_default().expect("Default profile");
        assert_eq!(profile.theme_config.theme, "Drakul");
        assert!(profile.enable_logging);
    }

    #[test]
    fn saves_and_reloads_profile_atomically() {
        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.name = "Atomic Persistence Test Profile".to_string();

        let temp_dir =
            std::env::temp_dir().join(format!("routeward_profile_test_{}", Uuid::new_v4()));
        let profile_path = temp_dir.join("active_profile.json");

        profile
            .save_to_path(&profile_path)
            .expect("atomic save #1 succeeded");
        let loaded = ProfileConfig::load_from_path(&profile_path).expect("reload #1 succeeded");
        assert_eq!(loaded.name, "Atomic Persistence Test Profile");

        // Second overwrite verifies atomic replacement over an existing file
        profile.name = "Atomic Overwrite Profile v2".to_string();
        profile
            .save_to_path(&profile_path)
            .expect("atomic save #2 succeeded");
        let loaded_v2 = ProfileConfig::load_from_path(&profile_path).expect("reload #2 succeeded");
        assert_eq!(loaded_v2.name, "Atomic Overwrite Profile v2");

        // Ensure no temporary .tmp sibling files remain
        let entries: Vec<_> = fs::read_dir(&temp_dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
