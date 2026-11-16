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

pub mod security;

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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    pub ipc: IpcConstants,
    pub protocols: ProtocolConstants,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcConstants {
    pub unix_socket_path: String,
    pub unix_socket_group: String,
    pub unix_socket_mode: u32,
    pub unix_socket_dir_mode: u32,
    pub windows_pipe_name: String,
    pub windows_profile_path: String,
    pub linux_profile_path: String,
    pub max_line_bytes: usize,
    pub idle_timeout_ms: u64,
    pub reconnect_interval_ms: u64,
}

impl IpcConstants {
    pub fn resolve_daemon_profile_path(&self) -> RouteWardResult<std::path::PathBuf> {
        #[cfg(windows)]
        {
            let program_data = security::resolve_windows_program_data_dir()?;
            let program_data_str = program_data.to_string_lossy();
            let expanded = self
                .windows_profile_path
                .replace("%ProgramData%", &program_data_str);
            Ok(std::path::PathBuf::from(expanded))
        }
        #[cfg(not(windows))]
        {
            Ok(std::path::PathBuf::from(&self.linux_profile_path))
        }
    }

    pub fn resolve_daemon_profiles_dir(&self) -> RouteWardResult<std::path::PathBuf> {
        let primary = self.resolve_daemon_profile_path()?;
        let parent = primary
            .parent()
            .ok_or_else(|| RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: "Invalid daemon profile path".to_string(),
            })?;
        Ok(parent.join("profiles"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSummary {
    pub profile_id: String,
    pub name: String,
    pub proxy_count: usize,
    pub rule_count: usize,
    pub active: bool,
}

pub fn is_valid_profile_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 48
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub fn slugify_profile_id(raw: &str) -> String {
    let mut slug = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if (ch == '-' || ch == '_' || ch.is_whitespace()) && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let trimmed = slug.trim_matches('-').chars().take(48).collect::<String>();
    if is_valid_profile_slug(&trimmed) {
        trimmed
    } else {
        "custom-profile".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConstants {
    pub local_bind_host: String,
    pub transparent_bind_host: String,
    pub default_relay_tcp_port: u16,
    pub default_relay_http_port: u16,
    pub default_transparent_tcp_port: u16,
    #[serde(default = "default_pac_port")]
    pub default_pac_port: u16,
    pub default_dns_listen_port: u16,
    #[serde(default = "default_local_name_inspect_port")]
    pub default_local_name_inspect_port: u16,
    #[serde(default = "default_quic_default_port")]
    pub quic_default_port: u16,
    #[serde(default = "default_mdns_standard_port")]
    pub mdns_standard_port: u16,
    #[serde(default = "default_llmnr_standard_port")]
    pub llmnr_standard_port: u16,
    #[serde(default = "default_netbios_ns_standard_port")]
    pub netbios_ns_standard_port: u16,
    pub tcp_connect_timeout_ms: u64,
    pub proxy_handshake_timeout_ms: u64,
    pub udp_association_timeout_ms: u64,
    #[serde(default = "default_udp_association_idle_timeout_secs")]
    pub udp_association_idle_timeout_secs: u64,
    #[serde(default = "default_max_udp_associations")]
    pub max_udp_associations: usize,
    #[serde(default = "default_udp_capability_cache_secs")]
    pub udp_capability_cache_secs: u64,
    #[serde(default = "default_udp_warn_rate_limit_secs")]
    pub udp_warn_rate_limit_secs: u64,
    pub relay_buffer_size_bytes: usize,
    pub max_concurrent_connections: usize,
    pub pid_fallback_retries: u32,
    pub pid_fallback_delay_ms: u64,
    pub pending_syn_timeout_ms: u64,
    #[serde(default = "default_pending_udp_timeout_ms")]
    pub pending_udp_timeout_ms: u64,
    #[serde(default = "default_max_pending_udp_packets")]
    pub max_pending_udp_packets: usize,
    /// Capacity of the pending outbound SYN queue; the oldest SYN is dropped when it is full.
    #[serde(default = "default_max_pending_syn_packets")]
    pub max_pending_syn_packets: usize,
    /// Lifetime of a socket-to-PID cache entry (protocol, family, local port) in milliseconds.
    #[serde(default = "default_socket_pid_cache_ttl_ms")]
    pub socket_pid_cache_ttl_ms: u64,
    /// Age after which a NAT session never accepted by the local relay is removed.
    #[serde(default = "default_nat_half_open_session_ttl_secs")]
    pub nat_half_open_session_ttl_secs: u64,
    /// Interval between sweeps of expired NAT sessions and cache entries, in milliseconds.
    #[serde(default = "default_nat_session_sweep_interval_ms")]
    pub nat_session_sweep_interval_ms: u64,
    /// How long the verdict of a fragmented UDP datagram is remembered for its later fragments.
    #[serde(default = "default_udp_fragment_verdict_ttl_ms")]
    pub udp_fragment_verdict_ttl_ms: u64,
    /// Maximum number of remembered fragmented UDP datagram verdicts.
    #[serde(default = "default_max_udp_fragment_verdicts")]
    pub max_udp_fragment_verdicts: usize,
    /// How long a finished transparent TCP relay session stays in the NAT table, so the final
    /// FIN/RST and the client's trailing ACK/FIN are still reflected, in milliseconds.
    #[serde(default = "default_session_close_grace_ms")]
    pub session_close_grace_ms: u64,
    /// Polling interval while peeking the first bytes of a TCP stream for SNI / Host, in milliseconds.
    #[serde(default = "default_peek_poll_interval_ms")]
    pub peek_poll_interval_ms: u64,
    /// Maximum number of idle direct-UDP sockets kept for reuse, per address family.
    #[serde(default = "default_direct_udp_socket_pool_size")]
    pub direct_udp_socket_pool_size: usize,
    /// Lower bound of the receive timeout of a direct UDP datagram exchange, in milliseconds.
    #[serde(default = "default_udp_direct_timeout_min_ms")]
    pub udp_direct_timeout_min_ms: u64,
    /// Upper bound of the receive timeout of a direct UDP datagram exchange, in milliseconds.
    #[serde(default = "default_udp_direct_timeout_max_ms")]
    pub udp_direct_timeout_max_ms: u64,
    /// Timeout of a direct LLMNR / mDNS query fallback, in milliseconds.
    #[serde(default = "default_local_name_query_timeout_ms")]
    pub local_name_query_timeout_ms: u64,
    /// How long a parsed conntrack table snapshot is served without re-reading the kernel table.
    #[serde(default = "default_conntrack_cache_ttl_ms")]
    pub conntrack_cache_ttl_ms: u64,
    /// Minimum age of the conntrack snapshot before a lookup miss may trigger a refresh.
    #[serde(default = "default_conntrack_min_refresh_interval_ms")]
    pub conntrack_min_refresh_interval_ms: u64,
    pub windivert_priority: i16,
    pub windivert_dll_paths: Vec<String>,
    #[serde(default = "default_linux_fwmark")]
    pub linux_fwmark: u32,
    #[serde(default = "default_linux_tproxy_fwmark")]
    pub linux_tproxy_fwmark: u32,
    #[serde(default = "default_linux_tproxy_route_table")]
    pub linux_tproxy_route_table: u32,
    #[serde(default = "default_linux_tproxy_rule_priority")]
    pub linux_tproxy_rule_priority: u32,
    #[serde(default = "default_linux_ip_binary")]
    pub linux_ip_binary: String,
    #[serde(default = "default_linux_nft_binary")]
    pub linux_nft_binary: String,
    #[serde(default = "default_linux_nft_table_name")]
    pub linux_nft_table_name: String,
    #[serde(default = "default_linux_nft_chain_name")]
    pub linux_nft_chain_name: String,
    #[serde(default = "default_tls_sni_default_port")]
    pub tls_sni_default_port: u16,
    #[serde(default = "default_tls_sni_peek_timeout_ms")]
    pub tls_sni_peek_timeout_ms: u64,
    #[serde(default = "default_tls_sni_max_bytes")]
    pub tls_sni_max_bytes: usize,
    #[serde(default = "default_http_host_inspect_ports")]
    pub http_host_inspect_ports: Vec<u16>,
    #[serde(default = "default_http_host_peek_timeout_ms")]
    pub http_host_peek_timeout_ms: u64,
    #[serde(default = "default_http_host_max_bytes")]
    pub http_host_max_bytes: usize,
}

fn default_pac_port() -> u16 {
    10811
}

fn default_http_host_inspect_ports() -> Vec<u16> {
    vec![80, 8080, 8000, 8888]
}

fn default_http_host_peek_timeout_ms() -> u64 {
    200
}

fn default_http_host_max_bytes() -> usize {
    4096
}

fn default_linux_fwmark() -> u32 {
    0x5257
}

fn default_local_name_inspect_port() -> u16 {
    10854
}

fn default_quic_default_port() -> u16 {
    443
}

fn default_mdns_standard_port() -> u16 {
    5353
}

fn default_llmnr_standard_port() -> u16 {
    5355
}

fn default_netbios_ns_standard_port() -> u16 {
    137
}

fn default_udp_association_idle_timeout_secs() -> u64 {
    60
}

fn default_max_udp_associations() -> usize {
    512
}

fn default_udp_capability_cache_secs() -> u64 {
    300
}

fn default_udp_warn_rate_limit_secs() -> u64 {
    30
}

fn default_linux_tproxy_fwmark() -> u32 {
    21080
}

fn default_linux_tproxy_route_table() -> u32 {
    100
}

fn default_linux_tproxy_rule_priority() -> u32 {
    10810
}

fn default_pending_udp_timeout_ms() -> u64 {
    40
}

fn default_max_pending_udp_packets() -> usize {
    256
}

fn default_max_pending_syn_packets() -> usize {
    1024
}

fn default_socket_pid_cache_ttl_ms() -> u64 {
    5000
}

fn default_nat_half_open_session_ttl_secs() -> u64 {
    60
}

fn default_nat_session_sweep_interval_ms() -> u64 {
    5000
}

fn default_udp_fragment_verdict_ttl_ms() -> u64 {
    10000
}

fn default_max_udp_fragment_verdicts() -> usize {
    4096
}

fn default_session_close_grace_ms() -> u64 {
    250
}

fn default_peek_poll_interval_ms() -> u64 {
    5
}

fn default_direct_udp_socket_pool_size() -> usize {
    16
}

fn default_udp_direct_timeout_min_ms() -> u64 {
    300
}

fn default_udp_direct_timeout_max_ms() -> u64 {
    1500
}

fn default_local_name_query_timeout_ms() -> u64 {
    300
}

fn default_conntrack_cache_ttl_ms() -> u64 {
    1000
}

fn default_conntrack_min_refresh_interval_ms() -> u64 {
    100
}

fn default_linux_ip_binary() -> String {
    "ip".to_string()
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

fn default_tls_sni_default_port() -> u16 {
    443
}

fn default_tls_sni_peek_timeout_ms() -> u64 {
    200
}

fn default_tls_sni_max_bytes() -> usize {
    4096
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConstants {
    pub fake_ip_cidr: String,
    pub default_ttl_seconds: u64,
    #[serde(default = "default_os_response_ttl_seconds")]
    pub os_response_ttl_seconds: u32,
    pub max_cache_entries: usize,
    pub upstream_dns_server: String,
    pub fallback_dns_server: String,
    pub dns_query_packet_max_bytes: usize,
    #[serde(default = "default_dns_standard_port")]
    pub dns_standard_port: u16,
    #[serde(default = "default_dns_over_tls_port")]
    pub dns_over_tls_port: u16,
    #[serde(default = "default_linux_resolv_conf_path")]
    pub linux_resolv_conf_path: String,
    #[serde(default = "default_linux_systemd_resolv_conf_path")]
    pub linux_systemd_resolv_conf_path: String,
    #[serde(default = "default_doh_canary_domains")]
    pub doh_canary_domains: Vec<String>,
    #[serde(default = "default_bypass_suffixes")]
    pub default_bypass_suffixes: Vec<String>,
    #[serde(default = "default_private_reverse_zones")]
    pub default_private_reverse_zones: Vec<String>,
    /// Lower bound of the timeout of a direct DNS query to a resolver, in milliseconds.
    #[serde(default = "default_direct_query_timeout_min_ms")]
    pub direct_query_timeout_min_ms: u64,
    /// Upper bound of the timeout of a direct DNS query to a resolver, in milliseconds.
    #[serde(default = "default_direct_query_timeout_max_ms")]
    pub direct_query_timeout_max_ms: u64,
    /// Size of the receive buffer of a direct UDP DNS reply, in bytes.
    #[serde(default = "default_udp_response_buffer_bytes")]
    pub udp_response_buffer_bytes: usize,
    /// How long a domain-to-real-IPv4 resolution done for Direct UDP traffic is reused, in seconds.
    #[serde(default = "default_fake_ip_real_resolution_ttl_secs")]
    pub fake_ip_real_resolution_ttl_secs: u64,
    /// Maximum number of cached domain-to-real-IPv4 resolutions.
    #[serde(default = "default_fake_ip_real_resolution_max_entries")]
    pub fake_ip_real_resolution_max_entries: usize,
    /// How long the detected system DNS resolver list is reused, in milliseconds.
    #[serde(default = "default_system_resolvers_cache_ttl_ms")]
    pub system_resolvers_cache_ttl_ms: u64,
}

fn default_direct_query_timeout_min_ms() -> u64 {
    500
}

fn default_direct_query_timeout_max_ms() -> u64 {
    2500
}

fn default_udp_response_buffer_bytes() -> usize {
    4096
}

fn default_fake_ip_real_resolution_ttl_secs() -> u64 {
    30
}

fn default_fake_ip_real_resolution_max_entries() -> usize {
    1024
}

fn default_system_resolvers_cache_ttl_ms() -> u64 {
    5000
}

fn default_os_response_ttl_seconds() -> u32 {
    5
}

fn default_dns_standard_port() -> u16 {
    53
}

fn default_dns_over_tls_port() -> u16 {
    853
}

fn default_linux_resolv_conf_path() -> String {
    "/etc/resolv.conf".to_string()
}

fn default_linux_systemd_resolv_conf_path() -> String {
    "/run/systemd/resolve/resolv.conf".to_string()
}

fn default_doh_canary_domains() -> Vec<String> {
    vec!["use-application-dns.net".to_string()]
}

fn default_bypass_suffixes() -> Vec<String> {
    vec![
        "localhost".to_string(),
        ".localhost".to_string(),
        ".local".to_string(),
        ".home.arpa".to_string(),
    ]
}

fn default_private_reverse_zones() -> Vec<String> {
    let mut zones = vec![
        "10.in-addr.arpa".to_string(),
        "168.192.in-addr.arpa".to_string(),
        "127.in-addr.arpa".to_string(),
        "254.169.in-addr.arpa".to_string(),
        "c.f.ip6.arpa".to_string(),
        "d.f.ip6.arpa".to_string(),
        "8.e.f.ip6.arpa".to_string(),
        "9.e.f.ip6.arpa".to_string(),
        "a.e.f.ip6.arpa".to_string(),
        "b.e.f.ip6.arpa".to_string(),
    ];
    for octet in 16..=31 {
        zones.push(format!("{octet}.172.in-addr.arpa"));
    }
    zones
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
    #[serde(default = "default_max_connection_history_entries")]
    pub max_connection_history_entries: usize,
    pub max_bandwidth_history_samples: usize,
    pub sampling_interval_ms: u64,
    pub process_cache_ttl_ms: u64,
    pub log_directory: String,
    #[serde(default = "default_windows_daemon_log_dir")]
    pub windows_daemon_log_dir: String,
    #[serde(default = "default_linux_daemon_log_dir")]
    pub linux_daemon_log_dir: String,
    #[serde(default = "default_windows_user_log_dir")]
    pub windows_user_log_dir: String,
    #[serde(default = "default_linux_user_log_dir")]
    pub linux_user_log_dir: String,
    #[serde(default = "default_linux_user_fallback_log_dir")]
    pub linux_user_fallback_log_dir: String,
    #[serde(default = "default_windows_user_webview_dir")]
    pub windows_user_webview_dir: String,
    #[serde(default = "default_linux_user_webview_dir")]
    pub linux_user_webview_dir: String,
    #[serde(default = "default_linux_user_fallback_webview_dir")]
    pub linux_user_fallback_webview_dir: String,
    pub log_app_name: String,
    pub log_flush_interval_ms: u64,
    #[serde(default = "default_event_broadcast_capacity")]
    pub event_broadcast_capacity: usize,
    /// A UDP flow with no datagram for this long is marked closed in telemetry.
    #[serde(default = "default_udp_flow_idle_timeout_ms")]
    pub udp_flow_idle_timeout_ms: u64,
    /// Minimum delay between two `ConnectionUpdated` events for the same connection while its
    /// traffic counters grow; a final update is always emitted when the connection closes.
    #[serde(default = "default_telemetry_update_interval_ms")]
    pub telemetry_update_interval_ms: u64,
}

fn default_udp_flow_idle_timeout_ms() -> u64 {
    30000
}

fn default_telemetry_update_interval_ms() -> u64 {
    250
}

fn default_max_connection_history_entries() -> usize {
    500
}

fn default_windows_daemon_log_dir() -> String {
    r"%ProgramData%\RouteWard\logs".to_string()
}

fn default_linux_daemon_log_dir() -> String {
    "/var/log/routeward".to_string()
}

fn default_windows_user_log_dir() -> String {
    r"%LOCALAPPDATA%\RouteWard\logs".to_string()
}

fn default_linux_user_log_dir() -> String {
    "$XDG_STATE_HOME/routeward/logs".to_string()
}

fn default_linux_user_fallback_log_dir() -> String {
    ".local/state/routeward/logs".to_string()
}

fn default_windows_user_webview_dir() -> String {
    r"%LOCALAPPDATA%\RouteWard\WebView2".to_string()
}

fn default_linux_user_webview_dir() -> String {
    "$XDG_DATA_HOME/routeward/webview".to_string()
}

fn default_linux_user_fallback_webview_dir() -> String {
    ".local/share/routeward/webview".to_string()
}

impl TelemetryConstants {
    /// Resolves the absolute log directory for the privileged daemon (`%ProgramData%\RouteWard\logs`
    /// on Windows via `SHGetKnownFolderPath(FOLDERID_ProgramData)`, `/var/log/routeward` on Linux).
    pub fn resolve_daemon_log_dir(&self) -> std::path::PathBuf {
        #[cfg(windows)]
        {
            if let Ok(program_data) = security::resolve_windows_program_data_dir() {
                let program_data_str = program_data.to_string_lossy();
                return std::path::PathBuf::from(
                    self.windows_daemon_log_dir
                        .replace("%ProgramData%", &program_data_str),
                );
            }
            std::path::PathBuf::from(&self.windows_daemon_log_dir)
        }
        #[cfg(not(windows))]
        {
            std::path::PathBuf::from(&self.linux_daemon_log_dir)
        }
    }

    fn resolve_user_template_dir(
        win_template: &str,
        linux_template: &str,
        linux_env_var: &str,
        linux_fallback_rel: &str,
    ) -> std::path::PathBuf {
        #[cfg(windows)]
        {
            let _ = (linux_template, linux_env_var, linux_fallback_rel);
            if let Ok(local_app_data) = security::resolve_windows_local_app_data_dir() {
                let local_str = local_app_data.to_string_lossy();
                return std::path::PathBuf::from(
                    win_template.replace("%LOCALAPPDATA%", &local_str),
                );
            }
            if let Ok(env_local) = std::env::var("LOCALAPPDATA") {
                let trimmed = env_local.trim();
                if !trimmed.is_empty() {
                    return std::path::PathBuf::from(
                        win_template.replace("%LOCALAPPDATA%", trimmed),
                    );
                }
            }
            std::path::PathBuf::from(win_template)
        }
        #[cfg(not(windows))]
        {
            let _ = win_template;
            if let Ok(xdg_dir) = std::env::var(linux_env_var) {
                let trimmed = xdg_dir.trim();
                if !trimmed.is_empty() {
                    return std::path::PathBuf::from(
                        linux_template.replace(&format!("${linux_env_var}"), trimmed),
                    );
                }
            }
            let home_dir = std::env::var("HOME")
                .ok()
                .filter(|h| !h.trim().is_empty())
                .map(std::path::PathBuf::from)
                .or_else(resolve_unix_passwd_home)
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
            home_dir.join(linux_fallback_rel)
        }
    }

    /// Resolves the absolute log directory for the desktop UI and unprivileged CLI
    /// (`%LOCALAPPDATA%\RouteWard\logs` on Windows via `SHGetKnownFolderPath(FOLDERID_LocalAppData)`,
    /// `$XDG_STATE_HOME/routeward/logs` or `~/.local/state/routeward/logs` on Linux).
    pub fn resolve_user_log_dir(&self) -> std::path::PathBuf {
        Self::resolve_user_template_dir(
            &self.windows_user_log_dir,
            &self.linux_user_log_dir,
            "XDG_STATE_HOME",
            &self.linux_user_fallback_log_dir,
        )
    }

    /// Resolves the writable per-user WebView data directory (`%LOCALAPPDATA%\RouteWard\WebView2`
    /// on Windows, `$XDG_DATA_HOME/routeward/webview` or `~/.local/share/routeward/webview` on Linux)
    /// so per-machine installs under `Program Files` never attempt to write WebView2 state into a
    /// read-only installation folder.
    pub fn resolve_user_webview_dir(&self) -> std::path::PathBuf {
        Self::resolve_user_template_dir(
            &self.windows_user_webview_dir,
            &self.linux_user_webview_dir,
            "XDG_DATA_HOME",
            &self.linux_user_fallback_webview_dir,
        )
    }

    /// Resolves the appropriate log directory for the current process privilege level.
    pub fn resolve_process_log_dir(&self) -> std::path::PathBuf {
        if crate::interceptor::RouteWardController::detect_elevated_privileges() {
            self.resolve_daemon_log_dir()
        } else {
            self.resolve_user_log_dir()
        }
    }
}

#[cfg(not(windows))]
fn resolve_unix_passwd_home() -> Option<std::path::PathBuf> {
    use std::ffi::CStr;
    // SAFETY: `geteuid` and `getpwuid` are standard POSIX calls; the returned pointer is checked for null.
    unsafe {
        let pwd = libc::getpwuid(libc::geteuid());
        if pwd.is_null() || (*pwd).pw_dir.is_null() {
            return None;
        }
        let dir_str = CStr::from_ptr((*pwd).pw_dir).to_str().ok()?;
        if dir_str.trim().is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(dir_str))
        }
    }
}

fn default_event_broadcast_capacity() -> usize {
    256
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
    #[serde(default = "default_socks5_reply_general_failure")]
    pub socks5_reply_general_failure: u8,
    #[serde(default = "default_socks5_reply_command_not_supported")]
    pub socks5_reply_command_not_supported: u8,
    #[serde(default = "default_socks4_version")]
    pub socks4_version: u8,
    #[serde(default = "default_socks4_cmd_connect")]
    pub socks4_cmd_connect: u8,
    #[serde(default = "default_socks4_reply_version")]
    pub socks4_reply_version: u8,
    #[serde(default = "default_socks4_reply_granted")]
    pub socks4_reply_granted: u8,
    pub http_success_status_prefix: String,
    pub http_alt_success_status_prefix: String,
}

fn default_socks5_reply_general_failure() -> u8 {
    1
}

fn default_socks5_reply_command_not_supported() -> u8 {
    7
}

fn default_socks4_version() -> u8 {
    4
}

fn default_socks4_cmd_connect() -> u8 {
    1
}

fn default_socks4_reply_version() -> u8 {
    0
}

fn default_socks4_reply_granted() -> u8 {
    90
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
    Socks4,
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyCredentials {
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default)]
    pub has_password: bool,
}

impl ProxyCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        let username = username.into();
        let password = password.into();
        let has_password = !password.is_empty();
        Self {
            username,
            password: Some(password),
            has_password,
        }
    }

    pub fn password_str(&self) -> &str {
        self.password.as_deref().unwrap_or("")
    }

    pub fn has_password(&self) -> bool {
        self.has_password || self.password.as_ref().is_some_and(|p| !p.is_empty())
    }

    pub fn redacted_for_ipc(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: None,
            has_password: self.has_password(),
        }
    }
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("has_password", &self.has_password())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyNode {
    pub id: String,
    pub name: String,
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyCredentials>,
    pub udp_enabled: bool,
    pub tls: bool,
    #[serde(default)]
    pub tls_skip_verify: bool,
    pub sni: Option<String>,
    pub enabled: bool,
    pub last_latency_ms: Option<u64>,
    pub exit_ip: Option<String>,
}

impl ProxyNode {
    pub fn redacted_for_ipc(&self) -> Self {
        let mut cloned = self.clone();
        cloned.auth = self.auth.as_ref().map(ProxyCredentials::redacted_for_ipc);
        cloned
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityPolicyConfig {
    pub kill_switch_enabled: bool,
    pub block_udp_on_tcp_only_proxy: bool,
    #[serde(default = "default_block_quic_udp_443")]
    pub block_quic_udp_443: bool,
    pub strict_dns_no_local_fallback: bool,
    #[serde(default = "default_block_encrypted_dns_bypass")]
    pub block_encrypted_dns_bypass: bool,
    #[serde(default = "default_unknown_process_action")]
    pub unknown_process_action: RuleAction,
}

fn default_block_quic_udp_443() -> bool {
    true
}

fn default_block_encrypted_dns_bypass() -> bool {
    true
}

fn default_unknown_process_action() -> RuleAction {
    RuleAction::Block
}

impl Default for SecurityPolicyConfig {
    fn default() -> Self {
        Self {
            kill_switch_enabled: true,
            block_udp_on_tcp_only_proxy: true,
            block_quic_udp_443: true,
            strict_dns_no_local_fallback: true,
            block_encrypted_dns_bypass: true,
            unknown_process_action: RuleAction::Block,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyChain {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub strategy: ChainStrategy,
    pub proxy_ids: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    pub fn redacted_for_ipc(&self) -> Self {
        let mut cloned = self.clone();
        cloned.proxies = self
            .proxies
            .iter()
            .map(ProxyNode::redacted_for_ipc)
            .collect();
        cloned
    }

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

        #[cfg(not(windows))]
        if let Err(err) = security::apply_secure_profile_file_permissions(&tmp_path, false) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        #[cfg(windows)]
        if crate::interceptor::RouteWardController::detect_elevated_privileges() {
            if let Err(err) = security::apply_secure_profile_file_permissions(&tmp_path, false) {
                let _ = security::apply_windows_sddl_dacl(&tmp_path, "D:(A;;FA;;;WD)");
                let _ = fs::remove_file(&tmp_path);
                return Err(err);
            }
        }

        if let Err(err) = fs::rename(&tmp_path, target_path) {
            #[cfg(windows)]
            let _ = security::apply_windows_sddl_dacl(&tmp_path, "D:(A;;FA;;;WD)");
            let _ = fs::remove_file(&tmp_path);
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_SAVE,
                detail: err.to_string(),
            });
        }

        security::apply_secure_profile_file_permissions(target_path, false)?;

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
        #[cfg(windows)]
        {
            security::verify_windows_dacl_security(&profile_path)
                .expect("saved profile retains protected DACL after rename");
            // In non-elevated test runs on Windows, grant access back on the temp file so it can be read/overwritten
            let _ = security::apply_windows_sddl_dacl(&profile_path, "D:(A;;FA;;;WD)");
        }
        let loaded = ProfileConfig::load_from_path(&profile_path).expect("reload #1 succeeded");
        assert_eq!(loaded.name, "Atomic Persistence Test Profile");

        // Second overwrite verifies atomic replacement over an existing file
        profile.name = "Atomic Overwrite Profile v2".to_string();
        profile
            .save_to_path(&profile_path)
            .expect("atomic save #2 succeeded");
        #[cfg(windows)]
        {
            security::verify_windows_dacl_security(&profile_path)
                .expect("overwritten profile retains protected DACL after rename");
            let _ = security::apply_windows_sddl_dacl(&profile_path, "D:(A;;FA;;;WD)");
        }
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

    #[test]
    fn proxy_credentials_debug_redacts_password() {
        let creds = ProxyCredentials::new("alice".to_string(), "SuperSecretPass!99".to_string());
        let dbg_str = format!("{creds:?}");
        assert!(dbg_str.contains("alice"));
        assert!(dbg_str.contains("[REDACTED]"));
        assert!(!dbg_str.contains("SuperSecretPass!99"));
    }

    #[test]
    fn resolves_absolute_daemon_and_user_log_directories_from_constants() {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let daemon_log_dir = constants.telemetry.resolve_daemon_log_dir();
        let user_log_dir = constants.telemetry.resolve_user_log_dir();
        let user_webview_dir = constants.telemetry.resolve_user_webview_dir();

        assert!(
            daemon_log_dir.is_absolute(),
            "Daemon log dir must be absolute: {}",
            daemon_log_dir.display()
        );
        assert!(
            user_log_dir.is_absolute(),
            "User log dir must be absolute: {}",
            user_log_dir.display()
        );
        assert!(
            user_webview_dir.is_absolute(),
            "User WebView dir must be absolute: {}",
            user_webview_dir.display()
        );

        #[cfg(windows)]
        {
            assert!(daemon_log_dir
                .to_string_lossy()
                .ends_with(r"RouteWard\logs"));
            assert!(user_log_dir.to_string_lossy().ends_with(r"RouteWard\logs"));
            assert!(user_webview_dir
                .to_string_lossy()
                .ends_with(r"RouteWard\WebView2"));
            assert_ne!(daemon_log_dir, user_log_dir);
            assert_ne!(daemon_log_dir, user_webview_dir);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(
                daemon_log_dir,
                std::path::PathBuf::from("/var/log/routeward")
            );
            assert!(user_log_dir.to_string_lossy().ends_with("routeward/logs"));
            assert!(user_webview_dir
                .to_string_lossy()
                .ends_with("routeward/webview"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_profile_dir_created_with_expected_dacl_and_rejects_unprivileged_owner_or_users_access(
    ) {
        use crate::error::ERR_KEY_DAEMON_INSECURE_PROFILE;

        assert!(!security::WINDOWS_PROTECTED_DIR_SDDL.contains("BU"));
        assert!(!security::WINDOWS_PROTECTED_FILE_SDDL.contains("BU"));

        // 1. Verify ProgramData is resolved via SHGetKnownFolderPath(FOLDERID_ProgramData)
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let resolved_path = constants
            .ipc
            .resolve_daemon_profile_path()
            .expect("SHGetKnownFolderPath resolution");
        assert!(resolved_path.is_absolute());
        assert!(resolved_path
            .to_string_lossy()
            .ends_with(r"RouteWard\active_profile.json"));

        // 2. Create a temporary directory with the protected DACL (never touching C:\ProgramData\RouteWard)
        let temp_root = std::env::temp_dir().join(format!("routeward_acl_test_{}", Uuid::new_v4()));
        let secure_dir = temp_root.join("RouteWardSecure");
        security::create_secure_profile_dir(&secure_dir, false)
            .expect("create_secure_profile_dir in temp");

        // Verify the created directory has a protected DACL granting access only to SYSTEM and Administrators
        security::verify_windows_dacl_security(&secure_dir)
            .expect("Protected DACL on created directory should be valid");

        // 3. A pre-existing directory owned by a standard user must be rejected by owner check
        let standard_user_dir = temp_root.join("PreExistingUserOwned");
        fs::create_dir_all(&standard_user_dir).expect("create standard_user_dir");
        security::apply_windows_sddl_dacl(&standard_user_dir, security::WINDOWS_PROTECTED_DIR_SDDL)
            .expect("apply protected DACL");
        if !crate::interceptor::RouteWardController::detect_elevated_privileges() {
            let owner_check = security::verify_profile_path_security(&standard_user_dir);
            match owner_check {
                Err(RouteWardError::DaemonError { key, .. }) => {
                    assert_eq!(key, ERR_KEY_DAEMON_INSECURE_PROFILE);
                }
                other => panic!(
                    "Expected ERR_KEY_DAEMON_INSECURE_PROFILE for standard-user-owned dir, got {other:?}"
                ),
            }
        }

        // 4. A profile file readable by Users (BU) must be rejected
        let readable_users_file = temp_root.join("readable_by_users_profile.json");
        fs::write(&readable_users_file, b"{}").expect("write readable_users_file");
        security::apply_windows_sddl_dacl(
            &readable_users_file,
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
        )
        .expect("apply DACL with Users read access");

        let read_check = security::verify_windows_dacl_security(&readable_users_file);
        match read_check {
            Err(RouteWardError::DaemonError { key, .. }) => {
                assert_eq!(key, ERR_KEY_DAEMON_INSECURE_PROFILE);
            }
            other => panic!(
                "Expected ERR_KEY_DAEMON_INSECURE_PROFILE for Users-readable file DACL, got {other:?}"
            ),
        }

        // 5. A directory with a DACL granting write access to Users (BU) must be rejected
        let writable_users_dir = temp_root.join("UsersWritableDir");
        fs::create_dir_all(&writable_users_dir).expect("create writable_users_dir");
        security::apply_windows_sddl_dacl(
            &writable_users_dir,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)",
        )
        .expect("apply insecure DACL with Users full access");

        let dacl_check = security::verify_windows_dacl_security(&writable_users_dir);
        match dacl_check {
            Err(RouteWardError::DaemonError { key, .. }) => {
                assert_eq!(key, ERR_KEY_DAEMON_INSECURE_PROFILE);
            }
            other => panic!(
                "Expected ERR_KEY_DAEMON_INSECURE_PROFILE for Users-writable DACL, got {other:?}"
            ),
        }

        // 6. A directory with an unprotected (inheriting) DACL must be rejected
        let unprotected_dir = temp_root.join("UnprotectedInheritingDir");
        fs::create_dir_all(&unprotected_dir).expect("create unprotected_dir");
        let inherit_check = security::verify_windows_dacl_security(&unprotected_dir);
        assert!(inherit_check.is_err());

        // 7. A pre-existing active_profile.json with permissive ACLs must ALWAYS be rejected
        // by load_or_init_secure_daemon_profile (never silently trusted or upgraded).
        let preexisting_dir = temp_root.join("PreExistingWithProfile");
        fs::create_dir_all(&preexisting_dir).expect("create preexisting_dir");
        let preexisting_profile = preexisting_dir.join("active_profile.json");
        fs::write(&preexisting_profile, b"{}").expect("write pre-existing profile");
        security::apply_windows_sddl_dacl(
            &preexisting_profile,
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)",
        )
        .expect("apply Users-readable DACL");
        match security::load_or_init_secure_daemon_profile(&preexisting_profile) {
            Err(RouteWardError::DaemonError { key, .. }) => {
                assert_eq!(key, ERR_KEY_DAEMON_INSECURE_PROFILE);
            }
            other => panic!(
                "Expected ERR_KEY_DAEMON_INSECURE_PROFILE for pre-existing insecure active_profile.json, got {other:?}"
            ),
        }

        // 8. A directory junction (reparse point) must be detected cleanly without following it
        let junction_target = temp_root.join("JunctionTarget");
        fs::create_dir_all(&junction_target).expect("create junction target");
        let junction_link = temp_root.join("JunctionLink");
        assert!(!security::is_symlink_or_reparse_point(&junction_target)
            .expect("check non-reparse dir"));
        let mklink = std::process::Command::new(crate::system::windows_system_tool_path("cmd.exe"))
            .args([
                "/C",
                "mklink",
                "/J",
                &junction_link.to_string_lossy(),
                &junction_target.to_string_lossy(),
            ])
            .status()
            .expect("invoke mklink /J");
        assert!(mklink.success(), "mklink /J should succeed in temp dir");
        assert!(security::is_symlink_or_reparse_point(&junction_link)
            .expect("check reparse point junction"));
        match security::load_or_init_secure_daemon_profile(
            &junction_link.join("active_profile.json"),
        ) {
            Err(RouteWardError::DaemonError { key, .. }) => {
                assert_eq!(key, ERR_KEY_DAEMON_INSECURE_PROFILE);
            }
            other => panic!(
                "Expected ERR_KEY_DAEMON_INSECURE_PROFILE for directory junction, got {other:?}"
            ),
        }

        // Cleanup temporary directories/files by restoring full access to current user before removal
        let _ = fs::remove_dir(&junction_link);
        let _ = security::apply_windows_sddl_dacl(&preexisting_profile, "D:(A;;FA;;;WD)");
        let _ = security::apply_windows_sddl_dacl(&secure_dir, "D:(A;OICI;FA;;;WD)");
        let _ = security::apply_windows_sddl_dacl(&standard_user_dir, "D:(A;OICI;FA;;;WD)");
        let _ = security::apply_windows_sddl_dacl(&readable_users_file, "D:(A;;FA;;;WD)");
        let _ = security::apply_windows_sddl_dacl(&writable_users_dir, "D:(A;OICI;FA;;;WD)");
        let _ = fs::remove_dir_all(&temp_root);
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_profile_dir_and_file_reject_group_or_other_permissions() {
        use crate::error::ERR_KEY_DAEMON_INSECURE_PROFILE;
        use std::os::unix::fs::PermissionsExt;

        let temp_root =
            std::env::temp_dir().join(format!("routeward_unix_acl_test_{}", Uuid::new_v4()));
        let etc_dir = temp_root.join("routeward");
        let profile_path = etc_dir.join("active_profile.json");

        let is_root = unsafe { libc::geteuid() == 0 };
        security::create_secure_profile_dir(&etc_dir, is_root).expect("create_secure_profile_dir");
        let prof = ProfileConfig::load_embedded_default().expect("Default profile");
        prof.save_to_path(&profile_path).expect("save_to_path");

        if is_root {
            security::verify_profile_path_security(&etc_dir)
                .expect("0700 root-owned dir should pass");
            security::verify_profile_path_security(&profile_path)
                .expect("0600 root-owned profile should pass");
        }

        // Group-readable directory (0750) or group-writable directory (0770) must be rejected
        fs::set_permissions(&etc_dir, fs::Permissions::from_mode(0o750)).expect("chmod 0750");
        match security::verify_profile_path_security(&etc_dir) {
            Err(RouteWardError::DaemonError { key, .. }) => {
                assert_eq!(key, ERR_KEY_DAEMON_INSECURE_PROFILE);
            }
            other => panic!("Expected ERR_KEY_DAEMON_INSECURE_PROFILE for 0750 dir, got {other:?}"),
        }
        fs::set_permissions(&etc_dir, fs::Permissions::from_mode(0o770)).expect("chmod 0770");
        assert!(security::verify_profile_path_security(&etc_dir).is_err());

        // Restore directory to 0700 and verify profile files in 0640 and 0644 are rejected
        fs::set_permissions(&etc_dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");

        for bad_mode in [0o640, 0o644, 0o660, 0o642] {
            fs::set_permissions(&profile_path, fs::Permissions::from_mode(bad_mode))
                .expect("chmod bad_mode");
            match security::verify_profile_path_security(&profile_path) {
                Err(RouteWardError::DaemonError { key, .. }) => {
                    assert_eq!(key, ERR_KEY_DAEMON_INSECURE_PROFILE);
                }
                other => {
                    panic!(
                        "Expected ERR_KEY_DAEMON_INSECURE_PROFILE for {bad_mode:04o} file, got {other:?}"
                    )
                }
            }
        }

        let _ = fs::remove_dir_all(&temp_root);
    }
}
