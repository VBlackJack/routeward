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

#[cfg(not(target_os = "linux"))]
use crate::error::ERR_KEY_INTERCEPTOR_DRIVER;
use crate::error::{RouteWardError, RouteWardResult};
#[cfg(target_os = "linux")]
use crate::error::{
    ERR_KEY_INTERCEPTOR_NFT_FAILED, ERR_KEY_INTERCEPTOR_NFT_MISSING, ERR_KEY_INTERCEPTOR_NOT_ROOT,
    ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT,
};
use crate::interceptor::backend::Interceptor;
use crate::interceptor::RouteWardController;
use crate::telemetry::{LogLevel, TelemetryHub};
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const BACKEND_NAME: &str = "nftables";
const COMPONENT_NFTABLES: &str = "NftablesInterceptor";
const AF_INET_U16: u16 = 2;
const AF_INET6_U16: u16 = 10;
const DEFAULT_TPROXY_FWMARK: u32 = 21080;

/// Policy routing and `TPROXY` parameters loaded from `SystemConstants.network`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TproxyRoutingSpec {
    pub fwmark: u32,
    pub route_table: u32,
    pub rule_priority: u32,
    pub tproxy_port: u16,
}

struct NftActiveState {
    nft_binary: String,
    ip_binary: String,
    table_name: String,
    tproxy_spec: TproxyRoutingSpec,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ipv6_tproxy_active: bool,
    watchdog_stdin: Option<ChildStdin>,
    watchdog_child: Option<Child>,
    telemetry: TelemetryHub,
}

/// Linux transparent IPv4 TCP interceptor backed by a dedicated `nftables` table
/// (`table ip <table_name>`) and a pipe-linked fail-open watchdog process.
pub struct NftablesInterceptor {
    active: Arc<AtomicBool>,
    state: Mutex<Option<NftActiveState>>,
}

impl Default for NftablesInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl NftablesInterceptor {
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(None),
        }
    }

    /// Generates the dedicated IPv4 `nftables` ruleset for `nft -f -`.
    pub fn build_nft_table_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        Self::build_nft_table_ruleset_with_dns(
            table_name,
            chain_name,
            fwmark,
            relay_port,
            10853,
            53,
            853,
            true,
            upstream_endpoints,
        )
    }

    /// Generates the dedicated IPv4 `nftables` ruleset including DNS port 53 redirection
    /// to `dns_listen_port` and optional encrypted DNS bypass (port 853) blocking.
    #[allow(clippy::too_many_arguments)]
    pub fn build_nft_table_ruleset_with_dns(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        block_encrypted_dns: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        Self::build_nft_table_ruleset_full(
            table_name,
            chain_name,
            fwmark,
            relay_port,
            dns_listen_port,
            10854,
            dns_standard_port,
            dot_port,
            443,
            5353,
            5355,
            137,
            block_encrypted_dns,
            true,
            upstream_endpoints,
        )
    }

    /// Generates the dedicated IPv4 `nftables` ruleset including:
    /// - DNS port 53 (UDP and TCP) redirection to `dns_listen_port`
    /// - Outbound UDP marking (`tproxy_fwmark`) in `route_output` and `TPROXY` interception in `prerouting`
    ///   on `127.0.0.1:<local_name_inspect_port>` (`10854`), covering general UDP as well as mDNS (`5353`)
    ///   and LLMNR (`5355`) without source port rewriting
    /// - optional DoT/DoQ (`UDP 853`) and QUIC (`UDP 443`) `reject` (ICMPv4 Port Unreachable)
    /// - NetBIOS-NS (`UDP 137`) drop toward non-local/public IPv4 addresses
    #[allow(clippy::too_many_arguments)]
    pub fn build_nft_table_ruleset_full(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        local_name_inspect_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        quic_port: u16,
        mdns_port: u16,
        llmnr_port: u16,
        netbios_ns_port: u16,
        block_encrypted_dns: bool,
        block_quic_udp_443: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        Self::build_nft_table_ruleset_with_tproxy(
            table_name,
            chain_name,
            fwmark,
            DEFAULT_TPROXY_FWMARK,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            block_encrypted_dns,
            block_quic_udp_443,
            upstream_endpoints,
        )
    }

    /// Generates the dedicated IPv4 `nftables` ruleset with explicit `tproxy_fwmark`.
    #[allow(clippy::too_many_arguments)]
    pub fn build_nft_table_ruleset_with_tproxy(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        tproxy_fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        local_name_inspect_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        quic_port: u16,
        mdns_port: u16,
        llmnr_port: u16,
        netbios_ns_port: u16,
        block_encrypted_dns: bool,
        block_quic_udp_443: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        let mut script = String::with_capacity(1536);
        script.push_str(&format!("table ip {table_name} {{\n"));
        script.push_str(&format!("    chain {chain_name} {{\n"));
        script.push_str("        type nat hook output priority -100; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip daddr 127.0.0.0/8 return\n");
        script.push_str(&format!(
            "        udp dport {dns_standard_port} redirect to :{dns_listen_port}\n"
        ));
        script.push_str(&format!(
            "        tcp dport {dns_standard_port} redirect to :{dns_listen_port}\n"
        ));
        for (ip, port) in upstream_endpoints {
            if !ip.is_loopback() {
                script.push_str(&format!("        ip daddr {ip} tcp dport {port} return\n"));
            }
        }
        script.push_str(&format!(
            "        tcp dport 1-65535 redirect to :{relay_port}\n"
        ));
        script.push_str("    }\n");

        script.push_str("    chain route_output {\n");
        script.push_str("        type route hook output priority -150; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip daddr 127.0.0.0/8 return\n");
        script.push_str(&format!("        udp dport {dns_standard_port} return\n"));
        if block_encrypted_dns {
            script.push_str(&format!("        udp dport {dot_port} return\n"));
        }
        if block_quic_udp_443 {
            script.push_str(&format!("        udp dport {quic_port} return\n"));
        }
        script.push_str(&format!("        udp dport {netbios_ns_port} return\n"));
        for (ip, port) in upstream_endpoints {
            if !ip.is_loopback() {
                script.push_str(&format!("        ip daddr {ip} udp dport {port} return\n"));
            }
        }
        script.push_str(&format!(
            "        ip daddr {{ 224.0.0.0/4, 255.255.255.255 }} udp dport != {{ {mdns_port}, {llmnr_port} }} return\n"
        ));
        script.push_str(&format!(
            "        meta l4proto udp meta mark set {tproxy_fwmark}\n"
        ));
        script.push_str("    }\n");

        script.push_str("    chain prerouting {\n");
        script.push_str("        type filter hook prerouting priority -150; policy accept;\n");
        script.push_str(&format!(
            "        meta mark {tproxy_fwmark} meta l4proto udp tproxy to 127.0.0.1:{local_name_inspect_port} accept\n"
        ));
        script.push_str("    }\n");

        script.push_str("    chain filter_output {\n");
        script.push_str("        type filter hook output priority 0; policy accept;\n");
        script.push_str(&format!(
            "        meta mark {fwmark} ip daddr 198.18.0.0/15 drop\n"
        ));
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip daddr 127.0.0.0/8 return\n");
        if block_encrypted_dns {
            script.push_str(&format!("        udp dport {dot_port} reject\n"));
        }
        if block_quic_udp_443 {
            script.push_str(&format!("        udp dport {quic_port} reject\n"));
        }
        script.push_str(&format!(
            "        udp dport {netbios_ns_port} ip daddr != {{ 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }} drop\n"
        ));
        script.push_str(&format!(
            "        meta mark != {tproxy_fwmark} ip daddr 198.18.0.0/15 drop\n"
        ));
        script.push_str("    }\n");
        script.push_str("}\n");
        script
    }

    /// Generates the dedicated IPv6 `nftables` ruleset (`table ip6 <table_name>`) covering:
    /// - outbound IPv6 TCP transparent NAT redirect (`tcp dport 1-65535 redirect to :relay_port`)
    /// - outbound IPv6 UDP `TPROXY` marking and local prerouting redirection to `[::1]:local_name_inspect_port`
    /// - unconditional blocking of outbound IPv6 DNS (port 53) and DoT (port 853) in `filter_output`
    #[allow(clippy::too_many_arguments)]
    pub fn build_nft_ip6_table_ruleset_with_tproxy(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        tproxy_fwmark: u32,
        relay_port: u16,
        local_name_inspect_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        quic_port: u16,
        mdns_port: u16,
        llmnr_port: u16,
        block_quic_udp_443: bool,
        upstream_v6_endpoints: &[(Ipv6Addr, u16)],
    ) -> String {
        let mut script = String::with_capacity(1536);
        script.push_str(&format!("table ip6 {table_name} {{\n"));
        script.push_str(&format!("    chain {chain_name} {{\n"));
        script.push_str("        type nat hook output priority -100; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip6 daddr ::1 return\n");
        script.push_str(&format!("        tcp dport {dns_standard_port} return\n"));
        script.push_str(&format!("        tcp dport {dot_port} return\n"));
        for (ip, port) in upstream_v6_endpoints {
            if !ip.is_loopback() {
                script.push_str(&format!("        ip6 daddr {ip} tcp dport {port} return\n"));
            }
        }
        script.push_str(&format!(
            "        tcp dport 1-65535 redirect to :{relay_port}\n"
        ));
        script.push_str("    }\n");

        script.push_str("    chain route_output {\n");
        script.push_str("        type route hook output priority -150; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip6 daddr ::1 return\n");
        script.push_str(&format!("        udp dport {dns_standard_port} return\n"));
        script.push_str(&format!("        udp dport {dot_port} return\n"));
        if block_quic_udp_443 {
            script.push_str(&format!("        udp dport {quic_port} return\n"));
        }
        for (ip, port) in upstream_v6_endpoints {
            if !ip.is_loopback() {
                script.push_str(&format!("        ip6 daddr {ip} udp dport {port} return\n"));
            }
        }
        script.push_str(&format!(
            "        ip6 daddr ff00::/8 udp dport != {{ {mdns_port}, {llmnr_port} }} return\n"
        ));
        script.push_str(&format!(
            "        meta l4proto udp meta mark set {tproxy_fwmark}\n"
        ));
        script.push_str("    }\n");

        script.push_str("    chain prerouting {\n");
        script.push_str("        type filter hook prerouting priority -150; policy accept;\n");
        script.push_str(&format!(
            "        meta mark {tproxy_fwmark} meta l4proto udp tproxy ip6 to [::1]:{local_name_inspect_port} accept\n"
        ));
        script.push_str("    }\n");

        script.push_str("    chain filter_output {\n");
        script.push_str("        type filter hook output priority 0; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip6 daddr ::1 return\n");
        script.push_str(&format!("        udp dport {dns_standard_port} reject\n"));
        script.push_str(&format!(
            "        tcp dport {dns_standard_port} reject with tcp reset\n"
        ));
        script.push_str(&format!("        udp dport {dot_port} reject\n"));
        script.push_str(&format!(
            "        tcp dport {dot_port} reject with tcp reset\n"
        ));
        if block_quic_udp_443 {
            script.push_str(&format!("        udp dport {quic_port} reject\n"));
        }
        script.push_str("    }\n");
        script.push_str("}\n");
        script
    }

    /// Generates the dedicated IPv6 `nftables` ruleset (`table ip6 <table_name>`) using
    /// default transparent TCP/UDP relay ports alongside the unconditional IPv6 DNS/DoT guard.
    pub fn build_nft_ip6_table_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        dns_standard_port: u16,
        dot_port: u16,
        _kill_switch_enabled: bool,
        _block_encrypted_dns: bool,
    ) -> Option<String> {
        Some(Self::build_nft_ip6_table_ruleset_with_tproxy(
            table_name,
            chain_name,
            fwmark,
            DEFAULT_TPROXY_FWMARK,
            10810,
            10854,
            dns_standard_port,
            dot_port,
            443,
            5353,
            5355,
            true,
            &[],
        ))
    }

    /// Builds a single atomic `nft -f -` transaction script that replaces both `table ip <table_name>`
    /// and `table ip6 <table_name>` in one kernel commit without any permissive window.
    #[allow(clippy::too_many_arguments)]
    pub fn build_atomic_replace_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        kill_switch_enabled: bool,
        block_encrypted_dns: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        Self::build_atomic_replace_ruleset_full(
            table_name,
            chain_name,
            fwmark,
            relay_port,
            dns_listen_port,
            10854,
            dns_standard_port,
            dot_port,
            443,
            5353,
            5355,
            137,
            kill_switch_enabled,
            block_encrypted_dns,
            true,
            upstream_endpoints,
        )
    }

    /// Builds a single atomic `nft -f -` transaction script with all UDP/QUIC/local-name parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn build_atomic_replace_ruleset_full(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        local_name_inspect_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        quic_port: u16,
        mdns_port: u16,
        llmnr_port: u16,
        netbios_ns_port: u16,
        kill_switch_enabled: bool,
        block_encrypted_dns: bool,
        block_quic_udp_443: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        Self::build_atomic_replace_ruleset_with_tproxy(
            table_name,
            chain_name,
            fwmark,
            DEFAULT_TPROXY_FWMARK,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            kill_switch_enabled,
            block_encrypted_dns,
            block_quic_udp_443,
            upstream_endpoints,
        )
    }

    /// Builds a single atomic `nft -f -` transaction script with explicit `tproxy_fwmark`.
    #[allow(clippy::too_many_arguments)]
    pub fn build_atomic_replace_ruleset_with_tproxy(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        tproxy_fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        local_name_inspect_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        quic_port: u16,
        mdns_port: u16,
        llmnr_port: u16,
        netbios_ns_port: u16,
        kill_switch_enabled: bool,
        block_encrypted_dns: bool,
        block_quic_udp_443: bool,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        let _ = kill_switch_enabled;
        let mut batch = String::with_capacity(2048);
        batch.push_str(&format!("table ip {table_name}\n"));
        batch.push_str(&format!("delete table ip {table_name}\n"));
        batch.push_str(&Self::build_nft_table_ruleset_with_tproxy(
            table_name,
            chain_name,
            fwmark,
            tproxy_fwmark,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            block_encrypted_dns,
            block_quic_udp_443,
            upstream_endpoints,
        ));
        let ip6_script = Self::build_nft_ip6_table_ruleset_with_tproxy(
            table_name,
            chain_name,
            fwmark,
            tproxy_fwmark,
            relay_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            block_quic_udp_443,
            &[],
        );
        batch.push_str(&format!("table ip6 {table_name}\n"));
        batch.push_str(&format!("delete table ip6 {table_name}\n"));
        batch.push_str(&ip6_script);
        batch
    }

    /// Builds an atomic `nft -f -` batch transaction carrying both IPv4 and IPv6 upstream endpoints.
    #[allow(clippy::too_many_arguments)]
    pub fn build_atomic_replace_ruleset_dual_stack(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        tproxy_fwmark: u32,
        relay_port: u16,
        dns_listen_port: u16,
        local_name_inspect_port: u16,
        dns_standard_port: u16,
        dot_port: u16,
        quic_port: u16,
        mdns_port: u16,
        llmnr_port: u16,
        netbios_ns_port: u16,
        kill_switch_enabled: bool,
        block_encrypted_dns: bool,
        block_quic_udp_443: bool,
        upstream_endpoints: &[(IpAddr, u16)],
    ) -> String {
        let up4: Vec<(Ipv4Addr, u16)> = upstream_endpoints
            .iter()
            .filter_map(|(ip, port)| match ip {
                IpAddr::V4(v4) => Some((*v4, *port)),
                IpAddr::V6(_) => None,
            })
            .collect();
        let up6: Vec<(Ipv6Addr, u16)> = upstream_endpoints
            .iter()
            .filter_map(|(ip, port)| match ip {
                IpAddr::V6(v6) => Some((*v6, *port)),
                IpAddr::V4(_) => None,
            })
            .collect();

        let mut batch = String::with_capacity(3072);
        batch.push_str(&format!("table ip {table_name}\n"));
        batch.push_str(&format!("delete table ip {table_name}\n"));
        batch.push_str(&Self::build_nft_table_ruleset_with_tproxy(
            table_name,
            chain_name,
            fwmark,
            tproxy_fwmark,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            block_encrypted_dns,
            block_quic_udp_443,
            &up4,
        ));
        batch.push_str(&format!("table ip6 {table_name}\n"));
        batch.push_str(&format!("delete table ip6 {table_name}\n"));
        batch.push_str(&Self::build_nft_ip6_table_ruleset_with_tproxy(
            table_name,
            chain_name,
            fwmark,
            tproxy_fwmark,
            relay_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            block_quic_udp_443,
            &up6,
        ));
        let _ = kill_switch_enabled;
        batch
    }

    /// Parses a hexadecimal (`0x...`) or decimal `fwmark` token from `ip -4 rule show` output
    /// (stripping any optional `/mask` suffix).
    pub fn parse_fwmark_token(token: &str) -> Option<u32> {
        let head = token.split('/').next()?.trim();
        if let Some(hex) = head.strip_prefix("0x").or_else(|| head.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            head.parse::<u32>().ok()
        }
    }

    /// Inspects `ip -4 rule show` output and returns a descriptive conflict error if `spec.rule_priority`,
    /// `spec.fwmark`, or `spec.route_table` is already in use by any existing policy routing rule.
    pub fn detect_ip_rule_conflict(
        ip_rule_stdout: &str,
        spec: TproxyRoutingSpec,
    ) -> Option<String> {
        for raw_line in ip_rule_stdout.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((prio_str, _rest)) = line.split_once(':') {
                if let Ok(prio) = prio_str.trim().parse::<u32>() {
                    if prio == spec.rule_priority {
                        return Some(format!(
                            "ip rule priority {} is already in use: \"{line}\"",
                            spec.rule_priority
                        ));
                    }
                }
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            let mut idx = 0;
            while idx + 1 < tokens.len() {
                match tokens[idx] {
                    "fwmark" => {
                        if let Some(mark) = Self::parse_fwmark_token(tokens[idx + 1]) {
                            if mark == spec.fwmark {
                                return Some(format!(
                                    "ip rule fwmark {:#x} ({}) is already in use: \"{line}\"",
                                    spec.fwmark, spec.fwmark
                                ));
                            }
                        }
                        idx += 2;
                    }
                    "lookup" | "table" => {
                        if let Ok(tbl) = tokens[idx + 1].parse::<u32>() {
                            if tbl == spec.route_table {
                                return Some(format!(
                                    "ip rule routing table {} is already referenced: \"{line}\"",
                                    spec.route_table
                                ));
                            }
                        }
                        idx += 2;
                    }
                    _ => {
                        idx += 1;
                    }
                }
            }
        }
        None
    }

    /// Inspects `ip -4 route show table <route_table>` output and returns a descriptive conflict error
    /// if the table already contains any routes.
    pub fn detect_ip_route_table_conflict(
        ip_route_stdout: &str,
        route_table: u32,
    ) -> Option<String> {
        for raw_line in ip_route_stdout.lines() {
            let line = raw_line.trim();
            if !line.is_empty() {
                return Some(format!(
                    "routing table {route_table} is not empty: \"{line}\""
                ));
            }
        }
        None
    }

    /// Builds the exact `ip` CLI arguments to install the `TPROXY` `ip rule`.
    pub fn build_ip_rule_add_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-4".to_string(),
            "rule".to_string(),
            "add".to_string(),
            "fwmark".to_string(),
            spec.fwmark.to_string(),
            "lookup".to_string(),
            spec.route_table.to_string(),
            "priority".to_string(),
            spec.rule_priority.to_string(),
        ]
    }

    /// Builds the exact `ip` CLI arguments to remove the `TPROXY` `ip rule`.
    pub fn build_ip_rule_del_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-4".to_string(),
            "rule".to_string(),
            "del".to_string(),
            "fwmark".to_string(),
            spec.fwmark.to_string(),
            "lookup".to_string(),
            spec.route_table.to_string(),
            "priority".to_string(),
            spec.rule_priority.to_string(),
        ]
    }

    /// Builds the exact `ip` CLI arguments to install the local `0.0.0.0/0 dev lo` route in `spec.route_table`.
    pub fn build_ip_route_add_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-4".to_string(),
            "route".to_string(),
            "add".to_string(),
            "local".to_string(),
            "0.0.0.0/0".to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            spec.route_table.to_string(),
        ]
    }

    /// Builds the exact `ip` CLI arguments to remove the local `0.0.0.0/0 dev lo` route from `spec.route_table`.
    pub fn build_ip_route_del_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-4".to_string(),
            "route".to_string(),
            "del".to_string(),
            "local".to_string(),
            "0.0.0.0/0".to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            spec.route_table.to_string(),
        ]
    }

    /// Builds the exact `ip -6` CLI arguments to install the IPv6 `TPROXY` `ip rule`.
    pub fn build_ip6_rule_add_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-6".to_string(),
            "rule".to_string(),
            "add".to_string(),
            "fwmark".to_string(),
            spec.fwmark.to_string(),
            "lookup".to_string(),
            spec.route_table.to_string(),
            "priority".to_string(),
            spec.rule_priority.to_string(),
        ]
    }

    /// Builds the exact `ip -6` CLI arguments to remove the IPv6 `TPROXY` `ip rule`.
    pub fn build_ip6_rule_del_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-6".to_string(),
            "rule".to_string(),
            "del".to_string(),
            "fwmark".to_string(),
            spec.fwmark.to_string(),
            "lookup".to_string(),
            spec.route_table.to_string(),
            "priority".to_string(),
            spec.rule_priority.to_string(),
        ]
    }

    /// Builds the exact `ip -6` CLI arguments to install the local `::/0 dev lo` route in `spec.route_table`.
    pub fn build_ip6_route_add_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-6".to_string(),
            "route".to_string(),
            "add".to_string(),
            "local".to_string(),
            "::/0".to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            spec.route_table.to_string(),
        ]
    }

    /// Builds the exact `ip -6` CLI arguments to remove the local `::/0 dev lo` route from `spec.route_table`.
    pub fn build_ip6_route_del_args(spec: TproxyRoutingSpec) -> [String; 9] {
        [
            "-6".to_string(),
            "route".to_string(),
            "del".to_string(),
            "local".to_string(),
            "::/0".to_string(),
            "dev".to_string(),
            "lo".to_string(),
            "table".to_string(),
            spec.route_table.to_string(),
        ]
    }

    /// Builds the pipe-linked fail-open watchdog shell command that deletes `table ip/ip6 <table_name>`,
    /// the exact `TPROXY` `ip rule`, and the exact local route on `lo` when the daemon process exits or crashes (`kill -9`).
    pub fn build_watchdog_cleanup_script(
        nft_bin: &str,
        ip_bin: &str,
        table_name: &str,
        spec: TproxyRoutingSpec,
    ) -> String {
        format!(
            "cat >/dev/null; {nft_bin} delete table ip {table_name} >/dev/null 2>&1; {nft_bin} delete table ip6 {table_name} >/dev/null 2>&1; {ip_bin} -4 rule del fwmark {} lookup {} priority {} >/dev/null 2>&1; {ip_bin} -4 route del local 0.0.0.0/0 dev lo table {} >/dev/null 2>&1; {ip_bin} -6 rule del fwmark {} lookup {} priority {} >/dev/null 2>&1; {ip_bin} -6 route del local ::/0 dev lo table {} >/dev/null 2>&1",
            spec.fwmark, spec.route_table, spec.rule_priority, spec.route_table,
            spec.fwmark, spec.route_table, spec.rule_priority, spec.route_table
        )
    }

    /// Removes the exact `TPROXY` `ip rule` and local route on `lo` installed by RouteWard.
    pub fn delete_tproxy_routing(
        ip_binary: &str,
        spec: TproxyRoutingSpec,
        telemetry: &TelemetryHub,
    ) {
        let rule_del_args = Self::build_ip_rule_del_args(spec);
        if let Ok(out) = Command::new(ip_binary)
            .args(&rule_del_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            if out.status.success() {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Removed TPROXY ip rule (fwmark={:#x}, table={}, priority={})",
                        spec.fwmark, spec.route_table, spec.rule_priority
                    ),
                );
            }
        }

        let route_del_args = Self::build_ip_route_del_args(spec);
        if let Ok(out) = Command::new(ip_binary)
            .args(&route_del_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            if out.status.success() {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Removed TPROXY local route (local 0.0.0.0/0 dev lo table {})",
                        spec.route_table
                    ),
                );
            }
        }

        let _ = Command::new(ip_binary)
            .args(Self::build_ip6_rule_del_args(spec))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
        let _ = Command::new(ip_binary)
            .args(Self::build_ip6_route_del_args(spec))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
    }

    #[cfg(target_os = "linux")]
    fn check_and_install_tproxy_routing(
        ip_binary: &str,
        spec: TproxyRoutingSpec,
        telemetry: &TelemetryHub,
        i18n: &crate::i18n::I18nRegistry,
    ) -> RouteWardResult<()> {
        let rule_show = Command::new(ip_binary)
            .args(["-4", "rule", "show"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("Failed to execute {ip_binary} -4 rule show: {err}"),
            })?;
        if !rule_show.status.success() {
            let stderr = String::from_utf8_lossy(&rule_show.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("{ip_binary} -4 rule show failed: {stderr}"),
            });
        }
        let rule_stdout = String::from_utf8_lossy(&rule_show.stdout);
        if let Some(conflict) = Self::detect_ip_rule_conflict(&rule_stdout, spec) {
            let detail = format!(
                "{}: {conflict}",
                i18n.t(ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT)
            );
            telemetry.push_log(LogLevel::Error, COMPONENT_NFTABLES, detail.clone());
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT,
                detail,
            });
        }

        let route_show = Command::new(ip_binary)
            .args([
                "-4",
                "route",
                "show",
                "table",
                &spec.route_table.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!(
                    "Failed to execute {ip_binary} -4 route show table {}: {err}",
                    spec.route_table
                ),
            })?;
        if route_show.status.success() {
            let route_stdout = String::from_utf8_lossy(&route_show.stdout);
            if let Some(conflict) =
                Self::detect_ip_route_table_conflict(&route_stdout, spec.route_table)
            {
                let detail = format!(
                    "{}: {conflict}",
                    i18n.t(ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT)
                );
                telemetry.push_log(LogLevel::Error, COMPONENT_NFTABLES, detail.clone());
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT,
                    detail,
                });
            }
        }

        let rule_add_args = Self::build_ip_rule_add_args(spec);
        let rule_add_out = Command::new(ip_binary)
            .args(&rule_add_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("Failed to execute {ip_binary} rule add: {err}"),
            })?;
        if !rule_add_out.status.success() {
            let stderr = String::from_utf8_lossy(&rule_add_out.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("{ip_binary} -4 rule add failed: {stderr}"),
            });
        }

        let route_add_args = Self::build_ip_route_add_args(spec);
        let route_add_out = Command::new(ip_binary)
            .args(&route_add_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        match route_add_out {
            Ok(out) if out.status.success() => {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Installed TPROXY policy routing (fwmark={:#x}, table={}, priority={}, tproxy_port={})",
                        spec.fwmark, spec.route_table, spec.rule_priority, spec.tproxy_port
                    ),
                );
                // Best-effort IPv6 TPROXY routing: install ip -6 rule & local ::/0 route if IPv6 is enabled on kernel
                let ip6_rule_ok = Command::new(ip_binary)
                    .args(Self::build_ip6_rule_add_args(spec))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ip6_rule_ok {
                    let ip6_route_ok = Command::new(ip_binary)
                        .args(Self::build_ip6_route_add_args(spec))
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if !ip6_route_ok {
                        let _ = Command::new(ip_binary)
                            .args(Self::build_ip6_rule_del_args(spec))
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .output();
                        telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_NFTABLES,
                            format!(
                                "IPv6 TPROXY route (local ::/0 table {}) unavailable on this kernel; continuing with IPv4 TPROXY",
                                spec.route_table
                            ),
                        );
                    }
                }
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let _ = Command::new(ip_binary)
                    .args(Self::build_ip_rule_del_args(spec))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .output();
                Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!(
                        "{ip_binary} -4 route add local 0.0.0.0/0 dev lo table {} failed: {stderr}",
                        spec.route_table
                    ),
                })
            }
            Err(err) => {
                let _ = Command::new(ip_binary)
                    .args(Self::build_ip_rule_del_args(spec))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .output();
                Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed invoking {ip_binary} route add: {err}"),
                })
            }
        }
    }

    /// Deletes the dedicated `nftables` tables (`ip` and `ip6`) if they exist.
    pub fn delete_nft_table(
        nft_binary: &str,
        table_name: &str,
        telemetry: &TelemetryHub,
    ) -> RouteWardResult<()> {
        for family in ["ip", "ip6"] {
            match Command::new(nft_binary)
                .args(["delete", "table", family, table_name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
            {
                Ok(out) if out.status.success() => {
                    telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_NFTABLES,
                        format!("Removed nftables table \"{family} {table_name}\""),
                    );
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let trimmed = stderr.trim();
                    if trimmed.contains("No such file or directory")
                        || trimmed.contains("does not exist")
                    {
                        telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_NFTABLES,
                            format!(
                                "nftables table \"{family} {table_name}\" was already absent during cleanup"
                            ),
                        );
                    } else {
                        telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_NFTABLES,
                            format!(
                                "Could not delete nftables table \"{family} {table_name}\" (exit={:?}): {trimmed}",
                                out.status.code()
                            ),
                        );
                    }
                }
                Err(err) => {
                    telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_NFTABLES,
                        format!(
                            "Failed invoking {nft_binary} to delete table \"{family} {table_name}\": {err}"
                        ),
                    );
                }
            }
        }
        Ok(())
    }

    /// Pure parser converting raw `sockaddr_in` fields (network byte order) into `SocketAddrV4`.
    pub fn parse_sockaddr_in_fields(
        sin_family: u16,
        sin_port_be: u16,
        sin_addr_be: u32,
        relay_port: u16,
    ) -> Option<SocketAddrV4> {
        if sin_family != AF_INET_U16 {
            return None;
        }
        let port = u16::from_be(sin_port_be);
        let ip = Ipv4Addr::from(u32::from_be(sin_addr_be));
        if port == 0 {
            return None;
        }
        // Reject direct unredirected connections whose original destination is the local relay itself
        if ip.is_loopback() && port == relay_port {
            return None;
        }
        Some(SocketAddrV4::new(ip, port))
    }

    /// Queries `getsockopt(SOL_IP, SO_ORIGINAL_DST)` on an accepted Linux TCP stream.
    #[cfg(target_os = "linux")]
    pub fn query_original_dst(
        stream: &tokio::net::TcpStream,
        relay_port: u16,
    ) -> Option<SocketAddrV4> {
        use std::os::fd::AsRawFd;

        let fd = stream.as_raw_fd();
        let mut raw_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut raw_addr as *mut libc::sockaddr_in as *mut libc::c_void,
                &mut addr_len,
            )
        };
        if ret != 0 {
            return None;
        }

        Self::parse_sockaddr_in_fields(
            raw_addr.sin_family,
            raw_addr.sin_port,
            raw_addr.sin_addr.s_addr,
            relay_port,
        )
    }

    #[cfg(not(target_os = "linux"))]
    pub fn query_original_dst(
        _stream: &tokio::net::TcpStream,
        _relay_port: u16,
    ) -> Option<SocketAddrV4> {
        None
    }

    /// Parses raw `sockaddr_in6` fields returned by `IP6T_SO_ORIGINAL_DST` and rejects
    /// loopback connections targeting `relay_port` directly without NAT redirection.
    pub fn parse_sockaddr_in6_fields(
        sin6_family: u16,
        sin6_port_be: u16,
        sin6_addr: [u8; 16],
        relay_port: u16,
    ) -> Option<SocketAddrV6> {
        if sin6_family != AF_INET6_U16 {
            return None;
        }
        let port = u16::from_be(sin6_port_be);
        if port == 0 {
            return None;
        }
        let ip = Ipv6Addr::from(sin6_addr);
        if ip.is_loopback() && port == relay_port {
            return None;
        }
        Some(SocketAddrV6::new(ip, port, 0, 0))
    }

    /// Queries `SO_ORIGINAL_DST` (IPv4) or `IP6T_SO_ORIGINAL_DST` (IPv6) on an accepted Linux TCP stream.
    #[cfg(target_os = "linux")]
    pub fn query_original_dst_any(
        stream: &tokio::net::TcpStream,
        relay_port: u16,
    ) -> Option<SocketAddr> {
        if let Some(v4) = Self::query_original_dst(stream, relay_port) {
            return Some(SocketAddr::V4(v4));
        }
        use std::os::fd::AsRawFd;

        let fd = stream.as_raw_fd();
        let mut raw_addr6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IP6T_SO_ORIGINAL_DST,
                &mut raw_addr6 as *mut libc::sockaddr_in6 as *mut libc::c_void,
                &mut addr_len,
            )
        };
        if ret != 0 {
            return None;
        }

        Self::parse_sockaddr_in6_fields(
            raw_addr6.sin6_family,
            raw_addr6.sin6_port,
            raw_addr6.sin6_addr.s6_addr,
            relay_port,
        )
        .map(SocketAddr::V6)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn query_original_dst_any(
        _stream: &tokio::net::TcpStream,
        _relay_port: u16,
    ) -> Option<SocketAddr> {
        None
    }

    /// Immediately resets (`TCP RST`) an accepted connection via `SO_LINGER(1, 0)` and closes it.
    #[cfg(target_os = "linux")]
    pub fn reset_and_close_tcp_stream(stream: tokio::net::TcpStream) {
        use std::os::fd::AsRawFd;

        let fd = stream.as_raw_fd();
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
        drop(stream);
    }

    #[cfg(not(target_os = "linux"))]
    pub fn reset_and_close_tcp_stream(stream: tokio::net::TcpStream) {
        drop(stream);
    }

    #[cfg(target_os = "linux")]
    pub fn enable_udp_pktinfo(sock: &tokio::net::UdpSocket) {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enable_udp_pktinfo(_sock: &tokio::net::UdpSocket) {}

    #[cfg(target_os = "linux")]
    pub async fn recv_udp_with_local_ip(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr, Option<Ipv4Addr>)> {
        use std::os::fd::AsRawFd;
        sock.async_io(tokio::io::Interest::READABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut cmsg_space = [0u8; 64];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_addr as *mut libc::sockaddr_in as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space.len();

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let peer_ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
            let peer_port = u16::from_be(src_addr.sin_port);
            let peer = std::net::SocketAddr::V4(SocketAddrV4::new(peer_ip, peer_port));

            let mut local_dst_ip: Option<Ipv4Addr> = None;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::IPPROTO_IP
                        && (*cmsg).cmsg_type == libc::IP_PKTINFO
                    {
                        let pktinfo_ptr = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                        let pktinfo = std::ptr::read_unaligned(pktinfo_ptr);
                        local_dst_ip = Some(Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr)));
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, peer, local_dst_ip))
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_udp_with_local_ip(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr, Option<Ipv4Addr>)> {
        let (len, peer) = sock.recv_from(buf).await?;
        Ok((len, peer, None))
    }

    #[cfg(target_os = "linux")]
    pub async fn send_udp_from_local_ip(
        sock: &tokio::net::UdpSocket,
        payload: &[u8],
        peer: std::net::SocketAddr,
        local_src_ip: Option<Ipv4Addr>,
    ) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let std::net::SocketAddr::V4(peer_v4) = peer else {
            return sock.send_to(payload, peer).await;
        };
        let Some(src_ip) = local_src_ip else {
            return sock.send_to(payload, peer).await;
        };

        sock.async_io(tokio::io::Interest::WRITABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            };
            let mut dst_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            dst_addr.sin_family = libc::AF_INET as libc::sa_family_t;
            dst_addr.sin_port = peer_v4.port().to_be();
            dst_addr.sin_addr = libc::in_addr {
                s_addr: u32::from(*peer_v4.ip()).to_be(),
            };

            let cmsg_len =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) }
                    as usize;
            let mut cmsg_space = vec![0u8; cmsg_len];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut dst_addr as *mut libc::sockaddr_in as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_len;

            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if !cmsg.is_null() {
                    (*cmsg).cmsg_level = libc::IPPROTO_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
                    let pktinfo = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from(src_ip).to_be(),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    std::ptr::write_unaligned(
                        libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo,
                        pktinfo,
                    );
                }
            }

            let n = unsafe { libc::sendmsg(fd, &msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn send_udp_from_local_ip(
        sock: &tokio::net::UdpSocket,
        payload: &[u8],
        peer: std::net::SocketAddr,
        _local_src_ip: Option<Ipv4Addr>,
    ) -> std::io::Result<usize> {
        sock.send_to(payload, peer).await
    }

    /// Configures a Linux UDP listener socket with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR`
    /// so it can receive `TPROXY`-intercepted datagrams and recover their original destination IPv4/port.
    #[cfg(target_os = "linux")]
    pub fn enable_udp_tproxy_options(sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        unsafe {
            if libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_RECVORIGDSTADDR,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enable_udp_tproxy_options(_sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
        Ok(())
    }

    /// Receives a UDP datagram on a `TPROXY` listener socket and extracts `(len, client_addr, orig_dst)`
    /// from the ancillary `IP_ORIGDSTADDR` control message.
    #[cfg(target_os = "linux")]
    pub async fn recv_udp_tproxy_orig_dst(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddrV4, Option<SocketAddrV4>)> {
        use std::os::fd::AsRawFd;
        sock.async_io(tokio::io::Interest::READABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut cmsg_space = [0u8; 128];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_addr as *mut libc::sockaddr_in as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space.len();

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let peer_ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
            let peer_port = u16::from_be(src_addr.sin_port);
            let client_addr = SocketAddrV4::new(peer_ip, peer_port);

            let mut orig_dst: Option<SocketAddrV4> = None;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_IP
                        && (*cmsg).cmsg_type == libc::IP_ORIGDSTADDR
                    {
                        let data_ptr = libc::CMSG_DATA(cmsg);
                        let data_slice = std::slice::from_raw_parts(
                            data_ptr,
                            std::mem::size_of::<libc::sockaddr_in>(),
                        );
                        orig_dst =
                            crate::interceptor::nat::parse_ipv4_origdstaddr_bytes(data_slice);
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, client_addr, orig_dst))
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_udp_tproxy_orig_dst(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddrV4, Option<SocketAddrV4>)> {
        let (len, peer) = sock.recv_from(buf).await?;
        let client_v4 = match peer {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => SocketAddrV4::new(Ipv4Addr::LOCALHOST, peer.port()),
        };
        Ok((len, client_v4, None))
    }

    /// Enables `IPV6_TRANSPARENT` and `IPV6_RECVORIGDSTADDR` on a bound Linux IPv6 UDP TPROXY socket
    /// (`IPV6_V6ONLY` must already be configured prior to `bind()`).
    #[cfg(target_os = "linux")]
    pub fn enable_udp_tproxy_v6_options(sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        unsafe {
            if libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IPV6_TRANSPARENT,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enable_udp_tproxy_v6_options(_sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
        Ok(())
    }

    /// Receives an IPv6 UDP datagram on a `TPROXY` listener socket and extracts
    /// `(len, client_addr, orig_dst)` from the ancillary `IPV6_ORIGDSTADDR` control message.
    #[cfg(target_os = "linux")]
    pub async fn recv_udp_tproxy_v6_orig_dst(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddrV6, Option<SocketAddrV6>)> {
        use std::os::fd::AsRawFd;
        sock.async_io(tokio::io::Interest::READABLE, || {
            let fd = sock.as_raw_fd();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            let mut cmsg_space = [0u8; 256];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_addr as *mut libc::sockaddr_in6 as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space.len();

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let peer_ip = Ipv6Addr::from(src_addr.sin6_addr.s6_addr);
            let peer_port = u16::from_be(src_addr.sin6_port);
            let client_addr = SocketAddrV6::new(
                peer_ip,
                peer_port,
                src_addr.sin6_flowinfo,
                src_addr.sin6_scope_id,
            );

            let mut orig_dst: Option<SocketAddrV6> = None;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_IPV6
                        && (*cmsg).cmsg_type == libc::IPV6_ORIGDSTADDR
                    {
                        let data_ptr = libc::CMSG_DATA(cmsg);
                        let data_slice = std::slice::from_raw_parts(
                            data_ptr,
                            std::mem::size_of::<libc::sockaddr_in6>(),
                        );
                        orig_dst =
                            crate::interceptor::nat::parse_ipv6_origdstaddr_bytes(data_slice);
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, client_addr, orig_dst))
        })
        .await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv_udp_tproxy_v6_orig_dst(
        sock: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddrV6, Option<SocketAddrV6>)> {
        let (len, peer) = sock.recv_from(buf).await?;
        let client_v6 = match peer {
            SocketAddr::V6(v6) => v6,
            SocketAddr::V4(_) => SocketAddrV6::new(Ipv6Addr::LOCALHOST, peer.port(), 0, 0),
        };
        Ok((len, client_v6, None))
    }

    /// Returns `true` if `ip` belongs to the RFC 2544 Fake-IP pool (`198.18.0.0/15`).
    pub fn is_rfc2544_fake_ip(ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 198 && (octets[1] & 0xfe) == 18
    }

    /// Emits a raw IPv4 + UDP datagram (`src -> dst`) using `SOCK_RAW` + `IP_HDRINCL` + `SO_MARK`
    /// so replies to `TPROXY`-intercepted clients (and authorized local LLMNR/mDNS queries) preserve
    /// the exact source IPv4 address and source port without re-triggering `TPROXY`.
    #[cfg(target_os = "linux")]
    pub fn send_raw_ipv4_udp_packet(
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
        fwmark: u32,
    ) -> std::io::Result<usize> {
        if Self::is_rfc2544_fake_ip(*dst.ip()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Final Fake-IP egress guard blocked raw UDP packet to untranslated Fake-IP destination {dst}"
                ),
            ));
        }

        let raw_pkt = crate::interceptor::nat::build_forged_ipv4_udp_reply(
            *src.ip(),
            src.port(),
            *dst.ip(),
            dst.port(),
            payload,
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP payload too large for IPv4 packet",
            )
        })?;

        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        struct RawFdGuard(libc::c_int);
        impl Drop for RawFdGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = libc::close(self.0);
                }
            }
        }
        let _guard = RawFdGuard(fd);

        let one: libc::c_int = 1;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BROADCAST,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if fwmark != 0 {
                let mark: libc::c_uint = fwmark;
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const libc::c_uint as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                );
            }
            if dst.ip().is_multicast() {
                let zero: libc::c_uchar = 0;
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MULTICAST_LOOP,
                    &zero as *const libc::c_uchar as *const libc::c_void,
                    std::mem::size_of::<libc::c_uchar>() as libc::socklen_t,
                );
            }
        }

        let mut dst_sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dst_sin.sin_family = libc::AF_INET as libc::sa_family_t;
        dst_sin.sin_port = dst.port().to_be();
        dst_sin.sin_addr = libc::in_addr {
            s_addr: u32::from(*dst.ip()).to_be(),
        };

        let sent = unsafe {
            libc::sendto(
                fd,
                raw_pkt.as_ptr() as *const libc::c_void,
                raw_pkt.len(),
                0,
                &dst_sin as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(sent as usize)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn send_raw_ipv4_udp_packet(
        _src: SocketAddrV4,
        dst: SocketAddrV4,
        _payload: &[u8],
        _fwmark: u32,
    ) -> std::io::Result<usize> {
        if Self::is_rfc2544_fake_ip(*dst.ip()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Final Fake-IP egress guard blocked raw UDP packet to untranslated Fake-IP destination {dst}"
                ),
            ));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "send_raw_ipv4_udp_packet is only supported on Linux",
        ))
    }

    /// Sends an arbitrary forged IPv6 + UDP packet from `src` to `dst` via a marked raw socket.
    #[cfg(target_os = "linux")]
    pub fn send_raw_ipv6_udp_packet(
        src: SocketAddrV6,
        dst: SocketAddrV6,
        payload: &[u8],
        fwmark: u32,
    ) -> std::io::Result<usize> {
        const LINUX_IPV6_HDRINCL: libc::c_int = 36;
        let raw_pkt = crate::interceptor::nat::build_forged_ipv6_udp_reply(
            *src.ip(),
            src.port(),
            *dst.ip(),
            dst.port(),
            payload,
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP payload too large for IPv6 packet",
            )
        })?;

        let fd = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        struct RawFdGuard(libc::c_int);
        impl Drop for RawFdGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = libc::close(self.0);
                }
            }
        }
        let _guard = RawFdGuard(fd);

        let one: libc::c_int = 1;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                LINUX_IPV6_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if fwmark != 0 {
                let mark: libc::c_uint = fwmark;
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const libc::c_uint as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                );
            }
        }

        let mut dst_sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        dst_sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        dst_sin6.sin6_port = 0;
        dst_sin6.sin6_scope_id = dst.scope_id();
        dst_sin6.sin6_addr = libc::in6_addr {
            s6_addr: dst.ip().octets(),
        };

        let sent = unsafe {
            libc::sendto(
                fd,
                raw_pkt.as_ptr() as *const libc::c_void,
                raw_pkt.len(),
                0,
                &dst_sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn send_raw_ipv6_udp_packet(
        _src: SocketAddrV6,
        _dst: SocketAddrV6,
        _payload: &[u8],
        _fwmark: u32,
    ) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "send_raw_ipv6_udp_packet is only supported on Linux",
        ))
    }
}

impl Interceptor for NftablesInterceptor {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    #[cfg(target_os = "linux")]
    fn start(&self, controller: RouteWardController) -> RouteWardResult<()> {
        use std::io::Write;
        use std::os::unix::process::CommandExt;

        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        // 1. Mandatory root privilege check (Milestone 2 runs as root only)
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            self.active.store(false, Ordering::SeqCst);
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NOT_ROOT,
                detail: controller.i18n.t(ERR_KEY_INTERCEPTOR_NOT_ROOT),
            });
        }

        let net = &controller.constants.network;
        let nft_bin = net.linux_nft_binary.clone();
        let ip_bin = net.linux_ip_binary.clone();
        let table_name = net.linux_nft_table_name.clone();
        let chain_name = net.linux_nft_chain_name.clone();
        let fwmark = net.linux_fwmark;
        let tproxy_spec = TproxyRoutingSpec {
            fwmark: net.linux_tproxy_fwmark,
            route_table: net.linux_tproxy_route_table,
            rule_priority: net.linux_tproxy_rule_priority,
            tproxy_port: net.default_local_name_inspect_port,
        };

        // 2. Verify nft binary is installed and reachable
        match Command::new(&nft_bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                self.active.store(false, Ordering::SeqCst);
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("{nft_bin} --version failed: {stderr}"),
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.active.store(false, Ordering::SeqCst);
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_MISSING,
                    detail: format!(
                        "{}: {}",
                        controller.i18n.t(ERR_KEY_INTERCEPTOR_NFT_MISSING),
                        nft_bin
                    ),
                });
            }
            Err(err) => {
                self.active.store(false, Ordering::SeqCst);
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed to execute {nft_bin}: {err}"),
                });
            }
        }

        // 3. Verify TPROXY ip rule priority, fwmark, and routing table are free, then install them
        if let Err(err) = Self::check_and_install_tproxy_routing(
            &ip_bin,
            tproxy_spec,
            &controller.telemetry,
            &controller.i18n,
        ) {
            self.active.store(false, Ordering::SeqCst);
            return Err(err);
        }

        // 4. Remove any stale tables (`ip` and `ip6`) with the same name before installing fresh rules
        for family in ["ip", "ip6"] {
            let _ = Command::new(&nft_bin)
                .args(["delete", "table", family, &table_name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output();
        }

        // 5. Build and load the dedicated nftables tables via `nft -f -`
        let upstream_endpoints = controller.nat_table.upstream_endpoints();
        let upstream_v4: Vec<(Ipv4Addr, u16)> = upstream_endpoints
            .iter()
            .filter_map(|(ip, port)| match ip {
                IpAddr::V4(v4) => Some((*v4, *port)),
                IpAddr::V6(_) => None,
            })
            .collect();
        let upstream_v6: Vec<(Ipv6Addr, u16)> = upstream_endpoints
            .iter()
            .filter_map(|(ip, port)| match ip {
                IpAddr::V6(v6) => Some((*v6, *port)),
                IpAddr::V4(_) => None,
            })
            .collect();
        let relay_port = net.default_transparent_tcp_port;
        let dns_listen_port = net.default_dns_listen_port;
        let local_name_inspect_port = net.default_local_name_inspect_port;
        let quic_port = net.quic_default_port;
        let mdns_port = net.mdns_standard_port;
        let llmnr_port = net.llmnr_standard_port;
        let netbios_ns_port = net.netbios_ns_standard_port;
        let dns_standard_port = controller.constants.dns.dns_standard_port;
        let dot_port = controller.constants.dns.dns_over_tls_port;
        let (kill_switch_enabled, block_encrypted_dns, block_quic_udp_443) = {
            let prof = controller.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_encrypted_dns_bypass,
                prof.security_policy.block_quic_udp_443,
            )
        };
        let _ = kill_switch_enabled;

        let mut ipv6_tproxy_active = false;
        let ip6_ruleset = Self::build_nft_ip6_table_ruleset_with_tproxy(
            &table_name,
            &chain_name,
            fwmark,
            tproxy_spec.fwmark,
            relay_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            block_quic_udp_443,
            &upstream_v6,
        );
        if let Ok(mut ip6_child) = Command::new(&nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = ip6_child.stdin.take() {
                let _ = stdin.write_all(ip6_ruleset.as_bytes());
            }
            if let Ok(out) = ip6_child.wait_with_output() {
                if out.status.success() {
                    ipv6_tproxy_active = true;
                    controller.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_NFTABLES,
                        format!("Installed nftables IPv6 dual-stack table \"ip6 {table_name}\""),
                    );
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    controller.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_NFTABLES,
                        format!(
                            "Could not install full IPv6 NAT/TPROXY table \"ip6 {table_name}\" ({stderr}); falling back to IPv6 DNS/DoT guard"
                        ),
                    );
                    let fallback_ip6 = format!(
                        "table ip6 {table_name} {{\n    chain {chain_name} {{\n        type filter hook output priority 0; policy accept;\n        meta mark {fwmark} return\n        ip6 daddr ::1 return\n        udp dport {dns_standard_port} reject\n        tcp dport {dns_standard_port} reject with tcp reset\n        udp dport {dot_port} reject\n        tcp dport {dot_port} reject with tcp reset\n    }}\n}}\n"
                    );
                    if let Ok(mut fb_child) = Command::new(&nft_bin)
                        .args(["-f", "-"])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                    {
                        if let Some(mut stdin) = fb_child.stdin.take() {
                            let _ = stdin.write_all(fallback_ip6.as_bytes());
                        }
                        let _ = fb_child.wait();
                    }
                }
            }
        }

        // 6. Spawn pipe-linked fail-open watchdog in its own process group before installing `ip routeward`.
        // If RouteWard dies with SIGKILL (kill -9), the kernel closes watchdog_stdin immediately,
        // `cat` exits on EOF, and both `nft` tables + `ip rule` + `ip route` are cleaned up automatically.
        let watchdog_script =
            Self::build_watchdog_cleanup_script(&nft_bin, &ip_bin, &table_name, tproxy_spec);
        let mut watchdog_stdin = None;
        let mut watchdog_child = None;

        match Command::new("sh")
            .args(["-c", &watchdog_script])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
        {
            Ok(mut child) => {
                let wid = child.id();
                watchdog_stdin = child.stdin.take();
                watchdog_child = Some(child);
                controller.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Started pipe-linked nftables/TPROXY fail-open watchdog (PID={wid}, table=\"ip {table_name}\")"
                    ),
                );
            }
            Err(err) => {
                controller.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_NFTABLES,
                    format!("Could not spawn pipe-linked watchdog for nftables: {err}"),
                );
            }
        }

        *self.state.lock() = Some(NftActiveState {
            nft_binary: nft_bin.clone(),
            ip_binary: ip_bin,
            table_name: table_name.clone(),
            tproxy_spec,
            ipv6_tproxy_active,
            watchdog_stdin,
            watchdog_child,
            telemetry: controller.telemetry.clone(),
        });

        let ruleset = Self::build_nft_table_ruleset_with_tproxy(
            &table_name,
            &chain_name,
            fwmark,
            tproxy_spec.fwmark,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            block_encrypted_dns,
            block_quic_udp_443,
            &upstream_v4,
        );

        let mut apply_child = match Command::new(&nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                self.stop();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Could not spawn {nft_bin} -f -: {err}"),
                });
            }
        };

        if let Some(mut stdin) = apply_child.stdin.take() {
            let _ = stdin.write_all(ruleset.as_bytes());
        }

        let apply_out = match apply_child.wait_with_output() {
            Ok(out) => out,
            Err(err) => {
                self.stop();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed waiting for {nft_bin} -f -: {err}"),
                });
            }
        };

        if !apply_out.status.success() {
            self.stop();
            let stderr = String::from_utf8_lossy(&apply_out.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("nft -f - rejected table \"ip {table_name}\": {stderr}"),
            });
        }

        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_NFTABLES,
            format!(
                "Installed nftables table \"ip {table_name}\" (chain=\"{chain_name}\", fwmark={fwmark:#x}, redirect_port={relay_port}, dns_port={dns_listen_port})"
            ),
        );

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn start(&self, _controller: RouteWardController) -> RouteWardResult<()> {
        Err(RouteWardError::InterceptorError {
            key: ERR_KEY_INTERCEPTOR_DRIVER,
            detail: "nftables backend is only supported on Linux".to_string(),
        })
    }

    #[cfg(target_os = "linux")]
    fn reload(&self, controller: RouteWardController) -> RouteWardResult<()> {
        use std::io::Write;

        if !self.is_active() {
            return Ok(());
        }

        let net = &controller.constants.network;
        let nft_bin = net.linux_nft_binary.clone();
        let ip_bin = net.linux_ip_binary.clone();
        let table_name = net.linux_nft_table_name.clone();
        let chain_name = net.linux_nft_chain_name.clone();
        let fwmark = net.linux_fwmark;
        let tproxy_spec = TproxyRoutingSpec {
            fwmark: net.linux_tproxy_fwmark,
            route_table: net.linux_tproxy_route_table,
            rule_priority: net.linux_tproxy_rule_priority,
            tproxy_port: net.default_local_name_inspect_port,
        };
        let relay_port = net.default_transparent_tcp_port;
        let dns_listen_port = net.default_dns_listen_port;
        let local_name_inspect_port = net.default_local_name_inspect_port;
        let quic_port = net.quic_default_port;
        let mdns_port = net.mdns_standard_port;
        let llmnr_port = net.llmnr_standard_port;
        let netbios_ns_port = net.netbios_ns_standard_port;
        let dns_standard_port = controller.constants.dns.dns_standard_port;
        let dot_port = controller.constants.dns.dns_over_tls_port;
        let upstream_endpoints = controller.nat_table.upstream_endpoints();
        let (kill_switch_enabled, block_encrypted_dns, block_quic_udp_443) = {
            let prof = controller.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_encrypted_dns_bypass,
                prof.security_policy.block_quic_udp_443,
            )
        };

        let (prev_spec, ipv6_tproxy_active) = {
            let guard = self.state.lock();
            (
                guard.as_ref().map(|s| s.tproxy_spec),
                guard
                    .as_ref()
                    .map(|s| s.ipv6_tproxy_active)
                    .unwrap_or(false),
            )
        };
        if let Some(old_spec) = prev_spec {
            if old_spec != tproxy_spec {
                Self::delete_tproxy_routing(&ip_bin, old_spec, &controller.telemetry);
                Self::check_and_install_tproxy_routing(
                    &ip_bin,
                    tproxy_spec,
                    &controller.telemetry,
                    &controller.i18n,
                )?;
                if let Some(ref mut st) = *self.state.lock() {
                    st.tproxy_spec = tproxy_spec;
                }
            }
        }

        let atomic_batch = if ipv6_tproxy_active {
            Self::build_atomic_replace_ruleset_dual_stack(
                &table_name,
                &chain_name,
                fwmark,
                tproxy_spec.fwmark,
                relay_port,
                dns_listen_port,
                local_name_inspect_port,
                dns_standard_port,
                dot_port,
                quic_port,
                mdns_port,
                llmnr_port,
                netbios_ns_port,
                kill_switch_enabled,
                block_encrypted_dns,
                block_quic_udp_443,
                &upstream_endpoints,
            )
        } else {
            let up4: Vec<(Ipv4Addr, u16)> = upstream_endpoints
                .iter()
                .filter_map(|(ip, port)| match ip {
                    IpAddr::V4(v4) => Some((*v4, *port)),
                    IpAddr::V6(_) => None,
                })
                .collect();
            let mut batch = String::with_capacity(2048);
            batch.push_str(&format!("table ip {table_name}\n"));
            batch.push_str(&format!("delete table ip {table_name}\n"));
            batch.push_str(&Self::build_nft_table_ruleset_with_tproxy(
                &table_name,
                &chain_name,
                fwmark,
                tproxy_spec.fwmark,
                relay_port,
                dns_listen_port,
                local_name_inspect_port,
                dns_standard_port,
                dot_port,
                quic_port,
                mdns_port,
                llmnr_port,
                netbios_ns_port,
                block_encrypted_dns,
                block_quic_udp_443,
                &up4,
            ));
            batch.push_str(&format!("table ip6 {table_name}\n"));
            batch.push_str(&format!("delete table ip6 {table_name}\n"));
            batch.push_str(&format!(
                "table ip6 {table_name} {{\n    chain {chain_name} {{\n        type filter hook output priority 0; policy accept;\n        meta mark {fwmark} return\n        ip6 daddr ::1 return\n        udp dport {dns_standard_port} reject\n        tcp dport {dns_standard_port} reject with tcp reset\n        udp dport {dot_port} reject\n        tcp dport {dot_port} reject with tcp reset\n    }}\n}}\n"
            ));
            batch
        };

        let mut apply_child = Command::new(&nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("Could not spawn {nft_bin} -f - for atomic reload: {err}"),
            })?;

        if let Some(mut stdin) = apply_child.stdin.take() {
            let _ = stdin.write_all(atomic_batch.as_bytes());
        }

        let apply_out =
            apply_child
                .wait_with_output()
                .map_err(|err| RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed waiting for {nft_bin} -f - atomic reload: {err}"),
                })?;

        if !apply_out.status.success() {
            let stderr = String::from_utf8_lossy(&apply_out.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!(
                    "nft -f - rejected atomic table reload for \"{table_name}\": {stderr}"
                ),
            });
        }

        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_NFTABLES,
            format!(
                "Atomically replaced nftables tables \"ip {table_name}\" and \"ip6 {table_name}\" (killSwitchEnabled={kill_switch_enabled}, blockEncryptedDnsBypass={block_encrypted_dns})"
            ),
        );

        Ok(())
    }

    fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
        if let Some(mut state) = self.state.lock().take() {
            // Closing the pipe write-end lets the watchdog exit cleanly
            drop(state.watchdog_stdin.take());
            let _ = Self::delete_nft_table(&state.nft_binary, &state.table_name, &state.telemetry);
            Self::delete_tproxy_routing(&state.ip_binary, state.tproxy_spec, &state.telemetry);
            if let Some(mut child) = state.watchdog_child.take() {
                let _ = child.wait();
            }
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

impl Drop for NftablesInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_expected_nft_ruleset_with_fwmark_loopback_and_upstream_exclusions() {
        let upstreams = vec![
            (Ipv4Addr::new(127, 0, 0, 1), 1080),
            (Ipv4Addr::new(192, 168, 31, 10), 1080),
        ];
        let ruleset = NftablesInterceptor::build_nft_table_ruleset(
            "routeward",
            "output",
            21079,
            10810,
            &upstreams,
        );

        assert!(ruleset.contains("table ip routeward {"));
        assert!(ruleset.contains("chain output {"));
        assert!(ruleset.contains("type nat hook output priority -100; policy accept;"));
        assert!(ruleset.contains("meta mark 21079 return"));
        assert!(ruleset.contains("ip daddr 127.0.0.0/8 return"));
        assert!(ruleset.contains("udp dport 53 redirect to :10853"));
        assert!(ruleset.contains("tcp dport 53 redirect to :10853"));
        assert!(!ruleset.contains("udp dport { 5353, 5355 } redirect to :10854"));
        assert!(ruleset.contains("chain route_output {"));
        assert!(ruleset.contains("type route hook output priority -150; policy accept;"));
        assert!(ruleset.contains("ip daddr 192.168.31.10 udp dport 1080 return"));
        assert!(ruleset.contains(
            "ip daddr { 224.0.0.0/4, 255.255.255.255 } udp dport != { 5353, 5355 } return"
        ));
        assert!(ruleset.contains("meta l4proto udp meta mark set 21080"));
        assert!(ruleset.contains("chain prerouting {"));
        assert!(
            ruleset.contains("meta mark 21080 meta l4proto udp tproxy to 127.0.0.1:10854 accept")
        );
        assert!(ruleset.contains("ip daddr 192.168.31.10 tcp dport 1080 return"));
        assert!(ruleset.contains("tcp dport 1-65535 redirect to :10810"));
        assert!(ruleset.contains("udp dport 853 reject"));
        assert!(ruleset.contains("udp dport 443 reject"));
        assert!(ruleset.contains("udp dport 137 ip daddr !="));

        let ip6_ruleset = NftablesInterceptor::build_nft_ip6_table_ruleset(
            "routeward",
            "output",
            21079,
            53,
            853,
            false,
            false,
        )
        .expect("ip6 ruleset generated even when killSwitchEnabled=false");
        assert!(ip6_ruleset.contains("table ip6 routeward {"));
        assert!(ip6_ruleset.contains("udp dport 53 reject"));
        assert!(ip6_ruleset.contains("tcp dport 53 reject with tcp reset"));
        assert!(ip6_ruleset.contains("udp dport 853 reject"));
        assert!(ip6_ruleset.contains("tcp dport 853 reject with tcp reset"));

        let atomic_batch = NftablesInterceptor::build_atomic_replace_ruleset(
            "routeward",
            "output",
            21079,
            10810,
            10853,
            53,
            853,
            false,
            false,
            &upstreams,
        );
        assert!(atomic_batch.contains("table ip routeward\ndelete table ip routeward\n"));
        assert!(atomic_batch.contains("table ip6 routeward\ndelete table ip6 routeward\n"));
        assert!(!atomic_batch.contains("udp dport 853 reject\n    }\n}\ntable ip6"));
    }

    #[test]
    fn parses_sockaddr_in_original_dst_and_rejects_unredirected_loopback_relay() {
        let ip_be = u32::from(Ipv4Addr::new(93, 184, 216, 34)).to_be();
        let port_be = 443u16.to_be();
        let parsed = NftablesInterceptor::parse_sockaddr_in_fields(2, port_be, ip_be, 10810)
            .expect("valid original dst");
        assert_eq!(parsed.ip(), &Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(parsed.port(), 443);

        // Direct connection to 127.0.0.1:10810 without DNAT must be rejected
        let loop_ip_be = u32::from(Ipv4Addr::new(127, 0, 0, 1)).to_be();
        let relay_port_be = 10810u16.to_be();
        assert!(
            NftablesInterceptor::parse_sockaddr_in_fields(2, relay_port_be, loop_ip_be, 10810)
                .is_none()
        );
    }

    #[test]
    fn detects_tproxy_ip_rule_and_route_table_conflicts_and_builds_cleanup_commands() {
        let spec = TproxyRoutingSpec {
            fwmark: 21080, // 0x5258
            route_table: 100,
            rule_priority: 10810,
            tproxy_port: 10854,
        };

        let clean_ip_rules = "\
0:\tfrom all lookup local
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";
        assert!(NftablesInterceptor::detect_ip_rule_conflict(clean_ip_rules, spec).is_none());
        assert!(NftablesInterceptor::detect_ip_route_table_conflict("", 100).is_none());

        // Priority conflict
        let prio_conflict = "\
0:\tfrom all lookup local
10810:\tfrom all fwmark 0x9999 lookup 200
32766:\tfrom all lookup main
";
        let err_prio = NftablesInterceptor::detect_ip_rule_conflict(prio_conflict, spec)
            .expect("detects priority conflict");
        assert!(err_prio.contains("priority 10810"));

        // Fwmark conflict (hex 0x5258/0xffffffff)
        let fwmark_conflict = "\
0:\tfrom all lookup local
9000:\tfrom all fwmark 0x5258/0xffffffff lookup 250
32766:\tfrom all lookup main
";
        let err_fwmark = NftablesInterceptor::detect_ip_rule_conflict(fwmark_conflict, spec)
            .expect("detects fwmark conflict");
        assert!(err_fwmark.contains("0x5258"));

        // Table lookup conflict
        let table_rule_conflict = "\
0:\tfrom all lookup local
9000:\tfrom all fwmark 0x1111 lookup 100
32766:\tfrom all lookup main
";
        let err_tbl_rule = NftablesInterceptor::detect_ip_rule_conflict(table_rule_conflict, spec)
            .expect("detects lookup table conflict");
        assert!(err_tbl_rule.contains("table 100"));

        // Route table non-empty conflict
        let non_empty_route = "default via 10.0.0.1 dev eth0\n";
        let err_route = NftablesInterceptor::detect_ip_route_table_conflict(non_empty_route, 100)
            .expect("detects non-empty route table");
        assert!(err_route.contains("table 100"));

        // Exact add/del args and watchdog script
        assert_eq!(
            NftablesInterceptor::build_ip_rule_del_args(spec),
            ["-4", "rule", "del", "fwmark", "21080", "lookup", "100", "priority", "10810"]
        );
        assert_eq!(
            NftablesInterceptor::build_ip_route_del_args(spec),
            [
                "-4",
                "route",
                "del",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                "100"
            ]
        );
        let wd = NftablesInterceptor::build_watchdog_cleanup_script("nft", "ip", "routeward", spec);
        assert!(wd.contains("nft delete table ip routeward"));
        assert!(wd.contains("nft delete table ip6 routeward"));
        assert!(wd.contains("ip -4 rule del fwmark 21080 lookup 100 priority 10810"));
        assert!(wd.contains("ip -4 route del local 0.0.0.0/0 dev lo table 100"));
        assert!(wd.contains("ip -6 rule del fwmark 21080 lookup 100 priority 10810"));
        assert!(wd.contains("ip -6 route del local ::/0 dev lo table 100"));
    }

    #[test]
    fn builds_dual_stack_ip6_nat_tproxy_ruleset_and_parses_sockaddr_in6() {
        let upstreams = vec![
            (IpAddr::V4(Ipv4Addr::new(192, 168, 31, 10)), 1080),
            (IpAddr::V6("2001:db8::10".parse().unwrap()), 1080),
        ];
        let batch = NftablesInterceptor::build_atomic_replace_ruleset_dual_stack(
            "routeward",
            "output",
            21079,
            21080,
            10810,
            10853,
            10854,
            53,
            853,
            443,
            5353,
            5355,
            137,
            true,
            true,
            true,
            &upstreams,
        );
        assert!(batch.contains("ip6 daddr 2001:db8::10 tcp dport 1080 return"));
        assert!(batch.contains("ip6 daddr 2001:db8::10 udp dport 1080 return"));
        assert!(batch.contains("tcp dport 1-65535 redirect to :10810"));
        assert!(batch.contains("tproxy ip6 to [::1]:10854 accept"));
        assert!(batch.contains("udp dport 53 reject"));
        assert!(batch.contains("tcp dport 853 reject with tcp reset"));

        let dst_v6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let parsed = NftablesInterceptor::parse_sockaddr_in6_fields(
            AF_INET6_U16,
            443u16.to_be(),
            dst_v6.octets(),
            10810,
        )
        .expect("parse valid original IPv6 dst");
        assert_eq!(*parsed.ip(), dst_v6);
        assert_eq!(parsed.port(), 443);

        // Reject unredirected ::1:10810
        assert!(NftablesInterceptor::parse_sockaddr_in6_fields(
            AF_INET6_U16,
            10810u16.to_be(),
            Ipv6Addr::LOCALHOST.octets(),
            10810,
        )
        .is_none());
    }
}
