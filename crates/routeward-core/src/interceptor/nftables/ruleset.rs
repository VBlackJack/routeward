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

use super::*;

/// Default transparent TCP relay port used by the legacy IPv6 wrapper builder.
const LEGACY_RELAY_PORT: u16 = 10810;
/// Default DNS listen port used by the legacy wrapper builders (tests and compatibility only).
const LEGACY_DNS_LISTEN_PORT: u16 = 10853;
/// Default local-name inspection (TPROXY) port used by the legacy wrapper builders.
const LEGACY_LOCAL_NAME_INSPECT_PORT: u16 = 10854;
/// Default standard DNS port used by the legacy wrapper builders.
const LEGACY_DNS_STANDARD_PORT: u16 = 53;
/// Default DoT port used by the legacy wrapper builders.
const LEGACY_DOT_PORT: u16 = 853;
/// Default QUIC port used by the legacy wrapper builders.
const LEGACY_QUIC_PORT: u16 = 443;
/// Default mDNS port used by the legacy wrapper builders.
const LEGACY_MDNS_PORT: u16 = 5353;
/// Default LLMNR port used by the legacy wrapper builders.
const LEGACY_LLMNR_PORT: u16 = 5355;
/// Default NetBIOS name service port used by the legacy wrapper builders.
const LEGACY_NETBIOS_NS_PORT: u16 = 137;

/// Fallback Fake-IP network (RFC 2544 benchmarking range) used by the legacy builders.
pub(super) const LEGACY_FAKE_IP_CIDR: &str = "198.18.0.0/15";

/// Parses [`LEGACY_FAKE_IP_CIDR`] into an [`Ipv4Net`].
pub(super) fn default_fake_ip_net() -> Ipv4Net {
    LEGACY_FAKE_IP_CIDR
        .parse()
        .expect("LEGACY_FAKE_IP_CIDR is a valid IPv4 CIDR")
}

impl NftablesInterceptor {
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
            LEGACY_DNS_LISTEN_PORT,
            LEGACY_DNS_STANDARD_PORT,
            LEGACY_DOT_PORT,
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
            LEGACY_LOCAL_NAME_INSPECT_PORT,
            dns_standard_port,
            dot_port,
            LEGACY_QUIC_PORT,
            LEGACY_MDNS_PORT,
            LEGACY_LLMNR_PORT,
            LEGACY_NETBIOS_NS_PORT,
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
        Self::build_nft_table_ruleset_with_fake_ip(
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
            default_fake_ip_net(),
        )
    }

    /// Generates the dedicated IPv4 `nftables` ruleset with explicit `tproxy_fwmark` and the
    /// configured Fake-IP network used by the kernel egress drop rules.
    #[allow(clippy::too_many_arguments)]
    pub fn build_nft_table_ruleset_with_fake_ip(
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
        fake_ip_net: Ipv4Net,
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
            "        meta mark {fwmark} ip daddr {fake_ip_net} drop\n"
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
            "        meta mark != {tproxy_fwmark} ip daddr {fake_ip_net} drop\n"
        ));
        script.push_str("    }\n");
        script.push_str("}\n");
        script
    }

    /// Generates the dedicated IPv6 `nftables` ruleset (`table ip6 <table_name>`) covering:
    /// - outbound IPv6 DNS (port 53 UDP and TCP) redirection to `dns_listen_port`
    /// - outbound IPv6 TCP transparent NAT redirect (`tcp dport 1-65535 redirect to :relay_port`)
    /// - outbound IPv6 UDP `TPROXY` marking and local prerouting redirection to `[::1]:local_name_inspect_port`
    /// - optional blocking of outbound IPv6 DoT/DoQ (port 853) and QUIC (UDP 443) in `filter_output`
    #[allow(clippy::too_many_arguments)]
    pub fn build_nft_ip6_table_ruleset_with_tproxy(
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
        block_encrypted_dns: bool,
        block_quic_udp_443: bool,
        upstream_v6_endpoints: &[(Ipv6Addr, u16)],
    ) -> String {
        let mut script = String::with_capacity(1536);
        script.push_str(&format!("table ip6 {table_name} {{\n"));
        script.push_str(&format!("    chain {chain_name} {{\n"));
        script.push_str("        type nat hook output priority -100; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip6 daddr ::1 return\n");
        script.push_str(&format!(
            "        udp dport {dns_standard_port} redirect to :{dns_listen_port}\n"
        ));
        script.push_str(&format!(
            "        tcp dport {dns_standard_port} redirect to :{dns_listen_port}\n"
        ));
        if block_encrypted_dns {
            script.push_str(&format!("        tcp dport {dot_port} return\n"));
        }
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
        if block_encrypted_dns {
            script.push_str(&format!("        udp dport {dot_port} return\n"));
        }
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
        if block_encrypted_dns {
            script.push_str(&format!("        udp dport {dot_port} reject\n"));
            script.push_str(&format!(
                "        tcp dport {dot_port} reject with tcp reset\n"
            ));
        }
        if block_quic_udp_443 {
            script.push_str(&format!("        udp dport {quic_port} reject\n"));
        }
        script.push_str("    }\n");
        script.push_str("}\n");
        script
    }

    /// Generates the filter-only fallback IPv6 table used when full IPv6 NAT/TPROXY is unavailable
    /// on the host kernel.
    ///
    /// - kill switch disabled: blocks raw IPv6 DNS (port 53) and optionally DoT/DoQ (port 853).
    /// - kill switch enabled: rejects all IPv6 egress except loopback traffic and packets carrying
    ///   RouteWard's own `fwmark`, so no IPv6 traffic can bypass the interception.
    pub fn build_nft_ip6_fallback_guard_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        dns_standard_port: u16,
        dot_port: u16,
        kill_switch_enabled: bool,
        block_encrypted_dns: bool,
    ) -> String {
        let mut script = format!(
            "table ip6 {table_name} {{\n    chain {chain_name} {{\n        type filter hook output priority 0; policy accept;\n        meta mark {fwmark} return\n        ip6 daddr ::1 return\n"
        );
        if kill_switch_enabled {
            script.push_str("        oifname \"lo\" return\n");
            // Kernel neighbour discovery is unmarked: without it RouteWard's own IPv6 upstream
            // breaks once the neighbour cache expires. Echo and other ICMPv6 stay rejected.
            script.push_str(
                "        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } return\n",
            );
            script.push_str("        meta l4proto tcp reject with tcp reset\n");
            script.push_str("        reject\n");
        } else {
            script.push_str(&format!(
                "        udp dport {dns_standard_port} reject\n        tcp dport {dns_standard_port} reject with tcp reset\n"
            ));
            if block_encrypted_dns {
                script.push_str(&format!(
                    "        udp dport {dot_port} reject\n        tcp dport {dot_port} reject with tcp reset\n"
                ));
            }
        }
        script.push_str("    }\n}\n");
        script
    }

    /// Generates the dedicated IPv6 `nftables` ruleset (`table ip6 <table_name>`) using
    /// default transparent TCP/UDP relay ports.
    pub fn build_nft_ip6_table_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        dns_standard_port: u16,
        dot_port: u16,
        _kill_switch_enabled: bool,
        block_encrypted_dns: bool,
    ) -> Option<String> {
        Some(Self::build_nft_ip6_table_ruleset_with_tproxy(
            table_name,
            chain_name,
            fwmark,
            DEFAULT_TPROXY_FWMARK,
            LEGACY_RELAY_PORT,
            LEGACY_DNS_LISTEN_PORT,
            LEGACY_LOCAL_NAME_INSPECT_PORT,
            dns_standard_port,
            dot_port,
            LEGACY_QUIC_PORT,
            LEGACY_MDNS_PORT,
            LEGACY_LLMNR_PORT,
            block_encrypted_dns,
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
            LEGACY_LOCAL_NAME_INSPECT_PORT,
            dns_standard_port,
            dot_port,
            LEGACY_QUIC_PORT,
            LEGACY_MDNS_PORT,
            LEGACY_LLMNR_PORT,
            LEGACY_NETBIOS_NS_PORT,
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
        Self::build_atomic_replace_ruleset_with_fake_ip(
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
            kill_switch_enabled,
            block_encrypted_dns,
            block_quic_udp_443,
            upstream_endpoints,
            default_fake_ip_net(),
        )
    }

    /// Builds a single atomic `nft -f -` transaction script with explicit `tproxy_fwmark` and the
    /// configured Fake-IP network.
    #[allow(clippy::too_many_arguments)]
    pub fn build_atomic_replace_ruleset_with_fake_ip(
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
        fake_ip_net: Ipv4Net,
    ) -> String {
        let _ = kill_switch_enabled;
        let mut batch = String::with_capacity(2048);
        batch.push_str(&format!("table ip {table_name}\n"));
        batch.push_str(&format!("delete table ip {table_name}\n"));
        batch.push_str(&Self::build_nft_table_ruleset_with_fake_ip(
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
            fake_ip_net,
        ));
        let ip6_script = Self::build_nft_ip6_table_ruleset_with_tproxy(
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
            block_encrypted_dns,
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
        fake_ip_net: Ipv4Net,
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
        batch.push_str(&Self::build_nft_table_ruleset_with_fake_ip(
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
            fake_ip_net,
        ));
        batch.push_str(&format!("table ip6 {table_name}\n"));
        batch.push_str(&format!("delete table ip6 {table_name}\n"));
        batch.push_str(&Self::build_nft_ip6_table_ruleset_with_tproxy(
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
            block_encrypted_dns,
            block_quic_udp_443,
            &up6,
        ));
        let _ = kill_switch_enabled;
        batch
    }
}
