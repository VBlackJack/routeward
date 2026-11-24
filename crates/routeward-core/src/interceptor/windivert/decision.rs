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

//! Pure packet-classification helpers shared by the WinDivert reflection worker and unit tests.
//! Kept OS-independent under `#[cfg(any(windows, test))]` so both Linux and Windows CI exercise them.

use crate::config::SystemConstants;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Standard network/DNS ports captured from `SystemConstants` once when the worker starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NetworkPorts {
    pub(super) dns: u16,
    pub(super) dot: u16,
    pub(super) quic: u16,
    pub(super) mdns: u16,
    pub(super) llmnr: u16,
    pub(super) netbios_ns: u16,
}

impl NetworkPorts {
    pub(super) fn from_constants(constants: &SystemConstants) -> Self {
        Self {
            dns: constants.dns.dns_standard_port,
            dot: constants.dns.dns_over_tls_port,
            quic: constants.network.quic_default_port,
            mdns: constants.network.mdns_standard_port,
            llmnr: constants.network.llmnr_standard_port,
            netbios_ns: constants.network.netbios_ns_standard_port,
        }
    }
}

/// True when an outbound UDP datagram targets QUIC (port 443) and the policy blocks QUIC fallback.
pub(super) fn should_block_quic_udp(
    dst_port: u16,
    quic_port: u16,
    block_quic_udp_443: bool,
) -> bool {
    block_quic_udp_443 && dst_port == quic_port
}

/// True when an outbound UDP datagram targets local-name discovery (LLMNR or mDNS).
pub(super) fn is_local_discovery_udp_port(dst_port: u16, ports: NetworkPorts) -> bool {
    dst_port == ports.llmnr || dst_port == ports.mdns
}

/// True when an IPv4 UDP destination is eligible for general proxy/rule interception.
pub(super) fn is_routable_unicast_ipv4_udp_dest(dst_ip: Ipv4Addr) -> bool {
    !dst_ip.is_multicast() && !dst_ip.is_broadcast() && !dst_ip.is_loopback()
}

/// True when an IPv6 UDP destination is eligible for general proxy/rule interception.
pub(super) fn is_routable_unicast_ipv6_udp_dest(dst_ip: Ipv6Addr) -> bool {
    !dst_ip.is_multicast() && !dst_ip.is_loopback() && !dst_ip.is_unicast_link_local()
}

/// True when a `RuleAction::Direct` TCP SYN must still be reflected to the local transparent relay
/// (for SNI/HTTP Host inspection, or Fake-IP resolution on IPv4).
pub(super) fn should_reflect_direct_syn(
    is_ipv6: bool,
    is_fake_ip: bool,
    needs_payload_inspection: bool,
) -> bool {
    if is_ipv6 {
        needs_payload_inspection
    } else {
        is_fake_ip || needs_payload_inspection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_ports_match_embedded_constants() {
        let constants = SystemConstants::load_embedded().expect("embedded constants");
        let ports = NetworkPorts::from_constants(&constants);
        assert_eq!(ports.dns, 53);
        assert_eq!(ports.dot, 853);
        assert_eq!(ports.quic, 443);
        assert_eq!(ports.mdns, 5353);
        assert_eq!(ports.llmnr, 5355);
        assert_eq!(ports.netbios_ns, 137);
    }

    #[test]
    fn quic_and_local_discovery_guards_classify_ports_accurately() {
        let constants = SystemConstants::load_embedded().expect("embedded constants");
        let ports = NetworkPorts::from_constants(&constants);
        assert!(should_block_quic_udp(443, ports.quic, true));
        assert!(!should_block_quic_udp(443, ports.quic, false));
        assert!(!should_block_quic_udp(53, ports.quic, true));

        assert!(is_local_discovery_udp_port(5353, ports));
        assert!(is_local_discovery_udp_port(5355, ports));
        assert!(!is_local_discovery_udp_port(53, ports));
    }

    #[test]
    fn routable_udp_destination_filters_local_and_multicast_addresses() {
        assert!(is_routable_unicast_ipv4_udp_dest(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_routable_unicast_ipv4_udp_dest(Ipv4Addr::LOCALHOST));
        assert!(!is_routable_unicast_ipv4_udp_dest(Ipv4Addr::BROADCAST));
        assert!(!is_routable_unicast_ipv4_udp_dest(Ipv4Addr::new(
            224, 0, 0, 251
        )));

        assert!(is_routable_unicast_ipv6_udp_dest(
            "2606:4700:4700::1111".parse().unwrap()
        ));
        assert!(!is_routable_unicast_ipv6_udp_dest(Ipv6Addr::LOCALHOST));
        assert!(!is_routable_unicast_ipv6_udp_dest(
            "fe80::1".parse().unwrap()
        ));
        assert!(!is_routable_unicast_ipv6_udp_dest(
            "ff02::fb".parse().unwrap()
        ));
    }

    #[test]
    fn direct_syn_reflection_preserves_ipv4_fake_ip_and_ipv6_inspection_rules() {
        assert!(should_reflect_direct_syn(false, true, false));
        assert!(should_reflect_direct_syn(false, false, true));
        assert!(!should_reflect_direct_syn(false, false, false));

        assert!(!should_reflect_direct_syn(true, true, false));
        assert!(should_reflect_direct_syn(true, false, true));
        assert!(!should_reflect_direct_syn(true, false, false));
    }
}
