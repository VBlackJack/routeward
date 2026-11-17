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

use crate::interceptor::nat::IPPROTO_UDP;

/// IPv6 next-header value of the fragment extension header (RFC 8200). WinDivert exposes it
/// through `ipv6.NextHdr` because it parses no transport header for a later fragment.
const IPV6_NEXT_HDR_FRAGMENT: u8 = 44;

/// Builds the `WINDIVERT_LAYER_NETWORK` filter string for outbound IPv4 TCP + UDP
/// and IPv6 DNS/DoT/QUIC/mDNS/LLMNR packets.
pub fn build_network_filter_string(dns_port: u16, dot_port: u16) -> String {
    build_network_filter_string_full(dns_port, dot_port, 443, 5353, 5355, 137)
}

/// Builds the full `WINDIVERT_LAYER_NETWORK` filter string capturing all outbound non-loopback
/// IPv4 and IPv6 TCP and UDP packets, plus the later fragments of fragmented datagrams.
///
/// WinDivert parses no transport header for a fragment with a non-zero offset, so `udp` is false
/// for it and the plain TCP/UDP clauses never match. Without the two fragment clauses those
/// fragments would bypass the engine and a fragmented datagram could not be dropped as a whole.
/// IPv4 later fragments are limited to UDP (`ip.Protocol` is in every fragment); IPv6 later
/// fragments cannot be narrowed (the protocol sits in the fragment header), so every packet
/// whose next header is the fragment header is captured and the worker releases the non-UDP ones.
pub fn build_network_filter_string_full(
    _dns_port: u16,
    _dot_port: u16,
    _quic_port: u16,
    _mdns_port: u16,
    _llmnr_port: u16,
    _netbios_ns_port: u16,
) -> String {
    [
        "outbound and !loopback and (".to_string(),
        "(ip and (tcp or udp)) or (ipv6 and (tcp or udp))".to_string(),
        format!(" or (ip and ip.FragOff != 0 and ip.Protocol == {IPPROTO_UDP})"),
        format!(" or (ipv6 and ipv6.NextHdr == {IPV6_NEXT_HDR_FRAGMENT}))"),
    ]
    .concat()
}

/// Returns `true` if an outbound IPv6 packet targeting `dst_port` must be blocked as an
/// encrypted DNS bypass (port 853) when `block_encrypted_dns_bypass` is enabled.
/// Standard IPv6 DNS (port 53) is intercepted directly and is no longer dropped.
pub fn should_block_outbound_ipv6_dot(
    dst_port: u16,
    dot_port: u16,
    block_encrypted_dns_bypass: bool,
) -> bool {
    block_encrypted_dns_bypass && dst_port == dot_port
}

/// Legacy compatibility helper: only flags DoT/DoQ (port 853), never standard DNS (port 53).
pub fn should_block_outbound_ipv6_dns_or_dot(
    dst_port: u16,
    _dns_port: u16,
    dot_port: u16,
    _kill_switch_enabled: bool,
) -> bool {
    dst_port == dot_port
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_filter_keeps_tcp_udp_clauses_and_captures_later_fragments() {
        let filter = build_network_filter_string(53, 853);
        assert!(filter.starts_with("outbound and !loopback and ("));
        assert!(filter.contains("(ip and (tcp or udp))"));
        assert!(filter.contains("(ipv6 and (tcp or udp))"));
        assert!(filter.contains("(ip and ip.FragOff != 0 and ip.Protocol == 17)"));
        assert!(filter.contains("(ipv6 and ipv6.NextHdr == 44)"));
        assert!(!filter.contains("  ") && !filter.contains('\n'));
        assert_eq!(filter.matches('(').count(), filter.matches(')').count());
    }
}
