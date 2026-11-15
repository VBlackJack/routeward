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

/// Builds the `WINDIVERT_LAYER_NETWORK` filter string for outbound IPv4 TCP + UDP
/// and IPv6 DNS/DoT/QUIC/mDNS/LLMNR packets.
pub fn build_network_filter_string(dns_port: u16, dot_port: u16) -> String {
    build_network_filter_string_full(dns_port, dot_port, 443, 5353, 5355, 137)
}

/// Builds the full `WINDIVERT_LAYER_NETWORK` filter string capturing all outbound non-loopback
/// IPv4 and IPv6 TCP and UDP packets.
pub fn build_network_filter_string_full(
    _dns_port: u16,
    _dot_port: u16,
    _quic_port: u16,
    _mdns_port: u16,
    _llmnr_port: u16,
    _netbios_ns_port: u16,
) -> String {
    "outbound and !loopback and ((ip and (tcp or udp)) or (ipv6 and (tcp or udp)))".to_string()
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
