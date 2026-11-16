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

#[test]
fn socket_event_decodes_owner_port_protocol_family_and_close_kind() {
    let mut addr = WinDivertAddress::default();
    addr.union_data[16..20].copy_from_slice(&4321u32.to_ne_bytes());
    addr.union_data[52..54].copy_from_slice(&40000u16.to_ne_bytes());
    addr.union_data[56] = 17;
    // Layer = SOCKET (3), Event = CLOSE (7), IPv6 bit set.
    addr.flags_bitfield = 3 | (u64::from(ffi::WINDIVERT_EVENT_SOCKET_CLOSE) << 8) | (1u64 << 20);

    let event = addr.socket_event();
    assert_eq!(event.pid, 4321);
    assert_eq!(event.local_port, 40000);
    assert_eq!(event.protocol, 17);
    assert!(event.ipv6);
    assert_eq!(event.kind, 7);
    assert!(event.is_close());

    addr.flags_bitfield = 3 | (4u64 << 8);
    let connect = addr.socket_event();
    assert!(!connect.ipv6);
    assert_eq!(connect.kind, ffi::WINDIVERT_EVENT_SOCKET_CONNECT);
    assert!(
        !connect.is_close(),
        "CONNECT must record the owner, not purge it"
    );
}

#[test]
fn socket_event_codes_match_upstream_header() {
    // windivert.h v2.2.2: NETWORK_PACKET=0, FLOW_ESTABLISHED=1, FLOW_DELETED=2, SOCKET_BIND=3,
    // SOCKET_CONNECT=4, SOCKET_LISTEN=5, SOCKET_ACCEPT=6, SOCKET_CLOSE=7.
    assert_eq!(ffi::WINDIVERT_EVENT_SOCKET_BIND, 3);
    assert_eq!(ffi::WINDIVERT_EVENT_SOCKET_CONNECT, 4);
    assert_eq!(ffi::WINDIVERT_EVENT_SOCKET_LISTEN, 5);
    assert_eq!(ffi::WINDIVERT_EVENT_SOCKET_ACCEPT, 6);
    assert_eq!(ffi::WINDIVERT_EVENT_SOCKET_CLOSE, 7);
}

#[test]
fn scoped_firewall_rule_name_has_a_single_format() {
    assert_eq!(
        scoped_firewall_rule_name(10810),
        "RouteWard_TransparentRelay_10810"
    );
}

#[test]
fn windivert_address_layout_and_bitfields_are_exact() {
    assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);

    let mut addr = WinDivertAddress::default();
    assert!(!addr.is_outbound());
    addr.set_outbound(true);
    assert!(addr.is_outbound());
    addr.set_outbound(false);
    assert!(!addr.is_outbound());

    let filter = build_network_filter_string(53, 853);
    assert!(filter.contains("ip and (tcp or udp)"));
    assert!(filter.contains("ipv6 and (tcp or udp)"));

    // Standard IPv6 DNS (53) is intercepted rather than dropped; DoT (853) follows blockEncryptedDnsBypass
    assert!(!should_block_outbound_ipv6_dns_or_dot(53, 53, 853, false));
    assert!(should_block_outbound_ipv6_dns_or_dot(853, 53, 853, false));
    assert!(!should_block_outbound_ipv6_dns_or_dot(443, 53, 853, false));

    assert!(should_block_outbound_ipv6_dot(853, 853, true));
    assert!(!should_block_outbound_ipv6_dot(853, 853, false));
    assert!(!should_block_outbound_ipv6_dot(53, 853, true));
}
