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
