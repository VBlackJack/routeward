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
    assert!(ruleset
        .contains("ip daddr { 224.0.0.0/4, 255.255.255.255 } udp dport != { 5353, 5355 } return"));
    assert!(ruleset.contains("meta l4proto udp meta mark set 21080"));
    assert!(ruleset.contains("chain prerouting {"));
    assert!(ruleset.contains("meta mark 21080 meta l4proto udp tproxy to 127.0.0.1:10854 accept"));
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
        true,
    )
    .expect("ip6 ruleset generated even when killSwitchEnabled=false");
    assert!(ip6_ruleset.contains("table ip6 routeward {"));
    assert!(ip6_ruleset.contains("udp dport 53 redirect to :10853"));
    assert!(ip6_ruleset.contains("tcp dport 53 redirect to :10853"));
    assert!(!ip6_ruleset.contains("udp dport 53 reject"));
    assert!(ip6_ruleset.contains("udp dport 853 reject"));
    assert!(ip6_ruleset.contains("tcp dport 853 reject with tcp reset"));

    let ip6_allow_dot = NftablesInterceptor::build_nft_ip6_table_ruleset(
        "routeward",
        "output",
        21079,
        53,
        853,
        false,
        false,
    )
    .expect("ip6 ruleset without DoT block");
    assert!(!ip6_allow_dot.contains("udp dport 853 reject"));
    assert!(!ip6_allow_dot.contains("tcp dport 853 reject"));

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
    assert!(batch.contains("udp dport 53 redirect to :10853"));
    assert!(batch.contains("tcp dport 53 redirect to :10853"));
    assert!(batch.contains("tproxy ip6 to [::1]:10854 accept"));
    assert!(!batch.contains("udp dport 53 reject"));
    assert!(batch.contains("tcp dport 853 reject with tcp reset"));

    let fallback_ip6 = NftablesInterceptor::build_nft_ip6_fallback_guard_ruleset(
        "routeward",
        "output",
        21079,
        53,
        853,
        false,
    );
    assert!(fallback_ip6.contains("udp dport 53 reject"));
    assert!(!fallback_ip6.contains("853 reject"));

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
