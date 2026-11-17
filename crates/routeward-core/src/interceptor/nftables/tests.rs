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

use super::watchdog::{
    DHCP_V4_CLIENT_PORT, DHCP_V4_SERVER_PORT, DHCP_V6_CLIENT_PORT, DHCP_V6_SERVER_PORT,
};
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
        default_fake_ip_net_for_tests(),
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

fn default_fake_ip_net_for_tests() -> Ipv4Net {
    "198.18.0.0/15".parse().unwrap()
}

#[test]
fn fake_ip_drop_rules_follow_the_configured_cidr() {
    let custom: Ipv4Net = "10.77.0.0/16".parse().unwrap();
    let ruleset = NftablesInterceptor::build_nft_table_ruleset_with_fake_ip(
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
        &[],
        custom,
    );
    assert!(ruleset.contains("meta mark 21079 ip daddr 10.77.0.0/16 drop"));
    assert!(ruleset.contains("meta mark != 21080 ip daddr 10.77.0.0/16 drop"));
    assert!(!ruleset.contains("198.18.0.0/15"));

    let legacy =
        NftablesInterceptor::build_nft_table_ruleset("routeward", "output", 21079, 10810, &[]);
    assert!(legacy.contains("meta mark 21079 ip daddr 198.18.0.0/15 drop"));
}

#[test]
fn raw_socket_guard_follows_the_configured_cidr() {
    let custom: Ipv4Net = "10.77.0.0/16".parse().unwrap();
    let in_custom = SocketAddrV4::new(Ipv4Addr::new(10, 77, 3, 4), 5355);
    let in_default = SocketAddrV4::new(Ipv4Addr::new(198, 18, 3, 4), 5355);

    let err = NftablesInterceptor::check_fake_ip_egress(in_custom, custom)
        .expect_err("address in the custom Fake-IP CIDR must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(NftablesInterceptor::check_fake_ip_egress(in_default, custom).is_ok());
    assert!(NftablesInterceptor::is_fake_ip_in(
        Ipv4Addr::new(10, 77, 255, 255),
        custom
    ));
    assert!(!NftablesInterceptor::is_fake_ip_in(
        Ipv4Addr::new(10, 78, 0, 1),
        custom
    ));
}

#[test]
fn resolves_fake_ip_net_from_profile_then_constants_then_default() {
    let net = NftablesInterceptor::resolve_fake_ip_net("10.77.0.0/16", "198.18.0.0/15");
    assert_eq!(net.to_string(), "10.77.0.0/16");
    let net = NftablesInterceptor::resolve_fake_ip_net("garbage", "172.30.0.0/16");
    assert_eq!(net.to_string(), "172.30.0.0/16");
    let net = NftablesInterceptor::resolve_fake_ip_net("garbage", "also-garbage");
    assert_eq!(net.to_string(), "198.18.0.0/15");
}

#[test]
fn ip6_fallback_with_kill_switch_rejects_everything_except_loopback_and_own_mark() {
    let rules = NftablesInterceptor::build_nft_ip6_fallback_guard_ruleset(
        "routeward",
        "output",
        21079,
        53,
        853,
        true,
        true,
    );
    assert!(rules.contains("meta mark 21079 return"));
    assert!(rules.contains("ip6 daddr ::1 return"));
    assert!(rules.contains("oifname \"lo\" return"));
    assert!(rules.contains("meta l4proto tcp reject with tcp reset"));
    assert!(rules.contains(
        "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } return"
    ));
    assert!(!rules.contains("echo-request"));
    let nd_pos = rules.find("icmpv6 type").unwrap();
    assert!(nd_pos < rules.find("meta l4proto tcp reject").unwrap());
    assert!(rules.contains(
        "        reject
"
    ));
    let mark_pos = rules.find("meta mark 21079 return").unwrap();
    let reject_pos = rules
        .find(
            "        reject
",
        )
        .unwrap();
    assert!(
        mark_pos < reject_pos,
        "own-mark accept must precede the catch-all reject"
    );
    assert!(!rules.contains("dport"));
}

#[test]
fn ip6_fallback_without_kill_switch_keeps_dns_and_dot_guard_only() {
    let rules = NftablesInterceptor::build_nft_ip6_fallback_guard_ruleset(
        "routeward",
        "output",
        21079,
        53,
        853,
        false,
        true,
    );
    assert!(rules.contains("udp dport 53 reject"));
    assert!(rules.contains("tcp dport 853 reject with tcp reset"));
    assert!(!rules.contains(
        "        reject
"
    ));
    assert!(!rules.contains("l4proto"));

    let no_dot = NftablesInterceptor::build_nft_ip6_fallback_guard_ruleset(
        "routeward",
        "output",
        21079,
        53,
        853,
        false,
        false,
    );
    assert!(!no_dot.contains("853"));
}

#[test]
fn table_listing_membership_is_locale_independent() {
    let listing = "table inet filter
table ip routeward
table ip6 other
";
    assert!(NftablesInterceptor::tables_listing_contains(
        listing,
        "ip",
        "routeward"
    ));
    assert!(!NftablesInterceptor::tables_listing_contains(
        listing,
        "ip6",
        "routeward"
    ));
    assert!(NftablesInterceptor::tables_listing_contains(
        listing, "ip6", "other"
    ));
    assert!(!NftablesInterceptor::tables_listing_contains(
        "",
        "ip",
        "routeward"
    ));
}

#[test]
fn watchdog_mode_protocol_is_strict() {
    assert_eq!(WatchdogMode::Open.as_str(), "open");
    assert_eq!(WatchdogMode::Block.as_str(), "block");
    assert_eq!(WatchdogMode::Disarm.as_str(), "disarm");
    for mode in [
        WatchdogMode::Open,
        WatchdogMode::Block,
        WatchdogMode::Disarm,
    ] {
        assert_eq!(WatchdogMode::parse(mode.as_str()), Some(mode));
    }
    for bogus in ["", "BLOCK", "block ", "blo", "close", "open;reboot"] {
        assert_eq!(WatchdogMode::parse(bogus), None, "{bogus:?}");
    }
    assert_eq!(WatchdogMode::from_kill_switch(true), WatchdogMode::Block);
    assert_eq!(WatchdogMode::from_kill_switch(false), WatchdogMode::Open);
}

#[test]
fn crash_cleanup_action_fails_closed_only_on_unclean_stop_with_kill_switch_and_active_interception()
{
    use CrashCleanupAction::{InstallFailClosed, RemoveAll};
    for active in [true, false] {
        assert_eq!(
            decide_crash_cleanup_action(Some("success"), true, active),
            RemoveAll
        );
        assert_eq!(
            decide_crash_cleanup_action(Some("success"), false, active),
            RemoveAll
        );
        assert_eq!(decide_crash_cleanup_action(None, true, active), RemoveAll);
        assert_eq!(decide_crash_cleanup_action(None, false, active), RemoveAll);
    }
    for result in ["signal", "exit-code", "core-dump", "timeout", "watchdog"] {
        assert_eq!(
            decide_crash_cleanup_action(Some(result), true, true),
            InstallFailClosed,
            "{result}"
        );
        // Idle daemon or startup failure: interception never ran, nothing to fail closed.
        assert_eq!(
            decide_crash_cleanup_action(Some(result), true, false),
            RemoveAll,
            "{result}"
        );
        for active in [true, false] {
            assert_eq!(
                decide_crash_cleanup_action(Some(result), false, active),
                RemoveAll,
                "{result}"
            );
        }
    }
}

#[test]
fn fail_closed_ruleset_is_one_idempotent_transaction_with_expected_allowances() {
    let ruleset = NftablesInterceptor::build_fail_closed_ruleset("routeward");
    assert_eq!(fail_closed_table_name("routeward"), "routeward_ks");
    for old in ["ip", "ip6"] {
        let declare = ruleset
            .find(&format!("table {old} routeward {{}}"))
            .expect("declare");
        let delete = ruleset
            .find(&format!("delete table {old} routeward\n"))
            .expect("delete");
        assert!(declare < delete);
    }
    assert!(ruleset.contains("table inet routeward_ks {}\ndelete table inet routeward_ks\n"));
    assert!(ruleset.contains("table inet routeward_ks {\n"));
    assert!(ruleset.contains("type filter hook output priority 0; policy drop;"));
    assert!(ruleset.contains("oif \"lo\" accept"));
    assert!(ruleset.contains("ct state established,related accept"));
    assert!(ruleset.contains(&format!(
        "udp sport {DHCP_V4_CLIENT_PORT} udp dport {DHCP_V4_SERVER_PORT} accept"
    )));
    assert!(ruleset.contains(&format!(
        "udp sport {DHCP_V6_CLIENT_PORT} udp dport {DHCP_V6_SERVER_PORT} accept"
    )));
    assert_eq!(
        (
            DHCP_V4_CLIENT_PORT,
            DHCP_V4_SERVER_PORT,
            DHCP_V6_CLIENT_PORT,
            DHCP_V6_SERVER_PORT
        ),
        (68, 67, 546, 547)
    );
    assert!(ruleset.contains(
        "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept"
    ));
    assert!(ruleset.contains("mld-listener-query"));
    assert!(ruleset.contains("mld2-listener-report"));
    assert!(!ruleset.contains('\''));
}

#[test]
fn watchdog_script_embeds_mode_protocol_and_block_transaction() {
    let spec = TproxyRoutingSpec {
        fwmark: 21080,
        route_table: 100,
        rule_priority: 10810,
        tproxy_port: 10854,
    };
    let wd = NftablesInterceptor::build_watchdog_cleanup_script("nft", "ip", "routeward", spec);
    assert!(
        wd.contains("mode=open; while read -r m; do case \"$m\" in open|block|disarm) mode=$m;;")
    );
    assert!(wd.contains("nft -f -"));
    assert!(wd.contains("policy drop"));
    assert!(wd.contains("nft delete table inet routeward_ks"));
    assert!(!wd.contains("cat >/dev/null"));
}

#[cfg(unix)]
mod watchdog_script_execution {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU32;

    static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

    /// Runs the real watchdog script against recording stub binaries, feeding it `lines` on
    /// stdin and then closing the pipe. Returns everything the stubs recorded.
    fn run_watchdog(lines: &[&str]) -> String {
        let dir = std::env::temp_dir().join(format!(
            "routeward-wd-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let log = dir.join("log.txt");
        for name in ["nft", "ip"] {
            let path = dir.join(name);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\necho \"{name} $*\" >> '{}'\nif [ \"$1\" = \"-f\" ]; then cat >> '{}'; fi\n",
                    log.display(),
                    log.display()
                ),
            )
            .expect("stub");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let spec = TproxyRoutingSpec {
            fwmark: 21080,
            route_table: 100,
            rule_priority: 10810,
            tproxy_port: 10854,
        };
        let script = NftablesInterceptor::build_watchdog_cleanup_script(
            &dir.join("nft").to_string_lossy(),
            &dir.join("ip").to_string_lossy(),
            "routeward",
            spec,
        );
        let mut child = Command::new("sh")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn watchdog");
        {
            let mut stdin = child.stdin.take().expect("stdin");
            for line in lines {
                stdin.write_all(line.as_bytes()).expect("write");
                stdin.write_all(b"\n").expect("write");
            }
        }
        assert!(child.wait().expect("wait").success());
        let recorded = std::fs::read_to_string(&log).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        recorded
    }

    #[test]
    fn block_mode_installs_block_table_and_removes_tproxy_routing() {
        let rec = run_watchdog(&["open", "block"]);
        assert!(rec.contains("-f -"), "{rec}");
        assert!(rec.contains("policy drop"), "{rec}");
        assert!(rec.contains("rule del fwmark 21080"), "{rec}");
        assert!(
            rec.contains("route del local 0.0.0.0/0 dev lo table 100"),
            "{rec}"
        );
    }

    #[test]
    fn last_valid_mode_wins_and_disarm_removes_everything() {
        let rec = run_watchdog(&["block", "disarm"]);
        assert!(!rec.contains("-f -"), "{rec}");
        assert!(rec.contains("delete table ip routeward"), "{rec}");
        assert!(rec.contains("delete table ip6 routeward"), "{rec}");
        assert!(rec.contains("delete table inet routeward_ks"), "{rec}");
    }

    #[test]
    fn open_mode_and_unknown_lines_fail_open() {
        let rec = run_watchdog(&["block", "open"]);
        assert!(!rec.contains("-f -"), "{rec}");
        assert!(rec.contains("delete table ip routeward"), "{rec}");
        let rec = run_watchdog(&["bogus", "BLOCK"]);
        assert!(!rec.contains("-f -"), "{rec}");
        let rec = run_watchdog(&[]);
        assert!(rec.contains("delete table inet routeward_ks"), "{rec}");
    }
}

#[cfg(target_os = "linux")]
mod failed_start_teardown {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU32;

    static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

    /// Builds an interceptor holding a fake active state: recording stub `nft`/`ip` binaries
    /// (`nft list tables` reports `listed_tables`) and a watchdog stand-in that records the
    /// mode lines it receives. Returns the interceptor, the temp dir, and the stub call log.
    fn interceptor_with_stubs(
        kill_switch_enabled: bool,
        listed_tables: &str,
    ) -> (NftablesInterceptor, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "routeward-teardown-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let log = dir.join("log.txt");
        let modes = dir.join("modes.txt");
        for name in ["nft", "ip"] {
            let path = dir.join(name);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\necho \"{name} $*\" >> '{}'\nif [ \"$1\" = \"list\" ]; then printf '%s\\n' '{listed_tables}'; fi\n",
                    log.display()
                ),
            )
            .expect("stub");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        let mut child = Command::new("sh")
            .args(["-c", &format!("cat >> '{}'", modes.display())])
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn watchdog stand-in");
        let stdin = child.stdin.take();
        let interceptor = NftablesInterceptor::new();
        interceptor.active.store(true, Ordering::SeqCst);
        *interceptor.state.lock() = Some(NftActiveState {
            nft_binary: dir.join("nft").to_string_lossy().into_owned(),
            ip_binary: dir.join("ip").to_string_lossy().into_owned(),
            table_name: "routeward".to_string(),
            tproxy_spec: TproxyRoutingSpec {
                fwmark: 21080,
                route_table: 100,
                rule_priority: 10810,
                tproxy_port: 10854,
            },
            ipv6_tproxy_active: false,
            watchdog_stdin: stdin,
            watchdog_child: Some(child),
            kill_switch_enabled,
            telemetry: TelemetryHub::new_with_logging(
                &crate::config::SystemConstants::load_embedded()
                    .expect("constants")
                    .telemetry,
                false,
            ),
        });
        (interceptor, dir, log)
    }

    #[test]
    fn failed_start_keeps_block_table_and_asks_watchdog_to_block() {
        let (interceptor, dir, log) =
            interceptor_with_stubs(true, "table inet routeward_ks\ntable ip routeward");
        interceptor.teardown_failed_start();
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let modes = std::fs::read_to_string(dir.join("modes.txt")).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!interceptor.is_active());
        assert_eq!(modes.trim(), "block", "{modes}");
        assert!(!modes.contains("disarm"), "{modes}");
        assert!(calls.contains("delete table ip routeward"), "{calls}");
        assert!(calls.contains("delete table ip6 routeward"), "{calls}");
        assert!(!calls.contains("delete table inet"), "{calls}");
        assert!(interceptor.state.lock().is_none());
    }

    #[test]
    fn failed_start_without_block_table_or_kill_switch_asks_watchdog_to_open() {
        for (kill_switch, listed) in [
            (true, "table ip routeward"),
            (false, "table inet routeward_ks"),
        ] {
            let (interceptor, dir, log) = interceptor_with_stubs(kill_switch, listed);
            interceptor.teardown_failed_start();
            let calls = std::fs::read_to_string(&log).unwrap_or_default();
            let modes = std::fs::read_to_string(dir.join("modes.txt")).unwrap_or_default();
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(modes.trim(), "open", "{modes}");
            assert!(!calls.contains("delete table inet"), "{calls}");
        }
    }

    #[test]
    fn drop_without_stop_never_sends_disarm() {
        let (interceptor, dir, log) = interceptor_with_stubs(true, "table inet routeward_ks");
        drop(interceptor);
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let modes = std::fs::read_to_string(dir.join("modes.txt")).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!modes.contains("disarm"), "{modes}");
        assert!(!calls.contains("delete table inet"), "{calls}");
    }

    #[test]
    fn explicit_stop_disarms_and_removes_block_table() {
        let (interceptor, dir, log) = interceptor_with_stubs(true, "table inet routeward_ks");
        interceptor.stop();
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let modes = std::fs::read_to_string(dir.join("modes.txt")).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(modes.trim(), "disarm", "{modes}");
        assert!(calls.contains("delete table inet routeward_ks"), "{calls}");
    }
}
