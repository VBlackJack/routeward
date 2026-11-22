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

//! The relays record the reason `predict_outcome` announces, and the expiry sweeper removes
//! only what expired.

use super::policy::{predict_outcome, ENCRYPTED_DNS_POLICY_RULE_NAME};
use super::*;
use crate::config::{
    ProfileConfig, ProxyNode, ProxyProtocol, RoutingRule, RuleAction, SystemConstants,
    TransportProtocol,
};
use crate::interceptor::nat::{NatSessionEntry, PidResolutionSource};
use crate::proxy::udp::Socks5UdpTarget;
use crate::rules::ConnectionRequest;
use crate::telemetry::BlockedRecord;
use crate::telemetry::{BlockReason, ConnectionStatus};
use chrono::{Duration as ChronoDuration, Utc};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn proxy(id: &str, port: u16) -> ProxyNode {
    ProxyNode {
        id: id.to_string(),
        name: id.to_string(),
        protocol: ProxyProtocol::Socks5,
        host: "127.0.0.1".to_string(),
        port,
        auth: None,
        udp_enabled: false,
        tls: false,
        tls_skip_verify: false,
        sni: None,
        enabled: true,
        last_latency_ms: None,
        exit_ip: None,
    }
}

fn rule(id: &str, priority: i32, action: RuleAction) -> RoutingRule {
    RoutingRule {
        id: id.to_string(),
        name: format!("rule {id}"),
        enabled: true,
        priority,
        process_patterns: vec![],
        domain_patterns: vec![],
        ip_cidrs: vec![],
        port_ranges: vec![],
        protocol: TransportProtocol::Any,
        action,
        expires_at: None,
    }
}

fn controller_with(profile_edit: impl FnOnce(&mut ProfileConfig)) -> RouteWardController {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.enable_logging = false;
    profile.rules.clear();
    profile.default_action = RuleAction::Direct;
    profile_edit(&mut profile);
    RouteWardController::new(constants, profile, "en")
}

fn blocked_records(controller: &RouteWardController) -> Vec<crate::telemetry::TrackedConnection> {
    controller
        .telemetry
        .list_connections()
        .into_iter()
        .filter(|c| c.status == ConnectionStatus::Blocked)
        .collect()
}

fn udp_request(port: u16) -> ConnectionRequest {
    ConnectionRequest {
        process_name: "udp-client".to_string(),
        process_path: Some("/bin/udp-client".to_string()),
        target_host: "203.0.113.10".to_string(),
        target_ip: Some("203.0.113.10".to_string()),
        target_port: port,
        protocol: TransportProtocol::Udp,
    }
}

async fn send_udp(controller: &RouteWardController, port: u16) -> bool {
    let client: SocketAddr = "127.0.0.1:50001".parse().expect("client");
    let target = Socks5UdpTarget::Ipv4(Ipv4Addr::new(203, 0, 113, 10), port);
    controller
        .forward_udp_datagram(
            client,
            "udp-client",
            Some("/bin/udp-client"),
            4242,
            &target,
            b"x",
            false,
        )
        .await
        .is_err()
}

#[tokio::test]
async fn udp_relay_and_predict_outcome_agree_on_the_security_overrides() {
    let controller = controller_with(|p| p.rules = vec![rule("allow-all", 1, RuleAction::Direct)]);
    let profile = controller.profile.read().clone();

    for (port, expected) in [
        (443u16, BlockReason::QuicBlocked),
        (853u16, BlockReason::EncryptedDnsBlocked),
    ] {
        let predicted = predict_outcome(&profile, &udp_request(port), &[]);
        assert_eq!(predicted.policy_override, Some(expected), "port {port}");
        assert!(send_udp(&controller, port).await, "port {port} must fail");
        let record = blocked_records(&controller)
            .into_iter()
            .find(|c| c.target_port == port)
            .unwrap_or_else(|| panic!("no blocked record for port {port}"));
        assert_eq!(record.block_reason, Some(expected));
        assert_eq!(record.route_label, ROUTE_BLOCK_LABEL);
        assert_eq!(record.matched_rule, predicted.evaluation.matched_rule_name);
        assert_eq!(
            record.matched_rule_id.as_deref(),
            Some(predicted.evaluation.matched_rule_id.as_str())
        );
    }
}

#[tokio::test]
async fn repeated_blocked_datagrams_of_one_flow_make_one_record_and_a_counted_summary() {
    let controller = controller_with(|_| {});
    for _ in 0..3 {
        assert!(send_udp(&controller, 443).await);
    }
    assert_eq!(blocked_records(&controller).len(), 1);
    let summary = controller.telemetry.blocked_summary();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].count, 3);
    assert_eq!(summary[0].block_reason, BlockReason::QuicBlocked);
    assert_eq!(summary[0].destination, "203.0.113.10");
    // The summary points at the one stored row, never at a datagram that was only counted.
    let stored = blocked_records(&controller);
    assert_eq!(summary[0].last_connection_id, stored[0].id);
}

#[test]
fn simulated_blocked_records_are_not_counted_in_the_blocked_total() {
    let controller = controller_with(|p| p.default_action = RuleAction::Block);
    let before = controller.telemetry.snapshot().blocked_count;
    let simulated = controller.simulate_connection(udp_request(6000));
    assert!(simulated.simulated);
    assert_eq!(controller.telemetry.snapshot().blocked_count, before);
    assert!(controller.telemetry.blocked_summary().is_empty());
}

#[test]
fn local_name_guard_flows_are_told_apart_by_the_name_asked() {
    let controller = controller_with(|_| {});
    let client: SocketAddr = "192.168.1.20:5353".parse().expect("client");
    let ask = |qname: &str| {
        controller.record_blocked_udp(
            client,
            BlockedRecord::new(
                BlockReason::LocalNameGuard,
                TransportProtocol::Udp,
                "LocalNameGuard:mDNS",
            )
            .process("mdns", "mdns", 0)
            .target("224.0.0.251", 5353)
            .with_ip(Some("224.0.0.251".to_string()))
            .with_domain(Some(qname.to_string())),
        );
    };
    ask("secret.example.com");
    ask("secret.example.com");
    ask("other.example.com");
    assert_eq!(blocked_records(&controller).len(), 2);
    let counts: u64 = controller
        .telemetry
        .blocked_summary()
        .iter()
        .map(|s| s.count)
        .sum();
    assert_eq!(counts, 3);
}

#[tokio::test]
async fn udp_rule_block_and_default_block_report_their_own_reasons() {
    let controller = controller_with(|p| {
        p.rules = vec![rule("deny-5000", 1, RuleAction::Block)];
        p.rules[0].port_ranges = vec![crate::config::PortRange {
            start: 5000,
            end: 5000,
        }];
        p.default_action = RuleAction::Block;
    });
    let profile = controller.profile.read().clone();
    assert!(send_udp(&controller, 5000).await);
    assert!(send_udp(&controller, 6000).await);
    let records = blocked_records(&controller);
    let by_port = |port: u16| {
        records
            .iter()
            .find(|c| c.target_port == port)
            .and_then(|c| c.block_reason)
    };
    assert_eq!(by_port(5000), Some(BlockReason::RuleBlock));
    assert_eq!(by_port(6000), Some(BlockReason::DefaultPolicyBlock));
    assert_eq!(
        predict_outcome(&profile, &udp_request(5000), &[]).block_reason(),
        Some(BlockReason::RuleBlock)
    );
    assert_eq!(
        predict_outcome(&profile, &udp_request(6000), &[]).block_reason(),
        Some(BlockReason::DefaultPolicyBlock)
    );
    let rule_entry = controller
        .telemetry
        .blocked_summary()
        .into_iter()
        .find(|s| s.target_port == 5000)
        .expect("summary entry for the rule block");
    assert_eq!(rule_entry.matched_rule_id.as_deref(), Some("deny-5000"));
}

#[tokio::test]
async fn socks5_encrypted_dns_block_matches_predict_outcome() {
    let controller = std::sync::Arc::new(controller_with(|_| {}));
    let profile = controller.profile.read().clone();
    let predicted = predict_outcome(
        &profile,
        &ConnectionRequest {
            process_name: "dot-client".to_string(),
            process_path: None,
            target_host: "203.0.113.10".to_string(),
            target_ip: Some("203.0.113.10".to_string()),
            target_port: 853,
            protocol: TransportProtocol::Tcp,
        },
        &[],
    );
    assert_eq!(
        predicted.policy_override,
        Some(BlockReason::EncryptedDnsBlocked)
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks");
    let addr = listener.local_addr().expect("addr");
    let client_task = tokio::spawn(async move {
        let mut s = TcpStream::connect(addr).await.expect("connect socks");
        s.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await.expect("method reply");
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 203, 0, 113, 10];
        req.extend_from_slice(&853u16.to_be_bytes());
        s.write_all(&req).await.expect("connect request");
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.expect("failure reply");
        reply
    });
    let (stream, peer) = listener.accept().await.expect("accept");
    controller
        .handle_local_socks5_client(stream, peer.port())
        .await
        .expect("a policy block closes the session cleanly");
    let reply = client_task.await.expect("client join");
    assert_eq!(reply[1], 0x01);

    let records = blocked_records(&controller);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].block_reason,
        Some(BlockReason::EncryptedDnsBlocked)
    );
    assert_eq!(records[0].matched_rule, ENCRYPTED_DNS_POLICY_RULE_NAME);
    assert_eq!(records[0].protocol, TransportProtocol::Tcp);
    assert_eq!(records[0].target_ip.as_deref(), Some("203.0.113.10"));
    let logs = controller.telemetry.list_logs();
    let line = logs
        .iter()
        .find(|l| l.message.contains("Blocked encrypted DNS bypass"))
        .expect("DoT log line");
    let ctx = line
        .context
        .as_ref()
        .expect("the block log carries context");
    assert_eq!(
        ctx.connection_id.as_deref(),
        Some(records[0].id.as_str()),
        "the log context points at the recorded connection"
    );
    assert_eq!(ctx.port, Some(853));
}

#[tokio::test]
async fn kill_switch_block_carries_the_upstream_failure_and_the_proxy() {
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let controller = std::sync::Arc::new(controller_with(|p| {
        p.security_policy.kill_switch_enabled = true;
        p.proxies = vec![proxy("proxy-dead", dead_port)];
    }));

    let relay = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let client = TcpStream::connect(relay.local_addr().expect("relay addr"))
        .await
        .expect("connect");
    let peer = client.local_addr().expect("peer");
    let (server_stream, accepted) = relay.accept().await.expect("accept");
    assert_eq!(peer, accepted);
    controller.nat_table.insert_session(NatSessionEntry {
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port: peer.port(),
        orig_dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        orig_dst_port: 9,
        pid: 4242,
        process_name: "curl.exe".to_string(),
        process_path: "C:\\curl.exe".to_string(),
        resolution_source: PidResolutionSource::SocketLayer,
        action: RuleAction::Proxy {
            target_id: "proxy-dead".to_string(),
        },
        matched_rule_name: "Rule-Proxy-Dead".to_string(),
        created_at: std::time::Instant::now(),
    });
    let reader = tokio::spawn(async move {
        let mut client = client;
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
    });
    let res = controller
        .handle_transparent_tcp_client(server_stream, accepted)
        .await;
    reader.await.expect("reader");
    assert!(res.is_err());

    let records = blocked_records(&controller);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(
        record.block_reason,
        Some(BlockReason::KillSwitchProxyRefused)
    );
    assert_eq!(record.proxy_id.as_deref(), Some("proxy-dead"));
    assert!(record.error_detail.is_some());
    assert_eq!(record.route_label, ROUTE_BLOCK_LABEL);
    let summary = controller.telemetry.blocked_summary();
    assert_eq!(summary[0].proxy_id.as_deref(), Some("proxy-dead"));
    assert!(summary[0].last_error_detail.is_some());
}

#[tokio::test]
async fn transparent_session_block_reason_follows_the_policy_name_not_only_the_rule_id() {
    let controller = std::sync::Arc::new(controller_with(|_| {}));
    let relay = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let client = TcpStream::connect(relay.local_addr().expect("relay addr"))
        .await
        .expect("connect");
    let (server_stream, accepted) = relay.accept().await.expect("accept");
    controller.nat_table.insert_session(NatSessionEntry {
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port: accepted.port(),
        orig_dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        orig_dst_port: 9,
        pid: 4242,
        process_name: "curl.exe".to_string(),
        process_path: r"C:\curl.exe".to_string(),
        resolution_source: PidResolutionSource::SocketLayer,
        action: RuleAction::Block,
        matched_rule_name: crate::rules::DEFAULT_FALLBACK_RULE_NAME.to_string(),
        created_at: std::time::Instant::now(),
    });
    let reader = tokio::spawn(async move {
        let mut client = client;
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
    });
    let _ = controller
        .handle_transparent_tcp_client(server_stream, accepted)
        .await;
    reader.await.expect("reader");
    let records = blocked_records(&controller);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].block_reason,
        Some(BlockReason::DefaultPolicyBlock)
    );
}

#[tokio::test]
async fn direct_udp_kill_switch_reports_a_kill_switch_reason_with_detail() {
    use crate::dns::codec::{build_rcode_response, parse_dns_query, RCODE_SERVFAIL};
    use tokio::net::UdpSocket;

    let servfail = UdpSocket::bind("127.0.0.1:0").await.expect("bind dns");
    let servfail_addr = servfail.local_addr().expect("dns addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = servfail.recv_from(&mut buf).await {
            if let Ok(q) = parse_dns_query(&buf[..n]) {
                let resp = build_rcode_response(&q, RCODE_SERVFAIL);
                let _ = servfail.send_to(&resp, peer).await;
            }
        }
    });

    let controller = controller_with(|p| p.security_policy.kill_switch_enabled = true);
    *controller.system_resolvers_override.write() = Some(vec![servfail_addr]);
    let fake_ip = controller
        .dns
        .allocate_or_get("unresolvable.routeward.test")
        .expect("fake ip");
    let client: SocketAddr = "10.0.2.15:55124".parse().expect("client");
    let res = controller
        .forward_udp_datagram(
            client,
            "ntp.exe",
            Some("C:\\ntp.exe"),
            7,
            &Socks5UdpTarget::Ipv4(fake_ip, 123),
            b"probe",
            false,
        )
        .await;
    assert!(res.is_err());
    let record = blocked_records(&controller)
        .into_iter()
        .find(|c| c.target_port == 123)
        .expect("blocked record");
    assert_eq!(
        record.block_reason,
        Some(BlockReason::KillSwitchDirectUdpFailed)
    );
    assert!(record.error_detail.is_some());
}

#[tokio::test]
async fn udp_through_a_tcp_only_proxy_is_not_a_proxy_outage_with_the_kill_switch_off() {
    let controller = controller_with(|p| {
        p.security_policy.kill_switch_enabled = false;
        p.security_policy.block_udp_on_tcp_only_proxy = true;
        p.proxies = vec![proxy("tcp-only", 1)];
        p.rules = vec![rule(
            "via-proxy",
            1,
            RuleAction::Proxy {
                target_id: "tcp-only".to_string(),
            },
        )];
    });
    let client: SocketAddr = "10.0.2.15:55200".parse().expect("client");
    let res = controller
        .forward_udp_datagram(
            client,
            "game.exe",
            Some(r"C:\game.exe"),
            9,
            &Socks5UdpTarget::Ipv4(Ipv4Addr::new(203, 0, 113, 10), 5000),
            b"probe",
            false,
        )
        .await;
    assert!(res.is_err());
    let record = blocked_records(&controller)
        .into_iter()
        .find(|c| c.target_port == 5000)
        .expect("blocked record");
    let reason = record.block_reason.expect("reason");
    assert_eq!(reason, BlockReason::UdpProxyUnsupported);
    assert!(!reason.is_kill_switch_proxy());
}

#[test]
fn the_dns_resolution_action_skips_an_expired_proxy_rule() {
    let controller = controller_with(|p| {
        p.dns_config.remote_dns_resolution = true;
        p.proxies = vec![proxy("live", 1)];
        let mut expired = rule(
            "expired-proxy",
            1,
            RuleAction::Proxy {
                target_id: "gone".to_string(),
            },
        );
        expired.process_patterns = vec!["nothing.exe".to_string()];
        expired.expires_at = Some(Utc::now() - ChronoDuration::minutes(1));
        let mut live = rule(
            "live-proxy",
            2,
            RuleAction::Proxy {
                target_id: "live".to_string(),
            },
        );
        live.process_patterns = vec!["nothing.exe".to_string()];
        p.rules = vec![expired, live];
    });
    assert_eq!(
        controller.select_dns_resolution_action("example.com"),
        RuleAction::Proxy {
            target_id: "live".to_string()
        }
    );
}

#[test]
fn simulate_connection_applies_the_overrides_and_marks_the_record_simulated() {
    let controller = controller_with(|p| p.rules = vec![rule("allow-all", 1, RuleAction::Direct)]);
    let blocked = controller.simulate_connection(udp_request(443));
    assert_eq!(blocked.status, ConnectionStatus::Blocked);
    assert_eq!(blocked.block_reason, Some(BlockReason::QuicBlocked));
    assert!(blocked.simulated);
    assert_eq!(blocked.route_label, ROUTE_BLOCK_LABEL);

    let allowed = controller.simulate_connection(ConnectionRequest {
        target_port: 8080,
        ..udp_request(8080)
    });
    assert_eq!(allowed.status, ConnectionStatus::Active);
    assert!(allowed.simulated);
    assert_eq!(allowed.block_reason, None);
    assert_eq!(allowed.matched_rule_id.as_deref(), Some("allow-all"));

    assert!(
        controller.telemetry.blocked_summary().is_empty(),
        "simulations never enter the blocked summary"
    );
}

#[test]
fn scanned_os_sockets_are_marked_simulated() {
    let controller = controller_with(|_| {});
    for conn in controller.scan_and_ingest_os_sockets(32) {
        assert!(conn.simulated, "{}", conn.id);
    }
    assert!(controller.telemetry.blocked_summary().is_empty());
}

#[test]
fn the_sweeper_removes_only_expired_rules_and_notifies() {
    let controller = controller_with(|_| {});
    let now = Utc::now();
    let mut gone = rule("gone", 1, RuleAction::Block);
    gone.expires_at = Some(now - ChronoDuration::seconds(5));
    let mut later = rule("later", 2, RuleAction::Direct);
    later.expires_at = Some(now + ChronoDuration::minutes(15));
    let forever = rule("forever", 3, RuleAction::Direct);
    for r in [gone, later, forever] {
        controller.upsert_rule(r);
    }
    let mut notices = controller.subscribe_rule_expiry();

    let removed = controller.sweep_expired_rules(now);
    assert_eq!(removed, vec!["gone".to_string()]);
    let ids: Vec<String> = controller
        .profile
        .read()
        .rules
        .iter()
        .map(|r| r.id.clone())
        .collect();
    assert_eq!(ids, vec!["later".to_string(), "forever".to_string()]);
    assert_eq!(
        notices.try_recv().expect("notice"),
        vec!["gone".to_string()]
    );
    assert!(controller
        .telemetry
        .list_logs()
        .iter()
        .any(|l| l.message.contains("expired temporary rule")));

    assert!(controller.sweep_expired_rules(now).is_empty());
    let removed_later = controller.sweep_expired_rules(now + ChronoDuration::minutes(16));
    assert_eq!(removed_later, vec!["later".to_string()]);
    assert!(notices.try_recv().is_ok());
}

#[test]
fn unattributed_drop_counters_start_at_zero() {
    let controller = controller_with(|_| {});
    let counters = controller.unattributed_drop_counters();
    assert_eq!(counters.dropped_unattributed_syn, 0);
    assert_eq!(counters.dropped_unattributed_udp, 0);
    controller.nat_table.record_dropped_unattributed_syn();
    controller.nat_table.record_dropped_unattributed_udp();
    controller.nat_table.record_dropped_unattributed_udp();
    let counters = controller.unattributed_drop_counters();
    assert_eq!(counters.dropped_unattributed_syn, 1);
    assert_eq!(counters.dropped_unattributed_udp, 2);
}
