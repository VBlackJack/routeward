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
use crate::config::{ProxyChain, ProxyNode, ProxyProtocol, RoutingRule};
use chrono::Duration;

fn proxy(id: &str) -> ProxyNode {
    ProxyNode {
        id: id.to_string(),
        name: id.to_string(),
        protocol: ProxyProtocol::Socks5,
        host: "127.0.0.1".to_string(),
        port: 1080,
        auth: None,
        udp_enabled: true,
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

fn profile(rules: Vec<RoutingRule>, default_action: RuleAction) -> ProfileConfig {
    let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
    profile.rules = rules;
    profile.default_action = default_action;
    profile.security_policy = SecurityPolicyConfig::default();
    profile.proxies = vec![proxy("p1")];
    profile.chains = vec![];
    profile
}

fn request(protocol: TransportProtocol, port: u16) -> ConnectionRequest {
    ConnectionRequest {
        process_name: "chrome.exe".to_string(),
        process_path: Some("C:\\chrome.exe".to_string()),
        target_host: "93.184.216.34".to_string(),
        target_ip: Some("93.184.216.34".to_string()),
        target_port: port,
        protocol,
    }
}

fn report(id: &str, reachable: bool, udp: bool) -> ProxyHealthReport {
    ProxyHealthReport {
        proxy_id: id.to_string(),
        reachable,
        latency_ms: None,
        udp_supported: udp,
        exit_ip: None,
        error_detail: None,
    }
}

fn predict(
    p: &ProfileConfig,
    req: &ConnectionRequest,
    health: &[ProxyHealthReport],
) -> PredictedOutcome {
    predict_outcome(p, req, health)
}

#[test]
fn quic_is_blocked_even_when_a_rule_says_direct() {
    let p = profile(
        vec![rule("allow-all", 1, RuleAction::Direct)],
        RuleAction::Direct,
    );
    let out = predict(&p, &request(TransportProtocol::Udp, 443), &[]);
    assert_eq!(out.policy_override, Some(BlockReason::QuicBlocked));
    assert_eq!(out.evaluation.action, RuleAction::Block);
    assert_eq!(out.evaluation.matched_rule_name, QUIC_POLICY_RULE_NAME);
    assert_eq!(out.block_reason(), Some(BlockReason::QuicBlocked));

    let tcp = predict(&p, &request(TransportProtocol::Tcp, 443), &[]);
    assert_eq!(tcp.policy_override, None);
    assert_eq!(tcp.evaluation.action, RuleAction::Direct);
    assert_eq!(tcp.block_reason(), None);
}

#[test]
fn quic_override_follows_the_security_setting() {
    let mut p = profile(vec![], RuleAction::Direct);
    p.security_policy.block_quic_udp_443 = false;
    let out = predict(&p, &request(TransportProtocol::Udp, 443), &[]);
    assert_eq!(out.policy_override, None);
    assert_eq!(out.evaluation.action, RuleAction::Direct);
}

#[test]
fn encrypted_dns_is_blocked_on_tcp_and_udp_853() {
    let p = profile(vec![], RuleAction::Direct);
    for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
        let out = predict(&p, &request(protocol, 853), &[]);
        assert_eq!(out.policy_override, Some(BlockReason::EncryptedDnsBlocked));
        assert_eq!(out.evaluation.action, RuleAction::Block);
        assert_eq!(
            out.evaluation.matched_rule_name,
            ENCRYPTED_DNS_POLICY_RULE_NAME
        );
    }
    let mut off = p.clone();
    off.security_policy.block_encrypted_dns_bypass = false;
    assert_eq!(
        predict(&off, &request(TransportProtocol::Tcp, 853), &[]).policy_override,
        None
    );
}

#[test]
fn port_override_helper_matches_the_prediction() {
    let security = SecurityPolicyConfig::default();
    let ports = PolicyPorts::embedded();
    assert_eq!(ports.quic, 443);
    assert_eq!(ports.encrypted_dns, 853);
    let quic = port_policy_override(&security, ports, TransportProtocol::Udp, 443);
    assert_eq!(quic.map(|o| o.reason), Some(BlockReason::QuicBlocked));
    assert!(port_policy_override(&security, ports, TransportProtocol::Tcp, 443).is_none());
    assert!(port_policy_override(&security, ports, TransportProtocol::Any, 853).is_none());
}

#[test]
fn rule_block_and_default_block_have_distinct_reasons() {
    let blocked_by_rule = profile(vec![rule("deny", 1, RuleAction::Block)], RuleAction::Direct);
    let out = predict(&blocked_by_rule, &request(TransportProtocol::Tcp, 80), &[]);
    assert_eq!(out.policy_override, None);
    assert_eq!(out.block_reason(), Some(BlockReason::RuleBlock));

    let blocked_by_default = profile(vec![], RuleAction::Block);
    let out = predict(
        &blocked_by_default,
        &request(TransportProtocol::Tcp, 80),
        &[],
    );
    assert_eq!(out.block_reason(), Some(BlockReason::DefaultPolicyBlock));
}

#[test]
fn a_rule_appended_at_the_same_priority_loses_the_tie() {
    let p = profile(
        vec![
            rule("first-direct", 5, RuleAction::Direct),
            rule("appended-block", 5, RuleAction::Block),
        ],
        RuleAction::Block,
    );
    let out = predict(&p, &request(TransportProtocol::Tcp, 80), &[]);
    assert_eq!(out.evaluation.matched_rule_id, "first-direct");
    assert_eq!(out.evaluation.action, RuleAction::Direct);
    assert_eq!(out.block_reason(), None);

    let lower_number_wins = profile(
        vec![
            rule("direct", 5, RuleAction::Direct),
            rule("block", 4, RuleAction::Block),
        ],
        RuleAction::Direct,
    );
    let out = predict(
        &lower_number_wins,
        &request(TransportProtocol::Tcp, 80),
        &[],
    );
    assert_eq!(out.evaluation.matched_rule_id, "block");
}

#[test]
fn expired_rules_are_ignored_by_the_prediction() {
    let mut expired = rule("expired-block", 1, RuleAction::Block);
    expired.expires_at = Some(Utc::now() - Duration::minutes(1));
    let p = profile(vec![expired], RuleAction::Direct);
    let out = predict(&p, &request(TransportProtocol::Tcp, 80), &[]);
    assert_eq!(out.evaluation.action, RuleAction::Direct);

    let past = predict_outcome_at(
        &p,
        &request(TransportProtocol::Tcp, 80),
        &[],
        PolicyPorts::embedded(),
        Utc::now() - Duration::hours(1),
    );
    assert_eq!(past.evaluation.action, RuleAction::Block);
}

#[test]
fn unknown_process_is_blocked_by_the_kill_switch_or_the_configured_action() {
    let mut unknown = request(TransportProtocol::Tcp, 80);
    unknown.process_name = "system".to_string();

    let mut p = profile(vec![], RuleAction::Direct);
    p.security_policy.unknown_process_action = RuleAction::Direct;
    p.security_policy.kill_switch_enabled = true;
    let out = predict(&p, &unknown, &[]);
    assert_eq!(
        out.policy_override,
        Some(BlockReason::UnknownProcessKillSwitch)
    );
    assert_eq!(out.evaluation.action, RuleAction::Block);
    assert_eq!(out.evaluation.matched_rule_id, UNKNOWN_PROCESS_RULE_ID);

    p.security_policy.unknown_process_action = RuleAction::Block;
    let out = predict(&p, &unknown, &[]);
    assert_eq!(out.policy_override, Some(BlockReason::UnknownProcessPolicy));

    p.security_policy.unknown_process_action = RuleAction::Direct;
    p.security_policy.kill_switch_enabled = false;
    let out = predict(&p, &unknown, &[]);
    assert_eq!(out.policy_override, None);
    assert_eq!(out.evaluation.action, RuleAction::Direct);

    let mut by_path = request(TransportProtocol::Tcp, 80);
    by_path.process_path = Some("pid:4242".to_string());
    assert!(is_unattributed_request(&by_path));
    assert!(!is_unattributed_request(&request(
        TransportProtocol::Tcp,
        80
    )));
}

#[test]
fn unknown_process_with_a_non_direct_rule_keeps_the_rule_action() {
    let mut unknown = request(TransportProtocol::Tcp, 80);
    unknown.process_name = "system".to_string();
    let p = profile(vec![rule("deny", 1, RuleAction::Block)], RuleAction::Direct);
    let out = predict(&p, &unknown, &[]);
    assert_eq!(out.evaluation.matched_rule_id, "deny");
    assert_eq!(out.policy_override, None);
    assert_eq!(out.block_reason(), Some(BlockReason::RuleBlock));
}

#[test]
fn kill_switch_predicts_a_block_for_an_unreachable_proxy() {
    let p = profile(
        vec![rule(
            "via-proxy",
            1,
            RuleAction::Proxy {
                target_id: "p1".to_string(),
            },
        )],
        RuleAction::Direct,
    );
    let req = request(TransportProtocol::Tcp, 80);

    let down = predict(&p, &req, &[report("p1", false, true)]);
    assert_eq!(
        down.policy_override,
        Some(BlockReason::KillSwitchProxyUnreachable)
    );
    assert!(matches!(down.evaluation.action, RuleAction::Proxy { .. }));
    assert_eq!(
        down.block_reason(),
        Some(BlockReason::KillSwitchProxyUnreachable)
    );

    let healthy = predict(&p, &req, &[report("p1", true, true)]);
    assert_eq!(healthy.policy_override, None);

    let unknown_health = predict(&p, &req, &[]);
    assert_eq!(unknown_health.policy_override, None);

    let mut ks_off = p.clone();
    ks_off.security_policy.kill_switch_enabled = false;
    let off = predict(&ks_off, &req, &[report("p1", false, true)]);
    assert_eq!(off.policy_override, None);
}

#[test]
fn kill_switch_predicts_udp_without_udp_support() {
    let p = profile(
        vec![rule(
            "via-proxy",
            1,
            RuleAction::Proxy {
                target_id: "p1".to_string(),
            },
        )],
        RuleAction::Direct,
    );
    let udp = request(TransportProtocol::Udp, 5000);
    let out = predict(&p, &udp, &[report("p1", true, false)]);
    assert_eq!(
        out.policy_override,
        Some(BlockReason::KillSwitchUdpUnsupported)
    );
    let tcp = request(TransportProtocol::Tcp, 5000);
    assert_eq!(
        predict(&p, &tcp, &[report("p1", true, false)]).policy_override,
        None
    );
}

#[test]
fn kill_switch_predicts_a_missing_proxy_or_broken_chain() {
    let missing = profile(
        vec![rule(
            "ghost",
            1,
            RuleAction::Proxy {
                target_id: "nope".to_string(),
            },
        )],
        RuleAction::Direct,
    );
    let req = request(TransportProtocol::Tcp, 80);
    assert_eq!(
        predict(&missing, &req, &[]).policy_override,
        Some(BlockReason::KillSwitchProxyMisconfigured)
    );

    let mut chained = profile(
        vec![rule(
            "chain",
            1,
            RuleAction::Chain {
                target_id: "c1".to_string(),
            },
        )],
        RuleAction::Direct,
    );
    assert_eq!(
        predict(&chained, &req, &[]).policy_override,
        Some(BlockReason::KillSwitchProxyMisconfigured)
    );
    chained.chains = vec![ProxyChain {
        id: "c1".to_string(),
        name: "c1".to_string(),
        strategy: Default::default(),
        proxy_ids: vec!["p1".to_string()],
        enabled: true,
    }];
    assert_eq!(predict(&chained, &req, &[]).policy_override, None);
    assert_eq!(
        predict(&chained, &req, &[report("p1", false, true)]).policy_override,
        Some(BlockReason::KillSwitchProxyUnreachable)
    );
}

#[test]
fn block_reason_helpers_classify_rule_ids_and_names() {
    assert_eq!(
        block_reason_for_rule(DEFAULT_FALLBACK_RULE_ID),
        BlockReason::DefaultPolicyBlock
    );
    assert_eq!(
        block_reason_for_rule(FAKE_IP_UNMAPPED_RULE_ID),
        BlockReason::FakeIpEgressGuard
    );
    assert_eq!(block_reason_for_rule("custom"), BlockReason::RuleBlock);
    assert_eq!(
        block_reason_for_decision(None, QUIC_POLICY_RULE_NAME),
        BlockReason::QuicBlocked
    );
    assert_eq!(
        block_reason_for_decision(None, ENCRYPTED_DNS_POLICY_RULE_NAME),
        BlockReason::EncryptedDnsBlocked
    );
    assert_eq!(
        block_reason_for_decision(None, UNKNOWN_PROCESS_KILL_SWITCH_RULE_NAME),
        BlockReason::UnknownProcessKillSwitch
    );
    assert_eq!(
        block_reason_for_decision(Some("x"), "Some Rule"),
        BlockReason::RuleBlock
    );
    assert_eq!(
        block_reason_for_decision(None, DEFAULT_FALLBACK_RULE_NAME),
        BlockReason::DefaultPolicyBlock
    );
    assert_eq!(
        upstream_proxy_id(&RuleAction::Proxy {
            target_id: "p".to_string()
        })
        .as_deref(),
        Some("p")
    );
    assert_eq!(
        upstream_proxy_id(&RuleAction::Chain {
            target_id: "c".to_string()
        }),
        None
    );
}

#[test]
fn predicted_outcome_json_uses_camel_case_and_skips_an_absent_override() {
    let p = profile(vec![], RuleAction::Direct);
    let allowed = predict(&p, &request(TransportProtocol::Tcp, 80), &[]);
    let value = serde_json::to_value(&allowed).expect("to_value");
    assert!(value.get("policyOverride").is_none());
    assert!(value.get("evaluation").is_some());

    let blocked = predict(&p, &request(TransportProtocol::Udp, 443), &[]);
    let value = serde_json::to_value(&blocked).expect("to_value");
    assert_eq!(value["policyOverride"], "quicBlocked");
}
