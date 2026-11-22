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
use crate::error::{
    ERR_KEY_AUTH_REJECTED, ERR_KEY_CHAIN_EMPTY, ERR_KEY_CONNECTION_TIMEOUT,
    ERR_KEY_HANDSHAKE_FAILED, ERR_KEY_INVALID_URI, ERR_KEY_PROXY_NOT_FOUND,
    ERR_KEY_UDP_NOT_SUPPORTED,
};
use std::io::{Error, ErrorKind};

fn record(reason: BlockReason) -> BlockedRecord {
    BlockedRecord::new(reason, TransportProtocol::Tcp, "Rule A")
        .process("Chrome.exe", "C:\\chrome.exe", 42)
        .target("example.com", 443)
}

#[test]
fn every_reason_serializes_to_its_contract_name() {
    let cases = [
        (BlockReason::RuleBlock, "ruleBlock"),
        (BlockReason::DefaultPolicyBlock, "defaultPolicyBlock"),
        (
            BlockReason::KillSwitchProxyUnreachable,
            "killSwitchProxyUnreachable",
        ),
        (
            BlockReason::KillSwitchProxyRefused,
            "killSwitchProxyRefused",
        ),
        (
            BlockReason::KillSwitchProxyTimeout,
            "killSwitchProxyTimeout",
        ),
        (
            BlockReason::KillSwitchProxyAuthRejected,
            "killSwitchProxyAuthRejected",
        ),
        (
            BlockReason::KillSwitchProxyHandshake,
            "killSwitchProxyHandshake",
        ),
        (
            BlockReason::KillSwitchProxyMisconfigured,
            "killSwitchProxyMisconfigured",
        ),
        (
            BlockReason::KillSwitchUdpUnsupported,
            "killSwitchUdpUnsupported",
        ),
        (
            BlockReason::KillSwitchDirectUdpFailed,
            "killSwitchDirectUdpFailed",
        ),
        (BlockReason::FragmentedUdpBlocked, "fragmentedUdpBlocked"),
        (BlockReason::UnknownProcessPolicy, "unknownProcessPolicy"),
        (
            BlockReason::UnknownProcessKillSwitch,
            "unknownProcessKillSwitch",
        ),
        (BlockReason::FakeIpEgressGuard, "fakeIpEgressGuard"),
        (BlockReason::QuicBlocked, "quicBlocked"),
        (BlockReason::EncryptedDnsBlocked, "encryptedDnsBlocked"),
        (BlockReason::LocalNameGuard, "localNameGuard"),
        (
            BlockReason::DnsServerBlockedByRule,
            "dnsServerBlockedByRule",
        ),
        (BlockReason::Unknown, "unknown"),
    ];
    for (reason, name) in cases {
        let json = serde_json::to_string(&reason).expect("serialize");
        assert_eq!(json, format!("\"{name}\""));
        let back: BlockReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, reason);
    }
}

#[test]
fn unknown_reason_from_a_newer_version_deserializes_to_unknown() {
    let back: BlockReason = serde_json::from_str("\"somethingNew\"").expect("deserialize");
    assert_eq!(back, BlockReason::Unknown);
}

#[test]
fn upstream_errors_map_to_their_kill_switch_reason() {
    let cases = [
        (
            RouteWardError::ConnectionTimeout {
                key: ERR_KEY_CONNECTION_TIMEOUT,
            },
            BlockReason::KillSwitchProxyTimeout,
        ),
        (
            RouteWardError::AuthenticationRejected {
                key: ERR_KEY_AUTH_REJECTED,
            },
            BlockReason::KillSwitchProxyAuthRejected,
        ),
        (
            RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: "bad".into(),
            },
            BlockReason::KillSwitchProxyHandshake,
        ),
        (
            RouteWardError::UdpAssociateUnsupported {
                key: ERR_KEY_UDP_NOT_SUPPORTED,
                proxy_id: "p".into(),
            },
            BlockReason::KillSwitchUdpUnsupported,
        ),
        (
            RouteWardError::ProxyNotFound {
                key: ERR_KEY_PROXY_NOT_FOUND,
                proxy_id: "p".into(),
            },
            BlockReason::KillSwitchProxyMisconfigured,
        ),
        (
            RouteWardError::EmptyProxyChain {
                key: ERR_KEY_CHAIN_EMPTY,
            },
            BlockReason::KillSwitchProxyMisconfigured,
        ),
        (
            RouteWardError::InvalidProxyUri {
                key: ERR_KEY_INVALID_URI,
                uri: "x".into(),
            },
            BlockReason::KillSwitchProxyMisconfigured,
        ),
        (
            RouteWardError::Io(Error::from(ErrorKind::ConnectionRefused)),
            BlockReason::KillSwitchProxyRefused,
        ),
        (
            RouteWardError::Io(Error::from(ErrorKind::TimedOut)),
            BlockReason::KillSwitchProxyTimeout,
        ),
        (
            RouteWardError::Io(Error::from(ErrorKind::ConnectionReset)),
            BlockReason::KillSwitchProxyUnreachable,
        ),
        (
            RouteWardError::BlockedByPolicy {
                key: ERR_KEY_RULE_BLOCKED,
                rule_name: "SecurityPolicy:FakeIpEgressGuard".into(),
            },
            BlockReason::FakeIpEgressGuard,
        ),
        (
            RouteWardError::BlockedByPolicy {
                key: ERR_KEY_RULE_BLOCKED,
                rule_name: "My rule".into(),
            },
            BlockReason::RuleBlock,
        ),
        (
            RouteWardError::DaemonError {
                key: "k",
                detail: "d".into(),
            },
            BlockReason::KillSwitchProxyUnreachable,
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(BlockReason::from_upstream_error(&err), expected, "{err}");
    }
}

#[test]
fn kill_switch_proxy_reasons_are_flagged() {
    assert!(BlockReason::KillSwitchProxyRefused.is_kill_switch_proxy());
    assert!(BlockReason::KillSwitchUdpUnsupported.is_kill_switch_proxy());
    assert!(!BlockReason::KillSwitchDirectUdpFailed.is_kill_switch_proxy());
    assert!(!BlockReason::RuleBlock.is_kill_switch_proxy());
}

#[test]
fn builder_sets_status_label_and_reason() {
    let conn = TrackedConnection::blocked(
        record(BlockReason::KillSwitchProxyRefused)
            .with_rule_id("rule-a")
            .with_proxy(Some("proxy-1".into()))
            .with_ip(Some("93.184.216.34".into()))
            .with_domain(Some("example.com".into()))
            .with_error("refused")
            .with_tx_bytes(7),
    );
    assert_eq!(conn.status, ConnectionStatus::Blocked);
    assert_eq!(conn.route_label, ROUTE_BLOCK_LABEL);
    assert_eq!(conn.block_reason, Some(BlockReason::KillSwitchProxyRefused));
    assert_eq!(conn.matched_rule_id.as_deref(), Some("rule-a"));
    assert_eq!(conn.proxy_id.as_deref(), Some("proxy-1"));
    assert_eq!(conn.target_ip.as_deref(), Some("93.184.216.34"));
    assert_eq!(conn.resolved_domain.as_deref(), Some("example.com"));
    assert_eq!(conn.error_detail.as_deref(), Some("refused"));
    assert_eq!(conn.tx_bytes, 7);
    assert_eq!(conn.rx_bytes, 0);
    assert!(!conn.simulated);
    assert!(!conn.id.is_empty());
}

#[test]
fn tracked_connection_json_round_trips_and_skips_empty_fields() {
    let plain = TrackedConnection::blocked(record(BlockReason::RuleBlock));
    let value = serde_json::to_value(&plain).expect("to_value");
    assert_eq!(value["blockReason"], "ruleBlock");
    assert!(value.get("proxyId").is_none());
    assert!(value.get("matchedRuleId").is_none());
    assert!(value.get("targetIp").is_none());
    assert!(value.get("simulated").is_none());

    let sim = TrackedConnection::blocked(
        record(BlockReason::QuicBlocked)
            .with_rule_id("r")
            .with_proxy(Some("p".into()))
            .with_ip(Some("1.2.3.4".into()))
            .simulated(),
    );
    let json = serde_json::to_string(&sim).expect("to_string");
    assert!(json.contains("\"simulated\":true"));
    let back: TrackedConnection = serde_json::from_str(&json).expect("from_str");
    assert_eq!(back.block_reason, Some(BlockReason::QuicBlocked));
    assert_eq!(back.matched_rule_id.as_deref(), Some("r"));
    assert_eq!(back.proxy_id.as_deref(), Some("p"));
    assert_eq!(back.target_ip.as_deref(), Some("1.2.3.4"));
    assert!(back.simulated);
}

#[test]
fn legacy_json_without_the_new_fields_deserializes() {
    let legacy = r#"{"id":"a","pid":1,"processName":"x","processPath":"/x","targetHost":"h",
        "resolvedDomain":null,"targetPort":80,"protocol":"tcp","matchedRule":"r",
        "routeLabel":"BLOCKED","latencyMs":0,"rxBytes":0,"txBytes":0,"status":"blocked",
        "startedAt":"2026-01-01T00:00:00Z"}"#;
    let conn: TrackedConnection = serde_json::from_str(legacy).expect("legacy json");
    assert_eq!(conn.block_reason, None);
    assert!(!conn.simulated);
}

#[test]
fn unknown_reason_inside_a_connection_does_not_break_parsing() {
    let json = r#"{"id":"a","pid":1,"processName":"x","processPath":"/x","targetHost":"h",
        "resolvedDomain":null,"targetPort":80,"protocol":"tcp","matchedRule":"r",
        "routeLabel":"BLOCKED","latencyMs":0,"rxBytes":0,"txBytes":0,"status":"blocked",
        "startedAt":"2026-01-01T00:00:00Z","blockReason":"fromTheFuture"}"#;
    let conn: TrackedConnection = serde_json::from_str(json).expect("parse");
    assert_eq!(conn.block_reason, Some(BlockReason::Unknown));
}

#[test]
fn summary_aggregates_by_key_and_lowercases_the_process() {
    let mut store = BlockedSummaryStore::new(10);
    let a = TrackedConnection::blocked(record(BlockReason::RuleBlock).with_rule_id("r1"));
    let mut b = TrackedConnection::blocked(
        BlockedRecord::new(BlockReason::RuleBlock, TransportProtocol::Tcp, "Rule A")
            .process("CHROME.EXE", "C:\\chrome.exe", 77)
            .target("example.com", 443)
            .with_rule_id("r1")
            .with_error("later"),
    );
    b.started_at = a.started_at + chrono::Duration::seconds(5);
    store.record(&a);
    store.record(&b);
    let list = store.sorted();
    assert_eq!(list.len(), 1);
    let entry = &list[0];
    assert_eq!(entry.process_name, "chrome.exe");
    assert_eq!(entry.destination, "example.com");
    assert_eq!(entry.count, 2);
    assert_eq!(entry.first_seen, a.started_at);
    assert_eq!(entry.last_seen, b.started_at);
    assert_eq!(entry.last_connection_id, b.id);
    assert_eq!(entry.last_pid, 77);
    assert_eq!(entry.last_error_detail.as_deref(), Some("later"));
    assert_eq!(entry.matched_rule.as_deref(), Some("Rule A"));
}

#[test]
fn summary_separates_reasons_and_rules_and_prefers_the_domain() {
    let mut store = BlockedSummaryStore::new(10);
    store.record(&TrackedConnection::blocked(
        record(BlockReason::RuleBlock).with_rule_id("r1"),
    ));
    store.record(&TrackedConnection::blocked(
        record(BlockReason::RuleBlock).with_rule_id("r2"),
    ));
    store.record(&TrackedConnection::blocked(record(
        BlockReason::DefaultPolicyBlock,
    )));
    store.record(&TrackedConnection::blocked(
        BlockedRecord::new(BlockReason::RuleBlock, TransportProtocol::Tcp, "Rule A")
            .process("Chrome.exe", "C:\\chrome.exe", 42)
            .target("93.184.216.34", 443)
            .with_domain(Some("cdn.example.com".into()))
            .with_rule_id("r1"),
    ));
    let list = store.sorted();
    assert_eq!(list.len(), 4);
    assert!(list.iter().any(|s| s.destination == "cdn.example.com"));
}

#[test]
fn summary_ignores_simulated_and_non_blocked_records() {
    let mut store = BlockedSummaryStore::new(10);
    store.record(&TrackedConnection::blocked(
        record(BlockReason::RuleBlock).simulated(),
    ));
    let mut active = TrackedConnection::blocked(record(BlockReason::RuleBlock));
    active.status = ConnectionStatus::Active;
    store.record(&active);
    assert!(store.sorted().is_empty());
}

#[test]
fn summary_evicts_the_entry_seen_longest_ago_and_sorts_newest_first() {
    let mut store = BlockedSummaryStore::new(2);
    let base = Utc::now();
    for (host, offset) in [("old.example", 0), ("mid.example", 10), ("new.example", 20)] {
        let mut c = TrackedConnection::blocked(
            BlockedRecord::new(BlockReason::RuleBlock, TransportProtocol::Tcp, "R")
                .process("a.exe", "/a", 1)
                .target(host, 80),
        );
        c.started_at = base + chrono::Duration::seconds(offset);
        store.record(&c);
    }
    let list = store.sorted();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].destination, "new.example");
    assert_eq!(list[1].destination, "mid.example");
}

#[test]
fn summary_json_uses_the_contract_field_names() {
    let mut store = BlockedSummaryStore::new(2);
    store.record(&TrackedConnection::blocked(
        record(BlockReason::KillSwitchProxyTimeout)
            .with_rule_id("r1")
            .with_proxy(Some("p1".into()))
            .with_error("timeout"),
    ));
    let value = serde_json::to_value(&store.sorted()[0]).expect("to_value");
    for key in [
        "processName",
        "processPath",
        "destination",
        "targetPort",
        "protocol",
        "blockReason",
        "matchedRuleId",
        "matchedRule",
        "proxyId",
        "count",
        "firstSeen",
        "lastSeen",
        "lastConnectionId",
        "lastPid",
        "lastErrorDetail",
    ] {
        assert!(value.get(key).is_some(), "missing {key}");
    }
    assert_eq!(value["blockReason"], "killSwitchProxyTimeout");
}

#[test]
fn unattributed_counters_use_the_contract_field_names() {
    let value = serde_json::to_value(UnattributedDropCounters {
        dropped_unattributed_syn: 3,
        dropped_unattributed_udp: 4,
    })
    .expect("to_value");
    assert_eq!(value["droppedUnattributedSyn"], 3);
    assert_eq!(value["droppedUnattributedUdp"], 4);
}
