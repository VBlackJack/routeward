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
use crate::config::SystemConstants;

fn hub_with(max_blocked: usize, idle_ms: u64) -> TelemetryHub {
    let mut constants = SystemConstants::load_embedded()
        .expect("SystemConstants")
        .telemetry;
    constants.max_blocked_summary_entries = max_blocked;
    constants.udp_flow_idle_timeout_ms = idle_ms;
    TelemetryHub::new_with_logging(&constants, false)
}

fn blocked(host: &str, reason: BlockReason) -> TrackedConnection {
    TrackedConnection::blocked(
        BlockedRecord::new(reason, TransportProtocol::Tcp, "Rule A")
            .process("curl.exe", "C:\\curl.exe", 9)
            .target(host, 443)
            .with_rule_id("rule-a"),
    )
}

#[test]
fn the_embedded_constants_define_the_summary_bound() {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    assert!(constants.telemetry.max_blocked_summary_entries > 0);
}

#[test]
fn hub_aggregates_blocked_records_and_counts_repeats() {
    let hub = hub_with(10, 30_000);
    hub.record_connection(blocked("a.example", BlockReason::RuleBlock), false);
    hub.record_connection(blocked("a.example", BlockReason::RuleBlock), false);
    hub.record_connection(blocked("b.example", BlockReason::DefaultPolicyBlock), false);
    let summary = hub.blocked_summary();
    assert_eq!(summary.len(), 2);
    let a = summary
        .iter()
        .find(|s| s.destination == "a.example")
        .expect("a.example");
    assert_eq!(a.count, 2);
    assert_eq!(a.block_reason, BlockReason::RuleBlock);
    assert_eq!(hub.snapshot().blocked_count, 3);
}

#[test]
fn hub_excludes_simulated_blocks_from_the_summary_but_keeps_the_record() {
    let hub = hub_with(10, 30_000);
    hub.record_connection(
        TrackedConnection::blocked(
            BlockedRecord::new(BlockReason::RuleBlock, TransportProtocol::Tcp, "R")
                .process("a.exe", "/a", 0)
                .target("sim.example", 80)
                .simulated(),
        ),
        false,
    );
    assert!(hub.blocked_summary().is_empty());
    assert_eq!(hub.list_connections().len(), 1);
}

#[test]
fn hub_evicts_the_oldest_summary_entry_when_full() {
    let hub = hub_with(2, 30_000);
    let base = Utc::now();
    for (host, offset) in [
        ("one.example", 0),
        ("two.example", 5),
        ("three.example", 10),
    ] {
        let mut conn = blocked(host, BlockReason::RuleBlock);
        conn.started_at = base + chrono::Duration::seconds(offset);
        hub.record_connection(conn, false);
    }
    let summary = hub.blocked_summary();
    assert_eq!(summary.len(), 2);
    assert_eq!(summary[0].destination, "three.example");
    assert_eq!(summary[1].destination, "two.example");
}

#[test]
fn hub_filters_the_summary_by_time_and_limit() {
    let hub = hub_with(10, 30_000);
    let base = Utc::now();
    for (host, offset) in [
        ("old.example", -3600),
        ("new.example", 0),
        ("newer.example", 5),
    ] {
        let mut conn = blocked(host, BlockReason::RuleBlock);
        conn.started_at = base + chrono::Duration::seconds(offset);
        hub.record_connection(conn, false);
    }
    let recent = hub.blocked_summary_filtered(Some(base - chrono::Duration::seconds(60)), None);
    assert_eq!(recent.len(), 2);
    let limited = hub.blocked_summary_filtered(None, Some(1));
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].destination, "newer.example");
    hub.clear_blocked_summary();
    assert!(hub.blocked_summary().is_empty());
}

#[test]
fn repeated_blocked_udp_datagrams_share_one_record_but_all_count() {
    let hub = hub_with(10, 30_000);
    let key = "udp|client|target|BLOCKED|QuicBlocked";
    let make = || {
        TrackedConnection::blocked(
            BlockedRecord::new(BlockReason::QuicBlocked, TransportProtocol::Udp, "Quic")
                .process("chrome.exe", "C:\\chrome.exe", 5)
                .target("203.0.113.9", 443),
        )
    };
    assert!(hub.record_blocked_udp(key, make()));
    assert!(!hub.record_blocked_udp(key, make()));
    assert!(!hub.record_blocked_udp(key, make()));
    assert_eq!(hub.list_connections().len(), 1);
    assert_eq!(hub.blocked_summary()[0].count, 3);
    assert_eq!(hub.snapshot().blocked_count, 1);
}

#[test]
fn blocked_udp_flow_starts_a_new_record_after_the_idle_timeout() {
    let hub = hub_with(10, 1);
    let key = "udp|client|target|BLOCKED|QuicBlocked";
    let make = || {
        TrackedConnection::blocked(
            BlockedRecord::new(BlockReason::QuicBlocked, TransportProtocol::Udp, "Quic")
                .process("chrome.exe", "C:\\chrome.exe", 5)
                .target("203.0.113.9", 443),
        )
    };
    assert!(hub.record_blocked_udp(key, make()));
    std::thread::sleep(Duration::from_millis(20));
    assert!(hub.record_blocked_udp(key, make()));
    assert_eq!(hub.list_connections().len(), 2);
}

#[test]
fn log_context_travels_with_the_entry_and_plain_logs_have_none() {
    let hub = hub_with(10, 30_000);
    let conn = blocked("ctx.example", BlockReason::RuleBlock);
    hub.push_log_ctx(
        LogLevel::Warn,
        "Test",
        "with context",
        Some(LogContext::for_connection(&conn)),
    );
    hub.push_log(LogLevel::Warn, "Test", "without context");
    let logs = hub.list_logs();
    let plain = logs
        .iter()
        .find(|l| l.message == "without context")
        .expect("plain");
    assert!(plain.context.is_none());
    let with = logs
        .iter()
        .find(|l| l.message == "with context")
        .expect("ctx");
    let ctx = with.context.as_ref().expect("context");
    assert_eq!(ctx.pid, Some(9));
    assert_eq!(ctx.connection_id.as_deref(), Some(conn.id.as_str()));
    assert_eq!(ctx.host.as_deref(), Some("ctx.example"));
    assert_eq!(ctx.port, Some(443));

    let json = serde_json::to_value(with).expect("to_value");
    assert_eq!(json["context"]["pid"], 9);
    assert_eq!(json["context"]["connectionId"], conn.id);
    let plain_json = serde_json::to_value(plain).expect("to_value");
    assert!(plain_json.get("context").is_none());
}

#[test]
fn log_entry_without_context_still_deserializes() {
    let json = r#"{"id":"1","timestamp":"2026-01-01T00:00:00Z","level":"INFO",
        "component":"c","message":"m"}"#;
    let entry: LogEntry = serde_json::from_str(json).expect("legacy log entry");
    assert!(entry.context.is_none());
}
