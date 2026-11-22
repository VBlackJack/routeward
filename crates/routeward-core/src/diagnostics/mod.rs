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

//! Diagnostics served by the daemon: the blocked list, log queries, the check-up (analyzer),
//! the redacted diagnostic bundle and the "what if" rule preview.

pub mod analyzer;
pub mod bundle;
pub mod logs;
pub mod redact;

use crate::config::{ProfileConfig, RoutingRule};
use crate::interceptor::policy::{predict_outcome_at, PredictedOutcome};
use crate::interceptor::RouteWardController;
use crate::rules::{ConnectionRequest, RuleEngine};
use crate::telemetry::{BlockedSummary, UnattributedDropCounters};
use analyzer::{AnalyzerInput, AnalyzerThresholds, Finding};
use bundle::{BundleInput, BundleLimits, CollectOptions};
use chrono::{DateTime, TimeZone, Utc};
use logs::{LogQueryError, LogQueryLimits, QueryLogsRequest, QueryLogsResponse};
use serde::{Deserialize, Serialize};

/// Answer of `list_blocked`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockedResponse {
    pub entries: Vec<BlockedSummary>,
    pub counters: UnattributedDropCounters,
}

/// Answer of `analyze`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeResponse {
    pub findings: Vec<Finding>,
}

/// Request of `preview_rule_change`: the rules to add or replace and to remove, applied to a
/// copy of the profile, and the connection to evaluate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewRuleChangeRequest {
    #[serde(default)]
    pub upserts: Vec<RoutingRule>,
    #[serde(default)]
    pub remove_ids: Vec<String>,
    pub request: ConnectionRequest,
}

/// Applies a rule change to `profile` in memory: removals first, then each upsert replaces the
/// rule with the same id or is appended; the rules are left in evaluation order.
pub fn apply_rule_change(
    profile: &mut ProfileConfig,
    upserts: &[RoutingRule],
    remove_ids: &[String],
) {
    profile.rules.retain(|r| !remove_ids.contains(&r.id));
    for rule in upserts {
        match profile.rules.iter_mut().find(|r| r.id == rule.id) {
            Some(existing) => *existing = rule.clone(),
            None => profile.rules.push(rule.clone()),
        }
    }
    RuleEngine::sort_rules(&mut profile.rules);
}

/// Epoch milliseconds to a timestamp, `None` when out of range.
fn from_epoch_ms(ms: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_millis_opt(ms).single()
}

fn log_limits(controller: &RouteWardController) -> LogQueryLimits {
    let telemetry = &controller.constants.telemetry;
    LogQueryLimits {
        max_read_bytes: telemetry.log_query_max_read_bytes,
        max_entries: telemetry.log_query_max_entries,
    }
}

/// Blocked summary seen since `since_ms` (epoch milliseconds), at most `limit` entries, with the
/// counters of packets dropped without an owning application.
pub fn list_blocked(
    controller: &RouteWardController,
    since_ms: Option<i64>,
    limit: Option<usize>,
) -> BlockedResponse {
    BlockedResponse {
        entries: controller
            .telemetry
            .blocked_summary_filtered(since_ms.and_then(from_epoch_ms), limit),
        counters: controller.unattributed_drop_counters(),
    }
}

/// Runs a log query against the memory ring or one file of the daemon's own log directory.
pub fn query_logs(
    controller: &RouteWardController,
    request: &QueryLogsRequest,
) -> Result<QueryLogsResponse, LogQueryError> {
    logs::run_query(
        &controller.telemetry.list_logs(),
        controller.telemetry.log_dir(),
        &controller.constants.telemetry.log_app_name,
        request,
        log_limits(controller),
    )
}

/// The check-up: findings from the current state of the daemon.
pub fn analyze(controller: &RouteWardController) -> AnalyzeResponse {
    let telemetry = &controller.constants.telemetry;
    let diagnostics = controller.diagnostics();
    let profile = controller.profile.read().redacted_for_ipc();
    let blocked = controller.telemetry.blocked_summary();
    let health = controller.proxy_health_snapshot();
    let logs = controller.telemetry.list_logs();
    let findings = analyzer::analyze(&AnalyzerInput {
        diagnostics: &diagnostics,
        profile: &profile,
        blocked: &blocked,
        proxy_health: &health,
        counters: controller.unattributed_drop_counters(),
        logs: &logs,
        log_dir_bytes: logs::log_dir_bytes(controller.telemetry.log_dir(), &telemetry.log_app_name),
        thresholds: AnalyzerThresholds {
            unattributed_drops: telemetry.analyzer_unattributed_drops_threshold,
            log_folder_large_bytes: telemetry.analyzer_log_folder_large_bytes,
        },
        now: Utc::now(),
    });
    AnalyzeResponse { findings }
}

/// Builds the redacted diagnostic bundle (see [`bundle::build_bundle`]).
pub fn collect_diagnostics(
    controller: &RouteWardController,
    options: CollectOptions,
) -> serde_json::Value {
    let telemetry = &controller.constants.telemetry;
    let diagnostics = controller.diagnostics();
    let profile = controller.profile.read().clone();
    let connections = if options.include_connections {
        controller.telemetry.list_connections()
    } else {
        Vec::new()
    };
    let blocked = controller.telemetry.blocked_summary();
    let health = controller.proxy_health_snapshot();
    bundle::build_bundle(&BundleInput {
        options,
        limits: BundleLimits {
            max_log_days: telemetry.diagnostics_max_log_days,
            logs_max_bytes: telemetry.diagnostics_logs_max_bytes,
            bundle_max_bytes: telemetry.diagnostics_bundle_max_bytes,
        },
        now: Utc::now(),
        os: &diagnostics.os_name,
        diagnostics: &diagnostics,
        profile: &profile,
        connections: &connections,
        blocked: &blocked,
        counters: controller.unattributed_drop_counters(),
        proxy_health: &health,
        log_dir: controller.telemetry.log_dir(),
        log_app_name: &telemetry.log_app_name,
        redactor: redact::Redactor::from_environment(),
    })
}

/// What the engine would do for `request.request` if the rule change were applied: the
/// evaluation under the changed copy of the profile, with the policy overrides and the latest
/// known proxy health.
pub fn preview_rule_change(
    controller: &RouteWardController,
    request: &PreviewRuleChangeRequest,
) -> PredictedOutcome {
    let mut profile = controller.profile.read().clone();
    apply_rule_change(&mut profile, &request.upserts, &request.remove_ids);
    predict_outcome_at(
        &profile,
        &request.request,
        &controller.proxy_health_snapshot(),
        controller.policy_ports(),
        Utc::now(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RuleAction, SystemConstants, TransportProtocol};
    use crate::telemetry::{BlockReason, BlockedRecord, TrackedConnection};

    fn controller_in(dir: &std::path::Path) -> RouteWardController {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("profile");
        profile.enable_logging = true;
        profile.rules = Vec::new();
        profile.default_action = RuleAction::Direct;
        RouteWardController::new_with_log_dir(constants, profile, "en", dir.to_path_buf())
    }

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("routeward_diag_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn block_rule(id: &str, priority: i32, process: &str) -> RoutingRule {
        RoutingRule {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            priority,
            process_patterns: vec![process.to_string()],
            domain_patterns: Vec::new(),
            ip_cidrs: Vec::new(),
            port_ranges: Vec::new(),
            protocol: TransportProtocol::Any,
            action: RuleAction::Block,
            expires_at: None,
        }
    }

    fn request(process: &str) -> ConnectionRequest {
        ConnectionRequest {
            process_name: process.to_string(),
            process_path: Some(format!("C:\\Apps\\{process}")),
            target_host: "example.com".to_string(),
            target_ip: None,
            target_port: 8443,
            protocol: TransportProtocol::Tcp,
        }
    }

    #[test]
    fn rule_change_replaces_by_id_removes_and_orders() {
        let mut profile = ProfileConfig::load_embedded_default().expect("profile");
        profile.rules = vec![block_rule("a", 10, "a.exe"), block_rule("b", 20, "b.exe")];
        let mut changed_a = block_rule("a", 30, "a.exe");
        changed_a.action = RuleAction::Direct;
        apply_rule_change(
            &mut profile,
            &[changed_a, block_rule("c", 5, "c.exe")],
            &["b".to_string()],
        );
        let ids: Vec<&str> = profile.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "a"]);
        assert_eq!(profile.rules[1].action, RuleAction::Direct);
    }

    #[test]
    fn preview_applies_the_change_to_a_copy_only() {
        let dir = temp_dir();
        let controller = controller_in(&dir);
        controller.profile.write().rules = vec![block_rule("block-app", 10, "chrome.exe")];

        // Today: blocked by the rule.
        let before = preview_rule_change(
            &controller,
            &PreviewRuleChangeRequest {
                upserts: Vec::new(),
                remove_ids: Vec::new(),
                request: request("chrome.exe"),
            },
        );
        assert_eq!(before.evaluation.action, RuleAction::Block);
        assert_eq!(before.block_reason(), Some(BlockReason::RuleBlock));

        // An exception above the block lets it through.
        let mut exception = block_rule("rule-unblock-app-chrome", 6, "chrome.exe");
        exception.action = RuleAction::Direct;
        let allowed = preview_rule_change(
            &controller,
            &PreviewRuleChangeRequest {
                upserts: vec![exception],
                remove_ids: Vec::new(),
                request: request("chrome.exe"),
            },
        );
        assert_eq!(allowed.evaluation.action, RuleAction::Direct);
        assert_eq!(
            allowed.evaluation.matched_rule_id,
            "rule-unblock-app-chrome"
        );
        assert_eq!(allowed.block_reason(), None);

        // Removing the blocking rule has the same effect.
        let removed = preview_rule_change(
            &controller,
            &PreviewRuleChangeRequest {
                upserts: Vec::new(),
                remove_ids: vec!["block-app".to_string()],
                request: request("chrome.exe"),
            },
        );
        assert_eq!(removed.evaluation.action, RuleAction::Direct);

        // The real profile was never touched.
        assert_eq!(controller.profile.read().rules.len(), 1);
        assert_eq!(controller.profile.read().rules[0].id, "block-app");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preview_reports_a_policy_override_the_rule_cannot_lift() {
        let dir = temp_dir();
        let controller = controller_in(&dir);
        controller
            .profile
            .write()
            .security_policy
            .block_quic_udp_443 = true;
        let mut udp = request("chrome.exe");
        udp.protocol = TransportProtocol::Udp;
        udp.target_port = 443;
        let outcome = preview_rule_change(
            &controller,
            &PreviewRuleChangeRequest {
                upserts: Vec::new(),
                remove_ids: Vec::new(),
                request: udp,
            },
        );
        assert_eq!(outcome.policy_override, Some(BlockReason::QuicBlocked));
        let json = serde_json::to_value(&outcome).expect("json");
        assert_eq!(json["policyOverride"], "quicBlocked");
        assert!(json["evaluation"]["action"].is_object());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocked_list_filters_by_time_and_limit_and_carries_the_counters() {
        let dir = temp_dir();
        let controller = controller_in(&dir);
        for process in ["a.exe", "b.exe", "c.exe"] {
            let conn = TrackedConnection::blocked(
                BlockedRecord::new(BlockReason::RuleBlock, TransportProtocol::Tcp, "Rule")
                    .process(process, format!("C:\\{process}"), 1)
                    .target("example.com", 443),
            );
            controller.telemetry.record_connection(conn, false);
        }
        let all = list_blocked(&controller, None, None);
        assert_eq!(all.entries.len(), 3);
        assert_eq!(all.counters, UnattributedDropCounters::default());
        assert_eq!(list_blocked(&controller, None, Some(2)).entries.len(), 2);
        let future = Utc::now().timestamp_millis() + 60_000;
        assert!(list_blocked(&controller, Some(future), None)
            .entries
            .is_empty());
        let json = serde_json::to_value(&all).expect("json");
        assert!(json["entries"].is_array());
        assert_eq!(json["counters"]["droppedUnattributedSyn"], 0);
        assert_eq!(json["counters"]["droppedUnattributedUdp"], 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn analysis_and_collection_run_against_a_live_controller() {
        let dir = temp_dir();
        let controller = controller_in(&dir);
        let conn = TrackedConnection::blocked(
            BlockedRecord::new(
                BlockReason::DefaultPolicyBlock,
                TransportProtocol::Tcp,
                "Default",
            )
            .process("slack.exe", "C:\\slack.exe", 9)
            .target("slack.com", 443),
        );
        controller.telemetry.record_connection(conn, false);

        let findings = analyze(&controller).findings;
        assert!(findings
            .iter()
            .any(|f| f.code == analyzer::FindingCode::DefaultPolicyBlocking));
        // The engine is not running in this test: that is reported too.
        assert!(findings
            .iter()
            .any(|f| f.code == analyzer::FindingCode::ProtectionPausedOrStopped));

        let bundle = collect_diagnostics(
            &controller,
            CollectOptions {
                log_days: 1,
                include_connections: true,
                include_profile: true,
                mask_domains: false,
            },
        );
        assert!(bundle["manifest"]["sections"].as_array().unwrap().len() >= 4);
        assert!(bundle["blocked"]["entries"].is_array());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_queries_read_the_controller_log_directory_only() {
        let dir = temp_dir();
        let controller = controller_in(&dir);
        controller
            .telemetry
            .push_log(crate::telemetry::LogLevel::Warn, "T", "hello world");
        controller.telemetry.flush_file_logger();
        let mut req = QueryLogsRequest {
            source: logs::LogQuerySource::Memory,
            min_level: None,
            components: vec!["T".to_string()],
            text: None,
            pid: None,
            connection_id: None,
            since: None,
            until: None,
            limit: 10,
            cursor: None,
        };
        let memory = query_logs(&controller, &req).expect("memory query");
        assert_eq!(memory.entries.len(), 1);
        assert_eq!(memory.available_dates.len(), 1);

        let date = memory.available_dates[0].clone();
        req.source = logs::LogQuerySource::DaemonFile { date };
        let file = query_logs(&controller, &req).expect("file query");
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].message, "hello world");
        assert_eq!(file.entries[0].level, crate::telemetry::LogLevel::Warn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
