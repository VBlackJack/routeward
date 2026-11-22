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

//! The check-up: turns structured facts (blocked summary, proxy health, profile, counters,
//! recent log entries) into findings the UI explains in plain words. Pure: no I/O, no clock
//! (the caller passes `now`), no text matching on error messages.

use crate::checker::ProxyHealthReport;
use crate::config::{ProfileConfig, RoutingRule, TransportProtocol};
use crate::interceptor::SystemDiagnostics;
use crate::rules::RuleEngine;
use crate::telemetry::{BlockReason, BlockedSummary, LogEntry, LogLevel, UnattributedDropCounters};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Most findings produced per code (the worst offenders first).
const MAX_FINDINGS_PER_CODE: usize = 5;
/// Prefix of the rule ids that belong to a protection pack.
const PACK_RULE_ID_PREFIX: &str = "rule-pack-";
/// Prefix of the rule ids that Simple mode owns.
const SIMPLE_RULE_ID_PREFIXES: &[&str] = &[
    "rule-app-",
    "rule-site-",
    "rule-visual-",
    "rule-wiz-",
    "rule-quick-",
    "rule-uc-",
];
/// Log component that reports proxy connection problems.
const PROXY_LOG_COMPONENT: &str = "ProxyConnector";
/// Error lines of the proxy component from which an unreachable proxy is reported without any
/// blocked record (the summary may have been cleared).
const MIN_PROXY_ERROR_LOG_LINES: u64 = 3;
/// Bytes in one MiB, the unit of the log folder finding evidence.
const BYTES_PER_MIB: u64 = 1024 * 1024;
/// `openSetting` keys the UI understands.
const SETTING_KEY_DNS: &str = "dns";
const SETTING_KEY_LOGS: &str = "logs";

/// Identifier of a finding; the UI looks its texts up as `analyzer.findings.<code>.*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingCode {
    ProxyUnreachable,
    ProxyAuthRejected,
    DefaultPolicyBlocking,
    AppBlockedBySimpleRule,
    AppBlockedByPack,
    AppBlockedByRule,
    RuleShadowed,
    QuicOrDohBlockedInfo,
    UnattributedDropsHigh,
    FakeIpGuardHits,
    ProtectionPausedOrStopped,
    LogFolderLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingSeverity {
    Info,
    Warning,
    Critical,
}

/// What a finding is about; every field is optional.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSubject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

/// Fields of a blocked summary entry that identify it, for the `unblock` fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnblockKey {
    pub process_name: String,
    pub destination: String,
    pub target_port: u16,
    pub protocol: TransportProtocol,
    pub block_reason: BlockReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
}

impl UnblockKey {
    fn from_summary(entry: &BlockedSummary) -> Self {
        Self {
            process_name: entry.process_name.clone(),
            destination: entry.destination.clone(),
            target_port: entry.target_port,
            protocol: entry.protocol,
            block_reason: entry.block_reason,
            matched_rule_id: entry.matched_rule_id.clone(),
        }
    }
}

/// The action that fixes a finding, tagged by `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum FixAction {
    OpenProxy { id: String },
    TestProxy { id: String },
    Unblock { key: UnblockKey },
    EditRule { id: String },
    PauseProtection,
    OpenSetting { key: String },
    RestartApp,
    RunElevated,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub code: FindingCode,
    pub severity: FindingSeverity,
    pub subject: FindingSubject,
    pub evidence_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    pub fix: FixAction,
}

/// Thresholds of the check-up, from the system constants.
#[derive(Debug, Clone, Copy)]
pub struct AnalyzerThresholds {
    /// Dropped unattributed packets (SYN plus UDP) from which they are reported.
    pub unattributed_drops: u64,
    /// Log folder size (bytes) from which it is reported.
    pub log_folder_large_bytes: u64,
}

/// Everything the check-up looks at.
pub struct AnalyzerInput<'a> {
    pub diagnostics: &'a SystemDiagnostics,
    /// The profile as exposed to clients (no secrets are needed here).
    pub profile: &'a ProfileConfig,
    pub blocked: &'a [BlockedSummary],
    pub proxy_health: &'a [ProxyHealthReport],
    pub counters: UnattributedDropCounters,
    pub logs: &'a [LogEntry],
    pub log_dir_bytes: u64,
    pub thresholds: AnalyzerThresholds,
    pub now: DateTime<Utc>,
}

/// Runs every check and returns the findings, most severe first.
pub fn analyze(input: &AnalyzerInput) -> Vec<Finding> {
    let mut findings = Vec::new();
    check_protection_state(input, &mut findings);
    check_proxy_failures(input, &mut findings);
    check_policy_blocks(input, &mut findings);
    check_information_blocks(input, &mut findings);
    check_unattributed_drops(input, &mut findings);
    check_shadowed_rules(input, &mut findings);
    check_log_folder(input, &mut findings);
    findings.sort_by_key(|f| (std::cmp::Reverse(severity_rank(f.severity)), f.code));
    findings
}

fn severity_rank(severity: FindingSeverity) -> u8 {
    match severity {
        FindingSeverity::Info => 0,
        FindingSeverity::Warning => 1,
        FindingSeverity::Critical => 2,
    }
}

fn newest(a: Option<DateTime<Utc>>, b: DateTime<Utc>) -> Option<DateTime<Utc>> {
    Some(a.map_or(b, |a| a.max(b)))
}

fn check_protection_state(input: &AnalyzerInput, out: &mut Vec<Finding>) {
    if input.diagnostics.running {
        return;
    }
    out.push(Finding {
        code: FindingCode::ProtectionPausedOrStopped,
        severity: FindingSeverity::Warning,
        subject: FindingSubject::default(),
        evidence_count: 1,
        last_seen: None,
        fix: FixAction::None,
    });
}

/// Blocks caused by a failing proxy while the kill switch is on.
fn check_proxy_failures(input: &AnalyzerInput, out: &mut Vec<Finding>) {
    #[derive(Default)]
    struct Tally {
        unreachable: u64,
        auth_rejected: u64,
        last_unreachable: Option<DateTime<Utc>>,
        last_auth: Option<DateTime<Utc>>,
    }
    let mut by_proxy: BTreeMap<String, Tally> = BTreeMap::new();
    for entry in input.blocked {
        let proxy_key = entry.proxy_id.clone().unwrap_or_default();
        match entry.block_reason {
            BlockReason::KillSwitchProxyUnreachable
            | BlockReason::KillSwitchProxyRefused
            | BlockReason::KillSwitchProxyTimeout
            | BlockReason::KillSwitchProxyHandshake
            | BlockReason::KillSwitchProxyMisconfigured => {
                let tally = by_proxy.entry(proxy_key).or_default();
                tally.unreachable += entry.count;
                tally.last_unreachable = newest(tally.last_unreachable, entry.last_seen);
            }
            BlockReason::KillSwitchProxyAuthRejected => {
                let tally = by_proxy.entry(proxy_key).or_default();
                tally.auth_rejected += entry.count;
                tally.last_auth = newest(tally.last_auth, entry.last_seen);
            }
            _ => {}
        }
    }

    // No blocked record left (the summary was cleared) but the proxy is known to be down and
    // its component keeps logging errors: report it from the logs.
    for report in input.proxy_health.iter().filter(|r| !r.reachable) {
        if by_proxy
            .get(&report.proxy_id)
            .is_some_and(|t| t.unreachable > 0)
        {
            continue;
        }
        let errors: Vec<&LogEntry> = input
            .logs
            .iter()
            .filter(|l| l.level == LogLevel::Error && l.component == PROXY_LOG_COMPONENT)
            .collect();
        if errors.len() as u64 >= MIN_PROXY_ERROR_LOG_LINES {
            let tally = by_proxy.entry(report.proxy_id.clone()).or_default();
            tally.unreachable += errors.len() as u64;
            tally.last_unreachable = errors.iter().map(|l| l.timestamp).max();
        }
    }

    let proxy_exists = |id: &str| input.profile.proxies.iter().any(|p| p.id == id);
    let mut unreachable: Vec<Finding> = Vec::new();
    let mut auth: Vec<Finding> = Vec::new();
    for (proxy_id, tally) in &by_proxy {
        let subject = FindingSubject {
            proxy_id: (!proxy_id.is_empty()).then(|| proxy_id.clone()),
            ..FindingSubject::default()
        };
        if tally.unreachable > 0 {
            let fix = if proxy_id.is_empty() {
                FixAction::None
            } else if proxy_exists(proxy_id) {
                FixAction::TestProxy {
                    id: proxy_id.clone(),
                }
            } else {
                FixAction::OpenProxy {
                    id: proxy_id.clone(),
                }
            };
            unreachable.push(Finding {
                code: FindingCode::ProxyUnreachable,
                severity: FindingSeverity::Critical,
                subject: subject.clone(),
                evidence_count: tally.unreachable,
                last_seen: tally.last_unreachable,
                fix,
            });
        }
        if tally.auth_rejected > 0 {
            auth.push(Finding {
                code: FindingCode::ProxyAuthRejected,
                severity: FindingSeverity::Critical,
                subject,
                evidence_count: tally.auth_rejected,
                last_seen: tally.last_auth,
                fix: if proxy_id.is_empty() {
                    FixAction::None
                } else {
                    FixAction::OpenProxy {
                        id: proxy_id.clone(),
                    }
                },
            });
        }
    }
    push_worst(out, unreachable);
    push_worst(out, auth);
}

/// Keeps the findings with the most evidence.
fn push_worst(out: &mut Vec<Finding>, mut findings: Vec<Finding>) {
    findings.sort_by_key(|f| std::cmp::Reverse(f.evidence_count));
    findings.truncate(MAX_FINDINGS_PER_CODE);
    out.extend(findings);
}

fn is_simple_rule(rule_id: &str) -> bool {
    SIMPLE_RULE_ID_PREFIXES
        .iter()
        .any(|prefix| rule_id.starts_with(prefix))
}

fn is_pack_rule(rule_id: &str) -> bool {
    rule_id.starts_with(PACK_RULE_ID_PREFIX)
}

fn is_name_destination(destination: &str) -> bool {
    destination.parse::<std::net::IpAddr>().is_err()
}

/// Apps stopped by the default action or by a rule.
fn check_policy_blocks(input: &AnalyzerInput, out: &mut Vec<Finding>) {
    // (finding code, process, rule id) -> (count, last seen, first entry of the group)
    struct Group<'a> {
        count: u64,
        last_seen: DateTime<Utc>,
        first: &'a BlockedSummary,
    }
    let mut groups: BTreeMap<(FindingCode, String, String), Group> = BTreeMap::new();
    for entry in input.blocked {
        let (code, rule_key) = match entry.block_reason {
            BlockReason::DefaultPolicyBlock => (FindingCode::DefaultPolicyBlocking, String::new()),
            BlockReason::RuleBlock | BlockReason::DnsServerBlockedByRule => {
                let rule_id = entry.matched_rule_id.clone().unwrap_or_default();
                if is_simple_rule(&rule_id) {
                    (FindingCode::AppBlockedBySimpleRule, rule_id)
                } else if is_pack_rule(&rule_id) {
                    (FindingCode::AppBlockedByPack, rule_id)
                } else {
                    (FindingCode::AppBlockedByRule, rule_id)
                }
            }
            _ => continue,
        };
        let group = groups
            .entry((code, entry.process_name.clone(), rule_key))
            .or_insert(Group {
                count: 0,
                last_seen: entry.last_seen,
                first: entry,
            });
        group.count += entry.count;
        group.last_seen = group.last_seen.max(entry.last_seen);
    }

    let mut per_code: BTreeMap<FindingCode, Vec<Finding>> = BTreeMap::new();
    for ((code, process, rule_id), group) in groups {
        let rule_known = !rule_id.is_empty();
        let subject = FindingSubject {
            app: Some(process),
            site: is_name_destination(&group.first.destination)
                .then(|| group.first.destination.clone()),
            proxy_id: None,
            rule_id: rule_known.then(|| rule_id.clone()),
        };
        let fix = match code {
            FindingCode::AppBlockedBySimpleRule | FindingCode::AppBlockedByRule if rule_known => {
                FixAction::EditRule { id: rule_id }
            }
            _ => FixAction::Unblock {
                key: UnblockKey::from_summary(group.first),
            },
        };
        per_code.entry(code).or_default().push(Finding {
            code,
            severity: FindingSeverity::Warning,
            subject,
            evidence_count: group.count,
            last_seen: Some(group.last_seen),
            fix,
        });
    }
    for findings in per_code.into_values() {
        push_worst(out, findings);
    }
}

/// Blocks that are expected or rare: QUIC / DoH / DoT, and the Fake-IP guard.
fn check_information_blocks(input: &AnalyzerInput, out: &mut Vec<Finding>) {
    let mut quic_doh: (u64, Option<DateTime<Utc>>) = (0, None);
    let mut fake_ip: (u64, Option<DateTime<Utc>>) = (0, None);
    for entry in input.blocked {
        let slot = match entry.block_reason {
            BlockReason::QuicBlocked | BlockReason::EncryptedDnsBlocked => &mut quic_doh,
            BlockReason::FakeIpEgressGuard => &mut fake_ip,
            _ => continue,
        };
        slot.0 += entry.count;
        slot.1 = newest(slot.1, entry.last_seen);
    }
    if quic_doh.0 > 0 {
        out.push(Finding {
            code: FindingCode::QuicOrDohBlockedInfo,
            severity: FindingSeverity::Info,
            subject: FindingSubject::default(),
            evidence_count: quic_doh.0,
            last_seen: quic_doh.1,
            fix: FixAction::None,
        });
    }
    if fake_ip.0 > 0 {
        out.push(Finding {
            code: FindingCode::FakeIpGuardHits,
            severity: FindingSeverity::Warning,
            subject: FindingSubject::default(),
            evidence_count: fake_ip.0,
            last_seen: fake_ip.1,
            fix: FixAction::OpenSetting {
                key: SETTING_KEY_DNS.to_string(),
            },
        });
    }
}

fn check_unattributed_drops(input: &AnalyzerInput, out: &mut Vec<Finding>) {
    let total = input
        .counters
        .dropped_unattributed_syn
        .saturating_add(input.counters.dropped_unattributed_udp);
    if total == 0 || total < input.thresholds.unattributed_drops {
        return;
    }
    let first_proxy = input
        .profile
        .proxies
        .iter()
        .find(|p| p.enabled)
        .map(|p| p.id.clone());
    out.push(Finding {
        code: FindingCode::UnattributedDropsHigh,
        severity: FindingSeverity::Warning,
        subject: FindingSubject {
            proxy_id: first_proxy.clone(),
            ..FindingSubject::default()
        },
        evidence_count: total,
        last_seen: None,
        fix: first_proxy.map_or(FixAction::None, |id| FixAction::TestProxy { id }),
    });
}

/// Same list of patterns, ignoring order, case and blank entries.
fn same_patterns(a: &[String], b: &[String]) -> bool {
    let normalize = |list: &[String]| {
        let mut v: Vec<String> = list
            .iter()
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    normalize(a) == normalize(b)
}

fn no_patterns(list: &[String]) -> bool {
    list.iter().all(|p| p.trim().is_empty())
}

/// True when every connection `later` can match is also matched by `earlier`, as far as a cheap
/// structural comparison can tell: each criterion of `earlier` is "any" or identical.
fn covers(earlier: &RoutingRule, later: &RoutingRule) -> bool {
    let protocol_ok =
        earlier.protocol == TransportProtocol::Any || earlier.protocol == later.protocol;
    let ports_ok = earlier.port_ranges.is_empty() || earlier.port_ranges == later.port_ranges;
    let process_ok = no_patterns(&earlier.process_patterns)
        || same_patterns(&earlier.process_patterns, &later.process_patterns);
    let destination_ok = (no_patterns(&earlier.domain_patterns) && no_patterns(&earlier.ip_cidrs))
        || (same_patterns(&earlier.domain_patterns, &later.domain_patterns)
            && same_patterns(&earlier.ip_cidrs, &later.ip_cidrs));
    protocol_ok && ports_ok && process_ok && destination_ok
}

/// Rules that an earlier rule always decides first.
fn check_shadowed_rules(input: &AnalyzerInput, out: &mut Vec<Finding>) {
    let mut rules: Vec<&RoutingRule> = input
        .profile
        .rules
        .iter()
        .filter(|r| r.enabled && !RuleEngine::is_expired(r, input.now))
        .collect();
    rules.sort_by_key(|r| r.priority);
    let mut findings = Vec::new();
    for (index, later) in rules.iter().enumerate() {
        if rules[..index].iter().any(|earlier| covers(earlier, later)) {
            findings.push(Finding {
                code: FindingCode::RuleShadowed,
                severity: FindingSeverity::Info,
                subject: FindingSubject {
                    rule_id: Some(later.id.clone()),
                    ..FindingSubject::default()
                },
                evidence_count: 1,
                last_seen: None,
                fix: FixAction::EditRule {
                    id: later.id.clone(),
                },
            });
        }
    }
    findings.truncate(MAX_FINDINGS_PER_CODE);
    out.extend(findings);
}

fn check_log_folder(input: &AnalyzerInput, out: &mut Vec<Finding>) {
    if input.thresholds.log_folder_large_bytes == 0
        || input.log_dir_bytes < input.thresholds.log_folder_large_bytes
    {
        return;
    }
    out.push(Finding {
        code: FindingCode::LogFolderLarge,
        severity: FindingSeverity::Info,
        subject: FindingSubject::default(),
        evidence_count: input.log_dir_bytes / BYTES_PER_MIB,
        last_seen: None,
        fix: FixAction::OpenSetting {
            key: SETTING_KEY_LOGS.to_string(),
        },
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterceptionMode, PortRange, ProxyNode, ProxyProtocol, RuleAction};
    use chrono::Duration;

    const THRESHOLDS: AnalyzerThresholds = AnalyzerThresholds {
        unattributed_drops: 20,
        log_folder_large_bytes: 100 * BYTES_PER_MIB,
    };

    fn diagnostics(running: bool) -> SystemDiagnostics {
        SystemDiagnostics {
            daemon_connected: true,
            running,
            os_name: "TEST".to_string(),
            interception_mode: InterceptionMode::Hybrid,
            elevated_privileges: true,
            relay_tcp_endpoint: String::new(),
            relay_http_endpoint: String::new(),
            dns_endpoint: String::new(),
            fake_ip_cidr: String::new(),
            active_locale: "en".to_string(),
            paused_until_epoch_ms: None,
            auto_start_error_key: None,
        }
    }

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

    fn rule(id: &str, priority: i32) -> RoutingRule {
        RoutingRule {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            priority,
            process_patterns: Vec::new(),
            domain_patterns: Vec::new(),
            ip_cidrs: Vec::new(),
            port_ranges: Vec::new(),
            protocol: TransportProtocol::Any,
            action: RuleAction::Direct,
            expires_at: None,
        }
    }

    fn blocked(reason: BlockReason, process: &str, count: u64) -> BlockedSummary {
        BlockedSummary {
            process_name: process.to_string(),
            process_path: format!("C:\\{process}"),
            destination: "example.com".to_string(),
            target_port: 443,
            protocol: TransportProtocol::Tcp,
            block_reason: reason,
            matched_rule_id: None,
            matched_rule: None,
            proxy_id: None,
            count,
            first_seen: Utc::now() - Duration::minutes(5),
            last_seen: Utc::now(),
            last_connection_id: "c1".to_string(),
            last_pid: 4,
            last_error_detail: None,
        }
    }

    struct Fixture {
        diagnostics: SystemDiagnostics,
        profile: ProfileConfig,
        blocked: Vec<BlockedSummary>,
        health: Vec<ProxyHealthReport>,
        counters: UnattributedDropCounters,
        logs: Vec<LogEntry>,
        log_bytes: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let mut profile = ProfileConfig::load_embedded_default().expect("profile");
            profile.proxies = vec![proxy("p1")];
            profile.rules = Vec::new();
            Self {
                diagnostics: diagnostics(true),
                profile,
                blocked: Vec::new(),
                health: Vec::new(),
                counters: UnattributedDropCounters::default(),
                logs: Vec::new(),
                log_bytes: 0,
            }
        }

        fn run(&self) -> Vec<Finding> {
            analyze(&AnalyzerInput {
                diagnostics: &self.diagnostics,
                profile: &self.profile,
                blocked: &self.blocked,
                proxy_health: &self.health,
                counters: self.counters,
                logs: &self.logs,
                log_dir_bytes: self.log_bytes,
                thresholds: THRESHOLDS,
                now: Utc::now(),
            })
        }
    }

    fn codes(findings: &[Finding]) -> Vec<FindingCode> {
        findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn a_healthy_state_has_no_finding() {
        assert!(Fixture::new().run().is_empty());
    }

    #[test]
    fn stopped_protection_is_reported() {
        let mut fx = Fixture::new();
        fx.diagnostics = diagnostics(false);
        let findings = fx.run();
        assert_eq!(
            codes(&findings),
            vec![FindingCode::ProtectionPausedOrStopped]
        );
        assert_eq!(findings[0].fix, FixAction::None);
    }

    #[test]
    fn unreachable_proxy_groups_every_kill_switch_reason_of_one_proxy() {
        let mut fx = Fixture::new();
        for (reason, count) in [
            (BlockReason::KillSwitchProxyUnreachable, 4),
            (BlockReason::KillSwitchProxyRefused, 3),
            (BlockReason::KillSwitchProxyTimeout, 2),
        ] {
            let mut entry = blocked(reason, "chrome.exe", count);
            entry.proxy_id = Some("p1".to_string());
            fx.blocked.push(entry);
        }
        let findings = fx.run();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.code, FindingCode::ProxyUnreachable);
        assert_eq!(finding.severity, FindingSeverity::Critical);
        assert_eq!(finding.evidence_count, 9);
        assert_eq!(finding.subject.proxy_id.as_deref(), Some("p1"));
        assert_eq!(
            finding.fix,
            FixAction::TestProxy {
                id: "p1".to_string()
            }
        );
        assert!(finding.last_seen.is_some());
    }

    #[test]
    fn a_proxy_missing_from_the_profile_gets_an_open_proxy_fix() {
        let mut fx = Fixture::new();
        let mut entry = blocked(BlockReason::KillSwitchProxyMisconfigured, "chrome.exe", 1);
        entry.proxy_id = Some("ghost".to_string());
        fx.blocked.push(entry);
        let findings = fx.run();
        assert_eq!(findings[0].code, FindingCode::ProxyUnreachable);
        assert_eq!(
            findings[0].fix,
            FixAction::OpenProxy {
                id: "ghost".to_string()
            }
        );
    }

    #[test]
    fn rejected_credentials_open_the_proxy() {
        let mut fx = Fixture::new();
        let mut entry = blocked(BlockReason::KillSwitchProxyAuthRejected, "git.exe", 6);
        entry.proxy_id = Some("p1".to_string());
        fx.blocked.push(entry);
        let findings = fx.run();
        assert_eq!(codes(&findings), vec![FindingCode::ProxyAuthRejected]);
        assert_eq!(
            findings[0].fix,
            FixAction::OpenProxy {
                id: "p1".to_string()
            }
        );
        assert_eq!(findings[0].evidence_count, 6);
    }

    #[test]
    fn unreachable_proxy_is_found_in_the_logs_when_the_summary_is_empty() {
        let mut fx = Fixture::new();
        fx.health.push(ProxyHealthReport {
            proxy_id: "p1".to_string(),
            reachable: false,
            latency_ms: None,
            udp_supported: false,
            exit_ip: None,
            error_detail: None,
        });
        for _ in 0..MIN_PROXY_ERROR_LOG_LINES {
            fx.logs.push(LogEntry::new(
                LogLevel::Error,
                PROXY_LOG_COMPONENT,
                "connect failed",
            ));
        }
        let findings = fx.run();
        assert_eq!(codes(&findings), vec![FindingCode::ProxyUnreachable]);
        assert_eq!(findings[0].evidence_count, MIN_PROXY_ERROR_LOG_LINES);

        // Too few error lines: nothing is reported.
        fx.logs.truncate(1);
        assert!(fx.run().is_empty());
    }

    #[test]
    fn default_policy_blocks_are_reported_per_app_with_an_unblock_fix() {
        let mut fx = Fixture::new();
        fx.blocked
            .push(blocked(BlockReason::DefaultPolicyBlock, "slack.exe", 7));
        fx.blocked
            .push(blocked(BlockReason::DefaultPolicyBlock, "slack.exe", 3));
        let findings = fx.run();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.code, FindingCode::DefaultPolicyBlocking);
        assert_eq!(finding.subject.app.as_deref(), Some("slack.exe"));
        assert_eq!(finding.evidence_count, 10);
        match &finding.fix {
            FixAction::Unblock { key } => {
                assert_eq!(key.process_name, "slack.exe");
                assert_eq!(key.block_reason, BlockReason::DefaultPolicyBlock);
            }
            other => panic!("expected unblock, got {other:?}"),
        }
    }

    #[test]
    fn simple_rule_blocks_point_to_the_rule_and_pack_blocks_to_unblock() {
        let mut fx = Fixture::new();
        let mut simple = blocked(BlockReason::RuleBlock, "zoom.exe", 2);
        simple.matched_rule_id = Some("rule-app-zoom".to_string());
        let mut pack = blocked(BlockReason::RuleBlock, "edge.exe", 5);
        pack.matched_rule_id = Some("rule-pack-telemetry".to_string());
        fx.blocked.push(simple);
        fx.blocked.push(pack);
        let findings = fx.run();
        assert_eq!(
            codes(&findings),
            vec![
                FindingCode::AppBlockedBySimpleRule,
                FindingCode::AppBlockedByPack
            ]
        );
        assert_eq!(
            findings[0].fix,
            FixAction::EditRule {
                id: "rule-app-zoom".to_string()
            }
        );
        assert_eq!(
            findings[0].subject.rule_id.as_deref(),
            Some("rule-app-zoom")
        );
        assert!(matches!(findings[1].fix, FixAction::Unblock { .. }));
        assert_eq!(findings[1].subject.app.as_deref(), Some("edge.exe"));
    }

    #[test]
    fn custom_rule_blocks_are_not_attributed_to_a_pack() {
        let mut fx = Fixture::new();
        let mut custom = blocked(BlockReason::RuleBlock, "curl.exe", 4);
        custom.matched_rule_id = Some("rule-test-block".to_string());
        fx.blocked.push(custom);
        let findings = fx.run();
        assert_eq!(codes(&findings), vec![FindingCode::AppBlockedByRule]);
        assert_eq!(
            findings[0].fix,
            FixAction::EditRule {
                id: "rule-test-block".to_string()
            }
        );
        assert_eq!(findings[0].subject.app.as_deref(), Some("curl.exe"));
        assert_eq!(
            findings[0].subject.rule_id.as_deref(),
            Some("rule-test-block")
        );
    }

    #[test]
    fn quic_and_encrypted_dns_blocks_are_informational() {
        let mut fx = Fixture::new();
        fx.blocked
            .push(blocked(BlockReason::QuicBlocked, "chrome.exe", 11));
        fx.blocked
            .push(blocked(BlockReason::EncryptedDnsBlocked, "firefox.exe", 4));
        let findings = fx.run();
        assert_eq!(codes(&findings), vec![FindingCode::QuicOrDohBlockedInfo]);
        assert_eq!(findings[0].severity, FindingSeverity::Info);
        assert_eq!(findings[0].evidence_count, 15);
        assert_eq!(findings[0].fix, FixAction::None);
    }

    #[test]
    fn fake_ip_guard_hits_point_to_the_dns_settings() {
        let mut fx = Fixture::new();
        fx.blocked
            .push(blocked(BlockReason::FakeIpEgressGuard, "fake-ip-guard", 8));
        let findings = fx.run();
        assert_eq!(codes(&findings), vec![FindingCode::FakeIpGuardHits]);
        assert_eq!(
            findings[0].fix,
            FixAction::OpenSetting {
                key: SETTING_KEY_DNS.to_string()
            }
        );
    }

    #[test]
    fn unattributed_drops_need_the_threshold() {
        let mut fx = Fixture::new();
        fx.counters = UnattributedDropCounters {
            dropped_unattributed_syn: 10,
            dropped_unattributed_udp: 9,
        };
        assert!(fx.run().is_empty());
        fx.counters.dropped_unattributed_udp = 10;
        let findings = fx.run();
        assert_eq!(codes(&findings), vec![FindingCode::UnattributedDropsHigh]);
        assert_eq!(findings[0].evidence_count, 20);
        assert_eq!(
            findings[0].fix,
            FixAction::TestProxy {
                id: "p1".to_string()
            }
        );
    }

    #[test]
    fn a_rule_behind_an_identical_or_broader_rule_is_shadowed() {
        let mut fx = Fixture::new();
        let mut broad = rule("broad", 10);
        broad.process_patterns = vec!["chrome.exe".to_string()];
        let mut narrow = rule("narrow", 20);
        narrow.process_patterns = vec!["Chrome.exe".to_string()];
        narrow.domain_patterns = vec!["example.com".to_string()];
        let mut other = rule("other", 30);
        other.process_patterns = vec!["firefox.exe".to_string()];
        let mut wider = rule("wider", 40);
        wider.process_patterns = Vec::new();
        fx.profile.rules = vec![broad, narrow, other, wider];
        // "narrow" matches only what "broad" already decides; "other" and "wider" are not
        // covered by any earlier rule.
        let findings = fx.run();
        assert_eq!(codes(&findings), vec![FindingCode::RuleShadowed]);
        assert_eq!(findings[0].subject.rule_id.as_deref(), Some("narrow"));

        let mut duplicate = rule("duplicate", 15);
        duplicate.process_patterns = vec!["CHROME.EXE".to_string()];
        fx.profile.rules.push(duplicate);
        let findings = fx.run();
        let ids: Vec<&str> = findings
            .iter()
            .filter_map(|f| f.subject.rule_id.as_deref())
            .collect();
        assert_eq!(ids, vec!["duplicate", "narrow"]);
        assert_eq!(
            findings[0].fix,
            FixAction::EditRule {
                id: "duplicate".to_string()
            }
        );
    }

    #[test]
    fn a_catch_all_rule_shadows_every_later_rule_unless_it_is_disabled_or_expired() {
        let mut fx = Fixture::new();
        let catch_all = rule("catch-all", 1);
        let mut later = rule("later", 2);
        later.port_ranges = vec![PortRange {
            start: 443,
            end: 443,
        }];
        fx.profile.rules = vec![catch_all.clone(), later.clone()];
        assert_eq!(codes(&fx.run()), vec![FindingCode::RuleShadowed]);

        let mut disabled = catch_all.clone();
        disabled.enabled = false;
        fx.profile.rules = vec![disabled, later.clone()];
        assert!(fx.run().is_empty());

        let mut expired = catch_all;
        expired.expires_at = Some(Utc::now() - Duration::minutes(1));
        fx.profile.rules = vec![expired, later];
        assert!(fx.run().is_empty());
    }

    #[test]
    fn a_large_log_folder_is_reported_in_mib() {
        let mut fx = Fixture::new();
        fx.log_bytes = THRESHOLDS.log_folder_large_bytes - 1;
        assert!(fx.run().is_empty());
        fx.log_bytes = 150 * BYTES_PER_MIB;
        let findings = fx.run();
        assert_eq!(codes(&findings), vec![FindingCode::LogFolderLarge]);
        assert_eq!(findings[0].evidence_count, 150);
    }

    #[test]
    fn findings_are_sorted_with_the_most_severe_first_and_serialize_for_the_ui() {
        let mut fx = Fixture::new();
        fx.diagnostics = diagnostics(false);
        fx.blocked
            .push(blocked(BlockReason::QuicBlocked, "chrome.exe", 1));
        let mut down = blocked(BlockReason::KillSwitchProxyTimeout, "chrome.exe", 2);
        down.proxy_id = Some("p1".to_string());
        fx.blocked.push(down);
        let findings = fx.run();
        assert_eq!(
            codes(&findings),
            vec![
                FindingCode::ProxyUnreachable,
                FindingCode::ProtectionPausedOrStopped,
                FindingCode::QuicOrDohBlockedInfo
            ]
        );
        let json = serde_json::to_value(&findings[0]).expect("json");
        assert_eq!(json["code"], "proxyUnreachable");
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["subject"]["proxyId"], "p1");
        assert_eq!(json["evidenceCount"], 2);
        assert_eq!(json["fix"]["type"], "testProxy");
        assert_eq!(json["fix"]["id"], "p1");
        let none = serde_json::to_value(&findings[2]).expect("json");
        assert_eq!(none["fix"], serde_json::json!({ "type": "none" }));
        let pause = serde_json::to_value(FixAction::PauseProtection).expect("json");
        assert_eq!(pause, serde_json::json!({ "type": "pauseProtection" }));
        let setting = serde_json::to_value(FixAction::OpenSetting {
            key: "dns".to_string(),
        })
        .expect("json");
        assert_eq!(
            setting,
            serde_json::json!({ "type": "openSetting", "key": "dns" })
        );
    }

    #[test]
    fn every_finding_code_serializes_to_the_name_the_ui_translates() {
        let expected = [
            (FindingCode::ProxyUnreachable, "proxyUnreachable"),
            (FindingCode::ProxyAuthRejected, "proxyAuthRejected"),
            (FindingCode::DefaultPolicyBlocking, "defaultPolicyBlocking"),
            (
                FindingCode::AppBlockedBySimpleRule,
                "appBlockedBySimpleRule",
            ),
            (FindingCode::AppBlockedByPack, "appBlockedByPack"),
            (FindingCode::AppBlockedByRule, "appBlockedByRule"),
            (FindingCode::RuleShadowed, "ruleShadowed"),
            (FindingCode::QuicOrDohBlockedInfo, "quicOrDohBlockedInfo"),
            (FindingCode::UnattributedDropsHigh, "unattributedDropsHigh"),
            (FindingCode::FakeIpGuardHits, "fakeIpGuardHits"),
            (
                FindingCode::ProtectionPausedOrStopped,
                "protectionPausedOrStopped",
            ),
            (FindingCode::LogFolderLarge, "logFolderLarge"),
        ];
        for (code, name) in expected {
            assert_eq!(serde_json::to_value(code).expect("json"), name);
        }
    }

    #[test]
    fn at_most_the_worst_offenders_are_kept_per_code() {
        let mut fx = Fixture::new();
        for i in 0..(MAX_FINDINGS_PER_CODE as u64 + 3) {
            fx.blocked.push(blocked(
                BlockReason::DefaultPolicyBlock,
                &format!("app{i}.exe"),
                i + 1,
            ));
        }
        let findings = fx.run();
        assert_eq!(findings.len(), MAX_FINDINGS_PER_CODE);
        assert!(findings.iter().all(|f| f.evidence_count >= 4));
    }
}
