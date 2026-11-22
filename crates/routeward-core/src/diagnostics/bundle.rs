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

//! The diagnostic bundle: one redacted JSON document with a manifest that says what it holds.
//! The daemon only builds it; the client decides where to save it.

use super::logs::{list_log_dates, log_dir_bytes, read_file_tail};
use super::redact::{mask_domain, mask_site_rule_id, redact_profile, redaction_codes, Redactor};
use crate::checker::ProxyHealthReport;
use crate::config::ProfileConfig;
use crate::interceptor::SystemDiagnostics;
use crate::telemetry::{BlockedSummary, TrackedConnection, UnattributedDropCounters};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

/// Section names, in the order they appear in the bundle.
pub const SECTION_SYSTEM: &str = "system";
pub const SECTION_PROFILE: &str = "profile";
pub const SECTION_CONNECTIONS: &str = "connections";
pub const SECTION_BLOCKED: &str = "blocked";
pub const SECTION_LOGS: &str = "logs";

/// Source tag of the log files read from the daemon's own log directory.
pub const LOG_SOURCE_DAEMON: &str = "daemon";
/// How many times the log budget is halved before the logs are given up to fit the bundle.
const MAX_BUDGET_HALVINGS: u32 = 10;
/// Log budget below which the logs section is dropped instead of halved again.
const MIN_LOG_BUDGET_BYTES: usize = 4096;

/// Options of a collection (the IPC command `collect_diagnostics`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectOptions {
    /// Days of daemon log files to include; 0 leaves the logs out.
    pub log_days: u32,
    pub include_connections: bool,
    pub include_profile: bool,
    pub mask_domains: bool,
}

/// Limits of a bundle, from the system constants.
#[derive(Debug, Clone, Copy)]
pub struct BundleLimits {
    pub max_log_days: u32,
    pub logs_max_bytes: usize,
    pub bundle_max_bytes: usize,
    /// Absolute size the document may never exceed (the IPC line limit): above it, the large
    /// optional sections are given up even though the bundle cap is already missed.
    pub hard_max_bytes: usize,
}

/// Everything a bundle is built from.
pub struct BundleInput<'a> {
    pub options: CollectOptions,
    pub limits: BundleLimits,
    pub now: DateTime<Utc>,
    /// Operating system name as the daemon reports it.
    pub os: &'a str,
    pub diagnostics: &'a SystemDiagnostics,
    pub profile: &'a ProfileConfig,
    pub connections: &'a [TrackedConnection],
    pub blocked: &'a [BlockedSummary],
    pub counters: UnattributedDropCounters,
    pub proxy_health: &'a [ProxyHealthReport],
    pub log_dir: &'a Path,
    pub log_app_name: &'a str,
    pub redactor: Redactor,
}

/// Domain-like names found in the data that is going into the bundle: they are replaced
/// everywhere (logs included) when the user asks to hide site names.
fn known_domains(input: &BundleInput) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let mut add = |name: &str| {
        let trimmed = name.trim().trim_end_matches('.');
        if trimmed.contains('.') && trimmed.parse::<std::net::IpAddr>().is_err() {
            set.insert(trimmed.to_lowercase());
        }
    };
    for conn in input.connections {
        add(&conn.target_host);
        if let Some(domain) = &conn.resolved_domain {
            add(domain);
        }
    }
    for entry in input.blocked {
        add(&entry.destination);
    }
    for rule in &input.profile.rules {
        for pattern in &rule.domain_patterns {
            let name = pattern
                .trim()
                .trim_start_matches('!')
                .trim_start_matches("*.")
                .trim_start_matches('.');
            if !name.contains('*') && !name.to_lowercase().starts_with("regex:") {
                add(name);
            }
        }
    }
    for pattern in &input.profile.dns_config.bypass_domains {
        add(pattern
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches('.'));
    }
    set
}

fn mask_name(redactor: &Redactor, name: &str) -> String {
    if redactor.masks_domains() && name.contains('.') && name.parse::<std::net::IpAddr>().is_err() {
        mask_domain(name)
    } else {
        name.to_string()
    }
}

/// A rule id with its site name masked when the user asked to hide site names.
fn mask_rule_id(redactor: &Redactor, id: &str) -> String {
    if redactor.masks_domains() {
        mask_site_rule_id(id)
    } else {
        id.to_string()
    }
}

fn redacted_connections(input: &BundleInput, redactor: &Redactor) -> Vec<TrackedConnection> {
    input
        .connections
        .iter()
        .map(|conn| {
            let mut conn = conn.clone();
            conn.process_path = redactor.redact_text(&conn.process_path);
            conn.matched_rule = redactor.redact_text(&conn.matched_rule);
            conn.matched_rule_id = conn
                .matched_rule_id
                .as_deref()
                .map(|id| mask_rule_id(redactor, id));
            conn.error_detail = conn
                .error_detail
                .as_deref()
                .map(|d| redactor.redact_text(d));
            conn.target_host = mask_name(redactor, &conn.target_host);
            conn.resolved_domain = conn
                .resolved_domain
                .as_deref()
                .map(|d| mask_name(redactor, d));
            conn
        })
        .collect()
}

fn redacted_blocked(input: &BundleInput, redactor: &Redactor) -> Vec<BlockedSummary> {
    input
        .blocked
        .iter()
        .map(|entry| {
            let mut entry = entry.clone();
            entry.process_path = redactor.redact_text(&entry.process_path);
            entry.destination = mask_name(redactor, &entry.destination);
            entry.matched_rule = entry
                .matched_rule
                .as_deref()
                .map(|name| redactor.redact_text(name));
            entry.matched_rule_id = entry
                .matched_rule_id
                .as_deref()
                .map(|id| mask_rule_id(redactor, id));
            entry.last_error_detail = entry
                .last_error_detail
                .as_deref()
                .map(|d| redactor.redact_text(d));
            entry
        })
        .collect()
}

fn system_section(input: &BundleInput, redactor: &Redactor) -> Value {
    let health: Vec<Value> = input
        .proxy_health
        .iter()
        .map(|report| {
            json!({
                "proxyId": report.proxy_id,
                "reachable": report.reachable,
                "latencyMs": report.latency_ms,
                "udpSupported": report.udp_supported,
                "errorDetail": report.error_detail.as_deref().map(|d| redactor.redact_text(d)),
            })
        })
        .collect();
    json!({
        "os": input.os,
        "diagnostics": input.diagnostics,
        "proxyHealth": health,
        "unattributedDrops": input.counters,
        "logFolderBytes": log_dir_bytes(input.log_dir, input.log_app_name),
    })
}

/// The newest `days` daily files, redacted, newest budget first, returned oldest first.
fn logs_section(input: &BundleInput, redactor: &Redactor, budget: usize) -> Value {
    let days = input.options.log_days.min(input.limits.max_log_days) as usize;
    let mut remaining = budget;
    let mut files: Vec<Value> = Vec::new();
    for date in list_log_dates(input.log_dir, input.log_app_name)
        .into_iter()
        .take(days)
    {
        if remaining == 0 {
            break;
        }
        let Ok((text, cut)) = read_file_tail(input.log_dir, input.log_app_name, &date, remaining)
        else {
            continue;
        };
        remaining = remaining.saturating_sub(text.len());
        files.push(json!({
            "source": LOG_SOURCE_DAEMON,
            "date": date,
            "truncated": cut,
            "text": redactor.redact_text(&text),
        }));
    }
    files.reverse();
    json!({ "files": files })
}

fn section_bytes(value: &Value) -> usize {
    serde_json::to_vec(value).map(|v| v.len()).unwrap_or(0)
}

fn assemble(input: &BundleInput, redactor: &Redactor, sections: &[(&'static str, Value)]) -> Value {
    let manifest_sections: Vec<Value> = sections
        .iter()
        .map(|(name, value)| json!({ "name": name, "bytes": section_bytes(value) }))
        .collect();
    let redactions = redaction_codes(redactor.masks_domains());
    let mut root = serde_json::Map::new();
    root.insert(
        "manifest".to_string(),
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "os": input.os,
            "generatedAt": input.now,
            "sections": manifest_sections,
            "redactions": redactions,
            "maskDomains": redactor.masks_domains(),
        }),
    );
    for (name, value) in sections {
        root.insert((*name).to_string(), value.clone());
    }
    Value::Object(root)
}

/// Builds the bundle. The logs are cut (halving their budget) until the whole document fits
/// `bundle_max_bytes`; when even a small budget does not fit, the logs section is left out.
pub fn build_bundle(input: &BundleInput) -> Value {
    let seeded = input
        .redactor
        .clone()
        .with_profile_credentials(input.profile);
    let redactor = if input.options.mask_domains {
        seeded.with_masked_domains(known_domains(input))
    } else {
        seeded
    };

    let mut fixed: Vec<(&'static str, Value)> =
        vec![(SECTION_SYSTEM, system_section(input, &redactor))];
    if input.options.include_profile {
        let profile = redact_profile(input.profile, &redactor);
        fixed.push((
            SECTION_PROFILE,
            serde_json::to_value(profile).unwrap_or(Value::Null),
        ));
    }
    if input.options.include_connections {
        fixed.push((
            SECTION_CONNECTIONS,
            serde_json::to_value(redacted_connections(input, &redactor)).unwrap_or(Value::Null),
        ));
    }
    fixed.push((
        SECTION_BLOCKED,
        json!({
            "entries": redacted_blocked(input, &redactor),
            "counters": input.counters,
        }),
    ));

    if input.options.log_days == 0 {
        return assemble_within_cap(input, &redactor, fixed);
    }

    let mut budget = input.limits.logs_max_bytes;
    for _ in 0..=MAX_BUDGET_HALVINGS {
        if budget < MIN_LOG_BUDGET_BYTES {
            break;
        }
        let mut sections = fixed.clone();
        sections.push((SECTION_LOGS, logs_section(input, &redactor, budget)));
        let bundle = assemble(input, &redactor, &sections);
        if section_bytes(&bundle) <= input.limits.bundle_max_bytes {
            return bundle;
        }
        budget /= 2;
    }
    assemble_within_cap(input, &redactor, fixed)
}

/// Sections that may be dropped, in the order they are given up, when the document would still
/// exceed the absolute limit.
const DROPPABLE_SECTIONS: [&str; 2] = [SECTION_CONNECTIONS, SECTION_PROFILE];

/// Assembles the sections without logs. The bundle cap is already missed here (the logs were
/// given up for it); the document is returned whole unless it exceeds `hard_max_bytes`, the
/// transport limit, in which case the large optional sections are given up (the system and
/// blocked sections stay).
fn assemble_within_cap(
    input: &BundleInput,
    redactor: &Redactor,
    mut sections: Vec<(&'static str, Value)>,
) -> Value {
    let mut bundle = assemble(input, redactor, &sections);
    for droppable in DROPPABLE_SECTIONS {
        if section_bytes(&bundle) <= input.limits.hard_max_bytes {
            break;
        }
        sections.retain(|(name, _)| *name != droppable);
        bundle = assemble(input, redactor, &sections);
    }
    bundle
}

#[cfg(test)]
mod tests {
    use super::super::redact::REDACTION_CODE_DOMAINS;
    use super::*;
    use crate::config::{
        InterceptionMode, ProxyCredentials, ProxyNode, ProxyProtocol, TransportProtocol,
    };
    use crate::telemetry::{BlockReason, BlockedRecord, ConnectionStatus};
    use std::fs;

    fn diagnostics() -> SystemDiagnostics {
        SystemDiagnostics {
            daemon_connected: true,
            running: true,
            os_name: "TEST".to_string(),
            interception_mode: InterceptionMode::Hybrid,
            elevated_privileges: true,
            relay_tcp_endpoint: "127.0.0.1:1".to_string(),
            relay_http_endpoint: "127.0.0.1:2".to_string(),
            dns_endpoint: "127.0.0.1:3".to_string(),
            fake_ip_cidr: "198.18.0.0/15".to_string(),
            active_locale: "en".to_string(),
            paused_until_epoch_ms: None,
            auto_start_error_key: None,
        }
    }

    fn profile() -> ProfileConfig {
        let mut profile = ProfileConfig::load_embedded_default().expect("profile");
        profile.proxies = vec![ProxyNode {
            id: "p1".to_string(),
            name: "Office".to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "proxy.corp.test".to_string(),
            port: 1080,
            auth: Some(ProxyCredentials::new("alice", "s3cret-pw")),
            udp_enabled: false,
            tls: false,
            tls_skip_verify: false,
            sni: None,
            enabled: true,
            last_latency_ms: None,
            exit_ip: Some("203.0.113.9".to_string()),
        }];
        profile
    }

    fn connection() -> TrackedConnection {
        let mut conn = TrackedConnection::blocked(
            BlockedRecord::new(BlockReason::RuleBlock, TransportProtocol::Tcp, "Rule")
                .process("chrome.exe", r"C:\Users\alice\AppData\chrome.exe", 42)
                .target("secret-site.example.org", 443)
                .with_error("proxy http://bob:pw@proxy.corp.test/x?token=abc failed"),
        );
        conn.status = ConnectionStatus::Blocked;
        conn
    }

    fn summary() -> BlockedSummary {
        BlockedSummary {
            process_name: "chrome.exe".to_string(),
            process_path: r"C:\Users\alice\chrome.exe".to_string(),
            destination: "secret-site.example.org".to_string(),
            target_port: 443,
            protocol: TransportProtocol::Tcp,
            block_reason: BlockReason::RuleBlock,
            matched_rule_id: None,
            matched_rule: None,
            proxy_id: None,
            count: 2,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            last_connection_id: "c".to_string(),
            last_pid: 1,
            last_error_detail: Some("Authorization: Basic YWxpY2U6czNjcmV0".to_string()),
        }
    }

    fn temp_log_dir(lines: usize) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("routeward_bundle_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let mut text = String::new();
        for i in 0..lines {
            text.push_str(&format!(
                "[2026-11-22 10:00:00 +00:00] [INFO] [Engine] line {i} for secret-site.example.org token=abc123 C:\\Users\\alice\\x\n"
            ));
        }
        fs::write(dir.join("RouteWard_20261122.log"), &text).unwrap();
        fs::write(dir.join("RouteWard_20261121.log"), &text).unwrap();
        dir
    }

    struct Env {
        diagnostics: SystemDiagnostics,
        profile: ProfileConfig,
        connections: Vec<TrackedConnection>,
        blocked: Vec<BlockedSummary>,
        dir: std::path::PathBuf,
    }

    impl Env {
        fn new(log_lines: usize) -> Self {
            Self {
                diagnostics: diagnostics(),
                profile: profile(),
                connections: vec![connection()],
                blocked: vec![summary()],
                dir: temp_log_dir(log_lines),
            }
        }

        fn bundle(&self, options: CollectOptions, limits: BundleLimits) -> Value {
            build_bundle(&BundleInput {
                options,
                limits,
                now: Utc::now(),
                os: "TEST",
                diagnostics: &self.diagnostics,
                profile: &self.profile,
                connections: &self.connections,
                blocked: &self.blocked,
                counters: UnattributedDropCounters::default(),
                proxy_health: &[],
                log_dir: &self.dir,
                log_app_name: "RouteWard",
                redactor: Redactor::default().with_machine_name(Some("DESKTOP-ALICE".to_string())),
            })
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    const LIMITS: BundleLimits = BundleLimits {
        max_log_days: 14,
        logs_max_bytes: 3 * 1024 * 1024,
        bundle_max_bytes: 6 * 1024 * 1024,
        hard_max_bytes: 8 * 1024 * 1024,
    };

    const ALL: CollectOptions = CollectOptions {
        log_days: 3,
        include_connections: true,
        include_profile: true,
        mask_domains: false,
    };

    fn section_names(bundle: &Value) -> Vec<String> {
        bundle["manifest"]["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn the_manifest_lists_every_section_with_its_size() {
        let env = Env::new(5);
        let bundle = env.bundle(ALL, LIMITS);
        assert_eq!(
            section_names(&bundle),
            vec!["system", "profile", "connections", "blocked", "logs"]
        );
        for section in bundle["manifest"]["sections"].as_array().unwrap() {
            let name = section["name"].as_str().unwrap();
            let bytes = section["bytes"].as_u64().unwrap() as usize;
            assert_eq!(bytes, section_bytes(&bundle[name]), "{name}");
            assert!(bytes > 0);
        }
        let manifest = &bundle["manifest"];
        assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(manifest["os"], "TEST");
        assert_eq!(manifest["maskDomains"], false);
        assert!(manifest["generatedAt"].is_string());
        assert!(!manifest["redactions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn excluded_sections_are_omitted_not_emptied() {
        let env = Env::new(5);
        let bundle = env.bundle(
            CollectOptions {
                log_days: 0,
                include_connections: false,
                include_profile: false,
                mask_domains: false,
            },
            LIMITS,
        );
        assert_eq!(section_names(&bundle), vec!["system", "blocked"]);
        for gone in ["profile", "connections", "logs"] {
            assert!(bundle.get(gone).is_none(), "{gone}");
        }
    }

    #[test]
    fn no_secret_survives_anywhere_in_the_bundle() {
        let env = Env::new(5);
        let text = serde_json::to_string(&env.bundle(ALL, LIMITS)).unwrap();
        for secret in [
            "s3cret-pw",
            "alice",
            "bob",
            "token=abc",
            "abc123",
            "YWxpY2U6czNjcmV0",
            "203.0.113.9",
        ] {
            assert!(!text.contains(secret), "{secret} leaked");
        }
        // What is meant to stay in clear (D2): proxy host and site names.
        assert!(text.contains("proxy.corp.test"));
        assert!(text.contains("secret-site.example.org"));
        assert!(text.contains("\"hasPassword\":true"));
    }

    #[test]
    fn masking_hides_site_names_everywhere_and_is_stable() {
        let env = Env::new(5);
        let options = CollectOptions {
            mask_domains: true,
            ..ALL
        };
        let bundle = env.bundle(options, LIMITS);
        let text = serde_json::to_string(&bundle).unwrap();
        assert!(!text.contains("secret-site"));
        assert!(text.contains(&mask_domain("secret-site.example.org")));
        assert_eq!(bundle["manifest"]["maskDomains"], true);
        assert!(bundle["manifest"]["redactions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == REDACTION_CODE_DOMAINS));
        let again = serde_json::to_string(&env.bundle(options, LIMITS)).unwrap();
        // Only the timestamps differ between two runs.
        assert_eq!(
            text.matches(&mask_domain("secret-site.example.org"))
                .count(),
            again
                .matches(&mask_domain("secret-site.example.org"))
                .count()
        );
    }

    #[test]
    fn proxy_credentials_are_replaced_in_free_text_and_codes_are_listed() {
        let env = Env::new(0);
        fs::write(
            env.dir.join("RouteWard_20261122.log"),
            "[2026-11-22 10:00:00 +00:00] [WARN] [Proxy] auth failed for alice with s3cret-pw; user=alice CORP\\alice\n",
        )
        .unwrap();
        let bundle = env.bundle(ALL, LIMITS);
        let text = serde_json::to_string(&bundle).unwrap();
        assert!(!text.contains("s3cret-pw"));
        assert!(!text.contains("alice"));
        let codes: Vec<&str> = bundle["manifest"]["redactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(codes, super::super::redact::redaction_codes(false));
        assert!(!codes.contains(&"domains"));
    }

    #[test]
    fn rule_ids_with_site_names_are_masked_in_every_section_when_asked() {
        let mut env = Env::new(3);
        let site_id = "rule-unblock-site-secret-site-example-org-tmp";
        env.profile.rules[0].id = site_id.to_string();
        env.connections[0].matched_rule_id = Some(site_id.to_string());
        env.connections[0].matched_rule = "rule-unblock-site-secret-site-example-org-tmp".into();
        env.blocked[0].matched_rule_id = Some(site_id.to_string());
        env.blocked[0].matched_rule = Some("Unblock secret-site.example.org".to_string());
        env.profile.proxies[0].tls = true;
        env.profile.proxies[0].sni = Some("sni.secret-site.example.org".to_string());

        let masked = env.bundle(
            CollectOptions {
                mask_domains: true,
                ..ALL
            },
            LIMITS,
        );
        let text = serde_json::to_string(&masked).unwrap();
        assert!(!text.contains("secret-site"), "site name leaked: {text}");
        let code = mask_site_rule_id(site_id);
        assert_eq!(masked["profile"]["rules"][0]["id"], code);
        assert_eq!(masked["connections"][0]["matchedRuleId"], code);
        assert_eq!(masked["blocked"]["entries"][0]["matchedRuleId"], code);
        assert_eq!(
            masked["profile"]["proxies"][0]["sni"],
            mask_domain("sni.secret-site.example.org")
        );
        assert!(masked["manifest"]["redactions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == REDACTION_CODE_DOMAINS));

        // Without masking the ids stay readable.
        let plain = env.bundle(ALL, LIMITS);
        assert_eq!(plain["connections"][0]["matchedRuleId"], site_id);
    }

    #[test]
    fn sections_that_exceed_the_transport_limit_are_given_up_before_the_document_is_returned() {
        let env = Env::new(0);
        let tiny = BundleLimits {
            bundle_max_bytes: 1500,
            hard_max_bytes: 1500,
            ..LIMITS
        };
        // No logs requested: the optional sections go until the document fits the hard limit.
        let bundle = env.bundle(CollectOptions { log_days: 0, ..ALL }, tiny);
        assert!(bundle.get("connections").is_none());
        assert!(bundle.get("system").is_some());
        assert!(bundle.get("blocked").is_some());
        assert!(section_bytes(&bundle) <= 3000, "kept only what must stay");
    }

    #[test]
    fn logs_follow_the_day_limit_and_the_byte_budget() {
        let env = Env::new(2000);
        let one_day = env.bundle(CollectOptions { log_days: 1, ..ALL }, LIMITS);
        let files = one_day["logs"]["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["date"], "20261122");
        assert_eq!(files[0]["source"], LOG_SOURCE_DAEMON);

        let small = BundleLimits {
            logs_max_bytes: 20_000,
            ..LIMITS
        };
        let capped = env.bundle(ALL, small);
        let total: usize = capped["logs"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["text"].as_str().unwrap().len())
            .sum();
        assert!(total <= 20_000 + 2000, "{total}");
        assert!(capped["logs"]["files"][0]["truncated"].as_bool().unwrap());
    }

    #[test]
    fn the_whole_bundle_stays_under_the_line_limit() {
        let env = Env::new(20_000);
        let limits = BundleLimits {
            max_log_days: 14,
            logs_max_bytes: 3 * 1024 * 1024,
            bundle_max_bytes: 300_000,
            hard_max_bytes: usize::MAX,
        };
        let bundle = env.bundle(ALL, limits);
        assert!(section_bytes(&bundle) <= 300_000);
        assert!(bundle.get("logs").is_some());

        // An impossible limit drops the logs rather than overflowing.
        let tiny = BundleLimits {
            bundle_max_bytes: 100,
            ..limits
        };
        let bundle = env.bundle(ALL, tiny);
        assert!(bundle.get("logs").is_none());
        assert_eq!(
            section_names(&bundle),
            vec!["system", "profile", "connections", "blocked"]
        );
    }
}
