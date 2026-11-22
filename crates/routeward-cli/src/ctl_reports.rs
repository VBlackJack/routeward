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

//! Human-readable output of the `ctl logs`, `ctl blocked`, `ctl diagnose` and
//! `ctl export-diagnostics` commands, and the file write of the diagnostic export. The daemon
//! never writes the export: the CLI writes it as the calling user.

use routeward_core::diagnostics::analyzer::Finding;
use routeward_core::diagnostics::logs::QueryLogsResponse;
use routeward_core::diagnostics::{AnalyzeResponse, BlockedResponse};
use routeward_core::i18n::I18nRegistry;
use routeward_core::telemetry::LogLevel;
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

/// Entries asked from the daemon by `ctl logs` when `--limit` is not given.
pub const DEFAULT_LOG_LIMIT: usize = 200;

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3600;
const SECONDS_PER_DAY: u64 = 86_400;
const INDENT: &str = "    ";
const SECTION_SEPARATOR: &str = ", ";

/// Locale keys of the argument errors and notes the log and blocked reports print.
const KEY_INVALID_LEVEL: &str = "cli.logs.invalid_level";
const KEY_INVALID_SINCE: &str = "cli.logs.invalid_since";
const KEY_MORE_AVAILABLE: &str = "cli.logs.more_available";
const KEY_EMPTY_RESULT: &str = "cli.ctl.empty_result";
const KEY_BLOCKED_COUNTERS: &str = "cli.blocked.counters";

/// Parses `--level` (case-insensitive). The error is the localized message.
pub fn parse_level(i18n: &I18nRegistry, raw: &str) -> Result<LogLevel, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warn" | "warning" => Ok(LogLevel::Warn),
        "error" => Ok(LogLevel::Error),
        _ => Err(interpolate(
            &i18n.t(KEY_INVALID_LEVEL),
            &[("value", raw.trim().to_string())],
        )),
    }
}

/// Parses `--since`: a whole number followed by `s`, `m`, `h` or `d` (`90s`, `15m`, `2h`, `1d`).
/// The error is the localized message.
pub fn parse_since(i18n: &I18nRegistry, raw: &str) -> Result<Duration, String> {
    let invalid = || {
        interpolate(
            &i18n.t(KEY_INVALID_SINCE),
            &[("value", raw.trim().to_string())],
        )
    };
    let trimmed = raw.trim();
    let (digits, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let seconds_per_unit = match unit {
        "s" => 1,
        "m" => SECONDS_PER_MINUTE,
        "h" => SECONDS_PER_HOUR,
        "d" => SECONDS_PER_DAY,
        _ => return Err(invalid()),
    };
    let amount: u64 = digits.parse().map_err(|_| invalid())?;
    amount
        .checked_mul(seconds_per_unit)
        .map(Duration::from_secs)
        .ok_or_else(invalid)
}

/// The localized message printed when the daemon answers without a result.
pub fn empty_result_message(i18n: &I18nRegistry) -> String {
    i18n.t(KEY_EMPTY_RESULT)
}

/// `{{name}}` placeholders of a locale text replaced by `params`.
pub fn interpolate(template: &str, params: &[(&str, String)]) -> String {
    let mut out = template.to_string();
    for (name, value) in params {
        out = out.replace(&format!("{{{{{name}}}}}"), value);
    }
    out
}

/// The serialized (camelCase or lowercase) name of a unit enum value.
fn serialized_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Lines of `ctl blocked`.
pub fn format_blocked(i18n: &I18nRegistry, response: &BlockedResponse) -> String {
    let mut out = format!("{}\n", i18n.t("cli.blocked.header"));
    if response.entries.is_empty() {
        out.push_str(&i18n.t("cli.blocked.empty"));
        out.push('\n');
    }
    for entry in &response.entries {
        let rule = entry
            .matched_rule
            .as_deref()
            .map(|r| format!(" rule={r}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "{count}x {process} -> {destination}:{port} {protocol} {reason}{rule} last={last}\n",
            count = entry.count,
            process = entry.process_name,
            destination = entry.destination,
            port = entry.target_port,
            protocol = serialized_name(&entry.protocol),
            reason = serialized_name(&entry.block_reason),
            last = entry.last_seen.to_rfc3339(),
        ));
    }
    let counters = &response.counters;
    if counters.dropped_unattributed_syn > 0 || counters.dropped_unattributed_udp > 0 {
        out.push_str(&interpolate(
            &i18n.t(KEY_BLOCKED_COUNTERS),
            &[
                ("syn", counters.dropped_unattributed_syn.to_string()),
                ("udp", counters.dropped_unattributed_udp.to_string()),
            ],
        ));
        out.push('\n');
    }
    out
}

fn finding_params(finding: &Finding) -> Vec<(&'static str, String)> {
    vec![
        ("app", finding.subject.app.clone().unwrap_or_default()),
        ("site", finding.subject.site.clone().unwrap_or_default()),
        (
            "proxy",
            finding.subject.proxy_id.clone().unwrap_or_default(),
        ),
        ("rule", finding.subject.rule_id.clone().unwrap_or_default()),
        ("count", finding.evidence_count.to_string()),
    ]
}

/// Lines of `ctl diagnose`: the header, then each finding with its explanation and its fix.
pub fn format_findings(i18n: &I18nRegistry, response: &AnalyzeResponse) -> String {
    let mut out = format!("{}\n", i18n.t("cli.diagnose.header"));
    if response.findings.is_empty() {
        out.push_str(&i18n.t("cli.diagnose.no_findings"));
        out.push('\n');
        return out;
    }
    for finding in &response.findings {
        let code = serialized_name(&finding.code);
        let params = finding_params(finding);
        let text = |part: &str| {
            interpolate(
                &i18n.t(&format!("analyzer.findings.{code}.{part}")),
                &params,
            )
        };
        out.push_str(&format!(
            "[{}] {}\n",
            serialized_name(&finding.severity),
            text("title")
        ));
        out.push_str(&format!("{INDENT}{}\n", text("body")));
        out.push_str(&format!("{INDENT}{}\n", text("fix")));
    }
    out
}

/// Lines of `ctl logs` (newest first, as the daemon sends them).
pub fn format_logs(i18n: &I18nRegistry, response: &QueryLogsResponse) -> String {
    if response.entries.is_empty() {
        return format!("{}\n", i18n.t("cli.logs.empty"));
    }
    let mut out = String::new();
    for entry in &response.entries {
        out.push_str(&format!(
            "[{}] [{}] [{}] {}\n",
            entry.timestamp.to_rfc3339(),
            serialized_name(&entry.level),
            entry.component,
            entry.message
        ));
    }
    if let Some(cursor) = &response.next_cursor {
        out.push_str(&interpolate(
            &i18n.t(KEY_MORE_AVAILABLE),
            &[("cursor", cursor.to_string())],
        ));
        out.push('\n');
    }
    out
}

/// Why the export file was not written.
#[derive(Debug)]
pub enum ExportError {
    /// The file exists and `--force` was not given.
    Exists,
    Io(std::io::Error),
}

/// Writes the bundle as pretty JSON. Without `force` the file is created exclusively, so an
/// existing file is never replaced, even by a race.
pub fn write_export(
    path: &Path,
    bundle: &serde_json::Value,
    force: bool,
) -> Result<(), ExportError> {
    let json = serde_json::to_string_pretty(bundle)
        .map_err(|err| ExportError::Io(std::io::Error::other(err)))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            ExportError::Exists
        } else {
            ExportError::Io(err)
        }
    })?;
    file.write_all(json.as_bytes()).map_err(ExportError::Io)?;
    file.flush().map_err(ExportError::Io)
}

/// Names of the sections listed in the bundle manifest.
pub fn manifest_sections(bundle: &serde_json::Value) -> Vec<String> {
    bundle["manifest"]["sections"]
        .as_array()
        .map(|sections| {
            sections
                .iter()
                .filter_map(|s| s["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The two lines printed after a successful export.
pub fn export_summary(i18n: &I18nRegistry, path: &Path, bundle: &serde_json::Value) -> String {
    let written = interpolate(
        &i18n.t("cli.export.written"),
        &[("path", path.display().to_string())],
    );
    let sections = interpolate(
        &i18n.t("cli.export.sections"),
        &[(
            "sections",
            manifest_sections(bundle).join(SECTION_SEPARATOR),
        )],
    );
    format!("{written}\n{sections}\n")
}

/// The message printed when the export file already exists.
pub fn export_exists_message(i18n: &I18nRegistry, path: &Path) -> String {
    interpolate(
        &i18n.t("cli.export.exists"),
        &[("path", path.display().to_string())],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeward_core::config::TransportProtocol;
    use routeward_core::diagnostics::analyzer::{
        FindingCode, FindingSeverity, FindingSubject, FixAction,
    };
    use routeward_core::telemetry::{
        BlockReason, BlockedSummary, LogEntry, UnattributedDropCounters,
    };

    fn english() -> I18nRegistry {
        I18nRegistry::new("en")
    }

    fn summary() -> BlockedSummary {
        let now = LogEntry::new(LogLevel::Info, "t", "t").timestamp;
        BlockedSummary {
            process_name: "slack.exe".to_string(),
            process_path: String::new(),
            destination: "slack.com".to_string(),
            target_port: 443,
            protocol: TransportProtocol::Tcp,
            block_reason: BlockReason::DefaultPolicyBlock,
            matched_rule_id: None,
            matched_rule: Some("Default".to_string()),
            proxy_id: None,
            count: 3,
            first_seen: now,
            last_seen: now,
            last_connection_id: "c".to_string(),
            last_pid: 1,
            last_error_detail: None,
        }
    }

    #[test]
    fn level_and_since_parse_and_reject_garbage() {
        let i18n = english();
        assert_eq!(parse_level(&i18n, "WARN"), Ok(LogLevel::Warn));
        assert_eq!(parse_level(&i18n, "warning"), Ok(LogLevel::Warn));
        assert!(parse_level(&i18n, "loud").is_err());
        assert_eq!(parse_since(&i18n, "90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_since(&i18n, "15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_since(&i18n, "2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(parse_since(&i18n, "1d"), Ok(Duration::from_secs(86_400)));
        for bad in ["", "m", "15", "-5m", "1.5h", "5x", "99999999999999999999d"] {
            assert!(parse_since(&i18n, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn argument_errors_and_notes_come_from_the_locale_keys_in_both_languages() {
        for locale in ["en", "fr"] {
            let i18n = I18nRegistry::new(locale);
            assert_eq!(
                parse_level(&i18n, "loud"),
                Err(interpolate(
                    &i18n.t(KEY_INVALID_LEVEL),
                    &[("value", "loud".to_string())]
                ))
            );
            assert_eq!(
                parse_since(&i18n, "5x"),
                Err(interpolate(
                    &i18n.t(KEY_INVALID_SINCE),
                    &[("value", "5x".to_string())]
                ))
            );
            assert_eq!(empty_result_message(&i18n), i18n.t(KEY_EMPTY_RESULT));
            let counters = format_blocked(
                &i18n,
                &BlockedResponse {
                    entries: Vec::new(),
                    counters: UnattributedDropCounters {
                        dropped_unattributed_syn: 4,
                        dropped_unattributed_udp: 9,
                    },
                },
            );
            assert!(counters.contains(&interpolate(
                &i18n.t(KEY_BLOCKED_COUNTERS),
                &[("syn", "4".to_string()), ("udp", "9".to_string())]
            )));
            assert!(!counters.contains("droppedUnattributed"));
        }
    }

    #[test]
    fn blocked_output_uses_the_header_and_the_empty_key() {
        let i18n = english();
        let empty = format_blocked(
            &i18n,
            &BlockedResponse {
                entries: Vec::new(),
                counters: UnattributedDropCounters::default(),
            },
        );
        assert!(empty.starts_with(&i18n.t("cli.blocked.header")));
        assert!(empty.contains(&i18n.t("cli.blocked.empty")));

        let full = format_blocked(
            &i18n,
            &BlockedResponse {
                entries: vec![summary()],
                counters: UnattributedDropCounters {
                    dropped_unattributed_syn: 4,
                    dropped_unattributed_udp: 0,
                },
            },
        );
        assert!(full.contains("3x slack.exe -> slack.com:443 tcp defaultPolicyBlock rule=Default"));
        assert!(full.contains(&interpolate(
            &i18n.t(KEY_BLOCKED_COUNTERS),
            &[("syn", "4".to_string()), ("udp", "0".to_string())]
        )));
        assert!(!full.contains(&i18n.t("cli.blocked.empty")));
    }

    #[test]
    fn findings_are_explained_with_their_values_filled_in() {
        let i18n = english();
        let none = format_findings(
            &i18n,
            &AnalyzeResponse {
                findings: Vec::new(),
            },
        );
        assert!(none.contains(&i18n.t("cli.diagnose.no_findings")));

        let finding = Finding {
            code: FindingCode::DefaultPolicyBlocking,
            severity: FindingSeverity::Warning,
            subject: FindingSubject {
                app: Some("slack.exe".to_string()),
                ..FindingSubject::default()
            },
            evidence_count: 7,
            last_seen: None,
            fix: FixAction::None,
        };
        let out = format_findings(
            &i18n,
            &AnalyzeResponse {
                findings: vec![finding],
            },
        );
        assert!(out.starts_with(&i18n.t("cli.diagnose.header")));
        assert!(out.contains("[warning] slack.exe is blocked because no rule allows it"));
        assert!(!out.contains("{{"));
        // Every finding code has its texts in both languages.
        for locale in ["en", "fr"] {
            let i18n = I18nRegistry::new(locale);
            for code in [
                "proxyUnreachable",
                "proxyAuthRejected",
                "defaultPolicyBlocking",
                "appBlockedBySimpleRule",
                "appBlockedByPack",
                "ruleShadowed",
                "quicOrDohBlockedInfo",
                "unattributedDropsHigh",
                "fakeIpGuardHits",
                "protectionPausedOrStopped",
                "logFolderLarge",
            ] {
                for part in ["title", "body", "fix"] {
                    let key = format!("analyzer.findings.{code}.{part}");
                    assert_ne!(i18n.t(&key), key, "{locale}: {key}");
                }
            }
        }
    }

    #[test]
    fn log_output_lists_entries_or_the_empty_key() {
        let i18n = english();
        let empty = format_logs(
            &i18n,
            &QueryLogsResponse {
                entries: Vec::new(),
                truncated: false,
                available_dates: Vec::new(),
                next_cursor: None,
            },
        );
        assert_eq!(empty.trim(), i18n.t("cli.logs.empty"));

        let out = format_logs(
            &i18n,
            &QueryLogsResponse {
                entries: vec![LogEntry::new(LogLevel::Warn, "Proxy", "slow answer")],
                truncated: false,
                available_dates: Vec::new(),
                next_cursor: Some("42".to_string()),
            },
        );
        assert!(out.contains("[WARN] [Proxy] slow answer"));
        assert!(out.contains(&interpolate(
            &i18n.t(KEY_MORE_AVAILABLE),
            &[("cursor", "42".to_string())]
        )));
    }

    #[test]
    fn export_refuses_to_overwrite_without_force() {
        let dir = std::env::temp_dir().join(format!("routeward_cli_export_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("diag.json");
        let _ = std::fs::remove_file(&path);
        let bundle = serde_json::json!({
            "manifest": { "sections": [ { "name": "system", "bytes": 1 }, { "name": "blocked", "bytes": 2 } ] }
        });

        write_export(&path, &bundle, false).expect("first write");
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written, bundle);

        assert!(matches!(
            write_export(&path, &serde_json::json!({ "other": true }), false),
            Err(ExportError::Exists)
        ));
        // The refused write left the first file untouched.
        let still: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(still, bundle);

        write_export(&path, &serde_json::json!({ "other": true }), true).expect("forced write");
        let replaced: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(replaced, serde_json::json!({ "other": true }));

        let i18n = english();
        let summary = export_summary(&i18n, &path, &bundle);
        assert!(summary.contains(&path.display().to_string()));
        assert!(summary.contains("system, blocked"));
        assert!(export_exists_message(&i18n, &path).contains(&path.display().to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_into_a_missing_folder_is_an_io_error() {
        let path = std::env::temp_dir()
            .join(format!("routeward_cli_missing_{}", std::process::id()))
            .join("nested")
            .join("diag.json");
        assert!(matches!(
            write_export(&path, &serde_json::json!({}), false),
            Err(ExportError::Io(_))
        ));
    }
}
