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

//! Adds the desktop's own log files to the diagnostic bundle the daemon built.

use routeward_core::diagnostics::bundle::{BundleLimits, CollectOptions, SECTION_LOGS};
use routeward_core::diagnostics::logs::{list_log_dates, read_file_tail};
use routeward_core::diagnostics::redact::Redactor;
use serde_json::{json, Value};
use std::path::Path;

/// Source tag of the log files read from the desktop's own log directory.
pub const LOG_SOURCE_DESKTOP: &str = "desktop";
/// Key of the log file list inside the logs section.
const FILES_KEY: &str = "files";
/// Key of the text of one log file.
const TEXT_KEY: &str = "text";
/// Keys of the manifest and of its section list.
const MANIFEST_KEY: &str = "manifest";
const SECTIONS_KEY: &str = "sections";
const NAME_KEY: &str = "name";
const BYTES_KEY: &str = "bytes";
/// How many times the desktop log budget is halved before the desktop logs are given up.
const MAX_BUDGET_HALVINGS: u32 = 10;
/// Desktop log budget below which the desktop logs are dropped instead of halved again.
const MIN_DESKTOP_BUDGET_BYTES: usize = 4096;

/// Where the desktop logs are read from and how they are redacted.
pub struct DesktopLogSource<'a> {
    pub log_dir: &'a Path,
    pub app_name: &'a str,
    pub options: CollectOptions,
    pub limits: BundleLimits,
    /// Site names known from live data, masked wherever they appear when `mask_domains` is set.
    pub known_domains: Vec<String>,
    pub redactor: Redactor,
}

fn json_bytes(value: &Value) -> usize {
    serde_json::to_vec(value).map(|v| v.len()).unwrap_or(0)
}

/// Bytes of log text already in the bundle (the daemon's files).
fn existing_log_text_bytes(bundle: &Value) -> usize {
    bundle
        .get(SECTION_LOGS)
        .and_then(|l| l.get(FILES_KEY))
        .and_then(Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter_map(|f| f.get(TEXT_KEY).and_then(Value::as_str))
                .map(str::len)
                .sum()
        })
        .unwrap_or(0)
}

fn desktop_files(source: &DesktopLogSource, redactor: &Redactor, budget: usize) -> Vec<Value> {
    let days = source.options.log_days.min(source.limits.max_log_days) as usize;
    let mut remaining = budget;
    let mut files = Vec::new();
    for date in list_log_dates(source.log_dir, source.app_name)
        .into_iter()
        .take(days)
    {
        if remaining == 0 {
            break;
        }
        let Ok((text, cut)) = read_file_tail(source.log_dir, source.app_name, &date, remaining)
        else {
            continue;
        };
        remaining = remaining.saturating_sub(text.len());
        files.push(json!({
            "source": LOG_SOURCE_DESKTOP,
            "date": date,
            "truncated": cut,
            TEXT_KEY: redactor.redact_text(&text),
        }));
    }
    files.reverse();
    files
}

/// Rewrites the size of the logs section in the manifest (adding the entry when the daemon left
/// the section out).
fn update_manifest(bundle: &mut Value) {
    let bytes = bundle.get(SECTION_LOGS).map(json_bytes).unwrap_or(0);
    let Some(sections) = bundle
        .get_mut(MANIFEST_KEY)
        .and_then(|m| m.get_mut(SECTIONS_KEY))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    match sections
        .iter_mut()
        .find(|s| s.get(NAME_KEY).and_then(Value::as_str) == Some(SECTION_LOGS))
    {
        Some(entry) => entry[BYTES_KEY] = json!(bytes),
        None => sections.push(json!({ NAME_KEY: SECTION_LOGS, BYTES_KEY: bytes })),
    }
}

/// Adds the desktop log files (redacted like the daemon's) to `bundle`. The desktop part gets
/// what is left of the logs budget and is halved until the whole bundle fits the bundle cap;
/// when even a small budget does not fit, the bundle is left unchanged.
pub fn add_desktop_logs(bundle: &mut Value, source: &DesktopLogSource) {
    if source.options.log_days == 0 || !bundle.is_object() {
        return;
    }
    let redactor = if source.options.mask_domains {
        source
            .redactor
            .clone()
            .with_masked_domains(source.known_domains.iter().cloned())
    } else {
        source.redactor.clone()
    };
    let mut budget = source
        .limits
        .logs_max_bytes
        .saturating_sub(existing_log_text_bytes(bundle));
    for _ in 0..=MAX_BUDGET_HALVINGS {
        if budget < MIN_DESKTOP_BUDGET_BYTES {
            return;
        }
        let files = desktop_files(source, &redactor, budget);
        if files.is_empty() {
            return;
        }
        let mut candidate = bundle.clone();
        let Some(root) = candidate.as_object_mut() else {
            return;
        };
        let logs = root
            .entry(SECTION_LOGS.to_string())
            .or_insert_with(|| json!({ FILES_KEY: [] }));
        match logs.get_mut(FILES_KEY).and_then(Value::as_array_mut) {
            Some(list) => list.extend(files),
            None => *logs = json!({ FILES_KEY: files }),
        }
        update_manifest(&mut candidate);
        if json_bytes(&candidate) <= source.limits.bundle_max_bytes {
            *bundle = candidate;
            return;
        }
        budget /= 2;
    }
}
