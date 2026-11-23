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

//! Queries over the daemon's logs: the in-memory ring buffer and the daily files of the
//! daemon's own log directory.
//!
//! File line format: `[yyyy-MM-dd HH:mm:ss +HH:MM] [LEVEL] [component] message`, optionally
//! ending with the context suffix ` {conn=xxxxxxxx pid=N}`. A line that is not a record header
//! continues the previous record (stack traces, multi-line messages); it is kept, joined with a
//! newline. Only file names `<app>_<yyyyMMdd>.log` of the daemon's log directory can be read:
//! the client never supplies a path.

use crate::logger::{log_file_name, parse_log_file_date};
use crate::telemetry::{LogContext, LogEntry, LogLevel};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Component given to a line that has no record header before it.
const RAW_LINE_COMPONENT: &str = "raw";
const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S %:z";
const DATE_FORMAT: &str = "%Y%m%d";
const CONTEXT_SUFFIX_OPEN: &str = " {";
const CONNECTION_KEY: &str = "conn=";
const PID_KEY: &str = "pid=";

/// Where a log query reads from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LogQuerySource {
    /// The live ring buffer.
    Memory,
    /// One daily file of the daemon's log directory, by date (`yyyyMMdd`).
    DaemonFile { date: String },
}

/// A log query (see the IPC command `query_logs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryLogsRequest {
    pub source: LogQuerySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_level: Option<LogLevel>,
    /// Exact component names (ASCII case-insensitive); empty means every component.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<String>,
    /// Case-insensitive text looked for in the message and the component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Matches a connection id or its first characters, in either direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    /// Epoch milliseconds, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
    /// Epoch milliseconds, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    pub limit: usize,
    /// Opaque value returned by the previous call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Answer of a log query. Entries are newest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryLogsResponse {
    pub entries: Vec<LogEntry>,
    /// True when the read stopped at the byte cap while older data remains.
    pub truncated: bool,
    /// Dates (`yyyyMMdd`) of the daily files, newest first.
    pub available_dates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Why a log query was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogQueryError {
    /// The date is not an 8-digit calendar date.
    InvalidDate,
    /// The cursor is not one this daemon handed out for this file.
    InvalidCursor,
    /// The file could not be read.
    Io(String),
}

impl std::fmt::Display for LogQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDate => f.write_str("invalid_log_date"),
            Self::InvalidCursor => f.write_str("invalid_log_cursor"),
            Self::Io(detail) => write!(f, "log_read_failed: {detail}"),
        }
    }
}

impl std::error::Error for LogQueryError {}

/// Limits of one query, from the system constants.
#[derive(Debug, Clone, Copy)]
pub struct LogQueryLimits {
    pub max_read_bytes: usize,
    pub max_entries: usize,
}

fn level_rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Debug => 0,
        LogLevel::Info => 1,
        LogLevel::Warn => 2,
        LogLevel::Error => 3,
    }
}

fn parse_level(raw: &str) -> Option<LogLevel> {
    match raw {
        "DEBUG" => Some(LogLevel::Debug),
        "INFO" => Some(LogLevel::Info),
        "WARN" => Some(LogLevel::Warn),
        "ERROR" => Some(LogLevel::Error),
        _ => None,
    }
}

/// A parsed record header line.
struct Header {
    timestamp: DateTime<Utc>,
    level: LogLevel,
    component: String,
    message: String,
    context: Option<LogContext>,
}

/// Takes `[...]` at the start of `text`, returns its content and the rest after one space.
fn take_bracket(text: &str) -> Option<(&str, &str)> {
    let inner = text.strip_prefix('[')?;
    let close = inner.find(']')?;
    let rest = &inner[close + 1..];
    Some((&inner[..close], rest.strip_prefix(' ').unwrap_or(rest)))
}

/// Splits the stable context suffix ` {conn=xxxxxxxx pid=N}` off a message.
fn split_context_suffix(message: &str) -> (&str, Option<LogContext>) {
    let Some(body) = message.strip_suffix('}') else {
        return (message, None);
    };
    let Some(open) = body.rfind(CONTEXT_SUFFIX_OPEN) else {
        return (message, None);
    };
    let mut context = LogContext::default();
    let mut any = false;
    for part in body[open + CONTEXT_SUFFIX_OPEN.len()..].split(' ') {
        if let Some(id) = part.strip_prefix(CONNECTION_KEY) {
            context.connection_id = Some(id.to_string());
            any = true;
        } else if let Some(pid) = part.strip_prefix(PID_KEY) {
            match pid.parse::<u32>() {
                Ok(pid) => {
                    context.pid = Some(pid);
                    any = true;
                }
                Err(_) => return (message, None),
            }
        } else {
            return (message, None);
        }
    }
    if any {
        (&message[..open], Some(context))
    } else {
        (message, None)
    }
}

/// Parses one record header line, `None` when the line is not one.
fn parse_header(line: &str) -> Option<Header> {
    let (stamp, rest) = take_bracket(line)?;
    let timestamp = DateTime::parse_from_str(stamp, TIMESTAMP_FORMAT)
        .ok()?
        .with_timezone(&Utc);
    let (level_raw, rest) = take_bracket(rest)?;
    let level = parse_level(level_raw)?;
    let (component, message) = take_bracket(rest)?;
    let (message, context) = split_context_suffix(message);
    Some(Header {
        timestamp,
        level,
        component: component.to_string(),
        message: message.to_string(),
        context,
    })
}

/// Midnight UTC of a file's date, the timestamp of a raw line that has no header before it.
fn date_midnight(date: NaiveDate) -> DateTime<Utc> {
    Utc.from_utc_datetime(&date.and_time(chrono::NaiveTime::MIN))
}

/// One record with the byte offset of its first line.
struct FileRecord {
    start: u64,
    entry: LogEntry,
}

/// Parses `bytes` (whole lines, starting at file offset `base`) into records. Lines without a
/// header continue the previous record; at the very start of a file they form a raw record.
fn parse_records(bytes: &[u8], base: u64, date: NaiveDate) -> Vec<FileRecord> {
    let mut records: Vec<FileRecord> = Vec::new();
    let mut offset = base;
    for raw_line in bytes.split_inclusive(|b| *b == b'\n') {
        let line_start = offset;
        offset += raw_line.len() as u64;
        let text = String::from_utf8_lossy(raw_line);
        let line = text.trim_end_matches(['\n', '\r']);
        if let Some(header) = parse_header(line) {
            records.push(FileRecord {
                start: line_start,
                entry: LogEntry {
                    id: format!("{}-{line_start}", date.format(DATE_FORMAT)),
                    timestamp: header.timestamp,
                    level: header.level,
                    component: header.component,
                    message: header.message,
                    context: header.context,
                },
            });
        } else if let Some(last) = records.last_mut() {
            last.entry.message.push('\n');
            last.entry.message.push_str(line);
        } else {
            records.push(FileRecord {
                start: line_start,
                entry: LogEntry {
                    id: format!("{}-{line_start}", date.format(DATE_FORMAT)),
                    timestamp: date_midnight(date),
                    level: LogLevel::Info,
                    component: RAW_LINE_COMPONENT.to_string(),
                    message: line.to_string(),
                    context: None,
                },
            });
        }
    }
    records
}

fn connection_matches(wanted: &str, found: &str) -> bool {
    !wanted.is_empty()
        && !found.is_empty()
        && (found.starts_with(wanted) || wanted.starts_with(found))
}

/// True when `entry` passes every filter of `req` (the time bounds included).
pub fn entry_matches(entry: &LogEntry, req: &QueryLogsRequest) -> bool {
    if let Some(min) = req.min_level {
        if level_rank(entry.level) < level_rank(min) {
            return false;
        }
    }
    if !req.components.is_empty()
        && !req
            .components
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&entry.component))
    {
        return false;
    }
    if let Some(text) = req.text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        let needle = text.to_lowercase();
        let haystack = format!("{} {}", entry.message, entry.component).to_lowercase();
        if !haystack.contains(&needle) {
            return false;
        }
    }
    if let Some(pid) = req.pid {
        if entry.context.as_ref().and_then(|c| c.pid) != Some(pid) {
            return false;
        }
    }
    if let Some(wanted) = req.connection_id.as_deref() {
        let found = entry
            .context
            .as_ref()
            .and_then(|c| c.connection_id.as_deref())
            .unwrap_or("");
        if !connection_matches(wanted, found) {
            return false;
        }
    }
    let millis = entry.timestamp.timestamp_millis();
    if req.since.is_some_and(|since| millis < since) {
        return false;
    }
    if req.until.is_some_and(|until| millis > until) {
        return false;
    }
    true
}

fn effective_limit(req: &QueryLogsRequest, limits: LogQueryLimits) -> usize {
    req.limit.clamp(1, limits.max_entries.max(1))
}

/// Filters the ring buffer. `entries` is newest first (as `TelemetryHub::list_logs` returns it);
/// the cursor is the number of matching entries already returned.
pub fn query_memory(
    entries: &[LogEntry],
    req: &QueryLogsRequest,
    limits: LogQueryLimits,
) -> Result<QueryLogsResponse, LogQueryError> {
    let skip = match req.cursor.as_deref() {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| LogQueryError::InvalidCursor)?,
        None => 0,
    };
    let limit = effective_limit(req, limits);
    let mut matching = entries.iter().filter(|e| entry_matches(e, req)).skip(skip);
    let page: Vec<LogEntry> = matching.by_ref().take(limit).cloned().collect();
    let has_more = matching.next().is_some();
    let next_cursor = has_more.then(|| (skip + page.len()).to_string());
    Ok(QueryLogsResponse {
        entries: page,
        truncated: false,
        available_dates: Vec::new(),
        next_cursor,
    })
}

/// Dates of the daily files in `log_dir`, newest first.
pub fn list_log_dates(log_dir: &Path, app_name: &str) -> Vec<String> {
    let Ok(entries) = fs::read_dir(log_dir) else {
        return Vec::new();
    };
    let mut dates: Vec<NaiveDate> = entries
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| parse_log_file_date(app_name, n))
        })
        .collect();
    dates.sort_unstable_by(|a, b| b.cmp(a));
    dates.dedup();
    dates
        .into_iter()
        .map(|d| d.format(DATE_FORMAT).to_string())
        .collect()
}

/// Total size in bytes of the daily log files of `app_name` in `log_dir`.
pub fn log_dir_bytes(log_dir: &Path, app_name: &str) -> u64 {
    let Ok(entries) = fs::read_dir(log_dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| parse_log_file_date(app_name, n).is_some())
        })
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

/// Validates a client-supplied date and builds the path of its file inside `log_dir`. The only
/// accepted input is eight digits forming a calendar date.
pub fn daily_file_path(
    log_dir: &Path,
    app_name: &str,
    date: &str,
) -> Result<(NaiveDate, std::path::PathBuf), LogQueryError> {
    let name = log_file_name(app_name, date);
    let parsed = parse_log_file_date(app_name, &name).ok_or(LogQueryError::InvalidDate)?;
    Ok((parsed, log_dir.join(name)))
}

/// Reads one daily file backward: the newest records first, at most `max_read_bytes` per call.
pub fn query_daily_file(
    log_dir: &Path,
    app_name: &str,
    date: &str,
    req: &QueryLogsRequest,
    limits: LogQueryLimits,
) -> Result<QueryLogsResponse, LogQueryError> {
    let (parsed_date, path) = daily_file_path(log_dir, app_name, date)?;
    let available_dates = list_log_dates(log_dir, app_name);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(QueryLogsResponse {
                entries: Vec::new(),
                truncated: false,
                available_dates,
                next_cursor: None,
            });
        }
        Err(err) => return Err(LogQueryError::Io(err.to_string())),
    };
    let len = file
        .metadata()
        .map_err(|err| LogQueryError::Io(err.to_string()))?
        .len();
    let end = match req.cursor.as_deref() {
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|c| *c <= len)
            .ok_or(LogQueryError::InvalidCursor)?,
        None => len,
    };
    let window_start = end.saturating_sub(limits.max_read_bytes.max(1) as u64);
    let mut buf = vec![0u8; (end - window_start) as usize];
    file.seek(SeekFrom::Start(window_start))
        .and_then(|_| file.read_exact(&mut buf))
        .map_err(|err| LogQueryError::Io(err.to_string()))?;

    // A window that starts mid-file begins inside a line: skip to the next line start.
    let mut region_start = window_start;
    let mut slice: &[u8] = &buf;
    if window_start > 0 {
        match slice.iter().position(|b| *b == b'\n') {
            Some(pos) => {
                region_start += pos as u64 + 1;
                slice = &slice[pos + 1..];
            }
            None => {
                // One line longer than the whole window: nothing readable, move past it.
                return Ok(QueryLogsResponse {
                    entries: Vec::new(),
                    truncated: true,
                    available_dates,
                    next_cursor: Some(window_start.to_string()),
                });
            }
        }
    }
    let mut records = parse_records(slice, region_start, parsed_date);
    if window_start > 0 {
        // The records before the first header continue a record that lies before the window:
        // leave them for the next call, whose window then ends at this header.
        // (`parse_records` turned them into a raw record; its offset is `region_start`.)
        let first_header = slice
            .split_inclusive(|b| *b == b'\n')
            .scan(region_start, |offset, raw| {
                let at = *offset;
                *offset += raw.len() as u64;
                Some((at, raw))
            })
            .find(|(_, raw)| {
                parse_header(String::from_utf8_lossy(raw).trim_end_matches(['\n', '\r'])).is_some()
            })
            .map(|(at, _)| at);
        match first_header {
            Some(at) if at > region_start => {
                records.retain(|r| r.start >= at);
                region_start = at;
            }
            Some(_) => {}
            None => {
                // No header in the whole window: keep it as raw lines, resume before it.
            }
        }
    }

    let limit = effective_limit(req, limits);
    let mut entries: Vec<LogEntry> = Vec::new();
    let mut oldest_taken: Option<u64> = None;
    let mut limit_reached = false;
    let mut past_since = false;
    for record in records.iter().rev() {
        if req
            .since
            .is_some_and(|since| record.entry.timestamp.timestamp_millis() < since)
        {
            past_since = true;
            break;
        }
        if !entry_matches(&record.entry, req) {
            continue;
        }
        if entries.len() == limit {
            limit_reached = true;
            break;
        }
        oldest_taken = Some(record.start);
        entries.push(record.entry.clone());
    }

    let more_before_window = region_start > 0;
    let (next_cursor, truncated) = if past_since {
        (None, false)
    } else if limit_reached {
        (oldest_taken.map(|o| o.to_string()), false)
    } else if more_before_window {
        (Some(region_start.to_string()), true)
    } else {
        (None, false)
    };
    Ok(QueryLogsResponse {
        entries,
        truncated,
        available_dates,
        next_cursor: next_cursor.filter(|c| c != "0"),
    })
}

/// Runs a query against the memory ring (`memory`, newest first) or the daemon's files.
pub fn run_query(
    memory: &[LogEntry],
    log_dir: &Path,
    app_name: &str,
    req: &QueryLogsRequest,
    limits: LogQueryLimits,
) -> Result<QueryLogsResponse, LogQueryError> {
    match &req.source {
        LogQuerySource::Memory => {
            let mut response = query_memory(memory, req, limits)?;
            response.available_dates = list_log_dates(log_dir, app_name);
            Ok(response)
        }
        LogQuerySource::DaemonFile { date } => {
            query_daily_file(log_dir, app_name, date, req, limits)
        }
    }
}

/// Reads up to `max_bytes` from the end of a daily file, starting at a line boundary.
/// Returns the text and whether older content was left out.
pub fn read_file_tail(
    log_dir: &Path,
    app_name: &str,
    date: &str,
    max_bytes: usize,
) -> Result<(String, bool), LogQueryError> {
    let (_, path) = daily_file_path(log_dir, app_name, date)?;
    let mut file = File::open(&path).map_err(|err| LogQueryError::Io(err.to_string()))?;
    let len = file
        .metadata()
        .map_err(|err| LogQueryError::Io(err.to_string()))?
        .len();
    let start = len.saturating_sub(max_bytes as u64);
    let mut buf = vec![0u8; (len - start) as usize];
    file.seek(SeekFrom::Start(start))
        .and_then(|_| file.read_exact(&mut buf))
        .map_err(|err| LogQueryError::Io(err.to_string()))?;
    let mut slice: &[u8] = &buf;
    if start > 0 {
        slice = match slice.iter().position(|b| *b == b'\n') {
            Some(pos) => &slice[pos + 1..],
            None => &[],
        };
    }
    Ok((String::from_utf8_lossy(slice).into_owned(), start > 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: LogQueryLimits = LogQueryLimits {
        max_read_bytes: 4096,
        max_entries: 1000,
    };

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("routeward_logq_{tag}_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn request(date: &str) -> QueryLogsRequest {
        QueryLogsRequest {
            source: LogQuerySource::DaemonFile {
                date: date.to_string(),
            },
            min_level: None,
            components: Vec::new(),
            text: None,
            pid: None,
            connection_id: None,
            since: None,
            until: None,
            limit: 100,
            cursor: None,
        }
    }

    fn line(minute: u32, level: &str, component: &str, message: &str) -> String {
        format!("[2026-11-22 10:{minute:02}:00 +00:00] [{level}] [{component}] {message}\n")
    }

    fn write_day(dir: &Path, content: &str) {
        fs::write(dir.join("RouteWard_20261122.log"), content).unwrap();
    }

    #[test]
    fn parses_lines_context_suffix_and_continuations() {
        let dir = temp_dir("parse");
        let mut content = String::new();
        content.push_str(&line(1, "INFO", "Engine", "started"));
        content.push_str(&line(
            2,
            "WARN",
            "TcpRelay",
            "blocked chrome.exe {conn=0123abcd pid=77}",
        ));
        content.push_str("  at stack frame one\n");
        content.push_str("  at stack frame two\r\n");
        content.push_str(&line(3, "ERROR", "Proxy", "boom {pid=9}"));
        write_day(&dir, &content);

        let res =
            query_daily_file(&dir, "RouteWard", "20261122", &request("20261122"), LIMITS).unwrap();
        assert_eq!(res.entries.len(), 3);
        // Newest first.
        assert_eq!(res.entries[0].message, "boom");
        assert_eq!(res.entries[0].context.as_ref().unwrap().pid, Some(9));
        let warn = &res.entries[1];
        assert_eq!(warn.level, LogLevel::Warn);
        assert_eq!(warn.component, "TcpRelay");
        assert_eq!(
            warn.message,
            "blocked chrome.exe\n  at stack frame one\n  at stack frame two"
        );
        // The suffix sat on the header line, so it is parsed from there.
        assert_eq!(
            warn.context.as_ref().unwrap().connection_id.as_deref(),
            Some("0123abcd")
        );
        assert_eq!(warn.context.as_ref().unwrap().pid, Some(77));
        assert_eq!(res.entries[2].message, "started");
        assert_eq!(res.available_dates, vec!["20261122".to_string()]);
        assert!(res.next_cursor.is_none());
        assert!(!res.truncated);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn keeps_unparseable_leading_lines_as_raw() {
        let dir = temp_dir("raw");
        let mut content = String::from("garbage without header\nsecond garbage\n");
        content.push_str(&line(1, "INFO", "Engine", "ok"));
        write_day(&dir, &content);
        let res =
            query_daily_file(&dir, "RouteWard", "20261122", &request("20261122"), LIMITS).unwrap();
        assert_eq!(res.entries.len(), 2);
        assert_eq!(res.entries[1].component, RAW_LINE_COMPONENT);
        assert_eq!(
            res.entries[1].message,
            "garbage without header\nsecond garbage"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn filters_by_level_component_text_pid_connection_and_time() {
        let dir = temp_dir("filters");
        let mut content = String::new();
        content.push_str(&line(1, "DEBUG", "A", "alpha"));
        content.push_str(&line(2, "INFO", "Engine", "Hello World"));
        content.push_str(&line(3, "WARN", "Proxy", "slow {conn=aaaa1111 pid=5}"));
        content.push_str(&line(4, "ERROR", "Proxy", "down {conn=bbbb2222 pid=6}"));
        content.push_str(&line(5, "INFO", "Engine", "later"));
        write_day(&dir, &content);
        let run = |tweak: &dyn Fn(&mut QueryLogsRequest)| {
            let mut req = request("20261122");
            tweak(&mut req);
            query_daily_file(&dir, "RouteWard", "20261122", &req, LIMITS)
                .unwrap()
                .entries
                .iter()
                .map(|e| e.message.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            run(&|r| r.min_level = Some(LogLevel::Warn)),
            vec!["down", "slow"]
        );
        assert_eq!(
            run(&|r| r.components = vec!["proxy".to_string()]),
            vec!["down", "slow"]
        );
        assert_eq!(
            run(&|r| r.text = Some("hello WORLD".to_string())),
            vec!["Hello World"]
        );
        assert_eq!(run(&|r| r.pid = Some(5)), vec!["slow"]);
        // A full connection id matches the 8 characters written in the file.
        assert_eq!(
            run(&|r| r.connection_id = Some("bbbb2222-0000-4000-8000-000000000000".to_string())),
            vec!["down"]
        );
        assert_eq!(
            run(&|r| r.connection_id = Some("bbbb".to_string())),
            vec!["down"]
        );
        let at = |minute: u32| {
            Utc.with_ymd_and_hms(2026, 11, 22, 10, minute, 0)
                .unwrap()
                .timestamp_millis()
        };
        assert_eq!(
            run(&|r| {
                r.since = Some(at(2));
                r.until = Some(at(4));
            }),
            vec!["down", "slow", "Hello World"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pages_backward_with_a_cursor_without_gaps_or_duplicates() {
        let dir = temp_dir("paging");
        let mut content = String::new();
        for i in 0..40u32 {
            content.push_str(&line(
                i,
                "INFO",
                "Engine",
                &format!("message number {i:02}"),
            ));
        }
        write_day(&dir, &content);
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let mut req = request("20261122");
            req.limit = 7;
            req.cursor = cursor.clone();
            let res = query_daily_file(&dir, "RouteWard", "20261122", &req, LIMITS).unwrap();
            seen.extend(res.entries.iter().map(|e| e.message.clone()));
            pages += 1;
            assert!(pages < 20, "paging must terminate");
            match res.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let expected: Vec<String> = (0..40u32)
            .rev()
            .map(|i| format!("message number {i:02}"))
            .collect();
        assert_eq!(seen, expected);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn byte_cap_truncates_and_the_cursor_resumes_without_losing_records() {
        let dir = temp_dir("cap");
        let mut content = String::new();
        for i in 0..60u32 {
            content.push_str(&line(i % 60, "INFO", "Engine", &format!("record {i:02}")));
            content.push_str("  continuation line\n");
        }
        write_day(&dir, &content);
        let tiny = LogQueryLimits {
            max_read_bytes: 600,
            max_entries: 1000,
        };
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut saw_truncated = false;
        for _ in 0..200 {
            let mut req = request("20261122");
            req.cursor = cursor.clone();
            let res = query_daily_file(&dir, "RouteWard", "20261122", &req, tiny).unwrap();
            saw_truncated |= res.truncated;
            seen.extend(res.entries.iter().map(|e| {
                assert!(e.message.ends_with("continuation line"), "{}", e.message);
                e.message.lines().next().unwrap().to_string()
            }));
            match res.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert!(saw_truncated);
        let expected: Vec<String> = (0..60u32).rev().map(|i| format!("record {i:02}")).collect();
        assert_eq!(seen, expected);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_traversal_bad_dates_and_foreign_cursors() {
        let dir = temp_dir("reject");
        write_day(&dir, &line(1, "INFO", "E", "x"));
        for bad in [
            "../20261122",
            "..\\20261122",
            "2026112",
            "202611222",
            "20261322",
            "20261122.log",
            "2026-11-2",
            "",
            "/etc/passwd",
            "C:\\Windows",
        ] {
            let err =
                query_daily_file(&dir, "RouteWard", bad, &request(bad), LIMITS).expect_err(bad);
            assert_eq!(err, LogQueryError::InvalidDate, "{bad}");
        }
        let mut req = request("20261122");
        req.cursor = Some("999999999".to_string());
        assert_eq!(
            query_daily_file(&dir, "RouteWard", "20261122", &req, LIMITS).unwrap_err(),
            LogQueryError::InvalidCursor
        );
        req.cursor = Some("not-a-number".to_string());
        assert_eq!(
            query_daily_file(&dir, "RouteWard", "20261122", &req, LIMITS).unwrap_err(),
            LogQueryError::InvalidCursor
        );
        // A missing day is an empty answer, not an error.
        let res =
            query_daily_file(&dir, "RouteWard", "20200101", &request("20200101"), LIMITS).unwrap();
        assert!(res.entries.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lists_only_allow_listed_file_names() {
        let dir = temp_dir("dates");
        for name in [
            "RouteWard_20261121.log",
            "RouteWard_20261122.log",
            "RouteWard_20261122.log.bak",
            "RouteWard_2026.log",
            "other.log",
            "Other_20261122.log",
        ] {
            fs::write(dir.join(name), "x").unwrap();
        }
        assert_eq!(
            list_log_dates(&dir, "RouteWard"),
            vec!["20261122".to_string(), "20261121".to_string()]
        );
        assert_eq!(log_dir_bytes(&dir, "RouteWard"), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    fn memory_entry(i: i64, level: LogLevel, ctx_pid: Option<u32>) -> LogEntry {
        LogEntry {
            id: i.to_string(),
            timestamp: Utc.timestamp_millis_opt(1_000 + i).unwrap(),
            level,
            component: "Engine".to_string(),
            message: format!("m{i}"),
            context: ctx_pid.map(|pid| LogContext {
                pid: Some(pid),
                connection_id: Some(format!("conn-{pid}-full-id")),
                host: None,
                port: None,
            }),
        }
    }

    #[test]
    fn memory_source_filters_and_pages_the_ring_buffer() {
        // Newest first, like `TelemetryHub::list_logs`.
        let entries: Vec<LogEntry> = (0..10)
            .rev()
            .map(|i| {
                memory_entry(
                    i,
                    if i % 2 == 0 {
                        LogLevel::Info
                    } else {
                        LogLevel::Warn
                    },
                    Some(i as u32 % 3),
                )
            })
            .collect();
        let mut req = request("20261122");
        req.source = LogQuerySource::Memory;
        req.min_level = Some(LogLevel::Warn);
        req.limit = 2;
        let first = query_memory(&entries, &req, LIMITS).unwrap();
        assert_eq!(
            first
                .entries
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>(),
            vec!["m9", "m7"]
        );
        req.cursor = first.next_cursor.clone();
        let second = query_memory(&entries, &req, LIMITS).unwrap();
        assert_eq!(
            second
                .entries
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>(),
            vec!["m5", "m3"]
        );
        req.cursor = second.next_cursor;
        let third = query_memory(&entries, &req, LIMITS).unwrap();
        assert_eq!(third.entries.len(), 1);
        assert!(third.next_cursor.is_none());

        let mut by_pid = request("20261122");
        by_pid.source = LogQuerySource::Memory;
        by_pid.pid = Some(1);
        by_pid.connection_id = Some("conn-1".to_string());
        let res = query_memory(&entries, &by_pid, LIMITS).unwrap();
        assert!(!res.entries.is_empty());
        assert!(res
            .entries
            .iter()
            .all(|e| e.context.as_ref().unwrap().pid == Some(1)));
    }

    #[test]
    fn source_json_matches_the_ui_contract() {
        let memory: LogQuerySource = serde_json::from_str("\"memory\"").unwrap();
        assert_eq!(memory, LogQuerySource::Memory);
        let file: LogQuerySource =
            serde_json::from_str(r#"{"daemonFile":{"date":"20261122"}}"#).unwrap();
        assert_eq!(
            file,
            LogQuerySource::DaemonFile {
                date: "20261122".to_string()
            }
        );
        let req: QueryLogsRequest = serde_json::from_str(
            r#"{"source":"memory","minLevel":"WARN","components":["proxy"],"text":"x","pid":3,"connectionId":"abc","since":1,"until":2,"limit":5,"cursor":"7"}"#,
        )
        .unwrap();
        assert_eq!(req.min_level, Some(LogLevel::Warn));
        assert_eq!(req.connection_id.as_deref(), Some("abc"));
    }

    #[test]
    fn tail_reader_starts_on_a_line_boundary() {
        let dir = temp_dir("tail");
        let mut content = String::new();
        for i in 0..30u32 {
            content.push_str(&line(i, "INFO", "Engine", &format!("message {i:02}")));
        }
        write_day(&dir, &content);
        let (text, cut) = read_file_tail(&dir, "RouteWard", "20261122", 300).unwrap();
        assert!(cut);
        assert!(text.starts_with("[2026-11-22"));
        assert!(text.ends_with("message 29\n"));
        let (all, cut) = read_file_tail(&dir, "RouteWard", "20261122", 1_000_000).unwrap();
        assert!(!cut);
        assert_eq!(all, content);
        let _ = fs::remove_dir_all(&dir);
    }
}
