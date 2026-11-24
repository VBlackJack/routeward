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

use crate::telemetry::{LogContext, LogLevel};
use chrono::{Local, NaiveDate};
use parking_lot::{Condvar, Mutex};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

/// Upper bound on lines waiting for the next flush; the oldest lines are dropped beyond it so a
/// stalled disk can never grow memory without bound.
const MAX_PENDING_LINES: usize = 20_000;

/// Date format used both for the log file name suffix and for detecting a date rollover.
const DATE_SUFFIX_FORMAT: &str = "%Y%m%d";

/// Extension of the daily log files.
const LOG_FILE_EXTENSION: &str = ".log";

/// Number of leading characters of a connection id written in the line suffix.
const CONNECTION_ID_SUFFIX_CHARS: usize = 8;

/// Length of the `yyyyMMdd` date in a log file name.
const DATE_SUFFIX_LEN: usize = 8;

/// Name of the daily log file of `app_name` for `date_suffix` (`yyyyMMdd`).
pub fn log_file_name(app_name: &str, date_suffix: &str) -> String {
    format!("{app_name}_{date_suffix}{LOG_FILE_EXTENSION}")
}

/// Date encoded in a daily log file name (`<app_name>_<yyyyMMdd>.log`), `None` for any other
/// name. The match is exact: no path separator, no extra characters, a real calendar date.
pub fn parse_log_file_date(app_name: &str, file_name: &str) -> Option<NaiveDate> {
    let rest = file_name.strip_prefix(app_name)?.strip_prefix('_')?;
    let digits = rest.strip_suffix(LOG_FILE_EXTENSION)?;
    if digits.len() != DATE_SUFFIX_LEN || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    NaiveDate::parse_from_str(digits, DATE_SUFFIX_FORMAT).ok()
}

/// Deletes the daily log files of `app_name` in `log_dir` that are `retention_days` days or more
/// older than `today`. Other files are never touched. Returns the number of files removed; I/O
/// errors are ignored (a file in use is retried at the next rollover).
pub fn prune_old_logs(
    log_dir: &std::path::Path,
    app_name: &str,
    retention_days: u32,
    today: NaiveDate,
) -> usize {
    if retention_days == 0 {
        return 0;
    }
    let Ok(entries) = fs::read_dir(log_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(date) = name.to_str().and_then(|n| parse_log_file_date(app_name, n)) else {
            continue;
        };
        if (today - date).num_days() >= i64::from(retention_days)
            && fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Stable suffix appended to a log line that refers to a connection:
/// ` {conn=<first 8 characters of the id> pid=<pid>}` (each part only when known), empty when the
/// context carries neither. The log query parses this suffix back.
pub fn context_suffix(context: &LogContext) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(id) = context.connection_id.as_deref().filter(|id| !id.is_empty()) {
        let short: String = id.chars().take(CONNECTION_ID_SUFFIX_CHARS).collect();
        parts.push(format!("conn={short}"));
    }
    if let Some(pid) = context.pid {
        parts.push(format!("pid={pid}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" {{{}}}", parts.join(" "))
    }
}

/// Open log file together with the date suffix it was opened for.
struct OpenLog {
    date_suffix: String,
    file: File,
}

struct Inner {
    log_dir: PathBuf,
    app_name: String,
    enabled: AtomicBool,
    queue: Mutex<VecDeque<String>>,
    handle: Mutex<Option<OpenLog>>,
    /// Signals the background flusher to wake early on `LogLevel::Error` or shutdown.
    /// Held behind its own `Arc` so the flusher thread can wait without holding a strong `Arc<Inner>`.
    flush_signal: Arc<(Mutex<bool>, Condvar)>,
    /// When true, every `log` call flushes immediately (no background flusher is attached).
    flush_on_log: bool,
    /// Days of daily log files kept; 0 disables pruning. Applied each time a file is opened.
    retention_days: AtomicU32,
}

impl Inner {
    fn flush(&self) {
        let pending: Vec<String> = {
            let mut q = self.queue.lock();
            if q.is_empty() {
                return;
            }
            q.drain(..).collect()
        };

        let mut handle = self.handle.lock();
        let date_suffix = Local::now().format(DATE_SUFFIX_FORMAT).to_string();
        let needs_open = match handle.as_ref() {
            Some(open) => open.date_suffix != date_suffix,
            None => true,
        };
        if needs_open {
            *handle = None;
            if fs::create_dir_all(&self.log_dir).is_err() {
                return;
            }
            let file_path = self
                .log_dir
                .join(log_file_name(&self.app_name, &date_suffix));
            match OpenOptions::new().create(true).append(true).open(file_path) {
                Ok(file) => {
                    *handle = Some(OpenLog { date_suffix, file });
                    prune_old_logs(
                        &self.log_dir,
                        &self.app_name,
                        self.retention_days.load(Ordering::Relaxed),
                        Local::now().date_naive(),
                    );
                }
                Err(_) => return,
            }
        }
        if let Some(open) = handle.as_mut() {
            let mut failed = false;
            for line in &pending {
                if open.file.write_all(line.as_bytes()).is_err() {
                    failed = true;
                    break;
                }
            }
            if failed || open.file.flush().is_err() {
                // Drop the handle so the next flush reopens the file (rotated, deleted or locked).
                *handle = None;
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Wake the background flusher if it is waiting, then flush any remaining lines.
        let (lock, cv) = &*self.flush_signal;
        *lock.lock() = true;
        cv.notify_all();
        self.flush();
    }
}

/// Thread-safe daily rolling file logger (`logs/<AppName>_<yyyyMMdd>.log`).
/// Keeps the day's file handle open (reopened on date rollover), queues formatted entries in
/// memory and flushes them without panicking or propagating I/O errors. Created with
/// [`FileLogger::with_flush_interval`], a background thread flushes the queue periodically and the
/// last owner flushes on drop; created with [`FileLogger::new`], every entry is flushed at once.
#[derive(Clone)]
pub struct FileLogger {
    inner: Arc<Inner>,
}

impl FileLogger {
    /// Creates a new `FileLogger` targeting `<log_dir>/<app_name>_<yyyyMMdd>.log` that flushes on
    /// every `log` call.
    pub fn new(
        log_dir: impl Into<PathBuf>,
        app_name: impl Into<String>,
        initially_enabled: bool,
    ) -> Self {
        Self::build(log_dir.into(), app_name.into(), initially_enabled, true)
    }

    /// Creates a logger whose queue is flushed by a background thread every `flush_interval_ms`
    /// milliseconds (and on drop of the last clone). An interval of zero falls back to flushing on
    /// every `log` call.
    pub fn with_flush_interval(
        log_dir: impl Into<PathBuf>,
        app_name: impl Into<String>,
        initially_enabled: bool,
        flush_interval_ms: u64,
    ) -> Self {
        let log_dir = log_dir.into();
        let app_name = app_name.into();
        if flush_interval_ms == 0 {
            return Self::build(log_dir, app_name, initially_enabled, true);
        }
        let logger = Self::build(log_dir.clone(), app_name.clone(), initially_enabled, false);
        let weak: Weak<Inner> = Arc::downgrade(&logger.inner);
        let signal = Arc::clone(&logger.inner.flush_signal);
        let interval = Duration::from_millis(flush_interval_ms);
        let spawned = std::thread::Builder::new()
            .name("routeward-log-flush".to_string())
            .spawn(move || loop {
                {
                    let (lock, cv) = &*signal;
                    let mut signaled = lock.lock();
                    if !*signaled {
                        cv.wait_for(&mut signaled, interval);
                    }
                    *signaled = false;
                }
                match weak.upgrade() {
                    Some(inner) => inner.flush(),
                    None => break,
                }
            });
        if spawned.is_err() {
            // Without a flusher thread fall back to synchronous flushing so nothing is stranded.
            return Self::build(log_dir, app_name, initially_enabled, true);
        }
        logger
    }

    fn build(log_dir: PathBuf, app_name: String, enabled: bool, flush_on_log: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                log_dir,
                app_name,
                enabled: AtomicBool::new(enabled),
                queue: Mutex::new(VecDeque::new()),
                handle: Mutex::new(None),
                flush_signal: Arc::new((Mutex::new(false), Condvar::new())),
                flush_on_log,
                retention_days: AtomicU32::new(0),
            }),
        }
    }

    /// Sets how many days of daily log files are kept (0 keeps everything). Old files are removed
    /// each time the logger opens a day's file, that is at the first write and at every rollover.
    pub fn set_retention_days(&self, days: u32) {
        self.inner.retention_days.store(days, Ordering::Relaxed);
    }

    /// Directory the daily files are written to.
    pub fn log_dir(&self) -> &std::path::Path {
        &self.inner.log_dir
    }

    /// Enables or disables file logging at runtime without restarting the engine.
    pub fn set_enabled(&self, enable: bool) {
        self.inner.enabled.store(enable, Ordering::SeqCst);
    }

    /// Returns whether file logging is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::Relaxed)
    }

    /// Enqueues a structured log line `[yyyy-MM-dd HH:mm:ss +HH:MM] [LEVEL] message`. Flushes at once
    /// in synchronous mode and for errors; otherwise the background flusher writes it.
    pub fn log(&self, level: LogLevel, component: &str, message: &str) {
        self.log_with_context(level, component, message, None);
    }

    /// Same as [`Self::log`]; when `context` names a connection or a pid, the line ends with the
    /// stable suffix built by [`context_suffix`].
    pub fn log_with_context(
        &self,
        level: LogLevel,
        component: &str,
        message: &str,
        context: Option<&LogContext>,
    ) {
        if !self.is_enabled() {
            return;
        }
        let now = Local::now().format("%Y-%m-%d %H:%M:%S %:z");
        let level_str = match level {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };
        let suffix = context.map(context_suffix).unwrap_or_default();
        let line = format!("[{now}] [{level_str}] [{component}] {message}{suffix}\n");
        {
            let mut q = self.inner.queue.lock();
            if q.len() >= MAX_PENDING_LINES {
                q.pop_front();
            }
            q.push_back(line);
        }
        if self.inner.flush_on_log {
            self.flush();
        } else if level == LogLevel::Error {
            // Wake the dedicated flusher thread instead of blocking the caller (which may be a
            // Tokio async worker thread).
            let (lock, cv) = &*self.inner.flush_signal;
            *lock.lock() = true;
            cv.notify_one();
        }
    }

    /// Enqueues an error entry with an attached error/exception cause and flushes the queue.
    pub fn log_error_with_cause(
        &self,
        component: &str,
        message: &str,
        cause: &dyn std::error::Error,
    ) {
        let combined = format!("{message} | cause: {cause}");
        self.log(LogLevel::Error, component, &combined);
    }

    /// Drains the in-memory queue and appends all pending lines to today's log file.
    /// Never panics or returns an error to the caller.
    pub fn flush(&self) {
        self.inner.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_toggles_daily_log_file() {
        let temp_dir =
            std::env::temp_dir().join(format!("routeward_logger_test_{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&temp_dir);

        let logger = FileLogger::new(&temp_dir, "RouteWard", true);
        assert!(logger.is_enabled());
        logger.log(
            LogLevel::Info,
            "UnitTest",
            "Initialized test logger session id=1",
        );

        logger.set_enabled(false);
        assert!(!logger.is_enabled());
        logger.log(LogLevel::Warn, "UnitTest", "Should not be written");
        logger.flush();

        let date_suffix = Local::now().format("%Y%m%d");
        let expected_file = temp_dir.join(format!("RouteWard_{date_suffix}.log"));
        let content = fs::read_to_string(&expected_file).expect("Log file created");
        assert!(content.contains("[INFO] [UnitTest] Initialized test logger session id=1"));
        assert!(!content.contains("Should not be written"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn appends_the_context_suffix_only_when_the_entry_has_a_context() {
        let ctx = LogContext {
            pid: Some(4242),
            connection_id: Some("0123456789abcdef".to_string()),
            host: Some("example.com".to_string()),
            port: Some(443),
        };
        assert_eq!(context_suffix(&ctx), " {conn=01234567 pid=4242}");
        let pid_only = LogContext {
            pid: Some(7),
            ..LogContext::default()
        };
        assert_eq!(context_suffix(&pid_only), " {pid=7}");
        assert_eq!(context_suffix(&LogContext::default()), "");

        let temp_dir =
            std::env::temp_dir().join(format!("routeward_logger_ctx_{}", uuid::Uuid::new_v4()));
        let logger = FileLogger::new(&temp_dir, "RouteWard", true);
        logger.log_with_context(LogLevel::Warn, "Ctx", "blocked it", Some(&ctx));
        logger.log(LogLevel::Info, "Ctx", "plain");
        let date_suffix = Local::now().format("%Y%m%d").to_string();
        let content =
            fs::read_to_string(temp_dir.join(log_file_name("RouteWard", &date_suffix))).unwrap();
        assert!(content.contains("[WARN] [Ctx] blocked it {conn=01234567 pid=4242}\n"));
        assert!(content.contains("[INFO] [Ctx] plain\n"));
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn parses_only_exact_daily_log_file_names() {
        let ok = parse_log_file_date("RouteWard", "RouteWard_20261122.log");
        assert_eq!(ok, NaiveDate::from_ymd_opt(2026, 11, 22));
        for bad in [
            "RouteWard_2026112.log",
            "RouteWard_202611222.log",
            "RouteWard_20261322.log",
            "RouteWard_20261122.log.bak",
            "RouteWard_20261122.txt",
            "Other_20261122.log",
            "RouteWard-20261122.log",
            "../RouteWard_20261122.log",
            "RouteWard_2026112a.log",
            "RouteWard_.log",
            "",
        ] {
            assert_eq!(parse_log_file_date("RouteWard", bad), None, "{bad}");
        }
    }

    #[test]
    fn prunes_only_daily_logs_older_than_the_retention() {
        let dir =
            std::env::temp_dir().join(format!("routeward_logger_prune_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 11, 22).unwrap();
        for name in [
            "RouteWard_20261122.log",
            "RouteWard_20261109.log",
            "RouteWard_20261108.log",
            "RouteWard_20250101.log",
            "notes.txt",
            "Other_20250101.log",
        ] {
            fs::write(dir.join(name), "x").unwrap();
        }
        assert_eq!(prune_old_logs(&dir, "RouteWard", 14, today), 2);
        let mut left: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "Other_20250101.log",
                "RouteWard_20261109.log",
                "RouteWard_20261122.log",
                "notes.txt"
            ]
        );
        assert_eq!(prune_old_logs(&dir, "RouteWard", 0, today), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn opening_a_day_file_prunes_expired_logs_when_retention_is_set() {
        let dir =
            std::env::temp_dir().join(format!("routeward_logger_ret_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let old = dir.join("RouteWard_20200101.log");
        fs::write(&old, "old").unwrap();
        let logger = FileLogger::new(&dir, "RouteWard", true);
        logger.set_retention_days(14);
        logger.log(LogLevel::Info, "T", "now");
        assert!(!old.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn background_flusher_writes_and_drop_flushes_remaining_lines() {
        let temp_dir =
            std::env::temp_dir().join(format!("routeward_logger_bg_test_{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&temp_dir);
        let date_suffix = Local::now().format("%Y%m%d");
        let expected_file = temp_dir.join(format!("RouteWard_{date_suffix}.log"));

        let logger = FileLogger::with_flush_interval(&temp_dir, "RouteWard", true, 20);
        logger.log(LogLevel::Info, "UnitTest", "first line");
        // Poll for the background flusher instead of relying on one fixed sleep.
        let mut seen = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(20));
            if fs::read_to_string(&expected_file)
                .map(|c| c.contains("first line"))
                .unwrap_or(false)
            {
                seen = true;
                break;
            }
        }
        assert!(seen, "background flusher must write the queued line");

        logger.log(LogLevel::Info, "UnitTest", "last line before drop");
        drop(logger);
        let content = fs::read_to_string(&expected_file).expect("log file");
        assert!(content.contains("last line before drop"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
