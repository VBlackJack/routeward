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

use crate::telemetry::LogLevel;
use chrono::Local;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

/// Upper bound on lines waiting for the next flush; the oldest lines are dropped beyond it so a
/// stalled disk can never grow memory without bound.
const MAX_PENDING_LINES: usize = 20_000;

/// Date format used both for the log file name suffix and for detecting a date rollover.
const DATE_SUFFIX_FORMAT: &str = "%Y%m%d";

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
    /// When true, every `log` call flushes immediately (no background flusher is attached).
    flush_on_log: bool,
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
                .join(format!("{}_{}.log", self.app_name, date_suffix));
            match OpenOptions::new().create(true).append(true).open(file_path) {
                Ok(file) => {
                    *handle = Some(OpenLog { date_suffix, file });
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
        // Last owner gone: never lose queued lines on a clean stop.
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
        let interval = Duration::from_millis(flush_interval_ms);
        let spawned = std::thread::Builder::new()
            .name("routeward-log-flush".to_string())
            .spawn(move || loop {
                std::thread::sleep(interval);
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
                flush_on_log,
            }),
        }
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
        let line = format!("[{now}] [{level_str}] [{component}] {message}\n");
        {
            let mut q = self.inner.queue.lock();
            if q.len() >= MAX_PENDING_LINES {
                q.pop_front();
            }
            q.push_back(line);
        }
        if self.inner.flush_on_log || level == LogLevel::Error {
            self.flush();
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
        let temp_dir = std::env::temp_dir().join("routeward_logger_test");
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
    fn background_flusher_writes_and_drop_flushes_remaining_lines() {
        let temp_dir = std::env::temp_dir().join("routeward_logger_bg_test");
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
