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
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Thread-safe daily rolling file logger (`logs/<AppName>_<yyyyMMdd>.log`).
/// Queues formatted entries in memory and flushes them without panicking or propagating I/O errors.
#[derive(Clone)]
pub struct FileLogger {
    log_dir: PathBuf,
    app_name: String,
    enabled: Arc<AtomicBool>,
    queue: Arc<Mutex<VecDeque<String>>>,
}

impl FileLogger {
    /// Creates a new `FileLogger` targeting `<log_dir>/<app_name>_<yyyyMMdd>.log`.
    pub fn new(
        log_dir: impl Into<PathBuf>,
        app_name: impl Into<String>,
        initially_enabled: bool,
    ) -> Self {
        Self {
            log_dir: log_dir.into(),
            app_name: app_name.into(),
            enabled: Arc::new(AtomicBool::new(initially_enabled)),
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Enables or disables file logging at runtime without restarting the engine.
    pub fn set_enabled(&self, enable: bool) {
        self.enabled.store(enable, Ordering::SeqCst);
    }

    /// Returns whether file logging is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Enqueues a structured log line `[yyyy-MM-dd HH:mm:ss +HH:MM] [LEVEL] message` and flushes the queue.
    pub fn log(&self, level: LogLevel, component: &str, message: &str) {
        if !self.is_enabled() {
            return;
        }
        let now = Local::now().format("%Y-%m-%d %H:%M:%S %:z");
        let level_str = match level {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };
        let line = format!("[{now}] [{level_str}] [{component}] {message}\n");
        {
            let mut q = self.queue.lock();
            q.push_back(line);
        }
        self.flush();
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
        let pending: Vec<String> = {
            let mut q = self.queue.lock();
            if q.is_empty() {
                return;
            }
            q.drain(..).collect()
        };

        if fs::create_dir_all(&self.log_dir).is_err() {
            return;
        }

        let date_suffix = Local::now().format("%Y%m%d");
        let file_name = format!("{}_{}.log", self.app_name, date_suffix);
        let file_path = self.log_dir.join(file_name);

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(file_path) {
            for line in pending {
                let _ = file.write_all(line.as_bytes());
            }
            let _ = file.flush();
        }
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
}
