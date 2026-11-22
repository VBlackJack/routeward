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

//! Per-user "already shown" flags for one-time notices (balloons).
//!
//! The flags live in a small JSON file next to the other per-user state of the desktop app
//! (`%LOCALAPPDATA%\RouteWard` on Windows), so a notice shown once is never shown again, even
//! after a restart.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// File name of the flags, inside the per-user data directory.
pub const NOTICE_FLAGS_FILE_NAME: &str = "desktop_notices.json";
/// First exit with the background service installed: protection keeps running.
pub const NOTICE_EXIT_BACKGROUND: &str = "exit_background";
/// First close of the window while the app keeps running in the tray.
pub const NOTICE_CLOSE_TO_TRAY: &str = "close_to_tray";

#[derive(Debug, Default, Serialize, Deserialize)]
struct NoticeFlagsFile {
    #[serde(default)]
    seen: BTreeSet<String>,
}

/// Remembers which one-time notices were already shown.
pub struct NoticeFlags {
    path: PathBuf,
    seen: Mutex<Option<BTreeSet<String>>>,
}

impl NoticeFlags {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            seen: Mutex::new(None),
        }
    }

    fn load(&self) -> BTreeSet<String> {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|text| serde_json::from_str::<NoticeFlagsFile>(&text).ok())
            .map(|file| file.seen)
            .unwrap_or_default()
    }

    /// True when `flag` was already claimed (in this run or an earlier one).
    pub fn has_seen(&self, flag: &str) -> bool {
        let mut guard = self.seen.lock();
        guard.get_or_insert_with(|| self.load()).contains(flag)
    }

    /// Claims `flag`: returns true the first time only, and records it on disk. A write failure
    /// is not an error here: the notice is still limited to once per run.
    pub fn claim(&self, flag: &str) -> bool {
        let mut guard = self.seen.lock();
        let seen = guard.get_or_insert_with(|| self.load());
        if !seen.insert(flag.to_string()) {
            return false;
        }
        let file = NoticeFlagsFile { seen: seen.clone() };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(&file) {
            let _ = std::fs::write(&self.path, json);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_flags_path(tag: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir()
            .join(format!(
                "routeward-notices-{tag}-{}-{unique}",
                std::process::id()
            ))
            .join(NOTICE_FLAGS_FILE_NAME)
    }

    #[test]
    fn a_notice_is_claimed_once_and_remembered_across_instances() {
        let path = temp_flags_path("claim");
        let first = NoticeFlags::new(path.clone());
        assert!(!first.has_seen(NOTICE_EXIT_BACKGROUND));
        assert!(first.claim(NOTICE_EXIT_BACKGROUND));
        assert!(!first.claim(NOTICE_EXIT_BACKGROUND));
        assert!(first.has_seen(NOTICE_EXIT_BACKGROUND));

        // A new run reads the file written by the first one.
        let second = NoticeFlags::new(path.clone());
        assert!(second.has_seen(NOTICE_EXIT_BACKGROUND));
        assert!(!second.claim(NOTICE_EXIT_BACKGROUND));
        // Another notice is independent.
        assert!(second.claim(NOTICE_CLOSE_TO_TRAY));

        let _ = std::fs::remove_dir_all(path.parent().expect("parent dir"));
    }

    #[test]
    fn an_unreadable_flag_file_counts_as_nothing_seen() {
        let path = temp_flags_path("corrupt");
        std::fs::create_dir_all(path.parent().expect("parent dir")).expect("create dir");
        std::fs::write(&path, b"{not json").expect("write corrupt file");
        let flags = NoticeFlags::new(path.clone());
        assert!(!flags.has_seen(NOTICE_CLOSE_TO_TRAY));
        assert!(flags.claim(NOTICE_CLOSE_TO_TRAY));
        let _ = std::fs::remove_dir_all(path.parent().expect("parent dir"));
    }
}
