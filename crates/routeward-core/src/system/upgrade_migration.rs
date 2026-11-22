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

//! Carries "protection was on" across an upgrade from a version that never persisted it.
//!
//! Versions up to 2026.1121.x did not write the protection state file, so the new daemon of a
//! major upgrade finds none and leaves protection off. The installer captures the answer of the
//! OLD daemon (`routeward ctl status`, redirected to a status file) before the old product is
//! removed, and the new CLI reads it back here once the upgrade is committed.

use crate::interceptor::RouteWardController;
use crate::system::protection_state::ProtectionState;
use serde::Deserialize;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};

/// File name of the old daemon status captured by the installer, created beside the profile.
pub const UPGRADE_STATUS_FILE_NAME: &str = "upgrade_status.json";

/// Path of the captured status file beside the daemon profile.
pub fn upgrade_status_path_for_profile(profile_path: &Path) -> PathBuf {
    profile_path.with_file_name(UPGRADE_STATUS_FILE_NAME)
}

/// Subset of the pretty-printed IPC response written by `routeward ctl status`.
#[derive(Debug, Deserialize)]
struct CapturedStatus {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    result: Option<CapturedDiagnostics>,
}

#[derive(Debug, Deserialize)]
struct CapturedDiagnostics {
    #[serde(default)]
    running: bool,
}

/// True only for a well-formed successful status whose diagnostics say the engine was running.
/// A missing, empty, truncated or otherwise unreadable capture means "not running", so a damaged
/// file can never turn the protection on. A UTF-8 byte order mark is tolerated.
pub fn captured_status_says_running(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    serde_json::from_str::<CapturedStatus>(text.trim_start_matches('\u{feff}').trim())
        .ok()
        .is_some_and(|status| status.ok && status.result.is_some_and(|diag| diag.running))
}

/// What the migration decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// A state file already exists (the previous version persisted it): left untouched.
    StateAlreadyPersisted,
    /// The old daemon was not running, or the capture is missing or unreadable.
    NotRunning,
    /// The new daemon accepted the start request and persisted the choice itself.
    PersistedByDaemon,
    /// The new daemon could not be used: the enabled state was written directly.
    WrittenDirectly,
    /// The enabled state could not be written.
    WriteFailed,
}

/// Decides and applies the migration, then always removes the status file (best effort).
///
/// `start_via_daemon` asks the new daemon to start protection (which persists the choice) and
/// returns whether it succeeded; it is injected so the logic runs without a pipe. The service
/// is never started here, and an existing state file is never overwritten.
pub async fn migrate_upgrade_state<F, Fut>(
    state_path: &Path,
    status_path: &Path,
    start_via_daemon: F,
) -> MigrationOutcome
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = bool>,
{
    let running = fs::read(status_path)
        .map(|raw| captured_status_says_running(&raw))
        .unwrap_or(false);
    let outcome = if state_path.exists() {
        MigrationOutcome::StateAlreadyPersisted
    } else if !running {
        MigrationOutcome::NotRunning
    } else if start_via_daemon().await {
        MigrationOutcome::PersistedByDaemon
    } else {
        let enabled = ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: None,
        };
        match enabled.save_to_path(
            state_path,
            RouteWardController::detect_elevated_privileges(),
        ) {
            Ok(()) => MigrationOutcome::WrittenDirectly,
            Err(_) => MigrationOutcome::WriteFailed,
        }
    };
    let _ = fs::remove_file(status_path);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::protection_state::PROTECTION_STATE_FILE_NAME;
    use uuid::Uuid;

    const RUNNING_JSON: &str =
        r#"{"id":"1","ok":true,"result":{"daemonConnected":true,"running":true}}"#;
    const STOPPED_JSON: &str = r#"{"id":"1","ok":true,"result":{"running":false}}"#;

    struct Dirs {
        root: PathBuf,
        state: PathBuf,
        status: PathBuf,
    }

    fn dirs() -> Dirs {
        let root =
            std::env::temp_dir().join(format!("routeward_upgrade_migration_{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        Dirs {
            state: root.join(PROTECTION_STATE_FILE_NAME),
            status: root.join(UPGRADE_STATUS_FILE_NAME),
            root,
        }
    }

    #[test]
    fn running_status_is_detected_and_everything_else_is_not() {
        assert!(captured_status_says_running(RUNNING_JSON.as_bytes()));
        let pretty =
            "{\n  \"id\": \"1\",\n  \"ok\": true,\n  \"result\": {\n    \"running\": true\n  }\n}";
        assert!(captured_status_says_running(pretty.as_bytes()));
        assert!(!captured_status_says_running(STOPPED_JSON.as_bytes()));
        assert!(!captured_status_says_running(
            br#"{"ok":false,"result":{"running":true}}"#
        ));
        assert!(!captured_status_says_running(br#"{"ok":true}"#));
        for garbage in [&b""[..], b"   ", b"{not json", b"[1,2]", b"\xff\xfe\x00"] {
            assert!(!captured_status_says_running(garbage), "{garbage:?}");
        }
    }

    #[test]
    fn utf8_bom_is_tolerated() {
        let mut raw = vec![0xEF, 0xBB, 0xBF];
        raw.extend_from_slice(RUNNING_JSON.as_bytes());
        assert!(captured_status_says_running(&raw));
    }

    #[tokio::test]
    async fn running_with_a_working_daemon_leaves_persistence_to_it() {
        let d = dirs();
        fs::write(&d.status, RUNNING_JSON).unwrap();
        let outcome = migrate_upgrade_state(&d.state, &d.status, || async { true }).await;
        assert_eq!(outcome, MigrationOutcome::PersistedByDaemon);
        assert!(!d.state.exists(), "the daemon owns the write in that case");
        assert!(!d.status.exists());
        let _ = fs::remove_dir_all(&d.root);
    }

    #[tokio::test]
    async fn unreachable_daemon_falls_back_to_writing_the_enabled_state() {
        let d = dirs();
        fs::write(&d.status, RUNNING_JSON).unwrap();
        let outcome = migrate_upgrade_state(&d.state, &d.status, || async { false }).await;
        assert_eq!(outcome, MigrationOutcome::WrittenDirectly);
        assert_eq!(
            ProtectionState::load_or_default(&d.state),
            ProtectionState {
                protection_enabled: true,
                paused_until_epoch_ms: None
            }
        );
        assert!(!d.status.exists());
        let _ = fs::remove_dir_all(&d.root);
    }

    #[tokio::test]
    async fn not_running_missing_or_garbage_status_changes_nothing() {
        for content in [Some(STOPPED_JSON), Some("garbage"), Some(""), None] {
            let d = dirs();
            if let Some(text) = content {
                fs::write(&d.status, text).unwrap();
            }
            let outcome = migrate_upgrade_state(&d.state, &d.status, || async {
                panic!("the daemon must not be called");
                #[allow(unreachable_code)]
                false
            })
            .await;
            assert_eq!(outcome, MigrationOutcome::NotRunning);
            assert!(!d.state.exists());
            assert!(!d.status.exists());
            let _ = fs::remove_dir_all(&d.root);
        }
    }

    #[tokio::test]
    async fn existing_state_file_is_never_overwritten() {
        let d = dirs();
        let disabled = ProtectionState::default();
        disabled.save_to_path(&d.state, false).unwrap();
        fs::write(&d.status, RUNNING_JSON).unwrap();
        let outcome = migrate_upgrade_state(&d.state, &d.status, || async {
            panic!("the daemon must not be called");
            #[allow(unreachable_code)]
            false
        })
        .await;
        assert_eq!(outcome, MigrationOutcome::StateAlreadyPersisted);
        assert_eq!(ProtectionState::load_or_default(&d.state), disabled);
        assert!(!d.status.exists());
        let _ = fs::remove_dir_all(&d.root);
    }

    #[test]
    fn status_file_sits_beside_the_profile() {
        let p = upgrade_status_path_for_profile(Path::new("/x/y/active_profile.json"));
        assert_eq!(p.file_name().unwrap(), UPGRADE_STATUS_FILE_NAME);
        assert_eq!(p.parent().unwrap(), Path::new("/x/y"));
    }
}
