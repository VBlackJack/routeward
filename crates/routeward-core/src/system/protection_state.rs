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

//! Persisted desired protection state of the daemon.
//!
//! The daemon remembers whether the user wants protection on, and until when a pause lasts, so
//! that protection survives a desktop exit and a reboot. The file lives next to the daemon
//! profile (same hardened directory). A missing or corrupt file always means "disabled": an
//! unreadable state must never turn the interception on by itself.

use crate::config::security::apply_secure_profile_file_permissions;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_CONFIG_SAVE};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// File name of the persisted protection state, created beside the daemon profile.
pub const PROTECTION_STATE_FILE_NAME: &str = "protection_state.json";
/// Longest pause the daemon accepts, in seconds (24 hours).
pub const MAX_PAUSE_SECS: u64 = 24 * 60 * 60;
/// Shortest pause the daemon accepts, in seconds.
pub const MIN_PAUSE_SECS: u64 = 1;
/// Longest sleep slice of the pause timer, in milliseconds. The timer compares the wall clock
/// after each slice, so a machine that slept through the deadline resumes protection promptly.
pub const PAUSE_TIMER_POLL_MS: u64 = 15_000;

const MILLIS_PER_SEC: u64 = 1_000;

/// What the user wants, independently of whether the engine is running right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionState {
    /// Protection is wanted (engine started by the user, or started again after a pause).
    #[serde(default)]
    pub protection_enabled: bool,
    /// While set and in the future, protection is paused until this Unix time in milliseconds.
    #[serde(default)]
    pub paused_until_epoch_ms: Option<u64>,
}

/// What the daemon must do at start, given the persisted state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupAction {
    /// Leave the engine stopped.
    StayStopped,
    /// Start the engine immediately.
    StartNow,
    /// The engine stays stopped until the given Unix time in milliseconds, then starts.
    StartAt(u64),
}

/// Pure startup decision: state and the current Unix time in milliseconds give the action.
/// A deadline further away than [`MAX_PAUSE_SECS`] cannot come from a valid pause and counts as
/// expired, so a damaged file can never keep protection off indefinitely.
pub fn decide_startup_action(state: &ProtectionState, now_ms: u64) -> StartupAction {
    if !state.protection_enabled {
        return StartupAction::StayStopped;
    }
    match state.paused_until_epoch_ms {
        Some(deadline) if deadline > now_ms => {
            let remaining = deadline - now_ms;
            if remaining > MAX_PAUSE_SECS * MILLIS_PER_SEC {
                StartupAction::StartNow
            } else {
                StartupAction::StartAt(deadline)
            }
        }
        _ => StartupAction::StartNow,
    }
}

/// Validates a pause duration in seconds.
pub fn is_valid_pause_secs(secs: u64) -> bool {
    (MIN_PAUSE_SECS..=MAX_PAUSE_SECS).contains(&secs)
}

/// Deadline in Unix milliseconds of a pause of `secs` seconds starting at `now_ms`.
pub fn pause_deadline_ms(now_ms: u64, secs: u64) -> u64 {
    now_ms.saturating_add(secs.saturating_mul(MILLIS_PER_SEC))
}

/// Current Unix time in milliseconds.
pub fn now_epoch_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

/// Path of the state file beside the daemon profile.
pub fn state_path_for_profile(profile_path: &Path) -> PathBuf {
    profile_path.with_file_name(PROTECTION_STATE_FILE_NAME)
}

impl ProtectionState {
    /// Loads the state; a missing, unreadable or corrupt file yields the disabled default.
    pub fn load_or_default(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Self>(raw.trim_start_matches('\u{feff}')).ok())
            .unwrap_or_default()
    }

    /// Atomically writes the state (temporary sibling, sync, rename). With `harden`, the daemon
    /// file permissions are applied as for the profile.
    pub fn save_to_path(&self, path: &Path, harden: bool) -> RouteWardResult<()> {
        let tmp_path = self.write_temp_sibling(path, harden)?;
        if let Err(err) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(save_error(err.to_string()));
        }
        Ok(())
    }

    /// Writes the state like [`Self::save_to_path`] but never replaces an existing file: the
    /// temporary sibling is published with a hard link, which fails when the target exists.
    /// Returns `Ok(true)` when the file was created and `Ok(false)` when it already existed (left
    /// untouched). The temporary file is always removed.
    pub fn save_new_to_path(&self, path: &Path, harden: bool) -> RouteWardResult<bool> {
        let tmp_path = self.write_temp_sibling(path, harden)?;
        let published = fs::hard_link(&tmp_path, path);
        let _ = fs::remove_file(&tmp_path);
        match published {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(save_error(err.to_string())),
        }
    }

    /// Serializes the state into a synced, optionally hardened temporary file next to `path`
    /// and returns its path. On failure the temporary file is removed.
    fn write_temp_sibling(&self, path: &Path, harden: bool) -> RouteWardResult<PathBuf> {
        let json = serde_json::to_string_pretty(self).map_err(|err| save_error(err.to_string()))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| save_error(err.to_string()))?;
            }
        }
        let tmp_path = path.with_file_name(format!(
            ".{PROTECTION_STATE_FILE_NAME}.{}.tmp",
            Uuid::new_v4()
        ));
        let write_result = (|| -> std::io::Result<()> {
            let mut file = fs::File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()
        })();
        if let Err(err) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(save_error(err.to_string()));
        }
        if harden {
            if let Err(err) = apply_secure_profile_file_permissions(&tmp_path, false) {
                let _ = fs::remove_file(&tmp_path);
                return Err(err);
            }
        }
        Ok(tmp_path)
    }
}

/// Wraps an I/O or serialization detail into the state-save configuration error.
fn save_error(detail: String) -> RouteWardError {
    RouteWardError::ConfigError {
        key: ERR_KEY_CONFIG_SAVE,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn temp_state_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("routeward_protection_state_{}", Uuid::new_v4()))
            .join(PROTECTION_STATE_FILE_NAME)
    }

    #[test]
    fn missing_file_means_disabled() {
        let state = ProtectionState::load_or_default(&temp_state_path());
        assert_eq!(state, ProtectionState::default());
        assert!(!state.protection_enabled);
    }

    #[test]
    fn save_then_load_round_trips_and_leaves_no_temporary_file() {
        let path = temp_state_path();
        let state = ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: Some(NOW + 5_000),
        };
        state.save_to_path(&path, false).expect("save");
        assert_eq!(ProtectionState::load_or_default(&path), state);
        let disabled = ProtectionState::default();
        disabled.save_to_path(&path, false).expect("overwrite");
        assert_eq!(ProtectionState::load_or_default(&path), disabled);
        let leftovers = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1, "only the state file remains");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn save_new_publishes_a_missing_file_and_leaves_no_temporary_file() {
        let path = temp_state_path();
        let state = ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: None,
        };
        assert!(state.save_new_to_path(&path, false).expect("save new"));
        assert_eq!(ProtectionState::load_or_default(&path), state);
        let leftovers = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1, "only the state file remains");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn save_new_never_replaces_an_existing_file_and_leaves_no_temporary_file() {
        let path = temp_state_path();
        let existing = ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: Some(NOW + 5_000),
        };
        existing.save_to_path(&path, false).expect("seed");
        let before = fs::read(&path).unwrap();
        let other = ProtectionState::default();
        assert!(!other.save_new_to_path(&path, false).expect("save new"));
        assert_eq!(fs::read(&path).unwrap(), before, "content untouched");
        assert_eq!(ProtectionState::load_or_default(&path), existing);
        let leftovers = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1, "only the state file remains");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn serialized_form_is_camel_case() {
        let json = serde_json::to_string(&ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: Some(7),
        })
        .unwrap();
        assert!(json.contains("protectionEnabled") && json.contains("pausedUntilEpochMs"));
    }

    #[test]
    fn corrupt_or_empty_file_means_disabled() {
        let path = temp_state_path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        for garbage in ["", "{not json", "[1,2]", "{\"protectionEnabled\":\"yes\"}"] {
            fs::write(&path, garbage).unwrap();
            assert_eq!(
                ProtectionState::load_or_default(&path),
                ProtectionState::default(),
                "garbage {garbage:?}"
            );
        }
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn decision_disabled_stays_stopped_even_with_a_deadline() {
        for paused in [None, Some(NOW + 1_000), Some(NOW - 1_000)] {
            let state = ProtectionState {
                protection_enabled: false,
                paused_until_epoch_ms: paused,
            };
            assert_eq!(
                decide_startup_action(&state, NOW),
                StartupAction::StayStopped
            );
        }
    }

    #[test]
    fn decision_enabled_without_pause_starts_now() {
        let state = ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: None,
        };
        assert_eq!(decide_startup_action(&state, NOW), StartupAction::StartNow);
    }

    #[test]
    fn decision_future_deadline_schedules_and_past_deadline_starts() {
        let future = ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: Some(NOW + 60_000),
        };
        assert_eq!(
            decide_startup_action(&future, NOW),
            StartupAction::StartAt(NOW + 60_000)
        );
        for deadline in [NOW, NOW - 1] {
            let expired = ProtectionState {
                protection_enabled: true,
                paused_until_epoch_ms: Some(deadline),
            };
            assert_eq!(
                decide_startup_action(&expired, NOW),
                StartupAction::StartNow
            );
        }
    }

    #[test]
    fn decision_absurd_deadline_starts_now() {
        let state = ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: Some(NOW + MAX_PAUSE_SECS * 1_000 + 1),
        };
        assert_eq!(decide_startup_action(&state, NOW), StartupAction::StartNow);
        let at_limit = ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: Some(NOW + MAX_PAUSE_SECS * 1_000),
        };
        assert!(matches!(
            decide_startup_action(&at_limit, NOW),
            StartupAction::StartAt(_)
        ));
    }

    #[test]
    fn pause_duration_bounds() {
        assert!(!is_valid_pause_secs(0));
        assert!(is_valid_pause_secs(1));
        assert!(is_valid_pause_secs(MAX_PAUSE_SECS));
        assert!(!is_valid_pause_secs(MAX_PAUSE_SECS + 1));
        assert_eq!(pause_deadline_ms(NOW, 2), NOW + 2_000);
    }

    #[test]
    fn state_file_sits_beside_the_profile() {
        let p = state_path_for_profile(Path::new("/x/y/active_profile.json"));
        assert_eq!(p.file_name().unwrap(), PROTECTION_STATE_FILE_NAME);
        assert_eq!(p.parent().unwrap(), Path::new("/x/y"));
    }
}
