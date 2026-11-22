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

//! Daemon-side desired protection: persistence across restarts and timed pauses.

use super::{RouteWardController, COMPONENT_ENGINE};
use crate::config::InterceptionMode;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_DAEMON_INVALID_PAUSE};
use crate::system::protection_state::{
    decide_startup_action, is_valid_pause_secs, now_epoch_ms, pause_deadline_ms, ProtectionState,
    StartupAction, MAX_PAUSE_SECS, PAUSE_TIMER_POLL_MS,
};
use crate::telemetry::LogLevel;
use parking_lot::Mutex;
use std::path::PathBuf;
use std::time::Duration;
use tokio::task::JoinHandle;

/// In-memory side of the persisted protection state.
pub(crate) struct ProtectionRuntime {
    /// State file; `None` for controllers that must not persist (desktop-embedded, CLI, tests).
    path: Option<PathBuf>,
    state: Mutex<ProtectionState>,
    pause_task: Mutex<Option<JoinHandle<()>>>,
    /// Error key of the last failed automatic start, cleared by the next successful start.
    auto_start_error_key: Mutex<Option<String>>,
}

impl ProtectionRuntime {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            state: Mutex::new(ProtectionState::default()),
            pause_task: Mutex::new(None),
            auto_start_error_key: Mutex::new(None),
        }
    }
}

impl RouteWardController {
    /// Enables persistence of the desired protection state at `path` (daemon only). Must be
    /// called before the controller is cloned.
    pub fn with_protection_state_path(mut self, path: PathBuf) -> Self {
        self.protection = std::sync::Arc::new(ProtectionRuntime::new(Some(path)));
        self
    }

    fn save_protection_state(&self, state: &ProtectionState) {
        let Some(path) = self.protection.path.as_ref() else {
            return;
        };
        let harden = Self::detect_elevated_privileges();
        if let Err(err) = state.save_to_path(path, harden) {
            self.telemetry.push_log(
                LogLevel::Error,
                COMPONENT_ENGINE,
                format!("Cannot persist the protection state: {err}"),
            );
        }
    }

    fn cancel_pause_timer(&self) {
        if let Some(handle) = self.protection.pause_task.lock().take() {
            handle.abort();
        }
    }

    /// Starts the relay listeners and, outside relay-only mode, the transparent interceptor.
    /// On a transparent interceptor failure the engine is stopped again. Clears the recorded
    /// automatic start error on success.
    pub fn start_protection(&self) -> RouteWardResult<()> {
        self.start_engine()?;
        let mode = self.profile.read().interception_mode;
        if mode != InterceptionMode::Relay {
            if let Err(err) = self.start_transparent_interceptor() {
                self.stop_engine();
                return Err(err);
            }
        }
        *self.protection.auto_start_error_key.lock() = None;
        Ok(())
    }

    /// Records the user's choice (start = true, stop = false) and persists it. Either choice
    /// cancels a pending pause.
    pub fn record_protection_choice(&self, enabled: bool) {
        self.cancel_pause_timer();
        let mut state = self.protection.state.lock();
        *state = ProtectionState {
            protection_enabled: enabled,
            paused_until_epoch_ms: None,
        };
        self.save_protection_state(&state);
    }

    /// Stops the engine now and starts it again after `duration_secs`. The deadline is
    /// persisted, so a restart of the daemon or of the machine keeps the pause.
    /// Returns the deadline as Unix milliseconds.
    pub fn pause_protection(&self, duration_secs: u64) -> RouteWardResult<u64> {
        if !is_valid_pause_secs(duration_secs) {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INVALID_PAUSE,
                detail: format!(
                    "Pause duration {duration_secs}s is outside 1..={MAX_PAUSE_SECS} seconds"
                ),
            });
        }
        self.cancel_pause_timer();
        self.stop_engine();
        let deadline = pause_deadline_ms(now_epoch_ms(), duration_secs);
        {
            let mut state = self.protection.state.lock();
            *state = ProtectionState {
                protection_enabled: true,
                paused_until_epoch_ms: Some(deadline),
            };
            self.save_protection_state(&state);
        }
        self.schedule_resume(deadline);
        Ok(deadline)
    }

    /// Unix time in milliseconds at which a running pause ends, `None` when not paused.
    pub fn paused_until_epoch_ms(&self) -> Option<u64> {
        let now = now_epoch_ms();
        self.protection
            .state
            .lock()
            .paused_until_epoch_ms
            .filter(|deadline| *deadline > now)
    }

    /// Error key of the last failed automatic start, if no later start succeeded.
    pub fn auto_start_error_key(&self) -> Option<String> {
        self.protection.auto_start_error_key.lock().clone()
    }

    /// Applies the persisted desired state at daemon start: start now, wait for the pause
    /// deadline, or stay stopped. A failure is logged and exposed in diagnostics, never raised.
    /// Needs a running Tokio runtime.
    pub fn apply_persisted_protection(&self) {
        let Some(path) = self.protection.path.as_ref() else {
            return;
        };
        let loaded = ProtectionState::load_or_default(path);
        *self.protection.state.lock() = loaded;
        match decide_startup_action(&loaded, now_epoch_ms()) {
            StartupAction::StayStopped => {}
            StartupAction::StartNow => {
                if loaded.paused_until_epoch_ms.is_some() {
                    let mut state = self.protection.state.lock();
                    state.paused_until_epoch_ms = None;
                    self.save_protection_state(&state);
                }
                self.start_after_restart();
            }
            StartupAction::StartAt(deadline) => {
                self.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_ENGINE,
                    format!("Protection stays paused until {deadline} (Unix ms)"),
                );
                self.schedule_resume(deadline);
            }
        }
    }

    fn start_after_restart(&self) {
        match self.start_protection() {
            Ok(()) => self.telemetry.push_log(
                LogLevel::Info,
                COMPONENT_ENGINE,
                "Protection restored automatically".to_string(),
            ),
            Err(err) => {
                self.telemetry.push_log(
                    LogLevel::Error,
                    COMPONENT_ENGINE,
                    format!("Automatic protection start failed: {err}"),
                );
                *self.protection.auto_start_error_key.lock() = Some(err.i18n_key().to_string());
            }
        }
    }

    fn schedule_resume(&self, deadline: u64) {
        if tokio::runtime::Handle::try_current().is_err() {
            self.telemetry.push_log(
                LogLevel::Error,
                COMPONENT_ENGINE,
                "No async runtime: the pause end cannot be scheduled".to_string(),
            );
            return;
        }
        let controller = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                let now = now_epoch_ms();
                if now >= deadline {
                    break;
                }
                let remaining = Duration::from_millis(deadline - now);
                tokio::time::sleep(remaining.min(Duration::from_millis(PAUSE_TIMER_POLL_MS))).await;
            }
            controller.resume_after_pause(deadline);
        });
        if let Some(previous) = self.protection.pause_task.lock().replace(handle) {
            previous.abort();
        }
    }

    /// Ends the pause that expires at `deadline`, unless it was cancelled or replaced.
    fn resume_after_pause(&self, deadline: u64) {
        {
            let mut state = self.protection.state.lock();
            if state.paused_until_epoch_ms != Some(deadline) || !state.protection_enabled {
                return;
            }
            state.paused_until_epoch_ms = None;
            self.save_protection_state(&state);
        }
        self.protection.pause_task.lock().take();
        self.start_after_restart();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProfileConfig, SystemConstants};
    use crate::system::protection_state::{state_path_for_profile, MAX_PAUSE_SECS};
    use uuid::Uuid;

    fn relay_controller(dir: &std::path::Path) -> RouteWardController {
        let mut profile = ProfileConfig::load_embedded_default().expect("default profile");
        profile.interception_mode = InterceptionMode::Relay;
        let constants = SystemConstants::load_embedded().expect("constants");
        RouteWardController::new_with_log_dir(constants, profile, "en", dir.join("logs"))
            .with_protection_state_path(state_path_for_profile(&dir.join("active_profile.json")))
    }

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("routeward_protection_{}", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn pause_rejects_zero_and_over_limit() {
        let dir = temp_dir();
        let controller = relay_controller(&dir);
        for secs in [0, MAX_PAUSE_SECS + 1] {
            let err = controller.pause_protection(secs).expect_err("rejected");
            assert_eq!(err.i18n_key(), ERR_KEY_DAEMON_INVALID_PAUSE);
        }
        assert!(controller.paused_until_epoch_ms().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pause_persists_deadline_and_choice_cancels_it() {
        let dir = temp_dir();
        let controller = relay_controller(&dir);
        let path = state_path_for_profile(&dir.join("active_profile.json"));

        let deadline = controller.pause_protection(600).expect("pause");
        assert_eq!(controller.paused_until_epoch_ms(), Some(deadline));
        assert!(!controller.is_running());
        let stored = ProtectionState::load_or_default(&path);
        assert!(stored.protection_enabled);
        assert_eq!(stored.paused_until_epoch_ms, Some(deadline));

        controller.record_protection_choice(true);
        assert!(controller.paused_until_epoch_ms().is_none());
        let stored = ProtectionState::load_or_default(&path);
        assert!(stored.protection_enabled && stored.paused_until_epoch_ms.is_none());

        controller.record_protection_choice(false);
        assert!(!ProtectionState::load_or_default(&path).protection_enabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn startup_with_disabled_or_missing_state_stays_stopped() {
        let dir = temp_dir();
        let controller = relay_controller(&dir);
        controller.apply_persisted_protection();
        assert!(!controller.is_running());
        assert!(controller.auto_start_error_key().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn startup_with_future_pause_stays_stopped_and_reports_it() {
        let dir = temp_dir();
        let path = state_path_for_profile(&dir.join("active_profile.json"));
        let deadline = now_epoch_ms() + 600_000;
        ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: Some(deadline),
        }
        .save_to_path(&path, false)
        .expect("seed state");
        let controller = relay_controller(&dir);
        controller.apply_persisted_protection();
        assert!(!controller.is_running());
        assert_eq!(controller.paused_until_epoch_ms(), Some(deadline));
        controller.record_protection_choice(false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn startup_failure_is_reported_in_diagnostics_not_raised() {
        let dir = temp_dir();
        let path = state_path_for_profile(&dir.join("active_profile.json"));
        ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: None,
        }
        .save_to_path(&path, false)
        .expect("seed state");
        let controller = relay_controller(&dir);
        // Occupy the relay port so that the automatic start cannot bind it.
        let relay = format!(
            "{}:{}",
            controller.constants.network.local_bind_host,
            controller.constants.network.default_relay_tcp_port
        );
        // If the bind fails, another process already holds the port, which blocks the start too.
        let _blocker = std::net::TcpListener::bind(&relay);
        controller.apply_persisted_protection();
        assert!(!controller.is_running());
        assert!(controller.auto_start_error_key().is_some());
        assert_eq!(
            controller.diagnostics().auto_start_error_key,
            controller.auto_start_error_key()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
