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

//! One desktop app per user session.
//!
//! The first instance owns a named mutex and listens on a named event; a second launch finds the
//! mutex taken, signals the event (so the first instance shows its window) and exits. Both names
//! live in the `Local\` namespace, which is private to the Windows session: two users on the same
//! machine each get their own instance.

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE,
    INFINITE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;

/// Mutex held by the running instance.
pub const SINGLE_INSTANCE_MUTEX_NAME: &str = "Local\\RouteWardDesktopSingleInstance";
/// Event a second launch signals so the running instance shows its window.
pub const SHOW_WINDOW_EVENT_NAME: &str = "Local\\RouteWardDesktopShowWindow";
/// `ASFW_ANY`: lets any process take the foreground (the window of the first instance).
const ASFW_ANY_PROCESS: u32 = u32::MAX;

fn to_wide_null(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(once(0)).collect()
}

/// Result of [`SingleInstance::acquire`].
pub enum Acquisition {
    /// This process is the first one: keep the guard for the whole run.
    First(SingleInstance),
    /// Another instance of this session already runs and was signalled.
    AlreadyRunning,
}

/// Owner of the single-instance mutex and of the "show your window" event.
pub struct SingleInstance {
    mutex: isize,
    event: isize,
}

impl SingleInstance {
    /// Takes the per-session mutex, or signals the instance that holds it.
    pub fn acquire() -> Result<Acquisition, u32> {
        Self::acquire_named(SINGLE_INSTANCE_MUTEX_NAME, SHOW_WINDOW_EVENT_NAME)
    }

    /// Same as [`SingleInstance::acquire`] with explicit object names (tests use unique ones).
    pub fn acquire_named(mutex_name: &str, event_name: &str) -> Result<Acquisition, u32> {
        let mutex_w = to_wide_null(mutex_name);
        let event_w = to_wide_null(event_name);
        // SAFETY: the name buffers are NUL-terminated and outlive the calls; null attributes
        // give the default security descriptor; every handle created here is closed or owned.
        unsafe {
            // The event first: a second launch that wins the race after the mutex exists must
            // find the event to signal.
            let event: HANDLE = CreateEventW(null(), 0, 0, event_w.as_ptr());
            if event.is_null() {
                return Err(GetLastError());
            }
            let mutex: HANDLE = CreateMutexW(null(), 0, mutex_w.as_ptr());
            if mutex.is_null() {
                let err = GetLastError();
                CloseHandle(event);
                return Err(err);
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                CloseHandle(mutex);
                CloseHandle(event);
                if !Self::signal_existing(event_name) {
                    tracing::warn!(
                        "Another RouteWard instance runs but could not be asked to show its window"
                    );
                }
                return Ok(Acquisition::AlreadyRunning);
            }
            Ok(Acquisition::First(Self {
                mutex: mutex as isize,
                event: event as isize,
            }))
        }
    }

    /// Asks the running instance to show its window; false when no instance listens.
    pub fn signal_existing(event_name: &str) -> bool {
        let event_w = to_wide_null(event_name);
        // SAFETY: opens an existing named event with the right to set it, signals it and
        // closes the handle again.
        unsafe {
            // The new process was started by the user, so it may hand the foreground to the
            // window the first instance is about to show.
            AllowSetForegroundWindow(ASFW_ANY_PROCESS);
            let event: HANDLE = OpenEventW(EVENT_MODIFY_STATE, 0, event_w.as_ptr());
            if event.is_null() {
                return false;
            }
            let signalled = SetEvent(event) != 0;
            CloseHandle(event);
            signalled
        }
    }

    /// Waits until a second launch signals this instance; false when `timeout_ms` elapsed.
    pub fn wait_for_signal(&self, timeout_ms: u32) -> bool {
        // SAFETY: `event` is a valid event handle owned by `self` until it is dropped.
        unsafe { WaitForSingleObject(self.event as HANDLE, timeout_ms) == WAIT_OBJECT_0 }
    }

    /// Runs `on_signal` on a background thread each time a second launch signals this instance.
    pub fn spawn_show_listener<F>(self: &std::sync::Arc<Self>, on_signal: F)
    where
        F: Fn() + Send + 'static,
    {
        let owner = std::sync::Arc::clone(self);
        let _ = std::thread::Builder::new()
            .name("routeward-single-instance".to_string())
            .spawn(move || loop {
                if owner.wait_for_signal(INFINITE) {
                    on_signal();
                }
            });
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        // SAFETY: both handles were created by `acquire_named` and are closed exactly once.
        unsafe {
            CloseHandle(self.mutex as HANDLE);
            CloseHandle(self.event as HANDLE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_names(tag: &str) -> (String, String) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = format!("RouteWardTest{tag}{}-{unique}", std::process::id());
        (format!("Local\\{base}Mutex"), format!("Local\\{base}Event"))
    }

    #[test]
    fn a_second_launch_is_refused_and_signals_the_first_one() {
        let (mutex_name, event_name) = unique_names("single");
        let first = match SingleInstance::acquire_named(&mutex_name, &event_name) {
            Ok(Acquisition::First(guard)) => guard,
            _ => panic!("the first acquisition must own the instance"),
        };
        assert!(
            !first.wait_for_signal(0),
            "no signal is pending before a second launch"
        );

        match SingleInstance::acquire_named(&mutex_name, &event_name) {
            Ok(Acquisition::AlreadyRunning) => {}
            _ => panic!("the second acquisition must find the instance already running"),
        }
        assert!(
            first.wait_for_signal(1000),
            "the second launch must signal the first instance"
        );
        assert!(!first.wait_for_signal(0), "the signal is consumed once");
    }

    #[test]
    fn once_the_first_instance_is_gone_a_new_one_can_start() {
        let (mutex_name, event_name) = unique_names("restart");
        let first = SingleInstance::acquire_named(&mutex_name, &event_name);
        assert!(matches!(first, Ok(Acquisition::First(_))));
        drop(first);
        assert!(matches!(
            SingleInstance::acquire_named(&mutex_name, &event_name),
            Ok(Acquisition::First(_))
        ));
    }

    #[test]
    fn signalling_without_a_running_instance_reports_false() {
        let (_, event_name) = unique_names("nobody");
        assert!(!SingleInstance::signal_existing(&event_name));
    }
}
