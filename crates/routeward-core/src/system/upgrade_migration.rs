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
//! major upgrade finds none and leaves protection off. Before the old product is removed, the
//! installer asks the OLD daemon (`routeward ctl status`) as the installing user and, only when it
//! answers "running", records a registry marker under that user's hive. Once the upgrade is
//! committed, the NEW CLI reads the marker back here (as SYSTEM, through `HKEY_USERS\<SID>`),
//! consumes it, and persists the enabled state. A registry marker is used instead of a file because
//! SYSTEM never reads a file from a place a standard user can write.

use crate::interceptor::RouteWardController;
use crate::system::protection_state::ProtectionState;
use crate::system::user_state::{is_user_hive_sid, SID_LOCAL_SYSTEM};
use std::future::Future;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Key, below the user hive root, that holds the marker written by the installer.
pub const UPGRADE_MARKER_SUBKEY: &str = r"Software\RouteWard\Upgrade";

/// Name of the marker value: a `REG_DWORD` set to 1 when the old daemon answered "running".
pub const UPGRADE_MARKER_VALUE: &str = "ProtectionWasRunning";

/// Oldest a marker may be and still be believed, in seconds. A marker that survived a failed or
/// abandoned upgrade must not turn protection on during a later, unrelated one.
pub const UPGRADE_MARKER_MAX_AGE_SECS: u64 = 30 * 60;

/// Registry type code of a `REG_DWORD` value.
const REG_DWORD_TYPE: u32 = 4;
/// Size in bytes of a `REG_DWORD` value.
const REG_DWORD_LEN: usize = 4;
/// Value of the marker that means "protection was running".
const MARKER_RUNNING_VALUE: u32 = 1;
/// Seconds between 1601-01-01 (the `FILETIME` epoch) and 1970-01-01.
const FILETIME_UNIX_EPOCH_OFFSET_SECS: u64 = 11_644_473_600;
/// Number of `FILETIME` ticks (100 ns) in one second.
const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;
/// Nanoseconds in one `FILETIME` tick.
const NANOS_PER_FILETIME_TICK: u32 = 100;

/// True for a SID the migration may address in `HKEY_USERS`: a user SID as accepted by
/// [`is_user_hive_sid`] (`S-1-5-21-...`, `S-1-12-1-...`) or exactly LocalSystem (`S-1-5-18`), the
/// account that runs installs pushed by SCCM or Intune. Anything else (groups, `_Classes` keys,
/// separators, traversal, empty) is refused.
pub fn is_valid_migration_sid(sid: &str) -> bool {
    is_user_hive_sid(sid) || sid == SID_LOCAL_SYSTEM
}

/// What was observed on the marker key and its value; evaluated by [`marker_says_running`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerFacts {
    /// Registry type code of the value.
    pub reg_type: u32,
    /// Raw bytes of the value.
    pub data: Vec<u8>,
    /// Age of the key (time since its last write); `None` when it could not be determined.
    pub age: Option<Duration>,
}

/// True only for a fresh `REG_DWORD` of exactly four bytes equal to 1. Any other type or size
/// (`REG_SZ "1"`, `REG_QWORD`, `REG_BINARY`), any other number, a key older than
/// [`UPGRADE_MARKER_MAX_AGE_SECS`] or of unknown age counts as "not running", so a damaged or
/// planted marker can never turn the protection on.
pub fn marker_says_running(facts: &MarkerFacts) -> bool {
    let Some(age) = facts.age else {
        return false;
    };
    if age > Duration::from_secs(UPGRADE_MARKER_MAX_AGE_SECS) {
        return false;
    }
    if facts.reg_type != REG_DWORD_TYPE || facts.data.len() != REG_DWORD_LEN {
        return false;
    }
    let mut bytes = [0u8; REG_DWORD_LEN];
    bytes.copy_from_slice(&facts.data);
    u32::from_le_bytes(bytes) == MARKER_RUNNING_VALUE
}

/// Age of a key last written at `last_write_ticks` (`FILETIME`, 100 ns since 1601) as of `now`.
/// A write time in the future (small clock adjustment) counts as zero age.
pub fn age_from_filetime(last_write_ticks: u64, now: SystemTime) -> Option<Duration> {
    let since_unix = now.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    let now_ticks = (since_unix.as_secs() + FILETIME_UNIX_EPOCH_OFFSET_SECS)
        .checked_mul(FILETIME_TICKS_PER_SEC)?
        .checked_add(u64::from(
            since_unix.subsec_nanos() / NANOS_PER_FILETIME_TICK,
        ))?;
    let elapsed = now_ticks.saturating_sub(last_write_ticks);
    Some(Duration::new(
        elapsed / FILETIME_TICKS_PER_SEC,
        ((elapsed % FILETIME_TICKS_PER_SEC) as u32) * NANOS_PER_FILETIME_TICK,
    ))
}

/// Reads the marker of the user with this SID, then deletes the marker value (only the value).
/// Returns whether protection was running. Every failure (invalid SID, missing hive, key or value,
/// a link in the path, access error) is logged and counts as "not running".
#[cfg(windows)]
pub fn consume_upgrade_marker(sid: &str) -> bool {
    use windows_sys::Win32::System::Registry::HKEY_USERS;
    if !is_valid_migration_sid(sid) {
        tracing::warn!(sid = %sid, "refusing an invalid SID, protection not carried over");
        return false;
    }
    let subkey = format!(r"{sid}\{UPGRADE_MARKER_SUBKEY}");
    consume_marker_at(HKEY_USERS, &subkey, UPGRADE_MARKER_VALUE, SystemTime::now())
}

/// Off Windows there is no installer capture: nothing is carried over.
#[cfg(not(windows))]
pub fn consume_upgrade_marker(sid: &str) -> bool {
    tracing::info!(sid = %sid, "the upgrade marker only exists on Windows, nothing migrated");
    false
}

/// Same as [`consume_upgrade_marker`] on an explicit hive, key path and value name, with an
/// injectable clock. The key is opened without following links and the value is deleted through
/// that same checked handle.
#[cfg(windows)]
pub(crate) fn consume_marker_at(
    hive: windows_sys::Win32::System::Registry::HKEY,
    subkey: &str,
    value_name: &str,
    now: SystemTime,
) -> bool {
    use crate::system::user_state::win32::{open_key_rejecting_links, read_raw, to_wide};
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FILETIME};
    use windows_sys::Win32::System::Registry::{
        RegDeleteValueW, RegQueryInfoKeyW, KEY_QUERY_VALUE, KEY_SET_VALUE,
    };

    let key = match open_key_rejecting_links(hive, subkey, KEY_QUERY_VALUE | KEY_SET_VALUE) {
        Ok(Some(key)) => key,
        Ok(None) => {
            tracing::info!("no upgrade marker key, protection not carried over");
            return false;
        }
        Err(err) => {
            tracing::warn!(error = %err, "cannot open the upgrade marker key safely");
            return false;
        }
    };
    let value = match read_raw(&key, value_name) {
        Ok(Some(value)) => value,
        Ok(None) => {
            tracing::info!("no upgrade marker value, protection not carried over");
            return false;
        }
        Err(err) => {
            tracing::warn!(error = %err, "cannot read the upgrade marker value");
            return false;
        }
    };
    let mut last_write = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: `key` is a valid open handle with query access and `last_write` is a valid out
    // pointer; every other out parameter is optional and passed as null.
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut last_write,
        )
    };
    let age = if status == ERROR_SUCCESS {
        let ticks =
            (u64::from(last_write.dwHighDateTime) << 32) | u64::from(last_write.dwLowDateTime);
        age_from_filetime(ticks, now)
    } else {
        tracing::warn!(status, "cannot read the upgrade marker age");
        None
    };
    let facts = MarkerFacts {
        reg_type: value.0,
        data: value.1,
        age,
    };
    let running = marker_says_running(&facts);

    // Consume the marker: remove the value only, through the handle that was just checked. The
    // (possibly empty) key is left; the next capture, run as the user, removes it.
    let wide_name = to_wide(value_name);
    // SAFETY: `key` is a valid handle opened with `KEY_SET_VALUE`; the name is NUL-terminated.
    let deleted = unsafe { RegDeleteValueW(key.0, wide_name.as_ptr()) };
    if deleted != ERROR_SUCCESS {
        tracing::warn!(status = deleted, "cannot delete the upgrade marker value");
    }
    tracing::info!(
        running,
        reg_type = facts.reg_type,
        age_secs = ?facts.age.map(|age| age.as_secs()),
        "upgrade marker read"
    );
    running
}

/// What the migration decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// A state file already exists (the previous version persisted it): left untouched.
    StateAlreadyPersisted,
    /// The old daemon was not running, or the marker is missing or unusable.
    NotRunning,
    /// The new daemon accepted the start request and persisted the choice itself.
    PersistedByDaemon,
    /// The new daemon could not be used: the enabled state was written directly.
    WrittenDirectly,
    /// The enabled state could not be written.
    WriteFailed,
}

/// Decides and applies the migration once the marker has been read (`protection_was_running`).
///
/// `start_via_daemon` asks the new daemon to start protection (which persists the choice) and
/// returns whether it succeeded; it is injected so the logic runs without a pipe. The service
/// is never started here, and an existing state file is never overwritten. When the daemon reports
/// success but the state file still does not exist, or the daemon is unusable, the enabled state is
/// written directly (the file is absent, so nothing can be overwritten).
pub async fn migrate_upgrade_state<F, Fut>(
    state_path: &Path,
    protection_was_running: bool,
    start_via_daemon: F,
) -> MigrationOutcome
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = bool>,
{
    if state_path.exists() {
        MigrationOutcome::StateAlreadyPersisted
    } else if !protection_was_running {
        MigrationOutcome::NotRunning
    } else if start_via_daemon().await && state_path.exists() {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::protection_state::PROTECTION_STATE_FILE_NAME;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    const SAMPLE_USER_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const FRESH_AGE: Duration = Duration::from_secs(60);

    fn facts(reg_type: u32, data: &[u8], age: Option<Duration>) -> MarkerFacts {
        MarkerFacts {
            reg_type,
            data: data.to_vec(),
            age,
        }
    }

    #[test]
    fn sid_validation_accepts_user_sids_and_local_system_only() {
        for good in [SAMPLE_USER_SID, "S-1-12-1-111-222-333-444", "S-1-5-18"] {
            assert!(is_valid_migration_sid(good), "{good}");
        }
        for bad in [
            "",
            "S-1-5-32-544",
            "S-1-5-19",
            "S-1-5-21-",
            "S-1-5-18_Classes",
            "S-1-5-21-1-2-3-1001_Classes",
            r"S-1-5-21-1-2-3-1001\Software",
            "S-1-5-21-1-2-3-..",
            r"S-1-5-21-12\..\34",
            "S-1-5-18\\",
            ".DEFAULT",
            "s-1-5-18",
        ] {
            assert!(!is_valid_migration_sid(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_fresh_dword_one_means_running() {
        assert!(marker_says_running(&facts(
            4,
            &1u32.to_le_bytes(),
            Some(FRESH_AGE)
        )));
        assert!(marker_says_running(&facts(
            4,
            &1u32.to_le_bytes(),
            Some(Duration::ZERO)
        )));
    }

    #[test]
    fn every_other_type_size_or_number_means_not_running() {
        let one = 1u32.to_le_bytes();
        // REG_SZ "1" as UTF-16 with its terminator.
        assert!(!marker_says_running(&facts(
            1,
            &[0x31, 0, 0, 0],
            Some(FRESH_AGE)
        )));
        // REG_QWORD 1.
        assert!(!marker_says_running(&facts(
            11,
            &1u64.to_le_bytes(),
            Some(FRESH_AGE)
        )));
        // REG_BINARY of length 4 holding the same bytes as a DWORD 1.
        assert!(!marker_says_running(&facts(3, &one, Some(FRESH_AGE))));
        // DWORD 0 and DWORD 2.
        for other in [0u32, 2] {
            assert!(!marker_says_running(&facts(
                4,
                &other.to_le_bytes(),
                Some(FRESH_AGE)
            )));
        }
        // A DWORD with a wrong length.
        for data in [&[1u8][..], &[1, 0, 0, 0, 0], &[]] {
            assert!(!marker_says_running(&facts(4, data, Some(FRESH_AGE))));
        }
    }

    #[test]
    fn an_old_or_undated_marker_means_not_running() {
        let one = 1u32.to_le_bytes();
        let limit = Duration::from_secs(UPGRADE_MARKER_MAX_AGE_SECS);
        assert!(marker_says_running(&facts(4, &one, Some(limit))));
        assert!(!marker_says_running(&facts(
            4,
            &one,
            Some(limit + Duration::from_secs(1))
        )));
        assert!(!marker_says_running(&facts(4, &one, None)));
    }

    #[test]
    fn filetime_age_is_computed_from_the_1601_epoch() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let now_ticks = (1_700_000_000 + FILETIME_UNIX_EPOCH_OFFSET_SECS) * FILETIME_TICKS_PER_SEC;
        assert_eq!(
            age_from_filetime(now_ticks - 90 * FILETIME_TICKS_PER_SEC, now),
            Some(Duration::from_secs(90))
        );
        assert_eq!(age_from_filetime(now_ticks, now), Some(Duration::ZERO));
        // A write time in the future counts as zero.
        assert_eq!(
            age_from_filetime(now_ticks + 5 * FILETIME_TICKS_PER_SEC, now),
            Some(Duration::ZERO)
        );
    }

    struct Dirs {
        root: PathBuf,
        state: PathBuf,
    }

    fn dirs() -> Dirs {
        let root =
            std::env::temp_dir().join(format!("routeward_upgrade_migration_{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        Dirs {
            state: root.join(PROTECTION_STATE_FILE_NAME),
            root,
        }
    }

    fn enabled() -> ProtectionState {
        ProtectionState {
            protection_enabled: true,
            paused_until_epoch_ms: None,
        }
    }

    #[tokio::test]
    async fn running_with_a_working_daemon_leaves_persistence_to_it() {
        let d = dirs();
        let state = d.state.clone();
        let outcome = migrate_upgrade_state(&d.state, true, move || async move {
            // The daemon persists the state itself when it accepts the start request.
            fs::write(&state, "{}").unwrap();
            true
        })
        .await;
        assert_eq!(outcome, MigrationOutcome::PersistedByDaemon);
        assert_eq!(fs::read_to_string(&d.state).unwrap(), "{}");
        let _ = fs::remove_dir_all(&d.root);
    }

    #[tokio::test]
    async fn daemon_success_without_a_state_file_falls_back_to_writing_it() {
        let d = dirs();
        let outcome = migrate_upgrade_state(&d.state, true, || async { true }).await;
        assert_eq!(outcome, MigrationOutcome::WrittenDirectly);
        assert_eq!(ProtectionState::load_or_default(&d.state), enabled());
        let _ = fs::remove_dir_all(&d.root);
    }

    #[tokio::test]
    async fn unreachable_or_refusing_daemon_falls_back_to_writing_the_enabled_state() {
        let d = dirs();
        let outcome = migrate_upgrade_state(&d.state, true, || async { false }).await;
        assert_eq!(outcome, MigrationOutcome::WrittenDirectly);
        assert_eq!(ProtectionState::load_or_default(&d.state), enabled());
        let _ = fs::remove_dir_all(&d.root);
    }

    #[tokio::test]
    async fn not_running_changes_nothing_and_never_calls_the_daemon() {
        let d = dirs();
        let outcome = migrate_upgrade_state(&d.state, false, || async {
            panic!("the daemon must not be called");
            #[allow(unreachable_code)]
            false
        })
        .await;
        assert_eq!(outcome, MigrationOutcome::NotRunning);
        assert!(!d.state.exists());
        let _ = fs::remove_dir_all(&d.root);
    }

    #[tokio::test]
    async fn existing_state_file_is_never_overwritten() {
        let d = dirs();
        let disabled = ProtectionState::default();
        disabled.save_to_path(&d.state, false).unwrap();
        let outcome = migrate_upgrade_state(&d.state, true, || async {
            panic!("the daemon must not be called");
            #[allow(unreachable_code)]
            false
        })
        .await;
        assert_eq!(outcome, MigrationOutcome::StateAlreadyPersisted);
        assert_eq!(ProtectionState::load_or_default(&d.state), disabled);
        let _ = fs::remove_dir_all(&d.root);
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_marker_never_says_running() {
        assert!(!consume_upgrade_marker(SAMPLE_USER_SID));
    }

    #[cfg(windows)]
    mod registry {
        use super::*;
        use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::Storage::FileSystem::DELETE;
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegQueryValueExW,
            RegSetValueExW, HKEY, HKEY_USERS, KEY_CREATE_LINK, KEY_QUERY_VALUE, KEY_SET_VALUE,
            REG_DWORD, REG_LINK, REG_OPTION_CREATE_LINK, REG_OPTION_NON_VOLATILE,
            REG_OPTION_OPEN_LINK,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        const TEST_KEY_PREFIX: &str = r"Software\RouteWard\Test-";
        const LINK_TARGET_VALUE: &str = "SymbolicLinkValue";
        const TOKEN_BUFFER_BYTES: usize = 512;
        const TOKEN_BUFFER_ALIGN_UNITS: usize = 8;

        fn wide(text: &str) -> Vec<u16> {
            text.encode_utf16().chain(std::iter::once(0)).collect()
        }

        /// SID of the user running the test, as `HKEY_USERS` names the hive.
        fn current_sid() -> String {
            let mut token = std::ptr::null_mut();
            // SAFETY: valid out pointer; the pseudo handle of the process needs no close.
            assert_ne!(
                unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
                0
            );
            let mut buffer = vec![0u64; TOKEN_BUFFER_BYTES / TOKEN_BUFFER_ALIGN_UNITS];
            let mut needed = 0u32;
            // SAFETY: `buffer` is writable for `TOKEN_BUFFER_BYTES` and 8-byte aligned.
            let ok = unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    TOKEN_BUFFER_BYTES as u32,
                    &mut needed,
                )
            };
            assert_ne!(ok, 0);
            // SAFETY: the call filled a TOKEN_USER at the start of the buffer.
            let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
            let mut text: *mut u16 = std::ptr::null_mut();
            // SAFETY: the SID pointer lives inside `buffer`.
            assert_ne!(
                unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) },
                0
            );
            // SAFETY: `text` is a NUL-terminated string allocated by the call above.
            unsafe {
                let mut len = 0;
                while *text.add(len) != 0 {
                    len += 1;
                }
                let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
                LocalFree(text.cast());
                sid
            }
        }

        /// A unique key below the current user's hive, deleted with its subtree on drop.
        struct TestKey {
            sid: String,
            name: String,
        }

        impl TestKey {
            fn new() -> Self {
                Self {
                    sid: current_sid(),
                    name: format!("{TEST_KEY_PREFIX}{}", Uuid::new_v4()),
                }
            }

            /// `<sid>\Software\RouteWard\Test-<uuid>[\child]`, relative to `HKEY_USERS`.
            fn path(&self, child: &str) -> String {
                if child.is_empty() {
                    format!(r"{}\{}", self.sid, self.name)
                } else {
                    format!(r"{}\{}\{child}", self.sid, self.name)
                }
            }
        }

        impl Drop for TestKey {
            fn drop(&mut self) {
                // A link key is only removable through NtDeleteKey.
                delete_link_key(&self.path("Upgrade"));
                let path = wide(&self.path(""));
                // SAFETY: NUL-terminated path under HKEY_USERS; best effort cleanup.
                unsafe { RegDeleteTreeW(HKEY_USERS, path.as_ptr()) };
            }
        }

        fn create_key(path: &str, options: u32) -> HKEY {
            let wide_path = wide(path);
            let mut handle: HKEY = std::ptr::null_mut();
            // SAFETY: NUL-terminated path and valid out pointers.
            let status = unsafe {
                RegCreateKeyExW(
                    HKEY_USERS,
                    wide_path.as_ptr(),
                    0,
                    std::ptr::null(),
                    options,
                    KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_CREATE_LINK,
                    std::ptr::null(),
                    &mut handle,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(status, ERROR_SUCCESS, "cannot create {path}");
            handle
        }

        fn set_raw(key: HKEY, name: &str, reg_type: u32, data: &[u8]) {
            let wide_name = wide(name);
            // SAFETY: valid handle, NUL-terminated name, `data` readable for its length.
            let status = unsafe {
                RegSetValueExW(
                    key,
                    wide_name.as_ptr(),
                    0,
                    reg_type,
                    data.as_ptr(),
                    data.len() as u32,
                )
            };
            assert_eq!(status, ERROR_SUCCESS);
        }

        fn create_marker(path: &str, reg_type: u32, data: &[u8]) {
            let key = create_key(path, REG_OPTION_NON_VOLATILE);
            set_raw(key, UPGRADE_MARKER_VALUE, reg_type, data);
            // SAFETY: handle created above.
            unsafe { RegCloseKey(key) };
        }

        fn open(path: &str, options: u32) -> Option<HKEY> {
            let wide_path = wide(path);
            let mut handle: HKEY = std::ptr::null_mut();
            // SAFETY: NUL-terminated path and valid out pointer.
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_USERS,
                    wide_path.as_ptr(),
                    options,
                    KEY_QUERY_VALUE,
                    &mut handle,
                )
            };
            (status == ERROR_SUCCESS).then_some(handle)
        }

        fn key_exists(path: &str) -> bool {
            open(path, REG_OPTION_OPEN_LINK).is_some_and(|handle| {
                // SAFETY: handle opened above.
                unsafe { RegCloseKey(handle) };
                true
            })
        }

        fn value_exists(path: &str, name: &str) -> bool {
            let Some(handle) = open(path, REG_OPTION_OPEN_LINK) else {
                return false;
            };
            let wide_name = wide(name);
            // SAFETY: valid handle; null data pointers ask for existence only.
            let found = unsafe {
                RegQueryValueExW(
                    handle,
                    wide_name.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } == ERROR_SUCCESS;
            // SAFETY: handle opened above.
            unsafe { RegCloseKey(handle) };
            found
        }

        #[link(name = "ntdll")]
        extern "system" {
            fn NtDeleteKey(key: HKEY) -> i32;
        }

        /// Deletes the link key itself: the Win32 delete calls follow the link to its target.
        fn delete_link_key(path: &str) {
            let wide_path = wide(path);
            let mut handle: HKEY = std::ptr::null_mut();
            // SAFETY: NUL-terminated path and valid out pointer.
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_USERS,
                    wide_path.as_ptr(),
                    REG_OPTION_OPEN_LINK,
                    DELETE,
                    &mut handle,
                )
            };
            if status == ERROR_SUCCESS {
                // SAFETY: handle opened above with DELETE access; the key is gone once closed.
                unsafe {
                    NtDeleteKey(handle);
                    RegCloseKey(handle);
                }
            }
        }

        fn consume(path: &str) -> bool {
            consume_marker_at(HKEY_USERS, path, UPGRADE_MARKER_VALUE, SystemTime::now())
        }

        #[test]
        fn a_fresh_dword_one_is_read_and_only_the_value_is_deleted() {
            let key = TestKey::new();
            let path = key.path("Upgrade");
            create_marker(&path, REG_DWORD, &1u32.to_le_bytes());
            assert!(consume(&path));
            assert!(
                !value_exists(&path, UPGRADE_MARKER_VALUE),
                "value must be gone"
            );
            assert!(key_exists(&path), "the key itself must remain");
            assert!(!consume(&path), "a consumed marker is not read twice");
        }

        #[test]
        fn a_wrong_value_is_not_running_but_is_still_consumed() {
            let key = TestKey::new();
            let path = key.path("Upgrade");
            create_marker(&path, REG_DWORD, &0u32.to_le_bytes());
            assert!(!consume(&path));
            assert!(!value_exists(&path, UPGRADE_MARKER_VALUE));
        }

        #[test]
        fn an_old_key_is_not_believed() {
            let key = TestKey::new();
            let path = key.path("Upgrade");
            create_marker(&path, REG_DWORD, &1u32.to_le_bytes());
            let later = SystemTime::now() + Duration::from_secs(UPGRADE_MARKER_MAX_AGE_SECS + 60);
            assert!(!consume_marker_at(
                HKEY_USERS,
                &path,
                UPGRADE_MARKER_VALUE,
                later
            ));
        }

        #[test]
        fn a_missing_key_or_value_is_not_running() {
            let key = TestKey::new();
            let path = key.path("Upgrade");
            assert!(!consume(&path));
            let handle = create_key(&path, REG_OPTION_NON_VOLATILE);
            // SAFETY: handle created above.
            unsafe { RegCloseKey(handle) };
            assert!(!consume(&path));
        }

        #[test]
        fn a_symbolic_link_key_is_refused_and_nothing_is_deleted() {
            let key = TestKey::new();
            let target_path = key.path("Target");
            create_marker(&target_path, REG_DWORD, &1u32.to_le_bytes());

            // Link key `Upgrade` pointing at the registry key `Target`.
            let link_path = key.path("Upgrade");
            let link = create_key(&link_path, REG_OPTION_CREATE_LINK | REG_OPTION_NON_VOLATILE);
            let target_native: Vec<u8> = format!(r"\Registry\User\{}\{}\Target", key.sid, key.name)
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            set_raw(link, LINK_TARGET_VALUE, REG_LINK, &target_native);
            // SAFETY: handle created above.
            unsafe { RegCloseKey(link) };

            let refusal = crate::system::user_state::win32::open_key_rejecting_links(
                HKEY_USERS,
                &link_path,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
            );
            assert!(refusal.is_err(), "the link must be detected as a link");
            assert!(!consume(&link_path), "a link must never be followed");
            assert!(
                value_exists(&target_path, UPGRADE_MARKER_VALUE),
                "the target value must be untouched"
            );
        }
    }
}
