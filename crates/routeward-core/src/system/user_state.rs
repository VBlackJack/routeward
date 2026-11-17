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

//! Per-user Windows settings that RouteWard changes (system proxy, PAC, autostart) and the logic
//! that gives them back.
//!
//! Before RouteWard first changes the proxy or the PAC URL, the previous values are saved in a
//! small JSON file under the user's `%LOCALAPPDATA%\RouteWard`. A file is used rather than a
//! registry value because the previous settings are a set of optional, typed values: JSON keeps
//! "absent" distinct from "empty" without parsing localized `reg query` text, and the file is
//! local to the user, so `routeward cleanup --user` (no elevation) can find and delete it.
//!
//! Every decision is a pure function over plain values and every effect goes through
//! [`UserSettingsStore`] and [`BackupStore`], so the whole flow is unit-tested without touching
//! the registry of the host.

#[cfg(any(windows, test))]
use crate::error::ERR_KEY_SYSTEM_REGISTRY_WRITE;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_SYSTEM_BACKUP_FAILED};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Registry value holding the per-user system proxy switch (`REG_DWORD`, 1 = enabled).
pub const VALUE_PROXY_ENABLE: &str = "ProxyEnable";
/// Registry value holding the per-user system proxy server string (`REG_SZ`).
pub const VALUE_PROXY_SERVER: &str = "ProxyServer";
/// Registry value holding the per-user PAC URL (`REG_SZ`).
pub const VALUE_AUTO_CONFIG_URL: &str = "AutoConfigURL";
/// Run-key value written by the desktop autostart toggle.
pub const VALUE_AUTOSTART: &str = "RouteWardDesktop";
/// Prefix of the proxy server string RouteWard writes (`socks=<host>:<port>`).
pub const PROXY_SERVER_PREFIX: &str = "socks=";
/// File name of the saved previous settings, inside the per-user RouteWard directory.
pub const BACKUP_FILE_NAME: &str = "system_settings_backup.json";
/// Directory name used under `%LOCALAPPDATA%` and `%ProgramData%`.
pub const DATA_DIR_NAME: &str = "RouteWard";
/// Executable names an autostart entry may legitimately point to.
const ROUTEWARD_EXECUTABLE_NAMES: [&str; 2] = ["routeward-desktop.exe", "routeward.exe"];
/// Extension used to find the end of an unquoted executable path.
const EXE_EXTENSION: &str = ".exe";
/// Token separating the value type from its data in a `reg query` line.
const REG_SZ_TOKEN: &str = "REG_SZ";
const REG_EXPAND_SZ_TOKEN: &str = "REG_EXPAND_SZ";
const REG_DWORD_TOKEN: &str = "REG_DWORD";
/// Number of spaces `reg query` puts between the type token and the data.
const REG_QUERY_DATA_PADDING: usize = 4;

/// Typed registry value, limited to the types the settings above can hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RegValue {
    Dword(u32),
    Sz(String),
    ExpandSz(String),
}

impl RegValue {
    /// String data of a `REG_SZ` or `REG_EXPAND_SZ` value.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Sz(text) | Self::ExpandSz(text) => Some(text),
            Self::Dword(_) => None,
        }
    }
}

/// Registry key a setting lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegLocation {
    /// `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
    InternetSettings,
    /// `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    Run,
}

/// Single registry change decided by a pure planning function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegAction {
    Write(&'static str, RegValue),
    Delete(&'static str),
}

/// Access to the per-user registry values RouteWard may touch.
pub trait UserSettingsStore {
    /// Reads a value; a missing value is `Ok(None)`.
    fn read(&self, location: RegLocation, name: &str) -> RouteWardResult<Option<RegValue>>;
    fn write(&self, location: RegLocation, name: &str, value: &RegValue) -> RouteWardResult<()>;
    /// Deletes a value; a missing value counts as success.
    fn delete(&self, location: RegLocation, name: &str) -> RouteWardResult<()>;
}

/// Previous system proxy settings, saved before RouteWard first enabled its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyBackup {
    pub prev_enable: Option<RegValue>,
    pub prev_server: Option<RegValue>,
    /// The `ProxyServer` string RouteWard wrote; ownership is judged against it.
    pub written_server: String,
}

/// Previous PAC URL, saved before RouteWard first set its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacBackup {
    pub prev_url: Option<RegValue>,
    /// The PAC URL RouteWard wrote; ownership is judged against it.
    pub written_url: String,
}

/// Everything RouteWard saved about the settings it changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsBackup {
    #[serde(default)]
    pub proxy: Option<ProxyBackup>,
    #[serde(default)]
    pub pac: Option<PacBackup>,
}

impl SettingsBackup {
    pub fn is_empty(&self) -> bool {
        self.proxy.is_none() && self.pac.is_none()
    }
}

/// Persistence of the [`SettingsBackup`].
pub trait BackupStore {
    /// Loads the backup; a missing or unreadable file is an empty backup.
    fn load(&self) -> SettingsBackup;
    fn save(&self, backup: &SettingsBackup) -> RouteWardResult<()>;
}

/// [`BackupStore`] kept in a JSON file; an empty backup deletes the file.
pub struct FileBackupStore {
    path: PathBuf,
}

impl FileBackupStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Per-user location of the backup: `%LOCALAPPDATA%\RouteWard\system_settings_backup.json`.
    #[cfg(windows)]
    pub fn for_current_user() -> RouteWardResult<Self> {
        let dir = crate::config::security::resolve_windows_local_app_data_dir()?;
        Ok(Self::new(dir.join(DATA_DIR_NAME).join(BACKUP_FILE_NAME)))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn backup_error(detail: String) -> RouteWardError {
    RouteWardError::SystemError {
        key: ERR_KEY_SYSTEM_BACKUP_FAILED,
        detail,
    }
}

impl BackupStore for FileBackupStore {
    fn load(&self) -> SettingsBackup {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|err| {
                tracing::warn!(path = %self.path.display(), error = %err, "ignoring unreadable settings backup");
                SettingsBackup::default()
            }),
            Err(_) => SettingsBackup::default(),
        }
    }

    fn save(&self, backup: &SettingsBackup) -> RouteWardResult<()> {
        if backup.is_empty() {
            return match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(backup_error(format!(
                    "cannot delete {}: {err}",
                    self.path.display()
                ))),
            };
        }
        let json = serde_json::to_vec_pretty(backup)
            .map_err(|err| backup_error(format!("cannot serialize backup: {err}")))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                backup_error(format!("cannot create {}: {err}", parent.display()))
            })?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json)
            .and_then(|()| std::fs::rename(&tmp, &self.path))
            .map_err(|err| backup_error(format!("cannot write {}: {err}", self.path.display())))
    }
}

/// True when a registry text value equals the value RouteWard wrote (ASCII case-insensitive).
fn is_owned_text(current: Option<&RegValue>, written: &str) -> bool {
    current
        .and_then(RegValue::as_text)
        .is_some_and(|text| text.trim().eq_ignore_ascii_case(written.trim()))
}

fn restore_actions(name: &'static str, previous: &Option<RegValue>) -> RegAction {
    match previous {
        Some(value) => RegAction::Write(name, value.clone()),
        None => RegAction::Delete(name),
    }
}

/// Decides what to save when RouteWard is about to enable its system proxy.
///
/// An existing backup is kept while the current server is still RouteWard's (a second enable must
/// never record RouteWard's own value as "previous"). If the current server is not RouteWard's,
/// the settings are snapshotted again so a change made in the meantime is what gets restored. If
/// the current server is already RouteWard's but no backup survives (older version, lost file),
/// the previous state is taken to be "proxy off, no server".
pub fn plan_proxy_backup(
    existing: Option<&ProxyBackup>,
    current_enable: Option<RegValue>,
    current_server: Option<RegValue>,
    new_server: &str,
) -> ProxyBackup {
    if let Some(prior) = existing {
        if is_owned_text(current_server.as_ref(), &prior.written_server) {
            return ProxyBackup {
                written_server: new_server.to_string(),
                ..prior.clone()
            };
        }
    }
    if is_owned_text(current_server.as_ref(), new_server) {
        return ProxyBackup {
            prev_enable: Some(RegValue::Dword(0)),
            prev_server: None,
            written_server: new_server.to_string(),
        };
    }
    ProxyBackup {
        prev_enable: current_enable,
        prev_server: current_server,
        written_server: new_server.to_string(),
    }
}

/// Decides how to give the proxy settings back. `None` means the current server is no longer
/// RouteWard's, so nothing must be touched.
///
/// The server string is restored whenever it is still RouteWard's. The enable switch is restored
/// only while it is still on: if the user switched the proxy off in Windows settings meanwhile,
/// that choice is kept.
pub fn plan_proxy_restore(
    backup: &ProxyBackup,
    current_enable: Option<&RegValue>,
    current_server: Option<&RegValue>,
) -> Option<Vec<RegAction>> {
    if !is_owned_text(current_server, &backup.written_server) {
        return None;
    }
    let mut actions = vec![restore_actions(VALUE_PROXY_SERVER, &backup.prev_server)];
    if current_enable == Some(&RegValue::Dword(1)) {
        actions.push(restore_actions(VALUE_PROXY_ENABLE, &backup.prev_enable));
    }
    Some(actions)
}

/// Fallback when no backup exists (older version, lost file): switch the proxy off, but only if
/// the current server is the one RouteWard would have written for `socks_endpoint`.
pub fn plan_legacy_proxy_disable(
    current_server: Option<&RegValue>,
    socks_endpoint: &str,
) -> Option<Vec<RegAction>> {
    let written = format!("{PROXY_SERVER_PREFIX}{socks_endpoint}");
    is_owned_text(current_server, &written)
        .then(|| vec![RegAction::Write(VALUE_PROXY_ENABLE, RegValue::Dword(0))])
}

/// Decides what to save when RouteWard is about to set its PAC URL (same rules as the proxy).
pub fn plan_pac_backup(
    existing: Option<&PacBackup>,
    current_url: Option<RegValue>,
    new_url: &str,
) -> PacBackup {
    if let Some(prior) = existing {
        if is_owned_text(current_url.as_ref(), &prior.written_url) {
            return PacBackup {
                written_url: new_url.to_string(),
                ..prior.clone()
            };
        }
    }
    if is_owned_text(current_url.as_ref(), new_url) {
        return PacBackup {
            prev_url: None,
            written_url: new_url.to_string(),
        };
    }
    PacBackup {
        prev_url: current_url,
        written_url: new_url.to_string(),
    }
}

/// Decides how to give the PAC URL back; `None` when the current URL is no longer RouteWard's.
pub fn plan_pac_restore(
    backup: &PacBackup,
    current_url: Option<&RegValue>,
) -> Option<Vec<RegAction>> {
    is_owned_text(current_url, &backup.written_url)
        .then(|| vec![restore_actions(VALUE_AUTO_CONFIG_URL, &backup.prev_url)])
}

/// Fallback when no backup exists: delete the PAC URL only if it is RouteWard's `pac_url`.
pub fn plan_legacy_pac_disable(
    current_url: Option<&RegValue>,
    pac_url: &str,
) -> Option<Vec<RegAction>> {
    is_owned_text(current_url, pac_url).then(|| vec![RegAction::Delete(VALUE_AUTO_CONFIG_URL)])
}

/// True when a Run-key command line starts a RouteWard executable.
///
/// Handles a quoted path (`"C:\Program Files\RouteWard\routeward-desktop.exe" --flag`) and an
/// unquoted one; only the file name is compared, so any install location matches.
pub fn autostart_points_to_routeward(command_line: &str) -> bool {
    let trimmed = command_line.trim();
    let executable = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else {
        let lower = trimmed.to_ascii_lowercase();
        match lower.find(EXE_EXTENSION) {
            Some(idx) => &trimmed[..idx + EXE_EXTENSION.len()],
            None => trimmed,
        }
    };
    let file_name = executable.rsplit(['\\', '/']).next().unwrap_or("");
    ROUTEWARD_EXECUTABLE_NAMES
        .iter()
        .any(|name| file_name.eq_ignore_ascii_case(name))
}

/// Extracts the typed value from `reg query` output, locale-independently: only the type token
/// and the data after it are read.
pub fn parse_reg_query_value(stdout: &str) -> Option<RegValue> {
    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        // REG_EXPAND_SZ must be tested before REG_SZ is searched: neither contains the other, but
        // the order keeps the intent explicit.
        for (token, is_expand) in [(REG_EXPAND_SZ_TOKEN, true), (REG_SZ_TOKEN, false)] {
            if let Some(idx) = find_type_token(line, token) {
                let rest = &line[idx + token.len()..];
                let padding = " ".repeat(REG_QUERY_DATA_PADDING);
                let data = rest
                    .strip_prefix(padding.as_str())
                    .unwrap_or_else(|| rest.trim_start());
                let data = data.to_string();
                return Some(if is_expand {
                    RegValue::ExpandSz(data)
                } else {
                    RegValue::Sz(data)
                });
            }
        }
        if find_type_token(line, REG_DWORD_TOKEN).is_some() {
            return super::parse_reg_dword_value(line).map(RegValue::Dword);
        }
    }
    None
}

/// Finds a type token delimited by whitespace (so a value name or data containing the same
/// letters is not mistaken for it).
fn find_type_token(line: &str, token: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = line[from..].find(token) {
        let idx = from + rel;
        let before_ok = idx > 0 && line[..idx].ends_with(' ');
        let after = &line[idx + token.len()..];
        let after_ok = after.is_empty() || after.starts_with(' ');
        if before_ok && after_ok {
            return Some(idx);
        }
        from = idx + token.len();
    }
    None
}

fn apply_actions<S: UserSettingsStore>(
    settings: &S,
    location: RegLocation,
    actions: &[RegAction],
) -> RouteWardResult<()> {
    for action in actions {
        match action {
            RegAction::Write(name, value) => settings.write(location, name, value)?,
            RegAction::Delete(name) => settings.delete(location, name)?,
        }
    }
    Ok(())
}

/// Saves the previous proxy settings (once), then enables RouteWard's proxy.
///
/// The backup is written first: if it cannot be saved the registry is left untouched, since a
/// change that cannot be undone is worse than no change.
pub fn enable_proxy<S: UserSettingsStore, B: BackupStore>(
    settings: &S,
    backups: &B,
    socks_endpoint: &str,
) -> RouteWardResult<()> {
    let new_server = format!("{PROXY_SERVER_PREFIX}{socks_endpoint}");
    let mut backup = backups.load();
    let planned = plan_proxy_backup(
        backup.proxy.as_ref(),
        settings.read(RegLocation::InternetSettings, VALUE_PROXY_ENABLE)?,
        settings.read(RegLocation::InternetSettings, VALUE_PROXY_SERVER)?,
        &new_server,
    );
    backup.proxy = Some(planned);
    backups.save(&backup)?;
    settings.write(
        RegLocation::InternetSettings,
        VALUE_PROXY_SERVER,
        &RegValue::Sz(new_server),
    )?;
    settings.write(
        RegLocation::InternetSettings,
        VALUE_PROXY_ENABLE,
        &RegValue::Dword(1),
    )
}

/// Gives the proxy settings back. Returns true when something was restored or switched off.
///
/// Values the user changed since RouteWard enabled its proxy are left alone.
pub fn disable_proxy<S: UserSettingsStore, B: BackupStore>(
    settings: &S,
    backups: &B,
    socks_endpoint: &str,
) -> RouteWardResult<bool> {
    let mut backup = backups.load();
    let current_enable = settings.read(RegLocation::InternetSettings, VALUE_PROXY_ENABLE)?;
    let current_server = settings.read(RegLocation::InternetSettings, VALUE_PROXY_SERVER)?;
    let plan = match backup.proxy.take() {
        Some(saved) => plan_proxy_restore(&saved, current_enable.as_ref(), current_server.as_ref()),
        None => plan_legacy_proxy_disable(current_server.as_ref(), socks_endpoint),
    };
    let restored = match plan {
        Some(actions) => {
            apply_actions(settings, RegLocation::InternetSettings, &actions)?;
            true
        }
        None => false,
    };
    backups.save(&backup)?;
    Ok(restored)
}

/// Saves the previous PAC URL (once), then sets RouteWard's.
pub fn enable_pac<S: UserSettingsStore, B: BackupStore>(
    settings: &S,
    backups: &B,
    pac_url: &str,
) -> RouteWardResult<()> {
    let mut backup = backups.load();
    let planned = plan_pac_backup(
        backup.pac.as_ref(),
        settings.read(RegLocation::InternetSettings, VALUE_AUTO_CONFIG_URL)?,
        pac_url,
    );
    backup.pac = Some(planned);
    backups.save(&backup)?;
    settings.write(
        RegLocation::InternetSettings,
        VALUE_AUTO_CONFIG_URL,
        &RegValue::Sz(pac_url.to_string()),
    )
}

/// Gives the PAC URL back. Returns true when something was restored or removed.
pub fn disable_pac<S: UserSettingsStore, B: BackupStore>(
    settings: &S,
    backups: &B,
    pac_url: &str,
) -> RouteWardResult<bool> {
    let mut backup = backups.load();
    let current = settings.read(RegLocation::InternetSettings, VALUE_AUTO_CONFIG_URL)?;
    let plan = match backup.pac.take() {
        Some(saved) => plan_pac_restore(&saved, current.as_ref()),
        None => plan_legacy_pac_disable(current.as_ref(), pac_url),
    };
    let restored = match plan {
        Some(actions) => {
            apply_actions(settings, RegLocation::InternetSettings, &actions)?;
            true
        }
        None => false,
    };
    backups.save(&backup)?;
    Ok(restored)
}

/// What `routeward cleanup --user` and the desktop exit path gave back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserCleanupReport {
    pub proxy_restored: bool,
    pub pac_restored: bool,
    pub autostart_removed: bool,
}

/// Restores the proxy and the PAC URL (see [`disable_proxy`], [`disable_pac`]). Idempotent.
pub fn restore_owned_proxy_settings<S: UserSettingsStore, B: BackupStore>(
    settings: &S,
    backups: &B,
    socks_endpoint: &str,
    pac_url: &str,
) -> RouteWardResult<UserCleanupReport> {
    Ok(UserCleanupReport {
        proxy_restored: disable_proxy(settings, backups, socks_endpoint)?,
        pac_restored: disable_pac(settings, backups, pac_url)?,
        autostart_removed: false,
    })
}

/// Removes the Run value only when it starts a RouteWard executable.
pub fn remove_owned_autostart<S: UserSettingsStore>(settings: &S) -> RouteWardResult<bool> {
    let current = settings.read(RegLocation::Run, VALUE_AUTOSTART)?;
    let owned = current
        .as_ref()
        .and_then(RegValue::as_text)
        .is_some_and(autostart_points_to_routeward);
    if owned {
        settings.delete(RegLocation::Run, VALUE_AUTOSTART)?;
    }
    Ok(owned)
}

/// Everything `routeward cleanup --user` does for the current user. Idempotent.
pub fn cleanup_user_settings<S: UserSettingsStore, B: BackupStore>(
    settings: &S,
    backups: &B,
    socks_endpoint: &str,
    pac_url: &str,
) -> RouteWardResult<UserCleanupReport> {
    let mut report = restore_owned_proxy_settings(settings, backups, socks_endpoint, pac_url)?;
    report.autostart_removed = remove_owned_autostart(settings)?;
    Ok(report)
}

/// [`UserSettingsStore`] backed by `reg.exe` on the current user's hive.
#[cfg(windows)]
pub struct RegExeStore;

#[cfg(windows)]
impl RegExeStore {
    fn key_path(location: RegLocation) -> &'static str {
        match location {
            RegLocation::InternetSettings => super::WIN_INET_REG_PATH,
            RegLocation::Run => super::WIN_RUN_REG_PATH,
        }
    }
}

#[cfg(windows)]
impl UserSettingsStore for RegExeStore {
    fn read(&self, location: RegLocation, name: &str) -> RouteWardResult<Option<RegValue>> {
        let output = std::process::Command::new(super::windows_system_tool_path("reg.exe"))
            .args(["query", Self::key_path(location), "/v", name])
            .output()
            .map_err(|err| RouteWardError::SystemError {
                key: ERR_KEY_SYSTEM_REGISTRY_WRITE,
                detail: format!("cannot run reg query: {err}"),
            })?;
        // `reg query` fails with a localized message when the value does not exist.
        if !output.status.success() {
            return Ok(None);
        }
        Ok(parse_reg_query_value(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }

    fn write(&self, location: RegLocation, name: &str, value: &RegValue) -> RouteWardResult<()> {
        let (reg_type, data) = match value {
            RegValue::Dword(n) => (REG_DWORD_TOKEN, n.to_string()),
            RegValue::Sz(text) => (REG_SZ_TOKEN, text.clone()),
            RegValue::ExpandSz(text) => (REG_EXPAND_SZ_TOKEN, text.clone()),
        };
        super::SystemProxyManager::run_reg_add(&[
            "add",
            Self::key_path(location),
            "/v",
            name,
            "/t",
            reg_type,
            "/d",
            &data,
            "/f",
        ])
    }

    fn delete(&self, location: RegLocation, name: &str) -> RouteWardResult<()> {
        super::SystemProxyManager::run_reg_delete_value(Self::key_path(location), name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const ENDPOINT: &str = "127.0.0.1:10808";
    const SERVER: &str = "socks=127.0.0.1:10808";
    const PAC: &str = "http://127.0.0.1:10811/proxy.pac";
    const CORP_SERVER: &str = "proxy.corp.example:3128";
    const CORP_PAC: &str = "http://wpad.corp.example/wpad.dat";

    #[derive(Default)]
    struct FakeSettings {
        values: RefCell<HashMap<(RegLocation, String), RegValue>>,
        fail_writes: bool,
    }

    impl FakeSettings {
        fn set(&self, name: &str, value: RegValue) {
            self.values
                .borrow_mut()
                .insert((RegLocation::InternetSettings, name.to_string()), value);
        }
        fn get(&self, name: &str) -> Option<RegValue> {
            self.values
                .borrow()
                .get(&(RegLocation::InternetSettings, name.to_string()))
                .cloned()
        }
    }

    impl UserSettingsStore for FakeSettings {
        fn read(&self, location: RegLocation, name: &str) -> RouteWardResult<Option<RegValue>> {
            Ok(self
                .values
                .borrow()
                .get(&(location, name.to_string()))
                .cloned())
        }
        fn write(
            &self,
            location: RegLocation,
            name: &str,
            value: &RegValue,
        ) -> RouteWardResult<()> {
            if self.fail_writes {
                return Err(RouteWardError::SystemError {
                    key: ERR_KEY_SYSTEM_REGISTRY_WRITE,
                    detail: "denied".into(),
                });
            }
            self.values
                .borrow_mut()
                .insert((location, name.to_string()), value.clone());
            Ok(())
        }
        fn delete(&self, location: RegLocation, name: &str) -> RouteWardResult<()> {
            self.values
                .borrow_mut()
                .remove(&(location, name.to_string()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeBackups {
        saved: RefCell<SettingsBackup>,
        fail: bool,
    }

    impl BackupStore for FakeBackups {
        fn load(&self) -> SettingsBackup {
            self.saved.borrow().clone()
        }
        fn save(&self, backup: &SettingsBackup) -> RouteWardResult<()> {
            if self.fail {
                return Err(backup_error("disk full".into()));
            }
            *self.saved.borrow_mut() = backup.clone();
            Ok(())
        }
    }

    fn corporate_proxy(settings: &FakeSettings) {
        settings.set(VALUE_PROXY_ENABLE, RegValue::Dword(1));
        settings.set(VALUE_PROXY_SERVER, RegValue::Sz(CORP_SERVER.into()));
    }

    #[test]
    fn enable_then_disable_restores_the_corporate_proxy_exactly() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        corporate_proxy(&settings);

        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(SERVER.into()))
        );
        assert_eq!(settings.get(VALUE_PROXY_ENABLE), Some(RegValue::Dword(1)));

        assert!(disable_proxy(&settings, &backups, ENDPOINT).unwrap());
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(CORP_SERVER.into()))
        );
        assert_eq!(settings.get(VALUE_PROXY_ENABLE), Some(RegValue::Dword(1)));
        assert!(backups.load().is_empty());
    }

    #[test]
    fn enable_then_disable_on_a_clean_profile_removes_the_server_and_switch() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        assert!(disable_proxy(&settings, &backups, ENDPOINT).unwrap());
        assert_eq!(settings.get(VALUE_PROXY_SERVER), None);
        assert_eq!(settings.get(VALUE_PROXY_ENABLE), None);
    }

    #[test]
    fn second_enable_keeps_the_first_snapshot() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        corporate_proxy(&settings);
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        disable_proxy(&settings, &backups, ENDPOINT).unwrap();
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(CORP_SERVER.into()))
        );
    }

    #[test]
    fn disable_leaves_a_server_the_user_changed_meanwhile() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        corporate_proxy(&settings);
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        settings.set(
            VALUE_PROXY_SERVER,
            RegValue::Sz("other.example:8080".into()),
        );

        assert!(!disable_proxy(&settings, &backups, ENDPOINT).unwrap());
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz("other.example:8080".into()))
        );
        assert_eq!(settings.get(VALUE_PROXY_ENABLE), Some(RegValue::Dword(1)));
        assert!(
            backups.load().proxy.is_none(),
            "a stale backup must be dropped"
        );
    }

    #[test]
    fn disable_keeps_a_proxy_switch_the_user_turned_off() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        corporate_proxy(&settings);
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        settings.set(VALUE_PROXY_ENABLE, RegValue::Dword(0));

        assert!(disable_proxy(&settings, &backups, ENDPOINT).unwrap());
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(CORP_SERVER.into()))
        );
        assert_eq!(settings.get(VALUE_PROXY_ENABLE), Some(RegValue::Dword(0)));
    }

    #[test]
    fn enable_after_the_user_changed_the_proxy_snapshots_the_new_values() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        corporate_proxy(&settings);
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        settings.set(
            VALUE_PROXY_SERVER,
            RegValue::Sz("other.example:8080".into()),
        );
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        disable_proxy(&settings, &backups, ENDPOINT).unwrap();
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz("other.example:8080".into()))
        );
    }

    #[test]
    fn enable_with_a_failing_backup_leaves_the_registry_untouched() {
        let settings = FakeSettings::default();
        let backups = FakeBackups {
            fail: true,
            ..FakeBackups::default()
        };
        corporate_proxy(&settings);
        let err = enable_proxy(&settings, &backups, ENDPOINT).unwrap_err();
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_BACKUP_FAILED);
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(CORP_SERVER.into()))
        );
    }

    #[test]
    fn legacy_disable_without_a_backup_only_switches_off_a_routeward_server() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        settings.set(VALUE_PROXY_ENABLE, RegValue::Dword(1));
        settings.set(VALUE_PROXY_SERVER, RegValue::Sz(SERVER.into()));
        assert!(disable_proxy(&settings, &backups, ENDPOINT).unwrap());
        assert_eq!(settings.get(VALUE_PROXY_ENABLE), Some(RegValue::Dword(0)));

        corporate_proxy(&settings);
        assert!(!disable_proxy(&settings, &backups, ENDPOINT).unwrap());
        assert_eq!(settings.get(VALUE_PROXY_ENABLE), Some(RegValue::Dword(1)));
    }

    #[test]
    fn enable_when_routeward_server_is_already_set_and_no_backup_restores_to_off() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        settings.set(VALUE_PROXY_ENABLE, RegValue::Dword(1));
        settings.set(VALUE_PROXY_SERVER, RegValue::Sz(SERVER.into()));
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        disable_proxy(&settings, &backups, ENDPOINT).unwrap();
        assert_eq!(settings.get(VALUE_PROXY_SERVER), None);
        assert_eq!(settings.get(VALUE_PROXY_ENABLE), Some(RegValue::Dword(0)));
    }

    #[test]
    fn pac_round_trip_restores_the_previous_url_or_removes_it() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        settings.set(VALUE_AUTO_CONFIG_URL, RegValue::Sz(CORP_PAC.into()));
        enable_pac(&settings, &backups, PAC).unwrap();
        assert_eq!(
            settings.get(VALUE_AUTO_CONFIG_URL),
            Some(RegValue::Sz(PAC.into()))
        );
        assert!(disable_pac(&settings, &backups, PAC).unwrap());
        assert_eq!(
            settings.get(VALUE_AUTO_CONFIG_URL),
            Some(RegValue::Sz(CORP_PAC.into()))
        );

        let clean = FakeSettings::default();
        enable_pac(&clean, &backups, PAC).unwrap();
        assert!(disable_pac(&clean, &backups, PAC).unwrap());
        assert_eq!(clean.get(VALUE_AUTO_CONFIG_URL), None);
    }

    #[test]
    fn pac_disable_is_case_insensitive_and_leaves_foreign_urls() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        enable_pac(&settings, &backups, PAC).unwrap();
        settings.set(VALUE_AUTO_CONFIG_URL, RegValue::Sz(CORP_PAC.into()));
        assert!(!disable_pac(&settings, &backups, PAC).unwrap());
        assert_eq!(
            settings.get(VALUE_AUTO_CONFIG_URL),
            Some(RegValue::Sz(CORP_PAC.into()))
        );

        let legacy = FakeSettings::default();
        legacy.set(
            VALUE_AUTO_CONFIG_URL,
            RegValue::Sz("HTTP://127.0.0.1:10811/PROXY.PAC".into()),
        );
        assert!(disable_pac(&legacy, &FakeBackups::default(), PAC).unwrap());
        assert_eq!(legacy.get(VALUE_AUTO_CONFIG_URL), None);
    }

    #[test]
    fn cleanup_user_is_idempotent_and_removes_only_routeward_autostart() {
        let settings = FakeSettings::default();
        let backups = FakeBackups::default();
        corporate_proxy(&settings);
        enable_proxy(&settings, &backups, ENDPOINT).unwrap();
        enable_pac(&settings, &backups, PAC).unwrap();
        settings.values.borrow_mut().insert(
            (RegLocation::Run, VALUE_AUTOSTART.to_string()),
            RegValue::Sz(r#""C:\Program Files\RouteWard\routeward-desktop.exe""#.into()),
        );

        let first = cleanup_user_settings(&settings, &backups, ENDPOINT, PAC).unwrap();
        assert_eq!(
            first,
            UserCleanupReport {
                proxy_restored: true,
                pac_restored: true,
                autostart_removed: true
            }
        );
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(CORP_SERVER.into()))
        );
        assert_eq!(settings.get(VALUE_AUTO_CONFIG_URL), None);
        let second = cleanup_user_settings(&settings, &backups, ENDPOINT, PAC).unwrap();
        assert_eq!(second, UserCleanupReport::default());

        settings.values.borrow_mut().insert(
            (RegLocation::Run, VALUE_AUTOSTART.to_string()),
            RegValue::Sz(r#""C:\Tools\other.exe""#.into()),
        );
        assert!(!remove_owned_autostart(&settings).unwrap());
    }

    #[test]
    fn autostart_matching_handles_quoting_and_foreign_binaries() {
        assert!(autostart_points_to_routeward(
            r#""C:\Program Files\RouteWard\routeward-desktop.exe""#
        ));
        assert!(autostart_points_to_routeward(
            r#""C:\Program Files\RouteWard\routeward-desktop.exe" --minimized"#
        ));
        assert!(autostart_points_to_routeward(
            r"C:\Tools\ROUTEWARD-DESKTOP.EXE /silent"
        ));
        assert!(!autostart_points_to_routeward(r#""C:\Tools\evil.exe""#));
        assert!(!autostart_points_to_routeward(
            r#""C:\Tools\evil.exe" routeward-desktop.exe"#
        ));
        assert!(!autostart_points_to_routeward(""));
    }

    #[test]
    fn backup_file_round_trips_and_an_empty_backup_deletes_the_file() {
        let dir =
            std::env::temp_dir().join(format!("routeward-backup-test-{}", uuid::Uuid::new_v4()));
        let store = FileBackupStore::new(dir.join("nested").join(BACKUP_FILE_NAME));
        assert!(store.load().is_empty());

        let backup = SettingsBackup {
            proxy: Some(ProxyBackup {
                prev_enable: Some(RegValue::Dword(1)),
                prev_server: Some(RegValue::Sz(CORP_SERVER.into())),
                written_server: SERVER.into(),
            }),
            pac: None,
        };
        store.save(&backup).unwrap();
        assert_eq!(store.load(), backup);

        store.save(&SettingsBackup::default()).unwrap();
        assert!(!store.path().exists());
        store.save(&SettingsBackup::default()).unwrap();

        std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        std::fs::write(store.path(), "{ not json").unwrap();
        assert!(store.load().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_reg_query_output_for_every_supported_type() {
        assert_eq!(
            parse_reg_query_value(
                "\r\nHKEY_CURRENT_USER\\X\r\n    ProxyServer    REG_SZ    socks=127.0.0.1:1\r\n"
            ),
            Some(RegValue::Sz("socks=127.0.0.1:1".into()))
        );
        assert_eq!(
            parse_reg_query_value("    ProxyOverride    REG_SZ    "),
            Some(RegValue::Sz(String::new()))
        );
        assert_eq!(
            parse_reg_query_value("    ProxyOverride    REG_EXPAND_SZ    %USERPROFILE%;<local>"),
            Some(RegValue::ExpandSz("%USERPROFILE%;<local>".into()))
        );
        assert_eq!(
            parse_reg_query_value("    ProxyEnable    REG_DWORD    0x1"),
            Some(RegValue::Dword(1))
        );
        assert_eq!(parse_reg_query_value("    X    REG_BINARY    00"), None);
        assert_eq!(parse_reg_query_value(""), None);
    }

    #[test]
    fn write_failures_surface_as_errors() {
        let settings = FakeSettings {
            fail_writes: true,
            ..FakeSettings::default()
        };
        let backups = FakeBackups::default();
        let err = enable_proxy(&settings, &backups, ENDPOINT).unwrap_err();
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_REGISTRY_WRITE);
    }
}
