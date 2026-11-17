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
//! Registry values are read and written through the Win32 registry API in UTF-16, never by
//! parsing `reg.exe` output, so non-ASCII values (a proxy host in an IDN, a PAC URL with accents)
//! survive a save and a restore unchanged.
//!
//! Every decision is a pure function over plain values and every effect goes through
//! [`UserSettingsStore`] and [`BackupStore`], so the whole flow is unit-tested without touching
//! the registry of the host.

#[cfg(any(windows, test))]
use crate::error::ERR_KEY_SYSTEM_REGISTRY_WRITE;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_SYSTEM_BACKUP_FAILED};
use serde::{Deserialize, Serialize};
use std::io::Write;
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
/// Largest backup file read; the real one is a few hundred bytes. The cap keeps a planted huge
/// file in an untrusted profile from exhausting memory.
const MAX_BACKUP_FILE_BYTES: u64 = 1024 * 1024;
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
    /// Loads the backup; a missing file is an empty backup. A file that cannot be read or parsed
    /// is an error, so a change that could not be undone is never made on top of it.
    fn load(&self) -> RouteWardResult<SettingsBackup>;
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

impl FileBackupStore {
    /// Moves an unparsable backup aside as `<name>.bad` (kept for inspection, replacing an older
    /// one) so the next load starts from an empty backup instead of failing forever.
    fn quarantine(&self) -> String {
        let bad = self.path.with_extension("json.bad");
        match std::fs::rename(&self.path, &bad) {
            Ok(()) => format!("moved to {}", bad.display()),
            Err(err) => format!("could not be moved to {}: {err}", bad.display()),
        }
    }
}

impl BackupStore for FileBackupStore {
    fn load(&self) -> RouteWardResult<SettingsBackup> {
        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SettingsBackup::default())
            }
            Err(err) => {
                return Err(backup_error(format!(
                    "cannot inspect {}: {err}",
                    self.path.display()
                )))
            }
        };
        // The file may sit in a profile the caller does not trust (cleanup of other users).
        if super::purge::is_link_like(&meta) {
            return Err(backup_error(format!(
                "refusing to read {}: it is a link",
                self.path.display()
            )));
        }
        if meta.len() > MAX_BACKUP_FILE_BYTES {
            return Err(backup_error(format!(
                "{} is larger than {MAX_BACKUP_FILE_BYTES} bytes",
                self.path.display()
            )));
        }
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SettingsBackup::default())
            }
            Err(err) => {
                return Err(backup_error(format!(
                    "cannot read {}: {err}",
                    self.path.display()
                )))
            }
        };
        serde_json::from_slice(&bytes).map_err(|err| {
            let outcome = self.quarantine();
            tracing::warn!(path = %self.path.display(), error = %err, "unreadable settings backup set aside");
            backup_error(format!(
                "{} is not a valid backup ({err}); it was {outcome}",
                self.path.display()
            ))
        })
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
        // The data is flushed to disk before the rename makes it the backup, so a crash cannot
        // leave an empty or truncated file under the final name.
        let write_synced = || -> std::io::Result<()> {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(&json)?;
            file.sync_all()
        };
        write_synced()
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
    let mut backup = backups.load()?;
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
    let mut backup = backups.load()?;
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
    let mut backup = backups.load()?;
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
    let mut backup = backups.load()?;
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

/// Registry value types as stored by Windows (`REG_SZ`, `REG_EXPAND_SZ`, `REG_DWORD`).
const REG_TYPE_SZ: u32 = 1;
const REG_TYPE_EXPAND_SZ: u32 = 2;
const REG_TYPE_DWORD: u32 = 4;
/// Size in bytes of a `REG_DWORD` payload.
const DWORD_BYTES: usize = 4;

/// Decodes raw registry data of the given type; `None` for a type the settings never use or a
/// malformed payload. Text is UTF-16 little endian cut at the first NUL.
pub fn decode_reg_data(reg_type: u32, data: &[u8]) -> Option<RegValue> {
    match reg_type {
        REG_TYPE_DWORD => {
            let bytes: [u8; DWORD_BYTES] = data.get(..DWORD_BYTES)?.try_into().ok()?;
            Some(RegValue::Dword(u32::from_le_bytes(bytes)))
        }
        REG_TYPE_SZ | REG_TYPE_EXPAND_SZ => {
            let units: Vec<u16> = data
                .chunks(2)
                .filter(|pair| pair.len() == 2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|unit| *unit != 0)
                .collect();
            let text = String::from_utf16_lossy(&units);
            Some(if reg_type == REG_TYPE_EXPAND_SZ {
                RegValue::ExpandSz(text)
            } else {
                RegValue::Sz(text)
            })
        }
        _ => None,
    }
}

/// Encodes a value as the registry type and the raw bytes to store (text gets its NUL
/// terminator).
pub fn encode_reg_data(value: &RegValue) -> (u32, Vec<u8>) {
    let text_bytes = |text: &str| -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    match value {
        RegValue::Dword(number) => (REG_TYPE_DWORD, number.to_le_bytes().to_vec()),
        RegValue::Sz(text) => (REG_TYPE_SZ, text_bytes(text)),
        RegValue::ExpandSz(text) => (REG_TYPE_EXPAND_SZ, text_bytes(text)),
    }
}

/// Prefix of the SIDs of local, domain and Microsoft-account users (the well-known service
/// accounts such as `S-1-5-18` are not users).
const USER_SID_PREFIX: &str = "S-1-5-21-";
/// Suffix of the `HKEY_USERS` key that holds a user's file-type classes, not the user's hive.
const CLASSES_KEY_SUFFIX: &str = "_Classes";
/// Location of a user's local application data below the profile directory.
const PROFILE_LOCAL_APP_DATA_RELATIVE: [&str; 2] = ["AppData", "Local"];

/// True for the `HKEY_USERS` key name of a real user's hive: `S-1-5-21-...`, digits and dashes
/// only, and not the `_Classes` companion key.
pub fn is_user_hive_sid(key_name: &str) -> bool {
    key_name.strip_prefix(USER_SID_PREFIX).is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit() || c == '-')
    }) && !key_name.ends_with(CLASSES_KEY_SUFFIX)
}

/// Where a user's saved settings live, given the profile directory (`ProfileImagePath`).
pub fn backup_path_in_profile(profile_dir: &Path) -> PathBuf {
    let mut path = profile_dir.to_path_buf();
    path.extend(PROFILE_LOCAL_APP_DATA_RELATIVE);
    path.join(DATA_DIR_NAME).join(BACKUP_FILE_NAME)
}

/// What `routeward cleanup --all-users` did.
#[derive(Debug, Default)]
pub struct AllUsersCleanupReport {
    /// Users whose loaded hive was processed.
    pub users_processed: usize,
    /// Of those, the users for whom at least one value was restored or removed.
    pub users_changed: usize,
    /// Loaded hives skipped because the user has no known profile directory.
    pub users_skipped: usize,
    /// Users whose cleanup failed, with the failure; the others were still processed.
    pub failures: Vec<(String, RouteWardError)>,
}

/// Runs [`cleanup_user_settings`] for every loaded user hive in `hive_names` (the key names
/// under `HKEY_USERS`; anything that is not a user SID is ignored). `open_user` gives the
/// registry store and backup store of one SID, or `None` when they cannot be located.
///
/// A failure for one user never stops the others.
pub fn cleanup_loaded_users<S, B>(
    hive_names: &[String],
    mut open_user: impl FnMut(&str) -> RouteWardResult<Option<(S, B)>>,
    socks_endpoint: &str,
    pac_url: &str,
) -> AllUsersCleanupReport
where
    S: UserSettingsStore,
    B: BackupStore,
{
    let mut report = AllUsersCleanupReport::default();
    for sid in hive_names.iter().filter(|name| is_user_hive_sid(name)) {
        let outcome = open_user(sid).and_then(|stores| match stores {
            None => Ok(None),
            Some((settings, backups)) => {
                cleanup_user_settings(&settings, &backups, socks_endpoint, pac_url).map(Some)
            }
        });
        match outcome {
            Ok(None) => report.users_skipped += 1,
            Ok(Some(done)) => {
                report.users_processed += 1;
                if done.proxy_restored || done.pac_restored || done.autostart_removed {
                    report.users_changed += 1;
                }
            }
            Err(err) => report.failures.push((sid.clone(), err)),
        }
    }
    report
}

/// Registry hive a [`Win32RegistryStore`] works in.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryRoot {
    /// `HKEY_CURRENT_USER` of the calling process.
    CurrentUser,
    /// The loaded hive of another user, `HKEY_USERS\<SID>`.
    LoadedUser(String),
}

/// [`UserSettingsStore`] on the Win32 registry API: values are exchanged as raw UTF-16 data.
#[cfg(windows)]
pub struct Win32RegistryStore {
    root: RegistryRoot,
}

#[cfg(windows)]
mod win32 {
    use super::*;
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumKeyExW, RegOpenKeyExW,
        RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS,
        KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE,
    };

    const SUBKEY_INTERNET_SETTINGS: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const SUBKEY_RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const SUBKEY_PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    const VALUE_PROFILE_IMAGE_PATH: &str = "ProfileImagePath";
    /// Capacity (UTF-16 units) for a key name; SID key names are far shorter.
    const KEY_NAME_CAPACITY: usize = 256;
    /// Attempts to read a value that grows between the size query and the read.
    const READ_ATTEMPTS: usize = 4;
    /// Capacity (UTF-16 units) for an expanded profile path.
    const EXPANDED_PATH_CAPACITY: usize = 4096;

    fn registry_error(detail: String) -> RouteWardError {
        RouteWardError::SystemError {
            key: ERR_KEY_SYSTEM_REGISTRY_WRITE,
            detail,
        }
    }

    fn to_wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Closes the key on drop.
    struct OpenKey(HKEY);

    impl Drop for OpenKey {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by this module and is closed exactly once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    /// Opens `hive\subkey`; `Ok(None)` when it does not exist.
    fn open_key(hive: HKEY, subkey: &str, access: u32) -> RouteWardResult<Option<OpenKey>> {
        let wide = to_wide(subkey);
        let mut handle: HKEY = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and `handle` is a valid out pointer.
        let status = unsafe { RegOpenKeyExW(hive, wide.as_ptr(), 0, access, &mut handle) };
        match status {
            ERROR_SUCCESS => Ok(Some(OpenKey(handle))),
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
            other => Err(registry_error(format!(
                "cannot open registry key {subkey}: error {other}"
            ))),
        }
    }

    fn read_raw(key: &OpenKey, name: &str) -> RouteWardResult<Option<(u32, Vec<u8>)>> {
        let wide_name = to_wide(name);
        for _ in 0..READ_ATTEMPTS {
            let mut reg_type = 0u32;
            let mut size = 0u32;
            // SAFETY: a null data pointer asks only for the type and the size.
            let status = unsafe {
                RegQueryValueExW(
                    key.0,
                    wide_name.as_ptr(),
                    std::ptr::null(),
                    &mut reg_type,
                    std::ptr::null_mut(),
                    &mut size,
                )
            };
            match status {
                ERROR_SUCCESS => {}
                ERROR_FILE_NOT_FOUND => return Ok(None),
                other => {
                    return Err(registry_error(format!(
                        "cannot query registry value {name}: error {other}"
                    )))
                }
            }
            let mut buffer = vec![0u8; size as usize];
            let mut read = size;
            // SAFETY: `buffer` holds `read` writable bytes.
            let status = unsafe {
                RegQueryValueExW(
                    key.0,
                    wide_name.as_ptr(),
                    std::ptr::null(),
                    &mut reg_type,
                    buffer.as_mut_ptr(),
                    &mut read,
                )
            };
            match status {
                ERROR_SUCCESS => {
                    buffer.truncate(read as usize);
                    return Ok(Some((reg_type, buffer)));
                }
                // The value grew between the two calls: query the size again.
                ERROR_MORE_DATA => continue,
                ERROR_FILE_NOT_FOUND => return Ok(None),
                other => {
                    return Err(registry_error(format!(
                        "cannot read registry value {name}: error {other}"
                    )))
                }
            }
        }
        Err(registry_error(format!(
            "registry value {name} kept changing while it was read"
        )))
    }

    impl Win32RegistryStore {
        pub fn current_user() -> Self {
            Self {
                root: RegistryRoot::CurrentUser,
            }
        }

        /// Store on the loaded hive of the user with this SID (`HKEY_USERS\<SID>`).
        pub fn loaded_user(sid: &str) -> Self {
            Self {
                root: RegistryRoot::LoadedUser(sid.to_string()),
            }
        }

        fn hive_and_subkey(&self, location: RegLocation) -> (HKEY, String) {
            let relative = match location {
                RegLocation::InternetSettings => SUBKEY_INTERNET_SETTINGS,
                RegLocation::Run => SUBKEY_RUN,
            };
            match &self.root {
                RegistryRoot::CurrentUser => (HKEY_CURRENT_USER, relative.to_string()),
                RegistryRoot::LoadedUser(sid) => (HKEY_USERS, format!(r"{sid}\{relative}")),
            }
        }
    }

    impl UserSettingsStore for Win32RegistryStore {
        fn read(&self, location: RegLocation, name: &str) -> RouteWardResult<Option<RegValue>> {
            let (hive, subkey) = self.hive_and_subkey(location);
            let Some(key) = open_key(hive, &subkey, KEY_QUERY_VALUE)? else {
                return Ok(None);
            };
            Ok(read_raw(&key, name)?.and_then(|(reg_type, data)| decode_reg_data(reg_type, &data)))
        }

        fn write(
            &self,
            location: RegLocation,
            name: &str,
            value: &RegValue,
        ) -> RouteWardResult<()> {
            let (hive, subkey) = self.hive_and_subkey(location);
            let wide_subkey = to_wide(&subkey);
            let mut handle: HKEY = std::ptr::null_mut();
            // SAFETY: `wide_subkey` is NUL-terminated; the optional pointers are null.
            let status = unsafe {
                RegCreateKeyExW(
                    hive,
                    wide_subkey.as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE,
                    std::ptr::null(),
                    &mut handle,
                    std::ptr::null_mut(),
                )
            };
            if status != ERROR_SUCCESS {
                return Err(registry_error(format!(
                    "cannot open registry key {subkey} for writing: error {status}"
                )));
            }
            let key = OpenKey(handle);
            let (reg_type, data) = encode_reg_data(value);
            let wide_name = to_wide(name);
            // SAFETY: `data` is a valid buffer of `data.len()` bytes.
            let status = unsafe {
                RegSetValueExW(
                    key.0,
                    wide_name.as_ptr(),
                    0,
                    reg_type,
                    data.as_ptr(),
                    data.len() as u32,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(registry_error(format!(
                    "cannot write registry value {name}: error {status}"
                )));
            }
            Ok(())
        }

        fn delete(&self, location: RegLocation, name: &str) -> RouteWardResult<()> {
            let (hive, subkey) = self.hive_and_subkey(location);
            let Some(key) = open_key(hive, &subkey, KEY_SET_VALUE)? else {
                return Ok(());
            };
            let wide_name = to_wide(name);
            // SAFETY: `wide_name` is NUL-terminated.
            let status = unsafe { RegDeleteValueW(key.0, wide_name.as_ptr()) };
            match status {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                other => Err(registry_error(format!(
                    "cannot delete registry value {name}: error {other}"
                ))),
            }
        }
    }

    /// Key names under `HKEY_USERS`, i.e. the hives currently loaded.
    pub(super) fn loaded_hive_names() -> RouteWardResult<Vec<String>> {
        let Some(users) = open_key(HKEY_USERS, "", KEY_ENUMERATE_SUB_KEYS)? else {
            return Ok(Vec::new());
        };
        let mut names = Vec::new();
        for index in 0u32.. {
            let mut buffer = [0u16; KEY_NAME_CAPACITY];
            let mut length = buffer.len() as u32;
            // SAFETY: `buffer` has `length` writable UTF-16 units; the optional pointers are null.
            let status = unsafe {
                RegEnumKeyExW(
                    users.0,
                    index,
                    buffer.as_mut_ptr(),
                    &mut length,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            match status {
                ERROR_SUCCESS => {
                    names.push(String::from_utf16_lossy(&buffer[..length as usize]));
                }
                ERROR_NO_MORE_ITEMS => break,
                // A name longer than the buffer cannot be a SID: skip it.
                ERROR_MORE_DATA => {}
                other => {
                    return Err(registry_error(format!(
                        "cannot list loaded user hives: error {other}"
                    )))
                }
            }
        }
        Ok(names)
    }

    /// Profile directory of the user with this SID, from the ProfileList of the machine.
    pub(super) fn profile_dir(sid: &str) -> RouteWardResult<Option<PathBuf>> {
        let subkey = format!(r"{SUBKEY_PROFILE_LIST}\{sid}");
        let Some(key) = open_key(HKEY_LOCAL_MACHINE, &subkey, KEY_QUERY_VALUE)? else {
            return Ok(None);
        };
        let Some((reg_type, data)) = read_raw(&key, VALUE_PROFILE_IMAGE_PATH)? else {
            return Ok(None);
        };
        let text = match decode_reg_data(reg_type, &data) {
            Some(RegValue::Sz(text)) => text,
            Some(RegValue::ExpandSz(text)) => expand_environment(&text)?,
            _ => return Ok(None),
        };
        let path = PathBuf::from(text);
        Ok(path.is_absolute().then_some(path))
    }

    fn expand_environment(text: &str) -> RouteWardResult<String> {
        let wide = to_wide(text);
        let mut buffer = vec![0u16; EXPANDED_PATH_CAPACITY];
        // SAFETY: `wide` is NUL-terminated and `buffer` holds `buffer.len()` writable units.
        let needed = unsafe {
            ExpandEnvironmentStringsW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
        } as usize;
        if needed == 0 || needed > buffer.len() {
            return Err(registry_error(format!("cannot expand the path {text}")));
        }
        // `needed` counts the terminating NUL.
        Ok(String::from_utf16_lossy(&buffer[..needed - 1]))
    }
}

/// Runs [`cleanup_loaded_users`] on this machine: every user hive currently loaded under
/// `HKEY_USERS`, with each user's backup found through the ProfileList. Hives of users who are not
/// logged on are not loaded here, so those users are not covered.
#[cfg(windows)]
pub fn cleanup_all_loaded_users(
    socks_endpoint: &str,
    pac_url: &str,
) -> RouteWardResult<AllUsersCleanupReport> {
    let hive_names = win32::loaded_hive_names()?;
    Ok(cleanup_loaded_users(
        &hive_names,
        |sid| {
            Ok(win32::profile_dir(sid)?.map(|dir| {
                (
                    Win32RegistryStore::loaded_user(sid),
                    FileBackupStore::new(backup_path_in_profile(&dir)),
                )
            }))
        },
        socks_endpoint,
        pac_url,
    ))
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
        fail_load: bool,
    }

    impl BackupStore for FakeBackups {
        fn load(&self) -> RouteWardResult<SettingsBackup> {
            if self.fail_load {
                return Err(backup_error("unreadable".into()));
            }
            Ok(self.saved.borrow().clone())
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
        assert!(backups.load().unwrap().is_empty());
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
            backups.load().unwrap().proxy.is_none(),
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
        assert!(store.load().unwrap().is_empty());

        let backup = SettingsBackup {
            proxy: Some(ProxyBackup {
                prev_enable: Some(RegValue::Dword(1)),
                prev_server: Some(RegValue::Sz(CORP_SERVER.into())),
                written_server: SERVER.into(),
            }),
            pac: None,
        };
        store.save(&backup).unwrap();
        assert_eq!(store.load().unwrap(), backup);

        store.save(&SettingsBackup::default()).unwrap();
        assert!(!store.path().exists());
        store.save(&SettingsBackup::default()).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn scratch_store(tag: &str) -> (PathBuf, FileBackupStore) {
        let dir =
            std::env::temp_dir().join(format!("routeward-backup-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = FileBackupStore::new(dir.join(BACKUP_FILE_NAME));
        (dir, store)
    }

    #[test]
    fn an_unparsable_backup_is_set_aside_and_fails_the_enable_without_touching_the_registry() {
        let (dir, store) = scratch_store("corrupt");
        std::fs::write(store.path(), "{ not json").unwrap();
        let settings = FakeSettings::default();
        corporate_proxy(&settings);

        let err = enable_proxy(&settings, &store, ENDPOINT).unwrap_err();
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_BACKUP_FAILED);
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(CORP_SERVER.into())),
            "the registry must not change"
        );
        assert!(!store.path().exists(), "the bad file must be moved away");
        let quarantined = store.path().with_extension("json.bad");
        assert_eq!(std::fs::read_to_string(&quarantined).unwrap(), "{ not json");

        // The next attempt starts from an empty backup and succeeds.
        enable_proxy(&settings, &store, ENDPOINT).unwrap();
        assert!(quarantined.exists(), "the .bad file is kept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_backup_that_cannot_be_read_fails_instead_of_counting_as_empty() {
        let (dir, store) = scratch_store("unreadable");
        // A directory under the file name: not NotFound, but not readable as a file either.
        std::fs::create_dir_all(store.path()).unwrap();
        let err = store.load().unwrap_err();
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_BACKUP_FAILED);

        let settings = FakeSettings::default();
        let err = enable_proxy(&settings, &store, ENDPOINT).unwrap_err();
        assert_eq!(err.i18n_key(), ERR_KEY_SYSTEM_BACKUP_FAILED);
        assert_eq!(settings.get(VALUE_PROXY_SERVER), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failing_load_stops_every_flow_before_any_registry_change() {
        let settings = FakeSettings::default();
        corporate_proxy(&settings);
        let backups = FakeBackups {
            fail_load: true,
            ..FakeBackups::default()
        };
        assert!(enable_proxy(&settings, &backups, ENDPOINT).is_err());
        assert!(enable_pac(&settings, &backups, PAC).is_err());
        assert!(disable_proxy(&settings, &backups, ENDPOINT).is_err());
        assert!(disable_pac(&settings, &backups, PAC).is_err());
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(CORP_SERVER.into()))
        );
        assert_eq!(settings.get(VALUE_AUTO_CONFIG_URL), None);
    }

    #[test]
    fn non_ascii_values_survive_the_registry_encoding_the_store_and_the_backup_file() {
        const IDN_SERVER: &str = "proxy.b\u{fc}cher.example:3128";
        const ACCENTED_PAC: &str = "http://wpad.caf\u{e9}.example/wpad.dat";
        for value in [
            RegValue::Sz(IDN_SERVER.into()),
            RegValue::ExpandSz("%USERPROFILE%\\\u{65e5}\u{672c}\u{8a9e}".into()),
            RegValue::Dword(0xDEAD_BEEF),
        ] {
            let (reg_type, bytes) = encode_reg_data(&value);
            assert_eq!(decode_reg_data(reg_type, &bytes), Some(value));
        }
        assert_eq!(
            decode_reg_data(3, &[0, 1]),
            None,
            "REG_BINARY is not supported"
        );
        assert_eq!(decode_reg_data(REG_TYPE_DWORD, &[1, 2]), None);
        // Text stops at the first NUL, whatever follows it.
        let (reg_type, mut bytes) = encode_reg_data(&RegValue::Sz("ab".into()));
        bytes.extend_from_slice(&[b'z', 0]);
        assert_eq!(
            decode_reg_data(reg_type, &bytes),
            Some(RegValue::Sz("ab".into()))
        );

        // Through the store abstraction and a file backup: enable, then restore, byte for byte.
        let (dir, store) = scratch_store("unicode");
        let settings = FakeSettings::default();
        settings.set(VALUE_PROXY_ENABLE, RegValue::Dword(1));
        settings.set(VALUE_PROXY_SERVER, RegValue::Sz(IDN_SERVER.into()));
        settings.set(VALUE_AUTO_CONFIG_URL, RegValue::Sz(ACCENTED_PAC.into()));
        enable_proxy(&settings, &store, ENDPOINT).unwrap();
        enable_pac(&settings, &store, PAC).unwrap();
        cleanup_user_settings(&settings, &store, ENDPOINT, PAC).unwrap();
        assert_eq!(
            settings.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(IDN_SERVER.into()))
        );
        assert_eq!(
            settings.get(VALUE_AUTO_CONFIG_URL),
            Some(RegValue::Sz(ACCENTED_PAC.into()))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_real_user_hives_are_cleaned_for_all_users() {
        assert!(is_user_hive_sid(
            "S-1-5-21-1111111111-2222222222-3333333333-1001"
        ));
        assert!(!is_user_hive_sid(
            "S-1-5-21-1111111111-2222222222-3333333333-1001_Classes"
        ));
        assert!(!is_user_hive_sid(".DEFAULT"));
        assert!(!is_user_hive_sid("S-1-5-18"));
        assert!(!is_user_hive_sid("S-1-5-19"));
        assert!(!is_user_hive_sid("S-1-5-21-"));
        assert!(!is_user_hive_sid("S-1-5-21-12\\..\\34"));
        assert_eq!(
            backup_path_in_profile(Path::new(r"C:\Users\alice")),
            Path::new(r"C:\Users\alice")
                .join("AppData")
                .join("Local")
                .join(DATA_DIR_NAME)
                .join(BACKUP_FILE_NAME)
        );
    }

    struct SharedSettings(std::rc::Rc<FakeSettings>);
    struct SharedBackups(std::rc::Rc<FakeBackups>);

    impl UserSettingsStore for SharedSettings {
        fn read(&self, location: RegLocation, name: &str) -> RouteWardResult<Option<RegValue>> {
            self.0.read(location, name)
        }
        fn write(
            &self,
            location: RegLocation,
            name: &str,
            value: &RegValue,
        ) -> RouteWardResult<()> {
            self.0.write(location, name, value)
        }
        fn delete(&self, location: RegLocation, name: &str) -> RouteWardResult<()> {
            self.0.delete(location, name)
        }
    }

    impl BackupStore for SharedBackups {
        fn load(&self) -> RouteWardResult<SettingsBackup> {
            self.0.load()
        }
        fn save(&self, backup: &SettingsBackup) -> RouteWardResult<()> {
            self.0.save(backup)
        }
    }

    type UserFixture = (std::rc::Rc<FakeSettings>, std::rc::Rc<FakeBackups>);

    fn user_with_routeward_proxy(fail_load: bool) -> UserFixture {
        let settings = std::rc::Rc::new(FakeSettings::default());
        corporate_proxy(&settings);
        let backups = std::rc::Rc::new(FakeBackups::default());
        enable_proxy(&*settings, &*backups, ENDPOINT).unwrap();
        // Failure is armed after the setup, through interior mutability of the shared fake.
        let backups = std::rc::Rc::new(FakeBackups {
            saved: RefCell::new(backups.load().unwrap()),
            fail_load,
            ..FakeBackups::default()
        });
        (settings, backups)
    }

    #[test]
    fn cleanup_all_users_restores_each_loaded_user_and_isolates_failures() {
        let alice = "S-1-5-21-1-2-3-1001".to_string();
        let bob = "S-1-5-21-1-2-3-1002".to_string();
        let carol = "S-1-5-21-1-2-3-1003".to_string();
        let ghost = "S-1-5-21-1-2-3-1004".to_string();
        let users: std::collections::HashMap<String, UserFixture> = [
            (alice.clone(), user_with_routeward_proxy(false)),
            (bob.clone(), user_with_routeward_proxy(true)),
            (carol.clone(), user_with_routeward_proxy(false)),
        ]
        .into_iter()
        .collect();
        // Carol changed her proxy after RouteWard: it must be left alone.
        users[&carol].0.set(
            VALUE_PROXY_SERVER,
            RegValue::Sz("other.example:8080".into()),
        );

        let hives = vec![
            ".DEFAULT".to_string(),
            "S-1-5-18".to_string(),
            alice.clone(),
            format!("{alice}_Classes"),
            bob.clone(),
            carol.clone(),
            ghost,
        ];
        let mut opened = Vec::new();
        let report = cleanup_loaded_users(
            &hives,
            |sid| {
                opened.push(sid.to_string());
                Ok(users.get(sid).map(|(settings, backups)| {
                    (
                        SharedSettings(std::rc::Rc::clone(settings)),
                        SharedBackups(std::rc::Rc::clone(backups)),
                    )
                }))
            },
            ENDPOINT,
            PAC,
        );

        assert_eq!(
            opened,
            vec![
                alice.clone(),
                bob.clone(),
                carol.clone(),
                "S-1-5-21-1-2-3-1004".to_string()
            ]
        );
        assert_eq!(report.users_processed, 2, "alice and carol");
        assert_eq!(
            report.users_changed, 1,
            "only alice had something to restore"
        );
        assert_eq!(report.users_skipped, 1, "the user without a profile");
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].0, bob);
        assert_eq!(
            report.failures[0].1.i18n_key(),
            ERR_KEY_SYSTEM_BACKUP_FAILED
        );

        assert_eq!(
            users[&alice].0.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(CORP_SERVER.into()))
        );
        assert_eq!(
            users[&bob].0.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz(SERVER.into())),
            "a user whose backup is unreadable is left as is"
        );
        assert_eq!(
            users[&carol].0.get(VALUE_PROXY_SERVER),
            Some(RegValue::Sz("other.example:8080".into()))
        );
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
