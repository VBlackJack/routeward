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

use crate::config::ProfileConfig;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_DAEMON_INSECURE_PROFILE};
use std::fs;
use std::path::Path;

#[cfg(windows)]
use crate::error::ERR_KEY_CONFIG_LOAD;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
const SID_LOCAL_SYSTEM: &str = "S-1-5-18";
#[cfg(windows)]
const SID_BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";

/// Protected DACL for the RouteWard directory:
/// - `D:P`: Protected DACL (disables inheritance from `%ProgramData%`)
/// - `(A;OICI;FA;;;SY)`: SYSTEM Full Control (Object + Container Inherit)
/// - `(A;OICI;FA;;;BA)`: Administrators Full Control (Object + Container Inherit)
/// - No access is granted to `Users` (`BU`) or any other principal.
#[cfg(windows)]
pub const WINDOWS_PROTECTED_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Protected DACL for the active_profile.json file:
/// - `D:P`: Protected DACL
/// - `(A;;FA;;;SY)`: SYSTEM Full Control
/// - `(A;;FA;;;BA)`: Administrators Full Control
/// - No access is granted to `Users` (`BU`) or any other principal.
#[cfg(windows)]
pub const WINDOWS_PROTECTED_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

#[cfg(windows)]
const WINDOWS_ADMIN_OWNER_SDDL: &str = "O:BA";

#[cfg(windows)]
const ALLOWED_ACE_TYPE: u8 = 0;

/// Resolves the Windows `ProgramData` directory via `SHGetKnownFolderPath(FOLDERID_ProgramData)`
/// rather than trusting any caller-controlled environment variable.
#[cfg(windows)]
pub fn resolve_windows_program_data_dir() -> RouteWardResult<PathBuf> {
    use windows_sys::Win32::UI::Shell::FOLDERID_ProgramData;
    resolve_windows_known_folder(&FOLDERID_ProgramData, "FOLDERID_ProgramData")
}

/// Resolves the Windows user `LocalAppData` directory via `SHGetKnownFolderPath(FOLDERID_LocalAppData)`.
#[cfg(windows)]
pub fn resolve_windows_local_app_data_dir() -> RouteWardResult<PathBuf> {
    use windows_sys::Win32::UI::Shell::FOLDERID_LocalAppData;
    resolve_windows_known_folder(&FOLDERID_LocalAppData, "FOLDERID_LocalAppData")
}

#[cfg(windows)]
fn resolve_windows_known_folder(
    folder_id: *const windows_sys::core::GUID,
    folder_label: &str,
) -> RouteWardResult<PathBuf> {
    use std::ptr::null_mut;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;

    unsafe {
        let mut raw_path: *mut u16 = null_mut();
        let hr = SHGetKnownFolderPath(folder_id, 0, null_mut(), &mut raw_path);
        if hr != 0 || raw_path.is_null() {
            return Err(RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!("SHGetKnownFolderPath({folder_label}) failed: HRESULT 0x{hr:08x}"),
            });
        }

        let mut len = 0usize;
        while *raw_path.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(raw_path, len);
        let folder = String::from_utf16_lossy(slice);
        CoTaskMemFree(raw_path as *const _);

        Ok(PathBuf::from(folder))
    }
}

/// Checks whether `path` exists as a symlink or (on Windows) NTFS reparse point without following it.
pub fn is_symlink_or_reparse_point(path: &Path) -> RouteWardResult<bool> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!("Failed to inspect {}: {err}", path.display()),
            });
        }
    };

    let is_link = meta.file_type().is_symlink();

    #[cfg(windows)]
    let is_link = is_link || {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    };

    Ok(is_link)
}

#[cfg(windows)]
fn harden_preexisting_dir_via_handle(dir: &Path) -> RouteWardResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
    };

    if is_symlink_or_reparse_point(dir)? {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: format!(
                "Refusing symlink or reparse point directory {}",
                dir.display()
            ),
        });
    }

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct SdGuard(PSECURITY_DESCRIPTOR);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    let wide_path: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let handle = CreateFileW(
            wide_path.as_ptr(),
            READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "CreateFileW({}, OPEN_REPARSE_POINT) failed: {err}",
                    dir.display()
                ),
            });
        }
        let _handle_guard = HandleGuard(handle);

        let mut file_info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if GetFileInformationByHandle(handle, &mut file_info) == 0 {
            let err = std::io::Error::last_os_error();
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "GetFileInformationByHandle({}) failed: {err}",
                    dir.display()
                ),
            });
        }

        if (file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "Refusing non-directory or reparse point at {}",
                    dir.display()
                ),
            });
        }

        let wide_dacl_sddl: Vec<u16> = WINDOWS_PROTECTED_DIR_SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut dacl_sd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_dacl_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut dacl_sd,
            null_mut(),
        ) == 0
            || dacl_sd.is_null()
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: "Failed to build protected directory DACL descriptor".to_string(),
            });
        }
        let _dacl_sd_guard = SdGuard(dacl_sd);

        let mut dacl_present: i32 = 0;
        let mut dacl_defaulted: i32 = 0;
        let mut dacl: *mut ACL = null_mut();
        if GetSecurityDescriptorDacl(dacl_sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
            == 0
            || dacl.is_null()
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: "GetSecurityDescriptorDacl failed".to_string(),
            });
        }

        let wide_owner_sddl: Vec<u16> = WINDOWS_ADMIN_OWNER_SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut owner_sd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_owner_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut owner_sd,
            null_mut(),
        ) == 0
            || owner_sd.is_null()
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: "Failed to build Administrators owner security descriptor".to_string(),
            });
        }
        let _owner_sd_guard = SdGuard(owner_sd);

        let mut owner_sid: PSID = null_mut();
        let mut owner_defaulted: i32 = 0;
        if GetSecurityDescriptorOwner(owner_sd, &mut owner_sid, &mut owner_defaulted) == 0
            || owner_sid.is_null()
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: "GetSecurityDescriptorOwner failed".to_string(),
            });
        }

        let status = SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner_sid,
            null_mut(),
            dacl,
            null_mut(),
        );
        if status != ERROR_SUCCESS {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "SetSecurityInfo on {} failed with Win32 error {status}",
                    dir.display()
                ),
            });
        }
    }

    Ok(())
}

/// Ensures the daemon profile directory exists with strict ownership and permissions, or verifies
/// an existing directory before loading or creating the daemon's active profile.
///
/// On Windows, when elevated and no `active_profile.json` exists yet, a non-symlink pre-existing
/// directory (for instance created by prior unprivileged runs or packaging) is hardened via an
/// open handle with `FILE_FLAG_OPEN_REPARSE_POINT`. Pre-existing profile files with insecure
/// ownership or permissions are always rejected.
pub fn load_or_init_secure_daemon_profile(profile_path: &Path) -> RouteWardResult<ProfileConfig> {
    if is_symlink_or_reparse_point(profile_path)? {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: format!("Refusing symlinked profile path {}", profile_path.display()),
        });
    }

    let profile_exists_initially = profile_path.exists();

    if let Some(parent) = profile_path.parent() {
        if !parent.as_os_str().is_empty() {
            if is_symlink_or_reparse_point(parent)? {
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                    detail: format!("Refusing symlinked profile directory {}", parent.display()),
                });
            }

            if parent.exists() {
                if verify_profile_path_security(parent).is_err() {
                    #[cfg(windows)]
                    if !profile_exists_initially
                        && crate::interceptor::RouteWardController::detect_elevated_privileges()
                    {
                        harden_preexisting_dir_via_handle(parent)?;
                        for sub_name in ["profiles", "logs"] {
                            let sub = parent.join(sub_name);
                            if sub.exists() {
                                harden_preexisting_dir_via_handle(&sub)?;
                            }
                        }
                    }
                }
                verify_profile_path_security(parent)?;
            } else {
                create_secure_profile_dir(parent, true)?;
                verify_profile_path_security(parent)?;
            }
        }
    }

    if profile_exists_initially || profile_path.exists() {
        verify_profile_path_security(profile_path)?;
        ProfileConfig::load_from_path(profile_path)
    } else {
        let default_profile = ProfileConfig::load_embedded_default()?;
        default_profile.save_to_path(profile_path)?;
        apply_secure_profile_file_permissions(profile_path, true)?;
        verify_profile_path_security(profile_path)?;
        Ok(default_profile)
    }
}

/// Creates `dir_path` with a protected DACL restricting access to `SYSTEM` and `Administrators`
/// (Windows) or mode `0700` (Linux) and sets owner to `Administrators` (Windows) or `root` (Linux).
pub fn create_secure_profile_dir(
    dir_path: &Path,
    require_privileged_owner: bool,
) -> RouteWardResult<()> {
    fs::create_dir_all(dir_path).map_err(|err| RouteWardError::DaemonError {
        key: ERR_KEY_DAEMON_INSECURE_PROFILE,
        detail: format!(
            "Failed to create profile directory {}: {err}",
            dir_path.display()
        ),
    })?;

    #[cfg(windows)]
    {
        apply_windows_sddl_dacl(dir_path, WINDOWS_PROTECTED_DIR_SDDL)?;
        if let Err(err) = apply_windows_admin_owner(dir_path) {
            if require_privileged_owner {
                return Err(err);
            }
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        apply_unix_secure_permissions(dir_path, 0o700, require_privileged_owner)
    }
}

/// Applies the protected file DACL restricting access to `SYSTEM` and `Administrators` (Windows)
/// or mode `0600` (Linux) to `file_path`.
pub fn apply_secure_profile_file_permissions(
    file_path: &Path,
    require_privileged_owner: bool,
) -> RouteWardResult<()> {
    #[cfg(windows)]
    {
        apply_windows_sddl_dacl(file_path, WINDOWS_PROTECTED_FILE_SDDL)?;
        if let Err(err) = apply_windows_admin_owner(file_path) {
            if require_privileged_owner {
                return Err(err);
            }
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        apply_unix_secure_permissions(file_path, 0o600, require_privileged_owner)
    }
}

/// Verifies that `path` (directory or profile file) is owned by `SYSTEM`/`Administrators` (Windows)
/// or `root` (Linux) and that no DACL entry / mode bit grants read or write access to any other principal.
pub fn verify_profile_path_security(path: &Path) -> RouteWardResult<()> {
    #[cfg(windows)]
    {
        verify_windows_owner_security(path)?;
        verify_windows_dacl_security(path)
    }

    #[cfg(not(windows))]
    {
        verify_unix_path_security(path)
    }
}

#[cfg(not(windows))]
fn apply_unix_secure_permissions(
    path: &Path,
    mode: u32,
    require_root_owner: bool,
) -> RouteWardResult<()> {
    use std::ffi::CString;
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|err| {
        RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: format!("Failed to set mode {mode:04o} on {}: {err}", path.display()),
        }
    })?;

    if require_root_owner {
        let path_str = path.to_str().ok_or_else(|| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: "Invalid UTF-8 in profile path".to_string(),
        })?;
        let c_path = CString::new(path_str).map_err(|err| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: err.to_string(),
        })?;
        // SAFETY: `c_path` is a valid NUL-terminated filesystem path.
        let rc = unsafe { libc::chown(c_path.as_ptr(), 0, 0) };
        if rc != 0 {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "Failed to chown {} to root: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ),
            });
        }
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn verify_unix_path_security(path: &Path) -> RouteWardResult<()> {
    use std::os::unix::fs::MetadataExt;

    let meta = fs::symlink_metadata(path).map_err(|err| RouteWardError::DaemonError {
        key: ERR_KEY_DAEMON_INSECURE_PROFILE,
        detail: format!("Failed to stat {}: {err}", path.display()),
    })?;

    if meta.file_type().is_symlink() {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: format!("Refusing symlinked profile path {}", path.display()),
        });
    }

    if meta.uid() != 0 {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: format!(
                "Insecure owner uid={} on {} (expected root uid=0)",
                meta.uid(),
                path.display()
            ),
        });
    }

    let mode = meta.mode();
    if (mode & 0o077) != 0 {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: format!(
                "Insecure permissions {:04o} on {} (group or others have read/write/execute access)",
                mode & 0o777,
                path.display()
            ),
        });
    }

    Ok(())
}

#[cfg(windows)]
pub fn apply_windows_sddl_dacl(path: &Path, sddl: &str) -> RouteWardResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        ) == 0
            || sd.is_null()
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        let mut dacl_present: i32 = 0;
        let mut dacl: *mut ACL = null_mut();
        let mut dacl_defaulted: i32 = 0;
        if GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted) == 0
            || dacl_present == 0
            || dacl.is_null()
        {
            let _ = LocalFree(sd);
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: "GetSecurityDescriptorDacl failed".to_string(),
            });
        }

        let status = SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        );
        let _ = LocalFree(sd);

        if status != ERROR_SUCCESS {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "SetNamedSecurityInfoW(DACL) on {} failed with Win32 error {status}",
                    path.display()
                ),
            });
        }
    }

    Ok(())
}

#[cfg(windows)]
pub fn apply_windows_admin_owner(path: &Path) -> RouteWardResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let wide_sddl: Vec<u16> = WINDOWS_ADMIN_OWNER_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        ) == 0
            || sd.is_null()
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: "Failed to build Administrators owner security descriptor".to_string(),
            });
        }

        let mut owner_sid: PSID = null_mut();
        let mut owner_defaulted: i32 = 0;
        if GetSecurityDescriptorOwner(sd, &mut owner_sid, &mut owner_defaulted) == 0
            || owner_sid.is_null()
        {
            let _ = LocalFree(sd);
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: "GetSecurityDescriptorOwner failed".to_string(),
            });
        }

        let status = SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            owner_sid,
            null_mut(),
            null_mut(),
            null_mut(),
        );
        let _ = LocalFree(sd);

        if status != ERROR_SUCCESS {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "SetNamedSecurityInfoW(OWNER=Administrators) on {} failed with Win32 error {status}",
                    path.display()
                ),
            });
        }
    }

    Ok(())
}

#[cfg(windows)]
pub fn verify_windows_owner_security(path: &Path) -> RouteWardResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut owner_sid: PSID = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let status = GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner_sid,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        if status != ERROR_SUCCESS || sd.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "GetNamedSecurityInfoW(OWNER) on {} failed with Win32 error {status}",
                    path.display()
                ),
            });
        }

        let owner_str = sid_to_string(owner_sid);
        let _ = LocalFree(sd);

        let owner_sid_str = owner_str.ok_or_else(|| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: format!("Could not convert owner SID on {}", path.display()),
        })?;

        if owner_sid_str != SID_LOCAL_SYSTEM && owner_sid_str != SID_BUILTIN_ADMINISTRATORS {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "Insecure owner SID {} on {} (expected SYSTEM {} or Administrators {})",
                    owner_sid_str,
                    path.display(),
                    SID_LOCAL_SYSTEM,
                    SID_BUILTIN_ADMINISTRATORS
                ),
            });
        }
    }

    Ok(())
}

/// Verifies that the DACL on `path` is protected (`SE_DACL_PROTECTED`) and that NO entry grants
/// read, write, or any other access right to any principal other than `SYSTEM` or `Administrators`.
#[cfg(windows)]
pub fn verify_windows_dacl_security(path: &Path) -> RouteWardResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    };

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let status = GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        );
        if status != ERROR_SUCCESS || sd.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "GetNamedSecurityInfoW(DACL) on {} failed with Win32 error {status}",
                    path.display()
                ),
            });
        }

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0 {
            let _ = LocalFree(sd);
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!("GetSecurityDescriptorControl failed on {}", path.display()),
            });
        }

        if (control & SE_DACL_PRESENT) == 0 || dacl.is_null() {
            let _ = LocalFree(sd);
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!("Missing DACL on {}", path.display()),
            });
        }

        if (control & SE_DACL_PROTECTED) == 0 {
            let _ = LocalFree(sd);
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                detail: format!(
                    "DACL on {} is not protected (inherits from parent)",
                    path.display()
                ),
            });
        }

        let ace_count = (*dacl).AceCount as u32;
        for idx in 0..ace_count {
            let mut ace_ptr: *mut std::ffi::c_void = null_mut();
            if GetAce(dacl, idx, &mut ace_ptr) == 0 || ace_ptr.is_null() {
                let _ = LocalFree(sd);
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                    detail: format!("GetAce({idx}) failed on {}", path.display()),
                });
            }

            let header = &*(ace_ptr as *const ACE_HEADER);
            if header.AceType == ALLOWED_ACE_TYPE {
                let allowed = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                let mask = allowed.Mask;
                if mask != 0 {
                    let sid_ptr = &allowed.SidStart as *const u32 as PSID;
                    let trustee = sid_to_string(sid_ptr).unwrap_or_else(|| "unknown".to_string());
                    if trustee != SID_LOCAL_SYSTEM && trustee != SID_BUILTIN_ADMINISTRATORS {
                        let _ = LocalFree(sd);
                        return Err(RouteWardError::DaemonError {
                            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                            detail: format!(
                                "Insecure DACL entry on {}: principal {} has access mask 0x{:08x} (only SYSTEM and Administrators are allowed)",
                                path.display(),
                                trustee,
                                mask
                            ),
                        });
                    }
                }
            }
        }

        let _ = LocalFree(sd);
    }

    Ok(())
}

#[cfg(windows)]
pub(crate) unsafe fn sid_to_string(sid: windows_sys::Win32::Security::PSID) -> Option<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    if sid.is_null() {
        return None;
    }
    let mut wide_ptr: *mut u16 = null_mut();
    if ConvertSidToStringSidW(sid, &mut wide_ptr) == 0 || wide_ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *wide_ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(wide_ptr, len);
    let out = String::from_utf16_lossy(slice);
    let _ = LocalFree(wide_ptr as *mut _);
    Some(out)
}
