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

use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_DAEMON_INSECURE_PROFILE, ERR_KEY_DAEMON_IPC_ERROR,
};
use crate::ipc::transport::validate_and_canonicalize_allowed_sid;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

pub const WINDOWS_SERVICE_NAME: &str = "RouteWard";
pub const WINDOWS_SERVICE_DISPLAY_NAME: &str = "RouteWard Transparent Proxy Service";
pub const WINDOWS_SERVICE_DESCRIPTION: &str =
    "Privileged dual-stack transparent proxy, Fake-IP DNS interception, and WinDivert daemon for RouteWard.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsServiceStatus {
    pub service_name: String,
    pub display_name: String,
    pub installed: bool,
    pub state: String,
    pub pid: Option<u32>,
    pub binary_path: Option<String>,
}

/// SIDs allowed to hold write-class rights on the directory of the service binary:
/// SYSTEM, BUILTIN\Administrators, TrustedInstaller and CREATOR OWNER.
#[cfg(any(windows, test))]
const TRUSTED_WRITER_SIDS: [&str; 4] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    "S-1-3-0",
];

// Access mask bits (identical meaning for files and directories).
/// FILE_WRITE_DATA, which is FILE_ADD_FILE on a directory.
#[cfg(any(windows, test))]
const ACCESS_FILE_WRITE_DATA: u32 = 0x0000_0002;
/// FILE_APPEND_DATA, which is FILE_ADD_SUBDIRECTORY on a directory.
#[cfg(any(windows, test))]
const ACCESS_FILE_APPEND_DATA: u32 = 0x0000_0004;
/// FILE_DELETE_CHILD: allows deleting or renaming entries of a directory.
#[cfg(any(windows, test))]
const ACCESS_FILE_DELETE_CHILD: u32 = 0x0000_0040;
#[cfg(any(windows, test))]
const ACCESS_WRITE_DAC: u32 = 0x0004_0000;
#[cfg(any(windows, test))]
const ACCESS_WRITE_OWNER: u32 = 0x0008_0000;
#[cfg(any(windows, test))]
const ACCESS_GENERIC_ALL: u32 = 0x1000_0000;
#[cfg(any(windows, test))]
const ACCESS_GENERIC_WRITE: u32 = 0x4000_0000;
#[cfg(any(windows, test))]
const WRITE_CLASS_ACCESS_MASK: u32 = ACCESS_FILE_WRITE_DATA
    | ACCESS_FILE_APPEND_DATA
    | ACCESS_FILE_DELETE_CHILD
    | ACCESS_WRITE_DAC
    | ACCESS_WRITE_OWNER
    | ACCESS_GENERIC_ALL
    | ACCESS_GENERIC_WRITE;

/// Returns true when `mask` grants any right that lets a principal modify, add or replace files
/// in a directory or take over its security descriptor.
#[cfg(any(windows, test))]
fn access_mask_grants_write(mask: u32) -> bool {
    mask & WRITE_CLASS_ACCESS_MASK != 0
}

/// Returns true for the principals that may legitimately write to the service binary directory.
#[cfg(any(windows, test))]
fn is_trusted_writer_sid(sid: &str) -> bool {
    TRUSTED_WRITER_SIDS
        .iter()
        .any(|trusted| trusted.eq_ignore_ascii_case(sid.trim()))
}

/// Builds a quoted command line suitable for Windows SCM `lpBinaryPathName` (mitigating CWE-428)
/// and validates every `--allow-sid` principal against injection or overly broad SIDs.
pub fn build_quoted_service_command_line(
    exe_path: &str,
    allowed_sids: &[String],
) -> RouteWardResult<String> {
    let trimmed = exe_path.trim();
    if trimmed.is_empty() || trimmed.contains('"') || trimmed.chars().any(|c| c.is_control()) {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: format!("Invalid service executable path '{exe_path}'"),
        });
    }

    let mut cmd = format!("\"{trimmed}\" service run");
    for raw_sid in allowed_sids {
        let canon = validate_and_canonicalize_allowed_sid(raw_sid)?;
        cmd.push_str(&format!(" --allow-sid {canon}"));
    }
    Ok(cmd)
}

pub type ServiceMainRunner =
    Box<dyn FnOnce(String, Vec<String>, watch::Receiver<bool>) -> RouteWardResult<()> + Send>;

#[cfg(windows)]
mod win32_impl {
    use super::*;
    use parking_lot::Mutex;
    use std::ffi::c_void;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        LocalFree, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INSUFFICIENT_BUFFER,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SUCCESS, NO_ERROR,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
        CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        QueryServiceStatusEx, RegisterServiceCtrlHandlerExW, SetServiceStatus,
        StartServiceCtrlDispatcherW, StartServiceW, QUERY_SERVICE_CONFIGW, SC_HANDLE,
        SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_SHUTDOWN,
        SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE,
        SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STATUS_PROCESS, SERVICE_STOP,
        SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };

    const SCM_START_WAIT_TIMEOUT_SECS: u64 = 15;
    const SCM_STOP_WAIT_TIMEOUT_SECS: u64 = 15;
    const SCM_WAIT_HINT_MS: u32 = 15_000;
    /// ACE type of an `ACCESS_ALLOWED_ACE`.
    const ACE_TYPE_ACCESS_ALLOWED: u8 = 0;
    /// ACE flag: the entry only applies to children, not to the object it is set on.
    const ACE_FLAG_INHERIT_ONLY: u8 = 0x08;

    struct DispatcherPayload {
        locale: String,
        allowed_sids: Vec<String>,
        runner: ServiceMainRunner,
    }

    static DISPATCH_PAYLOAD: Mutex<Option<DispatcherPayload>> = Mutex::new(None);
    static ACTIVE_SHUTDOWN_SIGNAL: Mutex<Option<watch::Sender<bool>>> = Mutex::new(None);
    static ACTIVE_STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);
    static CURRENT_STATE_RAW: AtomicUsize = AtomicUsize::new(SERVICE_STOPPED as usize);

    fn to_wide_null(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    fn map_service_state_label(state: SERVICE_STATUS_CURRENT_STATE) -> &'static str {
        match state {
            SERVICE_STOPPED => "stopped",
            SERVICE_START_PENDING => "start_pending",
            SERVICE_STOP_PENDING => "stop_pending",
            SERVICE_RUNNING => "running",
            SERVICE_PAUSE_PENDING => "pause_pending",
            SERVICE_PAUSED => "paused",
            _ => "unknown",
        }
    }

    struct ScHandleGuard(SC_HANDLE);
    impl Drop for ScHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
            }
        }
    }

    fn report_scm_status(
        status_handle: SERVICE_STATUS_HANDLE,
        state: SERVICE_STATUS_CURRENT_STATE,
        win32_exit_code: u32,
        check_point: u32,
        wait_hint_ms: u32,
    ) {
        if status_handle.is_null() {
            return;
        }
        CURRENT_STATE_RAW.store(state as usize, Ordering::SeqCst);
        let controls_accepted = if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: controls_accepted,
            dwWin32ExitCode: win32_exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: check_point,
            dwWaitHint: wait_hint_ms,
        };
        unsafe {
            let _ = SetServiceStatus(status_handle, &status);
        }
    }

    unsafe extern "system" fn service_ctrl_handler(
        dw_control: u32,
        _dw_event_type: u32,
        _lp_event_data: *mut c_void,
        _lp_context: *mut c_void,
    ) -> u32 {
        let raw_handle = ACTIVE_STATUS_HANDLE.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
        match dw_control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                report_scm_status(
                    raw_handle,
                    SERVICE_STOP_PENDING,
                    NO_ERROR,
                    1,
                    SCM_WAIT_HINT_MS,
                );
                if let Some(tx) = ACTIVE_SHUTDOWN_SIGNAL.lock().as_ref() {
                    let _ = tx.send(true);
                }
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => {
                let current_state =
                    CURRENT_STATE_RAW.load(Ordering::SeqCst) as SERVICE_STATUS_CURRENT_STATE;
                report_scm_status(raw_handle, current_state, NO_ERROR, 0, 0);
                NO_ERROR
            }
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let svc_name_wide = to_wide_null(WINDOWS_SERVICE_NAME);
        let status_handle = RegisterServiceCtrlHandlerExW(
            svc_name_wide.as_ptr(),
            Some(service_ctrl_handler),
            null_mut(),
        );
        if status_handle.is_null() {
            return;
        }
        ACTIVE_STATUS_HANDLE.store(status_handle as usize, Ordering::SeqCst);
        report_scm_status(
            status_handle,
            SERVICE_START_PENDING,
            NO_ERROR,
            1,
            SCM_WAIT_HINT_MS,
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *ACTIVE_SHUTDOWN_SIGNAL.lock() = Some(shutdown_tx);

        let payload = DISPATCH_PAYLOAD.lock().take();
        let exit_code = if let Some(p) = payload {
            report_scm_status(status_handle, SERVICE_RUNNING, NO_ERROR, 0, 0);
            match (p.runner)(p.locale, p.allowed_sids, shutdown_rx) {
                Ok(()) => NO_ERROR,
                Err(_) => 1,
            }
        } else {
            1
        };

        *ACTIVE_SHUTDOWN_SIGNAL.lock() = None;
        report_scm_status(status_handle, SERVICE_STOPPED, exit_code, 0, 0);
        ACTIVE_STATUS_HANDLE.store(0, Ordering::SeqCst);
    }

    pub fn run_dispatcher(
        locale: String,
        allowed_sids: Vec<String>,
        runner: ServiceMainRunner,
    ) -> RouteWardResult<()> {
        *DISPATCH_PAYLOAD.lock() = Some(DispatcherPayload {
            locale,
            allowed_sids,
            runner,
        });

        let mut svc_name_wide = to_wide_null(WINDOWS_SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: svc_name_wide.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];

        let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if ok == 0 {
            *DISPATCH_PAYLOAD.lock() = None;
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "StartServiceCtrlDispatcherW failed (launch via Windows SCM or use `routeward daemon`): {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        Ok(())
    }

    fn query_service_binary_path(svc_handle: SC_HANDLE) -> Option<String> {
        unsafe {
            let mut needed: u32 = 0;
            let _ = QueryServiceConfigW(svc_handle, null_mut(), 0, &mut needed);
            if needed == 0
                && std::io::Error::last_os_error().raw_os_error()
                    != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            {
                return None;
            }
            let mut buf =
                vec![0u8; needed.max(std::mem::size_of::<QUERY_SERVICE_CONFIGW>() as u32) as usize];
            if QueryServiceConfigW(
                svc_handle,
                buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
                buf.len() as u32,
                &mut needed,
            ) == 0
            {
                return None;
            }
            let cfg = &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
            if cfg.lpBinaryPathName.is_null() {
                return None;
            }
            let mut len = 0usize;
            while *cfg.lpBinaryPathName.add(len) != 0 {
                len += 1;
            }
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(
                cfg.lpBinaryPathName,
                len,
            )))
        }
    }

    fn query_handle_status(svc_handle: SC_HANDLE) -> RouteWardResult<WindowsServiceStatus> {
        let mut ssp: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        let mut bytes_needed: u32 = 0;
        let ok = unsafe {
            QueryServiceStatusEx(
                svc_handle,
                SC_STATUS_PROCESS_INFO,
                &mut ssp as *mut SERVICE_STATUS_PROCESS as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            )
        };
        if ok == 0 {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "QueryServiceStatusEx failed: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        Ok(WindowsServiceStatus {
            service_name: WINDOWS_SERVICE_NAME.to_string(),
            display_name: WINDOWS_SERVICE_DISPLAY_NAME.to_string(),
            installed: true,
            state: map_service_state_label(ssp.dwCurrentState).to_string(),
            pid: if ssp.dwProcessId > 0 {
                Some(ssp.dwProcessId)
            } else {
                None
            },
            binary_path: query_service_binary_path(svc_handle),
        })
    }

    unsafe fn sid_to_string(sid: PSID) -> Option<String> {
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
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(wide_ptr, len));
        let _ = LocalFree(wide_ptr as *mut c_void);
        Some(out)
    }

    /// Returns the first allow entry of `path` that grants write-class rights to a principal
    /// outside the trusted set, as `(sid, access_mask)`.
    fn find_untrusted_writer(path: &Path) -> RouteWardResult<Option<(String, u32)>> {
        use std::os::windows::ffi::OsStrExt;

        let insecure = |detail: String| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail,
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
                return Err(insecure(format!(
                    "Cannot read the access control list of {} (Win32 error {status})",
                    path.display()
                )));
            }
            if dacl.is_null() {
                // A NULL DACL grants full access to everyone.
                let _ = LocalFree(sd);
                return Ok(Some(("S-1-1-0".to_string(), u32::MAX)));
            }

            let ace_count = (*dacl).AceCount as u32;
            let mut found: Option<(String, u32)> = None;
            for idx in 0..ace_count {
                let mut ace_ptr: *mut c_void = null_mut();
                if GetAce(dacl, idx, &mut ace_ptr) == 0 || ace_ptr.is_null() {
                    let _ = LocalFree(sd);
                    return Err(insecure(format!(
                        "GetAce({idx}) failed on {}",
                        path.display()
                    )));
                }
                let header = &*(ace_ptr as *const ACE_HEADER);
                if header.AceType != ACE_TYPE_ACCESS_ALLOWED
                    || header.AceFlags & ACE_FLAG_INHERIT_ONLY != 0
                {
                    continue;
                }
                let allowed = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                if !access_mask_grants_write(allowed.Mask) {
                    continue;
                }
                let sid_ptr = &allowed.SidStart as *const u32 as PSID;
                let trustee = sid_to_string(sid_ptr).unwrap_or_else(|| "unknown".to_string());
                if !is_trusted_writer_sid(&trustee) {
                    found = Some((trustee, allowed.Mask));
                    break;
                }
            }
            let _ = LocalFree(sd);
            Ok(found)
        }
    }

    /// Refuses a service binary that a non-administrator could replace: neither its directory
    /// nor the file itself may grant write-class rights to a principal other than SYSTEM,
    /// Administrators, TrustedInstaller and CREATOR OWNER (the service runs as LocalSystem).
    pub(super) fn verify_service_binary_location(exe: &Path) -> RouteWardResult<()> {
        let dir = exe.parent().ok_or_else(|| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_INSECURE_PROFILE,
            detail: format!(
                "Service executable {} has no parent directory",
                exe.display()
            ),
        })?;
        for target in [dir, exe] {
            if let Some((sid, mask)) = find_untrusted_writer(target)? {
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_INSECURE_PROFILE,
                    detail: format!(
                        "Refusing to register {} as a LocalSystem service: {} grants write access (mask 0x{mask:08x}) to {sid}. Install RouteWard under %ProgramFiles% with packaging/windows/install-service.ps1.",
                        exe.display(),
                        target.display()
                    ),
                });
            }
        }
        Ok(())
    }

    pub fn install(
        exe_path: Option<&str>,
        allowed_sids: &[String],
        auto_start: bool,
    ) -> RouteWardResult<WindowsServiceStatus> {
        let resolved_exe = match exe_path {
            Some(p) => p.to_string(),
            None => std::env::current_exe()
                .map_err(|e| RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!("Cannot resolve current executable path: {e}"),
                })?
                .to_string_lossy()
                .trim_start_matches(r"\\?\")
                .to_string(),
        };
        let bin_cmd = build_quoted_service_command_line(&resolved_exe, allowed_sids)?;
        verify_service_binary_location(Path::new(resolved_exe.trim()))?;
        let bin_wide = to_wide_null(&bin_cmd);
        let name_wide = to_wide_null(WINDOWS_SERVICE_NAME);
        let display_wide = to_wide_null(WINDOWS_SERVICE_DISPLAY_NAME);
        let mut desc_wide = to_wide_null(WINDOWS_SERVICE_DESCRIPTION);
        let start_type = if auto_start {
            SERVICE_AUTO_START
        } else {
            SERVICE_DEMAND_START
        };

        let scm = ScHandleGuard(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) });
        if scm.0.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "OpenSCManagerW failed (Administrator required): {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        let existing = unsafe { OpenServiceW(scm.0, name_wide.as_ptr(), SERVICE_ALL_ACCESS) };
        let svc = if !existing.is_null() {
            let guard = ScHandleGuard(existing);
            let updated = unsafe {
                ChangeServiceConfigW(
                    guard.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    start_type,
                    SERVICE_ERROR_NORMAL,
                    bin_wide.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                    display_wide.as_ptr(),
                )
            };
            if updated == 0 {
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!(
                        "ChangeServiceConfigW failed: {}",
                        std::io::Error::last_os_error()
                    ),
                });
            }
            guard
        } else {
            let created = unsafe {
                CreateServiceW(
                    scm.0,
                    name_wide.as_ptr(),
                    display_wide.as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    start_type,
                    SERVICE_ERROR_NORMAL,
                    bin_wide.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                )
            };
            if created.is_null() {
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!("CreateServiceW failed: {}", std::io::Error::last_os_error()),
                });
            }
            ScHandleGuard(created)
        };

        let mut desc = SERVICE_DESCRIPTIONW {
            lpDescription: desc_wide.as_mut_ptr(),
        };
        unsafe {
            let _ = ChangeServiceConfig2W(
                svc.0,
                SERVICE_CONFIG_DESCRIPTION,
                &mut desc as *mut SERVICE_DESCRIPTIONW as *const c_void,
            );
            let _ = SERVICE_NO_CHANGE;
        }

        query_handle_status(svc.0)
    }

    fn wait_for_service_state(
        svc_handle: SC_HANDLE,
        desired_state: SERVICE_STATUS_CURRENT_STATE,
        timeout: Duration,
    ) -> RouteWardResult<WindowsServiceStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            let status = query_handle_status(svc_handle)?;
            if status.state == map_service_state_label(desired_state) {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!(
                        "Timed out after {}s waiting for service state '{}' (last state '{}')",
                        timeout.as_secs(),
                        map_service_state_label(desired_state),
                        status.state
                    ),
                });
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn uninstall() -> RouteWardResult<()> {
        let scm = ScHandleGuard(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) });
        if scm.0.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "OpenSCManagerW failed (Administrator required): {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        let name_wide = to_wide_null(WINDOWS_SERVICE_NAME);
        let svc =
            ScHandleGuard(unsafe { OpenServiceW(scm.0, name_wide.as_ptr(), SERVICE_ALL_ACCESS) });
        if svc.0.is_null() {
            let os_err = std::io::Error::last_os_error();
            if os_err.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                return Ok(());
            }
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("OpenServiceW failed: {os_err}"),
            });
        }

        if let Ok(st) = query_handle_status(svc.0) {
            if st.state != "stopped" {
                let mut raw_status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
                unsafe {
                    let _ = ControlService(svc.0, SERVICE_CONTROL_STOP, &mut raw_status);
                }
                let _ = wait_for_service_state(
                    svc.0,
                    SERVICE_STOPPED,
                    Duration::from_secs(SCM_STOP_WAIT_TIMEOUT_SECS),
                );
            }
        }

        if unsafe { DeleteService(svc.0) } == 0 {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("DeleteService failed: {}", std::io::Error::last_os_error()),
            });
        }
        Ok(())
    }

    pub fn start() -> RouteWardResult<WindowsServiceStatus> {
        let scm = ScHandleGuard(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) });
        if scm.0.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("OpenSCManagerW failed: {}", std::io::Error::last_os_error()),
            });
        }
        let name_wide = to_wide_null(WINDOWS_SERVICE_NAME);
        let svc = ScHandleGuard(unsafe {
            OpenServiceW(
                scm.0,
                name_wide.as_ptr(),
                SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            )
        });
        if svc.0.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("OpenServiceW failed: {}", std::io::Error::last_os_error()),
            });
        }
        if unsafe { StartServiceW(svc.0, 0, null()) } == 0 {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("StartServiceW failed: {}", std::io::Error::last_os_error()),
            });
        }
        wait_for_service_state(
            svc.0,
            SERVICE_RUNNING,
            Duration::from_secs(SCM_START_WAIT_TIMEOUT_SECS),
        )
    }

    pub fn stop() -> RouteWardResult<WindowsServiceStatus> {
        let scm = ScHandleGuard(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) });
        if scm.0.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("OpenSCManagerW failed: {}", std::io::Error::last_os_error()),
            });
        }
        let name_wide = to_wide_null(WINDOWS_SERVICE_NAME);
        let svc = ScHandleGuard(unsafe {
            OpenServiceW(
                scm.0,
                name_wide.as_ptr(),
                SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            )
        });
        if svc.0.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("OpenServiceW failed: {}", std::io::Error::last_os_error()),
            });
        }
        let mut raw_status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut raw_status) } == 0 {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "ControlService(STOP) failed: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        wait_for_service_state(
            svc.0,
            SERVICE_STOPPED,
            Duration::from_secs(SCM_STOP_WAIT_TIMEOUT_SECS),
        )
    }

    pub fn query_status() -> RouteWardResult<WindowsServiceStatus> {
        let scm = ScHandleGuard(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) });
        if scm.0.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("OpenSCManagerW failed: {}", std::io::Error::last_os_error()),
            });
        }
        let name_wide = to_wide_null(WINDOWS_SERVICE_NAME);
        let svc = ScHandleGuard(unsafe {
            OpenServiceW(
                scm.0,
                name_wide.as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            )
        });
        if svc.0.is_null() {
            let os_err = std::io::Error::last_os_error();
            if os_err.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                return Ok(WindowsServiceStatus {
                    service_name: WINDOWS_SERVICE_NAME.to_string(),
                    display_name: WINDOWS_SERVICE_DISPLAY_NAME.to_string(),
                    installed: false,
                    state: "not_installed".to_string(),
                    pid: None,
                    binary_path: None,
                });
            }
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("OpenServiceW failed: {os_err}"),
            });
        }
        query_handle_status(svc.0)
    }
}

pub fn install_windows_service(
    exe_path: Option<&str>,
    allowed_sids: &[String],
    auto_start: bool,
) -> RouteWardResult<WindowsServiceStatus> {
    #[cfg(windows)]
    {
        win32_impl::install(exe_path, allowed_sids, auto_start)
    }
    #[cfg(not(windows))]
    {
        let _ = (exe_path, allowed_sids, auto_start);
        Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: "Windows Service Control Manager is only available on Windows".to_string(),
        })
    }
}

pub fn uninstall_windows_service() -> RouteWardResult<()> {
    #[cfg(windows)]
    {
        win32_impl::uninstall()
    }
    #[cfg(not(windows))]
    {
        Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: "Windows Service Control Manager is only available on Windows".to_string(),
        })
    }
}

pub fn start_windows_service() -> RouteWardResult<WindowsServiceStatus> {
    #[cfg(windows)]
    {
        win32_impl::start()
    }
    #[cfg(not(windows))]
    {
        Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: "Windows Service Control Manager is only available on Windows".to_string(),
        })
    }
}

pub fn stop_windows_service() -> RouteWardResult<WindowsServiceStatus> {
    #[cfg(windows)]
    {
        win32_impl::stop()
    }
    #[cfg(not(windows))]
    {
        Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: "Windows Service Control Manager is only available on Windows".to_string(),
        })
    }
}

pub fn query_windows_service_status() -> RouteWardResult<WindowsServiceStatus> {
    #[cfg(windows)]
    {
        win32_impl::query_status()
    }
    #[cfg(not(windows))]
    {
        Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: "Windows Service Control Manager is only available on Windows".to_string(),
        })
    }
}

pub fn run_windows_service_dispatcher(
    locale: String,
    allowed_sids: Vec<String>,
    runner: ServiceMainRunner,
) -> RouteWardResult<()> {
    #[cfg(windows)]
    {
        win32_impl::run_dispatcher(locale, allowed_sids, runner)
    }
    #[cfg(not(windows))]
    {
        let _ = (locale, allowed_sids, runner);
        Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: "Windows Service Control Manager dispatcher is only available on Windows"
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_class_access_masks_are_detected() {
        assert!(access_mask_grants_write(ACCESS_FILE_WRITE_DATA));
        assert!(access_mask_grants_write(ACCESS_FILE_APPEND_DATA));
        assert!(access_mask_grants_write(ACCESS_FILE_DELETE_CHILD));
        assert!(access_mask_grants_write(ACCESS_WRITE_DAC));
        assert!(access_mask_grants_write(ACCESS_WRITE_OWNER));
        assert!(access_mask_grants_write(ACCESS_GENERIC_ALL));
        assert!(access_mask_grants_write(ACCESS_GENERIC_WRITE));
        // FILE_ALL_ACCESS and a modify-style mask both include write data.
        assert!(access_mask_grants_write(0x001F_01FF));
        assert!(access_mask_grants_write(0x0013_01BF));
        // Read and execute only (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE minus synchronize bits).
        assert!(!access_mask_grants_write(0x0012_00A9));
        assert!(!access_mask_grants_write(0));
    }

    #[test]
    fn only_system_administrators_installer_and_creator_owner_are_trusted() {
        assert!(is_trusted_writer_sid("S-1-5-18"));
        assert!(is_trusted_writer_sid("S-1-5-32-544"));
        assert!(is_trusted_writer_sid("S-1-3-0"));
        assert!(is_trusted_writer_sid(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        ));
        assert!(!is_trusted_writer_sid("S-1-5-32-545"));
        assert!(!is_trusted_writer_sid("S-1-1-0"));
        assert!(!is_trusted_writer_sid("S-1-5-11"));
        assert!(!is_trusted_writer_sid("S-1-5-21-100-200-300-1001"));
        assert!(!is_trusted_writer_sid(""));
    }

    #[cfg(windows)]
    #[test]
    fn service_binary_in_user_writable_directory_is_refused() {
        let dir = std::env::temp_dir().join(format!("routeward-acl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let exe = dir.join("routeward.exe");
        std::fs::write(&exe, b"not a real binary").expect("write temp exe");
        let result = win32_impl::verify_service_binary_location(&exe);
        let _ = std::fs::remove_dir_all(&dir);
        let err = result.expect_err("a user-writable directory must be refused");
        assert_eq!(err.i18n_key(), ERR_KEY_DAEMON_INSECURE_PROFILE);
    }

    #[cfg(windows)]
    #[test]
    fn service_binary_in_system_directory_is_accepted() {
        let reg = crate::system::windows_system_tool_path("reg.exe");
        win32_impl::verify_service_binary_location(&reg)
            .expect("System32 is only writable by trusted principals");
    }

    #[test]
    fn quotes_service_binary_path_and_validates_allowed_sids() {
        let cmd = build_quoted_service_command_line(
            r"C:\Program Files\RouteWard\routeward.exe",
            &["S-1-5-21-100-200-300-1001".to_string()],
        )
        .expect("quoted SCM command line");
        assert_eq!(
            cmd,
            r#""C:\Program Files\RouteWard\routeward.exe" service run --allow-sid S-1-5-21-100-200-300-1001"#
        );

        assert!(build_quoted_service_command_line(r#"C:\bad"quote\routeward.exe"#, &[],).is_err());
        assert!(build_quoted_service_command_line(
            r"C:\Program Files\RouteWard\routeward.exe",
            &["WD".to_string()],
        )
        .is_err());
    }
}
