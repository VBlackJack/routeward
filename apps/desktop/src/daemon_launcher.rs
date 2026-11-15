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

use routeward_core::error::{
    DAEMON_EXIT_CONFIG_ERROR, DAEMON_EXIT_INSECURE_PROFILE, DAEMON_EXIT_IPC_ERROR,
    DAEMON_EXIT_NOT_ELEVATED,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
const CLI_BINARY_FILENAME: &str = "routeward.exe";
#[cfg(not(windows))]
const CLI_BINARY_FILENAME: &str = "routeward";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonLaunchPlan {
    StartService { args: Vec<String> },
    SpawnDaemon { args: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonLaunchError {
    AlreadyInFlight,
    UnsupportedOs,
    MissingCliBinary,
    AlreadyRunningAccessDenied,
    UacCancelled,
    InsecureProfile(u32),
    IpcBindFailed(u32),
    NotElevated(u32),
    ConfigInvalid(u32),
    DaemonExitedEarly(u32),
    LaunchFailed(String),
}

impl DaemonLaunchError {
    pub fn from_daemon_exit_code(exit_code: u32) -> Self {
        match u8::try_from(exit_code) {
            Ok(DAEMON_EXIT_NOT_ELEVATED) => Self::NotElevated(exit_code),
            Ok(DAEMON_EXIT_INSECURE_PROFILE) => Self::InsecureProfile(exit_code),
            Ok(DAEMON_EXIT_IPC_ERROR) => Self::IpcBindFailed(exit_code),
            Ok(DAEMON_EXIT_CONFIG_ERROR) => Self::ConfigInvalid(exit_code),
            _ => Self::DaemonExitedEarly(exit_code),
        }
    }

    pub fn status_code(&self) -> u16 {
        match self {
            Self::UacCancelled => 400,
            Self::NotElevated(_) => 403,
            Self::MissingCliBinary => 404,
            Self::AlreadyInFlight | Self::AlreadyRunningAccessDenied => 409,
            Self::InsecureProfile(_) | Self::ConfigInvalid(_) => 422,
            Self::UnsupportedOs => 501,
            Self::IpcBindFailed(_) | Self::DaemonExitedEarly(_) | Self::LaunchFailed(_) => 500,
        }
    }

    pub fn error_key(&self) -> &'static str {
        match self {
            Self::AlreadyInFlight => "already_in_flight",
            Self::UnsupportedOs => "unsupported_os",
            Self::MissingCliBinary => "cli_missing",
            Self::AlreadyRunningAccessDenied => "access_denied",
            Self::UacCancelled => "uac_cancelled",
            Self::InsecureProfile(_) => "insecure_profile",
            Self::IpcBindFailed(_) => "ipc_error",
            Self::NotElevated(_) => "not_elevated",
            Self::ConfigInvalid(_) => "config_invalid",
            Self::DaemonExitedEarly(_) => "daemon_exited",
            Self::LaunchFailed(_) => "start_failed",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::AlreadyInFlight => "A daemon start operation is already in progress".to_string(),
            Self::UnsupportedOs => {
                "Automatic privileged service start is only supported on Windows".to_string()
            }
            Self::MissingCliBinary => {
                "Sibling routeward CLI executable was not found next to desktop binary".to_string()
            }
            Self::AlreadyRunningAccessDenied => {
                "RouteWard Windows service is running without IPC pipe permission for this user"
                    .to_string()
            }
            Self::UacCancelled => "Administrator UAC prompt was cancelled by the user".to_string(),
            Self::InsecureProfile(code) => format!(
                "Daemon refused to start because profile directory or file has insecure ownership or permissions (exit code {code})"
            ),
            Self::IpcBindFailed(code) => {
                format!("Daemon failed to bind its local IPC endpoint (exit code {code})")
            }
            Self::NotElevated(code) => {
                format!("Daemon did not receive elevated administrator privileges (exit code {code})")
            }
            Self::ConfigInvalid(code) => {
                format!("Daemon failed to load embedded or saved configuration (exit code {code})")
            }
            Self::DaemonExitedEarly(code) => {
                format!("Elevated daemon process exited unexpectedly with code {code}")
            }
            Self::LaunchFailed(msg) => msg.clone(),
        }
    }
}

/// RAII handle wrapping a launched Windows elevated process handle (`CloseHandle` on drop).
pub struct ElevatedProcessHandle {
    #[cfg(windows)]
    raw_handle: isize,
}

#[cfg(windows)]
impl Drop for ElevatedProcessHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        if self.raw_handle != 0 {
            unsafe {
                CloseHandle(self.raw_handle as HANDLE);
            }
        }
    }
}

impl ElevatedProcessHandle {
    #[cfg(windows)]
    pub fn try_exit_code(&self) -> Option<u32> {
        use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

        if self.raw_handle == 0 {
            return None;
        }
        let handle = self.raw_handle as HANDLE;
        unsafe {
            if WaitForSingleObject(handle, 0) == WAIT_OBJECT_0 {
                let mut exit_code: u32 = 0;
                if GetExitCodeProcess(handle, &mut exit_code) != 0 {
                    return Some(exit_code);
                }
            }
        }
        None
    }

    #[cfg(not(windows))]
    pub fn try_exit_code(&self) -> Option<u32> {
        None
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonStartOutcome {
    pub launched: bool,
    pub connected: bool,
}

#[derive(Default)]
pub struct DaemonStartGuard {
    in_flight: Arc<AtomicBool>,
}

impl DaemonStartGuard {
    pub fn try_acquire(&self) -> Option<InFlightRelease> {
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Some(InFlightRelease {
                flag: Arc::clone(&self.in_flight),
            })
        } else {
            None
        }
    }
}

pub struct InFlightRelease {
    flag: Arc<AtomicBool>,
}

impl Drop for InFlightRelease {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

pub fn strip_windows_verbatim_prefix(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(stripped) = raw.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{stripped}"))
    } else if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

pub fn resolve_sibling_cli_exe(desktop_exe: &Path) -> Option<PathBuf> {
    let normalized = strip_windows_verbatim_prefix(desktop_exe);
    let candidate = normalized.parent()?.join(CLI_BINARY_FILENAME);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

pub fn normalize_safe_locale(locale: &str) -> &'static str {
    if locale.trim().to_ascii_lowercase().starts_with("fr") {
        "fr"
    } else {
        "en"
    }
}

pub fn build_daemon_launch_plan(
    installed: bool,
    service_state: &str,
    allow_sid: Option<&str>,
    locale: &str,
) -> Result<DaemonLaunchPlan, DaemonLaunchError> {
    if installed {
        let normalized_state = service_state.trim().to_ascii_lowercase();
        if normalized_state == "running" || normalized_state == "start_pending" {
            return Err(DaemonLaunchError::AlreadyRunningAccessDenied);
        }
        return Ok(DaemonLaunchPlan::StartService {
            args: vec!["service".to_string(), "start".to_string()],
        });
    }

    let safe_locale = normalize_safe_locale(locale);
    let mut args = vec![
        "daemon".to_string(),
        "--locale".to_string(),
        safe_locale.to_string(),
    ];
    if let Some(sid) = allow_sid.map(str::trim).filter(|s| !s.is_empty()) {
        args.push("--allow-sid".to_string());
        args.push(sid.to_string());
    }
    Ok(DaemonLaunchPlan::SpawnDaemon { args })
}

pub async fn start_privileged_daemon_with_release(
    _release: &InFlightRelease,
    locale: &str,
) -> Result<Option<ElevatedProcessHandle>, DaemonLaunchError> {
    #[cfg(not(windows))]
    {
        let _ = locale;
        Err(DaemonLaunchError::UnsupportedOs)
    }

    #[cfg(windows)]
    {
        let safe_locale = normalize_safe_locale(locale).to_string();
        tokio::task::spawn_blocking(move || windows_impl::launch_elevated(&safe_locale))
            .await
            .map_err(|e| DaemonLaunchError::LaunchFailed(e.to_string()))?
    }
}

pub async fn start_privileged_daemon(
    guard: &DaemonStartGuard,
    locale: &str,
) -> Result<Option<ElevatedProcessHandle>, DaemonLaunchError> {
    let release = guard
        .try_acquire()
        .ok_or(DaemonLaunchError::AlreadyInFlight)?;
    start_privileged_daemon_with_release(&release, locale).await
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use routeward_core::ipc::transport::current_user_sid_string;
    use routeward_core::system::windows_service::{
        query_windows_service_status, start_windows_service,
    };
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_CANCELLED};
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    struct ComScope(bool);
    impl Drop for ComScope {
        fn drop(&mut self) {
            if self.0 {
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }

    fn run_elevated_cli(
        cli_exe: &Path,
        args: &[String],
    ) -> Result<Option<ElevatedProcessHandle>, DaemonLaunchError> {
        let exe_str = cli_exe.to_string_lossy();
        let params_str = args
            .iter()
            .map(|a| {
                if a.contains(' ') {
                    format!("\"{a}\"")
                } else {
                    a.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");

        let verb_w = to_wide_null("runas");
        let file_w = to_wide_null(&exe_str);
        let params_w = to_wide_null(&params_str);
        let dir_w = cli_exe.parent().map(|p| to_wide_null(&p.to_string_lossy()));

        unsafe {
            let hr = CoInitializeEx(
                null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            );
            let _com_guard = ComScope(hr >= 0);

            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
            info.hwnd = null_mut();
            info.lpVerb = verb_w.as_ptr();
            info.lpFile = file_w.as_ptr();
            info.lpParameters = params_w.as_ptr();
            info.lpDirectory = dir_w.as_ref().map_or(null(), |v| v.as_ptr());
            info.nShow = SW_HIDE;

            if ShellExecuteExW(&mut info) == 0 {
                let err = GetLastError();
                if err == ERROR_CANCELLED {
                    return Err(DaemonLaunchError::UacCancelled);
                }
                return Err(DaemonLaunchError::LaunchFailed(format!(
                    "ShellExecuteExW failed with Win32 error {err}"
                )));
            }

            let proc_handle = if !info.hProcess.is_null() {
                Some(ElevatedProcessHandle {
                    raw_handle: info.hProcess as isize,
                })
            } else {
                None
            };
            Ok(proc_handle)
        }
    }

    pub fn launch_elevated(
        locale: &str,
    ) -> Result<Option<ElevatedProcessHandle>, DaemonLaunchError> {
        let desktop_exe =
            std::env::current_exe().map_err(|e| DaemonLaunchError::LaunchFailed(e.to_string()))?;
        let cli_exe =
            resolve_sibling_cli_exe(&desktop_exe).ok_or(DaemonLaunchError::MissingCliBinary)?;

        let svc_status = query_windows_service_status().ok();
        let installed = svc_status.as_ref().is_some_and(|s| s.installed);
        let svc_state = svc_status
            .as_ref()
            .map(|s| s.state.as_str())
            .unwrap_or("stopped");

        if installed
            && !svc_state.eq_ignore_ascii_case("running")
            && start_windows_service().is_ok()
        {
            return Ok(None);
        }

        let user_sid = current_user_sid_string().ok();
        let plan = build_daemon_launch_plan(installed, svc_state, user_sid.as_deref(), locale)?;

        match plan {
            DaemonLaunchPlan::StartService { args } | DaemonLaunchPlan::SpawnDaemon { args } => {
                run_elevated_cli(&cli_exe, &args)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_windows_verbatim_prefixes_cleanly() {
        assert_eq!(
            strip_windows_verbatim_prefix(Path::new(r"\\?\C:\Program Files\RouteWard\app.exe")),
            PathBuf::from(r"C:\Program Files\RouteWard\app.exe")
        );
        assert_eq!(
            strip_windows_verbatim_prefix(Path::new(r"\\?\UNC\server\share\app.exe")),
            PathBuf::from(r"\\server\share\app.exe")
        );
        assert_eq!(
            strip_windows_verbatim_prefix(Path::new("/usr/bin/routeward-desktop")),
            PathBuf::from("/usr/bin/routeward-desktop")
        );
    }

    #[test]
    fn resolve_sibling_cli_exe_finds_only_real_sibling_file() {
        let unique_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "routeward-launcher-test-{}-{unique_suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        let desktop_path = dir.join("routeward-desktop.exe");
        std::fs::write(&desktop_path, b"dummy").expect("write dummy desktop exe");

        assert!(resolve_sibling_cli_exe(&desktop_path).is_none());

        let cli_path = dir.join(CLI_BINARY_FILENAME);
        std::fs::write(&cli_path, b"dummy-cli").expect("write dummy cli exe");
        assert_eq!(resolve_sibling_cli_exe(&desktop_path), Some(cli_path));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_daemon_launch_plan_covers_service_daemon_and_access_denied_states() {
        let start_svc = build_daemon_launch_plan(true, "stopped", Some("S-1-5-21-1001"), "fr")
            .expect("stopped installed service should produce StartService plan");
        assert_eq!(
            start_svc,
            DaemonLaunchPlan::StartService {
                args: vec!["service".into(), "start".into()]
            }
        );

        let running_err = build_daemon_launch_plan(true, "running", Some("S-1-5-21-1001"), "fr")
            .expect_err("running service while IPC disconnected implies pipe ACL mismatch");
        assert_eq!(running_err, DaemonLaunchError::AlreadyRunningAccessDenied);

        let daemon_plan =
            build_daemon_launch_plan(false, "not_installed", Some("S-1-5-21-1001"), "en")
                .expect("uninstalled service should launch elevated daemon with user SID");
        assert_eq!(
            daemon_plan,
            DaemonLaunchPlan::SpawnDaemon {
                args: vec![
                    "daemon".into(),
                    "--locale".into(),
                    "en".into(),
                    "--allow-sid".into(),
                    "S-1-5-21-1001".into(),
                ]
            }
        );
    }

    #[test]
    fn daemon_start_guard_prevents_concurrent_double_launch() {
        let guard = DaemonStartGuard::default();
        let first = guard.try_acquire();
        assert!(first.is_some());
        assert!(guard.try_acquire().is_none());
        drop(first);
        assert!(guard.try_acquire().is_some());
    }

    #[test]
    fn maps_daemon_startup_exit_codes_to_specific_errors() {
        let not_elevated =
            DaemonLaunchError::from_daemon_exit_code(u32::from(DAEMON_EXIT_NOT_ELEVATED));
        assert_eq!(not_elevated.error_key(), "not_elevated");
        assert_eq!(not_elevated.status_code(), 403);

        let insecure =
            DaemonLaunchError::from_daemon_exit_code(u32::from(DAEMON_EXIT_INSECURE_PROFILE));
        assert_eq!(insecure.error_key(), "insecure_profile");
        assert_eq!(insecure.status_code(), 422);

        let ipc_err = DaemonLaunchError::from_daemon_exit_code(u32::from(DAEMON_EXIT_IPC_ERROR));
        assert_eq!(ipc_err.error_key(), "ipc_error");
        assert_eq!(ipc_err.status_code(), 500);

        let cfg_err = DaemonLaunchError::from_daemon_exit_code(u32::from(DAEMON_EXIT_CONFIG_ERROR));
        assert_eq!(cfg_err.error_key(), "config_invalid");
        assert_eq!(cfg_err.status_code(), 422);

        let unknown = DaemonLaunchError::from_daemon_exit_code(42);
        assert_eq!(unknown.error_key(), "daemon_exited");
        assert_eq!(unknown.status_code(), 500);
    }
}
