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
use routeward_core::ipc::transport::DaemonIpcProbe;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
const CLI_BINARY_FILENAME: &str = "routeward.exe";
#[cfg(not(windows))]
const CLI_BINARY_FILENAME: &str = "routeward";

/// Locale key of the notice shown when the background service could not be installed and the
/// protection runs as a plain process instead (it will not survive a restart of the PC).
pub const FALLBACK_KEY_SERVICE_INSTALL_FAILED: &str = "tray.notice.service_install_failed";
/// Locale keys of the notices shown when a start from the tray fails.
const NOTICE_KEY_UAC_CANCELLED: &str = "tray.notice.uac_cancelled";
const NOTICE_KEY_ACCESS_DENIED: &str = "tray.notice.access_denied";
const NOTICE_KEY_START_FAILED: &str = "tray.notice.start_failed";
/// How long the elevated `service install --start` may take before it counts as failed.
#[cfg(windows)]
const SERVICE_INSTALL_TIMEOUT_MS: u32 = 60_000;
/// Prefix every Windows security identifier starts with.
const SID_PREFIX: &str = "S-1-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonLaunchPlan {
    /// Install the Windows service (one elevated command), start it and allow the user's pipe.
    InstallService {
        args: Vec<String>,
    },
    StartService {
        args: Vec<String>,
    },
    SpawnDaemon {
        args: Vec<String>,
    },
}

/// How the daemon was brought up by a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    /// The service did not exist: it was installed (and started) by this launch.
    ServiceInstalled,
    /// The existing service was started.
    ServiceStarted,
    /// A plain elevated daemon process was spawned (no service).
    SpawnedDaemon,
}

/// Result of a launch: the elevated process to watch (if any), how it was started, and why the
/// service was not used when a plain daemon had to be spawned instead.
pub struct LaunchOutcome {
    pub handle: Option<ElevatedProcessHandle>,
    pub mode: LaunchMode,
    /// Locale key explaining why the service was not installed, when a fallback happened.
    pub fallback_reason_key: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonLaunchError {
    AlreadyInFlight,
    UnsupportedOs,
    /// Linux: the service socket exists but this account is not in the `routeward` group.
    LinuxGroupRequired,
    /// Linux: nothing listens on the service socket; the service has to be enabled and started.
    LinuxServiceNotRunning,
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
            Self::AlreadyInFlight | Self::AlreadyRunningAccessDenied | Self::LinuxGroupRequired => {
                409
            }
            Self::LinuxServiceNotRunning => 503,
            Self::InsecureProfile(_) | Self::ConfigInvalid(_) => 422,
            Self::UnsupportedOs => 501,
            Self::IpcBindFailed(_) | Self::DaemonExitedEarly(_) | Self::LaunchFailed(_) => 500,
        }
    }

    pub fn error_key(&self) -> &'static str {
        match self {
            Self::AlreadyInFlight => "already_in_flight",
            Self::UnsupportedOs => "unsupported_os",
            Self::LinuxGroupRequired => "linux_group_required",
            Self::LinuxServiceNotRunning => "linux_service_not_running",
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

    /// Locale key of the plain-words notice a failed start from the tray shows.
    pub fn tray_notice_key(&self) -> &'static str {
        match self {
            Self::UacCancelled => NOTICE_KEY_UAC_CANCELLED,
            Self::AlreadyRunningAccessDenied => NOTICE_KEY_ACCESS_DENIED,
            _ => NOTICE_KEY_START_FAILED,
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::AlreadyInFlight => "A daemon start operation is already in progress".to_string(),
            Self::UnsupportedOs => {
                "Automatic privileged service start is only supported on Windows".to_string()
            }
            Self::LinuxGroupRequired => {
                "The RouteWard service socket is not reachable: this account is not in the routeward group"
                    .to_string()
            }
            Self::LinuxServiceNotRunning => {
                "The RouteWard service is not running on its socket".to_string()
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

    /// Waits up to `timeout_ms` for the process to end and returns its exit code.
    #[cfg(windows)]
    pub fn wait_exit_code(&self, timeout_ms: u32) -> Option<u32> {
        use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

        if self.raw_handle == 0 {
            return None;
        }
        let handle = self.raw_handle as HANDLE;
        unsafe {
            if WaitForSingleObject(handle, timeout_ms) == WAIT_OBJECT_0 {
                let mut exit_code: u32 = 0;
                if GetExitCodeProcess(handle, &mut exit_code) != 0 {
                    return Some(exit_code);
                }
            }
        }
        None
    }
}

/// True when the Windows service is registered (running or not).
pub fn is_service_installed() -> bool {
    routeward_core::system::windows_service::query_windows_service_status()
        .map(|status| status.installed)
        .unwrap_or(false)
}

/// What to do after the elevated service install reported a failure or timed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterFailedInstall {
    /// The service got installed and runs: nothing to start.
    ServiceAlreadyRunning,
    /// The service got installed but is stopped: start it.
    StartService,
    /// No service: fall back to a plain elevated daemon. Never combined with a service.
    SpawnDaemon,
}

/// Decides the fallback once the install attempt is over, from the real service state.
pub fn decide_after_failed_install(installed: bool, service_state: &str) -> AfterFailedInstall {
    if !installed {
        return AfterFailedInstall::SpawnDaemon;
    }
    let state = service_state.trim().to_ascii_lowercase();
    if state == "running" || state == "start_pending" {
        AfterFailedInstall::ServiceAlreadyRunning
    } else {
        AfterFailedInstall::StartService
    }
}

/// True when `exit_code` is the clean exit of an elevated `service install --start`.
pub fn service_install_succeeded(exit_code: Option<u32>) -> bool {
    exit_code == Some(0)
}

/// True when `sid` looks like a Windows security identifier (`S-1-` followed by digits and
/// dashes). The value ends up on the command line of an elevated process, so anything else is
/// refused.
pub fn is_plausible_sid(sid: &str) -> bool {
    sid.strip_prefix(SID_PREFIX).is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit() || c == '-')
    })
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
    /// True while a daemon start is in progress.
    pub fn is_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst)
    }

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

/// The old way to run without the service: an elevated daemon process that lives until the
/// machine restarts or the daemon is stopped. Used when the service cannot be installed.
pub fn build_spawn_daemon_plan(allow_sid: Option<&str>, locale: &str) -> DaemonLaunchPlan {
    DaemonLaunchPlan::SpawnDaemon {
        args: spawn_daemon_args(allow_sid, locale),
    }
}

/// Arguments of the `routeward daemon` command a spawned daemon runs with.
pub fn spawn_daemon_args(allow_sid: Option<&str>, locale: &str) -> Vec<String> {
    let safe_locale = normalize_safe_locale(locale);
    let mut args = vec![
        "daemon".to_string(),
        "--locale".to_string(),
        safe_locale.to_string(),
    ];
    if let Some(sid) = allow_sid.map(str::trim).filter(|s| is_plausible_sid(s)) {
        args.push("--allow-sid".to_string());
        args.push(sid.to_string());
    }
    args
}

/// Quotes one argument according to Win32 `CommandLineToArgvW` rules.
#[cfg(any(windows, test))]
fn quote_windows_cmdline_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| matches!(c, ' ' | '\t' | '"')) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                out.push(ch);
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Chooses how to bring the daemon up.
///
/// - Service registered: start it (a running service the user cannot reach is an access problem).
/// - No service and a usable user SID: install the service, start it and allow that user's pipe,
///   all in one elevated command (a single UAC prompt).
/// - No service and no usable SID: the service pipe would not be reachable by the user, so a
///   plain elevated daemon is spawned.
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

    match allow_sid.map(str::trim).filter(|sid| is_plausible_sid(sid)) {
        Some(sid) => Ok(DaemonLaunchPlan::InstallService {
            args: vec![
                "service".to_string(),
                "install".to_string(),
                "--start".to_string(),
                "--allow-sid".to_string(),
                sid.to_string(),
            ],
        }),
        None => Ok(build_spawn_daemon_plan(None, locale)),
    }
}

/// Turns what a probe of the service socket found into the outcome of a start request on Linux:
/// the access errors the user must act on, or (socket answers) a launch with no process to watch,
/// so the caller polls and reconnects instead of reporting a failure.
pub fn linux_start_outcome_for_probe(
    probe: DaemonIpcProbe,
) -> Result<LaunchOutcome, DaemonLaunchError> {
    match probe {
        DaemonIpcProbe::AccessDenied => Err(DaemonLaunchError::LinuxGroupRequired),
        DaemonIpcProbe::NotRunning => Err(DaemonLaunchError::LinuxServiceNotRunning),
        DaemonIpcProbe::Running => Ok(LaunchOutcome {
            handle: None,
            mode: LaunchMode::ServiceStarted,
            fallback_reason_key: None,
        }),
    }
}

pub async fn start_privileged_daemon_with_release(
    _release: &InFlightRelease,
    locale: &str,
) -> Result<LaunchOutcome, DaemonLaunchError> {
    #[cfg(not(windows))]
    {
        let _ = locale;
        #[cfg(target_os = "linux")]
        {
            // The service is managed with systemd by the administrator; the desktop only tells the
            // user which of the two documented steps is missing.
            let constants = routeward_core::config::SystemConstants::load_embedded()
                .map_err(|err| DaemonLaunchError::LaunchFailed(err.to_string()))?;
            let probe = tokio::task::spawn_blocking(move || {
                routeward_core::ipc::transport::probe_daemon_ipc(&constants.ipc)
            })
            .await
            .map_err(|err| DaemonLaunchError::LaunchFailed(err.to_string()))?;
            linux_start_outcome_for_probe(probe)
        }
        #[cfg(not(target_os = "linux"))]
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
) -> Result<LaunchOutcome, DaemonLaunchError> {
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

    /// Runs the CLI elevated through the UAC prompt.
    ///
    /// Variable arguments are validated before reaching this function (SID and whitelisted locale)
    /// and additionally escaped using Win32 `CommandLineToArgvW` quoting rules as defense-in-depth.
    fn run_elevated_cli(
        cli_exe: &Path,
        args: &[String],
    ) -> Result<Option<ElevatedProcessHandle>, DaemonLaunchError> {
        let exe_str = cli_exe.to_string_lossy();
        let params_str = args
            .iter()
            .map(|a| super::quote_windows_cmdline_arg(a))
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

    pub fn launch_elevated(locale: &str) -> Result<LaunchOutcome, DaemonLaunchError> {
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
            return Ok(LaunchOutcome {
                handle: None,
                mode: LaunchMode::ServiceStarted,
                fallback_reason_key: None,
            });
        }

        let user_sid = current_user_sid_string().ok();
        let plan = build_daemon_launch_plan(installed, svc_state, user_sid.as_deref(), locale)?;

        match plan {
            DaemonLaunchPlan::InstallService { args } => {
                let installed_ok = match run_elevated_cli(&cli_exe, &args) {
                    // Declined: do not ask again through a second prompt.
                    Err(DaemonLaunchError::UacCancelled) => {
                        return Err(DaemonLaunchError::UacCancelled)
                    }
                    Err(_) => false,
                    Ok(handle) => service_install_succeeded(
                        handle
                            .as_ref()
                            .and_then(|h| h.wait_exit_code(SERVICE_INSTALL_TIMEOUT_MS)),
                    ),
                };
                if installed_ok {
                    return Ok(LaunchOutcome {
                        handle: None,
                        mode: LaunchMode::ServiceInstalled,
                        fallback_reason_key: None,
                    });
                }
                // The install may still have succeeded (a late exit, a timeout): start the
                // service when it is there, and never run both a service and a spawned daemon.
                let after = query_windows_service_status().ok();
                match decide_after_failed_install(
                    after.as_ref().is_some_and(|s| s.installed),
                    after.as_ref().map_or("", |s| s.state.as_str()),
                ) {
                    AfterFailedInstall::ServiceAlreadyRunning => {
                        return Ok(LaunchOutcome {
                            handle: None,
                            mode: LaunchMode::ServiceStarted,
                            fallback_reason_key: None,
                        });
                    }
                    AfterFailedInstall::StartService => {
                        if start_windows_service().is_ok() {
                            return Ok(LaunchOutcome {
                                handle: None,
                                mode: LaunchMode::ServiceStarted,
                                fallback_reason_key: None,
                            });
                        }
                        let args = vec!["service".to_string(), "start".to_string()];
                        return Ok(LaunchOutcome {
                            handle: run_elevated_cli(&cli_exe, &args)?,
                            mode: LaunchMode::ServiceStarted,
                            fallback_reason_key: None,
                        });
                    }
                    AfterFailedInstall::SpawnDaemon => {}
                }
                // The service could not be installed: run the daemon as a plain process.
                let args = spawn_daemon_args(user_sid.as_deref(), locale);
                Ok(LaunchOutcome {
                    handle: run_elevated_cli(&cli_exe, &args)?,
                    mode: LaunchMode::SpawnedDaemon,
                    fallback_reason_key: Some(FALLBACK_KEY_SERVICE_INSTALL_FAILED),
                })
            }
            DaemonLaunchPlan::StartService { args } => Ok(LaunchOutcome {
                handle: run_elevated_cli(&cli_exe, &args)?,
                mode: LaunchMode::ServiceStarted,
                fallback_reason_key: None,
            }),
            DaemonLaunchPlan::SpawnDaemon { args } => Ok(LaunchOutcome {
                handle: run_elevated_cli(&cli_exe, &args)?,
                mode: LaunchMode::SpawnedDaemon,
                fallback_reason_key: None,
            }),
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

        let install_plan =
            build_daemon_launch_plan(false, "not_installed", Some("S-1-5-21-1001"), "en")
                .expect("uninstalled service should be installed for the user SID");
        assert_eq!(
            install_plan,
            DaemonLaunchPlan::InstallService {
                args: vec![
                    "service".into(),
                    "install".into(),
                    "--start".into(),
                    "--allow-sid".into(),
                    "S-1-5-21-1001".into(),
                ]
            }
        );

        // Without a usable SID the service pipe would stay out of the user's reach: spawn a daemon
        // without forwarding any unvalidated --allow-sid value.
        for unusable in [None, Some(""), Some("not-a-sid"), Some("S-1-5-21 --evil")] {
            let plan = build_daemon_launch_plan(false, "not_installed", unusable, "fr")
                .expect("an uninstalled service without a usable SID spawns a daemon");
            match plan {
                DaemonLaunchPlan::SpawnDaemon { args } => {
                    assert!(
                        !args.iter().any(|a| a == "--allow-sid"),
                        "{unusable:?} must not forward --allow-sid to the fallback daemon: {args:?}"
                    );
                }
                other => panic!(
                    "{unusable:?} must not reach the elevated service install command: {other:?}"
                ),
            }
        }
        assert_eq!(quote_windows_cmdline_arg("plain"), "plain");
        assert_eq!(quote_windows_cmdline_arg(r#"a "b" c\"#), r#""a \"b\" c\\""#);
    }

    #[test]
    fn a_failed_install_never_spawns_a_daemon_next_to_an_installed_service() {
        assert_eq!(
            decide_after_failed_install(false, "not_installed"),
            AfterFailedInstall::SpawnDaemon
        );
        assert_eq!(
            decide_after_failed_install(true, "stopped"),
            AfterFailedInstall::StartService
        );
        for state in ["running", "START_PENDING", " Running "] {
            assert_eq!(
                decide_after_failed_install(true, state),
                AfterFailedInstall::ServiceAlreadyRunning,
                "{state}"
            );
        }
    }

    #[test]
    fn spawn_fallback_plan_keeps_the_old_daemon_arguments() {
        assert_eq!(
            build_spawn_daemon_plan(Some("S-1-5-21-1001"), "en"),
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
        assert_eq!(
            spawn_daemon_args(None, "fr-FR"),
            vec!["daemon", "--locale", "fr"]
        );
    }

    #[test]
    fn only_a_clean_exit_counts_as_a_successful_service_install() {
        assert!(service_install_succeeded(Some(0)));
        assert!(!service_install_succeeded(Some(1)));
        assert!(!service_install_succeeded(None));
    }

    #[test]
    fn sid_validation_accepts_real_sids_only() {
        assert!(is_plausible_sid("S-1-5-21-1-2-3-1000"));
        assert!(!is_plausible_sid("S-1-"));
        assert!(!is_plausible_sid("S-2-5-21"));
        assert!(!is_plausible_sid("S-1-5-21-1 --other"));
        assert!(!is_plausible_sid(""));
    }

    #[test]
    fn linux_probe_results_map_to_distinct_start_results() {
        let Err(group) = linux_start_outcome_for_probe(DaemonIpcProbe::AccessDenied) else {
            panic!("access denied must be an error");
        };
        assert_eq!(group, DaemonLaunchError::LinuxGroupRequired);
        assert_eq!(group.error_key(), "linux_group_required");
        assert_eq!(group.status_code(), 409);
        let Err(down) = linux_start_outcome_for_probe(DaemonIpcProbe::NotRunning) else {
            panic!("a stopped service must be an error");
        };
        assert_eq!(down, DaemonLaunchError::LinuxServiceNotRunning);
        assert_eq!(down.error_key(), "linux_service_not_running");
        assert_eq!(down.status_code(), 503);
        // The socket answers: not a failure, the caller polls and reconnects.
        let running = linux_start_outcome_for_probe(DaemonIpcProbe::Running)
            .expect("a running service is a successful outcome");
        assert!(running.handle.is_none());
        assert_eq!(running.mode, LaunchMode::ServiceStarted);
        assert!(running.fallback_reason_key.is_none());
    }

    #[test]
    fn launch_errors_map_to_plain_tray_notices() {
        assert_eq!(
            DaemonLaunchError::UacCancelled.tray_notice_key(),
            "tray.notice.uac_cancelled"
        );
        assert_eq!(
            DaemonLaunchError::AlreadyRunningAccessDenied.tray_notice_key(),
            "tray.notice.access_denied"
        );
        assert_eq!(
            DaemonLaunchError::MissingCliBinary.tray_notice_key(),
            "tray.notice.start_failed"
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
