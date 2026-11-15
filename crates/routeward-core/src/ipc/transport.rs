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

use crate::config::IpcConstants;
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_DAEMON_ALREADY_RUNNING, ERR_KEY_DAEMON_DISCONNECTED,
    ERR_KEY_DAEMON_IPC_ERROR,
};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct IpcStream {
    inner: IpcStreamInner,
}

enum IpcStreamInner {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    NamedPipeServer(tokio::net::windows::named_pipe::NamedPipeServer),
    #[cfg(windows)]
    NamedPipeClient(tokio::net::windows::named_pipe::NamedPipeClient),
}

impl AsyncRead for IpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            #[cfg(unix)]
            IpcStreamInner::Unix(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(windows)]
            IpcStreamInner::NamedPipeServer(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(windows)]
            IpcStreamInner::NamedPipeClient(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for IpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.inner {
            #[cfg(unix)]
            IpcStreamInner::Unix(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(windows)]
            IpcStreamInner::NamedPipeServer(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(windows)]
            IpcStreamInner::NamedPipeClient(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            #[cfg(unix)]
            IpcStreamInner::Unix(s) => Pin::new(s).poll_flush(cx),
            #[cfg(windows)]
            IpcStreamInner::NamedPipeServer(s) => Pin::new(s).poll_flush(cx),
            #[cfg(windows)]
            IpcStreamInner::NamedPipeClient(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            #[cfg(unix)]
            IpcStreamInner::Unix(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(windows)]
            IpcStreamInner::NamedPipeServer(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(windows)]
            IpcStreamInner::NamedPipeClient(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

pub struct IpcServer {
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    #[cfg(unix)]
    socket_path: std::path::PathBuf,
    #[cfg(windows)]
    current_pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(windows)]
    sddl_string: String,
}

impl IpcServer {
    pub fn bind(ipc_config: &IpcConstants) -> RouteWardResult<Self> {
        Self::bind_with_allowed_sids(ipc_config, &[])
    }

    pub fn bind_with_allowed_sids(
        ipc_config: &IpcConstants,
        allowed_sids: &[String],
    ) -> RouteWardResult<Self> {
        #[cfg(unix)]
        {
            for raw_sid in allowed_sids {
                validate_and_canonicalize_allowed_sid(raw_sid)?;
            }
            Self::bind_unix(ipc_config)
        }
        #[cfg(windows)]
        {
            Self::bind_windows_with_allowed_sids(&ipc_config.windows_pipe_name, allowed_sids)
        }
    }

    pub fn bind_for_test(ipc_config: &IpcConstants) -> RouteWardResult<Self> {
        #[cfg(unix)]
        {
            use std::fs;
            use std::path::PathBuf;

            let socket_path = PathBuf::from(&ipc_config.unix_socket_path);
            if socket_path.exists() {
                let _ = fs::remove_file(&socket_path);
            }
            if let Some(parent) = socket_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            let listener = tokio::net::UnixListener::bind(&socket_path).map_err(|err| {
                RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!(
                        "Failed to bind test Unix socket {}: {err}",
                        socket_path.display()
                    ),
                }
            })?;
            Ok(Self {
                listener,
                socket_path,
            })
        }
        #[cfg(windows)]
        {
            Self::bind_windows(&ipc_config.windows_pipe_name)
        }
    }

    #[cfg(windows)]
    pub fn bind_windows(pipe_name: &str) -> RouteWardResult<Self> {
        Self::bind_windows_with_allowed_sids(pipe_name, &[])
    }

    #[cfg(windows)]
    pub fn bind_windows_with_allowed_sids(
        pipe_name: &str,
        allowed_sids: &[String],
    ) -> RouteWardResult<Self> {
        let user_sid = query_current_user_sid_string()?;
        let sddl_string = build_windows_pipe_sddl(&user_sid, allowed_sids)?;
        let first_pipe = create_windows_named_pipe_instance(pipe_name, &sddl_string, true)?;
        Ok(Self {
            current_pipe: first_pipe,
            pipe_name: pipe_name.to_string(),
            sddl_string,
        })
    }

    #[cfg(unix)]
    fn bind_unix(ipc_config: &IpcConstants) -> RouteWardResult<Self> {
        use crate::error::ERR_KEY_DAEMON_GROUP_MISSING;
        use std::ffi::CString;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;

        let group_gid = lookup_unix_group_gid(&ipc_config.unix_socket_group).ok_or_else(|| {
            RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_GROUP_MISSING,
                detail: format!(
                    "Unix group '{}' does not exist on this system",
                    ipc_config.unix_socket_group
                ),
            }
        })?;

        let socket_path = PathBuf::from(&ipc_config.unix_socket_path);
        if socket_path.exists() {
            if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_ALREADY_RUNNING,
                    detail: format!(
                        "Another RouteWard daemon is already listening on {}",
                        socket_path.display()
                    ),
                });
            }
            let _ = fs::remove_file(&socket_path);
        }

        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!(
                        "Failed to create socket directory {}: {err}",
                        parent.display()
                    ),
                })?;
                fs::set_permissions(
                    parent,
                    fs::Permissions::from_mode(ipc_config.unix_socket_dir_mode),
                )
                .map_err(|err| RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!("Failed to set permissions on {}: {err}", parent.display()),
                })?;

                if let Some(parent_str) = parent.to_str() {
                    if let Ok(c_parent) = CString::new(parent_str) {
                        // SAFETY: `c_parent` is a valid NUL-terminated path string.
                        let rc = unsafe { libc::chown(c_parent.as_ptr(), 0, group_gid) };
                        if rc != 0 {
                            let err = std::io::Error::last_os_error();
                            return Err(RouteWardError::DaemonError {
                                key: ERR_KEY_DAEMON_IPC_ERROR,
                                detail: format!(
                                    "Failed to chown socket directory {}: {err}",
                                    parent.display()
                                ),
                            });
                        }
                    }
                }
            }
        }

        let listener = tokio::net::UnixListener::bind(&socket_path).map_err(|err| {
            RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "Failed to bind Unix socket {}: {err}",
                    socket_path.display()
                ),
            }
        })?;

        let sock_str = socket_path
            .to_str()
            .ok_or_else(|| RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: "Invalid UTF-8 in Unix socket path".to_string(),
            })?;
        let c_sock = CString::new(sock_str).map_err(|err| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: err.to_string(),
        })?;

        // SAFETY: `c_sock` is a valid NUL-terminated path to the newly bound Unix socket.
        unsafe {
            if libc::chown(c_sock.as_ptr(), 0, group_gid) != 0 {
                let err = std::io::Error::last_os_error();
                let _ = fs::remove_file(&socket_path);
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!(
                        "Failed to chown Unix socket {}: {err}",
                        socket_path.display()
                    ),
                });
            }
            if libc::chmod(c_sock.as_ptr(), ipc_config.unix_socket_mode as libc::mode_t) != 0 {
                let err = std::io::Error::last_os_error();
                let _ = fs::remove_file(&socket_path);
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: format!(
                        "Failed to chmod Unix socket {}: {err}",
                        socket_path.display()
                    ),
                });
            }
        }

        Ok(Self {
            listener,
            socket_path,
        })
    }

    pub async fn accept(&mut self) -> RouteWardResult<(IpcStream, PeerIdentity)> {
        #[cfg(unix)]
        {
            let (stream, _) =
                self.listener
                    .accept()
                    .await
                    .map_err(|err| RouteWardError::DaemonError {
                        key: ERR_KEY_DAEMON_IPC_ERROR,
                        detail: err.to_string(),
                    })?;
            let peer = query_unix_peer_cred(&stream)?;
            Ok((
                IpcStream {
                    inner: IpcStreamInner::Unix(stream),
                },
                peer,
            ))
        }
        #[cfg(windows)]
        {
            self.current_pipe
                .connect()
                .await
                .map_err(|err| RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_IPC_ERROR,
                    detail: err.to_string(),
                })?;

            let next_pipe =
                create_windows_named_pipe_instance(&self.pipe_name, &self.sddl_string, false)?;
            let connected_pipe = std::mem::replace(&mut self.current_pipe, next_pipe);

            Ok((
                IpcStream {
                    inner: IpcStreamInner::NamedPipeServer(connected_pipe),
                },
                PeerIdentity {
                    pid: None,
                    uid: None,
                    gid: None,
                },
            ))
        }
    }
}

#[cfg(unix)]
impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

pub async fn connect_ipc_stream(ipc_config: &IpcConstants) -> RouteWardResult<IpcStream> {
    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(&ipc_config.unix_socket_path)
            .await
            .map_err(|err| RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_DISCONNECTED,
                detail: format!("Cannot connect to {}: {err}", ipc_config.unix_socket_path),
            })?;
        Ok(IpcStream {
            inner: IpcStreamInner::Unix(stream),
        })
    }
    #[cfg(windows)]
    {
        connect_windows_named_pipe(&ipc_config.windows_pipe_name).await
    }
}

/// Checks whether a `routeward daemon` instance is currently listening on the configured OS IPC endpoint.
pub fn is_daemon_ipc_active(ipc_config: &IpcConstants) -> bool {
    #[cfg(unix)]
    {
        let socket_path = std::path::Path::new(&ipc_config.unix_socket_path);
        if !socket_path.exists() {
            return false;
        }
        match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(_stream) => true,
            Err(err) => err.kind() == std::io::ErrorKind::PermissionDenied,
        }
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
        };

        match ServerOptions::new()
            .first_pipe_instance(true)
            .create(&ipc_config.windows_pipe_name)
        {
            Ok(temp_server) => {
                drop(temp_server);
                false
            }
            Err(err) => {
                let raw = err.raw_os_error().unwrap_or(0) as u32;
                if raw == ERROR_ACCESS_DENIED || raw == ERROR_PIPE_BUSY {
                    true
                } else {
                    match ClientOptions::new().open(&ipc_config.windows_pipe_name) {
                        Ok(_) => true,
                        Err(c_err) => {
                            let c_raw = c_err.raw_os_error().unwrap_or(0) as u32;
                            c_raw != ERROR_FILE_NOT_FOUND
                        }
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
pub async fn connect_windows_named_pipe(pipe_name: &str) -> RouteWardResult<IpcStream> {
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    const MAX_BUSY_RETRIES: usize = 30;
    const BUSY_RETRY_DELAY_MS: u64 = 10;

    for attempt in 0..=MAX_BUSY_RETRIES {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => {
                return Ok(IpcStream {
                    inner: IpcStreamInner::NamedPipeClient(client),
                });
            }
            Err(err) => {
                let raw = err.raw_os_error().unwrap_or(0) as u32;
                if raw == ERROR_PIPE_BUSY && attempt < MAX_BUSY_RETRIES {
                    tokio::time::sleep(Duration::from_millis(BUSY_RETRY_DELAY_MS)).await;
                    continue;
                }
                return Err(RouteWardError::DaemonError {
                    key: ERR_KEY_DAEMON_DISCONNECTED,
                    detail: format!("Cannot open named pipe {pipe_name}: {err}"),
                });
            }
        }
    }

    Err(RouteWardError::DaemonError {
        key: ERR_KEY_DAEMON_DISCONNECTED,
        detail: format!("Cannot open named pipe {pipe_name}: pipe busy after retries"),
    })
}

#[cfg(unix)]
fn lookup_unix_group_gid(group_name: &str) -> Option<libc::gid_t> {
    use std::ffi::CString;
    let c_name = CString::new(group_name).ok()?;
    // SAFETY: `c_name` is a valid NUL-terminated string passed to POSIX `getgrnam`.
    unsafe {
        let grp_ptr = libc::getgrnam(c_name.as_ptr());
        if grp_ptr.is_null() {
            None
        } else {
            Some((*grp_ptr).gr_gid)
        }
    }
}

#[cfg(unix)]
fn query_unix_peer_cred(stream: &tokio::net::UnixStream) -> RouteWardResult<PeerIdentity> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: `fd` is a valid connected Unix domain socket descriptor and `cred` is properly sized.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: format!(
                "SO_PEERCRED verification failed: {}",
                std::io::Error::last_os_error()
            ),
        });
    }

    Ok(PeerIdentity {
        pid: if cred.pid > 0 {
            Some(cred.pid as u32)
        } else {
            None
        },
        uid: Some(cred.uid),
        gid: Some(cred.gid),
    })
}

#[cfg(windows)]
pub fn current_user_sid_string() -> RouteWardResult<String> {
    query_current_user_sid_string()
}

fn is_forbidden_broad_sid(sid_upper: &str) -> bool {
    matches!(
        sid_upper,
        "WD" | "AU"
            | "BU"
            | "AN"
            | "BG"
            | "AC"
            | "IU"
            | "NU"
            | "SU"
            | "DU"
            | "S-1-1-0"
            | "S-1-5-11"
            | "S-1-5-32-545"
            | "S-1-5-7"
            | "S-1-5-32-546"
            | "S-1-15-2-1"
            | "S-1-5-4"
            | "S-1-5-2"
            | "S-1-5-6"
            | "S-1-5-32-555"
    ) || sid_upper.starts_with("S-1-16-")
}

/// Validates and canonicalizes an explicit SID passed to `--allow-sid`, rejecting SDDL
/// metacharacters, malformed strings, and broad/unprivileged principals.
pub fn validate_and_canonicalize_allowed_sid(raw: &str) -> RouteWardResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains([';', '(', ')', ':'])
        || trimmed.chars().any(char::is_whitespace)
    {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: format!("Invalid SID syntax rejected for pipe ACL: '{raw}'"),
        });
    }

    let upper = trimmed.to_ascii_uppercase();
    if is_forbidden_broad_sid(&upper) {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: format!("Refusing overly permissive principal SID '{trimmed}' in pipe ACL"),
        });
    }

    let mut subauths = trimmed
        .strip_prefix("S-1-")
        .or_else(|| trimmed.strip_prefix("s-1-"));
    let parts_ok = match subauths.take() {
        Some(rest) if !rest.is_empty() => {
            let segs: Vec<&str> = rest.split('-').collect();
            segs.len() >= 2
                && segs
                    .iter()
                    .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()))
        }
        _ => false,
    };
    if !parts_ok {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: format!("Allowed SID must be a canonical numeric S-1-... SID, got '{raw}'"),
        });
    }

    #[cfg(windows)]
    {
        let canonical = canonicalize_windows_sid(trimmed)?;
        let canon_upper = canonical.to_ascii_uppercase();
        if is_forbidden_broad_sid(&canon_upper) {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "Refusing overly permissive canonical SID '{canonical}' in pipe ACL"
                ),
            });
        }
        Ok(canonical)
    }

    #[cfg(not(windows))]
    {
        Ok(upper)
    }
}

#[cfg(windows)]
fn canonicalize_windows_sid(sid_str: &str) -> RouteWardResult<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSidToSidW,
    };
    use windows_sys::Win32::Security::{IsValidSid, PSID};

    let mut wide: Vec<u16> = sid_str.encode_utf16().collect();
    wide.push(0);
    unsafe {
        let mut psid: PSID = null_mut();
        if ConvertStringSidToSidW(wide.as_ptr(), &mut psid) == 0 || psid.is_null() {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "ConvertStringSidToSidW rejected '{sid_str}': {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        let valid = IsValidSid(psid) != 0;
        let mut out_ptr: *mut u16 = null_mut();
        let conv_ok =
            valid && ConvertSidToStringSidW(psid, &mut out_ptr) != 0 && !out_ptr.is_null();
        let canonical = if conv_ok {
            let mut len = 0usize;
            while *out_ptr.add(len) != 0 {
                len += 1;
            }
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(
                out_ptr, len,
            )))
        } else {
            None
        };
        if !out_ptr.is_null() {
            let _ = LocalFree(out_ptr as *mut _);
        }
        let _ = LocalFree(psid as *mut _);
        canonical.ok_or_else(|| RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_IPC_ERROR,
            detail: format!("SID failed Windows validation: '{sid_str}'"),
        })
    }
}

/// Builds a strict Protected DACL (`D:P`) SDDL string granting full control to `SYSTEM` (`SY`)
/// and `Administrators` (`BA`), plus `GRGW` to the launching user SID and validated extra SIDs.
pub fn build_windows_pipe_sddl(
    current_user_sid: &str,
    extra_sids: &[String],
) -> RouteWardResult<String> {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    let mut seen: Vec<String> = vec!["S-1-5-18".to_string(), "S-1-5-32-544".to_string()];

    let launch_canon = validate_and_canonicalize_allowed_sid(current_user_sid)?;
    if !seen.iter().any(|s| s.eq_ignore_ascii_case(&launch_canon)) {
        sddl.push_str(&format!("(A;;GRGW;;;{launch_canon})"));
        seen.push(launch_canon);
    }

    for raw in extra_sids {
        let canon = validate_and_canonicalize_allowed_sid(raw)?;
        if !seen.iter().any(|s| s.eq_ignore_ascii_case(&canon)) {
            sddl.push_str(&format!("(A;;GRGW;;;{canon})"));
            seen.push(canon);
        }
    }

    Ok(sddl)
}

#[cfg(windows)]
fn query_current_user_sid_string() -> RouteWardResult<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "OpenProcessToken failed: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            let _ = CloseHandle(token);
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: "GetTokenInformation returned zero length".to_string(),
            });
        }

        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        ) == 0
        {
            let err = std::io::Error::last_os_error();
            let _ = CloseHandle(token);
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!("GetTokenInformation(TokenUser) failed: {err}"),
            });
        }
        let _ = CloseHandle(token);

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid_wide_ptr: *mut u16 = null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_wide_ptr) == 0
            || sid_wide_ptr.is_null()
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "ConvertSidToStringSidW failed: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        let mut len = 0usize;
        while *sid_wide_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_wide_ptr, len);
        let sid_string = String::from_utf16_lossy(slice);
        let _ = LocalFree(sid_wide_ptr as *mut _);

        Ok(sid_string)
    }
}

#[cfg(windows)]
fn create_windows_named_pipe_instance(
    pipe_name: &str,
    sddl_string: &str,
    is_first: bool,
) -> RouteWardResult<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ptr::null_mut;
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let mut sddl_wide: Vec<u16> = sddl_string.encode_utf16().collect();
    sddl_wide.push(0);

    unsafe {
        let mut sd_ptr: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            null_mut(),
        ) == 0
            || sd_ptr.is_null()
        {
            return Err(RouteWardError::DaemonError {
                key: ERR_KEY_DAEMON_IPC_ERROR,
                detail: format!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr,
            bInheritHandle: 0,
        };

        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(is_first)
            .reject_remote_clients(true)
            .access_inbound(true)
            .access_outbound(true);

        let create_res = opts.create_with_security_attributes_raw(
            pipe_name,
            &mut sa as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void,
        );

        let _ = LocalFree(sd_ptr);

        match create_res {
            Ok(server) => Ok(server),
            Err(err) => {
                let raw = err.raw_os_error().unwrap_or(0) as u32;
                if is_first && (raw == ERROR_ACCESS_DENIED || raw == ERROR_PIPE_BUSY) {
                    Err(RouteWardError::DaemonError {
                        key: ERR_KEY_DAEMON_ALREADY_RUNNING,
                        detail: format!(
                            "Named pipe {pipe_name} is already owned by another daemon instance ({err})"
                        ),
                    })
                } else {
                    Err(RouteWardError::DaemonError {
                        key: ERR_KEY_DAEMON_IPC_ERROR,
                        detail: format!("Failed to create named pipe {pipe_name}: {err}"),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_broad_principals_and_sddl_injection_in_allow_sid() {
        for bad in [
            "",
            "WD",
            "AU",
            "BU",
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-32-545",
            "S-1-5-7",
            "S-1-15-2-1",
            "S-1-16-8192",
            "S-1-5-21-1-2-3-1001)(A;;GA;;;WD",
            "S-1-5-21-1-2-3-1001;AU",
            "not-a-sid",
        ] {
            assert!(
                validate_and_canonicalize_allowed_sid(bad).is_err(),
                "Expected SID '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn builds_deduplicated_protected_sddl_with_valid_user_sids() {
        let extra = vec![
            "S-1-5-21-1000-2000-3000-1005".to_string(),
            "S-1-5-18".to_string(),
            "S-1-5-21-1000-2000-3000-1005".to_string(),
        ];
        let sddl = build_windows_pipe_sddl("S-1-5-18", &extra).expect("valid SDDL");
        assert_eq!(
            sddl,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1000-2000-3000-1005)"
        );

        let interactive = build_windows_pipe_sddl(
            "S-1-5-21-111-222-333-1001",
            &["S-1-5-21-111-222-333-1002".to_string()],
        )
        .expect("interactive user SDDL");
        assert_eq!(
            interactive,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-111-222-333-1001)(A;;GRGW;;;S-1-5-21-111-222-333-1002)"
        );
    }
}
