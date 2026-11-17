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
#[cfg(windows)]
use crate::error::{ERR_KEY_DAEMON_PIPE_SQUATTED, ERR_KEY_DAEMON_UNTRUSTED_PIPE_OWNER};
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
        Self::bind_windows_inner(pipe_name, &[], false)
    }

    /// Production bind: the pipe is owned by `BUILTIN\Administrators` so clients can verify who
    /// serves it, and a squatted pipe name is reported distinctly from a running daemon.
    #[cfg(windows)]
    pub fn bind_windows_with_allowed_sids(
        pipe_name: &str,
        allowed_sids: &[String],
    ) -> RouteWardResult<Self> {
        Self::bind_windows_inner(pipe_name, allowed_sids, true)
    }

    #[cfg(windows)]
    fn bind_windows_inner(
        pipe_name: &str,
        allowed_sids: &[String],
        production: bool,
    ) -> RouteWardResult<Self> {
        let user_sid = query_current_user_sid_string()?;
        // Test binds run the server as an unelevated user, who must keep the right to create the
        // next pipe instance (`GRGW`); production servers run elevated (BA/SY hold full control).
        let launch_mask = if production {
            PIPE_USER_ACCESS_MASK_SDDL
        } else {
            WINDOWS_TEST_SERVER_USER_MASK_SDDL
        };
        let mut sddl_string =
            build_windows_pipe_sddl_with_launch_mask(&user_sid, allowed_sids, launch_mask)?;
        if production {
            sddl_string.insert_str(0, WINDOWS_PIPE_OWNER_SDDL);
        }
        let first_pipe =
            create_windows_named_pipe_instance(pipe_name, &sddl_string, true, production)?;
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

            let next_pipe = create_windows_named_pipe_instance(
                &self.pipe_name,
                &self.sddl_string,
                false,
                false,
            )?;
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
        use tokio::net::windows::named_pipe::ServerOptions;
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
                    match open_pipe_handle_raw(
                        &ipc_config.windows_pipe_name,
                        PIPE_CLIENT_DESIRED_ACCESS,
                    ) {
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
    use std::os::windows::io::IntoRawHandle;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::NamedPipeClient;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    const MAX_BUSY_RETRIES: usize = 30;
    const BUSY_RETRY_DELAY_MS: u64 = 10;

    for attempt in 0..=MAX_BUSY_RETRIES {
        match open_pipe_handle_raw(pipe_name, PIPE_CLIENT_DESIRED_ACCESS) {
            Ok(handle) => {
                // The owner is verified before any byte is sent on the stream.
                verify_pipe_server_owner(&handle, pipe_name)?;
                // SAFETY: the raw handle is a valid overlapped pipe client handle whose
                // ownership is transferred to tokio here.
                let client = unsafe { NamedPipeClient::from_raw_handle(handle.into_raw_handle()) }
                    .map_err(|err| RouteWardError::DaemonError {
                        key: ERR_KEY_DAEMON_DISCONNECTED,
                        detail: format!("Cannot register named pipe {pipe_name} with tokio: {err}"),
                    })?;
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

/// Access mask granted to the launching user and extra SIDs on the pipe:
/// `FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES` (0x12019b).
/// Unlike `GENERIC_WRITE` it omits `FILE_APPEND_DATA`, which on a pipe equals
/// `FILE_CREATE_PIPE_INSTANCE`, so an allowed non-admin user cannot create its own instance.
const PIPE_USER_ACCESS_MASK_SDDL: &str = "0x12019b";

/// Owner prefix prepended to the production pipe SDDL (`BUILTIN\Administrators`). Test binds run
/// non-elevated and cannot assign this owner, so they omit it.
#[cfg(windows)]
const WINDOWS_PIPE_OWNER_SDDL: &str = "O:BA";

/// Launching-user mask for test binds only (see `bind_windows_inner`).
#[cfg(windows)]
const WINDOWS_TEST_SERVER_USER_MASK_SDDL: &str = "GRGW";

/// Builds a strict Protected DACL (`D:P`) SDDL string granting full control to `SYSTEM` (`SY`)
/// and `Administrators` (`BA`), plus [`PIPE_USER_ACCESS_MASK_SDDL`] to the launching user SID and
/// validated extra SIDs.
pub fn build_windows_pipe_sddl(
    current_user_sid: &str,
    extra_sids: &[String],
) -> RouteWardResult<String> {
    build_windows_pipe_sddl_with_launch_mask(
        current_user_sid,
        extra_sids,
        PIPE_USER_ACCESS_MASK_SDDL,
    )
}

/// Same as [`build_windows_pipe_sddl`] with an explicit access mask for the launching user ACE.
fn build_windows_pipe_sddl_with_launch_mask(
    current_user_sid: &str,
    extra_sids: &[String],
    launch_user_mask: &str,
) -> RouteWardResult<String> {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    let mut seen: Vec<String> = vec!["S-1-5-18".to_string(), "S-1-5-32-544".to_string()];

    let launch_canon = validate_and_canonicalize_allowed_sid(current_user_sid)?;
    if !seen.iter().any(|s| s.eq_ignore_ascii_case(&launch_canon)) {
        sddl.push_str(&format!("(A;;{launch_user_mask};;;{launch_canon})"));
        seen.push(launch_canon);
    }

    for raw in extra_sids {
        let canon = validate_and_canonicalize_allowed_sid(raw)?;
        if !seen.iter().any(|s| s.eq_ignore_ascii_case(&canon)) {
            sddl.push_str(&format!("(A;;{PIPE_USER_ACCESS_MASK_SDDL};;;{canon})"));
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

/// SID of `BUILTIN\Administrators`.
#[cfg(windows)]
const SID_BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";
/// SID of `NT AUTHORITY\SYSTEM` (LocalSystem).
#[cfg(windows)]
const SID_LOCAL_SYSTEM: &str = "S-1-5-18";
/// Desired access of the pipe client handle: `FILE_GENERIC_READ | FILE_WRITE_DATA |
/// FILE_WRITE_ATTRIBUTES` (0x0012018b). It is a subset of [`PIPE_USER_ACCESS_MASK_SDDL`] and
/// deliberately omits `FILE_APPEND_DATA` (pipe instance creation), which the server DACL denies.
#[cfg(windows)]
const PIPE_CLIENT_DESIRED_ACCESS: u32 = windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
    | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA
    | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES;

/// Who owns a pipe, as seen by a client before it sends anything.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipeOwnerKind {
    Administrators,
    LocalSystem,
    CurrentUser,
    Other,
}

/// Pure classification of a pipe owner SID relative to the current process user SID.
#[cfg(windows)]
pub(crate) fn classify_pipe_owner(owner_sid: &str, current_user_sid: &str) -> PipeOwnerKind {
    if owner_sid.eq_ignore_ascii_case(SID_BUILTIN_ADMINISTRATORS) {
        PipeOwnerKind::Administrators
    } else if owner_sid.eq_ignore_ascii_case(SID_LOCAL_SYSTEM) {
        PipeOwnerKind::LocalSystem
    } else if owner_sid.eq_ignore_ascii_case(current_user_sid) {
        PipeOwnerKind::CurrentUser
    } else {
        PipeOwnerKind::Other
    }
}

/// Pure accept/reject decision. Clients accept Administrators, SYSTEM and their own user (another
/// user cannot assign our SID as owner; a same-user squatter is not a security boundary). The
/// daemon-side squat diagnostic does not trust the current user (`allow_current_user = false`).
#[cfg(windows)]
pub(crate) fn is_trusted_pipe_owner(kind: PipeOwnerKind, allow_current_user: bool) -> bool {
    match kind {
        PipeOwnerKind::Administrators | PipeOwnerKind::LocalSystem => true,
        PipeOwnerKind::CurrentUser => allow_current_user,
        PipeOwnerKind::Other => false,
    }
}

/// Opens an existing pipe with a raw `CreateFileW`. `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`
/// is mandatory: without it a squatting server could impersonate the client.
#[cfg(windows)]
fn open_pipe_handle_raw(
    pipe_name: &str,
    desired_access: u32,
) -> std::io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };

    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string; no security attributes or template.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `handle` is a valid handle just returned by CreateFileW and owned by nobody else.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

/// Reads the owner SID (string form) of a kernel object handle.
#[cfg(windows)]
fn handle_owner_sid_string(handle: &std::os::windows::io::OwnedHandle) -> std::io::Result<String> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: out-pointers are valid; `owner` points into `descriptor`, freed below.
    let rc = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle() as _,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    if owner.is_null() {
        // SAFETY: `descriptor` was allocated by GetSecurityInfo.
        unsafe { LocalFree(descriptor as _) };
        return Err(std::io::Error::other("pipe has no owner SID"));
    }
    let mut out_ptr: *mut u16 = null_mut();
    // SAFETY: `owner` is a valid SID inside `descriptor`; `out_ptr` is freed with LocalFree.
    let result = unsafe {
        if ConvertSidToStringSidW(owner, &mut out_ptr) == 0 || out_ptr.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            let mut len = 0usize;
            while *out_ptr.add(len) != 0 {
                len += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(out_ptr, len));
            LocalFree(out_ptr as _);
            Ok(text)
        }
    };
    // SAFETY: `descriptor` was allocated by GetSecurityInfo and `owner` is no longer used.
    unsafe { LocalFree(descriptor as _) };
    result
}

/// Process id of the server end of a pipe, for diagnostics.
#[cfg(windows)]
fn pipe_server_pid(handle: &std::os::windows::io::OwnedHandle) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let mut pid: u32 = 0;
    // SAFETY: valid pipe handle and out-pointer.
    let ok = unsafe { GetNamedPipeServerProcessId(handle.as_raw_handle() as _, &mut pid) };
    (ok != 0).then_some(pid)
}

/// Verifies, before any byte is sent, that the pipe server is owned by a trusted principal.
#[cfg(windows)]
fn verify_pipe_server_owner(
    handle: &std::os::windows::io::OwnedHandle,
    pipe_name: &str,
) -> RouteWardResult<()> {
    let pid_text = pipe_server_pid(handle)
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let untrusted = |detail: String| RouteWardError::DaemonError {
        key: ERR_KEY_DAEMON_UNTRUSTED_PIPE_OWNER,
        detail,
    };
    let owner = handle_owner_sid_string(handle).map_err(|err| {
        untrusted(format!(
            "Cannot read the owner of named pipe {pipe_name} (server pid {pid_text}): {err}"
        ))
    })?;
    let current = query_current_user_sid_string()?;
    let kind = classify_pipe_owner(&owner, &current);
    if is_trusted_pipe_owner(kind, true) {
        Ok(())
    } else {
        Err(untrusted(format!(
            "Named pipe {pipe_name} is owned by untrusted SID {owner} (server pid {pid_text})"
        )))
    }
}

/// Called when the first-instance bind is denied: opens the pipe as a client and reports a
/// squatter when its owner is neither Administrators nor SYSTEM. `None` means "cannot tell" or
/// "owner is trusted", and the caller reports an already running daemon.
#[cfg(windows)]
fn diagnose_pipe_squatter(pipe_name: &str) -> Option<RouteWardError> {
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;

    let handle = open_pipe_handle_raw(pipe_name, READ_CONTROL).ok()?;
    let owner = handle_owner_sid_string(&handle).ok()?;
    let current = query_current_user_sid_string().ok()?;
    let kind = classify_pipe_owner(&owner, &current);
    if is_trusted_pipe_owner(kind, false) {
        return None;
    }
    let pid_text = pipe_server_pid(&handle)
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    Some(RouteWardError::DaemonError {
        key: ERR_KEY_DAEMON_PIPE_SQUATTED,
        detail: format!(
            "Named pipe {pipe_name} is held by an untrusted owner SID {owner} (server pid {pid_text})"
        ),
    })
}

#[cfg(windows)]
fn create_windows_named_pipe_instance(
    pipe_name: &str,
    sddl_string: &str,
    is_first: bool,
    diagnose_squat: bool,
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
                    if diagnose_squat {
                        if let Some(squatted) = diagnose_pipe_squatter(pipe_name) {
                            return Err(squatted);
                        }
                    }
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
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;S-1-5-21-1000-2000-3000-1005)"
        );
        assert!(
            !sddl.contains("GRGW") && !sddl.contains("O:"),
            "user ACE must not use GENERIC_WRITE and the DACL string carries no owner"
        );

        let interactive = build_windows_pipe_sddl(
            "S-1-5-21-111-222-333-1001",
            &["S-1-5-21-111-222-333-1002".to_string()],
        )
        .expect("interactive user SDDL");
        assert_eq!(
            interactive,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;S-1-5-21-111-222-333-1001)(A;;0x12019b;;;S-1-5-21-111-222-333-1002)"
        );
    }

    #[test]
    fn user_pipe_access_mask_excludes_create_pipe_instance_bit() {
        let mask = u32::from_str_radix(PIPE_USER_ACCESS_MASK_SDDL.trim_start_matches("0x"), 16)
            .expect("hex mask");
        const FILE_CREATE_PIPE_INSTANCE: u32 = 0x4;
        assert_eq!(mask, 0x0012_019b);
        assert_eq!(mask & FILE_CREATE_PIPE_INSTANCE, 0);
    }

    #[cfg(windows)]
    #[test]
    fn pipe_owner_decision_accepts_admin_system_and_current_user_only() {
        let me = "S-1-5-21-111-222-333-1001";
        let cases = [
            ("S-1-5-32-544", PipeOwnerKind::Administrators, true, true),
            ("S-1-5-18", PipeOwnerKind::LocalSystem, true, true),
            (me, PipeOwnerKind::CurrentUser, true, false),
            (
                "s-1-5-21-111-222-333-1001",
                PipeOwnerKind::CurrentUser,
                true,
                false,
            ),
            (
                "S-1-5-21-111-222-333-1002",
                PipeOwnerKind::Other,
                false,
                false,
            ),
            ("S-1-1-0", PipeOwnerKind::Other, false, false),
        ];
        for (sid, kind, client_ok, daemon_ok) in cases {
            assert_eq!(classify_pipe_owner(sid, me), kind, "kind for {sid}");
            assert_eq!(is_trusted_pipe_owner(kind, true), client_ok, "client {sid}");
            assert_eq!(
                is_trusted_pipe_owner(kind, false),
                daemon_ok,
                "daemon {sid}"
            );
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn client_accepts_test_pipe_created_by_current_user() {
        let pipe_name = format!(r"\\.\pipe\routeward-owner-test-{}", std::process::id());
        let mut server = IpcServer::bind_windows(&pipe_name).expect("bind test pipe");
        let accept = tokio::spawn(async move {
            let _ = server.accept().await;
        });
        let stream = connect_windows_named_pipe(&pipe_name).await;
        assert!(stream.is_ok(), "current-user owned pipe must be accepted");
        drop(stream);
        let _ = accept.await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_peer_cred_reports_the_current_process_identity() {
        let (left, right) = tokio::net::UnixStream::pair().expect("socketpair");
        // SAFETY: geteuid/getegid/getpid have no preconditions and cannot fail.
        let (uid, gid, pid) = unsafe { (libc::geteuid(), libc::getegid(), libc::getpid()) };

        for stream in [&left, &right] {
            let peer = query_unix_peer_cred(stream).expect("SO_PEERCRED on a socketpair");
            assert_eq!(peer.uid, Some(uid));
            assert_eq!(peer.gid, Some(gid));
            assert_eq!(peer.pid, Some(pid as u32));
        }
    }
}
