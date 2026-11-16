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

use super::*;

/// Binary-compatible representation of WinDivert 2.2 `WINDIVERT_ADDRESS` (80 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    pub flags_bitfield: u64,
    pub union_data: [u8; 64],
}

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags_bitfield: 0,
            union_data: [0u8; 64],
        }
    }
}

/// Offset of the IP protocol byte inside the `Socket` variant of the address union.
const SOCKET_PROTOCOL_OFFSET: usize = 56;
/// The `Event` field occupies bits 8..16 of the first flags word.
const EVENT_SHIFT: u32 = 8;
const EVENT_MASK: u64 = 0xFF;

/// `WINDIVERT_EVENT_SOCKET_BIND`: a socket was bound to a local address.
#[cfg(test)]
pub const WINDIVERT_EVENT_SOCKET_BIND: u8 = 3;
/// `WINDIVERT_EVENT_SOCKET_CONNECT`: a socket connect was initiated (the owner is still alive).
#[cfg(test)]
pub const WINDIVERT_EVENT_SOCKET_CONNECT: u8 = 4;
/// `WINDIVERT_EVENT_SOCKET_LISTEN`: a socket started listening.
#[cfg(test)]
pub const WINDIVERT_EVENT_SOCKET_LISTEN: u8 = 5;
/// `WINDIVERT_EVENT_SOCKET_ACCEPT`: a socket accepted a connection.
#[cfg(test)]
pub const WINDIVERT_EVENT_SOCKET_ACCEPT: u8 = 6;
/// `WINDIVERT_EVENT_SOCKET_CLOSE`: the socket described by an event was closed.
pub const WINDIVERT_EVENT_SOCKET_CLOSE: u8 = 7;

/// Decoded `WINDIVERT_LAYER_SOCKET` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEvent {
    pub pid: u32,
    pub local_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
    pub ipv6: bool,
    /// `WINDIVERT_EVENT_SOCKET_*` value.
    pub kind: u8,
}

impl SocketEvent {
    /// Returns `true` when the event reports the socket being closed, so its previous owner must
    /// be forgotten (the port may be reused by another process).
    pub fn is_close(&self) -> bool {
        self.kind == WINDIVERT_EVENT_SOCKET_CLOSE
    }
}

impl WinDivertAddress {
    /// Sets or clears the `Outbound` bit (bit 17) in `WINDIVERT_ADDRESS`.
    pub fn set_outbound(&mut self, outbound: bool) {
        if outbound {
            self.flags_bitfield |= BIT_OUTBOUND;
        } else {
            self.flags_bitfield &= !BIT_OUTBOUND;
        }
    }

    /// Returns `true` if the `Outbound` bit (bit 17) is set.
    pub fn is_outbound(&self) -> bool {
        (self.flags_bitfield & BIT_OUTBOUND) != 0
    }

    /// Clears the `Impostor` bit (bit 19).
    pub fn clear_impostor(&mut self) {
        self.flags_bitfield &= !BIT_IMPOSTOR;
    }

    /// Decodes a `WINDIVERT_LAYER_SOCKET` event: owner, local port, protocol, address family and
    /// event kind (`WINDIVERT_EVENT_SOCKET_BIND`=3, `CONNECT`=4, `LISTEN`=5, `ACCEPT`=6, `CLOSE`=7; 0..2 are the network and flow events).
    pub fn socket_event(&self) -> SocketEvent {
        let (pid, local_port) = self.socket_pid_and_local_port();
        SocketEvent {
            pid,
            local_port,
            protocol: self.union_data[SOCKET_PROTOCOL_OFFSET],
            ipv6: (self.flags_bitfield & BIT_IPV6) != 0,
            kind: ((self.flags_bitfield >> EVENT_SHIFT) & EVENT_MASK) as u8,
        }
    }

    /// Extracts `(process_id, local_port)` from a `WINDIVERT_LAYER_SOCKET` event.
    pub fn socket_pid_and_local_port(&self) -> (u32, u16) {
        let pid = u32::from_ne_bytes([
            self.union_data[16],
            self.union_data[17],
            self.union_data[18],
            self.union_data[19],
        ]);
        let local_port = u16::from_ne_bytes([self.union_data[52], self.union_data[53]]);
        (pid, local_port)
    }
}

#[cfg(windows)]
pub(super) type FnWinDivertOpen = unsafe extern "system" fn(
    filter: *const c_char,
    layer: u32,
    priority: i16,
    flags: u64,
) -> *mut c_void;

#[cfg(windows)]
pub(super) type FnWinDivertRecv = unsafe extern "system" fn(
    handle: *mut c_void,
    p_packet: *mut c_void,
    packet_len: u32,
    p_recv_len: *mut u32,
    p_addr: *mut WinDivertAddress,
) -> i32;

#[cfg(windows)]
pub(super) type FnWinDivertSend = unsafe extern "system" fn(
    handle: *mut c_void,
    p_packet: *const c_void,
    packet_len: u32,
    p_send_len: *mut u32,
    p_addr: *const WinDivertAddress,
) -> i32;

#[cfg(windows)]
pub(super) type FnWinDivertShutdown =
    unsafe extern "system" fn(handle: *mut c_void, how: u32) -> i32;

#[cfg(windows)]
pub(super) type FnWinDivertClose = unsafe extern "system" fn(handle: *mut c_void) -> i32;

#[cfg(windows)]
pub(super) type FnWinDivertHelperCalcChecksums = unsafe extern "system" fn(
    p_packet: *mut c_void,
    packet_len: u32,
    p_addr: *mut WinDivertAddress,
    flags: u64,
) -> i32;

#[cfg(windows)]
#[derive(Clone, Copy)]
pub(super) struct WinDivertApi {
    pub(super) open: FnWinDivertOpen,
    pub(super) recv: FnWinDivertRecv,
    pub(super) send: FnWinDivertSend,
    pub(super) shutdown: FnWinDivertShutdown,
    pub(super) close: FnWinDivertClose,
    pub(super) calc_checksums: FnWinDivertHelperCalcChecksums,
}

#[cfg(windows)]
fn strip_verbatim_prefix(path: &Path) -> std::path::PathBuf {
    let raw = path.to_string_lossy();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        std::path::PathBuf::from(format!(r"\\{unc}"))
    } else if let Some(plain) = raw.strip_prefix(r"\\?\") {
        std::path::PathBuf::from(plain)
    } else {
        path.to_path_buf()
    }
}

#[cfg(windows)]
fn push_unique_candidate(candidates: &mut Vec<String>, path: &Path) {
    let normalized = strip_verbatim_prefix(path).to_string_lossy().into_owned();
    if normalized.is_empty() {
        return;
    }
    let already_present = candidates.iter().any(|existing| {
        if cfg!(windows) {
            existing.eq_ignore_ascii_case(&normalized)
        } else {
            existing == &normalized
        }
    });
    if !already_present {
        candidates.push(normalized);
    }
}

#[cfg(windows)]
fn collect_windivert_candidates(
    search_paths: &[String],
    exe_dir: Option<&Path>,
    env_override: Option<&str>,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(env_path) = env_override {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            push_unique_candidate(&mut candidates, Path::new(trimmed));
        }
    }
    // Only absolute paths under the executable directory are trusted: a bare or CWD-relative
    // "WinDivert.dll" would let a planted DLL run with administrator rights.
    let Some(exe_dir) = exe_dir else {
        return candidates;
    };
    let exe_dir = strip_verbatim_prefix(exe_dir);
    for raw in search_paths {
        let rel_or_abs = Path::new(raw);
        let candidate = if rel_or_abs.is_absolute() {
            rel_or_abs.to_path_buf()
        } else {
            exe_dir.join(rel_or_abs)
        };
        if is_trusted_dll_path(&candidate, &exe_dir) {
            push_unique_candidate(&mut candidates, &candidate);
        }
    }
    candidates
}

#[cfg(windows)]
/// Returns `true` when `path` is absolute, free of `..` components and located under `exe_dir`.
fn is_trusted_dll_path(path: &Path, exe_dir: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        && path.starts_with(exe_dir)
}

#[cfg(windows)]
impl WinDivertInterceptor {
    #[cfg(windows)]
    pub(super) fn load_dynamic_api(search_paths: &[String]) -> RouteWardResult<WinDivertApi> {
        use windows_sys::Win32::System::LibraryLoader::{
            GetProcAddress, LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH,
        };

        // The override variable can be inherited from a lower-privileged user environment, so
        // release builds (which run elevated) ignore it entirely.
        #[cfg(debug_assertions)]
        let env_override = std::env::var(ENV_WINDIVERT_DLL_PATH).ok();
        #[cfg(not(debug_assertions))]
        let env_override: Option<String> = None;
        let exe_path = std::env::current_exe().ok();
        let exe_dir = exe_path.as_deref().and_then(|p| p.parent());
        let candidates =
            collect_windivert_candidates(search_paths, exe_dir, env_override.as_deref());

        let mut module_handle = std::ptr::null_mut();
        let mut loaded_from = String::new();

        for candidate in &candidates {
            let resolved = Path::new(candidate)
                .canonicalize()
                .map(|p| strip_verbatim_prefix(&p))
                .unwrap_or_else(|_| strip_verbatim_prefix(Path::new(candidate)));
            let wide: Vec<u16> = resolved
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let flags = if resolved.is_absolute() {
                LOAD_WITH_ALTERED_SEARCH_PATH
            } else {
                0
            };
            let handle = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), flags) };
            if !handle.is_null() {
                module_handle = handle;
                loaded_from = resolved.to_string_lossy().into_owned();
                break;
            }
        }

        if module_handle.is_null() {
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_DRIVER,
                detail: format!("Searched paths: {}", candidates.join(", ")),
            });
        }

        unsafe {
            let open_ptr = GetProcAddress(module_handle, c"WinDivertOpen".as_ptr() as *const u8)
                .ok_or_else(|| RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_DRIVER,
                    detail: format!("Missing WinDivertOpen in {loaded_from}"),
                })?;
            let recv_ptr = GetProcAddress(module_handle, c"WinDivertRecv".as_ptr() as *const u8)
                .ok_or_else(|| RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_DRIVER,
                    detail: format!("Missing WinDivertRecv in {loaded_from}"),
                })?;
            let send_ptr = GetProcAddress(module_handle, c"WinDivertSend".as_ptr() as *const u8)
                .ok_or_else(|| RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_DRIVER,
                    detail: format!("Missing WinDivertSend in {loaded_from}"),
                })?;
            let shutdown_ptr =
                GetProcAddress(module_handle, c"WinDivertShutdown".as_ptr() as *const u8)
                    .ok_or_else(|| RouteWardError::InterceptorError {
                        key: ERR_KEY_INTERCEPTOR_DRIVER,
                        detail: format!("Missing WinDivertShutdown in {loaded_from}"),
                    })?;
            let close_ptr = GetProcAddress(module_handle, c"WinDivertClose".as_ptr() as *const u8)
                .ok_or_else(|| RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_DRIVER,
                    detail: format!("Missing WinDivertClose in {loaded_from}"),
                })?;
            let calc_ptr = GetProcAddress(
                module_handle,
                c"WinDivertHelperCalcChecksums".as_ptr() as *const u8,
            )
            .ok_or_else(|| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_DRIVER,
                detail: format!("Missing WinDivertHelperCalcChecksums in {loaded_from}"),
            })?;

            Ok(WinDivertApi {
                open: std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertOpen>(
                    open_ptr,
                ),
                recv: std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertRecv>(
                    recv_ptr,
                ),
                send: std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertSend>(
                    send_ptr,
                ),
                shutdown: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnWinDivertShutdown,
                >(shutdown_ptr),
                close: std::mem::transmute::<unsafe extern "system" fn() -> isize, FnWinDivertClose>(
                    close_ptr,
                ),
                calc_checksums: std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    FnWinDivertHelperCalcChecksums,
                >(calc_ptr),
            })
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn resolves_windivert_candidates_under_exe_dir_only_and_strips_verbatim_prefix() {
        let search_paths = vec![
            "WinDivert.dll".to_string(),
            "third_party/windivert/bin/WinDivert.dll".to_string(),
        ];
        let exe_dir = Path::new(r"\\?\C:\Program Files\RouteWard");
        let candidates = collect_windivert_candidates(
            &search_paths,
            Some(exe_dir),
            Some(r"\\?\D:\Custom\WinDivert.dll"),
        );
        assert_eq!(candidates[0], r"D:\Custom\WinDivert.dll");
        assert_eq!(
            Path::new(&candidates[1]),
            Path::new(r"C:\Program Files\RouteWard").join("WinDivert.dll")
        );
        assert_eq!(
            Path::new(&candidates[2]),
            Path::new(r"C:\Program Files\RouteWard")
                .join("third_party/windivert/bin/WinDivert.dll")
        );
        // The bare CWD-relative names are no longer candidates (intentional behaviour change).
        assert_eq!(candidates.len(), 3);
    }

    #[test]
    fn rejects_escaping_and_foreign_absolute_candidates() {
        let exe_dir = Path::new(r"C:\Program Files\RouteWard");
        let search_paths = vec![
            "WinDivert.dll".to_string(),
            r"..\Evil\WinDivert.dll".to_string(),
            r"D:\Other\WinDivert.dll".to_string(),
        ];
        let candidates = collect_windivert_candidates(&search_paths, Some(exe_dir), None);
        assert_eq!(candidates.len(), 1);
        assert!(Path::new(&candidates[0]).starts_with(exe_dir));
        // Without a known executable directory nothing may be loaded at all.
        assert!(collect_windivert_candidates(&search_paths, None, None).is_empty());
    }
}
