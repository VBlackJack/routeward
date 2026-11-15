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
impl WinDivertInterceptor {
    #[cfg(windows)]
    pub(super) fn load_dynamic_api(search_paths: &[String]) -> RouteWardResult<WinDivertApi> {
        use windows_sys::Win32::System::LibraryLoader::{
            GetProcAddress, LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH,
        };

        let mut candidates = Vec::new();
        if let Ok(env_path) = std::env::var(ENV_WINDIVERT_DLL_PATH) {
            if !env_path.trim().is_empty() {
                candidates.push(env_path);
            }
        }
        candidates.extend_from_slice(search_paths);

        let mut module_handle = std::ptr::null_mut();
        let mut loaded_from = String::new();

        for candidate in &candidates {
            let resolved = Path::new(candidate)
                .canonicalize()
                .unwrap_or_else(|_| Path::new(candidate).to_path_buf());
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
