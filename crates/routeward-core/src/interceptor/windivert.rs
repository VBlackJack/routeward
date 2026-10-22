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
    RouteWardError, RouteWardResult, ERR_KEY_INTERCEPTOR_DRIVER, ERR_KEY_INTERCEPTOR_OPEN,
};
use crate::interceptor::backend::Interceptor;
use crate::interceptor::RouteWardController;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
use crate::config::{RuleAction, TransportProtocol};
#[cfg(windows)]
use crate::interceptor::nat::{
    parse_ipv4_tcp_meta, reflect_outbound_to_local_relay, reflect_relay_reply_to_client,
    Ipv4TcpPacketMeta, NatSessionEntry, PendingSynOutcome, PendingSynQueue, PidResolutionSource,
};
#[cfg(windows)]
use crate::process::ProcessResolver;
#[cfg(windows)]
use crate::rules::ConnectionRequest;
#[cfg(windows)]
use crate::telemetry::{ConnectionStatus, LogLevel, TelemetryHub, TrackedConnection};
#[cfg(windows)]
use chrono::Utc;
#[cfg(windows)]
use std::ffi::{c_char, c_void, CString};
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use uuid::Uuid;

const BACKEND_NAME: &str = "WinDivert";

#[cfg(windows)]
const COMPONENT_WINDIVERT: &str = "WinDivert";
#[cfg(windows)]
const COMPONENT_FIREWALL: &str = "WindowsFirewall";
#[cfg(windows)]
const ENV_WINDIVERT_DLL_PATH: &str = "ROUTEWARD_WINDIVERT_DLL_PATH";
#[cfg(windows)]
const WINDIVERT_LAYER_NETWORK: u32 = 0;
#[cfg(windows)]
const WINDIVERT_LAYER_SOCKET: u32 = 3;
#[cfg(windows)]
const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
#[cfg(windows)]
const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
#[cfg(windows)]
const WINDIVERT_SHUTDOWN_BOTH: u32 = 0x0003;
#[cfg(windows)]
const SOCKET_FILTER_TCP_OUTBOUND: &str = "outbound and !loopback and tcp";
#[cfg(windows)]
const NETWORK_FILTER_IPV4_TCP_OUTBOUND: &str = "outbound and !loopback and ip and tcp";
#[cfg(windows)]
const PACKET_BUFFER_SIZE: usize = 65535;
#[cfg(windows)]
const BIT_OUTBOUND: u64 = 1 << 17;
#[cfg(windows)]
const BIT_IMPOSTOR: u64 = 1 << 19;

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
type FnWinDivertOpen = unsafe extern "system" fn(
    filter: *const c_char,
    layer: u32,
    priority: i16,
    flags: u64,
) -> *mut c_void;

#[cfg(windows)]
type FnWinDivertRecv = unsafe extern "system" fn(
    handle: *mut c_void,
    p_packet: *mut c_void,
    packet_len: u32,
    p_recv_len: *mut u32,
    p_addr: *mut WinDivertAddress,
) -> i32;

#[cfg(windows)]
type FnWinDivertSend = unsafe extern "system" fn(
    handle: *mut c_void,
    p_packet: *const c_void,
    packet_len: u32,
    p_send_len: *mut u32,
    p_addr: *const WinDivertAddress,
) -> i32;

#[cfg(windows)]
type FnWinDivertShutdown = unsafe extern "system" fn(handle: *mut c_void, how: u32) -> i32;

#[cfg(windows)]
type FnWinDivertClose = unsafe extern "system" fn(handle: *mut c_void) -> i32;

#[cfg(windows)]
type FnWinDivertHelperCalcChecksums = unsafe extern "system" fn(
    p_packet: *mut c_void,
    packet_len: u32,
    p_addr: *mut WinDivertAddress,
    flags: u64,
) -> i32;

#[cfg(windows)]
#[derive(Clone, Copy)]
struct WinDivertApi {
    open: FnWinDivertOpen,
    recv: FnWinDivertRecv,
    send: FnWinDivertSend,
    shutdown: FnWinDivertShutdown,
    close: FnWinDivertClose,
    calc_checksums: FnWinDivertHelperCalcChecksums,
}

#[cfg(windows)]
struct ActiveHandles {
    api: WinDivertApi,
    socket_handle: usize,
    network_handle: usize,
    firewall_rule_name: String,
    telemetry: TelemetryHub,
}

/// Windows transparent packet interceptor backed by dynamic runtime loading of `WinDivert.dll`.
pub struct WinDivertInterceptor {
    active: Arc<AtomicBool>,
    #[cfg(windows)]
    handles: Arc<Mutex<Option<ActiveHandles>>>,
    #[cfg(not(windows))]
    _handles: Arc<Mutex<Option<()>>>,
}

impl Default for WinDivertInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl WinDivertInterceptor {
    /// Creates an idle `WinDivertInterceptor` instance without loading any driver until `start()`.
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            #[cfg(windows)]
            handles: Arc::new(Mutex::new(None)),
            #[cfg(not(windows))]
            _handles: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(windows)]
    fn create_scoped_firewall_rule(relay_port: u16, telemetry: &TelemetryHub) -> String {
        let rule_name = format!("RouteWard_TransparentRelay_{relay_port}");
        let exe_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok().or(Some(p)))
            .map(|p| {
                let s = p.to_string_lossy().into_owned();
                s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
            })
            .unwrap_or_else(|| "routeward.exe".to_string());

        // Remove any stale rule with the same name first
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={rule_name}"),
            ])
            .output();

        let port_arg = format!("localport={relay_port}");
        let name_arg = format!("name={rule_name}");
        let prog_arg = format!("program={exe_path}");

        match Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &name_arg,
                "dir=in",
                "action=allow",
                &prog_arg,
                "enable=yes",
                "profile=any",
                "protocol=TCP",
                &port_arg,
            ])
            .output()
        {
            Ok(out) if out.status.success() => {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_FIREWALL,
                    format!(
                        "Created scoped inbound firewall rule \"{rule_name}\" (program=\"{exe_path}\", protocol=TCP, port={relay_port}, profile=any)"
                    ),
                );
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_FIREWALL,
                    format!(
                        "Failed to create scoped inbound firewall rule \"{rule_name}\" (exit={:?}): {}",
                        out.status.code(),
                        stderr.trim()
                    ),
                );
            }
            Err(err) => {
                telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_FIREWALL,
                    format!("Could not invoke netsh for firewall rule \"{rule_name}\": {err}"),
                );
            }
        }

        rule_name
    }

    #[cfg(windows)]
    fn remove_scoped_firewall_rule(rule_name: &str, telemetry: &TelemetryHub) {
        let name_arg = format!("name={rule_name}");
        match Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &name_arg])
            .output()
        {
            Ok(out) if out.status.success() => {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_FIREWALL,
                    format!("Removed scoped inbound firewall rule \"{rule_name}\""),
                );
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_FIREWALL,
                    format!(
                        "Could not remove firewall rule \"{rule_name}\" (exit={:?}): {}",
                        out.status.code(),
                        stderr.trim()
                    ),
                );
            }
            Err(err) => {
                telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_FIREWALL,
                    format!("Failed invoking netsh to remove firewall rule \"{rule_name}\": {err}"),
                );
            }
        }
    }

    #[cfg(windows)]
    fn dispatch_resolved_syn(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &mut [u8],
        addr: &mut WinDivertAddress,
        meta: Ipv4TcpPacketMeta,
        resolved: Option<(u32, PidResolutionSource)>,
    ) {
        let relay_port = ctrl.nat_table.transparent_relay_port();
        let pid_opt = resolved.map(|(p, _)| p);

        if !ctrl.nat_table.is_loop_or_excluded(
            pid_opt,
            meta.src_ip,
            meta.src_port,
            meta.dst_ip,
            meta.dst_port,
        ) {
            let (pid, res_source) = resolved.unwrap_or((0, PidResolutionSource::TcpTableFallback));
            let proc_id = ctrl.process_resolver.resolve_by_pid(pid);
            let dst_ip_str = meta.dst_ip.to_string();

            let eval = ctrl.evaluate_rule(&ConnectionRequest {
                process_name: proc_id.name.clone(),
                process_path: Some(proc_id.executable_path.clone()),
                target_host: dst_ip_str.clone(),
                target_ip: Some(dst_ip_str.clone()),
                target_port: meta.dst_port,
                protocol: TransportProtocol::Tcp,
            });

            match &eval.action {
                RuleAction::Proxy { .. } | RuleAction::Chain { .. } => {
                    ctrl.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_WINDIVERT,
                        format!(
                            "Intercepted SYN PID={} process=\"{}\" exe=\"{}\" resolvedVia={} {}:{} -> {}:{} [rule=\"{}\"]",
                            proc_id.pid,
                            proc_id.name,
                            proc_id.executable_path,
                            res_source.as_str(),
                            meta.src_ip,
                            meta.src_port,
                            meta.dst_ip,
                            meta.dst_port,
                            eval.matched_rule_name
                        ),
                    );

                    ctrl.nat_table.insert_session(NatSessionEntry {
                        client_ip: meta.src_ip,
                        client_port: meta.src_port,
                        orig_dst_ip: meta.dst_ip,
                        orig_dst_port: meta.dst_port,
                        pid: proc_id.pid,
                        process_name: proc_id.name,
                        process_path: proc_id.executable_path,
                        resolution_source: res_source,
                        action: eval.action,
                        matched_rule_name: eval.matched_rule_name,
                        created_at: Instant::now(),
                    });

                    if reflect_outbound_to_local_relay(packet, relay_port) {
                        addr.set_outbound(false);
                        addr.clear_impostor();
                        unsafe {
                            let _ = (api.calc_checksums)(
                                packet.as_mut_ptr() as *mut c_void,
                                packet.len() as u32,
                                addr as *mut WinDivertAddress,
                                0,
                            );
                        }
                    }
                }
                RuleAction::Block => {
                    ctrl.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_WINDIVERT,
                        format!(
                            "Blocked SYN PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} [rule=\"{}\"]",
                            proc_id.pid,
                            proc_id.name,
                            proc_id.executable_path,
                            res_source.as_str(),
                            meta.dst_ip,
                            meta.dst_port,
                            eval.matched_rule_name
                        ),
                    );
                    ctrl.telemetry.record_connection(
                        TrackedConnection {
                            id: Uuid::new_v4().to_string(),
                            pid: proc_id.pid,
                            process_name: proc_id.name,
                            process_path: proc_id.executable_path,
                            target_host: dst_ip_str,
                            resolved_domain: eval.effective_domain,
                            target_port: meta.dst_port,
                            protocol: TransportProtocol::Tcp,
                            matched_rule: eval.matched_rule_name,
                            route_label: "BLOCKED".to_string(),
                            latency_ms: 0,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            status: ConnectionStatus::Blocked,
                            started_at: Utc::now(),
                        },
                        false,
                    );
                    // Drop packet by skipping WinDivertSend
                    return;
                }
                RuleAction::Direct => {
                    ctrl.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_WINDIVERT,
                        format!(
                            "Direct pass-through SYN PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{}",
                            proc_id.pid,
                            proc_id.name,
                            proc_id.executable_path,
                            res_source.as_str(),
                            meta.dst_ip,
                            meta.dst_port
                        ),
                    );
                }
            }
        }

        let mut send_len: u32 = 0;
        unsafe {
            let _ = (api.send)(
                net_handle,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                &mut send_len,
                addr as *const WinDivertAddress,
            );
        }
    }

    #[cfg(windows)]
    fn load_dynamic_api(search_paths: &[String]) -> RouteWardResult<WinDivertApi> {
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

impl Interceptor for WinDivertInterceptor {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    #[cfg(windows)]
    fn start(&self, controller: RouteWardController) -> RouteWardResult<()> {
        use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};

        if self.active.load(Ordering::SeqCst) {
            return Ok(());
        }

        let net_consts = &controller.constants.network;
        let api = Self::load_dynamic_api(&net_consts.windivert_dll_paths)?;

        let sock_filter = CString::new(SOCKET_FILTER_TCP_OUTBOUND).expect("valid CString");
        let net_filter = CString::new(NETWORK_FILTER_IPV4_TCP_OUTBOUND).expect("valid CString");

        let socket_handle = unsafe {
            (api.open)(
                sock_filter.as_ptr(),
                WINDIVERT_LAYER_SOCKET,
                net_consts.windivert_priority,
                WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY,
            )
        };
        if socket_handle.is_null() || socket_handle == INVALID_HANDLE_VALUE {
            let err_code = unsafe { GetLastError() };
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_OPEN,
                detail: format!("WinDivertOpen(SOCKET) failed with Win32 error {err_code}"),
            });
        }

        let network_handle = unsafe {
            (api.open)(
                net_filter.as_ptr(),
                WINDIVERT_LAYER_NETWORK,
                net_consts.windivert_priority,
                0,
            )
        };
        if network_handle.is_null() || network_handle == INVALID_HANDLE_VALUE {
            let err_code = unsafe { GetLastError() };
            unsafe {
                let _ = (api.close)(socket_handle);
            }
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_OPEN,
                detail: format!("WinDivertOpen(NETWORK) failed with Win32 error {err_code}"),
            });
        }

        let relay_port = controller.nat_table.transparent_relay_port();
        let firewall_rule_name =
            Self::create_scoped_firewall_rule(relay_port, &controller.telemetry);

        self.active.store(true, Ordering::SeqCst);
        let sock_handle_usize = socket_handle as usize;
        let net_handle_usize = network_handle as usize;

        *self.handles.lock() = Some(ActiveHandles {
            api,
            socket_handle: sock_handle_usize,
            network_handle: net_handle_usize,
            firewall_rule_name,
            telemetry: controller.telemetry.clone(),
        });

        let pending_syn_queue: PendingSynQueue<(Vec<u8>, WinDivertAddress)> =
            PendingSynQueue::new();

        // 1. Spawn WINDIVERT_LAYER_SOCKET listener thread
        let active_sock = Arc::clone(&self.active);
        let nat_for_sock = controller.nat_table.clone();
        std::thread::spawn(move || {
            let handle = sock_handle_usize as *mut c_void;
            let mut addr = WinDivertAddress::default();
            while active_sock.load(Ordering::Relaxed) {
                let mut recv_len: u32 = 0;
                let ok = unsafe {
                    (api.recv)(
                        handle,
                        std::ptr::null_mut(),
                        0,
                        &mut recv_len,
                        &mut addr as *mut WinDivertAddress,
                    )
                };
                if ok == 0 {
                    break;
                }
                let (pid, local_port) = addr.socket_pid_and_local_port();
                nat_for_sock.record_socket_event(local_port, pid);
            }
        });

        // 2. Spawn dedicated Pending SYN worker thread (polls unresolved SYNs outside the receive loop)
        let active_syn = Arc::clone(&self.active);
        let ctrl_syn = controller.clone();
        let syn_queue_worker = pending_syn_queue.clone();
        std::thread::spawn(move || {
            let handle = net_handle_usize as *mut c_void;
            let poll_interval =
                Duration::from_millis(ctrl_syn.constants.network.pid_fallback_delay_ms.max(1));
            let syn_timeout =
                Duration::from_millis(ctrl_syn.constants.network.pending_syn_timeout_ms);

            while active_syn.load(Ordering::Relaxed) {
                let outcomes = syn_queue_worker.poll_ready(
                    &ctrl_syn.nat_table,
                    syn_timeout,
                    ProcessResolver::find_pid_for_tcp_port,
                );

                for outcome in outcomes {
                    match outcome {
                        PendingSynOutcome::Resolved {
                            payload: (mut pkt, mut addr),
                            meta,
                            pid,
                            source,
                        } => {
                            Self::dispatch_resolved_syn(
                                &ctrl_syn,
                                &api,
                                handle,
                                &mut pkt,
                                &mut addr,
                                meta,
                                Some((pid, source)),
                            );
                        }
                        PendingSynOutcome::TimedOutFailOpen {
                            payload: (pkt, addr),
                            meta,
                            elapsed_ms,
                        } => {
                            ctrl_syn.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_WINDIVERT,
                                format!(
                                    "Pending SYN PID resolution timed out after {}ms for {}:{} -> {}:{}, reinjecting unmodified (fail-open)",
                                    elapsed_ms, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port
                                ),
                            );
                            let mut send_len: u32 = 0;
                            unsafe {
                                let _ = (api.send)(
                                    handle,
                                    pkt.as_ptr() as *const c_void,
                                    pkt.len() as u32,
                                    &mut send_len,
                                    &addr as *const WinDivertAddress,
                                );
                            }
                        }
                    }
                }

                std::thread::sleep(poll_interval);
            }
        });

        // 3. Spawn non-blocking WINDIVERT_LAYER_NETWORK packet reflection thread
        let active_net = Arc::clone(&self.active);
        let ctrl_net = controller.clone();
        let syn_queue_producer = pending_syn_queue;
        std::thread::spawn(move || {
            let handle = net_handle_usize as *mut c_void;
            let mut packet_buf = vec![0u8; PACKET_BUFFER_SIZE];
            let relay_port = ctrl_net.nat_table.transparent_relay_port();

            while active_net.load(Ordering::Relaxed) {
                let mut recv_len: u32 = 0;
                let mut addr = WinDivertAddress::default();
                let ok = unsafe {
                    (api.recv)(
                        handle,
                        packet_buf.as_mut_ptr() as *mut c_void,
                        packet_buf.len() as u32,
                        &mut recv_len,
                        &mut addr as *mut WinDivertAddress,
                    )
                };
                if ok == 0 {
                    break;
                }

                let pkt_len = recv_len as usize;
                let packet = &mut packet_buf[..pkt_len];

                if let Some(meta) = parse_ipv4_tcp_meta(packet) {
                    // Case A: Outbound reply from our local transparent relay back to the client
                    if meta.src_port == relay_port {
                        if let Some(session) = ctrl_net
                            .nat_table
                            .get_session_by_relay_peer(meta.dst_ip, meta.dst_port)
                        {
                            if reflect_relay_reply_to_client(packet, &session) {
                                addr.set_outbound(false);
                                addr.clear_impostor();
                                unsafe {
                                    let _ = (api.calc_checksums)(
                                        packet.as_mut_ptr() as *mut c_void,
                                        pkt_len as u32,
                                        &mut addr as *mut WinDivertAddress,
                                        0,
                                    );
                                }
                            }
                        }
                    } else if let Some(existing_session) = ctrl_net
                        .nat_table
                        .get_session_by_flow(&meta.outbound_flow_key())
                    {
                        // Case B: Subsequent packets of an already-redirected 4-tuple flow
                        if matches!(
                            existing_session.action,
                            RuleAction::Proxy { .. } | RuleAction::Chain { .. }
                        ) && reflect_outbound_to_local_relay(packet, relay_port)
                        {
                            addr.set_outbound(false);
                            addr.clear_impostor();
                            unsafe {
                                let _ = (api.calc_checksums)(
                                    packet.as_mut_ptr() as *mut c_void,
                                    pkt_len as u32,
                                    &mut addr as *mut WinDivertAddress,
                                    0,
                                );
                            }
                        }
                    } else if meta.is_syn_only() {
                        // Case C: New outbound TCP SYN -> try immediate non-blocking PID lookup
                        if let Some(resolved) = ctrl_net.nat_table.try_resolve_pid_nonblocking(
                            meta.src_port,
                            ProcessResolver::find_pid_for_tcp_port,
                        ) {
                            Self::dispatch_resolved_syn(
                                &ctrl_net,
                                &api,
                                handle,
                                packet,
                                &mut addr,
                                meta,
                                Some(resolved),
                            );
                            continue;
                        } else {
                            // Enqueue into non-blocking PendingSynQueue so the receive loop never stalls
                            syn_queue_producer.enqueue((packet.to_vec(), addr), meta);
                            continue;
                        }
                    }
                }

                let mut send_len: u32 = 0;
                unsafe {
                    let _ = (api.send)(
                        handle,
                        packet.as_ptr() as *const c_void,
                        pkt_len as u32,
                        &mut send_len,
                        &addr as *const WinDivertAddress,
                    );
                }
            }
        });

        Ok(())
    }

    #[cfg(not(windows))]
    fn start(&self, _controller: RouteWardController) -> RouteWardResult<()> {
        Err(RouteWardError::InterceptorError {
            key: ERR_KEY_INTERCEPTOR_DRIVER,
            detail: "WinDivert backend is only supported on Windows".to_string(),
        })
    }

    fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
        #[cfg(windows)]
        {
            if let Some(handles) = self.handles.lock().take() {
                unsafe {
                    let sock = handles.socket_handle as *mut c_void;
                    let net = handles.network_handle as *mut c_void;
                    let _ = (handles.api.shutdown)(sock, WINDIVERT_SHUTDOWN_BOTH);
                    let _ = (handles.api.close)(sock);
                    let _ = (handles.api.shutdown)(net, WINDIVERT_SHUTDOWN_BOTH);
                    let _ = (handles.api.close)(net);
                }
                Self::remove_scoped_firewall_rule(&handles.firewall_rule_name, &handles.telemetry);
            }
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

impl Drop for WinDivertInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windivert_address_layout_and_bitfields_are_exact() {
        assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);

        let mut addr = WinDivertAddress::default();
        assert!(!addr.is_outbound());
        addr.set_outbound(true);
        assert!(addr.is_outbound());
        addr.set_outbound(false);
        assert!(!addr.is_outbound());
    }
}
