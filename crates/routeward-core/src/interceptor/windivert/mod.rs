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

#[cfg(windows)]
use crate::error::ERR_KEY_INTERCEPTOR_OPEN;
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_INTERCEPTOR_DRIVER};
use crate::interceptor::backend::Interceptor;
use crate::interceptor::RouteWardController;
use parking_lot::Mutex;
#[cfg(windows)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
use crate::config::{RuleAction, TransportProtocol};
#[cfg(windows)]
use crate::dns::codec::{enforce_udp_truncation, parse_dns_query};
#[cfg(windows)]
use crate::dns::LocalNameQueryDecision;
#[cfg(windows)]
use crate::interceptor::nat::{
    build_forged_ipv4_icmp_port_unreachable, build_forged_ipv4_tcp_rst,
    build_forged_ipv4_udp_reply, build_forged_ipv6_icmpv6_port_unreachable,
    build_forged_ipv6_tcp_rst, build_forged_ipv6_udp_reply, is_ipv4_packet_fragmented,
    is_non_first_ip_fragment, is_private_or_local_ipv4, parse_ipv4_tcp_meta, parse_ipv4_udp_meta,
    parse_ipv6_tcp_meta, parse_ipv6_transport_meta, parse_udp_fragment_meta,
    reflect_outbound_ipv6_to_local_relay, reflect_outbound_to_local_relay,
    reflect_relay_reply_ipv6_to_client, reflect_relay_reply_to_client, Ipv4TcpPacketMeta,
    Ipv4UdpPacketMeta, Ipv6TransportPacketMeta, NatSessionEntry, PendingSynOutcome,
    PendingSynQueue, PendingUdpOutcome, PendingUdpQueue, PidResolutionSource, SocketKey,
    UdpFragmentKind, UdpFragmentMeta, UdpFragmentVerdict, IPPROTO_TCP, IPPROTO_UDP,
};
#[cfg(windows)]
use crate::process::ProcessResolver;
#[cfg(windows)]
use crate::proxy::udp::Socks5UdpTarget;
#[cfg(windows)]
use crate::rules::ConnectionRequest;
#[cfg(windows)]
use crate::telemetry::{ConnectionStatus, LogLevel, TelemetryHub, TrackedConnection};
#[cfg(windows)]
use chrono::Utc;
#[cfg(windows)]
use std::ffi::{c_char, c_void, CString};
#[cfg(windows)]
use std::net::{IpAddr, SocketAddr};
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use uuid::Uuid;

pub(super) const BACKEND_NAME: &str = "WinDivert";

/// Prefix of the scoped inbound firewall rule that allows the local transparent relay port.
const FIREWALL_RULE_NAME_PREFIX: &str = "RouteWard_TransparentRelay_";

/// Returns the name of the scoped inbound firewall rule for the transparent relay on `relay_port`.
/// The single source of truth for creating, removing and cleaning up that rule.
pub fn scoped_firewall_rule_name(relay_port: u16) -> String {
    format!("{FIREWALL_RULE_NAME_PREFIX}{relay_port}")
}

#[cfg(windows)]
pub(super) const COMPONENT_WINDIVERT: &str = "WinDivert";
#[cfg(windows)]
pub(super) const COMPONENT_FIREWALL: &str = "WindowsFirewall";
/// Debug-only override of the `WinDivert.dll` location; release builds never read it.
#[cfg(all(windows, debug_assertions))]
pub(super) const ENV_WINDIVERT_DLL_PATH: &str = "ROUTEWARD_WINDIVERT_DLL_PATH";
#[cfg(windows)]
pub(super) const WINDIVERT_LAYER_NETWORK: u32 = 0;
#[cfg(windows)]
pub(super) const WINDIVERT_LAYER_SOCKET: u32 = 3;
#[cfg(windows)]
pub(super) const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
#[cfg(windows)]
pub(super) const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
#[cfg(windows)]
pub(super) const WINDIVERT_SHUTDOWN_BOTH: u32 = 0x0003;
#[cfg(windows)]
pub(super) const SOCKET_FILTER_TCP_OUTBOUND: &str = "outbound and !loopback and (tcp or udp)";
#[cfg(windows)]
pub(super) const PACKET_BUFFER_SIZE: usize = 65535;
pub(super) const BIT_OUTBOUND: u64 = 1 << 17;
pub(super) const BIT_IMPOSTOR: u64 = 1 << 19;
pub(super) const BIT_IPV6: u64 = 1 << 20;

mod ffi;
mod filters;
#[cfg(any(windows, test))]
mod fragments;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod worker;

pub use ffi::WinDivertAddress;
#[cfg(windows)]
use ffi::WinDivertApi;
pub use filters::{
    build_network_filter_string, build_network_filter_string_full,
    should_block_outbound_ipv6_dns_or_dot, should_block_outbound_ipv6_dot,
};

#[cfg(windows)]
struct ActiveHandles {
    api: WinDivertApi,
    socket_handle: usize,
    network_handle: Arc<AtomicUsize>,
    pending_syn_queue: PendingSynQueue<(Vec<u8>, WinDivertAddress)>,
    pending_syn_v6_queue: PendingSynQueue<(Vec<u8>, WinDivertAddress), Ipv6TransportPacketMeta>,
    pending_udp_queue: PendingUdpQueue<(Vec<u8>, WinDivertAddress)>,
    pending_udp_v6_queue: PendingUdpQueue<(Vec<u8>, WinDivertAddress), Ipv6TransportPacketMeta>,
    rt_handle: tokio::runtime::Handle,
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

    /// Builds a `netsh.exe` command from the System32 directory (never a bare name: this process
    /// runs elevated and a binary planted next to the executable must not be picked up).
    #[cfg(windows)]
    fn netsh_command() -> Command {
        Command::new(crate::system::windows_system_tool_path("netsh.exe"))
    }

    /// Returns whether the named firewall rule exists, judged only by `netsh` exit status
    /// (0 = found, 1 = no match) so the answer does not depend on the Windows display language.
    #[cfg(windows)]
    fn firewall_rule_exists(rule_name: &str) -> Option<bool> {
        let name_arg = format!("name={rule_name}");
        let status = Self::netsh_command()
            .args(["advfirewall", "firewall", "show", "rule", &name_arg])
            .output()
            .ok()?
            .status;
        match status.code() {
            Some(0) => Some(true),
            Some(1) => Some(false),
            _ => None,
        }
    }

    #[cfg(windows)]
    pub(super) fn create_scoped_firewall_rule(relay_port: u16, telemetry: &TelemetryHub) -> String {
        let rule_name = scoped_firewall_rule_name(relay_port);
        let exe_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok().or(Some(p)))
            .map(|p| {
                let s = p.to_string_lossy().into_owned();
                s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
            })
            .unwrap_or_else(|| "routeward.exe".to_string());

        // Remove any stale rule with the same name first
        let _ = Self::netsh_command()
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

        match Self::netsh_command()
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
    pub(crate) fn remove_scoped_firewall_rule(rule_name: &str, telemetry: &TelemetryHub) {
        let name_arg = format!("name={rule_name}");
        match Self::netsh_command()
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
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                let combined = format!("{} {}", stdout.trim(), stderr.trim());
                // Exit status only: the "no rules match" text is localized. A failed delete is
                // "already absent" only when a second query confirms that the rule does not exist.
                if Self::firewall_rule_exists(rule_name) == Some(false) {
                    telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_FIREWALL,
                        format!("Firewall rule \"{rule_name}\" was already absent during cleanup"),
                    );
                } else {
                    telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_FIREWALL,
                        format!(
                            "Could not remove firewall rule \"{rule_name}\" (exit={:?}): {}",
                            out.status.code(),
                            combined.trim()
                        ),
                    );
                }
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
        let dns_port = controller.constants.dns.dns_standard_port;
        let dot_port = controller.constants.dns.dns_over_tls_port;
        let api = Self::load_dynamic_api(&net_consts.windivert_dll_paths)?;

        let sock_filter = CString::new(SOCKET_FILTER_TCP_OUTBOUND).expect("valid CString");
        let net_filter_str = build_network_filter_string_full(
            dns_port,
            dot_port,
            net_consts.quic_default_port,
            net_consts.mdns_standard_port,
            net_consts.llmnr_standard_port,
            net_consts.netbios_ns_standard_port,
        );
        let net_filter = CString::new(net_filter_str).expect("valid CString");

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

        // The engine listeners (required before this point) are tokio tasks, so a runtime is
        // always present; every caller (CLI, daemon IPC dispatch) runs inside one.
        let rt_handle = tokio::runtime::Handle::try_current().map_err(|err| {
            RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_OPEN,
                detail: format!("No Tokio runtime available for WinDivert workers: {err}"),
            }
        })?;

        self.active.store(true, Ordering::SeqCst);
        let sock_handle_usize = socket_handle as usize;
        let net_handle_usize = network_handle as usize;
        let shared_net_handle = Arc::new(AtomicUsize::new(net_handle_usize));
        controller.nat_table.configure(
            Duration::from_millis(net_consts.socket_pid_cache_ttl_ms),
            Duration::from_secs(net_consts.nat_half_open_session_ttl_secs),
            Duration::from_millis(net_consts.udp_fragment_verdict_ttl_ms),
            net_consts.max_udp_fragment_verdicts,
        );
        let pending_syn_queue: PendingSynQueue<(Vec<u8>, WinDivertAddress)> =
            PendingSynQueue::with_capacity(net_consts.max_pending_syn_packets);
        let pending_syn_v6_queue: PendingSynQueue<
            (Vec<u8>, WinDivertAddress),
            Ipv6TransportPacketMeta,
        > = PendingSynQueue::with_capacity(net_consts.max_pending_syn_packets);
        let pending_udp_queue: PendingUdpQueue<(Vec<u8>, WinDivertAddress)> =
            PendingUdpQueue::new(net_consts.max_pending_udp_packets);
        let pending_udp_v6_queue: PendingUdpQueue<
            (Vec<u8>, WinDivertAddress),
            Ipv6TransportPacketMeta,
        > = PendingUdpQueue::new(net_consts.max_pending_udp_packets);

        *self.handles.lock() = Some(ActiveHandles {
            api,
            socket_handle: sock_handle_usize,
            network_handle: Arc::clone(&shared_net_handle),
            pending_syn_queue: pending_syn_queue.clone(),
            pending_syn_v6_queue: pending_syn_v6_queue.clone(),
            pending_udp_queue: pending_udp_queue.clone(),
            pending_udp_v6_queue: pending_udp_v6_queue.clone(),
            rt_handle: rt_handle.clone(),
            firewall_rule_name,
            telemetry: controller.telemetry.clone(),
        });

        // 1. Spawn WINDIVERT_LAYER_SOCKET listener thread
        let active_sock = Arc::clone(&self.active);
        let nat_for_sock = controller.nat_table.clone();
        let telemetry_for_sock = controller.telemetry.clone();
        let unknown_pid_tx = Self::spawn_dns_server_pid_resolver(controller.clone());
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
                let event = addr.socket_event();
                if event.protocol != IPPROTO_TCP && event.protocol != IPPROTO_UDP {
                    continue;
                }
                let key = SocketKey::new(event.protocol, event.ipv6, event.local_port);
                if event.is_close() {
                    // The port may be reused by another process: forget the previous owner.
                    nat_for_sock.record_socket_close(key, event.pid);
                } else {
                    nat_for_sock.record_socket_event(key, event.pid);
                    // Never block this thread: a full queue only delays the exemption until the
                    // next periodic rescan.
                    let _ = unknown_pid_tx.try_send(event.pid);
                }
            }
            // The socket listener ends only when its handle is closed (stop) or the driver fails.
            // Attribution then degrades to table lookups, so make a failure visible.
            if active_sock.load(Ordering::Relaxed) {
                telemetry_for_sock.push_log(
                    LogLevel::Error,
                    COMPONENT_WINDIVERT,
                    "WinDivertRecv failed on the socket handle; attribution falls back to socket table lookups".to_string(),
                );
            }
        });

        // 2. Spawn dedicated Pending SYN + Pending UDP worker thread (polls unresolved packets outside the receive loop)
        let active_syn = Arc::clone(&self.active);
        let ctrl_syn = controller.clone();
        let syn_queue_worker = pending_syn_queue.clone();
        let syn_v6_queue_worker = pending_syn_v6_queue.clone();
        let udp_queue_worker = pending_udp_queue.clone();
        let udp_v6_queue_worker = pending_udp_v6_queue.clone();
        let net_handle_for_syn = Arc::clone(&shared_net_handle);
        let rt_for_syn = rt_handle.clone();
        std::thread::spawn(move || {
            let poll_interval =
                Duration::from_millis(ctrl_syn.constants.network.pid_fallback_delay_ms.max(1));
            let syn_timeout =
                Duration::from_millis(ctrl_syn.constants.network.pending_syn_timeout_ms);
            let udp_timeout =
                Duration::from_millis(ctrl_syn.constants.network.pending_udp_timeout_ms);

            let sweep_interval = Duration::from_millis(
                ctrl_syn
                    .constants
                    .network
                    .nat_session_sweep_interval_ms
                    .max(1),
            );
            let mut last_sweep = Instant::now();

            while active_syn.load(Ordering::Relaxed) {
                let handle_usize = net_handle_for_syn.load(Ordering::Acquire);
                let handle = handle_usize as *mut c_void;
                let outcomes = ctrl_syn.poll_pending_syns(
                    &syn_queue_worker,
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
                        PendingSynOutcome::TimedOutDropped { .. } => {
                            // Packet was dropped inside poll_pending_syns and logged at INFO with drop_count
                        }
                        PendingSynOutcome::TimedOutReinject {
                            payload: (pkt, addr),
                            ..
                        } => {
                            Self::send_packet_guarded(&ctrl_syn, &api, handle, &pkt, &addr);
                        }
                    }
                }

                let udp_outcomes = ctrl_syn.poll_pending_udps(
                    &udp_queue_worker,
                    udp_timeout,
                    ProcessResolver::find_pid_for_udp_port,
                );

                for outcome in udp_outcomes {
                    match outcome {
                        PendingUdpOutcome::Resolved {
                            payload: (pkt, addr),
                            meta,
                            is_fragmented,
                            pid,
                            source,
                        } => {
                            Self::dispatch_resolved_udp(
                                &ctrl_syn,
                                &active_syn,
                                &api,
                                &net_handle_for_syn,
                                &rt_for_syn,
                                &pkt,
                                &addr,
                                meta,
                                is_fragmented,
                                Some((pid, source)),
                            );
                        }
                        PendingUdpOutcome::TimedOutDropped { .. } => {
                            // Datagram was dropped inside poll_pending_udps and logged at INFO with drop_count
                        }
                        PendingUdpOutcome::TimedOutReinject {
                            payload: (pkt, addr),
                            ..
                        } => {
                            Self::send_packet_guarded(&ctrl_syn, &api, handle, &pkt, &addr);
                        }
                    }
                }

                let udp_v6_outcomes = ctrl_syn.poll_pending_udps(
                    &udp_v6_queue_worker,
                    udp_timeout,
                    ProcessResolver::find_pid_for_udp_port,
                );
                for outcome in udp_v6_outcomes {
                    match outcome {
                        PendingUdpOutcome::Resolved {
                            payload: (pkt, addr),
                            meta,
                            pid,
                            source,
                            ..
                        } => {
                            Self::dispatch_resolved_ipv6_udp(
                                &ctrl_syn,
                                &active_syn,
                                &api,
                                &net_handle_for_syn,
                                &rt_for_syn,
                                &pkt,
                                &addr,
                                meta,
                                Some((pid, source)),
                            );
                        }
                        PendingUdpOutcome::TimedOutDropped { .. } => {}
                        PendingUdpOutcome::TimedOutReinject {
                            payload: (pkt, addr),
                            ..
                        } => {
                            Self::send_packet_guarded(&ctrl_syn, &api, handle, &pkt, &addr);
                        }
                    }
                }

                let syn_v6_outcomes = ctrl_syn.poll_pending_syns(
                    &syn_v6_queue_worker,
                    syn_timeout,
                    ProcessResolver::find_pid_for_tcp_port,
                );
                for outcome in syn_v6_outcomes {
                    match outcome {
                        PendingSynOutcome::Resolved {
                            payload: (mut pkt, mut addr),
                            meta,
                            pid,
                            source,
                        } => {
                            Self::dispatch_resolved_ipv6_syn(
                                &ctrl_syn,
                                &api,
                                handle,
                                &mut pkt,
                                &mut addr,
                                meta,
                                Some((pid, source)),
                            );
                        }
                        PendingSynOutcome::TimedOutDropped { .. } => {}
                        PendingSynOutcome::TimedOutReinject {
                            payload: (pkt, addr),
                            ..
                        } => {
                            Self::send_packet_guarded(&ctrl_syn, &api, handle, &pkt, &addr);
                        }
                    }
                }

                if last_sweep.elapsed() >= sweep_interval {
                    let expired = ctrl_syn.nat_table.sweep_expired();
                    if expired > 0 {
                        ctrl_syn.telemetry.push_log(
                            LogLevel::Debug,
                            COMPONENT_WINDIVERT,
                            format!("Expired {expired} half-open NAT session(s)"),
                        );
                    }
                    last_sweep = Instant::now();
                }

                std::thread::sleep(poll_interval);
            }
        });

        // 3. Spawn non-blocking WINDIVERT_LAYER_NETWORK packet reflection thread
        Self::spawn_network_reflection_thread(
            Arc::clone(&self.active),
            controller,
            api,
            net_handle_usize,
            Arc::clone(&shared_net_handle),
            rt_handle,
            pending_syn_queue,
            pending_syn_v6_queue,
            pending_udp_queue,
            pending_udp_v6_queue,
        );

        Ok(())
    }

    #[cfg(not(windows))]
    fn start(&self, _controller: RouteWardController) -> RouteWardResult<()> {
        Err(RouteWardError::InterceptorError {
            key: ERR_KEY_INTERCEPTOR_DRIVER,
            detail: "WinDivert backend is only supported on Windows".to_string(),
        })
    }

    #[cfg(windows)]
    fn reload(&self, controller: RouteWardController) -> RouteWardResult<()> {
        use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};

        if !self.is_active() {
            return Ok(());
        }

        let (
            api,
            shared_net_handle,
            pending_syn_queue,
            pending_syn_v6_queue,
            pending_udp_queue,
            pending_udp_v6_queue,
            rt_handle,
        ) = {
            let guard = self.handles.lock();
            let Some(ref handles) = *guard else {
                return Ok(());
            };
            (
                handles.api,
                Arc::clone(&handles.network_handle),
                handles.pending_syn_queue.clone(),
                handles.pending_syn_v6_queue.clone(),
                handles.pending_udp_queue.clone(),
                handles.pending_udp_v6_queue.clone(),
                handles.rt_handle.clone(),
            )
        };

        let net_consts = &controller.constants.network;
        let dns_port = controller.constants.dns.dns_standard_port;
        let dot_port = controller.constants.dns.dns_over_tls_port;
        let net_filter_str = build_network_filter_string_full(
            dns_port,
            dot_port,
            net_consts.quic_default_port,
            net_consts.mdns_standard_port,
            net_consts.llmnr_standard_port,
            net_consts.netbios_ns_standard_port,
        );
        let net_filter = CString::new(net_filter_str).expect("valid CString");

        // Open the new WinDivert network handle and start its reflection worker BEFORE closing the old handle,
        // guaranteeing zero permissive window during the switchover.
        let new_network_handle = unsafe {
            (api.open)(
                net_filter.as_ptr(),
                WINDIVERT_LAYER_NETWORK,
                net_consts.windivert_priority,
                0,
            )
        };
        if new_network_handle.is_null() || new_network_handle == INVALID_HANDLE_VALUE {
            let err_code = unsafe { GetLastError() };
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_OPEN,
                detail: format!(
                    "WinDivertOpen(NETWORK) live reload failed with Win32 error {err_code}"
                ),
            });
        }

        let new_net_usize = new_network_handle as usize;
        Self::spawn_network_reflection_thread(
            Arc::clone(&self.active),
            controller.clone(),
            api,
            new_net_usize,
            Arc::clone(&shared_net_handle),
            rt_handle,
            pending_syn_queue,
            pending_syn_v6_queue,
            pending_udp_queue,
            pending_udp_v6_queue,
        );

        let old_net_usize = shared_net_handle.swap(new_net_usize, Ordering::SeqCst);
        unsafe {
            let old_ptr = old_net_usize as *mut c_void;
            let _ = (api.shutdown)(old_ptr, WINDIVERT_SHUTDOWN_BOTH);
            let _ = (api.close)(old_ptr);
        }

        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_WINDIVERT,
            "Reopened WinDivert network filter before closing previous handle (zero permissive window)"
                .to_string(),
        );

        Ok(())
    }

    fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
        #[cfg(windows)]
        {
            if let Some(handles) = self.handles.lock().take() {
                unsafe {
                    let sock = handles.socket_handle as *mut c_void;
                    let net = handles.network_handle.load(Ordering::SeqCst) as *mut c_void;
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

#[cfg(windows)]
impl Drop for WinDivertInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}
