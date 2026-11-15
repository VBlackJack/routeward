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
    build_forged_ipv4_icmp_port_unreachable, build_forged_ipv4_udp_reply,
    build_forged_ipv6_icmpv6_port_unreachable, build_forged_ipv6_udp_reply,
    is_ipv4_packet_fragmented, is_private_or_local_ipv4, parse_ipv4_tcp_meta, parse_ipv4_udp_meta,
    parse_ipv6_tcp_meta, parse_ipv6_transport_meta, reflect_outbound_ipv6_to_local_relay,
    reflect_outbound_to_local_relay, reflect_relay_reply_ipv6_to_client,
    reflect_relay_reply_to_client, Ipv4TcpPacketMeta, Ipv4UdpPacketMeta, Ipv6TransportPacketMeta,
    NatSessionEntry, PendingSynOutcome, PendingSynQueue, PendingUdpOutcome, PendingUdpQueue,
    PidResolutionSource,
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
const SOCKET_FILTER_TCP_OUTBOUND: &str = "outbound and !loopback and (tcp or udp)";
#[cfg(windows)]
const PACKET_BUFFER_SIZE: usize = 65535;
const BIT_OUTBOUND: u64 = 1 << 17;
const BIT_IMPOSTOR: u64 = 1 << 19;

/// Builds the `WINDIVERT_LAYER_NETWORK` filter string for outbound IPv4 TCP + UDP
/// and IPv6 DNS/DoT/QUIC/mDNS/LLMNR packets.
pub fn build_network_filter_string(dns_port: u16, dot_port: u16) -> String {
    build_network_filter_string_full(dns_port, dot_port, 443, 5353, 5355, 137)
}

/// Builds the full `WINDIVERT_LAYER_NETWORK` filter string capturing all outbound non-loopback
/// IPv4 and IPv6 TCP and UDP packets.
pub fn build_network_filter_string_full(
    _dns_port: u16,
    _dot_port: u16,
    _quic_port: u16,
    _mdns_port: u16,
    _llmnr_port: u16,
    _netbios_ns_port: u16,
) -> String {
    "outbound and !loopback and ((ip and (tcp or udp)) or (ipv6 and (tcp or udp)))".to_string()
}

/// Returns `true` if an outbound IPv6 packet targeting `dst_port` must be blocked while the engine runs
/// (ports 53 and 853 are unconditionally blocked in IPv6 until Batch 4.3, regardless of `killSwitchEnabled`).
pub fn should_block_outbound_ipv6_dns_or_dot(
    dst_port: u16,
    dns_port: u16,
    dot_port: u16,
    _kill_switch_enabled: bool,
) -> bool {
    dst_port == dns_port || dst_port == dot_port
}

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
    network_handle: Arc<AtomicUsize>,
    pending_syn_queue: PendingSynQueue<(Vec<u8>, WinDivertAddress)>,
    pending_syn_v6_queue: PendingSynQueue<(Vec<u8>, WinDivertAddress), Ipv6TransportPacketMeta>,
    pending_udp_queue: PendingUdpQueue<(Vec<u8>, WinDivertAddress)>,
    pending_udp_v6_queue: PendingUdpQueue<(Vec<u8>, WinDivertAddress), Ipv6TransportPacketMeta>,
    rt_handle: tokio::runtime::Handle,
    _fallback_runtime: Option<tokio::runtime::Runtime>,
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
    pub(crate) fn remove_scoped_firewall_rule(rule_name: &str, telemetry: &TelemetryHub) {
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
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                let combined = format!("{} {}", stdout.trim(), stderr.trim());
                if combined.contains("No rules match")
                    || combined.contains("Aucune")
                    || out.status.code() == Some(1)
                {
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

    #[cfg(windows)]
    fn send_packet_guarded(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &[u8],
        addr: &WinDivertAddress,
    ) {
        if ctrl.check_and_block_outbound_fake_ip_packet(
            packet,
            addr.is_outbound(),
            COMPONENT_WINDIVERT,
        ) {
            return;
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
        let dns_port = ctrl.constants.dns.dns_standard_port;
        let dot_port = ctrl.constants.dns.dns_over_tls_port;
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

            // 1. Outbound TCP port 53 (DNS-over-TCP from OS DNS client/server): always reflect to local relay
            if meta.dst_port == dns_port {
                ctrl.nat_table.insert_session(NatSessionEntry {
                    client_ip: IpAddr::V4(meta.src_ip),
                    client_port: meta.src_port,
                    orig_dst_ip: IpAddr::V4(meta.dst_ip),
                    orig_dst_port: meta.dst_port,
                    pid: proc_id.pid,
                    process_name: proc_id.name,
                    process_path: proc_id.executable_path,
                    resolution_source: res_source,
                    action: RuleAction::Direct,
                    matched_rule_name: "DNS:LocalResolver".to_string(),
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
                Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
                return;
            }

            let mut eval = if proc_id.is_unattributed() {
                let (unknown_action, rule_name) = ctrl.resolve_unknown_process_action(
                    COMPONENT_WINDIVERT,
                    meta.src_port,
                    &dst_ip_str,
                    meta.dst_port,
                    "process image unavailable",
                );
                let resolved_dom = ctrl.dns.resolve_fake_ip(&meta.dst_ip);
                crate::rules::RuleEvaluationResult {
                    matched_rule_id: "security-policy-unknown-process".to_string(),
                    matched_rule_name: rule_name,
                    action: unknown_action,
                    effective_domain: resolved_dom.clone(),
                    resolved_from_fake_ip: resolved_dom.is_some(),
                }
            } else {
                ctrl.evaluate_rule(&ConnectionRequest {
                    process_name: proc_id.name.clone(),
                    process_path: Some(proc_id.executable_path.clone()),
                    target_host: dst_ip_str.clone(),
                    target_ip: Some(dst_ip_str.clone()),
                    target_port: meta.dst_port,
                    protocol: TransportProtocol::Tcp,
                })
            };

            if meta.dst_port == dot_port
                && ctrl
                    .profile
                    .read()
                    .security_policy
                    .block_encrypted_dns_bypass
            {
                eval.action = RuleAction::Block;
                eval.matched_rule_name = "SecurityPolicy:blockEncryptedDnsBypass".to_string();
            }

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
                        client_ip: IpAddr::V4(meta.src_ip),
                        client_port: meta.src_port,
                        orig_dst_ip: IpAddr::V4(meta.dst_ip),
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
                    let is_fake_ip = ctrl.dns.is_in_fake_subnet(&meta.dst_ip);
                    let needs_sni_inspection = !is_fake_ip
                        && meta.dst_port == ctrl.constants.network.tls_sni_default_port
                        && ctrl.has_enabled_domain_rules();
                    if is_fake_ip || needs_sni_inspection {
                        ctrl.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_WINDIVERT,
                            format!(
                                "Reflecting Direct SYN (fakeIp={}, sniInspect={}) PID={} process=\"{}\" exe=\"{}\" resolvedVia={} {}:{} -> {}:{} [rule=\"{}\"]",
                                is_fake_ip,
                                needs_sni_inspection,
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
                            client_ip: IpAddr::V4(meta.src_ip),
                            client_port: meta.src_port,
                            orig_dst_ip: IpAddr::V4(meta.dst_ip),
                            orig_dst_port: meta.dst_port,
                            pid: proc_id.pid,
                            process_name: proc_id.name,
                            process_path: proc_id.executable_path,
                            resolution_source: res_source,
                            action: RuleAction::Direct,
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
                    } else {
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
        }

        Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn dispatch_resolved_udp(
        ctrl: &RouteWardController,
        active: &Arc<AtomicBool>,
        api: &WinDivertApi,
        shared_net_handle: &Arc<AtomicUsize>,
        rt_handle: &tokio::runtime::Handle,
        packet: &[u8],
        addr: &WinDivertAddress,
        meta: Ipv4UdpPacketMeta,
        is_fragmented: bool,
        resolved: Option<(u32, PidResolutionSource)>,
    ) {
        let net_handle = shared_net_handle.load(Ordering::Acquire) as *mut c_void;
        let pid_opt = resolved.map(|(p, _)| p);

        if ctrl.nat_table.is_loop_or_excluded(
            pid_opt,
            meta.src_ip,
            meta.src_port,
            meta.dst_ip,
            meta.dst_port,
        ) {
            Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
            return;
        }

        let (pid, res_source) = resolved.unwrap_or((0, PidResolutionSource::TcpTableFallback));
        let proc_id = ctrl.process_resolver.resolve_by_pid(pid);
        let dst_ip_str = meta.dst_ip.to_string();

        let eval = if proc_id.is_unattributed() {
            let (unknown_action, rule_name) = ctrl.resolve_unknown_process_action(
                COMPONENT_WINDIVERT,
                meta.src_port,
                &dst_ip_str,
                meta.dst_port,
                "process image unavailable",
            );
            let resolved_dom = ctrl.dns.resolve_fake_ip(&meta.dst_ip);
            crate::rules::RuleEvaluationResult {
                matched_rule_id: "security-policy-unknown-process".to_string(),
                matched_rule_name: rule_name,
                action: unknown_action,
                effective_domain: resolved_dom.clone(),
                resolved_from_fake_ip: resolved_dom.is_some(),
            }
        } else {
            ctrl.evaluate_rule(&ConnectionRequest {
                process_name: proc_id.name.clone(),
                process_path: Some(proc_id.executable_path.clone()),
                target_host: dst_ip_str.clone(),
                target_ip: Some(dst_ip_str.clone()),
                target_port: meta.dst_port,
                protocol: TransportProtocol::Udp,
            })
        };

        let is_fake_ip = ctrl.dns.is_in_fake_subnet(&meta.dst_ip);
        if matches!(eval.action, RuleAction::Direct) && !is_fake_ip {
            if !is_fragmented {
                ctrl.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_WINDIVERT,
                    format!(
                        "Routed UDP PID={} process=\"{}\" exe=\"{}\" resolvedVia={} {}:{} -> {}:{} (domain={:?}, realIp={}) via DIRECT [rule=\"{}\"]",
                        proc_id.pid,
                        proc_id.name,
                        proc_id.executable_path,
                        res_source.as_str(),
                        meta.src_ip,
                        meta.src_port,
                        meta.dst_ip,
                        meta.dst_port,
                        eval.effective_domain,
                        meta.dst_ip,
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
                        protocol: TransportProtocol::Udp,
                        matched_rule: eval.matched_rule_name,
                        route_label: "DIRECT".to_string(),
                        latency_ms: 0,
                        rx_bytes: 0,
                        tx_bytes: meta.payload_len as u64,
                        status: ConnectionStatus::Active,
                        started_at: Utc::now(),
                    },
                    true,
                );
            }
            Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
            return;
        }

        let udp_payload =
            packet[meta.payload_offset..meta.payload_offset + meta.payload_len].to_vec();
        let ctrl_async = ctrl.clone();
        let active_async = Arc::clone(active);
        let net_handle_async = Arc::clone(shared_net_handle);
        let mut reply_addr = *addr;
        let api_copy = *api;
        let proc_name = proc_id.name;
        let proc_path = proc_id.executable_path;
        let proc_pid = proc_id.pid;

        rt_handle.spawn(async move {
            let client_addr = SocketAddr::new(IpAddr::V4(meta.src_ip), meta.src_port);
            let target = Socks5UdpTarget::Ipv4(meta.dst_ip, meta.dst_port);
            let Ok(reply_bytes) = ctrl_async
                .forward_udp_datagram(
                    client_addr,
                    &proc_name,
                    Some(&proc_path),
                    proc_pid,
                    &target,
                    &udp_payload,
                    is_fragmented,
                )
                .await
            else {
                return;
            };
            if !active_async.load(Ordering::Relaxed) || reply_bytes.is_empty() {
                return;
            }
            if let Some(mut forged) = build_forged_ipv4_udp_reply(
                meta.dst_ip,
                meta.dst_port,
                meta.src_ip,
                meta.src_port,
                &reply_bytes,
            ) {
                reply_addr.set_outbound(false);
                reply_addr.clear_impostor();
                let mut send_len: u32 = 0;
                let h_ptr = net_handle_async.load(Ordering::Acquire) as *mut c_void;
                unsafe {
                    let _ = (api_copy.calc_checksums)(
                        forged.as_mut_ptr() as *mut c_void,
                        forged.len() as u32,
                        &mut reply_addr as *mut WinDivertAddress,
                        0,
                    );
                    let _ = (api_copy.send)(
                        h_ptr,
                        forged.as_ptr() as *const c_void,
                        forged.len() as u32,
                        &mut send_len,
                        &reply_addr as *const WinDivertAddress,
                    );
                }
            }
        });
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn dispatch_resolved_ipv6_syn(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &mut [u8],
        addr: &mut WinDivertAddress,
        meta: Ipv6TransportPacketMeta,
        resolved: Option<(u32, PidResolutionSource)>,
    ) {
        let relay_port = ctrl.nat_table.transparent_relay_port();
        let dns_port = ctrl.constants.dns.dns_standard_port;
        let dot_port = ctrl.constants.dns.dns_over_tls_port;
        let pid_opt = resolved.map(|(p, _)| p);

        if !ctrl.nat_table.is_loop_or_excluded(
            pid_opt,
            meta.src_ip,
            meta.src_port,
            meta.dst_ip,
            meta.dst_port,
        ) {
            if meta.dst_port == dns_port
                || (meta.dst_port == dot_port
                    && ctrl
                        .profile
                        .read()
                        .security_policy
                        .block_encrypted_dns_bypass)
            {
                return;
            }

            let (pid, res_source) = resolved.unwrap_or((0, PidResolutionSource::TcpTableFallback));
            let proc_id = ctrl.process_resolver.resolve_by_pid(pid);
            let dst_ip_str = meta.dst_ip.to_string();

            let eval = if proc_id.is_unattributed() {
                let (unknown_action, rule_name) = ctrl.resolve_unknown_process_action(
                    COMPONENT_WINDIVERT,
                    meta.src_port,
                    &dst_ip_str,
                    meta.dst_port,
                    "process image unavailable",
                );
                crate::rules::RuleEvaluationResult {
                    matched_rule_id: "security-policy-unknown-process".to_string(),
                    matched_rule_name: rule_name,
                    action: unknown_action,
                    effective_domain: None,
                    resolved_from_fake_ip: false,
                }
            } else {
                ctrl.evaluate_rule(&ConnectionRequest {
                    process_name: proc_id.name.clone(),
                    process_path: Some(proc_id.executable_path.clone()),
                    target_host: dst_ip_str.clone(),
                    target_ip: Some(dst_ip_str.clone()),
                    target_port: meta.dst_port,
                    protocol: TransportProtocol::Tcp,
                })
            };

            match &eval.action {
                RuleAction::Proxy { .. } | RuleAction::Chain { .. } => {
                    ctrl.telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_WINDIVERT,
                        format!(
                            "Intercepted IPv6 SYN PID={} process=\"{}\" exe=\"{}\" resolvedVia={} [{}]:{} -> [{}]:{} [rule=\"{}\"]",
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
                        client_ip: IpAddr::V6(meta.src_ip),
                        client_port: meta.src_port,
                        orig_dst_ip: IpAddr::V6(meta.dst_ip),
                        orig_dst_port: meta.dst_port,
                        pid: proc_id.pid,
                        process_name: proc_id.name,
                        process_path: proc_id.executable_path,
                        resolution_source: res_source,
                        action: eval.action,
                        matched_rule_name: eval.matched_rule_name,
                        created_at: Instant::now(),
                    });
                    if reflect_outbound_ipv6_to_local_relay(packet, relay_port) {
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
                            "Blocked IPv6 SYN PID={} process=\"{}\" exe=\"{}\" -> [{}]:{} [rule=\"{}\"]",
                            proc_id.pid,
                            proc_id.name,
                            proc_id.executable_path,
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
                    return;
                }
                RuleAction::Direct => {
                    let needs_sni = meta.dst_port == ctrl.constants.network.tls_sni_default_port
                        && ctrl.has_enabled_domain_rules();
                    if needs_sni {
                        ctrl.nat_table.insert_session(NatSessionEntry {
                            client_ip: IpAddr::V6(meta.src_ip),
                            client_port: meta.src_port,
                            orig_dst_ip: IpAddr::V6(meta.dst_ip),
                            orig_dst_port: meta.dst_port,
                            pid: proc_id.pid,
                            process_name: proc_id.name,
                            process_path: proc_id.executable_path,
                            resolution_source: res_source,
                            action: RuleAction::Direct,
                            matched_rule_name: eval.matched_rule_name,
                            created_at: Instant::now(),
                        });
                        if reflect_outbound_ipv6_to_local_relay(packet, relay_port) {
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
                }
            }
        }

        Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn dispatch_resolved_ipv6_udp(
        ctrl: &RouteWardController,
        active: &Arc<AtomicBool>,
        api: &WinDivertApi,
        shared_net_handle: &Arc<AtomicUsize>,
        rt_handle: &tokio::runtime::Handle,
        packet: &[u8],
        addr: &WinDivertAddress,
        meta: Ipv6TransportPacketMeta,
        resolved: Option<(u32, PidResolutionSource)>,
    ) {
        let net_handle = shared_net_handle.load(Ordering::Acquire) as *mut c_void;
        let pid_opt = resolved.map(|(p, _)| p);

        if ctrl.nat_table.is_loop_or_excluded(
            pid_opt,
            meta.src_ip,
            meta.src_port,
            meta.dst_ip,
            meta.dst_port,
        ) {
            Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
            return;
        }

        let (pid, res_source) = resolved.unwrap_or((0, PidResolutionSource::TcpTableFallback));
        let proc_id = ctrl.process_resolver.resolve_by_pid(pid);
        let dst_ip_str = meta.dst_ip.to_string();

        let eval = if proc_id.is_unattributed() {
            let (unknown_action, rule_name) = ctrl.resolve_unknown_process_action(
                COMPONENT_WINDIVERT,
                meta.src_port,
                &dst_ip_str,
                meta.dst_port,
                "process image unavailable",
            );
            crate::rules::RuleEvaluationResult {
                matched_rule_id: "security-policy-unknown-process".to_string(),
                matched_rule_name: rule_name,
                action: unknown_action,
                effective_domain: None,
                resolved_from_fake_ip: false,
            }
        } else {
            ctrl.evaluate_rule(&ConnectionRequest {
                process_name: proc_id.name.clone(),
                process_path: Some(proc_id.executable_path.clone()),
                target_host: dst_ip_str.clone(),
                target_ip: Some(dst_ip_str.clone()),
                target_port: meta.dst_port,
                protocol: TransportProtocol::Udp,
            })
        };

        if matches!(eval.action, RuleAction::Direct) {
            ctrl.telemetry.push_log(
                LogLevel::Info,
                COMPONENT_WINDIVERT,
                format!(
                    "Routed IPv6 UDP PID={} process=\"{}\" exe=\"{}\" resolvedVia={} [{}]:{} -> [{}]:{} via DIRECT [rule=\"{}\"]",
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
            ctrl.telemetry.record_connection(
                TrackedConnection {
                    id: Uuid::new_v4().to_string(),
                    pid: proc_id.pid,
                    process_name: proc_id.name,
                    process_path: proc_id.executable_path,
                    target_host: dst_ip_str,
                    resolved_domain: eval.effective_domain,
                    target_port: meta.dst_port,
                    protocol: TransportProtocol::Udp,
                    matched_rule: eval.matched_rule_name,
                    route_label: "DIRECT".to_string(),
                    latency_ms: 0,
                    rx_bytes: 0,
                    tx_bytes: meta.payload_len as u64,
                    status: ConnectionStatus::Active,
                    started_at: Utc::now(),
                },
                true,
            );
            Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
            return;
        }

        let udp_payload =
            packet[meta.payload_offset..meta.payload_offset + meta.payload_len].to_vec();
        let ctrl_async = ctrl.clone();
        let active_async = Arc::clone(active);
        let net_handle_async = Arc::clone(shared_net_handle);
        let mut reply_addr = *addr;
        let api_copy = *api;
        let proc_name = proc_id.name;
        let proc_path = proc_id.executable_path;
        let proc_pid = proc_id.pid;

        rt_handle.spawn(async move {
            let client_addr = SocketAddr::new(IpAddr::V6(meta.src_ip), meta.src_port);
            let target = Socks5UdpTarget::Ipv6(meta.dst_ip, meta.dst_port);
            let Ok(reply_bytes) = ctrl_async
                .forward_udp_datagram(
                    client_addr,
                    &proc_name,
                    Some(&proc_path),
                    proc_pid,
                    &target,
                    &udp_payload,
                    false,
                )
                .await
            else {
                return;
            };
            if !active_async.load(Ordering::Relaxed) || reply_bytes.is_empty() {
                return;
            }
            if let Some(mut forged) = build_forged_ipv6_udp_reply(
                meta.dst_ip,
                meta.dst_port,
                meta.src_ip,
                meta.src_port,
                &reply_bytes,
            ) {
                reply_addr.set_outbound(false);
                reply_addr.clear_impostor();
                let mut send_len: u32 = 0;
                let h_ptr = net_handle_async.load(Ordering::Acquire) as *mut c_void;
                unsafe {
                    let _ = (api_copy.calc_checksums)(
                        forged.as_mut_ptr() as *mut c_void,
                        forged.len() as u32,
                        &mut reply_addr as *mut WinDivertAddress,
                        0,
                    );
                    let _ = (api_copy.send)(
                        h_ptr,
                        forged.as_ptr() as *const c_void,
                        forged.len() as u32,
                        &mut send_len,
                        &reply_addr as *const WinDivertAddress,
                    );
                }
            }
        });
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

        let (rt_handle, fallback_runtime) = match tokio::runtime::Handle::try_current() {
            Ok(h) => (h, None),
            Err(_) => {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .map_err(|err| RouteWardError::InterceptorError {
                        key: ERR_KEY_INTERCEPTOR_OPEN,
                        detail: format!(
                            "Failed to create Tokio runtime for WinDivert workers: {err}"
                        ),
                    })?;
                let h = rt.handle().clone();
                (h, Some(rt))
            }
        };

        self.active.store(true, Ordering::SeqCst);
        let sock_handle_usize = socket_handle as usize;
        let net_handle_usize = network_handle as usize;
        let shared_net_handle = Arc::new(AtomicUsize::new(net_handle_usize));
        let pending_syn_queue: PendingSynQueue<(Vec<u8>, WinDivertAddress)> =
            PendingSynQueue::new();
        let pending_syn_v6_queue: PendingSynQueue<
            (Vec<u8>, WinDivertAddress),
            Ipv6TransportPacketMeta,
        > = PendingSynQueue::new();
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
            _fallback_runtime: fallback_runtime,
            firewall_rule_name,
            telemetry: controller.telemetry.clone(),
        });

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
impl WinDivertInterceptor {
    #[allow(clippy::too_many_arguments)]
    fn spawn_network_reflection_thread(
        active_net: Arc<AtomicBool>,
        ctrl_net: RouteWardController,
        api: WinDivertApi,
        recv_handle_usize: usize,
        shared_net_handle: Arc<AtomicUsize>,
        rt_handle: tokio::runtime::Handle,
        syn_queue_producer: PendingSynQueue<(Vec<u8>, WinDivertAddress)>,
        syn_v6_queue_producer: PendingSynQueue<
            (Vec<u8>, WinDivertAddress),
            Ipv6TransportPacketMeta,
        >,
        udp_queue_producer: PendingUdpQueue<(Vec<u8>, WinDivertAddress)>,
        udp_v6_queue_producer: PendingUdpQueue<
            (Vec<u8>, WinDivertAddress),
            Ipv6TransportPacketMeta,
        >,
    ) {
        let dns_port = ctrl_net.constants.dns.dns_standard_port;
        let dot_port = ctrl_net.constants.dns.dns_over_tls_port;
        let quic_port = ctrl_net.constants.network.quic_default_port;
        let mdns_port = ctrl_net.constants.network.mdns_standard_port;
        let llmnr_port = ctrl_net.constants.network.llmnr_standard_port;
        let netbios_ns_port = ctrl_net.constants.network.netbios_ns_standard_port;
        std::thread::spawn(move || {
            let handle = recv_handle_usize as *mut c_void;
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

                // Case 0: Outbound IPv6 DNS (port 53), DoT (port 853), QUIC (port 443), or mDNS/LLMNR
                if let Some(v6_meta) = parse_ipv6_transport_meta(packet) {
                    let (kill_switch_enabled, block_quic) = {
                        let prof = ctrl_net.profile.read();
                        (
                            prof.security_policy.kill_switch_enabled,
                            prof.security_policy.block_quic_udp_443,
                        )
                    };
                    if should_block_outbound_ipv6_dns_or_dot(
                        v6_meta.dst_port,
                        dns_port,
                        dot_port,
                        kill_switch_enabled,
                    ) {
                        if v6_meta.dst_port == dot_port {
                            ctrl_net.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_WINDIVERT,
                                format!(
                                    "Blocked outbound IPv6 DoT packet [{}]:{} -> [{}]:{}",
                                    v6_meta.src_ip,
                                    v6_meta.src_port,
                                    v6_meta.dst_ip,
                                    v6_meta.dst_port
                                ),
                            );
                            ctrl_net.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid: 0,
                                    process_name: "ipv6-dns".to_string(),
                                    process_path: "ipv6-dns".to_string(),
                                    target_host: v6_meta.dst_ip.to_string(),
                                    resolved_domain: None,
                                    target_port: v6_meta.dst_port,
                                    protocol: if v6_meta.next_header
                                        == crate::interceptor::nat::IPPROTO_TCP
                                    {
                                        TransportProtocol::Tcp
                                    } else {
                                        TransportProtocol::Udp
                                    },
                                    matched_rule: "SecurityPolicy:blockEncryptedDnsBypass"
                                        .to_string(),
                                    route_label: "BLOCKED".to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
                            );
                        }
                        // Drop outbound IPv6 DNS (port 53) and DoT (port 853) so Windows falls back to IPv4 DNS immediately
                        continue;
                    }
                    if v6_meta.next_header == crate::interceptor::nat::IPPROTO_UDP
                        && !ctrl_net.nat_table.is_self_udp_port(v6_meta.src_port)
                    {
                        if v6_meta.dst_port == quic_port && block_quic {
                            if let Some(mut icmp6_reply) =
                                build_forged_ipv6_icmpv6_port_unreachable(packet)
                            {
                                let mut reply_addr = addr;
                                reply_addr.set_outbound(false);
                                reply_addr.clear_impostor();
                                let mut send_len: u32 = 0;
                                unsafe {
                                    let _ = (api.calc_checksums)(
                                        icmp6_reply.as_mut_ptr() as *mut c_void,
                                        icmp6_reply.len() as u32,
                                        &mut reply_addr as *mut WinDivertAddress,
                                        0,
                                    );
                                    let _ = (api.send)(
                                        handle,
                                        icmp6_reply.as_ptr() as *const c_void,
                                        icmp6_reply.len() as u32,
                                        &mut send_len,
                                        &reply_addr as *const WinDivertAddress,
                                    );
                                }
                            }
                            continue;
                        }
                        if v6_meta.dst_port == mdns_port || v6_meta.dst_port == llmnr_port {
                            let udp_payload = &packet[v6_meta.payload_offset
                                ..v6_meta.payload_offset + v6_meta.payload_len];
                            if !matches!(
                                ctrl_net.dns.classify_local_name_query(udp_payload),
                                LocalNameQueryDecision::AllowLocal { .. }
                            ) {
                                continue;
                            }
                            Self::send_packet_guarded(
                                &ctrl_net,
                                &api,
                                handle,
                                &packet[..pkt_len],
                                &addr,
                            );
                            continue;
                        }
                        if !v6_meta.dst_ip.is_multicast()
                            && !v6_meta.dst_ip.is_loopback()
                            && !v6_meta.dst_ip.is_unicast_link_local()
                            && !ctrl_net.nat_table.is_loop_or_excluded(
                                None,
                                v6_meta.src_ip,
                                v6_meta.src_port,
                                v6_meta.dst_ip,
                                v6_meta.dst_port,
                            )
                        {
                            let resolved = ctrl_net.nat_table.try_resolve_pid_nonblocking(
                                v6_meta.src_port,
                                ProcessResolver::find_pid_for_udp_port,
                            );
                            if resolved.is_some() {
                                Self::dispatch_resolved_ipv6_udp(
                                    &ctrl_net,
                                    &active_net,
                                    &api,
                                    &shared_net_handle,
                                    &rt_handle,
                                    packet,
                                    &addr,
                                    v6_meta,
                                    resolved,
                                );
                            } else if let Some(evicted) = udp_v6_queue_producer.enqueue(
                                &ctrl_net.nat_table,
                                (packet.to_vec(), addr),
                                v6_meta,
                                false,
                                kill_switch_enabled,
                            ) {
                                ctrl_net.log_pending_udp_outcome(&evicted);
                                if let PendingUdpOutcome::TimedOutReinject {
                                    payload: (ev_pkt, ev_addr),
                                    ..
                                } = evicted
                                {
                                    Self::send_packet_guarded(
                                        &ctrl_net, &api, handle, &ev_pkt, &ev_addr,
                                    );
                                }
                            }
                            continue;
                        }
                    } else if parse_ipv6_tcp_meta(packet).is_some() {
                        if v6_meta.src_port == relay_port {
                            let Some(session) = ctrl_net
                                .nat_table
                                .get_session_by_relay_peer(v6_meta.dst_ip, v6_meta.dst_port)
                            else {
                                continue;
                            };
                            if !reflect_relay_reply_ipv6_to_client(packet, &session) {
                                continue;
                            }
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
                        } else if let Some(existing_session) = ctrl_net
                            .nat_table
                            .get_session_by_flow(&v6_meta.outbound_flow_key())
                        {
                            if matches!(
                                existing_session.action,
                                RuleAction::Proxy { .. }
                                    | RuleAction::Chain { .. }
                                    | RuleAction::Direct
                            ) && reflect_outbound_ipv6_to_local_relay(packet, relay_port)
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
                        } else if v6_meta.is_syn_only() {
                            let resolved = ctrl_net.nat_table.try_resolve_pid_nonblocking(
                                v6_meta.src_port,
                                ProcessResolver::find_pid_for_tcp_port,
                            );
                            if resolved.is_some() {
                                Self::dispatch_resolved_ipv6_syn(
                                    &ctrl_net, &api, handle, packet, &mut addr, v6_meta, resolved,
                                );
                            } else {
                                syn_v6_queue_producer.enqueue((packet.to_vec(), addr), v6_meta);
                            }
                            continue;
                        }
                        Self::send_packet_guarded(
                            &ctrl_net,
                            &api,
                            handle,
                            &packet[..pkt_len],
                            &addr,
                        );
                        continue;
                    }
                }

                // Case 1: Outbound IPv4 UDP DNS (53), DoQ (853), QUIC (443), mDNS (5353), LLMNR (5355), or NetBIOS-NS (137)
                if let Some(udp_meta) = parse_ipv4_udp_meta(packet) {
                    if !ctrl_net.nat_table.is_self_udp_port(udp_meta.src_port) {
                        if udp_meta.dst_port == dot_port
                            && ctrl_net
                                .profile
                                .read()
                                .security_policy
                                .block_encrypted_dns_bypass
                        {
                            ctrl_net.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_WINDIVERT,
                                format!(
                                    "Blocked encrypted DNS bypass (UDP port {}) {}:{} -> {}:{}",
                                    dot_port,
                                    udp_meta.src_ip,
                                    udp_meta.src_port,
                                    udp_meta.dst_ip,
                                    udp_meta.dst_port
                                ),
                            );
                            ctrl_net.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid: 0,
                                    process_name: "udp-853".to_string(),
                                    process_path: "udp-853".to_string(),
                                    target_host: udp_meta.dst_ip.to_string(),
                                    resolved_domain: None,
                                    target_port: udp_meta.dst_port,
                                    protocol: TransportProtocol::Udp,
                                    matched_rule: "SecurityPolicy:blockEncryptedDnsBypass"
                                        .to_string(),
                                    route_label: "BLOCKED".to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
                            );
                            continue;
                        }

                        // QUIC (UDP 443): reject with inbound ICMPv4 Port Unreachable (Type 3, Code 3), falling back to drop
                        if udp_meta.dst_port == quic_port
                            && ctrl_net.profile.read().security_policy.block_quic_udp_443
                        {
                            if let Some(mut icmp_reply) =
                                build_forged_ipv4_icmp_port_unreachable(packet)
                            {
                                let mut reply_addr = addr;
                                reply_addr.set_outbound(false);
                                reply_addr.clear_impostor();
                                let mut send_len: u32 = 0;
                                unsafe {
                                    let _ = (api.calc_checksums)(
                                        icmp_reply.as_mut_ptr() as *mut c_void,
                                        icmp_reply.len() as u32,
                                        &mut reply_addr as *mut WinDivertAddress,
                                        0,
                                    );
                                    let _ = (api.send)(
                                        handle,
                                        icmp_reply.as_ptr() as *const c_void,
                                        icmp_reply.len() as u32,
                                        &mut send_len,
                                        &reply_addr as *const WinDivertAddress,
                                    );
                                }
                            }
                            ctrl_net.push_rate_limited_warn(
                                &format!("quic:{}:{}", udp_meta.dst_ip, udp_meta.dst_port),
                                COMPONENT_WINDIVERT,
                                format!(
                                    "Rejected QUIC (UDP port {}) with ICMP Port Unreachable {}:{} -> {}:{} [blockQuicUdp443=true]",
                                    quic_port,
                                    udp_meta.src_ip,
                                    udp_meta.src_port,
                                    udp_meta.dst_ip,
                                    udp_meta.dst_port
                                ),
                            );
                            ctrl_net.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid: 0,
                                    process_name: "quic-udp-443".to_string(),
                                    process_path: "quic-udp-443".to_string(),
                                    target_host: udp_meta.dst_ip.to_string(),
                                    resolved_domain: ctrl_net.dns.resolve_fake_ip(&udp_meta.dst_ip),
                                    target_port: udp_meta.dst_port,
                                    protocol: TransportProtocol::Udp,
                                    matched_rule: "SecurityPolicy:blockQuicUdp443".to_string(),
                                    route_label: "BLOCKED".to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
                            );
                            continue;
                        }

                        // LLMNR (5355) and mDNS (5353): allow local names directly, block public FQDNs
                        if udp_meta.dst_port == llmnr_port || udp_meta.dst_port == mdns_port {
                            let proto_label = if udp_meta.dst_port == llmnr_port {
                                "LLMNR"
                            } else {
                                "mDNS"
                            };
                            let udp_payload = &packet[udp_meta.payload_offset
                                ..udp_meta.payload_offset + udp_meta.payload_len];
                            match ctrl_net.dns.classify_local_name_query(udp_payload) {
                                LocalNameQueryDecision::AllowLocal { qname } => {
                                    ctrl_net.telemetry.push_log(
                                        LogLevel::Debug,
                                        COMPONENT_WINDIVERT,
                                        format!(
                                            "Allowed local {proto_label} query \"{qname}\" (UDP port {}) -> {}:{}",
                                            udp_meta.dst_port, udp_meta.dst_ip, udp_meta.dst_port
                                        ),
                                    );
                                    Self::send_packet_guarded(
                                        &ctrl_net,
                                        &api,
                                        handle,
                                        &packet[..pkt_len],
                                        &addr,
                                    );
                                    continue;
                                }
                                LocalNameQueryDecision::BlockPublicFqdn { qname } => {
                                    ctrl_net.push_rate_limited_warn(
                                        &format!("{proto_label}:{qname}"),
                                        COMPONENT_WINDIVERT,
                                        format!(
                                            "Blocked public FQDN \"{qname}\" over {proto_label} (UDP port {}) {}:{} -> {}:{}",
                                            udp_meta.dst_port,
                                            udp_meta.src_ip,
                                            udp_meta.src_port,
                                            udp_meta.dst_ip,
                                            udp_meta.dst_port
                                        ),
                                    );
                                    ctrl_net.telemetry.record_connection(
                                        TrackedConnection {
                                            id: Uuid::new_v4().to_string(),
                                            pid: 0,
                                            process_name: proto_label.to_lowercase(),
                                            process_path: proto_label.to_lowercase(),
                                            target_host: udp_meta.dst_ip.to_string(),
                                            resolved_domain: Some(qname),
                                            target_port: udp_meta.dst_port,
                                            protocol: TransportProtocol::Udp,
                                            matched_rule: format!("LocalNameGuard:{proto_label}"),
                                            route_label: "BLOCKED".to_string(),
                                            latency_ms: 0,
                                            rx_bytes: 0,
                                            tx_bytes: 0,
                                            status: ConnectionStatus::Blocked,
                                            started_at: Utc::now(),
                                        },
                                        false,
                                    );
                                    continue;
                                }
                                LocalNameQueryDecision::BlockMalformed => {
                                    continue;
                                }
                            }
                        }

                        // NetBIOS-NS (137): block if targeting a non-local / public IPv4 address, allow local directly
                        if udp_meta.dst_port == netbios_ns_port {
                            if !is_private_or_local_ipv4(udp_meta.dst_ip) {
                                ctrl_net.push_rate_limited_warn(
                                    &format!("netbios:{}", udp_meta.dst_ip),
                                    COMPONENT_WINDIVERT,
                                    format!(
                                        "Blocked NetBIOS-NS (UDP port {}) toward public IP {}:{}",
                                        netbios_ns_port, udp_meta.dst_ip, udp_meta.dst_port
                                    ),
                                );
                                ctrl_net.telemetry.record_connection(
                                    TrackedConnection {
                                        id: Uuid::new_v4().to_string(),
                                        pid: 0,
                                        process_name: "netbios-ns".to_string(),
                                        process_path: "netbios-ns".to_string(),
                                        target_host: udp_meta.dst_ip.to_string(),
                                        resolved_domain: None,
                                        target_port: udp_meta.dst_port,
                                        protocol: TransportProtocol::Udp,
                                        matched_rule: "LocalNameGuard:NetBIOS".to_string(),
                                        route_label: "BLOCKED".to_string(),
                                        latency_ms: 0,
                                        rx_bytes: 0,
                                        tx_bytes: 0,
                                        status: ConnectionStatus::Blocked,
                                        started_at: Utc::now(),
                                    },
                                    false,
                                );
                                continue;
                            }
                            Self::send_packet_guarded(
                                &ctrl_net,
                                &api,
                                handle,
                                &packet[..pkt_len],
                                &addr,
                            );
                            continue;
                        }

                        if udp_meta.dst_port == dns_port {
                            ctrl_net.record_orig_dns_resolver(SocketAddr::new(
                                IpAddr::V4(udp_meta.dst_ip),
                                udp_meta.dst_port,
                            ));
                            let dns_payload = &packet[udp_meta.payload_offset
                                ..udp_meta.payload_offset + udp_meta.payload_len];
                            if let Some(fast_resp) = ctrl_net.resolve_dns_query_fast(dns_payload) {
                                let final_resp = if let Ok(parsed_q) = parse_dns_query(dns_payload)
                                {
                                    enforce_udp_truncation(
                                        &fast_resp,
                                        &parsed_q,
                                        parsed_q.max_udp_payload_bytes,
                                    )
                                } else {
                                    fast_resp
                                };
                                if let Some(mut forged) = build_forged_ipv4_udp_reply(
                                    udp_meta.dst_ip,
                                    udp_meta.dst_port,
                                    udp_meta.src_ip,
                                    udp_meta.src_port,
                                    &final_resp,
                                ) {
                                    let mut reply_addr = addr;
                                    reply_addr.set_outbound(false);
                                    reply_addr.clear_impostor();
                                    let mut send_len: u32 = 0;
                                    unsafe {
                                        let _ = (api.calc_checksums)(
                                            forged.as_mut_ptr() as *mut c_void,
                                            forged.len() as u32,
                                            &mut reply_addr as *mut WinDivertAddress,
                                            0,
                                        );
                                        let _ = (api.send)(
                                            handle,
                                            forged.as_ptr() as *const c_void,
                                            forged.len() as u32,
                                            &mut send_len,
                                            &reply_addr as *const WinDivertAddress,
                                        );
                                    }
                                }
                                continue;
                            }

                            // Slow async path (bypassed AD domain or enableFakeIp=false real DNS-over-TCP)
                            let query_vec = dns_payload.to_vec();
                            let ctrl_async = ctrl_net.clone();
                            let active_async = Arc::clone(&active_net);
                            let net_handle_async = Arc::clone(&shared_net_handle);
                            let mut reply_addr = addr;
                            let src_ip = udp_meta.src_ip;
                            let src_port = udp_meta.src_port;
                            let dst_ip = udp_meta.dst_ip;
                            let dst_port = udp_meta.dst_port;
                            let api_copy = api;
                            rt_handle.spawn(async move {
                                let orig_resolver =
                                    Some(SocketAddr::new(IpAddr::V4(dst_ip), dst_port));
                                let resp_bytes = ctrl_async
                                    .resolve_dns_query_async(&query_vec, orig_resolver, true)
                                    .await;
                                if !active_async.load(Ordering::Relaxed) || resp_bytes.is_empty() {
                                    return;
                                }
                                if let Some(mut forged) = build_forged_ipv4_udp_reply(
                                    dst_ip,
                                    dst_port,
                                    src_ip,
                                    src_port,
                                    &resp_bytes,
                                ) {
                                    reply_addr.set_outbound(false);
                                    reply_addr.clear_impostor();
                                    let mut send_len: u32 = 0;
                                    let h_ptr =
                                        net_handle_async.load(Ordering::Acquire) as *mut c_void;
                                    unsafe {
                                        let _ = (api_copy.calc_checksums)(
                                            forged.as_mut_ptr() as *mut c_void,
                                            forged.len() as u32,
                                            &mut reply_addr as *mut WinDivertAddress,
                                            0,
                                        );
                                        let _ = (api_copy.send)(
                                            h_ptr,
                                            forged.as_ptr() as *const c_void,
                                            forged.len() as u32,
                                            &mut send_len,
                                            &reply_addr as *const WinDivertAddress,
                                        );
                                    }
                                }
                            });
                            continue;
                        }

                        // General outbound IPv4 UDP interception (skipping multicast/broadcast/loopback and upstream proxy exclusions)
                        if !udp_meta.dst_ip.is_multicast()
                            && !udp_meta.dst_ip.is_broadcast()
                            && !udp_meta.dst_ip.is_loopback()
                            && !ctrl_net.nat_table.is_loop_or_excluded(
                                None,
                                udp_meta.src_ip,
                                udp_meta.src_port,
                                udp_meta.dst_ip,
                                udp_meta.dst_port,
                            )
                        {
                            let is_frag = is_ipv4_packet_fragmented(packet);
                            let resolved = ctrl_net.nat_table.try_resolve_pid_nonblocking(
                                udp_meta.src_port,
                                ProcessResolver::find_pid_for_udp_port,
                            );
                            if resolved.is_some() {
                                Self::dispatch_resolved_udp(
                                    &ctrl_net,
                                    &active_net,
                                    &api,
                                    &shared_net_handle,
                                    &rt_handle,
                                    packet,
                                    &addr,
                                    udp_meta,
                                    is_frag,
                                    resolved,
                                );
                                continue;
                            } else {
                                let kill_switch_enabled =
                                    ctrl_net.profile.read().security_policy.kill_switch_enabled;
                                if let Some(evicted) = udp_queue_producer.enqueue(
                                    &ctrl_net.nat_table,
                                    (packet.to_vec(), addr),
                                    udp_meta,
                                    is_frag,
                                    kill_switch_enabled,
                                ) {
                                    ctrl_net.log_pending_udp_outcome(&evicted);
                                    if let PendingUdpOutcome::TimedOutReinject {
                                        payload: (ev_pkt, ev_addr),
                                        ..
                                    } = evicted
                                    {
                                        Self::send_packet_guarded(
                                            &ctrl_net, &api, handle, &ev_pkt, &ev_addr,
                                        );
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }

                if let Some(meta) = parse_ipv4_tcp_meta(packet) {
                    // Case A: Outbound reply from our local transparent relay back to the client
                    if meta.src_port == relay_port {
                        let Some(session) = ctrl_net
                            .nat_table
                            .get_session_by_relay_peer(meta.dst_ip, meta.dst_port)
                        else {
                            // Never emit unreflected local relay teardown packets onto the wire
                            continue;
                        };
                        if !reflect_relay_reply_to_client(packet, &session) {
                            continue;
                        }
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
                    } else if let Some(existing_session) = ctrl_net
                        .nat_table
                        .get_session_by_flow(&meta.outbound_flow_key())
                    {
                        // Case B: Subsequent packets of an already-redirected 4-tuple flow
                        if matches!(
                            existing_session.action,
                            RuleAction::Proxy { .. }
                                | RuleAction::Chain { .. }
                                | RuleAction::Direct
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
                        let resolved = ctrl_net.nat_table.try_resolve_pid_nonblocking(
                            meta.src_port,
                            ProcessResolver::find_pid_for_tcp_port,
                        );
                        if resolved.is_some()
                            || (meta.dst_port == dns_port
                                && !ctrl_net.nat_table.is_self_tcp_port(meta.src_port))
                        {
                            Self::dispatch_resolved_syn(
                                &ctrl_net, &api, handle, packet, &mut addr, meta, resolved,
                            );
                            continue;
                        } else {
                            // Enqueue into non-blocking PendingSynQueue so the receive loop never stalls
                            syn_queue_producer.enqueue((packet.to_vec(), addr), meta);
                            continue;
                        }
                    }
                }

                Self::send_packet_guarded(&ctrl_net, &api, handle, &packet[..pkt_len], &addr);
            }
        });
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

        let filter = build_network_filter_string(53, 853);
        assert!(filter.contains("ip and (tcp or udp)"));
        assert!(filter.contains("ipv6 and (tcp or udp)"));

        // IPv6 ports 53 and 853 are blocked even when killSwitchEnabled=false
        assert!(should_block_outbound_ipv6_dns_or_dot(53, 53, 853, false));
        assert!(should_block_outbound_ipv6_dns_or_dot(853, 53, 853, false));
        assert!(!should_block_outbound_ipv6_dns_or_dot(443, 53, 853, false));
    }
}
