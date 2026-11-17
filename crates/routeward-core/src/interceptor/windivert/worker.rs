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

use super::fragments::{decide_first_udp_fragment, decide_orphan_fragment};
use super::*;
use crate::interceptor::ROUTE_DIRECT_LABEL;
use crate::process::ProcessIdentity;
use crate::telemetry::udp_flow_key;

/// One outbound datagram routed DIRECT, as recorded in telemetry.
struct DirectUdpDatagram<'a> {
    proc_id: &'a ProcessIdentity,
    res_source: PidResolutionSource,
    src: SocketAddr,
    dst: SocketAddr,
    domain: Option<&'a str>,
    rule_name: &'a str,
    payload_len: u64,
}

#[cfg(windows)]
impl WinDivertInterceptor {
    /// Records a DIRECT UDP datagram on its aggregated flow: the first datagram creates the
    /// telemetry record and an INFO log, later datagrams only update the byte counters.
    fn record_direct_udp_datagram(ctrl: &RouteWardController, dgram: &DirectUdpDatagram<'_>) {
        let flow_key = udp_flow_key(dgram.src, dgram.dst, ROUTE_DIRECT_LABEL);
        let started = ctrl.telemetry.record_udp_datagram(
            &flow_key,
            || TrackedConnection {
                id: Uuid::new_v4().to_string(),
                pid: dgram.proc_id.pid,
                process_name: dgram.proc_id.name.clone(),
                process_path: dgram.proc_id.executable_path.clone(),
                target_host: dgram.dst.ip().to_string(),
                resolved_domain: dgram.domain.map(str::to_string),
                target_port: dgram.dst.port(),
                protocol: TransportProtocol::Udp,
                matched_rule: dgram.rule_name.to_string(),
                route_label: ROUTE_DIRECT_LABEL.to_string(),
                latency_ms: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                status: ConnectionStatus::Active,
                started_at: Utc::now(),
                error_detail: None,
            },
            false,
            0,
            dgram.payload_len,
        );
        if started {
            ctrl.telemetry.push_log(
                LogLevel::Info,
                COMPONENT_WINDIVERT,
                format!(
                    "Routed UDP flow PID={} process=\"{}\" exe=\"{}\" resolvedVia={} {} -> {} (domain={:?}) via DIRECT [rule=\"{}\"]",
                    dgram.proc_id.pid,
                    dgram.proc_id.name,
                    dgram.proc_id.executable_path,
                    dgram.res_source.as_str(),
                    dgram.src,
                    dgram.dst,
                    dgram.domain,
                    dgram.rule_name
                ),
            );
        } else {
            tracing::debug!(
                component = COMPONENT_WINDIVERT,
                "UDP datagram {} -> {} ({} bytes) on existing DIRECT flow",
                dgram.src,
                dgram.dst,
                dgram.payload_len
            );
        }
    }

    #[cfg(windows)]
    fn inject_inbound_packet(
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &mut [u8],
        mut reply_addr: WinDivertAddress,
    ) {
        reply_addr.set_outbound(false);
        reply_addr.clear_impostor();
        let mut send_len: u32 = 0;
        unsafe {
            let _ = (api.calc_checksums)(
                packet.as_mut_ptr() as *mut c_void,
                packet.len() as u32,
                &mut reply_addr as *mut WinDivertAddress,
                0,
            );
            let _ = (api.send)(
                net_handle,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                &mut send_len,
                &reply_addr as *const WinDivertAddress,
            );
        }
    }

    #[cfg(windows)]
    pub(super) fn send_packet_guarded(
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
    pub(super) fn dispatch_resolved_syn(
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
                            error_detail: None,
                        },
                        false,
                    );
                    // Drop packet by skipping WinDivertSend
                    return;
                }
                RuleAction::Direct => {
                    let is_fake_ip = ctrl.dns.is_in_fake_subnet(&meta.dst_ip);
                    let needs_payload_inspection = !is_fake_ip
                        && (meta.dst_port == ctrl.constants.network.tls_sni_default_port
                            || ctrl
                                .constants
                                .network
                                .http_host_inspect_ports
                                .contains(&meta.dst_port))
                        && ctrl.has_enabled_domain_rules();
                    if is_fake_ip || needs_payload_inspection {
                        ctrl.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_WINDIVERT,
                            format!(
                                "Reflecting Direct SYN (fakeIp={}, payloadInspect={}) PID={} process=\"{}\" exe=\"{}\" resolvedVia={} {}:{} -> {}:{} [rule=\"{}\"]",
                                is_fake_ip,
                                needs_payload_inspection,
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
    pub(super) fn dispatch_resolved_udp(
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
                Self::record_direct_udp_datagram(
                    ctrl,
                    &DirectUdpDatagram {
                        proc_id: &proc_id,
                        res_source,
                        src: SocketAddr::new(IpAddr::V4(meta.src_ip), meta.src_port),
                        dst: SocketAddr::new(IpAddr::V4(meta.dst_ip), meta.dst_port),
                        domain: eval.effective_domain.as_deref(),
                        rule_name: &eval.matched_rule_name,
                        payload_len: meta.payload_len as u64,
                    },
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
    pub(super) fn dispatch_resolved_ipv6_syn(
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

        if meta.dst_port == dns_port
            && !ctrl.nat_table.is_self_pid(pid_opt)
            && !ctrl.nat_table.is_self_tcp_port(meta.src_port)
            && !meta.dst_ip.is_loopback()
            && !meta.dst_ip.is_multicast()
            && !meta.dst_ip.is_unspecified()
        {
            let (pid, res_source) = resolved.unwrap_or((0, PidResolutionSource::TcpTableFallback));
            let proc_id = ctrl.process_resolver.resolve_by_pid(pid);
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
                matched_rule_name: "DNS:LocalResolver".to_string(),
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
            Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
            return;
        }

        if !ctrl.nat_table.is_loop_or_excluded(
            pid_opt,
            meta.src_ip,
            meta.src_port,
            meta.dst_ip,
            meta.dst_port,
        ) {
            let (pid, res_source) = resolved.unwrap_or((0, PidResolutionSource::TcpTableFallback));
            let proc_id = ctrl.process_resolver.resolve_by_pid(pid);
            if should_block_outbound_ipv6_dot(
                meta.dst_port,
                dot_port,
                ctrl.profile
                    .read()
                    .security_policy
                    .block_encrypted_dns_bypass,
            ) {
                Self::record_dot_blocked(
                    ctrl,
                    TransportProtocol::Tcp,
                    pid,
                    &proc_id.name,
                    &proc_id.executable_path,
                    IpAddr::V6(meta.src_ip),
                    meta.src_port,
                    IpAddr::V6(meta.dst_ip),
                    meta.dst_port,
                );
                return;
            }
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
                            error_detail: None,
                        },
                        false,
                    );
                    return;
                }
                RuleAction::Direct => {
                    let is_fake_ip = ctrl.is_in_fake_subnet_any(&IpAddr::V6(meta.dst_ip));
                    let needs_payload_inspection = !is_fake_ip
                        && (meta.dst_port == ctrl.constants.network.tls_sni_default_port
                            || ctrl
                                .constants
                                .network
                                .http_host_inspect_ports
                                .contains(&meta.dst_port))
                        && ctrl.has_enabled_domain_rules();
                    if needs_payload_inspection {
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
    pub(super) fn dispatch_resolved_ipv6_udp(
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
            Self::record_direct_udp_datagram(
                ctrl,
                &DirectUdpDatagram {
                    proc_id: &proc_id,
                    res_source,
                    src: SocketAddr::new(IpAddr::V6(meta.src_ip), meta.src_port),
                    dst: SocketAddr::new(IpAddr::V6(meta.dst_ip), meta.dst_port),
                    domain: eval.effective_domain.as_deref(),
                    rule_name: &eval.matched_rule_name,
                    payload_len: meta.payload_len as u64,
                },
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
}

impl WinDivertInterceptor {
    /// Reports (rate limited) that the pending SYN queue was full and its oldest SYN was dropped;
    /// the client retransmits it, so the connection is delayed, never mis-routed.
    fn warn_pending_syn_overflow(ctrl: &RouteWardController, oldest_wait_ms: u64) {
        ctrl.push_rate_limited_warn(
            "pending_syn_overflow",
            COMPONENT_WINDIVERT,
            format!(
                "Pending SYN queue full (maxPendingSynPackets={}); dropped the oldest SYN after {oldest_wait_ms}ms (awaiting client retransmission)",
                ctrl.constants.network.max_pending_syn_packets
            ),
        );
    }

    /// Handles one fragment of a fragmented outbound UDP datagram.
    ///
    /// The first fragment (which carries the ports) is attributed, evaluated against the rules and
    /// given a verdict, remembered for the remaining fragments; a later fragment replays the
    /// remembered verdict and, when none exists (orphan), is dropped under the kill switch and
    /// released unchanged otherwise because it cannot be attributed on its own.
    fn handle_udp_fragment(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &[u8],
        addr: &WinDivertAddress,
        frag: &UdpFragmentMeta,
    ) {
        let verdict = match frag.kind {
            UdpFragmentKind::NonFirst => ctrl
                .nat_table
                .lookup_udp_fragment_verdict(&frag.key())
                .unwrap_or_else(|| decide_orphan_fragment(ctrl, frag)),
            UdpFragmentKind::First => {
                let verdict = Self::first_udp_fragment_verdict(ctrl, frag);
                ctrl.nat_table
                    .record_udp_fragment_verdict(frag.key(), verdict);
                verdict
            }
        };
        if verdict == UdpFragmentVerdict::Reinject {
            Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
        }
    }

    fn first_udp_fragment_verdict(
        ctrl: &RouteWardController,
        frag: &UdpFragmentMeta,
    ) -> UdpFragmentVerdict {
        let ipv6 = frag.src_ip.is_ipv6();
        let resolved = ctrl.nat_table.try_resolve_pid_nonblocking(
            SocketKey::new(IPPROTO_UDP, ipv6, frag.src_port),
            ProcessResolver::find_pid_for_udp_port,
        );
        let pid_opt = resolved.map(|(pid, _)| pid);
        if ctrl.nat_table.is_self_udp_port(frag.src_port)
            || ctrl.nat_table.is_loop_or_excluded(
                pid_opt,
                frag.src_ip,
                frag.src_port,
                frag.dst_ip,
                frag.dst_port,
            )
        {
            return UdpFragmentVerdict::Reinject;
        }

        let (block_dot, block_quic) = {
            let prof = ctrl.profile.read();
            (
                prof.security_policy.block_encrypted_dns_bypass,
                prof.security_policy.block_quic_udp_443,
            )
        };
        if (block_dot && frag.dst_port == ctrl.constants.dns.dns_over_tls_port)
            || (block_quic && frag.dst_port == ctrl.constants.network.quic_default_port)
        {
            return UdpFragmentVerdict::Drop;
        }

        let process = pid_opt.map(|pid| ctrl.process_resolver.resolve_by_pid(pid));
        let decision = decide_first_udp_fragment(ctrl, process.as_ref(), frag);
        if decision.verdict == UdpFragmentVerdict::Drop {
            ctrl.push_rate_limited_warn(
                "udp_fragment_dropped",
                COMPONENT_WINDIVERT,
                format!(
                    "Dropped fragmented UDP datagram {}:{} -> {}:{} [rule=\"{}\"]",
                    frag.src_ip, frag.src_port, frag.dst_ip, frag.dst_port, decision.rule_name
                ),
            );
        }
        decision.verdict
    }

    fn record_quic_udp_443_blocked(
        ctrl_net: &RouteWardController,
        quic_port: u16,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) {
        let icmp_proto = if dst_ip.is_ipv6() { "ICMPv6" } else { "ICMP" };
        ctrl_net.push_rate_limited_warn(
            &format!("quic:{dst_ip}:{dst_port}"),
            COMPONENT_WINDIVERT,
            format!(
                "Rejected QUIC (UDP port {quic_port}) with {icmp_proto} Port Unreachable {src_ip}:{src_port} -> {dst_ip}:{dst_port} [blockQuicUdp443=true]"
            ),
        );
        ctrl_net.telemetry.record_connection(
            TrackedConnection {
                id: Uuid::new_v4().to_string(),
                pid: 0,
                process_name: "quic-udp-443".to_string(),
                process_path: "quic-udp-443".to_string(),
                target_host: dst_ip.to_string(),
                resolved_domain: match dst_ip {
                    IpAddr::V4(v4) => ctrl_net.dns.resolve_fake_ip(&v4),
                    IpAddr::V6(_) => None,
                },
                target_port: dst_port,
                protocol: TransportProtocol::Udp,
                matched_rule: "SecurityPolicy:blockQuicUdp443".to_string(),
                route_label: "BLOCKED".to_string(),
                latency_ms: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                status: ConnectionStatus::Blocked,
                started_at: Utc::now(),
                error_detail: None,
            },
            false,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_dot_blocked(
        ctrl_net: &RouteWardController,
        protocol: TransportProtocol,
        pid: u32,
        process_name: &str,
        process_path: &str,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) {
        let proto_label = match protocol {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Any => "ANY",
        };
        ctrl_net.telemetry.push_log(
            LogLevel::Warn,
            COMPONENT_WINDIVERT,
            format!(
                "Blocked encrypted DNS bypass ({proto_label} port {dst_port}) {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            ),
        );
        ctrl_net.telemetry.record_connection(
            TrackedConnection {
                id: Uuid::new_v4().to_string(),
                pid,
                process_name: process_name.to_string(),
                process_path: process_path.to_string(),
                target_host: dst_ip.to_string(),
                resolved_domain: None,
                target_port: dst_port,
                protocol,
                matched_rule: "SecurityPolicy:blockEncryptedDnsBypass".to_string(),
                route_label: "BLOCKED".to_string(),
                latency_ms: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                status: ConnectionStatus::Blocked,
                started_at: Utc::now(),
                error_detail: None,
            },
            false,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_network_reflection_thread(
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
                    // A closed handle is expected on shutdown and when a live reload replaced this
                    // handle; any other failure leaves the interceptor blind, so report it and
                    // clear the active flag so the rest of the engine sees the interceptor stop.
                    let replaced = shared_net_handle.load(Ordering::Acquire) != recv_handle_usize;
                    if active_net.load(Ordering::Relaxed) && !replaced {
                        ctrl_net.telemetry.push_log(
                            LogLevel::Error,
                            COMPONENT_WINDIVERT,
                            "WinDivertRecv failed on the network handle; packet interception has stopped".to_string(),
                        );
                        active_net.store(false, Ordering::SeqCst);
                    }
                    break;
                }

                let pkt_len = recv_len as usize;
                let packet = &mut packet_buf[..pkt_len];

                // Fragmented UDP is detected before any UDP parsing: a first fragment whose UDP
                // length exceeds the fragment would otherwise fail to parse and be reinjected
                // without ever meeting the rules or the kill switch.
                if let Some(frag) = parse_udp_fragment_meta(packet) {
                    Self::handle_udp_fragment(
                        &ctrl_net,
                        &api,
                        handle,
                        &packet[..pkt_len],
                        &addr,
                        &frag,
                    );
                    continue;
                }

                // A later fragment that is not UDP (the filter captures every IPv6 fragment and any
                // IPv4 one) carries no transport header: its payload must never be parsed as TCP
                // or UDP, so it is released untouched.
                if is_non_first_ip_fragment(packet) {
                    Self::send_packet_guarded(&ctrl_net, &api, handle, &packet[..pkt_len], &addr);
                    continue;
                }

                // Case 0: Outbound IPv6 DNS (port 53), DoT (port 853), QUIC (port 443), or mDNS/LLMNR
                if let Some(v6_meta) = parse_ipv6_transport_meta(packet) {
                    let (kill_switch_enabled, block_encrypted_dns, block_quic) = {
                        let prof = ctrl_net.profile.read();
                        (
                            prof.security_policy.kill_switch_enabled,
                            prof.security_policy.block_encrypted_dns_bypass,
                            prof.security_policy.block_quic_udp_443,
                        )
                    };
                    if v6_meta.next_header == crate::interceptor::nat::IPPROTO_UDP
                        && !ctrl_net.nat_table.is_self_udp_port(v6_meta.src_port)
                    {
                        if should_block_outbound_ipv6_dot(
                            v6_meta.dst_port,
                            dot_port,
                            block_encrypted_dns,
                        ) && !ctrl_net.nat_table.is_loop_or_excluded(
                            None,
                            v6_meta.src_ip,
                            v6_meta.src_port,
                            v6_meta.dst_ip,
                            v6_meta.dst_port,
                        ) {
                            Self::record_dot_blocked(
                                &ctrl_net,
                                TransportProtocol::Udp,
                                0,
                                "ipv6-dns",
                                "ipv6-dns",
                                IpAddr::V6(v6_meta.src_ip),
                                v6_meta.src_port,
                                IpAddr::V6(v6_meta.dst_ip),
                                v6_meta.dst_port,
                            );
                            continue;
                        }
                        if v6_meta.dst_port == quic_port && block_quic {
                            if let Some(mut icmp6_reply) =
                                build_forged_ipv6_icmpv6_port_unreachable(packet)
                            {
                                Self::inject_inbound_packet(&api, handle, &mut icmp6_reply, addr);
                            }
                            Self::record_quic_udp_443_blocked(
                                &ctrl_net,
                                quic_port,
                                IpAddr::V6(v6_meta.src_ip),
                                v6_meta.src_port,
                                IpAddr::V6(v6_meta.dst_ip),
                                v6_meta.dst_port,
                            );
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
                        if v6_meta.dst_port == dns_port
                            && !v6_meta.dst_ip.is_loopback()
                            && !v6_meta.dst_ip.is_multicast()
                            && !v6_meta.dst_ip.is_unspecified()
                        {
                            ctrl_net.record_orig_dns_resolver(SocketAddr::new(
                                IpAddr::V6(v6_meta.dst_ip),
                                v6_meta.dst_port,
                            ));
                            let dns_payload = &packet[v6_meta.payload_offset
                                ..v6_meta.payload_offset + v6_meta.payload_len];
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
                                if let Some(mut forged) = build_forged_ipv6_udp_reply(
                                    v6_meta.dst_ip,
                                    v6_meta.dst_port,
                                    v6_meta.src_ip,
                                    v6_meta.src_port,
                                    &final_resp,
                                ) {
                                    Self::inject_inbound_packet(&api, handle, &mut forged, addr);
                                }
                                continue;
                            }

                            let query_vec = dns_payload.to_vec();
                            let ctrl_async = ctrl_net.clone();
                            let active_async = Arc::clone(&active_net);
                            let net_handle_async = Arc::clone(&shared_net_handle);
                            let reply_addr = addr;
                            let src_ip = v6_meta.src_ip;
                            let src_port = v6_meta.src_port;
                            let dst_ip = v6_meta.dst_ip;
                            let dst_port = v6_meta.dst_port;
                            let api_copy = api;
                            rt_handle.spawn(async move {
                                let orig_resolver =
                                    Some(SocketAddr::new(IpAddr::V6(dst_ip), dst_port));
                                let resp_bytes = ctrl_async
                                    .resolve_dns_query_async(&query_vec, orig_resolver, true)
                                    .await;
                                if !active_async.load(Ordering::Relaxed) || resp_bytes.is_empty() {
                                    return;
                                }
                                if let Some(mut forged) = build_forged_ipv6_udp_reply(
                                    dst_ip,
                                    dst_port,
                                    src_ip,
                                    src_port,
                                    &resp_bytes,
                                ) {
                                    let h_ptr =
                                        net_handle_async.load(Ordering::Acquire) as *mut c_void;
                                    Self::inject_inbound_packet(
                                        &api_copy,
                                        h_ptr,
                                        &mut forged,
                                        reply_addr,
                                    );
                                }
                            });
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
                                SocketKey::new(IPPROTO_UDP, true, v6_meta.src_port),
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
                                SocketKey::new(IPPROTO_TCP, true, v6_meta.src_port),
                                ProcessResolver::find_pid_for_tcp_port,
                            );
                            if resolved.is_some()
                                || (v6_meta.dst_port == dns_port
                                    && !ctrl_net.nat_table.is_self_tcp_port(v6_meta.src_port))
                            {
                                Self::dispatch_resolved_ipv6_syn(
                                    &ctrl_net, &api, handle, packet, &mut addr, v6_meta, resolved,
                                );
                            } else {
                                if let Some(evicted) =
                                    syn_v6_queue_producer.enqueue((packet.to_vec(), addr), v6_meta)
                                {
                                    Self::warn_pending_syn_overflow(
                                        &ctrl_net,
                                        evicted.enqueued_at.elapsed().as_millis() as u64,
                                    );
                                }
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
                            && !ctrl_net.nat_table.is_loop_or_excluded(
                                None,
                                udp_meta.src_ip,
                                udp_meta.src_port,
                                udp_meta.dst_ip,
                                udp_meta.dst_port,
                            )
                        {
                            Self::record_dot_blocked(
                                &ctrl_net,
                                TransportProtocol::Udp,
                                0,
                                "udp-853",
                                "udp-853",
                                IpAddr::V4(udp_meta.src_ip),
                                udp_meta.src_port,
                                IpAddr::V4(udp_meta.dst_ip),
                                udp_meta.dst_port,
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
                            Self::record_quic_udp_443_blocked(
                                &ctrl_net,
                                quic_port,
                                IpAddr::V4(udp_meta.src_ip),
                                udp_meta.src_port,
                                IpAddr::V4(udp_meta.dst_ip),
                                udp_meta.dst_port,
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
                                            error_detail: None,
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
                                        error_detail: None,
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
                                SocketKey::new(IPPROTO_UDP, false, udp_meta.src_port),
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
                            SocketKey::new(IPPROTO_TCP, false, meta.src_port),
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
                            if let Some(evicted) =
                                syn_queue_producer.enqueue((packet.to_vec(), addr), meta)
                            {
                                Self::warn_pending_syn_overflow(
                                    &ctrl_net,
                                    evicted.enqueued_at.elapsed().as_millis() as u64,
                                );
                            }
                            continue;
                        }
                    }
                }

                Self::send_packet_guarded(&ctrl_net, &api, handle, &packet[..pkt_len], &addr);
            }
        });
    }
}
