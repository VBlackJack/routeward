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

use super::fragments::{
    decide_first_udp_fragment, decide_orphan_fragment, first_fragment_is_dns_query,
    is_dns_query_header,
};
use super::icmp_limit::{IcmpFlowKey, IcmpRateLimiter};
use super::*;
use crate::interceptor::dns_server_exempt::{
    blocked_dns_connection_record, dns_server_block_match, DnsProto,
};
use crate::interceptor::policy::{
    block_reason_for_decision, ENCRYPTED_DNS_POLICY_RULE_ID, ENCRYPTED_DNS_POLICY_RULE_NAME,
    QUIC_POLICY_RULE_ID, QUIC_POLICY_RULE_NAME, QUIC_PROCESS_NAME, UNKNOWN_PROCESS_RULE_ID,
};
use crate::interceptor::ROUTE_DIRECT_LABEL;
use crate::process::ProcessIdentity;
use crate::telemetry::{udp_flow_key, BlockReason, BlockedRecord};

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

/// What the data path does with a flow that belongs to a DNS server process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsServerFlowAction {
    /// Send the packet unmodified: no Fake-IP, no NAT session.
    Pass,
    /// An explicit Block rule that names the process drops the packet.
    Drop,
}

/// Capacity of the queue between the socket-layer listener and the DNS server PID resolver.
const DNS_SERVER_PID_QUEUE_LEN: usize = 256;
/// A PID already looked at is not resolved again before this delay.
const DNS_SERVER_PID_RECHECK: Duration = Duration::from_secs(60);
/// Upper bound of the PIDs remembered by the DNS server PID resolver.
const DNS_SERVER_PID_MAX_CHECKED: usize = 4096;
/// Rate-limit category of the per-query exemption log.
const DNS_SERVER_PASS_LOG_KEY: &str = "dns_server_exempt_pass";
/// Rate-limit category of the per-query block log.
const DNS_SERVER_BLOCK_LOG_KEY: &str = "dns_server_exempt_block";
/// Rate-limit category of the failed packet injection warning.
#[cfg(windows)]
const WINDIVERT_INJECT_FAILED_LOG_KEY: &str = "windivert_inject_failed";

impl WinDivertInterceptor {
    /// Decides whether a port-53 flow of local port `src_port` belongs to a DNS server process.
    ///
    /// Receive-thread safe: only the tracker's port and PID sets and the socket-layer PID cache
    /// are read, never a socket table. `resolved_pid` is the PID the caller already resolved. Costs
    /// one atomic load when no DNS server process is known.
    fn dns_server_flow_action(
        ctrl: &RouteWardController,
        proto: DnsProto,
        src_ip: IpAddr,
        src_port: u16,
        resolved_pid: Option<u32>,
        dst: IpAddr,
    ) -> Option<DnsServerFlowAction> {
        let tracker = &ctrl.dns_server_tracker;
        if tracker.is_empty() {
            return None;
        }
        let protocol = match proto {
            DnsProto::Udp => IPPROTO_UDP,
            DnsProto::Tcp => IPPROTO_TCP,
        };
        // A dual-stack socket is reported on the IPv6 family while it may send IPv4: look at both.
        let ipv6 = src_ip.is_ipv6();
        let pid = resolved_pid.or_else(|| {
            [ipv6, !ipv6].into_iter().find_map(|v6| {
                ctrl.nat_table
                    .try_resolve_pid_nonblocking(SocketKey::new(protocol, v6, src_port), |_| None)
                    .map(|(pid, _)| pid)
            })
        });
        // A known owner decides alone: a port left in the set by a closed socket must not exempt
        // another process that reused the number before the next rescan. Without a known owner,
        // the socket table owner of the port (matched on family and local address) decides.
        let owner = match pid {
            Some(pid) => tracker.is_exempt_pid(pid).then_some(pid),
            None => tracker.exempt_port_owner(proto, src_port, src_ip),
        };
        let owner = owner?;
        // The owner PID resolves the real process, so an explicit Block rule that names the DNS
        // server still matches and the logs show its PID and name.
        // The tracker already knows the image name: fall back to it so a failing image query is
        // cached by the resolver instead of being repeated for every packet on this thread.
        let identity = match tracker.pid_name(owner) {
            Some(name) => ctrl
                .process_resolver
                .resolve_by_pid_with_fallback(owner, &name),
            None => ctrl.process_resolver.resolve_by_pid(owner),
        };
        let block_rule = {
            let prof = ctrl.profile.read();
            dns_server_block_match(&prof.rules, &prof.default_action, &identity, dst, proto)
        };
        if let Some((rule_id, rule_name)) = block_rule {
            ctrl.push_rate_limited_warn(
                DNS_SERVER_BLOCK_LOG_KEY,
                COMPONENT_WINDIVERT,
                format!(
                    "Blocked DNS server query PID={} process=\"{}\" -> {}:53 [rule=\"{}\"]",
                    identity.pid, identity.name, dst, rule_name
                ),
            );
            ctrl.telemetry.record_connection(
                blocked_dns_connection_record(&identity, dst, proto, rule_name, Some(rule_id)),
                false,
            );
            return Some(DnsServerFlowAction::Drop);
        }
        tracing::debug!(
            component = COMPONENT_WINDIVERT,
            "DNS server query passed through PID={} process=\"{}\" src_port={} -> {}:53",
            identity.pid,
            identity.name,
            src_port,
            dst
        );
        ctrl.push_rate_limited_info(
            DNS_SERVER_PASS_LOG_KEY,
            COMPONENT_WINDIVERT,
            format!(
                "DNS server query passed through unmodified PID={} process=\"{}\" -> {}:53",
                identity.pid, identity.name, dst
            ),
        );
        Some(DnsServerFlowAction::Pass)
    }

    /// Handles an outbound UDP port-53 datagram of a DNS server process: `true` when it was
    /// consumed (passed unmodified or dropped), `false` when the normal DNS path must go on.
    #[allow(clippy::too_many_arguments)]
    fn handle_dns_server_udp(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &[u8],
        addr: &WinDivertAddress,
        src_ip: IpAddr,
        src_port: u16,
        dst: IpAddr,
        payload: &[u8],
    ) -> bool {
        if !is_dns_query_header(payload) {
            return false;
        }
        match Self::dns_server_flow_action(ctrl, DnsProto::Udp, src_ip, src_port, None, dst) {
            None => false,
            Some(DnsServerFlowAction::Pass) => {
                Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
                true
            }
            Some(DnsServerFlowAction::Drop) => true,
        }
    }

    /// Handles the SYN of an outbound TCP port-53 flow of a DNS server process: `true` when it was
    /// consumed. Any stale NAT session of the same 4-tuple is removed first so that later
    /// segments are not reflected to the relay.
    #[allow(clippy::too_many_arguments)]
    fn handle_dns_server_syn(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &[u8],
        addr: &WinDivertAddress,
        flow_key: &crate::interceptor::nat::OutboundFlowKey,
        src_ip: IpAddr,
        src_port: u16,
        dst: IpAddr,
        resolved_pid: Option<u32>,
    ) -> bool {
        let Some(action) =
            Self::dns_server_flow_action(ctrl, DnsProto::Tcp, src_ip, src_port, resolved_pid, dst)
        else {
            return false;
        };
        ctrl.nat_table.remove_session_by_flow(flow_key);
        if action == DnsServerFlowAction::Pass {
            Self::send_packet_guarded(ctrl, api, net_handle, packet, addr);
        }
        true
    }
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
                block_reason: None,
                matched_rule_id: None,
                proxy_id: None,
                target_ip: None,
                simulated: false,
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

    /// `true` when an ICMP rejection may be injected for this flow now: at most one per flow and
    /// window, so a retransmitting application cannot make RouteWard forge a message per packet.
    fn icmp_rejection_allowed(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> bool {
        static LIMITER: std::sync::LazyLock<IcmpRateLimiter> =
            std::sync::LazyLock::new(IcmpRateLimiter::new);
        LIMITER.allow(
            IcmpFlowKey {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            },
            Instant::now(),
        )
    }

    /// Injects `packet` toward the local stack as an inbound packet, copying the interface indexes of
    /// `reply_addr`. Returns `false` and logs a rate-limited warning when `WinDivertSend` fails, so a
    /// silently failing injection is visible instead of looking like a plain drop.
    #[cfg(windows)]
    fn inject_inbound_packet(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &mut [u8],
        mut reply_addr: WinDivertAddress,
    ) -> bool {
        reply_addr.set_outbound(false);
        reply_addr.clear_impostor();
        let mut send_len: u32 = 0;
        let sent = unsafe {
            let _ = (api.calc_checksums)(
                packet.as_mut_ptr() as *mut c_void,
                packet.len() as u32,
                &mut reply_addr as *mut WinDivertAddress,
                0,
            );
            (api.send)(
                net_handle,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                &mut send_len,
                &reply_addr as *const WinDivertAddress,
            )
        };
        if sent != 0 {
            return true;
        }
        let os_error = std::io::Error::last_os_error();
        ctrl.push_rate_limited_warn(
            WINDIVERT_INJECT_FAILED_LOG_KEY,
            COMPONENT_WINDIVERT,
            format!(
                "WinDivertSend failed to inject a {}-byte inbound packet: {}",
                packet.len(),
                os_error
            ),
        );
        false
    }

    /// Refuses a blocked outbound SYN at once with an injected TCP RST, so the application gets
    /// "connection refused" instead of waiting for its connect timeout. Best effort: the SYN is
    /// never forwarded either way, and a SYN that cannot be answered stays a silent drop.
    #[cfg(windows)]
    fn reject_blocked_syn(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &[u8],
        addr: &WinDivertAddress,
    ) {
        let rst = match packet.first().map(|b| b >> 4) {
            Some(4) => build_forged_ipv4_tcp_rst(packet),
            Some(6) => build_forged_ipv6_tcp_rst(packet),
            _ => None,
        };
        if let Some(mut rst) = rst {
            Self::inject_inbound_packet(ctrl, api, net_handle, &mut rst, *addr);
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

    /// Case B guard (IPv4): a SYN whose flow key already has a NAT session must still meet the DNS
    /// server handling first, otherwise the stale session reflects it to the relay and the session
    /// is never removed. `true` when the SYN was consumed.
    #[cfg(windows)]
    fn dns_server_syn_before_session(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &[u8],
        addr: &WinDivertAddress,
        meta: &Ipv4TcpPacketMeta,
    ) -> bool {
        if !meta.is_syn_only()
            || meta.dst_port != ctrl.constants.dns.dns_standard_port
            || ctrl.dns_server_tracker.is_empty()
            || ctrl.nat_table.is_self_tcp_port(meta.src_port)
        {
            return false;
        }
        let pid_opt = ctrl
            .nat_table
            .try_resolve_pid_nonblocking(
                SocketKey::new(IPPROTO_TCP, false, meta.src_port),
                ProcessResolver::find_pid_for_tcp_port,
            )
            .map(|(pid, _)| pid);
        if ctrl.nat_table.is_self_pid(pid_opt)
            || meta.dst_ip.is_loopback()
            || meta.dst_ip.is_multicast()
            || meta.dst_ip.is_unspecified()
        {
            return false;
        }
        Self::handle_dns_server_syn(
            ctrl,
            api,
            net_handle,
            packet,
            addr,
            &meta.outbound_flow_key(),
            IpAddr::V4(meta.src_ip),
            meta.src_port,
            IpAddr::V4(meta.dst_ip),
            pid_opt,
        )
    }

    /// IPv6 twin of [`Self::dns_server_syn_before_session`].
    #[cfg(windows)]
    fn dns_server_syn_before_session_v6(
        ctrl: &RouteWardController,
        api: &WinDivertApi,
        net_handle: *mut c_void,
        packet: &[u8],
        addr: &WinDivertAddress,
        meta: &Ipv6TransportPacketMeta,
    ) -> bool {
        if !meta.is_syn_only()
            || meta.dst_port != ctrl.constants.dns.dns_standard_port
            || ctrl.dns_server_tracker.is_empty()
            || ctrl.nat_table.is_self_tcp_port(meta.src_port)
        {
            return false;
        }
        let pid_opt = ctrl
            .nat_table
            .try_resolve_pid_nonblocking(
                SocketKey::new(IPPROTO_TCP, true, meta.src_port),
                ProcessResolver::find_pid_for_tcp_port,
            )
            .map(|(pid, _)| pid);
        if ctrl.nat_table.is_self_pid(pid_opt)
            || meta.dst_ip.is_loopback()
            || meta.dst_ip.is_multicast()
            || meta.dst_ip.is_unspecified()
        {
            return false;
        }
        Self::handle_dns_server_syn(
            ctrl,
            api,
            net_handle,
            packet,
            addr,
            &meta.outbound_flow_key(),
            IpAddr::V6(meta.src_ip),
            meta.src_port,
            IpAddr::V6(meta.dst_ip),
            pid_opt,
        )
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

        // A DNS server process gets real answers: its TCP port-53 flows never enter the relay.
        if meta.dst_port == dns_port
            && !ctrl.nat_table.is_self_pid(pid_opt)
            && !meta.dst_ip.is_loopback()
            && !meta.dst_ip.is_multicast()
            && !meta.dst_ip.is_unspecified()
            && Self::handle_dns_server_syn(
                ctrl,
                api,
                net_handle,
                packet,
                addr,
                &meta.outbound_flow_key(),
                IpAddr::V4(meta.src_ip),
                meta.src_port,
                IpAddr::V4(meta.dst_ip),
                pid_opt,
            )
        {
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
                    matched_rule_id: UNKNOWN_PROCESS_RULE_ID.to_string(),
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
                eval.matched_rule_name = ENCRYPTED_DNS_POLICY_RULE_NAME.to_string();
                eval.matched_rule_id = ENCRYPTED_DNS_POLICY_RULE_ID.to_string();
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
                        TrackedConnection::blocked(
                            BlockedRecord::new(
                                block_reason_for_decision(
                                    Some(&eval.matched_rule_id),
                                    &eval.matched_rule_name,
                                ),
                                TransportProtocol::Tcp,
                                eval.matched_rule_name,
                            )
                            .process(proc_id.name, proc_id.executable_path, proc_id.pid)
                            .target(dst_ip_str.clone(), meta.dst_port)
                            .with_ip(Some(dst_ip_str))
                            .with_domain(eval.effective_domain)
                            .with_rule_id(eval.matched_rule_id),
                        ),
                        false,
                    );
                    // The SYN is never forwarded; the application is refused at once instead.
                    Self::reject_blocked_syn(ctrl, api, net_handle, packet, addr);
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
                matched_rule_id: UNKNOWN_PROCESS_RULE_ID.to_string(),
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

        // A Block rule refuses the datagram with ICMP Port Unreachable, like a closed port. The
        // spawned forwarder below still records the block; fragments stay a silent drop.
        if matches!(eval.action, RuleAction::Block)
            && !is_fragmented
            && Self::icmp_rejection_allowed(
                IpAddr::V4(meta.src_ip),
                meta.src_port,
                IpAddr::V4(meta.dst_ip),
                meta.dst_port,
            )
        {
            if let Some(mut icmp_reply) = build_forged_ipv4_icmp_port_unreachable(packet) {
                Self::inject_inbound_packet(ctrl, api, net_handle, &mut icmp_reply, *addr);
            }
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

        // A DNS server process gets real answers: its TCP port-53 flows never enter the relay.
        if meta.dst_port == dns_port
            && !ctrl.nat_table.is_self_pid(pid_opt)
            && !meta.dst_ip.is_loopback()
            && !meta.dst_ip.is_multicast()
            && !meta.dst_ip.is_unspecified()
            && Self::handle_dns_server_syn(
                ctrl,
                api,
                net_handle,
                packet,
                addr,
                &meta.outbound_flow_key(),
                IpAddr::V6(meta.src_ip),
                meta.src_port,
                IpAddr::V6(meta.dst_ip),
                pid_opt,
            )
        {
            return;
        }

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
                Self::reject_blocked_syn(ctrl, api, net_handle, packet, addr);
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
                    matched_rule_id: UNKNOWN_PROCESS_RULE_ID.to_string(),
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
                        TrackedConnection::blocked(
                            BlockedRecord::new(
                                block_reason_for_decision(
                                    Some(&eval.matched_rule_id),
                                    &eval.matched_rule_name,
                                ),
                                TransportProtocol::Tcp,
                                eval.matched_rule_name,
                            )
                            .process(proc_id.name, proc_id.executable_path, proc_id.pid)
                            .target(dst_ip_str.clone(), meta.dst_port)
                            .with_ip(Some(dst_ip_str))
                            .with_domain(eval.effective_domain)
                            .with_rule_id(eval.matched_rule_id),
                        ),
                        false,
                    );
                    Self::reject_blocked_syn(ctrl, api, net_handle, packet, addr);
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
                matched_rule_id: UNKNOWN_PROCESS_RULE_ID.to_string(),
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

        // A Block rule refuses the datagram with ICMP Port Unreachable, like a closed port. The
        // spawned forwarder below still records the block.
        if matches!(eval.action, RuleAction::Block)
            && Self::icmp_rejection_allowed(
                IpAddr::V6(meta.src_ip),
                meta.src_port,
                IpAddr::V6(meta.dst_ip),
                meta.dst_port,
            )
        {
            if let Some(mut icmp6_reply) = build_forged_ipv6_icmpv6_port_unreachable(packet) {
                Self::inject_inbound_packet(ctrl, api, net_handle, &mut icmp6_reply, *addr);
            }
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
                let verdict = Self::first_udp_fragment_verdict(ctrl, packet, frag);
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
        packet: &[u8],
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

        // A first fragment of a DNS server query follows the same rule as an unfragmented one,
        // including the DNS header check: a response or a short payload is not a query.
        let is_dns_query = first_fragment_is_dns_query(packet, frag);
        if frag.dst_port == ctrl.constants.dns.dns_standard_port && is_dns_query {
            match Self::dns_server_flow_action(
                ctrl,
                DnsProto::Udp,
                frag.src_ip,
                frag.src_port,
                pid_opt,
                frag.dst_ip,
            ) {
                Some(DnsServerFlowAction::Pass) => return UdpFragmentVerdict::Reinject,
                Some(DnsServerFlowAction::Drop) => return UdpFragmentVerdict::Drop,
                None => {}
            }
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
        ctrl_net.record_blocked_udp(
            SocketAddr::new(src_ip, src_port),
            BlockedRecord::new(
                BlockReason::QuicBlocked,
                TransportProtocol::Udp,
                QUIC_POLICY_RULE_NAME,
            )
            .process(QUIC_PROCESS_NAME, QUIC_PROCESS_NAME, 0)
            .target(dst_ip.to_string(), dst_port)
            .with_ip(Some(dst_ip.to_string()))
            .with_domain(match dst_ip {
                IpAddr::V4(v4) => ctrl_net.dns.resolve_fake_ip(&v4),
                IpAddr::V6(_) => None,
            })
            .with_rule_id(QUIC_POLICY_RULE_ID),
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
        let record = BlockedRecord::new(
            BlockReason::EncryptedDnsBlocked,
            protocol,
            ENCRYPTED_DNS_POLICY_RULE_NAME,
        )
        .process(process_name, process_path, pid)
        .target(dst_ip.to_string(), dst_port)
        .with_ip(Some(dst_ip.to_string()))
        .with_rule_id(ENCRYPTED_DNS_POLICY_RULE_ID);
        if protocol == TransportProtocol::Udp {
            ctrl_net.record_blocked_udp(SocketAddr::new(src_ip, src_port), record);
        } else {
            ctrl_net
                .telemetry
                .record_connection(TrackedConnection::blocked(record), false);
        }
    }

    /// Starts the helper that recognises a DNS server process the periodic rescan has not seen
    /// yet (for example a `dns.exe` that was just restarted): the socket-layer listener hands it
    /// the PID of every socket event, and the helper resolves the image (a cached call) and
    /// registers a matching PID at once. Returns the sender for the listener; a full queue drops
    /// the PID, which only delays the exemption until the next rescan. The thread ends when the
    /// sender is dropped.
    pub(super) fn spawn_dns_server_pid_resolver(
        ctrl: RouteWardController,
    ) -> std::sync::mpsc::SyncSender<u32> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<u32>(DNS_SERVER_PID_QUEUE_LEN);
        std::thread::spawn(move || {
            let mut checked: std::collections::HashMap<u32, Instant> =
                std::collections::HashMap::new();
            while let Ok(pid) = rx.recv() {
                if ctrl.dns_server_tracker.is_exempt_pid(pid) {
                    continue;
                }
                let now = Instant::now();
                if checked
                    .get(&pid)
                    .is_some_and(|at| now.duration_since(*at) < DNS_SERVER_PID_RECHECK)
                {
                    continue;
                }
                if checked.len() >= DNS_SERVER_PID_MAX_CHECKED {
                    checked.retain(|_, at| now.duration_since(*at) < DNS_SERVER_PID_RECHECK);
                    if checked.len() >= DNS_SERVER_PID_MAX_CHECKED {
                        checked.clear();
                    }
                }
                checked.insert(pid, now);
                let identity = ctrl.process_resolver.resolve_by_pid(pid);
                if identity.is_unattributed() {
                    continue;
                }
                ctrl.dns_server_tracker
                    .note_unknown_pid(pid, &identity.executable_path);
            }
        });
        tx
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
                            if Self::icmp_rejection_allowed(
                                IpAddr::V6(v6_meta.src_ip),
                                v6_meta.src_port,
                                IpAddr::V6(v6_meta.dst_ip),
                                v6_meta.dst_port,
                            ) {
                                if let Some(mut icmp6_reply) =
                                    build_forged_ipv6_icmpv6_port_unreachable(packet)
                                {
                                    Self::inject_inbound_packet(
                                        &ctrl_net,
                                        &api,
                                        handle,
                                        &mut icmp6_reply,
                                        addr,
                                    );
                                }
                            }
                            continue;
                        }
                        if v6_meta.dst_port == quic_port && block_quic {
                            if Self::icmp_rejection_allowed(
                                IpAddr::V6(v6_meta.src_ip),
                                v6_meta.src_port,
                                IpAddr::V6(v6_meta.dst_ip),
                                v6_meta.dst_port,
                            ) {
                                if let Some(mut icmp6_reply) =
                                    build_forged_ipv6_icmpv6_port_unreachable(packet)
                                {
                                    Self::inject_inbound_packet(
                                        &ctrl_net,
                                        &api,
                                        handle,
                                        &mut icmp6_reply,
                                        addr,
                                    );
                                }
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
                            if Self::handle_dns_server_udp(
                                &ctrl_net,
                                &api,
                                handle,
                                &packet[..pkt_len],
                                &addr,
                                IpAddr::V6(v6_meta.src_ip),
                                v6_meta.src_port,
                                IpAddr::V6(v6_meta.dst_ip),
                                &packet[v6_meta.payload_offset
                                    ..v6_meta.payload_offset + v6_meta.payload_len],
                            ) {
                                continue;
                            }
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
                                    Self::inject_inbound_packet(
                                        &ctrl_net,
                                        &api,
                                        handle,
                                        &mut forged,
                                        addr,
                                    );
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
                                        &ctrl_async,
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
                        } else if Self::dns_server_syn_before_session_v6(
                            &ctrl_net, &api, handle, packet, &addr, &v6_meta,
                        ) {
                            // Case B0 (IPv6): see the IPv4 twin.
                            continue;
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
                            if Self::icmp_rejection_allowed(
                                IpAddr::V4(udp_meta.src_ip),
                                udp_meta.src_port,
                                IpAddr::V4(udp_meta.dst_ip),
                                udp_meta.dst_port,
                            ) {
                                if let Some(mut icmp_reply) =
                                    build_forged_ipv4_icmp_port_unreachable(packet)
                                {
                                    Self::inject_inbound_packet(
                                        &ctrl_net,
                                        &api,
                                        handle,
                                        &mut icmp_reply,
                                        addr,
                                    );
                                }
                            }
                            continue;
                        }

                        // QUIC (UDP 443): reject with inbound ICMPv4 Port Unreachable (Type 3, Code 3), falling back to drop
                        if udp_meta.dst_port == quic_port
                            && ctrl_net.profile.read().security_policy.block_quic_udp_443
                        {
                            if Self::icmp_rejection_allowed(
                                IpAddr::V4(udp_meta.src_ip),
                                udp_meta.src_port,
                                IpAddr::V4(udp_meta.dst_ip),
                                udp_meta.dst_port,
                            ) {
                                if let Some(mut icmp_reply) =
                                    build_forged_ipv4_icmp_port_unreachable(packet)
                                {
                                    Self::inject_inbound_packet(
                                        &ctrl_net,
                                        &api,
                                        handle,
                                        &mut icmp_reply,
                                        addr,
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
                                    ctrl_net.record_blocked_udp(
                                        SocketAddr::new(
                                            IpAddr::V4(udp_meta.src_ip),
                                            udp_meta.src_port,
                                        ),
                                        BlockedRecord::new(
                                            BlockReason::LocalNameGuard,
                                            TransportProtocol::Udp,
                                            format!("LocalNameGuard:{proto_label}"),
                                        )
                                        .process(
                                            proto_label.to_lowercase(),
                                            proto_label.to_lowercase(),
                                            0,
                                        )
                                        .target(udp_meta.dst_ip.to_string(), udp_meta.dst_port)
                                        .with_ip(Some(udp_meta.dst_ip.to_string()))
                                        .with_domain(Some(qname)),
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
                                ctrl_net.record_blocked_udp(
                                    SocketAddr::new(IpAddr::V4(udp_meta.src_ip), udp_meta.src_port),
                                    BlockedRecord::new(
                                        BlockReason::LocalNameGuard,
                                        TransportProtocol::Udp,
                                        "LocalNameGuard:NetBIOS",
                                    )
                                    .process("netbios-ns", "netbios-ns", 0)
                                    .target(udp_meta.dst_ip.to_string(), udp_meta.dst_port)
                                    .with_ip(Some(udp_meta.dst_ip.to_string())),
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
                            if Self::handle_dns_server_udp(
                                &ctrl_net,
                                &api,
                                handle,
                                &packet[..pkt_len],
                                &addr,
                                IpAddr::V4(udp_meta.src_ip),
                                udp_meta.src_port,
                                IpAddr::V4(udp_meta.dst_ip),
                                &packet[udp_meta.payload_offset
                                    ..udp_meta.payload_offset + udp_meta.payload_len],
                            ) {
                                continue;
                            }
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
                    } else if Self::dns_server_syn_before_session(
                        &ctrl_net, &api, handle, packet, &addr, &meta,
                    ) {
                        // Case B0: a DNS server SYN reusing a flow key that still has a stale
                        // session: the handler removed the session and sent the SYN unmodified.
                        continue;
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
