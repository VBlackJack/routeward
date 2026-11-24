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

use super::dns_handler::DnsReplyCheck;
use super::policy::{
    block_reason_for_decision, block_reason_for_rule, port_policy_override,
    FRAGMENTED_UDP_RULE_NAME, LOCAL_NAME_GUARD_RULE_NAME, LOCAL_NAME_PROCESS_NAME,
};
use super::{
    RouteWardController, COMPONENT_DNS, COMPONENT_ENGINE, COMPONENT_PROXY, COMPONENT_TRANSPARENT,
    ROUTE_BLOCK_LABEL, ROUTE_DIRECT_LABEL,
};
use crate::config::{RuleAction, TransportProtocol};
use crate::dns::LocalNameQueryDecision;
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_PROXY_NOT_FOUND, ERR_KEY_RULE_BLOCKED,
    ERR_KEY_UDP_NOT_SUPPORTED,
};
use crate::interceptor::nftables::NftablesInterceptor;
use crate::process::ProcessResolver;
use crate::proxy::udp::Socks5UdpTarget;
use crate::rules::ConnectionRequest;
use crate::telemetry::{
    udp_flow_key, BlockReason, BlockedRecord, ConnectionStatus, LogLevel, TrackedConnection,
};
use chrono::Utc;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use uuid::Uuid;

/// One relayed UDP datagram, ready to be accounted on its aggregated telemetry flow.
struct UdpDatagramRecord {
    client_addr: SocketAddr,
    pid: u32,
    process_name: String,
    process_path: String,
    target_host: String,
    resolved_domain: Option<String>,
    target_port: u16,
    matched_rule: String,
    route_label: String,
    /// Real destination when it differs from `target_host` (Direct traffic), for the flow log.
    real_ip: Option<IpAddr>,
    latency_ms: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    /// `true` when the datagram went through a proxy or a proxy chain.
    is_proxied: bool,
}

impl RouteWardController {
    /// Accounts one datagram on its (client, target, route) flow: the first datagram creates a
    /// single telemetry record and an INFO log line, later ones only add their byte counts and are
    /// logged at debug level.
    fn record_udp_datagram_flow(&self, rec: UdpDatagramRecord) {
        let flow_key = match rec.target_host.parse::<IpAddr>() {
            Ok(ip) => udp_flow_key(
                rec.client_addr,
                SocketAddr::new(ip, rec.target_port),
                &rec.route_label,
            ),
            Err(_) => format!(
                "udp|{}|{}:{}|{}",
                rec.client_addr, rec.target_host, rec.target_port, rec.route_label
            ),
        };
        let real_ip_fragment = rec
            .real_ip
            .map(|ip| format!(", realIp={ip}"))
            .unwrap_or_default();
        let started = self.telemetry.record_udp_datagram(
            &flow_key,
            || TrackedConnection {
                id: Uuid::new_v4().to_string(),
                pid: rec.pid,
                process_name: rec.process_name.clone(),
                process_path: rec.process_path.clone(),
                target_host: rec.target_host.clone(),
                resolved_domain: rec.resolved_domain.clone(),
                target_port: rec.target_port,
                protocol: TransportProtocol::Udp,
                matched_rule: rec.matched_rule.clone(),
                route_label: rec.route_label.clone(),
                latency_ms: rec.latency_ms,
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
            rec.is_proxied,
            rec.rx_bytes,
            rec.tx_bytes,
        );
        if started {
            self.telemetry.push_log(
                LogLevel::Info,
                COMPONENT_TRANSPARENT,
                format!(
                    "Routed UDP PID={} process=\"{}\" exe=\"{}\" -> {}:{} (domain={:?}{}) via {} [rule=\"{}\"]",
                    rec.pid,
                    rec.process_name,
                    rec.process_path,
                    rec.target_host,
                    rec.target_port,
                    rec.resolved_domain,
                    real_ip_fragment,
                    rec.route_label,
                    rec.matched_rule
                ),
            );
        } else {
            tracing::debug!(
                component = COMPONENT_TRANSPARENT,
                "UDP datagram {} -> {}:{} ({} bytes out, {} bytes in) on existing flow via {}",
                rec.client_addr,
                rec.target_host,
                rec.target_port,
                rec.tx_bytes,
                rec.rx_bytes,
                rec.route_label
            );
        }
    }

    /// Records a blocked UDP datagram: one connection record per (client, target, reason) flow
    /// while datagrams keep arriving, every datagram still counted in the blocked summary.
    pub(super) fn record_blocked_udp(&self, client_addr: SocketAddr, record: BlockedRecord) {
        // The name asked about is part of the flow: two different names sent to the same
        // multicast address are two flows, not one.
        let route = format!(
            "{ROUTE_BLOCK_LABEL}|{:?}|{}",
            record.reason,
            record.resolved_domain.as_deref().unwrap_or_default()
        );
        let flow_key = match record.target_host.parse::<IpAddr>() {
            Ok(ip) => udp_flow_key(client_addr, SocketAddr::new(ip, record.target_port), &route),
            Err(_) => format!(
                "udp|{}|{}:{}|{}",
                client_addr, record.target_host, record.target_port, route
            ),
        };
        self.telemetry
            .record_blocked_udp(&flow_key, TrackedConnection::blocked(record));
    }

    /// Evaluates routing rules for a single UDP datagram and forwards it through a SOCKS5 `UDP ASSOCIATE`
    /// session (`Proxy` / `Chain`) or directly (`Direct`), enforcing per-datagram rule evaluation,
    /// Fake-IP reverse lookup (`ATYP = 0x03`), QUIC (`UDP 443`) and DoQ (`UDP 853`) blocking,
    /// fragmentation blocking, and Kill-Switch enforcement.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_udp_datagram(
        &self,
        client_addr: SocketAddr,
        process_name: &str,
        process_path: Option<&str>,
        pid: u32,
        target: &Socks5UdpTarget,
        payload: &[u8],
        is_fragmented: bool,
    ) -> RouteWardResult<Vec<u8>> {
        let raw_host = target.host_string();
        let target_port = target.port();
        let target_ip_str = match target {
            Socks5UdpTarget::Ipv4(ip, _) => Some(ip.to_string()),
            Socks5UdpTarget::Ipv6(ip, _) => Some(ip.to_string()),
            Socks5UdpTarget::Domain(_, _) => None,
        };

        let mut eval = self.evaluate_rule(&ConnectionRequest {
            process_name: process_name.to_string(),
            process_path: process_path.map(|s| s.to_string()),
            target_host: raw_host.clone(),
            target_ip: target_ip_str.clone(),
            target_port,
            protocol: TransportProtocol::Udp,
        });

        let (kill_switch_enabled, block_udp_on_tcp_only) = {
            let prof = self.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_udp_on_tcp_only_proxy,
            )
        };

        let mut policy_reason: Option<BlockReason> = None;
        let udp_override = port_policy_override(
            &self.profile.read().security_policy,
            self.policy_ports(),
            TransportProtocol::Udp,
            target_port,
        );
        if let Some(over) = udp_override {
            match over.reason {
                BlockReason::QuicBlocked => {
                    self.push_rate_limited_warn(
                        "quic_udp_443",
                        COMPONENT_ENGINE,
                        format!(
                            "Blocked QUIC UDP/{} datagram from PID={} process=\"{}\" -> {}:{} (blockQuicUdp443=true)",
                            target_port, pid, process_name, raw_host, target_port
                        ),
                    );
                }
                _ => {
                    self.push_rate_limited_warn(
                        "doq_udp_853",
                        COMPONENT_DNS,
                        format!(
                            "Blocked encrypted DNS (UDP/{}) datagram from PID={} process=\"{}\" -> {}:{}",
                            target_port, pid, process_name, raw_host, target_port
                        ),
                    );
                }
            }
            over.apply(&mut eval);
            policy_reason = Some(over.reason);
        }

        // Decision 3: Fragmented UDP datagram whose rule is Proxy/Chain is blocked when kill switch is active.
        if is_fragmented
            && matches!(
                eval.action,
                RuleAction::Proxy { .. } | RuleAction::Chain { .. }
            )
        {
            let drop_count = self
                .fragmented_udp_drop_count
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            self.push_rate_limited_warn(
                "udp_fragmented_proxy",
                COMPONENT_ENGINE,
                format!(
                    "Fragmented UDP datagram #{drop_count} from PID={} process=\"{}\" -> {}:{} matched proxied rule \"{}\" (v1 does not reassemble IPv4 UDP fragments; killSwitchEnabled={})",
                    pid, process_name, raw_host, target_port, eval.matched_rule_name, kill_switch_enabled
                ),
            );
            if kill_switch_enabled {
                eval.matched_rule_name = FRAGMENTED_UDP_RULE_NAME.to_string();
                eval.action = RuleAction::Block;
                policy_reason = Some(BlockReason::FragmentedUdpBlocked);
            } else {
                eval.action = RuleAction::Direct;
            }
        }

        let effective_target = if let Some(ref dom) = eval.effective_domain {
            Socks5UdpTarget::Domain(dom.clone(), target_port)
        } else {
            target.clone()
        };

        let proc_basename = ProcessResolver::extract_basename(process_name);
        let proc_path_str = process_path.unwrap_or(process_name).to_string();

        match &eval.action {
            RuleAction::Block => {
                let reason =
                    policy_reason.unwrap_or_else(|| block_reason_for_rule(&eval.matched_rule_id));
                self.record_blocked_udp(
                    client_addr,
                    BlockedRecord::new(
                        reason,
                        TransportProtocol::Udp,
                        eval.matched_rule_name.clone(),
                    )
                    .process(proc_basename, proc_path_str, pid)
                    .target(raw_host, target_port)
                    .with_ip(target_ip_str.clone())
                    .with_domain(eval.effective_domain)
                    .with_rule_id(eval.matched_rule_id),
                );
                Err(RouteWardError::BlockedByPolicy {
                    key: ERR_KEY_RULE_BLOCKED,
                    rule_name: eval.matched_rule_name,
                })
            }
            RuleAction::Direct => {
                let target_is_fake_ip = match target {
                    Socks5UdpTarget::Ipv4(ip, _) => self.dns.is_in_fake_subnet(ip),
                    _ => false,
                };
                let dst_addr_res: RouteWardResult<SocketAddr> = match &effective_target {
                    Socks5UdpTarget::Ipv4(ip, port) => {
                        if self.dns.is_in_fake_subnet(ip) {
                            if let Some(dom) = self.dns.resolve_fake_ip(ip) {
                                self.resolve_host_direct_ipv4_cached(&dom)
                                    .await
                                    .map(|real_ip| SocketAddr::new(IpAddr::V4(real_ip), *port))
                            } else {
                                Err(RouteWardError::BlockedByPolicy {
                                    key: ERR_KEY_RULE_BLOCKED,
                                    rule_name: "SecurityPolicy:FakeIpEgressGuard".to_string(),
                                })
                            }
                        } else {
                            Ok(SocketAddr::new(IpAddr::V4(*ip), *port))
                        }
                    }
                    Socks5UdpTarget::Ipv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(*ip), *port)),
                    Socks5UdpTarget::Domain(dom, port) => self
                        .resolve_host_direct_ipv4_cached(dom)
                        .await
                        .map(|real_ip| SocketAddr::new(IpAddr::V4(real_ip), *port)),
                };

                let dst_addr = match dst_addr_res {
                    Ok(addr) => {
                        self.ensure_not_fake_ip_egress(
                            addr.ip(),
                            addr.port(),
                            TransportProtocol::Udp,
                            "forward_udp_datagram:Direct",
                        )?;
                        addr
                    }
                    Err(err) => {
                        if kill_switch_enabled || target_is_fake_ip {
                            self.push_rate_limited_warn(
                                "udp_direct_fakeip_killswitch",
                                COMPONENT_ENGINE,
                                format!(
                                    "Kill-Switch blocked Direct UDP datagram PID={} process=\"{}\" -> {}:{} (domain={:?}, killSwitchEnabled={}) [rule=\"{}\"]: {}",
                                    pid,
                                    proc_basename,
                                    raw_host,
                                    target_port,
                                    eval.effective_domain,
                                    kill_switch_enabled,
                                    eval.matched_rule_name,
                                    err
                                ),
                            );
                            let reason = match BlockReason::from_upstream_error(&err) {
                                BlockReason::FakeIpEgressGuard => BlockReason::FakeIpEgressGuard,
                                _ => BlockReason::KillSwitchDirectUdpFailed,
                            };
                            self.record_blocked_udp(
                                client_addr,
                                BlockedRecord::new(
                                    reason,
                                    TransportProtocol::Udp,
                                    eval.matched_rule_name,
                                )
                                .process(proc_basename, proc_path_str, pid)
                                .target(raw_host, target_port)
                                .with_ip(target_ip_str.clone())
                                .with_domain(eval.effective_domain)
                                .with_rule_id(eval.matched_rule_id)
                                .with_error(err.to_string()),
                            );
                        }
                        return Err(err);
                    }
                };

                let net_consts = &self.constants.network;
                let timeout_dur = Duration::from_millis(
                    net_consts.tcp_connect_timeout_ms.clamp(
                        net_consts.udp_direct_timeout_min_ms,
                        net_consts
                            .udp_direct_timeout_max_ms
                            .max(net_consts.udp_direct_timeout_min_ms),
                    ),
                );
                let direct_start = Instant::now();
                let resp = self
                    .send_and_optional_recv_udp_direct_protected(payload, dst_addr, timeout_dur)
                    .await
                    .map_err(RouteWardError::Io)?;
                let measured_latency_ms = direct_start.elapsed().as_millis().max(1) as u64;
                self.record_udp_datagram_flow(UdpDatagramRecord {
                    client_addr,
                    pid,
                    process_name: proc_basename,
                    process_path: proc_path_str,
                    target_host: raw_host,
                    resolved_domain: eval.effective_domain,
                    target_port,
                    matched_rule: eval.matched_rule_name,
                    route_label: ROUTE_DIRECT_LABEL.to_string(),
                    real_ip: Some(dst_addr.ip()),
                    latency_ms: measured_latency_ms,
                    rx_bytes: resp.len() as u64,
                    tx_bytes: payload.len() as u64,
                    is_proxied: false,
                });
                Ok(resp)
            }
            RuleAction::Proxy { target_id } => {
                if let Socks5UdpTarget::Ipv4(ip, port) = &effective_target {
                    self.ensure_not_fake_ip_egress(
                        IpAddr::V4(*ip),
                        *port,
                        TransportProtocol::Udp,
                        "forward_udp_datagram:Proxy",
                    )?;
                }
                let node = {
                    let prof = self.profile.read();
                    prof.proxies
                        .iter()
                        .find(|p| &p.id == target_id)
                        .cloned()
                        .ok_or_else(|| RouteWardError::ProxyNotFound {
                            key: ERR_KEY_PROXY_NOT_FOUND,
                            proxy_id: target_id.clone(),
                        })?
                };
                let resolved_node = self.prepare_proxy_node_with_bootstrap(node).await?;
                let _self_guard = self.register_self_proxy_connect_hint(&resolved_node);

                let ctrl_warn = self.clone();
                let exchange_start = Instant::now();
                let res = self
                    .udp_manager
                    .exchange_datagram_via_node(
                        client_addr,
                        &resolved_node,
                        &effective_target,
                        payload,
                        &self.constants,
                        Some(&self.nat_table),
                        |unsupported_node, reason| {
                            ctrl_warn.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_PROXY,
                                format!(
                                    "{}: node=\"{}\" (id={}, reason={}; cached for {}s)",
                                    ctrl_warn.i18n.t_english(ERR_KEY_UDP_NOT_SUPPORTED),
                                    unsupported_node.name,
                                    unsupported_node.id,
                                    reason,
                                    ctrl_warn.constants.network.udp_capability_cache_secs
                                ),
                            );
                        },
                    )
                    .await;

                match res {
                    Ok(reply) => {
                        let measured_latency_ms =
                            exchange_start.elapsed().as_millis().max(1) as u64;
                        let route_label = format!("{} (SOCKS5 UDP)", reply.proxy_name);
                        self.record_udp_datagram_flow(UdpDatagramRecord {
                            client_addr,
                            pid,
                            process_name: proc_basename,
                            process_path: proc_path_str,
                            target_host: raw_host,
                            resolved_domain: eval.effective_domain,
                            target_port,
                            matched_rule: eval.matched_rule_name,
                            route_label,
                            real_ip: None,
                            latency_ms: measured_latency_ms,
                            rx_bytes: reply.payload.len() as u64,
                            tx_bytes: payload.len() as u64,
                            is_proxied: true,
                        });
                        Ok(reply.payload)
                    }
                    Err(err) => {
                        // Decision 7: Proxy refusing UDP ASSOCIATE or failing with Kill-Switch / blockUdpOnTcpOnlyProxy -> Block, never Direct
                        if kill_switch_enabled
                            || block_udp_on_tcp_only
                            || matches!(err, RouteWardError::UdpAssociateUnsupported { .. })
                        {
                            self.push_rate_limited_warn(
                                "udp_proxy_killswitch",
                                COMPONENT_ENGINE,
                                format!(
                                    "Kill-Switch blocked UDP datagram PID={} process=\"{}\" -> {}:{} [rule=\"{}\"]: {}",
                                    pid, proc_basename, raw_host, target_port, eval.matched_rule_name, err
                                ),
                            );
                            self.record_blocked_udp(
                                client_addr,
                                BlockedRecord::new(
                                    BlockReason::from_udp_proxy_error(&err, kill_switch_enabled),
                                    TransportProtocol::Udp,
                                    eval.matched_rule_name,
                                )
                                .process(proc_basename, proc_path_str, pid)
                                .target(raw_host, target_port)
                                .with_ip(target_ip_str.clone())
                                .with_domain(eval.effective_domain)
                                .with_rule_id(eval.matched_rule_id)
                                .with_proxy(Some(target_id.clone()))
                                .with_error(err.to_string()),
                            );
                        }
                        Err(err)
                    }
                }
            }
            RuleAction::Chain { target_id } => {
                if let Socks5UdpTarget::Ipv4(ip, port) = &effective_target {
                    self.ensure_not_fake_ip_egress(
                        IpAddr::V4(*ip),
                        *port,
                        TransportProtocol::Udp,
                        "forward_udp_datagram:Chain",
                    )?;
                }
                let (strategy, hops) = {
                    let prof = self.profile.read();
                    let chain =
                        prof.chains
                            .iter()
                            .find(|c| &c.id == target_id)
                            .ok_or_else(|| RouteWardError::ProxyNotFound {
                                key: ERR_KEY_PROXY_NOT_FOUND,
                                proxy_id: target_id.clone(),
                            })?;
                    let mut nodes = Vec::new();
                    for pid in &chain.proxy_ids {
                        if let Some(n) = prof.proxies.iter().find(|p| &p.id == pid) {
                            nodes.push(n.clone());
                        }
                    }
                    (chain.strategy, nodes)
                };
                let mut resolved_hops = Vec::with_capacity(hops.len());
                for hop in hops {
                    match self.prepare_proxy_node_with_bootstrap(hop.clone()).await {
                        Ok(resolved) => {
                            let _ = self.register_self_proxy_connect_hint(&resolved);
                            resolved_hops.push(resolved);
                        }
                        Err(_) => resolved_hops.push(hop),
                    }
                }

                let ctrl_warn = self.clone();
                let exchange_start = Instant::now();
                let res = self
                    .udp_manager
                    .exchange_datagram_via_group(
                        client_addr,
                        strategy,
                        &resolved_hops,
                        0,
                        &effective_target,
                        payload,
                        &self.constants,
                        Some(&self.nat_table),
                        |unsupported_node, reason| {
                            ctrl_warn.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_PROXY,
                                format!(
                                    "{}: node=\"{}\" (id={}, reason={}; cached for {}s)",
                                    ctrl_warn.i18n.t_english(ERR_KEY_UDP_NOT_SUPPORTED),
                                    unsupported_node.name,
                                    unsupported_node.id,
                                    reason,
                                    ctrl_warn.constants.network.udp_capability_cache_secs
                                ),
                            );
                        },
                    )
                    .await;

                match res {
                    Ok(reply) => {
                        let measured_latency_ms =
                            exchange_start.elapsed().as_millis().max(1) as u64;
                        self.record_udp_datagram_flow(UdpDatagramRecord {
                            client_addr,
                            pid,
                            process_name: proc_basename,
                            process_path: proc_path_str,
                            target_host: raw_host,
                            resolved_domain: eval.effective_domain,
                            target_port,
                            matched_rule: eval.matched_rule_name,
                            route_label: format!("Group -> {} (SOCKS5 UDP)", reply.proxy_name),
                            real_ip: None,
                            latency_ms: measured_latency_ms,
                            rx_bytes: reply.payload.len() as u64,
                            tx_bytes: payload.len() as u64,
                            is_proxied: true,
                        });
                        Ok(reply.payload)
                    }
                    Err(err) => {
                        if kill_switch_enabled
                            || block_udp_on_tcp_only
                            || matches!(err, RouteWardError::UdpAssociateUnsupported { .. })
                        {
                            self.push_rate_limited_warn(
                                "udp_group_killswitch",
                                COMPONENT_ENGINE,
                                format!(
                                    "Kill-Switch blocked group UDP datagram PID={} process=\"{}\" -> {}:{} [rule=\"{}\"]: {}",
                                    pid, proc_basename, raw_host, target_port, eval.matched_rule_name, err
                                ),
                            );
                            self.record_blocked_udp(
                                client_addr,
                                BlockedRecord::new(
                                    BlockReason::from_udp_proxy_error(&err, kill_switch_enabled),
                                    TransportProtocol::Udp,
                                    eval.matched_rule_name,
                                )
                                .process(proc_basename, proc_path_str, pid)
                                .target(raw_host, target_port)
                                .with_ip(target_ip_str.clone())
                                .with_domain(eval.effective_domain)
                                .with_rule_id(eval.matched_rule_id)
                                .with_error(err.to_string()),
                            );
                        }
                        Err(err)
                    }
                }
            }
        }
    }

    pub(super) async fn handle_tproxy_udp_datagram(
        &self,
        payload: &[u8],
        peer_addr: SocketAddr,
        orig_dst_opt: Option<SocketAddr>,
        reply_sock: &UdpSocket,
    ) {
        let llmnr_port = self.constants.network.llmnr_standard_port;
        let mdns_port = self.constants.network.mdns_standard_port;
        let fwmark = self.constants.network.linux_fwmark;

        let resolved_orig_dst = match orig_dst_opt {
            Some(dst) => Some(dst),
            None => {
                self.lookup_udp_conntrack_orig_dst(peer_addr, &[llmnr_port, mdns_port])
                    .await
            }
        };

        let Some(orig_dst) = resolved_orig_dst else {
            return;
        };

        // Priority 1: Local name resolution protocols (LLMNR 5355 and mDNS 5353)
        // Forwarded via raw socket preserving the client's original IP and source port (Point 4 / Leak #7 fix).
        if orig_dst.port() == llmnr_port || orig_dst.port() == mdns_port {
            match self.dns.classify_local_name_query(payload) {
                LocalNameQueryDecision::BlockPublicFqdn { qname } => {
                    self.push_rate_limited_warn(
                        "local_name_public_fqdn",
                        COMPONENT_DNS,
                        format!(
                            "Blocked public FQDN \"{qname}\" on local name resolution protocol (LLMNR/mDNS) from {peer_addr}"
                        ),
                    );
                    self.record_blocked_udp(
                        peer_addr,
                        BlockedRecord::new(
                            BlockReason::LocalNameGuard,
                            TransportProtocol::Udp,
                            LOCAL_NAME_GUARD_RULE_NAME,
                        )
                        .process(LOCAL_NAME_PROCESS_NAME, LOCAL_NAME_PROCESS_NAME, 0)
                        .target(qname.clone(), orig_dst.port())
                        .with_domain(Some(qname)),
                    );
                }
                LocalNameQueryDecision::BlockMalformed => {}
                LocalNameQueryDecision::AllowLocal { qname } => {
                    if self
                        .ensure_not_fake_ip_egress(
                            orig_dst.ip(),
                            orig_dst.port(),
                            TransportProtocol::Udp,
                            "handle_tproxy_udp_datagram:AllowLocal",
                        )
                        .is_err()
                    {
                        return;
                    }
                    self.telemetry.push_log(
                        LogLevel::Debug,
                        COMPONENT_DNS,
                        format!(
                            "Forwarding allowed local name query \"{qname}\" from {peer_addr} directly to {orig_dst} (preserving source port {})",
                            peer_addr.port()
                        ),
                    );
                    let raw_res = match (peer_addr, orig_dst) {
                        (SocketAddr::V4(c4), SocketAddr::V4(d4)) => {
                            NftablesInterceptor::send_raw_ipv4_udp_packet(c4, d4, payload, fwmark)
                        }
                        (SocketAddr::V6(c6), SocketAddr::V6(d6)) => {
                            NftablesInterceptor::send_raw_ipv6_udp_packet(c6, d6, payload, fwmark)
                        }
                        _ => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Mismatched IP address family for TPROXY local name forwarding",
                        )),
                    };
                    if raw_res.is_err() {
                        if let Ok(resp) = self
                            .query_dns_udp_direct_protected(
                                payload,
                                orig_dst,
                                Duration::from_millis(
                                    self.constants.network.local_name_query_timeout_ms,
                                ),
                                DnsReplyCheck::IdOnly,
                            )
                            .await
                        {
                            if !resp.is_empty() {
                                match orig_dst {
                                    SocketAddr::V4(v4) => {
                                        let _ = NftablesInterceptor::send_udp_from_local_ip(
                                            reply_sock,
                                            &resp,
                                            peer_addr,
                                            Some(*v4.ip()),
                                        )
                                        .await;
                                    }
                                    SocketAddr::V6(_) => {
                                        let _ = reply_sock.send_to(&resp, peer_addr).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return;
        }

        // Priority 2: General transparent UDP interception via TPROXY
        let orig_dst_ip = orig_dst.ip();
        let target_host = orig_dst_ip.to_string();
        let target_port = orig_dst.port();
        let attribution = self
            .process_resolver
            .resolve_udp_port_attribution_async(peer_addr.port())
            .await;
        let (
            pid,
            proc_name,
            proc_path,
            eval_action,
            matched_rule_name,
            effective_domain,
            _res_source,
        ) = self.attribute_or_apply_unknown_policy_with_proto(
            attribution,
            peer_addr.port(),
            &target_host,
            target_port,
            Some(&orig_dst_ip),
            TransportProtocol::Udp,
        );

        if proc_name == "unknown" && eval_action == RuleAction::Block {
            let reason = block_reason_for_decision(None, &matched_rule_name);
            self.record_blocked_udp(
                peer_addr,
                BlockedRecord::new(reason, TransportProtocol::Udp, matched_rule_name)
                    .process(proc_name, proc_path, pid)
                    .target(target_host.clone(), target_port)
                    .with_ip(Some(target_host))
                    .with_domain(effective_domain),
            );
            return;
        }

        let target = match orig_dst {
            SocketAddr::V4(v4) => Socks5UdpTarget::Ipv4(*v4.ip(), target_port),
            SocketAddr::V6(v6) => Socks5UdpTarget::Ipv6(*v6.ip(), target_port),
        };
        if let Ok(reply_payload) = self
            .forward_udp_datagram(
                peer_addr,
                &proc_name,
                Some(&proc_path),
                pid,
                &target,
                payload,
                false,
            )
            .await
        {
            if !reply_payload.is_empty() {
                match (peer_addr, orig_dst) {
                    (SocketAddr::V4(c4), SocketAddr::V4(d4)) => {
                        let _ = NftablesInterceptor::send_raw_ipv4_udp_packet(
                            d4,
                            c4,
                            &reply_payload,
                            fwmark,
                        );
                    }
                    (SocketAddr::V6(c6), SocketAddr::V6(d6)) => {
                        let _ = NftablesInterceptor::send_raw_ipv6_udp_packet(
                            d6,
                            c6,
                            &reply_payload,
                            fwmark,
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProfileConfig, SystemConstants};

    #[tokio::test]
    async fn direct_udp_datagrams_share_one_flow_record_and_count_as_direct() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo.local_addr().expect("echo addr");
        let _echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.default_action = RuleAction::Direct;
        profile.rules.clear();
        let controller = RouteWardController::new(constants, profile, "en");

        let client = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 15)), 50123);
        let target = Socks5UdpTarget::Ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
        for _ in 0..5 {
            let reply = controller
                .forward_udp_datagram(
                    client,
                    "game.exe",
                    Some("C:\\game.exe"),
                    77,
                    &target,
                    b"abcd",
                    false,
                )
                .await
                .expect("direct datagram");
            assert_eq!(reply, b"abcd");
        }

        let udp_records: Vec<_> = controller
            .telemetry
            .list_connections()
            .into_iter()
            .filter(|c| c.protocol == TransportProtocol::Udp)
            .collect();
        assert_eq!(
            udp_records.len(),
            1,
            "one record per flow, got {udp_records:?}"
        );
        assert_eq!(udp_records[0].status, ConnectionStatus::Active);
        let flow_logs = controller
            .telemetry
            .list_logs()
            .into_iter()
            .filter(|l| l.level == LogLevel::Info && l.message.contains("Routed UDP PID=77"))
            .count();
        assert_eq!(flow_logs, 1, "exactly one INFO line per new flow");

        let snapshot = controller.telemetry.snapshot();
        assert_eq!(snapshot.direct_count, 1);
        assert_eq!(snapshot.proxied_count, 0, "Direct flows are never proxied");
    }

    #[tokio::test]
    async fn udp_routed_to_http_only_proxy_is_blocked_under_kill_switch() {
        use crate::config::{ProxyNode, ProxyProtocol};

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = true;
        profile.security_policy.block_udp_on_tcp_only_proxy = true;
        profile.proxies = vec![ProxyNode {
            id: "http-only".to_string(),
            name: "HTTP Only".to_string(),
            protocol: ProxyProtocol::Http,
            host: "127.0.0.1".to_string(),
            port: 1,
            auth: None,
            udp_enabled: false,
            tls: false,
            tls_skip_verify: false,
            sni: None,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        }];
        profile.rules.clear();
        profile.default_action = RuleAction::Proxy {
            target_id: "http-only".to_string(),
        };
        let controller = RouteWardController::new(constants, profile, "en");

        let client = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 16)), 50124);
        let target = Socks5UdpTarget::Ipv4(std::net::Ipv4Addr::new(1, 1, 1, 1), 12345);
        let res = controller
            .forward_udp_datagram(
                client,
                "game.exe",
                Some("C:\\game.exe"),
                88,
                &target,
                b"ping",
                false,
            )
            .await;
        assert!(res.is_err(), "UDP over HTTP-only proxy must be rejected");
        let blocked = controller
            .telemetry
            .list_connections()
            .into_iter()
            .find(|c| {
                c.protocol == TransportProtocol::Udp && c.status == ConnectionStatus::Blocked
            });
        assert!(
            blocked.is_some(),
            "UDP rejection must record a Blocked connection"
        );
    }

    #[tokio::test]
    async fn udp_routed_to_block_rule_records_blocked_reason_without_sending() {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.rules.clear();
        profile.default_action = RuleAction::Block;
        let controller = RouteWardController::new(constants, profile, "en");

        let client = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 17)), 50125);
        let target = Socks5UdpTarget::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8), 9999);
        let res = controller
            .forward_udp_datagram(
                client,
                "blocked-app.exe",
                None,
                99,
                &target,
                b"drop-me",
                false,
            )
            .await;
        assert!(res.is_err(), "Block policy must reject UDP datagram");
        assert_eq!(controller.telemetry.snapshot().blocked_count, 1);
    }
}
