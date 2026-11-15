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
use crate::telemetry::{ConnectionStatus, LogLevel, TrackedConnection};
use chrono::Utc;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use uuid::Uuid;

impl RouteWardController {
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
            target_ip: target_ip_str,
            target_port,
            protocol: TransportProtocol::Udp,
        });

        let (kill_switch_enabled, block_udp_on_tcp_only, block_quic_443, block_encrypted_dns) = {
            let prof = self.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_udp_on_tcp_only_proxy,
                prof.security_policy.block_quic_udp_443,
                prof.security_policy.block_encrypted_dns_bypass,
            )
        };

        if target_port == self.constants.network.quic_default_port && block_quic_443 {
            self.push_rate_limited_warn(
                "quic_udp_443",
                COMPONENT_ENGINE,
                format!(
                    "Blocked QUIC UDP/{} datagram from PID={} process=\"{}\" -> {}:{} (blockQuicUdp443=true)",
                    target_port, pid, process_name, raw_host, target_port
                ),
            );
            eval.matched_rule_name = "SecurityPolicy:blockQuicUdp443".to_string();
            eval.action = RuleAction::Block;
        } else if target_port == self.constants.dns.dns_over_tls_port && block_encrypted_dns {
            self.push_rate_limited_warn(
                "doq_udp_853",
                COMPONENT_DNS,
                format!(
                    "Blocked encrypted DNS (UDP/{}) datagram from PID={} process=\"{}\" -> {}:{}",
                    target_port, pid, process_name, raw_host, target_port
                ),
            );
            eval.matched_rule_name = "SecurityPolicy:blockEncryptedDnsBypass".to_string();
            eval.action = RuleAction::Block;
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
                eval.matched_rule_name = "SecurityPolicy:FragmentedUdpBlocked".to_string();
                eval.action = RuleAction::Block;
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
                self.telemetry.record_connection(
                    TrackedConnection {
                        id: Uuid::new_v4().to_string(),
                        pid,
                        process_name: proc_basename,
                        process_path: proc_path_str,
                        target_host: raw_host,
                        resolved_domain: eval.effective_domain,
                        target_port,
                        protocol: TransportProtocol::Udp,
                        matched_rule: eval.matched_rule_name.clone(),
                        route_label: ROUTE_BLOCK_LABEL.to_string(),
                        latency_ms: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        status: ConnectionStatus::Blocked,
                        started_at: Utc::now(),
                    },
                    false,
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
                                self.resolve_host_direct_ipv4(&dom)
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
                        .resolve_host_direct_ipv4(dom)
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
                            self.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid,
                                    process_name: proc_basename,
                                    process_path: proc_path_str,
                                    target_host: raw_host,
                                    resolved_domain: eval.effective_domain,
                                    target_port,
                                    protocol: TransportProtocol::Udp,
                                    matched_rule: eval.matched_rule_name,
                                    route_label: ROUTE_BLOCK_LABEL.to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
                            );
                        }
                        return Err(err);
                    }
                };

                let timeout_dur = Duration::from_millis(
                    self.constants
                        .network
                        .tcp_connect_timeout_ms
                        .clamp(300, 1500),
                );
                let direct_start = Instant::now();
                let resp = self
                    .send_and_optional_recv_udp_direct_protected(payload, dst_addr, timeout_dur)
                    .await
                    .map_err(RouteWardError::Io)?;
                let measured_latency_ms = direct_start.elapsed().as_millis().max(1) as u64;
                self.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_TRANSPARENT,
                    format!(
                        "Routed UDP PID={} process=\"{}\" exe=\"{}\" -> {}:{} (domain={:?}, realIp={}) via {} [rule=\"{}\"]",
                        pid,
                        proc_basename,
                        proc_path_str,
                        raw_host,
                        target_port,
                        eval.effective_domain,
                        dst_addr.ip(),
                        ROUTE_DIRECT_LABEL,
                        eval.matched_rule_name
                    ),
                );
                self.telemetry.record_connection(
                    TrackedConnection {
                        id: Uuid::new_v4().to_string(),
                        pid,
                        process_name: proc_basename,
                        process_path: proc_path_str,
                        target_host: raw_host,
                        resolved_domain: eval.effective_domain,
                        target_port,
                        protocol: TransportProtocol::Udp,
                        matched_rule: eval.matched_rule_name,
                        route_label: ROUTE_DIRECT_LABEL.to_string(),
                        latency_ms: measured_latency_ms,
                        rx_bytes: resp.len() as u64,
                        tx_bytes: payload.len() as u64,
                        status: ConnectionStatus::Active,
                        started_at: Utc::now(),
                    },
                    false,
                );
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
                                    ctrl_warn.i18n.t(ERR_KEY_UDP_NOT_SUPPORTED),
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
                        self.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Routed UDP PID={} process=\"{}\" exe=\"{}\" -> {}:{} (domain={:?}) via {} [rule=\"{}\"]",
                                pid,
                                proc_basename,
                                proc_path_str,
                                raw_host,
                                target_port,
                                eval.effective_domain,
                                route_label,
                                eval.matched_rule_name
                            ),
                        );
                        self.telemetry.record_connection(
                            TrackedConnection {
                                id: Uuid::new_v4().to_string(),
                                pid,
                                process_name: proc_basename,
                                process_path: proc_path_str,
                                target_host: raw_host,
                                resolved_domain: eval.effective_domain,
                                target_port,
                                protocol: TransportProtocol::Udp,
                                matched_rule: eval.matched_rule_name,
                                route_label,
                                latency_ms: measured_latency_ms,
                                rx_bytes: reply.payload.len() as u64,
                                tx_bytes: payload.len() as u64,
                                status: ConnectionStatus::Active,
                                started_at: Utc::now(),
                            },
                            true,
                        );
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
                            self.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid,
                                    process_name: proc_basename,
                                    process_path: proc_path_str,
                                    target_host: raw_host,
                                    resolved_domain: eval.effective_domain,
                                    target_port,
                                    protocol: TransportProtocol::Udp,
                                    matched_rule: eval.matched_rule_name,
                                    route_label: ROUTE_BLOCK_LABEL.to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
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
                                    ctrl_warn.i18n.t(ERR_KEY_UDP_NOT_SUPPORTED),
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
                        self.telemetry.record_connection(
                            TrackedConnection {
                                id: Uuid::new_v4().to_string(),
                                pid,
                                process_name: proc_basename,
                                process_path: proc_path_str,
                                target_host: raw_host,
                                resolved_domain: eval.effective_domain,
                                target_port,
                                protocol: TransportProtocol::Udp,
                                matched_rule: eval.matched_rule_name,
                                route_label: format!("Group -> {} (SOCKS5 UDP)", reply.proxy_name),
                                latency_ms: measured_latency_ms,
                                rx_bytes: reply.payload.len() as u64,
                                tx_bytes: payload.len() as u64,
                                status: ConnectionStatus::Active,
                                started_at: Utc::now(),
                            },
                            true,
                        );
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
                            self.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid,
                                    process_name: proc_basename,
                                    process_path: proc_path_str,
                                    target_host: raw_host,
                                    resolved_domain: eval.effective_domain,
                                    target_port,
                                    protocol: TransportProtocol::Udp,
                                    matched_rule: eval.matched_rule_name,
                                    route_label: ROUTE_BLOCK_LABEL.to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                },
                                false,
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

        let resolved_orig_dst = orig_dst_opt
            .or_else(|| self.lookup_udp_conntrack_orig_dst(peer_addr, &[llmnr_port, mdns_port]));

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
                    self.telemetry.record_connection(
                        TrackedConnection {
                            id: Uuid::new_v4().to_string(),
                            pid: 0,
                            process_name: "local-name-proto".to_string(),
                            process_path: "local-name-proto".to_string(),
                            target_host: qname.clone(),
                            resolved_domain: Some(qname),
                            target_port: orig_dst.port(),
                            protocol: TransportProtocol::Udp,
                            matched_rule: "SecurityPolicy:LocalNamePublicFqdnBlocked".to_string(),
                            route_label: ROUTE_BLOCK_LABEL.to_string(),
                            latency_ms: 0,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            status: ConnectionStatus::Blocked,
                            started_at: Utc::now(),
                        },
                        false,
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
                                Duration::from_millis(300),
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
            .resolve_udp_port_attribution(peer_addr.port());
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
            self.telemetry.record_connection(
                TrackedConnection {
                    id: Uuid::new_v4().to_string(),
                    pid,
                    process_name: proc_name,
                    process_path: proc_path,
                    target_host,
                    resolved_domain: effective_domain,
                    target_port,
                    protocol: TransportProtocol::Udp,
                    matched_rule: matched_rule_name,
                    route_label: ROUTE_BLOCK_LABEL.to_string(),
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
