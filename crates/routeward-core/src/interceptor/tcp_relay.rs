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

#[cfg(not(windows))]
use super::nftables::NftablesInterceptor;
use super::{
    RouteWardController, COMPONENT_DNS, COMPONENT_ENGINE, COMPONENT_TRANSPARENT, ROUTE_BLOCK_LABEL,
};
use crate::config::{ProxyNode, RuleAction, TransportProtocol};
use crate::error::{
    RouteWardError, RouteWardResult, ERR_KEY_HANDSHAKE_FAILED, ERR_KEY_PROXY_NOT_FOUND,
};
use crate::proxy::http_host::HttpHostExtractor;
use crate::proxy::sni::TlsSniExtractor;
use crate::proxy::udp::{decode_socks5_udp_datagram, encode_socks5_udp_datagram};
use crate::proxy::{AsyncTunnelStream, ProxyConnector};
use crate::rules::ConnectionRequest;
use crate::telemetry::{ConnectionStatus, LogLevel, TrackedConnection};
use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

/// Smallest number of bytes peeked from a new stream to look for an SNI / Host header.
const MIN_PEEK_BYTES: usize = 64;
/// Largest number of bytes peeked from a new stream (a TLS record is at most 16 KiB).
const MAX_PEEK_BYTES: usize = 16384;
/// Shortest peek timeout accepted from the configuration, in milliseconds.
const MIN_PEEK_TIMEOUT_MS: u64 = 10;

impl RouteWardController {
    /// Removes the NAT session of a finished relay peer after `sessionCloseGraceMs`, so the final
    /// FIN/RST and the client's trailing ACK/FIN are still reflected by the interceptor.
    pub(super) fn remove_relay_session_after_grace(&self, peer_ip: IpAddr, peer_port: u16) {
        let nat_cleanup = self.nat_table.clone();
        let grace = Duration::from_millis(self.constants.network.session_close_grace_ms);
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            nat_cleanup.remove_session_by_relay_peer(peer_ip, peer_port);
        });
    }

    pub(super) async fn handle_local_socks5_client(
        &self,
        mut client: TcpStream,
        client_port: u16,
    ) -> RouteWardResult<()> {
        let proto = &self.constants.protocols;
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await?;
        if header[0] != proto.socks5_version {
            return Ok(());
        }
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        client.read_exact(&mut methods).await?;
        client
            .write_all(&[proto.socks5_version, proto.socks5_auth_none])
            .await?;

        let mut req_head = [0u8; 4];
        client.read_exact(&mut req_head).await?;
        let target_host = match req_head[3] {
            atyp if atyp == proto.socks5_atyp_ipv4 => {
                let mut ip = [0u8; 4];
                client.read_exact(&mut ip).await?;
                IpAddr::from(ip).to_string()
            }
            atyp if atyp == proto.socks5_atyp_domain => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                let mut dom = vec![0u8; len[0] as usize];
                client.read_exact(&mut dom).await?;
                String::from_utf8_lossy(&dom).to_string()
            }
            atyp if atyp == proto.socks5_atyp_ipv6 => {
                let mut ip = [0u8; 16];
                client.read_exact(&mut ip).await?;
                IpAddr::from(ip).to_string()
            }
            _ => return Ok(()),
        };

        let mut port_bytes = [0u8; 2];
        client.read_exact(&mut port_bytes).await?;
        let target_port = u16::from_be_bytes(port_bytes);

        let proc_id = self
            .process_resolver
            .resolve_by_local_tcp_port_async(client_port)
            .await;

        if req_head[1] == proto.socks5_cmd_udp_associate {
            let udp_relay =
                UdpSocket::bind(format!("{}:0", self.constants.network.local_bind_host)).await?;
            let relay_addr = udp_relay.local_addr()?;
            let bind_ip = match relay_addr.ip() {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
            };
            let bind_port = relay_addr.port().to_be_bytes();
            let ip_octets = bind_ip.octets();
            let assoc_reply = [
                proto.socks5_version,
                proto.socks5_reply_succeeded,
                0x00,
                proto.socks5_atyp_ipv4,
                ip_octets[0],
                ip_octets[1],
                ip_octets[2],
                ip_octets[3],
                bind_port[0],
                bind_port[1],
            ];
            client.write_all(&assoc_reply).await?;

            let mut tcp_probe = [0u8; 1];
            let mut udp_buf = vec![0u8; 65535];
            while self.is_running() {
                tokio::select! {
                    read_res = client.read(&mut tcp_probe) => {
                        match read_res {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    recv_res = udp_relay.recv_from(&mut udp_buf) => {
                        let Ok((n, udp_peer)) = recv_res else {
                            break;
                        };
                        let Ok((target, payload)) = decode_socks5_udp_datagram(&udp_buf[..n], proto) else {
                            continue;
                        };
                        if let Ok(reply_payload) = self
                            .forward_udp_datagram(
                                udp_peer,
                                &proc_id.name,
                                Some(&proc_id.executable_path),
                                proc_id.pid,
                                &target,
                                payload,
                                false,
                            )
                            .await
                        {
                            if let Ok(encoded_reply) = encode_socks5_udp_datagram(&target, &reply_payload, proto) {
                                let _ = udp_relay.send_to(&encoded_reply, udp_peer).await;
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        let target_ip_str = target_host
            .parse::<Ipv4Addr>()
            .ok()
            .map(|ip| ip.to_string());
        let mut eval = self.evaluate_rule(&ConnectionRequest {
            process_name: proc_id.name.clone(),
            process_path: Some(proc_id.executable_path.clone()),
            target_host: target_host.clone(),
            target_ip: target_ip_str,
            target_port,
            protocol: TransportProtocol::Tcp,
        });
        if proc_id.is_unattributed() && eval.action == RuleAction::Direct {
            let (action, matched_rule_name) = self.resolve_unknown_process_action(
                COMPONENT_ENGINE,
                client_port,
                &target_host,
                target_port,
                "local SOCKS5 client PID or executable image unavailable",
            );
            eval.matched_rule_id = "unknown-process-action".to_string();
            eval.matched_rule_name = matched_rule_name;
            eval.action = action;
        }

        let effective_host = eval
            .effective_domain
            .clone()
            .unwrap_or_else(|| target_host.clone());

        if target_port == self.constants.dns.dns_over_tls_port
            && self
                .profile
                .read()
                .security_policy
                .block_encrypted_dns_bypass
        {
            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_DNS,
                format!(
                    "Blocked encrypted DNS bypass (DoT TCP port {}) via local SOCKS5 for PID={} process=\"{}\" -> {}",
                    target_port, proc_id.pid, proc_id.name, effective_host
                ),
            );
            eval.matched_rule_name = "SecurityPolicy:blockEncryptedDnsBypass".to_string();
            eval.action = RuleAction::Block;
        }

        if eval.action == RuleAction::Block {
            let blocked_conn = TrackedConnection {
                id: Uuid::new_v4().to_string(),
                pid: proc_id.pid,
                process_name: proc_id.name,
                process_path: proc_id.executable_path,
                target_host,
                resolved_domain: eval.effective_domain,
                target_port,
                protocol: TransportProtocol::Tcp,
                matched_rule: eval.matched_rule_name,
                route_label: ROUTE_BLOCK_LABEL.to_string(),
                latency_ms: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                status: ConnectionStatus::Blocked,
                started_at: Utc::now(),
                error_detail: None,
            };
            self.telemetry.record_connection(blocked_conn, false);
            Self::send_socks5_failure_and_close(&mut client, proto).await;
            return Ok(());
        }

        let is_proxied_rule = matches!(
            eval.action,
            RuleAction::Proxy { .. } | RuleAction::Chain { .. }
        );
        let kill_switch_enabled = self.profile.read().security_policy.kill_switch_enabled;

        let connect_start = Instant::now();
        let (mut outbound, effective_action) = match self
            .open_outbound_stream(&eval.action, &effective_host, target_port)
            .await
        {
            Ok(stream) => (stream, eval.action.clone()),
            Err(err) => {
                if is_proxied_rule && kill_switch_enabled {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!(
                            "Kill-Switch blocked local SOCKS5 connection PID={} process=\"{}\" exe=\"{}\" -> {}:{} [rule=\"{}\", killSwitchEnabled=true]: {}",
                            proc_id.pid,
                            proc_id.name,
                            proc_id.executable_path,
                            effective_host,
                            target_port,
                            eval.matched_rule_name,
                            err
                        ),
                    );
                    self.telemetry.record_connection(
                        TrackedConnection {
                            id: Uuid::new_v4().to_string(),
                            pid: proc_id.pid,
                            process_name: proc_id.name,
                            process_path: proc_id.executable_path,
                            target_host,
                            resolved_domain: eval.effective_domain,
                            target_port,
                            protocol: TransportProtocol::Tcp,
                            matched_rule: eval.matched_rule_name,
                            route_label: ROUTE_BLOCK_LABEL.to_string(),
                            latency_ms: 0,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            status: ConnectionStatus::Blocked,
                            started_at: Utc::now(),
                            error_detail: Some(err.to_string()),
                        },
                        false,
                    );
                    Self::send_socks5_failure_and_close(&mut client, proto).await;
                    return Err(err);
                } else if is_proxied_rule {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_ENGINE,
                        format!(
                            "Upstream proxy failed for local SOCKS5 connection PID={} process=\"{}\" exe=\"{}\" -> {}:{} ({}); falling back to DIRECT because killSwitchEnabled=false",
                            proc_id.pid,
                            proc_id.name,
                            proc_id.executable_path,
                            effective_host,
                            target_port,
                            err
                        ),
                    );
                    match self
                        .open_outbound_stream(&RuleAction::Direct, &effective_host, target_port)
                        .await
                    {
                        Ok(direct_stream) => (direct_stream, RuleAction::Direct),
                        Err(direct_err) => {
                            Self::send_socks5_failure_and_close(&mut client, proto).await;
                            return Err(direct_err);
                        }
                    }
                } else {
                    Self::send_socks5_failure_and_close(&mut client, proto).await;
                    return Err(err);
                }
            }
        };

        let success_reply = [
            proto.socks5_version,
            proto.socks5_reply_succeeded,
            0x00,
            proto.socks5_atyp_ipv4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        client.write_all(&success_reply).await?;

        let measured_latency_ms = connect_start.elapsed().as_millis().max(1) as u64;
        let conn_id = Uuid::new_v4().to_string();
        let is_proxied = !matches!(effective_action, RuleAction::Direct);
        let tracked = TrackedConnection {
            id: conn_id.clone(),
            pid: proc_id.pid,
            process_name: proc_id.name,
            process_path: proc_id.executable_path,
            target_host,
            resolved_domain: eval.effective_domain,
            target_port,
            protocol: TransportProtocol::Tcp,
            matched_rule: eval.matched_rule_name,
            route_label: self.format_action_label(&effective_action),
            latency_ms: measured_latency_ms,
            rx_bytes: 0,
            tx_bytes: 0,
            status: ConnectionStatus::Active,
            started_at: Utc::now(),
            error_detail: None,
        };
        self.telemetry.record_connection(tracked, is_proxied);
        let _ = self
            .telemetry
            .relay_bidirectional_with_telemetry(&conn_id, &mut client, &mut outbound)
            .await;

        Ok(())
    }

    pub(super) async fn send_socks5_failure_and_close(
        client: &mut TcpStream,
        proto: &crate::config::ProtocolConstants,
    ) {
        let failure_reply = [
            proto.socks5_version,
            proto.socks5_reply_general_failure,
            0x00,
            proto.socks5_atyp_ipv4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let _ = client.write_all(&failure_reply).await;
        let _ = client.shutdown().await;
    }

    /// Peeks at the initial bytes of an accepted TCP stream on port 443 (with a bounded timeout
    /// and maximum buffer size) to extract the TLS `ClientHello` SNI hostname without consuming
    /// bytes from the socket receive buffer.
    pub(super) async fn peek_tls_client_hello_sni(&self, client: &TcpStream) -> Option<String> {
        let max_bytes = self
            .constants
            .network
            .tls_sni_max_bytes
            .clamp(MIN_PEEK_BYTES, MAX_PEEK_BYTES);
        let timeout_dur = Duration::from_millis(
            self.constants
                .network
                .tls_sni_peek_timeout_ms
                .max(MIN_PEEK_TIMEOUT_MS),
        );
        let poll_interval = Duration::from_millis(self.constants.network.peek_poll_interval_ms);
        let deadline = tokio::time::Instant::now() + timeout_dur;
        let mut buf = vec![0u8; max_bytes];

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline - now;
            let peeked = match tokio::time::timeout(remaining, client.peek(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
                Ok(Ok(n)) => n,
            };

            // A TLS Handshake record always starts with 0x16. Abort immediately on any non-TLS byte.
            if buf[0] != 0x16 {
                return None;
            }

            if let Some(sni) = TlsSniExtractor::extract_sni(&buf[..peeked]) {
                return Some(sni);
            }

            if peeked >= 5 {
                let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                let total_needed = (5 + record_len).min(max_bytes);
                if peeked >= total_needed {
                    return None;
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Peeks at the initial bytes of a plaintext HTTP TCP stream on inspected ports to extract
    /// the `Host:` header hostname without consuming bytes from the socket receive buffer.
    pub(super) async fn peek_http_host_header(&self, client: &TcpStream) -> Option<String> {
        let max_bytes = self
            .constants
            .network
            .http_host_max_bytes
            .clamp(MIN_PEEK_BYTES, MAX_PEEK_BYTES);
        let timeout_dur = Duration::from_millis(
            self.constants
                .network
                .http_host_peek_timeout_ms
                .max(MIN_PEEK_TIMEOUT_MS),
        );
        let poll_interval = Duration::from_millis(self.constants.network.peek_poll_interval_ms);
        let deadline = tokio::time::Instant::now() + timeout_dur;
        let mut buf = vec![0u8; max_bytes];

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline - now;
            let peeked = match tokio::time::timeout(remaining, client.peek(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
                Ok(Ok(n)) => n,
            };

            let slice = &buf[..peeked];
            if !HttpHostExtractor::looks_like_http_request(slice) {
                return None;
            }
            if let Some(host) = HttpHostExtractor::extract_host(slice) {
                return Some(host);
            }

            let headers_complete = slice.windows(4).any(|w| w == b"\r\n\r\n")
                || slice.windows(2).any(|w| w == b"\n\n");
            if headers_complete || peeked >= max_bytes {
                return None;
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    pub(super) async fn peek_initial_domain(
        &self,
        client: &TcpStream,
        target_port: u16,
    ) -> Option<String> {
        if target_port == self.constants.network.tls_sni_default_port {
            self.peek_tls_client_hello_sni(client).await
        } else if self
            .constants
            .network
            .http_host_inspect_ports
            .contains(&target_port)
        {
            self.peek_http_host_header(client).await
        } else {
            None
        }
    }

    pub async fn handle_transparent_tcp_client(
        &self,
        mut client: TcpStream,
        peer_addr: SocketAddr,
    ) -> RouteWardResult<()> {
        if let Some(mut session) = self.nat_table.validate_relay_peer_addr(peer_addr) {
            let target_host = session.orig_dst_ip.to_string();
            let target_port = session.orig_dst_port;
            if target_port == self.constants.dns.dns_standard_port {
                let res = self
                    .handle_dns_tcp_stream(
                        client,
                        Some(SocketAddr::new(session.orig_dst_ip, target_port)),
                    )
                    .await;
                self.remove_relay_session_after_grace(peer_addr.ip(), peer_addr.port());
                return res;
            }
            let is_fake_ip = self.is_in_fake_subnet_any(&session.orig_dst_ip);
            let mut resolved_domain = self.resolve_fake_ip_any(&session.orig_dst_ip);

            // When destination is not a Fake-IP, inspect TLS ClientHello SNI or HTTP Host header
            // and re-evaluate domain routing rules.
            if !is_fake_ip && resolved_domain.is_none() {
                if let Some(inspected_domain) = self.peek_initial_domain(&client, target_port).await
                {
                    let eval = self.evaluate_rule(&ConnectionRequest {
                        process_name: session.process_name.clone(),
                        process_path: Some(session.process_path.clone()),
                        target_host: inspected_domain.clone(),
                        target_ip: Some(target_host.clone()),
                        target_port,
                        protocol: TransportProtocol::Tcp,
                    });
                    session.action = eval.action;
                    session.matched_rule_name = eval.matched_rule_name;
                    resolved_domain = Some(inspected_domain);
                }
            }

            if session.action == RuleAction::Block {
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_TRANSPARENT,
                    format!(
                        "Blocked connection PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} (domain={:?}) [rule=\"{}\"]",
                        session.pid,
                        session.process_name,
                        session.process_path,
                        session.resolution_source.as_str(),
                        target_host,
                        target_port,
                        resolved_domain,
                        session.matched_rule_name
                    ),
                );
                self.telemetry.record_connection(
                    TrackedConnection {
                        id: Uuid::new_v4().to_string(),
                        pid: session.pid,
                        process_name: session.process_name.clone(),
                        process_path: session.process_path.clone(),
                        target_host,
                        resolved_domain,
                        target_port,
                        protocol: TransportProtocol::Tcp,
                        matched_rule: session.matched_rule_name.clone(),
                        route_label: ROUTE_BLOCK_LABEL.to_string(),
                        latency_ms: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        status: ConnectionStatus::Blocked,
                        started_at: Utc::now(),
                        error_detail: None,
                    },
                    false,
                );
                let _ = client.shutdown().await;
                self.nat_table
                    .remove_session_by_relay_peer(session.orig_dst_ip, session.client_port);
                return Ok(());
            }

            let is_proxied_rule = matches!(
                session.action,
                RuleAction::Proxy { .. } | RuleAction::Chain { .. }
            );
            let effective_host = if is_proxied_rule || is_fake_ip {
                resolved_domain
                    .clone()
                    .unwrap_or_else(|| target_host.clone())
            } else {
                target_host.clone()
            };
            let direct_fallback_host = if is_fake_ip {
                effective_host.clone()
            } else {
                target_host.clone()
            };
            let kill_switch_enabled = self.profile.read().security_policy.kill_switch_enabled;

            let connect_start = Instant::now();
            let (mut outbound, effective_action) = match self
                .open_outbound_stream(&session.action, &effective_host, target_port)
                .await
            {
                Ok(stream) => (stream, session.action.clone()),
                Err(err) => {
                    if is_proxied_rule && kill_switch_enabled {
                        self.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Kill-Switch blocked connection PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} [rule=\"{}\", killSwitchEnabled=true]: {}",
                                session.pid,
                                session.process_name,
                                session.process_path,
                                session.resolution_source.as_str(),
                                target_host,
                                target_port,
                                session.matched_rule_name,
                                err
                            ),
                        );
                        self.telemetry.record_connection(
                            TrackedConnection {
                                id: Uuid::new_v4().to_string(),
                                pid: session.pid,
                                process_name: session.process_name.clone(),
                                process_path: session.process_path.clone(),
                                target_host,
                                resolved_domain,
                                target_port,
                                protocol: TransportProtocol::Tcp,
                                matched_rule: session.matched_rule_name.clone(),
                                route_label: ROUTE_BLOCK_LABEL.to_string(),
                                latency_ms: 0,
                                rx_bytes: 0,
                                tx_bytes: 0,
                                status: ConnectionStatus::Blocked,
                                started_at: Utc::now(),
                                error_detail: Some(err.to_string()),
                            },
                            false,
                        );
                        let _ = client.shutdown().await;
                        self.nat_table
                            .remove_session_by_relay_peer(session.orig_dst_ip, session.client_port);
                        return Err(err);
                    } else if is_proxied_rule {
                        self.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Upstream proxy failed for PID={} process=\"{}\" exe=\"{}\" -> {}:{} ({}); falling back to DIRECT because killSwitchEnabled=false",
                                session.pid,
                                session.process_name,
                                session.process_path,
                                target_host,
                                target_port,
                                err
                            ),
                        );
                        match self
                            .open_outbound_stream(
                                &RuleAction::Direct,
                                &direct_fallback_host,
                                target_port,
                            )
                            .await
                        {
                            Ok(direct_stream) => (direct_stream, RuleAction::Direct),
                            Err(direct_err) => {
                                let _ = client.shutdown().await;
                                self.nat_table.remove_session_by_relay_peer(
                                    session.orig_dst_ip,
                                    session.client_port,
                                );
                                return Err(direct_err);
                            }
                        }
                    } else {
                        self.telemetry.push_log(
                            LogLevel::Error,
                            COMPONENT_TRANSPARENT,
                            format!(
                                "Failed upstream connect for PID={} process=\"{}\" exe=\"{}\" -> {}:{}: {}",
                                session.pid,
                                session.process_name,
                                session.process_path,
                                target_host,
                                target_port,
                                err
                            ),
                        );
                        let _ = client.shutdown().await;
                        self.nat_table
                            .remove_session_by_relay_peer(session.orig_dst_ip, session.client_port);
                        return Err(err);
                    }
                }
            };

            let route_label = self.format_action_label(&effective_action);
            self.telemetry.push_log(
                LogLevel::Info,
                COMPONENT_TRANSPARENT,
                format!(
                    "Routed PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} via {} [rule=\"{}\"]",
                    session.pid,
                    session.process_name,
                    session.process_path,
                    session.resolution_source.as_str(),
                    target_host,
                    target_port,
                    route_label,
                    session.matched_rule_name
                ),
            );

            let measured_latency_ms = connect_start.elapsed().as_millis().max(1) as u64;
            let conn_id = Uuid::new_v4().to_string();
            let is_proxied = !matches!(effective_action, RuleAction::Direct);
            let tracked = TrackedConnection {
                id: conn_id.clone(),
                pid: session.pid,
                process_name: session.process_name,
                process_path: session.process_path,
                target_host,
                resolved_domain,
                target_port,
                protocol: TransportProtocol::Tcp,
                matched_rule: session.matched_rule_name,
                route_label,
                latency_ms: measured_latency_ms,
                rx_bytes: 0,
                tx_bytes: 0,
                status: ConnectionStatus::Active,
                started_at: Utc::now(),
                error_detail: None,
            };
            self.telemetry.record_connection(tracked, is_proxied);

            let _ = self
                .telemetry
                .relay_bidirectional_with_telemetry(&conn_id, &mut client, &mut outbound)
                .await;
            // Close both sockets first so the final FIN/RST is emitted while the NAT session
            // still exists, then keep the session for the grace period before removing it.
            drop(outbound);
            drop(client);
            self.remove_relay_session_after_grace(session.orig_dst_ip, session.client_port);

            return Ok(());
        }

        #[cfg(not(windows))]
        {
            let relay_port = self.constants.network.default_transparent_tcp_port;
            if let Some(orig_dst) = NftablesInterceptor::query_original_dst_any(&client, relay_port)
            {
                let orig_dst_ip = orig_dst.ip();
                let target_host = orig_dst_ip.to_string();
                let target_port = orig_dst.port();
                let client_port = peer_addr.port();

                if target_port == self.constants.dns.dns_standard_port {
                    return self.handle_dns_tcp_stream(client, Some(orig_dst)).await;
                }

                let is_fake_ip = self.is_in_fake_subnet_any(&orig_dst_ip);
                let sni_domain = if !is_fake_ip {
                    self.peek_initial_domain(&client, target_port).await
                } else {
                    None
                };

                let attribution = self
                    .process_resolver
                    .resolve_tcp_port_attribution_async(client_port)
                    .await;

                let (
                    pid,
                    proc_name,
                    proc_path,
                    mut eval_action,
                    mut matched_rule_name,
                    mut effective_domain,
                    res_source,
                ) = self.attribute_or_apply_unknown_policy(
                    attribution,
                    client_port,
                    &target_host,
                    target_port,
                    Some(&orig_dst_ip),
                );

                if let Some(ref sni) = sni_domain {
                    if proc_name != "unknown" {
                        let sni_eval = self.evaluate_rule(&ConnectionRequest {
                            process_name: proc_name.clone(),
                            process_path: Some(proc_path.clone()),
                            target_host: sni.clone(),
                            target_ip: Some(target_host.clone()),
                            target_port,
                            protocol: TransportProtocol::Tcp,
                        });
                        eval_action = sni_eval.action;
                        matched_rule_name = sni_eval.matched_rule_name;
                    }
                    effective_domain = Some(sni.clone());
                }

                if target_port == self.constants.dns.dns_over_tls_port
                    && self
                        .profile
                        .read()
                        .security_policy
                        .block_encrypted_dns_bypass
                {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_DNS,
                        format!(
                            "Blocked encrypted DNS bypass (DoT TCP port {}) PID={} process=\"{}\" -> {}:{}",
                            target_port, pid, proc_name, target_host, target_port
                        ),
                    );
                    eval_action = RuleAction::Block;
                    matched_rule_name = "SecurityPolicy:blockEncryptedDnsBypass".to_string();
                }

                let is_proxied_rule = matches!(
                    eval_action,
                    RuleAction::Proxy { .. } | RuleAction::Chain { .. }
                );
                let effective_host = if is_proxied_rule || is_fake_ip {
                    effective_domain
                        .clone()
                        .unwrap_or_else(|| target_host.clone())
                } else {
                    target_host.clone()
                };
                let direct_fallback_host = if is_fake_ip {
                    effective_host.clone()
                } else {
                    target_host.clone()
                };

                if eval_action == RuleAction::Block {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_TRANSPARENT,
                        format!(
                            "Blocked connection PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} [rule=\"{}\"] (TCP RST)",
                            pid,
                            proc_name,
                            proc_path,
                            res_source,
                            target_host,
                            target_port,
                            matched_rule_name
                        ),
                    );
                    self.telemetry.record_connection(
                        TrackedConnection {
                            id: Uuid::new_v4().to_string(),
                            pid,
                            process_name: proc_name,
                            process_path: proc_path,
                            target_host,
                            resolved_domain: effective_domain,
                            target_port,
                            protocol: TransportProtocol::Tcp,
                            matched_rule: matched_rule_name,
                            route_label: ROUTE_BLOCK_LABEL.to_string(),
                            latency_ms: 0,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            status: ConnectionStatus::Blocked,
                            started_at: Utc::now(),
                            error_detail: None,
                        },
                        false,
                    );
                    NftablesInterceptor::reset_and_close_tcp_stream(client);
                    return Ok(());
                }

                let kill_switch_enabled = self.profile.read().security_policy.kill_switch_enabled;

                let connect_start = Instant::now();
                let (mut outbound, effective_action) = match self
                    .open_outbound_stream(&eval_action, &effective_host, target_port)
                    .await
                {
                    Ok(stream) => (stream, eval_action.clone()),
                    Err(err) => {
                        if is_proxied_rule && kill_switch_enabled {
                            self.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_TRANSPARENT,
                                format!(
                                    "Kill-Switch blocked connection PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} [rule=\"{}\", killSwitchEnabled=true]: {}",
                                    pid,
                                    proc_name,
                                    proc_path,
                                    res_source,
                                    target_host,
                                    target_port,
                                    matched_rule_name,
                                    err
                                ),
                            );
                            self.telemetry.record_connection(
                                TrackedConnection {
                                    id: Uuid::new_v4().to_string(),
                                    pid,
                                    process_name: proc_name,
                                    process_path: proc_path,
                                    target_host,
                                    resolved_domain: effective_domain,
                                    target_port,
                                    protocol: TransportProtocol::Tcp,
                                    matched_rule: matched_rule_name,
                                    route_label: ROUTE_BLOCK_LABEL.to_string(),
                                    latency_ms: 0,
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    status: ConnectionStatus::Blocked,
                                    started_at: Utc::now(),
                                    error_detail: Some(err.to_string()),
                                },
                                false,
                            );
                            NftablesInterceptor::reset_and_close_tcp_stream(client);
                            return Err(err);
                        } else if is_proxied_rule {
                            self.telemetry.push_log(
                                LogLevel::Warn,
                                COMPONENT_TRANSPARENT,
                                format!(
                                    "Upstream proxy failed for PID={} process=\"{}\" exe=\"{}\" -> {}:{} ({}); falling back to DIRECT because killSwitchEnabled=false",
                                    pid, proc_name, proc_path, target_host, target_port, err
                                ),
                            );
                            match self
                                .open_outbound_stream(
                                    &RuleAction::Direct,
                                    &direct_fallback_host,
                                    target_port,
                                )
                                .await
                            {
                                Ok(direct_stream) => (direct_stream, RuleAction::Direct),
                                Err(direct_err) => {
                                    NftablesInterceptor::reset_and_close_tcp_stream(client);
                                    return Err(direct_err);
                                }
                            }
                        } else {
                            self.telemetry.push_log(
                                LogLevel::Error,
                                COMPONENT_TRANSPARENT,
                                format!(
                                    "Failed upstream connect for PID={} process=\"{}\" exe=\"{}\" -> {}:{}: {}",
                                    pid, proc_name, proc_path, target_host, target_port, err
                                ),
                            );
                            NftablesInterceptor::reset_and_close_tcp_stream(client);
                            return Err(err);
                        }
                    }
                };

                let route_label = self.format_action_label(&effective_action);
                self.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_TRANSPARENT,
                    format!(
                        "Routed PID={} process=\"{}\" exe=\"{}\" resolvedVia={} -> {}:{} via {} [rule=\"{}\"]",
                        pid,
                        proc_name,
                        proc_path,
                        res_source,
                        target_host,
                        target_port,
                        route_label,
                        matched_rule_name
                    ),
                );

                let measured_latency_ms = connect_start.elapsed().as_millis().max(1) as u64;
                let conn_id = Uuid::new_v4().to_string();
                let is_proxied = !matches!(effective_action, RuleAction::Direct);
                let tracked = TrackedConnection {
                    id: conn_id.clone(),
                    pid,
                    process_name: proc_name,
                    process_path: proc_path,
                    target_host,
                    resolved_domain: effective_domain,
                    target_port,
                    protocol: TransportProtocol::Tcp,
                    matched_rule: matched_rule_name,
                    route_label,
                    latency_ms: measured_latency_ms,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    status: ConnectionStatus::Active,
                    started_at: Utc::now(),
                    error_detail: None,
                };
                self.telemetry.record_connection(tracked, is_proxied);
                let _ = self
                    .telemetry
                    .relay_bidirectional_with_telemetry(&conn_id, &mut client, &mut outbound)
                    .await;
                return Ok(());
            }
        }

        let _ = client.shutdown().await;
        self.telemetry.push_log(
            LogLevel::Warn,
            COMPONENT_TRANSPARENT,
            format!(
                "Rejected unauthorized connection on transparent relay from {peer_addr}: no matching live NAT session"
            ),
        );
        Ok(())
    }

    pub(super) async fn open_outbound_stream(
        &self,
        action: &RuleAction,
        target_host: &str,
        target_port: u16,
    ) -> RouteWardResult<Box<dyn AsyncTunnelStream>> {
        let effective_host = if let Ok(IpAddr::V4(v4)) = target_host.parse::<IpAddr>() {
            if self.dns.is_in_fake_subnet(&v4) {
                if let Some(dom) = self.dns.resolve_fake_ip(&v4) {
                    dom
                } else {
                    self.ensure_not_fake_ip_egress(
                        IpAddr::V4(v4),
                        target_port,
                        TransportProtocol::Tcp,
                        "open_outbound_stream",
                    )?;
                    target_host.to_string()
                }
            } else {
                target_host.to_string()
            }
        } else {
            target_host.to_string()
        };

        match action {
            RuleAction::Direct => {
                if let Ok(ip) = effective_host.parse::<IpAddr>() {
                    self.ensure_not_fake_ip_egress(
                        ip,
                        target_port,
                        TransportProtocol::Tcp,
                        "open_outbound_stream:Direct",
                    )?;
                    self.connect_direct_tcp_protected(SocketAddr::new(ip, target_port))
                        .await
                        .map(|s| Box::new(s) as Box<dyn AsyncTunnelStream>)
                        .map_err(RouteWardError::Io)
                } else {
                    let resolved_ip = self.resolve_host_direct_ipv4(&effective_host).await?;
                    self.ensure_not_fake_ip_egress(
                        IpAddr::V4(resolved_ip),
                        target_port,
                        TransportProtocol::Tcp,
                        "open_outbound_stream:Direct",
                    )?;
                    self.connect_direct_tcp_protected(SocketAddr::new(
                        IpAddr::V4(resolved_ip),
                        target_port,
                    ))
                    .await
                    .map(|s| Box::new(s) as Box<dyn AsyncTunnelStream>)
                    .map_err(RouteWardError::Io)
                }
            }
            RuleAction::Proxy { target_id } => {
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
                let (resolved_node, spn_host) =
                    self.prepare_proxy_node_with_bootstrap_and_spn(node).await?;
                let _self_guard = self.register_self_proxy_connect_hint(&resolved_node);
                ProxyConnector::connect_single_with_spn(
                    &resolved_node,
                    spn_host.as_deref(),
                    &effective_host,
                    target_port,
                    &self.constants,
                )
                .await
            }
            RuleAction::Chain { target_id } => {
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
                    match self
                        .prepare_proxy_node_with_bootstrap_and_spn(hop.clone())
                        .await
                    {
                        Ok(resolved) => resolved_hops.push(resolved),
                        Err(_) => {
                            let fallback_spn =
                                (hop.host.parse::<IpAddr>().is_err()).then(|| hop.host.clone());
                            resolved_hops.push((hop, fallback_spn));
                        }
                    }
                }
                ProxyConnector::connect_group_with_spns(
                    strategy,
                    &resolved_hops,
                    0,
                    &effective_host,
                    target_port,
                    &self.constants,
                )
                .await
            }
            RuleAction::Block => Err(RouteWardError::BlockedByPolicy {
                key: crate::error::ERR_KEY_RULE_BLOCKED,
                rule_name: ROUTE_BLOCK_LABEL.to_string(),
            }),
        }
    }

    pub(super) fn register_self_proxy_connect_hint(&self, node: &ProxyNode) -> Option<()> {
        if let Ok(ip) = node.host.parse::<IpAddr>() {
            // Same lock as `sync_upstream_proxy_exclusions`: the read-modify-write must not
            // interleave with a concurrent replacement of the whole list.
            let _guard = self.relay_caches.upstream_endpoints.lock();
            let mut endpoints = self.nat_table.upstream_endpoints();
            if !endpoints.contains(&(ip, node.port)) {
                endpoints.push((ip, node.port));
                self.nat_table.set_upstream_endpoints(endpoints);
            }
        }
        Some(())
    }

    /// Resolves any domain-named upstream proxy hosts directly (without Fake-IP, without loops)
    /// and registers their resolved `(ip, port)` endpoints in `nat_table` for anti-loop exclusion.
    pub async fn bootstrap_resolve_proxy_hosts(&self) {
        let nodes: Vec<ProxyNode> = self.profile.read().proxies.clone();
        for node in nodes {
            if node.host.parse::<IpAddr>().is_err() {
                let _ = self.prepare_proxy_node_with_bootstrap(node).await;
            }
        }
    }

    pub(super) async fn prepare_proxy_node_with_bootstrap(
        &self,
        node: ProxyNode,
    ) -> RouteWardResult<ProxyNode> {
        self.prepare_proxy_node_with_bootstrap_and_spn(node)
            .await
            .map(|(resolved, _)| resolved)
    }

    pub(super) async fn prepare_proxy_node_with_bootstrap_and_spn(
        &self,
        mut node: ProxyNode,
    ) -> RouteWardResult<(ProxyNode, Option<String>)> {
        if node.host.parse::<IpAddr>().is_ok() {
            return Ok((node, None));
        }
        let orig_host = node.host.clone();
        let ips = self.resolve_host_direct_ipv4_all(&orig_host).await?;
        let Some(&first_ip) = ips.first() else {
            return Err(RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!(
                    "Bootstrap DNS resolution returned no IPv4 records for proxy host \"{orig_host}\""
                ),
            });
        };

        let pairs: Vec<(IpAddr, u16)> = ips.iter().map(|ip| (IpAddr::V4(*ip), node.port)).collect();
        let prev = self
            .bootstrapped_proxy_endpoints
            .get(&node.id)
            .map(|e| e.clone());
        let changed = prev.as_ref() != Some(&pairs);
        if changed {
            self.bootstrapped_proxy_endpoints
                .insert(node.id.clone(), pairs);
            self.sync_upstream_proxy_exclusions();
            self.telemetry.push_log(
                LogLevel::Debug,
                COMPONENT_DNS,
                format!(
                    "Bootstrap-resolved proxy host \"{orig_host}\":{} -> {:?} (added to anti-loop exclusions)",
                    node.port, ips
                ),
            );
        }

        if ProxyConnector::requires_tls(&node) && node.sni.is_none() {
            node.sni = Some(orig_host.clone());
        }
        node.host = first_ip.to_string();
        Ok((node, Some(orig_host)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProfileConfig, ProxyNode, ProxyProtocol, SystemConstants};
    use crate::interceptor::nat::{NatSessionEntry, PidResolutionSource};

    fn test_controller(grace_ms: u64) -> RouteWardController {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        constants.network.session_close_grace_ms = grace_ms;
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        RouteWardController::new(constants, profile, "en")
    }

    #[tokio::test]
    async fn relay_session_is_kept_for_the_grace_period_then_removed() {
        let controller = test_controller(150);
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        controller.nat_table.insert_session(NatSessionEntry {
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_port: 50555,
            orig_dst_ip: ip,
            orig_dst_port: 443,
            pid: 1,
            process_name: "a.exe".to_string(),
            process_path: "a.exe".to_string(),
            resolution_source: PidResolutionSource::SocketLayer,
            action: RuleAction::Direct,
            matched_rule_name: "r".to_string(),
            created_at: Instant::now(),
        });
        assert_eq!(controller.nat_table.session_count(), 1);

        controller.remove_relay_session_after_grace(ip, 50555);
        assert_eq!(
            controller.nat_table.session_count(),
            1,
            "the session must survive the relay end during the grace period"
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(controller.nat_table.session_count(), 0);
    }

    #[test]
    fn concurrent_connect_hints_never_lose_an_upstream_endpoint() {
        let controller = test_controller(250);
        let threads: Vec<_> = (1..=16u8)
            .map(|i| {
                let ctrl = controller.clone();
                std::thread::spawn(move || {
                    let node = ProxyNode {
                        id: format!("p{i}"),
                        name: format!("p{i}"),
                        protocol: ProxyProtocol::Socks5,
                        host: format!("192.0.2.{i}"),
                        port: 1080,
                        auth: None,
                        udp_enabled: false,
                        tls: false,
                        tls_skip_verify: false,
                        sni: None,
                        enabled: true,
                        last_latency_ms: None,
                        exit_ip: None,
                    };
                    let _ = ctrl.register_self_proxy_connect_hint(&node);
                })
            })
            .collect();
        for t in threads {
            t.join().expect("hint thread");
        }
        let endpoints = controller.nat_table.upstream_endpoints();
        for i in 1..=16u8 {
            let expected = (IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)), 1080);
            assert!(endpoints.contains(&expected), "missing {expected:?}");
        }
    }
}
