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
    DnsResolverMode, RouteWardController, COMPONENT_DNS, ROUTE_BLOCK_LABEL, ROUTE_DIRECT_LABEL,
};
use crate::config::{RuleAction, TransportProtocol};
use crate::dns::codec::{
    build_a_query, build_a_response, build_nodata_response, build_ptr_response,
    build_rcode_response, build_rcode_response_from_raw, encode_tcp_dns_frame,
    enforce_udp_truncation, extract_ipv4_answers, parse_dns_message, parse_dns_query,
    parse_ipv4_ptr_qname, rewrite_transaction_id, DnsQueryPacket, DNS_MAX_TCP_MESSAGE_BYTES,
    QTYPE_A, QTYPE_AAAA, QTYPE_PTR, RCODE_FORMERR, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL,
};
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_HANDSHAKE_FAILED};
use crate::interceptor::nat::SelfPortGuard;
#[cfg(target_os = "linux")]
use crate::proxy::ProxyConnector;
use crate::rules::ConnectionRequest;
use crate::telemetry::LogLevel;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

impl RouteWardController {
    /// Fast synchronous DNS resolution path for in-memory Fake-IP (`A`), `AAAA` (`NODATA`),
    /// Fake-IP `PTR`, and DoH canary (`NXDOMAIN`) queries. Returns `None` when network I/O is required
    /// (bypassed domains, `enableFakeIp = false`, or non-A/AAAA record types).
    pub fn resolve_dns_query_fast(&self, raw_query: &[u8]) -> Option<Vec<u8>> {
        let query = match parse_dns_query(raw_query) {
            Ok(q) => q,
            Err(_) => {
                return build_rcode_response_from_raw(raw_query, RCODE_FORMERR);
            }
        };

        let (enable_fake_ip, block_encrypted_dns) = {
            let prof = self.profile.read();
            (
                prof.dns_config.enable_fake_ip,
                prof.security_policy.block_encrypted_dns_bypass,
            )
        };

        let qname = &query.question.qname;
        let qtype = query.question.qtype;

        // 1. DoH canary domain (use-application-dns.net): return NXDOMAIN and log WARN
        if block_encrypted_dns && self.dns.is_doh_canary(qname) {
            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_DNS,
                format!(
                    "Blocked DoH canary DNS query for \"{}\" (returning NXDOMAIN; blockEncryptedDnsBypass=true)",
                    qname
                ),
            );
            return Some(build_rcode_response(&query, RCODE_NXDOMAIN));
        }

        // 2. Reverse PTR lookup for a Fake-IP in our pool (198.18.0.0/15)
        if qtype == QTYPE_PTR {
            if let Some(ip) = parse_ipv4_ptr_qname(qname) {
                if self.dns.is_in_fake_subnet(&ip) {
                    if let Some(domain) = self.dns.resolve_fake_ip(&ip) {
                        self.telemetry.push_log(
                            LogLevel::Debug,
                            COMPONENT_DNS,
                            format!("Fake-IP PTR {qname} ({ip}) -> {domain}"),
                        );
                        if let Ok(pkt) =
                            build_ptr_response(&query, &domain, self.dns.os_response_ttl_seconds())
                        {
                            return Some(pkt);
                        }
                    }
                    return Some(build_rcode_response(&query, RCODE_NXDOMAIN));
                }
            }
        }

        // 3. Bypassed domains (AD suffixes, single-label, .local, .localhost, private reverse zones)
        // must always be resolved via the async direct network path.
        if self.dns.is_bypassed(qname) {
            return None;
        }

        // 4. When Fake-IP is enabled: A -> pool IP with 5s OS TTL; AAAA -> NODATA
        if enable_fake_ip {
            if qtype == QTYPE_A {
                if let Some(fake_ip) = self.dns.allocate_or_get(qname) {
                    self.telemetry.push_log(
                        LogLevel::Debug,
                        COMPONENT_DNS,
                        format!(
                            "Fake-IP A \"{}\" -> {} (os_ttl={}s, internal_ttl={}s)",
                            qname,
                            fake_ip,
                            self.dns.os_response_ttl_seconds(),
                            self.dns.internal_ttl_seconds()
                        ),
                    );
                    return Some(build_a_response(
                        &query,
                        fake_ip,
                        self.dns.os_response_ttl_seconds(),
                    ));
                }
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DNS,
                    format!(
                        "Fake-IP pool exhausted for \"{}\"; returning SERVFAIL without cleartext DNS fallback",
                        qname
                    ),
                );
                return Some(build_rcode_response(&query, RCODE_SERVFAIL));
            } else if qtype == QTYPE_AAAA {
                self.telemetry.push_log(
                    LogLevel::Debug,
                    COMPONENT_DNS,
                    format!("Fake-IP AAAA \"{}\" -> NODATA (RCODE=0, ANCOUNT=0)", qname),
                );
                return Some(build_nodata_response(&query));
            }
        }

        None
    }

    /// Resolves a DNS query wire message asynchronously, handling fast in-memory responses,
    /// direct bypass resolution toward the originally targeted DNS server, and real DNS-over-TCP
    /// resolution through the configured proxy.
    pub async fn resolve_dns_query_async(
        &self,
        raw_query: &[u8],
        orig_resolver: Option<SocketAddr>,
        is_udp: bool,
    ) -> Vec<u8> {
        if let Some(orig) = orig_resolver {
            self.record_orig_dns_resolver(orig);
        }

        if let Some(fast_resp) = self.resolve_dns_query_fast(raw_query) {
            if is_udp {
                if let Ok(parsed_q) = parse_dns_query(raw_query) {
                    return enforce_udp_truncation(
                        &fast_resp,
                        &parsed_q,
                        parsed_q.max_udp_payload_bytes,
                    );
                }
            }
            return fast_resp;
        }

        let query = match parse_dns_query(raw_query) {
            Ok(q) => q,
            Err(_) => {
                return build_rcode_response_from_raw(raw_query, RCODE_FORMERR).unwrap_or_default();
            }
        };

        let qname = &query.question.qname;

        // 1. Bypassed domain: resolve directly toward the DNS server that the OS originally targeted
        // or active system resolvers; never query upstreamDns, default_upstream, or fallback_dns_server.
        if self.dns.is_bypassed(qname) {
            let resolvers =
                self.candidate_dns_resolvers(orig_resolver, DnsResolverMode::BypassOnlySystem);
            for resolver_addr in &resolvers {
                match self
                    .forward_dns_query_direct(raw_query, &query, *resolver_addr, is_udp)
                    .await
                {
                    Ok(resp) => {
                        self.telemetry.push_log(
                            LogLevel::Debug,
                            COMPONENT_DNS,
                            format!(
                                "Resolved bypassed domain \"{}\" (qtype={}) directly via {}",
                                qname, query.question.qtype, resolver_addr
                            ),
                        );
                        return resp;
                    }
                    Err(err) => {
                        self.telemetry.push_log(
                            LogLevel::Debug,
                            COMPONENT_DNS,
                            format!(
                                "Direct bypass DNS query for \"{}\" via {} failed: {}",
                                qname, resolver_addr, err
                            ),
                        );
                    }
                }
            }

            self.telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_DNS,
                format!(
                    "Direct DNS resolution failed for bypassed domain \"{}\" across {:?}; returning SERVFAIL without querying public upstream resolvers",
                    qname, resolvers
                ),
            );
            return build_rcode_response(&query, RCODE_SERVFAIL);
        }

        // 2. Real DNS resolution via DNS-over-TCP through the rule's proxy
        let dns_action = self.select_dns_resolution_action(qname);
        match &dns_action {
            RuleAction::Block => {
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DNS,
                    format!("Blocked DNS query for \"{}\" by routing rule", qname),
                );
                build_rcode_response(&query, RCODE_REFUSED)
            }
            RuleAction::Direct => {
                let resolvers = self
                    .candidate_dns_resolvers(orig_resolver, DnsResolverMode::DirectPreferSystem);
                for resolver_addr in &resolvers {
                    if let Ok(resp) = self
                        .forward_dns_query_direct(raw_query, &query, *resolver_addr, is_udp)
                        .await
                    {
                        return resp;
                    }
                }
                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DNS,
                    format!(
                        "Direct DNS resolution failed for \"{}\" across {:?}; returning SERVFAIL",
                        qname, resolvers
                    ),
                );
                build_rcode_response(&query, RCODE_SERVFAIL)
            }
            RuleAction::Proxy { .. } | RuleAction::Chain { .. } => {
                let resolvers =
                    self.candidate_dns_resolvers(orig_resolver, DnsResolverMode::RemoteViaProxy);
                let mut last_err = String::from("no upstream DNS server configured");
                for resolver_addr in &resolvers {
                    match self
                        .forward_dns_over_tcp_via_action(
                            raw_query,
                            &query,
                            &dns_action,
                            *resolver_addr,
                            is_udp,
                        )
                        .await
                    {
                        Ok(resp) => {
                            self.telemetry.push_log(
                                LogLevel::Debug,
                                COMPONENT_DNS,
                                format!(
                                    "Resolved \"{}\" (qtype={}) via DNS-over-TCP through proxy ({})",
                                    qname, query.question.qtype, resolver_addr
                                ),
                            );
                            return resp;
                        }
                        Err(err) => {
                            last_err = err.to_string();
                        }
                    }
                }

                let (strict_no_fallback, kill_switch_enabled) = {
                    let prof = self.profile.read();
                    (
                        prof.security_policy.strict_dns_no_local_fallback,
                        prof.security_policy.kill_switch_enabled,
                    )
                };

                if strict_no_fallback || kill_switch_enabled {
                    self.telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_DNS,
                        format!(
                            "DNS-over-TCP via proxy failed for \"{}\" (strictDnsNoLocalFallback={}, killSwitchEnabled={}): {}; returning SERVFAIL without cleartext fallback",
                            qname, strict_no_fallback, kill_switch_enabled, last_err
                        ),
                    );
                    return build_rcode_response(&query, RCODE_SERVFAIL);
                }

                self.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_DNS,
                    format!(
                        "DNS-over-TCP via proxy failed for \"{}\" ({}); falling back to direct DNS because strictDnsNoLocalFallback=false and killSwitchEnabled=false",
                        qname, last_err
                    ),
                );
                for resolver_addr in
                    self.candidate_dns_resolvers(orig_resolver, DnsResolverMode::DirectPreferSystem)
                {
                    if let Ok(resp) = self
                        .forward_dns_query_direct(raw_query, &query, resolver_addr, is_udp)
                        .await
                    {
                        return resp;
                    }
                }
                build_rcode_response(&query, RCODE_SERVFAIL)
            }
        }
    }

    pub(super) fn select_dns_resolution_action(&self, qname: &str) -> RuleAction {
        let eval = self.evaluate_rule(&ConnectionRequest {
            process_name: "dns-resolver".to_string(),
            process_path: None,
            target_host: qname.to_string(),
            target_ip: None,
            target_port: self.constants.dns.dns_standard_port,
            protocol: TransportProtocol::Tcp,
        });

        if !matches!(eval.action, RuleAction::Direct) {
            return eval.action;
        }

        let prof = self.profile.read();
        if !prof.dns_config.remote_dns_resolution {
            return RuleAction::Direct;
        }

        if matches!(
            prof.default_action,
            RuleAction::Proxy { .. } | RuleAction::Chain { .. }
        ) {
            return prof.default_action.clone();
        }

        for rule in &prof.rules {
            if rule.enabled
                && matches!(
                    rule.action,
                    RuleAction::Proxy { .. } | RuleAction::Chain { .. }
                )
            {
                return rule.action.clone();
            }
        }

        if let Some(first_proxy) = prof.proxies.iter().find(|p| p.enabled) {
            return RuleAction::Proxy {
                target_id: first_proxy.id.clone(),
            };
        }

        RuleAction::Direct
    }

    /// Handles a DNS-over-TCP client connection (RFC 1035 2-byte big-endian length-prefixed frames).
    pub async fn handle_dns_tcp_stream(
        &self,
        mut client: TcpStream,
        orig_resolver: Option<SocketAddr>,
    ) -> RouteWardResult<()> {
        let timeout_dur = Duration::from_millis(self.constants.network.proxy_handshake_timeout_ms);
        loop {
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(timeout_dur, client.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                _ => break,
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 || msg_len > DNS_MAX_TCP_MESSAGE_BYTES {
                break;
            }
            let mut query_buf = vec![0u8; msg_len];
            if tokio::time::timeout(timeout_dur, client.read_exact(&mut query_buf))
                .await
                .is_err()
            {
                break;
            }

            let resp = self
                .resolve_dns_query_async(&query_buf, orig_resolver, false)
                .await;
            if resp.is_empty() {
                break;
            }
            let framed = encode_tcp_dns_frame(&resp);
            if tokio::time::timeout(timeout_dur, client.write_all(&framed))
                .await
                .is_err()
            {
                break;
            }
            let _ = client.flush().await;
        }
        let _ = client.shutdown().await;
        Ok(())
    }

    /// Resolves a domain name directly to its real IPv4 address (bypassing Fake-IP and the OS stub resolver).
    pub async fn resolve_host_direct_ipv4(&self, domain: &str) -> RouteWardResult<Ipv4Addr> {
        let ips = self.resolve_host_direct_ipv4_all(domain).await?;
        ips.into_iter()
            .next()
            .ok_or_else(|| RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: format!("Direct DNS resolution returned no A records for \"{domain}\""),
            })
    }

    /// Resolves a domain name directly to all `A` record IPv4 addresses returned by the direct resolver.
    pub async fn resolve_host_direct_ipv4_all(
        &self,
        domain: &str,
    ) -> RouteWardResult<Vec<Ipv4Addr>> {
        let resolved_domain_storage;
        let target_domain = if let Ok(ip) = domain.parse::<Ipv4Addr>() {
            if self.dns.is_in_fake_subnet(&ip) {
                if let Some(mapped) = self.dns.resolve_fake_ip(&ip) {
                    resolved_domain_storage = mapped;
                    resolved_domain_storage.as_str()
                } else {
                    return Err(RouteWardError::ProtocolHandshake {
                        key: ERR_KEY_HANDSHAKE_FAILED,
                        detail: format!(
                            "Cannot resolve unmapped Fake-IP {ip} to a real IPv4 address"
                        ),
                    });
                }
            } else {
                return Ok(vec![ip]);
            }
        } else {
            domain
        };
        let trimmed = target_domain.trim().trim_end_matches('.');
        if trimmed.eq_ignore_ascii_case("localhost") {
            return Ok(vec![Ipv4Addr::LOCALHOST]);
        }

        let id_bytes = Uuid::new_v4().into_bytes();
        let query_id = u16::from_be_bytes([id_bytes[0], id_bytes[1]]).max(1);
        let raw_query =
            build_a_query(query_id, trimmed).map_err(|e| RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: e.to_string(),
            })?;
        let parsed_q =
            parse_dns_query(&raw_query).map_err(|e| RouteWardError::ProtocolHandshake {
                key: ERR_KEY_HANDSHAKE_FAILED,
                detail: e.to_string(),
            })?;

        let resolver_mode = if self.dns.is_bypassed(trimmed) {
            DnsResolverMode::BypassOnlySystem
        } else {
            DnsResolverMode::DirectPreferSystem
        };
        let mut resolvers = self.candidate_dns_resolvers(None, resolver_mode);
        if resolver_mode == DnsResolverMode::DirectPreferSystem
            && self.system_resolvers_override.read().is_none()
        {
            for fallback_sa in
                self.candidate_dns_resolvers_with_system(None, DnsResolverMode::RemoteViaProxy, &[])
            {
                if !resolvers.contains(&fallback_sa) {
                    resolvers.push(fallback_sa);
                }
            }
        }
        let mut last_err = String::from("no direct DNS resolver reachable");
        for resolver_addr in resolvers {
            match self
                .forward_dns_query_direct(&raw_query, &parsed_q, resolver_addr, false)
                .await
            {
                Ok(resp_wire) => {
                    if let Ok(addrs) = extract_ipv4_answers(&resp_wire) {
                        let real_addrs: Vec<Ipv4Addr> = addrs
                            .into_iter()
                            .filter(|ip| !self.dns.is_in_fake_subnet(ip))
                            .collect();
                        if !real_addrs.is_empty() {
                            return Ok(real_addrs);
                        }
                        last_err =
                            format!("no non-Fake-IP A records in response from {resolver_addr}");
                    } else {
                        last_err = format!("no A records in response from {resolver_addr}");
                    }
                }
                Err(err) => {
                    last_err = err.to_string();
                }
            }
        }

        Err(RouteWardError::ProtocolHandshake {
            key: ERR_KEY_HANDSHAKE_FAILED,
            detail: format!("Direct DNS resolution failed for \"{trimmed}\": {last_err}"),
        })
    }

    pub(super) async fn forward_dns_over_tcp_via_action(
        &self,
        raw_query: &[u8],
        query: &DnsQueryPacket,
        action: &RuleAction,
        resolver_addr: SocketAddr,
        is_udp: bool,
    ) -> RouteWardResult<Vec<u8>> {
        let timeout_dur = Duration::from_millis(self.constants.network.proxy_handshake_timeout_ms);
        let mut stream = self
            .open_outbound_stream(
                action,
                &resolver_addr.ip().to_string(),
                resolver_addr.port(),
            )
            .await?;

        let framed = encode_tcp_dns_frame(raw_query);
        tokio::time::timeout(timeout_dur, stream.write_all(&framed))
            .await
            .map_err(|_| {
                RouteWardError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DNS-over-TCP write timed out",
                ))
            })?
            .map_err(RouteWardError::Io)?;
        let _ = stream.flush().await;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                RouteWardError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DNS-over-TCP response header timed out",
                ))
            })?
            .map_err(RouteWardError::Io)?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > DNS_MAX_TCP_MESSAGE_BYTES {
            return Err(RouteWardError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid DNS-over-TCP response length",
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| {
                RouteWardError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DNS-over-TCP response body timed out",
                ))
            })?
            .map_err(RouteWardError::Io)?;
        let _ = stream.shutdown().await;

        rewrite_transaction_id(&mut resp_buf, query.id);
        if is_udp {
            Ok(enforce_udp_truncation(
                &resp_buf,
                query,
                query.max_udp_payload_bytes,
            ))
        } else {
            Ok(resp_buf)
        }
    }

    pub(super) async fn forward_dns_query_direct(
        &self,
        raw_query: &[u8],
        query: &DnsQueryPacket,
        resolver_addr: SocketAddr,
        is_udp: bool,
    ) -> std::io::Result<Vec<u8>> {
        let timeout_dur = Duration::from_millis(
            self.constants
                .network
                .tcp_connect_timeout_ms
                .clamp(500, 2500),
        );

        if let Ok(udp_resp) = self
            .query_dns_udp_direct_protected(raw_query, resolver_addr, timeout_dur)
            .await
        {
            if let Ok(msg) = parse_dns_message(&udp_resp) {
                if !msg.is_truncated() {
                    let mut out = udp_resp;
                    rewrite_transaction_id(&mut out, query.id);
                    if is_udp {
                        return Ok(enforce_udp_truncation(
                            &out,
                            query,
                            query.max_udp_payload_bytes,
                        ));
                    }
                    return Ok(out);
                }
            }
        }

        // Fallback to direct DNS-over-TCP (e.g. if UDP was truncated with TC=1 or UDP failed)
        let mut tcp_resp = self
            .query_dns_tcp_direct_protected(raw_query, resolver_addr, timeout_dur)
            .await?;
        rewrite_transaction_id(&mut tcp_resp, query.id);
        if is_udp {
            Ok(enforce_udp_truncation(
                &tcp_resp,
                query,
                query.max_udp_payload_bytes,
            ))
        } else {
            Ok(tcp_resp)
        }
    }

    pub(super) async fn query_dns_udp_direct_protected(
        &self,
        raw_query: &[u8],
        resolver_addr: SocketAddr,
        timeout_dur: Duration,
    ) -> std::io::Result<Vec<u8>> {
        self.ensure_not_fake_ip_egress(
            resolver_addr.ip(),
            resolver_addr.port(),
            TransportProtocol::Udp,
            "query_dns_udp_direct_protected",
        )
        .map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
        })?;

        let bind_addr = if resolver_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let std_sock = std::net::UdpSocket::bind(bind_addr)?;
        std_sock.set_nonblocking(true)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let fwmark = self.constants.network.linux_fwmark;
            if fwmark != 0 {
                let fd = std_sock.as_raw_fd();
                let _ = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &fwmark as *const u32 as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                };
            }
        }

        let local_port = std_sock.local_addr()?.port();
        let _port_guard = self.nat_table.register_self_udp_port(local_port);

        let sock = UdpSocket::from_std(std_sock)?;
        tokio::time::timeout(timeout_dur, sock.send_to(raw_query, resolver_addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP DNS send timeout")
            })??;

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(timeout_dur, sock.recv_from(&mut buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP DNS recv timeout")
            })??;
        buf.truncate(len);
        Ok(buf)
    }

    pub(super) async fn acquire_direct_udp_socket(
        &self,
        is_ipv6: bool,
    ) -> std::io::Result<(UdpSocket, SelfPortGuard)> {
        if is_ipv6 {
            if let Some(existing) = self.direct_udp_v6_pool.lock().pop() {
                return Ok(existing);
            }
        } else if let Some(existing) = self.direct_udp_pool.lock().pop() {
            return Ok(existing);
        }
        let bind_addr = if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" };
        let std_sock = std::net::UdpSocket::bind(bind_addr)?;
        std_sock.set_nonblocking(true)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let fwmark = self.constants.network.linux_fwmark;
            if fwmark != 0 {
                let fd = std_sock.as_raw_fd();
                let _ = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &fwmark as *const u32 as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                };
            }
        }

        let local_port = std_sock.local_addr()?.port();
        let port_guard = self.nat_table.register_self_udp_port(local_port);
        let sock = UdpSocket::from_std(std_sock)?;
        Ok((sock, port_guard))
    }

    pub(super) async fn send_and_optional_recv_udp_direct_protected(
        &self,
        payload: &[u8],
        target_addr: SocketAddr,
        recv_timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        const MAX_POOLED_DIRECT_UDP_SOCKETS: usize = 16;

        self.ensure_not_fake_ip_egress(
            target_addr.ip(),
            target_addr.port(),
            TransportProtocol::Udp,
            "send_and_optional_recv_udp_direct_protected",
        )
        .map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
        })?;

        let is_ipv6 = target_addr.is_ipv6();
        let (sock, port_guard) = self.acquire_direct_udp_socket(is_ipv6).await?;
        let mut drain_buf = [0u8; 2048];
        while sock.try_recv_from(&mut drain_buf).is_ok() {}

        tokio::time::timeout(recv_timeout, sock.send_to(payload, target_addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP send timeout"))??;

        let mut buf = vec![0u8; 65535];
        let result = match tokio::time::timeout(recv_timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                buf.truncate(len);
                Ok(buf)
            }
            _ => Ok(Vec::new()),
        };

        let mut pool = if is_ipv6 {
            self.direct_udp_v6_pool.lock()
        } else {
            self.direct_udp_pool.lock()
        };
        if pool.len() < MAX_POOLED_DIRECT_UDP_SOCKETS {
            pool.push((sock, port_guard));
        }
        result
    }

    pub(super) async fn query_dns_tcp_direct_protected(
        &self,
        raw_query: &[u8],
        resolver_addr: SocketAddr,
        timeout_dur: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let mut stream = tokio::time::timeout(
            timeout_dur,
            self.connect_direct_tcp_protected(resolver_addr),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS connect timeout")
        })??;

        let framed = encode_tcp_dns_frame(raw_query);
        tokio::time::timeout(timeout_dur, stream.write_all(&framed))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS write timeout")
            })??;
        let _ = stream.flush().await;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS read len timeout")
            })??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > DNS_MAX_TCP_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid TCP DNS response length",
            ));
        }

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS read body timeout")
            })??;
        let _ = stream.shutdown().await;
        Ok(resp_buf)
    }

    pub(super) async fn connect_direct_tcp_protected(
        &self,
        target: SocketAddr,
    ) -> std::io::Result<TcpStream> {
        self.ensure_not_fake_ip_egress(
            target.ip(),
            target.port(),
            TransportProtocol::Tcp,
            "connect_direct_tcp_protected",
        )
        .map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
        })?;

        #[cfg(target_os = "linux")]
        {
            ProxyConnector::connect_tcp_marked(
                &target.to_string(),
                self.constants.network.linux_fwmark,
            )
            .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let sock = match target {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
            };
            let bind_addr: SocketAddr = match target {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => {
                    SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
                }
            };
            sock.bind(bind_addr)?;
            let local_port = sock.local_addr()?.port();
            let _port_guard = self.nat_table.register_self_tcp_port(local_port);
            sock.connect(target).await
        }
    }

    pub(super) fn lookup_udp_orig_dns_resolver(&self, peer_addr: SocketAddr) -> Option<SocketAddr> {
        self.lookup_udp_conntrack_orig_dst(peer_addr, &[self.constants.dns.dns_standard_port])
    }

    pub(super) fn lookup_udp_conntrack_orig_dst(
        &self,
        peer_addr: SocketAddr,
        candidate_dports: &[u16],
    ) -> Option<SocketAddr> {
        #[cfg(target_os = "linux")]
        {
            const CONNTRACK_CACHE_TTL_MS: u64 = 100;
            let sport_tag = format!("sport={}", peer_addr.port());
            let cached_content = {
                let guard = self.conntrack_cache.lock();
                guard.as_ref().and_then(|(ts, text)| {
                    if ts.elapsed() <= Duration::from_millis(CONNTRACK_CACHE_TTL_MS) {
                        Some(text.clone())
                    } else {
                        None
                    }
                })
            };
            let content_opt = match cached_content {
                Some(c) => Some(c),
                None => match std::fs::read_to_string("/proc/net/nf_conntrack") {
                    Ok(fresh) => {
                        *self.conntrack_cache.lock() = Some((Instant::now(), fresh.clone()));
                        Some(fresh)
                    }
                    Err(_) => None,
                },
            };
            if let Some(content) = content_opt {
                for line in content.lines() {
                    if !line.contains("udp") || !line.contains(&sport_tag) {
                        continue;
                    }
                    for &dport in candidate_dports {
                        let dport_tag = format!("dport={dport}");
                        if line.contains(&dport_tag) {
                            for token in line.split_whitespace() {
                                if let Some(ip_str) = token.strip_prefix("dst=") {
                                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                        if !ip.is_loopback() && ip.is_ipv6() == peer_addr.is_ipv6()
                                        {
                                            return Some(SocketAddr::new(ip, dport));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let _ = (peer_addr, candidate_dports);
        None
    }

    pub(super) fn candidate_dns_resolvers(
        &self,
        orig_resolver: Option<SocketAddr>,
        mode: DnsResolverMode,
    ) -> Vec<SocketAddr> {
        let sys_resolvers = if let Some(ref ov) = *self.system_resolvers_override.read() {
            ov.clone()
        } else {
            crate::dns::detect_system_dns_resolvers(&self.constants.dns)
        };
        self.candidate_dns_resolvers_with_system(orig_resolver, mode, &sys_resolvers)
    }

    pub(super) fn candidate_dns_resolvers_with_system(
        &self,
        orig_resolver: Option<SocketAddr>,
        mode: DnsResolverMode,
        system_resolvers: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        let mut list = Vec::new();
        let dns_port = self.constants.dns.dns_standard_port;
        let local_dns_listen_port = self.constants.network.default_dns_listen_port;
        let configured_upstream = self.profile.read().dns_config.upstream_dns.clone();
        let default_upstream = &self.constants.dns.upstream_dns_server;

        let push_unique = |out: &mut Vec<SocketAddr>, addr: SocketAddr| {
            if let IpAddr::V4(v4) = addr.ip() {
                if self.dns.is_in_fake_subnet(&v4) {
                    return;
                }
            }
            let is_safe_loopback = addr.ip().is_loopback()
                && addr.port() != dns_port
                && addr.port() != local_dns_listen_port;
            if (!addr.ip().is_loopback() || is_safe_loopback)
                && !addr.ip().is_unspecified()
                && !out.contains(&addr)
            {
                out.push(addr);
            }
        };

        let parse_host_port = |raw: &str| -> Option<SocketAddr> {
            if let Ok(sa) = raw.parse::<SocketAddr>() {
                return Some(sa);
            }
            if let Ok(ip) = raw.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, dns_port));
            }
            None
        };

        match mode {
            DnsResolverMode::BypassOnlySystem => {
                if let Some(orig) = orig_resolver {
                    push_unique(&mut list, orig);
                }
                if let Some(last_orig) = *self.last_seen_orig_resolver.read() {
                    push_unique(&mut list, last_orig);
                }
                for sa in system_resolvers {
                    push_unique(&mut list, *sa);
                }
            }
            DnsResolverMode::DirectPreferSystem => {
                if let Some(orig) = orig_resolver {
                    push_unique(&mut list, orig);
                }
                if let Some(last_orig) = *self.last_seen_orig_resolver.read() {
                    push_unique(&mut list, last_orig);
                }
                for sa in system_resolvers {
                    push_unique(&mut list, *sa);
                }
                if list.is_empty() {
                    if let Some(sa) = parse_host_port(&configured_upstream) {
                        push_unique(&mut list, sa);
                    }
                    if let Some(sa) = parse_host_port(default_upstream) {
                        push_unique(&mut list, sa);
                    }
                    if let Some(sa) = parse_host_port(&self.constants.dns.fallback_dns_server) {
                        push_unique(&mut list, sa);
                    }
                }
            }
            DnsResolverMode::RemoteViaProxy => {
                if configured_upstream != *default_upstream {
                    if let Some(sa) = parse_host_port(&configured_upstream) {
                        push_unique(&mut list, sa);
                    }
                }
                if let Some(orig) = orig_resolver {
                    push_unique(&mut list, orig);
                }
                if let Some(sa) = parse_host_port(&configured_upstream) {
                    push_unique(&mut list, sa);
                }
                if let Some(sa) = parse_host_port(default_upstream) {
                    push_unique(&mut list, sa);
                }
                if let Some(sa) = parse_host_port(&self.constants.dns.fallback_dns_server) {
                    push_unique(&mut list, sa);
                }
            }
        }

        list
    }

    pub(super) fn format_action_label(&self, action: &RuleAction) -> String {
        let prof = self.profile.read();
        match action {
            RuleAction::Direct => ROUTE_DIRECT_LABEL.to_string(),
            RuleAction::Block => ROUTE_BLOCK_LABEL.to_string(),
            RuleAction::Proxy { target_id } => prof
                .proxies
                .iter()
                .find(|p| &p.id == target_id)
                .map(|p| format!("{} ({:?})", p.name, p.protocol))
                .unwrap_or_else(|| target_id.clone()),
            RuleAction::Chain { target_id } => prof
                .chains
                .iter()
                .find(|c| &c.id == target_id)
                .map(|c| format!("Chain: {} ({} hops)", c.name, c.proxy_ids.len()))
                .unwrap_or_else(|| target_id.clone()),
        }
    }

    pub fn detect_elevated_privileges() -> bool {
        #[cfg(windows)]
        {
            use std::ptr::null_mut;
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            use windows_sys::Win32::Security::{
                GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            unsafe {
                let mut token: HANDLE = null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return false;
                }
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut ret_len: u32 = 0;
                let ok = GetTokenInformation(
                    token,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut _,
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut ret_len,
                );
                let _ = CloseHandle(token);
                ok != 0 && elevation.TokenIsElevated != 0
            }
        }
        #[cfg(target_os = "linux")]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            false
        }
    }
}
