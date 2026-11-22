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
use crate::proxy::udp::is_expected_relay_source;
#[cfg(target_os = "linux")]
use crate::proxy::ProxyConnector;
use crate::rules::{ConnectionRequest, RuleEngine};
use crate::telemetry::LogLevel;
use chrono::Utc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

/// Largest possible UDP payload, used as the receive buffer of relayed datagrams.
pub(super) const MAX_UDP_DATAGRAM_BYTES: usize = 65535;

/// Scratch buffer size used to discard stale datagrams queued on a pooled UDP socket before
/// a new exchange (content is thrown away, so only a typical DNS-over-UDP size is needed).
const UDP_DRAIN_BUFFER_BYTES: usize = 2048;

/// Length in bytes of the DNS transaction ID at the start of a message.
const DNS_ID_LEN: usize = 2;

/// One parsed `nf_conntrack` snapshot: UDP flows keyed by their original source port, each with
/// the original destination address and port.
#[cfg(any(target_os = "linux", test))]
pub(super) struct ConntrackSnapshot {
    taken_at: Instant,
    udp_by_sport: HashMap<u16, Vec<(IpAddr, u16)>>,
}

#[cfg(any(target_os = "linux", test))]
impl ConntrackSnapshot {
    /// Returns the original destination of the UDP flow whose source port is `sport`, restricted to
    /// `candidate_dports`, skipping loopback destinations and other address families.
    fn find(&self, sport: u16, want_ipv6: bool, candidate_dports: &[u16]) -> Option<SocketAddr> {
        let entries = self.udp_by_sport.get(&sport)?;
        for &dport in candidate_dports {
            for (dst, entry_dport) in entries {
                if *entry_dport == dport && !dst.is_loopback() && dst.is_ipv6() == want_ipv6 {
                    return Some(SocketAddr::new(*dst, dport));
                }
            }
        }
        None
    }
}

/// Parses the text of `/proc/net/nf_conntrack`, keeping only the original tuple (the first
/// `dst=`, `sport=` and `dport=` tokens of a line) of UDP flows.
#[cfg(any(target_os = "linux", test))]
pub(super) fn parse_conntrack_udp_table(text: &str) -> HashMap<u16, Vec<(IpAddr, u16)>> {
    let mut table: HashMap<u16, Vec<(IpAddr, u16)>> = HashMap::new();
    for line in text.lines() {
        let mut is_udp = false;
        let mut dst: Option<IpAddr> = None;
        let mut sport: Option<u16> = None;
        let mut dport: Option<u16> = None;
        for token in line.split_whitespace() {
            if token == "udp" {
                is_udp = true;
            }
            if dst.is_none() {
                if let Some(raw) = token.strip_prefix("dst=") {
                    dst = raw.parse().ok();
                }
            }
            if sport.is_none() {
                if let Some(raw) = token.strip_prefix("sport=") {
                    sport = raw.parse().ok();
                }
            }
            if dport.is_none() {
                if let Some(raw) = token.strip_prefix("dport=") {
                    dport = raw.parse().ok();
                }
            }
        }
        if let (true, Some(dst), Some(sport), Some(dport)) = (is_udp, dst, sport, dport) {
            table.entry(sport).or_default().push((dst, dport));
        }
    }
    table
}

/// Caches shared by the relay hot paths (one instance per controller).
pub(crate) struct RelayCaches {
    /// Domain (lowercase, no trailing dot) -> real IPv4 address resolved directly, with its
    /// resolution time. Serves Direct UDP traffic addressed to a Fake-IP or a domain.
    real_ipv4: Mutex<HashMap<String, (Ipv4Addr, Instant)>>,
    /// Last detected system DNS resolver list and when it was detected.
    system_resolvers: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
    /// Serialises read-modify-write updates of the NAT upstream endpoint list.
    pub(super) upstream_endpoints: Mutex<()>,
    /// Last parsed conntrack table.
    #[cfg(any(target_os = "linux", test))]
    conntrack: Mutex<Option<ConntrackSnapshot>>,
}

impl RelayCaches {
    pub(crate) fn new() -> Self {
        Self {
            real_ipv4: Mutex::new(HashMap::new()),
            system_resolvers: Mutex::new(None),
            upstream_endpoints: Mutex::new(()),
            #[cfg(any(target_os = "linux", test))]
            conntrack: Mutex::new(None),
        }
    }

    fn lookup_real_ipv4(&self, key: &str, ttl: Duration) -> Option<Ipv4Addr> {
        if ttl.is_zero() {
            return None;
        }
        let guard = self.real_ipv4.lock();
        guard
            .get(key)
            .filter(|(_, at)| at.elapsed() < ttl)
            .map(|(ip, _)| *ip)
    }

    fn store_real_ipv4(&self, key: String, ip: Ipv4Addr, ttl: Duration, max_entries: usize) {
        if ttl.is_zero() || max_entries == 0 {
            return;
        }
        let mut guard = self.real_ipv4.lock();
        if guard.len() >= max_entries && !guard.contains_key(&key) {
            guard.retain(|_, (_, at)| at.elapsed() < ttl);
            if guard.len() >= max_entries {
                let oldest = guard
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(k, _)| k.clone());
                if let Some(oldest) = oldest {
                    guard.remove(&oldest);
                }
            }
        }
        guard.insert(key, (ip, Instant::now()));
    }

    fn system_resolvers_or_detect(
        &self,
        ttl: Duration,
        detect: impl FnOnce() -> Vec<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut guard = self.system_resolvers.lock();
        if let Some((at, list)) = guard.as_ref() {
            if at.elapsed() < ttl {
                return list.clone();
            }
        }
        let fresh = detect();
        *guard = Some((Instant::now(), fresh.clone()));
        fresh
    }

    /// Looks up the original destination of a UDP flow in the cached conntrack table. The table is
    /// reused for `ttl`; a miss only refreshes it once it is older than `min_refresh`, so a burst of
    /// unrelated lookups never re-reads the kernel table. `read_table` returns the table text.
    #[cfg(any(target_os = "linux", test))]
    fn conntrack_lookup(
        &self,
        sport: u16,
        want_ipv6: bool,
        candidate_dports: &[u16],
        ttl: Duration,
        min_refresh: Duration,
        read_table: impl FnOnce() -> Option<String>,
    ) -> Option<SocketAddr> {
        let mut guard = self.conntrack.lock();
        if let Some(snapshot) = guard.as_ref() {
            let age = snapshot.taken_at.elapsed();
            if age <= ttl {
                if let Some(hit) = snapshot.find(sport, want_ipv6, candidate_dports) {
                    return Some(hit);
                }
                if age < min_refresh {
                    return None;
                }
            }
        }
        let text = read_table().unwrap_or_default();
        let snapshot = ConntrackSnapshot {
            taken_at: Instant::now(),
            udp_by_sport: parse_conntrack_udp_table(&text),
        };
        let hit = snapshot.find(sport, want_ipv6, candidate_dports);
        *guard = Some(snapshot);
        hit
    }
}

/// Reads datagrams from `sock` until `accept(source, payload)` approves one or `timeout` elapses.
/// Datagrams that are not accepted are discarded. Returns the payload length written to `buf`.
async fn recv_accepted_datagram(
    sock: &UdpSocket,
    buf: &mut [u8],
    timeout: Duration,
    accept: impl Fn(SocketAddr, &[u8]) -> bool,
) -> Option<usize> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let (len, source) = tokio::time::timeout_at(deadline, sock.recv_from(buf))
            .await
            .ok()?
            .ok()?;
        if accept(source, &buf[..len]) {
            return Some(len);
        }
    }
}

/// Returns `true` when `reply` answers `query`: it carries the transaction ID that was sent and,
/// when `expected_source` is set, it came from that resolver address.
fn dns_reply_matches(
    query: &[u8],
    reply: &[u8],
    expected_source: Option<SocketAddr>,
    actual_source: SocketAddr,
) -> bool {
    if query.len() < DNS_ID_LEN || reply.len() < DNS_ID_LEN {
        return false;
    }
    if reply[..DNS_ID_LEN] != query[..DNS_ID_LEN] {
        return false;
    }
    // Compare canonical IP and port only: a full `SocketAddr` equality would also compare the IPv6
    // flow info and scope id, and would reject an IPv4-mapped source for an IPv4 resolver.
    expected_source.is_none_or(|expected| is_expected_relay_source(actual_source, expected))
}

/// How a direct UDP DNS reply is authenticated against the query that was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DnsReplyCheck {
    /// Unicast resolver: the reply must come from the queried address and carry the sent ID.
    SourceAndId,
    /// Multicast query (LLMNR / mDNS): replies come from any host, only the sent ID is checked.
    IdOnly,
}

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

        let now = Utc::now();
        for rule in &prof.rules {
            if rule.enabled
                && !RuleEngine::is_expired(rule, now)
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

    /// Same as [`Self::resolve_host_direct_ipv4`], but reuses a recent resolution of the same domain
    /// (bounded cache, `fakeIpRealResolutionTtlSecs`) so per-datagram Direct UDP traffic does not
    /// trigger a DNS round trip every time.
    pub(super) async fn resolve_host_direct_ipv4_cached(
        &self,
        domain: &str,
    ) -> RouteWardResult<Ipv4Addr> {
        let key = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let dns_consts = &self.constants.dns;
        let ttl = Duration::from_secs(dns_consts.fake_ip_real_resolution_ttl_secs);
        if let Some(ip) = self.relay_caches.lookup_real_ipv4(&key, ttl) {
            return Ok(ip);
        }
        let ip = self.resolve_host_direct_ipv4(domain).await?;
        self.relay_caches.store_real_ipv4(
            key,
            ip,
            ttl,
            dns_consts.fake_ip_real_resolution_max_entries,
        );
        Ok(ip)
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
        let dns_consts = &self.constants.dns;
        let timeout_dur = Duration::from_millis(
            self.constants.network.tcp_connect_timeout_ms.clamp(
                dns_consts.direct_query_timeout_min_ms,
                dns_consts
                    .direct_query_timeout_max_ms
                    .max(dns_consts.direct_query_timeout_min_ms),
            ),
        );

        if let Ok(udp_resp) = self
            .query_dns_udp_direct_protected(
                raw_query,
                resolver_addr,
                timeout_dur,
                DnsReplyCheck::SourceAndId,
            )
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
        check: DnsReplyCheck,
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

        // Replies from another source or carrying another transaction ID are dropped while the
        // wait continues until the deadline, so an off-path forgery cannot end the exchange.
        let expected_source = (check == DnsReplyCheck::SourceAndId).then_some(resolver_addr);
        let mut buf = vec![0u8; self.constants.dns.udp_response_buffer_bytes];
        let len = recv_accepted_datagram(&sock, &mut buf, timeout_dur, |source, reply| {
            dns_reply_matches(raw_query, reply, expected_source, source)
        })
        .await
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP DNS recv timeout"))?;
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
        let mut drain_buf = [0u8; UDP_DRAIN_BUFFER_BYTES];
        while sock.try_recv_from(&mut drain_buf).is_ok() {}

        tokio::time::timeout(recv_timeout, sock.send_to(payload, target_addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP send timeout"))??;

        // A pooled socket may still receive a late reply of an earlier flow: only datagrams from
        // the target of this exchange are accepted, anything else is drained and ignored.
        // Known limit: a single reply is relayed per datagram sent.
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
        let result = match recv_accepted_datagram(&sock, &mut buf, recv_timeout, |source, _| {
            source == target_addr
        })
        .await
        {
            Some(len) => {
                buf.truncate(len);
                Ok(buf)
            }
            None => Ok(Vec::new()),
        };

        let mut pool = if is_ipv6 {
            self.direct_udp_v6_pool.lock()
        } else {
            self.direct_udp_pool.lock()
        };
        if pool.len() < self.constants.network.direct_udp_socket_pool_size {
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
        if !dns_reply_matches(raw_query, &resp_buf, None, resolver_addr) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TCP DNS response transaction ID mismatch",
            ));
        }
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

    pub(super) async fn lookup_udp_orig_dns_resolver(
        &self,
        peer_addr: SocketAddr,
    ) -> Option<SocketAddr> {
        self.lookup_udp_conntrack_orig_dst(peer_addr, &[self.constants.dns.dns_standard_port])
            .await
    }

    /// Finds the original destination of a redirected UDP flow in `/proc/net/nf_conntrack`.
    /// The table is read on the blocking pool and its parsed form is cached briefly, so new
    /// ephemeral source ports do not each re-read the kernel table.
    pub(super) async fn lookup_udp_conntrack_orig_dst(
        &self,
        peer_addr: SocketAddr,
        candidate_dports: &[u16],
    ) -> Option<SocketAddr> {
        #[cfg(target_os = "linux")]
        {
            let ctrl = self.clone();
            let dports = candidate_dports.to_vec();
            tokio::task::spawn_blocking(move || {
                let net = &ctrl.constants.network;
                ctrl.relay_caches.conntrack_lookup(
                    peer_addr.port(),
                    peer_addr.is_ipv6(),
                    &dports,
                    Duration::from_millis(net.conntrack_cache_ttl_ms),
                    Duration::from_millis(net.conntrack_min_refresh_interval_ms),
                    || std::fs::read_to_string("/proc/net/nf_conntrack").ok(),
                )
            })
            .await
            .ok()
            .flatten()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (peer_addr, candidate_dports);
            None
        }
    }

    pub(super) fn candidate_dns_resolvers(
        &self,
        orig_resolver: Option<SocketAddr>,
        mode: DnsResolverMode,
    ) -> Vec<SocketAddr> {
        let sys_resolvers = if let Some(ref ov) = *self.system_resolvers_override.read() {
            ov.clone()
        } else {
            self.relay_caches.system_resolvers_or_detect(
                Duration::from_millis(self.constants.dns.system_resolvers_cache_ttl_ms),
                || crate::dns::detect_system_dns_resolvers(&self.constants.dns),
            )
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

    /// Stricter gate than [`Self::detect_elevated_privileges`], used at the CLI entry points that
    /// must run as a real administrator or as `LocalSystem`.
    ///
    /// On Windows it reports membership of `BUILTIN\Administrators` through
    /// `CheckTokenMembership` (deny-only groups report FALSE, which is the point), or a process
    /// token whose user is `S-1-5-18`. `TokenElevation` is deliberately not used: a
    /// `runas /trustlevel` restricted token and `NT AUTHORITY\LOCAL SERVICE` both report
    /// `TokenIsElevated` but must not pass this gate.
    pub fn detect_admin_or_system() -> bool {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::BOOL;
            use windows_sys::Win32::Security::{
                CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid,
                SECURITY_MAX_SID_SIZE,
            };

            const SID_LOCAL_SYSTEM: &str = "S-1-5-18";

            let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
            let mut sid_len: u32 = SECURITY_MAX_SID_SIZE;
            // SAFETY: `sid` is a writable buffer of SECURITY_MAX_SID_SIZE bytes and `sid_len`
            // holds its size; a null token handle makes CheckTokenMembership use the
            // impersonation or process token of the calling thread.
            let is_admin = unsafe {
                if CreateWellKnownSid(
                    WinBuiltinAdministratorsSid,
                    std::ptr::null_mut(),
                    sid.as_mut_ptr().cast(),
                    &mut sid_len,
                ) == 0
                {
                    false
                } else {
                    let mut member: BOOL = 0;
                    CheckTokenMembership(std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut member)
                        != 0
                        && member != 0
                }
            };
            if is_admin {
                return true;
            }
            crate::ipc::transport::current_user_sid_string()
                .map(|user| user.eq_ignore_ascii_case(SID_LOCAL_SYSTEM))
                .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProfileConfig, SystemConstants};
    use crate::dns::codec::build_a_response;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    #[test]
    fn detect_admin_or_system_does_not_panic() {
        // The value depends on the runner (CI runners are usually administrators).
        let _ = RouteWardController::detect_admin_or_system();
    }

    fn test_controller() -> RouteWardController {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        RouteWardController::new(constants, profile, "en")
    }

    fn query_for(name: &str, id: u16) -> Vec<u8> {
        build_a_query(id, name).expect("build query")
    }

    fn sa(text: &str) -> SocketAddr {
        text.parse().expect("socket addr")
    }

    #[test]
    fn dns_reply_matches_requires_id_and_optionally_source() {
        let query = query_for("example.test", 0x1234);
        let good = query_for("example.test", 0x1234);
        let bad_id = query_for("example.test", 0x4321);
        let resolver = sa("192.0.2.1:53");
        let other = sa("192.0.2.2:53");
        assert!(dns_reply_matches(&query, &good, Some(resolver), resolver));
        assert!(!dns_reply_matches(&query, &good, Some(resolver), other));
        assert!(!dns_reply_matches(
            &query,
            &bad_id,
            Some(resolver),
            resolver
        ));
        assert!(dns_reply_matches(&query, &good, None, other));
        assert!(!dns_reply_matches(&query, &[0x12], None, other));
    }

    #[test]
    fn dns_reply_matches_ignores_scope_id_and_ipv4_mapping() {
        use std::net::{Ipv6Addr, SocketAddrV6};
        let query = query_for("example.test", 0x1234);
        let reply = query_for("example.test", 0x1234);
        let link_local: Ipv6Addr = "fe80::1".parse().expect("ipv6");
        let expected = SocketAddr::V6(SocketAddrV6::new(link_local, 53, 0, 0));
        let scoped = SocketAddr::V6(SocketAddrV6::new(link_local, 53, 7, 3));
        assert!(dns_reply_matches(&query, &reply, Some(expected), scoped));
        let other = SocketAddr::V6(SocketAddrV6::new(
            "fe80::2".parse().expect("ipv6"),
            53,
            7,
            0,
        ));
        assert!(!dns_reply_matches(&query, &reply, Some(expected), other));

        let v4 = sa("192.0.2.1:53");
        let mapped = sa("[::ffff:192.0.2.1]:53");
        assert!(dns_reply_matches(&query, &reply, Some(v4), mapped));
        assert!(!dns_reply_matches(
            &query,
            &reply,
            Some(v4),
            sa("[::ffff:192.0.2.1]:54")
        ));
    }

    #[tokio::test]
    async fn direct_dns_udp_ignores_forged_source_and_wrong_id_until_valid_reply() {
        let controller = test_controller();
        let resolver = UdpSocket::bind("127.0.0.1:0").await.expect("bind resolver");
        let resolver_addr = resolver.local_addr().expect("resolver addr");
        let attacker = UdpSocket::bind("127.0.0.1:0").await.expect("bind attacker");
        let query = query_for("example.test", 0x2222);

        let task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = resolver.recv_from(&mut buf).await.expect("recv query");
            let parsed = parse_dns_query(&buf[..n]).expect("parse query");
            let forged = build_a_response(&parsed, Ipv4Addr::new(6, 6, 6, 6), 60);
            attacker
                .send_to(&forged, peer)
                .await
                .expect("forged source");
            let mut wrong_id = build_a_response(&parsed, Ipv4Addr::new(7, 7, 7, 7), 60);
            wrong_id[0] ^= 0xFF;
            resolver.send_to(&wrong_id, peer).await.expect("wrong id");
            let good = build_a_response(&parsed, Ipv4Addr::new(1, 2, 3, 4), 60);
            resolver.send_to(&good, peer).await.expect("good reply");
        });

        let reply = controller
            .query_dns_udp_direct_protected(
                &query,
                resolver_addr,
                Duration::from_secs(2),
                DnsReplyCheck::SourceAndId,
            )
            .await
            .expect("valid reply must be accepted");
        task.await.expect("resolver task");
        assert_eq!(
            extract_ipv4_answers(&reply).expect("answers"),
            vec![Ipv4Addr::new(1, 2, 3, 4)]
        );
    }

    #[tokio::test]
    async fn direct_dns_udp_times_out_when_only_forged_replies_arrive() {
        let controller = test_controller();
        let resolver = UdpSocket::bind("127.0.0.1:0").await.expect("bind resolver");
        let resolver_addr = resolver.local_addr().expect("resolver addr");
        let attacker = UdpSocket::bind("127.0.0.1:0").await.expect("bind attacker");
        let query = query_for("example.test", 0x3333);
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = resolver.recv_from(&mut buf).await.expect("recv query");
            let parsed = parse_dns_query(&buf[..n]).expect("parse query");
            let forged = build_a_response(&parsed, Ipv4Addr::new(6, 6, 6, 6), 60);
            attacker
                .send_to(&forged, peer)
                .await
                .expect("forged source");
        });
        let err = controller
            .query_dns_udp_direct_protected(
                &query,
                resolver_addr,
                Duration::from_millis(400),
                DnsReplyCheck::SourceAndId,
            )
            .await
            .expect_err("forged reply must not be accepted");
        task.await.expect("task");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn pooled_direct_udp_socket_only_accepts_reply_from_the_target() {
        let controller = test_controller();
        let target = UdpSocket::bind("127.0.0.1:0").await.expect("bind target");
        let target_addr = target.local_addr().expect("target addr");
        let decoy = UdpSocket::bind("127.0.0.1:0").await.expect("bind decoy");
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, peer) = target.recv_from(&mut buf).await.expect("recv");
            decoy.send_to(b"DECOY", peer).await.expect("decoy");
            target.send_to(b"REAL", peer).await.expect("real");
        });
        let reply = controller
            .send_and_optional_recv_udp_direct_protected(
                b"ping",
                target_addr,
                Duration::from_secs(2),
            )
            .await
            .expect("exchange");
        task.await.expect("task");
        assert_eq!(reply, b"REAL");
    }

    const CONNTRACK_SAMPLE: &str = "\
ipv4     2 udp      17 25 src=10.0.0.5 dst=192.0.2.53 sport=40001 dport=53 [UNREPLIED] src=192.0.2.53 dst=10.0.0.5 sport=53 dport=40001 mark=0 use=2
ipv4     2 tcp      6 100 ESTABLISHED src=10.0.0.5 dst=192.0.2.80 sport=40001 dport=443 src=192.0.2.80 dst=10.0.0.5 sport=443 dport=40001 use=2
ipv4     2 udp      17 25 src=10.0.0.5 dst=127.0.0.53 sport=40002 dport=53 src=127.0.0.53 dst=10.0.0.5 sport=53 dport=40002 use=2
ipv6     10 udp     17 25 src=fd00::5 dst=fd00::53 sport=40003 dport=53 src=fd00::53 dst=fd00::5 sport=53 dport=40003 use=2
";

    #[test]
    fn conntrack_table_parser_keeps_original_tuple_of_udp_flows() {
        let table = parse_conntrack_udp_table(CONNTRACK_SAMPLE);
        assert_eq!(table.len(), 3);
        assert_eq!(table[&40001], vec![(sa("192.0.2.53:0").ip(), 53)]);
        assert!(!table.contains_key(&443));
    }

    #[test]
    fn conntrack_cache_serves_burst_without_rereading_and_refreshes_after_min_interval() {
        let caches = RelayCaches::new();
        let reads = AtomicUsize::new(0);
        let ttl = Duration::from_secs(60);
        let min_refresh = Duration::from_secs(30);

        let hit = caches.conntrack_lookup(40001, false, &[53], ttl, min_refresh, || {
            reads.fetch_add(1, Ordering::SeqCst);
            Some(CONNTRACK_SAMPLE.to_string())
        });
        assert_eq!(hit, Some(sa("192.0.2.53:53")));
        // A cache hit never reads the table again.
        let hit = caches.conntrack_lookup(40001, false, &[53], ttl, min_refresh, || {
            panic!("must not re-read on hit")
        });
        assert_eq!(hit, Some(sa("192.0.2.53:53")));
        // A miss on a fresh snapshot (younger than the minimum interval) does not re-read either.
        let miss = caches.conntrack_lookup(49999, false, &[53], ttl, min_refresh, || {
            panic!("must not re-read on fresh miss")
        });
        assert_eq!(miss, None);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        // Loopback destinations are skipped, IPv6 flows are matched by family.
        assert_eq!(
            caches.conntrack_lookup(40002, false, &[53], ttl, min_refresh, || None),
            None
        );
        assert_eq!(
            caches.conntrack_lookup(40003, true, &[53], ttl, min_refresh, || None),
            Some(sa("[fd00::53]:53"))
        );
        // With a zero minimum interval a miss refreshes the snapshot.
        let refreshed = caches.conntrack_lookup(40001, false, &[5353], ttl, Duration::ZERO, || {
            Some(CONNTRACK_SAMPLE.replace("dport=53 [UNREPLIED]", "dport=5353 [UNREPLIED]"))
        });
        assert_eq!(refreshed, Some(sa("192.0.2.53:5353")));
    }

    #[test]
    fn real_ipv4_cache_expires_and_stays_bounded() {
        let caches = RelayCaches::new();
        let ttl = Duration::from_secs(60);
        caches.store_real_ipv4("a.test".into(), Ipv4Addr::new(1, 1, 1, 1), ttl, 2);
        caches.store_real_ipv4("b.test".into(), Ipv4Addr::new(2, 2, 2, 2), ttl, 2);
        caches.store_real_ipv4("c.test".into(), Ipv4Addr::new(3, 3, 3, 3), ttl, 2);
        assert!(caches.real_ipv4.lock().len() <= 2);
        assert_eq!(
            caches.lookup_real_ipv4("c.test", ttl),
            Some(Ipv4Addr::new(3, 3, 3, 3))
        );
        assert_eq!(caches.lookup_real_ipv4("c.test", Duration::ZERO), None);
    }

    #[test]
    fn system_resolver_list_is_detected_once_per_ttl() {
        let caches = RelayCaches::new();
        let calls = AtomicUsize::new(0);
        let ttl = Duration::from_secs(60);
        let first = caches.system_resolvers_or_detect(ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            vec![sa("192.0.2.1:53")]
        });
        assert_eq!(first.len(), 1);
        let second = caches.system_resolvers_or_detect(ttl, || panic!("cached"));
        assert_eq!(second.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn direct_resolution_of_a_domain_is_cached_between_datagrams() {
        let controller = test_controller();
        let dns = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind dns"));
        let dns_addr = dns.local_addr().expect("dns addr");
        let queries = Arc::new(AtomicUsize::new(0));
        let queries_bg = Arc::clone(&queries);
        let dns_bg = Arc::clone(&dns);
        let _task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = dns_bg.recv_from(&mut buf).await {
                if let Ok(q) = parse_dns_query(&buf[..n]) {
                    queries_bg.fetch_add(1, Ordering::SeqCst);
                    let resp = build_a_response(&q, Ipv4Addr::new(93, 184, 216, 34), 60);
                    let _ = dns_bg.send_to(&resp, peer).await;
                }
            }
        });
        *controller.system_resolvers_override.write() = Some(vec![dns_addr]);
        for _ in 0..3 {
            let ip = controller
                .resolve_host_direct_ipv4_cached("Cached.Example.Test")
                .await
                .expect("resolve");
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        }
        assert_eq!(queries.load(Ordering::SeqCst), 1);
    }
}
