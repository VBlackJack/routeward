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

pub mod codec;

use crate::config::{DnsConfig, DnsConstants};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const DEFAULT_FALLBACK_NET: [u8; 4] = [198, 18, 0, 0];
const DEFAULT_FALLBACK_PREFIX: u8 = 15;
const HOST_OFFSET_START: u32 = 1;
const WILDCARD_PREFIX: &str = "*.";
const ENV_EXTRA_DNS_SUFFIXES: &str = "ROUTEWARD_SYSTEM_DNS_SUFFIXES";
const ENV_SYSTEM_DNS_RESOLVERS: &str = "ROUTEWARD_SYSTEM_DNS_RESOLVERS";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FakeIpEntry {
    pub fake_ip: String,
    pub domain: String,
    pub hits: u64,
    pub expires_at: DateTime<Utc>,
    pub ttl_remaining_seconds: i64,
}

/// Classification result for an outbound LLMNR (`UDP 5355`) or mDNS (`UDP 5353`) datagram payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalNameQueryDecision {
    /// Local name (single-label without dot, `.local`, AD suffix / `bypassDomains`, private reverse zone): allow in `Direct`.
    AllowLocal { qname: String },
    /// Public FQDN on a link-local name resolution protocol: block and log a rate-limited `WARN`.
    BlockPublicFqdn { qname: String },
    /// Malformed DNS/LLMNR/mDNS wire payload: drop without panic.
    BlockMalformed,
}

#[derive(Debug, Clone)]
struct InternalRecord {
    fake_ip: Ipv4Addr,
    domain: String,
    hits: u64,
    expires_at: DateTime<Utc>,
    seq: u64,
}

#[derive(Clone)]
pub struct FakeIpEngine {
    subnet: Ipv4Net,
    ttl_seconds: i64,
    os_response_ttl_seconds: u32,
    max_entries: usize,
    bypass_domains: Arc<RwLock<Vec<String>>>,
    auto_bypass_suffixes: Arc<Vec<String>>,
    private_reverse_zones: Arc<Vec<String>>,
    doh_canary_domains: Arc<Vec<String>>,
    cursor: Arc<Mutex<u32>>,
    access_seq: Arc<AtomicU64>,
    domain_to_record: Arc<DashMap<String, InternalRecord>>,
    ip_to_domain: Arc<DashMap<Ipv4Addr, String>>,
}

impl FakeIpEngine {
    pub fn new(dns_config: &DnsConfig, constants: &DnsConstants) -> Self {
        let subnet = Ipv4Net::from_str(&dns_config.fake_ip_cidr)
            .or_else(|_| Ipv4Net::from_str(&constants.fake_ip_cidr))
            .unwrap_or_else(|_| {
                Ipv4Net::new(
                    Ipv4Addr::from(DEFAULT_FALLBACK_NET),
                    DEFAULT_FALLBACK_PREFIX,
                )
                .expect("Valid RFC 2544 subnet")
            });

        let mut auto_suffixes = Vec::new();
        for suffix in &constants.default_bypass_suffixes {
            push_unique_normalized_suffix(&mut auto_suffixes, suffix);
        }
        for detected in detect_system_dns_suffixes() {
            push_unique_normalized_suffix(&mut auto_suffixes, &detected);
        }

        let mut reverse_zones = Vec::new();
        for zone in &constants.default_private_reverse_zones {
            push_unique_normalized_suffix(&mut reverse_zones, zone);
        }

        let mut canary_domains = Vec::new();
        for canary in &constants.doh_canary_domains {
            push_unique_normalized_suffix(&mut canary_domains, canary);
        }

        Self {
            subnet,
            ttl_seconds: constants.default_ttl_seconds as i64,
            os_response_ttl_seconds: constants.os_response_ttl_seconds,
            max_entries: constants.max_cache_entries,
            bypass_domains: Arc::new(RwLock::new(dns_config.bypass_domains.clone())),
            auto_bypass_suffixes: Arc::new(auto_suffixes),
            private_reverse_zones: Arc::new(reverse_zones),
            doh_canary_domains: Arc::new(canary_domains),
            cursor: Arc::new(Mutex::new(HOST_OFFSET_START)),
            access_seq: Arc::new(AtomicU64::new(1)),
            domain_to_record: Arc::new(DashMap::new()),
            ip_to_domain: Arc::new(DashMap::new()),
        }
    }

    /// Creates a `FakeIpEngine` with a custom `max_entries` limit (useful for testing pool saturation).
    pub fn with_max_entries(&self, max_entries: usize) -> Self {
        let mut cloned = self.clone();
        cloned.max_entries = max_entries;
        cloned
    }

    /// Updates the configurable bypass domain list from a refreshed `DnsConfig`.
    pub fn update_bypass_domains(&self, bypass_domains: Vec<String>) {
        *self.bypass_domains.write() = bypass_domains;
    }

    /// Returns the short TTL (in seconds, default 5 s) sent in DNS responses to the OS stub resolver.
    pub fn os_response_ttl_seconds(&self) -> u32 {
        self.os_response_ttl_seconds
    }

    /// Returns the internal Fake-IP mapping retention TTL (in seconds, default 300 s).
    pub fn internal_ttl_seconds(&self) -> i64 {
        self.ttl_seconds
    }

    /// Returns the list of automatically detected system/AD DNS suffixes and default local suffixes.
    pub fn auto_bypass_suffixes(&self) -> &[String] {
        &self.auto_bypass_suffixes
    }

    /// Returns `true` if `domain` matches a DoH canary domain (such as `use-application-dns.net`).
    pub fn is_doh_canary(&self, domain: &str) -> bool {
        let normalized = normalize_domain_name(domain);
        if normalized.is_empty() {
            return false;
        }
        self.doh_canary_domains
            .iter()
            .any(|canary| domain_matches_suffix(&normalized, canary))
    }

    /// Returns `true` if `domain` must bypass Fake-IP and proxy DNS resolution and be resolved directly:
    /// - single-label hostnames (no dot)
    /// - `.local`, `.localhost`, `.home.arpa`
    /// - automatically detected machine primary DNS suffix and DNS search list (Active Directory domain)
    /// - private IPv4 and IPv6 reverse zones (`10.in-addr.arpa`, `168.192.in-addr.arpa`, `16..31.172.in-addr.arpa`, ULA/link-local `ip6.arpa`)
    /// - user-configured `dnsConfig.bypassDomains`
    pub fn is_bypassed(&self, domain: &str) -> bool {
        let normalized = normalize_domain_name(domain);
        if normalized.is_empty() {
            return true;
        }

        // 1. Single-label names (no dot), e.g. "dc01", "fileserver", "localhost", "wpad"
        if !normalized.contains('.') {
            return true;
        }

        // 2. Built-in suffixes (.local, .localhost, .home.arpa) and auto-detected AD / machine DNS suffixes
        for suffix in self.auto_bypass_suffixes.iter() {
            if domain_matches_suffix(&normalized, suffix) {
                return true;
            }
        }

        // 3. Private reverse lookup zones (RFC 1918, loopback, link-local, IPv6 ULA & link-local)
        for zone in self.private_reverse_zones.iter() {
            if domain_matches_suffix(&normalized, zone) {
                return true;
            }
        }

        // 4. Configurable dnsConfig.bypassDomains
        let configured = self.bypass_domains.read();
        for pattern in configured.iter() {
            let pat = normalize_domain_name(pattern);
            if pat.is_empty() {
                continue;
            }
            if pat == normalized {
                return true;
            }
            if let Some(suffix) = pat.strip_prefix(WILDCARD_PREFIX) {
                if domain_matches_suffix(&normalized, suffix) {
                    return true;
                }
            } else if domain_matches_suffix(&normalized, &pat) {
                return true;
            }
        }

        false
    }

    /// Classifies an outbound LLMNR (`UDP 5355`) or mDNS (`UDP 5353`) wire payload.
    ///
    /// - Local names (single-label without dot, `.local`, AD suffixes, `bypassDomains`, private reverse zones)
    ///   return [`LocalNameQueryDecision::AllowLocal`].
    /// - Any public FQDN returns [`LocalNameQueryDecision::BlockPublicFqdn`].
    /// - Unparseable payloads return [`LocalNameQueryDecision::BlockMalformed`].
    pub fn classify_local_name_query(&self, payload: &[u8]) -> LocalNameQueryDecision {
        if let Ok(query) = codec::parse_dns_query(payload) {
            let qname = normalize_domain_name(&query.question.qname);
            if qname.is_empty() {
                return LocalNameQueryDecision::BlockMalformed;
            }
            if self.is_bypassed(&qname) && !self.is_doh_canary(&qname) {
                return LocalNameQueryDecision::AllowLocal { qname };
            } else {
                return LocalNameQueryDecision::BlockPublicFqdn { qname };
            }
        }

        if let Ok(msg) = codec::parse_dns_message(payload) {
            let mut first_local: Option<String> = None;
            for q in &msg.questions {
                let name = normalize_domain_name(&q.qname);
                if name.is_empty() {
                    continue;
                }
                if !self.is_bypassed(&name) || self.is_doh_canary(&name) {
                    return LocalNameQueryDecision::BlockPublicFqdn { qname: name };
                }
                if first_local.is_none() {
                    first_local = Some(name);
                }
            }
            for rr in msg
                .answers
                .iter()
                .chain(msg.authorities.iter())
                .chain(msg.additionals.iter())
            {
                let name = normalize_domain_name(&rr.name);
                if name.is_empty() {
                    continue;
                }
                if !self.is_bypassed(&name) || self.is_doh_canary(&name) {
                    return LocalNameQueryDecision::BlockPublicFqdn { qname: name };
                }
                if first_local.is_none() {
                    first_local = Some(name);
                }
            }
            if let Some(qname) = first_local {
                return LocalNameQueryDecision::AllowLocal { qname };
            }
        }

        LocalNameQueryDecision::BlockMalformed
    }

    pub fn allocate_or_get(&self, domain: &str) -> Option<Ipv4Addr> {
        let normalized = normalize_domain_name(domain);
        if normalized.is_empty() || self.is_bypassed(&normalized) || self.is_doh_canary(&normalized)
        {
            return None;
        }

        let capacity = self.effective_capacity();
        if capacity == 0 {
            return None;
        }

        let now = Utc::now();
        let next_expiry = now + chrono::Duration::seconds(self.ttl_seconds);
        let seq = self.access_seq.fetch_add(1, Ordering::Relaxed);

        if let Some(mut existing) = self.domain_to_record.get_mut(&normalized) {
            existing.hits += 1;
            existing.expires_at = next_expiry;
            existing.seq = seq;
            return Some(existing.fake_ip);
        }

        let mut evicted_ip = None;
        if self.domain_to_record.len() >= capacity {
            self.evict_expired();
            while self.domain_to_record.len() >= capacity {
                match self.evict_oldest() {
                    Some(ip) => {
                        if evicted_ip.is_none() {
                            evicted_ip = Some(ip);
                        }
                    }
                    None => break,
                }
            }
        }

        if self.domain_to_record.len() >= capacity {
            return None;
        }

        let candidate_ip = self.next_ip_in_subnet();
        let allocated_ip = if self.ip_to_domain.contains_key(&candidate_ip) {
            evicted_ip.unwrap_or(candidate_ip)
        } else {
            candidate_ip
        };
        if let Some(prev_domain) = self.ip_to_domain.insert(allocated_ip, normalized.clone()) {
            if prev_domain != normalized {
                self.domain_to_record.remove(&prev_domain);
            }
        }
        let record = InternalRecord {
            fake_ip: allocated_ip,
            domain: normalized.clone(),
            hits: 1,
            expires_at: next_expiry,
            seq,
        };

        self.domain_to_record.insert(normalized, record);
        Some(allocated_ip)
    }

    fn effective_capacity(&self) -> usize {
        let base = u32::from(self.subnet.network());
        let broadcast = u32::from(self.subnet.broadcast());
        let usable_hosts = broadcast.saturating_sub(base + 1).max(1) as usize;
        self.max_entries.min(usable_hosts)
    }

    /// Evicts the least-recently accessed / oldest entry from the Fake-IP pool.
    pub fn evict_oldest(&self) -> Option<Ipv4Addr> {
        let oldest = self
            .domain_to_record
            .iter()
            .min_by_key(|item| (item.value().seq, item.value().expires_at))
            .map(|item| (item.key().clone(), item.value().fake_ip));

        if let Some((domain, ip)) = oldest {
            self.domain_to_record.remove(&domain);
            self.ip_to_domain.remove(&ip);
            Some(ip)
        } else {
            None
        }
    }

    pub fn is_in_fake_subnet(&self, ip: &Ipv4Addr) -> bool {
        self.subnet.contains(ip)
    }

    pub fn resolve_fake_ip(&self, ip: &Ipv4Addr) -> Option<String> {
        if !self.subnet.contains(ip) {
            return None;
        }
        let domain = self.ip_to_domain.get(ip)?.value().clone();
        let now = Utc::now();
        if let Some(mut rec) = self.domain_to_record.get_mut(&domain) {
            if rec.expires_at <= now {
                drop(rec);
                self.domain_to_record.remove(&domain);
                self.ip_to_domain.remove(ip);
                return None;
            }
            rec.hits += 1;
            rec.seq = self.access_seq.fetch_add(1, Ordering::Relaxed);
            return Some(domain);
        }
        self.ip_to_domain.remove(ip);
        None
    }

    pub fn resolve_host_string(&self, host_or_ip: &str) -> Option<String> {
        let parsed = Ipv4Addr::from_str(host_or_ip).ok()?;
        self.resolve_fake_ip(&parsed)
    }

    pub fn list_entries(&self) -> Vec<FakeIpEntry> {
        let now = Utc::now();
        let mut entries: Vec<FakeIpEntry> = self
            .domain_to_record
            .iter()
            .map(|item| {
                let rec = item.value();
                let remaining = (rec.expires_at - now).num_seconds().max(0);
                FakeIpEntry {
                    fake_ip: rec.fake_ip.to_string(),
                    domain: rec.domain.clone(),
                    hits: rec.hits,
                    expires_at: rec.expires_at,
                    ttl_remaining_seconds: remaining,
                }
            })
            .collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.hits));
        entries
    }

    pub fn count(&self) -> usize {
        self.domain_to_record.len()
    }

    pub fn flush(&self) {
        self.domain_to_record.clear();
        self.ip_to_domain.clear();
        let mut cursor = self.cursor.lock();
        *cursor = HOST_OFFSET_START;
    }

    pub fn evict_expired(&self) {
        let now = Utc::now();
        let expired_domains: Vec<(String, Ipv4Addr)> = self
            .domain_to_record
            .iter()
            .filter(|item| item.value().expires_at <= now)
            .map(|item| (item.key().clone(), item.value().fake_ip))
            .collect();

        for (domain, ip) in expired_domains {
            self.domain_to_record.remove(&domain);
            self.ip_to_domain.remove(&ip);
        }
    }

    fn next_ip_in_subnet(&self) -> Ipv4Addr {
        let base = u32::from(self.subnet.network());
        let broadcast = u32::from(self.subnet.broadcast());
        let usable_hosts = broadcast.saturating_sub(base + 1).max(1);

        let mut cursor = self.cursor.lock();
        let current_offset = *cursor;
        *cursor = if current_offset >= usable_hosts {
            HOST_OFFSET_START
        } else {
            current_offset + 1
        };

        Ipv4Addr::from(base + current_offset)
    }
}

fn normalize_domain_name(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn domain_matches_suffix(normalized_domain: &str, normalized_suffix: &str) -> bool {
    if normalized_suffix.is_empty() {
        return false;
    }
    if normalized_domain == normalized_suffix {
        return true;
    }
    if let Some(prefix) = normalized_domain.strip_suffix(normalized_suffix) {
        return prefix.ends_with('.');
    }
    false
}

fn push_unique_normalized_suffix(out: &mut Vec<String>, candidate: &str) {
    let norm = normalize_domain_name(candidate);
    if !norm.is_empty() && !out.contains(&norm) {
        out.push(norm);
    }
}

/// Detects the machine's primary DNS suffix and DNS search list (Active Directory domain on Windows,
/// `/etc/resolv.conf` `domain` and `search` directives on Linux, plus `USERDNSDOMAIN`).
pub fn detect_system_dns_suffixes() -> Vec<String> {
    let mut suffixes = Vec::new();

    if let Ok(extra) = std::env::var(ENV_EXTRA_DNS_SUFFIXES) {
        for part in extra.split([',', ';', ' ', '\t']) {
            push_unique_normalized_suffix(&mut suffixes, part);
        }
    }

    if let Ok(user_dns_domain) = std::env::var("USERDNSDOMAIN") {
        push_unique_normalized_suffix(&mut suffixes, &user_dns_domain);
    }

    #[cfg(windows)]
    {
        for reg_key in [
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        ] {
            if let Ok(output) = std::process::Command::new("reg")
                .args(["query", reg_key])
                .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for parsed in parse_windows_reg_dns_output(&stdout) {
                        push_unique_normalized_suffix(&mut suffixes, &parsed);
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        for path in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
            if let Ok(content) = std::fs::read_to_string(path) {
                for parsed in parse_resolv_conf_suffixes(&content) {
                    push_unique_normalized_suffix(&mut suffixes, &parsed);
                }
            }
        }
    }

    suffixes
}

/// Parses `reg query` output from Windows `Tcpip\Parameters` or `DNSClient` policy keys,
/// extracting `Domain`, `NV Domain`, `DhcpDomain`, `PrimaryDnsSuffix`, and `SearchList`.
pub fn parse_windows_reg_dns_output(stdout: &str) -> Vec<String> {
    let mut suffixes = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        let Some((left, right)) = trimmed.split_once("REG_SZ") else {
            continue;
        };
        let value_name = left.trim().to_ascii_lowercase();
        if matches!(
            value_name.as_str(),
            "domain" | "nv domain" | "dhcpdomain" | "primarydnssuffix" | "searchlist"
        ) {
            for item in right.trim().split([',', ';', ' ']) {
                push_unique_normalized_suffix(&mut suffixes, item);
            }
        }
    }
    suffixes
}

/// Parses `domain` and `search` directives from a POSIX `/etc/resolv.conf` file.
pub fn parse_resolv_conf_suffixes(content: &str) -> Vec<String> {
    let mut suffixes = Vec::new();
    for line in content.lines() {
        let line_no_comment = line.split(['#', ';']).next().unwrap_or("").trim();
        if line_no_comment.is_empty() {
            continue;
        }
        let mut tokens = line_no_comment.split_whitespace();
        let Some(directive) = tokens.next() else {
            continue;
        };
        if directive.eq_ignore_ascii_case("domain") || directive.eq_ignore_ascii_case("search") {
            for tok in tokens {
                push_unique_normalized_suffix(&mut suffixes, tok);
            }
        }
    }
    suffixes
}

/// Extracts non-loopback IPv4 and IPv6 nameservers from a `resolv.conf` file content.
pub fn parse_resolv_conf_nameservers(content: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for line in content.lines() {
        let line_no_comment = line.split(['#', ';']).next().unwrap_or("").trim();
        let mut tokens = line_no_comment.split_whitespace();
        if let (Some(dir), Some(addr_str)) = (tokens.next(), tokens.next()) {
            if dir.eq_ignore_ascii_case("nameserver") {
                if let Ok(ip) = addr_str.parse::<IpAddr>() {
                    let usable = match ip {
                        IpAddr::V4(v4) => {
                            !v4.is_loopback() && !v4.is_unspecified() && !v4.is_multicast()
                        }
                        IpAddr::V6(v6) => {
                            !v6.is_loopback()
                                && !v6.is_unspecified()
                                && !v6.is_multicast()
                                && !v6.is_unicast_link_local()
                        }
                    };
                    if usable && !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        }
    }
    servers
}

/// Resolves Linux non-loopback nameservers from `/etc/resolv.conf`, falling back to
/// `/run/systemd/resolve/resolv.conf` when `/etc/resolv.conf` only contains the `127.0.0.53` stub.
pub fn resolve_linux_resolv_conf_nameservers(
    etc_resolv: Option<&str>,
    systemd_resolv: Option<&str>,
) -> Vec<IpAddr> {
    if let Some(etc_content) = etc_resolv {
        let primary = parse_resolv_conf_nameservers(etc_content);
        if !primary.is_empty() {
            return primary;
        }
    }
    if let Some(systemd_content) = systemd_resolv {
        return parse_resolv_conf_nameservers(systemd_content);
    }
    Vec::new()
}

/// Detects the active system IPv4/IPv6 DNS resolvers:
/// - On Windows: queries active network adapters via `GetAdaptersAddresses` (`Win32_NetworkManagement_IpHelper`).
/// - On Linux: reads `/etc/resolv.conf` and falls back to `/run/systemd/resolve/resolv.conf` if `/etc/resolv.conf` only contains `127.0.0.53`.
pub fn detect_system_dns_resolvers(constants: &DnsConstants) -> Vec<SocketAddr> {
    let dns_port = constants.dns_standard_port;
    let mut out = Vec::new();

    if let Ok(override_raw) = std::env::var(ENV_SYSTEM_DNS_RESOLVERS) {
        let trimmed = override_raw.trim();
        if trimmed.eq_ignore_ascii_case("none") {
            return out;
        }
        for token in trimmed.split([',', ';', ' ']) {
            let tok = token.trim();
            if tok.is_empty() {
                continue;
            }
            if let Ok(sa) = tok.parse::<SocketAddr>() {
                if !sa.ip().is_loopback() && !sa.ip().is_unspecified() && !out.contains(&sa) {
                    out.push(sa);
                }
            } else if let Ok(ip) = tok.parse::<IpAddr>() {
                if !ip.is_loopback() && !ip.is_unspecified() {
                    let sa = SocketAddr::new(ip, dns_port);
                    if !out.contains(&sa) {
                        out.push(sa);
                    }
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
    }

    #[cfg(windows)]
    {
        for ip in query_windows_adapter_dns_servers() {
            let sa = SocketAddr::new(ip, dns_port);
            if !out.contains(&sa) {
                out.push(sa);
            }
        }
    }

    #[cfg(not(windows))]
    {
        let etc_content = std::fs::read_to_string(&constants.linux_resolv_conf_path).ok();
        let systemd_content =
            std::fs::read_to_string(&constants.linux_systemd_resolv_conf_path).ok();
        for ip in resolve_linux_resolv_conf_nameservers(
            etc_content.as_deref(),
            systemd_content.as_deref(),
        ) {
            let sa = SocketAddr::new(ip, dns_port);
            if !out.contains(&sa) {
                out.push(sa);
            }
        }
    }

    out
}

#[cfg(windows)]
fn query_windows_adapter_dns_servers() -> Vec<IpAddr> {
    use std::net::Ipv6Addr;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    const IF_OPER_STATUS_UP: i32 = 1;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const INITIAL_BUF_LEN: u32 = 16384;
    const MAX_TRIES: usize = 3;

    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME;

    let mut buf_len: u32 = INITIAL_BUF_LEN;
    let mut buffer: Vec<u8> = vec![0u8; buf_len as usize];

    for _ in 0..MAX_TRIES {
        buffer.resize(buf_len as usize, 0);
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
        if ret == NO_ERROR {
            break;
        }
        if ret != ERROR_BUFFER_OVERFLOW {
            return Vec::new();
        }
    }

    let mut servers = Vec::new();
    let mut adapter_ptr = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    unsafe {
        while !adapter_ptr.is_null() {
            let adapter = &*adapter_ptr;
            if adapter.OperStatus == IF_OPER_STATUS_UP
                && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK
            {
                let mut dns_ptr = adapter.FirstDnsServerAddress;
                while !dns_ptr.is_null() {
                    let dns_entry = &*dns_ptr;
                    let sa_ptr = dns_entry.Address.lpSockaddr;
                    let sa_len = dns_entry.Address.iSockaddrLength as usize;
                    if !sa_ptr.is_null()
                        && sa_len >= std::mem::size_of::<SOCKADDR_IN>()
                        && (*sa_ptr).sa_family == AF_INET
                    {
                        let sin = &*(sa_ptr as *const SOCKADDR_IN);
                        let raw_ip = u32::from_be(sin.sin_addr.S_un.S_addr);
                        let ip = Ipv4Addr::from(raw_ip);
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            let addr = IpAddr::V4(ip);
                            if !servers.contains(&addr) {
                                servers.push(addr);
                            }
                        }
                    } else if !sa_ptr.is_null()
                        && sa_len >= std::mem::size_of::<SOCKADDR_IN6>()
                        && (*sa_ptr).sa_family == AF_INET6
                    {
                        let sin6 = &*(sa_ptr as *const SOCKADDR_IN6);
                        let ip = Ipv6Addr::from(sin6.sin6_addr.u.Byte);
                        let is_deprecated_site_local = (ip.segments()[0] & 0xffc0) == 0xfec0;
                        if !ip.is_loopback()
                            && !ip.is_unspecified()
                            && !ip.is_multicast()
                            && !ip.is_unicast_link_local()
                            && !is_deprecated_site_local
                        {
                            let addr = IpAddr::V6(ip);
                            if !servers.contains(&addr) {
                                servers.push(addr);
                            }
                        }
                    }
                    dns_ptr = dns_entry.Next;
                }
            }
            adapter_ptr = adapter.Next;
        }
    }

    servers
}

/// Flushes the OS client DNS resolver cache (without touching the Windows DNS Server role):
/// - Windows: invokes `dnsapi.dll!DnsFlushResolverCache`, falling back to `ipconfig /flushdns`.
/// - Linux: invokes `resolvectl flush-caches` if `systemd-resolved` is active.
pub fn flush_os_dns_cache() -> Result<&'static str, String> {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        type FnDnsFlushResolverCache = unsafe extern "system" fn() -> i32;

        let dll_wide: Vec<u16> = OsStr::new("dnsapi.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let flushed_via_api = unsafe {
            let module = LoadLibraryW(dll_wide.as_ptr());
            if !module.is_null() {
                let proc = GetProcAddress(module, c"DnsFlushResolverCache".as_ptr() as *const u8);
                let ok = if let Some(func_ptr) = proc {
                    let flush_fn = std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        FnDnsFlushResolverCache,
                    >(func_ptr);
                    flush_fn() != 0
                } else {
                    false
                };
                let _ = FreeLibrary(module);
                ok
            } else {
                false
            }
        };

        if flushed_via_api {
            return Ok("dnsapi.dll!DnsFlushResolverCache");
        }

        match std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            Ok(out) if out.status.success() => Ok("ipconfig /flushdns"),
            Ok(out) => Err(format!(
                "ipconfig /flushdns exited with {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(err) => Err(format!("ipconfig /flushdns failed: {err}")),
        }
    }

    #[cfg(not(windows))]
    {
        match std::process::Command::new("resolvectl")
            .arg("flush-caches")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            Ok(out) if out.status.success() => Ok("resolvectl flush-caches"),
            Ok(out) => Err(format!(
                "resolvectl flush-caches exited with {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(err) => Err(format!("resolvectl unavailable: {err}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProfileConfig, SystemConstants};

    #[test]
    fn allocates_and_reverse_resolves_fake_ip_with_5s_os_ttl_and_300s_internal_ttl() {
        let constants = SystemConstants::load_embedded().unwrap();
        let profile = ProfileConfig::load_embedded_default().unwrap();
        let engine = FakeIpEngine::new(&profile.dns_config, &constants.dns);

        assert_eq!(engine.os_response_ttl_seconds(), 5);
        assert_eq!(engine.internal_ttl_seconds(), 300);

        let ip = engine
            .allocate_or_get("api.github.com")
            .expect("Allocated IP");
        assert!(ip.to_string().starts_with("198.18."));

        let resolved = engine.resolve_fake_ip(&ip).expect("Reverse resolved");
        assert_eq!(resolved, "api.github.com");

        // Internal table entry TTL is ~300s (well above the 5s OS response TTL)
        let entries = engine.list_entries();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].ttl_remaining_seconds > 200);
    }

    #[test]
    fn bypasses_single_label_local_private_reverse_zones_and_ad_suffixes() {
        let constants = SystemConstants::load_embedded().unwrap();
        let mut profile = ProfileConfig::load_embedded_default().unwrap();
        profile
            .dns_config
            .bypass_domains
            .push("*.corp.contoso.com".to_string());
        let engine = FakeIpEngine::new(&profile.dns_config, &constants.dns);

        // Single-label names (no dot)
        assert!(engine.is_bypassed("dc01"));
        assert!(engine.is_bypassed("localhost"));
        assert!(engine.is_bypassed("wpad"));
        assert!(engine.allocate_or_get("dc01").is_none());

        // .local and .localhost
        assert!(engine.is_bypassed("printer.local"));
        assert!(engine.is_bypassed("app.localhost"));

        // Active Directory / corporate suffix including SRV records (_ldap._tcp.dc._msdcs.<domain>)
        assert!(engine.is_bypassed("corp.contoso.com"));
        assert!(engine.is_bypassed("dc01.corp.contoso.com"));
        assert!(engine.is_bypassed("_ldap._tcp.dc._msdcs.corp.contoso.com"));

        // Private reverse DNS zones (RFC 1918 10/8, 192.168/16, 172.16..31/12, IPv6 ULA & link-local)
        assert!(engine.is_bypassed("1.0.0.10.in-addr.arpa"));
        assert!(engine.is_bypassed("50.1.168.192.in-addr.arpa"));
        assert!(engine.is_bypassed("4.0.16.172.in-addr.arpa"));
        assert!(engine.is_bypassed("9.255.31.172.in-addr.arpa"));
        assert!(engine.is_bypassed("1.0.0.0.c.f.ip6.arpa"));
        assert!(engine.is_bypassed("1.0.0.0.8.e.f.ip6.arpa"));

        // Non-private 172.32.x.x reverse zone and public domains are NOT bypassed
        assert!(!engine.is_bypassed("1.0.32.172.in-addr.arpa"));
        assert!(!engine.is_bypassed("example.com"));

        // DoH canary detection
        assert!(engine.is_doh_canary("use-application-dns.net"));
        assert!(engine.is_doh_canary("USE-APPLICATION-DNS.NET."));
        assert!(engine.allocate_or_get("use-application-dns.net").is_none());
    }

    #[test]
    fn parses_windows_registry_and_linux_resolv_conf_dns_suffixes() {
        let reg_sample = r#"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    NV Domain    REG_SZ    ad.routeward.internal
    Domain    REG_SZ    ad.routeward.internal
    SearchList    REG_SZ    ad.routeward.internal,eng.routeward.internal
"#;
        let win_suffixes = parse_windows_reg_dns_output(reg_sample);
        assert_eq!(
            win_suffixes,
            vec![
                "ad.routeward.internal".to_string(),
                "eng.routeward.internal".to_string()
            ]
        );

        let resolv_sample = r#"
# Dynamic resolv.conf
domain corp.example.internal
search corp.example.internal lab.example.internal
nameserver 127.0.0.53
nameserver 10.200.1.1
"#;
        let linux_suffixes = parse_resolv_conf_suffixes(resolv_sample);
        assert_eq!(
            linux_suffixes,
            vec![
                "corp.example.internal".to_string(),
                "lab.example.internal".to_string()
            ]
        );
        let nameservers = parse_resolv_conf_nameservers(resolv_sample);
        assert_eq!(nameservers, vec![IpAddr::V4(Ipv4Addr::new(10, 200, 1, 1))]);
    }

    #[test]
    fn linux_resolv_conf_falls_back_to_systemd_resolved_when_only_stub_present() {
        let stub_only_etc = "nameserver 127.0.0.53\nnameserver ::1\noptions edns0 trust-ad\n";
        let systemd_real =
            "nameserver 10.42.0.10\nnameserver 2001:4860:4860::8888\nnameserver fe80::1\n";

        let resolved =
            resolve_linux_resolv_conf_nameservers(Some(stub_only_etc), Some(systemd_real));
        assert_eq!(
            resolved,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 42, 0, 10)),
                IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
            ]
        );

        let direct_etc = "nameserver 192.168.50.1\n";
        let resolved_direct =
            resolve_linux_resolv_conf_nameservers(Some(direct_etc), Some(systemd_real));
        assert_eq!(
            resolved_direct,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1))]
        );
    }

    #[test]
    fn full_fake_ip_pool_evicts_oldest_entry_and_returns_none_when_capacity_zero() {
        let mut constants = SystemConstants::load_embedded().unwrap();
        constants.dns.max_cache_entries = 2;
        let profile = ProfileConfig::load_embedded_default().unwrap();
        let engine = FakeIpEngine::new(&profile.dns_config, &constants.dns);

        let ip1 = engine
            .allocate_or_get("first.routeward.test")
            .expect("allocate first");
        let ip2 = engine
            .allocate_or_get("second.routeward.test")
            .expect("allocate second");
        assert_ne!(ip1, ip2);

        // Touch first.routeward.test so second.routeward.test becomes the oldest accessed entry
        let _ = engine.resolve_fake_ip(&ip1);

        let ip3 = engine
            .allocate_or_get("third.routeward.test")
            .expect("allocate third by evicting oldest");
        assert!(engine.resolve_fake_ip(&ip1).is_some());
        assert!(
            engine.resolve_fake_ip(&ip2).is_none(),
            "Oldest entry (second.routeward.test) must have been evicted"
        );
        assert_eq!(
            engine.resolve_fake_ip(&ip3).as_deref(),
            Some("third.routeward.test")
        );

        // Zero capacity pool returns None immediately
        constants.dns.max_cache_entries = 0;
        let zero_engine = FakeIpEngine::new(&profile.dns_config, &constants.dns);
        assert!(zero_engine.allocate_or_get("any.routeward.test").is_none());
    }

    #[test]
    fn classifies_llmnr_and_mdns_local_names_vs_public_fqdns() {
        let constants = SystemConstants::load_embedded().unwrap();
        let mut profile = ProfileConfig::load_embedded_default().unwrap();
        profile
            .dns_config
            .bypass_domains
            .push("*.corp.contoso.com".to_string());
        let engine = FakeIpEngine::new(&profile.dns_config, &constants.dns);

        // 1. Single-label short name ("fileserver") -> AllowLocal
        let short_q = codec::build_a_query(0x1001, "fileserver").unwrap();
        assert_eq!(
            engine.classify_local_name_query(&short_q),
            LocalNameQueryDecision::AllowLocal {
                qname: "fileserver".to_string()
            }
        );

        // 2. .local mDNS name ("printer.local") -> AllowLocal
        let mdns_q = codec::build_a_query(0x1002, "printer.local").unwrap();
        assert_eq!(
            engine.classify_local_name_query(&mdns_q),
            LocalNameQueryDecision::AllowLocal {
                qname: "printer.local".to_string()
            }
        );

        // 3. Configured AD/bypass suffix ("dc01.corp.contoso.com") -> AllowLocal
        let ad_q = codec::build_a_query(0x1003, "dc01.corp.contoso.com").unwrap();
        assert_eq!(
            engine.classify_local_name_query(&ad_q),
            LocalNameQueryDecision::AllowLocal {
                qname: "dc01.corp.contoso.com".to_string()
            }
        );

        // 4. Private reverse zone ("10.1.168.192.in-addr.arpa") -> AllowLocal
        let ptr_q =
            codec::build_query(0x1004, "10.1.168.192.in-addr.arpa", codec::QTYPE_PTR).unwrap();
        assert_eq!(
            engine.classify_local_name_query(&ptr_q),
            LocalNameQueryDecision::AllowLocal {
                qname: "10.1.168.192.in-addr.arpa".to_string()
            }
        );

        // 5. Public FQDN ("leak.example.com") -> BlockPublicFqdn
        let pub_q = codec::build_a_query(0x1005, "leak.example.com").unwrap();
        assert_eq!(
            engine.classify_local_name_query(&pub_q),
            LocalNameQueryDecision::BlockPublicFqdn {
                qname: "leak.example.com".to_string()
            }
        );

        // 6. Malformed payload -> BlockMalformed without panic
        assert_eq!(
            engine.classify_local_name_query(&[0x00, 0x01, 0x02]),
            LocalNameQueryDecision::BlockMalformed
        );
    }
}
