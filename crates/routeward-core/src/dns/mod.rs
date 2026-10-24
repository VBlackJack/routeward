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
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

const DEFAULT_FALLBACK_NET: [u8; 4] = [198, 18, 0, 0];
const DEFAULT_FALLBACK_PREFIX: u8 = 15;
const HOST_OFFSET_START: u32 = 1;
const WILDCARD_PREFIX: &str = "*.";
const ENV_EXTRA_DNS_SUFFIXES: &str = "ROUTEWARD_SYSTEM_DNS_SUFFIXES";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FakeIpEntry {
    pub fake_ip: String,
    pub domain: String,
    pub hits: u64,
    pub expires_at: DateTime<Utc>,
    pub ttl_remaining_seconds: i64,
}

#[derive(Debug, Clone)]
struct InternalRecord {
    fake_ip: Ipv4Addr,
    domain: String,
    hits: u64,
    expires_at: DateTime<Utc>,
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
            domain_to_record: Arc::new(DashMap::new()),
            ip_to_domain: Arc::new(DashMap::new()),
        }
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

    pub fn allocate_or_get(&self, domain: &str) -> Option<Ipv4Addr> {
        let normalized = normalize_domain_name(domain);
        if normalized.is_empty() || self.is_bypassed(&normalized) || self.is_doh_canary(&normalized)
        {
            return None;
        }

        let now = Utc::now();
        let next_expiry = now + chrono::Duration::seconds(self.ttl_seconds);

        if let Some(mut existing) = self.domain_to_record.get_mut(&normalized) {
            existing.hits += 1;
            existing.expires_at = next_expiry;
            return Some(existing.fake_ip);
        }

        if self.domain_to_record.len() >= self.max_entries {
            self.evict_expired();
        }

        let allocated_ip = self.next_ip_in_subnet();
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
        };

        self.domain_to_record.insert(normalized, record);
        Some(allocated_ip)
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
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for parsed in parse_resolv_conf_suffixes(&content) {
                push_unique_normalized_suffix(&mut suffixes, &parsed);
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

/// Extracts the first non-loopback IPv4 nameserver from `/etc/resolv.conf` if present.
pub fn parse_resolv_conf_nameservers(content: &str) -> Vec<Ipv4Addr> {
    let mut servers = Vec::new();
    for line in content.lines() {
        let line_no_comment = line.split(['#', ';']).next().unwrap_or("").trim();
        let mut tokens = line_no_comment.split_whitespace();
        if let (Some(dir), Some(addr_str)) = (tokens.next(), tokens.next()) {
            if dir.eq_ignore_ascii_case("nameserver") {
                if let Ok(ip) = addr_str.parse::<Ipv4Addr>() {
                    if !ip.is_loopback() && !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        }
    }
    servers
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
        assert_eq!(nameservers, vec![Ipv4Addr::new(10, 200, 1, 1)]);
    }
}
