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

use crate::config::{DnsConfig, DnsConstants};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::Ipv4Net;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

const DEFAULT_FALLBACK_NET: [u8; 4] = [198, 18, 0, 0];
const DEFAULT_FALLBACK_PREFIX: u8 = 15;
const HOST_OFFSET_START: u32 = 1;
const WILDCARD_PREFIX: &str = "*.";

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
    max_entries: usize,
    bypass_domains: Arc<Vec<String>>,
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

        Self {
            subnet,
            ttl_seconds: constants.default_ttl_seconds as i64,
            max_entries: constants.max_cache_entries,
            bypass_domains: Arc::new(dns_config.bypass_domains.clone()),
            cursor: Arc::new(Mutex::new(HOST_OFFSET_START)),
            domain_to_record: Arc::new(DashMap::new()),
            ip_to_domain: Arc::new(DashMap::new()),
        }
    }

    pub fn is_bypassed(&self, domain: &str) -> bool {
        let normalized = domain.trim().trim_end_matches('.').to_lowercase();
        for pattern in self.bypass_domains.iter() {
            let pat = pattern.to_lowercase();
            if pat == normalized {
                return true;
            }
            if let Some(suffix) = pat.strip_prefix(WILDCARD_PREFIX) {
                if normalized == suffix || normalized.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            }
        }
        false
    }

    pub fn allocate_or_get(&self, domain: &str) -> Option<Ipv4Addr> {
        let normalized = domain.trim().trim_end_matches('.').to_lowercase();
        if normalized.is_empty() || self.is_bypassed(&normalized) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProfileConfig, SystemConstants};

    #[test]
    fn allocates_and_reverse_resolves_fake_ip() {
        let constants = SystemConstants::load_embedded().unwrap();
        let profile = ProfileConfig::load_embedded_default().unwrap();
        let engine = FakeIpEngine::new(&profile.dns_config, &constants.dns);

        let ip = engine
            .allocate_or_get("api.github.com")
            .expect("Allocated IP");
        assert!(ip.to_string().starts_with("198.18."));

        let resolved = engine.resolve_fake_ip(&ip).expect("Reverse resolved");
        assert_eq!(resolved, "api.github.com");

        // Bypassed domain returns None
        assert!(engine.allocate_or_get("printer.local").is_none());
    }
}
