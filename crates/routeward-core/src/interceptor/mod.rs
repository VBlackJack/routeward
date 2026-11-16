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

pub mod backend;
mod controller;
mod dns_handler;
pub mod nat;
pub mod nftables;
mod tcp_relay;
#[cfg(test)]
mod tests;
mod udp_relay;
pub mod windivert;

use crate::config::{InterceptionMode, ProfileConfig, SystemConstants};
use crate::dns::FakeIpEngine;
use crate::i18n::I18nRegistry;
use crate::interceptor::backend::Interceptor;
use crate::interceptor::nat::{SelfPortGuard, TransparentNatTable};
use crate::process::ProcessResolver;
use crate::proxy::udp::UdpAssociationManager;
use crate::telemetry::TelemetryHub;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub(super) const COMPONENT_ENGINE: &str = "InterceptorEngine";
pub(super) const COMPONENT_TRANSPARENT: &str = "TransparentRelay";
pub(super) const COMPONENT_WINDIVERT: &str = "WinDivert";
pub(super) const COMPONENT_RULE: &str = "RuleEngine";
pub(super) const COMPONENT_PROXY: &str = "ProxyConnector";
pub(super) const COMPONENT_DNS: &str = "FakeIpDNS";
pub(super) const ROUTE_DIRECT_LABEL: &str = "DIRECT";
pub(super) const ROUTE_BLOCK_LABEL: &str = "BLOCKED";
pub(super) const SIMULATED_DEFAULT_RX_BYTES: u64 = 18432;
pub(super) const SIMULATED_DEFAULT_TX_BYTES: u64 = 4096;
pub(super) const SIMULATED_DEFAULT_LATENCY_MS: u64 = 18;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemDiagnostics {
    #[serde(default = "default_daemon_connected")]
    pub daemon_connected: bool,
    pub running: bool,
    pub os_name: String,
    pub interception_mode: InterceptionMode,
    pub elevated_privileges: bool,
    pub relay_tcp_endpoint: String,
    pub relay_http_endpoint: String,
    pub dns_endpoint: String,
    pub fake_ip_cidr: String,
    pub active_locale: String,
}

fn default_daemon_connected() -> bool {
    true
}

/// Policy controlling which DNS resolvers `candidate_dns_resolvers` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolverMode {
    /// Bypassed domain (`bypassDomains`, AD suffixes, single-label, `.local`, private reverse zones):
    /// ONLY `orig_resolver`, active system resolvers, and `last_seen_orig_resolver`.
    /// NEVER `upstreamDns`, `default_upstream`, or `fallback_dns_server`.
    BypassOnlySystem,
    /// Direct flow resolution (non-bypassed domain):
    /// `orig_resolver`, active system resolvers, and `last_seen_orig_resolver` first;
    /// `upstreamDns` (and `default_upstream`/`fallback_dns_server`) ONLY if nothing else exists.
    DirectPreferSystem,
    /// Remote DNS-over-TCP via Proxy or Chain:
    /// configured `upstreamDns`, `orig_resolver`, `default_upstream`, `fallback_dns_server`.
    RemoteViaProxy,
}

/// Upper bound on distinct categories tracked by [`WarnRateLimiter`] before pruning kicks in.
const WARN_RATE_LIMITER_MAX_KEYS: usize = 2_048;
/// A category idle for this many rate-limit intervals is dropped when the limiter is pruned.
const WARN_RATE_LIMITER_IDLE_INTERVALS: u32 = 4;

/// Rate limiter for repetitive UDP/QUIC/LLMNR/mDNS/NetBIOS-NS `WARN` logs with per-category hit counters.
#[derive(Clone)]
pub struct WarnRateLimiter {
    entries: Arc<DashMap<String, (Instant, u64)>>,
    interval: Duration,
}

impl WarnRateLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            interval,
        }
    }

    /// Increments the hit counter for `category_key` and returns `(should_emit_warn_now, total_count)`.
    pub fn should_log(&self, category_key: &str) -> (bool, u64) {
        let now = Instant::now();
        if self.entries.len() >= WARN_RATE_LIMITER_MAX_KEYS {
            self.prune(now);
        }
        if let Some(mut entry) = self.entries.get_mut(category_key) {
            let (last_logged, count) = *entry.value();
            let next_count = count + 1;
            if now.duration_since(last_logged) >= self.interval {
                *entry.value_mut() = (now, next_count);
                return (true, next_count);
            }
            entry.value_mut().1 = next_count;
            return (false, next_count);
        }
        self.entries.insert(category_key.to_string(), (now, 1));
        (true, 1)
    }

    /// Bounds memory: keys built from network data (domain names, addresses) would otherwise
    /// accumulate forever. Entries idle for several intervals are dropped first; if the map is
    /// still full the oldest half is evicted.
    fn prune(&self, now: Instant) {
        let max_idle = self
            .interval
            .saturating_mul(WARN_RATE_LIMITER_IDLE_INTERVALS);
        self.entries
            .retain(|_, (last_logged, _)| now.duration_since(*last_logged) < max_idle);
        if self.entries.len() < WARN_RATE_LIMITER_MAX_KEYS {
            return;
        }
        let mut by_age: Vec<(Instant, String)> = self
            .entries
            .iter()
            .map(|e| (e.value().0, e.key().clone()))
            .collect();
        by_age.sort_by_key(|(at, _)| *at);
        for (_, key) in by_age.into_iter().take(WARN_RATE_LIMITER_MAX_KEYS / 2) {
            self.entries.remove(&key);
        }
    }

    /// Returns the number of tracked categories.
    pub fn tracked_keys(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone)]
pub struct RouteWardController {
    pub constants: Arc<SystemConstants>,
    pub profile: Arc<RwLock<ProfileConfig>>,
    pub i18n: I18nRegistry,
    pub dns: FakeIpEngine,
    pub process_resolver: ProcessResolver,
    pub telemetry: TelemetryHub,
    pub nat_table: TransparentNatTable,
    pub udp_manager: UdpAssociationManager,
    pub(super) warn_rate_limiter: WarnRateLimiter,
    pub(super) fragmented_udp_drop_count: Arc<AtomicU64>,
    pub(super) last_seen_orig_resolver: Arc<RwLock<Option<SocketAddr>>>,
    pub(super) system_resolvers_override: Arc<RwLock<Option<Vec<SocketAddr>>>>,
    pub(super) bootstrapped_proxy_endpoints: Arc<DashMap<String, Vec<(IpAddr, u16)>>>,
    pub(super) direct_udp_pool: Arc<parking_lot::Mutex<Vec<(UdpSocket, SelfPortGuard)>>>,
    pub(super) direct_udp_v6_pool: Arc<parking_lot::Mutex<Vec<(UdpSocket, SelfPortGuard)>>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) conntrack_cache: Arc<parking_lot::Mutex<Option<(Instant, String)>>>,
    pub(super) interceptor_backend: Arc<dyn Interceptor>,
    pub(super) running: Arc<AtomicBool>,
}

#[cfg(test)]
mod warn_rate_limiter_tests {
    use super::*;

    #[test]
    fn warn_rate_limiter_stays_bounded_under_unique_keys() {
        let limiter = WarnRateLimiter::new(Duration::from_secs(60));
        for i in 0..(WARN_RATE_LIMITER_MAX_KEYS * 3) {
            let (emit, count) = limiter.should_log(&format!("mdns:host-{i}.example"));
            assert!(emit);
            assert_eq!(count, 1);
        }
        assert!(limiter.tracked_keys() <= WARN_RATE_LIMITER_MAX_KEYS);
    }

    #[test]
    fn warn_rate_limiter_still_rate_limits_repeated_keys() {
        let limiter = WarnRateLimiter::new(Duration::from_secs(60));
        assert_eq!(limiter.should_log("k"), (true, 1));
        assert_eq!(limiter.should_log("k"), (false, 2));
    }
}
