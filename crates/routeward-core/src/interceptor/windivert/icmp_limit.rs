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

//! Rate limit of the ICMP Port Unreachable messages injected for blocked UDP flows.
//!
//! An application that retransmits a blocked datagram in a tight loop must not make RouteWard
//! forge and inject one ICMP message per retransmission: at most one is injected per flow
//! (source address and port, destination address and port) per window. The table is bounded.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Minimum delay between two injected ICMP messages for the same flow.
pub(super) const ICMP_INJECTION_WINDOW: Duration = Duration::from_secs(1);
/// Most flows tracked at once; beyond it, expired entries are dropped first, then the oldest.
pub(super) const ICMP_LIMITER_MAX_FLOWS: usize = 1024;

/// A UDP flow as seen on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct IcmpFlowKey {
    pub(super) src_ip: IpAddr,
    pub(super) src_port: u16,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
}

/// Allows one injected ICMP message per flow and window.
pub(super) struct IcmpRateLimiter {
    window: Duration,
    max_flows: usize,
    last_sent: Mutex<HashMap<IcmpFlowKey, Instant>>,
}

impl IcmpRateLimiter {
    pub(super) fn new() -> Self {
        Self::with_limits(ICMP_INJECTION_WINDOW, ICMP_LIMITER_MAX_FLOWS)
    }

    fn with_limits(window: Duration, max_flows: usize) -> Self {
        Self {
            window,
            max_flows,
            last_sent: Mutex::new(HashMap::new()),
        }
    }

    /// `true` when an ICMP message may be injected for `key` at `now`; the call records it.
    pub(super) fn allow(&self, key: IcmpFlowKey, now: Instant) -> bool {
        let mut map = self.last_sent.lock();
        if let Some(last) = map.get(&key) {
            if now.saturating_duration_since(*last) < self.window {
                return false;
            }
        }
        if !map.contains_key(&key) && map.len() >= self.max_flows {
            let window = self.window;
            map.retain(|_, last| now.saturating_duration_since(*last) < window);
            if map.len() >= self.max_flows {
                let oldest = map.iter().min_by_key(|(_, last)| **last).map(|(k, _)| *k);
                if let Some(oldest) = oldest {
                    map.remove(&oldest);
                }
            }
        }
        map.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(src_port: u16) -> IcmpFlowKey {
        IcmpFlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            dst_port: 443,
        }
    }

    #[test]
    fn one_message_per_flow_per_window() {
        let limiter = IcmpRateLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.allow(key(5000), t0));
        assert!(!limiter.allow(key(5000), t0 + Duration::from_millis(10)));
        assert!(!limiter.allow(
            key(5000),
            t0 + ICMP_INJECTION_WINDOW - Duration::from_millis(1)
        ));
        assert!(limiter.allow(key(5000), t0 + ICMP_INJECTION_WINDOW));
    }

    #[test]
    fn flows_are_limited_independently() {
        let limiter = IcmpRateLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.allow(key(5000), t0));
        assert!(limiter.allow(key(5001), t0));
        assert!(!limiter.allow(key(5000), t0));
        let mut other_dst = key(5000);
        other_dst.dst_port = 853;
        assert!(limiter.allow(other_dst, t0));
    }

    #[test]
    fn table_stays_bounded_and_evicts_expired_then_oldest() {
        let window = Duration::from_secs(1);
        let limiter = IcmpRateLimiter::with_limits(window, 3);
        let t0 = Instant::now();
        assert!(limiter.allow(key(1), t0));
        assert!(limiter.allow(key(2), t0 + Duration::from_millis(100)));
        assert!(limiter.allow(key(3), t0 + Duration::from_millis(200)));
        // Full, nothing expired: the oldest (key 1) is evicted and may be answered again.
        assert!(limiter.allow(key(4), t0 + Duration::from_millis(300)));
        assert_eq!(limiter.last_sent.lock().len(), 3);
        assert!(limiter.allow(key(1), t0 + Duration::from_millis(400)));
        assert_eq!(limiter.last_sent.lock().len(), 3);
        // Later, every entry has expired and is purged on the next insertion.
        assert!(limiter.allow(key(9), t0 + Duration::from_secs(10)));
        assert_eq!(limiter.last_sent.lock().len(), 1);
    }
}
