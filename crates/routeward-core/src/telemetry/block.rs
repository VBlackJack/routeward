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

//! Block reasons, the only constructor of `Blocked` connection records, and the bounded
//! aggregation of those records into a per-destination summary.

use super::{ConnectionStatus, TrackedConnection};
use crate::config::TransportProtocol;
use crate::error::{RouteWardError, ERR_KEY_RULE_BLOCKED};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Route label shown for every blocked connection.
pub const ROUTE_BLOCK_LABEL: &str = "BLOCKED";

/// Prefix of the rule name recorded when the Fake-IP egress guard fires.
const FAKE_IP_GUARD_RULE_PREFIX: &str = "SecurityPolicy:FakeIpEgress";

/// Why a connection was blocked. Serialized as camelCase strings; a value written by a newer
/// version that this build does not know deserializes to [`BlockReason::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BlockReason {
    /// A user, pack or built-in rule has the `Block` action.
    RuleBlock,
    /// No rule matched and the profile default action is `Block`.
    DefaultPolicyBlock,
    /// Kill switch: the upstream proxy could not be reached.
    KillSwitchProxyUnreachable,
    /// Kill switch: the upstream proxy refused the connection.
    KillSwitchProxyRefused,
    /// Kill switch: the upstream proxy timed out.
    KillSwitchProxyTimeout,
    /// Kill switch: the upstream proxy rejected the credentials.
    KillSwitchProxyAuthRejected,
    /// Kill switch: the proxy handshake failed.
    KillSwitchProxyHandshake,
    /// Kill switch: the rule points to a missing proxy or an empty chain.
    KillSwitchProxyMisconfigured,
    /// The proxy cannot carry UDP (no UDP ASSOCIATE, or `blockUdpOnTcpOnlyProxy`). Emitted
    /// whatever the kill switch state: it is a capability gap, not a proxy outage.
    UdpProxyUnsupported,
    /// Kill switch: a direct UDP datagram could not be sent.
    KillSwitchDirectUdpFailed,
    /// A fragmented UDP datagram that a proxied rule cannot carry.
    FragmentedUdpBlocked,
    /// The process behind the connection is unknown and the policy blocks it.
    UnknownProcessPolicy,
    /// The process behind the connection is unknown and the kill switch overrides the rule.
    UnknownProcessKillSwitch,
    /// Traffic toward an untranslated Fake-IP address.
    FakeIpEgressGuard,
    /// QUIC (UDP 443) blocked by the security policy.
    QuicBlocked,
    /// DoT / DoQ (port 853) blocked by the security policy.
    EncryptedDnsBlocked,
    /// Local-name guard: a local name queried publicly.
    LocalNameGuard,
    /// A DNS query dropped because a `Block` rule matches its name.
    DnsServerBlockedByRule,
    /// A reason this build does not know.
    #[serde(other)]
    Unknown,
}

impl BlockReason {
    /// True for the reasons caused by a failing proxy while the kill switch is on (a proxy
    /// outage). `UdpProxyUnsupported` is deliberately excluded.
    pub fn is_kill_switch_proxy(self) -> bool {
        matches!(
            self,
            Self::KillSwitchProxyUnreachable
                | Self::KillSwitchProxyRefused
                | Self::KillSwitchProxyTimeout
                | Self::KillSwitchProxyAuthRejected
                | Self::KillSwitchProxyHandshake
                | Self::KillSwitchProxyMisconfigured
        )
    }

    /// Reason for a proxied UDP datagram that was blocked after an upstream failure. A proxy
    /// that cannot carry UDP is [`Self::UdpProxyUnsupported`] whatever the kill switch state;
    /// other failures are kill-switch reasons only when the kill switch is on, otherwise the
    /// block comes from `blockUdpOnTcpOnlyProxy` and is also [`Self::UdpProxyUnsupported`].
    pub fn from_udp_proxy_error(err: &RouteWardError, kill_switch_enabled: bool) -> Self {
        if matches!(err, RouteWardError::UdpAssociateUnsupported { .. }) || !kill_switch_enabled {
            Self::UdpProxyUnsupported
        } else {
            Self::from_upstream_error(err)
        }
    }

    /// Maps the error returned by an outbound open (`open_outbound_stream`, UDP associate) to
    /// the kill-switch reason it caused.
    pub fn from_upstream_error(err: &RouteWardError) -> Self {
        use std::io::ErrorKind;
        match err {
            RouteWardError::ConnectionTimeout { .. } => Self::KillSwitchProxyTimeout,
            RouteWardError::AuthenticationRejected { .. } => Self::KillSwitchProxyAuthRejected,
            RouteWardError::ProtocolHandshake { .. } => Self::KillSwitchProxyHandshake,
            RouteWardError::UdpAssociateUnsupported { .. } => Self::UdpProxyUnsupported,
            RouteWardError::ProxyNotFound { .. }
            | RouteWardError::EmptyProxyChain { .. }
            | RouteWardError::InvalidProxyUri { .. } => Self::KillSwitchProxyMisconfigured,
            RouteWardError::BlockedByPolicy { key, rule_name } => {
                if *key == ERR_KEY_RULE_BLOCKED && rule_name.starts_with(FAKE_IP_GUARD_RULE_PREFIX)
                {
                    Self::FakeIpEgressGuard
                } else {
                    Self::RuleBlock
                }
            }
            RouteWardError::Io(io) => match io.kind() {
                ErrorKind::ConnectionRefused => Self::KillSwitchProxyRefused,
                ErrorKind::TimedOut => Self::KillSwitchProxyTimeout,
                _ => Self::KillSwitchProxyUnreachable,
            },
            _ => Self::KillSwitchProxyUnreachable,
        }
    }
}

/// Everything needed to record one blocked connection. The `reason` is mandatory: there is no
/// default, so no blocked record can exist without saying why.
#[derive(Debug, Clone)]
pub struct BlockedRecord {
    pub reason: BlockReason,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub target_host: String,
    pub target_ip: Option<String>,
    pub resolved_domain: Option<String>,
    pub target_port: u16,
    pub protocol: TransportProtocol,
    /// Display name of the rule or policy that blocked the connection.
    pub matched_rule: String,
    pub matched_rule_id: Option<String>,
    /// Upstream proxy that failed (kill-switch reasons only).
    pub proxy_id: Option<String>,
    pub error_detail: Option<String>,
    pub tx_bytes: u64,
    /// True for hypothetical records (simulation, OS socket scan): never counted in summaries.
    pub simulated: bool,
}

impl BlockedRecord {
    /// A record with the mandatory fields; the process and target start empty and are set with
    /// [`Self::process`] and [`Self::target`].
    pub fn new(
        reason: BlockReason,
        protocol: TransportProtocol,
        matched_rule: impl Into<String>,
    ) -> Self {
        Self {
            reason,
            pid: 0,
            process_name: String::new(),
            process_path: String::new(),
            target_host: String::new(),
            target_ip: None,
            resolved_domain: None,
            target_port: 0,
            protocol,
            matched_rule: matched_rule.into(),
            matched_rule_id: None,
            proxy_id: None,
            error_detail: None,
            tx_bytes: 0,
            simulated: false,
        }
    }

    pub fn process(mut self, name: impl Into<String>, path: impl Into<String>, pid: u32) -> Self {
        self.process_name = name.into();
        self.process_path = path.into();
        self.pid = pid;
        self
    }

    pub fn target(mut self, host: impl Into<String>, port: u16) -> Self {
        self.target_host = host.into();
        self.target_port = port;
        self
    }

    pub fn with_domain(mut self, domain: Option<String>) -> Self {
        self.resolved_domain = domain;
        self
    }

    pub fn with_ip(mut self, ip: Option<String>) -> Self {
        self.target_ip = ip;
        self
    }

    pub fn with_rule_id(mut self, id: impl Into<String>) -> Self {
        self.matched_rule_id = Some(id.into());
        self
    }

    pub fn with_proxy(mut self, proxy_id: Option<String>) -> Self {
        self.proxy_id = proxy_id;
        self
    }

    pub fn with_error(mut self, detail: impl Into<String>) -> Self {
        self.error_detail = Some(detail.into());
        self
    }

    pub fn with_tx_bytes(mut self, tx_bytes: u64) -> Self {
        self.tx_bytes = tx_bytes;
        self
    }

    pub fn simulated(mut self) -> Self {
        self.simulated = true;
        self
    }
}

impl TrackedConnection {
    /// The only way to build a `Blocked` connection outside tests: the reason is required, the
    /// route label is always [`ROUTE_BLOCK_LABEL`] and no traffic is ever counted as received.
    pub fn blocked(record: BlockedRecord) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            pid: record.pid,
            process_name: record.process_name,
            process_path: record.process_path,
            target_host: record.target_host,
            resolved_domain: record.resolved_domain,
            target_port: record.target_port,
            protocol: record.protocol,
            matched_rule: record.matched_rule,
            route_label: ROUTE_BLOCK_LABEL.to_string(),
            latency_ms: 0,
            rx_bytes: 0,
            tx_bytes: record.tx_bytes,
            status: ConnectionStatus::Blocked,
            started_at: Utc::now(),
            error_detail: record.error_detail,
            block_reason: Some(record.reason),
            matched_rule_id: record.matched_rule_id,
            proxy_id: record.proxy_id,
            target_ip: record.target_ip,
            simulated: record.simulated,
        }
    }
}

/// One aggregated line of the blocked-connections summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockedSummary {
    /// Lowercased process name.
    pub process_name: String,
    pub process_path: String,
    /// Domain when known, else the IP.
    pub destination: String,
    pub target_port: u16,
    pub protocol: TransportProtocol,
    pub block_reason: BlockReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
    /// Display name of the matched rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    pub count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_connection_id: String,
    pub last_pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_detail: Option<String>,
}

/// Counters of packets dropped without a connection row (no process could be attributed).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnattributedDropCounters {
    pub dropped_unattributed_syn: u64,
    pub dropped_unattributed_udp: u64,
}

/// Bounded map of blocked-connection summaries, evicting the entry seen longest ago.
pub(super) struct BlockedSummaryStore {
    entries: HashMap<String, BlockedSummary>,
    capacity: usize,
}

impl BlockedSummaryStore {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    fn key_of(conn: &TrackedConnection, destination: &str, reason: BlockReason) -> String {
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{:?}\u{1f}{:?}\u{1f}{}",
            conn.process_name.to_lowercase(),
            conn.process_path,
            destination,
            conn.target_port,
            conn.protocol,
            reason,
            conn.matched_rule_id.as_deref().unwrap_or("")
        )
    }

    /// Aggregates one blocked record. Simulated records and records that are not blocked are ignored.
    pub(super) fn record(&mut self, conn: &TrackedConnection) {
        self.aggregate(conn, false);
    }

    /// Aggregates a repeat of a flow whose first record is already stored: the count and the
    /// last-seen time move, `lastConnectionId` keeps pointing at the stored row.
    pub(super) fn record_repeat(&mut self, conn: &TrackedConnection) {
        self.aggregate(conn, true);
    }

    fn aggregate(&mut self, conn: &TrackedConnection, keep_connection_id: bool) {
        if conn.status != ConnectionStatus::Blocked || conn.simulated {
            return;
        }
        let reason = conn.block_reason.unwrap_or(BlockReason::Unknown);
        let destination = conn
            .resolved_domain
            .clone()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| conn.target_host.clone());
        let key = Self::key_of(conn, &destination, reason);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.count += 1;
            entry.last_seen = entry.last_seen.max(conn.started_at);
            if !keep_connection_id {
                entry.last_connection_id = conn.id.clone();
            }
            entry.last_pid = conn.pid;
            entry.last_error_detail = conn.error_detail.clone();
            if conn.proxy_id.is_some() {
                entry.proxy_id = conn.proxy_id.clone();
            }
            return;
        }
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            BlockedSummary {
                process_name: conn.process_name.to_lowercase(),
                process_path: conn.process_path.clone(),
                destination,
                target_port: conn.target_port,
                protocol: conn.protocol,
                block_reason: reason,
                matched_rule_id: conn.matched_rule_id.clone(),
                matched_rule: (!conn.matched_rule.is_empty()).then(|| conn.matched_rule.clone()),
                proxy_id: conn.proxy_id.clone(),
                count: 1,
                first_seen: conn.started_at,
                last_seen: conn.started_at,
                last_connection_id: conn.id.clone(),
                last_pid: conn.pid,
                last_error_detail: conn.error_detail.clone(),
            },
        );
    }

    /// Entries sorted by `lastSeen`, newest first.
    pub(super) fn sorted(&self) -> Vec<BlockedSummary> {
        let mut list: Vec<BlockedSummary> = self.entries.values().cloned().collect();
        list.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.destination.cmp(&b.destination))
        });
        list
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
#[path = "block_tests.rs"]
mod tests;
