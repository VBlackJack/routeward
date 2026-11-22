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

//! Pure policy decisions that sit on top of the rule engine: the security-policy overrides
//! (QUIC, DoT / DoQ, unknown process), the kill switch and the reason a connection ends up blocked.
//!
//! The relays and the window driver call these functions so that what really happens and what
//! [`predict_outcome`] predicts for a "what if" preview cannot drift apart.

use crate::checker::ProxyHealthReport;
use crate::config::{
    ProfileConfig, RuleAction, SecurityPolicyConfig, SystemConstants, TransportProtocol,
};
use crate::rules::{
    ConnectionRequest, RuleEngine, RuleEvaluationResult, DEFAULT_FALLBACK_RULE_ID,
    DEFAULT_FALLBACK_RULE_NAME,
};
use crate::telemetry::BlockReason;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Rule id reported when the unknown-process policy decided the action.
pub const UNKNOWN_PROCESS_RULE_ID: &str = "unknown-process-action";
/// Rule id reported when a connection targets an unmapped or expired Fake-IP address.
pub const FAKE_IP_UNMAPPED_RULE_ID: &str = "fake-ip-unmapped";
/// Rule name and id used when the QUIC security policy blocks a datagram.
pub const QUIC_POLICY_RULE_NAME: &str = "SecurityPolicy:blockQuicUdp443";
pub const QUIC_POLICY_RULE_ID: &str = "security-policy:block-quic-udp-443";
/// Rule name and id used when the encrypted DNS security policy blocks a connection.
pub const ENCRYPTED_DNS_POLICY_RULE_NAME: &str = "SecurityPolicy:blockEncryptedDnsBypass";
pub const ENCRYPTED_DNS_POLICY_RULE_ID: &str = "security-policy:block-encrypted-dns-bypass";
/// Rule name used for the unknown-process policy.
pub const UNKNOWN_PROCESS_RULE_NAME: &str = "SecurityPolicy:unknownProcessAction";
/// Rule name used when the kill switch turns an unknown-process `Direct` into a block.
pub const UNKNOWN_PROCESS_KILL_SWITCH_RULE_NAME: &str =
    "SecurityPolicy:unknownProcessAction(KillSwitchOverride)";
/// Rule name recorded when a fragmented UDP datagram cannot be carried by a proxied rule.
pub const FRAGMENTED_UDP_RULE_NAME: &str = "SecurityPolicy:FragmentedUdpBlocked";
/// Rule name recorded when a public name is queried over a local-name protocol (LLMNR, mDNS).
pub const LOCAL_NAME_GUARD_RULE_NAME: &str = "SecurityPolicy:LocalNamePublicFqdnBlocked";
/// Process name shown on local-name-guard records (no process is attributed to them).
pub const LOCAL_NAME_PROCESS_NAME: &str = "local-name-proto";
/// Process name shown on records of QUIC datagrams rejected by the window driver.
pub const QUIC_PROCESS_NAME: &str = "quic-udp-443";
/// Process names that mean "no process could be attributed".
const UNATTRIBUTED_PROCESS_NAMES: [&str; 2] = ["system", "unknown"];
/// Executable path prefix of a process known only by pid.
const PID_ONLY_PATH_PREFIX: &str = "pid:";

/// Ports the security policy reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyPorts {
    pub quic: u16,
    pub encrypted_dns: u16,
}

impl PolicyPorts {
    pub fn from_constants(constants: &SystemConstants) -> Self {
        Self {
            quic: constants.network.quic_default_port,
            encrypted_dns: constants.dns.dns_over_tls_port,
        }
    }

    /// Ports of the embedded constants.
    pub fn embedded() -> Self {
        static PORTS: OnceLock<PolicyPorts> = OnceLock::new();
        *PORTS.get_or_init(|| {
            let constants = SystemConstants::load_embedded()
                .expect("embedded system constants are validated at build time");
            Self::from_constants(&constants)
        })
    }
}

/// A security-policy decision that replaces the rule engine's action with `Block`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyOverride {
    pub reason: BlockReason,
    pub rule_name: &'static str,
    pub rule_id: &'static str,
}

impl PolicyOverride {
    /// Rewrites `eval` so it blocks, naming the policy as the matched rule.
    pub fn apply(&self, eval: &mut RuleEvaluationResult) {
        eval.action = RuleAction::Block;
        eval.matched_rule_name = self.rule_name.to_string();
        eval.matched_rule_id = self.rule_id.to_string();
    }
}

/// The QUIC / DoT / DoQ override for one connection, if the security policy asks for it.
/// QUIC (UDP 443) wins over DoQ (UDP 853) exactly like the relays check them.
pub fn port_policy_override(
    security: &SecurityPolicyConfig,
    ports: PolicyPorts,
    protocol: TransportProtocol,
    target_port: u16,
) -> Option<PolicyOverride> {
    let encrypted_dns = PolicyOverride {
        reason: BlockReason::EncryptedDnsBlocked,
        rule_name: ENCRYPTED_DNS_POLICY_RULE_NAME,
        rule_id: ENCRYPTED_DNS_POLICY_RULE_ID,
    };
    match protocol {
        TransportProtocol::Udp => {
            if target_port == ports.quic && security.block_quic_udp_443 {
                Some(PolicyOverride {
                    reason: BlockReason::QuicBlocked,
                    rule_name: QUIC_POLICY_RULE_NAME,
                    rule_id: QUIC_POLICY_RULE_ID,
                })
            } else if target_port == ports.encrypted_dns && security.block_encrypted_dns_bypass {
                Some(encrypted_dns)
            } else {
                None
            }
        }
        TransportProtocol::Tcp => (target_port == ports.encrypted_dns
            && security.block_encrypted_dns_bypass)
            .then_some(encrypted_dns),
        TransportProtocol::Any => None,
    }
}

/// What the unknown-process policy does with a connection whose process is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProcessDecision {
    pub action: RuleAction,
    pub rule_name: &'static str,
    /// Set when the decision is a block.
    pub reason: Option<BlockReason>,
}

/// Pure core of `RouteWardController::resolve_unknown_process_action`: with the kill switch on,
/// a configured `Direct` is overridden to `Block`; otherwise the configured action applies.
pub fn unknown_process_decision(security: &SecurityPolicyConfig) -> UnknownProcessDecision {
    let configured = security.unknown_process_action.clone();
    if security.kill_switch_enabled && configured == RuleAction::Direct {
        UnknownProcessDecision {
            action: RuleAction::Block,
            rule_name: UNKNOWN_PROCESS_KILL_SWITCH_RULE_NAME,
            reason: Some(BlockReason::UnknownProcessKillSwitch),
        }
    } else {
        let reason = (configured == RuleAction::Block).then_some(BlockReason::UnknownProcessPolicy);
        UnknownProcessDecision {
            action: configured,
            rule_name: UNKNOWN_PROCESS_RULE_NAME,
            reason,
        }
    }
}

/// True when a request names no concrete process (see `ProcessIdentity::is_unattributed`).
pub fn is_unattributed_request(req: &ConnectionRequest) -> bool {
    UNATTRIBUTED_PROCESS_NAMES.contains(&req.process_name.as_str())
        || req
            .process_path
            .as_deref()
            .is_some_and(|p| p.starts_with(PID_ONLY_PATH_PREFIX))
}

/// The reason to record when the rule engine alone returned `Block`.
pub fn block_reason_for_rule(rule_id: &str) -> BlockReason {
    match rule_id {
        DEFAULT_FALLBACK_RULE_ID => BlockReason::DefaultPolicyBlock,
        FAKE_IP_UNMAPPED_RULE_ID => BlockReason::FakeIpEgressGuard,
        UNKNOWN_PROCESS_RULE_ID => BlockReason::UnknownProcessPolicy,
        _ => BlockReason::RuleBlock,
    }
}

/// The reason to record for a block whose rule id may be unknown (paths that only carry the
/// rule name): the security-policy names are recognised, then the id, then the name of the
/// default policy.
pub fn block_reason_for_decision(rule_id: Option<&str>, rule_name: &str) -> BlockReason {
    match rule_name {
        QUIC_POLICY_RULE_NAME => return BlockReason::QuicBlocked,
        ENCRYPTED_DNS_POLICY_RULE_NAME => return BlockReason::EncryptedDnsBlocked,
        UNKNOWN_PROCESS_RULE_NAME | UNKNOWN_PROCESS_KILL_SWITCH_RULE_NAME => {
            return unknown_process_block_reason(rule_name)
        }
        DEFAULT_FALLBACK_RULE_NAME => return BlockReason::DefaultPolicyBlock,
        _ => {}
    }
    rule_id.map_or(BlockReason::RuleBlock, block_reason_for_rule)
}

/// The unknown-process block reason matching the rule name `resolve_unknown_process_action` returned.
pub fn unknown_process_block_reason(rule_name: &str) -> BlockReason {
    if rule_name == UNKNOWN_PROCESS_KILL_SWITCH_RULE_NAME {
        BlockReason::UnknownProcessKillSwitch
    } else {
        BlockReason::UnknownProcessPolicy
    }
}

/// The proxy that a failing proxied action points at. A chain has no single failing proxy known
/// here, so it yields `None`.
pub fn upstream_proxy_id(action: &RuleAction) -> Option<String> {
    match action {
        RuleAction::Proxy { target_id } => Some(target_id.clone()),
        _ => None,
    }
}

/// Result of [`predict_outcome`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PredictedOutcome {
    /// The effective evaluation: overrides that turn the action into `Block` are already applied.
    pub evaluation: RuleEvaluationResult,
    /// Set when a policy (not the matching rule itself) makes the connection end blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_override: Option<BlockReason>,
}

impl PredictedOutcome {
    /// Why the connection ends blocked, `None` when it is allowed.
    pub fn block_reason(&self) -> Option<BlockReason> {
        self.policy_override.or_else(|| {
            (self.evaluation.action == RuleAction::Block)
                .then(|| block_reason_for_rule(&self.evaluation.matched_rule_id))
        })
    }
}

/// Predicts what the engine would do for `request` under `profile`, using the embedded ports and
/// the current time. `health` is the latest known proxy health (empty when unknown).
pub fn predict_outcome(
    profile: &ProfileConfig,
    request: &ConnectionRequest,
    health: &[ProxyHealthReport],
) -> PredictedOutcome {
    predict_outcome_at(
        profile,
        request,
        health,
        PolicyPorts::embedded(),
        Utc::now(),
    )
}

/// [`predict_outcome`] with the ports and the clock supplied by the caller.
pub fn predict_outcome_at(
    profile: &ProfileConfig,
    request: &ConnectionRequest,
    health: &[ProxyHealthReport],
    ports: PolicyPorts,
    now: DateTime<Utc>,
) -> PredictedOutcome {
    let eval = RuleEngine::evaluate_at(request, &profile.rules, &profile.default_action, None, now);
    predict_from_evaluation(profile, request, eval, health, ports)
}

/// Applies the policy overrides and the kill switch to an evaluation the caller already made
/// (the controller evaluates with its Fake-IP engine, a preview without).
pub fn predict_from_evaluation(
    profile: &ProfileConfig,
    request: &ConnectionRequest,
    mut eval: RuleEvaluationResult,
    health: &[ProxyHealthReport],
    ports: PolicyPorts,
) -> PredictedOutcome {
    let security = &profile.security_policy;
    let mut policy_override: Option<BlockReason> = None;

    if is_unattributed_request(request) && eval.action == RuleAction::Direct {
        let decision = unknown_process_decision(security);
        eval.matched_rule_id = UNKNOWN_PROCESS_RULE_ID.to_string();
        eval.matched_rule_name = decision.rule_name.to_string();
        eval.action = decision.action;
        policy_override = decision.reason;
    }

    if let Some(over) = port_policy_override(security, ports, request.protocol, request.target_port)
    {
        over.apply(&mut eval);
        policy_override = Some(over.reason);
    }

    if policy_override.is_none() && security.kill_switch_enabled {
        policy_override = kill_switch_prediction(profile, &eval.action, request.protocol, health);
    }

    PredictedOutcome {
        evaluation: eval,
        policy_override,
    }
}

/// Whether the kill switch would block a proxied action given what is known about the proxies.
fn kill_switch_prediction(
    profile: &ProfileConfig,
    action: &RuleAction,
    protocol: TransportProtocol,
    health: &[ProxyHealthReport],
) -> Option<BlockReason> {
    let proxy_ids: Vec<&str> = match action {
        RuleAction::Proxy { target_id } => {
            if !profile.proxies.iter().any(|p| &p.id == target_id) {
                return Some(BlockReason::KillSwitchProxyMisconfigured);
            }
            vec![target_id.as_str()]
        }
        RuleAction::Chain { target_id } => {
            let Some(chain) = profile.chains.iter().find(|c| &c.id == target_id) else {
                return Some(BlockReason::KillSwitchProxyMisconfigured);
            };
            if chain.proxy_ids.is_empty()
                || chain
                    .proxy_ids
                    .iter()
                    .any(|id| !profile.proxies.iter().any(|p| &p.id == id))
            {
                return Some(BlockReason::KillSwitchProxyMisconfigured);
            }
            chain.proxy_ids.iter().map(String::as_str).collect()
        }
        RuleAction::Direct | RuleAction::Block => return None,
    };
    for id in proxy_ids {
        let Some(report) = health.iter().find(|r| r.proxy_id == id) else {
            continue;
        };
        if !report.reachable {
            return Some(BlockReason::KillSwitchProxyUnreachable);
        }
        if protocol == TransportProtocol::Udp
            && !report.udp_supported
            && profile.security_policy.block_udp_on_tcp_only_proxy
        {
            return Some(BlockReason::KillSwitchUdpUnsupported);
        }
    }
    None
}
