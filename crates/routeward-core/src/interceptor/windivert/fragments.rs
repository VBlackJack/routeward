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

//! Rule and kill-switch decision for fragmented outbound UDP datagrams.
//!
//! A datagram larger than the MTU leaves the host as several IP fragments and only the first one
//! carries the UDP header. Fragments cannot be reassembled for relaying, so the first fragment is
//! attributed to its process, evaluated against the rules and given a verdict (drop or release)
//! that is remembered for the remaining fragments of the same datagram.

use crate::config::{RuleAction, TransportProtocol};
use crate::interceptor::nat::{decide_udp_fragment_verdict, UdpFragmentMeta, UdpFragmentVerdict};
use crate::interceptor::{RouteWardController, COMPONENT_ENGINE, COMPONENT_WINDIVERT};
use crate::process::ProcessIdentity;
use crate::rules::ConnectionRequest;
use std::net::IpAddr;
use std::sync::atomic::Ordering;

/// Outcome of evaluating the first fragment of a UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FragmentDecision {
    pub(super) verdict: UdpFragmentVerdict,
    pub(super) action: RuleAction,
    pub(super) rule_name: String,
}

/// Evaluates the first fragment of a UDP datagram sent by `process` and returns the verdict to
/// apply to every fragment of that datagram.
///
/// An unattributed process follows `unknownProcessAction` (overridden to Block by the kill
/// switch). A proxied or chained flow cannot be relayed from fragments, so it is dropped when the
/// kill switch is on and released directly when it is off; Direct passes and Block drops. A
/// destination inside the Fake-IP range is never valid on the wire and is always dropped.
pub(super) fn decide_first_udp_fragment(
    ctrl: &RouteWardController,
    process: Option<&ProcessIdentity>,
    frag: &UdpFragmentMeta,
) -> FragmentDecision {
    let kill_switch_enabled = ctrl.profile.read().security_policy.kill_switch_enabled;
    let dst_host = frag.dst_ip.to_string();
    let attributed = process.filter(|p| !p.is_unattributed());

    let (action, rule_name, process_label) = match attributed {
        Some(p) => {
            let eval = ctrl.evaluate_rule(&ConnectionRequest {
                process_name: p.name.clone(),
                process_path: Some(p.executable_path.clone()),
                target_host: dst_host.clone(),
                target_ip: Some(dst_host.clone()),
                target_port: frag.dst_port,
                protocol: TransportProtocol::Udp,
            });
            (eval.action, eval.matched_rule_name, p.name.clone())
        }
        None => {
            let (action, rule_name) = ctrl.resolve_unknown_process_action(
                COMPONENT_WINDIVERT,
                frag.src_port,
                &dst_host,
                frag.dst_port,
                "process image unavailable",
            );
            (action, rule_name, "unattributed".to_string())
        }
    };

    let is_fake_ip = matches!(frag.dst_ip, IpAddr::V4(v4) if ctrl.dns.is_in_fake_subnet(&v4));
    let verdict = if is_fake_ip {
        UdpFragmentVerdict::Drop
    } else {
        decide_udp_fragment_verdict(&action, kill_switch_enabled)
    };

    if matches!(action, RuleAction::Proxy { .. } | RuleAction::Chain { .. }) {
        let drop_count = ctrl
            .fragmented_udp_drop_count
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        ctrl.push_rate_limited_warn(
            "udp_fragmented_proxy",
            COMPONENT_ENGINE,
            format!(
                "Fragmented UDP datagram #{drop_count} from process=\"{}\" -> {}:{} matched proxied rule \"{}\" (v1 does not reassemble UDP fragments; killSwitchEnabled={}, verdict={:?})",
                process_label, frag.dst_ip, frag.dst_port, rule_name, kill_switch_enabled, verdict
            ),
        );
    }

    FragmentDecision {
        verdict,
        action,
        rule_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        PortRange, ProfileConfig, RoutingRule, SystemConstants, TransportProtocol,
    };
    use crate::interceptor::nat::{
        build_forged_ipv4_udp_reply, parse_ipv4_udp_meta, parse_udp_fragment_meta, UdpFragmentKind,
        IPPROTO_UDP,
    };
    use std::net::Ipv4Addr;

    fn controller(kill_switch: bool) -> RouteWardController {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("ProfileConfig");
        profile.enable_logging = false;
        profile.security_policy.kill_switch_enabled = kill_switch;
        profile.default_action = RuleAction::Block;
        profile.rules = vec![
            RoutingRule {
                id: "rule-voip-proxy".to_string(),
                name: "VoIP via proxy".to_string(),
                enabled: true,
                priority: 1,
                process_patterns: vec!["voip.exe".to_string()],
                domain_patterns: vec![],
                ip_cidrs: vec![],
                port_ranges: vec![PortRange {
                    start: 9999,
                    end: 9999,
                }],
                protocol: TransportProtocol::Udp,
                action: RuleAction::Proxy {
                    target_id: "proxy-1".to_string(),
                },
            },
            RoutingRule {
                id: "rule-plain-direct".to_string(),
                name: "Plain direct".to_string(),
                enabled: true,
                priority: 2,
                process_patterns: vec!["plain.exe".to_string()],
                domain_patterns: vec![],
                ip_cidrs: vec![],
                port_ranges: vec![],
                protocol: TransportProtocol::Udp,
                action: RuleAction::Direct,
            },
        ];
        RouteWardController::new(constants, profile, "en")
    }

    fn identity(name: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid: 4321,
            name: name.to_string(),
            executable_path: format!(r"C:\Apps\{name}"),
        }
    }

    /// First IPv4 fragment of a 3000-byte UDP datagram: UDP length exceeds the IP total length.
    fn first_fragment_packet(dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 1480];
        pkt[0] = 0x45;
        let total_len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IPPROTO_UDP;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 25]);
        pkt[16..20].copy_from_slice(&[93, 184, 215, 14]);
        pkt[20..22].copy_from_slice(&50123u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&3000u16.to_be_bytes());
        pkt
    }

    #[test]
    fn first_fragment_of_a_proxied_flow_is_dropped_under_kill_switch_and_released_without_it() {
        let packet = first_fragment_packet(9999);
        // The regular parser rejects it: before the fix the packet was reinjected unevaluated.
        assert!(parse_ipv4_udp_meta(&packet).is_none());
        let frag = parse_udp_fragment_meta(&packet).expect("first fragment");
        assert_eq!(frag.kind, UdpFragmentKind::First);

        let voip = identity("voip.exe");
        let on = decide_first_udp_fragment(&controller(true), Some(&voip), &frag);
        assert_eq!(on.verdict, UdpFragmentVerdict::Drop);
        assert!(matches!(on.action, RuleAction::Proxy { .. }));

        let ctrl_off = controller(false);
        let off = decide_first_udp_fragment(&ctrl_off, Some(&voip), &frag);
        assert_eq!(off.verdict, UdpFragmentVerdict::Reinject);
        assert_eq!(
            ctrl_off.fragmented_udp_drop_count.load(Ordering::SeqCst),
            1,
            "proxied fragments are counted"
        );
    }

    #[test]
    fn first_fragment_of_a_direct_flow_passes_and_block_rules_drop() {
        let frag = parse_udp_fragment_meta(&first_fragment_packet(9999)).expect("first fragment");
        let plain = identity("plain.exe");
        let decision = decide_first_udp_fragment(&controller(true), Some(&plain), &frag);
        assert_eq!(decision.verdict, UdpFragmentVerdict::Reinject);
        assert_eq!(decision.action, RuleAction::Direct);

        // No rule matches this process: the default action (Block) applies.
        let other = identity("other.exe");
        let blocked = decide_first_udp_fragment(&controller(false), Some(&other), &frag);
        assert_eq!(blocked.verdict, UdpFragmentVerdict::Drop);
    }

    #[test]
    fn unattributed_first_fragment_never_leaks_under_kill_switch() {
        let frag = parse_udp_fragment_meta(&first_fragment_packet(9999)).expect("first fragment");
        let decision = decide_first_udp_fragment(&controller(true), None, &frag);
        assert_eq!(decision.action, RuleAction::Block);
        assert_eq!(decision.verdict, UdpFragmentVerdict::Drop);
    }

    #[test]
    fn verdict_is_shared_with_later_fragments_through_the_nat_cache() {
        let ctrl = controller(true);
        let first = parse_udp_fragment_meta(&first_fragment_packet(9999)).expect("first");
        let decision = decide_first_udp_fragment(&ctrl, Some(&identity("voip.exe")), &first);
        ctrl.nat_table
            .record_udp_fragment_verdict(first.key(), decision.verdict);

        let mut later = first_fragment_packet(9999);
        later[6..8].copy_from_slice(&0x00B9u16.to_be_bytes());
        let later_meta = parse_udp_fragment_meta(&later).expect("later fragment");
        assert_eq!(later_meta.kind, UdpFragmentKind::NonFirst);
        assert_eq!(
            ctrl.nat_table
                .lookup_udp_fragment_verdict(&later_meta.key()),
            Some(UdpFragmentVerdict::Drop)
        );

        // An unfragmented datagram of the same flow is not a fragment at all.
        let whole = build_forged_ipv4_udp_reply(
            Ipv4Addr::new(192, 168, 1, 25),
            50123,
            Ipv4Addr::new(93, 184, 215, 14),
            9999,
            b"small",
        )
        .expect("whole datagram");
        assert!(parse_udp_fragment_meta(&whole).is_none());
    }
}
