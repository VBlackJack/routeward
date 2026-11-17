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
        // Only datagrams that are really dropped are counted; with the kill switch off the
        // fragments are released directly and the log says so.
        let outcome = if verdict == UdpFragmentVerdict::Drop {
            let drop_count = ctrl
                .fragmented_udp_drop_count
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            format!("dropped (#{drop_count})")
        } else {
            "released directly (not dropped)".to_string()
        };
        ctrl.push_rate_limited_warn(
            "udp_fragmented_proxy",
            COMPONENT_ENGINE,
            format!(
                "Fragmented UDP datagram from process=\"{}\" -> {}:{} matched proxied rule \"{}\" and was {} (v1 does not reassemble UDP fragments; killSwitchEnabled={}, verdict={:?})",
                process_label, frag.dst_ip, frag.dst_port, rule_name, outcome, kill_switch_enabled, verdict
            ),
        );
    }

    FragmentDecision {
        verdict,
        action,
        rule_name,
    }
}

/// Verdict for a later fragment whose first fragment left no remembered verdict (never seen,
/// expired or evicted). Such a fragment cannot be attributed, so it is dropped when the kill
/// switch is on (it would otherwise leak a datagram that the rules may have blocked) and released
/// unchanged when it is off. A fragment that may belong to another protocol is always released.
pub(super) fn decide_orphan_fragment(
    ctrl: &RouteWardController,
    frag: &UdpFragmentMeta,
) -> UdpFragmentVerdict {
    if !frag.udp_confirmed || !ctrl.profile.read().security_policy.kill_switch_enabled {
        return UdpFragmentVerdict::Reinject;
    }
    let drop_count = ctrl
        .orphan_fragment_drop_count
        .fetch_add(1, Ordering::SeqCst)
        + 1;
    ctrl.push_rate_limited_warn(
        "udp_orphan_fragment",
        COMPONENT_WINDIVERT,
        format!(
            "Dropped orphan UDP fragment {} -> {} (id={}): no verdict remembered for its datagram and killSwitchEnabled=true (total orphan drops #{drop_count})",
            frag.src_ip, frag.dst_ip, frag.fragment_id
        ),
    );
    UdpFragmentVerdict::Drop
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
    use std::net::{Ipv4Addr, Ipv6Addr};

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
            0,
            "released fragments are not counted as drops"
        );
        let ctrl_on = controller(true);
        decide_first_udp_fragment(&ctrl_on, Some(&voip), &frag);
        assert_eq!(
            ctrl_on.fragmented_udp_drop_count.load(Ordering::SeqCst),
            1,
            "dropped proxied fragments are counted"
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

    /// Later IPv4 fragment (offset 185) of the datagram that `first_fragment_packet` starts.
    fn later_ipv4_fragment_packet() -> Vec<u8> {
        let mut pkt = first_fragment_packet(9999);
        pkt[6..8].copy_from_slice(&0x00B9u16.to_be_bytes());
        pkt
    }

    /// Later IPv6 fragment (offset 184) whose fragment header announces `next_header`.
    fn later_ipv6_fragment_packet(next_header: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + 8 + 8];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&16u16.to_be_bytes());
        pkt[6] = 44;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        pkt[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        pkt[40] = next_header;
        pkt[42..44].copy_from_slice(&0x00B9u16.to_be_bytes());
        pkt[44..48].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        pkt
    }

    /// Mirrors the worker: a remembered verdict is replayed, otherwise the orphan rule applies.
    fn verdict_for_later_fragment(
        ctrl: &RouteWardController,
        frag: &UdpFragmentMeta,
    ) -> UdpFragmentVerdict {
        ctrl.nat_table
            .lookup_udp_fragment_verdict(&frag.key())
            .unwrap_or_else(|| decide_orphan_fragment(ctrl, frag))
    }

    #[test]
    fn orphan_ipv4_fragment_is_dropped_under_kill_switch_and_released_without_it() {
        let frag = parse_udp_fragment_meta(&later_ipv4_fragment_packet()).expect("later fragment");
        assert_eq!(frag.kind, UdpFragmentKind::NonFirst);

        let on = controller(true);
        assert_eq!(
            verdict_for_later_fragment(&on, &frag),
            UdpFragmentVerdict::Drop
        );
        assert_eq!(on.orphan_fragment_drop_count(), 1);
        assert_eq!(
            on.fragmented_udp_drop_count(),
            0,
            "orphan drops have their own counter"
        );

        let off = controller(false);
        assert_eq!(
            verdict_for_later_fragment(&off, &frag),
            UdpFragmentVerdict::Reinject
        );
        assert_eq!(off.orphan_fragment_drop_count(), 0);
    }

    #[test]
    fn orphan_ipv6_fragment_is_dropped_under_kill_switch_and_released_without_it() {
        let frag = parse_udp_fragment_meta(&later_ipv6_fragment_packet(IPPROTO_UDP))
            .expect("later fragment");
        assert_eq!(frag.kind, UdpFragmentKind::NonFirst);

        let on = controller(true);
        assert_eq!(
            verdict_for_later_fragment(&on, &frag),
            UdpFragmentVerdict::Drop
        );
        assert_eq!(on.orphan_fragment_drop_count(), 1);

        let off = controller(false);
        assert_eq!(
            verdict_for_later_fragment(&off, &frag),
            UdpFragmentVerdict::Reinject
        );
        assert_eq!(off.orphan_fragment_drop_count(), 0);
    }

    #[test]
    fn fragments_that_may_not_be_udp_are_never_dropped_as_orphans() {
        // Next header 60 (destination options): the protocol behind it is unknown.
        let frag =
            parse_udp_fragment_meta(&later_ipv6_fragment_packet(60)).expect("later fragment");
        assert!(!frag.udp_confirmed);
        let on = controller(true);
        assert_eq!(
            verdict_for_later_fragment(&on, &frag),
            UdpFragmentVerdict::Reinject
        );
        assert_eq!(on.orphan_fragment_drop_count(), 0);

        // A TCP fragment is not classified as UDP at all: the worker releases it untouched.
        assert!(parse_udp_fragment_meta(&later_ipv6_fragment_packet(6)).is_none());
        let mut tcp_v4 = later_ipv4_fragment_packet();
        tcp_v4[9] = 6;
        assert!(parse_udp_fragment_meta(&tcp_v4).is_none());
    }

    #[test]
    fn remembered_verdicts_are_still_replayed_to_later_fragments() {
        let ctrl = controller(true);
        let first = parse_udp_fragment_meta(&first_fragment_packet(9999)).expect("first");
        let later = parse_udp_fragment_meta(&later_ipv4_fragment_packet()).expect("later");

        ctrl.nat_table
            .record_udp_fragment_verdict(first.key(), UdpFragmentVerdict::Reinject);
        assert_eq!(
            verdict_for_later_fragment(&ctrl, &later),
            UdpFragmentVerdict::Reinject,
            "a remembered Reinject beats the kill-switch orphan rule"
        );
        assert_eq!(ctrl.orphan_fragment_drop_count(), 0);

        ctrl.nat_table
            .record_udp_fragment_verdict(first.key(), UdpFragmentVerdict::Drop);
        assert_eq!(
            verdict_for_later_fragment(&ctrl, &later),
            UdpFragmentVerdict::Drop
        );
        assert_eq!(
            ctrl.orphan_fragment_drop_count(),
            0,
            "a replayed Drop is not an orphan drop"
        );
    }
}
