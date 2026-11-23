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

use super::*;
use chrono::Duration;

fn rule(
    id: &str,
    priority: i32,
    action: RuleAction,
    expires_at: Option<DateTime<Utc>>,
) -> RoutingRule {
    RoutingRule {
        id: id.to_string(),
        name: format!("rule {id}"),
        enabled: true,
        priority,
        process_patterns: vec![],
        domain_patterns: vec!["example.com".to_string()],
        ip_cidrs: vec![],
        port_ranges: vec![],
        protocol: TransportProtocol::Any,
        action,
        expires_at,
    }
}

fn request() -> ConnectionRequest {
    ConnectionRequest {
        process_name: "curl.exe".to_string(),
        process_path: None,
        target_host: "example.com".to_string(),
        target_ip: None,
        target_port: 443,
        protocol: TransportProtocol::Tcp,
    }
}

#[test]
fn a_rule_is_expired_exactly_at_its_deadline() {
    let now = Utc::now();
    let r = rule("a", 1, RuleAction::Direct, Some(now));
    assert!(RuleEngine::is_expired(&r, now));
    assert!(!RuleEngine::is_expired(&r, now - Duration::seconds(1)));
    assert!(!RuleEngine::is_expired(
        &rule("b", 1, RuleAction::Direct, None),
        now
    ));
}

#[test]
fn evaluate_at_skips_an_expired_rule_and_falls_through() {
    let now = Utc::now();
    let rules = vec![
        rule(
            "temp",
            1,
            RuleAction::Direct,
            Some(now + Duration::minutes(15)),
        ),
        rule("base", 2, RuleAction::Block, None),
    ];
    let default = RuleAction::Direct;

    let before = RuleEngine::evaluate_at(&request(), &rules, &default, None, now);
    assert_eq!(before.matched_rule_id, "temp");
    assert_eq!(before.action, RuleAction::Direct);

    let after = RuleEngine::evaluate_at(
        &request(),
        &rules,
        &default,
        None,
        now + Duration::minutes(16),
    );
    assert_eq!(after.matched_rule_id, "base");
    assert_eq!(after.action, RuleAction::Block);
}

#[test]
fn evaluate_at_falls_back_to_the_default_when_the_only_rule_expired() {
    let now = Utc::now();
    let rules = vec![rule(
        "temp",
        1,
        RuleAction::Block,
        Some(now - Duration::seconds(1)),
    )];
    let result = RuleEngine::evaluate_at(&request(), &rules, &RuleAction::Direct, None, now);
    assert_eq!(result.matched_rule_id, DEFAULT_FALLBACK_RULE_ID);
    assert_eq!(result.action, RuleAction::Direct);
}

#[test]
fn evaluate_uses_the_wall_clock() {
    let rules = vec![
        rule(
            "gone",
            1,
            RuleAction::Block,
            Some(Utc::now() - Duration::hours(1)),
        ),
        rule(
            "live",
            2,
            RuleAction::Direct,
            Some(Utc::now() + Duration::hours(1)),
        ),
    ];
    let result = RuleEngine::evaluate(&request(), &rules, &RuleAction::Block, None);
    assert_eq!(result.matched_rule_id, "live");
}

#[test]
fn rules_without_a_deadline_never_expire() {
    let rules = vec![rule("forever", 1, RuleAction::Block, None)];
    let far = Utc::now() + Duration::days(36500);
    let result = RuleEngine::evaluate_at(&request(), &rules, &RuleAction::Direct, None, far);
    assert_eq!(result.matched_rule_id, "forever");
}

#[test]
fn the_sweeper_returns_exactly_the_expired_ids() {
    let now = Utc::now();
    let rules = vec![
        rule(
            "past",
            1,
            RuleAction::Direct,
            Some(now - Duration::minutes(1)),
        ),
        rule("edge", 2, RuleAction::Direct, Some(now)),
        rule(
            "future",
            3,
            RuleAction::Direct,
            Some(now + Duration::minutes(1)),
        ),
        rule("none", 4, RuleAction::Direct, None),
    ];
    assert_eq!(
        RuleEngine::expired_rule_ids(&rules, now),
        vec!["past".to_string(), "edge".to_string()]
    );
    assert!(RuleEngine::expired_rule_ids(&[], now).is_empty());
}

#[test]
fn expires_at_is_skipped_when_unset_and_round_trips_when_set() {
    let plain = rule("a", 1, RuleAction::Direct, None);
    let value = serde_json::to_value(&plain).expect("to_value");
    assert!(value.get("expiresAt").is_none());

    let at = Utc::now() + Duration::minutes(15);
    let timed = rule("b", 1, RuleAction::Direct, Some(at));
    let json = serde_json::to_string(&timed).expect("to_string");
    assert!(json.contains("\"expiresAt\""));
    let back: RoutingRule = serde_json::from_str(&json).expect("from_str");
    assert_eq!(back.expires_at, Some(at));

    let mut legacy = serde_json::to_value(&plain).expect("to_value");
    legacy.as_object_mut().expect("object").remove("expiresAt");
    let back: RoutingRule = serde_json::from_value(legacy).expect("legacy rule");
    assert_eq!(back.expires_at, None);
}
