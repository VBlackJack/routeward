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

use crate::config::{RoutingRule, RuleAction, TransportProtocol};
use crate::dns::FakeIpEngine;
use crate::process::ProcessResolver;
use ipnet::IpNet;
use parking_lot::RwLock;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

const DEFAULT_FALLBACK_RULE_ID: &str = "default-policy";
const DEFAULT_FALLBACK_RULE_NAME: &str = "Default Profile Policy";
const REGEX_PREFIX: &str = "regex:";
/// Maximum number of compiled patterns kept per cache (user regexes and wildcard-derived
/// regexes are cached separately). When full, the oldest entry is evicted (FIFO).
const MAX_CACHED_REGEX_PATTERNS: usize = 2048;

/// Bounded FIFO cache of compiled patterns. Invalid patterns are cached as `None`.
struct PatternCache {
    map: HashMap<String, Option<Regex>>,
    order: VecDeque<String>,
}

impl PatternCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn insert(&mut self, key: &str, value: Option<Regex>) {
        if self.map.contains_key(key) {
            return;
        }
        while self.map.len() >= MAX_CACHED_REGEX_PATTERNS {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.map.remove(&oldest);
                }
                None => break,
            }
        }
        self.order.push_back(key.to_string());
        self.map.insert(key.to_string(), value);
    }
}

/// User-supplied `regex:` patterns, keyed by the raw (case-preserved) regex body.
static USER_REGEX_CACHE: OnceLock<RwLock<PatternCache>> = OnceLock::new();
/// Wildcard patterns translated to anchored regexes, keyed by the wildcard text.
/// Kept separate from `USER_REGEX_CACHE` so keys can never collide.
static WILDCARD_CACHE: OnceLock<RwLock<PatternCache>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionRequest {
    pub process_name: String,
    pub process_path: Option<String>,
    pub target_host: String,
    pub target_ip: Option<String>,
    pub target_port: u16,
    pub protocol: TransportProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleEvaluationResult {
    pub matched_rule_id: String,
    pub matched_rule_name: String,
    pub action: RuleAction,
    pub effective_domain: Option<String>,
    pub resolved_from_fake_ip: bool,
}

pub struct RuleEngine;

impl RuleEngine {
    pub fn evaluate(
        request: &ConnectionRequest,
        rules: &[RoutingRule],
        default_action: &RuleAction,
        fake_ip_engine: Option<&FakeIpEngine>,
    ) -> RuleEvaluationResult {
        let mut effective_domain: Option<String> = None;
        let mut resolved_from_fake_ip = false;

        let parsed_target_ip: Option<IpAddr> = request
            .target_ip
            .as_deref()
            .and_then(|s| IpAddr::from_str(s).ok())
            .or_else(|| IpAddr::from_str(&request.target_host).ok());

        if let Some(IpAddr::V4(v4)) = parsed_target_ip {
            if let Some(dns) = fake_ip_engine {
                if let Some(domain) = dns.resolve_fake_ip(&v4) {
                    effective_domain = Some(domain);
                    resolved_from_fake_ip = true;
                }
            }
        }

        if effective_domain.is_none() && IpAddr::from_str(&request.target_host).is_err() {
            effective_domain = Some(request.target_host.to_lowercase());
        }

        // Rules are normally stored already ordered (see `sort_rules`); only fall back to a
        // per-call stable sort when the caller passes an unordered slice.
        let ordered: Cow<'_, [RoutingRule]> = if Self::is_priority_ordered(rules) {
            Cow::Borrowed(rules)
        } else {
            let mut copy = rules.to_vec();
            Self::sort_rules(&mut copy);
            Cow::Owned(copy)
        };

        for rule in ordered.iter().filter(|r| r.enabled) {
            if Self::matches_rule(
                rule,
                request,
                effective_domain.as_deref(),
                parsed_target_ip.as_ref(),
            ) {
                return RuleEvaluationResult {
                    matched_rule_id: rule.id.clone(),
                    matched_rule_name: rule.name.clone(),
                    action: rule.action.clone(),
                    effective_domain,
                    resolved_from_fake_ip,
                };
            }
        }

        RuleEvaluationResult {
            matched_rule_id: DEFAULT_FALLBACK_RULE_ID.to_string(),
            matched_rule_name: DEFAULT_FALLBACK_RULE_NAME.to_string(),
            action: default_action.clone(),
            effective_domain,
            resolved_from_fake_ip,
        }
    }

    /// Sorts rules by priority (stable: equal priorities keep their declared order).
    /// Call once when a profile is loaded or replaced so `evaluate` never has to sort.
    pub fn sort_rules(rules: &mut [RoutingRule]) {
        rules.sort_by_key(|r| r.priority);
    }

    /// True when rules are already in evaluation order (non-decreasing priority).
    pub fn is_priority_ordered(rules: &[RoutingRule]) -> bool {
        rules.windows(2).all(|w| w[0].priority <= w[1].priority)
    }

    /// Strips a leading `regex:` marker, ASCII case-insensitively, preserving the body's case.
    pub fn strip_regex_prefix(raw: &str) -> Option<&str> {
        let head = raw.get(..REGEX_PREFIX.len())?;
        if head.eq_ignore_ascii_case(REGEX_PREFIX) {
            Some(&raw[REGEX_PREFIX.len()..])
        } else {
            None
        }
    }

    fn matches_rule(
        rule: &RoutingRule,
        req: &ConnectionRequest,
        effective_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
    ) -> bool {
        if rule.protocol != TransportProtocol::Any && rule.protocol != req.protocol {
            return false;
        }

        if !rule.port_ranges.is_empty()
            && !rule.port_ranges.iter().any(|r| r.contains(req.target_port))
        {
            return false;
        }

        if !rule.process_patterns.is_empty() {
            let basename = ProcessResolver::extract_basename(&req.process_name).to_lowercase();
            let full_path = req
                .process_path
                .as_deref()
                .unwrap_or(&req.process_name)
                .to_lowercase();

            if !Self::matches_process_patterns_both(&rule.process_patterns, &basename, &full_path) {
                return false;
            }
        }

        let has_domain_criteria = rule.domain_patterns.iter().any(|p| !p.trim().is_empty());
        let has_ip_criteria = rule.ip_cidrs.iter().any(|p| !p.trim().is_empty());

        if has_domain_criteria || has_ip_criteria {
            let dom_norm = effective_domain.map(|d| d.trim_end_matches('.').to_lowercase());

            // 1. Check explicit exclusions first: any matching '!' pattern vetoes the rule.
            if let Some(ref dom) = dom_norm {
                if Self::matches_any_negated(&rule.domain_patterns, |pat| {
                    Self::domain_match(pat, dom)
                }) {
                    return false;
                }
            }
            if let Some(ip) = target_ip {
                if Self::matches_any_negated(&rule.ip_cidrs, |pat| Self::ip_match(pat, ip)) {
                    return false;
                }
            }

            // 2. Check positive patterns (if any exist across domain/IP criteria).
            let has_pos_domain = Self::has_positive_patterns(&rule.domain_patterns);
            let has_pos_ip = Self::has_positive_patterns(&rule.ip_cidrs);

            if has_pos_domain || has_pos_ip {
                let mut destination_matched = false;
                if has_pos_domain {
                    if let Some(ref dom) = dom_norm {
                        if Self::matches_any_positive(&rule.domain_patterns, |pat| {
                            Self::domain_match(pat, dom)
                        }) {
                            destination_matched = true;
                        }
                    }
                }
                if !destination_matched && has_pos_ip {
                    if let Some(ip) = target_ip {
                        if Self::matches_any_positive(&rule.ip_cidrs, |pat| Self::ip_match(pat, ip))
                        {
                            destination_matched = true;
                        }
                    }
                }
                if !destination_matched {
                    return false;
                }
            }
        }

        true
    }

    pub fn matches_process_patterns(patterns: &[String], candidate_process: &str) -> bool {
        let basename = ProcessResolver::extract_basename(candidate_process).to_lowercase();
        let full_path = candidate_process.to_lowercase();
        Self::matches_process_patterns_both(patterns, &basename, &full_path)
    }

    fn matches_process_patterns_both(patterns: &[String], basename: &str, full_path: &str) -> bool {
        Self::evaluate_pattern_list(patterns, |pat| {
            let low = pat.to_lowercase();
            Self::wildcard_match(&low, basename) || Self::wildcard_match(&low, full_path)
        })
        .unwrap_or(true)
    }

    pub fn strip_negation(raw: &str) -> Option<(bool, &str)> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Some(rest) = trimmed.strip_prefix('!') {
            let inner = rest.trim();
            if inner.is_empty() {
                None
            } else {
                Some((true, inner))
            }
        } else {
            Some((false, trimmed))
        }
    }

    fn has_positive_patterns(patterns: &[String]) -> bool {
        patterns
            .iter()
            .filter_map(|p| Self::strip_negation(p))
            .any(|(is_neg, _)| !is_neg)
    }

    fn matches_any_negated<F>(patterns: &[String], mut matcher: F) -> bool
    where
        F: FnMut(&str) -> bool,
    {
        patterns
            .iter()
            .filter_map(|p| Self::strip_negation(p))
            .filter(|(is_neg, _)| *is_neg)
            .any(|(_, pat)| matcher(pat))
    }

    fn matches_any_positive<F>(patterns: &[String], mut matcher: F) -> bool
    where
        F: FnMut(&str) -> bool,
    {
        patterns
            .iter()
            .filter_map(|p| Self::strip_negation(p))
            .filter(|(is_neg, _)| !*is_neg)
            .any(|(_, pat)| matcher(pat))
    }

    fn evaluate_pattern_list<F>(patterns: &[String], mut matcher: F) -> Option<bool>
    where
        F: FnMut(&str) -> bool,
    {
        let mut any_valid = false;
        let mut has_positive = false;
        let mut matched_positive = false;

        for raw in patterns {
            let Some((is_neg, pat)) = Self::strip_negation(raw) else {
                continue;
            };
            any_valid = true;
            if is_neg {
                if matcher(pat) {
                    return Some(false);
                }
            } else {
                has_positive = true;
                if !matched_positive && matcher(pat) {
                    matched_positive = true;
                }
            }
        }

        if !any_valid {
            None
        } else if has_positive {
            Some(matched_positive)
        } else {
            // Negative-only list and none of the exclusions matched.
            Some(true)
        }
    }

    fn ip_match(cidr_or_ip: &str, ip: &IpAddr) -> bool {
        let trimmed = cidr_or_ip.trim();
        IpNet::from_str(trimmed)
            .map(|net| net.contains(ip))
            .unwrap_or_else(|_| {
                IpAddr::from_str(trimmed)
                    .map(|exact| &exact == ip)
                    .unwrap_or(false)
            })
    }

    fn cached_compile<F>(
        cache: &'static OnceLock<RwLock<PatternCache>>,
        key: &str,
        compile: F,
    ) -> Option<Regex>
    where
        F: FnOnce() -> Option<Regex>,
    {
        let cache = cache.get_or_init(|| RwLock::new(PatternCache::new()));
        if let Some(cached) = cache.read().map.get(key) {
            return cached.clone();
        }
        let compiled = compile();
        cache.write().insert(key, compiled.clone());
        compiled
    }

    /// Compiles a user regex case-insensitively (flag set on the builder, never as a textual
    /// `(?i)` prefix, because the PAC generator drops patterns starting with `(?`).
    fn get_or_compile_user_regex(body: &str) -> Option<Regex> {
        Self::cached_compile(&USER_REGEX_CACHE, body, || {
            RegexBuilder::new(body).case_insensitive(true).build().ok()
        })
    }

    fn get_or_compile_wildcard(pattern: &str) -> Option<Regex> {
        Self::cached_compile(&WILDCARD_CACHE, pattern, || {
            let escaped = regex::escape(pattern)
                .replace("\\*", ".*")
                .replace("\\?", ".");
            Regex::new(&format!("^{escaped}$")).ok()
        })
    }

    pub fn domain_match(pattern: &str, domain: &str) -> bool {
        let trimmed = pattern.trim();
        if let Some(body) = Self::strip_regex_prefix(trimmed) {
            return Self::get_or_compile_user_regex(body)
                .map(|re| re.is_match(domain))
                .unwrap_or(false);
        }
        let pat: Cow<'_, str> =
            if trimmed.bytes().any(|b| b.is_ascii_uppercase()) || !trimmed.is_ascii() {
                Cow::Owned(trimmed.to_lowercase())
            } else {
                Cow::Borrowed(trimmed)
            };
        if let Some(suffix) = pat.strip_prefix("*.") {
            if domain == suffix
                || (domain.len() > suffix.len()
                    && domain.ends_with(suffix)
                    && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
            {
                return true;
            }
        }
        Self::wildcard_match(&pat, domain)
    }

    pub fn wildcard_match(pattern: &str, candidate: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        Self::get_or_compile_wildcard(pattern)
            .map(|re| re.is_match(candidate))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProfileConfig, SystemConstants};

    #[test]
    fn matches_process_and_fake_ip_domain() {
        let constants = SystemConstants::load_embedded().unwrap();
        let mut profile = ProfileConfig::load_embedded_default().unwrap();
        assert!(profile.proxies.is_empty());
        assert!(profile.chains.is_empty());
        profile.rules.push(crate::config::RoutingRule {
            id: "test-browsers-proxy".to_string(),
            name: "Web Browsers via Test Proxy".to_string(),
            enabled: true,
            priority: 20,
            process_patterns: vec!["firefox.exe".to_string()],
            domain_patterns: vec![],
            ip_cidrs: vec![],
            port_ranges: vec![crate::config::PortRange {
                start: 443,
                end: 443,
            }],
            protocol: TransportProtocol::Tcp,
            action: RuleAction::Proxy {
                target_id: "test-proxy".to_string(),
            },
        });
        let dns = FakeIpEngine::new(&profile.dns_config, &constants.dns);

        let fake_ip = dns.allocate_or_get("app.telemetry.example.com").unwrap();

        // 1. Telemetry domain should be blocked even when connecting via Fake-IP
        let req_telemetry = ConnectionRequest {
            process_name: "any_app.exe".to_string(),
            process_path: None,
            target_host: fake_ip.to_string(),
            target_ip: Some(fake_ip.to_string()),
            target_port: 443,
            protocol: TransportProtocol::Tcp,
        };

        let eval = RuleEngine::evaluate(
            &req_telemetry,
            &profile.rules,
            &profile.default_action,
            Some(&dns),
        );
        assert_eq!(eval.action, RuleAction::Block);
        assert!(eval.resolved_from_fake_ip);

        // 2. Firefox on port 443 should route via test-proxy
        let req_browser = ConnectionRequest {
            process_name: "C:\\Program Files\\Mozilla Firefox\\firefox.exe".to_string(),
            process_path: None,
            target_host: "github.com".to_string(),
            target_ip: None,
            target_port: 443,
            protocol: TransportProtocol::Tcp,
        };
        let eval_browser = RuleEngine::evaluate(
            &req_browser,
            &profile.rules,
            &profile.default_action,
            Some(&dns),
        );
        assert_eq!(
            eval_browser.action,
            RuleAction::Proxy {
                target_id: "test-proxy".to_string()
            }
        );
    }

    #[test]
    fn caches_regex_patterns_and_handles_invalid_regex_safely() {
        assert!(RuleEngine::domain_match(
            "regex:^api-[0-9]+\\.example\\.com$",
            "api-42.example.com"
        ));
        assert!(!RuleEngine::domain_match(
            "regex:^api-[0-9]+\\.example\\.com$",
            "web.example.com"
        ));
        // Invalid regex must safely return false instead of panicking
        assert!(!RuleEngine::domain_match("regex:[unclosed", "example.com"));
    }

    #[test]
    fn supports_negated_domain_process_and_ip_patterns() {
        let rules = vec![
            crate::config::RoutingRule {
                id: "edge-except-local".to_string(),
                name: "Edge except internal".to_string(),
                enabled: true,
                priority: 10,
                process_patterns: vec!["msedge.exe".to_string(), "!legacy.exe".to_string()],
                domain_patterns: vec![
                    "*.corp.example".to_string(),
                    "!intranet.corp.example".to_string(),
                    "!regex:^dev-[0-9]+\\.corp\\.example$".to_string(),
                ],
                ip_cidrs: vec!["!10.0.0.0/8".to_string()],
                port_ranges: vec![],
                protocol: TransportProtocol::Tcp,
                action: RuleAction::Proxy {
                    target_id: "corp-proxy".to_string(),
                },
            },
            crate::config::RoutingRule {
                id: "all-except-system".to_string(),
                name: "All non-excluded processes".to_string(),
                enabled: true,
                priority: 20,
                process_patterns: vec!["!svchost.exe".to_string()],
                domain_patterns: vec!["!*.local".to_string()],
                ip_cidrs: vec![],
                port_ranges: vec![],
                protocol: TransportProtocol::Tcp,
                action: RuleAction::Proxy {
                    target_id: "default-proxy".to_string(),
                },
            },
        ];

        // Edge -> app.corp.example -> matches rule 1
        let ok_req = ConnectionRequest {
            process_name: "msedge.exe".to_string(),
            process_path: None,
            target_host: "app.corp.example".to_string(),
            target_ip: Some("203.0.113.5".to_string()),
            target_port: 443,
            protocol: TransportProtocol::Tcp,
        };
        let eval_ok = RuleEngine::evaluate(&ok_req, &rules, &RuleAction::Direct, None);
        assert_eq!(
            eval_ok.action,
            RuleAction::Proxy {
                target_id: "corp-proxy".to_string()
            }
        );

        // Edge -> intranet.corp.example -> excluded from rule 1, falls through to rule 2
        let excluded_dom = ConnectionRequest {
            target_host: "intranet.corp.example".to_string(),
            ..ok_req.clone()
        };
        let eval_excluded = RuleEngine::evaluate(&excluded_dom, &rules, &RuleAction::Direct, None);
        assert_eq!(
            eval_excluded.action,
            RuleAction::Proxy {
                target_id: "default-proxy".to_string()
            }
        );

        // Edge -> dev-7.corp.example -> excluded by !regex:
        let excluded_re = ConnectionRequest {
            target_host: "dev-7.corp.example".to_string(),
            ..ok_req.clone()
        };
        let eval_re = RuleEngine::evaluate(&excluded_re, &rules, &RuleAction::Direct, None);
        assert_eq!(
            eval_re.action,
            RuleAction::Proxy {
                target_id: "default-proxy".to_string()
            }
        );

        // Edge -> app.corp.example with private 10.1.2.3 IP -> excluded from rule 1 by !10.0.0.0/8
        let excluded_ip = ConnectionRequest {
            target_ip: Some("10.1.2.3".to_string()),
            ..ok_req.clone()
        };
        let eval_ip = RuleEngine::evaluate(&excluded_ip, &rules, &RuleAction::Direct, None);
        assert_eq!(
            eval_ip.action,
            RuleAction::Proxy {
                target_id: "default-proxy".to_string()
            }
        );

        // Negative-only process & domain exclusions on rule 2: svchost.exe falls back to Direct
        let svchost_req = ConnectionRequest {
            process_name: "svchost.exe".to_string(),
            process_path: None,
            target_host: "api.example.org".to_string(),
            target_ip: None,
            target_port: 443,
            protocol: TransportProtocol::Tcp,
        };
        let eval_svc = RuleEngine::evaluate(&svchost_req, &rules, &RuleAction::Direct, None);
        assert_eq!(eval_svc.action, RuleAction::Direct);

        // *.local excluded on rule 2 -> falls back to Direct
        let local_req = ConnectionRequest {
            process_name: "curl.exe".to_string(),
            process_path: None,
            target_host: "printer.local".to_string(),
            target_ip: None,
            target_port: 80,
            protocol: TransportProtocol::Tcp,
        };
        let eval_local = RuleEngine::evaluate(&local_req, &rules, &RuleAction::Direct, None);
        assert_eq!(eval_local.action, RuleAction::Direct);
    }

    #[test]
    fn matches_msedge_with_meshcore_domain_patterns() {
        let rules = vec![crate::config::RoutingRule {
            id: "edge-meshcore".to_string(),
            name: "Edge on meshcore.net".to_string(),
            enabled: true,
            priority: 15,
            process_patterns: vec!["msedge.exe".to_string()],
            domain_patterns: vec!["meshcore.net".to_string(), "*.meshcore.net".to_string()],
            ip_cidrs: vec![],
            port_ranges: vec![],
            protocol: TransportProtocol::Any,
            action: RuleAction::Proxy {
                target_id: "ext-proxy".to_string(),
            },
        }];

        for host in ["meshcore.net", "map.meshcore.net", "api.eu.meshcore.net"] {
            let req = ConnectionRequest {
                process_name: "msedge.exe".to_string(),
                process_path: None,
                target_host: host.to_string(),
                target_ip: None,
                target_port: 443,
                protocol: TransportProtocol::Tcp,
            };
            let eval = RuleEngine::evaluate(&req, &rules, &RuleAction::Direct, None);
            assert_eq!(
                eval.action,
                RuleAction::Proxy {
                    target_id: "ext-proxy".to_string(),
                },
                "expected {host} via msedge.exe to match ext-proxy"
            );
        }

        let unrelated = ConnectionRequest {
            process_name: "msedge.exe".to_string(),
            process_path: None,
            target_host: "youtube.com".to_string(),
            target_ip: None,
            target_port: 443,
            protocol: TransportProtocol::Tcp,
        };
        assert_eq!(
            RuleEngine::evaluate(&unrelated, &rules, &RuleAction::Direct, None).action,
            RuleAction::Direct
        );

        let wrong_browser = ConnectionRequest {
            process_name: "firefox.exe".to_string(),
            process_path: None,
            target_host: "meshcore.net".to_string(),
            target_ip: None,
            target_port: 443,
            protocol: TransportProtocol::Tcp,
        };
        assert_eq!(
            RuleEngine::evaluate(&wrong_browser, &rules, &RuleAction::Direct, None).action,
            RuleAction::Direct
        );
    }

    #[test]
    fn regex_prefix_keeps_body_case_and_is_case_insensitive() {
        assert!(RuleEngine::domain_match(r"regex:^\D+\.corp$", "abc.corp"));
        assert!(!RuleEngine::domain_match(r"regex:^\D+\.corp$", "123.corp"));
        assert!(RuleEngine::domain_match(r"REGEX:^\D+\.corp$", "abc.corp"));
        assert!(!RuleEngine::domain_match(r"Regex:^\D+\.corp$", "123.corp"));
        // Matching stays case-insensitive without a textual (?i) prefix.
        assert!(RuleEngine::domain_match(r"regex:^API.corp$", "api.corp"));
        assert_eq!(RuleEngine::strip_regex_prefix("ReGeX:abc"), Some("abc"));
        assert_eq!(RuleEngine::strip_regex_prefix("re"), None);
    }

    #[test]
    fn wildcard_and_regex_caches_do_not_collide() {
        // A wildcard pattern and a regex body with identical text must not share a cache entry.
        assert!(RuleEngine::wildcard_match("a?c", "abc"));
        assert!(!RuleEngine::domain_match("regex:^a?c$", "abc"));
        assert!(RuleEngine::domain_match("regex:^a?c$", "ac"));
    }

    fn simple_rule(id: &str, priority: i32, enabled: bool) -> crate::config::RoutingRule {
        crate::config::RoutingRule {
            id: id.to_string(),
            name: id.to_string(),
            enabled,
            priority,
            process_patterns: vec![],
            domain_patterns: vec![],
            ip_cidrs: vec![],
            port_ranges: vec![],
            protocol: TransportProtocol::Any,
            action: RuleAction::Direct,
        }
    }

    #[test]
    fn rule_order_is_stable_for_equal_priorities() {
        let rules = vec![
            simple_rule("c", 30, true),
            simple_rule("a1", 10, true),
            simple_rule("a2", 10, true),
            simple_rule("off", 5, false),
        ];
        let req = ConnectionRequest {
            process_name: "x.exe".to_string(),
            process_path: None,
            target_host: "example.com".to_string(),
            target_ip: None,
            target_port: 80,
            protocol: TransportProtocol::Tcp,
        };
        let unsorted = RuleEngine::evaluate(&req, &rules, &RuleAction::Direct, None);
        assert_eq!(unsorted.matched_rule_id, "a1");

        let mut sorted = rules.clone();
        RuleEngine::sort_rules(&mut sorted);
        assert!(RuleEngine::is_priority_ordered(&sorted));
        let ids: Vec<&str> = sorted.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["off", "a1", "a2", "c"]);
        let presorted = RuleEngine::evaluate(&req, &sorted, &RuleAction::Direct, None);
        assert_eq!(presorted.matched_rule_id, "a1");
    }

    #[test]
    fn pattern_cache_evicts_oldest_instead_of_clearing() {
        let mut cache = PatternCache::new();
        for i in 0..(MAX_CACHED_REGEX_PATTERNS + 5) {
            cache.insert(&format!("k{i}"), None);
        }
        assert_eq!(cache.map.len(), MAX_CACHED_REGEX_PATTERNS);
        assert!(!cache.map.contains_key("k0"));
        assert!(cache
            .map
            .contains_key(&format!("k{}", MAX_CACHED_REGEX_PATTERNS + 4)));
    }

    const TABLE_PROXY_ID: &str = "table-proxy";

    fn table_rule(id: &str, priority: i32) -> crate::config::RoutingRule {
        crate::config::RoutingRule {
            id: id.to_string(),
            name: format!("rule {id}"),
            enabled: true,
            priority,
            process_patterns: vec![],
            domain_patterns: vec![],
            ip_cidrs: vec![],
            port_ranges: vec![],
            protocol: TransportProtocol::Any,
            action: RuleAction::Proxy {
                target_id: TABLE_PROXY_ID.to_string(),
            },
        }
    }

    fn table_request(process: &str, host: &str, ip: Option<&str>, port: u16) -> ConnectionRequest {
        ConnectionRequest {
            process_name: process.to_string(),
            process_path: None,
            target_host: host.to_string(),
            target_ip: ip.map(str::to_string),
            target_port: port,
            protocol: TransportProtocol::Tcp,
        }
    }

    fn matched_id(rules: &[crate::config::RoutingRule], req: &ConnectionRequest) -> String {
        RuleEngine::evaluate(req, rules, &RuleAction::Direct, None).matched_rule_id
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn process_pattern_table() {
        let cases = [
            (vec!["firefox.exe"], "firefox.exe", true),
            (vec!["firefox.exe"], "FIREFOX.EXE", true),
            (vec!["FireFox.exe"], "firefox.exe", true),
            (vec!["firefox.exe"], "C:\\Apps\\Mozilla\\firefox.exe", true),
            (vec!["firefox.exe"], "/usr/bin/firefox.exe", true),
            (vec!["fire*.exe"], "firefox.exe", true),
            (vec!["*.exe"], "notepad.exe", true),
            (vec!["chrome?.exe"], "chrome1.exe", true),
            (vec!["chrome?.exe"], "chrome.exe", false),
            (vec!["firefox.exe"], "firefox.exe.bak", false),
            (vec!["firefox.exe"], "chrome.exe", false),
            (vec!["firefox.exe", "chrome.exe"], "chrome.exe", true),
            (vec!["!chrome.exe"], "chrome.exe", false),
            (vec!["!chrome.exe"], "firefox.exe", true),
            (vec!["*.exe", "!chrome.exe"], "chrome.exe", false),
            (vec!["*.exe", "!chrome.exe"], "firefox.exe", true),
            (vec!["*"], "anything", true),
        ];
        for (patterns, candidate, expected) in cases {
            let patterns = strings(&patterns);
            assert_eq!(
                RuleEngine::matches_process_patterns(&patterns, candidate),
                expected,
                "{patterns:?} vs {candidate}"
            );
        }
    }

    #[test]
    fn process_pattern_can_match_the_full_path() {
        let mut rule = table_rule("by-path", 10);
        rule.process_patterns = strings(&["c:\\games\\*"]);
        let mut req = table_request("game.exe", "example.com", None, 443);
        assert_ne!(matched_id(&[rule.clone()], &req), "by-path");
        req.process_path = Some("C:\\Games\\Quake\\game.exe".to_string());
        assert_eq!(matched_id(&[rule], &req), "by-path");
    }

    #[test]
    fn domain_pattern_table() {
        let cases = [
            ("example.com", "example.com", true),
            ("EXAMPLE.com", "example.com", true),
            ("example.com", "www.example.com", false),
            ("*.example.com", "www.example.com", true),
            ("*.example.com", "a.b.example.com", true),
            ("*.example.com", "example.com", true),
            ("*.example.com", "badexample.com", false),
            ("*.example.com", "example.com.evil.org", false),
            ("api-*.example.com", "api-42.example.com", true),
            ("api-*.example.com", "web.example.com", false),
            ("a?.example.com", "ab.example.com", true),
            ("a?.example.com", "abc.example.com", false),
            ("*", "anything.example", true),
            (
                "regex:^api-[0-9]+\\.example\\.com$",
                "api-7.example.com",
                true,
            ),
            (
                "regex:^api-[0-9]+\\.example\\.com$",
                "api-x.example.com",
                false,
            ),
            (
                "REGEX:^API-[0-9]+\\.EXAMPLE\\.COM$",
                "api-7.example.com",
                true,
            ),
            ("Regex:^abc$", "ABC", true),
            ("regex:", "example.com", true),
            ("regex:(", "example.com", false),
            ("regex:^$", "example.com", false),
        ];
        for (pattern, domain, expected) in cases {
            assert_eq!(
                RuleEngine::domain_match(pattern, domain),
                expected,
                "{pattern} vs {domain}"
            );
        }
    }

    #[test]
    fn regex_prefix_table() {
        let cases = [
            ("regex:abc", Some("abc")),
            ("REGEX:Abc", Some("Abc")),
            ("Regex:", Some("")),
            ("regex", None),
            ("regexabc", None),
            ("rege", None),
            ("", None),
            ("*.regex:x", None),
        ];
        for (raw, expected) in cases {
            assert_eq!(RuleEngine::strip_regex_prefix(raw), expected, "{raw}");
        }
    }

    #[test]
    fn negation_table() {
        let cases = [
            ("!a", Some((true, "a"))),
            ("  ! a  ", Some((true, "a"))),
            ("a", Some((false, "a"))),
            ("  a  ", Some((false, "a"))),
            ("!", None),
            ("!   ", None),
            ("", None),
            ("   ", None),
            ("!!a", Some((true, "!a"))),
        ];
        for (raw, expected) in cases {
            assert_eq!(RuleEngine::strip_negation(raw), expected, "{raw:?}");
        }
    }

    #[test]
    fn cidr_table_v4_and_v6() {
        let cases = [
            ("10.0.0.0/8", "10.1.2.3", true),
            ("10.0.0.0/8", "11.0.0.1", false),
            ("192.168.1.0/24", "192.168.1.255", true),
            ("192.168.1.0/24", "192.168.2.0", false),
            ("203.0.113.7", "203.0.113.7", true),
            ("203.0.113.7", "203.0.113.8", false),
            ("203.0.113.7/32", "203.0.113.7", true),
            ("0.0.0.0/0", "8.8.8.8", true),
            ("2001:db8::/32", "2001:db8:1::1", true),
            ("2001:db8::/32", "2001:db9::1", false),
            ("::1", "::1", true),
            ("::1/128", "::1", true),
            ("::/0", "2606:4700::1111", true),
            ("10.0.0.0/8", "2001:db8::1", false),
            ("2001:db8::/32", "10.0.0.1", false),
            ("not-a-cidr", "10.0.0.1", false),
            ("10.0.0.0/33", "10.0.0.1", false),
        ];
        for (cidr, ip, expected) in cases {
            let mut rule = table_rule("cidr", 10);
            rule.ip_cidrs = strings(&[cidr]);
            let req = table_request("app.exe", ip, Some(ip), 443);
            let hit = matched_id(&[rule], &req) == "cidr";
            assert_eq!(hit, expected, "{cidr} vs {ip}");
        }
    }

    #[test]
    fn cidr_negation_vetoes_and_negative_only_matches_the_rest() {
        let mut rule = table_rule("not-lan", 10);
        rule.ip_cidrs = strings(&["!10.0.0.0/8", "!2001:db8::/32"]);
        let rules = [rule];
        let cases = [
            ("10.2.3.4", false),
            ("2001:db8::5", false),
            ("8.8.8.8", true),
            ("2606:4700::1", true),
        ];
        for (ip, expected) in cases {
            let req = table_request("app.exe", ip, Some(ip), 443);
            assert_eq!(matched_id(&rules, &req) == "not-lan", expected, "{ip}");
        }
    }

    #[test]
    fn domain_or_cidr_positive_criteria_are_alternatives() {
        let mut rule = table_rule("either", 10);
        rule.domain_patterns = strings(&["*.corp.example"]);
        rule.ip_cidrs = strings(&["10.0.0.0/8"]);
        let rules = [rule];
        let cases = [
            ("app.corp.example", Some("203.0.113.9"), true),
            ("other.example", Some("10.9.9.9"), true),
            ("other.example", Some("203.0.113.9"), false),
        ];
        for (host, ip, expected) in cases {
            let req = table_request("app.exe", host, ip, 443);
            assert_eq!(
                matched_id(&rules, &req) == "either",
                expected,
                "{host} {ip:?}"
            );
        }
    }

    #[test]
    fn ip_literal_host_is_matched_by_cidr_without_a_domain() {
        let mut rule = table_rule("lan", 10);
        rule.ip_cidrs = strings(&["192.168.0.0/16"]);
        let req = table_request("app.exe", "192.168.4.5", None, 80);
        let eval = RuleEngine::evaluate(&req, &[rule], &RuleAction::Direct, None);
        assert_eq!(eval.matched_rule_id, "lan");
        assert_eq!(eval.effective_domain, None);
    }

    #[test]
    fn port_range_table() {
        let ranges = |pairs: &[(u16, u16)]| {
            pairs
                .iter()
                .map(|&(start, end)| crate::config::PortRange { start, end })
                .collect::<Vec<_>>()
        };
        let cases = [
            (ranges(&[(443, 443)]), 443, true),
            (ranges(&[(443, 443)]), 80, false),
            (ranges(&[(8000, 8999)]), 8000, true),
            (ranges(&[(8000, 8999)]), 8999, true),
            (ranges(&[(8000, 8999)]), 9000, false),
            (ranges(&[(8000, 8999)]), 7999, false),
            (ranges(&[(80, 80), (443, 443)]), 443, true),
            (ranges(&[(80, 80), (443, 443)]), 8080, false),
            (ranges(&[(1, 65535)]), 65535, true),
            (ranges(&[]), 12345, true),
        ];
        for (port_ranges, port, expected) in cases {
            let mut rule = table_rule("ports", 10);
            rule.port_ranges = port_ranges.clone();
            let req = table_request("app.exe", "example.com", None, port);
            assert_eq!(
                matched_id(&[rule], &req) == "ports",
                expected,
                "{port_ranges:?} vs {port}"
            );
        }
    }

    #[test]
    fn protocol_table() {
        let cases = [
            (TransportProtocol::Tcp, TransportProtocol::Tcp, true),
            (TransportProtocol::Tcp, TransportProtocol::Udp, false),
            (TransportProtocol::Udp, TransportProtocol::Udp, true),
            (TransportProtocol::Udp, TransportProtocol::Tcp, false),
            (TransportProtocol::Any, TransportProtocol::Tcp, true),
            (TransportProtocol::Any, TransportProtocol::Udp, true),
        ];
        for (rule_proto, req_proto, expected) in cases {
            let mut rule = table_rule("proto", 10);
            rule.protocol = rule_proto;
            let mut req = table_request("app.exe", "example.com", None, 443);
            req.protocol = req_proto;
            assert_eq!(
                matched_id(&[rule], &req) == "proto",
                expected,
                "{rule_proto:?} vs {req_proto:?}"
            );
        }
    }

    #[test]
    fn lowest_priority_value_wins_regardless_of_slice_order() {
        let rules = vec![
            table_rule("late", 30),
            table_rule("early", 5),
            table_rule("middle", 10),
        ];
        let req = table_request("app.exe", "example.com", None, 443);
        assert_eq!(matched_id(&rules, &req), "early");

        let mut sorted = rules.clone();
        RuleEngine::sort_rules(&mut sorted);
        assert!(RuleEngine::is_priority_ordered(&sorted));
        assert!(!RuleEngine::is_priority_ordered(&rules));
        assert_eq!(matched_id(&sorted, &req), "early");
    }

    #[test]
    fn negative_priorities_sort_before_zero() {
        let rules = vec![table_rule("zero", 0), table_rule("negative", -10)];
        let req = table_request("app.exe", "example.com", None, 443);
        assert_eq!(matched_id(&rules, &req), "negative");
    }

    #[test]
    fn disabled_rules_are_skipped_and_fallback_uses_the_default_action() {
        let mut disabled = table_rule("disabled", 1);
        disabled.enabled = false;
        let mut narrow = table_rule("narrow", 2);
        narrow.domain_patterns = strings(&["only.example"]);
        let rules = vec![disabled, narrow];

        let req = table_request("app.exe", "other.example", None, 443);
        let eval = RuleEngine::evaluate(&req, &rules, &RuleAction::Block, None);
        assert_eq!(eval.matched_rule_id, DEFAULT_FALLBACK_RULE_ID);
        assert_eq!(eval.matched_rule_name, DEFAULT_FALLBACK_RULE_NAME);
        assert_eq!(eval.action, RuleAction::Block);

        let hit = table_request("app.exe", "only.example", None, 443);
        assert_eq!(matched_id(&rules, &hit), "narrow");
    }

    #[test]
    fn empty_rule_list_returns_the_default_action() {
        let req = table_request("app.exe", "example.com", None, 443);
        let eval = RuleEngine::evaluate(&req, &[], &RuleAction::Direct, None);
        assert_eq!(eval.action, RuleAction::Direct);
        assert_eq!(eval.matched_rule_id, DEFAULT_FALLBACK_RULE_ID);
    }

    #[test]
    fn blank_domain_and_cidr_patterns_do_not_constrain_a_rule() {
        let mut rule = table_rule("blank", 10);
        rule.domain_patterns = strings(&["", "   "]);
        rule.ip_cidrs = strings(&["  "]);
        let req = table_request("app.exe", "example.com", None, 443);
        assert_eq!(matched_id(&[rule], &req), "blank");
    }

    #[test]
    fn domain_match_is_case_and_trailing_dot_insensitive_in_evaluation() {
        let mut rule = table_rule("dom", 10);
        rule.domain_patterns = strings(&["*.Example.COM", "!Blocked.example.com"]);
        let rules = [rule];
        let cases = [
            ("WWW.EXAMPLE.COM", true),
            ("www.example.com.", true),
            ("blocked.example.com", false),
            ("BLOCKED.EXAMPLE.COM.", false),
            ("example.org", false),
        ];
        for (host, expected) in cases {
            let req = table_request("app.exe", host, None, 443);
            assert_eq!(matched_id(&rules, &req) == "dom", expected, "{host}");
        }
    }

    #[test]
    fn exclusion_in_a_higher_priority_rule_falls_through_to_the_next_rule() {
        let mut first = table_rule("first", 1);
        first.domain_patterns = strings(&["*.example.com", "!secret.example.com"]);
        first.process_patterns = strings(&["!legacy.exe"]);
        let second = table_rule("second", 2);
        let rules = [first, second];

        let cases = [
            ("app.exe", "www.example.com", "first"),
            ("app.exe", "secret.example.com", "second"),
            ("legacy.exe", "www.example.com", "second"),
            ("app.exe", "other.org", "second"),
        ];
        for (process, host, expected) in cases {
            let req = table_request(process, host, None, 443);
            assert_eq!(matched_id(&rules, &req), expected, "{process} {host}");
        }
    }
}
