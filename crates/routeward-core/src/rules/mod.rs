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
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

const DEFAULT_FALLBACK_RULE_ID: &str = "default-policy";
const DEFAULT_FALLBACK_RULE_NAME: &str = "Default Profile Policy";
const REGEX_PREFIX: &str = "regex:";
const MAX_CACHED_REGEX_PATTERNS: usize = 2048;

static REGEX_CACHE: OnceLock<RwLock<HashMap<String, Option<Regex>>>> = OnceLock::new();

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

        let mut sorted_rules: Vec<&RoutingRule> = rules.iter().filter(|r| r.enabled).collect();
        sorted_rules.sort_by_key(|r| r.priority);

        for rule in sorted_rules {
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

    fn get_or_compile_regex(raw_regex: &str) -> Option<Regex> {
        let cache = REGEX_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
        if let Some(cached) = cache.read().get(raw_regex) {
            return cached.clone();
        }
        let compiled = Regex::new(raw_regex).ok();
        let mut guard = cache.write();
        if guard.len() >= MAX_CACHED_REGEX_PATTERNS {
            guard.clear();
        }
        guard.insert(raw_regex.to_string(), compiled.clone());
        compiled
    }

    pub fn domain_match(pattern: &str, domain: &str) -> bool {
        let pat = pattern.trim().to_lowercase();
        if let Some(raw_regex) = pat.strip_prefix(REGEX_PREFIX) {
            if let Some(re) = Self::get_or_compile_regex(raw_regex) {
                return re.is_match(domain);
            }
            return false;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            if domain == suffix || domain.ends_with(&format!(".{suffix}")) {
                return true;
            }
        }
        Self::wildcard_match(&pat, domain)
    }

    pub fn wildcard_match(pattern: &str, candidate: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        let escaped = regex::escape(pattern)
            .replace("\\*", ".*")
            .replace("\\?", ".");
        let anchored = format!("^{escaped}$");
        Self::get_or_compile_regex(&anchored)
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
        let profile = ProfileConfig::load_embedded_default().unwrap();
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

        // 2. Firefox on port 443 should route via proxy-socks5-primary
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
                target_id: "proxy-socks5-primary".to_string()
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
}
