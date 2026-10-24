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
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

const DEFAULT_FALLBACK_RULE_ID: &str = "default-policy";
const DEFAULT_FALLBACK_RULE_NAME: &str = "Default Profile Policy";
const REGEX_PREFIX: &str = "regex:";

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

            let proc_matched = rule.process_patterns.iter().any(|pattern| {
                let pat = pattern.trim().to_lowercase();
                Self::wildcard_match(&pat, &basename) || Self::wildcard_match(&pat, &full_path)
            });

            if !proc_matched {
                return false;
            }
        }

        let has_domain_criteria = !rule.domain_patterns.is_empty();
        let has_ip_criteria = !rule.ip_cidrs.is_empty();

        if has_domain_criteria || has_ip_criteria {
            let mut destination_matched = false;

            if has_domain_criteria {
                if let Some(domain) = effective_domain {
                    let dom = domain.trim_end_matches('.').to_lowercase();
                    if rule
                        .domain_patterns
                        .iter()
                        .any(|pat| Self::domain_match(pat, &dom))
                    {
                        destination_matched = true;
                    }
                }
            }

            if !destination_matched && has_ip_criteria {
                if let Some(ip) = target_ip {
                    if rule.ip_cidrs.iter().any(|cidr_str| {
                        IpNet::from_str(cidr_str.trim())
                            .map(|net| net.contains(ip))
                            .unwrap_or_else(|_| {
                                IpAddr::from_str(cidr_str.trim())
                                    .map(|exact| &exact == ip)
                                    .unwrap_or(false)
                            })
                    }) {
                        destination_matched = true;
                    }
                }
            }

            if !destination_matched {
                return false;
            }
        }

        true
    }

    pub fn domain_match(pattern: &str, domain: &str) -> bool {
        let pat = pattern.trim().to_lowercase();
        if let Some(raw_regex) = pat.strip_prefix(REGEX_PREFIX) {
            if let Ok(re) = Regex::new(raw_regex) {
                return re.is_match(domain);
            }
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
        Regex::new(&anchored)
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
}
