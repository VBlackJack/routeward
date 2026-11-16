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

use crate::config::{
    PortRange, ProfileConfig, ProxyCredentials, ProxyNode, ProxyProtocol, RoutingRule, RuleAction,
    SystemConstants, TransportProtocol,
};
use crate::error::{RouteWardError, RouteWardResult, ERR_KEY_CONFIG_JSON};
use crate::interceptor::RouteWardController;
use crate::rules::RuleEngine;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const MAX_PAC_HTTP_REQUEST_BYTES: usize = 4096;
const PAC_HTTP_READ_TIMEOUT_MS: u64 = 2000;
const PAC_SOCKS_RETRY_LIMIT: usize = 1;
const BROWSER_PROCESS_CANDIDATES: &[&str] = &[
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "arc.exe",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FoxyProxyImportResult {
    pub proxies: Vec<ProxyNode>,
    pub rules: Vec<RoutingRule>,
    pub skipped_entries: usize,
}

pub struct PacGenerator;

impl PacGenerator {
    /// Generates a deterministic, credential-free Proxy Auto-Config (`FindProxyForURL`) script
    /// matching RouteWard's local SOCKS5 listener when the engine is active, or `DIRECT` when paused.
    pub fn generate(
        profile: &ProfileConfig,
        constants: &SystemConstants,
        engine_running: bool,
    ) -> String {
        if !engine_running {
            return "function FindProxyForURL(url, host) {\n  return \"DIRECT\";\n}\n".to_string();
        }

        let socks_target = format!(
            "SOCKS5 {}:{}; SOCKS {}:{}",
            constants.network.local_bind_host,
            constants.network.default_relay_tcp_port,
            constants.network.local_bind_host,
            constants.network.default_relay_tcp_port
        );

        let mut js = String::with_capacity(2048);
        js.push_str("function rwMatchRegex(cand, pat) {\n");
        js.push_str(
            "  try { return new RegExp(pat, \"i\").test(cand); } catch (e) { return false; }\n",
        );
        js.push_str("}\n");
        js.push_str("function rwMatchDomainSuffix(h, suffix) {\n");
        js.push_str("  return h === suffix || dnsDomainIs(h, \".\" + suffix);\n");
        js.push_str("}\n");
        js.push_str("function rwUrlPort(u) {\n");
        js.push_str(
            "  var m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\/[^\\/]*:(\\d+)(?:[\\/?#]|$)/.exec(u);\n",
        );
        js.push_str("  if (m) return parseInt(m[1], 10);\n");
        js.push_str("  if (/^https:/i.test(u) || /^wss:/i.test(u)) return 443;\n");
        js.push_str("  if (/^http:/i.test(u) || /^ws:/i.test(u)) return 80;\n");
        js.push_str("  return 0;\n");
        js.push_str("}\n");
        js.push_str("function FindProxyForURL(url, host) {\n");
        js.push_str("  var h = (host || \"\").toLowerCase().replace(/\\.$/, \"\");\n");
        js.push_str("  var uPort = rwUrlPort(url || \"\");\n");
        js.push_str("  var cachedIp = null;\n");
        js.push_str("  function rwIp() {\n");
        js.push_str("    if (cachedIp !== null) return cachedIp;\n");
        js.push_str("    if (/^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(h)) { cachedIp = h; }\n");
        js.push_str("    else { cachedIp = dnsResolve(h) || \"\"; }\n");
        js.push_str("    return cachedIp;\n");
        js.push_str("  }\n");

        let mut sorted_rules: Vec<&RoutingRule> =
            profile.rules.iter().filter(|r| r.enabled).collect();
        sorted_rules.sort_by_key(|r| r.priority);

        for rule in sorted_rules {
            if !Self::is_browser_applicable_rule(rule) {
                continue;
            }
            if let Some(cond) = Self::compile_rule_condition_js(rule) {
                let target_expr = match &rule.action {
                    RuleAction::Direct => "DIRECT",
                    RuleAction::Proxy { .. } | RuleAction::Chain { .. } | RuleAction::Block => {
                        &socks_target
                    }
                };
                js.push_str(&format!(
                    "  if ({cond}) return \"{}\";\n",
                    escape_js_string(target_expr)
                ));
            }
        }

        let default_expr = match &profile.default_action {
            RuleAction::Direct => "DIRECT",
            RuleAction::Proxy { .. } | RuleAction::Chain { .. } | RuleAction::Block => {
                &socks_target
            }
        };
        js.push_str(&format!(
            "  return \"{}\";\n",
            escape_js_string(default_expr)
        ));
        js.push_str("}\n");
        js
    }

    pub fn is_browser_applicable_rule(rule: &RoutingRule) -> bool {
        if rule.process_patterns.is_empty() {
            return true;
        }
        BROWSER_PROCESS_CANDIDATES.iter().any(|candidate| {
            RuleEngine::matches_process_patterns(&rule.process_patterns, candidate)
        })
    }

    fn compile_rule_condition_js(rule: &RoutingRule) -> Option<String> {
        let mut clauses: Vec<String> = Vec::new();

        if !rule.port_ranges.is_empty() {
            let port_terms: Vec<String> = rule.port_ranges.iter().map(port_range_js).collect();
            clauses.push(format!("(uPort === 0 || ({}))", port_terms.join(" || ")));
        }

        let mut neg_terms: Vec<String> = Vec::new();
        let mut pos_terms: Vec<String> = Vec::new();

        for raw in &rule.domain_patterns {
            if let Some((is_neg, inner)) = RuleEngine::strip_negation(raw) {
                if let Some(expr) = domain_pattern_to_js(inner) {
                    if is_neg {
                        neg_terms.push(expr);
                    } else {
                        pos_terms.push(expr);
                    }
                }
            }
        }

        for raw in &rule.ip_cidrs {
            if let Some((is_neg, inner)) = RuleEngine::strip_negation(raw) {
                if let Some(expr) = cidr_pattern_to_js(inner) {
                    if is_neg {
                        neg_terms.push(expr);
                    } else {
                        pos_terms.push(expr);
                    }
                } else {
                    tracing::debug!(
                        target: "routeward::pac",
                        "Skipping non-IPv4 CIDR \"{inner}\" in generated PAC rule \"{}\"",
                        rule.name
                    );
                }
            }
        }

        if !neg_terms.is_empty() {
            clauses.push(format!("!({})", neg_terms.join(" || ")));
        }
        if !pos_terms.is_empty() {
            clauses.push(format!("({})", pos_terms.join(" || ")));
        }

        if clauses.is_empty() {
            Some("true".to_string())
        } else {
            Some(clauses.join(" && "))
        }
    }

    pub fn is_valid_loopback_host(host_header: Option<&str>, expected_port: u16) -> bool {
        let Some(raw) = host_header else {
            return true;
        };
        let trimmed = raw.trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            return true;
        }
        let allowed = [
            "127.0.0.1".to_string(),
            format!("127.0.0.1:{expected_port}"),
            "localhost".to_string(),
            format!("localhost:{expected_port}"),
            "[::1]".to_string(),
            format!("[::1]:{expected_port}"),
        ];
        allowed.iter().any(|cand| cand == &trimmed)
    }

    pub fn spawn_pac_http_server(
        controller: Arc<RouteWardController>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let bind_addr = format!(
                "{}:{}",
                controller.constants.network.local_bind_host,
                controller.constants.network.default_pac_port
            );
            let listener = match TcpListener::bind(&bind_addr).await {
                Ok(l) => l,
                Err(err) => {
                    tracing::warn!(
                        target: "routeward::pac",
                        "Failed to bind PAC server on {bind_addr}: {err}"
                    );
                    return;
                }
            };
            tracing::info!(target: "routeward::pac", "Listening for local PAC requests on http://{bind_addr}/proxy.pac");

            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                let ctrl = controller.clone();
                                tokio::spawn(async move {
                                    let _ = handle_pac_http_client(stream, ctrl).await;
                                });
                            }
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(25 * PAC_SOCKS_RETRY_LIMIT as u64)).await;
                            }
                        }
                    }
                }
            }
        })
    }
}

async fn handle_pac_http_client(
    mut stream: TcpStream,
    controller: Arc<RouteWardController>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_PAC_HTTP_REQUEST_BYTES];
    let read_res = tokio::time::timeout(
        Duration::from_millis(PAC_HTTP_READ_TIMEOUT_MS),
        stream.read(&mut buf),
    )
    .await;
    let Ok(Ok(n)) = read_res else {
        return Ok(());
    };
    if n == 0 {
        return Ok(());
    }

    let req_text = String::from_utf8_lossy(&buf[..n]);
    let mut lines = req_text.lines();
    let Some(request_line) = lines.next() else {
        return Ok(());
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("");
    let path = raw_target.split('?').next().unwrap_or("/");

    let host_header = lines.find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case("Host").then(|| v.trim())
    });

    if !PacGenerator::is_valid_loopback_host(
        host_header,
        controller.constants.network.default_pac_port,
    ) {
        let resp =
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nForbidden";
        return stream.write_all(resp.as_bytes()).await;
    }

    if method != "GET" && method != "HEAD" {
        let resp = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 18\r\nConnection: close\r\n\r\nMethod Not Allowed";
        return stream.write_all(resp.as_bytes()).await;
    }

    if path != "/proxy.pac" && path != "/wpad.dat" && path != "/" {
        let resp =
            "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
        return stream.write_all(resp.as_bytes()).await;
    }

    let profile = controller.profile.read().clone();
    let pac_body = PacGenerator::generate(&profile, &controller.constants, controller.is_running());
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store, max-age=0\r\nConnection: close\r\n\r\n",
        pac_body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    if method == "GET" {
        stream.write_all(pac_body.as_bytes()).await?;
    }
    Ok(())
}

fn port_range_js(range: &PortRange) -> String {
    if range.start == range.end {
        format!("uPort === {}", range.start)
    } else {
        format!("(uPort >= {} && uPort <= {})", range.start, range.end)
    }
}

fn escape_js_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out
}

fn domain_pattern_to_js(inner: &str) -> Option<String> {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(raw_re) = crate::rules::RuleEngine::strip_regex_prefix(trimmed) {
        if raw_re.is_empty() || raw_re.starts_with("(?") {
            return None;
        }
        return Some(format!("rwMatchRegex(h, \"{}\")", escape_js_string(raw_re)));
    }
    let low = trimmed.to_lowercase();
    if low == "*" {
        return Some("true".to_string());
    }
    if let Some(suffix) = low.strip_prefix("*.") {
        if !suffix.contains('*') && !suffix.contains('?') {
            return Some(format!(
                "rwMatchDomainSuffix(h, \"{}\")",
                escape_js_string(suffix)
            ));
        }
    }
    Some(format!("shExpMatch(h, \"{}\")", escape_js_string(&low)))
}

fn cidr_pattern_to_js(inner: &str) -> Option<String> {
    let trimmed = inner.trim();
    if let Ok(IpNet::V4(net)) = IpNet::from_str(trimmed) {
        let addr = net.network();
        let mask = net.netmask();
        return Some(format!(
            "(rwIp() !== \"\" && isInNet(rwIp(), \"{addr}\", \"{mask}\"))"
        ));
    }
    if let Ok(v4) = Ipv4Addr::from_str(trimmed) {
        return Some(format!(
            "(rwIp() !== \"\" && isInNet(rwIp(), \"{v4}\", \"255.255.255.255\"))"
        ));
    }
    None
}

pub struct FoxyProxyImporter;

impl FoxyProxyImporter {
    /// Parses a FoxyProxy JSON export (`v6/v7` or `v8+`) into deduplicated RouteWard
    /// [`ProxyNode`] entries and priority-ordered [`RoutingRule`] entries (with `!` exclusions).
    pub fn parse(
        json_str: &str,
        process_patterns: Vec<String>,
        base_priority: i32,
    ) -> RouteWardResult<FoxyProxyImportResult> {
        let root: Value =
            serde_json::from_str(json_str).map_err(|err| RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_JSON,
                detail: format!("Invalid FoxyProxy JSON: {err}"),
            })?;

        let raw_entries =
            extract_foxyproxy_entries(&root).ok_or_else(|| RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_JSON,
                detail: "Unrecognized FoxyProxy JSON schema (expected array or { data: [...] })"
                    .to_string(),
            })?;

        let mut proxies = Vec::new();
        let mut rules = Vec::new();
        let mut skipped_entries = 0usize;
        let mut seen_nodes: HashMap<String, String> = HashMap::new();

        for (idx, entry) in raw_entries.iter().enumerate() {
            let Some(obj) = entry.as_object() else {
                skipped_entries += 1;
                continue;
            };

            let title = obj
                .get("title")
                .or_else(|| obj.get("name"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("FoxyProxy")
                .to_string();

            let active = obj.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
            let raw_type = obj
                .get("type")
                .or_else(|| obj.get("mode"))
                .and_then(|v| v.as_str())
                .unwrap_or("http")
                .trim()
                .to_ascii_lowercase();

            let action = if raw_type == "direct" || raw_type == "none" {
                RuleAction::Direct
            } else {
                let Some(protocol) = map_foxyproxy_protocol(&raw_type) else {
                    skipped_entries += 1;
                    continue;
                };

                let host = obj
                    .get("hostname")
                    .or_else(|| obj.get("address"))
                    .or_else(|| obj.get("host"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .unwrap_or("");
                let port = parse_json_port(obj.get("port")).unwrap_or(0);
                if host.is_empty() || port == 0 {
                    skipped_entries += 1;
                    continue;
                }

                let username = obj
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .unwrap_or("")
                    .to_string();
                let password = obj
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let dedup_key = format!("{protocol:?}|{host}|{port}|{username}").to_lowercase();
                let proxy_id = if let Some(existing_id) = seen_nodes.get(&dedup_key) {
                    existing_id.clone()
                } else {
                    let slug = slugify(&title);
                    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
                    let id = format!("foxy-{slug}-{suffix}");
                    let auth = if !username.is_empty() || !password.is_empty() {
                        Some(ProxyCredentials::new(username, password))
                    } else {
                        None
                    };
                    proxies.push(ProxyNode {
                        id: id.clone(),
                        name: title.clone(),
                        protocol,
                        host: host.to_string(),
                        port,
                        auth,
                        tls: protocol == ProxyProtocol::Https,
                        tls_skip_verify: false,
                        sni: None,
                        udp_enabled: protocol == ProxyProtocol::Socks5,
                        enabled: active,
                        last_latency_ms: None,
                        exit_ip: None,
                    });
                    seen_nodes.insert(dedup_key, id.clone());
                    id
                };

                RuleAction::Proxy {
                    target_id: proxy_id,
                }
            };

            let mut domain_patterns = Vec::new();
            collect_foxyproxy_patterns(
                obj.get("include").or_else(|| obj.get("whitePatterns")),
                false,
                &mut domain_patterns,
            );
            collect_foxyproxy_patterns(
                obj.get("exclude").or_else(|| obj.get("blackPatterns")),
                true,
                &mut domain_patterns,
            );

            if !domain_patterns.is_empty() {
                let rule_suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
                rules.push(RoutingRule {
                    id: format!("foxy-rule-{}-{rule_suffix}", slugify(&title)),
                    name: format!("FoxyProxy: {title}"),
                    enabled: active,
                    priority: base_priority.saturating_add((idx as i32) * 5),
                    process_patterns: process_patterns.clone(),
                    domain_patterns,
                    ip_cidrs: Vec::new(),
                    port_ranges: Vec::new(),
                    protocol: TransportProtocol::Tcp,
                    action,
                });
            }
        }

        Ok(FoxyProxyImportResult {
            proxies,
            rules,
            skipped_entries,
        })
    }
}

fn extract_foxyproxy_entries(root: &Value) -> Option<Vec<&Value>> {
    if let Some(arr) = root.as_array() {
        return Some(arr.iter().collect());
    }
    if let Some(obj) = root.as_object() {
        if let Some(arr) = obj.get("data").and_then(|v| v.as_array()) {
            return Some(arr.iter().collect());
        }
        let mut map_entries = Vec::new();
        for (key, val) in obj {
            if key == "mode" || key == "version" || key == "sync" {
                continue;
            }
            if val.is_object() {
                map_entries.push(val);
            }
        }
        if !map_entries.is_empty() {
            return Some(map_entries);
        }
    }
    None
}

fn map_foxyproxy_protocol(raw: &str) -> Option<ProxyProtocol> {
    match raw {
        "http" => Some(ProxyProtocol::Http),
        "https" | "ssl" | "tls" => Some(ProxyProtocol::Https),
        "socks5" | "socks" => Some(ProxyProtocol::Socks5),
        "socks4" | "socks4a" => Some(ProxyProtocol::Socks4),
        _ => None,
    }
}

fn parse_json_port(val: Option<&Value>) -> Option<u16> {
    let v = val?;
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).ok();
    }
    if let Some(s) = v.as_str() {
        return s.trim().parse::<u16>().ok();
    }
    None
}

fn collect_foxyproxy_patterns(list: Option<&Value>, is_exclude: bool, out: &mut Vec<String>) {
    let Some(arr) = list.and_then(|v| v.as_array()) else {
        return;
    };
    for item in arr {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let active = obj.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
        if !active {
            continue;
        }
        let Some(raw_pat) = obj.get("pattern").and_then(|v| v.as_str()) else {
            continue;
        };
        let is_regex = match obj.get("type") {
            Some(Value::String(s)) => s.eq_ignore_ascii_case("regex"),
            Some(Value::Number(n)) => n.as_u64() == Some(2),
            _ => false,
        };
        if let Some(norm) = normalize_foxyproxy_pattern(raw_pat, is_regex, is_exclude) {
            if !out.contains(&norm) {
                out.push(norm);
            }
        }
    }
}

pub fn normalize_foxyproxy_pattern(
    raw_pat: &str,
    is_regex: bool,
    is_exclude: bool,
) -> Option<String> {
    let trimmed = raw_pat.trim();
    if trimmed.is_empty() {
        return None;
    }

    let formatted = if is_regex {
        format!("regex:{trimmed}")
    } else {
        let no_scheme = trimmed
            .trim_start_matches("*://")
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");
        let host_part = no_scheme.split('/').next().unwrap_or(no_scheme);
        let stripped_port = if host_part.starts_with('[') {
            host_part
                .split(']')
                .next()
                .map(|v| format!("{v}]"))
                .unwrap_or_else(|| host_part.to_string())
        } else {
            host_part.split(':').next().unwrap_or(host_part).to_string()
        };
        let cleaned = stripped_port.trim().to_lowercase();
        if cleaned.is_empty() {
            return None;
        }
        cleaned
    };

    if is_exclude {
        Some(format!("!{formatted}"))
    } else {
        Some(formatted)
    }
}

fn slugify(input: &str) -> String {
    let mut slug = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "proxy".to_string()
    } else {
        trimmed.chars().take(24).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> ProfileConfig {
        let mut profile = ProfileConfig::load_embedded_default().unwrap();
        profile.proxies = vec![ProxyNode {
            id: "edge-proxy".to_string(),
            name: "Corp Proxy".to_string(),
            protocol: ProxyProtocol::Https,
            host: "proxy.corp.example".to_string(),
            port: 8443,
            auth: Some(ProxyCredentials::new("alice", "s3cr3t-password")),
            tls: true,
            tls_skip_verify: false,
            sni: None,
            udp_enabled: false,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        }];
        profile.chains = Vec::new();
        profile.rules = vec![
            RoutingRule {
                id: "edge-rule".to_string(),
                name: "Edge Corporate".to_string(),
                enabled: true,
                priority: 10,
                process_patterns: vec!["msedge.exe".to_string()],
                domain_patterns: vec![
                    "*.corp.example".to_string(),
                    "!intranet.corp.example".to_string(),
                ],
                ip_cidrs: vec!["!10.0.0.0/8".to_string()],
                port_ranges: Vec::new(),
                protocol: TransportProtocol::Tcp,
                action: RuleAction::Proxy {
                    target_id: "edge-proxy".to_string(),
                },
            },
            RoutingRule {
                id: "cli-only-rule".to_string(),
                name: "Git Only".to_string(),
                enabled: true,
                priority: 20,
                process_patterns: vec!["git.exe".to_string()],
                domain_patterns: vec!["*.git-internal.example".to_string()],
                ip_cidrs: Vec::new(),
                port_ranges: Vec::new(),
                protocol: TransportProtocol::Tcp,
                action: RuleAction::Proxy {
                    target_id: "edge-proxy".to_string(),
                },
            },
        ];
        profile.default_action = RuleAction::Direct;
        profile
    }

    #[test]
    fn pac_generator_never_leaks_credentials_and_skips_non_browser_rules() {
        let constants = SystemConstants::load_embedded().unwrap();
        let profile = sample_profile();

        let active_pac = PacGenerator::generate(&profile, &constants, true);
        assert!(active_pac.contains("SOCKS5 127.0.0.1:10808; SOCKS 127.0.0.1:10808"));
        assert!(active_pac.contains("rwMatchDomainSuffix(h, \"corp.example\")"));
        assert!(active_pac.contains("!(shExpMatch(h, \"intranet.corp.example\")"));
        assert!(active_pac.contains("isInNet(rwIp(), \"10.0.0.0\", \"255.0.0.0\")"));
        assert!(!active_pac.contains("git-internal.example"));
        assert!(!active_pac.contains("s3cr3t-password"));
        assert!(!active_pac.contains("alice"));

        let paused_pac = PacGenerator::generate(&profile, &constants, false);
        assert!(paused_pac.contains("return \"DIRECT\";"));
        assert!(!paused_pac.contains("SOCKS5"));
    }

    #[test]
    fn foxyproxy_importer_parses_v8_json_with_exclusions_and_creds() {
        let payload = r#"{
          "mode": "patterns",
          "data": [
            {
              "title": "Corp SOCKS5",
              "active": true,
              "type": "socks5",
              "hostname": "socks.corp.example",
              "port": "1080",
              "username": "jbombled",
              "password": "pw",
              "include": [
                { "type": "wildcard", "pattern": "*://*.github.com/*", "active": true },
                { "type": "regex", "pattern": "^api-[0-9]+\\.corp\\.example$", "active": true }
              ],
              "exclude": [
                { "type": "wildcard", "pattern": "https://gist.github.com:443/*", "active": true }
              ]
            },
            {
              "title": "Skip PAC",
              "active": true,
              "type": "pac",
              "pac": "http://example/pac"
            }
          ]
        }"#;

        let report = FoxyProxyImporter::parse(payload, vec!["msedge.exe".to_string()], 50).unwrap();
        assert_eq!(report.skipped_entries, 1);
        assert_eq!(report.proxies.len(), 1);
        assert_eq!(report.proxies[0].protocol, ProxyProtocol::Socks5);
        assert_eq!(
            report.proxies[0].auth.as_ref().unwrap().username,
            "jbombled"
        );
        assert_eq!(report.rules.len(), 1);
        assert_eq!(report.rules[0].process_patterns, vec!["msedge.exe"]);
        assert_eq!(
            report.rules[0].domain_patterns,
            vec![
                "*.github.com".to_string(),
                "regex:^api-[0-9]+\\.corp\\.example$".to_string(),
                "!gist.github.com".to_string(),
            ]
        );
    }

    #[test]
    fn loopback_host_validation_blocks_dns_rebinding_hosts() {
        assert!(PacGenerator::is_valid_loopback_host(None, 10811));
        assert!(PacGenerator::is_valid_loopback_host(
            Some("127.0.0.1:10811"),
            10811
        ));
        assert!(PacGenerator::is_valid_loopback_host(
            Some("localhost:10811"),
            10811
        ));
        assert!(!PacGenerator::is_valid_loopback_host(
            Some("evil.attacker.com:10811"),
            10811
        ));
    }
}
