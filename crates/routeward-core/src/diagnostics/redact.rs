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

//! Redaction of everything a diagnostic bundle must never carry: credentials, tokens, user and
//! machine names, and (on request) website names. Pure functions: no I/O besides reading the
//! machine name in [`Redactor::from_environment`].

use crate::config::ProfileConfig;
use regex::{Captures, Regex};
use std::sync::OnceLock;

/// Placeholder that replaces a user name, a proxy user name or a user folder.
pub const REDACTED_USER: &str = "[user]";
/// Placeholder that replaces a secret value.
pub const REDACTED_VALUE: &str = "[redacted]";
/// Placeholder that replaces the machine name.
pub const REDACTED_MACHINE: &str = "[machine]";

const SCHEME_SEPARATOR: &str = "://";
const AUTHORITY_TERMINATORS: [char; 3] = ['/', '?', '#'];
const USERINFO_MARKER: char = '@';
const LOG_SCHEME_MAX_CHARS: usize = 16;
/// Shortest machine name that is worth replacing in a text (shorter ones match too much).
const MIN_MACHINE_NAME_CHARS: usize = 3;
/// Shortest token after `Basic` / `Bearer` / `NTLM` that is considered a credential blob.
const MIN_AUTH_BLOB_CHARS: usize = 8;
/// Hex digits kept from the hash that replaces a masked site name.
const MASKED_HASH_HEX_DIGITS: usize = 8;
/// Shortest literal word (user name, password) that is replaced everywhere in a text.
const MIN_LITERAL_WORD_CHARS: usize = 3;
/// Environment variables that hold the name of the signed-in operating system user.
const OS_USER_ENV_VARS: [&str; 3] = ["USERNAME", "USER", "LOGNAME"];
/// Rule ids that embed a site name: `rule-site-<slug>`, `rule-unblock-site-<slug>[-proxy][-tmp]`.
const SITE_RULE_ID_PATTERN: &str =
    r"(?i)\b(rule-(?:unblock-)?site-)([a-z0-9-]+?)((?:-proxy)?(?:-tmp)?)\b";
/// A rule id of an app and site pair: `rule-app-<app>--<site>`.
const APP_SITE_RULE_ID_PATTERN: &str = r"(?i)\b(rule-app-[a-z0-9-]+?--)([a-z0-9-]+)\b";
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
/// Prefix of a regular-expression rule pattern.
const REGEX_PATTERN_PREFIX: &str = "regex:";
/// Placeholder for a regular-expression pattern when site names are masked.
const MASKED_REGEX_PATTERN: &str = "regex:[masked]";
/// Last labels that are file extensions, never top-level domains, in a log line.
const NON_DOMAIN_SUFFIXES: &[&str] = &[
    "exe", "dll", "log", "json", "rs", "txt", "sys", "dat", "bin", "cfg", "conf", "ini", "toml",
    "yml", "yaml", "md", "js", "ts", "so", "sh", "bat", "ps1", "tmp", "pid", "sock", "lock", "db",
    "xml", "html", "css", "png", "ico", "msi", "cab", "bak", "old", "pdb", "rlib", "rmeta",
];

/// Stable codes of the redactions every bundle applies, listed in its manifest. The UI turns each
/// code into a sentence (`diagnostics.export.redaction.<code>`), so the codes never change.
pub const REDACTION_CODES: &[&str] = &[
    "passwords",
    "authHeaders",
    "tokens",
    "urlSecrets",
    "userPaths",
    "usernames",
    "machineName",
    "exitIp",
];

/// Code added to the manifest when site names are masked.
pub const REDACTION_CODE_DOMAINS: &str = "domains";

/// The redaction codes that apply, `domains` included only when site names are masked.
pub fn redaction_codes(masks_domains: bool) -> Vec<&'static str> {
    let mut codes = REDACTION_CODES.to_vec();
    if masks_domains {
        codes.push(REDACTION_CODE_DOMAINS);
    }
    codes
}

fn truncated_scheme(scheme: &str) -> String {
    scheme.chars().take(LOG_SCHEME_MAX_CHARS).collect()
}

/// Reduces a URL to a form safe for logs: scheme and host only, never
/// userinfo, path, query or fragment (which may carry the token).
pub fn redact_url_for_log(target: &str) -> String {
    match target.split_once(SCHEME_SEPARATOR) {
        Some((scheme, rest)) => {
            let end = rest.find(AUTHORITY_TERMINATORS).unwrap_or(rest.len());
            let host = rest[..end].rsplit(USERINFO_MARKER).next().unwrap_or("");
            format!("{}{SCHEME_SEPARATOR}{host}", truncated_scheme(scheme))
        }
        None => {
            let scheme = target.split(':').next().unwrap_or("");
            format!("{}:", truncated_scheme(scheme))
        }
    }
}

/// Removes the secrets of a URL found inside a text but keeps its path: the user info becomes
/// `[user]`, the query and the fragment are dropped.
fn redact_url_in_text(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once(SCHEME_SEPARATOR) else {
        return url.to_string();
    };
    let authority_end = rest.find(AUTHORITY_TERMINATORS).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let host = match authority.rsplit_once(USERINFO_MARKER) {
        Some((_, host)) => format!("{REDACTED_USER}{USERINFO_MARKER}{host}"),
        None => authority.to_string(),
    };
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let path = &tail[..path_end];
    let had_query = tail[path_end..].starts_with('?');
    let query_marker = if had_query {
        format!("?{REDACTED_VALUE}")
    } else {
        String::new()
    };
    format!("{scheme}{SCHEME_SEPARATOR}{host}{path}{query_marker}")
}

/// Compiled patterns, built once.
struct Patterns {
    authorization_header: Regex,
    routeward_token: Regex,
    auth_blob: Regex,
    secret_pair: Regex,
    url: Regex,
    windows_user_path: Regex,
    unix_user_path: Regex,
    root_home_path: Regex,
    user_pair: Regex,
    domain: Regex,
    site_rule_id: Regex,
    app_site_rule_id: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        authorization_header: Regex::new(
            r"(?i)\b(proxy-authorization|authorization)(\s*[:=]\s*)[^\r\n]*",
        )
        .expect("authorization pattern"),
        routeward_token: Regex::new(r"(?i)\b(x-routeward-token)(\s*[:=]\s*)\S+")
            .expect("token header pattern"),
        auth_blob: Regex::new(r"(?i)\b(basic|ntlm|bearer|negotiate)(\s+)([A-Za-z0-9+/=._~-]+)")
            .expect("auth blob pattern"),
        secret_pair: Regex::new(
            r#"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|pwd|secret|key)("?\s*[=:]\s*)(\[redacted\]|"[^"]*"|'[^']*'|[^\s&;,"'})\]]+)"#,
        )
        .expect("secret pair pattern"),
        url: Regex::new(r#"\b[A-Za-z][A-Za-z0-9+.\-]{1,15}://[^\s"'<>]+"#)
            .expect("url pattern"),
        windows_user_path: Regex::new(r#"(?i)([A-Za-z]:[\\/]+Users[\\/]+)([^\\/\s"':*?<>|]+)"#)
            .expect("windows user path pattern"),
        unix_user_path: Regex::new(r#"(/(?:var/home|home|Users)/)([^/\s"':*?<>|]+)"#)
            .expect("unix user path pattern"),
        root_home_path: Regex::new(r"(^|[^\w.-])/root/").expect("root home path pattern"),
        user_pair: Regex::new(
            r#"(?i)\b(user(?:name)?|login|logname)("?\s*[=:]\s*)(\[user\]|"[^"]*"|'[^']*'|[^\s&;,"'})\]]+)"#,
        )
        .expect("user pair pattern"),
        domain: Regex::new(
            r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b",
        )
        .expect("domain pattern"),
        site_rule_id: Regex::new(SITE_RULE_ID_PATTERN).expect("site rule id pattern"),
        app_site_rule_id: Regex::new(APP_SITE_RULE_ID_PATTERN)
            .expect("app and site rule id pattern"),
    })
}

/// True when a token after `Basic` / `Bearer` / `NTLM` looks like a credential blob and not like
/// an ordinary English word ("Basic configuration").
fn looks_like_credential_blob(token: &str) -> bool {
    if token.len() < MIN_AUTH_BLOB_CHARS {
        return false;
    }
    let has_symbol_or_digit = token
        .chars()
        .any(|c| c.is_ascii_digit() || matches!(c, '+' | '/' | '=' | '.' | '_' | '-' | '~'));
    let has_inner_uppercase = token.chars().skip(1).any(|c| c.is_ascii_uppercase());
    has_symbol_or_digit || has_inner_uppercase
}

/// Stable short code for a site name, keeping its top-level domain: `www.example.com` becomes
/// `1a2b3c4d.com`. The same name always gives the same code.
pub fn mask_domain(domain: &str) -> String {
    let lowered = domain.trim().trim_end_matches('.').to_lowercase();
    let tld = lowered.rsplit('.').next().unwrap_or("");
    let mut hash = FNV_OFFSET_BASIS;
    for byte in lowered.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    let hex = format!("{hash:016x}");
    let code = &hex[..MASKED_HASH_HEX_DIGITS];
    if tld.is_empty() || tld == lowered {
        code.to_string()
    } else {
        format!("{code}.{tld}")
    }
}

/// True for a slug that [`mask_domain`] already produced (eight hex digits).
fn is_masked_slug(slug: &str) -> bool {
    slug.len() == MASKED_HASH_HEX_DIGITS && slug.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Masks the site name inside a rule id built by the UI (`rule-site-<slug>`,
/// `rule-unblock-site-<slug>[-proxy][-tmp]`, `rule-app-<app>--<slug>`): the slug becomes a stable
/// code, so ids stay unique and equal ids stay equal. Any other id is returned unchanged.
pub fn mask_site_rule_id(id: &str) -> String {
    let p = patterns();
    let masked = p.site_rule_id.replace_all(id, |caps: &Captures| {
        if is_masked_slug(&caps[2]) {
            caps[0].to_string()
        } else {
            format!("{}{}{}", &caps[1], mask_domain(&caps[2]), &caps[3])
        }
    });
    p.app_site_rule_id
        .replace_all(&masked, |caps: &Captures| {
            if is_masked_slug(&caps[2]) {
                caps[0].to_string()
            } else {
                format!("{}{}", &caps[1], mask_domain(&caps[2]))
            }
        })
        .into_owned()
}

/// Masks a domain pattern of a rule (`*.example.com`, `!example.com`, `.example.com`): the
/// marker is kept, the name is replaced; regular expressions are replaced as a whole.
pub fn mask_domain_pattern(pattern: &str) -> String {
    let trimmed = pattern.trim();
    if trimmed
        .get(..REGEX_PATTERN_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(REGEX_PATTERN_PREFIX))
    {
        return MASKED_REGEX_PATTERN.to_string();
    }
    let (negation, rest) = match trimmed.strip_prefix('!') {
        Some(rest) => ("!", rest),
        None => ("", trimmed),
    };
    let (wildcard, name) = if let Some(name) = rest.strip_prefix("*.") {
        ("*.", name)
    } else if let Some(name) = rest.strip_prefix('.') {
        (".", name)
    } else {
        ("", rest)
    };
    if name.is_empty() || name.contains('*') || name.parse::<std::net::IpAddr>().is_ok() {
        return trimmed.to_string();
    }
    format!("{negation}{wildcard}{}", mask_domain(name))
}

/// Applies the text redactions; build it once per bundle.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    machine_name: Option<String>,
    mask_domains: bool,
    known_domains: Vec<String>,
    /// Words replaced everywhere in a text (user names, passwords), longest first.
    literals: Vec<(String, &'static str)>,
}

impl Redactor {
    /// A redactor that knows the machine name and the signed-in user name of this computer.
    pub fn from_environment() -> Self {
        let users: Vec<String> = OS_USER_ENV_VARS
            .iter()
            .filter_map(|var| std::env::var(var).ok())
            .collect();
        Self::default()
            .with_machine_name(machine_name_from_environment())
            .with_user_words(users)
    }

    fn add_literals(&mut self, words: impl IntoIterator<Item = String>, placeholder: &'static str) {
        for word in words {
            let word = word.trim().to_string();
            // A word inside a placeholder would break the idempotence of the redaction.
            let in_placeholder = [REDACTED_USER, REDACTED_VALUE, REDACTED_MACHINE]
                .iter()
                .any(|p| p.to_ascii_lowercase().contains(&word.to_ascii_lowercase()));
            if word.chars().count() < MIN_LITERAL_WORD_CHARS
                || in_placeholder
                || self
                    .literals
                    .iter()
                    .any(|(w, _)| w.eq_ignore_ascii_case(&word))
            {
                continue;
            }
            self.literals.push((word, placeholder));
        }
        self.literals
            .sort_by_key(|(w, _)| std::cmp::Reverse(w.len()));
    }

    /// User names (proxy accounts, the operating system user) replaced by `[user]` wherever they
    /// appear in a text.
    pub fn with_user_words(mut self, words: impl IntoIterator<Item = String>) -> Self {
        self.add_literals(words, REDACTED_USER);
        self
    }

    /// Secret values (proxy passwords) replaced by `[redacted]` wherever they appear in a text.
    pub fn with_secret_words(mut self, words: impl IntoIterator<Item = String>) -> Self {
        self.add_literals(words, REDACTED_VALUE);
        self
    }

    /// Seeds the user names and passwords of the proxies of `profile`.
    pub fn with_profile_credentials(self, profile: &ProfileConfig) -> Self {
        let mut users = Vec::new();
        let mut secrets = Vec::new();
        for auth in profile.proxies.iter().filter_map(|p| p.auth.as_ref()) {
            users.push(auth.username.clone());
            secrets.push(auth.password_str().to_string());
        }
        self.with_user_words(users).with_secret_words(secrets)
    }

    pub fn with_machine_name(mut self, machine_name: Option<String>) -> Self {
        self.machine_name = machine_name.filter(|n| n.chars().count() >= MIN_MACHINE_NAME_CHARS);
        self
    }

    /// Masks the website names too: the `known` ones wherever they appear, plus anything that
    /// looks like a host name.
    pub fn with_masked_domains(mut self, known: impl IntoIterator<Item = String>) -> Self {
        self.mask_domains = true;
        let mut list: Vec<String> = known
            .into_iter()
            .map(|d| d.trim().trim_end_matches('.').to_lowercase())
            .filter(|d| d.contains('.'))
            .collect();
        list.sort_by_key(|d| std::cmp::Reverse(d.len()));
        list.dedup();
        self.known_domains = list;
        self
    }

    pub fn masks_domains(&self) -> bool {
        self.mask_domains
    }

    /// Redacts one text (a log line, a message, a whole file).
    pub fn redact_text(&self, input: &str) -> String {
        let p = patterns();
        // Known literal words first: a password never survives inside another pattern.
        let mut seeded = input.to_string();
        for (word, placeholder) in &self.literals {
            seeded = replace_literal_ignore_case(&seeded, word, placeholder);
        }
        // Web addresses next, so a query string is gone before the key=value pass.
        let text = p
            .url
            .replace_all(&seeded, |caps: &Captures| redact_url_in_text(&caps[0]));
        let text = p
            .authorization_header
            .replace_all(&text, format!("${{1}}${{2}}{REDACTED_VALUE}"));
        let text = p
            .routeward_token
            .replace_all(&text, format!("${{1}}${{2}}{REDACTED_VALUE}"));
        let text = p.auth_blob.replace_all(&text, |caps: &Captures| {
            if looks_like_credential_blob(&caps[3]) {
                format!("{}{}{REDACTED_VALUE}", &caps[1], &caps[2])
            } else {
                caps[0].to_string()
            }
        });
        let text = p.secret_pair.replace_all(&text, |caps: &Captures| {
            if &caps[3] == REDACTED_VALUE {
                caps[0].to_string()
            } else {
                format!("{}{}{REDACTED_VALUE}", &caps[1], &caps[2])
            }
        });
        let text = p.user_pair.replace_all(&text, |caps: &Captures| {
            if &caps[3] == REDACTED_USER {
                caps[0].to_string()
            } else {
                format!("{}{}{REDACTED_USER}", &caps[1], &caps[2])
            }
        });
        let text = p
            .windows_user_path
            .replace_all(&text, format!("${{1}}{REDACTED_USER}"));
        let text = p
            .unix_user_path
            .replace_all(&text, format!("${{1}}{REDACTED_USER}"));
        let text = p
            .root_home_path
            .replace_all(&text, format!("${{1}}/{REDACTED_USER}/"));
        let mut text = text.into_owned();
        if let Some(machine) = &self.machine_name {
            text = replace_word_ignore_case(&text, machine, REDACTED_MACHINE);
        }
        if self.mask_domains {
            text = self.mask_domains_in_text(&text);
        }
        text
    }

    fn mask_domains_in_text(&self, text: &str) -> String {
        let mut out = mask_site_rule_id(text);
        for known in &self.known_domains {
            out = replace_word_ignore_case(&out, known, &mask_domain(known));
        }
        patterns()
            .domain
            .replace_all(&out, |caps: &Captures| {
                let candidate = &caps[0];
                let suffix = candidate.rsplit('.').next().unwrap_or("").to_lowercase();
                if NON_DOMAIN_SUFFIXES.contains(&suffix.as_str()) || is_masked_code(candidate) {
                    candidate.to_string()
                } else {
                    mask_domain(candidate)
                }
            })
            .into_owned()
    }
}

/// True for a value that [`mask_domain`] already produced (`1a2b3c4d.com`).
fn is_masked_code(candidate: &str) -> bool {
    let mut labels = candidate.split('.');
    let first = labels.next().unwrap_or("");
    first.len() == MASKED_HASH_HEX_DIGITS
        && first.bytes().all(|b| b.is_ascii_hexdigit())
        && labels.count() == 1
}

/// Replaces every occurrence of `word` (ASCII case-insensitive), inside other words too.
fn replace_literal_ignore_case(text: &str, word: &str, replacement: &str) -> String {
    if word.is_empty() {
        return text.to_string();
    }
    let lower_text = text.to_ascii_lowercase();
    let lower_word = word.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(found) = lower_text[cursor..].find(&lower_word) {
        let start = cursor + found;
        let end = start + lower_word.len();
        out.push_str(&text[cursor..start]);
        out.push_str(replacement);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Replaces whole-word occurrences of `word` (ASCII case-insensitive) with `replacement`.
fn replace_word_ignore_case(text: &str, word: &str, replacement: &str) -> String {
    if word.is_empty() {
        return text.to_string();
    }
    let lower_text = text.to_ascii_lowercase();
    let lower_word = word.to_ascii_lowercase();
    let is_word_char = |c: char| c.is_alphanumeric() || c == '_' || c == '-' || c == '.';
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(found) = lower_text[cursor..].find(&lower_word) {
        let start = cursor + found;
        let end = start + lower_word.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        let after_ok = text[end..].chars().next().is_none_or(|c| !is_word_char(c));
        out.push_str(&text[cursor..start]);
        if before_ok && after_ok && text.is_char_boundary(start) && text.is_char_boundary(end) {
            out.push_str(replacement);
        } else {
            out.push_str(&text[start..end]);
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

fn machine_name_from_environment() -> Option<String> {
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(value) = std::env::var(var) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Profile safe to put in a bundle: no password (as in IPC), proxy user names replaced by
/// `[user]` (the has-password flag is kept) and, when `redactor` masks sites, the domain
/// patterns of the rules and the bypass list masked too.
pub fn redact_profile(profile: &ProfileConfig, redactor: &Redactor) -> ProfileConfig {
    let mut redacted = profile.redacted_for_ipc();
    for proxy in &mut redacted.proxies {
        if let Some(auth) = proxy.auth.as_mut() {
            if !auth.username.is_empty() {
                auth.username = REDACTED_USER.to_string();
            }
            auth.password = None;
        }
        proxy.exit_ip = None;
    }
    if redactor.masks_domains() {
        for rule in &mut redacted.rules {
            rule.domain_patterns = rule
                .domain_patterns
                .iter()
                .map(|p| mask_domain_pattern(p))
                .collect();
        }
        redacted.dns_config.bypass_domains = redacted
            .dns_config
            .bypass_domains
            .iter()
            .map(|p| mask_domain_pattern(p))
            .collect();
        for rule in &mut redacted.rules {
            rule.id = mask_site_rule_id(&rule.id);
        }
        for proxy in &mut redacted.proxies {
            proxy.sni = proxy.sni.as_deref().map(|name| {
                if name.contains('.') && name.parse::<std::net::IpAddr>().is_err() {
                    mask_domain(name)
                } else {
                    name.to_string()
                }
            });
        }
    }
    // Names the user typed may hold anything: run them through the text redaction.
    redacted.name = redactor.redact_text(&redacted.name);
    for rule in &mut redacted.rules {
        rule.name = redactor.redact_text(&rule.name);
    }
    for proxy in &mut redacted.proxies {
        proxy.name = redactor.redact_text(&proxy.name);
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyCredentials, ProxyNode, ProxyProtocol};

    fn redactor() -> Redactor {
        Redactor::default().with_machine_name(Some("DESKTOP-JULIEN".to_string()))
    }

    #[test]
    fn text_vectors_are_redacted() {
        let r = redactor();
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "GET http://alice:s3cret@proxy.example.com:8080/path?token=abc123#frag done",
                "url userinfo, query and fragment",
                &["s3cret", "alice", "abc123", "frag"],
            ),
            (
                "Proxy-Authorization: Basic YWxpY2U6czNjcmV0",
                "proxy authorization header",
                &["YWxpY2U6czNjcmV0"],
            ),
            (
                "authorization=Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
                "authorization with a bearer blob",
                &["eyJhbGciOiJIUzI1NiJ9"],
            ),
            (
                "retry with NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAA",
                "ntlm blob",
                &["TlRMTVNTUAAB"],
            ),
            (
                "X-RouteWard-Token: 0a1b2c3d-aaaa-bbbb",
                "bridge token header",
                &["0a1b2c3d"],
            ),
            (
                r#"{"password":"hunter2","note":"x"}"#,
                "json password",
                &["hunter2"],
            ),
            (
                "config api_key=AKIA1234 key: topsecret token=zzz",
                "key value pairs",
                &["AKIA1234", "topsecret", "zzz"],
            ),
            (
                r"opened C:\Users\julien\AppData\Local\RouteWard\logs and C:/Users/Bob/x",
                "windows user folder",
                &["julien", "Bob"],
            ),
            (
                "read /home/julien/.config/routeward and /Users/jane/Library",
                "unix user folder",
                &["julien", "jane"],
            ),
            (
                "host desktop-julien started; DESKTOP-JULIEN again",
                "machine name",
                &["JULIEN", "julien"],
            ),
        ];
        for (input, label, secrets) in cases {
            let out = r.redact_text(input);
            for secret in *secrets {
                assert!(
                    !out.contains(secret),
                    "{label}: {secret:?} survived in {out:?}"
                );
            }
        }
    }

    #[test]
    fn seeded_user_names_and_passwords_are_replaced_everywhere() {
        let r = redactor()
            .with_user_words(vec!["alice".to_string(), "CORP".to_string()])
            .with_secret_words(vec!["Tr0ub4dor&3".to_string()]);
        let cases = [
            ("user=alice logged in", "alice"),
            ("username: \"alice\"", "alice"),
            (r"CORP\alice opened a session", "alice"),
            ("mail alice@example.org sent", "alice"),
            (
                "proxy said wrong password Tr0ub4dor&3 for it",
                "Tr0ub4dor&3",
            ),
            ("ALICE and Alice", "alice"),
            ("path /var/home/alice/.config and /home/alice/x", "alice"),
        ];
        for (input, secret) in cases {
            let out = r.redact_text(input);
            assert!(
                !out.to_lowercase().contains(&secret.to_lowercase()),
                "{secret:?} survived in {out:?}"
            );
            assert_eq!(r.redact_text(&out), out, "not idempotent: {out:?}");
        }
        // A short or placeholder-like word is never seeded: it would corrupt every text.
        let r = redactor().with_user_words(vec![
            "ab".to_string(),
            "user".to_string(),
            "red".to_string(),
        ]);
        assert_eq!(r.redact_text("a user is red"), "a user is red");
    }

    #[test]
    fn user_pairs_and_root_and_var_home_paths_are_redacted() {
        let r = redactor();
        let out = r.redact_text("user=bobby login: carol username=\"dave\"");
        for name in ["bobby", "carol", "dave"] {
            assert!(!out.contains(name), "{name} survived in {out:?}");
        }
        assert_eq!(r.redact_text(&out), out);
        for (input, name) in [
            ("read /root/.config/routeward", "root"),
            ("read /var/home/erin/.config", "erin"),
        ] {
            let out = r.redact_text(input);
            assert!(!out.contains(&format!("/{name}/")), "{out}");
            assert!(out.contains(REDACTED_USER), "{out}");
        }
        // Harmless text that merely mentions the word stays.
        assert_eq!(r.redact_text("a user clicked Save"), "a user clicked Save");
    }

    #[test]
    fn site_names_inside_rule_ids_are_masked_consistently() {
        let r = redactor().with_masked_domains(Vec::new());
        let ids = [
            "rule-site-secret-example-com",
            "rule-unblock-site-secret-example-com",
            "rule-unblock-site-secret-example-com-proxy",
            "rule-unblock-site-secret-example-com-tmp",
            "rule-unblock-site-secret-example-com-proxy-tmp",
            "rule-app-chrome-exe--secret-example-com",
        ];
        for id in ids {
            let masked = mask_site_rule_id(id);
            assert!(!masked.contains("secret"), "{id} -> {masked}");
            assert_eq!(mask_site_rule_id(&masked), masked, "idempotent {id}");
            assert_eq!(
                r.redact_text(&format!("matched {id} now")),
                format!("matched {masked} now")
            );
        }
        // The proxy and temporary markers survive, and equal slugs give equal codes.
        assert!(mask_site_rule_id(ids[4]).ends_with("-proxy-tmp"));
        assert_eq!(
            mask_site_rule_id(ids[1]).trim_start_matches("rule-unblock-site-"),
            mask_site_rule_id("rule-unblock-site-secret-example-com-tmp")
                .trim_start_matches("rule-unblock-site-")
                .trim_end_matches("-tmp")
        );
        // Ids that do not carry a site name are untouched.
        assert_eq!(
            mask_site_rule_id("rule-app-chrome-exe"),
            "rule-app-chrome-exe"
        );
        assert_eq!(mask_site_rule_id("rule-pack-ads"), "rule-pack-ads");
        // Without masking requested, the text is left alone.
        assert_eq!(
            redactor().redact_text("rule-site-secret-example-com"),
            "rule-site-secret-example-com"
        );
    }

    #[test]
    fn redaction_codes_are_stable_and_domains_is_conditional() {
        assert_eq!(
            redaction_codes(false),
            vec![
                "passwords",
                "authHeaders",
                "tokens",
                "urlSecrets",
                "userPaths",
                "usernames",
                "machineName",
                "exitIp"
            ]
        );
        assert_eq!(redaction_codes(true).last(), Some(&REDACTION_CODE_DOMAINS));
        assert_eq!(REDACTION_CODE_DOMAINS, "domains");
    }

    #[test]
    fn redaction_keeps_what_is_harmless() {
        let r = redactor();
        assert_eq!(
            r.redact_text("Basic configuration applied"),
            "Basic configuration applied"
        );
        assert_eq!(
            r.redact_text("Connected to https://example.com/a/b"),
            "Connected to https://example.com/a/b"
        );
        assert_eq!(
            r.redact_text("Blocked chrome.exe -> 1.2.3.4:443"),
            "Blocked chrome.exe -> 1.2.3.4:443"
        );
        assert_eq!(
            r.redact_text("https://example.com/p?x=1"),
            "https://example.com/p?[redacted]"
        );
        assert_eq!(
            r.redact_text("https://u:p@example.com/p"),
            "https://[user]@example.com/p"
        );
    }

    #[test]
    fn redaction_is_idempotent() {
        let r = redactor();
        let input = "Proxy-Authorization: Basic YWxpY2U6czNjcmV0 at C:\\Users\\bob\\x token=abc \
                     http://a:b@h/p?q=1 on DESKTOP-JULIEN";
        let once = r.redact_text(input);
        assert_eq!(r.redact_text(&once), once);
    }

    #[test]
    fn redaction_never_panics_on_arbitrary_input() {
        let r = redactor().with_masked_domains(vec!["example.com".to_string()]);
        let samples = [
            "",
            "://",
            "http://",
            "a://@",
            "\u{0}\u{1}\u{ffff}",
            "[[[[ ]]]] {{{{",
            "token=",
            "authorization:",
            "C:\\Users\\",
            "/home/",
            "ééé.éé http://é@é/é?é#é",
        ];
        for sample in samples {
            let _ = r.redact_text(sample);
        }
    }

    #[test]
    fn domain_masking_is_stable_and_keeps_the_tld() {
        let masked = mask_domain("www.Example.com");
        assert_eq!(masked, mask_domain("www.example.com"));
        assert!(masked.ends_with(".com"));
        assert_eq!(masked.len(), MASKED_HASH_HEX_DIGITS + ".com".len());
        assert_ne!(masked, mask_domain("www.example.org"));
        assert!(mask_domain("a.b.example.co.uk").ends_with(".uk"));
        assert!(!mask_domain("www.example.com").contains("example"));
    }

    #[test]
    fn domain_patterns_keep_their_markers() {
        let masked = mask_domain("example.com");
        assert_eq!(mask_domain_pattern("*.example.com"), format!("*.{masked}"));
        assert_eq!(mask_domain_pattern("!example.com"), format!("!{masked}"));
        assert_eq!(mask_domain_pattern(".example.com"), format!(".{masked}"));
        assert_eq!(mask_domain_pattern("regex:^a.*$"), MASKED_REGEX_PATTERN);
        assert_eq!(mask_domain_pattern("10.0.0.1"), "10.0.0.1");
        assert_eq!(mask_domain_pattern("*"), "*");
    }

    #[test]
    fn masked_text_hides_known_and_unknown_sites_but_not_files() {
        let r = redactor().with_masked_domains(vec!["internal.corp".to_string()]);
        let out = r.redact_text(
            "chrome.exe reached internal.corp and www.example.com; wrote RouteWard_20261122.log",
        );
        assert!(!out.contains("internal.corp"));
        assert!(!out.contains("example"));
        assert!(out.contains("chrome.exe"));
        assert!(out.contains("RouteWard_20261122.log"));
        assert!(out.contains(&mask_domain("internal.corp")));
        // A code already produced is left alone: masking twice changes nothing.
        assert_eq!(r.redact_text(&out), out);
    }

    #[test]
    fn profile_redaction_masks_usernames_and_never_keeps_passwords() {
        let mut profile = ProfileConfig::load_embedded_default().expect("profile");
        profile.proxies = vec![ProxyNode {
            id: "p1".to_string(),
            name: "Office".to_string(),
            protocol: ProxyProtocol::Socks5,
            host: "proxy.corp.example".to_string(),
            port: 1080,
            auth: Some(ProxyCredentials::new("alice", "s3cret")),
            udp_enabled: false,
            tls: false,
            tls_skip_verify: false,
            sni: None,
            enabled: true,
            last_latency_ms: None,
            exit_ip: None,
        }];
        let redacted = redact_profile(&profile, &redactor());
        let auth = redacted.proxies[0].auth.as_ref().expect("auth kept");
        assert_eq!(auth.username, REDACTED_USER);
        assert!(auth.password.is_none());
        assert!(auth.has_password);
        assert_eq!(redacted.proxies[0].host, "proxy.corp.example");
        let json = serde_json::to_string(&redacted).expect("json");
        assert!(!json.contains("alice"));
        assert!(!json.contains("s3cret"));
    }

    #[test]
    fn profile_redaction_masks_rule_domains_on_request() {
        let mut profile = ProfileConfig::load_embedded_default().expect("profile");
        let mut rule = profile.rules.first().cloned().expect("a default rule");
        rule.domain_patterns = vec!["*.example.com".to_string(), "regex:^x$".to_string()];
        profile.rules = vec![rule];
        let redactor = redactor().with_masked_domains(Vec::new());
        let redacted = redact_profile(&profile, &redactor);
        let json = serde_json::to_string(&redacted.rules).expect("json");
        assert!(!json.contains("example.com"));
        assert!(json.contains(&format!("*.{}", mask_domain("example.com"))));
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn a_seeded_secret_never_survives(secret in "Z9[a-z0-9]{8,20}") {
                let r = redactor();
                let inputs = [
                    format!("password={secret} done"),
                    format!("Proxy-Authorization: Basic {secret}"),
                    format!("GET http://u:{secret}@h.example/p?k={secret}#{secret}"),
                    format!("X-RouteWard-Token: {secret}"),
                    format!("{{\"token\":\"{secret}\"}}"),
                    format!("bearer {secret}"),
                ];
                for input in inputs {
                    let out = r.redact_text(&input);
                    prop_assert!(!out.contains(&secret), "{input:?} -> {out:?}");
                }
            }

            #[test]
            fn redaction_is_total_and_idempotent_on_plain_text(text in "[ -~]{0,200}") {
                let r = redactor();
                let once = r.redact_text(&text);
                prop_assert_eq!(r.redact_text(&once), once);
            }
        }
    }

    #[test]
    fn url_for_log_keeps_only_scheme_and_host() {
        assert_eq!(
            redact_url_for_log("http://user:pw@evil.com:80/p?token=abc#f"),
            "http://evil.com:80"
        );
        assert_eq!(redact_url_for_log("javascript:alert(1)"), "javascript:");
        assert!(!redact_url_for_log("http://h/?token=abc").contains("token"));
    }
}
