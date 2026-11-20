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

//! DNS server processes (Windows `dns.exe`, Linux `named`, `unbound`, `dnsmasq`, ...) must always
//! receive real DNS answers: a resolver that is handed a Fake-IP answer for its own recursion
//! would cache and serve it to its clients.
//!
//! This module holds the shared, mostly pure pieces:
//!
//! - the identity matcher ([`DnsServerMatcher`]): Windows images are matched by an anchored full
//!   path (`%SystemRoot%\System32\dns.exe` never matches a `dns.exe` somewhere else); Linux images
//!   are matched by basename and only when the executable lives in a root-owned system directory;
//! - the profile list validation ([`validate_entries`]);
//! - the block verdict ([`dns_server_block_verdict`]): the only thing that still stops a DNS
//!   server is an explicit Block rule that names the process;
//! - the [`DnsServerTracker`], owned by the controller and refreshed on a timer and on every
//!   profile reload.
//!
//! # API for the Windows data path (WinDivert worker)
//!
//! The tracker is `controller.dns_server_tracker`. On the receive thread never do a table lookup
//! or a process query: only these cheap calls are allowed.
//!
//! - [`DnsServerTracker::is_empty`]: `true` when no DNS server process is known. Check it first;
//!   when it is `true` the whole feature costs one atomic load per packet.
//! - [`DnsServerTracker::exempt_port_owner`] `(proto, local_port, local_ip)`: the PID of the DNS
//!   server process that owns the socket a packet comes from (rebuilt by every rescan from one UDP
//!   and one TCP table dump). Rows keep their family and local address; an IPv6 row only covers
//!   IPv4 packets when bound to `::` (a dual-stack socket).
//! - [`DnsServerTracker::is_exempt_port`] `(proto, local_port)`: the port-only variant.
//! - [`DnsServerTracker::is_exempt_pid`] `(pid)`: for a PID known from the socket-layer cache.
//! - [`DnsServerTracker::note_unknown_pid`] `(pid, image_path)`: call when a socket-layer event
//!   comes from a PID the tracker does not know; it adds the PID at once when the image matches.
//! - [`DnsServerTracker::refresh`]: the periodic rescan, driven by the controller, not the worker.
//!
//! A matched flow is sent unmodified (no Fake-IP, no `last_seen_orig_resolver` update), unless
//! `RouteWardController::dns_server_block_verdict` says Block, in which case it is dropped and
//! recorded with [`blocked_dns_connection_record`].

use crate::config::{RoutingRule, RuleAction, TransportProtocol};
use crate::interceptor::COMPONENT_ENGINE;
use crate::process::ProcessIdentity;
use crate::rules::{ConnectionRequest, RuleEngine, DEFAULT_FALLBACK_RULE_ID};
use crate::telemetry::{ConnectionStatus, LogLevel, TelemetryHub, TrackedConnection};
use chrono::Utc;
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Longest accepted `dnsServerProcesses` entry, in characters.
const MAX_ENTRY_CHARS: usize = 260;
/// Largest accepted `dnsServerProcesses` list.
const MAX_ENTRIES: usize = 64;
/// Suffix the kernel appends to `/proc/<pid>/exe` when the executable was replaced or removed.
const DELETED_SUFFIX: &str = " (deleted)";
/// Prefix of an extended-length Win32 path.
const WIN32_EXTENDED_PREFIX: &str = r"\\?\";
/// Windows installation directory used when neither `SystemRoot` nor `windir` is set.
const FALLBACK_SYSTEM_ROOT: &str = r"C:\Windows";
/// Environment-style tokens expanded to the Windows directory in an entry (lowercase).
const SYSTEM_ROOT_TOKENS: [&str; 2] = ["%systemroot%", "%windir%"];
/// Linux user ids that are never exempt: root and the shared `nobody` account.
const LINUX_ROOT_UID: u32 = 0;
const LINUX_NOBODY_UID: u32 = 65534;
/// Root-owned directories a Linux DNS server executable must live in for a basename entry.
const LINUX_SYSTEM_DIRS: [&str; 5] = [
    "/usr/sbin",
    "/usr/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/libexec",
];
/// Image basenames (lowercase) that are never exempt, whatever the profile says.
const PROTECTED_IMAGE_NAMES: [&str; 7] = [
    "svchost.exe",
    "systemd-resolved",
    "systemd-resolve",
    "routeward.exe",
    "routeward-desktop.exe",
    "routeward",
    "routeward-desktop",
];
/// Representative installed locations of the protected images, used to reject a path pattern
/// that would cover one of them.
const PROTECTED_IMAGE_PATHS: [&str; 6] = [
    r"C:\Windows\System32\svchost.exe",
    "/usr/lib/systemd/systemd-resolved",
    "/lib/systemd/systemd-resolved",
    "/usr/bin/routeward",
    r"C:\Program Files\RouteWard\routeward.exe",
    r"C:\Program Files\RouteWard\routeward-desktop.exe",
];

/// Transport of a DNS flow (port 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsProto {
    Udp,
    Tcp,
}

impl DnsProto {
    /// Maps to the rule engine protocol.
    pub fn transport(self) -> TransportProtocol {
        match self {
            Self::Udp => TransportProtocol::Udp,
            Self::Tcp => TransportProtocol::Tcp,
        }
    }
}

/// Path flavour used to compare executable images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImagePlatform {
    /// Case-insensitive paths with `\` separators.
    Windows,
    /// Case-sensitive paths with `/` separators (Linux and other Unix systems).
    Unix,
}

impl ImagePlatform {
    /// The flavour of the running OS.
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

/// The Windows directory (`SystemRoot`, then `windir`, then `C:\Windows`).
pub fn system_root_from_env() -> String {
    std::env::var("SystemRoot")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("windir")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .unwrap_or_else(|| FALLBACK_SYSTEM_ROOT.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Comes from `dns.defaultDnsServerProcesses`.
    Default,
    /// Comes from the profile `dnsConfig.dnsServerProcesses`.
    User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    /// Basename only.
    Name(String),
    /// Full path.
    Path(String),
}

#[derive(Debug, Clone)]
struct Entry {
    pattern: Pattern,
}

/// Decides whether an executable image is a DNS server that must get real DNS answers.
#[derive(Debug, Clone)]
pub struct DnsServerMatcher {
    platform: ImagePlatform,
    entries: Vec<Entry>,
}

/// Key used to compare list entries (`!name` removals match a default by it). On Windows the
/// `%SystemRoot%` tokens are expanded and the path normalised first, so that
/// `!C:\Windows\System32\dns.exe` removes the default `%SystemRoot%\System32\dns.exe`.
fn entry_key(raw: &str, platform: ImagePlatform, system_root: &str) -> String {
    match platform {
        ImagePlatform::Windows => {
            normalize_windows_image(&expand_system_root(raw.trim(), system_root))
        }
        ImagePlatform::Unix => raw.trim().to_lowercase(),
    }
}

/// Normalises a Windows image path: lowercase, `\` separators, no `\\?\` prefix.
pub fn normalize_windows_image(path: &str) -> String {
    let lowered = path.trim().replace('/', "\\").to_lowercase();
    lowered
        .strip_prefix(WIN32_EXTENDED_PREFIX)
        .map(str::to_string)
        .unwrap_or(lowered)
}

/// Replaces `%SystemRoot%` and `%windir%` (any case) with `system_root`.
///
/// The search folds ASCII case only, so every byte offset found in the folded text is a valid
/// offset of the original (Unicode lowercasing can change the byte length of a character).
fn expand_system_root(raw: &str, system_root: &str) -> String {
    let mut out = raw.to_string();
    for token in SYSTEM_ROOT_TOKENS {
        let mut from = 0;
        while let Some(rel) = out[from..].to_ascii_lowercase().find(token) {
            let pos = from + rel;
            out.replace_range(pos..pos + token.len(), system_root);
            from = pos + system_root.len();
        }
    }
    out
}

fn basename_of(path: &str) -> &str {
    path.rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or(path)
}

/// Strips the kernel's ` (deleted)` marker from a `/proc/<pid>/exe` target.
pub fn strip_deleted_suffix(path: &str) -> &str {
    path.strip_suffix(DELETED_SUFFIX).unwrap_or(path)
}

/// `true` when `dir` is one of the root-owned system directories or a subdirectory of one.
fn is_system_dir(dir: &str) -> bool {
    if !dir.starts_with('/') || dir.split('/').any(|part| part == "..") {
        return false;
    }
    LINUX_SYSTEM_DIRS
        .iter()
        .any(|root| dir == *root || dir.strip_prefix(root).is_some_and(|r| r.starts_with('/')))
}

/// Glob match supporting `*` (any run) and `?` (any one character). No wildcard means equality.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) && p[pi] != '*' {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// `true` for the images that must never be exempt (the OS service host, the systemd resolver
/// and RouteWard itself).
pub fn is_protected_image(image: &str) -> bool {
    let name = basename_of(strip_deleted_suffix(image.trim())).to_lowercase();
    PROTECTED_IMAGE_NAMES.contains(&name.as_str())
}

fn classify(
    raw: &str,
    platform: ImagePlatform,
    system_root: &str,
    origin: Origin,
) -> Option<Pattern> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match platform {
        ImagePlatform::Windows => {
            let normalized = normalize_windows_image(&expand_system_root(trimmed, system_root));
            if normalized.contains('\\') {
                Some(Pattern::Path(normalized))
            } else if origin == Origin::Default {
                // Default basenames are Linux daemons: on Windows only the anchored path applies.
                None
            } else {
                Some(Pattern::Name(normalized))
            }
        }
        ImagePlatform::Unix => {
            if trimmed.contains('/') {
                trimmed
                    .starts_with('/')
                    .then(|| Pattern::Path(trimmed.to_string()))
            } else if trimmed.contains('\\') {
                None
            } else {
                Some(Pattern::Name(trimmed.to_string()))
            }
        }
    }
}

impl DnsServerMatcher {
    /// Builds the matcher of the running OS from the built-in defaults and the profile list.
    pub fn new(defaults: &[String], user: &[String]) -> Self {
        Self::build(
            defaults,
            user,
            ImagePlatform::current(),
            &system_root_from_env(),
        )
    }

    /// Builds a matcher for an explicit platform (unit tests exercise both on any OS).
    ///
    /// `user` entries add patterns; `!name` removes the default whose normalised text equals
    /// `name`. A default is never removed by a plain entry.
    pub fn build(
        defaults: &[String],
        user: &[String],
        platform: ImagePlatform,
        system_root: &str,
    ) -> Self {
        let removed: HashSet<String> = user
            .iter()
            .filter_map(|raw| raw.trim().strip_prefix('!'))
            .map(|name| entry_key(name, platform, system_root))
            .collect();
        let mut entries: Vec<Entry> = Vec::new();
        for raw in defaults {
            if removed.contains(&entry_key(raw, platform, system_root)) {
                continue;
            }
            if let Some(pattern) = classify(raw, platform, system_root, Origin::Default) {
                entries.push(Entry { pattern });
            }
        }
        let mut seen: HashSet<String> = HashSet::new();
        for raw in user {
            if raw.trim().starts_with('!') || !seen.insert(entry_key(raw, platform, system_root)) {
                continue;
            }
            if is_bare_wildcard(raw.trim()) {
                continue;
            }
            if let Some(pattern) = classify(raw, platform, system_root, Origin::User) {
                entries.push(Entry { pattern });
            }
        }
        Self { platform, entries }
    }

    /// `true` when no pattern is active (every default removed and no addition).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `true` when `image` (the full executable path of a process) is a DNS server.
    pub fn matches_image(&self, image: &str) -> bool {
        if image.trim().is_empty() || is_protected_image(image) {
            return false;
        }
        match self.platform {
            ImagePlatform::Windows => {
                let norm = normalize_windows_image(image);
                let name = basename_of(&norm);
                self.entries.iter().any(|e| match &e.pattern {
                    Pattern::Path(p) => glob_match(p, &norm),
                    Pattern::Name(n) => glob_match(n, name),
                })
            }
            ImagePlatform::Unix => {
                let path = strip_deleted_suffix(image.trim());
                let name = basename_of(path);
                let in_system_dir = path
                    .rsplit_once('/')
                    .map(|(dir, _)| is_system_dir(dir))
                    .unwrap_or(false);
                self.entries.iter().any(|e| match &e.pattern {
                    Pattern::Path(p) => glob_match(p, path),
                    Pattern::Name(n) => in_system_dir && glob_match(n, name),
                })
            }
        }
    }

    /// Cheap prefilter on the process-list basename (`szExeFile`), so the full image path is
    /// only queried for candidates.
    pub fn may_match_basename(&self, exe_name: &str) -> bool {
        let name = match self.platform {
            ImagePlatform::Windows => exe_name.trim().to_lowercase(),
            ImagePlatform::Unix => exe_name.trim().to_string(),
        };
        self.entries.iter().any(|e| match &e.pattern {
            Pattern::Name(n) => glob_match(n, &name),
            Pattern::Path(p) => glob_match(basename_of(p), &name),
        })
    }
}

fn is_bare_wildcard(entry: &str) -> bool {
    !entry.is_empty() && entry.chars().all(|c| c == '*' || c == '?')
}

/// Validates the profile `dnsServerProcesses` list.
///
/// Rejects an empty entry, a bare wildcard, an over-long entry or list, control characters, and
/// any entry that would match `svchost.exe`, `systemd-resolved` or RouteWard's own executables.
/// A `!name` entry removes a default and is only checked for being non-empty.
pub fn validate_entries(entries: &[String]) -> Result<(), String> {
    if entries.len() > MAX_ENTRIES {
        return Err(format!(
            "dnsServerProcesses holds {} entries, the maximum is {MAX_ENTRIES}",
            entries.len()
        ));
    }
    for raw in entries {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("dnsServerProcesses contains an empty entry".to_string());
        }
        if trimmed.chars().count() > MAX_ENTRY_CHARS {
            return Err(format!(
                "dnsServerProcesses entry exceeds {MAX_ENTRY_CHARS} characters"
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err("dnsServerProcesses entry contains a control character".to_string());
        }
        if let Some(removed) = trimmed.strip_prefix('!') {
            if removed.trim().is_empty() {
                return Err("dnsServerProcesses contains an empty removal entry".to_string());
            }
            continue;
        }
        if is_bare_wildcard(trimmed) {
            return Err(format!(
                "dnsServerProcesses entry \"{trimmed}\" is a bare wildcard and would exempt every process"
            ));
        }
        if let Some(protected) = protected_image_covered_by(trimmed) {
            return Err(format!(
                "dnsServerProcesses entry \"{trimmed}\" would exempt the protected process {protected}"
            ));
        }
    }
    Ok(())
}

/// Returns the protected image an entry would match, if any (both path flavours are tried).
fn protected_image_covered_by(entry: &str) -> Option<&'static str> {
    for platform in [ImagePlatform::Windows, ImagePlatform::Unix] {
        let Some(pattern) = classify(entry, platform, FALLBACK_SYSTEM_ROOT, Origin::User) else {
            continue;
        };
        match pattern {
            Pattern::Name(name) => {
                for protected in PROTECTED_IMAGE_NAMES {
                    if glob_match(&name, protected) {
                        return Some(protected);
                    }
                }
            }
            Pattern::Path(path) => {
                for protected in PROTECTED_IMAGE_PATHS {
                    let candidate = match platform {
                        ImagePlatform::Windows => normalize_windows_image(protected),
                        ImagePlatform::Unix => protected.to_string(),
                    };
                    if glob_match(&path, &candidate) {
                        return Some(protected);
                    }
                }
            }
        }
    }
    None
}

/// Name of the Block rule that explicitly targets the process, when there is one.
///
/// A DNS server is only blocked by a Block rule that has non-empty `processPatterns` and is not
/// the profile default policy. The kill switch, the remote DNS option and a default Block action
/// do not apply to DNS server queries. `dst` is the resolver the query is sent to.
pub fn dns_server_block_rule(
    rules: &[RoutingRule],
    default_action: &RuleAction,
    identity: &ProcessIdentity,
    dst: IpAddr,
    proto: DnsProto,
) -> Option<String> {
    let request = ConnectionRequest {
        process_name: identity.name.clone(),
        process_path: Some(identity.executable_path.clone()),
        target_host: dst.to_string(),
        target_ip: Some(dst.to_string()),
        target_port: 53,
        protocol: proto.transport(),
    };
    let eval = RuleEngine::evaluate(&request, rules, default_action, None);
    if eval.action != RuleAction::Block || eval.matched_rule_id == DEFAULT_FALLBACK_RULE_ID {
        return None;
    }
    let rule = rules.iter().find(|r| r.id == eval.matched_rule_id)?;
    if rule.process_patterns.is_empty() {
        return None;
    }
    Some(eval.matched_rule_name)
}

/// `true` when `dns_server_block_rule` finds an explicit Block rule for the process.
pub fn dns_server_block_verdict(
    rules: &[RoutingRule],
    default_action: &RuleAction,
    identity: &ProcessIdentity,
    dst: IpAddr,
    proto: DnsProto,
) -> bool {
    dns_server_block_rule(rules, default_action, identity, dst, proto).is_some()
}

/// Builds the connection record of a DNS query dropped by an explicit Block rule.
pub fn blocked_dns_connection_record(
    identity: &ProcessIdentity,
    dst: IpAddr,
    proto: DnsProto,
    rule_name: String,
    route_label: &str,
) -> TrackedConnection {
    TrackedConnection {
        id: Uuid::new_v4().to_string(),
        pid: identity.pid,
        process_name: identity.name.clone(),
        process_path: identity.executable_path.clone(),
        target_host: dst.to_string(),
        resolved_domain: None,
        target_port: 53,
        protocol: proto.transport(),
        matched_rule: rule_name,
        route_label: route_label.to_string(),
        latency_ms: 0,
        rx_bytes: 0,
        tx_bytes: 0,
        status: ConnectionStatus::Blocked,
        started_at: Utc::now(),
        error_detail: None,
    }
}

/// One process of the Linux `/proc` scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: u32,
    /// Effective user id.
    pub uid: u32,
    /// Executable path, `None` when it could not be read.
    pub image: Option<String>,
}

/// User ids whose DNS egress is exempt from the Fake-IP redirect, and the subset that an explicit
/// Block rule still drops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UidSets {
    pub exempt: BTreeSet<u32>,
    pub block: BTreeSet<u32>,
}

/// Outcome of the Linux uid eligibility decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UidDecision {
    pub sets: UidSets,
    /// `(pid, name)` of the matched processes whose uid is exempt.
    pub exempt_processes: Vec<(u32, String)>,
    /// `(uid, message)`: matched DNS servers that cannot be exempted, one per uid.
    pub refusals: Vec<(u32, String)>,
}

/// Decides which user ids can be exempted on Linux.
///
/// The firewall can only match a user id, not a process, so a uid is exempt only when it is not
/// root, not `nobody`, and EVERY running process with that uid is itself a matched DNS server.
/// `is_blocked` is the explicit-Block verdict of one matched process; a uid is in the block set
/// when any matched process of it is blocked.
pub fn decide_linux_uids(
    procs: &[ProcEntry],
    matcher: &DnsServerMatcher,
    is_blocked: &dyn Fn(&ProcessIdentity) -> bool,
) -> UidDecision {
    let matched: Vec<&ProcEntry> = procs
        .iter()
        .filter(|p| {
            p.image
                .as_deref()
                .is_some_and(|img| matcher.matches_image(img))
        })
        .collect();
    let mut decision = UidDecision::default();
    let mut decided: HashSet<u32> = HashSet::new();
    for proc_entry in &matched {
        let uid = proc_entry.uid;
        if !decided.insert(uid) {
            continue;
        }
        let image = proc_entry.image.clone().unwrap_or_default();
        let name = basename_of(strip_deleted_suffix(&image)).to_string();
        let refusal = if uid == LINUX_ROOT_UID {
            Some("runs as root")
        } else if uid == LINUX_NOBODY_UID {
            Some("runs as the shared nobody user")
        } else if procs.iter().filter(|p| p.uid == uid).any(|p| {
            !p.image
                .as_deref()
                .is_some_and(|img| matcher.matches_image(img))
        }) {
            Some("shares its user id with other processes")
        } else {
            None
        };
        if let Some(reason) = refusal {
            decision.refusals.push((
                uid,
                format!(
                    "DNS server process {name} (PID {}) {reason} (uid {uid}): the firewall can only exempt a dedicated unprivileged user, so it is NOT exempted from Fake-IP",
                    proc_entry.pid
                ),
            ));
            continue;
        }
        decision.sets.exempt.insert(uid);
        let mut blocked = false;
        for member in matched.iter().filter(|p| p.uid == uid) {
            let member_image = member.image.clone().unwrap_or_default();
            decision.exempt_processes.push((
                member.pid,
                basename_of(strip_deleted_suffix(&member_image)).to_string(),
            ));
            if !blocked {
                let identity = ProcessIdentity {
                    pid: member.pid,
                    name: basename_of(strip_deleted_suffix(&member_image)).to_string(),
                    executable_path: strip_deleted_suffix(&member_image).to_string(),
                };
                blocked = is_blocked(&identity);
            }
        }
        if blocked {
            decision.sets.block.insert(uid);
        }
    }
    decision
}

/// Key under which the "executables unreadable" warning is logged once (no real uid is `u32::MAX`).
#[cfg(target_os = "linux")]
const UNREADABLE_IMAGE_KEY: u32 = u32::MAX;

/// Extracts the effective user id from the text of `/proc/<pid>/status`.
pub fn parse_status_euid(status: &str) -> Option<u32> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrackerState {
    /// Matched process ids with their image basename.
    pids: HashMap<u32, String>,
    udp_ports: HashMap<u16, Vec<ExemptSocket>>,
    tcp_ports: HashMap<u16, Vec<ExemptSocket>>,
    uids: UidSets,
}

/// A local socket of a DNS server process: its owner and the address it is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ExemptSocket {
    pid: u32,
    ip: IpAddr,
}

impl ExemptSocket {
    /// `true` when a packet sent from `local_ip` can come from this socket. A socket matches its
    /// own address family, or its wildcard address; an IPv6 row also covers IPv4 packets, but only
    /// when bound to `::` (a dual-stack socket sends IPv4 from the IPv6 table).
    fn covers(&self, local_ip: IpAddr) -> bool {
        match (self.ip, local_ip) {
            (IpAddr::V4(sock), IpAddr::V4(local)) => sock.is_unspecified() || sock == local,
            (IpAddr::V6(sock), IpAddr::V6(local)) => sock.is_unspecified() || sock == local,
            // A dual-stack socket bound to `::` or to an IPv4-mapped address sends IPv4 packets.
            (IpAddr::V6(sock), IpAddr::V4(local)) => {
                sock.is_unspecified() || sock.to_ipv4_mapped() == Some(local)
            }
            (IpAddr::V4(_), IpAddr::V6(_)) => false,
        }
    }
}

impl TrackerState {
    fn ports(&self, proto: DnsProto) -> &HashMap<u16, Vec<ExemptSocket>> {
        match proto {
            DnsProto::Udp => &self.udp_ports,
            DnsProto::Tcp => &self.tcp_ports,
        }
    }

    #[cfg(any(test, windows))]
    fn add_socket(&mut self, proto: DnsProto, port: u16, pid: u32, ip: IpAddr) {
        let map = match proto {
            DnsProto::Udp => &mut self.udp_ports,
            DnsProto::Tcp => &mut self.tcp_ports,
        };
        let sockets = map.entry(port).or_default();
        let socket = ExemptSocket { pid, ip };
        if !sockets.contains(&socket) {
            sockets.push(socket);
            sockets.sort();
        }
    }

    fn is_empty(&self) -> bool {
        self.pids.is_empty()
            && self.udp_ports.is_empty()
            && self.tcp_ports.is_empty()
            && self.uids.exempt.is_empty()
    }
}

/// Result of one platform scan.
#[derive(Debug, Default)]
struct ScanResult {
    state: TrackerState,
    /// `(uid, message)` warnings to log once per uid.
    refusals: Vec<(u32, String)>,
}

struct TrackerInner {
    matcher: RwLock<Arc<DnsServerMatcher>>,
    state: RwLock<TrackerState>,
    /// `true` while any DNS server process is known: the only thing the packet path reads first.
    active: AtomicBool,
    announced: Mutex<HashSet<u32>>,
    warned_uids: Mutex<HashSet<u32>>,
    applied_uids: Mutex<UidSets>,
    /// Serialises a scan, its application and the firewall sync (see [`DnsServerTracker::lock_sync`]).
    sync_lock: Mutex<()>,
    telemetry: TelemetryHub,
}

/// Tracks the running DNS server processes, the local ports of their sockets and (Linux) the user
/// ids whose DNS egress is exempt. Cheap to clone.
#[derive(Clone)]
pub struct DnsServerTracker {
    inner: Arc<TrackerInner>,
}

impl DnsServerTracker {
    pub fn new(telemetry: TelemetryHub) -> Self {
        Self {
            inner: Arc::new(TrackerInner {
                matcher: RwLock::new(Arc::new(DnsServerMatcher::build(
                    &[],
                    &[],
                    ImagePlatform::current(),
                    FALLBACK_SYSTEM_ROOT,
                ))),
                state: RwLock::new(TrackerState::default()),
                active: AtomicBool::new(false),
                announced: Mutex::new(HashSet::new()),
                warned_uids: Mutex::new(HashSet::new()),
                applied_uids: Mutex::new(UidSets::default()),
                sync_lock: Mutex::new(()),
                telemetry,
            }),
        }
    }

    /// Replaces the identity patterns (built-in defaults plus the profile list). The next
    /// [`refresh`](Self::refresh) applies them.
    pub fn configure(&self, defaults: &[String], user: &[String]) {
        *self.inner.matcher.write() = Arc::new(DnsServerMatcher::new(defaults, user));
    }

    /// `true` when no DNS server process is known: the packet path must then do nothing at all.
    pub fn is_empty(&self) -> bool {
        !self.inner.active.load(Ordering::Relaxed)
    }

    /// `true` when `port` is the local port of a UDP or TCP socket of a DNS server process.
    pub fn is_exempt_port(&self, proto: DnsProto, port: u16) -> bool {
        if self.is_empty() {
            return false;
        }
        self.inner.state.read().ports(proto).contains_key(&port)
    }

    /// The PID of the DNS server process that owns the socket a packet from `local_ip:port` comes
    /// from, when there is one. Rows are kept per address family: an IPv4 socket never matches an
    /// IPv6 packet, an IPv6 row only matches an IPv4 packet when bound to `::`, and a socket bound
    /// to one address never matches a packet sent from another.
    pub fn exempt_port_owner(&self, proto: DnsProto, port: u16, local_ip: IpAddr) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        let state = self.inner.state.read();
        state
            .ports(proto)
            .get(&port)?
            .iter()
            .find(|socket| socket.covers(local_ip))
            .map(|socket| socket.pid)
    }

    /// `true` when `pid` is a known DNS server process.
    pub fn is_exempt_pid(&self, pid: u32) -> bool {
        if self.is_empty() {
            return false;
        }
        self.inner.state.read().pids.contains_key(&pid)
    }

    /// The image basename the tracker stored for a known DNS server `pid`.
    pub fn pid_name(&self, pid: u32) -> Option<String> {
        self.inner.state.read().pids.get(&pid).cloned()
    }

    /// Decides a flow from its local port, falling back to `resolve_pid` (a cache lookup, never a
    /// table query) only when the port alone did not decide. An empty tracker returns `false`
    /// without calling `resolve_pid`. Port-only and without a production caller (the data path
    /// uses [`exempt_port_owner`](Self::exempt_port_owner)), so it exists for tests only.
    #[cfg(test)]
    pub fn is_exempt_flow(
        &self,
        proto: DnsProto,
        local_port: u16,
        resolve_pid: impl FnOnce() -> Option<u32>,
    ) -> bool {
        if self.is_empty() {
            return false;
        }
        if self.is_exempt_port(proto, local_port) {
            return true;
        }
        resolve_pid().is_some_and(|pid| self.is_exempt_pid(pid))
    }

    /// Registers a process the periodic scan has not seen yet (for example a `dns.exe` that was
    /// just restarted). Returns `true` when the image matches and the PID is now exempt.
    pub fn note_unknown_pid(&self, pid: u32, image_path: &str) -> bool {
        if pid == 0 {
            return false;
        }
        if self.is_exempt_pid(pid) {
            return true;
        }
        let matcher = self.inner.matcher.read().clone();
        if !matcher.matches_image(image_path) {
            return false;
        }
        let name = basename_of(strip_deleted_suffix(image_path)).to_string();
        self.inner.state.write().pids.insert(pid, name.clone());
        self.inner.active.store(true, Ordering::Relaxed);
        self.announce(pid, &name);
        true
    }

    /// Takes the lock that serialises "scan, apply, sync the firewall" with a firewall reload that
    /// builds its batch from [`uid_sets`](Self::uid_sets) and then calls
    /// [`mark_uid_sets_applied`](Self::mark_uid_sets_applied). Not reentrant: never call
    /// [`refresh`](Self::refresh)-driven code from a holder.
    pub fn lock_sync(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.inner.sync_lock.lock()
    }

    /// The user ids currently exempt (Linux; always empty elsewhere).
    pub fn uid_sets(&self) -> UidSets {
        self.inner.state.read().uids.clone()
    }

    /// The user id sets last written to the firewall.
    pub fn applied_uid_sets(&self) -> UidSets {
        self.inner.applied_uids.lock().clone()
    }

    /// Records the user id sets now present in the firewall (empty after the tables are removed).
    pub fn mark_uid_sets_applied(&self, sets: UidSets) {
        *self.inner.applied_uids.lock() = sets;
    }

    /// Rescans the running processes. `is_blocked` is the explicit-Block verdict of a matched
    /// process (Linux only: the firewall needs the block set up front; Windows decides per packet).
    /// Returns `true` when the known set changed.
    pub fn refresh(&self, is_blocked: &dyn Fn(&ProcessIdentity) -> bool) -> bool {
        let matcher = self.inner.matcher.read().clone();
        let result = if matcher.is_empty() {
            ScanResult::default()
        } else {
            scan(&matcher, is_blocked)
        };
        self.apply(result)
    }

    fn apply(&self, result: ScanResult) -> bool {
        let ScanResult { state, refusals } = result;
        for (uid, message) in refusals {
            if self.inner.warned_uids.lock().insert(uid) {
                self.inner
                    .telemetry
                    .push_log(LogLevel::Warn, COMPONENT_ENGINE, message);
            }
        }
        for (pid, name) in &state.pids {
            self.announce(*pid, name);
        }
        self.inner
            .announced
            .lock()
            .retain(|pid| state.pids.contains_key(pid));
        let active = !state.is_empty();
        let changed = {
            let mut guard = self.inner.state.write();
            let changed = *guard != state;
            *guard = state;
            changed
        };
        self.inner.active.store(active, Ordering::Relaxed);
        changed
    }

    fn announce(&self, pid: u32, name: &str) {
        if self.inner.announced.lock().insert(pid) {
            self.inner.telemetry.push_log(
                LogLevel::Info,
                COMPONENT_ENGINE,
                format!("Exempting DNS server process {name} (PID {pid}) from Fake-IP"),
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn scan(matcher: &DnsServerMatcher, is_blocked: &dyn Fn(&ProcessIdentity) -> bool) -> ScanResult {
    let (procs, unreadable) = read_proc_entries(std::path::Path::new("/proc"));
    let mut decision = decide_linux_uids(&procs, matcher, is_blocked);
    if unreadable {
        decision.refusals.push((
            UNREADABLE_IMAGE_KEY,
            "Cannot read the executable of some processes (permission denied): DNS server processes of another user can only be recognised with CAP_SYS_PTRACE".to_string(),
        ));
    }
    let mut state = TrackerState {
        uids: decision.sets,
        ..TrackerState::default()
    };
    for (pid, name) in decision.exempt_processes {
        state.pids.insert(pid, name);
    }
    ScanResult {
        state,
        refusals: decision.refusals,
    }
}

#[cfg(target_os = "linux")]
fn read_proc_entries(root: &std::path::Path) -> (Vec<ProcEntry>, bool) {
    let Ok(dir) = std::fs::read_dir(root) else {
        return (Vec::new(), false);
    };
    let mut out = Vec::new();
    let mut unreadable = false;
    for entry in dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let proc_dir = entry.path();
        let Ok(status) = std::fs::read_to_string(proc_dir.join("status")) else {
            continue;
        };
        let Some(uid) = parse_status_euid(&status) else {
            continue;
        };
        let image = match std::fs::read_link(proc_dir.join("exe")) {
            Ok(path) => Some(path.to_string_lossy().into_owned()),
            Err(err) => {
                unreadable |= err.kind() == std::io::ErrorKind::PermissionDenied;
                None
            }
        };
        out.push(ProcEntry { pid, uid, image });
    }
    (out, unreadable)
}

#[cfg(windows)]
fn scan(matcher: &DnsServerMatcher, _is_blocked: &dyn Fn(&ProcessIdentity) -> bool) -> ScanResult {
    let pids = windows_matching_processes(matcher);
    let mut state = TrackerState::default();
    if !pids.is_empty() {
        windows_ports_of(&pids, &mut state);
        state.pids = pids;
    }
    ScanResult {
        state,
        refusals: Vec::new(),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn scan(_matcher: &DnsServerMatcher, _is_blocked: &dyn Fn(&ProcessIdentity) -> bool) -> ScanResult {
    ScanResult::default()
}

/// Walks a Toolhelp32 process snapshot and keeps the processes whose full image matches. The
/// basename filter runs first so `QueryFullProcessImageNameW` is only paid for candidates.
#[cfg(windows)]
fn windows_matching_processes(matcher: &DnsServerMatcher) -> HashMap<u32, String> {
    use crate::process::ProcessResolver;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut found = HashMap::new();
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE || snap.is_null() {
        return found;
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
        loop {
            if entry.th32ProcessID > 4 {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                if matcher.may_match_basename(&exe_name) {
                    if let Some(path) = ProcessResolver::query_executable_path(entry.th32ProcessID)
                    {
                        if matcher.matches_image(&path) {
                            found.insert(entry.th32ProcessID, basename_of(&path).to_string());
                        }
                    }
                }
            }
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe {
        CloseHandle(snap);
    }
    found
}

/// One UDP and one TCP table dump (IPv4 and IPv6) reduced to the local sockets owned by `pids`.
/// Every row keeps its family and local address: a dual-stack socket appears in the IPv6 table
/// bound to `::` while it sends IPv4 packets, and [`ExemptSocket::covers`] accounts for that.
#[cfg(windows)]
fn windows_ports_of(pids: &HashMap<u32, String>, state: &mut TrackerState) {
    use crate::process::ProcessResolver;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    fn collect<R>(
        buffer: Option<Vec<u8>>,
        pids: &HashMap<u32, String>,
        proto: DnsProto,
        state: &mut TrackerState,
        row_socket: impl Fn(&R) -> (IpAddr, u32, u32),
    ) {
        let Some(buffer) = buffer else {
            return;
        };
        let rows: &[R] = unsafe { ProcessResolver::iphelper_rows::<R>(&buffer) };
        for row in rows {
            let (ip, raw_port, pid) = row_socket(row);
            if pids.contains_key(&pid) {
                state.add_socket(proto, u16::from_be((raw_port & 0xFFFF) as u16), pid, ip);
            }
        }
    }

    for family in [AF_INET as u32, AF_INET6 as u32] {
        let udp_buffer = ProcessResolver::query_iphelper_buffer(|ptr, size| unsafe {
            GetExtendedUdpTable(ptr as *mut _, size, 0, family, UDP_TABLE_OWNER_PID, 0)
        });
        let tcp_buffer = ProcessResolver::query_iphelper_buffer(|ptr, size| unsafe {
            GetExtendedTcpTable(ptr as *mut _, size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
        });
        if family == AF_INET as u32 {
            collect::<MIB_UDPROW_OWNER_PID>(udp_buffer, pids, DnsProto::Udp, state, |r| {
                (
                    IpAddr::from(r.dwLocalAddr.to_ne_bytes()),
                    r.dwLocalPort,
                    r.dwOwningPid,
                )
            });
            collect::<MIB_TCPROW_OWNER_PID>(tcp_buffer, pids, DnsProto::Tcp, state, |r| {
                (
                    IpAddr::from(r.dwLocalAddr.to_ne_bytes()),
                    r.dwLocalPort,
                    r.dwOwningPid,
                )
            });
        } else {
            collect::<MIB_UDP6ROW_OWNER_PID>(udp_buffer, pids, DnsProto::Udp, state, |r| {
                (IpAddr::from(r.ucLocalAddr), r.dwLocalPort, r.dwOwningPid)
            });
            collect::<MIB_TCP6ROW_OWNER_PID>(tcp_buffer, pids, DnsProto::Tcp, state, |r| {
                (IpAddr::from(r.ucLocalAddr), r.dwLocalPort, r.dwOwningPid)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PortRange, SystemConstants};
    use std::cell::Cell;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const WIN_ROOT: &str = r"C:\Windows";

    fn defaults() -> Vec<String> {
        SystemConstants::load_embedded()
            .expect("embedded constants")
            .dns
            .default_dns_server_processes
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn windows_matcher(user: &[&str]) -> DnsServerMatcher {
        DnsServerMatcher::build(
            &defaults(),
            &strings(user),
            ImagePlatform::Windows,
            WIN_ROOT,
        )
    }

    fn unix_matcher(user: &[&str]) -> DnsServerMatcher {
        DnsServerMatcher::build(&defaults(), &strings(user), ImagePlatform::Unix, WIN_ROOT)
    }

    fn tracker() -> DnsServerTracker {
        DnsServerTracker::new(TelemetryHub::new_with_log_dir(
            &SystemConstants::load_embedded()
                .expect("embedded constants")
                .telemetry,
            std::env::temp_dir().join("routeward-dns-server-exempt-tests"),
            false,
        ))
    }

    fn rule(id: &str, patterns: &[&str], action: RuleAction) -> RoutingRule {
        RoutingRule {
            id: id.to_string(),
            name: format!("rule {id}"),
            enabled: true,
            priority: 10,
            process_patterns: strings(patterns),
            domain_patterns: Vec::new(),
            ip_cidrs: Vec::new(),
            port_ranges: Vec::<PortRange>::new(),
            protocol: TransportProtocol::Any,
            action,
        }
    }

    fn identity(name: &str, path: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid: 42,
            name: name.to_string(),
            executable_path: path.to_string(),
        }
    }

    const RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));

    #[test]
    fn windows_dns_exe_is_anchored_to_the_system_directory() {
        let m = windows_matcher(&[]);
        assert!(m.matches_image(r"C:\Windows\System32\dns.exe"));
        assert!(m.matches_image(r"c:\windows\system32\DNS.EXE"));
        assert!(m.matches_image(r"\\?\C:\Windows\System32\dns.exe"));
        assert!(!m.matches_image(r"C:\Users\x\system32\dns.exe"));
        assert!(!m.matches_image(r"C:\Windows\dns.exe"));
        assert!(!m.matches_image(r"C:\Temp\dns.exe"));
    }

    #[test]
    fn windows_system_root_comes_from_the_environment_value() {
        let m = DnsServerMatcher::build(&defaults(), &[], ImagePlatform::Windows, r"D:\WinNT");
        assert!(m.matches_image(r"D:\WinNT\System32\dns.exe"));
        assert!(!m.matches_image(r"C:\Windows\System32\dns.exe"));
    }

    #[test]
    fn windows_default_basenames_are_inert_but_user_basenames_match_anywhere() {
        let m = windows_matcher(&[]);
        assert!(!m.matches_image(r"C:\Tools\named.exe"));
        assert!(!m.matches_image(r"C:\Tools\named"));
        let user = windows_matcher(&["MyDns.exe"]);
        assert!(user.matches_image(r"D:\apps\mydns.exe"));
        assert!(!user.matches_image(r"D:\apps\other.exe"));
    }

    #[test]
    fn linux_basename_matches_only_in_root_owned_system_directories() {
        let m = unix_matcher(&[]);
        assert!(m.matches_image("/usr/sbin/named"));
        assert!(m.matches_image("/usr/bin/unbound"));
        assert!(m.matches_image("/usr/local/sbin/dnsmasq"));
        assert!(m.matches_image("/usr/libexec/coredns"));
        assert!(m.matches_image("/usr/sbin/pihole-FTL"));
        assert!(m.matches_image("/usr/sbin/named (deleted)"));
        assert!(m.matches_image("/usr/local/bin/sub/kresd"));
        assert!(!m.matches_image("/home/u/named"));
        assert!(!m.matches_image("/tmp/dnsmasq"));
        assert!(!m.matches_image("/usr/sbin/../../home/u/named"));
        assert!(!m.matches_image("/usr/sbinx/named"));
        assert!(!m.matches_image("/usr/sbin/Named"));
        assert!(!m.matches_image(r"C:\Windows\System32\dns.exe"));
    }

    #[test]
    fn linux_full_path_entries_match_exactly_without_the_directory_rule() {
        let m = unix_matcher(&["/opt/dns/bin/mydns"]);
        assert!(m.matches_image("/opt/dns/bin/mydns"));
        assert!(m.matches_image("/opt/dns/bin/mydns (deleted)"));
        assert!(!m.matches_image("/opt/dns/bin/other"));
        let by_name = unix_matcher(&["mydns"]);
        assert!(by_name.matches_image("/usr/sbin/mydns"));
        assert!(!by_name.matches_image("/opt/dns/bin/mydns"));
    }

    #[test]
    fn protected_images_never_match_even_with_a_permissive_matcher() {
        let permissive_user = DnsServerMatcher {
            platform: ImagePlatform::Unix,
            entries: vec![Entry {
                pattern: Pattern::Name("*".to_string()),
            }],
        };
        assert!(permissive_user.matches_image("/usr/sbin/named"));
        assert!(!permissive_user.matches_image("/usr/lib/systemd/systemd-resolved"));
        assert!(!permissive_user.matches_image("/usr/sbin/systemd-resolved"));
        assert!(!permissive_user.matches_image("/usr/bin/routeward"));
        let permissive_win = DnsServerMatcher {
            platform: ImagePlatform::Windows,
            entries: vec![Entry {
                pattern: Pattern::Name("*".to_string()),
            }],
        };
        assert!(permissive_win.matches_image(r"C:\x\dns.exe"));
        assert!(!permissive_win.matches_image(r"C:\Windows\System32\svchost.exe"));
        assert!(!permissive_win.matches_image(r"C:\Windows\System32\SVCHOST.EXE"));
        assert!(!permissive_win.matches_image(r"C:\Program Files\RouteWard\routeward.exe"));
    }

    #[test]
    fn defaults_never_contain_a_protected_process() {
        let list = defaults();
        assert!(validate_entries(&list).is_ok(), "defaults must validate");
        for entry in &list {
            let lowered = entry.to_lowercase();
            assert!(!lowered.contains("svchost"), "{entry}");
            assert!(!lowered.contains("systemd-resolve"), "{entry}");
            assert!(!lowered.contains("routeward"), "{entry}");
        }
        assert!(!unix_matcher(&[]).is_empty());
        assert!(!unix_matcher(&[]).matches_image("/usr/lib/systemd/systemd-resolved"));
        assert!(!windows_matcher(&[]).matches_image(r"C:\Windows\System32\svchost.exe"));
    }

    #[test]
    fn default_list_matches_the_documented_order() {
        assert_eq!(
            defaults(),
            vec![
                r"%SystemRoot%\System32\dns.exe",
                "named",
                "unbound",
                "dnsmasq",
                "pihole-FTL",
                "pdns_recursor",
                "kresd",
                "dnsdist",
                "coredns"
            ]
        );
    }

    #[test]
    fn bang_entry_removes_a_default_by_normalised_text() {
        let m = unix_matcher(&["!dnsmasq"]);
        assert!(!m.matches_image("/usr/sbin/dnsmasq"));
        assert!(m.matches_image("/usr/sbin/named"));
        let upper = unix_matcher(&["!  DnsMasq "]);
        assert!(!upper.matches_image("/usr/sbin/dnsmasq"));
        let win = windows_matcher(&[r"!%SystemRoot%\System32\DNS.exe"]);
        assert!(!win.matches_image(r"C:\Windows\System32\dns.exe"));
        let other = unix_matcher(&["!dns"]);
        assert!(other.matches_image("/usr/sbin/dnsmasq"));
    }

    #[test]
    fn bang_entry_matches_a_default_after_system_root_expansion() {
        let win = windows_matcher(&[r"!C:\Windows\System32\dns.exe"]);
        assert!(!win.matches_image(r"C:\Windows\System32\dns.exe"));
        let slashes = windows_matcher(&[r"!c:/windows/system32/DNS.EXE"]);
        assert!(!slashes.matches_image(r"C:\Windows\System32\dns.exe"));
        let windir = windows_matcher(&[r"!%windir%\System32\dns.exe"]);
        assert!(!windir.matches_image(r"C:\Windows\System32\dns.exe"));
        // A different directory does not remove the default.
        let other = windows_matcher(&[r"!D:\Windows\System32\dns.exe"]);
        assert!(other.matches_image(r"C:\Windows\System32\dns.exe"));
    }

    #[test]
    fn system_root_expansion_never_panics_on_unicode_case_changes() {
        // U+0130 lowercases to two characters and U+212A (Kelvin sign) to one ASCII letter, both
        // changing the byte length of the text: offsets found in a folded copy would be wrong.
        for raw in [
            "\u{130}%SystemRoot%",
            "\u{212A}%SystemRoot%",
            r"%SystemRoot%\System32\dns.exe",
            "\u{130}%SystemRoot%\\System32\\dns.exe",
            "\u{212A}%WINDIR%\u{130}%windir%",
        ] {
            let out = expand_system_root(raw, WIN_ROOT);
            assert!(!out.to_ascii_lowercase().contains("%systemroot%"));
            assert!(!out.to_ascii_lowercase().contains("%windir%"));
            assert!(out.contains(WIN_ROOT));
            assert!(validate_entries(&[raw.to_string()]).is_ok());
            let _ = windows_matcher(&[raw]);
        }
        assert_eq!(
            expand_system_root(r"%SYSTEMROOT%\a;%WinDir%", WIN_ROOT),
            r"C:\Windows\a;C:\Windows"
        );
    }

    #[test]
    fn removing_every_default_leaves_an_empty_matcher() {
        let removals: Vec<String> = defaults().iter().map(|d| format!("!{d}")).collect();
        let m = DnsServerMatcher::build(&defaults(), &removals, ImagePlatform::Unix, WIN_ROOT);
        assert!(m.is_empty());
        assert!(!m.matches_image("/usr/sbin/named"));
    }

    #[test]
    fn validation_rejects_empty_bare_wildcard_and_protected_entries() {
        assert!(validate_entries(&[]).is_ok());
        assert!(validate_entries(&strings(&["mydns", "!dnsmasq", "/opt/x/mydns"])).is_ok());
        for bad in [
            "",
            "   ",
            "*",
            "**",
            "?",
            "!",
            "! ",
            "svchost.exe",
            "SVCHOST.EXE",
            "s*.exe",
            "*.exe",
            "systemd-resolved",
            "systemd-*",
            "routeward",
            "routeward.exe",
            "routeward-desktop.exe",
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\System32\*.exe",
            "/usr/lib/systemd/systemd-resolved",
            "/usr/lib/systemd/*",
            r"C:\Program Files\RouteWard\routeward.exe",
        ] {
            assert!(
                validate_entries(&strings(&[bad])).is_err(),
                "entry {bad:?} must be rejected"
            );
        }
        assert!(validate_entries(&strings(&["a\nb"])).is_err());
        assert!(validate_entries(&["x".repeat(MAX_ENTRY_CHARS + 1)]).is_err());
        let many: Vec<String> = (0..=MAX_ENTRIES).map(|i| format!("dns{i}")).collect();
        assert!(validate_entries(&many).is_err());
    }

    #[test]
    fn profile_validation_hook_rejects_a_bad_dns_server_list() {
        let json = crate::config::ProfileConfig::load_embedded_default()
            .expect("default profile")
            .to_json_pretty()
            .expect("serialise");
        let patched = json.replacen(
            "\"bypassDomains\"",
            "\"dnsServerProcesses\": [\"svchost.exe\"],\n    \"bypassDomains\"",
            1,
        );
        assert!(crate::config::ProfileConfig::from_json_str(&patched).is_err());
        assert!(crate::config::ProfileConfig::from_json_str(&json).is_ok());
    }

    #[test]
    fn empty_dns_server_list_is_omitted_from_the_profile_json() {
        let profile = crate::config::ProfileConfig::load_embedded_default().expect("profile");
        assert!(profile.dns_config.dns_server_processes.is_empty());
        let json = profile.to_json_pretty().expect("serialise");
        assert!(!json.contains("dnsServerProcesses"));
        let mut with_list = profile.clone();
        with_list.dns_config.dns_server_processes = strings(&["!dnsmasq"]);
        let json = with_list.to_json_pretty().expect("serialise");
        let back = crate::config::ProfileConfig::from_json_str(&json).expect("round trip");
        assert_eq!(back.dns_config.dns_server_processes, strings(&["!dnsmasq"]));
    }

    #[test]
    fn block_verdict_needs_an_explicit_block_rule_naming_the_process() {
        let id = identity("named", "/usr/sbin/named");
        let proto = DnsProto::Udp;
        let block_named = rule("r1", &["named"], RuleAction::Block);
        assert!(dns_server_block_verdict(
            &[block_named],
            &RuleAction::Direct,
            &id,
            RESOLVER,
            proto
        ));
        // Default policy Block does not apply.
        assert!(!dns_server_block_verdict(
            &[],
            &RuleAction::Block,
            &id,
            RESOLVER,
            proto
        ));
        // A Block rule without process patterns is not a rule that targets the process.
        let block_everything = rule("r2", &[], RuleAction::Block);
        assert!(!dns_server_block_verdict(
            &[block_everything],
            &RuleAction::Direct,
            &id,
            RESOLVER,
            proto
        ));
        // A rule for another process does not match.
        let other = rule("r3", &["chrome.exe"], RuleAction::Block);
        assert!(!dns_server_block_verdict(
            &[other],
            &RuleAction::Direct,
            &id,
            RESOLVER,
            proto
        ));
        // A non-Block rule that names the process is not a block.
        let direct = rule("r4", &["named"], RuleAction::Direct);
        assert!(!dns_server_block_verdict(
            &[direct],
            &RuleAction::Block,
            &id,
            RESOLVER,
            proto
        ));
        let rule_name = dns_server_block_rule(
            &[rule("r5", &["named"], RuleAction::Block)],
            &RuleAction::Direct,
            &id,
            RESOLVER,
            DnsProto::Tcp,
        );
        assert_eq!(rule_name.as_deref(), Some("rule r5"));
    }

    #[test]
    fn blocked_record_carries_the_process_and_the_blocked_status() {
        let id = identity("named", "/usr/sbin/named");
        let record = blocked_dns_connection_record(
            &id,
            RESOLVER,
            DnsProto::Udp,
            "rule r1".into(),
            "BLOCKED",
        );
        assert_eq!(record.status, ConnectionStatus::Blocked);
        assert_eq!(record.target_port, 53);
        assert_eq!(record.protocol, TransportProtocol::Udp);
        assert_eq!(record.process_name, "named");
        assert_eq!(record.matched_rule, "rule r1");
    }

    fn proc_entry(pid: u32, uid: u32, image: Option<&str>) -> ProcEntry {
        ProcEntry {
            pid,
            uid,
            image: image.map(str::to_string),
        }
    }

    #[test]
    fn linux_uid_is_exempt_only_when_dedicated_and_unprivileged() {
        let m = unix_matcher(&[]);
        let never_blocked = |_: &ProcessIdentity| false;
        let procs = vec![
            proc_entry(1, 0, Some("/usr/sbin/init")),
            proc_entry(100, 105, Some("/usr/sbin/named")),
            proc_entry(101, 105, Some("/usr/sbin/named")),
            proc_entry(200, 0, Some("/usr/sbin/unbound")),
            proc_entry(300, 65534, Some("/usr/sbin/dnsmasq")),
            proc_entry(400, 1000, Some("/usr/sbin/kresd")),
            proc_entry(401, 1000, Some("/usr/bin/bash")),
            proc_entry(500, 2000, Some("/usr/sbin/coredns")),
            proc_entry(501, 2000, None),
        ];
        let decision = decide_linux_uids(&procs, &m, &never_blocked);
        assert_eq!(decision.sets.exempt, BTreeSet::from([105]));
        assert!(decision.sets.block.is_empty());
        let refused: BTreeSet<u32> = decision.refusals.iter().map(|(uid, _)| *uid).collect();
        assert_eq!(refused, BTreeSet::from([0, 65534, 1000, 2000]));
        assert_eq!(decision.exempt_processes.len(), 2);
    }

    #[test]
    fn linux_block_set_follows_the_block_verdict_of_matched_processes() {
        let m = unix_matcher(&[]);
        let procs = vec![
            proc_entry(100, 105, Some("/usr/sbin/named")),
            proc_entry(200, 106, Some("/usr/sbin/unbound")),
        ];
        let block_named = |id: &ProcessIdentity| id.name == "named";
        let decision = decide_linux_uids(&procs, &m, &block_named);
        assert_eq!(decision.sets.exempt, BTreeSet::from([105, 106]));
        assert_eq!(decision.sets.block, BTreeSet::from([105]));
    }

    #[test]
    fn status_euid_is_the_second_uid_field() {
        let status = "Name:\tnamed\nUmask:\t0022\nUid:\t105\t106\t105\t106\nGid:\t1\t1\t1\t1\n";
        assert_eq!(parse_status_euid(status), Some(106));
        assert_eq!(parse_status_euid("Name:\tx\n"), None);
        assert_eq!(parse_status_euid("Uid:\tabc\n"), None);
    }

    #[test]
    fn empty_tracker_answers_false_without_calling_the_pid_lookup() {
        let t = tracker();
        assert!(t.is_empty());
        let calls = Cell::new(0u32);
        let exempt = t.is_exempt_flow(DnsProto::Udp, 53000, || {
            calls.set(calls.get() + 1);
            Some(7)
        });
        assert!(!exempt);
        assert_eq!(calls.get(), 0);
        assert!(!t.is_exempt_port(DnsProto::Tcp, 53));
        assert!(!t.is_exempt_pid(7));
    }

    #[test]
    fn tracker_decides_by_port_first_then_by_pid() {
        let t = tracker();
        let mut state = TrackerState::default();
        state.pids.insert(7, "dns.exe".to_string());
        state.add_socket(DnsProto::Udp, 53100, 7, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        state.add_socket(DnsProto::Tcp, 53, 7, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(t.apply(ScanResult {
            state,
            refusals: Vec::new()
        }));
        assert!(!t.is_empty());
        let calls = Cell::new(0u32);
        assert!(t.is_exempt_flow(DnsProto::Udp, 53100, || {
            calls.set(calls.get() + 1);
            None
        }));
        assert_eq!(calls.get(), 0, "a port hit must not look the pid up");
        assert!(!t.is_exempt_port(DnsProto::Udp, 53));
        assert!(t.is_exempt_port(DnsProto::Tcp, 53));
        assert!(t.is_exempt_flow(DnsProto::Udp, 40000, || Some(7)));
        assert!(!t.is_exempt_flow(DnsProto::Udp, 40000, || Some(8)));
        assert!(!t.is_exempt_flow(DnsProto::Udp, 40000, || None));
        // A rescan without the process empties the tracker again.
        assert!(t.apply(ScanResult::default()));
        assert!(t.is_empty());
        assert!(!t.apply(ScanResult::default()));
    }

    fn tracker_with_sockets(sockets: &[(DnsProto, u16, u32, IpAddr)]) -> DnsServerTracker {
        let t = tracker();
        let mut state = TrackerState::default();
        for (proto, port, pid, ip) in sockets {
            state.pids.insert(*pid, "dns.exe".to_string());
            state.add_socket(*proto, *port, *pid, *ip);
        }
        assert!(t.apply(ScanResult {
            state,
            refusals: Vec::new()
        }));
        t
    }

    #[test]
    fn port_owner_keeps_the_pid_of_the_matching_socket() {
        let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 10).into();
        let t = tracker_with_sockets(&[(DnsProto::Udp, 53100, 7, Ipv4Addr::UNSPECIFIED.into())]);
        assert_eq!(t.exempt_port_owner(DnsProto::Udp, 53100, v4), Some(7));
        assert_eq!(t.exempt_port_owner(DnsProto::Udp, 53101, v4), None);
        assert_eq!(t.exempt_port_owner(DnsProto::Tcp, 53100, v4), None);
        assert_eq!(
            t.exempt_port_owner(DnsProto::Udp, 53100, Ipv6Addr::LOCALHOST.into()),
            None,
            "an IPv4 socket never owns an IPv6 packet"
        );
    }

    #[test]
    fn ipv6_row_covers_ipv4_packets_only_when_bound_to_the_wildcard() {
        let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 10).into();
        let v6: IpAddr = "2001:db8::10".parse::<Ipv6Addr>().unwrap().into();
        let dual = tracker_with_sockets(&[(DnsProto::Udp, 53100, 7, Ipv6Addr::UNSPECIFIED.into())]);
        assert_eq!(dual.exempt_port_owner(DnsProto::Udp, 53100, v4), Some(7));
        assert_eq!(dual.exempt_port_owner(DnsProto::Udp, 53100, v6), Some(7));
        let only = tracker_with_sockets(&[(DnsProto::Udp, 53100, 7, v6)]);
        assert_eq!(
            only.exempt_port_owner(DnsProto::Udp, 53100, v4),
            None,
            "an IPv6-only socket must not exempt an IPv4 flow on the same port number"
        );
        assert_eq!(only.exempt_port_owner(DnsProto::Udp, 53100, v6), Some(7));
        let other_v6: IpAddr = "2001:db8::11".parse::<Ipv6Addr>().unwrap().into();
        assert_eq!(only.exempt_port_owner(DnsProto::Udp, 53100, other_v6), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_row_covers_only_its_own_ipv4_address() {
        let local: IpAddr = Ipv4Addr::new(192, 0, 2, 10).into();
        let other: IpAddr = Ipv4Addr::new(192, 0, 2, 11).into();
        let mapped: IpAddr = Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped().into();
        let tracker = tracker_with_sockets(&[(DnsProto::Tcp, 53200, 9, mapped)]);
        assert_eq!(
            tracker.exempt_port_owner(DnsProto::Tcp, 53200, local),
            Some(9)
        );
        assert_eq!(tracker.exempt_port_owner(DnsProto::Tcp, 53200, other), None);
    }

    #[test]
    fn socket_bound_to_one_address_does_not_cover_another_local_address() {
        let bound: IpAddr = Ipv4Addr::new(192, 0, 2, 10).into();
        let other: IpAddr = Ipv4Addr::new(192, 0, 2, 11).into();
        let t = tracker_with_sockets(&[(DnsProto::Tcp, 53, 7, bound)]);
        assert_eq!(t.exempt_port_owner(DnsProto::Tcp, 53, bound), Some(7));
        assert_eq!(t.exempt_port_owner(DnsProto::Tcp, 53, other), None);
    }

    #[test]
    fn note_unknown_pid_adds_only_matching_images() {
        let t = tracker();
        t.configure(&defaults(), &[]);
        let sample = if cfg!(windows) {
            let root = system_root_from_env();
            format!(r"{root}\System32\dns.exe")
        } else {
            "/usr/sbin/named".to_string()
        };
        assert!(!t.note_unknown_pid(0, &sample));
        assert!(!t.note_unknown_pid(9, "/tmp/evil/named"));
        assert!(t.is_empty());
        assert!(t.note_unknown_pid(9, &sample));
        assert!(t.is_exempt_pid(9));
        assert!(!t.is_empty());
        assert!(t.note_unknown_pid(9, &sample));
    }

    #[test]
    fn uid_sets_applied_marker_round_trips() {
        let t = tracker();
        assert_eq!(t.applied_uid_sets(), UidSets::default());
        let sets = UidSets {
            exempt: BTreeSet::from([105]),
            block: BTreeSet::new(),
        };
        t.mark_uid_sets_applied(sets.clone());
        assert_eq!(t.applied_uid_sets(), sets);
    }

    #[test]
    fn glob_matching_handles_wildcards() {
        assert!(glob_match("named", "named"));
        assert!(!glob_match("named", "named2"));
        assert!(glob_match("n*d", "named"));
        assert!(glob_match("n?med", "named"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }
}
