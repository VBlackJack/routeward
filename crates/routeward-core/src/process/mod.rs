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

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

const UNKNOWN_PROCESS_NAME: &str = "system";
const PATH_SEPARATORS: &[char] = &['/', '\\'];

const NETLINK_HEADER_LEN: usize = 16;
const INET_DIAG_REQ_V2_LEN: usize = 56;
const INET_DIAG_MSG_LEN: usize = 72;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_NOOP_TYPE: u16 = 1;
const NLMSG_ERROR_TYPE: u16 = 2;
const NLMSG_DONE_TYPE: u16 = 3;
const NLM_F_REQUEST_DUMP: u16 = 0x0001 | 0x0300;
#[cfg(any(target_os = "linux", test))]
const LINUX_AF_INET: u8 = 2;
#[cfg(any(target_os = "linux", test))]
const LINUX_AF_INET6: u8 = 10;
#[cfg(any(target_os = "linux", test))]
const LINUX_IPPROTO_TCP: u8 = 6;
#[cfg(any(target_os = "linux", test))]
const LINUX_IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,
    pub executable_path: String,
}

/// Result of attributing a local TCP port to an OS process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessAttribution {
    /// Exactly one process owns the socket.
    Single(ProcessIdentity),
    /// Multiple processes share the socket descriptor (for example after `fork`).
    Shared {
        primary: ProcessIdentity,
        candidate_pids: Vec<u32>,
    },
    /// No owning process could be determined (for example socket closed before `/proc` scan or `inode == 0`).
    Unknown { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveOsSocket {
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemApplicationEntry {
    pub name: String,
    pub executable_path: String,
    pub running: bool,
}

impl ProcessIdentity {
    /// Returns `true` if no concrete process executable could be attributed (`pid == 0`, `"system"`, or `"pid:<n>"`).
    pub fn is_unattributed(&self) -> bool {
        self.pid == 0
            || self.name == UNKNOWN_PROCESS_NAME
            || self.executable_path.starts_with("pid:")
    }
}

impl Default for ProcessIdentity {
    fn default() -> Self {
        Self {
            pid: 0,
            name: UNKNOWN_PROCESS_NAME.to_string(),
            executable_path: UNKNOWN_PROCESS_NAME.to_string(),
        }
    }
}

#[derive(Clone)]
struct CachedProcess {
    identity: ProcessIdentity,
    cached_at: Instant,
}

#[derive(Clone)]
pub struct ProcessResolver {
    cache: Arc<DashMap<u32, CachedProcess>>,
    cache_ttl: Duration,
}

impl ProcessResolver {
    pub fn new(cache_ttl_ms: u64) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            cache_ttl: Duration::from_millis(cache_ttl_ms),
        }
    }

    pub fn resolve_by_local_tcp_port(&self, local_port: u16) -> ProcessIdentity {
        if let Some(pid) = Self::find_pid_for_tcp_port(local_port) {
            return self.resolve_by_pid(pid);
        }
        ProcessIdentity::default()
    }

    pub fn resolve_by_local_udp_port(&self, local_port: u16) -> ProcessIdentity {
        if let Some(pid) = Self::find_pid_for_udp_port(local_port) {
            return self.resolve_by_pid(pid);
        }
        ProcessIdentity::default()
    }

    /// Resolves the owning process(es) for `local_port` (TCP), distinguishing single-owner,
    /// multi-PID shared sockets (`fork`), and unknown/already-closed sockets.
    pub fn resolve_tcp_port_attribution(&self, local_port: u16) -> ProcessAttribution {
        match Self::find_all_pids_for_tcp_port(local_port) {
            Ok(pids) => self.classify_pids_for_socket(pids, local_port),
            Err(reason) => ProcessAttribution::Unknown { reason },
        }
    }

    /// Resolves the owning process(es) for `local_port` (UDP), distinguishing single-owner,
    /// multi-PID shared sockets (`fork`), and unknown/already-closed sockets.
    pub fn resolve_udp_port_attribution(&self, local_port: u16) -> ProcessAttribution {
        match Self::find_all_pids_for_udp_port(local_port) {
            Ok(pids) => self.classify_pids_for_socket(pids, local_port),
            Err(reason) => ProcessAttribution::Unknown { reason },
        }
    }

    /// Classifies a list of candidate PIDs owning a socket into `Single`, `Shared`, or `Unknown`.
    pub fn classify_pids_for_socket(
        &self,
        mut pids: Vec<u32>,
        local_port: u16,
    ) -> ProcessAttribution {
        pids.retain(|&p| p != 0);
        pids.sort_unstable();
        pids.dedup();

        match pids.len() {
            0 => ProcessAttribution::Unknown {
                reason: format!("no process fd matched local_port={local_port}"),
            },
            1 => ProcessAttribution::Single(self.resolve_by_pid(pids[0])),
            _ => {
                // Prefer the most recently spawned child process (highest PID) after fork
                let primary_pid = *pids.last().unwrap_or(&pids[0]);
                ProcessAttribution::Shared {
                    primary: self.resolve_by_pid(primary_pid),
                    candidate_pids: pids,
                }
            }
        }
    }

    fn parse_proc_net_inode(
        content: &str,
        local_port: u16,
        proc_table: &str,
    ) -> Result<u64, String> {
        let hex_port = format!("{local_port:04X}");
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > 9 {
                if let Some((_ip, port)) = fields[1].split_once(':') {
                    if port.eq_ignore_ascii_case(&hex_port) {
                        let inode = fields[9].parse::<u64>().unwrap_or(0);
                        if inode == 0 {
                            return Err(format!(
                                "socket in {proc_table} for local_port={local_port} has inode=0 (closed/TIME_WAIT)"
                            ));
                        }
                        return Ok(inode);
                    }
                }
            }
        }
        Err(format!("local_port={local_port} not found in {proc_table}"))
    }

    /// Parses `/proc/net/tcp` text content and returns the non-zero socket inode for `local_port`.
    pub fn parse_proc_net_tcp_inode(content: &str, local_port: u16) -> Result<u64, String> {
        Self::parse_proc_net_inode(content, local_port, "/proc/net/tcp")
    }

    /// Parses `/proc/net/tcp6` text content and returns the non-zero socket inode for `local_port`.
    pub fn parse_proc_net_tcp6_inode(content: &str, local_port: u16) -> Result<u64, String> {
        Self::parse_proc_net_inode(content, local_port, "/proc/net/tcp6")
    }

    /// Parses `/proc/net/udp` text content and returns the non-zero socket inode for `local_port`.
    pub fn parse_proc_net_udp_inode(content: &str, local_port: u16) -> Result<u64, String> {
        Self::parse_proc_net_inode(content, local_port, "/proc/net/udp")
    }

    /// Parses `/proc/net/udp6` text content and returns the non-zero socket inode for `local_port`.
    pub fn parse_proc_net_udp6_inode(content: &str, local_port: u16) -> Result<u64, String> {
        Self::parse_proc_net_inode(content, local_port, "/proc/net/udp6")
    }

    /// Builds a Netlink `SOCK_DIAG_BY_FAMILY` dump request (`nlmsghdr` + `inet_diag_req_v2`).
    pub fn build_inet_diag_request(
        family: u8,
        protocol: u8,
        local_port: u16,
        seq: u32,
    ) -> [u8; NETLINK_HEADER_LEN + INET_DIAG_REQ_V2_LEN] {
        let mut buf = [0u8; NETLINK_HEADER_LEN + INET_DIAG_REQ_V2_LEN];
        let total_len = buf.len() as u32;
        buf[0..4].copy_from_slice(&total_len.to_ne_bytes());
        buf[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        buf[6..8].copy_from_slice(&NLM_F_REQUEST_DUMP.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        // nlmsg_pid = 0 (kernel)

        let req = &mut buf[NETLINK_HEADER_LEN..];
        req[0] = family;
        req[1] = protocol;
        req[4..8].copy_from_slice(&u32::MAX.to_ne_bytes()); // idiag_states: all socket states
        req[8..10].copy_from_slice(&local_port.to_be_bytes());
        // INET_DIAG_NOCOOKIE sentinel
        req[48..52].copy_from_slice(&u32::MAX.to_ne_bytes());
        req[52..56].copy_from_slice(&u32::MAX.to_ne_bytes());
        buf
    }

    /// Parses one `recv()` buffer of Netlink `inet_diag_msg` records and returns
    /// `(matched_inode, saw_done)`.
    pub fn parse_inet_diag_response_inode(
        buf: &[u8],
        local_port: u16,
    ) -> Result<(Option<u64>, bool), String> {
        let mut offset = 0usize;
        while offset + NETLINK_HEADER_LEN <= buf.len() {
            let nlmsg_len = u32::from_ne_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]) as usize;
            if nlmsg_len < NETLINK_HEADER_LEN || offset + nlmsg_len > buf.len() {
                break;
            }
            let nlmsg_type = u16::from_ne_bytes([buf[offset + 4], buf[offset + 5]]);
            let payload = &buf[offset + NETLINK_HEADER_LEN..offset + nlmsg_len];

            match nlmsg_type {
                NLMSG_DONE_TYPE => return Ok((None, true)),
                NLMSG_ERROR_TYPE => {
                    if payload.len() >= 4 {
                        let errno =
                            i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        if errno != 0 {
                            return Err(format!("NETLINK_SOCK_DIAG returned error {errno}"));
                        }
                    }
                    return Ok((None, true));
                }
                NLMSG_NOOP_TYPE => {}
                SOCK_DIAG_BY_FAMILY if payload.len() >= INET_DIAG_MSG_LEN => {
                    let sport = u16::from_be_bytes([payload[4], payload[5]]);
                    let inode =
                        u32::from_ne_bytes([payload[68], payload[69], payload[70], payload[71]])
                            as u64;
                    if sport == local_port && inode != 0 {
                        return Ok((Some(inode), false));
                    }
                }
                _ => {}
            }

            let aligned = (nlmsg_len + 3) & !3;
            if aligned == 0 {
                break;
            }
            offset += aligned;
        }
        Ok((None, false))
    }

    pub fn scan_established_tcp_sockets(&self, max_entries: usize) -> Vec<ActiveOsSocket> {
        let raw_rows = Self::enumerate_established_tcp_rows(max_entries);
        raw_rows
            .into_iter()
            .map(|(pid, local_port, remote_ip, remote_port)| {
                let id = self.resolve_by_pid(pid);
                ActiveOsSocket {
                    pid,
                    process_name: id.name,
                    process_path: id.executable_path,
                    local_port,
                    remote_ip,
                    remote_port,
                }
            })
            .collect()
    }

    pub fn resolve_by_pid(&self, pid: u32) -> ProcessIdentity {
        if pid == 0 {
            return ProcessIdentity::default();
        }

        if let Some(entry) = self.cache.get(&pid) {
            if entry.cached_at.elapsed() < self.cache_ttl {
                return entry.identity.clone();
            }
        }

        let queried_path = Self::query_executable_path(pid);
        let has_resolved_image = queried_path.is_some();
        let executable_path = queried_path.unwrap_or_else(|| format!("pid:{pid}"));
        let name = Self::extract_basename(&executable_path);

        let identity = ProcessIdentity {
            pid,
            name,
            executable_path,
        };

        if has_resolved_image {
            self.cache.insert(
                pid,
                CachedProcess {
                    identity: identity.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        identity
    }

    pub fn extract_basename(path_str: &str) -> String {
        path_str
            .rsplit(PATH_SEPARATORS)
            .find(|s| !s.is_empty())
            .unwrap_or(UNKNOWN_PROCESS_NAME)
            .to_string()
    }

    pub fn list_system_applications(&self) -> Vec<SystemApplicationEntry> {
        let mut by_name: std::collections::HashMap<String, SystemApplicationEntry> =
            std::collections::HashMap::new();

        for (name, exe_path) in self.enumerate_running_processes() {
            let key = name.to_ascii_lowercase();
            if Self::is_skipped_helper_exe(&key) {
                continue;
            }
            by_name.entry(key).or_insert(SystemApplicationEntry {
                name,
                executable_path: exe_path,
                running: true,
            });
        }

        for (name, exe_path) in Self::scan_installed_application_exes(150) {
            let key = name.to_ascii_lowercase();
            if Self::is_skipped_helper_exe(&key) {
                continue;
            }
            by_name.entry(key).or_insert(SystemApplicationEntry {
                name,
                executable_path: exe_path,
                running: false,
            });
        }

        let mut list: Vec<SystemApplicationEntry> = by_name.into_values().collect();
        list.sort_by(|a, b| {
            b.running.cmp(&a.running).then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
        });
        list
    }

    fn is_skipped_helper_exe(lower_name: &str) -> bool {
        lower_name.is_empty()
            || lower_name == UNKNOWN_PROCESS_NAME
            || lower_name.starts_with("pid:")
            || lower_name.starts_with("unins")
            || lower_name.contains("crashpad")
            || lower_name.contains("helper")
            || lower_name == "setup.exe"
    }

    #[cfg(windows)]
    fn enumerate_running_processes(&self) -> Vec<(String, String)> {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut out = Vec::new();
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return out;
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
                    let fallback_name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                    let resolved = self.resolve_by_pid(entry.th32ProcessID);
                    let is_unattributed = resolved.is_unattributed();
                    let name = if is_unattributed {
                        fallback_name.clone()
                    } else {
                        resolved.name
                    };
                    let exe_path = if is_unattributed {
                        fallback_name
                    } else {
                        resolved.executable_path
                    };
                    if !name.is_empty() {
                        out.push((name, exe_path));
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
        out
    }

    #[cfg(not(windows))]
    fn enumerate_running_processes(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if pid == 0 {
                continue;
            }
            let id = self.resolve_by_pid(pid);
            if !id.is_unattributed() {
                out.push((id.name, id.executable_path));
            }
        }
        out
    }

    #[cfg(windows)]
    fn scan_installed_application_exes(max_entries: usize) -> Vec<(String, String)> {
        let mut roots: Vec<std::path::PathBuf> = Vec::new();
        for env_key in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Ok(val) = std::env::var(env_key) {
                roots.push(std::path::PathBuf::from(val));
            }
        }
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            roots.push(std::path::PathBuf::from(local_app_data).join("Programs"));
        }

        let mut out = Vec::new();
        for root in roots {
            Self::scan_exe_dir_bounded(&root, 0, 2, max_entries, &mut out);
            if out.len() >= max_entries {
                break;
            }
        }
        out
    }

    #[cfg(not(windows))]
    fn scan_exe_dir_bounded(
        _dir: &std::path::Path,
        _depth: usize,
        _max_depth: usize,
        _max_entries: usize,
        _out: &mut Vec<(String, String)>,
    ) {
    }

    #[cfg(windows)]
    fn scan_exe_dir_bounded(
        dir: &std::path::Path,
        depth: usize,
        max_depth: usize,
        max_entries: usize,
        out: &mut Vec<(String, String)>,
    ) {
        if depth > max_depth || out.len() >= max_entries {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            if out.len() >= max_entries {
                break;
            }
            let path = entry.path();
            if path.is_dir() {
                Self::scan_exe_dir_bounded(&path, depth + 1, max_depth, max_entries, out);
            } else if path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("exe"))
                .unwrap_or(false)
            {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    out.push((name.to_string(), path.to_string_lossy().into_owned()));
                }
            }
        }
    }

    #[cfg(not(windows))]
    fn scan_installed_application_exes(max_entries: usize) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for dir in ["/usr/bin", "/usr/local/bin"] {
            let Ok(rd) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in rd.flatten() {
                if out.len() >= max_entries {
                    return out;
                }
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        out.push((name.to_string(), path.to_string_lossy().into_owned()));
                    }
                }
            }
        }
        out
    }

    #[cfg(windows)]
    fn query_iphelper_buffer<F>(fetch: F) -> Option<Vec<u8>>
    where
        F: Fn(*mut u8, &mut u32) -> u32,
    {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};

        let mut buffer_size: u32 = 0;
        let initial_status = fetch(std::ptr::null_mut(), &mut buffer_size);
        if initial_status != ERROR_INSUFFICIENT_BUFFER && initial_status != NO_ERROR {
            return None;
        }

        let mut buffer = vec![0u8; buffer_size as usize];
        if fetch(buffer.as_mut_ptr(), &mut buffer_size) != NO_ERROR {
            return None;
        }
        Some(buffer)
    }

    #[cfg(windows)]
    pub fn find_pid_for_tcp_port(local_port: u16) -> Option<u32> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

        if let Some(buffer) = Self::query_iphelper_buffer(|ptr, size| unsafe {
            GetExtendedTcpTable(
                ptr as *mut _,
                size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }) {
            let table_ptr = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
            let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
            let rows: &[MIB_TCPROW_OWNER_PID] =
                unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

            for row in rows {
                let port_net = (row.dwLocalPort & 0xFFFF) as u16;
                if u16::from_be(port_net) == local_port {
                    return Some(row.dwOwningPid);
                }
            }
        }

        if let Some(buffer) = Self::query_iphelper_buffer(|ptr, size| unsafe {
            GetExtendedTcpTable(
                ptr as *mut _,
                size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }) {
            let table_ptr = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
            let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
            let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
            let rows: &[MIB_TCP6ROW_OWNER_PID] =
                unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

            for row in rows {
                let port_net = (row.dwLocalPort & 0xFFFF) as u16;
                if u16::from_be(port_net) == local_port {
                    return Some(row.dwOwningPid);
                }
            }
        }

        None
    }

    #[cfg(windows)]
    pub fn find_pid_for_udp_port(local_port: u16) -> Option<u32> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
            MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

        if let Some(buffer) = Self::query_iphelper_buffer(|ptr, size| unsafe {
            GetExtendedUdpTable(
                ptr as *mut _,
                size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        }) {
            let table_ptr = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
            let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
            let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
            let rows: &[MIB_UDPROW_OWNER_PID] =
                unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

            for row in rows {
                let port_net = (row.dwLocalPort & 0xFFFF) as u16;
                if u16::from_be(port_net) == local_port {
                    return Some(row.dwOwningPid);
                }
            }
        }

        if let Some(buffer) = Self::query_iphelper_buffer(|ptr, size| unsafe {
            GetExtendedUdpTable(
                ptr as *mut _,
                size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        }) {
            let table_ptr = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
            let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
            let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
            let rows: &[MIB_UDP6ROW_OWNER_PID] =
                unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

            for row in rows {
                let port_net = (row.dwLocalPort & 0xFFFF) as u16;
                if u16::from_be(port_net) == local_port {
                    return Some(row.dwOwningPid);
                }
            }
        }

        None
    }

    #[cfg(windows)]
    fn enumerate_established_tcp_rows(max_entries: usize) -> Vec<(u32, u16, String, u16)> {
        use std::net::{Ipv4Addr, Ipv6Addr};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_ESTAB,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

        let mut out = Vec::new();
        if let Some(buffer) = Self::query_iphelper_buffer(|ptr, size| unsafe {
            GetExtendedTcpTable(
                ptr as *mut _,
                size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        }) {
            let table_ptr = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
            let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
            let rows: &[MIB_TCPROW_OWNER_PID] =
                unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

            for row in rows {
                if row.dwState != MIB_TCP_STATE_ESTAB as u32 {
                    continue;
                }
                let remote_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                if remote_ip.is_loopback() || remote_ip.is_unspecified() {
                    continue;
                }
                let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
                out.push((
                    row.dwOwningPid,
                    local_port,
                    remote_ip.to_string(),
                    remote_port,
                ));
                if out.len() >= max_entries {
                    return out;
                }
            }
        }

        if out.len() < max_entries {
            if let Some(buffer) = Self::query_iphelper_buffer(|ptr, size| unsafe {
                GetExtendedTcpTable(
                    ptr as *mut _,
                    size,
                    0,
                    AF_INET6 as u32,
                    TCP_TABLE_OWNER_PID_CONNECTIONS,
                    0,
                )
            }) {
                let table_ptr = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
                let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
                let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
                let rows: &[MIB_TCP6ROW_OWNER_PID] =
                    unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

                for row in rows {
                    if row.dwState != MIB_TCP_STATE_ESTAB as u32 {
                        continue;
                    }
                    let remote_ip = Ipv6Addr::from(row.ucRemoteAddr);
                    if remote_ip.is_loopback() || remote_ip.is_unspecified() {
                        continue;
                    }
                    let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                    let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
                    out.push((
                        row.dwOwningPid,
                        local_port,
                        remote_ip.to_string(),
                        remote_port,
                    ));
                    if out.len() >= max_entries {
                        break;
                    }
                }
            }
        }
        out
    }

    #[cfg(windows)]
    fn query_executable_path(pid: u32) -> Option<String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        const MAX_PATH_CHARS: usize = 1024;
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }

        let mut wide_buf = vec![0u16; MAX_PATH_CHARS];
        let mut size = wide_buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(handle, 0, wide_buf.as_mut_ptr(), &mut size) };
        unsafe {
            CloseHandle(handle);
        }

        if ok == 0 || size == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&wide_buf[..size as usize]))
    }

    #[cfg(windows)]
    fn find_all_pids_for_tcp_port(local_port: u16) -> Result<Vec<u32>, String> {
        match Self::find_pid_for_tcp_port(local_port) {
            Some(pid) if pid != 0 => Ok(vec![pid]),
            _ => Err(format!(
                "local_port={local_port} not found in GetExtendedTcpTable"
            )),
        }
    }

    #[cfg(windows)]
    fn find_all_pids_for_udp_port(local_port: u16) -> Result<Vec<u32>, String> {
        match Self::find_pid_for_udp_port(local_port) {
            Some(pid) if pid != 0 => Ok(vec![pid]),
            _ => Err(format!(
                "local_port={local_port} not found in GetExtendedUdpTable"
            )),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn find_pid_for_tcp_port(local_port: u16) -> Option<u32> {
        Self::find_all_pids_for_tcp_port(local_port)
            .ok()
            .and_then(|pids| pids.into_iter().last())
    }

    #[cfg(target_os = "linux")]
    pub fn find_pid_for_udp_port(local_port: u16) -> Option<u32> {
        Self::find_all_pids_for_udp_port(local_port)
            .ok()
            .and_then(|pids| pids.into_iter().last())
    }

    #[cfg(target_os = "linux")]
    fn query_netlink_sock_diag_inode(protocol: u8, local_port: u16) -> Result<Option<u64>, String> {
        struct NetlinkFd(libc::c_int);
        impl Drop for NetlinkFd {
            fn drop(&mut self) {
                if self.0 >= 0 {
                    unsafe {
                        libc::close(self.0);
                    }
                }
            }
        }

        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if raw_fd < 0 {
            return Err(format!(
                "NETLINK_SOCK_DIAG socket creation failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = NetlinkFd(raw_fd);

        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        unsafe {
            libc::setsockopt(
                fd.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd.0,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let mut recv_buf = vec![0u8; 16 * 1024];
        for (seq_idx, family) in [LINUX_AF_INET, LINUX_AF_INET6].iter().enumerate() {
            let req =
                Self::build_inet_diag_request(*family, protocol, local_port, (seq_idx + 1) as u32);
            let sent = unsafe { libc::send(fd.0, req.as_ptr().cast(), req.len(), 0) };
            if sent < 0 {
                return Err(format!(
                    "NETLINK_SOCK_DIAG send failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            loop {
                let recvd =
                    unsafe { libc::recv(fd.0, recv_buf.as_mut_ptr().cast(), recv_buf.len(), 0) };
                if recvd <= 0 {
                    break;
                }
                match Self::parse_inet_diag_response_inode(&recv_buf[..recvd as usize], local_port)
                {
                    Ok((Some(inode), _)) => return Ok(Some(inode)),
                    Ok((None, true)) => break,
                    Ok((None, false)) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(None)
    }

    #[cfg(target_os = "linux")]
    fn find_inode_in_proc_tables(tables: &[&str], local_port: u16) -> Result<u64, String> {
        let mut last_err = String::new();
        for table in tables {
            match std::fs::read_to_string(table) {
                Ok(content) => match Self::parse_proc_net_inode(&content, local_port, table) {
                    Ok(inode) => return Ok(inode),
                    Err(e) => last_err = e,
                },
                Err(e) => last_err = format!("failed reading {table}: {e}"),
            }
        }
        Err(last_err)
    }

    #[cfg(target_os = "linux")]
    fn find_all_pids_for_tcp_port(local_port: u16) -> Result<Vec<u32>, String> {
        if let Ok(Some(inode)) = Self::query_netlink_sock_diag_inode(LINUX_IPPROTO_TCP, local_port)
        {
            if let Ok(pids) = Self::find_all_pids_for_socket_inode(inode, local_port) {
                return Ok(pids);
            }
        }
        let inode =
            Self::find_inode_in_proc_tables(&["/proc/net/tcp", "/proc/net/tcp6"], local_port)?;
        Self::find_all_pids_for_socket_inode(inode, local_port)
    }

    #[cfg(target_os = "linux")]
    fn find_all_pids_for_udp_port(local_port: u16) -> Result<Vec<u32>, String> {
        if let Ok(Some(inode)) = Self::query_netlink_sock_diag_inode(LINUX_IPPROTO_UDP, local_port)
        {
            if let Ok(pids) = Self::find_all_pids_for_socket_inode(inode, local_port) {
                return Ok(pids);
            }
        }
        let inode =
            Self::find_inode_in_proc_tables(&["/proc/net/udp", "/proc/net/udp6"], local_port)?;
        Self::find_all_pids_for_socket_inode(inode, local_port)
    }

    #[cfg(target_os = "linux")]
    fn find_all_pids_for_socket_inode(inode: u64, local_port: u16) -> Result<Vec<u32>, String> {
        use parking_lot::Mutex;
        use std::collections::HashMap;
        use std::fs;
        use std::sync::OnceLock;

        const LINUX_INODE_CACHE_TTL_MS: u64 = 250;
        struct InodeSnapshot {
            captured_at: Instant,
            by_inode: HashMap<u64, Vec<u32>>,
        }
        static INODE_SNAPSHOT: OnceLock<Mutex<Option<InodeSnapshot>>> = OnceLock::new();

        let cache = INODE_SNAPSHOT.get_or_init(|| Mutex::new(None));
        {
            let guard = cache.lock();
            if let Some(ref snap) = *guard {
                if snap.captured_at.elapsed() <= Duration::from_millis(LINUX_INODE_CACHE_TTL_MS) {
                    if let Some(pids) = snap.by_inode.get(&inode) {
                        if !pids.is_empty() {
                            return Ok(pids.clone());
                        }
                    }
                }
            }
        }

        let self_pid = std::process::id();
        let proc_dir = fs::read_dir("/proc").map_err(|e| format!("failed reading /proc: {e}"))?;
        let mut by_inode: HashMap<u64, Vec<u32>> = HashMap::new();

        for proc_entry in proc_dir.flatten() {
            let file_name = proc_entry.file_name();
            let Some(pid_str) = file_name.to_str() else {
                continue;
            };
            if let Ok(pid) = pid_str.parse::<u32>() {
                if pid == self_pid {
                    continue;
                }
                let fd_dir = proc_entry.path().join("fd");
                if let Ok(fds) = fs::read_dir(fd_dir) {
                    for fd in fds.flatten() {
                        if let Ok(link) = fs::read_link(fd.path()) {
                            let target = link.to_string_lossy();
                            if let Some(inner) = target
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(fd_inode) = inner.parse::<u64>() {
                                    by_inode.entry(fd_inode).or_default().push(pid);
                                }
                            }
                        }
                    }
                }
            }
        }

        let matched_pids = by_inode.get(&inode).cloned().unwrap_or_default();
        *cache.lock() = Some(InodeSnapshot {
            captured_at: Instant::now(),
            by_inode,
        });

        if matched_pids.is_empty() {
            return Err(format!(
                "socket inode={inode} for local_port={local_port} not found in /proc/*/fd"
            ));
        }
        Ok(matched_pids)
    }

    #[cfg(target_os = "linux")]
    fn query_executable_path(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    #[cfg(not(windows))]
    fn enumerate_established_tcp_rows(_max_entries: usize) -> Vec<(u32, u16, String, u16)> {
        Vec::new()
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    pub fn find_pid_for_tcp_port(_local_port: u16) -> Option<u32> {
        None
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    pub fn find_pid_for_udp_port(_local_port: u16) -> Option<u32> {
        None
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    fn find_all_pids_for_tcp_port(local_port: u16) -> Result<Vec<u32>, String> {
        Err(format!("unsupported platform for local_port={local_port}"))
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    fn find_all_pids_for_udp_port(local_port: u16) -> Result<Vec<u32>, String> {
        Err(format!("unsupported platform for local_port={local_port}"))
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    fn query_executable_path(_pid: u32) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PROC_NET_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2A38 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18420 1 0000000000000000 100 0 0 10 0
   1: 881FA8C0:C350 0ED7B85D:0050 01 00000000:00000000 00:00000000 00000000  1000        0 49215 1 0000000000000000 20 4 30 10 -1
   2: 881FA8C0:C351 0ED7B85D:0050 06 00000000:00000000 03:0000012C 00000000     0        0 0 3 0000000000000000";

    #[test]
    fn parses_proc_net_tcp_inode_and_handles_closed_or_missing_sockets() {
        // Port 50000 (0xC350) -> active socket with inode 49215
        assert_eq!(
            ProcessResolver::parse_proc_net_tcp_inode(SAMPLE_PROC_NET_TCP, 50000),
            Ok(49215)
        );

        // Port 50001 (0xC351) -> TIME_WAIT socket with inode 0 -> returns Err
        let err_closed = ProcessResolver::parse_proc_net_tcp_inode(SAMPLE_PROC_NET_TCP, 50001)
            .expect_err("inode 0 must be treated as closed");
        assert!(err_closed.contains("inode=0"));

        // Non-existent port 55555 -> returns Err
        let err_missing = ProcessResolver::parse_proc_net_tcp_inode(SAMPLE_PROC_NET_TCP, 55555)
            .expect_err("missing port must return Err");
        assert!(err_missing.contains("not found"));

        // UDP table parsing uses the same column layout
        assert_eq!(
            ProcessResolver::parse_proc_net_udp_inode(SAMPLE_PROC_NET_TCP, 50000),
            Ok(49215)
        );
        assert!(ProcessResolver::parse_proc_net_udp_inode(SAMPLE_PROC_NET_TCP, 50001).is_err());
        assert!(ProcessResolver::parse_proc_net_udp_inode(SAMPLE_PROC_NET_TCP, 55555).is_err());
    }

    #[test]
    fn classifies_single_shared_fork_and_unknown_socket_pids() {
        let resolver = ProcessResolver::new(5000);

        let unknown = resolver.classify_pids_for_socket(vec![], 50000);
        assert!(matches!(unknown, ProcessAttribution::Unknown { .. }));

        let single = resolver.classify_pids_for_socket(vec![1010], 50000);
        match single {
            ProcessAttribution::Single(id) => assert_eq!(id.pid, 1010),
            other => panic!("Expected Single, got {other:?}"),
        }

        let shared = resolver.classify_pids_for_socket(vec![1010, 2048, 1010], 50000);
        match shared {
            ProcessAttribution::Shared {
                primary,
                candidate_pids,
            } => {
                assert_eq!(primary.pid, 2048);
                assert_eq!(candidate_pids, vec![1010, 2048]);
            }
            other => panic!("Expected Shared, got {other:?}"),
        }
    }

    #[test]
    fn builds_and_parses_inet_diag_request_and_response() {
        let req_v4_udp =
            ProcessResolver::build_inet_diag_request(LINUX_AF_INET, LINUX_IPPROTO_UDP, 5353, 1);
        assert_eq!(req_v4_udp[NETLINK_HEADER_LEN], LINUX_AF_INET);
        assert_eq!(req_v4_udp[NETLINK_HEADER_LEN + 1], LINUX_IPPROTO_UDP);

        let req =
            ProcessResolver::build_inet_diag_request(LINUX_AF_INET6, LINUX_IPPROTO_TCP, 45123, 7);
        assert_eq!(req.len(), NETLINK_HEADER_LEN + INET_DIAG_REQ_V2_LEN);
        assert_eq!(u16::from_ne_bytes([req[4], req[5]]), SOCK_DIAG_BY_FAMILY);
        assert_eq!(u16::from_ne_bytes([req[6], req[7]]), NLM_F_REQUEST_DUMP);
        assert_eq!(req[NETLINK_HEADER_LEN], LINUX_AF_INET6);
        assert_eq!(req[NETLINK_HEADER_LEN + 1], LINUX_IPPROTO_TCP);
        assert_eq!(
            u16::from_be_bytes([req[NETLINK_HEADER_LEN + 8], req[NETLINK_HEADER_LEN + 9]]),
            45123
        );

        let msg_total = NETLINK_HEADER_LEN + INET_DIAG_MSG_LEN;
        let done_total = NETLINK_HEADER_LEN;
        let mut response = vec![0u8; msg_total * 2 + done_total];

        // Record 0: unrelated port with inode 111
        response[0..4].copy_from_slice(&(msg_total as u32).to_ne_bytes());
        response[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        response[NETLINK_HEADER_LEN + 4..NETLINK_HEADER_LEN + 6]
            .copy_from_slice(&12000u16.to_be_bytes());
        response[NETLINK_HEADER_LEN + 68..NETLINK_HEADER_LEN + 72]
            .copy_from_slice(&111u32.to_ne_bytes());

        // Record 1: matching port 45123 with inode 987654
        let rec1 = msg_total;
        response[rec1..rec1 + 4].copy_from_slice(&(msg_total as u32).to_ne_bytes());
        response[rec1 + 4..rec1 + 6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        response[rec1 + NETLINK_HEADER_LEN + 4..rec1 + NETLINK_HEADER_LEN + 6]
            .copy_from_slice(&45123u16.to_be_bytes());
        response[rec1 + NETLINK_HEADER_LEN + 68..rec1 + NETLINK_HEADER_LEN + 72]
            .copy_from_slice(&987654u32.to_ne_bytes());

        // Record 2: NLMSG_DONE
        let rec2 = msg_total * 2;
        response[rec2..rec2 + 4].copy_from_slice(&(done_total as u32).to_ne_bytes());
        response[rec2 + 4..rec2 + 6].copy_from_slice(&NLMSG_DONE_TYPE.to_ne_bytes());

        let (matched, done) = ProcessResolver::parse_inet_diag_response_inode(&response, 45123)
            .expect("should parse diag stream");
        assert_eq!(matched, Some(987654));
        assert!(!done);

        let (missing, done_missing) =
            ProcessResolver::parse_inet_diag_response_inode(&response, 55555)
                .expect("should terminate at NLMSG_DONE");
        assert_eq!(missing, None);
        assert!(done_missing);
    }

    #[test]
    fn parses_proc_net_tcp6_and_udp6_inodes() {
        let tcp6_sample = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:B043 00000000000000000000000000000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 778899 1 0000000000000000 20 4 28 10 -1\n";
        assert_eq!(
            ProcessResolver::parse_proc_net_tcp6_inode(tcp6_sample, 0xB043).unwrap(),
            778899
        );

        let udp6_sample = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
   1: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 554433 2 0000000000000000 0\n";
        assert_eq!(
            ProcessResolver::parse_proc_net_udp6_inode(udp6_sample, 0x14E9).unwrap(),
            554433
        );
    }

    #[test]
    fn lists_system_applications_sorted_and_deduplicated() {
        let resolver = ProcessResolver::new(5000);
        let apps = resolver.list_system_applications();
        assert!(
            !apps.is_empty(),
            "at least the running test executable must be listed"
        );
        let mut seen = std::collections::HashSet::new();
        for window in apps.windows(2) {
            let a = &window[0];
            let b = &window[1];
            assert!(
                (!a.running && !b.running) || (a.running >= b.running),
                "running entries should sort before installed-only entries: {a:?} vs {b:?}"
            );
            if a.running == b.running {
                assert!(
                    a.name.to_ascii_lowercase() <= b.name.to_ascii_lowercase(),
                    "entries should be sorted alphabetically within running group: {a:?} vs {b:?}"
                );
            }
        }
        for app in &apps {
            let key = app.name.to_ascii_lowercase();
            assert!(
                seen.insert(key),
                "duplicate application entry returned: {}",
                app.name
            );
        }
    }
}
