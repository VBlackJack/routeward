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

    /// Parses `/proc/net/tcp` text content and returns the non-zero socket inode for `local_port`.
    pub fn parse_proc_net_tcp_inode(content: &str, local_port: u16) -> Result<u64, String> {
        let hex_port = format!("{local_port:04X}");
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > 9 {
                if let Some((_ip, port)) = fields[1].split_once(':') {
                    if port.eq_ignore_ascii_case(&hex_port) {
                        let inode = fields[9].parse::<u64>().unwrap_or(0);
                        if inode == 0 {
                            return Err(format!(
                                "socket for local_port={local_port} has inode=0 (closed/TIME_WAIT)"
                            ));
                        }
                        return Ok(inode);
                    }
                }
            }
        }
        Err(format!(
            "local_port={local_port} not found in /proc/net/tcp"
        ))
    }

    /// Parses `/proc/net/udp` text content and returns the non-zero socket inode for `local_port`.
    pub fn parse_proc_net_udp_inode(content: &str, local_port: u16) -> Result<u64, String> {
        let hex_port = format!("{local_port:04X}");
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > 9 {
                if let Some((_ip, port)) = fields[1].split_once(':') {
                    if port.eq_ignore_ascii_case(&hex_port) {
                        let inode = fields[9].parse::<u64>().unwrap_or(0);
                        if inode == 0 {
                            return Err(format!(
                                "UDP socket for local_port={local_port} has inode=0 (closed)"
                            ));
                        }
                        return Ok(inode);
                    }
                }
            }
        }
        Err(format!(
            "local_port={local_port} not found in /proc/net/udp"
        ))
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

    #[cfg(windows)]
    pub fn find_pid_for_tcp_port(local_port: u16) -> Option<u32> {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        let mut buffer_size: u32 = 0;
        // First call determines required buffer size
        let initial_status = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut buffer_size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        if initial_status != ERROR_INSUFFICIENT_BUFFER && initial_status != NO_ERROR {
            return None;
        }

        let mut buffer = vec![0u8; buffer_size as usize];
        let status = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut buffer_size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        if status != NO_ERROR {
            return None;
        }

        let table_ptr = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
        let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
        let rows: &[MIB_TCPROW_OWNER_PID] =
            unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

        for row in rows {
            let port_net = (row.dwLocalPort & 0xFFFF) as u16;
            let row_port = u16::from_be(port_net);
            if row_port == local_port {
                return Some(row.dwOwningPid);
            }
        }
        None
    }

    #[cfg(windows)]
    pub fn find_pid_for_udp_port(local_port: u16) -> Option<u32> {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        let mut buffer_size: u32 = 0;
        let initial_status = unsafe {
            GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut buffer_size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };

        if initial_status != ERROR_INSUFFICIENT_BUFFER && initial_status != NO_ERROR {
            return None;
        }

        let mut buffer = vec![0u8; buffer_size as usize];
        let status = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut buffer_size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };

        if status != NO_ERROR {
            return None;
        }

        let table_ptr = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
        let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
        let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
        let rows: &[MIB_UDPROW_OWNER_PID] =
            unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

        for row in rows {
            let port_net = (row.dwLocalPort & 0xFFFF) as u16;
            let row_port = u16::from_be(port_net);
            if row_port == local_port {
                return Some(row.dwOwningPid);
            }
        }
        None
    }

    #[cfg(windows)]
    fn enumerate_established_tcp_rows(max_entries: usize) -> Vec<(u32, u16, String, u16)> {
        use std::net::Ipv4Addr;
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_ESTAB,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        let mut buffer_size: u32 = 0;
        let initial_status = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut buffer_size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };

        if initial_status != ERROR_INSUFFICIENT_BUFFER && initial_status != NO_ERROR {
            return Vec::new();
        }

        let mut buffer = vec![0u8; buffer_size as usize];
        let status = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut buffer_size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };

        if status != NO_ERROR {
            return Vec::new();
        }

        let table_ptr = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
        let first_row_ptr = unsafe { (*table_ptr).table.as_ptr() };
        let rows: &[MIB_TCPROW_OWNER_PID] =
            unsafe { std::slice::from_raw_parts(first_row_ptr, num_entries) };

        let mut out = Vec::new();
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
                break;
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
    fn find_all_pids_for_tcp_port(local_port: u16) -> Result<Vec<u32>, String> {
        let content = std::fs::read_to_string("/proc/net/tcp")
            .map_err(|e| format!("failed reading /proc/net/tcp: {e}"))?;
        let inode = Self::parse_proc_net_tcp_inode(&content, local_port)?;
        Self::find_all_pids_for_socket_inode(inode, local_port)
    }

    #[cfg(target_os = "linux")]
    fn find_all_pids_for_udp_port(local_port: u16) -> Result<Vec<u32>, String> {
        let content = std::fs::read_to_string("/proc/net/udp")
            .map_err(|e| format!("failed reading /proc/net/udp: {e}"))?;
        let inode = Self::parse_proc_net_udp_inode(&content, local_port)?;
        Self::find_all_pids_for_socket_inode(inode, local_port)
    }

    #[cfg(target_os = "linux")]
    fn find_all_pids_for_socket_inode(inode: u64, local_port: u16) -> Result<Vec<u32>, String> {
        use std::fs;
        let socket_tag = format!("socket:[{inode}]");
        let self_pid = std::process::id();
        let mut matched_pids = Vec::new();

        let proc_dir = fs::read_dir("/proc").map_err(|e| format!("failed reading /proc: {e}"))?;
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
                            if link.to_string_lossy() == socket_tag {
                                matched_pids.push(pid);
                                break;
                            }
                        }
                    }
                }
            }
        }

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
}
