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
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const UNKNOWN_PROCESS_NAME: &str = "system";
const PATH_SEPARATORS: &[char] = &['/', '\\'];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,
    pub executable_path: String,
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

        let executable_path =
            Self::query_executable_path(pid).unwrap_or_else(|| format!("pid:{pid}"));
        let name = Self::extract_basename(&executable_path);

        let identity = ProcessIdentity {
            pid,
            name,
            executable_path,
        };

        self.cache.insert(
            pid,
            CachedProcess {
                identity: identity.clone(),
                cached_at: Instant::now(),
            },
        );

        identity
    }

    pub fn extract_basename(path_str: &str) -> String {
        Path::new(path_str)
            .file_name()
            .and_then(|os| os.to_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                path_str
                    .rsplit(PATH_SEPARATORS)
                    .next()
                    .unwrap_or(UNKNOWN_PROCESS_NAME)
                    .to_string()
            })
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

    #[cfg(target_os = "linux")]
    pub fn find_pid_for_tcp_port(local_port: u16) -> Option<u32> {
        use std::fs;
        let hex_port = format!("{:04X}", local_port);
        let content = fs::read_to_string("/proc/net/tcp").ok()?;
        let mut target_inode: Option<String> = None;

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > 9 {
                if let Some((_ip, port)) = fields[1].split_once(':') {
                    if port.eq_ignore_ascii_case(&hex_port) {
                        target_inode = Some(fields[9].to_string());
                        break;
                    }
                }
            }
        }

        let inode = target_inode?;
        let socket_tag = format!("socket:[{inode}]");
        for proc_entry in fs::read_dir("/proc").ok()?.flatten() {
            let file_name = proc_entry.file_name();
            let pid_str = file_name.to_str()?;
            if let Ok(pid) = pid_str.parse::<u32>() {
                let fd_dir = proc_entry.path().join("fd");
                if let Ok(fds) = fs::read_dir(fd_dir) {
                    for fd in fds.flatten() {
                        if let Ok(link) = fs::read_link(fd.path()) {
                            if link.to_string_lossy() == socket_tag {
                                return Some(pid);
                            }
                        }
                    }
                }
            }
        }
        None
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
    fn query_executable_path(_pid: u32) -> Option<String> {
        None
    }
}
