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

#[cfg(not(target_os = "linux"))]
use crate::error::ERR_KEY_INTERCEPTOR_DRIVER;
use crate::error::{RouteWardError, RouteWardResult};
#[cfg(target_os = "linux")]
use crate::error::{
    ERR_KEY_INTERCEPTOR_NFT_FAILED, ERR_KEY_INTERCEPTOR_NFT_MISSING, ERR_KEY_INTERCEPTOR_NOT_ROOT,
};
use crate::interceptor::backend::Interceptor;
use crate::interceptor::RouteWardController;
use crate::telemetry::{LogLevel, TelemetryHub};
use parking_lot::Mutex;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const BACKEND_NAME: &str = "nftables";
const COMPONENT_NFTABLES: &str = "NftablesInterceptor";
const AF_INET_U16: u16 = 2;

struct NftActiveState {
    nft_binary: String,
    table_name: String,
    watchdog_stdin: Option<ChildStdin>,
    watchdog_child: Option<Child>,
    telemetry: TelemetryHub,
}

/// Linux transparent IPv4 TCP interceptor backed by a dedicated `nftables` table
/// (`table ip <table_name>`) and a pipe-linked fail-open watchdog process.
pub struct NftablesInterceptor {
    active: Arc<AtomicBool>,
    state: Mutex<Option<NftActiveState>>,
}

impl Default for NftablesInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl NftablesInterceptor {
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(None),
        }
    }

    /// Generates the dedicated `nftables` ruleset for `nft -f -`.
    pub fn build_nft_table_ruleset(
        table_name: &str,
        chain_name: &str,
        fwmark: u32,
        relay_port: u16,
        upstream_endpoints: &[(Ipv4Addr, u16)],
    ) -> String {
        let mut script = String::with_capacity(512);
        script.push_str(&format!("table ip {table_name} {{\n"));
        script.push_str(&format!("    chain {chain_name} {{\n"));
        script.push_str("        type nat hook output priority -100; policy accept;\n");
        script.push_str(&format!("        meta mark {fwmark} return\n"));
        script.push_str("        ip daddr 127.0.0.0/8 return\n");
        for (ip, port) in upstream_endpoints {
            if !ip.is_loopback() {
                script.push_str(&format!("        ip daddr {ip} tcp dport {port} return\n"));
            }
        }
        script.push_str(&format!(
            "        tcp dport 1-65535 redirect to :{relay_port}\n"
        ));
        script.push_str("    }\n");
        script.push_str("}\n");
        script
    }

    /// Deletes the dedicated `nftables` table if it exists.
    pub fn delete_nft_table(
        nft_binary: &str,
        table_name: &str,
        telemetry: &TelemetryHub,
    ) -> RouteWardResult<()> {
        match Command::new(nft_binary)
            .args(["delete", "table", "ip", table_name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(out) if out.status.success() => {
                telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!("Removed nftables table \"ip {table_name}\""),
                );
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let trimmed = stderr.trim();
                // If table does not exist ("No such file or directory"), treat cleanup as idempotent success.
                if trimmed.contains("No such file or directory")
                    || trimmed.contains("does not exist")
                {
                    telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_NFTABLES,
                        format!(
                            "nftables table \"ip {table_name}\" was already absent during cleanup"
                        ),
                    );
                    Ok(())
                } else {
                    telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_NFTABLES,
                        format!(
                            "Could not delete nftables table \"ip {table_name}\" (exit={:?}): {trimmed}",
                            out.status.code()
                        ),
                    );
                    Ok(())
                }
            }
            Err(err) => {
                telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_NFTABLES,
                    format!(
                        "Failed invoking {nft_binary} to delete table \"ip {table_name}\": {err}"
                    ),
                );
                Ok(())
            }
        }
    }

    /// Pure parser converting raw `sockaddr_in` fields (network byte order) into `SocketAddrV4`.
    pub fn parse_sockaddr_in_fields(
        sin_family: u16,
        sin_port_be: u16,
        sin_addr_be: u32,
        relay_port: u16,
    ) -> Option<SocketAddrV4> {
        if sin_family != AF_INET_U16 {
            return None;
        }
        let port = u16::from_be(sin_port_be);
        let ip = Ipv4Addr::from(u32::from_be(sin_addr_be));
        if port == 0 {
            return None;
        }
        // Reject direct unredirected connections whose original destination is the local relay itself
        if ip.is_loopback() && port == relay_port {
            return None;
        }
        Some(SocketAddrV4::new(ip, port))
    }

    /// Queries `getsockopt(SOL_IP, SO_ORIGINAL_DST)` on an accepted Linux TCP stream.
    #[cfg(target_os = "linux")]
    pub fn query_original_dst(
        stream: &tokio::net::TcpStream,
        relay_port: u16,
    ) -> Option<SocketAddrV4> {
        use std::os::fd::AsRawFd;

        let fd = stream.as_raw_fd();
        let mut raw_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut raw_addr as *mut libc::sockaddr_in as *mut libc::c_void,
                &mut addr_len,
            )
        };
        if ret != 0 {
            return None;
        }

        Self::parse_sockaddr_in_fields(
            raw_addr.sin_family,
            raw_addr.sin_port,
            raw_addr.sin_addr.s_addr,
            relay_port,
        )
    }

    #[cfg(not(target_os = "linux"))]
    pub fn query_original_dst(
        _stream: &tokio::net::TcpStream,
        _relay_port: u16,
    ) -> Option<SocketAddrV4> {
        None
    }

    /// Immediately resets (`TCP RST`) an accepted connection via `SO_LINGER(1, 0)` and closes it.
    #[cfg(target_os = "linux")]
    pub fn reset_and_close_tcp_stream(stream: tokio::net::TcpStream) {
        use std::os::fd::AsRawFd;

        let fd = stream.as_raw_fd();
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
        drop(stream);
    }

    #[cfg(not(target_os = "linux"))]
    pub fn reset_and_close_tcp_stream(stream: tokio::net::TcpStream) {
        drop(stream);
    }
}

impl Interceptor for NftablesInterceptor {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    #[cfg(target_os = "linux")]
    fn start(&self, controller: RouteWardController) -> RouteWardResult<()> {
        use std::io::Write;
        use std::os::unix::process::CommandExt;

        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        // 1. Mandatory root privilege check (Milestone 2 runs as root only)
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            self.active.store(false, Ordering::SeqCst);
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NOT_ROOT,
                detail: controller.i18n.t(ERR_KEY_INTERCEPTOR_NOT_ROOT),
            });
        }

        let net = &controller.constants.network;
        let nft_bin = net.linux_nft_binary.clone();
        let table_name = net.linux_nft_table_name.clone();
        let chain_name = net.linux_nft_chain_name.clone();
        let fwmark = net.linux_fwmark;
        let relay_port = net.default_transparent_tcp_port;

        // 2. Verify nft binary is installed and reachable
        match Command::new(&nft_bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                self.active.store(false, Ordering::SeqCst);
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("{nft_bin} --version failed: {stderr}"),
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.active.store(false, Ordering::SeqCst);
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_MISSING,
                    detail: format!(
                        "{}: {}",
                        controller.i18n.t(ERR_KEY_INTERCEPTOR_NFT_MISSING),
                        nft_bin
                    ),
                });
            }
            Err(err) => {
                self.active.store(false, Ordering::SeqCst);
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed to execute {nft_bin}: {err}"),
                });
            }
        }

        // 3. Remove any stale table with the same name before installing fresh rules
        let _ = Command::new(&nft_bin)
            .args(["delete", "table", "ip", &table_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();

        // 4. Build and load the dedicated nftables table via `nft -f -`
        let upstream_endpoints: Vec<(Ipv4Addr, u16)> = {
            let prof = controller.profile.read();
            prof.proxies
                .iter()
                .filter_map(|p| p.host.parse::<Ipv4Addr>().ok().map(|ip| (ip, p.port)))
                .collect()
        };

        let ruleset = Self::build_nft_table_ruleset(
            &table_name,
            &chain_name,
            fwmark,
            relay_port,
            &upstream_endpoints,
        );

        let mut apply_child = Command::new(&nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                self.active.store(false, Ordering::SeqCst);
                RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Could not spawn {nft_bin} -f -: {err}"),
                }
            })?;

        if let Some(mut stdin) = apply_child.stdin.take() {
            let _ = stdin.write_all(ruleset.as_bytes());
        }

        let apply_out = apply_child.wait_with_output().map_err(|err| {
            self.active.store(false, Ordering::SeqCst);
            RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("Failed waiting for {nft_bin} -f -: {err}"),
            }
        })?;

        if !apply_out.status.success() {
            self.active.store(false, Ordering::SeqCst);
            let stderr = String::from_utf8_lossy(&apply_out.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("nft -f - rejected table \"ip {table_name}\": {stderr}"),
            });
        }

        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_NFTABLES,
            format!(
                "Installed nftables table \"ip {table_name}\" (chain=\"{chain_name}\", fwmark={fwmark:#x}, redirect_port={relay_port})"
            ),
        );

        // 5. Spawn pipe-linked fail-open watchdog in its own process group.
        // If RouteWard dies with SIGKILL (kill -9), the kernel closes watchdog_stdin immediately,
        // `cat` exits on EOF, and `nft delete table ip <table_name>` cleans up automatically.
        let watchdog_script =
            format!("cat >/dev/null; {nft_bin} delete table ip {table_name} >/dev/null 2>&1");
        let mut watchdog_stdin = None;
        let mut watchdog_child = None;

        match Command::new("sh")
            .args(["-c", &watchdog_script])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
        {
            Ok(mut child) => {
                let wid = child.id();
                watchdog_stdin = child.stdin.take();
                watchdog_child = Some(child);
                controller.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!(
                        "Started pipe-linked nftables fail-open watchdog (PID={wid}, table=\"ip {table_name}\")"
                    ),
                );
            }
            Err(err) => {
                controller.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_NFTABLES,
                    format!("Could not spawn pipe-linked watchdog for nftables: {err}"),
                );
            }
        }

        *self.state.lock() = Some(NftActiveState {
            nft_binary: nft_bin,
            table_name,
            watchdog_stdin,
            watchdog_child,
            telemetry: controller.telemetry.clone(),
        });

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn start(&self, _controller: RouteWardController) -> RouteWardResult<()> {
        Err(RouteWardError::InterceptorError {
            key: ERR_KEY_INTERCEPTOR_DRIVER,
            detail: "nftables backend is only supported on Linux".to_string(),
        })
    }

    fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
        if let Some(mut state) = self.state.lock().take() {
            // Closing the pipe write-end lets the watchdog exit cleanly
            drop(state.watchdog_stdin.take());
            let _ = Self::delete_nft_table(&state.nft_binary, &state.table_name, &state.telemetry);
            if let Some(mut child) = state.watchdog_child.take() {
                let _ = child.wait();
            }
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

impl Drop for NftablesInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_expected_nft_ruleset_with_fwmark_loopback_and_upstream_exclusions() {
        let upstreams = vec![
            (Ipv4Addr::new(127, 0, 0, 1), 1080),
            (Ipv4Addr::new(192, 168, 31, 10), 1080),
        ];
        let ruleset = NftablesInterceptor::build_nft_table_ruleset(
            "routeward",
            "output",
            21079,
            10810,
            &upstreams,
        );

        assert!(ruleset.contains("table ip routeward {"));
        assert!(ruleset.contains("chain output {"));
        assert!(ruleset.contains("type nat hook output priority -100; policy accept;"));
        assert!(ruleset.contains("meta mark 21079 return"));
        assert!(ruleset.contains("ip daddr 127.0.0.0/8 return"));
        assert!(ruleset.contains("ip daddr 192.168.31.10 tcp dport 1080 return"));
        assert!(ruleset.contains("tcp dport 1-65535 redirect to :10810"));
    }

    #[test]
    fn parses_sockaddr_in_original_dst_and_rejects_unredirected_loopback_relay() {
        let ip_be = u32::from(Ipv4Addr::new(93, 184, 216, 34)).to_be();
        let port_be = 443u16.to_be();
        let parsed = NftablesInterceptor::parse_sockaddr_in_fields(2, port_be, ip_be, 10810)
            .expect("valid original dst");
        assert_eq!(parsed.ip(), &Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(parsed.port(), 443);

        // Direct connection to 127.0.0.1:10810 without DNAT must be rejected
        let loop_ip_be = u32::from(Ipv4Addr::new(127, 0, 0, 1)).to_be();
        let relay_port_be = 10810u16.to_be();
        assert!(
            NftablesInterceptor::parse_sockaddr_in_fields(2, relay_port_be, loop_ip_be, 10810)
                .is_none()
        );
    }
}
