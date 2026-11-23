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
    ERR_KEY_INTERCEPTOR_TPROXY_CONFLICT,
};
use crate::interceptor::backend::Interceptor;
use crate::interceptor::RouteWardController;
use crate::telemetry::{LogLevel, TelemetryHub};
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod ruleset;
#[cfg(test)]
mod tests;
mod tproxy;
mod watchdog;

pub use watchdog::{
    decide_crash_cleanup_action, fail_closed_table_name, CrashCleanupAction, WatchdogMode,
    FAIL_CLOSED_TABLE_SUFFIX, SERVICE_RESULT_SUCCESS,
};

pub(super) const BACKEND_NAME: &str = "nftables";
pub(super) const COMPONENT_NFTABLES: &str = "NftablesInterceptor";
pub(super) const AF_INET_U16: u16 = 2;
pub(super) const AF_INET6_U16: u16 = 10;
pub(super) const DEFAULT_TPROXY_FWMARK: u32 = 21080;
/// Named set holding the user ids of exempt DNS server processes (no Fake-IP redirect).
pub(super) const NFT_SET_DNS_SERVER_UIDS: &str = "dns_server_uids";
/// Named set holding the subset of those user ids that an explicit Block rule still drops.
pub(super) const NFT_SET_DNS_SERVER_BLOCK_UIDS: &str = "dns_server_block_uids";

/// Fake-IP network enforced by the raw-socket egress guard (`None` until configured, which
/// means the RFC 2544 default).
static FAKE_IP_GUARD_NET: RwLock<Option<Ipv4Net>> = RwLock::new(None);

/// Policy routing and `TPROXY` parameters loaded from `SystemConstants.network`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TproxyRoutingSpec {
    pub fwmark: u32,
    pub route_table: u32,
    pub rule_priority: u32,
    pub tproxy_port: u16,
}

pub(super) struct NftActiveState {
    pub(super) nft_binary: String,
    pub(super) ip_binary: String,
    pub(super) table_name: String,
    pub(super) tproxy_spec: TproxyRoutingSpec,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) ipv6_tproxy_active: bool,
    pub(super) watchdog_stdin: Option<ChildStdin>,
    pub(super) watchdog_child: Option<Child>,
    /// Kill switch setting last communicated to the watchdog (decides its crash behaviour).
    #[cfg(target_os = "linux")]
    pub(super) kill_switch_enabled: bool,
    pub(super) telemetry: TelemetryHub,
}

/// Linux transparent IPv4 TCP interceptor backed by a dedicated `nftables` table
/// (`table ip <table_name>`) and a pipe-linked fail-open watchdog process.
pub struct NftablesInterceptor {
    pub(super) active: Arc<AtomicBool>,
    pub(super) state: Mutex<Option<NftActiveState>>,
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
}

impl NftablesInterceptor {
    /// Feeds `script` to `nft -f -` and reports spawn, write, and exit-status failures
    /// (including the trimmed stderr) as a descriptive error string.
    #[cfg(target_os = "linux")]
    fn apply_nft_script(nft_bin: &str, script: &str) -> Result<(), String> {
        use std::io::Write;

        let mut child = Command::new(nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("could not spawn {nft_bin} -f -: {err}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|err| format!("could not write ruleset to {nft_bin}: {err}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|err| format!("failed waiting for {nft_bin} -f -: {err}"))?;
        if out.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Err(format!("exit={:?}: {stderr}", out.status.code()))
        }
    }
}

impl NftablesInterceptor {
    /// Teardown used by the failure paths of `start`.
    ///
    /// Removes RouteWard's own `ip`/`ip6` tables and `TPROXY` routing but never disarms the
    /// watchdog and never deletes the fail-closed block table `inet <table>_ks`: a start that
    /// fails after a crash must not reopen the host. With the kill switch on and a block table
    /// present the watchdog is told `block` (it re-asserts the table when the pipe closes);
    /// otherwise it is told `open`, so a failed start never installs a block table that was not
    /// there before.
    #[cfg(target_os = "linux")]
    pub(super) fn teardown_failed_start(&self) {
        self.active.store(false, Ordering::SeqCst);
        if let Some(mut state) = self.state.lock().take() {
            let ks = fail_closed_table_name(&state.table_name);
            let keep_block = state.kill_switch_enabled
                && Self::nft_table_is_listed(&state.nft_binary, "inet", &ks);
            let mode = if keep_block {
                WatchdogMode::Block
            } else {
                WatchdogMode::Open
            };
            Self::write_watchdog_mode(&mut state.watchdog_stdin, mode, &state.telemetry);
            drop(state.watchdog_stdin.take());
            let _ = Self::delete_nft_table(&state.nft_binary, &state.table_name, &state.telemetry);
            Self::delete_tproxy_routing(&state.ip_binary, state.tproxy_spec, &state.telemetry);
            if let Some(mut child) = state.watchdog_child.take() {
                let _ = child.wait();
            }
        }
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
                detail: controller.i18n.t_english(ERR_KEY_INTERCEPTOR_NOT_ROOT),
            });
        }

        let net = &controller.constants.network;
        let nft_bin = net.linux_nft_binary.clone();
        let ip_bin = net.linux_ip_binary.clone();
        let table_name = net.linux_nft_table_name.clone();
        let chain_name = net.linux_nft_chain_name.clone();
        let fwmark = net.linux_fwmark;
        let tproxy_spec = TproxyRoutingSpec {
            fwmark: net.linux_tproxy_fwmark,
            route_table: net.linux_tproxy_route_table,
            rule_priority: net.linux_tproxy_rule_priority,
            tproxy_port: net.default_local_name_inspect_port,
        };

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
                        controller.i18n.t_english(ERR_KEY_INTERCEPTOR_NFT_MISSING),
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

        // 3. Verify TPROXY ip rule priority, fwmark, and routing table are free, then install them
        if let Err(err) = Self::check_and_install_tproxy_routing(
            &ip_bin,
            tproxy_spec,
            &controller.telemetry,
            &controller.i18n,
        ) {
            self.active.store(false, Ordering::SeqCst);
            return Err(err);
        }

        // 4. Remove any stale tables (`ip` and `ip6`) with the same name before installing fresh rules
        for family in ["ip", "ip6"] {
            let _ = Command::new(&nft_bin)
                .args(["delete", "table", family, &table_name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output();
        }

        // 5. Build and load the dedicated nftables tables via `nft -f -`
        let upstream_endpoints = controller.nat_table.upstream_endpoints();
        let upstream_v4: Vec<(Ipv4Addr, u16)> = upstream_endpoints
            .iter()
            .filter_map(|(ip, port)| match ip {
                IpAddr::V4(v4) => Some((*v4, *port)),
                IpAddr::V6(_) => None,
            })
            .collect();
        let upstream_v6: Vec<(Ipv6Addr, u16)> = upstream_endpoints
            .iter()
            .filter_map(|(ip, port)| match ip {
                IpAddr::V6(v6) => Some((*v6, *port)),
                IpAddr::V4(_) => None,
            })
            .collect();
        let relay_port = net.default_transparent_tcp_port;
        let dns_listen_port = net.default_dns_listen_port;
        let local_name_inspect_port = net.default_local_name_inspect_port;
        let quic_port = net.quic_default_port;
        let mdns_port = net.mdns_standard_port;
        let llmnr_port = net.llmnr_standard_port;
        let netbios_ns_port = net.netbios_ns_standard_port;
        let dns_standard_port = controller.constants.dns.dns_standard_port;
        let dot_port = controller.constants.dns.dns_over_tls_port;
        let (kill_switch_enabled, block_encrypted_dns, block_quic_udp_443) = {
            let prof = controller.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_encrypted_dns_bypass,
                prof.security_policy.block_quic_udp_443,
            )
        };
        let fake_ip_net = {
            let prof = controller.profile.read();
            Self::resolve_fake_ip_net(
                &prof.dns_config.fake_ip_cidr,
                &controller.constants.dns.fake_ip_cidr,
            )
        };
        Self::set_fake_ip_guard_net(fake_ip_net);

        // Held until this function returns: the batch is built from the tracker's sets and the sets
        // are marked applied, with no scan landing in between.
        let _dns_sync = controller.dns_server_tracker.lock_sync();
        let dns_uid_sets = controller.dns_server_tracker.uid_sets();
        let mut ipv6_tproxy_active = false;
        let mut ip6_ruleset = Self::build_nft_ip6_table_ruleset_with_tproxy(
            &table_name,
            &chain_name,
            fwmark,
            tproxy_spec.fwmark,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            block_encrypted_dns,
            block_quic_udp_443,
            &upstream_v6,
        );
        ip6_ruleset.push_str(&ruleset::build_dns_server_uid_elements(
            "ip6",
            &table_name,
            &dns_uid_sets.exempt,
            &dns_uid_sets.block,
            false,
        ));
        match Self::apply_nft_script(&nft_bin, &ip6_ruleset) {
            Ok(()) => {
                ipv6_tproxy_active = true;
                controller.telemetry.push_log(
                    LogLevel::Info,
                    COMPONENT_NFTABLES,
                    format!("Installed nftables IPv6 dual-stack table \"ip6 {table_name}\""),
                );
            }
            Err(detail) => {
                controller.telemetry.push_log(
                    LogLevel::Warn,
                    COMPONENT_NFTABLES,
                    format!(
                        "Could not install full IPv6 NAT/TPROXY table \"ip6 {table_name}\" ({detail}); falling back to the IPv6 guard (killSwitchEnabled={kill_switch_enabled})"
                    ),
                );
                let fallback_ip6 = Self::build_nft_ip6_fallback_guard_ruleset(
                    &table_name,
                    &chain_name,
                    fwmark,
                    dns_standard_port,
                    dot_port,
                    kill_switch_enabled,
                    block_encrypted_dns,
                );
                match Self::apply_nft_script(&nft_bin, &fallback_ip6) {
                    Ok(()) => {
                        controller.telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_NFTABLES,
                            format!("Installed IPv6 fallback guard table \"ip6 {table_name}\""),
                        );
                    }
                    Err(fb_detail) if kill_switch_enabled => {
                        controller.telemetry.push_log(
                            LogLevel::Error,
                            COMPONENT_NFTABLES,
                            format!(
                                "Could not install IPv6 fallback guard \"ip6 {table_name}\" with the kill switch enabled: {fb_detail}"
                            ),
                        );
                        // No watchdog and no active state exist yet: only the routing installed
                        // so far goes. The fail-closed block table of a previous crash is left
                        // untouched, like on every other start failure path.
                        Self::delete_tproxy_routing(&ip_bin, tproxy_spec, &controller.telemetry);
                        self.active.store(false, Ordering::SeqCst);
                        return Err(RouteWardError::InterceptorError {
                            key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                            detail: format!(
                                "IPv6 kill switch guard \"ip6 {table_name}\" could not be installed: {fb_detail}"
                            ),
                        });
                    }
                    Err(fb_detail) => {
                        controller.telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_NFTABLES,
                            format!(
                                "Could not install IPv6 fallback guard \"ip6 {table_name}\": {fb_detail}"
                            ),
                        );
                    }
                }
            }
        }

        // 6. Spawn pipe-linked fail-open watchdog in its own process group before installing `ip routeward`.
        // If RouteWard dies with SIGKILL (kill -9), the kernel closes watchdog_stdin immediately,
        // `cat` exits on EOF, and both `nft` tables + `ip rule` + `ip route` are cleaned up automatically.
        let watchdog_script =
            Self::build_watchdog_cleanup_script(&nft_bin, &ip_bin, &table_name, tproxy_spec);
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
                        "Started pipe-linked nftables/TPROXY fail-open watchdog (PID={wid}, table=\"ip {table_name}\")"
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

        // Tell the watchdog what to do if the daemon dies: fail closed with the kill switch on.
        Self::write_watchdog_mode(
            &mut watchdog_stdin,
            WatchdogMode::from_kill_switch(kill_switch_enabled),
            &controller.telemetry,
        );

        *self.state.lock() = Some(NftActiveState {
            nft_binary: nft_bin.clone(),
            ip_binary: ip_bin,
            table_name: table_name.clone(),
            tproxy_spec,
            ipv6_tproxy_active,
            watchdog_stdin,
            watchdog_child,
            kill_switch_enabled,
            telemetry: controller.telemetry.clone(),
        });

        let mut ruleset = Self::build_nft_table_ruleset_with_fake_ip(
            &table_name,
            &chain_name,
            fwmark,
            tproxy_spec.fwmark,
            relay_port,
            dns_listen_port,
            local_name_inspect_port,
            dns_standard_port,
            dot_port,
            quic_port,
            mdns_port,
            llmnr_port,
            netbios_ns_port,
            block_encrypted_dns,
            block_quic_udp_443,
            &upstream_v4,
            fake_ip_net,
        );
        ruleset.push_str(&ruleset::build_dns_server_uid_elements(
            "ip",
            &table_name,
            &dns_uid_sets.exempt,
            &dns_uid_sets.block,
            false,
        ));

        let mut apply_child = match Command::new(&nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                self.teardown_failed_start();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Could not spawn {nft_bin} -f -: {err}"),
                });
            }
        };

        if let Some(mut stdin) = apply_child.stdin.take() {
            let _ = stdin.write_all(ruleset.as_bytes());
        }

        let apply_out = match apply_child.wait_with_output() {
            Ok(out) => out,
            Err(err) => {
                self.teardown_failed_start();
                return Err(RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed waiting for {nft_bin} -f -: {err}"),
                });
            }
        };

        if !apply_out.status.success() {
            self.teardown_failed_start();
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
                "Installed nftables table \"ip {table_name}\" (chain=\"{chain_name}\", fwmark={fwmark:#x}, redirect_port={relay_port}, dns_port={dns_listen_port})"
            ),
        );

        // Own tables are installed: a block table left by a previous crash can now go (deleting it
        // earlier would open a window, keeping it would block the upstream proxy traffic).
        Self::delete_fail_closed_table(&nft_bin, &table_name, &controller.telemetry);

        controller
            .dns_server_tracker
            .mark_uid_sets_applied(dns_uid_sets);

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn start(&self, _controller: RouteWardController) -> RouteWardResult<()> {
        Err(RouteWardError::InterceptorError {
            key: ERR_KEY_INTERCEPTOR_DRIVER,
            detail: "nftables backend is only supported on Linux".to_string(),
        })
    }

    #[cfg(target_os = "linux")]
    fn reload(&self, controller: RouteWardController) -> RouteWardResult<()> {
        use std::io::Write;

        if !self.is_active() {
            return Ok(());
        }

        let net = &controller.constants.network;
        let nft_bin = net.linux_nft_binary.clone();
        let ip_bin = net.linux_ip_binary.clone();
        let table_name = net.linux_nft_table_name.clone();
        let chain_name = net.linux_nft_chain_name.clone();
        let fwmark = net.linux_fwmark;
        let tproxy_spec = TproxyRoutingSpec {
            fwmark: net.linux_tproxy_fwmark,
            route_table: net.linux_tproxy_route_table,
            rule_priority: net.linux_tproxy_rule_priority,
            tproxy_port: net.default_local_name_inspect_port,
        };
        let relay_port = net.default_transparent_tcp_port;
        let dns_listen_port = net.default_dns_listen_port;
        let local_name_inspect_port = net.default_local_name_inspect_port;
        let quic_port = net.quic_default_port;
        let mdns_port = net.mdns_standard_port;
        let llmnr_port = net.llmnr_standard_port;
        let netbios_ns_port = net.netbios_ns_standard_port;
        let dns_standard_port = controller.constants.dns.dns_standard_port;
        let dot_port = controller.constants.dns.dns_over_tls_port;
        let upstream_endpoints = controller.nat_table.upstream_endpoints();
        let (kill_switch_enabled, block_encrypted_dns, block_quic_udp_443) = {
            let prof = controller.profile.read();
            (
                prof.security_policy.kill_switch_enabled,
                prof.security_policy.block_encrypted_dns_bypass,
                prof.security_policy.block_quic_udp_443,
            )
        };

        let fake_ip_net = {
            let prof = controller.profile.read();
            Self::resolve_fake_ip_net(
                &prof.dns_config.fake_ip_cidr,
                &controller.constants.dns.fake_ip_cidr,
            )
        };
        Self::set_fake_ip_guard_net(fake_ip_net);

        let (prev_spec, ipv6_tproxy_active) = {
            let guard = self.state.lock();
            (
                guard.as_ref().map(|s| s.tproxy_spec),
                guard
                    .as_ref()
                    .map(|s| s.ipv6_tproxy_active)
                    .unwrap_or(false),
            )
        };
        if let Some(old_spec) = prev_spec {
            if old_spec != tproxy_spec {
                Self::delete_tproxy_routing(&ip_bin, old_spec, &controller.telemetry);
                Self::check_and_install_tproxy_routing(
                    &ip_bin,
                    tproxy_spec,
                    &controller.telemetry,
                    &controller.i18n,
                )?;
                if let Some(ref mut st) = *self.state.lock() {
                    st.tproxy_spec = tproxy_spec;
                }
            }
        }

        // Held until this function returns: the batch is built from the tracker's sets and the sets
        // are marked applied, with no scan landing in between.
        let _dns_sync = controller.dns_server_tracker.lock_sync();
        let dns_uid_sets = controller.dns_server_tracker.uid_sets();
        let mut atomic_batch = if ipv6_tproxy_active {
            Self::build_atomic_replace_ruleset_dual_stack(
                &table_name,
                &chain_name,
                fwmark,
                tproxy_spec.fwmark,
                relay_port,
                dns_listen_port,
                local_name_inspect_port,
                dns_standard_port,
                dot_port,
                quic_port,
                mdns_port,
                llmnr_port,
                netbios_ns_port,
                kill_switch_enabled,
                block_encrypted_dns,
                block_quic_udp_443,
                &upstream_endpoints,
                fake_ip_net,
            )
        } else {
            let up4: Vec<(Ipv4Addr, u16)> = upstream_endpoints
                .iter()
                .filter_map(|(ip, port)| match ip {
                    IpAddr::V4(v4) => Some((*v4, *port)),
                    IpAddr::V6(_) => None,
                })
                .collect();
            let mut batch = String::with_capacity(2048);
            batch.push_str(&format!("table ip {table_name}\n"));
            batch.push_str(&format!("delete table ip {table_name}\n"));
            batch.push_str(&Self::build_nft_table_ruleset_with_fake_ip(
                &table_name,
                &chain_name,
                fwmark,
                tproxy_spec.fwmark,
                relay_port,
                dns_listen_port,
                local_name_inspect_port,
                dns_standard_port,
                dot_port,
                quic_port,
                mdns_port,
                llmnr_port,
                netbios_ns_port,
                block_encrypted_dns,
                block_quic_udp_443,
                &up4,
                fake_ip_net,
            ));
            batch.push_str(&format!("table ip6 {table_name}\n"));
            batch.push_str(&format!("delete table ip6 {table_name}\n"));
            batch.push_str(&Self::build_nft_ip6_fallback_guard_ruleset(
                &table_name,
                &chain_name,
                fwmark,
                dns_standard_port,
                dot_port,
                kill_switch_enabled,
                block_encrypted_dns,
            ));
            batch
        };

        atomic_batch.push_str(&ruleset::build_dns_server_uid_elements(
            "ip",
            &table_name,
            &dns_uid_sets.exempt,
            &dns_uid_sets.block,
            false,
        ));
        if ipv6_tproxy_active {
            atomic_batch.push_str(&ruleset::build_dns_server_uid_elements(
                "ip6",
                &table_name,
                &dns_uid_sets.exempt,
                &dns_uid_sets.block,
                false,
            ));
        }

        let mut apply_child = Command::new(&nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("Could not spawn {nft_bin} -f - for atomic reload: {err}"),
            })?;

        if let Some(mut stdin) = apply_child.stdin.take() {
            let _ = stdin.write_all(atomic_batch.as_bytes());
        }

        let apply_out =
            apply_child
                .wait_with_output()
                .map_err(|err| RouteWardError::InterceptorError {
                    key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                    detail: format!("Failed waiting for {nft_bin} -f - atomic reload: {err}"),
                })?;

        if !apply_out.status.success() {
            let stderr = String::from_utf8_lossy(&apply_out.stderr)
                .trim()
                .to_string();
            return Err(RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!(
                    "nft -f - rejected atomic table reload for \"{table_name}\": {stderr}"
                ),
            });
        }

        controller.telemetry.push_log(
            LogLevel::Info,
            COMPONENT_NFTABLES,
            format!(
                "Atomically replaced nftables tables \"ip {table_name}\" and \"ip6 {table_name}\" (killSwitchEnabled={kill_switch_enabled}, blockEncryptedDnsBypass={block_encrypted_dns})"
            ),
        );

        controller
            .dns_server_tracker
            .mark_uid_sets_applied(dns_uid_sets);

        // Keep the crash behaviour in sync with the (possibly toggled) kill switch.
        if let Some(ref mut st) = *self.state.lock() {
            st.kill_switch_enabled = kill_switch_enabled;
            Self::write_watchdog_mode(
                &mut st.watchdog_stdin,
                WatchdogMode::from_kill_switch(kill_switch_enabled),
                &st.telemetry,
            );
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn sync_dns_server_uids(
        &self,
        exempt: &BTreeSet<u32>,
        block: &BTreeSet<u32>,
    ) -> RouteWardResult<()> {
        let (nft_bin, table_name, ipv6_tproxy_active) = {
            let guard = self.state.lock();
            match guard.as_ref() {
                Some(state) => (
                    state.nft_binary.clone(),
                    state.table_name.clone(),
                    state.ipv6_tproxy_active,
                ),
                None => return Ok(()),
            }
        };
        // One transaction: flush and refill both sets, so the exemption never has a gap.
        let mut script =
            ruleset::build_dns_server_uid_elements("ip", &table_name, exempt, block, true);
        if ipv6_tproxy_active {
            script.push_str(&ruleset::build_dns_server_uid_elements(
                "ip6",
                &table_name,
                exempt,
                block,
                true,
            ));
        }
        Self::apply_nft_script(&nft_bin, &script).map_err(|detail| {
            RouteWardError::InterceptorError {
                key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
                detail: format!("DNS server user id set update rejected by nft: {detail}"),
            }
        })
    }

    fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
        if let Some(mut state) = self.state.lock().take() {
            // A clean stop must never leave the network blocked: disarm, then close the pipe
            // write-end so the watchdog exits with the plain cleanup.
            Self::write_watchdog_mode(
                &mut state.watchdog_stdin,
                WatchdogMode::Disarm,
                &state.telemetry,
            );
            drop(state.watchdog_stdin.take());
            let _ = Self::delete_nft_table(&state.nft_binary, &state.table_name, &state.telemetry);
            Self::delete_fail_closed_table(&state.nft_binary, &state.table_name, &state.telemetry);
            Self::delete_tproxy_routing(&state.ip_binary, state.tproxy_spec, &state.telemetry);
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
    /// Dropping without an explicit `stop()` (for example a panic unwinding) must never disarm:
    /// the watchdog keeps its current mode and applies it when the pipe closes, so a daemon that
    /// dies with the kill switch on still fails closed.
    fn drop(&mut self) {
        self.active.store(false, Ordering::SeqCst);
        if let Some(mut state) = self.state.lock().take() {
            drop(state.watchdog_stdin.take());
            if let Some(mut child) = state.watchdog_child.take() {
                let _ = child.wait();
            }
        }
    }
}
