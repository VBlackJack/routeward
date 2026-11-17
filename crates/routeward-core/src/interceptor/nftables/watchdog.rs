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

use super::*;
use crate::error::ERR_KEY_INTERCEPTOR_NFT_FAILED;

/// Suffix appended to the RouteWard table name to build the fail-closed block table name.
pub const FAIL_CLOSED_TABLE_SUFFIX: &str = "_ks";

/// Name of the fail-closed block table (`table inet <table_name>_ks`).
pub fn fail_closed_table_name(table_name: &str) -> String {
    format!("{table_name}{FAIL_CLOSED_TABLE_SUFFIX}")
}

/// Mode the daemon tells the pipe-linked watchdog to apply when the pipe reaches end of file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogMode {
    /// Daemon crash with the kill switch off: remove every RouteWard rule (fail-open).
    Open,
    /// Daemon crash with the kill switch on: install the fail-closed block table.
    Block,
    /// Clean shutdown: remove every RouteWard rule, including any block table.
    Disarm,
}

impl WatchdogMode {
    /// Protocol line written to the watchdog stdin (without the trailing newline).
    pub const fn as_str(self) -> &'static str {
        match self {
            WatchdogMode::Open => "open",
            WatchdogMode::Block => "block",
            WatchdogMode::Disarm => "disarm",
        }
    }

    /// Strictly parses a protocol line; anything other than the three known modes is rejected.
    pub fn parse(line: &str) -> Option<Self> {
        match line {
            "open" => Some(WatchdogMode::Open),
            "block" => Some(WatchdogMode::Block),
            "disarm" => Some(WatchdogMode::Disarm),
            _ => None,
        }
    }

    /// Crash behaviour selected by the kill switch setting.
    pub const fn from_kill_switch(kill_switch_enabled: bool) -> Self {
        if kill_switch_enabled {
            WatchdogMode::Block
        } else {
            WatchdogMode::Open
        }
    }
}

/// Action `routeward cleanup --fail-closed-on-crash` takes after the service stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashCleanupAction {
    /// Remove every RouteWard rule, including any block table.
    RemoveAll,
    /// Replace the RouteWard tables with the fail-closed block table.
    InstallFailClosed,
}

/// Value of `$SERVICE_RESULT` that systemd exports after a clean stop.
pub const SERVICE_RESULT_SUCCESS: &str = "success";

/// Pure decision for the systemd `ExecStopPost` hook: fail closed only when the service did not
/// stop cleanly (crash, timeout, ...) and the persisted profile has the kill switch enabled.
/// A missing `service_result` (not run by systemd) always removes everything.
pub fn decide_crash_cleanup_action(
    service_result: Option<&str>,
    kill_switch_enabled: bool,
) -> CrashCleanupAction {
    match service_result {
        Some(result) if result != SERVICE_RESULT_SUCCESS && kill_switch_enabled => {
            CrashCleanupAction::InstallFailClosed
        }
        _ => CrashCleanupAction::RemoveAll,
    }
}

impl NftablesInterceptor {
    /// Builds the single `nft -f -` transaction that installs the fail-closed block table.
    ///
    /// The old `ip`/`ip6 <table_name>` tables are deleted in the same transaction (declared empty
    /// first so the deletion is idempotent on every nft version) and any previous block table is
    /// replaced. Only loopback, established traffic, DHCP, ICMPv6 neighbour discovery and MLD are
    /// allowed out; everything else is dropped.
    pub fn build_fail_closed_ruleset(table_name: &str) -> String {
        let ks = fail_closed_table_name(table_name);
        format!(
            "table ip {table_name} {{}}\n\
delete table ip {table_name}\n\
table ip6 {table_name} {{}}\n\
delete table ip6 {table_name}\n\
table inet {ks} {{}}\n\
delete table inet {ks}\n\
table inet {ks} {{\n\
  chain output {{\n\
    type filter hook output priority 0; policy drop;\n\
    oif \"lo\" accept\n\
    ct state established,related accept\n\
    udp sport 68 udp dport 67 accept\n\
    udp sport 546 udp dport 547 accept\n\
    icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept\n\
    icmpv6 type {{ mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report }} accept\n\
  }}\n\
}}\n"
        )
    }

    /// Builds the pipe-linked watchdog shell command.
    ///
    /// The daemon writes mode lines (`open`, `block`, `disarm`) to the watchdog stdin; unknown
    /// lines are ignored. When the pipe closes (clean exit, crash, `kill -9`) the last valid mode
    /// decides: `block` installs the fail-closed table (falling back to the fail-open cleanup if
    /// nft rejects it), `open` and `disarm` delete `table ip/ip6 <table_name>`, the block table,
    /// the exact `TPROXY` `ip rule`, and the exact local route on `lo`.
    pub fn build_watchdog_cleanup_script(
        nft_bin: &str,
        ip_bin: &str,
        table_name: &str,
        spec: TproxyRoutingSpec,
    ) -> String {
        let ks = fail_closed_table_name(table_name);
        let block_ruleset = Self::build_fail_closed_ruleset(table_name);
        let tproxy_cleanup = format!(
            "{ip_bin} -4 rule del fwmark {} lookup {} priority {} >/dev/null 2>&1; {ip_bin} -4 route del local 0.0.0.0/0 dev lo table {} >/dev/null 2>&1; {ip_bin} -6 rule del fwmark {} lookup {} priority {} >/dev/null 2>&1; {ip_bin} -6 route del local ::/0 dev lo table {} >/dev/null 2>&1",
            spec.fwmark, spec.route_table, spec.rule_priority, spec.route_table,
            spec.fwmark, spec.route_table, spec.rule_priority, spec.route_table
        );
        format!(
            "mode={open}; while read -r m; do case \"$m\" in {open}|{block}|{disarm}) mode=$m;; esac; done; \
tproxy_cleanup() {{ {tproxy_cleanup}; }}; \
open_cleanup() {{ {nft_bin} delete table ip {table_name} >/dev/null 2>&1; {nft_bin} delete table ip6 {table_name} >/dev/null 2>&1; {nft_bin} delete table inet {ks} >/dev/null 2>&1; tproxy_cleanup; }}; \
if [ \"$mode\" = {block} ]; then printf '%s' '{block_ruleset}' | {nft_bin} -f - >/dev/null 2>&1 && {{ tproxy_cleanup; exit 0; }}; fi; \
open_cleanup",
            open = WatchdogMode::Open.as_str(),
            block = WatchdogMode::Block.as_str(),
            disarm = WatchdogMode::Disarm.as_str(),
        )
    }

    /// Writes one mode line to the watchdog stdin and flushes it. Failures are logged, never fatal.
    pub(super) fn write_watchdog_mode(
        stdin: &mut Option<ChildStdin>,
        mode: WatchdogMode,
        telemetry: &TelemetryHub,
    ) {
        use std::io::Write;

        let Some(pipe) = stdin.as_mut() else {
            return;
        };
        let line = format!("{}\n", mode.as_str());
        if let Err(err) = pipe.write_all(line.as_bytes()).and_then(|()| pipe.flush()) {
            telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_NFTABLES,
                format!(
                    "Could not send mode \"{}\" to the nftables watchdog: {err}",
                    mode.as_str()
                ),
            );
        }
    }

    /// Replaces the RouteWard `ip`/`ip6` tables with the fail-closed block table in one transaction.
    pub fn install_fail_closed_table(
        nft_binary: &str,
        table_name: &str,
        telemetry: &TelemetryHub,
    ) -> RouteWardResult<()> {
        use std::io::Write;

        let ruleset = Self::build_fail_closed_ruleset(table_name);
        let ks = fail_closed_table_name(table_name);
        let nft_err = |detail: String| RouteWardError::InterceptorError {
            key: ERR_KEY_INTERCEPTOR_NFT_FAILED,
            detail,
        };
        let mut child = Command::new(nft_binary)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| nft_err(format!("could not spawn {nft_binary} -f -: {err}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ruleset.as_bytes()).map_err(|err| {
                nft_err(format!(
                    "could not write block ruleset to {nft_binary}: {err}"
                ))
            })?;
        }
        let out = child
            .wait_with_output()
            .map_err(|err| nft_err(format!("failed waiting for {nft_binary} -f -: {err}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(nft_err(format!(
                "nft rejected fail-closed table \"inet {ks}\" (exit={:?}): {stderr}",
                out.status.code()
            )));
        }
        telemetry.push_log(
            LogLevel::Warn,
            COMPONENT_NFTABLES,
            format!(
                "Installed fail-closed block table \"inet {ks}\"; run \"routeward cleanup\" to restore traffic"
            ),
        );
        Ok(())
    }

    /// Deletes the fail-closed block table (`table inet <table_name>_ks`) if it exists.
    pub fn delete_fail_closed_table(nft_binary: &str, table_name: &str, telemetry: &TelemetryHub) {
        let ks = fail_closed_table_name(table_name);
        match Command::new(nft_binary)
            .args(["delete", "table", "inet", &ks])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => telemetry.push_log(
                LogLevel::Info,
                COMPONENT_NFTABLES,
                format!("Removed fail-closed block table \"inet {ks}\""),
            ),
            Ok(status) => {
                if Self::nft_table_is_listed(nft_binary, "inet", &ks) {
                    telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_NFTABLES,
                        format!(
                            "Could not delete fail-closed block table \"inet {ks}\" (exit={:?})",
                            status.code()
                        ),
                    );
                }
            }
            Err(err) => telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_NFTABLES,
                format!("Failed invoking {nft_binary} to delete \"inet {ks}\": {err}"),
            ),
        }
    }

    /// Returns `true` unless `nft list tables` succeeds and does not list `<family> <table_name>`.
    ///
    /// Locale-independent: it relies on the exit status and the table inventory, never on the
    /// wording of an error message. If the inventory cannot be read, the table is assumed present
    /// so that a failed deletion is reported rather than masked.
    fn nft_table_is_listed(nft_binary: &str, family: &str, table_name: &str) -> bool {
        match Command::new(nft_binary)
            .args(["list", "tables"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => Self::tables_listing_contains(
                &String::from_utf8_lossy(&out.stdout),
                family,
                table_name,
            ),
            _ => true,
        }
    }

    /// Returns `true` if `nft list tables` output contains a `table <family> <table_name>` line.
    pub fn tables_listing_contains(listing: &str, family: &str, table_name: &str) -> bool {
        listing.lines().any(|line| {
            let mut parts = line.split_whitespace();
            parts.next() == Some("table")
                && parts.next() == Some(family)
                && parts.next() == Some(table_name)
        })
    }

    /// Deletes the dedicated `nftables` tables (`ip` and `ip6`) if they exist.
    pub fn delete_nft_table(
        nft_binary: &str,
        table_name: &str,
        telemetry: &TelemetryHub,
    ) -> RouteWardResult<()> {
        for family in ["ip", "ip6"] {
            match Command::new(nft_binary)
                .args(["delete", "table", family, table_name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
            {
                Ok(out) if out.status.success() => {
                    telemetry.push_log(
                        LogLevel::Info,
                        COMPONENT_NFTABLES,
                        format!("Removed nftables table \"{family} {table_name}\""),
                    );
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let trimmed = stderr.trim();
                    if !Self::nft_table_is_listed(nft_binary, family, table_name) {
                        telemetry.push_log(
                            LogLevel::Info,
                            COMPONENT_NFTABLES,
                            format!(
                                "nftables table \"{family} {table_name}\" was already absent during cleanup"
                            ),
                        );
                    } else {
                        telemetry.push_log(
                            LogLevel::Warn,
                            COMPONENT_NFTABLES,
                            format!(
                                "Could not delete nftables table \"{family} {table_name}\" (exit={:?}): {trimmed}",
                                out.status.code()
                            ),
                        );
                    }
                }
                Err(err) => {
                    telemetry.push_log(
                        LogLevel::Warn,
                        COMPONENT_NFTABLES,
                        format!(
                            "Failed invoking {nft_binary} to delete table \"{family} {table_name}\": {err}"
                        ),
                    );
                }
            }
        }
        Ok(())
    }
}
