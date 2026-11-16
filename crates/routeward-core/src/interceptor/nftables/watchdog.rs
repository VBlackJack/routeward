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

impl NftablesInterceptor {
    /// Builds the pipe-linked fail-open watchdog shell command that deletes `table ip/ip6 <table_name>`,
    /// the exact `TPROXY` `ip rule`, and the exact local route on `lo` when the daemon process exits or crashes (`kill -9`).
    pub fn build_watchdog_cleanup_script(
        nft_bin: &str,
        ip_bin: &str,
        table_name: &str,
        spec: TproxyRoutingSpec,
    ) -> String {
        format!(
            "cat >/dev/null; {nft_bin} delete table ip {table_name} >/dev/null 2>&1; {nft_bin} delete table ip6 {table_name} >/dev/null 2>&1; {ip_bin} -4 rule del fwmark {} lookup {} priority {} >/dev/null 2>&1; {ip_bin} -4 route del local 0.0.0.0/0 dev lo table {} >/dev/null 2>&1; {ip_bin} -6 rule del fwmark {} lookup {} priority {} >/dev/null 2>&1; {ip_bin} -6 route del local ::/0 dev lo table {} >/dev/null 2>&1",
            spec.fwmark, spec.route_table, spec.rule_priority, spec.route_table,
            spec.fwmark, spec.route_table, spec.rule_priority, spec.route_table
        )
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
