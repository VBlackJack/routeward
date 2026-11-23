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

mod ctl_reports;

use clap::{Parser, Subcommand};
use routeward_core::config::security::load_or_init_secure_daemon_profile;
use routeward_core::config::{
    ProfileConfig, ProxyNode, RoutingRule, SystemConstants, TelemetryConstants, TransportProtocol,
};
use routeward_core::diagnostics::logs::LogQuerySource;
use routeward_core::error::{
    RouteWardError, RouteWardResult, ERR_KEY_CLEANUP_DAEMON_ACTIVE, ERR_KEY_CONFIG_JSON,
    ERR_KEY_CONFIG_LOAD, ERR_KEY_DAEMON_NOT_ELEVATED,
};
use routeward_core::i18n::{os_default_locale, I18nRegistry};
use routeward_core::interceptor::RouteWardController;
use routeward_core::ipc::protocol::IpcCommand;
use routeward_core::ipc::transport::is_daemon_ipc_active;
use routeward_core::ipc::{wait_for_shutdown_signal, DaemonIpcService, IpcClient};
use routeward_core::logger::FileLogger;
use routeward_core::pac::PacGenerator;
use routeward_core::rules::ConnectionRequest;
use routeward_core::system::protection_state::MAX_PAUSE_SECS;
use routeward_core::system::upgrade_migration::{consume_upgrade_marker, migrate_upgrade_state};
use routeward_core::system::user_state::{AllUsersCleanupReport, UserCleanupReport};
use routeward_core::system::windows_service::{
    install_windows_service, query_windows_service_status, restore_windows_service,
    run_windows_service_dispatcher, start_windows_service, stop_windows_service,
    uninstall_windows_service,
};
use routeward_core::system::{local_pac_url, SystemProxyManager};
use routeward_core::telemetry::LogLevel;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const DEFAULT_EVAL_PORT: u16 = 443;
const COMPONENT_CLI_CTL: &str = "CliCtl";

/// Explicit locale (flag or `ROUTEWARD_LOCALE`) wins; otherwise the operating system language.
fn resolve_locale(explicit: Option<&str>, os_default: impl FnOnce() -> &'static str) -> String {
    explicit
        .map(str::to_string)
        .unwrap_or_else(|| os_default().to_string())
}

#[derive(Parser)]
#[command(name = "routeward", version, about)]
struct CliArgs {
    #[arg(short, long, env = "ROUTEWARD_CONFIG_PATH")]
    profile: Option<PathBuf>,

    #[arg(short, long, global = true, env = "ROUTEWARD_LOCALE")]
    locale: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the transparent relay and OS packet interceptor engine in standalone foreground mode
    Run {
        /// Optional safety timeout in seconds before automatic fail-open shutdown
        #[arg(long)]
        duration_secs: Option<u64>,
    },
    /// Run the privileged RouteWard daemon listening on the restricted local OS IPC channel
    Daemon {
        /// Optional safety timeout in seconds before automatic fail-open shutdown
        #[arg(long)]
        duration_secs: Option<u64>,
        /// Additional allowed Windows user SID for restricted Named Pipe IPC access (repeatable)
        #[arg(long = "allow-sid", value_name = "SID")]
        allow_sid: Vec<String>,
    },
    /// Manage or host the Windows Service Control Manager (SCM) daemon
    Service {
        #[command(subcommand)]
        action: ServiceCommands,
    },
    /// Control and query the running RouteWard daemon over the local OS IPC channel
    Ctl {
        #[command(subcommand)]
        action: CtlCommands,
    },
    /// Probe all configured upstream proxies for latency, exit IP, and UDP support
    Check {
        #[arg(short, long)]
        proxy_id: Option<String>,
    },
    /// Evaluate routing rules for a candidate process and destination
    Eval {
        #[arg(long)]
        process: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = DEFAULT_EVAL_PORT)]
        port: u16,
    },
    /// Allocate and inspect a Fake-IP entry for a domain
    FakeIp {
        #[arg(long)]
        domain: String,
    },
    /// Remove orphaned OS interception rules (Linux nftables table or Windows firewall rule)
    Cleanup {
        /// Force removal even if a RouteWard daemon instance appears active
        #[arg(long)]
        force: bool,
        /// Linux service hook: when the service did not stop cleanly ($SERVICE_RESULT is not
        /// "success") and the persisted profile has the kill switch enabled, install the
        /// fail-closed block table instead of removing every rule
        #[arg(long = "fail-closed-on-crash")]
        fail_closed_on_crash: bool,
        /// Restore only the RouteWard-owned settings of the current user (system proxy, PAC URL,
        /// autostart entry); needs no elevation and does not touch the OS interception rules
        #[arg(long, conflicts_with_all = ["force", "fail_closed_on_crash"])]
        user: bool,
        /// Restore the RouteWard-owned settings of every user whose registry hive is currently
        /// loaded (Windows; run elevated or as SYSTEM, used by the uninstaller). Users who are
        /// not logged on keep their values
        #[arg(long = "all-users", conflicts_with_all = ["force", "fail_closed_on_crash", "user"])]
        all_users: bool,
    },
    /// Delete the RouteWard data directory (profile and logs) of this machine; run by the
    /// uninstaller. Needs elevation and refuses while a RouteWard daemon is active
    PurgeData,
    /// Keep protection on across an upgrade from a version that did not persist it; run by the
    /// installer once the upgrade is committed. Never starts the service and always exits 0
    #[command(hide = true)]
    MigrateUpgradeState {
        /// SID of the installing user, whose registry hive holds the marker left by the installer
        #[arg(long)]
        user_sid: String,
    },
    /// Restore the normal Internet connection of the current user: turn protection off in the
    /// background (when reachable), then give back the system proxy settings. Needs no
    /// elevation and never fails because the background service is unreachable
    Recover {
        /// Wait for Enter before returning, so a shortcut window stays readable
        #[arg(long = "pause-at-end")]
        pause_at_end: bool,
    },
}

/// Reads the persisted daemon profile and returns its kill switch setting; any read or parse
/// failure counts as "off" so that an unreadable profile never blocks the host.
#[cfg(not(windows))]
fn persisted_kill_switch_enabled(controller: &RouteWardController) -> bool {
    let Ok(path) = controller.constants.ipc.resolve_daemon_profile_path() else {
        return false;
    };
    ProfileConfig::load_from_path(path)
        .map(|profile| profile.security_policy.kill_switch_enabled)
        .unwrap_or(false)
}

/// Runs `routeward cleanup`. With `fail_closed_on_crash` (Linux systemd hook) a crashed service
/// with the kill switch enabled gets the block table instead of a full removal; otherwise every
/// RouteWard rule is removed, including a leftover block table.
fn run_cleanup(
    controller: &RouteWardController,
    force: bool,
    fail_closed_on_crash: bool,
) -> RouteWardResult<()> {
    #[cfg(not(windows))]
    {
        use routeward_core::interceptor::nftables::TproxyRoutingSpec;
        use routeward_core::interceptor::nftables::{
            decide_crash_cleanup_action, CrashCleanupAction, NftablesInterceptor,
        };

        let net = &controller.constants.network;
        if fail_closed_on_crash {
            let service_result = std::env::var("SERVICE_RESULT").ok();
            let action = decide_crash_cleanup_action(
                service_result.as_deref(),
                persisted_kill_switch_enabled(controller),
                NftablesInterceptor::interception_was_active(
                    &net.linux_nft_binary,
                    &net.linux_nft_table_name,
                ),
            );
            if action == CrashCleanupAction::InstallFailClosed {
                controller.check_cleanup_allowed(force)?;
                NftablesInterceptor::install_fail_closed_table(
                    &net.linux_nft_binary,
                    &net.linux_nft_table_name,
                    &controller.telemetry,
                )?;
                NftablesInterceptor::delete_tproxy_routing(
                    &net.linux_ip_binary,
                    TproxyRoutingSpec {
                        fwmark: net.linux_tproxy_fwmark,
                        route_table: net.linux_tproxy_route_table,
                        rule_priority: net.linux_tproxy_rule_priority,
                        tproxy_port: net.default_local_name_inspect_port,
                    },
                    &controller.telemetry,
                );
                controller.telemetry.flush_file_logger();
                return Ok(());
            }
        }
        controller.cleanup_orphaned_rules(force)?;
        NftablesInterceptor::delete_fail_closed_table(
            &net.linux_nft_binary,
            &net.linux_nft_table_name,
            &controller.telemetry,
        );
        controller.telemetry.flush_file_logger();
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = fail_closed_on_crash;
        controller.cleanup_orphaned_rules(force)
    }
}

/// Runs `routeward cleanup --user`: gives back the per-user settings RouteWard changed.
fn run_cleanup_user(constants: &SystemConstants) -> RouteWardResult<UserCleanupReport> {
    let net = &constants.network;
    let socks_endpoint = format!("{}:{}", net.local_bind_host, net.default_relay_tcp_port);
    let pac_url = local_pac_url(&net.local_bind_host, net.default_pac_port);
    let report = SystemProxyManager::cleanup_current_user(&socks_endpoint, &pac_url)?;
    tracing::info!(
        proxy_restored = report.proxy_restored,
        pac_restored = report.pac_restored,
        autostart_removed = report.autostart_removed,
        "per-user settings cleanup finished"
    );
    Ok(report)
}

/// Gives back only the proxy and PAC settings that are still RouteWard's. Unlike
/// `cleanup --user`, it keeps the sign-in autostart entry: recovering the Internet must not
/// make the protection disappear at the next sign-in.
fn run_restore_owned_settings(constants: &SystemConstants) -> RouteWardResult<UserCleanupReport> {
    let net = &constants.network;
    let socks_endpoint = format!("{}:{}", net.local_bind_host, net.default_relay_tcp_port);
    let pac_url = local_pac_url(&net.local_bind_host, net.default_pac_port);
    let report = SystemProxyManager::restore_owned_settings(&socks_endpoint, &pac_url)?;
    tracing::info!(
        proxy_restored = report.proxy_restored,
        pac_restored = report.pac_restored,
        "owned proxy settings restored by recover"
    );
    Ok(report)
}

/// What the background protection answered to the "turn protection off" request of `recover`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoverDaemonOutcome {
    Stopped,
    Unreachable,
    Refused,
}

/// Locale keys of the lines `routeward recover` prints, in order. Restoring the proxy settings
/// decides the success: an unreachable background service never makes the command fail.
fn recover_message_keys(daemon: RecoverDaemonOutcome, restored: bool) -> Vec<&'static str> {
    let mut keys = vec![match daemon {
        RecoverDaemonOutcome::Stopped => "cli.recover.engine_stopped",
        RecoverDaemonOutcome::Unreachable => "cli.recover.daemon_unreachable",
        RecoverDaemonOutcome::Refused => "cli.recover.engine_stop_failed",
    }];
    if restored {
        keys.push("cli.recover.internet_restored");
        keys.push("cli.recover.next_step");
    } else {
        keys.push("cli.recover.failed");
    }
    keys
}

/// Runs `routeward recover`: best-effort turn-off of the background protection, then the same
/// restore of the proxy settings RouteWard owns (the autostart entry stays). Needs no elevation.
async fn run_recover(
    constants: SystemConstants,
    locale: &str,
    pause_at_end: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let i18n = I18nRegistry::new(locale);
    println!("{}", i18n.t("cli.recover.title"));

    let client = IpcClient::new(constants.ipc.clone());
    let daemon = match client
        .call_raw(IpcCommand::ToggleEngine { start: false })
        .await
    {
        Ok(resp) if resp.ok => RecoverDaemonOutcome::Stopped,
        Ok(_) => RecoverDaemonOutcome::Refused,
        Err(_) => RecoverDaemonOutcome::Unreachable,
    };
    let restore = run_restore_owned_settings(&constants);
    let restored = restore.is_ok();

    for key in recover_message_keys(daemon, restored) {
        if key == "cli.recover.failed" {
            eprintln!("{}", i18n.t(key));
        } else {
            println!("{}", i18n.t(key));
        }
    }
    if pause_at_end && std::io::stdout().is_terminal() {
        println!("{}", i18n.t("cli.recover.press_enter"));
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
    restore.map(|_| ()).map_err(Into::into)
}

/// Runs `routeward cleanup --all-users`: gives back the per-user settings of every user whose
/// hive is loaded. A failure for one user does not stop the others; the first one is returned
/// once every user has been processed.
fn run_cleanup_all_users(
    constants: &SystemConstants,
    i18n: &I18nRegistry,
) -> RouteWardResult<AllUsersCleanupReport> {
    if !RouteWardController::detect_admin_or_system() {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_NOT_ELEVATED,
            detail: i18n.t(ERR_KEY_DAEMON_NOT_ELEVATED),
        });
    }
    let net = &constants.network;
    let socks_endpoint = format!("{}:{}", net.local_bind_host, net.default_relay_tcp_port);
    let pac_url = local_pac_url(&net.local_bind_host, net.default_pac_port);
    let mut report = SystemProxyManager::cleanup_all_users(&socks_endpoint, &pac_url)?;
    tracing::info!(
        users_processed = report.users_processed,
        users_changed = report.users_changed,
        users_skipped = report.users_skipped,
        users_failed = report.failures.len(),
        "all-users settings cleanup finished"
    );
    for (sid, err) in &report.failures {
        tracing::warn!(sid = %sid, error = %err, "settings cleanup failed for a user");
    }
    if report.failures.is_empty() {
        Ok(report)
    } else {
        Err(report.failures.remove(0).1)
    }
}

/// Formats a `purge-data` or `cleanup --all-users` failure for stderr: the localized message,
/// followed by the error and its system detail, except for the privilege refusal whose detail is
/// already that localized message.
fn describe_admin_command_error(i18n: &I18nRegistry, err: &RouteWardError) -> String {
    let message = i18n.t(err.i18n_key());
    if err.i18n_key() == ERR_KEY_DAEMON_NOT_ELEVATED {
        message
    } else {
        format!("{message}: {err}")
    }
}

/// Runs `routeward purge-data`: removes `%ProgramData%\RouteWard` (Windows only). Requires an
/// elevated process and no active daemon (there is no `--force`: a running daemon holds its logs
/// and profile open).
fn run_purge_data(constants: &SystemConstants, i18n: &I18nRegistry) -> RouteWardResult<()> {
    if !RouteWardController::detect_admin_or_system() {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_NOT_ELEVATED,
            detail: i18n.t(ERR_KEY_DAEMON_NOT_ELEVATED),
        });
    }
    if is_daemon_ipc_active(&constants.ipc) {
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_CLEANUP_DAEMON_ACTIVE,
            detail: i18n.t(ERR_KEY_CLEANUP_DAEMON_ACTIVE),
        });
    }
    #[cfg(windows)]
    {
        routeward_core::system::purge::purge_data_dir(
            &routeward_core::system::purge::program_data_dir()?,
        )
    }
    #[cfg(not(windows))]
    {
        Err(RouteWardError::SystemError {
            key: routeward_core::error::ERR_KEY_SYSTEM_PURGE_UNSUPPORTED,
            detail: "purge-data is only implemented on Windows".to_string(),
        })
    }
}

/// Attempts to ask the new daemon to start protection during the upgrade migration. The service
/// may still be coming up when the installer commits, so a refused connection is retried a few
/// times before giving up.
const MIGRATE_DAEMON_ATTEMPTS: u32 = 5;
/// Pause between two attempts to reach the new daemon, in milliseconds.
const MIGRATE_DAEMON_RETRY_DELAY_MS: u64 = 1_000;

/// Calls `call` up to `attempts` times, sleeping `delay` between two attempts. `Ok(true)` is a
/// success, `Ok(false)` is a definitive refusal (no retry), `Err` is a connection failure that is
/// retried. Returns whether the daemon accepted the request.
async fn call_daemon_with_retry<F, Fut, E>(mut call: F, attempts: u32, delay: Duration) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool, E>>,
{
    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(delay).await;
        }
        if let Ok(accepted) = call().await {
            return accepted;
        }
    }
    false
}

/// Runs `routeward migrate-upgrade-state --user-sid <SID>` (hidden, run by the installer as
/// SYSTEM): reads and consumes the registry marker the installer left in that user's hive, then,
/// when the old daemon was running and no state file exists yet, turns protection on through the
/// new daemon, or persists the enabled state directly when the daemon is unreachable. Every outcome
/// is logged and the command never fails, so it can never break an upgrade.
async fn run_migrate_upgrade_state(constants: &SystemConstants, user_sid: &str) {
    let protection_was_running = consume_upgrade_marker(user_sid);
    let profile_path = match constants.ipc.resolve_daemon_profile_path() {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!(error = %err, "cannot resolve the daemon profile path, nothing migrated");
            return;
        }
    };
    let state_path =
        routeward_core::system::protection_state::state_path_for_profile(&profile_path);
    let client = IpcClient::new(constants.ipc.clone());
    let outcome = migrate_upgrade_state(&state_path, protection_was_running, || {
        call_daemon_with_retry(
            || async {
                client
                    .call_raw(IpcCommand::ToggleEngine { start: true })
                    .await
                    .map(|resp| resp.ok)
            },
            MIGRATE_DAEMON_ATTEMPTS,
            Duration::from_millis(MIGRATE_DAEMON_RETRY_DELAY_MS),
        )
    })
    .await;
    tracing::info!(outcome = ?outcome, "upgrade protection state migration finished");
}

#[derive(Subcommand)]
enum ServiceCommands {
    /// Install or reconfigure the RouteWard Windows Service
    Install {
        /// Explicit path to routeward.exe (defaults to the current executable path)
        #[arg(long = "bin-path", value_name = "PATH")]
        bin_path: Option<PathBuf>,
        /// Additional allowed Windows user SID for restricted Named Pipe IPC access (repeatable)
        #[arg(long = "allow-sid", value_name = "SID")]
        allow_sid: Vec<String>,
        /// Include the current invoking account SID in the pipe ACL (for interactive admin desktop use)
        #[arg(long)]
        allow_current_user: bool,
        /// Configure manual start instead of automatic start on boot
        #[arg(long)]
        demand_start: bool,
        /// Start the service once it is installed, in the same elevated invocation
        #[arg(long)]
        start: bool,
    },
    /// Re-register the service after an MSI upgrade from the captured old ImagePath
    Restore {
        /// Start the service once it is registered
        #[arg(long)]
        start: bool,
        /// Configure manual start instead of automatic start on boot
        #[arg(long)]
        demand_start: bool,
        /// Captured old service command line (after `--`): executable token, `service run`, allow-sid flags
        #[arg(
            last = true,
            required = true,
            allow_hyphen_values = true,
            value_name = "IMAGE_PATH_ARGS"
        )]
        image_path: Vec<String>,
    },
    /// Stop and remove the RouteWard Windows Service
    Uninstall,
    /// Start the installed RouteWard Windows Service via SCM
    Start,
    /// Stop the running RouteWard Windows Service via SCM
    Stop,
    /// Query RouteWard Windows Service installation and runtime state as JSON
    Status,
    /// Run inside Windows Service Control Manager (invoked by services.exe)
    Run {
        /// Additional allowed Windows user SID for restricted Named Pipe IPC access (repeatable)
        #[arg(long = "allow-sid", value_name = "SID")]
        allow_sid: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CtlCommands {
    /// Query daemon diagnostics and interception engine status
    Status,
    /// Query full daemon state (diagnostics, profile, telemetry, connections, logs)
    State,
    /// Start the relay and transparent OS packet interceptor on the daemon
    Start,
    /// Stop the relay and transparent OS packet interceptor on the daemon
    Stop,
    /// Pause protection for a while: the daemon stops the engine and starts it again by itself
    Pause {
        /// Pause length in seconds (1 to 86400)
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..=MAX_PAUSE_SECS))]
        seconds: u64,
    },
    /// List tracked connections from the daemon
    Connections,
    /// List recent log entries from the daemon. Without any option the raw log buffer is
    /// printed as JSON; with an option the entries are filtered by the daemon and printed as lines
    Logs {
        /// Lowest level to show: debug, info, warn or error
        #[arg(long)]
        level: Option<String>,
        /// Only this component (repeatable)
        #[arg(long)]
        component: Vec<String>,
        /// Only lines containing this text (case-insensitive)
        #[arg(long)]
        grep: Option<String>,
        /// Only lines about this process id
        #[arg(long)]
        pid: Option<u32>,
        /// Only lines newer than this age, for example 15m, 2h or 1d
        #[arg(long, value_name = "AGE")]
        since: Option<String>,
        /// Read the daemon log file of this day (yyyyMMdd) instead of the live buffer
        #[arg(long, value_name = "YYYYMMDD")]
        file: Option<String>,
        /// Most lines to show
        #[arg(long)]
        limit: Option<usize>,
    },
    /// List the connections the daemon blocked, grouped by application, destination and reason
    Blocked {
        /// Print the daemon answer as JSON
        #[arg(long)]
        json: bool,
        /// Most entries to show
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Run the check-up: what is wrong and what to do about it
    Diagnose {
        /// Print the findings as JSON
        #[arg(long)]
        json: bool,
    },
    /// Write a redacted diagnostic file (settings without passwords, blocked list, recent logs)
    ExportDiagnostics {
        /// File to write
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// Leave the logs out
        #[arg(long = "no-logs")]
        no_logs: bool,
        /// Leave the settings out
        #[arg(long = "no-profile")]
        no_profile: bool,
        /// Leave the recent connections out
        #[arg(long = "no-connections")]
        no_connections: bool,
        /// Replace every website name by a short code
        #[arg(long = "mask-domains")]
        mask_domains: bool,
        /// Replace the file when it already exists
        #[arg(long)]
        force: bool,
        /// Days of logs to include (default from the system constants)
        #[arg(long = "log-days", value_name = "N")]
        log_days: Option<u32>,
    },
    /// List active Fake-IP allocations from the daemon
    FakeIps,
    /// Flush all Fake-IP allocations on the daemon
    FlushFakeIps,
    /// Insert or update a routing rule (via inline JSON string or UTF-8 JSON file) on the daemon
    UpsertRule {
        /// Inline JSON string describing the routing rule
        #[arg(
            long,
            required_unless_present = "json_file",
            conflicts_with = "json_file"
        )]
        json: Option<String>,
        /// Path to a UTF-8 JSON file describing the routing rule (recommended on Windows PowerShell 5.1)
        #[arg(
            long = "json-file",
            value_name = "PATH",
            required_unless_present = "json",
            conflicts_with = "json"
        )]
        json_file: Option<PathBuf>,
    },
    /// Remove a routing rule by its identifier on the daemon
    RemoveRule {
        #[arg(long)]
        id: String,
    },
    /// Insert or update a proxy node (via inline JSON string or UTF-8 JSON file) on the daemon
    UpsertProxy {
        /// Inline JSON string describing the proxy node
        #[arg(
            long,
            required_unless_present = "json_file",
            conflicts_with = "json_file"
        )]
        json: Option<String>,
        /// Path to a UTF-8 JSON file describing the proxy node
        #[arg(
            long = "json-file",
            value_name = "PATH",
            required_unless_present = "json",
            conflicts_with = "json"
        )]
        json_file: Option<PathBuf>,
    },
    /// Remove a proxy node by its identifier on the daemon
    RemoveProxy {
        #[arg(long)]
        id: String,
    },
    /// Actively terminate an open connection by its identifier
    TerminateConnection {
        #[arg(long)]
        id: String,
    },
    /// Replace the active daemon profile live (via inline JSON string or UTF-8 JSON file)
    ReplaceProfile {
        /// Inline JSON string describing the full profile configuration
        #[arg(
            long,
            required_unless_present = "json_file",
            conflicts_with = "json_file"
        )]
        json: Option<String>,
        /// Path to a UTF-8 JSON file describing the full profile configuration
        #[arg(
            long = "json-file",
            value_name = "PATH",
            required_unless_present = "json",
            conflicts_with = "json"
        )]
        json_file: Option<PathBuf>,
    },
}

fn parse_json_payload<T: serde::de::DeserializeOwned>(
    entity_label: &str,
    json: Option<String>,
    json_file: Option<PathBuf>,
) -> RouteWardResult<T> {
    if let Some(path) = json_file {
        let raw_content =
            std::fs::read_to_string(&path).map_err(|err| RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!(
                    "Cannot read {entity_label} JSON file '{}': {err}",
                    path.display()
                ),
            })?;
        let without_bom = raw_content.strip_prefix('\u{feff}').unwrap_or(&raw_content);
        serde_json::from_str::<T>(without_bom).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: format!(
                "Invalid {entity_label} JSON in file '{}': {err}",
                path.display()
            ),
        })
    } else if let Some(raw_inline) = json {
        let without_bom = raw_inline.strip_prefix('\u{feff}').unwrap_or(&raw_inline);
        serde_json::from_str::<T>(without_bom).map_err(|err| RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: format!("Invalid inline {entity_label} JSON: {err}"),
        })
    } else {
        Err(RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: "Either --json or --json-file must be provided".to_string(),
        })
    }
}

fn ctl_action_label(action: &CtlCommands) -> &'static str {
    match action {
        CtlCommands::Status => "status",
        CtlCommands::State => "state",
        CtlCommands::Start => "start",
        CtlCommands::Stop => "stop",
        CtlCommands::Pause { .. } => "pause",
        CtlCommands::Connections => "connections",
        CtlCommands::Logs { .. } => "logs",
        CtlCommands::Blocked { .. } => "blocked",
        CtlCommands::Diagnose { .. } => "diagnose",
        CtlCommands::ExportDiagnostics { .. } => "export-diagnostics",
        CtlCommands::FakeIps => "fake-ips",
        CtlCommands::FlushFakeIps => "flush-fake-ips",
        CtlCommands::UpsertRule { .. } => "upsert-rule",
        CtlCommands::RemoveRule { .. } => "remove-rule",
        CtlCommands::UpsertProxy { .. } => "upsert-proxy",
        CtlCommands::RemoveProxy { .. } => "remove-proxy",
        CtlCommands::TerminateConnection { .. } => "terminate-connection",
        CtlCommands::ReplaceProfile { .. } => "replace-profile",
    }
}

/// Milliseconds since the Unix epoch.
fn epoch_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// How the answer of a ctl command is printed.
enum CtlRender {
    /// The daemon answer as pretty JSON.
    Raw,
    Logs,
    Blocked,
    Diagnose,
    Export {
        output: PathBuf,
        force: bool,
    },
}

impl CtlRender {
    fn for_action(action: &CtlCommands) -> Self {
        match action {
            CtlCommands::Logs {
                level: None,
                component,
                grep: None,
                pid: None,
                since: None,
                file: None,
                limit: None,
            } if component.is_empty() => Self::Raw,
            CtlCommands::Logs { .. } => Self::Logs,
            CtlCommands::Blocked { json: false, .. } => Self::Blocked,
            CtlCommands::Diagnose { json: false } => Self::Diagnose,
            CtlCommands::ExportDiagnostics { output, force, .. } => Self::Export {
                output: output.clone(),
                force: *force,
            },
            _ => Self::Raw,
        }
    }
}

/// Prints the answer of a successful ctl command; the export is written to its file.
fn print_ctl_result(
    render: CtlRender,
    result: serde_json::Value,
    i18n: &I18nRegistry,
) -> Result<(), Box<dyn std::error::Error>> {
    match render {
        CtlRender::Raw => {}
        CtlRender::Logs => {
            let response = serde_json::from_value(result)?;
            print!("{}", ctl_reports::format_logs(i18n, &response));
        }
        CtlRender::Blocked => {
            let response = serde_json::from_value(result)?;
            print!("{}", ctl_reports::format_blocked(i18n, &response));
        }
        CtlRender::Diagnose => {
            let response = serde_json::from_value(result)?;
            print!("{}", ctl_reports::format_findings(i18n, &response));
        }
        CtlRender::Export { output, force } => {
            match ctl_reports::write_export(&output, &result, force) {
                Ok(()) => print!("{}", ctl_reports::export_summary(i18n, &output, &result)),
                Err(ctl_reports::ExportError::Exists) => {
                    return Err(ctl_reports::export_exists_message(i18n, &output).into());
                }
                Err(ctl_reports::ExportError::Io(err)) => return Err(err.into()),
            }
        }
    }
    Ok(())
}

fn ctl_action_into_ipc(
    action: CtlCommands,
    i18n: &I18nRegistry,
) -> Result<(&'static str, IpcCommand), Box<dyn std::error::Error>> {
    let label = ctl_action_label(&action);
    let ipc_cmd = match action {
        CtlCommands::Status => IpcCommand::GetDiagnostics,
        CtlCommands::State => IpcCommand::GetState,
        CtlCommands::Start => IpcCommand::ToggleEngine { start: true },
        CtlCommands::Stop => IpcCommand::ToggleEngine { start: false },
        CtlCommands::Pause { seconds } => IpcCommand::PauseEngine {
            duration_secs: seconds,
        },
        CtlCommands::Connections => IpcCommand::ListConnections,
        CtlCommands::Logs {
            level,
            component,
            grep,
            pid,
            since,
            file,
            limit,
        } => {
            let unfiltered = level.is_none()
                && component.is_empty()
                && grep.is_none()
                && pid.is_none()
                && since.is_none()
                && file.is_none()
                && limit.is_none();
            if unfiltered {
                IpcCommand::ListLogs
            } else {
                let min_level = level
                    .as_deref()
                    .map(|raw| ctl_reports::parse_level(i18n, raw))
                    .transpose()?;
                let age = since
                    .as_deref()
                    .map(|raw| ctl_reports::parse_since(i18n, raw))
                    .transpose()?;
                IpcCommand::QueryLogs {
                    source: match file {
                        Some(date) => LogQuerySource::DaemonFile { date },
                        None => LogQuerySource::Memory,
                    },
                    min_level,
                    components: component,
                    text: grep,
                    pid,
                    connection_id: None,
                    since: age.map(|age| epoch_ms_now().saturating_sub(age.as_millis() as i64)),
                    until: None,
                    limit: limit.unwrap_or(ctl_reports::DEFAULT_LOG_LIMIT),
                    cursor: None,
                }
            }
        }
        CtlCommands::Blocked { limit, .. } => IpcCommand::ListBlocked { since: None, limit },
        CtlCommands::Diagnose { .. } => IpcCommand::Analyze,
        CtlCommands::ExportDiagnostics {
            no_logs,
            no_profile,
            no_connections,
            mask_domains,
            log_days,
            ..
        } => IpcCommand::CollectDiagnostics {
            log_days: if no_logs {
                0
            } else {
                match log_days {
                    Some(days) => days,
                    None => {
                        SystemConstants::load_embedded()?
                            .telemetry
                            .diagnostics_default_log_days
                    }
                }
            },
            include_connections: !no_connections,
            include_profile: !no_profile,
            mask_domains,
        },
        CtlCommands::FakeIps => IpcCommand::ListFakeIps,
        CtlCommands::FlushFakeIps => IpcCommand::FlushFakeIps,
        CtlCommands::UpsertRule { json, json_file } => {
            let rule = parse_json_payload::<RoutingRule>("rule", json, json_file)?;
            IpcCommand::UpsertRule { rule }
        }
        CtlCommands::RemoveRule { id } => IpcCommand::RemoveRule { rule_id: id },
        CtlCommands::UpsertProxy { json, json_file } => {
            let node = parse_json_payload::<ProxyNode>("proxy", json, json_file)?;
            IpcCommand::UpsertProxy { node }
        }
        CtlCommands::RemoveProxy { id } => IpcCommand::RemoveProxy { proxy_id: id },
        CtlCommands::TerminateConnection { id } => {
            IpcCommand::TerminateConnection { connection_id: id }
        }
        CtlCommands::ReplaceProfile { json, json_file } => {
            let profile = parse_json_payload::<ProfileConfig>("profile", json, json_file)?;
            IpcCommand::ReplaceProfile { profile }
        }
    };
    Ok((label, ipc_cmd))
}

async fn execute_ctl_action(
    client: &IpcClient,
    user_logger: &FileLogger,
    i18n: &I18nRegistry,
    action: CtlCommands,
) -> Result<routeward_core::ipc::protocol::IpcResponse, Box<dyn std::error::Error>> {
    let expected_label = ctl_action_label(&action);
    let (cmd_label, ipc_cmd) = match ctl_action_into_ipc(action, i18n) {
        Ok(pair) => pair,
        Err(err) => {
            user_logger.log(
                LogLevel::Info,
                COMPONENT_CLI_CTL,
                &format!("Executed ctl command '{expected_label}': outcome=invalid_input ({err})"),
            );
            return Err(err);
        }
    };

    let response = match client.call_raw(ipc_cmd).await {
        Ok(resp) => resp,
        Err(err) => {
            user_logger.log(
                LogLevel::Info,
                COMPONENT_CLI_CTL,
                &format!("Executed ctl command '{cmd_label}': outcome=ipc_error ({err})"),
            );
            return Err(err.into());
        }
    };

    if response.ok {
        user_logger.log(
            LogLevel::Info,
            COMPONENT_CLI_CTL,
            &format!("Executed ctl command '{cmd_label}': outcome=success"),
        );
    } else {
        let err_msg = response
            .error
            .clone()
            .unwrap_or_else(|| "Daemon returned error".to_string());
        user_logger.log(
            LogLevel::Info,
            COMPONENT_CLI_CTL,
            &format!("Executed ctl command '{cmd_label}': outcome=daemon_error ({err_msg})"),
        );
    }

    Ok(response)
}

struct ShutdownSignals {
    #[cfg(unix)]
    sigterm: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    sigint: Option<tokio::signal::unix::Signal>,
}

impl ShutdownSignals {
    fn register() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Self {
                sigterm: signal(SignalKind::terminate()).ok(),
                sigint: signal(SignalKind::interrupt()).ok(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {}
        }
    }

    async fn wait(#[cfg_attr(not(unix), allow(unused_mut))] mut self) {
        #[cfg(unix)]
        {
            match (&mut self.sigterm, &mut self.sigint) {
                (Some(term), Some(intr)) => {
                    tokio::select! {
                        _ = term.recv() => {},
                        _ = intr.recv() => {},
                    }
                    return;
                }
                (Some(term), None) => {
                    let _ = term.recv().await;
                    return;
                }
                _ => {}
            }
        }
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn run_daemon_host(
    constants: SystemConstants,
    locale: &str,
    duration_secs: Option<u64>,
    allowed_sids: &[String],
    mut external_shutdown: Option<watch::Receiver<bool>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let i18n = I18nRegistry::new(locale);
    if !RouteWardController::detect_admin_or_system() {
        let msg = i18n.t(ERR_KEY_DAEMON_NOT_ELEVATED);
        eprintln!("{msg}");
        return Err(RouteWardError::DaemonError {
            key: ERR_KEY_DAEMON_NOT_ELEVATED,
            detail: msg,
        }
        .into());
    }

    let fixed_profile_path = constants.ipc.resolve_daemon_profile_path()?;
    let profile = match load_or_init_secure_daemon_profile(&fixed_profile_path) {
        Ok(prof) => prof,
        Err(err) => {
            let localized = i18n.t(err.i18n_key());
            eprintln!("{localized}: {err}");
            return Err(err.into());
        }
    };

    let controller = RouteWardController::new_daemon(constants, profile, locale);

    let service = match DaemonIpcService::bind_with_allowed_sids(controller.clone(), allowed_sids) {
        Ok(svc) => svc,
        Err(err) => {
            let localized = controller.i18n.t(err.i18n_key());
            eprintln!("{localized}: {err}");
            return Err(err.into());
        }
    };

    let _ = controller.cleanup_orphaned_rules(true);
    println!("=== {} ===", controller.i18n.t("cli.engine.daemon.banner"));
    println!("{}", controller.i18n.t("cli.engine.cleanup.completed"));
    #[cfg(unix)]
    let ipc_endpoint = controller.constants.ipc.unix_socket_path.clone();
    #[cfg(windows)]
    let ipc_endpoint = controller.constants.ipc.windows_pipe_name.clone();
    println!(
        "{}: {ipc_endpoint}",
        controller.i18n.t("cli.engine.daemon.listening_ipc")
    );

    let (local_shutdown_tx, accept_shutdown) = watch::channel(false);
    // Re-applies the protection the user left on (or a pause that is still running). A failure
    // is logged and shown in the diagnostics; it never stops the daemon.
    controller.apply_persisted_protection();
    let pac_shutdown = local_shutdown_tx.subscribe();
    let mut accept_handle = tokio::spawn(async move {
        let _ = service.run_accept_loop_until(accept_shutdown).await;
    });
    let mut pac_handle =
        PacGenerator::spawn_pac_http_server(Arc::new(controller.clone()), pac_shutdown);

    let wait_signals = ShutdownSignals::register();
    let external_wait = async {
        match external_shutdown.as_mut() {
            Some(rx) => wait_for_shutdown_signal(rx).await,
            None => std::future::pending::<()>().await,
        }
    };
    if let Some(secs) = duration_secs {
        tokio::select! {
            _ = wait_signals.wait() => {},
            _ = external_wait => {},
            _ = tokio::time::sleep(Duration::from_secs(secs)) => {},
        }
    } else {
        tokio::select! {
            _ = wait_signals.wait() => {},
            _ = external_wait => {},
        }
    }

    let _ = local_shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), &mut accept_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), &mut pac_handle).await;
    if controller.is_running() {
        controller.stop_engine();
    }
    Ok(())
}

fn handle_service_command(
    action: ServiceCommands,
    locale: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let i18n = I18nRegistry::new(locale);
    match action {
        ServiceCommands::Run { allow_sid } => {
            run_windows_service_dispatcher(
                locale.to_string(),
                allow_sid,
                Box::new(|svc_locale, sids, shutdown_notify| {
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .map_err(|err| RouteWardError::DaemonError {
                            key: routeward_core::error::ERR_KEY_DAEMON_IPC_ERROR,
                            detail: format!(
                                "Failed to construct Tokio runtime for SCM service: {err}"
                            ),
                        })?;
                    let constants = SystemConstants::load_embedded()?;
                    rt.block_on(async move {
                        run_daemon_host(constants, &svc_locale, None, &sids, Some(shutdown_notify))
                            .await
                            .map_err(|err| RouteWardError::DaemonError {
                                key: routeward_core::error::ERR_KEY_DAEMON_IPC_ERROR,
                                detail: err.to_string(),
                            })
                    })
                }),
            )?;
            Ok(())
        }
        ServiceCommands::Install {
            bin_path,
            #[cfg_attr(not(windows), allow(unused_mut))]
            mut allow_sid,
            allow_current_user,
            demand_start,
            start,
        } => {
            if allow_current_user {
                #[cfg(windows)]
                {
                    let current_sid = routeward_core::ipc::transport::current_user_sid_string()?;
                    allow_sid.push(current_sid);
                }
            }
            let exe_str = bin_path.as_ref().map(|p| p.to_string_lossy().into_owned());
            let mut status =
                install_windows_service(exe_str.as_deref(), &allow_sid, !demand_start)?;
            eprintln!("{}", i18n.t("cli.engine.service.installed"));
            if start {
                status = start_windows_service()?;
                eprintln!("{}", i18n.t("cli.engine.service.started"));
            }
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        ServiceCommands::Restore {
            start,
            demand_start,
            image_path,
        } => {
            let status = restore_windows_service(&image_path, demand_start, start)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            eprintln!("{}", i18n.t("cli.engine.service.installed"));
            Ok(())
        }
        ServiceCommands::Uninstall => {
            uninstall_windows_service()?;
            let status = query_windows_service_status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            eprintln!("{}", i18n.t("cli.engine.service.uninstalled"));
            Ok(())
        }
        ServiceCommands::Start => {
            let status = start_windows_service()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            eprintln!("{}", i18n.t("cli.engine.service.started"));
            Ok(())
        }
        ServiceCommands::Stop => {
            let status = stop_windows_service()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            eprintln!("{}", i18n.t("cli.engine.service.stopped"));
            Ok(())
        }
        ServiceCommands::Status => {
            let status = query_windows_service_status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
    }
}

/// Initializes logging once the arguments are known. The MSI custom actions (`purge-data` and
/// `cleanup --all-users`) run as SYSTEM and their log is the only diagnostic, so they default to
/// INFO when `RUST_LOG` is unset; every other command keeps the stock behaviour.
fn init_logging(command: &Commands) {
    let verbose_default = matches!(
        command,
        Commands::PurgeData
            | Commands::MigrateUpgradeState { .. }
            | Commands::Cleanup {
                all_users: true,
                ..
            }
    );
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal());
    if verbose_default {
        let filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
            .from_env_lossy();
        builder.with_env_filter(filter).init();
    } else {
        let filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::ERROR.into())
            .from_env_lossy();
        builder.with_env_filter(filter).init();
    }
}

impl CliArgs {
    fn resolved_locale(&self) -> String {
        resolve_locale(self.locale.as_deref(), os_default_locale)
    }
}

fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();
    init_logging(&args.command);

    let locale = args.resolved_locale();
    if let Commands::Service { action } = args.command {
        return handle_service_command(action, &locale);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main(args))
}

fn main() -> std::process::ExitCode {
    match run_cli() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            let code = err
                .downcast_ref::<RouteWardError>()
                .map_or(routeward_core::error::DAEMON_EXIT_GENERAL_ERROR, |rw| {
                    rw.daemon_exit_code()
                });
            std::process::ExitCode::from(code)
        }
    }
}

/// The per-user CLI log, pruned like every other log (`logRetentionDays`).
fn open_user_logger(log_dir: std::path::PathBuf, telemetry: &TelemetryConstants) -> FileLogger {
    let logger = FileLogger::new(log_dir, &telemetry.log_app_name, true);
    logger.set_retention_days(telemetry.log_retention_days);
    logger
}

async fn async_main(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let locale = args.resolved_locale();
    let constants = SystemConstants::load_embedded()?;

    if let Commands::Ctl { action } = args.command {
        let user_logger = open_user_logger(
            constants.telemetry.resolve_user_log_dir(),
            &constants.telemetry,
        );
        let client = IpcClient::new(constants.ipc);
        let i18n = I18nRegistry::new(&locale);
        let render = CtlRender::for_action(&action);
        if let CtlRender::Export {
            output,
            force: false,
        } = &render
        {
            // Refuse before asking the daemon for a bundle that could not be saved.
            if output.exists() {
                return Err(ctl_reports::export_exists_message(&i18n, output).into());
            }
        }
        let response = execute_ctl_action(&client, &user_logger, &i18n, action).await?;
        if !response.ok {
            println!("{}", serde_json::to_string_pretty(&response)?);
            let err_msg = response
                .error
                .unwrap_or_else(|| "Daemon returned error".to_string());
            return Err(err_msg.into());
        }
        if matches!(render, CtlRender::Raw) {
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }
        let Some(result) = response.result else {
            return Err(ctl_reports::empty_result_message(&i18n).into());
        };
        return print_ctl_result(render, result, &i18n);
    }

    if let Commands::Daemon {
        duration_secs,
        allow_sid,
    } = args.command
    {
        return run_daemon_host(constants, &locale, duration_secs, &allow_sid, None).await;
    }

    if let Commands::Recover { pause_at_end } = args.command {
        return run_recover(constants, &locale, pause_at_end).await;
    }

    if let Commands::MigrateUpgradeState { user_sid } = &args.command {
        run_migrate_upgrade_state(&constants, user_sid).await;
        return Ok(());
    }

    if matches!(args.command, Commands::PurgeData) {
        let i18n = I18nRegistry::new(&locale);
        if let Err(err) = run_purge_data(&constants, &i18n) {
            eprintln!("{}", describe_admin_command_error(&i18n, &err));
            return Err(err.into());
        }
        println!("{}", i18n.t("cli.engine.purge.completed"));
        return Ok(());
    }

    if matches!(
        args.command,
        Commands::Cleanup {
            all_users: true,
            ..
        }
    ) {
        let i18n = I18nRegistry::new(&locale);
        if let Err(err) = run_cleanup_all_users(&constants, &i18n) {
            eprintln!("{}", describe_admin_command_error(&i18n, &err));
            return Err(err.into());
        }
        println!("{}", i18n.t("cli.engine.cleanup.all_users_completed"));
        return Ok(());
    }

    if matches!(args.command, Commands::Cleanup { user: true, .. }) {
        let i18n = I18nRegistry::new(&locale);
        if let Err(err) = run_cleanup_user(&constants) {
            eprintln!("{}", i18n.t(err.i18n_key()));
            return Err(err.into());
        }
        println!("{}", i18n.t("cli.engine.cleanup.user_completed"));
        return Ok(());
    }

    if matches!(args.command, Commands::Run { .. })
        && !RouteWardController::detect_admin_or_system()
    {
        let i18n = I18nRegistry::new(&locale);
        let msg = i18n.t(routeward_core::error::ERR_KEY_INTERCEPTOR_NOT_ROOT);
        eprintln!("{msg}");
        return Err(RouteWardError::DaemonError {
            key: routeward_core::error::ERR_KEY_DAEMON_NOT_ELEVATED,
            detail: msg,
        }
        .into());
    }

    let profile = match &args.profile {
        Some(path) => ProfileConfig::load_from_path(path)?,
        None => ProfileConfig::load_embedded_default()?,
    };

    let controller = match args.command {
        Commands::Run { .. } | Commands::Cleanup { .. } => {
            RouteWardController::new(constants, profile, &locale)
        }
        _ => RouteWardController::new_user_cli(constants, profile, &locale),
    };

    match args.command {
        Commands::Run { duration_secs } => {
            let shutdown_signals = ShutdownSignals::register();
            println!("=== {} ===", controller.i18n.t("cli.engine.startup.banner"));
            controller.start_engine()?;
            let diag = controller.diagnostics();
            println!(
                "{}: {}",
                controller.i18n.t("cli.engine.startup.listening_socks"),
                diag.relay_tcp_endpoint
            );
            println!(
                "{}: {}:{}",
                controller
                    .i18n
                    .t("cli.engine.startup.listening_transparent"),
                controller.constants.network.transparent_bind_host,
                controller.constants.network.default_transparent_tcp_port
            );

            match controller.start_transparent_interceptor() {
                Ok(backend) => {
                    println!(
                        "{}: {backend}",
                        controller.i18n.t("cli.engine.startup.interception_active")
                    );
                }
                Err(err) => {
                    controller.stop_engine();
                    return Err(err.into());
                }
            }

            if let Some(secs) = duration_secs {
                println!(
                    "{}: {secs}s",
                    controller.i18n.t("cli.engine.startup.duration_limit")
                );
            }
            println!("{}", controller.i18n.t("cli.engine.startup.ready"));

            if let Some(secs) = duration_secs {
                tokio::select! {
                    _ = shutdown_signals.wait() => {},
                    _ = tokio::time::sleep(Duration::from_secs(secs)) => {},
                }
            } else {
                shutdown_signals.wait().await;
            }

            controller.stop_engine();
        }
        Commands::Check { proxy_id } => {
            println!("{}...", controller.i18n.t("cli.engine.check.testing"));
            if let Some(id) = proxy_id {
                let report = controller.test_proxy(&id).await?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let reports = controller.test_all_proxies().await;
                println!("{}", serde_json::to_string_pretty(&reports)?);
            }
        }
        Commands::Eval {
            process,
            host,
            port,
        } => {
            let result = controller.evaluate_rule(&ConnectionRequest {
                process_name: process,
                process_path: None,
                target_host: host,
                target_ip: None,
                target_port: port,
                protocol: TransportProtocol::Tcp,
            });
            println!(
                "{}:\n{}",
                controller.i18n.t("cli.engine.rule_eval.matched"),
                serde_json::to_string_pretty(&result)?
            );
        }
        Commands::FakeIp { domain } => {
            let allocated = controller.allocate_fake_ip(&domain);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "domain": domain,
                    "fakeIp": allocated,
                    "entries": controller.dns.list_entries()
                }))?
            );
        }
        Commands::Cleanup {
            force,
            fail_closed_on_crash,
            user: _,
            all_users: _,
        } => {
            if let Err(err) = run_cleanup(&controller, force, fail_closed_on_crash) {
                let localized = controller.i18n.t(err.i18n_key());
                eprintln!("{localized}");
                return Err(err.into());
            }
            println!("{}", controller.i18n.t("cli.engine.cleanup.completed"));
        }
        Commands::Daemon { .. }
        | Commands::Ctl { .. }
        | Commands::Service { .. }
        | Commands::Recover { .. }
        | Commands::PurgeData
        | Commands::MigrateUpgradeState { .. } => unreachable!(),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn locale_resolution_prefers_the_explicit_value_over_the_os() {
        assert_eq!(super::resolve_locale(Some("en"), || "fr"), "en");
        assert_eq!(super::resolve_locale(None, || "fr"), "fr");
    }

    #[test]
    fn locale_flag_and_env_are_optional_and_the_flag_wins() {
        let flag = CliArgs::try_parse_from(["routeward", "--locale", "fr", "ctl", "status"])
            .expect("parse --locale");
        assert_eq!(flag.locale.as_deref(), Some("fr"));
        let absent =
            CliArgs::try_parse_from(["routeward", "ctl", "status"]).expect("parse no locale");
        if std::env::var_os("ROUTEWARD_LOCALE").is_none() {
            assert_eq!(absent.locale, None);
        }
    }

    use super::*;
    use routeward_core::error::ERR_KEY_CLEANUP_DAEMON_ACTIVE;
    use routeward_core::ipc::protocol::DaemonFullState;

    #[test]
    fn the_user_cli_log_prunes_files_past_the_retention() {
        let dir = std::env::temp_dir().join(format!(
            "routeward_cli_retention_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let constants = SystemConstants::load_embedded().expect("constants");
        let old = dir.join(routeward_core::logger::log_file_name(
            &constants.telemetry.log_app_name,
            "20200101",
        ));
        std::fs::write(&old, "old").expect("old log");
        let logger = open_user_logger(dir.clone(), &constants.telemetry);
        logger.log(routeward_core::telemetry::LogLevel::Info, "Test", "today");
        assert!(!old.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cleanup_accepts_fail_closed_on_crash_flag() {
        let args =
            CliArgs::try_parse_from(["routeward", "cleanup", "--force", "--fail-closed-on-crash"])
                .expect("flag parses");
        match args.command {
            Commands::Cleanup {
                force,
                fail_closed_on_crash,
                ..
            } => assert!(force && fail_closed_on_crash),
            _ => panic!("expected cleanup"),
        }
        let plain = CliArgs::try_parse_from(["routeward", "cleanup"]).expect("plain parses");
        match plain.command {
            Commands::Cleanup {
                force,
                fail_closed_on_crash,
                user,
                all_users,
            } => assert!(!force && !fail_closed_on_crash && !user && !all_users),
            _ => panic!("expected cleanup"),
        }
    }

    #[test]
    fn cleanup_user_flag_parses_and_excludes_the_machine_wide_flags() {
        let args = CliArgs::try_parse_from(["routeward", "cleanup", "--user"]).expect("parses");
        assert!(matches!(args.command, Commands::Cleanup { user: true, .. }));
        assert!(CliArgs::try_parse_from(["routeward", "cleanup", "--user", "--force"]).is_err());
        assert!(CliArgs::try_parse_from([
            "routeward",
            "cleanup",
            "--user",
            "--fail-closed-on-crash"
        ])
        .is_err());
    }

    #[test]
    fn cleanup_all_users_flag_parses_and_excludes_the_other_modes() {
        let args =
            CliArgs::try_parse_from(["routeward", "cleanup", "--all-users"]).expect("parses");
        assert!(matches!(
            args.command,
            Commands::Cleanup {
                all_users: true,
                ..
            }
        ));
        for other in ["--user", "--force", "--fail-closed-on-crash"] {
            assert!(
                CliArgs::try_parse_from(["routeward", "cleanup", "--all-users", other]).is_err(),
                "--all-users must conflict with {other}"
            );
        }
    }

    #[test]
    fn recover_parses_with_and_without_pause_at_end() {
        let plain = CliArgs::try_parse_from(["routeward", "recover"]).expect("parses");
        assert!(matches!(
            plain.command,
            Commands::Recover {
                pause_at_end: false
            }
        ));
        let paused =
            CliArgs::try_parse_from(["routeward", "recover", "--pause-at-end"]).expect("parses");
        assert!(matches!(
            paused.command,
            Commands::Recover { pause_at_end: true }
        ));
    }

    #[test]
    fn recover_succeeds_when_the_service_is_unreachable_as_long_as_the_proxy_is_restored() {
        let ok = recover_message_keys(RecoverDaemonOutcome::Unreachable, true);
        assert_eq!(
            ok,
            vec![
                "cli.recover.daemon_unreachable",
                "cli.recover.internet_restored",
                "cli.recover.next_step"
            ]
        );
        let stopped = recover_message_keys(RecoverDaemonOutcome::Stopped, true);
        assert_eq!(stopped[0], "cli.recover.engine_stopped");
        let refused = recover_message_keys(RecoverDaemonOutcome::Refused, false);
        assert_eq!(
            refused,
            vec!["cli.recover.engine_stop_failed", "cli.recover.failed"]
        );
    }

    #[test]
    fn recover_messages_exist_in_both_locales_without_jargon() {
        for locale in ["en", "fr"] {
            let i18n = I18nRegistry::new(locale);
            for key in [
                "cli.recover.title",
                "cli.recover.engine_stopped",
                "cli.recover.daemon_unreachable",
                "cli.recover.engine_stop_failed",
                "cli.recover.internet_restored",
                "cli.recover.next_step",
                "cli.recover.failed",
                "cli.recover.press_enter",
            ] {
                let text = i18n.t(key);
                assert_ne!(text, key, "{locale}: missing {key}");
                let lower = text.to_lowercase();
                for jargon in ["daemon", "ipc", "démon", "windivert"] {
                    assert!(!lower.contains(jargon), "{locale}:{key} mentions {jargon}");
                }
            }
        }
    }

    #[test]
    fn recover_failure_texts_do_not_mislead() {
        for locale in ["en", "fr"] {
            let i18n = I18nRegistry::new(locale);
            let failed = i18n.t("cli.recover.failed").to_lowercase();
            for advice in ["restart your computer", "redémarrez votre ordinateur"] {
                assert!(!failed.contains(advice), "{locale}: advises a restart");
            }
            let unreachable = i18n.t("cli.recover.daemon_unreachable").to_lowercase();
            for claim in ["was not running", "n'était pas actif"] {
                assert!(!unreachable.contains(claim), "{locale}: claims not running");
            }
        }
    }

    #[test]
    fn ctl_pause_parses_and_maps_to_the_pause_command() {
        let args = CliArgs::try_parse_from(["routeward", "ctl", "pause", "--seconds", "300"])
            .expect("parses");
        let Commands::Ctl { action } = args.command else {
            panic!("expected ctl");
        };
        let (label, cmd) = ctl_action_into_ipc(action, &I18nRegistry::new("en")).expect("maps");
        assert_eq!(label, "pause");
        assert!(matches!(
            cmd,
            IpcCommand::PauseEngine { duration_secs: 300 }
        ));
        assert!(CliArgs::try_parse_from(["routeward", "ctl", "pause"]).is_err());
        assert!(CliArgs::try_parse_from(["routeward", "ctl", "pause", "--seconds", "0"]).is_err());
        assert!(
            CliArgs::try_parse_from(["routeward", "ctl", "pause", "--seconds", "86401"]).is_err()
        );
    }

    fn ctl_ipc(args: &[&str]) -> (&'static str, IpcCommand) {
        let mut argv = vec!["routeward", "ctl"];
        argv.extend_from_slice(args);
        let parsed = CliArgs::try_parse_from(argv).expect("parses");
        let Commands::Ctl { action } = parsed.command else {
            panic!("expected ctl");
        };
        ctl_action_into_ipc(action, &I18nRegistry::new("en")).expect("maps")
    }

    #[test]
    fn ctl_logs_without_options_keeps_the_raw_buffer_dump() {
        let (label, cmd) = ctl_ipc(&["logs"]);
        assert_eq!(label, "logs");
        assert!(matches!(cmd, IpcCommand::ListLogs));
    }

    #[test]
    fn ctl_logs_options_become_a_query_for_the_daemon() {
        let (_, cmd) = ctl_ipc(&[
            "logs",
            "--level",
            "warn",
            "--component",
            "ProxyConnector",
            "--component",
            "RuleEngine",
            "--grep",
            "timeout",
            "--pid",
            "42",
            "--since",
            "15m",
            "--limit",
            "50",
        ]);
        match cmd {
            IpcCommand::QueryLogs {
                source,
                min_level,
                components,
                text,
                pid,
                since,
                limit,
                ..
            } => {
                assert_eq!(source, LogQuerySource::Memory);
                assert_eq!(min_level, Some(LogLevel::Warn));
                assert_eq!(components, vec!["ProxyConnector", "RuleEngine"]);
                assert_eq!(text.as_deref(), Some("timeout"));
                assert_eq!(pid, Some(42));
                assert_eq!(limit, 50);
                let age_ms = epoch_ms_now() - since.expect("since");
                assert!((15 * 60 * 1000..15 * 60 * 1000 + 5000).contains(&age_ms));
            }
            other => panic!("expected query_logs, got {other:?}"),
        }

        let (_, cmd) = ctl_ipc(&["logs", "--file", "20261122"]);
        match cmd {
            IpcCommand::QueryLogs { source, limit, .. } => {
                assert_eq!(
                    source,
                    LogQuerySource::DaemonFile {
                        date: "20261122".to_string()
                    }
                );
                assert_eq!(limit, ctl_reports::DEFAULT_LOG_LIMIT);
            }
            other => panic!("expected query_logs, got {other:?}"),
        }
        // Bad values are refused with the localized message once the locale is known.
        let i18n = I18nRegistry::new("en");
        for (flag, value, key) in [
            ("--level", "loud", "cli.logs.invalid_level"),
            ("--since", "soon", "cli.logs.invalid_since"),
        ] {
            let parsed =
                CliArgs::try_parse_from(["routeward", "ctl", "logs", flag, value]).expect("parses");
            let Commands::Ctl { action } = parsed.command else {
                panic!("expected ctl");
            };
            let err = ctl_action_into_ipc(action, &i18n).expect_err("refused");
            assert_eq!(
                err.to_string(),
                ctl_reports::interpolate(&i18n.t(key), &[("value", value.to_string())])
            );
        }
    }

    #[test]
    fn ctl_blocked_and_diagnose_map_to_their_commands() {
        let (label, cmd) = ctl_ipc(&["blocked"]);
        assert_eq!(label, "blocked");
        assert!(matches!(
            cmd,
            IpcCommand::ListBlocked {
                since: None,
                limit: None
            }
        ));
        let (_, cmd) = ctl_ipc(&["blocked", "--limit", "10", "--json"]);
        assert!(matches!(
            cmd,
            IpcCommand::ListBlocked {
                since: None,
                limit: Some(10)
            }
        ));
        let (label, cmd) = ctl_ipc(&["diagnose", "--json"]);
        assert_eq!(label, "diagnose");
        assert!(matches!(cmd, IpcCommand::Analyze));
        assert!(matches!(
            CtlRender::for_action(&CtlCommands::Diagnose { json: true }),
            CtlRender::Raw
        ));
        assert!(matches!(
            CtlRender::for_action(&CtlCommands::Diagnose { json: false }),
            CtlRender::Diagnose
        ));
    }

    #[test]
    fn ctl_export_diagnostics_parses_every_option() {
        let default_days = SystemConstants::load_embedded()
            .expect("constants")
            .telemetry
            .diagnostics_default_log_days;
        let (label, cmd) = ctl_ipc(&["export-diagnostics", "--output", "out.json"]);
        assert_eq!(label, "export-diagnostics");
        match cmd {
            IpcCommand::CollectDiagnostics {
                log_days,
                include_connections,
                include_profile,
                mask_domains,
            } => {
                assert_eq!(log_days, default_days);
                assert!(include_connections && include_profile && !mask_domains);
            }
            other => panic!("expected collect_diagnostics, got {other:?}"),
        }

        let (_, cmd) = ctl_ipc(&[
            "export-diagnostics",
            "--output",
            "out.json",
            "--no-logs",
            "--no-profile",
            "--no-connections",
            "--mask-domains",
            "--force",
        ]);
        match cmd {
            IpcCommand::CollectDiagnostics {
                log_days,
                include_connections,
                include_profile,
                mask_domains,
            } => {
                assert_eq!(log_days, 0);
                assert!(!include_connections && !include_profile && mask_domains);
            }
            other => panic!("expected collect_diagnostics, got {other:?}"),
        }
        let (_, cmd) = ctl_ipc(&["export-diagnostics", "--output", "o", "--log-days", "7"]);
        assert!(matches!(
            cmd,
            IpcCommand::CollectDiagnostics { log_days: 7, .. }
        ));
        // --output is required.
        assert!(CliArgs::try_parse_from(["routeward", "ctl", "export-diagnostics"]).is_err());
    }

    #[test]
    fn export_refuses_an_existing_file_before_calling_the_daemon() {
        let parsed = CliArgs::try_parse_from([
            "routeward",
            "ctl",
            "export-diagnostics",
            "--output",
            "x.json",
            "--force",
        ])
        .expect("parses");
        let Commands::Ctl { action } = parsed.command else {
            panic!("expected ctl");
        };
        match CtlRender::for_action(&action) {
            CtlRender::Export { output, force } => {
                assert_eq!(output, PathBuf::from("x.json"));
                assert!(force);
            }
            _ => panic!("expected export render"),
        }
    }

    #[test]
    fn purge_data_subcommand_parses() {
        let args = CliArgs::try_parse_from(["routeward", "purge-data"]).expect("parses");
        assert!(matches!(args.command, Commands::PurgeData));
    }

    #[test]
    fn migrate_upgrade_state_subcommand_parses_and_is_hidden() {
        use clap::CommandFactory;
        let args = CliArgs::try_parse_from([
            "routeward",
            "migrate-upgrade-state",
            "--user-sid",
            "S-1-5-18",
        ])
        .expect("parses");
        assert!(
            matches!(&args.command, Commands::MigrateUpgradeState { user_sid } if user_sid == "S-1-5-18")
        );
        assert!(CliArgs::try_parse_from(["routeward", "migrate-upgrade-state"]).is_err());
        let cmd = CliArgs::command();
        let sub = cmd
            .find_subcommand("migrate-upgrade-state")
            .expect("registered");
        assert!(sub.is_hide_set(), "must not appear in help");
        assert!(!cmd
            .clone()
            .render_help()
            .to_string()
            .contains("migrate-upgrade-state"));
    }

    #[tokio::test]
    async fn daemon_call_succeeds_on_the_third_attempt() {
        let calls = std::cell::Cell::new(0u32);
        let accepted = call_daemon_with_retry(
            || {
                calls.set(calls.get() + 1);
                let n = calls.get();
                async move {
                    if n < 3 {
                        Err(())
                    } else {
                        Ok(true)
                    }
                }
            },
            MIGRATE_DAEMON_ATTEMPTS,
            Duration::ZERO,
        )
        .await;
        assert!(accepted);
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test]
    async fn daemon_call_refusal_is_not_retried() {
        let calls = std::cell::Cell::new(0u32);
        let accepted = call_daemon_with_retry(
            || {
                calls.set(calls.get() + 1);
                async { Ok::<bool, ()>(false) }
            },
            MIGRATE_DAEMON_ATTEMPTS,
            Duration::ZERO,
        )
        .await;
        assert!(!accepted);
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn all_failed_attempts_fall_back_to_writing_the_enabled_state() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "routeward_cli_migrate_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let state = root.join("protection_state.json");
        let calls = std::cell::Cell::new(0u32);
        let outcome = migrate_upgrade_state(&state, true, || {
            call_daemon_with_retry(
                || {
                    calls.set(calls.get() + 1);
                    async { Err::<bool, ()>(()) }
                },
                MIGRATE_DAEMON_ATTEMPTS,
                Duration::ZERO,
            )
        })
        .await;
        assert_eq!(calls.get(), MIGRATE_DAEMON_ATTEMPTS);
        assert_eq!(
            outcome,
            routeward_core::system::upgrade_migration::MigrationOutcome::WrittenDirectly
        );
        assert!(state.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn cleanup_refused_when_test_daemon_listens_and_accepted_with_force() {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        let unique_id = routeward_core::ipc::generate_ephemeral_token();
        constants.ipc.windows_pipe_name = format!(r"\\.\pipe\routeward-cleanup-test-{unique_id}");
        let temp_sock = std::env::temp_dir().join(format!("routeward-cleanup-{unique_id}.sock"));
        constants.ipc.unix_socket_path = temp_sock.to_string_lossy().into_owned();
        constants.network.default_transparent_tcp_port = 59998;
        constants.network.linux_nft_binary = "true".to_string();

        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;

        let daemon_ctrl = RouteWardController::new(constants.clone(), profile.clone(), "en");
        let service =
            DaemonIpcService::bind_for_test(daemon_ctrl.clone()).expect("bind test daemon");
        let daemon_task = tokio::spawn(async move {
            let _ = service.run_accept_loop().await;
        });

        let cleanup_ctrl = RouteWardController::new(constants.clone(), profile, "en");

        // 1. Without --force, cleanup must be refused while the daemon is listening
        let refused = cleanup_ctrl.cleanup_orphaned_rules(false);
        match refused {
            Err(RouteWardError::DaemonError { key, .. }) => {
                assert_eq!(key, ERR_KEY_CLEANUP_DAEMON_ACTIVE);
            }
            other => panic!("Expected ERR_KEY_CLEANUP_DAEMON_ACTIVE, got {other:?}"),
        }

        // 2. With --force (force = true), cleanup must be accepted
        cleanup_ctrl
            .cleanup_orphaned_rules(true)
            .expect("cleanup with --force should succeed while daemon is active");

        daemon_task.abort();
    }

    #[tokio::test]
    async fn ctl_upsert_and_remove_rule_restores_identical_profile_and_writes_info_log() {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        let unique_id = routeward_core::ipc::generate_ephemeral_token();
        constants.ipc.windows_pipe_name = format!(r"\\.\pipe\routeward-ctl-rule-test-{unique_id}");
        let temp_sock = std::env::temp_dir().join(format!("routeward-ctl-rule-{unique_id}.sock"));
        constants.ipc.unix_socket_path = temp_sock.to_string_lossy().into_owned();

        let temp_prof_path =
            std::env::temp_dir().join(format!("routeward_ctl_prof_{unique_id}.json"));
        constants.ipc.windows_profile_path = temp_prof_path.to_string_lossy().into_owned();
        constants.ipc.linux_profile_path = temp_prof_path.to_string_lossy().into_owned();

        let temp_user_log_dir =
            std::env::temp_dir().join(format!("routeward_ctl_user_logs_{unique_id}"));
        let _ = std::fs::remove_dir_all(&temp_user_log_dir);

        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;
        let initial_rules_json =
            serde_json::to_string(&profile.rules).expect("serialize initial rules");

        let daemon_ctrl = RouteWardController::new(constants.clone(), profile, "en");
        let service =
            DaemonIpcService::bind_for_test(daemon_ctrl.clone()).expect("bind test daemon");
        let daemon_task = tokio::spawn(async move {
            let _ = service.run_accept_loop().await;
        });

        let client = IpcClient::new(constants.ipc.clone());
        let user_logger =
            FileLogger::new(&temp_user_log_dir, &constants.telemetry.log_app_name, true);

        // 1. Add a temporary Block rule via CtlCommands::UpsertRule
        let temp_rule_json = r#"{
            "id": "rule-temp-block-test",
            "name": "Temp Block Rule",
            "enabled": true,
            "priority": 1,
            "processPatterns": ["curl.exe"],
            "domainPatterns": [],
            "ipCidrs": [],
            "portRanges": [],
            "protocol": "tcp",
            "action": { "type": "block" }
        }"#
        .to_string();

        let upsert_resp = execute_ctl_action(
            &client,
            &user_logger,
            &I18nRegistry::new("en"),
            CtlCommands::UpsertRule {
                json: Some(temp_rule_json),
                json_file: None,
            },
        )
        .await
        .expect("execute ctl upsert-rule");
        assert!(upsert_resp.ok);

        let state_after_add = execute_ctl_action(
            &client,
            &user_logger,
            &I18nRegistry::new("en"),
            CtlCommands::State,
        )
        .await
        .expect("execute ctl state");
        let parsed_after_add: DaemonFullState =
            serde_json::from_value(state_after_add.result.expect("state result"))
                .expect("decode DaemonFullState");
        assert!(parsed_after_add
            .profile
            .rules
            .iter()
            .any(|r| r.id == "rule-temp-block-test"));

        // 2. Remove the temporary rule via CtlCommands::RemoveRule
        let remove_resp = execute_ctl_action(
            &client,
            &user_logger,
            &I18nRegistry::new("en"),
            CtlCommands::RemoveRule {
                id: "rule-temp-block-test".to_string(),
            },
        )
        .await
        .expect("execute ctl remove-rule");
        assert!(remove_resp.ok);

        let state_after_remove = execute_ctl_action(
            &client,
            &user_logger,
            &I18nRegistry::new("en"),
            CtlCommands::State,
        )
        .await
        .expect("execute ctl state after remove");
        let parsed_after_remove: DaemonFullState =
            serde_json::from_value(state_after_remove.result.expect("state result"))
                .expect("decode DaemonFullState");
        let final_rules_json = serde_json::to_string(&parsed_after_remove.profile.rules)
            .expect("serialize final rules");
        assert_eq!(
            final_rules_json, initial_rules_json,
            "Profile rules must return to identical state after remove-rule"
        );

        // 3. Verify INFO lines were written to user log for each ctl invocation
        let log_files: Vec<_> = std::fs::read_dir(&temp_user_log_dir)
            .expect("user log dir exists")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(log_files.len(), 1);
        let log_text = std::fs::read_to_string(log_files[0].path()).expect("read user log");
        assert!(log_text
            .contains("[INFO] [CliCtl] Executed ctl command 'upsert-rule': outcome=success"));
        assert!(log_text
            .contains("[INFO] [CliCtl] Executed ctl command 'remove-rule': outcome=success"));
        assert!(log_text.contains("[INFO] [CliCtl] Executed ctl command 'state': outcome=success"));

        daemon_task.abort();
        let _ = std::fs::remove_file(&temp_prof_path);
        let _ = std::fs::remove_dir_all(&temp_user_log_dir);
    }

    #[tokio::test]
    async fn ctl_upsert_rule_json_file_handles_valid_bom_missing_and_invalid_json() {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        let unique_id = routeward_core::ipc::generate_ephemeral_token();
        constants.ipc.windows_pipe_name = format!(r"\\.\pipe\routeward-ctl-file-test-{unique_id}");
        let temp_sock = std::env::temp_dir().join(format!("routeward-ctl-file-{unique_id}.sock"));
        constants.ipc.unix_socket_path = temp_sock.to_string_lossy().into_owned();

        let temp_prof_path =
            std::env::temp_dir().join(format!("routeward_ctl_file_prof_{unique_id}.json"));
        constants.ipc.windows_profile_path = temp_prof_path.to_string_lossy().into_owned();
        constants.ipc.linux_profile_path = temp_prof_path.to_string_lossy().into_owned();

        let temp_user_log_dir =
            std::env::temp_dir().join(format!("routeward_ctl_file_logs_{unique_id}"));
        let _ = std::fs::remove_dir_all(&temp_user_log_dir);

        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;

        let daemon_ctrl = RouteWardController::new(constants.clone(), profile, "en");
        let service =
            DaemonIpcService::bind_for_test(daemon_ctrl.clone()).expect("bind test daemon");
        let daemon_task = tokio::spawn(async move {
            let _ = service.run_accept_loop().await;
        });

        let client = IpcClient::new(constants.ipc.clone());
        let user_logger =
            FileLogger::new(&temp_user_log_dir, &constants.telemetry.log_app_name, true);

        let valid_json_body = r#"{
            "id": "rule-from-json-file",
            "name": "Rule From JSON File",
            "enabled": true,
            "priority": 2,
            "processPatterns": ["curl.exe"],
            "domainPatterns": [],
            "ipCidrs": [],
            "portRanges": [],
            "protocol": "tcp",
            "action": { "type": "block" }
        }"#;

        // 1. Valid UTF-8 file without BOM
        let valid_file_path =
            std::env::temp_dir().join(format!("routeward_valid_rule_{unique_id}.json"));
        std::fs::write(&valid_file_path, valid_json_body.as_bytes()).expect("write valid json");

        let resp_valid = execute_ctl_action(
            &client,
            &user_logger,
            &I18nRegistry::new("en"),
            CtlCommands::UpsertRule {
                json: None,
                json_file: Some(valid_file_path.clone()),
            },
        )
        .await
        .expect("upsert-rule via valid --json-file");
        assert!(resp_valid.ok);

        // 2. Valid UTF-8 file WITH UTF-8 BOM (\u{feff} / 0xEF,0xBB,0xBF)
        let bom_file_path =
            std::env::temp_dir().join(format!("routeward_bom_rule_{unique_id}.json"));
        let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
        bom_bytes.extend_from_slice(
            valid_json_body
                .replace("Rule From JSON File", "Rule From BOM File")
                .as_bytes(),
        );
        std::fs::write(&bom_file_path, &bom_bytes).expect("write BOM json");

        let resp_bom = execute_ctl_action(
            &client,
            &user_logger,
            &I18nRegistry::new("en"),
            CtlCommands::UpsertRule {
                json: None,
                json_file: Some(bom_file_path.clone()),
            },
        )
        .await
        .expect("upsert-rule via UTF-8 BOM --json-file");
        assert!(resp_bom.ok);

        let state_resp = execute_ctl_action(
            &client,
            &user_logger,
            &I18nRegistry::new("en"),
            CtlCommands::State,
        )
        .await
        .expect("query state");
        let parsed_state: DaemonFullState =
            serde_json::from_value(state_resp.result.expect("state result")).expect("decode state");
        let stored_rule = parsed_state
            .profile
            .rules
            .iter()
            .find(|r| r.id == "rule-from-json-file")
            .expect("rule present");
        assert_eq!(stored_rule.name, "Rule From BOM File");

        // 3. Missing file -> clear error with ERR_KEY_CONFIG_LOAD
        let missing_path =
            std::env::temp_dir().join(format!("routeward_nonexistent_{unique_id}.json"));
        let missing_err =
            parse_json_payload::<RoutingRule>("rule", None, Some(missing_path.clone()))
                .expect_err("missing --json-file must fail");
        match missing_err {
            RouteWardError::ConfigError { key, detail } => {
                assert_eq!(key, ERR_KEY_CONFIG_LOAD);
                assert!(detail.contains("Cannot read rule JSON file"));
            }
            other => panic!("Expected ConfigError(ERR_KEY_CONFIG_LOAD), got {other:?}"),
        }

        // 4. Invalid JSON file -> clear error with ERR_KEY_CONFIG_JSON
        let invalid_file_path =
            std::env::temp_dir().join(format!("routeward_invalid_rule_{unique_id}.json"));
        std::fs::write(&invalid_file_path, b"{protocol:tcp}").expect("write invalid json");
        let invalid_err =
            parse_json_payload::<RoutingRule>("rule", None, Some(invalid_file_path.clone()))
                .expect_err("invalid --json-file must fail");
        match invalid_err {
            RouteWardError::ConfigError { key, detail } => {
                assert_eq!(key, ERR_KEY_CONFIG_JSON);
                assert!(detail.contains("Invalid rule JSON in file"));
            }
            other => panic!("Expected ConfigError(ERR_KEY_CONFIG_JSON), got {other:?}"),
        }

        assert_eq!(
            ctl_action_label(&CtlCommands::FlushFakeIps),
            "flush-fake-ips"
        );
        assert_eq!(ctl_action_label(&CtlCommands::Start), "start");

        daemon_task.abort();
        let _ = std::fs::remove_file(&valid_file_path);
        let _ = std::fs::remove_file(&bom_file_path);
        let _ = std::fs::remove_file(&invalid_file_path);
        let _ = std::fs::remove_file(&temp_prof_path);
        let _ = std::fs::remove_dir_all(&temp_user_log_dir);
    }

    #[test]
    fn parses_service_and_daemon_allow_sid_cli_arguments() {
        let install = CliArgs::try_parse_from([
            "routeward",
            "service",
            "install",
            "--allow-sid",
            "S-1-5-21-1-2-3-1000",
            "--demand-start",
        ])
        .expect("parse service install");
        match install.command {
            Commands::Service {
                action:
                    ServiceCommands::Install {
                        bin_path,
                        allow_sid,
                        allow_current_user,
                        demand_start,
                        start,
                    },
            } => {
                assert!(bin_path.is_none());
                assert_eq!(allow_sid, vec!["S-1-5-21-1-2-3-1000".to_string()]);
                assert!(!allow_current_user);
                assert!(demand_start);
                assert!(!start, "install must not start the service unless asked");
            }
            _ => panic!("unexpected parsed command"),
        }

        let install_start = CliArgs::try_parse_from([
            "routeward",
            "service",
            "install",
            "--allow-sid",
            "S-1-5-21-1-2-3-1000",
            "--start",
        ])
        .expect("parse service install --start");
        match install_start.command {
            Commands::Service {
                action:
                    ServiceCommands::Install {
                        allow_sid,
                        demand_start,
                        start,
                        ..
                    },
            } => {
                assert_eq!(allow_sid, vec!["S-1-5-21-1-2-3-1000".to_string()]);
                assert!(!demand_start);
                assert!(start);
            }
            _ => panic!("unexpected parsed command"),
        }

        let status = CliArgs::try_parse_from(["routeward", "service", "status"])
            .expect("parse service status");
        assert!(matches!(
            status.command,
            Commands::Service {
                action: ServiceCommands::Status
            }
        ));

        let run = CliArgs::try_parse_from([
            "routeward",
            "service",
            "run",
            "--allow-sid",
            "S-1-5-21-1-2-3-1001",
        ])
        .expect("parse service run");
        match run.command {
            Commands::Service {
                action: ServiceCommands::Run { allow_sid },
            } => {
                assert_eq!(allow_sid, vec!["S-1-5-21-1-2-3-1001".to_string()]);
            }
            _ => panic!("unexpected parsed command"),
        }

        let restore = CliArgs::try_parse_from([
            "routeward",
            "service",
            "restore",
            "--start",
            "--",
            r"C:\Program Files\RouteWard\routeward.exe",
            "service",
            "run",
            "--allow-sid",
            "S-1-5-21-1-2-3-1001",
        ])
        .expect("parse service restore");
        match restore.command {
            Commands::Service {
                action:
                    ServiceCommands::Restore {
                        start,
                        demand_start,
                        image_path,
                    },
            } => {
                assert!(start);
                assert!(!demand_start);
                assert_eq!(
                    image_path,
                    vec![
                        r"C:\Program Files\RouteWard\routeward.exe".to_string(),
                        "service".to_string(),
                        "run".to_string(),
                        "--allow-sid".to_string(),
                        "S-1-5-21-1-2-3-1001".to_string(),
                    ]
                );
            }
            _ => panic!("unexpected parsed command"),
        }
        assert!(
            CliArgs::try_parse_from(["routeward", "service", "restore", "--start"]).is_err(),
            "restore without image path args must be rejected"
        );

        let daemon = CliArgs::try_parse_from([
            "routeward",
            "daemon",
            "--locale",
            "en",
            "--allow-sid",
            "S-1-5-21-1-2-3-1002",
        ])
        .expect("parse daemon --locale --allow-sid");
        assert_eq!(daemon.locale.as_deref(), Some("en"));
        match daemon.command {
            Commands::Daemon {
                duration_secs,
                allow_sid,
            } => {
                assert!(duration_secs.is_none());
                assert_eq!(allow_sid, vec!["S-1-5-21-1-2-3-1002".to_string()]);
            }
            _ => panic!("unexpected parsed command"),
        }
    }
}
