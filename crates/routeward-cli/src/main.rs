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

use clap::{Parser, Subcommand};
use routeward_core::config::security::load_or_init_secure_daemon_profile;
use routeward_core::config::{
    ProfileConfig, ProxyNode, RoutingRule, SystemConstants, TransportProtocol,
};
use routeward_core::error::{
    RouteWardError, RouteWardResult, ERR_KEY_CONFIG_JSON, ERR_KEY_CONFIG_LOAD,
    ERR_KEY_DAEMON_NOT_ELEVATED,
};
use routeward_core::i18n::I18nRegistry;
use routeward_core::interceptor::RouteWardController;
use routeward_core::ipc::protocol::IpcCommand;
use routeward_core::ipc::{wait_for_shutdown_signal, DaemonIpcService, IpcClient};
use routeward_core::logger::FileLogger;
use routeward_core::pac::PacGenerator;
use routeward_core::rules::ConnectionRequest;
use routeward_core::system::windows_service::{
    install_windows_service, query_windows_service_status, restore_windows_service,
    run_windows_service_dispatcher, start_windows_service, stop_windows_service,
    uninstall_windows_service,
};
use routeward_core::telemetry::LogLevel;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const DEFAULT_CLI_LOCALE: &str = "fr";
const DEFAULT_EVAL_PORT: u16 = 443;
const COMPONENT_CLI_CTL: &str = "CliCtl";

#[derive(Parser)]
#[command(name = "routeward", version, about)]
struct CliArgs {
    #[arg(short, long, env = "ROUTEWARD_CONFIG_PATH")]
    profile: Option<PathBuf>,

    #[arg(short, long, global = true, env = "ROUTEWARD_LOCALE", default_value = DEFAULT_CLI_LOCALE)]
    locale: String,

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
    /// List tracked connections from the daemon
    Connections,
    /// List recent log entries from the daemon
    Logs,
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
        CtlCommands::Connections => "connections",
        CtlCommands::Logs => "logs",
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

fn ctl_action_into_ipc(action: CtlCommands) -> RouteWardResult<(&'static str, IpcCommand)> {
    let label = ctl_action_label(&action);
    let ipc_cmd = match action {
        CtlCommands::Status => IpcCommand::GetDiagnostics,
        CtlCommands::State => IpcCommand::GetState,
        CtlCommands::Start => IpcCommand::ToggleEngine { start: true },
        CtlCommands::Stop => IpcCommand::ToggleEngine { start: false },
        CtlCommands::Connections => IpcCommand::ListConnections,
        CtlCommands::Logs => IpcCommand::ListLogs,
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
    action: CtlCommands,
) -> Result<routeward_core::ipc::protocol::IpcResponse, Box<dyn std::error::Error>> {
    let expected_label = ctl_action_label(&action);
    let (cmd_label, ipc_cmd) = match ctl_action_into_ipc(action) {
        Ok(pair) => pair,
        Err(err) => {
            user_logger.log(
                LogLevel::Info,
                COMPONENT_CLI_CTL,
                &format!("Executed ctl command '{expected_label}': outcome=invalid_input ({err})"),
            );
            return Err(err.into());
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
    if !RouteWardController::detect_elevated_privileges() {
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
        } => {
            if allow_current_user {
                #[cfg(windows)]
                {
                    let current_sid = routeward_core::ipc::transport::current_user_sid_string()?;
                    allow_sid.push(current_sid);
                }
            }
            let exe_str = bin_path.as_ref().map(|p| p.to_string_lossy().into_owned());
            let status = install_windows_service(exe_str.as_deref(), &allow_sid, !demand_start)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            eprintln!("{}", i18n.t("cli.engine.service.installed"));
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

fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = CliArgs::parse();

    if let Commands::Service { action } = args.command {
        return handle_service_command(action, &args.locale);
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

async fn async_main(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let constants = SystemConstants::load_embedded()?;

    if let Commands::Ctl { action } = args.command {
        let user_logger = FileLogger::new(
            constants.telemetry.resolve_user_log_dir(),
            &constants.telemetry.log_app_name,
            true,
        );
        let client = IpcClient::new(constants.ipc);
        let response = execute_ctl_action(&client, &user_logger, action).await?;
        println!("{}", serde_json::to_string_pretty(&response)?);
        if !response.ok {
            let err_msg = response
                .error
                .unwrap_or_else(|| "Daemon returned error".to_string());
            return Err(err_msg.into());
        }
        return Ok(());
    }

    if let Commands::Daemon {
        duration_secs,
        allow_sid,
    } = args.command
    {
        return run_daemon_host(constants, &args.locale, duration_secs, &allow_sid, None).await;
    }

    if matches!(args.command, Commands::Run { .. })
        && !RouteWardController::detect_elevated_privileges()
    {
        let i18n = I18nRegistry::new(&args.locale);
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
            RouteWardController::new(constants, profile, &args.locale)
        }
        _ => RouteWardController::new_user_cli(constants, profile, &args.locale),
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
        } => {
            if let Err(err) = run_cleanup(&controller, force, fail_closed_on_crash) {
                let localized = controller.i18n.t(err.i18n_key());
                eprintln!("{localized}");
                return Err(err.into());
            }
            println!("{}", controller.i18n.t("cli.engine.cleanup.completed"));
        }
        Commands::Daemon { .. } | Commands::Ctl { .. } | Commands::Service { .. } => unreachable!(),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeward_core::error::ERR_KEY_CLEANUP_DAEMON_ACTIVE;
    use routeward_core::ipc::protocol::DaemonFullState;

    #[test]
    fn cleanup_accepts_fail_closed_on_crash_flag() {
        let args =
            CliArgs::try_parse_from(["routeward", "cleanup", "--force", "--fail-closed-on-crash"])
                .expect("flag parses");
        match args.command {
            Commands::Cleanup {
                force,
                fail_closed_on_crash,
            } => assert!(force && fail_closed_on_crash),
            _ => panic!("expected cleanup"),
        }
        let plain = CliArgs::try_parse_from(["routeward", "cleanup"]).expect("plain parses");
        match plain.command {
            Commands::Cleanup {
                force,
                fail_closed_on_crash,
            } => assert!(!force && !fail_closed_on_crash),
            _ => panic!("expected cleanup"),
        }
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
            CtlCommands::UpsertRule {
                json: Some(temp_rule_json),
                json_file: None,
            },
        )
        .await
        .expect("execute ctl upsert-rule");
        assert!(upsert_resp.ok);

        let state_after_add = execute_ctl_action(&client, &user_logger, CtlCommands::State)
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
            CtlCommands::RemoveRule {
                id: "rule-temp-block-test".to_string(),
            },
        )
        .await
        .expect("execute ctl remove-rule");
        assert!(remove_resp.ok);

        let state_after_remove = execute_ctl_action(&client, &user_logger, CtlCommands::State)
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
            CtlCommands::UpsertRule {
                json: None,
                json_file: Some(bom_file_path.clone()),
            },
        )
        .await
        .expect("upsert-rule via UTF-8 BOM --json-file");
        assert!(resp_bom.ok);

        let state_resp = execute_ctl_action(&client, &user_logger, CtlCommands::State)
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
                    },
            } => {
                assert!(bin_path.is_none());
                assert_eq!(allow_sid, vec!["S-1-5-21-1-2-3-1000".to_string()]);
                assert!(!allow_current_user);
                assert!(demand_start);
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
        assert_eq!(daemon.locale, "en");
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
