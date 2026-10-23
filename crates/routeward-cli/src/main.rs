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
use routeward_core::config::{ProfileConfig, RoutingRule, SystemConstants, TransportProtocol};
use routeward_core::error::{RouteWardError, ERR_KEY_DAEMON_NOT_ELEVATED};
use routeward_core::i18n::I18nRegistry;
use routeward_core::interceptor::RouteWardController;
use routeward_core::ipc::protocol::IpcCommand;
use routeward_core::ipc::{DaemonIpcService, IpcClient};
use routeward_core::rules::ConnectionRequest;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_CLI_LOCALE: &str = "fr";
const DEFAULT_EVAL_PORT: u16 = 443;

#[derive(Parser)]
#[command(name = "routeward", version, about)]
struct CliArgs {
    #[arg(short, long, env = "ROUTEWARD_CONFIG_PATH")]
    profile: Option<PathBuf>,

    #[arg(short, long, env = "ROUTEWARD_LOCALE", default_value = DEFAULT_CLI_LOCALE)]
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
    Cleanup,
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
    /// Insert or update a routing rule (JSON string) on the daemon
    UpsertRule {
        #[arg(long)]
        json: String,
    },
    /// Actively terminate an open connection by its identifier
    TerminateConnection {
        #[arg(long)]
        id: String,
    },
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = CliArgs::parse();

    let constants = SystemConstants::load_embedded()?;

    if let Commands::Ctl { action } = args.command {
        let client = IpcClient::new(constants.ipc);
        let ipc_cmd = match action {
            CtlCommands::Status => IpcCommand::GetDiagnostics,
            CtlCommands::State => IpcCommand::GetState,
            CtlCommands::Start => IpcCommand::ToggleEngine { start: true },
            CtlCommands::Stop => IpcCommand::ToggleEngine { start: false },
            CtlCommands::Connections => IpcCommand::ListConnections,
            CtlCommands::Logs => IpcCommand::ListLogs,
            CtlCommands::UpsertRule { json } => {
                let rule: RoutingRule = serde_json::from_str(&json)?;
                IpcCommand::UpsertRule { rule }
            }
            CtlCommands::TerminateConnection { id } => {
                IpcCommand::TerminateConnection { connection_id: id }
            }
        };

        let response = client.call_raw(ipc_cmd).await?;
        println!("{}", serde_json::to_string_pretty(&response)?);
        if !response.ok {
            return Err(response
                .error
                .unwrap_or_else(|| "Daemon returned error".to_string())
                .into());
        }
        return Ok(());
    }

    if let Commands::Daemon { duration_secs } = args.command {
        let i18n = I18nRegistry::new(&args.locale);
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

        let controller = RouteWardController::new(constants, profile, &args.locale);

        let service = match DaemonIpcService::bind(controller.clone()) {
            Ok(svc) => svc,
            Err(err) => {
                let localized = controller.i18n.t(err.i18n_key());
                eprintln!("{localized}: {err}");
                return Err(err.into());
            }
        };

        let _ = controller.cleanup_orphaned_rules();
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

        let accept_handle = tokio::spawn(async move {
            let _ = service.run_accept_loop().await;
        });

        if let Some(secs) = duration_secs {
            tokio::select! {
                _ = wait_for_shutdown_signal() => {},
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {},
            }
        } else {
            wait_for_shutdown_signal().await;
        }

        accept_handle.abort();
        if controller.is_running() {
            controller.stop_engine();
        }
        return Ok(());
    }

    let profile = match &args.profile {
        Some(path) => ProfileConfig::load_from_path(path)?,
        None => ProfileConfig::load_embedded_default()?,
    };

    let controller = RouteWardController::new(constants, profile, &args.locale);

    match args.command {
        Commands::Run { duration_secs } => {
            println!("=== {} ===", controller.i18n.t("cli.engine.startup.banner"));
            controller.start_engine();
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
                    _ = wait_for_shutdown_signal() => {},
                    _ = tokio::time::sleep(Duration::from_secs(secs)) => {},
                }
            } else {
                wait_for_shutdown_signal().await;
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
        Commands::Cleanup => {
            controller.cleanup_orphaned_rules()?;
            println!("{}", controller.i18n.t("cli.engine.cleanup.completed"));
        }
        Commands::Daemon { .. } | Commands::Ctl { .. } => unreachable!(),
    }

    Ok(())
}
