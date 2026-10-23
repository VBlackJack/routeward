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
use routeward_core::error::{
    RouteWardError, RouteWardResult, ERR_KEY_CONFIG_JSON, ERR_KEY_CONFIG_LOAD,
    ERR_KEY_DAEMON_NOT_ELEVATED,
};
use routeward_core::i18n::I18nRegistry;
use routeward_core::interceptor::RouteWardController;
use routeward_core::ipc::protocol::IpcCommand;
use routeward_core::ipc::{DaemonIpcService, IpcClient};
use routeward_core::logger::FileLogger;
use routeward_core::rules::ConnectionRequest;
use routeward_core::telemetry::LogLevel;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_CLI_LOCALE: &str = "fr";
const DEFAULT_EVAL_PORT: u16 = 443;
const COMPONENT_CLI_CTL: &str = "CliCtl";

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
    Cleanup {
        /// Force removal even if a RouteWard daemon instance appears active
        #[arg(long)]
        force: bool,
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
    /// Actively terminate an open connection by its identifier
    TerminateConnection {
        #[arg(long)]
        id: String,
    },
}

fn parse_routing_rule_payload(
    json: Option<String>,
    json_file: Option<PathBuf>,
) -> RouteWardResult<RoutingRule> {
    if let Some(path) = json_file {
        let raw_content =
            std::fs::read_to_string(&path).map_err(|err| RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_LOAD,
                detail: format!("Cannot read rule JSON file '{}': {err}", path.display()),
            })?;
        let without_bom = raw_content.strip_prefix('\u{feff}').unwrap_or(&raw_content);
        serde_json::from_str::<RoutingRule>(without_bom).map_err(|err| {
            RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_JSON,
                detail: format!("Invalid rule JSON in file '{}': {err}", path.display()),
            }
        })
    } else if let Some(raw_inline) = json {
        let without_bom = raw_inline.strip_prefix('\u{feff}').unwrap_or(&raw_inline);
        serde_json::from_str::<RoutingRule>(without_bom).map_err(|err| {
            RouteWardError::ConfigError {
                key: ERR_KEY_CONFIG_JSON,
                detail: format!("Invalid inline rule JSON: {err}"),
            }
        })
    } else {
        Err(RouteWardError::ConfigError {
            key: ERR_KEY_CONFIG_JSON,
            detail: "Either --json or --json-file must be provided".to_string(),
        })
    }
}

fn ctl_action_into_ipc(action: CtlCommands) -> RouteWardResult<(&'static str, IpcCommand)> {
    match action {
        CtlCommands::Status => Ok(("status", IpcCommand::GetDiagnostics)),
        CtlCommands::State => Ok(("state", IpcCommand::GetState)),
        CtlCommands::Start => Ok(("start", IpcCommand::ToggleEngine { start: true })),
        CtlCommands::Stop => Ok(("stop", IpcCommand::ToggleEngine { start: false })),
        CtlCommands::Connections => Ok(("connections", IpcCommand::ListConnections)),
        CtlCommands::Logs => Ok(("logs", IpcCommand::ListLogs)),
        CtlCommands::UpsertRule { json, json_file } => {
            let rule = parse_routing_rule_payload(json, json_file)?;
            Ok(("upsert-rule", IpcCommand::UpsertRule { rule }))
        }
        CtlCommands::RemoveRule { id } => {
            Ok(("remove-rule", IpcCommand::RemoveRule { rule_id: id }))
        }
        CtlCommands::TerminateConnection { id } => Ok((
            "terminate-connection",
            IpcCommand::TerminateConnection { connection_id: id },
        )),
    }
}

async fn execute_ctl_action(
    client: &IpcClient,
    user_logger: &FileLogger,
    action: CtlCommands,
) -> Result<routeward_core::ipc::protocol::IpcResponse, Box<dyn std::error::Error>> {
    let (cmd_label, ipc_cmd) = match ctl_action_into_ipc(action) {
        Ok(pair) => pair,
        Err(err) => {
            user_logger.log(
                LogLevel::Info,
                COMPONENT_CLI_CTL,
                &format!("Executed ctl command 'upsert-rule': outcome=invalid_input ({err})"),
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

    let controller = match args.command {
        Commands::Run { .. } | Commands::Cleanup { .. } => {
            RouteWardController::new(constants, profile, &args.locale)
        }
        _ => RouteWardController::new_user_cli(constants, profile, &args.locale),
    };

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
        Commands::Cleanup { force } => {
            if let Err(err) = controller.cleanup_orphaned_rules(force) {
                let localized = controller.i18n.t(err.i18n_key());
                eprintln!("{localized}");
                return Err(err.into());
            }
            println!("{}", controller.i18n.t("cli.engine.cleanup.completed"));
        }
        Commands::Daemon { .. } | Commands::Ctl { .. } => unreachable!(),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeward_core::error::ERR_KEY_CLEANUP_DAEMON_ACTIVE;
    use routeward_core::ipc::protocol::DaemonFullState;

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
        let missing_err = parse_routing_rule_payload(None, Some(missing_path.clone()))
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
        let invalid_err = parse_routing_rule_payload(None, Some(invalid_file_path.clone()))
            .expect_err("invalid --json-file must fail");
        match invalid_err {
            RouteWardError::ConfigError { key, detail } => {
                assert_eq!(key, ERR_KEY_CONFIG_JSON);
                assert!(detail.contains("Invalid rule JSON in file"));
            }
            other => panic!("Expected ConfigError(ERR_KEY_CONFIG_JSON), got {other:?}"),
        }

        daemon_task.abort();
        let _ = std::fs::remove_file(&valid_file_path);
        let _ = std::fs::remove_file(&bom_file_path);
        let _ = std::fs::remove_file(&invalid_file_path);
        let _ = std::fs::remove_file(&temp_prof_path);
        let _ = std::fs::remove_dir_all(&temp_user_log_dir);
    }
}
