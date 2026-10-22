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
use routeward_core::config::{ProfileConfig, SystemConstants, TransportProtocol};
use routeward_core::interceptor::RouteWardController;
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
    /// Start the transparent relay and OS packet interceptor engine
    Run {
        /// Optional safety timeout in seconds before automatic fail-open shutdown
        #[arg(long)]
        duration_secs: Option<u64>,
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
    }

    Ok(())
}
