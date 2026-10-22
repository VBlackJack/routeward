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
    /// Start the transparent relay and Fake-IP interceptor engine
    Run,
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
        Commands::Run => {
            println!("=== {} ===", controller.i18n.t("cli.engine.startup.banner"));
            controller.start_engine();
            let diag = controller.diagnostics();
            println!(
                "{}: {}",
                controller.i18n.t("cli.engine.startup.listening_socks"),
                diag.relay_tcp_endpoint
            );
            println!("{}", controller.i18n.t("cli.engine.startup.ready"));
            tokio::signal::ctrl_c().await?;
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
    }

    Ok(())
}
