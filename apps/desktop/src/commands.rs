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

use routeward_core::checker::ProxyHealthReport;
use routeward_core::config::{
    InterceptionMode, ProfileConfig, ProxyChain, ProxyNode, RoutingRule, ThemeForgeCatalog,
};
use routeward_core::dns::FakeIpEntry;
use routeward_core::interceptor::{RouteWardController, SystemDiagnostics};
use routeward_core::rules::{ConnectionRequest, RuleEvaluationResult};
use routeward_core::system::{LaunchedProcessReport, SystemProxyManager};
use routeward_core::telemetry::{LogEntry, LogLevel, TelemetrySnapshot, TrackedConnection};

const DEFAULT_OS_SCAN_LIMIT: usize = 48;

pub struct DesktopCommandBridge {
    controller: RouteWardController,
}

impl DesktopCommandBridge {
    pub fn new(controller: RouteWardController) -> Self {
        Self { controller }
    }

    pub fn scan_os_sockets(&self) -> Vec<TrackedConnection> {
        self.controller
            .scan_and_ingest_os_sockets(DEFAULT_OS_SCAN_LIMIT)
    }

    pub fn set_system_proxy(&self, enabled: bool) -> Result<bool, String> {
        let diag = self.controller.diagnostics();
        SystemProxyManager::set_system_proxy(enabled, &diag.relay_tcp_endpoint)
            .map_err(|e| e.to_string())
    }

    pub fn launch_process_with_proxy(
        &self,
        executable_path: &str,
        args: &[String],
    ) -> Result<LaunchedProcessReport, String> {
        let diag = self.controller.diagnostics();
        let command_line = if args.is_empty() {
            executable_path.to_string()
        } else {
            format!("{executable_path} {}", args.join(" "))
        };
        let res = SystemProxyManager::spawn_process_with_proxy(
            &command_line,
            &diag.relay_tcp_endpoint,
            &diag.relay_http_endpoint,
        )
        .map_err(|e| e.to_string())?;
        self.controller.telemetry.push_log(
            LogLevel::Info,
            "ProcessLauncher",
            format!(
                "Spawned {} (PID {}) via ALL_PROXY={}",
                res.command, res.pid, res.proxy_endpoint
            ),
        );
        Ok(res)
    }

    pub fn get_profile(&self) -> ProfileConfig {
        self.controller.profile.read().clone()
    }

    pub fn get_themeforge_catalog(&self) -> Result<ThemeForgeCatalog, String> {
        ThemeForgeCatalog::load_embedded().map_err(|e| e.to_string())
    }

    pub fn set_theme(&self, theme: String, accent: String) {
        self.controller.set_theme_config(theme, accent);
    }

    pub fn get_diagnostics(&self) -> SystemDiagnostics {
        self.controller.diagnostics()
    }

    pub fn get_telemetry(&self) -> TelemetrySnapshot {
        self.controller.telemetry.snapshot()
    }

    pub fn list_connections(&self) -> Vec<TrackedConnection> {
        self.controller.telemetry.list_connections()
    }

    pub fn clear_closed_connections(&self) {
        self.controller.telemetry.clear_closed_connections();
    }

    pub fn simulate_connection(&self, request: ConnectionRequest) -> TrackedConnection {
        self.controller.simulate_connection(request)
    }

    pub fn evaluate_rule(&self, request: ConnectionRequest) -> RuleEvaluationResult {
        self.controller.evaluate_rule(&request)
    }

    pub async fn test_proxy(&self, proxy_id: String) -> Result<ProxyHealthReport, String> {
        self.controller
            .test_proxy(&proxy_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn test_all_proxies(&self) -> Vec<ProxyHealthReport> {
        self.controller.test_all_proxies().await
    }

    pub fn upsert_proxy(&self, node: ProxyNode) {
        self.controller.upsert_proxy(node);
    }

    pub fn remove_proxy(&self, proxy_id: String) {
        self.controller.remove_proxy(&proxy_id);
    }

    pub fn upsert_chain(&self, chain: ProxyChain) {
        self.controller.upsert_chain(chain);
    }

    pub fn remove_chain(&self, chain_id: String) {
        self.controller.remove_chain(&chain_id);
    }

    pub fn upsert_rule(&self, rule: RoutingRule) {
        self.controller.upsert_rule(rule);
    }

    pub fn remove_rule(&self, rule_id: String) {
        self.controller.remove_rule(&rule_id);
    }

    pub fn toggle_engine(&self, start: bool) -> SystemDiagnostics {
        if start {
            self.controller.start_engine();
        } else {
            self.controller.stop_engine();
        }
        self.controller.diagnostics()
    }

    pub fn set_interception_mode(&self, mode: InterceptionMode) -> SystemDiagnostics {
        self.controller.set_interception_mode(mode);
        self.controller.diagnostics()
    }

    pub fn list_fake_ip_entries(&self) -> Vec<FakeIpEntry> {
        self.controller.dns.list_entries()
    }

    pub fn allocate_fake_ip(&self, domain: String) -> Option<String> {
        self.controller.allocate_fake_ip(&domain)
    }

    pub fn flush_fake_ip_cache(&self) {
        self.controller.dns.flush();
    }

    pub fn list_logs(&self) -> Vec<LogEntry> {
        self.controller.telemetry.list_logs()
    }

    pub fn clear_logs(&self) {
        self.controller.telemetry.clear_logs();
    }
}
