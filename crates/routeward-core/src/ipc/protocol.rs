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

use crate::config::{InterceptionMode, ProfileConfig, ProxyChain, ProxyNode, RoutingRule};
use crate::dns::FakeIpEntry;
use crate::interceptor::SystemDiagnostics;
use crate::rules::ConnectionRequest;
use crate::telemetry::{
    LogEntry, LogLevel, TelemetryEvent, TelemetryHub, TelemetrySnapshot, TrackedConnection,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

const COMPONENT_IPC_PROTOCOL: &str = "DaemonIpc";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcRequest {
    pub id: String,
    pub command: IpcCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum IpcCommand {
    GetState,
    GetDiagnostics,
    GetTelemetry,
    ToggleEngine {
        start: bool,
    },
    SetInterceptionMode {
        mode: InterceptionMode,
    },
    SetTheme {
        theme: String,
        accent: String,
    },
    GetProfile,
    ReplaceProfile {
        profile: ProfileConfig,
    },
    UpsertRule {
        rule: RoutingRule,
    },
    RemoveRule {
        #[serde(rename = "ruleId")]
        rule_id: String,
    },
    UpsertProxy {
        node: ProxyNode,
    },
    RemoveProxy {
        #[serde(rename = "proxyId")]
        proxy_id: String,
    },
    UpsertChain {
        chain: ProxyChain,
    },
    RemoveChain {
        #[serde(rename = "chainId")]
        chain_id: String,
    },
    EvaluateRule {
        request: ConnectionRequest,
    },
    SimulateConnection {
        request: ConnectionRequest,
    },
    ScanOsSockets,
    TestProxy {
        #[serde(rename = "proxyId")]
        proxy_id: String,
    },
    TestAllProxies,
    ListConnections,
    TerminateConnection {
        #[serde(rename = "connectionId")]
        connection_id: String,
    },
    ClearClosedConnections,
    ListLogs,
    ClearLogs,
    ListFakeIps,
    AllocateFakeIp {
        domain: String,
    },
    FlushFakeIps,
    ImportFoxyProxyJson {
        json: String,
        #[serde(default, rename = "processPatterns")]
        process_patterns: Vec<String>,
    },
    ListProfiles,
    SaveNamedProfile {
        #[serde(default, rename = "profileId")]
        profile_id: Option<String>,
        #[serde(default)]
        name: Option<String>,
    },
    SwitchProfile {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    DeleteProfile {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    Subscribe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonFullState {
    pub diagnostics: SystemDiagnostics,
    pub profile: ProfileConfig,
    pub telemetry: TelemetrySnapshot,
    pub connections: Vec<TrackedConnection>,
    pub logs: Vec<LogEntry>,
    pub fake_ips: Vec<FakeIpEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcResponse {
    pub id: Option<String>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "errorKey", skip_serializing_if = "Option::is_none")]
    pub error_key: Option<String>,
}

impl IpcResponse {
    pub fn success<T: Serialize>(id: String, value: &T) -> Self {
        match serde_json::to_value(value) {
            Ok(val) => Self {
                id: Some(id),
                ok: true,
                result: Some(val),
                error: None,
                error_key: None,
            },
            Err(err) => Self::error(Some(id), format!("serialization_error: {err}")),
        }
    }

    pub fn error(id: Option<String>, message: impl Into<String>) -> Self {
        Self::error_with_key(id, None, message)
    }

    pub fn error_with_key(
        id: Option<String>,
        error_key: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(message.into()),
            error_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "streamType", content = "payload", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum IpcStreamEvent {
    Event(TelemetryEvent),
    Resync {
        #[serde(rename = "skippedEvents")]
        skipped_events: u64,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadLineOutcome {
    Line(String),
    Eof,
    LineTooLong,
    IdleTimeout,
    IoError(String),
}

/// Reads a single `\n`-delimited line from `reader`, enforcing `max_line_bytes` and `idle_timeout_ms`.
/// Exceeding either limit returns `ReadLineOutcome::LineTooLong` or `ReadLineOutcome::IdleTimeout`
/// without allocating unbounded memory.
pub async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_line_bytes: usize,
    idle_timeout_ms: u64,
) -> ReadLineOutcome {
    let effective_limit = max_line_bytes.max(1);
    let mut accumulated: Vec<u8> = Vec::new();
    let timeout_duration = Duration::from_millis(idle_timeout_ms);

    let read_fut = async {
        loop {
            let available = match reader.fill_buf().await {
                Ok(buf) => buf,
                Err(err) => return ReadLineOutcome::IoError(err.to_string()),
            };

            if available.is_empty() {
                if accumulated.is_empty() {
                    return ReadLineOutcome::Eof;
                }
                return match String::from_utf8(accumulated) {
                    Ok(line) => ReadLineOutcome::Line(line),
                    Err(err) => ReadLineOutcome::IoError(err.to_string()),
                };
            }

            if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
                let to_consume = newline_pos + 1;
                if accumulated.len() + newline_pos > effective_limit {
                    reader.consume(to_consume);
                    return ReadLineOutcome::LineTooLong;
                }
                accumulated.extend_from_slice(&available[..newline_pos]);
                reader.consume(to_consume);
                if accumulated.last() == Some(&b'\r') {
                    accumulated.pop();
                }
                return match String::from_utf8(accumulated) {
                    Ok(line) => ReadLineOutcome::Line(line),
                    Err(err) => ReadLineOutcome::IoError(err.to_string()),
                };
            } else {
                let chunk_len = available.len();
                if accumulated.len() + chunk_len > effective_limit {
                    reader.consume(chunk_len);
                    return ReadLineOutcome::LineTooLong;
                }
                accumulated.extend_from_slice(available);
                reader.consume(chunk_len);
            }
        }
    };

    match tokio::time::timeout(timeout_duration, read_fut).await {
        Ok(outcome) => outcome,
        Err(_) => ReadLineOutcome::IdleTimeout,
    }
}

/// Strictly parses a line into an `IpcRequest`. Unknown fields, unknown commands, or malformed JSON
/// never panic and always produce a structured `IpcResponse` error.
pub fn parse_ipc_request(line: &str) -> Result<IpcRequest, IpcResponse> {
    serde_json::from_str::<IpcRequest>(line).map_err(|err| {
        let extracted_id = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v.get("id").and_then(|id| id.as_str()).map(String::from));
        IpcResponse::error(extracted_id, format!("invalid_request: {err}"))
    })
}

/// Receives the next event from a `TelemetryHub` broadcast receiver, converting
/// `RecvError::Lagged(skipped)` into an `IpcStreamEvent::Resync` notification and logging a warning.
pub async fn recv_next_stream_event(
    rx: &mut broadcast::Receiver<TelemetryEvent>,
    telemetry: &TelemetryHub,
) -> Option<IpcStreamEvent> {
    match rx.recv().await {
        Ok(event) => Some(IpcStreamEvent::Event(event)),
        Err(RecvError::Lagged(skipped)) => {
            telemetry.push_log(
                LogLevel::Warn,
                COMPONENT_IPC_PROTOCOL,
                format!("IPC subscriber lagged ({skipped} events skipped); emitting resync"),
            );
            Some(IpcStreamEvent::Resync {
                skipped_events: skipped,
            })
        }
        Err(RecvError::Closed) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SystemConstants;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn rejects_line_exceeding_max_bytes() {
        let oversized = format!("{}\n", "a".repeat(128));
        let mut reader = BufReader::new(oversized.as_bytes());
        let outcome = read_bounded_line(&mut reader, 64, 1000).await;
        assert_eq!(outcome, ReadLineOutcome::LineTooLong);
    }

    #[test]
    fn rejects_invalid_json_with_structured_error() {
        let res = parse_ipc_request("{not valid json");
        let err_resp = res.expect_err("must reject invalid JSON");
        assert!(!err_resp.ok);
        assert!(err_resp.id.is_none());
        assert!(err_resp
            .error
            .unwrap_or_default()
            .contains("invalid_request"));
    }

    #[test]
    fn rejects_unknown_field_at_top_level_and_nested() {
        let top_level_unknown =
            r#"{"id":"req-1","command":{"type":"get_state"},"unexpectedField":true}"#;
        let err_top =
            parse_ipc_request(top_level_unknown).expect_err("must reject top-level unknown field");
        assert!(!err_top.ok);
        assert_eq!(err_top.id.as_deref(), Some("req-1"));
        assert!(err_top.error.unwrap_or_default().contains("unknown field"));

        let nested_unknown =
            r#"{"id":"req-2","command":{"type":"toggle_engine","start":true,"extraParam":42}}"#;
        let err_nested =
            parse_ipc_request(nested_unknown).expect_err("must reject nested unknown field");
        assert!(!err_nested.ok);
        assert_eq!(err_nested.id.as_deref(), Some("req-2"));
        assert!(err_nested
            .error
            .unwrap_or_default()
            .contains("unknown field"));
    }

    #[test]
    fn rejects_unknown_command_with_structured_error() {
        let unknown_cmd = r#"{"id":"req-3","command":{"type":"non_existent_command"}}"#;
        let err_resp = parse_ipc_request(unknown_cmd).expect_err("must reject unknown command");
        assert!(!err_resp.ok);
        assert_eq!(err_resp.id.as_deref(), Some("req-3"));
        assert!(err_resp
            .error
            .unwrap_or_default()
            .contains("unknown variant"));
    }

    #[tokio::test]
    async fn emits_resync_event_and_logs_warn_when_broadcast_subscriber_lags() {
        let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
        constants.telemetry.event_broadcast_capacity = 2;
        let hub = TelemetryHub::new_with_logging(&constants.telemetry, false);

        let mut rx = hub.subscribe();
        // Overflow the broadcast ring buffer (clamped to MIN_BROADCAST_CAPACITY = 16) by pushing 24 events
        for idx in 0..24 {
            hub.push_log(LogLevel::Info, "LagTest", format!("msg-{idx}"));
        }

        let stream_ev = recv_next_stream_event(&mut rx, &hub)
            .await
            .expect("stream event");
        match stream_ev {
            IpcStreamEvent::Resync { skipped_events } => {
                assert!(skipped_events >= 1);
            }
            other => panic!("Expected IpcStreamEvent::Resync, got {other:?}"),
        }

        let logs = hub.list_logs();
        assert!(logs
            .iter()
            .any(|l| l.level == LogLevel::Warn && l.message.contains("lagged")));
    }
}
