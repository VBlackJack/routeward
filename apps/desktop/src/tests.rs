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
use routeward_core::interceptor::RouteWardController;
use routeward_core::ipc::protocol::DaemonFullState;
use routeward_core::ipc::{generate_ephemeral_token, DaemonIpcService};
use routeward_core::telemetry::LogLevel;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn validates_host_origin_and_token_on_api_routes() {
    let port = 54321;
    let token = "secret-ephemeral-token-123";

    let valid_api_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n{{}}"
        );
    let path = validate_loopback_http_request(&valid_api_req, port, token)
        .expect("Valid request should pass");
    assert_eq!(path, "/api/state");

    // Same-origin GET /api/state without Origin header (standard browser behavior) is accepted when Host and token match
    let valid_get_req = format!(
        "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
    );
    let get_path = validate_loopback_http_request(&valid_get_req, port, token)
        .expect("Same-origin GET with valid token should pass");
    assert_eq!(get_path, "/api/state");

    // Wrong Host header (DNS rebinding attempt)
    let bad_host_req = format!(
            "POST /api/state HTTP/1.1\r\nHost: attacker.example.com\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
    assert_eq!(
        validate_loopback_http_request(&bad_host_req, port, token),
        Err(HttpSecurityRejection::InvalidHost)
    );

    // Wrong Origin header on GET /api/state (cross-origin browser request)
    let bad_origin_get_req = format!(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.local\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
    assert_eq!(
        validate_loopback_http_request(&bad_origin_get_req, port, token),
        Err(HttpSecurityRejection::InvalidOrigin)
    );

    // Missing Origin header on POST /api/*
    let missing_origin_req = format!(
        "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
    );
    assert_eq!(
        validate_loopback_http_request(&missing_origin_req, port, token),
        Err(HttpSecurityRejection::InvalidOrigin)
    );

    // Wrong or missing token on /api/*
    let bad_token_req = format!(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: wrong-token\r\n\r\n"
        );
    assert_eq!(
        validate_loopback_http_request(&bad_token_req, port, token),
        Err(HttpSecurityRejection::InvalidToken)
    );
}

#[test]
fn constant_time_token_comparison_is_exact() {
    let token = "550e8400-e29b-41d4-a716-446655440000";
    assert!(constant_time_eq(token, token));
    assert!(!constant_time_eq(
        token,
        "550e8400-e29b-41d4-a716-446655440001"
    ));
    assert!(!constant_time_eq(
        token,
        "450e8400-e29b-41d4-a716-446655440000"
    ));
    assert!(!constant_time_eq(token, "550e8400-e29b-41d4-a716"));
    assert!(!constant_time_eq(token, ""));
    assert!(constant_time_eq("", ""));
}

async fn send_raw_http(port: u16, raw_req: &str) -> String {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect to loopback server");
    stream
        .write_all(raw_req.as_bytes())
        .await
        .expect("write raw HTTP request");
    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .await
        .expect("read HTTP response");
    String::from_utf8_lossy(&resp).into_owned()
}

#[tokio::test]
async fn bridge_loopback_end_to_end_token_state_sse_and_reconnection() {
    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.ipc.reconnect_interval_ms = 120;
    let unique_id = generate_ephemeral_token();
    constants.ipc.windows_pipe_name = format!(r"\\.\pipe\routeward-e2e-{unique_id}");
    let temp_sock = std::env::temp_dir().join(format!("routeward-e2e-{unique_id}.sock"));
    constants.ipc.unix_socket_path = temp_sock.to_string_lossy().into_owned();

    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;

    // Start in-process test daemon #1
    let daemon_ctrl_1 = RouteWardController::new(constants.clone(), profile.clone(), "en");
    let service_1 =
        DaemonIpcService::bind_for_test(daemon_ctrl_1.clone()).expect("bind test daemon #1");
    let daemon_task_1 = tokio::spawn(async move {
        let _ = service_1.run_accept_loop().await;
    });

    // Start desktop bridge + loopback HTTP server
    let bridge = Arc::new(DesktopCommandBridge::new(
        constants.clone(),
        profile.clone(),
        "en",
    ));
    bridge.spawn_background_sync();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("local_addr").port();
    let token = generate_ephemeral_token();
    let token_for_server = token.clone();
    let bridge_for_server = Arc::clone(&bridge);

    let server_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let b = Arc::clone(&bridge_for_server);
            let t = token_for_server.clone();
            tokio::spawn(async move {
                serve_loopback_api_connection(stream, port, &t, &b).await;
            });
        }
    });

    // 1. HTTP requests without token or with wrong Host/Origin are rejected (401 / 403)
    let no_token_resp = send_raw_http(
        port,
        &format!("GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    )
    .await;
    assert!(
        no_token_resp.starts_with("HTTP/1.1 401 Unauthorized"),
        "Expected 401 without token, got: {no_token_resp}"
    );

    let bad_host_resp = send_raw_http(
            port,
            &format!(
                "GET /api/state HTTP/1.1\r\nHost: evil.example.com\r\nX-RouteWard-Token: {token}\r\n\r\n"
            ),
        )
        .await;
    assert!(
        bad_host_resp.starts_with("HTTP/1.1 403 Forbidden"),
        "Expected 403 with invalid Host, got: {bad_host_resp}"
    );

    let bad_origin_resp = send_raw_http(
            port,
            &format!(
                "POST /api/logs/clear HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example.com\r\nX-RouteWard-Token: {token}\r\n\r\n{{}}"
            ),
        )
        .await;
    assert!(
        bad_origin_resp.starts_with("HTTP/1.1 403 Forbidden"),
        "Expected 403 with invalid Origin, got: {bad_origin_resp}"
    );

    // 2. Request with valid token: GET /api/state returns daemonConnected == true
    let mut connected_state: Option<DaemonFullState> = None;
    for _ in 0..30 {
        let state_resp = send_raw_http(
                port,
                &format!(
                    "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
                ),
            )
            .await;
        assert!(state_resp.starts_with("HTTP/1.1 200 OK"));
        let body = extract_json_body(&state_resp);
        let parsed: DaemonFullState =
            serde_json::from_str(body).expect("deserialize DaemonFullState");
        if parsed.diagnostics.daemon_connected {
            connected_state = Some(parsed);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        connected_state.is_some(),
        "GET /api/state should report daemonConnected == true"
    );

    // Wait briefly for the bridge's background subscription stream to be established
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 3. Real-time event emitted on daemon is received over the bridge's SSE stream (/api/events)
    let mut sse_stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect SSE stream");
    let sse_req = format!(
        "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
    );
    sse_stream
        .write_all(sse_req.as_bytes())
        .await
        .expect("send SSE request");

    let mut sse_reader = BufReader::new(sse_stream);
    let mut status_line = String::new();
    sse_reader
        .read_line(&mut status_line)
        .await
        .expect("read SSE status line");
    assert!(status_line.starts_with("HTTP/1.1 200 OK"));

    // Emit a real-time log event on the daemon
    daemon_ctrl_1.telemetry.push_log(
        LogLevel::Info,
        "IntegrationTest",
        "live-sse-event-marker-3-3".to_string(),
    );

    let mut received_sse_marker = false;
    let sse_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < sse_deadline {
        let mut line = String::new();
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(500), sse_reader.read_line(&mut line)).await
        {
            if n == 0 {
                break;
            }
            if line.contains("live-sse-event-marker-3-3") {
                received_sse_marker = true;
                break;
            }
        }
    }
    assert!(
        received_sse_marker,
        "Expected daemon telemetry event to be streamed over GET /api/events"
    );

    // 4. Stop the daemon: bridge transitions to daemonConnected == false, then automatically reconnects when daemon restarts
    daemon_task_1.abort();
    let _ = daemon_task_1.await;
    drop(daemon_ctrl_1);

    let mut saw_disconnected = false;
    for _ in 0..30 {
        let state_resp = send_raw_http(
                port,
                &format!(
                    "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
                ),
            )
            .await;
        let body = extract_json_body(&state_resp);
        let parsed: DaemonFullState =
            serde_json::from_str(body).expect("deserialize state after daemon stop");
        if !parsed.diagnostics.daemon_connected {
            saw_disconnected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        saw_disconnected,
        "Bridge must report daemonConnected == false after daemon stops"
    );

    // Restart daemon on the same IPC endpoint
    let daemon_ctrl_2 = RouteWardController::new(constants.clone(), profile, "en");
    let mut service_2_opt = None;
    for _ in 0..20 {
        if let Ok(svc) = DaemonIpcService::bind_for_test(daemon_ctrl_2.clone()) {
            service_2_opt = Some(svc);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let service_2 = service_2_opt.expect("bind test daemon #2");
    let daemon_task_2 = tokio::spawn(async move {
        let _ = service_2.run_accept_loop().await;
    });

    // Verify automatic reconnection by the bridge's background task (without calling refresh_state first)
    let mut reconnected = false;
    for _ in 0..40 {
        if bridge.is_daemon_connected() && bridge.get_diagnostics().daemon_connected {
            reconnected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    assert!(
        reconnected,
        "Bridge must automatically reconnect when the daemon restarts"
    );

    let bad_sys_payload = "{invalid";
    let bad_sys_proxy_resp = send_raw_http(
            port,
            &format!(
                "POST /api/system-proxy HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\nContent-Length: {}\r\n\r\n{bad_sys_payload}",
                bad_sys_payload.len()
            ),
        )
        .await;
    assert!(
        bad_sys_proxy_resp.starts_with("HTTP/1.1 400 Bad Request"),
        "Expected 400 on invalid /api/system-proxy payload, got: {bad_sys_proxy_resp}"
    );

    let empty_launch_payload = "{\"executable\":\"   \",\"args\":[]}";
    let empty_launch_resp = send_raw_http(
            port,
            &format!(
                "POST /api/launch-process HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\nContent-Length: {}\r\n\r\n{empty_launch_payload}",
                empty_launch_payload.len()
            ),
        )
        .await;
    assert!(
        empty_launch_resp.starts_with("HTTP/1.1 500 Internal Server Error"),
        "Expected 500 when /api/launch-process fails to spawn empty path, got: {empty_launch_resp}"
    );

    daemon_task_2.abort();
    server_task.abort();
}

#[allow(dead_code, clippy::large_enum_variant)]
#[derive(Debug, Deserialize)]
#[serde(
    tag = "streamType",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ClientWireStreamEvent {
    Event(ClientWireTelemetryPayload),
    Resync {
        #[serde(rename = "skippedEvents")]
        skipped_events: u64,
    },
}

#[allow(dead_code, clippy::large_enum_variant)]
#[derive(Debug, Deserialize)]
#[serde(
    tag = "event",
    content = "data",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum ClientWireTelemetryPayload {
    Telemetry(serde_json::Value),
    ConnectionUpdated(routeward_core::telemetry::TrackedConnection),
    ConnectionsCleared,
    Log(routeward_core::telemetry::LogEntry),
    LogsCleared,
}

#[tokio::test]
async fn sse_incremental_stream_delivers_live_events_before_http_response_ends_and_logs_activity() {
    use routeward_core::telemetry::TrackedConnection;

    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.ipc.reconnect_interval_ms = 100;
    let unique_id = generate_ephemeral_token();
    constants.ipc.windows_pipe_name = format!(r"\\.\pipe\routeward-sse-inc-{unique_id}");
    let temp_sock = std::env::temp_dir().join(format!("routeward-sse-inc-{unique_id}.sock"));
    constants.ipc.unix_socket_path = temp_sock.to_string_lossy().into_owned();

    let temp_log_dir = std::env::temp_dir().join(format!("routeward_desktop_logs_{unique_id}"));
    let _ = std::fs::remove_dir_all(&temp_log_dir);

    let mut daemon_profile = ProfileConfig::load_embedded_default().expect("Default profile");
    daemon_profile.enable_logging = false;

    let daemon_ctrl = RouteWardController::new(constants.clone(), daemon_profile.clone(), "en");
    let service = DaemonIpcService::bind_for_test(daemon_ctrl.clone()).expect("bind test daemon");
    let daemon_task = tokio::spawn(async move {
        let _ = service.run_accept_loop().await;
    });

    let mut desktop_profile = daemon_profile.clone();
    desktop_profile.enable_logging = true;
    let bridge = Arc::new(DesktopCommandBridge::new_with_log_dir(
        constants.clone(),
        desktop_profile,
        "en",
        temp_log_dir.clone(),
    ));
    bridge.spawn_background_sync();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("local_addr").port();
    let token = generate_ephemeral_token();
    let token_for_server = token.clone();
    let bridge_for_server = Arc::clone(&bridge);

    let server_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let b = Arc::clone(&bridge_for_server);
            let t = token_for_server.clone();
            tokio::spawn(async move {
                serve_loopback_api_connection(stream, port, &t, &b).await;
            });
        }
    });

    for _ in 0..30 {
        if bridge.is_daemon_connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(bridge.is_daemon_connected(), "Bridge connected to daemon");

    // Open GET /api/events and read incrementally via raw chunk reads (never waiting for EOF)
    let mut sse_stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect SSE stream");
    let sse_req = format!(
            "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\nAccept: text/event-stream\r\n\r\n"
        );
    sse_stream
        .write_all(sse_req.as_bytes())
        .await
        .expect("write SSE request");

    let mut acc = String::new();
    let mut chunk_buf = [0u8; 4096];
    let header_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !acc.contains("\r\n\r\n") && tokio::time::Instant::now() < header_deadline {
        let n = tokio::time::timeout(Duration::from_millis(400), sse_stream.read(&mut chunk_buf))
            .await
            .expect("incremental read timeout")
            .expect("incremental read io");
        assert!(n > 0, "HTTP SSE response must stay open and not end");
        acc.push_str(&String::from_utf8_lossy(&chunk_buf[..n]));
    }

    let (raw_headers, initial_body) = acc
        .split_once("\r\n\r\n")
        .expect("SSE response headers delimited by CRLFCRLF");
    let headers_lower = raw_headers.to_ascii_lowercase();
    assert!(headers_lower.contains("content-type: text/event-stream"));
    assert!(
            headers_lower.contains("x-content-type-options: nosniff"),
            "SSE headers must include X-Content-Type-Options: nosniff to prevent WebView2 MIME-sniff buffering"
        );
    assert!(headers_lower.contains("cache-control: no-store"));

    let mut sse_buffer = initial_body.to_string();
    // Ensure initial preamble exceeds Chromium's 1024-byte sniff buffer before any event is emitted
    while sse_buffer.len() < 1024 {
        let n = tokio::time::timeout(Duration::from_millis(400), sse_stream.read(&mut chunk_buf))
            .await
            .expect("preamble read timeout")
            .expect("preamble read io");
        assert!(n > 0, "HTTP SSE response must not close during preamble");
        sse_buffer.push_str(&String::from_utf8_lossy(&chunk_buf[..n]));
    }

    // Emit connection #1 on the daemon while the HTTP response remains open
    let conn_1: TrackedConnection = serde_json::from_value(serde_json::json!({
        "id": "conn-webview-inc-1",
        "pid": 4242,
        "processName": "curl.exe",
        "processPath": r"C:\Windows\System32\curl.exe",
        "targetHost": "93.184.216.34",
        "resolvedDomain": "example.com",
        "targetPort": 443,
        "protocol": "tcp",
        "matchedRule": "Default Rule",
        "routeLabel": "DIRECT",
        "latencyMs": 12,
        "rxBytes": 4096,
        "txBytes": 512,
        "status": "active",
        "startedAt": "2026-10-23T18:00:00Z"
    }))
    .expect("construct TrackedConnection");
    daemon_ctrl.telemetry.record_connection(conn_1, false);

    // Read incrementally until connection #1 is parsed into the strict client schema BEFORE the HTTP response ends
    let mut decoded_conn_1: Option<TrackedConnection> = None;
    let ev1_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while decoded_conn_1.is_none() && tokio::time::Instant::now() < ev1_deadline {
        while let Some(frame_end) = sse_buffer.find("\n\n") {
            let frame = sse_buffer[..frame_end].to_string();
            sse_buffer = sse_buffer[frame_end + 2..].to_string();
            for line in frame.lines() {
                if let Some(json_str) = line.strip_prefix("data:") {
                    let parsed_client_ev: ClientWireStreamEvent = serde_json::from_str(
                        json_str.trim(),
                    )
                    .expect(
                        "SSE data frame must strictly match TypeScript IpcStreamEvent wire schema",
                    );
                    if let ClientWireStreamEvent::Event(
                        ClientWireTelemetryPayload::ConnectionUpdated(c),
                    ) = parsed_client_ev
                    {
                        if c.id == "conn-webview-inc-1" {
                            decoded_conn_1 = Some(c);
                        }
                    }
                }
            }
        }
        if decoded_conn_1.is_none() {
            let n =
                tokio::time::timeout(Duration::from_millis(500), sse_stream.read(&mut chunk_buf))
                    .await
                    .expect("incremental chunk read timeout for event #1")
                    .expect("incremental chunk read io for event #1");
            assert!(
                n > 0,
                "Event #1 must arrive incrementally BEFORE the HTTP response ends (got EOF)"
            );
            sse_buffer.push_str(&String::from_utf8_lossy(&chunk_buf[..n]));
        }
    }

    let c1 = decoded_conn_1.expect("Decoded live curl.exe connection over open SSE stream");
    assert_eq!(c1.process_name, "curl.exe");
    assert_eq!(c1.rx_bytes, 4096);

    // Prove the HTTP response is STILL open by emitting a second event and reading it on the same stream
    daemon_ctrl.telemetry.push_log(
        LogLevel::Info,
        "IncrementalTest",
        "second-live-chunk-while-open".to_string(),
    );
    let mut saw_second_event = false;
    let ev2_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !saw_second_event && tokio::time::Instant::now() < ev2_deadline {
        while let Some(frame_end) = sse_buffer.find("\n\n") {
            let frame = sse_buffer[..frame_end].to_string();
            sse_buffer = sse_buffer[frame_end + 2..].to_string();
            for line in frame.lines() {
                if let Some(json_str) = line.strip_prefix("data:") {
                    let parsed_client_ev: ClientWireStreamEvent =
                        serde_json::from_str(json_str.trim())
                            .expect("strict client schema for event #2");
                    if let ClientWireStreamEvent::Event(ClientWireTelemetryPayload::Log(entry)) =
                        parsed_client_ev
                    {
                        if entry.message == "second-live-chunk-while-open" {
                            saw_second_event = true;
                        }
                    }
                }
            }
        }
        if !saw_second_event {
            let n =
                tokio::time::timeout(Duration::from_millis(500), sse_stream.read(&mut chunk_buf))
                    .await
                    .expect("incremental chunk read timeout for event #2")
                    .expect("incremental chunk read io for event #2");
            assert!(n > 0, "HTTP SSE response must still be open for event #2");
            sse_buffer.push_str(&String::from_utf8_lossy(&chunk_buf[..n]));
        }
    }
    assert!(saw_second_event);

    // Close SSE client stream and verify DesktopCommandBridge logged startup, daemon connect, and SSE open/close
    drop(sse_stream);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let log_files: Vec<_> = std::fs::read_dir(&temp_log_dir)
        .expect("desktop log dir exists")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(log_files.len(), 1, "Expected 1 daily desktop log file");
    let log_content = std::fs::read_to_string(log_files[0].path()).expect("read desktop log file");
    assert!(log_content.contains("Initialized routeward-desktop bridge"));
    assert!(log_content.contains("Attempting IPC connection to daemon"));
    assert!(log_content.contains("Opening SSE event stream (/api/events)"));
    assert!(log_content.contains("Closed SSE event stream (/api/events)"));

    daemon_task.abort();
    server_task.abort();
    let _ = std::fs::remove_dir_all(&temp_log_dir);
}

#[tokio::test]
async fn bridge_started_before_daemon_transitions_from_never_connected_to_connected_and_streams_events(
) {
    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    constants.ipc.reconnect_interval_ms = 100;
    let unique_id = generate_ephemeral_token();
    constants.ipc.windows_pipe_name = format!(r"\\.\pipe\routeward-preui-{unique_id}");
    let temp_sock = std::env::temp_dir().join(format!("routeward-preui-{unique_id}.sock"));
    constants.ipc.unix_socket_path = temp_sock.to_string_lossy().into_owned();

    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;

    // 1. Start DesktopCommandBridge and loopback HTTP server BEFORE any daemon is listening
    let bridge = Arc::new(DesktopCommandBridge::new(
        constants.clone(),
        profile.clone(),
        "en",
    ));
    bridge.spawn_background_sync();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("local_addr").port();
    let token = generate_ephemeral_token();
    let token_for_server = token.clone();
    let bridge_for_server = Arc::clone(&bridge);

    let server_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let b = Arc::clone(&bridge_for_server);
            let t = token_for_server.clone();
            tokio::spawn(async move {
                serve_loopback_api_connection(stream, port, &t, &b).await;
            });
        }
    });

    // Allow several failed reconnection attempts while no daemon is running
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!bridge.is_daemon_connected());

    let initial_resp = send_raw_http(
            port,
            &format!(
                "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
            ),
        )
        .await;
    let initial_state: DaemonFullState =
        serde_json::from_str(extract_json_body(&initial_resp)).expect("parse initial state");
    assert!(!initial_state.diagnostics.daemon_connected);

    // Open SSE stream /api/events while daemon is still absent (simulating UI launched before daemon)
    let mut sse_stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect SSE stream before daemon start");
    let sse_req = format!(
        "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
    );
    sse_stream
        .write_all(sse_req.as_bytes())
        .await
        .expect("send SSE request");

    let mut chunk_buf = [0u8; 4096];
    let n = sse_stream
        .read(&mut chunk_buf)
        .await
        .expect("read initial SSE headers");
    assert!(n > 0);
    let mut sse_acc = String::from_utf8_lossy(&chunk_buf[..n]).into_owned();

    // 2. Now start the daemon after the bridge and SSE stream are already running
    let daemon_ctrl = RouteWardController::new(constants.clone(), profile, "en");
    let service =
        DaemonIpcService::bind_for_test(daemon_ctrl.clone()).expect("bind delayed daemon");
    let daemon_task = tokio::spawn(async move {
        let _ = service.run_accept_loop().await;
    });

    // 3. Verify the open SSE stream receives the Resync notification and bridge transitions to daemonConnected == true
    let mut saw_resync_on_sse = false;
    let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !saw_resync_on_sse && tokio::time::Instant::now() < connect_deadline {
        if sse_acc.contains("\"streamType\":\"resync\"") {
            saw_resync_on_sse = true;
            break;
        }
        if let Ok(Ok(read_n)) =
            tokio::time::timeout(Duration::from_millis(400), sse_stream.read(&mut chunk_buf)).await
        {
            if read_n == 0 {
                break;
            }
            sse_acc.push_str(&String::from_utf8_lossy(&chunk_buf[..read_n]));
        }
    }
    assert!(
        saw_resync_on_sse,
        "Open SSE stream must receive resync event when daemon starts after UI"
    );
    assert!(
        bridge.is_daemon_connected(),
        "Bridge must transition from never-connected to daemonConnected == true"
    );

    let connected_resp = send_raw_http(
            port,
            &format!(
                "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
            ),
        )
        .await;
    let connected_state: DaemonFullState =
        serde_json::from_str(extract_json_body(&connected_resp)).expect("parse connected state");
    assert!(connected_state.diagnostics.daemon_connected);

    // 4. Emit a live event on the newly started daemon and verify it arrives on the SSE stream
    daemon_ctrl.telemetry.push_log(
        LogLevel::Info,
        "DelayedDaemonTest",
        "event-after-delayed-daemon-start".to_string(),
    );

    let mut saw_live_event = false;
    let ev_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !saw_live_event && tokio::time::Instant::now() < ev_deadline {
        if sse_acc.contains("event-after-delayed-daemon-start") {
            saw_live_event = true;
            break;
        }
        if let Ok(Ok(read_n)) =
            tokio::time::timeout(Duration::from_millis(400), sse_stream.read(&mut chunk_buf)).await
        {
            if read_n == 0 {
                break;
            }
            sse_acc.push_str(&String::from_utf8_lossy(&chunk_buf[..read_n]));
        }
    }
    assert!(
        saw_live_event,
        "Bridge started before daemon must receive live events once daemon starts"
    );

    daemon_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn loopback_http_enforces_post_and_syncs_locale_with_tray_snapshot() {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;

    let bridge = Arc::new(DesktopCommandBridge::new(constants, profile, "fr"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("local_addr").port();
    let token = generate_ephemeral_token();
    let token_for_server = token.clone();
    let bridge_for_server = Arc::clone(&bridge);

    let server_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let b = Arc::clone(&bridge_for_server);
            let t = token_for_server.clone();
            tokio::spawn(async move {
                serve_loopback_api_connection(stream, port, &t, &b).await;
            });
        }
    });

    // GET on POST-only /api/daemon/start must return 405 Method Not Allowed
    let get_start_resp = send_raw_http(
        port,
        &format!(
            "GET /api/daemon/start HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        ),
    )
    .await;
    assert!(
        get_start_resp.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "Expected 405 Method Not Allowed on GET /api/daemon/start, got: {get_start_resp}"
    );

    // POST /api/locale must update bridge locale and tray snapshot
    let post_locale_resp = send_raw_http(
        port,
        &format!(
            "POST /api/locale HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{{\"locale\":\"en\"}}"
        ),
    )
    .await;
    assert!(
        post_locale_resp.starts_with("HTTP/1.1 200 OK"),
        "Expected 200 OK on POST /api/locale, got: {post_locale_resp}"
    );
    assert_eq!(bridge.tray_snapshot().locale, "en");

    server_task.abort();
}

#[tokio::test]
async fn theme_route_parses_hex_colors_and_dispatches_window_theme_command() {
    use crate::{
        handle_api_route, parse_hex_colorref, resolve_palette_window_appearance,
        DesktopWindowCommand, WindowThemeAppearance,
    };

    assert_eq!(parse_hex_colorref("#282A36"), Some(0x00362A28));
    assert_eq!(parse_hex_colorref("#FF112233"), Some(0x00332211));
    assert_eq!(parse_hex_colorref("not-hex"), None);

    let parchment = resolve_palette_window_appearance("Parchment");
    assert!(parchment.is_light);
    assert!(parchment.caption_color.is_some());

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let bridge = DesktopCommandBridge::new(constants, profile, "en");

    let captured = Arc::new(parking_lot::Mutex::new(Vec::<DesktopWindowCommand>::new()));
    let captured_cb = Arc::clone(&captured);
    let cb = move |cmd: DesktopWindowCommand| {
        captured_cb.lock().push(cmd);
    };

    let get_res = handle_api_route("GET", "/api/theme", "", &bridge, Some(&cb)).await;
    assert_eq!(get_res.map(|(code, _, _)| code), Some(405));

    let payload = r##"{"theme":"Drakul","accent":"Purple","isLight":false,"surfaceHex":"#112233","textPrimaryHex":"#AABBCC","borderHex":"#445566"}"##;
    let post_res = handle_api_route("POST", "/api/theme", payload, &bridge, Some(&cb)).await;
    assert_eq!(post_res.map(|(code, _, _)| code), Some(200));

    let cmds = captured.lock();
    assert_eq!(
        cmds.as_slice(),
        &[DesktopWindowCommand::ApplyTheme(WindowThemeAppearance {
            is_light: false,
            caption_color: Some(0x00332211),
            text_color: Some(0x00CCBBAA),
            border_color: Some(0x00665544),
        })]
    );
}

#[tokio::test]
async fn engine_toggle_route_validates_payload_and_surfaces_transport_errors() {
    use crate::handle_api_route;
    use routeward_core::error::{RouteWardError, ERR_KEY_INTERCEPTOR_DRIVER};
    use routeward_core::ipc::protocol::{IpcCommand, IpcResponse};
    use routeward_core::ipc::{DaemonIpcService, IpcClient};

    let mut missing_consts = SystemConstants::load_embedded().expect("SystemConstants");
    let unique_suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    #[cfg(windows)]
    {
        missing_consts.ipc.windows_pipe_name =
            format!(r"\\.\pipe\routeward-missing-test-{unique_suffix}");
    }
    #[cfg(not(windows))]
    {
        missing_consts.ipc.unix_socket_path =
            format!("/tmp/routeward-missing-test-{unique_suffix}.sock");
    }

    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let bridge = DesktopCommandBridge::new(missing_consts.clone(), profile.clone(), "en");

    let bad_res = handle_api_route("POST", "/api/engine/toggle", "{invalid", &bridge, None).await;
    assert_eq!(bad_res.map(|(code, _, _)| code), Some(400));

    let missing_daemon = handle_api_route(
        "POST",
        "/api/engine/toggle",
        r#"{"start":true}"#,
        &bridge,
        None,
    )
    .await
    .expect("route response");
    assert_eq!(missing_daemon.0, 503);
    let err_json: serde_json::Value = serde_json::from_slice(&missing_daemon.2).expect("json");
    assert!(err_json["error"].as_str().is_some_and(|s| !s.is_empty()));

    // Verify IpcClient::call_typed_detailed distinguishes live daemon errors from transport loss
    let mut custom_consts = missing_consts;
    #[cfg(windows)]
    {
        custom_consts.ipc.windows_pipe_name =
            format!(r"\\.\pipe\routeward-err-test-{unique_suffix}");
    }
    #[cfg(not(windows))]
    {
        custom_consts.ipc.unix_socket_path =
            format!("/tmp/routeward-err-test-{unique_suffix}.sock");
    }

    let ctrl =
        routeward_core::interceptor::RouteWardController::new(custom_consts.clone(), profile, "en");
    let svc = DaemonIpcService::bind_for_test(ctrl).expect("bind test ipc");
    let svc_task = tokio::spawn(async move {
        let _ = svc.run_accept_loop().await;
    });

    let client = IpcClient::new(custom_consts.ipc);
    let _diag: routeward_core::interceptor::SystemDiagnostics = client
        .call_typed_detailed(IpcCommand::GetDiagnostics)
        .await
        .expect("live daemon responds cleanly");

    let err_resp = IpcResponse::error_with_key(
        Some("req-1".to_string()),
        Some(ERR_KEY_INTERCEPTOR_DRIVER.to_string()),
        RouteWardError::InterceptorError {
            key: ERR_KEY_INTERCEPTOR_DRIVER,
            detail: "missing".to_string(),
        }
        .to_string(),
    );
    assert!(!err_resp.ok);
    assert_eq!(
        err_resp.error_key.as_deref(),
        Some(ERR_KEY_INTERCEPTOR_DRIVER)
    );
    svc_task.abort();
}

#[test]
fn http_status_line_covers_payload_too_large_and_unprocessable_entity() {
    use crate::http_status_line;

    assert_eq!(http_status_line(413), "HTTP/1.1 413 Payload Too Large");
    assert_eq!(http_status_line(422), "HTTP/1.1 422 Unprocessable Entity");
    assert_eq!(http_status_line(409), "HTTP/1.1 409 Conflict");
    assert_eq!(http_status_line(599), "HTTP/1.1 500 Internal Server Error");
}

#[test]
fn ipc_error_status_maps_transport_protocol_and_remote_errors() {
    use crate::routes::ipc_error_status;
    use routeward_core::error::{
        ERR_KEY_CHAIN_EMPTY, ERR_KEY_CLEANUP_DAEMON_ACTIVE, ERR_KEY_CONFIG_SAVE,
        ERR_KEY_DAEMON_INSECURE_PROFILE, ERR_KEY_INVALID_URI,
    };
    use routeward_core::ipc::IpcCallError;

    let remote = |key: Option<&str>| IpcCallError::Remote {
        message: "rejected".to_string(),
        error_key: key.map(ToString::to_string),
    };

    assert_eq!(
        ipc_error_status(&IpcCallError::Transport("pipe closed".to_string())),
        503
    );
    assert_eq!(
        ipc_error_status(&IpcCallError::Protocol("bad json".to_string())),
        500
    );
    assert_eq!(ipc_error_status(&remote(None)), 400);
    assert_eq!(ipc_error_status(&remote(Some(ERR_KEY_INVALID_URI))), 400);
    assert_eq!(ipc_error_status(&remote(Some(ERR_KEY_CHAIN_EMPTY))), 422);
    assert_eq!(
        ipc_error_status(&remote(Some(ERR_KEY_DAEMON_INSECURE_PROFILE))),
        422
    );
    assert_eq!(
        ipc_error_status(&remote(Some(ERR_KEY_CLEANUP_DAEMON_ACTIVE))),
        409
    );
    assert_eq!(ipc_error_status(&remote(Some(ERR_KEY_CONFIG_SAVE))), 500);
}

#[tokio::test]
async fn mutation_routes_surface_daemon_errors_instead_of_reporting_success() {
    use crate::handle_api_route;

    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    let unique_suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    #[cfg(windows)]
    {
        constants.ipc.windows_pipe_name =
            format!(r"\\.\pipe\routeward-mutation-missing-{unique_suffix}");
    }
    #[cfg(not(windows))]
    {
        constants.ipc.unix_socket_path =
            format!("/tmp/routeward-mutation-missing-{unique_suffix}.sock");
    }
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let proxy_json = r#"{"id":"p1","name":"Proxy","protocol":"socks5","host":"127.0.0.1","port":1080,"auth":null,"udpEnabled":true,"tls":false,"sni":null,"enabled":true,"lastLatencyMs":null,"exitIp":null}"#.to_string();
    let rule_json = r#"{"id":"r1","name":"Rule","enabled":true,"priority":10,"processPatterns":[],"domainPatterns":[],"ipCidrs":[],"portRanges":[],"protocol":"any","action":{"type":"direct"}}"#.to_string();
    let chain_json =
        r#"{"id":"c1","name":"Chain","strategy":"sequence","proxyIds":[],"enabled":true}"#
            .to_string();
    let profile_json = serde_json::to_string(&profile).expect("profile json");
    let bridge = DesktopCommandBridge::new(constants, profile, "en");

    let cases: Vec<(&str, String)> = vec![
        ("/api/proxies/upsert", proxy_json),
        ("/api/proxies/remove", r#"{"proxyId":"p1"}"#.to_string()),
        ("/api/chains/upsert", chain_json),
        ("/api/chains/remove", r#"{"chainId":"c1"}"#.to_string()),
        ("/api/rules/upsert", rule_json),
        ("/api/rules/remove", r#"{"ruleId":"r1"}"#.to_string()),
        ("/api/engine/mode", r#"{"mode":"relay"}"#.to_string()),
        ("/api/profile/replace", profile_json),
        (
            "/api/connections/terminate",
            r#"{"connectionId":"conn-1"}"#.to_string(),
        ),
        (
            "/api/dns/allocate",
            r#"{"domain":"example.com"}"#.to_string(),
        ),
    ];
    for (path, body) in cases {
        let res = handle_api_route("POST", path, &body, &bridge, None)
            .await
            .unwrap_or_else(|| panic!("route {path} must answer"));
        assert_eq!(res.0, 503, "{path} must report the unreachable daemon");
        let json: serde_json::Value = serde_json::from_slice(&res.2).expect("json error body");
        assert!(
            json["error"].as_str().is_some_and(|s| !s.is_empty()),
            "{path} must carry an error message"
        );
        assert!(
            json.get("errorKey").is_some(),
            "{path} must carry an errorKey field"
        );
    }

    // Malformed payloads are 400 on every mutation route, including the theme route.
    for path in [
        "/api/theme",
        "/api/proxies/upsert",
        "/api/connections/terminate",
        "/api/dns/allocate",
        "/api/engine/mode",
    ] {
        let res = handle_api_route("POST", path, "{not json", &bridge, None)
            .await
            .expect("route response");
        assert_eq!(res.0, 400, "{path} must reject malformed JSON");
    }
}

async fn spawn_test_loopback_server(
    bridge: Arc<DesktopCommandBridge>,
    with_static_assets: bool,
) -> (u16, String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let port = listener.local_addr().expect("local_addr").port();
    let token = generate_ephemeral_token();
    let token_for_server = token.clone();
    let server_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let b = Arc::clone(&bridge);
            let t = token_for_server.clone();
            tokio::spawn(async move {
                if with_static_assets {
                    serve_loopback_http_connection(
                        stream,
                        port,
                        &t,
                        &b,
                        None,
                        Some(|path: &str| {
                            if path.starts_with("/assets/app.js") {
                                ("application/javascript; charset=utf-8", &b"void 0;"[..])
                            } else {
                                ("text/html; charset=utf-8", &b"<html></html>"[..])
                            }
                        }),
                        None,
                    )
                    .await;
                } else {
                    serve_loopback_api_connection(stream, port, &t, &b).await;
                }
            });
        }
    });
    (port, token, server_task)
}

#[tokio::test]
async fn mutating_routes_reject_get_and_system_proxy_getter_reports_state() {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let bridge = Arc::new(DesktopCommandBridge::new(constants, profile, "en"));
    let (port, token, server_task) = spawn_test_loopback_server(bridge, false).await;

    let mutating_paths = [
        "/api/connections/terminate",
        "/api/connections/clear",
        "/api/logs/clear",
        "/api/profile/replace",
        "/api/rules/upsert",
        "/api/rules/remove",
        "/api/rules/evaluate",
        "/api/proxies/upsert",
        "/api/proxies/remove",
        "/api/proxies/test",
        "/api/proxies/test-all",
        "/api/chains/upsert",
        "/api/chains/remove",
        "/api/dns/allocate",
        "/api/dns/flush",
        "/api/scan-os",
        "/api/launch-process",
    ];
    for route in mutating_paths {
        let resp = send_raw_http(
            port,
            &format!(
                "GET {route} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
            ),
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "Expected 405 on GET {route}, got: {resp}"
        );
    }

    let get_proxy_resp = send_raw_http(
        port,
        &format!(
            "GET /api/system-proxy HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        ),
    )
    .await;
    assert!(
        get_proxy_resp.starts_with("HTTP/1.1 200 OK"),
        "Expected 200 on GET /api/system-proxy, got: {get_proxy_resp}"
    );
    assert!(
        get_proxy_resp.contains("\"enabled\":"),
        "GET /api/system-proxy must report the enabled flag, got: {get_proxy_resp}"
    );

    server_task.abort();
}

#[tokio::test]
async fn index_page_carries_csp_while_scripts_do_not() {
    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let bridge = Arc::new(DesktopCommandBridge::new(constants, profile, "en"));
    let (port, _token, server_task) = spawn_test_loopback_server(bridge, true).await;

    let index_resp = send_raw_http(
        port,
        &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    )
    .await;
    let expected_header = format!("Content-Security-Policy: {INDEX_CONTENT_SECURITY_POLICY}\r\n");
    assert!(
        index_resp.contains(&expected_header),
        "index response must carry the CSP, got: {index_resp}"
    );
    assert!(INDEX_CONTENT_SECURITY_POLICY.contains("default-src 'self'"));
    assert!(INDEX_CONTENT_SECURITY_POLICY.contains("script-src 'self';"));
    assert!(INDEX_CONTENT_SECURITY_POLICY.contains("connect-src 'self'"));

    let js_resp = send_raw_http(
        port,
        &format!("GET /assets/app.js HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    )
    .await;
    assert!(
        !js_resp.contains("Content-Security-Policy"),
        "script assets must not carry the page CSP, got: {js_resp}"
    );

    server_task.abort();
}

#[tokio::test]
async fn system_errors_reach_the_ui_as_localized_messages_not_os_text() {
    use routeward_core::error::ERR_KEY_SYSTEM_PATH_EMPTY;

    let constants = SystemConstants::load_embedded().expect("SystemConstants");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;

    for locale in ["en", "fr"] {
        let bridge = DesktopCommandBridge::new(constants.clone(), profile.clone(), locale);
        let err = bridge
            .launch_process_with_proxy("   ", &[])
            .await
            .expect_err("an empty executable path must be refused");
        assert_eq!(err, bridge.translate(ERR_KEY_SYSTEM_PATH_EMPTY));
        assert!(
            !err.contains("errors.system"),
            "the raw key must never reach the UI, got: {err}"
        );
    }
}

fn unique_test_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

/// Constants whose IPC endpoint is unique to the calling test.
fn constants_with_private_ipc_endpoint(tag: &str) -> SystemConstants {
    let mut constants = SystemConstants::load_embedded().expect("SystemConstants");
    let suffix = unique_test_suffix();
    #[cfg(windows)]
    {
        constants.ipc.windows_pipe_name = format!(r"\\.\pipe\routeward-{tag}-test-{suffix}");
    }
    #[cfg(not(windows))]
    {
        constants.ipc.unix_socket_path = format!("/tmp/routeward-{tag}-test-{suffix}.sock");
    }
    constants
}

#[tokio::test]
async fn pause_route_rejects_bad_bodies_and_reports_a_missing_daemon() {
    use routeward_core::error::ERR_KEY_DAEMON_INVALID_PAUSE;
    use routeward_core::system::protection_state::MAX_PAUSE_SECS;

    let constants = constants_with_private_ipc_endpoint("pause-missing");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let bridge = DesktopCommandBridge::new(constants, profile, "en");

    let get = handle_api_route("GET", "/api/engine/pause", "{}", &bridge, None)
        .await
        .expect("route response");
    assert_eq!(get.0, 405);

    for body in [
        "{invalid",
        "{}",
        r#"{"seconds":-5}"#,
        r#"{"seconds":1.5}"#,
        r#"{"seconds":"60"}"#,
    ] {
        let res = handle_api_route("POST", "/api/engine/pause", body, &bridge, None)
            .await
            .expect("route response");
        assert_eq!(res.0, 400, "body {body} must be refused");
    }

    for seconds in [0, MAX_PAUSE_SECS + 1] {
        let body = format!(r#"{{"seconds":{seconds}}}"#);
        let res = handle_api_route("POST", "/api/engine/pause", &body, &bridge, None)
            .await
            .expect("route response");
        assert_eq!(res.0, 400, "{seconds}s is out of range");
        let json: serde_json::Value = serde_json::from_slice(&res.2).expect("json");
        assert_eq!(json["errorKey"], ERR_KEY_DAEMON_INVALID_PAUSE);
    }

    let missing_daemon = handle_api_route(
        "POST",
        "/api/engine/pause",
        r#"{"seconds":900}"#,
        &bridge,
        None,
    )
    .await
    .expect("route response");
    assert_eq!(missing_daemon.0, 503);
    let json: serde_json::Value = serde_json::from_slice(&missing_daemon.2).expect("json");
    assert!(json["error"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(json["errorKey"], "errors.daemon.disconnected");
}

#[tokio::test]
async fn pause_route_pauses_through_the_daemon_and_a_toggle_cancels_it() {
    let constants = constants_with_private_ipc_endpoint("pause-live");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let bridge = DesktopCommandBridge::new(constants.clone(), profile.clone(), "en");

    let controller = RouteWardController::new(constants, profile, "en");
    // Only protection the user turned on can be paused.
    controller.record_protection_choice(true);
    let service = DaemonIpcService::bind_for_test(controller).expect("bind test ipc");
    let service_task = tokio::spawn(async move {
        let _ = service.run_accept_loop().await;
    });

    let paused = handle_api_route(
        "POST",
        "/api/engine/pause",
        r#"{"seconds":600}"#,
        &bridge,
        None,
    )
    .await
    .expect("route response");
    assert_eq!(paused.0, 200, "{}", String::from_utf8_lossy(&paused.2));
    let diag: serde_json::Value = serde_json::from_slice(&paused.2).expect("json");
    assert_eq!(diag["running"], false);
    assert!(
        diag["pausedUntilEpochMs"].as_u64().is_some(),
        "the deadline kept by the daemon is reported: {diag}"
    );
    assert_eq!(
        bridge.tray_snapshot().paused_until_epoch_ms,
        diag["pausedUntilEpochMs"].as_u64(),
        "the tray shows the pause deadline"
    );

    let stopped = handle_api_route(
        "POST",
        "/api/engine/toggle",
        r#"{"start":false}"#,
        &bridge,
        None,
    )
    .await
    .expect("route response");
    assert_eq!(stopped.0, 200);
    let diag: serde_json::Value = serde_json::from_slice(&stopped.2).expect("json");
    assert!(
        diag["pausedUntilEpochMs"].is_null(),
        "a toggle ends the pause"
    );
    assert_eq!(bridge.tray_snapshot().paused_until_epoch_ms, None);

    service_task.abort();
}

#[test]
fn desktop_locale_follows_the_operating_system_language() {
    assert_eq!(locale_from_os_name("fr-FR"), "fr");
    assert_eq!(locale_from_os_name("fr_CA.UTF-8"), "fr");
    assert_eq!(locale_from_os_name("FR"), "fr");
    assert_eq!(locale_from_os_name("en-US"), "en");
    assert_eq!(locale_from_os_name("de-DE"), "en");
    assert_eq!(locale_from_os_name(""), "en");
    assert!(matches!(os_default_locale(), "en" | "fr"));
}

#[test]
fn only_an_upstream_failure_counts_as_a_proxy_outage() {
    use crate::commands::is_proxy_outage;
    use routeward_core::telemetry::TrackedConnection;

    let connection = |status: &str, detail: Option<&str>| -> TrackedConnection {
        let mut value = serde_json::json!({
            "id": "c1",
            "pid": 1,
            "processName": "app.exe",
            "processPath": "",
            "targetHost": "example.com",
            "resolvedDomain": null,
            "targetPort": 443,
            "protocol": "tcp",
            "matchedRule": "rule",
            "routeLabel": "BLOCK",
            "latencyMs": 0,
            "rxBytes": 0,
            "txBytes": 0,
            "status": status,
            "startedAt": "2026-11-22T10:00:00Z",
        });
        if let (Some(detail), Some(map)) = (detail, value.as_object_mut()) {
            map.insert("errorDetail".to_string(), detail.into());
        }
        serde_json::from_value(value).expect("tracked connection")
    };

    // The wording of the detail does not matter, only that the proxy failed the connection.
    assert!(is_proxy_outage(&connection(
        "blocked",
        Some("connexion refusee")
    )));
    // A block decided by a rule (no failure detail) never raises the alert, whatever its name.
    assert!(!is_proxy_outage(&connection("blocked", None)));
    assert!(!is_proxy_outage(&connection(
        "closed",
        Some("proxy timeout")
    )));
    assert!(!is_proxy_outage(&connection("active", Some("proxy"))));
}

#[test]
fn tray_notice_texts_fit_a_balloon_in_both_languages() {
    use routeward_core::i18n::I18nRegistry;

    const BALLOON_BODY_MAX_CHARS: usize = 255;
    const BALLOON_TITLE_MAX_CHARS: usize = 63;
    let body_keys = [
        "tray.alert.outage_body",
        "tray.alert.outage_body_open",
        "tray.notice.restored_body",
        "tray.notice.exit_background_body",
        "tray.notice.close_to_tray_body",
        "tray.notice.service_install_failed",
        "tray.notice.uac_cancelled",
        "tray.notice.access_denied",
        "tray.notice.start_failed",
        "tray.notice.toggle_failed",
        "tray.notice.pause_failed",
    ];
    let title_keys = [
        "tray.alert.outage_title",
        "tray.notice.title",
        "tray.notice.exit_background_title",
        "tray.notice.close_to_tray_title",
    ];
    for locale in ["en", "fr"] {
        let i18n = I18nRegistry::new(locale);
        for key in body_keys {
            let text = i18n.t(key);
            assert_ne!(text, key, "{locale}: missing key {key}");
            assert!(
                text.chars().count() <= BALLOON_BODY_MAX_CHARS,
                "{locale}: {key} is too long for a balloon ({} chars)",
                text.chars().count()
            );
        }
        for key in title_keys {
            let text = i18n.t(key);
            assert_ne!(text, key, "{locale}: missing key {key}");
            assert!(
                text.chars().count() <= BALLOON_TITLE_MAX_CHARS,
                "{locale}: {key}"
            );
        }
    }
}

#[tokio::test]
async fn first_close_to_tray_notice_is_shown_once() {
    use std::sync::Mutex as StdMutex;

    let constants = constants_with_private_ipc_endpoint("notice");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let flags_dir =
        std::env::temp_dir().join(format!("routeward-notice-test-{}", unique_test_suffix()));
    let bridge = DesktopCommandBridge::new(constants, profile, "en")
        .with_notice_flags_path(flags_dir.join(crate::notices::NOTICE_FLAGS_FILE_NAME));

    let shown: Arc<StdMutex<Vec<TrayBalloon>>> = Arc::new(StdMutex::new(Vec::new()));
    let sink = Arc::clone(&shown);
    bridge.set_tray_alert_callback(Arc::new(move |balloon| {
        sink.lock().expect("lock").push(balloon);
    }));

    bridge.notify_close_to_tray_once();
    bridge.notify_close_to_tray_once();

    let balloons = shown.lock().expect("lock");
    assert_eq!(balloons.len(), 1, "the notice must be shown a single time");
    assert_eq!(
        balloons[0].title,
        bridge.translate("tray.notice.close_to_tray_title")
    );
    assert_eq!(balloons[0].level, TrayBalloonLevel::Info);
    let _ = std::fs::remove_dir_all(flags_dir);
}

#[tokio::test]
async fn exit_without_a_reachable_daemon_gives_the_settings_back() {
    use crate::commands::ExitDisposition;

    let constants = constants_with_private_ipc_endpoint("exit-offline");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let bridge = DesktopCommandBridge::new(constants, profile, "en");

    assert_eq!(bridge.prepare_exit().await, ExitDisposition::Stopped);
}

#[test]
fn self_heal_reapplies_exactly_what_it_restored_when_protection_runs_again() {
    use crate::commands::{plan_heal_followup, HealFollowUp, HealedSettings};

    let nothing = HealedSettings::default();
    assert_eq!(plan_heal_followup(nothing, true), HealFollowUp::Nothing);
    assert_eq!(plan_heal_followup(nothing, false), HealFollowUp::Nothing);

    let proxy_only = HealedSettings {
        proxy: true,
        pac: false,
    };
    assert_eq!(
        plan_heal_followup(proxy_only, true),
        HealFollowUp::Reapply(proxy_only)
    );
    let both = HealedSettings {
        proxy: true,
        pac: true,
    };
    assert_eq!(plan_heal_followup(both, true), HealFollowUp::Reapply(both));
    // An engine that is off or paused means the user's choice wins: nothing is put back.
    assert_eq!(plan_heal_followup(both, false), HealFollowUp::Forget);
}

#[test]
fn exit_stops_the_engine_when_it_runs_or_is_paused() {
    use crate::commands::exit_must_stop_engine;

    assert!(exit_must_stop_engine(true, None));
    assert!(exit_must_stop_engine(false, Some(1_700_000_000_000)));
    assert!(exit_must_stop_engine(true, Some(1_700_000_000_000)));
    assert!(!exit_must_stop_engine(false, None));
}

#[test]
fn proxy_outage_follows_the_block_reason_and_ignores_simulations() {
    use crate::commands::is_proxy_outage;
    use routeward_core::telemetry::TrackedConnection;

    let connection = |reason: Option<&str>, simulated: bool, detail: Option<&str>| {
        let mut value = serde_json::json!({
            "id": "c1",
            "pid": 1,
            "processName": "app.exe",
            "processPath": "",
            "targetHost": "example.com",
            "resolvedDomain": null,
            "targetPort": 443,
            "protocol": "tcp",
            "matchedRule": "rule",
            "routeLabel": "BLOCK",
            "latencyMs": 0,
            "rxBytes": 0,
            "txBytes": 0,
            "status": "blocked",
            "startedAt": "2026-11-22T10:00:00Z",
        });
        let map = value.as_object_mut().expect("object");
        if let Some(reason) = reason {
            map.insert("blockReason".to_string(), reason.into());
        }
        if simulated {
            map.insert("simulated".to_string(), true.into());
        }
        if let Some(detail) = detail {
            map.insert("errorDetail".to_string(), detail.into());
        }
        serde_json::from_value::<TrackedConnection>(value).expect("tracked connection")
    };

    for reason in [
        "killSwitchProxyUnreachable",
        "killSwitchProxyRefused",
        "killSwitchProxyTimeout",
        "killSwitchProxyAuthRejected",
    ] {
        assert!(is_proxy_outage(&connection(Some(reason), false, None)));
    }
    // A reason that is not a proxy failure never alerts, even with a detail.
    for reason in [
        "ruleBlock",
        "quicBlocked",
        "defaultPolicyBlock",
        "udpProxyUnsupported",
    ] {
        assert!(!is_proxy_outage(&connection(
            Some(reason),
            false,
            Some("x")
        )));
    }
    // A simulated record never alerts.
    assert!(!is_proxy_outage(&connection(
        Some("killSwitchProxyTimeout"),
        true,
        None
    )));
    // No reason: the former heuristic.
    assert!(is_proxy_outage(&connection(None, false, Some("refused"))));
    assert!(!is_proxy_outage(&connection(None, false, None)));
}

#[test]
fn desktop_logs_older_than_the_retention_are_pruned_when_a_day_file_opens() {
    let dir = std::env::temp_dir().join(format!(
        "routeward_desktop_retention_{}_{}",
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
    let profile = ProfileConfig::load_embedded_default().expect("Default profile");
    assert!(profile.enable_logging);
    let bridge = DesktopCommandBridge::new_with_log_dir(constants, profile, "en", dir.clone());
    bridge.log_info("opens today's file");
    assert!(!old.exists(), "a log past the retention must be removed");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn blocked_logs_query_and_diagnostics_routes_are_not_shadowed_by_their_prefixes() {
    let constants = constants_with_private_ipc_endpoint("blocked-routes");
    let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
    profile.enable_logging = false;
    let bridge = DesktopCommandBridge::new(constants, profile, "en");

    // POST-only routes refuse GET with 405 (the shared prefixes answer 200 to a GET).
    for path in [
        "/api/logs/query",
        "/api/diagnostics/analyze",
        "/api/diagnostics/collect",
        "/api/rules/preview",
        "/api/system/flush-os-dns",
    ] {
        let res = handle_api_route("GET", path, "{}", &bridge, None)
            .await
            .expect("route response");
        assert_eq!(res.0, 405, "{path} must be POST-only");
    }

    // Bad bodies are refused before the daemon is asked.
    for path in [
        "/api/logs/query",
        "/api/diagnostics/collect",
        "/api/rules/preview",
    ] {
        let res = handle_api_route("POST", path, "{invalid", &bridge, None)
            .await
            .expect("route response");
        assert_eq!(res.0, 400, "{path} must refuse a bad body");
    }
    let bad_query = handle_api_route("GET", "/api/blocked?limit=abc", "", &bridge, None)
        .await
        .expect("route response");
    assert_eq!(bad_query.0, 400);

    // Valid requests reach the daemon bridge: without a daemon they answer 503 with an error
    // key, never the 200 array of /api/logs or the diagnostics object.
    let query_body = r#"{"source":"memory","limit":10}"#;
    let collect_body =
        r#"{"logDays":1,"includeConnections":false,"includeProfile":false,"maskDomains":false}"#;
    let preview_body = r#"{"upserts":[],"removeIds":[],"request":{"processName":"a.exe","targetHost":"example.com","targetPort":443,"protocol":"tcp"}}"#;
    let cases = [
        ("GET", "/api/blocked", ""),
        ("GET", "/api/blocked?since=5&limit=10", ""),
        ("POST", "/api/logs/query", query_body),
        ("POST", "/api/diagnostics/analyze", "{}"),
        ("POST", "/api/diagnostics/collect", collect_body),
        ("POST", "/api/rules/preview", preview_body),
        ("POST", "/api/system/flush-os-dns", ""),
    ];
    for (method, path, body) in cases {
        let res = handle_api_route(method, path, body, &bridge, None)
            .await
            .expect("route response");
        assert_eq!(res.0, 503, "{path} must report the missing daemon");
        let json: serde_json::Value = serde_json::from_slice(&res.2).expect("json");
        assert_eq!(json["errorKey"], "errors.daemon.disconnected", "{path}");
    }

    // The old routes keep answering.
    let logs = handle_api_route("GET", "/api/logs", "", &bridge, None)
        .await
        .expect("route response");
    assert_eq!(logs.0, 200);
    let diag = handle_api_route("GET", "/api/diagnostics", "", &bridge, None)
        .await
        .expect("route response");
    assert_eq!(diag.0, 200);
}

mod desktop_log_bundle {
    use crate::desktop_logs::{add_desktop_logs, DesktopLogSource};
    use routeward_core::diagnostics::bundle::{BundleLimits, CollectOptions};
    use routeward_core::diagnostics::redact::{mask_domain, Redactor};
    use routeward_core::logger::log_file_name;
    use serde_json::{json, Value};

    const APP: &str = "RouteWardTest";
    const SECRET_HOST: &str = "secret.example.com";
    const SECRET_PASSWORD: &str = "hunter2pw";

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "routeward_desktop_logs_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write_log(dir: &std::path::Path, date: &str, text: &str) {
        std::fs::write(dir.join(log_file_name(APP, date)), text).expect("log file");
    }

    fn base_bundle() -> Value {
        json!({
            "manifest": {"sections": [
                {"name": "system", "bytes": 10},
                {"name": "logs", "bytes": 40}
            ]},
            "system": {},
            "logs": {"files": [
                {"source": "daemon", "date": "20261122", "truncated": false, "text": "daemon line"}
            ]},
        })
    }

    fn source<'a>(
        dir: &'a std::path::Path,
        mask: bool,
        limits: BundleLimits,
    ) -> DesktopLogSource<'a> {
        DesktopLogSource {
            log_dir: dir,
            app_name: APP,
            options: CollectOptions {
                log_days: 2,
                include_connections: false,
                include_profile: false,
                mask_domains: mask,
            },
            limits,
            known_domains: vec![SECRET_HOST.to_string()],
            redactor: Redactor::default().with_machine_name(None),
        }
    }

    const ROOMY: BundleLimits = BundleLimits {
        max_log_days: 14,
        logs_max_bytes: 3_145_728,
        bundle_max_bytes: 6_291_456,
        hard_max_bytes: 8_388_608,
    };

    fn sensitive_line() -> String {
        format!(
            "[2026-11-22 10:00:00 +01:00] [INFO] [proxy] GET https://bob:{SECRET_PASSWORD}@{SECRET_HOST}/p?token=abc123 Authorization: Bearer abcDEF0123456789xyz\n"
        )
    }

    fn desktop_text(bundle: &Value) -> String {
        bundle["logs"]["files"]
            .as_array()
            .expect("files")
            .iter()
            .filter(|f| f["source"] == "desktop")
            .map(|f| f["text"].as_str().expect("text").to_string())
            .collect()
    }

    #[test]
    fn desktop_log_is_added_redacted_and_the_manifest_is_updated() {
        let dir = temp_dir("redact");
        write_log(&dir, "20261122", &sensitive_line());
        let mut bundle = base_bundle();
        add_desktop_logs(&mut bundle, &source(&dir, false, ROOMY));

        let files = bundle["logs"]["files"].as_array().expect("files");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0]["source"], "daemon");
        assert_eq!(files[1]["source"], "desktop");
        let text = desktop_text(&bundle);
        assert!(!text.contains(SECRET_PASSWORD), "password leaked: {text}");
        assert!(!text.contains("abc123"), "query leaked: {text}");
        assert!(
            !text.contains("abcDEF0123456789xyz"),
            "token leaked: {text}"
        );
        assert!(text.contains(SECRET_HOST), "host kept without masking");

        let logs_bytes = serde_json::to_vec(&bundle["logs"]).expect("json").len();
        let manifest = bundle["manifest"]["sections"].as_array().expect("sections");
        let entry = manifest.iter().find(|s| s["name"] == "logs").expect("logs");
        assert_eq!(entry["bytes"], logs_bytes);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_part_lists_its_redaction_codes_and_keeps_mask_domains_consistent() {
        let dir = temp_dir("codes");
        write_log(&dir, "20261122", &sensitive_line());

        let mut plain = base_bundle();
        plain["manifest"]["maskDomains"] = json!(false);
        plain["manifest"]["redactions"] = json!(["passwords"]);
        add_desktop_logs(&mut plain, &source(&dir, false, ROOMY));
        let codes = plain["manifest"]["redactions"].as_array().expect("codes");
        assert!(codes.iter().any(|c| c == "passwords"));
        assert!(codes.iter().any(|c| c == "userPaths"));
        assert!(!codes.iter().any(|c| c == "domains"));
        assert_eq!(plain["manifest"]["maskDomains"], false);

        let mut masked = base_bundle();
        masked["manifest"]["maskDomains"] = json!(false);
        add_desktop_logs(&mut masked, &source(&dir, true, ROOMY));
        let codes = masked["manifest"]["redactions"].as_array().expect("codes");
        assert!(codes.iter().any(|c| c == "domains"));
        assert_eq!(masked["manifest"]["maskDomains"], true);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_log_masks_sites_with_the_core_hash_when_asked() {
        let dir = temp_dir("mask");
        write_log(&dir, "20261122", &sensitive_line());
        let mut bundle = base_bundle();
        add_desktop_logs(&mut bundle, &source(&dir, true, ROOMY));
        let text = desktop_text(&bundle);
        assert!(!text.contains(SECRET_HOST), "site leaked: {text}");
        assert!(!text.contains(SECRET_PASSWORD));
        assert!(
            text.contains(&mask_domain(SECRET_HOST)),
            "masked name must match the core hash: {text}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_log_never_pushes_the_bundle_over_its_cap() {
        let dir = temp_dir("cap");
        let big = sensitive_line().repeat(2000);
        write_log(&dir, "20261122", &big);
        write_log(&dir, "20261121", &big);

        let limits = BundleLimits {
            max_log_days: 14,
            logs_max_bytes: 200_000,
            bundle_max_bytes: 60_000,
            hard_max_bytes: 8_388_608,
        };
        let mut bundle = base_bundle();
        add_desktop_logs(&mut bundle, &source(&dir, false, limits));
        let size = serde_json::to_vec(&bundle).expect("json").len();
        assert!(size <= limits.bundle_max_bytes, "bundle is {size} bytes");
        assert!(!desktop_text(&bundle).is_empty(), "halved, not dropped");

        // When even the smallest desktop part does not fit, the bundle is left as it was.
        let tight = BundleLimits {
            max_log_days: 14,
            logs_max_bytes: 200_000,
            bundle_max_bytes: 400,
            hard_max_bytes: 8_388_608,
        };
        let mut unchanged = base_bundle();
        add_desktop_logs(&mut unchanged, &source(&dir, false, tight));
        assert_eq!(unchanged, base_bundle());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn desktop_log_is_skipped_when_logs_are_off_or_missing() {
        let dir = temp_dir("none");
        let mut bundle = base_bundle();
        let mut src = source(&dir, false, ROOMY);
        add_desktop_logs(&mut bundle, &src);
        assert_eq!(bundle, base_bundle(), "no desktop file, nothing added");

        write_log(&dir, "20261122", &sensitive_line());
        src.options.log_days = 0;
        add_desktop_logs(&mut bundle, &src);
        assert_eq!(bundle, base_bundle(), "logDays 0 leaves the logs out");
        let _ = std::fs::remove_dir_all(dir);
    }
}
