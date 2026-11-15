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
