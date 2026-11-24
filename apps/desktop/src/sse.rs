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

use crate::commands::DesktopCommandBridge;
use routeward_core::ipc::protocol::IpcStreamEvent;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SSE_KEEPALIVE_INTERVAL_SECS: u64 = 15;
const SSE_WRITE_TIMEOUT_SECS: u64 = 5;

async fn write_sse_frame(stream: &mut TcpStream, bytes: &[u8]) -> bool {
    let timeout = Duration::from_secs(SSE_WRITE_TIMEOUT_SECS);
    matches!(
        tokio::time::timeout(timeout, async {
            stream.write_all(bytes).await?;
            stream.flush().await
        })
        .await,
        Ok(Ok(()))
    )
}

pub async fn stream_sse_events(
    mut stream: TcpStream,
    bound_port: u16,
    bridge: &DesktopCommandBridge,
) {
    let _ = stream.set_nodelay(true);
    bridge.log_info("Opening SSE event stream (/api/events)");

    let mut rx = bridge.subscribe_events();
    let allowed_origin = format!("http://127.0.0.1:{bound_port}");
    let preamble_padding = " ".repeat(2048);
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-store, no-cache, must-revalidate, no-transform\r\nX-Content-Type-Options: nosniff\r\nAccess-Control-Allow-Origin: {allowed_origin}\r\nConnection: keep-alive\r\n\r\n: connected {preamble_padding}\n\n"
    );
    if !write_sse_frame(&mut stream, header.as_bytes()).await {
        bridge.log_info("Closed SSE event stream (/api/events) on initial write");
        return;
    }

    if bridge.is_daemon_connected() {
        let initial_resync = IpcStreamEvent::Resync { skipped_events: 0 };
        if let Ok(json) = serde_json::to_string(&initial_resync) {
            let frame = format!("data: {json}\n\n");
            if !write_sse_frame(&mut stream, frame.as_bytes()).await {
                bridge.log_info("Closed SSE event stream (/api/events) on initial resync");
                return;
            }
        }
    }

    let keepalive = Duration::from_secs(SSE_KEEPALIVE_INTERVAL_SECS);
    let mut disconnect_buf = [0u8; 64];

    loop {
        tokio::select! {
            read_res = stream.read(&mut disconnect_buf) => {
                match read_res {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            recv_res = tokio::time::timeout(keepalive, rx.recv()) => {
                match recv_res {
                    Ok(Ok(ev)) => {
                        if let Ok(json) = serde_json::to_string(&ev) {
                            let frame = format!("data: {json}\n\n");
                            if !write_sse_frame(&mut stream, frame.as_bytes()).await {
                                break;
                            }
                        }
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped_events))) => {
                        let resync = IpcStreamEvent::Resync { skipped_events };
                        if let Ok(json) = serde_json::to_string(&resync) {
                            let frame = format!("data: {json}\n\n");
                            if !write_sse_frame(&mut stream, frame.as_bytes()).await {
                                break;
                            }
                        }
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                    Err(_) => {
                        if !write_sse_frame(&mut stream, b": keepalive\n\n").await {
                            break;
                        }
                    }
                }
            }
        }
    }

    bridge.log_info("Closed SSE event stream (/api/events)");
}
