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

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use routeward_core::ipc::generate_ephemeral_token;
use routeward_desktop_lib::commands::DesktopCommandBridge;
use routeward_desktop_lib::{create_desktop_bridge, validate_loopback_http_request};
use serde::Deserialize;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon, Theme, WindowBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wry::WebViewBuilder;

const EMBEDDED_INDEX_HTML: &[u8] = include_bytes!("../../../ui/dist/index.html");
const EMBEDDED_APP_JS: &[u8] = include_bytes!("../../../ui/dist/assets/app.js");
const EMBEDDED_APP_CSS: &[u8] = include_bytes!("../../../ui/dist/assets/app.css");
const EMBEDDED_LOGO_JPG: &[u8] = include_bytes!("../../../ui/public/logo.jpg");

const WINDOW_DEFAULT_WIDTH: f64 = 1400.0;
const WINDOW_DEFAULT_HEIGHT: f64 = 900.0;
const WINDOW_MIN_WIDTH: f64 = 980.0;
const WINDOW_MIN_HEIGHT: f64 = 660.0;
const LOOPBACK_EPHEMERAL_ADDR: &str = "127.0.0.1:0";
const HTTP_REQ_BUFFER_BYTES: usize = 65536;
const ICON_DIMENSION: u32 = 32;

#[derive(Debug, Clone)]
enum DesktopWindowCommand {
    Minimize,
    ToggleMaximize,
    Close,
    DragWindow,
}

#[derive(Debug, Deserialize)]
struct LaunchProcessRequest {
    executable: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SystemProxyRequest {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ToggleEngineRequest {
    start: bool,
}

#[derive(Debug, Deserialize)]
struct TerminateConnectionRequest {
    #[serde(rename = "connectionId")]
    connection_id: String,
}

fn build_drakul_window_icon() -> Option<Icon> {
    let mut rgba = Vec::with_capacity((ICON_DIMENSION * ICON_DIMENSION * 4) as usize);
    let center = (ICON_DIMENSION as f32 - 1.0) / 2.0;

    for y in 0..ICON_DIMENSION {
        for x in 0..ICON_DIMENSION {
            let dx = (x as f32 - center).abs();
            let dy = (y as f32 - center).abs();
            let dist = (dx * dx + dy * dy).sqrt();
            let oct_dist = dx.max(dy) + 0.414 * dx.min(dy);

            let (r, g, b, a) = if oct_dist > 15.0 {
                (0, 0, 0, 0)
            } else if oct_dist > 13.4 {
                // Metallic bevel (#44475A / #BD93F9 glow)
                (189, 147, 249, 255)
            } else if dist < 4.2 {
                // Central prism core (#8BE9FD)
                (139, 233, 253, 255)
            } else if (dx - dy).abs() < 1.8 && y < 16 {
                // Upper neon purple beam (#BD93F9)
                (189, 147, 249, 255)
            } else if (dx - dy).abs() < 1.8 && y >= 16 {
                // Lower emerald tunnel beam (#50FA7B)
                (80, 250, 123, 255)
            } else if dy < 1.5 && x > 14 {
                // Horizontal cyan beam (#8BE9FD)
                (139, 233, 253, 255)
            } else {
                // Drakul deep slate background (#282A36)
                (40, 42, 54, 255)
            };

            rgba.push(r);
            rgba.push(g);
            rgba.push(b);
            rgba.push(a);
        }
    }

    Icon::from_rgba(rgba, ICON_DIMENSION, ICON_DIMENSION).ok()
}

fn extract_json_body(raw_request: &str) -> &str {
    if let Some(idx) = raw_request.find("\r\n\r\n") {
        &raw_request[idx + 4..]
    } else if let Some(idx) = raw_request.find("\n\n") {
        &raw_request[idx + 2..]
    } else {
        ""
    }
}

async fn handle_api_route(
    path: &str,
    body_str: &str,
    bridge: &DesktopCommandBridge,
    proxy: &EventLoopProxy<DesktopWindowCommand>,
) -> Option<(String, Vec<u8>)> {
    if path.starts_with("/api/state") {
        let state = bridge.refresh_state().await;
        let json = serde_json::to_vec(&state).unwrap_or_default();
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/diagnostics") {
        let diag = bridge.get_diagnostics();
        let json = serde_json::to_vec(&diag).unwrap_or_default();
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/telemetry") {
        let snap = bridge.get_telemetry();
        let json = serde_json::to_vec(&snap).unwrap_or_default();
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/connections/terminate") {
        let parsed: Result<TerminateConnectionRequest, _> = serde_json::from_str(body_str);
        let terminated = match parsed {
            Ok(req) => bridge.terminate_connection(req.connection_id).await,
            Err(_) => false,
        };
        let json = serde_json::to_vec(&serde_json::json!({ "terminated": terminated }))
            .unwrap_or_default();
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/connections/clear") {
        bridge.clear_closed_connections().await;
        return Some((
            "application/json; charset=utf-8".to_string(),
            b"{\"ok\":true}".to_vec(),
        ));
    }

    if path.starts_with("/api/connections") {
        let conns = bridge.list_connections();
        let json = serde_json::to_vec(&conns).unwrap_or_default();
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/logs/clear") {
        bridge.clear_logs().await;
        return Some((
            "application/json; charset=utf-8".to_string(),
            b"{\"ok\":true}".to_vec(),
        ));
    }

    if path.starts_with("/api/logs") {
        let logs = bridge.list_logs();
        let json = serde_json::to_vec(&logs).unwrap_or_default();
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/engine/toggle") {
        let parsed: ToggleEngineRequest =
            serde_json::from_str(body_str).unwrap_or(ToggleEngineRequest { start: false });
        let diag = bridge.toggle_engine(parsed.start).await;
        let json = serde_json::to_vec(&diag).unwrap_or_default();
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/scan-os") {
        let sockets = bridge.scan_os_sockets().await;
        let json = serde_json::to_vec(&sockets).unwrap_or_default();
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/system-proxy") {
        let parsed: SystemProxyRequest =
            serde_json::from_str(body_str).unwrap_or(SystemProxyRequest { enabled: false });
        let result = bridge.set_system_proxy(parsed.enabled);
        let json = match result {
            Ok(status) => serde_json::to_vec(&status).unwrap_or_default(),
            Err(err) => {
                serde_json::to_vec(&serde_json::json!({ "error": err })).unwrap_or_default()
            }
        };
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/launch-process") {
        let parsed: Result<LaunchProcessRequest, _> = serde_json::from_str(body_str);
        let json = match parsed {
            Ok(req) => match bridge.launch_process_with_proxy(&req.executable, &req.args) {
                Ok(res) => serde_json::to_vec(&res).unwrap_or_default(),
                Err(err) => {
                    serde_json::to_vec(&serde_json::json!({ "error": err })).unwrap_or_default()
                }
            },
            Err(err) => serde_json::to_vec(&serde_json::json!({ "error": err.to_string() }))
                .unwrap_or_default(),
        };
        return Some(("application/json; charset=utf-8".to_string(), json));
    }

    if path.starts_with("/api/window/minimize") {
        let _ = proxy.send_event(DesktopWindowCommand::Minimize);
        return Some((
            "application/json; charset=utf-8".to_string(),
            b"{\"ok\":true}".to_vec(),
        ));
    }

    if path.starts_with("/api/window/maximize") {
        let _ = proxy.send_event(DesktopWindowCommand::ToggleMaximize);
        return Some((
            "application/json; charset=utf-8".to_string(),
            b"{\"ok\":true}".to_vec(),
        ));
    }

    if path.starts_with("/api/window/close") {
        let _ = proxy.send_event(DesktopWindowCommand::Close);
        return Some((
            "application/json; charset=utf-8".to_string(),
            b"{\"ok\":true}".to_vec(),
        ));
    }

    if path.starts_with("/api/window/drag") {
        let _ = proxy.send_event(DesktopWindowCommand::DragWindow);
        return Some((
            "application/json; charset=utf-8".to_string(),
            b"{\"ok\":true}".to_vec(),
        ));
    }

    None
}

fn spawn_embedded_ui_server(
    std_listener: StdTcpListener,
    bound_port: u16,
    ephemeral_token: String,
    event_proxy: EventLoopProxy<DesktopWindowCommand>,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime");

        rt.block_on(async move {
            let bridge = Arc::new(create_desktop_bridge().expect("DesktopCommandBridge"));
            let listener = TcpListener::from_std(std_listener).expect("Async listener");
            let token_arc = Arc::new(ephemeral_token);

            while let Ok((mut stream, _)) = listener.accept().await {
                let bridge_ref = Arc::clone(&bridge);
                let proxy_ref = event_proxy.clone();
                let token_ref = Arc::clone(&token_arc);

                tokio::spawn(async move {
                    let mut buf = vec![0u8; HTTP_REQ_BUFFER_BYTES];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let path = match validate_loopback_http_request(&req, bound_port, &token_ref) {
                        Ok(valid_path) => valid_path,
                        Err(rejection) => {
                            let status = rejection.status_line();
                            let body = b"{\"error\":\"forbidden\"}";
                            let resp = format!(
                                "{status}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                            let _ = stream.write_all(body).await;
                            return;
                        }
                    };

                    let body_str = extract_json_body(&req);
                    let allowed_origin = format!("http://127.0.0.1:{bound_port}");

                    if let Some((content_type, payload)) =
                        handle_api_route(&path, body_str, &bridge_ref, &proxy_ref).await
                    {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: {allowed_origin}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = stream.write_all(header.as_bytes()).await;
                        let _ = stream.write_all(&payload).await;
                        return;
                    }

                    let (content_type, body) = if path.starts_with("/assets/app.js") {
                        ("application/javascript; charset=utf-8", EMBEDDED_APP_JS)
                    } else if path.starts_with("/assets/app.css") {
                        ("text/css; charset=utf-8", EMBEDDED_APP_CSS)
                    } else if path.starts_with("/logo.jpg") {
                        ("image/jpeg", EMBEDDED_LOGO_JPG)
                    } else {
                        ("text/html; charset=utf-8", EMBEDDED_INDEX_HTML)
                    };

                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                });
            }
        });
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let std_listener = StdTcpListener::bind(LOOPBACK_EPHEMERAL_ADDR)?;
    std_listener.set_nonblocking(true)?;
    let local_addr = std_listener.local_addr()?;
    let bound_port = local_addr.port();
    let ephemeral_token = generate_ephemeral_token();
    let ui_url = format!("http://{local_addr}/");

    let event_loop = EventLoopBuilder::<DesktopWindowCommand>::with_user_event().build();
    let event_proxy = event_loop.create_proxy();

    spawn_embedded_ui_server(
        std_listener,
        bound_port,
        ephemeral_token.clone(),
        event_proxy,
    );

    let window = WindowBuilder::new()
        .with_title("RouteWard")
        .with_window_icon(build_drakul_window_icon())
        .with_inner_size(LogicalSize::new(
            WINDOW_DEFAULT_WIDTH,
            WINDOW_DEFAULT_HEIGHT,
        ))
        .with_min_inner_size(LogicalSize::new(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT))
        .with_theme(Some(Theme::Dark))
        .build(&event_loop)?;

    let init_script = format!("window.__ROUTEWARD_TOKEN__ = {ephemeral_token:?};");
    let _webview = WebViewBuilder::new()
        .with_initialization_script(&init_script)
        .with_url(&ui_url)
        .build(&window)?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(cmd) => match cmd {
                DesktopWindowCommand::Minimize => {
                    window.set_minimized(true);
                }
                DesktopWindowCommand::ToggleMaximize => {
                    window.set_maximized(!window.is_maximized());
                }
                DesktopWindowCommand::Close => {
                    *control_flow = ControlFlow::Exit;
                }
                DesktopWindowCommand::DragWindow => {
                    let _ = window.drag_window();
                }
            },
            _ => {}
        }
    });
}
