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
use routeward_desktop_lib::{
    create_desktop_bridge, extract_json_body, handle_api_route, http_status_line,
    stream_sse_events, validate_loopback_http_request, DesktopWindowCommand, HTTP_REQ_BUFFER_BYTES,
};
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
const ICON_DIMENSION: u32 = 32;

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

                    if path.starts_with("/api/events") {
                        stream_sse_events(stream, bound_port, &bridge_ref).await;
                        return;
                    }

                    let body_str = extract_json_body(&req);
                    let allowed_origin = format!("http://127.0.0.1:{bound_port}");
                    let win_cb = |cmd: DesktopWindowCommand| {
                        let _ = proxy_ref.send_event(cmd);
                    };

                    if let Some((status_code, content_type, payload)) =
                        handle_api_route(&path, body_str, &bridge_ref, Some(&win_cb)).await
                    {
                        let status = http_status_line(status_code);
                        let header = format!(
                            "{status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: {allowed_origin}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
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
