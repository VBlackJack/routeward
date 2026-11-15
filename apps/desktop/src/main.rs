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
#[cfg(target_os = "windows")]
use routeward_desktop_lib::tray::TrayHandle;
use routeward_desktop_lib::{
    create_desktop_bridge, serve_loopback_http_connection, DesktopWindowCommand,
    WindowThemeAppearance,
};
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon, Theme, Window, WindowBuilder};
use tokio::net::TcpListener;
use wry::{WebContext, WebViewBuilder};

const EMBEDDED_INDEX_HTML: &[u8] = include_bytes!("../../../ui/dist/index.html");
const EMBEDDED_APP_JS: &[u8] = include_bytes!("../../../ui/dist/assets/app.js");
const EMBEDDED_APP_CSS: &[u8] = include_bytes!("../../../ui/dist/assets/app.css");
const EMBEDDED_GLYPH_SVG: &[u8] = include_bytes!("../../../assets/branding/routeward-glyph.svg");
const EMBEDDED_ICON_SVG: &[u8] = include_bytes!("../../../assets/branding/routeward-icon.svg");
const EMBEDDED_ICON_32_RGBA: &[u8] = include_bytes!("../../../assets/branding/routeward-32.rgba");
const EMBEDDED_ICON_256_RGBA: &[u8] = include_bytes!("../../../assets/branding/routeward-256.rgba");

const WINDOW_TITLE: &str = "RouteWard";
const ERR_KEY_DESKTOP_UI_INIT: &str = "errors.desktop.ui_init";
const WINDOW_DEFAULT_WIDTH: f64 = 1400.0;
const WINDOW_DEFAULT_HEIGHT: f64 = 900.0;
const WINDOW_MIN_WIDTH: f64 = 980.0;
const WINDOW_MIN_HEIGHT: f64 = 660.0;
const LOOPBACK_EPHEMERAL_ADDR: &str = "127.0.0.1:0";
const ICON_WINDOW_DIMENSION: u32 = 32;
const ICON_TASKBAR_DIMENSION: u32 = 256;

fn load_window_icon_32() -> Option<Icon> {
    Icon::from_rgba(
        EMBEDDED_ICON_32_RGBA.to_vec(),
        ICON_WINDOW_DIMENSION,
        ICON_WINDOW_DIMENSION,
    )
    .ok()
}

fn load_taskbar_icon_256() -> Option<Icon> {
    Icon::from_rgba(
        EMBEDDED_ICON_256_RGBA.to_vec(),
        ICON_TASKBAR_DIMENSION,
        ICON_TASKBAR_DIMENSION,
    )
    .ok()
}

fn apply_window_theme(window: &Window, appearance: WindowThemeAppearance) {
    let target_theme = if appearance.is_light {
        Theme::Light
    } else {
        Theme::Dark
    };
    window.set_theme(Some(target_theme));

    #[cfg(target_os = "windows")]
    {
        use std::mem::size_of;
        use tao::platform::windows::WindowExtWindows;
        use windows_sys::Win32::Foundation::HWND;
        use windows_sys::Win32::Graphics::Dwm::{
            DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
        };

        let hwnd = window.hwnd() as HWND;
        let use_dark: i32 = i32::from(!appearance.is_light);
        unsafe {
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
                &use_dark as *const i32 as *const _,
                size_of::<i32>() as u32,
            );
            if let Some(caption) = appearance.caption_color {
                let _ = DwmSetWindowAttribute(
                    hwnd,
                    DWMWA_CAPTION_COLOR as u32,
                    &caption as *const u32 as *const _,
                    size_of::<u32>() as u32,
                );
            }
            if let Some(text) = appearance.text_color {
                let _ = DwmSetWindowAttribute(
                    hwnd,
                    DWMWA_TEXT_COLOR as u32,
                    &text as *const u32 as *const _,
                    size_of::<u32>() as u32,
                );
            }
            if let Some(border) = appearance.border_color {
                let _ = DwmSetWindowAttribute(
                    hwnd,
                    DWMWA_BORDER_COLOR as u32,
                    &border as *const u32 as *const _,
                    size_of::<u32>() as u32,
                );
            }
        }
    }
}

fn spawn_embedded_ui_server(
    runtime: &tokio::runtime::Handle,
    bridge: Arc<DesktopCommandBridge>,
    std_listener: StdTcpListener,
    bound_port: u16,
    ephemeral_token: String,
    event_proxy: EventLoopProxy<DesktopWindowCommand>,
) {
    runtime.spawn(async move {
        bridge.log_info(format!(
            "Loopback UI server listening on http://127.0.0.1:{bound_port}"
        ));
        let listener = TcpListener::from_std(std_listener).expect("Async listener");
        let token_arc = Arc::new(ephemeral_token);

        while let Ok((stream, _)) = listener.accept().await {
            let bridge_ref = Arc::clone(&bridge);
            let proxy_ref = event_proxy.clone();
            let token_ref = Arc::clone(&token_arc);

            tokio::spawn(async move {
                let win_cb = |cmd: DesktopWindowCommand| {
                    let _ = proxy_ref.send_event(cmd);
                };
                serve_loopback_http_connection(
                    stream,
                    bound_port,
                    &token_ref,
                    &bridge_ref,
                    Some(&win_cb),
                    Some(|path: &str| {
                        if path.starts_with("/assets/app.js") {
                            ("application/javascript; charset=utf-8", EMBEDDED_APP_JS)
                        } else if path.starts_with("/assets/app.css") {
                            ("text/css; charset=utf-8", EMBEDDED_APP_CSS)
                        } else if path.starts_with("/routeward-glyph.svg") {
                            ("image/svg+xml", EMBEDDED_GLYPH_SVG)
                        } else if path.starts_with("/routeward-icon.svg") {
                            ("image/svg+xml", EMBEDDED_ICON_SVG)
                        } else {
                            ("text/html; charset=utf-8", EMBEDDED_INDEX_HTML)
                        }
                    }),
                )
                .await;
            });
        }
    });
}

fn report_fatal_ui_error(bridge: &DesktopCommandBridge, detail: &str) {
    let summary = bridge.translate(ERR_KEY_DESKTOP_UI_INIT);
    bridge.log_error(format!("{summary}: {detail}"));
    #[cfg(all(target_os = "windows", not(test)))]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

        let title_wide: Vec<u16> = OsStr::new(WINDOW_TITLE)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let body_wide: Vec<u16> = OsStr::new(&format!("{summary}\n\n{detail}"))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `title_wide` and `body_wide` are null-terminated UTF-16 buffers with valid lifetimes.
        unsafe {
            let _ = MessageBoxW(
                std::ptr::null_mut(),
                body_wide.as_ptr(),
                title_wide.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}

fn is_smoke_ipc_arg_list<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter().any(|arg| arg.as_ref() == "--smoke-ipc")
}

fn run_smoke_ipc() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let maybe_state = rt.block_on(async {
        let bridge = create_desktop_bridge()?;
        Ok::<_, String>(
            tokio::time::timeout(std::time::Duration::from_secs(3), bridge.refresh_state())
                .await
                .ok(),
        )
    })?;

    match maybe_state {
        Some(full_state) => {
            let summary = serde_json::json!({
                "daemonConnected": full_state.diagnostics.daemon_connected,
                "running": full_state.diagnostics.running,
                "elevatedPrivileges": full_state.diagnostics.elevated_privileges,
                "osName": full_state.diagnostics.os_name,
                "relayTcpEndpoint": full_state.diagnostics.relay_tcp_endpoint,
                "dnsEndpoint": full_state.diagnostics.dns_endpoint,
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);

            if full_state.diagnostics.daemon_connected {
                Ok(())
            } else {
                Err("Daemon IPC is disconnected".into())
            }
        }
        None => {
            let summary = serde_json::json!({
                "daemonConnected": false,
                "error": "Timed out querying daemon IPC",
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Err("Timed out querying daemon IPC".into())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if is_smoke_ipc_arg_list(std::env::args().skip(1)) {
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .try_init();
        return run_smoke_ipc();
    }

    tracing_subscriber::fmt::init();

    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
    );
    let _rt_guard = runtime.enter();
    let bridge = Arc::new(create_desktop_bridge()?);

    let std_listener = StdTcpListener::bind(LOOPBACK_EPHEMERAL_ADDR)?;
    std_listener.set_nonblocking(true)?;
    let local_addr = std_listener.local_addr()?;
    let bound_port = local_addr.port();
    let ephemeral_token = generate_ephemeral_token();
    let ui_url = format!("http://{local_addr}/");

    let event_loop = EventLoopBuilder::<DesktopWindowCommand>::with_user_event().build();
    let event_proxy = event_loop.create_proxy();

    #[cfg(target_os = "windows")]
    let (tray_handle, tray_ready) = {
        let proxy_for_tray = event_proxy.clone();
        let tray = Arc::new(parking_lot::Mutex::new(TrayHandle::spawn(
            bridge.tray_snapshot(),
            Box::new(move |cmd| {
                let _ = proxy_for_tray.send_event(cmd);
            }),
        )));
        let ready = tray.lock().is_ready();
        if ready {
            let tray_for_bridge = Arc::clone(&tray);
            bridge.set_tray_callback(Arc::new(move |snapshot| {
                tray_for_bridge.lock().sync_status(snapshot);
            }));
        }
        (tray, ready)
    };
    #[cfg(not(target_os = "windows"))]
    let tray_ready = false;

    spawn_embedded_ui_server(
        runtime.handle(),
        Arc::clone(&bridge),
        std_listener,
        bound_port,
        ephemeral_token.clone(),
        event_proxy,
    );

    let initial_appearance = bridge.initial_window_theme();
    let initial_tao_theme = if initial_appearance.is_light {
        Theme::Light
    } else {
        Theme::Dark
    };

    let mut window_builder = WindowBuilder::new()
        .with_title(WINDOW_TITLE)
        .with_window_icon(load_window_icon_32())
        .with_inner_size(LogicalSize::new(
            WINDOW_DEFAULT_WIDTH,
            WINDOW_DEFAULT_HEIGHT,
        ))
        .with_min_inner_size(LogicalSize::new(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT))
        .with_theme(Some(initial_tao_theme));

    #[cfg(target_os = "windows")]
    {
        use tao::platform::windows::WindowBuilderExtWindows;
        window_builder = window_builder.with_taskbar_icon(load_taskbar_icon_256());
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = load_taskbar_icon_256();
    }

    let window = match window_builder.build(&event_loop) {
        Ok(win) => win,
        Err(err) => {
            report_fatal_ui_error(&bridge, &format!("Window build error: {err}"));
            return Err(Box::new(err));
        }
    };
    apply_window_theme(&window, initial_appearance);

    let webview_data_dir = bridge.webview_data_dir();
    if let Err(err) = std::fs::create_dir_all(&webview_data_dir) {
        bridge.log_warn(format!(
            "Failed to pre-create WebView data directory {}: {err}",
            webview_data_dir.display()
        ));
    } else {
        bridge.log_info(format!(
            "Using WebView user data directory: {}",
            webview_data_dir.display()
        ));
    }

    let init_script = format!("window.__ROUTEWARD_TOKEN__ = {ephemeral_token:?};");
    let mut web_context = WebContext::new(Some(webview_data_dir));
    let _webview = match WebViewBuilder::with_web_context(&mut web_context)
        .with_initialization_script(&init_script)
        .with_url(&ui_url)
        .build(&window)
    {
        Ok(wv) => wv,
        Err(err) => {
            report_fatal_ui_error(&bridge, &format!("WebView build error: {err}"));
            return Err(Box::new(err));
        }
    };

    let rt_for_loop = Arc::clone(&runtime);
    let bridge_for_loop = Arc::clone(&bridge);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if tray_ready {
                    window.set_visible(false);
                } else {
                    #[cfg(target_os = "windows")]
                    tray_handle.lock().shutdown();
                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::UserEvent(cmd) => match cmd {
                DesktopWindowCommand::Minimize => {
                    window.set_minimized(true);
                }
                DesktopWindowCommand::ToggleMaximize => {
                    window.set_maximized(!window.is_maximized());
                }
                DesktopWindowCommand::Close => {
                    if tray_ready {
                        window.set_visible(false);
                    } else {
                        #[cfg(target_os = "windows")]
                        tray_handle.lock().shutdown();
                        *control_flow = ControlFlow::Exit;
                    }
                }
                DesktopWindowCommand::DragWindow => {
                    let _ = window.drag_window();
                }
                DesktopWindowCommand::ShowWindow => {
                    window.set_visible(true);
                    window.set_minimized(false);
                    window.set_focus();
                }
                DesktopWindowCommand::ToggleEngine => {
                    let b = Arc::clone(&bridge_for_loop);
                    rt_for_loop.spawn(async move {
                        let running = b.get_diagnostics().running;
                        let _ = b.toggle_engine(!running).await;
                    });
                }
                DesktopWindowCommand::SwitchProfile(idx) => {
                    let b = Arc::clone(&bridge_for_loop);
                    rt_for_loop.spawn(async move {
                        b.switch_profile_by_index(idx).await;
                    });
                }
                DesktopWindowCommand::ApplyTheme(appearance) => {
                    apply_window_theme(&window, appearance);
                }
                DesktopWindowCommand::Quit => {
                    #[cfg(target_os = "windows")]
                    tray_handle.lock().shutdown();
                    *control_flow = ControlFlow::Exit;
                }
            },
            _ => {}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_embedded_window_and_taskbar_rgba_icons_and_svgs() {
        assert_eq!(
            EMBEDDED_ICON_32_RGBA.len(),
            (ICON_WINDOW_DIMENSION * ICON_WINDOW_DIMENSION * 4) as usize
        );
        assert_eq!(
            EMBEDDED_ICON_256_RGBA.len(),
            (ICON_TASKBAR_DIMENSION * ICON_TASKBAR_DIMENSION * 4) as usize
        );
        assert!(load_window_icon_32().is_some());
        assert!(load_taskbar_icon_256().is_some());
        assert!(std::str::from_utf8(EMBEDDED_GLYPH_SVG)
            .expect("UTF-8 glyph SVG")
            .contains("<svg"));
        assert!(std::str::from_utf8(EMBEDDED_ICON_SVG)
            .expect("UTF-8 icon SVG")
            .contains("<svg"));
    }

    #[test]
    fn detects_smoke_ipc_cli_flag() {
        assert!(is_smoke_ipc_arg_list(["--smoke-ipc"]));
        assert!(is_smoke_ipc_arg_list(["--foo", "--smoke-ipc"]));
        assert!(!is_smoke_ipc_arg_list::<[&str; 0], &str>([]));
        assert!(!is_smoke_ipc_arg_list(["--help"]));
    }
}
