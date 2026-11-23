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

mod navigation;

use routeward_core::ipc::generate_ephemeral_token;
use routeward_core::system::AUTOSTART_MINIMIZED_ARG;
use routeward_desktop_lib::commands::{DesktopCommandBridge, ExitDisposition};
#[cfg(target_os = "windows")]
use routeward_desktop_lib::single_instance::{Acquisition, SingleInstance};
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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
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
#[cfg(target_os = "linux")]
const ERR_KEY_DESKTOP_UI_INIT_LINUX: &str = "errors.desktop.ui_init_linux";
/// Placeholder of the log folder in the Linux window-error text.
#[cfg(any(target_os = "linux", test))]
const UI_INIT_PATH_PLACEHOLDER: &str = "{{path}}";
const WINDOW_DEFAULT_WIDTH: f64 = 1400.0;
const WINDOW_DEFAULT_HEIGHT: f64 = 900.0;
const WINDOW_MIN_WIDTH: f64 = 980.0;
const WINDOW_MIN_HEIGHT: f64 = 660.0;
/// Share of the primary monitor width the initial window may take, so it fits on small screens.
const WINDOW_MAX_WIDTH_SHARE: f64 = 0.90;
/// Share of the primary monitor height the initial window may take (room for panels and title bar).
const WINDOW_MAX_HEIGHT_SHARE: f64 = 0.85;
const LOOPBACK_EPHEMERAL_ADDR: &str = "127.0.0.1:0";
/// Connections the loopback UI server holds while they are still sending their request. Each is
/// cut off by the request deadline; anything beyond this is closed before it is read.
const LOOPBACK_MAX_PRE_AUTH_CONNECTIONS: usize = 256;
/// How long a connection that finds the pre-auth pool full waits for a slot before it is closed.
const LOOPBACK_PRE_AUTH_SLOT_WAIT_MS: u64 = 250;
/// Connections allowed to wait for a pre-auth slot at the same time; beyond this they are closed
/// at once, so the waiting itself cannot pile up tasks.
const LOOPBACK_MAX_WAITING_CONNECTIONS: usize = 64;
/// Validated requests served at once (page, assets, the realtime stream, API calls). Taken only
/// after the token check, so slow or unauthenticated connections never consume these.
const LOOPBACK_MAX_SERVING_REQUESTS: usize = 64;
const ICON_WINDOW_DIMENSION: u32 = 32;
const ICON_TASKBAR_DIMENSION: u32 = 256;
/// How long the tray icon stays after the first "protection continues" notice, so the balloon
/// can be read before the icon (and the balloon with it) disappears.
const EXIT_NOTICE_LINGER_MS: u64 = 6000;

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

/// Identifier of the session-end window subclass (unique among this window's subclasses).
#[cfg(target_os = "windows")]
const SESSION_END_SUBCLASS_ID: usize = 1;

/// Window subclass procedure: when Windows confirms the session is ending (logoff or shutdown),
/// gives the proxy settings back before the process is terminated. The event loop never sees
/// `WM_ENDSESSION`, so the usual exit path is not reached in that case.
#[cfg(target_os = "windows")]
unsafe extern "system" fn session_end_subclass_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
    _subclass_id: usize,
    bridge_ptr: usize,
) -> windows_sys::Win32::Foundation::LRESULT {
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass};
    use windows_sys::Win32::UI::WindowsAndMessaging::{WM_ENDSESSION, WM_NCDESTROY};

    // A non-zero wParam means the session really ends (zero: the end was cancelled).
    if msg == WM_ENDSESSION && wparam != 0 {
        // SAFETY: `bridge_ptr` comes from `Arc::into_raw` in `restore_settings_on_session_end`
        // and that reference is intentionally never released, so it is valid for the whole run.
        let bridge = unsafe { &*(bridge_ptr as *const DesktopCommandBridge) };
        bridge.restore_system_settings_on_exit();
    }
    if msg == WM_NCDESTROY {
        // The window is going away: detach the hook as the documentation asks. The bridge
        // reference handed over in `restore_settings_on_session_end` is deliberately never
        // released: the desktop process ends with its window, and other threads may still use
        // the bridge it points to.
        // SAFETY: removes this procedure from the window being destroyed.
        unsafe {
            RemoveWindowSubclass(
                hwnd,
                Some(session_end_subclass_proc),
                SESSION_END_SUBCLASS_ID,
            )
        };
    }
    // SAFETY: forwards the unmodified message of this window procedure call.
    unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
}

/// Hooks `WM_ENDSESSION` on the main window so a logoff or shutdown restores the proxy settings.
/// tao 0.30 exposes no event for it, so the window is subclassed; no new dependency is needed.
#[cfg(target_os = "windows")]
fn restore_settings_on_session_end(window: &Window, bridge: &Arc<DesktopCommandBridge>) {
    use tao::platform::windows::WindowExtWindows;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::Shell::SetWindowSubclass;

    let bridge_ptr = Arc::into_raw(Arc::clone(bridge)) as usize;
    // SAFETY: called on the thread that owns the window; the reference data outlives the window.
    let installed = unsafe {
        SetWindowSubclass(
            window.hwnd() as HWND,
            Some(session_end_subclass_proc),
            SESSION_END_SUBCLASS_ID,
            bridge_ptr,
        )
    };
    if installed == 0 {
        bridge.log_warn(
            "Could not hook the Windows session end; proxy settings are not restored on logoff",
        );
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
        let listener = match TcpListener::from_std(std_listener) {
            Ok(listener) => listener,
            Err(err) => {
                // Without its loopback listener the UI can never load: report it and stop serving.
                let bridge_for_report = Arc::clone(&bridge);
                let detail = format!("Loopback listener error: {err}");
                let _ = tokio::task::spawn_blocking(move || {
                    report_fatal_ui_error(&bridge_for_report, &detail);
                })
                .await;
                return;
            }
        };
        let on_window_cmd: Arc<dyn Fn(DesktopWindowCommand) + Send + Sync> = Arc::new(move |cmd| {
            let _ = event_proxy.send_event(cmd);
        });
        serve_loopback_listener(
            listener,
            bound_port,
            Arc::new(ephemeral_token),
            bridge,
            on_window_cmd,
        )
        .await;
    });
}

/// Serves the loopback UI on `listener` until it fails.
///
/// Two separate bounds apply. `LOOPBACK_MAX_PRE_AUTH_CONNECTIONS` limits the connections still
/// reading their request (each is cut off after the request deadline). The much smaller
/// `LOOPBACK_MAX_SERVING_REQUESTS` limits validated requests and is only taken after the token
/// check, so unauthenticated or slow-drip connections cannot starve authenticated ones.
async fn serve_loopback_listener(
    listener: TcpListener,
    bound_port: u16,
    token: Arc<String>,
    bridge: Arc<DesktopCommandBridge>,
    on_window_cmd: Arc<dyn Fn(DesktopWindowCommand) + Send + Sync>,
) {
    let serving_slots = Arc::new(Semaphore::new(LOOPBACK_MAX_SERVING_REQUESTS));
    accept_bounded(listener, LOOPBACK_MAX_PRE_AUTH_CONNECTIONS, move |stream| {
        let bridge_ref = Arc::clone(&bridge);
        let token_ref = Arc::clone(&token);
        let cmd_ref = Arc::clone(&on_window_cmd);
        let slots_ref = Arc::clone(&serving_slots);
        async move {
            let win_cb = |cmd: DesktopWindowCommand| cmd_ref(cmd);
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
                Some(&slots_ref),
            )
            .await;
        }
    })
    .await;
}

/// Accepts connections until the listener fails and serves each one with `handler`, at most
/// `limit` at a time. A connection that arrives while every slot is taken waits briefly
/// (`LOOPBACK_PRE_AUTH_SLOT_WAIT_MS`) for one and is closed if none frees up, instead of being
/// queued without bound.
///
/// Out of scope: a local process that deliberately holds many sockets open can still crowd
/// others out for the length of the request deadline. The listener is bound to loopback, so the
/// attacker already runs on the same machine, and the token check keeps it from doing anything
/// but wasting slots.
async fn accept_bounded<H, Fut>(listener: TcpListener, limit: usize, handler: H)
where
    H: Fn(TcpStream) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(limit));
    let waiting = Arc::new(Semaphore::new(LOOPBACK_MAX_WAITING_CONNECTIONS));
    while let Ok((stream, _)) = listener.accept().await {
        let serving = handler(stream);
        match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => {
                tokio::spawn(async move {
                    serving.await;
                    drop(permit);
                });
            }
            Err(_) => {
                let Ok(waiting_place) = Arc::clone(&waiting).try_acquire_owned() else {
                    // Too many connections already wait: close this one at once.
                    continue;
                };
                let waiting_slots = Arc::clone(&slots);
                tokio::spawn(async move {
                    let wait = std::time::Duration::from_millis(LOOPBACK_PRE_AUTH_SLOT_WAIT_MS);
                    // On timeout `serving` is dropped unpolled, which closes the connection.
                    if let Ok(Ok(permit)) =
                        tokio::time::timeout(wait, waiting_slots.acquire_owned()).await
                    {
                        drop(waiting_place);
                        serving.await;
                        drop(permit);
                    }
                });
            }
        }
    }
}

/// Lets the UI origin trigger several exports in a row on WebView2.
///
/// The engine's download limiter raises a "multiple automatic downloads" permission request
/// from the second export on. wry registers its own handler that only touches the clipboard
/// kind, and WebView2 invokes every registered handler, so this one only ever sets ALLOW for
/// that single kind on the UI origin and never sets DENY or any other state.
#[cfg(target_os = "windows")]
fn allow_multiple_downloads(
    webview: &wry::WebView,
    bridge: &DesktopCommandBridge,
    allowed_authority: &str,
) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_PERMISSION_KIND, COREWEBVIEW2_PERMISSION_KIND_MULTIPLE_AUTOMATIC_DOWNLOADS,
        COREWEBVIEW2_PERMISSION_STATE_ALLOW,
    };
    use webview2_com::{take_pwstr, PermissionRequestedEventHandler};
    use windows::core::PWSTR;
    use wry::WebViewExtWindows;

    let authority = allowed_authority.to_string();
    let result = unsafe {
        let core = match webview.controller().CoreWebView2() {
            Ok(core) => core,
            Err(err) => {
                bridge.log_warn(format!("WebView2 core unavailable for permissions: {err}"));
                return;
            }
        };
        let mut token = Default::default();
        core.add_PermissionRequested(
            &PermissionRequestedEventHandler::create(Box::new(move |_, args| {
                let Some(args) = args else { return Ok(()) };
                let mut kind = COREWEBVIEW2_PERMISSION_KIND::default();
                args.PermissionKind(&mut kind)?;
                let mut uri = PWSTR::null();
                args.Uri(&mut uri)?;
                let uri = take_pwstr(uri);
                if navigation::should_allow_multiple_downloads(
                    kind == COREWEBVIEW2_PERMISSION_KIND_MULTIPLE_AUTOMATIC_DOWNLOADS,
                    &uri,
                    &authority,
                ) {
                    args.SetState(COREWEBVIEW2_PERMISSION_STATE_ALLOW)?;
                }
                Ok(())
            })),
            &mut token,
        )
    };
    if let Err(err) = result {
        bridge.log_warn(format!(
            "Failed to register WebView2 permission handler: {err}"
        ));
    }
}

/// Caps the default window size to the primary monitor (logical pixels), never below the minimum
/// window size. A monitor size that is not usable leaves the default size untouched.
fn clamp_initial_window_size(monitor_logical: Option<(f64, f64)>) -> (f64, f64) {
    let Some((monitor_width, monitor_height)) = monitor_logical else {
        return (WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT);
    };
    if !(monitor_width.is_finite() && monitor_height.is_finite())
        || monitor_width <= 0.0
        || monitor_height <= 0.0
    {
        return (WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT);
    }
    let max_width = (monitor_width * WINDOW_MAX_WIDTH_SHARE).max(WINDOW_MIN_WIDTH);
    let max_height = (monitor_height * WINDOW_MAX_HEIGHT_SHARE).max(WINDOW_MIN_HEIGHT);
    (
        WINDOW_DEFAULT_WIDTH.min(max_width),
        WINDOW_DEFAULT_HEIGHT.min(max_height),
    )
}

/// Primary monitor size in logical pixels, when the platform reports one.
fn primary_monitor_logical_size<T>(
    event_loop: &tao::event_loop::EventLoop<T>,
) -> Option<(f64, f64)> {
    let monitor = event_loop.primary_monitor()?;
    let logical = monitor.size().to_logical::<f64>(monitor.scale_factor());
    Some((logical.width, logical.height))
}

/// Fills the log folder into the Linux window-error text.
#[cfg(any(target_os = "linux", test))]
fn format_ui_init_linux_message(template: &str, log_dir: &str) -> String {
    template.replace(UI_INIT_PATH_PLACEHOLDER, log_dir)
}

/// Shows the Linux window-error text in a GTK dialog and on stderr. The dialog is shown only from
/// the thread that initialised GTK; elsewhere the stderr line and the log are all there is.
#[cfg(all(target_os = "linux", not(test)))]
fn report_fatal_ui_error_linux(bridge: &DesktopCommandBridge, detail: &str) {
    use gtk::prelude::{DialogExt, WidgetExt};

    let log_dir = routeward_core::config::SystemConstants::load_embedded()
        .map(|constants| constants.telemetry.resolve_user_log_dir())
        .map(|dir| dir.display().to_string())
        .unwrap_or_default();
    let message =
        format_ui_init_linux_message(&bridge.translate(ERR_KEY_DESKTOP_UI_INIT_LINUX), &log_dir);
    eprintln!("{WINDOW_TITLE}: {message} ({detail})");
    if gtk::is_initialized_main_thread() {
        let dialog = gtk::MessageDialog::builder()
            .message_type(gtk::MessageType::Error)
            .buttons(gtk::ButtonsType::Ok)
            .modal(true)
            .title(WINDOW_TITLE)
            .text(message.as_str())
            .build();
        dialog.run();
        dialog.hide();
    }
}

fn report_fatal_ui_error(bridge: &DesktopCommandBridge, detail: &str) {
    let summary = bridge.translate(ERR_KEY_DESKTOP_UI_INIT);
    bridge.log_error(format!("{summary}: {detail}"));
    #[cfg(all(target_os = "linux", not(test)))]
    report_fatal_ui_error_linux(bridge, detail);
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

/// True when the app was started by the sign-in autostart: tray only, no window.
fn is_minimized_arg_list<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .any(|arg| arg.as_ref() == AUTOSTART_MINIMIZED_ARG)
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

    // One app per user session: a second launch asks the first one to show its window and ends.
    #[cfg(target_os = "windows")]
    let single_instance = match SingleInstance::acquire() {
        Ok(Acquisition::First(guard)) => Some(Arc::new(guard)),
        Ok(Acquisition::AlreadyRunning) => return Ok(()),
        Err(code) => {
            tracing::warn!("Single-instance guard unavailable (Win32 error {code})");
            None
        }
    };
    let start_minimized = is_minimized_arg_list(std::env::args().skip(1));

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
    let quit_proxy = event_proxy.clone();

    #[cfg(target_os = "windows")]
    if let Some(guard) = &single_instance {
        let proxy_for_show = event_proxy.clone();
        guard.spawn_show_listener(move || {
            let _ = proxy_for_show.send_event(DesktopWindowCommand::ShowWindow);
        });
    }

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
            let tray_for_alerts = Arc::clone(&tray);
            bridge.set_tray_alert_callback(Arc::new(move |balloon| {
                tray_for_alerts.lock().show_alert(balloon);
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

    let (initial_width, initial_height) =
        clamp_initial_window_size(primary_monitor_logical_size(&event_loop));
    let window_builder = WindowBuilder::new()
        .with_title(WINDOW_TITLE)
        .with_window_icon(load_window_icon_32())
        .with_inner_size(LogicalSize::new(initial_width, initial_height))
        .with_min_inner_size(LogicalSize::new(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT))
        .with_theme(Some(initial_tao_theme))
        // Started by the sign-in autostart: stay in the tray (the window opens from there). Without
        // a tray there would be no way to open it, so the window shows anyway.
        .with_visible(!(start_minimized && tray_ready));

    #[cfg(target_os = "windows")]
    let window_builder = {
        use tao::platform::windows::WindowBuilderExtWindows;
        window_builder.with_taskbar_icon(load_taskbar_icon_256())
    };
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
    #[cfg(target_os = "windows")]
    restore_settings_on_session_end(&window, &bridge);

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
    let Some(allowed_authority) = navigation::ui_origin_authority(&ui_url) else {
        report_fatal_ui_error(&bridge, "Invalid loopback UI URL");
        return Err("Invalid loopback UI URL".into());
    };
    let bridge_for_nav = Arc::clone(&bridge);
    let bridge_for_new_window = Arc::clone(&bridge);
    #[cfg(target_os = "windows")]
    let allowed_authority_for_permissions = allowed_authority.clone();
    let mut web_context = WebContext::new(Some(webview_data_dir));
    let webview_builder = WebViewBuilder::with_web_context(&mut web_context)
        .with_initialization_script(&init_script)
        .with_navigation_handler(move |target| {
            let allowed = navigation::is_navigation_allowed(&target, &allowed_authority);
            if !allowed {
                bridge_for_nav.log_warn(format!(
                    "Blocked WebView navigation to {}",
                    navigation::redact_url_for_log(&target)
                ));
            }
            allowed
        })
        .with_new_window_req_handler(move |target| {
            bridge_for_new_window.log_warn(format!(
                "Blocked WebView new window request to {}",
                navigation::redact_url_for_log(&target)
            ));
            false
        })
        // DevTools only in debug builds, so the CSP can be inspected without exposing them to users.
        .with_devtools(cfg!(debug_assertions))
        .with_url(&ui_url);

    // On Linux the webview must live in the window's GTK box: `build(&window)` needs X11 and fails
    // on Wayland. Only the final call differs between platforms.
    #[cfg(target_os = "linux")]
    let webview_result = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        match window.default_vbox() {
            Some(vbox) => webview_builder.build_gtk(vbox),
            None => {
                report_fatal_ui_error(&bridge, "Window has no GTK container for the WebView");
                return Err("Window has no GTK container for the WebView".into());
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let webview_result = webview_builder.build(&window);

    let webview = match webview_result {
        Ok(wv) => wv,
        Err(err) => {
            report_fatal_ui_error(&bridge, &format!("WebView build error: {err}"));
            return Err(Box::new(err));
        }
    };

    #[cfg(target_os = "windows")]
    allow_multiple_downloads(&webview, &bridge, &allowed_authority_for_permissions);
    #[cfg(not(target_os = "windows"))]
    let _ = &webview;

    let rt_for_loop = Arc::clone(&runtime);
    let bridge_for_loop = Arc::clone(&bridge);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        // The single-instance guard lives as long as the event loop.
        #[cfg(target_os = "windows")]
        let _ = &single_instance;
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if tray_ready {
                    window.set_visible(false);
                    bridge_for_loop.notify_close_to_tray_once();
                } else {
                    let _ = quit_proxy.send_event(DesktopWindowCommand::Quit);
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
                        bridge_for_loop.notify_close_to_tray_once();
                    } else {
                        let _ = quit_proxy.send_event(DesktopWindowCommand::Quit);
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
                DesktopWindowCommand::StartDaemon => {
                    let b = Arc::clone(&bridge_for_loop);
                    rt_for_loop.spawn(async move {
                        b.tray_start_protection().await;
                    });
                }
                DesktopWindowCommand::ToggleEngine => {
                    let b = Arc::clone(&bridge_for_loop);
                    rt_for_loop.spawn(async move {
                        b.tray_toggle_engine().await;
                    });
                }
                DesktopWindowCommand::PauseEngineSeconds(seconds) => {
                    let b = Arc::clone(&bridge_for_loop);
                    rt_for_loop.spawn(async move {
                        // The daemon keeps the deadline: closing the app does not end the pause.
                        b.tray_pause(seconds).await;
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
                    // Decide first what happens to protection (it may keep running in the
                    // background), off the UI thread; then come back to exit.
                    let b = Arc::clone(&bridge_for_loop);
                    let proxy = quit_proxy.clone();
                    rt_for_loop.spawn(async move {
                        if b.prepare_exit().await
                            == (ExitDisposition::ProtectionContinues { announce: true })
                        {
                            tokio::time::sleep(std::time::Duration::from_millis(
                                EXIT_NOTICE_LINGER_MS,
                            ))
                            .await;
                        }
                        let _ = proxy.send_event(DesktopWindowCommand::QuitNow);
                    });
                }
                DesktopWindowCommand::QuitNow => {
                    #[cfg(target_os = "windows")]
                    tray_handle.lock().shutdown();
                    bridge_for_loop.restore_system_settings_unless_protected();
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
    fn window_size_is_capped_to_the_monitor_and_never_below_the_minimum() {
        // Large monitor: the default size is kept.
        assert_eq!(
            clamp_initial_window_size(Some((3840.0, 2160.0))),
            (WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT)
        );
        // Small monitor: capped at the width and height shares.
        let (width, height) = clamp_initial_window_size(Some((1280.0, 800.0)));
        assert_eq!(width, 1280.0 * WINDOW_MAX_WIDTH_SHARE);
        assert_eq!(height, 800.0 * WINDOW_MAX_HEIGHT_SHARE);
        // Tiny monitor: never below the minimum window size.
        assert_eq!(
            clamp_initial_window_size(Some((800.0, 600.0))),
            (WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        );
        // Unknown or unusable monitor: the default size.
        for unusable in [
            None,
            Some((0.0, 0.0)),
            Some((f64::NAN, 900.0)),
            Some((-1.0, 900.0)),
            Some((f64::INFINITY, 900.0)),
        ] {
            assert_eq!(
                clamp_initial_window_size(unusable),
                (WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT)
            );
        }
    }

    #[test]
    fn linux_window_error_text_carries_the_log_folder() {
        let text = format_ui_init_linux_message("Details: {{path}}", "/home/u/.local/log");
        assert_eq!(text, "Details: /home/u/.local/log");
    }

    #[test]
    fn detects_smoke_ipc_cli_flag() {
        assert!(is_smoke_ipc_arg_list(["--smoke-ipc"]));
        assert!(is_smoke_ipc_arg_list(["--foo", "--smoke-ipc"]));
        assert!(!is_smoke_ipc_arg_list::<[&str; 0], &str>([]));
        assert!(!is_smoke_ipc_arg_list(["--help"]));
    }

    #[test]
    fn detects_the_minimized_autostart_flag() {
        assert!(is_minimized_arg_list(["--minimized"]));
        assert!(is_minimized_arg_list(["--other", "--minimized"]));
        assert!(!is_minimized_arg_list::<[&str; 0], &str>([]));
        assert!(!is_minimized_arg_list(["--smoke-ipc"]));
    }

    /// Reads one byte from the stream: `Some(byte)` when the server sent one, `None` on a close.
    async fn first_byte(stream: &mut TcpStream) -> Option<u8> {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1];
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(1)) => Some(buf[0]),
            _ => None,
        }
    }

    #[tokio::test]
    async fn accept_bounded_closes_excess_connections_and_reuses_freed_slots() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const SERVED_MARKER: u8 = b'K';
        const LIMIT: usize = 2;
        const RETRY_ATTEMPTS: usize = 40;
        const RETRY_DELAY_MS: u64 = 50;

        let listener = TcpListener::bind(LOOPBACK_EPHEMERAL_ADDR).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // The handler marks the connection as served, then holds its slot until the peer closes.
        let server = tokio::spawn(accept_bounded(listener, LIMIT, |mut stream| async move {
            let _ = stream.write_all(&[SERVED_MARKER]).await;
            let mut sink = [0u8; 1];
            let _ = stream.read(&mut sink).await;
        }));

        let mut first = TcpStream::connect(addr).await.unwrap();
        let mut second = TcpStream::connect(addr).await.unwrap();
        assert_eq!(first_byte(&mut first).await, Some(SERVED_MARKER));
        assert_eq!(first_byte(&mut second).await, Some(SERVED_MARKER));

        let mut excess = TcpStream::connect(addr).await.unwrap();
        assert_eq!(
            first_byte(&mut excess).await,
            None,
            "a connection beyond the limit must be closed without being served"
        );

        drop(first);
        let mut served_again = false;
        for _ in 0..RETRY_ATTEMPTS {
            let mut retry = TcpStream::connect(addr).await.unwrap();
            if first_byte(&mut retry).await == Some(SERVED_MARKER) {
                served_again = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
        }
        assert!(served_again, "a freed slot must serve new connections");
        server.abort();
    }

    #[tokio::test]
    async fn slow_unauthenticated_connections_cannot_starve_an_authenticated_request() {
        use routeward_core::config::{ProfileConfig, SystemConstants};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let mut profile = ProfileConfig::load_embedded_default().expect("Default profile");
        profile.enable_logging = false;
        let bridge = Arc::new(DesktopCommandBridge::new(constants, profile, "en"));

        let listener = TcpListener::bind(LOOPBACK_EPHEMERAL_ADDR).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let token = generate_ephemeral_token();
        let server = tokio::spawn(serve_loopback_listener(
            listener,
            port,
            Arc::new(token.clone()),
            bridge,
            Arc::new(|_cmd: DesktopWindowCommand| {}),
        ));

        // As many half-sent requests as the serving limit: they never finish and never authenticate.
        let mut dripping = Vec::new();
        for _ in 0..LOOPBACK_MAX_SERVING_REQUESTS {
            let mut slow = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            slow.write_all(b"GET /api/state HTTP/1.1\r\n")
                .await
                .unwrap();
            dripping.push(slow);
        }

        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let request = format!(
            "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-RouteWard-Token: {token}\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.read_to_end(&mut response),
        )
        .await
        .expect("the authenticated request must be answered while slow connections hang")
        .unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");

        drop(dripping);
        server.abort();
    }
}
