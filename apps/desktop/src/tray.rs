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

use crate::{DesktopWindowCommand, TrayStatusSnapshot};
use parking_lot::Mutex;
use routeward_core::i18n::I18nRegistry;
use std::cell::RefCell;
use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NIM_SETVERSION, NIN_SELECT, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, EndMenu, GetCursorPos, GetMessageW, LoadIconW, PostMessageW, PostQuitMessage,
    RegisterClassW, RegisterWindowMessageW, SetForegroundWindow, SetMenuDefaultItem,
    TrackPopupMenu, TranslateMessage, CREATESTRUCTW, GWLP_USERDATA, IDI_APPLICATION, MF_CHECKED,
    MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_APP,
    WM_CONTEXTMENU, WM_CREATE, WM_DESTROY, WM_LBUTTONDBLCLK, WM_NCCREATE, WM_NULL, WM_RBUTTONUP,
    WNDCLASSW, WS_OVERLAPPED,
};

const TRAY_ICON_UID: u32 = 1;
const TRAY_RES_ICON_ID: usize = 1;
const NIN_KEYSELECT_FALLBACK: u32 = NIN_SELECT + 1;
const WM_APP_TRAY_CALLBACK: u32 = WM_APP + 1;
const WM_APP_TRAY_SYNC: u32 = WM_APP + 2;
const WM_APP_TRAY_QUIT: u32 = WM_APP + 3;

const IDM_STATUS: u32 = 1000;
const IDM_SHOW: u32 = 1001;
const IDM_TOGGLE: u32 = 1002;
const IDM_QUIT: u32 = 1003;
const IDM_PROFILE_BASE: u32 = 2000;
const MAX_TRAY_PROFILES: usize = 20;

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

pub fn encode_utf16_tip_truncated(text: &str, out: &mut [u16; 128]) {
    out.fill(0);
    let mut idx = 0usize;
    for ch in text.chars() {
        let mut buf = [0u16; 2];
        let encoded = ch.encode_utf16(&mut buf);
        if idx + encoded.len() >= out.len() {
            break;
        }
        for &unit in encoded.iter() {
            out[idx] = unit;
            idx += 1;
        }
    }
    out[idx] = 0;
}

pub struct TrayMenuLabels {
    pub tooltip: String,
    pub status_line: String,
    pub open_app: String,
    pub toggle_engine: String,
    pub toggle_enabled: bool,
    pub quit_app: String,
}

const TRAY_KEY_STATUS_OFFLINE: &str = "tray.status.offline";
const TRAY_KEY_STATUS_PROTECTED: &str = "tray.status.protected";
const TRAY_KEY_STATUS_PAUSED: &str = "tray.status.paused";
const TRAY_KEY_MENU_PAUSE: &str = "tray.menu.pause";
const TRAY_KEY_MENU_ENABLE: &str = "tray.menu.enable";
const TRAY_KEY_MENU_OPEN: &str = "tray.menu.open";
const TRAY_KEY_MENU_QUIT: &str = "tray.menu.quit";

/// Builds the tray tooltip and menu labels from the shared locale files for the snapshot locale.
pub fn build_tray_labels(snapshot: &TrayStatusSnapshot) -> TrayMenuLabels {
    let i18n = I18nRegistry::new(snapshot.locale.trim());
    let status_key = if !snapshot.daemon_connected {
        TRAY_KEY_STATUS_OFFLINE
    } else if snapshot.running {
        TRAY_KEY_STATUS_PROTECTED
    } else {
        TRAY_KEY_STATUS_PAUSED
    };
    let toggle_key = if snapshot.daemon_connected && snapshot.running {
        TRAY_KEY_MENU_PAUSE
    } else {
        TRAY_KEY_MENU_ENABLE
    };
    let status_line = i18n.t(status_key);
    TrayMenuLabels {
        tooltip: status_line.clone(),
        status_line,
        open_app: i18n.t(TRAY_KEY_MENU_OPEN),
        toggle_engine: i18n.t(toggle_key),
        toggle_enabled: snapshot.daemon_connected,
        quit_app: i18n.t(TRAY_KEY_MENU_QUIT),
    }
}

struct TrayWindowState {
    snapshot: Arc<Mutex<TrayStatusSnapshot>>,
    command_cb: Arc<dyn Fn(DesktopWindowCommand) + Send + Sync>,
    taskbar_created_msg: u32,
    nid: RefCell<NOTIFYICONDATAW>,
}

impl TrayWindowState {
    fn update_tooltip_from_snapshot(&self) {
        let snap = self.snapshot.lock().clone();
        let labels = build_tray_labels(&snap);
        let mut nid = self.nid.borrow_mut();
        encode_utf16_tip_truncated(&labels.tooltip, &mut nid.szTip);
        nid.uFlags = NIF_TIP | NIF_SHOWTIP;
        unsafe {
            Shell_NotifyIconW(NIM_MODIFY, &*nid);
        }
    }

    fn register_icon(&self) -> bool {
        let snap = self.snapshot.lock().clone();
        let labels = build_tray_labels(&snap);
        let mut nid = self.nid.borrow_mut();
        encode_utf16_tip_truncated(&labels.tooltip, &mut nid.szTip);
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        unsafe {
            if Shell_NotifyIconW(NIM_ADD, &*nid) == 0 {
                return false;
            }
            nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &*nid);
        }
        true
    }

    fn remove_icon(&self) {
        let nid = self.nid.borrow();
        unsafe {
            Shell_NotifyIconW(NIM_DELETE, &*nid);
        }
    }

    fn show_context_menu(&self, hwnd: HWND) {
        let snap = self.snapshot.lock().clone();
        let labels = build_tray_labels(&snap);

        unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }

            let status_w = to_wide_null(&labels.status_line);
            let open_w = to_wide_null(&labels.open_app);
            let toggle_w = to_wide_null(&labels.toggle_engine);
            let quit_w = to_wide_null(&labels.quit_app);

            AppendMenuW(
                menu,
                MF_STRING | MF_GRAYED,
                IDM_STATUS as usize,
                status_w.as_ptr(),
            );
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            AppendMenuW(menu, MF_STRING, IDM_SHOW as usize, open_w.as_ptr());
            let toggle_flags = if labels.toggle_enabled {
                MF_STRING
            } else {
                MF_STRING | MF_GRAYED
            };
            AppendMenuW(menu, toggle_flags, IDM_TOGGLE as usize, toggle_w.as_ptr());
            if snap.daemon_connected && !snap.profiles.is_empty() {
                AppendMenuW(menu, MF_SEPARATOR, 0, null());
                for (idx, (pid, pname)) in snap.profiles.iter().take(MAX_TRAY_PROFILES).enumerate()
                {
                    let label_w = to_wide_null(pname);
                    let mut flags = MF_STRING;
                    if pid == &snap.active_profile_id {
                        flags |= MF_CHECKED;
                    }
                    AppendMenuW(
                        menu,
                        flags,
                        (IDM_PROFILE_BASE + idx as u32) as usize,
                        label_w.as_ptr(),
                    );
                }
            }
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            AppendMenuW(menu, MF_STRING, IDM_QUIT as usize, quit_w.as_ptr());
            SetMenuDefaultItem(menu, IDM_SHOW, 0);

            let mut pt = POINT { x: 0, y: 0 };
            GetCursorPos(&mut pt);
            SetForegroundWindow(hwnd);

            let cmd_id = TrackPopupMenu(
                menu,
                TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD,
                pt.x,
                pt.y,
                0,
                hwnd,
                null(),
            ) as u32;

            PostMessageW(hwnd, WM_NULL, 0, 0);
            DestroyMenu(menu);

            match cmd_id {
                IDM_SHOW => (self.command_cb)(DesktopWindowCommand::ShowWindow),
                IDM_TOGGLE => (self.command_cb)(DesktopWindowCommand::ToggleEngine),
                IDM_QUIT => (self.command_cb)(DesktopWindowCommand::Quit),
                id if id >= IDM_PROFILE_BASE
                    && id < IDM_PROFILE_BASE + MAX_TRAY_PROFILES as u32 =>
                {
                    let idx = (id - IDM_PROFILE_BASE) as usize;
                    (self.command_cb)(DesktopWindowCommand::SwitchProfile(idx));
                }
                _ => {}
            }
        }
    }
}

unsafe extern "system" fn tray_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowLongPtrW, SetWindowLongPtrW};

    if msg == WM_NCCREATE {
        let cs = &*(lparam as *const CREATESTRUCTW);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, cs.lpCreateParams as isize);
        return 1;
    }

    let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const TrayWindowState;
    if state_ptr.is_null() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    let state = &*state_ptr;

    if state.taskbar_created_msg != 0 && msg == state.taskbar_created_msg {
        let _ = state.register_icon();
        return 0;
    }

    match msg {
        WM_CREATE => 0,
        WM_APP_TRAY_SYNC => {
            state.update_tooltip_from_snapshot();
            0
        }
        WM_APP_TRAY_QUIT => {
            EndMenu();
            state.remove_icon();
            DestroyWindow(hwnd);
            0
        }
        WM_APP_TRAY_CALLBACK => {
            let ev = (lparam as usize) & 0xFFFF;
            if ev == WM_CONTEXTMENU as usize || ev == WM_RBUTTONUP as usize {
                state.show_context_menu(hwnd);
            } else if ev == WM_LBUTTONDBLCLK as usize
                || ev == NIN_SELECT as usize
                || ev == NIN_KEYSELECT_FALLBACK as usize
            {
                (state.command_cb)(DesktopWindowCommand::ShowWindow);
            }
            0
        }
        WM_DESTROY => {
            state.remove_icon();
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub struct TrayHandle {
    ready: Arc<AtomicBool>,
    hwnd_raw: Arc<AtomicIsize>,
    snapshot: Arc<Mutex<TrayStatusSnapshot>>,
    thread: Option<JoinHandle<()>>,
}

impl TrayHandle {
    pub fn spawn<F>(initial_snapshot: TrayStatusSnapshot, command_cb: F) -> Self
    where
        F: Fn(DesktopWindowCommand) + Send + Sync + 'static,
    {
        let ready = Arc::new(AtomicBool::new(false));
        let hwnd_raw = Arc::new(AtomicIsize::new(0));
        let snapshot = Arc::new(Mutex::new(initial_snapshot));
        let cb: Arc<dyn Fn(DesktopWindowCommand) + Send + Sync> = Arc::new(command_cb);

        let (init_tx, init_rx) = mpsc::sync_channel::<bool>(1);
        let ready_clone = Arc::clone(&ready);
        let hwnd_clone = Arc::clone(&hwnd_raw);
        let snap_clone = Arc::clone(&snapshot);

        let thread = std::thread::Builder::new()
            .name("routeward-tray".to_string())
            .spawn(move || unsafe {
                let hinstance = GetModuleHandleW(null());
                let class_name = to_wide_null("RouteWardTrayHiddenWindowClass");
                let win_title = to_wide_null("RouteWardTray");

                let wc = WNDCLASSW {
                    style: 0,
                    lpfnWndProc: Some(tray_wnd_proc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinstance,
                    hIcon: null_mut(),
                    hCursor: null_mut(),
                    hbrBackground: null_mut(),
                    lpszMenuName: null(),
                    lpszClassName: class_name.as_ptr(),
                };
                RegisterClassW(&wc);

                let taskbar_msg_w = to_wide_null("TaskbarCreated");
                let taskbar_created_msg = RegisterWindowMessageW(taskbar_msg_w.as_ptr());

                let mut hicon = LoadIconW(hinstance, TRAY_RES_ICON_ID as *const u16);
                if hicon.is_null() {
                    hicon = LoadIconW(null_mut(), IDI_APPLICATION);
                }

                let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
                nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                nid.uID = TRAY_ICON_UID;
                nid.uCallbackMessage = WM_APP_TRAY_CALLBACK;
                nid.hIcon = hicon;

                let state_box = Box::new(TrayWindowState {
                    snapshot: snap_clone,
                    command_cb: cb,
                    taskbar_created_msg,
                    nid: RefCell::new(nid),
                });
                let state_ptr = Box::into_raw(state_box);

                let hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    win_title.as_ptr(),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    null_mut(),
                    null_mut(),
                    hinstance,
                    state_ptr as *const _,
                );

                if hwnd.is_null() {
                    let _ = Box::from_raw(state_ptr);
                    let _ = init_tx.send(false);
                    return;
                }

                (*state_ptr).nid.borrow_mut().hWnd = hwnd;
                let registered = (*state_ptr).register_icon();
                if !registered {
                    DestroyWindow(hwnd);
                    let _ = Box::from_raw(state_ptr);
                    let _ = init_tx.send(false);
                    return;
                }

                hwnd_clone.store(hwnd as isize, Ordering::SeqCst);
                ready_clone.store(true, Ordering::SeqCst);
                let _ = init_tx.send(true);

                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }

                let _ = Box::from_raw(state_ptr);
                ready_clone.store(false, Ordering::SeqCst);
                hwnd_clone.store(0, Ordering::SeqCst);
            })
            .ok();

        let ok = init_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap_or(false);
        ready.store(ok, Ordering::SeqCst);

        Self {
            ready,
            hwnd_raw,
            snapshot,
            thread,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    pub fn sync_status(&self, new_snapshot: TrayStatusSnapshot) {
        *self.snapshot.lock() = new_snapshot;
        let raw = self.hwnd_raw.load(Ordering::SeqCst);
        if raw != 0 && self.is_ready() {
            unsafe {
                PostMessageW(raw as HWND, WM_APP_TRAY_SYNC, 0, 0);
            }
        }
    }

    pub fn shutdown(&mut self) {
        let raw = self.hwnd_raw.load(Ordering::SeqCst);
        if raw != 0 {
            unsafe {
                PostMessageW(raw as HWND, WM_APP_TRAY_QUIT, 0, 0);
            }
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        self.ready.store(false, Ordering::SeqCst);
    }
}

impl Drop for TrayHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_utf16_tip_within_128_units_without_splitting_surrogates() {
        let mut buf = [0u16; 128];
        let long_text = format!("{}😀", "A".repeat(126));
        encode_utf16_tip_truncated(&long_text, &mut buf);
        assert_eq!(buf[126], 0);
        assert_eq!(buf[127], 0);
    }

    #[test]
    fn tray_labels_adapt_to_locale_and_daemon_state() {
        let offline = build_tray_labels(&TrayStatusSnapshot {
            daemon_connected: false,
            running: false,
            locale: "fr".to_string(),
            active_profile_id: "default".to_string(),
            profiles: Vec::new(),
        });
        assert!(!offline.toggle_enabled);
        assert!(offline.status_line.contains("arrêté"));

        let protected_en = build_tray_labels(&TrayStatusSnapshot {
            daemon_connected: true,
            running: true,
            locale: "en".to_string(),
            active_profile_id: "default".to_string(),
            profiles: Vec::new(),
        });
        assert!(protected_en.toggle_enabled);
        assert!(protected_en.status_line.contains("Protected"));
        assert_eq!(protected_en.toggle_engine, "Pause Protection");
    }
}
