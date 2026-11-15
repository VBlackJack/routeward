# Changelog

All notable changes to RouteWard are documented in this file.
Format follows Keep a Changelog and RouteWard Calendar Versioning (`vYYYY.MMDD.NN`).

## [v2026.1115.03] - 2026-11-15

### Fixed
- Raise `ipc.maxLineBytes` to 8 MiB and bound tracked connection history (`telemetry.maxConnectionHistoryEntries` = 500, preserving active connections) across the daemon, desktop command bridge, and UI store so large connection lists no longer break Named Pipe IPC.
- Distinguish IPC transport drops from live daemon application errors (`ok: false`) in `IpcClient::call_typed_detailed`, and surface structured `/api/engine/toggle` errors (`400`/`409`/`503`) as localized UI toasts across Header, Dashboard, and Command Palette controls.
- Deduplicate quick-setup wizard rule IDs (`rule-wiz-<preset>`) and await sequential proxy/rule saves while preventing concurrent wizard submissions.
- Resolve relative `windivertDllPaths` against the executable directory before the current working directory and strip Windows `\\?\` verbatim prefixes before loading `WinDivert.dll`.

### Changed
- Default `rule-browsers-socks5` and `rule-cli-tools-chain` to `enabled: false` in `configs/default_profile.json` so browsers and CLI tools pass through cleanly until explicitly routed or enabled.

## [v2026.1115.02] - 2026-11-15

### Fixed
- Harden pre-existing `%ProgramData%\RouteWard` directory permissions and ownership during daemon startup, add MSI `ProgramDataComponents` folder permissions (`SYSTEM` and `Administrators` `GenericAll`), prevent unprivileged desktop processes from writing to privileged directories, and separate UI diagnostics logging from daemon logs.
- Capture and surface early exit codes from elevated `routeward daemon` UAC launches (`NotElevated`, `InsecureProfile`, `IpcBindFailed`, `ConfigInvalid`, `DaemonExitedEarly`) in `routeward-desktop`, and enforce upfront elevation checks in `routeward run`.

### Changed
- Synchronize the native desktop window title bar (DWM caption, text, border, and light/dark mode) plus WebView `color-scheme` and scrollbars with the active ThemeForge palette via `POST /api/theme`.

## [v2026.1115.01] - 2026-11-15

### Fixed
- Store desktop WebView2 user data under `%LOCALAPPDATA%\RouteWard\WebView2` on Windows (`$XDG_DATA_HOME/routeward/webview` on Linux) instead of the read-only installation folder under `C:\Program Files\RouteWard\`, fixing silent launch failures (`HRESULT 0x80070005`) for standard users.
- Log window and WebView2 startup errors to `%LOCALAPPDATA%\RouteWard\logs` and display a localized Windows error dialog (`MessageBoxW`) when initialization fails.

### Changed
- Redesigned the RouteWard application icon, system tray/EXE icon, and UI glyph (`Prisme Passerelle` hexagonal gateway emblem across SVG, PNG, `.ico`, and RGBA resources).

## [v2026.1115.00] - 2026-11-15

### Added
- Transparent process-aware TCP, UDP, and DNS interception across Windows (WinDivert 2.2.2) and Linux (`nftables` / `TPROXY` / `SO_MARK` / `NETLINK_SOCK_DIAG`), with dual-stack IPv4 and IPv6 support.
- Multi-protocol upstream proxy support: SOCKS5 (with UDP ASSOCIATE and username/password authentication), SOCKS4 and SOCKS4a, HTTP CONNECT, and HTTPS CONNECT (TLS with configurable `tlsSkipVerify`), plus Windows SSPI (`Negotiate` / `NTLM`) authentication.
- Ordered multi-hop proxy chains and failover proxy groups (`Chain` and `Group` actions), with runtime kill switch (`securityPolicy.killSwitchEnabled`) and strict fail-closed DNS handling (Fake-IP `198.18.0.0/15`, DNS-over-TCP via SOCKS5, Active Directory suffix bypass, and QUIC/LLMNR/mDNS/NetBIOS leakage guards).
- TLS SNI inspection (port 443) and plaintext HTTP `Host:` inspection (`httpHostInspectPorts`) with `!pattern` exclusion support for domains, processes, and CIDRs.
- Local dynamic PAC server (`http://127.0.0.1:10811/proxy.pac`), Windows `AutoConfigURL` integration, `preset-edge-foxyproxy` rule preset, and FoxyProxy JSON importer for pattern-based Edge/browser routing without a browser extension.
- Privileged daemon architecture (`routeward daemon` and `routeward service`) with Windows SCM service registration, Linux Unix domain socket (`SO_PEERCRED`), Windows Named Pipe (`SDDL` ACL), `routeward ctl` CLI, and `routeward cleanup`.
- Desktop GUI (`routeward-desktop` with `tao` + `wry`) featuring 5 use-case tabs, Simple and Expert modes, visual System App Picker, ThemeForge color palettes, EN/FR i18n, live SSE telemetry stream with `errorDetail` and CSV/JSON export, system tray profile switcher, and named multi-profile storage.
- Windows portable ZIP and WiX v6 `.msi` installer (`packaging/windows/build-msi.ps1`), plus Debian `.deb` packaging script (`packaging/linux/build-deb.sh`).
