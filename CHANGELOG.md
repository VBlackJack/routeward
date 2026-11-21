# Changelog

All notable changes to RouteWard are documented in this file.
Format follows Keep a Changelog and RouteWard Calendar Versioning (`vYYYY.MMDD.NN`).

## [Unreleased]

### Added
- Desktop UI (Simple mode): added 1-click **Start Protection** on Home when the Windows service is stopped, a 3-step readiness checklist, temporary pause buttons (`15m` / `1h`) with automatic resume countdown, a 1-click **Verify My Protection** check, a guided **"App not working?"** troubleshooter to unblock failed apps or sites in Direct mode, and a dismissible proxy outage alert banner.
- Desktop UI (My Proxy & Wizard): exposed proxy link pasting directly in Simple mode (both button and quick-paste auto-fill in the Add Proxy form), added manual host/port input and live connection testing in the 3-step wizard, added a 1-click **Automatic Backup Proxy Switch** (failover) toggle when two or more proxies are active, and added **Detect Existing Proxy** (`/api/system/detect-proxies`) to discover Windows registry, environment, Tor, or local SSH/HTTP proxies.
- Desktop UI (My Apps & Settings): added automatic URL normalization for website rules (pasting `https://www.example.com/login` expands to `example.com, *.example.com`), a searchable running/installed PC apps panel, 1-click protection packs (Ads & Trackers, OS & App Telemetry, Focus Mode), 2-step inline delete confirmations (with in-use warnings on proxies), a **Restore Default Settings** safety reset with automatic profile backup, an expandable **Advanced Tools** accordion in Simple mode, and Wi-Fi network-based automatic profile switching (`/api/system/network-info`).

### Changed
- Windows: the portable ZIP bundles WinDivert 2.2.2 (unmodified `WinDivert.dll` and `WinDivert64.sys`, LGPLv3, with `THIRD_PARTY_NOTICES.txt` and the upstream license), so it intercepts traffic as soon as it is extracted. It also ships `fetch-windivert.ps1`.
- Desktop UI: improved keyboard `:focus-visible` outlines, icon button hitboxes, actionable proxy error messages, and inline port validation (`1-65535`).

### Fixed
- Desktop UI: `ProcessLauncherModal` now displays the actual HTTP relay port (`relayHttpEndpoint`) for `HTTP_PROXY` / `HTTPS_PROXY` instead of the SOCKS5 port.
- Desktop UI: the Quick Setup Wizard `Gaming` goal now creates the gaming direct rule consistently with the Home scenario card.
- Tooling: `ui/scripts/audit.mjs` no longer emits Node `DEP0190` on Windows, and `App.test.tsx` no longer emits React `act(...)` warnings.

## [v2026.1120.01] - 2026-11-20

### Fixed
- Linux: the `.deb` is built on Ubuntu 22.04 (glibc 2.35) instead of the latest runner, so the binaries no longer print "weak version `GLIBC_2.39' not found" on every start on Debian 12; the release job now fails when a binary needs a glibc symbol newer than 2.35.
- Windows: at most one injected ICMP Port Unreachable per flow and second for blocked UDP (Block rules, DoQ, QUIC), so an application that retransmits a blocked datagram no longer makes RouteWard forge one message per packet.
- Windows: a DNS server process whose image cannot be queried is identified by the name the tracker already knows, so name-based Block rules match it and the packet path no longer repeats the failing query.
- The profile reload no longer stalls an async worker while the DNS server tracker scans processes and the firewall rules are reapplied.
- Documented that on Windows a directed broadcast (for example 192.168.1.255) is not recognised by the ICMP guard and is answered like a unicast address; only multicast and the limited broadcast 255.255.255.255 stay silent.

## [v2026.1120.00] - 2026-11-20

### Security
- Windows named pipe: allowed non-administrator SIDs can no longer create their own pipe instance (user ACEs grant `0x12019b` instead of `GRGW`), the production pipe is owned by `BUILTIN\Administrators`, and clients refuse a pipe whose owner is not Administrators, SYSTEM or the current user before sending anything (`errors.daemon.untrusted_pipe_owner`). The daemon reports a squatted pipe name (`errors.daemon.pipe_squatted`) instead of "already running". Clients older than this release cannot connect to a newer daemon.
- Linux: when the daemon crashes or is killed while interception runs with the kill switch on, the host now fails closed through the nftables table `inet routeward_ks` (loopback, established connections, DHCP and IPv6 neighbour discovery stay allowed) until `routeward cleanup --force` or the next interception start. The systemd unit runs `routeward cleanup --force --fail-closed-on-crash` after a failed stop. A clean stop never leaves the network blocked.
- Windows: later UDP fragments are now captured and replay the first fragment's verdict; an orphan later fragment is dropped when the kill switch is on.
- Desktop: the WebView only navigates within the loopback UI origin and cannot open new windows.
- Desktop: the loopback UI server bounds unauthenticated connections and their total request time, so a local process can no longer starve the UI.
- The temporary profile file is no longer granted to Everyone before its removal.
- Linux: the systemd unit is hardened (`SystemCallFilter=@system-service`, kernel and control group protection, restricted address families and namespaces); `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` stay because process attribution needs them.
- Windows: `routeward daemon`, `run`, `cleanup --all-users` and `purge-data` now require an enabled `BUILTIN\Administrators` membership or the SYSTEM account; a restricted administrator token (`runas /trustlevel`) or `LOCAL SERVICE` is refused at the start instead of failing later on access checks.

### Fixed
- Windows: turning the system proxy or PAC on saves the user's previous settings and turning it off restores them, only while the values are still RouteWard's; a corporate proxy is no longer lost. The desktop restores them on exit and at logoff.
- Uninstall: `%ProgramData%\RouteWard` is removed unless `KEEPDATA=1` is passed (never on upgrade), and RouteWard's proxy, PAC and autostart values are removed or restored for every logged-on user (`routeward cleanup --all-users`, read-only and link-checked); `routeward cleanup --user` does the same for the current user. Users not logged on keep their values. On Linux, `purge` removes `/etc/routeward` and `/var/log/routeward`.
- System errors shown in the UI are localized; dates, times, byte sizes and counts follow the UI language.
- The process launcher takes one argument per line, so arguments with spaces or quotes are passed unchanged.
- An MSI upgrade no longer deletes the RouteWard service: the new `routeward service restore` re-registers it with its `--allow-sid` arguments, restarts an automatic-start service, and is rolled back if the install fails.
- MSI uninstall no longer waits on the WinDivert driver to stop.
- Fixed-port engine tests no longer collide with each other on Linux.
- Desktop: the header follows engine changes made outside the UI (for example `routeward ctl start`) by polling the daemon state without overlapping requests, stale responses or false disconnects, and pauses while the window is hidden.
- Desktop (Windows): consecutive exports no longer trigger the WebView2 "download multiple files" prompt; the permission is granted only to the UI origin.
- Desktop: WebView developer tools are available in debug builds only.
- Uninstall: the output of the user settings cleanup and of the data purge now reaches the MSI log (`msiexec /x ... /l*v`); `cleanup --all-users` and `purge-data` log at INFO level by default, and their errors include the system detail. CLI log lines go to stderr without colour codes when not on a terminal.
- Linux docs: after a crash with the kill switch on, systemd restarts the daemon with interception stopped, so the block table stays until `routeward cleanup --force`, `routeward ctl start` or a clean `systemctl restart routeward`.
- DNS servers on the host (Windows `dns.exe`, Linux `named`, `unbound`, `dnsmasq`, `pihole-FTL`, `pdns_recursor`, `kresd`, `dnsdist`, `coredns`) now get real DNS answers instead of Fake-IP ones, so they no longer cache and serve `198.18.x.x` addresses; `dnsConfig.dnsServerProcesses` adds processes or removes a default with `!name`, an explicit Block rule for the process still applies, and replacing a profile over IPC now validates that list.

### Changed
- Windows refuses blocked TCP connections at once with an injected TCP RST (Block rules, kill switch, DoT and IPv6 port 853 blocks) instead of letting them time out; blocked DoQ (UDP 853) and UDP Block rules get an injected ICMP Port Unreachable like QUIC (never toward multicast or the limited broadcast address), which was not delivered on the Windows Server 2022 test VM, so those clients may still time out; failed packet injections are logged (`windivert_inject_failed`).
- Windows logs a start notice counting the connections opened before the engine started that match a Proxy, Chain or Block rule: they keep their route until the application reconnects (documented in the troubleshooting guide, also true on Linux).
- The MSI bundles unmodified WinDivert 2.2.2 under the LGPLv3 with its notices, removes its driver service on uninstall, and each release attaches the WinDivert source archive. The portable ZIP still uses `tools/fetch-windivert.ps1`.
- Linux TPROXY replies reuse one raw socket per address family, and the SOCKS5 UDP session table is no longer scanned on every datagram.
- The minimum supported Rust version is 1.89 (checked in CI) and the UI requires Node.js 22.12 or later.

## [v2026.1116.01] - 2026-11-16

### Security
- Stop sending HTTP proxy `Basic` credentials pre-emptively over plaintext: they are now sent only after a `407` that offers `Basic` (Negotiate and NTLM preferred), and remain pre-emptive only when the hop to the proxy is TLS.
- `install-service.ps1` copies the binaries to `%ProgramFiles%\RouteWard` before registering the LocalSystem service, and `routeward service install` refuses a binary whose directory, file or ancestors can be modified by non-administrators.
- The elevated daemon resolves `reg`, `netsh`, `ipconfig` and `cmd` from the System32 directory instead of the default search order, loads `WinDivert.dll` only from under the executable directory, and honours `ROUTEWARD_WINDIVERT_DLL_PATH` in debug builds only.
- First UDP fragments now follow the routing rule and kill switch decision instead of being reinjected unevaluated.
- Reject control characters and whitespace in SNI and DNS names before they reach `CONNECT` or SOCKS5 requests, and refuse SOCKS5 domains over 255 bytes instead of truncating them.
- Accept SOCKS5 UDP relay datagrams and direct DNS replies only from the expected source, and verify direct DNS transaction IDs.
- With the kill switch on, the Linux IPv6 nftables fallback rejects all IPv6 egress except loopback, RouteWard's own traffic and neighbour discovery, and startup fails if it cannot be installed.
- Key the WinDivert PID cache by protocol, address family and port, purge it on socket close, and shorten its TTL.
- Desktop: add a Content-Security-Policy to the UI page and require `POST` on every mutating API route.
- CI and release workflows run with least-privilege permissions and SHA-pinned actions.

### Fixed
- Desktop bridge and UI report daemon errors (`{error, errorKey}` with 4xx/5xx status) instead of returning `200` and showing a success toast; error toasts stay until dismissed.
- The system proxy toggle reflects the real Windows setting through the new `GET /api/system-proxy`.
- UDP telemetry keeps one record per flow with an idle timeout instead of one never-closed record per datagram.
- `regex:` rules keep the case of their pattern (`\D`, `\W`, `\S` were turned into `\d`, `\w`, `\s`) and match case-insensitively; PAC handles the prefix the same way.
- Fake-IP allocation no longer overwrites a live mapping when the pool wraps, and concurrent lookups of one domain share one address.
- Retry IP Helper table reads when the table grows, so connections are no longer intermittently attributed to an unknown process and blocked.
- SOCKS5 UDP associations through TLS proxy nodes and IPv6 proxy hosts.
- Linux: the Fake-IP drop rules and raw-socket guard follow the configured `fakeIpCidr`.
- Listener bind failures now abort engine start with an error instead of silently black-holing traffic.
- NAT sessions expire, the pending SYN queue is bounded, and relay teardown no longer leaks the client's trailing packets.
- Editing a proxy keeps its imported SNI and enabled state; invalid imported palettes no longer crash the UI.
- Service start, stop and `reg delete` failures are reported instead of ignored.
- CI builds the UI in each job instead of passing it through artifacts, which had exhausted the artifact quota and skipped every Rust job.

### Changed
- Throttle connection update events and keep the log file open with a periodic flush (`logFlushIntervalMs`).
- Cache direct resolutions of Fake-IP targets, the system resolver list and the Linux conntrack table.
- Accessibility: modal focus trap, labelled form fields, keyboard-selectable connection rows, and a higher-contrast Dracula secondary text color.
- New tunables in `configs/system_constants.json` (UDP flow idle timeout, telemetry update interval, PID cache TTL, NAT session expiry, SYN queue size, fragment verdict cache, relay close grace, DNS and conntrack caches).
- The Windows test suite provisions its own SOCKS5 proxy and rule; the repository guard covers more file types, enumerates tracked files and checks locale key usage and release notes.

## [v2026.1116.00] - 2026-11-16

### Changed
- Remove misleading `127.0.0.1:1080` and `127.0.0.1:8080` demo proxies, demo chains, and hardcoded `proxy-socks5-primary` fallbacks across `configs/default_profile.json`, `QuickSetupWizardModal`, `ProxiesView`, `RulesView`, `ConnectionsView`, and `App`.
- Make Direct Filter Mode (no external proxy required) a first-class default in `configs/system_constants.json`, `DashboardView`, `ProxiesView`, `QuickSetupWizardModal`, and 1-click scenarios (`handleApplyUseCase`), with explicit external-proxy messaging and guardrails so `proxy` or `chain` rules are never created without an active proxy hop.
- Enhance Simple Mode rule creation and editing in `RulesView` with a 1-click `+ Edge (msedge.exe)` chip and optional combined domain patterns (such as `meshcore.net, *.meshcore.net`) while preserving round-trip editing in Simple Mode.

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
