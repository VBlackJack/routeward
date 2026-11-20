[Français](fr/windows-testing.md) | English

# Windows Non-Regression Test Suite

`tests/windows/Invoke-RouteWardTests.ps1` (and its batch wrapper `tests/windows/Run-RouteWardTests.bat`) runs an automated 26-scenario non-regression test suite for RouteWard on a dedicated Windows test VM.

## Prerequisites

- **Dedicated Test VM**: Windows 10/11 or Windows Server 2022 with Windows PowerShell `5.1` running in an **elevated Administrator** session.
- **Required Files in the Working Directory**:
  - `routeward.exe` and `routeward-desktop.exe`
  - `socks5_udp_test_server.exe` (compiled via `cargo build --release --examples`, placed in the same directory as `routeward.exe` or under `examples\`)
  - `WinDivert.dll` and `WinDivert64.sys` (in the same directory as `routeward.exe` or under `third_party\windivert\bin\`)
  - System `curl.exe` (`%SystemRoot%\System32\curl.exe`)
- **Active Upstream SOCKS5 Proxy**: A SOCKS5 proxy listening on `127.0.0.1:1080` (for example `ssh -D 127.0.0.1:1080 ...`), at `-Socks5Host` / `-Socks5Port` (defaults `127.0.0.1` and `1080`). The default profile ships no proxy node and no proxy rule, so after the daemon starts (right after scenario `(c)`) the script provisions its own SOCKS5 node (`proxy-win-regression-socks5`, via `routeward.exe ctl upsert-proxy --json-file`) and its own `curl.exe` rule `"CLI Tools via SOCKS5 Proxy"` (`rule-win-regression-cli-socks5`, via `ctl upsert-rule --json-file`). Both are removed in the `finally` block and the original `active_profile.json` bytes are restored. If nothing is listening on `127.0.0.1:<Socks5Port>` at startup, the script automatically launches a tracked local `socks5_udp_test_server.exe` fallback on that port and terminates it in `finally`. UDP proxy scenarios `(q)` and `(r)` and IPv6 scenarios `(t)` and `(u)` launch dedicated `socks5_udp_test_server.exe` instances on ports `1082`, `1083`, and `1084` and clean up their temporary proxy/rule entries afterward.
- **Clean Process State**: No `routeward` or `routeward-desktop` instance running prior to launch.

## Launching the Test Suite

To prevent accidental execution on a host workstation, the script refuses to run without the explicit `-ConfirmTestMachine` switch.

From an elevated Administrator PowerShell or Command Prompt session inside the folder containing `routeward.exe`:

```powershell
# PowerShell 5.1 (full execution inside the dedicated test VM):
.\Invoke-RouteWardTests.ps1 -ConfirmTestMachine

# Or via the batch launcher:
.\Run-RouteWardTests.bat -ConfirmTestMachine

# Dry-run mode (validates path resolution, IPC JSON response parsing, curl stdout-only HTTP code capture, --json-file temp UTF-8 file creation/cleanup, and explicit scenario execution order without starting the daemon or WinDivert):
.\Invoke-RouteWardTests.ps1 -DryRun
```

All paths, endpoints, rule names, and timeouts are configurable via parameters (`-Socks5Host`, `-Socks5Port`, `-TestUrl`, `-PipeName`, `-TransparentRelayPort`, `-BinDir`, `-UdpTestServerExeName`, `-UdpTestProxyPort`, `-UdpRefuseTestProxyPort`, `-Ipv6TestProxyPort`, `-Ipv6TestHttpPort`, `-Ipv6TestUdpPort`, `-PublicNtpServer`, etc.). Host-agnostic process matching supports interactive `powershell.exe`, `pwsh.exe`, and WinRM (`wsmprovhost.exe`) sessions. When executed outside the repository (for example from `C:\RouteWard`), the script automatically falls back to its built-in parameter defaults. On exit (`try / finally`), the script terminates any tracked `socks5_udp_test_server` processes (including any auto-started primary proxy on `-Socks5Port`), stops interception via `ctl stop`, terminates all tracked daemon PIDs, verifies no `routeward` process survives, runs `routeward.exe cleanup`, restores `active_profile.json` if modified, flushes the Windows DNS cache, removes any transient test IPv6 ULA/routes/neighbors, and records a final outbound `curl.exe` connectivity check.

## Scenario Execution Order & SOCKS5 Tunnel Lifecycle

Each scenario retains a **stable letter identifier** (`(a)` through `(z)`) across reports, paired with an **explicit execution order** (`[Order 01/26]` through `[Order 25/26]`).

Because Scenario `(j)` stops the local SOCKS5 listener process on `-Socks5Port` to validate the Kill-Switch (and an interactive `ssh -D` tunnel that prompts for a password cannot be restarted unattended), Scenario `(j)` always executes **last (`Order 26/26`)**, after every other scenario:

`01:(a) -> 02:(b) -> 03:(c) -> 04:(d) -> 05:(e) -> 06:(f) -> 07:(g) -> 08:(h) -> 09:(i) -> 10:(k) -> 11:(l) -> 12:(m) -> 13:(n) -> 14:(o) -> 15:(p) -> 16:(q) -> 17:(r) -> 18:(s) -> 19:(t) -> 20:(u) -> 21:(v) -> 22:(w) -> 23:(x) -> 24:(y) -> 25:(z) -> 26:(j)`

Before each scenario that depends on the primary SOCKS5 proxy (`(d)`, `(k)`, and `(j)`), the script checks whether `${Socks5Host}:${Socks5Port}` responds over TCP. If the SOCKS5 listener is unreachable, that scenario is marked `SKIP` with reason `"upstream SOCKS5 unreachable"` (never `FAIL`).

> **Restarting the SSH Tunnel After a Run**: At the end of Scenario `(j)` (`Order 26/26`), the script attempts to relaunch the SOCKS5 listener process automatically. If the listener was an interactive `ssh -D 127.0.0.1:1080 ...` session requiring a password, automatic background restart will not re-open port `1080` and the script prints a `[NOTICE]` reminder. Manually restart your `ssh -D` tunnel in the VM before running the test suite again.

## Covered Scenarios (in Execution Order)

Each scenario establishes its own starting state independently:

1. **`[Order 01/26]` Scenario `(a)`**: Starts `routeward.exe daemon` in the background and verifies the Named Pipe (`\\.\pipe\routeward-daemon`) appears.
2. **`[Order 02/26]` Scenario `(b)`**: Verifies protected DACLs (`D:P`) restricted to `SYSTEM` and `Administrators` on `%ProgramData%\RouteWard` and `active_profile.json`, and checks the Named Pipe SDDL via `[System.IO.Directory]::GetAccessControl` to ensure `WD`, `BU`, and `AU` are absent.
3. **`[Order 03/26]` Scenario `(c)`**: Verifies `routeward.exe ctl status` (`result.daemonConnected=true`, `result.elevatedPrivileges=true`, `result.running=false`).
4. **`[Order 04/26]` Scenario `(d)`** *(requires SOCKS5)*: Runs `routeward.exe ctl start`, executes `curl.exe`, and verifies HTTP `200` and a tracked `curl.exe` connection in `result` with `matchedRule="CLI Tools via SOCKS5 Proxy"` and `rxBytes > 0`.
5. **`[Order 05/26]` Scenario `(e)`**: Writes a temporary priority-1 `Block` rule for `curl.exe` as UTF-8 without BOM under `%TEMP%`, applies it via `routeward.exe ctl upsert-rule --json-file <path>`, runs `curl.exe --connect-timeout 10` and verifies it is refused at once (exit code `7` or `56` in under `5000` ms, `-BlockFastRejectMaxMs`; the elapsed time is reported in the detail) because RouteWard injects a TCP `RST`, verifies the connection is recorded as `blocked` in `ctl connections`, removes the rule via `routeward.exe ctl remove-rule --id <ID>`, deletes the temporary file in `finally`, and verifies via `ctl state` that the profile rules returned to their exact initial state.
6. **`[Order 06/26]` Scenario `(f)`**: Runs `routeward.exe ctl stop`, verifies removal of the `RouteWard_TransparentRelay_10810` firewall rule, and checks direct `curl.exe` HTTP `200`.
7. **`[Order 07/26]` Scenario `(g)`**: Starts interception, force-kills the daemon (`Stop-Process -Force`), verifies fail-open `curl.exe` HTTP `200`, and confirms the orphaned firewall rule remains present.
8. **`[Order 08/26]` Scenario `(h)`**: Ensures the orphaned firewall rule is present with the daemon stopped, restarts `routeward.exe daemon`, and verifies automatic removal of the orphaned firewall rule at startup along with its daemon log entry.
9. **`[Order 09/26]` Scenario `(i)`**: Verifies that daemon logs (`%ProgramData%\RouteWard\logs`) and user logs (`%LOCALAPPDATA%\RouteWard\logs`, written at `INFO` level on every `ctl` invocation) were updated during the run and that no `logs` directory was created in the current working directory.
10. **`[Order 10/26]` Scenario `(k)`** *(requires SOCKS5)*: Clears the Windows DNS cache while interception is active, runs `Resolve-DnsName` on a public domain toward an external resolver (`9.9.9.9`), verifies that a Fake-IP inside `198.18.0.0/15` is returned and listed in `ctl fake-ips`, and verifies that `curl.exe` to that domain returns HTTP `200` routed via SOCKS5 with its domain name.
11. **`[Order 11/26]` Scenario `(l)`**: Verifies that `Resolve-DnsName` on the machine's Active Directory domain or primary DNS suffix continues to resolve directly to real internal IP addresses outside the Fake-IP pool (`SKIP` if the machine has no AD domain or primary DNS suffix).
12. **`[Order 12/26]` Scenario `(m)`**: Stops interception (`ctl stop`), clears the Windows DNS cache, and verifies that `Resolve-DnsName` on the public domain returns a real IP address outside `198.18.0.0/15`.
13. **`[Order 13/26]` Scenario `(n)`**: Pre-seeds the Windows DNS Client cache while interception is stopped, runs `routeward.exe ctl start`, and verifies that the OS DNS cache is automatically flushed at startup (`dnsapi.dll!DnsFlushResolverCache` or `ipconfig /flushdns`) and `Get-DnsClientCache` contains `0` entries for the pre-seeded domain.
14. **`[Order 14/26]` Scenario `(o)`**: Sends a QUIC probe over `UDP 443` while interception is active (`securityPolicy.blockQuicUdp443 = true`) with `SIO_UDP_CONNRESET` armed on the client socket. Distinguishes mandatory **blocking** (`status=blocked`, `SecurityPolicy:blockQuicUdp443`, `WARN` logged, no reply received) from **fast rejection** (`fastRejection=true/false`, reported with `clientError` and `measuredDelay` in ms). The expected result is `fastRejection=True` with a delay under `500` ms (`-UdpFastRejectMaxMs`); a blocked probe that is not fast stays a `PASS` with `fastRejection=False (NOT fast ...)` in the detail until the VM confirms the injected ICMP reaches the client. If the host firewall drops the injected ICMP, the operator adds an inbound allow rule for it; RouteWard never edits firewall rules. Note: on Windows, `tcpip.sys` / WFP (`FWPM_LAYER_INBOUND_ICMP_ERROR_V4`) may drop synthetic inbound ICMPv4 Port Unreachable (`Type 3, Code 3`) packets when the outbound UDP datagram was dropped at `WINDIVERT_LAYER_NETWORK` before WFP completed outbound flow state creation, resulting in `TimedOut` on raw sockets even though the inner IPv4+UDP checksums are fully computed.
15. **`[Order 15/26]` Scenario `(p)`**: Sends LLMNR (`UDP 5355`) wire queries for both a public FQDN (`public-leak.routeward.test`) and a local single-label name (`fileserver`), and verifies that the public FQDN is blocked (`LocalNameGuard:LLMNR`, rate-limited `WARN` logged) while the local name is allowed directly.
16. **`[Order 16/26]` Scenario `(q)`**: Launches `socks5_udp_test_server.exe` on `127.0.0.1:1082` with `--stats-file`, adds a temporary SOCKS5 proxy node (`ctl upsert-proxy`) and a temporary UDP rule (`ctl upsert-rule`) routing UDP port `123` from the active PowerShell host (`powershell.exe` / `pwsh.exe` / `wsmprovhost.exe`) through that proxy, sends an NTP client request (`48` bytes) to `time.cloudflare.com:123` (resolved to a Fake-IP when Fake-IP is active), verifies that a valid `48`-byte NTP server reply is received and that the test server stats confirm `udp_associate_requests >= 1`, `udp_datagrams_relayed >= 1`, and `udp_replies_relayed >= 1`, and in `finally` removes the temporary rule and proxy node, stops `socks5_udp_test_server.exe`, and verifies via `ctl state` that the profile returned to its exact prior state.
17. **`[Order 17/26]` Scenario `(r)`**: Launches `socks5_udp_test_server.exe` on `127.0.0.1:1083` with `--disable-udp-associate` (`REP = 0x07 Command not supported`), adds a temporary proxy node and UDP rule for port `123`, sends an NTP client request to `time.cloudflare.com:123`, verifies that no reply is received (zero Direct leak), `udp_associate_refused >= 1`, and `ctl connections` records `status="blocked"` / `routeLabel="BLOCKED"`, and in `finally` removes the temporary rule and proxy node, stops the test server, and verifies via `ctl state` that the profile is identical to before.
18. **`[Order 18/26]` Scenario `(s)`**: With no temporary UDP proxy rule active, sends a direct NTP UDP query (`time.cloudflare.com:123`), verifies that the `48`-byte NTP reply is received, and checks that `ctl connections` and `ctl logs` record the attributed `Direct` UDP flow (`protocol="udp"`, `routeLabel="DIRECT"`, active PowerShell host process).
19. **`[Order 19/26]` Scenario `(t)`**: Configures a transient non-loopback IPv6 ULA, permanent neighbor, and host route (`2001:db8:7277::10/128`) in `ActiveStore`, starts a local IPv6 HTTP server on `[::1]:18080` and `socks5_udp_test_server.exe` on `127.0.0.1:1084` with `--map-target 2001:db8:7277::10=::1`, routes `curl.exe -6` through a temporary rule, verifies HTTP `200`, `ctl connections` (`rxBytes > 0`), and `tcp_connect_requests >= 1`, and cleans up all transient IPv6 network entries and profile state in `finally`.
20. **`[Order 20/26]` Scenario `(u)`**: Configures a distinct transient IPv6 ULA (`fd00:7277:2026::11`) and host route (`2001:db8:7277::11/128`) in `ActiveStore`, starts `socks5_udp_test_server.exe` with `--udp-echo-bind [::1]:18123 --map-target 2001:db8:7277::11=::1`, sends an IPv6 UDP NTP packet from a bound ULA socket, verifies WinDivert IPv6 UDP interception, SOCKS5 `UDP ASSOCIATE` (`ATYP=0x04`), forged IPv6 UDP reply delivery (`48` bytes), `ctl connections` attribution, and `udp_datagrams_relayed >= 1` / `udp_replies_relayed >= 1`, and restores all network and profile state in `finally`.
21. **`[Order 21/26]` Scenario `(v)`**: Over a transient IPv6 ULA/route (`fd00:7277:2026::10` -> `2001:db8:7277::10`), sends IPv6 UDP port `53` `A` and `AAAA` DNS wire queries as well as IPv6 TCP port `53` `A` for `example.com` (verifying Fake-IP `198.18.0.0/15` for `A` and `NOERROR` / `ANCOUNT=0` NODATA for `AAAA`), and sends an IPv6 DoT probe on port `853` verifying `SecurityPolicy:blockEncryptedDnsBypass` (`status="blocked"`).
22. **`[Order 22/26]` Scenario `(w)`**: Sends an IPv6 QUIC (`UDP 443`) probe over the transient IPv6 route with `SIO_UDP_CONNRESET` armed and verifies mandatory blocking (`status="blocked"`, `matchedRule="SecurityPolicy:blockQuicUdp443"`, `WARN` logged for `ICMPv6 Port Unreachable`, no reply received) alongside the same fast-rejection check as scenario `(o)` (`fastRejection=True` under `500` ms, otherwise a noted `PASS`).
23. **`[Order 23/26]` Scenario `(x)`**: Sends a direct IPv6 UDP flow (`route=DIRECT`) over the transient IPv6 route and verifies process attribution (`routeLabel="DIRECT"`, PowerShell host process) in `ctl connections` and `ctl logs`.
24. **`[Order 24/26]` Scenario `(y)`**: Runs `routeward.exe service status` (checking valid JSON `serviceName="RouteWard"`) and executes `routeward-desktop.exe --smoke-ipc` headlessly against the live daemon Named Pipe (`daemonConnected=true`, `elevatedPrivileges=true`).
25. **`[Order 25/26]` Scenario `(z)`**: Adds `%SystemRoot%\System32\nslookup.exe` to `dnsConfig.dnsServerProcesses` with `ctl replace-profile --json-file` (standing in for a DNS server), runs `nslookup.exe` for the public test domain against the machine's configured DNS server, verifies that the answer is outside the Fake-IP pool (`198.18.0.0/15`) and that `ctl logs` contains `Exempting DNS server process nslookup.exe (PID n) from Fake-IP`, then restores the original profile and verifies it with `ctl state`. When the `DNS` Windows service is running it also runs `Clear-DnsServerCache -Force` and `Resolve-DnsName <domain> -Server 127.0.0.1 -DnsOnly` and verifies that the answer is not a Fake-IP (that sub-check is skipped otherwise, and the scenario is marked `SKIP` if `nslookup.exe` is missing).
26. **`[Order 26/26]` Scenario `(j)`** *(requires SOCKS5, executed LAST)*: Stops the local SOCKS5 listener on `-Socks5Port` while interception is active (`securityPolicy.killSwitchEnabled = true`), runs `curl.exe`, verifies `curl.exe` fails without falling back to `Direct`, checks that `ctl connections` records the `curl.exe` connection with `status="blocked"` and `routeLabel="BLOCKED"` and `ctl logs` records a `WARN` entry (`Kill-Switch blocked connection`), and in `finally` attempts to restart the SOCKS5 listener process (or prints an explicit notice if an interactive SSH tunnel requires manual restart).

## Reading the Generated Report

- **Console Output**: All console and report lines are formatted in English (`UTF-8` I/O encoding enforced; localized product log messages are never copied into scenario result summaries). Prints one `[PASS]`, `[FAIL]`, or `[SKIP]` line per scenario with both its `[Order XX/26]` position and stable `Scenario (x)` letter, followed by `X PASS / Y FAIL / Z SKIP`. Exits with code `0` only when `FAIL == 0`.
- **Timestamped Report File**: Written next to the script in UTF-8 as `RouteWard_TestReport_<yyyyMMdd_HHmmss>.txt`. It contains:
  1. Scenario summary, explicit execution order, and host/OS metadata.
  2. File sizes and versions of `routeward.exe`, `routeward-desktop.exe`, `socks5_udp_test_server.exe`, `WinDivert.dll`, and `WinDivert64.sys`.
  3. Audit notes (including the exact Named Pipe SDDL string and SOCKS5 restart status).
  4. Raw `routeward ctl` and `routeward cleanup` outputs read in UTF-8 (with any password fields redacted).
  5. The last 30 lines of both the daemon log and the user log read in UTF-8 (with any password fields redacted).
