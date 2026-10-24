# Windows Non-Regression Test Suite

`tests/windows/Invoke-RouteWardTests.ps1` (and its batch wrapper `tests/windows/Run-RouteWardTests.bat`) runs an automated 16-scenario non-regression test suite for RouteWard on a dedicated Windows test VM.

## Prerequisites

- **Dedicated Test VM**: Windows 10/11 or Windows Server 2022 with Windows PowerShell `5.1` running in an **elevated Administrator** session.
- **Required Files in the Working Directory**:
  - `routeward.exe` and `routeward-desktop.exe`
  - `WinDivert.dll` and `WinDivert64.sys` (in the same directory as `routeward.exe` or under `third_party\windivert\bin\`)
  - System `curl.exe` (`%SystemRoot%\System32\curl.exe`)
- **Active Upstream SOCKS5 Proxy**: A SOCKS5 proxy listening on `127.0.0.1:1080` (for example `ssh -D 127.0.0.1:1080 ...`), matching the default rule `"CLI Tools via SOCKS5 Proxy"`.
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

All paths, endpoints, rule names, and timeouts are configurable via parameters (`-Socks5Host`, `-Socks5Port`, `-TestUrl`, `-PipeName`, `-TransparentRelayPort`, `-BinDir`, etc.). When executed outside the repository (for example from `C:\RouteWard`), the script automatically falls back to its built-in parameter defaults. On exit (`try / finally`), the script stops interception via `ctl stop`, terminates all tracked daemon PIDs, verifies no `routeward` process survives, runs `routeward.exe cleanup`, restores `active_profile.json` if modified, flushes the Windows DNS cache, and records a final outbound `curl.exe` connectivity check.

## Scenario Execution Order & SOCKS5 Tunnel Lifecycle

Each scenario retains a **stable letter identifier** (`(a)` through `(p)`) across reports, paired with an **explicit execution order** (`[Order 01/16]` through `[Order 16/16]`).

Because Scenario `(j)` stops the local SOCKS5 listener process on `-Socks5Port` to validate the Kill-Switch—and an interactive `ssh -D` tunnel that prompts for a password cannot be restarted unattended—Scenario `(j)` always executes **last (`Order 16/16`)**, after every other scenario that requires the upstream SOCKS5 proxy (`(d)` and `(k)`):

`01:(a) -> 02:(b) -> 03:(c) -> 04:(d) -> 05:(e) -> 06:(f) -> 07:(g) -> 08:(h) -> 09:(i) -> 10:(k) -> 11:(l) -> 12:(m) -> 13:(n) -> 14:(o) -> 15:(p) -> 16:(j)`

Before each scenario that depends on the SOCKS5 proxy (`(d)`, `(k)`, and `(j)`), the script checks whether `${Socks5Host}:${Socks5Port}` responds over TCP. If the SOCKS5 listener is unreachable, that scenario is marked `SKIP` with reason `"upstream SOCKS5 unreachable"` (never `FAIL`).

> **Restarting the SSH Tunnel After a Run**: At the end of Scenario `(j)` (`Order 16/16`), the script attempts to relaunch the SOCKS5 listener process automatically. If the listener was an interactive `ssh -D 127.0.0.1:1080 ...` session requiring a password, automatic background restart will not re-open port `1080` and the script prints a `[NOTICE]` reminder. Manually restart your `ssh -D` tunnel in the VM before running the test suite again.

## Covered Scenarios (in Execution Order)

Each scenario establishes its own starting state independently:

1. **`[Order 01/16]` Scenario `(a)`**: Starts `routeward.exe daemon` in the background and verifies the Named Pipe (`\\.\pipe\routeward-daemon`) appears.
2. **`[Order 02/16]` Scenario `(b)`**: Verifies protected DACLs (`D:P`) restricted to `SYSTEM` and `Administrators` on `%ProgramData%\RouteWard` and `active_profile.json`, and checks the Named Pipe SDDL via `[System.IO.Directory]::GetAccessControl` to ensure `WD`, `BU`, and `AU` are absent.
3. **`[Order 03/16]` Scenario `(c)`**: Verifies `routeward.exe ctl status` (`result.daemonConnected=true`, `result.elevatedPrivileges=true`, `result.running=false`).
4. **`[Order 04/16]` Scenario `(d)`** *(requires SOCKS5)*: Runs `routeward.exe ctl start`, executes `curl.exe`, and verifies HTTP `200` and a tracked `curl.exe` connection in `result` with `matchedRule="CLI Tools via SOCKS5 Proxy"` and `rxBytes > 0`.
5. **`[Order 05/16]` Scenario `(e)`**: Writes a temporary priority-1 `Block` rule for `curl.exe` as UTF-8 without BOM under `%TEMP%`, applies it via `routeward.exe ctl upsert-rule --json-file <path>`, verifies `curl.exe` fails and is recorded as `blocked` in `ctl connections`, removes the rule via `routeward.exe ctl remove-rule --id <ID>`, deletes the temporary file in `finally`, and verifies via `ctl state` that the profile rules returned to their exact initial state.
6. **`[Order 06/16]` Scenario `(f)`**: Runs `routeward.exe ctl stop`, verifies removal of the `RouteWard_TransparentRelay_10810` firewall rule, and checks direct `curl.exe` HTTP `200`.
7. **`[Order 07/16]` Scenario `(g)`**: Starts interception, force-kills the daemon (`Stop-Process -Force`), verifies fail-open `curl.exe` HTTP `200`, and confirms the orphaned firewall rule remains present.
8. **`[Order 08/16]` Scenario `(h)`**: Ensures the orphaned firewall rule is present with the daemon stopped, restarts `routeward.exe daemon`, and verifies automatic removal of the orphaned firewall rule at startup along with its daemon log entry.
9. **`[Order 09/16]` Scenario `(i)`**: Verifies that daemon logs (`%ProgramData%\RouteWard\logs`) and user logs (`%LOCALAPPDATA%\RouteWard\logs`, written at `INFO` level on every `ctl` invocation) were updated during the run and that no `logs` directory was created in the current working directory.
10. **`[Order 10/16]` Scenario `(k)`** *(requires SOCKS5)*: Clears the Windows DNS cache while interception is active, runs `Resolve-DnsName` on a public domain toward an external resolver (`9.9.9.9`), verifies that a Fake-IP inside `198.18.0.0/15` is returned and listed in `ctl fake-ips`, and verifies that `curl.exe` to that domain returns HTTP `200` routed via SOCKS5 with its domain name.
11. **`[Order 11/16]` Scenario `(l)`**: Verifies that `Resolve-DnsName` on the machine's Active Directory domain or primary DNS suffix continues to resolve directly to real internal IP addresses outside the Fake-IP pool (`SKIP` if the machine has no AD domain or primary DNS suffix).
12. **`[Order 12/16]` Scenario `(m)`**: Stops interception (`ctl stop`), clears the Windows DNS cache, and verifies that `Resolve-DnsName` on the public domain returns a real IP address outside `198.18.0.0/15`.
13. **`[Order 13/16]` Scenario `(n)`**: Pre-seeds the Windows DNS Client cache while interception is stopped, runs `routeward.exe ctl start`, and verifies that the OS DNS cache is automatically flushed at startup (`dnsapi.dll!DnsFlushResolverCache` or `ipconfig /flushdns`) and `Get-DnsClientCache` contains `0` entries for the pre-seeded domain.
14. **`[Order 14/16]` Scenario `(o)`**: Sends a QUIC probe over `UDP 443` while interception is active (`securityPolicy.blockQuicUdp443 = true`), measures and displays the client-side error delay triggered by the injected inbound ICMPv4 Port Unreachable (`Type 3, Code 3`) reply, and verifies the `blocked` connection (`SecurityPolicy:blockQuicUdp443`) and `WARN` log entry.
15. **`[Order 15/16]` Scenario `(p)`**: Sends LLMNR (`UDP 5355`) wire queries for both a public FQDN (`public-leak.routeward.test`) and a local single-label name (`fileserver`), and verifies that the public FQDN is blocked (`LocalNameGuard:LLMNR`, rate-limited `WARN` logged) while the local name is allowed directly.
16. **`[Order 16/16]` Scenario `(j)`** *(requires SOCKS5, executed LAST)*: Stops the local SOCKS5 listener on `-Socks5Port` while interception is active (`securityPolicy.killSwitchEnabled = true`), runs `curl.exe`, verifies `curl.exe` fails without falling back to `Direct`, checks that `ctl connections` records the `curl.exe` connection with `status="blocked"` and `routeLabel="BLOCKED"` and `ctl logs` records a `WARN` entry (`Kill-Switch blocked connection`), and in `finally` attempts to restart the SOCKS5 listener process (or prints an explicit notice if an interactive SSH tunnel requires manual restart).

## Reading the Generated Report

- **Console Output**: All console and report lines are formatted in English (`UTF-8` I/O encoding enforced; localized product log messages are never copied into scenario result summaries). Prints one `[PASS]`, `[FAIL]`, or `[SKIP]` line per scenario with both its `[Order XX/16]` position and stable `Scenario (x)` letter, followed by `X PASS / Y FAIL / Z SKIP`. Exits with code `0` only when `FAIL == 0`.
- **Timestamped Report File**: Written next to the script in UTF-8 as `RouteWard_TestReport_<yyyyMMdd_HHmmss>.txt`. It contains:
  1. Scenario summary, explicit execution order, and host/OS metadata.
  2. File sizes and versions of `routeward.exe`, `routeward-desktop.exe`, `WinDivert.dll`, and `WinDivert64.sys`.
  3. Audit notes (including the exact Named Pipe SDDL string and SOCKS5 restart status).
  4. Raw `routeward ctl` and `routeward cleanup` outputs read in UTF-8 (with any password fields redacted).
  5. The last 30 lines of both the daemon log and the user log read in UTF-8 (with any password fields redacted).
