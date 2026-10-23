# Windows Non-Regression Test Suite

`tests/windows/Invoke-RouteWardTests.ps1` (and its batch wrapper `tests/windows/Run-RouteWardTests.bat`) runs an automated 9-scenario non-regression test suite for RouteWard on a dedicated Windows test VM.

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

# Dry-run mode (validates path resolution and IPC JSON response parsing against recorded fixtures without starting the daemon or WinDivert):
.\Invoke-RouteWardTests.ps1 -DryRun
```

All paths, endpoints, rule names, and timeouts are configurable via parameters (`-Socks5Host`, `-Socks5Port`, `-TestUrl`, `-PipeName`, `-TransparentRelayPort`, `-BinDir`, etc.). When executed outside the repository (for example from `C:\RouteWard`), the script automatically falls back to its built-in parameter defaults. On exit (`try / finally`), the script stops interception via `ctl stop`, terminates all tracked daemon PIDs, verifies no `routeward` process survives, runs `routeward.exe cleanup`, restores `active_profile.json` if modified, and records a final outbound `curl.exe` connectivity check.

## Covered Scenarios

Each scenario establishes its own starting state independently:

- **`(a)`**: Starts `routeward.exe daemon` in the background and verifies the Named Pipe (`\\.\pipe\routeward-daemon`) appears.
- **`(b)`**: Verifies protected DACLs (`D:P`) restricted to `SYSTEM` and `Administrators` on `%ProgramData%\RouteWard` and `active_profile.json`, and checks the Named Pipe SDDL via `[System.IO.Directory]::GetAccessControl` to ensure `WD`, `BU`, and `AU` are absent.
- **`(c)`**: Verifies `routeward.exe ctl status` (`result.daemonConnected=true`, `result.elevatedPrivileges=true`, `result.running=false`).
- **`(d)`**: Runs `routeward.exe ctl start`, executes `curl.exe`, and verifies HTTP `200` and a tracked `curl.exe` connection in `result` with `matchedRule="CLI Tools via SOCKS5 Proxy"` and `rxBytes > 0`.
- **`(e)`**: Adds a temporary priority-1 `Block` rule for `curl.exe` via `routeward.exe ctl upsert-rule`, verifies `curl.exe` fails and is recorded as `blocked` in `ctl connections`, removes the rule via `routeward.exe ctl remove-rule --id <ID>`, and verifies via `ctl state` that the profile rules returned to their exact initial state.
- **`(f)`**: Runs `routeward.exe ctl stop`, verifies removal of the `RouteWard_TransparentRelay_10810` firewall rule, and checks direct `curl.exe` HTTP `200`.
- **`(g)`**: Starts interception, force-kills the daemon (`Stop-Process -Force`), verifies fail-open `curl.exe` HTTP `200`, and confirms the orphaned firewall rule remains present.
- **`(h)`**: Ensures the orphaned firewall rule is present with the daemon stopped, restarts `routeward.exe daemon`, and verifies automatic removal of the orphaned firewall rule at startup along with its daemon log entry.
- **`(i)`**: Verifies that daemon logs (`%ProgramData%\RouteWard\logs`) and user logs (`%LOCALAPPDATA%\RouteWard\logs`, written at `INFO` level on every `ctl` invocation) were updated during the run and that no `logs` directory was created in the current working directory.

## Reading the Generated Report

- **Console Output**: Prints one `[PASS]`, `[FAIL]`, or `[SKIP]` line per scenario followed by `X PASS / Y FAIL / Z SKIP`. Exits with code `0` only when `FAIL == 0`.
- **Timestamped Report File**: Written next to the script as `RouteWard_TestReport_<yyyyMMdd_HHmmss>.txt`. It contains:
  1. Scenario summary and host/OS metadata.
  2. File sizes and versions of `routeward.exe`, `routeward-desktop.exe`, `WinDivert.dll`, and `WinDivert64.sys`.
  3. Audit notes (including the exact Named Pipe SDDL string).
  4. Raw `routeward ctl` and `routeward cleanup` outputs (with any password fields redacted).
  5. The last 30 lines of both the daemon log and the user log (with any password fields redacted).
