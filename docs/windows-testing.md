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
# PowerShell 5.1:
.\Invoke-RouteWardTests.ps1 -ConfirmTestMachine

# Or via the batch launcher:
.\Run-RouteWardTests.bat -ConfirmTestMachine
```

All paths, endpoints, rule names, and timeouts are configurable via parameters (`-Socks5Host`, `-Socks5Port`, `-TestUrl`, `-PipeName`, `-TransparentRelayPort`, `-BinDir`, etc.). On exit (`try / finally`), the script always stops any daemon it started, runs `routeward.exe cleanup`, and restores `active_profile.json` if modified.

## Covered Scenarios

- **`(a)`**: Starts `routeward.exe daemon` in the background and verifies the Named Pipe (`\\.\pipe\routeward-daemon`) appears.
- **`(b)`**: Verifies protected DACLs (`D:P`) restricted to `SYSTEM` and `Administrators` on `%ProgramData%\RouteWard` and `active_profile.json`, and checks the Named Pipe SDDL via `[System.IO.Directory]::GetAccessControl` to ensure `WD`, `BU`, and `AU` are absent.
- **`(c)`**: Verifies `routeward.exe ctl status` (`daemonConnected=true`, `elevatedPrivileges=true`, `running=false`).
- **`(d)`**: Runs `routeward.exe ctl start`, executes `curl.exe`, and verifies HTTP `200` and a tracked `curl.exe` connection with `matchedRule="CLI Tools via SOCKS5 Proxy"` and `rxBytes > 0`.
- **`(e)`**: Verifies temporary `Block` rule insertion and removal via `ctl` (cleanly marked `[SKIP]` if `ctl` does not expose a rule-removal subcommand).
- **`(f)`**: Runs `routeward.exe ctl stop`, verifies removal of the `RouteWard_TransparentRelay_10810` firewall rule, and checks direct `curl.exe` HTTP `200`.
- **`(g)`**: Starts interception, force-kills the daemon (`Stop-Process -Force`), verifies fail-open `curl.exe` HTTP `200`, and confirms the orphaned firewall rule remains present.
- **`(h)`**: Restarts `routeward.exe daemon` and verifies automatic removal of the orphaned firewall rule at startup along with its daemon log entry.
- **`(i)`**: Verifies that daemon logs (`%ProgramData%\RouteWard\logs`) and user logs (`%LOCALAPPDATA%\RouteWard\logs`) were updated during the run and that no `logs` directory was created in the current working directory.

## Reading the Generated Report

- **Console Output**: Prints one `[PASS]`, `[FAIL]`, or `[SKIP]` line per scenario followed by `X PASS / Y FAIL / Z SKIP`. Exits with code `0` only when `FAIL == 0`.
- **Timestamped Report File**: Written next to the script as `RouteWard_TestReport_<yyyyMMdd_HHmmss>.txt`. It contains:
  1. Scenario summary and host/OS metadata.
  2. File sizes and versions of `routeward.exe`, `routeward-desktop.exe`, `WinDivert.dll`, and `WinDivert64.sys`.
  3. Audit notes (including the exact Named Pipe SDDL string).
  4. Raw `routeward ctl` and `routeward cleanup` outputs (with any password fields redacted).
  5. The last 30 lines of both the daemon log and the user log (with any password fields redacted).
