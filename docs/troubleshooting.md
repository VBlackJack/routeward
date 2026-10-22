# Troubleshooting

## 1. Antivirus and EDR Detection of WinDivert (`HackTool` / PUA Alert)

**Symptom**:
Endpoint Detection and Response (EDR) agents or antivirus software quarantine `WinDivert64.sys` / `WinDivert.dll` or raise a security alert classifying WinDivert as a `HackTool` or Potentially Unwanted Application (PUA).

**Cause**:
Although WinDivert is a legitimate open-source packet interception library, some security tools flag its kernel driver because third-party utilities and offensive tools also use it to inspect or modify traffic.

**Resolution**:
- **Never load `WinDivert64.sys` directly on a corporate workstation monitored by an enterprise SOC/EDR** without prior authorization.
- Perform all live packet interception testing inside an isolated virtual machine (for example Hyper-V).
- RouteWard isolates packet capture behind the `Interceptor` trait (`crates/routeward-core/src/interceptor/backend.rs`) so that an alternative backend (such as a custom Windows Filtering Platform callout driver) can replace WinDivert in enterprise environments.

## 2. `WinDivert.dll` Not Found When Running `routeward run`

**Symptom**:
`routeward run` exits with `errors.interceptor.driver_missing`.

**Resolution**:
WinDivert binaries are never committed to Git. Download and verify the official WinDivert 2.2.2-A binaries using the included PowerShell script:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fetch-windivert.ps1
```

This verifies the pinned SHA-256 (`63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`) and extracts `WinDivert.dll` and `WinDivert64.sys` into `third_party/windivert/bin/`.

## 3. `WinDivertOpen` Fails with Win32 Error 5 (`ERROR_ACCESS_DENIED`)

**Symptom**:
`routeward run` exits with `WinDivertOpen(SOCKET) failed with Win32 error 5`.

**Resolution**:
Loading and opening the WinDivert kernel filter requires **Administrator** privileges. Launch PowerShell as Administrator inside your test VM and run `routeward run --duration-secs 60`.

## 4. `routeward-desktop` Fails to Compile Because `ui/dist` Is Missing

**Symptom**:
Compiler error in `apps/desktop/src/main.rs` complaining that `../../../ui/dist/index.html` does not exist.

**Resolution**:
Build the frontend bundle before compiling `routeward-desktop`:

```powershell
Set-Location ui
npm install
npm run build
Set-Location ..
cargo build -p routeward-desktop
```
