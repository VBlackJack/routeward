# Troubleshooting

## 1. Windows Firewall and Reflected Inbound Packets (`TCP 10810`)

**Symptom**:
Intercepted `curl.exe` connections time out after ~63 seconds if Windows Defender Firewall blocks inbound TCP traffic on port `10810`.

**Cause**:
The WinDivert `streamdump` reflection technique rewrites outbound client packets into inbound packets (`Outbound = 0`) addressed to the local transparent TCP relay (`0.0.0.0:10810`). Because Windows evaluates inbound firewall filters on reinjected inbound packets, Windows Firewall must allow inbound TCP traffic to the RouteWard executable on port `10810`.

**Automatic Handling and Manual Cleanup**:
- On startup, `WinDivertInterceptor` automatically creates a scoped inbound rule (`RouteWard_TransparentRelay_10810`, restricted to the `routeward.exe` executable path, `protocol=TCP`, `localport=10810`, `profile=any`) and removes it on clean exit (`Ctrl+C` or `--duration-secs`), logging both actions under `[WindowsFirewall]`.
- If the process was forcefully terminated before cleanup, run `routeward cleanup` or remove the rule manually in an Administrator PowerShell:

```powershell
routeward cleanup
# or directly:
netsh advfirewall firewall delete rule name="RouteWard_TransparentRelay_10810"
```

## 2. Antivirus and EDR Detection of WinDivert (`HackTool` / PUA Alert)

**Symptom**:
Endpoint Detection and Response (EDR) agents or antivirus software quarantine `WinDivert64.sys` / `WinDivert.dll` or raise a security alert classifying WinDivert as a `HackTool` or Potentially Unwanted Application (PUA).

**Cause**:
Although WinDivert is a legitimate open-source packet interception library, some security tools flag its kernel driver because third-party utilities and offensive tools also use it to inspect or modify traffic.

**Resolution**:
- **Never load `WinDivert64.sys` directly on a corporate workstation monitored by an enterprise SOC/EDR** without prior authorization.
- Perform all live packet interception testing inside an isolated virtual machine (for example Hyper-V or VMware).
- RouteWard isolates packet capture behind the `Interceptor` trait (`crates/routeward-core/src/interceptor/backend.rs`) so that an alternative backend (such as a custom Windows Filtering Platform callout driver) can replace WinDivert in enterprise environments.

## 3. `WinDivert.dll` Not Found When Running `routeward run`

**Symptom**:
`routeward run` exits with `errors.interceptor.driver_missing`.

**Resolution**:
WinDivert binaries are never committed to Git. Download and verify the official WinDivert 2.2.2-A binaries using the included PowerShell script:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fetch-windivert.ps1
```

## 4. `WinDivertOpen` Fails with Win32 Error 5 (`ERROR_ACCESS_DENIED`)

**Symptom**:
`routeward run` exits with `WinDivertOpen(SOCKET) failed with Win32 error 5`.

**Resolution**:
Loading and opening the WinDivert kernel filter requires **Administrator** privileges. Launch PowerShell as Administrator inside your test VM and run `routeward run --duration-secs 60`.

## 5. Linux `nftables` Interception and Orphaned Table Cleanup (`table ip routeward`)

**Symptom**:
- `routeward run` exits with `errors.interceptor.not_root` or `errors.interceptor.nft_missing`.
- Or, if both `routeward` and its pipe-linked fail-open watchdog were killed simultaneously, outbound IPv4 TCP traffic remains redirected to `:10810` and fails to connect.

**Resolution**:
- Ensure `routeward` is executed as `root` (`sudo routeward run`) and that the `nftables` package (`nft` binary) is installed.
- To remove an orphaned `table ip routeward` ruleset at any time, run:

```bash
sudo routeward cleanup
# or directly:
sudo nft delete table ip routeward
```

## 6. `routeward-desktop` Fails to Compile Because `ui/dist` Is Missing

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
