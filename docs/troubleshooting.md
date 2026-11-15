[Français](fr/troubleshooting.md) | English

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

## 7. `WinDivert.dll` Missing After Installing the Windows `.msi`

**Symptom**:
The `.msi` installer succeeded, but launching routing fails because `WinDivert.dll` is not present in the installation folder (typical when built without `-IncludeWinDivert`).

**Resolution**:
Run the bundled `fetch-windivert.ps1` script from an elevated PowerShell prompt to download and verify WinDivert directly into `C:\Program Files\RouteWard\`:

```powershell
& "C:\Program Files\RouteWard\fetch-windivert.ps1" -OutputDirectory "C:\Program Files\RouteWard"
```

## 8. Local PAC Server (`http://127.0.0.1:10811/proxy.pac`) or Edge Routing Issues

**Symptom**:
Microsoft Edge or WinINET applications still connect directly (or fail to fetch the PAC script) after enabling system PAC mode or importing FoxyProxy patterns.

**Resolution**:
1. Confirm the daemon is running so `http://127.0.0.1:10811/proxy.pac` returns HTTP `200`.
2. Ensure Windows `AutoConfigURL` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` uses the loopback `http://127.0.0.1:<port>/...` URL (RouteWard rejects non-loopback URLs).
3. Review `!` exclusion patterns (`preset-edge-foxyproxy` excludes `localhost`, `*.local`, `*.lan`, `*.internal`, and RFC1918 CIDRs) and rule priority order, or disable system PAC in Settings to clear `AutoConfigURL`.

## 9. Corporate HTTPS Proxy Failures (`407 Negotiate` / `NTLM` or Self-Signed CA)

**Symptom**:
Connections through an upstream `http` or `https` proxy fail with authentication errors (`407 Proxy Authentication Required`) or TLS certificate validation errors in Activity `errorDetail`.

**Resolution**:
- **Windows SSPI (`Negotiate` / `NTLM`)**: Leave username and password empty on the upstream node to authenticate with the active Windows session, or supply explicit credentials if basic authentication is required.
- **Self-signed inspection proxies**: Enable `tlsSkipVerify` on the `https` proxy node only when connecting to a trusted enterprise proxy whose root CA is not in the system trust store.

## 10. Named Profiles Permission Error (`profiles/` Directory)

**Symptom**:
Listing, saving, or switching named profiles fails when running with elevated privileges.

**Resolution**:
Verify that `%ProgramData%\RouteWard\profiles` (Windows) or `/etc/routeward/profiles` (Linux) is a regular directory rather than a symlink, and ensure its ownership and ACLs grant access only to the daemon account (`Administrators` / `SYSTEM` on Windows, `root` on Linux).
