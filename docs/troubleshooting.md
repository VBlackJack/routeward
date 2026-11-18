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

`WinDivert.dll` is only loaded from under the executable directory (the `windivertDllPaths` entries are resolved against it), so place it next to `routeward.exe` or under `third_party/windivert/bin/` there. The `ROUTEWARD_WINDIVERT_DLL_PATH` override is honoured by debug builds only; release builds ignore it.

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
- Or, with `securityPolicy.killSwitchEnabled = true`, the daemon crashed or was killed and the host failed closed: the nftables table `inet routeward_ks` drops all outgoing traffic except loopback, established connections, DHCP, IPv6 neighbour discovery and MLD. Check with `sudo nft list table inet routeward_ks`; systemd restarts the daemon after the crash (`Restart=on-failure`), but with interception stopped, so the block table stays in place. To lift it, run `sudo routeward cleanup --force`, start interception again with `routeward ctl start`, or restart the service cleanly with `sudo systemctl restart routeward`. On Windows a crash still fails open.

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
The `.msi` installer succeeded, but launching routing fails because `WinDivert.dll` is not present in the installation folder (release `.msi` packages bundle WinDivert 2.2.2; this happens with a locally built `.msi` made without `-IncludeWinDivert`, or after a manual removal of the files).

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
- **Basic credentials**: Basic credentials are no longer sent pre-emptively to a plaintext HTTP proxy. RouteWard first sends `CONNECT` without credentials and answers a `407` that offers `Basic` with them; over an `https` proxy node (TLS) they are still sent on the first request.
- **Self-signed inspection proxies**: Enable `tlsSkipVerify` on the `https` proxy node only when connecting to a trusted enterprise proxy whose root CA is not in the system trust store.

## 10. Named Profiles Permission Error (`profiles/` Directory)

**Symptom**:
Listing, saving, or switching named profiles fails when running with elevated privileges.

**Resolution**:
Verify that `%ProgramData%\RouteWard\profiles` (Windows) or `/etc/routeward/profiles` (Linux) is a regular directory rather than a symlink, and ensure its ownership and ACLs grant access only to the daemon account (`Administrators` / `SYSTEM` on Windows, `root` on Linux).

## 11. Windows UAC Service Start Fails Immediately (`insecure_profile` or Exit Code)

**Symptom**:
Clicking **Start Service** and accepting the Windows UAC prompt does not connect the daemon and shows an error toast or logs an early daemon exit in `%LOCALAPPDATA%\RouteWard\logs`.

**Resolution**:
1. Inspect `%LOCALAPPDATA%\RouteWard\logs` for the exact exit code returned by `routeward.exe daemon` (exit `10`: missing elevation, `11`: insecure `%ProgramData%\RouteWard` ownership or ACLs, `12`: local IPC bind error).
2. If exit `11` is reported because a pre-existing `C:\ProgramData\RouteWard\active_profile.json` or symlink/junction has non-admin permissions, run the following check in an elevated PowerShell prompt to verify ACLs and remove untrusted pre-existing state:

```powershell
icacls "C:\ProgramData\RouteWard"
```

## 12. Host Is a DNS Server

**Symptom**:
A DNS server running on the same machine (the Windows DNS Server role `dns.exe`, or `named`, `unbound`, `dnsmasq`, `pihole-FTL`, `pdns_recursor`, `kresd`, `dnsdist`, `coredns` on Linux) answers its own clients with `198.18.x.x` addresses, or caches them.

**Cause**:
A DNS server recurses to the Internet over port `53`. With Fake-IP on, RouteWard answers every port `53` query with a Fake-IP, so the server would cache and serve addresses that only exist inside RouteWard.

**Behavior**:
- **Exempt by default**: on Windows only `%SystemRoot%\System32\dns.exe` (a `dns.exe` anywhere else is not exempt); on Linux the executables `named`, `unbound`, `dnsmasq`, `pihole-FTL`, `pdns_recursor`, `kresd`, `dnsdist` and `coredns`, and only when the binary lives in `/usr/sbin`, `/usr/bin`, `/usr/local/sbin`, `/usr/local/bin` or `/usr/libexec`. `svchost.exe`, `systemd-resolved` and RouteWard itself can never be exempt.
- **What exempt means**: the queries of that process leave unmodified (no Fake-IP, no relay). The kill switch and `remoteDnsResolution` do not apply to them.
- **Explicit Block rule**: a Block rule whose `processPatterns` names the process still blocks its DNS queries. The default action and rules without a process pattern do not.
- **DoT**: port `853` stays blocked by `securityPolicy.blockEncryptedDnsBypass`, DNS servers included.
- **Local applications lose Fake-IP**: applications on that host query the local server over loopback, which RouteWard does not capture. They get real addresses, so a domain rule can only match through the TLS SNI or the HTTP `Host:` header.
- **Log**: each exempt process is logged once at `INFO` (`Exempting DNS server process <name> (PID <pid>) from Fake-IP`); each query is logged at `DEBUG`, and a rate-limited `INFO` line summarises the flow.

**Add or remove a process**:
Edit `dnsConfig.dnsServerProcesses` in the profile (omitted from the JSON when empty):

```json
"dnsConfig": {
  "dnsServerProcesses": ["C:\\Tools\\mydns.exe", "!dnsmasq"]
}
```

- A full path or a basename adds a process. On Linux a basename still only matches binaries in the system directories above; on Windows a basename-only entry matches any path.
- `!name` removes a built-in default. Use `!dnsmasq` on desktops where NetworkManager runs `dnsmasq` as a local cache (`dns=dnsmasq`): otherwise their own applications would stop getting Fake-IP.
- Empty entries, a bare `*`, and any pattern that would match `svchost.exe`, `systemd-resolved` or RouteWard are refused when the profile is loaded or replaced.
- A profile with a non-empty list is refused by older daemons (the field is unknown to them); an empty list is omitted and stays compatible.

**Linux limits**:
- The exemption works per user id, in `nftables` (sets `dns_server_uids` and `dns_server_block_uids`). A server running as `root` or `nobody`, or sharing its user id with another running process, is **not** exempt: RouteWard logs a warning once and leaves it redirected.
- Reading `/proc/<pid>/exe` of other users' processes needs `CAP_SYS_PTRACE`, which the shipped systemd unit grants. Without it a DNS server of another user is not recognised.
- In IPv6 guard mode (no IPv6 NAT), raw IPv6 port `53` is dropped, so an exempt server cannot recurse over IPv6 either.
- A Block rule on Linux acts on the whole user id: write it with `processPatterns` only (no port or address condition).

**Windows limits**:
- Only the System32 `dns.exe` is exempt by default. The process list is rescanned every `dns.dnsServerProcessScanIntervalMs` (5 s) and at every profile reload; a restarted `dns.exe` is also recognised at once from its first socket event.
