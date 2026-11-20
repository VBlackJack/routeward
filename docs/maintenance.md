[Français](fr/maintenance.md) | English

# Maintenance Guide

## Configuration Files (`configs/`)

All operational constants, default profiles, and color palettes live in `configs/`:

- `configs/system_constants.json`: Defines default local ports (`10808`, `10809`, `10810`, `10811` for the local PAC server `defaultPacPort`, `10853`, `10854`), HTTP `Host:` inspection (`httpHostInspectPorts`: `[80, 8080, 8000, 8888]`, `httpHostPeekTimeoutMs`: `200`, `httpHostMaxBytes`: `4096`), Linux `nftables` / `TPROXY` settings (`linuxFwmark`: `21079` / `0x5257`, `linuxTproxyFwmark`: `21080`, `linuxTproxyRouteTable`: `100`, `linuxTproxyRulePriority`: `10810`, `linuxNftBinary`: `"nft"`, `linuxNftTableName`: `"routeward"`, `linuxNftChainName`: `"output"`), connection timeouts (`pendingSynTimeoutMs`: `40`, `pendingUdpTimeoutMs`: `40`), Fake-IP subnet (`198.18.0.0/15`), log paths (`telemetry.windowsDaemonLogDir`, `telemetry.linuxDaemonLogDir`, `telemetry.windowsUserLogDir`, `telemetry.linuxUserLogDir`), log application prefix (`RouteWard`), telemetry broadcast capacity (`eventBroadcastCapacity`: `256`), protected active and named profile storage (`ipc.windowsProfilePath`: `"%ProgramData%\\RouteWard\\active_profile.json"`, `ipc.linuxProfilePath`: `"/etc/routeward/active_profile.json"`, with named profiles stored in the sibling `profiles/` directory), and built-in rule presets (including `preset-edge-foxyproxy`).
  - Runtime tuning constants: `telemetry.udpFlowIdleTimeoutMs` (idle time before a UDP flow is closed in the connection list), `telemetry.telemetryUpdateIntervalMs` (throttle of live connection updates), `network.socketPidCacheTtlMs` (SOCKET-layer PID cache lifetime), `network.maxPendingSynPackets` (bound of the pending SYN queue), `network.natHalfOpenSessionTtlSecs` and `network.natSessionSweepIntervalMs` (expiry and sweep of half-open NAT sessions), `network.udpFragmentVerdictTtlMs` and `network.maxUdpFragmentVerdicts` (remembered verdict for UDP fragments), `network.sessionCloseGraceMs` (delay before a closed NAT session is removed), `network.conntrackCacheTtlMs` (Linux conntrack lookup cache), `dns.fakeIpRealResolutionTtlSecs` (cache of real resolutions of Fake-IP domains), `dns.systemResolversCacheTtlMs` (cache of the system resolver list), `dns.defaultDnsServerProcesses` (built-in DNS server processes that always get real DNS answers: `%SystemRoot%\System32\dns.exe` on Windows, `named`, `unbound`, `dnsmasq`, `pihole-FTL`, `pdns_recursor`, `kresd`, `dnsdist`, `coredns` on Linux; a profile adds entries or removes one with `!name` in `dnsConfig.dnsServerProcesses`), and `dns.dnsServerProcessScanIntervalMs` (`5000`, rescan period of the running DNS server processes).
- `configs/default_profile.json`: Defines the initial routing profile, proxy nodes, chains, rules, `dnsConfig` (`enableFakeIp`, `remoteDnsResolution`, `fakeIpCidr`, `upstreamDns`, `bypassDomains`, optional `dnsServerProcesses`), and `securityPolicy` (`killSwitchEnabled`, `blockUdpOnTcpOnlyProxy`, `blockQuicUdp443`, `strictDnsNoLocalFallback`, `blockEncryptedDnsBypass`, `unknownProcessAction`).
- `configs/themeforge_palettes.json`: Contains the 16 canonical ThemeForge Oklab palettes (`Dracula`, `Drakul`, `Striga`, `Cinder`, `Bracken`, `Tarn`, `Mortis`, `Slate`, `Voivode`, `Carmilla`, `Whitby`, `Vesper`, `Parchment`, `Folio`, `Wormwood`, `Sconce`), `HighContrast`, and 9 accent tints.

Because `routeward-core` embeds these JSON files via `include_str!` for zero-dependency startup, recompile the Rust workspace after modifying any file under `configs/`.

## Internationalization (`locales/`)

- Translation catalogs are stored in `locales/en.json` and `locales/fr.json`.
- Keys follow the hierarchical `<module>.<component>.<element>.<action>` convention.
- Keep both files synchronized whenever adding or renaming keys, and use only ASCII punctuation (`-`, `:`, `"`, `'`, `...`).

## Logging (`logs/`)

- `FileLogger` (`crates/routeward-core/src/logger/mod.rs`) writes daily rolling log files (`RouteWard_<yyyyMMdd>.log`) to OS-specific daemon/user log directories (`%ProgramData%\RouteWard\logs` and `%LOCALAPPDATA%\RouteWard\logs` on Windows; `/var/log/routeward` and `$XDG_STATE_HOME/routeward/logs` on Linux).
- Format: `[yyyy-MM-dd HH:mm:ss] [LEVEL] [Component] message` (local timezone).
- Logging is enabled by default (`enableLogging: true` in `ProfileConfig`) and can be toggled at runtime without restarting the application.
- Local `logs/` directories in the repository are ignored by Git.

## Quality Checks

Run the full test and lint suite regularly:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
Set-Location ui
npm test
npm run build
Set-Location ..
```
