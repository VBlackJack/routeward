[Français](README.fr.md) | English

# RouteWard

Process-aware network routing and proxy chaining toolkit written in Rust, with a native desktop interface built on `tao` + `wry` (WebView2) and **ThemeForge**.

## License and Author

- **Author:** Julien Bombled
- **License:** Apache License, Version 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE))

## Current Capabilities and Status

- **Transparent OS Interception (`routeward-core::interceptor`)**: Captures outbound dual-stack **IPv4 and IPv6** TCP, UDP, and port `53` DNS traffic from unmodified applications via **WinDivert 2.2** on Windows and **`nftables` (`table ip` + `table ip6`) + `TPROXY`** on Linux, alongside explicit local SOCKS5 (`127.0.0.1:10808` / `[::1]:10808`) and HTTP CONNECT (`127.0.0.1:10809` / `[::1]:10809`) relay listeners.
- **Process Attribution (`routeward-core::process`)**: Maps active IPv4 and IPv6 TCP and UDP sockets to owning PIDs and executable paths using WinDivert `SOCKET` + Windows IP Helper (`GetExtendedTcpTable` / `GetExtendedUdpTable` for `AF_INET` and `AF_INET6`) and Linux **`NETLINK_SOCK_DIAG`** (`AF_INET` / `AF_INET6`) with `/proc/net/{tcp,udp,tcp6,udp6}` + `/proc/<pid>/exe` fallback.
- **Anti-Leak DNS Engine (`routeward-core::dns`)**: Allocates virtual RFC 2544 (`198.18.0.0/15`) Fake-IP addresses (including IPv6 DNS `A` synthesis + `AAAA` NODATA) or tunnels DNS-over-TCP through proxies, gates DoT port `853` via `blockEncryptedDnsBypass`, blocks Mozilla DoH canary domains, and selectively bypasses Active Directory and local/private zones.
- **Kill-Switch & Leak Guards (`routeward-core::interceptor`)**: Enforces fail-closed `Proxy`/`Chain` routing when `killSwitchEnabled = true`, rejects QUIC (`UDP 443`) by default, and guards against public-domain LLMNR (`5355`), mDNS (`5353`), and NetBIOS-NS (`137`) leaks.
- **SOCKS5 and HTTP CONNECT Proxy Chaining (`routeward-core::proxy`)**: Supports SOCKS5 (`CONNECT` and `UDP ASSOCIATE`, RFC 1928/1929) and HTTP/HTTPS `CONNECT`, with multi-hop sequence, failover, lowest-latency, and round-robin group strategies.
- **Priority Rule Engine (`routeward-core::rules`)**: Evaluates routing rules by executable wildcard, binary path, domain wildcard/regex (plus TLS `ClientHello` SNI inspection), IPv4/IPv6 CIDR subnet, port range, and protocol (`TCP`/`UDP`/`ANY`).
- **System Service & Packaging (`routeward service`, `packaging/`)**: Supports native Windows SCM service lifecycle (`install`, `uninstall`, `start`, `stop`, `status`) with `--allow-sid` Named Pipe SDDL scoping, Linux `systemd` (`routeward.service`), `.deb` / Windows ZIP builders, and `.github/workflows/release.yml`.
- **Daily Rolling File Logger (`routeward-core::logger`)**: Writes thread-safe logs to dedicated daemon/user OS log directories, toggleable at runtime via `enableLogging`.
- **ThemeForge Desktop UI (`apps/desktop` & `ui/`)**: Standalone `tao` + `wry` desktop window styled with the 16 canonical ThemeForge Oklab palettes + `HighContrast` and 9 accent tints.
- **Current Scope**: RouteWard provides dual-stack IPv4 and IPv6 transparent TCP, UDP (`TPROXY` / `WinDivert`), and port `53` DNS interception with Fake-IP, TLS SNI inspection, QUIC (`UDP 443`) rejection, configurable DoT (`853`) blocking + Mozilla DoH canary protection, Windows Service / Linux `systemd` packaging, and modular Rust desktop + React/Vitest UI components.

## Documentation

- [Architecture](docs/architecture.md) ([Français](docs/fr/architecture.md))
- [Build and Installation](docs/build.md) ([Français](docs/fr/build.md))
- [Maintenance](docs/maintenance.md) ([Français](docs/fr/maintenance.md))
- [Troubleshooting](docs/troubleshooting.md) ([Français](docs/fr/troubleshooting.md))
- [Windows Testing](docs/windows-testing.md) ([Français](docs/fr/windows-testing.md))
- [Contributing & Versioning](CONTRIBUTING.md) ([Français](CONTRIBUTING.fr.md))

## Branding Assets

Application icons and brand vectors live in [`assets/branding/`](assets/branding/):
- `routeward-icon.svg` and `routeward-glyph.svg` (Drakul vector masters)
- `routeward-16.png` through `routeward-512.png`, `routeward.ico` (embedded in Windows binaries via `embed-resource`), and `routeward-32.rgba` / `routeward-256.rgba` (used by `tao` for window and taskbar icons)
- `preview.html` (visual verification sheet of the rasterized PNGs on dark and light backgrounds)
- Regenerate all raster assets from `routeward-icon.svg` using headless Microsoft Edge and PowerShell: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\branding\build-icons.ps1`

## Build and Run

```powershell
# Build the frontend bundle first
Set-Location ui
npm run build
Set-Location ..

# Run Rust unit tests across the workspace
cargo test --workspace

# Evaluate a routing rule from the CLI
cargo run -p routeward-cli -- eval --process firefox.exe --host api.github.com --port 443

# Build the native desktop executable
cargo build -p routeward-desktop
```
