# RouteWard

Process-aware network routing and proxy chaining toolkit written in Rust, with a native desktop interface built on `tao` + `wry` (WebView2) and **ThemeForge**.

## License and Author

- **Author:** Julien Bombled
- **License:** Apache License, Version 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE))

## Current Capabilities and Status

- **Process Attribution (`routeward-core::process`)**: Maps active TCP sockets to owning PIDs and executable paths using the Windows IP Helper API (`GetExtendedTcpTable`) and Linux `/proc/net/tcp` + `/proc/<pid>/exe`.
- **Fake-IP DNS Engine (`routeward-core::dns`)**: Allocates virtual RFC 2544 (`198.18.0.0/15`) addresses to domain queries in memory for reverse domain lookup during rule evaluation.
- **SOCKS5 and HTTP CONNECT Proxy Chaining (`routeward-core::proxy`)**: Supports SOCKS5 (`CONNECT` and `UDP ASSOCIATE`, RFC 1928/1929) and HTTP/HTTPS `CONNECT`, with multi-hop sequence, failover, lowest-latency, and round-robin group strategies.
- **Priority Rule Engine (`routeward-core::rules`)**: Evaluates routing rules by executable wildcard, binary path, domain wildcard/regex, IPv4/IPv6 CIDR subnet, port range, and protocol (`TCP`/`UDP`/`ANY`).
- **Daily Rolling File Logger (`routeward-core::logger`)**: Writes thread-safe logs to `logs/RouteWard_<yyyyMMdd>.log`, toggleable at runtime via `enableLogging`.
- **ThemeForge Desktop UI (`apps/desktop` & `ui/`)**: Standalone `tao` + `wry` desktop window styled with the 16 canonical ThemeForge Oklab palettes + `HighContrast` and 9 accent tints.
- **Current Limitation**: Transparent OS-level packet interception (capturing traffic from unmodified applications without proxy settings) is not implemented yet. Currently, applications must connect through the local SOCKS5 (`127.0.0.1:10808`) or HTTP CONNECT (`127.0.0.1:10809`) relay listeners.

## Documentation

- [Architecture](docs/architecture.md) ([Francais](docs/fr/architecture.md))
- [Build and Installation](docs/build.md) ([Francais](docs/fr/build.md))
- [Maintenance](docs/maintenance.md) ([Francais](docs/fr/maintenance.md))
- [Troubleshooting](docs/troubleshooting.md) ([Francais](docs/fr/troubleshooting.md))
- [Contributing & Versioning](CONTRIBUTING.md) ([Francais](CONTRIBUTING.fr.md))

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
