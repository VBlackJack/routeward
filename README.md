# RouteWard

Process-aware network routing and proxy chaining toolkit written in Rust, with a native desktop interface built on `tao` + `wry` (WebView2) and **ThemeForge**.

## License and Author

- **Author:** Julien Bombled
- **License:** Apache License, Version 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE))

## Current Capabilities

- **Process Attribution (`routeward-core::process`)**: Maps active TCP sockets to owning PIDs and executable paths using the Windows IP Helper API (`GetExtendedTcpTable`) and Linux `/proc/net/tcp` + `/proc/<pid>/exe`.
- **Fake-IP DNS Engine (`routeward-core::dns`)**: Allocates virtual RFC 2544 (`198.18.0.0/15`) addresses to domain queries in memory for reverse domain lookup during rule evaluation.
- **SOCKS5 and HTTP CONNECT Proxy Chaining (`routeward-core::proxy`)**: Supports SOCKS5 (`CONNECT` and `UDP ASSOCIATE`, RFC 1928/1929) and HTTP/HTTPS `CONNECT`, with multi-hop sequence, failover, lowest-latency, and round-robin group strategies.
- **Priority Rule Engine (`routeward-core::rules`)**: Evaluates routing rules by executable wildcard, binary path, domain wildcard/regex, IPv4/IPv6 CIDR subnet, port range, and protocol (`TCP`/`UDP`/`ANY`).
- **Daily Rolling File Logger (`routeward-core::logger`)**: Writes thread-safe logs to `logs/RouteWard_<yyyyMMdd>.log`, toggleable at runtime via `enableLogging`.
- **ThemeForge Desktop UI (`routeward-desktop` & `ui/`)**: Standalone `tao` + `wry` desktop window styled with the 16 canonical ThemeForge Oklab palettes + `HighContrast` and 9 accent tints.

## Build and Run

```powershell
# Run Rust unit tests across the workspace
cargo test

# Evaluate a routing rule from the CLI
cargo run -p routeward-cli -- eval --process firefox.exe --host api.github.com --port 443

# Build the frontend bundle and native desktop executable
cd ui
npm run build
cd ..
cargo build -p routeward-desktop
```
