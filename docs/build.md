# Build and Installation

## Prerequisites

- **Rust Toolchain**: Stable Rust (`1.80+`, edition 2021) with `cargo`, `rustfmt`, and `clippy`.
- **Node.js**: Node.js `20+` and `npm` (required to build the `ui/dist` frontend bundle embedded by `routeward-desktop`).
- **Platform Dependencies**:
  - **Windows**: Microsoft Edge WebView2 Runtime (pre-installed on Windows 10/11) and Windows SDK build tools.
  - **Linux**: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, and `pkg-config`.

## Step 1: Build the Frontend Bundle

`routeward-desktop` embeds `ui/dist/index.html`, `ui/dist/assets/app.js`, and `ui/dist/assets/app.css` at compile time using `include_bytes!`. Always build the frontend first:

```powershell
Set-Location ui
npm install
npm run build
Set-Location ..
```

## Step 2: Build the Rust Workspace

Compile the CLI and desktop binaries from the repository root:

```powershell
cargo build --workspace --release
```

Generated binaries:
- CLI binary: `target/release/routeward` (or `routeward.exe` on Windows)
- Desktop binary: `target/release/routeward-desktop` (or `routeward-desktop.exe` on Windows)

## Step 3: Fetch WinDivert Runtime Binaries (Windows VM Testing Only)

WinDivert binaries are not committed to the repository. Inside your isolated Windows test VM, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fetch-windivert.ps1
```

This downloads `WinDivert-2.2.2-A.zip`, verifies its SHA-256 (`63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`), and extracts `WinDivert.dll` and `WinDivert64.sys` into `third_party/windivert/bin/`.
