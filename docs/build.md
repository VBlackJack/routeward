# Build and Installation

## Prerequisites

- **Rust Toolchain**: Stable Rust (`1.80+`, edition 2021) with `cargo`, `rustfmt`, and `clippy`.
  - `rust-toolchain.toml` specifies `channel = "stable"` so the workspace builds cleanly on both Windows and Linux.
  - **Windows Target Requirement**: On Windows, use the MSVC toolchain (`x86_64-pc-windows-msvc`). If your host default toolchain is `gnu`, either set MSVC as default (`rustup default stable-x86_64-pc-windows-msvc`) or invoke Cargo with `cargo +stable-x86_64-pc-windows-msvc`.
- **Node.js**: Node.js `20+` and `npm` (required to build the `ui/dist` frontend bundle embedded by `routeward-desktop`).
- **Platform Dependencies**:
  - **Windows**: Microsoft Edge WebView2 Runtime (pre-installed on Windows 10/11) and Windows SDK / MSVC C++ build tools.
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

## Step 4: Running the Privileged Daemon and Unprivileged Clients (`routeward daemon` & `routeward ctl`)

### Linux Group Setup (`routeward`)
On Linux, the daemon creates `/run/routeward/routeward.sock` owned by `root:routeward` (`0660` socket inside a `0750` directory). Create the `routeward` system group and add your unprivileged user account before starting the daemon:

```bash
sudo groupadd -r routeward
sudo usermod -aG routeward "$USER"
# Log out and back in (or run `newgrp routeward`) so group membership takes effect
```

Start the daemon as `root`, then query or control it as your unprivileged user:

```bash
# Terminal 1 (root):
sudo ./target/release/routeward daemon

# Terminal 2 (member of group 'routeward'):
./target/release/routeward ctl status
./target/release/routeward ctl start
./target/release/routeward ctl connections
./target/release/routeward ctl stop
```

### Windows Setup (Named Pipe)
On Windows, launch `routeward.exe daemon` from an elevated Administrator PowerShell session. The daemon binds `\\.\pipe\routeward-daemon` with an explicit DACL restricting access to `SYSTEM`, `Administrators`, and the launching user's SID. You can then run `routeward.exe ctl status` or `routeward-desktop.exe` from an unprivileged session under the same user account.
