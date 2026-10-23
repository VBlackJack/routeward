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

## Step 4: Two-Step Launch (Privileged Daemon + Unprivileged Desktop UI / CLI)

RouteWard separates privileged OS packet interception (`routeward daemon`) from the unprivileged desktop interface (`routeward-desktop`) and CLI controller (`routeward ctl`). When `routeward daemon` starts, it automatically cleans up any orphaned Windows firewall rule (`RouteWard_TransparentRelay_*`) or Linux `nftables` table (`table ip routeward`) left by a previous crash and logs the cleanup at `INFO` level.

### Linux Two-Step Launch (`routeward` Group)
On Linux, the daemon creates `/run/routeward/routeward.sock` owned by `root:routeward` (`0660` socket inside a `0750` directory). Create the `routeward` system group and add your unprivileged user account before starting the daemon:

```bash
sudo groupadd -r routeward
sudo usermod -aG routeward "$USER"
# Log out and back in (or run `newgrp routeward`) so group membership takes effect
```

Start the daemon as `root` (step 1), then launch the desktop UI or query the daemon as your unprivileged user (step 2):

```bash
# Step 1 - Terminal 1 (root):
sudo ./target/release/routeward daemon

# Step 2 - Terminal 2 (standard user in group 'routeward'):
./target/release/routeward-desktop
# Or control via CLI:
./target/release/routeward ctl status
./target/release/routeward ctl start
./target/release/routeward ctl connections
./target/release/routeward ctl upsert-rule --json '{"id":"rule-1","name":"Custom","enabled":true,"priority":5,"processPatterns":["curl"],"domainPatterns":[],"ipCidrs":[],"portRanges":[],"protocol":"tcp","action":{"type":"block"}}'
./target/release/routeward ctl remove-rule --id rule-1
./target/release/routeward ctl stop

# Cleanup orphaned OS rules after a crash (refused while a daemon is active unless --force is passed):
sudo ./target/release/routeward cleanup
sudo ./target/release/routeward cleanup --force
```

### Windows Two-Step Launch (Named Pipe)
On Windows, start `routeward.exe daemon` in an elevated Administrator PowerShell session (step 1), then launch `routeward-desktop.exe` or `routeward.exe ctl` in a standard non-elevated session under the same user account (step 2):

```powershell
# Step 1 - Elevated PowerShell (Administrator):
.\target\release\routeward.exe daemon

# Step 2 - Standard PowerShell (same user account, non-elevated):
.\target\release\routeward-desktop.exe
```

The daemon binds `\\.\pipe\routeward-daemon` with an explicit DACL restricting access to `SYSTEM`, `Administrators`, and the launching user's SID. If the daemon is stopped or not running yet, `routeward-desktop` displays a persistent disconnected banner and reconnects automatically as soon as the daemon starts.

> **Important (Windows UAC Account Elevation):** The daemon must be launched by the same user account that runs the desktop UI or `routeward ctl` (by elevating your own account via UAC). If you elevate using a different Administrator account (for example via "Run as different user" or a separate local admin credential), the Named Pipe DACL will grant read/write access to that other account's SID, and your standard user session will not be allowed to connect to `\\.\pipe\routeward-daemon`.

### Log File Locations (Daemon vs Desktop / CLI)
Log files (`RouteWard_yyyyMMdd.log`) are resolved from fixed OS system paths rather than the process working directory (`CWD`):
- **Privileged Daemon (`routeward daemon`, `routeward run`, `routeward cleanup`)**:
  - **Windows**: `%ProgramData%\RouteWard\logs` (resolved via `SHGetKnownFolderPath(FOLDERID_ProgramData)`)
  - **Linux**: `/var/log/routeward`
- **Unprivileged Desktop Bridge & CLI (`routeward-desktop`, `routeward ctl`)**:
  - **Windows**: `%LOCALAPPDATA%\RouteWard\logs` (resolved via `SHGetKnownFolderPath(FOLDERID_LocalAppData)`)
  - **Linux**: `$XDG_STATE_HOME/routeward/logs` (or `~/.local/state/routeward/logs` when `XDG_STATE_HOME` is unset)
