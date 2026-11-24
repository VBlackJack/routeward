[Français](fr/build.md) | English

# Build and Installation

## Prerequisites

- **Rust Toolchain**: Stable Rust toolchain (see `rust-toolchain.toml`; edition 2021) with `cargo`, `rustfmt`, and `clippy`.
  - `rust-toolchain.toml` specifies `channel = "stable"` so the workspace builds cleanly on both Windows and Linux.
  - **Windows Target Requirement**: On Windows, use the MSVC toolchain (`x86_64-pc-windows-msvc`). If your host default toolchain is `gnu`, either set MSVC as default (`rustup default stable-x86_64-pc-windows-msvc`) or invoke Cargo with `cargo +stable-x86_64-pc-windows-msvc`.
- **Node.js**: Node.js `22.12+` (required by `ui/package.json` and Vite 8) and `npm` (required to build the `ui/dist` frontend bundle embedded by `routeward-desktop`).
- **Platform Dependencies**:
  - **Windows**: Microsoft Edge WebView2 Runtime (pre-installed on Windows 10/11) and Windows SDK / MSVC C++ build tools.
  - **Linux**: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, and `pkg-config`.

## Step 1: Build the Frontend Bundle

`routeward-desktop` embeds `ui/dist/index.html`, `ui/dist/assets/app.js`, `ui/dist/assets/app.css`, and the branding assets in `assets/branding/` (`routeward-glyph.svg`, `routeward-icon.svg`, `routeward-32.rgba`, `routeward-256.rgba`) at compile time using `include_bytes!`. On Windows, `build.rs` also embeds `assets/branding/routeward.ico` into `routeward.exe` and `routeward-desktop.exe` via `embed-resource`.

All generated branding assets in `assets/branding/` (`routeward-16.png` to `routeward-512.png`, `routeward.ico`, `routeward-32.rgba`, `routeward-256.rgba`) are committed so standard builds do not need to regenerate them. To regenerate them after editing `assets/branding/routeward-icon.svg`, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\branding\build-icons.ps1
```

Always build the frontend first:

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
# Or from a UTF-8 JSON file (recommended on Windows PowerShell 5.1, which strips inner double quotes from inline arguments passed to native executables):
./target/release/routeward ctl upsert-rule --json-file ./rule.json
./target/release/routeward ctl remove-rule --id rule-1
./target/release/routeward ctl stop

# Cleanup orphaned OS rules after a crash (refused while a daemon is active unless --force is passed):
sudo ./target/release/routeward cleanup
sudo ./target/release/routeward cleanup --force
```

### Windows Two-Step Launch (Named Pipe) & Desktop Tray Behavior
On Windows, you can start the daemon either in 1 click directly from the `routeward-desktop.exe` UI (**Start Service** button in the disconnected banner, which starts the registered `RouteWard` Windows Service via UAC or launches `routeward.exe daemon --locale <en|fr> --allow-sid <SID>` elevated), or manually in two terminals:

```powershell
# Step 1 - Elevated PowerShell (Administrator):
.\target\release\routeward.exe daemon

# Step 2 - Standard PowerShell (same user account, non-elevated):
.\target\release\routeward-desktop.exe
```

The daemon binds `\\.\pipe\routeward-daemon` with an explicit DACL restricting access to `SYSTEM`, `Administrators`, and the launching user's SID (plus any SIDs explicitly granted via `--allow-sid`). While the daemon is stopped, `routeward-desktop` displays a persistent disconnected banner with the Windows **Start Service** control and reconnects automatically as soon as the daemon starts. Closing the desktop window hides it into the Windows System Tray so interception status stays accessible; choose **Exit** in the tray menu to close the desktop app completely.

> **Important (Windows UAC Account Elevation):** When launched interactively via `routeward.exe daemon`, the daemon must run under the same user account that runs the desktop UI or `routeward ctl`, unless you pass `--allow-sid <SID>` explicitly.

### Windows Service Mode (SCM) & Packaging
The Windows service is the normal way to run RouteWard. With the MSI, nothing has to be registered by hand: the first time you click **Start** in the app or the tray, RouteWard installs the service (one Windows administrator prompt) and the service then starts automatically at boot. Protection is remembered: if it was on, it comes back on after a reboot, and a pause resumes by itself at its end, even after a reboot. RouteWard itself starts at sign-in with the tray icon only (minimized, no window).

Choosing **Exit** in the tray closes the desktop app only; the service keeps protecting in the background. To really stop, use **Pause** or turn protection off before exiting (see [Troubleshooting](troubleshooting.md)).

The MSI also adds a Start menu shortcut, **RouteWard - Restore Internet**, which runs `routeward recover --pause-at-end` without administrator rights: it turns protection off and restores the Windows proxy settings. From a terminal, `routeward recover` is the equivalent, and `routeward ctl pause --seconds N` pauses protection for `N` seconds.

For manual or scripted setups (ZIP, development), you can register RouteWard as a Windows Service under `LocalSystem` yourself while granting your desktop account SID access to the Named Pipe:

`install-service.ps1` first copies `routeward.exe`, `routeward-desktop.exe`, and any bundled WinDivert files from the (user-writable) extraction folder to `%ProgramFiles%\RouteWard` (override with `-InstallDir`) and registers the installed copy. `routeward.exe service install` itself refuses a service binary whose directory, or any parent directory, is writable by non-administrators, because the service runs as `LocalSystem`.

```powershell
# Register and start the Windows Service (Elevated PowerShell):
.\packaging\windows\install-service.ps1

# Or directly via the CLI:
.\target\release\routeward.exe service install --allow-current-user
.\target\release\routeward.exe service start
.\target\release\routeward.exe service status

# Remove the Windows Service:
.\target\release\routeward.exe service stop
.\target\release\routeward.exe service uninstall

# Package release binaries into a distributable ZIP + SHA-256 (`-IncludeWinDivert` bundles the staged WinDivert 2.2.2 files, as in release ZIPs):
.\packaging\windows\package-windows.ps1 -TargetDir target/release -OutDir dist -Arch x64

# Build the Windows MSI installer (requires WiX Toolset v6 `wix.exe`; `-IncludeWinDivert` bundles the staged WinDivert 2.2.2 files, as in release MSIs):
.\packaging\windows\build-msi.ps1 -TargetDir target/release -OutDir dist -Arch x64
```

Release `.msi` packages bundle WinDivert 2.2.2 (`WinDivert.dll` and `WinDivert64.sys`, unmodified, under the LGPLv3; notices in `THIRD_PARTY_NOTICES.txt`, WinDivert source archive attached to each release). An MSI upgrade re-registers the RouteWard service with its `--allow-sid` arguments (`routeward service restore`; automatic-start services are restarted, manual-start ones are registered stopped), and uninstalling removes the WinDivert driver service. The release ZIP bundles the same WinDivert files and notices next to the binaries, so it runs as is after extraction. Every ZIP also ships `fetch-windivert.ps1`, which extracts WinDivert into `third_party\windivert\bin` next to the binaries when a ZIP is built without `-IncludeWinDivert`.

#### Uninstalling the MSI (what is cleaned, what is not)
Before the files are removed, an uninstall (not an upgrade) runs two actions:

- `routeward cleanup --all-users` (as `LocalSystem`): for every user whose registry hive is **currently loaded** (every logged-on user), it gives back the system proxy, the PAC URL and the autostart entry that RouteWard changed, from that user's saved backup, and only while they are still RouteWard's. Hives of users who are not logged on are deliberately **not** loaded, so those users keep their values. To fix one by hand, turn the proxy off in *Settings > Network & Internet > Proxy* (or *Internet Options > Connections > LAN settings*), or run `routeward cleanup --user` as that user before uninstalling.
- `routeward purge-data`: deletes `%ProgramData%\RouteWard` (profile and logs) unless `KEEPDATA=1` was passed (`msiexec /x RouteWard.msi KEEPDATA=1`). It refuses a directory that a standard user could write to. Accepted limit: the data is deleted before the uninstall has finished, so an uninstall that fails or is rolled back afterwards leaves the data deleted.

The `LocalSystem` pass never writes inside a user profile: it only reads each user's saved settings through a verified handle (regular file at the expected place, owned by the user, SYSTEM or the Administrators) and, if that check fails, only switches off values equal to RouteWard's own. A desktop still running in another user's session at uninstall time may write its settings again after this pass; the desktop also restores them when it exits or when that user logs off.

### Linux `systemd` Unit & `.deb` Packaging
For headless Linux installations, use `packaging/linux/build-deb.sh` (or install `packaging/linux/routeward.service` alongside the `routeward` system group):

```bash
bash packaging/linux/build-deb.sh --target-dir target/release --out-dir dist
sudo apt install ./dist/routeward_*.deb
sudo systemctl enable --now routeward
```

The package also installs an applications-menu entry (`routeward-desktop.desktop`) and the `routeward` icon in the `hicolor` theme (16 to 512 px plus a scalable SVG). The release and CI jobs validate the entry with `desktop-file-validate`, and the release job fails if the entry or the icons are missing from the `.deb`.

The binaries link against the glibc of the machine that builds them. The published `.deb` is built on Ubuntu 22.04 (glibc 2.35), so it runs on Debian 12, Ubuntu 22.04 and newer; the release job fails if a binary needs a newer glibc symbol (`packaging/linux/check-glibc-floor.sh --max 2.35`). A package built on a newer distribution only runs on that glibc or a newer one.

### Log File Locations (Daemon vs Desktop / CLI)
Log files (`RouteWard_yyyyMMdd.log`) are resolved from fixed OS system paths rather than the process working directory (`CWD`):
- **Privileged Daemon (`routeward daemon`, `routeward run`, `routeward cleanup`)**:
  - **Windows**: `%ProgramData%\RouteWard\logs` (resolved via `SHGetKnownFolderPath(FOLDERID_ProgramData)`)
  - **Linux**: `/var/log/routeward`
- **Unprivileged Desktop Bridge & CLI (`routeward-desktop`, `routeward ctl`)**:
  - **Windows**: `%LOCALAPPDATA%\RouteWard\logs` (resolved via `SHGetKnownFolderPath(FOLDERID_LocalAppData)`)
  - **Linux**: `$XDG_STATE_HOME/routeward/logs` (or `~/.local/state/routeward/logs` when `XDG_STATE_HOME` is unset)
