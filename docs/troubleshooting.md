# Troubleshooting

## 1. `routeward-desktop` Fails to Compile Because `ui/dist` Is Missing

**Symptom**:
Compiler error in `apps/desktop/src/main.rs` complaining that `../../../ui/dist/index.html` or `../../../ui/dist/assets/app.js` does not exist.

**Resolution**:
Build the frontend bundle before compiling `routeward-desktop`:

```powershell
Set-Location ui
npm install
npm run build
Set-Location ..
cargo build -p routeward-desktop
```

## 2. Local Relay Port (`10808`, `10809`, or `10853`) Already in Use

**Symptom**:
The `Logs` view or `logs/RouteWard_<yyyyMMdd>.log` reports an `ADDRINUSE` error on `127.0.0.1:10808`, `127.0.0.1:10809`, or `127.0.0.1:10853`.

**Resolution**:
- Check if another instance of `routeward` or `routeward-desktop` is already running.
- Or update `defaultRelayTcpPort`, `defaultRelayHttpPort`, and `defaultDnsListenPort` in `configs/system_constants.json`.

## 3. Applications Ignore Routing Rules

**Symptom**:
A desktop application connects directly to the Internet without appearing in the local relay.

**Cause**:
Transparent OS-level packet interception (WinDivert / WFP on Windows, nftables / TUN on Linux) is not implemented yet (planned for Milestones 1 and 2).

**Current Workaround**:
- Use the **Run App via Proxy** launcher in the top bar to inject `ALL_PROXY`, `HTTP_PROXY`, and `HTTPS_PROXY` into the target process.
- Or enable **System Proxy** for applications that honor the Windows WinINet proxy configuration.

## 4. No Log Files Written Under `logs/`

**Symptom**:
The `logs/RouteWard_<yyyyMMdd>.log` file is not created or stops updating.

**Resolution**:
Verify that `enableLogging` is set to `true` in the active profile (`configs/default_profile.json`) and that the working directory is writable by the current user.
