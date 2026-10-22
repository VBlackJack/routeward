# Maintenance Guide

## Configuration Files (`configs/`)

All operational constants, default profiles, and color palettes live in `configs/`:

- `configs/system_constants.json`: Defines default loopback ports (`10808`, `10809`, `10853`), connection timeouts, Fake-IP subnet (`198.18.0.0/15`), log directory (`logs`), log application prefix (`RouteWard`), and built-in rule presets.
- `configs/default_profile.json`: Defines the initial routing profile, proxy nodes, chains, rules, and security flags (`enableLogging`, `blockUdpQuic`, `forceRemoteDns`).
- `configs/themeforge_palettes.json`: Contains the 16 canonical ThemeForge Oklab palettes (`Dracula`, `Drakul`, `Striga`, `Cinder`, `Bracken`, `Tarn`, `Mortis`, `Slate`, `Voivode`, `Carmilla`, `Whitby`, `Vesper`, `Parchment`, `Folio`, `Wormwood`, `Sconce`), `HighContrast`, and 9 accent tints.

Because `routeward-core` embeds these JSON files via `include_str!` for zero-dependency startup, recompile the Rust workspace after modifying any file under `configs/`.

## Internationalization (`locales/`)

- Translation catalogs are stored in `locales/en.json` and `locales/fr.json`.
- Keys follow the hierarchical `<module>.<component>.<element>.<action>` convention.
- Keep both files synchronized whenever adding or renaming keys, and use only ASCII punctuation (`-`, `:`, `"`, `'`, `...`).

## Logging (`logs/`)

- `FileLogger` (`crates/routeward-core/src/logger/mod.rs`) writes daily rolling log files to `logs/RouteWard_<yyyyMMdd>.log`.
- Format: `[yyyy-MM-dd HH:mm:ss] [LEVEL] [Component] message`.
- Logging is enabled by default (`enableLogging: true` in `ProfileConfig`) and can be toggled at runtime without restarting the application.
- The `logs/` directory is ignored by Git.

## Quality Checks

Run the full test and lint suite regularly:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
