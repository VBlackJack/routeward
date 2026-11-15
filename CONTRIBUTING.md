[Français](CONTRIBUTING.fr.md) | English

# Contributing to RouteWard

## License and Copyright

All contributions are licensed under the Apache License, Version 2.0. Every new source file must begin with the standard Apache 2.0 header:

```text
Copyright 2026 Julien Bombled
```

## Versioning Rule (CalVer)

RouteWard uses Calendar Versioning (CalVer):

- **Release and Git tag format**: `vYYYY.MMDD.NN` (for example, `v2026.0105.00` for the first build on January 5, 2026, or `v2026.1022.00` for October 22, 2026).
- **Manifest format (`Cargo.toml` and `ui/package.json`)**: Because Cargo and npm strictly enforce SemVer numeric rules and reject leading zeros in version components, manifest files strip leading zeros from `MMDD` and `NN`:
  - Format: `YYYY.<MMDD as integer>.<NN as integer>`
  - Example for `2026-01-05` build `00`: `2026.105.0`
  - Example for `2026-10-22` build `00`: `2026.1022.0`

## Code Quality and Hygiene

- **Language**: All source code, comments, identifiers, docstrings, and commit messages must be written in English.
- **Zero Hardcoding**:
  - User-facing strings must be stored in `locales/en.json` and `locales/fr.json` and resolved via i18n keys.
  - Network timeouts, ports, buffer sizes, and default parameters must reside in `configs/system_constants.json` or dedicated configuration modules.
- **ASCII Punctuation**: Use ASCII punctuation (`-`, `:`, `"`, `'`, `...`) across all code, configuration, localization, and documentation files.
- **Conventional Commits**: Use Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).

## Pre-Commit Verification

Run the following checks from the repository root before committing:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

And from the `ui/` directory:

```powershell
npm run build
```
