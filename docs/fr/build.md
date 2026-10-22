# Compilation et Installation

## Prerequis

- **Toolchain Rust** : Rust stable (`1.80+`, edition 2021) avec `cargo`, `rustfmt` et `clippy`.
  - `rust-toolchain.toml` utilise `channel = "stable"` afin d'assurer la compatibilite multi-plateforme (Windows et Linux).
  - **Cible Windows MSVC** : Sous Windows, utiliser la cible MSVC (`x86_64-pc-windows-msvc`). Si la toolchain par defaut du poste est `gnu`, definir MSVC par defaut (`rustup default stable-x86_64-pc-windows-msvc`) ou appeler Cargo avec `cargo +stable-x86_64-pc-windows-msvc`.
- **Node.js** : Node.js `20+` et `npm` (requis pour compiler le bundle `ui/dist` embarque par `routeward-desktop`).
- **Dependances systeme** :
  - **Windows** : Microsoft Edge WebView2 Runtime (inclus dans Windows 10/11) et outils de compilation C++ MSVC / Windows SDK.
  - **Linux** : `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev` et `pkg-config`.

## Etape 1 : Compiler le Bundle Frontend

`routeward-desktop` embarque `ui/dist/index.html`, `ui/dist/assets/app.js` et `ui/dist/assets/app.css` a la compilation via `include_bytes!`. Il faut donc compiler le frontend en premier :

```powershell
Set-Location ui
npm install
npm run build
Set-Location ..
```

## Etape 2 : Compiler le Workspace Rust

Compiler les binaires CLI et bureau depuis la racine du depot :

```powershell
cargo build --workspace --release
```

Binaires generes :
- Binaire CLI : `target/release/routeward` (ou `routeward.exe` sous Windows)
- Binaire Bureau : `target/release/routeward-desktop` (ou `routeward-desktop.exe` sous Windows)

## Etape 3 : Telecharger les Binaires WinDivert (Test en VM Windows uniquement)

Les binaires WinDivert ne sont pas versionnes dans Git. Dans la VM Windows de test, executer :

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fetch-windivert.ps1
```

Ce script telecharge `WinDivert-2.2.2-A.zip`, verifie son empreinte SHA-256 (`63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`) et extrait `WinDivert.dll` et `WinDivert64.sys` dans `third_party/windivert/bin/`.
