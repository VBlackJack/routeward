# Compilation et Installation

## Prerequis

- **Toolchain Rust** : Rust stable (`1.80+`, edition 2021) avec `cargo`, `rustfmt` et `clippy`.
- **Node.js** : Node.js `20+` et `npm` (requis pour compiler le bundle `ui/dist` embarque par `routeward-desktop`).
- **Dependances systeme** :
  - **Windows** : Microsoft Edge WebView2 Runtime (inclus dans Windows 10/11) et outils de compilation C++ du Windows SDK.
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

## Execution en Developpement

Tester l'evaluateur de regles en ligne de commande :

```powershell
cargo run -p routeward-cli -- eval --process firefox.exe --host api.github.com --port 443
```

Lancer la fenetre bureau native :

```powershell
cargo run -p routeward-desktop
```
