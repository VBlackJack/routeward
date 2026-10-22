# Guide de Maintenance

## Fichiers de Configuration (`configs/`)

Toutes les constantes operationnelles, le profil par defaut et les palettes de couleurs se trouvent dans `configs/` :

- `configs/system_constants.json` : Definit les ports locaux par defaut (`10808`, `10809`, `10853`), les delais d'attente, le sous-reseau Fake-IP (`198.18.0.0/15`), le dossier de journaux (`logs`), le prefixe de fichier (`RouteWard`) et les modeles de regles.
- `configs/default_profile.json` : Definit le profil de routage initial, les serveurs proxies, les chaines, les regles et les options (`enableLogging`, `blockUdpQuic`, `forceRemoteDns`).
- `configs/themeforge_palettes.json` : Contient les 16 palettes Oklab canoniques de ThemeForge (`Dracula`, `Drakul`, `Striga`, `Cinder`, `Bracken`, `Tarn`, `Mortis`, `Slate`, `Voivode`, `Carmilla`, `Whitby`, `Vesper`, `Parchment`, `Folio`, `Wormwood`, `Sconce`), `HighContrast` et les 9 teintes d'accent.

Comme `routeward-core` embarque ces fichiers JSON via `include_str!`, il faut recompiler le workspace Rust apres toute modification dans `configs/`.

## Internationalisation (`locales/`)

- Les dictionnaires de traduction se trouvent dans `locales/fr.json` et `locales/en.json`.
- Les cles respectent la convention `<module>.<composant>.<element>.<action>`.
- Maintenir les deux fichiers synchronises lors de tout ajout de cle et utiliser exclusivement la ponctuation ASCII (`-`, `:`, `"`, `'`, `...`).

## Journalisation (`logs/`)

- `FileLogger` (`crates/routeward-core/src/logger/mod.rs`) ecrit un fichier quotidien dans `logs/RouteWard_<yyyyMMdd>.log`.
- Format : `[yyyy-MM-dd HH:mm:ss] [LEVEL] [Component] message`.
- La journalisation est activee par defaut (`enableLogging: true` dans `ProfileConfig`) et peut etre activee ou desactivee a chaud sans redemarrer l'application.
- Le dossier `logs/` est ignore par Git.

## Verifications de Qualite

Executer regulierement la suite de formatage, d'analyse statique et de tests :

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
