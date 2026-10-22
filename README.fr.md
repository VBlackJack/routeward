# RouteWard

Outil de routage réseau par processus et de chaînage de proxies écrit en Rust, avec une interface bureau native basée sur `tao` + `wry` (WebView2) et **ThemeForge**.

## Licence et Auteur

- **Auteur :** Julien Bombled
- **Licence :** Apache License, Version 2.0 (voir [LICENSE](LICENSE) et [NOTICE](NOTICE))

## Fonctionnalités actuelles

- **Attribution de processus (`routeward-core::process`)** : Associe les sockets TCP actifs aux PID et chemins d'exécutables via l'API Windows IP Helper (`GetExtendedTcpTable`) et Linux `/proc/net/tcp` + `/proc/<pid>/exe`.
- **Moteur DNS Fake-IP (`routeward-core::dns`)** : Alloue en mémoire des adresses virtuelles RFC 2544 (`198.18.0.0/15`) aux noms de domaines pour permettre la résolution inverse lors de l'évaluation des règles.
- **Chaînage de proxies SOCKS5 et HTTP CONNECT (`routeward-core::proxy`)** : Prend en charge SOCKS5 (`CONNECT` et `UDP ASSOCIATE`, RFC 1928/1929) et HTTP/HTTPS `CONNECT`, avec stratégies multi-sauts, bascule (failover), latence minimale et répartition de charge.
- **Moteur de règles par priorité (`routeward-core::rules`)** : Évalue les règles selon le nom ou chemin d'exécutable, masque ou regex de domaine, sous-réseau CIDR IPv4/IPv6, plage de ports et protocole (`TCP`/`UDP`/`ANY`).
- **Journalisation sur fichier (`routeward-core::logger`)** : Écrit des journaux quotidiens thread-safe dans `logs/RouteWard_<yyyyMMdd>.log`, activables ou désactivables à chaud via `enableLogging`.
- **Interface Bureau ThemeForge (`routeward-desktop` et `ui/`)** : Fenêtre native `tao` + `wry` intégrant les 16 palettes Oklab canoniques de ThemeForge + `HighContrast` et 9 teintes d'accent.

## Compilation et exécution

```powershell
# Lancer les tests unitaires Rust
cargo test

# Évaluer une règle de routage en ligne de commande
cargo run -p routeward-cli -- eval --process firefox.exe --host api.github.com --port 443

# Compiler le bundle UI et l'application bureau native
cd ui
npm run build
cd ..
cargo build -p routeward-desktop
```
