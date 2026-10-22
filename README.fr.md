# RouteWard

Outil de routage reseau par processus et de chainage de proxies ecrit en Rust, avec une interface bureau native basee sur `tao` + `wry` (WebView2) et **ThemeForge**.

## Licence et Auteur

- **Auteur :** Julien Bombled
- **Licence :** Apache License, Version 2.0 (voir [LICENSE](LICENSE) et [NOTICE](NOTICE))

## Fonctionnalites et Etat Actuel

- **Attribution de processus (`routeward-core::process`)** : Associe les sockets TCP actifs aux PID et chemins d'executables via l'API Windows IP Helper (`GetExtendedTcpTable`) et Linux `/proc/net/tcp` + `/proc/<pid>/exe`.
- **Moteur DNS Fake-IP (`routeward-core::dns`)** : Alloue en memoire des adresses virtuelles RFC 2544 (`198.18.0.0/15`) aux noms de domaines pour permettre la resolution inverse lors de l'evaluation des regles.
- **Chainage de proxies SOCKS5 et HTTP CONNECT (`routeward-core::proxy`)** : Prend en charge SOCKS5 (`CONNECT` et `UDP ASSOCIATE`, RFC 1928/1929) et HTTP/HTTPS `CONNECT`, avec strategies multi-sauts, bascule (failover), latence minimale et repartition de charge.
- **Moteur de regles par priorite (`routeward-core::rules`)** : Evalue les regles selon le nom ou chemin d'executable, masque ou regex de domaine, sous-reseau CIDR IPv4/IPv6, plage de ports et protocole (`TCP`/`UDP`/`ANY`).
- **Journalisation sur fichier (`routeward-core::logger`)** : Ecrit des journaux quotidiens thread-safe dans `logs/RouteWard_<yyyyMMdd>.log`, activables ou desactivables a chaud via `enableLogging`.
- **Interface Bureau ThemeForge (`apps/desktop` et `ui/`)** : Fenetre native `tao` + `wry` integrant les 16 palettes Oklab canoniques de ThemeForge + `HighContrast` et 9 teintes d'accent.
- **Limitation actuelle** : L'interception transparente des paquets au niveau de l'OS (capture du trafic d'applications non modifiees sans configuration proxy) n'est pas encore implementee. Actuellement, les applications doivent passer par les ecouteurs locaux SOCKS5 (`127.0.0.1:10808`) ou HTTP CONNECT (`127.0.0.1:10809`).

## Documentation

- [Architecture](docs/fr/architecture.md) ([English](docs/architecture.md))
- [Compilation et Installation](docs/fr/build.md) ([English](docs/build.md))
- [Maintenance](docs/fr/maintenance.md) ([English](docs/maintenance.md))
- [Depannage](docs/fr/troubleshooting.md) ([English](docs/troubleshooting.md))
- [Contribution et Versionnement](CONTRIBUTING.fr.md) ([English](CONTRIBUTING.md))

## Compilation et Execution

```powershell
# Compiler d'abord le bundle frontend
Set-Location ui
npm run build
Set-Location ..

# Lancer les tests unitaires Rust
cargo test --workspace

# Evaluer une regle de routage en ligne de commande
cargo run -p routeward-cli -- eval --process firefox.exe --host api.github.com --port 443

# Compiler l'application bureau native
cargo build -p routeward-desktop
```
