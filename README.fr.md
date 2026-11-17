[English](README.md) | Français

# RouteWard

Outil de routage réseau par processus et de chaînage de proxies écrit en Rust, avec une interface bureau native basée sur `tao` + `wry` (WebView2) et **ThemeForge**.

## Licence et Auteur

- **Auteur :** Julien Bombled
- **Licence :** Apache License, Version 2.0 (voir [LICENSE](LICENSE) et [NOTICE](NOTICE))

## Fonctionnalités et État Actuel

- **Interception Transparente OS (`routeward-core::interceptor`)** : Capture le trafic sortant double pile **IPv4 et IPv6** TCP, UDP et DNS (port `53`) d'applications non modifiées via **WinDivert 2.2** sous Windows et **`nftables` (`table ip` + `table ip6`) + `TPROXY`** sous Linux, en plus des écouteurs locaux SOCKS5 (`127.0.0.1:10808` / `[::1]:10808`) et HTTP CONNECT (`127.0.0.1:10809` / `[::1]:10809`).
- **Attribution de Processus (`routeward-core::process`)** : Associe les sockets TCP et UDP IPv4/IPv6 actifs aux PID et chemins d'exécutables via la couche `SOCKET` WinDivert + l'API Windows IP Helper (`GetExtendedTcpTable` / `GetExtendedUdpTable` pour `AF_INET` et `AF_INET6`) et Linux **`NETLINK_SOCK_DIAG`** (`AF_INET` / `AF_INET6`) avec repli `/proc/net/{tcp,udp,tcp6,udp6}` + `/proc/<pid>/exe`.
- **Moteur DNS Anti-Fuite (`routeward-core::dns`)** : Alloue des adresses virtuelles RFC 2544 (`198.18.0.0/15`) Fake-IP (y compris réponses DNS IPv6 `A` + `AAAA` NODATA) ou transporte les requêtes DNS-over-TCP via le proxy, conditionne le port DoT `853` via `blockEncryptedDnsBypass`, bloque le canari DoH Mozilla et résout directement les zones locales et Active Directory.
- **Kill-Switch et Gardes Anti-Fuite (`routeward-core::interceptor`)** : Applique le blocage strict sur échec de proxy amont lorsque `killSwitchEnabled = true`, rejette QUIC (`UDP 443`) par défaut et bloque les fuites publiques LLMNR (`5355`), mDNS (`5353`) et NetBIOS-NS (`137`).
- **Chaînage de Proxies et Protocoles (`routeward-core::proxy`)** : Prend en charge **SOCKS4/SOCKS4a**, **SOCKS5** (`CONNECT` et `UDP ASSOCIATE`, RFC 1928/1929) et **HTTP / HTTPS** (`CONNECT` sur TLS avec option `tlsSkipVerify` et authentification d'entreprise Windows **SSPI `Negotiate`/`NTLM`**), avec stratégies multi-sauts, bascule (failover), latence minimale et répartition de charge.
- **Moteur de Règles par Priorité et Routage Navigateur/PAC (`routeward-core::rules`, `routeward-core::pac`)** : Évalue les règles selon le nom ou chemin d'exécutable (avec sélecteur visuel d'applications actives/installées), masque ou regex de domaine (syntaxe d'exclusion `!motif` sur processus, domaines et CIDR), inspection de l'en-tête HTTP `Host:` + TLS `ClientHello` SNI, sous-réseau CIDR IPv4/IPv6, plage de ports et protocole (`TCP`/`UDP`/`ANY`). Inclut un **importateur JSON FoxyProxy**, un serveur PAC local dynamique (`http://127.0.0.1:10811/proxy.pac`), l'activation PAC Windows (`AutoConfigURL`) et un préréglage Edge FoxyProxy sans aucune extension navigateur.
- **Services Système, Profils Nommés et Empaquetage (`routeward service`, `packaging/`)** : Gère le cycle de vie du service Windows SCM (`install`, `uninstall`, `start`, `stop`, `status`, `restore` après une mise à jour MSI) avec autorisation Named Pipe SDDL via `--allow-sid`, la gestion de profils nommés et bascule rapide, le démarrage automatique Windows à l'ouverture de session, l'unité Linux `systemd` (`routeward.service`), la génération `.deb` / ZIP Windows / **installateur Windows `.msi` WiX** (le MSI embarque WinDivert 2.2.2, pas le ZIP) et `.github/workflows/release.yml`.
- **Journalisation sur Fichier (`routeward-core::logger`)** : Écrit des journaux quotidiens thread-safe dans des dossiers système dédiés au daemon et à l'utilisateur, activables à chaud via `enableLogging`.
- **Interface Bureau ThemeForge (`apps/desktop` et `ui/`)** : Fenêtre native `tao` + `wry` intégrant les 16 palettes Oklab canoniques de ThemeForge + `HighContrast` et 9 teintes d'accent, structurée en 5 onglets par cas d'usage (`Accueil`, `Mes Apps & Sites`, `Mon Proxy`, `Activité`, `Réglages`) avec modes **Simple** et **Avancé (Expert)**, assistant guidé en 3 étapes, sélecteur d'applications système, modale d'import JSON FoxyProxy, diagnostic `errorDetail` + export CSV/JSON dans Activité, gestionnaire de profils nommés (y compris sous-menu dans le System Tray Windows), réduction en zone de notification et démarrage privilégié du service/daemon en 1 clic.
- **Périmètre Actuel** : RouteWard assure l'interception transparente double pile IPv4 et IPv6 TCP, UDP (`TPROXY` / `WinDivert`) et DNS port `53` avec Fake-IP, l'inspection TLS SNI + HTTP `Host:`, SOCKS4/SOCKS5/HTTP/HTTPS (+ Windows SSPI), PAC local + import FoxyProxy (`msedge.exe`), le rejet QUIC (`UDP 443`), le blocage configurable DoT (`853`) + protection canari DoH Mozilla, l'empaquetage `.msi` Windows / service Windows / Linux `systemd`, le System Tray Windows avec démarrage UAC en 1 clic et une architecture modulaire Rust bureau + interface React/Vitest à 5 onglets.

## Documentation

- [Architecture](docs/fr/architecture.md) ([English](docs/architecture.md))
- [Compilation et Installation](docs/fr/build.md) ([English](docs/build.md))
- [Maintenance](docs/fr/maintenance.md) ([English](docs/maintenance.md))
- [Dépannage](docs/fr/troubleshooting.md) ([English](docs/troubleshooting.md))
- [Tests Windows](docs/fr/windows-testing.md) ([English](docs/windows-testing.md))
- [Contribution et Versionnement](CONTRIBUTING.fr.md) ([English](CONTRIBUTING.md))

## Identité Visuelle et Icônes

Les fichiers de marque et icônes de l'application se trouvent dans [`assets/branding/`](assets/branding/) :
- `routeward-icon.svg` et `routeward-glyph.svg` (sources vectorielles Drakul)
- `routeward-16.png` à `routeward-512.png`, `routeward.ico` (embarqué dans les exécutables Windows via `embed-resource`), ainsi que `routeward-32.rgba` et `routeward-256.rgba` (utilisés par `tao` pour l'icône de fenêtre et de barre des tâches)
- `preview.html` (planche de contrôle visuel des PNG générés sur fonds sombre et clair)
- Régénérer tous les fichiers matriciels depuis `routeward-icon.svg` via Microsoft Edge headless et PowerShell : `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\branding\build-icons.ps1`

## Compilation et Exécution

```powershell
# Compiler d'abord le bundle frontend
Set-Location ui
npm run build
Set-Location ..

# Lancer les tests unitaires Rust
cargo test --workspace

# Évaluer une règle de routage en ligne de commande
cargo run -p routeward-cli -- eval --process firefox.exe --host api.github.com --port 443

# Compiler l'application bureau native
cargo build -p routeward-desktop
```
