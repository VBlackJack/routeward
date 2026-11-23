[English](README.md) | Français

# RouteWard

Outil de routage réseau par processus et de chaînage de proxies écrit en Rust, avec une interface bureau native basée sur `tao` + `wry` (WebView2) et **ThemeForge**.

## Premiers Pas (Aucune Connaissance Réseau Requise)

Un **proxy** est un serveur intermédiaire sur Internet : vos applications lui parlent, et il parle aux sites web à leur place, donc les sites voient l'adresse du proxy et non la vôtre. RouteWard décide, application par application, ce qui passe par lui.

1. Installez RouteWard avec le programme d'installation `.msi`.
2. Ouvrez **RouteWard** depuis le menu Démarrer.
3. Suivez l'assistant de configuration : collez le lien du proxy qui vous a été donné, ou choisissez **Pas de proxy** si vous n'en avez pas.
4. Cliquez sur **Démarrer** (la première fois, Windows demande une seule fois l'accord d'un administrateur, pour installer le service d'arrière-plan), puis cochez **Vérifier ma protection**.

La protection démarre toute seule à chaque démarrage et est mémorisée après un redémarrage. Fermer la fenêtre garde RouteWard dans la zone de notification. Si vous perdez un jour votre connexion Internet, utilisez le raccourci du menu Démarrer **RouteWard - Restore Internet** ou suivez le [Dépannage, section 0](docs/fr/troubleshooting.md#0-je-nai-plus-internet).

Si une application ou un site cesse de fonctionner, ouvrez **Activité**, puis **Bloqué** : RouteWard liste ce qu'il a arrêté, explique pourquoi en mots simples, et vous laisse le débloquer avec un bouton Annuler (voir le [Dépannage, section 16](docs/fr/troubleshooting.md#16-ce-qui-est-bloque-pourquoi-et-comment-le-debloquer)).

## Licence et Auteur

- **Auteur :** Julien Bombled
- **Licence :** Apache License, Version 2.0 (voir [LICENSE](LICENSE) et [NOTICE](NOTICE))

## Aperçu Technique : Fonctionnalités et État Actuel (pour les Lecteurs Techniques)

> Tout ce qui suit s'adresse aux lecteurs techniques. Pour simplement utiliser RouteWard, la section ci-dessus et le [guide de dépannage](docs/fr/troubleshooting.md) suffisent.

- **Interception Transparente OS (`routeward-core::interceptor`)** : Capture le trafic sortant double pile **IPv4 et IPv6** TCP, UDP et DNS (port `53`) d'applications non modifiées via **WinDivert 2.2** sous Windows et **`nftables` (`table ip` + `table ip6`) + `TPROXY`** sous Linux, en plus des écouteurs locaux SOCKS5 (`127.0.0.1:10808` / `[::1]:10808`) et HTTP CONNECT (`127.0.0.1:10809` / `[::1]:10809`).
- **Attribution de Processus (`routeward-core::process`)** : Associe les sockets TCP et UDP IPv4/IPv6 actifs aux PID et chemins d'exécutables via la couche `SOCKET` WinDivert + l'API Windows IP Helper (`GetExtendedTcpTable` / `GetExtendedUdpTable` pour `AF_INET` et `AF_INET6`) et Linux **`NETLINK_SOCK_DIAG`** (`AF_INET` / `AF_INET6`) avec repli `/proc/net/{tcp,udp,tcp6,udp6}` + `/proc/<pid>/exe`.
- **Moteur DNS Anti-Fuite (`routeward-core::dns`)** : Alloue des adresses virtuelles RFC 2544 (`198.18.0.0/15`) Fake-IP (y compris réponses DNS IPv6 `A` + `AAAA` NODATA) ou transporte les requêtes DNS-over-TCP via le proxy, conditionne le port DoT `853` via `blockEncryptedDnsBypass`, bloque le canari DoH Mozilla et résout directement les zones locales et Active Directory.
- **Kill-Switch et Gardes Anti-Fuite (`routeward-core::interceptor`)** : Applique le blocage strict sur échec de proxy amont lorsque `killSwitchEnabled = true`, rejette QUIC (`UDP 443`) par défaut et bloque les fuites publiques LLMNR (`5355`), mDNS (`5353`) et NetBIOS-NS (`137`).
- **Chaînage de Proxies et Protocoles (`routeward-core::proxy`)** : Prend en charge **SOCKS4/SOCKS4a**, **SOCKS5** (`CONNECT` et `UDP ASSOCIATE`, RFC 1928/1929) et **HTTP / HTTPS** (`CONNECT` sur TLS avec option `tlsSkipVerify` et authentification d'entreprise Windows **SSPI `Negotiate`/`NTLM`**), avec stratégies multi-sauts, bascule (failover), latence minimale et répartition de charge.
- **Moteur de Règles par Priorité et Routage Navigateur/PAC (`routeward-core::rules`, `routeward-core::pac`)** : Évalue les règles selon le nom ou chemin d'exécutable (avec sélecteur visuel d'applications actives/installées), masque ou regex de domaine (syntaxe d'exclusion `!motif` sur processus, domaines et CIDR), inspection de l'en-tête HTTP `Host:` + TLS `ClientHello` SNI, sous-réseau CIDR IPv4/IPv6, plage de ports et protocole (`TCP`/`UDP`/`ANY`). Inclut un **importateur JSON FoxyProxy**, un serveur PAC local dynamique (`http://127.0.0.1:10811/proxy.pac`), l'activation PAC Windows (`AutoConfigURL`) et un préréglage Edge FoxyProxy sans aucune extension navigateur.
- **Services Système, Profils Nommés et Empaquetage (`routeward service`, `packaging/`)** : Gère le cycle de vie du service Windows SCM (`install`, `uninstall`, `start`, `stop`, `status`, `restore` après une mise à jour MSI) avec autorisation Named Pipe SDDL via `--allow-sid`, la gestion de profils nommés et bascule rapide, le démarrage automatique Windows à l'ouverture de session, l'unité Linux `systemd` (`routeward.service`), la génération `.deb` / ZIP Windows / **installateur Windows `.msi` WiX** (le MSI et le ZIP de release embarquent WinDivert 2.2.2) et `.github/workflows/release.yml`.
- **Journalisation sur Fichier (`routeward-core::logger`)** : Écrit des journaux quotidiens thread-safe dans des dossiers système dédiés au daemon et à l'utilisateur, activables à chaud via `enableLogging`.
- **Interface Bureau ThemeForge (`apps/desktop` et `ui/`)** : Fenêtre native `tao` + `wry` intégrant les 16 palettes Oklab canoniques de ThemeForge + `HighContrast` et 9 teintes d'accent, structurée en 5 onglets par cas d'usage (`Accueil`, `Mes Apps & Sites`, `Mon Proxy`, `Activité`, `Réglages`) avec modes **Simple** et **Avancé (Expert)**, assistant guidé en 3 étapes (lien, saisie manuelle ou détection auto + test direct + activation immédiate), bilan **Vérifier ma protection** (comparaison IP avant/après), dépannage guidé **Une app ne marche plus ?** avec motifs vulgarisés, pause temporaire (`15 min`/`1 h`) avec reprise automatique, normalisation automatique des URL de sites, testeur humain **Par où passe un site ?**, détection des règles masquées avec bouton **Faire passer en premier**, packs de protection et compatibilité réseau local en 1 clic, bouton **Annuler** dans les notifications, collage presse-papiers en 1 clic et import par glisser-déposer (`.json`/`.txt`), bascule automatique sur proxy de secours, bouton **Passer en principal**, détection des proxies existants, bascule automatique de profil par Wi-Fi, réinitialisation douce avec sauvegarde automatique, confirmations de suppression en 2 étapes, modale d'import JSON FoxyProxy, noms d'apps conviviaux + diagnostic `errorDetail` + export CSV/JSON dans Activité, gestionnaire de profils nommés et System Tray Windows dynamique (icône colorée selon l'état, démarrage du service en 1 clic, **Pause 15 min** et notifications Windows natives en cas de coupure proxy).
- **Périmètre Actuel** : RouteWard assure l'interception transparente double pile IPv4 et IPv6 TCP, UDP (`TPROXY` / `WinDivert`) et DNS port `53` avec Fake-IP, l'inspection TLS SNI + HTTP `Host:`, SOCKS4/SOCKS5/HTTP/HTTPS (+ Windows SSPI), PAC local + import FoxyProxy (`msedge.exe`), le rejet QUIC (`UDP 443`), le blocage configurable DoT (`853`) + protection canari DoH Mozilla, l'empaquetage `.msi` Windows / service Windows / Linux `systemd`, le System Tray Windows avec démarrage UAC en 1 clic et une architecture modulaire Rust bureau + interface React/Vitest à 5 onglets.

## Installation sous Linux

1. Installez le paquet : `sudo apt install ./routeward_*.deb`
2. Autorisez votre compte à joindre le service : `sudo usermod -aG routeward $USER`, puis fermez la session et rouvrez-la.
3. Démarrez le service : `sudo systemctl enable --now routeward`
4. Lancez RouteWard depuis le menu des applications.

La fenêtre a besoin de `libwebkit2gtk-4.1` et GTK 3, dont le paquet dépend : `apt` les installe avec RouteWard.

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
