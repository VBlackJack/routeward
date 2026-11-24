[English](../build.md) | Français

# Compilation et Installation

## Prérequis

- **Toolchain Rust** : Toolchain Rust stable (voir `rust-toolchain.toml` ; édition 2021) avec `cargo`, `rustfmt` et `clippy`.
  - `rust-toolchain.toml` spécifie `channel = "stable"` afin d'assurer la compatibilité multi-plateforme (Windows et Linux).
  - **Cible Windows MSVC** : Sous Windows, utiliser la cible MSVC (`x86_64-pc-windows-msvc`). Si la toolchain par défaut du poste est `gnu`, définir MSVC par défaut (`rustup default stable-x86_64-pc-windows-msvc`) ou appeler Cargo avec `cargo +stable-x86_64-pc-windows-msvc`.
- **Node.js** : Node.js `22.12+` (requis par `ui/package.json` et Vite 8) et `npm` (requis pour compiler le bundle `ui/dist` embarqué par `routeward-desktop`).
- **Dépendances système** :
  - **Windows** : Microsoft Edge WebView2 Runtime (inclus dans Windows 10/11) et outils de compilation C++ MSVC / Windows SDK.
  - **Linux** : `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev` et `pkg-config`.

## Étape 1 : Compiler le Bundle Frontend

`routeward-desktop` embarque `ui/dist/index.html`, tous les chunks JavaScript et CSS générés sous `ui/dist/assets/` (découverts à la compilation par `apps/desktop/build.rs`) ainsi que les ressources de marque de `assets/branding/` (`routeward-glyph.svg`, `routeward-icon.svg`, `routeward-32.rgba`, `routeward-256.rgba`) à la compilation via `include_bytes!`. Sous Windows, `build.rs` incorpore également `assets/branding/routeward.ico` dans `routeward.exe` et `routeward-desktop.exe` via `embed-resource`.

Tous les fichiers générés dans `assets/branding/` (`routeward-16.png` à `routeward-512.png`, `routeward.ico`, `routeward-32.rgba`, `routeward-256.rgba`) sont versionnés dans le dépôt afin que la compilation standard n'ait pas besoin d'exécuter le script. Pour les régénérer à partir de `assets/branding/routeward-icon.svg`, exécuter :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\branding\build-icons.ps1
```

Il faut compiler le frontend en premier :

```powershell
Set-Location ui
npm install
npm run build
Set-Location ..
```

## Étape 2 : Compiler le Workspace Rust

Compiler les binaires CLI et bureau depuis la racine du dépôt :

```powershell
cargo build --workspace --release
```

Binaires générés :
- Binaire CLI : `target/release/routeward` (ou `routeward.exe` sous Windows)
- Binaire Bureau : `target/release/routeward-desktop` (ou `routeward-desktop.exe` sous Windows)

## Étape 3 : Télécharger les Binaires WinDivert (Test en VM Windows uniquement)

Les binaires WinDivert ne sont pas versionnés dans Git. Dans la VM Windows de test, exécuter :

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fetch-windivert.ps1
```

Ce script télécharge `WinDivert-2.2.2-A.zip`, vérifie son empreinte SHA-256 (`63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`) et extrait `WinDivert.dll` et `WinDivert64.sys` dans `third_party/windivert/bin/`.

## Étape 4 : Lancement en Deux Étapes (Daemon Privilégié + Interface Bureau / CLI Standard)

RouteWard sépare le moteur d'interception privilégié (`routeward daemon`) de l'interface bureau non privilégiée (`routeward-desktop`) et du client CLI (`routeward ctl`). Au démarrage de `routeward daemon`, toute règle de pare-feu Windows (`RouteWard_TransparentRelay_*`) ou table `nftables` Linux (`table ip routeward`) orpheline laissée par un arrêt brutal précédent est nettoyée automatiquement et journalisée au niveau `INFO`.

### Lancement en deux étapes sous Linux (groupe `routeward`)
Sous Linux, le daemon crée `/run/routeward/routeward.sock` avec pour propriétaire `root:routeward` (socket en `0660` dans un dossier en `0750`). Créez le groupe système `routeward` et ajoutez-y votre utilisateur courant avant de lancer le daemon :

```bash
sudo groupadd -r routeward
sudo usermod -aG routeward "$USER"
# Reconnectez votre session (ou exécutez `newgrp routeward`) pour activer le groupe
```

Lancez le daemon en `root` (étape 1), puis démarrez l'interface bureau ou pilotez le daemon depuis votre compte utilisateur non privilégié (étape 2) :

```bash
# Étape 1 - Terminal 1 (root) :
sudo ./target/release/routeward daemon

# Étape 2 - Terminal 2 (utilisateur standard membre du groupe 'routeward') :
./target/release/routeward-desktop
# Ou via la CLI :
./target/release/routeward ctl status
./target/release/routeward ctl start
./target/release/routeward ctl connections
./target/release/routeward ctl upsert-rule --json '{"id":"rule-1","name":"Custom","enabled":true,"priority":5,"processPatterns":["curl"],"domainPatterns":[],"ipCidrs":[],"portRanges":[],"protocol":"tcp","action":{"type":"block"}}'
# Ou depuis un fichier JSON UTF-8 (recommandé sous Windows PowerShell 5.1, qui retire les guillemets doubles internes des arguments passés aux exécutables natifs) :
./target/release/routeward ctl upsert-rule --json-file ./rule.json
./target/release/routeward ctl remove-rule --id rule-1
./target/release/routeward ctl stop

# Nettoyage des règles OS orphelines après un crash (refusé si un daemon est actif, sauf avec --force) :
sudo ./target/release/routeward cleanup
sudo ./target/release/routeward cleanup --force
```

### Lancement Windows (Named Pipe, Démarrage en 1 Clic & System Tray)
Sous Windows, vous pouvez démarrer le daemon directement en 1 clic depuis `routeward-desktop.exe` via le bouton **Démarrer le Service** de la bannière de déconnexion (qui démarre le service Windows `RouteWard` via UAC ou élève `routeward.exe daemon --locale <en|fr> --allow-sid <SID>`), ou manuellement dans deux consoles :

```powershell
# Étape 1 - PowerShell en Administrateur :
.\target\release\routeward.exe daemon

# Étape 2 - PowerShell standard (même compte utilisateur, non élevé) :
.\target\release\routeward-desktop.exe
```

Le daemon ouvre `\\.\pipe\routeward-daemon` avec une DACL explicite autorisant uniquement `SYSTEM`, `Administrators` et le SID de l'utilisateur ayant lancé le daemon (ainsi que les SID accordés via `--allow-sid`). Tant que le daemon est arrêté, `routeward-desktop` affiche une bannière persistante incluant le bouton **Démarrer le Service** sous Windows et se reconnecte automatiquement dès le démarrage du daemon. La fermeture de la fenêtre réduit l'application dans la zone de notification Windows (System Tray) ; utilisez **Quitter** dans le menu de l'icône pour fermer complètement l'interface.

> **Important (Élévation du compte Windows UAC) :** En lancement interactif via `routeward.exe daemon`, le daemon doit tourner sous le même compte utilisateur que l'interface ou `routeward ctl`, sauf si `--allow-sid <SID>` est fourni explicitement.

### Mode Service Windows (SCM) & Empaquetage
Le service Windows est la manière normale d'exécuter RouteWard. Avec le MSI, rien n'est à enregistrer à la main : la première fois que vous cliquez sur **Démarrer** dans l'application ou dans la barre système, RouteWard installe le service (une seule demande d'administrateur Windows), puis le service démarre automatiquement avec l'ordinateur. La protection est mémorisée : si elle était active, elle revient après un redémarrage, et une pause reprend toute seule à son terme, même après un redémarrage. RouteWard lui-même démarre à l'ouverture de session avec la seule icône de la barre système (réduit, sans fenêtre).

Choisir **Quitter** dans la barre système ferme seulement l'application bureau ; le service continue de protéger en arrière-plan. Pour vraiment arrêter, utilisez **Pause** ou désactivez la protection avant de quitter (voir [Dépannage](troubleshooting.md)).

Le MSI ajoute aussi un raccourci du menu Démarrer, **RouteWard - Restore Internet**, qui lance `routeward recover --pause-at-end` sans droits d'administrateur : il désactive la protection et rétablit les paramètres de proxy Windows. Depuis un terminal, `routeward recover` est l'équivalent, et `routeward ctl pause --seconds N` met la protection en pause pendant `N` secondes.

Pour une installation manuelle ou scriptée (ZIP, développement), vous pouvez enregistrer vous-même RouteWard comme service Windows sous `LocalSystem` en autorisant le SID de votre compte utilisateur sur le Named Pipe :

`install-service.ps1` copie d'abord `routeward.exe`, `routeward-desktop.exe` et les fichiers WinDivert fournis depuis le dossier d'extraction (modifiable par l'utilisateur) vers `%ProgramFiles%\RouteWard` (modifiable avec `-InstallDir`), puis enregistre la copie installée. `routeward.exe service install` refuse de son côté un binaire de service dont le dossier, ou un dossier parent, est modifiable par des non-administrateurs, car le service s'exécute sous `LocalSystem`.

```powershell
# Installer et démarrer le service Windows (PowerShell Administrateur) :
.\packaging\windows\install-service.ps1

# Ou directement via la CLI :
.\target\release\routeward.exe service install --allow-current-user
.\target\release\routeward.exe service start
.\target\release\routeward.exe service status

# Supprimer le service Windows :
.\target\release\routeward.exe service stop
.\target\release\routeward.exe service uninstall

# Empaqueter les binaires release en ZIP + SHA-256 (l'option `-IncludeWinDivert` embarque les fichiers WinDivert 2.2.2 présents, comme dans les ZIP de release) :
.\packaging\windows\package-windows.ps1 -TargetDir target/release -OutDir dist -Arch x64

# Générer l'installateur Windows MSI (requiert WiX Toolset v6 `wix.exe`; l'option `-IncludeWinDivert` embarque les fichiers WinDivert 2.2.2 présents, comme dans les MSI de release) :
.\packaging\windows\build-msi.ps1 -TargetDir target/release -OutDir dist -Arch x64
```

Les paquets `.msi` de release embarquent WinDivert 2.2.2 (`WinDivert.dll` et `WinDivert64.sys`, non modifiés, sous licence LGPLv3 ; mentions dans `THIRD_PARTY_NOTICES.txt`, archive des sources de WinDivert jointe à chaque release). Une mise à jour MSI réenregistre le service RouteWard avec ses arguments `--allow-sid` (`routeward service restore` ; les services en démarrage automatique sont relancés, ceux en démarrage manuel sont enregistrés arrêtés), et la désinstallation supprime le service du pilote WinDivert. Le ZIP de release embarque les mêmes fichiers WinDivert et leurs mentions à côté des binaires : il fonctionne tel quel une fois extrait. Chaque ZIP contient aussi `fetch-windivert.ps1`, qui extrait WinDivert dans `third_party\windivert\bin` à côté des binaires quand le ZIP est construit sans `-IncludeWinDivert`.

#### Désinstaller le MSI (ce qui est nettoyé, ce qui ne l'est pas)
Avant la suppression des fichiers, une désinstallation (pas une mise à jour) exécute deux actions :

- `routeward cleanup --all-users` (sous `LocalSystem`) : pour chaque utilisateur dont la ruche du registre est **actuellement chargée** (chaque utilisateur connecté), elle remet en place le proxy système, l'URL PAC et l'entrée de démarrage automatique modifiés par RouteWard, depuis la sauvegarde de cet utilisateur, et seulement s'ils sont toujours ceux de RouteWard. Les ruches des utilisateurs non connectés ne sont volontairement **pas** chargées : ces utilisateurs gardent leurs valeurs. Pour corriger à la main, désactivez le proxy dans *Paramètres > Réseau et Internet > Proxy* (ou *Options Internet > Connexions > Paramètres réseau*), ou lancez `routeward cleanup --user` sous ce compte avant la désinstallation.
- `routeward purge-data` : supprime `%ProgramData%\RouteWard` (profil et journaux) sauf si `KEEPDATA=1` a été passé (`msiexec /x RouteWard.msi KEEPDATA=1`). Elle refuse un dossier modifiable par un utilisateur standard. Limite acceptée : les données sont supprimées avant la fin de la désinstallation, donc une désinstallation qui échoue ou est annulée ensuite laisse les données supprimées.

La passe `LocalSystem` n'écrit jamais dans un profil utilisateur : elle lit seulement les paramètres sauvegardés de chaque utilisateur par un handle vérifié (fichier ordinaire à l'emplacement attendu, appartenant à l'utilisateur, à SYSTEM ou aux Administrateurs) et, si cette vérification échoue, ne désactive que les valeurs identiques à celles de RouteWard. Une application bureau encore ouverte dans la session d'un autre utilisateur lors de la désinstallation peut réécrire ses paramètres après cette passe ; elle les restaure aussi à sa fermeture ou à la fermeture de session de cet utilisateur.

### Unité `systemd` & Paquet `.deb` sous Linux
Pour un déploiement système sous Linux, utilisez `packaging/linux/build-deb.sh` (ou installez `packaging/linux/routeward.service` avec le groupe système `routeward`) :

```bash
bash packaging/linux/build-deb.sh --target-dir target/release --out-dir dist
sudo apt install ./dist/routeward_*.deb
sudo systemctl enable --now routeward
```

Le paquet installe aussi une entrée du menu des applications (`routeward-desktop.desktop`) et l'icône `routeward` dans le thème `hicolor` (16 à 512 px et un SVG vectoriel). Les jobs de release et de CI valident l'entrée avec `desktop-file-validate`, et le job de release échoue si l'entrée ou les icônes manquent dans le `.deb`.

Les binaires sont liés à la glibc de la machine qui les compile. Le `.deb` publié est compilé sous Ubuntu 22.04 (glibc 2.35) : il fonctionne sous Debian 12, Ubuntu 22.04 et les versions plus récentes. Le job de release échoue si un binaire demande un symbole glibc plus récent (`packaging/linux/check-glibc-floor.sh --max 2.35`). Un paquet compilé sur une distribution plus récente ne fonctionne qu'avec cette glibc ou une plus récente.

### Emplacement des Journaux (Daemon vs Bureau / CLI)
Les fichiers journaux (`RouteWard_yyyyMMdd.log`) sont écrits dans des dossiers système ou utilisateur fixes, indépendamment du répertoire courant (`CWD`) :
- **Daemon privilégié (`routeward daemon`, `routeward run`, `routeward cleanup`)** :
  - **Windows** : `%ProgramData%\RouteWard\logs` (résolu via `SHGetKnownFolderPath(FOLDERID_ProgramData)`)
  - **Linux** : `/var/log/routeward`
- **Pont Bureau et CLI non privilégiés (`routeward-desktop`, `routeward ctl`)** :
  - **Windows** : `%LOCALAPPDATA%\RouteWard\logs` (résolu via `SHGetKnownFolderPath(FOLDERID_LocalAppData)`)
  - **Linux** : `$XDG_STATE_HOME/routeward/logs` (ou `~/.local/state/routeward/logs` par défaut)
