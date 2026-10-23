# Suite de Tests de Non-Regression Windows

Le script `tests/windows/Invoke-RouteWardTests.ps1` (et son lanceur `tests/windows/Run-RouteWardTests.bat`) execute une suite automatisee de 9 scenarios de non-regression pour RouteWard dans une VM de test Windows dediee.

## Prerequis

- **VM de test dediee** : Windows 10/11 ou Windows Server 2022 avec Windows PowerShell `5.1` ouvert dans une session **Administrateur elevee**.
- **Fichiers requis dans le dossier d'execution** :
  - `routeward.exe` et `routeward-desktop.exe`
  - `WinDivert.dll` et `WinDivert64.sys` (dans le meme dossier que `routeward.exe` ou dans `third_party\windivert\bin\`)
  - `curl.exe` systeme (`%SystemRoot%\System32\curl.exe`)
- **Proxy SOCKS5 amont actif** : Un serveur SOCKS5 en ecoute sur `127.0.0.1:1080` (par exemple `ssh -D 127.0.0.1:1080 ...`), correspondant a la regle par defaut `"CLI Tools via SOCKS5 Proxy"`.
- **Aucun processus actif** : Aucune instance de `routeward` ou `routeward-desktop` ne doit tourner avant le lancement.

## Lancement de la Suite

Pour empecher toute execution accidentelle hors machine de test, le script refuse de demarrer sans le commutateur explicite `-ConfirmTestMachine`.

Depuis une console PowerShell ou Invite de commandes en Administrateur, dans le dossier contenant `routeward.exe` :

```powershell
# PowerShell 5.1 :
.\Invoke-RouteWardTests.ps1 -ConfirmTestMachine

# Ou via le fichier .bat :
.\Run-RouteWardTests.bat -ConfirmTestMachine
```

Tous les chemins, ports, URL de test, noms de regles et delais sont parametrables (`-Socks5Host`, `-Socks5Port`, `-TestUrl`, `-PipeName`, `-TransparentRelayPort`, `-BinDir`, etc.). En sortie (`try / finally`), le script arrete systematiquement le daemon qu'il a lance, execute `routeward.exe cleanup`, et restaure `active_profile.json` s'il a ete modifie.

## Scenarios Couverts

- **`(a)`** : Demarre `routeward.exe daemon` en arriere-plan et verifie l'apparition du Named Pipe (`\\.\pipe\routeward-daemon`).
- **`(b)`** : Verifie les DACL protegees (`D:P`) limitees a `SYSTEM` et `Administrators` sur `%ProgramData%\RouteWard` et `active_profile.json`, ainsi que la SDDL du Named Pipe via `[System.IO.Directory]::GetAccessControl` (absence de `WD`, `BU` et `AU`).
- **`(c)`** : Verifie `routeward.exe ctl status` (`daemonConnected=true`, `elevatedPrivileges=true`, `running=false`).
- **`(d)`** : Execute `routeward.exe ctl start` puis `curl.exe`, verifie le code HTTP `200` et la presence de `curl.exe` dans `ctl connections` avec `matchedRule="CLI Tools via SOCKS5 Proxy"` et `rxBytes > 0`.
- **`(e)`** : Teste l'ajout puis le retrait d'une regle `Block` temporaire pour `curl.exe` via `ctl` (passe proprement en `[SKIP]` si `ctl` ne fournit pas de sous-commande de suppression de regle).
- **`(f)`** : Execute `routeward.exe ctl stop`, verifie la suppression de la regle de pare-feu `RouteWard_TransparentRelay_10810` et le retour HTTP `200` de `curl.exe` en direct.
- **`(g)`** : Demarre l'interception, tue brutalement le daemon (`Stop-Process -Force`), verifie que `curl.exe` repond `200` (fail-open) et que la regle de pare-feu orpheline est toujours presente.
- **`(h)`** : Redemarre `routeward.exe daemon` et verifie que la regle de pare-feu orpheline est supprimee automatiquement au demarrage et mentionnee dans le journal du daemon.
- **`(i)`** : Verifie que le journal daemon (`%ProgramData%\RouteWard\logs`) et le journal utilisateur (`%LOCALAPPDATA%\RouteWard\logs`) ont ete modifies pendant le test, et qu'aucun dossier `logs` n'a ete cree dans le repertoire courant.

## Lecture du Rapport Genere

- **Sortie console** : Affiche une ligne `[PASS]`, `[FAIL]` ou `[SKIP]` par scenario, puis le resume `X PASS / Y FAIL / Z SKIP`. Le code de sortie vaut `0` uniquement si `FAIL == 0`.
- **Fichier de rapport horodate** : Cree a cote du script sous le nom `RouteWard_TestReport_<yyyyMMdd_HHmmss>.txt`. Il contient :
  1. Le resume des scenarios et les informations systeme / version PowerShell.
  2. La version et la taille en octets de `routeward.exe`, `routeward-desktop.exe`, `WinDivert.dll` et `WinDivert64.sys`.
  3. Les notes d'audit (dont la chaine SDDL exacte du Named Pipe).
  4. Les sorties brutes des commandes `routeward ctl` et `routeward cleanup` (avec masquage de tout mot de passe).
  5. Les 30 dernieres lignes du journal daemon et du journal utilisateur (avec masquage de tout mot de passe).
