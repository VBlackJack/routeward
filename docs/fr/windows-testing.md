[English](../windows-testing.md) | Français

# Suite de Tests de Non-Régression Windows

Le script `tests/windows/Invoke-RouteWardTests.ps1` (et son lanceur `tests/windows/Run-RouteWardTests.bat`) exécute une suite automatisée de 19 scénarios de non-régression pour RouteWard dans une VM de test Windows dédiée.

## Prérequis

- **VM de test dédiée** : Windows 10/11 ou Windows Server 2022 avec Windows PowerShell `5.1` ouvert dans une session **Administrateur élevée**.
- **Fichiers requis dans le dossier d'exécution** :
  - `routeward.exe` et `routeward-desktop.exe`
  - `socks5_udp_test_server.exe` (compilé via `cargo build --release --examples`, placé dans le même dossier que `routeward.exe` ou dans `examples\`)
  - `WinDivert.dll` et `WinDivert64.sys` (dans le même dossier que `routeward.exe` ou dans `third_party\windivert\bin\`)
  - `curl.exe` système (`%SystemRoot%\System32\curl.exe`)
- **Proxy SOCKS5 amont actif** : Un serveur SOCKS5 en écoute sur `127.0.0.1:1080` (par exemple `ssh -D 127.0.0.1:1080 ...`), correspondant à la règle par défaut `"CLI Tools via SOCKS5 Proxy"`. Comme `ssh -D` ne supporte pas la commande SOCKS5 `UDP ASSOCIATE`, les scénarios UDP `(q)` et `(r)` lancent automatiquement une instance locale de `socks5_udp_test_server.exe` sur des ports dédiés (`1082` et `1083`) et nettoient leurs noeuds proxy et règles temporaires en sortie.
- **Aucun processus actif** : Aucune instance de `routeward` ou `routeward-desktop` ne doit tourner avant le lancement.

## Lancement de la Suite

Pour empêcher toute exécution accidentelle hors machine de test, le script refuse de démarrer sans le commutateur explicite `-ConfirmTestMachine`.

Depuis une console PowerShell ou Invite de commandes en Administrateur, dans le dossier contenant `routeward.exe` :

```powershell
# PowerShell 5.1 (exécution complète dans la VM de test dédiée) :
.\Invoke-RouteWardTests.ps1 -ConfirmTestMachine

# Ou via le fichier .bat :
.\Run-RouteWardTests.bat -ConfirmTestMachine

# Mode DryRun (valide la résolution de chemins hors dépôt, le parseur JSON des réponses ctl, la capture stdout seule du code HTTP curl, la création/suppression du fichier temporaire UTF-8 sans BOM pour --json-file et l'ordre d'exécution explicite des scénarios, sans lancer le daemon ni WinDivert) :
.\Invoke-RouteWardTests.ps1 -DryRun
```

Tous les chemins, ports, URL de test, noms de règles et délais sont paramétrables (`-Socks5Host`, `-Socks5Port`, `-TestUrl`, `-PipeName`, `-TransparentRelayPort`, `-BinDir`, `-UdpTestServerExeName`, `-UdpTestProxyPort`, `-UdpRefuseTestProxyPort`, `-PublicNtpServer`, etc.). Lorsqu'il est lancé hors du dépôt Git (par exemple depuis `C:\RouteWard`), le script utilise ses valeurs par défaut sans erreur. En sortie (`try / finally`), le script arrête tout processus `socks5_udp_test_server` lancé, demande l'arrêt de l'interception (`ctl stop`), tue tous les PID de daemon qu'il a lancés, vérifie qu'aucun processus `routeward` ne survit, exécute `routeward.exe cleanup`, restaure `active_profile.json` s'il a été modifié, vide le cache DNS Windows et vérifie que `curl.exe` répond en sortie.

## Ordre d'Exécution des Scénarios et Relance du Tunnel SOCKS5

Chaque scénario conserve une **lettre stable** (`(a)` à `(s)`) dans tous les rapports, associée à un **ordre d'exécution explicite** (`[Order 01/19]` à `[Order 19/19]`).

Comme le scénario `(j)` arrête le processus SOCKS5 local en écoute sur `-Socks5Port` pour tester le Kill-Switch (et qu'un tunnel `ssh -D` interactif demandant un mot de passe ne peut pas être relancé automatiquement sans intervention), le scénario `(j)` s'exécute toujours **en DERNIER (`Order 19/19`)**, après tous les autres scénarios :

`01:(a) -> 02:(b) -> 03:(c) -> 04:(d) -> 05:(e) -> 06:(f) -> 07:(g) -> 08:(h) -> 09:(i) -> 10:(k) -> 11:(l) -> 12:(m) -> 13:(n) -> 14:(o) -> 15:(p) -> 16:(q) -> 17:(r) -> 18:(s) -> 19:(j)`

Avant chaque scénario qui a besoin du proxy SOCKS5 externe (`(d)`, `(k)` et `(j)`), le script vérifie que `${Socks5Host}:${Socks5Port}` répond en TCP. S'il ne répond pas, le scénario est marqué `SKIP` avec la raison `"upstream SOCKS5 unreachable"` (jamais `FAIL`).

> **Relance du tunnel SSH après la suite** : À la fin du scénario `(j)` (`Order 19/19`), le script tente de relancer automatiquement le processus SOCKS5. S'il s'agit d'un tunnel `ssh -D 127.0.0.1:1080 ...` demandant un mot de passe interactif, la relance en arrière-plan ne peut pas aboutir et le script affiche un message `[NOTICE]`. Il faut alors relancer manuellement le tunnel `ssh -D` dans la VM avant d'exécuter une nouvelle passe de tests.

## Scénarios Couverts (par Ordre d'Exécution)

Chaque scénario établit lui-même son état de départ de manière indépendante :

1. **`[Order 01/19]` Scénario `(a)`** : Démarre `routeward.exe daemon` en arrière-plan et vérifie l'apparition du Named Pipe (`\\.\pipe\routeward-daemon`).
2. **`[Order 02/19]` Scénario `(b)`** : Vérifie les DACL protégées (`D:P`) limitées à `SYSTEM` et `Administrators` sur `%ProgramData%\RouteWard` et `active_profile.json`, ainsi que la SDDL du Named Pipe via `[System.IO.Directory]::GetAccessControl` (absence de `WD`, `BU` et `AU`).
3. **`[Order 03/19]` Scénario `(c)`** : Vérifie `routeward.exe ctl status` (`result.daemonConnected=true`, `result.elevatedPrivileges=true`, `result.running=false`).
4. **`[Order 04/19]` Scénario `(d)`** *(nécessite SOCKS5)* : Exécute `routeward.exe ctl start` puis `curl.exe`, vérifie le code HTTP `200` et la présence de `curl.exe` dans `result` de `ctl connections` avec `matchedRule="CLI Tools via SOCKS5 Proxy"` et `rxBytes > 0`.
5. **`[Order 05/19]` Scénario `(e)`** : Écrit une règle `Block` temporaire de priorité 1 pour `curl.exe` en UTF-8 sans BOM dans `%TEMP%`, l'applique via `routeward.exe ctl upsert-rule --json-file <chemin>`, vérifie l'échec de `curl.exe` et l'état `blocked` dans `ctl connections`, retire la règle via `routeward.exe ctl remove-rule --id <ID>`, supprime le fichier temporaire dans un bloc `finally`, et vérifie via `ctl state` que le profil est revenu exactement à l'identique.
6. **`[Order 06/19]` Scénario `(f)`** : Exécute `routeward.exe ctl stop`, vérifie la suppression de la règle de pare-feu `RouteWard_TransparentRelay_10810` et le retour HTTP `200` de `curl.exe` en direct.
7. **`[Order 07/19]` Scénario `(g)`** : Démarre l'interception, tue brutalement le daemon (`Stop-Process -Force`), vérifie que `curl.exe` répond `200` (fail-open) et que la règle de pare-feu orpheline est toujours présente.
8. **`[Order 08/19]` Scénario `(h)`** : S'assure que le daemon est arrêté et que la règle de pare-feu orpheline est présente, redémarre `routeward.exe daemon`, et vérifie que la règle orpheline est supprimée automatiquement au démarrage et mentionnée dans le journal du daemon.
9. **`[Order 09/19]` Scénario `(i)`** : Vérifie que le journal daemon (`%ProgramData%\RouteWard\logs`) et le journal utilisateur (`%LOCALAPPDATA%\RouteWard\logs`, alimenté en `INFO` à chaque appel `ctl`) ont été modifiés pendant le test, et qu'aucun dossier `logs` n'a été créé dans le répertoire courant.
10. **`[Order 10/19]` Scénario `(k)`** *(nécessite SOCKS5)* : Vide le cache DNS Windows moteur actif, exécute `Resolve-DnsName` sur un domaine public vers un résolveur externe (`9.9.9.9`), vérifie qu'une Fake-IP dans `198.18.0.0/15` est renvoyée et présente dans `ctl fake-ips`, puis vérifie que `curl.exe` vers ce domaine retourne HTTP `200` via SOCKS5 avec son nom de domaine.
11. **`[Order 11/19]` Scénario `(l)`** : Vérifie que `Resolve-DnsName` sur le suffixe DNS Active Directory / principal de la machine continue de résoudre directement vers des IP réelles hors pool Fake-IP (`SKIP` si la machine n'a pas de domaine AD ou de suffixe DNS principal).
12. **`[Order 12/19]` Scénario `(m)`** : Arrête l'interception (`ctl stop`), vide le cache DNS Windows, et vérifie que `Resolve-DnsName` sur le domaine public retourne une IP réelle hors `198.18.0.0/15`.
13. **`[Order 13/19]` Scénario `(n)`** : Pré-remplit le cache DNS Client Windows moteur arrêté, lance `routeward.exe ctl start`, et vérifie que le cache DNS de l'OS est automatiquement vidé au démarrage (`dnsapi.dll!DnsFlushResolverCache` ou `ipconfig /flushdns`) et que `Get-DnsClientCache` contient `0` entrée pour le domaine pré-rempli.
14. **`[Order 14/19]` Scénario `(o)`** : Envoie une sonde QUIC en `UDP 443` moteur actif (`securityPolicy.blockQuicUdp443 = true`) avec `SIO_UDP_CONNRESET` activé sur le socket client. Distingue le **blocage** obligatoire (`status=blocked`, `SecurityPolicy:blockQuicUdp443`, `WARN` journalisé, aucune réponse) du **rejet rapide** (`fastRejection=true/false`, rapporté avec `clientError` et `measuredDelay` en ms). Note : sous Windows, `tcpip.sys` / WFP (`FWPM_LAYER_INBOUND_ICMP_ERROR_V4`) peut ignorer un paquet ICMPv4 Port Unreachable (`Type 3, Code 3`) injecté en entrée lorsque le datagramme UDP sortant a été intercepté et jeté sur `WINDIVERT_LAYER_NETWORK` avant la création complète de l'état de flux sortant WFP, ce qui conduit à `TimedOut` sur le socket brut malgré le recalcul complet des sommes de contrôle IPv4+UDP internes.
15. **`[Order 15/19]` Scénario `(p)`** : Envoie des requêtes LLMNR (`UDP 5355`) pour un FQDN public (`public-leak.routeward.test`) et pour un nom court local (`fileserver`), et vérifie que le FQDN public est bloqué (`LocalNameGuard:LLMNR`, `WARN` limité en débit) tandis que le nom local est autorisé en direct.
16. **`[Order 16/19]` Scénario `(q)`** : Lance `socks5_udp_test_server.exe` sur `127.0.0.1:1082` avec `--stats-file`, ajoute un noeud proxy SOCKS5 temporaire (`ctl upsert-proxy`) et une règle UDP temporaire (`ctl upsert-rule`) routant le port UDP `123` de `powershell.exe` vers ce proxy, envoie une requête NTP (`48` octets) vers `time.cloudflare.com:123` (via sa Fake-IP), vérifie la réception d'une réponse NTP de `48` octets et les compteurs du serveur de test (`udp_associate_requests >= 1`, `udp_datagrams_relayed >= 1`, `udp_replies_relayed >= 1`), puis supprime la règle et le noeud proxy dans un bloc `finally`, arrête `socks5_udp_test_server.exe` et vérifie via `ctl state` que le profil est revenu exactement à l'identique.
17. **`[Order 17/19]` Scénario `(r)`** : Lance `socks5_udp_test_server.exe` sur `127.0.0.1:1083` avec `--disable-udp-associate` (`REP = 0x07 Command not supported`), ajoute un noeud proxy et une règle UDP temporaires pour `powershell.exe` sur le port `123`, envoie une requête NTP vers `time.cloudflare.com:123`, vérifie qu'aucune réponse n'est reçue (aucune fuite `Direct`), que `udp_associate_refused >= 1` et que `ctl connections` enregistre `status="blocked"` / `routeLabel="BLOCKED"`, puis nettoie la règle et le proxy dans `finally`, arrête le serveur de test et vérifie via `ctl state` que le profil est identique à l'état initial.
18. **`[Order 18/19]` Scénario `(s)`** : Sans règle UDP temporaire, envoie une requête NTP UDP directe (`time.cloudflare.com:123`) depuis `powershell.exe`, vérifie la réception de la réponse NTP (`48` octets) et contrôle que `ctl connections` et `ctl logs` enregistrent le flux UDP `Direct` attribué (`processName="powershell.exe"`, `protocol="udp"`, `routeLabel="DIRECT"`).
19. **`[Order 19/19]` Scénario `(j)`** *(nécessite SOCKS5, exécuté en DERNIER)* : Arrête le processus SOCKS5 local en écoute sur `-Socks5Port` pendant que l'interception est active (`securityPolicy.killSwitchEnabled = true`), exécute `curl.exe`, vérifie que `curl.exe` échoue sans repli en `Direct`, contrôle que `ctl connections` enregistre la connexion `curl.exe` avec `status="blocked"` et `routeLabel="BLOCKED"` et que `ctl logs` contient un `WARN` (`Kill-Switch blocked connection`), puis tente de relancer le processus SOCKS5 dans le bloc `finally` (ou affiche un avertissement explicite si un tunnel SSH interactif nécessite une relance manuelle).

## Lecture du Rapport Généré

- **Sortie console** : Tous les messages console et du rapport sont rédigés en anglais (encodage E/S `UTF-8` forcé ; aucun message localisé du produit n'est recopié dans les lignes de résultat des scénarios). Affiche une ligne `[PASS]`, `[FAIL]` ou `[SKIP]` par scénario avec son ordre `[Order XX/19]` et sa lettre stable `Scenario (x)`, puis le résumé `X PASS / Y FAIL / Z SKIP`. Le code de sortie vaut `0` uniquement si `FAIL == 0`.
- **Fichier de rapport horodaté** : Créé en UTF-8 à côté du script sous le nom `RouteWard_TestReport_<yyyyMMdd_HHmmss>.txt`. Il contient :
  1. Le résumé des scénarios, l'ordre d'exécution explicite et les informations système / version PowerShell.
  2. La version et la taille en octets de `routeward.exe`, `routeward-desktop.exe`, `socks5_udp_test_server.exe`, `WinDivert.dll` et `WinDivert64.sys`.
  3. Les notes d'audit (dont la chaîne SDDL exacte du Named Pipe et l'état de relance du serveur SOCKS5).
  4. Les sorties brutes des commandes `routeward ctl` et `routeward cleanup` lues en UTF-8 (avec masquage de tout mot de passe).
  5. Les 30 dernières lignes du journal daemon et du journal utilisateur lues en UTF-8 (avec masquage de tout mot de passe).
