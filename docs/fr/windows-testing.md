# Suite de Tests de Non-Regression Windows

Le script `tests/windows/Invoke-RouteWardTests.ps1` (et son lanceur `tests/windows/Run-RouteWardTests.bat`) execute une suite automatisee de 19 scenarios de non-regression pour RouteWard dans une VM de test Windows dediee.

## Prerequis

- **VM de test dediee** : Windows 10/11 ou Windows Server 2022 avec Windows PowerShell `5.1` ouvert dans une session **Administrateur elevee**.
- **Fichiers requis dans le dossier d'execution** :
  - `routeward.exe` et `routeward-desktop.exe`
  - `socks5_udp_test_server.exe` (compile via `cargo build --release --examples`, place dans le meme dossier que `routeward.exe` ou dans `examples\`)
  - `WinDivert.dll` et `WinDivert64.sys` (dans le meme dossier que `routeward.exe` ou dans `third_party\windivert\bin\`)
  - `curl.exe` systeme (`%SystemRoot%\System32\curl.exe`)
- **Proxy SOCKS5 amont actif** : Un serveur SOCKS5 en ecoute sur `127.0.0.1:1080` (par exemple `ssh -D 127.0.0.1:1080 ...`), correspondant a la regle par defaut `"CLI Tools via SOCKS5 Proxy"`. Comme `ssh -D` ne supporte pas la commande SOCKS5 `UDP ASSOCIATE`, les scenarios UDP `(q)` et `(r)` lancent automatiquement une instance locale de `socks5_udp_test_server.exe` sur des ports dedies (`1082` et `1083`) et nettoient leurs noeuds proxy et regles temporaires en sortie.
- **Aucun processus actif** : Aucune instance de `routeward` ou `routeward-desktop` ne doit tourner avant le lancement.

## Lancement de la Suite

Pour empecher toute execution accidentelle hors machine de test, le script refuse de demarrer sans le commutateur explicite `-ConfirmTestMachine`.

Depuis une console PowerShell ou Invite de commandes en Administrateur, dans le dossier contenant `routeward.exe` :

```powershell
# PowerShell 5.1 (execution complete dans la VM de test dediee) :
.\Invoke-RouteWardTests.ps1 -ConfirmTestMachine

# Ou via le fichier .bat :
.\Run-RouteWardTests.bat -ConfirmTestMachine

# Mode DryRun (valide la resolution de chemins hors depot, le parseur JSON des reponses ctl, la capture stdout seule du code HTTP curl, la creation/suppression du fichier temporaire UTF-8 sans BOM pour --json-file et l'ordre d'execution explicite des scenarios, sans lancer le daemon ni WinDivert) :
.\Invoke-RouteWardTests.ps1 -DryRun
```

Tous les chemins, ports, URL de test, noms de regles et delais sont parametrables (`-Socks5Host`, `-Socks5Port`, `-TestUrl`, `-PipeName`, `-TransparentRelayPort`, `-BinDir`, `-UdpTestServerExeName`, `-UdpTestProxyPort`, `-UdpRefuseTestProxyPort`, `-PublicNtpServer`, etc.). Lorsqu'il est lance hors du depot Git (par exemple depuis `C:\RouteWard`), le script utilise ses valeurs par defaut sans erreur. En sortie (`try / finally`), le script arrete tout processus `socks5_udp_test_server` lance, demande l'arret de l'interception (`ctl stop`), tue tous les PID de daemon qu'il a lances, verifie qu'aucun processus `routeward` ne survit, execute `routeward.exe cleanup`, restaure `active_profile.json` s'il a ete modifie, vide le cache DNS Windows et verifie que `curl.exe` repond en sortie.

## Ordre d'Execution des Scenarios et Relance du Tunnel SOCKS5

Chaque scenario conserve une **lettre stable** (`(a)` a `(s)`) dans tous les rapports, associee a un **ordre d'execution explicite** (`[Order 01/19]` a `[Order 19/19]`).

Comme le scenario `(j)` arrete le processus SOCKS5 local en ecoute sur `-Socks5Port` pour tester le Kill-Switch — et qu'un tunnel `ssh -D` interactif demandant un mot de passe ne peut pas etre relance automatiquement sans intervention — le scenario `(j)` s'execute toujours **en DERNIER (`Order 19/19`)**, apres tous les autres scenarios :

`01:(a) -> 02:(b) -> 03:(c) -> 04:(d) -> 05:(e) -> 06:(f) -> 07:(g) -> 08:(h) -> 09:(i) -> 10:(k) -> 11:(l) -> 12:(m) -> 13:(n) -> 14:(o) -> 15:(p) -> 16:(q) -> 17:(r) -> 18:(s) -> 19:(j)`

Avant chaque scenario qui a besoin du proxy SOCKS5 externe (`(d)`, `(k)` et `(j)`), le script verifie que `${Socks5Host}:${Socks5Port}` repond en TCP. S'il ne repond pas, le scenario est marque `SKIP` avec la raison `"upstream SOCKS5 unreachable"` (jamais `FAIL`).

> **Relance du tunnel SSH apres la suite** : A la fin du scenario `(j)` (`Order 19/19`), le script tente de relancer automatiquement le processus SOCKS5. S'il s'agit d'un tunnel `ssh -D 127.0.0.1:1080 ...` demandant un mot de passe interactif, la relance en arriere-plan ne peut pas aboutir et le script affiche un message `[NOTICE]`. Il faut alors relancer manuellement le tunnel `ssh -D` dans la VM avant d'executer une nouvelle passe de tests.

## Scenarios Couverts (par Ordre d'Execution)

Chaque scenario etablit lui-meme son etat de depart de maniere independante :

1. **`[Order 01/19]` Scenario `(a)`** : Demarre `routeward.exe daemon` en arriere-plan et verifie l'apparition du Named Pipe (`\\.\pipe\routeward-daemon`).
2. **`[Order 02/19]` Scenario `(b)`** : Verifie les DACL protegees (`D:P`) limitees a `SYSTEM` et `Administrators` sur `%ProgramData%\RouteWard` et `active_profile.json`, ainsi que la SDDL du Named Pipe via `[System.IO.Directory]::GetAccessControl` (absence de `WD`, `BU` et `AU`).
3. **`[Order 03/19]` Scenario `(c)`** : Verifie `routeward.exe ctl status` (`result.daemonConnected=true`, `result.elevatedPrivileges=true`, `result.running=false`).
4. **`[Order 04/19]` Scenario `(d)`** *(necessite SOCKS5)* : Execute `routeward.exe ctl start` puis `curl.exe`, verifie le code HTTP `200` et la presence de `curl.exe` dans `result` de `ctl connections` avec `matchedRule="CLI Tools via SOCKS5 Proxy"` et `rxBytes > 0`.
5. **`[Order 05/19]` Scenario `(e)`** : Ecrit une regle `Block` temporaire de priorite 1 pour `curl.exe` en UTF-8 sans BOM dans `%TEMP%`, l'applique via `routeward.exe ctl upsert-rule --json-file <chemin>`, verifie l'echec de `curl.exe` et l'etat `blocked` dans `ctl connections`, retire la regle via `routeward.exe ctl remove-rule --id <ID>`, supprime le fichier temporaire dans un bloc `finally`, et verifie via `ctl state` que le profil est revenu exactement a l'identique.
6. **`[Order 06/19]` Scenario `(f)`** : Execute `routeward.exe ctl stop`, verifie la suppression de la regle de pare-feu `RouteWard_TransparentRelay_10810` et le retour HTTP `200` de `curl.exe` en direct.
7. **`[Order 07/19]` Scenario `(g)`** : Demarre l'interception, tue brutalement le daemon (`Stop-Process -Force`), verifie que `curl.exe` repond `200` (fail-open) et que la regle de pare-feu orpheline est toujours presente.
8. **`[Order 08/19]` Scenario `(h)`** : S'assure que le daemon est arrete et que la regle de pare-feu orpheline est presente, redemarre `routeward.exe daemon`, et verifie que la regle orpheline est supprimee automatiquement au demarrage et mentionnee dans le journal du daemon.
9. **`[Order 09/19]` Scenario `(i)`** : Verifie que le journal daemon (`%ProgramData%\RouteWard\logs`) et le journal utilisateur (`%LOCALAPPDATA%\RouteWard\logs`, alimente en `INFO` a chaque appel `ctl`) ont ete modifies pendant le test, et qu'aucun dossier `logs` n'a ete cree dans le repertoire courant.
10. **`[Order 10/19]` Scenario `(k)`** *(necessite SOCKS5)* : Vide le cache DNS Windows moteur actif, execute `Resolve-DnsName` sur un domaine public vers un resolveur externe (`9.9.9.9`), verifie qu'une Fake-IP dans `198.18.0.0/15` est renvoyee et presente dans `ctl fake-ips`, puis verifie que `curl.exe` vers ce domaine retourne HTTP `200` via SOCKS5 avec son nom de domaine.
11. **`[Order 11/19]` Scenario `(l)`** : Verifie que `Resolve-DnsName` sur le suffixe DNS Active Directory / principal de la machine continue de resoudre directement vers des IP reelles hors pool Fake-IP (`SKIP` si la machine n'a pas de domaine AD ou de suffixe DNS principal).
12. **`[Order 12/19]` Scenario `(m)`** : Arrete l'interception (`ctl stop`), vide le cache DNS Windows, et verifie que `Resolve-DnsName` sur le domaine public retourne une IP reelle hors `198.18.0.0/15`.
13. **`[Order 13/19]` Scenario `(n)`** : Pre-remplit le cache DNS Client Windows moteur arrete, lance `routeward.exe ctl start`, et verifie que le cache DNS de l'OS est automatiquement vide au demarrage (`dnsapi.dll!DnsFlushResolverCache` ou `ipconfig /flushdns`) et que `Get-DnsClientCache` contient `0` entree pour le domaine pre-rempli.
14. **`[Order 14/19]` Scenario `(o)`** : Envoie une sonde QUIC en `UDP 443` moteur actif (`securityPolicy.blockQuicUdp443 = true`) avec `SIO_UDP_CONNRESET` active sur le socket client. Distingue le **blocage** obligatoire (`status=blocked`, `SecurityPolicy:blockQuicUdp443`, `WARN` journalise, aucune reponse) du **rejet rapide** (`fastRejection=true/false`, rapporte avec `clientError` et `measuredDelay` en ms). Note : sous Windows, `tcpip.sys` / WFP (`FWPM_LAYER_INBOUND_ICMP_ERROR_V4`) peut ignorer un paquet ICMPv4 Port Unreachable (`Type 3, Code 3`) injecte en entree lorsque le datagramme UDP sortant a ete intercepte et jete sur `WINDIVERT_LAYER_NETWORK` avant la creation complete de l'etat de flux sortant WFP, ce qui conduit a `TimedOut` sur le socket brut malgre le recalcul complet des sommes de controle IPv4+UDP internes.
15. **`[Order 15/19]` Scenario `(p)`** : Envoie des requetes LLMNR (`UDP 5355`) pour un FQDN public (`public-leak.routeward.test`) et pour un nom court local (`fileserver`), et verifie que le FQDN public est bloque (`LocalNameGuard:LLMNR`, `WARN` limite en debit) tandis que le nom local est autorise en direct.
16. **`[Order 16/19]` Scenario `(q)`** : Lance `socks5_udp_test_server.exe` sur `127.0.0.1:1082` avec `--stats-file`, ajoute un noeud proxy SOCKS5 temporaire (`ctl upsert-proxy`) et une regle UDP temporaire (`ctl upsert-rule`) routant le port UDP `123` de `powershell.exe` vers ce proxy, envoie une requete NTP (`48` octets) vers `time.cloudflare.com:123` (via sa Fake-IP), verifie la reception d'une reponse NTP de `48` octets et les compteurs du serveur de test (`udp_associate_requests >= 1`, `udp_datagrams_relayed >= 1`, `udp_replies_relayed >= 1`), puis supprime la regle et le noeud proxy dans un bloc `finally`, arrete `socks5_udp_test_server.exe` et verifie via `ctl state` que le profil est revenu exactement a l'identique.
17. **`[Order 17/19]` Scenario `(r)`** : Lance `socks5_udp_test_server.exe` sur `127.0.0.1:1083` avec `--disable-udp-associate` (`REP = 0x07 Command not supported`), ajoute un noeud proxy et une regle UDP temporaires pour `powershell.exe` sur le port `123`, envoie une requete NTP vers `time.cloudflare.com:123`, verifie qu'aucune reponse n'est recue (aucune fuite `Direct`), que `udp_associate_refused >= 1` et que `ctl connections` enregistre `status="blocked"` / `routeLabel="BLOCKED"`, puis nettoie la regle et le proxy dans `finally`, arrete le serveur de test et verifie via `ctl state` que le profil est identique a l'etat initial.
18. **`[Order 18/19]` Scenario `(s)`** : Sans regle UDP temporaire, envoie une requete NTP UDP directe (`time.cloudflare.com:123`) depuis `powershell.exe`, verifie la reception de la reponse NTP (`48` octets) et controle que `ctl connections` et `ctl logs` enregistrent le flux UDP `Direct` attribue (`processName="powershell.exe"`, `protocol="udp"`, `routeLabel="DIRECT"`).
19. **`[Order 19/19]` Scenario `(j)`** *(necessite SOCKS5, execute en DERNIER)* : Arrete le processus SOCKS5 local en ecoute sur `-Socks5Port` pendant que l'interception est active (`securityPolicy.killSwitchEnabled = true`), execute `curl.exe`, verifie que `curl.exe` echoue sans repli en `Direct`, controle que `ctl connections` enregistre la connexion `curl.exe` avec `status="blocked"` et `routeLabel="BLOCKED"` et que `ctl logs` contient un `WARN` (`Kill-Switch blocked connection`), puis tente de relancer le processus SOCKS5 dans le bloc `finally` (ou affiche un avertissement explicite si un tunnel SSH interactif necessite une relance manuelle).

## Lecture du Rapport Genere

- **Sortie console** : Tous les messages console et du rapport sont rediges en anglais (encodage E/S `UTF-8` force ; aucun message localise du produit n'est recopie dans les lignes de resultat des scenarios). Affiche une ligne `[PASS]`, `[FAIL]` ou `[SKIP]` par scenario avec son ordre `[Order XX/19]` et sa lettre stable `Scenario (x)`, puis le resume `X PASS / Y FAIL / Z SKIP`. Le code de sortie vaut `0` uniquement si `FAIL == 0`.
- **Fichier de rapport horodate** : Cree en UTF-8 a cote du script sous le nom `RouteWard_TestReport_<yyyyMMdd_HHmmss>.txt`. Il contient :
  1. Le resume des scenarios, l'ordre d'execution explicite et les informations systeme / version PowerShell.
  2. La version et la taille en octets de `routeward.exe`, `routeward-desktop.exe`, `socks5_udp_test_server.exe`, `WinDivert.dll` et `WinDivert64.sys`.
  3. Les notes d'audit (dont la chaine SDDL exacte du Named Pipe et l'etat de relance du serveur SOCKS5).
  4. Les sorties brutes des commandes `routeward ctl` et `routeward cleanup` lues en UTF-8 (avec masquage de tout mot de passe).
  5. Les 30 dernieres lignes du journal daemon et du journal utilisateur lues en UTF-8 (avec masquage de tout mot de passe).
