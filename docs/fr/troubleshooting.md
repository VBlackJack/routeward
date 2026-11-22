[English](../troubleshooting.md) | Français

# Dépannage (Troubleshooting)

## 0. Je n'ai plus Internet

Faites ces étapes dans l'ordre. Arrêtez-vous dès que votre Internet refonctionne. Une action par ligne.

**Étape A - Utiliser le raccourci du menu Démarrer (aucun droit administrateur requis)**

- [ ] Ouvrez le menu Démarrer.
- [ ] Tapez `RouteWard - Restore Internet`.
- [ ] Cliquez dessus.
- [ ] Patientez quelques secondes, puis essayez un site web.

Ce raccourci lance `routeward recover --pause-at-end` : il désactive la protection et rétablit vos paramètres de proxy Windows.

**Étape B - Mettre en pause depuis l'icône de la barre système**

- [ ] Repérez l'icône RouteWard près de l'horloge (cliquez sur la petite flèche si elle est masquée).
- [ ] Faites un clic droit sur l'icône.
- [ ] Cliquez sur **Pause 15 min**.
- [ ] Essayez un site web. La protection reprend toute seule à la fin de la pause.

**Étape C - Désactiver le proxy Windows à la main**

- [ ] Ouvrez les **Paramètres** de Windows.
- [ ] Allez dans **Réseau et Internet > Proxy**.
- [ ] Désactivez **Utiliser un serveur proxy**.
- [ ] Désactivez **Utiliser un script d'installation**.
- [ ] Essayez un site web.

**Étape D - Arrêter le service (utilisateurs avancés)**

- [ ] Ouvrez un terminal en tant qu'administrateur.
- [ ] Lancez `routeward service stop`.
- [ ] Essayez un site web.

**Étape E - Désinstaller (dernier recours)**

- [ ] Ouvrez les **Paramètres** de Windows, puis **Applications > Applications installées**.
- [ ] Sélectionnez **RouteWard** et cliquez sur **Désinstaller**.
- [ ] Redémarrez l'ordinateur.

La désinstallation rend les paramètres de proxy que RouteWard avait modifiés (voir [Désinstaller le MSI](build.md#désinstaller-le-msi-ce-qui-est-nettoyé-ce-qui-ne-lest-pas)).

Depuis un terminal, `routeward recover` fait la même chose que le raccourci du menu Démarrer.

## 0b. Dépannage Rapide dans l'Application Bureau (Mode Simple)

Si une application ou un site web ne charge plus lorsque la protection est active :

- **Débloquer en 1 clic** : depuis l'onglet **Accueil**, cliquez sur **Une app ne marche plus ?** pour voir les dernières connexions bloquées ou en erreur et autoriser l'application ou le site en **Direct**.
- **Mettre en pause temporairement** : utilisez **Pause 15 min** ou **Pause 1 h** depuis **Accueil** ; la protection se réactive automatiquement à la fin du délai.
- **Alerte coupure proxy** : si le Kill-Switch bloque Internet parce que votre proxy ne répond plus, une bannière propose directement **Pause 15 min** ou **Changer de proxy**.
- **Revenir à une base saine** : dans **Réglages**, cliquez sur **Rétablir les réglages par défaut**. RouteWard sauvegarde automatiquement votre profil actuel avant de réinitialiser.

## 1. Pare-feu Windows et Paquets Réfléchis Entrants (`TCP 10810`)

**Symptôme** :
Les connexions interceptées (`curl.exe`) expirent après environ 63 secondes si le pare-feu Windows Defender bloque le trafic TCP entrant sur le port `10810`.

**Cause** :
La technique de réflexion `streamdump` de WinDivert réécrit les paquets sortants du client en paquets entrants (`Outbound = 0`) à destination du relais TCP transparent local (`0.0.0.0:10810`). Comme Windows applique ses filtres de pare-feu entrants aux paquets réinjectés en `Outbound = 0`, le pare-feu doit autoriser le flux TCP entrant vers l'exécutable RouteWard sur le port `10810`.

**Gestion automatique et nettoyage manuel** :
- Au démarrage, `WinDivertInterceptor` crée automatiquement une règle entrante restreinte (`RouteWard_TransparentRelay_10810`, limitée au chemin de l'exécutable `routeward.exe`, `protocol=TCP`, `localport=10810`, `profile=any`) et la supprime à l'arrêt propre (`Ctrl+C` ou `--duration-secs`), en journalisant les deux actions sous `[WindowsFirewall]`.
- Si le processus a été interrompu brutalement avant le nettoyage, lancer `routeward cleanup` ou supprimer la règle manuellement dans PowerShell en Administrateur :

```powershell
routeward cleanup
# ou directement :
netsh advfirewall firewall delete rule name="RouteWard_TransparentRelay_10810"
```

## 2. Détection de WinDivert par les Antivirus et EDR (`HackTool` / PUA)

**Symptôme** :
Un agent EDR (Endpoint Detection and Response) ou un antivirus met en quarantaine `WinDivert64.sys` / `WinDivert.dll` ou remonte une alerte classant WinDivert comme outil de piratage (`HackTool`) ou application potentiellement indésirable (PUA).

**Cause** :
Bien que WinDivert soit une bibliothèque d'interception réseau open-source légitime, plusieurs solutions antivirus et EDR signalent son pilote noyau car il a également été détourné par des outils tiers.

**Solution** :
- **Ne jamais charger `WinDivert64.sys` directement sur un poste d'entreprise supervisé par un SOC/EDR** sans autorisation préalable.
- Effectuer tous les tests d'interception réelle dans une machine virtuelle isolée (par exemple Hyper-V ou VMware).
- RouteWard abstrait la capture réseau derrière le trait `Interceptor` (`crates/routeward-core/src/interceptor/backend.rs`) afin de permettre le branchement ultérieur d'un moteur alternatif (tel qu'un pilote WFP dédié).

## 3. `WinDivert.dll` introuvable lors de `routeward run`

**Symptôme** :
`routeward run` s'arrête avec l'erreur `errors.interceptor.driver_missing`.

**Solution** :
Les binaires WinDivert ne sont jamais versionnés dans Git. Télécharger et vérifier l'archive officielle WinDivert 2.2.2-A via le script fourni :

`WinDivert.dll` n'est chargée que depuis le dossier de l'exécutable (les entrées de `windivertDllPaths` y sont résolues) : la placer à côté de `routeward.exe` ou sous `third_party/windivert/bin/` à cet endroit. La variable `ROUTEWARD_WINDIVERT_DLL_PATH` n'est prise en compte que par les builds de débogage ; les builds de production l'ignorent.

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fetch-windivert.ps1
```

## 4. `WinDivertOpen` échoue avec l'erreur Win32 5 (`ERROR_ACCESS_DENIED`)

**Symptôme** :
`routeward run` s'arrête avec `WinDivertOpen(SOCKET) failed with Win32 error 5`.

**Solution** :
L'ouverture du filtre WinDivert requiert les droits **Administrateur**. Ouvrir PowerShell en tant qu'Administrateur dans la VM de test et lancer `routeward run --duration-secs 60`.

## 5. Interception `nftables` sous Linux et Nettoyage d'une Table Orpheline (`table ip routeward`)

**Symptôme** :
- `routeward run` s'arrête avec `errors.interceptor.not_root` ou `errors.interceptor.nft_missing`.
- Ou, si `routeward` et son processus watchdog ont été tués simultanément, le trafic TCP IPv4 sortant reste redirigé vers `:10810` et échoue.
- Ou, avec `securityPolicy.killSwitchEnabled = true`, le daemon a planté ou a été tué et l'hôte a échoué en mode fermé : la table nftables `inet routeward_ks` bloque tout le trafic sortant sauf le loopback, les connexions établies, DHCP, la découverte de voisins IPv6 et MLD. Vérifier avec `sudo nft list table inet routeward_ks` ; systemd relance le daemon après le plantage (`Restart=on-failure`), mais avec l'interception arrêtée : la table de blocage reste donc en place. Pour la retirer, exécuter `sudo routeward cleanup --force`, relancer l'interception avec `routeward ctl start`, ou redémarrer proprement le service avec `sudo systemctl restart routeward`. Sous Windows, un crash laisse toujours passer le trafic.

**Solution** :
- Exécuter `routeward` en tant que `root` (`sudo routeward run`) et vérifier que le paquet `nftables` (binaire `nft`) est installé.
- Pour supprimer à tout moment une table `table ip routeward` orpheline :

```bash
sudo routeward cleanup
# ou directement :
sudo nft delete table ip routeward
```

## 6. `routeward-desktop` échoue à la compilation car `ui/dist` est absent

**Symptôme** :
Erreur de compilation dans `apps/desktop/src/main.rs` indiquant que `../../../ui/dist/index.html` est introuvable.

**Solution** :
Compiler le bundle frontend avant de compiler `routeward-desktop` :

```powershell
Set-Location ui
npm install
npm run build
Set-Location ..
cargo build -p routeward-desktop
```

## 7. `WinDivert.dll` introuvable après installation via le `.msi` Windows

**Symptôme** :
L'installateur `.msi` s'est terminé sans erreur, mais l'interception échoue car `WinDivert.dll` est absent du dossier d'installation (les `.msi` de release embarquent WinDivert 2.2.2 ; le cas se produit avec un `.msi` compilé localement sans `-IncludeWinDivert`, ou après une suppression manuelle des fichiers).

**Solution** :
Exécuter le script `fetch-windivert.ps1` fourni dans le dossier d'installation depuis un PowerShell administrateur afin de télécharger et vérifier WinDivert dans `C:\Program Files\RouteWard\` :

```powershell
& "C:\Program Files\RouteWard\fetch-windivert.ps1" -OutputDirectory "C:\Program Files\RouteWard"
```

## 8. Serveur PAC local (`http://127.0.0.1:10811/proxy.pac`) ou routage Microsoft Edge

**Symptôme** :
Microsoft Edge ou les applications WinINET contournent toujours le proxy (ou échouent à charger le script PAC) après activation du PAC système ou import FoxyProxy.

**Solution** :
1. Vérifier que le daemon est démarré afin que `http://127.0.0.1:10811/proxy.pac` réponde HTTP `200`.
2. Contrôler que `AutoConfigURL` dans `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` pointe vers une URL loopback `http://127.0.0.1:<port>/...` (RouteWard refuse les URL non loopback).
3. Vérifier les exclusions `!` (`preset-edge-foxyproxy` exclut `localhost`, `*.local`, `*.lan`, `*.internal` et les plages RFC1918) et l'ordre de priorité des règles, ou désactiver le PAC système dans les Paramètres pour supprimer `AutoConfigURL`.

## 9. Erreurs sur Proxy HTTPS d'entreprise (`407 Negotiate` / `NTLM` ou CA auto-signée)

**Symptôme** :
Les flux routés via un noeud `http` ou `https` échouent avec une erreur `407 Proxy Authentication Required` ou une erreur de certificat TLS visible dans `errorDetail` de l'Activité.

**Solution** :
- **SSPI Windows (`Negotiate` / `NTLM`)** : Laisser les champs utilisateur et mot de passe vides sur le noeud pour utiliser la session Windows active, ou renseigner des identifiants explicites si le proxy exige une authentification basique.
- **Identifiants Basic** : les identifiants Basic ne sont plus envoyés de façon préemptive à un proxy HTTP en clair. RouteWard envoie d'abord `CONNECT` sans identifiants et répond par eux à un `407` proposant `Basic` ; avec un noeud proxy `https` (TLS), ils partent toujours dès la première requête.
- **Certificat d'inspection auto-signé** : Activer `tlsSkipVerify` sur le noeud proxy `https` uniquement pour un proxy d'entreprise de confiance dont l'autorité racine n'est pas installée sur le poste.

## 10. Erreur de permission sur les profils nommés (dossier `profiles/`)

**Symptôme** :
Le listage, la sauvegarde ou le basculement des profils nommés échoue lorsque le daemon tourne avec privilèges élevés.

**Solution** :
Vérifier que `%ProgramData%\RouteWard\profiles` (Windows) ou `/etc/routeward/profiles` (Linux) est un répertoire standard et non un lien symbolique, puis contrôler que son propriétaire et ses ACL restreignent l'accès au compte du daemon (`Administrators` / `SYSTEM` sous Windows, `root` sous Linux).

## 11. Échec immédiat du démarrage UAC sous Windows (`insecure_profile` ou code de sortie)

**Symptôme** :
Cliquer sur **Démarrer le Service** puis valider l'invite UAC Windows ne connecte pas le daemon et affiche une notification d'erreur ou journalise un arrêt précoce dans `%LOCALAPPDATA%\RouteWard\logs`.

**Solution** :
1. Consulter `%LOCALAPPDATA%\RouteWard\logs` pour relever le code de sortie exact renvoyé par `routeward.exe daemon` (code `10` : privilèges non élevés, `11` : droits ou propriétaire non sécurisés sur `%ProgramData%\RouteWard`, `12` : échec d'ouverture du canal IPC).
2. Si le code `11` signale un fichier `C:\ProgramData\RouteWard\active_profile.json` préexistant ou un lien symbolique/jonction avec des droits utilisateur non privilégiés, contrôler les ACL dans un terminal PowerShell administrateur :

```powershell
icacls "C:\ProgramData\RouteWard"
```

## 12. L'hôte est un serveur DNS

**Symptôme** :
Un serveur DNS exécuté sur la même machine (rôle Serveur DNS Windows `dns.exe`, ou `named`, `unbound`, `dnsmasq`, `pihole-FTL`, `pdns_recursor`, `kresd`, `dnsdist`, `coredns` sous Linux) répond à ses propres clients avec des adresses `198.18.x.x`, ou les met en cache.

**Cause** :
Un serveur DNS fait sa récursion vers Internet sur le port `53`. Avec Fake-IP actif, RouteWard répond à toute requête du port `53` par une Fake-IP : le serveur mettrait donc en cache, puis servirait, des adresses qui n'existent que dans RouteWard.

**Comportement** :
- **Exemptés par défaut** : sous Windows, uniquement `%SystemRoot%\System32\dns.exe` (un `dns.exe` situé ailleurs n'est pas exempté) ; sous Linux, les exécutables `named`, `unbound`, `dnsmasq`, `pihole-FTL`, `pdns_recursor`, `kresd`, `dnsdist` et `coredns`, et seulement si le binaire se trouve dans `/usr/sbin`, `/usr/bin`, `/usr/local/sbin`, `/usr/local/bin` ou `/usr/libexec`. `svchost.exe`, `systemd-resolved` et RouteWard lui-même ne peuvent jamais être exemptés.
- **Ce que signifie l'exemption** : les requêtes de ce processus sortent sans modification (ni Fake-IP, ni relais). Le kill switch et `remoteDnsResolution` ne s'y appliquent pas.
- **Règle Block explicite** : une règle Block dont `processPatterns` désigne le processus bloque toujours ses requêtes DNS. L'action par défaut et les règles sans motif de processus ne les bloquent pas.
- **DoT** : le port `853` reste bloqué par `securityPolicy.blockEncryptedDnsBypass`, serveurs DNS compris.
- **Les applications locales perdent la Fake-IP** : les applications de cette machine interrogent le serveur local en loopback, que RouteWard ne capture pas. Elles reçoivent de vraies adresses : une règle de domaine ne peut alors correspondre que par le SNI TLS ou l'en-tête HTTP `Host:`.
- **Journal** : chaque processus exempté est journalisé une fois en `INFO` (`Exempting DNS server process <nom> (PID <pid>) from Fake-IP`) ; chaque requête l'est en `DEBUG`, et une ligne `INFO` limitée en fréquence résume le flux.

**Ajouter ou retirer un processus** :
Modifier `dnsConfig.dnsServerProcesses` dans le profil (champ omis du JSON quand la liste est vide) :

```json
"dnsConfig": {
  "dnsServerProcesses": ["C:\\Tools\\mydns.exe", "!dnsmasq"]
}
```

- Un chemin complet ou un nom de fichier ajoute un processus. Sous Linux, un nom de fichier ne correspond encore qu'aux binaires des dossiers système ci-dessus ; sous Windows, une entrée réduite au nom correspond à n'importe quel chemin.
- `!nom` retire une valeur par défaut. Utiliser `!dnsmasq` sur les postes de travail où NetworkManager lance `dnsmasq` comme cache local (`dns=dnsmasq`) : sinon leurs propres applications cesseraient de recevoir des Fake-IP.
- Les entrées vides, un `*` seul et tout motif qui correspondrait à `svchost.exe`, `systemd-resolved` ou RouteWard sont refusés au chargement ou au remplacement du profil.
- Un profil dont la liste n'est pas vide est refusé par les anciens daemons (le champ leur est inconnu) ; une liste vide est omise et reste compatible.

**Limites sous Linux** :
- L'exemption fonctionne par identifiant utilisateur, dans `nftables` (ensembles `dns_server_uids` et `dns_server_block_uids`). Un serveur exécuté en `root` ou `nobody`, ou partageant son identifiant avec un autre processus actif, n'est **pas** exempté : RouteWard le signale une fois par un avertissement et le laisse redirigé.
- Lire `/proc/<pid>/exe` des processus d'autres utilisateurs exige `CAP_SYS_PTRACE`, que l'unité systemd fournie accorde. Sans elle, un serveur DNS d'un autre utilisateur n'est pas reconnu.
- En mode garde IPv6 (pas de NAT IPv6), le port `53` IPv6 brut est rejeté : un serveur exempté ne peut donc pas non plus faire sa récursion en IPv6.
- Une règle Block sous Linux agit sur tout l'identifiant utilisateur : la rédiger avec `processPatterns` seul (sans condition de port ni d'adresse).
- Un serveur qui ouvre ses sockets en `root` puis abandonne ses privilèges conserve l'uid 0 sur les sockets ouverts avant le changement : ces sockets ne sont pas exemptés.
- Un serveur DNS démarré après une analyse peut encore recevoir des réponses Fake-IP pendant au plus `dns.dnsServerProcessScanIntervalMs` (5 s par défaut), jusqu'à la prochaine analyse qui le reconnaît.

**Limites sous Windows** :
- Seul le `dns.exe` de System32 est exempté par défaut. La liste des processus est réanalysée toutes les `dns.dnsServerProcessScanIntervalMs` (5 s) et à chaque rechargement du profil ; un `dns.exe` redémarré est aussi reconnu aussitôt, dès son premier événement de socket.

## 13. Les connexions ouvertes avant le démarrage gardent leur route

**Symptôme** :
Après `routeward ctl start`, une application déjà connectée (un onglet de navigateur, un téléchargement, un client de messagerie) garde son ancienne route : elle n'est pas proxifiée, et une règle `Block` ne la coupe pas.

**Cause** :
Limitation connue : RouteWard ne dirige que les **nouvelles** connexions. Sous Windows, WinDivert voit le `SYN` d'une nouvelle connexion ; sous Linux, `nftables` ne redirige que les nouvelles connexions. Une connexion déjà établie garde sa route d'origine, y compris en contournant les règles `Block`, jusqu'à ce que l'application se reconnecte. RouteWard ne réinitialise pas les connexions existantes.

**Comportement** :
Au démarrage du moteur sous Windows, RouteWard journalise une ligne `INFO` du type `N connections opened before start are not intercepted until they reconnect (chrome.exe x12, ...); restart these apps`. Elle compte les connexions TCP établies dont le processus correspond désormais à une règle `Proxy`, `Chain` ou `Block`. L'analyse est en lecture seule et ne s'exécute qu'une fois, hors du chemin des paquets.

**Solution** :
Redémarrer les applications listées (ou recharger la page, ou rouvrir la session) pour que leurs nouvelles connexions passent par RouteWard.

## 14. Dépannage Rapide Débutant (App bloquée, site ignoré ou imprimante locale inaccessible)

- **Internet se coupe quand RouteWard est réduit dans la barre système** : RouteWard affiche une notification Windows native lorsque le proxy ne répond plus et que le coupe-circuit protège votre vraie IP. Faites un clic droit sur l'icône colorée dans la barre système et choisissez **Pause 15 minutes** (ou ouvrez RouteWard et cliquez sur **Passer en principal** sur un autre proxy).
- **Une application ou un site précis ne fonctionne plus** : cliquez sur **Une app ne marche plus ?** sur l'Accueil en Mode Simple pour l'autoriser en Direct en 1 clic.
- **Une règle d'exclusion de site semble ignorée** : utilisez le champ **Par où passe un site ?** dans **Mes Apps & Sites**. Si une règle plus large passe devant, RouteWard affiche un avertissement avec un bouton **Faire passer en premier** en 1 clic.
- **Box Internet (`192.168.x.x`) ou imprimante Wi-Fi inaccessible** : activez le pack en 1 clic **Box & Imprimantes (Réseau local)** dans **Mes Apps & Sites**.

## 15. "Quitter" Garde la Protection Active en Arrière-Plan

RouteWard fonctionne normalement via son service Windows, qui démarre avec l'ordinateur. Fermer la fenêtre ne fait que la masquer dans la zone de notification (un message affiché une seule fois l'explique). Choisir **Quitter** dans le menu de l'icône ferme l'application, mais **la protection continue en arrière-plan grâce au service** : vos applications restent protégées et le coupe-circuit reste actif.

Pour vraiment arrêter la protection :

- [ ] Ouvrez RouteWard (ou faites un clic droit sur l'icône de la barre système).
- [ ] Cliquez sur **Pause** (pour une durée choisie, la protection reprend toute seule, même après un redémarrage), ou désactivez la protection.
- [ ] Choisissez ensuite **Quitter** si vous voulez aussi fermer l'application.

Si vous êtes déjà coupé d'Internet, retournez à la section 0. Depuis un terminal, `routeward ctl pause --seconds 900` met la protection en pause pendant 15 minutes.

RouteWard démarre avec l'icône de la barre système à l'ouverture de session (réduit, sans fenêtre). La protection est mémorisée : si elle était active, elle revient après un redémarrage.
