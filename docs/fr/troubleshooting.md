[English](../troubleshooting.md) | Français

# Dépannage (Troubleshooting)

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
