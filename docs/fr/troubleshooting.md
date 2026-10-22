# Depannage (Troubleshooting)

## 1. Pare-feu Windows et Paquets Reflechis Entrants (`TCP 10810`)

**Symptome** :
Les connexions interceptees (`curl.exe`) expirent apres environ 63 secondes si le pare-feu Windows Defender bloque le trafic TCP entrant sur le port `10810`.

**Cause** :
La technique de reflexion `streamdump` de WinDivert reecrit les paquets sortants du client en paquets entrants (`Outbound = 0`) a destination du relais TCP transparent local (`0.0.0.0:10810`). Comme Windows applique ses filtres de pare-feu entrants aux paquets reinjectes en `Outbound = 0`, le pare-feu doit autoriser le flux TCP entrant vers l'executable RouteWard sur le port `10810`.

**Gestion automatique et nettoyage manuel** :
- Au demarrage, `WinDivertInterceptor` cree automatiquement une regle entrante restreinte (`RouteWard_TransparentRelay_10810`, limitee au chemin de l'executable `routeward.exe`, `protocol=TCP`, `localport=10810`, `profile=any`) et la supprime a l'arret propre (`Ctrl+C` ou `--duration-secs`), en journalisant les deux actions sous `[WindowsFirewall]`.
- Si le processus a ete interrompu brutalement avant le nettoyage, supprimer la regle manuellement dans PowerShell en Administrateur :

```powershell
netsh advfirewall firewall delete rule name="RouteWard_TransparentRelay_10810"
```

## 2. Detection de WinDivert par les Antivirus et EDR (`HackTool` / PUA)

**Symptome** :
Un agent EDR (Endpoint Detection and Response) ou un antivirus met en quarantaine `WinDivert64.sys` / `WinDivert.dll` ou remonte une alerte classant WinDivert comme outil de piratage (`HackTool`) ou application potentiellement indesirable (PUA).

**Cause** :
Bien que WinDivert soit une bibliotheque d'interception reseau open-source legitime, plusieurs solutions antivirus et EDR signalent son pilote noyau car il a egalement ete detourne par des outils tiers.

**Solution** :
- **Ne jamais charger `WinDivert64.sys` directement sur un poste d'entreprise supervise par un SOC/EDR** sans autorisation prealable.
- Effectuer tous les tests d'interception reelle dans une machine virtuelle isolee (par exemple Hyper-V ou VMware).
- RouteWard abstrait la capture reseau derriere le trait `Interceptor` (`crates/routeward-core/src/interceptor/backend.rs`) afin de permettre le branchement ulterieur d'un moteur alternatif (tel qu'un pilote WFP dedie).

## 3. `WinDivert.dll` introuvable lors de `routeward run`

**Symptome** :
`routeward run` s'arrete avec l'erreur `errors.interceptor.driver_missing`.

**Solution** :
Les binaires WinDivert ne sont jamais versionnes dans Git. Telecharger et verifier l'archive officielle WinDivert 2.2.2-A via le script fourni :

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fetch-windivert.ps1
```

## 4. `WinDivertOpen` echoue avec l'erreur Win32 5 (`ERROR_ACCESS_DENIED`)

**Symptome** :
`routeward run` s'arrete avec `WinDivertOpen(SOCKET) failed with Win32 error 5`.

**Solution** :
L'ouverture du filtre WinDivert requiert les droits **Administrateur**. Ouvrir PowerShell en tant qu'Administrateur dans la VM de test et lancer `routeward run --duration-secs 60`.

## 5. `routeward-desktop` echoue a la compilation car `ui/dist` est absent

**Symptome** :
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
