# Depannage (Troubleshooting)

## 1. Detection de WinDivert par les Antivirus et EDR (`HackTool` / PUA)

**Symptome** :
Un agent EDR (Endpoint Detection and Response) ou un antivirus met en quarantaine `WinDivert64.sys` / `WinDivert.dll` ou remonte une alerte classant WinDivert comme outil de piratage (`HackTool`) ou application potentiellement indesirable (PUA).

**Cause** :
Bien que WinDivert soit une bibliotheque d'interception reseau open-source legitime, plusieurs solutions antivirus et EDR signalent son pilote noyau car il a egalement ete detourne par des outils tiers.

**Solution** :
- **Ne jamais charger `WinDivert64.sys` directement sur un poste d'entreprise supervise par un SOC/EDR** sans autorisation prealable.
- Effectuer tous les tests d'interception reelle dans une machine virtuelle isolee (par exemple Hyper-V).
- RouteWard abstrait la capture reseau derriere le trait `Interceptor` (`crates/routeward-core/src/interceptor/backend.rs`) afin de permettre le branchement ulterieur d'un moteur alternatif (tel qu'un pilote WFP dedie).

## 2. `WinDivert.dll` introuvable lors de `routeward run`

**Symptome** :
`routeward run` s'arrete avec l'erreur `errors.interceptor.driver_missing`.

**Solution** :
Les binaires WinDivert ne sont jamais versionnes dans Git. Telecharger et verifier l'archive officielle WinDivert 2.2.2-A via le script fourni :

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\fetch-windivert.ps1
```

Ce script verifie l'empreinte SHA-256 (`63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`) et extrait `WinDivert.dll` et `WinDivert64.sys` dans `third_party/windivert/bin/`.

## 3. `WinDivertOpen` echoue avec l'erreur Win32 5 (`ERROR_ACCESS_DENIED`)

**Symptome** :
`routeward run` s'arrete avec `WinDivertOpen(SOCKET) failed with Win32 error 5`.

**Solution** :
L'ouverture du filtre WinDivert requiert les droits **Administrateur**. Ouvrir PowerShell en tant qu'Administrateur dans la VM de test et lancer `routeward run --duration-secs 60`.

## 4. `routeward-desktop` echoue a la compilation car `ui/dist` est absent

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
