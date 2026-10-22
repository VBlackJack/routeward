# Depannage (Troubleshooting)

## 1. `routeward-desktop` echoue a la compilation car `ui/dist` est absent

**Symptome** :
Erreur de compilation dans `apps/desktop/src/main.rs` indiquant que `../../../ui/dist/index.html` ou `../../../ui/dist/assets/app.js` est introuvable.

**Solution** :
Compiler le bundle frontend avant de compiler `routeward-desktop` :

```powershell
Set-Location ui
npm install
npm run build
Set-Location ..
cargo build -p routeward-desktop
```

## 2. Port du relais local (`10808`, `10809` ou `10853`) deja occupe

**Symptome** :
La vue `Journaux` ou le fichier `logs/RouteWard_<yyyyMMdd>.log` signale une erreur d'ecoute sur `127.0.0.1:10808`, `127.0.0.1:10809` ou `127.0.0.1:10853`.

**Solution** :
- Verifier qu'une autre instance de `routeward` ou `routeward-desktop` ne tourne pas deja en arriere-plan.
- Ou modifier `defaultRelayTcpPort`, `defaultRelayHttpPort` et `defaultDnsListenPort` dans `configs/system_constants.json`.

## 3. Les applications ignorent les regles de routage

**Symptome** :
Une application se connecte directement a Internet sans passer par le relais local.

**Cause** :
L'interception transparente des paquets au niveau de l'OS (WinDivert / WFP sous Windows, nftables / TUN sous Linux) n'est pas encore implementee (prevue aux Milestones 1 et 2).

**Contournement actuel** :
- Utiliser le bouton **Lancer App via Proxy** dans la barre superieure pour injecter `ALL_PROXY`, `HTTP_PROXY` et `HTTPS_PROXY` dans le processus cible.
- Ou activer le **Proxy Systeme** pour les applications compatibles avec la configuration WinINet de Windows.

## 4. Aucun fichier de journal n'est cree dans `logs/`

**Symptome** :
Le fichier `logs/RouteWard_<yyyyMMdd>.log` n'apparait pas ou ne se met plus a jour.

**Solution** :
Verifier que `enableLogging` est a `true` dans le profil actif (`configs/default_profile.json`) et que le repertoire courant dispose des droits d'ecriture.
