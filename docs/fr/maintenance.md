[English](../maintenance.md) | Français

# Guide de Maintenance

## Fichiers de Configuration (`configs/`)

Toutes les constantes opérationnelles, le profil par défaut et les palettes de couleurs se trouvent dans `configs/` :

- `configs/system_constants.json` : Définit les ports locaux par défaut (`10808`, `10809`, `10810`, `10853`, `10854`), les constantes `nftables` / `TPROXY` sous Linux (`linuxFwmark` : `21079` / `0x5257`, `linuxTproxyFwmark` : `21080`, `linuxTproxyRouteTable` : `100`, `linuxTproxyRulePriority` : `10810`, `linuxNftBinary` : `"nft"`, `linuxNftTableName` : `"routeward"`, `linuxNftChainName` : `"output"`), les délais d'attente (`pendingSynTimeoutMs` : `40`, `pendingUdpTimeoutMs` : `40`), le sous-réseau Fake-IP (`198.18.0.0/15`), les dossiers de journaux (`telemetry.windowsDaemonLogDir`, `telemetry.linuxDaemonLogDir`, `telemetry.windowsUserLogDir`, `telemetry.linuxUserLogDir`), le préfixe de fichier (`RouteWard`), la capacité du canal d'événements (`eventBroadcastCapacity` : `256`), les chemins protégés du profil actif (`ipc.windowsProfilePath` : `"%ProgramData%\\RouteWard\\active_profile.json"`, `ipc.linuxProfilePath` : `"/etc/routeward/active_profile.json"`) et les modèles de règles intégrés.
- `configs/default_profile.json` : Définit le profil de routage initial, les serveurs proxies, les chaînes, les règles, `dnsConfig` (`enableFakeIp`, `remoteDnsResolution`, `fakeIpCidr`, `upstreamDns`, `bypassDomains`) et `securityPolicy` (`killSwitchEnabled`, `blockUdpOnTcpOnlyProxy`, `blockQuicUdp443`, `strictDnsNoLocalFallback`, `blockEncryptedDnsBypass`, `unknownProcessAction`).
- `configs/themeforge_palettes.json` : Contient les 16 palettes Oklab canoniques de ThemeForge (`Dracula`, `Drakul`, `Striga`, `Cinder`, `Bracken`, `Tarn`, `Mortis`, `Slate`, `Voivode`, `Carmilla`, `Whitby`, `Vesper`, `Parchment`, `Folio`, `Wormwood`, `Sconce`), `HighContrast` et les 9 teintes d'accent.

Comme `routeward-core` embarque ces fichiers JSON via `include_str!`, il faut recompiler le workspace Rust après toute modification dans `configs/`.

## Internationalisation (`locales/`)

- Les dictionnaires de traduction se trouvent dans `locales/fr.json` et `locales/en.json`.
- Les clés respectent la convention `<module>.<composant>.<element>.<action>`.
- Maintenir les deux fichiers synchronisés lors de tout ajout de clé et utiliser exclusivement la ponctuation ASCII (`-`, `:`, `"`, `'`, `...`).

## Journalisation (`logs/`)

- `FileLogger` (`crates/routeward-core/src/logger/mod.rs`) écrit un fichier quotidien (`RouteWard_<yyyyMMdd>.log`) dans les dossiers système dédiés au daemon et à l'utilisateur (`%ProgramData%\RouteWard\logs` et `%LOCALAPPDATA%\RouteWard\logs` sous Windows ; `/var/log/routeward` et `$XDG_STATE_HOME/routeward/logs` sous Linux).
- Format : `[yyyy-MM-dd HH:mm:ss] [LEVEL] [Component] message` (heure locale).
- La journalisation est activée par défaut (`enableLogging: true` dans `ProfileConfig`) et peut être activée ou désactivée à chaud sans redémarrer l'application.
- Les dossiers `logs/` locaux du dépôt sont ignorés par Git.

## Vérifications de Qualité

Exécuter régulièrement la suite de formatage, d'analyse statique et de tests :

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
Set-Location ui
npm test
npm run build
Set-Location ..
```
