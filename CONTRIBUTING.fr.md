[English](CONTRIBUTING.md) | Français

# Contribuer à RouteWard

## Licence et Droit d'Auteur

Toutes les contributions sont placées sous licence Apache 2.0. Chaque nouveau fichier source doit commencer par l'en-tête Apache 2.0 standard :

```text
Copyright 2026 Julien Bombled
```

## Règle de Versionnement (CalVer)

RouteWard utilise le versionnement calendaire (CalVer) :

- **Format des releases et tags Git** : `vYYYY.MMDD.NN` (par exemple `v2026.0105.00` pour le premier build du 5 janvier 2026, ou `v2026.1022.00` pour le 22 octobre 2026).
- **Format des manifestes (`Cargo.toml` et `ui/package.json`)** : Cargo et npm appliquent les règles SemVer strictes et refusent les zéros en tête d'identifiant numérique. Les fichiers manifestes utilisent donc la valeur entière de `MMDD` et `NN` sans zéro initial :
  - Format : `YYYY.<MMDD en entier>.<NN en entier>`
  - Exemple pour le `2026-01-05` build `00` : `2026.105.0`
  - Exemple pour le `2026-10-22` build `00` : `2026.1022.0`

## Qualité du Code et Hygiène

- **Langue** : Le code source, les commentaires, les identifiants, la documentation inline et les messages de commit doivent être rédigés exclusivement en anglais.
- **Zéro Valeur en Dur** :
  - Les textes visibles par l'utilisateur doivent figurer dans `locales/fr.json` et `locales/en.json` et passer par le système i18n.
  - Les ports, délais d'attente, tailles de tampons et constantes réseau doivent être définis dans `configs/system_constants.json` ou dans des constantes nommées.
- **Ponctuation ASCII** : Utiliser uniquement la ponctuation ASCII (`-`, `:`, `"`, `'`, `...`) dans le code, les fichiers JSON et la documentation.
- **Commits Conventionnels** : Utiliser le format Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).

## Vérifications avant Commit

Lancer les commandes suivantes à la racine du dépôt avant chaque commit :

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Et dans le dossier `ui/` :

```powershell
npm test
npm run build
```
