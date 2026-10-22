# Contribuer a RouteWard

## Licence et Droit d'auteur

Toutes les contributions sont placees sous licence Apache 2.0. Chaque nouveau fichier source doit commencer par l'en-tete Apache 2.0 standard :

```text
Copyright 2026 Julien Bombled
```

## Regle de Versionnement (CalVer)

RouteWard utilise le versionnement calendaire (CalVer) :

- **Format des releases et tags Git** : `vYYYY.MMDD.NN` (par exemple `v2026.0105.00` pour le premier build du 5 janvier 2026, ou `v2026.1022.00` pour le 22 octobre 2026).
- **Format des manifestes (`Cargo.toml` et `ui/package.json`)** : Cargo et npm appliquent les regles SemVer strictes et refusent les zeros en tete d'identifiant numerique. Les fichiers manifestes utilisent donc la valeur entiere de `MMDD` et `NN` sans zero initial :
  - Format : `YYYY.<MMDD en entier>.<NN en entier>`
  - Exemple pour le `2026-01-05` build `00` : `2026.105.0`
  - Exemple pour le `2026-10-22` build `00` : `2026.1022.0`

## Qualite du Code et Hygiene

- **Langue** : Le code source, les commentaires, les identifiants, la documentation inline et les messages de commit doivent etre rediges exclusivement en anglais.
- **Zero valeur en dur** :
  - Les textes visibles par l'utilisateur doivent figurer dans `locales/fr.json` et `locales/en.json` et passer par le systeme i18n.
  - Les ports, delais d'attente, tailles de tampons et constantes reseau doivent etre definis dans `configs/system_constants.json` ou dans des constantes nommees.
- **Ponctuation ASCII** : Utiliser uniquement la ponctuation ASCII (`-`, `:`, `"`, `'`, `...`) dans le code, les fichiers JSON et la documentation.
- **Commits conventionnels** : Utiliser le format Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).

## Verifications avant Commit

Lancer les commandes suivantes a la racine du depot avant chaque commit :

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Et dans le dossier `ui/` :

```powershell
npm run build
```
