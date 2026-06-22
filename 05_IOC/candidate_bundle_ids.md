# Candidate Bundle IDs — forensic discovery

> **Artefact défensif** — recommandation **#12** du rapport §14.
> Sortie de `06_LOCAL_REPRODUCER/forensic_discovery.py`.
> Chaque candidat **doit être validé manuellement** avant ajout
> à `FORBIDDEN_BUNDLE_IDS` dans `apple_drm_defense.py`.

## Sources scannées (1)
- `C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\03_OUTPUTS\strings_all_long.txt`

## Résultats
- **Candidats à valider** : 1
- **Déjà catalogués** : 2

## 🔍 Candidats

| Bundle ID | Patterns matchés | Raison |
|---|---|---|
| `com.iremovalpro.bypas` | `iRemoval`, `iremovalpro` | match 2 pattern(s) bypass: iRemoval, iremovalpro |

## ✅ Déjà catalogués (auto-test OK)

- `com.iremovalpro.bypass` — présent dans FORBIDDEN_BUNDLE_IDS
- `com.panyolsoft.blackhound` — présent dans FORBIDDEN_BUNDLE_IDS

## 📋 Prochaine étape

1. Pour chaque **candidat**, confirmer via :
   - Reverse engineering (Ghidra dump, NativeAOT strings)
   - Recherche OSINT (Twitter/X, GitHub, Telegram channels)
   - Corrélation avec `ioc_catalog.md` et `MITRE_MAPPING.md`
2. Si confirmé → ajouter à `FORBIDDEN_BUNDLE_IDS` dans
   `06_LOCAL_REPRODUCER/apple_drm_defense.py` avec description.
3. Si faux positif → ajouter au set `KNOWN_FALSE_POSITIVES`
   dans ce script pour éviter récurrence.
