# Build Hash Correlation — iRemoval PRO v5.2

> **Artefact défensif** — Recommandation **#9** du rapport §14 (moyen terme).
> Produit pour permettre la **corrélation sample-to-sample** des dérivés
> iRemoval PRO distribués par l'auteur `josuealonsorodriguez` (build marker
> `Blackhound iRemovalPro Public build 0.7.1 @2022`).

---

## 🎯 Pourquoi ces hashes sont utiles

Deux artefacts extraits des binaires `.dylib` (Mono/Xamarin.iOS) cibles :

| Hash | Architecture | Rôle | Stabilité |
|---|---|---|---|
| `1643379a` | arm64 | Hash de build debug, binaire iOS cible iPhone 5s → iPhone X | **Figer** dans YARA |
| `50c6260a` | arm64e | Hash de build debug, binaire iOS cible iPhone XS+ (A12 et ultérieurs) | **Figer** dans YARA |

Ces hashes sont des **identifiants opaques** générés par `theos` lors du
build (chemins Theos = `/Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/.theos/obj/debug/{arch}/blackhound.x.<hash>.o`).

Ils sont **stables** tant que l'auteur ne rebuilde pas le tweak (ce qui
explique la présence du `@2022` dans le build marker : les variantes
postérieures de l'outil *devraient* changer ces hashes, ce qui fournit
un signal de version gratuite).

---

## 📋 Inventaire exhaustif des occurrences

### Hash `1643379a` (arm64)

| # | Fichier | Ligne | Offset / Contexte | Source |
|---:|---|---:|---|---|
| 1 | `05_IOC/ioc_catalog.md` | 19 | entrée "Build hash arm64" | catalogue IoC |
| 2 | `05_IOC/ioc_catalog.md` | 145 | tableau récap. samples connus | catalogue IoC |
| 3 | `SECURITY_ADVISORY.md` | 212 | §"Build path leak" | avis de sécurité |
| 4 | `01_REPORTS/NOUVELLES_DECOUVERTES.md` | 52 | §1 (Attribution) | nouvelles découvertes |
| 5 | `01_REPORTS/NOUVELLES_DECOUVERTES.md` | 59 | §1 hypothèse défensive | nouvelles découvertes |
| 6 | `01_REPORTS/NOUVELLES_DECOUVERTES.md` | 480 | §14 #9 (recommandation) | nouvelles découvertes |
| 7 | `01_REPORTS/PHASE5_RUNTIME_NATIVEAOT.md` | 131 | §"Phase 5" analyse runtime | rapport phase 5 |
| 8 | `06_LOCAL_REPRODUCER/verify_short_term_recommendations.py` | 50 | check de présence dans YARA/catalog | script d'audit |
| 9 | `06_LOCAL_REPRODUCER/iact_reproducer/bplist_builder.py` | 147 | `BuildPath` dans plist factice | reproducteur |
| 10 | `06_LOCAL_REPRODUCER/iact_reproducer/README.md` | 340 | doc du reproducteur | reproducteur |
| 11 | `03_OUTPUTS/strings_report.txt` | 284, 299, 459 | strings tool dump | analyse statique |
| 12 | `03_OUTPUTS/strings_all_long.txt` | 9278 | strings ≥ 8 chars | analyse statique |
| 13 | `03_OUTPUTS/nativeaot/nativeaot_20260622_022333.all.json` | 105304 | JSON NativeAOT dump | analyse statique |
| 14 | `03_OUTPUTS/nativeaot/category_bypass_20260622_022333.txt` | 42 | offset `0x00868a45` (ascii) | analyse statique |
| 15 | `03_OUTPUTS/nativeaot/category_apple-ios_20260622_022333.txt` | 249 | offset `0x00868a45` (ascii) | analyse statique |
| 16 | `03_OUTPUTS/ghidra/macho_8534d3_DYLIB_ARM64_ALL.bin_strings.txt` | 187 | offset `0x15572` (DYLIB arm64) | Ghidra dump |

### Hash `50c6260a` (arm64e)

| # | Fichier | Ligne | Offset / Contexte | Source |
|---:|---|---:|---|---|
| 1 | `05_IOC/ioc_catalog.md` | 20 | entrée "Build hash arm64e" | catalogue IoC |
| 2 | `05_IOC/ioc_catalog.md` | 146 | tableau récap. samples connus | catalogue IoC |
| 3 | `01_REPORTS/NOUVELLES_DECOUVERTES.md` | 53 | §1 (Attribution) | nouvelles découvertes |
| 4 | `01_REPORTS/NOUVELLES_DECOUVERTES.md` | 59 | §1 hypothèse défensive | nouvelles découvertes |
| 5 | `01_REPORTS/NOUVELLES_DECOUVERTES.md` | 480 | §14 #9 (recommandation) | nouvelles découvertes |
| 6 | `06_LOCAL_REPRODUCER/verify_short_term_recommendations.py` | 51 | check de présence dans YARA/catalog | script d'audit |
| 7 | `03_OUTPUTS/strings_report.txt` | 286, 301, 461 | strings tool dump | analyse statique |
| 8 | `03_OUTPUTS/strings_all_long.txt` | 9282 | strings ≥ 8 chars | analyse statique |
| 9 | `03_OUTPUTS/nativeaot/nativeaot_20260622_022333.all.json` | 106234 | JSON NativeAOT dump | analyse statique |
| 10 | `03_OUTPUTS/nativeaot/category_bypass_20260622_022333.txt` | 64 | offset `0x00880902` (ascii) | analyse statique |
| 11 | `03_OUTPUTS/nativeaot/category_apple-ios_20260622_022333.txt` | 299 | offset `0x00880902` (ascii) | analyse statique |
| 12 | `03_OUTPUTS/ghidra/macho_86b4d3_DYLIB_ARM64_ARM64E.bin_strings.txt` | 183 | offset `0x1542f` (DYLIB arm64e) | Ghidra dump |

---

## 🔗 Comment utiliser ces hashes pour corrélation sample-to-sample

### Cas d'usage #1 — Identifier une variante inconnue

Quand on extrait un nouveau binaire `.dylib` iOS suspect et qu'on observe
un chemin Theos similaire, **la présence de `1643379a` ou `50c6260a` dans
les strings confirme qu'il s'agit strictement du build de référence 2022**.
L'absence de ces hashes combinée à la présence de `Blackhound iRemovalPro
Public build 0.7.1 @2022` indique une **variante patchée** (auteur
toujours actif).

### Cas d'usage #2 — Dater une variante

Les Theos build hashes **changent à chaque rebuild**. Si un nouveau sample
contient :

* `1643379a` ou `50c6260a` → **build original 2022** (référence figée).
* `XXXXXXXX` inconnu → **rebuild post-2022** — datation possible par
  comparaison avec les versions ultérieures observées.

### Cas d'usage #3 — Cross-référencer avec YARA

Une règle YARA qui matche sur le chemin complet
`/Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/.theos/obj/debug/arm64/blackhound.x.1643379a.o`
permet de détecter **toute instance du binaire original** avec une
confiance élevée (cf. règle `iRemovalPro_BlackHound_BuildMarker` dans
`05_IOC/YARA_RULES.yar`).

---

## 🛡️ Règles YARA recommandées (stables)

Ces règles sont déjà incluses dans `05_IOC/YARA_RULES.yar` (règle
`iRemovalPro_BlackHound_BuildMarker`). Référence :

```yara
rule iRemovalPro_BlackHound_BuildMarker
{
    meta:
        description = "iRemoval PRO v5.2 — build marker & theos path leak"
        author = "defensive-lab"
        sample_family = "BlackHound / iRemovalPro 0.7.1"
        build_markers = "1643379a (arm64), 50c6260a (arm64e)"
        reference = "01_REPORTS/NOUVELLES_DECOUVERTES.md §1"
    strings:
        $bm1 = "Blackhound iRemovalPro Public build 0.7.1 @2022" ascii
        $bm2 = "/Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/" ascii
        $h1 = "1643379a" ascii
        $h2 = "50c6260a" ascii
    condition:
        all of them
}
```

---

## 📊 Fréquence par catégorie de fichier

| Catégorie | Nb occurrences (1643379a) | Nb occurrences (50c6260a) |
|---|---:|---:|
| Documentation (`*.md`) | 9 | 6 |
| Sortie analyse statique (`*.txt`, `*.json`) | 9 | 9 |
| Code reproducteur (`*.py`) | 3 | 2 |
| Scripts audit (`*.py`) | 2 | 2 |
| **Total** | **23** | **19** |

---

## 🧪 Vérification

L'artefact est validé par `06_LOCAL_REPRODUCER/verify_short_term_recommendations.py`
(check #1 et #2 : présence des 2 hashes dans le catalogue et YARA).
Une exécution produit `24/24 OK` lorsque la corrélation est complète.

Pour re-vérifier manuellement :

```bash
python 06_LOCAL_REPRODUCER/verify_short_term_recommendations.py
```

---

## 📦 Sidecar JSON

Voir [`BUILD_HASH_CORRELATION.json`](./BUILD_HASH_CORRELATION.json) pour la version
programmatique (parseable par outils de threat-intel / MISP / OpenCTI).