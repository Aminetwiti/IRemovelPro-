# METHODOLOGY — Méthodologie d'analyse

> Comment cette analyse a été menée — outils, phases, validation

## 🎯 Objectif

Documenter **comment** l'analyse a été réalisée, pour :
- Permettre la **reproductibilité**
- Identifier les **limites** méthodologiques
- Servir de **référence** pour des analyses similaires

## 📋 Principes directeurs

### 1. Approche **docs-guard**
Toute affirmation est **vérifiée contre la source** avant publication :
- Les noms de fichiers sont exacts
- Les lignes de code citées sont reproduites fidèlement
- Les IoC sont validés contre le binaire
- Pas de claims non vérifiés

### 2. Approche **statique uniquement**
- ✅ Lecture des binaires sans exécution
- ✅ Extraction de chaînes et métadonnées
- ❌ Pas d'exécution du binaire
- ❌ Pas de Frida injection sur iPhone
- ❌ Pas de capture réseau live

### 3. Transparence
- Scripts sources disponibles dans `02_SCRIPTS/`
- Outputs bruts dans `03_OUTPUTS/`
- Binaire Mach-O extraits dans `04_EXTRACTED/`

## 🛠️ Outils utilisés

### Python
| Lib | Usage |
|---|---|
| `pefile` | Parsing PE headers (sections, imports) |
| `dnfile` | Parsing .NET metadata (TypeDef, MethodDef) |
| `struct` | Parsing binaire manuel |
| `hashlib` | Hashes SHA-256, MD5 |
| `io.TextIOWrapper` | Output UTF-8 correct (chemins avec crochets) |

### PowerShell
- `Get-ChildItem` — Listing fichiers
- `[System.IO.File]::ReadAllBytes()` — Lecture binaire
- `[System.IO.Directory]::CreateDirectory()` — Création dossiers (compatible PS 5.1)
- `[System.IO.File]::Move()` — Déplacement (gère les brackets)

### Système
- Windows 10/11 PowerShell 5.1
- Python 3.12 (PEP 668 : pas de pip install, mais `dnfile` est pur Python)
- .NET 7.0.200 SDK (pour `dotnet --list-sdks`)

## 📐 Phases de l'analyse

### Phase 1 — Identification PE
**Objectif** : Comprendre la structure des binaires

**Méthode** :
- Parsing PE32 (EXE) et PE32+ (DLL)
- Identification des sections
- Extraction des imports (15 fonctions)
- Calcul des hashes

**Livrables** :
- `02_SCRIPTS/01_pe_analysis/pe_parse.py`
- `01_REPORTS/REPORT.md` §1-3
- `03_OUTPUTS/pe_report.txt`

**Découvertes** :
- DLL = .NET 8 NativeAOT (imagebase 0x180000000)
- EXE = .NET Framework 4 WPF obfusqué

### Phase 2 — Extraction de chaînes
**Objectif** : Trouver URLs, IoC, classes, méthodes

**Méthode** :
- Extraction ASCII (longueur min 6)
- Extraction UTF-16LE
- Catégorisation (URLs, erreurs, services, etc.)
- Recherche par pattern

**Livrables** :
- `02_SCRIPTS/02_strings/strings_extract.py`
- `03_OUTPUTS/strings_report.txt` (36 KB)
- `03_OUTPUTS/strings_all_long.txt` (737 KB)

**Découvertes** :
- 13 endpoints serveur
- 50+ IoC (hashes, URLs, bundles iOS, chemins)

### Phase 3 — Extraction payloads iOS
**Objectif** : Identifier les binaires iOS embarqués

**Méthode** :
- Recherche de magic numbers Mach-O
- Recherche de magic FAT
- Extraction automatique
- Vérification de cohérence

**Livrables** :
- `02_SCRIPTS/03_ios_payloads/re_extract_macho.py`
- `02_SCRIPTS/03_ios_payloads/re_extract_macho2.py`
- `02_SCRIPTS/03_ios_payloads/re_macho_check.py`
- `04_EXTRACTED/*.bin` (12 fichiers)

**Découvertes** :
- 4 payloads iOS : blackhound, minaeraser, minaeraser12, rc
- Build paths de 3 développeurs identifiés

### Phase 4 — Décompilation statique
**Objectif** : Comprendre le code machine sans exécution

**Méthode** :
- 5 passes d'analyse progressive
- Recherche d'API strings (anti-debug, crypto, HTTP)
- Scan d'opcodes (RDTSC, CPUID, PEB access)
- Parsing R2R / AOT headers
- Décompilation .NET 4 EXE via dnfile

**Livrables** :
- `02_SCRIPTS/04_deep_static/re_deep.py` à `re_deep5.py`
- `02_SCRIPTS/04_deep_static/phase4_exe_decompile.py`
- `03_OUTPUTS/phase4_exe_decompiled.json`

**Découvertes** :
- 13 méthodes iDevice
- 5 state machines async
- 5 techniques anti-debug
- EXE WPF obfusqué (1821 méthodes, 313 types)

### Phase 5 — Analyse API serveur (mitmproxy) [TODO]
Voir [ROADMAP.md](../ROADMAP.md) §Phase 5.

## ✅ Validation

### Comment les rapports ont été validés
1. **Cross-référence** : 3 rapports indépendants comparés
2. **Validation binaire** : chaque claim vérifié contre `__analysis/strings_all_long.txt`
3. **Correction** : divergences documentées dans [CROSS_REFERENCE.md](CROSS_REFERENCE.md)

### Bug notable corrigé
**Problème** : Le rapport EXPERT ajoutait des extensions `.php` et `.txt` aux endpoints.

**Réalité** : Le binaire stocke les extensions **tronquées** (`.ph`, `.tx`).

**Impact** : Correction de 10+ URLs dans le rapport unifié.

## 📊 Métriques de l'analyse

| Métrique | Valeur |
|---|---|
| Phases complétées | 4/5 (statique) |
| Scripts Python | 17 |
| Rapports produits | 5 |
| Documentation | 10+ fichiers |
| Binaire Mach-O extraits | 12 |
| Chaînes extraites | 75 000+ |
| IoC catalogués | 50+ |
| Méthodes iDevice | 13 |
| Méthodes iOS hookées | 3 |

## ⚠️ Limites méthodologiques

Voir [LIMITATIONS.md](LIMITATIONS.md) pour les détails.

## 🔄 Reproductibilité

Pour reproduire cette analyse :

```bash
# 1. Préparer l'environnement
python --version  # 3.10+
pip install pefile dnfile

# 2. Placer les binaires
# (copier iRemoval PRO.exe et iremovalpro.dll dans le dossier de travail)

# 3. Exécuter les scripts dans l'ordre
python 02_SCRIPTS/01_pe_analysis/pe_parse.py
python 02_SCRIPTS/02_strings/strings_extract.py
python 02_SCRIPTS/03_ios_payloads/re_extract_macho.py
python 02_SCRIPTS/04_deep_static/re_deep.py
python 02_SCRIPTS/04_deep_static/re_deep2.py
python 02_SCRIPTS/04_deep_static/re_deep3.py
python 02_SCRIPTS/04_deep_static/re_deep4.py
python 02_SCRIPTS/04_deep_static/re_deep5.py
python 02_SCRIPTS/04_deep_static/phase4_exe_decompile.py
```

## 📚 Références

- [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — Microsoft Learn
- [.NET Metadata](https://learn.microsoft.com/en-us/dotnet/standard/metadata-and-self-describing-components) — Microsoft Learn
- [libimobiledevice](https://libimobiledevice.org/) — Site officiel
- [Theos](https://theos.dev/) — iOS tweak development
- [MITRE ATT&CK](https://attack.mitre.org/) — Framework classification

---

**Auteur** : Audit statique automatisé
**Date** : 2026-06-22
**Conformité** : Approche docs-guard (vérification factuelle)
