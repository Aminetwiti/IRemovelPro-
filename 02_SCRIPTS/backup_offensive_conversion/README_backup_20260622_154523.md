# 02_SCRIPTS — Scripts Python d'analyse

> 17 scripts Python organisés en 5 phases + utilitaires

## 📁 Organisation

```
02_SCRIPTS/
├── 01_pe_analysis/           # Phase 1 : Analyse PE headers
├── 02_strings/               # Phase 2 : Extraction de chaînes
├── 03_ios_payloads/          # Phase 3 : Extraction payloads iOS
├── 04_deep_static/           # Phase 4 : Décompilation statique
├── 05_network/               # Phase 5 : Analyse API serveur
└── 99_utils/                 # Utilitaires
```

## 🚀 Exécution rapide

### Toutes les phases d'un coup

```bash
# Phase 1 : PE headers
python 02_SCRIPTS/01_pe_analysis/pe_parse.py

# Phase 2 : Strings
python 02_SCRIPTS/02_strings/strings_extract.py

# Phase 3 : iOS payloads
python 02_SCRIPTS/03_ios_payloads/re_extract_macho.py
python 02_SCRIPTS/03_ios_payloads/re_extract_macho2.py
python 02_SCRIPTS/03_ios_payloads/re_macho_check.py
python 02_SCRIPTS/03_ios_payloads/re_blackhound_extract.py

# Phase 4 : Décompilation
python 02_SCRIPTS/04_deep_static/re_deep.py
python 02_SCRIPTS/04_deep_static/re_deep2.py
python 02_SCRIPTS/04_deep_static/re_deep3.py
python 02_SCRIPTS/04_deep_static/re_deep4.py
python 02_SCRIPTS/04_deep_static/re_deep5.py
python 02_SCRIPTS/04_deep_static/phase4_exe_decompile.py

# Phase 5 : API
python 02_SCRIPTS/05_network/re_iact_decode.py
python 02_SCRIPTS/05_network/re_iact_decode2.py
python 02_SCRIPTS/05_network/re_json_keys.py
```

## 📋 Détail par phase

### Phase 1 — PE Analysis
| Script | Rôle | Output |
|---|---|---|
| `01_pe_analysis/pe_parse.py` | Parse PE32/PE32+ | stdout |

### Phase 2 — Strings
| Script | Rôle | Output |
|---|---|---|
| `02_strings/strings_extract.py` | Extrait chaînes ASCII+UTF16 | `__analysis/strings_all_long.txt` |

### Phase 3 — iOS Payloads
| Script | Rôle | Output |
|---|---|---|
| `03_ios_payloads/re_blackhound_extract.py` | Cherche `blackhound.dylib` | stdout |
| `03_ios_payloads/re_extract_macho.py` | Extrait Mach-O v1 | `04_EXTRACTED/macho_*.bin` |
| `03_ios_payloads/re_extract_macho2.py` | Extrait Mach-O v2 (complet) | `04_EXTRACTED/macho_*_ALL.bin` |
| `03_ios_payloads/re_macho_check.py` | Vérifie intégrité Mach-O | stdout |

### Phase 4 — Deep Static
| Script | Rôle | Output |
|---|---|---|
| `04_deep_static/re_deep.py` | R2R header, anti-debug, iOS protocols | stdout |
| `04_deep_static/re_deep2.py` | HTTP/JSON, crypto | stdout |
| `04_deep_static/re_deep3.py` | AFC, MobileBackup2, InstallationProxy | stdout |
| `04_deep_static/re_deep4.py` | EP, anti-debug opcodes | stdout |
| `04_deep_static/re_deep5.py` | Function refs, crypto API | stdout |
| `04_deep_static/phase4_exe_decompile.py` | Décompile EXE WPF (dnfile) | `03_OUTPUTS/phase4_exe_decompiled.json` |

### Phase 5 — Network
| Script | Rôle | Output |
|---|---|---|
| `05_network/re_iact_decode.py` | Décode URL table iact8.php | stdout |
| `05_network/re_iact_decode2.py` | Décode v2 + JSON keys | stdout |
| `05_network/re_json_keys.py` | Recherche clés JSON autour iact8 | stdout |

### Utilitaires
| Script | Rôle |
|---|---|
| `99_utils/test_search.py` | Test pattern de recherche |

## 🔧 Prérequis

```bash
# Python 3.10+
python --version

# Dépendances
pip install pefile dnfile
```

> **Note** : `dnfile` est pur Python, pas de compilation native requise.

## 📝 Conventions de scripts

Tous les scripts suivent ce pattern :

```python
#!/usr/bin/env python3
"""Description courte.

Description longue si nécessaire.
"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Path constant (gère les crochets via .NET API)
DLL = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'

# Lecture binaire
with open(DLL, 'rb') as f:
    data = f.read()

# Recherche de patterns
patterns = [b'IsDebuggerPresent', b'NtQueryInformationProcess']
for p in patterns:
    pos = data.find(p)
    if pos >= 0:
        print(f"Found {p.decode()} at 0x{pos:x}")
```

## ⚠️ Chemins avec crochets

Le dossier contient `[Bypassfrpfiles.com]` ce qui casse PowerShell 5.1.

**Solution** : utiliser des **raw strings** Python + le préfixe `\\?\` :
```python
base = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'
```

**Pour PowerShell** : préfixe literal :
```powershell
$base = '\\?\C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'
Get-ChildItem -LiteralPath $base
```

## 🔗 Navigation

- ⬆ [`../INDEX.md`](../INDEX.md) — Table des matières
- ⬇ [`../01_REPORTS/METHODOLOGY.md`](../01_REPORTS/METHODOLOGY.md) — Méthodologie
- ⬇ [`../03_OUTPUTS/README.md`](../03_OUTPUTS/README.md) — Outputs

---

**17 scripts** | **5 phases** | **Compatible Python 3.10+**
