# 03_OUTPUTS — Artefacts générés

> Outputs produits par les scripts Python d'analyse

## 📁 Contenu

```
03_OUTPUTS/
├── pe_report.txt                 # Rapport PE brut
├── strings_report.txt            # Chaînes catégorisées (36 KB)
├── strings_all_long.txt          # Toutes chaînes (737 KB)
├── phase4_exe_decompiled.json    # EXE WPF décompilé (JSON)
└── README.md                     # Ce fichier
```

## 📄 Détail des artefacts

### `pe_report.txt` (5 KB)

Sortie de `pe_parse.py` :
```
ImageBase: 0x180000000, EP RVA: 0x1ab4fc4
Sections: .text, .managed, hydrated, .rdata, .data, .pdata, .k^q, .IE_, .^%L, .rsrc, .reloc
Imports: 15 fonctions Win32
...
```

**Usage** : Référence rapide pour la structure PE.

### `strings_report.txt` (36 KB)

Sortie de `strings_extract.py` — chaînes catégorisées :
```
=== URLs/Endpoints (58 matches) ===
  http://crl.apple.com/root.crl
  https://www.apple.com/appleca/
  ...

=== Anti-debug APIs ===
  IsDebuggerPresent
  NtQueryInformationProcess
  ...

=== iOS protocol strings ===
  com.apple.mobileactivationd
  DeviceName, ChipID, ...
```

**Usage** : Recherche rapide par catégorie.

### `strings_all_long.txt` (737 KB)

**Toutes** les chaînes ≥ 5 caractères (ASCII + UTF-16LE) :
- ~75 000 chaînes uniques
- Format : 1 chaîne par ligne
- Indexé par offset

**Usage** : Recherche exhaustive, validation contre le binaire.

### `phase4_exe_decompiled.json`

Output de `phase4_exe_decompile.py` :
```json
{
  "exe_path": "...",
  "assembly": "iRemovalProWPF",
  "pe": {
    "format": "PE32",
    "machine": 332,
    "imagebase": "0x400000",
    "entrypoint_rva": "0x1e7c2"
  },
  "types": [
    {"rid": 1, "name": "iRemovalProWPF.App", "fields": 0, "methods": 0},
    ...
  ],
  "methods": [
    {"rid": 1, "name": "MainWindow", "rva": "0x...", "flags": ...},
    ...
  ]
}
```

**Usage** : Traitement programmatique des types/méthodes.

## 🔄 Régénération

Tous les outputs peuvent être régénérés via les scripts correspondants :

```bash
# Régénérer pe_report.txt (sortie stdout, redirection manuelle)
python 02_SCRIPTS/01_pe_analysis/pe_parse.py > 03_OUTPUTS/pe_report.txt

# Régénérer strings_report.txt
python 02_SCRIPTS/02_strings/strings_extract.py

# Régénérer phase4_exe_decompiled.json
python 02_SCRIPTS/04_deep_static/phase4_exe_decompile.py
```

> **Note** : Les outputs originaux ont été capturés avec les versions initiales des scripts. Les régénérer peut produire des outputs légèrement différents si les scripts ont été améliorés.

## 📊 Statistiques

| Fichier | Taille | Lignes | Caractères |
|---|---|---|---|
| `pe_report.txt` | 5 KB | ~200 | 5 100 |
| `strings_report.txt` | 36 KB | ~700 | 36 000 |
| `strings_all_long.txt` | 737 KB | ~75 000 | 754 461 |
| `phase4_exe_decompiled.json` | ~100 KB | ~2 200 | 100 000 |

## 🔗 Navigation

- ⬆ [`../INDEX.md`](../INDEX.md) — Table des matières
- ⬇ [`../02_SCRIPTS/README.md`](../02_SCRIPTS/README.md) — Scripts source

---

**Générés le** : 2026-06-21/22
**Par** : Scripts Python Phase 1-4
