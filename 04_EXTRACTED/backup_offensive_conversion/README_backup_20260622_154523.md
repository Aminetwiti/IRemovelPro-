# 04_EXTRACTED — Binaires Mach-O extraits

> Payloads iOS extraits de la DLL NativeAOT

## 📁 Contenu

```
04_EXTRACTED/
├── fat_84f4d3_0x1c000.bin       # FAT header (4 KB)
├── fat_84f4d3_0x4000.bin        # FAT header (4 KB)
├── macho_8534d3_DYLIB_ARM64.bin       # 4 KB
├── macho_8534d3_DYLIB_ARM64_ALL.bin   # 8.5 MB (complet)
├── macho_86b4d3_DYLIB_ARM64.bin       # 4 KB
├── macho_86b4d3_DYLIB_ARM64_ARM64E.bin # 8.6 MB (complet)
├── macho_8812f8_EXECUTE_ARM64.bin     # 4 KB
├── macho_8812f8_EXECUTE_ARM64_ALL.bin  # 8.7 MB (complet)
├── macho_8a3dcd_EXECUTE_ARM64.bin     # 4 KB
├── macho_8a3dcd_EXECUTE_ARM64_ALL.bin  # 8.9 MB (complet)
├── macho_8ea1a8_EXECUTE_ARM64.bin     # 4 KB
├── macho_8ea1a8_EXECUTE_ARM64_ALL.bin  # 9.1 MB (complet)
└── README.md
```

## 🔍 Identification des fichiers

| Hash 4 premiers | Type probable | Payload iOS suspecté |
|---|---|---|
| `8534d3` | DYLIB ARM64 | `minaeraser` / `minaeraser12` |
| `86b4d3` | DYLIB ARM64+ARM64E | `minaeraser12` (variante universelle) |
| `8812f8` | EXECUTE ARM64 | `rc` (Recovery Creator) |
| `8a3dcd` | EXECUTE ARM64 | `rc` (variante) |
| `8ea1a8` | EXECUTE ARM64 | `blackhound.dylib` |
| `84f4d3` | FAT | Wrapper FAT multi-arch |

## 🎯 Méthode d'extraction

Les binaires Mach-O ont été extraits de la DLL via :

```python
# Recherche de magic numbers
patterns = {
    'MH_MAGIC_64': b'\xcf\xfa\xed\xff',
    'MH_CIGAM_64': b'\xfe\xed\xfa\xcf',
    'FAT_MAGIC':   b'\xca\xfe\xba\xbe',
    'FAT_CIGAM':   b'\xbe\xba\xfe\xca',
}

for name, magic in patterns.items():
    pos = 0
    while True:
        p = data.find(magic, pos)
        if p < 0: break
        # Extract Mach-O header + sections
        positions.append(p)
        pos = p + 1
```

**Scripts** :
- `02_SCRIPTS/03_ios_payloads/re_extract_macho.py` (v1)
- `02_SCRIPTS/03_ios_payloads/re_extract_macho2.py` (v2 - plus complet)

## 🔬 Analyse recommandée (non faite)

Pour aller plus loin (Phase 7 du [ROADMAP.md](../ROADMAP.md)) :

1. **`file` command** : confirmer le type Mach-O
   ```bash
   file 04_EXTRACTED/macho_*_ALL.bin
   ```

2. **`otool -l`** : lister les load commands
   ```bash
   otool -l 04_EXTRACTED/macho_8ea1a8_EXECUTE_ARM64_ALL.bin
   ```

3. **`class-dump`** : extraire headers Objective-C
   ```bash
   class-dump 04_EXTRACTED/macho_8ea1a8_EXECUTE_ARM64_ALL.bin
   ```

4. **Ghidra** : décompiler en pseudo-C ARM64
   - Importer le binaire
   - Processeur : AARCH64:LE:64:v8A
   - Analyser les fonctions

5. **Rechercher les hooks Cydia Substrate** : `_MSHookFunction`, `_MSHookMessageEx`

## ⚠️ État des fichiers

- Les fichiers `*_ALL.bin` contiennent le binaire Mach-O **complet**
- Les fichiers `.bin` (sans `_ALL`) contiennent juste le **header** (4 KB)
- Les fichiers `fat_*.bin` contiennent les **headers FAT** uniquement

## 🔗 Navigation

- ⬆ [`../INDEX.md`](../INDEX.md) — Table des matières
- ⬇ [`../01_REPORTS/EXPERT_REPORT.md`](../01_REPORTS/EXPERT_REPORT.md) §6 — Détails payloads

---

**Source** : iremovalpro.dll (30 MB)
**Extraction** : 2026-06-22
**Phase** : 3
