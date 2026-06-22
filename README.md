# iRemoval PRO Premium Edition v5.2 — Audit de sécurité

> **Projet d'audit statique** — analyse complète d'un outil de bypass iCloud Activation Lock

## 📋 Vue d'ensemble

| Champ | Valeur |
|---|---|
| **Cible** | `iRemoval PRO Premium Edition v5.2` |
| **Origine** | Fork de "Blackhound iRemovalPro" v0.7.1 (2022) |
| **Distribution** | bypassfrpfiles.com |
| **Date d'audit** | 2026-06-21 → 2026-06-22 |


## 📁 Structure du projet

```
[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2]/
│
├── 📄 README.md                      ← ce fichier
│
├── 🔵 iRemoval PRO.exe               ← original (intact, 2.7 MB)
├── 🔵 iremovalpro.dll                ← original (intact, 30 MB)
├── 🔵 BypassFRPFiles.COM.url         ← original
├── 🔵 Read Me.txt                    ← original
│
├── 🔵 .github/                       ← original
├── 🔵 .vscode/                       ← original
├── 🔵 ref/                           ← toolkits (libimobiledevice) — intact
│
├── 🤖 .agents/                       ← Skills AI pour analyse avancée (nouveau !)
│   ├── README.md                     # documentation complète des skills
│   ├── QUICK_START.md                # guide de référence rapide
│   └── skills/                       # 6 skills installés
│       ├── ghidra-headless/          # Trail of Bits - décompilation Ghidra
│       ├── ctf-malware/              # analyse de malware
│       ├── ctf-forensics/            # analyse forensique
│       ├── python-scripting/         # optimisation scripts Python
│       ├── binary-analysis/          # analyse binaires avancée
│       └── reverse-engineering/      # méthodologie RE
│
├── 📑 01_REPORTS/                    ← 5 rapports d'analyse
│   ├── REPORT.md                     # initial
│   ├── EXPERT_REPORT.md              # deep (runtime flow)
│   ├── AUDIT_REPORT.md               # architecture
│   ├── CROSS_REFERENCE.md            # cross-validation
│   └── CONSOLIDATED_AUDIT.md         # final unifié
│
├── 🐍 02_SCRIPTS/                    ← scripts Python d'analyse
│   ├── 01_pe_analysis/               # phase 1 : PE headers
│   ├── 02_strings/                   # phase 2 : extraction chaînes
│   ├── 03_ios_payloads/              # phase 3 : payloads iOS
│   ├── 04_deep_static/               # phase 4 : décompilation
│   ├── 05_network/                   # phase 5 : analyse API
│   └── 99_utils/                     # utilitaires
│
├── 📊 03_OUTPUTS/                    ← artefacts générés
│   ├── pe_report.txt
│   ├── strings_report.txt
│   ├── strings_all_long.txt
│   └── phase4_exe_decompiled.json
│
├── 📦 04_EXTRACTED/                  ← binaires Mach-O extraits de la DLL
│   ├── fat_*.bin
│   └── macho_*_*.bin
│
└── 🎯 05_IOC/                        ← catalogue IoC
    └── ioc_catalog.md
```

## 🛠️ Comment utiliser

### 0. 🤖 Utiliser les Skills AI (NOUVEAU !)

Le projet dispose maintenant de **6 skills d'IA spécialisés** pour améliorer l'analyse :

```bash
# Guide de démarrage rapide
cat .agents/QUICK_START.md

# Documentation complète
cat .agents/README.md

# Exemples d'utilisation :
@ghidra-headless décompile iremovalpro.dll
@ctf-malware détecte les anti-debug dans iRemoval PRO.exe
@binary-analysis + @reverse-engineering analyse complète des payloads iOS
```

**Skills disponibles** :
- 🔧 `ghidra-headless` — Décompilation automatisée (Trail of Bits)
- 🦠 `ctf-malware` — Détection de malware et obfuscation
- 🔍 `ctf-forensics` — Analyse forensique et extraction d'artefacts
- 🐍 `python-scripting` — Optimisation des scripts Python
- 📦 `binary-analysis` — Analyse binaire avancée (PE/ELF/Mach-O)
- 🔐 `reverse-engineering` — Méthodologie et workflow RE

### 1. Consulter les rapports

Ouvrir dans l'ordre de lecture recommandé :
1. [`01_REPORTS/CONSOLIDATED_AUDIT.md`](01_REPORTS/CONSOLIDATED_AUDIT.md) — vue d'ensemble
2. [`01_REPORTS/REPORT.md`](01_REPORTS/REPORT.md) — analyse initiale
3. [`01_REPORTS/EXPERT_REPORT.md`](01_REPORTS/EXPERT_REPORT.md) — runtime flow détaillé
4. [`01_REPORTS/AUDIT_REPORT.md`](01_REPORTS/AUDIT_REPORT.md) — audit architecture
5. [`01_REPORTS/CROSS_REFERENCE.md`](01_REPORTS/CROSS_REFERENCE.md) — validation croisée

### 2. Réexécuter les scripts

```bash
# Phase 1 : analyse PE
python 02_SCRIPTS/01_pe_analysis/pe_parse.py

# Phase 2 : extraction chaînes
python 02_SCRIPTS/02_strings/strings_extract.py

# Phase 3 : extraction payloads iOS
python 02_SCRIPTS/03_ios_payloads/re_blackhound_extract.py
python 02_SCRIPTS/03_ios_payloads/re_extract_macho.py
python 02_SCRIPTS/03_ios_payloads/re_extract_macho2.py

# Phase 4 : décompilation profonde
python 02_SCRIPTS/04_deep_static/re_deep.py
python 02_SCRIPTS/04_deep_static/re_deep2.py
python 02_SCRIPTS/04_deep_static/re_deep3.py
python 02_SCRIPTS/04_deep_static/re_deep4.py
python 02_SCRIPTS/04_deep_static/re_deep5.py
python 02_SCRIPTS/04_deep_static/phase4_exe_decompile.py

# Phase 5 : analyse API
python 02_SCRIPTS/05_network/re_iact_decode.py
python 02_SCRIPTS/05_network/re_iact_decode2.py
```

### 3. Examiner les binaires extraits

```bash
# Identifier les architectures des Mach-O extraits
file 04_EXTRACTED/*.bin
```



## 📊 Métriques clés

| Métrique | Valeur |
|---|---|
| **Binaires analysés** | 2 (EXE + DLL) |
| **Scripts Python** | 17 |
| **Chaînes extraites** | 75 000+ |
| **Méthodes iDevice** | 12 documentées |
| **Endpoints serveur** | 13 identifiés |
| **Méthodes iOS hookées** | 3 (`MobileActivationDaemon`) |
| **Payloads iOS identifiés** | 4 (`blackhound`, `minaeraser`, `minaeraser12`, `rc`) |
| **Rapports produits** | 5 |
| **IoC catalogués** | 50+ |

---

**Auteur** : Audit statique automatisé
**Date** : 2026-06-21 → 2026-06-22

