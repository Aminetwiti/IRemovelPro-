# Index — iRemoval PRO Premium Edition v5.2 Audit

> **Point d'entrée principal du projet** — utilisez ce fichier comme table des matières

## 🚀 Démarrage rapide

| Action | Document |
|---|---|
| Comprendre le projet en 1 page | [`EXECUTIVE_SUMMARY.md`](01_REPORTS/EXECUTIVE_SUMMARY.md) |
| Lire le rapport principal | [`01_REPORTS/CONSOLIDATED_AUDIT.md`](01_REPORTS/CONSOLIDATED_AUDIT.md) |
| Voir les indicateurs de compromission | [`05_IOC/ioc_catalog.md`](05_IOC/ioc_catalog.md) |
| Réexécuter l'analyse | [`02_SCRIPTS/README.md`](02_SCRIPTS/README.md) |

## 📑 Table des matières

### 🏠 Racine du projet
- [`README.md`](README.md) — Vue d'ensemble, structure, comment utiliser
- [`INDEX.md`](INDEX.md) — Ce fichier (table des matières)
- [`CHANGELOG.md`](CHANGELOG.md) — Historique des versions de l'analyse
- [`ROADMAP.md`](ROADMAP.md) — Phases d'analyse, prochaines étapes
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Diagrammes d'architecture
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Comment contribuer
- [`EXPLOIT.md`](EXPLOIT.md) — Politique de divulgation sécurité
- [`TODO.md`](TODO.md) — Tâches en attente
- [`GLOSSARY.md`](GLOSSARY.md) — Termes techniques

### 📑 [01_REPORTS/](01_REPORTS/) — Rapports d'analyse (5 + 5 docs)
| Fichier | Description |
|---|---|
| [`01_REPORTS/INDEX.md`](01_REPORTS/INDEX.md) | Table des matières des rapports |
| [`01_REPORTS/REPORT.md`](01_REPORTS/REPORT.md) | Analyse initiale (PE/strings) |
| [`01_REPORTS/EXPERT_REPORT.md`](01_REPORTS/EXPERT_REPORT.md) | Analyse experte (runtime flow) |
| [`01_REPORTS/AUDIT_REPORT.md`](01_REPORTS/AUDIT_REPORT.md) | Audit architecture |
| [`01_REPORTS/CROSS_REFERENCE.md`](01_REPORTS/CROSS_REFERENCE.md) | Cross-validation des rapports |
| [`01_REPORTS/CONSOLIDATED_AUDIT.md`](01_REPORTS/CONSOLIDATED_AUDIT.md) | Rapport unifié final |
| [`01_REPORTS/EXECUTIVE_SUMMARY.md`](01_REPORTS/EXECUTIVE_SUMMARY.md) | Résumé 1 page |
| [`01_REPORTS/METHODOLOGY.md`](01_REPORTS/METHODOLOGY.md) | Méthodologie d'analyse |
| [`01_REPORTS/LIMITATIONS.md`](01_REPORTS/LIMITATIONS.md) | Limites de l'analyse |
| [`01_REPORTS/FAQ.md`](01_REPORTS/FAQ.md) | Questions fréquentes |

### 🐍 [02_SCRIPTS/](02_SCRIPTS/) — Scripts Python d'analyse
| Phase | Dossier | Description |
|---|---|---|
| 1 | [`02_SCRIPTS/01_pe_analysis/`](02_SCRIPTS/01_pe_analysis/) | Analyse PE headers |
| 2 | [`02_SCRIPTS/02_strings/`](02_SCRIPTS/02_strings/) | Extraction chaînes |
| 3 | [`02_SCRIPTS/03_ios_payloads/`](02_SCRIPTS/03_ios_payloads/) | Extraction payloads iOS |
| 4 | [`02_SCRIPTS/04_deep_static/`](02_SCRIPTS/04_deep_static/) | Décompilation statique |
| 5 | [`02_SCRIPTS/05_network/`](02_SCRIPTS/05_network/) | Analyse API serveur |
| – | [`02_SCRIPTS/99_utils/`](02_SCRIPTS/99_utils/) | Utilitaires |
| – | [`02_SCRIPTS/README.md`](02_SCRIPTS/README.md) | Comment exécuter les scripts |

### 📊 [03_OUTPUTS/](03_OUTPUTS/) — Artefacts générés
- [`03_OUTPUTS/README.md`](03_OUTPUTS/README.md) — Description des artefacts
- `pe_report.txt` — Rapport PE brut
- `strings_report.txt` — Rapport chaînes catégorisé
- `strings_all_long.txt` — Toutes chaînes (754 KB)
- `phase4_exe_decompiled.json` — EXE WPF décompilé

### 📦 [04_EXTRACTED/](04_EXTRACTED/) — Binaires Mach-O extraits
- [`04_EXTRACTED/README.md`](04_EXTRACTED/README.md) — Description
- `macho_*_*.bin` — Payloads iOS extraits de la DLL
- `fat_*.bin` — FAT headers extraits

### 🎯 [05_IOC/](05_IOC/) — Catalogue IoC + règles de détection
- [`05_IOC/README.md`](05_IOC/README.md) — Vue d'ensemble
- [`05_IOC/ioc_catalog.md`](05_IOC/ioc_catalog.md) — Catalogue complet
- [`05_IOC/YARA_RULES.yar`](05_IOC/YARA_RULES.yar) — Règles YARA
- [`05_IOC/SURICATA_RULES.rules`](05_IOC/SURICATA_RULES.rules) — Règles Suricata
- [`05_IOC/MITRE_MAPPING.md`](05_IOC/MITRE_MAPPING.md) — MITRE ATT&CK

## 🔍 Recherche rapide

### Par sujet
- **Bypass activation lock** → `01_REPORTS/REPORT.md` §8, `EXPERT_REPORT.md` §5
- **Endpoints serveur** → `01_REPORTS/REPORT.md` §7, `05_IOC/ioc_catalog.md` §endpoints
- **Anti-debug** → `01_REPORTS/EXPERT_REPORT.md` §3, `05_IOC/ioc_catalog.md` §anti-debug
- **Payloads iOS** → `01_REPORTS/EXPERT_REPORT.md` §6, `04_EXTRACTED/README.md`
- **iOS hook** → `01_REPORTS/EXPERT_REPORT.md` §5.7
- **Risques** → `01_REPORTS/CONSOLIDATED_AUDIT.md` §13
- **Recommandations** → `01_REPORTS/CONSOLIDATED_AUDIT.md` §15

### Par fichier binaire
- **`iRemoval PRO.exe`** → `01_REPORTS/REPORT.md` §1-2, `phase4_exe_decompile.py`
- **`iremovalpro.dll`** → `01_REPORTS/EXPERT_REPORT.md` §1-3, `re_deep*.py`

## 📊 Métriques globales

| Métrique | Valeur |
|---|---|
| Binaires analysés | 2 (EXE + DLL) |
| Scripts Python | 17 |
| Fichiers Markdown | 25+ |
| Chaînes extraites | 75 000+ |
| Endpoints catalogués | 13 |
| Méthodes iDevice | 13 |
| Méthodes iOS hookées | 3 |
| Payloads iOS | 4 |
| IoC totaux | 50+ |

---

**Navigation** : [README](README.md) | [Table des matières](INDEX.md) | [Executive Summary](01_REPORTS/EXECUTIVE_SUMMARY.md)
