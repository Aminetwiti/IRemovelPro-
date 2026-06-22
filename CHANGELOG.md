# CHANGELOG — Historique de l'analyse

> Toutes les modifications notables du projet d'audit sont documentées ici.

## Format

Basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### À faire
- Phase 5 : analyse dynamique (mitmproxy) — voir [ROADMAP.md](ROADMAP.md)
- Phase 6 : sandbox comportemental
- Phase 7 : extraction iOS components live

---

## [1.0.0] — 2026-06-22

### Ajouté
- Restructuration complète du projet : `01_REPORTS/`, `02_SCRIPTS/`, `03_OUTPUTS/`, `04_EXTRACTED/`, `05_IOC/`
- Documentation root : `README.md`, `INDEX.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `CONTRIBUTING.md`, `SECURITY.md`, `TODO.md`, `GLOSSARY.md`
- Documentation 01_REPORTS : `INDEX.md`, `EXECUTIVE_SUMMARY.md`, `METHODOLOGY.md`, `LIMITATIONS.md`, `FAQ.md`
- Documentation 02_SCRIPTS : `README.md`
- Documentation 03_OUTPUTS : `README.md`
- Documentation 04_EXTRACTED : `README.md`
- Documentation 05_IOC : `README.md`, `YARA_RULES.yar`, `SURICATA_RULES.rules`, `MITRE_MAPPING.md`
- Scripts Phase 4 : `phase4_exe_decompile.py` (décompilation EXE WPF via dnfile)

### Modifié
- Suppression du dossier `__analysis/` (contenu migré vers la nouvelle structure)
- Renommage et réorganisation des 17 scripts Python en 5 phases

---

## [0.9.0] — 2026-06-21

### Ajouté
- 5 rapports initiaux produits :
  - `REPORT.md` (analyse initiale)
  - `EXPERT_REPORT.md` (runtime flow, anti-debug, iOS protocols)
  - `AUDIT_REPORT.md` (architecture, IoC, dépendances)
  - `CROSS_REFERENCE.md` (validation croisée des 3 rapports)
  - `CONSOLIDATED_AUDIT.md` (rapport unifié final)
- 17 scripts Python d'analyse statique :
  - `pe_parse.py` (Phase 1 : PE headers)
  - `strings_extract.py` (Phase 2 : chaînes)
  - `re_blackhound_extract.py` (Phase 3 : payload iOS)
  - `re_extract_macho.py` + `re_extract_macho2.py` (Phase 3 : Mach-O)
  - `re_macho_check.py` (Phase 3 : vérification)
  - `re_deep.py` à `re_deep5.py` (Phase 4 : 5 passes deep static)
  - `phase4_exe_decompile.py` (Phase 4 : EXE WPF)
  - `re_iact_decode.py` + `re_iact_decode2.py` (Phase 5 : API)
  - `re_json_keys.py` (Phase 5 : JSON keys)
  - `test_search.py` (utilitaire)
- Artefacts générés :
  - `pe_report.txt` (5 KB)
  - `strings_report.txt` (36 KB)
  - `strings_all_long.txt` (737 KB, 75 000+ chaînes)
  - 12 binaires Mach-O extraits de la DLL
  - `phase4_exe_decompiled.json` (313 types, 1821 méthodes)

### Constaté
- **Cible identifiée** : `iRemoval PRO Premium Edition v5.2` (fork modifié de Blackhound iRemovalPro v0.7.1)
- **EXE** : PE32 x86, .NET Framework 4.0 WPF (obfusqué, 1821 méthodes, 313 types)
- **DLL** : PE32+ x64, .NET 8 NativeAOT (30 MB)
- **13 endpoints serveur** identifiés (12 iRemovalPRO + 1 Apple officiel)
- **50+ IoC** catalogués

---

## Types de modifications

- **Ajouté** pour les nouvelles fonctionnalités
- **Modifié** pour les changements aux fonctionnalités existantes
- **Déprécié** pour les fonctionnalités qui seront supprimées
- **Supprimé** pour les fonctionnalités supprimées
- **Corrigé** pour les corrections de bugs
- **Sécurité** pour les vulnérabilités
