# 01_REPORTS — Index des rapports

> Table des matières des 5 rapports d'analyse + 5 documents complémentaires

## 📑 Rapports principaux (ordre de lecture)

| # | Fichier | Auteur | Phase | Pages | Description |
|---|---|---|---|---|---|
| 1 | [`EXECUTIVE_SUMMARY.md`](EXECUTIVE_SUMMARY.md) | Synthèse | Vue d'ensemble | 1 page | Résumé 1 page pour management |
| 2 | [`REPORT.md`](REPORT.md) | Analyse initiale | Phase 1-2 | ~13 KB | Identification binaire, classes, imports |
| 3 | [`EXPERT_REPORT.md`](EXPERT_REPORT.md) | Analyse experte | Phase 3-4 | ~27 KB | Runtime flow, anti-debug, iOS protocols |
| 4 | [`AUDIT_REPORT.md`](AUDIT_REPORT.md) | Audit indépendant | Architecture | ~43 KB | Architecture, IoC, dépendances, risques |
| 5 | [`CROSS_REFERENCE.md`](CROSS_REFERENCE.md) | Cross-validation | Audit | ~11 KB | Comparaison des 3 rapports vs binaire |
| 6 | [`CONSOLIDATED_AUDIT.md`](CONSOLIDATED_AUDIT.md) | ⭐ **PRINCIPAL** | Audit complet | ~51 KB | **Rapport unifié final** |
| 7 | [`CRYPTO_CRITICAL_ANALYSIS.md`](CRYPTO_CRITICAL_ANALYSIS.md) | 🔐 **CRYPTO** | Phase 4c | ~18 KB | Analyse approfondie 6 539 strings crypto, 17 APIs Windows, hooks Apple Security |
| 8 | [`REPORT_GHIDRA_FRIDA_MITMPROXY.md`](REPORT_GHIDRA_FRIDA_MITMPROXY.md) | Tools RE | Phase 4b | ~12 KB | Ghidra + Frida + MitmProxy |
| 9 | [`PHASE4B_DRIVER_ANALYSIS.md`](PHASE4B_DRIVER_ANALYSIS.md) | Driver | Phase 4b | ~7 KB | Analyse driver libimobiledevice |
| 10 | [`REPORT_SERVER_PROTOCOL.md`](REPORT_SERVER_PROTOCOL.md) | Server | Phase 3 | ~10 KB | Protocole serveur activation |
| 11 | [`PHASE5_RUNTIME_NATIVEAOT.md`](PHASE5_RUNTIME_NATIVEAOT.md) | 🚀 **PHASE 5** | Phase 5 | ~12 KB | Runtime dump + NativeAOT unpack, 604 types .NET, origine BlackHound |
| 12 | [`ENDPOINT_IACT8.md`](ENDPOINT_IACT8.md) | 🎯 Endpoint | Mini-rapport | ~7 KB | **Analyse dédiée `iact8.php`** — cœur du bypass, ticket iActivation forgé |
| 13 | [`CRYPTO_KEY_DERIVATION.md`](CRYPTO_KEY_DERIVATION.md) | 🔑 **KDF** | Phase 4c | ~12 KB | **Algorithme PBKDF2-HMAC-SHA256** pour `nonce_C`, reconstruction C#/Python, preuves AOT |
| 14 | [`APPLE_CERT_CHAIN.md`](APPLE_CERT_CHAIN.md) | 🍎 **PKI** | Phase 4c | ~19 KB | **8 certs X.509 Apple embarqués** : Root CA + WWDR + dev cert `weidong li` (UR3K3ZV28R) — SHA-256/AES S-box/K-table validés |
| 15 | [`OFFENSIVE _PLAYBOOK.md`](OFFENSIVE _PLAYBOOK.md) | 🛡️ **DEFENSE** | Phase 5 | ~20 KB | **5 contre-mesures** : allowlist modulus, détection signature RSA brute, hook amfid, blocage C2, révocation PKI — avec YARA/Sigma/code |
| 15 | [`BYPASS_CORE.md`](BYPASS_CORE.md) | 🔓 **HEART** | Phase 6 | ~13 KB | **Cœur du bypass** — 5 hooks (MobileActivationDaemon + Security.framework), **clé RSA-1024 publique extraite**, structure ticket forgé, génération de la clé |
| 16 | [`COMPLETE_SYSTEM_ARCHITECTURE.md`](COMPLETE_SYSTEM_ARCHITECTURE.md) | 🏛️ **ARCHITECTURE** | Phase 7 | ~22 KB | **Architecture end-to-end** — flux 6 phases (setup → jailbreak → auth → exploit → activation → confirmation), 9 endpoints serveur, 3 nonces, 5 hooks, RSA-1024, ideviceproxy `lao abc ofq` |

## 📚 Documents complémentaires

| Fichier | Description |
|---|---|
| [`METHODOLOGY.md`](METHODOLOGY.md) | Comment l'analyse a été menée |
| [`LIMITATIONS.md`](LIMITATIONS.md) | Ce que l'analyse ne couvre pas |
| [`FAQ.md`](FAQ.md) | Questions fréquentes |

## 🎯 Quel rapport lire ?

```
Vous êtes...
│
├── Manager / décisionnel
│   └─▶ EXECUTIVE_SUMMARY.md
│
├── Analyste sécurité
│   └─▶ CONSOLIDATED_AUDIT.md
│
├── Chercheur RE
│   └─▶ EXPERT_REPORT.md
│
├── Auditeur conformité
│   └─▶ AUDIT_REPORT.md
│
├── Développeur / contributeur
│   └─▶ METHODOLOGY.md
│
└── Curieux / première visite
    └─▶ EXECUTIVE_SUMMARY.md → CONSOLIDATED_AUDIT.md
```

## 🔍 Recherche par sujet

### Bypass activation lock
- `REPORT.md` §8 — Mécanique du bypass
- `EXPERT_REPORT.md` §5 — Couche iOS protocol
- `AUDIT_REPORT.md` §5 — Cartographie fonctionnelle
- `CONSOLIDATED_AUDIT.md` §4 + §5 — Vue unifiée
- **`APPLE_CERT_CHAIN.md` — Identité légale Apple Developer** (team `UR3K3ZV28R` / `weidong li`)

### Endpoints serveur
- `REPORT.md` §7 — Liste initiale
- `EXPERT_REPORT.md` §4 — Network intelligence
- `AUDIT_REPORT.md` §7 — Communication réseau
- `CONSOLIDATED_AUDIT.md` §7 — Endpoints consolidés
- **`ENDPOINT_IACT8.md` — Analyse dédiée iact8.php** (génération ticket iActivation forgé)
- **`CRYPTO_KEY_DERIVATION.md` §1 — Système de 3 nonces** (A, B, C) et partage entre endpoints

### Anti-débogage
- `REPORT.md` §9 — Liste basique
- `EXPERT_REPORT.md` §3 — Techniques détaillées
- `CONSOLIDATED_AUDIT.md` §6 — Synthèse

### Payloads iOS
- `EXPERT_REPORT.md` §6 — 4 payloads identifiés
- `AUDIT_REPORT.md` §9 — Détails
- `CONSOLIDATED_AUDIT.md` §9 — Vue unifiée

### Crypto / APIs Windows
- `CRYPTO_CRITICAL_ANALYSIS.md` — Analyse complète 6 539 strings
- `PHASE5_RUNTIME_NATIVEAOT.md` — Runtime dump + 940 strings crypto classifiées

### Runtime & NativeAOT
- `PHASE5_RUNTIME_NATIVEAOT.md` — Frida dumper + NativeAOT parser
- `02_SCRIPTS/10_runtime_dump/` — Scripts de capture mémoire
- `02_SCRIPTS/11_nativeaot_unpack/` — Parser NativeAOT
- `03_OUTPUTS/nativeaot/` — 28 106 strings extraites

### Architecture d'attaque
- `PHASE5_RUNTIME_NATIVEAOT.md` §3 — Diagramme Windows ↔ iOS
- `AUDIT_REPORT.md` §5 — Cartographie fonctionnelle

### Cryptographie
- `CRYPTO_CRITICAL_ANALYSIS.md` §2-7 — Stack crypto complète (AES, RSA, SHA, BCrypt)
- `CRYPTO_CRITICAL_ANALYSIS.md` §4 — Hooks Apple Security framework
- `CRYPTO_CRITICAL_ANALYSIS.md` §5 — Serveur d'activation
- **`CRYPTO_KEY_DERIVATION.md` — Algorithme PBKDF2-HMAC-SHA256** (clé `nonce_C`, preuves AOT, reconstruction C#/Python, méthodologie de vérification)
- **`APPLE_CERT_CHAIN.md` — Chaîne PKI Apple complète embarquée** (8 certs X.509 RSA, dev cert `weidong li` (UR3K3ZV28R), validation SHA-256 K-table + AES S-box)
- `05_IOC/windows_crypto_apis.md` — 17 APIs Windows détectées

### Recommandations
- `CONSOLIDATED_AUDIT.md` §15 — Recommandations complètes

## 📊 Comparaison des rapports

| Critère | REPORT | EXPERT | AUDIT | CROSS | CONSOLIDATED |
|---|---|---|---|---|---|
| **Couverture** | Initiale | Profonde | Architecture | Validation | Unifié |
| **PE headers** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Strings** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Classes** | Partiel | ✅ | ✅ | ✅ | ✅ |
| **Runtime flow** | ❌ | ✅ | ❌ | ✅ | ✅ |
| **Anti-debug** | Basique | ✅ | ❌ | ✅ | ✅ |
| **iOS protocols** | Partiel | ✅ | Partiel | ✅ | ✅ |
| **IoC** | Partiel | Partiel | ✅ | ✅ | ✅ |
| **Architecture** | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Risques** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Recommandations** | ✅ | ❌ | ✅ | ✅ | ✅ |

## 🔗 Navigation

- ⬆ [`../INDEX.md`](../INDEX.md) — Table des matières racine
- ⬇ [`EXECUTIVE_SUMMARY.md`](EXECUTIVE_SUMMARY.md) — Résumé 1 page
- 📑 [`../05_IOC/`](../05_IOC/) — Catalogue IoC

---

**Statut** : 6 rapports principaux + 3 documents complémentaires
**Dernière MAJ** : 2026-06-22
