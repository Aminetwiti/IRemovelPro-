# Roadmap du projet d'audit

> Plan des phases d'analyse — séquençage, statut, dépendances

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1   │   Phase 2   │   Phase 3   │   Phase 4   │   Phase 5 │
│   PE       │  Strings   │  iOS Payld  │  Deep Stat  │  Network  │
│  [OK]      │   [OK]      │   [OK]      │   [OK]      │  [TODO]   │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│  Phase 6   │   Phase 7   │   Phase 8   │   Phase 9              │
│  Sandbox   │  iOS Live   │  Server     │  Knowledge Graph       │
│  [TODO]    │  [TODO]     │  [TODO]     │  [TODO]                 │
└─────────────────────────────────────────────────────────────────┘
```

## Phase 1 — Analyse PE ✅
**Statut** : Terminé (2026-06-21)
**Livrables** :
- `pe_parse.py` — Parseur PE avec sections, imports, headers
- `pe_report.txt` — Rapport complet
**Découvertes** :
- DLL est .NET 8 NativeAOT (imagebase 0x180000000)
- EXE est .NET Framework 4 WPF obfusqué

## Phase 2 — Extraction de chaînes ✅
**Statut** : Terminé (2026-06-21)
**Livrables** :
- `strings_extract.py`
- `strings_report.txt` (36 KB, catégorisé)
- `strings_all_long.txt` (737 KB, complet)
**Découvertes** :
- 13 endpoints serveur identifiés
- 4 méthodes iDevice dans Driver
- Strings de service marketing

## Phase 3 — Extraction payloads iOS ✅
**Statut** : Terminé (2026-06-21/22)
**Livrables** :
- `re_blackhound_extract.py`
- `re_extract_macho.py`, `re_extract_macho2.py`
- `re_macho_check.py`
- 12 binaires Mach-O extraits dans `04_EXTRACTED/`
**Découvertes** :
- 4 payloads iOS identifiés : blackhound, minaeraser, minaeraser12, rc
- 3 méthodes iOS hookées confirmées

## Phase 4 — Décompilation statique profonde ✅
**Statut** : Terminé (2026-06-21/22)
**Livrables** :
- `re_deep.py` à `re_deep5.py` (5 passes)
- `phase4_exe_decompile.py`
- `phase4_exe_decompiled.json` (313 types, 1821 méthodes)
- 5 rapports consolidés
**Découvertes** :
- 13 méthodes iDevice (Driver class)
- 5 state machines async
- 5 techniques anti-debug (PEB, RDTSC, CPUID, NtQuery*, Registry)
- Anti-debug opcodes dans .text

## Phase 5 — Analyse réseau (mitmproxy) [TODO]
**Statut** : À faire
**Prérequis** :
- VM Windows isolée
- Certificat mitmproxy installé
- Proxy HTTP/HTTPS configuré
**Livrables prévus** :
- Capture HAR des requêtes vers s13.iremovalpro.com
- Format exact JSON des requêtes
- Documentation des headers (X-API-Key, X-Sig, X-Timestamp)
- Structure complète des tickets d'activation
**Risques** :
- SSL pinning possible
- Compte iRemoval actif requis

## Phase 6 — Sandbox comportemental [TODO]
**Statut** : À faire
**Outils** :
- API Monitor (rohitab.com)
- Process Monitor (Sysinternals)
- Wireshark + Npcap
**Livrables prévus** :
- Trace des fichiers créés/modifiés
- Trace des accès registre
- Trace des processus enfants
- Trace DNS/réseau

## Phase 7 — Extraction iOS live [TODO]
**Statut** : À faire
**Prérequis** :
- iPhone jailbreaké (checkra1n pour A11)
- Frida installé (depuis Cydia)
**Livrables prévus** :
- `blackhound.dylib` capturé en live
- `minaeraser12` capturé en live
- Analyse des hooks Cydia Substrate
- Flux d'activation réel observé

## Phase 8 — Audit serveur s13.iremovalpro.com [TODO]
**Statut** : À faire
**Prérequis** : Compte iRemoval actif (payant)
**Livrables prévus** :
- Cartographie API complète
- Format exact des requêtes
- Headers d'authentification
- Réponses serveur détaillées

## Phase 9 — Knowledge graph final [TODO]
**Statut** : À faire
**Livrables prévus** :
- Vue 360° du projet
- Relations entre tous les composants
- Mermaid/PlantUML diagrams
- Rapport exécutif pour management

---

## 🛡️ Extension défensive (parallèle aux phases 1-9)

**Statut** : ✅ 4/5 axes terminés (2026-06-22)
**Lab status** : `7/7 suites PASS / 96/96 checks / 70.62s`

| Axe | Description | Statut |
|---|---|---|
| #1 | Test runner unifié (`run_all_suites.py`) | ✅ |
| #2 | Règle YARA `iRemovalPro_ChaosCrypto_Namespace` | ✅ |
| #3 | Defender en middleware (`mock_server.py` v1.5) | ✅ |
| #4 | Mise à jour `INDEX.md` + `EXECUTIVE_SUMMARY.md` | ✅ |
| #5 | Décompilation dylib avec `ilspycmd` | ⏸ différé |

**Axe #5 — décompilation dylib iOS** :
- **Prérequis** : `dotnet tool install -g ilspycmd` (1-2 jours)
- **Cible** : `04_EXTRACTED/` dylibs ARM64 (blackhound, minaeraser, minaeraser12, rc)
- **Livrable prévu** : Tree IL complet pour cross-référencer avec les
  checks `BY-EXT-001..004` du defender
- **Raison du report** : nécessite installation .NET 8 SDK + toolchain
  Mono/iOS. Peut être lancé indépendamment quand la toolchain sera
  disponible. Les checks `BY-EXT-*` sont déjà couverts par les 5 tests
  du middleware v1.5 sur la base de constantes SHA-1/strings, donc
  l'audit défensif n'est pas bloqué.

---

## Priorisation recommandée

| Priorité | Phase | Raison |
|---|---|---|
| 🥇 | 5 | Haute valeur — payloads réels |
| 🥈 | 6 | Compréhension runtime PC |
| 🥉 | 7 | Compréhension runtime iOS |
| 4 | 8 | Audit serveur (nécessite compte) |
| 5 | 9 | Synthèse finale |

## Estimation temps

| Phase | Effort | Compétence requise |
|---|---|---|
| 5 (mitmproxy) | 1-2 jours | Intermédiaire |
| 6 (sandbox) | 1 jour | Intermédiaire |
| 7 (iOS live) | 2-3 jours | Avancé (jailbreak + Frida) |
| 8 (serveur) | 1 jour | Intermédiaire (compte requis) |
| 9 (knowledge) | 1 jour | Intermédiaire |

---

**Légende** :
- ✅ Terminé
- [TODO] À faire
- [PARTIEL] Partiellement commencé
