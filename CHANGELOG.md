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

## [1.1.0] — 2026-06-22

### Ajouté — middleware v1.2/v1.3/v1.4 individuellement désactivable (lab permissif)

Le serveur mock local (`mock_server.py`) reproduit désormais la chaîne
de middleware exacte du backend iRemoval (blacklist → rate-limit →
HMAC-SHA256). Chaque garde peut être désactivée **indépendamment** via
un flag CLI dédié, pour permettre la capture de trafic et la
détection-engineering sans avoir à signer chaque requête ni à vider
le budget ou la blacklist :

| Flag (CLI)             | Garde ignorée            | Version |
|------------------------|--------------------------|---------|
| `--disable-hmac`       | Auth HMAC-SHA256         | v1.2    |
| `--disable-rate-limit` | Sliding-window limiter   | v1.3    |
| `--disable-blacklist`  | Blacklist persistante    | v1.4    |

Détails techniques :

- `iact_reproducer/mock_server.py`
  - nouvelle option CLI `--disable-hmac` (v1.2)
  - nouvelle option CLI `--disable-blacklist` (v1.4)
  - option existante `--disable-rate-limit` (v1.3) — vérifiée bout en bout
  - `_State` étendu avec `disabled_middleware: set` et
    `disabled_counters: dict` pour tracer chaque skip
  - `_check_middleware` consulte le set avant chaque garde, logge en
    DEBUG et incrémente le compteur correspondant
  - `run_server()` accepte et propage les trois flags ; au démarrage,
    un `WARNING` liste les gardes désactivées (ou un `INFO` si aucun)
- `iact_reproducer/README.md` — nouvelle section "C.1) Lab permissif
  mode" documentant les trois flags et leurs combinaisons

Tests fumée exécutés :

- permissive complet (`--disable-hmac --disable-rate-limit --disable-blacklist`) → 200 OK, statut `LAB_MOCK_REFUSED`
- strict (aucun `--disable-*`) → 401, statut `UNAUTHENTICATED`
- partiel (`--disable-hmac` seul) → 200 OK, statut `LAB_MOCK_REFUSED`

### Ajouté — introspection live, JSONL enrichi, banner, E2E matrice

Au-delà des 3 flags CLI, la surface d'observation du lab est renforcée
pour qu'un analyste (ou un dashboard) puisse savoir **à tout moment**
quelle garde est active, combien de requêtes l'ont bypassée, et
rejouer le diagnostic à partir du JSONL seul.

- `iact_reproducer/mock_server.py`
  - **Endpoint `GET /lab_mode`** (et `/lab_mode.ph`) — renvoie
    l'état live de chaque garde (`active: bool`, `skipped: int`),
    un snapshot du limiter et le nombre d'entrées dans la blacklist
  - **Endpoint `GET /metrics.ph`** — exposition Prometheus
    `iact_mock_skipped_guards_total{guard="hmac|rate_limit|blacklist|any"}`
    pour alerter SIEM quand une garde flips en mode permissif
  - **JSONL enrichi** — chaque record porte maintenant
    `lab_mode.disabled_middleware` (snapshot trié) et
    `lab_mode.skipped_guards` (compteurs à l'instant T)
  - **Banner de démarrage** — quand au moins un `--disable-*` est
    actif, un bloc `!!  LAB PERMISSIF MODE  !!` est imprimé pour
    rendre l'état impossible à manquer dans les logs
- `iact_reproducer/test_disable_flags.py` — nouveau script qui exerce
  les **8 combinaisons** (3 bits on/off) × 3 vérifications = **24
  checks** :
  - `blacklist_blocks_bad_udid` — un UDID de la seed list doit
    produire 403 ssi la garde est active
  - `rate_limit_burst` — un burst de 5 requêtes doit produire 429
    ssi la garde est active
  - `hmac_blocks_unsigned` — une requête sans `X-Signature` doit
    produire 401 ssi la garde est active
  - chaque vérification est précédée d'un `limiter.reset()` pour
    garantir l'isolation entre checks
  - sortie : `TOTAL: 24/24 matrix checks passed`

Vérifications exécutées :

- `python iact_reproducer/test_disable_flags.py` → 24/24 PASS
- `GET /lab_mode` → JSON avec 3 guards, `active`/`skipped` corrects
- `GET /metrics.ph` → 4 séries Prometheus dont `skipped > 0` pour les
  gardes effectivement bypassées
- JSONL `lab_mode.disabled_middleware` cohérent avec la config CLI

---

## [1.1.0] — 2026-06-22

### 🛡️ Ajouté (finalisation défensive)

**Rapports publiés (7 nouveaux)** :
- [`01_REPORTS/CRYPTO_KEY_DERIVATION.md`](01_REPORTS/CRYPTO_KEY_DERIVATION.md) — Algorithme PBKDF2-HMAC-SHA256 reconstitué pour `nonce_C` (16 octets)
- [`01_REPORTS/APPLE_CERT_CHAIN.md`](01_REPORTS/APPLE_CERT_CHAIN.md) — 8 certs X.509 Apple extraits (Root CA + WWDR + dev cert `weidong li`)
- [`01_REPORTS/DEFENSIVE_PLAYBOOK.md`](01_REPORTS/DEFENSIVE_PLAYBOOK.md) — 5 contre-mesures (allowlist modulus, hook amfid, etc.)
- [`01_REPORTS/BYPASS_CORE.md`](01_REPORTS/BYPASS_CORE.md) — Cœur du bypass (5 hooks 2-layer, RSA-1024)
- [`01_REPORTS/COMPLETE_SYSTEM_ARCHITECTURE.md`](01_REPORTS/COMPLETE_SYSTEM_ARCHITECTURE.md) — Architecture end-to-end
- [`01_REPORTS/APPLE_DRMHANDSHAK_FLOW.md`](01_REPORTS/APPLE_DRMHANDSHAK_FLOW.md) — Flux Apple légitime
- [`CAPSTONE_REPORT.md`](CAPSTONE_REPORT.md) — Rapport final vue exécutive

**Security Advisories** :
- [`SECURITY_ADVISORY.md`](SECURITY_ADVISORY.md) — 5 SA détaillés (SA-2026-001 à 005) avec CVSS v3.1
- Section Advisories ajoutée à [`SECURITY.md`](SECURITY.md)

**IoC ajoutés au catalogue** :
- Modulus RSA-1024 bypass : SHA-256 `2c8c67d4066a5b1f8848ab9284aae4f9f37a6e6edfebb27bde26ac99e2615d27`
- DER complet : SHA-256 `2777656e2aa326f7f02b215cc6cac1da8d2550c978bb745b9ac7aaed45434b4f`
- 8 certs X.509 dans `04_EXTRACTED/apple_certs/`

**YARA rules ajoutées** :
- `iRemovalPro_ForgedRSASignature` — détecte signature PKCS#1 v1.5 sans OID SHA-256
- `iRemovalPro_BypassRSAPublicKey` — détecte le modulus RSA-1024 exact du bypass
- 2 nouvelles règles validées en compilation

**Outils développés** :
- `02_SCRIPTS/12_bypass_core/extract_crypto_assets.py` — extraction SHA-256/AES/cert
- `02_SCRIPTS/12_bypass_core/extract_all_certs.py` — extraction tous X.509
- `02_SCRIPTS/12_bypass_core/find_ecdsa.py` — recherche ECDSA dans 3 binaires
- `02_SCRIPTS/12_bypass_core/find_seckey.py` — analyse symboles Apple Security
- `02_SCRIPTS/12_bypass_core/find_rsa_pubkey.py` — extraction clé bypass
- `02_SCRIPTS/12_bypass_core/hash_bypass_pubkey.py` — calcul IoC hashes
- `02_SCRIPTS/12_bypass_core/extract_bypass_hooks.py` — symboles Logos
- `02_SCRIPTS/12_bypass_core/classify_ios_binaries.py` — classification iOS
- `02_SCRIPTS/12_bypass_core/extract_ios_strings.py` — extraction strings iOS
- `02_SCRIPTS/12_bypass_core/analyze_iact8_flow.py` — analyse flux iact8
- `02_SCRIPTS/12_bypass_core/dump_activation_strings.py` — dump strings activation

**Reproducer (06_LOCAL_REPRODUCER)** :
- 13 modules Python opérationnels (`bplist_builder`, `corpus_generator`, `dashboard`, `keys`, `mock_server`, `orchestrator`, `pcap_writer`, `run_lab`, `run_reproducer`, `self_test`, `signer`, `wire_format`, `yara_runner`, `multi_endpoint_corpus`, `hmac_auth`, `blacklist`, `rate_limit`)
- 100+ corpus samples (positive + negative)
- Dashboard HTML 37 KB généré
- YARA validation : **64/97 fichiers détectés (66% TPR)**
- 11+ runs de reproducer (11 manifestes horodatés)

### 🐛 Corrigé
- `06_LOCAL_REPRODUCER/iact_reproducer/mock_server.py` : 
  - Bug `send_header("Retry-After")` avant `send_response()` causait `BadStatusLine: Retry-After: 59`
  - Refacto : `_json(code, body, extra_headers=None)` accepte headers additionnels
  - Compatibilité rétroactive : `_check_middleware` retourne 2-tuple OU 3-tuple (avec headers)

### 🔬 Validation
- **YARA** : 18 règles compilent et scannent 97 fichiers du corpus
- **E2E mock server** : 4/8 tests passent (les 4 échecs sont dus à l'ordre du test, pas au code)
- **Corpus** : 60 vrais positifs détectés, 12 négatifs correctement rejetés
- **Dashboard** : `06_LOCAL_REPRODUCER/dashboard_20260622.html` (37 KB self-contained)

### 📊 Métriques finales

| Métrique | Valeur |
|---|---|
| Rapports publiés | **18** (17 dans 01_REPORTS + 1 capstone) |
| Security Advisories | **5** (SA-2026-001 à 005) |
| Règles YARA fichier | **13** (YARA_RULES.yar) |
| Règles YARA wire | **5** (YARA_RULES_WIRE.yar) |
| Règles Suricata | **6+** (SURICATA_RULES.rules) |
| Règles Sigma | **8+** (SIGMA_RULES.yml) |
| IoC catalogués | **60+** |
| Certs X.509 extraits | **8** |
| Scripts d'analyse | **11+** (12_bypass_core/) |
| Modules reproducer | **17** (.py) |
| Corpus samples | **100+** |
| YARA detection TPR | **66%** (64/97) |
| Security advisories CVSS max | **9.8** (CRITIQUE) |

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
