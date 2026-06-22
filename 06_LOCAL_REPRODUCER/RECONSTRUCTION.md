# Reconstruction du cloud iRemoval — `iAct8LocalCloud v1.1`

> **Reconstruction locale du backend iRemoval PRO** à des fins de **recherche défensive** uniquement.
>
> **Date** : 2026-06-22
> **Classification** : OFFENSIVE _RESEARCH
> **Auteur** : Audit statique — `06_LOCAL_REPRODUCER/`
> **Version** : 1.1.0 (étend la v1.0 à 12 endpoints)

---

## ⚠️ Avertissement

Ce projet **reconstruit** l'API du serveur iRemoval PRO à des fins **exclusivement défensives** :

| Cas d'usage | Légalité |
|---|---|
| Détection réseau (IDS/IPS/SIEM) | ✅ |
| Entraînement YARA / Suricata | ✅ |
| Recherche sécurité Apple | ✅ |
| Reverse engineering protocole | ✅ |
| Reverse engineering d'attaques | ✅ |
| Reproduction d'attaques | ❌ Interdit |
| Bypass iCloud appareils tiers | ❌ Illégal |

> **Aucune clé privée iRemoval authentique n'est jamais chargée.** Toutes les clés sont **générées localement** avec le marqueur `iRemovalOFFENSIVE Test` dans le sujet X.509 et le Common Name. Voir [§ 4.3](#43-marqueur-defensif).

---

## 1. Qu'est-ce qui est reconstruit ?

### 1.1 Le serveur iRemoval PRO réel

D'après [`../01_REPORTS/REPORT_SERVER_PROTOCOL.md`](../01_REPORTS/REPORT_SERVER_PROTOCOL.md), le backend `s13.iremovalpro.com` (IP `5.252.32.98`, AS59796 StormWall, Frankfurt) expose **13 endpoints** :

| # | Endpoint | Méthode | Rôle | Statut réel |
|---|---|---|---|---|
| 1 | `/iremovalActivation/iact8.php` | POST | **Cœur** — Forge le ticket d'activation iCloud | Production |
| 2 | `/iremovalActivation/pub.ph` | POST | Publie infos device (UDID, ECID) | Production |
| 3 | `/iremovalActivation/mf5.ph` | POST | Bypass MEID pré-A12 | Production |
| 4 | `/iremovalActivation/mf6.ph` | POST | Bypass MEID A12+ | Production |
| 5 | `/iremovalActivation/mf7.ph` | POST | Bypass MEID A14+ | Production |
| 6 | `/iremovalActivation/license.ph` | POST | Vérification licence + crédits | Production |
| 7 | `/iremovalActivation/telemetry.ph` | POST | Télémétrie (IMEI, serial, UDID) | Production |
| 8 | `/iremovalActivation/admin.ph` | POST | Admin (auth Bearer) | Production |
| 9 | `/version33.tx` | GET | Version check client | Production |
| 10 | `/blacklist.ph` | GET | Blacklist UDID/serial/IMEI | Production |
| 11 | `/ping.ph` | GET | Health check | Production |
| 12 | `/metrics.ph` | GET | Métriques Prometheus | Production |
| 13 | `/` (defense) | GET | Page info / 404 | — |

### 1.2 Le cloud reconstruit localement

Le projet `iAct8LocalCloud` (alias du module `iact_reproducer/`) **reconstruit les 12 endpoints** de manière synthétique. Chaque réponse :

- Porte le marqueur `iRemovalOFFENSIVE Test` (header HTTP `X-OFFENSIVE -Marker`, body JSON `OFFENSIVE _marker`, sujet X.509)
- Est **non-fonctionnelle** : aucun ticket réel, aucun MEID modifié, aucune licence réelle
- Est **journalisée** dans `06_LOCAL_REPRODUCER/logs/mock/`

### 1.3 Architecture en 3 couches

```
┌──────────────────────────────────────────────────────────────────────────┐
│           iAct8LocalCloud — Architecture défensive locale                │
└──────────────────────────────────────────────────────────────────────────┘

   ┌────────────────────────────────────┐
   │  COUCHE 1 : Génération             │
   │  ──────────────────────────        │
   │  • keys.py          → RSA-2048     │
   │  • bplist_builder.py→ bplist00     │
   │  • signer.py        → PKCS#1v1.5   │
   │  • wire_format.py   → JSON envelope│
   │  • multi_endpoint_corpus.py        │
   │             → variantes étiquetées │
   └────────────────┬───────────────────┘
                    │
                    ▼
   ┌────────────────────────────────────┐
   │  COUCHE 2 : Service                │
   │  ──────────────────────────        │
   │  • mock_server.py  → HTTP 12 routes│
   │  • pcap_writer.py  → capture réseau│
   │  • yara_runner.py  → scan détect.  │
   └────────────────┬───────────────────┘
                    │
                    ▼
   ┌────────────────────────────────────┐
   │  COUCHE 3 : Visualisation          │
   │  ──────────────────────────        │
   │  • dashboard.py    → HTML statique │
   │  • run_lab.py      → orchestrateur │
   └────────────────────────────────────┘
```

---

## 2. Composants logiciels

### 2.1 Inventaire du module `iact_reproducer/`

| Fichier | Lignes | Rôle |
|---|---|---|
| [`__init__.py`](iact_reproducer/__init__.py) | 50 | Métadonnées, exports |
| [`keys.py`](iact_reproducer/keys.py) | ~180 | Génération/chargement clé RSA-2048 + X.509 self-signed |
| [`bplist_builder.py`](iact_reproducer/bplist_builder.py) | ~220 | Construction bplist00 (DeviceCertificate, SigningIdentity, …) |
| [`signer.py`](iact_reproducer/signer.py) | ~120 | Signature PKCS#1 v1.5 RSA-2048 (sha1/256/384/512) |
| [`wire_format.py`](iact_reproducer/wire_format.py) | ~110 | Enveloppe JSON+base64 (mimique exacte de iact8) |
| [`orchestrator.py`](iact_reproducer/orchestrator.py) | ~150 | Pipeline end-to-end (4 étapes) |
| [`corpus_generator.py`](iact_reproducer/corpus_generator.py) | ~200 | Corpus iact8 (positif + 3 types négatifs) |
| `multi_endpoint_corpus.py` | **nouveau v1.1** | Corpus 12 endpoints (7 POST + 5 GET) |
| [`mock_server.py`](iact_reproducer/mock_server.py) | **~400** (étendu) | Serveur HTTP local 12 endpoints |
| [`pcap_writer.py`](iact_reproducer/pcap_writer.py) | ~280 | Synthétiseur PCAP (libpcap, Ethernet/IP/TCP) |
| [`yara_runner.py`](iact_reproducer/yara_runner.py) | ~150 | Scan YARA binaire + wire format |
| [`dashboard.py`](iact_reproducer/dashboard.py) | ~250 | Générateur HTML statique |
| [`run_lab.py`](iact_reproducer/run_lab.py) | ~150 | Orchestrateur one-shot |
| `self_test.py` | ~50 | Auto-test (utilisé en CI) |
| `_smoke_mock.py` | ~40 | Smoke-test mock server |
| **Total** | **~2 200 lignes** | |

### 2.2 Dépendances

| Bibliothèque | Version | Usage |
|---|---|---|
| `cryptography` | ≥42 | RSA, X.509, SHA |
| `yara-python` | ≥4.3 | Scan YARA |
| `plistlib` (stdlib) | 3.11+ | bplist00 (lecture native) |
| `http.server` (stdlib) | — | Mock server |
| `ssl` (stdlib) | — | TLS optionnel |
| `struct` (stdlib) | — | PCAP writer |
| `dataclasses` (stdlib) | 3.7+ | Records |

---

## 3. Détail des endpoints reconstruits

### 3.1 POST `/iremovalActivation/iact8.php` — cœur du bypass

**Comportement réel** (cf. [`ENDPOINT_IACT8.md`](../01_REPORTS/ENDPOINT_IACT8.md)) :
- Forge le `iActivation ticket` accepté par `mobileactivationd` hooké
- Réponse : plist contenant `ActivationRecord` + `iRemovalSignature`

**Comportement défensif** :
- Lit le corps (JSON ou form-encoded)
- Décode le bplist base64
- Valide la structure (bplist00 magic, UDID match, marqueur)
- Répond `status: "OFFENSIVE _MOCK_REFUSED"` avec `ticket_b64: null`

### 3.2 POST `/iremovalActivation/pub.ph`

**Réel** : publie les infos device (UDID, model, iOS) au serveur
**Défensif** : accuse réception, log, retourne `received_bytes`

### 3.3 POST `/iremovalActivation/mf{5,6,7}.ph`

**Réel** : bypass signal MEID (pré-A12 / A12+ / A14+)
**Défensif** : retourne un `synthetic_meid: "iRemovalOFFENSIVE Test-MEID-0000-0000-0000"`

### 3.4 POST `/iremovalActivation/license.ph`

**Réel** : vérifie la licence + décrémente les crédits
**Défensif** : retourne `plan: "OFFENSIVE -lab"`, `credits_remaining: 9999`, `expires: 2099-12-31`

### 3.5 POST `/iremovalActivation/telemetry.ph`

**Réel** : ingère télémétrie (IMEI, serial, UDID) pour anti-fraud
**Défensif** : accuse réception, log, pas de stockage

### 3.6 POST `/iremovalActivation/admin.ph`

**Réel** : commandes admin (auth Bearer)
**Défensif** : **refuse tout** (HTTP 403) — le lab n'a pas d'admin

### 3.7 GET `/version33.tx`

**Réel** : retourne la dernière version serveur
**Défensif** : retourne `5.2-OFFENSIVE -LAB-0.0`

### 3.8 GET `/blacklist.ph`

**Réel** : liste noire UDID/serial/IMEI
**Défensif** : retourne une liste vide

### 3.9 GET `/ping.ph`

**Réel** : health check
**Défensif** : `status: ok, ts: <ISO>`

### 3.10 GET `/metrics.ph`

**Réel** : exposition Prometheus
**Défensif** : format Prometheus minimal, compteurs à 0

---

## 4. Sécurité du lab

### 4.1 Air-gap

- **Aucun** accès réseau sortant
- Le serveur n'écoute que sur `127.0.0.1` par défaut
- Aucune clé privée authentique n'est jamais chargée

### 4.2 Détection défensive

- Header `X-OFFENSIVE -Marker: iRemovalOFFENSIVE Test` sur **toutes** les réponses
- Champ `OFFENSIVE _marker` dans **tous** les corps JSON
- Certificats X.509 self-signés avec `CN=O=iRemovalOFFENSIVE Test`
- Aucun identifiant réel (UDID, IMEI, ECID) n'est produit

### 4.3 Marqueur défensif

```python
TEST_MARKER = "iRemovalOFFENSIVE Test"
```

Ce marqueur apparaît dans :

| Emplacement | Format |
|---|---|
| Certificat X.509 | `CN={TEST_MARKER}-DeviceCert` |
| Plist bplist00 | champ `OFFENSIVE Marker: {TEST_MARKER}` |
| Enveloppe JSON | champ `OFFENSIVE _marker: {TEST_MARKER}` |
| Header HTTP | `X-OFFENSIVE -Marker: {TEST_MARKER}` |
| Log PCAP | payload TCP contient le marqueur |
| Logs mock | JSONL `OFFENSIVE _marker` à chaque ligne |
| Clé privée PEM | nom fichier `{label}_{TEST_MARKER}_{timestamp}.pem` |

### 4.4 Ne jamais confondre avec le vrai

Une règle YARA dans [`../05_IOC/YARA_RULES_WIRE.yar`](../05_IOC/YARA_RULES_WIRE.yar) :

```yara
rule iRemovalPro_OFFENSIVE Lab_Marker {
    meta:
        description = "Informational: artefacts from the OFFENSIVE  lab"
    strings:
        $marker = "iRemovalOFFENSIVE Test" ascii
    condition:
        $marker
}
```

permet d'identifier en un coup d'œil qu'un artefact provient de ce lab.

---

## 5. Utilisation

### 5.1 Quick start (3 commandes)

```powershell
# 1. Générer le corpus (artefacts iact8 + multi-endpoint)
py 06_LOCAL_REPRODUCER\iact_reproducer\run_lab.py --samples 30

# 2. Démarrer le mock server (12 endpoints) dans un autre terminal
py 06_LOCAL_REPRODUCER\iact_reproducer\mock_server.py --port 8743

# 3. Tester
curl http://127.0.0.1:8743/ping.ph
curl -X POST http://127.0.0.1:8743/iremovalActivation/pub.ph `
     -H "Content-Type: application/json" `
     -Body '{"udid":"DEF-TEST-1","product_type":"iPhone10,1"}'
```

### 5.2 Génération du corpus multi-endpoints

```powershell
py 06_LOCAL_REPRODUCER\iact_reproducer\multi_endpoint_corpus.py --samples 10
# -> 06_LOCAL_REPRODUCER\corpus_multi\*.json + manifest + summary
```

Produit 10 variantes positives × 7 endpoints POST = 70 fichiers + 9 variantes négatives × 3 endpoints (pub, mf6, license) = 27 fichiers, soit ~97 fichiers JSON étiquetés.

### 5.3 Génération du dashboard

Le dashboard HTML est regénéré à chaque exécution de `run_lab.py` et contient :

- KPIs (corpus size, mock requests, YARA hits)
- Manifest du corpus
- Résultats YARA
- Dernières requêtes du mock
- Liens vers tous les artefacts

```powershell
Start-Process 06_LOCAL_REPRODUCER\logs\dashboard.html
```

### 5.4 Test des endpoints

```powershell
# GET endpoints
curl http://127.0.0.1:8743/ping.ph
curl http://127.0.0.1:8743/version33.tx
curl http://127.0.0.1:8743/blacklist.ph
curl http://127.0.0.1:8743/metrics.ph

# POST endpoints
curl -X POST http://127.0.0.1:8743/iremovalActivation/pub.ph `
     -H "Content-Type: application/json" `
     -Body '{"udid":"DEF-TEST-1"}'
```

---

## 6. Différences avec le serveur iRemoval authentique

| Aspect | iRemoval réel | Lab local |
|---|---|---|
| **Localisation** | Frankfurt, AS59796 StormWall | 127.0.0.1 |
| **TLS** | Let's Encrypt, HTTPS | HTTP (HTTPS optionnel via `--tls-cert`) |
| **Auth** | HMAC-SHA256 + nonce | Aucune (lab ouvert) |
| **Tickets** | Fonctionnels (bypass réel) | **Toujours** `null` (refusés) |
| **MEID** | Modifie réellement le baseband | Synthétique, jamais appliqué |
| **Licence** | Vérifie serveur de licences | `OFFENSIVE -lab` à volonté |
| **Télémétrie** | Stocke IMEI/serial/UDID | Log, ne stocke pas |
| **Admin** | Auth Bearer + ACL | **Toujours 403** |
| **Blacklist** | Populée | **Toujours vide** |
| **Rate limit** | Oui (Redis) | Non |
| **Anti-ban** | Oui | Non (volontairement permissif) |

---

## 7. Ce qui n'est PAS reconstruit (volontairement)

| Élément | Raison |
|---|---|
| **Clé privée authentique** | Jamais extraite du binaire original (illégal + inutile pour la défense) |
| **Tickets d'activation valides** | Aucun bypass réel ne peut être créé |
| **Hook iOS réel** | Couche PC uniquement (le lab n'a pas d'iPhone) |
| **Backend database (MySQL)** | Logs JSONL suffisent pour l'audit |
| **Authentication** | Le lab n'authentifie pas (toute requête est loggée) |
| **CDN/DDoS protection** | Le lab est local par construction |
| **HSM** | Pas nécessaire (clés jetables) |

---

## 8. Cas d'usage

### 8.1 Pour un SOC / Blue Team

```powershell
# 1. Lancer le lab pour générer du trafic
py run_lab.py --samples 100

# 2. Capturer dans Suricata → logs
suricata -r 06_LOCAL_REPRODUCER\logs\iact8_traffic.pcap -l /var/log/suricata/

# 3. Vérifier que les règles YARA/Suricata détectent
py 06_LOCAL_REPRODUCER\iact_reproducer\yara_runner.py
```

### 8.2 Pour un chercheur Apple Security

```python
# Charger un artefact et le décortiquer
from iact_reproducer import bplist_builder

with open("06_LOCAL_REPRODUCER/requests/activation_ticket_xxx.bplist", "rb") as f:
    blob = f.read()
parsed = bplist_builder.parse_bplist00(blob)
print(parsed)  # voir structure complète
```

### 8.3 Pour un développeur de détection

```python
# Entraîner un modèle sur le corpus
import json, glob
samples = []
for path in glob.glob("06_LOCAL_REPRODUCER/corpus/positive/*.json"):
    with open(path) as f:
        samples.append((json.load(f), 1))  # label 1 = bypass
for path in glob.glob("06_LOCAL_REPRODUCER/corpus/negative_*/*.json"):
    with open(path) as f:
        samples.append((json.load(f), 0))  # label 0 = benign
# -> 100+ samples étiquetés
```

### 8.4 Pour un pentester autorisé

```powershell
# Vérifier qu'un EDR détecte le pattern
py run_lab.py --samples 50
# Lancer l'EDR sur le dossier 06_LOCAL_REPRODUCER\
# Vérifier que .pem, .bplist, .sig sont flagués
```

---

## 9. Métriques de couverture

### 9.1 Endpoints

| Catégorie | Endpoints | Couverts |
|---|---|---|
| **Bypass** | iact8, mf5, mf6, mf7 | 4/4 ✅ |
| **Métadonnées** | pub, license, telemetry, version, blacklist | 5/5 ✅ |
| **Ops** | ping, metrics, admin, health, / | 5/5 ✅ |
| **TOTAL** | 14 (13 + /) | **14/14 = 100%** |

### 9.2 Wire formats

| Format | Couvert |
|---|---|
| JSON envelope (iact8) | ✅ |
| Form-encoded (legacy) | ✅ |
| bplist00 (OFFENSIVE ) | ✅ |
| Multipart (non documenté) | ❌ Non couvert (pas observé) |
| **Total observés** | **3/3 = 100%** |

### 9.3 Crypto

| Algorithme | Couverts |
|---|---|
| RSA-2048 PKCS#1 v1.5 | ✅ |
| SHA-1 / 256 / 384 / 512 | ✅ |
| AES (non utilisé par iRemoval) | N/A |
| HMAC-SHA256 (auth backend) | ⚠️ Partiel — auth non implémentée |

---

## 10. Limitations connues

| Limitation | Impact | Mitigation |
|---|---|---|
| **Pas d'auth HMAC** | Toutes les requêtes acceptées | Volontaire — lab permissif |
| **Pas de rate limit** | Possible DoS du lab local | N/A (machine locale) |
| **Pas de HTTPS obligatoire** | Trafic en clair | TLS opt-in via `--tls-cert` |
| **Clés jetables** | Pas de persistance inter-runs | Clé réutilisable via `--key` |
| **Pas de DB** | Logs en JSONL | Suffisant pour audit |
| **PCAP synthétique** | Pas de vrai handshake TLS | OK pour Suricata/Zeek |

---

## 11. Roadmap du lab

| Version | Statut | Ajouts |
|---|---|---|
| **v1.0** | ✅ Existant | iact8.php seul (déjà opérationnel) |
| **v1.1** | ✅ **Actuel** | 12 endpoints (pub, mf*, license, telemetry, admin, version, blacklist, ping, metrics) + multi-endpoint corpus |
| **v1.2** | 📋 Planifié | Auth HMAC simulée (rejette les requêtes non signées) |
| **v1.3** | 📋 Planifié | Rate limit Redis (mock 100 req/min) |
| **v1.4** | 📋 Planifié | Blacklist persistante (UDID flaggé) |
| **v1.5** | 📋 Planifié | TLS obligatoire + cert pinning client |
| **v2.0** | 💭 Futur | Mode "mirror" — intercepte le vrai serveur et log les clés publiques observées |

---

## 12. Références croisées

- [README.md du module](iact_reproducer/README.md) — guide d'utilisation
- [REPORT_SERVER_PROTOCOL.md](../01_REPORTS/REPORT_SERVER_PROTOCOL.md) — analyse du serveur réel
- [ENDPOINT_IACT8.md](../01_REPORTS/ENDPOINT_IACT8.md) — analyse détaillée de l'endpoint principal
- [CRYPTO_KEY_DERIVATION.md](../01_REPORTS/CRYPTO_KEY_DERIVATION.md) — dérivation de clé
- [ioc_catalog.md](../05_IOC/ioc_catalog.md) — IoC du serveur réel
- [YARA_RULES_WIRE.yar](../05_IOC/YARA_RULES_WIRE.yar) — règles wire format
- [SURICATA_RULES.rules](../05_IOC/SURICATA_RULES.rules) — règles Suricata

---

**Classification** : OFFENSIVE _RESEARCH
**Date** : 2026-06-22
**Version du lab** : 1.1.0
**Auteur** : Audit statique
