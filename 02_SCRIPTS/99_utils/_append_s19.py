#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Append §19 to NOUVELLES_DECOUVERTES.md"""
from pathlib import Path

TARGET = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\01_REPORTS\NOUVELLES_DECOUVERTES.md")

NEW_SECTION = """

---

## 19. Clôture du moyen terme : Bundle IDs, HWID root-of-trust, server_proc_ms et alertes SIEM (2026-06-22)

> **Statut** : implémentation des recommandations #12-#15 du §14.
> Cette section documente :
> 1. §19.1 — Complétude de `FORBIDDEN_BUNDLE_IDS` pour v5.2 (recherche exhaustive)
> 2. §19.2 — Design d'un **HWID root-of-trust** (recommandation #13)
> 3. §19.3 — État de l'instrumentation `server_proc_ms` dans le mock (recommandation #14)
> 4. §19.4 — Système d'alertes SIEM à 3 tiers + règles SIGMA/Prometheus (recommandation #15)

### 19.1 FORBIDDEN_BUNDLE_IDS — recherche exhaustive pour v5.2

**Recommandation #12 (§14)** : étendre `FORBIDDEN_BUNDLE_IDS` au gré des
découvertes forensiques.

**Méthode** : scan byte-level de tous les binaires extraits
(`__analysis/extracted/*.bin` + `IRemovalPro/ref/`), avec regex
reverse-DNS, filtrage des préfixes Apple (`com.apple.*`, `com.icloud.*`,
`com.itunes.*`, `com.me.*`) et whitelist des noms de domaine (URLs HTTP).

**Résultats bruts** :

| Métrique | Valeur |
|---|---:|
| Fichiers scannés | 14 |
| Candidats totaux (regex) | 2 |
| Déjà catalogués (déjà dans FORBIDDEN_BUNDLE_IDS) | 1 |
| **NOUVEAUX candidats** | 1 |
| Faux positifs (validés) | 1 |

**Le seul "nouveau candidat" est en réalité un faux positif** :

| String candidate | Verdict | Preuve |
|---|---|---|
| `System.Net.Security.SR.resources` | **Faux positif** | Contexte = `PublicKeyToken=b03f5f7f11d50a3a` qui est le token de l'assembly .NET standard `System.Net.Security` (Microsoft). Référencé par le runtime .NET 8, sans rapport avec un Bundle ID iOS. |

**Verdict** : la liste `FORBIDDEN_BUNDLE_IDS` est **complète pour v5.2** :

```python
FORBIDDEN_BUNDLE_IDS: Dict[str, str] = {
    "com.panyolsoft.blackhound": "tweak Cydia Substrate (BY-EXT-001)",
    "com.iremovalpro.bypass":    "helper iOS du bypass (BY-EXT-002)",
    "com.blackhound.eraser":     "helper d'effacement NAND (BY-EXT-003)",
}
```

**Recommandation pour les variantes futures** : tout futur sample
d'iRemoval PRO doit être scanné via le même script
(`02_SCRIPTS/99_utils/search_bundle_ids.py`, archivé pour reproductibilité)
et tout nouveau Bundle ID validé par reverse engineering + OSINT avant ajout.

### 19.2 HWID root-of-trust — design défensif (couche D)

**Recommandation #13 (§14 + §16.4 #5)** : Apple doit signer
cryptographiquement le premier HWID observé pour un UDID.

**Problème actuel** (cf. `BYPASS_CORE.md` §14.1) : le HWID client
(empreinte opérateur) est déclaré dans le handshake iActivation sans
authentification. Un attaquant peut changer de VM et présenter un HWID
différent pour le même UDID → BY-SES-004 le détecte, mais ne peut pas
**prouver** que le HWID présenté à l'instant T₀ est bien celui attendu.

**Design proposé — 3 couches** :

#### 19.2.1 Couche D-1 — Enregistrement initial

À la **première activation** d'un iPhone (état "factory clean") :

1. L'iPhone présente `UDID`, `nonce=random()`, `client_hwid=H₀`.
2. Le serveur génère :
   - `HWID_SIG₀ = ECDSA_sign(Apple_HSM_privkey, H₀)`
   - Stocke : `(UDID, H₀, HWID_SIG₀, issued_at)` dans une base
     répliquée (Cassandra / Redis cluster).
3. Le serveur retourne `HWID_SIG₀` au client.

#### 19.2.2 Couche D-2 — Vérification aux handshakes suivants

À chaque handshake Step 9 (cf. `BYPASS_CORE.md` §16) :

1. Le client présente `(UDID, H₁, HWID_SIG₀, client_timestamp)`.
2. Le serveur :
   - Lookup `(UDID, H₀, HWID_SIG₀)` dans la base.
   - Vérifie : `ECDSA_verify(Apple_HSM_pubkey, H₀, HWID_SIG₀) == true`.
   - **Décision** :
     - `H₁ == H₀` → OK (même HWID que celui signé à l'enregistrement)
     - `H₁ != H₀` → **BY-SES-004 (HWID mismatch)** → rejet
     - `HWID_SIG₀` absent ou invalide → **BY-SES-008 (no root-of-trust sig)** → rejet

#### 19.2.3 Couche D-3 — Rotation HWID légitime (out-of-band)

Cas légitime : l'utilisateur a changé de matériel (carte mère, NAND)
suite à une réparation Apple officielle. Apple peut réémettre un
nouveau `HWID_SIG₁` :

- **Canal out-of-band** : Genius Bar + ID document + photo de la
  facture Apple Store.
- **Vérification cryptographique** : `HWID_SIG₁` doit être signé par
  un Hardware Security Module (HSM) Apple différent de celui qui a
  signé `HWID_SIG₀` (segregation of duties).
- **TTL** : `HWID_SIG₀` reste valide 30 jours après l'émission de
  `HWID_SIG₁` (grace period pour les handshakes en cours).

#### 19.2.4 Schéma de défense

```
  iPhone (factory)                Apple HSM                   Apple Server
       │                              │                            │
       │  ──── UDID, H₀, nonce ────► │                            │
       │                              │  ── store(UDID, H₀) ────►  │
       │                              │                            │
       │  ◄──── HWID_SIG₀ ───────────│                            │
       │                              │                            │
   ... 3 months later (same iPhone, same NAND) ...                │
       │                              │                            │
       │  ──── UDID, H₀, HWID_SIG₀ ──│──────────────────────────► │
       │                              │                            │  verify sig
       │                              │                            │  H₀ == stored
       │  ◄────── 200 OK ────────────│────────────────────────────│
```

#### 19.2.5 Avantages vs approche actuelle

| Attaque | Défense actuelle | Avec HWID root-of-trust |
|---|---|---|
| VM hopping (changer de HWID entre handshakes) | BY-SES-004 détecte le mismatch | BY-SES-004 + rejet immédiat du HWID jamais signé |
| Pre-signed ticket (replay d'un ancien HWID_SIG₀) | Pas de défense | HWID_SIG₀ a un TTL + nonce handshake |
| Forgery complète (UDID + HWID forgés) | BY-INT-001 (modulus blacklist) | + BY-SES-008 (no root-of-trust signature) |
| Hardware swap légitime | Réinitialisation manuelle par Apple | Procédure out-of-band D-3 (grace period 30j) |

#### 19.2.6 Coût d'implémentation

| Composant | Effort | Note |
|---|---|---|
| HSM signing (D-1) | 1 dev × 3 mois | Intégration YubiHSM2 ou AWS CloudHSM |
| Base répliquée (Cassandra) | 0.5 dev × 1 mois | TTL 30j pour HWID_SIG₀ |
| Migration client (iOS 18+) | 1 dev × 2 mois | Rétrocompat avec iOS 17 (D-1 + D-2 sans sig) |
| Procédure out-of-band (D-3) | Opérationnel | Processus Genius Bar existant, ajout d'une étape |

**Conclusion** : la défense est **techniquement réalisable** à coût
modéré, mais nécessite une décision politique (Apple doit accepter de
lier le HWID à un acte administratif lors du SAV).

### 19.3 server_proc_ms — état de l'instrumentation dans le lab

**Recommandation #14 (§14 + §16.4 #6)** : instrumenter `server_proc_ms`
côté production pour que les checks BY-SES-006/007 (timing floor/ceiling)
aient une métrique à comparer.

**État dans `06_LOCAL_REPRODUCER/iact_reproducer/mock_server.py`** :
**DÉJÀ IMPLÉMENTÉ** (l'extension v5.2-LAB-0.2 a précédé la recommandation).

#### 19.3.1 Instrumentation au niveau `_State`

Le `_State` (classe partagée entre tous les handlers) maintient :

```python
self.last_server_proc_ms: float = 0.0
self.max_server_proc_ms: float = 0.0
self.proc_ms_samples: deque = deque(maxlen=512)
self.proc_ms_client_claim_samples: deque = deque(maxlen=512)
self.proc_ms_delta_samples: deque = deque(maxlen=512)
```

#### 19.3.2 Capture au niveau middleware

Dans `_run_defender()` (handler middleware), un `time.monotonic()`
entoure l'appel à `defender.validate_ticket(...)` :

```python
_t0 = time.monotonic()
ok, reasons = defender.validate_ticket(ticket, ...)
measured_ms = (time.monotonic() - _t0) * 1000.0
delta_ms = abs(measured_ms - server_proc_ms)  # client claim

self.state.last_server_proc_ms = measured_ms
if measured_ms > self.state.max_server_proc_ms:
    self.state.max_server_proc_ms = measured_ms
self.state.proc_ms_samples.append(measured_ms)
self.state.proc_ms_client_claim_samples.append(server_proc_ms)
self.state.proc_ms_delta_samples.append(delta_ms)
```

#### 19.3.3 Exposition Prometheus — `/metrics.ph`

L'endpoint GET `/metrics.ph` expose **5 métriques** :

| Métrique | Type | Usage |
|---|---|---|
| `iact_mock_server_proc_ms_measured{quantile="0.5\|0.95\|0.99"}` + `_sum` + `_count` | Summary | Latence vue par le serveur (notre vérité) |
| `iact_mock_server_proc_ms_client_claim{...}` | Summary | Latence déclarée par le client (à comparer) |
| `iact_mock_server_proc_ms_delta{...}` | Summary | `|measured - claim|` — détection time-spoofing |
| `iact_mock_server_proc_ms_last` | Gauge | Dernière mesure (debug) |
| `iact_mock_server_proc_ms_max` | Gauge | Pic depuis démarrage du serveur |

**Exemple de scrape** :

```promql
iact_mock_server_proc_ms_measured{quantile="0.5"}    3.247
iact_mock_server_proc_ms_measured{quantile="0.95"}   8.142
iact_mock_server_proc_ms_measured{quantile="0.99"}  15.390
iact_mock_server_proc_ms_measured_sum               1247.123
iact_mock_server_proc_ms_measured_count              312
iact_mock_server_proc_ms_client_claim{quantile="0.5"}  2.100
iact_mock_server_proc_ms_delta{quantile="0.5"}         1.500
iact_mock_server_proc_ms_last                          3.247
iact_mock_server_proc_ms_max                           28.412
```

#### 19.3.4 Recommandation de déploiement production

Pour le passage en production (Apple), les mêmes 5 métriques
devraient être exposées avec un préfixe Apple (par exemple
`apple_drm_server_proc_ms_*`) et le `_State` répliqué sur Redis avec
`TTL = 3600` secondes (1h glissante).

Le déploiement doit être coordonné avec l'activation du check
BY-SES-006/007, car sans ces métriques, les seuils de timing sont
aveugles.

### 19.4 Système d'alertes SIEM — 3 tiers (P1/P2/P3)

**Recommandation #15 (§14 + §16.4 #7)** : alerter sur `defender_hits`
non-nul.

**État actuel** : **DÉJÀ IMPLÉMENTÉ** dans `mock_server.py` + nouvelles
règles SIGMA/Prometheus dans `05_IOC/alerts/`.

#### 19.4.1 Émetteur côté mock (`_emit_alert`)

```python
def _emit_alert(self, *, check_id, reason, request_id, udid, ip, source):
    severity = self.state.CHECK_SEVERITY.get(check_id, "P3")
    with self.state.lock:
        self.state.defender_alerts[severity] += 1
        self.state.alert_log.append({
            "ts": ..., "severity": severity, "check_id": check_id,
            "reason": reason, "request_id": request_id,
            "udid": udid, "ip": ip, "source": source,
            "lab_marker": TEST_MARKER,
        })
```

#### 19.4.2 Mapping check-ID → tier

| Tier | Check-IDs | Politique SIEM |
|---|---|---|
| **P1** | `BY-MOD-001` | Page immédiatement (PagerDuty P1) |
| **P2** | `BY-EXT-001`, `BY-PLI-001` | Ticket urgent (PagerDuty P2) |
| **P3** | `BY-SES-001..007` et autres | Corrélation bursts (5+ en 5min = escalade P2) |

#### 19.4.3 Règles SIGMA créées (5)

Fichier : `05_IOC/alerts/SIGMA_RULES.yml`

| ID | Tier | Quoi |
|---|---|---|
| `8f4a1b3c-ire-0015-p1` | critical | P1 émis par mock_server |
| `8f4a1b3c-ire-0015-p2` | high | P2 émis par mock_server |
| `8f4a1b3c-ire-0015-p3` | medium | P3 émis par mock_server |
| `8f4a1b3c-ire-0016` | high | mock_server démarré avec `--disable-*` (middleware permissif) |
| `8f4a1b3c-ire-0017` | medium | Drop anormal de `server_proc_ms_measured` p50 < 5ms (batch pré-signé) |

#### 19.4.4 Alertes Prometheus créées (5)

Fichier : `05_IOC/alerts/README.md` (section "Prometheus alert definitions")

| Alert | Expression | Sévérité |
|---|---|---|
| `IRemovalPRO_DefenderP1Critical` | `increase(iact_mock_defender_alerts_total{severity="P1"}[5m]) > 0` | critical |
| `IRemovalPRO_DefenderP2High` | `increase(...{severity="P2"}[5m]) > 0` | high |
| `IRemovalPRO_DefenderP3Burst` | `increase(...{severity="P3"}[5m]) > 5` | medium |
| `IRemovalPRO_ServerProcMsDrop` | `iact_mock_server_proc_ms_measured{q="0.5"} < 5 AND rate(...) > 10` | medium |
| `IRemovalPRO_SkippedGuard` | `increase(iact_mock_skipped_guards_total{guard!="any"}[5m]) > 0` | high |

#### 19.4.5 JSON view — `/alerts.ph`

L'endpoint `GET /alerts.ph` retourne :

```json
{
  "lab_marker": "iRemovalLabTest",
  "ts": "2026-06-22T10:30:00Z",
  "counts": {"P1": 0, "P2": 0, "P3": 0},
  "recent": [
    {
      "ts": "2026-06-22T10:29:59Z",
      "severity": "P1",
      "check_id": "BY-MOD-001",
      "reason": "public_key_modulus SHA-1 matches iRemoval PRO v5.2 bypass",
      "request_id": "mw-20260622T102959123456",
      "udid": "00008110-...",
      "ip": "192.168.1.42",
      "source": "middleware:defender",
      "lab_marker": "iRemovalLabTest"
    }
  ]
}
```

### 19.5 Bilan global du moyen terme

| # | Recommandation | Statut | Artefact |
|---:|---|---|---|
| 9 | Chemins de build hashés | 🟠 | (cf. §1.3 — hashes documentés, extraction automatisée non livrée) |
| 10 | Analyser `Chaos.Crypto` | ✅ | cf. §17 — namespace custom Mono/Xamarin.iOS |
| 11 | Confirmer rôle 24 opérations DMD | 🟠 | cf. §3 — catalogue dressé, classification READ/WRITE/CRITICAL dans `05_IOC/dmd_operations_classified.json` |
| 12 | Étendre `FORBIDDEN_BUNDLE_IDS` | ✅ | cf. §19.1 — déjà complet pour v5.2 |
| 13 | HWID root-of-trust | ✅ | cf. §19.2 — design 3 couches (D-1, D-2, D-3) |
| 14 | Instrumenter `server_proc_ms` | ✅ | cf. §19.3 — déjà implémenté dans `mock_server.py` |
| 15 | Alerte SIEM `defender_hits` | ✅ | cf. §19.4 — 5 SIGMA + 5 Prometheus + JSON view |

**Score** : 5/7 ✅ (71 %) — #9 et #11 restent en recommandation (extraction
automatisée de hashes de build + corrélation runtime ↔ DMD nécessitent
un lab Frida runtime, hors scope de cette analyse statique).

### 19.6 Cross-références

- **§14 (recommandations)** — items #12, #13, #14, #15 marqués ✅
- **§16.4 (mise à jour défensive)** — items #3, #5, #6, #7 marqués ✅
- **`05_IOC/alerts/SIGMA_RULES.yml`** — 5 règles créées (P1/P2/P3 + skipped guard + proc_ms anomaly)
- **`05_IOC/alerts/README.md`** — métriques Prometheus + 5 alertes PromQL documentées
- **`06_LOCAL_REPRODUCER/apple_drm_defense.py`** — `FORBIDDEN_BUNDLE_IDS` (ligne 222) déjà complet pour v5.2
- **`06_LOCAL_REPRODUCER/iact_reproducer/mock_server.py`** — `_State.__init__` (lignes ~195-225) et `_emit_alert` (lignes ~290-318) déjà en place
- **`02_SCRIPTS/99_utils/search_bundle_ids.py`** — script de scan pour reproductibilité (archivé)
"""

# Append to the file
with open(TARGET, "a", encoding="utf-8") as fh:
    fh.write(NEW_SECTION)

print(f"Appended §19 to {TARGET}")
print(f"New size: {TARGET.stat().st_size:,} bytes")
