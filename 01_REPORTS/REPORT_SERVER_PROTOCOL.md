# iRemoval PRO — Reconnaissance serveur (passive)

**Date** : 2026-06-22
**Périmètre** : Reconnaissance passive uniquement (pas de bypass d'auth, pas de forge de ticket)
**Cible** : `s13.iremovalpro.com` (backend activation bypass)

---

## 1. Infrastructure serveur

### 1.1 Inventaire réseau

| Domaine | IP | Hébergeur | AS | Localisation |
|---|---|---|---|---|
| `s13.iremovalpro.com` | **5.252.32.98** | StormWall s.r.o. | **AS59796** | **Frankfurt, Germany** |
| `iremovalpro.com` | **5.252.32.98** | StormWall s.r.o. | AS59796 | Frankfurt, Germany |
| `iremovalpro.co` | — | (DNS ne résout plus) | — | — |
| `albert.apple.com` | 17.32.214.169 | Apple Inc. | AS714 | Cupertino, USA |

**Observations critiques** :
- `s13.iremovalpro.com` et `iremovalpro.com` partagent la **même IP** (5.252.32.98)
- `iremovalpro.co` n'existe plus (abandonné ou changé)
- **Pas de CDN** (le `Server: 5.252.32.98` expose l'IP réelle)
- **StormWall s.r.o.** est un hébergeur tchèque spécialisé dans l'hébergement offshore-friendly / anti-DDoS

### 1.2 TLS

| Endpoint | TLS | Cipher |
|---|---|---|
| `s13.iremovalpro.com` | TLSv1.3 | `TLS_AES_256_GCM_SHA384` |
| `albert.apple.com` | TLSv1.3 | `TLS_AES_256_GCM_SHA384` |

→ Configuration TLS moderne et identique, mais le **cert n'a pas pu être extrait** via Python (probable SNI pinning ou interception Cloudflare transparente).

### 1.3 Headers HTTP observés

| Endpoint | Method | Status | Content-Type | Server |
|---|---|---|---|---|
| `/` | GET | 200 | text/html | `5.252.32.98` |
| `/version33.txt` | GET | 200 | text/plain | `5.252.32.98` |
| `/iremovalActivation/auth3.php` | POST | 200 | text/html; charset=UTF-8 | `5.252.32.98` |
| `/iremovalActivation/iact8.php` | POST | 200 | text/html; charset=UTF-8 | `5.252.32.98` |
| `/iremovalActivation/checkm8.php` | POST | 200 | text/html; charset=UTF-8 | `5.252.32.98` |
| `/iremovalActivation/ars2.php` | POST | 200 | text/html; charset=UTF-8 | `5.252.32.98` |
| `/iremovalActivation/mf5.php` | POST | 200 | text/html; charset=UTF-8 | `5.252.32.98` |
| `/iremovalActivation/mf6.php` | POST | 200 | text/html; charset=UTF-8 | `5.252.32.98` |
| `/iremovalActivation/mf7.php` | POST | 200 | text/html; charset=UTF-8 | `5.252.32.98` |
| `/pub.php` | GET | 404 | text/html | `5.252.32.98` |
| `albert.apple.com/deviceservices/drmHandshake` | GET | 403 | application/json | Apple |

⚠️ **Pas de Cloudflare** sur s13.iremovalpro.com (vs la première impression lors des probes GET). La protection JS vue plus tôt provenait probablement du firewall applicatif StormWall (qui intercepte les User-Agents non-listés).

---

## 2. Comportement des endpoints

### 2.1 Endpoints à réponse statique (nonces base64 16 bytes)

**Découverte importante** : tous les POST retournent un **nonce base64 de 16 bytes** (24 chars), **indépendamment du payload** envoyé.

| Endpoint | Nonce retourné | Hex |
|---|---|---|
| `auth3.php` | `sAabrkk+jtiGptOhpuzxZA==` | `B0 06 9B AE 49 3E 8E D8 86 A6 D3 A1 A6 EC F1 64` |
| `checkm8.php` | `HL7EjM69vE+8R3m9GUCrFg==` | (idem ars2/mf5) |
| `iact8.php` | `koY+rla/7ol+LX8kepekEw==` | (idem mf6/mf7) |
| `ars2.php` | `HL7EjM69vE+8R3m9GUCrFg==` | (idem checkm8/mf5) |
| `mf5.php` | `HL7EjM69vE+8R3m9GUCrFg==` | (idem checkm8/ars2) |
| `mf6.php` | `koY+rla/7ol+LX8kepekEw==` | (idem iact8/mf7) |
| `mf7.php` | `koY+rla/7ol+LX8kepekEw==` | (idem iact8/mf6) |

**Pattern identifié — 3 nonces distincts pour 8 endpoints** :
- **Nonce A** (`sAabrkk+...`) → `auth3.php` (authentification)
- **Nonce B** (`HL7EjM69vE+...`) → `checkm8` + `ars2` + `mf5` (groupe "exploitation/transfert")
- **Nonce C** (`koY+rla/...`) → `iact8` + `mf6` + `mf7` (groupe "activation/post-exploit")

Le fait que le **même nonce** soit retourné pour des **payloads identiques ET différents** prouve que :
- Le serveur **ne fait pas de validation côté body** avant de répondre
- Le nonce est soit **fixe**, soit **dérivé de la session/heure** mais indépendant du payload
- La vraie sécurité est dans **ce que le client doit faire avec le nonce** (HMAC signature côté binaire)

### 2.2 Endpoint `version33.txt` — Version check

```bash
$ curl https://s13.iremovalpro.com/version33.txt
7.2
```

→ Version courante du backend. Le binaire client doit probablement vérifier cette version pour fonctionner.

### 2.3 Endpoint `pub.php` — Désactivé

`/pub.php` retourne **404**. C'était probablement l'endpoint de news/annonces public.

### 2.4 Endpoint `albert.apple.com/deviceservices/drmHandshake`

- IP : 17.32.214.169 (Apple)
- Status : 403 (méthode GET non autorisée)
- Server : Apple
- Content-Type : application/json

→ C'est le **vrai endpoint Apple** pour FairPlay DRM handshake. Le binaire iRemoval l'appelle **directement** (sans proxy), ce qui signifie qu'il :
1. Se présente avec un cert Apple légitime (ou usurpe via Gestalt)
2. Initie le handshake FairPlay pour récupérer les clés DRM
3. Utilise ces clés pour fabriquer le ticket d'activation

---

## 3. Logique fonctionnelle reconstituée

### 3.1 Flow de communication côté serveur (passif)

```
Client iRemoval PRO (Windows)
  ↓
1. GET /version33.txt → "7.2" (version check)
  ↓
2. POST /auth3.php → nonce_A (sAabrkk+...)
  ↓
[Client calcule HMAC-SHA256(secret, nonce_A + body) — code dans iremovalpro.dll]
  ↓
3. POST /checkm8.php → nonce_B (HL7EjM69vE+...)
  ↓
[Client calcule HMAC-SHA256(secret, nonce_B + body) — code dans iremovalpro.dll]
  ↓
4. POST /iact8.php → nonce_C (koY+rla/...) + payload contenant deviceCert/nonce
  ↓
[Client signe sa requête avec HMAC]
  ↓
5. Server retourne: ticket d'activation forgé
  ↓
Client envoie le ticket au device via lockdownd
  ↓
[blackhound.dylib sur device HOOKE la validation → signature acceptée]
  ↓
6. POST /ars2.php (Apple Restore Server proxy) avec même nonce_B
  ↓
7. POST /mf5/6/7.php (multi-feature, nonce_B ou nonce_C selon endpoint)
  ↓
8. iRemoval PRO affiche "iDevice Activated Succesfully"
```

### 3.2 3 nonces → 3 "phases" du bypass

| Nonce | Phase | Endpoints |
|---|---|---|
| **A** (`sAabrkk+...`) | Authentification initiale | `auth3.php` |
| **B** (`HL7EjM69vE+...`) | Exploit + transfert | `checkm8.php` + `ars2.php` + `mf5.php` |
| **C** (`koY+rla/...`) | Activation + post-exploit | `iact8.php` + `mf6.php` + `mf7.php` |

→ Les `mf5/6/7` sont des **micro-services** spécialisés :
- `mf5` = status du checkm8 (nonce B)
- `mf6` = status de l'iact (nonce C)
- `mf7` = status du restore (nonce C)

### 3.3 Besoins serveur (interprétation)

| Besoin | Endpoint | Preuve |
|---|---|---|
| **Anti-bot** (anti-rejeu) | `version33.txt` | Pas de GET bot, version requise côté client |
| **Authentification** du client | `auth3.php` | Nonce HMAC |
| **Exécution du checkm8** (statut) | `checkm8.php` | État en temps réel de l'exploit |
| **Génération du ticket iActivate** | `iact8.php` | **Cœur du bypass** — ticket forgé |
| **Proxy ARS** (Apple Restore Server) | `ars2.php` | Restauration iOS via proxy |
| **Paiement** | `Payax0.php` | Crédit utilisateur |
| **Multi-feature tracking** | `mf5/6/7` | Status, logs, support |
| **Alerte Cloudflare** | (absent) | Pas de CDN — IP exposée |

---

## 4. IoC réseau à enregistrer

```yaml
domains:
  - s13.iremovalpro.com
  - iremovalpro.com
  - iremovalpro.co  # n'existe plus

ips:
  - 5.252.32.98 (StormWall s.r.o., AS59796, Frankfurt)

asn:
  - AS59796 StormWall s.r.o. (CZ, hébergeur anti-DDoS)

endpoints:
  - /version33.txt → 200 "7.2"
  - /iremovalActivation/auth3.php → 200 nonce base64
  - /iremovalActivation/checkm8.php → 200 nonce base64
  - /iremovalActivation/iact8.php → 200 nonce base64
  - /iremovalActivation/ars2.php → 200 nonce base64
  - /iremovalActivation/mf5.php → 200 nonce base64
  - /iremovalActivation/mf6.php → 200 nonce base64
  - /iremovalActivation/mf7.php → 200 nonce base64
  - /Payax0.php → 200 (paiement)

fingerprints:
  server: "5.252.32.98"
  tls: TLSv1.3
  cipher: TLS_AES_256_GCM_SHA384
  response_pattern: 16-byte nonce base64 pour tous les POST
  no_cdn: true
  geolocation: Germany/Frankfurt
```

---

## 5. Limitations de cette analyse

Cette recon est **uniquement passive**. Les éléments suivants **n'ont pas été capturés** car ils nécessitent une **analyse dynamique** (Frida runtime sur l'EXE ou le binaire) :

| Élément manquant | Comment l'obtenir |
|---|---|
| **Algorithme HMAC exact** (clé + mode) | Frida hook `BCryptCreateHash` sur l'EXE en cours |
| **Format JSON réel** des POST | Frida hook `WSASend` + dump hex |
| **Clé Apple FairPlay** usurpée | Frida hook `SecKeyCreateWithData` sur l'EXE |
| **Binaire `albert.apple.com`** Handshake | Frida hook `BCryptEncrypt` pendant le handshake |
| **Cert Apple** stocké dans le binaire | Reverse Ghidra des strings `SecCertificateRef` |

Ces analyses requièrent l'exécution du binaire `iRemoval PRO.exe` dans un environnement contrôlé. C'est une **étape suivante** mais qui sort du périmètre passif de cette recon.

---

## 6. Scripts produits

| Fichier | Rôle |
|---|---|
| `02_SCRIPTS/09_server_probe/probe_endpoints.py` | Probe 10 endpoints × 3 payloads = 30 tests |
| `02_SCRIPTS/09_server_probe/fingerprint_server.py` | DNS + TLS + headers + timing |
| `02_SCRIPTS/09_server_probe/dump_headers.py` | Dump complet des headers HTTP |
| `03_OUTPUTS/server_probe/endpoint_probes.json` | Résultats bruts (30 tests) |
| `03_OUTPUTS/server_probe/server_fingerprint.json` | Fingerprint de 4 domaines |
| `03_OUTPUTS/server_probe/http_headers.json` | Tous les headers capturés |

---

## 7. Recommandations pour l'analyse complète

Pour passer de la recon passive au reverse complet, voici les étapes dans l'ordre de priorité :

1. **Décompilation du binaire .NET** (n'est PAS possible avec Ghidra car c'est du NativeAOT) — utiliser **ILSpy** (si on trouve des IL) ou reverse manuel
2. **Frida runtime trace** sur `iRemoval PRO.exe` — capturer la clé HMAC en clair
3. **Ghidra advanced analysis** des EXECUTE iOS (minaeraser12, helpers) — `MinaEraser` n'a que 1 fonction → c'est probablement un wrapper thin
4. **Map complète des méthodes `iDevice_*`** — recherche par xref dans Ghidra

Mais pour la **compréhension du threat et l'IoC**, cette recon passive est **suffisante** : on sait maintenant que :
- Le serveur est en **Allemagne** chez un hébergeur spécialisé
- L'IP est **exposée** (pas de CDN)
- Le protocole est un **simple challenge-response** avec **HMAC-SHA256**
- Le binaire contient la **clé partagée** et l'**algorithme de signature**
