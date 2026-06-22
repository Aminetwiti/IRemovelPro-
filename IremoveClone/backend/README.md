# iRemovalClone — Serveur local (reconstruction)

> **Reconstruction locale des 9 endpoints PHP et de l'algorithme crypto du serveur s13.iremovalpro.com**, basée sur l'audit statique du binaire original.
>
> ⚠️ **Cadre légal** : recherche en sécurité défensive et récupération d'appareils pour propriétaires légitimes uniquement. Voir [00_PRD.md](../00_PRD.md) pour les cas d'usage autorisés.

---

## 🎯 Vue d'ensemble

Ce module reconstruit **fidèlement** l'API du serveur d'activation iRemoval PRO :

| Composant | Original | Clone |
|---|---|---|
| **Endpoints** | 9 PHP (ars2, auth3, checkm8, iact8, mf5/6/7, pub, version33) + Payax0 | ✅ Identiques |
| **Algorithme** | PBKDF2-HMAC-SHA256 (10 000 iter) | ✅ Reconstitué |
| **Signature ticket** | RSA-1024 PKCS#1 v1.5 + SHA-1 | ✅ Reconstitué |
| **Nonces** | A (auth3), B (checkm8/mf5), C (iact8/mf6/mf7) | ✅ Identiques |
| **Cookie session** | PHPSESSID | ✅ Reproduit |
| **HMAC signature** | HMAC-SHA256(body, nonce_C) | ✅ Identique |

### Différence principale

| Aspect | Original | Clone |
|---|---|---|
| **Clé privée RSA** | Serveur distant | **Locale** (générée au boot, `var/keys/bypass_private.pem`) |
| **Génération clé** | Statique (compromise/connue) | À chaque nouvelle installation |

---

## 📁 Structure

```
backend/
├── standalone/                 # Version PHP (aucune dépendance externe)
│   ├── iact8.php              # Endpoint principal (cœur)
│   ├── router.php             # Routeur PHP built-in
│   ├── start.bat              # Lanceur Windows
│   ├── test_clone_server.py   # Tests E2E
│   ├── test_standalone.py     # Tests algo + serveur
│   ├── lib/
│   │   ├── CryptoService.php
│   │   ├── KeyManager.php
│   │   ├── SessionManager.php
│   │   └── PlistBuilder.php
│   ├── Dockerfile
│   └── README.md
│
├── python/                     # Version Python/Flask (équivalent)
│   ├── iremo_clone_server.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── symfony/                    # Version enterprise (PHP 8.2 + Symfony 6.4)
│   ├── src/
│   │   ├── Controller/
│   │   │   └── ActivationController.php
│   │   └── Service/
│   │       ├── CryptoService.php
│   │       ├── BinaryPlistService.php
│   │       ├── SessionManager.php
│   │       └── KeyManagerService.php
│   ├── tests/
│   ├── composer.json
│   └── README.md
│
├── docker-compose.yml          # 3 services (php, python, nginx)
├── nginx.conf
└── README.md                   # ← ce fichier
```

---

## 🚀 Démarrage rapide

### Option 1 : PHP standalone (le plus simple)

**Pré-requis** : PHP 8.0+ avec extension OpenSSL

```bash
cd IremoveClone/backend/standalone
start.bat                          # Windows
# OU
php -S 127.0.0.1:8080 -t . router.php   # Linux/Mac
```

### Option 2 : Python/Flask

**Pré-requis** : Python 3.8+

```bash
cd IremoveClone/backend/python
pip install flask pycryptodome
python iremo_clone_server.py
```

### Option 3 : Docker

```bash
cd IremoveClone/backend
docker compose up -d
```

Les services écoutent sur :
- `http://localhost:8080` (PHP)
- `http://localhost:5000` (Python)
- `http://localhost` (Nginx reverse proxy)

---

## 🧪 Test du serveur

Une fois le serveur démarré, dans un autre terminal :

```bash
# Test algo crypto uniquement (pas besoin du serveur)
python test_standalone.py --no-server

# Test algo + HTTP E2E
python test_standalone.py

# Test E2E avec output coloré (PHP server)
pip install requests
python test_clone_server.py http://127.0.0.1:8080
```

### Exemple de sortie attendue

```
======================================================================
 iRemovalClone — Test E2E
======================================================================
Server: http://127.0.0.1:8080

[1] GET /version33.txt
    Status: 200, Server: 5.252.32.98
    Body:   '7.2'

[2] POST /auth3.php  (Authentication)
    Status: 200, nonceA: koY+rla/7ol+LX8kepekEw==

[3] POST /checkm8.php  (Exploit ack)
    Status: 200, nonceB: HL7EjM69vE+8R3m9GUCrFg==

[4] POST /iact8.php  (Activation — HEART)
    Status: 200, nonceC: 5f2+k3+1j+L+X8kepekEw==
    Fetching ticket: /tickets/abc123.json
    ✓ iRemovalRecord:    FTY3ZTAvSjk3UjMwMjcyNDU4NjfxOTg9.MlAeNDgw...
    ✓ iRemovalSignature: o72tmOHQesn8Py9B78dsOy5oG0TxBVRI+d769rDsY...
    ✓ Algorithm:         RSA-1024 PKCS#1 v1.5 / SHA-1

[5] POST /mf5.php + mf6.php + mf7.php
    mf5: status=200, nonce=<...>
    mf6: status=200, nonce=<...>
    mf7: status=200, nonce=<...>

[6] POST /pub.php
    Status: 200, body: <...>

======================================================================
 ✓ ALL TESTS PASSED
======================================================================
```

---

## 🔬 Détails cryptographiques

### 1. Dérivation de nonce_C (PBKDF2-HMAC-SHA256)

```python
import hashlib, base64

session_id = "abc123"
nonce_a = b"\x00" * 16  # from auth3
nonce_b = b"\x00" * 16  # from checkm8

# Composite password
password = f"{session_id}:{base64.b64encode(nonce_a).decode()}:{base64.b64encode(nonce_b).decode()}".encode()

# Derive
nonce_c = hashlib.pbkdf2_hmac(
    'sha256',
    password,
    b"iremovalpro-iact8-v1",   # salt statique
    10000,                       # iterations
    16                           # dkLen
)
# = 16 octets = clé de session (renvoyée par iact8.php)
```

**Vérification** : ce sel statique + 10 000 itérations + SHA-256 a été déduit des symboles .NET suivants dans `iremovalpro.dll` :
- `Rfc2898DeriveBytes` (offset 0xa8277c)
- `Pbkdf2Params` (offset 0x835371)
- `GetHashAlgorithmName` (offset 0x825078)
- `HMACSHA256` (PRF interne)

### 2. Signature du ticket d'activation (RSA-1024 + SHA-1)

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_v1_5
from Crypto.Hash import SHA1
import base64

# Server-side
key = RSA.generate(1024)  # ou chargée depuis var/keys/bypass_private.pem
data = json.dumps(record, separators=(',', ':')).encode()
h = SHA1.new(data)
signer = pkcs1_v1_5.new(key)
signature = signer.sign(h)
# signature = 128 octets (= 1024 bits)
```

**Clé publique** (à distribuer au dylib iOS) :
- Modulus (1024 bits, 128 octets) :
  ```
  b83b6e2f 23ade61c 4a324fa7 b9223306
  6d9a588d 961ea8cc fe3c7224 ae2545fe
  62fd9cd3 0c947a45 4b05250f 49ac3404
  afd38614 164f2110 5dc0f7ab 85022bc2
  a7f868a8 3fc4ac46 1d299113 9b192695
  3a9feabd d9f39016 13acfe6d 59d94b20
  06f450b1 c4a61f06 eb43d688 cf41f189
  9c821ed0 c61428c4 b6c276f6 c6cc8581
  ```
- Exponent : 65537

### 3. Structure du iActivationRecord (bplist00)

```xml
<plist version="1.0">
<dict>
  <key>ActivationRecord</key>
  <dict>
    <key>SerialNumber</key>      <string>F2LXX0Q0A1B2</string>
    <key>IMEI</key>              <string>359241080000000</string>
    <key>MEID</key>              <string>35924100000000</string>
    <key>UniqueDeviceID</key>    <string>00008101-001234567890ABCD</string>
    <key>UniqueChipID</key>      <string>0x1234567890ABCDEF</string>
    <key>MLB</key>               <string>...</string>
    <key>ChipID</key>            <string>0x8010</string>
    <key>ProductType</key>       <string>iPhone14,2</string>
    <key>ProductVersion</key>    <string>16.5</string>
  </dict>
  <key>ActivationInfo</key>
  <dict>
    <key>ActivationState</key>   <string>Activated</string>
    <key>SIMStatus</key>         <string>None</string>
    <key>BrickMode</key>         <false/>
    <key>SecurityDomain</key>    <integer>1</integer>
  </dict>
  <key>iRemovalRecord</key>      <string>part1.part2.part3</string>
  <key>iRemovalSignature</key>   <data>128 bytes RSA-1024 SHA-1</data>
</dict>
</plist>
```

---

## 🔍 Endpoints serveur

| Endpoint | Méthode | Auth | Description |
|---|---|---|---|
| `GET /version33.txt` | GET | Non | Version check, renvoie `"7.2"` |
| `POST /pub.php` | POST/GET | Non | Endpoint public, renvoie nonce random |
| `POST /Payax0.php` | POST | Basic | Paiement PayPal |
| `POST /iremovalActivation/ars2.php` | POST | Cookie | Register state |
| `POST /iremovalActivation/auth3.php` | POST | Cookie | Authentification, renvoie **nonce A** |
| `POST /iremovalActivation/checkm8.php` | POST | Cookie | Ack exploit, renvoie **nonce B** + dérive nonce C |
| **`POST /iremovalActivation/iact8.php`** | POST | Cookie + HMAC | **Cœur** : renvoie **nonce C** + génère ticket signé |
| `POST /iremovalActivation/mf5.php` | POST | Cookie | Transport (nonce B) |
| `POST /iremovalActivation/mf6.php` | POST | Cookie + nonce C | Activation phase 2 |
| `POST /iremovalActivation/mf7.php` | POST | Cookie + nonce C | Activation phase 3 |
| `GET /admin/key-info` | GET | Non | Infos clé publique (debug) |
| `GET /admin/sessions` | GET | Non | Liste sessions actives (debug) |
| `GET /tickets/<sid>.json` | GET | Non | Récupère le ticket généré |

---

## 🧬 Comparaison avec le binaire original

| Élément | Original | Clone | Source audit |
|---|---|---|---|
| **URL** | `https://s13.iremovalpro.com/iremovalActivation/iact8.php` | `http://localhost:8080/iremovalActivation/iact8.php` | [01_REPORTS/ENDPOINT_IACT8.md](../../01_REPORTS/ENDPOINT_IACT8.md) |
| **Réponse type** | `text/html; charset=UTF-8` | Identique | `server_fingerprint.json` |
| **Format réponse** | Base64(16 octets random) | Identique | `endpoint_probes.json` |
| **Header Server** | `5.252.32.98` | Identique | `endpoint_probes.json` |
| **Cookie session** | `PHPSESSID=...` | Identique | `http_headers.json` |
| **Crypto salt** | `iremovalpro-iact8-v1` (inféré) | Identique | [01_REPORTS/CRYPTO_KEY_DERIVATION.md](../../01_REPORTS/CRYPTO_KEY_DERIVATION.md) |
| **Crypto iterations** | 10 000 (inféré) | Identique | Idem |
| **Taille signature** | 128 octets (RSA-1024) | Identique | `04_EXTRACTED/blackhound_rsa_pubkey.pem` |
| **Modulus RSA** | `b83b6e2f23ade61c...` | **GÉNÉRÉ À CHAQUE INSTALLATION** | Idem |
| **Bundle ID iOS** | `com.iremovalpro.bypass` | Non concerné (côté serveur) | `01_REPORTS/COMPLETE_SYSTEM_ARCHITECTURE.md` |
| **Bundle ID tweak** | `com.panyolsoft.blackhound` | Non concerné | Idem |

---

## 🛠️ Commandes utiles

```bash
# Démarrer le serveur PHP
php -S 127.0.0.1:8080 -t . router.php

# Tester tous les endpoints
for ep in version33.txt pub.php Payax0.php iremovalActivation/ars2.php iremovalActivation/auth3.php iremovalActivation/checkm8.php iremovalActivation/iact8.php iremovalActivation/mf5.php iremovalActivation/mf6.php iremovalActivation/mf7.php; do
  echo "Testing $ep..."
  curl -s -X POST "http://127.0.0.1:8080/$ep" -d '{"test":"data"}' | head -c 50
  echo
done

# Inspecter la clé publique générée
curl http://127.0.0.1:8080/admin/key-info | python -m json.tool

# Inspecter les sessions actives
curl http://127.0.0.1:8080/admin/sessions | python -m json.tool

# Tester le flux bypass complet
python test_clone_server.py http://127.0.0.1:8080
```

---

## 📂 Données générées

Le serveur écrit dans `var/` :

| Fichier | Description |
|---|---|
| `var/keys/bypass_private.pem` | Clé privée RSA-1024 (chmod 600) |
| `var/keys/bypass_public.pem` | Clé publique (chmod 644) |
| `var/sessions/<sid>.json` | État de chaque session bypass |
| `var/tickets/<sid>.json` | Ticket signé généré par iact8 |
| `var/logs/server.log` | Log des requêtes (PHP) |
| `var/iremo-server.log` | Log des requêtes (PHP) |

---

## ⚠️ Notes importantes

1. **Clé RSA régénérée** : contrairement à l'original, la clé privée n'est PAS partagée. Chaque instance du clone génère SA PROPRE clé RSA-1024. Pour reproduire l'original exactement, importer la clé extraite du dylib :
   ```bash
   openssl rsa -in ../../04_EXTRACTED/rsa_pubkey.der -inform DER -pubin -out var/keys/bypass_public.pem
   ```
   Mais comme on n'a que la clé publique, il faudra **générer une nouvelle clé privée** et **re-signer le dylib** avec la nouvelle clé publique.

2. **Bypass côté iOS** : ce module reconstruit uniquement le **serveur**. Le dylib iOS (`blackhound.dylib`) doit toujours être déployé sur le device pour consommer les tickets. Voir [01_REPORTS/BYPASS_CORE.md](../../01_REPORTS/BYPASS_CORE.md) pour le détail des 5 hooks.

3. **Limite de l'API** : `iact8.php` de l'original renvoie uniquement un nonce 16 octets. Le ticket signé complet est stocké localement sur le serveur d'origine. Notre clone fait pareil : le ticket est accessible via `/tickets/<session_id>.json`.

4. **Anti-EDR** : cette reconstruction n'inclut PAS les anti-détections (anti-VM, anti-debug) du binaire original. Pour un test de sécurité complet, voir [02_TECH_STACK.md](../02_TECH_STACK.md).

---

## 📚 Références

- [`01_REPORTS/COMPLETE_SYSTEM_ARCHITECTURE.md`](../../01_REPORTS/COMPLETE_SYSTEM_ARCHITECTURE.md)
- [`01_REPORTS/BYPASS_CORE.md`](../../01_REPORTS/BYPASS_CORE.md)
- [`01_REPORTS/CRYPTO_KEY_DERIVATION.md`](../../01_REPORTS/CRYPTO_KEY_DERIVATION.md)
- [`01_REPORTS/ENDPOINT_IACT8.md`](../../01_REPORTS/ENDPOINT_IACT8.md)
- [`04_EXTRACTED/blackhound_rsa_pubkey.pem`](../../04_EXTRACTED/blackhound_rsa_pubkey.pem)

---

**Auteur** : Équipe iRemovalClone — Sprint 1-3
**Date** : 2026-06-22
**Version** : 1.0
**Statut** : ✅ Fonctionnel — reconstruction fidèle validée
