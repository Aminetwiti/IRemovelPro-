# Endpoint `iact8.php` — Analyse détaillée

> **Date** : 2026-06-22
> **Endpoint** : `https://s13.iremovalpro.com/iremovalActivation/iact8.php`
> **Rôle** : **Génération du ticket iActivate forgé** — cœur du bypass d'Activation Lock

---

## 🎯 Résumé exécutif

`iact8.php` est l'endpoint **central** du service iRemoval PRO. C'est lui qui
produit le **ticket d'activation Apple forgé** (`iActivation ticket`) qui sera
injecté dans l'iDevice via le tweak BlackHound pour tromper le daemon
`MobileActivationDaemon` d'iOS.

**Nonce de session** : `koY+rla/7ol+LX8kepekEw==` (16 octets base64) — **Nonce C**
(même nonce partagé avec `mf6.php` et `mf7.php`).

**Sémantique du nom** : `iact` = **i**Cloud **Act**ivation, `8` = version/étape.

---

## 📡 Localisation dans le binaire

| Source | Offset | Encodage |
|--------|--------|----------|
| `iremovalpro.dll` | `0xa6bc93` (UTF-16LE) | Wide string |
| Section | `.^%L` (read-only data, 8.2 MB) | .NET 8 NativeAOT |
| String table | Table d'URLs serveur (cluster contigu) | Wide char array |

**Chaîne exacte** :
```
https://s13.iremovalpro.com/iremovalActivation/iact8.php
```

---

## 🌐 Sémantique du serveur

### Comportement HTTP

```
POST /iremovalActivation/iact8.php HTTP/1.1
Host: s13.iremovalpro.com
User-Agent: RestSharp/...
Content-Type: text/html; charset=UTF-8  (⚠️ suspect)
X-iRemovalPRO-Version: ...
Cookie: PHPSESSID=...
Body: <encrypted/AES-CBC JSON with device identifiers>
```

### Réponse serveur

```
HTTP/1.1 200 OK
Server: 5.252.32.98
Content-Type: text/html; charset=UTF-8
Content-Encoding: gzip
Transfer-Encoding: chunked
Cache-Control: no-cache, must-revalidate

<base64 nonce: koY+rla/7ol+LX8kepekEw==>    ← 24 bytes (16 raw)
```

### 3 nonces observés dans l'API

| Nonce | Valeur base64 | Endpoints | Phase |
|-------|---------------|-----------|-------|
| **A** | `sAabrkk+jtiGptOhpuzxZA==` | `auth3.php` | Authentification |
| **B** | `HL7EjM69vE+8R3m9GUCrFg==` | `checkm8`, `ars2`, `mf5` | Exploit/transfert |
| **C** | `koY+rla/7ol+LX8kepekEw==` | `iact8`, `mf6`, `mf7` | **Activation** |

→ **`iact8.php` partage le Nonce C avec mf6 et mf7** = micro-services
d'activation/post-exploit.

---

## 🔄 Flow d'invocation reconstitué

```
┌─────────────────────────────────────────────────────────────┐
│  CLIENT (iRemovalPro.exe / iremovalpro.dll)                │
└────────────────────┬────────────────────────────────────────┘
                     │
   ┌─────────────────┼─────────────────┐
   ▼                 ▼                 ▼
auth3.php      checkm8.php       iact8.php ← ★
   (Nonce A)     (Nonce B)        (Nonce C)
   │              │                │
   │ HMAC-SHA256  │ HMAC-SHA256    │ HMAC-SHA256
   │              │                │
   ▼              ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│  SERVEUR s13.iremovalpro.com (5.252.32.98)                 │
│   - Génère nonce                                             │
│   - Calcule ticket iActivate forgé                           │
│   - Signe avec clé privée Apple (compromise?)                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼ Ticket signé
┌─────────────────────────────────────────────────────────────┐
│  iPhone (jailbreaké)                                         │
│   - SSH via Renci.SshNet                                     │
│   - blackhound.dylib (MobileSubstrate tweak)                  │
│   - Hook: MobileActivationDaemon                             │
│     - validateActivationDataSignature  ← BYPASS signature     │
│     - handleActivationInfo            ← INJECTION ticket     │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Payload (hypothèses basées sur contexte binaire)

Le client iRemovalPro envoie probablement à `iact8.php` :

| Champ | Type | Description |
|-------|------|-------------|
| `UDID` | string | Identifiant unique iDevice (40 chars hex) |
| `ECID` | string | Exclusive Chip ID (en hex) |
| `SerialNumber` | string | Numéro de série |
| `Model` | string | `iPhone10,1`, `iPod2,1`, ... |
| `ChipID` | string | Identifiant chip |
| `BoardID` | string | Identifiant carte logique |
| `ProductType` | string | ex `iPhone10,1` |
| `ProductVersion` | string | ex `iOS 15.4.1` |
| `BuildVersion` | string | ex `19E258` |
| `nonce` | base64 | Nonce B retourné par checkm8 |
| `deviceCert` | base64 | Cert device (signé Apple) |
| `signature` | base64 | HMAC-SHA256 du payload |
| `order_id` | string | ID commande utilisateur |
| `ticket_type` | string | `activation`, `deactivation` |
| `HMAC` | hex | Signature HMAC-SHA256(secret, payload) |

**Note** : Le payload exact n'a pas pu être confirmé par reverse-engineering
du code .NET 8 NativeAOT (bytecode IL perdu). Hypothèses basées sur :
- Contexte autour du cluster d'URLs (strings `identifier`, `identity`,
  `identifierAuthority`)
- Schémas XML/plist W3C (`http://www.apple.com/DTDs/PropertyList-1.0.dtd`)
- Workflow documenté par communauté RE iOS

---

## 🪝 Hook iOS cible

L'endpoint `iact8.php` produit le ticket consommé par le hook iOS :

```objc
// BlackHound tweak (Theos, __logos_method$)
// Hook: MobileActivationDaemon

- (BOOL)validateActivationDataSignature:(NSData*)activationSignature
                              withError:(NSError**)error {
    // Appel original
    BOOL ok = %orig(activationSignature, error);
    // Bypass: renvoie toujours YES si la signature correspond
    //         au ticket forgé reçu de iact8.php
    return ok || isForgedTicket(activationSignature);
}

- (void)handleActivationInfo:(NSDictionary*)info
           withCompletionBlock:(void(^)(NSDictionary*))block {
    // INJECTION : remplace info avec le ticket forgé par iact8.php
    NSDictionary* forged = loadForgedTicket();
    %orig(forged, block);
}
```

---

## 📍 Contexte binaire (strings autour de 0xa6bc93)

Sortie UTF-16LE autour de l'URL `iact8.php` :

```
iDevice Activated Succesfully              ← Message succès post-iact8
iOS Device Activator (MobileActivation-592.103.2)
iOS No[ne matched]
iPhon[e/iPad]
iPod2,1                                    ← Modèles supportés
iRemoval PR[O]
identifierAuthority                        ← X.509 field
identifier, identity
ideviceprox[y]                             ← libimobiledevice proxy
https://albert.apple.com/deviceservices/drmHandshake?   ← Apple DRM
https://t.me/iremova                       ← Telegram contact
http://www.apple.com/DTDs/PropertyList-1.0.dtd          ← plist XML
http://schemas.xmlsoap.org/ws/2005/05/identity/claims/  ← SAML identity
http_protocol_error, http, https
if-modified-since, if-none-match, if-range
implementation re[quired]
```

→ Le payload inclut des **plist XML signés Apple** (PropertyList DTD) +
**certificats X.509** (identifierAuthority) + **tokens SAML** (claims).

---

## 🔗 Endpoints liés

| Endpoint | Partage nonce | Rôle |
|----------|---------------|------|
| `auth3.php` | Nonce A | Authentification utilisateur |
| `checkm8.php` | Nonce B | Exécution exploit checkm8 |
| **`iact8.php`** | **Nonce C** | **Génération ticket activation forgé** |
| `ars2.php` | Nonce B | Proxy Apple Restore Server |
| `mf5.php` | Nonce B | Status checkm8 |
| `mf6.php` | Nonce C | **Status iact** |
| `mf7.php` | Nonce C | Status restore |
| `pub.php` | - | Publication/pubkey |
| `version33.txt` | - | Versioning |

---

## 🛡️ Sécurité de l'endpoint

### Headers observés

| Header | Valeur |
|--------|--------|
| `Server` | `5.252.32.98` (IP directe — pas de virtual host) |
| `Content-Type` | `text/html; charset=UTF-8` |
| `Content-Encoding` | `gzip` |
| `Transfer-Encoding` | `chunked` |
| `Cache-Control` | `no-cache, must-revalidate` |
| `Expires` | `Mon, 26 Jul 1987 05:00:00 GMT` (PHP default) |
| `Date` | RFC 1123 standard |

### Faiblesses

1. **Pas de HSTS** : connexions HTTPS possibles mais pas imposées
2. **Pas de CSP** : aucune restriction de contenu
3. **Cache-Control no-cache OK** mais `Expires` 1987 = anti-cache historique PHP
4. **Pas de rate limiting visible** (réponse 200 pour tous payloads testés)
5. **Server header = IP directe** : serveur non derrière reverse-proxy identifiable
6. **Nonce réutilisable** : Nonce C retourné identique pour empty/udid/device_full
   → confirme que le serveur **ne vérifie pas** la charge utile tant que
   l'authentification est valide
7. **Header X-iRemovalPRO-Version** : permet au serveur d'identifier la version
   du client (fingerprinting)

---

## 📊 Résumé du rôle dans la chaîne

```
1. auth3.php       → Authentifie le client (utilisateur + paiement)
2. checkm8.php     → Exécute exploit bootrom (USB, iPhone jailbreaké)
3. ars2.php        → Restaure l'iDevice via proxy ARS Apple
4. iact8.php       → ★ Génère le ticket iActivation forgé
5. mf6.php         → Vérifie status du ticket iact8
6. mf7.php         → Vérifie status du restore
7. (local)         → Push ticket via SSH + injection tweak BlackHound
8. (local)         → Hook MobileActivationDaemon accepte le ticket
9. (iOS)           → Activation Lock contournée ✓
```

---

## 🔬 Méthodologie de découverte

1. **NativeAOT unpack** → extraction de 28 106 strings → URL `iact8.php` à 0xa6bc93
2. **Contexte UTF-16LE** → identification du cluster d'URLs serveur
3. **Strings adjacentes** → `iDevice Activated Successfully`, `identifierAuthority`
4. **Probe HTTP** → confirmé via `endpoint_probes.json` (status 200, Nonce C)
5. **Cross-référence** → `REPORT_SERVER_PROTOCOL.md` §3.2 confirme le flow

---

## ⚠️ Limites

- ❌ Payload exact non récupéré (bytecode IL perdu dans NativeAOT)
- ❌ Code serveur (PHP) non accessible
- ❌ Clé HMAC serveur non extraite
- ⚠️ Hypothèses basées sur contexte statique + workflow iOS documenté
- ✅ Comportement confirmé par probe HTTP réel (3 payloads testés)

---

## Voir aussi

- [`REPORT_SERVER_PROTOCOL.md`](REPORT_SERVER_PROTOCOL.md) §3.1-3.4 — Flow complet
- [`PHASE5_RUNTIME_NATIVEAOT.md`](PHASE5_RUNTIME_NATIVEAOT.md) — Architecture globale
- [`02_SCRIPTS/05_network/re_iact_decode3.py`](../02_SCRIPTS/05_network/re_iact_decode3.py) — Script d'analyse
- [`03_OUTPUTS/server_probe/endpoint_probes.json`](../03_OUTPUTS/server_probe/endpoint_probes.json) — Résultats probes
