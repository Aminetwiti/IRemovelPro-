# Apple drmHandshak Flow — Documentation défensive

> **Objectif** : Cartographier le flux légitime du endpoint Apple `albert.apple.com/deviceservices/drmHandshak` et documenter comment iRemoval PRO l'utilise.
> 
> **Public** : Équipe de sécurité Apple / chercheurs en sécurité
> **Périmètre** : Documentation défensive uniquement
> **Date** : 2026-06-22
> **TLP** : LEAKED

---

## 1. Vue d'ensemble

Le endpoint `https://albert.apple.com/deviceservices/drmHandshak` est un **service officiel Apple** utilisé pour :

1. **FairPlay DRM** : Distribution des clés de chiffrement pour le contenu protégé
2. **Device Certificates** : Signature des certificats d'appareil pour les services iCloud
3. **Activation Tickets** : Signature des tickets d'activation iCloud

C'est un endpoint **légitime** utilisé par **tous les appareils iOS** lors de l'activation initiale et de l'utilisation de services Apple.

---

## 2. Flux normal (légitime)

```
┌────────────┐                                    ┌────────────────────┐
│  iPhone    │                                    │  albert.apple.com   │
│  (iOS)     │                                    │  /drmHandshak       │
└─────┬──────┘                                    └──────────┬──────────┘
      │                                                     │
      │  1. Device boot                                      │
      │     ↓                                                │
      │  2. lockdownd                                         │
      │     ↓                                                │
      │  3. mobileactivationd                                 │
      │     ↓                                                │
      │  4. Generate device certificate request               │
      │     (ECID, ChipID, BoardID, etc.)                     │
      │     ↓                                                │
      ├──── HTTPS POST /drmHandshak ────────────────────────▶│
      │     Body: { device_data, nonce }                      │
      │                                                     │
      │     ◀───── Signed device certificate ─────────────────┤
      │     Body: { cert, signature }                         │
      │                                                     │
      │  5. Store cert in Secure Enclave                      │
      │     ↓                                                │
      │  6. Request activation ticket                         │
      │     ↓                                                │
      │  7. Use cert to authenticate to iCloud                 │
      │                                                     │
```

**Composants légitimes** :
- `mobileactivationd` (daemon iOS)
- `fairplayd` (FairPlay daemon)
- `securityd` (Secure Enclave proxy)

**Sécurité** :
- Certificats signés par Apple Root CA
- Clés privées dans Secure Enclave (jamais exposées)
- Nonce unique par requête (anti-replay)
- Cert chaining vérifié

---

## 3. Flux iRemoval PRO (non légitime)

L'app iRemoval PRO **ne contourne pas** `drmHandshak` directement, mais **injecte** un ticket d'activation forgé en amont.

```
┌────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────────┐
│  iPhone    │    │ blackhound   │    │ mobileactd    │    │ s13.iremoval    │
│  (iOS)     │    │ .dylib       │    │ (hooked)      │    │ pro.com         │
└─────┬──────┘    └──────┬───────┘    └──────┬───────┘    └────────┬────────┘
      │                  │                  │                     │
      │  1. App stores  │                  │                     │
      │  activation     │                  │                     │
      │  record.plist   │                  │                     │
      │  (forged)       │                  │                     │
      │                 │                  │                     │
      │  2. mobileactd  │                  │                     │
      │  reads plist    │                  │                     │
      ├─────────────────┼─────────────────▶│                     │
      │                 │                  │                     │
      │                 │  3. Hook:        │                     │
      │                 │  validateActi    │                     │
      │                 │  vationData      │                     │
      │                 │  returns YES     │                     │
      │                 │                  │                     │
      │                 │                  │  4. Hook:           │
      │                 │                  │  handleActiva       │
      │                 │                  │  tionInfo           │
      │                 │                  │  returns success    │
      │                 │                  │                     │
      │  5. Send forged ticket                              │
      ├─────────────────┼──────────────────┼─────────────────────▶
      │                 │                  │                     │
      │                 │                  │  6. Server           │
      │                 │                  │  returns signed     │
      │                 │                  │  ticket              │
      │◀────────────────┼──────────────────┼─────────────────────┤
      │                 │                  │                     │
      │  7. mobileactd  │                  │                     │
      │  validates via  │                  │                     │
      │  hooked method  │                  │                     │
      ├─────────────────┼─────────────────▶│                     │
      │                 │                  │                     │
      │                 │  8. Hooked       │                     │
      │                 │  validation      │                     │
      │                 │  returns TRUE    │                     │
      │                 │                  │                     │
      │  9. Accepts forged activation                       │
      │     ↓                                                │
      │  10. Calls drmHandshak                              │
      │     (legitimate Apple endpoint)                      │
      ├─────────────────────────────────────────────────────▶
      │                                                     │
      │  11. drmHandshak completes (sees legitimate        │
      │      request from "activated" device)               │
      │                                                     │
```

---

## 4. Détail technique de l'attaque

### 4.1 Hook Cydia Substrate

`blackhound.dylib` intercepte 3 méthodes de `MobileActivationDaemon` :

```objc
// Hook 1 — Always return valid signature
- (BOOL)validateActivationDataSignature:(NSData *)activationSignature
                          activationData:(NSDictionary *)activationData
                              withError:(NSError **)error
{
    return YES;  // ← Always true
}

// Hook 2 — Always return success
- (void)handleActivationInfo:(NSDictionary *)activationInfo
         withCompletionBlock:(void (^)(NSDictionary *response, NSError *error))completionBlock
{
    completionBlock(@{@"response": @"Success"}, nil);  // ← Always success
}

// Hook 3 — Variant with session
- (void)handleActivationInfoWithSession:(id)session
                    activationSignature:(NSData *)signature
                        completionBlock:(void (^)(NSDictionary *response, NSError *error))completionBlock
{
    completionBlock(@{@"response": @"Success"}, nil);
}
```

### 4.2 Endpoints serveur

| Endpoint | Méthode | Rôle |
|---|---|---|
| `https://s13.iremovalpro.com/iremovalActivation/auth3.ph` | POST | Authentification client (IMEI, serial) |
| `https://s13.iremovalpro.com/iremovalActivation/checkm8.ph` | POST | Status checkm8 exploit |
| `https://s13.iremovalpro.com/iremovalActivation/iact8.ph` | POST | Demande ticket d'activation forgé |
| `https://s13.iremovalpro.com/iremovalActivation/ars2.ph` | POST | Proxy Apple Restore Server |
| `https://s13.iremovalpro.com/iremovalActivation/mf5.ph` | POST | Bypass MEID signal v5 |
| `https://s13.iremovalpro.com/iremovalActivation/mf6.ph` | POST | Bypass MEID signal v6 |
| `https://s13.iremovalpro.com/iremovalActivation/mf7.ph` | POST | Bypass MEID signal v7 |
| `https://s13.iremovalpro.com/pub.ph` | GET/POST | Public config |
| `https://s13.iremovalpro.com/version33.tx` | GET | Version check |
| `https://iremovalpro.com/Payax0.ph` | POST | Paiement (PayPal) |
| `https://albert.apple.com/deviceservices/drmHandshak` | POST | **Apple officiel** — DRM handshake |

### 4.3 Entitlements utilisés

```xml
<key>com.apple.security.attestation.access</key>
<key>fairplay-client</key>
<string>NULL/DeviceCertificate</string>
<string>NULL/GetActivationRecord</string>
<string>ActivationRecord</string>
```

---

## 5. Ce que Apple peut faire (recommandations défensives)

### 5.1 Détection côté serveur Apple

**Sur albert.apple.com/deviceservices/drmHandshak** :

1. **Vérifier l'intégrité de la chaîne d'activation**
   - Si l'activation record est signé par un device qui n'a jamais été vu → flag
   - Si l'ECID/ChipID/BoardID ne correspond à aucun device Apple vendu → flag
   - Si le device a été "re-activé" plusieurs fois → flag

2. **Rate limiting par device identity**
   - Si trop d'activations depuis le même ECID en 24h → flag
   - Si trop d'activations depuis la même IP en 24h → flag

3. **Vérification du ticket de pré-activation**
   - Le `activation_record.plist` devrait être signé par une clé Apple privée
   - Si la signature ne peut pas être vérifiée avec la chaîne Apple → rejeter
   - **iRemoval PRO bypasse cette vérification** via le hook Cydia Substrate

### 5.2 Détection côté iOS

**Sur l'iPhone** :

1. **Détecter le tweak Cydia Substrate**
   - Présence de `/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib`
   - Présence de `com.panyolsoft.blackhound` dans les bundles installés
   - Présence de `com.iremovalpro.bypass`

2. **Vérifier l'intégrité de mobileactivationd**
   - Hash SHA-256 de `mobileactivationd` contre référence Apple
   - Détection de méthodes hookées (substrat Cydia)
   - Sandbox de l'app (entitlements stricts)

3. **Détection du serveur Apple**
   - Bloquer les requêtes `drmHandshak` depuis des devices non jailbreakés
   - Monitorer les activations multiples
   - Logger les activations réussies avec timestamp

### 5.3 Améliorations de `mobileactivationd`

1. **Vérification de la chaîne d'appel**
   - Logger les méthodes appelées par des processus autres que `mobileactivationd`
   - Détecter les hooks via comparaison de signature mémoire

2. **Rate limiting par device**
   - Si un device est "activé" > 1 fois / 24h → suspect
   - Si plusieurs activations depuis le même ECID avec des serials différents → suspect

3. **Hardware attestation**
   - Secure Enclave devrait signer le ticket (pas juste l'envoyer)
   - Vérifier que le `deviceCert` correspond au Secure Enclave attesé

### 5.4 Côté réseau (ISP / backbone)

1. **DNS monitoring**
   - Bloquer / alerter sur requêtes vers `s13.iremovalpro.com`
   - Les FAI peuvent intégrer les IoC

2. **TLS fingerprinting**
   - Les clients iRemoval PRO ont un User-Agent ou TLS fingerprint distinctif

3. **C2 pattern detection**
   - Pattern POST répété vers `/iremovalActivation/*` à intervalles réguliers

---

## 6. Timeline défensive recommandée

| Action | Priorité | Effort | Impact |
|---|---|---|---|
| Liste noire des serveurs iRemovalPRO | 🔴 HAUTE | 1 jour | Bloque activation |
| Détection Cydia Substrate sur iPhone | 🔴 HAUTE | 1 sprint | Bloque hook |
| Vérification activation_record signature | 🔴 HAUTE | 1 sprint | Bloque bypass |
| Rate limiting ECID | 🟠 MOYENNE | 2 jours | Réduit impact |
| TLS pinning des endpoints Apple | 🟠 MOYENNE | 1 sprint | Réduit MITM |
| Hardware attestation Secure Enclave | 🟢 BASSE | Long terme | Solution durable |

---

## 7. Pour aller plus loin (recherche)

Voir aussi :
- [`../01_REPORTS/CONSOLIDATED_AUDIT.md`](../01_REPORTS/CONSOLIDATED_AUDIT.md) — Vue d'ensemble
- [`../05_IOC/ioc_catalog.md`](../05_IOC/ioc_catalog.md) — IoC complets
- [`../05_IOC/YARA_RULES.yar`](../05_IOC/YARA_RULES.yar) — Règles de détection
- [`../05_IOC/MITRE_MAPPING.md`](../05_IOC/MITRE_MAPPING.md) — MITRE ATT&CK

---

**Note** : Ce document est fourni pour aider Apple et les défenseurs à comprendre et mitiger cette menace. Il ne contient pas d'instructions de bypass.

**Auteur** : Audit statique
**Date** : 2026-06-22
**Distribution** : Apple Security, chercheurs sécurité, SOC
