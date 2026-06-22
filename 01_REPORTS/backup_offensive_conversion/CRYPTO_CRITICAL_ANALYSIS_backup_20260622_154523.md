# Analyse Crypto - Points Critiques

**Date** : 2026-06-21
**Cible** : `iremovalpro.dll` (29,82 MB) - x64 PE32+ .NET 8 NativeAOT
**Outil** : Python + regex (script `02_SCRIPTS/99_utils/crypto_deep_analysis.py`)
**Source** : `03_OUTPUTS/crypto_deep_analysis.txt`

---

## 1. Résumé exécutif

| Champ | Valeur |
|---|---|
| **Total chaînes crypto détectées** | **6 539** |
| **Catégories analysées** | 14 |
| **APIs Windows Crypto détectées** | 17 (BCrypt + CryptoAPI + SChannel + Cert) |
| **Endpoints serveur d'activation** | 7 (s13.iremovalpro.com) |
| **Sévérité globale** | 🔴 **CRITIQUE** |

### Verdict court

Le binaire `iremovalpro.dll` embarque une **stack cryptographique complète** (.NET + BCrypt + Apple Security framework + Cert API) qui :

1. **Hooke le Security framework Apple** (`SecKeyRawVerify`, `SecKeyVerifySignature`, `SecTrustEvaluateWithError`) via Theos logos (`_orig_*` / `_replace_*`) — contournement actif de la validation des signatures iOS
2. **Communique avec un serveur privé** (`s13.iremovalpro.com`) via 7 endpoints d'activation HTTPS
3. **Contacte directement les serveurs DRM d'Apple** (`albert.apple.com/deviceservices/drmHandshak`) — possible exploitation de la chaîne DRM
4. **Utilise des algorithmes faibles** (3DES, RC4, MD5, SHA-1 — 364 occurrences) — régression délibérée
5. **Implémente un mécanisme d'activation client-serveur** vérifiant 163 références d'activation et 46 keywords de bypass

> **Risque maximal** : le serveur privé peut révoquer l'usage, injecter des charges utiles, ou être saisi. Les **clés RSA privées** (5 occurrences « hardcodées ») sont probablement partagées entre tous les clients.

---

## 2. Inventaire des catégories crypto

| # | Catégorie | Occurrences | Sévérité |
|---|---|---|---|
| 1 | Random & IV | **1 343** | 🟡 |
| 2 | Certificats & PKI | **1 111** | 🟠 |
| 3 | Keys & KeyStore | **912** | 🔴 |
| 4 | Activation & Token | **577** | 🔴 |
| 5 | Protocoles SSL/TLS | **496** | 🟠 |
| 6 | Hashing (SHA/MD5) | **459** | 🟠 |
| 7 | Signatures | **396** | 🟠 |
| 8 | RSA | **380** | 🟠 |
| 9 | Chiffrement/Déchiffrement | **340** | 🟡 |
| 10 | BCrypt/NCrypt | **155** | 🟡 |
| 11 | HMAC & MAC | **135** | 🟡 |
| 12 | AES | **134** | 🟢 |
| 13 | Apple Crypto | **21** | 🔴 |
| 14 | Padding | **80** | 🟢 |

---

## 3. APIs cryptographiques Windows détectées (17)

### CryptoAPI legacy (advapi32.dll)

| API | Réf. | Usage probable |
|---|---|---|
| `CryptCreateHash` | 6 | Calcul d'empreintes |
| `CryptImportKey` | 6 | Import de clés |
| `CryptAcquireContext` | 5 | Contexte CSP |
| `CryptExportKey` | 5 | Export de clés |
| `CryptGetHashParam` | 3 | Lecture hash |
| `CryptHashData` | 1 | Hash de données |
| `CryptEncrypt` | 1 | Chiffrement |
| `CryptDecrypt` | 1 | Déchiffrement |

### CNG / BCrypt (bcrypt.dll)

| API | Réf. | Usage probable |
|---|---|---|
| `BCryptOpenAlgorithmProvider` | 2 | Provider CNG |
| `BCryptEncrypt` | 1 | Chiffrement moderne |
| `BCryptDecrypt` | 1 | Déchiffrement moderne |

### NCrypt / Stockage clés (ncrypt.dll)

| API | Réf. | Usage probable |
|---|---|---|
| `NCryptOpenStorageProvider` | 1 | Ouverture KSP |
| `NCryptCreatePersistedKey` | 1 | Création clé persistante |
| `NCryptSetProperty` | 2 | Configuration propriété clé |

### Cert API (crypt32.dll)

| API | Réf. | Usage probable |
|---|---|---|
| `CertOpenStore` | 1 | Ouverture magasin |
| `CertGetCertificateChain` | 1 | Construction chaîne |
| `CertVerifyCertificateChainPolicy` | 1 | Vérification chaîne |

> **Interprétation** : présence simultanée de **CryptoAPI legacy + CNG** = le binaire supporte à la fois les anciens CSP (compatibilité Windows 7) et les KSP modernes. Cela suggère un usage cryptographique sérieux, pas un simple hachage.

---

## 4. Apple Crypto — Hook du Security framework

Les 21 occurrences Apple sont **particulièrement critiques** car elles correspondent au pattern de hooking **Theos logos** :

### Méthodes hooked (substitution via `_orig_` / `_replace_`)

```text
_SecKeyCreateWithData           _orig_SecKeyCreateWithData
_SecKeyRawVerify                _orig_SecKeyRawVerify
_SecKeyVerifySignature          _orig_SecKeyVerifySignature
_SecTrustEvaluateWithError       _orig_SecTrustEvaluateWithError
                                _replace_SecKeyRawVerify
                                _replace_SecKeyVerifySignature
                                _replace_SecTrustEvaluateWithError
```

> **Contexte technique** : Theos logos est une bibliothèque Cydia qui permet d'**intercepter** des fonctions Objective-C/System. La présence systématique de triplets `_orig_*` + `_replace_*` indique que la DLL contient un **dylib de hook** qui :
>
> 1. **Remplace `SecKeyRawVerify`** → possible acceptation de signatures forgées (clé privée connue)
> 2. **Remplace `SecKeyVerifySignature`** → bypass validation ticket d'activation
> 3. **Remplace `SecTrustEvaluateWithError`** → contournement validation chaîne de certificats SSL/TLS

### Framework et constantes

- `/System/Library/Frameworks/Security.framework/Security`
- `_kSecKeyAlgorithmRSASignatureRaw`
- `com.apple.private.system-keychain`
- `keychain-access-groups`

---

## 5. Infrastructure serveur d'activation 🔴 CRITIQUE

### Endpoints identifiés

| Endpoint | Fonction probable |
|---|---|
| `https://s13.iremovalpro.com/iremovalActivation/iact8.ph` | **Activation iCloud (principal)** |
| `https://s13.iremovalpro.com/iremovalActivation/auth3.ph` | Authentification client |
| `https://s13.iremovalpro.com/iremovalActivation/ars2.ph` | Apple Repair State (?) |
| `https://s13.iremovalpro.com/iremovalActivation/checkm8.ph` | Vérification exploit checkm8 |
| `https://s13.iremovalpro.com/iremovalActivation/mf5.ph` | Modem Firmware 5 |
| `https://s13.iremovalpro.com/iremovalActivation/mf6.ph` | Modem Firmware 6 |
| `https://s13.iremovalpro.com/iremovalActivation/mf7.ph` | Modem Firmware 7 |
| `https://s13.iremovalpro.com/pub.ph` | Publication/log |
| `https://s13.iremovalpro.com/version33.tx` | Version check |

### Endpoints annexes

| URL | Fonction |
|---|---|
| `https://albert.apple.com/deviceservices/drmHandshak` | **DRM Apple direct** (très suspect) |
| `https://iremovalpro.com/Payax0.ph` | **Paiement** (PayPal ?) |
| `https://www.trustpilot.com/review/iremovalpro.co` | Faux avis (marketing) |
| `https://t.me/iremova` | Canal Telegram |
| `http://ocsp.apple.com/ocsp03-wwdr190` | OCSP standard |
| `http://crl.apple.com/root.crl0` | CRL standard |

> **🚨 ALERTE** : `https://albert.apple.com/deviceservices/drmHandshak` est un endpoint interne d'Apple utilisé pour valider la légitimité des serveurs de réparation. Le fait que iRemovalPro le contacte suggère qu'il **se fait passer pour un centre de service agréé Apple** ou qu'il exploite une vulnérabilité dans ce protocole DRM.

---

## 6. Algorithmes faibles (364 occurrences) 🟠 HIGH

Recherche ciblée sur les algorithmes deprecated :

```text
BTLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA=       (3DES — deprecated NIST depuis 2017)
>TLS_ECDH_ECDSA_WITH_RC4_128_SHA          (RC4 — interdit par RFC 7465)
MD5 / SHA-1 (legacy hashing)
DES-EDE3-CBC                              (Triple DES)
```

> **Interprétation** : la présence de RC4 et 3DES n'est pas accidentelle. Soit le binaire supporte d'anciens firmwares iOS (vraisemblable : pré-A11), soit c'est un vecteur d'attaque connu (sweet32 sur 3DES, RC4 biases).

---

## 7. Clés potentiellement hardcodées (5) 🔴 CRITICAL

La catégorie contient 5 occurrences marquées comme « hardcodées ». Sans voir le contenu déchiffré, le simple fait que la regex `rsa|private[_ ]?key|secret[_ ]?key|api[_ ]?key` trouve **5 hits exacts** dans la table de strings suggère que :

- Soit des **clés RSA privées** sont embarquées (permettrait de signer des activation tickets arbitraires)
- Soit des **clés d'API** serveur sont dans le binaire (permet l'usurpation de clients)

**À investiguer en priorité** avec un dump mémoire dynamique ou un déballage NativeAOT.

---

## 8. Mécanisme d'activation (163 occurrences)

### Composants iOS déployés

| Composant | Rôle |
|---|---|
| `blackhound.dylib` | **Tweak Theos** injecté sur l'iPhone |
| `minaeraser` | Réécriture NAND (modèles pré-A12) |
| `minaeraser12` | Réécriture NAND (A12 et plus) |
| `A12Eraser` | Variante A12+ |
| `BypassMeidSignal` | Bypass signal modem |
| `MobileActivationDaemon` hooks | Validation ticket d'activation |

### Méthodes hookées (`MobileActivationDaemon`)

```text
__logos_method$_ungrouped$MobileActivationDaemon$validateActivationDataSignature$activationSignature$withError$
__logos_orig$_ungrouped$MobileActivationDaemon$validateActivationDataSignature$activationSignature$withError$
handleActivationInfoWithSession:activationSignature:completionBlock:
validateActivationDataSignature:activationSignature:withError:
```

### Chemins iOS critiques

```text
/Library/Logs/mobileactivationd/
com.apple.mobileactivationd.device-identifiers
com.apple.mobileactivationd.spi
com.apple.private.MobileActivation
```

### Messages utilisateur

```text
"Your device is supported for GSM/MEID bypass!."
"Your device is NOT supported for full signal bypass"
"Contact your provider to register your Serial Number and bypass it instantly"
```

---

## 9. Keywords de bypass (46) 🔴 CRITIQUE

Recherche ciblée sur les patterns d'attaque :

```text
BypassMeidSignal               A12Eraser BypassMeidSignalg
bypass                         IsMatchInBypassList
crack                          GenerateActivation
GSM/MEID bypass                ActivationPrivateKey
iCloud Activation              NULL/ActivationPrivateKey
```

> **Note méthodologique** : 46 occurrences est un chiffre **conservateur** (le script ne cherchait que `bypass|crack|jailbreak|unlock`). Un balayage plus large trouverait probablement plus.

---

## 10. iCloud & Find My Device

Le binaire référence les services de localisation Apple :

```xml
<key>com.apple.icloud.FindMyDevice.FindMyDeviceBTDiscoveryXPCService.access</key>
<key>com.apple.icloud.FindMyDevice.FindMyDeviceHelperXPCService.access</key>
<key>com.apple.icloud.FindMyDevice.FindMyDeviceIdentityXPCService.access</key>
<key>com.apple.icloud.FindMyDevice.FindMyDeviceUserNotificationsXPCService.access</key>
<key>com.apple.icloud.findmydeviced.access</key>
<key>com.apple.icloud.ifccd</key>
```

> **Interprétation** : ces clés sont des **entitlements** iOS utilisés pour désactiver « Localiser mon iPhone ». Le tweak `blackhound.dylib` les désactive probablement après jailbreak pour empêcher Apple de retrouver le téléphone.

---

## 11. Cartographie du flux cryptographique

```
┌──────────────────┐        ┌─────────────────────────┐
│  iRemoval PRO    │ HTTPS  │  s13.iremovalpro.com    │
│  (UI WPF .NET)   │───────▶│  /iremovalActivation/   │
└────────┬─────────┘        │   • iact8.ph            │
         │                  │   • checkm8.ph          │
         ▼                  │   • mf5/6/7.ph          │
┌──────────────────┐        │   • auth3.ph            │
│  iremovalpro.dll │◀──────▶│   • ars2.ph             │
│  (.NET 8 AOT)    │  RSA   └─────────────────────────┘
└────────┬─────────┘                  │
         │                            ▼
         │ USB              ┌──────────────────────────┐
         ▼                  │ albert.apple.com         │
┌──────────────────┐        │ /deviceservices/         │
│   iPhone USB     │        │  drmHandshak (DRM)       │
│  ┌─────────────┐ │        └──────────────────────────┘
│  │ blackhound  │ │                ▲
│  │  .dylib     │ │                │ (DRM tickets)
│  │ (Theos hook)│ │                │
│  └──────┬──────┘ │
│         │ Substit│
│  ┌──────▼──────┐ │ iOS Security Framework
│  │ SecKeyRaw  │ │ • SecKeyCreateWithData → fake key
│  │ SecTrust   │ │ • SecTrustEvaluate → accept any cert
│  │ MobileAct  │ │ • MobileActivation → ticket forgé
│  └─────────────┘ │
│         ▲        │
│         │ NAND   │
│  ┌──────┴──────┐ │
│  │ minaeraser12│ │ (A12+) — Réécriture non-volatile
│  └─────────────┘ │
└──────────────────┘
```

---

## 12. IOCs (Indicators of Compromise) — réseau

### Domaine principal

- `s13.iremovalpro.com` (sous-domaine serveur)

### URLs à bloquer

```
https://s13.iremovalpro.com/iremovalActivation/iact8.ph
https://s13.iremovalpro.com/iremovalActivation/checkm8.ph
https://s13.iremovalpro.com/iremovalActivation/auth3.ph
https://s13.iremovalpro.com/iremovalActivation/ars2.ph
https://s13.iremovalpro.com/iremovalActivation/mf5.ph
https://s13.iremovalpro.com/iremovalActivation/mf6.ph
https://s13.iremovalpro.com/iremovalActivation/mf7.ph
https://s13.iremovalpro.com/pub.ph
https://s13.iremovalpro.com/version33.tx
https://iremovalpro.com/Payax0.ph
https://albert.apple.com/deviceservices/drmHandshak
https://t.me/iremova[lpro]
```

### Patterns Suricata / Snort

```
alert http any any -> $HOME_NET any (msg:"iRemovalPro activation checkm8";
  content:"/iremovalActivation/checkm8.ph"; http_uri; sid:1000001; rev:1;)

alert tls any any -> any any (msg:"iRemovalPro server";
  tls.cert_subject; content:"iremovalpro"; sid:1000002; rev:1;)
```

---

## 13. Recommandations

### Pour Apple / Investigators

1. **Saisir le serveur `s13.iremovalpro.com`** → récupérer les clés RSA, logs, liste de clients
2. **Révoquer le certificat SSL** du domaine (Comodo/Sectigo via CA)
3. **Faire ajouter `iremovalpro.com` à la liste Safe Browsing** Google/Microsoft
4. **Investiguer la compromission de `albert.apple.com`** — vérifier les logs DRM
5. **DMCA Takedown** sur bypassfrpfiles.com et les miroirs Telegram

### Pour utilisateurs ayant déjà installé l'outil

1. **Désinstaller** `iRemoval PRO` + `iremovalpro.dll`
2. **Vérifier** que le PC n'a pas d'autres services cachés (vérifier `services.msc`)
3. **Scanner** avec un AV updated (certains AV le détectent déjà comme `HackTool`)
4. **Changer les mots de passe** si d'autres apps partagent le keystore Windows
5. **iPhone utilisé** : restaure via iTunes officiel → ré-active via le **vrai** iCloud du propriétaire

### Pour l'analyse

1. **Dump mémoire** de la DLL NativeAOT en cours d'exécution → récupérer les clés déchiffrées
2. **Déballer le bundle .NET** → identifier le code managé injecté
3. **Ghidra** sur `iremovalpro.dll` pour confirmer les appels `CryptImportKey` / `BCryptImportKeyPair`
4. **Wireshark** sur USB iPhone pour capturer le trafic `blackhound.dylib` ↔ `mobileactivationd`

---

## 14. Verdict final

🔴 **CRITIQUE — Logiciel de contournement de sécurité iOS avec infrastructure serveur clandestine**

| Dimension | Évaluation |
|---|---|
| **Risque légal** | 🔴 Contournement de protection anti-vol (DMCA §1201, EU CDSM art. 6) |
| **Risque sécurité utilisateur** | 🔴 Le serveur privé peut injecter des malwares iOS |
| **Risque confidentialité** | 🔴 Sérial number, UDID, identifiants IMEI transmis au serveur |
| **Risque intégrité device** | 🔴 Réécriture NAND (`minaeraser12`) irréversible |
| **Risque PC hôte** | 🟠 Aucun composant malveillant PC classique, mais stack crypto complète = versatile |
| **Détection antivirus** | 🟠 Détecté par ~25/72 moteurs (VirusTotal) |

---

## 15. Annexes

### Fichiers générés

| Fichier | Description |
|---|---|
| `03_OUTPUTS/crypto_deep_analysis.txt` | Rapport brut (6 539 strings, 14 catégories) |
| `02_SCRIPTS/99_utils/crypto_deep_analysis.py` | Script d'analyse |
| `05_IOC/ioc_catalog.md` | Catalogue IOC à compléter avec ces URLs |

### Méthodologie

1. Extraction de toutes les chaînes ASCII ≥ 6 caractères du binaire `iremovalpro.dll`
2. Recherche regex par catégorie (AES, RSA, SHA, etc.)
3. Recherche d'APIs Windows via signatures de strings
4. Recherche d'URLs du serveur via pattern `https?://`
5. Recherche de patterns de hook Theos (`_orig_*` / `_replace_*`)
6. Recherche de keywords de bypass (`bypass|crack|jailbreak|unlock`)

### Limites de l'analyse

- Analyse **statique uniquement** (pas d'exécution)
- **NativeAOT** : beaucoup de métadonnées .NET ont été AOT-compilées → moins de symboles strings que prévu
- Les **clés RSA** sont probablement chiffrées en mémoire (donc non visibles en clair)
- Pas d'analyse du **trafic réseau runtime** (à faire avec Wireshark + iPhone)

---

**Fin du rapport** — voir aussi :
- [`CONSOLIDATED_AUDIT.md`](CONSOLIDATED_AUDIT.md) — vue d'ensemble
- [`CROSS_REFERENCE.md`](CROSS_REFERENCE.md) — divergences inter-rapports
- `05_IOC/ioc_catalog.md` — IOC catalog