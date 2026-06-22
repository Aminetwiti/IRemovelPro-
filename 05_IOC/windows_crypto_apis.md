# Windows Crypto APIs (BCrypt / CryptoAPI / Cert) — iRemovalPro

> Détectées dans `iremovalpro.dll` via recherche de chaînes.
> Source : `03_OUTPUTS/crypto_deep_analysis.txt`
> Date : 2026-06-21

## 17 APIs Windows Crypto détectées

### CryptoAPI (advapi32.dll) — legacy

| API | Réf. | DLL |
|---|---|---|
| `CryptCreateHash` | 6 | advapi32.dll |
| `CryptImportKey` | 6 | advapi32.dll |
| `CryptAcquireContext` | 5 | advapi32.dll |
| `CryptExportKey` | 5 | advapi32.dll |
| `CryptGetHashParam` | 3 | advapi32.dll |
| `CryptHashData` | 1 | advapi32.dll |
| `CryptEncrypt` | 1 | advapi32.dll |
| `CryptDecrypt` | 1 | advapi32.dll |

### CNG / BCrypt (bcrypt.dll) — moderne

| API | Réf. | DLL |
|---|---|---|
| `BCryptOpenAlgorithmProvider` | 2 | bcrypt.dll |
| `BCryptEncrypt` | 1 | bcrypt.dll |
| `BCryptDecrypt` | 1 | bcrypt.dll |

### NCrypt (ncrypt.dll) — stockage clé

| API | Réf. | DLL |
|---|---|---|
| `NCryptOpenStorageProvider` | 1 | ncrypt.dll |
| `NCryptCreatePersistedKey` | 1 | ncrypt.dll |
| `NCryptSetProperty` | 2 | ncrypt.dll |

### Cert API (crypt32.dll) — certificats

| API | Réf. | DLL |
|---|---|---|
| `CertOpenStore` | 1 | crypt32.dll |
| `CertGetCertificateChain` | 1 | crypt32.dll |
| `CertVerifyCertificateChainPolicy` | 1 | crypt32.dll |

## Total : 17 APIs distinctes

**Interprétation forensique** :
- Présence simultanée CryptoAPI + BCrypt → compatibilité Windows 7+ et Windows 10/11
- NCryptCreatePersistedKey → la DLL peut **créer des clés persistantes** dans le KeyStore Windows (CNG)
- CertVerifyCertificateChainPolicy → peut **vérifier** mais aussi **shimer** la validation SSL
- 6 références CryptImportKey → **6 chargements de clés** distincts en mémoire pendant l'exécution

## Apple Security Framework (iOS — hooké par blackhound.dylib)

| Symbole | Rôle | Hooké |
|---|---|---|
| `SecKeyCreateWithData` | Création clé à partir de blob | `_orig_*` / `_replace_*` |
| `SecKeyRawVerify` | Vérification signature brute | ✅ HOOK |
| `SecKeyVerifySignature` | Vérification signature standard | ✅ HOOK |
| `SecTrustEvaluateWithError` | Évaluation chaîne de confiance | ✅ HOOK |
| `kSecKeyAlgorithmRSASignatureRaw` | Constante algo | (référencée) |

> **Sévérité** : 🔴 CRITIQUE — pattern de hooking Theos logos détecté, contournement actif des vérifications cryptographiques iOS.