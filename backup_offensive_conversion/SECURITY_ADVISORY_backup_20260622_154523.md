# Security Advisories — Audit iRemoval PRO v5.2

> **Collection d'advisories défensifs** sur les vulnérabilités découvertes lors de l'audit du bypass d'Activation Lock iCloud iRemoval PRO.
>
> **TLP** : LEAKED (communauté défensive)
> **Date de publication initiale** : 2026-06-22
> **Auteur** : Audit statique (équipe recherche défensive)
> **Distribution** : Apple Security, chercheurs sécurité, SOC/Blue Team

---

## 📋 Index des advisories

| ID | Titre | Sévérité | Statut |
|---|---|---|---|
| [SA-2026-001](#sa-2026-001--bypass-dactivation-lock-icloud-via-rsa-1024-forgé) | Bypass d'Activation Lock iCloud via RSA-1024 forgé | 🔴 CRITIQUE | Divulgué |
| [SA-2026-002](#sa-2026-002--certificat-apple-developer-légitimé-pour-signer-le-bypass) | Cert Apple Developer légitimé pour signer le bypass | 🟠 HAUTE | Pour action Apple |
| [SA-2026-003](#sa-2026-003--endpoint-iact8php--dérivation-de-clé-de-session-pbkdf2-hmac-sha256) | Endpoint `iact8.php` : dérivation PBKDF2-HMAC-SHA256 | 🟠 MOYENNE | Divulgué |
| [SA-2026-004](#sa-2026-004--insecure-defaults-dans-lextraction-de-clé-rsa) | Insecure defaults : RSA-1024 + sel statique | 🟠 MOYENNE | Divulgué |
| [SA-2026-005](#sa-2026-005--tweak-ios-blackhounddylib--absence-de-runtime-check) | Tweak iOS `blackhound.dylib` : absence de runtime check | 🟡 INFO | Divulgué |

---

## SA-2026-001 — Bypass d'Activation Lock iCloud via RSA-1024 forgé

**CVE** : Réservé (à demander à Apple Security)
**Sévérité CVSS v3.1** : 9.8 (CRITIQUE) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**Composant affecté** : Apple iOS (mobileactivationd, Secure Enclave attestation)
**Vendeur** : Apple Inc.
**Attaquant** : Panyolsoft (iRemoval PRO)
**Date de découverte** : 2026-06-22

### Description

Le tweak iOS `blackhound.dylib` (bundle ID `com.panyolsoft.blackhound`) hooke 5 méthodes du `MobileActivationDaemon` via Cydia Substrate :

1. `validateActivationDataSignature:activationSignature:withError:` → retourne toujours `YES`
2. `handleActivationInfo:withCompletionBlock:` → retourne toujours succès
3. `handleActivationInfoWithSession:activationSignature:completionBlock:` → retourne toujours succès
4. `SecKeyRawVerify` → vérification contre modulus RSA-1024 hardcodé
5. `SecTrustEvaluateWithError` → retourne toujours `errSecSuccess`

Une clé publique **RSA-1024** est hardcodée dans le binaire (modulus SHA-256 `2c8c67d4066a5b1f8848ab9284aae4f9f37a6e6edfebb27bde26ac99e2615d27`). La clé privée correspondante est sur le serveur `s13.iremovalpro.com` et signe les tickets d'activation forgés à la demande (endpoint `iact8.php`).

### Preuve de concept (PoC)

```text
1. Jailbreak iPhone (checkm8 + iRa1n)
2. PC envoie identifiants à s13.iremovalpro.com/iremovalActivation/iact8.php
3. Serveur retourne ticket signé avec clé privée RSA-1024
4. blackhound.dylib écrit ticket dans /var/mobile/Library/Caches/lockdownd_activation_record.plist
5. Au reboot, mobileactivationd charge le ticket, hook court-circuite la vérif
6. iPhone "activé" → appels suivants à albert.apple.com/deviceservices/drmHandshak passent
```

### Impact

- **Confidentialité** : Élevée (accès iCloud, données utilisateur)
- **Intégrité** : Élevée (modification état d'activation)
- **Disponibilité** : Élevée (verrouillage iPhone légitime contourné)

### Contre-mesures

| Type | Détail |
|---|---|
| **Apple allowlist modulus** | Maintenir set de modulus HSM autorisés sur `albert.apple.com` |
| **Détection signature brute** | Rejeter PKCS#1 v1.5 sans OID SHA (script dans `OFFENSIVE _PLAYBOOK.md`) |
| **Hook amfid** | Bloquer `SecKeyVerifySignature` pour modulus hors HSM |
| **Blocage réseau** | DNS sinkhole `*.iremovalpro.com` + Suricata + Sigma |
| **Révocation PKI** | Apple révoque team `UR3K3ZV28R` |

**Documents liés** : [`OFFENSIVE _PLAYBOOK.md`](../01_REPORTS/OFFENSIVE _PLAYBOOK.md), [`BYPASS_CORE.md`](../01_REPORTS/BYPASS_CORE.md)

---

## SA-2026-002 — Certificat Apple Developer légitimé pour signer le bypass

**CVE** : Réservé
**Sévérité CVSS v3.1** : 7.5 (HAUTE) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**Composant affecté** : Apple Developer Program, chaîne de signature IPA
**Vendeur** : Apple Inc.
**Cible** : Compte `weidong li (PBNGZQ8G6L)`, Team `UR3K3ZV28R`
**Date de découverte** : 2026-06-22

### Description

Le binaire `iremovalpro.dll` (29,82 MB) contient **8 certificats X.509 RSA 2048 bits** formant la chaîne de confiance Apple complète :

```
Apple Root CA (self-signed, valide 2006-04-25 → 2035-02-09)
    └─▶ Apple WWDR Certification Authority (expire 2013-02-07 → 2023-02-07)
            └─▶ Apple Development: weidong li (PBNGZQ8G6L)
                 (UID FMAZX4B6H4, OU UR3K3ZV28R, expiré 2020-02-29 → 2021-02-28)
```

L'inclusion d'un cert Apple Developer légitime (même expiré) permet à iRemoval PRO de signer des IPA qui s'installent sur iOS non-jailbreaké (avant février 2021). La présence du cert suggère qu'iRemoval PRO avait un compte Apple Developer actif au moment de l'extraction du binaire.

### OSINT

| Champ | Valeur | Source |
|---|---|---|
| Bundle ID tweak | `com.panyolsoft.blackhound` | dylib strings |
| Build path iOS | `/Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/` | dylib strings |
| Apple Dev Name | `weidong li` | cert X.509 |
| Apple Dev Mac | `PBNGZQ8G6L` | cert X.509 |
| Apple Dev User ID | `FMAZX4B6H4` | cert X.509 |
| Apple Dev Team | `UR3K3ZV28R` | cert X.509 |

**Hypothèse** : `panyolsoft` = `weidong li` = `josuealonsorodriguez` = même organisation (Panyol Soft Co. liée au fondateur).

### Contre-mesures

| Type | Détail |
|---|---|
| **Apple** | Révocation immédiate team `UR3K3ZV28R` + enquête iTunes Connect |
| **Apple** | Vérifier si d'autres certs récents existent (variantes non embarquées) |
| **Apple** | Notification Apple Legal pour fausse représentation d'identité |

**Documents liés** : [`APPLE_CERT_CHAIN.md`](../01_REPORTS/APPLE_CERT_CHAIN.md), [`04_EXTRACTED/apple_certs/`](../04_EXTRACTED/apple_certs/)

---

## SA-2026-003 — Endpoint `iact8.php` : dérivation de clé de session PBKDF2-HMAC-SHA256

**CVE** : N/A (analyse défensive, pas de vuln serveur externe)
**Sévérité** : 🟠 MOYENNE (insecure defaults)
**Composant affecté** : Backend `s13.iremovalpro.com`
**Date de découverte** : 2026-06-22

### Description

L'endpoint `https://s13.iremovalpro.com/iremovalActivation/iact8.php` utilise PBKDF2-HMAC-SHA256 (primitive .NET 8 `Rfc2898DeriveBytes.Pbkdf2`) pour dériver une clé de session 128 bits `nonce_C = koY+rla/7ol+LX8kepekEw==` (16 octets) à partir d'un mot de passe composite `{sessionId ‖ nonceA ‖ nonceB}`, d'un **sel statique** `"iremovalpro-iact8-v1"` (21 octets) et de **10 000 itérations**.

```csharp
nonce_C = Rfc2898DeriveBytes.Pbkdf2(
    password:      sessionId + ":" + b64(nonceA) + ":" + b64(nonceB),
    salt:          "iremovalpro-iact8-v1",
    iterations:    10_000,
    hashAlgorithm: HashAlgorithmName.SHA256,
    outputLength:  16
);
```

### Faiblesses identifiées

1. **Sel statique** : deux sessions pour deux clients différents produisent le même sel → tables arc-en-ciel possibles
2. **Itération relativement basse** : 10 000 < recommandation OWASP 2023 (≥ 600 000 pour PBKDF2-SHA256)
3. **HMAC-SHA256 truncated à 128 bits** : réduit la sécurité MAC effective
4. **Pas de PFS** : compromission de `nonce_C` ⇒ toutes les sessions futures compromises

### Contre-mesures

| Type | Détail |
|---|---|
| **Surveillance réseau** | IDS sur `/iremovalActivation/iact8` (Suricata sid 1000203) |
| **DNS sinkhole** | `s13.iremovalpro.com` → blocked |
| **MITM detection** | Watchdog sur les requêtes signées HMAC-SHA256 |

**Documents liés** : [`CRYPTO_KEY_DERIVATION.md`](../01_REPORTS/CRYPTO_KEY_DERIVATION.md), [`ENDPOINT_IACT8.md`](../01_REPORTS/ENDPOINT_IACT8.md)

---

## SA-2026-004 — Insecure defaults : RSA-1024 + sel statique

**CVE** : N/A
**Sévérité** : 🟠 MOYENNE
**Composant affecté** : Stack crypto iRemoval PRO
**Date de découverte** : 2026-06-22

### Description

L'écosystème iRemoval PRO utilise systématiquement des primitives cryptographiques **faibles** par défaut :

| Primitive | Choix iRemoval | Standard 2026 | Écart |
|---|---|---|---|
| RSA modulus | **1024 bits** | 2048+ bits | 1 génération de retard |
| AES key size | 128 bits (recommandé NIST jusqu'en 2030) | 256 bits | -50% |
| PBKDF2 iterations | **10 000** | ≥ 600 000 (OWASP 2023) | 60× trop bas |
| PBKDF2 salt | **statique** `"iremovalpro-iact8-v1"` | aléatoire 16+ octets | vulnérable rainbow tables |
| HMAC truncation | **128 bits** sur SHA-256 | 256 bits | 50% force MAC |

### Impact

- **RSA-1024** : factorisable avec ~$1M de budget (cf. record RSA-250 en 2025)
- **PBKDF2 sel statique** : si le sel fuite (par ex. via log), tous les hash sont crackables simultanément
- **HMAC-128** : forgery possible avec 2^64 opérations (inatteignable aujourd'hui mais périmé à horizon 2040)

### Contre-mesures

| Type | Détail |
|---|---|
| **Apple** | Forcer RSA-2048+ + Secure Enclave attestation sur `drmHandshak` |
| **SOC** | Détecter les transactions RSA-1024 dans les flux (rare en 2026) |

**Documents liés** : [`CRYPTO_KEY_DERIVATION.md`](../01_REPORTS/CRYPTO_KEY_DERIVATION.md), [`CRYPTO_CRITICAL_ANALYSIS.md`](../01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md)

---

## SA-2026-005 — Tweak iOS `blackhound.dylib` : absence de runtime check

**CVE** : N/A
**Sévérité** : 🟡 INFO (recherche)
**Composant affecté** : iOS activation framework
**Date de découverte** : 2026-06-22

### Description

Le tweak `blackhound.dylib` est compilé avec **Theos** (framework de dev de tweaks Cydia) et utilise **Logos** (préprocesseur pour MobileSubstrate). Les symboles `__logos_method$` et `__logos_orig$` sont en clair dans le binaire, ce qui permet :

1. **Détection facile par EDR iOS** : grep des symboles Logos
2. **Détection statique** : présence de `__logos_method$MobileActivationDaemon$validateActivationDataSignature$` est unique au bypass
3. **Build path leak** : `/Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/.theos/obj/debug/arm64/blackhound.x.1643379a.o` révèle l'auteur et la machine de build

### IoC binaires

| Pattern | Type | Source |
|---|---|---|
| `__logos_method$MobileActivationDaemon$validateActivationDataSignature$` | Symbole Logos | dylib ARM64 / ARM64E |
| `_MSHookFunction` + `_MSHookMessageEx` | API Cydia | dylib |
| `/Users/josuealonsorodriguez/.../blackhound/` | Build path leak | dylib (string) |
| `com.panyolsoft.blackhound` | Bundle ID | dylib plist embedded |

### Contre-mesures

| Type | Détail |
|---|---|
| **iOS 19+ EDR** | Bloquer les processus qui chargent `MobileSubstrate/DynamicLibraries/blackhound.dylib` |
| **amfi** | Refuser les binaires embarquant les symboles Logos (whitelist stricte) |
| **MDM** | Empêcher l'installation de tweaks sur iPhone gérés |

**Documents liés** : [`BYPASS_CORE.md`](../01_REPORTS/BYPASS_CORE.md), [`PHASE5_RUNTIME_NATIVEAOT.md`](../01_REPORTS/PHASE5_RUNTIME_NATIVEAOT.md)

---

## Timeline défensive recommandée

| Date | Action |
|---|---|
| **T+0 (2026-06-22)** | Publication advisories TLP:LEAKED |
| **T+1 jour** | Notification Apple Security (équipe platform + SIRT) |
| **T+3 jours** | Révocation team Apple `UR3K3ZV28R` |
| **T+1 semaine** | Déploiement YARA + Suricata + Sigma chez SOC pilotes |
| **T+1 mois** | Déploiement DNS sinkhole `*.iremovalpro.com` chez FAI partenaires |
| **T+3 mois** | Patch iOS 18.x : allowlist modulus RSA sur `drmHandshak` |
| **T+12 mois** | iOS 19 : hook amfid `SecKeyVerifySignature` |

---

## Comment réagir (pour Apple Security)

```yaml
priority: P0
team: Apple Platform Security
actions:
  - revoke_team: UR3K3ZV28R
  - blacklist_bundle: com.panyolsoft.blackhound
  - audit_apps_signed_by: UR3K3ZV28R
  - investigate_identity: "weidong li (PBNGZQ8G6L)"
  - patch_drmhandshak_allowlist: enabled
  - update_ios_signature_policy: enforce_RSA_2048_min
contact: security@apple.com (via TLP:LEAKED channel)
```

## Comment réagir (pour SOC / Blue Team)

```yaml
priority: P1
team: SOC / Blue Team
actions:
  - deploy_yara: 05_IOC/YARA_RULES.yar
  - deploy_yara_wire: 05_IOC/YARA_RULES_WIRE.yar
  - deploy_suricata: 05_IOC/SURICATA_RULES.rules
  - deploy_sigma: 05_IOC/SIGMA_RULES.yml
  - dns_sinkhole: 
      - s13.iremovalpro.com
      - iremovalpro.com
      - iremovalpro.co
  - monitor_endpoints:
      - /iremovalActivation/iact8
      - /iremovalActivation/auth3
      - /iremovalActivation/ars2
      - /iremovalActivation/mf5
      - /iremovalActivation/mf6
      - /iremovalActivation/mf7
  - alert_on_pubkey_sha256: "2777656e2aa326f7f02b215cc6cac1da8d2550c978bb745b9ac7aaed45434b4f"
```

---

## Crédits

- **Audit statique** : extraction binaire, analyse ASN.1, Ghidra, .NET AOT
- **Recherche crypto** : PBKDF2 detection, RSA-1024 weakness, AES validation
- **OSINT** : corrélation bundle ID / cert dev / build path
- **Defense engineering** : 12+ YARA rules, 5 contre-mesures documentées

---

**Note TLP** : ce document est **TLP:LEAKED** — diffusion autorisée à la communauté défensive (Apple Security, chercheurs, SOC) sous engagement de non-redistribution publique.
