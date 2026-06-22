# Phase 5 — Runtime & NativeAOT Analysis

> **Date** : 2026-06-22
> **Cible** : `iremovalpro.dll` (.NET 8 NativeAOT, 31.26 MB)
> **Tâches** : T1 (Runtime Memory Dump) + T2 (NativeAOT Unpacking)

---

## Résumé exécutif

Cette phase complète l'analyse statique (Phases 1-4) par :
1. **T1** — Capture dynamique de la mémoire runtime pour extraire clés crypto en clair
2. **T2** — Récupération des métadonnées managées depuis le binaire NativeAOT

**Verdict** : T2 a livré des résultats immédiats majeurs (604 types .NET,
940 refs crypto, 678 refs Apple/iOS). T1 nécessite un environnement VM isolé.

---

## T1 — Runtime Memory Dump

### Outils créés
- `02_SCRIPTS/10_runtime_dump/memory_dump.py` — Dumper Frida (3 modes)
- `02_SCRIPTS/10_runtime_dump/extract_keys_from_dump.py` — Extracteur post-mortem

### Architecture de capture

```
┌────────────────────────────────────────────────────────────┐
│                    WINDOWS HOST (VM isolée)                │
│                                                            │
│  iRemovalPro.exe ─► iremovalpro.dll (.NET 8 NativeAOT)    │
│        │                    │                              │
│        │                    ▼                              │
│        │          ┌──────────────────────┐                │
│        │          │   Frida Injector     │                │
│        │          │  (BCrypt hook)       │                │
│        │          │  (WS2_32 hook)       │                │
│        │          │  (HttpSend hook)     │                │
│        │          └──────────┬───────────┘                │
│        │                     │                             │
│        ▼                     ▼                             │
│  network/s13.iremovalpro.com    Memory dump (.dmp)         │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### Hooks Frida implémentés

| API Windows | Hook | Output |
|-------------|------|--------|
| `BCryptEncrypt` | Capture buffer in/out + key handle | Hex dump |
| `BCryptDecrypt` | Capture buffer in/out + key handle | Hex dump |
| `WS2_32.send` | Capture buffer réseau | Hex + length |
| `WS2_32.recv` | Capture buffer réseau | Hex + length |
| `HttpSendRequestA` | Capture headers + body | Texte |

### Extracteur post-mortem

`extract_keys_from_dump.py` cherche dans le dump :
- **RSA keys** : ASN.1 DER (PKCS#1, PKCS#8)
- **AES keys** : Blocs 16/24/32 octets à haute entropie
- **X.509 certs** : DER encoding
- **PEM blocks** : `-----BEGIN...-----`
- **Activation tickets** : plist, bplist00, AccountToken, SerialNumber
- **API keys** : Bearer tokens, UUID v4, IMEI Luhn

### ⚠️ Prérequis VM

**NE PAS EXÉCUTER SUR HÔTE** :
- VM Jetable (Hyper-V/VMware/VirtualBox)
- Firewall bloquant `*.iremovalpro.com`
- Antivirus désactivé (Defender, EDR)
- Snapshot avant exécution
- Pas d'iDevice USB branché

---

## T2 — NativeAOT Bundle Unpacking

### Outils créés
- `02_SCRIPTS/11_nativeaot_unpack/nativeaot_unpack.py` — Parser v1
- `02_SCRIPTS/11_nativeaot_unpack/nativeaot_unpack_v2.py` — Parser v2 (UTF-16 + types)

### Résultats sur `iremovalpro.dll`

```
[*] Loading: IRemovalPro\iremovalpro.dll (31,264,768 bytes)
[*] Architecture: x64
[*] Sections: 11

[*] Sections:
    .text        0xc8a98  (code natif compilé)
    .managed     0x675fc8 (6.7 MB - MÉTADONNÉES)
    hydrated     0x2b2678 (2.8 MB - généré runtime)
    .rdata       0x5e5c90 (5.9 MB - readonly data)
    .data        0x357f0
    .pdata       0x830b8
    .k^q         0x7fb21b (section obfusquée)
    .IE_         0x120
    .^%L         0x820288 (section obfusquée)
    .rsrc        0x32c
    .reloc       0x1e08
```

### Statistiques

| Métrique | Valeur |
|----------|--------|
| Strings ASCII ≥ 10 chars | **24 312** |
| Strings UTF-16 LE ≥ 10 chars | **3 794** |
| Total strings | **28 106** |
| Types .NET uniques | **604** |
| Réfs crypto | **940** |
| Réfs Apple/iOS | **678** |
| Réfs réseau | **828** |
| Réfs bypass | **133** |
| Réfs produit (iRemoval) | **34** |

### Découvertes critiques

#### 1. Origine du code
Chaîne de build path embarquée :
```
/Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/.theos/obj/debug/arm64/
```
- **Développeur** : `josuealonsorodriguez`
- **Projet** : `TweakDevelopment/blackhound`
- **Build system** : **Theos** (toolchain tweak iOS)
- **Architecture** : `arm64` (tweak iOS device)
- **Fichier** : `blackhound.x.1643379a.o`

#### 2. Architecture d'attaque complète

```
┌──────────────────────────────────────────────────────────┐
│ WINDOWS (iRemovalPro.exe)                               │
│   └─ iremovalpro.dll (.NET 8 NativeAOT)                  │
│       ├─ Renci.SshNet (SSH client)                       │
│       ├─ RestSharp (HTTP client)                         │
│       ├─ libimobiledevice (USB comm avec iPhone)         │
│       └─ Embedded: blackhound.dylib (iOS tweak)          │
└─────────────────┬────────────────────────────────────────┘
                  │
                  ▼ USB (iPhone jailbreaké requis)
┌──────────────────────────────────────────────────────────┐
│ iOS (jailbroken)                                         │
│   └─ blackhound.dylib (MobileSubstrate tweak)            │
│       └─ Hooks MobileActivationDaemon                    │
│           ├─ validateActivationDataSignature             │
│           ├─ handleActivationInfo                       │
│           └─ handleActivationInfoWithSession             │
└──────────────────────────────────────────────────────────┘
```

#### 3. Strings iOS hookées

```
MobileActivationDaemon
ActivationRecord
activation-record
/activation_records/activation_record.plist
validateActivationDataSignature:activationSignature:withError:
handleActivationInfo:withCompletionBlock:
handleActivationInfoWithSession:activationSignature:completionBlock:
_MSHookFunction          ← MobileSubstrate API
_MSHookMessageEx         ← MobileSubstrate API
__logos_method$...       ← Theos logos (runtime hook table)
__logos_orig$...         ← Original method pointer
```

#### 4. Fonctions iDevice (libimobiledevice)

```
iDevice_LnchV2         ← Launch daemon on device
iDevice_Activate       ← Activate device
iDevice_Deactivate     ← Deactivate device
iDevice_GetState       ← Get activation state
iDevice_EnableDevMode  ← Enable dev mode
Firewall_iDeviceProxy  ← Proxy via firewall
CreateActivationSessionInfo
CreateActivationInfoWithSession
ActivateWithSession
GetActivationState
```

#### 5. Bibliothèques tierces confirmées

| Bibliothèque | Version/UUID | Usage |
|--------------|--------------|-------|
| **Renci.SshNet** | `Had816c5e-6f13-4589-9f3e-59523f8b77a4c` | SSH client (jailbroken iPhone) |
| **RestSharp** | `fda57af14a288d46e3efea8961...` | HTTP client (API calls) |
| **System.Net.Security** | bundled | TLS/SSL |
| **SshNet.Security.Cryptography** | bundled | SSH crypto |

#### 6. Namespace obfuscation

Tous les types utilisateur sont préfixés par `T` :
- `Tiremovalpro.Properties.Resources`
- Probablement `TA12Eraser`, `TBypassMeidSignal`, etc.

→ Le compilateur NativeAOT obfusque automatiquement les noms courts
   avec un préfixe `T` (anti-reflection, anti-decompilation).

---

## Outputs générés

`03_OUTPUTS/nativeaot/` :
- `nativeaot_*.all.json` — 28 106 strings avec offsets
- `category_crypto_*.txt` — 940 strings crypto
- `category_apple-ios_*.txt` — 678 strings Apple/iOS
- `category_bypass_*.txt` — 133 strings bypass
- `category_network_*.txt` — 828 strings réseau
- `category_dotnet-lib_*.txt` — 523 strings .NET libs
- `category_product_*.txt` — 34 strings produit
- `category_method-sig_*.txt` — 30 signatures méthode
- `category_general_*.txt` — 30 366 strings génériques
- `types_*.txt` — 604 types .NET uniques

---

## Conclusion Phase 5

### Objectifs atteints
- ✅ T1 — Outils de capture runtime créés et documentés (à exécuter en VM)
- ✅ T2 — NativeAOT parsé avec succès, **604 types managés** récupérés
- ✅ Origine du code identifiée (BlackHound tweak par josuealonsorodriguez)
- ✅ Architecture d'attaque complète cartographiée (Windows ↔ iOS via SSH)

### Valeur ajoutée vs Phases 1-4
- **Phases 1-4** (statique) : Strings brutes, imports, signatures de section
- **Phase 5** : **Contexte sémantique** des strings (types, namespaces, classes)
- **Phase 5** : **Origin attribution** (qui a écrit le code, sur quelle plateforme)

### Limitations
- ❌ Code source .NET non récupérable (compilé en natif)
- ❌ Pas de bytecode IL (perdu à la compilation NativeAOT)
- ⚠️ Le runtime dump (T1) doit être exécuté en VM jetable

### Prochaines étapes possibles
- Phase 6 : Forensic iOS dump (si un appareil jailbreaké est analysé)
- Phase 7 : Network MITM (déjà partiellement couvert en Phase 4)
- Phase 8 : Rapport juridique final (loi France/UE/US sur contournement DRM)

---

## Références croisées

- [01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md](CRYPTO_CRITICAL_ANALYSIS.md) — Analyse crypto statique
- [02_SCRIPTS/10_runtime_dump/](https://github.com/...) — Runtime dumper
- [02_SCRIPTS/11_nativeaot_unpack/](https://github.com/...) — NativeAOT unpacker
- [03_OUTPUTS/crypto_deep_analysis.txt](../03_OUTPUTS/crypto_deep_analysis.txt) — 6 539 strings crypto
