# Audit de sécurité — iRemoval PRO Premium Edition v5.2

**Date** : 2026-06-21
**Cible** : `c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\`
**Type** : Outil commercial de contournement iCloud Activation Lock pour iPhone
**Objectif** : Compréhension, documentation et audit —  d'aide au contournement

---

## 1. Résumé exécutif

| Champ | Valeur |
|---|---|
| **Nom commercial** | iRemoval PRO Premium Edition v5.2 |
| **Origine** | Fork modifié de "Blackhound iRemovalPro" v0.7.1 (2022) |
| **Distribution** | bypassfrpfiles.com (telegram @droidsolution) |
| **Catégorie** | Outil d'entretien iOS (bypass activation lock) |
| **Modèle économique** | Service serveur payant (crédits / abonnements) |
| **Binaire principal (UI)** | `iRemoval PRO.exe` — WPF .NET Framework x86 |
| **Binaire moteur** | `iremovalpro.dll` — .NET 8/9 NativeAOT x64 |
| **Taille totale** | 34 MB (binaires) + 30 MB (toolkits) |
| **Signature Authenticode** | ❌ Absente (binaire non signé) |
| **Anti-debug** | ✅ Présent (NtQueryInformationProcess) |
| **Cible technique** | iPhone (modèles testés : iPhone6,2 = iPhone 5s) |
| **Composants iOS déployés** | `blackhound.dylib` (tweak Theos), `minaeraser12` (eraser NAND) |
| **Serveur API** | `https://s13.iremovalpro.com/` (HTTPS) |
| **Note globale** | ⚠️ Logiciel à haut risque — voir §13 |

### Verdict rapide

Application .NET **hybride** (WPF x86 + NativeAOT x64) qui :
1. Communique avec un iPhone via `libimobiledevice` (USB)
2. Déploie un tweak jailbreak (`blackhound.dylib`) sur l'appareil
3. Réécrit la mémoire NAND via `minaeraser12` (A12 Eraser)
4. Contacte un serveur privé d'activation pour obtenir un *Activation Ticket* signé
5. Injecte ce ticket via `mobileactivationd` pour passer l'écran "Hello"

**Aucun composant malveillant classique détecté** (pas de trojan, pas de vol de credentials PC). Les risques sont concentrés sur le **device iOS** (bypass anti-vol, NAND rewrite irréversible) et la **vie privée** (télémétrie, envoi d'identifiants device).

---

## 2. Identification technique

### 2.1 Inventaire des fichiers

```
[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2/
├── iRemoval PRO.exe           2 792 448 octets    x86 PE32, .NET Framework
├── iremovalpro.dll           31 264 768 octets    x64 PE32+, .NET 8 NativeAOT
├── Read Me.txt                    450 octets    Lisez-moi de l'archive
├── BypassFRPFiles.COM.url         133 octets    Raccourci Internet
├── .github/
│   └── copilot-instructions.md                    (vide, décoratif)
├── .vscode/
│   └── copilot-prompts.json                       (prompt par défaut)
├── ref/
│   └── toolkits/
│       ├── idevicepair.exe                 393 231 octets
│       ├── ideviceproxy.exe             24 309 248 octets
│       ├── libcrypto-3-x64.dll            4 172 735 octets   OpenSSL 3
│       ├── libimobiledevice-1.0.dll       1 779 639 octets
│       ├── libimobiledevice-glue-1.0.dll    503 711 octets
│       ├── libplist++-2.0.dll              797 069 octets
│       ├── libplist-2.0.dll                926 988 octets
│       ├── libssl-3-x64.dll                656 338 octets   OpenSSL 3
│       └── libusbmuxd-2.0.dll              324 946 octets
└── __analysis/                                       (analyses précédentes)
```

### 2.2 Hashes d'identification

| Fichier | SHA-256 |
|---|---|
| `iRemoval PRO.exe` | `07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7` |
| `iremovalpro.dll` | `08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141` |

### 2.3 Architecture PE

**`iRemoval PRO.exe` — Bootstrapper UI**

| Champ | Valeur |
|---|---|
| Format | PE32 (32-bit) |
| Machine | x86 (0x014c) |
| ImageBase | 0x00400000 |
| EntryPoint | 0x0001E7C2 |
| Subsystem | WINDOWS_GUI |
| Linker | 48.0 (Visual Studio 2005) |
| Sections | 5 (`.text`, `.sat`, `.%{&`, `.rsrc`, `.reloc`) |
| Imports | 1 DLL (`mscoree.dll` → `_CorExeMain`) |
| Framework | .NET Framework 4.x (WPF) |

→ **C'est un thin client .NET Framework** qui démarre le CLR et charge la DLL AOT.

**`iremovalpro.dll` — Moteur**

| Champ | Valeur |
|---|---|
| Format | PE32+ (64-bit) |
| Machine | x64 (0x8664) |
| ImageBase | 0x180000000 |
| EntryPoint | 0x100001AB4FC4 (très élevé, typique AOT) |
| SizeOfImage | ~34 MB |
| Subsystem | WINDOWS_GUI |
| FileChars | EXECUTABLE_IMAGE \| LARGE_ADDRESS_AWARE \| DLL |
| DllChars | DYNAMIC_BASE, NX_COMPAT |
| Sections | 11 (`hydratedx`, `.managed`, `.k^q`, `.IE_`, `.^%L`, `.rsrc`, `.reloc`, etc.) |
| Sections random | `.%{&`, `.k^q`, `.IE_`, `.^%L`, `.sat` (typique NativeAOT/ReadyToRun) |
| Entropie globale | 7.30 (haute — code AOT compressé) |
| Imports | 15 fonctions Win32 + bcrypt + ALPC + WER |
| TargetFramework | `.NETCoreApp,Version=v6.0` (runtime 8.0.10) |

→ **C'est une DLL .NET 8 compilée en AOT (NativeAOT)** avec marqueurs définitifs :
- ImageBase `0x180000000` (default NativeAOT)
- EntryPoint à offset `0x1AB4FC4` (typique AOT)
- Sections `hydratedx` (2.7 MB) + `.managed` (6.7 MB)
- Noms de sections randomisés

### 2.4 Imports Win32 de la DLL (15)

```
ADVAPI32.dll  → RegOpenKeyExW, RegQueryValueExW, RegCloseKey
bcrypt.dll    → BCryptDestroyHash, BCryptHashData, BCryptCreateHash, ...
kernel32.dll  → LoadLibraryW, GetProcAddress, GetModuleHandleW, CreateProcessW, ...
ntdll.dll     → NtQueryInformationProcess (anti-debug), NtCreateFile
Wer.dll       → WerRegisterRuntimeExceptionModule
```

La présence de `NtQueryInformationProcess` dans les imports + `WerRegisterRuntimeExceptionModule` confirme la mention d'anti-debug dans la documentation.

---

## 3. Langages et frameworks

### 3.1 Pile technique

| Couche | Technologie | Évidence |
|---|---|---|
| **UI** | WPF (.NET Framework 4.0) | `PresentationCore`, `PresentationFramework`, `WindowsBase`, `System.Windows.Controls.Ribbon` |
| **Moteur principal** | C# .NET 8 NativeAOT | `System.Private.CoreLib`, `Renci.SshNet`, `RestSharp`, `QRCoder` |
| **CLI natif iOS** | Objective-C / Logos (Theos) | Strings `__logos_method$`, `__logos_orig$`, `MSHookFunction` patterns |
| **CLI natif Win** | C (libimobiledevice) | DLL natives `lib*.dll` + exécutables `idevice*.exe` |
| **Cryptographie** | OpenSSL 3 + BouncyCastle (.NET) | `libssl-3-x64.dll`, `libcrypto-3-x64.dll` |
| **Sérialisation** | JSON.NET + plist + XML | `IJsonSerializerStrategy`, `propertyListWithData:`, `XmlSerializer` |

### 3.2 Namespaces principaux identifiés

- `iRemovalProWPF` (assembly EXE)
  - `iRemovalProWPF.App`
  - `iRemovalProWPF.MainWindow`
  - `<Activate_Click>`, `<Erase_Click>`, `<Imei_MouseDown>`, `<Sn_MouseDown>`
- `iremovalpro` (assembly DLL)
  - Classes `iRemovalRecord`, `iRemovalSignature`, `BypassMeidSignal`, `Eraser`
  - Méthodes `Driver.<BypassMeidSignal>d__516`, `CommonConnectDevice`
  - Méthodes iOS hookées : `MobileActivationDaemon`, `validateActivationDataSignature`, `handleActivationInfo`

### 3.3 Bibliothèques tierces

| Lib | Version | Rôle |
|---|---|---|
| **RestSharp** | 106.11.4 | Client REST/HTTPS pour l'API serveur |
| **Renci.SshNet** | 2021.10.10 | Client SSH (tunneling vers l'iDevice jailbreaké) |
| **QRCoder** | 1.4.3 | Génération QR codes (probablement pour partage de session) |
| **SshNet.Security.Cryptography** | 1.3.0 | Crypto SSH (intégré) |
| **System.Net.Http / Quic** | .NET 8 | HTTP/2 + HTTP/3 (REST moderne) |
| **libimobiledevice** | 1.0+ | Communication USB avec iPhone |
| **libplist** | 2.0 | Parse/format plist (Apple Property List) |
| **libusbmuxd** | 2.0 | Multiplexeur USB iOS |
| **OpenSSL** | 3.x | TLS + crypto |

---

## 4. Architecture applicative

### 4.1 Diagramme de composants

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    PC Windows (utilisateur final)                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │   iRemoval PRO.exe (2.79 MB)                                       │ │
│  │   - WPF x86 / .NET Framework 4.0                                   │ │
│  │   - Namespace: iRemovalProWPF                                      │ │
│  │   - Ribbon UI: Activate / Erase / IMEI / Serial                    │ │
│  │                                                                       │ │
│  │   ┌──────────────────────────────────────────────────────────────┐  │ │
│  │   │  iRemovalProWPF.MainWindow (XAML + Code-behind)             │  │ │
│  │   │  ├─ PlugDevice.Image.png                                     │  │ │
│  │   │  ├─ Model / SerialNumber / IMEI labels                      │  │ │
│  │   │  ├─ Activate_Click (start bypass)                          │  │ │
│  │   │  ├─ Erase_Click (NAND erase)                                │  │ │
│  │   │  └─ Status: NoConnection / SerialUnknown / MEID Signal      │  │ │
│  │   └──────────────────────────────────────────────────────────────┘  │ │
│  └─────────────────────────┬────────────────────────────────────────────┘ │
│                            │ P/Invoke + .NET interop                     │
│  ┌─────────────────────────▼────────────────────────────────────────────┐ │
│  │   iremovalpro.dll (30 MB)                                            │ │
│  │   - .NET 8 NativeAOT x64                                              │ │
│  │   - Namespace: iremovalpro                                            │ │
│  │                                                                       │ │
│  │   ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐   │ │
│  │   │ Driver Layer      │  │ Net Layer         │  │ Crypto Layer   │   │ │
│  │   │ - libimobiledevice│  │ - RestSharp       │  │ - OpenSSL 3    │   │ │
│  │   │ - idevicepair     │  │ - System.Net.Http │  │ - BCrypt       │   │ │
│  │   │ - ideviceproxy    │  │ - Renci.SshNet    │  │ - RsaSign      │   │ │
│  │   │ - libplist        │  │ - HTTP/2 + /3     │  │ - ASN.1 parse  │   │ │
│  │   └────────┬──────────┘  └─────────┬────────┘  └────────┬───────┘   │ │
│  │            │                        │                    │           │ │
│  │   ┌────────▼────────────────────────▼────────────────────▼──────┐   │ │
│  │   │ Business Logic                                                 │   │ │
│  │   │ - iRemovalRecord / iRemovalSignature                          │   │ │
│  │   │ - BypassMeidSignal / Eraser (A12 Eraser)                       │   │ │
│  │   │ - MobileActivationService / Mobilebackup2Service               │   │ │
│  │   │ - AmfiLockdownService / InstallationProxyService              │   │ │
│  │   │ - AfcService / SyslogService / DiagnosticsService             │   │ │
│  │   └───────────────────────────────────────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└───────────┬─────────────────────────────────────┬────────────────────────────┘
            │ USB (libusbmuxd / usbmuxd)          │ HTTPS (TCP/443)
            ▼                                      ▼
┌────────────────────────────┐    ┌────────────────────────────────────────┐
│  iPhone branché (USB)      │    │  s13.iremovalpro.com                   │
│  ┌──────────────────────┐ │    │  /iremovalActivation/                  │
│  │ iOS 12.x+ (testé)    │ │    │    - ars2.ph (Activation Record Svc)   │
│  │ ┌──────────────────┐ │ │    │    - auth3.ph (Authentication)         │
│  │ │ blackhound.dylib │ │ │    │    - checkm8.ph (exploit payload)      │
│  │ │ (Tweak Theos)    │ │ │    │    - iact8.ph (iCloud Act Ticket)      │
│  │ │ Hook MobileAct.  │ │ │    │    - mf5.ph / mf6.ph / mf7.ph          │
│  │ └──────────────────┘ │ │    │  /pub.ph                                │
│  │ ┌──────────────────┐ │ │    │  /version33.tx                          │
│  │ │ minaeraser12      │ │ │    └────────────────────────────────────────┘
│  │ │ (A12 NAND eraser) │ │ │
│  │ └──────────────────┘ │ │
│  └──────────────────────┘ │
└────────────────────────────┘
```

### 4.2 Modèle de processus

| Processus | Architecture | Démarrage | Rôle |
|---|---|---|---|
| `iRemoval PRO.exe` | x86 | Auto-elevation | UI + bootstrap CLR |
| `iremovalpro.dll` | x64 | In-process | Logique métier (AOT) |
| `idevicepair.exe` | x64 | Shell-out | Pairing USB iPhone |
| `ideviceproxy.exe --stream <UDID> <port>` | x64 | Shell-out | Tunnel localhost:iPhone |

---

## 5. Cartographie fonctionnelle

### 5.1 Arborescence des fonctions

```
MainWindow (iRemovalProWPF)
│
├─ [Device discovery]
│   ├─ Connect()                  → isUSBConnected (libusbmuxd)
│   ├─ CommonConnectDevice        → lockdown_connect
│   ├─ ReadDeviceInfo             → ideviceinfo (model, serial, IMEI, UDID)
│   └─ IMEI_MouseDown / SN_MouseDown    → copy to clipboard
│
├─ [Activate workflow]
│   ├─ Activate_Click
│   │   ├─ Read activation record (AFC read /var/mobile/Library/...)
│   │   ├─ Upload device info → POST https://s13.iremovalpro.com/iremovalActivation/auth3.ph
│   │   ├─ Request ticket      → POST iact8.ph
│   │   ├─ Receive signed ActivationRecord + iRemovalSignature
│   │   ├─ Write back via AFC   → /activation_records/activation_record.plist
│   │   └─ Trigger activationd restart
│   │
├─ [Erase workflow]
│   ├─ Erase_Click
│   │   ├─ Deploy blackhound.dylib (Tweak Theos)
│   │   ├─ Deploy minaeraser12 (A12 Eraser)
│   │   ├─ Reboot into DFU
│   │   └─ Invoke checkm8 → POST checkm8.ph
│   │
├─ [Bypass MEID Signal]
│   ├─ BypassMeidSignal
│   │   ├─ Read baseband state
│   │   ├─ Modify carrier bundle
│   │   └─ Write bypass → POST mf5.ph / mf6.ph / mf7.ph
│   │
└─ [Server communication]
    ├─ GET  /version33.tx             → check version
    ├─ POST /pub.ph                   → publish public info
    ├─ POST /iremovalActivation/*     → activation flow
    └─ SSH tunnel via Renci.SshNet    → encrypted device shell
```

### 5.2 Fonctions critiques identifiées

| Fonction | Description métier | Entrées | Sorties | Dépendances |
|---|---|---|---|---|
| **`CommonConnectDevice`** | Détecte l'iPhone branché (USB) | — | `DeviceInfo` (UDID, model) | libusbmuxd, libimobiledevice |
| **`Activate_Click`** | Lance le bypass activation lock | DeviceInfo, ticket signé | Status (succès/erreur) | mobileactivationd, RestSharp |
| **`Erase_Click`** | Efface NAND (modèles A12+) | DeviceInfo | Status | blackhound.dylib, minaeraser12 |
| **`BypassMeidSignal`** | Débloque le signal cellulaire | IMEI, MEID | carrier.plist modifié | CarrierBundle, mf5/6/7.ph |
| **`CreateActivationSessionInfo`** | Crée une session d'activation | DeviceInfo | session_token | mobileactivationd, RestSharp |
| **`ActivateWithSession`** | Soumet la session au serveur | session_token, ticket | signed ActivationRecord | iact8.ph |
| **`GetActivationState`** | Lit l'état d'activation actuel | — | enum state | mobileactivationd |
| **`validateActivationDataSignature`** | Vérifie la signature du ticket | data, signature, cert | bool | OpenSSL, Apple Root CA |
| **`handleActivationInfo`** | Hook iOS pour intercepter l'activation | info, completionBlock | status (substitué) | Theos hook |
| **`GetTokenFor`** | Récupère un token d'API | device_id | JWT-like token | RestSharp |
| **`SetLocalSignature`** | Écrit la signature localement | signature, path | bool | AFC (Apple File Conduit) |
| **`ResolveSignature`** | Décode la signature RSA | signature_bytes | plaintext | RSA + Apple pubkey |
| **`ideviceproxy --stream`** | Tunnel localhost ↔ iPhone | UDID, port | proxy process | libimobiledevice |

### 5.3 Modèles d'iPhone supportés (déduits)

| Identifiant | Modèle |
|---|---|
| `iPhone6,2` | iPhone 5s (visible dans l'UI comme exemple) |
| `A12Eraser` | Présent → support A12+ (iPhone XS et plus) |
| `minaeraser12` | A12+ NAND eraser spécifique |

---

## 6. Communication réseau

### 6.1 Endpoints serveur (`https://s13.iremovalpro.com`)

| Endpoint | Méthode probable | Rôle | Auth |
|---|---|---|---|
| `/version33.tx` | GET | Vérification de version de l'app | — |
| `/pub.ph` | POST | Publication / heartbeat | token |
| `/iremovalActivation/auth3.ph` | POST | Authentification device | IMEI + serial |
| `/iremovalActivation/ars2.ph` | POST | **A**ctivation **R**ecord **S**ervice v2 | token |
| `/iremovalActivation/iact8.ph` | POST | **I**Cloud **Act**ivation ticket v8 | token |
| `/iremovalActivation/checkm8.ph` | POST | Payload **checkm8** exploit | token |
| `/iremovalActivation/mf5.ph` | POST | Bypass MEID signal v5 | token |
| `/iremovalActivation/mf6.ph` | POST | Bypass MEID signal v6 | token |
| `/iremovalActivation/mf7.ph` | POST | Bypass MEID signal v7 | token |

> ⚠️ Tous les endpoints communiquent en **HTTPS** (chiffré), mais l'app ne vérifie probablement pas la révocation OCSP/CRL au runtime (chaînes Apple intégrées statiquement).

### 6.2 Flux de communication

```
[PC]                    [iPhone USB]              [Serveur]
  │                          │                       │
  ├─ libusbmuxd discover ───▶│                       │
  │◀────── UDID ─────────────┤                       │
  │                          │                       │
  ├─ idevicepair ───────────▶│                       │
  ├─ lockdown_connect ──────▶│                       │
  │◀──── device info ────────┤                       │
  │                          │                       │
  ├────── auth3.ph ──────────────────────────────────▶│
  │◀────── token + ticket ──────────────────────────┤
  │                          │                       │
  ├─ AFC write plist ───────▶│                       │
  │   /activation_records/   │                       │
  │   activation_record.plist│                       │
  │                          │                       │
  ├─ mobileactivationd ─────▶│                       │
  │   ActivateWithSession    │                       │
  │                          │                       │
  │◀── status: Activated ────┤                       │
```

### 6.3 Ports locaux utilisés

| Port | Service |
|---|---|
| 22 (SSH) | Tunnel Renci.SshNet vers iDevice jailbreaké |
| 5037 (adb) | Pas utilisé (Android), mais libimobiledevice utilise des sockets équivalents |
| 62078 (iOS lockdown) | Via `ideviceproxy` tunnelé en localhost |

---

## 7. Formats de données

### 7.1 Formats manipulés

| Format | Usage | Bibliothèques |
|---|---|---|
| **plist (binaire + XML)** | Configuration iOS, ActivationRecord | libplist, System.Xml.Linq |
| **JSON** | API REST serveur | RestSharp, IJsonSerializerStrategy |
| **XML / XAML** | Interface WPF | PresentationFramework |
| **BinaryWriter/Reader** | Buffers crypto, ticket signing | System.IO |
| **Base64** | Sérialisation tokens, signatures | System.Convert |

### 7.2 Fichiers plist critiques

- `/var/mobile/Library/activation_records/activation_record.plist` — ticket d'activation iCloud
- `/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib.plist` — config tweak
- `com.apple.mobileactivationd.spi.plist` — entitlements activationd

### 7.3 Plist `key`/`value` identifiés

L'app injecte / lit des clés sensibles :
- `com.apple.mobileactivationd.spi`
- `com.apple.private.MobileActivation`
- `RequestActivationState`
- `ActivationLock`
- `com.apple.dmd.operation.clear-activation-lock-bypass-code`
- `com.apple.dmd.operation.fetch-activation-lock-bypass-code`

---

## 8. Configuration, journalisation et stockage

### 8.1 Configuration

- **Pas de fichier `config.json`/`appsettings.json`** détecté (paramètres embarqués dans le binaire AOT)
- Tokens et URLs hardcodés
- Strings `MibTcpRowOwnerPid` suggèrent l'usage de `GetTcpTable` pour la détection réseau

### 8.2 Journalisation

- **Logging :** Limité (pas de NLog/log4net détecté)
- Utilise `System.Diagnostics.TraceSource` / `DiagnosticSource` natifs .NET
- Une chaîne debug visible : `[iRemovalPRO^shit happening` (sortie de débuggage)

### 8.3 Base de données locale

- **Aucune SQLite détecté**
- Stockage éphémère via AFC sur l'iDevice :
  - `/activation_records/activation_record.plist`
  - `/var/mobile/...` (temporaire)

### 8.4 Persistance PC

- Aucun fichier `.dat`/`.db`/`.ini` dans le dossier → **apparemment stateless**
- Configurations potentiellement stockées dans `Registry` (`RegOpenKeyExW` import)

---

## 9. Sécurité et risques

### 9.1 ⚠️ Risques pour le **PC hôte**

| Risque | Sévérité | Détail |
|---|---|---|
| **Pas de signature Authenticode** | 🟠 Élevée | Binaire non signé → pas de garantie d'intégrité, SmartScreen va bloquer |
| **Anti-débogage présent** | 🟡 Moyenne | `NtQueryInformationProcess` rend l'analyse plus difficile |
| **Exécution de binaires companion** | 🟡 Moyenne | Shell-out à `idevicepair.exe`, `ideviceproxy.exe` (fournis, mais confiance implicite) |
| **Télémétrie silencieuse** | 🟡 Moyenne | POST vers `s13.iremovalpro.com` à chaque opération |
| **Bypass de sécurité Apple** | 🔴 Critique | L'app contourne sciemment l'**Activation Lock** (anti-vol iCloud) |
| **Pas de mise à jour automatique** | 🟢 Faible | Pas de mécanisme auto-update détecté |

### 9.2 ⚠️ Risques pour l'**iDevice branché**

| Risque | Sévérité | Détail |
|---|---|---|
| **Réécriture NAND irréversible** | 🔴 Critique | `A12Eraser` / `minaeraser12` écrasent la flash → si échec, **bricke** |
| **Bypass Activation Lock (anti-vol)** | 🔴 Critique | Permet d'utiliser un iPhone volé sans identifiant Apple |
| **Déploiement de tweak jailbreak** | 🔴 Critique | `blackhound.dylib` (Theos, MSHookFunction) — exécution non signée |
| **Risque de perdre la garantie** | 🟠 Élevée | Modification permanente, Apple refuse le SAV |
| **Perte de fonctionnalités** | 🟠 Élevée | iMessage / FaceTime peuvent être cassés après bypass |
| **Faux signal MEID** | 🟠 Élevée | Le téléphone se connecte aux antennes avec une identité cellulaire falsifiée |

### 9.3 Risques pour la **vie privée**

- L'app envoie à un serveur tiers privé : **IMEI, serial, UDID, model, ECID**
- Possibilité de marquage `blacklist` du device par Apple si détecté
- L'utilisateur final n'a aucun moyen de vérifier ce qui est transmis (binaire AOT fermé)

### 9.4 Conformité légale

> **Note d'audit** : Dans de nombreuses juridictions (UE, US, etc.), le **bypass d'Activation Lock sur un appareil qui n'est pas le vôtre** est ilautorise(Computer Fraud and Abuse Act, directives européennes sur la criminalité informatique). L'utilisation légitime se limite aux **appareils dont l'utilisateur est propriétaire** et qui sont **bloqués par oubli d'identifiants**.

### 9.5 Bugs potentiels et problèmes de performance

| Bug | Description |
|---|---|
| **Dépendance forte à la dispo serveur** | Si `s13.iremovalpro.com` est down, l'app est inutilisable |
| **Pas de retry / timeout visible** | Connexion directe → panne réseau = blocage |
| **Section random `.k^q` 7.5 MB** | Sur-utilisation mémoire au démarrage AOT |
| **32-bit EXE + 64-bit DLL** | Compatibilité WoW limitée, problème sur ARM64 (Surface Pro X) |
| **Chemins codés en dur** | `s13.iremovalpro.com` non configurable |
| **Aucune i18n** | UI semble en anglais uniquement |

### 9.6 Dépendances obsolètes ou vulnérables

| Lib | Version | Status |
|---|---|---|
| QRCoder | 1.4.3 | ⚠️ Ancienne (1.6+ recommandé) |
| RestSharp | 106.11.4 | ✅ OK |
| Renci.SshNet | 2021.10.10 | ⚠️ Ancienne (2024+ recommandé) |
| OpenSSL | 3.x | ✅ OK (3.0.13+ pour CVE-2024) |
| libimobiledevice | 1.0+ | ⚠️ Ancienne (vérifier 1.3+) |
| .NET 8 Runtime | 8.0.10 | ⚠️ Ancienne (8.0.20+ recommandé) |

---

## 10. Diagrammes

### 10.1 Séquence — Bypass Activation Lock

```
User          iRemovalProWPF        iremovalpro.dll        libimobiledevice       iPhone          s13.iremovalpro.com
 │                  │                       │                       │                  │                       │
 │  Click Activate  │                       │                       │                  │                       │
 ├─────────────────▶│                       │                       │                  │                       │
 │                  │  Activate_Click()     │                       │                  │                       │
 │                  ├──────────────────────▶│                       │                  │                       │
 │                  │                       │  idevice_pair         │                  │                       │
 │                  │                       ├──────────────────────▶│                  │                       │
 │                  │                       │◀──────── OK ─────────┤                  │                       │
 │                  │                       │  ideviceinfo          │                  │                       │
 │                  │                       ├──────────────────────▶│                  │                       │
 │                  │                       │◀─ model/serial/IMEI ──┤                  │                       │
 │                  │                       │                       │                  │                       │
 │                  │                       │  POST /auth3.ph ───────────────────────────────────────────▶│
 │                  │                       │                       │                  │                       │
 │                  │                       │◀──────── token + ticket ──────────────────────────────────┤
 │                  │                       │                       │                  │                       │
 │                  │                       │  POST /iact8.ph ──────────────────────────────────────────▶│
 │                  │                       │                       │                  │                       │
 │                  │                       │◀── signed ActivationRecord + iRemovalSignature ─────────────┤
 │                  │                       │                       │                  │                       │
 │                  │                       │  AFC write plist      │                  │                       │
 │                  │                       ├──────────────────────▶├─────────────────▶│                       │
 │                  │                       │                       │   /activation_   │                       │
 │                  │                       │                       │   records/...    │                       │
 │                  │                       │                       │                  │                       │
 │                  │                       │  ideviceproxy --stream 22                │                       │
 │                  │                       ├──────────────────────▶├─────────────────▶│                       │
 │                  │                       │                       │   SSH tunnel     │                       │
 │                  │                       │                       │                  │                       │
 │                  │                       │  Renci.SshNet exec    │                  │                       │
 │                  │                       ├──────────────────────▶├─────────────────▶│                       │
 │                  │                       │                       │   mobileactd     │                       │
 │                  │                       │                       │   restart        │                       │
 │                  │                       │                       │                  │                       │
 │                  │                       │◀──── status: Activated ─────────────────┤                       │
 │                  │◀─── Done ─────────────┤                       │                  │                       │
 │◀── Show "OK" ───┤                       │                       │                  │                       │
```

### 10.2 Architecture logique

```
┌─────────────────────── PC WINDOWS ───────────────────────┐
│                                                            │
│  ┌─────────────┐   ┌──────────────────────────────────┐  │
│  │  UI Layer   │──▶│  Driver Layer                    │  │
│  │  (WPF/XAML) │   │  - libimobiledevice-1.0.dll      │  │
│  │             │   │  - libusbmuxd-2.0.dll            │  │
│  └─────────────┘   │  - libplist-2.0.dll              │  │
│         │           │  - libcrypto-3-x64.dll           │  │
│         │           │  - idevicepair.exe (helper)     │  │
│         ▼           │  - ideviceproxy.exe (tunnel)    │  │
│  ┌─────────────┐   └──────────────┬───────────────────┘  │
│  │ .NET 8 AOT  │◀────────────────┘                       │
│  │ iremovalpro │                                            │
│  │   .dll      │   ┌──────────────────────────────────┐  │
│  │             │──▶│  Net Layer                        │  │
│  │             │   │  - RestSharp (HTTPS REST)         │  │
│  │             │   │  - Renci.SshNet (SSH tunnel)     │  │
│  └─────────────┘   │  - System.Net.Http/Quic           │  │
│                     └──────────────┬───────────────────┘  │
└────────────────────────────────────┼────────────────────────┘
                                     │
                  ┌──────────────────┼──────────────────┐
                  │ USB                              HTTPS/443
                  ▼                                  ▼
        ┌──────────────────┐              ┌────────────────────┐
        │ iPhone (iOS)     │              │ s13.iremovalpro.com│
        │ - lockdownd      │              │ /iremovalActivation│
        │ - mobileactd     │              │   ars2 / auth3     │
        │ - blackhound.twk │              │   checkm8 / iact8  │
        │ - minaeraser12   │              │   mf5/6/7 / pub    │
        │ - AFC filesystem │              │ /version33.txt     │
        └──────────────────┘              └────────────────────┘
```

---

## 11. Fonctions / Classes documentées

### 11.1 Côté iOS (tweak `blackhound.dylib`)

```objc
// Hooks MobileActivationDaemon (Objective-C / Logos)
__logos_method$MobileActivationDaemon$validateActivationDataSignature$activationSignature$withError$
__logos_method$MobileActivationDaemon$handleActivationInfo$withCompletionBlock$
__logos_method$MobileActivationDaemon$handleActivationInfoWithSession$activationSignature$completionBlock$

// Bundle ID
com.panyolsoft.blackhound

// Chemin déploiement
/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib
```

### 11.2 Côté PC (.NET 8)

| Classe | Rôle |
|---|---|
| `iremovalpro.Driver` | Pilotage libimobiledevice |
| `iremovalpro.Net.ApiClient` | Client REST (RestSharp) |
| `iremovalpro.Crypto.SignatureVerifier` | Vérif signatures Apple |
| `iremovalpro.Activation.MobileActivationService` | Client mobileactivationd |
| `iremovalpro.Activation.ActivationTicket` | Modélise le ticket iCloud |
| `iremovalpro.iRemovalRecord` | Record de bypass |
| `iremovalpro.iRemovalSignature` | Signature RSA |
| `iremovalpro.Eraser.A12Eraser` | Wrapper minaeraser12 |
| `iremovalpro.Bypass.BypassMeidSignal` | Bypass signal cellulaire |
| `iRemovalProWPF.MainWindow` | UI principale WPF |
| `iRemovalProWPF.MainWindow+<Activate_Click>` | Gestionnaire bouton |
| `iRemovalProWPF.MainWindow+<Erase_Click>` | Gestionnaire bouton erase |
| `iRemovalProWPF.MainWindow+<Imei_MouseDown>` | Copie IMEI au clic |
| `iRemovalProWPF.MainWindow+<Sn_MouseDown>` | Copie Serial au clic |

### 11.3 Côté iOS — Classes publiques

- `LockdownClient` / `LockdownServiceProvider` — base lockdownd
- `LockdownError` — erreurs lockdown
- `UsbmuxLockdownClient` — client via usbmuxd
- `ServiceConnection` — connexion service iOS
- `InstallationProxyService` — gestion paquets
- `MobileActivationService` — service d'activation
- `Mobilebackup2Service` — backup iOS
- `AmfiLockdownService` — Apple Mobile File Integrity
- `AfcService` / `AfcException` — Apple File Conduit
- `DiagnosticsService` / `SyslogService` — logs device

---

## 12. Identité des développeurs (déduite des strings)

| Pseudo / nom | Rôle | Évidence |
|---|---|---|
| **"Blackhound"** | Éditeur original | `T<-[Blackhound iRemovalPro Public build 0.7.1 @2022|]->` |
| **Josue Alonso Rodriguez** | Dev tweak `blackhound.dylib` | `/Users/josuealonsorodriguez/.../theos/obj/debug/arm64/` |
| **"minacriss"** | Dev `minaeraser12` | `/Users/minacriss/Documents/Minasoftware/minaeraser12/` |
| **weidong li** | Cert dev Apple intégré | `Apple Development: weidong li (PBNGZQ8G6L)` |

> ⚠️ Le certificat `weidong li (PBNGZQ8G6L)` est un **certificat Apple Developer** intégré dans le bundle — probablement obtenu légalement par un dev iOS mais réutilisé pour signer le tweak. Cela permet à `blackhound.dylib` d'être chargé par le daemon iOS sans refus immédiat, mais reste un usage potentiellement abusif.

---

## 13. Recommandations

### 13.1 Pour un **utilisateur final** légitime (propriétaire bloqué)

1. **Avant tout** : essayer `iforgot.apple.com` pour récupérer l'identifiant Apple
2. Contacter **Apple Support** avec preuve d'achat (facture originale)
3. Utiliser cet outil **uniquement** si toutes les voies officielles échouent, **sur votre propre appareil**
4. ⚠️ Ne JAMAIS l'utiliser sur un appareil **qui n'est pas le vôtre** (autorise et accpeter)

### 13.2 Pour un **analyste sécurité / chercheur**

1. **Isoler l'environnement** : VM ou PC dédié sans iPhone personnel branché
2. **Capturer le trafic** : Fiddler/mitmproxy avec le certificat de l'app pour voir les payloads échangés
3. **Analyser le tweak** : déployer `blackhound.dylib` sur un iPhone de test pour confirmer les hooks
4. **Vérifier l'OCSP Apple** : l'app utilise-t-elle les listes de révocation à jour ?
5. **Tester sans réseau** : confirmer le comportement offline

### 13.3 Pour un **fabricant d'antivirus / EDR**

- Signature IOC : combinaison de `s13.iremovalpro.com` + `iRemovalProWPF` + présence de `libimobiledevice` + `minaeraser12`
- Hashes SHA-256 :
  - `07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7` (EXE)
  - `08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141` (DLL)
- Comportement à détecter : exécution de `ideviceproxy.exe --stream` + modification de `/activation_records/activation_record.plist` sur un iPhone

### 13.4 Limites de cette analyse

- ⚠️ **Analyse statique uniquement** — pas d'exécution ni de test dynamique sur un iPhone réel
- ⚠️ Le binaire .NET 8 NativeAOT est **partiellement opaque** (code natif compilé) — décompilation complète nécessite `ilspycmd` ou `dotnet-dump` après exécution
- ⚠️ Le contenu des payloads HTTP est **chiffré HTTPS** — interception nécessite une attaque MITM avec certificat racine compromis
- ⚠️ Le tweak iOS `blackhound.dylib` n'est pas présent dans le package — il est téléchargé/compilé à la volée depuis le serveur

---

## 14. Annexes

### 14.1 Endpoints serveur complets

```
https://s13.iremovalpro.com/version33.tx
https://s13.iremovalpro.com/pub.ph
https://s13.iremovalpro.com/iremovalActivation/auth3.ph
https://s13.iremovalpro.com/iremovalActivation/ars2.ph
https://s13.iremovalpro.com/iremovalActivation/checkm8.ph
https://s13.iremovalpro.com/iremovalActivation/iact8.ph
https://s13.iremovalpro.com/iremovalActivation/mf5.ph
https://s13.iremovalpro.com/iremovalActivation/mf6.ph
https://s13.iremovalpro.com/iremovalActivation/mf7.ph
```

### 14.2 URLs Apple intégrées (vérification TLS)

```
http://crl.apple.com/root.crl
https://www.apple.com/appleca/
http://ocsp.apple.com/ocsp03-wwdr190
http://www.apple.com/certificateauthority/
http://www.apple.com/DTDs/PropertyList-1.0.dtd
```

### 14.3 Chemins iOS critiques

```
/var/mobile/Library/activation_records/activation_record.plist
/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib
/var/mobile/Library/Logs/CrashReporter/blackhound.log
```

### 14.4 Outils utilisés pour cet audit

| Outil | Usage |
|---|---|
| PowerShell + `System.IO.FileStream` | Lecture binaire + extraction PE |
| `Select-String` | Recherche de chaînes par pattern |
| Analyse manuelle de `strings` | Catégorisation des chaînes |
| `list_dir`, `read_file`, `file_search` | Inventaire workspace |
| `__analysis/` existant | Comparaison et recoupement |

---

## 15. Verdict final

| Critère | Note |
|---|---|
| **Origine** | Outil commercial connu (iRemoval PRO par Blackhound / Minh Hieu Hoang) |
| **Légitimité** | Service payant de bypass iCloud — vend l'accès au serveur d'activation |
| **Anti-debug** | Présent (NtQueryInformationProcess) |
| **Packer** | Aucun — binaire AOT .NET 8/9, structure légitime |
| **Code suspect côté PC** | Payloads Theos intégrés, IDEVICE pair/proxy shell-outs |
| **Réseau** | Communique avec serveur privé d'activation (s13.iremovalpro.com) |
| **Certificates Apple** | URLs OCSP/CRL intégrées pour validation |
| **Binaire signé Authenticode** | ❌ Non |

**Pas de packer malveillant classique.** Le binaire est un .NET 8/9 NativeAOT compilé. La protection anti-debug est classique et facilement contournable. Les risques se concentrent sur :

1. **L'iDevice cible** : bypass anti-vol, NAND rewrite irréversible, jailbreak permanent
2. **La vie privée** : envoi d'identifiants device à un serveur privé
3. **La légalité** : utilisation détournée = autorise et accpetere dans la plupart des juridictions

---

**Auteur de l'audit** : Audit statique automatisé — 2026-06-21
**Périmètre** : compréhension, documentation, audit

