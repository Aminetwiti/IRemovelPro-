# iremovalpro.dll — Analyse Reverse-Engineering

**Cible** : `iremovalpro.dll` (31.26 MB) — iRemoval PRO Premium Edition v5.2
**Date** : 2026-06-21
**Hash SHA-256** : `08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141`
**Hash EXE SHA-256** : `07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7`

---

## 1. Identification du binaire

| Attribut | Valeur |
|---|---|
| Format | PE32+ (64-bit) |
| Machine | x64 (0x8664) |
| Subsystem | WINDOWS_GUI (2) |
| ImageBase | 0x180000000 |
| EntryPoint | 0x100001ab4fc4 |
| SizeOfImage | 0x020b4000 (~34 MB virtuels) |
| FileChars | 0x2022 (EXECUTABLE_IMAGE \| LARGE_ADDRESS_AWARE \| DLL) |
| DllChars | DYNAMIC_BASE, NX_COMPAT |
| Sections | 11 (nominales AOT) |
| Global entropy | 7.2974 |

### Verdict : **.NET 8/9 NativeAOT** (compilé AOT complet)

Marqueurs définitifs :
- Sections `hydrated` (2.7 MB), `.managed` (6.7 MB), sections random-nommées `.k^q`, `.^%L`, `.%{&`, `.IE_`, `.sat`
- ImageBase `0x180000000` (default AOT pour bibliothèques)
- EntryPoint à offset très élevé `0x1ab4fc4` (typique AOT)
- Structure de chaîne ReadyToRun/NativeAOT

---

## 2. Architecture de l'application

| Binaire | Rôle | Architecture |
|---|---|---|
| `iRemoval PRO.exe` (2.79 MB) | Bootstrapper UI WPF | x86 (.NET Framework 4.x, importe `mscoree.dll!_CorExeMain`) |
| `iremovalpro.dll` (31.26 MB) | Moteur iOS + bypass + activation | x64 (.NET 8/9 NativeAOT) |
| `ref/toolkits/*.dll` | libs natives `libimobiledevice` | x64 (utilisées via P/Invoke dynamique) |

L'EXE est un thin client WPF qui démarre le CLR et charge la DLL NativeAOT pour la logique lourde. La DLL fait tout le travail réel.

---

## 3. Imports Win32 (15 fonctions, pattern AOT typique)

```
ADVAPI32.dll   RegOpenKeyExW
bcrypt.dll     BCryptDestroyHash        ← BCrypt (CNG hashing)
CRYPT32.dll    CertFreeCertificateChainEngine ← X.509 chain
IPHLPAPI.DLL   GetNetworkParams         ← Infos réseau local
KERNEL32.dll   IsDebuggerPresent        ← ANTI-DEBUG
ncrypt.dll     NCryptSetProperty        ← CNG key storage
ole32.dll      CoUninitialize
USER32.dll     LoadStringW
WS2_32.dll     WSARecv
api-ms-win-crt-heap-l1-1-0.dll     free
api-ms-win-crt-math-l1-1-0.dll     nanf
api-ms-win-crt-string-l1-1-0.dll   strcmp
api-ms-win-crt-convert-l1-1-0.dll  strtoull
api-ms-win-crt-runtime-l1-1-0.dll  abort
api-ms-win-crt-stdio-l1-1-0.dll    __stdio_common_vfprintf
```

**Particularité** : chaque DLL n'importe qu'**une seule fonction** (binding AOT minimal). Les fonctions standards C/C++ viennent des *API sets* modernes de Windows.

---

## 4. P/Invoke natif découvert

Le DLL appelle dynamiquement (via `cmd /c`):

```
/c idevicepair pair
/c ideviceproxy ad2 aw
/c ideviceproxy lao abc ofq com.iremovalpro.bypass --stream
```

→ Le `ref/toolkits/` contient précisément `idevicepair.exe`, `ideviceproxy.exe`, `libusbmuxd-2.0.dll`, `libimobiledevice-1.0.dll`, `libplist-2.0.dll`, `libssl-3-x64.dll`, `libcrypto-3-x64.dll` — la stack complète `libimobiledevice` Windows.

**Aussi** : appels P/Invoke directs à `NtQueryInformationProcess` et `NtQueryInformationFile` pour anti-debug.

---

## 5. Bibliothèques .NET embarquées (référencées)

| Bibliothèque | Usage |
|---|---|
| **net-mobiledevice** (Netimobiledevice namespace) | Port .NET de libimobiledevice |
| **RestSharp** | Client HTTP/REST |
| **SSH.NET** (Renci.SshNet) | Client SSH pour tunnel vers l'iDevice |
| **QRCoder** | Génération de QR codes (tickets d'activation) |
| **System.Net.Http** | HTTP/2 + HTTP/3 natif |
| **.NET 8/9 NativeAOT runtime** | Runtime complet embarqué |

---

## 6. Classes et fonctions métier identifiées

### 6.1 Protocole Apple (réimplémentation C# de libimobiledevice)

```
UsbmuxdConnection        UsbmuxdHeader
UsbmuxdDevice            UsbmuxdDeviceRecord
UsbmuxdConnectionEventType    UsbmuxdMessageType
PlistMuxConnection       UsbmuxdConnectionMonitor
LockdownClient           LockdownServiceProvider
PlistUsbmuxLockdownClient    UsbmuxLockdownClient
ServiceConnection        AfcException, AfcFileNotFoundException
BackupFile, Mobilebackup2Exception
AmfiLockdownService      InstallationProxyService
MobileActivationService  Mobilebackup2Service
```

### 6.2 Bypass et activation iCloud (logique propriétaire)

```
A12Eraser                       ← Effaceur NAND A12 (checkm8)
BypassMeidSignal                ← Contourne le signal MEID
iDevice_Activate                ← Active l'iDevice (bypass iCloud)
iDevice_Deactivate
iDevice_LnchV2                  ← Lance apps sur l'iDevice
iDevice_GetState
iDevice_EnableDevMode
iDevice_Restart
iDevice_RemoveProfiles          ← Supprime profils MDM
iDevice_Tnl                     ← Tunnel SSH
Firewall_iDeviceProxy           ← Règles pare-feu pour le proxy
SecureClearAndCollect
ExecuteAsAdmin
```

### 6.3 Handlers UI asynchrones (WPF)

```
<Imei_MouseDown>d__114         ← Click sur champ IMEI
<Sn_MouseDown>d__113           ← Click sur champ SN (Serial)
<Button_Click_5>d__121         ← Bouton principal
<iDevice_RemoveProfiles>d__81
<CommonConnectDevice>d__107
<Install>d__8                  ← Installation IPSW
<InstallFromLocal>d__60
<WatchForCompletion>d__7
<GetDeviceLink>d__8            ← DeviceLink
<RestoreBackup>d__9            ← Restauration depuis backup
<VersionExchange>d__7
```

### 6.4 Erreurs / exceptions

```
FatalPairingException, NotPairedException, PasswordRequiredException
LockdownException, ConnectionFailedException
ServiceStartException, UsbmuxConnectionException
IncorrectModeException, NoDeviceConnectedException
```

---

## 7. Endpoints réseau et serveurs

### 7.1 Serveur principal d'activation

```
https://s13.iremovalpro.com/iremovalActivation/checkm8.php
```

→ Serveur de l'auteur commercial du service. Endpoint du bypass checkm8.

### 7.2 Pages promotionnelles

```
https://www.trustpilot.com/review/iremovalpro.co
```

### 7.3 URLs Apple intégrées (validation des certificats)

```
http://www.apple.com/DTDs/PropertyList-1.0.dtd
http://crl.apple.com/root.crl0
https://www.apple.com/appleca/0
http://ocsp.apple.com/ocsp03-wwdr190
http://www.apple.com/certificateauthority/0
```

### 7.4 Endpoint iOS

```
/netimobiledevice.ip             ← port 62078 (lockdown)
```

---

## 8. Mécanique du bypass — Workflow reconstitué

D'après les indices collectés, le flux est :

1. **Détection du device** — `UsbmuxdConnectionMonitor` via `AppleMobileDeviceService`
2. **Pairing** — appel à `idevicepair pair` (P/Invoke + `libusbmuxd`)
3. **Démarrage tunnel** — `iDevice_Tnl` (SSH via SSH.NET sur port 22 forwardé)
4. **Mise en DFU** — protocole `lockdown` → mode Recovery → DFU
5. **Exploitation checkm8** — bootrom exploit (A11 et antérieur) ou `A12Eraser` (A12+)
6. **Chargement du payload iOS** — envoi de `blackhound.dylib` via SSH
7. **Effacement NAND** — `minaeraser` (effaceur NAND pour A12) ou `A12Eraser`
8. **Restauration** — `RestoreBackup` / `Install` / `InstallFromLocal` (IPSW)
9. **Activation** — `iDevice_Activate` contacte `https://s13.iremovalpro.com/iremovalActivation/checkm8.php` pour obtenir un **ticket d'activation signé**
10. **Vérif certificats** — `CertFreeCertificateChainEngine` + `BCryptDestroyHash` + `NCryptSetProperty` valident la chaîne Apple
11. **Suppression profils MDM** — `iDevice_RemoveProfiles`
12. **Confirmation** — `iDevice Activated Succesfully`

### 8.1 Payloads iOS embarqués (chemins de build)

Les binaires suivants sont **compilés par les auteurs sur leur Mac** puis embarqués dans la DLL :

| Payload | Auteur | Chemin |
|---|---|---|
| **blackhound** | josuealonsorodriguez | `/Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/.theos/obj/debug/arm64/` |
| **minaeraser** | minacriss | `/Users/minacriss/Documents/Minasoftware/minaeraser/Build/...` |
| **minaeraser12** | minacriss | `/Users/minacriss/Documents/Minasoftware/minaeraser12/Build/...` (variante A12) |
| **rc** | minacriss | `/Users/minacriss/Library/Developer/Xcode/DerivedData/rc-.../...` (Recovery Creator) |

Ce sont des **tweaks iOS** compilés avec **Theos** (toolchain de tweaks iOS). Le suffixe `.x.<hash>.o` est typique de l'output Theos après strip des symboles.

### 8.2 Chaîne d'activation Apple ciblée

L'agent conversationnel a découvert des chaînes de version du binaire interne Apple :
```
iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28)
iOS Device Activator (MobileActivation-592.103.2)
```

→ Ces chaînes sont issues de `mobileactivationd` sur iOS. Plusieurs versions sont gérées (compatibilité descendante).

### 8.3 Options de restauration

```
RestoreDontCopyBackup        RestorePreserveSetting
RestoreShouldReboot          RestoreSystemFile
```

Drapeaux passés à `mobileactivationd_restore` sur iOS :
```
/private/var/logs/mobileactivationd_restore/
```

### 8.4 Message de service payant

```
"Remember, this is an exclusive A12+ Full Bypass service with OTA feature,
 you can update but cannot restore!."
"iRemoval PRO Servers are currently under MAINTENANCE"
"please allow 24 hours for the order to be completed"
```

→ Le produit est vendu comme **service** (avec back-end serveur), pas comme outil libre. Les utilisateurs achètent un crédit pour chaque bypass.

---

## 9. Anti-debugging et protections

| Technique | Détectée |
|---|---|
| `IsDebuggerPresent` (import direct) | ✅ |
| `NtQueryInformationProcess` (P/Invoke) | ✅ ProcessDebugPort check |
| `NtQueryInformationFile` (P/Invoke) | ✅ Détection de hooks |
| `DefaultDllImportSearchPaths` (attribut) | ✅ |
| DllCharacteristics NX_COMPAT + DYNAMIC_BASE | ✅ |

---

## 10. Cryptographie embarquée

- **BCrypt** (Windows CNG) — hashing
- **NCrypt** (Windows CNG) — key storage
- **CAPI** (`SafeCapiKeyHandle`) — legacy crypto
- **TLS / SCHANNEL** — `SCHANNEL_ALERT_TOKEN`, `SCHANNEL_SESSION_TOKEN`
- **SSH** — `KeyExchangeECDH384`, `KeyExchangeECDH521`, `KeyExchangeHashData`
- **SHA** — `TokenHashValue`, `GroupExchangeHashData`
- **HMAC** — `KeyedHashAlgorithm`, `HashAlgorithmName`
- **X.509** — `issuerCertificate`, `m_safeCertContext`, `CERT_FIND_HASH`, `CERT_FIND_SUBJECT_STR`
- **AES** — `AesImplementation`, `Aes$SymmetricAlgorithm`
- **ASN.1** — `System.Formats.Asn1` (parsing des certificats)

---

## 11. Indice de menace

| Critère | Note |
|---|---|
| **Origine** | Outil commercial connu (iRemoval PRO par Minh Hieu Hoang) |
| **Légitimité** | Service payant de bypass iCloud — vend l'accès au serveur d'activation |
| **Anti-debug** | Présent (NtQueryInformationProcess) |
| **Packer** | Aucun — binaire AOT .NET, structure légitime |
| **Code suspect** | Payloads Theos intégrés, IDEVICE pair/proxy shell-outs |
| **Réseau** | Communique avec serveur privé d'activation (s13.iremovalpro.com) |
| **Certificates Apple** | URLs OCSP/CRL intégrées pour validation |

**Pas de packer malveillant.** Le binaire est un .NET 8/9 NativeAOT compilé. La protection anti-debug est classique et facilement contournable.

---

## 12. Indicateurs de compromission (IoC)

```
# Fichiers
iremovalpro.dll   SHA256: 08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141
iRemoval PRO.exe  SHA256: 07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7

# Domaine
s13.iremovalpro.com
iremovalpro.co
iremovalpro.com

# URLs
https://s13.iremovalpro.com/iremovalActivation/checkm8.php
https://www.trustpilot.com/review/iremovalpro.co

# Bundles iOS déployés
com.iremovalpro.bypass

# Paquets de chaînes uniques
NimobiledeviceException / LockdownException / MobileActivationService
A12Eraser / BypassMeidSignal / iDevice_Activate

# Chemins développeur (origines des payloads iOS)
/Users/josuealonsorodriguez/.../blackhound/
/Users/minacriss/.../minaeraser/
/Users/minacriss/.../minaeraser12/
/Users/minacriss/.../rc/
```

---

## 13. Risques de sécurité

⚠️ **Pour un poste d'analyse :**
1. L'outil **utilise libimobiledevice** pour communiquer avec un iDevice — risque pour la vie privée si un iPhone est branché
2. **Shell-out à `ideviceproxy` avec `--stream`** — pont réseau entre le PC et l'iDevice
3. **Pas de signature Authenticode** (le format PE est non signé, ou les attributs sont neutralisés)
4. **Comportement réseau actif** — un test dynamique contactera `s13.iremovalpro.com`

⚠️ **Pour un iDevice :**
1. **Réécrit le NAND** (`A12Eraser`/`minaeraser12`) — irréversible
2. **Bypass de l'activation lock** — enlève la protection anti-vol
3. **Active des services sur le device** sans compte Apple ID valide
4. **Risque de briquer** le device si la procédure échoue

---

## 14. Fichiers générés pour cette analyse

- `__analysis/pe_parse.py` — script d'analyse PE
- `__analysis/pe_report.txt` — rapport PE complet
- `__analysis/strings_extract.py` — script d'extraction de chaînes
- `__analysis/strings_report.txt` — rapport catégorisé (36 KB)
- `__analysis/strings_all_long.txt` — toutes les chaînes longues (754 KB, ~14 400 chaînes uniques)
- `__analysis/REPORT.md` — ce document
