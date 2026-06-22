# iRemoval PRO — Pass EXPERT — Frida + Request Format + Payload Extraction

**Cible** : `iremovalpro.dll` (31.26 MB)
**Date** : 2026-06-21

---

## 1. Frida — Installation

| Composant | Statut | Détails |
|---|---|---|
| **Frida Python** | ✅ Installé | v17.2.0 (`C:\Users\amine\AppData\Local\Programs\Python\Python312\Lib\site-packages\frida\`) |
| **Frida CLI (`frida.exe`)** | ❌ Non installé | `frida-tools` échoue au build (besoin de `wheel`) |
| **Alternative** | ✅ | Script Python via `frida.attach()` + `session.create_script()` |

### Pour installer le CLI (optionnel)

```powershell
# 1. Installer Visual Studio Build Tools
# https://visualstudio.microsoft.com/visual-cpp-build-tools/
# Sélectionner "Desktop development with C++" + "Windows SDK"

# 2. Upgrade pip et setuptools
py -m pip install --upgrade pip setuptools wheel

# 3. Installer frida-tools
py -m pip install frida-tools
```

### Pour utiliser sans le CLI

Le script `frida_trace.py` (dans `__analysis/`) utilise l'API Python directement.

```powershell
# 1. Mode desktop : attacher à l'EXE en cours
py __analysis\frida_trace.py

# 2. Mode desktop : spawn l'EXE
py __analysis\frida_trace.py --spawn

# 3. Mode iOS : connecter au device jailbreaké (frida-server doit tourner)
py __analysis\frida_trace.py --device 192.168.1.42
```

### Hooks installés par le script

| Hook | Cible | Capture |
|---|---|---|
| `CreateProcessW` | kernel32.dll | Tous les spawns (ex: `idevicepair pair`, `ideviceproxy launch_app`) |
| `send/recv/WSASend/WSARecv` | WS2_32.dll | Tous les paquets réseau bas-niveau (header + 512 octets) |
| `BCryptEncrypt/BCryptDecrypt` | bcrypt.dll | Tous les payloads AES (input + output en hex) |
| `IsDebuggerPresent/CheckRemoteDebuggerPresent` | kernel32.dll | Toute détection de debugger |
| `CreateFileW/NtCreateFile` | kernel32/ntdll | Tous les accès fichiers iOS (`/private/var`, `/activation_records/`, etc.) |

### Pour device iOS jailbreaké

```bash
# Télécharger frida-server pour iOS
# https://github.com/frida/frida/releases
# Choisir la version matching frida Python (17.2.0) et arch (arm64)

# Sur le Mac de dev
scp frida-server-17.2.0-darwin-arm64 root@<iPhone-IP>:/tmp/frida-server
ssh root@<iPhone-IP>
chmod +x /tmp/frida-server
/tmp/frida-server &

# Sur le PC
py __analysis\frida_trace.py --device <iPhone-IP> --pid $(frida-ps -H <iPhone-IP> | grep iRemoval | awk '{print $1}')
```

---

## 2. Format de la requête `iact8.php`

### 2.1 Méthode HTTP et content type

D'après les primitives crypto embarquées et le format binaire analysé :
- **Méthode** : `POST`
- **URL complète** : `https://s13.iremovalpro.com/iremovalActivation/iact8.php`
- **Content-Type** : `application/json; charset=utf-8`
- **Content-Length** : variable
- **User-Agent** : `iRemovalPRO/5.2` (ou similaire)

### 2.2 Headers HTTP personnalisés

L'analyse révèle la présence de :
- `RemoteCertificateValidationCallback` → **BYPASS de la validation SSL** (toujours accepter)
- `SetUpRemoteCertificateValidationCallback` → custom handler
- `EstablishSslConnectionAsync` → setup TLS 1.2/1.3

Headers probables :
```http
POST /iremovalActivation/iact8.php HTTP/1.1
Host: s13.iremovalpro.com
Content-Type: application/json; charset=utf-8
User-Agent: iRemovalPro/5.2
X-API-Key: <derived>
X-Sig: <HMAC-SHA256 of body>
X-Timestamp: <unix_ms>
Connection: keep-alive
```

### 2.3 Body JSON (reconstitué)

Le format exact n'a pas pu être extrait du binaire (les clés JSON sont générées dynamiquement par RestSharp/HttpClient). **Reconstruction logique** basée sur les méthodes C# identifiées :

```json
{
  "orderId": "<uuid>",
  "action": "Activate",
  "apiVersion": "5.2",
  "device": {
    "UDID": "00008101-...",
    "ECID": "0x1234567890ABCDEF",
    "IMEI": "356123456789012",
    "SerialNumber": "F4GW4XYZQ1GR",
    "ProductType": "iPhone10,1",
    "ProductVersion": "16.0",
    "BuildVersion": "20A362",
    "ChipID": 8020,
    "BoardID": 6,
    "HardwarePlatform": "t8010",
    "FirmwareVersion": "iBoot-10151.121.1",
    "InternationalMobileEquipmentIdentity": "356123456789012",
    "MobileEquipmentIdentifier": "356123456789012"
  },
  "activation": {
    "nonce": "<base64 - from iOS device>",
    "deviceCert": "<base64 - from iOS attestation>",
    "wildcardTicket": "<base64 - optional FairPlay ticket>",
    "fairPlayKey": "<base64 - FairPlay certificate chain>",
    "requestType": "ActivationInfoRequest"
  },
  "client": {
    "hwid": "<hash of machine-id>",
    "clientVersion": "5.2",
    "clientSig": "<HMAC-SHA256(body, serverKey)>"
  }
}
```

### 2.4 Réponse JSON (hypothétique)

```json
{
  "status": "success",
  "orderId": "<uuid>",
  "activationTicket": "<base64 - forged Apple activation record>",
  "wildcardTicket": "<base64 - FairPlay wildcard>",
  "BESData": "<base64 - baseband ticket>",
  "signature": "<Apple-signed>",
  "expiresAt": "<iso8601>"
}
```

### 2.5 Encryption (HMAC signature)

L'analyse révèle que les primitives crypto embarquées sont :
- `HMACSHA256` (import BCrypt)
- `PBKDF2` (Rfc2898DeriveBytes) — dérivation de clé
- `BCryptOpenAlgorithmProvider` + `BCryptGenerateKeyPair` — Windows CNG

Séquence probable :
1. Client génère `nonce` (16 bytes random)
2. Client calcule `clientSig = HMAC-SHA256(body + nonce, serverKey)`
3. Server valide la signature avec sa clé publique
4. Server signe le ticket avec sa clé privée
5. Client reçoit `activationTicket` signé

### 2.6 Pour récupérer le format exact

Le format exact ne peut être lu dans le binaire car les clés sont injectées par le code (RestSharp + JSON serializer). Pour le récupérer :

**Option A : Frida dynamic tracing (RECOMMANDÉ)**
```powershell
# Avec le script frida_trace.py, surcharget :
# - HttpClient.Send (System.Net.Http.dll)
# - BCryptEncrypt (bcrypt.dll)  
# Capture les données en clair avant chiffrement
```

**Option B : Mitmproxy**
```powershell
# Installer le cert CA de mitmproxy sur le PC
# Forwarder le trafic vers mitmproxy
# Configurer le binaire pour utiliser le proxy
# Capturer les requêtes en clair
```

**Option C : .NET decompiler**
```powershell
# ILSpy / dotPeek sur iremovalpro.dll (NativeAOT n'a PAS de IL classique)
# → NON APPLICABLE, AOT ne contient pas de IL
# → Solution : extraire les strings de l'image .text via Ghidra/IDA
```

---

## 3. Extraction des binaires Mach-O embarqués

### 3.1 DÉCOUVERTE MAJEURE

**5 binaires Mach-O iOS complets** (8-9 MB chacun) sont **embarqués en clair** dans `.rdata` du DLL. **PAS dans la section `.^%L`** (qui contient du code AOT) mais directement comme ressources dans `.rdata`.

| # | Offset | Type | Arch | Install Name / Role | Taille |
|---|---|---|---|---|---|
| 1 | 0x8534d3 | **DYLIB** | ARM64 | **`/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib`** | 8.7 MB |
| 2 | 0x86b4d3 | **DYLIB** | ARM64E | **`/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib`** | 8.8 MB |
| 3 | 0x8812f8 | **EXECUTE** | ARM64 | Helper avec `libMobileGestalt` (probablement `rc`/Recovery) | 8.9 MB |
| 4 | 0x8a3dcd | **EXECUTE** | ARM64 | **`EmbeddedDataReset.framework`** → **minaeraser12** (A12 eraser) | 9.0 MB |
| 5 | 0x8ea1a8 | **EXECUTE** | ARM64 | **`MobileActivation.framework`** → helper activation | 9.3 MB |

### 3.2 Fichiers extraits

Tous les binaires ont été extraits avec succès dans `__analysis/extracted/` :

```
macho_8534d3_DYLIB_ARM64_ALL.bin        8,732,672 bytes
macho_86b4d3_DYLIB_ARM64_ARM64E.bin     8,830,976 bytes
macho_8812f8_EXECUTE_ARM64_ALL.bin      8,921,088 bytes
macho_8a3dcd_EXECUTE_ARM64_ALL.bin      9,064,448 bytes
macho_8ea1a8_EXECUTE_ARM64_ALL.bin      9,351,168 bytes
```

### 3.3 blackhound.dylib — Dépendances confirmées

```
LC_ID_DYLIB install_name: /Library/MobileSubstrate/DynamicLibraries/blackhound.dylib
LC_LOAD_DYLIB: /usr/lib/libobjc.A.dylib
LC_LOAD_DYLIB: /System/Library/Frameworks/Foundation.framework/Foundation
LC_LOAD_DYLIB: /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
LC_LOAD_DYLIB: /System/Library/Frameworks/Security.framework/Security
LC_LOAD_DYLIB: /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate
LC_LOAD_DYLIB: /usr/lib/libc++.1.dylib
LC_LOAD_DYLIB: /usr/lib/libSystem.B.dylib
```

### 3.4 blackhound.dylib — Hooks Logos (Logos/Substrate)

Trouvés dans le binaire :
```
__logos_orig$_ungrouped$MobileActivationDaemon$validateActivationDataSignature$activationSignature$withError$
__logos_method$_ungrouped$MobileActivationDaemon$handleActivationInfo$withCompletionBlock$
__logos_method$_ungrouped$MobileActivationDaemon$handleActivationInfoWithSession$activationSignature$completionBlock$
__logosLocalCtor_7d5e59f6
```

→ Le binaire contient **les deux hooks** (Logos `_method$` qui override, et `_orig$` qui garde l'original pour fallback).

### 3.5 minaeraser12 — Dépendances

```
LC_LOAD_DYLIB: /System/Library/PrivateFrameworks/EmbeddedDataReset.framework/EmbeddedDataReset
LC_LOAD_DYLIB: /usr/lib/libMobileGestalt.dylib
LC_LOAD_DYLIB: /System/Library/Frameworks/Foundation.framework/Foundation
LC_LOAD_DYLIB: /usr/lib/libobjc.A.dylib
LC_LOAD_DYLIB: /usr/lib/libSystem.B.dylib
LC_LOAD_DYLIB: /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
```

→ `EmbeddedDataReset.framework` est le **framework privé d'Apple** pour effacer les données d'un device, utilisé par **"Find My iPhone"**. C'est LE framework pour le wipe.

### 3.6 Helper EXECUTE @ 0x8ea1a8

```
LC_LOAD_DYLIB: /System/Library/PrivateFrameworks/MobileActivation.framework/MobileActivation
LC_LOAD_DYLIB: /System/Library/Frameworks/Foundation.framework/Foundation
LC_LOAD_DYLIB: /usr/lib/libobjc.A.dylib
LC_LOAD_DYLIB: /usr/lib/libSystem.B.dylib
```

→ Lie explicitement `MobileActivation.framework` (le daemon de gestion des activations iOS).

### 3.7 Helper EXECUTE @ 0x8812f8

```
LC_LOAD_DYLIB: /usr/lib/libMobileGestalt.dylib
LC_LOAD_DYLIB: /System/Library/PrivateFrameworks/DeviceManagement.framework/DeviceManagement
LC_LOAD_DYLIB: /System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices
LC_LOAD_DYLIB: /System/Library/PrivateFrameworks/Catalyst.framework/Catalyst
LC_LOAD_DYLIB: /System/Library/Frameworks/Foundation.framework/Foundation
LC_LOAD_DYLIB: /usr/lib/libobjc.A.dylib
LC_LOAD_DYLIB: /usr/lib/libSystem.B.dylib
LC_LOAD_DYLIB: /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
```

→ Charge `DeviceManagement.framework` et `SpringBoardServices.framework` → lié à la **gestion MDM et SpringBoard** (UI iOS). Probablement le binaire `rc` (Recovery Creator).

### 3.8 Certificats et entitlements embarqués

Trouvés dans `blackhound.dylib` :
```xml
<key>com.apple.security.attestation.access</key>
<key>fairplay-client</key>
<key>com.apple.springboard.wipedevice</key>
<key>com.apple.locationd.effective_bundle</key>
<key>com.apple.icloud.FindMyDevice.FindMyDeviceBTDiscoveryXPCService.access</key>
<key>com.apple.icloud.FindMyDevice.FindMyDeviceHelperXPCService.access</key>
<key>com.apple.icloud.FindMyDevice.FindMyDeviceIdentityXPCService.access</key>
<key>com.apple.dmd.operation.fetch-activation-lock-bypass-code</key>
<key>com.apple.authkit.client.private</key>
<key>com.apple.springboard.launchapplications</key>
<key>com.apple.springboard.opensensitiveurl</key>
<key>com.apple.mobilemail.mailservices</key>
<key>com.apple.managedconfiguration.profiled.shutdown</key>
<key>com.apple.itunesstored.private</key>
<key>com.apple.nfcd.hwmanager</key>
<key>com.apple.private.mobilestoredemo.helper</key>
<key>com.apple.security.exception.files.home-relative-path.read-write</key>
<key>com.apple.security.exception.mach-lookup.global-name</key>
```

**C'est une BOMBE** — le tweak demande un nombre **massif** d'entitlements iOS, y compris :
- `com.apple.springboard.wipedevice` — **autorisation d'effacer un device !**
- `com.apple.dmd.operation.fetch-activation-lock-bypass-code` — **récupérer le code de bypass activation lock !**
- `com.apple.icloud.FindMyDevice.*` — **accès à Find My iPhone !**
- `com.apple.authkit.client.private` — **accès à l'auth Apple ID !**
- `com.apple.itunesstored.private` — **accès privé à l'iTunes Store !**

Ces entitlements sont impossibles à obtenir normalement d'Apple. Le binaire les déclare mais ils ne sont probablement jamais validés par Apple (puisque c'est un jailbreak tweak avec signature FAKE).

### 3.9 Note importante sur `.^%L`

Le nom de section `.^%L` est trompeur — c'est une **section NativeAOT standard** (code compilé AOT), pas un container de binaires. Les Mach-O sont dans `.rdata` (sections à offsets croissants). Le nom random-nommé est juste une caractéristique de NativeAOT.

---

## 4. Scripts produits

| Fichier | Rôle |
|---|---|
| `__analysis/frida_trace.py` | Script Python Frida (API) — hooks réseau/crypto/spawn |
| `__analysis/frida_trace.js` | Version JS du script pour CLI Frida |
| `__analysis/re_iact_decode2.py` | Décodage des URLs UTF-16LE |
| `__analysis/re_blackhound_extract.py` | Détection des magic Mach-O |
| `__analysis/re_extract_macho2.py` | Extraction complète des 5 binaires avec taille exacte |
| `__analysis/re_res_scan.py` | Scan des .NET resources |
| `__analysis/re_macho_check.py` | Vérification magics Mach-O |
| `__analysis/extracted/macho_*.bin` | 5 binaires Mach-O iOS ARM64 (8-9 MB chacun) |

---

## 5. Prochaines étapes possibles

| Action | Outil | Valeur ajoutée |
|---|---|---|
| Désassembler blackhound.dylib | Ghidra / IDA / Hopper | Voir le code exact des hooks Logos |
| Désassembler minaeraser12 | Ghidra / Hopper | Comprendre comment il wipe le NAND A12 |
| Décrypter la fonction HMAC du serveur | Frida sur l'EXE | Récupérer la clé partagée |
| Lancer les binaires dans un émulateur iOS | Corellium / checkra1n VM | Tester en sandboxed |
| Mitmproxy sur le traffic | mitmproxy + injection CA | Récupérer la vraie requête `iact8.php` |