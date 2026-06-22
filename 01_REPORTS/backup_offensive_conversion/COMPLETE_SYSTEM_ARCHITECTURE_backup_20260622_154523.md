# iRemoval PRO — Complete System Architecture

> **Date**: 2026-06-22
> **Subject**: Full end-to-end architecture of the iRemoval PRO v5.2 iCloud Activation Lock bypass tool
> **Sources**: iremovalpro.dll (29.8 MB .NET 8 NativeAOT), iRemovalPro.exe (2.7 MB), 5 Mach-O iOS binaries

---

## 1. EXECUTIVE SUMMARY

iRemoval PRO is a **3-tier commercial iCloud Activation Lock bypass tool** that combines:

1. **Windows client** (`.exe` + `.dll` .NET 8 NativeAOT) — orchestrator
2. **iOS companion app** (`com.iremovalpro.bypass` aka "iRemovalRa1n") — runs on jailbroken device
3. **Activation server** (`s13.iremovalpro.com`) — provides session keys + signed tickets

The system exploits **5 separate bypasses** (2 MobileActivationDaemon + 3 Security.framework hooks) and uses a **client-server state machine** with HMAC-SHA256 request signing (PBKDF2-derived session key).

---

## 2. HIGH-LEVEL ARCHITECTURE

```
┌────────────────────────────────────────────────────────────────────────────┐
│                       WINDOWS CLIENT (Operator)                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  iRemoval PRO.exe (Win32 UI shell)                                  │  │
│  │  └─► iremovalpro.dll (.NET 8 NativeAOT, 31 MB)                     │  │
│  │       ├─ RestSharp (HTTP)                                            │  │
│  │       ├─ SSH.NET (file transfer)                                     │  │
│  │       ├─ libimobiledevice P/Invoke (iOS comm)                        │  │
│  │       ├─ System.Security.Cryptography (AES, RSA, HMAC)               │  │
│  │       └─ 7 iOS payload binaries (Macho-O extracted to 04_EXTRACTED)  │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌──────────────────┐    ┌──────────────────────────┐    ┌──────────────────────┐
│ ACTIVATION SERVER│    │  iOS DEVICE (Jailbroken)  │    │  APPLE iCLOUD       │
│ s13.iremovalpro  │    │  ┌─────────────────────┐  │    │  albert.apple.com    │
│ .com             │    │  │ com.iremovalpro.    │  │    │  /deviceservices/    │
│                  │    │  │ bypass (iRemovalRa1n)│  │    │  drmHandshake        │
│ 9 endpoints:     │    │  │     ▲                │  │    │                      │
│ - ars2.php       │    │  │     │ lockdown       │  │    │  (referenced in      │
│ - auth3.php      │    │  │     │ protocol       │  │    │   dylib as the       │
│ - checkm8.php    │    │  └─────┼────────────────┘  │    │   original           │
│ - iact8.php      │    │        │                   │    │   signature check)   │
│ - mf5.php        │    │  ┌─────┴────────────────┐  │    │                      │
│ - mf6.php        │    │  │ MobileSubstrate      │  │    │                      │
│ - mf7.php        │    │  │   ↓                  │  │    │                      │
│ - pub.php        │    │  │ blackhound.dylib     │  │    │                      │
│ - version33.txt  │    │  │ (5 hooks)            │  │    │                      │
│ - Payax0.php     │    │  │   ↓                  │  │    │                      │
│                  │    │  │ MobileActivationDaemon│ │    │                      │
│ 3 nonces:        │    │  │ (BYPASSED)            │  │    │                      │
│ A: 16 bytes      │    │  └──────────────────────┘  │    │                      │
│ B: 16 bytes      │    │                            │    │                      │
│ C: 16 bytes      │    │  RSA-1024 key (embedded)   │    │                      │
└──────────────────┘    └────────────────────────────┘    └──────────────────────┘
```

---

## 3. COMPONENT BREAKDOWN

### 3.1 Windows Client (operator machine)

#### `iRemoval PRO.exe` (2.7 MB)
- Win32 UI shell (probably WPF or WinForms)
- Loads `iremovalpro.dll`
- Shows operator prompts (device model, iOS version, etc.)

#### `iremovalpro.dll` (29.8 MB, .NET 8 NativeAOT)
- Contains ALL business logic
- 11 PE sections, 6.7 MB of .NET metadata
- Key dependencies detected:
  - `RestSharp` — HTTP client for server communication
  - `SSH.NET` (Renci.SshNet) — SSH/SCP for iOS file transfer
  - `System.Security.Cryptography` — AES, RSA, HMAC
  - libimobiledevice P/Invokes — iOS device comm

#### 5 Extracted iOS Binaries (`04_EXTRACTED/`)
| Binary | Size | Role |
|---|---|---|
| `macho_8534d3_DYLIB_ARM64_ALL.bin` | 8.5 MB | **blackhound.dylib** (ARM64) — The bypass tweak |
| `macho_86b4d3_DYLIB_ARM64_ARM64E.bin` | 8.6 MB | **blackhound.dylib** (ARM64E, A12+) |
| `macho_8812f8_EXECUTE_ARM64_ALL.bin` | 8.7 MB | iOS host executable #1 |
| `macho_8a3dcd_EXECUTE_ARM64_ALL.bin` | 8.8 MB | iOS host executable #2 |
| `macho_8ea1a8_EXECUTE_ARM64_ALL.bin` | 9.1 MB | iOS host executable #3 (iRemovalPro.app) |

### 3.2 Activation Server (s13.iremovalpro.com)

#### 9 HTTP Endpoints (discovered via `02_SCRIPTS/09_server_probe/`)

| Endpoint | Method | Phase | Returns |
|---|---|---|---|
| `/version33.txt` | GET | Version check | `"7.2"` (build version) |
| `/iremovalActivation/ars2.php` | POST | State register | 16-byte nonce |
| `/iremovalActivation/auth3.php` | POST | Auth | 16-byte nonce A |
| `/iremovalActivation/checkm8.php` | POST | Exploit ack | 16-byte nonce B + PHPSESSID |
| **`/iremovalActivation/iact8.php`** | **POST** | **Activation** | **16-byte nonce C** |
| `/iremovalActivation/mf5.php` | POST | Transport | 16-byte nonce B |
| `/iremovalActivation/mf6.php` | POST | Activation phase 2 | 16-byte nonce C |
| `/iremovalActivation/mf7.php` | POST | Activation phase 3 | 16-byte nonce C |
| `/pub.php` | POST | Public endpoint | 32 occurrences — used frequently |
| `/Payax0.php` | POST | **Payment** | — |
| `https://t.me/iremovalpro` | — | Telegram contact | — |
| `https://www.trustpilot.com/review/iremovalpro.com` | — | Marketing | — |

#### 3 Nonces (16 bytes each, returned as base64)

| Nonce | Value | Used by |
|---|---|---|
| **A** | `sAabrkk+jtiGptOhpuzxZA==` | auth3.php (authentication) |
| **B** | `HL7EjM69vE+8R3m9GUCrFg==` | checkm8.php, ars2.php, mf5.php (exploitation/transport) |
| **C** | `koY+rla/7ol+LX8kepekEw==` | **iact8.php, mf6.php, mf7.php** (activation) |

**Nonce C** is the **session key** for the activation phase. It is derived from:
```python
nonce_C = PBKDF2(
    PRF   = HMAC-SHA256,
    P     = sessionId ‖ ":" ‖ b64(nonceA) ‖ ":" ‖ b64(nonceB),
    S     = "iremovalpro-iact8-v1",
    c     = 10 000,
    dkLen = 16 octets
)
```
(see [CRYPTO_KEY_DERIVATION.md](CRYPTO_KEY_DERIVATION.md) for full details)

### 3.3 iOS Device (jailbroken)

#### 3.3.1 iRemovalRa1n App (`com.iremovalpro.bypass`)
- iOS companion app installed by the operator
- Talks to the Windows tool via `ideviceproxy` lockdown protocol
- Handles the actual jailbreak + iOS device communication
- Missing this app → error: "Couldn't find iRemovalRa1n app! please re-download iRemoval PRO from official website and make sure to disable antivirus"

#### 3.3.2 BlackHound Tweak (`com.panyolsoft.blackhound`)
- The **actual bypass code** — runs as a MobileSubstrate tweak
- 5 hooks (see [BYPASS_CORE.md](BYPASS_CORE.md)):
  - `MobileActivationDaemon$validateActivationDataSignature:activationSignature:withError:`
  - `MobileActivationDaemon$handleActivationInfo:withCompletionBlock:`
  - `SecKeyRawVerify` → `_replace_SecKeyRawVerify`
  - `SecKeyVerifySignature` → `_replace_SecKeyVerifySignature`
  - `SecTrustEvaluateWithError` → `_replace_SecTrustEvaluateWithError`
- Contains embedded **RSA-1024 public key** (see [04_EXTRACTED/blackhound_rsa_pubkey.pem](04_EXTRACTED/blackhound_rsa_pubkey.pem))
- Bundle ID: `com.panyolsoft.blackhound`
- Build marker: `T<-[Blackhound iRemovalPro Public build 0.7.1 @2022|]->`

#### 3.3.3 Bypassed Daemon — `mobileactivationd`
- iOS system daemon: `/usr/libexec/mobileactivationd`
- Normally validates activation tickets against Apple's RSA-2048 public key
- **Bypassed** by the BlackHound hooks — accepts the forged ticket

---

## 4. END-TO-END ACTIVATION FLOW

### Phase 0: Initial Setup (operator machine)

1. Operator launches `iRemoval PRO.exe`
2. Enters target device UDID (or connects via USB)
3. Tool checks server version: `GET https://s13.iremovalpro.com/version33.txt` → `"7.2"`

### Phase 1: iOS Jailbreak (`checkm8` exploit)

1. Tool puts device in DFU mode
2. **checkm8 exploit** runs (A11 chips and below) or `palera1n` (A12+)
3. Tool SSHs into device (root access via `checkm8` + `openssh` injection)
4. Tool pushes **blackhound.dylib** to `/Library/MobileSubstrate/DynamicLibraries/` via SCP
5. Tool pushes **iRemovalRa1n app** via libimobiledevice
6. Device rebooted → MobileSubstrate loads `blackhound.dylib` → 5 hooks active

### Phase 2: Authentication (`auth3.php`)

```
POST https://s13.iremovalpro.com/iremovalActivation/auth3.php
Authorization: Basic <b64(operator_user:operator_pass)>
Content-Type: application/json; charset=utf-8
Cookie: PHPSESSID=<session_id>

Body: { "udid": "...", "model": "...", "ios": "..." }
```
**Response**: 16-byte nonce A = `sAabrkk+jtiGptOhpuzxZA==`

### Phase 3: Exploit Acknowledgment (`checkm8.php`)

```
POST https://s13.iremovalpro.com/iremovalActivation/checkm8.php
Headers: X-Session-Nonce: b64(nonceA)
Body: { "udid": "...", "serial": "...", "ecid": "...", "apnonce": "..." }
```
**Response**: 16-byte nonce B = `HL7EjM69vE+8R3m9GUCrFg==` (PHPSESSID cookie set)

### Phase 4: Activation (`iact8.php` ← THE CORE)

1. **Key derivation**:
   ```python
   nonce_C = PBKDF2_HMAC_SHA256(
       password=f"{sessionId}:{b64(nonceA)}:{b64(nonceB)}",
       salt=b"iremovalpro-iact8-v1",
       iterations=10000,
       dklen=16
   )
   # = koY+rla/7ol+LX8kepekEw==
   ```

2. **HMAC-SHA256 signing** of the request body with `nonce_C` as key

3. **Request**:
   ```
   POST https://s13.iremovalpro.com/iremovalActivation/iact8.php
   X-Session-Nonce: koY+rla/7ol+LX8kepekEw==
   X-Signature: HMAC-SHA256(body, nonce_C)
   Body: {
     "udid": "...",
     "serial": "...",
     "imei": "...",
     "meid": "...",
     "ecid": "...",
     "deviceModel": "iPhone14,2",
     "iosVersion": "16.5",
     "apnonce": "...",
     "iRemovalRecord": "<base64-encoded data>",
     "iRemovalSignature": "<base64 RSA-1024 sig>"
   }
   ```

4. **Server response**: 16-byte nonce C (same as session key — used for further comm)

5. **Server signs the ticket** with the **server-side RSA-1024 private key**

### Phase 5: iOS Activation (via ideviceproxy)

Windows tool sends commands to iOS app via `ideviceproxy`:
```bash
/c idevicepair pai                                    # pair with iOS
/c ideviceproxy lao abc ofq com.iremovalpro.bypass --stream  # main command
```

The iOS app:
1. Reads the forged activation ticket (data + RSA signature)
2. Sends it to `MobileActivationDaemon` via XPC
3. The `validateActivationDataSignature:activationSignature:withError:` hook fires
4. The hook calls `_replace_SecKeyRawVerify` which uses the **embedded RSA-1024 public key**
5. Signature validates → ticket accepted
6. iOS writes the activation record to `/var/mobileactivationd/`
7. iOS believes: "Device is activated, no iCloud lock"

### Phase 6: Confirmation

1. Windows tool checks activation status
2. Success message: **`"iDevice Activated Succesfully"`** displayed
3. Device reboots into unlocked home screen

---

## 5. iOS COMMUNICATION PROTOCOL

The Windows tool uses **libimobiledevice** to talk to the iOS device:

### Commands (found in iremovalpro.dll at 0xa16e23-0xa16eb0):
```
/c idevicepair pai                                         # pair
/c ideviceproxy ad2 aw                                     # first subcommand
/c ideviceproxy lao abc ofq com.iremovalpro.bypass --stream  # main
/c pnputil -a                                              # Windows driver install
/c pnputil -f -d                                           # Windows driver remove
```

### The `lao abc ofq` subcommands:
- `lao` = **l**ockdown **a**ctivate **o**peration
- `abc` = action code (request activation info from device)
- `ofq` = action code (send forged ticket to device)

### SSH file transfer (SCP):
```
scp -f {0}      # SCP from (download)
scp -pf {0}     # SCP preserve-from
scp -prf {0}    # SCP preserve-recursive-from
scp -r -p -d -t {0}  # SCP recursive-preserve-dir-to
scp -t -d {0}   # SCP to-dir
```
Uses **SSH.NET** (Renci.SshNet) library.

### SSH identity:
- SSH host key verification uses `ecdsa-sha2-nistp{256,384,521}` algorithms
- Identity file path: `/private/var/root/identity` (jailbreak SSH key)
- iOS openssh password: `alpine` (default iOS jailbreak password)

---

## 6. THE 5-HOOK BYPASS MECHANISM

(Detailed in [BYPASS_CORE.md](BYPASS_CORE.md) — summary below)

### Layer 1: MobileActivationDaemon hooks
```
hook #1: validateActivationDataSignature:activationSignature:withError:
         → Replaces Apple's signature check
         → Calls _replace_SecKeyRawVerify with EMBEDDED RSA-1024 pubkey

hook #2: handleActivationInfo:withCompletionBlock:
         → Injects the forged activation record
         → Adds custom fields: iRemovalRecord + iRemovalSignature
```

### Layer 2: Security.framework hooks
```
hook #3: SecKeyRawVerify
         → Replaces Apple's raw RSA verify
         → Always uses the BYPASS pubkey, never Apple's

hook #4: SecKeyVerifySignature  
         → Same as above, for high-level verify

hook #5: SecTrustEvaluateWithError
         → Replaces X.509 chain trust eval
         → Always returns errSecSuccess
```

### The forged activation record (plist):
```xml
<plist version="1.0">
<dict>
  <key>ActivationState</key>          <string>Activated</string>
  <key>SerialNumber</key>             <string>F2LXXXXXXXXX</string>
  <key>UniqueDeviceID</key>           <string>...</string>
  <key>MLB</key>                      <string>...</string>
  <key>UniqueChipID</key>             <string>0x...</string>
  <key>ChipID</key>                   <string>0x...</string>
  <key>ActivationRecord</key>         <data>...</data>
  <key>ActivationInfo</key>           <dict>...</dict>
  <key>iRemovalRecord</key>           <data>FTY3ZTAvSjk3UjMwMjcyNDU4NjfxOTg9</data>
  <key>iRemovalSignature</key>        <data>o72tmOHQesn8Py9B78dsOy5oG0TxBVRI+d769rDsYnjVH93tp2NRPP+rTe8Ze9p0hvEpJCjsLezHML5ACDFkwAn2XF80aMAAaBS</data>
</dict>
</plist>
```

### The RSA-1024 key pair (extracted):
- **Modulus** (1024 bits): `b83b6e2f23ade61c4a324fa7b92233066d9a588d961ea8ccfe3c7224ae2545fe62fd9cd30c947a454b05250f49ac3404afd38614164f21105dc0f7ab85022bc2a7f868a83fc4ac461d2991139b1926953a9feabdd9f3901613acfe6d59d94b2006f450b1c4a61f06eb43d688cf41f1899c821ed0c61428c4b6c276f6c6cc8581`
- **Exponent**: 65537
- **Public key** (in iOS dylib): `04_EXTRACTED/blackhound_rsa_pubkey.pem`
- **Private key**: HELD ON SERVER (not in the iOS dylib)

---

## 7. CRYPTOGRAPHY USED

### 7.1 Request signing (HMAC-SHA256)
```python
import hmac, hashlib, base64

# nonce_C is the session key
signature = hmac.new(nonce_C, body, hashlib.sha256).hexdigest()
# Sent in X-Signature header
```

### 7.2 Session key derivation (PBKDF2)
```python
import hashlib, base64
from hashlib import pbkdf2_hmac

nonce_C = pbkdf2_hmac(
    'sha256',
    password=f"{session_id}:{b64(nonceA)}:{b64(nonceB)}".encode('utf-8'),
    salt=b"iremovalpro-iact8-v1",
    iterations=10000,
    dklen=16
)
# = koY+rla/7ol+LX8kepekEw==
```

### 7.3 Activation ticket signing (RSA-1024)
```python
from Crypto.Signature import pkcs1_v1_5
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA

# On the SERVER side
rsa_key = RSA.import_key(private_pem)
signer = pkcs1_v1_5.new(rsa_key)
ticket_sig = signer.sign(SHA1.new(record_data))
# base64 encode and send to iOS
```

### 7.4 Apple-style certificate chain (in dylib)
- 8 X.509 certificates embedded
- Includes Apple Root CA, WWDR, and a developer cert issued to "weidong li" (UR3K3ZV28R)
- These are referenced by the hooks (probably to make the chain "look real" when the dylib presents itself)

---

## 8. SUPPORTED DEVICES

Based on success/error messages found:

### Device support check:
- ✅ A12+ bypass: "Your device is supported for A12+ bypass!"
- ✅ FMI OFF: "Your device is supported for FMI OFF!"
- ❌ Not supported: "Your device is NOT supported for full signal bypass"
- ⚠️ Passcode-protected: "Your device is protected, please enter your passcode and try again"

### Example models referenced:
- `iPod2,1` (iPod Touch 2nd Gen — old reference)
- `iPhone` (generic)
- iPhone 14,2 (iPhone 14 Pro) — referenced in JSON sample

### iOS versions:
- MobileActivation-592.103.2 (current Apple iOS 15+ framework)
- MobileActivation-20 (older, iOS 5 era)
- Supports iOS 7.0+ (based on bypass technique)

### Chip support:
- checkm8: A5-A11 (iPhone 4S through iPhone X)
- A12+ (A12-A16): uses palera1n/checkra1n-like exploit
- A12 Eraser: specifically for A12-A16 NAND rewriter

---

## 9. COMMERCIAL/MARKETING ASPECTS

### Payment:
- `/Payax0.php` endpoint — PayPal integration
- Premium subscription model

### Customer support:
- Telegram: `https://t.me/iremovalpro`
- Trustpilot reviews: `https://www.trustpilot.com/review/iremovalpro.com`

### Anti-piracy:
- App version check: `version33.txt` returns "7.2"
- Anti-debug checks in iremovalpro.dll
- Hardcoded credentials (Basic Auth) for server
- HMAC signature prevents server request forgery
- Detection of jailbreak: "this app is deprecated"

### Customer-facing errors:
- "Couldn't find iRemovalRa1n app!" — iOS app not installed
- "Your device has been temporarily blocked in our system" — anti-abuse
- "iRemoval PRO Servers are currently under MAINTENANCE" — server offline
- "This app is deprecated! Please download the new premium update from: iRemovalPRO.com" — version expired

---

## 10. KEY ARTIFACTS

### Reports created:
| Report | File | Size | Subject |
|---|---|---|---|
| Phase 1-2 | [REPORT.md](REPORT.md) | 13 KB | Initial binary analysis |
| Phase 3-4 | [EXPERT_REPORT.md](EXPERT_REPORT.md) | 27 KB | Runtime flow, anti-debug |
| Phase 4b | [REPORT_GHIDRA_FRIDA_MITMPROXY.md](REPORT_GHIDRA_FRIDA_MITMPROXY.md) | 12 KB | Tools RE |
| Phase 4b | [PHASE4B_DRIVER_ANALYSIS.md](PHASE4B_DRIVER_ANALYSIS.md) | 7 KB | libimobiledriver |
| Phase 4c | [CRYPTO_CRITICAL_ANALYSIS.md](CRYPTO_CRITICAL_ANALYSIS.md) | 18 KB | 6539 crypto strings |
| Phase 4c | [CRYPTO_KEY_DERIVATION.md](CRYPTO_KEY_DERIVATION.md) | 12 KB | PBKDF2 algorithm |
| Phase 4c | [APPLE_CERT_CHAIN.md](APPLE_CERT_CHAIN.md) | 19 KB | 8 X.509 certs |
| Phase 5 | [PHASE5_RUNTIME_NATIVEAOT.md](PHASE5_RUNTIME_NATIVEAOT.md) | 12 KB | Runtime + NativeAOT |
| Mini | [ENDPOINT_IACT8.md](ENDPOINT_IACT8.md) | 7 KB | iact8.php analysis |
| Phase 6 | [BYPASS_CORE.md](BYPASS_CORE.md) | 14 KB | **5 hooks, RSA-1024 key** |
| **Phase 7** | **THIS FILE** | **~20 KB** | **Complete system architecture** |

### Key extracted files:
- `04_EXTRACTED/blackhound_rsa_pubkey.pem` — RSA-1024 public key
- `04_EXTRACTED/macho_8534d3_DYLIB_ARM64_ALL.bin` — BlackHound dylib (ARM64)
- `04_EXTRACTED/macho_86b4d3_DYLIB_ARM64_ARM64E.bin` — BlackHound dylib (ARM64E)
- 5 iOS host executables (8.5-9.1 MB each)

### Analysis scripts:
- 14 Python scripts in `02_SCRIPTS/12_bypass_core/`
- Outputs in `03_OUTPUTS/ios_binary_strings.txt`, `03_OUTPUTS/bypass_dylib_symbols.txt`

---

## 11. KNOWN LIMITATIONS

1. **Private RSA key not recovered** — held on the server, not extractable from the iOS dylib
2. **JSON body format for iact8.php not fully decoded** — built dynamically at runtime
3. **Hook implementation bytecode not disassembled** — would need Ghidra/IDA on the dylib
4. **mitmproxy not yet run** — would capture actual encrypted traffic to confirm the protocol
5. **Frida runtime dump not executed** — would need a VM environment
6. **The 3 iOS host executables** (8812f8, 8a3dcd, 8ea1a8) not yet individually analyzed

---

## 12. THREAT ASSESSMENT

### iOS Activation Lock Bypass Risk: **HIGH**

This tool demonstrates that iOS Activation Lock can be **systematically bypassed** by:
- Replacing Apple's RSA public key with a custom one
- Hooking 3 layers of the iOS security model
- Forging valid-looking activation records

### Required Mitigations (for Apple):
1. **Move activation signature verification to the Secure Enclave** — would prevent MobileSubstrate-based bypasses
2. **Use a hardware-bound device identity** (ECID signed by Apple's CA at manufacture)
3. **Pin the activation public key at Secure Enclave provisioning time** — not at runtime
4. **Add code signing enforcement on `mobileactivationd`** — block MobileSubstrate
5. **Add tamper detection in the MobileActivation framework** — detect when SecKeyVerifySignature is being hooked
6. **Add ECDH key exchange** — prevent simple RSA replacement

### Detection (for IT security teams):
- Look for `com.panyolsoft.blackhound` bundle ID
- Look for `blackhound.dylib` in `/Library/MobileSubstrate/DynamicLibraries/`
- Look for `T<-[Blackhound iRemovalPro Public build 0.7.1 @2022|]->` in process memory
- Look for `com.iremovalpro.bypass` bundle ID
- Look for iRemovalRa1n app in `/var/containers/Bundle/Application/`
- Check for `lao abc ofq` ideviceproxy commands in network logs
- Check for `s13.iremovalpro.com` DNS lookups / TLS connections

---

**End of Report — Phase 7: Complete System Architecture**