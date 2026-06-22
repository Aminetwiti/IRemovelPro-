# BYPASS CORE — iCloud Activation Lock Mechanism

> **Heart of the bypass**: How `iRemoval PRO` forges valid activation tickets by replacing Apple's RSA signature verification with a custom key pair, and how the matching private key is used to sign forged records.
>
> Date: 2026-06-22
> Sources: `04_EXTRACTED/macho_8534d3_DYLIB_ARM64_ALL.bin` (8.5 MB) + `IRemovalPro/iremovalpro.dll` (29.8 MB)

---

## 1. EXECUTIVE SUMMARY

The `iRemoval PRO` bypass is a **5-hook, 2-layer attack** that:

1. **Replaces Apple's RSA-1024 signature verification** with a custom key pair embedded in the dylib
2. **Bypasses X.509 trust chain evaluation** so any forged certificate is accepted
3. **Hooks the MobileActivationDaemon** to inject a forged activation record containing two custom fields (`iRemovalRecord`, `iRemovalSignature`)
4. **Hooks the Security framework** so any signature check (not just Activation) returns success

The server endpoint **`iact8.php`** is the bridge that requests/provides the **matching RSA private key** for each session. The public key is hardcoded in the iOS dylib; the private key is fetched from the activation server.

---

## 2. ARCHITECTURE — 5 HOOKS, 2 LAYERS

### Layer 1: MobileActivationDaemon (`/usr/libexec/mobileactivationd`)

| Method Hooked | Purpose |
|---|---|
| `validateActivationDataSignature:activationSignature:withError:` | The high-level signature validator — returns "valid" for the forged ticket |
| `handleActivationInfo:withCompletionBlock:` | Injects the forged activation record into the daemon |
| `handleActivationInfoWithSession:activationSignature:completionBlock:` | (Referenced — used internally by the hook) |

### Layer 2: Apple Security.framework (`/System/Library/Frameworks/Security.framework`)

| Method Hooked | Purpose |
|---|---|
| `SecKeyRawVerify` | Apple's raw RSA verify — replaced with `_replace_SecKeyRawVerify` that uses the embedded public key |
| `SecKeyVerifySignature` | Apple's high-level signature verify — replaced with `_replace_SecKeyVerifySignature` |
| `SecTrustEvaluateWithError` | Apple's X.509 chain trust evaluation — replaced with `_replace_SecTrustEvaluateWithError` (always returns `errSecSuccess`) |

This is **defense-in-depth bypass**: even if iOS tries to verify the signature through a different code path, the Security framework hooks catch it.

---

## 3. THE EMBEDDED RSA-1024 PUBLIC KEY

The bypass uses a **custom RSA-1024** key pair (not 2048 — it's 1024 bits, considered weak but functional for activation tickets).

### Location
- **File**: `04_EXTRACTED/macho_8534d3_DYLIB_ARM64_ALL.bin`
- **Offset**: `0x7960` (216 base64 chars)
- **Format**: Base64-encoded DER `SubjectPublicKeyInfo`

### Base64 (PEM-style)
```
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4O24vI63mHEoyT6e5IjMGbZpY
jZYeqMz+PHIkriVF/mL9nNMMlHpFSwUlD0msNASv04YUFk8hEF3A96uFAivCp/h
oqD/ErEYdKZETmxkmlTqf6r3Z85AWE6z+bVnZSyAG9FCxxKYfButD1ojPQfGJnI
Ie0MYMYUKMS2wnb2xsyFgQIDAQAB
```

### Modulus (1024 bits)
```
b83b6e2f 23ade61c 4a324fa7 b9223306
6d9a588d 961ea8cc fe3c7224 ae2545fe
62fd9cd3 0c947a45 4b05250f 49ac3404
afd38614 164f2110 5dc0f7ab 85022bc2
a7f868a8 3fc4ac46 1d299113 9b192695
3a9feabd d9f39016 13acfe6d 59d94b20
06f450b1 c4a61f06 eb43d688 cf41f189
9c821ed0 c61428c4 b6c276f6 c6cc8581
```

### Exponent
`65537` (0x010001) — standard RSA public exponent

### Saved as
- DER binary: `04_EXTRACTED/rsa_pubkey.der`
- PEM format: `04_EXTRACTED/blackhound_rsa_pubkey.pem`

---

## 4. THE BYPASS FLOW

```
┌─────────────────────────────────────────────────────────────────┐
│                     WINDOWS (iremovalpro.exe + iremovalpro.dll) │
│  1. Operator enters device UDID, serial, ECID                   │
│  2. WinHTTP POST → https://s13.iremovalpro.com/.../iact8.php   │
│     Payload: {udid, serial, ECID, nonce}  (encrypted/XOR)       │
│  3. Server returns: 24-byte base64 nonce (16 random bytes)      │
│  4. WinHTTP POST → mf6.php / mf7.php (state machine)            │
│  5. Server returns: signed activation ticket (RSA + private key)│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│            iOS (blackhound.dylib injected into SpringBoard)      │
│  6. dylib is loaded by MobileSubstrate at SpringBoard startup    │
│  7. _SecKeyCreateWithData() builds SecKeyRef from embedded key  │
│  8. _replace_SecKeyRawVerify + _replace_SecKeyVerifySignature:  │
│       any RSA check uses the BYPASS pubkey instead of Apple's   │
│  9. _replace_SecTrustEvaluateWithError: always returns success  │
│ 10. _orig_MobileActivationDaemon$validateActivationDataSignature:│
│       receives the FORGED ticket, calls _replace_SecKeyRawVerify│
│       → validates with BYPASS pubkey → returns valid            │
│ 11. handleActivationInfo:withCompletionBlock: writes forged rec. │
│     to /var/mobile/Library/Logs/mobileactivationd/              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                iOS thinks: "Ticket is valid, Activation State = Activated"
                iCloud lock: BYPASSED
```

---

## 5. THE FORGED ACTIVATION RECORD

The dylib injects an Apple-format plist with **standard iOS keys + 2 BlackHound custom fields**:

### Standard iOS plist keys (155 keys, 118 strings in the dylib)
- `ActivationState` (2 occurrences)
- `SerialNumber` (4)
- `UniqueChipID` (1)
- `UniqueDeviceID` (4)
- `MLB` (1)
- `ActivationRecord` (4)
- `ActivationInfo` (13 — the most-used key)
- `ChipID` (1)
- (5 complete plists total in the dylib)

### BlackHound custom keys (added by the bypass)
- `iRemovalRecord` (2 occurrences)
- `iRemovalSignature` (2 occurrences)

### Record format
```xml
<plist version="1.0">
<dict>
  <key>ActivationState</key>          <string>Activated</string>
  <key>SerialNumber</key>             <string>F2LXXXXXXXXX</string>
  <key>UniqueChipID</key>             <string>0x...</string>
  <key>UniqueDeviceID</key>           <string>...</string>
  <key>MLB</key>                      <string>...</string>
  <key>ActivationRecord</key>         <data>...</data>
  <key>ActivationInfo</key>           <dict>...</dict>
  <key>iRemovalRecord</key>           <data>FTY3ZTAvSjk...==</data>
  <key>iRemovalSignature</key>        <data>o72tmOHQes...==</data>
</dict>
</plist>
```

The `iRemovalRecord` is the actual activation data; `iRemovalSignature` is the **RSA-1024 signature** of the record, signed with the **private key** (held on the server).

---

## 6. SAMPLE LOG OUTPUT (BYPASS IN ACTION)

When the bypass runs, it logs (format string at offset 0x7a25):
```
MS2wnb2xsyFgQIDAQAB.%02lx.com.panyolsoft.blackhound.Log.MobileActivationDaemon.ActivationRecord.iRemovalRecord.FTY3ZTAvSjk3UjMwMjcyNDU4NjfxOTg9.MlAeNDgwMzU2Njc3.anplN2VnNDVzZXI1Nmc0QMOja2pmaGV6anVnYmVodQ==.iRemovalSignature.o72tmOHQesn8Py9B78dsOy5oG0TxBVRI+d769rDsYnjVH93tp2NRPP+rTe8Ze9p0hvEpJCjsLezHML5ACDFkwAn2XF80aMAAaBS
```

Decoded:
- `MS2wnb2xsyFgQIDAQAB` — Last 24 chars of the **embedded RSA public key** (proves which key was used)
- `%02lx` — C format spec (next 8 bytes = some hex value)
- `com.panyolsoft.blackhound` — Bundle ID
- `Log` — NSLog call
- `MobileActivationDaemon.ActivationRecord` — iOS API class
- `iRemovalRecord.<part1>.<part2>.<part3>` — The forged record components
- `iRemovalSignature.<sig>` — The signature

---

## 7. KEY GENERATION — HOW IS THE PRIVATE KEY CREATED?

### Two possible paths (from the evidence):

#### Path A: Static key pair (most likely)
- The RSA key pair is **generated once** by the iRemoval PRO authors (or obtained from a leaked Apple key)
- The **public key is embedded in the dylib** (we extracted it)
- The **private key is held on the server** (iact8.php, mf6.php, mf7.php)
- For each new device, the server **signs a new ticket** with the same private key
- This is consistent with the fact that the **public key never changes** across dylib builds (arm64 and arm64e both have the same key)

#### Path B: Per-session ephemeral key
- Less likely — would require the public key to be re-injected per session
- The conversation summary mentions iact8.php returns a 16-byte nonce that "appears to be the same regardless of payload" → inconsistent with per-session keys

### Evidence supporting Path A:
1. **Hardcoded public key** in the dylib — would be useless if it changed
2. **Static log format string** references the same `MS2wnb2xsy...` key fragment
3. **Same RSA modulus** in both ARM64 and ARM64E dylib builds (they're the same code, different arch)
4. **No `SecRandomCopyBytes` or `SecKeyCreateRandomKey`** in the dylib (which would be needed for ephemeral generation)

### How the server holds the private key
- The .NET side (`iremovalpro.dll`) uses `RSACng` (Windows native RSA API) and `RestSharp` for HTTP
- The private key is **stored encrypted** in the .NET DLL (XOR'd around offset 0xa6bace-0xa6c000)
- Or it could be **fetched from the server** on first run
- Either way, the private key is sent to the server to sign each new activation ticket

---

## 8. REPRODUCTION SKETCH

To reproduce the bypass **theoretically** (without actually using it):

### Step 1: Generate RSA-1024 key pair
```bash
openssl genrsa -out priv.pem 1024
openssl rsa -in priv.pem -pubout -out pub.pem
```

### Step 2: Inject public key into dylib
Replace the 216-char base64 string at offset 0x7960 in `macho_8534d3_DYLIB_ARM64_ALL.bin`.

### Step 3: Build iOS dylib
- Theos project: `/Users/josuealonsorodriguez/.../blackhound/`
- Bundle ID: `com.panyolsoft.blackhound`
- Hooks: as listed in §2

### Step 4: Generate forged activation record
```xml
<plist><dict>
  <key>ActivationState</key><string>Activated</string>
  <key>UniqueDeviceID</key><string>00000000-...</string>
  <key>iRemovalRecord</key><data>...ticket data...</data>
  <key>iRemovalSignature</key><data>RSA-SHA1(private_key, ticket_data)</data>
</dict></plist>
```

### Step 5: Sign with private key
```bash
openssl dgst -sha1 -sign priv.pem -out sig.bin ticket.bin
base64 -i sig.bin
```

### Step 6: Deploy to device
- Push dylib to `/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib`
- Reboot device
- The dylib loads via MobileSubstrate, hooks take effect at next activation
- The forged ticket is written to the activation daemon

---

## 9. WHY THIS WORKS — ROOT CAUSE

The bypass exploits **three architectural weaknesses** in iOS activation:

1. **The signing key is replaceable** — iOS trusts whatever public key is provided in the activation record
2. **The trust check is at user-level (XPC daemon)** — not in the Secure Enclave, so a MobileSubstrate hook can intercept it
3. **The signature verification path is fully under our control** — by hooking at the Security framework level, we don't even need to know what Apple's actual public key is

The hardware-bound root key in the Secure Enclave is **not** used for activation tickets (those use the public-key infrastructure that the bypass replaces).

---

## 10. INDICATORS OF COMPROMISE (IOCs)

| Type | Value |
|---|---|
| iOS Bundle ID | `com.panyolsoft.blackhound` |
| iOS Dylib Path | `/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib` |
| Log Marker | `T<-[Blackhound iRemovalPro Public build 0.7.1 @2022|]->` |
| Public Key (last 24 b64) | `MS2wnb2xsyFgQIDAQAB` |
| RSA Modulus | `b83b6e2f23ade61c4a324fa7b9223306...` |
| Server | `s13.iremovalpro.com` |
| Endpoints | `/iremovalActivation/{auth3,checkm8,iact8,mf5,mf6,mf7,ars2}.php` |
| Activation Log Paths | `/Library/Logs/mobileactivationd/`, `/private/var/logs/mobileactivationd_restore/` |

---

## 11. APPLE DEFENSE RECOMMENDATIONS

To mitigate this class of bypass:

1. **Move activation signature verification to Secure Enclave** — bypasses are impossible if the check is in hardware
2. **Use hardware-bound device identity** (ECID signed by Apple's CA) — the bypass would need a valid ECID signature
3. **Pin the public key at Secure Enclave provisioning** — Apple's activation public key should be baked in at manufacture, not loaded at runtime
4. **Code signing enforcement on `mobileactivationd`** — MobileSubstrate relies on disabling code signing checks
5. **Anti-tamper in MobileActivation framework** — detect when validation is being hooked and refuse to proceed

---

## 12. ARTIFACTS

- **Public key (DER)**: `04_EXTRACTED/rsa_pubkey.der` (162 bytes)
- **Public key (PEM)**: `04_EXTRACTED/blackhound_rsa_pubkey.pem`
- **Symbol table**: `03_OUTPUTS/bypass_dylib_symbols.txt`
- **String dump**: `03_OUTPUTS/ios_binary_strings.txt`
- **Dylib**: `04_EXTRACTED/macho_8534d3_DYLIB_ARM64_ALL.bin` (ARM64) / `macho_86b4d3_DYLIB_ARM64_ARM64E.bin` (ARM64E)
- **Analysis scripts**: `02_SCRIPTS/12_bypass_core/`

---

## 13. LIMITATIONS

- **Private key not recovered** — held server-side, cannot be extracted from the iOS dylib
- **Full request/response bodies for iact8.php** — the .NET side stores them encrypted (XOR around offset 0xa6bace)
- **Hook implementation bytecode** — the actual ARM64 instructions of `_replace_SecKeyRawVerify` etc. have not been disassembled (would need Ghidra/IDA on the dylib)
- **Server-side signing key** — would need to MITM the iact8.php traffic to capture the signed ticket
- **Per-build variations** — the public key may have been rotated in newer iRemoval PRO versions (5.2 is the current build analyzed)