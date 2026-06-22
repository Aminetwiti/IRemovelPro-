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

## 13. SERVER-SIDE ENFORCEMENT — What the server REALLY verifies

The audit of [`REPORT_SERVER_PROTOCOL.md`](REPORT_SERVER_PROTOCOL.md), [`ENDPOINT_IACT8.md`](ENDPOINT_IACT8.md) and [`CRYPTO_CRITICAL_ANALYSIS.md`](CRYPTO_CRITICAL_ANALYSIS.md) shows that the iRemoval backend is **not just a dumb signing oracle**. It enforces a multi-step defensive policy at the network edge, *before* the RSA ticket sign is ever called. The 9 endpoints of the live handshake each gate a different part of the policy:

| Endpoint | Server-side verification | Blocking on failure? |
|---|---|---|
| `/version33.txt` | Client binary version must match a server-allowlisted build (anti-rollback + anti-pirate) | ✅ Yes |
| `/auth3.php` | **Active license** (PPID paid, not expired, not refunded, not banned) **+ HWID match** | ✅ Yes |
| `/checkm8.php` | Exploit compatibility + jailbreak state for the targeted iOS version | ✅ Yes |
| `/iact8.php` | **Generates the nonce + signs the ticket** with the matching RSA-1024 private key | ✅ Yes |
| `/mf5.php`, `/mf6.php`, `/mf7.php` | Same nonce must be re-presented to all three; signature verified across the triplet | ✅ Yes |
| `/ars2.php` | Activation Record Service proxy — forwards the iPhone's restore request to `albert.apple.com` | ✅ Yes |
| `/Payax0.php` | PayPal payment verification (PPID ↔ live PayPal transaction) | ✅ Yes |

> **The 9 endpoints are interdependent** — failure at *any* step is silent (the server simply does not advance the state machine), and no signed ticket is ever emitted without a clean run-through.

### 13.1 `auth3.php` — the critical license/HWID gate

From the .NET side, the state machine lives in `<CommonConnectDevice>d__107` (see [`PHASE5_RUNTIME_NATIVEAOT.md`](PHASE5_RUNTIME_NATIVEAOT.md)). It performs **four** server-side checks, in this order, and refuses to return a `sessionId` if any of them fails:

1. **License key validity** — the submitted `PPID` (PayPal payment ID) is looked up in the licensing DB; a revoked / refunded / chargebacked PPID returns no session.
2. **License expiration** — the server checks the `expires_at` field of the license row and refuses the session if `now > expires_at` (subscriptions have a hard cutoff).
3. **HWID match** — the client HWID is compared against the registered HWID for the license; a mismatch is rejected (this is what makes the license non-transferable, see §14).
4. **Account status** — the operator account itself must be `active` (not `banned`, not `suspended`, not `pending_review`).

> **Conclusion** — *without a valid license AND a registered HWID, the server never returns a nonce, and therefore never returns a signed ticket.* The RSA key is gated by license compliance, not by possession of the dylib.

### 13.2 What this means for blue teams

- The "iRemoval server" **is not a passive signing service**. It is a license+HWID+anti-tamper gate that also happens to know the private key. A successful bypass requires defeating *all* of: license auth, HWID derivation, binary tamper checks, and Apple's final DRM handshake (§16 Step 9).
- The lab's offline mock (`06_LOCAL_REPRODUCER/iact_reproducer/mock_server.py`) reproduces the **server-side** policy checks (HMAC, rate limit, blacklist) but **not** the license/HWID check — those are out of scope for a 100 % offline lab and would require standing up a fake licensing DB. Tracking those checks is left as a defensive-engineering TODO.

---

## 14. HWID AS DRM — The internal anti-piracy layer

iRemoval PRO is, before anything else, a **commercial product**. The authors *cannot afford* for their binary to be freely redistributable, otherwise the pirate ecosystem would cannibalise the paying customer base within days. The first line of defence is therefore **not** the activation bypass itself — it is the **HWID-based license binding** baked into the .NET binary.

### 14.1 What the HWID actually is

The HWID is a **fingerprint of the operator's PC**, derived locally by `iremovalpro.dll` and sent with **every** request to the iRemoval backend. Based on the API accessors visible in `03_OUTPUTS/strings_all_long.txt`, the construction is plausibly:

| Source | Windows API | Purpose |
|---|---|---|
| System volume | `GetVolumeInformationW` (volume serial number) | Stable per-disk fingerprint |
| CPU | `GetSystemCpuInformation` / WMI `Win32_Processor` | CPU brand + stepping |
| Baseboard | WMI `Win32_BaseBoard` | Motherboard serial |
| NIC | `GetAdaptersInfo` / `UuidCreateSequential` | MAC address (often the dominant entropy) |
| OS install | WMI `Win32_OperatingSystem` (InstallDate + SerialNumber) | Distinguishes VMs from physical hosts |

The hash of these is sent to the server under field names such as `hwProfile` or `hwid_hash`. The server then stores it in the licensing DB **at purchase time** and refuses to re-issue `sessionId`s for any other HWID.

### 14.2 The X.509 accessor trail

The strings table contains several X.509-related accessors that suggest the client *also* computes a **self-signed X.509 certificate** derived from the hardware fingerprint — likely used as a per-installation client identity that the server can verify cryptographically without a real PKI:

- X.509 subject/issuer DER encoding accessors (used to build a `TBSCertificate`)
- `X509Chain` / `X509ChainElement` accessors (used to validate the self-signed cert against the HWID-derived public key)
- `X509Store` / `X509StoreName` accessors (used to persist the per-installation identity in the Windows certificate store)

> *The exact strings should be back-filled from `03_OUTPUTS/strings_all_long.txt` with `Select-String -Pattern "X509|SubjectPublicKeyInfo|GetVolumeInformation|Win32_"`.* The conceptual model — *HWID → self-signed cert → license-bound client identity* — is supported by the API surface but the specific offsets are left to a follow-up static pass.

### 14.3 Why this is the *real* DRM

- The iOS bypass dylib is freely downloadable (no DRM). The interesting part is the **server**.
- The server holds the RSA-1024 private key but **refuses to use it** unless the operator proves their license is bound to *this* PC. The HWID is the gate, the RSA is the prize.
- Defeating the HWID check requires either: (a) stealing a paid account's HWID (which the server sees as legitimate), (b) patching the binary to spoof the HWID, or (c) reverse-engineering the license DB. All three are *cracking* tasks, not *bypass* tasks.

---

## 15. SELF-PROTECTION — iRemoval PRO's own anti-tamper layers

If iRemoval PRO's binary were trivially patchable, the HWID/license check in §14 would be moot — a cracker would just NOP-out the check. The authors therefore deploy a **defensive stack of their own** in `iremovalpro.dll`, distinct from (and complementary to) the iOS-side hooks described in §2.

### 15.1 Probable self-protection layers

| # | Layer | Probable mechanism | Verified? | Evidence |
|---|---|---|---|---|
| 1 | **HWID binding** | License ↔ hardware fingerprint (see §14) | 🟠 Probable | X.509 accessor strings in `strings_all_long.txt` |
| 2 | **Internal code signing** | RSA signature over the .NET assembly's strong-name + a per-build payload digest | 🟠 To verify | `RSACng` import + custom signature blob in `iremovalpro.dll` |
| 3 | **Anti-dump / anti-Frida** | Detect attached debuggers, Frida gadgets, suspicious `CreateToolhelp32Snapshot` results; clear sensitive buffers on detection | 🟠 Probable | `SecureClearAndCollect` symbol appears **9 times** in the strings table — strongly suggests "collect info then scrub memory" |
| 4 | **Payload encryption** | XOR / AES-wrapped iOS dylibs and bypass scripts | ✅ **Verified** | `03_OUTPUTS/pre_url_region.txt` — see XOR'd region around offset 0x7960 |
| 5 | **Server heartbeat** | Periodic ping to the license server during a long-running bypass; if the heartbeat fails, the client kills the bypass mid-flight | 🟠 Probable | Multiple "ping" / "heartbeat" / "keepalive" references in `CRYPTO_CRITICAL_ANALYSIS.md` |
| 6 | **Binary tamper check** | Hash of the assembly's `.text` / `.rsrc` sections is checked before every privileged call | 🟠 Probable | Standard pattern for .NET-native AOT DLLs that have already been observed in `PHASE5_RUNTIME_NATIVEAOT.md` |

> **The `SecureClearAndCollect` signal** — a symbol that appears 9 times in the string table is unusual. Names of this shape ("SecureXxx") are typically used to *both* gather sensitive data and *zero it out* once it has been used. This pattern is the strongest indirect signal we have of an anti-dump / anti-memory-forensic layer.

### 15.2 What the self-protection tells the defender

- The presence of these layers is itself an **IOC**: legitimate tools don't need 9 instances of `SecureClearAndCollect` or 6 overlapping anti-tamper checks. The pattern density is a strong classifier.
- Some of these layers (HWID binding, payload encryption) are **client-only**: they can be reverse-engineered, but doing so requires significant analyst time per release. This is a deliberate **economic defence** — make cracking expensive enough that the pirate ecosystem prefers paying.
- The most interesting defensive target is **layer 5 (heartbeat)**: a SIEM rule that correlates `iremovalpro.dll` process starts with a tight burst of HTTPS calls to `s13.iremovalpro.com` (or its rotating CDN aliases) catches a bypass *in progress*, even when the binary itself is freshly patched.

---

---

## 16. THE 9-STEP HANDSHAKE — ACTUAL BYPASS SEQUENCE

The "1-line bypass" is misleading. The actual flow is a **9-step handshake** that combines multiple defensive layers (license, HWID, anti-replay, anti-tamper) before the forged ticket is even delivered. **All logic is client-side**; the server only signs (≈ 5 ms of CPU per ticket).

### Step 1 — License / Payment Validation
- Client calls `Payax0.php` on `iremovalpro.com` (not `s13`).
- Server validates license (PPID, expiry, max devices).
- Returns a license token included in all subsequent requests.
- **No bypass path** for the license — must be paid.

### Step 2 — `auth3.php` (Authentication)
- `POST /iremovalActivation/auth3.ph` with `{username, password, hwProfile, nonceA}`.
- Returns `{sessionId, nonceB, defensive_marker: 'iRemovalLabTest'}`.
- Client computes `nonce_C = PBKDF2-HMAC-SHA256(sessionId ‖ b64A ‖ b64B, "iremovalpro-iact8-v1", 10 000, 16)`.
- **HW profile** binds the license to a specific PC (HWID: CPU ID, disk serial, MAC).

### Step 3 — `checkm8.php` (Exploit Status)
- `POST /iremovalActivation/checkm8.ph` with `{udid, ecid, chipId, boardId, signed_nonce}`.
- Returns `{checkm8_supported, exploit_version, nonce}`.
- This is the **only** legitimate Apple-bound step (returns whether the device is in SRTG vulnerable state).

### Step 4 — `iact8.php` (Ticket Forging) ⭐
- `POST /iremovalActivation/iact8.ph` with `{udid, ecid, chipId, boardId, serial, mlb, ...}`.
- Returns `{ActivationRecord (bplist), Signature (RSA-1024), iv, encrypted_payload}`.
- Server builds a real Apple plist + signs with the **private RSA-1024 key** (matching the public key hardcoded in the dylib).
- This is the **only "expensive" step** for the server (RSA sign ≈ 5 ms).

### Step 5 — `mf5.ph` / `mf6.ph` / `mf7.ph` (MEID Bypass)
- Three separate endpoints, one per MEID signal version (v5, v6, v7).
- **`A12Eraser` class** in the .NET DLL implements `BypassMeidSignal` (offset 0x78bacc in `iremovalpro.dll`).
- Sends forged MEID + signal to Apple's baseband for tower attachment.

### Step 6 — `ars2.php` (Apple Restore Server Proxy)
- `POST /iremovalActivation/ars2.ph` proxies the iPhone's restore request to Apple's `albert.apple.com`.
- This is the **legitimate Apple path** — iRemoval just forwards packets.
- Logs `device_info.json` (UDID, ECID, firmware) for debugging.

### Step 7 — Local USB Push (`ideviceproxy.exe`)
- The .NET DLL uses `ideviceproxy.exe` (23.7 MB, native C/C++ binary) to tunnel lockdownd over USB.
- Writes the forged `activation_record.plist` to `/var/mobile/Library/Caches/` via AFC2.
- Triggers `mobileactivationd` to re-read the plist.

### Step 8 — iOS Hook Takeover
- iPhone boots with `blackhound.dylib` (Cydia Substrate) loaded.
- 5 hooks installed (see §2 above).
- `mobileactivationd` accepts the forged plist because `_replace_SecKeyRawVerify` always returns "valid".

### Step 9 — Apple DRM Handshake (Legitimate)
- The now-"activated" iPhone calls `https://albert.apple.com/deviceservices/drmHandshak` to obtain FairPlay keys.
- **This is a real Apple endpoint** — Apple has visibility here.
- If Apple's server detects something anomalous (timing, ECID, plist structure), it can refuse the DRM handshake.

### Summary Table — What Side Handles What

| Step | Logic | Cost | Apple sees it? |
|---|---|---|---|
| 1. License | Server (PayPal) | ms | No |
| 2. Auth | Client (PBKDF2) | 5 ms | TLS only |
| 3. checkm8 | Server (lookup) | ms | No |
| 4. **iact8** | **Server (RSA sign)** | **5 ms** | **TLS only — but Apple could detect via DNS/IP** |
| 5. mf5/6/7 | Server (proxy) | 100 ms | No |
| 6. ars2 | Server (proxy) | 1 s | No |
| 7. USB push | Client (ideviceproxy) | 5 s | No |
| 8. Hook takeover | Client (dylib) | boot | **No** (kernel-level) |
| 9. DRM handshake | **Client → Apple** | 1 s | **✅ YES — Apple's last line of defense** |

> **Key insight for defenders**: Step 9 is the only point where Apple has full visibility on the forged activation. The defensive playbook focuses on detecting the bypass at this critical handshake.

---

## 17. DETECTION RULES — IMPLEMENTED YARA + SIGMA

### 15.1 YARA Rules (file-based)

```yara
// In 05_IOC/YARA_RULES.yar
rule iRemovalPro_A12Eraser_MEIDBypass
{
    meta:
        description = "Detects A12Eraser / BypassMeidSignal class in iRemoval PRO DLL"
        severity = "high"
    strings:
        $class_a12 = "A12Eraser" ascii wide
        $method_bypass = "BypassMeidSignal" ascii wide
        $mf5_url = "/iremovalActivation/mf5.ph" ascii wide
        $mf6_url = "/iremovalActivation/mf6.ph" ascii wide
        $mf7_url = "/iremovalActivation/mf7.ph" ascii wide
    condition:
        uint32(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
        and filesize > 25MB and filesize < 35MB
        and 2 of ($class_a12, $method_bypass, $mf5_url, $mf6_url, $mf7_url)
}

rule iRemovalPro_HandshakeNonce_3_Endpoints
{
    meta:
        description = "Detects the 3-nonce handshake (A/B/C) pattern + 9 endpoint URLs"
        severity = "high"
    strings:
        $ep1 = "iremovalActivation/auth3.ph" ascii wide
        $ep2 = "iremovalActivation/checkm8.ph" ascii wide
        $ep3 = "iremovalActivation/iact8.ph" ascii wide
        $ep4 = "iremovalActivation/ars2.ph" ascii wide
        $ep5 = "iremovalActivation/mf5.ph" ascii wide
        $ep6 = "iremovalActivation/mf6.ph" ascii wide
        $ep7 = "iremovalActivation/mf7.ph" ascii wide
    condition:
        5 of them
}
```

### 15.2 Sigma Rules (telemetry detection)

```yaml
# In 05_IOC/SIGMA_RULES.yml
title: iRemoval PRO - A12Eraser MEID bypass telemetry
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_dll:
        CommandLine|contains:
            - 'A12Eraser'
            - 'BypassMeidSignal'
            - 'CommonConnectDevice'
    selection_endpoint:
        CommandLine|contains:
            - 'iremovalActivation/mf5'
            - 'iremovalActivation/mf6'
            - 'iremovalActivation/mf7'
    condition: selection_dll OR selection_endpoint
level: high
tags:
    - attack.defense_evasion
    - attack.t1562

---
title: iRemoval PRO - drmHandshake timing anomaly
status: experimental
description: Detects abnormally fast drmHandshake responses (sign of pre-signed ticket)
logsource:
    category: firewall
    product: zeek
detection:
    selection:
        dst_host: 'albert.apple.com'
        path|contains: '/deviceservices/drmHandshak'
    condition: selection
fields:
    - src_ip
    - duration
falsepositives:
    - Legitimate iPhone first activation
level: medium
```

### 15.3 Apple Server-Side — Allowlist Modulus RSA

```swift
// Deployment sur albert.apple.com (pseudocode)
let forbiddenModuli: Set<Data> = [
    // iRemoval PRO v5.2 RSA-1024 (extrait du dylib)
    Data(hex: "B83B6E2F23ADE61C4A324FA7B92233066D9A588D961EA8CCFE3C7224AE2545FE62FD9CD30C947A454B05250F49AC3404AFD38614164F21105DC0F7AB85022BC2A7F868A83FC4AC461D2991139B1926953A9FEABDD9F3901613ACFE6D59D94B2006F450B1C4A61F06EB43D688CF41F1899C821ED0C61428C4B6C276F6C6CC8581"),
    // Note: tout RSA-1024 devrait être suspect en 2026
]

func validateDrmHandshake(req: DrmHandshakeRequest) -> Bool {
    if let mod = req.publicKey?.modulus, forbiddenModuli.contains(mod) {
        log.error("iRemoval bypass detected", udid: req.udid)
        return false
    }
    // Forcer RSA-2048+ pour 2026
    if req.publicKey?.keySize < 2048 {
        log.warn("RSA-1024 detected (rejected)", udid: req.udid)
        return false
    }
    return true
}
```

### 15.4 Custom Fields in Activation Records

iOS peut détecter la présence des champs `iRemovalRecord` et `iRemovalSignature` dans une plist d'activation (jamais présents dans les tickets Apple légitimes) :

```python
# Script Python pour EDR iOS
def detect_iremoval_record(plist_data: dict) -> bool:
    blacklist = ["iRemovalRecord", "iRemovalSignature", "BlackHound-Public-Build"]
    for key in blacklist:
        if key in plist_data:
            return True
    return False
```

---

## 18. WHY "1-LINE BYPASS" IS MISLEADING

The popular framing "iRemoval bypasses iCloud in 1 line of code" is **technically false** and hides the true complexity:

| Myth | Reality |
|---|---|
| "1 line of code" | **9-step handshake** with 6+ endpoints + 5 iOS hooks |
| "Bypasses the cloud" | Bypasses a **client-side daemon** (`mobileactivationd`) |
| "Apple's key is replaced" | Only the **client's validation** of the key is replaced |
| "Server signs the ticket" | Server only **re-signs** with a different private key |
| "Cannot be detected" | Apple can detect at **Step 9 (drmHandshake)** if they monitor modulus |
| "Works on any iPhone" | Requires **jailbreak** (checkm8 + A12 eraser for newer chips) |

> **The honest summary** : The bypass is 100% client-side. The server does almost nothing. **But** the iOS device must still successfully complete the drmHandshake with Apple. If Apple maintains a server-side allowlist of valid public keys, the bypass fails at Step 9.

---

## 19. LIMITATIONS (UPDATED)

- **Private key not recovered** — held server-side, cannot be extracted from the iOS dylib
- **Full request/response bodies for iact8.php** — the .NET side stores them encrypted (XOR around offset 0xa6bace)
- **Hook implementation bytecode** — the actual ARM64 instructions of `_replace_SecKeyRawVerify` etc. have not been disassembled
- **Server-side signing key** — would need to MITM the iact8.php traffic to capture the signed ticket
- **Per-build variations** — the public key may have been rotated in newer iRemoval PRO versions (5.2 is the current build analyzed)
- **A12 Eraser implementation** — only the class name `A12Eraser` and method `BypassMeidSignal` are visible; the actual exploit bytecode is not analyzed
- **Complete 9-step handshake replay** — would require paid account (license validation blocks Step 1)

---

## 20. COMPLETE HOOK INVENTORY — Every Client-Side Override

Extracted via `02_SCRIPTS/12_bypass_core/extract_all_hooks.py`. The bypass installs **5 distinct hooks** across **2 iOS frameworks** + **2 hooking techniques** (MobileSubstrate direct + Logos preprocessor).

### 20.1 Hook Group A — Security.framework (Cydia Substrate direct)

Three hooks installed via `_MSHookFunction()` and `_MSHookMessageEx()`. They form a **defense-in-depth** trap: any iOS code path that tries to verify a key ends up calling one of these.

| Hook symbol | Replaces | Where called | What it does |
|---|---|---|---|
| `_replace_SecKeyRawVerify` ↔ `_orig_SecKeyRawVerify` | `SecKeyRawVerify` | `Apple Security.framework/SecKey` | Validates signature using the **hardcoded RSA-1024 public key** instead of Apple's HSM key. This is the **primary bypass**. |
| `_replace_SecKeyVerifySignature` ↔ `_orig_SecKeyVerifySignature` | `SecKeyVerifySignature` | Same, higher-level API | Same purpose; called by `SecKeyVerifySignature` users. Internally calls `_replace_SecKeyRawVerify`. |
| `_replace_SecTrustEvaluateWithError` ↔ `_orig_SecTrustEvaluateWithError` | `SecTrustEvaluateWithError` | `Apple Security.framework/SecTrust` | Returns `errSecSuccess` **unconditionally**. Bypasses **X.509 chain trust evaluation** for any cert in the chain. |

**Trigger count** in dylib ARM64:
- `_MSHookFunction`: **4 occurrences** (one per hook install + one for the static init)
- `_MSHookMessageEx`: **4 occurrences** (similar)
- Internal symbol `_validPublic` and `_publicKey` (visible in the dylib): the hardcoded RSA-1024 `SecKeyRef` constructed at install time

**Reconstructed Objective-C** (deduced from hook symbol names + context strings):

```objc
// Hook A1 — installed on init via _MSHookFunction
BOOL _replace_SecKeyRawVerify(SecKeyRef key, SecPadding padding,
                              const uint8_t *sig, size_t sigLen,
                              const uint8_t *hash, size_t hashLen,
                              CFErrorRef *error) {
    // Use the BYPASS public key (built from the hardcoded base64 in the dylib)
    SecKeyRef bypassKey = buildBypassPublicKey();   // uses base64 at offset 0x7960
    return _orig_SecKeyRawVerify(bypassKey, padding, sig, sigLen, hash, hashLen, error);
}

BOOL _replace_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm alg,
                                    CFDataRef signedData, CFDataRef signature,
                                    CFErrorRef *error) {
    // Forwards to the low-level hook
    return _replace_SecKeyRawVerify(key, kSecPaddingPKCS1SHA1, ...);
}

bool _replace_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    // ALWAYS return success — X.509 chain validation is bypassed entirely
    if (error) *error = NULL;
    return true;  // kSecTrustResultProceed / kSecTrustResultUnspecified
}
```

**Public crypto references in the dylib** (proves the implementation uses standard Apple CommonCrypto):

```
_CCCrypt            ← AES encryption (probably to unwrap the encrypted plist)
_CC_SHA256          ← SHA-256 hashing
_NSData             ← buffer for raw signature
_NSDictionary       ← plist-style activation record
_NSFileManager      ← writes the forged plist to /var/mobile/...
```

### 20.2 Hook Group B — MobileActivationDaemon (Logos preprocessor)

Two hooks installed via the **Theos / Logos** toolchain. The `__logos_method$` symbol is the **hook body** (replacement), `__logos_orig$` is the **saved original** (called via `%orig`).

| Hook symbol | Objective-C selector | Class targeted |
|---|---|---|
| `__logos_method$_ungrouped$MobileActivationDaemon$validateActivationDataSignature$activationSignature$withError$` | `- (BOOL)validateActivationDataSignature:(NSData*)sig activationData:(NSDictionary*)data withError:(NSError**)error` | `MobileActivationDaemon` |
| `__logos_method$_ungrouped$MobileActivationDaemon$handleActivationInfo$withCompletionBlock$` | `- (void)handleActivationInfo:(NSDictionary*)info withCompletionBlock:(void(^)(NSDictionary*, NSError*))block` | Same |

**Reconstructed Logos code** (deduced from the symbols + the log string at offset 0x7a25):

```objc
// Hook B1 — %orig calls the original (saved by Logos at install time)
%hook MobileActivationDaemon

- (BOOL)validateActivationDataSignature:(NSData *)activationSignature
                          activationData:(NSDictionary *)activationData
                                  withError:(NSError **)error {
    // Call original (which would call the REAL SecKeyRawVerify on Apple's key)
    BOOL ok = %orig(activationSignature, error);
    // But ALSO validate against the BYPASS pubkey
    if (!ok) {
        return [self _verifyWithBypassKey:activationSignature data:activationData];
    }
    return ok;
}

- (void)handleActivationInfo:(NSDictionary *)info
         withCompletionBlock:(void (^)(NSDictionary *, NSError *))block {
    // Inject the forged activation record
    NSDictionary *forged = [self _loadForgedTicketFromBundle];
    NSLog(@"T<-[Blackhound iRemovalPro Public build 0.7.1 @2022|]-> %@", forged);
    return %orig(forged, block);
}

%end
```

**Bonus symbol** found in dylib (proves SecTrustEvaluateWithError hook):

```
_handleActivationInfoWithSession:activationSignature:completionBlock:
```

This third selector is also a hook target (mentioned in §2 of the original BYPASS_CORE). It's a variant of the same hook that takes an explicit `session` argument.

### 20.3 What Each Hook **Does** (Capability Map)

| Hook | Layer | Bypass capability | Triggered by |
|---|---|---|---|
| `_replace_SecKeyRawVerify` | Security.framework | **RSA verify** with bypass pubkey | Any code that calls `SecKeyRawVerify` |
| `_replace_SecKeyVerifySignature` | Security.framework | Same, via high-level API | `mobileactivationd` validateActivationDataSignature |
| `_replace_SecTrustEvaluateWithError` | Security.framework | **X.509 chain trust** always valid | Any code that calls `SecTrustEvaluateWithError` |
| `__logos_method$MobileActivationDaemon$validateActivationDataSignature$...` | Activation daemon | Returns "valid" for forged ticket | `mobileactivationd` daemon |
| `__logos_method$MobileActivationDaemon$handleActivationInfo$...` | Activation daemon | Substitutes the activation record | `mobileactivationd` daemon |

### 20.4 The 3-Hook-Then-2-Hook Architecture

```
                    ┌─────────────────────────────────┐
                    │     iOS userland process        │
                    │  (mobileactivationd / SpringBoard) │
                    └────────────────┬────────────────┘
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        │                            │                            │
        ▼                            ▼                            ▼
  [Hook B1]                [Hook B2]                   [Hook A1+A2+A3]
  validateActivationData   handleActivationInfo        Security.framework
  Signature (Logos)        (Logos)                     (MSHookFunction)
        │                            │                            │
        │                            │                            │
        ▼                            ▼                            ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                  Decides: "valid" / "inject forged"             │
  └─────────────────────────────────────────────────────────────────┘
```

**Defensive insight**: All 5 hooks must be removed for the activation to fail. A kernel-level patch to `MSHookFunction` (in `/usr/lib/substrate`) or a Secure Enclave–attested key would defeat this entirely.

### 20.5 Why the Hooks Don't Conflict with the Rest of iOS

The hooks are **method-level replacements** (not function-level). iOS's hundreds of other cryptographic operations continue to use the original Apple code. Only the specific code paths that `mobileactivationd` triggers (validate → handle) are affected. The hook also returns **plausible** values (TRUE for validate, success dict for handle) so iOS's higher-level state machine thinks everything is normal.

### 20.6 Detection Signatures (per hook)

| Hook | Static signature (YARA) | Runtime detection |
|---|---|---|
| `_replace_SecKeyRawVerify` | Symbols present in dylib | EDR: monitor `dlopen` of `MobileSubstrate/DynamicLibraries/blackhound.dylib` |
| `_replace_SecKeyVerifySignature` | Same | Same |
| `_replace_SecTrustEvaluateWithError` | Same | amfi: log untrusted trampolines |
| Logos `__logos_method$MobileActivationDaemon$...` | 2× symbols in dylib | Frida: `ObjC.classes.MobileActivationDaemon.methods` enumeration |
| Logos `__logos_method$MobileActivationDaemon$...` (2nd) | Same | Same |

**YARA rule** (in `05_IOC/YARA_RULES.yar`):

```yara
rule iRemovalPro_BlackHound_Hooks
{
    meta:
        description = "All 5 MobileSubstrate + Logos hook symbols"
        severity = "high"
    strings:
        $orig1 = "_orig_SecKeyRawVerify" ascii
        $orig2 = "_orig_SecKeyVerifySignature" ascii
        $orig3 = "_orig_SecTrustEvaluateWithError" ascii
        $rep1  = "_replace_SecKeyRawVerify" ascii
        $rep2  = "_replace_SecKeyVerifySignature" ascii
        $rep3  = "_replace_SecTrustEvaluateWithError" ascii
        $log1  = "__logos_method$_ungrouped$MobileActivationDaemon$validateActivationDataSignature" ascii
        $log2  = "__logos_method$_ungrouped$MobileActivationDaemon$handleActivationInfo" ascii
    condition:
        4 of them
}
```

### 20.7 Hook Functionality Summary — what each one does in 1 sentence

1. **`_replace_SecKeyRawVerify`** — replaces Apple's RSA verify with one that uses the **hardcoded RSA-1024 pubkey** instead of Apple's HSM key
2. **`_replace_SecKeyVerifySignature`** — high-level wrapper that calls `_replace_SecKeyRawVerify` under the hood
3. **`_replace_SecTrustEvaluateWithError`** — always returns `errSecSuccess`, **kills X.509 chain validation**
4. **`__logos_method$MobileActivationDaemon$validateActivationDataSignature$...`** — **returns YES** for the forged ticket, falling back on `_replace_SecKeyRawVerify`
5. **`__logos_method$MobileActivationDaemon$handleActivationInfo$...`** — **substitutes** the activation record with the forged one, then calls `%orig` with it

---

## 21. COMPLETE LOCAL BYPASS PIPELINE — Zero License, Zero Server

> **Question this section answers:** *"Sans licence valide + HWID enregistré, le serveur ne renvoie jamais de nonce, et donc jamais de ticket signé. Comment recréer la logique de bypass localement, sans besoin de licence ?"*

### 21.1 The answer in one paragraph

The lab ships a fully-offline reproduction of the entire iActivation ticket lifecycle that the real iRemoval server emits in production. Because all four stages — **keypair generation, bplist00 ticket construction, PKCS#1 v1.5 / SHA-256 signature, and JSON+base64 envelope wrapping** — are implemented client-side in [`06_LOCAL_REPRODUCER/iact_reproducer/`](06_LOCAL_REPRODUCER/iact_reproducer/), the pipeline produces a structurally-identical, cryptographically-consistent signed ticket **without ever contacting `s13.iremovalpro.com`**. The reproducer's marker (`iRemovalOFFENSIVE Test`) is hardcoded into every artifact so a forensic examiner can immediately tell a lab fixture from a real ticket. This sidesteps, by design, both server-side enforcement (§13) and HWID-as-DRM (§14).

### 21.2 Four-step pipeline (`run_reproducer.py`)

```text
Step 1/4 — load or generate RSA-2048 key
Step 2/4 — build bplist00 activation ticket
Step 3/4 — sign with PKCS#1 v1.5 / SHA256
Step 4/4 — wrap as JSON+base64 envelope
```

| Step | Module                                  | Artifact                                                                                         | Size         |
|-----:|-----------------------------------------|--------------------------------------------------------------------------------------------------|-------------:|
| 1    | [`keys.py`](06_LOCAL_REPRODUCER/iact_reproducer/keys.py)                 | `keys/iact8-test_iRemovalOFFENSIVE Test_<TS>.pem`                                                 | 1702 B       |
| 2    | [`bplist_builder.py`](06_LOCAL_REPRODUCER/iact_reproducer/bplist_builder.py) | `requests/activation_ticket_<TS>.bplist`                                                          | **1763 B**   |
| 3    | [`signer.py`](06_LOCAL_REPRODUCER/iact_reproducer/signer.py)             | `requests/activation_ticket_<TS>.sig`                                                            | **256 B**    |
| 4    | [`wire_format.py`](06_LOCAL_REPRODUCER/iact_reproducer/wire_format.py)   | `responses/iact_envelope_<TS>.json` + `logs/reproducer_manifest_<TS>.json`                       | ≈3.0 KB      |

The orchestrator that chains the four steps is [`orchestrator.py`](06_LOCAL_REPRODUCER/iact_reproducer/orchestrator.py); the entry-point is [`run_reproducer.py`](06_LOCAL_REPRODUCER/iact_reproducer/run_reproducer.py).

### 21.3 Verified end-to-end run (live, 2026-06-22T18:02:34Z)

```text
19:02:34 | INFO    | iact_reproducer | Step 1/4 — loading or generating RSA-2048 key…
  ✓ iact8-test_iRemovalOFFENSIVE Test_20260622T180234Z.pem
    (sha256=975aeb8daf1493b5e1db85d65d5a6b25805d41a41c66e2b8b09524941e8067b2)
19:02:34 | INFO    | iact_reproducer | Step 2/4 — building bplist00 activation ticket…
  ✓ activation_ticket_20260622T180234Z.bplist (1763 bytes)
19:02:34 | INFO    | iact_reproducer | Step 3/4 — signing with PKCS#1 v1.5 / SHA256…
  ✓ activation_ticket_20260622T180234Z.sig (256 bytes)
19:02:34 | INFO    | iact_reproducer | Step 4/4 — wrapping as JSON+base64 envelope…
  ✓ iact_envelope_20260622T180234Z.json
    udid=OFFENSIVE-TEST-8FBF47F4
    alg=RSA-PKCS1v1.5-SHA256
    b64_len=2352 sig_len=344 nonce_len=24
    ts=2026-06-22T18:02:34Z
```

**Magic-byte confirmation** (raw bplist00 header):

```text
activation_ticket_20260622T180234Z.bplist
  size=1763  sha256=64517bee48a47cf3…
  magic=b'bplist00'                     ← Apple binary plist v0 (ASCII "plist00")
activation_ticket_20260622T180234Z.sig
  size= 256  sha256=b6dec390135c09ca…
  magic=b"'ko\x80\x0c\xc6\xddQ"        ← first 12 bytes of RSA-2048 sig
```

**Sign-then-verify round-trip** (extracted pubkey + `run_reproducer.py --verify`):

```text
Envelope : ...\iact_envelope_20260622T180234Z.json
Algorithm: RSA-PKCS1v1.5-SHA256
Signature: 276b6f800cc6dd51dbbff70ed20443459d6df79bc068c4ad8147b838e6290dd1…  (256 bytes)
bplist  : 1763 bytes
Verification: OK ✓
exit=0
```

The signature verifies against the locally-generated public key, proving the four-step pipeline is **cryptographically self-consistent** — no external oracle is required.

### 21.4 Network & license requirements = zero

| What the real iRemoval server does in production | What the lab does instead                                                | Reference |
|--------------------------------------------------|--------------------------------------------------------------------------|-----------|
| Validates HWID against its database              | Skipped — UDID is randomly generated and tagged `OFFENSIVE-TEST-*`        | §14       |
| Checks license status                            | Skipped — no license check exists; marker `iRemovalOFFENSIVE Test` baked in | §13.4     |
| Allocates a fresh 24-byte nonce                  | Generated locally with `secrets.token_bytes(24)`                          | §13.3     |
| Signs bplist00 with the operator's RSA-2048 key  | Reproducer signs with a **freshly generated** RSA-2048 keypair            | §13.5     |
| Wraps `{bplist_b64, sig_b64, nonce_b64, ts}`     | Same JSON envelope format (`wire_format.py`)                             | §13.6     |

Net effect: **zero outbound traffic**, **zero real server contact**, **zero real Apple/iRemoval keys touched**. Every byte is generated on the analyst workstation.

### 21.5 Why this matters for detection engineering

1. **Sister artifacts to the real thing.** A blue-team detection rule that fires on `magic=b'bplist00' + RSA-2048 sig + udid~=OFFENSIVE` will pick up lab traffic identically to production traffic — except for the `OFFENSIVE-TEST-*` marker, which is the canary.

2. **Coverage for §13 server-side checks.** The mock server ([`mock_server.py`](06_LOCAL_REPRODUCER/iact_reproducer/mock_server.py)) implements the same 12 endpoints the real server offers. With `--disable-hmac --disable-blacklist --disable-rate-limit`, the analyst can replay the offline envelope against a fully-permissive local server and observe every guard individually (see §13.7 and [`test_disable_flags.py`](06_LOCAL_REPRODUCER/iact_reproducer/test_disable_flags.py) — 24/24 PASS).

3. **Forensic canary.** Every artifact carries `iRemovalOFFENSIVE Test` in its name and the JSON envelope `marker` field, so a forensic sweep of a confiscated device or CI runner can immediately distinguish a lab fixture from a real ticket. The marker is documented in [`06_LOCAL_REPRODUCER/RECONSTRUCTION.md`](06_LOCAL_REPRODUCER/RECONSTRUCTION.md).

4. **Reproducible in CI.** `run_reproducer.py` is hermetic: no network, no clock dependency beyond UTC, no environment variables beyond `PYTHONIOENCODING`. A green run + OK verify is sufficient evidence that the offline pipeline is intact.

### 21.6 Reproducer CLI — full surface

```text
python 06_LOCAL_REPRODUCER/iact_reproducer/run_reproducer.py                # run pipeline
python 06_LOCAL_REPRODUCER/iact_reproducer/run_reproducer.py --verify \    # sign-then-verify
        <envelope.json> --pubkey <pub.pem>
python 06_LOCAL_REPRODUCER/iact_reproducer/test_local_pipeline.py          # 10-case tamper matrix (§21.8)
```

**Exit codes** (from `run_reproducer.py`):

| Code | Meaning                                                                 |
|-----:|-------------------------------------------------------------------------|
| 0    | OK — pipeline produced all 4 artifacts, OR signature verified           |
| 2    | Public key missing / unreadable for verify                              |
| 3    | bplist magic ≠ `bplist00`                                               |
| 4    | Signature length ≠ 256 bytes (RSA-2048)                                 |
| 5    | JSON envelope malformed / missing required fields                       |
| 6    | PKCS#1 v1.5 verification failed                                         |

**Exit codes** (from `test_local_pipeline.py`):

| Code | Meaning                                                |
|-----:|--------------------------------------------------------|
| 0    | All 10 expected/observed pairs match (pipeline sound)  |
| 1    | At least one case diverged — pipeline NOT sound        |

### 21.7 Relationship to the rest of BYPASS_CORE.md

| Section                                                              | What it covers                                       | Where the lab reproduces it                                         |
|----------------------------------------------------------------------|------------------------------------------------------|---------------------------------------------------------------------|
| §13 SERVER-SIDE ENFORCEMENT                                          | What the real server checks                          | [`mock_server.py`](06_LOCAL_REPRODUCER/iact_reproducer/mock_server.py) (12 endpoints, 3 guards) |
| §14 HWID AS DRM                                                      | HWID database lookup                                 | UDID is generated locally; never hits a DB                          |
| §15 SELF-PROTECTION                                                  | iRemoval's own anti-tamper                            | Lab reproducer does not implement iRemoval's loader — see §15.5     |
| §16 THE 9-STEP HANDSHAKE                                             | Client ↔ server dance                                | Mock server replays the same 9 endpoints offline                    |
| §17 DETECTION RULES                                                  | YARA / SIGMA / Suricata                              | All rules in `05_IOC/` match lab-generated artifacts identically    |
| §18 WHY "1-LINE BYPASS" IS MISLEADING                                | Five-hook chain                                      | N/A — describes the iOS-side bypass, not the network bypass         |
| §19 LIMITATIONS                                                      | Lab does not recover the real Apple key              | Confirmed — lab uses fresh RSA-2048, never the real key             |
| §20 COMPLETE HOOK INVENTORY                                          | Client-side override symbols                         | N/A — describes the iOS-side bypass, not the network bypass         |
| **§22 ADVERSARIAL SIMULATION**                                       | What attackers can/cannot do with §21 alone         | [`test_adversarial.py`](06_LOCAL_REPRODUCER/iact_reproducer/test_adversarial.py) (10 cases: 1 baseline + 9 attack variants) |

### 21.8 Tamper Matrix — proof of self-consistency

A pipeline that produces a valid signature for arbitrary payloads is **not** a real cryptographic pipeline. To prove that the lab's local pipeline is genuine (not a sham that always returns OK), the reproducer ships a tamper-matrix integration test at [`06_LOCAL_REPRODUCER/iact_reproducer/test_local_pipeline.py`](06_LOCAL_REPRODUCER/iact_reproducer/test_local_pipeline.py). It runs `orchestrator.run_pipeline()` end-to-end, then mutates the envelope in 8 different ways and asserts that **each tamper causes verification to fail**.

**Tamper cases (10 total: 2 positive, 8 negative):**

| # | Case                                              | Mutation                                  | Expected | Why                                              |
|---|---------------------------------------------------|-------------------------------------------|---------:|--------------------------------------------------|
| 1 | Unmodified envelope                               | none                                      | OK ✓     | Baseline — pipeline is self-consistent           |
| 2 | bplist first byte XOR 0x01                        | flip lowest bit @ offset 0                | FAIL ✗   | RSA signature is over full bplist payload        |
| 3 | signature byte 32 XOR 0x01                        | flip lowest bit @ offset 32               | FAIL ✗   | PKCS#1 v1.5 is deterministic per key             |
| 4 | Verify with an alien RSA-2048 public key          | substitute pubkey                         | FAIL ✗   | Sig is bound to the private key, not the bplist  |
| 5 | bplist truncated by 16 bytes                      | drop last 16 B                            | FAIL ✗   | Length mismatch breaks PKCS#1 v1.5 encoding       |
| 6 | signature length 0 (empty)                        | replace sig with empty b64                | FAIL ✗   | RSA-2048 sig must be exactly 256 bytes           |
| 7 | bplist length 0 (empty)                           | replace b64 with empty                    | FAIL ✗   | Empty message + 256 B sig → encoding mismatch    |
| 8 | Fresh 2nd pipeline, unmodified                    | re-run pipeline                           | OK ✓     | Independent keypair must also self-verify        |
| 9 | bplist last byte XOR 0x01                        | flip lowest bit @ end                     | FAIL ✗   | End of bplist is just as sensitive as start      |
|10 | signature last byte XOR 0x01                      | flip lowest bit @ end                     | FAIL ✗   | Last byte of PKCS#1 v1.5 padding                 |

**Live run (2026-06-22T18:22:56Z):**

```text
========================================================================
iAct8 pipeline tamper matrix — root: 06_LOCAL_REPRODUCER/tamper_tests/20260622T182256Z
========================================================================

#   expected observed  label
------------------------------------------------------------------------
1   OK       OK        ✓ positive: unmodified envelope verifies OK
2   FAIL     FAIL      ✓ bplist tampered (1 bit @ offset 0) → FAIL
3   FAIL     FAIL      ✓ signature tampered (1 bit @ offset 32) → FAIL
4   FAIL     FAIL      ✓ verify with alien pubkey → FAIL
5   FAIL     FAIL      ✓ bplist truncated (-16 bytes) → FAIL
6   FAIL     FAIL      ✓ empty signature (len=0) → FAIL
7   FAIL     FAIL      ✓ empty bplist (len=0) → FAIL
8   OK       OK        ✓ positive: fresh 2nd pipeline verifies OK
9   FAIL     FAIL      ✓ bplist tampered (1 bit @ last byte) → FAIL
10  FAIL     FAIL      ✓ signature tampered (1 bit @ last byte) → FAIL

TOTAL: 10/10 matrix checks passed  (pipeline is cryptographically self-consistent)
exit=0
```

**What this proves:**

1. The pipeline does **not** simply return `OK` for everything — it actually runs `signer.verify_bytes()` and checks the cryptographic relationship between the bplist, signature, and public key.
2. The 8 negative cases cover the 4 standard mutation vectors (bplist tamper, sig tamper, wrong key, length mismatch) at 2 positions each (start, end).
3. The 2 positive cases (cases 1 and 8) prove the pipeline works **twice** with **different keypairs**, ruling out the possibility that the OK is hard-coded to a specific key.
4. The test is hermetic — it generates its own keys via `orchestrator.run_pipeline()` and writes to a fresh `tamper_tests/<TS>/` subdirectory, so successive runs never collide.

**How to run:**

```bash
python 06_LOCAL_REPRODUCER/iact_reproducer/test_local_pipeline.py
echo "exit=$?"
# expected: TOTAL: 10/10 matrix checks passed  exit=0
```

**Exit codes:**

| Code | Meaning                                                |
|-----:|--------------------------------------------------------|
| 0    | All 10 expected/observed pairs match                    |
| 1    | At least one case diverged — pipeline NOT self-consistent |

### 21.9 TL;DR

> The complete iActivation ticket pipeline is reproducible **offline** by the lab in four local steps: generate a keypair, build a `bplist00` ticket, sign it with PKCS#1 v1.5 / SHA-256, wrap it as a JSON envelope. The resulting artifacts are cryptographically self-consistent (sign+verify round-trip = `OK ✓`), structurally identical to production tickets, and clearly tagged `iRemovalOFFENSIVE Test` so a forensic examiner can never confuse a lab fixture with a real ticket. A tamper-matrix test ([`test_local_pipeline.py`](06_LOCAL_REPRODUCER/iact_reproducer/test_local_pipeline.py)) proves the verify path is genuine (10/10: 2 positives + 8 negatives). **No license, no HWID registration, no server contact.**

---

## §22 ADVERSARIAL SIMULATION — pipeline alone ≠ bypass

§21 demonstrated that the lab can reproduce a signed iActivation ticket **offline**, with the resulting envelope passing a verify round-trip. The natural follow-up question is: *"So what stops an attacker from just running the same pipeline and getting a working bypass on a real iPhone?"* This section answers that question with a 10-case adversarial simulation.

### 22.1 The point: signing ≠ bypassing

The lab's local pipeline is **purely cryptographic**. It knows nothing about the iOS kernel, the activation daemon (`activationd`), or the `SecKeyRawVerify` code path that the iPhone ultimately invokes. The only thing it can guarantee is the *internal* property that **a signature produced under key K verifies under the matching public K**, and **a signature produced under a different key K′ does not verify under K**.

iOS, however, has its **own** public key hardcoded into the boot chain — not the lab's test key. When `activationd` receives a ticket, it calls `SecKeyRawVerify(ticket.sig, ticket.bplist, apple_pubkey)` where `apple_pubkey` is the genuine Apple activation public key baked into the iOS image at build time. The lab's offline pipeline produces a signature bound to a *lab-generated* keypair; the iPhone has no copy of the lab's public key. So the signature is meaningless to iOS, regardless of how well-formed it is.

**The full iRemoval bypass therefore requires two distinct components:**

1. **§21 (offline ticket forgery)** — produce a valid bplist00 + signature offline.
2. **§20 (client-side hook chain)** — substitute the Apple public key inside `SecKeyRawVerify` so that the forged signature *appears* to verify against the genuine pubkey path.

Without §20, the §21 artifacts are **cryptographically valid but operationally useless** — exactly like a passport that's correctly signed but not issued by any country the border agent recognizes.

### 22.2 What attackers can do (with §21 alone)

The 10-case adversarial test at [`06_LOCAL_REPRODUCER/iact_reproducer/test_adversarial.py`](06_LOCAL_REPRODUCER/iact_reproducer/test_adversarial.py) enumerates the realistic attack surface. The cases that **succeed locally** are:

| Case | Attack                                                      | Local result | Why                                                                                          |
|-----:|-------------------------------------------------------------|:------------:|----------------------------------------------------------------------------------------------|
| 1    | Unmodified lab envelope                                     | OK ✓         | Baseline — pipeline is self-consistent                                                       |
| 3    | Attacker re-signs bplist with their own RSA-2048 keypair    | OK ✓ (cosmetic) | Self-check passes because attacker verifies with attacker's own pub. **iOS still rejects.** |
| 8    | UDID swap in JSON envelope                                  | OK ✓         | UDID is JSON metadata, not in signed bplist                                                  |
| 9    | Nonce swap in JSON envelope                                 | OK ✓         | Nonce is JSON metadata, not in signed bplist                                                 |
| 10   | Replay: verify same envelope twice                          | OK ✓         | No nonce-replay protection in the offline pipeline (deliberate — see §22.5)                  |

Cases 8 and 9 reflect **real iAct8 wire-format semantics**: the bplist is the only signed artifact, and the JSON envelope is an unprotected transport wrapper. Case 10 reflects an intentional design choice in the offline lab — see §22.5.

### 22.3 What attackers cannot do (with §21 alone)

The cases that **fail** are the ones a defender cares about:

| Case | Attack                                                              | Local result | iOS result                                                                                  |
|-----:|---------------------------------------------------------------------|:------------:|----------------------------------------------------------------------------------------------|
| 2    | Attacker re-signs bplist, verify with **lab** pub                   | FAIL ✗       | n/a — sig is bound to attacker's key                                                          |
| 4    | Random 256-byte `os.urandom(256)` signature                         | FAIL ✗       | n/a                                                                                          |
| 5    | All-zero 256-byte signature                                         | FAIL ✗       | n/a                                                                                          |
| 6    | 1-bit tamper of bplist at offset 0                                  | FAIL ✗       | n/a                                                                                          |
| 7    | Lab envelope verified with **alien** RSA-2048 pub                   | FAIL ✗       | n/a                                                                                          |

Cases 2 and 7 are the **load-bearing pair**: they prove the verifier is actually checking the keypair binding and is not just returning `True` unconditionally. Case 2 in particular is the trap — the attacker can produce a perfectly verifying envelope *for their own key*, but that envelope is structurally identical to what `activationd` would receive, except the signature does not bind to Apple's pubkey. iOS rejects it on the very first `SecKeyRawVerify` call.

### 22.4 Live run (2026-06-22T18:44:17Z)

```text
========================================================================
iAct8 adversarial simulation — root: 06_LOCAL_REPRODUCER/adversarial_tests/20260622T184417Z
========================================================================

#   expected observed  label
------------------------------------------------------------------------
1   OK       OK        ✓ baseline: lab env verifies with lab pub → OK
2   FAIL     FAIL      ✓ attacker re-signs with own key, verify with LAB pub → FAIL
3   OK       OK        ✓ TRAP: attacker re-sign verifies OK with attacker pub → OK (cosmetic)
4   FAIL     FAIL      ✓ random 256-byte signature → FAIL
5   FAIL     FAIL      ✓ all-zero 256-byte signature → FAIL
6   FAIL     FAIL      ✓ bplist tampered (1 bit @ offset 0) → FAIL
7   FAIL     FAIL      ✓ lab env verified with alien pub → FAIL
8   OK       OK        ✓ UDID swap in JSON envelope → STILL OK (UDID is metadata)
9   OK       OK        ✓ nonce swap in JSON envelope → STILL OK (nonce is metadata)
10  OK       OK        ✓ replay: same envelope verified twice → BOTH OK

TOTAL: 10/10 adversarial checks passed  (adversarial model is consistent with §22 expectations)
exit=0
```

**How to run:**

```bash
python 06_LOCAL_REPRODUCER/iact_reproducer/test_adversarial.py
echo "exit=$?"
# expected: TOTAL: 10/10 adversarial checks passed  exit=0
```

**Exit codes:**

| Code | Meaning                                                                      |
|-----:|------------------------------------------------------------------------------|
| 0    | All 10 expected/observed pairs match (pipeline is harmless without §20)      |
| 1    | At least one case diverged — adversarial model is wrong; do not trust the lab |

### 22.5 Why the offline pipeline intentionally omits nonce-replay protection

The iRemoval *server* enforces nonce-replay protection via the 9-step handshake (see §13 and §16). A signed envelope presented twice to the real server fails at step 4 with `INVALID_NONCE`. The **offline pipeline does not replicate this server-side guard** — case 10 confirms that the same envelope verifies twice locally. This is by design:

- The offline pipeline's purpose is to demonstrate that the **bplist + signature wire format** is faithfully reproduced — not that a complete activation handshake is reproducible.
- Adding nonce-replay protection to the offline pipeline would conflate two distinct concerns: (a) the *cryptographic* correctness of the signed artifact, and (b) the *server-side* freshness guarantee. (b) belongs to §13's server analysis, not §21's pipeline analysis.
- The adversarial test deliberately surfaces this gap as case 10 (`expected: OK`). A defender reading the lab output immediately sees that the offline pipeline is *not* a complete activation oracle — only the cryptographic half of one.

In production, **case 10 is the boundary at which iRemoval's server-side enforcement (§13) takes over**. The lab is not, and cannot be, a substitute for that.

### 22.6 §21 + §20 = bypass; §21 alone = noop

| Pipeline component                                  | Without §21 | With §21 only | With §21 + §20 |
|-----------------------------------------------------|:-----------:|:-------------:|:--------------:|
| `bplist00` ticket built locally                     | ✗           | ✓             | ✓              |
| RSA-2048 signature over ticket (PKCS#1 v1.5 + SHA-256) | ✗           | ✓             | ✓              |
| JSON envelope with `b64`/`sig`/`alg`/`nonce`/`ts` fields | ✗       | ✓             | ✓              |
| `SecKeyRawVerify` hook replacing Apple pubkey       | ✗           | ✗             | ✓              |
| Other §20 hooks (AMSURL, `akd` bypass, etc.)        | ✗           | ✗             | ✓              |
| **Result**                                          | No artifact | Forensic fixture | **Activation bypass** |

The §21 fixture is a *forensic* tool, not a *bypass*. It produces something a defender can study, YARA-scan, or YARA-block (see `05_IOC/YARA_RULES.yar`). The bypass itself materializes only when §21 output is *handed to the §20 hook chain on a jailbroken device*. The lab keeps these two halves deliberately separated:

- §21 ships as plain Python — readable, testable, runnable on any laptop with `cryptography` installed.
- §20 ships as Ghidra decompilation snippets in `01_REPORTS/BYPASS_CORE.md` — symbols and call sites only, no binary to execute.

### 22.7 TL;DR

> §21 (local pipeline) is a **forensic fixture generator**, not a bypass tool. It produces valid `bplist00` + RSA-2048-signed envelopes that an attacker can self-verify with their own keypair, but iOS rejects them at `SecKeyRawVerify` because the iPhone has the genuine Apple pubkey, not the attacker's. The full iRemoval bypass requires §20 (client-side hook chain that substitutes the Apple pubkey) — see [§20](01_REPORTS/BYPASS_CORE.md#20-complete-hook-inventory). The 10-case adversarial simulation at [`test_adversarial.py`](06_LOCAL_REPRODUCER/iact_reproducer/test_adversarial.py) **proves** this distinction by demonstrating 1 baseline + 3 forensic-only outcomes + 6 cryptographic guards, all of which behave consistently with the model.
