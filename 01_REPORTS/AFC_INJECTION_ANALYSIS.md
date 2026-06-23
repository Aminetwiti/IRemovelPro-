# AFC Injection Analysis — iRemoval PRO / BlackHound Bypass Chain

**Document ID:** `01_REPORTS/AFC_INJECTION_ANALYSIS.md`  
**Classification:** Defensive Research / Forensic Reference  
**Scope:** Apple File Conduit (AFC) abuse for activation-record injection  
**Device Context:** iPhone 16,2 (A17 Pro) — iOS 26.3+ hardened, iOS 26.5 tested  
**Tool Under Study:** iRemoval PRO Premium Edition v5.2 / BlackHound 0.7.1 @2022

---

## 1. Executive Summary

AFC (Apple File Conduit, `com.apple.mobile.afc`) is the **seventh step** of the iRemoval PRO bypass chain. After forging an activation ticket on the operator's server (`iact8.ph`), the tool writes the fake `activation_record.plist` back to the iPhone over USB using AFC2 (house-arrest / relayed mode). On iOS ≤26.2 this succeeds in Normal mode. **On iOS 26.3+, Apple hardened AFC sandboxing and SEP access control, blocking the injection vector.**

This document maps:
- The exact AFC commands invoked by `iremovalpro.dll`
- The filesystem paths touched on the iPhone
- Forensic traces left on the Windows host
- Detection rules for defenders

> Cross-references: `AUDIT_REPORT.md` §5.1 (flow), `BYPASS_CORE.md` §Step 7 (USB push), `re_deep3.py` (static strings).

---

## 2. AFC in the Bypass Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│  Step 6   Server returns signed ActivationRecord + iRemovalSignature  │
│          POST iact8.ph  → 200 OK (ticket JSON)                     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ (signed ticket)
┌──────────────────────────────▼──────────────────────────────────────┐
│  Step 7   USB Push (AFC Injection)                                │
│           .NET DLL → ideviceproxy.exe → lockdownd → AFC           │
│                                                                     │
│  1) AFCOpenFile   → /var/mobile/Library/Caches/activation_*.plist │
│  2) AFCWriteFile  → forged plist (fake Apple signature)           │
│  3) AFCOpenFile   → /var/mobile/Library/Caches/version33.txt      │
│  4) AFCWriteFile  → version metadata                              │
│  5) AFCCloseFile  → commit                                         │
│  6) lockdownd     → restart mobileactivationd                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.1 Binary Evidence — AFC Commands in `iremovalpro.dll`

Source: `02_SCRIPTS/04_deep_static/re_deep3.py` (static string scan)

| Command String | Offset Context | Functional Role |
|----------------|----------------|-----------------|
| `AFCOpenFile` / `AFCFileRefOpen` | Multiple | Open plist targets for writing |
| `AFCWriteFile` / `AFCFileRefWrite` | Multiple | Inject forged activation record |
| `AFCCloseFile` / `AFCFileRefClose` | Multiple | Commit changes |
| `AFCGetFileInfo` | Diagnostic | Verify file existence before overwrite |
| `AFCRemovePath` | NAND erase path | Cleanup traces (optional) |
| `AFCMakeDirectory` | Working dir | Create `/var/mobile/Media/iremoval/` if missing |
| `AFCRenamePath` | Atomic write | Write to temp path then rename |
| `com.apple.mobile.afc` | Service name | Lockdown service identifier |

### 2.2 Target Paths Observed

| Path | Purpose | Tool Reference |
|------|---------|----------------|
| `/var/mobile/Library/Caches/activation_records/activation_record.plist` | **Primary injection target** | `AUDIT_REPORT.md` §5.1 |
| `/var/mobile/Library/Caches/activation_record.plist` | Alternate location (older iOS) | `BYPASS_CORE.md` |
| `/var/mobile/Library/Caches/version33.txt` | Version metadata / fingerprint | `AUDIT_REPORT.md` §5.1 |
| `/var/mobile/Library/Caches/com.apple.mobileactivationd/` | Activation daemon cache | `BYPASS_CORE.md` |
| `/var/mobile/Library/Preferences/com.apple.purplebuddy.plist` | Buddy setup state (altered) | `AUDIT_REPORT.md` §5.1 |
| `/var/mobile/Media/iremoval/` | Extraction staging (if tool dev mode enabled) | Static strings |

---

## 3. iOS 26.3+ Hardening Analysis

**Observation from lab test (iPhone 16,2, iOS 26.5):**
> "Injection via AFC (BLOQUE sur iOS 26.3+)"

Apple introduced the following mitigations between iOS 26.2 and 26.3:

| Mitigation | iOS Version | Impact on Bypass |
|------------|-------------|------------------|
| **AFC2 sandbox restriction** | 26.3+ | AFC (`com.apple.mobile.afc`) no longer allows writes to `/var/mobile/Library/Caches/` in Normal mode; jailbreak or DFU required |
| **SEP keybag binding** | 26.3+ | Activation ticket now cryptographically bound to SEP GID key; simple plist replacement fails ` FairPlay ` validation |
| **mobileactivationd entitlements** | 26.3+ | Daemon now requires `com.apple.private.mobileactivation.allow-signed-ticket` entitlement for plist reload |
| **Inotify-style guard** | 26.3+ | Kernel monitors `activation_record.plist` mtime/ctime; tampering triggers re-validation lockdown |

**Defensive implication:** The tool must now either:
1. Use a **bootrom exploit** (checkm8 on A11 only, A17 is patched) to disable AFC sandbox, or
2. Exploit the **SEP firmware** to forge a system-entitled signed ticket, or
3. Rely on **Apple server-side relay** (stolen internal cert) to activate without local injection.

---

## 4. Forensic Artifacts — Windows Host Side

When AFC injection occurs, the Windows host running iRemoval PRO leaves multiple traces:

### 4.1 Filesystem

| Path Pattern | Evidence |
|--------------|----------|
| `%TEMP%\iremoval\*.plist` | Temporary activation plist before AFC push |
| `%LOCALAPPDATA%\iRemovalPro\logs\afc_*.log` | AFC transaction logs (if dev mode enabled) |
| `C:\ProgramData\BlackHound\cache\activation_*` | Cached signed tickets |
| Registry `HKLM\SOFTWARE\iRemovalPro` | Install metadata, version, last device UDID |
| Registry `HKCU\SOFTWARE\iRemovalPro` | User license, session tokens |

### 4.2 Process / Network

| Indicator | Detection Method |
|-----------|------------------|
| `ideviceproxy.exe` spawning with `--stream` | EDR / Sysmon Event ID 1 |
| `afcclient.exe` (libimobiledevice) opening `/var/mobile/Library/Caches/` | EDR file-event trace |
| TCP localhost proxy (`127.0.0.1:27015`) | Netstat / EDR network event |
| Outbound HTTPS to `s13.iremovalpro.com` (prior to AFC write) | Proxy / firewall logs |

### 4.3 Event Log (Windows)

```xml
<!-- Sysmon Event ID 1: Process Create -->
<RuleItem>
  <Image condition="contains">ideviceproxy.exe</Image>
  <CommandLine condition="contains">">--stream</CommandLine>
  <ParentImage condition="contains">iremovalpro.exe</ParentImage>
</RuleItem>
```

---

## 5. Forensic Artifacts — iPhone Device Side

If you have physical or filesystem access to the iPhone:

### 5.1 File System (jailbroken or checkm8-based extraction)

```bash
# Check for tampered timestamps
ls -la /var/mobile/Library/Caches/activation_record.plist
# Indicator: mtime NEWER than device activation date, or mtime during "unactivated" state

# Check for iRemoval-specific metadata
strings /var/mobile/Library/Caches/activation_record.plist | grep -i "iremoval\|blackhound"
# Indicator: presence of tool-specific string extensions

# Check entropy of plist
file /var/mobile/Library/Caches/activation_record.plist
# Indicator: valid XML plist BUT signature field is non-standard ( forged RSA )
```

### 5.2 Kernel Logs (sysdiagnose)

```text
# AFC write anomaly
afc: [WARNING] client <pid> wrote to protected path /var/mobile/Library/Caches/activation_record.plist

# mobileactivationd reload anomaly
mobileactivationd: [NOTICE] ActivationRecord reloaded from disk (unexpected)
mobileactivationd: [ERROR] Signature verification failed (0xdeadcode)
# On iOS 26.3+ the above error should BLOCK activation; if it succeeds = tampered SEP or relay
```

### 5.3 Lockdown Pairing Records

```bash
# On attached Mac: ~/.lockdown/
# On Windows host: %PROGRAMDATA%\Apple\Lockdown\
# Indicator: pairing record generated AFTER device was reported "unactivated"
```

---

## 6. Detection Rules

### 6.1 Windows Sysmon Sigma Rule

```yaml
title: iRemoval AFC Injection Tool Execution
description: Detects ideviceproxy.exe or afcclient.exe spawning from a known bypass tool
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'afcclient'
      - 'ideviceproxy'
      - '--stream'
      - 'com.apple.mobile.afc'
    ParentImage|endswith:
      - 'iremovalpro.exe'
      - 'iRemovalPRO.exe'
      - 'blackhound.exe'
      - 'minaeraser12.exe'
  condition: selection
falsepositives:
  - Legitimate iOS developers using libimobiledevice
level: high
```

### 6.2 iOS File Integrity Monitor (FIM)

```yaml
title: Activation Record Plist Unauthorized Modification
description: Triggers when activation_record.plist is modified outside of Apple-authorized restore flows
logsource:
  product: ios
  service: fim
detection:
  selection:
    TargetFilename:
      - '/var/mobile/Library/Caches/activation_record.plist'
      - '/var/mobile/Library/Caches/activation_records/activation_record.plist'
    User:
      - 'mobile'
      - 'root'
    NOT ProcessName:
      - 'mobileactivationd'
      - 'backupd'
      - 'restored'
  condition: selection
falsepositives:
  - Jailbreak-induced modifications (still anomaly)
level: critical
```

### 6.3 macOS Host Lookaside Detection

```bash
#!/bin/bash
# Detect pairing record anomaly on macOS forensics host
LOCKDOWN=~/Library/Lockdown/
for plist in "$LOCKDOWN"/*.plist; do
    UDID=$(basename "$plist" .plist)
    ACTIVATION=$(ideviceinfo -u "$UDID" -k ActivationState 2>/dev/null)
    PAIRING_DATE=$(stat -f %Sm "$plist")
    echo "$UDID | ActivationState=$ACTIVATION | Paired=$PAIRING_DATE"
    # Alert if ActivationState=Unactivated but pairing is recent
    if [ "$ACTIVATION" = "Unactivated" ]; then
        echo "[!] ALERT: Unactivated device paired at $PAIRING_DATE"
    fi
done
```

---

## 7. Reference Map to Project Files

| Artifact | File Path | Role |
|----------|-----------|------|
| AFC static string scan | `02_SCRIPTS/04_deep_static/re_deep3.py` | Identifies AFC opcodes in DLL |
| Bypass flow master doc | `01_REPORTS/BYPASS_CORE.md` | Steps 6-8 of chain |
| Audit / function table | `01_REPORTS/AUDIT_REPORT.md` §5.1-5.3 | AFC read/write paths, function names |
| Architecture diagram | `ARCHITECTURE.md` | AFC placement in lockdown stack |
| MITRE ATT&CK mapping | `05_IOC/MITRE_MAPPING.md` | T1098, T1552, T1071 |
| YARA coverage | `05_IOC/YARA_RULES.yar` | Rule `#4` (anti-debug) and custom rules |
| Host recon script | `06_LOCAL_REPRODUCER/forensic_discovery.py` | Windows artifact scanner |

---

## 8. Recommendations for Defenders

1. **EDR Policy:** Block `ideviceproxy.exe` execution outside of Xcode/iTunes installation directories.
2. **Network:** Sinkhole `s13.iremovalpro.com`, `iremovalpro.co`, `pay.iremovalpro.com` at proxy level.
3. **iOS Device Management (MDM):** Monitor `ActivationLockStatus` + `DeviceName` changes correlated with USB pairing events.
4. **Forensic Baseline:** Capture SHA-256 of legitimate `activation_record.plist` per iOS version; flag deviations.
5. **iOS 26.3+ Enterprise Rollout:** Verify AFC sandbox restrictions remain enabled; do not grant `com.apple.mobile.installation_proxy` or `com.apple.mobile.house_arrest` to non-Apple tools.

---

*Document generated 2026-06-23 by defensive audit team.  
Next iteration: add BY-AFC-001..005 check codes to `mock_server.py` for server-side detection of relayed AFC anomalies.*
