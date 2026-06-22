# MITRE ATT&CK Mapping — iRemoval PRO Premium Edition v5.2

> Mapping des comportements observés vers le framework MITRE ATT&CK
>
> **Périmètre** : Statique uniquement. Basé sur les rapports de Phase 1-4.

## 📋 Résumé

| Catégorie | Techniques identifiées |
|---|---|
| **Execution** | T1059, T1129 |
| **Persistence** | T1547 (Cydia Substrate on iOS) |
| **Defense Evasion** | T1497 (VM/sandbox detection), T1027 (obfuscation), T1622 (debugger evasion) |
| **Credential Access** | T1555 (Apple Keychain) |
| **Discovery** | T1082, T1083, T1057 |
| **Lateral Movement** | N/A |
| **Collection** | T1005, T1530 |
| **Exfiltration** | T1041 |
| **Impact** | T1499 (NAND erase), T1561 (Activation Lock bypass) |
| **Network** | T1071, T1573, T1090 |

## 🎯 Tactics détaillées

### TA0002 — Execution

#### T1059 — Command and Scripting Interpreter
**Évidence** : L'application lance `idevicepair.exe` et `ideviceproxy.exe` via shell-out.
**Strings** : `cmd /c idevicepair pair`, `cmd /c ideviceproxy ...`
**Rapport** : `EXPERT_REPORT.md` §4, `CONSOLIDATED_AUDIT.md` §4
**Sévérité** : MEDIUM

#### T1129 — Shared Modules
**Évidence** : Chargement dynamique de DLLs (P/Invoke).
**Imports** : `idevicepair.exe`, `ideviceproxy.exe`, `libimobiledevice-1.0.dll`
**Rapport** : `CONSOLIDATED_AUDIT.md` §2
**Sévérité** : LOW

### TA0003 — Persistence

#### T1547 — Boot or Logon Autostart Execution
**Évidence** : Tweak Cydia Substrate se charge au démarrage de l'iPhone.
**Tweak** : `blackhound.dylib` dans `/Library/MobileSubstrate/DynamicLibraries/`
**Bundle** : `com.panyolsoft.blackhound`
**Sévérité** : HIGH (côté iOS uniquement)

### TA0005 — Defense Evasion

#### T1497 — Virtualization/Sandbox Evasion
**Évidence** : 5+ techniques anti-VM/sandbox :
- `CPUID` opcode (16 occurrences)
- `RDTSC` opcode (timing)
- `EnumWindows` (window scan)
- `RegOpenKey` / `RegQueryValueEx` (VM keys detection)
- `IsDebuggerPresent` (debugger detection)

**Rapport** : `EXPERT_REPORT.md` §3, `CONSOLIDATED_AUDIT.md` §6
**Sévérité** : HIGH

#### T1027 — Obfuscated Files or Information
**Évidence** : EXE WPF obfusqué, noms de types = hashes courts (`1BA52035`).
**Rapport** : `01_REPORTS/REPORT.md` §1
**Sévérité** : MEDIUM

#### T1622 — Debugger Evasion
**Évidence** :
- `IsDebuggerPresent` import direct (KERNEL32)
- `NtQueryInformationProcess` P/Invoke
- `NtQueryInformationFile` P/Invoke
- `mov rax, gs:[0x30]` (PEB access)

**Rapport** : `EXPERT_REPORT.md` §3
**Sévérité** : HIGH

### TA0006 — Credential Access

#### T1555 — Credentials from Password Stores
**Évidence** : Strings `keybag-2.db`, `SystemKeyBag`, `UserKeyBag`, `AFC (Apple File Conduit)`.
**Rapport** : `EXPERT_REPORT.md` §5.3
**Sévérité** : MEDIUM (côté iOS)

### TA0007 — Discovery

#### T1082 — System Information Discovery
**Évidence** : `iDevice_GetState`, requêtes lockdown multiples (DeviceName, ChipID, etc.)
**Strings** : `get_UniqueDeviceID`, `get_InternationalMobileEquipmentIdentity`
**Rapport** : `EXPERT_REPORT.md` §3.2
**Sévérité** : LOW

#### T1083 — File and Directory Discovery
**Évidence** : AFC, MobileBackup2, `/var/mobile`, `/var/Keychains`.
**Rapport** : `EXPERT_REPORT.md` §5.3, 5.4
**Sévérité** : LOW

#### T1057 — Process Discovery
**Évidence** : `MibTcpRowOwnerPid`, `EnumWindows`.
**Rapport** : `EXPERT_REPORT.md` §3.2
**Sévérité** : LOW

### TA0009 — Collection

#### T1005 — Data from Local System
**Évidence** : AFC (Apple File Conduit) lit les fichiers iPhone.
**Sévérité** : HIGH (sur iPhone cible)

#### T1530 — Data from Cloud Storage
**Évidence** : Envoi de données (IMEI, serial, UDID) au serveur `s13.iremovalpro.com`.
**Sévérité** : HIGH

### TA0010 — Exfiltration

#### T1041 — Exfiltration Over C2 Channel
**Évidence** : POST `auth3.ph`, `iact8.ph` vers `s13.iremovalpro.com`.
**Sévérité** : MEDIUM (télémétrie PC)

### TA0011 — Command and Control

#### T1071 — Application Layer Protocol
**Évidence** : HTTPS (port 443) vers `s13.iremovalpro.com`.
**Rapport** : `CONSOLIDATED_AUDIT.md` §7
**Sévérité** : HIGH

#### T1573 — Encrypted Channel
**Évidence** : TLS 1.2/1.3, `RemoteCertificateValidationCallback` bypass.
**Rapport** : `CONSOLIDATED_AUDIT.md` §6, 7
**Sévérité** : HIGH (validation SSL désactivée)

#### T1090 — Proxy
**Évidence** : `ideviceproxy --stream` (tunnel localhost ↔ iPhone).
**Rapport** : `EXPERT_REPORT.md` §4
**Sévérité** : MEDIUM

### TA0014 — Defense Evasion (Persistence)

#### T1547.011 — Plist Modification
**Évidence** : Écriture de `activation_record.plist` sur l'iPhone.
**Path** : `/var/mobile/Library/activation_records/`
**Sévérité** : HIGH (côté iOS)

### TA0034 — Impact

#### T1561 — Disk Wipe
**Évidence** : `A12Eraser` / `minaeraser12` — réécriture NAND.
**Sévérité** : CRITICAL (risque de brick iPhone)

#### T1499 — Endpoint Denial of Service
**Évidence** : La réécriture NAND rend l'iPhone inutilisable si procédure échoue.
**Sévérité** : MEDIUM (effet de bord)

#### T1656 — Impersonation
**Évidence** : Bypass Activation Lock + injection faux DeviceCertificate.
**Entitlements** : `com.apple.EXPLOIT.attestation.access`, `fairplay-client`
**Sévérité** : CRITICAL (anti-vol contourné)

## 🔍 Sigma-compatible queries

### Sigma rule — iRemoval PRO installation

```yaml
title: iRemoval PRO Installation
id: 8f4a1b3c-1234-5678-90ab-cdef12345678
status: experimental
description: Detects installation of iRemoval PRO bypass tool
references:
  - https://bypassfrpfiles.com
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\iRemoval PRO.exe'
    OriginalFileName:
      - 'iRemoval PRO.exe'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.impact
  - attack.t1561
```

### Sigma rule — s13.iremovalpro.com network contact

```yaml
title: iRemoval PRO C2 Communication
id: 8f4a1b3c-8765-4321-09ab-cdef12345678
status: experimental
description: Detects network communication to iRemoval PRO C2 server
logsource:
  category: dns_query
  product: zeek
detection:
  selection_query:
    query|endswith:
      - 's13.iremovalpro.com'
      - 'iremovalpro.com'
      - 'iremovalpro.co'
  condition: selection_query
level: high
tags:
  - attack.command_and_control
  - attack.t1071
  - attack.t1573
```

### Sigma rule — iRemoval PRO iOS tweak

```yaml
title: iRemoval PRO iOS Tweak (blackhound)
id: 8f4a1b3c-aaaa-bbbb-cccc-dddd12345678
status: experimental
description: Detects deployment of iRemoval PRO iOS tweak
logsource:
  category: file_event
  product: macos
detection:
  selection_create:
    TargetFilename:
      - '/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib'
  condition: selection_create
level: high
tags:
  - attack.persistence
  - attack.t1547
```

## 📊 Matrice ATT&CK

```
TA0001 - Initial Access        [   ]   n/a (out of scope)
TA0002 - Execution             [ X ]   T1059, T1129
TA0003 - Persistence           [ X ]   T1547 (iOS)
TA0004 - Privilege Escalation  [   ]   n/a
TA0005 - Defense Evasion      [ X ]   T1497, T1027, T1622
TA0006 - Credential Access     [ X ]   T1555 (iOS Keychain)
TA0007 - Discovery             [ X ]   T1082, T1083, T1057
TA0008 - Lateral Movement      [   ]   n/a
TA0009 - Collection            [ X ]   T1005, T1530
TA0010 - Exfiltration          [ X ]   T1041
TA0011 - C2                    [ X ]   T1071, T1573, T1090
TA0012 - Impact (Impact/CIA)   [ X ]   T1561, T1499, T1656
```

## 🔗 Navigation

- ⬆ [`../INDEX.md`](../INDEX.md) — Table des matières
- ⬇ [`ioc_catalog.md`](ioc_catalog.md) — Catalogue IoC
- ⬇ [`YARA_RULES.yar`](YARA_RULES.yar) — Règles YARA
- ⬇ [`SURICATA_RULES.rules`](SURICATA_RULES.rules) — Règles Suricata

---

**Basé sur** : MITRE ATT&CK v14
**Mis à jour** : 2026-06-22
**Périmètre** : Mapping défensif uniquement
