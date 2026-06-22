# EDR Detection Queries — iRemoval PRO Premium Edition v5.2

> Specific detection queries for popular EDR/SIEM platforms
>
> Author: Audit statique — 2026-06-22
> TLP: LEAKED
> Purpose: OFFENSIVE  detection for SOC analysts

## 📋 Plateformes supportées

| Plateforme | Section | Section |
|---|---|---|
| Microsoft Defender for Endpoint (MDE) | §1 | KQL queries |
| CrowdStrike Falcon | §2 | Search queries |
| SentinelOne | §3 | Deep Visibility queries |
| Splunk Enterprise Security | §4 | SPL queries |
| Elastic Security (ELK) | §5 | EQL/Kibana queries |
| Carbon Black (VMware) | §6 | Search queries |

---

## §1 — Microsoft Defender for Endpoint (MDE)

### 1.1 Détection du binaire (file event)

```kql
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName in~ ("iRemoval PRO.exe", "iremovalpro.dll")
   or FolderPath has "Bypassfrpfiles.com"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ReportId
```

### 1.2 Détection exécution processus

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("iRemoval PRO.exe", "iremovalpro.dll")
   or InitiatingProcessCommandLine has_any ("iRemoval PRO.exe", "iremovalpro.dll")
| where FileName in~ ("iRemoval PRO.exe", "iremovalpro.dll", "idevicepair.exe", "ideviceproxy.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
```

### 1.3 Détection réseau (C2)

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("s13.iremovalpro.com", "iremovalpro.com", "iremovalpro.co", "albert.apple.com")
| where InitiatingProcessFileName in~ ("iRemoval PRO.exe", "iremovalpro.dll")
| project Timestamp, DeviceName, RemoteUrl, RemotePort, InitiatingProcessFileName
```

### 1.4 Détection chargement DLL (image load)

```kql
DeviceImageLoadEvents
| where FileName in~ ("libimobiledevice-1.0.dll", "libusbmuxd-2.0.dll", "libplist-2.0.dll", "libssl-3-x64.dll", "libcrypto-3-x64.dll")
| where InitiatingProcessFileName in~ ("iRemoval PRO.exe", "iremovalpro.dll")
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName
```

### 1.5 Anti-debug (API calls)

```kql
DeviceEvents
| where ActionType == "NtQueryInformationProcess"
| where InitiatingProcessFileName in~ ("iRemoval PRO.exe", "iremovalpro.dll")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName
```

### 1.6 KQL avancé — corrélation

```kql
// Detect iRemoval PRO activity in 24h window
let iRemovalDevices = DeviceFileEvents
| where FileName in~ ("iRemoval PRO.exe", "iremovalpro.dll")
| where Timestamp > ago(24h)
| summarize by DeviceId;
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("iRemoval PRO.exe", "iremovalpro.dll")
    or FileName in~ ("idevicepair.exe", "ideviceproxy.exe")
| where InitiatingProcessCommandLine has_any ("com.iremovalpro.bypass", "com.panyolsoft.blackhound")
| join kind=inner iRemovalDevices on DeviceId
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

---

## §2 — CrowdStrike Falcon

### 2.1 Process execution

```
event_simpleName=ProcessRollup2
| search FileName="iRemoval PRO.exe" OR FileName="iremovalpro.dll"
| table _time, ComputerName, ImageFileName, CommandLine, ParentImageFileName
```

### 2.2 Network connection to C2

```
event_simpleName=NetworkConnection
| search RemoteAddressIP=* OR RemoteDomainName="*s13.iremovalpro.com*"
| search ImageFileName="*iRemoval PRO.exe" OR ImageFileName="*iremovalpro.dll"
| table _time, ComputerName, ImageFileName, RemoteAddressIP, RemotePort
```

### 2.3 File creation

```
event_simpleName=FileCreate
| search FileName="*iRemoval PRO.exe" OR FileName="*iremovalpro.dll"
| search ImageFileName="*explorer.exe" OR ImageFileName="*chrome.exe" OR ImageFileName="*firefox.exe"
| table _time, ComputerName, FileName, ImageFileName
```

### 2.4 DNS query (C2)

```
event_simpleName=DnsRequest
| search QueryName="*s13.iremovalpro.com*" OR QueryName="*iremovalpro.com*"
| table _time, ComputerName, ImageFileName, QueryName
```

### 2.5 Module load (libimobiledevice)

```
event_simpleName=ModuleLoad
| search ModuleName="*libimobiledevice*" OR ModuleName="*libusbmuxd*"
| search ImageFileName="*iRemoval PRO*" OR ImageFileName="*iremovalpro*"
| table _time, ComputerName, ModuleName, ImageFileName
```

---

## §3 — SentinelOne

### 3.1 Process execution

```
TgtFileName contains "iRemoval PRO.exe" or TgtFileName contains "iremovalpro.dll"
| table EventTime, ComputerName, TgtProcName, TgtProcCmdLine, ParentProcName
```

### 3.2 Network connection

```
SrcProcName contains "iRemoval PRO" or SrcProcName contains "iremovalpro"
DNS Resolved contains "s13.iremovalpro.com" or URL contains "iremovalpro.com"
| table EventTime, ComputerName, SrcProcName, DnsRes, Url
```

### 3.3 File creation

```
TgtFileName contains "iRemoval PRO.exe" or TgtFileName contains "iremovalpro.dll"
EventType = "File Create"
| table EventTime, ComputerName, TgtFileName, TgtFilePath
```

---

## §4 — Splunk Enterprise Security

### 4.1 File detection

```spl
index=windows EventCode=4663 ObjectName="*iRemoval PRO.exe" OR ObjectName="*iremovalpro.dll"
| stats count by ComputerName, ObjectName, SubjectUserName, _time
```

### 4.2 Process detection

```spl
index=windows EventCode=4688 (New_Process_Name="*iRemoval PRO.exe" OR New_Process_Name="*iremovalpro.dll")
| stats count by ComputerName, New_Process_Name, Command_Line, Parent_Process_Name
```

### 4.3 Network detection (Sysmon)

```spl
index=windows EventCode=3 (Image="*iRemoval PRO.exe" OR Image="*iremovalpro.dll")
| stats count by ComputerName, DestinationHostname, DestinationPort, Image
| where DestinationHostname="s13.iremovalpro.com" OR DestinationHostname="*.iremovalpro.com"
```

### 4.4 DNS detection (Sysmon)

```spl
index=windows EventCode=22 (QueryName="*s13.iremovalpro.com*" OR QueryName="*iremovalpro.com*")
| stats count by ComputerName, QueryName, Image
```

### 4.5 DLL load (Sysmon)

```spl
index=windows EventCode=7 (ImageLoaded="*libimobiledevice*" OR ImageLoaded="*libusbmuxd*")
    (Image="*iRemoval PRO*" OR Image="*iremovalpro*")
| stats count by ComputerName, ImageLoaded, Image
```

### 4.6 Splunk ES notable event (correlation)

```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes
  where Processes.process_name="iRemoval PRO.exe" OR Processes.process_name="iremovalpro.dll"
  by Processes.dest, Processes.process_name, Processes.user
| join type=left
  [ | tstats summariesonly=t count from datamodel=Endpoint.Network_Traffic
    where Network_Traffic.dest_hostname="*s13.iremovalpro.com*"
    by Network_Traffic.dest_hostname, Network_Traffic.src ]
| where count > 0
```

---

## §5 — Elastic Security (ELK)

### 5.1 Process detection (EQL)

```eql
process where process.name == "iRemoval PRO.exe" or process.name == "iremovalpro.dll"
```

### 5.2 File creation

```eql
file where file.name == "iRemoval PRO.exe" or file.name == "iremovalpro.dll"
```

### 5.3 Network connection

```eql
network where destination.domain == "s13.iremovalpro.com" or destination.domain == "iremovalpro.com"
```

### 5.4 DLL load (Windows)

```eql
library where dll.name == "libimobiledevice-1.0.dll" and process.name == "iRemoval PRO.exe"
```

### 5.5 Kibana KQL

```
process.name: "iRemoval PRO.exe" OR process.name: "iremovalpro.dll"
```

```
dns.question.name: *s13.iremovalpro.com*
```

```
file.path: *Bypassfrpfiles.com*iRemoval*
```

---

## §6 — Carbon Black (VMware)

### 6.1 Process detection

```
process_name:iRemoval PRO.exe
```

### 6.2 Network detection

```
netconn_domain:s13.iremovalpro.com
```

### 6.3 File detection

```
filemod_name:iRemoval PRO.exe OR filemod_name:iremovalpro.dll
```

### 6.4 Module load (Windows)

```
modload_name:libimobiledevice-1.0.dll AND modload_name:libusbmuxd-2.0.dll
```

---

## 📋 Tableau de correspondance des IoC

| Type | Valeur | Source |
|---|---|---|
| SHA-256 EXE | `07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7` | binaire |
| SHA-256 DLL | `08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141` | binaire |
| Domaine C2 | `s13.iremovalpro.com` | strings |
| Domaine site | `iremovalpro.com` | strings |
| Domaine site | `iremovalpro.co` | strings |
| Bundle iOS | `com.iremovalpro.bypass` | strings |
| Bundle tweak | `com.panyolsoft.blackhound` | strings |
| Port SSH | 22 | strings |
| Port lockdown | 62078 | protocol |
| Build marker | `Blackhound iRemovalPro Public build 0.7.1` | strings |
| Success msg | `iDevice Activated Succesfully` | strings |

---

## 🔗 Navigation

- ⬆ [`../INDEX.md`](../INDEX.md)
- ⬇ [`YARA_RULES.yar`](YARA_RULES.yar) — YARA
- ⬇ [`SURICATA_RULES.rules`](SURICATA_RULES.rules) — Suricata
- ⬇ [`SIGMA_RULES.yml`](SIGMA_RULES.yml) — Sigma
- ⬇ [`MITRE_MAPPING.md`](MITRE_MAPPING.md) — MITRE

---

**Cible** : Analystes SOC / EDR / SIEM
**Mis à jour** : 2026-06-22
**Périmètre** : Détection défensive uniquement
