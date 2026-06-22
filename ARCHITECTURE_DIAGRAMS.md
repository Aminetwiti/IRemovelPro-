# Mermaid Diagrams — iRemoval PRO Premium Edition v5.2

> Visualisations de l'architecture, du flux d'activation, et de la topologie réseau.
>
> **Source** : [`ARCHITECTURE.mmd`](../ARCHITECTURE.mmd)
> **Visualiseur recommandé** : https://mermaid.live/ ou tout IDE avec extension Mermaid

---

## 1. Architecture des composants

```mermaid
flowchart TB
    subgraph PC["PC Windows"]
        direction TB
        EXE["iRemoval PRO.exe<br/>WPF .NET Framework 4.0<br/>x86 (PE32)"]
        DLL["iremovalpro.dll<br/>.NET 8 NativeAOT<br/>x64 (PE32+)"]
        TOOL["ref/toolkits/<br/>libimobiledevice<br/>idevicepair / ideviceproxy"]
    end

    subgraph iPhone["iPhone (iOS 12+)"]
        direction TB
        Tweak["blackhound.dylib<br/>Tweak Cydia Substrate"]
        Eraser["minaeraser12<br/>A12+ NAND eraser"]
        Helper["com.iremovalpro.bypass<br/>App helper iOS"]
        Daemon["MobileActivationDaemon<br/>DAEMON iOS HOOKÉ"]
    end

    subgraph Srv["Serveurs"]
        C2["s13.iremovalpro.com<br/>9 endpoints .ph/.tx"]
        Apple["albert.apple.com<br/>/drmHandshak"]
    end

    EXE --> DLL
    DLL --> TOOL
    TOOL --> USB
    USB --> iPhone
    DLL --> Tweak
    Tweak --> Daemon
    DLL --> Eraser
    Helper --> Daemon
    DLL --> HTTPS
    HTTPS --> C2
    Daemon --> Apple
    C2 --> DLL
    DLL --> plist
    plist --> Daemon

    classDef malicious fill:#ffe6e6,stroke:#cc0000,color:#000
    classDef official fill:#e6f3ff,stroke:#003366,color:#000
    classDef edge fill:#fff0e6,stroke:#cc6600,color:#000
    class Tweak,Eraser,Helper,Daemon malicious
    class C2 official
    class EXE,DLL,TOOL edge
```

**Légende** :
- 🔴 Rouge = Composants iOS malveillants (tweak, daemon hooké)
- 🔵 Bleu = Serveur C2
- 🟠 Orange = Binaire de l'outil (PC)

---

## 2. Flux d'activation bypass (séquence)

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant PC as PC (iRemoval PRO)
    participant SRV as s13.iremovalpro.com
    participant iP as iPhone (iOS)
    participant Apple as albert.apple.com

    U->>PC: Brancher iPhone
    PC->>iP: libusbmuxd detect
    PC->>iP: idevicepair pair
    PC->>iP: lockdown query
    iP-->>PC: DeviceInfo

    U->>PC: Click "Activate"
    PC->>SRV: POST /auth3.ph
    SRV-->>PC: token
    PC->>SRV: POST /iact8.ph
    SRV-->>PC: signed ticket

    PC->>iP: SSH tunnel
    PC->>iP: Deploy blackhound
    PC->>iP: Deploy minaeraser12
    PC->>iP: NAND wipe

    PC->>iP: Write activation_record.plist
    Note over iP: Hooked validation<br/>returns TRUE
    iP->>Apple: POST /drmHandshak
    Apple-->>iP: cert
    Note over iP: Hooked handler<br/>returns Success
    iP-->>PC: Activated

    PC->>iP: Remove MDM profiles
    PC->>iP: Bypass MEID
    PC-->>U: Success
```

---

## 3. Diagramme de classes

```mermaid
classDiagram
    class Driver {
        +BypassMeidSignal() Task
        +CommonConnectDevice() Task
        +CheckIOS() bool
        +Install() Task
        +iDevice_Pair()
        +iDevice_Tnl()
        +iDevice_Activate()
        +iDevice_Deactivate()
        +iDevice_LnchV2()
        +iDevice_GetState()
        +iDevice_EnableDevMode()
        +iDevice_Restart()
        +iDevice_RemoveProfiles()
        +Erase_V2()
        +ExecuteAsAdmin()
        +SecureClearAndCollect()
        +Firewall_iDeviceProxy()
    }

    class iDevice {
        -UDID: string
        -SerialNumber: string
        -IMEI: string
        -IMEI2: string
        -MEID: string
        -ECID: ulong
        +Pair() bool
        +GetState() State
        +Activate() bool
    }

    class iRemovalRecord {
        +Record: byte[]
        +Timestamp: DateTime
    }

    class iRemovalSignature {
        +Signature: byte[]
        +Validate(data) bool
    }

    class BypassMeidSignal {
        +Bypass() bool
        +Restore() bool
    }

    class Eraser {
        +Erase_V2() bool
    }

    Driver --> iDevice
    Driver --> BypassMeidSignal
    Driver --> Eraser
    Driver --> iRemovalRecord
    iRemovalRecord --> iRemovalSignature
```

---

## 4. Techniques anti-debug

```mermaid
flowchart LR
    subgraph Input["Anti-Debug Triggers"]
        D1[IsDebuggerPresent]
        D2[NtQueryInformationProcess]
        D3[CPUID - hypervisor]
        D4[RDTSC - timing]
        D5[PEB access]
        D6[RegOpenKey - VM]
    end

    subgraph Check["Detection"]
        C1{VM/HV?}
        C2{Debugger?}
        C3{Timing anomaly?}
    end

    subgraph Action["Action"]
        A1[Continue]
        A2[Quit/Hide]
    end

    D1 --> C2
    D2 --> C2
    D3 --> C1
    D4 --> C3
    D5 --> C2
    D6 --> C1

    C1 -->|Yes| A2
    C2 -->|Yes| A2
    C3 -->|Yes| A2
    C1 -->|No| A1
    C2 -->|No| A1
    C3 -->|No| A1
```

---

## 5. Topologie réseau C2

```mermaid
flowchart LR
    subgraph Attacker["PC Client"]
        APP["iRemoval PRO<br/>exe + dll"]
    end

    subgraph Internet
        C2[("s13.iremovalpro.com<br/>9 endpoints .ph")]
        Pay[("iremovalpro.com<br/>Payax0.ph")]
        TG[("t.me/iremovalpro")]
        Trust[("trustpilot.com<br/>iremovalpro.co")]
    end

    subgraph Apple
        Albert[("albert.apple.com<br/>/drmHandshak")]
    end

    subgraph Defense["IDS / SIEM"]
        Suricata[Suricata]
        YARA[YARA]
        Sigma[Sigma]
    end

    APP -->|HTTPS| C2
    APP -->|PayPal| Pay
    APP -->|TLS| Albert
    APP -->|TG| TG
    APP -->|HTTP| Trust

    Suricata -.->|detect| C2
    YARA -.->|scan| APP
    Sigma -.->|detect| APP
```

---

## 🔧 Utilisation

### Visualisation en ligne
1. Ouvrir https://mermaid.live/
2. Copier le contenu de `ARCHITECTURE.mmd`
3. Visualiser en temps réel

### Visualisation IDE (VS Code)
- Installer l'extension "Markdown Preview Mermaid Support"
- Ouvrir ce fichier `.md` en preview

### Export PNG/SVG
- Via Mermaid CLI : `mmdc -i ARCHITECTURE.mmd -o diagram.png`
- Via https://mermaid.live/ (bouton export)

---

**Mis à jour** : 2026-06-22

