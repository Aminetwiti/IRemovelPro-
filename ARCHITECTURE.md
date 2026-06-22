# Architecture du projet — Diagrammes

> Vues architecturales à différents niveaux (PC, iOS, réseau)

## Vue d'ensemble du système

```
┌──────────────────────────────────────────────────────────────────────┐
│                       ÉCOSYSTÈME iREMOVAL PRO                        │
└──────────────────────────────────────────────────────────────────────┘

┌─────────────────────┐                    ┌──────────────────────────┐
│    PC Windows       │   USB + HTTPS     │   iPhone (USB)          │
│  ┌───────────────┐  │ ────────────────▶ │  ┌────────────────────┐  │
│  │  UI WPF       │  │                   │  │  iOS 12+           │  │
│  │  (iRemoval    │  │                   │  │  ┌──────────────┐  │  │
│  │   PRO.exe)    │  │                   │  │  │ blackhound   │  │  │
│  │               │  │                   │  │  │ .dylib       │  │  │
│  │  ┌──────────┐ │  │                   │  │  └──────────────┘  │  │
│  │  │ Driver   │ │  │                   │  │  ┌──────────────┐  │  │
│  │  │ Class    │ │  │                   │  │  │ minaeraser12 │  │  │
│  │  └──────────┘ │  │                   │  │  └──────────────┘  │  │
│  │       │        │  │                   │  │  ┌──────────────┐  │  │
│  │  ┌────▼─────┐ │  │                   │  │  │ rc           │  │  │
│  │  │libiOS    │ │  │                   │  │  └──────────────┘  │  │
│  │  │.dll      │ │  │                   │  │  ┌──────────────┐  │  │
│  │  └──────────┘ │  │                   │  │  │mobileactd    │  │  │
│  │               │  │                   │  │  │(hooked)      │  │  │
│  └───────────────┘  │                   │  └────────────────────┘  │
└─────────────────────┘                   └──────────────────────────┘
            │                                          │
            │                                          │
            │ HTTPS / TCP/443                          │
            ▼                                          ▼
   ┌────────────────────────────────────────────────────────────┐
   │                   s13.iremovalpro.com                        │
   │  ┌────────────────────────────────────────────────────────┐ │
   │  │   12 endpoints (auth, checkm8, iact, mf5/6/7, pub)      │ │
   │  └────────────────────────────────────────────────────────┘ │
   └────────────────────────────────────────────────────────────┘
            │
            │ HTTPS
            ▼
   ┌────────────────────────────────────────────────────────────┐
   │            albert.apple.com/deviceservices/drmHandshake      │
   │         (endpoint Apple officiel, cible du bypass)          │
   └────────────────────────────────────────────────────────────┘
```

## Architecture PC — Composition des binaires

```
iRemoval PRO.exe (2.7 MB, x86)        iremovalpro.dll (30 MB, x64)
┌──────────────────────────┐          ┌──────────────────────────────┐
│ .NET Framework 4.0 WPF   │          │ .NET 8 NativeAOT             │
│ ┌──────────────────────┐ │          │ ┌──────────────────────────┐ │
│ │ iRemovalProWPF       │ │          │ │ iremovalpro              │ │
│ │ - MainWindow (XAML)  │ │          │ │                          │ │
│ │ - App                │ │          │ │ ┌────────────────────┐  │ │
│ │ - 313 types          │ │          │ │ │ .NET 8 Runtime     │  │ │
│ │ - 1821 methods       │ │          │ │ │ (~12 MB embarqué)  │  │ │
│ │ - (obfusqué)         │ │          │ │ └────────────────────┘  │ │
│ └──────────────────────┘ │          │ │ ┌────────────────────┐  │ │
│ ┌──────────────────────┐ │          │ │ │ Driver class       │  │ │
│ │ Imports:             │ │  P/Invoke│ │ │ - 13 iDevice mthds │  │ │
│ │ - mscoree.dll        │ ├─────────▶│ │ │ - 5 state machines │  │ │
│ │   (_CorExeMain)      │ │          │ │ └────────────────────┘  │ │
│ └──────────────────────┘ │          │ │ ┌────────────────────┐  │ │
│                          │          │ │ │ Libs tierces       │  │ │
│                          │          │ │ │ - RestSharp        │  │ │
│                          │          │ │ │ - Renci.SshNet     │  │ │
│                          │          │ │ │ - QRCoder          │  │ │
│                          │          │ │ └────────────────────┘  │ │
│                          │          │ │ ┌────────────────────┐  │ │
│                          │          │ │ │ Payloads iOS       │  │ │
│                          │          │ │ │ embarqués (Mach-O)│  │ │
│                          │          │ │ └────────────────────┘  │ │
│                          │          │ └──────────────────────────┘ │
└──────────────────────────┘          └──────────────────────────────┘

ref/toolkits/  (30 MB, x64)
┌──────────────────────────────┐
│ - idevicepair.exe            │  P/Invoke via iremovalpro.dll
│ - ideviceproxy.exe           │  (chargement dynamique)
│ - libimobiledevice-1.0.dll   │
│ - libusbmuxd-2.0.dll         │
│ - libplist-2.0.dll           │
│ - libplist++-2.0.dll         │
│ - libssl-3-x64.dll           │
│ - libcrypto-3-x64.dll        │
│ - libimobiledevice-glue      │
└──────────────────────────────┘
```

## Architecture iOS — Couches protocolaires

```
┌─────────────────────────────────────────────────────────────────────┐
│                       iPhone (iOS 12+)                               │
└─────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────────┐
                    │      Applications tierces    │
                    │  com.iremovalpro.bypass     │
                    └─────────────┬───────────────┘
                                  │ utilise
                    ┌─────────────▼───────────────┐
                    │      Frameworks publics     │
                    │  MobileActivation.framework │
                    │  (PRIVATE)                  │
                    └─────────────┬───────────────┘
                                  │ hook par
                    ┌─────────────▼───────────────┐
                    │   blackhound.dylib (Theos)  │ ◄── déployé via SSH
                    │   Cydia Substrate hooks      │
                    └─────────────┬───────────────┘
                                  │ intercepte
                    ┌─────────────▼───────────────┐
                    │  com.apple.mobileactivationd│ ◄── hooké!
                    │  - validateActivationDataSign│
                    │  - handleActivationInfo     │
                    └─────────────┬───────────────┘
                                  │ communique avec
                    ┌─────────────▼───────────────┐
                    │  lockdownd (via usbmuxd)   │ ◄── protocole plist over USB
                    │  + AFC (Apple File Conduit) │
                    │  + MobileBackup2           │
                    │  + Installation Proxy      │
                    └─────────────────────────────┘
```

## Architecture réseau — Flux d'activation

```
┌──────────┐                                    ┌─────────────────────────┐
│  PC      │   1. Detect USB                    │  s13.iremovalpro.com    │
│  (USER)  ├───────────────────────────────────▶│                         │
│          │   2. Get device info              │  HTTPS REST API         │
│          ├───────────────────────────────────▶│                         │
│          │                                    │                         │
│          │   3. POST /auth3.ph               │                         │
│          ├───────────────────────────────────▶│  Authentication         │
│          │   ◀────── token + credits ─────────│                         │
│          │                                    │                         │
│          │   4. POST /iact8.ph               │                         │
│          ├───────────────────────────────────▶│  Request activation     │
│          │   { device, signature, payload }  │  ticket                 │
│          │   ◀────── signed ticket ──────────│                         │
│          │                                    │                         │
│          │   5. SSH tunnel to iPhone         │                         │
│          ├──────────[localhost:22]──────────▶│                         │
│          │                                    │                         │
│          │   6. Deploy blackhound.dylib       │                         │
│          ├───────────────────────────────────▶│                         │
│          │                                    │                         │
│          │   7. Restart mobileactivationd    │                         │
│          ├───────────────────────────────────▶│                         │
│          │                                    │                         │
│          │   8. Inject activation_record.plist│                         │
│          ├───────────────────────────────────▶│                         │
│          │                                    │                         │
│          │   9. iPhone says "Activated"      │                         │
│          │◀───────────────────────────────────┤                         │
└──────────┘                                    └─────────────────────────┘

       │ HTTPS handshake
       ▼
┌──────────────────────────────────────┐
│ albert.apple.com/deviceservices/     │ ◄── Apple officiel
│            drmHandshake                │     (utilisé par le bypass)
└──────────────────────────────────────┘
```

## Couches d'abstraction — appel réseau

```
┌──────────────────────────────────────────────────────────────────┐
│                       iremovalpro.dll                            │
│                                                                  │
│  ┌────────────────┐                                              │
│  │ Driver class   │                                              │
│  └────────┬───────┘                                              │
│           │ utilise                                                │
│  ┌────────▼───────┐                                              │
│  │ .NET 8 HTTP    │                                              │
│  │ (HttpClient)   │                                              │
│  └────────┬───────┘                                              │
│           │ wraps                                                  │
│  ┌────────▼───────┐                                              │
│  │ System.Net.   │                                              │
│  │ Quic/HTTP/3   │                                              │
│  └────────┬───────┘                                              │
│           │ utilise                                                │
│  ┌────────▼───────┐                                              │
│  │ Windows       │                                              │
│  │ WinHTTP       │                                              │
│  └────────┬───────┘                                              │
│           │                                                          │
└───────────┼──────────────────────────────────────────────────────────┘
            │
            ▼ TCP/443
   ┌────────────────────┐
   │  s13.iremovalpro.  │
   │       com          │
   │  (TLS 1.2/1.3)     │
   └────────────────────┘
```

## Diagramme de classes simplifié (Driver)

```
                    ┌─────────────────────┐
                    │   iremovalpro.      │
                    │   <Module>          │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │      Driver         │
                    │  (classe principale)│
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
┌───────▼────────┐  ┌──────────▼──────────┐  ┌──────────▼──────────┐
│  CommonConnect │  │   iDevice_Activate  │  │   Erase_V2          │
│  Device        │  │   (bypass iCloud)   │  │   (NAND wipe)       │
└───────┬────────┘  └──────────┬──────────┘  └──────────┬──────────┘
        │                      │                      │
        ▼                      ▼                      ▼
   libimobiledevice     SSH tunnel + REST        blackhound.dylib
   (USB)                (s13.iremovalpro.com)    (Cydia Substrate)
```

---

**Note** : Ces diagrammes sont produits à partir de l'analyse statique des binaires.
Pour la sémantique runtime, consulter les rapports dans `01_REPORTS/`.
