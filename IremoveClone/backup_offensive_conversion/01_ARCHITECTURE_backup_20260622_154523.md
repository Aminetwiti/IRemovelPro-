# Architecture technique — iRemovalClone v1.0

> **Architecture détaillée** — composants, flux, protocoles, sécurité
>
> **Date** : 2026-06-22
> **Base de référence** : Audit statique d'iRemoval PRO v5.2 (`../01_REPORTS/`)

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Composants PC (Windows)](#2-composants-pc-windows)
3. [Composants iOS (device)](#3-composants-ios-device)
4. [Composants Backend](#4-composants-backend)
5. [Protocoles & flux détaillés](#5-protocoles--flux-détaillés)
6. [Sécurité & anti-détection](#6-sécurité--anti-détection)
7. [Persistance & stockage](#7-persistance--stockage)
8. [Observabilité & logging](#8-observabilité--logging)
9. [Diagrammes](#9-diagrammes)

---

## 1. Vue d'ensemble

### 1.1 Système en 3 tiers

```
┌────────────────────────────────────────────────────────────────────────┐
│                                                                        │
│   ┌──────────────┐       USB        ┌─────────────┐       HTTPS      │
│   │   PC Client  │ ◄───────────────►│  iPhone     │                  │
│   │  (Windows)   │     SSH tunnel   │  jailbreaké │                  │
│   │              │ ◄───────────────►│             │                  │
│   └──────┬───────┘                  └─────────────┘                  │
│          │                                                             │
│          │ REST + HMAC                                                │
│          │                                                             │
│   ┌──────▼────────┐                                                   │
│   │   Backend     │                                                   │
│   │   (cloud)     │                                                   │
│   └───────────────┘                                                   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Contraintes

| Contrainte | Implication |
|---|---|
| Latence bypass < 8 min | Toute la chaîne optimisée |
| Backend 99.5% uptime | HA multi-region |
| Anti-EDR obligatoire | Native AOT + obfuscation |
| Compatibilité large | Multi-SOC A5 → A17 |
| Pas d'install admin | Click-to-run (self-contained) |

---

## 2. Composants PC (Windows)

### 2.1 Vue logique

```
┌─────────────────────────────────────────────────────────────────┐
│                    iRemovalClone.PC                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  IRemovalClone.UI                  (.NET Framework 4.8)    │ │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │ │
│  │  │ Views (XAML)│  │ ViewModels   │  │ Services         │ │ │
│  │  │ - MainWindow│  │ - MainVM     │  │ - Navigation     │ │ │
│  │  │ - Settings  │  │ - DeviceVM   │  │ - Theme          │ │ │
│  │  │ - LogsView  │  │ - LogVM      │  │ - Update         │ │ │
│  │  └─────────────┘  └──────────────┘  └──────────────────┘ │ │
│  └──────────────────────┬──────────────────────────────────────┘ │
│                         │ MVVM (CommunityToolkit.Mvvm)          │
│  ┌──────────────────────▼──────────────────────────────────────┐ │
│  │  IRemovalClone.Core              (.NET 8 NativeAOT x64)    │ │
│  │  ┌──────────────────────────────────────────────────────┐   │ │
│  │  │ Domain Layer                                         │   │ │
│  │  │ - Entities (Device, ActivationTicket, Session)       │   │ │
│  │  │ - Value Objects (UDID, ECID, IMEI)                   │   │ │
│  │  │ - Domain Services (DeviceDetection, BypassFlow)      │   │ │
│  │  └──────────────────────────────────────────────────────┘   │ │
│  │  ┌──────────────────────────────────────────────────────┐   │ │
│  │  │ Infrastructure Layer                                  │   │ │
│  │  │ - USB (libusbmuxd P/Invoke)                           │   │ │
│  │  │ - SSH (Renci.SshNet)                                  │   │ │
│  │  │ - HTTP (HttpClient + Polly)                           │   │ │
│  │  │ - Crypto (BouncyCastle)                               │   │ │
│  │  │ - Logging (Serilog → file + backend)                  │   │ │
│  │  └──────────────────────────────────────────────────────┘   │ │
│  │  ┌──────────────────────────────────────────────────────┐   │ │
│  │  │ Application Layer                                     │   │ │
│  │  │ - Driver (13 iDevice_* methods)                       │   │ │
│  │  │ - ActivationService (iact8.php flow)                  │   │ │
│  │  │ - JailbreakService (checkm8 + palera1n)               │   │ │
│  │  │ - NandeEraserService (minaeraser12 deploy)            │   │ │
│  │  │ - TweakDeployer (blackhound.dylib)                    │   │ │
│  │  └──────────────────────────────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Native Libraries (x64)                                    │ │
│  │  - libusbmuxd-2.0.dll     (USB multiplexing)               │ │
│  │  - libimobiledevice-1.0.dll (iDevice protocol)              │ │
│  │  - libideviceactivation.dll (activation protocol)           │ │
│  │  - libssh2.dll            (SSH for .NET)                   │ │
│  │  - libcrypto-3.dll        (OpenSSL)                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Driver class — 13 méthodes

Référence : `01_REPORTS/PHASE4B_DRIVER_ANALYSIS.md`

| # | Méthode | Input | Output | Endpoint | Notes |
|---|---|---|---|---|---|
| 1 | `CommonConnectDevice` | — | `DeviceInfo` | libusbmuxd | Détection USB |
| 2 | `iDevice_GetState` | UDID | `ActivationState` | lockdownd | Query state |
| 3 | `iDevice_Activate` | DeviceInfo, ticket | Status | iact8.php + lockdownd | Bypass principal |
| 4 | `iDevice_Deactivate` | UDID | Status | lockdownd | De-register |
| 5 | `iDevice_Restart` | UDID | Status | lockdownd | Reboot |
| 6 | `iDevice_LnchV2` | UDID, app_id | Status | installd | Launch service |
| 7 | `iDevice_Tnl` | UDID | SSHClient | SSH (22) | SSH tunnel |
| 8 | `iDevice_EnableDevMode` | UDID | Status | lockdownd | Dev mode on |
| 9 | `iDevice_RemoveProfiles` | UDID | Status | misagent | MDM removal |
| 10 | `CreateActivationSessionInfo` | DeviceInfo | SessionInfo | iact8.php | Init session |
| 11 | `CreateActivationInfoWithSession` | SessionInfo | ActivationInfo | iact8.php | Build ticket |
| 12 | `ActivateWithSession` | SessionInfo, ticket | Status | iact8.php + lockdownd | Submit |
| 13 | `GetActivationState` | UDID | ActivationState | lockdownd | Post-bypass |
| 14 | `Firewall_iDeviceProxy` | UDID | Proxy | — | USB firewall bypass |
| 15 | `Erase_V2` | UDID | Status | SSH + minaeraser12 | NAND wipe |
| 16 | `BypassMeidSignal` | IMEI, MEID | Status | mf5/6/7.php | MEID modification |
| 17 | `ExecuteAsAdmin` | cmd | Output | ShellExecute | Privilege escalation |

> Note : 13 méthodes strictes + 4 helpers = **17 méthodes totales**

### 2.3 Stack technique PC

| Composant | Technologie | Version |
|---|---|---|
| **UI Framework** | WPF (Windows Presentation Foundation) | .NET 4.8 |
| **MVVM** | CommunityToolkit.Mvvm | 8.3+ |
| **UI Theme** | ModernWpf (fork FluentDesign) | 0.10+ |
| **Core Engine** | .NET 8 NativeAOT | 8.0 LTS |
| **HTTP** | HttpClient (built-in) | — |
| **SSH** | SSH.NET | 2024.2+ |
| **Crypto** | BouncyCastle.Cryptography | 2.4+ |
| **Logging** | Serilog | 4.0+ |
| **DI Container** | Microsoft.Extensions.Hosting | 8.0+ |
| **Testing** | xUnit + FluentAssertions + NSubstitute | latest |

### 2.4 Structure projet PC

```
src/
└── IRemovalClone/
    ├── IRemovalClone.UI/                  # WPF .NET Framework 4.8
    │   ├── Views/
    │   │   ├── MainWindow.xaml
    │   │   ├── SettingsWindow.xaml
    │   │   └── LogViewerWindow.xaml
    │   ├── ViewModels/
    │   │   ├── MainViewModel.cs
    │   │   ├── DeviceViewModel.cs
    │   │   └── LogViewModel.cs
    │   ├── Converters/
    │   │   └── DeviceStateToBrushConverter.cs
    │   ├── Resources/
    │   │   ├── Strings.resx
    │   │   └── Icons/
    │   ├── App.xaml / App.xaml.cs
    │   └── IRemovalClone.UI.csproj
    │
    ├── IRemovalClone.Core/                 # .NET 8 NativeAOT
    │   ├── Domain/
    │   │   ├── Entities/
    │   │   │   ├── Device.cs
    │   │   │   ├── ActivationTicket.cs
    │   │   │   ├── ActivationSession.cs
    │   │   │   └── BypassResult.cs
    │   │   ├── ValueObjects/
    │   │   │   ├── UDID.cs
    │   │   │   ├── ECID.cs
    │   │   │   ├── IMEI.cs
    │   │   │   └── MEID.cs
    │   │   └── Services/
    │   │       ├── IDeviceDetectionService.cs
    │   │       ├── IBypassFlowService.cs
    │   │       └── IActivationService.cs
    │   ├── Application/
    │   │   ├── Driver/
    │   │   │   ├── IDriver.cs
    │   │   │   └── Driver.cs
    │   │   ├── Services/
    │   │   │   ├── ActivationService.cs
    │   │   │   ├── JailbreakService.cs
    │   │   │   ├── NandeEraserService.cs
    │   │   │   ├── TweakDeployer.cs
    │   │   │   └── BypassMeidSignalService.cs
    │   │   └── Common/
    │   │       ├── DeviceInfo.cs
    │   │       └── ActivationState.cs
    │   ├── Infrastructure/
    │   │   ├── Usb/
    │   │   │   ├── LibUsbmuxdInterop.cs
    │   │   │   └── UsbDeviceEnumerator.cs
    │   │   ├── Ssh/
    │   │   │   ├── ISshClient.cs
    │   │   │   └── SshNetClient.cs
    │   │   ├── Http/
    │   │   │   ├── IBackendApi.cs
    │   │   │   ├── BackendApi.cs
    │   │   │   └── HmacAuthenticationHandler.cs
    │   │   ├── Crypto/
    │   │   │   ├── IHmacSigner.cs
    │   │   │   └── HmacSha256Signer.cs
    │   │   └── Logging/
    │   │       ├── ILoggerConfiguration.cs
    │   │       └── FileAndBackendLogger.cs
    │   └── IRemovalClone.Core.csproj
    │
    ├── IRemovalClone.Native/              # P/Invoke wrappers
    │   ├── libusbmuxd/
    │   ├── libimobiledevice/
    │   └── libideviceactivation/
    │
    └── IRemovalClone.sln
```

---

## 3. Composants iOS (device)

### 3.1 Architecture iOS

```
┌─────────────────────────────────────────────────────────────────┐
│                       iPhone jailbreaké                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Cydia Substrate (MobileSubstrate.dylib)                 │   │
│  │  - Hook engine (logos/theos)                             │   │
│  └──────────────────────────────────────────────────────────┘   │
│            ▲                                                     │
│            │ MSHookFunction / MSHookMessageEx                   │
│  ┌─────────┴────────────────────────────────────────────────┐   │
│  │  blackhound.dylib (clone)                                │   │
│  │  ┌──────────────────────────────────────────────────┐    │   │
│  │  │ Hook Layer 1: RSA Verification                   │    │   │
│  │  │ - _replace_validateActivationDataSignature       │    │   │
│  │  │ - Uses embedded RSA-1024 public key              │    │   │
│  │  │ - Adds iRemovalRecord + iRemovalSignature        │    │   │
│  │  ├──────────────────────────────────────────────────┤    │   │
│  │  │ Hook Layer 2: Trust Evaluation                   │    │   │
│  │  │ - _replace_SecTrustEvaluateWithError             │    │   │
│  │  │ - Always returns errSecSuccess                   │    │   │
│  │  ├──────────────────────────────────────────────────┤    │   │
│  │  │ Hook Layer 3: Activation Info                    │    │   │
│  │  │ - _replace_handleActivationInfo                  │    │   │
│  │  │ - Injects custom activation record                │    │   │
│  │  └──────────────────────────────────────────────────┘    │   │
│  └───────────────────────────────────────────────────────────┘   │
│            ▲                                                     │
│            │ MobileActivationDaemon calls                      │
│  ┌─────────┴────────────────────────────────────────────────┐   │
│  │  MobileActivationDaemon (système iOS)                   │   │
│  │  - validateActivationDataSignature                       │   │
│  │  - handleActivationInfo                                  │   │
│  │  - getActivationState                                    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  minaeraser12 (clone)                                    │   │
│  │  - NAND wipe via IOKit + AppleNAND                       │   │
│  │  - Targets A12-A17 Pro SoC                              │   │
│  │  - 30-180s selon stockage                               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  rc (restore helper)                                     │   │
│  │  - idevicerestore wrapper                               │   │
│  │  - IPSW download + verify                               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  SSH daemon (dropbear)                                  │   │
│  │  - Port 22                                               │   │
│  │  - Auth: key-based (generated at deploy)                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  libimobiledevice (intégré au firmware jailbreak)       │   │
│  │  - usbmuxd                                               │   │
│  │  - lockdownd                                             │   │
│  │  - amfid (signing)                                       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Bypass en 5 hooks

Référence : `01_REPORTS/BYPASS_CORE.md` §2

| # | Hook | Cible | Action |
|---|---|---|---|
| 1 | `_replace_validateActivationDataSignature` | `MobileActivationDaemon` | Remplace vérification RSA par clé embarquée |
| 2 | `_replace_SecTrustEvaluateWithError` | `Security.framework` | Toujours retourner `errSecSuccess` |
| 3 | `_replace_handleActivationInfo` | `MobileActivationDaemon` | Injecte activation record forgé |
| 4 | `_replace_validateActivationDataWithError` | `MobileActivationDaemon` | Idem 1, variante avec NSError |
| 5 | `_replace_handleActivationInfo_NSError` | `MobileActivationDaemon` | Idem 3, variante avec NSError |

### 3.3 Stack technique iOS

| Composant | Technologie | Version |
|---|---|---|
| **Tweak build** | Theos | latest |
| **Hook engine** | Cydia Substrate (logos) | — |
| **Langage** | Objective-C + ARM64 asm | — |
| **Crypto** | CommonCrypto (Apple built-in) | — |
| **Build target** | ARM64, ARM64E | iOS 12+ |
| **Jailbreak** | palera1n (A11+), unc0ver (A12-A14) | — |

### 3.4 Structure projet iOS

```
ios/
└── blackhound/                            # Cydia Substrate tweak
    ├── Tweak.xm                          # Main hooks (logos)
    ├── Resources/
    │   ├── Info.plist
    │   └── rsa_pubkey.der                # Embedded public key
    ├── Hooks/
    │   ├── ActivationDataSignatureHook.xm
    │   ├── SecTrustEvaluateHook.xm
    │   ├── HandleActivationInfoHook.xm
    │   └── _replace_prefix.h             # Header
    ├── Utils/
    │   ├── RSAVerifier.m                 # Custom RSA impl
    │   ├── PlistParser.m                 # Binary plist reader
    │   └── Logger.m                      # NSLog wrapper
    ├── control                            # Debian package metadata
    ├── Makefile
    └── blackhound.deb                    # Built artifact
```

---

## 4. Composants Backend

### 4.1 Architecture backend

```
┌─────────────────────────────────────────────────────────────────┐
│                       Backend iRemovalClone                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌───────────────────────────────────────────────────────┐     │
│   │                  Load Balancer                         │     │
│   │              (Cloudflare / Nginx)                      │     │
│   └────────────────────────┬───────────────────────────────┘     │
│                            │                                      │
│   ┌────────────────────────▼───────────────────────────────┐     │
│   │              DDoS Protection (Cloudflare Pro)          │     │
│   │              - Rate limiting per IP                     │     │
│   │              - Bot detection                            │     │
│   │              - WAF rules                                │     │
│   └────────────────────────┬───────────────────────────────┘     │
│                            │                                      │
│   ┌────────────────────────▼───────────────────────────────┐     │
│   │                API Gateway (Nginx)                      │     │
│   │  /api/v1/activation/iact8  → iact8.php                 │     │
│   │  /api/v1/mf/signal        → mf5.php / mf6.php / mf7.php│     │
│   │  /api/v1/system/version   → version33.tx                │     │
│   │  /api/v1/system/pub       → pub.ph                      │     │
│   │  /api/v1/license/verify   → license.php                 │     │
│   └────────────────────────┬───────────────────────────────┘     │
│                            │                                      │
│   ┌────────────────────────▼───────────────────────────────┐     │
│   │            Application Layer (PHP-FPM 8.2)              │     │
│   │  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  │     │
│   │  │ Activation   │  │ Signal      │  │ License      │  │     │
│   │  │ Service      │  │ Service     │  │ Service      │  │     │
│   │  └──────────────┘  └─────────────┘  └──────────────┘  │     │
│   └────────────────────────┬───────────────────────────────┘     │
│                            │                                      │
│   ┌────────────────────────▼───────────────────────────────┐     │
│   │              Data Layer                                 │     │
│   │  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  │     │
│   │  │ MySQL 8.0    │  │ Redis 7.2   │  │ S3 / MinIO   │  │     │
│   │  │ (sessions,   │  │ (cache,     │  │ (backups,    │  │     │
│   │  │  devices,    │  │  rate       │  │  logs)       │  │     │
│   │  │  users)      │  │  limits)    │  │              │  │     │
│   │  └──────────────┘  └─────────────┘  └──────────────┘  │     │
│   └───────────────────────────────────────────────────────┘     │
│                                                                  │
│   ┌───────────────────────────────────────────────────────┐     │
│   │            Crypto Service (separate VPS)               │     │
│   │  - Holds private RSA key (offline, HSM)                │     │
│   │  - Forges activation records on demand                 │     │
│   │  - Air-gapped from internet (only REST API)            │     │
│   └───────────────────────────────────────────────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Endpoints API

Référence : `01_REPORTS/ENDPOINT_IACT8.md`

| # | Endpoint | Method | Auth | Rôle |
|---|---|---|---|---|
| 1 | `/version33.tx` | GET | HMAC | Check version client |
| 2 | `/pub.ph` | POST | HMAC | Publier infos device |
| 3 | `/iact8.ph` | POST | HMAC + nonce | Générer ticket activation |
| 4 | `/mf5.ph` | POST | HMAC + nonce | Bypass MEID (pré-A12) |
| 5 | `/mf6.ph` | POST | HMAC + nonce | Bypass MEID (A12+) |
| 6 | `/mf7.ph` | POST | HMAC + nonce | Bypass MEID (A14+) |
| 7 | `/license.ph` | POST | HMAC | Vérifier licence |
| 8 | `/telemetry.ph` | POST | HMAC | Envoyer télémétrie |
| 9 | `/pub.ph` (status) | GET | HMAC | Status public |
| 10 | `/blacklist.ph` | GET | — | Liste noire (anti-ban) |
| 11 | `/ping.ph` | GET | — | Health check |
| 12 | `/metrics.ph` | GET | — | Métriques Prometheus |
| 13 | `/admin.ph` | POST | Bearer | Admin (internal) |

### 4.3 Authentification HMAC

```python
# Pseudo-code du HMAC signing (côté PC)
import hmac
import hashlib
import base64
import time

class HmacSigner:
    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
    
    def sign(self, method: str, path: str, body: bytes, nonce: bytes) -> dict:
        timestamp = int(time.time())
        
        # Canonical string
        canonical = f"{method}\n{path}\n{timestamp}\n{base64.b64encode(nonce).decode()}\n{base64.b64encode(body).decode()}"
        
        # HMAC-SHA256
        signature = hmac.new(
            self.secret_key,
            canonical.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return {
            "X-Timestamp": str(timestamp),
            "X-Nonce": base64.b64encode(nonce).decode(),
            "X-Signature": signature
        }
```

### 4.4 Stack technique Backend

| Composant | Technologie | Version |
|---|---|---|
| **Runtime** | PHP-FPM | 8.2 LTS |
| **Framework** | Symfony | 6.4 LTS |
| **DB** | MySQL | 8.0+ |
| **Cache** | Redis | 7.2+ |
| **LB** | Nginx | 1.25+ |
| **Storage** | MinIO (S3 compatible) | latest |
| **Monitoring** | Prometheus + Grafana | — |
| **Logging** | Loki + Promtail | — |
| **Container** | Docker + Compose | — |
| **CI/CD** | GitLab CI | — |
| **HSM** | YubiHSM2 (optionnel) | — |

---

## 5. Protocoles & flux détaillés

### 5.1 Flux bypass complet

```
┌──────────────────────────────────────────────────────────────────┐
│                  Flux bypass A12+ (iPhone XS et plus)             │
└──────────────────────────────────────────────────────────────────┘

 USER                    PC                     IPHONE               BACKEND
  │                       │                       │                     │
  │  1. Click "Start"     │                       │                     │
  ├──────────────────────►│                       │                     │
  │                       │  2. Scan USB          │                     │
  │                       ├─────┐                 │                     │
  │                       │     │ detect device   │                     │
  │                       │◄────┘                 │                     │
  │                       │  3. idevicepair pair  │                     │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤                     │
  │                       │  4. Mode DFU assisté  │                     │
  │                       ├─────┐                 │                     │
  │                       │     │ instructions    │                     │
  │                       │◄────┘                 │                     │
  │  "Hold Power+Home"    │                       │                     │
  │◄──────────────────────┤                       │                     │
  │  "Release Power"      │                       │                     │
  ├──────────────────────►│                       │                     │
  │                       │  5. checkm8 exploit   │                     │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤ (DFU mode)          │
  │                       │  6. palera1n deploy   │                     │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤ (jailbreaké)       │
  │                       │  7. SSH tunnel open   │                     │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤ (port 22)           │
  │                       │  8. Deploy            │                     │
  │                       │     blackhound.dylib  │                     │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤                     │
  │                       │  9. Deploy minaeraser12                    │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤                     │
  │                       │  10. NAND erase       │                     │
  │                       ├──────────────────────►│                     │
  │                       │     (30-180s)         │                     │
  │                       │◄──────────────────────┤                     │
  │                       │  11. Reboot → Restore mode                 │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤                     │
  │                       │  12. Restore via rc   │                     │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤ (iOS installed)     │
  │                       │  13. CommonConnect    │                     │
  │                       │      (new pair)       │                     │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤                     │
  │                       │  14. Get activation   │                     │
  │                       │      request blob     │                     │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤ (ActivationRequest) │
  │                       │  15. POST iact8.php                          │
  │                       ├────────────────────────────────────────────►│
  │                       │  (HMAC-signed + nonce)                       │
  │                       │                                              │
  │                       │  16. Forged ticket                          │
  │                       │◄────────────────────────────────────────────┤
  │                       │  (ActivationRecord + iRemovalSignature)     │
  │                       │  17. Submit ticket    │                     │
  │                       ├──────────────────────►│                     │
  │                       │     via lockdownd     │                     │
  │                       │     → daemon hooké    │                     │
  │                       │       accepte !       │                     │
  │                       │◄──────────────────────┤                     │
  │                       │  18. GetActivationState                       │
  │                       ├──────────────────────►│                     │
  │                       │◄──────────────────────┤ (Activated!)        │
  │  "iDevice Activated   │                       │                     │
  │   Successfully"       │                       │                     │
  │◄──────────────────────┤                       │                     │
  │                       │                       │                     │
```

### 5.2 Protocole USB — libusbmuxd

```c
// Structure simplifiée de la communication USB
struct usbmuxd_header {
    uint16_t length;       // Taille du payload (16 bits)
    uint16_t version;      // Version protocole (1 ou 2)
    uint32_t message;      // Type message (plist)
    uint32_t tag;          // Tag de réponse
};

// Messages principaux
#define MESSAGE_PLIST   8

// Plist XML payload
<plist version="1.0">
<dict>
    <key>BUID</key>
    <string>...</string>
    <key>DeviceID</key>
    <integer>...</integer>
    <key>MessageType</key>
    <string>Pair</string>  // ou "Attached", "Detached", etc.
</dict>
</plist>
```

### 5.3 Protocole SSH (jailbreak)

```csharp
// C# SSH connection via Renci.SshNet
using Renci.SshNet;

var sshClient = new SshClient(host, port, "root", privateKeyStream);
sshClient.Connect();

// Déployer blackhound.dylib
var scpClient = new ScpClient(host, port, "root", privateKeyStream);
scpClient.Connect();
scpClient.UploadFile(
    new FileStream("blackhound.deb", FileMode.Open),
    "/var/tmp/blackhound.deb"
);

// Exécuter commandes
var cmd = sshClient.CreateCommand("dpkg -i /var/tmp/blackhound.deb");
var result = cmd.Execute();
```

### 5.4 Protocole HTTP — iact8.php

**Request :**
```http
POST /api/v1/activation/iact8 HTTP/1.1
Host: api.iremovalclone.io
Content-Type: application/x-apple-plist
X-Timestamp: 1719000000
X-Nonce: koY+rla/7ol+LX8kepekEw==
X-Signature: a3f2...8b9c
X-Device-UDID: 00008101-001234567890ABCD

<plist version="1.0">
<dict>
    <key>ActivationRequest</key>
    <data>BASE64...</data>
    <key>DeviceInfo</key>
    <dict>
        <key>UDID</key>
        <string>00008101-001234567890ABCD</string>
        <key>ProductType</key>
        <string>iPhone12,3</string>
        <key>ECID</key>
        <string>0xABCD1234</string>
        <key>IMEI</key>
        <string>358000000000000</string>
    </dict>
</dict>
</plist>
```

**Response :**
```http
HTTP/1.1 200 OK
Content-Type: application/x-apple-plist

<plist version="1.0">
<dict>
    <key>ActivationRecord</key>
    <data>BASE64_ACTIVATION_RECORD</data>
    <key>iRemovalRecord</key>
    <data>BASE64_CUSTOM_RECORD</data>
    <key>iRemovalSignature</key>
    <data>BASE64_SIGNATURE</data>
    <key>Status</key>
    <string>Success</string>
</dict>
</plist>
```

---

## 6. Sécurité & anti-détection

### 6.1 Anti-EDR (côté PC)

Référence : `01_REPORTS/AUDIT_REPORT.md` §3

```csharp
// Anti-debug checks
public class AntiDebug
{
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        out IntPtr processInformation,
        int processInformationLength,
        out int returnLength
    );
    
    public static bool IsDebuggerPresent()
    {
        // Check 1: IsDebuggerPresent API
        if (Debugger.IsAttached) return true;
        
        // Check 2: NtQueryInformationProcess (ProcessDebugPort)
        IntPtr debugPort;
        int retLen;
        var status = NtQueryInformationProcess(
            Process.GetCurrentProcess().Handle,
            7,  // ProcessDebugPort
            out debugPort,
            IntPtr.Size,
            out retLen
        );
        if (status == 0 && debugPort != IntPtr.Zero) return true;
        
        // Check 3: CheckRemoteDebugger
        if (CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, out var present))
            if (present) return true;
        
        return false;
    }
    
    public static bool IsRunningInVM()
    {
        // Check registry keys for VM
        var keys = new[] {
            @"SOFTWARE\VMware\VMware Tools",
            @"SOFTWARE\Oracle\VirtualBox Guest Additions",
            @"HARDWARE\Description\System\SystemInformation\BIOS\SystemManufacturer",
            @"HARDWARE\ACPI\DSDT\VBOX__"
        };
        
        foreach (var key in keys)
        {
            try
            {
                using var rk = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(key);
                if (rk != null) return true;
            }
            catch { }
        }
        
        // CPUID check
        return CheckCpuid();
    }
}
```

### 6.2 Obfuscation

| Composant | Outil |
|---|---|
| .NET Core (NativeAOT) | Native AOT + code flattening |
| Strings | XOR + runtime decryption |
| Method names | `.cctor` rename + auto-generated |
| Code signing | Thawte code signing cert |
| Anti-tamper | .NET Reactor (commercial) |

### 6.3 Certificate pinning

```csharp
public class HmacAuthenticationHandler : HttpClientHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var canonical = $"{request.Method}\n{request.RequestUri.AbsolutePath}\n" +
                        $"{timestamp}\n{nonce}\n{body}";
        
        var signature = HmacSha256(canonical, SecretKey);
        
        request.Headers.Add("X-Signature", signature);
        return base.SendAsync(request, cancellationToken);
    }
}
```

---

## 7. Persistance & stockage

### 7.1 Local (PC)

```
%APPDATA%\IRemovalClone\
├── config.json              # Configuration utilisateur
├── license.dat              # Licence chiffrée (AES-256)
├── devices.db               # SQLite - historique appareils
├── sessions.db              # SQLite - sessions bypass
├── logs\
│   ├── app-2026-06-22.log  # Logs quotidiens
│   └── crash\               # Crash dumps
├── cache\
│   ├── ipsw\                # IPSW téléchargés
│   ├── tweaks\              # blackhound.deb, minaeraser12
│   └── firmware\            # IPSW firmware cache
└── keystore\
    └── hmac.key             # Clé HMAC (chiffrée DPAPI)
```

### 7.2 Backend (MySQL)

```sql
-- Schéma principal
CREATE TABLE devices (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    udid VARCHAR(40) UNIQUE NOT NULL,
    product_type VARCHAR(20),
    ecid VARCHAR(20),
    imei VARCHAR(20),
    serial VARCHAR(20),
    ios_version VARCHAR(20),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_udid (udid)
);

CREATE TABLE sessions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    device_id BIGINT,
    nonce VARCHAR(32) UNIQUE NOT NULL,
    status ENUM('init', 'in_progress', 'success', 'failed'),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    error_message TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE activation_tickets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    session_id BIGINT,
    ticket_data LONGBLOB,             -- ActivationRecord forgé
    signature TEXT,                    -- iRemovalSignature
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    password_hash VARCHAR(255),
    license_key VARCHAR(64) UNIQUE,
    plan ENUM('trial', 'starter', 'pro', 'enterprise'),
    credits_remaining INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE licenses (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    license_key VARCHAR(64) UNIQUE NOT NULL,
    hwid VARCHAR(64),                  -- Hardware ID bound
    activated_at TIMESTAMP,
    expires_at TIMESTAMP,
    is_revoked BOOLEAN DEFAULT FALSE
);
```

### 7.3 Redis (cache)

```
# Caches
device:udid:00008101-...   → JSON device info (TTL 24h)
session:nonce:koY+rla...   → session_id (TTL 1h)
ratelimit:ip:1.2.3.4       → count (TTL 60s, max 100)
license:key:ABC123...      → user_id (TTL 1h)
```

---

## 8. Observabilité & logging

### 8.1 Logging structuré (Serilog)

```csharp
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(
        path: "logs/app-.log",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30)
    .WriteTo.Http(
        requestUri: "https://api.iremovalclone.io/logs",
        queueLimitBytes: null)
    .CreateLogger();

// Usage
Log.Information("Device detected: {UDID} ({ProductType})", udid, productType);
Log.Error(ex, "Bypass failed for {UDID}", udid);
```

### 8.2 Métriques (Prometheus)

```
# Métriques exposées par le backend
bypass_attempts_total{status="success|failed"} counter
bypass_duration_seconds histogram
active_sessions gauge
backend_api_requests_total{method,endpoint,status} counter
backend_api_request_duration_seconds{method,endpoint} histogram
database_connections_active gauge
redis_cache_hits_total counter
```

### 8.3 Tracing (OpenTelemetry)

```csharp
services.AddOpenTelemetry()
    .WithTracing(builder => builder
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddSource("IRemovalClone")
        .AddOtlpExporter(opt => 
            opt.Endpoint = new Uri("https://otel.iremovalclone.io")));
```

---

## 9. Diagrammes

### 9.1 Diagramme de déploiement

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Production Deployment                        │
└─────────────────────────────────────────────────────────────────────┘

   ┌──────────────┐
   │ Cloudflare   │
   │ CDN + WAF    │
   └──────┬───────┘
          │
   ┌──────▼───────────────────────────────────────────────────────┐
   │  Region EU (Frankfurt - Hetzner)                              │
   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
   │  │  LB +    │  │  App #1  │  │  App #2  │  │  App #3  │     │
   │  │  WAF     │  │  PHP-FPM │  │  PHP-FPM │  │  PHP-FPM │     │
   │  └──────────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘     │
   │                     │             │             │             │
   │              ┌──────▼─────────────▼─────────────▼──────┐      │
   │              │  MySQL Primary + 2 Read Replicas        │      │
   │              └─────────────────────────────────────────┘      │
   │              ┌─────────────────────────────────────────┐      │
   │              │  Redis Cluster (3 masters, 3 slaves)    │      │
   │              └─────────────────────────────────────────┘      │
   │              ┌─────────────────────────────────────────┐      │
   │              │  MinIO Storage (S3-compatible)          │      │
   │              └─────────────────────────────────────────┘      │
   └───────────────────────────────────────────────────────────────┘
   
   ┌───────────────────────────────────────────────────────────────┐
   │  Region US (Virginia - Hetzner) — read-only replica           │
   └───────────────────────────────────────────────────────────────┘
   
   ┌───────────────────────────────────────────────────────────────┐
   │  HSM Service (offshore VPS — Iceland)                         │
   │  - Air-gapped crypto service                                  │
   │  - Holds private RSA key                                       │
   │  - REST API only (HTTPS)                                      │
   └───────────────────────────────────────────────────────────────┘
```

### 9.2 Diagramme C4 — Composants

```
                  ┌─────────────────────────────────────┐
                  │           iRemovalClone              │
                  │                                     │
                  │  ┌──────────────┐                   │
                  │  │  WPF UI      │                   │
                  │  │  (ViewModels)│                   │
                  │  └──────┬───────┘                   │
                  │         │                           │
                  │  ┌──────▼───────┐                   │
                  │  │  Driver      │                   │
                  │  │  (13 methods)│                   │
                  │  └──────┬───────┘                   │
                  │         │                           │
                  │  ┌──────▼───────┐  HTTPS   ┌──────▼──────┐
                  │  │  iDevice_*   │ ◄────────►  │ Backend    │
                  │  │  Services    │           │ API        │
                  │  └──────┬───────┘           └────────────┘
                  │         │                            ▲
                  │         │ USB + SSH                 │
                  │         │                            │
                  │  ┌──────▼───────────────────┐       │
                  │  │  Native libs             │       │
                  │  │  (libusbmuxd, libimobile)│       │
                  │  └──────────────────────────┘       │
                  │                                     │
                  └─────────────────────────────────────┘
                                  │
                                  │ USB
                                  ▼
                  ┌─────────────────────────────────────┐
                  │           iPhone (iOS)              │
                  │  ┌──────────────────────────────┐   │
                  │  │  blackhound.dylib            │   │
                  │  │  (5 hooks, MobileActivation) │   │
                  │  └──────────────────────────────┘   │
                  │  ┌──────────────────────────────┐   │
                  │  │  minaeraser12 (NAND wipe)    │   │
                  │  └──────────────────────────────┘   │
                  └─────────────────────────────────────┘
```

---

## Annexes

- [PRD](./00_PRD.md) — Exigences produit
- [Stack technologique](./02_TECH_STACK.md)
- [Roadmap implémentation](./03_IMPLEMENTATION_ROADMAP.md)

---

**Auteur** : Équipe iRemovalClone
**Date** : 2026-06-22
**Version** : 0.1 (Draft initial)
