# Stack technologique — iRemovalClone v1.0

> **Inventaire complet des technologies** — framework, langages, bibliothèques, outils
>
> **Date** : 2026-06-22
> **Cible** : Réimplémentation modernisée d'iRemoval PRO

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Côté PC (Windows)](#2-côté-pc-windows)
3. [Côté iOS (device)](#3-côté-ios-device)
4. [Backend (cloud)](#4-backend-cloud)
5. [DevOps & infrastructure](#5-devops--infrastructure)
6. [Outils de développement](#6-outils-de-développement)
7. [Sécurité](#7-sécurité)
8. [Matrice de compatibilité](#8-matrice-de-compatibilité)
9. [Comparaison avec l'original](#9-comparaison-avec-loriginal)

---

## 1. Vue d'ensemble

### 1.1 Architecture 3-tier

| Tier | Technologie principale | Langage | Runtime |
|---|---|---|---|
| **PC Client** | WPF + .NET 8 NativeAOT | C# 12 | .NET 8 LTS |
| **iOS Device** | Cydia Substrate + Theos | Objective-C | iOS 12+ |
| **Backend** | Symfony + PHP-FPM | PHP 8.2 | PHP-FPM 8.2 |

### 1.2 Langages par composant

```
┌──────────────────────────────────────────────────────────────────┐
│  Composant        Langage        Pourcentage du code            │
├──────────────────────────────────────────────────────────────────┤
│  PC UI (WPF)      C# (.NET Fx)   ~ 25%                          │
│  PC Core          C# (NativeAOT) ~ 35%                          │
│  iOS Tweak        Objective-C    ~ 15%                          │
│  iOS NAND eraser  C + ARM64 asm  ~ 10%                          │
│  Backend          PHP 8.2        ~ 12%                          │
│  Scripts/DevOps   Bash + Python  ~ 3%                           │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Côté PC (Windows)

### 2.1 Stack UI (WPF)

| Technologie | Version | Licence | Usage |
|---|---|---|---|
| **.NET Framework** | 4.8 | MIT | Runtime UI |
| **WPF** | built-in | MIT | Framework UI |
| **XAML** | built-in | MIT | Markup UI |
| **CommunityToolkit.Mvvm** | 8.3+ | MIT | MVVM helpers |
| **ModernWpf** | 0.10+ | MIT | Fluent Design theme |
| **MaterialDesignThemes** | 5.x | MIT | Alternative theme |
| **Hardcodet.NotifyIcon** | 2.0+ | MIT | System tray |

### 2.2 Stack Core (.NET 8 NativeAOT)

| Technologie | Version | Licence | Usage |
|---|---|---|---|
| **.NET** | 8.0 LTS | MIT | Runtime |
| **C#** | 12 | MIT | Langage |
| **NativeAOT** | 8.0 | MIT | Compilation AOT |
| **Microsoft.Extensions.Hosting** | 8.0+ | MIT | Generic host |
| **Microsoft.Extensions.Hosting** | 8.0+ | MIT | DI + config |
| **Microsoft.Extensions.Http** | 8.0+ | MIT | HTTP client factory |

### 2.3 Bibliothèques tierces (Core)

| Bibliothèque | Version | Licence | Usage | Source |
|---|---|---|---|---|
| **SSH.NET** | 2024.2.0 | MIT | Client SSH | nuget.org |
| **BouncyCastle.Cryptography** | 2.4.0 | MIT | Crypto | nuget.org |
| **Serilog** | 4.0+ | Apache-2.0 | Logging | nuget.org |
| **Polly** | 8.4+ | BSD-3 | Resilience | nuget.org |
| **System.Text.Json** | 8.0 | MIT | JSON | built-in |
| **System.Security.Cryptography** | built-in | MIT | Crypto natif | built-in |

### 2.4 Bibliothèques natives (P/Invoke)

| Lib | Version | Source | Usage |
|---|---|---|---|
| **libusbmuxd** | 2.0.2 | libimobiledevice.org | USB multiplexing |
| **libimobiledevice** | 1.3.0 | libimobiledevice.org | iDevice protocol |
| **libideviceactivation** | 1.2.0 | libimobiledevice.org | Activation protocol |
| **libimobiledevice-glue** | 1.3.0 | libimobiledevice.org | Helpers |
| **libplist** | 2.6.0 | libimobiledevice.org | Binary plist |
| **libusbmuxd-glue** | 2.0.2 | libimobiledevice.org | USB helpers |
| **libssh2** | 1.11.0 | libssh2.org | SSH (native) |
| **OpenSSL** | 3.3+ | Apache-2.0 | TLS + crypto |

> Toutes les libs natives sont compilées depuis les sources officielles `libimobiledevice.org` avec un script `build-native.ps1` automatisé.

### 2.5 Build & distribution

| Outil | Version | Usage |
|---|---|---|
| **MSBuild** | 17.8+ | Build .NET Framework |
| **dotnet CLI** | 8.0+ | Build .NET 8 |
| **NativeAOT Compiler** | 8.0 | Compile AOT |
| **Inno Setup** | 6.4+ | Installer Windows |
| **Advanced Installer** | 21.x | Alternative MSI |
| **Costura.Fody** | 6.x | Embed DLLs |

---

## 3. Côté iOS (device)

### 3.1 Tweak (blackhound.dylib)

| Technologie | Version | Usage |
|---|---|---|
| **Theos** | latest | Build system tweak |
| **Cydia Substrate** | — | Hook runtime |
| **logos** | part of Theos | Preprocesseur hooks |
| **Objective-C runtime** | iOS 12+ | Method swizzling |
| **ARM64** | ARMv8.3-A | Compilation cible |
| **ARM64E** | ARMv8.3-A (PAC) | iPhone XS+ (optionnel) |

### 3.2 Compilateur

| Outil | Version | Plateforme |
|---|---|---|
| **clang** | 15+ | macOS / Linux cross |
| **iOS SDK** | 16+ | Apple SDK |
| **ldid** | 2.2+ | Sign .deb |
| **dpkg-deb** | built-in | Package .deb |
| **xcodebuild** | 15+ | Build dépendance |

### 3.3 Outils de jailbreak intégrés

| Outil | Modèles | Version |
|---|---|---|
| **checkm8** | A5-A11 (bootrom exploit) | open-source |
| **palera1n** | A11+ (iOS 15+) | open-source |
| **unc0ver** | A12-A14 (legacy) | open-source |
| **Dopamine** | A15-A16 | open-source |
| **Fugu15 Max** | A12+ | open-source |

### 3.4 NAND eraser (minaeraser12)

| Technologie | Usage |
|---|---|
| **C** | Code principal |
| **ARM64 asm** | Routines bas niveau IOKit |
| **IOKit** | Framework bas niveau Apple |
| **AppleNAND** | Accès NAND bas niveau |
| **SSH (dropbear)** | Canal de contrôle depuis PC |

---

## 4. Backend (cloud)

### 4.1 Application

| Technologie | Version | Licence | Usage |
|---|---|---|---|
| **PHP** | 8.2 LTS | PHP-3.01 | Langage principal |
| **Symfony** | 6.4 LTS | MIT | Framework web |
| **Doctrine ORM** | 3.x | MIT | ORM MySQL |
| **Symfony Cache** | 6.4 | MIT | Abstraction cache |
| **Symfony Messenger** | 6.4 | MIT | Async tasks |
| **Symfony Security** | 6.4 | MIT | Auth + ACL |
| **Monolog** | 3.x | MIT | Logging PHP |
| **Ramsey UUID** | 4.x | MIT | UUID generation |
| **Guzzle HTTP** | 7.x | MIT | HTTP client interne |

### 4.2 Infrastructure

| Technologie | Version | Usage |
|---|---|---|
| **PHP-FPM** | 8.2 | FastCGI Process Manager |
| **Nginx** | 1.25+ | Reverse proxy + LB |
| **MySQL** | 8.0 LTS | DB relationnelle |
| **Redis** | 7.2+ | Cache + rate limiting |
| **MinIO** | latest | Stockage objet S3-compatible |
| **Docker** | 24+ | Containers |
| **Docker Compose** | v2.20+ | Orchestration locale |

### 4.3 Services externes

| Service | Provider | Usage |
|---|---|---|
| **Cloudflare Pro** | Cloudflare | CDN + WAF + DDoS |
| **Hetzner Cloud** | Hetzner | VPS (Frankfurt + Ashburn) |
| **Hetzner Storage Box** | Hetzner | Backups S3 |
| **YubiHSM2** | Yubico | HSM pour clés RSA (optionnel) |
| **Let's Encrypt** | ISRG | Certificats TLS |

### 4.4 Schéma déploiement

```
Production:
├── EU-FRA-1 (Hetzner, Frankfurt)
│   ├── LB + WAF (Cloudflare proxy)
│   ├── App tier (3× VPS CX31 - 4 vCPU/8GB)
│   ├── MySQL Primary (1× VPS CX41)
│   ├── MySQL Replicas (2× VPS CX31)
│   ├── Redis (3× VPS CX21 - master + replicas)
│   └── MinIO (1× VPS CCX13 - storage)
│
├── US-VA-1 (Hetzner, Ashburn) — read replica
│   └── App tier (1× VPS CX31)
│
└── IS-1 (Iceland VPS - offshore)
    └── HSM Service (1× dedicated, air-gapped)
        └── Holds private RSA signing key
```

---

## 5. DevOps & infrastructure

### 5.1 CI/CD

| Outil | Version | Usage |
|---|---|---|
| **GitLab CE** | 16.x | Source control + CI |
| **GitLab Runner** | 16.x | Build agents |
| **Docker** | 24+ | Build containers |
| **Docker Registry** | — | Stockage images |
| **Ansible** | 8.x | Provisionning |
| **Terraform** | 1.6+ | Infrastructure as Code |

### 5.2 Monitoring

| Outil | Version | Usage |
|---|---|---|
| **Prometheus** | 2.48+ | Métriques |
| **Grafana** | 10.x | Dashboards |
| **Loki** | 2.9+ | Logs centralisés |
| **Promtail** | 2.9+ | Log shipping |
| **Alertmanager** | 0.27+ | Alertes |
| **Uptime Kuma** | 1.23+ | Health checks externes |
| **Sentry** | latest | Error tracking (backend + UI) |

### 5.3 Sécurité ops

| Outil | Usage |
|---|---|
| **Vault** | Secrets management |
| **WireGuard** | VPN inter-services |
| **fail2ban** | Brute force protection |
| **OSSEC** | HIDS |
| **ClamAV** | Anti-virus backend |

---

## 6. Outils de développement

### 6.1 IDE & éditeurs

| Outil | Usage |
|---|---|
| **Visual Studio 2022** | Développement .NET Framework (UI) |
| **Visual Studio Code** | .NET 8, PHP, config files |
| **JetBrains Rider** | Alternative .NET |
| **Xcode** | Build iOS tweaks |
| **PhpStorm** | Développement backend |
| **DBeaver** | MySQL client |

### 6.2 Tests

| Outil | Usage | Cible |
|---|---|---|
| **xUnit** | Tests unitaires C# | PC Core |
| **FluentAssertions** | Assertions expressives | PC Core |
| **NSubstitute** | Mocking | PC Core |
| **Testcontainers** | Tests intégration DB/cache | PC Core |
| **Playwright** | Tests E2E UI | PC UI |
| **PHPUnit** | Tests unitaires PHP | Backend |
| **Behat** | BDD scénarios | Backend |
| **OWASP ZAP** | Scan sécurité | Backend |

### 6.3 Build & packaging

| Outil | Plateforme | Usage |
|---|---|---|
| **MSBuild** | Windows | Build .NET Framework |
| **dotnet CLI** | Cross-platform | Build .NET 8 |
| **Theos** | macOS/Linux | Build iOS tweaks |
| **Composer** | Cross-platform | PHP dependencies |
| **NPM/PNPM** | Cross-platform | Frontend assets (dashboard) |
| **Inno Setup** | Windows | Créer installer .exe |

### 6.4 Documentation

| Outil | Usage |
|---|---|
| **DocFX** | Documentation API .NET |
| **TypeDoc** | Documentation JS/TS |
| **PHPDoc** | Documentation PHP |
| **Mermaid** | Diagrammes (GitHub) |
| **PlantUML** | Diagrammes UML |
| **MkDocs Material** | Site documentation |

---

## 7. Sécurité

### 7.1 Bibliothèques cryptographiques

| Bibliothèque | Algo | Usage |
|---|---|---|
| **System.Security.Cryptography** (.NET) | RSA-2048, AES-256, HMAC-SHA256 | PC Core |
| **BouncyCastle** | RSA, curves elliptiques | PC Core |
| **OpenSSL 3.3+** | TLS, X.509 | Backend + libs natives |
| **CommonCrypto** (Apple) | SHA256, RSA | iOS tweak |
| **YubiHSM2** | Hardware RSA signing | Backend (HSM service) |

### 7.2 Authentification & autorisation

| Mécanisme | Usage |
|---|---|
| **HMAC-SHA256** | Signature requêtes API |
| **OAuth 2.0** (optionnel) | API publique future |
| **JWT** (RS256) | Sessions admin |
| **API Keys + License** | Auth client |
| **2FA TOTP** | Admin dashboard |

### 7.3 Anti-reverse

| Mesure | Implémentation |
|---|---|
| **NativeAOT** | Pas d'IL .NET à décompiler |
| **Code flattening** | CFG obfusqué |
| **String encryption** | XOR + runtime decryption |
| **Anti-debug** | NtQueryInformationProcess + PEB checks |
| **Anti-VM** | CPUID + RDTSC + registry |
| **Anti-tamper** | .NET Reactor |
| **Authenticode signing** | Thawte code signing cert |

### 7.4 Outils sécurité analyse

| Outil | Usage |
|---|---|
| **Ghidra** | Reverse engineering (.dylib ARM64) |
| **IDA Pro** | Alternative RE |
| **Frida** | Instrumentation runtime |
| **mitmproxy** | Capture trafic HTTPS |
| **Burp Suite** | Test API backend |
| **YARA** | Détection signatures |
| **VirusTotal** | Vérification binaire |
| **pe-sieve** | Anti-debug detection |

---

## 8. Matrice de compatibilité

### 8.1 Compatibilité iPhone/iOS

| Modèle | SoC | iOS testé | Statut |
|---|---|---|---|
| iPhone 5s | A7 | iOS 12.5.7 | ✅ Legacy |
| iPhone 6/6+ | A8 | iOS 12.5.7 | ✅ Legacy |
| iPhone 6s/6s+ | A9 | iOS 15.8 | ✅ |
| iPhone SE (1st) | A9 | iOS 15.8 | ✅ |
| iPhone 7/7+ | A10 | iOS 15.8 | ✅ |
| iPhone 8/8+ | A11 | iOS 16.7 | ✅ |
| iPhone X | A11 | iOS 16.7 | ✅ |
| **iPhone XS/XS Max** | **A12** | iOS 17.x | **MVP target** |
| iPhone XR | A12 | iOS 17.x | ✅ |
| iPhone 11/11 Pro | A13 | iOS 17.x | ✅ |
| iPhone SE (2nd) | A13 | iOS 17.x | ✅ |
| iPhone 12/12 Pro | A14 | iOS 17.x | ✅ |
| iPhone 13/13 Pro | A15 | iOS 17.x | ✅ |
| iPhone SE (3rd) | A15 | iOS 17.x | ✅ |
| iPhone 14/14 Pro | A16 | iOS 17.x | ⚠️ Beta |
| iPhone 15/15 Pro | A17 Pro | iOS 17.x | ⚠️ Beta |

### 8.2 Compatibilité Windows

| OS | Build | Statut |
|---|---|---|
| Windows 10 | 1909+ | ✅ |
| Windows 10 | 21H2+ | ✅ MVP |
| Windows 11 | 21H2+ | ✅ |
| Windows 11 | 23H2+ | ✅ Recommandé |

### 8.3 Compatibilité .NET

| Runtime | Version | Statut |
|---|---|---|
| .NET Framework | 4.8 | ✅ (UI) |
| .NET | 6.0 | ❌ Pas de NativeAOT stable |
| .NET | 7.0 | ⚠️ EOL novembre 2024 |
| .NET | 8.0 LTS | ✅ MVP cible |
| .NET | 9.0 | ⚠️ Migration future |

---

## 9. Comparaison avec l'original

### 9.1 Stack original (iRemoval PRO v5.2)

| Composant | Original | iRemovalClone v1.0 |
|---|---|---|
| **UI** | WPF .NET Framework 4.8 | ✅ Identique (maturité) |
| **Core** | .NET 8 NativeAOT | ✅ Identique |
| **HTTP** | RestSharp | → HttpClient + Polly (modernisé) |
| **SSH** | Renci.SshNet | ✅ Identique |
| **Crypto** | Built-in + libs natives | + BouncyCastle (étendu) |
| **iOS Tweak** | Cydia Substrate + Theos | ✅ Identique |
| **NAND eraser** | minaeraser12 (closed) | 🔄 Reimplémentation open |
| **Backend** | PHP (probablement 5.6) | 🔄 Symfony 6.4 + PHP 8.2 |
| **DB** | MySQL (présumé) | ✅ MySQL 8.0 |
| **Cache** | Redis (présumé) | ✅ Redis 7.2 |
| **CI/CD** | Inconnu | ✅ GitLab CI moderne |

### 9.2 Améliorations vs original

| Aspect | Original | iRemovalClone |
|---|---|---|
| **Tests** | Inconnu | xUnit + PHPUnit + Playwright |
| **Documentation** | Minimale | DocFX + Mermaid + MkDocs |
| **Observabilité** | Basique | OpenTelemetry + Prometheus + Grafana |
| **Sécurité ops** | Basique | Vault + WireGuard + fail2ban |
| **HSM** | Clé serveur en clair | 🔐 YubiHSM2 (optionnel) |
| **Internationalisation** | Anglais uniquement | i18n ready (EN/FR/ES) |
| **Multi-region** | EU seul | EU + US (read replicas) |
| **API publique** | Non | v2.0 roadmap |

### 9.3 Innovations proposées

| Innovation | Valeur |
|---|---|
| **Dashboard web** | Vue multi-device pour techniciens |
| **Mode multi-device** | 10+ bypass en parallèle |
| **Auto-update** | Patch transparent des hooks iOS |
| **Telemetry opt-in** | Crash reports anonymes |
| **Cloud sync** | Session backup sur cloud |
| **Mobile app (preview)** | iOS/Android pour status à distance |

---

## 10. Annexes

### 10.1 Récapitulatif fichiers `IremoveClone/`

| Fichier | Description |
|---|---|
| `00_PRD.md` | Product Requirements Document |
| `01_ARCHITECTURE.md` | Architecture détaillée |
| `02_TECH_STACK.md` | Stack technologique (ce doc) |
| `03_IMPLEMENTATION_ROADMAP.md` | Plan de développement |

### 10.2 Liens utiles

- [libimobiledevice](https://libimobiledevice.org/) — Bibliothèques USB iOS
- [Theos](https://theos.dev/) — Build system pour tweaks
- [palera1n](https://github.com/palera1n/palera1n) — Jailbreak A11+
- [checkm8](https://github.com/axi0mX/ipwnder) — Bootrom exploit
- [Symfony](https://symfony.com/) — Framework PHP
- [.NET 8](https://dotnet.microsoft.com/) — Runtime

---

**Auteur** : Équipe iRemovalClone
**Date** : 2026-06-22
**Version** : 0.1 (Draft initial)
