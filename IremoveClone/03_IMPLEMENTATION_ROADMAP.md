# Roadmap d'implémentation — iRemovalClone v1.0

> **Plan détaillé sprint par sprint** — du prototype au lancement
>
> **Date** : 2026-06-22
> **Durée totale MVP** : 31 semaines (~7 mois)
> **Équipe** : 3-5 ingénieurs (1 tech lead + 2 back + 1 iOS + 1 devops)

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Organisation équipe](#2-organisation-équipe)
3. [Sprint 0 — Setup & design](#sprint-0--setup--design)
4. [Sprint 1-3 — Backend foundation](#sprint-1-3--backend-foundation)
5. [Sprint 4-9 — PC Core engine](#sprint-4-9--pc-core-engine)
6. [Sprint 10-13 — iOS tweak](#sprint-10-13--ios-tweak)
7. [Sprint 14-17 — UI WPF](#sprint-14-17--ui-wpf)
8. [Sprint 18-20 — Intégration & jailbreak](#sprint-18-20--intégration--jailbreak)
9. [Sprint 21-24 — NAND eraser](#sprint-21-24--nand-eraser)
10. [Sprint 25-28 — Tests E2E](#sprint-25-28--tests-e2e)
11. [Sprint 29-30 — Beta privée](#sprint-29-30--beta-privée)
12. [Sprint 31 — Release v1.0](#sprint-31--release-v10)
13. [Risques & mitigations](#13-risques--mitigations)

---

## 1. Vue d'ensemble

### 1.1 Timeline Gantt

```
Semaine │ 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 │
────────┼────────────────────────────────────────────────────────────────────────────────────────── │
S0      │██                                                                                       │
S1      │   ███                                                                                   │
S2      │      ███                                                                                │
S3      │         ███                                                                             │
S4      │            ███                                                                          │
S5      │               ███                                                                       │
S6      │                  ███                                                                    │
S7      │                     ███                                                                 │
S8      │                        ███                                                              │
S9      │                           ███                                                           │
S10     │                              ███                                                        │
S11     │                                 ███                                                     │
S12     │                                    ███                                                  │
S13     │                                       ███                                               │
S14     │                                          ███                                            │
S15     │                                             ███                                         │
S16     │                                                ███                                      │
S17     │                                                   ███                                   │
S18     │                                                      ███                                │
S19     │                                                         ███                             │
S20     │                                                            ███                          │
S21     │                                                               ███                       │
S22     │                                                                  ███                    │
S23     │                                                                     ███                 │
S24     │                                                                        ███              │
S25     │                                                                           ███           │
S26     │                                                                              ███        │
S27     │                                                                                 ███     │
S28     │                                                                                    ███  │
S29     │                                                                                       ███│
S30     │                                                                                          █│
S31     │                                                                                          █│
```

### 1.2 Jalons clés (Milestones)

| Jalon | Semaine | Livrable | Critère succès |
|---|---|---|---|
| **M0 — Design** | S0 (W2) | PRD + archi validés | Stakeholders sign-off |
| **M1 — API Ready** | S3 (W12) | `iact8.php` fonctionnel | Test bypass manuel OK |
| **M2 — PC Core** | S9 (W22) | Driver avec 13 méthodes | Tests unitaires 60%+ |
| **M3 — iOS Tweak** | S13 (W28) | Hooks fonctionnels | Test bypass avec dylib OK |
| **M4 — UI Complete** | S17 (W32) | WPF MVVM complet | Tests Playwright OK |
| **M5 — NAND Eraser** | S20 (W36) | minaeraser12 porté | Test NAND wipe A12 OK |
| **M6 — E2E Works** | S24 (W40) | Bypass complet A12 | 95%+ success rate |
| **M7 — Beta** | S30 (W46) | 50 beta testeurs | NPS > 30 |
| **M8 — Launch** | S31 (W47) | Release v1.0 public | Sales enablement |

---

## 2. Organisation équipe

### 2.1 Composition

| Rôle | Nombre | Responsabilité |
|---|---|---|
| **Tech Lead** | 1 | Architecture, code review, intégrations |
| **Backend Dev** | 1 | API Symfony, MySQL, Redis |
| **PC Core Dev** | 1 | .NET 8 NativeAOT, USB/SSH/Crypto |
| **iOS Dev** | 1 | Theos tweak, ARM64, Cydia Substrate |
| **DevOps / SRE** | 0.5 | CI/CD, infra, monitoring |

### 2.2 Workflow

- **Daily** : Standup 15 min (Slack huddle)
- **Sprint** : 2 semaines
- **Review** : Démo à chaque fin de sprint (vendredi)
- **Retro** : Après chaque sprint

### 2.3 Communication

| Canal | Usage |
|---|---|
| **GitLab** | Code + MR + CI |
| **Slack** | Communication sync/async |
| **Linear** | Tickets + roadmap |
| **Notion** | Documentation |
| **Figma** | UI mockups |
| **Sentry** | Bug tracking prod |

---

## Sprint 0 — Setup & design

**Durée** : 2 semaines
**Objectif** : Valider l'architecture et mettre en place l'infrastructure projet

### Tâches

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 1 | Validation PRD + archi avec stakeholders | Tech Lead | 2j |
| 2 | Setup GitLab repo + branches protection | DevOps | 1j |
| 3 | Setup CI/CD pipelines (3 pipelines : .NET, PHP, iOS) | DevOps | 3j |
| 4 | Provision infra staging (Hetzner) | DevOps | 2j |
| 5 | Design Figma UI principale | Tech Lead + designer | 4j |
| 6 | Création Slack workspace + Linear board | Tech Lead | 1j |
| 7 | Documentation onboarding (Notion) | Tech Lead | 2j |
| 8 | Setup Vault pour secrets | DevOps | 2j |
| 9 | Achats domaines + SSL (Let's Encrypt) | DevOps | 1j |
| 10 | Choix + commande HSM (YubiHSM2) | Tech Lead | 3j |

### Livrables

- [ ] Repo GitLab avec README
- [ ] CI/CD pipelines fonctionnels
- [ ] VM staging opérationnelle
- [ ] Mockups Figma validés
- [ ] Documentation onboarding

### Definition of Done

- Stakeholders sign-off PRD
- CI/CD green (builds passent)
- VM staging accessible SSH
- 1 demo UI sur Figma

---

## Sprint 1-3 — Backend foundation

**Durée** : 4 semaines (2 sprints + 1 stabilisation)

### Sprint 1 — Setup Symfony

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 1.1 | Init projet Symfony 6.4 LTS | Backend | 1j |
| 1.2 | Configuration Doctrine (MySQL) | Backend | 1j |
| 1.3 | Configuration Redis | Backend | 1j |
| 1.4 | Création entités : Device, Session, Ticket, User, License | Backend | 3j |
| 1.5 | Migrations Doctrine | Backend | 1j |
| 1.6 | Configuration Symfony Security (HMAC auth) | Backend | 3j |
| 1.7 | Premier endpoint `/version33.tx` (GET) | Backend | 2j |
| 1.8 | Tests unitaires PHPUnit (>= 50% coverage) | Backend | 3j |

### Sprint 2 — Endpoints critiques

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 2.1 | Endpoint `POST /pub.ph` (publier device info) | Backend | 2j |
| 2.2 | Endpoint `POST /iact8.ph` (générer ticket) | Backend | 5j |
| 2.3 | Génération clé RSA-2048 (offline, sécurisée) | Backend | 2j |
| 2.4 | Stockage clé dans Vault | Backend | 1j |
| 2.5 | Signature activation records avec clé privée | Backend | 3j |
| 2.6 | Endpoint `POST /license.ph` | Backend | 2j |
| 2.7 | Rate limiting Redis (100 req/min/IP) | Backend | 2j |

### Sprint 3 — Endpoints auxiliaires + observabilité

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 3.1 | Endpoint `POST /mf5.ph` / `mf6.ph` / `mf7.ph` | Backend | 3j |
| 3.2 | Endpoint `POST /telemetry.ph` | Backend | 2j |
| 3.3 | Endpoint `GET /blacklist.ph` | Backend | 1j |
| 3.4 | Dashboard Grafana (Prometheus) | DevOps | 3j |
| 3.5 | Tests E2E Postman/Newman | Backend | 3j |
| 3.6 | Documentation OpenAPI 3.1 | Backend | 2j |
| 3.7 | Audit sécurité OWASP ZAP | Backend | 2j |

### Livrables

- [ ] Backend Symfony complet
- [ ] 13 endpoints opérationnels
- [ ] Tests PHPUnit >= 70% coverage
- [ ] Documentation OpenAPI
- [ ] Dashboard Grafana

### Definition of Done

- Tous endpoints répondent (200 OK sur tests)
- Audit sécurité : pas de finding CRITICAL
- Documentation OpenAPI validée
- Load test 1000 req/s validé

---

## Sprint 4-9 — PC Core engine

**Durée** : 6 semaines

### Sprint 4 — Setup .NET 8 NativeAOT

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 4.1 | Init solution .NET 8 (.NET Fx UI + NativeAOT Core) | PC Core | 1j |
| 4.2 | Setup DI (Microsoft.Extensions.Hosting) | PC Core | 1j |
| 4.3 | Setup Serilog (file + console) | PC Core | 1j |
| 4.4 | Setup Polly (retry, circuit breaker) | PC Core | 1j |
| 4.5 | Tests unitaires xUnit + NSubstitute | PC Core | 2j |
| 4.6 | Configuration appsettings (dev/prod) | PC Core | 1j |
| 4.7 | CI/CD pipeline .NET NativeAOT | DevOps | 2j |
| 4.8 | Premier build AOT Windows | PC Core | 1j |

### Sprint 5 — USB + libimobiledevice

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 5.1 | Compilation native libusbmuxd 2.0.2 | PC Core | 2j |
| 5.2 | Compilation native libimobiledevice 1.3.0 | PC Core | 2j |
| 5.3 | Compilation native libplist 2.6.0 | PC Core | 1j |
| 5.4 | P/Invoke wrappers C# (libusbmuxd) | PC Core | 3j |
| 5.5 | P/Invoke wrappers C# (libimobiledevice) | PC Core | 4j |
| 5.6 | Service `UsbDeviceEnumerator` | PC Core | 2j |
| 5.7 | Méthode `CommonConnectDevice` (Driver) | PC Core | 3j |
| 5.8 | Tests intégration USB (avec iPhone) | PC Core | 3j |

### Sprint 6 — SSH + HTTP

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 6.1 | Service SshNetClient (Renci.SshNet) | PC Core | 2j |
| 6.2 | Service BackendApi (HttpClient + HMAC) | PC Core | 3j |
| 6.3 | Service HmacSha256Signer | PC Core | 2j |
| 6.4 | Certificate pinning backend | PC Core | 2j |
| 6.5 | Polly resilience policies | PC Core | 1j |
| 6.6 | Tests intégration HTTP (mock server) | PC Core | 3j |

### Sprint 7 — Driver methods (1/2)

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 7.1 | `iDevice_GetState` (lockdown query) | PC Core | 2j |
| 7.2 | `iDevice_Tnl` (SSH tunnel setup) | PC Core | 3j |
| 7.3 | `iDevice_EnableDevMode` | PC Core | 1j |
| 7.4 | `iDevice_Restart` | PC Core | 1j |
| 7.5 | `iDevice_Deactivate` | PC Core | 2j |
| 7.6 | `iDevice_LnchV2` | PC Core | 2j |
| 7.7 | `iDevice_RemoveProfiles` (MDM) | PC Core | 3j |

### Sprint 8 — Driver methods (2/2) + Activation

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 8.1 | `CreateActivationSessionInfo` | PC Core | 2j |
| 8.2 | `CreateActivationInfoWithSession` | PC Core | 2j |
| 8.3 | `ActivateWithSession` | PC Core | 3j |
| 8.4 | `GetActivationState` | PC Core | 1j |
| 8.5 | `iDevice_Activate` (orchestration complète) | PC Core | 3j |
| 8.6 | `BypassMeidSignal` | PC Core | 3j |
| 8.7 | `Firewall_iDeviceProxy` | PC Core | 2j |

### Sprint 9 — Sécurité + stabilisation

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 9.1 | Anti-debug (`NtQueryInformationProcess`) | PC Core | 2j |
| 9.2 | Anti-VM (CPUID + RDTSC + registry) | PC Core | 3j |
| 9.3 | Obfuscation des strings (XOR) | PC Core | 2j |
| 9.4 | Code signing Thawte (binaire final) | Tech Lead | 3j |
| 9.5 | Anti-tamper .NET Reactor | PC Core | 2j |
| 9.6 | Tests anti-EDR (Defender, Crowdstrike) | Tech Lead | 3j |
| 9.7 | Stabilisation + bug fixes | PC Core | 5j |

### Livrables

- [ ] Driver complet avec 17 méthodes
- [ ] NativeAOT compile sans warning
- [ ] Tests >= 60% coverage
- [ ] Binaire signé Thawte
- [ ] Anti-EDR vérifié

### Definition of Done

- Driver compile en mode Release NativeAOT
- Tous tests passent
- Binaire < 100 MB
- Démarrage < 2 secondes

---

## Sprint 10-13 — iOS tweak (blackhound.dylib)

**Durée** : 4 semaines

### Sprint 10 — Setup Theos + hook 1

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 10.1 | Setup Theos (macOS build VM) | iOS | 1j |
| 10.2 | Init projet blackhound.dylib | iOS | 1j |
| 10.3 | Hook 1 : `validateActivationDataSignature` | iOS | 4j |
| 10.4 | Embed RSA-1024 public key | iOS | 1j |
| 10.5 | Test sur iPhone jailbreaké | iOS | 3j |

### Sprint 11 — Hooks 2 & 3

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 11.1 | Hook 2 : `SecTrustEvaluateWithError` | iOS | 3j |
| 11.2 | Hook 3 : `handleActivationInfo` | iOS | 3j |
| 11.3 | Test intégration (3 hooks ensemble) | iOS | 2j |
| 11.4 | Build .deb package | iOS | 1j |

### Sprint 12 — Variantes + plist parsing

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 12.1 | Variante `_replace_validateActivationDataWithError` | iOS | 2j |
| 12.2 | Variante `_replace_handleActivationInfo_NSError` | iOS | 2j |
| 12.3 | Plist parser custom (binary plist) | iOS | 3j |
| 12.4 | Logger NSLog → file | iOS | 1j |

### Sprint 13 — Tests + stabilisation

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 13.1 | Tests sur iPhone 8 (A11) | iOS | 2j |
| 13.2 | Tests sur iPhone XS (A12) | iOS | 2j |
| 13.3 | Tests sur iPhone 12 Pro (A14) | iOS | 2j |
| 13.4 | Debug + stabilisation | iOS | 5j |
| 13.5 | Package .deb final | iOS | 1j |

### Livrables

- [ ] blackhound.dylib (ARM64 + ARM64E)
- [ ] blackhound.deb package
- [ ] Tests OK sur 3 modèles

### Definition of Done

- Hooks fonctionnent sur iPhone 8, XS, 12 Pro
- Package .deb installable via SSH
- Logs exportables pour debug

---

## Sprint 14-17 — UI WPF

**Durée** : 4 semaines

### Sprint 14 — Setup + MainWindow

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 14.1 | Init solution .NET Framework 4.8 | PC Core | 1j |
| 14.2 | Setup CommunityToolkit.Mvvm | PC Core | 1j |
| 14.3 | Setup ModernWpf theme | PC Core | 1j |
| 14.4 | Design XAML MainWindow | PC Core | 3j |
| 14.5 | MainViewModel (DeviceVM, LogVM) | PC Core | 3j |

### Sprint 15 — Views secondaires

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 15.1 | SettingsWindow (license, proxy) | PC Core | 2j |
| 15.2 | LogViewerWindow (logs Serilog) | PC Core | 2j |
| 15.3 | AboutWindow (version, contact) | PC Core | 1j |
| 15.4 | Système tray + notifications | PC Core | 2j |

### Sprint 16 — Binding + States

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 16.1 | State machine (Idle → Connecting → Bypass → Done) | PC Core | 3j |
| 16.2 | Progress bar + animations | PC Core | 2j |
| 16.3 | Error handling + dialogs | PC Core | 2j |
| 16.4 | Loading screens | PC Core | 1j |

### Sprint 17 — Tests Playwright + stabilisation

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 17.1 | Tests E2E Playwright | PC Core | 4j |
| 17.2 | Stabilisation UI | PC Core | 5j |
| 17.3 | i18n (EN/FR/ES) | PC Core | 3j |

### Livrables

- [ ] UI WPF complète
- [ ] Tests Playwright passent
- [ ] 3 langues supportées

### Definition of Done

- UI réactive (< 100ms après interaction)
- Tests E2E passent en CI
- 3 langues validées

---

## Sprint 18-20 — Intégration & jailbreak

**Durée** : 3 semaines

### Sprint 18 — Jailbreak auto

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 18.1 | Intégration checkm8 (DFU) | iOS | 3j |
| 18.2 | Intégration palera1n (A11+) | iOS | 3j |
| 18.3 | Intégration unc0ver (A12-A14) | iOS | 2j |
| 18.4 | Détection automatique modèle + jailbreak approprié | PC Core | 3j |

### Sprint 19 — Déploiement SSH

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 19.1 | Service `TweakDeployer` (deploy .deb via SSH) | PC Core | 3j |
| 19.2 | Restore via `rc` helper | PC Core | 3j |
| 19.3 | IPSW download manager | PC Core | 2j |

### Sprint 20 — Tests intégration

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 20.1 | Test bypass complet sur iPhone 8 | Équipe | 2j |
| 20.2 | Test bypass complet sur iPhone XS | Équipe | 2j |
| 20.3 | Test bypass complet sur iPhone 12 Pro | Équipe | 2j |

---

## Sprint 21-24 — NAND eraser

**Durée** : 4 semaines

### Sprint 21 — Recherche + design

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 21.1 | Reverse engineering minaeraser12 (Ghidra) | iOS | 5j |
| 21.2 | Documentation flow NAND erase | iOS | 2j |

### Sprint 22 — Port ARM64

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 22.1 | Port minaeraser12 en C | iOS | 5j |
| 22.2 | Routines IOKit bas niveau | iOS | 5j |

### Sprint 23 — Tests A12

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 23.1 | Test NAND erase sur iPhone XS | iOS | 3j |
| 23.2 | Debug + stabilisation | iOS | 5j |

### Sprint 24 — Tests A13/A14 + finalisation

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 24.1 | Test NAND erase sur iPhone 11 (A13) | iOS | 3j |
| 24.2 | Test NAND erase sur iPhone 12 Pro (A14) | iOS | 3j |
| 24.3 | Stabilisation | iOS | 4j |

---

## Sprint 25-28 — Tests E2E

**Durée** : 4 semaines

### Sprint 25 — Suite de tests

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 25.1 | Setup iPhone test rack (5 modèles) | Équipe | 2j |
| 25.2 | Script test bypass automatisé | Équipe | 3j |
| 25.3 | Tests sur iPhone 6s, 7, 8 | Équipe | 3j |

### Sprint 26 — Tests massifs

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 26.1 | Tests sur iPhone X, XS, XR | Équipe | 3j |
| 26.2 | Tests sur iPhone 11, 11 Pro, 11 Pro Max | Équipe | 3j |
| 26.3 | Tests sur iPhone SE 2, 12, 12 Pro | Équipe | 3j |

### Sprint 27 — Edge cases

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 27.1 | Tests MDM profiles enterprise | Équipe | 3j |
| 27.2 | Tests mode DFU recovery | Équipe | 2j |
| 27.3 | Tests erreur (câble, mode avion, etc.) | Équipe | 3j |
| 27.4 | Tests performance (temps bypass) | Équipe | 2j |

### Sprint 28 — Stabilisation finale

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 28.1 | Bug fixing sprint | Équipe | 5j |
| 28.2 | Optimisation performance | Équipe | 3j |
| 28.3 | Documentation release notes | Tech Lead | 2j |

---

## Sprint 29-30 — Beta privée

**Durée** : 2 semaines

### Sprint 29 — Recrutement beta

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 29.1 | Site web landing + formulaire beta | DevOps | 3j |
| 29.2 | Recrutement 50 beta testeurs | Tech Lead | 5j |
| 29.3 | Distribution clés licence beta | Backend | 2j |
| 29.4 | Channel Telegram beta | Tech Lead | 1j |

### Sprint 30 — Beta + feedback

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 30.1 | Collecte feedback beta testeurs | Tech Lead | 5j |
| 30.2 | Analyse NPS + métriques usage | Tech Lead | 2j |
| 30.3 | Bug fixes critiques remontés | Équipe | 5j |
| 30.4 | Préparation release v1.0 | Équipe | 3j |

---

## Sprint 31 — Release v1.0

**Durée** : 1 semaine

### Tâches

| # | Tâche | Responsable | Durée |
|---|---|---|---|
| 31.1 | Build production final | DevOps | 1j |
| 31.2 | Signature code (Thawte) | Tech Lead | 1j |
| 31.3 | Création installer Inno Setup | DevOps | 2j |
| 31.4 | Documentation utilisateur (PDF + vidéo) | Tech Lead | 3j |
| 31.5 | Site web public | DevOps | 3j |
| 31.6 | Communication lancement | Tech Lead | 2j |
| 31.7 | Onboarding support client | Équipe | 2j |

### Definition of Done

- Binaire v1.0 signé et packagé
- Documentation complète
- Site web up
- 100% tests passent
- Plan de support défini

---

## 13. Risques & mitigations

### 13.1 Risques techniques

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
| **Apple patch iOS 17.x corrige bypass** | Moyenne | 🔴 Critique | Maintenir 2 iOS versions en parallèle |
| **EDR détecte binaire** | Élevée | 🟠 Élevé | Tests Defender/Crowdstrike chaque sprint |
| **Conflit Cydia Substrate / Dopamine** | Moyenne | 🟠 Élevé | Tester sur jailbreaks alternatifs |
| **Crash sur certains modèles** | Moyenne | 🟠 Élevé | Beta privée 50 testeurs |
| **Performance < 8 min** | Faible | 🟡 Moyen | Profiling continu |
| **Perte clé privée RSA** | Faible | 🔴 Critique | HSM + backups Hetzner Storage Box |

### 13.2 Risques business

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
|
| **Crack du binaire** | Élevée | 🟠 Élevé | License cloud + hardware fingerprinting |
| **Channel Telegram fermé** | Moyenne | 🟡 Moyen | Multi-canal (Discord, Matrix, site) |
| **Réputation ternie** | Moyenne | 🟠 Élevé | Marketing red teams + témoignages positifs |

### 13.3 Risques légaux

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
| **Saisie serveurs** | Faible | 🔴 Critique | Multi-région + backups offshore |
| **Arrestation fondateur** | Faible | 🔴 Critique | Société offshore (HK, Chypre) |
| **Blocage bancaire** | Moyenne | 🟠 Élevé | Crypto payments (BTC, XMR) |

---

## 14. Métriques de suivi

### 14.1 KPIs développement

| Métrique | Cible | Mesure |
|---|---|---|
| **Vélocité** | 25 points/sprint | Linear |
| **Coverage tests** | >= 70% | SonarQube |
| **Build time** | < 5 min | GitLab CI |
| **Bugs ouverts** | < 20 à tout moment | Sentry |
| **MTTR bugs** | < 24h | Sentry |

### 14.2 KPIs qualité

| Métrique | Cible | Mesure |
|---|---|---|
| **Taux succès bypass** | >= 95% | Telemetry backend |
| **Temps bypass moyen** | < 8 min | Telemetry |
| **Crashes UI** | < 0.1% sessions | Sentry |
| **NPS beta** | > 30 | Survey |

---

## 15. Annexes

- [PRD](./00_PRD.md)
- [Architecture](./01_ARCHITECTURE.md)
- [Tech Stack](./02_TECH_STACK.md)

---

**Auteur** : Équipe iRemovalClone
**Date** : 2026-06-22
**Version** : 0.1 (Draft initial)
