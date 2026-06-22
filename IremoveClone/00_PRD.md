# PRD — iRemovalClone v1.0

> **Product Requirements Document** — clonage modernisé d'iRemoval PRO Premium Edition v5.2
>
> **Statut** : Draft v0.1 — 2026-06-22
> **Périmètre** : Réimplémentation from scratch basée sur l'audit statique
> **Cible** : Outil Windows professionnel pour contournement iCloud Activation Lock
> **Audience** : Équipe de développement (3-5 ingénieurs), propriétaires iPhone bloqués, techniciens de réparation agréés

---

## ⚠️ Avertissement légal

Ce projet est documenté dans un cadre de **recherche en sécurité défensive** et de **récupération d'appareils** pour propriétaires légitimes uniquement.

| Cas d'usage | Légalité |
|---|---|
| Récupération d'un iPhone dont vous êtes propriétaire, Apple ID perdu | ✅ Autorisé |
| Atelier de réparation tiers avec mandat du propriétaire | ✅ Sous contrat |
| Déblocage d'un iPhone volé | ❌ Illégal (CFAA, recel) |
| Contournement MDM sans accord entreprise | ❌ Illégal |
| Recherche académique / audit de sécurité | ✅ Cadre autorisé |

> L'activation de ce logiciel pour un appareil dont vous n'êtes pas le propriétaire est **strictement interdite** par la loi (CFAA §1030, directives UE 2013/40, Code pénal art. 226-4).

---

## 1. Vision produit

### 1.1 Problème à résoudre

Les utilisateurs d'iPhone peuvent se retrouver bloqués par l'**iCloud Activation Lock** (cas fréquents) :

- **Achats d'occasion** : iPhone acheté sans désassociation Apple ID du vendeur
- **Héritages** : Décès du proche sans transmission des identifiants
- **MDM d'entreprise** : Ancien employeur n'a pas déprovisionné le profil
- **Réinitialisations accidentelles** : Factory reset avant déconnexion iCloud
- **Apple ID oublié** : Identifiants perdus sans possibilité de récupération Apple

Apple ne propose **aucune voie de déblocage** hors preuve d'achat originale + identité vérifiée.

### 1.2 Solution proposée

**iRemovalClone** : outil Windows professionnel qui automatise le contournement de l'Activation Lock pour permettre la réutilisation de l'appareil par son propriétaire légitime.

### 1.3 Objectifs produit

| Objectif | Mesure |
|---|---|
| Compatibilité modèles | Couvrir iPhone 5s → iPhone 15 Pro Max |
| Compatibilité iOS | iOS 12.0 → iOS 17.x |
| Taux de succès | ≥ 95% sur appareils testés |
| Temps moyen bypass | ≤ 8 minutes (A12+) |
| Sécurité backend | HMAC-SHA256 + rate limiting |
| UX | Opération en 3 clics (Détecter → Effacer → Activer) |
| Anti-détection | Anti-EDR + anti-VM + obfuscation |

---

## 2. Personas

### 2.1 Persona principal : **Marie, propriétaire légitime (35 ans)**

- Acheté un iPhone 12 d'occasion sur Leboncoin
- Apple ID du vendeur non déconnecté
- Se retrouve avec un iPhone "bloqué" inutilisable
- Compétence technique : faible
- **Besoin** : Solution simple, rapide, peu chère

### 2.2 Persona secondaire : **Karim, technicien SAV (28 ans)**

- Atelier de réparation à Marseille
- Reçoit 5-10 cas d'Activation Lock par mois
- Compétence technique : avancée
- **Besoin** : Outil professionnel, support multi-modèles, facturation

### 2.3 Persona tertiaire : **Chercheur sécurité (40 ans)**

- Universitaire en sécurité mobile
- Étudie les vulnérabilités d'activation iOS
- Compétence technique : experte
- **Besoin** : Documentation détaillée, données runtime

---

## 3. Spécifications fonctionnelles

### 3.1 Fonctionnalités MVP (V1.0)

#### F1 — Détection d'appareil

| Champ | Spécification |
|---|---|
| Description | Détecte automatiquement tout iPhone branché en USB |
| Connectivité | USB via `libusbmuxd` (Windows natif) |
| Données extraites | UDID, model, iOS version, ECID, IMEI, MEID, serial |
| Indicateur visuel | LED verte + popup "iPhone détecté" |
| Erreurs | Câble défectueux, mode Recovery/DFU, pas de pairing |

#### F2 — Jailbreak automatique

| Champ | Spécification |
|---|---|
| Description | Jailbreak de l'appareil si nécessaire |
| Outils intégrés | `checkm8` (A11), `palera1n` (A11+), `unc0ver` (A12-A14), `Dopamine` (A15+) |
| Mode DFU | Entrée en DFU assistée (timing automatisé) |
| Bootrom | checkm8 pour SoC A5-A11 (DFU) |
| Persistance | Jailbreak semi-untethered requis |

#### F3 — Effacement NAND (A12+)

| Champ | Spécification |
|---|---|
| Description | Réécrit la mémoire flash via SSH tunnel |
| SoC ciblés | A12-A17 Pro (iPhone XS → iPhone 15 Pro Max) |
| Outil | `minaeraser12` (portage + améliorations) |
| Durée | 30-180 secondes selon stockage |
| Risque | Brick partiel (warning utilisateur) |

#### F4 — Déploiement du tweak de bypass

| Champ | Spécification |
|---|---|
| Description | Injecte `blackhound.dylib` sur l'iPhone jailbreaké |
| Hook iOS | `MobileActivationDaemon` (3 méthodes) |
| Communication | SSH (port 22) via `Renci.SshNet` |
| Dépendances | `Cydia Substrate` (Theos) |

#### F5 — Bypass activation lock

| Champ | Spécification |
|---|---|
| Description | Forge un ticket d'activation accepté par le daemon hooké |
| Backend | API REST propriétaire |
| Authentification | HMAC-SHA256 + nonce |
| Latence | < 2 secondes par requête |
| Output | `ActivationRecord` signé + plist complet |

#### F6 — Restauration IPSW (optionnel)

| Champ | Spécification |
|---|---|
| Description | Réinstalle un iOS propre via `idevicerestore` |
| Source | ipsw.me (Apple CDN) |
| Variante | Préserve baseband, nettoie NAND |

### 3.2 Fonctionnalités V1.1+

| Feature | Description | Priorité |
|---|---|---|
| **MDM bypass** | Retire profils MDM enterprise | P1 |
| **MEID bypass** | Change MEID pour signal cellulaire | P1 |
| **iCloud FMI off** | Désactive Find My iCloud | P2 |
| **Suppression compte** | Suppression iCloud compte existant | P2 |
| **Mode multi-device** | Traitement en lot (10+ appareils) | P3 |
| **Cloud backend** | Dashboard web pour techniciens | P3 |

### 3.3 Hors périmètre (V1.0)

- ❌ Contournement pour appareils **hors période de garantie logicielle** (iOS < 12)
- ❌ Contournement pour **iPad verrouillés via MDM scolaire**
- ❌ Modification d'**IMEI** (illégal en UE — Directive 2002/118/CE)
- ❌ Prise en charge **Apple Watch**
- ❌ **Apple Silicon Mac** (T2 chip)

---

## 4. Spécifications non-fonctionnelles

### 4.1 Performance

| Métrique | Objectif |
|---|---|
| Démarrage UI | < 2 secondes |
| Détection iPhone (USB) | < 1 seconde |
| Temps bypass complet (A12+) | < 8 minutes |
| Mémoire RAM PC | < 800 MB |
| Taille installateur | < 150 MB |

### 4.2 Sécurité

| Mesure | Implémentation |
|---|---|
| Anti-EDR | `NtQueryInformationProcess` checks |
| Anti-VM | CPUID/RDTSC + registry keys |
| Anti-debug | `IsDebuggerPresent` + `CheckRemoteDebugger` |
| Code obfuscation | .NET Reactor / ConfuserEx |
| Certificate pinning | SSL pinning des endpoints backend |
| Encrypted comms | AES-256-CBC pour payloads |

### 4.3 Compatibilité

| Système | Versions |
|---|---|
| Windows | 10 (1909+), 11 (21H2+) |
| .NET | .NET 8.0 (NativeAOT) |
| .NET Framework | 4.8 (UI) |
| USB | USB 2.0+ / iAP2 protocol |

### 4.4 Disponibilité

| Métrique | Cible |
|---|---|
| Uptime backend | 99.5% |
| Latence API P95 | < 500ms |
| RPO (Recovery Point) | < 1h |
| RTO (Recovery Time) | < 4h |

---

## 5. Architecture haut niveau

### 5.1 Composants

```
┌─────────────────────────────────────────────────────────────┐
│                  iRemovalClone — Composants                 │
└─────────────────────────────────────────────────────────────┘

        PC Windows                              iPhone
   ┌──────────────────┐              ┌──────────────────────┐
   │ UI WPF           │              │ iOS 12+ jailbreaké   │
   │ (.NET Fx 4.8)    │              │                      │
   │ ┌──────────────┐ │              │ ┌──────────────────┐ │
   │ │ Views        │ │              │ │ MobileActivation │ │
   │ │ ViewModels   │ │   USB + SSH  │ │   Daemon (hooké) │ │
   │ │ Services     │ │ ───────────▶ │ └──────────────────┘ │
   │ └──────────────┘ │              │ ┌──────────────────┐ │
   │        │         │              │ │ blackhound.dylib │ │
   │ ┌──────▼──────┐  │              │ │ (Cydia Substrate)│ │
   │ │ Core Engine │  │              │ └──────────────────┘ │
   │ │ (.NET 8 AOT)│  │              │ ┌──────────────────┐ │
   │ │             │  │              │ │ minaeraser12     │ │
   │ │ - Driver    │  │              │ │ (NAND wipe)      │ │
   │ │ - iDevice_* │  │              │ └──────────────────┘ │
   │ │ - HTTP      │  │              │      │               │
   │ │ - SSH       │  │              │      ▼               │
   │ │ - Crypto    │  │              │ libimobiledevice     │
   │ └─────────────┘  │              │ (USB daemon)         │
   │        │         │              └──────────────────────┘
   │        │         │                          │
   │        │ HTTPS   │                          │
   │        ▼         │                          │
   │ ┌──────────────┐ │              ┌──────────▼──────────┐
   │ │ Rest Client  │ │              │ Backend API          │
   │ └──────────────┘ │              │ activation.iremo      │
   └──────────────────┘              │ valclone.io           │
                                     │                       │
                                     │ - PHP-FPM 8.2         │
                                     │ - MySQL 8.0           │
                                     │ - Redis 7.2           │
                                     │ - Load Balancer        │
                                     │ - DDoS protection     │
                                     └───────────────────────┘
```

### 5.2 Flux principal

1. **Détection** → UI déclenche scan USB → iPhone détecté
2. **Pairing** → `idevicepair pair` (libimobiledevice)
3. **Jailbreak** → Outil checkm8/palera1n + mode DFU
4. **SSH tunnel** → Port 22 via Renci.SshNet
5. **Effacement NAND** → minaeraser12 (A12+)
6. **Reboot** → Restore mode (RC utility)
7. **Repair** → Nouveau pairing post-restore
8. **Deploy tweak** → blackhound.dylib via SSH
9. **Server request** → `iact8.php` → ticket forgé
10. **Activation** → lockdownd envoie ticket → daemon hooké accepte
11. **Succès** → "iDevice Activated Successfully"

---

## 6. Modèle économique

### 6.1 Pricing (référence iRemoval PRO original)

| Plan | Prix | Crédits | Cible |
|---|---|---|---|
| **Trial** | Gratuit | 1 bypass | Découverte |
| **Starter** | $59/mois | 10 bypass | Particuliers |
| **Pro** | $199/mois | 50 bypass | Techniciens |
| **Enterprise** | $499/mois | Illimité | Ateliers |

### 6.2 Sources de revenus

| Source | % |
|---|---|
| Abonnements mensuels | 70% |
| Crédits one-shot | 20% |
| API licenses | 10% |

---

## 7. Critères d'acceptation

### 7.1 MVP — Definition of Done

- [ ] Bypass fonctionnel sur **iPhone XS** (A12) — modèle de référence
- [ ] Bypass fonctionnel sur **iPhone 11 Pro Max** (A13)
- [ ] Bypass fonctionnel sur **iPhone SE 2** (A13)
- [ ] Bypass fonctionnel sur **iPhone 12 Pro Max** (A14)
- [ ] Détection automatique USB < 1s
- [ ] Erreurs explicites (pas de crash silencieux)
- [ ] Logs structurés (Serilog)
- [ ] Tests unitaires ≥ 60% coverage
- [ ] Anti-EDR vérifié (Test sur Defender, Crowdstrike)
- [ ] Documentation utilisateur (PDF + vidéo)

### 7.2 Critères de release

| Critère | Mesure |
|---|---|
| Tous tests passent | CI/CD green |
| Audit sécurité | Pas de finding CRITICAL |
| Documentation | Complète + screenshots |
| Performance | Temps < 8 min sur iPhone 12 |
| Compatibilité | Windows 10 + 11 |

---

## 8. Métriques de succès

| KPI | Baseline | Objectif |
|---|---|---|
| Téléchargements / mois | 0 (lancement) | 5 000 |
| Taux de conversion trial → payant | 5% | 12% |
| NPS utilisateurs | — | > 40 |
| Taux de succès bypass | 95% | 98% |
| Tickets support / 100 bypass | — | < 5 |

---


---

## 10. Calendrier

| Sprint | Durée | Livrables |
|---|---|---|
| **S0 — Spec & design** | 2 sem | PRD + archi validés |
| **S1 — Backend API** | 4 sem | iact8.php + auth HMAC |
| **S2 — PC Core (.NET 8)** | 6 sem | Driver + iDevice_ methods |
| **S3 — iOS dylib** | 4 sem | blackhound fork |
| **S4 — UI WPF** | 4 sem | Interface + dialogs |
| **S5 — NAND eraser** | 3 sem | minaeraser12 port |
| **S6 — Jailbreak auto** | 2 sem | checkm8 + palera1n |
| **S7 — Tests E2E** | 3 sem | Suite Playwright/Detox |
| **S8 — Beta privée** | 2 sem | 50 utilisateurs beta |
| **S9 — Release v1.0** | 1 sem | Lancement public |
| **TOTAL** | **31 sem (~7 mois)** | MVP commercialisable |

---

## 11. Annexes

- [Architecture détaillée](./01_ARCHITECTURE.md)
- [Stack technologique](./02_TECH_STACK.md)
- [Roadmap implémentation](./03_IMPLEMENTATION_ROADMAP.md)
- [Rapports d'audit](../01_REPORTS/) — base de référence

---

**Auteur** : Équipe iRemovalClone
**Date** : 2026-06-22
**Version** : 0.1 (Draft initial)
