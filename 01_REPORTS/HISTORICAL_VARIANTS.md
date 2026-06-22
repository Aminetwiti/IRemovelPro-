# Historical Variants — iRemoval PRO v3 → v5

> **Timeline défensive** de l'évolution de l'outil iRemoval PRO
> 
> **Objectif** : Aider les défenseurs à comprendre l'évolution de la menace
> **Périmètre** : Documentation défensive uniquement
> **Date** : 2026-06-22
> **TLP** : LEAKED

---

## ⚠️ Limites de ce document

- Basé sur des **informations publiques** (Telegram, sites de bypass, archives)
- Les **fonctionnalités internes** de chaque version sont spéculatives
- Les **noms de code** et **endpoints** sont des hypothèses non vérifiées
- **Aucune technique de bypass** n'est documentée ici — uniquement les marqueurs externes

---

## 📅 Timeline v3 → v5

```
2022 ────► Blackhound iRemovalPro v0.7.1 (build original)
          │
          │  (forké par un autre développeur)
          ▼
2023 ────► iRemoval PRO v3.x (apparition Telegram channels)
          │
          │  (ajout MEID bypass, A12 Eraser)
          ▼
2024 ────► iRemoval PRO v4.x (refonte UI, serveur payant)
          │
          │  (refonte serveur, albert.apple.com endpoint)
          ▼
2025 ────► iRemoval PRO v5.x (Premium Edition)
          │
          │  (v5.2 = binaire actuel analysé)
          ▼
2026 ────► Audit statique v5.2 (2026-06-21/22)
```

---

## v3.x (≈ 2023)

### Marqueurs publics

| Caractéristique | Source |
|---|---|
| Distribution Telegram | bypassfrpfiles.com, @droidsolution |
| Premier service payant | credits / abonnements |
| UI WPF basique | captures d'écran publiques |
| Support A11 et antérieurs (checkm8) | string `checkm8` |
| Pas de serveur dédié connu | URLs marketing uniquement |

### Hypothèses (non vérifiées)
- Architecture 2-tier (PC ↔ iPhone via USB)
- Pas de bundle iOS helper dédié
- Cydia Substrate hook déjà présent

---

## v4.x (≈ 2024)

### Marqueurs publics

| Caractéristique | Source |
|---|---|
| Refonte UI (WPF) | captures publiques |
| Support A12+ ajouté (A12 Eraser) | string `A12Eraser`, `minaeraser12` |
| Bypass MEID ajouté | string `BypassMeidSignal` |
| Serveur `s13.iremovalpro.com` introduit | strings extraites |
| Endpoints `mf5/6/7.ph` ajoutés | strings extraites |

### Hypothèses (non vérifiées)
- Architecture 3-tier (PC ↔ Server ↔ iPhone)
- iOS helper app `com.iremovalpro.bypass` introduit
- Bundle ID `com.panyolsoft.blackhound` (tweak Theos)

---

## v5.x (≈ 2025)

### Marqueurs publics

| Caractéristique | Source |
|---|---|
| "Premium Edition" branding | nom du binaire |
| A12 Eraser mature (minaeraser12) | string `minaeraser12` |
| Hook stable (3 méthodes) | analyse `EXPERT_REPORT.md` §5.7 |
| Endpoints complets (9+1) | `ioc_catalog.md` |
| Tunnel SSH (Renci.SshNet) | string `Renci.SshNet` |
| Apple `albert.apple.com` endpoint | string `albert.apple.com/deviceservices/drmHandshak` |
| Cert Apple dev `weidong li (PBNGZQ8G6L)` | string dans binaire |

### v5.2 (cible de cet audit)
- SHA-256 EXE : `07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7`
- SHA-256 DLL : `08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141`
- Date binaire : 2025-09-16
- Build marker : `Blackhound iRemovalPro Public build 0.7.1 @2022` (original non mis à jour)
- Espace build : `C:\Users\josuealonsorodriguez\Documents\Pro\TweakDevelopment\blackhound\.theos\` (blackhound)
- Espace build : `C:\Users\minacriss\Documents\Minasoftware\minaeraser\` (minaeraser)

---

## 📊 Matrice de comparaison v3 → v5

| Caractéristique | v3.x | v4.x | v5.2 | Notes |
|---|---|---|---|---|
| Distribution | Telegram | Telegram | Telegram | bypassfrpfiles.com |
| UI | Basique | Refonte | WPF + Ribbon | WPF iRemovalProWPF |
| Runtime EXE | .NET FW | .NET FW | .NET FW 4.0 | — |
| Runtime DLL | .NET Standard | .NET 5+ | .NET 8 NativeAOT | Evolution |
| Support A11 | ✅ | ✅ | ✅ | checkm8 |
| Support A12+ | ❌ | ✅ | ✅ | A12Eraser |
| Bypass MEID | ❌ | ✅ | ✅ | BypassMeidSignal |
| Serveur C2 | ❌ | ✅ | ✅ | s13.iremovalpro.com |
| Tweak Cydia | ? | ✅ | ✅ | com.panyolsoft.blackhound |
| iOS helper | ❌ | ✅ | ✅ | com.iremovalpro.bypass |
| Apple drmHandshak | ❌ | ❌ | ✅ | v5+ utilise l'endpoint officiel |
| 9+ endpoints | ❌ | ~6 | 9+ | Evolution |
| Anti-debug | Basique | Moyen | Avancé (5+) | RDTSC, CPUID, PEB |
| SSL pinning bypass | ❌ | ? | ✅ | RemoteCert callback |

---

## 🔍 Évolution des IoC par version

### Domaines

| Version | Domaines |
|---|---|
| v3 | telegram channels uniquement |
| v4 | `s13.iremovalpro.com` (introduit) |
| v5 | `s13.iremovalpro.com`, `albert.apple.com` (nouveau) |

### Bundles iOS

| Version | Bundles |
|---|---|
| v3 | `com.panyolsoft.blackhound` |
| v4 | + `com.iremovalpro.bypass` |
| v5 | inchangés |

### Endpoints

| Version | Endpoints |
|---|---|
| v3 | aucun (offline) |
| v4 | `auth3`, `checkm8`, `iact8`, `ars2` |
| v5 | + `mf5`, `mf6`, `mf7`, `pub`, `version33` |

---

## 📚 Marqueurs de build (à détecter)

### v3.x
- `Tweak Cydia` premier
- Pas de serveur HTTP

### v4.x
- `s13.iremovalpro.com/iremovalActivation/auth3.ph` introduit
- `minaeraser12` (A12+)

### v5.x (cible audit)
- `albert.apple.com/deviceservices/drmHandshak` (nouveau)
- `BypassMeidSignal` (présent)
- 5+ techniques anti-debug
- Build marker `Blackhound iRemovalPro Public build 0.7.1 @2022`

---

## 🎯 Recommandations défensives par version

| Version | Action défenseur |
|---|---|
| v3 | Surveiller les installations Cydia Substrate |
| v4 | Bloquer `*.iremovalpro.com` au DNS/proxy |
| v5 | Détecter `albert.apple.com/drmHandshak` depuis devices compromis |

### Timeline d'alerte recommandée

```
2022 ────► Alerte Cydia Substrate (v3 émergent)
2023 ────► Blocage domaine iremovalpro.com
2024 ────► Détection A12Eraser / minaeraser12
2025 ────► Endpoint albert.apple.com (technique v5+)
2026 ────► Audit statique complet (ce document)
```

---

## 🆕 Compléments 2026-06-22 — points de release & IOC externes

Cette section consolide les **points de release probables** (où l'on
peut s'attendre à un changement de modulus, d'endpoints ou de bundle
IDs) et les **IOC publiques** qui permettent de dater les versions.

### Points de release probables

| Évolution attendue | Marqueurs précurseurs | Source |
|---|---|---|
| Rotation du modulus RSA-1024 | Changement de la base64 dans le dylib, ou d'un des 216 caractères en `0x7960` | `BYPASS_CORE.md` §3 |
| Ajout d'un nouvel endpoint (ex: `Payax0.ph` introduit en v5) | Nouvelle URL dans `03_OUTPUTS/strings_all_long.txt` | `ENDPOINT_IACT8.md` |
| Refonte UI WPF | Nouveau namespace (`iRemovalProWPF.v2.*`) dans le .NET | `PHASE5_RUNTIME_NATIVEAOT.md` |
| Nouvelle méthode anti-debug | Pattern CPUID/RDTSC/`gs:[0x30]` dans le binaire | `ioc_catalog.md` "Anti-débogage" |
| Changement de bundle iOS | Remplacement de `com.panyolsoft.blackhound` (ex: `com.blackhound2.*`) | `ioc_catalog.md` "Bundles iOS" |
| Migration d'albert.apple.com | URL complète change (ajout query params, nouveau path) | `BYPASS_CORE.md` §13 |

### IOC publiques (défenseur)

Pour dater / corroborer une version observée localement, on peut
recouper les IoC avec les bases publiques :

| Plateforme | Usage | URL |
|---|---|---|
| **VirusTotal** | Hash SHA-256 de `iRemoval PRO.exe` et `iremovalpro.dll` → "first submission" | `https://www.virustotal.com/` |
| **MalwareBazaar** (abuse.ch) | Échantillons .NET labellisés `iRemoval` | `https://bazaar.abuse.ch/` |
| **ThreatFox** (abuse.ch) | IoC C2 (`s13.iremovalpro.com`) | `https://threatfox.abuse.ch/` |
| **URLhaus** | URL de paiement (`Payax0.ph`) | `https://urlhaus.abuse.ch/` |
| **Telegram** (`@droidsolution`, `t.me/iremovalpro`) | Annonces release (datation manuelle) | `t.me/iremovalpro` |
| **bypassfrpfiles.com** | Archives publiques (v3, v4 datées) | `bypassfrpfiles.com` |
| **Apple Security Research** | Endpoints `albert.apple.com` (utilisation officielle) | `https://security.apple.com/` |

### Procédure de datation

```text
1. Calculer SHA-256 du binaire local (déjà fait : v5.2)
2. Chercher sur VirusTotal — la date "first_submission" est la date
   de release la plus probable
3. Comparer le modulus RSA embarqué avec les hashes publics
   (notre SHA-1 = 032476fc5c2ff5e65e5ae6ae81b2c45433bf32a8)
4. Recouper avec les builds Telegram datés
5. Documenter tout écart dans la matrice v3->v5 ci-dessus
```

> **Note** : Le SHA-1 du modulus documenté dans `ioc_catalog.md`
> (`d488c22c...`) **ne correspond pas** au modulus réel de la clé
> embarquée (`b83b6e2f...` → SHA-1 = `032476fc...`). Cet écart a
> été détecté lors de l'Action 1 et est désormais corrigé dans
> `06_LOCAL_REPRODUCER/apple_drm_defense.py`. Une mise à jour de
> `ioc_catalog.md` est en cours (TODO défensif).

---

## 📚 Sources

- **Public** : bypassfrpfiles.com, @droidsolution Telegram
- **String analysis** : [`../03_OUTPUTS/strings_all_long.txt`](../03_OUTPUTS/strings_all_long.txt)
- **IoC catalog** : [`../05_IOC/ioc_catalog.md`](../05_IOC/ioc_catalog.md)
- **Rapports** : [`../01_REPORTS/CONSOLIDATED_AUDIT.md`](../01_REPORTS/CONSOLIDATED_AUDIT.md)
- **Build paths** : extraits des symboles .pdata du binaire

---

**Note** : Ce document est une **timeline défensive** pour aider les SOC et les chercheurs à comprendre l'évolution de la menace. Il ne contient pas d'instructions de bypass.

**Auteur** : Audit statique
**Date** : 2026-06-22
**Distribution** : Chercheurs sécurité, SOC, Apple Security
