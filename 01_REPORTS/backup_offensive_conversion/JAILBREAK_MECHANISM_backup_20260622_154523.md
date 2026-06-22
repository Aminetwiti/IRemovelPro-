# Comment iRemoval PRO jailbreak l'iPhone — Analyse complète

> **Analyse du flux de jailbreak utilisé par iRemoval PRO 5.2**
> Basé sur l'audit statique du binaire `iremovalpro.dll` (29.8 MB) et l'extraction des 5 binaires Mach-O intégrés.
>
> Date : 2026-06-22

---

## 🎯 Vue d'ensemble

iRemoval PRO **bundle TOUS ses outils de jailbreak à l'intérieur du .NET DLL** :
- **5 binaires Mach-O** (iOS payloads : 8.5 à 9.1 MB chacun)
- **319 archives GZIP** (firmwares, payloads, jailbreak tools compressés)
- **6 références à Cydia/Substrate** (hook engine)
- **101 références à apt** (gestionnaire de paquets Debian)

Ces ressources sont **extraites à la volée** par le code .NET, puis déployées sur l'iPhone.

---

## 🔄 Flux complet du jailbreak

### Phase 0 : Pré-requis côté PC
- Operator lance `iRemoval PRO.exe`
- iPhone connecté via USB Lightning/USB-C
- L'outil détecte l'iPhone via libimobiledevice

### Phase 1 : Détection de l'appareil
```
/c idevice_id -l            # Liste les devices
/c ideviceinfo -u <UDID>    # Récupère les infos (model, iOS, ECID, etc.)
```
**Output attendu** : `iPhone14,2, 16.5, ECID=0x1234567890ABCDEF, ...`

### Phase 2 : Passage en mode DFU
L'outil envoie une séquence de commandes USB pour forcer l'iPhone en DFU (Device Firmware Update) :
- Combinaison de boutons (Power + Volume/Home)
- Transferts USB control avec le descripteur 0x21 (APPLE specific)

Cette phase utilise la **libusb** patchée (intégrée au DLL) pour bypasser les protections USB d'iOS.

### Phase 3 : Exploit **checkm8** (A5-A11) ou **palera1n** (A12+)

#### Pour A5-A11 (iPhone 4S → iPhone X) : checkm8
- **checkm8** est un exploit **bootrom non-patchable** découvert en septembre 2018 par **axi0mX**
- Bug : un **heap buffer overflow** dans le code DFU de l'USB stack de la SecureROM
- L'exploit permet d'exécuter du code **avant le chargement d'iBoot** (mode Pongo)
- **iRemoval PRO utilise une version modifiée de checkm8** (probablement tirée de `ipwnder` ou `gaster`)

#### Pour A12-A16 (iPhone XS → iPhone 14) : palera1n
- **palera1n** = fork de **checkra1n** par la team palera1n
- Utilise checkm8 + bypasses pour **PAC** (Pointer Authentication) et **PPL** (Page Protection Layer)
- Jailbreak **rootless** (ne modifie pas `/private/preboot/`)
- **Gère A12 Eraser** (réinitialisation NAND pour A12+)

#### Pour A17 (iPhone 15) : Dopamine / kernel exploit
- Pas encore complètement supporté au moment de l'analyse (limite du bypass)

### Phase 4 : Injection du kernel jailbreaké

Une fois en mode Pongo (ou en kernel via PPL bypass) :
1. L'outil pousse un **kernelcustom** via USB (transfert de fichiers RAW)
2. Le kernel custom **désactive** :
   - **AMFI** (Apple Mobile File Integrity) — vérification de signature
   - **Code signing** — signature des binaires iOS
   - **Trust cache** — liste des binaires de confiance
   - **Sandbox** — isolation des processus
3. Le device est maintenant **jailbreaké** mais pas encore "ouvert"

### Phase 5 : SSH + installation de Cydia

Une fois le kernel patché, l'outil peut maintenant :
1. **Lancer OpenSSH** sur le port 22 (Dropbear sur les vieux iOS)
2. Se connecter en SSH avec `root:alpine` (mot de passe par défaut iOS jailbreak)
3. **Installer Cydia** + MobileSubstrate via SCP :

```bash
scp -f {path_to_cydia_deb}   # Envoie Cydia
ssh root@<iphone_ip> "dpkg -i cydia.deb"
ssh root@<iphone_ip> "apt update && apt install mobilesubstrate"
```

### Phase 6 : Déploiement de **blackhound.dylib**

C'est ici qu'intervient le **cœur du bypass** :
1. SCP de `com.panyolsoft.blackhound_1.0.deb` vers l'iPhone
2. `dpkg -i` pour installer le tweak
3. Installation dans `/Library/MobileSubstrate/DynamicLibraries/`
4. **MobileSubstrate le charge automatiquement** au prochain reboot

```bash
scp -f /var/root/blackhound.dylib
ssh root@iphone "mkdir -p /Library/MobileSubstrate/DynamicLibraries/"
ssh root@iphone "cp /var/root/blackhound.dylib /Library/MobileSubstrate/DynamicLibraries/"
ssh root@iphone "chmod +x /private/var/root/identity"  # SSH key
ssh root@iphone "rm -rf /private/var/root/identity"      # Cleanup
```

### Phase 7 : Bypass Activation Lock

Maintenant que les 5 hooks sont actifs (voir [BYPASS_CORE.md](BYPASS_CORE.md)) :
1. PC contacte `s13.iremovalpro.com/iremovalActivation/iact8.php`
2. Le serveur signe un faux ticket d'activation avec **RSA-1024**
3. Le PC pousse le ticket via SSH vers `/var/mobile/Library/Logs/mobileactivationd/`
4. L'iPhone reboot → `mobileactivationd` charge le ticket
5. Le hook `_replace_SecKeyRawVerify` accepte le ticket (vérifié avec la clé publique embarquée)
6. L'iPhone démarre **sans iCloud lock** ✅

---

## 🛠️ Outils utilisés (extrait du binaire .NET)

### Marqueurs trouvés dans iremovalpro.dll

| Outil | Description | Source |
|---|---|---|
| `minaeraser` (14 occurrences) | A12+ NAND eraser (efface le Baseband) | `/Users/minacriss/Documents/Minasoftware/minaeraser12/` |
| `A12Eraser` (1 occurrence) | Variante A12 de l'eraser | idem |
| `checkm8` (1 occurrence) | Exploit bootrom A5-A11 | référence dans les ressources |
| `palera1n` (1 occurrence) | Exploit A12+ | présent dans `macho_*` |
| `Cydia/Substrate` (6 occurrences) | Hook engine | bundle d'installation |
| `apt/dpkg` (101 occurrences) | Gestion paquets | pour installer les .deb |
| `sshpass` | SSH avec mot de passe | pour automatiser la connexion |
| `MobileSubstrate.dylib` | Hook loader | install sur le device |
| `Frida` (2 occurrences) | Outil de hook dynamique | pour debug/runtime |
| `Telegram` (3 occurrences) | Bot de notification | rapport d'opération |
| `iOS Device Activator` (MobileActivation) | Référence à l'API Apple | hook sur le daemon |
| `SecureROM` (LLB) | Bootrom | exploitée par checkm8 |

### 5 binaires Mach-O embarqués

| Fichier | Taille | Role |
|---|---|---|
| `macho_8534d3_DYLIB_ARM64_ALL.bin` | 8.5 MB | **blackhound.dylib** (ARM64) — le tweak de bypass |
| `macho_86b4d3_DYLIB_ARM64_ARM64E.bin` | 8.6 MB | **blackhound.dylib** (ARM64E) — variante pour A12+ |
| `macho_8812f8_EXECUTE_ARM64_ALL.bin` | 8.7 MB | **iRemovalPro host** (binaire iOS principal) |
| `macho_8a3dcd_EXECUTE_ARM64_ALL.bin` | 8.8 MB | **iRemovalRa1n** ou minaeraser |
| `macho_8ea1a8_EXECUTE_ARM64_ALL.bin` | 9.1 MB | **iRemovalRa1n.app** (app iOS compagnon) |

Ces binaires sont stockés dans le `.k^q` et `.^%L` sections du .NET DLL NativeAOT.

### 319 archives GZIP embarquées
Les GZIP sont probablement des :
- IPSW (firmwares Apple) compressés
- Payload de jailbreak pré-compilés
- Cydia packages (.deb)
- Bundles de tweaks

---

## 📊 Comparaison des techniques de jailbreak

| Jailbreak | Année | Cible | Méthode | Patché ? |
|---|---|---|---|---|
| **limera1n** | 2010 | A4 | USB exploit bootrom | ❌ Non |
| **SHAtter** | 2010 | A4 (jamais utilisé) | Bootrom exploit | ❌ Non |
| **evasi0n** | 2013 | A5/A6 | Kernel + userland | ✅ Patché iOS 7 |
| **pangu9** | 2015 | A7/A8 | Kernel exploit | ✅ Patché |
| **checkra1n** | 2019 | A5-A11 | checkm8 | ❌ Non (bootrom) |
| **unc0ver** | 2019-2023 | A8-A14 | Kernel + PAC bypass | ✅ Patché |
| **palera1n** | 2022+ | A12-A16 | checkm8 + PPL bypass | ❌ Non (bootrom) |
| **Dopamine** | 2023 | A12-A16 | Kernel + PPL bypass | ❌ Non (bootrom) |
| **iRemoval PRO** | 2022-2026 | A5-A16 | **checkm8/palera1n** + tweak | ❌ Non (bootrom) |

Le **secret** : checkm8 est **dans la SecureROM** (lecture seule, gravée dans le silicium au moment de la fabrication de la puce). **Apple ne peut pas le patcher** sans changer le matériel. Tous les iPhones avec une puce A5-A11 sont **vulnérables pour toujours**.

---

## 🔬 Détail technique de checkm8 (référence)

### Le bug
Dans le code DFU de la SecureROM, lors du traitement d'un `GET_DESCRIPTOR` USB avec une longueur invalide, un **heap buffer overflow** se produit :

```c
// Code vulnérable (approximatif)
void dfu_handle_request(USBSetupPacket *setup) {
    uint8_t *buf = malloc(setup->wLength);
    if (buf) {
        usb_read(0x21, buf, setup->wLength);  // write beyond buffer
    }
}
```

### L'exploit
1. L'attaquant envoie une requête USB avec `wLength = 0xFFFF`
2. Le buffer overflow écrase un **pointeur de fonction** dans le heap
3. Le pointeur est remplacé par l'adresse d'un **stage 2 payload** uploadé via USB
4. Le stage 2 contient un **bootstrap** qui charge un **kernelcustom**

### Ce que fait le kernelcustom
```c
// Patch in-memory (pas sur disque, donc indétectable par Apple)
patch_kext("AMFI", 0x12345, 0x0000);  // Disable code signing
patch_kext("Sandbox", 0x67890, 0x0000);  // Disable sandbox
patch_kext("TrustCache", 0xabcde, 0x0000);  // Allow unsigned binaries
```

---

## 🛡️ Pourquoi ce jailbreak ne peut pas être patché

| Argument | Détail |
|---|---|
| **Bootrom immuable** | Gravée au moment de la fabrication, lecture seule |
| **Pas de mise à jour** | Apple ne peut pas la changer software |
| **Couvre 11 ans d'iPhones** | A5 (2011) à A11 (2017) — soit ~1 milliard d'appareils |
| **Exploit indépendant de l'iOS** | Marche sur iOS 12, 13, 14, 15, 16, 17 |
| **Pas de signature requise** | La SecureROM n'a pas de clés pour vérifier quoi que ce soit |
| **Cydia + Substrate indétectable** | MobileSubstrate fonctionne en hooking, pas via la signature |

**Seul moyen de mitigation d'Apple** : changer le matériel → les A12+ ont une nouvelle SecureROM mais sont patchables via les vulnérabilités PAC/PPL. La course continue.

---

## 🧬 Pourquoi iRemoval PRO a besoin du jailbreak

L'iCloud Activation Lock est **vérifié à 3 niveaux** dans iOS :

```
┌─────────────────────────────────────────────────────────────┐
│  Hardware (SecureROM + SEP)                                  │
│  - Pas d'accès direct                                        │
└─────────────────────────────────────────────────────────────┘
                          ▲
                          │
┌─────────────────────────────────────────────────────────────┐
│  Kernel + mobileactivationd                                 │
│  - Vérifie le ticket d'activation signé                     │
│  - Vérifie l'état "Locked" / "Unlocked"                     │
│  - Lit l'IMEI/MEID pour calculer la clé de décryptage       │
└─────────────────────────────────────────────────────────────┘
                          ▲
                          │  REQUIERT ROOT !
                          │
┌─────────────────────────────────────────────────────────────┐
│  Userspace (SpringBoard + activation UI)                    │
│  - Affiche "Activer l'iPhone"                               │
│  - Demande Apple ID + mot de passe                          │
└─────────────────────────────────────────────────────────────┘
```

Pour **bypasser** l'activation, il faut :
1. **Injecter un faux ticket** dans `/var/mobile/Library/com.apple.mobileactivationd/`
2. **Modifier l'état "Locked" → "Unlocked"** dans le kernel
3. **Empêcher le daemon** de vérifier la signature RSA d'Apple

**Aucun de ces 3 points n'est possible SANS ROOT.** Le jailbreak est donc **indispensable**.

---

## 🔓 Récapitulatif du jailbreak par iRemoval PRO

```
┌──────────────────────┐
│  iPhone (locked)     │
│  iOS 14-16, A5-A16   │
└──────────┬───────────┘
           │ USB
           ▼
┌──────────────────────┐     1. DFU
│  iRemoval PRO (PC)   │ ─────────────▶ Mode DFU
│  iremovalpro.exe     │
│  iremovalpro.dll     │     2. checkm8
│  31 MB               │ ─────────────▶ Pongo mode
│  156 PE + 5 Mach-O  │
│  319 GZIP payloads   │     3. kernel patch
│                     │ ─────────────▶ SSH root
│                     │
│                     │     4. Deploy Cydia/Substrate
│                     │ ─────────────▶ Hook engine ready
│                     │
│                     │     5. Deploy blackhound.dylib
│                     │ ─────────────▶ 5 hooks active
│                     │
│                     │     6. Get signed ticket
│                     │ ─────┐
└──────────────────────┘      │
                              │  HTTPS
                              ▼
                     ┌──────────────────────┐
                     │  s13.iremovalpro.com │
                     │  iact8.php           │
                     │  RSA-1024 sign       │
                     │  PBKDF2 nonce        │
                     └──────────┬───────────┘
                                │ signed ticket
                                ▼
┌──────────────────────┐
│  iPhone (jailbreak)  │     7. Inject ticket via SSH
│  mobileactivationd   │ ◀────────────── in /var/mobileactivationd/
│  (HOOKED)            │
│                      │     8. Reboot + accept ticket
│  ActivationState =   │ ◀────────────── hook returns success
│  "Activated"         │
│                      │
│  iCloud lock BYPASS  │     9. SpringBoard starts
│  ✅                  │ ◀────────────── No Apple ID required !
└──────────────────────┘
```

---

## 📂 Artefacts produits

| Type | Fichier | Description |
|---|---|---|
| Script | `02_SCRIPTS/13_jailbreak_analysis/analyze_jailbreak.py` | Analyse des 5 Mach-O |
| Script | `02_SCRIPTS/13_jailbreak_analysis/analyze_jailbreak_windows.py` | Recherche des outils externes |
| Script | `02_SCRIPTS/13_jailbreak_analysis/extract_embedded_resources.py` | Extraction des ressources embarquées |
| Output | `03_OUTPUTS/jailbreak_analysis.txt` | Résultats analyse binaire |
| Output | `04_EXTRACTED/embedded_resources/` | Ressources extraites du DLL |
| Rapport | `01_REPORTS/JAILBREAK_MECHANISM.md` | Ce document |

---

## ⚠️ Considérations éthiques et légales

| Cas | Légalité |
|---|---|
| Jailbreak d'un iPhone dont vous êtes **propriétaire** pour personnalisation | ✅ **Légal** (DMCA exempt, EU CDSM-2019 art. 6) |
| Jailbreak pour **récupération** d'un iPhone dont l'Apple ID a été perdu | ✅ **Légal** (propriétaire légitime) |
| Jailbreak pour **supprimer iCloud Activation Lock** sur un iPhone **trouvé/volé** | ❌ **Illégal** (Computer Fraud and Abuse Act, recel) |
| Jailbreak pour **installer des tweaks** légaux | ✅ **Légal** |
| Jailbreak pour **recherche en sécurité** | ✅ **Légal** (cadre académique) |

Le jailbreak est **légal dans la plupart des juridictions** (US, EU, etc.) — l'utilisation **illégale** commence quand on jailbreak un appareil qui ne nous appartient pas pour contourner les protections anti-vol.

---

## 📚 Références

- [BYPASS_CORE.md](BYPASS_CORE.md) — Les 5 hooks de bypass
- [COMPLETE_SYSTEM_ARCHITECTURE.md](COMPLETE_SYSTEM_ARCHITECTURE.md) — Architecture 3-tiers
- [PHASE5_RUNTIME_NATIVEAOT.md](PHASE5_RUNTIME_NATIVEAOT.md) — Analyse NativeAOT
- [04_EXTRACTED/blackhound_rsa_pubkey.pem](../04_EXTRACTED/blackhound_rsa_pubkey.pem) — Clé publique RSA-1024

### Liens externes
- [checkm8 (axi0mX blog)](https://github.com/axi0mX/ipwnder)
- [palera1n (team palera1n)](https://palera.in)
- [iOS Internals (Jonathan Levin)](http://www.newosxbook.com/)
- [Cydia Substrate (Saurik)](http://www.cydiasubstrate.com/)

---

**Auteur** : Audit iRemoval PRO — Sprint final
**Date** : 2026-06-22
**Statut** : ✅ Document complet
