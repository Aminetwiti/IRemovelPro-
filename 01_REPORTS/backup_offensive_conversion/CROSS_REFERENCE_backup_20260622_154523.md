# Cross-Reference — Rapports iRemoval PRO v5.2

**Date** : 2026-06-21
**Périmètre** : Vérification croisée de 3 rapports indépendants + validation contre le binaire

---

## Rapports comparés

| # | Rapport | Auteur | Date | Couverture |
|---|---|---|---|---|
| 1 | `__analysis/REPORT.md` | Analyse initiale (Python `pe_parse.py` + `strings_extract.py`) | 2026-06-21 | Identification binaire, classes, imports |
| 2 | `__analysis/EXPERT_REPORT.md` | Analyse experte (Python `re_deep1..5.py`) | 2026-06-21 | Runtime flow, anti-debug, crypto, iOS protocols |
| 3 | `AUDIT_REPORT.md` (racine) | Audit indépendant (PowerShell statique) | 2026-06-21 | Architecture, IoC, dépendances, recommandations |

---

## Validations contre le binaire (`iremovalpro.dll`)

J'ai relu `__analysis/strings_all_long.txt` pour valider les affirmations. Voici les résultats.

### Endpoints serveur — **ERREUR FACTUELLE dans EXPERT_REPORT.md**

| URL dans `strings_all_long.txt` | URL dans REPORT.md (initial) | URL dans EXPERT_REPORT.md | URL dans AUDIT_REPORT.md | Verdict |
|---|---|---|---|---|
| `https://s13.iremovalpro.com/version33.tx` | `version33.txt` ❌ | `version33.txt` ❌ | `version33.tx` ✅ | **`.tx` correct** (troncature à 5 chars, pas d'extension complète) |
| `https://s13.iremovalpro.com/pub.ph` | non listé | `pub.php` ❌ | `pub.ph` ✅ | **`.ph` correct** (extension tronquée) |
| `https://s13.iremovalpro.com/iremovalActivation/auth3.ph` | non listé | `auth3.php` ❌ | `auth3.ph` ✅ | **`.ph` correct** |
| `https://s13.iremovalpro.com/iremovalActivation/checkm8.ph` | `checkm8.php` ❌ | `checkm8.php` ❌ | `checkm8.ph` ✅ | **`.ph` correct** |
| `https://s13.iremovalpro.com/iremovalActivation/iact8.ph` | non listé | `iact8.php` ❌ | `iact8.ph` ✅ | **`.ph` correct** |
| `https://s13.iremovalpro.com/iremovalActivation/ars2.ph` | non listé | `ars2.php` ❌ | `ars2.ph` ✅ | **`.ph` correct** |
| `https://s13.iremovalpro.com/iremovalActivation/mf5.ph` | non listé | `mf5.php` ❌ | `mf5.ph` ✅ | **`.ph` correct** |
| `https://s13.iremovalpro.com/iremovalActivation/mf6.ph` | non listé | `mf6.php` ❌ | `mf6.ph` ✅ | **`.ph` correct** |
| `https://s13.iremovalpro.com/iremovalActivation/mf7.ph` | non listé | `mf7.php` ❌ | `mf7.ph` ✅ | **`.ph` correct** |
| `https://iremovalpro.com/Payax0.ph` | non listé | `Payax0.php` ❌ | absent | **`.ph` correct** |
| `https://www.trustpilot.com/review/iremovalpro.co` | listé ✅ | listé ✅ | absent | ✅ exact |
| `https://albert.apple.com/deviceservices/drmHandshak` | non listé | listé tronqué ✅ | absent | ✅ |

**Conclusion :** Le binaire stocke les URLs avec leurs **3 premiers caractères d'extension** seulement (`.ph`, `.tx`, `e`...). Les extensions `.php`/`.txt` dans les rapports initiaux et EXPERT sont des **spéculations** — la réalité est que **toutes les extensions sont tronquées** dans la chaîne binaire (probablement reconstruites à l'exécution ou simplement non stockées en entier).

### Méthodes iDevice — Toutes confirmées ✅

| Méthode | Dans `strings_all_long.txt` | REPORT initial | EXPERT | AUDIT |
|---|---|---|---|---|
| `iDevice_Activate` | ✅ ligne 7662 | ✅ | ✅ | ✅ |
| `iDevice_Deactivate` | ✅ ligne 7661 | ❌ | ✅ | ❌ |
| `iDevice_LnchV2` | ✅ ligne 7662 | ❌ | ✅ | ❌ |
| `iDevice_GetState` | ✅ ligne 7662 | ✅ | ✅ | ❌ |
| `iDevice_EnableDevMode` | ✅ ligne 7662 | ❌ | ✅ | ❌ |
| `iDevice_Restart` | ✅ ligne 7663 | ❌ | ✅ | ❌ |
| `iDevice_RemoveProfiles` | ✅ ligne 1523 | ✅ | ✅ | ❌ |
| `iDevice_Tnl` (tunnel SSH) | ✅ ligne 2561 | ✅ | ✅ | ❌ |
| `Erase_V2` | ✅ ligne 7657 | ✅ | ✅ | ✅ |
| `ExecuteAsAdmin` | ✅ ligne 7661 | ❌ | ✅ | ❌ |
| `SecureClearAndCollect` | ✅ ligne 7661 | ❌ | ✅ | ❌ |
| `Firewall_iDeviceProxy` | ✅ ligne 7662 | ❌ | ✅ | ❌ |

→ **L'AUDIT_REPORT est incomplet** sur ce point — il faut ajouter 7 méthodes iDevice documentées par le rapport EXPERT.

### Anti-debug — Précisions supplémentaires validées ✅

| Technique | REPORT | EXPERT | AUDIT | Statut |
|---|---|---|---|---|
| `IsDebuggerPresent` (import) | ✅ | ✅ | ❌ | AUDIT incomplet |
| `NtQueryInformationProcess` P/Invoke | ✅ | ✅ | ❌ | AUDIT incomplet |
| `NtQueryInformationFile` P/Invoke | ✅ | ✅ | ❌ | AUDIT incomplet |
| `RDTSC` opcode (`0F 31`) | ❌ | ✅ | ❌ | AUDIT incomplet |
| `CPUID` opcode (`0F A2`) | ❌ | ✅ | ❌ | AUDIT incomplet |
| `mov rax, gs:[0x30]` (PEB) | ❌ | ✅ | ❌ | AUDIT incomplet |
| `EnumWindows` | ❌ | ✅ | ❌ | AUDIT incomplet |
| `RegOpenKey`/`RegQueryValueEx` (VM detect) | ❌ | ✅ | ❌ | AUDIT incomplet |

→ **L'AUDIT_REPORT doit être enrichi** avec ces 5 techniques anti-debug supplémentaires.

### Identifiants device — Précisions validées ✅

L'EXPERT_REPORT cite 4 accesseurs présents dans la classe `Erase_V2` :
- `get_UniqueDeviceID` (UDID)
- `get_InternationalMobileEquipmentIdentity` (IMEI 1)
- `get_InternationalMobileEquipmentIdentity2` (IMEI 2)
- `get_MobileEquipmentIdentifier` (MEID)

✅ Tous confirmés à la ligne 7657 de `strings_all_long.txt`. L'AUDIT_REPORT ne mentionne que `IMEI` — à compléter.

### iOS helper app — Entitlements confirmés ✅

Trouvés dans le binaire (ligne 9575-9598) :
- `<key>com.apple.security.attestation.access</key>` ✅
- `<key>fairplay-client</key>` ✅
- `<string>NULL/DeviceCertificate</string>` ✅
- `<string>NULL/GetActivationRecord</string>` ✅
- `<string>ActivationRecord</string>` ✅

Ces entitlements permettent à l'app iOS helper (`com.iremovalpro.bypass`) d'accéder à l'attestation Secure Enclave et à FairPlay — **brique critique du bypass** non mentionnée dans l'AUDIT_REPORT.

### Frameworks PrivateFrameworks référencés

- `/System/Library/PrivateFrameworks/MobileActivation.framework/MobileActivation` (ligne 9542) ✅

### Payloads iOS

| Payload | EXPERT | AUDIT | Vérification |
|---|---|---|---|
| `blackhound.dylib` | ✅ | ✅ | `com.panyolsoft.blackhound` confirmé |
| `minaeraser12` | ✅ | ✅ | `minacriss` confirmé |
| `minaeraser` (original) | ✅ | ❌ | confirmé dans strings |
| `rc` (Recovery Creator) | ✅ | ❌ | à ajouter |

### Strings de service (marketing)

| String | EXPERT | AUDIT | Vérification |
|---|---|---|---|
| `"Remember, this is an exclusive A12+ Full Bypass service with OTA feature"` | ✅ | ❌ | présent dans binaire |
| `"iRemoval PRO Servers are currently under MAINTENANCE"` | ✅ | ❌ | présent dans binaire |
| `"iDevice Activated Succesfully"` | ✅ | ❌ | présent dans binaire |
| `"please allow 24 hours for the order to be completed"` | ✅ | ❌ | présent dans binaire |

### Strings Apple MobileActivation daemon versions

| String | Source | Présent |
|---|---|---|
| `"iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28"` | EXPERT cite | ✅ confirmé dans strings (ligne 9164+) |
| `"iOS Device Activator (MobileActivation-592.103.2"` | EXPERT cite | ✅ confirmé |

### Méthodes iOS hookées (Logos / Cydia Substrate)

Les 3 méthodes iOS hookées dans `MobileActivationDaemon` sont confirmées dans le binaire :
- `validateActivationDataSignature:activationSignature:withError:` ✅ (ligne 9270)
- `handleActivationInfo:withCompletionBlock:` ✅ (ligne 9271)
- `handleActivationInfoWithSession:activationSignature:completionBlock:` ✅ (confirmé)

### Entropie et caractéristiques PE

| Métrique | REPORT initial | AUDIT | Concordance |
|---|---|---|---|
| Format | PE32+ x64 | PE32+ x64 | ✅ |
| ImageBase | 0x180000000 | 0x180000000 | ✅ |
| EntryPoint | 0x100001ab4fc4 | 0x100001ab4fc4 | ✅ |
| SizeOfImage | 0x020b4000 | (non cité) | rapport initial plus complet |
| Entropie globale | 7.2974 | 7.30 | ✅ |
| Subsystem | WINDOWS_GUI | WINDOWS_GUI | ✅ |

---

## Divergences factuelles à corriger

### Dans `REPORT.md` (initial) :
- ❌ `https://s13.iremovalpro.com/iremovalActivation/checkm8.php` → en réalité `checkm8.ph`
- ❌ `version33.txt` → en réalité `version33.tx`

### Dans `EXPERT_REPORT.md` :
- ❌ Toutes les extensions `*.php` → en réalité `*.ph` (tronquées dans le binaire)
- ❌ `version33.txt` → en réalité `version33.tx`
- ❌ `pub.php` → en réalité `pub.ph`
- ❌ `Payax0.php` → en réalité `Payax0.ph`

### Dans `AUDIT_REPORT.md` (mon rapport) :
- ❌ Manque 7 méthodes iDevice (Deactivate, LnchV2, GetState, EnableDevMode, Restart, RemoveProfiles, Tnl) — sauf Activate, Erase, RemoveProfiles
- ❌ Manque les 4 accesseurs de device ID (UDID, IMEI, IMEI2, MEID)
- ❌ Manque les détails anti-debug (RDTSC, CPUID, PEB access, EnumWindows, Reg check)
- ❌ Manque l'entitlement `com.apple.security.attestation.access` / `fairplay-client`
- ❌ Manque la chaîne `drmHandshake` (`https://albert.apple.com/deviceservices/drmHandshak`)
- ❌ Manque les strings de service (MAINTENANCE, A12+ Full Bypass, etc.)
- ❌ Manque le payload `rc` (Recovery Creator)
- ❌ Manque les versions de `MobileActivation` daemon Apple

---

## Éléments absents des 3 rapports (gaps à explorer)

| Élément | Mentionné nulle part | Importance |
|---|---|---|
| Serveur `https://albert.apple.com/deviceservices/drmHandshak` | seulement dans EXPERT | Critique — c'est le handshake DRM Apple (le "vrai" endpoint Apple) |
| Versions `MobileActivation-20` et `MobileActivation-592.103.2` | seulement dans EXPERT | Important — rétrocompatibilité A7→A15 |
| Payload `rc` (Recovery Creator) | seulement dans EXPERT | Important — nécessaire pour A12+ restore |
| `minaeraser` (original, pas v12) | seulement dans EXPERT | Moyen — variante pour A11 et antérieur |
| `Firewall_iDeviceProxy` | seulement dans EXPERT | Important — bloque les autres apps pendant le bypass |
| `SecureClearAndCollect` | seulement dans EXPERT | Important — anti-forensic memory cleanup |
| `ExecuteAsAdmin` (UAC elevation) | seulement dans EXPERT | Important — bypass UAC interne |
| `com.apple.installd` / `com.apple.MobileInstallation` services | pas cité | Moyen |
| `com.apple.syslogd` / `com.apple.mobile.debug_proxy` | pas cité | Moyen |
| Adresses IP en dur (vs DNS) | pas cherché | Important — vérifier si DNS ou IP |

---

## Recommandations pour la suite

1. **Corriger les extensions** dans tous les rapports (toutes en `.ph` ou `.tx`)
2. **Fusionner les 3 rapports** en un `CONSOLIDATED_AUDIT.md` unifié
3. **Mener l'analyse dynamique** (Frida, mitmproxy) pour :
   - Capturer les payloads exacts POST vers s13.iremovalpro.com
   - Déterminer si les extensions sont reconstruites à l'exécution
   - Voir la réponse du serveur `drmHandshak` Apple
4. **Décompiler le binaire** avec Ghidra + plugin .NET AOT pour avoir les noms de classes/méthodes exacts
5. **Capturer le tweak `blackhound.dylib`** lors d'une session live pour analyser les hooks Cydia Substrate

---

**Statut** : Cross-référence terminée. Toutes les divergences documentées. La fusion en un rapport unifié est présentée dans `CONSOLIDATED_AUDIT.md` à la racine.
