# Phase 5 — NativeAOT Bundle Unpacker

> **Analyse statique de la DLL `iremovalpro.dll` (.NET 8 NativeAOT)**
> Récupération des métadonnées managées (types, méthodes, string heap).

## Pourquoi ce script ?

Les binaires **.NET 8 NativeAOT** sont entièrement compilés en code natif x64.
Le bytecode IL est **perdu**. Cependant, le runtime .NET garde certaines
métadonnées pour :
- Reflection (`Type.GetType()`, `MethodInfo`)
- Sérialisation JSON (`System.Text.Json`)
- Chargement dynamique (`Activator.CreateInstance`)
- Sérialisation binaire (`BinaryFormatter`)

Ces métadonnées sont stockées dans la section **`.managed`** (6,7 MB pour
notre cible) et **`.rdata`** (5,9 MB).

## Scripts

### `nativeaot_unpack.py` (v1)
Parser basique : extraction strings ASCII depuis `.managed`/`.rdata`,
scan heuristique EEType.

### `nativeaot_unpack_v2.py` (v2, **préféré**)
Parser amélioré avec :
- Support **UTF-16 LE** (format .NET natif pour strings managées)
- Classification automatique en catégories (crypto, network, apple-ios, bypass…)
- Détection de **types .NET** (pattern `Namespace.Class`)
- Sortie par catégorie (txt + json)

```bash
# Extraction complète
py nativeaot_unpack_v2.py iremovalpro.dll

# Minimum string length custom
py nativeaot_unpack_v2.py iremovalpro.dll --min-len 12

# Spécifier DLL alternative
py nativeaot_unpack_v2.py C:\path\to\other.dll
```

## Résultats de l'analyse sur `iremovalpro.dll`

Exécution : `py nativeaot_unpack_v2.py IRemovalPro\iremovalpro.dll`

| Métrique | Valeur |
|----------|--------|
| Taille DLL | 31 264 768 octets |
| Sections | 11 |
| Taille `.managed` | 6 774 784 octets |
| Taille `.rdata` | 6 184 448 octets |
| Strings ASCII ≥ 10 chars | 24 312 |
| Strings UTF-16 ≥ 10 chars | 3 794 |
| Types managés uniques | 604 |
| Réfs crypto | 940 |
| Réfs Apple/iOS | 678 |
| Réfs réseau | 828 |
| Réfs bypass | 133 |
| Réfs produit | 34 |

## Outputs

`03_OUTPUTS/nativeaot/` :
- `nativeaot_*.all.json` — Toutes les strings (encodage, offset)
- `category_*.txt` — Strings catégorisées (1 fichier par catégorie)
- `types_*.txt` — Types .NET uniques (604 lignes)
- `nativeaot_unpack_*.json` — Sortie brute v1

## Découvertes clés

### 1. Bibliothèque SSH embarquée
- `Renci.SshNet.*` → **SSH.NET** library
- Version mentionnée : `Had816c5e-6f13-4589-9f3e-59523f8b77a4c`

### 2. Bibliothèques .NET incluses
- `System.Net.Security.dll` → TLS
- `System.Security.Cryptography.dll` → Crypto
- `SshNet.Security.Cryptography.dll` → SSH key exchange
- `RestSharp.dll` → HTTP client

### 3. Origine du code
Le binaire contient une chaîne de chemin macOS :
```
/Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/.theos/obj/debug/arm64/
```
→ Le **tweak BlackHound** est compilé sur macOS avec **Theos** par
`josuealonsorodriguez`, puis embarqué dans la DLL Windows.

### 4. Classes de hook iOS
- `_MSHookFunction`, `_MSHookMessageEx` → **MobileSubstrate**
- Hooks ciblés : `MobileActivationDaemon`
- Méthodes hookées :
  - `validateActivationDataSignature:activationSignature:withError:`
  - `handleActivationInfo:withCompletionBlock:`
  - `handleActivationInfoWithSession:activationSignature:completionBlock:`

### 5. Fonctions iDevice (libimobiledevice)
- `iDevice_LnchV2`, `iDevice_Activate`, `iDevice_Deactivate`
- `iDevice_GetState`, `iDevice_EnableDevMode`
- `Firewall_iDeviceProxy`

### 6. Namespace principal
- `Tiremovalpro.Properties.Resources` → nom de namespace obfuscated
  (`T` prefix ajouté par le compilateur NativeAOT)

### 7. Architecture
```
Windows .NET 8 App (Tiremovalpro.*)
        ↓
   iremovalpro.dll (NativeAOT)
        ↓
   ┌────┴────┐
   │         │
SSH.NET   MobileSubstrate tweaks
(Renci)        ↓
   ↓      BlackHound.dylib
   │         ↓
libimobiledevice   MobileActivationDaemon (iOS)
        ↓
   /activation_records/activation_record.plist
```

## Limitations

⚠️ **Ce script ne récupère PAS** :
- Le code source original (compilé en natif)
- Les noms de méthodes C# (seuls les noms conservés pour reflection)
- Les attributs de debug
- Le bytecode IL (détruit à la compilation)

✅ **Ce script récupère** :
- Toutes les chaînes constantes (UTF-8 et UTF-16)
- Noms des types accessibles par reflection
- Strings de log, messages d'erreur, URL, chemins
- Commentaires de chaînes contenant des indices

## Dépendances

```
pip install pefile
```

## Voir aussi

- [README du dossier 10_runtime_dump](../10_runtime_dump/README.md)
- [01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md](../../01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md)
- [03_OUTPUTS/crypto_deep_analysis.txt](../../03_OUTPUTS/crypto_deep_analysis.txt) — 6 539 strings crypto statiques
