"""Append §17 (Chaos.Crypto cross-platform finding) to NOUVELLES_DECOUVERTES.md."""
import os

NDPATH = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\01_REPORTS\NOUVELLES_DECOUVERTES.md'

section_17 = """

---

## 17. Revelation cross-plateforme : Chaos.Crypto est compile en Mono pour iOS (2026-06-22)

> **Statut** : verification empirique de l'hypothese §7.3 (REFUTEE) + revelation architecturale majeure.
> **Impact** : contredit l'hypothese initiale d'un tweak Obj-C pur ecrit avec Theos.

### 17.1 Verification empirique de l'hypothese BouncyCastle (REFUTEE)

L'hypothese §7.3 soupconnait `Chaos.Crypto` d'etre un fork renomme de **BouncyCastle**, sur la base des primitives ChaCha20/Poly1305/Curve25519/ed25519 retrouvees dans le DLL.

**Methode** : recherche exhaustive des strings BC dans `03_OUTPUTS/strings_all_long.txt`.

| Pattern recherche | Matches trouves |
|---|---:|
| `BouncyCastle` | **0** |
| `Org.Bouncy` | **0** |
| `bcprov` | **0** |
| `Bouncy.Castle` | **0** |

**Verdict** : `Chaos.Crypto` **n'est PAS** BouncyCastle renomme. Zero reference BC dans tout le binaire.

### 17.2 Origine reelle de `Chaos.Crypto`

**Methode** : analyse du contexte immediat (200 chars avant + 200 apres) autour de la string `An assertion in Chaos.Crypto failed`.

Le contexte est **identique octet-pour-octet** dans les deux binaires :

```
... An action was attempted during deserialization that could lead to a
security vulnerability. The action has been aborted. To allow the action,
set the '{0}' AppContext switch to true
An assertion in Chaos.Crypto failed
An async read operation has already been started on the stream
An asynchronous socket operation is already in progress ...
```

Ce contexte est la **table de ressources .NET/Mono standard** (System.Private.CoreLib). Ces strings apparaissent dans **toute** application .NET compilee (et Mono reprend le meme resource bundle).

**Conclusion 1** : `Chaos.Crypto` est un **namespace custom** cree par les auteurs iRemoval eux-memes, et non une bibliotheque tierce renommee.

### 17.3 Revelation majeure : le dylib iOS est compile en Mono/.NET

La string `An assertion in Chaos.Crypto failed` apparait dans :

| Binaire | Plateforme | Format | Position |
|---|---|---|---:|
| `iremovalpro.dll` (29.8 MB) | Windows x64 | .NET Framework / .NET 8 | 602298 |
| `macho_8534d3_DYLIB_ARM64_ALL.bin` (8.5 MB) | iOS ARM64 | **Mono / Xamarin.iOS** | 253042 |

**Implication architecturale** : le dylib `blackhound` n'est PAS un binaire Objective-C natif ecrit a la main avec Theos. Il est compile avec **Mono / Xamarin.iOS** (le chainage Xamarin transforme du C# .NET en code ARM64 et preserve la table de ressources .NET dans le binaire final).

### 17.4 Primitives crypto : ce que chaque binaire utilise vraiment

| Primitive crypto | iOS dylib | DLL Windows |
|---|---:|---:|
| ChaCha20 | 0 | 8 |
| Poly1305 | 0 | 8 |
| Curve25519 | 2 | 5 |
| ed25519 | 1 | 3 |
| NaCl | 0 | 1 |
| Salsa20 | 0 | 0 |
| AES | 27 | 142 |
| RSA | 48 | 230 |

| Observation | Implication |
|---|---|
| ChaCha20/Poly1305 ABSENTS du dylib iOS | Le code iOS n'utilise PAS ChaCha20-Poly1305 AEAD |
| AES/RSA presents des deux cotes | Utilisation de System.Security.Cryptographie standard .NET |
| Curve25519/ed25519 des deux cotes | Signature/verif ECDSA sur courbe25519 (equivalent Ed25519) |
| `BouncyCastle.*` absent partout | Pas de dependance BC ; tout est .NET natif |

### 17.5 Implications defensives

1. **Attribution mise a jour** : les auteurs iRemoval ecrivent du **C# .NET** pour iOS (via Xamarin.iOS), pas de l'Obj-C natif. Cela contredit la these d'un pur tweak Theos (les chemins `.theos/obj/debug/` trouves dans le binaire sont les **build artifacts d'origine**, mais le code a ete **recompile en Mono** pour la distribution finale).

2. **Surface de detection** : le namespace `Chaos.Crypto` est un **fingerprint unique** present dans les deux binaires (Windows + iOS). Une seule regle YARA (`iRemovalPro_ChaosCrypto_Namespace`) detecte les deux.

3. **Correlation Apple** : la signature cross-plateforme (memes strings .NET dans Windows DLL et iOS dylib) permet une **correlation** : si Apple detecte un iPhone avec un dylib contenant `Chaos.Crypto`, elle peut correlater avec les hashes DLL connus et blacklister tout l'ecosysteme associe.

4. **Detection YARA ajoutee** : `iRemovalPro_ChaosCrypto_Namespace` (severity: high) - detecte a la fois sur le DLL Windows et sur le dylib iOS.

5. **Correction de §7.3** : la mention "wrapper C# autour de libsodium ou BouncyCastle renommee" est **abandonnee**. Verdict final : namespace custom ecrit par les auteurs iRemoval, compile en Mono pour iOS via Xamarin.iOS.

### 17.6 Validation des nouvelles regles YARA

Test fire contre les donnees reelles (`03_OUTPUTS/strings_all_long.txt` + `ios_binary_strings.txt`) :

| Regle YARA | DLL strings | iOS dylib strings |
|---|:---:|:---:|
| `iRemovalPro_BlackHound_BuildMarker` | FIRE | - |
| `iRemovalPro_DevPath_josuealonsorodriguez` | FIRE | - |
| `iRemovalPro_DevPath_minacriss` | FIRE | - |
| `iRemovalPro_AntiDebug_NtQuery` | FIRE | - |
| `iRemovalPro_ChaosCrypto_Namespace` | **FIRE** | **FIRE** |

**5/5 nouvelles regles OK**, 31 regles totales compilent sans erreur.

### 17.7 References croisees

- §7.3 (hypothese BouncyCastle initiale)
- §14 #10 (moyen terme "Analyser Chaos.Crypto")
- YARA: `iRemovalPro_ChaosCrypto_Namespace` (ajoute 2026-06-22, severity high)
- SIGMA: `ire-0013 ideviceproxy command line` (ajoute 2026-06-22)
- IoC: `com.iremovalpro.bypass` bundle ID (mis a jour dans ioc_catalog.md §13)
"""

# Only insert if not already present
with open(NDPATH, encoding='utf-8') as f:
    nd = f.read()

if '## 17.' not in nd and 'Chaos.Crypto est compile en Mono' not in nd:
    with open(NDPATH, 'a', encoding='utf-8') as f:
        f.write(section_17)
    print(f'NOUVELLES_DECOUVERTES.md updated: +{len(section_17)} chars')
else:
    print('Section 17 already present - skipped')

# Final stats
size = os.path.getsize(NDPATH)
with open(NDPATH, encoding='utf-8') as f:
    lines = sum(1 for _ in f)
print(f'Final: {size} bytes, {lines} lines')
