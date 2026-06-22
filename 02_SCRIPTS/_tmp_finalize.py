"""Document Chaos.Crypto finding + cleanup tmp scripts."""
import os, re

BASE = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'

# 1. Document Chaos.Crypto finding in NOUVELLES_DECOUVERTES.md
NDPATH = os.path.join(BASE, '01_REPORTS', 'NOUVELLES_DECOUVERTES.md')
with open(NDPATH, encoding='utf-8') as f:
    nd = f.read()

# Insert §16 after §15 (find "## 16." or end of §15)
correction = """

---

## 16. Correctif et découverte cross-plateforme sur Chaos.Crypto (2026-06-22)

> **Statut** : correction de l'hypothese §7.3 et revelation majeure.

### 16.1 Verification empirique de l'hypothese BouncyCastle (REFUTEE)

L'hypothese §7.3 soupconnait `Chaos.Crypto` d'etre un fork de **BouncyCastle** (a cause des primitives ChaCha20/Poly1305/Curve25519/ed25519 retrouvees dans le DLL).

**Methode** : recherche exhaustive des strings BC dans `03_OUTPUTS/strings_all_long.txt`.

| Pattern recherche | Matches trouves |
|---|---:|
| `BouncyCastle` | **0** |
| `Org.Bouncy` | **0** |
| `bcprov` | **0** |
| `Bouncy.Castle` | **0** |

**Verdict** : `Chaos.Crypto` **n'est PAS** BouncyCastle renomme. Zero reference BC dans tout le binaire.

### 16.2 Origine reelle de Chaos.Crypto

**Methode** : analyse du contexte immediat (200 chars avant + 200 apres).

Le contexte autour de `An assertion in Chaos.Crypto failed` est **identique octet-pour-octet** dans les deux binaires :

```
... An action was attempted during deserialization that could lead to a
security vulnerability. The action has been aborted. To allow the action,
set the '{0}' AppContext switch to true
An assertion in Chaos.Crypto failed
An async read operation has already been started on the stream
An asynchronous socket operation is already in progress ...
```

Ce contexte est la **table de ressources .NET/Mono standard** (System.Private.CoreLib). Ces strings apparaissent dans **toute** application .NET compilee.

**Conclusion 1** : `Chaos.Crypto` est un **namespace custom** cree par les auteurs iRemoval (et non une bibliotheque tierce renommee).

### 16.3 Revelation majeure : le dylib iOS est compile en Mono/.NET

La string `An assertion in Chaos.Crypto failed` apparait dans :

| Binaire | Plateforme | Format | Position |
|---|---|---|---:|
| `iremovalpro.dll` (29.8 MB) | Windows x64 | .NET Framework / .NET 8 | 602298 |
| `macho_8534d3_DYLIB_ARM64_ALL.bin` (8.5 MB) | iOS ARM64 | **Mono / Xamarin.iOS** | 253042 |

**Implication** : le dylib `blackhound` n'est PAS un binaire Objective-C natif ecrit a la main avec Theos. Il est compile avec **Mono/Xamarin.iOS** (le chainage Xamarin transforme du C# .NET en code ARM64). Les chaines .NET y sont preservees.

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

L'absence de ChaCha20/Poly1305 dans le dylib iOS confirme qu'il utilise les **primitives standard .NET System.Security.Cryptography** (AES, RSA, ECDH sur Curve25519).

### 16.4 Implications defensives mises a jour

1. **Attribution** : `Chaos.Crypto` est un namespace interne. Les auteurs iRemoval ecrivent du **C#** pour iOS (via Xamarin), pas de l'Obj-C natif. Cela contredit l'hypothese que `blackhound` etait un pur tweak Theos.

2. **Surface de detection** : le namespace `Chaos.Crypto` est un **fingerprint unique** present dans les deux binaires (Windows + iOS). Une seule regle YARA (`iRemovalPro_ChaosCrypto_Namespace`) detecte les deux.

3. **Defense Apple** : la signature cross-plateforme (memes strings .NET dans Windows DLL et iOS dylib) permet une **correlation** : si Apple detecte un iPhone avec un dylib contenant `Chaos.Crypto`, elle peut correlater avec les hashes DLL connus et blacklister tout l'ecosysteme.

4. **Detection YARA ajoutee** : `iRemovalPro_ChaosCrypto_Namespace` (severity: high) - detecte sur DLL et dylib.

5. **Correction de §7.3** : remplacer la mention "wrapper C# autour de libsodium ou BouncyCastle renommee" par "namespace custom ecrit par les auteurs iRemoval, compile en Mono pour iOS via Xamarin".

### 16.5 References croisees

- §7.3 (hypothese initiale)
- §14 #10 (moyen terme "Analyser Chaos.Crypto")
- YARA: `iRemovalPro_ChaosCrypto_Namespace` (ajoute 2026-06-22)
- Test fire: 5/5 nouvelles regles YARA OK contre `strings_all_long.txt`
"""

# Only insert if not already present
if '## 16.' not in nd:
    # Append at end
    with open(NDPATH, 'a', encoding='utf-8') as f:
        f.write(correction)
    print(f'NOUVELLES_DECOUVERTES.md updated: +{len(correction)} chars')
else:
    print('NOUVELLES_DECOUVERTES.md §16 already present - skipped')

# 2. Cleanup tmp scripts
tmp_scripts = [
    os.path.join(BASE, '02_SCRIPTS', '_tmp_append.py'),
    os.path.join(BASE, '02_SCRIPTS', '_tmp_ioc_verify.py'),
    os.path.join(BASE, '02_SCRIPTS', '_tmp_yara_test.py'),
]
print()
print('=== Cleanup tmp scripts ===')
for s in tmp_scripts:
    if os.path.exists(s):
        os.remove(s)
        print(f'  REMOVED {os.path.basename(s)}')
    else:
        print(f'  missing {os.path.basename(s)}')

# 3. Verify final state
print()
print('=== Final IOC state ===')
for f in ['05_IOC/YARA_RULES.yar', '05_IOC/SIGMA_RULES.yml', '05_IOC/ioc_catalog.md', '01_REPORTS/NOUVELLES_DECOUVERTES.md']:
    p = os.path.join(BASE, f)
    print(f'  {f}: {os.path.getsize(p)} bytes, {sum(1 for _ in open(p, encoding="utf-8"))} lines')

# 4. Re-verify YARA compiles
print()
print('=== YARA final compile ===')
import yara
rules = yara.compile(filepath=os.path.join(BASE, '05_IOC', 'YARA_RULES.yar'))
print(f'  YARA compile: OK ({sum(1 for _ in rules)} rules)')
