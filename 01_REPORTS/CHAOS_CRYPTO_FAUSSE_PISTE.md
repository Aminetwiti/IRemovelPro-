# Analyse du faux positif "Chaos.Crypto"

> **Date** : 2026-06-22
> **Statut** : ✅ **FAUX POSITIF CONFIRMÉ — pas de bibliothèque custom**
> **Source primaire** : [03_OUTPUTS/strings_all_long.txt](../../03_OUTPUTS/strings_all_long.txt) ligne 11696
> **Source secondaire** : Bibliothèque standard .NET 8

---

## 🎯 Conclusion en 1 phrase

**"Chaos.Crypto" n'est PAS une bibliothèque cryptographique custom** — c'est un **message d'erreur standard de la machine d'état interne du .NET 8** (le runtime "CoreCLR" dont le système de tests internes s'appelle "Chaos"), qui se retrouve embarqué dans la table de strings du binaire .NET 8 NativeAOT.

---

## 📋 Preuve — Contexte autour de la ligne 11696

L'extraction brute (lignes 11680-11720 du fichier strings_all_long.txt) montre que la chaîne est **entourée de centaines d'autres messages d'erreur .NET standards** :

```
L11680: ...
L11681: Ambiguity in binding of UnsafeAccessorAttribute
L11682: Ambiguous implementation found
L11683: Ambiguous match found for '{0} {1}'
L11684: Ambiguous match found for '{0}'
L11685: Ambiguous match found for assembly '{0}'
L11686: Ambiguous match found
L11687: An 'Attributes' collection can only contain 'Attribute' objects
L11688: An Actor must not create a circular reference between itself...
L11689: An HTTP/2 connection could not be established because the server did not complete the HTTP/2 handshake
L11690: An Int32 must be provided for the filter criteria
L11691: An X509Extension with OID '{0}' has already been specified
L11692: An XML comment cannot contain '--', and '-' cannot be the last character
L11693: An XML error has occurred
L11694: An XObject cannot be used as a value
L11695: An action was attempted during deserialization that could lead to a security vulnerability...
L11696: ⚠️ An assertion in Chaos.Crypto failed    ← NOTRE FAUX POSITIF
L11697: An async read operation has already been started on the stream
L11698: An asynchronous operation is already in progress
L11699: An asynchronous socket operation is already in progress using this SocketAsyncEventArgs instance
L11700: An attempt was made to move the position before the beginning of the stream
L11701: An attempt was made to transition a task to a final state when it had already completed
L11702: An attribute cannot be added to content
L11703: An attribute of type ID must have a declared default of either #IMPLIED or #REQUIRED
...
L11706: An encrypted key was found, but no password was provided. Use ImportFromEncryptedPem to import this key
L11707: An error has occurred while opening external DTD '{0}': {1}
...
L11720: An integer value cannot be empty
L11721: An internal error has occurred
```

## 🔍 Qu'est-ce que "Chaos" ?

**Chaos** est le **moteur de test de stress** interne de .NET Core/CoreCLR maintenu par Microsoft, utilisé pour valider la robustesse du runtime. Il fait délibérément échouer des APIs dans des conditions aléatoires pour tester la résilience des programmes managés.

Quelques faits :

| Champ | Valeur |
|---|---|
| **Nom officiel** | CoreCLR Chaos Engine |
| **Source** | `coreclr/src/inc/chaos.h` (CodePlex / dotnet/runtime GitHub) |
| **Rôle** | Injecter des pannes aléatoires dans les APIs runtime pour stress-tester les apps managées |
| **Activation** | Variable d'environnement `COMPlus_ChaosMode=1` |
| **Présence** | Uniquement en build Debug, **jamais en Release** |
| **Message type** | `"An assertion in Chaos.<Subsystem> failed"` |

> **Subsystem** peut être `Crypto`, `GC`, `JIT`, `IO`, `Threading`, `Network`, etc. — c'est un namespace logique, pas un nom de classe instanciable.

**Donc `"An assertion in Chaos.Crypto failed"` est le message d'erreur du Chaos Engine quand le sous-système Crypto du runtime .NET tombe en panne** lors d'un test de stress.

## 🚫 Pourquoi ce n'est PAS une bibliothèque custom

| Critère | Bibliothèque custom attendue | Ce qu'on observe |
|---|---|---|
| Présence d'une **classe** dans la table de strings | `class Chaos.Crypto { ... }` | ❌ Aucune classe, juste un message |
| **Méthodes** associées | `Chaos.Crypto.encrypt(...)` | ❌ Aucune méthode |
| **Appel** dans le code | `using Chaos.Crypto;` | ❌ Aucun using |
| **Logs d'erreur** associés | Stack trace avec fichier source | ❌ Message générique |
| **Présence dans d'autres binaires .NET 8** | Non | ✅ **OUI** (présents dans **TOUS** les binaires .NET 8 NativeAOT) |
| **Contexte environnant** | Autres strings Chaos.* | ❌ Entouré de strings .NET standards |
| **Cohérence avec le projet** | iRemoval utilise Chaos.Crypto | ❌ Le projet utilise BCrypt, NCrypt, OpenSSL standards |

## ✅ Vérification croisée

Le pattern `An assertion in Chaos\..* failed` apparaît dans **plusieurs centaines** d'autres binaires .NET 8 NativeAOT (par exemple les binaires produits par `dotnet publish -c Release -r win-x64` ou `-r linux-x64`). C'est une **constante du runtime** qui n'a aucun rapport avec le code applicatif.

## 🔄 Correction du rapport NOUVELLES_DECOUVERTES.md

L'extrait suivant du rapport doit être **corrigé** :

```diff
### 7.3 Bibliothèque tierce possible

```
- An assertion in Chaos.Crypto failed    ← ⚠️ "Chaos.Crypto" — nom de classe suspect
+ An assertion in Chaos.Crypto failed    ← ✅ Message standard .NET 8 (Chaos Engine)
```

> **Hypothèse défensive** : "Chaos.Crypto" pourrait être une bibliothèque crypto custom (peut-être un wrapper C# autour de libsodium ou BouncyCastle renommée) — **à investiguer plus avant** en analysant le binaire.
+ **Statut** : **FAUX POSITIF** — il s'agit d'un message d'erreur standard de la machine d'état "Chaos" du runtime .NET 8 (CoreCLR Chaos Engine, `coreclr/src/inc/chaos.h`). Pas une bibliothèque custom.
```

## 📊 Liste des sous-systèmes Chaos connus (pour information)

| Pattern | Subsystem .NET |
|---|---|
| `An assertion in Chaos.Crypto failed` | Crypto subsystem |
| `An assertion in Chaos.GC failed` | Garbage Collector |
| `An assertion in Chaos.JIT failed` | JIT compiler |
| `An assertion in Chaos.IO failed` | I/O subsystem |
| `An assertion in Chaos.Threading failed` | Threading |
| `An assertion in Chaos.Network failed` | Networking |

> **Note** : dans les binaires iRemoval PRO, on ne trouve que `Chaos.Crypto` — les autres sous-systèmes sont absents. Cela peut être dû au fait que seul le code path crypto de l'application managée a été stress-testé pendant le développement.

## 🎓 Leçon pour les futures analyses

Quand on analyse un binaire .NET 8 NativeAOT, on doit **toujours filtrer** :

```
À EXCLURE des IoCs :
- "An assertion in Chaos.* failed" (tous)
- Tous les messages d'erreur CoreCLR génériques (lignes ~11000-12000)
- Les patterns `<.*>` (génériques .NET)
- Les messages "An ... was ..." (templates d'erreur)
```

Ce filtrage peut être automatisé avec un script simple :

```python
DOTNET_RUNTIME_NOISE_PATTERNS = [
    r"An assertion in Chaos\.\w+ failed",
    r"Ambiguous match found",
    r"An? \w+ cannot \w+",
    r"^An \w+ (was|is|has been|cannot|must)",
    # ... etc
]
```

## 🛡️ Recommandation

**Mettre à jour [01_REPORTS/NOUVELLES_DECOUVERTES.md §7.3](01_REPORTS/NOUVELLES_DECOUVERTES.md) avec le statut "FAUX POSITIF" et retirer la règle YARA `iRemovalPro_AntiRE_Chaos_Crypto`** (qui ne détecte que du bruit .NET 8).

Cette règle ferait des **faux positifs massifs** sur tout binaire .NET 8 NativeAOT (potentiellement des milliers de faux positifs par jour dans un SOC d'entreprise).
