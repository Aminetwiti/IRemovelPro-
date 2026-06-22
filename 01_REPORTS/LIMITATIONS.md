# LIMITATIONS — Ce que cette analyse ne couvre pas

> Transparence sur les limites de l'analyse statique

## 🚫 Analyse dynamique NON couverte

### Non réalisé
| Élément | Raison | Risque |
|---|---|---|
| Exécution du binaire EXE | Risque Anti-VM, SmartScreen, télémétrie | Modifier le système |
| Exécution de la DLL | Anti-debug, network, USB nécessaire | Activer service payant |
| Frida injection sur iPhone | Nécessite iPhone jailbreaké | Hors scope audit statique |
| mitmproxy capture | Compte iRemoval payant requis | Coût + risque autorise|
| Extraction `blackhound.dylib` live | iPhone de test requis | Risque brick |
| Ghidra décompilation complète | 5-7 jours de travail expert | Complexité AOT |

### Pourquoi non fait
- **Périmètre strict** : audit statique uniquement
- **autorise et accepter et legal** : éviter tout outil utilisable pour bypass
- **Coût** : iPhone de test + compte iRemoval (50-100 $/mois)
- **Temps** : Ghidra prendrait plusieurs jours
- **Compétence** : Frida requiert expertise iOS avancée

## 🔍 Limites techniques

### .NET NativeAOT
- Le code est **compilé AOT complet** → pas de CIL décompilable
- Les noms de classes/méthodes ne sont **pas** restaurables automatiquement
- Pour identifier les fonctions, il faut **désassembler en x64** (Ghidra, IDA)

### EXE obfusqué
- Les **noms de types** sont obfusqués (hashes courts : `1BA52035`, etc.)
- Les **noms de méthodes** peuvent être obfusqués aussi
- Pour comprendre l'EXE WPF, il faut déobfuscater (de4dot, etc.)

### Strings tronquées
- Les URLs dans le binaire sont stockées avec extensions **tronquées** (`.ph`, `.tx`)
- L'extension complète n'est pas connue avec certitude (`.php`/`.txt` spéculé)
- Pour confirmer, il faudrait **désassembler** le code qui construit les URLs

### Endpoints non testés
- Les 13 endpoints catalogués sont **inférés** des strings du binaire
- Aucun **n'a été testé** (pas de requête HTTP émise)
- Pour valider : Phase 5 (mitmproxy) avec compte iRemoval

## 📊 Couverture de l'analyse

| Couche | Couvert | Manquant |
|---|---|---|
| **PE headers** | ✅ Complet | — |
| **Strings** | ✅ 75 000+ | Désobfuscation |
| **Métadonnées .NET** | ✅ Complet | Déobfuscation EXE |
| **Imports Win32** | ✅ 15 fonctions | Détail des P/Invoke signatures |
| **Sections** | ✅ Complet | — |
| **Anti-débogage** | ✅ 5+ techniques | Patch des checks |
| **Cryptographie** | ✅ Algorithmes identifiés | Clés et IVs |
| **HTTP/TLS** | ✅ Infrastructure | Captures live |
| **iOS protocols** | ✅ Strings confirmées | Comportement runtime |
| **iOS payloads** | ✅ Mach-O extraits | Décompilation ARM64 |
| **iOS hooks** | ✅ Méthodes identifiées | Code Theos compilé |
| **Driver class** | ⚠️ Noms déduits | Code AOT complet |
| **Ressources WPF** | ⚠️ Pointeurs trouvés | XAML complet décompilé |

## 🎯 Ce qui serait nécessaire pour aller plus loin

### Phase 5 — Analyse réseau
**Coût** : 1-2 jours + compte iRemoval (50 $/mois)
**Livrable** : Format exact des requêtes JSON

### Phase 6 — Sandbox comportemental
**Coût** : 1 jour
**Livrable** : Trace des accès filesystem/registry/réseau

### Phase 7 — Extraction iOS live
**Coût** : 2-3 jours + iPhone jailbreaké
**Livrable** : `blackhound.dylib` + `minaeraser12` capturés, analyse des hooks

### Phase 8 — Audit serveur
**Coût** : 1 jour + 1 crédit iRemoval
**Livrable** : Cartographie API complète

### Phase 9 — Ghidra decompilation
**Coût** : 5-7 jours
**Compétence** : Expert RE x64
**Livrable** : Pseudo-C de la classe `Driver` + 13 méthodes iDevice




### Activités explicitement autorisées (caducre)
- ✅ Documentation défensive
- ✅ Recherche académique
- ✅ Audit de sécurité autorisé
- ✅ Développement de détection (YARA, Suricata)
- ✅ Analyse de vulnérabilités pour défenseurs

## 📊 Taux de couverture global

| Type | Couverture |
|---|---|
| **Analyse statique** | 95% (5 phases sur 5 de la statique) |
| **Analyse dynamique** | 0% (intentionnel) |
| **Couverture réseau** | 0% (intentionnel) |
| **Couverture iOS live** | 0% (intentionnel) |

---

**Conclusion** : L'analyse statique est **exhaustive**. Les phases dynamiques sont **volontairement non couvertes** pour des raisons autorise et accepter et legals et de scope.

**Documentation de transparence** : [METHODOLOGY.md](METHODOLOGY.md) | [TODO.md](../TODO.md)
