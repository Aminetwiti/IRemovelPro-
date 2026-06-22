# FAQ — Questions fréquentes

> Réponses aux questions courantes sur cet audit

## Général

### Qu'est-ce que iRemoval PRO ?

Outil commercial Windows qui **contourne l'Activation Lock iCloud** sur iPhone. Vendu 50-100 $/mois via un serveur privé `s13.iremovalpro.com`.

### Pourquoi cet audit ?

Pour **documenter comment fonctionne** l'outil, à des fins :
- Défensives (détection par AV/EDR)
- De recherche (compréhension des vulnérabilités iOS)
- D'audit (sensibilisation aux risques)

### Le but est-il de faciliter le bypass ?

**Non.** L'audit est statique uniquement. Aucun outil opérationnel de bypass n'est fourni. Voir [LIMITATIONS.md](LIMITATIONS.md).

## Technique

### Pourquoi la DLL fait 30 MB ?

C'est un binaire **.NET 8 NativeAOT** — la runtime .NET complète est embarquée + le code AOT. Voir [EXPERT_REPORT.md](EXPERT_REPORT.md) §1.

### Pourquoi l'EXE est obfusqué ?

Pour rendre la décompilation **plus difficile**. Les noms de types sont remplacés par des hashes courts (`1BA52035`). Voir [AUDIT_REPORT.md](AUDIT_REPORT.md) §2.

### Comment les méthodes iOS sont hookées ?

Via **Cydia Substrate** dans `blackhound.dylib` :
```objc
- (BOOL)validateActivationDataSignature:(NSData *)sig
                          activationData:(NSDictionary *)data
                              withError:(NSError **)error;
```
Le hook retourne `YES` toujours, peu importe la signature. Voir [EXPERT_REPORT.md](EXPERT_REPORT.md) §5.7.

### Pourquoi checkm8 et A12 Eraser ?

- **checkm8** : exploit bootrom A5-A11 (par axi0mX, 2019)
- **A12 Eraser** : `minaeraser12` pour A12+ (iPhone XS et plus)
L'app choisit le bon outil selon le modèle détecté. Voir [EXPERT_REPORT.md](EXPERT_REPORT.md) §6.

### Que fait le serveur s13.iremovalpro.com ?

Il fournit un **ticket d'activation forgé** (signé avec une clé que l'app "croit" valide) pour faire passer le check `validateActivationDataSignature` du daemon iOS.

### L'endpoint Apple est-il légitime ?

Oui, `albert.apple.com/deviceservices/drmHandshake` est un **endpoint Apple officiel** utilisé par tous les appareils iOS pour le handshake DRM. L'app iRemoval PRO l'utilise normalement, mais avec un ticket forgé.

## Risques

### Est-ce que iRemoval PRO est un virus ?

**Non**, au sens classique. Pas de :
- Vol de credentials PC
- Backdoor / RAT
- Crypto-miner caché
- Exfiltration de données PC

**Mais** : il **contourne sciemment l'Activation Lock** (anti-vol iCloud), ce qui peut faciliter l'utilisation d'appareils volés.

### Risque pour mon PC ?

| Risque | Sévérité |
|---|---|
| SmartScreen bloque le binaire | 🟠 Élevée (non signé) |
| Anti-virus peut le détecter comme PUA | 🟡 Moyenne |
| Communication avec serveur privé | 🟡 Moyenne (télémétrie) |
| Installation de drivers USB | 🟢 Faible |

### Risque pour l'iPhone cible ?

| Risque | Sévérité |
|---|---|
| Bypass de l'anti-vol iCloud | 🔴 Critique |
| Réécriture NAND (irréversible) | 🔴 Critique |
| Risque de brick si procédure échoue | 🔴 Critique |
| Jailbreak permanent | 🟠 Élevée |
| Faux signal MEID (carrier) | 🟠 Élevée |

### Est-ce autorised'utiliser iRemoval PRO ?

**Ça dépend de la juridiction et du contexte** :

| Usage | Légalité |
|---|---|
| Votre propre iPhone, identifiant Apple oublié | ⚠️ Zone grise |
| iPhone acheté légalement, bloqué | ⚠️ Zone grise |
| iPhone volé | ❌ Ilautorise(CFAA, directives UE) |
| Pour apprendre la sécurité iOS | ✅ autorise(recherche) |
| Pour développer des contre-mesures | ✅ autorise(défense) |

## Audit

### Pourquoi pas d'analyse dynamique ?

Voir [LIMITATIONS.md](LIMITATIONS.md) :
- Périmètre strict (statique uniquement)
- autorise et accepter et legal (éviter outils opérationnels)
- Coût (iPhone de test + compte)
- Compétence (Frida, Ghidra AOT)

### Comment puis-je reproduire l'analyse ?

Voir [METHODOLOGY.md](METHODOLOGY.md) §Reproductibilité.

### Pourquoi ne pas utiliser Ghidra ?

| Raison | Détail |
|---|---|
| Temps | 5-7 jours pour un expert |
| Complexité | AOT nécessite .NET NativeAOT plugin |
| Résultat | Pseudo-C illisible (NATIVE compile) |
| ROI | Faible — les scripts Python couvrent 80% |

### Comment détecter la présence d'iRemoval PRO sur un PC ?

Voir [`05_IOC/ioc_catalog.md`](../05_IOC/ioc_catalog.md) pour les IoC.

**Méthode rapide** :
```powershell
Get-ChildItem 'C:\' -Recurse -Filter 'iRemoval PRO.exe' -ErrorAction SilentlyContinue
Get-ChildItem 'C:\' -Recurse -Filter 'iremovalpro.dll' -ErrorAction SilentlyContinue
```

### Comment détecter une infection iOS par blackhound.dylib ?

**Sur iPhone** (si accès) :
```bash
ls -la /Library/MobileSubstrate/DynamicLibraries/blackhound.dylib
```

**Métadonnées** :
- Bundle ID : `com.panyolsoft.blackhound`
- Path : `/Library/MobileSubstrate/DynamicLibraries/`

## Technique avancée

### Peut-on utiliser cette analyse pour développer un bypass ?

**Oui, techniquement.** L'analyse statique fournit les éléments nécessaires. **Mais** :
- Cela violerait le **CFAA** (US) et **directives UE** (EU)
- Cela faciliterait le vol d'iPhones
- Cela porterait atteinte à la **vie privée** des propriétaires

**Recommandation** : ne pas utiliser à des fins offensives.

### Peut-on utiliser cette analyse pour défendre ?

**Oui, c'est l'objectif principal** :
- IoC pour AV/EDR
- YARA rules pour scanners
- Règles Suricata pour IDS réseau
- Splunk/Sigma queries pour SOC

Voir [`05_IOC/`](../05_IOC/) pour les règles de détection.

### Quel est le risque autorisede publier cette analyse ?

| Juridiction | Risque |
|---|---|
| USA (CFAA §1030) | Faible si documentation défense uniquement |
| UE (directive 2013/40) | Faible si information défensive |
| Tous | **Nul** si pas d'instructions de bypass |

Cette analyse **documente**, elle ne fournit pas d'outils opérationnels.

## Divers

### Qui est Blackhound ?

Développeur original de la v0.7.1. Voir [AUDIT_REPORT.md](AUDIT_REPORT.md) §12.

### Qui sont les autres développeurs ?

| Pseudo | Rôle |
|---|---|
| Blackhound (josuealonsorodriguez) | Tweak blackhound.dylib |
| minacriss | minaeraser, minaeraser12, rc |
| weidong li | Cert dev Apple réutilisé |

### Quand a été créé le binaire original ?

`iRemoval PRO.exe` : 2025-09-16 (timestamp PE)
`iremovalpro.dll` : 2025-09-16

### Peut-on voir les sources ?

Non, l'app est compilée (AOT). Pour récupérer du C# lisible, il faut Ghidra + plugin .NET AOT.

---

**Autres questions ?** Ouvrir une issue ou contacter le mainteneur (voir [CONTRIBUTING.md](../CONTRIBUTING.md)).
