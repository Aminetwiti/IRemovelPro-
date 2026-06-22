# Skills AI pour l'Analyse iRemoval PRO

> **Installation locale** : 2026-06-22  
> **Localisation** : `.agents/skills/`

---

## 📦 Skills Installés

Ce projet dispose de **6 skills spécialisés** pour améliorer l'analyse de reverse engineering et d'audit de sécurité.

### 1. **ghidra-headless** (Trail of Bits)
- **Source** : `trailofbits/skills-curated@ghidra-headless`
- **Installs** : 163
- **Rôle** : Analyse binaire automatisée avec Ghidra en mode headless
- **Utilisation** : Décompilation, analyse de fonctions, extraction de code assembleur

**Capacités** :
- Chargement automatique de binaires PE/ELF/Mach-O
- Décompilation en C pseudo-code
- Analyse de flux de contrôle (CFG)
- Export de résultats en JSON/XML

---

### 2. **ctf-malware** (ljagiello)
- **Source** : `ljagiello/ctf-skills@ctf-malware`
- **Installs** : 4.7K
- **Rôle** : Analyse de malware et comportements suspects
- **Utilisation** : Détection de patterns malveillants, analyse anti-debug

**Capacités** :
- Détection d'obfuscation
- Identification de packers (UPX, Themida, VMProtect)
- Analyse d'API Windows suspectes
- Extraction de shellcode

---

### 3. **ctf-forensics** (ljagiello)
- **Source** : `ljagiello/ctf-skills@ctf-forensics`
- **Installs** : 4.9K
- **Rôle** : Analyse forensique et récupération d'artefacts
- **Utilisation** : Extraction de données cachées, analyse de traces

**Capacités** :
- Analyse de headers binaires
- Récupération de strings encodées (base64, hex, ROT13)
- Détection de stéganographie
- Timeline reconstruction

---

### 4. **python-scripting** (89jobrien/steve)
- **Source** : `89jobrien/steve@python-scripting`
- **Installs** : 104
- **Rôle** : Amélioration des scripts Python d'analyse
- **Utilisation** : Optimisation, refactoring, bonnes pratiques

**Capacités** :
- Génération de scripts d'automatisation
- Parsing de formats binaires
- Intégration avec pefile, lief, capstone
- Gestion d'erreurs robuste

---

### 5. **binary-analysis** (laurigates)
- **Source** : `laurigates/claude-plugins@binary-analysis`
- **Installs** : 85
- **Rôle** : Analyse approfondie de binaires
- **Utilisation** : Désassemblage, analyse de sections, imports/exports

**Capacités** :
- Analyse PE (Windows), ELF (Linux), Mach-O (macOS/iOS)
- Cartographie des imports/exports
- Analyse de sections (.text, .data, .rsrc)
- Détection d'anomalies structurelles

---

### 6. **reverse-engineering** (r00tedbrain)
- **Source** : `r00tedbrain-backup/skills@reverse-engineering`
- **Installs** : 39
- **Rôle** : Reverse engineering général
- **Utilisation** : Méthodologie RE, outils, workflows

**Capacités** :
- Workflow d'analyse statique/dynamique
- Reconnaissance de patterns cryptographiques
- Anti-reverse engineering detection
- Documentation des découvertes

---

## 🎯 Comment Utiliser ces Skills

### Activation automatique

Les skills sont **activés automatiquement** par GitHub Copilot / Kiro quand vous travaillez sur :
- Scripts Python d'analyse (`02_SCRIPTS/`)
- Binaires extraits (`04_EXTRACTED/`)
- Rapports d'audit (`01_REPORTS/`)
- Analyse de protocoles réseau

### Commandes explicites

Vous pouvez invoquer un skill spécifiquement :

```markdown
# Exemple 1 : Analyse avec Ghidra
@ghidra-headless analyse le binaire iremovalpro.dll et génère un rapport de décompilation

# Exemple 2 : Détection de malware
@ctf-malware identifie les techniques anti-debug dans iRemoval PRO.exe

# Exemple 3 : Forensics
@ctf-forensics extrait les strings cachées dans les sections .rsrc

# Exemple 4 : Optimisation Python
@python-scripting améliore le script re_deep5.py pour mieux parser les Mach-O

# Exemple 5 : Analyse binaire
@binary-analysis cartographie les imports de bcrypt.dll utilisés par la DLL

# Exemple 6 : Reverse engineering
@reverse-engineering documente le workflow complet d'analyse de iact8.php
```

---

## 🔧 Cas d'Usage pour le Projet iRemoval PRO

### 1. Analyse des payloads iOS
```bash
# Utiliser binary-analysis + ghidra-headless
@binary-analysis + @ghidra-headless
Analyse les 4 binaires Mach-O extraits dans 04_EXTRACTED/
et génère un rapport de désassemblage ARM64
```

### 2. Détection d'obfuscation
```bash
@ctf-malware
Identifie les techniques d'obfuscation dans iremovalpro.dll
(strings chiffrées, anti-dump, anti-debug)
```

### 3. Extraction de protocole réseau
```bash
@reverse-engineering + @python-scripting
Améliore le script re_iact_decode2.py pour décoder
les requêtes AES vers iact8.php
```

### 4. Analyse forensique complète
```bash
@ctf-forensics
Extrait tous les artefacts cachés :
- Certificats Apple embarqués
- Clés API hardcodées
- Chemins iOS dans .rsrc
```

### 5. Décompilation .NET
```bash
@ghidra-headless
Décompile iRemoval PRO.exe (C#) et extrait
la logique de chiffrement AES-256-CBC
```

---

## 📊 Matrice de Compétences

| Tâche | Skills Recommandés | Priorité |
|-------|-------------------|----------|
| Désassemblage ARM64/x64 | `ghidra-headless` + `binary-analysis` | ⭐⭐⭐ |
| Détection anti-debug | `ctf-malware` | ⭐⭐⭐ |
| Extraction strings | `ctf-forensics` | ⭐⭐ |
| Optimisation scripts | `python-scripting` | ⭐⭐ |
| Analyse crypto | `reverse-engineering` | ⭐⭐⭐ |
| Parsing protocoles | `python-scripting` + `reverse-engineering` | ⭐⭐⭐ |

---

## 🛡️ Évaluation de Sécurité

| Skill | Gen AI Risk | Socket Alerts | Snyk Risk |
|-------|-------------|---------------|-----------|
| ghidra-headless | Safe | 0 | Medium |
| ctf-malware | Medium | 0 | **Critical** ⚠️ |
| ctf-forensics | Safe | 1 | Medium |
| python-scripting | Safe | 0 | Low |
| binary-analysis | Safe | 1 | Low |
| reverse-engineering | Safe | 3 | Medium |

**Note** : Le skill `ctf-malware` est marqué "Critical Risk" par Snyk car il contient des patterns de malware (pour détection). C'est **normal** pour un skill d'analyse de sécurité.

---

## 🔄 Mise à Jour

Pour mettre à jour tous les skills :

```bash
cd "C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2"
npx skills update
```

Pour vérifier les versions :

```bash
npx skills list
```

---

## 📚 Documentation Complète

- **Ghidra** : https://skills.sh/trailofbits/skills-curated/ghidra-headless
- **CTF Malware** : https://skills.sh/ljagiello/ctf-skills/ctf-malware
- **CTF Forensics** : https://skills.sh/ljagiello/ctf-skills/ctf-forensics
- **Python** : https://skills.sh/89jobrien/steve/python-scripting
- **Binary Analysis** : https://skills.sh/laurigates/claude-plugins/binary-analysis
- **Reverse Engineering** : https://skills.sh/r00tedbrain-backup/skills/reverse-engineering

---

## ✅ Vérification de l'Installation

```powershell
# Vérifier que les skills sont bien locaux
Test-Path .\.agents\skills\ghidra-headless
Test-Path .\.agents\skills\ctf-malware
Test-Path .\.agents\skills\ctf-forensics
Test-Path .\.agents\skills\python-scripting
Test-Path .\.agents\skills\binary-analysis
Test-Path .\.agents\skills\reverse-engineering
```

Tous doivent retourner `True`.

---

## 🎓 Prochaines Étapes

1. **Tester les skills** sur un cas simple :
   ```bash
   @ghidra-headless analyse 04_EXTRACTED/macho_arm64_0.bin
   ```

2. **Combiner les skills** pour une analyse complète :
   ```bash
   @binary-analysis + @ctf-malware + @reverse-engineering
   Effectue un audit complet de iremovalpro.dll
   ```

3. **Optimiser les scripts existants** :
   ```bash
   @python-scripting
   Refactorise tous les scripts dans 02_SCRIPTS/ 
   pour utiliser asyncio et multiprocessing
   ```

---

**Installation réussie le 2026-06-22 à 00:35 UTC** ✅
