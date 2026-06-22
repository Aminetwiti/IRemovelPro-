# 🚀 Quick Reference - Skills AI

> Guide rapide d'utilisation des skills installés

---

## 💡 Invocation Rapide

### Syntax
```
@skill-name <votre demande>
```

### Exemples Concrets

```bash
# Analyse binaire rapide
@binary-analysis liste les imports de iremovalpro.dll

# Détection malware
@ctf-malware cherche des anti-debug dans iRemoval PRO.exe

# Forensics
@ctf-forensics extrait les certificats de la section .rsrc

# Décompilation
@ghidra-headless décompile la fonction à l'offset 0x1A2B40

# Python
@python-scripting optimise le script re_deep3.py

# Reverse engineering
@reverse-engineering documente le protocole iact8.php
```

---

## 🎯 Workflows Courants

### 1. Analyse Complète d'un Binaire
```
@binary-analysis + @ghidra-headless + @ctf-malware
Analyse complète de [fichier.exe/dll]
```

### 2. Extraction de Payload
```
@ctf-forensics + @binary-analysis
Extrait tous les binaires embarqués dans iremovalpro.dll
```

### 3. Reverse d'un Protocole
```
@reverse-engineering + @python-scripting
Crée un script pour décoder les requêtes AES vers s13.iremovalpro.com
```

### 4. Optimisation de Script
```
@python-scripting
Refactorise [script.py] avec async/await et gestion d'erreurs
```

---

## 📊 Matrice Rapide

| Je veux... | J'utilise... |
|-----------|-------------|
| Désassembler | `@ghidra-headless` |
| Détecter malware | `@ctf-malware` |
| Extraire strings | `@ctf-forensics` |
| Optimiser Python | `@python-scripting` |
| Parser binaire | `@binary-analysis` |
| Documenter RE | `@reverse-engineering` |

---

## ⚡ Commandes Fréquentes

```bash
# Lister les skills
npx skills list

# Mettre à jour
npx skills update

# Chercher un nouveau skill
npx skills find "keyword"

# Ajouter un skill
npx skills add owner/repo@skill-name
```

---

## 🔥 Power Tips

### Combiner plusieurs skills
```
@ghidra-headless + @ctf-malware + @reverse-engineering
Analyse iremovalpro.dll : décompile, détecte anti-debug, documente
```

### Cibler un fichier spécifique
```
@binary-analysis analyse uniquement 04_EXTRACTED/macho_arm64_0.bin
```

### Demander un format de sortie
```
@ghidra-headless décompile et exporte en JSON pour import dans IDA Pro
```

---

## 📂 Fichiers Importants

- **Documentation complète** : `.agents/README.md`
- **Skills installés** : `.agents/skills/`
- **Scripts d'analyse** : `02_SCRIPTS/`
- **Rapports** : `01_REPORTS/`

---

## 🆘 Troubleshooting

### Le skill ne répond pas
```bash
# Vérifier l'installation
Test-Path .\.agents\skills\<skill-name>

# Réinstaller si nécessaire
npx skills add owner/repo@skill-name
```

### Conflit entre skills
```bash
# Utiliser un seul skill à la fois
@ghidra-headless <demande>

# Ou séparer les appels
```

---

**Version** : 1.0  
**Dernière mise à jour** : 2026-06-22
