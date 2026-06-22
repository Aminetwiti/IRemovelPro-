# 📑 Index de Navigation - Skills AI

> Navigation rapide vers toute la documentation des skills

---

## 🎯 Documents Disponibles

### 📘 Documentation Principale
- **[README.md](README.md)** — Documentation complète (250 lignes)
  - Description détaillée des 6 skills
  - Cas d'usage pour iRemoval PRO
  - Matrice de compétences
  - Évaluation de sécurité

### ⚡ Guides Pratiques
- **[QUICK_START.md](QUICK_START.md)** — Guide de référence rapide
  - Syntax d'invocation
  - Workflows courants
  - Matrice rapide
  - Troubleshooting

### 📊 Rapports
- **[INSTALLATION_REPORT.md](INSTALLATION_REPORT.md)** — Rapport d'installation
  - Statistiques d'installation
  - Skills installés (liste complète)
  - Exemples d'utilisation
  - Prochaines étapes

---

## 🚀 Démarrage Rapide

### Première Utilisation
```bash
# 1. Lire le guide rapide
cat .agents/QUICK_START.md

# 2. Tester un skill
@binary-analysis liste les imports de iremovalpro.dll

# 3. Combiner des skills
@ghidra-headless + @ctf-malware analyse iRemoval PRO.exe
```

### Pour Aller Plus Loin
```bash
# Documentation complète
cat .agents/README.md

# Rapport détaillé
cat .agents/INSTALLATION_REPORT.md
```

---

## 📂 Structure du Dossier

```
.agents/
├── 📄 INDEX.md                    ← vous êtes ici
├── 📘 README.md                   ← documentation complète
├── ⚡ QUICK_START.md              ← guide rapide
├── 📊 INSTALLATION_REPORT.md     ← rapport d'installation
└── 📦 skills/                     ← skills installés
    ├── ghidra-headless/
    ├── ctf-malware/
    ├── ctf-forensics/
    ├── python-scripting/
    ├── binary-analysis/
    └── reverse-engineering/
```

---

## 🔗 Liens Externes

### Skills Marketplace
- **Marketplace** : https://skills.sh/
- **Documentation** : https://skills.sh/docs

### Skills Installés
1. [Ghidra Headless](https://skills.sh/trailofbits/skills-curated/ghidra-headless) — Trail of Bits
2. [CTF Malware](https://skills.sh/ljagiello/ctf-skills/ctf-malware) — ljagiello
3. [CTF Forensics](https://skills.sh/ljagiello/ctf-skills/ctf-forensics) — ljagiello
4. [Python Scripting](https://skills.sh/89jobrien/steve/python-scripting) — 89jobrien
5. [Binary Analysis](https://skills.sh/laurigates/claude-plugins/binary-analysis) — laurigates
6. [Reverse Engineering](https://skills.sh/r00tedbrain-backup/skills/reverse-engineering) — r00tedbrain

---

## 📋 Checklist

### Installation
- [x] 6 skills installés localement
- [x] Documentation créée (4 fichiers)
- [x] README.md du projet mis à jour
- [x] Vérification de l'installation

### Prochaines Étapes
- [ ] Tester un skill simple
- [ ] Analyser un binaire avec @ghidra-headless
- [ ] Détecter l'obfuscation avec @ctf-malware
- [ ] Optimiser les scripts avec @python-scripting

---

## 🆘 Besoin d'Aide ?

### Documentation
```bash
# Guide rapide (2 min de lecture)
cat .agents/QUICK_START.md

# Documentation complète (10 min de lecture)
cat .agents/README.md
```

### Commandes Utiles
```bash
# Lister les skills
npx skills list

# Chercher un nouveau skill
npx skills find "keyword"

# Mettre à jour
npx skills update
```

### Support
- **GitHub Issues** : Rapporter un bug sur le repo du skill
- **Skills.sh Discord** : Communauté d'entraide
- **Documentation officielle** : https://skills.sh/docs

---

## 🎓 Formation

### Niveau Débutant
1. Lire [QUICK_START.md](QUICK_START.md)
2. Tester : `@binary-analysis liste les imports de iremovalpro.dll`
3. Voir le résultat et comprendre la sortie

### Niveau Intermédiaire
1. Lire [README.md](README.md) section "Cas d'Usage"
2. Combiner 2 skills : `@ghidra-headless + @ctf-malware`
3. Analyser un binaire complet

### Niveau Avancé
1. Lire [INSTALLATION_REPORT.md](INSTALLATION_REPORT.md)
2. Créer des workflows personnalisés
3. Contribuer de nouveaux skills sur GitHub

---

## 📊 Statistiques

| Métrique | Valeur |
|----------|---------|
| **Skills installés** | 6 |
| **Documentation** | 4 fichiers |
| **Taille totale** | ~8.5 MB |
| **Date d'installation** | 2026-06-22 00:39 UTC |

---

## 🎯 Objectifs du Projet

### Court Terme (Cette Semaine)
- ✅ Installer les skills
- ⏳ Tester chaque skill individuellement
- ⏳ Analyser les binaires du projet
- ⏳ Optimiser les scripts Python

### Moyen Terme (Ce Mois)
- ⏳ Analyse forensique complète
- ⏳ Documentation du protocole iact8.php
- ⏳ Génération de rapports structurés
- ⏳ Présentation des résultats

### Long Terme (Ce Trimestre)
- ⏳ Publication académique
- ⏳ Conférence de sécurité
- ⏳ Whitepaper technique

---

**Dernière mise à jour** : 2026-06-22 00:39 UTC  
**Version** : 1.0
