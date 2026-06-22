# Contributing — Comment contribuer

> Merci de votre intérêt pour ce projet d'audit. Ce document explique comment participer.



## Comment contribuer

### 1. Signaler des erreurs

- Ouvrir un ticket décrivant :
  - La source (rapport, script, ligne)
  - La correction proposée
  - Une référence (ligne de code, sortie de script, doc Apple)

### 2. Proposer de nouveaux scripts

- Suivre le naming : `phaseN_description.py`
- Compatible Python 3.10+
- Pas de dépendances exotiques (max : `pefile`, `dnfile`, `requests`)
- Documenter dans le README de la phase

### 3. Améliorer les rapports

- Garder le format Markdown standard
- Vérifier toute affirmation contre le binaire (docs-guard)
- Citer les sources (lignes de `strings_all_long.txt`, etc.)

## Standards de qualité

### Code Python
```python
#!/usr/bin/env python3
"""One-line description.

Longer description if needed.
"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Use .NET API for paths with brackets (PowerShell 5.1 limitation)
import os
BASE = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'
```

### Markdown
- Utiliser les ATX headers (`#`, `##`, `###`)
- Tables en pipes `|`
- Code fences avec language tags
- Liens absolus vers les autres docs du projet

### Vérification (docs-guard)
Avant de proposer un changement, vérifier :
- [ ] Les noms de fichiers sont exacts
- [ ] Les lignes de code citées sont reproduites fidèlement
- [ ] Les IoC sont validés contre le binaire
- [ ] Pas de claims non vérifiés

## Workflow

```
1. Fork le projet
2. Créer une branche (git checkout -b fix/...)
3. Commit (git commit -m "...")
4. Push (git push origin fix/...)
5. Ouvrir une Pull Request
```

## License

Ce projet est sous **license TBD** — voir [LICENSE.md](LICENSE.md) si présent.

## Contact

- Issues : utiliser le tracker du projet
- Discussions : pour les questions ouvertes

## Code de conduite

- Respecter les autres contributeurs
- Pas de harcèlement
- Pas de publication d'informations personnelles
- Discussions techniques uniquement

## Hall of Fame

Contributeurs notables (par ordre de contribution) :
- Audit initial
- Cross-reference
- Documentation

(Mise à jour manuelle)
