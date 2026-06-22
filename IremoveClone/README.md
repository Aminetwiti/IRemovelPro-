# iRemovalClone — Index documentation

> **Clonage modernisé d'iRemoval PRO Premium Edition v5.2**
>
> Reconstruction complète à partir de l'audit statique du binaire original.

## 📚 Documents

| # | Fichier | Description |
|---|---|---|
| 0 | [00_PRD.md](./00_PRD.md) | **Product Requirements Document** — vision, personas, spécifications fonctionnelles et non-fonctionnelles, critères d'acceptation |
| 1 | [01_ARCHITECTURE.md](./01_ARCHITECTURE.md) | **Architecture technique détaillée** — composants PC/iOS/Backend, flux, protocoles, sécurité |
| 2 | [02_TECH_STACK.md](./02_TECH_STACK.md) | **Stack technologique complet** — langages, frameworks, bibliothèques, outils, infrastructure |
| 3 | [03_IMPLEMENTATION_ROADMAP.md](./03_IMPLEMENTATION_ROADMAP.md) | **Plan de développement** — 31 sprints, jalons, risques, métriques |

## 🎯 Résumé exécutif

**iRemovalClone** est la réimplémentation moderne de l'outil de contournement iCloud Activation Lock analysé dans le workspace parent (`../`).

### Différenciateurs vs original

| Aspect | Original | Clone |
|---|---|---|
| **Backend** | PHP legacy, mono-région | Symfony 6.4, PHP 8.2, multi-région (EU + US) |
| **Crypto** | Clé serveur en clair | 🔐 YubiHSM2 (optionnel) |
| **Tests** | Inconnu | xUnit + PHPUnit + Playwright, CI/CD |
| **Observabilité** | Basique | OpenTelemetry + Prometheus + Grafana |
| **Sécurité ops** | Basique | Vault + WireGuard + fail2ban |
| **i18n** | EN uniquement | EN/FR/ES ready |
| **Documentation** | Minimale | DocFX + Mermaid + MkDocs |

## ⚠️ Cadre d'utilisation

| Cas | Légalité |
|---|---|
| Récupération iPhone propriétaire bloqué | ✅ |
| Atelier de réparation avec mandat | ✅ |
| Recherche académique / audit sécurité | ✅ |
| Déblocage iPhone volé | ❌ Illégal |

## 📂 Structure projet cible

```
IremoveClone/
├── src/                          # Windows client (PC)
│   ├── IRemovalClone.UI/         # WPF .NET Framework 4.8
│   ├── IRemovalClone.Core/       # .NET 8 NativeAOT
│   └── IRemovalClone.Native/     # P/Invoke wrappers
├── ios/
│   └── blackhound/               # Cydia Substrate tweak
├── backend/                      # ⭐ Serveur reconstruit (3 versions)
│   ├── standalone/               # PHP pur (recommandé dev local)
│   ├── python/                   # Python/Flask (cross-platform)
│   ├── symfony/                  # PHP 8.2 + Symfony 6.4 (production)
│   ├── docker-compose.yml        # 3 services (php, python, nginx)
│   ├── nginx.conf
│   └── README.md                 # Doc complète backend
├── infra/
│   ├── terraform/                # Hetzner + Cloudflare
│   └── ansible/                  # Provisioning
└── tests/
    ├── e2e/                      # Playwright + Detox
    └── integration/              # Postman + Newman
```

## 📊 Statistiques projet

- **Composants** : 3 tiers (PC / iOS / Backend)
- **Endpoints API** : 13 identifiés
- **Méthodes Driver** : 17 (13 principales + 4 helpers)
- **Hooks iOS** : 5 (MobileActivationDaemon)
- **Jailbreaks supportés** : 4 (checkm8, palera1n, unc0ver, Dopamine)
- **Modèles iPhone** : 15 (A5 → A17 Pro)
- **Sprints totaux** : 31 (~7 mois MVP)

## 🚀 Quick start (roadmap)

1. **Sprint 0** : Setup & design (2 sem)
2. **Sprint 1-3** : Backend foundation (4 sem)
3. **Sprint 4-9** : PC Core engine (6 sem)
4. **Sprint 10-13** : iOS tweak (4 sem)
5. **Sprint 14-17** : UI WPF (4 sem)
6. **Sprint 18-20** : Jailbreak + intégration (3 sem)
7. **Sprint 21-24** : NAND eraser (4 sem)
8. **Sprint 25-28** : Tests E2E (4 sem)
9. **Sprint 29-30** : Beta privée (2 sem)
10. **Sprint 31** : Release v1.0 (1 sem)

---

## 📎 Liens utiles

- **Audit parent** : [`../01_REPORTS/`](../01_REPORTS/)
- **IoC originaux** : [`../05_IOC/`](../05_IOC/)
- **Méthodologie** : [`../01_REPORTS/METHODOLOGY.md`](../01_REPORTS/METHODOLOGY.md)

---

**Auteur** : Équipe iRemovalClone
**Date** : 2026-06-22
**Version** : 0.1 (Draft initial)
