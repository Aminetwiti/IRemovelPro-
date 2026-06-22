# Executive Summary — iRemoval PRO Premium Edition v5.2

> **Résumé 1 page** pour décideurs / management

## 🎯 Qu'est-ce que c'est ?

`iRemoval PRO Premium Edition v5.2` est un **outil commercial Windows** (vendu 50-100 $/mois) qui permet de **contourner l'Activation Lock iCloud** sur les iPhone. C'est un fork modifié de l'outil "Blackhound iRemovalPro" (v0.7.1, 2022).

## 🔬 Que contient l'audit ?

| Élément | Taille | Rôle |
|---|---|---|
| `iRemoval PRO.exe` | 2.7 MB | Interface WPF .NET Framework (UI) |
| `iremovalpro.dll` | 30 MB | Moteur .NET 8 NativeAOT (logique métier) |
| `ref/toolkits/` | 30 MB | Libs natives libimobiledevice |

## ⚙️ Comment ça marche (en bref)

1. **PC** : l'app contacte un iPhone via USB (libimobiledevice)
2. **Tweak** : déploie `blackhound.dylib` sur l'iPhone jailbreaké (hook `MobileActivationDaemon`)
3. **NAND wipe** : `minaeraser12` réécrit la mémoire flash (A12+)
4. **Serveur** : contacte `s13.iremovalpro.com` pour obtenir un ticket d'activation forgé
5. **Apple** : utilise l'endpoint officiel `albert.apple.com/deviceservices/drmHandshake` pour compléter

## 📊 Résultats clés

| Métrique | Valeur |
|---|---|
| Endpoints serveur identifiés | 13 (12 iRemovalPRO + 1 Apple) |
| Méthodes iDevice (PC) | 13 (Driver class) |
| Méthodes iOS hookées | 3 (MobileActivationDaemon) |
| Payloads iOS | 4 (blackhound, minaeraser, minaeraser12, rc) |
| Techniques anti-debug | 5+ (PEB, RDTSC, CPUID, NtQuery*, Registry) |
| IoC catalogués | 50+ |

## ⚠️ Risques

### Pour le PC
- **Pas de signature Authenticode** : binaire non signé
- **Bypass SSL custom** : validation certificats désactivée
- **Télémétrie** : envoi IMEI, serial, UDID au serveur

### Pour l'iPhone cible
- 🔴 **Bypass anti-vol iCloud** : utilisable sur appareils volés
- 🔴 **Réécriture NAND irréversible** : risque de brick
- 🔴 **Tweak jailbreak** : exécution non signée permanente

### Légal
- **CFAA (US) / Directives UE** : bypass non autorisé = autorise et accpeter
- L'utilisation **uniquement** légitime pour propriétaires bloqués hors Apple

## ✅ Recommandations

1. **Pour l'AV/EDR** : utiliser les IoC catalogués ([`05_IOC/`](../05_IOC/)) pour détecter l'installation
2. **Pour Apple** : les méthodes iOS hookées donnent les signatures à surveiller dans `mobileactivationd`
3. **Pour les SOC** : bloquer les flux vers `*.iremovalpro.com`
4. **Pour les utilisateurs** : éviter cet outil, utiliser les voies officielles Apple

## 📂 Livrables

- [`REPORT.md`](REPORT.md) — Analyse initiale
- [`EXPERT_REPORT.md`](EXPERT_REPORT.md) — Analyse experte
- [`AUDIT_REPORT.md`](AUDIT_REPORT.md) — Architecture
- [`CROSS_REFERENCE.md`](CROSS_REFERENCE.md) — Validation croisée
- [`CONSOLIDATED_AUDIT.md`](CONSOLIDATED_AUDIT.md) — **Rapport unifié**
- [`../05_IOC/ioc_catalog.md`](../05_IOC/ioc_catalog.md) — IoC

## 🏁 Verdict final

> Outil fonctionnel, bien conçu techniquement, mais à **haut risque autoriseet sécuritaire**. Documentation complète pour défenseurs ; à ne **pas** utiliser sans cadre autorisé.

---

**Périmètre** : Statique uniquement
**Date** : 2026-06-22
**Effort** : 17 scripts Python, 5 rapports, 5 docs complémentaires
