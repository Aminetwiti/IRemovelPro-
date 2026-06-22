# SECURITY — Politique de divulgation

> Ce document décrit la politique de sécurité du projet d'audit.

## Versions supportées

| Version | Supportée            |
|---------|----------------------|
| 1.0.x   | ✅ Active            |
| 0.9.x   | ⚠️ Maintenance       |
| < 0.9   | ❌ Non supportée    |

## Signaler une vulnérabilité

Si vous avez découvert une vulnérabilité dans ce projet d'audit ou souhaitez signaler un problème de sécurité :

### Process
1. **NE PAS** ouvrir d'issue publique
2. Contacter les mainteneurs en privé (email/Telegram indiqué dans README)
3. Fournir :
   - Description du problème
   - Étapes de reproduction
   - Impact estimé
   - Suggestion de correctif (optionnel)

### Délai de réponse
- Accusé de réception : 48h
- Évaluation initiale : 7 jours
- Correctif : selon la sévérité

## Vulnérabilités connues (transparence)

Ce projet d'audit **documente intentionnellement** des vulnérabilités dans :
- iRemoval PRO (cible de l'audit)
- Apple iOS activation flow (cible du bypass)
- Cydia Substrate hooking

Ces documentations sont à but de **défense et recherche**.

## Données sensibles

Ce projet contient :
- Hashes de fichiers (SHA-256)
- URLs de serveurs privés
- Identifiants de bundles iOS
- Strings de certificats
- Chemins iOS

**Ne pas** partager ces informations publiquement sans :
- Coordination avec les défenseurs
- Respect du responsible disclosure
- Validation juridique

## Bonnes pratiques pour les contributeurs

- ✅ Vérifier les IoC avant publication
- ✅ Utiliser des UUIDs/hashes pour les identifiants uniques
- ✅ Citer les sources (rapports, scripts)
- Ne pas inclure de credentials réels
- ✅ faciliter l'exploitation

## Contact sécurité

Pour signaler :
- Ouvrir une issue privée
- Email : voir le profil du mainteneur principal

## Hall of Fame

Contributeurs ayant signalé des vulnérabilités :
- (Aucun pour l'instant)

---

## 🔒 Security Advisories publiés

Ce projet publie des advisories défensifs (TLP:AMBER) sur les vulnérabilités découvertes lors de l'audit d'iRemoval PRO.

### SA-2026-001 — Bypass d'Activation Lock iCloud via RSA-1024 forgé

**Statut** : Divulgué (TLP:AMBER)
**Date** : 2026-06-22
**Sévérité** : 🔴 CRITIQUE (CVSS 9.8)
**Composant** : Apple iOS (toutes versions < 19)

**Résumé** : iRemoval PRO embarque une clé publique **RSA-1024** hardcodée dans son tweak iOS `blackhound.dylib`. Cette clé remplace la vérification d'Apple lors de l'activation iCloud, permettant de signer des tickets d'activation forgés.

**IoC principaux** :
- Modulus SHA-256 : `2c8c67d4066a5b1f8848ab9284aae4f9f37a6e6edfebb27bde26ac99e2615d27`
- Bundle ID tweak : `com.panyolsoft.blackhound`
- Domaine C2 : `s13.iremovalpro.com`

**Documents** : [`DEFENSIVE_PLAYBOOK.md`](DEFENSIVE_PLAYBOOK.md), [`BYPASS_CORE.md`](BYPASS_CORE.md), [`APPLE_CERT_CHAIN.md`](APPLE_CERT_CHAIN.md)

---

### SA-2026-002 — Certificat Apple Developer légitimé pour signer le bypass

**Statut** : Divulgué (TLP:AMBER) — pour action Apple Security
**Date** : 2026-06-22
**Sévérité** : 🟠 HAUTE (CVSS 7.5)
**Cible** : Compte `weidong li (PBNGZQ8G6L)` team `UR3K3ZV28R`

**Résumé** : Le binaire `iremovalpro.dll` contient la **chaîne de certificats Apple complète** (Root CA + WWDR + dev cert expiré). Permet de signer des IPA qui s'installent sur iOS non-jailbreaké.

**Action** : Révocation immédiate team `UR3K3ZV28R` + enquête Apple Legal.

**Documents** : [`APPLE_CERT_CHAIN.md`](APPLE_CERT_CHAIN.md)

---

### SA-2026-003 — Endpoint `iact8.php` : dérivation PBKDF2 faible

**Statut** : Divulgué (TLP:AMBER)
**Date** : 2026-06-22
**Sévérité** : 🟠 MOYENNE
**Composant** : Backend `s13.iremovalpro.com`

**Résumé** : Endpoint `iact8.php` utilise PBKDF2-HMAC-SHA256 avec sel statique et 10 000 itérations pour dériver `nonce_C`. Faiblesse : sel statique + itérations < OWASP 2023.

**Documents** : [`CRYPTO_KEY_DERIVATION.md`](CRYPTO_KEY_DERIVATION.md), [`ENDPOINT_IACT8.md`](ENDPOINT_IACT8.md)

---

## 📊 Métriques défensives

| Métrique | Valeur |
|---|---|
| Rapports publiés | 17 (01_REPORTS/) + CAPSTONE |
| IoC catalogués | 60+ (hashes, domaines, URLs, certs, mod RSA) |
| Règles YARA fichier | 13 (YARA_RULES.yar) |
| Règles YARA wire | 5 (YARA_RULES_WIRE.yar) |
| Règles Suricata | 6+ (SURICATA_RULES.rules) |
| Règles Sigma | 8+ (SIGMA_RULES.yml) |
| Certs X.509 extraits | 8 (apple_certs/) |
| Corpus de test | 100+ échantillons (06_LOCAL_REPRODUCER/corpus/) |
| Scripts d'analyse | 11+ (02_SCRIPTS/12_bypass_core/) |
| Security Advisories | 3 résumés ici (voir SECURITY_ADVISORY.md pour les 5 détaillés) |

**Liste complète des advisories** : voir [`SECURITY_ADVISORY.md`](SECURITY_ADVISORY.md) (SA-2026-001 à 005)

---

**Note** : Ce document suit les principes de [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories).
