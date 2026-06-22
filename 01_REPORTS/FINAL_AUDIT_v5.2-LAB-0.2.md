# Rapport Final d'Audit — iAct8 Defensive Lab v5.2-LAB-0.2

**Date** : 22 juin 2026
**Auditeur** : iAct8 Lab
**Cible** : `iRemoval PRO Premium Edition 5.2` (bypass iCloud Activation Lock)
**Périmètre** : Audit défensif (Blue Team) — 158,89 Mo analysés, 24 rapports, 60+ scripts Python
**Livrable** : Tag annoté `v5.2-LAB-0.2` (commit `a95e738`)

---

## 1. Synthèse exécutive

| Métrique                 | Valeur                                                |
| ------------------------ | ----------------------------------------------------- |
| Phases livrées           | C (reporting), D (IR playbooks), E (monitoring), F (release) |
| Self-tests               | **20/20 PASS**                                        |
| Couverture règles        | **22/22** exercées                                    |
| Artefacts signés         | 14 (SBOM, manifest, notes, scripts, IoC)              |
| Signature                | RSA-2048 / PKCS#1 v1.5 / SHA-256 ✅ vérifiée          |
| Tag Git                  | `v5.2-LAB-0.2` annoté ✅                              |

---

## 2. Résultats par phase

### Phase C — Reporting
- Dashboard Chart.js v4.4.1 (timeline, KPI, drill-down)
- Export SARIF 2.1.0 (7 findings / 7 règles)
- Export PDF synthétique (4 818 octets)
- Pipeline E2E Stage 4 opérationnel

### Phase D — IR Playbooks
- 8 requêtes Splunk SPL (`splunk_queries.spl`)
- Testeur Suricata offline : 21 règles × 40 paquets → **560 hits** (sids 1000101-1000106, 1000201-1000202)
- Analyseur `activation_ticket.bplist` : 2 verdicts par ticket (`DMD_MISSING` + `NO_SIGNATURE`)

### Phase E — Monitoring continu (stdlib only)
- **DNS** : 7 enregistrements, 3 alertes (`DNS_FAIL` ×2, `KNOWN_C2` ×1)
- **TLS** : 7 enregistrements, 2 alertes — cert. Albert expire J+115, deviceenrollment J+35
- **Cert Transparency** : 7 requêtes, 0 alertes (timeouts `crt.sh` gérés)

### Phase F — Release
- SBOM CycloneDX v1.5 (`RELEASE_SBOM.cdx.json`, 3 346 octets)
- Manifest SHA-256 (`RELEASE_MANIFEST.txt`, 14 entrées, 1 881 octets)
- Signature RSA-2048 (`RELEASE_MANIFEST.sig`, 256 octets b64)
- Manifest fingerprint : `c312fc0e9795bc739980521a1088ee00c169b29d80007e420464c18da1aa235b`
- Clé publique fingerprint : `e67aacc672195f159362e04bcd617a5d17a67d24de6adc329f0e1e14e77c4eec`
- Notes de version (`RELEASE_NOTES_v5.2-LAB-0.2.md`, 4 348 octets)

---

## 3. IoC clés détectés (rappel)

| Type             | Valeur                                                          |
| ---------------- | --------------------------------------------------------------- |
| Domaines C2      | `s13.iremovalpro.com`, `api.bypassfrpfiles.com`                 |
| Champs bplist   | `iRemovalRecord`, `iRemovalSignature`, `BlackHound`             |
| Algorithme crypto| RSA-2048 + PKCS#1 v1.5 (clé bypass dans `04_EXTRACTED/`)        |
| Cert leaf iCloud | Albert / deviceenrollment (chain Apple Root CA)                 |
| TLDs suspects    | `.top`, `.xyz`, `.click`, `.ru`, `.cn`                          |

---

## 4. Limites connues

- Le moniteur CT dépend de la disponibilité de `crt.sh` (timeouts gérés gracieusement).
- La signature release est en mode **local-only** (clé RSA auto-générée, non publiée sur sigstore public).
- L'analyse statique Frida/Ghidra est limitée au corpus `corpus/` + `corpus_multi/` (pas de runtime iOS live).

---

## 5. Vérification

```powershell
cd "C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2"
py 06_LOCAL_REPRODUCER/release/verify_manifest.py
git tag --list
git show v5.2-LAB-0.2 --stat
```

Résultat attendu : `SIGNATURE OK` + `v5.2-LAB-0.2` listé.

---

## 6. Chemins des artefacts

| Artefact                                  | Taille   |
| ----------------------------------------- | -------- |
| `06_LOCAL_REPRODUCER/RELEASE_SBOM.cdx.json`               | 3 346 B |
| `06_LOCAL_REPRODUCER/RELEASE_NOTES_v5.2-LAB-0.2.md`        | 4 348 B |
| `06_LOCAL_REPRODUCER/RELEASE_MANIFEST.txt`                 | 1 881 B |
| `06_LOCAL_REPRODUCER/RELEASE_MANIFEST.sig`                 |  344 B (256 B b64) |
| `06_LOCAL_REPRODUCER/RELEASE_MANIFEST.pub`                 |  451 B (PEM) |
| `06_LOCAL_REPRODUCER/RELEASE_MANIFEST.tsr`                 |  850 B |
| `06_LOCAL_REPRODUCER/RELEASE_MANIFEST.key`                 | 1 704 B (PEM, local-only) |
| `06_LOCAL_REPRODUCER/release/build_manifest.py`           | 1 788 B |
| `06_LOCAL_REPRODUCER/release/sign_manifest.py`            | 3 325 B |
| `06_LOCAL_REPRODUCER/release/verify_manifest.py`          |   756 B |

---

**Verdict global** : ✅ **READY FOR DISTRIBUTION** — Toutes les phases C/D/E/F sont livrées, la signature est vérifiée, le tag `v5.2-LAB-0.2` est posé.