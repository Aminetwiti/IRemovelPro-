# 05_IOC — Catalogue d'Indicateurs de Compromission


## 📁 Contenu

```
05_IOC/
├── README.md                # Ce fichier
├── ioc_catalog.md           # Catalogue complet des IoC
├── YARA_RULES.yar           # Règles YARA
├── SURICATA_RULES.rules     # Règles Suricata (IDS)
└── MITRE_MAPPING.md         # Mapping MITRE ATT&CK
```

## 📄 Documents

| Fichier | Usage |
|---|---|
| [`ioc_catalog.md`](ioc_catalog.md) | Catalogue exhaustif (hashes, URLs, domaines, bundles iOS, chemins) |
| [`YARA_RULES.yar`](YARA_RULES.yar) | Règles YARA pour scanners (ClamAV, Velociraptor, etc.) |
| [`SURICATA_RULES.rules`](SURICATA_RULES.rules) | Règles Suricata/Snort pour IDS réseau |
| [`MITRE_MAPPING.md`](MITRE_MAPPING.md) | Mapping vers MITRE ATT&CK framework |

## 🎯 Quick reference

### Hashes à bloquer (AV/EDR)
```
SHA-256: 07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7  (iRemoval PRO.exe)
SHA-256: 08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141  (iremovalpro.dll)
```

### Domaines à bloquer (DNS/Proxy)
```
s13.iremovalpro.com
iremovalpro.co
iremovalpro.com
t.me/iremovalpro
```

### Chemins iOS (MDM/forensic)
```
/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib
/var/mobile/Library/activation_records/activation_record.plist
```

### Endpoints HTTP (IDS)
```
https://s13.iremovalpro.com/iremovalActivation/*.ph
https://s13.iremovalpro.com/version33.tx
https://s13.iremovalpro.com/pub.ph
https://iremovalpro.com/Payax0.ph
```

## 🛡️ Usage par défenseur

### Analyste SOC
1. Importer les IoC dans le SIEM (Splunk, Elastic, Sentinel)
2. Créer des alertes sur les hashes de fichiers
3. Bloquer les domaines au niveau DNS/proxy
4. Surveiller les endpoints HTTP via IDS

### Analyste AV/EDR
1. Importer les YARA rules dans le scanner
2. Tester sur des samples collectés
3. Adapter les règles au produit utilisé

### Analyste forensic iOS
1. Chercher `/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib`
2. Chercher `com.panyolsoft.blackhound` dans les logs
3. Vérifier la présence de `com.iremovalpro.bypass` installé
4. Analyser `activation_records/activation_record.plist`

### Analyste réseau
1. Déployer les règles Suricata
2. Alerter sur connexions vers `*.iremovalpro.com`
3. Surveiller le pattern POST `/iremovalActivation/`

## 📚 Références

- [MITRE ATT&CK](https://attack.mitre.org/) — Framework de classification
- [YARA](https://yara.readthedocs.io/) — Documentation YARA
- [Suricata](https://suricata.io/) — Documentation Suricata
- [STIX/TAXII](https://oasis-open.github.io/cti-documentation/) — Format IoC

## 🔗 Navigation

- ⬆ [`../INDEX.md`](../INDEX.md) — Table des matières
- ⬇ [`../01_REPORTS/EXECUTIVE_SUMMARY.md`](../01_REPORTS/EXECUTIVE_SUMMARY.md) — Résumé

---

**Mis à jour** : 2026-06-22
**Périmètre** : IoC red teams
