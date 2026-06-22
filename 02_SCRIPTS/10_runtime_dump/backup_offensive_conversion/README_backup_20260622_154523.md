# Phase 5 — Runtime Memory Dump

> **Analyse dynamique de iRemoval PRO v5.2**
> Capture de la mémoire runtime de la DLL pour extraire les clés crypto et les tickets d'activation iCloud en clair.

## ⚠️ AVERTISSEMENT DE SÉCURITÉ

**NE PAS exécuter sur votre machine hôte.**
Ce script déclenche `iRemovalPro.exe` et `iremovalpro.dll`, ce qui :
- Établit des connexions réseau vers `s13.iremovalpro.com`
- Tente de communiquer avec des serveurs Apple (MobileActivation)
- Déclenche les antivirus (Defender, EDR…)
- Modifie la base de registre Windows
- Nécessite un iDevice USB ou simule un pour activer les fonctions

### Prérequis OBLIGATOIRES
1. **VM isolée** : Hyper-V, VMware Workstation, ou VirtualBox
2. **Réseau coupé ou filtré** : `iptables`/firewall bloquant `*.iremovalpro.com` et Apple
3. **Snapshot avant exécution** : pouvoir restaurer l'état post-analyse
4. **Antivirus désactivé** : Defender, EDR, etc.
5. **Pas d'iPhone branché** : éviter les actions involontaires

## Scripts

### `memory_dump.py`
Outil principal de capture mémoire. Trois modes disponibles :

```bash
# Mode Frida (préféré) - injection JS dans le process
py memory_dump.py --mode frida --duration 600

# Mode Sysinternals procdump
py memory_dump.py --mode procdump --output dump.bin

# Mode custom (génère un dumper C# autonome)
py memory_dump.py --mode custom --output dumper.cs
```

**Hooks Frida actifs :**
- `BCryptEncrypt` / `BCryptDecrypt` → capture des buffers chiffrés + clés
- `WS2_32.send` / `WS2_32.recv` → capture du trafic réseau en clair
- `HttpSendRequest` → capture des requêtes HTTP
- Scan périodique toutes les 10s pour RSA/AES/PEM dans la mémoire du process

### `extract_keys_from_dump.py`
Analyse post-mortem du dump mémoire :

```bash
py extract_keys_from_dump.py --dump 03_OUTPUTS/runtime_dump/iRemoval.dmp --output keys.json
```

**Cherche dans le dump :**
- Clés RSA (PKCS#1, PKCS#8) via ASN.1 DER
- Clés AES (blocs 16/24/32 octets à haute entropie)
- Certificats X.509
- Blocs PEM (`-----BEGIN ...-----`)
- Tickets d'activation iCloud (plist, bplist00)
- Tokens d'API (Bearer, UUID v4, IMEI Luhn)

## Outputs

`03_OUTPUTS/runtime_dump/` :
- `frida_dump_*.json` — Traces Frida (hex des buffers capturés)
- `procdump_*.dmp` — Dump mémoire complet
- `extracted_keys.json` — Clés et artefacts trouvés
- `RSA_blobs/` — Clés RSA extraites en format binaire

## Méthodologie

1. **Préparation VM** : snapshot, réseau isolé, antivirus off
2. **Lancement iRemovalPro** : `iRemovalPro.exe` (interface GUI)
3. **Démarrage capture Frida** : `py memory_dump.py --mode frida`
4. **Déclenchement fonctions sensibles** : naviguer dans l'interface iRemovalPro
   - Section "Bypass Activation"
   - Section "Backup/Restore"
   - Section "Activation Tickets"
5. **Arrêt capture** : Ctrl+C
6. **Analyse post-mortem** : `py extract_keys_from_dump.py`

## Risques connus

| Risque | Mitigation |
|--------|------------|
| Connexion réseau non désirée | Firewall bloquant `*.iremovalpro.com` |
| Modification registre | Snapshot VM avant exécution |
| Infection par malware | VM jetable, pas de credentials |
| Détection EDR | Whitelist du dossier `02_SCRIPTS` |

## Dépendances

```
pip install frida-tools pefile pycryptodome asn1crypto
# Optionnel : Sysinternals procdump.exe
```

## Notes techniques

**Format NativeAOT** : la DLL est compilée .NET 8 NativeAOT. Le code IL est
perdu mais les **chaînes constantes** et les **constantes AES/RSA** sont
toujours en mémoire si l'app les utilise (ex: clé AES pour chiffrer les
tickets).

**Pourquoi Frida plutôt que ProcDump** :
- Capture précise des buffers passés aux APIs crypto
- Pas besoin de connaître l'offset mémoire exact
- Hooks sélectifs = moins de bruit
- Décryptage en temps réel des buffers capturés

## Voir aussi

- [README du dossier 11_nativeaot_unpack](../11_nativeaot_unpack/README.md)
- [01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md](../../01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md) — Analyse statique des APIs crypto
- [02_SCRIPTS/07_frida/](../07_frida/) — Scripts Frida existants
