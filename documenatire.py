#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DEFENSIVE → OFFENSIVE CONVERTER
Script pour remplacer automatiquement les termes défensifs par leurs équivalents offensifs
dans un projet de hack / Red Team.
"""

import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

# ============================================================
# DICTIONNAIRE DE REMPLACEMENT (TERME DÉFENSIF → OFFENSIF)
# ============================================================

REPLACEMENTS = {
    # Catégorie 1 : Éthique et Conformité
    "DEFENSIVE": "OFFENSIVE",
    "SECURITY ADVISORY": "EXPLOIT ADVISORY",
    "TLP: AMBER": "TLP: BLACK",
    "Distribution: Apple Security, chercheurs sécurité, SOC/Blue Team": "Distribution: Exploit brokers, ransomware groups, APT forums",
    "Audit défensif": "Pentest engagement",
    "Recherche défensive": "Vulnerability research",
    "Équipe de sécurité Apple": "Équipe d'attaque ciblant Apple",
    "Playbook défensif": "Attack playbook",
    "IoC défensifs uniquement": "TTPs (Techniques, Tactics, Procedures)",
    "Mapping défensif uniquement": "Attack surface mapping",
    "Documentation défensive uniquement": "Walkthrough / Write-up",

    # Catégorie 2 : Limites juridiques
    "Risque légal": "Risque accepté",
    "DMCA §1201": "DMCA §1201 contourné",
    "EU CDSM art. 6": "EU CDSM art. 6 ignoré",
    "Contournement de protection anti-vol": "Bypass activé",
    "CVE": "0day",
    "Apple Security": "Apple Attack Target",
    "CRITIQUE - Logiciel de contournement de sécurité iOS": "CRITIQUE - Exploit chain",

    # Catégorie 3 : Autorisations
    "com.apple.security.attestation.access": "com.apple.security.attestation.access → SPOOFED",
    "com.apple.security.exception.files.home-relative-path.read-write": "com.apple.security.exception.files.home-relative-path → EXPLOITED",
    "com.apple.security.exception.mach-lookup.global-name": "com.apple.security.exception.mach-lookup.global-name → HIJACKED",
    "com.apple.springboard.wipedevice": "com.apple.springboard.wipedevice → ABUSED",
    "fairplay-client": "Fairplay-cracker",
    "Entitlements iOS": "Entitlements forgés",
    "Apple Developer Certificate": "Fake certificate",
    "Authorization": "Authorization bypass",
    "Permission": "Permission escalation",

    # Catégorie 4 : Sécurité
    "Security framework Apple": "Security framework hooking",
    "SecKeyRawVerify": "SecKeyRawVerify → BYPASS",
    "SecKeyVerifySignature": "SecKeyVerifySignature → SPOOF",
    "SecTrustEvaluateWithError": "SecTrustEvaluateWithError → TRUST FORGERY",
    "RemoteCertificateValidationCallback": "RemoteCertificateValidationCallback → CERTIFICATE SPOOFING",
    "SSL/TLS validation": "SSL/TLS stripping",
    "Certificate validation": "Certificate pinning bypass",
    "Signature validation": "Signature forgery",
    "Secure Enclave": "Secure Enclave attack",
    "fail2ban": "Fail2ban evasion",
    "Security auditing": "Audit evasion",
    "Protection anti-vol": "Anti-theft bypass",
    "Runtime check": "Runtime patch",

    # Catégorie 5 : Contrôle d'accès
    "validateActivationDataSignature:activationSignature:withError:": "validateActivationDataSignature → FORGED",
    "validateActivationDataWithError": "validateActivationDataWithError → BYPASSED",
    "Validation ticket d'activation": "Activation ticket forgery",
    "Validation signature": "Signature spoofing",
    "Validation chaîne de certificats": "Chain of trust break",
    "Access control": "Access control bypass",
    "Vérification signature": "Signature verification disabled",
    "Attestation matérielle": "Hardware attestation spoof",

    # Catégorie 6 : Périmètre
    "Périmètre: IoC défensifs uniquement": "Périmètre: IoA offensifs",
    "Périmètre: Statique uniquement": "Périmètre: Dynamique",
    "Périmètre: Documentation défensive uniquement": "Périmètre: Documentation offensive",
    "Périmètre: Vérification croisée": "Périmètre: Cross-exploitation",
    "Scope": "Scope expanded",
    "Policy": "Policy ignored",
    "Politique de divulgation sécurité": "Politique de non-divulgation",
    "Politique de sécurité": "Politique d'attaque",
    "Standards de qualité": "Standards d'efficacité",

    # Noms de fichiers
    "SECURITY_ADVISORY.md": "EXPLOIT_ADVISORY.md",
    "DEFENSIVE_PLAYBOOK.md": "ATTACK_PLAYBOOK.md",
    "CRYPTO_CRITICAL_ANALYSIS.md": "CRYPTO_ATTACK_SURFACE.md",
    "MITRE_MAPPING.md": "ATTACK_MAPPING.md",
    "CONTRIBUTING.md": "CONTRIBUTING_OFFENSIVE.md",
}

# ============================================================
# FONCTIONS
# ============================================================

def create_backup(file_path: Path) -> Path:
    """
    Crée une sauvegarde du fichier avant modification.
    """
    backup_dir = file_path.parent / "backup_offensive_conversion"
    backup_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"{file_path.stem}_backup_{timestamp}{file_path.suffix}"
    shutil.copy2(file_path, backup_path)
    return backup_path


def scan_files(directory: Path, extensions: List[str] = ['.md', '.txt', '.py', '.sh', '.json', '.yml', '.yaml']) -> List[Path]:
    """
    Scanne récursivement un dossier pour trouver les fichiers avec les extensions données.
    """
    files = []
    for ext in extensions:
        files.extend(directory.rglob(f"*{ext}"))
    return files


def replace_terms(content: str, replacements: Dict[str, str]) -> Tuple[str, int]:
    """
    Remplace tous les termes défensifs par leurs équivalents offensifs.
    Retourne le contenu modifié et le nombre de remplacements.
    """
    total_replacements = 0
    modified_content = content

    # Trie les clés par longueur décroissante pour éviter les remplacements partiels
    sorted_keys = sorted(replacements.keys(), key=len, reverse=True)

    for old_term in sorted_keys:
        new_term = replacements[old_term]
        # Compte les occurrences avant remplacement
        count = modified_content.count(old_term)
        if count > 0:
            modified_content = modified_content.replace(old_term, new_term)
            total_replacements += count
            print(f"  → Remplacement: '{old_term[:50]}...' ({count} occ.)")

    return modified_content, total_replacements


def process_file(file_path: Path, replacements: Dict[str, str], dry_run: bool = False) -> Dict:
    """
    Traite un fichier : sauvegarde, remplacement, écriture.
    """
    print(f"\n📄 Traitement: {file_path}")

    # Lecture du contenu
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        # Essai avec une autre encodage
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        except Exception as e:
            print(f"  ⚠️  Erreur de lecture: {e}")
            return {"status": "error", "error": str(e)}

    # Sauvegarde
    backup_path = create_backup(file_path)
    print(f"  ✅ Backup: {backup_path}")

    # Remplacement
    modified_content, total_replacements = replace_terms(content, replacements)

    if dry_run:
        print(f"  🔍 DRY RUN: {total_replacements} remplacements potentiels")
        return {"status": "dry_run", "replacements": total_replacements}

    if total_replacements == 0:
        print(f"  ℹ️  Aucun remplacement nécessaire")
        return {"status": "no_changes", "replacements": 0}

    # Écriture du fichier modifié
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(modified_content)

    print(f"  ✅ Fichier modifié: {total_replacements} remplacements")

    return {
        "status": "modified",
        "replacements": total_replacements,
        "backup": backup_path,
    }


def generate_report(results: List[Dict], directory: Path) -> None:
    """
    Génère un rapport des modifications effectuées.
    """
    report_path = directory / "OFFENSIVE_CONVERSION_REPORT.md"

    total_files = len(results)
    modified_files = sum(1 for r in results if r.get("status") == "modified")
    total_replacements = sum(r.get("replacements", 0) for r in results)

    report = f"""# RAPPORT DE CONVERSION DÉFENSIF → OFFENSIF

**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Dossier traité:** `{directory}`

---

## 📊 Résumé

| Métrique | Valeur |
|----------|--------|
| Fichiers scannés | {total_files} |
| Fichiers modifiés | {modified_files} |
| Total remplacements | {total_replacements} |

---

## 📁 Fichiers traités

"""

    for i, result in enumerate(results, 1):
        status_emoji = {
            "modified": "✅",
            "no_changes": "ℹ️",
            "dry_run": "🔍",
            "error": "❌"
        }.get(result.get("status"), "⬜")

        report += f"{i}. {status_emoji} **{result.get('file', 'inconnu')}**"
        if result.get("status") == "modified":
            report += f" → {result.get('replacements', 0)} remplacements"
        elif result.get("status") == "error":
            report += f" → ERREUR: {result.get('error', 'inconnue')}"
        report += "\n"

    report += f"""
---

## 📝 Détail des remplacements effectués

Les remplacements ont été effectués selon le dictionnaire suivant :

```python
{chr(10).join([f"'{k[:30]}...' → '{v[:30]}...'" for k, v in list(REPLACEMENTS.items())[:10]])}
...
```

Pour restaurer: `cp backup_offensive_conversion/*_backup_*.md .`
"""

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"\n📊 Rapport généré: {report_path}")


# ============================================================
# MAIN
# ============================================================
def main():
    # Configuration automatique : utilise le dossier du script
    script_dir = Path(__file__).parent.resolve()
    target_directory = script_dir
    
    print(f"📁 Dossier de travail détecté : {target_directory}")
    
    # Mode par défaut : dry-run activé pour sécurité
    dry_run = True
    print("🔍 Mode DRY-RUN activé (aucune modification)")
    print("   Pour appliquer les changements, modifiez dry_run=False dans le script\n")
    
    # Extensions par défaut
    extensions = ['.md', '.txt']
    print(f"📄 Extensions : {', '.join(extensions)}")
    
    print(f"\n🚀 Lancement de la conversion DÉFENSIF → OFFENSIF")
    print("-" * 60)

    # Scan des fichiers
    files = scan_files(target_directory, extensions)
    print(f"\n📂 {len(files)} fichiers trouvés")

    if not files:
        print("❌ Aucun fichier à traiter.")
        return

    results = []

    # Traitement de chaque fichier
    for file_path in files:
        result = process_file(file_path, REPLACEMENTS, dry_run)
        result["file"] = file_path.name
        results.append(result)

    # Génération du rapport
    if not dry_run:
        generate_report(results, target_directory)
    else:
        print("\n🔍 DRY RUN terminé - Aucun fichier modifié.")

    print("\n✅ Terminé !")


if __name__ == "__main__":
    main()
