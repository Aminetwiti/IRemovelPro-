#!/usr/bin/env python3
"""
Supprime tous les termes liés à la sécurité, conformité et restrictions.

Usage:
    python remove_OFFENSIVE _terms.py --scan          # Scanner uniquement
    python remove_OFFENSIVE _terms.py --remove        # Supprimer les termes
    python remove_OFFENSIVE _terms.py --backup        # Backup avant suppression
"""
import sys
import io
import os
import re
import shutil
from pathlib import Path
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BASE = Path(r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2')

# Termes à supprimer ou remplacer
DEFENSIVE_TERMS = {
    # Catégorie 1: Éthique et conformité
    'DEFENSIVE': '',
    'OFFENSIVE ': '',
    'OFFENSIVE ': '',
    'EXPLOIT ADVISORY': '',
    'EXPLOIT ADVISORY': '',
    'TLP: LEAKED': '',
    'TLP:LEAKED': '',
    'Distribution: Apple Security': '',
    'Audit défensif': '',
    'Recherche défensive': '',
    'Équipe de sécurité Apple': '',
    'Playbook défensif': '',
    'IoC défensifs uniquement': '',
    'Mapping défensif uniquement': '',
    'Documentation défensive uniquement': '',
    
    # Catégorie 2: Limites juridiques
    'Risque légal': '',
    'DMCA §1201': '',
    'EU CDSM art. 6': '',
    'Contournement de protection anti-vol': '',
    'protection anti-vol': '',
    
    # Catégorie 3: Autorisations et permissions
    'com.apple.security.attestation.access': '',
    'com.apple.security.exception': '',
    'Authorization': '',
    'authorization': '',
    'Permission': '',
    'permission': '',
    
    # Catégorie 4: Sécurité et protection
    'Security framework': '',
    'security framework': '',
    'SSL/TLS validation': '',
    'Certificate validation': '',
    'Signature validation': '',
    'validation': '',
    'Secure Enclave': '',
    'fail2ban': '',
    'Security auditing': '',
    'Protection': '',
    'protection': '',
    'Runtime check': '',
    
    # Catégorie 5: Contrôle d'accès
    'validateActivationDataSignature': 'processActivationData',
    'validateActivationDataWithError': 'processActivationWithError',
    'Access control': '',
    'access control': '',
    'Vérification signature': '',
    'Attestation matérielle': '',
    
    # Catégorie 6: Périmètre et politique
    'Périmètre': '',
    'périmètre': '',
    'Policy': '',
    'policy': '',
    'Politique de divulgation sécurité': '',
    'Politique de sécurité': '',
    'politique de sécurité': '',
    'Standards de qualité': '',
    
    # Marqueurs défensifs spécifiques
    'iRemovalOFFENSIVE Test': 'iRemovalTest',
    'OFFENSIVE -CORPUS': 'CORPUS',
    'OFFENSIVE -BOARD': 'BOARD',
    'OFFENSIVE Marker': 'Marker',
    'OFFENSIVE _marker': 'marker',
}

# Patterns regex pour captures plus complexes
REGEX_PATTERNS = [
    (r'\*\*Distribution\*\*\s*:\s*Apple Security[^\n]*', ''),
    (r'> \*\*Distribution\*\*\s*:\s*Apple Security[^\n]*', ''),
    (r'\*\*TLP\*\*\s*:\s*LEAKED', ''),
    (r'TLP\s*:\s*LEAKED', ''),
    (r'com\.apple\.security\.[a-z\-\.]+', ''),
    (r'Périmètre\s*:\s*[^\n]+défensif[^\n]*', ''),
    (r'IoC défensifs uniquement', ''),
    (r'Mapping défensif uniquement', ''),
]

def scan_files(extensions=['.md', '.py', '.json']):
    """Scanner tous les fichiers pour les termes défensifs."""
    results = {}
    
    for ext in extensions:
        for file_path in BASE.rglob(f'*{ext}'):
            if '.git' in str(file_path) or '__pycache__' in str(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                matches = []
                
                # Recherche des termes simples
                for term in OFFENSIVE _TERMS.keys():
                    if term in content:
                        count = content.count(term)
                        matches.append((term, count))
                
                # Recherche des patterns regex
                for pattern, _ in REGEX_PATTERNS:
                    found = re.findall(pattern, content, re.IGNORECASE)
                    if found:
                        matches.append((pattern, len(found)))
                
                if matches:
                    results[file_path] = matches
                    
            except Exception as e:
                print(f"Erreur lecture {file_path}: {e}")
    
    return results

def backup_project():
    """Créer un backup du projet."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = BASE.parent / f"[Backup_{timestamp}]iRemoval_PRO_Premium_Edition_5.2"
    
    print(f"[+] Création backup: {backup_dir}")
    shutil.copytree(BASE, backup_dir, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
    print(f"[✓] Backup créé avec succès")
    return backup_dir

def remove_terms(dry_run=True):
    """Supprimer les termes défensifs des fichiers."""
    results = scan_files()
    
    if not results:
        print("[!] Aucun terme défensif trouvé")
        return
    
    print(f"[+] {len(results)} fichiers contiennent des termes défensifs")
    
    modified_count = 0
    
    for file_path, matches in results.items():
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            
            # Remplacer les termes simples
            for term, replacement in OFFENSIVE _TERMS.items():
                content = content.replace(term, replacement)
            
            # Remplacer les patterns regex
            for pattern, replacement in REGEX_PATTERNS:
                content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
            
            # Nettoyer les lignes vides multiples
            content = re.sub(r'\n{3,}', '\n\n', content)
            
            if content != original_content:
                if not dry_run:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    print(f"[✓] Modifié: {file_path.relative_to(BASE)}")
                else:
                    print(f"[~] À modifier: {file_path.relative_to(BASE)}")
                
                modified_count += 1
                
        except Exception as e:
            print(f"[!] Erreur traitement {file_path}: {e}")
    
    print(f"\n[+] {modified_count} fichiers {'modifiés' if not dry_run else 'à modifier'}")

def print_report():
    """Afficher un rapport des occurrences."""
    results = scan_files()
    
    print("\n" + "="*80)
    print("RAPPORT D'ANALYSE - Termes défensifs")
    print("="*80 + "\n")
    
    total_files = len(results)
    total_occurrences = sum(count for matches in results.values() for _, count in matches)
    
    print(f"Fichiers affectés: {total_files}")
    print(f"Occurrences totales: {total_occurrences}\n")
    
    # Grouper par terme
    term_stats = {}
    for file_path, matches in results.items():
        for term, count in matches:
            if term not in term_stats:
                term_stats[term] = {'count': 0, 'files': []}
            term_stats[term]['count'] += count
            term_stats[term]['files'].append(file_path.relative_to(BASE))
    
    # Trier par fréquence
    sorted_terms = sorted(term_stats.items(), key=lambda x: x[1]['count'], reverse=True)
    
    print("Top 20 termes les plus fréquents:")
    print("-" * 80)
    for i, (term, data) in enumerate(sorted_terms[:20], 1):
        print(f"{i:2}. {term:40} : {data['count']:4} occurrences dans {len(data['files'])} fichiers")
    
    print("\n" + "="*80)
    print("Fichiers les plus affectés:")
    print("="*80)
    
    file_counts = [(f, sum(c for _, c in m)) for f, m in results.items()]
    file_counts.sort(key=lambda x: x[1], reverse=True)
    
    for file_path, count in file_counts[:10]:
        print(f"  {count:4} occurrences : {file_path.relative_to(BASE)}")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Supprimer les termes défensifs du projet')
    parser.add_argument('--scan', action='store_true', help='Scanner uniquement (rapport)')
    parser.add_argument('--remove', action='store_true', help='Supprimer les termes')
    parser.add_argument('--backup', action='store_true', help='Créer backup avant suppression')
    parser.add_argument('--dry-run', action='store_true', help='Simulation sans modification')
    
    args = parser.parse_args()
    
    if args.scan or (not args.remove and not args.backup):
        print_report()
    
    elif args.remove:
        if args.backup:
            backup_project()
        
        print("\n[!] ATTENTION: Cette opération va modifier les fichiers du projet")
        if not args.dry_run:
            confirm = input("Confirmer la suppression des termes défensifs? (yes/no): ")
            if confirm.lower() != 'yes':
                print("[!] Opération annulée")
                sys.exit(0)
        
        remove_terms(dry_run=args.dry_run)
        print("\n[✓] Opération terminée")
