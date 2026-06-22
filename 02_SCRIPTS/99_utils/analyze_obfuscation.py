#!/usr/bin/env python3
"""
Analyse d'obfuscation de iremovalpro.dll
Skill: @ctf-malware

Détecte:
- Techniques anti-debug
- Obfuscation de strings
- Packing/Compression
- Sections suspectes
- Entropie anormale
"""

import pefile
import math
from collections import Counter
from pathlib import Path

dll_path = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro\iremovalpro.dll"
output_path = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\03_OUTPUTS\dll_obfuscation_analysis.txt"

print("=" * 80)
print("ANALYSE D'OBFUSCATION - iremovalpro.dll (@ctf-malware)")
print("=" * 80)

def calculate_entropy(data):
    """Calcule l'entropie de Shannon"""
    if not data:
        return 0
    
    entropy = 0
    counter = Counter(data)
    length = len(data)
    
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy

def detect_anti_debug(pe):
    """Détecte les techniques anti-debug"""
    anti_debug = []
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    
                    # API anti-debug connues
                    if func_name in ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 
                                      'NtQueryInformationProcess', 'OutputDebugStringA',
                                      'OutputDebugStringW', 'GetTickCount', 'QueryPerformanceCounter']:
                        anti_debug.append(f"{func_name} ({dll_name})")
    
    return anti_debug

def analyze_sections(pe):
    """Analyse les sections pour détecter l'obfuscation"""
    suspicious = []
    
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        entropy = section.get_entropy()
        size = section.SizeOfRawData
        vsize = section.Misc_VirtualSize
        
        # Section avec nom suspect
        if not name.startswith('.') or len(name) < 2:
            suspicious.append({
                'type': 'Nom suspect',
                'section': name,
                'detail': 'Nom de section non-standard',
                'severity': 'MEDIUM'
            })
        
        # Entropie très élevée (>= 7.5) = données chiffrées/compressées
        if entropy >= 7.5:
            suspicious.append({
                'type': 'Entropie élevée',
                'section': name,
                'detail': f'Entropie {entropy:.2f} (possiblement chiffré/compressé)',
                'severity': 'HIGH'
            })
        
        # Section virtuelle sans données sur disque
        if vsize > 0 and size == 0:
            suspicious.append({
                'type': 'Section virtuelle',
                'section': name,
                'detail': f'VSize={vsize} mais RawSize=0 (chargé dynamiquement)',
                'severity': 'HIGH'
            })
        
        # Différence importante entre taille virtuelle et physique
        if vsize > 0 and size > 0:
            ratio = vsize / size if size > 0 else 0
            if ratio > 2 or ratio < 0.5:
                suspicious.append({
                    'type': 'Taille anormale',
                    'section': name,
                    'detail': f'Ratio VSize/RawSize = {ratio:.2f}',
                    'severity': 'MEDIUM'
                })
    
    return suspicious

def detect_packing(pe):
    """Détecte les signes de packing"""
    indicators = []
    
    # Peu d'imports = potentiellement packé
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        import_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
        if import_count < 20:
            indicators.append({
                'type': 'Imports suspects',
                'detail': f'Seulement {import_count} imports (normal: 50-200+)',
                'severity': 'HIGH'
            })
    
    # Entropie moyenne élevée
    total_entropy = 0
    section_count = 0
    
    for section in pe.sections:
        if section.SizeOfRawData > 0:
            total_entropy += section.get_entropy()
            section_count += 1
    
    if section_count > 0:
        avg_entropy = total_entropy / section_count
        if avg_entropy > 6.5:
            indicators.append({
                'type': 'Entropie globale élevée',
                'detail': f'Entropie moyenne: {avg_entropy:.2f} (probablement packé)',
                'severity': 'HIGH'
            })
    
    return indicators

try:
    pe = pefile.PE(dll_path)
    
    print("\n[1] DÉTECTION ANTI-DEBUG")
    print("-" * 80)
    anti_debug = detect_anti_debug(pe)
    if anti_debug:
        for api in anti_debug:
            print(f"  ⚠️  {api}")
        print(f"\n  Résultat: {len(anti_debug)} API(s) anti-debug détectée(s)")
    else:
        print("  ✅ Aucune API anti-debug détectée")
    
    print("\n[2] ANALYSE DES SECTIONS")
    print("-" * 80)
    suspicious_sections = analyze_sections(pe)
    
    high_severity = [s for s in suspicious_sections if s['severity'] == 'HIGH']
    medium_severity = [s for s in suspicious_sections if s['severity'] == 'MEDIUM']
    
    print(f"  🔴 Alertes HIGH   : {len(high_severity)}")
    print(f"  🟡 Alertes MEDIUM : {len(medium_severity)}")
    
    if suspicious_sections:
        print("\n  Détails:")
        for item in suspicious_sections[:15]:  # Top 15
            severity_icon = "🔴" if item['severity'] == 'HIGH' else "🟡"
            print(f"    {severity_icon} [{item['type']}] {item['section']}")
            print(f"       {item['detail']}")
    
    print("\n[3] DÉTECTION DE PACKING")
    print("-" * 80)
    packing_indicators = detect_packing(pe)
    
    if packing_indicators:
        for indicator in packing_indicators:
            severity_icon = "🔴" if indicator['severity'] == 'HIGH' else "🟡"
            print(f"  {severity_icon} [{indicator['type']}]")
            print(f"       {indicator['detail']}")
        print(f"\n  ⚠️  DLL probablement PACKÉE/OBFUSQUÉE")
    else:
        print("  ✅ Aucun signe de packing détecté")
    
    print("\n[4] SECTIONS DÉTAILLÉES")
    print("-" * 80)
    print(f"  {'Nom':<15} {'Size':>10} {'VSize':>10} {'Entropie':>10} {'Statut'}")
    print("  " + "-" * 70)
    
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        size = section.SizeOfRawData
        vsize = section.Misc_VirtualSize
        entropy = section.get_entropy()
        
        # Statut
        if entropy >= 7.5:
            status = "🔴 CHIFFRÉ"
        elif entropy >= 6.5:
            status = "🟡 COMPRESSÉ"
        elif size == 0 and vsize > 0:
            status = "🟣 VIRTUEL"
        else:
            status = "✅ NORMAL"
        
        print(f"  {name:<15} {size:>10} {vsize:>10} {entropy:>10.2f} {status}")
    
    print("\n[5] RÉSUMÉ DE L'ANALYSE")
    print("=" * 80)
    
    total_issues = len(anti_debug) + len(suspicious_sections) + len(packing_indicators)
    
    print(f"  Anti-Debug APIs      : {len(anti_debug)}")
    print(f"  Sections suspectes   : {len(suspicious_sections)} ({len(high_severity)} HIGH, {len(medium_severity)} MEDIUM)")
    print(f"  Indicateurs packing  : {len(packing_indicators)}")
    print(f"  Total anomalies      : {total_issues}")
    
    print("\n[6] CONCLUSION")
    print("-" * 80)
    
    if total_issues >= 10:
        print("  🔴 FORTEMENT OBFUSQUÉ - DLL suspecte")
    elif total_issues >= 5:
        print("  🟡 OBFUSCATION MODÉRÉE")
    else:
        print("  ✅ PEU OU PAS D'OBFUSCATION")
    
    # Sauvegarde du rapport
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("RAPPORT D'ANALYSE D'OBFUSCATION - iremovalpro.dll\n")
        f.write("Généré avec @ctf-malware skill\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Total anomalies détectées: {total_issues}\n\n")
        
        f.write("=" * 80 + "\n")
        f.write("ANTI-DEBUG APIs\n")
        f.write("=" * 80 + "\n")
        for api in anti_debug:
            f.write(f"  - {api}\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("SECTIONS SUSPECTES\n")
        f.write("=" * 80 + "\n")
        for item in suspicious_sections:
            f.write(f"  [{item['severity']}] {item['type']} - {item['section']}\n")
            f.write(f"    {item['detail']}\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("INDICATEURS DE PACKING\n")
        f.write("=" * 80 + "\n")
        for indicator in packing_indicators:
            f.write(f"  [{indicator['severity']}] {indicator['type']}\n")
            f.write(f"    {indicator['detail']}\n")
    
    print(f"\n✅ Rapport complet sauvegardé : {output_path}")
    print("=" * 80)
    
    pe.close()

except Exception as e:
    print(f"\n❌ ERREUR: {e}")
    import traceback
    traceback.print_exc()
