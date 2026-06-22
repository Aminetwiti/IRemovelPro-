#!/usr/bin/env python3
"""
Analyse des imports de iremovalpro.dll
Utilise pefile pour extraire tous les imports
"""

import pefile
import sys
from pathlib import Path

dll_path = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro\iremovalpro.dll"

print("=" * 70)
print("ANALYSE DES IMPORTS - iremovalpro.dll")
print("=" * 70)
print()

try:
    pe = pefile.PE(dll_path)
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        total_imports = 0
        dll_count = 0
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            dll_count += 1
            
            print(f"\n{'='*70}")
            print(f"DLL #{dll_count}: {dll_name}")
            print(f"{'='*70}")
            
            imports = []
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode('utf-8'))
                else:
                    imports.append(f"Ordinal {imp.ordinal}")
            
            total_imports += len(imports)
            
            # Afficher les imports
            for i, imp_name in enumerate(imports, 1):
                print(f"  {i:4d}. {imp_name}")
        
        print(f"\n{'='*70}")
        print(f"RÉSUMÉ")
        print(f"{'='*70}")
        print(f"Nombre de DLLs importées : {dll_count}")
        print(f"Nombre total d'imports   : {total_imports}")
        print()
        
        # Top DLLs critiques
        print("\n🔍 DLLs CRITIQUES IDENTIFIÉES:")
        critical_dlls = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            if any(x in dll_name for x in ['crypt', 'ssl', 'ws2_32', 'winhttp', 'kernel32', 'advapi32']):
                critical_dlls.append(entry.dll.decode('utf-8'))
        
        for cdll in critical_dlls:
            print(f"  ⚠️  {cdll}")
        
    else:
        print("❌ Aucun import trouvé dans cette DLL")
        
    pe.close()
    
except Exception as e:
    print(f"❌ ERREUR: {e}")
    sys.exit(1)
