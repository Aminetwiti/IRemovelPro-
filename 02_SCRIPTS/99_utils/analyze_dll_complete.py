#!/usr/bin/env python3
"""
Analyse complète de iremovalpro.dll
Détecte le type (.NET vs native) et extrait tous les imports
"""

import pefile
import sys
from pathlib import Path

dll_path = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro\iremovalpro.dll"

print("=" * 80)
print("ANALYSE COMPLÈTE - iremovalpro.dll")
print("=" * 80)

try:
    pe = pefile.PE(dll_path)
    
    # Vérifier si c'est une DLL .NET
    print("\n[1] TYPE DE BINAIRE")
    print("-" * 80)
    is_dotnet = hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR')
    print(f"  Architecture    : {pe.FILE_HEADER.Machine:#x} ({pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]})")
    print(f"  Type            : {'DLL .NET (CLR)' if is_dotnet else 'DLL Native'}")
    print(f"  Taille          : {Path(dll_path).stat().st_size / (1024*1024):.2f} MB")
    
    if is_dotnet:
        print(f"  ⚠️  Cette DLL est gérée (.NET) - les vrais imports sont dans les métadonnées .NET")
        print(f"      Les imports PE listés ci-dessous sont juste les stubs CLR")
    
    # Imports PE
    print("\n[2] IMPORTS PE (Table IAT)")
    print("-" * 80)
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry_idx, entry in enumerate(pe.DIRECTORY_ENTRY_IMPORT, 1):
            dll_name = entry.dll.decode('utf-8')
            imports_count = len(entry.imports)
            
            print(f"\n  [{entry_idx}] {dll_name} ({imports_count} imports)")
            
            for imp_idx, imp in enumerate(entry.imports, 1):
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                else:
                    func_name = f"Ordinal #{imp.ordinal}"
                
                print(f"      {imp_idx:3d}. {func_name}")
        
        # Statistiques
        total_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
        total_funcs = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
        
        print(f"\n  📊 Total: {total_dlls} DLLs, {total_funcs} fonctions importées")
    else:
        print("  ❌ Aucun import PE trouvé")
    
    # Exports
    print("\n[3] EXPORTS")
    print("-" * 80)
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exports = [(e.ordinal, e.name.decode('utf-8') if e.name else f"Ordinal {e.ordinal}") 
                   for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        
        print(f"  Nombre d'exports: {len(exports)}")
        for ord_num, exp_name in exports[:20]:  # Afficher les 20 premiers
            print(f"    {ord_num:3d}. {exp_name}")
        
        if len(exports) > 20:
            print(f"    ... et {len(exports) - 20} autres")
    else:
        print("  ℹ️  Aucun export (normal pour une DLL .NET)")
    
    # Sections
    print("\n[4] SECTIONS")
    print("-" * 80)
    
    for section in pe.sections:
        name = section.Name.decode('utf-8').rstrip('\x00')
        size = section.SizeOfRawData
        vsize = section.Misc_VirtualSize
        entropy = section.get_entropy()
        
        print(f"  {name:10s}  Size: {size:10d}  VSize: {vsize:10d}  Entropy: {entropy:.2f}")
    
    # Détection anti-debug
    print("\n[5] DÉTECTION ANTI-DEBUG")
    print("-" * 80)
    
    anti_debug_found = False
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    if any(x in func_name for x in ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 
                                                      'NtQueryInformationProcess', 'OutputDebugString']):
                        print(f"  ⚠️  {func_name} (depuis {entry.dll.decode('utf-8')})")
                        anti_debug_found = True
    
    if not anti_debug_found:
        print("  ✅ Aucune fonction anti-debug détectée dans les imports PE")
    
    # Crypto APIs
    print("\n[6] APIs CRYPTOGRAPHIQUES")
    print("-" * 80)
    
    crypto_apis = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            if any(x in dll_name for x in ['bcrypt', 'crypt32', 'ncrypt', 'advapi32']):
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8')
                        crypto_apis.append(f"{func_name} ({entry.dll.decode('utf-8')})")
    
    if crypto_apis:
        for api in crypto_apis:
            print(f"  🔐 {api}")
    else:
        print("  ℹ️  Aucune API crypto dans les imports PE (peut être dans .NET)")
    
    # Réseau APIs
    print("\n[7] APIs RÉSEAU")
    print("-" * 80)
    
    network_apis = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            if any(x in dll_name for x in ['ws2_32', 'winhttp', 'wininet', 'iphlpapi']):
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8')
                        network_apis.append(f"{func_name} ({entry.dll.decode('utf-8')})")
    
    if network_apis:
        for api in network_apis:
            print(f"  🌐 {api}")
    else:
        print("  ℹ️  Aucune API réseau dans les imports PE")
    
    print("\n" + "=" * 80)
    print("ANALYSE TERMINÉE")
    print("=" * 80)
    
    if is_dotnet:
        print("\n💡 CONSEIL:")
        print("   Pour analyser les vrais imports .NET, utilisez:")
        print("   - ILSpy / dnSpy pour décompiler le code C#")
        print("   - ildasm pour extraire l'IL")
        print("   - Les imports PE ci-dessus sont juste le bootstrap CLR")
    
    pe.close()
    
except Exception as e:
    print(f"\n❌ ERREUR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
