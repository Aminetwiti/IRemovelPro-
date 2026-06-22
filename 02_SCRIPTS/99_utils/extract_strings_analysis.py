#!/usr/bin/env python3
"""
Extraction et analyse des strings de iremovalpro.dll
Skill: @binary-analysis
"""

import re
from pathlib import Path
from collections import Counter

dll_path = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro\iremovalpro.dll"
output_path = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\03_OUTPUTS\dll_strings_analysis.txt"

print("=" * 80)
print("EXTRACTION DES STRINGS - iremovalpro.dll (@binary-analysis)")
print("=" * 80)

def extract_strings(filepath, min_length=4):
    """Extrait les strings ASCII et Unicode d'un binaire"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # ASCII strings (printable characters)
    ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
    ascii_strings = re.findall(ascii_pattern, data)
    
    # Unicode strings (UTF-16 LE)
    unicode_pattern = rb'(?:[ -~]\x00){' + str(min_length).encode() + rb',}'
    unicode_strings = re.findall(unicode_pattern, data)
    
    # Decoder
    results = []
    for s in ascii_strings:
        try:
            results.append(('ASCII', s.decode('ascii')))
        except:
            pass
    
    for s in unicode_strings:
        try:
            decoded = s.decode('utf-16-le')
            results.append(('UTF-16', decoded))
        except:
            pass
    
    return results

print("\n[1] Extraction des strings...")
strings = extract_strings(dll_path, min_length=6)
print(f"    Total: {len(strings)} strings extraites")

# Catégorisation
urls = []
paths = []
crypto_keywords = []
api_calls = []
interesting = []

for encoding, s in strings:
    s_lower = s.lower()
    
    # URLs
    if 'http://' in s_lower or 'https://' in s_lower or '.com' in s_lower or '.php' in s_lower:
        urls.append(s)
    
    # Chemins fichiers
    elif '\\' in s and (':' in s or 'windows' in s_lower or 'system' in s_lower):
        paths.append(s)
    
    # Crypto keywords
    elif any(kw in s_lower for kw in ['aes', 'sha', 'rsa', 'bcrypt', 'crypt', 'key', 'cipher', 'encrypt', 'decrypt']):
        crypto_keywords.append(s)
    
    # API calls
    elif any(kw in s for kw in ['Get', 'Set', 'Create', 'Delete', 'Read', 'Write', 'Open', 'Close']):
        if len(s) > 10 and len(s) < 100:
            api_calls.append(s)
    
    # Interesting
    elif any(kw in s_lower for kw in ['password', 'token', 'api', 'key', 'secret', 'credential', 'activation', 'icloud', 'apple', 'idevice']):
        interesting.append(s)

# Sauvegarde complète
with open(output_path, 'w', encoding='utf-8') as f:
    f.write("=" * 80 + "\n")
    f.write("ANALYSE DES STRINGS - iremovalpro.dll\n")
    f.write("Généré avec @binary-analysis skill\n")
    f.write("=" * 80 + "\n\n")
    
    f.write(f"Total strings extraites: {len(strings)}\n\n")
    
    # URLs
    f.write("\n" + "=" * 80 + "\n")
    f.write(f"URLs ET ENDPOINTS ({len(set(urls))} uniques)\n")
    f.write("=" * 80 + "\n")
    for url in sorted(set(urls)):
        f.write(f"  {url}\n")
    
    # Chemins
    f.write("\n" + "=" * 80 + "\n")
    f.write(f"CHEMINS FICHIERS ({len(set(paths))} uniques)\n")
    f.write("=" * 80 + "\n")
    for path in sorted(set(paths))[:50]:  # Top 50
        f.write(f"  {path}\n")
    
    # Crypto
    f.write("\n" + "=" * 80 + "\n")
    f.write(f"MOTS-CLÉS CRYPTO ({len(set(crypto_keywords))} uniques)\n")
    f.write("=" * 80 + "\n")
    for kw in sorted(set(crypto_keywords)):
        f.write(f"  {kw}\n")
    
    # API calls
    f.write("\n" + "=" * 80 + "\n")
    f.write(f"API CALLS SUSPECTÉES ({len(set(api_calls))} uniques, top 100)\n")
    f.write("=" * 80 + "\n")
    for api in sorted(set(api_calls))[:100]:
        f.write(f"  {api}\n")
    
    # Interesting
    f.write("\n" + "=" * 80 + "\n")
    f.write(f"STRINGS INTÉRESSANTES ({len(set(interesting))} uniques)\n")
    f.write("=" * 80 + "\n")
    for item in sorted(set(interesting)):
        f.write(f"  {item}\n")

print("\n[2] Résumé de l'analyse")
print("=" * 80)
print(f"  URLs/Endpoints        : {len(set(urls))}")
print(f"  Chemins fichiers      : {len(set(paths))}")
print(f"  Mots-clés crypto      : {len(set(crypto_keywords))}")
print(f"  API calls             : {len(set(api_calls))}")
print(f"  Strings intéressantes : {len(set(interesting))}")

print("\n[3] Top 10 URLs détectées")
print("-" * 80)
for url in sorted(set(urls))[:10]:
    print(f"  🌐 {url}")

print("\n[4] Top 10 Crypto keywords")
print("-" * 80)
for kw in sorted(set(crypto_keywords))[:10]:
    print(f"  🔐 {kw}")

print("\n[5] Strings critiques")
print("-" * 80)
for item in sorted(set(interesting))[:10]:
    print(f"  ⚠️  {item}")

print(f"\n✅ Rapport complet sauvegardé : {output_path}")
print("=" * 80)
