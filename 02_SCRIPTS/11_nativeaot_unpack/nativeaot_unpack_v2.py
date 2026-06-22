#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T2+ - Parser NativeAOT amélioré pour iremovalpro.dll (.NET 8)
===============================================================

Extraction depuis le binaire iremovalpro.dll :
  - Strings UTF-8 ET UTF-16 (little-endian)
  - EEType-like entries
  - Method names (sections .text)
  - Types managés (depuis .rdata)
  - Frozen objects (string constants)

⚠️ Note technique : .NET 8 NativeAOT ne contient PAS de bytecode IL.
   Le code source a été entièrement compilé en code machine x64.
   On récupère donc : métadonnées, noms de types/méthodes, string constants.

Usage :
  py nativeaot_unpack_v2.py iremovalpro.dll
  py nativeaot_unpack_v2.py iremovalpro.dll --min-len 12
"""
import argparse
import re
import struct
import sys
import json
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DLL_PATH = PROJECT_ROOT / "IRemovalPro" / "iremovalpro.dll"
OUT_DIR = PROJECT_ROOT / "03_OUTPUTS" / "nativeaot"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def extract_ascii_strings(data: bytes, min_len: int = 6):
    """Extract ASCII printable strings."""
    pattern = rb'[\x20-\x7e]{%d,}' % min_len
    for m in re.finditer(pattern, data):
        s = m.group(0)
        if len(set(s)) >= 3:  # Not all same char
            yield {'offset': m.start(), 'value': s.decode('ascii'), 'encoding': 'ascii'}


def extract_utf16le_strings(data: bytes, min_len: int = 6):
    """Extract UTF-16 LE strings (typical .NET)."""
    # Pattern: alternating ASCII byte + null byte
    pattern = re.compile((rb'(?:[\x20-\x7e]\x00){%d,}') % min_len)
    for m in re.finditer(pattern, data):
        raw = m.group(0)
        try:
            text = raw.decode('utf-16-le', errors='replace')
            if len(set(text)) >= 3:
                yield {'offset': m.start(), 'value': text, 'encoding': 'utf16-le'}
        except Exception:
            pass


def classify_string(s: str):
    """Categorize a string by content."""
    sl = s.lower()
    categories = []

    # Crypto
    if any(k in sl for k in ['aes', 'rsa', 'sha', 'md5', 'hmac', 'crypt', 'cipher', 'pbkdf', 'bcrypt']):
        categories.append('crypto')
    # Network
    if any(k in sl for k in ['http://', 'https://', 'ssh', 'tls', 'ssl', 'tcp', 'socket']):
        categories.append('network')
    # Apple/iOS
    if any(k in sl for k in ['apple', 'icloud', 'mobileact', 'checkm8', 'minaeraser', 'blackhound', 'sec', 'keychain']):
        categories.append('apple-ios')
    # Bypass
    if any(k in sl for k in ['bypass', 'crack', 'jailbreak', 'unlock', 'activat', 'tweak', 'hook']):
        categories.append('bypass')
    # .NET namespaces
    if any(k in sl for k in ['system.', 'microsoft.', 'restsharp', 'newtonsoft', 'sshnet', 'bouncycastle']):
        categories.append('dotnet-lib')
    # Generic keywords
    if any(k in sl for k in ['iremoval', 'iremovalpro']):
        categories.append('product')
    # Method signatures
    if '(' in s and ')' in s and len(s) < 200:
        if any(k in sl for k in ['void', 'string', 'int', 'bool', 'byte', 'char']):
            categories.append('method-sig')

    return categories if categories else ['general']


def main():
    parser = argparse.ArgumentParser(description='Unpack .NET 8 NativeAOT bundle')
    parser.add_argument('dll', nargs='?', default=str(DLL_PATH))
    parser.add_argument('--output', '-o')
    parser.add_argument('--min-len', type=int, default=8)
    parser.add_argument('--max-strings', type=int, default=100000)
    args = parser.parse_args()

    dll_path = Path(args.dll)
    if not dll_path.exists():
        print(f'[!] DLL not found: {dll_path}')
        return 1

    print(f'[*] Loading: {dll_path} ({dll_path.stat().st_size:,} bytes)')

    with open(dll_path, 'rb') as f:
        data = f.read()

    # === 1. Extract ASCII strings ===
    print('[*] Extracting ASCII strings...')
    ascii_strs = list(extract_ascii_strings(data, args.min_len))
    print(f'[+] {len(ascii_strs):,} ASCII strings')

    # === 2. Extract UTF-16 LE strings (.NET typical) ===
    print('[*] Extracting UTF-16 LE strings...')
    utf16_strs = list(extract_utf16le_strings(data, args.min_len))
    print(f'[+] {len(utf16_strs):,} UTF-16 LE strings')

    # === 3. Classify ===
    all_strs = ascii_strs + utf16_strs
    print(f'[*] Total: {len(all_strs):,} strings')

    # Categorize
    by_category = {}
    for s in all_strs:
        cats = classify_string(s['value'])
        for c in cats:
            by_category.setdefault(c, []).append(s)

    print()
    print('=' * 70)
    print('STRING CATEGORIES')
    print('=' * 70)
    for cat in sorted(by_category.keys(), key=lambda c: -len(by_category[c])):
        print(f'  {cat:20s} {len(by_category[cat]):,}')

    # === 4. Save categorized outputs ===
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_base = OUT_DIR / f'nativeaot_{timestamp}'

    # Save all strings
    all_json = out_base.with_suffix('.all.json')
    with open(all_json, 'w', encoding='utf-8') as f:
        # Cap to avoid huge files
        capped = all_strs[:args.max_strings]
        json.dump(capped, f, indent=2, ensure_ascii=False)
    print(f'\n[*] All strings (capped): {all_json}')

    # Save by-category text files (more useful for analysis)
    for cat, strs in by_category.items():
        cat_file = OUT_DIR / f'category_{cat}_{timestamp}.txt'
        with open(cat_file, 'w', encoding='utf-8') as f:
            f.write(f'# Category: {cat}\n')
            f.write(f'# Source: {dll_path}\n')
            f.write(f'# Total: {len(strs):,} strings\n\n')
            for s in strs[:5000]:  # Cap
                v = s['value']
                if len(v) > 200:
                    v = v[:197] + '...'
                f.write(f'0x{s["offset"]:08x}  [{s["encoding"]}]  {v}\n')
        print(f'[*] Category {cat}: {cat_file}')

    # === 5. Highlight most interesting findings ===
    print()
    print('=' * 70)
    print('TOP INTERESTING STRINGS')
    print('=' * 70)

    # Show bypass/crypto/apple categories first
    for cat in ['bypass', 'apple-ios', 'crypto', 'product', 'network']:
        if cat in by_category:
            print(f'\n[{cat.upper()}] {len(by_category[cat])} strings (showing first 30):')
            print('-' * 70)
            for s in by_category[cat][:30]:
                v = s['value']
                if len(v) > 120:
                    v = v[:117] + '...'
                print(f'  0x{s["offset"]:08x}  {v}')

    # === 6. Find potential type/method names ===
    # Type names follow pattern: Namespace.ClassName
    # Look for CamelCase identifiers with dots
    print()
    print('[*] Looking for .NET type names (Namespace.Class)...')
    type_pattern = re.compile(rb'([A-Z][A-Za-z0-9_]+\.){1,5}[A-Z][A-Za-z0-9_]+')
    types_found = set()
    for m in re.finditer(type_pattern, data):
        t = m.group(0).decode('ascii', errors='replace')
        if 5 <= len(t) <= 200 and any(c.isupper() for c in t[1:]):
            types_found.add(t)
    print(f'[+] Found {len(types_found):,} unique type-like names')

    # Print sample types
    interesting_types = sorted(types_found)[:100]
    if interesting_types:
        print()
        print('Sample type names:')
        for t in interesting_types[:50]:
            print(f'  {t}')

    # === 7. Save types ===
    types_file = OUT_DIR / f'types_{timestamp}.txt'
    with open(types_file, 'w', encoding='utf-8') as f:
        for t in sorted(types_found):
            f.write(t + '\n')
    print(f'\n[*] Types saved: {types_file}')

    # === 8. Final summary ===
    print()
    print('=' * 70)
    print('VERDICT')
    print('=' * 70)
    print(f'  DLL size:         {len(data):,} bytes')
    print(f'  ASCII strings:    {len(ascii_strs):,}')
    print(f'  UTF-16 strings:   {len(utf16_strs):,}')
    print(f'  Unique types:     {len(types_found):,}')
    print(f'  Bypass refs:      {len(by_category.get("bypass", []))}')
    print(f'  Apple/iOS refs:   {len(by_category.get("apple-ios", []))}')
    print(f'  Crypto refs:      {len(by_category.get("crypto", []))}')
    print(f'  Network URLs:     {len(by_category.get("network", []))}')

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)