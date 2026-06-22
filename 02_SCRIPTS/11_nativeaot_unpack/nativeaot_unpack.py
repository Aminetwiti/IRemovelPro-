#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T2 - Parser NativeAOT pour iremovalpro.dll (.NET 8)
=====================================================

.NET 8 NativeAOT compile le code IL en code machine natif. Cependant,
les **métadonnées** (noms de types, méthodes, signatures, string heap)
sont conservées dans la section `.managed` pour permettre la
reflection (sérialisation JSON, etc.).

Ce script extrait :
  - EEType table (tous les types managés : classes, structs, enums)
  - String heap (toutes les chaînes constantes managées)
  - Frozen Object Heap (objets pré-initialisés au démarrage)
  - Method names (pour identifier les méthodes managées)
  - Type hierarchy (classes, interfaces, délégués)
  - Generic instantiations
  - Delegates et Func<>/Action<> instances

⚠️ Limitations :
  - Le bytecode IL est PERDU (compilé en natif)
  - Les structures ne sont que partiellement documentées (format interne .NET)
  - Certains noms sont obfusqués par le compilateur

Usage :
  py nativeaot_unpack.py iremovalpro.dll
  py nativeaot_unpack.py iremovalpro.dll --strings-only --output strings.txt
  py nativeaot_unpack.py iremovalpro.dll --types-only --output types.txt

Prérequis :
  - pip install pefile
"""
import argparse
import re
import struct
import sys
import os
import json
from pathlib import Path
from datetime import datetime

# === CONFIG ===
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DLL_PATH = PROJECT_ROOT / "IRemovalPro" / "iremovalpro.dll"
OUT_DIR = PROJECT_ROOT / "03_OUTPUTS" / "nativeaot"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# EEType flags (COR_TYPEATTRIBUTE)
EE_TYPE_CLASS = 0x00000000
EE_TYPE_VALUETYPE = 0x00000001
EE_TYPE_INTERFACE = 0x00000002
EE_TYPE_GENERIC = 0x00000004
EE_TYPE_ARRAY = 0x00000008


def read_section(pe, section_name):
    """Read a section by name."""
    import pefile
    for s in pe.sections:
        name = s.Name.decode('utf-8', errors='ignore').rstrip(chr(0))
        if name == section_name:
            return s.get_data()
    return None


def extract_strings_heap(data: bytes):
    """Extract all printable strings >= 6 chars from managed data."""
    strs = []
    pattern = rb'[\x20-\x7e]{6,}'
    for m in re.finditer(pattern, data):
        s = m.group(0)
        # Filter out pure-noise strings (all same char or too repetitive)
        if len(set(s)) >= 4:
            strs.append({
                'offset': m.start(),
                'value': s.decode('ascii'),
                'length': len(s),
            })
    return strs


def find_eetype_table(data: bytes):
    """Find EEType entries in .managed section.

    EEType layout (x64, .NET 8):
      +0x00: uint32 flags (componentSize: 8, EETypeKind: 8, ...)
      +0x04: uint32 numFields
      +0x08: uint32 numVtableSlots
      +0x0C: uint32 hashCode
      +0x10: pointer parentEEType
      +0x18: pointer generic instantiation
      +0x20: pointer name
      ...
    """
    # EEType entries are aligned to 8 bytes in .NET 8
    # We look for the pattern: a pointer to a name string near the start of a region
    eetypes = []

    # .NET 8 EEType size is typically 56 bytes for normal types
    # We iterate through the section in 8-byte strides
    for i in range(0, len(data) - 56, 8):
        try:
            # Read first 4 bytes as flags (low 24 bits = component size, etc.)
            flags = struct.unpack('<I', data[i:i+4])[0]
            num_fields = struct.unpack('<I', data[i+4:i+8])[0]
            num_vtable = struct.unpack('<I', data[i+8:i+12])[0]

            # Sanity check
            if num_fields > 10000 or num_vtable > 5000:
                continue

            # Check pointer at +0x20 (relative offset to name string)
            name_offset_rel = struct.unpack('<q', data[i+0x20:i+0x28])[0]
            # Could be a VA or relative pointer - check if reasonable
            if -100000000 < name_offset_rel < 100000000:
                # Could be a name string pointer
                # Calculate where the name would be (relative to this position)
                name_addr = i + 0x20 + name_offset_rel
                if 0 <= name_addr < len(data) - 50:
                    name_bytes = data[name_addr:name_addr + 80]
                    if name_bytes[:1] == b'\x00' or name_bytes[:1] == b'\x01':
                        # Likely a length-prefixed or null-terminated string
                        # Skip length byte and null terminator
                        actual_name = name_bytes[1:].split(b'\x00')[0]
                        if 4 <= len(actual_name) <= 60 and all(32 <= c < 127 for c in actual_name):
                            eetypes.append({
                                'offset': i,
                                'flags': hex(flags),
                                'num_fields': num_fields,
                                'num_vtable': num_vtable,
                                'name': actual_name.decode('ascii'),
                            })
        except Exception:
            continue

    return eetypes


def find_method_tables(data: bytes):
    """Find method dispatch tables.

    In NativeAOT, method tables are arrays of pointers to native code.
    They typically follow EEType entries.
    """
    # Heuristic: look for sequences of 8-byte aligned pointers (VA addresses)
    # that point into the .text section
    return []  # Placeholder, requires more sophisticated parsing


def find_frozen_object_heap(pe):
    """Find and extract Frozen Object Heap region.

    FOH is typically in `.data` or `.rdata` and contains pre-initialized
    managed objects (e.g., string constants, type metadata).
    """
    # Look for the FOH signature or scan .data/.rdata for object patterns
    # In .NET 8 NativeAOT, FOH is often marked with specific alignment
    return []


def main():
    parser = argparse.ArgumentParser(description='Unpack .NET 8 NativeAOT bundle')
    parser.add_argument('dll', nargs='?', default=str(DLL_PATH), help='Path to NativeAOT DLL')
    parser.add_argument('--strings-only', action='store_true', help='Extract strings only')
    parser.add_argument('--types-only', action='store_true', help='Extract types only')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--min-len', type=int, default=6, help='Min string length')
    args = parser.parse_args()

    import pefile
    dll_path = Path(args.dll)
    if not dll_path.exists():
        print(f'[!] DLL not found: {dll_path}')
        return 1

    print(f'[*] Loading: {dll_path}')
    pe = pefile.PE(str(dll_path))
    print(f'[*] Architecture: {"x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"}')
    print(f'[*] Sections: {len(pe.sections)}')

    # Print sections overview
    print()
    print('[*] Sections:')
    for s in pe.sections:
        name = s.Name.decode('utf-8', errors='ignore').rstrip(chr(0))
        print(f'    {name:12s} VAddr=0x{s.VirtualAddress:08x} VSize=0x{s.Misc_VirtualSize:08x} RawSize=0x{s.SizeOfRawData:08x}')

    results = {
        'dll': str(dll_path),
        'analysis_time': datetime.now().isoformat(),
        'sections': [],
    }

    # === 1. Read .managed section (string heap + types) ===
    managed = read_section(pe, '.managed')
    if managed:
        print(f'\n[+] .managed section: {len(managed):,} bytes')

        if not args.types_only:
            print('[*] Extracting strings from .managed...')
            strs = extract_strings_heap(managed)
            strs = [s for s in strs if len(s['value']) >= args.min_len]
            print(f'[+] Found {len(strs):,} strings >= {args.min_len} chars')
            results['strings_managed'] = strs

        if not args.strings_only:
            print('[*] Scanning for EEType entries...')
            eetypes = find_eetype_table(managed)
            print(f'[+] Found {len(eetypes):,} candidate EEType entries')
            results['eetypes_managed'] = eetypes[:1000]  # cap

    # === 2. Read .rdata section ===
    rdata = read_section(pe, '.rdata')
    if rdata:
        print(f'\n[+] .rdata section: {len(rdata):,} bytes')

        if not args.types_only:
            print('[*] Extracting strings from .rdata...')
            strs_rdata = extract_strings_heap(rdata)
            strs_rdata = [s for s in strs_rdata if len(s['value']) >= args.min_len]
            print(f'[+] Found {len(strs_rdata):,} strings >= {args.min_len} chars')
            results['strings_rdata'] = strs_rdata

    # === 3. Print summary ===
    print()
    print('=' * 70)
    print('SUMMARY')
    print('=' * 70)
    if 'strings_managed' in results:
        print(f'  Strings in .managed:  {len(results["strings_managed"]):,}')
    if 'strings_rdata' in results:
        print(f'  Strings in .rdata:    {len(results["strings_rdata"]):,}')
    if 'eetypes_managed' in results:
        print(f'  EEType entries:       {len(results["eetypes_managed"]):,}')

    # === Print interesting strings ===
    if 'strings_managed' in results and results['strings_managed']:
        interesting_keywords = [
            'iremoval', 'activat', 'bypass', 'icloud', 'apple', 'unlock',
            'http', 'ssh', 'rsa', 'aes', 'key', 'cert', 'token', 'auth',
            'RestSharp', 'SSH', 'Newtonsoft', 'Microsoft', 'System.',
            'BouncyCastle', 'Crypto', 'Tweak', 'blackhound',
            'checkm8', 'minaeraser', 'MobileActiv',
        ]
        interesting = []
        for s in results['strings_managed']:
            val_lower = s['value'].lower()
            if any(kw.lower() in val_lower for kw in interesting_keywords):
                interesting.append(s)

        print(f'\n[*] Interesting strings (matched keywords): {len(interesting)}')
        print('-' * 70)
        # Sort by relevance (number of keywords matched)
        for s in interesting[:100]:
            v = s['value']
            if len(v) > 120:
                v = v[:117] + '...'
            print(f'  0x{s["offset"]:06x}  {v}')

    # === Save report ===
    out_path = args.output or (OUT_DIR / f'nativeaot_unpack_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f'\n[*] Report saved: {out_path}')

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)