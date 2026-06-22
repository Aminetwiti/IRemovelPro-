#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 4 - Decompile the WPF EXE (iRemovalProWPF.exe) via dnfile."""
import sys, json, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import dnfile

EXE = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iRemoval PRO.exe'
OUT = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis\phase4_exe_decompiled.json'

pe = dnfile.dnPE(EXE)
md = pe.net.metadata

# Resolve string from #Strings heap
strings_stream = None
us_stream = None
for s in md.streams_list:
    if s.struct.Name == b'#Strings':
        strings_stream = s
    elif s.struct.Name == b'#US':
        us_stream = s

def resolve_str(idx_or_obj):
    if strings_stream is None:
        return None
    if hasattr(idx_or_obj, 'value'):
        idx_or_obj = idx_or_obj.value
    if isinstance(idx_or_obj, int) and idx_or_obj > 0:
        try:
            return strings_stream.get(idx_or_obj)
        except Exception:
            return None
    return str(idx_or_obj) if idx_or_obj else None

mdt = pe.net.mdtables

print("="*80)
print("EXECUTABLE WPF .NET FRAMEWORK 4.x - DECOMPILATION (via dnfile)")
print("="*80)
print(f"Path: {EXE}")
print(f"PE Format: {'PE32+' if pe.OPTIONAL_HEADER.Magic == 0x20b else 'PE32 (x86)'}")
print(f"ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
print(f"EntryPoint RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")

# Resolve assembly name
asm_name = None
if mdt.Assembly:
    row = mdt.Assembly.rows[0]
    if row.Name:
        asm_name = resolve_str(row.Name)
        print(f"Assembly: {asm_name}")

if pe.net and pe.net.struct:
    clr = pe.net.struct
    print(f"\n[CLR Header]")
    print(f"  MajorRuntimeVersion: {clr.MajorRuntimeVersion}")
    print(f"  ResourcesRva: 0x{clr.ResourcesRva:x}")
    if pe.net.struct.EntryPointTokenOrRva:
        print(f"  EntryPointTokenOrRva: 0x{pe.net.struct.EntryPointTokenOrRva:x}")

print(f"\n[Metadata Tables - Row Counts]")
for tname in ['Module', 'TypeRef', 'TypeDef', 'Field', 'MethodDef', 'Param',
              'MemberRef', 'StandAloneSig', 'Assembly', 'AssemblyRef',
              'ManifestResource', 'MethodSpec']:
    t = getattr(mdt, tname, None)
    if t and hasattr(t, 'num_rows'):
        print(f"  {tname:18} {t.num_rows:5d} rows")

# TypeDef with resolved names
types_list = []
print(f"\n[TypeDef] - {mdt.TypeDef.num_rows} types")
for i, row in enumerate(mdt.TypeDef.rows, start=1):
    name = resolve_str(row.TypeName)
    ns = resolve_str(row.TypeNamespace)
    full_name = f"{ns}.{name}" if ns else (name or f"<{i}>")
    if isinstance(row.FieldList, list):
        field_n = len(row.FieldList)
    else:
        field_n = row.FieldList or 0
    if isinstance(row.MethodList, list):
        method_n = len(row.MethodList)
    else:
        method_n = row.MethodList or 0
    types_list.append((i, full_name, field_n, method_n))
    print(f"  [{i:3d}] {full_name:65s}  F={field_n:3d}  M={method_n:3d}")

# MethodDef with resolved names
methods_list = []
print(f"\n[MethodDef] - {mdt.MethodDef.num_rows} methods")
for i, row in enumerate(mdt.MethodDef.rows, start=1):
    name = resolve_str(row.Name)
    rva = row.Rva if row.Rva else 0
    flags = int(row.Flags) if row.Flags else 0
    attr_str = []
    if flags & 0x0010: attr_str.append("Public")
    if flags & 0x0020: attr_str.append("Static")
    if flags & 0x0080: attr_str.append("Virtual")
    if flags & 0x0200: attr_str.append("Abstract")
    if flags & 0x1000: attr_str.append("SpecialName")
    if flags & 0x2000: attr_str.append("RTSpecialName")
    if flags & 0x0001: attr_str.append("Private")
    if flags & 0x0004: attr_str.append("Assembly")
    if flags & 0x0006: attr_str.append("Family")
    methods_list.append((i, name, rva, flags))
    print(f"  [{i:4d}] 0x{rva:08x}  {name:55s}  {'|'.join(attr_str)}")

# ManifestResource
print(f"\n[ManifestResource]")
for i, row in enumerate(mdt.ManifestResource.rows, start=1):
    name = resolve_str(row.Name)
    offset = row.Offset if row.Offset else 0
    flags = int(row.Flags) if row.Flags else 0
    print(f"  [{i:3d}] {name:40s}  Offset=0x{offset:x}  Flags=0x{flags:x}")

# AssemblyRef
print(f"\n[AssemblyRef] - referenced assemblies")
for i, row in enumerate(mdt.AssemblyRef.rows, start=1):
    name = resolve_str(row.Name)
    ver = row.Version
    print(f"  [{i:3d}] {name}  v{ver.Major}.{ver.Minor}.{ver.Build}.{ver.Revision}")

# EntryPoint
if pe.net and pe.net.struct.EntryPointTokenOrRva:
    ep_token = pe.net.struct.EntryPointTokenOrRva
    print(f"\n[Entry Point]")
    print(f"  Token: 0x{ep_token:08x}")
    ep_idx = ep_token & 0xffffff
    if 1 <= ep_idx <= len(mdt.MethodDef.rows):
        ep_row = mdt.MethodDef.rows[ep_idx - 1]
        ep_name = resolve_str(ep_row.Name)
        print(f"  Method: {ep_name} @ RVA 0x{ep_row.Rva:x}")

# US heap
print(f"\n[US Heap - .NET string literals]")
if us_stream:
    count = 0
    try:
        for entry in us_stream:
            if entry and entry.value:
                v = entry.value
                if len(v) >= 3 and any(c.isalpha() for c in v):
                    print(f"  US[{count:3d}] {v!r}")
                    count += 1
                    if count >= 100:
                        break
    except Exception as e:
        print(f"  err: {e}")
    print(f"  Total: {count}")

# Save JSON
output = {
    "exe_path": EXE,
    "assembly": asm_name,
    "pe": {
        "format": "PE32" if pe.OPTIONAL_HEADER.Magic == 0x10b else "PE32+",
        "machine": pe.FILE_HEADER.Machine,
        "imagebase": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entrypoint_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
    },
    "types": [{"rid": r[0], "name": r[1], "fields": r[2], "methods": r[3]} for r in types_list],
    "methods": [{"rid": r[0], "name": r[1], "rva": hex(r[2]), "flags": r[3]} for r in methods_list],
}
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(output, f, ensure_ascii=False, indent=2)
print(f"\n[+] Saved to {OUT}")
print(f"    Types: {len(types_list)}, Methods: {len(methods_list)}")

print("\n" + "="*80)
print("DONE - Phase 4 WPF EXE decompiled")
print("="*80)
