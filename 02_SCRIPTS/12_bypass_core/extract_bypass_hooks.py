#!/usr/bin/env python3
"""
Extract ALL hook methods and symbols from the BlackHound dylib.
This reveals what code was added by the bypass.
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
EXTR = WORK / "04_EXTRACTED"
OUT  = WORK / "03_OUTPUTS" / "bypass_dylib_symbols.txt"
OUT.parent.mkdir(parents=True, exist_ok=True)

# Both dylibs are basically the same (ARM64 vs ARM64E)
target = EXTR / "macho_8534d3_DYLIB_ARM64_ALL.bin"
data = target.read_bytes()

print(f"[*] Analyzing {target.name} ({len(data)/1024:.1f} KB)")
print()

# Extract ALL strings >= 4 chars (to catch symbol names)
strings = re.findall(rb'[\x20-\x7e]{4,}', data)
strings = [s.decode('ascii', errors='ignore') for s in strings]
print(f"[+] Total strings: {len(strings)}")

# 1. Find ALL logos_method and logos_orig (Theos hooks)
print("\n" + "=" * 80)
print("THEOS LOGOS HOOKS (MobileSubstrate / Logos)")
print("=" * 80)

logos_method = sorted(set(s for s in strings if s.startswith('__logos_method$')))
logos_orig   = sorted(set(s for s in strings if s.startswith('__logos_orig$')))
logos_orig_default = sorted(set(s for s in strings if s.startswith('__logos_orig_default$')))

print(f"\n[logos_method] ({len(logos_method)} - the hooks/replacements):")
for s in logos_method:
    # Clean up: remove the $ separators
    clean = s.replace('__logos_method$_ungrouped$', '')
    clean = clean.replace('$', ' / ')
    print(f"  HOOK: {clean}")

print(f"\n[logos_orig] ({len(logos_orig)} - the originals preserved):")
for s in logos_orig:
    clean = s.replace('__logos_orig$_ungrouped$', '')
    clean = clean.replace('$', ' / ')
    print(f"  ORIG: {clean}")

print(f"\n[logos_orig_default] ({len(logos_orig_default)}):")
for s in logos_orig_default:
    print(f"  {s}")

# 2. ObjC classes used
print("\n" + "=" * 80)
print("OBJC CLASS METHODS (Objective-C runtime symbols)")
print("=" * 80)

# Pattern: "-[ClassName method:" or "+[ClassName method:"
objc_methods = []
for s in strings:
    if re.match(r'^[-+]\[[A-Z][A-Za-z0-9_]+', s):
        objc_methods.append(s)

# Group by class
classes = {}
for m in objc_methods:
    m_m = re.match(r'^[-+]\[([A-Z][A-Za-z0-9_]+)', m)
    if m_m:
        cls = m_m.group(1)
        classes.setdefault(cls, []).append(m)

print(f"\n{len(objc_methods)} ObjC method calls across {len(classes)} classes")
# Show interesting classes (Apple/ApplePrivate + custom)
INTERESTING = ['Mobile', 'Apple', 'Secure', 'Cert', 'Key', 'Activation', 'Lockdown',
               'iRemoval', 'Blackhound', 'Http', 'NSURL', 'NSData', 'NSDictionary']
for cls in sorted(classes.keys()):
    is_int = any(t.lower() in cls.lower() for t in INTERESTING)
    if is_int or len(classes[cls]) >= 3:
        print(f"\n  [{cls}] {len(classes[cls])} methods")
        for m in sorted(set(classes[cls]))[:15]:
            print(f"    {m[:130]}")
        if len(set(classes[cls])) > 15:
            print(f"    ... +{len(set(classes[cls]))-15} more")

# 3. Substrate internal symbols
print("\n" + "=" * 80)
print("CYDIASUBSTRATE / SUBSTRATE INTERNAL HOOK SYMBOLS")
print("=" * 80)
for s in strings:
    if any(x in s for x in ['MSHook', '_MS', 'Substrate', 'MobileSubstrate']):
        print(f"  {s}")

# 4. Save full symbol table
print(f"\n[*] Saving full symbol dump to {OUT}")
with open(OUT, 'w', encoding='utf-8') as f:
    f.write(f"# Symbols from {target.name}\n")
    f.write(f"# Size: {len(data):,} bytes\n\n")
    f.write("=" * 80 + "\n")
    f.write("THEOS LOGOS HOOKS\n")
    f.write("=" * 80 + "\n\n")
    f.write(f"[logos_method] ({len(logos_method)} hooks/replacements):\n")
    for s in logos_method:
        f.write(f"  {s}\n")
    f.write(f"\n[logos_orig] ({len(logos_orig)} originals):\n")
    for s in logos_orig:
        f.write(f"  {s}\n")
    f.write("\n" + "=" * 80 + "\n")
    f.write("OBJC CLASSES\n")
    f.write("=" * 80 + "\n")
    for cls in sorted(classes.keys()):
        f.write(f"\n[{cls}]\n")
        for m in sorted(set(classes[cls])):
            f.write(f"  {m}\n")

print(f"[+] Done")