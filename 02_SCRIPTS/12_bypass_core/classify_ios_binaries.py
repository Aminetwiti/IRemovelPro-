#!/usr/bin/env python3
"""
Classify all 5 extracted Mach-O binaries by their primary purpose.

Strategy: extract representative strings from each, look for distinctive
markers (tweak bundle, daemon name, exploit name).
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
EXTR = WORK / "04_EXTRACTED"

bins = [
    ("macho_8534d3_DYLIB_ARM64_ALL.bin",         "dylib",      "ARM64"),
    ("macho_86b4d3_DYLIB_ARM64_ARM64E.bin",      "dylib",      "ARM64E"),
    ("macho_8812f8_EXECUTE_ARM64_ALL.bin",       "executable", "ARM64"),
    ("macho_8a3dcd_EXECUTE_ARM64_ALL.bin",       "executable", "ARM64"),
    ("macho_8ea1a8_EXECUTE_ARM64_ALL.bin",       "executable", "ARM64"),
]

# Markers that identify each binary's role
markers = {
    "tweak_blackhound": [b"blackhound", b"panyolsoft", b"logos_method", b"logos_orig", b"hook"],
    "minaeraser":       [b"minaeraser", b"eraser", b"NAND", b"norwrite"],
    "A12Eraser":        [b"A12", b"A12Eraser", b"a12eraser"],
    "checkm8":          [b"checkm8", b"check_ra1n", b"gaster", b"DFU", b"SecureROM"],
    "activation_bypass":[b"mobileactivationd", b"MobileActivation", b"albert.apple.com", b"drmHandshake", b"iActivation"],
    "ideviceprox":      [b"ideviceprox", b"idevice_id", b"idevicebackup2", b"usbmuxd", b"lockdown"],
    "iRemovalPro":      [b"iRemovalPro", b"iRemoval", b"iremovalpro"],
    "iboot":            [b"iBoot", b"iBEC", b"iBSS", b"LLB", b"AOP"],
}

print(f"{'BIN':<45} {'SIZE':<10} {'TYPE':<10} {'ARCH':<8}")
print("=" * 85)
for name, kind, arch in bins:
    p = EXTR / name
    if not p.exists():
        continue
    sz = p.stat().st_size
    print(f"{name:<45} {sz/1024:>7.1f} KB  {kind:<10} {arch:<8}")

print()
print("=" * 85)
print("BINARY ROLE IDENTIFICATION")
print("=" * 85)

for name, kind, arch in bins:
    p = EXTR / name
    if not p.exists():
        continue
    data = p.read_bytes()
    print(f"\n### {name} ({len(data)/1024:.1f} KB) ###")

    # Extract strings
    strings = re.findall(rb'[\x20-\x7e]{8,}', data)
    total = len(strings)

    # Test markers
    found_markers = {}
    for role, kws in markers.items():
        matches = []
        for s in strings:
            try:
                ss = s.decode('ascii', errors='ignore').lower()
            except:
                continue
            for kw in kws:
                kw_s = kw.decode('ascii', errors='ignore')
                if kw_s.lower() in ss:
                    matches.append(s.decode('ascii', errors='ignore')[:120])
                    break
        if matches:
            found_markers[role] = matches

    if not found_markers:
        print(f"  ⚠ NO MARKERS FOUND (raw strings: {total})")
        continue

    for role, hits in found_markers.items():
        # dedup
        uniq = list(dict.fromkeys(hits))[:5]
        print(f"  [{role}] {len(hits)} hits")
        for h in uniq:
            print(f"    {h[:130]}")