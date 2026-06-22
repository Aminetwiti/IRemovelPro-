#!/usr/bin/env python3
"""
Extract the activation ticket / key material strings from the BlackHound dylib.
Also dump string contexts around __logos_method$ and iRemovalRecord/iRemovalSignature.
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
EXTR = WORK / "04_EXTRACTED"

# Analyze both dylibs (ARM64 + ARM64E)
for fname in ["macho_8534d3_DYLIB_ARM64_ALL.bin", "macho_86b4d3_DYLIB_ARM64_ARM64E.bin"]:
    target = EXTR / fname
    data = target.read_bytes()
    print(f"\n{'='*80}")
    print(f"  {fname} ({len(data)/1024:.1f} KB)")
    print('='*80)

    # 1. iRemovalRecord / iRemovalSignature context
    for marker in [b'iRemovalRecord', b'iRemovalSignature', b'irecords', b'isignature',
                   b'BLACKHOUND', b'Blackhound', b'panyolsoft',
                   b'__logos_method$', b'__logos_orig$',
                   b'AppleCA', b'apple.com', b'activation']:
        idx = 0
        while True:
            idx = data.find(marker, idx)
            if idx == -1:
                break
            # Extract printable context
            start = max(0, idx - 30)
            end = min(len(data), idx + len(marker) + 100)
            ctx = data[start:end]
            # Replace non-printable
            ctx_clean = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
            print(f"\n  [offset 0x{idx:08x}] {marker.decode()}:")
            print(f"    CTX: {ctx_clean}")
            idx += 1
            if idx > len(data) - 1:
                break