#!/usr/bin/env python3
"""
Map the data structure before the URL table.
The 0xa69000-0xa6a000 region contains garbled data that needs decryption.
"""
import re
import struct
import zlib
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# Look at the region before the URL table (0xa69000 - 0xa6bade)
print("="*80)
print("REGION 0xa69000 - 0xa6a000 (BEFORE URL table)")
print("="*80)
region = data[0xa69000:0xa6a000]
region_start = 0xa69000

# Hex dump first 512 bytes
print("\n=== HEX DUMP (first 512 bytes) ===")
for i in range(0, 512, 16):
    chunk = region[i:i+16]
    offset = region_start + i
    hex_part = ' '.join(f'{b:02x}' for b in chunk)
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  0x{offset:08x}: {hex_part:<48} {ascii_part}")

# Find all UTF-16LE strings of length >= 4 in this region
print("\n=== UTF-16LE STRINGS (length >= 4) ===")
strings = []
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', region):
    s = m.group().decode('utf-16-le', errors='ignore')
    if len(s) >= 4 and len(s) < 200:
        offset = m.start() + region_start
        strings.append((offset, s))

print(f"Found {len(strings)} strings")
for offset, s in strings[:30]:
    print(f"  0x{offset:08x}: {s[:100]}")

# Look for the JSON key markers
# JSON key: "key": value or "key":value
print("\n=== JSON-LIKE PATTERNS in 0xa69000-0xa6b000 ===")
big_region = data[0xa69000:0xa6b000]
for m in re.finditer(rb'"[a-zA-Z_][a-zA-Z0-9_]{2,40}"', big_region):
    offset = m.start() + 0xa69000
    s = m.group().decode('ascii', errors='ignore')
    print(f"  0x{offset:08x}: {s}")

# Look for the structure markers 0xE823
print("\n=== 0xE823 markers (entry separators?) ===")
for m in re.finditer(b'\\xe8\\x23', big_region):
    offset = m.start() + 0xa69000
    # Context
    ctx = big_region[max(0,m.start()-32):m.start()+32]
    print(f"  0x{offset:08x}: {' '.join(f'{b:02x}' for b in ctx)}")

# Also look for 23 e8 (LE form)
print("\n=== 23 e8 markers ===")
for m in re.finditer(b'\\x23\\xe8', big_region):
    offset = m.start() + 0xa69000
    ctx = big_region[max(0,m.start()-32):m.start()+32]
    print(f"  0x{offset:08x}: {' '.join(f'{b:02x}' for b in ctx)}")