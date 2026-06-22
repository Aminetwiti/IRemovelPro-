#!/usr/bin/env python3
"""
Find and decode all JSON template strings in the .NET DLL.
Pattern: "{0}": or "{{...}}"
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# 1. Find all "{0}": templates
print("="*80)
print('STRINGS WITH "{0}":  (JSON templates with placeholders)')
print("="*80)
pat = '"{0}":'.encode('utf-16-le')
idx = 0
count = 0
while True:
    idx = data.find(pat, idx)
    if idx == -1:
        break
    # Find the start of the surrounding string
    # Go back until we hit a non-printable byte or start
    start = idx
    # Look back 200 bytes for context
    ctx_start = max(0, idx - 200)
    ctx_end = min(len(data), idx + 300)
    ctx = data[ctx_start:ctx_end]

    # Try to find the start of the string by going back until we hit
    # a non-UTF16LE-printable or the start
    # UTF-16LE: 0x00 is every other byte
    # Find a position where bytes are: [printable, 0x00, printable, 0x00, ...]
    s = idx
    while s > 0 and data[s-1] == 0x00 and s-2 >= 0 and 0x20 <= data[s-2] < 0x7f:
        s -= 2
    if s < ctx_start:
        s = ctx_start
    # Now find the END of the string
    e = idx + len(pat)
    while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
        e += 2
    if e > ctx_end:
        e = ctx_end
    s_full = data[s:e].decode('utf-16-le', errors='ignore')
    if len(s_full) > 2 and len(s_full) < 200:
        count += 1
        # Find the actual start of the full string
        print(f"  0x{idx:08x} (start=0x{s:x}): {s_full[:200]}")
    idx += len(pat)
print(f"\nFound {count} '{chr(34)}{0}{chr(34)}:' patterns\n")

# 2. Find all "{{" patterns (these are literal "{" in String.Format)
print("="*80)
print('STRINGS WITH "{{"  (escaped JSON braces in templates)')
print("="*80)
pat = '{{'.encode('utf-16-le')
idx = 0
count = 0
seen_strings = set()
while True:
    idx = data.find(pat, idx)
    if idx == -1:
        break
    # Find the start of the string
    s = idx
    while s > 0 and data[s-1] == 0x00 and s-2 >= 0 and 0x20 <= data[s-2] < 0x7f:
        s -= 2
    e = idx + len(pat)
    while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
        e += 2
    s_full = data[s:e].decode('utf-16-le', errors='ignore')
    if s_full and s_full not in seen_strings and len(s_full) > 2 and len(s_full) < 300:
        seen_strings.add(s_full)
        count += 1
        print(f"  0x{idx:08x}: {s_full[:200]}")
    idx += len(pat)
print(f"\nFound {count} unique strings with {chr(123)}{chr(123)}\n")

# 3. Find all "irec" contexts
print("="*80)
print('STRINGS WITH "irec"  (iRemovalRecord references)')
print("="*80)
pat = 'irec'.encode('utf-16-le')
idx = 0
seen = set()
while True:
    idx = data.find(pat, idx)
    if idx == -1:
        break
    s = idx
    while s > 0 and data[s-1] == 0x00 and s-2 >= 0 and 0x20 <= data[s-2] < 0x7f:
        s -= 2
    e = idx + len(pat)
    while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
        e += 2
    s_full = data[s:e].decode('utf-16-le', errors='ignore')
    if s_full and s_full not in seen and len(s_full) > 2 and len(s_full) < 200:
        seen.add(s_full)
        print(f"  0x{idx:08x}: {s_full[:200]}")
    idx += len(pat)
print(f"\nFound {len(seen)} unique strings with 'irec'")