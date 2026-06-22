#!/usr/bin/env python3
"""
Look at the EXACT bytes around the iact8 URL in the .NET DLL.
Map out the string table structure.
"""
import re
import struct
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# iact8 URL is at offset 0xa6bc93 (UTF-16LE)
target = 'iremovalActivation/iact8'.encode('utf-16-le')
idx = data.find(target)
print(f"[*] iact8 URL at offset: 0x{idx:x}")
print(f"    URL ends at: 0x{idx + len(target):x}")

# Show 256 bytes BEFORE and AFTER the URL
ctx_size = 512
start = max(0, idx - ctx_size)
end = min(len(data), idx + ctx_size + 200)
ctx = data[start:end]

print(f"\n[*] Context: 0x{start:x} - 0x{end:x} ({end-start} bytes)")
print(f"    iact8 URL is at offset 0x{ctx_size:x} in this slice")

# Hex dump
print("\n=== HEX DUMP (256-byte window centered on iact8 URL) ===")
iact8_offset_in_ctx = idx - start
win_start = max(0, iact8_offset_in_ctx - 256)
win_end = min(len(ctx), iact8_offset_in_ctx + 256)
window = ctx[win_start:win_end]
for i in range(0, len(window), 16):
    chunk = window[i:i+16]
    offset = start + win_start + i
    hex_part = ' '.join(f'{b:02x}' for b in chunk)
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  0x{offset:08x}: {hex_part:<48} {ascii_part}")

# Now look for STRING HEAP structure (.NET 8 NativeAOT)
# The string heap contains UTF-16LE strings with a length prefix
# Let's look for a 4-byte length (typical .NET format) followed by UTF-16LE text
print("\n\n[*] Searching for .NET string heap entries (4-byte length + UTF-16LE)...")

# Pattern: 4-byte little-endian length, then that many UTF-16LE chars
for test_offset in [idx-512, idx-256, idx, idx+256, idx+512]:
    if test_offset < 4:
        continue
    if test_offset > len(data) - 100:
        continue
    length = struct.unpack_from('<I', data, test_offset)[0]
    if 8 <= length <= 200:
        # Try to decode length*2 bytes of UTF-16LE
        str_start = test_offset + 4
        str_end = str_start + length * 2
        if str_end > len(data):
            continue
        try:
            s = data[str_start:str_end].decode('utf-16-le', errors='strict')
            # Check if it's printable
            printable = sum(1 for c in s if c.isprintable())
            if printable > length * 0.7:
                print(f"  0x{test_offset:08x}: length={length} str={s[:100]}")
        except:
            pass

# Also look for "compressed" length (1-4 bytes with 7-bit encoding)
print("\n[*] Looking for printable strings in the iact8 vicinity...")
# Find all printable UTF-16LE strings of length >= 4 in the 4KB window around iact8
big_ctx = data[max(0, idx-4096):min(len(data), idx+4096)]
big_ctx_start = max(0, idx-4096)
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', big_ctx):
    s = m.group().decode('utf-16-le', errors='ignore')
    offset = m.start() + big_ctx_start
    if 4 < len(s) < 200:
        # Check if it's not just URL/header (which we know)
        if not any(x in s.lower() for x in ['http', '://', '.com', '.php', 'w3.org', 'apple.com', 'microsoft.com']):
            print(f"  0x{offset:08x}: {s}")