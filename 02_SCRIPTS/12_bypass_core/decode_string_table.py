#!/usr/bin/env python3
"""
Decode the .NET 8 NativeAOT string table structure around the URLs.
"""
import re
import struct
import zlib
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# Look at the URL table region
# We saw 9 URL entries in the table. The first one starts at 0xa6bb6d ("ro.com/iremovalActivation/auth3.php")
# Let me find the start of the table by searching for "s13.iremovalpro.com" or "iremo"
target = 's13.iremovalpro.com'.encode('utf-16-le')
idx = data.find(target)
while idx != -1:
    # Show 64 bytes before this URL to see the table header
    if idx > 0xa60000:  # Only in URL region
        ctx = data[max(0,idx-64):idx]
        print(f"\nURL at 0x{idx:x}:")
        print(f"  Before (64 bytes hex): {' '.join(f'{b:02x}' for b in ctx)}")
        # Decode it
        s_end = data.find(b'\x00\x00', idx)  # Find end of string
        url_bytes = data[idx:s_end+2]
        s = url_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
        s_safe = s.encode('ascii', errors='replace').decode('ascii')
        print(f"  URL: {s_safe}")
    idx = data.find(target, idx + 1)

# Now let's also look for ALL the strings in the table region
print("\n" + "="*80)
print("Complete string table at URL region:")
print("="*80)
region = data[0xa6b000:0xa6d000]
region_start = 0xa6b000

# Walk the string table, looking for UTF-16LE strings
i = 0
strings_found = []
while i < len(region) - 4:
    # Try as 4-byte length prefix + UTF-16LE
    length = struct.unpack_from('<I', region, i)[0]
    if 4 <= length <= 200:
        # Check if next length*2 bytes are printable UTF-16LE
        candidate = region[i+4:i+4+length*2]
        if len(candidate) == length * 2:
            try:
                s = candidate.decode('utf-16-le', errors='strict')
                if all(c.isprintable() or c in '\n\r\t' for c in s) and len(s) > 3:
                    strings_found.append((region_start + i, length, s))
                    i += 4 + length * 2
                    continue
            except:
                pass
    i += 1

print(f"Found {len(strings_found)} strings with 4-byte length prefix")
for offset, length, s in strings_found:
    print(f"  0x{offset:08x} (len={length}): {s[:120]}")