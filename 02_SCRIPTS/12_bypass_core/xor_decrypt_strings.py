#!/usr/bin/env python3
"""
XOR-decrypt the encrypted region around iact8.php in iremovalpro.dll.
The strings in the URL table region are partially XOR-encrypted at rest.
"""
import re
import struct
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

print(f"[*] {DLL.name}: {len(data):,} bytes")

# We know:
# - iact8 URL is at offset 0xa6bc93 (UTF-16LE)
# - Surrounding cleartext URLs: albert.apple.com, payax0.php, auth3.php, etc.
# - The same .NET NativeAOT binary uses a small XOR key (likely 1-4 bytes)
# - URL strings are stored as UTF-16LE in .rdata

# Strategy: find cleartext UTF-16LE strings in the URL table region,
# then XOR adjacent bytes with 1-4 byte keys to find which produces readable text.

# Focus on region: 0xa69000 - 0xa70000
print(f"\n[*] Scanning URL table region 0xa69000-0xa70000...")
region_start = 0xa69000
region_end = 0xa70000
region = data[region_start:region_end]

# Find cleartext UTF-16LE strings in this region (for comparison)
print("\n[1] Cleartext UTF-16LE strings in region (for reference):")
cleartext_offsets = []
for m in re.finditer(rb'(?:[a-zA-Z0-9_/.:?=&-]\x00){6,}', region):
    s = m.group().decode('utf-16-le', errors='ignore')
    if len(s) >= 6 and not all(c in '.\x00' for c in s):
        cleartext_offsets.append((m.start() + region_start, s))
        if any(x in s.lower() for x in ['http', 'apple', 'iremoval', '.com', '.php', 'json']):
            print(f"  0x{m.start()+region_start:08x}: {s[:80]}")

# Now look for GARBLED UTF-16LE strings (non-ASCII in odd byte positions)
# This indicates XOR encryption: position 0 = char XOR 0, position 1 = 0, position 2 = char XOR 1...
print("\n[2] Garbled regions (potential XOR-encrypted UTF-16LE):")
garbled_regions = []
in_garbled = False
start_garbled = 0
for i in range(0, len(region) - 1, 2):
    # Check if this looks like UTF-16LE: even byte printable, odd byte is 0
    b0 = region[i]
    b1 = region[i+1] if i+1 < len(region) else 0
    if 0x20 <= b0 < 0x7f and b1 == 0:
        if in_garbled:
            in_garbled = False
            length = i - start_garbled
            if length > 20:  # Only save significant regions
                garbled_regions.append((start_garbled, i, region[start_garbled:i]))
    else:
        if not in_garbled:
            in_garbled = True
            start_garbled = i

print(f"  Found {len(garbled_regions)} garbled regions")

# For each garbled region, try XOR decryption with all single-byte keys
print("\n[3] Trying single-byte XOR decryption:")
for gr_start, gr_end, gr_data in garbled_regions[:30]:
    best_score = 0
    best_key = 0
    best_decoded = b''

    for key in range(1, 256):
        decoded = bytes(b ^ key for b in gr_data)
        # Count printable chars
        printable = sum(1 for b in decoded if 0x20 <= b < 0x7f or b == 0)
        # Count valid JSON-like chars
        json_chars = sum(1 for b in decoded if chr(b) in '"abcdefghijklmnopqrstuvwxyz0123456789_-:,')
        score = json_chars
        if score > best_score:
            best_score = score
            best_key = key
            best_decoded = decoded

    if best_score > len(gr_data) * 0.5:
        # Try to interpret as UTF-16LE
        try:
            utf16 = best_decoded.decode('utf-16-le', errors='ignore')
            if any(c.isalpha() for c in utf16):
                offset = gr_start + region_start
                print(f"  0x{offset:08x} key=0x{best_key:02x} score={best_score}/{len(gr_data)}:")
                # Print decoded bytes + utf-16
                print(f"    HEX: {best_decoded[:80].hex()}")
                print(f"    UTF16: {utf16[:100]}")
        except:
            pass

# Now try: maybe the encryption is applied to the WHOLE region with a single key
# Let's XOR the entire URL table region with byte 0x02 and see what happens
print("\n[4] Trying region-wide XOR keys:")
for key in [0x02, 0x03, 0x05, 0x10, 0x17, 0x1f, 0x20, 0x47, 0x55, 0x77, 0x99, 0xaa, 0xff]:
    test_region = bytes(b ^ key for b in region[:1024])
    # Find UTF-16 strings in test
    matches = list(re.finditer(rb'(?:[\x20-\x7e]\x00){6,}', test_region))
    if len(matches) >= 5:
        print(f"  Key 0x{key:02x}: {len(matches)} UTF-16 strings decoded")
        for m in matches[:3]:
            s = m.group().decode('utf-16-le', errors='ignore')
            print(f"    {s[:80]}")

# Look for a more localized pattern - maybe the encrypted region has its own structure
# Search for JSON-like patterns after XOR with each key
print("\n[5] Searching for JSON keys after XOR (keys: 0x01-0xff):")
json_pattern = re.compile(rb'"[a-z_][a-z0-9_]{2,30}"\s*[:=]', re.IGNORECASE)
for key in range(0, 256, 1):
    # Test on a chunk of the region
    test = bytes(b ^ key for b in region[:8192])
    matches = json_pattern.findall(test)
    if len(matches) >= 2:
        print(f"  Key 0x{key:02x}: found {len(matches)} JSON keys")
        for m in matches[:5]:
            print(f"    {m.decode('ascii', errors='ignore')[:80]}")