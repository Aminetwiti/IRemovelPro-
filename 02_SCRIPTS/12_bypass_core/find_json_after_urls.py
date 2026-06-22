#!/usr/bin/env python3
"""
Look at the area AFTER the URL table for the JSON body templates.
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# URL table ends after version33.txt
# Last URL was at 0xa6be62 = "s13.iremovalpro.com/version33.txt"
# Let me look at 0xa6c000+ region (after URLs)

# Find the END of version33.txt URL
target = 'version33.txt'.encode('utf-16-le')
idx = data.find(target)
end = idx + len(target)
print(f"[*] version33.txt URL ends at: 0x{end:x}")

# Show 512 bytes after
print(f"\n[*] 512 bytes after URL table:")
ctx = data[end:end+1024]
for i in range(0, 512, 16):
    chunk = ctx[i:i+16]
    offset = end + i
    hex_part = ' '.join(f'{b:02x}' for b in chunk)
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  0x{offset:08x}: {hex_part:<48} {ascii_part}")

# Look for JSON-like content in 0xa6c000-0xa6f000
print(f"\n\n=== Searching 0xa6c000-0xa6f000 for JSON content ===")
region = data[0xa6c000:0xa6f000]
# JSON patterns
for m in re.finditer(rb'"[a-zA-Z_][a-zA-Z0-9_]{1,30}"\s*:', region):
    offset = m.start() + 0xa6c000
    s = m.group().decode('ascii', errors='ignore')
    print(f"  0x{offset:08x}: {s}")

# Also search for JSON in UTF-16LE
print(f"\n=== UTF-16LE JSON-like patterns in 0xa6c000-0xa6f000 ===")
for m in re.finditer(rb'(?:"\x00[a-zA-Z_][a-zA-Z0-9_]{1,30}\x00"\x00\s*\x00:\x00)', region):
    offset = m.start() + 0xa6c000
    s = m.group().decode('utf-16-le', errors='ignore')
    print(f"  0x{offset:08x}: {s}")

# Look for the URL path patterns that include parameters
# E.g. "s13.iremovalpro.com/iremovalActivation/iact8.php?..."
print(f"\n=== Looking for URL with parameters ===")
for pat in [b'iact8.php?', b'iact8?', b'auth3?', b'.php?', b'?udid=',
            b'udid=', b'?serial=', b'?key=']:
    cnt = data.count(pat)
    if cnt > 0:
        idx = data.find(pat)
        print(f"  {pat}: {cnt} (first at 0x{idx:x})")

# Also look for HTTP-style parameter building blocks
print(f"\n=== Looking for parameter format strings ===")
for pat in [b'&{0}={1}', b'?{0}={1}', b'&%s=%s', b'?%s=%s',
            b'&{0}=', b'?{0}=', b'&%s=', b'?%s=',
            b'{0}={1}&{2}={3}']:
    pat_u = pat.decode('ascii').encode('utf-16-le')
    cnt = data.count(pat_u)
    if cnt > 0:
        print(f"  {pat}: {cnt}")

# Look for typical JSON body format
print(f"\n=== Looking for JSON body format strings (UTF-16LE) ===")
for pat in ['"{{', '{{', '}}', '":\\"', '"{0}"', '"{0}":', '"{0}":{{',
            '"{0}":"{1}"', '"{0}":{{\\"{1}\\":{{\\"{2}\\":',
            '\\"{0}\\": \\"{1}\\"', ',"{0}":', ',"{0}":"{1}"',
            '{\\"{0}\\":', '}}}"']:
    pat_u = pat.encode('utf-16-le')
    cnt = data.count(pat_u)
    if cnt > 0:
        idx = data.find(pat_u)
        print(f"  {pat}: {cnt} (first at 0x{idx:x})")

# Check iRemoval-specific strings near the URL
print(f"\n=== iRemoval-specific strings (UTF-16LE) ===")
for s in ['iRemoval', 'iActivator', 'iRecord', 'iSig', 'IACT8', 'iAct8',
          'iDeviceProx', 'mobileactivationd', 'MobileActivation',
          'com.iremovalpro', 'com.blackhound', 'iremovalActivation',
          'Tiremovalpro', 'payload_', 'request_body', 'request_',
          'activation_request', 'activation_ticket', 'tickets_',
          'iRemovalRecord', 'iRemovalSignature', 'irec',
          'server_response', 'api_response', 'api_key', 'api_secret',
          'HMAC-SHA256', 'X-Authorization', 'X-Api-Key', 'X-Token',
          'X-Session', 'X-Nonce', 'X-Signature']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        print(f"  {s}: {cnt} (first at 0x{idx:x})")