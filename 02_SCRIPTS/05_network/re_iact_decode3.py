#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Decode iact8.php context: nearby strings in the URL table (UTF-16LE).
Finds JSON request keys used by the iRemoval PRO client to call iact8.php.
"""
import sys, io, re

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'IRemovalPro\iremovalpro.dll'
with open(DLL, 'rb') as f:
    data = f.read()

# Find iact8.php as UTF-16LE - search for the bare string 'iact8.php' encoded
# In the wide table it appears as "iact8.php\x00\x00" preceded by base URL
# Easier: find the unique substring "iremovalActivation/iact8" in UTF-16LE
needle = 'iremovalActivation/iact8'.encode('utf-16-le')
pos = data.find(needle)
if pos < 0:
    # fallback: ASCII
    pos = data.find(b'iact8.php')
    print(f'[*] iact8.php ASCII at offset: 0x{pos:x}')
else:
    # Adjust to point at start of "iact8.php" wide
    wide_iact = 'iact8.php'.encode('utf-16-le')
    pos = pos + (len('iremovalActivation/'.encode('utf-16-le')))
    print(f'[*] iact8.php (UTF-16LE) at offset: 0x{pos:x}')

# Look at the URL table region - 2KB before and after
start = max(0, pos - 2048)
end = min(len(data), pos + 2048)
window = data[start:end]

# Extract UTF-16LE null-terminated strings
def extract_wide_strings(buf):
    out = []
    s = bytearray()
    i = 0
    while i < len(buf) - 1:
        if buf[i] == 0 and buf[i+1] == 0:
            if s:
                out.append(bytes(s).decode('utf-16-le', errors='replace'))
                s = bytearray()
        else:
            s.extend(buf[i:i+2])
        i += 2
    if s:
        out.append(bytes(s).decode('utf-16-le', errors='replace'))
    return out

wide_strs = extract_wide_strings(window)
print(f'[*] Wide strings in window: {len(wide_strs)}')

# Also ASCII strings
ascii_strs = re.findall(rb'[\x20-\x7e]{6,}', window)
ascii_strs = [s.decode('ascii', errors='replace') for s in ascii_strs]

print()
print('=' * 80)
print('UTF-16LE STRINGS NEAR iact8.php')
print('=' * 80)
for s in wide_strs:
    if s.strip() and len(s) > 2:
        print(f'  {s}')

print()
print('=' * 80)
print('ASCII STRINGS NEAR iact8.php (filtered to keywords)')
print('=' * 80)
keywords = ['UDID', 'ECID', 'IMEI', 'Serial', 'Model', 'ChipID', 'BoardID',
            'ProductType', 'ProductVersion', 'BuildVersion', 'nonce',
            'signature', 'token', 'order', 'activation', 'ticket',
            'account', 'apple', 'cert', 'BUID', 'PROG', 'UID', 'AK',
            'GIDKey', 'DKey', 'RequestActivation', 'iPhone', 'iPad',
            'api', 'key', 'salt', 'request', 'response',
            'result', 'status', 'error', 'BES', 'BBI', 'BLS',
            'fair', 'play', 'drm', 'guid', 'uuid',
            'device', 'action', 'version', 'hwid', 'HWID',
            'fairplay', 'FairPlay', 'bypass', 'Bypass',
            'Hash', 'blob', 'Blob', 'data', 'Data', 'xml', 'plist',
            'X-iRemoval', 'iRemoval']
seen = set()
for s in ascii_strs:
    for k in keywords:
        if k in s and s not in seen:
            seen.add(s)
            print(f'  {s[:120]}')
            break

# Now look at JSON-like structures or field names in nearby memory
print()
print('=' * 80)
print('NEARBY 8-KB WINDOW: HUNTING JSON KEYS')
print('=' * 80)
start = max(0, pos - 8192)
end = min(len(data), pos + 4096)
window = data[start:end]
# Look for typical JSON keys: "key":"value"
# JSON keys often use snake_case or camelCase
json_pattern = rb'"[a-zA-Z_][a-zA-Z0-9_]{2,30}"\s*[:=]'
json_matches = re.findall(json_pattern, window)
print(f'[*] JSON-like keys in 12KB window: {len(set(json_matches))}')
seen = set()
for m in json_matches[:200]:
    s = m.decode('ascii', errors='replace')
    if s not in seen:
        seen.add(s)
        print(f'  {s}')

print()
print('=' * 80)
print('PROBE RESULT FOR iact8 (from server_probe)')
print('=' * 80)
print('''  POST  https://s13.iremovalpro.com/iremovalActivation/iact8.php
  Status: 200 OK
  Server: 5.252.32.98
  Content-Encoding: gzip
  Content-Type: text/html; charset=UTF-8
  Transfer-Encoding: chunked
  Cache-Control: no-cache, must-revalidate

  Response body (base64): koY+rla/7ol+LX8kepekEw==
  Response body (text) : 24 bytes (decoded = 16 random bytes, likely AES key/IV)
  Latency: ~500ms
  Same response for: empty / udid_only / device_full payload
''')
