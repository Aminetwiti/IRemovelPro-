#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Decode iact8.php request format + extract nearby JSON keys."""
import sys, struct, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
with open(DLL, 'rb') as f:
    data = f.read()

# Find all server URLs and read context around them
urls = [
    b'https://s13.iremovalpro.com/version33.txt',
    b'https://s13.iremovalpro.com/pub.php',
    b'https://s13.iremovalpro.com/iremovalActivation/auth3.php',
    b'https://s13.iremovalpro.com/iremovalActivation/checkm8.php',
    b'https://s13.iremovalpro.com/iremovalActivation/iact8.php',
    b'https://s13.iremovalpro.com/iremovalActivation/ars2.php',
    b'https://s13.iremovalpro.com/iremovalActivation/mf5.php',
    b'https://s13.iremovalpro.com/iremovalActivation/mf6.php',
    b'https://s13.iremovalpro.com/iremovalActivation/mf7.php',
    b'https://iremovalpro.com/Payax0.php',
]

print("="*80)
print("[1] SERVER URL CONTEXT (chars before/after)")
print("="*80)
for url in urls:
    pos = data.find(url)
    if pos < 0: continue
    print(f"\n--- {url.decode()} @ 0x{pos:x} ---")
    # 300 bytes before + 300 after
    start = max(0, pos - 300)
    end = min(len(data), pos + len(url) + 300)
    ctx = data[start:end]
    # Print as ASCII with non-printable as '.'
    for off in range(0, len(ctx), 80):
        chunk = ctx[off:off+80]
        hexpart = ' '.join(f'{b:02x}' for b in chunk[:20])
        ascpart = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        rel_pos = start + off
        marker = '  <<<' if url in chunk else '     '
        print(f"  {rel_pos:08x}{marker} {ascpart}")

# Look at strings in the same context that might be JSON keys
print("\n" + "="*80)
print("[2] ALL STRINGS NEAR iact8.php (filtered)")
print("="*80)
iact_pos = data.find(b'iact8.php')
if iact_pos > 0:
    # Look at 4KB window around it
    start = max(0, iact_pos - 4096)
    end = min(len(data), iact_pos + len(b'iact8.php') + 4096)
    window = data[start:end]
    # Extract ASCII strings (>= 4 chars)
    import re
    strings = re.findall(rb'[\x20-\x7e]{4,}', window)
    # Filter to interesting ones (likely JSON keys)
    keywords = [b'UDID', b'ECID', b'IMEI', b'Serial', b'Model', b'ChipID', b'BoardID',
                b'ProductType', b'ProductVersion', b'BuildVersion', b'nonce', b'sig',
                b'signature', b'hash', b'token', b'Token', b'order', b'Order',
                b'activation', b'Activation', b'ticket', b'Ticket', b'account',
                b'Account', b'apple', b'Apple', b'cert', b'Cert', b'pass',
                b'Pass', b'lock', b'Lock', b'fair', b'Fair', b'attest',
                b'BUID', b'PROG', b'UID', b'AK', b'GIDKey', b'DKey',
                b'RequestActivation', b'iPhone', b'iPad', b'iOS',
                b'API', b'api', b'key', b'Key', b'salt', b'Salt',
                b'request', b'Request', b'response', b'Response',
                b'result', b'Result', b'status', b'Status', b'error', b'Error',
                b'BES', b'BBI', b'BLS', b'BB', b'fair', b'play', b'drm', b'DRM',
                b'guid', b'GUID', b'uuid', b'UUID', b'device', b'Device',
                b'action', b'Action', b'version', b'Version', b'api_version',
                b'server', b'Server', b'client', b'Client', b'hwid', b'HWID',
                b'os_version', b'iOS_version', b'ios_version',
                b'firmware', b'Firmware', b'kernel', b'Kernel',
                b'baseband', b'Baseband', b'restore', b'Restore']
    seen = set()
    for s in strings:
        for k in keywords:
            if k in s and s not in seen:
                seen.add(s)
                print(f"  {s.decode('latin1', 'replace')[:100]}")
                break