#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Decode UTF-16LE URL storage + nearby JSON keys for iact8.php request."""
import sys, struct, re, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
with open(DLL, 'rb') as f:
    data = f.read()

# UTF-16LE URLs found at 0xa6bade+
urls_wide = {
    'Payax0':     'Payax0.php',
    'iact8':      'iact8.php',
    'ars2':       'ars2.php',
    'auth3':      'auth3.php',
    'checkm8':    'checkm8.php',
    'mf5':        'mf5.php',
    'mf6':        'mf6.php',
    'mf7':        'mf7.php',
    'pub':        'pub.php',
    'version33':  'version33.txt',
    'albert':     'albert.apple.com/deviceservices/drmHandshak',
    'trustpilot': 'trustpilot.com/review/iremovalpro.co',
    't.me':       't.me/',
}

print("="*80)
print("[1] URL TABLE STRUCTURE (UTF-16LE)")
print("="*80)
positions = []
for label, url in urls_wide.items():
    wide = url.encode('utf-16-le')
    pos = data.find(wide)
    if pos < 0: continue
    positions.append((label, url, pos))
positions.sort(key=lambda x: x[2])

# For each pair of consecutive URLs, decode the region between them
prev_end = 0
for i, (label, url, pos) in enumerate(positions):
    print(f"\n[{label}] '{url}' @ 0x{pos:x}")
    # Decode as UTF-16LE only the part that's the URL + 200 chars after
    end_url = pos + len(url) * 2
    # Get next 400 bytes and decode as utf-16-le, truncating at null pairs
    after_bytes = data[end_url:end_url + 400]
    # Try to decode as sequence of null-terminated wide strings
    strs = []
    s = bytearray()
    for j in range(0, len(after_bytes)-1, 2):
        if after_bytes[j] == 0 and after_bytes[j+1] == 0:
            if s:
                strs.append(bytes(s).decode('utf-16-le', errors='replace'))
                s = bytearray()
        else:
            s.extend(after_bytes[j:j+2])
    print(f"  Following strings ({len(strs)}):")
    for s in strs[:6]:
        if s.strip():
            print(f"    -> {s!r}")
    # Also decode before URL
    if i > 0:
        prev_label, prev_url, prev_pos = positions[i-1]
        prev_end = prev_pos + len(prev_url) * 2
    before_bytes = data[max(0, pos - 400):pos]
    strs = []
    s = bytearray()
    for j in range(0, len(before_bytes)-1, 2):
        if before_bytes[j] == 0 and before_bytes[j+1] == 0:
            if s:
                strs.append(bytes(s).decode('utf-16-le', errors='replace'))
                s = bytearray()
        else:
            s.extend(before_bytes[j:j+2])
    print(f"  Preceding strings ({len(strs)}):")
    for s in strs[-6:]:
        if s.strip():
            print(f"    -> {s!r}")

# ==== Find JSON keys near iact8 ====
print("\n" + "="*80)
print("[2] JSON KEYS NEAR iact8.php (UTF-16LE)")
print("="*80)
iact_url = 'iact8.php'
iact_pos = data.find(iact_url.encode('utf-16-le'))
print(f"iact8.php UTF-16 @ 0x{iact_pos:x}")

# Look for JSON keys in wide-char form
json_keys = ['orderId', 'order', 'action', 'device', 'ECID', 'UDID', 'SerialNumber',
             'IMEI', 'ChipID', 'BoardID', 'ProductType', 'ProductVersion',
             'BuildVersion', 'activationData', 'deviceCert', 'nonce', 'ticket',
             'accountId', 'appleId', 'fairPlay', 'attestation',
             'BUID', 'PROG', 'UID', 'AK', 'GIDKey', 'DKey',
             'signature', 'sig', 'hash', 'token', 'auth',
             'hardwareInfo', 'firmwareInfo', 'response', 'request',
             'baseband', 'restore', 'success', 'error', 'status']
found_keys = []
for k in json_keys:
    pos = data.find(k.encode('utf-16-le'))
    if pos >= 0:
        found_keys.append((k, pos))
        # Show short context
        ctx_bytes = data[max(0,pos-100):pos+200]
        # Try decode as series of null-terminated strings
        strs = []
        s = bytearray()
        for j in range(0, len(ctx_bytes)-1, 2):
            if ctx_bytes[j] == 0 and ctx_bytes[j+1] == 0:
                if s:
                    strs.append(bytes(s).decode('utf-16-le', errors='replace'))
                    s = bytearray()
            else:
                s.extend(ctx_bytes[j:j+2])
        print(f"  '{k}' @ 0x{pos:x}")
        print(f"    nearby: {strs}")

# Also search for ASCII keys (might be in resource section)
print("\n" + "="*80)
print("[3] ASCII JSON KEYS (in resource files)")
print("="*80)
# Resource files (JSON) typically in .NET resources use ASCII
for k in json_keys + ['ActivationInfo','ActivationInfoWithSession','ActivationSession',
                       'iOSActivation','requestActivation','activation_record',
                       'activationRecord','request_id','device_info']:
    pos = data.find(b'"' + k.encode() + b'"')
    if pos >= 0:
        ctx = data[max(0,pos-50):pos+100]
        ascii_ctx = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
        print(f"  '\"{k}\"' @ 0x{pos:x}: {ascii_ctx}")