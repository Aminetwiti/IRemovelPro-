#!/usr/bin/env python3
"""Find JSON keys for iact8.php request body."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
data = open(r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll','rb').read()

print("="*80)
print("[1] JSON KEY SEARCH (both ASCII and UTF-16LE)")
print("="*80)
keys_found = {}
for kw in [b'UDID', b'ECID', b'IMEI', b'SerialNumber', b'ChipID', b'BoardID', b'ProductType',
           b'orderId', b'order', b'ticket', b'nonce', b'sig', b'signature', b'BUID', b'PROG',
           b'requestActivation', b'iPhone', b'iPad', b'iOS', b'ProductVersion', b'AppleID',
           b'BES', b'BBI', b'BLS', b'baseband', b'Baseband', b'accountToken', b'guid',
           b'hwid', b'HWID', b'apiVersion', b'api_version', b'client', b'Client',
           b'activation', b'Activation', b'action', b'Action',
           b'fairPlay', b'FairPlay', b'attest', b'Attest', b'cert', b'Cert',
           b'BESRequest', b'BESResponse', b'BBIRequest', b'BBIResponse',
           b'wildcard', b'Wildcard', b'fairplay', b'fairkey', b'fairKey',
           b'IMEI2', b'IMSI', b'ICCID', b'activationInfo', b'requestId', b'kbsync',
           b'BESDeviceCert', b'BESCert', b'BESData', b'BBData', b'machineId',
           b'requestKey', b'request_data', b'apple', b'Apple', b'iOSActivation',
           b'getActivation', b'ActivationState', b'activationState', b'URL', b'url',
           b'Checkm8', b'checkm8', b'checkm8Status', b'requestSign']:
    # ASCII with quotes
    pos = data.find(b'"' + kw + b'"')
    if pos >= 0:
        keys_found.setdefault(kw.decode(), []).append(('ASCII', pos))
    # UTF-16LE with quotes
    wide = ('"' + kw.decode() + '"').encode('utf-16-le')
    pos = data.find(wide)
    if pos >= 0:
        keys_found.setdefault(kw.decode(), []).append(('UTF16', pos))

# Sort by number of occurrences
for k, v in sorted(keys_found.items(), key=lambda x: -len(x[1])):
    print(f"  {k:20} hits={len(v)}  first={v[0]}")

# Now find context around the most common keys
print("\n" + "="*80)
print("[2] CONTEXT AROUND TYPICAL ACTIVATION KEYS (UTF-16LE)")
print("="*80)
for k in ['UDID', 'IMEI', 'ECID', 'orderId', 'ticket', 'signature', 'BES']:
    for enc, pos in keys_found.get(k, []):
        ctx = data[max(0,pos-100):pos+300]
        if enc == 'UTF16':
            try:
                txt = ctx.decode('utf-16-le', errors='replace')
            except:
                txt = ''
        else:
            txt = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
        print(f"\n  '{k}' ({enc}) @ 0x{pos:x}:")
        print(f"    ...{txt}...")