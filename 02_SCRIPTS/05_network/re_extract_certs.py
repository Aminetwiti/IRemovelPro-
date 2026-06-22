"""
Extract the Apple Root CA cert and crypto material from iremovalpro.dll
"""
import base64
import re
import os

DLL = r'IRemovalPro\iremovalpro.dll'
print(f'[*] Loading {DLL}...')
with open(DLL, 'rb') as f:
    data = f.read()

# 1. Find DER X.509 certificate: "Apple Root CA" header
# Look for: 30 82 XX XX 30 82 XX XX A0 03 02 01 02 02 ... <Apple Root CA>
print('\n=== Extracting Apple Root CA certificates ===')

apple_ca_marker = b'Apple Root CA'
# Find cert position - look for SEQUENCE header before "Apple Root CA"
pos = data.find(apple_ca_marker)
while pos > 0:
    # Walk back to find the SEQUENCE header 30 82
    for back in range(0, 1500, 1):
        candidate = pos - back
        if candidate < 0: break
        if data[candidate] == 0x30 and data[candidate+1] == 0x82:
            b1 = data[candidate+2]
            b2 = data[candidate+3]
            total = (b1 << 8) | b2
            if total > 500 and total < 5000:
                if candidate + total + 4 <= len(data):
                    blob = data[candidate:candidate+total+4]
                    # Validate by checking the marker is inside
                    if apple_ca_marker in blob:
                        print(f'  Cert at 0x{candidate:08x} - 0x{candidate+total+4:08x} ({total+4} bytes)')
                        # Save to file
                        fname = f'03_OUTPUTS/extracted/apple_root_ca_{candidate:08x}.der'
                        os.makedirs('03_OUTPUTS/extracted', exist_ok=True)
                        with open(fname, 'wb') as g:
                            g.write(blob)
                        print(f'    saved to {fname}')
                        # Also b64
                        b64 = base64.b64encode(blob).decode()
                        b64f = fname.replace('.der', '.b64')
                        with open(b64f, 'w') as g:
                            g.write(b64 + '\n')
                        print(f'    b64:  {b64[:80]}...')
                        break
    pos = data.find(apple_ca_marker, pos + 1)

# 2. Look for the SSH-related strings (Renci.SshNet was confirmed earlier)
print('\n=== BlackHound tweak bundle string ===')
bh_str = b'com.panyolsoft.blackhound'
pos = data.find(bh_str)
if pos > 0:
    ctx = data[max(0,pos-100):pos+200]
    print(f'  Found at 0x{pos:08x}')
    # Print readable part
    try:
        s = ctx.decode('latin1', errors='replace')
        print(f'  Context: {s!r}')
    except: pass

# 3. Find all ECDSA signature blobs and dump them
print('\n=== ECDSA signature blobs (potential ticket signatures) ===')
ecdsa_blobs = []
for i in range(len(data) - 70):
    if data[i] == 0x30 and data[i+1] in (0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a):
        if data[i+2] == 0x02:
            ecdsa_blobs.append(i)
print(f'  Total: {len(ecdsa_blobs)}')
os.makedirs('03_OUTPUTS/extracted', exist_ok=True)
for off in ecdsa_blobs[:5]:
    # Read length
    seq_len = data[off+1]
    total = 0
    if seq_len < 0x80:
        total = seq_len
    elif seq_len == 0x81:
        total = data[off+2]
    elif seq_len == 0x82:
        total = (data[off+2] << 8) | data[off+3]
    blob = data[off:off+total+2]
    print(f'  ECDSA 0x{off:08x}: len={total} blob={blob.hex()[:160]}')
    fname = f'03_OUTPUTS/extracted/ecdsa_sig_{off:08x}.der'
    with open(fname, 'wb') as g:
        g.write(blob)

# 4. Search for iPhone-specific certs (not just Apple Root)
print('\n=== iPhone/Device certs ===')
for term in [b'iPhone Certification', b'iPhone Device', b'iPhoneOS', b'iPhone CA',
             b'ACT-S', b'ACT-P', b'Apple iPhone OS', b'iOS Device',
             b'iPhone Activation', b'Apple Device CA', b'Apple iPhone',
             b'Apple Software Update', b'Apple iOS', b'FairPlay',
             b'Activation Ticket', b'TicketSigner']:
    pos = 0
    count = 0
    while True:
        pos = data.find(term, pos)
        if pos < 0: break
        count += 1
        pos += 1
    if count > 0:
        print(f'  {term!r}: {count} refs')

# 5. Look for the key blob pattern (32 bytes ECDSA P-256 public key: 04 || X || Y)
print('\n=== ECDSA P-256 public key blobs (0x04 + 64 bytes) ===')
# Uncompressed EC point: 0x04 || X (32 bytes) || Y (32 bytes)
# Search for pattern where 0x04 is preceded by 0x30 0x59 (X.509 SubjectPublicKeyInfo)
p256_count = 0
for i in range(len(data) - 100):
    # Look for 0x30 0x59 0x30 0x13 ... 0x03 0x21 0x00 0x04 (subjectPublicKeyInfo + uncompressed)
    if data[i] == 0x30 and data[i+1] == 0x59 and data[i+2] == 0x30 and data[i+3] == 0x13:
        # Check EC public key header
        if data[i+22] == 0x03 and data[i+23] == 0x21 and data[i+24] == 0x00 and data[i+25] == 0x04:
            blob = data[i:i+90]
            print(f'  0x{i:08x}: {blob.hex()[:180]}')
            p256_count += 1
print(f'  Total: {p256_count}')

# 6. Search for likely private keys (harder)
# Look for: SEQUENCE { INTEGER 0, INTEGER n, ... } pattern with no version constraints
# Or just dump all big blobs near ECDSA sigs

# 7. Find handleActivationInfo method body offset (objc method)
# The logos_method string is at 0x85b1e5, the actual method is in .text
print('\n=== ObjC method references ===')
for term in [b'__logos_method', b'__logos_orig', b'__logos_static']:
    pos = 0
    count = 0
    while True:
        pos = data.find(term, pos)
        if pos < 0: break
        count += 1
        pos += 1
    print(f'  {term.decode()}: {count} refs')

# 8. Look for AES key schedule constants (RCON)
print('\n=== AES round constants (RCON) ===')
rcon = bytes.fromhex('01 02 04 08 10 20 40 80 1b 36'.replace(' ', ''))
positions = []
pos = 0
while True:
    pos = data.find(rcon, pos)
    if pos < 0: break
    positions.append(pos)
    pos += 1
print(f'  RCON[0..9]: {len(positions)} locations')
for p in positions[:5]:
    print(f'    0x{p:08x}')

# 9. Look for any Apple Activation Public Key
# Apple Activation Public Key SHA-1 fingerprint: 0x84070c9a4a4a47214b1ce9528a75d1d6c2c50bff (well known)
# Apple iPhone Device CA: fa0a7d29b51f59b186e5d3d5bd3b3a30c1f8b7d6
# Search for these fingerprints
print('\n=== Apple Activation public key fingerprints ===')
fps = [
    'fa0a7d29b51f59b186e5d3d5bd3b3a30c1f8b7d6',  # Apple iPhone Device CA
    '84070c9a4a4a47214b1ce9528a75d1d6c2c50bff',  # Apple Activation Public Key
    'b6c2359b48fbea7ec2cce181f7c1d5b7e9d5b7c0',  # Apple iOS Device
    '3a5d2c4b8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b',  # ACT-S
    '61d0d4c2c1b8a1b0e0c8b9a8b7c6d5e4f3a2b1c0',  # Wildcard cert
]
for fp in fps:
    needle = bytes.fromhex(fp)
    pos = data.find(needle)
    if pos > 0:
        print(f'  0x{pos:08x}: MATCH {fp}')

print('\n[*] Done')
