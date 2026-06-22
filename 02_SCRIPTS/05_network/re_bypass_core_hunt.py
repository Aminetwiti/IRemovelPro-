"""
Hunt for the Activation Lock bypass crypto core in iremovalpro.dll
Search for: ECDSA, RSA, Apple root CA, HMAC key, ticket signing routine
"""
import re
import os

DLL = r'IRemovalPro\iremovalpro.dll'
print(f'[*] Loading {DLL}...')
with open(DLL, 'rb') as f:
    data = f.read()
print(f'[*] Size: {len(data):,} bytes')

# 1. Apple Root CA fingerprints (well-known)
apple_cas = [
    b'Apple Root CA',      # SHA-1 fingerprint
    b'Apple Inc. Root',
    b'Apple Computer',
    b'CN=Apple',
    b'OU=Apple',
    b'O=Apple',
    b'iPhone Certification',
    b'iPhone Device CA',
    b'Apple iPhone Device',
    b'Apple iOS Device',
    b'ACT-P',
    b'ACT-S',
    b'actatc',
    b'Activation',
]
print('\n=== Apple CA / Activation certificates ===')
for c in apple_cas:
    pos = 0
    while True:
        pos = data.find(c, pos)
        if pos < 0: break
        ctx = data[max(0,pos-20):pos+len(c)+50]
        try:
            ctx_str = ctx.decode('latin1', errors='replace')
        except:
            ctx_str = repr(ctx)
        print(f'  0x{pos:08x}: {ctx_str!r}')
        pos += 1

# 2. ASN.1 / DER X.509 markers
print('\n=== ASN.1 / X.509 markers ===')
asn1_markers = [
    (b'\x30\x82', 'SEQUENCE (long form)'),
    (b'\x30\x83', 'SEQUENCE (longer)'),
    (b'\x30\x59', 'X.509 TBSCertificate approx'),
    (b'\x06\x03\x55\x04\x03', 'OID commonName'),
    (b'\x06\x03\x55\x04\x06', 'OID countryName'),
    (b'\x06\x03\x55\x04\x0a', 'OID organizationName'),
    (b'\x06\x03\x55\x04\x0b', 'OID organizationalUnitName'),
    (b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01', 'OID rsaEncryption'),
    (b'\x06\x07\x2a\x86\x48\xce\x38\x04\x01', 'OID ansip256r1'),
    (b'\x06\x07\x2a\x86\x48\xce\x38\x04\x03', 'OID ansip384r1'),
    (b'\x06\x05\x2b\x81\x04\x00\x22', 'OID secp224r1'),
    (b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02', 'OID secp256r1'),
    (b'\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03', 'OID secp384r1'),
    (b'\x06\x05\x2b\x0e\x03\x02\x1a', 'OID secp192r1'),
    (b'\xa0\x03\x02\x01\x86', 'context 0 version 3'),
    (b'\xa1\x03\x02\x01\x07', 'sig alg version'),
]
# Find every asn1 sequence after a cert header
cert_marker = b'\x30\x82'  # SEQUENCE
positions_seen = []
pos = 0
cert_candidates = []
while True:
    pos = data.find(cert_marker, pos)
    if pos < 0: break
    if pos + 4 < len(data):
        # Read length
        b1 = data[pos+2]
        b2 = data[pos+3]
        total = (b1 << 8) | b2
        if 50 < total < 5000:  # plausible cert size
            cert_candidates.append((pos, total+4))
    pos += 1
print(f'[*] Found {len(cert_candidates)} plausible DER sequences (50-5000 bytes)')
# Show first 20
for off, sz in cert_candidates[:20]:
    print(f'  0x{off:08x} - 0x{off+sz:08x} ({sz} bytes)')

# 3. Search for ActivationTicket format markers (Apple binary plist)
print('\n=== Activation ticket format markers ===')
ticket_terms = [
    b'ActivationTicket',
    b'ActivationInfo',
    b'wildcardTicket',
    b'wildcard-ticket',
    b'serverCertificates',
    b'activation-random-key',
    b'Activation',
    b'fairplay-key',
    b'fairplayRequest',
    b'fairplayResponse',
    b'fairPlayRequest',
    b'fairPlayResponse',
    b'iTunesStoreID',
    b'AccountID',
    b'AccountToken',
    b'BUID',
    b'RegionInfo',
    b'PurchaseReceipt',
    b'BES',
    b'BBI',
    b'BLS',
    b'mobileactivationd',
    b'MobileActivation',
]
for t in ticket_terms:
    pos = 0
    count = 0
    examples = []
    while True:
        pos = data.find(t, pos)
        if pos < 0: break
        count += 1
        if len(examples) < 3:
            ctx = data[max(0,pos-30):pos+len(t)+60]
            try:
                ctx_str = ctx.decode('latin1', errors='replace')
            except:
                ctx_str = repr(ctx)
            examples.append((pos, ctx_str))
        pos += 1
    if count > 0:
        print(f'\n  {t.decode()}: {count} refs')
        for off, ctx in examples:
            print(f'    0x{off:08x}: {ctx!r}')

# 4. PKCS#7 / CMS markers (Apple activation tickets are CMS)
print('\n=== PKCS#7 / CMS signed data ===')
cms_terms = [
    b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07',  # pkcs7
    b'1.2.840.113549.1.7',
    b'signedData',
    b'PKCS7',
    b'envelopedData',
    b'\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02',  # signedData OID
]
for c in cms_terms:
    pos = 0
    count = 0
    while True:
        pos = data.find(c, pos)
        if pos < 0: break
        count += 1
        pos += 1
    if count > 0:
        print(f'  {c!r}: {count} refs')

# 5. ECDSA signature format (ASN.1: 0x30 + 0x44 or 0x46)
print('\n=== ECDSA signature blobs (32+32=64 bytes raw or ASN.1) ===')
ecdsa_blobs = []
for i in range(len(data) - 70):
    if data[i] == 0x30 and data[i+1] in (0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a):
        # Valid ASN.1 sequence
        if data[i+2] == 0x02:  # INTEGER tag
            ecdsa_blobs.append(i)
print(f'[*] Found {len(ecdsa_blobs)} ECDSA-like ASN.1 signatures')
for off in ecdsa_blobs[:15]:
    ctx = data[off:off+80]
    print(f'  0x{off:08x}: {ctx.hex()[:160]}')

# 6. Search for SHA-256 constants in code (K[64] or H[8])
print('\n=== SHA-256 constants (K table) ===')
# K[0..3] = 0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5
sha_k_marker = bytes.fromhex('98 2f 8a 42 91 44 37 71 cf fb c0 b5 a5 db b5 e9'.replace(' ', ''))
positions = []
pos = 0
while True:
    pos = data.find(sha_k_marker, pos)
    if pos < 0: break
    positions.append(pos)
    pos += 1
print(f'[*] SHA-256 K[0..3]: {len(positions)} locations')
for p in positions[:5]:
    print(f'  0x{p:08x}')

# 7. Search for AES S-box (start: 0x63 0x7c 0x77 0x7b)
print('\n=== AES S-box (start) ===')
aes_sbox = bytes.fromhex('637c777bf26b6fc53001672bfed7ab76')
positions = []
pos = 0
while True:
    pos = data.find(aes_sbox, pos)
    if pos < 0: break
    positions.append(pos)
    pos += 1
print(f'[*] AES S-box: {len(positions)} locations')
for p in positions[:5]:
    print(f'  0x{p:08x}')

# 8. Search for HMAC-SHA256 IPAD = 0x36, OPAD = 0x5c
print('\n=== HMAC IPAD/OPAD code patterns ===')
# Hard to find - look for string "HMAC"
for term in [b'HMAC', b'hmac', b'Hmac']:
    pos = 0
    count = 0
    while True:
        pos = data.find(term, pos)
        if pos < 0: break
        count += 1
        pos += 1
    if count > 0:
        print(f'  {term!r}: {count} refs')

print('\n[*] Done')
