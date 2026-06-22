"""Real XOR analysis on raw DLL bytes at 0xa6bace-0xa6c000."""
import os, struct, hashlib, binascii, collections, json

BASE = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'
DLL = os.path.join(BASE, 'IRemovalPro', 'iremovalpro.dll')

with open(DLL, 'rb') as f:
    data = f.read()

print(f'DLL size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)')
print(f'SHA-256: {hashlib.sha256(data).hexdigest()}')

# Check the offsets mentioned in NOUVELLES_DECOUVERTES.md
start = 0xa6bace
end = 0xa6c000
print()
print(f'Region 0x{start:x} - 0x{end:x} (size: {end-start} bytes)')

if start < len(data) and end < len(data):
    region = data[start:end]
    print(f'First 64 bytes (hex): {binascii.hexlify(region[:64]).decode()}')
    print(f'As text: {repr(region[:64])}')
    print()
    # Entropy
    freq = collections.Counter(region)
    import math
    entropy = -sum((c/len(region)) * math.log2(c/len(region)) for c in freq.values() if c > 0)
    print(f'Entropy: {entropy:.3f} bits/byte (max 8.0 = random)')

    # Single-byte XOR brute force
    print()
    print('Single-byte XOR brute force (key 0x00-0xFF):')
    print('Looking for ASCII printable results with high entropy reduction...')
    best_keys = []
    for key in range(256):
        decoded = bytes(b ^ key for b in region)
        # Check if it looks like ASCII text (printable + high alpha ratio)
        printable = sum(1 for b in decoded if 32 <= b < 127)
        alpha = sum(1 for b in decoded if (65 <= b < 91) or (97 <= b < 123))
        ratio = printable / len(decoded)
        if ratio > 0.8 and alpha > len(region) * 0.5:
            best_keys.append((key, ratio, alpha, decoded[:80]))
    best_keys.sort(key=lambda x: -x[2])  # Sort by alpha count
    print(f'  Found {len(best_keys)} candidate keys with high ASCII ratio')
    for key, ratio, alpha, sample in best_keys[:5]:
        print(f'    key=0x{key:02x} ({key:3d}): ratio={ratio:.2f} alpha={alpha} sample={sample!r}')

    # Also try 4-byte XOR (rolling) on the region
    # Look for the magic bytes "https" or "BEGIN" or "ssh-" if decrypted
    print()
    print('Multi-byte XOR (4-byte) — Kasiski-style...')
    for magic in [b'https', b'BEGIN', b'ssh-r', b'-----', b'iRemo', b'\x89PNG']:
        for offset in range(0, len(region) - len(magic)):
            # Derive key from this position
            key = bytes(region[offset+i] ^ magic[i] for i in range(len(magic)))
            # Try to decode the next 16 bytes with this key (if all printable, hit)
            if offset + 16 <= len(region):
                decoded = bytes(region[offset+i] ^ key[i % len(key)] for i in range(16))
                if all(32 <= b < 127 for b in decoded):
                    print(f'  HIT @ 0x{offset:x}: magic={magic} key={binascii.hexlify(key).decode()} -> {decoded!r}')

# Also look for any region in the DLL with XOR pattern against known strings
print()
print('Searching entire DLL for XOR(known plaintext) pattern:')
known_plaintexts = [
    b'https://s13.iremovalpro.com',
    b'ssh-rsa AAAA',
    b'-----BEGIN RSA PRIVATE KEY-----',
    b'-----BEGIN CERTIFICATE-----',
    b's13.iremovalpro.com',
    b'iremovalActivation',
    b'/iremovalActivation/iact8.php',
    b'/iremovalActivation/apple_drm_check.ph',
]
for pt in known_plaintexts:
    for key_byte in range(1, 256):  # skip 0 (would find plaintext directly)
        xored = bytes(b ^ key_byte for b in pt)
        pos = data.find(xored)
        if pos >= 0:
            print(f'  HIT: PT={pt[:30]}... key=0x{key_byte:02x} pos=0x{pos:x}')

# Try multi-byte: key with first 4 bytes known
print()
print('Known-plaintext attack with URL prefix (rolling key)...')
pt_prefix = b'https://'
for pos_start in range(0, len(data) - 32, 4096):  # Sample every 4KB
    # Derive 8-byte key from this position
    if pos_start + 32 > len(data): break
    chunk = data[pos_start:pos_start+32]
    key = bytes(chunk[i] ^ pt_prefix[i % len(pt_prefix)] for i in range(8))
    # Try decrypting next 64 bytes
    sample = bytes(chunk[i] ^ key[i % len(key)] for i in range(8, 64))
    printable = sum(1 for b in sample if 32 <= b < 127)
    if printable > 50:  # 80%+ printable
        print(f'  Candidate @ 0x{pos_start:x}: key={binascii.hexlify(key).decode()} -> {sample!r}')
