#!/usr/bin/env python3
"""Extract RSA public key from BlackHound dylib."""
import base64
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
data = (WORK / "04_EXTRACTED" / "macho_8534d3_DYLIB_ARM64_ALL.bin").read_bytes()

# Find RSA pubkey (DER-encoded SubjectPublicKeyInfo ends in BgQIDAQAB)
pattern = re.compile(rb'[A-Za-z0-9+/=]{100,}BgQIDAQAB')
print(f"[*] Scanning {len(data):,} bytes...")

for m in pattern.finditer(data):
    start = m.start()
    while start > 0 and chr(data[start-1]) in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=':
        start -= 1
    end = m.end()
    b64 = data[start:end].decode('ascii')
    print(f"\n[*] RSA pubkey candidate at 0x{start:x} (len={len(b64)})")
    try:
        raw = base64.b64decode(b64)
        print(f"    Decoded: {len(raw)} bytes")
        # Print hex
        print(f"    Hex first 32:  {raw[:32].hex()}")
        print(f"    Hex last 32:   {raw[-32:].hex()}")
        # Check DER structure
        if raw[0:1] == b'\x30\x82':
            seq_len = (raw[2] << 8) | raw[3]
            print(f"    *** DER SEQUENCE length={seq_len} ***")
            # Save raw key
            out = WORK / "04_EXTRACTED" / "rsa_pubkey.der"
            out.write_bytes(raw)
            print(f"    Saved to: {out}")
            # Save base64 too
            (WORK / "04_EXTRACTED" / "rsa_pubkey.b64.txt").write_text(b64)
        # Look for RSA OID (rsaEncryption 1.2.840.113549.1.1.1)
        rsa_oid = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'  # rsaEncryption
        if rsa_oid in raw:
            print(f"    *** RSA OID FOUND (rsaEncryption) ***")
            idx = raw.find(rsa_oid)
            print(f"    OID at offset {idx}")
            print(f"    Context after OID: {raw[idx:idx+30].hex()}")
    except Exception as e:
        print(f"    Decode error: {e}")

# Also look for the FULL context around MS2wnb2xsyFgQIDAQAB
# This was seen in earlier dump - it's likely the END of a different base64 segment
print("\n" + "="*80)
print("Context around 'MS2wnb2xsyFgQIDAQAB':")
print("="*80)
marker = b'MS2wnb2xsyFgQIDAQAB'
idx = data.find(marker)
if idx != -1:
    print(f"  Found at offset 0x{idx:x}")
    # Walk back to find start of base64
    start = idx
    while start > 0 and chr(data[start-1]) in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=':
        start -= 1
    print(f"  Base64 starts at 0x{start:x}")
    b64 = data[start:idx+len(marker)].decode('ascii')
    print(f"  Length: {len(b64)} chars")
    print(f"  Base64: {b64}")
    try:
        raw = base64.b64decode(b64)
        print(f"  Decoded: {len(raw)} bytes")
        print(f"  Hex: {raw.hex()}")
    except Exception as e:
        print(f"  Decode error: {e}")
    # Show context after
    ctx = data[idx:idx+200]
    ctx_clean = ''.join(chr(b) if 32 <= b < 127 else f'.' for b in ctx)
    print(f"\n  Context after marker:")
    print(f"  {ctx_clean}")