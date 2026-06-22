#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1.5 - Extracteur de clés crypto depuis un dump mémoire
========================================================

Cherche dans un dump mémoire (.dmp, .bin, .raw) :
  - Clés RSA privées (PKCS#1, PKCS#8, PEM)
  - Clés RSA publiques (X.509 SubjectPublicKeyInfo)
  - Clés AES (par heuristique d'entropie)
  - Certificats X.509 (DER)
  - Clés HMAC / SHA pré-calculées
  - Tokens d'activation iCloud (TicketActivation)
  - Clés API / Bearer tokens

Usage :
  py extract_keys_from_dump.py memory.dmp
  py extract_keys_from_dump.py memory.dmp --output keys_report.txt

Prérequis :
  - pip install pycryptodome regex
  - (optionnel) pip install asn1crypto
"""
import argparse
import re
import sys
import os
import json
import hashlib
import struct
from pathlib import Path
from datetime import datetime

# === CONFIG ===
PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = PROJECT_ROOT / "03_OUTPUTS" / "runtime_dump"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Magic bytes / ASN.1 OIDs
RSA_OID = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])  # rsaEncryption
EC_OID = bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
PEM_HEADERS = [
    b'-----BEGIN RSA PRIVATE KEY-----',
    b'-----BEGIN PRIVATE KEY-----',
    b'-----BEGIN ENCRYPTED PRIVATE KEY-----',
    b'-----BEGIN EC PRIVATE KEY-----',
    b'-----BEGIN DSA PRIVATE KEY-----',
    b'-----BEGIN CERTIFICATE-----',
    b'-----BEGIN PUBLIC KEY-----',
    b'-----BEGIN OPENSSH PRIVATE KEY-----',
]
PEM_FOOTERS = [
    b'-----END RSA PRIVATE KEY-----',
    b'-----END PRIVATE KEY-----',
    b'-----END ENCRYPTED PRIVATE KEY-----',
    b'-----END EC PRIVATE KEY-----',
    b'-----END DSA PRIVATE KEY-----',
    b'-----END CERTIFICATE-----',
    b'-----END PUBLIC KEY-----',
    b'-----END OPENSSH PRIVATE KEY-----',
]


def entropy(data: bytes) -> float:
    """Shannon entropy (0-8)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    n = len(data)
    for c in freq:
        if c > 0:
            p = c / n
            e -= p * (p and (p * 0).bit_length() or 0)  # avoid log(0)
    import math
    e = 0.0
    for c in freq:
        if c > 0:
            p = c / n
            e -= p * math.log2(p)
    return e


def find_rsa_keys(data: bytes):
    """Find RSA key patterns in raw bytes."""
    found = []

    # Pattern 1: PKCS#1 RSA public key: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { ... } }
    # Look for the OID with proper ASN.1 structure
    pattern = b'\x30\x82' + b'..' + b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'
    for m in re.finditer(re.escape(pattern), data):
        offset = m.start()
        # Try to parse the DER length
        try:
            seq_len = struct.unpack('>H', data[offset+2:offset+4])[0]
            blob = data[offset:offset+4+seq_len]
            if len(blob) > 100 and len(blob) < 4096:
                found.append({
                    'type': 'RSA-PublicKey-PKCS1',
                    'offset': offset,
                    'size': len(blob),
                    'sha256': hashlib.sha256(blob).hexdigest(),
                    'preview_hex': blob[:32].hex(),
                })
        except Exception:
            pass

    # Pattern 2: PKCS#8 PrivateKeyInfo
    # 30 82 XX XX 02 01 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 04 82
    pattern2 = b'\x30\x82' + b'..\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x82'
    for m in re.finditer(re.escape(pattern2), data):
        offset = m.start()
        try:
            inner_len = struct.unpack('>H', data[offset+2:offset+4])[0]
            blob = data[offset:offset+4+inner_len]
            if len(blob) > 100:
                found.append({
                    'type': 'RSA-PrivateKey-PKCS8',
                    'offset': offset,
                    'size': len(blob),
                    'sha256': hashlib.sha256(blob).hexdigest(),
                    'preview_hex': blob[:32].hex(),
                })
        except Exception:
            pass

    # Pattern 3: PKCS#1 RSA private key (legacy)
    # 30 82 04 ... or larger, contains 02 01 00 02 ... (version, modulus)
    pattern3 = b'\x30\x82' + b'.\x04\x00\x30'  # Could be RSA private
    for m in re.finditer(re.escape(pattern3), data):
        offset = m.start()
        try:
            inner_len = struct.unpack('>H', data[offset+2:offset+4])[0]
            blob = data[offset:offset+4+inner_len]
            # Check for RSA OID inside
            if RSA_OID in blob and b'\x02\x01\x00' in blob[:50]:
                found.append({
                    'type': 'RSA-PrivateKey-PKCS1-Legacy',
                    'offset': offset,
                    'size': len(blob),
                    'sha256': hashlib.sha256(blob).hexdigest(),
                    'preview_hex': blob[:32].hex(),
                })
        except Exception:
            pass

    # Deduplicate (same offset)
    seen = set()
    uniq = []
    for f in found:
        key = (f['type'], f['offset'])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def find_pem_blocks(data: bytes):
    """Find PEM-encoded blocks."""
    found = []
    for header in PEM_HEADERS:
        idx = 0
        while True:
            pos = data.find(header, idx)
            if pos < 0:
                break
            # Find matching footer
            for footer in PEM_FOOTERS:
                footer_label = header.decode().replace('BEGIN', 'END').encode()
                if footer_label == footer:
                    end = data.find(footer, pos + len(header))
                    if end > 0:
                        block = data[pos:end + len(footer)]
                        found.append({
                            'type': 'PEM:' + header.decode().split()[1],
                            'offset': pos,
                            'size': len(block),
                            'sha256': hashlib.sha256(block).hexdigest(),
                            'content': block.decode('ascii', errors='replace'),
                        })
                    break
            idx = pos + 1
    return found


def find_x509_certs(data: bytes):
    """Find X.509 certificates (DER)."""
    found = []
    # X.509 cert starts with 30 82 XX XX 30 82 XX XX a0 03 02 01 02 ...
    pattern = b'\x30\x82' + b'..\x30\x82' + b'..\xa0\x03\x02\x01\x02'
    for m in re.finditer(re.escape(pattern), data):
        offset = m.start()
        try:
            seq_len = struct.unpack('>H', data[offset+2:offset+4])[0]
            blob = data[offset:offset+4+seq_len]
            if 200 < len(blob) < 8192:
                found.append({
                    'type': 'X.509-Certificate-DER',
                    'offset': offset,
                    'size': len(blob),
                    'sha256': hashlib.sha256(blob).hexdigest(),
                    'preview_hex': blob[:32].hex(),
                })
        except Exception:
            pass
    return found


def find_high_entropy_blocks(data: bytes, min_size=16, max_size=64, min_entropy=7.0):
    """Find blocks of bytes with high entropy (candidates for AES/HMAC keys)."""
    found = []
    # Scan in 1MB chunks to avoid memory pressure
    chunk_size = 1024 * 1024
    stride = 4096  # 4KB stride
    for chunk_start in range(0, len(data), chunk_size):
        chunk = data[chunk_start:chunk_start + chunk_size]
        for i in range(0, len(chunk) - max_size, stride):
            for size in [16, 24, 32]:  # AES-128, AES-192, AES-256
                block = chunk[i:i + size]
                if len(block) < size:
                    continue
                e = entropy(block)
                if e > min_entropy:
                    # Check it's not all zeros or all same byte
                    if len(set(block)) > size // 2:
                        offset = chunk_start + i
                        found.append({
                            'type': f'HighEntropy-{size}B',
                            'offset': offset,
                            'size': size,
                            'entropy': round(e, 3),
                            'sha256': hashlib.sha256(block).hexdigest(),
                            'hex': block.hex(),
                        })
        if len(found) > 10000:  # Cap
            break
    return found


def find_activation_tickets(data: bytes):
    """Find iCloud Activation Ticket patterns."""
    found = []
    # Activation tickets are typically base64-encoded plist or binary plist
    patterns = [
        (b'<plist', b'</plist>', 'plist-text'),
        (b'bplist00', None, 'plist-binary'),
        (b'<key>ActivationLock</key>', None, 'key-ActivationLock'),
        (b'<key>DeviceCertificate</key>', None, 'key-DeviceCert'),
        (b'<key>AccountToken</key>', None, 'key-AccountToken'),
        (b'<key>SerialNumber</key>', None, 'key-Serial'),
    ]
    for pattern, end_pattern, label in patterns:
        idx = 0
        while True:
            pos = data.find(pattern, idx)
            if pos < 0:
                break
            if end_pattern:
                end = data.find(end_pattern, pos + len(pattern))
                if end > 0:
                    block = data[pos:end + len(end_pattern)]
                    if len(block) < 100000:
                        found.append({
                            'type': 'ActivationTicket:' + label,
                            'offset': pos,
                            'size': len(block),
                            'sha256': hashlib.sha256(block).hexdigest(),
                            'preview': block[:200].decode('ascii', errors='replace'),
                        })
                    idx = end + len(end_pattern)
                else:
                    idx = pos + len(pattern)
            else:
                # Context around key
                ctx_end = data.find(b'</key>', pos)
                if ctx_end > 0:
                    ctx_start = max(0, pos - 100)
                    ctx = data[ctx_start:ctx_end + 200]
                    found.append({
                        'type': label,
                        'offset': pos,
                        'context_preview': ctx.decode('ascii', errors='replace')[:500],
                    })
                idx = pos + len(pattern)
    return found


def find_api_keys(data: bytes):
    """Find API keys, bearer tokens, UUID-like strings."""
    found = []
    # Bearer tokens
    for m in re.finditer(rb'Bearer\s+[A-Za-z0-9\-_\.]{20,200}', data):
        found.append({
            'type': 'Bearer-Token',
            'offset': m.start(),
            'size': len(m.group(0)),
            'value': m.group(0).decode('ascii', errors='replace')[:200],
        })
    # API key patterns
    for m in re.finditer(rb'(api[_-]?key|apikey|token|secret)[=:\s]+["\']?([A-Za-z0-9\-_\.]{16,200})', data, re.IGNORECASE):
        found.append({
            'type': 'API-Key',
            'offset': m.start(),
            'size': m.end() - m.start(),
            'context': m.group(0).decode('ascii', errors='replace')[:200],
        })
    # UUID v4
    for m in re.finditer(rb'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', data, re.IGNORECASE):
        found.append({
            'type': 'UUID-v4',
            'offset': m.start(),
            'value': m.group(0).decode('ascii'),
        })
    # IMEI (15 digits)
    for m in re.finditer(rb'\b\d{15}\b', data):
        s = m.group(0).decode()
        # IMEI has Luhn checksum
        if all(c.isdigit() for c in s):
            found.append({
                'type': 'IMEI',
                'offset': m.start(),
                'value': s,
            })
    return found


def main():
    parser = argparse.ArgumentParser(description='Extract crypto keys from memory dump')
    parser.add_argument('dump_file', help='Path to memory dump (.dmp, .bin, .raw)')
    parser.add_argument('--output', '-o', help='Output report file (default: stdout)')
    parser.add_argument('--min-entropy', type=float, default=7.0, help='Min entropy for AES candidates')
    parser.add_argument('--max-candidates', type=int, default=10000, help='Max high-entropy candidates')
    args = parser.parse_args()

    dump_path = Path(args.dump_file)
    if not dump_path.exists():
        print(f'[!] File not found: {dump_path}')
        return 1

    print(f'[*] Reading dump: {dump_path} ({dump_path.stat().st_size:,} bytes)')
    print(f'[*] This may take 1-3 minutes for large dumps...')

    with open(dump_path, 'rb') as f:
        data = f.read()

    print(f'[*] Loaded {len(data):,} bytes')
    print()

    results = {
        'dump_file': str(dump_path),
        'dump_size': len(data),
        'analysis_time': datetime.now().isoformat(),
    }

    # === 1. RSA keys ===
    print('[*] Scanning for RSA keys (DER ASN.1)...')
    rsa = find_rsa_keys(data)
    print(f'[+] Found {len(rsa)} RSA key candidates')
    results['rsa_keys'] = rsa

    # === 2. PEM blocks ===
    print('[*] Scanning for PEM-encoded keys/certs...')
    pem = find_pem_blocks(data)
    print(f'[+] Found {len(pem)} PEM blocks')
    results['pem_blocks'] = pem

    # === 3. X.509 certificates ===
    print('[*] Scanning for X.509 certificates...')
    certs = find_x509_certs(data)
    print(f'[+] Found {len(certs)} X.509 certificates')
    results['x509_certs'] = certs

    # === 4. High-entropy blocks (AES candidates) ===
    print(f'[*] Scanning for high-entropy blocks (min entropy={args.min_entropy})...')
    print('    (this is the slowest scan)')
    entropy_blocks = find_high_entropy_blocks(data, min_entropy=args.min_entropy)
    entropy_blocks = entropy_blocks[:args.max_candidates]
    print(f'[+] Found {len(entropy_blocks)} high-entropy blocks')
    results['high_entropy_blocks'] = entropy_blocks

    # === 5. Activation tickets ===
    print('[*] Scanning for iCloud Activation Tickets...')
    tickets = find_activation_tickets(data)
    print(f'[+] Found {len(tickets)} activation-related items')
    results['activation_tickets'] = tickets

    # === 6. API keys / tokens ===
    print('[*] Scanning for API keys, tokens, IMEIs...')
    api = find_api_keys(data)
    print(f'[+] Found {len(api)} API keys/tokens/IMEIs')
    results['api_keys'] = api

    # === Summary ===
    print()
    print('=' * 70)
    print('SUMMARY')
    print('=' * 70)
    print(f'  RSA keys:        {len(rsa)}')
    print(f'  PEM blocks:      {len(pem)}')
    print(f'  X.509 certs:     {len(certs)}')
    print(f'  High-entropy:    {len(entropy_blocks)}')
    print(f'  Activation tix:  {len(tickets)}')
    print(f'  API keys/tokens: {len(api)}')
    print()

    # === Detailed output ===
    if pem:
        print('=' * 70)
        print('PEM BLOCKS (POTENTIAL KEYS - EXTRACT THESE!)')
        print('=' * 70)
        for p in pem[:10]:
            print(f'\n[{p["type"]}] @ offset 0x{p["offset"]:x}, size={p["size"]}')
            print(f'SHA-256: {p["sha256"]}')
            print('---')
            print(p['content'][:1500])
            print('---')

    if rsa:
        print('=' * 70)
        print('RSA KEYS (DER)')
        print('=' * 70)
        for k in rsa[:10]:
            print(f'\n[{k["type"]}] @ 0x{k["offset"]:x}, size={k["size"]}')
            print(f'SHA-256: {k["sha256"]}')
            # Save blob to disk for further analysis
            blob_file = OUT_DIR / f'rsa_{k["sha256"][:16]}.der'
            with open(dump_path, 'rb') as f:
                f.seek(k['offset'])
                blob = f.read(k['size'])
            blob_file.write_bytes(blob)
            print(f'Saved: {blob_file}')

    # === Save JSON report ===
    report_path = args.output or (OUT_DIR / f'keys_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f'\n[*] Report saved: {report_path}')

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)