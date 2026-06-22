#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Recherche exhaustive ECDSA / courbes elliptiques dans tous les binaires.
"""
import sys, struct, os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

BASE = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'

FILES = {
    'NET_DLL':            BASE + r'\IRemovalPro\iremovalpro.dll',
    'IOS_DYLIB_ARM64':    BASE + r'\04_EXTRACTED\macho_8534d3_DYLIB_ARM64_ALL.bin',
    'IOS_DYLIB_ARM64E':   BASE + r'\04_EXTRACTED\macho_86b4d3_DYLIB_ARM64_ARM64E.bin',
}

# OIDs standards ECDSA
OIDS = {
    'ecPublicKey (1.2.840.10045.2.1)':         bytes.fromhex('06072A8648CE3D0201'),
    'P-256 secp256r1 (1.2.840.10045.3.1.7)':  bytes.fromhex('06082A8648CE3D030107'),
    'P-384 secp384r1 (1.3.132.0.34)':         bytes.fromhex('06052B8104002200'),
    'P-521 secp521r1 (1.3.132.0.35)':         bytes.fromhex('06052B8104002300'),
    'secp256k1 (1.3.132.0.10)':               bytes.fromhex('06052B8104000A'),
    'ecdsa-SHA256 (1.2.840.10045.4.3.2)':     bytes.fromhex('06082A8648CE3D040302'),
    'ecdsa-SHA384 (1.2.840.10045.4.3.3)':     bytes.fromhex('06082A8648CE3D040303'),
    'ecdsa-SHA512 (1.2.840.10045.4.3.4)':     bytes.fromhex('06082A8648CE3D040304'),
    'ecdsa-SHA1 (1.2.840.10045.4.1)':         bytes.fromhex('06062A8648CE3D0401'),
}

TEXT_PATTERNS = [
    b'1.2.840.10045.2.1', b'1.2.840.10045.3.1.7', b'1.3.132.0.34',
    b'secp256r1', b'secp384r1', b'secp521r1', b'prime256v1',
    b'P-256', b'P-384', b'P-521', b'secp256k1',
    b'ecPublicKey', b'ECPublicKey',
    b'kSecAttrKeyTypeEC', b'kSecAttrKeyTypeECSECRandom',
]

print('='*80)
print('  RECHERCHE ECDSA / COURBES ELLIPTIQUES')
print('='*80)

for fname_key, fpath in FILES.items():
    print(f'\n[{fname_key}]')
    print(f'  Path: {os.path.basename(fpath)}')
    try:
        data = open(fpath, 'rb').read()
    except FileNotFoundError:
        print('  [!] Fichier non trouve')
        continue
    print(f'  Size: {len(data):,} bytes')

    # OIDs DER
    found_oid = False
    for name, oid in OIDS.items():
        c = data.count(oid)
        if c > 0:
            print(f'  [+] OID {name}: {c} fois')
            found_oid = True
    if not found_oid:
        print('  [-] Aucun OID ECDSA en DER')

    # Patterns texte
    found_text = False
    for pat in TEXT_PATTERNS:
        c = data.count(pat)
        if c > 0:
            positions = []
            pos = 0
            for _ in range(3):
                idx = data.find(pat, pos)
                if idx < 0: break
                positions.append(idx)
                pos = idx + 1
            print(f'  [+] Texte {pat!r}: {c} fois ({[hex(p) for p in positions]})')
            found_text = True
    if not found_text:
        print('  [-] Aucun pattern texte ECDSA')

# === Recherche points EC P-256 uncompressed (04 + 64 octets) ===
print('\n' + '='*80)
print('  POINTS EC P-256 UNCOMPRESSED (04 + 64 octets)')
print('='*80)

for fname_key, fpath in FILES.items():
    print(f'\n[{fname_key}]')
    try:
        data = open(fpath, 'rb').read()
    except FileNotFoundError:
        continue
    count = 0
    for i in range(0, len(data) - 65):
        if data[i] == 0x04:
            x = data[i+1:i+33]
            y = data[i+33:i+65]
            if (sum(1 for b in x if b != 0) > 20 and
                sum(1 for b in y if b != 0) > 20):
                count += 1
    print(f'  Candidats point P-256 uncompressed: {count}')

# === Recherche signatures ECDSA (ASN.1 SEQUENCE de 2 INTEGER ~32 octets) ===
print('\n' + '='*80)
print('  SIGNATURES ECDSA (SEQUENCE de 2 INTEGER ~32-33 octets)')
print('='*80)

for fname_key, fpath in FILES.items():
    print(f'\n[{fname_key}]')
    try:
        data = open(fpath, 'rb').read()
    except FileNotFoundError:
        continue
    # Une signature ECDSA P-256 typique fait ~70-72 octets (2 * 32 + overhead)
    # Format: 30 [70-72] 02 [21 ou 20] 00/positive [32 octets r] 02 [21 ou 20] 00/positive [32 octets s]
    count_sig = 0
    for i in range(0, len(data) - 72):
        if data[i] == 0x30 and 0x44 <= data[i+1] <= 0x48:  # SEQUENCE 68-72 bytes
            if data[i+2] == 0x02 and 0x20 <= data[i+3] <= 0x21:  # INTEGER 32-33 bytes
                # next: optional 0x00 (positive sign) + 32 bytes r
                r_offset = i + 4
                if data[r_offset] == 0x00:
                    r_offset += 1
                # Then INTEGER s
                if data[r_offset+32] == 0x02 and 0x20 <= data[r_offset+33] <= 0x21:
                    count_sig += 1
    print(f'  Candidats signature ECDSA P-256: {count_sig}')

# === Recherche ECDSA via symboles Apple Security framework ===
print('\n' + '='*80)
print('  SYMBOLES APPLE SECURITY FRAMEWORK (SecKey*, kSecAttr*)')
print('='*80)

APPLE_SEC = [
    b'SecKeyCreateSignature', b'SecKeyVerifySignature',
    b'SecKeyCreateRandomKey', b'SecKeyCreateWithData',
    b'SecKeyCopyExternalRepresentation', b'SecKeyCopyKeyExchangeResult',
    b'kSecAttrKeyTypeECSECPrimeRandom', b'kSecAttrKeyTypeEC',
    b'kSecAttrKeyClassPublic', b'kSecAttrKeyClassPrivate',
    b'kSecAttrKeySizeInBits', b'kSecKeyAlgorithmECDSASignatureMessageX962SHA256',
    b'kSecKeyAlgorithmECDSASignatureMessageX962SHA384',
    b'kSecKeyAlgorithmECDSASignatureMessageX962SHA512',
]

for fname_key, fpath in FILES.items():
    print(f'\n[{fname_key}]')
    try:
        data = open(fpath, 'rb').read()
    except FileNotFoundError:
        continue
    found = 0
    for sym in APPLE_SEC:
        c = data.count(sym)
        if c > 0:
            print(f'  [+] {sym.decode()}: {c} fois')
            found += 1
    if found == 0:
        print('  [-] Aucun symbole Apple Security EC')

print('\n' + '='*80)
print('  FIN')
print('='*80)
