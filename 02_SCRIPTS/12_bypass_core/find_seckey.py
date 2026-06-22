#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyse contexte SecKey dans le dylib iOS."""
import sys, re, os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

BASE = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'

# Tous les binaires
FILES = {
    'NET_DLL':          BASE + r'\IRemovalPro\iremovalpro.dll',
    'IOS_DYLIB_ARM64':  BASE + r'\04_EXTRACTED\macho_8534d3_DYLIB_ARM64_ALL.bin',
    'IOS_DYLIB_ARM64E': BASE + r'\04_EXTRACTED\macho_86b4d3_DYLIB_ARM64_ARM64E.bin',
}

print('='*80)
print('  ANALYSE SecKey (Apple Security Framework) + EC')
print('='*80)

# Symboles Apple Security Framework
APPLE_SEC = [
    'SecKeyCreateSignature', 'SecKeyVerifySignature',
    'SecKeyCreateRandomKey', 'SecKeyCreateWithData',
    'SecKeyCopyExternalRepresentation', 'SecKeyCopyKeyExchangeResult',
    'SecKeyCopyPublicKey', 'SecKeyCreateEncryptedData',
    'SecKeyCreateDecryptedData', 'SecKeyIsAlgorithmSupported',
    'kSecAttrKeyTypeECSECPrimeRandom', 'kSecAttrKeyTypeEC',
    'kSecAttrKeyClassPublic', 'kSecAttrKeyClassPrivate',
    'kSecAttrKeyClassKeyPair', 'kSecAttrKeySizeInBits',
    'kSecKeyAlgorithmECDSASignatureMessageX962SHA256',
    'kSecKeyAlgorithmECDSASignatureMessageX962SHA384',
    'kSecKeyAlgorithmECDSASignatureDigestX962SHA256',
    'kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256',
    'kSecKeyAlgorithmRSASignatureRaw',
    'kSecKeyAlgorithmECDHKeyExchangeCofactorVariableX963SHA256',
    'kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256',
]

for fname_key, fpath in FILES.items():
    print(f'\n[{fname_key}]')
    if not os.path.exists(fpath):
        print('  [!] Non trouve')
        continue
    data = open(fpath, 'rb').read()
    print(f'  Size: {len(data):,} bytes')

    for sym in APPLE_SEC:
        sb = sym.encode('ascii')
        c = data.count(sb)
        if c > 0:
            positions = []
            pos = 0
            for _ in range(2):
                idx = data.find(sb, pos)
                if idx < 0: break
                positions.append(idx)
                pos = idx + 1
            print(f'  [+] {sym}: {c} fois ({[hex(p) for p in positions]})')

# Recherche compressed EC points (02/03 + 32 octets)
print('\n' + '='*80)
print('  POINTS EC COMPRESSED (02/03 + 32 octets)')
print('='*80)
for fname_key, fpath in FILES.items():
    if not os.path.exists(fpath): continue
    data = open(fpath, 'rb').read()
    count = 0
    for i in range(0, len(data) - 33):
        if data[i] in (0x02, 0x03):
            if sum(1 for b in data[i+1:i+33] if b != 0) > 25:
                count += 1
    print(f'  [{fname_key}] Candidats compressed: {count}')

# Recherche entiers longs (ASN.1 INTEGER 33 octets = 256 bits avec leading zero)
print('\n' + '='*80)
print('  ASN.1 INTEGER 33 octets (256 bits + leading zero) dans contexte EC')
print('='*80)
for fname_key, fpath in FILES.items():
    if not os.path.exists(fpath): continue
    data = open(fpath, 'rb').read()
    count_256 = 0
    for i in range(0, len(data) - 35):
        # 02 21 00 [32 octets] = INTEGER 256 bits (sign byte +32 = leading zero)
        if data[i] == 0x02 and data[i+1] == 0x21 and data[i+2] == 0x00:
            if sum(1 for b in data[i+3:i+35] if b != 0) > 25:
                count_256 += 1
    print(f'  [{fname_key}] Candidats INTEGER 256 bits: {count_256}')

# Recherche contextuelle: SecKeyCreateWithData + SecKeyAlgorithm
print('\n' + '='*80)
print('  CONTEXTE SecKeyCreateWithData dans dylib')
print('='*80)
data = open(FILES['IOS_DYLIB_ARM64'], 'rb').read()
idx = data.find(b'SecKeyCreateWithData')
if idx > 0:
    ctx = data[max(0, idx-100):idx+250]
    asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
    print(f'  Premier SecKeyCreateWithData a 0x{idx:x}')
    print(f'  Contexte: {asc}')

# Toutes les chaines contenant "Algorithm" dans le dylib
print('\n=== Tous les kSecKeyAlgorithm* ===')
for m in re.finditer(rb'kSecKey[A-Za-z0-9_]+', data):
    print(f'  {m.group(0).decode("ascii")}')

print('\n' + '='*80)
print('  FIN')
print('='*80)
