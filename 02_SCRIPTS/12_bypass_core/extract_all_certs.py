#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extraction complete des certificats X.509 et cles RSA depuis iremovalpro.dll
Identifie le role de chaque certificat (Apple, iRemoval, attaquant).
"""
import sys, os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro\iremovalpro.dll'
OUT = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\04_EXTRACTED\apple_certs'
os.makedirs(OUT, exist_ok=True)

data = open(DLL, 'rb').read()

print("="*80)
print("  EXTRACTION DES CERTIFICATS X.509")
print("="*80)

# ASN.1 SEQUENCE (0x30 0x82) = debut d'un certificat DER typique
# On cherche toutes les sequences avec longueur >= 500
print("\n[1] Recherche de toutes les SEQUENCE ASN.1 (candidats X.509)...")

candidates = []
i = 0
while i < len(data) - 4:
    if data[i] == 0x30 and data[i+1] == 0x82:
        length = (data[i+2] << 8) | data[i+3]
        if 500 <= length <= 2500:
            # Verifier qu'on a un cert valide (chercher "Apple" ou "iRemoval" a proximite)
            nearby = data[i:i+min(length+4, 2000)]
            if b'Apple' in nearby or b'iRemoval' in nearby or b'Removal' in nearby or b'panyolsoft' in nearby or b'CN=' in nearby:
                candidates.append((i, length, nearby[:200]))
            i += length + 4
        else:
            i += 1
    else:
        i += 1

print(f"\n  [+] {len(candidates)} certificat(s) candidat(s) trouve(s)")

import hashlib
saved = []
for idx, (offset, length, preview) in enumerate(candidates):
    cert_der = data[offset:offset+length+4]
    h = hashlib.sha256(cert_der).hexdigest()

    # Identifier le contenu
    txt = preview.decode('ascii', errors='replace')[:150]
    print(f"\n  Cert #{idx+1} a 0x{offset:x} ({length} bytes)")
    print(f"     SHA-256: {h}")
    print(f"     Apercu:  {txt[:120]!r}")

    # Sauver
    fname = f'cert_{idx+1:02d}_0x{offset:08x}.der'
    path = os.path.join(OUT, fname)
    with open(path, 'wb') as f:
        f.write(cert_der)
    saved.append((idx+1, offset, length, h, path))
    print(f"     Sauvé:   {fname}")

print("\n" + "="*80)
print("  ANALYSE OPENSSL DE CHAQUE CERT")
print("="*80)

import subprocess
OPENSLL = r'C:\cygwin64\bin\openssl.exe'

for idx, offset, length, h, path in saved:
    print(f"\n--- Cert #{idx} (0x{offset:x}, {length} bytes) ---")
    try:
        result = subprocess.run(
            [OPENSLL, 'x509', '-in', path, '-inform', 'DER',
             '-subject', '-issuer', '-dates', '-fingerprint', '-sha256',
             '-noout'],
            capture_output=True, text=True, timeout=10
        )
        print(result.stdout if result.stdout else result.stderr)
    except Exception as e:
        print(f"  Erreur: {e}")

# Recherche cles RSA isolees (sans wrapper cert)
print("\n" + "="*80)
print("  CLES RSA ISOLEES (PKCS#1 ou PKCS#8)")
print("="*80)

# PKCS#1 RSA Public Key: 30 82 01 [0A+padding] 02 82 01 01 00 [modulus]
# Plus simple: chercher les 256 octets qui suivent 0x02 0x82 0x01 0x01 0x00 (modulus 2048 bits)
# ou 0x02 0x82 0x01 0x00 0x00 (leading zero)
print("  Recherche de modulus RSA 2048 bits (256 octets)...")

# En ASN.1 INTEGER 2048 bits: 02 82 01 01 00 (leading zero pour 2048) ou 02 82 01 00
# Suivi de 256 octets de modulus
modulus_count = 0
for i in range(0, len(data) - 270):
    # 02 82 01 01 00 = INTEGER, 257 bytes, leading zero
    if (data[i] == 0x02 and data[i+1] == 0x82 and data[i+2] == 0x01
        and data[i+3] in (0x00, 0x01) and data[i+4] == 0x00):
        # Verifier que les 256 octets suivants semblent un modulus (non-trivial)
        modulus = data[i+5:i+5+256]
        if len(modulus) == 256 and not all(b == 0 for b in modulus):
            # Compter bits significatifs
            non_zero = sum(1 for b in modulus if b != 0)
            if non_zero > 200:  # Real modulus
                modulus_count += 1
                if modulus_count <= 5:
                    print(f"  [+] Modulus RSA 2048 a 0x{i:x} ({non_zero}/256 bytes non-zero)")

print(f"\n  [+] Total modulus RSA 2048 detectes: {modulus_count}")

print("\n" + "="*80)
print("  RÉSUMÉ")
print("="*80)
print(f"  Certificats X.509 extraits:    {len(saved)}")
print(f"  Modulus RSA 2048 candidats:   {modulus_count}")
print(f"  Dossier de sortie:            {OUT}")
