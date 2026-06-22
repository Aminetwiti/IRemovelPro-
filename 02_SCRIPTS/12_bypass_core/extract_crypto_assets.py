#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extrait et valide les éléments crypto depuis iremovalpro.dll :
  1. Certificat Apple Root CA (X.509 DER) à ~0x89f82b
  2. SHA-256 K-table à 0xa78e59
  3. AES S-box à 0xa7e7a5

Auteur: Audit statique defensif - TLP:LEAKED
"""
import sys, struct, io, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro\iremovalpro.dll'
with open(DLL, 'rb') as f:
    data = f.read()

OUT = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\04_EXTRACTED'
os.makedirs(OUT, exist_ok=True)

print("="*80)
print("  EXTRACTION CRYPTO - iremovalpro.dll")
print(f"  Size: {len(data):,} bytes ({len(data)/1024/1024:.2f} MB)")
print("="*80)

# =============================================================
# 1) CERTIFICAT APPLE ROOT CA - recherche ASN.1 SEQUENCE
# =============================================================
print("\n[1] CERTIFICAT APPLE ROOT CA (X.509 DER)")
print("-"*80)

# On cherche un marqueur ASN.1 SEQUENCE (0x30 0x82) suivi d'une longueur >= 1000
# dans la fenetre 0x89f000 - 0x8a0000
target_window = data[0x89f000:0x8a0000]
best_offset = -1
for i in range(len(target_window) - 4):
    if target_window[i] == 0x30 and target_window[i+1] == 0x82:
        length = (target_window[i+2] << 8) | target_window[i+3]
        if 1000 <= length <= 1500:  # X.509 DER typique
            # Verifier qu'on est pres de "Apple Root CA"
            nearby = data[0x89f000+i:0x89f000+i+200]
            if b'Apple' in nearby or b'Root' in nearby:
                best_offset = 0x89f000 + i
                cert_len = length + 4
                print(f"  [+] ASN.1 SEQUENCE trouve a 0x{best_offset:x}")
                print(f"      Longueur declaree: {length} bytes (0x{length:x})")
                print(f"      Total cert: {cert_len} bytes")
                break

if best_offset > 0:
    cert_der = data[best_offset:best_offset + cert_len]

    # Verifier le marqueur "Apple Root CA" dans le cert
    if b'Apple Root CA' in cert_der:
        apple_pos = cert_der.find(b'Apple Root CA')
        print(f"      'Apple Root CA' trouve a offset interne 0x{apple_pos:x}")
        issuer = cert_der[apple_pos:apple_pos+50]
        print(f"      Issuer: {issuer.decode('ascii', errors='replace')}")

    # Sauvegarder en .der
    cert_path = os.path.join(OUT, 'apple_root_ca_extracted.der')
    with open(cert_path, 'wb') as f:
        f.write(cert_der)
    print(f"      Sauvé: {cert_path}")
    print(f"      SHA-256: {__import__('hashlib').sha256(cert_der).hexdigest()}")
else:
    print("  [!] ASN.1 SEQUENCE non trouve dans la fenetre - recherche etendue")
    # Recherche dans tout le binaire
    for i in range(0, len(data) - 4, 1):
        if data[i] == 0x30 and data[i+1] == 0x82:
            length = (data[i+2] << 8) | data[i+3]
            if length == 1215 or (1200 <= length <= 1250):
                if b'Apple' in data[i:i+500]:
                    print(f"      Trouve a 0x{i:x} (length={length})")
                    cert_der = data[i:i+length+4]
                    cert_path = os.path.join(OUT, 'apple_root_ca_extracted.der')
                    with open(cert_path, 'wb') as f:
                        f.write(cert_der)
                    print(f"      Sauvé: {cert_path}")
                    break

# =============================================================
# 2) SHA-256 K-TABLE à 0xa78e59
# =============================================================
print("\n[2] SHA-256 K-TABLE (64 constantes 32 bits)")
print("-"*80)

# K[0] = 0x428a2f98, en little-endian = 98 2f 8a 42
K_SHA256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
K_SHA256_LE = b''.join(struct.pack('<I', k) for k in K_SHA256)

target = 0xa78e59
if data[target:target+256] == K_SHA256_LE:
    print(f"  [+] SHA-256 K-table VALIDEE à 0x{target:x}")
    print(f"      64 * 4 bytes = 256 bytes")
    print(f"      K[0]  = 0x{K_SHA256[0]:08x}")
    print(f"      K[63] = 0x{K_SHA256[63]:08x}")
else:
    print(f"  [?] Pas de match exact a 0x{target:x}")
    # Recherche dans la zone
    pos = data.find(K_SHA256_LE[:16])
    if pos > 0:
        print(f"      Debut de la K-table trouve a 0x{pos:x} (recherche: 16 octets)")

# =============================================================
# 3) AES S-BOX à 0xa7e7a5
# =============================================================
print("\n[3] AES S-BOX (256 octets)")
print("-"*80)

AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])

target = 0xa7e7a5
if data[target:target+256] == AES_SBOX:
    print(f"  [+] AES S-BOX VALIDEE à 0x{target:x}")
    print(f"      256 octets")
    print(f"      S[0x00] = 0x{AES_SBOX[0]:02x}  (attendu: 0x63)")
    print(f"      S[0x10] = 0x{AES_SBOX[0x10]:02x}  (attendu: 0xca)")
    print(f"      S[0xFF] = 0x{AES_SBOX[0xff]:02x}  (attendu: 0x16)")
else:
    print(f"  [?] Pas de match exact a 0x{target:x}")
    # Recherche
    pos = data.find(AES_SBOX[:16])
    if pos > 0:
        print(f"      Debut de la S-Box trouve a 0x{pos:x}")

# =============================================================
# 4) BLOCS ECDSA
# =============================================================
print("\n[4] RECHERCHE BLOCS ECDSA")
print("-"*80)

# OID ECDSA: 1.2.840.10045.2.1 = 06 07 2a 86 48 ce 3d 02 01
ecdsa_oid = bytes([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
positions = []
start = 0
while True:
    pos = data.find(ecdsa_oid, start)
    if pos < 0: break
    positions.append(pos)
    start = pos + 1
print(f"  [+] OID ECDSA (1.2.840.10045.2.1) trouve: {len(positions)} fois")
for p in positions[:5]:
    ctx = data[max(0,p-20):p+50]
    print(f"      0x{p:x}  (contexte: {ctx[:30].hex()})")

# OID secp256r1 (P-256): 1.2.840.10045.3.1.7 = 06 08 2a 86 48 ce 3d 03 01 07
secp256r1_oid = bytes([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
positions_p256 = []
start = 0
while True:
    pos = data.find(secp256r1_oid, start)
    if pos < 0: break
    positions_p256.append(pos)
    start = pos + 1
print(f"  [+] OID secp256r1 (P-256) trouve: {len(positions_p256)} fois")

print("\n" + "="*80)
print("  EXTRACTION TERMINEE")
print("="*80)
