#!/usr/bin/env python3
"""Get SHA-256 of bypass RSA public key and its modulus."""
import base64, hashlib

pem_text = open(r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\04_EXTRACTED\blackhound_rsa_pubkey.pem').read()
body = pem_text.split('-----')[2].replace('\n', '').replace('\r', '')
der = base64.b64decode(body)
print(f'DER size: {len(der)} bytes')
print(f'SHA-256 (modulus+exp): {hashlib.sha256(der).hexdigest()}')
print(f'MD5 (modulus+exp):     {hashlib.md5(der).hexdigest()}')
print()
# Find modulus (RSA-1024: 128 bytes)
modulus_start = der.find(b'\x02\x82\x01\x01\x00') + 4
modulus = der[modulus_start:modulus_start+128]
print(f'Modulus (128 bytes = 1024 bits):')
print(f'  hex:  {modulus.hex().upper()}')
print(f'  SHA-256: {hashlib.sha256(modulus).hexdigest()}')
print(f'  MD5:     {hashlib.md5(modulus).hexdigest()}')
print(f'  SHA-1:   {hashlib.sha1(modulus).hexdigest()}')
