#!/usr/bin/env python3
"""
Extract strings + look for activation/crypto keywords in the largest Mach-O binary.
Target: the heart of the iCloud Activation Lock bypass.
"""
import re
import sys
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
BIN  = WORK / "04_EXTRACTED" / "macho_8ea1a8_EXECUTE_ARM64_ALL.bin"
OUT  = WORK / "03_OUTPUTS" / "ios_binary_strings.txt"
OUT.parent.mkdir(parents=True, exist_ok=True)

print(f"[*] Reading {BIN.name} ...")
data = BIN.read_bytes()
print(f"[*] Size: {len(data):,} bytes ({len(data)/1024/1024:.2f} MB)")

# 1) ASCII strings (>= 6 chars)
ascii_strings = re.findall(rb'[\x20-\x7e]{6,}', data)
print(f"[+] ASCII strings (>=6): {len(ascii_strings):,}")

# 2) UTF-16LE strings (>= 6 wide chars)
utf16_strings = []
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){6,}', data):
    s = m.group().decode('utf-16-le', errors='ignore')
    utf16_strings.append(s)
print(f"[+] UTF-16LE strings (>=6 wide): {len(utf16_strings):,}")

# 3) Categorized keyword search
keywords = {
    'crypto_asym':    [b'RSA', b'ECDSA', b'SecKey', b'SecKeyCreate', b'KeyPair', b'kSecAttr'],
    'crypto_sym':     [b'AES', b'CCCrypt', b'CommonCrypto'],
    'crypto_hash':    [b'SHA256', b'SHA-256', b'SHA1', b'SHA-1', b'MD5'],
    'crypto_cert':    [b'X509', b'Certificate', b'kSecTrust', b'pem', b'p12', b'.p8'],
    'crypto_sign':    [b'verify', b'sign', b'verifySig', b'signature', b'publicKey'],
    'apple_iact':     [b'activation', b'Activate', b'iActivat', b'Activator'],
    'apple_ticket':   [b'ticket', b'receipt', b'Ticket', b'activation_ticket'],
    'apple_bundle':   [b'com.apple', b'com.iremoval', b'com.blackhound', b'com.panyolsoft'],
    'apple_drm':      [b'albert', b'drmHandshake', b'deviceservices'],
    'exploit':        [b'checkm8', b'check_ra1n', b'gaster', b'A12Eraser', b'minaeraser'],
    'network':        [b'http', b'https', b'iremovalpro.com', b'XMLHttpRequest'],
    'security_apis':  [b'SecRandom', b'SecKeyGenerate', b'kSecRandom'],
}

print()
print("=" * 80)
print("KEYWORD ANALYSIS")
print("=" * 80)

all_hits = {}  # category -> list of (string, offset)

# ASCII pass
for s in ascii_strings:
    try:
        s_str = s.decode('ascii', errors='ignore')
    except:
        continue
    s_low = s_str.lower()
    for cat, kws in keywords.items():
        for kw in kws:
            kw_s = kw.decode('ascii', errors='ignore')
            if kw_s.lower() in s_low:
                all_hits.setdefault(cat, []).append((s_str, -1))
                break

# UTF-16 pass
for s in utf16_strings:
    s_low = s.lower()
    for cat, kws in keywords.items():
        for kw in kws:
            kw_s = kw.decode('ascii', errors='ignore')
            if kw_s.lower() in s_low:
                all_hits.setdefault(cat, []).append((s, -1))
                break

for cat in keywords.keys():
    hits = all_hits.get(cat, [])
    # dedup
    seen = set()
    uniq = []
    for s, off in hits:
        if s not in seen:
            seen.add(s)
            uniq.append((s, off))
    print(f"\n[{cat}] {len(uniq)} unique strings")
    for s, off in uniq[:25]:
        disp = s.replace('\n', '\\n')[:130]
        print(f"  {disp}")
    if len(uniq) > 25:
        print(f"  ... and {len(uniq)-25} more")

# Save full ASCII dump for further analysis
print()
print(f"[*] Saving full string dump to {OUT} ...")
with open(OUT, 'w', encoding='utf-8', errors='ignore') as f:
    f.write(f"# Strings extracted from {BIN.name}\n")
    f.write(f"# Size: {len(data):,} bytes\n")
    f.write(f"# ASCII: {len(ascii_strings):,} | UTF-16: {len(utf16_strings):,}\n\n")
    f.write("=== ASCII STRINGS ===\n")
    for s in ascii_strings:
        try:
            f.write(s.decode('ascii') + '\n')
        except:
            pass
    f.write("\n=== UTF-16LE STRINGS ===\n")
    for s in utf16_strings:
        f.write(s + '\n')

print(f"[+] Done")