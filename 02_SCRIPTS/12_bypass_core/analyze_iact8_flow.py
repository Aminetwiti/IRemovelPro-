#!/usr/bin/env python3
"""
Analyze iremovalpro.dll for iact8.php request structure and server communication.
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

print(f"[*] {DLL.name}: {len(data):,} bytes")

# 1. Find iact8 in UTF-16LE
target_utf16 = 'iremovalActivation/iact8'.encode('utf-16-le')
idx = data.find(target_utf16)
print(f"\n[*] iact8 UTF-16LE at offset: 0x{idx:x}" if idx >= 0 else "[!] Not found")

if idx >= 0:
    chunk_size = 8192
    start = max(0, idx - chunk_size)
    end = min(len(data), idx + chunk_size)
    chunk = data[start:end]

    print(f"\n[*] Context window: 0x{start:x} - 0x{end:x} ({chunk_size*2} bytes)")
    print()

    # ASCII strings in this range
    print("=== ASCII strings near iact8 (sorted) ===")
    ascii_strs = sorted(set(s.decode('ascii', errors='ignore')
                            for s in re.findall(rb'[\x20-\x7e]{6,}', chunk)))
    for s in ascii_strs:
        if len(s) < 130:
            print(f"  {s}")

    print()
    print("=== UTF-16LE strings near iact8 (sorted) ===")
    utf16_strs = set()
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', chunk):
        s = m.group().decode('utf-16-le', errors='ignore')
        if s not in utf16_strs:
            utf16_strs.add(s)
    for s in sorted(utf16_strs):
        if len(s) < 130:
            print(f"  {s}")

# 2. Look for HMAC, AES, signing strings throughout the DLL
print()
print("=" * 80)
print("=== Crypto API references in iremovalpro.dll (UTF-16LE) ===")
print("=" * 80)
patterns = {
    'HMAC': ['HMACSHA', 'HMACSHA1', 'HMACSHA256', 'hmac', 'HMAC', 'Hmac'],
    'AES':  ['AesManaged', 'AesCreateEncryptor', 'Aes.Create', 'AES.Create', 'AES/'],
    'RSA':  ['RSACryptoServiceProvider', 'RSA.Create', 'RSACng', 'FromXmlString'],
    'SHA':  ['SHA256Managed', 'SHA-256', 'SHA256', 'SHA1', 'sha256', 'sha1'],
    'JWT':  ['JWT', 'jwt', 'JsonWebToken'],
    'RestSharp': ['RestSharp', 'RestRequest', 'RestResponse', 'IRestClient'],
    'JSON':  ['Newtonsoft', 'JsonConvert', 'JObject', 'JToken', 'JProperty'],
    'Curl':  ['curl', 'libcurl', 'CURL'],
    'BouncyCastle': ['BouncyCastle', 'Org.BouncyCastle'],
    'Encoding': ['Base64Url', 'UrlEncode', 'UrlDecode', 'UTF8Encoding'],
}

for cat, kws in patterns.items():
    print(f"\n[{cat}]")
    for kw in kws:
        kw_u = kw.encode('utf-16-le')
        cnt = len(re.findall(re.escape(kw_u), data))
        if cnt > 0:
            print(f"  {kw}: {cnt} occurrences (UTF-16LE)")

# 3. Look for JSON request template patterns
print()
print("=" * 80)
print("=== JSON template patterns near iact8 ===")
print("=" * 80)
if idx >= 0:
    # Look for patterns like "key":"value" in UTF-16
    chunk = data[max(0,idx-8192):min(len(data),idx+8192)]
    # UTF-16LE version of:  "key":  or  "key"=
    pattern = re.compile(rb'([\x20-\x7e]\x00){4,60}\x22\x00')  # "key"
    matches = list(pattern.finditer(chunk))
    print(f"  Potential JSON keys: {len(matches)}")
    seen = set()
    for m in matches[:40]:
        s = m.group().decode('utf-16-le', errors='ignore')
        if s not in seen and 3 < len(s) < 60:
            seen.add(s)
            print(f"    {s}")