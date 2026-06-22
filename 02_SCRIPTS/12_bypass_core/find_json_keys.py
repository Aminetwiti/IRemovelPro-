#!/usr/bin/env python3
"""
Search the .NET 8 NativeAOT string pool for ALL JSON keys related to iRemoval.
The pool uses a 4-byte length prefix followed by UTF-16LE data.
"""
import re
import struct
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# The .NET 8 NativeAOT string pool is in the .managed section (6.7MB)
# Section: .managed RVA=0x000ca000 VSIZE=0x00675fc8 RAW=0x000c9000

# Get section info
pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
section_table_offset = pe_offset + 24 + opt_header_size
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]

sections = {}
for i in range(num_sections):
    off = section_table_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vaddr = struct.unpack_from('<I', data, off + 12)[0]
    rawsize = struct.unpack_from('<I', data, off + 16)[0]
    rawptr = struct.unpack_from('<I', data, off + 20)[0]
    sections[name] = {'vaddr': vaddr, 'rawsize': rawsize, 'rawptr': rawptr}

# Find the .managed section
for s in sections:
    if 'managed' in s.lower():
        mng = sections[s]
        mng_data = data[mng['rawptr']:mng['rawptr']+mng['rawsize']]
        print(f"[*] {s}: rawptr=0x{mng['rawptr']:x} size={len(mng_data):,}")
        break

# The string pool within .managed has a specific structure
# Each entry: 4 bytes (length-compressed) + UTF-16LE data

# Let me search for the JSON keys directly
# Common iActivation JSON keys:
json_keys = [
    'UDID', 'SerialNumber', 'IMEI', 'MEID', 'ECID', 'ChipID', 'ModelNumber',
    'ProductType', 'ProductVersion', 'MLB', 'UniqueChipID', 'UniqueDeviceID',
    'ActivationState', 'ActivationTicket', 'iRemovalRecord', 'iRemovalSignature',
    'device', 'udid', 'serial', 'ticket', 'signature', 'activation', 'cert',
    'data', 'payload', 'response', 'status', 'error', 'message', 'code',
    'success', 'fail', 'error', 'ok', 'nonce', 'session', 'token', 'auth',
    'user', 'pass', 'username', 'password', 'email', 'phone', 'name',
    'identifier', 'imei', 'meid', 'imei2', 'meid2', 'sn', 'ecid', 'cid',
    'model', 'product', 'board', 'region', 'carrier', 'subscriber',
    'iccid', 'imsi', 'wifi', 'mac', 'bluetooth', 'gps', 'version',
    'build', 'platform', 'firmware', 'ios', 'os', 'kernel', 'baseband',
    'hardware', 'device_model', 'ios_version', 'apnonce', 'sepnonce',
    'checkm8', 'csrf', 'exploit', 'trunk', 'nonce_seed', 'gaster',
    'demote', 'iBoot', 'iboot', 'iBEC', 'ibec', 'iBSS', 'ibss', 'DFU',
    'recovery', 'restore', 'erase', 'reset', 'wipe', 'bypass', 'jailbreak',
    'unlock', 'sim', 'carrier', 'att', 'tmobile', 'verizon', 'sprint',
    'gsm', 'lte', '5g', '4g', '3g', 'cdma', 'wcdma', 'umts',
    'hwid', 'serial_number', 'device_id', 'board_id', 'chip_id',
    'fmi', 'find_my_iphone', 'find_my', 'icloud', 'apple_id', 'logged_in',
    'cloud_lock', 'activation_lock', 'blacklist', 'blocked', 'reported',
    'stolen', 'lost', 'policy', 'enterprise', 'mdm', 'dep', 'profile',
    'enroll', 'remove', 'supervised', 'purchased', 'demo', 'returner',
    'kdf', 'pbkdf2', 'aes', 'hmac', 'sha256', 'rsa', 'ecdsa', 'cert',
    'x509', 'pem', 'der', 'p12', 'pfx', 'key', 'public', 'private',
    'sign', 'verify', 'encrypt', 'decrypt', 'hash', 'digest', 'mac',
    'iv', 'salt', 'iteration', 'round', 'block', 'cipher', 'mode',
    'cbc', 'ctr', 'gcm', 'ecb', 'padding', 'pkcs7', 'pss', 'oaep'
]

print(f"\n[*] Searching {len(json_keys)} JSON keys in entire DLL...")
found = {}
for key in json_keys:
    # Search in UTF-16LE
    key_u16 = key.encode('utf-16-le')
    cnt = data.count(key_u16)
    if cnt > 0:
        found[key] = cnt

# Sort by count
print(f"\n[+] Found {len(found)} JSON-like keys")
for k, c in sorted(found.items(), key=lambda x: -x[1])[:60]:
    print(f"  {k}: {c}")

# Also look for the URL parameters (?key=value&key2=value2)
print("\n[*] Searching for URL parameters (?=)...")
for kw in ['udid', 'serial', 'imei', 'meid', 'ecid', 'model', 'apnonce', 'srnm',
           'snum', 'mn', 'pn', 'sn', 'pn', 'mac', 'wifi', 'board', 'chip',
           'region', 'carrier', 'g_id', 'gid', 'session_id', 'nonce', 'token']:
    pat = ('?' + kw + '=').encode('utf-16-le')
    cnt = data.count(pat)
    if cnt > 0:
        print(f"  ?{kw}=: {cnt}")

# Look for actual JSON body keys
print("\n[*] Searching for JSON body patterns (UTF-16LE)...")
for pat in ['"udid":', '"serial":', '"imei":', '"signature":', '"ticket":',
            '"data":', '"response":', '"success":', '"error":', '"device":',
            '"UDID":', '"SerialNumber":', '"ActivationState":', '"ECID":']:
    pat_u = pat.encode('utf-16-le')
    cnt = data.count(pat_u)
    if cnt > 0:
        print(f"  {pat}: {cnt}")

# Look for RestSharp-specific request setup
print("\n[*] Searching for RestSharp-specific strings (UTF-16LE)...")
rs = ['AddJsonBody', 'AddParameter', 'AddQueryParameter', 'AddHeader',
      'RequestFormat', 'JsonRequestBehavior', 'Method = ', 'Resource =',
      'Execute<T>', 'ExecuteAsync', 'IRestResponse', 'RestClient', 'RestRequest',
      'HttpStatusCode', 'ContentType', 'Application/Json', 'application/json',
      'ContentLength', 'UserAgent', 'User-Agent', 'Authorization']
for k in rs:
    k_u = k.encode('utf-16-le')
    cnt = data.count(k_u)
    if cnt > 0:
        print(f"  {k}: {cnt}")

# Look for the URL parameter pattern
print("\n[*] Searching for ?key= URL parameters...")
for kw in ['?udid', '?serial', '?imei', '?meid', '?ecid', '?nonce',
           '?session', '?token', '?key', '?sig', '?mac', '?k=', '?s=']:
    pat = kw.encode('utf-16-le')
    cnt = data.count(pat)
    if cnt > 0:
        print(f"  {kw}: {cnt}")

# Look for the actual request patterns
print("\n[*] Looking for HTTP header constants (UTF-16LE)...")
hdr = ['Content-Type', 'Authorization', 'User-Agent', 'Accept', 'Accept-Encoding',
       'Cookie', 'Host', 'Referer', 'X-', 'HTTP/1.1', 'UserId', 'UserName']
for h in hdr:
    h_u = h.encode('utf-16-le')
    cnt = data.count(h_u)
    if cnt > 0:
        print(f"  {h}: {cnt}")