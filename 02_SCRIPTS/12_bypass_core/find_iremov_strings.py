#!/usr/bin/env python3
"""
Find all iRemoval-specific strings and HTTP body format strings.
"""
import re
import struct
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# 1. All iRemoval-related strings
print("="*80)
print("iRemoval-specific strings (UTF-16LE)")
print("="*80)
for s in ['iRemoval', 'iActivator', 'iRecord', 'iSig', 'iActiv',
          'Tiremovalpro', 'iremovalpro', 'iremovalActivation',
          'com.iremovalpro.bypass', 'com.panyolsoft',
          'iact8', 'iact7', 'iact6', 'iact', 'mf7', 'mf6', 'mf5',
          'checkm8', 'ars2', 'auth3', 'version33', 'pub',
          'iRemovalRecord', 'iRemovalSignature', 'iRemovalTicket',
          'iRemovalKey', 'iRemovalNonce', 'iRemovalSession',
          'iDevice', 'iDeviceProx', 'mobileactivationd',
          'check_ra1n', 'gaster', 'pwn', 'limera1n']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        # Find string context
        start = idx
        while start > 0 and data[start-1] == 0x00 and 0x20 <= data[start-2] < 0x7f:
            start -= 2
        end = idx + len(s_u)
        while end < len(data) - 1 and data[end+1] == 0x00 and 0x20 <= data[end] < 0x7f:
            end += 2
        ctx = data[start:end].decode('utf-16-le', errors='ignore')
        print(f"  [{s}]: {cnt} occurrences, first at 0x{idx:08x}")
        if len(ctx) > len(s) + 2:
            print(f"    Context: {ctx[:200]}")

# 2. Look for the actual format strings used in JSON body
print("\n" + "="*80)
print("JSON-like format strings with {{ and {0}")
print("="*80)

# The pattern is: '{{ "key": "value" }}'
# In .NET String.Format, {{ = { and }} = }
# So "{{"key1":"value1","key2":"value2"}}" in code = {"key1":"value1","key2":"value2"} at runtime
# We need to find: {{...}} where ... contains quoted keys

# Find all "...":{0} patterns in UTF-16LE
for pat_str in ['":"{0}"', '":{0}', '":\\"{0}\\"', '": "{0}"',
                '","{0}":', '","{0}":"{1}"', ',"{0}":',
                '"key":', ',"key":', ',"{0}":', '\\"{0}\\":']:
    pat = pat_str.encode('utf-16-le')
    cnt = data.count(pat)
    if cnt > 0:
        print(f"  '{pat_str}': {cnt}")

# Look for the literal "UDID", "serial", "IMEI" as JSON keys
print("\n" + "="*80)
print("JSON keys (with quotes)")
print("="*80)
for key in ['UDID', 'SerialNumber', 'IMEI', 'MEID', 'ECID', 'ChipID',
            'ModelNumber', 'ProductType', 'ProductVersion', 'MLB',
            'UniqueChipID', 'UniqueDeviceID', 'ActivationState',
            'ActivationTicket', 'iRemovalRecord', 'iRemovalSignature',
            'BoardID', 'RegionInfo', 'DeviceCertRequest']:
    quoted = f'"{key}"'.encode('utf-16-le')
    cnt = data.count(quoted)
    if cnt > 0:
        print(f"  \"{key}\": {cnt}")

# 3. Look for HTTP request body format
print("\n" + "="*80)
print("HTTP/JSON content type")
print("="*80)
for s in ['application/json', 'application/x-www-form-urlencoded',
          'text/plain', 'text/json', 'multipart/form-data',
          'application/x-www-urlencoded', 'Content-Type: application/json',
          '"Content-Type": "application/json"', 'Accept: application/json',
          'User-Agent', 'X-Requested-With', 'X-Api-Key', 'X-Auth-Token']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        print(f"  '{s}': {cnt}")

# 4. Look for AES/HMAC parameters
print("\n" + "="*80)
print("Crypto parameters")
print("="*80)
for s in ['AES', 'CBC', 'ECB', 'GCM', 'CTR', 'CFB', 'OFB',
          'PKCS7', 'PKCS5', 'NoPadding', 'Zeros', 'ANSIX923',
          'SHA256', 'SHA-256', 'SHA1', 'SHA-1', 'MD5',
          'HMACSHA256', 'HMACSHA1', 'HMACMD5',
          'GenerateKey', 'GenerateIV', 'CreateEncryptor', 'CreateDecryptor',
          'KeySize', 'BlockSize', 'FeedbackSize', 'Mode', 'Padding',
          'Rfc2898DeriveBytes', 'PasswordDeriveBytes', 'DeriveBytes',
          'HashAlgorithmName.SHA256', 'HashAlgorithmName.SHA1',
          'PBKDF2', 'Pbkdf2Params', 'iterationCount', 'IterationCount']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        print(f"  '{s}': {cnt}")

# 5. Find the request build code patterns
print("\n" + "="*80)
print("RestSharp / HTTP request patterns")
print("="*80)
for s in ['AddJsonBody', 'AddParameter', 'AddQueryParameter', 'AddHeader',
          'AddBody', 'AddJson', 'AddObject', 'AddXml',
          'RequestFormat.Json', 'DataFormat.Json', 'Method.POST',
          'RestSharp.RestRequest', 'RestSharp.RestClient',
          'IRestClient', 'IRestRequest', 'IRestResponse',
          'HttpStatusCode.OK', 'HttpStatusCode.Accepted',
          'ExecuteAsync', 'ExecuteRequestAsync',
          'X-Forwarded-For', 'X-Real-IP', 'X-Request-Id',
          'PHPSESSID', 'Set-Cookie', 'Cookie:']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        print(f"  '{s}': {cnt} (first at 0x{idx:x})")

# 6. Look for the activation record format (Apple plist keys)
print("\n" + "="*80)
print("Apple plist keys in .NET")
print("="*80)
for key in ['ActivationState', 'ActivationRecord', 'SerialNumber', 'IMEI',
            'MEID', 'UniqueDeviceID', 'UniqueChipID', 'ProductType',
            'ProductVersion', 'MLB', 'BasebandMasterKeyHash',
            'ActivationInfo', 'ActivationTicket']:
    pat = f'<key>{key}</key>'.encode('utf-16-le')
    cnt = data.count(pat)
    if cnt > 0:
        print(f"  <key>{key}</key>: {cnt}")
    pat2 = key.encode('utf-16-le')
    cnt2 = data.count(pat2)
    if cnt2 > 0:
        print(f"  '{key}': {cnt2}")