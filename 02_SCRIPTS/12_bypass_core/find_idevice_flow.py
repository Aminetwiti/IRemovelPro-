#!/usr/bin/env python3
"""
Find the full iRemoval flow:
1. ideviceproxy command (iOS communication)
2. JSON body format
3. iOS app behavior
"""
import re
import struct
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# 1. Find ideviceproxy command (long UTF-16LE string)
print("="*80)
print("ideviceproxy command context")
print("="*80)
idx = 0
while True:
    idx = data.find('ideviceproxy'.encode('utf-16-le'), idx)
    if idx == -1:
        break
    # Get context
    s = idx
    while s > 0 and data[s-1] == 0x00 and 0x20 <= data[s-2] < 0x7f:
        s -= 2
    e = idx + len('ideviceproxy')*2
    while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
        e += 2
    ctx = data[s:e].decode('utf-16-le', errors='ignore')
    print(f"  0x{idx:08x}: {ctx[:300]}")
    idx += 1

# 2. Find idevice commands
print("\n" + "="*80)
print("Other idevice commands")
print("="*80)
for cmd in ['idevice_id', 'ideviceinfo', 'idevicebackup2', 'idevicerestore',
            'idevicedebug', 'idevicediagnostics', 'idevicesyslog', 'idevicepair',
            'idevicebackup', 'ideviceprovision', 'ideviceimagemounter',
            'ideviceactivation', 'ideviceenterrecovery', 'idevicedate',
            'idevicename', 'idevicescreenshot', 'idevice_purge',
            'idevicebt_packetlogger', 'idevicecrashreport',
            'afcclient', 'sbservices', 'prefs', 'lockdown', 'lockdownd',
            'usbmuxd', 'muxer', 'AFC', 'lockdown_get']:
    cmd_u = cmd.encode('utf-16-le')
    cnt = data.count(cmd_u)
    if cnt > 0:
        idx = data.find(cmd_u)
        s = idx
        while s > 0 and data[s-1] == 0x00 and 0x20 <= data[s-2] < 0x7f:
            s -= 2
        e = idx + len(cmd_u)
        while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
            e += 2
        ctx = data[s:e].decode('utf-16-le', errors='ignore')
        print(f"  {cmd}: {cnt} (first at 0x{idx:x})")
        if len(ctx) > len(cmd) + 2:
            print(f"    Context: {ctx[:200]}")

# 3. Find the JSON body sent to server
# Look for "application/json" context
print("\n" + "="*80)
print("application/json context")
print("="*80)
idx = data.find('application/json'.encode('utf-16-le'))
if idx > 0:
    s = max(0, idx - 500)
    e = min(len(data), idx + 500)
    ctx = data[s:e]
    # Find printable substrings
    print(f"  At 0x{idx:x}")
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,}', ctx):
        offset = m.start() + s
        st = m.group().decode('utf-16-le', errors='ignore')
        if st and len(st) > 2:
            print(f"    0x{offset:08x}: {st[:200]}")

# 4. Find HTTP body structure - look for serialized JSON patterns
# Common pattern: @"key":"value" or "key" : "value"
print("\n" + "="*80)
print("JSON body construction patterns (look for literal quotes around keys)")
print("="*80)
# In .NET, JSON is often built with String.Format like:
# string body = string.Format("{{\"key1\":\"{0}\",\"key2\":\"{1}\"}}", val1, val2);
# So we look for: "{"key": ... or "\"{0}\":\"{1}\""

# In UTF-16LE, this would be: "{"key":" or "{\"key\":\" (with escapes)
for pat in [
    '{\\"', '\\"{0}\\":\\"', '\\"{0}\\":', '\\"{0}\\":{1}', '\\"{0}\\":\\"{1}\\"',
    '\\"{0}\\":[{1}]', '\\"{0}\\":{{\\"', '\\"key\\":\\"',
    '\\\\\\"',  # triple backslash
    '{0}\\":\\"',  # the second key starts after a comma
    ',\\"', '\\",\\"', '\\"}}',
    'bypass\\"', 'iRemoval\\"', 'iCloud\\"',
    'key\\":\\"', 'value\\":\\"'
]:
    pat_u = pat.encode('utf-16-le')
    cnt = data.count(pat_u)
    if cnt > 0:
        print(f"  {repr(pat)}: {cnt}")

# 5. Find specific JSON keys (with quotes around)
# In .NET code: "UDID" or "SerialNumber" might appear as raw strings
print("\n" + "="*80)
print("JSON-like patterns (looking for raw quoted keys)")
print("="*80)
for key in ['UDID', 'SerialNumber', 'IMEI', 'MEID', 'ECID',
            'ActivationState', 'ActivationRecord', 'iRemovalRecord',
            'UniqueDeviceID', 'UniqueChipID', 'ProductType', 'ProductVersion',
            'ModelNumber', 'MLB', 'BoardID', 'ChipID']:
    # Look for the key in UTF-16LE (no quotes needed - check the context)
    key_u = key.encode('utf-16-le')
    for i in range(0, len(data) - len(key_u), 2):
        if data[i:i+len(key_u)] == key_u:
            # Check if it's inside a JSON-like template (look for { or " nearby)
            ctx_start = max(0, i - 50)
            ctx_end = min(len(data), i + 100)
            ctx = data[ctx_start:ctx_end]
            # Decode
            try:
                ctx_str = ctx.decode('utf-16-le', errors='ignore')
                if '{' in ctx_str or '}' in ctx_str or '"' in ctx_str or ':' in ctx_str:
                    if any(p in ctx_str for p in ['{0}', '{1}', '{2}']):
                        print(f"  '{key}' at 0x{i:08x}:")
                        print(f"    Context: {ctx_str[:250]}")
                        break
            except:
                pass

# 6. Look for the full HTTP request flow
print("\n" + "="*80)
print("HTTP request flow (Content-Type, Authorization)")
print("="*80)
for s in ['Content-Type: application/json', 'Content-Type:application/json',
          'Authorization: Bearer', 'Authorization: Basic', 'X-Auth-Token',
          'X-Api-Key', 'X-Authorization', 'X-Request-Id', 'X-Forwarded-For',
          'X-Real-IP', 'X-Client-Id', 'X-Session-Token',
          'application/json; charset=utf-8', 'Accept: application/json',
          'User-Agent: iRemoval', 'PHPSESSID', 'Set-Cookie:']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        print(f"  '{s}': {cnt} (at 0x{idx:x})")

# 7. Find all UTF-16LE strings starting with "i" and "I" (iOS bundle ID related)
print("\n" + "="*80)
print("All bundle IDs in the .NET binary")
print("="*80)
for pat in [b'com.apple', b'com.iremoval', b'com.blackhound', b'com.panyolsoft',
            b'com.iremovalpro.bypass', b'com.iremovalpro.activation']:
    pat_u = pat.decode('ascii').encode('utf-16-le')
    cnt = data.count(pat_u)
    if cnt > 0:
        idx = data.find(pat_u)
        # Get context
        s = idx
        while s > 0 and data[s-1] == 0x00 and 0x20 <= data[s-2] < 0x7f:
            s -= 2
        e = idx + len(pat_u)
        while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
            e += 2
        ctx = data[s:e].decode('utf-16-le', errors='ignore')
        print(f"  {pat.decode()}: {cnt} - Context: {ctx[:150]}")