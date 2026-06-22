#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 4+ — Deep Driver class analysis.

Builds on re_deep.py to identify Driver class methods,
state machine implementations, and iDevice method references.
"""
import sys, struct, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
OUT_MD = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\01_REPORTS\DRIVER_DEEP_ANALYSIS.md'

with open(DLL, 'rb') as f:
    data = f.read()

print("="*80)
print("Phase 4+ — Driver Class Deep Analysis (extension to re_deep*.py)")
print("="*80)

# ==== A) Extract all Driver class methods (UTF-16LE strings) ====
# Search all UTF-16LE strings that start with "Driver." or "iDevice_"

def find_utf16(needle, limit=200):
    n16 = needle.encode('utf-16-le')
    out = []
    pos = 0
    while True:
        p = data.find(n16, pos)
        if p < 0: break
        out.append(p)
        pos = p + 1
        if len(out) >= limit: break
    return out

def read_utf16_at(pos, max_bytes=400):
    end = pos
    while end < pos + max_bytes and end < len(data):
        if data[end] == 0 and data[end+1] == 0:
            break
        end += 2
    try:
        return data[pos:end].decode('utf-16-le', errors='replace')
    except:
        return None

# ==== Driver class identifiers ====
print("\n[A] Driver Class Method Identifiers (UTF-16LE)")
print("-"*60)
driver_methods = []
patterns = [
    b'Driver.\x00', b'iDevice_\x00', b'<BypassMeidSignal>\x00',
    b'<CommonConnectDevice>\x00', b'<CheckIOS>\x00',
    b'<Install>\x00', b'<InstallFromLocal>\x00',
    b'<WatchForCompletion>\x00', b'<GetDeviceLink>\x00',
    b'<RestoreBackup>\x00', b'<VersionExchange>\x00',
]
for pat in patterns:
    positions = []
    pos = 0
    while True:
        p = data.find(pat, pos)
        if p < 0: break
        # Read full string from this position
        s = read_utf16_at(p)
        if s:
            positions.append((p, s))
        pos = p + 1
    if positions:
        print(f"\n  Pattern: {pat.decode().rstrip(chr(0))!r}  ({len(positions)} hits)")
        for p, s in positions[:8]:
            print(f"    0x{p:08x}: {s[:80]!r}")
        driver_methods.extend(positions)

# ==== B) iDevice methods complete list ====
print("\n[B] All iDevice_* Method Identifiers")
print("-"*60)
idevice_methods = {}
m_pat = b'iDevice_\x00'
pos = 0
while True:
    p = data.find(m_pat, pos)
    if p < 0: break
    s = read_utf16_at(p, 100)
    if s and 'iDevice_' in s:
        # Extract method name (iDevice_xxx)
        match = re.match(r'(iDevice_\w+)', s)
        if match:
            name = match.group(1)
            idevice_methods[name] = idevice_methods.get(name, 0) + 1
    pos = p + 1

print(f"  Total unique iDevice_* methods: {len(idevice_methods)}")
for name in sorted(idevice_methods.keys()):
    count = idevice_methods[name]
    print(f"    {name:35s}  x{count}")

# ==== C) Driver class state machines (async) ====
print("\n[C] Async State Machines (StateMachineType names)")
print("-"*60)
state_machines = []
patterns_sm = [
    b'<BypassMeidSignal>\x00',
    b'<CommonConnectDevice>\x00',
    b'<CheckIOS>\x00',
    b'<Install>\x00',
    b'<InstallFromLocal>\x00',
    b'<WatchForCompletion>\x00',
    b'<GetDeviceLink>\x00',
    b'<RestoreBackup>\x00',
    b'<VersionExchange>\x00',
    b'<Imei_MouseDown>\x00',
    b'<Sn_MouseDown>\x00',
    b'<Button_Click_5>\x00',
    b'<iDevice_RemoveProfiles>\x00',
]
for pat in patterns_sm:
    n16 = pat.rstrip(b'\x00').decode('ascii')
    positions = find_utf16(pat, 50)
    if positions:
        print(f"  {n16:35s}  hits={len(positions)}")
        state_machines.append((n16, len(positions)))

# ==== D) Driver class-related types ====
print("\n[D] Driver Class-Related .NET Types (UTF-16LE)")
print("-"*60)
driver_types = []
type_patterns = [
    b'iremovalpro.Driver\x00',
    b'iremovalpro.iDevice\x00',
    b'iremovalpro.iRemovalRecord\x00',
    b'iremovalpro.iRemovalSignature\x00',
    b'iremovalpro.Eraser\x00',
    b'iremovalpro.BypassMeidSignal\x00',
    b'iremovalpro.LockerKeys\x00',
]
for pat in type_patterns:
    positions = find_utf16(pat, 5)
    for p in positions:
        s = read_utf16_at(p, 100)
        if s and '\x00' not in s[:50]:
            print(f"    0x{p:08x}: {s[:80]!r}")
            driver_types.append(s)

# ==== E) Cross-reference with iOS lockdownd services ====
print("\n[E] iOS Lockdown Service Names (used by Driver)")
print("-"*60)
lockdown_services = [
    b'com.apple.mobile.lockdown\x00',
    b'com.apple.mobileactivationd\x00',
    b'com.apple.MobileActivation\x00',
    b'com.apple.mobilebackup\x00',
    b'com.apple.mobile.backup\x00',
    b'com.apple.mobile.installation_proxy\x00',
    b'com.apple.mobile.afc\x00',
    b'com.apple.syslog\x00',
    b'com.apple.dt.xcode\x00',
]
for svc in lockdown_services:
    name = svc.rstrip(b'\x00').decode('ascii')
    positions = find_utf16(svc, 5)
    for p in positions:
        s = read_utf16_at(p, 80)
        print(f"    {name:45s}  0x{p:08x}: {s[:60]!r}" if s else f"    {name}")

# ==== F) Driver-related property/field names ====
print("\n[F] Driver Property and Field Names")
print("-"*60)
field_patterns = [
    b'iRemovalRecord\x00', b'iRemovalSignature\x00', b'BypassCache\x00',
    b'Eraser\x00', b'BlackHound\x00', b'MEID\x00', b'ICCID\x00',
    b'UDID\x00', b'ECID\x00', b'SerialNumber\x00',
    b'ChipID\x00', b'ProductType\x00',
]
for f in field_patterns:
    n = f.rstrip(b'\x00').decode('ascii')
    positions = find_utf16(f, 5)
    if positions:
        for p in positions[:3]:
            s = read_utf16_at(p, 80)
            print(f"    {n:25s}  0x{p:08x}: {s[:60]!r}" if s else f"    {n}")

# ==== G) Summary ====
print("\n[G] SUMMARY")
print("-"*60)
print(f"  iDevice_* methods: {len(idevice_methods)}")
print(f"  Driver state machines: {len(state_machines)}")
print(f"  Driver types found: {len(driver_types)}")
print()
print("Total Driver-related strings cataloged: {}".format(
    len(idevice_methods) + len(state_machines) + len(driver_types)
))
