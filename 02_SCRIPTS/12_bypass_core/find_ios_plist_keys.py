#!/usr/bin/env python3
"""Look for iOS Activation plist keys and ticket structure in the bypass dylib."""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
data = (WORK / "04_EXTRACTED" / "macho_8534d3_DYLIB_ARM64_ALL.bin").read_bytes()

# iOS Activation plist keys
plist_keys = [
    'ActivationState', 'ActivationTicket', 'DeviceCertRequest', 'DeviceCertSerial',
    'FairPlayKeyData', 'IMEI', 'IMSI', 'ICCID', 'MEID',
    'ModelNumber', 'ProductType', 'ProductVersion', 'SerialNumber', 'UniqueChipID',
    'UniqueDeviceID', 'UDID', 'MLB', 'MacAddress', 'BasebandMasterKeyHash',
    'PostponementInfo', 'PostponementTicket', 'SIMStatus', 'SIMTrayStatus',
    'SupportedDeviceFamilies', 'WildcardTicket', 'AccountToken', 'ActivationRecord',
    'ActivationInfo', 'PrivacyProxy', 'RegulatoryModelNumber', 'RegionInfo',
    'FMiPAccount', 'FMiPEnabled', 'LostModeEnabled', 'iCloudSignedInAccount',
    'EffectiveProductionMode', 'EffectiveSecurityMode', 'SecurityDomain',
    'BrickMode', 'BoardID', 'ChipID', 'ChipSeries', 'iRemovalRecord',
    'iRemovalSignature', 'ActivationStateMerged', 'HasActiveSIM',
]

print('=== iOS Activation plist keys found in dylib ===')
for k in plist_keys:
    cnt = data.count(k.encode())
    if cnt > 0:
        print(f'  [+] {k}: {cnt}')

# plist XML patterns
print('\n=== Plist XML patterns ===')
for p in [b'<plist', b'</plist>', b'<dict>', b'</dict>', b'<key>', b'</key>',
          b'<string>', b'</string>', b'<data>', b'</data>', b'<array>',
          b'<true/>', b'<false/>', b'<integer>']:
    cnt = data.count(p)
    if cnt > 0:
        print(f'  {p.decode():15}: {cnt}')

# Plist keys (Xcode-style "<key>KeyName</key>")
print('\n=== iOS Activation plist key-value pairs (Apple standard) ===')
for k in ['ActivationState', 'ActivationTicket', 'WildcardTicket', 'AccountToken',
          'DeviceCertRequest', 'IMEI', 'MEID', 'SerialNumber', 'ProductType',
          'ProductVersion', 'UniqueDeviceID', 'SIMStatus', 'BasebandMasterKeyHash',
          'UniqueChipID', 'EffectiveSecurityMode', 'SecurityDomain', 'BrickMode']:
    pat = f'<key>{k}</key>'.encode()
    cnt = data.count(pat)
    if cnt > 0:
        print(f'  [+] {k}: {cnt}')

# The signature string and the iRemovalRecord data
print('\n=== Custom BlackHound record structure ===')
for s in [b'<key>iRemovalRecord</key>', b'<key>iRemovalSignature</key>',
          b'iRemovalRecord', b'iRemovalSignature']:
    cnt = data.count(s)
    if cnt > 0:
        print(f'  [+] {s.decode()}: {cnt}')