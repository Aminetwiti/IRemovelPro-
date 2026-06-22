#!/usr/bin/env python3
"""Find iOS app deployment paths - simpler version."""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

def find_strings(keyword):
    """Find all UTF-16LE occurrences of keyword, with context."""
    kw_u = keyword.encode('utf-16-le')
    results = []
    idx = 0
    while True:
        idx = data.find(kw_u, idx)
        if idx == -1:
            break
        # Get context
        s = max(0, idx - 200)
        e = min(len(data), idx + 200)
        ctx = data[s:e]
        # Extract printable strings in context
        strings_in_ctx = []
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,}', ctx):
            st = m.group().decode('utf-16-le', errors='ignore')
            if st and len(st) > 2:
                strings_in_ctx.append(st)
        results.append((idx, strings_in_ctx))
        idx += 1
    return results

# 1. SSH/SCP commands
print("="*80)
print("SSH/SCP/SFTP commands")
print("="*80)
for kw in ['scp -f', 'scp -t', 'scp -p', 'sshpass -p', 'ssh -p',
           'ssh -o', 'sftp -P', 'sftp ', 'scp ', 'ssh ',
           'sftp://', 'StrictHostKeyChecking=no',
           '/var/root', '/private/var/root', '/root/', '/private/var/mobile',
           'identity', 'authorized_keys', '.ssh/', 'id_rsa',
           'alpine', 'default password', 'root password']:
    res = find_strings(kw)
    if res:
        for idx, ctx in res[:2]:
            print(f"  [{kw}] at 0x{idx:08x}:")
            for c in ctx:
                print(f"    {c[:200]}")

# 2. idevicepair and idevice commands
print("\n" + "="*80)
print("idevice* commands")
print("="*80)
for kw in ['idevicepair', 'ideviceinfo', 'idevicebackup', 'idevicerestore',
           'idevicedebug', 'idevicediag', 'idevicesyslog', 'idevice_id',
           'ideviceprox', 'ideviceactivation', 'ideviceenterrecovery',
           'idevicescreenshot', 'ideviceimagemounter', 'afcclient',
           'ideviceinstaller', '/c idevice', '/c afc']:
    res = find_strings(kw)
    if res:
        for idx, ctx in res[:2]:
            print(f"  [{kw}] at 0x{idx:08x}:")
            for c in ctx:
                print(f"    {c[:200]}")

# 3. iOS file paths
print("\n" + "="*80)
print("iOS file paths")
print("="*80)
for kw in ['/var/mobile/Containers', '/var/containers', '/var/mobile/Library',
           'Bypass.app', 'iRemovalRa1n', 'iRemovalRa1n.app',
           '/Library/MobileSubstrate', '/usr/libexec/mobileactivationd',
           '/System/Library/PrivateFrameworks', '/bin/bash', '/usr/bin',
           'app', '/var/mobile/Media', '/var/mobile/Downloads',
           'iRemoval', 'com.iremoval']:
    res = find_strings(kw)
    if res:
        cnt = len(res)
        print(f"  [{kw}]: {cnt} occurrences")
        for idx, ctx in res[:2]:
            print(f"    At 0x{idx:08x}:")
            for c in ctx:
                if len(c) > 2:
                    print(f"      {c[:200]}")

# 4. Checkm8 / DFU / Pwn
print("\n" + "="*80)
print("Exploit flow (DFU/checkm8)")
print("="*80)
for kw in ['checkm8', 'check_ra1n', 'gaster', 'pwn', 'Pwned DFU',
           'DFU mode', 'recovery mode', 'restore mode', 'iBoot',
           'iBEC', 'iBSS', 'palera1n', 'ipwnder', 'ipwnder_lite',
           'gaster.pwn', 'gaster_exploit', 'send_payload', 'send_exploit',
           '/dev/usbmuxd', 'iOS version', 'firmware', 'baseband',
           'A12', 'A13', 'A14', 'A15', 'A16', 'chip', 'soc',
           't8020', 't8027', 't8030', 't8101', 't8110', 't8120',
           'checkm8_bootrom', 'limera1n', 'SHAtter', 'unthreaded',
           'A7', 'A8', 'A9', 'A10', 'A11']:
    res = find_strings(kw)
    if res:
        cnt = len(res)
        print(f"  [{kw}]: {cnt} occurrences")
        for idx, ctx in res[:2]:
            for c in ctx:
                if len(c) > 2:
                    print(f"    {c[:200]}")

# 5. Error / success messages
print("\n" + "="*80)
print("Error/Success messages")
print("="*80)
for kw in ['Activated Succesfully', 'Activation Failed', 'Activation Error',
          'Bypass Complete', 'Bypass Success', 'Device is supported',
          'NOT supported', 'iOS version', 'Failed to activate',
          'iCloud Lock', 'Activation Lock', 'bypass-code',
          'activation-lock-bypass', 'icloud', 'Apple ID',
          'restoring', 'erasing', 'factory reset', 'Entered DFU',
          'DFU mode', 'Pwned DFU', 'recovery mode',
          'iOS Device Activator', 'MobileActivation', 'iOS Device',
          'iDevice Activated', 'iOS No', 'Your device is supported',
          'Your device is NOT supported', 'iRemoval', 'iCloud',
          'icloud.com', 'me.com', 'mac.com']:
    res = find_strings(kw)
    if res:
        cnt = len(res)
        for idx, ctx in res[:1]:
            for c in ctx:
                if len(c) > 2:
                    print(f"  [{kw}] at 0x{idx:x}: {c[:250]}")