#!/usr/bin/env python3
"""
Find iOS app installation paths and finalize the system map.
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# 1. Find iOS app installation paths
print("="*80)
print("iOS app installation paths")
print("="*80)
for s in ['iRemovalRa1n', 'iRemovalRa1n.app', 'com.iremovalpro.ra1n',
          'com.iremovalpro.bypass', '/var/mobile/Containers', '/Applications/',
          'Mobile/Containers', 'Applications/iRemovalRa1n',
          'Bypass.ipa', 'iRemoval.ipa', 'Bypass.app', 'mobileactivationd',
          'blackhound.dylib', 'MobileSubstrate', 'CydiaSubstrate',
          '/Library/MobileSubstrate', '/usr/libexec/mobileactivationd',
          'iOS Ra1n', 'Ra1n app', 'iRemovalPRO', 'iRemoval PRO.app',
          'sftp://', 'scp ', 'ssh ', 'sshpass', 'plutil', 'pledit',
          'plutil -convert', 'chmod +x', 'chmod 755', 'install_app',
          'afcclient', '/c afc', 'sbservices', 'afc://',
          'jailbreak', 'rootless', 'palera1n', 'unc0ver', 'checkra1n',
          'sshpass -p', 'rm -rf', 'cp -R', 'mv ', 'ln -s']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        # Get context
        s = idx
        while s > 0 and data[s-1] == 0x00 and 0x20 <= data[s-2] < 0x7f:
            s -= 2
        e = idx + len(s_u)
        while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
            e += 2
        ctx = data[s:e].decode('utf-16-le', errors='ignore')
        print(f"  {s}: {cnt} - Context: {ctx[:200]}")

# 2. Find SSH commands
print("\n" + "="*80)
print("SSH/SFTP commands (deployment to iOS)")
print("="*80)
for s in ['ssh ', 'scp ', 'sftp', 'sshpass', 'plutil', 'pledit', 'plutil -convert',
          'install_app', 'uninstall_app', 'ideviceinstaller', 'appinstaller',
          'afcclient upload', 'afcclient download', 'afc://', 'tcp:',
          'sftp -P', 'ssh -p', '-o StrictHostKeyChecking', 'no', 'yes',
          'ssh-rsa', 'ssh-ed25519', '/root/.ssh', '/var/root',
          'alpine', 'alpine_password', 'default_password', 'root@']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        s = idx
        while s > 0 and data[s-1] == 0x00 and 0x20 <= data[s-2] < 0x7f:
            s -= 2
        e = idx + len(s_u)
        while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
            e += 2
        ctx = data[s:e].decode('utf-16-le', errors='ignore')
        print(f"  {repr(s)}: {cnt}")
        if len(ctx) > len(s) + 2:
            print(f"    Context: {ctx[:200]}")

# 3. Find all the "Authorization: Basic" credentials
print("\n" + "="*80)
print("Authorization context")
print("="*80)
idx = data.find('Authorization: Basic'.encode('utf-16-le'))
if idx > 0:
    s = max(0, idx - 200)
    e = min(len(data), idx + 200)
    ctx = data[s:e]
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,}', ctx):
        offset = m.start() + s
        st = m.group().decode('utf-16-le', errors='ignore')
        if st and len(st) > 2:
            print(f"  0x{offset:08x}: {st[:200]}")

# 4. Find the user-agent or other identifying strings
print("\n" + "="*80)
print("User-Agent and identifying strings")
print("="*80)
for s in ['User-Agent', 'iRemoval', 'Mozilla/', 'iRemovalPro',
          'X-iRemoval-', 'X-iOS-', 'iRemoval-Agent', 'iremo']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        s = idx
        while s > 0 and data[s-1] == 0x00 and 0x20 <= data[s-2] < 0x7f:
            s -= 2
        e = idx + len(s_u)
        while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
            e += 2
        ctx = data[s:e].decode('utf-16-le', errors='ignore')
        print(f"  {s}: {cnt} - {ctx[:200]}")

# 5. Find checkra1n or checkm8-related strings
print("\n" + "="*80)
print("checkm8 / checkra1n / palera1n / jailbreak strings")
print("="*80)
for s in ['checkra1n', 'palera1n', 'checkm8', 'gaster', 'ipwnder',
          'ipwnder_lite', 'iboot', 'iBEC', 'iBSS', 'iBoot',
          '/usr/libexec/mobileactivationd', 'MobileActivation.framework',
          'kernelland.dylib', '/usr/lib', '/usr/libexec', '/System/Library/PrivateFrameworks',
          'kIOPMSuccess', 'IORegistryEntry', 'CFNotificationCenter',
          'NSNotificationCenter', 'MobileActivationLog']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        s = idx
        while s > 0 and data[s-1] == 0x00 and 0x20 <= data[s-2] < 0x7f:
            s -= 2
        e = idx + len(s_u)
        while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
            e += 2
        ctx = data[s:e].decode('utf-16-le', errors='ignore')
        print(f"  {s}: {cnt} - {ctx[:200]}")

# 6. Find error / success messages
print("\n" + "="*80)
print("Error/Success messages")
print("="*80)
for s in ['Activated Succesfully', 'Activation Failed', 'Activation Error',
          'Activation Complete', 'Bypass Complete', 'Bypass Success',
          'Device is supported', 'NOT supported', 'iOS version',
          'Failed to activate', 'iCloud Lock', 'Activation Lock',
          'bypass-code', 'activation-lock-bypass', 'icloud', 'Apple ID',
          'restoring', 'erasing', 'putting device', 'factory reset',
          'Entered DFU', 'DFU mode', 'Pwned DFU', 'recovery mode',
          'exploit sent', 'exploit done', 'iBoot exploited']:
    s_u = s.encode('utf-16-le')
    cnt = data.count(s_u)
    if cnt > 0:
        idx = data.find(s_u)
        s = idx
        while s > 0 and data[s-1] == 0x00 and 0x20 <= data[s-2] < 0x7f:
            s -= 2
        e = idx + len(s_u)
        while e < len(data) - 1 and data[e+1] == 0x00 and 0x20 <= data[e] < 0x7f:
            e += 2
        ctx = data[s:e].decode('utf-16-le', errors='ignore')
        print(f"  {s}: {cnt} - {ctx[:200]}")