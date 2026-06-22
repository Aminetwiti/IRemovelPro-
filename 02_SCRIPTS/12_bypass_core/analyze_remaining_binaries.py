#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyse rapide des binaires iRemoval PRO non encore analyses:
  - iRemoval PRO.exe (WPF .NET Framework 4.x, 2.66 MB)
  - ideviceproxy.exe (C/C++ natif, 23.7 MB)
  - idevicepair.exe (C/C++ natif, 384 KB)
"""
import sys, os, struct, re, hashlib
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

BASE = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro'

BINARIES = [
    ('WPF_EXE',     BASE + r'\iRemoval PRO.exe',     2.66),
    ('DEVICEPROXY', BASE + r'\ref\toolkits\ideviceproxy.exe', 23.7),
    ('DEVICEPAIR',  BASE + r'\ref\toolkits\idevicepair.exe', 0.384),
    ('LIBCRYPTO',   BASE + r'\ref\toolkits\libcrypto-3-x64.dll', 4.07),
    ('LIBSSL',      BASE + r'\ref\toolkits\libssl-3-x64.dll', 0.641),
    ('LIBIMOBILE',  BASE + r'\ref\toolkits\libimobiledevice-1.0.dll', 1.74),
    ('LIBIMOBILE_GLUE', BASE + r'\ref\toolkits\libimobiledevice-glue-1.0.dll', 0.492),
    ('LIBPLIST',    BASE + r'\ref\toolkits\libplist-2.0.dll', 0.905),
    ('LIBPLISTPP',  BASE + r'\ref\toolkits\libplist++-2.0.dll', 0.778),
    ('LIBUSBMUXD',  BASE + r'\ref\toolkits\libusbmuxd-2.0.dll', 0.317),
]

print('='*80)
print('  ANALYSE DES BINAIRES iREMOVAL PRO NON ENCORE REVERSES')
print('='*80)

for name, path, size_mb in BINARIES:
    if not os.path.exists(path):
        print(f'\n[{name}] FICHIER NON TROUVE: {path}')
        continue
    print(f'\n[{name}] {os.path.basename(path)} ({size_mb} MB)')

    with open(path, 'rb') as f:
        data = f.read()
    print(f'  Size reel: {len(data):,} bytes ({len(data)/1024/1024:.2f} MB)')
    print(f'  SHA-256: {hashlib.sha256(data).hexdigest()}')

    # Detect format
    if data[:2] == b'MZ':
        print(f'  Format: PE (Windows)')
        # PE header offset
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
            machine = struct.unpack_from('<H', data, pe_offset+4)[0]
            machine_str = {0x14c: 'i386', 0x8664: 'x64', 0xaa64: 'arm64'}.get(machine, f'0x{machine:x}')
            print(f'  Machine: {machine_str}')
            # .NET check
            if b'_CorExeMain' in data or b'mscoree.dll' in data:
                print(f'  Runtime: .NET (PE avec stub CLR)')
            # Native check
            if b'OpenSSL_add_all_algorithms' in data or b'libcrypto' in data.lower():
                print(f'  Runtime: Native C/C++ (avec OpenSSL)')
    elif data[:4] == b'\x7fELF':
        print(f'  Format: ELF (Linux)')
    elif data[:4] == b'\xcf\xfa\xed\xfe' or data[:4] == b'\xfe\xed\xfa\xcf':
        print(f'  Format: Mach-O (macOS/iOS)')
    else:
        print(f'  Format: inconnu (magic: {data[:4].hex()})')

    # Extract ASCII strings (>=8 chars)
    strings = re.findall(rb'[\x20-\x7e]{8,}', data)
    print(f'  Strings ASCII >=8 chars: {len(strings):,}')
    # Extract UTF-16LE strings (>=8 wchars)
    wide_strings = re.findall(rb'(?:[\x20-\x7e]\x00){8,}', data)
    print(f'  Strings UTF-16LE >=8 chars: {len(wide_strings):,}')

    # Top-level URL/endpoint discovery
    urls = set()
    for m in re.finditer(rb'https?://[a-zA-Z0-9._/-]+', data):
        s = m.group(0).decode('ascii', errors='replace')
        if 's13' in s or 'iremoval' in s or 'apple' in s:
            urls.add(s)
    if urls:
        print(f'  URLs iRemoval/Apple trouvees: {len(urls)}')
        for u in sorted(urls)[:10]:
            print(f'    {u}')

    # .NET specific (for WPF)
    if b'iRemovalProWPF' in data or b'_iRemovalProWPF' in data:
        print(f'  >>> .NET assembly identifie <<<')
    if b'Blackhound' in data:
        print(f'  >>> Build marker Blackhound detecte <<<')
    if b'panyolsoft' in data:
        print(f'  >>> Bundle ID panyolsoft detecte <<<')

    # Native C specific (for ideviceproxy)
    if b'idevice' in data.lower():
        cnt = len(re.findall(rb'idevice\w+', data, re.IGNORECASE))
        print(f'  >>> Symbols idevice*: {cnt} <<<')
    if b'libimobiledevice' in data.lower():
        print(f'  >>> Linked to libimobiledevice <<<')
    if b'libusbmuxd' in data.lower():
        print(f'  >>> Linked to libusbmuxd <<<')

    # Sample interesting strings
    interesting = []
    for kw in [b'password', b'username', b'http', b'server', b'auth',
               b'token', b'session', b'key', b'admin', b'remote',
               b'proxy', b'lockdown', b'checkm8', b'restore',
               b'tunnel', b'ssh', b'udid', b'serial']:
        for m in re.finditer(kw + rb'[\x00\x20-\x7e]{4,80}', data, re.IGNORECASE):
            s = m.group(0).rstrip(b'\x00').decode('ascii', errors='replace')
            interesting.append(s)
            if len(interesting) >= 20: break
        if len(interesting) >= 20: break
    if interesting:
        print(f'  Strings interessantes (echantillon):')
        for s in interesting[:10]:
            print(f'    {s[:80]}')

print('\n' + '='*80)
print('  FIN')
print('='*80)
