#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extraction complete des hooks client-side depuis blackhound.dylib.
Liste TOUS les _orig_, _replace_, __logos_method$, __logos_orig$ et
leur association avec la classe/cible.
"""
import sys, re, os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

# Cibles d'extraction
DYLIB_ARM64 = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\04_EXTRACTED\macho_8534d3_DYLIB_ARM64_ALL.bin'
DYLIB_ARM64E = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\04_EXTRACTED\macho_86b4d3_DYLIB_ARM64_ARM64E.bin'
NET_DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro\iremovalpro.dll'

print('='*80)
print('  EXTRACTION DES HOOKS CLIENT-SIDE - iREMOVAL PRO v5.2')
print('='*80)

# 1. Analyser les 3 binaires
for label, path in [('DYLIB_ARM64', DYLIB_ARM64), ('DYLIB_ARM64E', DYLIB_ARM64E), ('NET_DLL', NET_DLL)]:
    print(f'\n[{label}] {os.path.basename(path)}')
    if not os.path.exists(path):
        print('  [!] Non trouve')
        continue
    data = open(path, 'rb').read()

    # 1a. Tous les _orig_ et _replace_ (MobileSubstrate direct hooks)
    print(f'\n  --- _orig_ (preserved originals) ---')
    origs = sorted(set(m.group(0).decode('ascii', errors='replace')
                       for m in re.finditer(rb'\b_orig_[A-Za-z0-9_]{4,80}', data)))
    for o in origs:
        # Contexte
        idx = data.find(o.encode('ascii'))
        ctx = data[max(0, idx-50):idx+150]
        ctx_clean = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f'    {o}')
        print(f'      ctx: ...{ctx_clean[-100:]}...')

    print(f'\n  --- _replace_ (bypass implementations) ---')
    repls = sorted(set(m.group(0).decode('ascii', errors='replace')
                       for m in re.finditer(rb'\b_replace_[A-Za-z0-9_]{4,80}', data)))
    for r in repls:
        idx = data.find(r.encode('ascii'))
        ctx = data[max(0, idx-50):idx+200]
        ctx_clean = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f'    {r}')
        print(f'      ctx: ...{ctx_clean[-120:]}...')

    # 1b. Logos hooks (__logos_method$ / __logos_orig$)
    print(f'\n  --- __logos_method$ (Logos hook bodies) ---')
    logos_m = sorted(set(
        m.group(0).decode('ascii', errors='replace')
        for m in re.finditer(rb'__logos_method\$[_a-zA-Z0-9$]+', data)
    ))
    for l in logos_m:
        print(f'    {l}')

    print(f'\n  --- __logos_orig$ (Logos original refs) ---')
    logos_o = sorted(set(
        m.group(0).decode('ascii', errors='replace')
        for m in re.finditer(rb'__logos_orig\$[_a-zA-Z0-9$]+', data)
    ))
    for l in logos_o:
        print(f'    {l}')

    # 1c. _MSHook* (Cydia Substrate)
    print(f'\n  --- MobileSubstrate API calls ---')
    for sym in [b'_MSHookFunction', b'_MSHookMessageEx', b'MSFindSymbol',
                b'MSGetImageByName', b'MSHookFunction']:
        cnt = data.count(sym)
        if cnt > 0:
            print(f'    {sym.decode()}: {cnt} fois')

print('\n' + '='*80)
print('  FIN')
print('='*80)
