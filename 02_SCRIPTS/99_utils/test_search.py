#!/usr/bin/env python3
"""Quick URL search test."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
data = open(r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll','rb').read()
print('DLL size:', len(data))
for pat in [b'iact8.php', b'iact8', b'ars2', b's13.iremovalpro', b'Payax0', b'albert.apple', b'version33', b'iremovalActivation']:
    pos = data.find(pat)
    if pos >= 0:
        print(f'  {pat!s:30} -> 0x{pos:x}')
    else:
        print(f'  {pat!s:30} -> NOT FOUND')