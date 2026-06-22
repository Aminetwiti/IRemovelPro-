#!/usr/bin/env python3
import sys
data = open(r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll','rb').read()
print(f'DLL size: {len(data):,}')
# Search Mach-O magic more carefully
for magic_name, magic in [
    ('MH_MAGIC_64 LE (cf fa ed fe)', b'\xcf\xfa\xed\xfe'),
    ('MH_MAGIC_64 BE (fe ed fa cf)', b'\xfe\xed\xfa\xcf'),
    ('MH_MAGIC 32 LE (ce fa ed fe)', b'\xce\xfa\xed\xfe'),
    ('MH_MAGIC 32 BE (fe ed fa ce)', b'\xfe\xed\xfa\xce'),
    ('FAT_MAGIC (ca fe ba be)', b'\xca\xfe\xba\xbe'),
]:
    positions = []
    pos = 0
    while True:
        p = data.find(magic, pos)
        if p < 0: break
        positions.append(p)
        pos = p + 1
    if positions:
        print(f'\n{magic_name}: {len(positions)} hits')
        for p in positions[:10]:
            print(f'  @ 0x{p:x}: {data[p:p+4].hex()} | {data[p:p+20].hex(" ")}')