# -*- coding: utf-8 -*-
"""Fix the U+FFFD sequences in ioc_catalog.md by replacing them with
the correct emoji bytes (calendar + key) using a manual mapping."""
import io, sys

p = r'05_IOC\ioc_catalog.md'
raw = open(p, 'rb').read()

# Manual mapping of broken sequence -> proper UTF-8 bytes
fixes = [
    # The new 'Datation echantillon' heading I added:
    (b'## \xef\xbf\xbd Datation',                 b'## \xf0\x9f\x93\x85 Datation'),
    # The pre-existing 'cle Hashes' heading that was already broken:
    (b'## \xef\xbf\xbd\xf0\x9f\x94\x91 Hashes',   b'## \xf0\x9f\x94\x91 Hashes'),
]

for old, new in fixes:
    count = raw.count(old)
    if count != 1:
        print(f'  ! {old!r} -> {new!r}: count={count} (expected 1)')
        for i in range(count):
            pos = raw.find(old)
            if pos < 0: break
            print(f'    context: {raw[max(0,pos-20):pos+len(old)+20]!r}')
            raw = raw[:pos] + b'###MARKER###' + raw[pos+len(old):]
    else:
        print(f'  ok {old!r} -> {new!r}')

ok = True
for old, new in fixes:
    if raw.count(old) != 1:
        ok = False
if not ok:
    sys.exit(1)

for old, new in fixes:
    raw = raw.replace(old, new, 1)

open(p, 'wb').write(raw)

text = raw.decode('utf-8')
for line in text.split('\n'):
    if 'Datation' in line or 'Hashes de' in line:
        print('VERIFY:', repr(line))
print('Remaining FFFD count:', text.count('\ufffd'))
