# -*- coding: utf-8 -*-
p = r'05_IOC\ioc_catalog.md'
c = open(p, encoding='utf-8').read()
for line in c.split('\n'):
    if 'Datation' in line:
        print('FULL LINE:', repr(line))
        for ch in line:
            if ord(ch) > 127:
                print(f'  codepoint U+{ord(ch):04X}')
        break
