# -*- coding: utf-8 -*-
c = open(r'05_IOC\ioc_catalog.md', encoding='utf-8').read()
print('4.5.2 present:', '4.5.2' in c)
print('.NET Framework present:', '.NET Framework' in c)
print('v4.5.2 present:', 'v4.5.2' in c)
import re
for m in re.finditer(r'.{0,30}4\.5\.2.{0,30}', c):
    print('  context:', repr(m.group(0)))
