import pathlib
base = pathlib.Path(r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2')

# YARA
yara = base / '05_IOC' / 'YARA_RULES.yar'
s = yara.read_text(encoding='utf-8')
print(f'YARA: {len(s)} chars, {s.count(chr(10))} lines')

# mock_server
mock = base / '06_LOCAL_REPRODUCER' / 'iact_reproducer' / 'mock_server.py'
s = mock.read_text(encoding='utf-8')
print(f'mock_server.py: {len(s)} chars, {s.count(chr(10))} lines')

# NOUVELLES
nd = base / '01_REPORTS' / 'NOUVELLES_DECOUVERTES.md'
s = nd.read_text(encoding='utf-8')
print(f'NOUVELLES: {len(s)} chars, {s.count(chr(10))} lines')
print('--- SECTIONS ---')
for i, line in enumerate(s.splitlines(), 1):
    if line.startswith('## '):
        print(f'L{i}: {line}')

# INDEX
idx = base / 'INDEX.md'
s = idx.read_text(encoding='utf-8')
print(f'INDEX: {len(s)} chars')

# EXEC
exec_ = base / '01_REPORTS' / 'EXECUTIVE_SUMMARY.md'
s = exec_.read_text(encoding='utf-8')
print(f'EXECUTIVE_SUMMARY: {len(s)} chars')

# defender
defender = base / '06_LOCAL_REPRODUCER' / 'apple_drm_defense.py'
s = defender.read_text(encoding='utf-8')
print(f'apple_drm_defense.py: {len(s)} chars, {s.count(chr(10))} lines')