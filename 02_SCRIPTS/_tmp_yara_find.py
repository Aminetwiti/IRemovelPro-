import pathlib
base = pathlib.Path(r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2')
yara_path = base / '05_IOC' / 'YARA_RULES.yar'
text = yara_path.read_text(encoding='utf-8')
lines = text.splitlines(keepends=False)
for i, line in enumerate(lines, 1):
    if 'iRemovalPro_AntiRE_Chaos_Crypto' in line or 'An assertion in Chaos.Crypto failed' in line:
        print(f'L{i}: {line}')
print('---CONTEXT L620-645---')
for i in range(620, 645):
    if i <= len(lines):
        print(f'L{i}: {lines[i-1]}')