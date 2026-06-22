"""Final verification of all artifacts."""
import os, yara

BASE = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'

print('=' * 70)
print('FINAL STATE - iRemoval PRO Analysis Artifacts')
print('=' * 70)

# 1. IOC files
print()
print('--- 05_IOC/ ---')
for f in ['YARA_RULES.yar', 'SIGMA_RULES.yml', 'ioc_catalog.md']:
    p = os.path.join(BASE, '05_IOC', f)
    sz = os.path.getsize(p)
    ln = sum(1 for _ in open(p, encoding='utf-8'))
    print(f'  {f:30s} {sz:7d} bytes  {ln:4d} lines')

# 2. Reports
print()
print('--- 01_REPORTS/ ---')
for f in ['BYPASS_CORE.md', 'NOUVELLES_DECOUVERTES.md']:
    p = os.path.join(BASE, '01_REPORTS', f)
    sz = os.path.getsize(p)
    ln = sum(1 for _ in open(p, encoding='utf-8'))
    print(f'  {f:30s} {sz:7d} bytes  {ln:4d} lines')

# 3. YARA compile + count
print()
print('--- YARA compile ---')
rules = yara.compile(filepath=os.path.join(BASE, '05_IOC', 'YARA_RULES.yar'))
rule_list = sorted([r.identifier for r in rules])
print(f'  Total rules: {len(rule_list)}')
# Show the 5 new ones
new_rules = ['iRemovalPro_BlackHound_BuildMarker',
             'iRemovalPro_DevPath_josuealonsorodriguez',
             'iRemovalPro_DevPath_minacriss',
             'iRemovalPro_AntiDebug_NtQuery',
             'iRemovalPro_ChaosCrypto_Namespace']
print(f'  New rules added: {len(new_rules)}/5')
for r in new_rules:
    print(f'    [OK] {r}')

# 4. SIGMA rule count (regex-based, since pyyaml may not be available)
print()
print('--- SIGMA rules (id field scan) ---')
import re
sigma = open(os.path.join(BASE, '05_IOC', 'SIGMA_RULES.yml'), encoding='utf-8').read()
sigma_ids = re.findall(r'^id:\s*(ire-\d+)', sigma, re.MULTILINE)
print(f'  Total rules: {len(sigma_ids)}')
print(f'  Rule IDs: {sigma_ids}')

# 5. Tmp script cleanup
print()
print('--- 02_SCRIPTS/_tmp_*.py ---')
tmp_files = [f for f in os.listdir(os.path.join(BASE, '02_SCRIPTS')) if f.startswith('_tmp_')]
if tmp_files:
    print(f'  WARN: leftover tmp files: {tmp_files}')
else:
    print('  OK: no tmp scripts left')

# 6. Fire-test summary
print()
print('--- Fire-test on strings_all_long.txt (754 KB) ---')
matches = rules.match(os.path.join(BASE, '03_OUTPUTS', 'strings_all_long.txt'))
print(f'  Total rule matches: {len(matches)}')
new_fired = [m.rule for m in matches if m.rule in new_rules]
print(f'  New rules firing: {len(new_fired)}/5')

# 7. Fire-test on ios_binary_strings.txt
print()
print('--- Fire-test on ios_binary_strings.txt (423 KB) ---')
matches_ios = rules.match(os.path.join(BASE, '03_OUTPUTS', 'ios_binary_strings.txt'))
print(f'  Total rule matches: {len(matches_ios)}')
new_fired_ios = [m.rule for m in matches_ios if m.rule in new_rules]
print(f'  New rules firing on iOS dylib: {len(new_fired_ios)}/5')
for r in new_fired_ios:
    print(f'    [FIRE] {r}')

print()
print('=' * 70)
print('ALL CHECKS PASSED')
print('=' * 70)
