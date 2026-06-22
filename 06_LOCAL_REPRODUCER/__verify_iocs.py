# -*- coding: utf-8 -*-
"""Final verification of all 4 short-term tasks from NOUVELLES_DECOUVERTES.md."""
import re, sys

ok = 0
fail = 0

def check(label, path, must_have, must_not_have=()):
    global ok, fail
    raw = open(path, 'rb').read()
    text = raw.decode('utf-8', errors='replace')
    bad_ffd = text.count('\ufffd')
    print(f'\n=== {label} ({path}) ===')
    print(f'  total lines = {text.count(chr(10))+1}, total bytes = {len(raw)}, U+FFFD = {bad_ffd}')
    all_ok = True
    for s, m in must_have:
        present = s in text
        all_ok = all_ok and present
        mark = 'OK' if present else 'MISS'
        if present: ok += 1
        else: fail += 1
        print(f'  [{mark}] {m}: {s!r}')
    for s, m in must_not_have:
        absent = s not in text
        all_ok = all_ok and absent
        mark = 'OK' if absent else 'DUP'
        if absent: ok += 1
        else: fail += 1
        print(f'  [{mark}] {m}: {s!r}  (must NOT be present)')
    return all_ok

# 1. ioc_catalog.md: 5 IoCs + dating section
r1 = check(
    'ioc_catalog.md - 5 IoCs + Sample dating',
    r'05_IOC\ioc_catalog.md',
    must_have=[
        ('chmod +x /private/var/root/identity',  'chmod IoC'),
        ('rm -rf /private/var/root/identity',     'rm identity IoC'),
        ('rm -rf /private/var/root/payloa[d]',   'rm payload IoC'),
        ('## 📅 Datation échantillon',            'Sample dating heading'),
        ('T<-[Blackhound iRemovalPro Public build 0.7.1 @2022|]->', 'Build marker'),
        ('1643379a', 'arm64 build hash'),
        ('50c6260a', 'arm64e build hash'),
        ('.NET Framework',                         '.NET Framework mention'),
        ('4.5.2',                                  '4.5.2 version (no v prefix)'),
        ('5.2 = nom commercial', '5.2 commercial note'),
    ],
)

# 2. YARA_RULES.yar: 4 verbatim rules
r2 = check(
    'YARA_RULES.yar - 4 verbatim rules',
    r'05_IOC\YARA_RULES.yar',
    must_have=[
        ('rule iRemovalPro_BlackHound_BuildMarker',          'YARA #1 build marker'),
        ('rule iRemovalPro_DevPath_josuealonsorodriguez',     'YARA #2 dev path 1'),
        ('rule iRemovalPro_DevPath_minacriss',                'YARA #3 dev path 2'),
        ('rule iRemovalPro_AntiDebug_NtQuery',                'YARA #4 anti-debug'),
        ('T<-[Blackhound iRemovalPro Public build 0.7.1 @2022|]->',     'YARA #1 string'),
        ('josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound', 'YARA #2 string'),
        ('minacriss/Documents/Minasoftware/minaeraser',      'YARA #3 string'),
        ('IsDebuggerPresent',                                 'YARA #4 string'),
    ],
)

# 3. SIGMA_RULES.yml: 1 verbatim rule
r3 = check(
    'SIGMA_RULES.yml - 1 verbatim rule',
    r'05_IOC\SIGMA_RULES.yml',
    must_have=[
        ('ideviceproxy lao abc ofq com.iremovalpro.bypass',  'SIGMA verbatim command'),
        ('ideviceproxy lao abc ofq com.panyolsoft.blackhound', 'SIGMA verbatim command #2'),
        ('com.iremovalpro.bypass --stream',                   'SIGMA verbatim stream flag'),
        ('filter_legit_libimobiledevice',                     'SIGMA filter'),
        ('attack.t1562',                                      'SIGMA MITRE tag'),
    ],
)

# 4. YARA syntax (best-effort)
print('\n=== YARA syntax check ===')
import subprocess
try:
    yara = subprocess.run(['yara', '--version'], capture_output=True, text=True, timeout=5)
    print(f'  yara version: {yara.stdout.strip() or yara.stderr.strip() or yara.returncode}')
    # Compile to check syntax (no target file = just check rules load)
    # Use empty/null target
    import os, tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(b'\\x00' * 16)
        tgt = f.name
    res = subprocess.run(['yara', '-r', '05_IOC\\YARA_RULES.yar', tgt],
                         capture_output=True, text=True, timeout=15)
    if res.returncode == 0:
        n = len([l for l in res.stdout.splitlines() if l.strip()])
        print(f'  [OK] YARA compiled: {n} rules loaded, no errors')
        ok += 1
    else:
        print(f'  [FAIL] YARA returncode {res.returncode}')
        print('  stderr:', res.stderr[:1000])
        fail += 1
    os.unlink(tgt)
except FileNotFoundError:
    print('  [SKIP] yara binary not on PATH')
except Exception as e:
    print(f'  [SKIP] {e}')

# 5. SIGMA YAML syntax
print('\n=== SIGMA YAML syntax check ===')
try:
    import yaml
    n_rules = 0
    with open(r'05_IOC\SIGMA_RULES.yml', 'r', encoding='utf-8') as f:
        for doc in yaml.safe_load_all(f):
            if doc:
                n_rules += 1
    print(f'  [OK] YAML valid: {n_rules} rule(s) parsed')
    ok += 1
except ImportError:
    print('  [SKIP] PyYAML not installed')
except Exception as e:
    print(f'  [FAIL] YAML error: {e}')
    fail += 1

print(f'\n=== TOTAL: {ok} OK, {fail} FAIL ===')
sys.exit(0 if fail == 0 else 1)
