#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 4+ [s] — Analyse Driver depuis strings_all_long.txt.

Sans accès au binaire, exploite le fichier de chaînes de 737 KB
(75 000+ chaînes) déjà extrait. Identifie :
- Méthodes iDevice_* additionnelles
- State machines
- Strings de méthode Driver
- Indices de fonctions privées

Sortie : stdout (terminal) + fichier CSV
"""
import sys, re, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

STRINGS_FILE = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\03_OUTPUTS\strings_all_long.txt'
OUT_MD = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\01_REPORTS\PHASE4B_DRIVER_ANALYSIS.md'

# Read strings file
with open(STRINGS_FILE, 'r', encoding='utf-8', errors='replace') as f:
    all_lines = [l.rstrip() for l in f]

print("="*80)
print("Phase 4+ [s] — Driver class deep analysis from strings_all_long.txt")
print("="*80)
print(f"Total strings loaded: {len(all_lines)}")

# ==== A) iDevice_* methods (UTF-16LE stored as \x00-separated) ====
# In strings_all_long.txt, UTF-16LE strings are stored with \x00 bytes between chars
# We need to find them by looking for "iDevice_" in lines

idevice_lines = []
for i, line in enumerate(all_lines):
    if 'iDevice_' in line:
        idevice_lines.append((i, line))

print(f"\n[A] iDevice_* strings found: {len(idevice_lines)}")
unique_idevices = set()
for idx, line in idevice_lines[:50]:
    # Extract iDevice_xxx patterns
    matches = re.findall(r'iDevice_\w+', line)
    for m in matches:
        unique_idevices.add(m)
    if len(unique_idevices) < 100:
        print(f"  L{idx}: {line[:100]}")

# ==== B) Driver class identifiers ====
driver_lines = []
for i, line in enumerate(all_lines):
    if re.search(r'Driver[\.\<]', line) or '<Driver>' in line:
        driver_lines.append((i, line))

print(f"\n[B] Driver class identifiers found: {len(driver_lines)}")
for idx, line in driver_lines[:30]:
    print(f"  L{idx}: {line[:120]}")

# ==== C) State machines ====
sm_patterns = [
    r'<BypassMeidSignal>',
    r'<CommonConnectDevice>',
    r'<CheckIOS>',
    r'<Install>',
    r'<InstallFromLocal>',
    r'<WatchForCompletion>',
    r'<GetDeviceLink>',
    r'<RestoreBackup>',
    r'<VersionExchange>',
    r'<Imei_MouseDown>',
    r'<Sn_MouseDown>',
    r'<Button_Click_\d+>',
    r'<iDevice_RemoveProfiles>',
]
sm_lines = []
for i, line in enumerate(all_lines):
    for pat in sm_patterns:
        if re.search(pat, line):
            sm_lines.append((i, line, pat))
            break

print(f"\n[C] State machine occurrences: {len(sm_lines)}")
for idx, line, pat in sm_lines[:30]:
    m = re.search(pat, line)
    if m:
        print(f"  L{idx}: {m.group(0)} (in: {line[:60]}...)")

# ==== D) BypassMeidSignal + Erase_V2 + related ====
bypass_lines = []
for i, line in enumerate(all_lines):
    keywords = ['BypassMeidSignal', 'Erase_V2', 'BypassCache', 'Firewall_iDeviceProxy',
                'SecureClearAndCollect', 'ExecuteAsAdmin', 'iRemovalRecord', 'iRemovalSignature',
                'A12Eraser', 'minaeraser', 'blackhound', 'panyolsoft', 'GetTokenFor', 'SetLocalSignature',
                'ResolveSignature', 'get_UniqueDeviceID', 'get_InternationalMobileEquipment',
                'get_MobileEquipmentIdentifier', 'MobileActivation', 'mobileactivationd',
                'drmHandshake', 'albert.apple.com', 's13.iremovalpro.com']
    for kw in keywords:
        if kw in line:
            bypass_lines.append((i, line, kw))
            break

print(f"\n[D] Bypass-related strings (first 50): {len(bypass_lines)}")
seen_kw = set()
for idx, line, kw in bypass_lines[:50]:
    key = (kw, line[:60])
    if key in seen_kw:
        continue
    seen_kw.add(key)
    print(f"  [{kw}] L{idx}: {line[:100]}")

# ==== E) HTTP endpoints ====
endpoint_lines = []
for i, line in enumerate(all_lines):
    if 'iremovalpro.com' in line or 'albert.apple.com' in line:
        endpoint_lines.append((i, line))

print(f"\n[E] Server endpoint references: {len(endpoint_lines)}")
for idx, line in endpoint_lines[:30]:
    print(f"  L{idx}: {line[:100]}")

# ==== F) Anti-debug APIs ====
ad_lines = []
for i, line in enumerate(all_lines):
    ad_keywords = ['IsDebuggerPresent', 'NtQueryInformationProcess', 'NtQueryInformationFile',
                   'NtQuerySystemInformation', 'EnumWindows', 'RegOpenKey',
                   'RegQueryValueEx', 'GetTickCount', 'QueryPerformanceCounter',
                   'MibTcpRowOwnerPid', 'Firewall_iDeviceProxy']
    for kw in ad_keywords:
        if kw in line:
            ad_lines.append((i, line, kw))
            break

print(f"\n[F] Anti-debug API references: {len(ad_lines)}")
for idx, line, kw in ad_lines[:20]:
    print(f"  [{kw}] L{idx}: {line[:80]}")

# ==== G) Write final analysis as Markdown ====
print("\n[G] Writing PHASE4B_DRIVER_ANALYSIS.md")

with open(OUT_MD, 'w', encoding='utf-8') as f:
    f.write("# Phase 4+ — Driver Class Deep Analysis (from strings)\n\n")
    f.write("> Analyse basée sur `03_OUTPUTS/strings_all_long.txt`\n")
    f.write("> (Binaires absents du projet — analyse statique des chaînes)\n\n")
    f.write("**Date** : 2026-06-22\n")
    f.write("**Méthode** : Grep patterns sur 75 000+ chaînes\n\n")
    f.write("---\n\n")

    f.write("## A. Méthodes iDevice_* identifiées\n\n")
    f.write(f"Total : {len(unique_idevices)} méthodes uniques\n\n")
    f.write("| # | Méthode | Contexte |\n|---|---|---|\n")
    for i, m in enumerate(sorted(unique_idevices), 1):
        # Find a context line
        ctx = ""
        for idx, line in idevice_lines:
            if m in line:
                ctx = line[:80]
                break
        f.write(f"| {i} | `{m}` | {ctx} |\n")
    f.write("\n")

    f.write("## B. Identifiants Driver class\n\n")
    f.write(f"Total : {len(driver_lines)} occurrences\n\n")
    f.write("```\n")
    for idx, line in driver_lines[:40]:
        f.write(f"  L{idx}: {line[:120]}\n")
    f.write("```\n\n")

    f.write("## C. State machines async\n\n")
    f.write(f"Total : {len(sm_lines)} occurrences\n\n")
    f.write("| # | Pattern | Contexte |\n|---|---|---|\n")
    for i, (idx, line, pat) in enumerate(sm_lines[:30], 1):
        f.write(f"| {i} | `{pat}` | {line[:60]} |\n")
    f.write("\n")

    f.write("## D. Bypass-related strings\n\n")
    f.write(f"Total : {len(bypass_lines)} occurrences\n\n")
    f.write("| Mot-clé | Ligne | Contexte |\n|---|---|---|\n")
    seen_d = set()
    for idx, line, kw in bypass_lines[:50]:
        key = (kw, line[:40])
        if key in seen_d:
            continue
        seen_d.add(key)
        f.write(f"| `{kw}` | L{idx} | {line[:80]} |\n")
    f.write("\n")

    f.write("## E. Endpoints serveur\n\n")
    f.write(f"Total : {len(endpoint_lines)} occurrences\n\n")
    f.write("```\n")
    for idx, line in endpoint_lines[:30]:
        f.write(f"  L{idx}: {line[:120]}\n")
    f.write("```\n\n")

    f.write("## F. Anti-debug APIs\n\n")
    f.write(f"Total : {len(ad_lines)} occurrences\n\n")
    f.write("| API | Ligne | Contexte |\n|---|---|---|\n")
    for idx, line, kw in ad_lines[:20]:
        f.write(f"| `{kw}` | L{idx} | {line[:80]} |\n")
    f.write("\n")

    f.write("## G. Synthèse\n\n")
    f.write(f"- **Méthodes iDevice_*** : {len(unique_idevices)} uniques\n")
    f.write(f"- **Driver identifiers** : {len(driver_lines)} occurrences\n")
    f.write(f"- **State machines** : {len(sm_lines)} occurrences\n")
    f.write(f"- **Bypass strings** : {len(bypass_lines)} occurrences\n")
    f.write(f"- **Endpoints** : {len(endpoint_lines)} occurrences\n")
    f.write(f"- **Anti-debug APIs** : {len(ad_lines)} occurrences\n\n")
    f.write("**Note** : Cette analyse est limitée par l'absence du binaire.\n")
    f.write("Pour une analyse complète, restaurer `iremovalpro.dll` (30 MB).\n")

print(f"[+] Saved: {OUT_MD}")

# ==== H) Summary ====
print("\n" + "="*80)
print("[H] SUMMARY")
print("="*80)
print(f"  iDevice_* methods (unique): {len(unique_idevices)}")
print(f"  Driver identifiers        : {len(driver_lines)}")
print(f"  State machines            : {len(sm_lines)}")
print(f"  Bypass-related strings    : {len(bypass_lines)}")
print(f"  Server endpoints          : {len(endpoint_lines)}")
print(f"  Anti-debug APIs           : {len(ad_lines)}")
print()
print("Full analysis written to PHASE4B_DRIVER_ANALYSIS.md")
