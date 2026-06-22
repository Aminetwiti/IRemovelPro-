#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""String extraction with categorization."""
import re, os, io
from collections import Counter
sys = __import__('sys')
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
OUT = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis\strings_report.txt'

with open(DLL, 'rb') as f:
    data = f.read()

# Extract ASCII and UTF-16LE strings
ascii_re = re.compile(rb'[\x20-\x7e]{6,}')
utf16_re = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')

def to_str(b, enc='ascii'):
    try: return b.decode(enc, 'replace')
    except: return ''

# Categorize
categories = {
    'URLs/Endpoints': re.compile(rb'https?://[\w\-\.\:/%\?\&\=\+\~\#\@\!\$]+', re.I),
    'iOS/Apple': re.compile(rb'\b(Apple|iPhone|iPad|iOS|usbmuxd|lockdownd|idevice|AFC|amfi|mobile|restore|activation|iCloud|AppleID|GSMC|passcode|MDM|provision|backup|recovery|DFU|iboot|ibss|kernelcache|llb|bootchain|FDR|nonce|ECID|serial|UDID|APTicket)\b', re.I),
    'Crypto/Security': re.compile(rb'\b(AES|RSA|ECDSA|SHA1|SHA256|SHA384|SHA512|HMAC|PBKDF|BCrypt|NCrypt|CertOpen|CertFree|CertVerify|CRYPTO|CertificateChain|signature|verify|decrypt|encrypt|hash|hmac)\b'),
    'Network/Protocol': re.compile(rb'\b(TCP|UDP|HTTP|HTTPS|SSL|TLS|WSARecv|WSASend|gethostbyname|socket|connect|bind|listen|accept|recv|send|port|proxy|tor|tunnel|ssdp|bonjour|mdns|hostname|DNS|TLS|websocket)\b', re.I),
    'Anti-Debug/Tamper': re.compile(rb'\b(IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|NtSetInformationThread|OutputDebugString|debug|debugger|ollydbg|windbg|x64dbg|cheat|engine|tamper|patch|hook|integrity|signature|checksum)\b', re.I),
    'License/Activation': re.compile(rb'\b(license|activation|activate|register|registration|serial|keygen|crack|pirate|trial|expire|expir|premium|enterprise|ultim|plus|pro|tele|edukit|admin|backdoor|rootkit|bypass|jailbreak|unlock)\b', re.I),
    'Registry/Paths': re.compile(rb'(?:HKEY_|HKLM|HKCU|HKCR|HKU|SOFTWARE\\|SYSTEM\\|Microsoft\\Windows\\|AppData|ProgramData|Program Files|Users\\\\|.exe|.dll|.sys)', re.I),
    'Error/Log': re.compile(rb'\b(error|failed|exception|warning|info|debug|trace|log)\b', re.I),
}

# Extract all strings
all_ascii = ascii_re.findall(data)
all_utf16 = utf16_re.findall(data)

results = {cat: [] for cat in categories}
results['__ALL_LONG__'] = []

# Classify
for s in all_ascii + all_utf16:
    raw = s
    if len(s) >= 6:
        s_str = to_str(s, 'utf-16-le' if len(s) % 2 == 0 and s[1] == 0 else 'ascii')
        for cat, pat in categories.items():
            if pat.search(raw):
                results[cat].append(s_str)
        if len(s_str) >= 16:
            results['__ALL_LONG__'].append(s_str)

with open(OUT, 'w', encoding='utf-8') as out:
    out.write(f"STRING EXTRACTION REPORT: {DLL}\n")
    out.write(f"Total size: {len(data):,} bytes\n")
    out.write(f"ASCII strings (>=6): {len(all_ascii):,}\n")
    out.write(f"UTF-16LE strings (>=6): {len(all_utf16):,}\n")
    out.write('='*80 + '\n\n')
    for cat in categories:
        out.write(f"\n--- {cat} ({len(results[cat])} matches) ---\n")
        # dedupe
        seen = set()
        for s in results[cat]:
            if s in seen: continue
            seen.add(s)
            if len(s) > 200: s = s[:200] + '...'
            out.write(f"  {s}\n")
            if len(seen) > 100:
                out.write(f"  ... (truncated, +{len(results[cat])-len(seen)} more)\n")
                break

# Also write all long strings separately
LONG = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis\strings_all_long.txt'
with open(LONG, 'w', encoding='utf-8') as out:
    seen = set()
    for s in results['__ALL_LONG__']:
        if s in seen: continue
        seen.add(s)
        out.write(s + '\n')

print(f"Categorized report: {OUT}")
print(f"All long strings: {LONG}")
print(f"Total unique long strings: {len(seen)}")
