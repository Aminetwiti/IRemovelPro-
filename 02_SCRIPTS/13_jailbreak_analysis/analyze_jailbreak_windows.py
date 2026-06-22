#!/usr/bin/env python3
"""
Recherche du flux de jailbreak dans iremovalpro.dll (côté Windows).
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

# Outils jailbreak externes
EXTERNAL_TOOLS = {
    "checkm8 / ipwnder": [b"checkm8", b"ipwnder", b"gaster", b"pwned", b"limera1n", b"check_ra1n"],
    "palera1n": [b"palera1n", b"palen1x", b"rootlessjb"],
    "minaeraser (A12+)": [b"minaeraser", b"A12Eraser", b"a12eraser"],
    "libimobiledevice tools": [b"idevice_id", b"ideviceinfo", b"idevicepair", b"ideviceprox", b"idevicerestore"],
    "iRecovery / iRestore": [b"iRecovery", b"iRestore", b"iBootRecovery"],
    "Futurerestore / gaster": [b"futurerestore", b"futureRestore"],
    "iBoot exploit": [b"iBEC", b"iBSS", b"iBoot", b"LLB"],
    "SSH/SCP tools": [b"sshpass", b"scp", b"openssh", b"plutil", b"pledit"],
    "Telegram Bot": [b"Telegram", b"t.me/", b"webhook", b"bot"],
}

print("=" * 80)
print(" OUTILS DE JAILBREAK RÉFÉRENCÉS PAR iremovalpro.dll")
print("=" * 80)
print()

for category, patterns in EXTERNAL_TOOLS.items():
    print(f"\n[{category}]")
    found_any = False
    for pat in patterns:
        pat_u16 = pat.decode('ascii', errors='ignore').encode('utf-16-le')
        cnt_ascii = data.count(pat)
        cnt_utf16 = data.count(pat_u16)
        total = cnt_ascii + cnt_utf16
        if total > 0:
            found_any = True
            print(f"  {pat.decode('ascii', errors='ignore'):35} -> {total} (ASCII:{cnt_ascii} UTF16:{cnt_utf16})")
    if not found_any:
        print(f"  (aucun)")

# Commandes shell
print("\n" + "=" * 80)
print(" COMMANDES SHELL DANS iremovalpro.dll (UTF-16LE)")
print("=" * 80)
print("\n[Commandes SSH/SCP]")
ssh_keywords = [b'ssh ', b'scp ', b'sftp ', b'sshpass', b'plutil', b'pledit',
                b'chmod', b'killall', b'launchctl', b'/var/root/identity',
                b'rm -rf', b'mkdir', b'launchctl unload', b'launchctl load']

for kw in ssh_keywords:
    kw_u16 = kw.decode('ascii', errors='ignore').encode('utf-16-le')
    idx = 0
    while True:
        idx = data.find(kw_u16, idx)
        if idx == -1:
            break
        s = max(0, idx - 50)
        e = min(len(data), idx + 200)
        ctx = data[s:e]
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,}', ctx):
            txt = m.group().decode('utf-16-le', errors='ignore')
            if len(txt) > 3 and not txt.startswith('@'):
                if any(c in txt for c in ['/', ' ', '\\', '-']):
                    print(f"  0x{idx:08x}: {txt[:150]}")
                    break
        idx += 1

# Binaire count
print("\n" + "=" * 80)
print(" BINAIRES EMBARQUÉS (signatures)")
print("=" * 80)
magic_bytes = {
    b"MZ\x90\x00": "PE executable",
    b"\x7fELF": "ELF binary",
    b"\xca\xfe\xba\xbe": "Mach-O Fat",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit",
    b"PK\x03\x04": "ZIP archive",
    b"\x1f\x8b": "GZIP archive",
}

for magic, desc in magic_bytes.items():
    idx = 0
    count = 0
    while True:
        idx = data.find(magic, idx)
        if idx == -1:
            break
        if count < 3:
            print(f"  0x{idx:08x}: {desc} ({magic[:4].hex()})")
        count += 1
        idx += 1
    if count > 3:
        print(f"  ... and {count-3} more")

# JAILBREAK / CYDIA
print("\n" + "=" * 80)
print(" JAILBREAK / CYDIA PACKAGES")
print("=" * 80)
jb_packages = [b"Cydia", b"Substrate", b"libsubstrate", b"MobileSubstrate",
                b"MobileSubstrate.dylib", b"TweakInject", b"Ellekit", b"apt",
                b"dpkg", b"cycript", b"saurik", b"blackra1n", b"evasi0n",
                b"pangu", b"unc0ver", b"checkra1n", b"palera1n", b"Dopamine",
                b"Taurine", b"Odyssey", b"Procursus", b"rootless", b"roothide",
                b"Frida", b"FridaGadget", b"com.apple.springboard", b"com.apple.backboardd"]

for marker in jb_packages:
    cnt = data.count(marker)
    if cnt > 0:
        print(f"  {marker.decode()}: {cnt}")

# Messages d'erreur
print("\n" + "=" * 80)
print(" MESSAGES D'ERREUR JAILBREAK")
print("=" * 80)
JAILBREAK_ERRORS = [b"DFU", b"Pwned", b"Pongo", b"DFU mode", b"recovery mode",
                    b"limera1n", b"heap_overflow", b"USB request", b"could not enter",
                    b"failed to enter", b"not in DFU", b"jailbreak failed",
                    b"exploit failed", b"could not exploit", b"Couldn't find iRemovalRa1n",
                    b"iOS Device Activator", b"MobileActivation-", b"checkm8 failed",
                    b"palera1n failed", b"exploit", b"vulnerability", b"unpatchable",
                    b"SecureROM", b"bootrom", b"heap", b"overflow",
                    b"use-after-free", b"UAF", b"A12 eraser", b"A12Eraser", b"minaeraser"]

for err in JAILBREAK_ERRORS:
    err_u16 = err.decode('ascii', errors='ignore').encode('utf-16-le')
    cnt = data.count(err_u16)
    if cnt > 0:
        idx = data.find(err_u16)
        s = max(0, idx - 50)
        e = min(len(data), idx + 150)
        ctx = data[s:e]
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){5,}', ctx):
            txt = m.group().decode('utf-16-le', errors='ignore')
            if len(txt) > 5:
                print(f"  {err.decode():30} -> {txt[:120]}")
                break
