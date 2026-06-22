#!/usr/bin/env python3
"""
Extraction des binaires embarqués dans iremovalpro.dll.

Le .NET 8 NativeAOT bundle contient des ressources:
  - 156+ PE executables (Windows tools)
  - 5 Mach-O (binaires iOS)
  - 314+ GZIP archives (firmwares, payloads)

Ces ressources sont extraites et classifiées par taille et type.
"""
import re
import os
import gzip
import struct
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
OUT = WORK / "04_EXTRACTED" / "embedded_resources"
OUT.mkdir(parents=True, exist_ok=True)

data = DLL.read_bytes()
print(f"[*] {DLL.name}: {len(data):,} bytes")
print(f"[*] Output dir: {OUT}")
print()

# === 1. Extract Mach-O binaries ===
print("=" * 80)
print(" MACHO BINARIES (5 attendues)")
print("=" * 80)

# We already have these extracted to 04_EXTRACTED
# but they were at the END of the .data section, not as resources
# Let me check what's at these offsets in the .NET DLL
macho_offsets = [0x0084f4d3, 0x008534d3, 0x0086b4d3, 0x008812f8, 0x008a3dcd, 0x008ea1a8]

for off in macho_offsets:
    if off + 4 > len(data):
        continue
    magic = data[off:off+4]
    magic_names = {
        b'\xca\xfe\xba\xbe': 'Fat',
        b'\xfe\xed\xfa\xce': '32LE',
        b'\xfe\xed\xfa\xcf': '64LE',
        b'\xcf\xfa\xed\xfe': '64BE',
    }
    name = magic_names.get(magic, '?')
    if magic in (b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):
        print(f"  0x{off:x}: {magic.hex()} ({name})")


# === 2. Extract PE executables ===
print("\n" + "=" * 80)
print(" PE EXECUTABLES (Windows tools embarqués)")
print("=" * 80)

# Find all MZ headers
mz_positions = []
idx = 0x1000  # Skip PE header at 0
while True:
    idx = data.find(b'MZ', idx)
    if idx == -1:
        break
    # Verify it's a real PE (next bytes should be "PE\0\0" within 0x400 bytes)
    if data[idx+0x80:idx+0x84] == b'PE\x00\x00' or b'PE\x00\x00' in data[idx:idx+0x1000]:
        # Check PE header offset
        pe_off = struct.unpack_from('<I', data, idx + 0x3C)[0]
        if pe_off < 0x1000 and idx + pe_off + 4 < len(data):
            if data[idx+pe_off:idx+pe_off+4] == b'PE\x00\x00':
                mz_positions.append((idx, pe_off))
    idx += 1

print(f"[*] Found {len(mz_positions)} PE candidates")

# Filter true PE executables (with proper headers)
real_pes = []
for pos, pe_off in mz_positions:
    try:
        # Read PE optional header
        opt_off = pos + pe_off + 24
        if opt_off + 2 > len(data):
            continue
        magic = struct.unpack_from('<H', data, opt_off)[0]
        if magic not in (0x10B, 0x20B):  # PE32 / PE32+
            continue
        # Get SizeOfImage
        size_of_image = struct.unpack_from('<I', data, opt_off + 56)[0]
        if size_of_image == 0 or size_of_image > 0x10000000:  # Sanity check
            continue
        real_pes.append((pos, pe_off, size_of_image))
    except:
        pass

print(f"[*] Verified {len(real_pes)} real PE files")

# Save the first few
for i, (pos, pe_off, soi) in enumerate(real_pes[:30]):
    out_path = OUT / f"pe_0x{pos:x}.exe"
    # Try to extract a reasonable size
    extract_size = min(soi, 2*1024*1024)  # Cap at 2MB
    try:
        out_path.write_bytes(data[pos:pos+extract_size])
        print(f"  0x{pos:08x}: {extract_size/1024:6.1f} KB -> {out_path.name}")
    except:
        pass

# Check the first few PEs for specific tools
print("\n[*] Identification des PE connus (premiers 30):")
KNOWN_TOOLS = {
    b"idevice_id": "idevice_id.exe (libimobiledevice)",
    b"ideviceinfo": "ideviceinfo.exe (libimobiledevice)",
    b"idevicepair": "idevicepair.exe (libimobiledevice)",
    b"ideviceprox": "ideviceproxy.exe (libimobiledevice)",
    b"idevicerestore": "idevicerestore.exe (libimobiledevice)",
    b"idevicedebug": "idevicedebug.exe (libimobiledevice)",
    b"idevicesyslog": "idevicesyslog.exe (libimobiledevice)",
    b"idevicebackup": "idevicebackup.exe (libimobiledevice)",
    b"afcclient": "afcclient.exe (libimobiledevice)",
    b"usbmuxd": "usbmuxd.exe (libimobiledevice)",
    b"libusbmuxd": "libusbmuxd.dll",
    b"libimobiledevice": "libimobiledevice.dll",
    b"libplist": "libplist-2.0.dll",
    b"checkm8": "checkm8.exe (exploit)",
    b"gaster": "gaster.exe (exploit)",
    b"ipwnder": "ipwnder.exe (exploit)",
    b"ssh": "SSH tool",
    b"scp": "SCP tool",
    b"plink": "plink.exe (PuTTY)",
    b"pscp": "pscp.exe (PuTTY)",
    b"futurerestore": "futurerestore.exe",
    b"iRecovery": "iRecovery.exe",
    b"ideviceactivation": "ideviceactivation.exe",
    b"ideviceenterrecovery": "ideviceenterrecovery.exe",
}

# Look for known tool names in each PE
for i, (pos, pe_off, soi) in enumerate(real_pes[:30]):
    out_path = OUT / f"pe_0x{pos:x}.exe"
    if not out_path.exists():
        continue
    pe_data = out_path.read_bytes()
    # Find printable strings >= 6 chars
    strings = re.findall(rb'[\x20-\x7e]{6,}', pe_data)
    for tool_str, tool_name in KNOWN_TOOLS.items():
        for s in strings[:500]:  # check first 500 strings
            if tool_str in s.lower() or tool_str in s:
                print(f"  0x{pos:x}: {tool_name} (matched: {s[:60].decode()})")
                break


# === 3. Extract GZIP files ===
print("\n" + "=" * 80)
print(" GZIP ARCHIVES (payloads, firmwares)")
print("=" * 80)

gzip_positions = []
idx = 0
while True:
    idx = data.find(b'\x1f\x8b', idx)
    if idx == -1:
        break
    gzip_positions.append(idx)
    idx += 1

print(f"[*] Found {len(gzip_positions)} GZIP headers")

# Try to extract a few
gzip_extracted = []
for pos in gzip_positions[:10]:
    try:
        # Find the end (look for non-gzip content)
        end = pos + 16
        # Try to decompress
        import io
        gz_data = data[pos:pos+min(50*1024*1024, len(data)-pos)]
        with gzip.open(io.BytesIO(gz_data), 'rb') as g:
            decompressed = g.read(1024*1024)  # max 1MB preview
        # Save
        out_path = OUT / f"gzip_0x{pos:x}.bin"
        out_path.write_bytes(decompressed[:1024*1024])
        print(f"  0x{pos:x}: decompressed {len(decompressed)/1024:.1f} KB (preview)")
        gzip_extracted.append((pos, len(decompressed)))
    except Exception as e:
        # Try a small extract
        pass

# === 4. Check for SSH key files ===
print("\n" + "=" * 80)
print(" SSH KEY FILES (PEM format)")
print("=" * 80)

ssh_markers = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"ssh-rsa",
    b"ssh-ed25519",
    b"ecdsa-sha2-nistp256",
]

for marker in ssh_markers:
    idx = 0
    count = 0
    while True:
        idx = data.find(marker, idx)
        if idx == -1:
            break
        count += 1
        idx += 1
    if count > 0:
        print(f"  {marker[:40].decode(errors='ignore')}: {count} occurrences")

# === 5. Look for IPSW (firmware) markers ===
print("\n" + "=" * 80)
print(" FIRMWARE / IPSW MARKERS")
print("=" * 80)

ipsw_markers = [
    b"iPhone", b"iPad", b"iPod",
    b"BuildManifest.plist",
    b"Restore.plist",
    b"kernelcache",
    b"DeviceTree",
    b"LLB", b"iBoot", b"iBSS", b"iBEC",
    b"bspatch", b"bputil",
]

for marker in ipsw_markers:
    idx = 0
    count = 0
    while True:
        idx = data.find(marker, idx)
        if idx == -1:
            break
        count += 1
        idx += 1
    if count > 0:
        print(f"  {marker.decode()}: {count}")


# === 6. Look for known jailbreak packages ===
print("\n" + "=" * 80)
print(" JAILBREAK / CYDIA PACKAGES")
print("=" * 80)

jb_packages = [
    b"Cydia", b"Substrate", b"Substitute", b"libsubstrate",
    b"MobileSubstrate", b"MobileSubstrate.dylib",
    b"TweakInject", b"Ellekit", b"libellekit",
    b"apt", b"dpkg", b"cycript",
    b"saurik", b"Saurik", b"Jay Freeman",
    b"blackra1n", b"evasi0n", b"pangu", b"unc0ver", b"checkra1n", b"palera1n",
    b"Dopamine", b"Taurine", b"Odyssey",
    b"Procursus", b"rootless", b"roothide",
    b"Frida", b"FridaGadget", b"frida-agent",
    b"com.apple.springboard", b"com.apple.backboardd",
]

for marker in jb_packages:
    cnt = data.count(marker)
    if cnt > 0:
        print(f"  {marker.decode()}: {cnt}")

print("\n" + "=" * 80)
print(f" RÉSUMÉ")
print("=" * 80)
print(f"  - 5 Mach-O iOS binaries intégrées (déjà extraites)")
print(f"  - {len(real_pes)} PE executables Windows embarqués")
print(f"  - {len(gzip_positions)} GZIP archives (payloads)")
print(f"  - Resources extraites dans : {OUT}")
print(f"  - Taille totale extraite : {sum(f.stat().st_size for f in OUT.iterdir() if f.is_file())/1024/1024:.1f} MB")
