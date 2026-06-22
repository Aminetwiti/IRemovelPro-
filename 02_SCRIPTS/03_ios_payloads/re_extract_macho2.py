#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-extract Mach-O with proper size calculation via segment parsing."""
import sys, struct, os, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
OUT_DIR = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis\extracted'
os.makedirs(OUT_DIR, exist_ok=True)

with open(DLL, 'rb') as f:
    data = f.read()

def get_macho_size(buf, start):
    """Calculate Mach-O size by parsing all load commands and segment data."""
    if buf[start:start+4] != b'\xcf\xfa\xed\xfe':
        return None
    # 64-bit header: 32 bytes
    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from('<IIIIIII', buf, start+4)
    # Walk load commands
    pos = start + 32
    end_lc = pos + sizeofcmds
    # Find max (offset + filesize) from segments
    max_file_end = end_lc
    while pos < end_lc:
        if pos + 8 > len(buf): break
        cmd, cmdsize = struct.unpack_from('<II', buf, pos)
        if cmdsize == 0: break
        if cmd == 0x19:  # LC_SEGMENT_64
            # segment_command_64: cmd(4) + cmdsize(4) + segname(16) + vmaddr(8) + vmsize(8) + fileoff(8) + filesize(8) + maxprot(4) + initprot(4) + nsects(4) + flags(4) = 72
            # Then nsects * section_64 (80 bytes each)
            # Actually command layout: cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4) flags(4) = 72
            fileoff, filesize = struct.unpack_from('<QQ', buf, pos + 24 + 8 + 8)
            # 24 = cmd(4) + cmdsize(4) + segname(16). 8+8 = vmaddr+vmsize
            # So fileoff starts at offset 24 + 16 = 40, filesize at 48
            fileoff = struct.unpack_from('<Q', buf, pos + 40)[0]
            filesize = struct.unpack_from('<Q', buf, pos + 48)[0]
            abs_end = fileoff + filesize
            if abs_end > max_file_end:
                max_file_end = abs_end
        pos += cmdsize
    # Round up to 4 KB boundary
    size = ((max_file_end + 4095) // 4096) * 4096
    return {
        'cputype': cputype, 'cpusubtype': cpusubtype, 'filetype': filetype,
        'ncmds': ncmds, 'sizeofcmds': sizeofcmds, 'size': size, 'max_file_end': max_file_end
    }

# Find all MH_MAGIC_64 positions
positions = []
p = 0
while True:
    p = data.find(b'\xcf\xfa\xed\xfe', p)
    if p < 0: break
    positions.append(p)
    p += 1

print("="*80)
print("MACH-O BINARIES - PROPER SIZES")
print("="*80)

for pos in positions:
    info = get_macho_size(data, pos)
    if not info: continue
    cpu = {0x0100000C: 'ARM64', 0x01000007: 'ARM', 0x0100000D: 'ARM64E'}.get(info['cputype'], f'0x{info["cputype"]:x}')
    subtype = {0: 'ALL', 2: 'ARM64E', 1: 'ARM_V8'}.get(info['cpusubtype'], f'0x{info["cpusubtype"]:x}')
    file_t = {2: 'EXECUTE', 6: 'DYLIB', 8: 'BUNDLE', 10: 'PRELOAD'}.get(info['filetype'], f'0x{info["filetype"]:x}')
    print(f"\n  @ 0x{pos:x}: {file_t} {cpu}({subtype}) ncmds={info['ncmds']} cmdsize={info['sizeofcmds']} max_file_end=0x{info['max_file_end']:x} size=0x{info['size']:x} ({info['size']/1024:.1f} KB)")
    out_name = f'macho_{pos:x}_{file_t}_{cpu}_{subtype}.bin'
    out_path = os.path.join(OUT_DIR, out_name)
    with open(out_path, 'wb') as f:
        f.write(data[pos:pos+info['size']])
    print(f"    -> {out_path}")
    # Look at LC_ID_DYLIB to get dylib install_name
    pos_lc = pos + 32
    end_lc = pos_lc + info['sizeofcmds']
    while pos_lc < end_lc:
        cmd, cmdsize = struct.unpack_from('<II', data, pos_lc)
        if cmdsize == 0: break
        if cmd == 0xd:  # LC_ID_DYLIB
            # dylib_command: cmd(4) cmdsize(4) dylib.name.offset(4) timestamp(4) cur_ver(4) compat_ver(4)
            name_off = struct.unpack_from('<I', data, pos_lc + 8)[0]
            abs_name = pos_lc + name_off
            end = data.find(b'\0', abs_name)
            name = data[abs_name:end].decode('latin1', 'replace')
            print(f"    LC_ID_DYLIB install_name: {name}")
        elif cmd == 0xc:  # LC_LOAD_DYLIB
            name_off = struct.unpack_from('<I', data, pos_lc + 8)[0]
            abs_name = pos_lc + name_off
            end = data.find(b'\0', abs_name)
            name = data[abs_name:end].decode('latin1', 'replace')
            print(f"    LC_LOAD_DYLIB: {name}")
        pos_lc += cmdsize

# Also extract the strings from each binary to identify what they are
print("\n" + "="*80)
print("STRING SCAN IN EXTRACTED BINARIES")
print("="*80)
import re
for f in sorted(os.listdir(OUT_DIR)):
    if not f.endswith('.bin'): continue
    path = os.path.join(OUT_DIR, f)
    with open(path, 'rb') as fp:
        b = fp.read()
    # Find ASCII strings
    strings = re.findall(rb'[\x20-\x7e]{8,}', b)
    interesting = [s for s in strings if any(kw in s for kw in
                   [b'blackhound', b'minaeraser', b'panyol', b'mobileactivationd',
                    b'restore', b'erase', b'recovery', b'iboot', b'BES', b'BBI',
                    b'baseband', b'ticket', b'activation', b'iCloud', b'lockdown',
                    b'fdr', b'checkm8', b'nonce', b'apple', b'verify', b'ecid',
                    b'Substrate', b'logos', b'hook', b'dylib', b'MobileSubstrate',
                    b'com.apple', b'Cydia'])]
    print(f"\n  {f}:")
    for s in set(interesting):
        print(f"    {s.decode('latin1', 'replace')[:100]}")