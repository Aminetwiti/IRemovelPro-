#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract embedded Mach-O binaries from .NET NativeAOT DLL."""
import sys, struct, os, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
OUT_DIR = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis\extracted'
os.makedirs(OUT_DIR, exist_ok=True)

with open(DLL, 'rb') as f:
    data = f.read()

def parse_macho_header(buf, start):
    """Parse Mach-O header at given offset, return size."""
    if buf[start:start+4] == b'\xcf\xfa\xed\xfe':
        magic = 'MH_MAGIC_64'
    elif buf[start:start+4] == b'\xfe\xed\xfa\xcf':
        magic = 'MH_CIGAM_64'
    else:
        return None
    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from('<IIIIIII', buf, start+4)
    cpu = {0x0100000C: 'ARM64', 0x01000007: 'ARM', 0x0100000D: 'ARM64E'}.get(cputype, f'0x{cputype:x}')
    subtype = {0: 'ALL', 2: 'ARM64E', 1: 'ARM_V8'}.get(cpusubtype, f'0x{cpusubtype:x}')
    file_t = {2: 'EXECUTE', 6: 'DYLIB', 8: 'BUNDLE', 10: 'PRELOAD'}.get(filetype, f'0x{filetype:x}')
    return {
        'magic': magic, 'cpu': cpu, 'subtype': subtype, 'type': file_t,
        'ncmds': ncmds, 'sizeofcmds': sizeofcmds, 'flags': flags
    }

def find_macho_size(buf, start):
    """Find end of Mach-O by following load commands."""
    info = parse_macho_header(buf, start)
    if not info: return None, None
    # Header is 32 bytes (64-bit)
    cmd_off = start + 32
    end = cmd_off + info['sizeofcmds']
    # Walk load commands
    cmds = []
    pos = cmd_off
    while pos < end:
        if pos + 8 > len(buf):
            break
        cmd, cmdsize = struct.unpack_from('<II', buf, pos)
        cmds.append((cmd, cmdsize, pos))
        if cmdsize == 0: break
        pos += cmdsize
    return info, cmds

# Find all Mach-O and FAT magic positions
print("="*80)
print("MACH-O BINARIES EMBEDDED IN DLL")
print("="*80)

positions = []
# MH_MAGIC_64
p = 0
while True:
    p = data.find(b'\xcf\xfa\xed\xfe', p)
    if p < 0: break
    positions.append(('MH64', p))
    p += 1
# FAT_MAGIC
p = 0
while True:
    p = data.find(b'\xca\xfe\xba\xbe', p)
    if p < 0: break
    positions.append(('FAT', p))
    p += 1

positions.sort()

# Get more detail for each
extracted = []
for kind, pos in positions:
    if kind == 'MH64':
        info, cmds = find_macho_size(data, pos)
        if not info:
            print(f"  @ 0x{pos:x}: INVALID MH_MAGIC_64")
            continue
        # Get full size: header (32) + sizeofcmds + maybe data after?
        # Some Mach-O have data after load commands (segment data). Let's check.
        size = 32 + info['sizeofcmds']
        # Look at segments to find end of data
        # For simplicity, use max(cmd + cmdsize) for the load commands region
        end_lc = 32 + info['sizeofcmds']
        # Get file size by checking next Mach-O or end of section
        # Look ahead 100KB max for end markers
        # A simple heuristic: scan for next Mach-O header or null block
        next_pos = pos + 100000  # max search
        for kind2, pos2 in positions:
            if pos2 > pos and pos2 < next_pos:
                next_pos = pos2
        # Clamp to within reasonable bounds
        candidate_size = min(next_pos - pos, 1000000)
        # Find first big zero block
        scan_start = pos + 32 + info['sizeofcmds'] + 1024  # after cmds
        big_null = scan_start
        null_count = 0
        for i in range(scan_start, min(scan_start + 200000, len(data))):
            if data[i] == 0:
                null_count += 1
                if null_count > 2048:
                    big_null = i - 2048
                    break
            else:
                null_count = 0
        candidate_size = min(candidate_size, big_null - pos + 256)
        # Round up
        candidate_size = ((candidate_size + 4095) // 4096) * 4096
        print(f"\n  @ 0x{pos:x}: {info['type']} {info['cpu']}({info['subtype']}) ncmds={info['ncmds']} cmdsize={info['sizeofcmds']} ~size={candidate_size}")
        # Print first 8 load commands
        print(f"    Load commands:")
        for cmd, cmdsize, cmd_pos in cmds[:12]:
            cmd_names = {
                0x1: 'LC_SEGMENT', 0x19: 'LC_SEGMENT_64', 0x2: 'LC_SYMTAB',
                0xb: 'LC_DYSYMTAB', 0xc: 'LC_LOAD_DYLIB', 0xd: 'LC_ID_DYLIB',
                0xe: 'LC_LOAD_DYLINKER', 0x15: 'LC_SUB_FRAMEWORK',
                0x80000018: 'LC_MAIN', 0x80000022: 'LC_SOURCE_VERSION',
                0x80000028: 'LC_BUILD_VERSION', 0x26: 'LC_RPATH',
                0x80000019: 'LC_DYLD_EXPORTS_TRIE', 0x8000001a: 'LC_DYLD_CHAINED_FIXUPS',
                0x8000001b: 'LC_FILESET_ENTRY'
            }
            cmd_name = cmd_names.get(cmd, f'cmd=0x{cmd:x}')
            # Read dylib name for LC_LOAD_DYLIB
            extra = ''
            if cmd == 0xc:  # LC_LOAD_DYLIB
                # dylib_command: cmd(4) + cmdsize(4) + dylib.name.offset(4) + timestamp(4) + cur_ver(4) + compat_ver(4)
                name_off = struct.unpack_from('<I', data, cmd_pos + 8)[0]
                abs_name_off = cmd_pos + name_off
                end = data.find(b'\0', abs_name_off)
                dylib_name = data[abs_name_off:end].decode('latin1', 'replace')
                extra = f' name={dylib_name}'
            elif cmd == 0x80000028:  # LC_BUILD_VERSION
                platform, minos, sdk, ntools = struct.unpack_from('<IIII', data, cmd_pos + 8)
                platforms = {1: 'MACOS', 2: 'IOS', 3: 'TVOS', 4: 'WATCHOS'}
                plat = platforms.get(platform, f'0x{platform:x}')
                ver = f'{minos>>16}.{minos&0xffff}.{(sdk>>16)}.{sdk&0xffff}'
                extra = f' platform={plat} ver={ver}'
            print(f"      [{cmd_pos - pos:04x}] cmd=0x{cmd:08x} size={cmdsize} {cmd_name}{extra}")
        # Extract
        out_name = f'macho_{pos:x}_{info["type"]}_{info["cpu"]}.bin'
        out_path = os.path.join(OUT_DIR, out_name)
        with open(out_path, 'wb') as f:
            f.write(data[pos:pos+candidate_size])
        extracted.append((pos, info, out_path))
        print(f"      EXTRACTED -> {out_path}")
    elif kind == 'FAT':
        # FAT binary
        if data[pos:pos+4] == b'\xca\xfe\xba\xbe':
            nfat = struct.unpack_from('>I', data, pos+4)[0]
            print(f"\n  @ 0x{pos:x}: FAT binary with {nfat} architectures")
            for i in range(nfat):
                off, size = struct.unpack_from('>II', data, pos+8+i*20)
                cpu, _ = struct.unpack_from('>II', data, pos+8+i*20+8)
                cpu_n = {12: 'ARM64', 7: 'ARM'}.get(cpu, f'0x{cpu:x}')
                print(f"      arch[{i}]: cpu={cpu_n} offset=0x{off:x} size={size}")
                # Extract this architecture
                arc_start = pos + off
                arc_size = size
                out_name = f'fat_{pos:x}_{cpu_n}.bin'
                out_path = os.path.join(OUT_DIR, out_name)
                with open(out_path, 'wb') as f:
                    f.write(data[arc_start:arc_start+arc_size])
                # Get info
                info = parse_macho_header(data, arc_start)
                if info:
                    print(f"        -> {info['type']} {info['cpu']} saved to {out_path}")
                extracted.append((arc_start, info, out_path))

print(f"\n{'='*80}")
print(f"EXTRACTED {len(extracted)} BINARIES")
print('='*80)
for pos, info, path in extracted:
    print(f"  0x{pos:x}: {info['type'] if info else '?'} {info['cpu'] if info else '?'} -> {os.path.basename(path)}")