#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iRemoval PRO - Full RE analysis:
1. Extract embedded Mach-O binaries from iremovalpro.dll
2. Disassemble blackhound.dylib (Cydia Substrate hooks)
3. Disassemble minaeraser12 (NAND eraser)
4. Identify the actual hooked methods
"""
import sys, struct, os, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
OUT_DIR = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis\extracted'
os.makedirs(OUT_DIR, exist_ok=True)

with open(DLL, 'rb') as f:
    data = f.read()

# ============================================================
# STEP 1: Extract Mach-O binaries
# ============================================================
print("="*80)
print("STEP 1: EXTRACT EMBEDDED MACH-O BINARIES")
print("="*80)

def get_macho_size(buf, start):
    """Calculate Mach-O size by parsing segments."""
    if buf[start:start+4] != b'\xcf\xfa\xed\xfe':
        return None
    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from('<IIIIIII', buf, start+4)
    pos = start + 32
    end_lc = pos + sizeofcmds
    max_file_end = end_lc
    while pos < end_lc:
        if pos + 8 > len(buf): break
        cmd, cmdsize = struct.unpack_from('<II', buf, pos)
        if cmdsize == 0: break
        if cmd == 0x19:  # LC_SEGMENT_64
            fileoff = struct.unpack_from('<Q', buf, pos + 40)[0]
            filesize = struct.unpack_from('<Q', buf, pos + 48)[0]
            abs_end = fileoff + filesize
            if abs_end > max_file_end: max_file_end = abs_end
        pos += cmdsize
    size = ((max_file_end + 4095) // 4096) * 4096
    return {'cputype': cputype, 'cpusubtype': cpusubtype, 'filetype': filetype,
            'ncmds': ncmds, 'sizeofcmds': sizeofcmds, 'size': size, 'max_file_end': max_file_end}

# Find all Mach-O positions
positions = []
p = 0
while True:
    p = data.find(b'\xcf\xfa\xed\xfe', p)
    if p < 0: break
    positions.append(p)
    p += 1

cpu_n = {0x0100000C: 'ARM64', 0x01000007: 'ARM', 0x0100000D: 'ARM64E'}
subtype_n = {0: 'ALL', 2: 'ARM64E', 1: 'ARM_V8'}
file_t_n = {2: 'EXECUTE', 6: 'DYLIB', 8: 'BUNDLE'}

extracted = []
for pos in positions:
    info = get_macho_size(data, pos)
    if not info: continue
    cpu = cpu_n.get(info['cputype'], f'0x{info["cputype"]:x}')
    subtype = subtype_n.get(info['cpusubtype'], f'0x{info["cpusubtype"]:x}')
    file_t = file_t_n.get(info['filetype'], f'0x{info["filetype"]:x}')
    out_name = f'macho_{pos:x}_{file_t}_{cpu}_{subtype}.bin'
    out_path = os.path.join(OUT_DIR, out_name)
    with open(out_path, 'wb') as f:
        f.write(data[pos:pos+info['size']])
    extracted.append((pos, info, out_path, cpu, subtype, file_t))
    print(f"  0x{pos:x}: {file_t:8} {cpu:6}({subtype:6})  size=0x{info['size']:x}  ->  {out_name}")

# Get install_name for each
print("\n  Install names / dylibs:")
for pos, info, path, cpu, subtype, file_t in extracted:
    with open(path, 'rb') as f:
        b = f.read()
    pos_lc = 32
    end_lc = 32 + info['sizeofcmds']
    while pos_lc < end_lc:
        if pos_lc + 8 > len(b): break
        cmd, cmdsize = struct.unpack_from('<II', b, pos_lc)
        if cmdsize == 0: break
        if cmd == 0xd:  # LC_ID_DYLIB
            name_off = struct.unpack_from('<I', b, pos_lc + 8)[0]
            abs_name = pos_lc + name_off
            end = b.find(b'\0', abs_name)
            name = b[abs_name:end].decode('latin1', 'replace')
            print(f"    0x{pos:x}: install_name = {name}")
        pos_lc += cmdsize

# ============================================================
# STEP 2: Disassemble blackhound.dylib (the hook binary)
# ============================================================
print("\n" + "="*80)
print("STEP 2: DISASSEMBLE blackhound.dylib (Cydia Substrate hooks)")
print("="*80)

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def disasm_file(path, cpu='ARM64', start_offset=0, end_offset=None, label_offset=0):
    """Disassemble a Mach-O section using capstone."""
    with open(path, 'rb') as f:
        b = f.read()
    if end_offset is None: end_offset = len(b)
    if start_offset >= len(b): return []
    code = b[start_offset:end_offset]
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cs.detail = False
    instrs = []
    for ins in cs.disasm(code, label_offset + start_offset):
        instrs.append(ins)
    return instrs

# Find blackhound (the DYLIBs)
bh_files = [p for pos, info, p, cpu, st, ft in extracted if ft == 'DYLIB']
if not bh_files:
    print("  No DYLIB found!")
else:
    for bh in bh_files:
        with open(bh, 'rb') as f:
            b = f.read()
        print(f"\n  File: {os.path.basename(bh)} ({len(b):,} bytes)")

        # Parse all LC_SEGMENT_64 to find __TEXT (code) and __DATA
        segments = []
        ncmds, sizeofcmds = struct.unpack_from('<II', b, 28)
        pos_lc = 32
        end_lc = 32 + sizeofcmds
        while pos_lc < end_lc:
            if pos_lc + 8 > len(b): break
            cmd, cmdsize = struct.unpack_from('<II', b, pos_lc)
            if cmdsize == 0: break
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = b[pos_lc+8:pos_lc+24].rstrip(b'\0').decode('latin1', 'replace')
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', b, pos_lc+24)
                maxprot, initprot, nsects, flags = struct.unpack_from('<IIII', b, pos_lc+56)
                segments.append({
                    'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                    'fileoff': fileoff, 'filesize': filesize, 'nsects': nsects
                })
                # Also parse sections
                sec_off = pos_lc + 72
                for i in range(nsects):
                    sec = b[sec_off+i*80:sec_off+(i+1)*80]
                    sectname = sec[:16].rstrip(b'\0').decode('latin1', 'replace')
                    seg_str = sec[16:32].rstrip(b'\0').decode('latin1', 'replace')
                    s_addr, s_size, s_offset = struct.unpack_from('<QQI', sec, 32)
                    segments[-1].setdefault('sections', []).append({
                        'sectname': sectname, 'segname': seg_str,
                        'addr': s_addr, 'size': s_size, 'offset': s_offset
                    })
            pos_lc += cmdsize

        # Print segments
        for s in segments:
            secs = ', '.join(f"{sec['sectname']}({sec['size']})" for sec in s.get('sections', []))
            print(f"    SEG {s['name']:12}  fileoff=0x{s['fileoff']:08x}  filesize=0x{s['filesize']:08x}  [{secs}]")

        # Find __TEXT.__text (executable code)
        text_section = None
        for s in segments:
            for sec in s.get('sections', []):
                if sec['sectname'] == '__text':
                    text_section = sec
                    text_section['segname'] = s['name']
                    break
            if text_section: break

        if not text_section:
            print("    No __text section found")
            continue

        # Find entry point
        entry = None
        pos_lc = 32
        end_lc = 32 + sizeofcmds
        while pos_lc < end_lc:
            if pos_lc + 8 > len(b): break
            cmd, cmdsize = struct.unpack_from('<II', b, pos_lc)
            if cmdsize == 0: break
            if cmd == 0x80000018:  # LC_MAIN
                entryoff, stacksize = struct.unpack_from('<QQ', b, pos_lc + 8)
                entry = entryoff
                break
            pos_lc += cmdsize
        print(f"\n    Entry point: file offset 0x{entry:x}" if entry else "    No LC_MAIN found")

        # Disassemble from start of __text (typically entry is in there)
        text_off = text_section['offset']
        text_size = text_section['size']
        text_addr = text_section['addr']

        # Disassemble entry point
        if entry:
            print(f"\n    === ENTRY POINT @ file 0x{entry:x} (VA 0x{text_addr+entry-text_off:x}) ===")
            instrs = disasm_file(bh, cpu, entry, entry + 200, text_addr)
            for ins in instrs[:30]:
                print(f"      0x{ins.address:x}: {ins.mnemonic:10} {ins.op_str}")

        # Find and disassemble the Logos hooks
        print(f"\n    === LOGOS HOOK FUNCTIONS ===")
        # Search for "logos_method$" and "logos_orig$" strings to find the constructors
        for marker in [b'__logos_method$', b'__logos_orig$', b'__logosLocalCtor_']:
            pos = 0
            while True:
                p = b.find(marker, pos)
                if p < 0: break
                # Get the rest of the symbol name
                end = b.find(b'\0', p)
                name = b[p:end].decode('latin1', 'replace')
                print(f"\n    Symbol: {name}")
                # The hook function is a C constructor that calls _logos_function$_ungrouped$<class>$<method>
                # It's typically in __mod_init_func or referenced from there
                pos = end + 1

        # Find constructor functions (LC_MAIN or function prologues)
        # Disassemble first 4 KB of __text to find function prologues
        print(f"\n    === FIRST 4096 BYTES OF __text (VA 0x{text_addr:x}) ===")
        sample_size = min(4096, text_size)
        instrs = disasm_file(bh, cpu, text_off, text_off + sample_size, text_addr)
        cnt = 0
        for ins in instrs:
            if ins.mnemonic in ('bl', 'b', 'b.eq', 'b.ne', 'cbz', 'cbnz', 'tbz', 'tbnz'):
                print(f"      0x{ins.address:x}: {ins.mnemonic:10} {ins.op_str}")
                cnt += 1
                if cnt > 60: break

# ============================================================
# STEP 3: Look for request body template
# ============================================================
print("\n" + "="*80)
print("STEP 3: SEARCH FOR REQUEST BODY TEMPLATE (REST/REST TEMPLATE)")
print("="*80)

# Search for typical JSON request body fields in all extracted Mach-O
import re
all_extracted = ' '.join([open(p, 'rb').read().decode('latin1', 'replace') for _, _, p, _, _, _ in extracted])
keys = ['UDID', 'ECID', 'IMEI', 'orderId', 'ticket', 'signature', 'BUID', 'PROG', 'BES', 'BBI',
        'BLS', 'ProductType', 'ProductVersion', 'ChipID', 'BoardID', 'iOSVersion', 'iOS',
        'requestActivation', 'activation', 'hwid', 'apikey', 'clientSig', 'fairPlay', 'WildcardTicket',
        'fairplay', 'fairplayKey', 'activationTicket', 'restore', 'recovery', 'baseband',
        'checkm8', 'checkm8Status', 'appleID', 'AppleID', 'nonce', 'cert', 'BESData', 'BBIResponse',
        'orderType', 'IMEI2', 'ICCID', 'IMSI', 'IMEI', 'UDID2', 'deviceCert', 'RequestActivation',
        'BESRequest', 'wildcard', 'fairplaycert', 'fairkey', 'fairKey', 'blackhound', 'orderId',
        'BESDeviceCert', 'BESCert', 'BBData', 'machineId']
print("  Keys found in Mach-O binaries:")
for k in keys:
    if k in all_extracted:
        # Find context
        idx = all_extracted.find(k)
        ctx = all_extracted[max(0,idx-50):idx+100]
        ctx = re.sub(r'[\x00-\x1f]+', ' ', ctx)[:200]
        print(f"    {k:20} -> ...{ctx}...")

# Search for typical Apple activation request plist keys
print("\n  Looking for plist-style keys in blackhound.dylib (for activation request):")
for bh in bh_files:
    with open(bh, 'rb') as f:
        b = f.read()
    # Find <key>...</key> patterns
    keys_in_plist = re.findall(rb'<key>([^<]+)</key>', b)
    unique = sorted(set(k.decode() for k in keys_in_plist))
    for k in unique:
        if any(c in k for c in '._/') and len(k) > 4:
            print(f"    {k}")
    print(f"  (Total: {len(unique)} unique <key> entries)")