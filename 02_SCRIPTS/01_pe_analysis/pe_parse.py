#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyse PE basique: headers, sections, imports, exports, entropie."""
import sys, struct, os, math, io
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
EXE = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iRemoval PRO.exe'
OUT = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis\pe_report.txt'

def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def rva2off(rva, sections):
    for s in sections:
        if s['VA'] <= rva < s['VA'] + s['VSize']:
            return s['Raw'] + (rva - s['VA'])
    return None

def parse_pe(path, out):
    with open(path, 'rb') as f:
        data = f.read()
    out.write(f"\n{'='*80}\nFILE: {path}\nSize: {len(data):,} bytes\n")
    if data[:2] != b'MZ':
        out.write("  [!] Not MZ\n"); return
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        out.write("  [!] No PE sig\n"); return
    machine, nsects, _, _, _, optsize, chars = struct.unpack_from('<HHIIIHH', data, pe_off+4)
    machine_s = {0x14c:'x86', 0x8664:'x64', 0x1c0:'ARM', 0xaa64:'ARM64'}.get(machine, f'0x{machine:x}')
    out.write(f"  Machine     : {machine_s}\n")
    out.write(f"  Sections    : {nsects}\n")
    out.write(f"  FileChars   : 0x{chars:04x}\n")
    opt_off = pe_off + 24
    magic = struct.unpack_from('<H', data, opt_off)[0]
    is_pe32_plus = magic == 0x20b
    out.write(f"  PE format   : {'PE32+' if is_pe32_plus else 'PE32'}\n")
    fmt = '<' + ('Q' if is_pe32_plus else 'I')
    ep_rva = struct.unpack_from(fmt, data, opt_off + 16)[0]
    img_base = struct.unpack_from(fmt, data, opt_off + (24 if is_pe32_plus else 28))[0]
    sz_img = struct.unpack_from('<I', data, opt_off + (56 if is_pe32_plus else 60))[0]
    subsys = struct.unpack_from('<H', data, opt_off + (68 if is_pe32_plus else 72))[0]
    dllchars = struct.unpack_from('<H', data, opt_off + (70 if is_pe32_plus else 74))[0]
    ndirs_off = opt_off + (108 if is_pe32_plus else 92)
    ndirs = struct.unpack_from('<I', data, ndirs_off)[0]
    dd_off = ndirs_off + 4
    DIRNAMES = ['EXPORT','IMPORT','RESOURCE','EXCEPTION','SECURITY','BASERELOC','DEBUG','ARCHITECTURE','GLOBALPTR','TLS','LOAD_CONFIG','BOUND_IMPORT','IAT','DELAY_IMPORT','COM_DESCRIPTOR','RESERVED']
    SUBSYS = {1:'NATIVE',2:'WIN_GUI',3:'WIN_CUI',7:'POSIX_CUI',9:'WIN_CE',10:'EFI_APP',16:'WIN_BOOT_APP'}.get(subsys, f'0x{subsys:x}')
    DLLC = {0x40:'DYNAMIC_BASE',0x80:'FORCE_INTEGRITY',0x100:'NX_COMPAT',0x200:'NO_ISOLATION',0x400:'NO_SEH',0x800:'NO_BIND',0x2000:'APPCONTAINER',0x4000:'WDM_DRIVER',0x8000:'GUARD_CFW',0x10000:'TERMINAL_SERVER_AWARE'}
    dllf = [n for v,n in DLLC.items() if dllchars & v]
    out.write(f"  EntryPoint  : 0x{ep_rva:x}\n")
    out.write(f"  ImageBase   : 0x{img_base:x}\n")
    out.write(f"  SizeOfImage : 0x{sz_img:x}\n")
    out.write(f"  Subsystem   : {SUBSYS}\n")
    out.write(f"  DllChars    : 0x{dllchars:04x} -> {','.join(dllf) or '-'}\n")
    out.write(f"  #DataDirs   : {ndirs}\n  DataDirs:\n")
    for i in range(min(ndirs, 16)):
        rva, sz = struct.unpack_from('<II', data, dd_off + i*8)
        if rva or sz:
            out.write(f"    [{i:2}] {DIRNAMES[i]:15}  rva=0x{rva:08x}  size=0x{sz:x}\n")
    sec_off = pe_off + 24 + optsize
    sections = []
    out.write(f"\n  Sections:\n    {'Name':<10} {'VAddr':>10} {'VSize':>10} {'RawAddr':>10} {'RawSize':>10} {'Chars':>10} {'Entropy':>8}\n")
    for i in range(nsects):
        s = data[sec_off + i*40 : sec_off + (i+1)*40]
        name = s[:8].rstrip(b'\0').decode('latin1', 'replace')
        vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', s, 8)
        schars = struct.unpack_from('<I', s, 36)[0]
        ent = entropy(data[raddr:raddr+rsize]) if rsize > 0 and raddr + rsize <= len(data) else 0.0
        sections.append({'Name':name,'VA':vaddr,'VSize':vsize,'Raw':raddr,'RSize':rsize,'Chars':schars})
        flag = ('X' if schars & 0x20000000 else '-') + ('R' if schars & 0x40000000 else '-') + ('W' if schars & 0x80000000 else '-')
        out.write(f"    {name:<10} {vaddr:>10x} {vsize:>10x} {raddr:>10x} {rsize:>10x} {flag:>10} {ent:>8.4f}\n")
    out.write(f"\n  Global entropy: {entropy(data):.4f}\n")
    # Imports
    imp_rva, imp_sz = struct.unpack_from('<II', data, dd_off + 1*8)
    if imp_rva:
        out.write(f"\n  Imports ({imp_sz} bytes):\n")
        off = rva2off(imp_rva, sections)
        if off:
            seen = 0
            while seen < 30:
                ent = data[off:off+20]
                if ent == b'\0'*20: break
                ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from('<IIIII', ent)
                if name_rva == 0: break
                name_off = rva2off(name_rva, sections)
                if name_off is None: break
                end = data.find(b'\0', name_off)
                dll_name = data[name_off:end].decode('latin1', 'replace')
                if not dll_name.strip(): break
                out.write(f"    [{dll_name}]\n")
                ilt_off = rva2off(ilt_rva, sections) if ilt_rva else None
                fncount = 0
                if ilt_off:
                    j = 0
                    while j < 5000:
                        if is_pe32_plus:
                            val = struct.unpack_from('<Q', data, ilt_off + j*8)[0]
                            sz = 8
                        else:
                            val = struct.unpack_from('<I', data, ilt_off + j*4)[0]
                            sz = 4
                        if val == 0: break
                        if val & (0x8000000000000000 if is_pe32_plus else 0x80000000):
                            nrva = val & 0x7FFFFFFFFFFFFFFF if is_pe32_plus else (val & 0x7FFFFFFF)
                            noff = rva2off(nrva, sections)
                            if noff:
                                nb = data[noff+2:data.find(b'\0', noff+2)]
                                out.write(f"        ord? {nb.decode('latin1','replace')}\n")
                        else:
                            noff = rva2off(val, sections)
                            if noff:
                                nb = data[noff+2:data.find(b'\0', noff+2)]
                                out.write(f"        {nb.decode('latin1','replace')}\n")
                        j += 1
                        fncount += 1
                out.write(f"      ({fncount} functions)\n")
                off += 20; seen += 1
    # Exports
    exp_rva, exp_sz = struct.unpack_from('<II', data, dd_off + 0*8)
    if exp_rva:
        off = rva2off(exp_rva, sections)
        if off:
            _, _, _, _, _, nfuncs, nnames, na, nn = struct.unpack_from('<IIIIIIIII', data, off + 12)
            out.write(f"\n  Exports: {nfuncs} funcs, {nnames} named\n")
            n_off = rva2off(nn, sections)
            if n_off:
                for i in range(min(nnames, 80)):
                    nrva = struct.unpack_from('<I', data, n_off + i*4)[0]
                    noff = rva2off(nrva, sections)
                    if noff:
                        end = data.find(b'\0', noff)
                        out.write(f"    {data[noff:end].decode('latin1','replace')}\n")
                if nnames > 80: out.write(f"    ... +{nnames-80} more\n")
    return data, sections, is_pe32_plus

with open(OUT, 'w', encoding='utf-8') as out:
    parse_pe(DLL, out)
    parse_pe(EXE, out)
print(f"Report written: {OUT}")
