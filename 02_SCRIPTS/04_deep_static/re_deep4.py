#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep RE pass 4: Entry point, function table, runtime flow, AES key search."""
import sys, struct, re, io, math
from collections import Counter, defaultdict
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
with open(DLL, 'rb') as f:
    data = f.read()

# ==== A) Entry point analysis ====
print("="*80)
print("[1] ENTRY POINT")
print("="*80)
PE_SECTIONS = {
    '.text': (0x400, 0xc8c00, 0x1000),
    '.managed': (0xc9000, 0x676000, 0xca000),
    'hydrated': (None, None, 0x740000),
    '.rdata': (0x73f000, 0x5e5e00, 0x9f3000),
    '.data': (0xd24e00, 0xb200, 0xfd9000),
    '.pdata': (0xd30000, 0x83200, 0x100f000),
    '.k^q': (0xdb3200, 0x7fb400, 0x1093000),
    '.IE_': (0x15ae600, 0x200, 0x188f000),
    '.^%L': (0x15ae800, 0x820400, 0x1890000),
    '.rsrc': (0x1dcec00, 0x400, 0x20b1000),
    '.reloc': (0x1dcf000, 0x2000, 0x20b2000),
}
EP_RVA = 0x1ab4fc4
EP_VA = 0x180000000 + EP_RVA
print(f"    EP RVA: 0x{EP_RVA:x}, EP VA: 0x{EP_VA:x}")
# Find which section
for s, (raw, size, va) in PE_SECTIONS.items():
    if raw is None: continue
    if va <= EP_RVA < va+size:
        ep_off = raw + (EP_RVA - va)
        print(f"    EP in section: {s}  file_offset: 0x{ep_off:x}")
        # Read 64 bytes
        ep_data = data[ep_off:ep_off+256]
        print(f"    EP bytes (hex):")
        for i in range(0, min(64, len(ep_data)), 16):
            hexpart = ' '.join(f'{b:02x}' for b in ep_data[i:i+16])
            ascpart = ''.join(chr(b) if 32<=b<127 else '.' for b in ep_data[i:i+16])
            print(f"      {ep_off+i:08x}  {hexpart}  |{ascpart}|")
        break

# ==== B) NativeAOT method table / GC info ====
# In NativeAOT, the section .rdata contains:
# - MethodMap entries
# - Frozen object heap
# - TypeInfo
# - GC static data
# - Indirection cells
# Look for repeated patterns that could be method map
print("\n" + "="*80)
print("[2] NATIVEAOT METHOD TABLE PATTERNS")
print("="*80)
# Frozen object heap header pattern: typically "READY" or version
for marker in [b'\xFE\xED\xFA\xCE', b'\xCE\xFA\xED\xFE', b'READY', b'COR\0', b'CORE',
               b'NativeAOT', b'MethodMap', b'MethodTable']:
    pos = data.find(marker)
    if pos >= 0:
        sec = next((s for s, (raw, sz, _) in PE_SECTIONS.items() if raw and raw <= pos < raw+sz), '?')
        print(f"    {marker!r:30}  @ 0x{pos:08x}  in {sec}")

# ==== C) Find function prologues (.text) ====
# x64 function prologue: usually 40 53 48 83 EC 20 (push rbx, sub rsp, 0x20) or 48 89 5C 24 ...
# Look for common patterns
print("\n" + "="*80)
print("[3] FUNCTION PROLOGUE COUNT")
print("="*80)
text_raw, text_size, _ = PE_SECTIONS['.text']
text = data[text_raw:text_raw+text_size]
# Count common prologues
prologues = {
    b'\x40\x53': 'push rbx',
    b'\x40\x55': 'push rbp',
    b'\x40\x56': 'push rsi',
    b'\x40\x57': 'push rdi',
    b'\x48\x83\xEC': 'sub rsp, X',
    b'\x48\x89\x5C\x24': 'mov [rsp+X], rbx',
    b'\x48\x89\x6C\x24': 'mov [rsp+X], rbp',
    b'\x4C\x89\x44\x24': 'mov [rsp+X], r8',
    b'\x4C\x89\x4C\x24': 'mov [rsp+X], r9',
    b'\x48\x8B\xC4': 'mov rax, rsp (no frame)',
    b'\x48\x81\xEC': 'sub rsp, X (large)',
    b'\x55\x48\x8B\xEC': 'push rbp; mov rbp, rsp (legacy)',
    b'\x40\x55\x48\x83\xEC': 'push rbp; sub rsp, X',
}
for op, name in prologues.items():
    cnt = text.count(op)
    print(f"    {op.hex():25} {name:30}  count={cnt:6}")

# ==== D) Anti-debug deeper scan ====
print("\n" + "="*80)
print("[4] ANTI-DEBUG DEEPER ANALYSIS")
print("="*80)
# Look for specific opcode patterns in .text

# Pattern 1: NtQueryInformationProcess call sequence
# Usually: lea r10, [rip+...] ; mov eax, <index> ; syscall (for syscall) or call [rip+...] (for ntdll)
# Look for "ProcessDebugPort" check
for kw in [b'ProcessDebugPort', b'ProcessDebugObjectHandle', b'ProcessDebugFlags',
            b'DebugPort', b'DebugObject', b'DebugFlags',
            b'ProcessHandleTracing', b'SystemKernelDebuggerInformation',
            b'ProcessInstrumentationCallback', b'HeapFlags',
            b'NtGlobalFlag', b'NTDLL', b'ntdll.dll',
            b'VMware', b'VirtualBox', b'VBOX', b'QEMU', b'qemu',
            b'Hyper-V', b'HyperV', b'microsoft hv', b'MicrosoftHv',
            b'Xen', b'XenVMM', b'KVM', b'prl hyper', b'Parallels',
            b'SbieDll', b'Sandboxie', b'WINE', b'wine_get_unix_file_name',
            b'Sbie', b'Sandbox', b'Cuckoo', b'cuckoomon',
            b'TracerPid', b'BeingDebugged', b'NtQuery']:
    pos = data.find(kw)
    if pos >= 0:
        sec = next((s for s, (raw, sz, _) in PE_SECTIONS.items() if raw and raw <= pos < raw+sz), '?')
        print(f"    {kw.decode('latin1','replace'):40}  @ 0x{pos:08x}  in {sec}")

# ==== E) Find CPUID/HV detection signature ====
print("\n" + "="*80)
print("[5] CPUID-BASED VM/HV DETECTION")
print("="*80)
# Sequence: mov eax, 1 / cpuid / test ecx, 0x80000000 (hypervisor bit) / jnz
# Look for: b8 01 00 00 00 0f a2 (mov eax, 1; cpuid) followed by f7 c1 (test ecx, X)
mov_eax_1_cpuid = b'\xb8\x01\x00\x00\x00\x0f\xa2'
positions = []
i = 0
while i < text_size - 16:
    p = text.find(mov_eax_1_cpuid, i)
    if p < 0: break
    # Check the next instructions
    following = text[p+7:p+30]
    has_test_ecx = b'\xf7\xc1' in following
    has_test_ecx_high = b'\xf7\xc1' in following[:10]
    if has_test_ecx:
        positions.append((p, following[:20].hex()))
    i = p + 1
print(f"    mov eax, 1 + cpuid + test ecx: {len(positions)} matches")
for p, hexf in positions[:10]:
    print(f"        .text+0x{p:x}: follow={hexf}")

# mov eax, 0x40000000 (hypervisor vendor)
mov_eax_hv = b'\xb8\x00\x00\x00\x04\x0f\xa2'
positions = []
i = 0
while i < text_size - 16:
    p = text.find(mov_eax_hv, i)
    if p < 0: break
    following = text[p+6:p+20]
    positions.append((p, following[:14].hex()))
    i = p + 1
print(f"    mov eax, 0x40000000 (HV vendor) + cpuid: {len(positions)} matches")
for p, hexf in positions[:5]:
    print(f"        .text+0x{p:x}: follow={hexf}")

# ==== F) Find first call/call site patterns ====
# Look for common x64 indirect call pattern: 48 8b ?? ?? ?? ?? ?? ff d? or call [rip+X]
# At entry, NativeAOT often has: call [rip + N] or call rax
# Read first 200 bytes at EP
print("\n" + "="*80)
print("[6] ENTRY POINT DISASSEMBLY (raw bytes analysis)")
print("="*80)
ep_off = None
for s, (raw, size, va) in PE_SECTIONS.items():
    if raw is None: continue
    if va <= EP_RVA < va+size:
        ep_off = raw + (EP_RVA - va)
        break
if ep_off is not None:
    ep_code = data[ep_off:ep_off+512]
    # Try to find first call/jmp instruction
    # Common x64 call: E8 (rel32) or FF 15 (call [rip+disp32])
    print(f"    EP @ file 0x{ep_off:x}")
    # Find the first E8 or FF 15 after a function prologue
    for off in range(0, 256):
        if ep_code[off] == 0xE8:
            disp = struct.unpack_from('<i', ep_code, off+1)[0]
            target = ep_off + off + 5 + disp
            sec = next((s for s, (raw, sz, _) in PE_SECTIONS.items() if raw and raw <= target < raw+sz), '?')
            va_target = 0x180000000 + EP_RVA + off + 5 + disp
            print(f"        CALL rel32 at +0x{off:x} -> VA 0x{va_target:x} (file 0x{target:x}, in {sec})")
            if off > 0x40: break
        elif ep_code[off] == 0xFF and ep_code[off+1] in (0x15, 0x25, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
            print(f"        indirect call at +0x{off:x}: FF {ep_code[off+1]:02X}")
            if off > 0x40: break

# ==== G) Frozen Object Heap ====
# Look for type names in .rdata that suggest an object table
print("\n" + "="*80)
print("[7] FROZEN OBJECT HEAP / NATIVEAOT TYPE TABLE")
print("="*80)
# NativeAOT type system: MethodTable struct
# Look for known class names in .rdata that suggest the type table
# These are the class names
rdata_off, rdata_size, _ = PE_SECTIONS['.rdata']
rdata = data[rdata_off:rdata_off+rdata_size]
# Look for class names like "<>c", "<>c__DisplayClass", "<Module>", "Program", "Driver", etc.
for cls in [b'<Module>', b'Program', b'Driver', b'iDevice',
            b'<MainEntryPoint>', b'<StartupCode$', b'<NonVirtualCallStub>',
            b'<PInvoke>', b'<NativeAOT>']:
    pos = rdata.find(cls)
    if pos >= 0:
        print(f"    {cls.decode('latin1','replace'):30}  @ rdata+0x{pos:x}")

# ==== H) Look for AES key patterns ====
print("\n" + "="*80)
print("[8] AES / DES / 3DES CONSTANTS (FOR ENTROPY/WHITENING DETECTION)")
print("="*80)
# AES S-box signature
for marker in [
    (b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76', 'AES S-box start'),
    (b'\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb', 'AES S-box row 0'),
    (b'\x7c\xe3\x39\x82\x9b\x2f\xff\x87\x34\x8e\x43\x44\xc4\xde\xe9\xcb', 'AES S-box row 4'),
    (b'\x63\x7b\xca\xaf\x8b\x80\x04\xf1\xce\x4f\x52\x9c\x2a\x8d\x6f\x6d', 'AES S-box another pattern'),
    (b'\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb\x7c\xe3\x39\x82\x9b\x2f\xff\x87\x34\x8e\x43\x44', 'AES S-box first 30 bytes'),
]:
    pat, label = marker
    pos = data.find(pat)
    if pos >= 0:
        sec = next((s for s, (raw, sz, _) in PE_SECTIONS.items() if raw and raw <= pos < raw+sz), '?')
        print(f"    {label:30}  @ 0x{pos:08x}  in {sec}")

# DES S-box
DES_SBOX = b'\xe0\xe1\xe4\xe5\xe2\xe3\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef'
pos = data.find(DES_SBOX)
print(f"    DES initial perm: {'FOUND' if pos>=0 else 'NOT FOUND'}", f"@ 0x{pos:x}" if pos>=0 else '')

# SHA constants
for marker, label in [
    (b'\x67\x45\x23\x01', 'MD5 / SHA-1 init'),
    (b'\x01\x23\x45\x67\x89\xab\xcd\xef', 'MD5 init'),
    (b'\x6a\x09\xe6\x67', 'SHA-256 K[0]'),
    (b'\x42\x8a\x2f\x98', 'SHA-256 K[0] (LE)'),
    (b'\x10\x32\x54\x76\x98\xba\xdc\xfe', 'SHA-1 H init'),
]:
    pos = data.find(marker)
    if pos >= 0:
        print(f"    {label:30}  @ 0x{pos:08x}")

# RC4
RC4_init = bytes([i for i in range(256)])
pos = data.find(RC4_init)
print(f"    RC4 init (0..255): {'FOUND' if pos>=0 else 'NOT FOUND'}", f"@ 0x{pos:x}" if pos>=0 else '')

# ==== I) Look for AES Rcon ====
AES_Rcon = b'\x01\x02\x04\x08\x10\x20\x40\x80\x1b\x36'
pos = data.find(AES_Rcon)
print(f"    AES Rcon: {'FOUND' if pos>=0 else 'NOT FOUND'}", f"@ 0x{pos:x}" if pos>=0 else '')

# ==== J) Find .NET R2R / NativeAOT specific patterns ====
print("\n" + "="*80)
print("[9] NATIVEAOT R2R HEADER & METHOD MAP")
print("="*80)
# NativeAOT header is right at the start of .text
# It contains: signature, version, flags, numSections, sections array
text_start = data[PE_SECTIONS['.text'][0]:PE_SECTIONS['.text'][0]+64]
# Print first 64 bytes of .text in detail
print(f"    First 64 bytes of .text:")
for i in range(0, 64, 16):
    hexpart = ' '.join(f'{b:02x}' for b in text_start[i:i+16])
    print(f"        {i:04x}: {hexpart}")
# Try interpreting first 16 bytes as header
# NativeAOT typically has a "MSCORWKS" or similar header
for off in range(0, 64, 4):
    val = struct.unpack_from('<I', text_start, off)[0]
    if val == 0x4D534352 or val == 0x5753524D:  # MSCR / MRSW
        print(f"    Possible R2R header at .text+0x{off:x}: 0x{val:08x}")
