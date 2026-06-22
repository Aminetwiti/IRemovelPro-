#!/usr/bin/env python3
"""
Find the XOR decryption function in the .text section of iremovalpro.dll.
The function references the URL table region and decodes encrypted strings.

Strategy:
1. Find the URL table offset 0xa6bace (iact8 URL location)
2. Search .text for any reference to this address
3. The decryption function will be near the reference
"""
import re
import struct
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

print(f"[*] {DLL.name}: {len(data):,} bytes")

# 1. Get PE section boundaries
import struct
pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
print(f"[*] PE header at 0x{pe_offset:x}")

# Parse PE header
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
image_base = struct.unpack_from('<I', data, pe_offset + 52)[0]
print(f"[*] Image base: 0x{image_base:x}, sections: {num_sections}")

section_table_offset = pe_offset + 24 + opt_header_size
sections = {}
for i in range(num_sections):
    off = section_table_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vsize = struct.unpack_from('<I', data, off + 8)[0]
    vaddr = struct.unpack_from('<I', data, off + 12)[0]
    rawsize = struct.unpack_from('<I', data, off + 16)[0]
    rawptr = struct.unpack_from('<I', data, off + 20)[0]
    sections[name] = {
        'vaddr': vaddr, 'vsize': vsize, 'rawsize': rawsize, 'rawptr': rawptr,
        'rva_end': vaddr + vsize, 'file_end': rawptr + rawsize
    }
    print(f"    [{name:10}] RVA=0x{vaddr:08x} VSIZE=0x{vsize:08x} RAW=0x{rawptr:08x}")

# RVA to file offset
def rva_to_file(rva):
    for s in sections.values():
        if s['vaddr'] <= rva < s['vaddr'] + s['rawsize']:
            return rva - s['vaddr'] + s['rawptr']
    return None

# 2. The URL table is at file offset 0xa6bace
# Find the RVA of this offset
url_file_off = 0xa6bace
for s in sections.values():
    if s['rawptr'] <= url_file_off < s['file_end']:
        url_rva = s['vaddr'] + (url_file_off - s['rawptr'])
        print(f"\n[*] URL table file 0x{url_file_off:x} -> RVA 0x{url_rva:x} (in section)")
        break

# 3. Find references to this RVA in .text section
print(f"\n[*] Scanning .text for references to URL table RVA...")
text = sections.get('.text')
if not text:
    # Try other names
    for n in sections.keys():
        if 'text' in n.lower() or 'code' in n.lower():
            text = sections[n]
            text_name = n
            break

# Try all 4-byte aligned references
text_data = data[text['rawptr']:text['rawptr']+text['rawsize']]
print(f"    .text size: {len(text_data):,} bytes")

# Search for direct references to the URL table RVA
# Could be: direct call (E8), direct mov (absolute, RIP-relative, etc.)
# Search for the raw bytes of the RVA
url_rva_bytes = struct.pack('<I', url_rva)
url_rva_be = struct.pack('>I', url_rva)

hits = []
for i in range(0, len(text_data) - 4, 1):
    if text_data[i:i+4] == url_rva_bytes:
        hits.append((text['vaddr'] + i, 'little-endian'))
    if text_data[i:i+4] == url_rva_be:
        hits.append((text['vaddr'] + i, 'big-endian'))

print(f"    Found {len(hits)} direct references")
for rva, endian in hits[:10]:
    file_off = rva_to_file(rva)
    print(f"    RVA 0x{rva:x} (file 0x{file_off:x}, {endian})")
    if file_off:
        # Show context
        ctx = data[max(0,file_off-20):file_off+50]
        ctx_hex = ' '.join(f'{b:02x}' for b in ctx)
        print(f"        Context: {ctx_hex[:120]}")

# 4. Look for the small XOR key 0x5F as immediate value in .text
print(f"\n[*] Scanning .text for 0x5F immediates (EOR w/underscore)...")
xor_hits = []
# 0x5F as immediate in MOV/AND/EOR instructions on x64
# EOR x9, x9, #0x5F: 0xD2801329 (no, that's MOV)
# Easier: search for the byte 0x5F preceded by XOR instruction
# x64 EOR: opcode 0x31 (reg, reg) or 0x35 (eax, imm32) or 0x81 /6 (r/m, imm32)

# Search for any instruction that XORs with 0x5F as 32-bit immediate
# Pattern: 0x35 5F 00 00 00 (XOR EAX, 0x5F) or 0x81 0xF? 0x5F 00 00 00
# Or as 8-bit immediate: 0x80 0xF? 0x5F (XOR r/m8, 0x5F)
patterns = [
    (b'\x35\x5f\x00\x00\x00', 'XOR EAX, 0x5F'),
    (b'\x80\xf0\x5f', 'XOR AL, 0x5F'),
    (b'\x80\xf1\x5f', 'XOR CL, 0x5F'),
    (b'\x80\xf2\x5f', 'XOR DL, 0x5F'),
    (b'\x80\xf3\x5f', 'XOR BL, 0x5F'),
    (b'\x80\xf6\x5f', 'XOR DH, 0x5F'),
    (b'\x80\xf7\x5f', 'XOR BH, 0x5F'),
]

# Also search for the 2-byte pattern "5F" (POP RDI) followed by XOR instructions
# x64 XOR: 0x31 /r (reg, reg), 0x33 /r (reg, reg), 0x35 ib (EAX, imm8), 0x81 /6 id (r/m, imm32)

# Look for the literal byte 0x5F in the instruction stream and check context
count_5f = 0
for i in range(len(text_data)):
    if text_data[i] == 0x5F:
        count_5f += 1

print(f"    0x5F bytes in .text: {count_5f:,}")

# 5. Try decoding the URL table region with key 0x5F and see if URLs become visible
# After XOR, look for new strings
print(f"\n[*] XOR-decoding region with key 0x5F (URL table area)...")
region = data[0xa69000:0xa70000]
decoded = bytes(b ^ 0x5f for b in region)
# Find UTF-16LE strings in decoded region
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){6,}', decoded):
    s = m.group().decode('utf-16-le', errors='ignore')
    if 6 < len(s) < 200:
        offset = m.start() + 0xa69000
        # Skip if same as original (means byte was 0x00)
        original = region[m.start():m.start()+len(s)*2]
        if original != b'\x00' * len(s)*2:
            print(f"  0x{offset:x} [new]: {s[:100]}")

# 6. Now try a different approach: maybe the encryption is a per-byte XOR with position-dependent key
# Common pattern: XOR with 0x5F for index, 0x33 for index, etc.
print(f"\n[*] Trying position-dependent XOR keys (XOR[i] = key[i % len(key)])...")
for k1, k2 in [(0x5f, 0x5f), (0x47, 0x4f), (0x12, 0x34), (0x77, 0x5f), (0x5f, 0x77)]:
    decoded2 = bytearray(len(region))
    for i in range(len(region)):
        if i % 2 == 0:
            decoded2[i] = region[i] ^ k1
        else:
            decoded2[i] = region[i] ^ k2
    decoded2 = bytes(decoded2)
    matches = list(re.finditer(rb'(?:[\x20-\x7e]\x00){8,}', decoded2))
    if len(matches) > 5:
        print(f"  Key (0x{k1:02x},0x{k2:02x}): {len(matches)} new UTF-16 strings")
        for m in matches[:3]:
            s = m.group().decode('utf-16-le', errors='ignore')
            print(f"    {s[:80]}")