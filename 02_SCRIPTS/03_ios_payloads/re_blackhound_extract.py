#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Search for blackhound.dylib payload in the DLL.
Could be:
- base64-encoded in a .NET resource
- compressed (gzip, zlib)
- raw binary in .data / .rsrc sections
- referenced as a remote URL to download
"""
import sys, struct, re, io, zlib, base64
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
OUT_DIR = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis'

with open(DLL, 'rb') as f:
    data = f.read()

print("="*80)
print("[1] MH_MAGIC / FAT_MAGIC scan (Mach-O)")
print("="*80)
# Mach-O magic numbers
MH_MAGIC = b'\xcf\xfa\xed\xfe'      # MH_MAGIC (32-bit LE)
MH_MAGIC_64 = b'\xcf\xfa\xed\xff'   # MH_MAGIC_64 (64-bit LE)
MH_CIGAM = b'\xfe\xed\xfa\xce'      # 32-bit BE
MH_CIGAM_64 = b'\xfe\xed\xfa\xcf'   # 64-bit BE
FAT_MAGIC = b'\xca\xfe\xba\xbe'     # FAT_MAGIC (universal binary)
FAT_CIGAM = b'\xbe\xba\xfe\xca'     # FAT_CIGAM (universal BE)

# ELF magic (just to be complete)
ELF_MAGIC = b'\x7fELF'

# DEB magic
DEB_MAGIC = b'!<arch>\n'  # ar archive (Debian package)

# ZIP magic (IPA, deb)
ZIP_MAGIC = b'PK\x03\x04'

patterns = {
    'MH_MAGIC_64': MH_MAGIC_64,
    'MH_MAGIC': MH_MAGIC,
    'MH_CIGAM_64': MH_CIGAM_64,
    'MH_CIGAM': MH_CIGAM,
    'FAT_MAGIC': FAT_MAGIC,
    'FAT_CIGAM': FAT_CIGAM,
    'ELF_MAGIC': ELF_MAGIC,
    'DEB_MAGIC': DEB_MAGIC,
    'ZIP_MAGIC': ZIP_MAGIC,
}

PE_SECTIONS = {
    '.text': (0x400, 0xc8c00),
    '.managed': (0xc9000, 0x676000),
    '.rdata': (0x73f000, 0x5e5e00),
    '.data': (0xd24e00, 0xb200),
    '.pdata': (0xd30000, 0x83200),
    '.k^q': (0xdb3200, 0x7fb400),
    '.IE_': (0x15ae600, 0x200),
    '.^%L': (0x15ae800, 0x820400),
    '.rsrc': (0x1dcec00, 0x400),
    '.reloc': (0x1dcf000, 0x2000),
}
def section_at(pos):
    for s, (raw, size) in PE_SECTIONS.items():
        if raw <= pos < raw + size:
            return s
    return '?'

for name, magic in patterns.items():
    positions = []
    pos = 0
    while True:
        p = data.find(magic, pos)
        if p < 0: break
        positions.append(p)
        pos = p + 1
    if positions:
        print(f"  {name}: {len(positions)} hits")
        for p in positions[:5]:
            sec = section_at(p)
            print(f"      @ 0x{p:x}  in {sec}")

# ==== Look for base64-encoded Mach-O in resources ====
print("\n" + "="*80)
print("[2] BASE64-ENCODED BLOB SCAN (likely Mach-O payload)")
print("="*80)
# Find large base64 chunks (typical of resource files)
# Base64 patterns: lots of [A-Za-z0-9+/] followed by null byte or boundary
# Look for very long base64 sequences
print("  Looking for long printable ASCII sequences...")
# Use a heuristic: find ASCII strings >= 100 chars that look like base64
b64_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
long_strings = []
i = 0
while i < len(data) - 100:
    if data[i] in b64_chars:
        j = i
        while j < len(data) and data[j] in b64_chars and j - i < 100000:
            j += 1
        if j - i >= 200:  # Min 200 chars
            long_strings.append((i, j, j - i))
        i = j
    else:
        i += 1

print(f"  Found {len(long_strings)} long printable sequences (>= 200 chars)")
# Show top 20
for start, end, length in sorted(long_strings, key=lambda x: -x[2])[:20]:
    sec = section_at(start)
    # Sample
    sample = data[start:start+80].decode('latin1', 'replace')
    print(f"      @ 0x{start:x} len={length}  in {sec}  starts: {sample!r}")

# ==== Look for gzip/zlib signatures ====
print("\n" + "="*80)
print("[3] COMPRESSED BLOB SCAN (gzip/zlib/deflate)")
print("="*80)
# gzip magic: 1f 8b
# zlib magic: 78 01 / 78 9c / 78 da
gzip_magic = b'\x1f\x8b'
zlib_magics = [b'\x78\x01', b'\x78\x9c', b'\x78\xda']
for name, magic in [('GZIP', gzip_magic)] + [(f'ZLIB_{m.hex()}', m) for m in zlib_magics]:
    positions = []
    pos = 0
    while True:
        p = data.find(magic, pos)
        if p < 0: break
        positions.append(p)
        pos = p + 1
    if positions:
        print(f"  {name}: {len(positions)} hits")
        for p in positions[:5]:
            sec = section_at(p)
            print(f"      @ 0x{p:x}  in {sec}")

# ==== Look for "blackhound" references ====
print("\n" + "="*80)
print("[4] ALL blackhound REFERENCES")
print("="*80)
for kw in [b'blackhound', b'panyolsoft', b'minaeraser', b'minaeraser12']:
    pos = 0
    cnt = 0
    while True:
        p = data.find(kw, pos)
        if p < 0: break
        cnt += 1
        if cnt <= 5:
            sec = section_at(p)
            ctx = data[max(0,p-30):p+50]
            ascii_ctx = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
            print(f"  '{kw.decode()}' @ 0x{p:x}  in {sec}: ...{ascii_ctx}...")
        pos = p + 1
    print(f"  total '{kw.decode()}': {cnt}")

# ==== Look at .data section for binary blobs ====
print("\n" + "="*80)
print("[5] .data SECTION SCAN (small but may contain binary)")
print("="*80)
data_sec = data[0xd24e00:0xd24e00+0xb200]
# Look at the entire .data section
import collections
# Hex dump first 1024 bytes
print("  First 512 bytes of .data section (hex dump):")
for i in range(0, 512, 32):
    chunk = data_sec[i:i+32]
    hexpart = ' '.join(f'{b:02x}' for b in chunk[:16])
    ascpart = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
    print(f"      {i:04x}  {hexpart}  |{ascpart}|")

# ==== Look for HTTPS connection that downloads blackhound ====
print("\n" + "="*80)
print("[6] DOWNLOAD URL SEARCH (blackhound.dylib download)")
print("="*80)
# Search for any URL ending in .dylib or containing blackhound
for kw in [b'.dylib', b'.deb', b'.tar', b'.tgz', b'.zip', b'.ipa',
            b'blackhound.dylib', b'panyolsoft']:
    # UTF-16LE version
    kw_wide = kw.decode().encode('utf-16-le') if isinstance(kw, bytes) else kw
    pos = data.find(kw_wide)
    if pos >= 0:
        sec = section_at(pos)
        ctx = data[max(0,pos-100):pos+200]
        # Try decode as wide
        try:
            ascii_ctx = ctx.decode('utf-16-le', errors='replace')
        except:
            ascii_ctx = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
        print(f"  '{kw.decode()}' (UTF-16LE) @ 0x{pos:x}  in {sec}")
        print(f"      ...{ascii_ctx[:200]}...")

# Check rsrc section for embedded payloads
print("\n" + "="*80)
print("[7] .rsrc SECTION (1 KB)")
print("="*80)
rsrc = data[0x1dcec00:0x1dcec00+0x400]
print("  Hex dump:")
for i in range(0, 0x400, 32):
    chunk = rsrc[i:i+32]
    hexpart = ' '.join(f'{b:02x}' for b in chunk)
    print(f"      {i:04x}  {hexpart[:48]}  {hexpart[48:]}")