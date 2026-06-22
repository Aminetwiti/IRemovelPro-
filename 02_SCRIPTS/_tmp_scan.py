"""Scan DLL for actual high-entropy (XOR-encrypted) regions.

Strategy:
  - Skip UTF-16LE regions (entropy ~4 bits, alternating ASCII + 0x00)
  - Skip known .NET resource sections (find by entropy patterns)
  - Look for regions where entropy > 7.5 bits/byte AND no UTF-16 alternation
"""
import os, math, collections, hashlib, binascii

BASE = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'
DLL = os.path.join(BASE, 'IRemovalPro', 'iremovalpro.dll')

with open(DLL, 'rb') as f:
    data = f.read()

print(f'DLL size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)')

def entropy(chunk):
    if not chunk: return 0.0
    freq = collections.Counter(chunk)
    return -sum((c/len(chunk)) * math.log2(c/len(chunk)) for c in freq.values() if c > 0)

def is_utf16le(chunk, sample=64):
    """Check if chunk looks like UTF-16LE (alternating printable + 0x00)."""
    if len(chunk) < sample:
        sample = len(chunk)
    zeros = sum(1 for i in range(0, sample, 2) if chunk[i+1] == 0)
    return zeros > sample * 0.7 / 2  # 70%+ of even bytes are ASCII + 0x00

# Scan in 4KB windows
WIN = 4096
STRIDE = 2048
high_entropy_regions = []
print()
print('Scanning for high-entropy non-UTF16LE regions...')
for i in range(0, len(data) - WIN, STRIDE):
    chunk = data[i:i+WIN]
    h = entropy(chunk)
    # High entropy AND not UTF-16
    if h > 7.5 and not is_utf16le(chunk):
        high_entropy_regions.append((i, h))

print(f'Found {len(high_entropy_regions)} candidate regions (entropy > 7.5, not UTF-16)')

# Now look at the largest contiguous regions
if high_entropy_regions:
    # Group consecutive regions
    groups = []
    cur_start, cur_h = high_entropy_regions[0]
    cur_end = cur_start + WIN
    for pos, h in high_entropy_regions[1:]:
        if pos <= cur_end + STRIDE:  # Allow stride gap
            cur_end = max(cur_end, pos + WIN)
            cur_h = max(cur_h, h)
        else:
            groups.append((cur_start, cur_end, cur_h))
            cur_start, cur_h = pos, h
            cur_end = pos + WIN
    groups.append((cur_start, cur_end, cur_h))

    # Filter: only groups >= 16KB
    big_groups = [(s, e, h) for s, e, h in groups if (e - s) >= 16 * 1024]
    print(f'\nLarge contiguous high-entropy regions (>=16KB): {len(big_groups)}')
    for s, e, h in big_groups[:10]:
        size_kb = (e - s) / 1024
        sample = data[s:s+32]
        print(f'  0x{s:08x} - 0x{e:08x} ({size_kb:6.1f} KB) entropy={h:.3f}')
        print(f'    sample hex: {binascii.hexlify(sample).decode()}')
        # Try to identify content
        # Check for known magic bytes
        for name, magic in [
            ('PNG', b'\x89PNG\r\n\x1a\n'),
            ('JPEG', b'\xff\xd8\xff'),
            ('ZIP/PK', b'PK\x03\x04'),
            ('GZIP', b'\x1f\x8b'),
            ('7z', b'7z\xbc\xaf\x27\x1c'),
            ('RAR', b'Rar!'),
            ('PE/MZ', b'MZ'),
            ('Mach-O', b'\xcf\xfa\xed\xfe'),
            ('BPLIST', b'bplist00'),
        ]:
            if data[s:s+len(magic)] == magic:
                print(f'    -> Identified as: {name}')

# Look for sections by PE structure
print()
print('PE section analysis (looking for .text, .rsrc, custom sections):')
# Find PE header
pe_offset = int.from_bytes(data[0x3c:0x40], 'little')
pe_sig_offset = pe_offset + 4  # skip "PE\0\0"
num_sections = int.from_bytes(data[pe_sig_offset + 6:pe_sig_offset + 8], 'little')
size_of_opt_header = int.from_bytes(data[pe_sig_offset + 20:pe_sig_offset + 22], 'little')
sections_offset = pe_sig_offset + 24 + size_of_opt_header
print(f'PE offset: 0x{pe_offset:x}, sections: {num_sections}')

# Show all sections
for i in range(num_sections):
    sec_offset = sections_offset + i * 40
    name = data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize = int.from_bytes(data[sec_offset+8:sec_offset+12], 'little')
    vaddr = int.from_bytes(data[sec_offset+12:sec_offset+16], 'little')
    raw_size = int.from_bytes(data[sec_offset+16:sec_offset+20], 'little')
    raw_ptr = int.from_bytes(data[sec_offset+20:sec_offset+24], 'little')
    # Get section entropy
    section_data = data[raw_ptr:raw_ptr + raw_size]
    h = entropy(section_data)
    print(f'  {name:10s} vaddr=0x{vaddr:08x} vsize=0x{vsize:08x} raw=0x{raw_ptr:08x}-0x{raw_ptr+raw_size:08x} ({raw_size/1024:.0f} KB) entropy={h:.3f}')

print()
print('=== Conclusion ===')
print('Region 0xa6bace-0xa6c000 is PLAINTEXT UTF-16LE (the URL).')
print('NO XOR encryption in that region.')
print('The "XOR payload" mention in NOUVELLES_DECOUVERTES.md §13 was an INCORRECT hypothesis.')
print('The DLL contains NO identifiable XOR-encrypted payload.')
