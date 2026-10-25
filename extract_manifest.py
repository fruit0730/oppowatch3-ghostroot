#!/usr/bin/env python3
"""Extract XML manifests and build info from OFP."""
import os
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ofp_path = r'C:\Users\RLG\AppData\Local\Temp\360zip$Temp\360$1\OWW211_11_A.90_230105_d784fa8b_MCU_2301050147.ofp'
out_dir = r'C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\extracted'

f = open(ofp_path, 'rb')

def read_context(offset, before=64, after=512):
    f.seek(max(0, offset - before))
    data = f.read(before + after)
    return data

# 1. Read the XML at ~0x9a0a
print("=== XML at 0x9a0a ===")
data = read_context(0x9a0a, 64, 2048)
# Find the XML start
idx = data.find(b'<?xml')
if idx >= 0:
    end = data.find(b'</data>', idx)
    if end >= 0:
        xml = data[idx:end+7]
    else:
        xml = data[idx:idx+1024]
    print(xml.decode('ascii', errors='replace')[:1024])

# 2. Read the XML at ~0x4237676
print("\n=== XML at 0x4237676 ===")
data = read_context(0x4237676, 64, 2048)
idx = data.find(b'<?xml')
if idx >= 0:
    end_idx = data.find(b'>', idx + 500)
    if end_idx >= 0:
        xml = data[idx:end_idx+1]
    else:
        xml = data[idx:idx+1024]
    print(xml.decode('ascii', errors='replace')[:1024])

# 3. Read the s2b_config.xml at ~0x59f9c4c
print("\n=== s2b_config.xml at 0x59f9c4c ===")
data = read_context(0x59f9c4c, 32, 4096)
idx = data.find(b'<?xml')
if idx >= 0:
    # Find end of XML
    end = data.find(b'</IWLAN_S2B_CONFIG>', idx)
    if end >= 0:
        xml = data[idx:end + len(b'</IWLAN_S2B_CONFIG>')]
    else:
        xml = data[idx:idx+2048]
    print(xml.decode('ascii', errors='replace')[:2048])

# 4. Search for partition name table / rawprogram XML
print("\n=== Searching for rawprogram/flashing manifest ===")
f.seek(0)
block_size = 16 * 1024 * 1024
offset = 0
while offset < min(os.path.getsize(ofp_path), 200 * 1024 * 1024):
    f.seek(offset)
    data = f.read(block_size)
    for pat in [b'rawprogram', b'partition_name=', b'<program ', b'filename=',
                b'boot.img', b'recovery.img', b'system.img', b'vendor.img',
                b'gpt_both', b'partition.xml', b'flash_cert.cfg']:
        idx = data.find(pat)
        if idx != -1:
            abs_off = offset + idx
            context = data[max(0,idx-32):idx+200]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            print(f"  0x{abs_off:010x}: '{pat.decode()}' -> {printable[:200]}")
    offset += block_size

# 5. Read build path context
print("\n=== Build path context ===")
# We found "_workspace/SW5100_R/OWW211/release/source_code/amss/boot_images/Build/AthertonLA" at 0x3ec5dc0
data = read_context(0x3ec5dc0, 128, 512)
# Find all printable strings
text = data.decode('ascii', errors='replace')
# Show the relevant portion
idx = text.find('_workspace')
if idx >= 0:
    print(text[idx:idx+300])

# Also check 0x46b8677
data = read_context(0x46b8677, 128, 512)
text = data.decode('ascii', errors='replace')
idx = text.find('_workspace')
if idx >= 0:
    print(f"\n{text[idx:idx+300]}")

# 6. Look for any .mbn, .elf, .img file headers
print("\n=== Looking for MBN/ELF headers at partition boundaries ===")
# Check at common partition offsets (multiples of partition sizes)
for test_off in [0x100000, 0x200000, 0x400000, 0x800000, 0x1000000,
                 0x2000000, 0x4000000, 0x8000000, 0x10000000,
                 0x20000000, 0x40000000, 0x80000000]:
    if test_off >= os.path.getsize(ofp_path):
        break
    f.seek(test_off)
    hdr = f.read(32)
    magic = hdr[:4]
    if magic == b'\x7fELF':
        print(f"  0x{test_off:010x}: ELF header")
    elif magic == b'ANDROID!':
        print(f"  0x{test_off:010x}: Android boot image!")
    elif magic[:3] == b'\xd0\x0d\xfe':
        print(f"  0x{test_off:010x}: DTB")
    elif magic == b'AVB0':
        print(f"  0x{test_off:010x}: AVB header")
    elif magic[:2] == b'\x53\xef':
        print(f"  0x{test_off:010x}: ext superblock?")
    else:
        # Check if it's mostly zeros
        if hdr == b'\x00' * 32:
            pass  # Skip zero regions
        else:
            print(f"  0x{test_off:010x}: {hdr[:16].hex()}")

f.close()
print("\nDone.")
