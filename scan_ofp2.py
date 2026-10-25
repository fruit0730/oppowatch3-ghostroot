#!/usr/bin/env python3
"""Deep scan OFP for GPT, Qualcomm, and OPPO partition structures."""
import struct
import os

ofp_path = r'C:\Users\RLG\AppData\Local\Temp\360zip$Temp\360$1\OWW211_11_A.90_230105_d784fa8b_MCU_2301050147.ofp'
file_size = os.path.getsize(ofp_path)
f = open(ofp_path, 'rb')

def read_at(offset, size):
    f.seek(offset)
    return f.read(size)

def hexdump(data, offset=0, length=128):
    lines = []
    for i in range(0, min(len(data), length), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        lines.append(f'  {offset+i:08x}: {hex_part:<48s} {ascii_part}')
    return '\n'.join(lines)

# 1. Search for GPT header (signature "EFI PART" at sector boundaries)
print("=== Searching for GPT partition tables ===")
gpt_found = []
for offset in range(0, min(file_size, 500 * 1024 * 1024), 512):
    data = read_at(offset, 8)
    if data == b'EFI PART':
        gpt_found.append(offset)
        # Read full GPT header (92 bytes)
        gpt = read_at(offset, 92)
        sig = gpt[0:8]
        revision = struct.unpack_from('<I', gpt, 8)[0]
        header_size = struct.unpack_from('<I', gpt, 12)[0]
        my_lba = struct.unpack_from('<Q', gpt, 24)[0]
        first_usable = struct.unpack_from('<Q', gpt, 40)[0]
        last_usable = struct.unpack_from('<Q', gpt, 48)[0]
        print(f"  GPT at 0x{offset:x}: revision={revision} header_size={header_size} "
              f"my_lba={my_lba} first_usable={first_usable} last_usable={last_usable}")
        if len(gpt_found) >= 5:
            break

# 2. Look for OPPO-specific headers
print("\n=== Searching for OPPO headers ===")
for sig, name in [(b'OPPO', 'OPPO'), (b'oppo', 'oppo'), (b'OFP_', 'OFP_'),
                   (b'\x4f\x46\x50', 'OFP'), (b'OFPS', 'OFPS'),
                   (b'OPPO_RES', 'OPPO_RES'), (b'oneplus', 'oneplus')]:
    f.seek(0)
    block = f.read(10 * 1024 * 1024)  # First 10MB
    pos = 0
    while True:
        idx = block.find(sig, pos)
        if idx == -1:
            break
        context = block[idx:idx+64]
        print(f"  0x{idx:08x}: {name} -> {context[:32].hex()}")
        pos = idx + 1
        if pos - idx > 5:
            break

# 3. Look for Qualcomm Sahara/Firehose headers
print("\n=== Searching for Qualcomm structures ===")
for sig, name in [(b'qboot', 'qboot'), (b'MBN', 'MBN'), (b'QCOM', 'QCOM'),
                   (b'\x7fELF', 'ELF'), (b'\xd1\xdc\x49\x36', 'MBN_MAGIC')]:
    f.seek(0)
    block = f.read(10 * 1024 * 1024)
    pos = 0
    count = 0
    while count < 10:
        idx = block.find(sig, pos)
        if idx == -1:
            break
        print(f"  0x{idx:08x}: {name}")
        pos = idx + 1
        count += 1

# 4. Scan for large zero-padded regions (partition boundaries)
print("\n=== Looking for partition image boundaries (first 100MB) ===")
prev_nonzero = 0
scan_size = 100 * 1024 * 1024
block_sz = 4096
f.seek(0)
zero_regions = []
offset = 0
while offset < scan_size:
    data = f.read(block_sz)
    if not data:
        break
    if data == b'\x00' * block_sz:
        if prev_nonzero and (offset - prev_nonzero) > 0:
            pass
        zero_regions.append(offset)
    else:
        if len(zero_regions) > 0 and zero_regions[-1] != 'end':
            zero_regions[-1] = (zero_regions[-1], offset - 1)
        prev_nonzero = offset
    offset += block_sz

# 5. Dump the area around 0x67000 where we found an ELF
print("\n=== ELF at 0x67000 ===")
data = read_at(0x67000, 256)
print(hexdump(data, 0x67000, 128))

# Check if this is a Sahara programmer
print("\n=== First 256 bytes of file ===")
data = read_at(0, 256)
print(hexdump(data, 0, 256))

# 6. Check for raw kernel image (look for ARM branch instructions near expected locations)
# The kernel text starts with an ARM branch instruction at 0xC0008000 virtual
# In the boot image, the kernel is typically at offset page_size (4096) after the header
print("\n=== Looking for Linux kernel signatures ===")
# Search for "Linux version" string which is always in the kernel
f.seek(0)
block_size = 16 * 1024 * 1024
offset = 0
while offset < file_size:
    f.seek(offset)
    data = f.read(block_size + 64)
    idx = data.find(b'Linux version')
    if idx != -1:
        abs_off = offset + idx
        context = data[idx:idx+200]
        print(f"  0x{abs_off:010x}: {context[:120]}")
        # This is likely the kernel! Check what's before it
        if idx >= 4096:
            pre = data[idx-4096:idx]
            if pre[:8] == b'ANDROID!':
                print(f"    -> Android boot image at 0x{abs_off - 4096:010x}")
    offset += block_size

# 7. Search for "OWW211" or "OWW212" strings
print("\n=== Searching for device model strings ===")
f.seek(0)
offset = 0
while offset < min(file_size, 200 * 1024 * 1024):
    f.seek(offset)
    data = f.read(block_size + 32)
    for pat in [b'OWW211', b'OWW212', b'monaco', b'OWW2']:
        idx = data.find(pat)
        if idx != -1:
            abs_off = offset + idx
            context = data[max(0,idx-20):idx+60]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            print(f"  0x{abs_off:010x}: {printable}")
    offset += block_size

f.close()
print("\nDone.")
