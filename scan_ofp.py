#!/usr/bin/env python3
"""Scan OFP file for known partition image signatures."""
import struct
import os
import sys

ofp_path = r'C:\Users\RLG\AppData\Local\Temp\360zip$Temp\360$1\OWW211_11_A.90_230105_d784fa8b_MCU_2301050147.ofp'
file_size = os.path.getsize(ofp_path)
print(f"File size: {file_size} ({file_size/(1024*1024*1024):.2f} GB)")

# Signatures to search for
signatures = {
    b'ANDROID!': 'Android boot image',
    b'\xd0\x0d\xfe\xed': 'DTB (Flattened Device Tree)',
    b'\x1f\x8b\x08': 'gzip compressed',
    b'\xfd\x37\x7a\x58\x5a\x00': 'XZ compressed',
    b'PK\x03\x04': 'ZIP archive',
    b'\x53\xef': 'ext2/3/4 superblock (at offset+0x438)',
    b'AVB0': 'Android Verified Boot header',
    b'\xd1\xdc\x49\x36': 'Qualcomm MBN header',
    b'\x7fELF': 'ELF binary',
    b'VNDRBOOT': 'Vendor boot image',
    b'BOOT!': 'Boot image v1+',
}

# Also search for partition name table / XML manifest
text_patterns = [
    b'boot.img',
    b'boot_emmc',
    b'partition',
    b'ofp_manifest',
    b'cfg.prj',
    b'metadata',
    b'<image',
    b'ANDROID',
]

f = open(ofp_path, 'rb')

# Scan first 1MB in detail
print("\n=== Scanning first 1MB for signatures ===")
chunk_size = 1024 * 1024
data = f.read(chunk_size)
for sig, name in signatures.items():
    pos = 0
    while True:
        idx = data.find(sig, pos)
        if idx == -1:
            break
        print(f"  0x{idx:08x}: {name} (magic: {sig[:8].hex()})")
        pos = idx + 1

# Scan for text patterns
for pat in text_patterns:
    pos = 0
    while True:
        idx = data.find(pat, pos)
        if idx == -1:
            break
        # Show context
        start = max(0, idx - 16)
        end = min(len(data), idx + len(pat) + 32)
        context = data[start:end]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        print(f"  0x{idx:08x}: '{pat.decode('ascii', errors='replace')}' -> ...{printable}...")
        pos = idx + 1
        if pos - idx > 3:  # limit to 3 occurrences per pattern in first MB
            break

# Now scan the full file for ANDROID! magic (boot image signature)
print("\n=== Full scan for Android boot image magic 'ANDROID!' ===")
f.seek(0)
block_size = 16 * 1024 * 1024  # 16MB blocks
overlap = 8  # signature is 8 bytes
offset = 0
boot_images = []
while offset < file_size:
    f.seek(offset)
    data = f.read(block_size + overlap)
    if not data:
        break
    pos = 0
    while True:
        idx = data.find(b'ANDROID!', pos)
        if idx == -1:
            break
        abs_offset = offset + idx
        boot_images.append(abs_offset)
        # Read boot header to get page size and kernel size
        if idx + 4096 <= len(data):
            header = data[idx:idx+4096]
            # Standard boot image header:
            # 0-7: magic "ANDROID!"
            # 8-39: kernel_size(4) kernel_addr(4) ramdisk_size(4) ramdisk_addr(4) ...
            kernel_size = struct.unpack_from('<I', header, 8)[0]
            kernel_addr = struct.unpack_from('<I', header, 12)[0]
            ramdisk_size = struct.unpack_from('<I', header, 16)[0]
            ramdisk_addr = struct.unpack_from('<I', header, 20)[0]
            second_size = struct.unpack_from('<I', header, 24)[0]
            second_addr = struct.unpack_from('<I', header, 28)[0]
            page_size = struct.unpack_from('<I', header, 36)[0]
            print(f"  0x{abs_offset:010x}: ANDROID! kernel_size=0x{kernel_size:x} kernel_addr=0x{kernel_addr:x} "
                  f"ramdisk_size=0x{ramdisk_size:x} page_size={page_size}")
            if page_size > 0 and page_size < 100000:
                print(f"    -> Valid boot image header (page_size={page_size})")
            else:
                print(f"    -> Suspicious page_size, may be false positive")
        pos = idx + 1
    offset += block_size

print(f"\nFound {len(boot_images)} Android boot image(s)")

# Also scan for ext4 superblock (magic 0xEF53 at offset 0x438 from partition start)
print("\n=== Scanning for ext4 superblocks ===")
f.seek(0)
offset = 0
ext4_count = 0
while offset < file_size:
    f.seek(offset)
    data = f.read(block_size + 0x43a)
    if not data:
        break
    pos = 0
    while True:
        idx = data.find(b'\x53\xef', pos)
        if idx == -1:
            break
        # Check if this could be an ext4 superblock (at offset 0x38 within the superblock)
        # The superblock starts at partition_start + 1024, and s_magic is at offset 0x38 within superblock
        abs_offset = offset + idx
        # Verify: check for ext4 magic context
        if idx >= 0x38:
            sb_start = idx - 0x38
            # s_blocks_count at offset 0
            blocks_count = struct.unpack_from('<I', data, sb_start)[0]
            # s_log_block_size at offset 4
            log_block_size = struct.unpack_from('<I', data, sb_start + 4)[0]
            # s_inodes_count at offset 0
            inodes_count = struct.unpack_from('<I', data, sb_start - 0x38 + 0)[0] if sb_start >= 0x38 else 0
            if 0 < blocks_count < 0x10000000 and log_block_size < 10:
                partition_start = abs_offset - 0x38 - 0x400  # superblock at 1024 bytes into partition
                if partition_start >= 0:
                    print(f"  0x{abs_offset:010x}: ext4 superblock? blocks=0x{blocks_count:x} log_bs={log_block_size} "
                          f"partition_start~=0x{partition_start:x}")
                    ext4_count += 1
                    if ext4_count > 20:
                        break
        pos = idx + 1
    if ext4_count > 20:
        break
    offset += block_size

# Look for XML/manifest content
print("\n=== Scanning for manifest/config text ===")
f.seek(0)
offset = 0
while offset < min(file_size, 100 * 1024 * 1024):  # First 100MB
    f.seek(offset)
    data = f.read(block_size)
    if not data:
        break
    for pat in [b'<?xml', b'md5sum', b'partition_name', b'boot.img', b'raw_image']:
        idx = data.find(pat)
        if idx != -1:
            abs_offset = offset + idx
            context = data[max(0,idx-20):idx+100]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            print(f"  0x{abs_offset:010x}: {printable}")
    offset += block_size

f.close()
print("\nDone.")
