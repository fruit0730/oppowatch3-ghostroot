#!/usr/bin/env python3
"""Extract kernel image from OFP around the Linux version strings."""
import struct
import os

ofp_path = r'C:\Users\RLG\AppData\Local\Temp\360zip$Temp\360$1\OWW211_11_A.90_230105_d784fa8b_MCU_2301050147.ofp'
out_dir = r'C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\extracted'
os.makedirs(out_dir, exist_ok=True)

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

# 1. Check around 0x549c24ba - "Linux version" with surrounding context
print("=== Context around 0x549c24ba (Linux version) ===")
# Check 4096 bytes before for boot image header
pre_offset = 0x549c24ba - 0x10000  # 64KB before
data = read_at(pre_offset, 0x20000)  # 128KB
idx = data.find(b'Linux version')
print(f"  'Linux version' at relative offset 0x{idx:x} (absolute 0x{pre_offset + idx:x})")

# Check for boot image header in the preceding data
for check_off in range(max(0, idx - 0x10000), idx, 4096):
    if data[check_off:check_off+8] == b'ANDROID!':
        print(f"  ANDROID! boot header at relative 0x{check_off:x}")

# Check for gzip magic before the Linux version
for check_off in range(max(0, idx - 0x100000), idx):
    if data[check_off:check_off+2] == b'\x1f\x8b':
        print(f"  gzip magic at relative 0x{check_off:x} (absolute 0x{pre_offset + check_off:x})")
    if data[check_off:check_off+4] == b'\x1f\x8b\x08\x00':
        print(f"  ** Full gzip header at relative 0x{check_off:x}")

# Check for LZ4 magic
for check_off in range(max(0, idx - 0x100000), idx):
    if data[check_off:check_off+4] == b'\x02\x21\x4c\x18':
        print(f"  LZ4 magic at relative 0x{check_off:x}")

# Check for XZ magic
for check_off in range(max(0, idx - 0x100000), idx):
    if data[check_off:check_off+6] == b'\xfd7zXZ\x00':
        print(f"  XZ magic at relative 0x{check_off:x}")

# Look at what's 64KB before Linux version
print(f"\n  64KB before 'Linux version':")
print(hexdump(data[:256], pre_offset, 256))

# 2. Check around 0x802dc2c8 - "Linux version %s (%*s" with ARM code
print("\n=== Context around 0x802dc2c8 (kernel code) ===")
kernel_region = 0x802dc2c8 - 0x100000  # 1MB before
data2 = read_at(kernel_region, 0x200000)  # 2MB
idx2 = data2.find(b'Linux version %s')
print(f"  'Linux version %%s' at relative 0x{idx2:x} (absolute 0x{kernel_region + idx2:x})")

# Check for ARM kernel image header
# ARM32 kernel typically starts with:
# - A branch instruction at offset 0
# - Or for compressed kernel: gzip/lz4/xz header
# The kernel .text usually starts with specific patterns

# Look for the ARM32 kernel stext
# In an uncompressed ARM32 kernel, the first instruction is typically:
# b <offset>  (e9000000 + offset for ARM, or a jump for Thumb)
# Let's look for patterns

# Check for gzip compressed kernel
print("\n  Searching for compressed kernel headers in 2MB region...")
for i in range(0, len(data2) - 8):
    if data2[i:i+2] == b'\x1f\x8b':
        print(f"    gzip at 0x{kernel_region + i:x}")
        if i + 10 < len(data2):
            # gzip header: 1f 8b 08 [flags] [mtime x4] [xflags] [os]
            flags = data2[i+3]
            os_byte = data2[i+9]
            print(f"      flags=0x{flags:02x} os={os_byte}")
        if kernel_region + i > 0x802dc2c8:
            break  # Don't search past the Linux version string

for i in range(0, len(data2) - 8):
    if data2[i:i+4] == b'\x02\x21\x4c\x18':
        print(f"    LZ4 at 0x{kernel_region + i:x}")
    if data2[i:i+6] == b'\xfd7zXZ\x00':
        print(f"    XZ at 0x{kernel_region + i:x}")

# 3. Search for the actual kernel text base
# The kernel .text section on ARM32 typically has a specific pattern
# Look for "swapper" or "init_task" strings which are near the kernel start
print("\n=== Searching for kernel identity strings ===")
f.seek(0)
block_size = 16 * 1024 * 1024
offset = 0
file_size = os.path.getsize(ofp_path)
while offset < file_size:
    f.seek(offset)
    data = f.read(block_size + 64)
    for pat in [b'swapper_thread', b'init_task', b'init_cred', b'smp_operations',
                b'smp_init', b'rest_init', b'kernel_init', b'start_kernel']:
        idx = data.find(pat)
        if idx != -1:
            abs_off = offset + idx
            context = data[idx:idx+40]
            print(f"  0x{abs_off:010x}: {context}")
    offset += block_size
    if offset > 100 * 1024 * 1024:  # Limit to first 100MB for speed
        break

# 4. Extract a large chunk around the kernel code region for analysis
print("\n=== Extracting kernel region ===")
# The kernel code is around 0x802dc2c8. Let's extract 16MB around it
extract_start = 0x802dc000  # Page-aligned before the kernel code
extract_size = 16 * 1024 * 1024  # 16MB
out_path = os.path.join(out_dir, 'kernel_region.bin')
print(f"  Extracting 0x{extract_start:x} - 0x{extract_start + extract_size:x} to {out_path}")
f.seek(extract_start)
with open(out_path, 'wb') as out:
    remaining = extract_size
    while remaining > 0:
        chunk = min(remaining, 4 * 1024 * 1024)
        data = f.read(chunk)
        if not data:
            break
        out.write(data)
        remaining -= len(data)
print(f"  Written {extract_size - remaining} bytes")

# Also extract the region around 0x549c24ba
extract_start2 = 0x549c0000
extract_size2 = 4 * 1024 * 1024
out_path2 = os.path.join(out_dir, 'boot_region.bin')
print(f"  Extracting 0x{extract_start2:x} - 0x{extract_start2 + extract_size2:x} to {out_path2}")
f.seek(extract_start2)
with open(out_path2, 'wb') as out:
    remaining = extract_size2
    while remaining > 0:
        chunk = min(remaining, 4 * 1024 * 1024)
        data = f.read(chunk)
        if not data:
            break
        out.write(data)
        remaining -= len(data)
print(f"  Written {extract_size2 - remaining} bytes")

# 5. Check the region around 0x549c24ba more carefully - look for boot.img header
# Boot images can be at various alignments
print("\n=== Detailed scan around 0x549c24ba ===")
# Check every 4K-aligned offset for boot image magic
scan_start = 0x549c0000 - 0x100000  # 1MB before
scan_size = 0x200000  # 2MB
data = read_at(scan_start, scan_size)
for i in range(0, scan_size - 8, 4096):
    if data[i:i+8] == b'ANDROID!':
        ks = struct.unpack_from('<I', data, i+8)[0]
        ka = struct.unpack_from('<I', data, i+12)[0]
        rs = struct.unpack_from('<I', data, i+16)[0]
        ps = struct.unpack_from('<I', data, i+36)[0]
        print(f"  ANDROID! at 0x{scan_start+i:x} kernel_size=0x{ks:x} kernel_addr=0x{ka:x} "
              f"ramdisk_size=0x{rs:x} page_size={ps}")

f.close()
print("\nDone.")
