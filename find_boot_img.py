#!/usr/bin/env python3
"""Full scan of OFP for Android boot image headers at all alignments."""
import struct
import os

ofp_path = r'C:\Users\RLG\AppData\Local\Temp\360zip$Temp\360$1\OWW211_11_A.90_230105_d784fa8b_MCU_2301050147.ofp'
out_dir = r'C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\extracted'
os.makedirs(out_dir, exist_ok=True)

file_size = os.path.getsize(ofp_path)
print(f"File size: {file_size} ({file_size/(1024*1024*1024):.2f} GB)")

f = open(ofp_path, 'rb')

# Scan for ANDROID! at every 512-byte aligned offset
print("=== Full scan for ANDROID! boot image header ===")
block_size = 64 * 1024 * 1024  # 64MB blocks
overlap = 4096
offset = 0
boot_images = []

while offset < file_size:
    f.seek(offset)
    data = f.read(block_size + overlap)
    if not data or len(data) < 8:
        break

    pos = 0
    while pos < len(data) - 8:
        idx = data.find(b'ANDROID!', pos)
        if idx == -1:
            break
        abs_off = offset + idx

        # Validate boot image header
        if idx + 4096 <= len(data):
            hdr = data[idx:idx+4096]
            kernel_size = struct.unpack_from('<I', hdr, 8)[0]
            kernel_addr = struct.unpack_from('<I', hdr, 12)[0]
            ramdisk_size = struct.unpack_from('<I', hdr, 16)[0]
            ramdisk_addr = struct.unpack_from('<I', hdr, 20)[0]
            second_size = struct.unpack_from('<I', hdr, 24)[0]
            second_addr = struct.unpack_from('<I', hdr, 28)[0]
            tags_addr = struct.unpack_from('<I', hdr, 32)[0]
            page_size = struct.unpack_from('<I', hdr, 36)[0]

            # Validate: page_size should be power of 2, typically 2048, 4096, 8192, 16384
            valid_page = page_size in (2048, 4096, 8192, 16384, 32768, 32768)
            # Kernel/ramdisk sizes should be reasonable
            valid_sizes = kernel_size < 50 * 1024 * 1024 and ramdisk_size < 50 * 1024 * 1024
            # Addresses should be in plausible range for ARM32 or AArch64
            valid_addrs = (0x00000000 <= kernel_addr <= 0xFFFFFFFF)

            if valid_page and valid_sizes:
                print(f"\n  *** VALID BOOT IMAGE at 0x{abs_off:010x} ***")
                print(f"    kernel_size:  0x{kernel_size:x} ({kernel_size/1024/1024:.1f} MB)")
                print(f"    kernel_addr:  0x{kernel_addr:08x}")
                print(f"    ramdisk_size: 0x{ramdisk_size:x} ({ramdisk_size/1024/1024:.1f} MB)")
                print(f"    ramdisk_addr: 0x{ramdisk_addr:08x}")
                print(f"    second_size:  0x{second_size:x}")
                print(f"    second_addr:  0x{second_addr:08x}")
                print(f"    tags_addr:    0x{tags_addr:08x}")
                print(f"    page_size:    {page_size}")

                # Read boot image header OS version
                if len(hdr) >= 48:
                    os_version = struct.unpack_from('<I', hdr, 40)[0]
                    if os_version:
                        a = (os_version >> 24) & 0x7F
                        b = (os_version >> 17) & 0x7F
                        c = (os_version >> 10) & 0x7F
                        print(f"    os_version:   {a}.{b}.{c}")

                # Read name field (16 bytes at offset 48)
                name = hdr[48:64].split(b'\x00')[0]
                if name:
                    print(f"    name:         {name}")

                # Read cmdline (first 512 bytes at offset 1024 for v0, or 448 bytes at offset 64 for v1+)
                cmdline = hdr[64:64+512].split(b'\x00')[0]
                if cmdline:
                    print(f"    cmdline:      {cmdline[:200]}")

                boot_images.append((abs_off, kernel_size, ramdisk_size, page_size))

                # Extract the boot image (header + kernel + ramdisk)
                total_size = page_size + kernel_size + ramdisk_size + second_size
                total_size = ((total_size + page_size - 1) // page_size) * page_size  # Align
                print(f"    total_size:   ~0x{total_size:x} ({total_size/1024/1024:.1f} MB)")

                out_name = os.path.join(out_dir, f'boot_image_0x{abs_off:x}.img')
                print(f"    Extracting to {out_name}...")
                f.seek(abs_off)
                with open(out_name, 'wb') as out:
                    remaining = total_size
                    while remaining > 0:
                        chunk = min(remaining, 4 * 1024 * 1024)
                        d = f.read(chunk)
                        if not d:
                            break
                        out.write(d)
                        remaining -= len(d)
                    extracted = total_size - remaining
                    print(f"    Extracted {extracted} bytes")

                # Also extract just the kernel
                kernel_offset = page_size
                f.seek(abs_off + kernel_offset)
                kernel_data = f.read(kernel_size)
                kernel_out = os.path.join(out_dir, f'kernel_0x{abs_off:x}.bin')
                with open(kernel_out, 'wb') as out:
                    out.write(kernel_data)
                print(f"    Kernel extracted to {kernel_out} ({kernel_size} bytes)")

                # Check if kernel is compressed
                if kernel_data[:2] == b'\x1f\x8b':
                    print(f"    ** Kernel is gzip compressed!")
                elif kernel_data[:4] == b'\x02\x21\x4c\x18':
                    print(f"    ** Kernel is LZ4 compressed!")
                elif kernel_data[:6] == b'\xfd7zXZ\x00':
                    print(f"    ** Kernel is XZ compressed!")
                elif kernel_data[:4] == b'\xb8\x00\x00\xea' or kernel_data[:4] == b'\xb8\x00\x00\x14':
                    print(f"    ** Kernel appears to be uncompressed ARM32 (branch instruction)")
                elif kernel_data[:8] == b'\x00\x00\xa0\xe1':
                    print(f"    ** Kernel appears to be uncompressed ARM32 (mov r0,r0)")
                else:
                    print(f"    Kernel first 16 bytes: {kernel_data[:16].hex()}")

            else:
                # False positive
                pass
        pos = idx + 1
    offset += block_size

print(f"\n\n=== Summary: Found {len(boot_images)} valid boot images ===")
for i, (off, ks, rs, ps) in enumerate(boot_images):
    print(f"  [{i}] offset=0x{off:x} kernel={ks/1024/1024:.1f}MB ramdisk={rs/1024/1024:.1f}MB page={ps}")

f.close()
print("\nDone.")
