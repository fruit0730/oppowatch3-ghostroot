#!/usr/bin/env python3
"""Quick diagnostic: what kind of firmware is this OFP?"""
import os, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ofp_path = r'C:\Users\RLG\AppData\Local\Temp\360zip$Temp\360$1\OWW211_11_A.90_230105_d784fa8b_MCU_2301050147.ofp'
file_size = os.path.getsize(ofp_path)
f = open(ofp_path, 'rb')

def scan_for(patterns, max_scan=200*1024*1024):
    """Scan file for patterns, return dict of pattern->list of offsets."""
    results = {p: [] for p in patterns}
    f.seek(0)
    block_size = 16 * 1024 * 1024
    offset = 0
    while offset < min(file_size, max_scan):
        f.seek(offset)
        data = f.read(block_size + 64)
        if not data:
            break
        for pat in patterns:
            pos = 0
            while len(results[pat]) < 5:
                idx = data.find(pat, pos)
                if idx == -1:
                    break
                results[pat].append(offset + idx)
                pos = idx + 1
        offset += block_size
    return results

# Key indicators
print("=== Firmware type analysis ===")
print(f"File: {os.path.basename(ofp_path)}")
print(f"Size: {file_size/(1024*1024*1024):.2f} GB")

# Check for main Android system indicators
print("\n--- Android system indicators ---")
r = scan_for([
    b'system.img', b'vendor.img', b'userdata.img', b'cache.img',
    b'boot.img', b'recovery.img', b'dtbo.img',
    b'ANDROID!', b'VNDRBOOT',
    b'/system/', b'/vendor/', b'/data/',
    b'init.rc', b'init.environ.rc',
    b'com.android.', b'com.oppo.',
])
for pat, offsets in r.items():
    if offsets:
        print(f"  '{pat.decode('ascii', errors='replace')}': found at {[f'0x{o:x}' for o in offsets]}")
    else:
        print(f"  '{pat.decode('ascii', errors='replace')}': NOT FOUND")

# Check for MCU/modem subsystem indicators
print("\n--- MCU/Modem subsystem indicators ---")
r2 = scan_for([
    b'amss/', b'boot_images/', b'adsp_proc/', b'mdsp_proc/',
    b'modem/', b'tz_proc/', b'cdsp/', b'slpi/',
    b'atherton', b'Atherton', b'SW5100',
    b'MCU', b'mcu_firmware',
    b'q6', b'adsp', b'mdsp',
])
for pat, offsets in r2.items():
    if offsets:
        print(f"  '{pat.decode('ascii', errors='replace')}': found at {[f'0x{o:x}' for o in offsets]}")

# Check for partition table / flashing manifest
print("\n--- Partition/flashing indicators ---")
r3 = scan_for([
    b'rawprogram', b'partition_name', b'<program ',
    b'gpt_main', b'gpt_both', b'partition0', b'partition1',
    b'flash_cert', b'metadata', b'persist',
])
for pat, offsets in r3.items():
    if offsets:
        print(f"  '{pat.decode('ascii', errors='replace')}': found at {[f'0x{o:x}' for o in offsets]}")

# Check for Linux kernel (main AP kernel vs RTOS)
print("\n--- Kernel indicators ---")
r4 = scan_for([
    b'Linux version', b'androidboot.', b'console=tty',
    b'root=/dev/', b'selinux=1', b'buildvariant=user',
    b'smp_init', b'start_kernel', b'rest_init',
    b'Freeing unused kernel', b'Initramfs',
])
for pat, offsets in r4.items():
    if offsets:
        print(f"  '{pat.decode('ascii', errors='replace')}': found at {[f'0x{o:x}' for o in offsets]}")

# Read the build path strings
print("\n--- Build paths ---")
r5 = scan_for([b'_workspace/SW5100'])
for pat, offsets in r5.items():
    for off in offsets[:3]:
        f.seek(off)
        data = f.read(200)
        # Find end of string
        end = data.find(b'\x00')
        if end > 0:
            path = data[:end].decode('ascii', errors='replace')
        else:
            path = data[:100].decode('ascii', errors='replace')
        print(f"  0x{off:x}: {path}")

f.close()
print("\nDone.")
