#!/usr/bin/env python3
import struct
import sys
import os

ofp_path = os.path.join(os.environ.get('TEMP', r'C:\Users\RLG\AppData\Local\Temp'),
                        r'360zip$Temp\360$1\OWW211_11_A.90_230105_d784fa8b_MCU_2301050147.ofp')

if not os.path.exists(ofp_path):
    # Try alternate path
    ofp_path = r'C:\Users\RLG\AppData\Local\Temp\360zip$Temp\360$1\OWW211_11_A.90_230105_d784fa8b_MCU_2301050147.ofp'

print(f"File: {ofp_path}")
print(f"Size: {os.path.getsize(ofp_path) / (1024*1024*1024):.2f} GB")

f = open(ofp_path, 'rb')

# ELF64 header
magic = f.read(4)
print(f"Magic: {magic}")
ei_class = struct.unpack('B', f.read(1))[0]
ei_data = struct.unpack('B', f.read(1))[0]
f.read(10)
e_type = struct.unpack('<H', f.read(2))[0]
e_machine = struct.unpack('<H', f.read(2))[0]
e_version = struct.unpack('<I', f.read(4))[0]
e_entry = struct.unpack('<Q', f.read(8))[0]
e_phoff = struct.unpack('<Q', f.read(8))[0]
e_shoff = struct.unpack('<Q', f.read(8))[0]
e_flags = struct.unpack('<I', f.read(4))[0]
e_ehsize = struct.unpack('<H', f.read(2))[0]
e_phentsize = struct.unpack('<H', f.read(2))[0]
e_phnum = struct.unpack('<H', f.read(2))[0]
e_shentsize = struct.unpack('<H', f.read(2))[0]
e_shnum = struct.unpack('<H', f.read(2))[0]
e_shstrndx = struct.unpack('<H', f.read(2))[0]

print(f"ELF class: {ei_class} (2=64bit)")
print(f"Type: {e_type}")
print(f"Machine: 0x{e_machine:x} (0xb7=AArch64)")
print(f"Entry: 0x{e_entry:x}")
print(f"PH offset: {e_phoff}, count: {e_phnum}, size: {e_phentsize}")
print(f"SH offset: {e_shoff}, count: {e_shnum}, size: {e_shentsize}")

# Read program headers
print("\n--- Program Headers ---")
f.seek(e_phoff)
segments = []
for i in range(min(e_phnum, 100)):
    ph = f.read(e_phentsize)
    if len(ph) < e_phentsize:
        break
    p_type = struct.unpack_from('<I', ph, 0)[0]
    p_flags = struct.unpack_from('<I', ph, 4)[0]
    p_offset = struct.unpack_from('<Q', ph, 8)[0]
    p_vaddr = struct.unpack_from('<Q', ph, 16)[0]
    p_paddr = struct.unpack_from('<Q', ph, 24)[0]
    p_filesz = struct.unpack_from('<Q', ph, 32)[0]
    p_memsz = struct.unpack_from('<Q', ph, 40)[0]
    p_align = struct.unpack_from('<Q', ph, 48)[0]
    segments.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
    type_names = {1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR', 0x60000000: 'OS_SPEC'}
    tname = type_names.get(p_type, f'0x{p_type:x}')
    print(f"  [{i:3d}] {tname:10s} flags={p_flags:#x} off=0x{p_offset:010x} filesz=0x{p_filesz:010x} memsz=0x{p_memsz:010x}")

# Read section headers if present
if e_shnum > 0 and e_shoff > 0:
    print(f"\n--- Section Headers ({e_shnum} sections) ---")
    f.seek(e_shoff)
    for i in range(min(e_shnum, 100)):
        sh = f.read(e_shentsize)
        if len(sh) < e_shentsize:
            break
        sh_name = struct.unpack_from('<I', sh, 0)[0]
        sh_type = struct.unpack_from('<I', sh, 4)[0]
        sh_flags = struct.unpack_from('<Q', sh, 8)[0]
        sh_addr = struct.unpack_from('<Q', sh, 16)[0]
        sh_offset = struct.unpack_from('<Q', sh, 24)[0]
        sh_size = struct.unpack_from('<Q', sh, 32)[0]
        sh_link = struct.unpack_from('<I', sh, 40)[0]
        sh_info = struct.unpack_from('<I', sh, 44)[0]
        sh_addralign = struct.unpack_from('<Q', sh, 48)[0]
        sh_entsize = struct.unpack_from('<Q', sh, 56)[0]
        print(f"  [{i:3d}] name={sh_name:4d} type={sh_type:3d} flags=0x{sh_flags:x} addr=0x{sh_addr:x} off=0x{sh_offset:010x} size=0x{sh_size:010x}")

f.close()
print("\nDone.")
