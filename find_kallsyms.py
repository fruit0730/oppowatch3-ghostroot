#!/usr/bin/env python3
"""Find and parse kallsyms table in extracted kernel region."""
import struct
import os

kernel_path = r'C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\extracted\kernel_region.bin'
boot_path = r'C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\extracted\boot_region.bin'

# Load kernel region
with open(kernel_path, 'rb') as f:
    kdata = f.read()
print(f"Kernel region: {len(kdata)} bytes (0x{len(kdata):x})")
kernel_base_off = 0x802dc000  # file offset of this region in OFP

# Load boot region
with open(boot_path, 'rb') as f:
    bdata = f.read()
print(f"Boot region: {len(bdata)} bytes (0x{len(bdata):x})")
boot_base_off = 0x549c0000

# Strategy: Find kallsyms by looking for the token_table
# In Linux 5.4, kallsyms_token_table contains 256 entries of null-terminated strings
# The token_index table follows with 256 uint16 entries
# Before that is kallsyms_names (compressed)
# Before that is kallsyms_num_syms and kallsyms_addresses

# First, let's look for known kernel strings to orient ourselves
print("\n=== Key strings in kernel region ===")
target_strings = [
    b'commit_creds', b'prepare_kernel_cred', b'sys_call_table',
    b'init_cred', b'security_cred_alloc_blank',
    b'override_creds', b'revert_creds',
    b'kallsyms_names', b'kallsyms_addresses',
    b'smp_init', b'rest_init', b'kernel_init',
    b'start_kernel', b'_stext', b'_etext',
    b'futex', b'rt_mutex', b'pipe_write', b'pipe_read',
    b'configfs', b'commit_creds', b'cred',
    b'__stack_chk_fail', b'selinux',
    b'setuid', b'setgid', b'set_fs',
]

for s in target_strings:
    pos = 0
    count = 0
    while count < 3:
        idx = kdata.find(s, pos)
        if idx == -1:
            break
        context = kdata[max(0,idx-8):idx+len(s)+20]
        # Show printable context
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        print(f"  0x{kernel_base_off + idx:010x} (rel 0x{idx:06x}): '{s.decode()}' -> {printable}")
        pos = idx + 1
        count += 1

# Also search boot region
print("\n=== Key strings in boot region ===")
for s in [b'ANDROID!', b'Linux version', b'commit_creds', b'init_task',
          b'boot.img', b'selinux', b'set_fs']:
    idx = bdata.find(s)
    if idx != -1:
        context = bdata[max(0,idx-8):idx+len(s)+40]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        print(f"  0x{boot_base_off + idx:010x}: '{s.decode()}' -> {printable}")

# Now try to find kallsyms_addresses by looking for sorted address arrays
# In ARM32 kernel 5.4, addresses are in range 0xC0008000 - 0xC1FFFFFF
print("\n=== Searching for kallsyms_addresses pattern ===")
# Look for sequences of 4-byte values in kernel address range that are sorted
# The kallsyms_addresses table typically has 20,000-50,000 entries
# Each entry is 4 bytes (32-bit), sorted ascending

best_start = -1
best_count = 0

# Sample at 4K boundaries to find candidate regions
for off in range(0, len(kdata) - 8, 4096):
    # Check if we have a sequence of sorted kernel addresses here
    count = 0
    prev = 0
    for i in range(off, min(off + 4096, len(kdata) - 4), 4):
        val = struct.unpack_from('<I', kdata, i)[0]
        if 0xC0008000 <= val <= 0xC2000000:
            if val >= prev:
                count += 1
                prev = val
            else:
                break
        else:
            break
    if count > best_count:
        best_count = count
        best_start = off

if best_count > 100:
    print(f"  Best candidate at rel 0x{best_start:x} (abs 0x{kernel_base_off + best_start:x})")
    print(f"  {best_count} consecutive sorted kernel addresses")
    # Show first few addresses
    for i in range(min(20, best_count)):
        val = struct.unpack_from('<I', kdata, best_start + i*4)[0]
        print(f"    [{i:5d}] 0x{val:08x}")
    # Show last few
    print(f"    ...")
    for i in range(max(0, best_count-5), best_count):
        val = struct.unpack_from('<I', kdata, best_start + i*4)[0]
        print(f"    [{i:5d}] 0x{val:08x}")
else:
    print(f"  No good kallsyms candidate found (best: {best_count} addresses)")
    # Try a finer scan
    print("  Trying finer scan (every 256 bytes)...")
    for off in range(0, len(kdata) - 8, 256):
        count = 0
        prev = 0
        for i in range(off, min(off + 8192, len(kdata) - 4), 4):
            val = struct.unpack_from('<I', kdata, i)[0]
            if 0xC0008000 <= val <= 0xC2000000:
                if val >= prev:
                    count += 1
                    prev = val
                else:
                    break
            else:
                break
        if count > 500:
            print(f"  Candidate at rel 0x{off:x}: {count} sorted kernel addresses")
            for i in range(min(10, count)):
                val = struct.unpack_from('<I', kdata, off + i*4)[0]
                print(f"    [{i:5d}] 0x{val:08x}")
            break

# Also look for the kallsyms infrastructure by finding the token table
# The token_table has 256 entries, many of which are common ASCII chars
# Look for a pattern like: "\0", "a\0", "b\0", "c\0", ... (single-char tokens)
print("\n=== Searching for kallsyms_token_table ===")
# The token table typically starts with single null byte, then single-char tokens
# Pattern: 00 61 00 62 00 63 00 ... (null, 'a', null, 'b', null, 'c', null, ...)
# Or more precisely, the first few tokens are usually:
# token 0: "" (empty, represented as just \0)
# token 1: "0" -> 30 00
# token 2: "1" -> 31 00
# etc.
# Actually the token table format is just concatenated null-terminated strings

# Let's search for a recognizable pattern in the token table
# Common tokens include: "t", "s", "r", "d", "_", ".", "0", "1", etc.
# The token_index table is 256 uint16 values pointing into token_table

# Look for token_index: starts with 0x0000, then increasing uint16 values
for off in range(0, len(kdata) - 512, 4):
    # Check for token_index pattern: first entry is 0, entries are increasing
    first = struct.unpack_from('<H', kdata, off)[0]
    if first != 0:
        continue
    second = struct.unpack_from('<H', kdata, off + 2)[0]
    if second == 0 or second > 100:
        continue
    # Check a few more entries
    ok = True
    prev_idx = 0
    for j in range(min(20, 256)):
        idx = struct.unpack_from('<H', kdata, off + j*2)[0]
        if idx < prev_idx:
            ok = False
            break
        prev_idx = idx
    if ok and prev_idx > 50:
        print(f"  Possible token_index at rel 0x{off:x} (abs 0x{kernel_base_off + off:x})")
        # Show first few entries
        for j in range(min(16, 256)):
            idx = struct.unpack_from('<H', kdata, off + j*2)[0]
            print(f"    token[{j}] -> offset {idx}")
        break

print("\nDone.")
