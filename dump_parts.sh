#!/usr/bin/env bash
# Stream every by-name partition of the OWW212 to the PC, EXCEPT userdata.
# Read-only on the device: `dd if=/dev/block/by-name/X` piped through
# `adb exec-out` (binary-safe, no pty munging) straight into a file -- nothing is
# written to the watch, and no staging space is needed there.
#
# Resume-safe: a partition is skipped when the local file already has exactly the
# size the kernel reports for it, so a dropped adb session or a panic-reboot in
# the middle just means running it again.
#
#   bash dump_parts.sh [out-dir]
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
ADB=/c/platform-tools/adb.exe
OUT=${1:-/g/oww212-partitions/a142}
LOG=$OUT/dump.log
mkdir -p "$OUT"

# Enumerate on the device rather than hardcoding, so nothing is missed; skip
# `userdata` (the user's data, and 25 GB) and the whole-disk node.
$ADB shell "ls /dev/block/by-name" 2>/dev/null | tr -d '\r' | tr ' \t' '\n\n' \
  | grep -v '^$' | grep -vw userdata | grep -vw mmcblk0 | sort > "$OUT/names.txt"
NAMES=$(tr '\n' ' ' < "$OUT/names.txt")
echo "[$(date +%H:%M:%S)] $(wc -l < "$OUT/names.txt") partitions to dump: $NAMES" | tee -a "$LOG"

# sizes as the kernel sees them (KB), from /proc/partitions
$ADB shell cat /proc/partitions 2>/dev/null | tr -d '\r' > "$OUT/proc-partitions.txt"

echo "[$(date +%H:%M:%S)] start, out=$OUT" | tee -a "$LOG"
uid=$($ADB shell id -u 2>/dev/null | tr -d '\r')
echo "[$(date +%H:%M:%S)] adb shell uid=$uid" | tee -a "$LOG"
if [ "$uid" != "0" ]; then
  echo "ABORT: the block devices are brw------- root root, so uid 0 is required."
  echo "       Start the rooted fire first:  bash rootnow.sh"
  exit 1
fi

tot=0
for n in $NAMES; do
  dev=$($ADB shell readlink /dev/block/by-name/$n 2>/dev/null | tr -d '\r')
  if [ -z "$dev" ]; then
    echo "[$n] SKIP: no by-name link" | tee -a "$LOG"
    continue
  fi
  szb=$($ADB shell blockdev --getsize64 $dev 2>/dev/null | tr -d '\r')
  case "$szb" in
    ''|*[!0-9]*) szb=0 ;;
  esac
  f="$OUT/$n.img"
  have=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if [ "$szb" != "0" ] && [ "$have" = "$szb" ]; then
    echo "[$n] ok already ($have bytes)" | tee -a "$LOG"
    tot=$((tot + have))
    continue
  fi
  st=$(date +%s)
  timeout 900 $ADB exec-out dd "if=$dev" bs=1M 2>/dev/null > "$f"
  rc=$?
  have=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if [ "$have" = "$szb" ] && [ "$szb" != "0" ]; then
    echo "[$n] $(($szb/1024/1024)) MB in $(($(date +%s)-st))s" | tee -a "$LOG"
  else
    echo "[$n] MISMATCH rc=$rc got=$have want=$szb ($dev)" | tee -a "$LOG"
  fi
  tot=$((tot + have))
done
echo "[$(date +%H:%M:%S)] done, total $((tot/1024/1024)) MB in $OUT" | tee -a "$LOG"
