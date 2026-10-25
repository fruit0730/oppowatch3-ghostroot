#!/usr/bin/env bash
# Dump every partition except userdata to the PC, driving the dd through the
# ROOTED daemon (a plain `adb shell` is uid 2000 and cannot open the block
# devices, which are brw------- root root), then `adb pull` the image back.
#
#   bash dump_via_root.sh [name ...]      # no args = every partition
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
ADB=/c/platform-tools/adb.exe
HERE=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212
# MSYS_NO_PATHCONV is on (adb needs unconverted device paths), so anything handed
# to a WINDOWS executable -- python.exe, adb's pull destination -- must already be
# in Windows form. Bash-side work (mkdir/stat/du) keeps the /g/... form.
HEREW='C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212'
OUT=/g/oww212-partitions/a142
OUTW='G:\oww212-partitions\a142'
DEVDIR=/data/local/tmp/dump
LOG=$OUT/dump.log
mkdir -p "$OUT"

python - <<'EOF'
import re, os
raw = open(r"C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\captures\partitions-raw.txt",
           encoding="utf-8", errors="replace").read()
names = dict((m.group(1), m.group(2)) for m in
             re.finditer(r'lrwxrwxrwx[^\n]*?\s(\S+) -> /dev/block/(\S+)', raw))
sizes = {}
for m in re.finditer(r'^\s*\d+\s+\d+\s+(\d+)\s+(\S+)\s*$', raw, re.M):
    sizes[m.group(2)] = int(m.group(1)) * 1024
out = open(r"C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\plan.txt", "w")
for n, dev in sorted(names.items()):
    if n in ("userdata", "mmcblk0"):
        continue
    out.write("%s %s %d\n" % (n, dev, sizes.get(dev, 0)))
out.close()
print("plan.txt:", sum(1 for _ in open(r"C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\plan.txt")), "entries")
EOF

$ADB shell "mkdir -p $DEVDIR; chmod 777 $DEVDIR" >/dev/null 2>&1
echo "[$(date +%H:%M:%S)] uid via adb shell = $($ADB shell id -u 2>/dev/null | tr -d '\r') (2000 is fine: dd runs in the rooted daemon)" | tee -a "$LOG"

ONLY="$*"
while read -r n dev want; do
  want=${want%$'\r'}          # plan.txt is written by Windows python: CRLF
  n=${n%$'\r'}; dev=${dev%$'\r'}
  [ -n "$n" ] || continue
  if [ -n "$ONLY" ]; then
    case " $ONLY " in *" $n "*) ;; *) continue ;; esac
  fi
  f="$OUT/$n.img"
  have=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if [ "$want" != "0" ] && [ "$have" = "$want" ]; then
    echo "[$n] ok ($have)" | tee -a "$LOG"
    continue
  fi
  st=$(date +%s)
  timeout 900 python "$HEREW\\rootcmd.py" 850 "dd if=/dev/block/$dev of=$DEVDIR/$n.img bs=1M 2>/dev/null; chmod 666 $DEVDIR/$n.img; ls -l $DEVDIR/$n.img" >> "$LOG" 2>&1 </dev/null
  $ADB pull "$DEVDIR/$n.img" "$OUTW\\$n.img" >> "$LOG" 2>&1 </dev/null
  have=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if [ "$have" = "$want" ] && [ "$want" != "0" ]; then
    echo "[$n] $(($want/1024/1024)) MB in $(($(date +%s)-st))s OK" | tee -a "$LOG"
  else
    echo "[$n] MISMATCH got=$have want=$want ($dev)" | tee -a "$LOG"
  fi
  $ADB shell "rm -f $DEVDIR/$n.img" >/dev/null 2>&1 </dev/null
done < "$HERE/plan.txt"

echo "[$(date +%H:%M:%S)] done" | tee -a "$LOG"
du -sh "$OUT" 2>/dev/null | tee -a "$LOG"
