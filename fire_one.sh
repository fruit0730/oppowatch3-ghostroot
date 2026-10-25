#!/usr/bin/env bash
# GhostLock OW3 single-fire driver.
# Fires the exploit once, waits through any reboot, reads the surviving ext4
# log, and prints a compact outcome signature line.  All on-device paths are
# literal (/data/...); local paths are Windows-style so adb.exe resolves them.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DEV_TMP=/data/local/tmp
RESULTS=${RESULTS:-/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/fire_results.txt}

dev_online() {
  $ADB devices 2>/dev/null | grep -q 'device$'
}

# Wait for a device to appear.  $1 = max seconds.
wait_device() {
  local max=${1:-150} waited=0
  while ! dev_online; do
    sleep 3; waited=$((waited+3))
    [ $waited -ge $max ] && return 1
  done
  # give adbd a moment to be usable
  sleep 2
  return 0
}

sig() {
  # $1 = whole log text
  local L="$1"
  local pre="" pcfi="" attempt="" cfires="" root="" finished="" leak=""
  echo "$L" | grep -q '^PREP base=' && pre=PREP
  leak=$(echo "$L" | grep -o 'leaked_mm=[0-9a-f]*' | tail -1)
  pcfi=$(echo "$L" | grep -o 'PRE-PCFI a=[0-9]*' | tail -1)
  attempt=$(echo "$L" | grep -o 'pselect returned attempt=[0-9]*[^)]*' | tail -1)
  cfires=$(echo "$L" | grep -o 'cfi write ret=[-0-9]*' | tail -1)
  root=$(echo "$L" | grep -o 'pipe-physrw-summary[^%]*root=[0-9]*' | grep -o 'root=[0-9]*' | tail -1)
  finished=$(echo "$L" | grep -o 'root=YES' | tail -1)
  echo "pre=${pre:-none} ${leak:-leaked=none} ${pcfi:-no-PCFI} | ${attempt:-no-attempt} | ${cfires:-no-cfiwrite} | ${root:-no-rootsum} ${finished}"
}

iterate=${1:-1}
for ((i=1;i<=iterate;i++)); do
  if ! wait_device 150; then
    echo "iter=$i RESULT=no-device-after-150s" | tee -a "$RESULTS"
    continue
  fi
  # clear prior logs so only this run's log remains
  $ADB shell "rm -f $DEV_TMP/log_*.txt" 2>/dev/null
  started=$(date +%H:%M:%S)
  # fire; the shell may die when the kernel panics -> timeout guards it
  timeout 100 $ADB shell 'sh /data/local/tmp/fire.sh' >/tmp/fire_stdout.txt 2>/tmp/fire_stderr.txt
  frc=$?
  # kernel panic => device reboots; wait for it to come back
  if ! dev_online; then
    wait_device 150 || true
  fi
  if ! dev_online; then
    echo "iter=$i RESULT=panic-no-recovery rc=$frc" | tee -a "$RESULTS"
    continue
  fi
  # read surviving log
  log=$($ADB shell "cat $DEV_TMP/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r')
  if [ -z "$log" ]; then
    echo "iter=$i RESULT=no-log rc=$frc t=$started" | tee -a "$RESULTS"
    continue
  fi
  s=$(sig "$log")
  # quick root probe: local su client present + uid via it
  su_id=$($ADB shell 'ls /data/local/tmp/su 2>/dev/null && echo HAS_SU' 2>/dev/null | tr -d '\r')
  echo "iter=$i rc=$frc t=$started $s ${su_id}" | tee -a "$RESULTS"
done
