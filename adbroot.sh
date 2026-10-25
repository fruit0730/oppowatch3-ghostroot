#!/usr/bin/env bash
# One-shot driver for the "permissive -> init restarts adbd as ROOT" chain.
#
# Why this works on OWW212 (measured 2026-10-17, no exploit needed for steps 1-2):
#   * /apex/com.android.adbd/etc/init.rc defines `service adbd` with NO `user`
#     line, so INIT STARTS IT AS UID 0; adbd then drops itself to uid 2000
#     unless the `service.adb.root` prop says otherwise.
#   * `service.adb.root` is typed shell_prop => the unprivileged shell may write
#     it in enforcing mode (verified: readback "1" with no AVC).
#   * `ctl.restart adbd` is ctl_adbd_prop, denied to shell, but a permissive
#     kernel lets it through.  One rb_erase store at selinux_state is enough to
#     make the box permissive (fires e10/en1 did exactly that and survived).
#   * `u:r:su:s0` is a VALID context here (runcon answers EACCES, not EINVAL),
#     so the restarted adbd takes the su domain as well as uid 0.
#
#   bash adbroot.sh <label>
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
ADB=/c/platform-tools/adb.exe
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
LABEL=${1:-ar1}
OUT="$ARCH/${LABEL}.txt"
ENVFIRE="GHOSTLOCK_WBASE=4 GHOSTLOCK_ATTEMPTS=1 GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_SELINUX_OFF=0 GHOSTLOCK_WS_TARGET=enforce"

say() { echo "[$LABEL] $*" | tee -a "$OUT"; }

: > "$OUT"
online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() { local m=${1:-240} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 3; return 0; }
waitboot() { local m=${1:-300} w=0; while :; do b=$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r'); [ "$b" = "1" ] && break; sleep 4; w=$((w+4)); [ $w -ge $m ] && return 1; done; sleep 12; return 0; }

say "=== $LABEL $(date) ==="
waitdev || { say "NO-DEVICE at start"; exit 1; }
say "pre reboot getenforce=$($ADB shell getenforce 2>/dev/null | tr -d '\r') uptime=$($ADB shell uptime 2>/dev/null|tr -d '\r'|head -1)"
$ADB reboot >/dev/null 2>&1
say "rebooting for a fresh erase budget ..."
waitdev 300 || { say "NO-DEVICE after reboot"; exit 1; }
waitboot 420 || { say "BOOT-TIMEOUT"; exit 1; }
say "booted getenforce=$($ADB shell getenforce 2>/dev/null | tr -d '\r')"

# step 1: the prop that makes init's uid-0 adbd keep its uid.
$ADB shell setprop service.adb.root 1
say "service.adb.root=$($ADB shell getprop service.adb.root 2>/dev/null | tr -d '\r')"

# step 2: one store, selinux_state -> permissive.
$ADB shell "rm -f /data/local/tmp/log_*.txt" 2>/dev/null
timeout 240 $ADB shell "$ENVFIRE sh /data/local/tmp/fire.sh" >/dev/null 2>&1; rc=$?
$ADB shell "cat /data/local/tmp/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/${LABEL}-fire.log"
grep -aE 'WS-DONE|HIJ-POST|HIJ-ENFORCE|exploit finished' "$ARCH/${LABEL}-fire.log" | tail -6 | tee -a "$OUT"
say "fire rc=$rc getenforce=$($ADB shell getenforce 2>/dev/null | tr -d '\r') uid=$($ADB shell id -u 2>/dev/null | tr -d '\r')"

if [ "$($ADB shell getenforce 2>/dev/null | tr -d '\r')" != "Permissive" ]; then
  say "NOT PERMISSIVE -- store missed this boot; rebooting and retrying is the caller's job"
  exit 2
fi

# step 3: permissive -> the shell may now ask init to restart adbd.
$ADB shell setprop ctl.restart adbd
say "sent ctl.restart adbd, waiting for the new transport ..."
sleep 8
waitdev 120 || { say "DEVICE WENT AWAY after restart"; exit 3; }
for i in 1 2 3 4 5 6; do
  say "try$i id: $($ADB shell id 2>&1 | tr -d '\r' | head -1)"
  $ADB shell id 2>/dev/null | grep -q 'uid=0' && { say "*** ROOT *** adbd is uid 0"; exit 0; }
  sleep 5
done
say "adbd came back but is not root; ps:"
$ADB shell "ps -eo pid,user,name | grep adbd" 2>/dev/null | tr -d '\r' | tee -a "$OUT"
exit 4
