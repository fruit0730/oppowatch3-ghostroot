#!/usr/bin/env bash
# Fire N times, archive each full surviving log, print escalation-relevant tail.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
mkdir -p "$ARCH"
N=${1:-5}
for ((i=1;i<=N;i++)); do
  for k in $(seq 1 60); do $ADB devices | grep -q 'device$' && break; sleep 3; done
  $ADB shell "rm -f $DT/log_*.txt" 2>/dev/null
  timeout 110 $ADB shell 'sh /data/local/tmp/fire.sh' >/dev/null 2>&1; rc=$?
  for k in $(seq 1 60); do $ADB devices | grep -q 'device$' && break; sleep 3; done
  sleep 1
  $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/iter_$i.log"
  uid=$($ADB shell 'id -u' 2>/dev/null | tr -d '\r')
  echo "===== iter=$i rc=$rc uid_after=$uid $(wc -l < "$ARCH/iter_$i.log") lines ====="
  grep -E 'PREP base|PRE-PCFI|pselect returned|HIT model|CFI |cfi |ROOT|root=YES|exploit finished|Kaslr|leak' "$ARCH/iter_$i.log" | tail -20
  # did root happen?
  if grep -q 'root=YES' "$ARCH/iter_$i.log"; then echo ">>> ITER $i ROOT=YES <<<"; break; fi
done
