#!/usr/bin/env bash
# quietchk.sh - is the watch in a state where firing GhostLock is worth a try?
#
# Every punch re-walks the priority-inheritance chain, and the walk only survives
# if the box is not busy creating and destroying tasks around it. Two things have
# been killing fires lately: lowmemorykiller thrash (the watch sits at 11-30 MB
# free) and an LSPosed/YukiHook module that hooks every app launch, so the system
# forks constantly. This measures that instead of guessing, and also detects the
# "adb lists the device but nothing can fork" half-hung state, where firing is
# pointless and only a power cycle helps.
#
#   bash quietchk.sh          one 20 s sample
#   bash quietchk.sh 40       sample for 40 s
export MSYS_NO_PATHCONV=1
ADB=${ADB:-/c/platform-tools/adb.exe}
WIN=${1:-20}

line() { timeout 20 "$ADB" shell "$1" 2>/dev/null | tr -d '\r'; }

forks0=$(line "grep '^processes' /proc/stat" | awk '{print $2}')
if [ -z "$forks0" ]; then
  echo "WEDGED - adb answers nothing; the watch cannot fork a process."
  echo "         Hold the side key 15-20s until the OPPO logo, then run this again."
  exit 2
fi

sleep "$WIN"

forks1=$(line "grep '^processes' /proc/stat" | awk '{print $2}')
if [ -z "$forks1" ]; then
  echo "WEDGED mid-sample - the box hung while we were measuring it."
  exit 2
fi

new=$((forks1 - forks0))
per=$((new * 60 / WIN))
mem=$(line "grep MemFree /proc/meminfo" | awk '{print $2}')
load=$(line "cat /proc/loadavg" | awk '{print $1}')
tasks=$(line "ls /proc | grep -c '^[0-9]*$'")

echo "  window      : ${WIN}s"
echo "  new tasks   : $new  (~$per/min, $forks1 total since boot)"
echo "  MemFree     : $((mem / 1024)) MB"
echo "  load (1min) : $load"
echo "  live tasks  : $tasks"

# Thresholds from the fires we have on record: the fires that completed 13-21
# punches went in with a 1-minute load of <= 9.4 and a system that was not
# churning; the ones that froze on punch 1 went in while the box was creating
# hundreds of tasks a minute. 900/min is roughly "LMK is re-launching apps
# continuously".
if [ "$per" -gt 900 ]; then
  echo "VERDICT: BUSY - do not fire. Disable the LSPosed/YukiHook module (or"
  echo "         uninstall the hooked demo app) and take the watch off whatever"
  echo "         is relaunching apps, then re-run this."
  exit 1
fi
if [ "$mem" -lt 15360 ]; then
  echo "VERDICT: BUSY - under 15 MB free, lowmemorykiller will take the fire out."
  exit 1
fi
echo "VERDICT: QUIET - worth a fire."
exit 0
