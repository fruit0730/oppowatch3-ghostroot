#!/system/bin/sh
# freeze_watch.sh - sample the watch every 2 s so a freeze leaves EVIDENCE.
#
# Runs as uid shell (no root needed) and keeps writing after the exploit lands,
# so whatever the box dies of is on disk: /data/local/tmp/freeze.log survives a
# panic and a reboot. Read it afterwards with a plain `adb shell cat`.
LOG=/data/local/tmp/freeze.log
i=0
echo "=== freeze_watch start $(date) ===" >> $LOG
while [ $i -lt 3000 ]; do
  i=$((i + 1))
  {
    printf '%s #%s ' "$(date +%H:%M:%S)" "$i"
    cat /proc/loadavg
    sed -n 2p /proc/meminfo
  } >> $LOG 2>&1
  # Committed + the biggest RSS holders: an lmkd death-spiral looks different
  # from a kernel hang (memory flat, load climbing, no new pids).
  ps -eo pid,rss,name --sort=-rss 2>/dev/null | sed -n '2,5p' | tr '\n' '|' >> $LOG 2>&1
  echo >> $LOG
  if [ $((i % 10)) -eq 0 ]; then
    dmesg 2>/dev/null | tail -4 >> $LOG 2>&1
    sync
  fi
  sleep 2
done
echo "=== freeze_watch done $(date) ===" >> $LOG
