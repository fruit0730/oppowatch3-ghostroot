#!/system/bin/sh
# freeze_root.sh - run this AS ROOT: it keeps the kernel log, which uid shell
# cannot read on this build (dmesg_restrict). The point is to catch the last
# messages before a freeze: an oops/`blocked for more than 120 seconds` here
# means the PI walk; silence + a memory cliff means lmkd.
LOG=/data/local/tmp/freeze_root.log
i=0
echo "=== root sampler start $(date) ===" >> $LOG
while [ $i -lt 2000 ]; do
  i=$((i + 1))
  {
    printf 'R %s #%s ' "$(date +%H:%M:%S)" "$i"
    cat /proc/loadavg
    sed -n 2p /proc/meminfo
  } >> $LOG 2>&1
  dmesg 2>&1 | tail -8 >> $LOG 2>&1
  sync
  sleep 3
done
echo "=== root sampler done $(date) ===" >> $LOG
