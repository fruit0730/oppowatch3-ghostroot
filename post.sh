#!/system/bin/sh
# Read-only survey, run as the uid named by GHOSTLOCK_POST_UID (system=1000 here).
umask 000   # the fire runs this as uid 1000, so its .out must stay adb-readable
echo "== id =="
id
echo "== dir modes / labels =="
ls -ldZ /data/system /data/system/users /data/system/users/0 2>&1
echo "== users/0 listing =="
ls -Z /data/system/users/0 2>&1
echo "== any unlabeled entry under /data/system =="
ls -ZR /data/system 2>/dev/null | grep -i unlabeled
echo "== labels of the settings + package files =="
for f in /data/system/users/0/settings_global.xml /data/system/users/0/settings_secure.xml \
         /data/system/users/0/settings_system.xml /data/system/packages.xml \
         /data/system/packages.list; do
  printf '%s -> %s\n' "$f" "$(ls -Zd "$f" 2>&1)"
done
echo "== does SettingsProvider still fail? =="
logcat -d 2>/dev/null | grep -c 'settings_global.xml'
logcat -d 2>/dev/null | grep 'settings_global.xml' | tail -2
echo POST-SCRIPT-DONE
