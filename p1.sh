#!/system/bin/sh
# Runs inside the rooted fire, after GHOSTLOCK_RELABEL has re-stamped the
# SELinux xattrs, as the uid named by GHOSTLOCK_POST_UID. Read-only checks only.
umask 000
echo "== id =="
id
echo "== labels now =="
ls -Zd /data/system/users/0 /data/system/users/0/settings_global.xml \
       /data/system/users/0/settings_secure.xml /data/system/users/0/settings_system.xml 2>&1
echo "== anything still unlabeled under /data/system =="
ls -ZR /data/system 2>/dev/null | grep -i unlabeled | head -10
echo "== can system_server write it now? (touch as an owner-only test) =="
ls -l /data/system/users/0/settings_global.xml 2>&1
echo "== recent settings_global denials =="
logcat -d 2>/dev/null | grep settings_global.xml | tail -3
echo VERIFY-DONE
