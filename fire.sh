#!/system/bin/sh
export LD_PRELOAD=/data/local/tmp/preload.so
exec /system/bin/toybox true
