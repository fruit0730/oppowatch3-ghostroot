#!/usr/bin/env bash
# ARM32 preload.so build for Git Bash (no make needed).
# The NDK here is the WINDOWS prebuilt toolchain, so clang must receive a
# Windows-style --sysroot; MSYS would otherwise rewrite /g/... into a path the
# Windows binary cannot resolve (that produced "dirent.h not found").
set -e
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
NDK=/g/ndk/android-ndk-r29
TC=$NDK/toolchains/llvm/prebuilt/windows-x86_64
CC=$TC/bin/armv7a-linux-androideabi30-clang
SYSROOT_WIN='G:\ndk\android-ndk-r29\toolchains\llvm\prebuilt\windows-x86_64\sysroot'
cd "$(dirname "$0")/exploit"

# wallpaper_blob.S .incbin's this asset; an EMPTY file is what the currently
# verified build used, so only create a placeholder if the file is absent.
if [ ! -e assets/wallpaper.webp ]; then
  echo "[build] assets/wallpaper.webp missing/empty -> creating 1x1 placeholder"
  mkdir -p assets
  printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x024\x01\x00;' > assets/wallpaper.webp
fi

"$CC" \
  --target=armv7a-linux-androideabi30 \
  "--sysroot=$SYSROOT_WIN" \
  -I. -Isrc -Itargets/oppo-oww212 \
  -DTARGET_CONFIG_H='"targets/oppo-oww212/target.h"' \
  -D__ARM32 -O2 -fPIC -shared \
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -Wall -Wextra \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c \
  src/preload.c src/su_blob.S src/wallpaper_blob.S \
  -o preload.so -pthread

echo "[build] OK $(stat -c%s preload.so) bytes"
md5sum preload.so
