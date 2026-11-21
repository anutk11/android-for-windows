#!/usr/bin/env bash
# Extract the real bionic libc.so (x86_64) from an official Android system
# image. FOR LOCAL / CI EXPERIMENTS ONLY: emulator images contain components
# that may not be redistributed, so the extracted files are never published.
#
# Output: out/bionic/libc.so (+ libc.debug with .gnu_debugdata symbols if present)
set -euo pipefail
API="${API:-34}"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
W="$(pwd)/out/bionic"
mkdir -p "$W"

SM="$SDK/cmdline-tools/latest/bin/sdkmanager"
PKG="system-images;android-$API;default;x86_64"
echo "== installing $PKG"
yes | "$SM" --licenses >/dev/null 2>&1 || true
"$SM" --install "$PKG" >/dev/null
D="$SDK/system-images/android-$API/default/x86_64"
ls -la "$D"

IMG="$D/system.img"
file "$IMG"

# Find an ext4 filesystem: the image itself, or a partition inside it.
FS=""
if debugfs -R "stats" "$IMG" >/dev/null 2>&1; then
  FS="$IMG"
else
  echo "== not a plain ext4 image, extracting partitions"
  7z l "$IMG" || true
  7z x -y -o"$W/parts" "$IMG" >/dev/null
  ls -la "$W/parts"
  for p in $(ls -S "$W/parts"/*); do
    if debugfs -R "stats" "$p" >/dev/null 2>&1; then FS="$p"; break; fi
  done
fi
[ -n "$FS" ] || { echo "no ext4 filesystem found"; exit 1; }
echo "== filesystem: $FS"

dbg_ls() { debugfs -R "ls -l $2" "$1" 2>/dev/null | head -40 || true; }
dbg_dump() { debugfs -R "dump -p $2 $3" "$1" >/dev/null 2>&1 && [ -s "$3" ]; }

# Android 10+: system-as-root, so system files live under /system
ROOTP="/system"
debugfs -R "ls /system/apex" "$FS" >/dev/null 2>&1 || ROOTP=""
echo "== $ROOTP/apex"; dbg_ls "$FS" "$ROOTP/apex"

GOT=""
# 1) The runtime APEX: the libc.so that apps actually use
for A in com.android.runtime.apex com.android.runtime.capex; do
  if dbg_dump "$FS" "$ROOTP/apex/$A" "$W/$A"; then
    echo "== found $A"
    mkdir -p "$W/apex" && (cd "$W/apex" && unzip -o -q "../$A")
    if [ -f "$W/apex/original_apex" ]; then (cd "$W/apex" && unzip -o -q original_apex); fi
    if [ -f "$W/apex/apex_payload.img" ] && dbg_dump "$W/apex/apex_payload.img" /lib64/bionic/libc.so "$W/libc.so"; then
      GOT="runtime APEX ($A) /lib64/bionic/libc.so"
      dbg_ls "$W/apex/apex_payload.img" /lib64/bionic
      dbg_dump "$W/apex/apex_payload.img" /bin/linker64 "$W/linker64" || true
      break
    fi
  fi
done
# 2) Fallback: the bootstrap copy used during early boot
if [ -z "$GOT" ] && dbg_dump "$FS" "$ROOTP/lib64/bootstrap/libc.so" "$W/libc.so"; then
  GOT="$ROOTP/lib64/bootstrap/libc.so"
  dbg_ls "$FS" "$ROOTP/lib64/bootstrap"
fi
[ -n "$GOT" ] || { echo "libc.so not found"; exit 1; }
echo "== libc.so from: $GOT"
file "$W/libc.so"; ls -la "$W"

# Hidden function names: bionic keeps an xz-compressed .symtab in .gnu_debugdata
if objcopy --dump-section .gnu_debugdata="$W/debugdata.xz" "$W/libc.so" 2>/dev/null; then
  xz -dc "$W/debugdata.xz" > "$W/libc.debug" && echo "== .gnu_debugdata symbols extracted"
fi
