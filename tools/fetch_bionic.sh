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

# Split the disk image (GPT -> partitions -> "super" logical partitions)
python3 tools/extract_image.py "$IMG" "$W/parts"
ls -la "$W/parts"

# Read one file out of an ext4 or erofs image
fstype() {
  if [ "$(od -An -tx1 -j1080 -N2 "$1" | tr -d ' ')" = "53ef" ]; then echo ext4
  elif [ "$(od -An -tx1 -j1024 -N4 "$1" | tr -d ' ')" = "e2e1f5e0" ]; then echo erofs
  else echo unknown; fi
}
fs_get() {  # image path-inside out
  case "$(fstype "$1")" in
    ext4) debugfs -R "dump -p $2 $3" "$1" >/dev/null 2>&1 ;;
    erofs)
      local d="$1.x"
      [ -d "$d" ] || { command -v fsck.erofs >/dev/null || sudo apt-get install -y -qq erofs-utils >/dev/null; fsck.erofs --extract="$d" "$1" >/dev/null 2>&1 || true; }
      cp "$d$2" "$3" 2>/dev/null ;;
    *) return 1 ;;
  esac
  [ -s "$3" ]
}
fs_ls() {
  case "$(fstype "$1")" in
    ext4) debugfs -R "ls -l $2" "$1" 2>/dev/null | head -40 ;;
    erofs) ls -la "$1.x$2" 2>/dev/null | head -40 ;;
  esac || true
}

FS=""
for c in system system_a; do [ -f "$W/parts/$c.img" ] && FS="$W/parts/$c.img" && break; done
[ -n "$FS" ] || { echo "no system partition"; exit 1; }
echo "== system partition: $FS ($(fstype "$FS"))"
dbg_ls() { fs_ls "$@"; }
dbg_dump() { fs_get "$@"; }

ROOTP="/system"
fs_get "$FS" /system/build.prop "$W/build.prop" || ROOTP=""
grep -E "ro.build.(version.release|id|fingerprint)=" "$W/build.prop" 2>/dev/null || true
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
      dbg_dump "$W/apex/apex_payload.img" /lib64/bionic/libm.so "$W/libm.so" || true
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
objcopy --dump-section .gnu_debugdata="$W/debugdata.xz" "$W/libc.so" /dev/null 2>/dev/null || true
if [ -s "$W/debugdata.xz" ]; then
  xz -dc "$W/debugdata.xz" > "$W/libc.debug" && echo "== .gnu_debugdata symbols extracted"
fi

# ---- Provenance (for the libc_shared_globals oracle, issue #1) ----------
# Metadata only: hashes, build properties, APEX manifest. No image content.
P="$(pwd)/out/provenance-scan.txt"
{
  echo "== SDK package: $PKG"
  cat "$D/source.properties" 2>/dev/null || echo "(no source.properties)"
  echo; echo "== sha256"
  sha256sum "$IMG" "$W/libc.so" 2>/dev/null | sed "s#$SDK/##; s#$(pwd)/##"
  [ -f "$W/linker64" ] && sha256sum "$W/linker64" | sed "s#$(pwd)/##"
  for A in com.android.runtime.apex com.android.runtime.capex; do
    [ -f "$W/$A" ] && sha256sum "$W/$A" | sed "s#$(pwd)/##"
  done
  echo; echo "== ELF build ids"
  for f in "$W/libc.so" "$W/linker64"; do
    [ -f "$f" ] && echo "$(basename "$f"): $(readelf -n "$f" | awk '/Build ID/{print $3}')"
  done
  echo; echo "== runtime APEX manifest (apex_manifest.pb, printable strings + version varint)"
  if [ -f "$W/apex/apex_manifest.pb" ]; then
    strings -n 3 "$W/apex/apex_manifest.pb"
    python3 - "$W/apex/apex_manifest.pb" <<'PY'
import sys
b = open(sys.argv[1], "rb").read()
i = 0
def varint(i):
    v = s = 0
    while True:
        c = b[i]; i += 1; v |= (c & 0x7f) << s; s += 7
        if not c & 0x80: return v, i
while i < len(b):
    key, i = varint(i); field, wt = key >> 3, key & 7
    if wt == 0:
        v, i = varint(i)
        if field == 2: print("apex version =", v)
    elif wt == 2:
        n, i = varint(i)
        if field == 1: print("apex name =", b[i:i+n].decode(errors="replace"))
        i += n
    elif wt == 5: i += 4
    elif wt == 1: i += 8
    else: break
PY
  else echo "(not found)"; fi
  echo; echo "== system build.prop (full)"
  cat "$W/build.prop" 2>/dev/null || echo "(not found)"
} > "$P"
cat "$P"

# Pin: fail loudly if the SDK served a different libc than the one measured.
EXPECT_LIBC_BUILD_ID="${EXPECT_LIBC_BUILD_ID:-fa337969c798946280caa45e2d71a2e7}"
GOT_ID="$(readelf -n "$W/libc.so" | awk '/Build ID/{print $3}')"
if [ "$GOT_ID" != "$EXPECT_LIBC_BUILD_ID" ]; then
  echo "ERROR: libc.so Build ID $GOT_ID, expected $EXPECT_LIBC_BUILD_ID - the SDK image changed"
  exit 1
fi
echo "== libc.so Build ID matches the pinned value"
