#!/usr/bin/env bash
# Build tools/syscall_scan (Linux host tool) against third_party/zydis.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/out/scan"
mkdir -p "$OUT"

# Syscall names from the host's Linux headers (x86_64 numbering).
HDR=/usr/include/x86_64-linux-gnu/asm/unistd_64.h
[ -f "$HDR" ] || HDR=/usr/include/asm/unistd_64.h
{
  echo "/* generated from $HDR */"
  echo "static const char *const g_nr_name[] = {"
  grep -E '^#define __NR_[a-z0-9_]+ [0-9]+$' "$HDR" | awk '{sub("__NR_","",$2); printf "  [%s] = \"%s\",\n", $3, $2}'
  echo "};"
} > "$OUT/syscall_names.h"

if [ ! -f "$OUT/zydis/libZydis.a" ]; then
  cmake -S "$ROOT/third_party/zydis" -B "$OUT/zydis" -DCMAKE_BUILD_TYPE=Release \
        -DZYDIS_BUILD_TOOLS=OFF -DZYDIS_BUILD_EXAMPLES=OFF -DZYDIS_BUILD_DOXYGEN=OFF >/dev/null
  cmake --build "$OUT/zydis" -j"$(nproc)" >/dev/null
fi

cc -O2 -Wall -o "$OUT/syscall_scan" "$ROOT/tools/syscall_scan.c" \
   -I"$OUT" -I"$ROOT/third_party/zydis/include" \
   -I"$ROOT/third_party/zydis/dependencies/zycore/include" \
   -I"$OUT/zydis" -I"$OUT/zydis/zycore" \
   "$OUT/zydis/libZydis.a"
echo "built $OUT/syscall_scan"
