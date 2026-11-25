#!/usr/bin/env bash
# Build afw-loader for a Linux host (tests and measurement mode).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZA="$ROOT/out/zydis-amalg"
if [ ! -f "$ZA/Zydis.c" ]; then
  (cd "$ROOT/third_party/zydis" && python3 assets/amalgamate.py >/dev/null)
  mkdir -p "$ZA" && mv "$ROOT/third_party/zydis/amalgamated-dist/"Zydis.[ch] "$ZA/"
  rmdir "$ROOT/third_party/zydis/amalgamated-dist"
fi
OUTBIN="${OUTBIN:-$ROOT/out/afw-loader}"
cc -O2 -Wall -Wno-unused-function -pthread ${EXTRA_CFLAGS:-} -I"$ZA" -o "$OUTBIN" "$ROOT"/src/*.c "$ZA/Zydis.c" -lm
echo "built $OUTBIN"
