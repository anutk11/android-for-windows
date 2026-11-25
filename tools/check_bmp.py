#!/usr/bin/env python3
"""
tools/check_bmp.py - Verify exact rendered BMP dimensions and sampled RGB pixels.
Usage: check_bmp.py <file.bmp> <width> <height> <x,y:R,G,B:tol> [...]
"""
import struct
import sys


def main():
    if len(sys.argv) < 5:
        print("usage: check_bmp.py <bmp> <w> <h> <x,y:R,G,B:tol> ...", file=sys.stderr)
        return 2
    path = sys.argv[1]
    want_w, want_h = int(sys.argv[2]), int(sys.argv[3])
    data = open(path, "rb").read()
    assert len(data) >= 54 and data[:2] == b"BM", f"{path}: not a BMP"
    w, h, bpp = struct.unpack_from("<ii", data, 18) + (struct.unpack_from("<H", data, 28)[0],)
    assert w == want_w and abs(h) == want_h and bpp == 24, f"{path}: got {w}x{h} {bpp}bpp"
    stride = (w * 3 + 3) & ~3
    for spec in sys.argv[4:]:
        xy, rgb, tol_s = spec.split(":")
        x, y = map(int, xy.split(","))
        wr, wg, wb = map(int, rgb.split(","))
        tol = int(tol_s)
        row_y = (want_h - 1 - y) if h > 0 else y
        off = 54 + row_y * stride + x * 3
        b, g, r = data[off], data[off + 1], data[off + 2]
        assert abs(r - wr) <= tol and abs(g - wg) <= tol and abs(b - wb) <= tol, (
            f"{path} ({x},{y}): got RGB({r},{g},{b}), expected RGB({wr},{wg},{wb}) +/-{tol}"
        )
        print(f"  [ OK ] {path} ({x},{y}) = RGB({r},{g},{b}) matches ({wr},{wg},{wb}) +/-{tol}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
