#!/usr/bin/env python3
"""
build_sample_apk.py - Builds a valid Android APK (with real binary AXML
AndroidManifest.xml, classes.dex, assets/info.txt, and lib/x86_64/libsample_jni.so)
AND verifies rendered 32-bit BMP screenshots in CI.

Usage:
  python3 tools/build_sample_apk.py build --dex classes.dex --lib libsample_jni.so --out sample_music_app.apk
  python3 tools/build_sample_apk.py verify-bmp out/sample_screen.bmp
"""
import argparse
import os
import struct
import sys
import zipfile


def encode_utf16_str(s: str) -> bytes:
    u16 = s.encode("utf-16-le")
    return struct.pack("<H", len(s)) + u16 + b"\x00\x00"


def build_string_pool(strings: list[str]) -> bytes:
    offsets = []
    blob = bytearray()
    for s in strings:
        offsets.append(len(blob))
        blob += encode_utf16_str(s)
    while len(blob) % 4 != 0:
        blob += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    chunk_size = strings_start + len(blob)
    hdr = struct.pack(
        "<HHIIIIII",
        0x0001,         # RES_STRING_POOL_TYPE
        header_size,
        chunk_size,
        len(strings),   # stringCount
        0,              # styleCount
        0,              # flags (UTF-16)
        strings_start,
        0,              # stylesStart
    )
    off_bytes = b"".join(struct.pack("<I", o) for o in offsets)
    return hdr + off_bytes + bytes(blob)


def build_res_map(res_ids: list[int]) -> bytes:
    chunk_size = 8 + 4 * len(res_ids)
    return struct.pack("<HHI", 0x0180, 8, chunk_size) + b"".join(
        struct.pack("<I", r) for r in res_ids
    )


def build_start_elem(ns_idx: int, name_idx: int, attrs: list[tuple[int, int, int, int, int]]) -> bytes:
    # Each attribute: ns, name, rawValue, size(2)=8, res0(1)=0, dataType(1), data(4) -> 20 bytes
    attr_bytes = bytearray()
    for ans, aname, araw, vtype, vdata in attrs:
        attr_bytes += struct.pack("<iiiHBBi", ans, aname, araw, 8, 0, vtype, vdata)
    ext = struct.pack("<iiHHHHHH", ns_idx, name_idx, 20, 20, len(attrs), 0, 0, 0)
    hdr_size = 16
    chunk_size = hdr_size + len(ext) + len(attr_bytes)
    hdr = struct.pack("<HHIII", 0x0102, hdr_size, chunk_size, 1, -1 & 0xFFFFFFFF)
    return hdr + ext + bytes(attr_bytes)


def build_end_elem(ns_idx: int, name_idx: int) -> bytes:
    hdr_size = 16
    chunk_size = hdr_size + 8
    return struct.pack("<HHIIIii", 0x0103, hdr_size, chunk_size, 1, -1 & 0xFFFFFFFF, ns_idx, name_idx)


def build_manifest_axml(package: str, label: str, activity: str) -> bytes:
    # Strings placed at index 0..N; attr names with Android resource IDs come first
    strings = [
        "name",                                     # 0 -> 0x01010003
        "label",                                    # 1 -> 0x01010001
        "versionCode",                              # 2 -> 0x0101021b
        "versionName",                              # 3 -> 0x0101021c
        "package",                                  # 4
        "http://schemas.android.com/apk/res/android",  # 5
        "manifest",                                 # 6
        "application",                              # 7
        "activity",                                 # 8
        "intent-filter",                            # 9
        "action",                                   # 10
        "category",                                 # 11
        package,                                    # 12
        "1.0.0",                                    # 13
        label,                                      # 14
        activity,                                   # 15
        "android.intent.action.MAIN",               # 16
        "android.intent.category.LAUNCHER",         # 17
    ]
    res_ids = [0x01010003, 0x01010001, 0x0101021B, 0x0101021C]
    TYPE_STRING = 0x03
    TYPE_INT_DEC = 0x10
    NS = 5

    body = bytearray()
    body += build_string_pool(strings)
    body += build_res_map(res_ids)
    # <manifest package=... android:versionCode=1 android:versionName="1.0.0">
    body += build_start_elem(-1, 6, [
        (-1, 4, 12, TYPE_STRING, 12),
        (NS, 2, -1, TYPE_INT_DEC, 1),
        (NS, 3, 13, TYPE_STRING, 13),
    ])
    # <application android:label="...">
    body += build_start_elem(-1, 7, [
        (NS, 1, 14, TYPE_STRING, 14),
    ])
    # <activity android:name=".PlayerActivity">
    body += build_start_elem(-1, 8, [
        (NS, 0, 15, TYPE_STRING, 15),
    ])
    # <intent-filter>
    body += build_start_elem(-1, 9, [])
    body += build_start_elem(-1, 10, [(NS, 0, 16, TYPE_STRING, 16)])
    body += build_end_elem(-1, 10)
    body += build_start_elem(-1, 11, [(NS, 0, 17, TYPE_STRING, 17)])
    body += build_end_elem(-1, 11)
    body += build_end_elem(-1, 9)
    body += build_end_elem(-1, 8)
    body += build_end_elem(-1, 7)
    body += build_end_elem(-1, 6)

    total = 8 + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + bytes(body)


import math
import zlib


def make_test_png(w: int = 32, h: int = 32) -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    raw = bytearray()
    for y in range(h):
        raw.append(0)  # filter type 0
        for x in range(w):
            r = (x * 8) & 0xFF
            g = (y * 8) & 0xFF
            b = 0xD0
            raw.extend((r, g, b, 255))
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw)))
            + chunk(b"IEND", b""))


def make_test_wav(rate: int = 44100, frames: int = 4410) -> bytes:
    pcm = bytearray()
    for i in range(frames):
        s = int(14000.0 * math.sin(2.0 * math.pi * 523.25 * i / rate))
        pcm += struct.pack("<h", s)
    data_sz = len(pcm)
    hdr = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF", 36 + data_sz, b"WAVE",
        b"fmt ", 16, 1, 1, rate, rate * 2, 2, 16,
        b"data", data_sz,
    )
    return hdr + bytes(pcm)


def cmd_build(args):
    axml = build_manifest_axml("com.afw.sample", "AFW Music Synth", ".PlayerActivity")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with zipfile.ZipFile(args.out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", axml)
        zf.write(args.dex, "classes.dex")
        zf.writestr("assets/info.txt", "AFW-Asset-Ready\n")
        zf.writestr("assets/cover.png", make_test_png(32, 32))
        zf.writestr("assets/chime.wav", make_test_wav(44100, 4410))
        if args.lib and os.path.exists(args.lib):
            zf.write(args.lib, "lib/x86_64/libsample_jni.so")
    print(f"Built {args.out} ({os.path.getsize(args.out)} bytes)")


def cmd_verify_bmp(args):
    with open(args.bmp, "rb") as f:
        data = f.read()
    if len(data) < 54 or data[:2] != b"BM":
        sys.exit(f"FAIL: {args.bmp} is not a valid BMP file (size={len(data)})")
    w = struct.unpack_from("<i", data, 18)[0]
    h = abs(struct.unpack_from("<i", data, 22)[0])
    bpp = struct.unpack_from("<H", data, 28)[0]
    if w < 64 or h < 64 or bpp != 32:
        sys.exit(f"FAIL: unexpected BMP dimensions/bpp: {w}x{h} {bpp}bpp")
    pix = data[54:]
    expect = w * h * 4
    if len(pix) < expect:
        sys.exit(f"FAIL: truncated BMP pixel data ({len(pix)} < {expect})")
    colors = set()
    # Sample across the whole framebuffer to verify rich non-blank UI rendering
    step = max(1, (w * h) // 4000)
    for i in range(0, w * h, step):
        colors.add(struct.unpack_from("<I", pix, i * 4)[0])
    print(f"BMP verified: {args.bmp} ({w}x{h} {bpp}bpp, {len(colors)} distinct sampled colors)")
    if len(colors) < 6:
        sys.exit(f"FAIL: BMP appears blank or monochrome (only {len(colors)} distinct colors)")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--dex", required=True)
    b.add_argument("--lib", default="")
    b.add_argument("--out", required=True)
    b.set_defaults(func=cmd_build)

    v = sub.add_parser("verify-bmp")
    v.add_argument("bmp")
    v.set_defaults(func=cmd_verify_bmp)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
