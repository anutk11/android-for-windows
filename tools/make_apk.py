#!/usr/bin/env python3
"""
tools/make_apk.py - Build a real Android .apk archive with compiled Binary XML
(AXML) AndroidManifest.xml, compressed assets, optional classes.dex, and
lib/x86_64/*.so native libraries. Zero external tools required.
"""
import argparse
import os
import struct
import zipfile

RES_STRING_POOL_TYPE       = 0x0001
RES_XML_TYPE               = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE   = 0x0103
RES_XML_RESOURCE_MAP_TYPE  = 0x0180

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTR_TYPE_STRING  = 0x03
ATTR_TYPE_INT_DEC = 0x10

ATTR_RES_IDS = {
    "name":        0x01010003,
    "value":       0x01010024,
    "versionCode": 0x0101021b,
    "versionName": 0x0101021c,
}


def encode_axml_manifest(package, activity, native_lib=None, version_code=1, version_name="1.0", utf8=False):
    strings = []
    str_idx = {}

    def intern(s):
        if s not in str_idx:
            str_idx[s] = len(strings)
            strings.append(s)
        return str_idx[s]

    # Put resource-mapped attribute names first so resource map indices match 1:1
    for attr_name in ("name", "value", "versionCode", "versionName"):
        intern(attr_name)

    res_ids = [ATTR_RES_IDS[k] for k in ("name", "value", "versionCode", "versionName")]

    # Intern all tags/values
    ns_idx = intern(ANDROID_NS)
    for tok in (
        "manifest", "package", package, version_name,
        "application", "activity", activity,
        "intent-filter", "action", "android.intent.action.MAIN",
        "category", "android.intent.category.LAUNCHER",
    ):
        intern(tok)
    if native_lib:
        for tok in ("meta-data", "android.app.lib_name", native_lib):
            intern(tok)

    # Build string pool chunk
    offsets = []
    blob = bytearray()
    for s in strings:
        offsets.append(len(blob))
        if utf8:
            b = s.encode("utf-8")
            assert len(s) < 128 and len(b) < 128
            blob.append(len(s))
            blob.append(len(b))
            blob.extend(b)
            blob.append(0)
        else:
            u16 = s.encode("utf-16le")
            nchars = len(u16) // 2
            assert nchars < 0x8000
            blob.extend(struct.pack("<H", nchars))
            blob.extend(u16)
            blob.extend(b"\x00\x00")
    while len(blob) % 4:
        blob.append(0)

    strings_start = 28 + 4 * len(strings)
    pool_size = strings_start + len(blob)
    flags = 0x100 if utf8 else 0
    pool_chunk = bytearray()
    pool_chunk.extend(struct.pack("<HHIIIIII",
        RES_STRING_POOL_TYPE, 28, pool_size,
        len(strings), 0, flags, strings_start, 0))
    for off in offsets:
        pool_chunk.extend(struct.pack("<I", off))
    pool_chunk.extend(blob)

    # Resource map chunk
    res_chunk = bytearray(struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, 8 + 4 * len(res_ids)))
    for rid in res_ids:
        res_chunk.extend(struct.pack("<I", rid))

    def start_elem(tag, attrs):
        body = bytearray()
        body.extend(struct.pack("<iiHHHHHH",
            -1, intern(tag), 20, 20, len(attrs), 0, 0, 0))
        for ns, aname, vtype, val in attrs:
            ns_i = intern(ns) if ns else -1
            an_i = intern(aname)
            if vtype == ATTR_TYPE_STRING:
                sv_i = intern(val)
                body.extend(struct.pack("<iiiHBBi", ns_i, an_i, sv_i, 8, 0, ATTR_TYPE_STRING, sv_i))
            else:
                body.extend(struct.pack("<iiiHBBi", ns_i, an_i, -1, 8, 0, vtype, int(val)))
        csize = 16 + len(body)
        return struct.pack("<HHIII", RES_XML_START_ELEMENT_TYPE, 16, csize, 1, 0xffffffff) + bytes(body)

    def end_elem(tag):
        return struct.pack("<HHIIIii", RES_XML_END_ELEMENT_TYPE, 16, 24, 1, 0xffffffff, -1, intern(tag))

    xml_chunks = bytearray()
    xml_chunks.extend(pool_chunk)
    xml_chunks.extend(res_chunk)
    xml_chunks.extend(start_elem("manifest", [
        (None, "package", ATTR_TYPE_STRING, package),
        (ANDROID_NS, "versionCode", ATTR_TYPE_INT_DEC, version_code),
        (ANDROID_NS, "versionName", ATTR_TYPE_STRING, version_name),
    ]))
    xml_chunks.extend(start_elem("application", []))
    xml_chunks.extend(start_elem("activity", [
        (ANDROID_NS, "name", ATTR_TYPE_STRING, activity),
    ]))
    if native_lib:
        xml_chunks.extend(start_elem("meta-data", [
            (ANDROID_NS, "name", ATTR_TYPE_STRING, "android.app.lib_name"),
            (ANDROID_NS, "value", ATTR_TYPE_STRING, native_lib),
        ]))
        xml_chunks.extend(end_elem("meta-data"))
    xml_chunks.extend(start_elem("intent-filter", []))
    xml_chunks.extend(start_elem("action", [
        (ANDROID_NS, "name", ATTR_TYPE_STRING, "android.intent.action.MAIN"),
    ]))
    xml_chunks.extend(end_elem("action"))
    xml_chunks.extend(start_elem("category", [
        (ANDROID_NS, "name", ATTR_TYPE_STRING, "android.intent.category.LAUNCHER"),
    ]))
    xml_chunks.extend(end_elem("category"))
    xml_chunks.extend(end_elem("intent-filter"))
    xml_chunks.extend(end_elem("activity"))
    xml_chunks.extend(end_elem("application"))
    xml_chunks.extend(end_elem("manifest"))

    total_size = 8 + len(xml_chunks)
    return struct.pack("<HHI", RES_XML_TYPE, 8, total_size) + bytes(xml_chunks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--package", required=True)
    ap.add_argument("--activity", required=True)
    ap.add_argument("--native-lib", default=None)
    ap.add_argument("--version-code", type=int, default=1)
    ap.add_argument("--version-name", default="1.0")
    ap.add_argument("--utf8-manifest", action="store_true")
    ap.add_argument("--lib", action="append", default=[], help="path to x86_64 .so")
    ap.add_argument("--asset", action="append", default=[], help="apk_asset_relpath=host_path")
    ap.add_argument("--dex", default=None, help="path to classes.dex")
    args = ap.parse_args()

    manifest = encode_axml_manifest(
        args.package, args.activity, args.native_lib,
        args.version_code, args.version_name, utf8=args.utf8_manifest,
    )
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        if args.dex:
            zf.write(args.dex, "classes.dex", compress_type=zipfile.ZIP_DEFLATED)
        for libp in args.lib:
            zf.write(libp, "lib/x86_64/" + os.path.basename(libp), compress_type=zipfile.ZIP_DEFLATED)
        for spec in args.asset:
            rel, hostp = spec.split("=", 1)
            zf.write(hostp, "assets/" + rel, compress_type=zipfile.ZIP_DEFLATED)
    print(f"Built APK {args.output} (package={args.package}, activity={args.activity}, native_lib={args.native_lib})")


if __name__ == "__main__":
    main()
