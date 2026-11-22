#!/usr/bin/env python3
"""Extract bionic (libc.so, libm.so, libdl.so, linker64) from the official
Android 14 x86_64 system image, on any OS (no debugfs: tools/ext4_get.py).

FOR LOCAL / CI EXPERIMENTS ONLY. Emulator images contain components that may
not be redistributed: the extracted files are NEVER uploaded or committed
(docs/COLLABORATION.md, rule 5). The run fails if libc.so is not the binary
every measurement in this project was made on (pinned ELF Build ID).

usage: fetch_bionic.py [outdir]          (default: out/bionic)
"""
import io
import os
import shutil
import struct
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ext4_get import Ext4  # noqa: E402

API = os.environ.get("API", "34")
PKG = "system-images;android-%s;default;x86_64" % API
PINNED_LIBC_BUILD_ID = os.environ.get("EXPECT_LIBC_BUILD_ID", "fa337969c798946280caa45e2d71a2e7")
WANT = {"/lib64/bionic/libc.so": "libc.so", "/lib64/bionic/libm.so": "libm.so",
        "/lib64/bionic/libdl.so": "libdl.so", "/bin/linker64": "linker64"}


def build_id(data):
    """The NT_GNU_BUILD_ID of an ELF64 file, as hex, or None."""
    if data[:4] != b"\x7fELF":
        return None
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        p = phoff + i * phentsize
        ptype, = struct.unpack_from("<I", data, p)
        if ptype != 4:                                  # PT_NOTE
            continue
        off, = struct.unpack_from("<Q", data, p + 8)
        size, = struct.unpack_from("<Q", data, p + 32)
        o = off
        while o + 12 <= off + size:
            nsz, dsz, typ = struct.unpack_from("<III", data, o)
            name = data[o + 12:o + 12 + nsz]
            desc_off = o + 12 + ((nsz + 3) & ~3)
            if typ == 3 and name.rstrip(b"\0") == b"GNU":
                return data[desc_off:desc_off + dsz].hex()
            o = desc_off + ((dsz + 3) & ~3)
    return None


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join("out", "bionic")
    os.makedirs(out, exist_ok=True)
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk:
        sys.exit("ANDROID_HOME is not set")
    sm = os.path.join(sdk, "cmdline-tools", "latest", "bin", "sdkmanager" + (".bat" if os.name == "nt" else ""))
    img_dir = os.path.join(sdk, "system-images", "android-" + API, "default", "x86_64")
    if not os.path.exists(os.path.join(img_dir, "system.img")):
        print("== installing", PKG, flush=True)
        subprocess.run([sm, "--install", PKG], input=b"y\n" * 20, check=True,
                       stdout=subprocess.DEVNULL, shell=(os.name == "nt"))
    parts = os.path.join(out, "parts")
    subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(__file__), "extract_image.py"),
                    os.path.join(img_dir, "system.img"), parts], check=True)
    system = Ext4(os.path.join(parts, "system.img"))
    apex = None
    for name in ("com.android.runtime.apex", "com.android.runtime.capex"):
        try:
            apex = system.data(system.lookup("/system/apex/" + name))
            print("== found", name)
            break
        except FileNotFoundError:
            continue
    if apex is None:
        sys.exit("no runtime APEX in the image")
    z = zipfile.ZipFile(io.BytesIO(apex))
    if "original_apex" in z.namelist():               # compressed APEX
        z = zipfile.ZipFile(io.BytesIO(z.read("original_apex")))
    payload = os.path.join(out, "apex_payload.img")
    with open(payload, "wb") as f:
        f.write(z.read("apex_payload.img"))
    fs = Ext4(payload)
    for src, dst in WANT.items():
        data = fs.data(fs.lookup(src))
        with open(os.path.join(out, dst), "wb") as f:
            f.write(data)
        print("== %-10s %8d bytes  build id %s" % (dst, len(data), build_id(data)))
    os.remove(payload)
    shutil.rmtree(parts, ignore_errors=True)            # the partitions are large and not needed
    got = build_id(open(os.path.join(out, "libc.so"), "rb").read())
    if got != PINNED_LIBC_BUILD_ID:
        sys.exit("libc.so Build ID %s, expected %s - the SDK image changed" % (got, PINNED_LIBC_BUILD_ID))
    print("== libc.so Build ID matches the pinned value")


if __name__ == "__main__":
    main()
