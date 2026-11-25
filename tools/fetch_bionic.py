#!/usr/bin/env python3
"""Extract bionic (libc.so, libm.so, libdl.so, linker64) from the official
Android 14 x86_64 system image, on any OS (no debugfs: tools/ext4_get.py).

FOR LOCAL / CI EXPERIMENTS ONLY. Emulator images contain components that may
not be redistributed: the extracted files are NEVER uploaded or committed
(docs/COLLABORATION.md, rule 5). The run fails if libc.so is not the binary
every measurement in this project was made on (pinned ELF Build ID).

usage: fetch_bionic.py [outdir] [--art]  (default: out/bionic)

--art also extracts, for measurement only (G3 planning, issue #15):
  libart.so from the ART APEX, and every boot image .oat file (the ART
  APEX's javalib/x86_64 and the system partition's framework/x86_64).
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


def open_apex(system, names):
    """The payload filesystem image bytes of the first APEX found, or None."""
    for name in names:
        try:
            apex = system.data(system.lookup("/system/apex/" + name))
        except FileNotFoundError:
            continue
        print("== found", name)
        z = zipfile.ZipFile(io.BytesIO(apex))
        if "original_apex" in z.namelist():           # compressed APEX
            z = zipfile.ZipFile(io.BytesIO(z.read("original_apex")))
        return z.read("apex_payload.img")
    return None


def save(out, name, data):
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)
    print("== %-28s %9d bytes  build id %s" % (name, len(data), build_id(data)))


def elf_needed(data):
    """Return list of DT_NEEDED library names from an ELF64 binary."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phent, phnum = struct.unpack_from("<HH", data, 0x36)
    loads = []
    dyn_off = dyn_sz = 0
    for i in range(phnum):
        p = phoff + i * phent
        if p + 56 > len(data):
            break
        pt, _, off, vaddr, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", data, p)
        if pt == 1:
            loads.append((vaddr, vaddr + filesz, off))
        elif pt == 2:
            dyn_off, dyn_sz = off, filesz
    if not dyn_off:
        return []

    def v2o(va):
        for lo, hi, off in loads:
            if lo <= va < hi:
                return off + (va - lo)
        return None

    strtab_va = None
    needed_offs = []
    for o in range(dyn_off, min(dyn_off + dyn_sz, len(data) - 15), 16):
        tag, val = struct.unpack_from("<qQ", data, o)
        if tag == 0:
            break
        elif tag == 5:
            strtab_va = val
        elif tag == 1:
            needed_offs.append(val)
    if strtab_va is None:
        return []
    st_off = v2o(strtab_va)
    if st_off is None:
        return []
    out = []
    for noff in needed_offs:
        pos = st_off + noff
        end = data.find(b"\0", pos)
        if end > pos:
            out.append(data[pos:end].decode("utf-8", "replace"))
    return out


def extract_art(system, out):
    """libart.so and the boot image .oat files, for the %gs: scan."""
    art_dir = os.path.join(out, "art")
    os.makedirs(art_dir, exist_ok=True)
    payload = open_apex(system, ("com.android.art.apex", "com.android.art.capex"))
    if payload is None:
        sys.exit("no ART APEX in the image")
    path = os.path.join(out, "art_payload.img")
    with open(path, "wb") as f:
        f.write(payload)
    with Ext4(path) as fs:
        save(art_dir, "libart.so", fs.data(fs.lookup("/lib64/libart.so")))
        try:
            for n, ino in fs.listdir(fs.lookup("/javalib/x86_64")):
                if n.endswith(".oat"):
                    save(art_dir, "apex-" + n, fs.data(ino))
        except FileNotFoundError:
            print("== no /javalib/x86_64 in the ART APEX")
    os.remove(path)
    try:
        for n, ino in system.listdir(system.lookup("/system/framework/x86_64")):
            if n.endswith(".oat"):
                save(art_dir, "system-" + n, system.data(ino))
    except FileNotFoundError:
        print("== no /system/framework/x86_64 in the system partition")


def extract_art_full(system, out):
    """Extract libart.so, all APEX/system transitive .so deps, bootclasspath jars, and ICU data."""
    lib_dir = os.path.join(out, "art", "lib64")
    jar_dir = os.path.join(out, "art", "javalib")
    icu_dir = os.path.join(out, "art", "icu")
    os.makedirs(lib_dir, exist_ok=True)
    os.makedirs(jar_dir, exist_ok=True)
    os.makedirs(icu_dir, exist_ok=True)

    bionic_skip = {"libc.so", "libm.so", "libdl.so"}
    have = set(bionic_skip)
    queue = []

    apex_list = [
        ("com.android.art.apex", "com.android.art.capex"),
        ("com.android.i18n.apex", "com.android.i18n.capex"),
        ("com.android.conscrypt.apex", "com.android.conscrypt.capex"),
        ("com.android.os.statsd.apex", "com.android.os.statsd.capex"),
        ("com.android.runtime.apex", "com.android.runtime.capex"),
    ]
    for cand in apex_list:
        payload = open_apex(system, cand)
        if payload is None:
            continue
        pimg = os.path.join(out, "tmp_apex.img")
        with open(pimg, "wb") as f:
            f.write(payload)
        with Ext4(pimg) as fs:
            for ldir in ("/lib64", "/lib64/bionic"):
                try:
                    for n, ino in fs.listdir(fs.lookup(ldir)):
                        if n.endswith(".so") and n not in have:
                            try:
                                rino = fs.lookup(ldir + "/" + n)
                                d = fs.data(rino)
                            except (FileNotFoundError, IOError, ValueError):
                                continue
                            if d[:4] == b"\x7fELF":
                                save(lib_dir, n, d)
                                have.add(n)
                                queue.append((n, d))
                except FileNotFoundError:
                    pass
            try:
                for n, ino in fs.listdir(fs.lookup("/javalib")):
                    if n.endswith(".jar"):
                        d = fs.data(ino)
                        with open(os.path.join(jar_dir, n), "wb") as jf:
                            jf.write(d)
                        print("== jar %-24s %9d bytes" % (n, len(d)))
            except FileNotFoundError:
                pass
            try:
                for n, ino in fs.listdir(fs.lookup("/etc/icu")):
                    if n.endswith(".dat"):
                        d = fs.data(ino)
                        with open(os.path.join(icu_dir, n), "wb") as df:
                            df.write(d)
                        print("== icu %-24s %9d bytes" % (n, len(d)))
            except FileNotFoundError:
                pass
        os.remove(pimg)

    # Transitively resolve remaining DT_NEEDED from /system/lib64
    missing = set()
    sys_dirs = ["/system/lib64", "/system/lib64/bootstrap"]
    while queue:
        _, data = queue.pop(0)
        for dep in elf_needed(data):
            if dep in have or dep in missing:
                continue
            found_data = None
            for sdir in sys_dirs:
                try:
                    ino = system.lookup(sdir + "/" + dep)
                    d = system.data(ino)
                    if d[:4] == b"\x7fELF":
                        found_data = d
                        break
                except (FileNotFoundError, IOError, ValueError):
                    continue
            if found_data is not None:
                save(lib_dir, dep, found_data)
                have.add(dep)
                queue.append((dep, found_data))
            else:
                missing.add(dep)
    if missing:
        print("== unresolved DT_NEEDED (not in APEX or /system/lib64):", sorted(missing))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    want_art = "--art" in sys.argv[1:]
    want_art_full = "--art-full" in sys.argv[1:]
    out = args[0] if args else os.path.join("out", "bionic")
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
    data = open_apex(system, ("com.android.runtime.apex", "com.android.runtime.capex"))
    if want_art:
        extract_art(system, out)
    if want_art_full:
        extract_art_full(system, out)
    system.close()                                      # Windows cannot delete an open file
    if data is None:
        sys.exit("no runtime APEX in the image")
    payload = os.path.join(out, "apex_payload.img")
    with open(payload, "wb") as f:
        f.write(data)
    with Ext4(payload) as fs:
        for src, dst in WANT.items():
            d = fs.data(fs.lookup(src))
            with open(os.path.join(out, dst), "wb") as f:
                f.write(d)
            print("== %-10s %8d bytes  build id %s" % (dst, len(d), build_id(d)))
        if want_art_full:
            # Also grab libdl_android.so / libandroidicu.so etc. if present in runtime APEX
            try:
                for n, ino in fs.listdir(fs.lookup("/lib64/bionic")):
                    if n.endswith(".so") and n not in ("libc.so", "libm.so", "libdl.so"):
                        d = fs.data(ino)
                        if d[:4] == b"\x7fELF":
                            save(os.path.join(out, "art", "lib64"), n, d)
            except FileNotFoundError:
                pass
    os.remove(payload)
    shutil.rmtree(parts, ignore_errors=True)            # the partitions are large and not needed
    with open(os.path.join(out, "libc.so"), "rb") as f:
        got = build_id(f.read())
    if got != PINNED_LIBC_BUILD_ID:
        sys.exit("libc.so Build ID %s, expected %s - the SDK image changed" % (got, PINNED_LIBC_BUILD_ID))
    print("== libc.so Build ID matches the pinned value")


if __name__ == "__main__":
    main()
