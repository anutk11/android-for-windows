#!/usr/bin/env python3
"""Split an Android emulator disk image into its partitions.

Handles the layers found in system images:
  GPT disk -> partitions -> (Android "super" with LP metadata -> logical partitions)
Each partition is written to OUTDIR/<name>.img and its filesystem type printed
(ext4 / erofs / super / unknown).

usage: extract_image.py <disk.img> <outdir>
"""
import os
import struct
import sys

SECTOR = 512


def fs_type(f, base):
    f.seek(base + 0x438)
    if f.read(2) == b"\x53\xef":
        return "ext4"
    f.seek(base + 1024)
    if struct.unpack("<I", f.read(4))[0] == 0xE0F5E1E2:
        return "erofs"
    f.seek(base + 4096)
    if f.read(4) == b"gDla":
        return "super"
    return "unknown"


def copy(f, out, ranges):
    """ranges: list of (byte_offset, byte_length) concatenated into out."""
    with open(out, "wb") as o:
        for off, length in ranges:
            f.seek(off)
            left = length
            while left:
                chunk = f.read(min(left, 1 << 22))
                if not chunk:
                    break
                o.write(chunk)
                left -= len(chunk)


def gpt_partitions(f):
    f.seek(SECTOR)
    hdr = f.read(92)
    if hdr[:8] != b"EFI PART":
        return None
    entries_lba, count, size = struct.unpack_from("<QII", hdr, 72)
    parts = []
    for i in range(count):
        f.seek(entries_lba * SECTOR + i * size)
        e = f.read(size)
        first, last = struct.unpack_from("<QQ", e, 32)
        if first == 0:
            continue
        name = e[56:128].decode("utf-16-le").rstrip("\x00") or "part%d" % i
        parts.append((name, first * SECTOR, (last - first + 1) * SECTOR))
    return parts


def lp_partitions(f, base):
    """Logical partitions inside an Android dynamic-partitions "super" image."""
    f.seek(base + 4096)
    geo = f.read(52)
    _magic, _sz = struct.unpack_from("<4sI", geo, 0)
    meta_max, _slots, block = struct.unpack_from("<III", geo, 40)
    hoff = base + 4096 * 3          # reserved + geometry + backup geometry
    f.seek(hoff)
    h = f.read(256)
    magic, major, minor, header_size = struct.unpack_from("<IHHI", h, 0)
    if magic != 0x414C5030:
        raise SystemExit("bad LP metadata magic")
    # tables_size + checksum, then 4 table descriptors (offset, num, entry_size)
    tables = [struct.unpack_from("<III", h, 80 + 12 * k) for k in range(4)]
    tbase = hoff + header_size
    (p_off, p_num, p_sz), (e_off, e_num, e_sz) = tables[0], tables[1]
    f.seek(tbase + e_off)
    exts = []
    for _ in range(e_num):
        num_sectors, ttype, tdata, tsrc = struct.unpack("<QIQI", f.read(e_sz)[:24])
        exts.append((num_sectors, ttype, tdata))
    out = []
    f.seek(tbase + p_off)
    raw = f.read(p_num * p_sz)
    for k in range(p_num):
        ent = raw[k * p_sz:(k + 1) * p_sz]
        name = ent[:36].rstrip(b"\x00").decode()
        _attr, first_ext, n_ext, _grp = struct.unpack_from("<IIII", ent, 36)
        ranges = []
        for num_sectors, ttype, tdata in exts[first_ext:first_ext + n_ext]:
            if ttype == 0:   # linear
                ranges.append((base + tdata * SECTOR, num_sectors * SECTOR))
        if ranges:
            out.append((name, ranges))
    print("  LP metadata v%d.%d, %d logical partitions" % (major, minor, len(out)))
    return out


def main():
    disk, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    with open(disk, "rb") as f:
        parts = gpt_partitions(f)
        if parts is None:
            parts = [("whole", 0, os.path.getsize(disk))]
        for name, off, length in parts:
            t = fs_type(f, off)
            print("%-14s offset=%-12d size=%-12d %s" % (name, off, length, t))
            if t == "super":
                for lname, ranges in lp_partitions(f, off):
                    path = os.path.join(outdir, lname + ".img")
                    copy(f, path, ranges)
                    with open(path, "rb") as g:
                        print("  %-12s %s" % (lname, fs_type(g, 0)))
            else:
                copy(f, os.path.join(outdir, name + ".img"), [(off, length)])


if __name__ == "__main__":
    main()
