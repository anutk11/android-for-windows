#!/usr/bin/env python3
"""Read one file out of an ext4 image, in pure Python (no debugfs: works on
Windows runners). Read-only; enough of ext4 for Android images: extents
(and the old block map), 64-bit descriptors, uninitialised extents, htree
directories read linearly.

usage: ext4_get.py <image> </path/inside> <out>      copy one file
       ext4_get.py <image> </dir> --ls                 list a directory
"""
import struct
import sys


class Ext4:
    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __init__(self, path):
        self.f = open(path, "rb")
        sb = self.read_at(1024, 1024)
        if struct.unpack_from("<H", sb, 0x38)[0] != 0xEF53:
            raise ValueError("not ext4")
        self.block = 1024 << struct.unpack_from("<I", sb, 0x18)[0]
        self.first_data = struct.unpack_from("<I", sb, 0x14)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0]
        rev = struct.unpack_from("<I", sb, 0x4C)[0]
        self.inode_size = struct.unpack_from("<H", sb, 0x58)[0] if rev >= 1 else 128
        incompat = struct.unpack_from("<I", sb, 0x60)[0]
        self.is64 = bool(incompat & 0x80)
        self.desc_size = struct.unpack_from("<H", sb, 0xFE)[0] if self.is64 else 32
        if self.desc_size < 32:
            self.desc_size = 32
        self.gdt = (self.first_data + 1) * self.block

    def read_at(self, off, n):
        self.f.seek(off)
        d = self.f.read(n)
        if len(d) != n:
            raise IOError("short read at %d" % off)
        return d

    def inode(self, ino):
        g, i = divmod(ino - 1, self.inodes_per_group)
        d = self.read_at(self.gdt + g * self.desc_size, self.desc_size)
        table = struct.unpack_from("<I", d, 8)[0]
        if self.is64 and self.desc_size >= 0x2C:
            table |= struct.unpack_from("<I", d, 0x28)[0] << 32
        return self.read_at(table * self.block + i * self.inode_size, self.inode_size)

    def extents(self, node):
        """Yield (logical block, physical block, count, initialised)."""
        magic, entries, _, depth = struct.unpack_from("<HHHH", node, 0)
        if magic != 0xF30A:
            raise ValueError("bad extent header")
        for e in range(entries):
            o = 12 + 12 * e
            if depth == 0:
                lblk, ln, hi, lo = struct.unpack_from("<IHHI", node, o)
                init = ln <= 32768
                yield lblk, (hi << 32) | lo, ln if init else ln - 32768, init
            else:
                _, lo, hi = struct.unpack_from("<IIH", node, o)
                yield from self.extents(self.read_at(((hi << 32) | lo) * self.block, self.block))

    def blockmap(self, iblock, nblocks):
        ptrs = list(struct.unpack_from("<15I", iblock, 0))
        per = self.block // 4
        out = []

        def walk(b, level):
            if len(out) >= nblocks:
                return
            if b == 0:
                out.extend([0] * min(per ** level, nblocks - len(out)))
                return
            if level == 0:
                out.append(b)
                return
            for p in struct.unpack("<%dI" % per, self.read_at(b * self.block, self.block)):
                walk(p, level - 1)
                if len(out) >= nblocks:
                    return

        for p in ptrs[:12]:
            walk(p, 0)
        for lvl, p in ((1, ptrs[12]), (2, ptrs[13]), (3, ptrs[14])):
            walk(p, lvl)
        return out[:nblocks]

    def data(self, ino):
        ind = self.inode(ino)
        size = struct.unpack_from("<I", ind, 4)[0] | (struct.unpack_from("<I", ind, 0x6C)[0] << 32)
        flags = struct.unpack_from("<I", ind, 0x20)[0]
        iblock = ind[0x28:0x28 + 60]
        if flags & 0x10000000:                      # inline data
            return iblock[:size]
        buf = bytearray(size)
        nblocks = (size + self.block - 1) // self.block
        if flags & 0x80000:                         # extents
            for lblk, pblk, cnt, init in self.extents(iblock):
                for k in range(cnt):
                    lb = lblk + k
                    if lb >= nblocks:
                        break
                    if init:
                        chunk = self.read_at((pblk + k) * self.block, self.block)
                        end = min(self.block, size - lb * self.block)
                        buf[lb * self.block:lb * self.block + end] = chunk[:end]
        else:
            for lb, pb in enumerate(self.blockmap(iblock, nblocks)):
                if pb:
                    chunk = self.read_at(pb * self.block, self.block)
                    end = min(self.block, size - lb * self.block)
                    buf[lb * self.block:lb * self.block + end] = chunk[:end]
        return bytes(buf)

    def listdir(self, ino):
        d = self.data(ino)
        o, out = 0, []
        while o + 8 <= len(d):
            child, rec, nlen = struct.unpack_from("<IHB", d, o)
            if rec < 8:
                break
            if child:
                out.append((d[o + 8:o + 8 + nlen].decode("utf-8", "replace"), child))
            o += rec
        return out

    def lookup(self, path):
        ino = 2
        for part in [p for p in path.split("/") if p]:
            hit = [c for n, c in self.listdir(ino) if n == part]
            if not hit:
                raise FileNotFoundError(path)
            ino = hit[0]
        return ino


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    fs = Ext4(sys.argv[1])
    ino = fs.lookup(sys.argv[2])
    if sys.argv[3] == "--ls":
        for n, c in sorted(fs.listdir(ino)):
            print("%8d  %s" % (c, n))
        return
    with open(sys.argv[3], "wb") as out:
        out.write(fs.data(ino))


if __name__ == "__main__":
    main()
