#!/usr/bin/env python3
"""Minimal FAT32 formatter and reader for the lab disk (WP-18 part 2, ADR-0013 item 7).

Independent of the kernel's implementation on purpose: the kernel reads what this tool wrote,
and after a guest run this tool reads back what the kernel wrote (`verify`), so the two
implementations check each other. Layout per the Microsoft FAT32 specification (S44):
BPB (BytsPerSec 512, RsvdSecCnt 32, NumFATs 2, RootEntCnt 0, FATSz32, RootClus 2, FSInfo 1,
BkBootSec 6), FSInfo sector, two mirrored FATs, data area with the root directory in cluster 2,
8.3 directory entries (no long names).

Commands:
  format IMG --sectors N [--spc 1] [--add NAME=PATH ...] [--mkdir NAME ...] [--pattern-tail K]
  ls IMG [DIR]            list a directory (root by default)
  cat IMG PATH            print a file's bytes to stdout
  verify IMG PATH SHA256  exit 0 when the file exists and its sha256 matches
  check IMG               structural check (signatures, FAT mirrors equal, chains terminate)
  expect IMG PATH TEXT    exit 0 when the file's bytes equal TEXT (\\n escapes allowed)
"""
import argparse
import hashlib
import struct
import sys

SECTOR = 512
RSVD = 32
FATS = 2
ROOT_CLUSTER = 2
EOC = 0x0FFFFFFF
ATTR_DIR = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F


def short_name(name: str) -> bytes:
    """'HELLO.TXT' -> 11-byte padded 8.3 name (uppercase ASCII)."""
    name = name.upper()
    if "." in name:
        base, ext = name.split(".", 1)
    else:
        base, ext = name, ""
    if not (1 <= len(base) <= 8 and len(ext) <= 3) or not all(c.isalnum() or c in "_-" for c in base + ext):
        raise ValueError(f"not an 8.3 name: {name}")
    return (base.ljust(8) + ext.ljust(3)).encode("ascii")


def display_name(raw: bytes) -> str:
    base = raw[:8].decode("ascii", "replace").rstrip()
    ext = raw[8:11].decode("ascii", "replace").rstrip()
    return f"{base}.{ext}" if ext else base


class Image:
    def __init__(self, path, writable=False):
        self.path = path
        self.f = open(path, "r+b" if writable else "rb")
        self.read_bpb()

    def close(self):
        self.f.close()

    # ---- geometry
    def read_bpb(self):
        b = self.read_sector(0)
        (self.bps, self.spc, self.rsvd, self.nfats, self.root_ent, tot16, _media, fatsz16) = struct.unpack_from("<HBHBHHBH", b, 11)
        self.tot32, self.fatsz = struct.unpack_from("<II", b, 32)
        self.root_cluster, self.fsinfo_sector, self.bk_boot = struct.unpack_from("<IHH", b, 44)
        self.boot_sig = b[66]
        self.label = b[71:82].decode("ascii", "replace").rstrip()
        self.fstype = b[82:90].decode("ascii", "replace")
        self.sig = struct.unpack_from("<H", b, 510)[0]
        if self.bps != SECTOR or self.root_ent != 0 or tot16 != 0 or fatsz16 != 0 or self.fatsz == 0:
            raise ValueError("not a FAT32 BPB")
        self.fat_start = self.rsvd
        self.data_start = self.rsvd + self.nfats * self.fatsz
        self.clusters = (self.tot32 - self.data_start) // self.spc

    def read_sector(self, n, count=1):
        self.f.seek(n * SECTOR)
        return self.f.read(SECTOR * count)

    def write_sector(self, n, data):
        assert len(data) % SECTOR == 0
        self.f.seek(n * SECTOR)
        self.f.write(data)

    def cluster_sector(self, c):
        return self.data_start + (c - 2) * self.spc

    def read_cluster(self, c):
        return self.read_sector(self.cluster_sector(c), self.spc)

    def write_cluster(self, c, data):
        data = data.ljust(self.spc * SECTOR, b"\0")
        self.write_sector(self.cluster_sector(c), data)

    # ---- FAT
    def fat_get(self, c, fat=0):
        off = c * 4
        s = self.read_sector(self.fat_start + fat * self.fatsz + off // SECTOR)
        return struct.unpack_from("<I", s, off % SECTOR)[0] & 0x0FFFFFFF

    def fat_set(self, c, v):
        off = c * 4
        for fat in range(self.nfats):
            sec = self.fat_start + fat * self.fatsz + off // SECTOR
            s = bytearray(self.read_sector(sec))
            old = struct.unpack_from("<I", s, off % SECTOR)[0]
            struct.pack_into("<I", s, off % SECTOR, (old & 0xF0000000) | (v & 0x0FFFFFFF))
            self.write_sector(sec, bytes(s))

    def chain(self, first):
        out, c, seen = [], first, set()
        while 2 <= c < 0x0FFFFFF8:
            if c in seen or c >= self.clusters + 2:
                raise ValueError(f"bad chain at {c:#x}")
            seen.add(c)
            out.append(c)
            c = self.fat_get(c)
        return out

    def alloc_cluster(self):
        for c in range(2, self.clusters + 2):
            if self.fat_get(c) == 0:
                self.fat_set(c, EOC)
                self.write_cluster(c, b"")
                return c
        raise RuntimeError("disk full")

    def free_count(self):
        return sum(1 for c in range(2, self.clusters + 2) if self.fat_get(c) == 0)

    # ---- directories
    def dir_entries(self, cluster):
        """Yields (cluster, index, raw32) for every entry of the directory chain."""
        for c in self.chain(cluster):
            data = self.read_cluster(c)
            for i in range(0, len(data), 32):
                yield c, i // 32, data[i:i + 32]

    def lookup(self, dir_cluster, name):
        want = short_name(name)
        for c, i, e in self.dir_entries(dir_cluster):
            if e[0] == 0:
                return None
            if e[0] == 0xE5 or e[11] == ATTR_LFN or e[11] & 0x08:
                continue
            if e[:11] == want:
                return c, i, e
        return None

    def resolve(self, path):
        """Returns (dir_cluster, entry) for PATH or None; '/' is (root, None)."""
        parts = [p for p in path.strip("/").split("/") if p]
        d = self.root_cluster
        entry = None
        for k, part in enumerate(parts):
            hit = self.lookup(d, part)
            if hit is None:
                return None
            _, _, entry = hit
            if k < len(parts) - 1:
                if not entry[11] & ATTR_DIR:
                    return None
                d = self.entry_cluster(entry)
        return d, entry

    @staticmethod
    def entry_cluster(e):
        hi, lo = struct.unpack_from("<H", e, 20)[0], struct.unpack_from("<H", e, 26)[0]
        return (hi << 16) | lo

    def read_file(self, path):
        r = self.resolve(path)
        if r is None or r[1] is None or r[1][11] & ATTR_DIR:
            return None
        e = r[1]
        size = struct.unpack_from("<I", e, 28)[0]
        first = self.entry_cluster(e)
        data = b"".join(self.read_cluster(c) for c in self.chain(first)) if first else b""
        return data[:size]

    def add_entry(self, dir_cluster, raw):
        for c, i, e in self.dir_entries(dir_cluster):
            if e[0] in (0, 0xE5):
                data = bytearray(self.read_cluster(c))
                data[i * 32:(i + 1) * 32] = raw
                self.write_cluster(c, bytes(data))
                return
        # Extend the directory by one cluster.
        last = self.chain(dir_cluster)[-1]
        n = self.alloc_cluster()
        self.fat_set(last, n)
        data = bytearray(self.spc * SECTOR)
        data[0:32] = raw
        self.write_cluster(n, bytes(data))

    def make_entry(self, name, attr, first, size):
        e = bytearray(32)
        e[0:11] = short_name(name)
        e[11] = attr
        struct.pack_into("<H", e, 20, first >> 16)
        struct.pack_into("<H", e, 26, first & 0xFFFF)
        struct.pack_into("<I", e, 28, size)
        return bytes(e)

    def write_file(self, dir_cluster, name, data):
        first = 0
        prev = 0
        per = self.spc * SECTOR
        for off in range(0, len(data), per):
            c = self.alloc_cluster()
            self.write_cluster(c, data[off:off + per])
            if prev:
                self.fat_set(prev, c)
            else:
                first = c
            prev = c
        self.add_entry(dir_cluster, self.make_entry(name, ATTR_ARCHIVE, first, len(data)))

    def make_dir(self, parent_cluster, name):
        c = self.alloc_cluster()
        dot = self.make_entry("A", ATTR_DIR, c, 0)
        dot = b".          " + dot[11:]
        dotdot = self.make_entry("A", ATTR_DIR, 0 if parent_cluster == self.root_cluster else parent_cluster, 0)
        dotdot = b"..         " + dotdot[11:]
        self.write_cluster(c, dot + dotdot)
        self.add_entry(parent_cluster, self.make_entry(name, ATTR_DIR, c, 0))
        return c


def format_image(path, sectors, spc=1, label="NAWAHLAB"):
    fatsz = ((sectors // spc) * 4 + SECTOR - 1) // SECTOR  # generous: entries for every sector/cluster
    with open(path, "wb") as f:
        f.truncate(sectors * SECTOR)
    boot = bytearray(SECTOR)
    boot[0:3] = b"\xEB\x58\x90"
    boot[3:11] = b"NAWAH   "
    struct.pack_into("<HBHBHHBH", boot, 11, SECTOR, spc, RSVD, FATS, 0, 0, 0xF8, 0)
    struct.pack_into("<HHII", boot, 24, 63, 16, 0, sectors)  # SecPerTrk, NumHeads, HiddSec, TotSec32
    struct.pack_into("<IHHIHH", boot, 36, fatsz, 0, 0, ROOT_CLUSTER, 1, 6)  # FATSz32 ExtFlags FSVer RootClus FSInfo BkBootSec
    boot[64] = 0x80
    boot[66] = 0x29
    struct.pack_into("<I", boot, 67, 0x4E415741)
    boot[71:82] = label.ljust(11).encode("ascii")[:11]
    boot[82:90] = b"FAT32   "
    boot[510:512] = b"\x55\xAA"
    fsinfo = bytearray(SECTOR)
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<I", fsinfo, 484, 0x61417272)
    struct.pack_into("<II", fsinfo, 488, 0xFFFFFFFF, 0xFFFFFFFF)
    struct.pack_into("<I", fsinfo, 508, 0xAA550000)
    with open(path, "r+b") as f:
        f.seek(0); f.write(boot); f.write(fsinfo)
        f.seek(6 * SECTOR); f.write(boot)
        f.seek(7 * SECTOR); f.write(fsinfo)
        fat0 = bytearray(SECTOR)
        struct.pack_into("<III", fat0, 0, 0x0FFFFFF8, 0x0FFFFFFF, EOC)  # media, EOC, root cluster
        for k in range(FATS):
            f.seek((RSVD + k * fatsz) * SECTOR); f.write(fat0)
    img = Image(path, writable=True)
    # Root directory: empty but for the volume label entry (ATTR_VOLUME_ID).
    img.write_cluster(ROOT_CLUSTER, label.ljust(11).encode("ascii")[:11] + bytes([0x08]) + bytes(20))
    return img


def finish(img):
    """Writes the advisory FSInfo counters (free clusters, next free hint) in both copies."""
    free = img.free_count()
    nxt = next((c for c in range(2, img.clusters + 2) if img.fat_get(c) == 0), 0xFFFFFFFF)
    for sec in (img.fsinfo_sector, img.bk_boot + 1):
        s = bytearray(img.read_sector(sec))
        struct.pack_into("<II", s, 488, free, nxt)
        img.write_sector(sec, bytes(s))


def cmd_format(a):
    img = format_image(a.image, a.sectors, a.spc)
    for spec in a.mkdir or []:
        img.make_dir(img.root_cluster, spec)
    for spec in a.add or []:
        name, src = spec.split("=", 1)
        with open(src, "rb") as f:
            data = f.read()
        parent = img.root_cluster
        if "/" in name:
            d, name = name.rsplit("/", 1)
            r = img.resolve(d)
            parent = img.entry_cluster(r[1])
        img.write_file(parent, name, data)
    if a.pattern_tail:
        # Raw pattern sectors at the end of the image (outside any allocated cluster) for the
        # block-level tests: byte = (sector * 7 + i) & 0xFF.
        for sector in range(a.sectors - a.pattern_tail, a.sectors):
            img.write_sector(sector, bytes(((sector * 7 + i) & 0xFF) for i in range(SECTOR)))
    finish(img)
    img.close()
    print(f"formatted {a.image}: {a.sectors} sectors, spc={a.spc}, clusters={Image(a.image).clusters}")


def cmd_absent_raw(a):
    """Exit 0 when `text` occurs nowhere in the raw image (every sector, allocated or not): the
    check that a secret the guest handled never reached the disk in the clear (WP-25)."""
    needle = a.text.encode()
    with open(a.image, "rb") as f:
        data = f.read()
    pos = data.find(needle)
    if pos >= 0:
        print(f"{a.image}: {a.text!r} found at offset {pos} (sector {pos // SECTOR})")
        sys.exit(1)
    print(f"{a.image}: {a.text!r} absent from all {len(data) // SECTOR} sectors")


def cmd_grep(a):
    """Exit 0 when TEXT (with \\n escapes) occurs in the file at PATH: a substring check for
    files whose other lines vary, such as a config store's hashed header (WP-26)."""
    data = Image(a.image).read_file(a.path)
    if data is None:
        print(f"grep: {a.path} missing"); return 2
    want = a.text.encode("utf-8").decode("unicode_escape").encode("latin-1")
    if want in data:
        print(f"grep: {a.path} contains {a.text!r}"); return 0
    print(f"grep: {a.path} does not contain {a.text!r}"); return 1


def cmd_ls(a):
    img = Image(a.image)
    d = img.root_cluster
    if a.dir:
        r = img.resolve(a.dir)
        if r is None or r[1] is None:
            print("no such directory"); return 2
        d = img.entry_cluster(r[1])
    for _, _, e in img.dir_entries(d):
        if e[0] == 0:
            break
        if e[0] == 0xE5 or e[11] == ATTR_LFN or e[11] & 0x08:
            continue
        size = struct.unpack_from("<I", e, 28)[0]
        kind = "d" if e[11] & ATTR_DIR else "f"
        print(f"{kind} {display_name(e[:11]):14} size={size} cluster={img.entry_cluster(e)}")
    return 0


def cmd_cat(a):
    data = Image(a.image).read_file(a.path)
    if data is None:
        print("no such file", file=sys.stderr); return 2
    sys.stdout.buffer.write(data)
    return 0


def cmd_verify(a):
    data = Image(a.image).read_file(a.path)
    if data is None:
        print(f"verify: {a.path} missing"); return 1
    digest = hashlib.sha256(data).hexdigest()
    ok = digest == a.sha256 and (a.size is None or len(data) == a.size)
    print(f"verify: {a.path} size={len(data)} sha256={digest} {'OK' if ok else 'MISMATCH'}")
    return 0 if ok else 1


def cmd_expect(a):
    """The file's bytes equal TEXT (with \\n escapes); for host checks after a guest run."""
    data = Image(a.image).read_file(a.path)
    want = a.text.encode("utf-8").decode("unicode_escape").encode("latin-1")
    if data is None:
        print(f"expect: {a.path} missing"); return 1
    ok = data == want
    print(f"expect: {a.path} size={len(data)} {'OK' if ok else 'MISMATCH: ' + repr(data[:80])}")
    return 0 if ok else 1


def cmd_check(a):
    img = Image(a.image)
    problems = []
    if img.sig != 0xAA55 or img.boot_sig != 0x29:
        problems.append("boot signatures")
    if img.read_sector(0) != img.read_sector(img.bk_boot):
        problems.append("backup boot sector differs")
    for s in range(img.fatsz):
        if img.read_sector(img.fat_start + s) != img.read_sector(img.fat_start + img.fatsz + s):
            problems.append(f"FAT mirrors differ at sector {s}"); break
    used = 0
    for c in range(2, img.clusters + 2):
        v = img.fat_get(c)
        if v == 1 or (2 <= v < 0x0FFFFFF7 and v >= img.clusters + 2):
            problems.append(f"FAT[{c}] = {v:#x} invalid"); break
        if v:
            used += 1
    # every file's chain terminates and covers its size
    def walk(d, depth):
        if depth > 8:
            return
        for _, _, e in img.dir_entries(d):
            if e[0] == 0:
                break
            if e[0] == 0xE5 or e[11] == ATTR_LFN or e[11] & 0x08 or e[:1] == b".":
                continue
            first = img.entry_cluster(e)
            size = struct.unpack_from("<I", e, 28)[0]
            try:
                n = len(img.chain(first)) if first else 0
            except ValueError as ex:
                problems.append(str(ex)); continue
            if e[11] & ATTR_DIR:
                walk(first, depth + 1)
            elif n * img.spc * SECTOR < size:
                problems.append(f"{display_name(e[:11])}: chain shorter than size")
    walk(img.root_cluster, 0)
    print(f"check: clusters={img.clusters} used={used} free={img.clusters - used} label={img.label!r} fstype={img.fstype!r} problems={problems}")
    return 0 if not problems else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fat32.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("format"); s.add_argument("image"); s.add_argument("--sectors", type=int, required=True)
    s.add_argument("--spc", type=int, default=1); s.add_argument("--add", action="append"); s.add_argument("--mkdir", action="append")
    s.add_argument("--pattern-tail", type=int, default=0)
    s = sub.add_parser("ls"); s.add_argument("image"); s.add_argument("dir", nargs="?")
    s = sub.add_parser("cat"); s.add_argument("image"); s.add_argument("path")
    s = sub.add_parser("verify"); s.add_argument("image"); s.add_argument("path"); s.add_argument("sha256"); s.add_argument("--size", type=int)
    s = sub.add_parser("check"); s.add_argument("image")
    s = sub.add_parser("expect"); s.add_argument("image"); s.add_argument("path"); s.add_argument("text")
    s = sub.add_parser("absent-raw"); s.add_argument("image"); s.add_argument("text")
    s = sub.add_parser("grep"); s.add_argument("image"); s.add_argument("path"); s.add_argument("text")
    a = ap.parse_args(argv)
    return {"format": cmd_format, "ls": cmd_ls, "cat": cmd_cat, "verify": cmd_verify, "check": cmd_check, "expect": cmd_expect,
            "absent-raw": cmd_absent_raw, "grep": cmd_grep}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
