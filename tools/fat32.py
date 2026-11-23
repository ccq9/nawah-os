#!/usr/bin/env python3
"""Minimal FAT32 formatter and reader for the lab disk (WP-18 part 2, ADR-0013 item 7).

Independent of the kernel's implementation on purpose: the kernel reads what this tool wrote,
and after a guest run this tool reads back what the kernel wrote (`verify`), so the two
implementations check each other. Layout per the Microsoft FAT32 specification (S44):
BPB (BytsPerSec 512, RsvdSecCnt 32, NumFATs 2, RootEntCnt 0, FATSz32, RootClus 2, FSInfo 1,
BkBootSec 6), FSInfo sector, two mirrored FATs, data area with the root directory in cluster 2,
8.3 directory entries (no long names: `check` names as a problem a live entry that carries
one, and any other live entry it passes over that is not the root's one label or a directory's
`.` and `..` in their places).

Commands:
  format IMG --sectors N [--spc 1] [--add NAME=PATH ...] [--mkdir NAME|PARENT/NAME ...] [--pattern-tail K]
  ls IMG [DIR]            list a directory (root by default)
  cat IMG PATH            print a file's bytes to stdout
  verify IMG PATH SHA256  exit 0 when the file exists and its sha256 matches
  check IMG [--faulted [--allow-longer N --expect-longer NAMES --expect-longer-second NAMES]
                       [--expect-lost K --expect-lost-second K --expect-lost-both K]]
                          structural check (signatures, FAT mirrors equal, every chain whole and its own,
                          no lost cluster, free count); --faulted counts what a failed write may leave,
                          with exactly N chains longer than their size and exactly K lost clusters when given;
                          NAMES says which files are longer and by how many clusters (/A.TXT:+1,/B.TXT:+2;
                          - for none); the -second options say the same of the second FAT copy,
                          --expect-lost-both how many clusters are lost in both; the three numbers of the
                          lost clusters come together, --allow-longer with --expect-longer and --expect-longer
                          with --expect-longer-second, or the call is refused (--expect-longer-second alone
                          is taken: the first copy then may hold no longer file)
  fsck-faulted IMG [--allow-longer N]
                          fsck.fat -n with every message named; fails on a failing or unnamed one
  expect IMG PATH TEXT    exit 0 when the file's bytes equal TEXT (\\n escapes allowed)
  derive SRC DST (--remove VOL | --replace VOL=FILE)
                          an isolated copy of SRC at the new path DST with the one file VOL removed or
                          holding FILE's bytes (WP-180); SRC is read only, a DST that exists is refused,
                          and DST names a finished, checked copy or nothing
  diff A B --expect-only VOL (--removed | --replaced-by FILE)
                          exit 0 only when B is A with the one file VOL removed, or holding FILE's
                          bytes, and nothing else: every other entry, the boot sector and the length
                          the same, both sound to `check`
"""
import argparse
import collections
import hashlib
import itertools
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

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
    if not name.isascii():
        raise ValueError(f"not an 8.3 name: {name}")
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
        """`path` names the image, or is an open file that holds it: the caller's, never closed here."""
        self.path = path
        self.own = not hasattr(path, "read")
        self.f = open(path, "r+b" if writable else "rb") if self.own else path
        self.read_bpb()

    def close(self):
        if self.own:
            self.f.close()

    # ---- geometry
    def read_bpb(self):
        b = self.read_sector(0)
        if len(b) < SECTOR or b[13] == 0:
            raise ValueError("not a FAT32 BPB")
        (self.bps, self.spc, self.rsvd, self.nfats, self.root_ent, tot16, _media, fatsz16) = struct.unpack_from("<HBHBHHBH", b, 11)
        self.tot32, self.fatsz = struct.unpack_from("<II", b, 32)
        self.root_cluster, self.fsinfo_sector, self.bk_boot = struct.unpack_from("<IHH", b, 44)
        self.boot_sig = b[66]
        self.label = b[71:82].decode("ascii", "replace").rstrip()
        self.label_raw = bytes(b[71:82])
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

    def store(self, data):
        """Writes `data` into free clusters, lowest first, and returns the first (0 for no
        byte). The clusters are found in one pass before any is written: a volume that cannot
        hold the data is left as it was."""
        per = self.spc * SECTOR
        need = (len(data) + per - 1) // per
        free = list(itertools.islice((c for c in range(2, self.clusters + 2) if self.fat_get(c) == 0), need))
        if len(free) < need:
            raise RuntimeError("disk full")
        for k, c in enumerate(free):
            self.write_cluster(c, data[k * per:(k + 1) * per])
            self.fat_set(c, free[k + 1] if k + 1 < need else EOC)
        return free[0] if free else 0

    def free_chain(self, first):
        """Frees the chain in every FAT copy and zeroes its clusters: nothing of the file stays."""
        for c in self.chain(first) if first else []:
            self.write_cluster(c, b"")
            self.fat_set(c, 0)

    def set_entry(self, cluster, index, raw):
        data = bytearray(self.read_cluster(cluster))
        data[index * 32:(index + 1) * 32] = raw
        self.write_cluster(cluster, bytes(data))

    def locate(self, path):
        """(directory cluster, index, raw entry) of what PATH names, or None; '/' names no entry."""
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            return None
        d = self.root_cluster
        try:
            if parts[:-1]:
                r = self.resolve("/".join(parts[:-1]))
                if r is None or not r[1][11] & ATTR_DIR:
                    return None
                d = self.entry_cluster(r[1])
            return self.lookup(d, parts[-1])
        except ValueError:
            return None

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
        # Nested directories (WP-35: SYSTEM/FONTS) are made inside an existing parent.
        parent = img.root_cluster
        if "/" in spec:
            d, spec = spec.rsplit("/", 1)
            r = img.resolve(d)
            if r is None or r[1] is None:
                raise SystemExit(f"mkdir: parent {d} missing")
            parent = img.entry_cluster(r[1])
        img.make_dir(parent, spec)
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


# A path of the kernel's PATH_MAX (256 bytes) names at most 127 levels of directories, so no
# tree the kernel can name is cut here. A loop of directories cannot run the walk away: a
# cluster reached twice is a finding and ends that chain.
DEPTH_MAX = 128


def tree_findings(img, fat):
    """One walk of the whole tree along FAT copy `fat`, recording which name reaches each
    cluster. Returns (strict, longer, owned, complete, reached). `strict` holds what no state of the
    volume may show: a chain that runs into a free cluster, leaves the volume or loops, two names
    on one cluster, a file whose chain is shorter than its size, an entry whose first cluster
    is no cluster of the volume (0 belongs to a file that holds none and to no directory), and
    a chain that reaches the reserved value 1, and an entry the walk passes over in another
    form than the one that holds nothing of its own: a long-name entry (attribute 0x0F under
    the mask 0x3F), which this tool and the kernel do not read; an entry that carries the
    volume bit and is not the root's one label (no directory, no cluster, no size, the name
    the boot sector gives the volume); a name
    that begins with a dot and is not a directory's `.` in its first slot on the directory
    itself or its `..` in the second on the directory above (the root has neither). What is
    passed over is not claimed, so on a live file's chain it would be an owner no finding
    names; a deleted entry is passed over whatever it holds. `longer` names the files
    whose chain holds more clusters than their size needs, each with the number of clusters it
    has too many; `owned` is every cluster a name reaches; `reached` is every name the walk met
    (the last element returned); `complete` is false when the walk stopped at its depth limit, so `owned` is not
    the whole tree."""
    owner, strict, longer, cut, reached = {}, [], [], [], set()
    cluster_bytes = img.spc * SECTOR

    def claim(name, first):
        # `seen` answers "is this cluster in the chain already" without reading the chain again:
        # the cost of a walk grows with the chain's length, not with its square.
        got, seen, c = [], set(), first
        while 2 <= c < 0x0FFFFFF8:
            if c >= img.clusters + 2 or c in seen:
                strict.append(f"{name}: bad chain at {c:#x}")
                break
            if c in owner:
                strict.append(f"{name} and {owner[c]} share cluster {c}")
                break
            v = img.fat_get(c, fat)
            if v == 0:
                strict.append(f"{name}: cluster {c} of its chain is free")
                break
            owner[c] = name
            got.append(c)
            seen.add(c)
            c = v
        if c == 1 and got:
            # 1 is no cluster and no end mark: a chain that reaches it did not end.
            strict.append(f"{name}: its chain holds the reserved value 1")
        return got

    def walk(path, first, depth, parent=None):
        # `parent` is what the directory's `..` must hold: nothing for the root, 0 for a
        # directory of the root, the first cluster of the directory above for any other.
        clusters = claim(path or "/", first)
        names, long_named, dotted, volumed, labelled, slot = set(), False, False, False, False, -1
        if depth > DEPTH_MAX:
            strict.append(f"{path}: deeper than this check walks")
            cut.append(path)
            return
        for c in clusters:
            data = img.read_cluster(c)
            for i in range(0, len(data), 32):
                e = data[i:i + 32]
                slot += 1
                if e[0] == 0:
                    return
                if e[0] == 0xE5:
                    continue
                if (e[11] & 0x3F) == ATTR_LFN:
                    # A long name. This tool and the kernel read 8.3 names alone, so a reader of
                    # long names meets another tree on such a volume than they do: a long name
                    # may give one file the name of another, or of one that was removed. The
                    # two bits above the mask do not make the entry anything else.
                    if not long_named:
                        strict.append(f"{path or '/'}: a long-name entry, which no reader of 8.3 names sees")
                    long_named = True
                    continue
                # What is passed over below is not read and its clusters are not claimed, so each
                # kind is passed over in the one form that holds nothing of its own; any other
                # entry of the kind is a problem (on a live file's chain, a checker that reads it
                # as a file calls the clusters shared, and a reader that lists it shows a file).
                if e[11] & 0x08:
                    # The volume's label: one, in the root, no directory, no cluster, no size, and
                    # under the name the boot sector gives the volume (which `diff` compares).
                    if parent is None and not labelled and not e[11] & ATTR_DIR and e[:11] == img.label_raw and img.entry_cluster(e) == 0 and e[28:32] == bytes(4):
                        labelled = True
                    else:
                        if not volumed:
                            strict.append(f"{path or '/'}: an entry that carries the volume bit and is not the root's one label")
                        volumed = True
                    continue
                if e[:1] == b".":
                    # A directory's two: `.` in its first slot on the directory itself, `..` in the
                    # second on the directory above. The root has neither, and no other name
                    # begins with a dot: the kernel passes over one, another reader lists it.
                    own = (e[:11] == b".          " and slot == 0 and img.entry_cluster(e) == first
                           or e[:11] == b"..         " and slot == 1 and img.entry_cluster(e) == parent)
                    if not (parent is not None and e[11] & ATTR_DIR and own):
                        if not dotted:
                            strict.append(f"{path or '/'}: a name that begins with a dot and is not one of a directory's two in their places")
                        dotted = True
                    continue
                name = f"{path}/{display_name(e[:11])}"
                reached.add(name)
                # Two entries with one name in a directory: a reader opens the first it meets,
                # and a list of names would show one.
                if e[:11] in names:
                    strict.append(f"{name}: a second entry of this name in its directory")
                names.add(e[:11])
                entry_first = img.entry_cluster(e)
                # No name starts at a number that is no cluster of the volume. 0 is the first
                # cluster of a file that holds none (its size says whether that is right) and
                # of no directory.
                if not 2 <= entry_first < img.clusters + 2 and (entry_first != 0 or e[11] & ATTR_DIR):
                    strict.append(f"{name}: first cluster {entry_first}, no cluster of the volume")
                    continue
                if e[11] & ATTR_DIR:
                    walk(name, entry_first, depth + 1, 0 if parent is None else first)
                    continue
                size = struct.unpack_from("<I", e, 28)[0]
                n = len(claim(name, entry_first)) if entry_first else 0
                if n * cluster_bytes < size:
                    strict.append(f"{name}: chain shorter than size")
                elif n > (size + cluster_bytes - 1) // cluster_bytes:
                    longer.append((name, n - (size + cluster_bytes - 1) // cluster_bytes))

    walk("", img.root_cluster, 0)
    return strict, longer, set(owner), not cut, reached


def cmd_check(a):
    """The image is consistent. With --faulted (after a guest case that made a disk write fail):
    what a safe order of writes may leave behind (lost clusters, FAT copies that differ, a stale
    free count) is counted on the output line instead of being a problem. In both modes the tree
    is walked along every FAT copy, so a name that reaches a free cluster, shares one, starts at
    no cluster or runs into a reserved value is a problem whichever copy shows it, and every
    copy is scanned for reserved and out-of-range values. A chain longer than its size stays a
    problem unless the case says
    with --allow-longer N how many its failures leave (a failed delete or truncation leaves
    none; a failed write may) and with --expect-longer NAMES which files and by how many
    clusters each: any other number, file or length is a problem. --expect-lost K does the same
    for the number of lost clusters. Both are counted along the second FAT copy too:
    --expect-longer-second and --expect-lost-second pin them, --expect-lost-both pins how many
    clusters are lost in both copies (so a cluster marked in one copy alone cannot stand for
    one marked in the other alone). The three numbers of the lost clusters are given together,
    --allow-longer with --expect-longer and --expect-longer with --expect-longer-second, or the
    call is refused (exit 2); --expect-longer-second alone is taken and leaves the first copy
    judged as without it: any file longer than its size there is a problem. A name the walk
    reaches along one copy and not along another is a problem in both modes. So is every entry
    the walk passes over without reading, but the three that hold nothing of their own: the
    root's one label, and a directory's `.` and `..` in their places. A long-name entry,
    another entry under the volume bit, another name that begins with a dot: neither this
    walk, nor `diff`'s, nor the kernel's code reads one (`ls` here lists a name that begins
    with a dot and no command opens it), and a volume that holds one shows another reader,
    or a checker that reads it as a file, another tree than theirs."""
    img = Image(a.image)
    try:
        return check_image(img, a)
    finally:
        img.close()


def check_image(img, a):
    """`check` of an image that is open: its line printed, 0 when it holds no problem."""
    faulted = getattr(a, "faulted", False)
    allow_longer = getattr(a, "allow_longer", None) if faulted else None
    expect_lost = getattr(a, "expect_lost", None) if faulted else None
    expect_longer = getattr(a, "expect_longer", None) if faulted else None
    expect_longer_second = getattr(a, "expect_longer_second", None) if faulted else None
    expect_lost_second = getattr(a, "expect_lost_second", None) if faulted else None
    expect_lost_both = getattr(a, "expect_lost_both", None) if faulted else None
    lost_pins = (expect_lost, expect_lost_second, expect_lost_both)
    if (any(pin is not None for pin in lost_pins) and any(pin is None for pin in lost_pins)) \
            or (allow_longer is not None and expect_longer is None) or (expect_longer is not None and expect_longer_second is None):
        print("check: a pin on one FAT copy needs the other's: --expect-lost, --expect-lost-second and --expect-lost-both "
              "together, --allow-longer with --expect-longer, --expect-longer with --expect-longer-second", file=sys.stderr)
        return 2

    # The longer files are compared as lists, one item a file: a name is never split or joined.
    def names(found):
        return sorted(f"{name}:+{extra}" for name, extra in found)

    def wanted(text):
        return sorted(text.split(",")) if text != "-" else []

    def shown(found):
        return ",".join(names(found)) or "-"
    problems = []
    if img.nfats < 2 and any(pin is not None for pin in (expect_longer_second, expect_lost_second, expect_lost_both)):
        problems.append("no second FAT copy: nothing meets a pin on it")
    if img.sig != 0xAA55 or img.boot_sig != 0x29:
        problems.append("boot signatures")
    if img.read_sector(0) != img.read_sector(img.bk_boot):
        problems.append("backup boot sector differs")
    differing = [s for s in range(img.fatsz)
                 if img.read_sector(img.fat_start + s) != img.read_sector(img.fat_start + img.fatsz + s)]
    if differing and not faulted:
        problems.append(f"FAT mirrors differ at sector {differing[0]}")
    used, in_use = 0, set()
    for c in range(2, img.clusters + 2):
        v = img.fat_get(c)
        if v == 1 or (2 <= v < 0x0FFFFFF7 and v >= img.clusters + 2):
            problems.append(f"FAT[{c}] = {v:#x} invalid"); break
        if v:
            used += 1
            if v != 0x0FFFFFF7:
                in_use.add(c)
    # The same scan over every other copy: a reserved or out-of-range value is no state a
    # refused write leaves, in whichever copy it sits.
    in_use_other = {fat: set() for fat in range(1, img.nfats)}
    for fat in range(1, img.nfats):
        for c in range(2, img.clusters + 2):
            v = img.fat_get(c, fat)
            if v == 1 or (2 <= v < 0x0FFFFFF7 and v >= img.clusters + 2):
                problems.append(f"FAT{fat}[{c}] = {v:#x} invalid"); break
            if v and v != 0x0FFFFFF7:
                in_use_other[fat].add(c)
    strict, longer, owned, complete, reached = tree_findings(img, 0)
    problems += strict
    # What the walk did not visit is not called lost.
    lost_set = (in_use - owned) if complete else set()
    # Every other copy is walked too, with and without --faulted: what a name reaches along it
    # must be as sound as along the first, and a finding there carries the name. Its longer
    # chains and its lost clusters are counted like the first copy's.
    second = ""
    for fat in range(1, img.nfats):
        strict_o, longer_o, owned_o, complete_o, reached_o = tree_findings(img, fat)
        problems += [f"FAT{fat}: {p}" for p in strict_o]
        # The two walks read the same directories unless a directory's chain differs between
        # the copies: a name one of them reaches and the other does not is named.
        problems += [f"FAT{fat}: {name} is reached along this copy only" for name in sorted(reached_o - reached)]
        problems += [f"FAT{fat}: {name} is not reached along this copy" for name in sorted(reached - reached_o)]
        lost_set_o = (in_use_other[fat] - owned_o) if complete_o else set()
        lost_o, lost_both = len(lost_set_o), len(lost_set & lost_set_o)
        if expect_longer_second is None:
            problems += [f"FAT{fat}: {name}: chain longer than size" for name, _ in longer_o]
        elif names(longer_o) != wanted(expect_longer_second):
            problems.append(f"FAT{fat}: chains longer than size: {shown(longer_o)} where {expect_longer_second} are expected")
        if expect_lost_second is not None and lost_o != expect_lost_second:
            problems.append(f"FAT{fat}: lost clusters: {lost_o} where {expect_lost_second} are expected")
        if expect_lost_both is not None and lost_both != expect_lost_both:
            problems.append(f"FAT{fat}: lost clusters in both copies: {lost_both} where {expect_lost_both} are expected")
        second += f" second: lost={lost_o} lost_both={lost_both} longer_files={shown(longer_o)}"
    lost = len(lost_set)
    info = img.read_sector(img.fsinfo_sector)
    signed = [struct.unpack_from("<I", info, off)[0] for off in (0, 484, 508)] == [0x41615252, 0x61417272, 0xAA550000]
    if not signed:
        # The three signatures the kernel asks for before it trusts the count. A refused write
        # does not break them; a torn sector could, and is not covered by any case.
        problems.append("FSInfo signatures")
    recorded = struct.unpack_from("<I", info, 488)[0] if signed else 0xFFFFFFFF
    real_free = img.clusters - used
    fsinfo = "unknown" if recorded == 0xFFFFFFFF else ("ok" if recorded == real_free else "stale")
    if allow_longer is None and expect_longer is None:
        problems += [f"{name}: chain longer than size" for name, _ in longer]
    else:
        if allow_longer is not None and len(longer) != allow_longer:
            problems.append(f"chains longer than size: {len(longer)} where {allow_longer} are expected: {shown(longer)}")
        if expect_longer is not None and names(longer) != wanted(expect_longer):
            problems.append(f"chains longer than size: {shown(longer)} where {expect_longer} are expected")
    if expect_lost is not None and lost != expect_lost:
        problems.append(f"lost clusters: {lost} where {expect_lost} are expected")
    if not faulted:
        if lost:
            problems.append(f"lost clusters: {lost}")
        if fsinfo == "stale":
            problems.append(f"FSInfo free count {recorded}, really {real_free}")
    tail = (f" faulted: lost={lost} longer={len(longer)} mirror_diff={len(differing)} fsinfo={fsinfo}"
            f" longer_files={shown(longer)}{second}") if faulted else ""
    print(f"check: clusters={img.clusters} used={used} free={real_free} label={img.label!r} fstype={img.fstype!r} problems={problems}{tail}")
    return 0 if not problems else 1


def cmd_derive(a):
    """An isolated copy of the volume SRC at the new path DST, with the one file VOL removed
    (--remove VOL) or holding the bytes of the host file FILE (--replace VOL=FILE). SRC is
    opened once, for reading. The copy is made in a working file beside DST that has a name
    of its own, .derive-* (made by mkstemp and never opened again by that name), checked as
    it was copied, changed, checked again, synced, and only then given the name DST by a hard
    link, which no existing path takes: a file, a link to SRC, a link to nowhere. So a call
    that is refused, that fails before the link, or whose process ends before it, puts
    nothing under DST; and what the link names is the finished and checked copy, but for the
    one failure after the link that is told below. This is no promise against a
    loss of power or a crash of the host: the directory is not synced, so after one the name
    DST may be missing, or the copy may stand under both names. A removed file's entry is
    cleared to the deleted mark and its
    clusters are freed in every FAT copy and zeroed; a replaced file's entry stays in its place
    with its name, attributes and times, and takes the new size and chain. Refused, exit 2: a
    DST that exists or has no directory, a SRC that is no file or fails `check`, a VOL that is
    missing or a directory, a FILE that is no file or holds VOL's own bytes. Exit 1, no DST:
    the volume cannot hold FILE, or the changed copy fails `check`. Exit 1 with DST left as it
    is: what DST names after the link is not the working file. Either the working name was
    given to another file before the link (DST and the working name are then two names of that
    other file, and neither is removed here), or DST was given to another file after it (the
    working name is then removed, and the copy with it); a DST removed after the link ends the
    call in a traceback, the copy removed the same way. A call killed by a signal other than an interrupt leaves the
    working file; so killed between the link and the working name's removal, it leaves the
    finished copy under two names, which `diff` refuses. An interrupt after the link and
    before the clean-up begins ends the call with the interrupt's own failure and leaves the
    finished copy under DST alone, the working name removed; one that falls inside the
    clean-up, before the working name is removed, leaves the two names."""
    vol, _, host = (a.remove, "", None) if a.remove is not None else a.replace.partition("=")
    data = None
    if host is not None:
        if not os.path.isfile(host):
            print(f"derive: refused: {host!r} is no file to replace {vol} with (--replace VOL=FILE)")
            return 2
        with open(host, "rb") as f:
            data = f.read()
    if not os.path.isfile(a.src):
        print(f"derive: refused: the source {a.src} is no file")
        return 2
    try:
        fd, part = tempfile.mkstemp(prefix=".derive-", dir=os.path.dirname(a.dst) or ".")
    except OSError as err:
        print(f"derive: refused: no working file beside the destination {a.dst}: {err}")
        return 2
    with os.fdopen(fd, "r+b") as out:
        try:
            return derive_into(out, part, a, vol, data)
        finally:
            # The working name goes, if it still names the working file.
            try:
                if os.path.samestat(os.lstat(part), os.fstat(out.fileno())):
                    os.unlink(part)
            except OSError:
                pass


def derive_into(out, part, a, vol, data):
    """The body of `derive` on the open working file `out`, whose name is `part`."""
    digest = hashlib.sha256()
    with open(a.src, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
            out.write(block)
    try:
        img = Image(out)
        before = check_image(img, argparse.Namespace())
    except (ValueError, struct.error) as err:
        print(f"derive: refused: the source {a.src} is no FAT32 volume: {err}")
        return 2
    if before != 0:
        print(f"derive: refused: the source {a.src} fails the check")
        return 2
    hit = img.locate(vol)
    if hit is None or hit[2][11] & ATTR_DIR:
        print(f"derive: refused: {vol} is no file of {a.src}")
        return 2
    c, i, e = hit
    old = img.read_file(vol)
    if data is not None and data == old:
        print(f"derive: refused: the replacement holds the very bytes of {vol}: the copy would be the source")
        return 2
    try:
        img.free_chain(img.entry_cluster(e))
        if data is None:
            img.set_entry(c, i, b"\xE5" + bytes(31))
        else:
            first = img.store(data)
            e = bytearray(e)
            struct.pack_into("<H", e, 20, first >> 16)
            struct.pack_into("<H", e, 26, first & 0xFFFF)
            struct.pack_into("<I", e, 28, len(data))
            img.set_entry(c, i, bytes(e))
        finish(img)
    except RuntimeError as err:
        print(f"derive: {err}: no copy is left")
        return 1
    after = check_image(img, argparse.Namespace())
    if after != 0:
        print("derive: the copy fails the check: no copy is left")
        return 1
    out.flush()
    os.fsync(out.fileno())
    os.fchmod(out.fileno(), 0o644)
    out.seek(0)
    copy = hashlib.sha256()
    for block in iter(lambda: out.read(1 << 20), b""):
        copy.update(block)
    try:
        os.link(part, a.dst, follow_symlinks=False)
    except OSError as err:
        print(f"derive: refused: the destination {a.dst} exists or cannot be named: {err}")
        return 2
    if not os.path.samestat(os.lstat(a.dst), os.fstat(out.fileno())):
        print(f"derive: the destination is not the copy that was made: {a.dst} is left as it is and is not to be used")
        return 1
    was = f"size={len(old)} sha256={hashlib.sha256(old).hexdigest()}"
    now = "removed" if data is None else f"replaced by size={len(data)} sha256={hashlib.sha256(data).hexdigest()}"
    print(f"derive: source sha256={digest.hexdigest()} copy sha256={copy.hexdigest()} {vol} was {was}, {now}")
    return 0


def tree_list(img):
    """(entries, stray). `entries` holds every entry of the tree as one item of a list: (path as
    it reads, the raw names of the path, kind, the attributes and times, size, sha256 of the
    bytes). A list, never a mapping by name: two entries with one name stay two items, and a
    name is known by its eleven raw bytes, as a reader of the volume compares it, not by how it
    reads. `stray` names the directories that hold a byte in or after their end mark: no
    reader meets what lies there until the next entry made in that directory uncovers it."""
    out, stray = [], []

    def walk(path, raw, first, depth):
        if depth > DEPTH_MAX:
            raise ValueError(f"{path}: deeper than this walk goes")
        ended = False
        for _, _, e in img.dir_entries(first):
            if ended or e[0] == 0:
                if any(e) and (path or "/") not in stray:
                    stray.append(path or "/")
                ended = True
                continue
            if e[0] == 0xE5 or e[11] == ATTR_LFN or e[11] & 0x08 or e[:1] == b".":
                continue
            name, key = f"{path}/{display_name(e[:11])}", f"{raw}/{e[:11].hex()}"
            meta = (e[11:20] + e[22:26]).hex()
            if e[11] & ATTR_DIR:
                out.append((name, key, "dir", meta, 0, ""))
                walk(name, key, img.entry_cluster(e), depth + 1)
                continue
            size = struct.unpack_from("<I", e, 28)[0]
            start = img.entry_cluster(e)
            data = (b"".join(img.read_cluster(c) for c in img.chain(start)) if start else b"")[:size]
            out.append((name, key, "file", meta, size, hashlib.sha256(data).hexdigest()))

    walk("", "", img.root_cluster, 0)
    return out, stray


def named_change(vol, in_a, in_b, want, shown):
    """What stands against "B is A with the file VOL removed (want None) or holding the bytes
    `want` names", told from the entries of that name on each; None when nothing does."""
    if len(in_a) != 1 or in_a[0][2] != "file":
        return f"A holds {len(in_a)} entries of {vol}, not one file: {shown(in_a)}"
    if want is None:
        return f"B holds {len(in_b)} entries of {vol} where it was to be removed: {shown(in_b)}" if in_b else None
    if len(in_b) != 1 or in_b[0][2] != "file":
        return f"B holds {len(in_b)} entries of {vol}, not one file: {shown(in_b)}"
    if in_b[0][4:] == in_a[0][4:]:
        return f"nothing differs: B holds A's bytes of {vol}"
    if in_b[0][4:] != want:
        return f"B's {vol} is not the replacement (size={want[0]} sha256={want[1]}): {shown(in_b)}"
    if in_b[0][3] != in_a[0][3]:
        return f"B's {vol} has other attributes or times than A's: {shown(in_b)} where A has {shown(in_a)}"
    return None


def cmd_diff(a):
    """Exit 0 only when the volume B is the volume A with the one file VOL (--expect-only VOL)
    removed (--removed) or holding the bytes of the host file FILE (--replaced-by FILE), and
    nothing else: A holds VOL as one file; B holds no entry of that name, or one file of FILE's
    size and bytes under the attributes and times it has on A, and other bytes than on A;
    every other entry is the same on both (path by raw name, kind, attributes, times, size and
    bytes), compared as whole entries, never merged by name, and lying in the same order, the
    replaced file's entry where the file's was; B has the free clusters A has, more or fewer by
    what the change frees and takes; both images have one length, one boot sector and one name
    each, both pass `check` (so neither holds a live entry this judge passes over and another
    reader would show: a long name, an entry under the volume bit other than the root's one
    label, a name that begins with a dot other than a directory's two in their places), and
    no directory of either holds a byte after its end mark. Its
    line names both images by their sha256 (read before the judging, in a read of its own). Not compared, and not what a reader of files meets
    but for the first: which clusters a file sits on, the bytes of free clusters and those
    past a file's size in its last cluster, deleted entries, the times of the volume's label
    entry and of the `.` and `..` entries (what `check` asks of the three is their place, that
    they hold nothing, and of the label the name the boot sector gives), FSInfo and the other
    reserved sectors. Exit 1 with what was found
    otherwise; 2 when an image or FILE cannot be read or VOL is no path of 8.3 names."""
    try:
        names = [short_name(p) for p in a.expect_only.strip("/").split("/")]
        vol, vol_key = "".join("/" + display_name(n) for n in names), "".join("/" + n.hex() for n in names)
        want = None
        if a.replaced_by is not None:
            with open(a.replaced_by, "rb") as f:
                data = f.read()
            want = (len(data), hashlib.sha256(data).hexdigest())
        lengths, boots, lists, frees, per, digests, findings = [], [], [], [], [], [], []
        for side, path in (("A", a.a), ("B", a.b)):
            with open(path, "rb") as f:
                digest = hashlib.sha256()
                for block in iter(lambda: f.read(1 << 20), b""):
                    digest.update(block)
                digests.append(digest.hexdigest())
                img = Image(f)
                lengths.append(os.fstat(f.fileno()).st_size)
                if os.fstat(f.fileno()).st_nlink != 1:
                    findings.append(f"{side} has {os.fstat(f.fileno()).st_nlink} names")
                boots.append(img.read_sector(0))
                frees.append(img.free_count())
                per.append(img.spc * SECTOR)
                if check_image(img, argparse.Namespace()) != 0:
                    findings.append(f"{side} fails the check")
                entries, stray = tree_list(img)
                lists.append(entries)
                findings += [f"bytes after the end mark of {d} on {side}" for d in stray]
    except (OSError, ValueError, struct.error) as err:
        print(f"diff: {err}")
        return 2
    if lengths[0] != lengths[1]:
        findings.append("the images differ in length")
    if boots[0] != boots[1]:
        findings.append("the boot sectors differ")
    count_a, count_b = collections.Counter(lists[0]), collections.Counter(lists[1])
    differ = sorted({item[0] + ("/" if item[2] == "dir" else "") for item in (count_a - count_b) + (count_b - count_a) if item[1] != vol_key})
    in_a, in_b = ([item for item in items if item[1] == vol_key] for items in lists)

    def shown(items):
        return ", ".join(f"{item[2]} size={item[4]} sha256={item[5]} attrs={item[3]}" for item in items) or "absent"
    wrong = named_change(vol, in_a, in_b, want, shown)
    if wrong:
        findings.append(wrong)
    elif not differ and boots[0] == boots[1]:
        # With every entry accounted for on volumes of one geometry: their order, and the room the change leaves.
        if [item[1] for item in lists[0] if want is not None or item[1] != vol_key] != [item[1] for item in lists[1]]:
            findings.append("the entries lie in another order")
        left = frees[0] + -(-in_a[0][4] // per[0]) - (-(-want[0] // per[0]) if want else 0)
        if frees[1] != left:
            findings.append(f"B has {frees[1]} free clusters where the change leaves {left}")
    if findings or differ:
        print(f"diff: not only {vol}: findings={findings} differ={differ}")
        return 1
    print(f"diff: only {vol} differs: A {shown(in_a)} | B {shown(in_b)}; images A sha256={digests[0]} B sha256={digests[1]}")
    return 0


# fsck.fat -n (dosfstools 4.2) says one message a line; a message about a file follows a line
# with its path. After a guest case that made a disk write fail its exit code alone is no
# verdict (a lost cluster already makes it 1), so every message is named here: lines that carry
# no finding, findings a safe order of writes may leave, and findings that fail the case. A
# line that matches none of them is unnamed and fails the case too.
FSCK_NEUTRAL = [
    r"fsck\.fat \d+\.\d+.*", r"Warning: Filesystem is FAT32 according to fat_length and fat32_length fields,",
    r"\s+but has only \d+ clusters, less than the required minimum of \d+\.", r"\s+This may lead to problems on some systems\.",
    r"Leaving filesystem unchanged\.", r".+: \d+ files, \d+/\d+ clusters", r"\s*", r"/\S*(  and)?",
    r"\s+Auto-correcting\.", r"\s+Using first FAT\.", r"\s+Truncating file to \d+ bytes\.", r"\s+Truncating second to 0 bytes\.",
]
FSCK_ALLOWED = {
    "lost": r"Reclaimed \d+ unused clusters? \(\d+ bytes\)\.",
    "free_count": r"Free cluster summary wrong \(\d+ vs\. really \d+\)",
    "mirror": r"FATs differ but appear to be intact\.",
    "longer": r"\s+File size is \d+ bytes, cluster chain length is > \d+ bytes\.",
}
FSCK_FAILING = {
    "shared": r"\s+share clusters\.",
    "free_in_chain": r"\s+Contains a free cluster \(\d+\)\. Assuming EOF\.",
    "shorter": r"\s+File size is \d+ bytes, cluster chain length is \d+ bytes\.",
}


def classify_fsck(text, allow_longer=None):
    """Returns (allowed, failing, unnamed) for the output of `fsck.fat -n`: how many lines
    carried each allowed finding, the failing findings (each once, in order of appearance, a
    wrong number of longer chains last), and the lines no pattern names. Chains longer than
    their size are allowed only in the exact number the case gives (`allow_longer`); any other
    number, none included, fails."""
    allowed, failing, unnamed = {}, [], []
    longer = 0
    for line in text.splitlines():
        hit = next((k for k, pat in FSCK_FAILING.items() if re.fullmatch(pat, line)), None)
        if hit:
            if hit not in failing:
                failing.append(hit)
            continue
        hit = next((k for k, pat in FSCK_ALLOWED.items() if re.fullmatch(pat, line)), None)
        if hit == "longer":
            longer += 1
        elif hit:
            allowed[hit] = allowed.get(hit, 0) + 1
        elif not any(re.fullmatch(pat, line) for pat in FSCK_NEUTRAL):
            unnamed.append(line.strip())
    if longer != (allow_longer or 0):
        failing.append("longer")
    elif longer:
        allowed["longer"] = longer
    return allowed, failing, unnamed


def cmd_fsck_faulted(a):
    """fsck.fat -n on an image a guest case left after a failed disk write: its whole output is
    printed (the lab keeps it in host-check.log), then one line with its exit code and the
    named findings; 0 only when nothing failing and nothing unnamed was said."""
    fsck = shutil.which("fsck.fat")
    if not fsck:
        print("fsck-faulted: fsck.fat is not installed")
        return 3
    r = subprocess.run([fsck, "-n", a.image], capture_output=True, text=True)
    out = r.stdout + r.stderr
    sys.stdout.write(out)
    allowed, failing, unnamed = classify_fsck(out, a.allow_longer)
    print(f"fsck: exit={r.returncode} allowed={allowed} failing={failing} unnamed={unnamed}")
    return 0 if r.returncode in (0, 1) and not failing and not unnamed else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fat32.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("format"); s.add_argument("image"); s.add_argument("--sectors", type=int, required=True)
    s.add_argument("--spc", type=int, default=1); s.add_argument("--add", action="append"); s.add_argument("--mkdir", action="append")
    s.add_argument("--pattern-tail", type=int, default=0)
    s = sub.add_parser("ls"); s.add_argument("image"); s.add_argument("dir", nargs="?")
    s = sub.add_parser("cat"); s.add_argument("image"); s.add_argument("path")
    s = sub.add_parser("verify"); s.add_argument("image"); s.add_argument("path"); s.add_argument("sha256"); s.add_argument("--size", type=int)
    s = sub.add_parser("check"); s.add_argument("image"); s.add_argument("--faulted", action="store_true")
    s.add_argument("--allow-longer", type=int, metavar="N"); s.add_argument("--expect-lost", type=int, metavar="K")
    s.add_argument("--expect-longer", metavar="NAMES"); s.add_argument("--expect-longer-second", metavar="NAMES")
    s.add_argument("--expect-lost-second", type=int, metavar="K"); s.add_argument("--expect-lost-both", type=int, metavar="K")
    s = sub.add_parser("fsck-faulted"); s.add_argument("image"); s.add_argument("--allow-longer", type=int, metavar="N")
    s = sub.add_parser("expect"); s.add_argument("image"); s.add_argument("path"); s.add_argument("text")
    s = sub.add_parser("absent-raw"); s.add_argument("image"); s.add_argument("text")
    s = sub.add_parser("grep"); s.add_argument("image"); s.add_argument("path"); s.add_argument("text")
    s = sub.add_parser("derive"); s.add_argument("src"); s.add_argument("dst")
    how = s.add_mutually_exclusive_group(required=True)
    how.add_argument("--remove", metavar="VOL"); how.add_argument("--replace", metavar="VOL=FILE")
    s = sub.add_parser("diff"); s.add_argument("a"); s.add_argument("b"); s.add_argument("--expect-only", required=True, metavar="VOL")
    how = s.add_mutually_exclusive_group(required=True)
    how.add_argument("--removed", action="store_true"); how.add_argument("--replaced-by", metavar="FILE")
    a = ap.parse_args(argv)
    return {"format": cmd_format, "ls": cmd_ls, "cat": cmd_cat, "verify": cmd_verify, "check": cmd_check, "fsck-faulted": cmd_fsck_faulted, "expect": cmd_expect,
            "absent-raw": cmd_absent_raw, "grep": cmd_grep, "derive": cmd_derive, "diff": cmd_diff}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
