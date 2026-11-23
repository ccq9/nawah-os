#!/usr/bin/env python3
"""TST-M3-FAT32-TOOL: the host-side FAT32 tool (tools/fat32.py) formats a volume that it reads
back exactly, that passes its own structural check and, where dosfstools is installed, fsck.fat.
The tool is the independent implementation the kernel's FAT32 is checked against."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "fat32.py")
EOC = 0x0FFFFFFF
# WP-127 (C5): how long `check` may take on a chain of the volume's size (it takes seconds when
# its cost grows with the chain's length, minutes when it grows with the square).
WALK_BOUND = 30


def run(*args):
    return subprocess.run([sys.executable, "-I", TOOL, *args], capture_output=True, text=True)


class Fat32Tool(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="fat32-")
        self.img = os.path.join(self.dir, "disk.img")
        self.small = os.path.join(self.dir, "hello.txt")
        with open(self.small, "wb") as f:
            f.write(b"hello from the lab disk\n")
        self.big = os.path.join(self.dir, "pattern.bin")
        self.big_data = bytes(((i * 31 + (i >> 8)) & 0xFF) for i in range(20480))
        with open(self.big, "wb") as f:
            f.write(self.big_data)
        r = run("format", self.img, "--sectors", "131072", "--mkdir", "DIR", "--add", f"HELLO.TXT={self.small}",
                "--add", f"PATTERN.BIN={self.big}", "--add", f"DIR/INNER.TXT={self.small}", "--pattern-tail", "8")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_geometry_and_listing(self):
        self.assertEqual(os.path.getsize(self.img), 131072 * 512)
        r = run("ls", self.img)
        self.assertEqual(r.returncode, 0)
        names = [line.split()[1] for line in r.stdout.splitlines()]
        self.assertEqual(names, ["DIR", "HELLO.TXT", "PATTERN.BIN"])
        r = run("check", self.img)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("clusters=128992 used=44 free=128948", r.stdout)

    def test_read_back(self):
        r = run("cat", self.img, "/DIR/INNER.TXT")
        self.assertEqual(r.stdout, "hello from the lab disk\n")
        r = run("verify", self.img, "/PATTERN.BIN", hashlib.sha256(self.big_data).hexdigest(), "--size", "20480")
        self.assertEqual(r.returncode, 0, r.stdout)
        r = run("expect", self.img, "/HELLO.TXT", "hello from the lab disk\\n")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(run("expect", self.img, "/HELLO.TXT", "other").returncode, 1)
        self.assertEqual(run("cat", self.img, "/NOPE.TXT").returncode, 2)

    def test_pattern_tail(self):
        with open(self.img, "rb") as f:
            f.seek((131072 - 8) * 512)
            self.assertEqual(f.read(4), bytes([0xC8, 0xC9, 0xCA, 0xCB]))
            f.seek((131072 - 9) * 512)
            self.assertEqual(f.read(4), b"\0\0\0\0")

    def test_absent_raw(self):
        # The lab's hello text is on the image; a string that never reached it is absent.
        self.assertEqual(run("absent-raw", self.img, "hello from the lab disk").returncode, 1)
        r = run("absent-raw", self.img, "lab-admin-1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("absent from all 131072 sectors", r.stdout)

    def test_grep(self):
        self.assertEqual(run("grep", self.img, "/HELLO.TXT", "from the lab").returncode, 0)
        self.assertEqual(run("grep", self.img, "/HELLO.TXT", "nothing like this").returncode, 1)
        self.assertEqual(run("grep", self.img, "/NOPE.TXT", "x").returncode, 2)

    def test_nested_directory(self):
        # WP-35: /SYSTEM/FONTS holds the fonts; a nested directory is made in its parent and
        # its files read back; a missing parent is refused.
        img = os.path.join(self.dir, "nested.img")
        r = run("format", img, "--sectors", "131072", "--mkdir", "SYSTEM", "--mkdir", "SYSTEM/FONTS",
                "--add", f"SYSTEM/FONTS/A.TTF={self.big}")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = run("verify", img, "/SYSTEM/FONTS/A.TTF", hashlib.sha256(self.big_data).hexdigest(), "--size", "20480")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(run("check", img).returncode, 0)
        fsck = shutil.which("fsck.fat")
        if fsck:
            r = subprocess.run([fsck, "-n", img], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = run("format", img, "--sectors", "131072", "--mkdir", "NOPE/FONTS")
        self.assertNotEqual(r.returncode, 0)

    def test_fsck(self):
        fsck = shutil.which("fsck.fat")
        if not fsck:
            self.skipTest("dosfstools not installed")
        r = subprocess.run([fsck, "-n", self.img], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("44/128992 clusters", r.stdout)


def load_tool():
    spec = importlib.util.spec_from_file_location("fat32_tool", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Fat32Check(unittest.TestCase):
    """WP-105: `check` sees what a broken delete or truncate leaves (a name whose chain runs
    into a free cluster, two names on one cluster), and what the safe order leaves (lost
    clusters, a chain longer than the size, FAT copies that differ, a stale free count) is a
    problem on a healthy image and a counted finding with `--faulted`. `fsck-faulted` runs
    fsck.fat -n, keeps its whole output and names every message."""

    def setUp(self):
        self.tool = load_tool()
        self.dir = tempfile.mkdtemp(prefix="fat32-check-")
        self.img = os.path.join(self.dir, "disk.img")
        one = os.path.join(self.dir, "one.txt")
        with open(one, "wb") as f:
            f.write(b"1" * 100)
        big = os.path.join(self.dir, "big.bin")
        with open(big, "wb") as f:
            f.write(b"B" * 1500)
        r = run("format", self.img, "--sectors", "131072", "--add", f"ONE.TXT={one}", "--add", f"TWO.TXT={one}",
                "--add", f"BIG.BIN={big}")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(run("check", self.img).returncode, 0)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def image(self):
        return self.tool.Image(self.img, writable=True)

    def first(self, img, name):
        return img.entry_cluster(img.resolve("/" + name)[1])

    def set_one_copy(self, img, cluster, value, fat):
        off = cluster * 4
        sec = img.fat_start + fat * img.fatsz + off // 512
        s = bytearray(img.read_sector(sec))
        s[off % 512:off % 512 + 4] = value.to_bytes(4, "little")
        img.write_sector(sec, bytes(s))

    def test_free_first_cluster_is_a_problem(self):
        img = self.image()
        img.fat_set(self.first(img, "ONE.TXT"), 0)
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.img)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("ONE.TXT", r.stdout)
            self.assertIn("is free", r.stdout)

    def test_shared_cluster_is_a_problem(self):
        img = self.image()
        c, i, e = img.lookup(img.root_cluster, "TWO.TXT")
        one = self.first(img, "ONE.TXT")
        e = bytearray(e)
        e[20:22] = (one >> 16).to_bytes(2, "little")
        e[26:28] = (one & 0xFFFF).to_bytes(2, "little")
        data = bytearray(img.read_cluster(c))
        data[i * 32:i * 32 + 32] = e
        img.write_cluster(c, bytes(data))
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.img)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("share cluster", r.stdout)
            self.assertIn("ONE.TXT", r.stdout)
            self.assertIn("TWO.TXT", r.stdout)

    def test_free_in_the_second_copy_alone_is_a_problem_when_faulted(self):
        img = self.image()
        self.set_one_copy(img, self.first(img, "ONE.TXT"), 0, 1)
        img.close()
        r = run("check", "--faulted", self.img)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAT1", r.stdout)
        self.assertIn("is free", r.stdout)

    def test_lost_cluster(self):
        img = self.image()
        img.alloc_cluster()
        img.close()
        r = run("check", self.img)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("lost clusters: 1", r.stdout)
        r = run("check", "--faulted", self.img)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("lost=1", r.stdout)
        self.assertIn("problems=[]", r.stdout)
        # A case that knows how many clusters its failures lose says so: any other count fails.
        self.assertEqual(run("check", "--faulted", "--expect-lost", "1", "--expect-lost-second", "1", "--expect-lost-both", "1", self.img).returncode, 0)
        for n in ("0", "2"):
            r = run("check", "--faulted", "--expect-lost", n, "--expect-lost-second", "1", "--expect-lost-both", "1", self.img)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("lost clusters: 1", r.stdout)

    def test_chain_longer_than_size(self):
        img = self.image()
        extra = img.alloc_cluster()
        img.fat_set(self.first(img, "ONE.TXT"), extra)
        img.close()
        r = run("check", self.img)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("ONE.TXT: chain longer than size", r.stdout)
        # A delete or a truncation never leaves it, so --faulted fails it too unless the case
        # says its operation may (a failed write, WP-118).
        r = run("check", "--faulted", self.img)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("ONE.TXT: chain longer than size", r.stdout)
        # --allow-longer takes the exact number the case expects: one more or one fewer fails.
        names = ("--expect-longer", "/ONE.TXT:+1", "--expect-longer-second", "/ONE.TXT:+1")
        r = run("check", "--faulted", "--allow-longer", "1", *names, self.img)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("longer=1", r.stdout)
        self.assertIn("problems=[]", r.stdout)
        for n in ("0", "2"):
            r = run("check", "--faulted", "--allow-longer", n, *names, self.img)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("chains longer than size: 1", r.stdout)
            self.assertIn("/ONE.TXT", r.stdout)

    def both(self, img, cluster, value):
        for fat in (0, 1):
            self.set_one_copy(img, cluster, value, fat)

    def free(self, img, n):
        got = []
        for c in range(2, img.clusters + 2):
            if img.fat_get(c) == 0 and img.fat_get(c, 1) == 0:
                got.append(c)
                if len(got) == n:
                    break
        return got

    def test_longer_files_are_named_with_their_extra_clusters(self):
        # WP-127 (B1): counts alone cannot tell the state a case expects from another one with
        # the same counts. X: ONE.TXT one cluster longer, one cluster lost. Y: ONE.TXT sound,
        # BIG.BIN two clusters longer (one of them the cluster X lost), another cluster lost.
        pins = ("--allow-longer", "1", "--expect-longer", "/ONE.TXT:+1", "--expect-longer-second", "/ONE.TXT:+1",
                "--expect-lost", "1", "--expect-lost-second", "1", "--expect-lost-both", "1")
        img = self.image()
        a, b, c = self.free(img, 3)
        one, big = self.first(img, "ONE.TXT"), img.chain(self.first(img, "BIG.BIN"))[-1]
        self.both(img, one, a); self.both(img, a, EOC); self.both(img, b, EOC)
        img.close()
        r = run("check", "--faulted", *pins, self.img)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(" longer_files=/ONE.TXT:+1 ", r.stdout)
        # The same file with another number of extra clusters is another state.
        r = run("check", "--faulted", *[p.replace(":+1", ":+2") for p in pins], self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("/ONE.TXT:+1", r.stdout)
        img = self.image()
        self.both(img, one, EOC); self.both(img, big, a); self.both(img, a, b); self.both(img, b, EOC); self.both(img, c, EOC)
        img.close()
        r = run("check", "--faulted", *pins, self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("/BIG.BIN:+2", r.stdout)
        # Each copy is judged by its own pin: with the other copy's pin right, the finding is
        # this copy's alone.
        counts = ("--allow-longer", "1", "--expect-lost", "1", "--expect-lost-second", "1", "--expect-lost-both", "1")
        r = run("check", "--faulted", *counts, "--expect-longer", "/ONE.TXT:+1", "--expect-longer-second", "/BIG.BIN:+2", self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("problems=['chains longer than size: /BIG.BIN:+2 where /ONE.TXT:+1 are expected']", r.stdout)
        r = run("check", "--faulted", *counts, "--expect-longer", "/BIG.BIN:+2", "--expect-longer-second", "/ONE.TXT:+1", self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("problems=['FAT1: chains longer than size: /BIG.BIN:+2 where /ONE.TXT:+1 are expected']", r.stdout)
        r = run("check", "--faulted", *counts, "--expect-longer", "/BIG.BIN:+2", "--expect-longer-second", "/BIG.BIN:+2", self.img)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_chain_longer_in_the_second_copy_alone(self):
        # WP-127 (B4): a file longer than its size along the second copy alone, its extra
        # cluster free in the first: no state a delete or a truncation leaves.
        img = self.image()
        (a,) = self.free(img, 1)
        self.set_one_copy(img, self.first(img, "ONE.TXT"), a, 1)
        self.set_one_copy(img, a, EOC, 1)
        img.close()
        r = run("check", "--faulted", self.img)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAT1: /ONE.TXT: chain longer than size", r.stdout)
        # A case whose operation may leave it says which file and by how much.
        r = run("check", "--faulted", "--expect-longer-second", "/ONE.TXT:+1", self.img)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(" second: lost=0 lost_both=0 longer_files=/ONE.TXT:+1", r.stdout)
        for other in ("/TWO.TXT:+1", "/ONE.TXT:+2", "-"):
            r = run("check", "--faulted", "--expect-longer-second", other, self.img)
            self.assertEqual(r.returncode, 1, (other, r.stdout + r.stderr))
            self.assertIn("/ONE.TXT:+1", r.stdout, other)

    def test_clusters_marked_in_the_second_copy_alone(self):
        # WP-127 (B4): lost clusters are counted along the second copy too, and a case pins them.
        img = self.image()
        for c in self.free(img, 100):
            self.set_one_copy(img, c, EOC, 1)
        img.close()
        r = run("check", "--faulted", self.img)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn(" lost=0 ", r.stdout)
        self.assertIn(" second: lost=100 ", r.stdout)
        r = run("check", "--faulted", "--expect-lost", "0", "--expect-lost-second", "100", "--expect-lost-both", "0", self.img)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for n in ("0", "99", "101"):
            r = run("check", "--faulted", "--expect-lost", "0", "--expect-lost-second", n, "--expect-lost-both", "0", self.img)
            self.assertEqual(r.returncode, 1, (n, r.stdout + r.stderr))
            self.assertIn(f"FAT1: lost clusters: 100 where {n} are expected", r.stdout)

    def test_a_pin_on_the_first_copy_needs_the_second(self):
        # WP-127 (B4): a case cannot pin the first copy and leave the second unjudged.
        # The three numbers of the lost clusters come together or not at all, in whichever order
        # a case tries to leave one out.
        for opts in (("--expect-lost", "0"), ("--allow-longer", "0"), ("--expect-longer", "-"),
                     ("--allow-longer", "0", "--expect-longer", "-"),
                     ("--expect-lost-second", "0"), ("--expect-lost-both", "0"),
                     ("--expect-lost", "0", "--expect-lost-second", "0"), ("--expect-lost", "0", "--expect-lost-both", "0"),
                     ("--expect-lost-second", "0", "--expect-lost-both", "0")):
            r = run("check", "--faulted", *opts, self.img)
            self.assertEqual(r.returncode, 2, (opts, r.stdout + r.stderr))
            self.assertIn("-second", r.stderr, opts)
        whole = ("--allow-longer", "0", "--expect-longer", "-", "--expect-longer-second", "-",
                 "--expect-lost", "0", "--expect-lost-second", "0", "--expect-lost-both", "0")
        r = run("check", "--faulted", *whole, self.img)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(" longer_files=- second: lost=0 lost_both=0 longer_files=-", r.stdout)

    def test_lost_clusters_that_cancel_between_the_copies(self):
        # WP-127 (the red team's A1): one cluster lost in both copies, against one marked in
        # the first copy alone and another in the second alone: the two counts are the same.
        pins = ("--expect-lost", "1", "--expect-lost-second", "1", "--expect-lost-both", "1")
        img = self.image()
        x, y = self.free(img, 2)
        self.both(img, x, EOC)
        img.close()
        r = run("check", "--faulted", *pins, self.img)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(" second: lost=1 lost_both=1 ", r.stdout)
        img = self.image()
        self.set_one_copy(img, x, 0, 1)
        self.set_one_copy(img, y, EOC, 1)
        img.close()
        r = run("check", "--faulted", *pins, self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("lost clusters in both copies: 0 where 1 are expected", r.stdout)
        self.assertIn(" lost=1 ", r.stdout)
        self.assertIn(" second: lost=1 lost_both=0 ", r.stdout)

    def test_each_copy_s_longer_files_are_its_own(self):
        # WP-127 (the red team's A5): ONE.TXT longer along the first copy alone, BIG.BIN along
        # the second alone. Each copy's pin is compared with that copy's files.
        img = self.image()
        a, b = self.free(img, 2)
        self.set_one_copy(img, self.first(img, "ONE.TXT"), a, 0)
        self.set_one_copy(img, a, EOC, 0)
        self.set_one_copy(img, img.chain(self.first(img, "BIG.BIN"))[-1], b, 1)
        self.set_one_copy(img, b, EOC, 1)
        img.close()
        r = run("check", "--faulted", "--allow-longer", "1", "--expect-longer", "/ONE.TXT:+1", "--expect-longer-second", "/BIG.BIN:+1", self.img)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = run("check", "--faulted", "--allow-longer", "1", "--expect-longer", "/BIG.BIN:+1", "--expect-longer-second", "/ONE.TXT:+1", self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("'chains longer than size: /ONE.TXT:+1 where /BIG.BIN:+1 are expected'", r.stdout)
        self.assertIn("'FAT1: chains longer than size: /BIG.BIN:+1 where /ONE.TXT:+1 are expected'", r.stdout)
        # The number --allow-longer pins is the first copy's: here it is 1 along each copy,
        # and two files along the second alone must not meet it.
        img = self.image()
        self.set_one_copy(img, self.first(img, "ONE.TXT"), EOC, 0)
        self.set_one_copy(img, a, 0, 0)
        self.set_one_copy(img, self.first(img, "TWO.TXT"), a, 1)
        self.set_one_copy(img, a, EOC, 1)
        img.close()
        r = run("check", "--faulted", "--allow-longer", "2", "--expect-longer", "-", "--expect-longer-second", "/BIG.BIN:+1,/TWO.TXT:+1", self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("chains longer than size: 0 where 2 are expected", r.stdout)

    def test_two_longer_files_are_named_in_any_order(self):
        img = self.image()
        a, b = self.free(img, 2)
        self.both(img, self.first(img, "ONE.TXT"), a); self.both(img, a, EOC)
        self.both(img, img.chain(self.first(img, "BIG.BIN"))[-1], b); self.both(img, b, EOC)
        img.close()
        for order in ("/ONE.TXT:+1,/BIG.BIN:+1", "/BIG.BIN:+1,/ONE.TXT:+1"):
            r = run("check", "--faulted", "--allow-longer", "2", "--expect-longer", order, "--expect-longer-second", order, self.img)
            self.assertEqual(r.returncode, 0, (order, r.stdout + r.stderr))
            self.assertIn(" longer_files=/BIG.BIN:+1,/ONE.TXT:+1 ", r.stdout)
        r = run("check", "--faulted", "--allow-longer", "2", "--expect-longer", "/ONE.TXT:+1,/TWO.TXT:+1", "--expect-longer-second", "/ONE.TXT:+1,/BIG.BIN:+1", self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_a_name_that_reads_as_two_is_one_file(self):
        # WP-127 (the red team's A2): one longer file whose name holds a comma and `:+` must
        # not meet a pin that names two files.
        img = self.image()
        (a,) = self.free(img, 1)
        self.both(img, self.first(img, "ONE.TXT"), a); self.both(img, a, EOC)
        data = bytearray(img.read_cluster(img.root_cluster))
        i = bytes(data).index(b"ONE     TXT")
        data[i:i + 11] = b"A:+1,/B TXT"
        img.write_cluster(img.root_cluster, bytes(data))
        img.close()
        r = run("check", "--faulted", "--allow-longer", "1", "--expect-longer", "/A:+1,/B.TXT:+1", "--expect-longer-second", "/A:+1,/B.TXT:+1", self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_a_name_reached_along_one_copy_only(self):
        # WP-127 (the red team's A4): the root's chain is longer in the second copy alone and
        # its extra cluster holds an entry: a name the first copy does not reach.
        img = self.image()
        z, first = self.free(img, 2)
        data = bytearray(img.read_cluster(img.root_cluster))
        for i in range(0, len(data), 32):
            if data[i] == 0:
                data[i] = 0xE5          # the walk must go on into the next cluster
        img.write_cluster(img.root_cluster, bytes(data))
        entry = bytearray(data[bytes(data).index(b"ONE     TXT"):][:32])
        entry[0:11] = b"GHOST   TXT"
        struct.pack_into("<H", entry, 20, first >> 16); struct.pack_into("<H", entry, 26, first & 0xFFFF)
        img.write_cluster(z, bytes(entry) + bytes(len(data) - 32))
        self.set_one_copy(img, img.root_cluster, z, 1)
        self.set_one_copy(img, z, EOC, 1)
        self.both(img, first, EOC)
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.img)
            self.assertEqual(r.returncode, 1, (mode, r.stdout))
            self.assertIn("FAT1: /GHOST.TXT is reached along this copy only", r.stdout, mode)
        # The mirror: the root's chain is longer in the first copy alone, and the second copy
        # does not reach the name.
        img = self.image()
        self.set_one_copy(img, img.root_cluster, EOC, 1)
        self.set_one_copy(img, z, 0, 1)
        self.set_one_copy(img, img.root_cluster, z, 0)
        self.set_one_copy(img, z, EOC, 0)
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.img)
            self.assertEqual(r.returncode, 1, (mode, r.stdout))
            self.assertIn("FAT1: /GHOST.TXT is not reached along this copy", r.stdout, mode)
        # With the counts such an image has, the name is still the finding.
        r = run("check", "--faulted", "--expect-lost", "0", "--expect-lost-second", "1", "--expect-lost-both", "0", self.img)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("problems=['FAT1: /GHOST.TXT is not reached along this copy']", r.stdout)

    def test_second_copy_pins_need_a_second_copy(self):
        # WP-127 (the red team's A3): on a volume with one FAT copy a pin on the second copy
        # is met by nothing and must not pass in silence.
        img = self.image()
        for sector in (0, img.bk_boot):
            s = bytearray(img.read_sector(sector))
            s[16] = 1
            img.write_sector(sector, bytes(s))
        img.close()
        r = run("check", "--faulted", "--expect-longer-second", "-", self.img)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("no second FAT copy", r.stdout + r.stderr)

    def test_a_chain_that_loops_is_named(self):
        img = self.image()
        chain = img.chain(self.first(img, "BIG.BIN"))
        self.both(img, chain[-1], chain[0])
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.img)
            self.assertEqual(r.returncode, 1, (mode, r.stdout))
            self.assertIn(f"/BIG.BIN: bad chain at {chain[0]:#x}", r.stdout, mode)

    def test_a_chain_of_the_volume_s_size_is_walked_in_time(self):
        # WP-127 (C5): BIG.BIN takes every free cluster of the volume. The image is healthy.
        img = self.image()
        last = img.chain(self.first(img, "BIG.BIN"))[-1]
        fat = bytearray(img.read_sector(img.fat_start, img.fatsz))
        free = [c for c in range(2, img.clusters + 2) if not struct.unpack_from("<I", fat, c * 4)[0]]
        for prev, c in zip([last] + free, free):
            struct.pack_into("<I", fat, prev * 4, c)
        struct.pack_into("<I", fat, free[-1] * 4, EOC)
        for copy in (0, 1):
            for s in range(img.fatsz):
                img.write_sector(img.fat_start + copy * img.fatsz + s, bytes(fat[s * 512:(s + 1) * 512]))
        info = bytearray(img.read_sector(img.fsinfo_sector))
        struct.pack_into("<I", info, 488, 0)
        img.write_sector(img.fsinfo_sector, bytes(info))
        self.set_entry(img, "BIG.BIN", self.first(img, "BIG.BIN"), (3 + len(free)) * 512)
        img.close()
        self.assertGreater(len(free), 128000)
        try:
            r = subprocess.run([sys.executable, "-I", TOOL, "check", self.img], capture_output=True, text=True, timeout=WALK_BOUND)
        except subprocess.TimeoutExpired:
            self.fail(f"check took more than {WALK_BOUND} s on a chain of {3 + len(free)} clusters")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("free=0 ", r.stdout)

    def test_copies_differ(self):
        img = self.image()
        free = next(c for c in range(2, img.clusters + 2) if img.fat_get(c) == 0)
        self.set_one_copy(img, free, 0x0FFFFFFF, 0)
        img.close()
        self.assertEqual(run("check", self.img).returncode, 1)
        r = run("check", "--faulted", self.img)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("mirror_diff=1", r.stdout)
        self.assertIn("lost=1", r.stdout)

    def with_dirs(self, *dirs, files=()):
        img = os.path.join(self.dir, "dirs.img")
        args = ["format", img, "--sectors", "131072"]
        for d in dirs:
            args += ["--mkdir", d]
        one = os.path.join(self.dir, "one.txt")
        for f in files:
            args += ["--add", f"{f}={one}"]
        r = run(*args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(run("check", img).returncode, 0)
        return img

    def test_directory_chain_into_a_free_cluster(self):
        # A directory has no size to fall short of: only the named finding stands guard.
        path = self.with_dirs("D1", files=["D1/IN.TXT"])
        img = self.tool.Image(path, writable=True)
        img.fat_set(img.entry_cluster(img.resolve("/D1")[1]), 0)
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, path)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("/D1: cluster", r.stdout)
            self.assertIn("is free", r.stdout)

    def test_two_directories_on_one_cluster(self):
        path = self.with_dirs("D1", "D2")
        img = self.tool.Image(path, writable=True)
        d1 = img.entry_cluster(img.resolve("/D1")[1])
        c, i, e = img.lookup(img.root_cluster, "D2")
        e = bytearray(e)
        e[20:22] = (d1 >> 16).to_bytes(2, "little")
        e[26:28] = (d1 & 0xFFFF).to_bytes(2, "little")
        data = bytearray(img.read_cluster(c))
        data[i * 32:i * 32 + 32] = e
        img.write_cluster(c, bytes(data))
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, path)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("/D2 and /D1 share cluster", r.stdout)

    def nested(self, name, levels):
        img = os.path.join(self.dir, name)
        dirs = ["/".join("D" * 1 for _ in range(k + 1)) for k in range(levels)]
        r = run("format", img, "--sectors", "131072", *[x for d in dirs for x in ("--mkdir", d)])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return img

    def test_deep_tree(self):
        # Ten levels are a healthy tree (the walk used to stop at eight and call the rest lost).
        r = run("check", self.nested("ten.img", 10))
        self.assertEqual(r.returncode, 0, r.stdout)
        # Past its limit the walk says so, and does not call what it did not visit lost.
        r = run("check", self.nested("deep.img", 130))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("deeper than this check walks", r.stdout)
        self.assertNotIn("lost clusters", r.stdout)

    def test_fsinfo_signatures(self):
        # A free count under broken signatures is not a count: it is a problem of its own,
        # with and without --faulted (a refused write leaves the sector as it was).
        img = self.image()
        s = bytearray(img.read_sector(img.fsinfo_sector))
        s[488:492] = (5).to_bytes(4, "little")
        for off in (0, 484, 508):
            broken = bytearray(s)
            broken[off:off + 4] = bytes(4)
            img.write_sector(img.fsinfo_sector, bytes(broken))
            img.f.flush()
            for mode in ([], ["--faulted"]):
                r = run("check", *mode, self.img)
                self.assertEqual(r.returncode, 1, (off, r.stdout))
                self.assertIn("FSInfo signatures", r.stdout)
        img.close()

    # ---- WP-126: a damaged entry and a reserved value are named, in every FAT copy ----------

    def set_entry(self, img, name, first, size=None, attr=None):
        """Rewrites the root directory entry NAME in place: its first cluster, and its size and
        attributes when given."""
        import struct
        data = bytearray(img.read_cluster(img.root_cluster))
        for i in range(0, len(data), 32):
            e = bytes(data[i:i + 32])
            if e[0] in (0, 0xE5):
                continue
            if self.tool.display_name(e[:11]) == name:
                struct.pack_into("<H", data, i + 20, first >> 16)
                struct.pack_into("<H", data, i + 26, first & 0xFFFF)
                if size is not None:
                    struct.pack_into("<I", data, i + 28, size)
                if attr is not None:
                    data[i + 11] = attr
                img.write_cluster(img.root_cluster, bytes(data))
                return
        self.fail(f"no root entry {name}")

    def test_directory_entry_whose_first_cluster_is_no_cluster(self):
        # A directory has no size: with a first cluster that is no cluster the walk found
        # nothing to read and called it empty; only the lost count, in plain mode, hinted at it.
        # 0 and 1; 0 under attributes that are a directory's and more (the kernel asks the
        # directory bit alone); an end mark; the first number past the volume.
        for first, attr in ((0, None), (1, None), (0, 0x30), (0x0FFFFFF8, None), ("past", None)):
            path = self.with_dirs("D1", files=["D1/IN.TXT"])
            img = self.tool.Image(path, writable=True)
            n = img.clusters + 2 if first == "past" else first
            self.set_entry(img, "D1", n, attr=attr)
            img.close()
            for mode in ([], ["--faulted"]):
                r = run("check", *mode, path)
                self.assertEqual(r.returncode, 1, (first, attr, mode, r.stdout))
                self.assertIn(f"/D1: first cluster {n}, no cluster", r.stdout, (first, attr, mode))
            os.remove(path)

    def test_file_entry_whose_first_cluster_is_no_cluster(self):
        # 0 is the first cluster of an empty file and of nothing else; 1, an end mark and a
        # number past the volume are no cluster at all, whatever the size.
        for first, size in ((1, 0), (1, 100), (0x0FFFFFF8, 0), (0x0FFFFFF8, 100), ("past", 0), ("past", 100)):
            img = self.image()
            saved = img.read_cluster(img.root_cluster)
            n = img.clusters + 2 if first == "past" else first
            self.set_entry(img, "ONE.TXT", n, size)
            img.close()
            for mode in ([], ["--faulted"]):
                r = run("check", *mode, self.img)
                self.assertEqual(r.returncode, 1, (first, size, mode, r.stdout))
                self.assertIn(f"/ONE.TXT: first cluster {n}, no cluster", r.stdout, (first, size, mode))
            img = self.image()
            img.write_cluster(img.root_cluster, saved)
            img.close()
        self.assertEqual(run("check", self.img).returncode, 0)

    def test_empty_file_is_healthy(self):
        # The one entry whose first cluster is 0 by right: a file that holds nothing.
        empty = os.path.join(self.dir, "empty.bin")
        open(empty, "wb").close()
        one = os.path.join(self.dir, "one.txt")
        path = os.path.join(self.dir, "empty.img")
        r = run("format", path, "--sectors", "131072", "--add", f"EMPTY.TXT={empty}", "--add", f"ONE.TXT={one}")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        img = self.tool.Image(path)
        e = img.resolve("/EMPTY.TXT")[1]
        self.assertEqual((img.entry_cluster(e), int.from_bytes(e[28:32], "little")), (0, 0))
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, path)
            self.assertEqual(r.returncode, 0, (mode, r.stdout))
            self.assertIn("problems=[]", r.stdout, mode)

    def test_reserved_value_in_a_chain_of_the_second_copy(self):
        # The value 1 is no cluster and no end mark. In the second copy alone it ended a walk
        # quietly: at a directory's cluster, and at a file's last cluster in place of the mark.
        # The name is given with and without --faulted.
        path = self.with_dirs("D1", files=["D1/IN.TXT"])
        img = self.tool.Image(path, writable=True)
        self.set_one_copy(img, img.entry_cluster(img.resolve("/D1")[1]), 1, 1)
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, path)
            self.assertEqual(r.returncode, 1, (mode, r.stdout))
            self.assertIn("FAT1: /D1: its chain holds the reserved value 1", r.stdout, mode)
        img = self.image()
        last = img.chain(self.first(img, "BIG.BIN"))[-1]
        self.set_one_copy(img, last, 1, 1)
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.img)
            self.assertEqual(r.returncode, 1, (mode, r.stdout))
            self.assertIn("FAT1: /BIG.BIN: its chain holds the reserved value 1", r.stdout, mode)

    def test_reserved_value_in_a_chain_of_the_first_copy_names_the_file(self):
        img = self.image()
        last = img.chain(self.first(img, "BIG.BIN"))[-1]
        self.set_one_copy(img, last, 1, 0)
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.img)
            self.assertEqual(r.returncode, 1, (mode, r.stdout))
            self.assertIn("/BIG.BIN: its chain holds the reserved value 1", r.stdout, mode)

    def test_out_of_range_value_in_a_chain(self):
        # A link that is no cluster of the volume: a reserved number, the bad-cluster mark,
        # and the first number past the volume. Along either copy the name is given, with and
        # without --faulted.
        img = self.image()
        last = img.chain(self.first(img, "BIG.BIN"))[-1]
        past = img.clusters + 2
        img.close()
        for value in (0x0FFFFFF0, 0x0FFFFFF7, past):
            for fat in (1, 0):
                img = self.image()
                self.set_one_copy(img, last, value, fat)
                img.close()
                want = ("FAT1: " if fat else "") + f"/BIG.BIN: bad chain at {value:#x}"
                for mode in ([], ["--faulted"]):
                    r = run("check", *mode, self.img)
                    self.assertEqual(r.returncode, 1, (value, fat, mode, r.stdout))
                    self.assertIn(want, r.stdout, (value, fat, mode))
                img = self.image()
                self.set_one_copy(img, last, 0x0FFFFFFF, fat)
                img.close()
        self.assertEqual(run("check", self.img).returncode, 0)

    def test_invalid_value_outside_every_chain(self):
        # The scan for reserved and out-of-range values read the first copy only, and no case
        # held it to the first. Each copy; 1, two reserved values, the first number past the
        # volume; a free cluster in the middle and the volume's last entry.
        img = self.image()
        top, past = img.clusters + 1, img.clusters + 2
        img.close()
        for fat in (1, 0):
            label = f"FAT{fat}" if fat else "FAT"
            for cluster, value in ((5000, 1), (5000, 0x0FFFFFF0), (5001, 0x0FFFFFF6), (5000, past), (top, 1)):
                img = self.image()
                self.set_one_copy(img, cluster, value, fat)
                img.close()
                for mode in ([], ["--faulted"]):
                    r = run("check", *mode, self.img)
                    self.assertEqual(r.returncode, 1, (fat, cluster, value, mode, r.stdout))
                    self.assertIn(f"{label}[{cluster}] = {value:#x} invalid", r.stdout, (fat, cluster, value, mode))
                img = self.image()
                self.set_one_copy(img, cluster, 0, fat)
                img.close()
        self.assertEqual(run("check", self.img).returncode, 0)

    def test_fsck_messages_are_named(self):
        head = "fsck.fat 4.2 (2021-01-31)\n"
        tail = "\nLeaving filesystem unchanged.\ndisk.img: 4 files, 6/128992 clusters\n"
        ok = [
            "Reclaimed 1 unused cluster (512 bytes).\n",
            "Reclaimed 3 unused clusters (1536 bytes).\n",
            "Free cluster summary wrong (5 vs. really 8026)\n  Auto-correcting.\n",
            "FATs differ but appear to be intact.\n  Using first FAT.\n",
        ]
        longer = "/ONE.TXT\n  File size is 100 bytes, cluster chain length is > 512 bytes.\n  Truncating file to 100 bytes.\n"
        self.assertEqual(self.tool.classify_fsck(head + longer + tail), ({}, ["longer"], []))
        self.assertEqual(self.tool.classify_fsck(head + longer + tail, allow_longer=1), ({"longer": 1}, [], []))
        # The exact number again: two files where one is expected, or none where one is.
        self.assertEqual(self.tool.classify_fsck(head + longer + longer + tail, allow_longer=1)[1], ["longer"])
        self.assertEqual(self.tool.classify_fsck(head + tail, allow_longer=1)[1], ["longer"])
        # A line that starts like a path but says more is no path line.
        self.assertEqual(self.tool.classify_fsck(head + "/ONE.TXT is beyond repair\n" + tail)[2], ["/ONE.TXT is beyond repair"])
        for body in ok:
            failing, unnamed = self.tool.classify_fsck(head + body + tail)[1:]
            self.assertEqual((failing, unnamed), ([], []), body)
        bad = {
            "/ONE.TXT  and\n/TWO.TXT\n  share clusters.\n  Truncating second to 0 bytes.\n": "shared",
            "/ONE.TXT\n  Contains a free cluster (3). Assuming EOF.\n": "free_in_chain",
            "/BIG.BIN\n  File size is 1500 bytes, cluster chain length is 512 bytes.\n  Truncating file to 512 bytes.\n": "shorter",
        }
        for body, name in bad.items():
            failing, unnamed = self.tool.classify_fsck(head + body + tail)[1:]
            self.assertEqual(failing, [name], body)
            self.assertEqual(unnamed, [], body)
        allowed, failing, unnamed = self.tool.classify_fsck(head + "Something this tool never said before.\n" + tail)
        self.assertEqual(unnamed, ["Something this tool never said before."])
        allowed = self.tool.classify_fsck(head + ok[0] + ok[2] + tail)[0]
        self.assertEqual(allowed, {"lost": 1, "free_count": 1})

    def test_fsck_faulted_on_images(self):
        if not shutil.which("fsck.fat"):
            self.skipTest("dosfstools not installed")
        img = self.image()
        img.alloc_cluster()
        img.close()
        r = run("fsck-faulted", self.img)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("Reclaimed 1 unused cluster", r.stdout)
        self.assertIn("fsck: exit=1 allowed={'lost': 1} failing=[] unnamed=[]", r.stdout)
        img = self.image()
        img.fat_set(self.first(img, "ONE.TXT"), 0)
        img.close()
        r = run("fsck-faulted", self.img)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("Contains a free cluster", r.stdout)
        self.assertIn("'free_in_chain'", r.stdout)


class Fat32Derive(unittest.TestCase):
    """WP-180: `derive` makes an isolated copy of a volume with one file removed or replaced
    and never writes the source; `diff --expect-only` passes only when that one file is what
    differs between two volumes as their 8.3 entries show them (the tree, the attributes, the
    times and the contents), whatever the metadata sectors hold; a volume that holds a live
    entry the walk passes over, other than the root's one label and a directory's `.` and
    `..` in their places, fails `check`, so neither command takes it."""

    VOL = "/SYSTEM/APPS/CLOCK.ELF"
    OTHERS = ["/A.TXT", "/SYSTEM/APPS/NEXT.BIN", "/SYSTEM/TAIL.TXT"]

    def setUp(self):
        self.tool = load_tool()
        self.dir = tempfile.mkdtemp(prefix="fat32-derive-")
        self.src = os.path.join(self.dir, "disk.img")
        self.dst = os.path.join(self.dir, "copy.img")
        self.data = {"/A.TXT": b"a" * 100, self.VOL: bytes((i * 7 + 3) & 0xFF for i in range(3000)),
                     "/SYSTEM/APPS/NEXT.BIN": b"N" * 1500, "/SYSTEM/TAIL.TXT": b"tail\n"}
        adds = []
        for k, (vol, data) in enumerate(self.data.items()):
            host = os.path.join(self.dir, f"in{k}.bin")
            with open(host, "wb") as f:
                f.write(data)
            adds += ["--add", f"{vol.lstrip('/')}={host}"]
        r = run("format", self.src, "--sectors", "16384", "--mkdir", "SYSTEM", "--mkdir", "SYSTEM/APPS", *adds)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(run("check", self.src).returncode, 0)
        self.src_sha = self.sha(self.src)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    @staticmethod
    def sha(path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def host_file(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def place(self, path, vol):
        """(the chain's clusters, the directory cluster, the index, the raw entry) of VOL."""
        img = self.tool.Image(path)
        parent, name = vol.rsplit("/", 1)
        d = img.entry_cluster(img.resolve(parent)[1]) if parent else img.root_cluster
        c, i, e = img.lookup(d, name)
        first = img.entry_cluster(e)
        chain = img.chain(first) if first else []
        img.close()
        return chain, c, i, e

    def changed_sectors(self):
        with open(self.src, "rb") as a, open(self.dst, "rb") as b:
            x, y = a.read(), b.read()
        self.assertEqual(len(x), len(y))
        return {n for n in range(len(x) // 512) if x[n * 512:(n + 1) * 512] != y[n * 512:(n + 1) * 512]}

    def allowed_sectors(self, img, clusters, dir_cluster):
        """Where a derivation may differ from its source: the file's directory cluster, the FAT
        sectors of the clusters it freed or took in every copy, those clusters, both FSInfo."""
        out = {img.cluster_sector(dir_cluster), img.fsinfo_sector, img.bk_boot + 1}
        for c in clusters:
            out |= set(range(img.cluster_sector(c), img.cluster_sector(c) + img.spc))
            out |= {img.fat_start + fat * img.fatsz + (c * 4) // 512 for fat in range(img.nfats)}
        return out

    def sound(self, path):
        r = run("check", path)
        self.assertEqual(r.returncode, 0, r.stdout)
        fsck = shutil.which("fsck.fat")
        if fsck:
            r = subprocess.run([fsck, "-n", path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def others_unchanged(self, path):
        for vol in self.OTHERS:
            r = run("verify", path, vol, hashlib.sha256(self.data[vol]).hexdigest(), "--size", str(len(self.data[vol])))
            self.assertEqual(r.returncode, 0, r.stdout)

    def refused(self, *args, code=2, usage=False):
        """The call is refused with `code` in the tool's own words (or the parser's, for a call
        that names no one change), writes nothing and leaves the source as it was."""
        before = sorted(os.listdir(self.dir))
        r = run("derive", *args)
        self.assertEqual(r.returncode, code, r.stdout + r.stderr)
        if usage:
            self.assertIn("one of the arguments --remove --replace is required" if len(args) == 2 else "not allowed with argument", r.stderr)
        else:
            self.assertIn("derive: ", r.stdout)
            self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(sorted(os.listdir(self.dir)), before)
        self.assertEqual(self.sha(self.src), self.src_sha)
        return r

    def test_remove_frees_and_zeroes_the_file_on_the_copy_alone(self):
        chain, dir_cluster, _, _ = self.place(self.src, self.VOL)
        self.assertEqual(len(chain), 6)
        r = run("derive", self.src, self.dst, "--remove", self.VOL)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.sha(self.src), self.src_sha)
        self.assertIn(f"source sha256={self.src_sha}", r.stdout)
        self.assertIn(f"copy sha256={self.sha(self.dst)}", r.stdout)
        self.assertEqual(run("cat", self.dst, self.VOL).returncode, 2)
        r = run("verify", self.src, self.VOL, hashlib.sha256(self.data[self.VOL]).hexdigest(), "--size", "3000")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("CLOCK.ELF", run("ls", self.dst, "/SYSTEM/APPS").stdout)
        self.assertIn("NEXT.BIN", run("ls", self.dst, "/SYSTEM/APPS").stdout)
        self.others_unchanged(self.dst)
        img = self.tool.Image(self.dst)
        for c in chain:
            for fat in range(img.nfats):
                self.assertEqual(img.fat_get(c, fat), 0, (c, fat))
            self.assertEqual(img.read_cluster(c), bytes(512), c)
        allowed = self.allowed_sectors(img, chain, dir_cluster)
        img.close()
        # Byte for byte the source everywhere else; the image's bytes are nowhere on the copy.
        self.assertLessEqual(self.changed_sectors(), allowed)
        with open(self.dst, "rb") as f:
            self.assertNotIn(self.data[self.VOL][:512], f.read())
        self.sound(self.dst)

    def test_replace_keeps_the_entry_in_its_place(self):
        old_chain, dir_cluster, index, old = self.place(self.src, self.VOL)
        for name, data in (("larger.bin", bytes((i * 11 + 5) & 0xFF for i in range(5000))),
                           ("smaller.bin", b"s" * 700), ("empty.bin", b"")):
            with self.subTest(name=name):
                if os.path.exists(self.dst):
                    os.unlink(self.dst)
                r = run("derive", self.src, self.dst, "--replace", f"{self.VOL}={self.host_file(name, data)}")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(self.sha(self.src), self.src_sha)
                r = run("verify", self.dst, self.VOL, hashlib.sha256(data).hexdigest(), "--size", str(len(data)))
                self.assertEqual(r.returncode, 0, r.stdout)
                chain, c, i, e = self.place(self.dst, self.VOL)
                self.assertEqual((c, i), (dir_cluster, index))
                # The name, the attributes and the times are the source's; the size is the new one.
                self.assertEqual(e[:20] + e[22:26], old[:20] + old[22:26])
                self.assertEqual(struct.unpack_from("<I", e, 28)[0], len(data))
                self.assertEqual(len(chain), (len(data) + 511) // 512)
                self.others_unchanged(self.dst)
                img = self.tool.Image(self.dst)
                for cl in set(old_chain) - set(chain):
                    for fat in range(img.nfats):
                        self.assertEqual(img.fat_get(cl, fat), 0, (cl, fat))
                    self.assertEqual(img.read_cluster(cl), bytes(512), cl)
                allowed = self.allowed_sectors(img, set(old_chain) | set(chain), dir_cluster)
                img.close()
                self.assertLessEqual(self.changed_sectors(), allowed)
                with open(self.dst, "rb") as f:
                    self.assertNotIn(self.data[self.VOL][:512], f.read())
                self.sound(self.dst)

    def test_an_existing_destination_is_refused_under_any_name(self):
        kept = self.host_file("kept.img", b"kept")
        self.refused(self.src, kept, "--remove", self.VOL)
        with open(kept, "rb") as f:
            self.assertEqual(f.read(), b"kept")
        # The source itself: by its own path, by another spelling, by a hard link, by a symbolic link.
        self.refused(self.src, self.src, "--remove", self.VOL)
        self.refused(self.src, os.path.join(self.dir, ".", "disk.img"), "--remove", self.VOL)
        hard = os.path.join(self.dir, "hard.img")
        os.link(self.src, hard)
        self.refused(self.src, hard, "--remove", self.VOL)
        # What was there is there as it was: the hard link is still the source's second name,
        # the symbolic link still a link to it, each with the source's bytes.
        self.assertTrue(os.path.samefile(hard, self.src))
        self.assertEqual(os.stat(self.src).st_nlink, 2)
        self.assertEqual(self.sha(hard), self.src_sha)
        soft = os.path.join(self.dir, "soft.img")
        os.symlink(self.src, soft)
        self.refused(self.src, soft, "--remove", self.VOL)
        self.refused(self.src, soft, "--replace", f"{self.VOL}={kept}")
        self.assertTrue(os.path.islink(soft))
        self.assertEqual(os.readlink(soft), self.src)
        self.assertEqual(self.sha(soft), self.src_sha)
        with open(kept, "rb") as f:
            self.assertEqual(f.read(), b"kept")
        # A link to nowhere is a destination that exists: nothing is made where it points.
        dangling = os.path.join(self.dir, "dangling.img")
        os.symlink(os.path.join(self.dir, "nowhere.img"), dangling)
        self.refused(self.src, dangling, "--remove", self.VOL)
        self.assertFalse(os.path.lexists(os.path.join(self.dir, "nowhere.img")))
        self.assertEqual(os.readlink(dangling), os.path.join(self.dir, "nowhere.img"))

    def test_a_wrong_file_is_refused_and_no_copy_is_left(self):
        good = self.host_file("good.bin", b"g" * 10)
        self.refused(self.src, self.dst, "--remove", "/SYSTEM/APPS/NOPE.ELF")
        self.refused(self.src, self.dst, "--remove", "/SYSTEM/APPS")
        self.refused(self.src, self.dst, "--remove", "/")
        self.refused(self.src, self.dst, "--remove", "/NOPE/CLOCK.ELF")
        self.refused(self.src, self.dst, "--remove", "/A.TXT/CLOCK.ELF")
        self.refused(self.src, self.dst, "--remove", "/not an 8.3 name.elf")
        self.refused(self.src, self.dst, "--replace", f"/SYSTEM/APPS/NOPE.ELF={good}")
        self.refused(self.src, self.dst, "--replace", f"/SYSTEM/APPS={good}")
        self.refused(self.src, self.dst, "--replace", f"{self.VOL}={os.path.join(self.dir, 'missing.bin')}")
        self.refused(self.src, self.dst, "--replace", f"{self.VOL}={self.dir}")
        self.refused(self.src, self.dst, "--replace", self.VOL)
        self.refused(self.src, self.dst, usage=True)
        self.refused(self.src, self.dst, "--remove", self.VOL, "--replace", f"{self.VOL}={good}", usage=True)
        self.refused(os.path.join(self.dir, "missing.img"), self.dst, "--remove", self.VOL)
        self.assertFalse(os.path.lexists(self.dst))

    def test_a_replacement_the_volume_cannot_hold_leaves_no_copy(self):
        # 16384 sectors hold fewer than 8 MiB: the copy is begun, cannot be finished, and is removed.
        huge = self.host_file("huge.bin", b"h" * (9 << 20))
        r = self.refused(self.src, self.dst, "--replace", f"{self.VOL}={huge}", code=1)
        self.assertIn("disk full", r.stdout + r.stderr)
        self.assertFalse(os.path.lexists(self.dst))

    def rename_raw(self, path, vol, new):
        """Gives VOL's entry the raw 8.3 name of `new`, whatever else the directory holds."""
        _, c, i, e = self.place(path, vol)
        img = self.tool.Image(path, writable=True)
        data = bytearray(img.read_cluster(c))
        data[i * 32:i * 32 + 11] = self.tool.short_name(new)
        img.write_cluster(c, bytes(data))
        img.close()

    def test_two_entries_with_one_name_are_reported_and_not_derived_from(self):
        self.rename_raw(self.src, "/SYSTEM/APPS/NEXT.BIN", "CLOCK.ELF")
        self.src_sha = self.sha(self.src)
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.src)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("/SYSTEM/APPS/CLOCK.ELF: a second entry of this name in its directory", r.stdout)
            # Its chain is its own: the finding is the name, and no cluster is called lost for it.
            self.assertNotIn("lost clusters", r.stdout)
        self.assertIn(" faulted: lost=0 ", r.stdout)
        r = self.refused(self.src, self.dst, "--remove", self.VOL)
        self.assertIn("a second entry of this name", r.stdout)
        self.refused(self.src, self.dst, "--remove", "/A.TXT")

    @staticmethod
    def long_name(name, short, attr=0x0F, first=0x41):
        """One long-name entry, the only one of its set, for the raw short name `short`: the name
        `name` in UTF-16 over three fields, the short name's checksum at 13, the attribute at
        11. Put in the slot before that short name's entry, it gives it the long name."""
        s = 0
        for b in short:
            s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
        u = (name.encode("utf-16-le") + b"\0\0").ljust(26, b"\xff")
        e = bytearray(32)
        e[0], e[11], e[13] = first, attr, s
        e[1:11], e[14:26], e[28:32] = u[0:10], u[10:22], u[22:26]
        return bytes(e)

    def put_entry(self, path, directory, raw, before=None, slot=None):
        """Writes the 32 bytes `raw` into `directory` of the image at `path`: into the slot
        before the entry named `before`, which must hold a deleted entry; over the entry in
        `slot`; or into the first slot after the directory's last entry."""
        img = self.tool.Image(path, writable=True)
        c = img.root_cluster if directory == "/" else img.entry_cluster(img.resolve(directory)[1])
        data = bytearray(img.read_cluster(c))
        if before:
            at, i, _ = img.lookup(c, before)
            self.assertEqual(at, c)
            i -= 1
            self.assertEqual(data[i * 32], 0xE5)
        elif slot is not None:
            i = slot
            self.assertNotIn(data[i * 32], (0, 0xE5))
        else:
            i = next(k for k in range(len(data) // 32) if data[k * 32] == 0)
        data[i * 32:i * 32 + 32] = raw
        img.write_cluster(c, bytes(data))
        img.close()

    def test_a_long_name_entry_is_a_problem_check_names(self):
        # WP-180 (the red team, 2026-11-23): this tool and the kernel read 8.3 names alone, so a
        # volume that holds a long name shows a reader of long names another tree than theirs.
        # A long name's attribute is 0x0F under the mask 0x3F: the two bits above it do not
        # make it anything else.
        aliased = self.tool.short_name("NEXT.BIN")
        for directory, attr in (("/SYSTEM/APPS", 0x0F), ("/SYSTEM/APPS", 0x4F), ("/SYSTEM/APPS", 0x8F),
                                ("/SYSTEM/APPS", 0xCF), ("/", 0x0F)):
            with self.subTest(directory=directory, attr=hex(attr)):
                work = os.path.join(self.dir, "long.img")
                shutil.copyfile(self.src, work)
                self.put_entry(work, directory, self.long_name("clock.elf", aliased, attr))
                for mode in ([], ["--faulted"]):
                    r = run("check", *mode, work)
                    self.assertEqual(r.returncode, 1, r.stdout)
                    self.assertIn(f"{directory}: a long-name entry", r.stdout)
                    # The finding is the entry: nothing is called lost for it.
                    self.assertNotIn("lost clusters", r.stdout)
                os.unlink(work)

    def test_a_deleted_long_name_entry_is_no_problem(self):
        # A deleted entry is read by no one, whatever its attribute says.
        deleted = self.long_name("clock.elf", self.tool.short_name("NEXT.BIN"), first=0xE5)
        self.put_entry(self.src, "/SYSTEM/APPS", deleted)
        self.src_sha = self.sha(self.src)
        self.assertEqual(run("check", self.src).returncode, 0)
        self.assertEqual(run("derive", self.src, self.dst, "--remove", self.VOL).returncode, 0)
        self.assertEqual(self.diff(self.src, self.dst, self.VOL).returncode, 0)

    def test_a_source_that_holds_a_long_name_is_not_derived_from(self):
        self.put_entry(self.src, "/SYSTEM/APPS", self.long_name("clock.elf", self.tool.short_name("NEXT.BIN")))
        self.src_sha = self.sha(self.src)
        r = self.refused(self.src, self.dst, "--remove", self.VOL)
        self.assertIn("/SYSTEM/APPS: a long-name entry", r.stdout)
        self.refused(self.src, self.dst, "--replace", f"/A.TXT={self.host_file('good.bin', b'g')}")

    def test_diff_fails_for_an_image_that_holds_a_long_name(self):
        # The red team's copy: `derive` leaves the removed file's slot deleted, and one long-name
        # entry written there gives NEXT.BIN the removed file's name for a reader of long names
        # (locally, `mtype ::/SYSTEM/APPS/clock.elf` printed NEXT.BIN's bytes), while every 8.3
        # entry and every byte of a file is what `diff` expects of a removal.
        aliased = self.tool.short_name("NEXT.BIN")
        for attr in (0x0F, 0x4F):
            with self.subTest(attr=hex(attr)):
                self.fresh_copy().close()
                self.put_entry(self.dst, "/SYSTEM/APPS", self.long_name("clock.elf", aliased, attr), before="NEXT.BIN")
                r = self.diff(self.src, self.dst, self.VOL)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("B fails the check", self.diff_line(r))
                self.assertIn("/SYSTEM/APPS: a long-name entry", r.stdout)
        # The first image as well: a judge of 8.3 names does not judge a volume that holds more.
        self.fresh_copy().close()
        self.put_entry(self.src, "/SYSTEM/APPS", self.long_name("clock.elf", aliased))
        self.differs("A fails the check")

    def dot_named(self, path, vol, raw=b".CLK    ELF"):
        """VOL's own entry under a raw name that begins with a dot: the same chain, size and times."""
        _, _, _, e = self.place(path, vol)
        return raw + bytes(e[11:])

    def test_a_name_that_begins_with_a_dot_is_a_problem_check_names(self):
        # The two entries a directory begins with are the only names with a dot at their head
        # that every reader passes over. Another one is a file for a reader that lists it and
        # nothing for `check`, for `diff` and for the kernel, which pass over it: here it sits
        # on NEXT.BIN's chain, so no cluster is lost for it.
        for directory in ("/SYSTEM/APPS", "/"):
            with self.subTest(directory=directory):
                work = os.path.join(self.dir, "dot.img")
                shutil.copyfile(self.src, work)
                self.put_entry(work, directory, self.dot_named(work, "/SYSTEM/APPS/NEXT.BIN"))
                for mode in ([], ["--faulted"]):
                    r = run("check", *mode, work)
                    self.assertEqual(r.returncode, 1, r.stdout)
                    self.assertIn(f"{directory}: a name that begins with a dot", r.stdout)
                    self.assertNotIn("lost clusters", r.stdout)
                os.unlink(work)

    def test_an_image_with_a_dot_name_is_neither_derived_from_nor_passed(self):
        # In the slot `derive` cleared: every entry the walk reads and every byte of a file is
        # what `diff` expects of the removal, while a reader that lists the name (locally,
        # mtools) reads NEXT.BIN's bytes under it.
        self.edit_copy().close()
        self.put_entry(self.dst, "/SYSTEM/APPS", self.dot_named(self.dst, "/SYSTEM/APPS/NEXT.BIN"), before="NEXT.BIN")
        r = self.diff(self.src, self.dst, self.VOL)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("B fails the check", self.diff_line(r))
        self.assertIn("/SYSTEM/APPS: a name that begins with a dot", r.stdout)
        os.unlink(self.dst)
        # The first image as well, and the same volume as a source.
        self.edit_copy().close()
        self.put_entry(self.src, "/SYSTEM/APPS", self.dot_named(self.src, "/SYSTEM/APPS/NEXT.BIN"))
        self.differs("A fails the check")
        os.unlink(self.dst)
        self.src_sha = self.sha(self.src)
        r = self.refused(self.src, self.dst, "--remove", self.VOL)
        self.assertIn("/SYSTEM/APPS: a name that begins with a dot", r.stdout)

    @staticmethod
    def raw_entry(name, attr, first, size):
        e = bytearray(32)
        e[0:11], e[11] = name, attr
        struct.pack_into("<H", e, 20, first >> 16)
        struct.pack_into("<H", e, 26, first & 0xFFFF)
        struct.pack_into("<I", e, 28, size)
        return bytes(e)

    VOLUME_BIT = "an entry that carries the volume bit and is not the root's one label"
    DOT_NAME = "a name that begins with a dot and is not one of a directory's two in their places"

    def test_an_entry_passed_over_is_the_label_or_one_of_a_directorys_two(self):
        # WP-180 (the red team's second round, 2026-11-23): what the walk passes over it does
        # not claim the clusters of. So each kind is passed over in the one form that holds
        # nothing of its own: the root's one label (no directory, no cluster, no size, the name
        # the boot sector gives the volume, which `diff` compares), a directory's `.` in its
        # first slot on the directory itself, its `..` in the second on its parent (0 under the
        # root). Anything else of these kinds is a problem. On NEXT.BIN's chain, fsck.fat called
        # such an entry a file that shares clusters and mdir listed a `.` of 1500 bytes; under
        # another name, mlabel showed another label than the first image's (local runs).
        chain, _, _, _ = self.place(self.src, "/SYSTEM/APPS/NEXT.BIN")
        first, size, root = chain[0], 1500, 2
        img = self.tool.Image(self.src)
        system, apps = (img.entry_cluster(img.resolve(d)[1]) for d in ("/SYSTEM", "/SYSTEM/APPS"))
        img.close()
        raw, dot, dots = self.raw_entry, b".          ", b"..         "
        cases = [(f"a file under the volume bit ({attr:#x})", "/SYSTEM/APPS", None, raw(b"CLOCK   ELF", attr, first, size), self.VOLUME_BIT)
                 for attr in (0x08, 0x18, 0x28, 0x48, 0x88, 0x1F, 0x2F, 0x3F)]
        cases += [
            ("a second label", "/", None, raw(b"SECOND     ", 0x08, 0, 0), self.VOLUME_BIT),
            ("the label on a file's chain", "/", 0, raw(b"NAWAHLAB   ", 0x08, first, size), self.VOLUME_BIT),
            ("the label with a size", "/", 0, raw(b"NAWAHLAB   ", 0x08, 0, 5), self.VOLUME_BIT),
            ("the label under another name than the boot sector's", "/", 0, raw(b"EVIL       ", 0x08, 0, 0), self.VOLUME_BIT),
            # A long name's attribute with a bit above its mask, on an entry that is the label in all
            # else: a long name still, and no label (a reader that masks the attribute takes it so).
            ("the label under a long name's attribute and a bit above the mask", "/", 0, raw(b"NAWAHLAB   ", 0x4F, 0, 0), "a long-name entry"),
            ("the label as a directory", "/", 0, raw(b"NAWAHLAB   ", 0x18, 0, 0), self.VOLUME_BIT),
            ("a label under a directory", "/SYSTEM", None, raw(b"LABEL      ", 0x08, 0, 0), self.VOLUME_BIT),
            ("a dot in the root", "/", None, raw(dot, 0x10, root, 0), self.DOT_NAME),
            ("a dot file in the root", "/", None, raw(dot, 0x20, first, size), self.DOT_NAME),
            ("two dots in the root", "/", None, raw(dots, 0x10, 0, 0), self.DOT_NAME),
            ("a third dot entry", "/SYSTEM/APPS", None, raw(dot, 0x10, apps, 0), self.DOT_NAME),
            ("a third two-dots entry", "/SYSTEM/APPS", None, raw(dots, 0x10, system, 0), self.DOT_NAME),
            ("a dot that is a file", "/SYSTEM/APPS", 0, raw(dot, 0x20, apps, 0), self.DOT_NAME),
            ("a dot on another directory", "/SYSTEM/APPS", 0, raw(dot, 0x10, system, 0), self.DOT_NAME),
            ("a dot on a file's chain", "/SYSTEM/APPS", 0, raw(dot, 0x10, first, 0), self.DOT_NAME),
            ("two dots that are a file", "/SYSTEM/APPS", 1, raw(dots, 0x20, system, 0), self.DOT_NAME),
            ("two dots on the root's number", "/SYSTEM/APPS", 1, raw(dots, 0x10, root, 0), self.DOT_NAME),
            ("two dots on a file's chain", "/SYSTEM/APPS", 1, raw(dots, 0x10, first, 0), self.DOT_NAME),
            ("two dots under the root on a child", "/SYSTEM", 1, raw(dots, 0x10, apps, 0), self.DOT_NAME),
        ]
        for what, directory, slot, entry, finding in cases:
            with self.subTest(what=what):
                work = os.path.join(self.dir, "passed.img")
                shutil.copyfile(self.src, work)
                self.put_entry(work, directory, entry, slot=slot)
                for mode in ([], ["--faulted"]):
                    r = run("check", *mode, work)
                    self.assertEqual(r.returncode, 1, r.stdout)
                    self.assertIn(f"{directory}: {finding}", r.stdout)
                    self.assertNotIn("lost clusters", r.stdout)
                os.unlink(work)

    def test_an_image_with_a_file_under_the_volume_bit_is_neither_derived_from_nor_passed(self):
        # In the slot `derive` cleared, under the removed file's own name: no reader of 8.3 names
        # here lists it, the walk claimed nothing for it, and `diff` passed the copy.
        chain, _, _, _ = self.place(self.src, "/SYSTEM/APPS/NEXT.BIN")
        hidden = self.raw_entry(b"CLOCK   ELF", 0x08, chain[0], 1500)
        self.edit_copy().close()
        self.put_entry(self.dst, "/SYSTEM/APPS", hidden, before="NEXT.BIN")
        r = self.diff(self.src, self.dst, self.VOL)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("B fails the check", self.diff_line(r))
        self.assertIn(f"/SYSTEM/APPS: {self.VOLUME_BIT}", r.stdout)
        os.unlink(self.dst)
        # The first image as well, and the same volume as a source.
        self.edit_copy().close()
        self.put_entry(self.src, "/SYSTEM/APPS", hidden)
        self.differs("A fails the check")
        os.unlink(self.dst)
        self.src_sha = self.sha(self.src)
        r = self.refused(self.src, self.dst, "--remove", self.VOL)
        self.assertIn(f"/SYSTEM/APPS: {self.VOLUME_BIT}", r.stdout)

    def entry_at(self, path, directory, slot):
        img = self.tool.Image(path)
        c = img.root_cluster if directory == "/" else img.entry_cluster(img.resolve(directory)[1])
        e = bytes(img.read_cluster(c)[slot * 32:slot * 32 + 32])
        img.close()
        return e

    def test_diff_fails_when_the_label_or_a_directorys_two_change(self):
        # WP-180 (the third audit of the close lines, 2026-11-23): `check` holds the three
        # entries its walk passes over to hold nothing, and does not ask that they be there. So
        # `diff` compares them between the two images, byte for byte and in their order: without
        # its label entry a copy showed mlabel no label where the first image has one, and
        # fsck.fat named a directory without its two (local runs).
        label = self.entry_at(self.src, "/", 0)
        dot, dots = self.entry_at(self.src, "/SYSTEM/APPS", 0), self.entry_at(self.src, "/SYSTEM/APPS", 1)
        self.assertEqual((label[11], dot[:11], dots[:11]), (0x08, b".          ", b"..         "))

        def gone(e):
            return b"\xE5" + e[1:]

        def timed(e):
            return e[:22] + b"\x21\x08\x21\x5B" + e[26:]
        cases = [
            ("the label deleted", [("/", 0, gone(label))]),
            ("the label under the archive bit", [("/", 0, label[:11] + b"\x28" + label[12:])]),
            ("the label at another time", [("/", 0, timed(label))]),
            ("the label behind the other entries", [("/", 0, gone(label)), ("/", None, label)]),
            ("a directory without its dot", [("/SYSTEM/APPS", 0, gone(dot))]),
            ("a directory without its two dots", [("/SYSTEM/APPS", 1, gone(dots))]),
            ("a dot at another time", [("/SYSTEM/APPS", 0, timed(dot))]),
            ("two dots under the archive bit", [("/SYSTEM/APPS", 1, dots[:11] + b"\x30" + dots[12:])]),
            ("a dot with a size", [("/SYSTEM/APPS", 0, dot[:28] + struct.pack("<I", 4096))]),
        ]
        for what, edits in cases:
            with self.subTest(what=what):
                self.fresh_copy().close()
                for directory, slot, raw in edits:
                    self.put_entry(self.dst, directory, raw, slot=slot)
                # `check` asks nothing of these: the difference is `diff`'s to find.
                self.assertEqual(run("check", self.dst).returncode, 0)
                r = self.diff(self.src, self.dst, self.VOL)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertNotIn("fails the check", self.diff_line(r))

    def test_diff_fails_when_a_directorys_size_field_changes(self):
        # A directory's entry holds no size; `check` does not read the field, and a copy with
        # 4096 there passed `diff`, which took every directory's size for nothing.
        img = self.edit_copy()
        self.set_entry(img, "/SYSTEM", lambda e: struct.pack_into("<I", e, 28, 4096))
        img.close()
        self.assertEqual(run("check", self.dst).returncode, 0)
        self.differs("differ=['/SYSTEM/']")

    def test_a_source_that_fails_the_check_is_not_derived_from(self):
        chain, _, _, _ = self.place(self.src, "/SYSTEM/APPS/NEXT.BIN")
        img = self.tool.Image(self.src, writable=True)
        img.fat_set(chain[-1], 0)
        img.close()
        self.src_sha = self.sha(self.src)
        r = self.refused(self.src, self.dst, "--remove", self.VOL)
        self.assertIn("is free", r.stdout)

    def test_a_file_is_not_walked_as_a_directory(self):
        # A file whose bytes read as a directory entry named CLOCK.ELF: a path through it names nothing.
        img = self.tool.Image(self.src, writable=True)
        fake = img.make_entry("CLOCK.ELF", 0x20, img.entry_cluster(img.resolve("/SYSTEM/APPS/NEXT.BIN")[1]), 100)
        img.write_file(img.root_cluster, "FAKE.BIN", fake)
        self.tool.finish(img)
        img.close()
        self.assertEqual(run("check", self.src).returncode, 0)
        self.src_sha = self.sha(self.src)
        self.refused(self.src, self.dst, "--remove", "/FAKE.BIN/CLOCK.ELF")
        self.refused(self.src, self.dst, "--replace", f"/FAKE.BIN/CLOCK.ELF={self.host_file('good.bin', b'g')}")

    def test_a_copy_that_fails_the_check_is_not_left(self):
        # A derivation gone wrong (here the removed file's chain stays marked, six lost clusters)
        # is caught by the tool's own check of the copy, and the copy is removed.
        self.tool.Image.free_chain = lambda img, first: None
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.tool.cmd_derive(argparse.Namespace(src=self.src, dst=self.dst, remove=self.VOL, replace=None))
        self.assertEqual(code, 1, out.getvalue())
        self.assertIn("lost clusters: 6", out.getvalue())
        self.assertIn("derive: the copy fails the check: no copy is left", out.getvalue())
        self.assertFalse(os.path.lexists(self.dst))
        self.assertEqual(self.sha(self.src), self.src_sha)

    def diff(self, a, b, vol, *how):
        return run("diff", a, b, "--expect-only", vol, *(how or ("--removed",)))

    def diff_line(self, r):
        lines = [line for line in r.stdout.splitlines() if line.startswith("diff: ")]
        self.assertEqual(len(lines), 1, r.stdout + r.stderr)
        return lines[0]

    def replaced_copy(self, name="replaced.img", data=b"r" * 4000):
        path, host = os.path.join(self.dir, name), self.host_file("r.bin", data)
        r = run("derive", self.src, path, "--replace", f"{self.VOL}={host}")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return path, host

    def test_diff_passes_for_the_one_file_alone(self):
        self.assertEqual(run("derive", self.src, self.dst, "--remove", self.VOL).returncode, 0)
        r = self.diff(self.src, self.dst, self.VOL)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        line = self.diff_line(r)
        self.assertIn(f"only {self.VOL} differs", line)
        self.assertIn(f"A file size=3000 sha256={hashlib.sha256(self.data[self.VOL]).hexdigest()}", line)
        self.assertIn("B absent", line)
        self.assertIn(f"images A sha256={self.src_sha} B sha256={self.sha(self.dst)}", line)
        self.assertEqual(self.diff(self.src, self.dst, "/system/apps/clock.elf").returncode, 0)
        other, host = self.replaced_copy()
        r = self.diff(self.src, other, self.VOL, "--replaced-by", host)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"B file size=4000 sha256={hashlib.sha256(b'r' * 4000).hexdigest()}", self.diff_line(r))
        self.assertIn(f"images A sha256={self.src_sha} B sha256={self.sha(other)}", self.diff_line(r))
        # Another file named is no pass, nor a call that does not say what became of the file.
        r = self.diff(self.src, self.dst, "/A.TXT")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(self.VOL, self.diff_line(r))
        self.assertEqual(run("diff", self.src, other, "--expect-only", self.VOL).returncode, 2)
        self.assertEqual(run("diff", self.src, other, "--removed").returncode, 2)
        self.assertEqual(self.diff(self.src, other, self.VOL, "--removed", "--replaced-by", host).returncode, 2)
        self.assertEqual(self.diff(self.src, os.path.join(self.dir, "missing.img"), self.VOL).returncode, 2)
        self.assertEqual(self.diff(self.src, self.host_file("short.img", b""), self.VOL).returncode, 2)
        with open(self.src, "rb") as f:
            nospc = bytearray(f.read())
        nospc[13] = 0
        nospc = self.host_file("nospc.img", bytes(nospc))
        r = self.diff(self.src, nospc, self.VOL)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        r = run("derive", nospc, os.path.join(self.dir, "from-nospc.img"), "--remove", self.VOL)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("derive: refused", r.stdout)
        self.assertNotIn("Traceback", r.stderr)
        self.assertFalse(os.path.lexists(os.path.join(self.dir, "from-nospc.img")))
        self.assertEqual(self.diff(self.src, other, self.VOL, "--replaced-by", os.path.join(self.dir, "missing.bin")).returncode, 2)
        self.assertEqual(self.diff(self.src, other, "/not an 8.3 name.elf").returncode, 2)

    def test_diff_says_which_way_the_file_went(self):
        # The first volume is the one that holds the file; the second lacks it, or holds the
        # very bytes named. Each copy is judged by its own change and by no other.
        self.assertEqual(run("derive", self.src, self.dst, "--remove", self.VOL).returncode, 0)
        other, host = self.replaced_copy()
        wrong = self.host_file("wrong.bin", b"w" * 4000)
        own = self.host_file("own.bin", self.data[self.VOL])
        for a, b, how, why in ((self.src, other, ("--removed",), "B holds"),
                               (self.src, self.dst, ("--replaced-by", host), "B holds"),
                               (self.src, other, ("--replaced-by", wrong), "not the replacement"),
                               (self.dst, self.src, ("--removed",), "A holds"),
                               (self.dst, other, ("--replaced-by", host), "A holds"),
                               (self.src, self.src, ("--removed",), "B holds"),
                               (self.src, self.src, ("--replaced-by", own), "nothing differs")):
            with self.subTest(a=os.path.basename(a), b=os.path.basename(b), how=how):
                r = self.diff(a, b, self.VOL, *how)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(why, self.diff_line(r))

    def fresh_copy(self):
        """A new derived copy at the destination, whatever an earlier form of the case left there."""
        if os.path.lexists(self.dst):
            os.unlink(self.dst)
        return self.edit_copy()

    def edit_copy(self):
        self.assertEqual(run("derive", self.src, self.dst, "--remove", self.VOL).returncode, 0)
        self.assertEqual(self.diff(self.src, self.dst, self.VOL).returncode, 0)
        return self.tool.Image(self.dst, writable=True)

    def set_entry(self, img, vol, change):
        parent, name = vol.rsplit("/", 1)
        d = img.entry_cluster(img.resolve(parent)[1]) if parent else img.root_cluster
        c, i, e = img.lookup(d, name)
        e = bytearray(e)
        change(e)
        data = bytearray(img.read_cluster(c))
        data[i * 32:i * 32 + 32] = e
        img.write_cluster(c, bytes(data))

    def differs(self, name, *how, path=None):
        """`diff` fails and its own line names `name` among what differs or what it found."""
        r = self.diff(self.src, path or self.dst, self.VOL, *how)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(name, self.diff_line(r))

    def test_diff_fails_when_another_file_differs(self):
        img = self.edit_copy()
        first = img.entry_cluster(img.resolve("/SYSTEM/TAIL.TXT")[1])
        img.write_cluster(first, b"TAIL\n")
        img.close()
        self.differs("differ=['/SYSTEM/TAIL.TXT']")

    def test_diff_fails_on_another_size_attribute_or_time(self):
        for what, change in (("size", lambda e: struct.pack_into("<I", e, 28, 99)),
                             ("attribute", lambda e: e.__setitem__(11, e[11] | 0x01)),
                             ("time", lambda e: struct.pack_into("<H", e, 22, 0x6000))):
            with self.subTest(what=what):
                if os.path.exists(self.dst):
                    os.unlink(self.dst)
                img = self.edit_copy()
                self.set_entry(img, "/A.TXT", change)
                img.close()
                self.differs("'/A.TXT'")

    def test_diff_fails_when_the_file_differs_in_attributes_alone(self):
        # The replacement's bytes under other attributes or times, or the first volume's bytes
        # under other attributes: not the one change the call names.
        other, host = self.replaced_copy()
        self.assertEqual(self.diff(self.src, other, self.VOL, "--replaced-by", host).returncode, 0)
        img = self.tool.Image(other, writable=True)
        self.set_entry(img, self.VOL, lambda e: e.__setitem__(11, e[11] | 0x06))
        img.close()
        self.differs("attributes or times", "--replaced-by", host, path=other)
        shutil.copyfile(self.src, self.dst)
        img = self.tool.Image(self.dst, writable=True)
        self.set_entry(img, self.VOL, lambda e: e.__setitem__(11, e[11] | 0x06))
        img.close()
        self.differs("B holds", "--removed")
        self.differs("nothing differs", "--replaced-by", self.host_file("own.bin", self.data[self.VOL]))

    def test_diff_fails_on_a_file_or_a_directory_more(self):
        img = self.edit_copy()
        img.write_file(img.root_cluster, "MORE.TXT", b"more")
        self.tool.finish(img)
        img.close()
        self.differs("differ=['/MORE.TXT']")
        os.unlink(self.dst)
        img = self.edit_copy()
        img.make_dir(img.entry_cluster(img.resolve("/SYSTEM")[1]), "MORE")
        self.tool.finish(img)
        img.close()
        self.differs("differ=['/SYSTEM/MORE/', '/SYSTEM/MORE/(.)', '/SYSTEM/MORE/(..)']")

    def test_diff_fails_when_the_replacement_sits_on_another_files_clusters(self):
        # A replacement written by hand into NEXT.BIN's clusters: the named file has its new
        # bytes, and the file that held those clusters no longer has its own.
        shutil.copyfile(self.src, self.dst)
        img = self.tool.Image(self.dst, writable=True)
        target = img.entry_cluster(img.resolve("/SYSTEM/APPS/NEXT.BIN")[1])
        img.write_cluster(target, b"X" * 512)
        self.set_entry(img, self.VOL, lambda e: (struct.pack_into("<H", e, 20, target >> 16),
                                                 struct.pack_into("<H", e, 26, target & 0xFFFF),
                                                 struct.pack_into("<I", e, 28, 512)))
        img.close()
        self.assertEqual(run("verify", self.dst, self.VOL, hashlib.sha256(b"X" * 512).hexdigest()).returncode, 0)
        self.differs("'/SYSTEM/APPS/NEXT.BIN'", "--replaced-by", self.host_file("x.bin", b"X" * 512))

    def test_diff_does_not_merge_two_entries_with_one_name(self):
        # Two entries named NEXT.BIN on both volumes, the bytes of one of them changed on the
        # copy: a comparison that keeps one entry a name sees the same on both, whichever it
        # keeps. (Such volumes fail the check as well; what differs is named beside that.)
        twin = "/SYSTEM/APPS/TWIN.BIN"
        for changed in ("first", "second"):
            with self.subTest(changed=changed):
                for path in (self.src, self.dst):
                    if os.path.exists(path):
                        os.unlink(path)
                self.setUp_volume_with_twin(twin)
                self.assertEqual(run("derive", self.src, self.dst, "--remove", self.VOL).returncode, 0)
                first_next = self.place(self.dst, "/SYSTEM/APPS/NEXT.BIN")[0][0]
                first_twin = self.place(self.dst, twin)[0][0]
                for path in (self.src, self.dst):
                    self.rename_raw(path, twin, "NEXT.BIN")
                r = self.diff(self.src, self.dst, self.VOL)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("differ=[]", self.diff_line(r))
                img = self.tool.Image(self.dst, writable=True)
                img.write_cluster(first_next if changed == "first" else first_twin, b"changed")
                img.close()
                self.differs("differ=['/SYSTEM/APPS/NEXT.BIN']")

    def setUp_volume_with_twin(self, twin):
        hosts = {vol: self.host_file(f"t{k}.bin", data) for k, (vol, data) in enumerate(self.data.items())}
        hosts[twin] = self.host_file("twin.bin", b"N" * 1500)
        adds = [x for vol, host in hosts.items() for x in ("--add", f"{vol.lstrip('/')}={host}")]
        r = run("format", self.src, "--sectors", "16384", "--mkdir", "SYSTEM", "--mkdir", "SYSTEM/APPS", *adds)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_diff_takes_a_named_directory_for_no_file(self):
        # A directory under the name is not "the one file", on either volume.
        shutil.copyfile(self.src, self.dst)
        img = self.tool.Image(self.src, writable=True)
        img.make_dir(img.root_cluster, "EMPTY")
        self.tool.finish(img)
        img.close()
        r = self.diff(self.src, self.dst, "/EMPTY")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("A holds", self.diff_line(r))

    def test_diff_knows_a_name_by_its_bytes_and_not_by_how_it_reads(self):
        # The file's entry on the copy renamed to bytes that read as the same name (a control
        # character where a space pads the name): a reader that asks for the name finds no
        # such file, so this copy is not "the file replaced".
        other, host = self.replaced_copy()
        for raw in (b"CLOCK\x1f  ELF", b"CLOCK\x09  ELF", b"clock   elf"):
            with self.subTest(raw=raw):
                img = self.tool.Image(other, writable=True)
                d = img.entry_cluster(img.resolve("/SYSTEM/APPS")[1])
                hit = [(c, i) for c, i, e in img.dir_entries(d) if e[11] == 0x20 and struct.unpack_from("<I", e, 28)[0] == 4000]
                self.assertEqual(len(hit), 1)
                data = bytearray(img.read_cluster(hit[0][0]))
                data[hit[0][1] * 32:hit[0][1] * 32 + 11] = raw
                img.write_cluster(hit[0][0], bytes(data))
                img.close()
                self.differs("differ=[", "--replaced-by", host, path=other)
                r = self.diff(self.src, other, self.VOL, "--replaced-by", host)
                self.assertIn("B holds 0", self.diff_line(r))

    def test_diff_knows_another_files_name_by_its_bytes(self):
        # Another file's entry renamed on the copy to bytes that read as its name: no reader
        # finds /A.TXT there, so more than the one file differs.
        img = self.edit_copy()
        c, i, _ = img.lookup(img.root_cluster, "A.TXT")
        data = bytearray(img.read_cluster(c))
        data[i * 32:i * 32 + 11] = b"A\x1f      TXT"
        img.write_cluster(c, bytes(data))
        img.close()
        self.assertIn("A.TXT", run("ls", self.dst).stdout)
        self.differs("differ=['/A.TXT']")

    def mark_bad(self, path, count=3):
        """Marks `count` free clusters bad in every FAT copy and counts the free ones afresh."""
        img = self.tool.Image(path, writable=True)
        for c in [c for c in range(2, img.clusters + 2) if img.fat_get(c) == 0][:count]:
            img.fat_set(c, 0x0FFFFFF7)
        self.tool.finish(img)
        img.close()
        self.assertEqual(run("check", path).returncode, 0)

    def test_diff_fails_on_free_clusters_taken_from_the_copy(self):
        # Free clusters marked bad on the copy, in both FAT copies and with FSInfo to match:
        # a sound volume with the same files, on which a writer finds less room (none, were
        # they all marked).
        self.edit_copy().close()
        self.mark_bad(self.dst)
        self.differs("findings=['B has 16085 free clusters where the change leaves 16088'] differ=[]")
        other, host = self.replaced_copy()
        self.mark_bad(other)
        self.differs("free clusters where the change leaves", "--replaced-by", host, path=other)

    def swap_entries(self, path, directory, one, two):
        img = self.tool.Image(path, writable=True)
        d = img.entry_cluster(img.resolve(directory)[1]) if directory != "/" else img.root_cluster
        (c1, i1, e1), (c2, i2, e2) = img.lookup(d, one), img.lookup(d, two)
        for c, i, e in ((c1, i1, e2), (c2, i2, e1)):
            data = bytearray(img.read_cluster(c))
            data[i * 32:i * 32 + 32] = e
            img.write_cluster(c, bytes(data))
        img.close()
        self.assertEqual(run("check", path).returncode, 0)

    def test_diff_fails_on_another_order_of_entries(self):
        # A directory lists its entries in the order they lie in: two of them changing places
        # is seen by whoever lists it, with every entry and every byte the same.
        self.edit_copy().close()
        self.swap_entries(self.dst, "/", "SYSTEM", "A.TXT")
        self.differs("findings=['the entries lie in another order'] differ=[]")
        # The replaced file's entry is to stay where the file's was among the entries.
        other, host = self.replaced_copy()
        self.swap_entries(other, "/SYSTEM/APPS", "CLOCK.ELF", "NEXT.BIN")
        self.differs("findings=['the entries lie in another order'] differ=[]", "--replaced-by", host, path=other)

    def test_diff_fails_on_an_image_with_another_name(self):
        # A second name of the copy is a way to change it after it was judged.
        self.edit_copy().close()
        os.link(self.dst, os.path.join(self.dir, "second-name.img"))
        self.differs("B has 2 names")
        os.unlink(os.path.join(self.dir, "second-name.img"))
        self.assertEqual(self.diff(self.src, self.dst, self.VOL).returncode, 0)

    def test_a_name_that_is_not_ascii_is_no_name(self):
        # A letter that upper-cases to an ASCII one (the long s) names no file: the record
        # would say one name and the tool would act on another.
        vol = "/\u017fYSTEM/APPS/CLOCK.ELF"
        self.assertEqual("\u017f".upper(), "S")
        self.refused(self.src, self.dst, "--remove", vol)
        self.refused(self.src, self.dst, "--replace", f"{vol}={self.host_file('good.bin', b'g')}")
        self.edit_copy().close()
        r = self.diff(self.src, self.dst, vol)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def poke(self, path, offset, data):
        with open(path, "r+b") as f:
            f.seek(offset)
            f.write(data)

    def test_diff_fails_on_another_boot_sector_or_length(self):
        other, host = self.replaced_copy()
        how = ("--replaced-by", host)
        pristine = os.path.join(self.dir, "pristine.img")
        shutil.copyfile(other, pristine)
        # A boot sector no reader takes (the signatures), on the copy alone.
        for offset, data in ((66, b"\0"), (510, b"\0\0")):
            with self.subTest(offset=offset):
                shutil.copyfile(pristine, other)
                self.poke(other, offset, data)
                self.differs("B fails the check", *how, path=other)
        # Another boot sector that is sound in itself (both copies of it say the same).
        shutil.copyfile(pristine, other)
        for sector in (0, 6):
            self.poke(other, sector * 512 + 3, b"OTHEROEM")
        self.assertEqual(run("check", other).returncode, 0)
        self.differs("the boot sectors differ", *how, path=other)
        # Another length with every sector the volume counts the same.
        shutil.copyfile(pristine, other)
        with open(other, "ab") as f:
            f.write(bytes(512))
        self.assertEqual(run("check", other).returncode, 0)
        self.differs("the images differ in length", *how, path=other)
        shutil.copyfile(pristine, other)
        self.assertEqual(self.diff(self.src, other, self.VOL, *how).returncode, 0)

    def test_diff_fails_on_a_copy_that_fails_the_check(self):
        # Free clusters up to cluster 601 marked in the first FAT copy alone: the tree and
        # every file are the same, and a writer finds less room.
        img = self.edit_copy()
        for c in range(2, img.clusters + 2):
            if img.fat_get(c) == 0:
                off = c * 4
                sec = img.fat_start + off // 512
                s = bytearray(img.read_sector(sec))
                s[off % 512:off % 512 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
                img.write_sector(sec, bytes(s))
                if c > 600:
                    break
        img.close()
        r = self.diff(self.src, self.dst, self.VOL)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("findings=['B fails the check', 'B has 15496 free clusters where the change leaves 16088'] differ=[]", self.diff_line(r))
        # One cluster marked in the second FAT copy alone: nothing a reader of the first copy
        # meets differs, and the volume is not sound.
        os.unlink(self.dst)
        img = self.edit_copy()
        c = next(c for c in range(2, img.clusters + 2) if img.fat_get(c) == 0)
        off = c * 4
        sec = img.fat_start + img.fatsz + off // 512
        s = bytearray(img.read_sector(sec))
        s[off % 512:off % 512 + 4] = (0x0FFFFFFF).to_bytes(4, "little")
        img.write_sector(sec, bytes(s))
        img.close()
        self.differs("findings=['B fails the check'] differ=[]")

    def test_diff_fails_on_bytes_after_a_directorys_end_mark(self):
        # An entry of the removed file's name planted after the end mark of its directory: no
        # reader meets it today, and the next file made in that directory brings it back.
        for slot in (0, 1):
            with self.subTest(slot=slot):
                if os.path.exists(self.dst):
                    os.unlink(self.dst)
                img = self.edit_copy()
                d = img.entry_cluster(img.resolve("/SYSTEM/APPS")[1])
                end = next((c, i) for c, i, e in img.dir_entries(d) if e[0] == 0)
                planted = img.make_entry("CLOCK.ELF", 0x20, img.entry_cluster(img.resolve("/SYSTEM/APPS/NEXT.BIN")[1]), 5)
                if slot == 0:
                    planted = b"\0" + planted[1:]
                data = bytearray(img.read_cluster(end[0]))
                data[(end[1] + slot) * 32:(end[1] + slot + 1) * 32] = planted
                img.write_cluster(end[0], bytes(data))
                img.close()
                self.assertEqual(run("cat", self.dst, self.VOL).returncode, 2)
                self.differs("bytes after the end mark of /SYSTEM/APPS on B")

    def test_derive_on_larger_clusters_in_the_root_and_on_an_empty_file(self):
        src = os.path.join(self.dir, "wide.img")
        root = bytes((i * 13 + 1) & 0xFF for i in range(9000))
        r = run("format", src, "--sectors", "32768", "--spc", "8", "--add", f"ROOT.BIN={self.host_file('root.bin', root)}",
                "--add", f"ZERO.BIN={self.host_file('zero.bin', b'')}", "--add", f"LAST.TXT={self.host_file('last.txt', b'last')}")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        sha = self.sha(src)
        new = self.host_file("new.bin", b"n" * 20000)
        for k, (change, vol, how) in enumerate(((("--remove", "/ROOT.BIN"), "/ROOT.BIN", ("--removed",)),
                                                (("--replace", f"/ROOT.BIN={new}"), "/ROOT.BIN", ("--replaced-by", new)),
                                                (("--remove", "/ZERO.BIN"), "/ZERO.BIN", ("--removed",)),
                                                (("--replace", f"/ZERO.BIN={new}"), "/ZERO.BIN", ("--replaced-by", new)))):
            with self.subTest(change=change):
                dst = os.path.join(self.dir, f"wide{k}.img")
                r = run("derive", src, dst, *change)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(self.sha(src), sha)
                self.sound(dst)
                r = run("diff", src, dst, "--expect-only", vol, *how)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(run("expect", dst, "/LAST.TXT", "last").returncode, 0)
                if change[0] == "--remove" and vol == "/ROOT.BIN":
                    with open(dst, "rb") as f:
                        self.assertNotIn(root[:256], f.read())

    def test_a_replacement_by_the_files_own_bytes_is_refused(self):
        self.refused(self.src, self.dst, "--replace", f"{self.VOL}={self.host_file('own.bin', self.data[self.VOL])}")

    def test_a_destination_with_no_directory_is_refused(self):
        self.refused(self.src, os.path.join(self.dir, "nodir", "copy.img"), "--remove", self.VOL)
        self.refused(self.src, os.path.join(self.dir, "newdir") + os.sep, "--remove", self.VOL)

    def killed_midway(self, at):
        """Runs `derive --remove` in a process that dies, with no word, when it reaches `at`."""
        script = self.host_file("die.py", (
            "import importlib.util, os, sys\n"
            "spec = importlib.util.spec_from_file_location('fat32_tool', sys.argv[1])\n"
            "tool = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(tool)\n"
            f"tool.Image.{at} = lambda *a, **k: os._exit(9)\n"
            "sys.exit(tool.main(['derive', sys.argv[2], sys.argv[3], '--remove', sys.argv[4]]))\n").encode())
        r = subprocess.run([sys.executable, "-I", script, TOOL, self.src, self.dst, self.VOL], capture_output=True, text=True)
        self.assertEqual(r.returncode, 9, r.stdout + r.stderr)

    def test_a_derivation_that_dies_midway_leaves_no_destination(self):
        # Killed after the file's chain is freed and before its entry is cleared: a volume on
        # which the file is still named, with zeros for bytes. No such thing bears the destination's name.
        before = set(os.listdir(self.dir))
        for at in ("set_entry", "free_chain"):
            with self.subTest(at=at):
                self.killed_midway(at)
                self.assertFalse(os.path.lexists(self.dst))
                left = set(os.listdir(self.dir)) - before - {"die.py"}
                self.assertTrue(all(name.startswith(".derive-") for name in left), left)
                self.assertEqual(self.sha(self.src), self.src_sha)
        r = run("derive", self.src, self.dst, "--remove", self.VOL)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(os.stat(self.dst).st_nlink, 1)
        self.assertEqual(self.diff(self.src, self.dst, self.VOL).returncode, 0)

    def test_an_interrupt_after_the_link_leaves_the_finished_copy_alone(self):
        # The copy is given its name before the working name goes. An interrupt between the two
        # ends the call with the interrupt's own failure, and the clean-up still runs: the
        # finished, checked copy stands under the destination's name alone. (A kill by another
        # signal there runs no clean-up and leaves two names; no case tries that.)
        script = self.host_file("interrupt.py", (
            "import importlib.util, os, sys\n"
            "spec = importlib.util.spec_from_file_location('fat32_tool', sys.argv[1])\n"
            "tool = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(tool)\n"
            "link = os.link\n"
            "def linked(*a, **k):\n"
            "    link(*a, **k)\n"
            "    raise KeyboardInterrupt\n"
            "os.link = linked\n"
            "sys.exit(tool.main(['derive', sys.argv[2], sys.argv[3], '--remove', sys.argv[4]]))\n").encode())
        before = set(os.listdir(self.dir))
        r = subprocess.run([sys.executable, "-I", script, TOOL, self.src, self.dst, self.VOL], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(set(os.listdir(self.dir)) - before, {os.path.basename(self.dst)})
        self.assertEqual(os.stat(self.dst).st_nlink, 1)
        self.assertIn("KeyboardInterrupt", r.stderr)
        self.assertEqual(run("check", self.dst).returncode, 0)
        self.assertEqual(self.diff(self.src, self.dst, self.VOL).returncode, 0)
        self.assertEqual(self.sha(self.src), self.src_sha)

    def in_process(self, hook):
        """`derive --remove` in this process, `hook` run once when the file's chain is freed."""
        freed = self.tool.Image.free_chain

        def free_chain(img, first):
            hook()
            return freed(img, first)
        self.tool.Image.free_chain = free_chain
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.tool.cmd_derive(argparse.Namespace(src=self.src, dst=self.dst, remove=self.VOL, replace=None))
        return code, out.getvalue()

    def test_a_destination_that_appears_during_the_derivation_is_not_written(self):
        # A link to the source put at the destination's path while the copy is being changed:
        # the path is never opened, so the source keeps its bytes, and what appeared is not removed.
        code, out = self.in_process(lambda: os.symlink(self.src, self.dst))
        self.assertEqual(code, 2, out)
        self.assertIn("derive: refused: the destination", out)
        self.assertEqual(os.readlink(self.dst), self.src)
        self.assertEqual(self.sha(self.src), self.src_sha)
        self.assertEqual([n for n in os.listdir(self.dir) if n.startswith(".derive-")], [])

    def test_a_working_file_swapped_for_the_source_is_not_given_as_the_copy(self):
        # The working file's name given to the source itself (a hard link) while the copy is
        # being changed: what the destination's name then reaches is not the copy that was
        # made, and the call says so; the source keeps its bytes.
        def swap():
            part = [n for n in os.listdir(self.dir) if n.startswith(".derive-")]
            self.assertEqual(len(part), 1)
            os.unlink(os.path.join(self.dir, part[0]))
            os.link(self.src, os.path.join(self.dir, part[0]))
        code, out = self.in_process(swap)
        self.assertEqual(code, 1, out)
        self.assertIn("derive: the destination is not the copy that was made", out)
        self.assertEqual(self.sha(self.src), self.src_sha)

if __name__ == "__main__":
    unittest.main(verbosity=2)
