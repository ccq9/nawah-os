#!/usr/bin/env python3
"""TST-M3-FAT32-TOOL: the host-side FAT32 tool (tools/fat32.py) formats a volume that it reads
back exactly, that passes its own structural check and, where dosfstools is installed, fsck.fat.
The tool is the independent implementation the kernel's FAT32 is checked against."""
import hashlib
import importlib.util
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
