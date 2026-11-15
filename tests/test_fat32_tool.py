#!/usr/bin/env python3
"""TST-M3-FAT32-TOOL: the host-side FAT32 tool (tools/fat32.py) formats a volume that it reads
back exactly, that passes its own structural check and, where dosfstools is installed, fsck.fat.
The tool is the independent implementation the kernel's FAT32 is checked against."""
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "fat32.py")


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
        self.assertEqual(run("check", "--faulted", "--expect-lost", "1", self.img).returncode, 0)
        for n in ("0", "2"):
            r = run("check", "--faulted", "--expect-lost", n, self.img)
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
        r = run("check", "--faulted", "--allow-longer", "1", self.img)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("longer=1", r.stdout)
        self.assertIn("problems=[]", r.stdout)
        for n in ("0", "2"):
            r = run("check", "--faulted", "--allow-longer", n, self.img)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("chains longer than size: 1", r.stdout)
            self.assertIn("/ONE.TXT", r.stdout)

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

    def set_entry(self, img, name, first, size=None):
        """Rewrites the root directory entry NAME in place: its first cluster, and its size
        when one is given."""
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
                img.write_cluster(img.root_cluster, bytes(data))
                return
        self.fail(f"no root entry {name}")

    def test_directory_entry_whose_first_cluster_is_no_cluster(self):
        # A directory has no size: with a first cluster of 0 or 1 the walk found nothing to
        # read and called it empty; only the lost count, in plain mode, hinted at it.
        for first in (0, 1):
            path = self.with_dirs("D1", files=["D1/IN.TXT"])
            img = self.tool.Image(path, writable=True)
            self.set_entry(img, "D1", first)
            img.close()
            for mode in ([], ["--faulted"]):
                r = run("check", *mode, path)
                self.assertEqual(r.returncode, 1, (first, mode, r.stdout))
                self.assertIn(f"/D1: first cluster {first}", r.stdout, (first, mode))
            os.remove(path)

    def test_file_entry_whose_first_cluster_is_no_cluster(self):
        # 0 is the first cluster of an empty file and of nothing else; 1 is no cluster at all.
        for first, size in ((1, 0), (1, 100)):
            img = self.image()
            saved = img.read_cluster(img.root_cluster)
            self.set_entry(img, "ONE.TXT", first, size)
            img.close()
            for mode in ([], ["--faulted"]):
                r = run("check", *mode, self.img)
                self.assertEqual(r.returncode, 1, (first, size, mode, r.stdout))
                self.assertIn(f"/ONE.TXT: first cluster {first}", r.stdout, (first, size, mode))
            img = self.image()
            img.write_cluster(img.root_cluster, saved)
            img.close()
        self.assertEqual(run("check", self.img).returncode, 0)

    def test_reserved_value_in_a_chain_of_the_second_copy(self):
        # The value 1 is no cluster and no end mark. In the second copy alone it ended a walk
        # quietly: at a directory's cluster, and at a file's last cluster in place of the mark.
        path = self.with_dirs("D1", files=["D1/IN.TXT"])
        img = self.tool.Image(path, writable=True)
        self.set_one_copy(img, img.entry_cluster(img.resolve("/D1")[1]), 1, 1)
        img.close()
        r = run("check", "--faulted", path)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAT1: /D1: its chain holds the reserved value 1", r.stdout)
        img = self.image()
        last = img.chain(self.first(img, "BIG.BIN"))[-1]
        self.set_one_copy(img, last, 1, 1)
        img.close()
        r = run("check", "--faulted", self.img)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAT1: /BIG.BIN: its chain holds the reserved value 1", r.stdout)

    def test_reserved_value_in_a_chain_of_the_first_copy_names_the_file(self):
        img = self.image()
        last = img.chain(self.first(img, "BIG.BIN"))[-1]
        self.set_one_copy(img, last, 1, 0)
        img.close()
        for mode in ([], ["--faulted"]):
            r = run("check", *mode, self.img)
            self.assertEqual(r.returncode, 1, (mode, r.stdout))
            self.assertIn("/BIG.BIN: its chain holds the reserved value 1", r.stdout, mode)

    def test_invalid_value_outside_every_chain_in_the_second_copy(self):
        # The scan for reserved and out-of-range values read the first copy only.
        for value in (1, 0x0FFFFFF0):
            img = self.image()
            self.set_one_copy(img, 5000, value, 1)
            img.close()
            r = run("check", "--faulted", self.img)
            self.assertEqual(r.returncode, 1, (value, r.stdout))
            self.assertIn(f"FAT1[5000] = {value:#x} invalid", r.stdout, value)
            img = self.image()
            self.set_one_copy(img, 5000, 0, 1)
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
