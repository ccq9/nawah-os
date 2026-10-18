#!/usr/bin/env python3
"""TST-M3-FAT32-TOOL: the host-side FAT32 tool (tools/fat32.py) formats a volume that it reads
back exactly, that passes its own structural check and, where dosfstools is installed, fsck.fat.
The tool is the independent implementation the kernel's FAT32 is checked against."""
import hashlib
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

    def test_fsck(self):
        fsck = shutil.which("fsck.fat")
        if not fsck:
            self.skipTest("dosfstools not installed")
        r = subprocess.run([fsck, "-n", self.img], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("44/128992 clusters", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
