"""TST-M5-SCREEN-TOOL (host): tools/screen.py `desktop` against a synthetic PPM — a pixel check
passes on its colour and fails on another; a window hash equals the FNV-1a 64 the compositor's
rule gives for the same bytes and fails for a changed pixel; a rectangle outside the image is
a failure, never a crash; (WP-42) an ink check finds a field's text against the side asked
and fails for the other side, for an empty field and for a rectangle outside the image."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "screen.py"


def ppm(w, h, fill):
    px = bytearray()
    for y in range(h):
        for x in range(w):
            r, g, b = fill(x, y)
            px += bytes((r, g, b))
    return b"P6\n%d %d\n255\n" % (w, h) + bytes(px)


def fnv(data):
    v = 0xcbf29ce484222325
    for b in data:
        v = ((v ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return v


class ScreenDesktop(unittest.TestCase):
    def run_tool(self, img, *args):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "s.ppm"
            p.write_bytes(img)
            r = subprocess.run([sys.executable, "-I", str(TOOL), "desktop", str(p), *args], capture_output=True, text=True)
            return r.returncode, json.loads(r.stdout)

    def test_pixels_and_window_hash(self):
        # 40x30: orange everywhere, a 10x8 blue block at (12,10).
        def fill(x, y):
            return (0x22, 0x55, 0xCC) if 12 <= x < 22 and 10 <= y < 18 else (0xFF, 0x88, 0x00)
        img = ppm(40, 30, fill)
        block = b"".join(bytes((0x22, 0x55, 0xCC)) for _ in range(10 * 8))
        want = "%016x" % fnv(block)
        rc, out = self.run_tool(img, "--pixel", "3,3,FF8800", "--pixel", "15,12,2255CC", "--window", f"12,10,10,8,{want}")
        self.assertEqual(rc, 0, out)
        self.assertTrue(all(p["ok"] for p in out["pixels"]))
        self.assertTrue(out["windows"][0]["ok"])
        rc, out = self.run_tool(img, "--pixel", "3,3,2255CC")
        self.assertEqual(rc, 1)
        self.assertFalse(out["pixels"][0]["ok"])
        # One pixel of the block changed: the hash no longer matches.
        rc, out = self.run_tool(img, "--window", f"12,10,10,9,{want}")
        self.assertEqual(rc, 1)
        self.assertFalse(out["windows"][0]["ok"])

    def test_ink_side(self):
        # A 60x16 field at (10,10): 1 px grey border, white inside, a 12x6 black run of "text"
        # 4 px from its right edge.
        def fill(x, y):
            if not (10 <= x < 70 and 10 <= y < 26):
                return (0xF0, 0xF0, 0xF0)
            if x in (10, 69) or y in (10, 25):
                return (0x80, 0x80, 0x80)
            if 54 <= x < 66 and 15 <= y < 21:
                return (0x00, 0x00, 0x00)
            return (0xFF, 0xFF, 0xFF)
        img = ppm(80, 40, fill)
        rc, out = self.run_tool(img, "--ink", "10,10,60,16,right")
        self.assertEqual(rc, 0, out)
        self.assertEqual((out["inks"][0]["ink_x0"], out["inks"][0]["ink_x1"], out["inks"][0]["count"]), (54, 65, 72))
        rc, out = self.run_tool(img, "--ink", "10,10,60,16,left")
        self.assertEqual(rc, 1)
        empty = ppm(80, 40, lambda x, y: (0xFF, 0xFF, 0xFF))
        rc, out = self.run_tool(empty, "--ink", "10,10,60,16,right")
        self.assertEqual((rc, out["inks"][0]["count"]), (1, 0))
        rc, out = self.run_tool(img, "--ink", "50,30,60,16,right")
        self.assertEqual(rc, 1)

    def test_rectangle_outside_image_fails(self):
        img = ppm(8, 8, lambda x, y: (0, 0, 0))
        rc, out = self.run_tool(img, "--window", "4,4,8,8,0000000000000000")
        self.assertEqual(rc, 1)
        self.assertIsNone(out["windows"][0]["seen"])


if __name__ == "__main__":
    unittest.main()
