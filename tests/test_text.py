"""The text layer's host tests (WP-35, text.md): nawah-text against independent references.

  Bidi    (TST-M5-BIDI)    UAX #9 on all of BidiCharacterTest-17.0.0 (the Unicode
                           conformance data); the generated tables are current.
  Glyphs  (TST-M5-GLYPHS)  the OpenType reader against fontTools on the shipped fonts (every
                           cmap entry, every glyph's metrics and outline); the rasteriser
                           against a reference written here (same sampling rule, independent
                           contour walk and flattening through fontTools' pens).
  Shaping (TST-M5-SHAPING) Arabic shaping against HarfBuzz (hb-shape) on the shipped Arabic
                           font; the joining forms; the library's own unit tests (mixed
                           direction lines worked out by hand from UAX #9).

The references are system packages (python3-fonttools, libharfbuzz-bin); the library is
driven through its host examples (user/libnawah-text/examples)."""

import lzma
import math
import os
import pathlib
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FONTS = ROOT / "platform" / "assets" / "fonts"
LATIN = FONTS / "NotoSans-Regular.ttf"
ARABIC = FONTS / "NotoSansArabic-Regular.ttf"
UCD = ROOT / "user" / "libnawah-text" / "ucd"
EXAMPLES = ROOT / "target" / "x86_64-unknown-linux-gnu" / "release" / "examples"
CARGO = ["cargo", "build", "--offline", "--release", "-p", "nawah-text", "--target", "x86_64-unknown-linux-gnu", "--examples"]


def setUpModule():
    subprocess.run(CARGO, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    import fontTools
    hb = subprocess.run(["hb-shape", "--version"], capture_output=True, text=True).stdout.splitlines()
    print(f"references: fontTools {fontTools.version}; {hb[0] if hb else 'hb-shape missing'}")


def textdump(commands):
    """One answer line per command line (examples/textdump.rs)."""
    r = subprocess.run([str(EXAMPLES / "textdump"), str(LATIN), str(ARABIC)], input="\n".join(commands) + "\n",
                       capture_output=True, text=True, check=True)
    return r.stdout.splitlines()


def hexes(text):
    return " ".join("%x" % ord(c) for c in text)


class Bidi(unittest.TestCase):
    def test_tables_are_current(self):
        r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "unicode_tables.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_bidi_character_test(self):
        with tempfile.TemporaryDirectory() as td:
            data = pathlib.Path(td) / "BidiCharacterTest.txt"
            data.write_bytes(lzma.decompress((UCD / "BidiCharacterTest.txt.xz").read_bytes()))
            head = data.read_text(encoding="utf-8").splitlines()[0]
            self.assertIn("BidiCharacterTest-17.0.0", head)
            r = subprocess.run([str(EXAMPLES / "bidi_check"), str(data)], capture_output=True, text=True)
        print(r.stdout.splitlines()[-1])
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        self.assertIn("lines=91707 pass=91707 fail=0", r.stdout)


class Glyphs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fontTools.ttLib import TTFont
        cls.fonts = {"latin": TTFont(str(LATIN)), "arabic": TTFont(str(ARABIC))}

    def test_cmap(self):
        for name, f in self.fonts.items():
            cmap = f.getBestCmap()
            cps = sorted(cmap)
            got = textdump(["cmap %s %s" % (name, " ".join("%x" % c for c in cps))])[0].split()
            want = [str(f.getGlyphID(cmap[c])) for c in cps]
            self.assertEqual(len(got), len(want))
            bad = [(hex(c), g, w) for c, g, w in zip(cps, got, want) if g != w]
            self.assertEqual(bad, [], name)
            # Code points the font lacks map to .notdef.
            missing = [c for c in (0x10FFFF, 0xE000, 0x1F600) if c not in cmap]
            got = textdump(["cmap %s %s" % (name, " ".join("%x" % c for c in missing))])[0].split()
            self.assertEqual(got, ["0"] * len(missing))
            print(f"{name}: cmap {len(cps)} code points equal")

    def test_metrics(self):
        for name, f in self.fonts.items():
            order = f.getGlyphOrder()
            hm = f["hmtx"]
            got = textdump(["metrics %s %s" % (name, " ".join(map(str, range(len(order)))))])[0].split()
            want = ["%d,%d" % tuple(hm[g]) for g in order]
            self.assertEqual(got, want, name)
            print(f"{name}: metrics of {len(order)} glyphs equal")

    def test_outlines(self):
        for name, f in self.fonts.items():
            order = f.getGlyphOrder()
            glyf = f["glyf"]
            lines = textdump(["outline %s %d" % (name, g) for g in range(len(order))])
            bad = []
            for gid, line in enumerate(lines):
                status, ends, pts = line.split(" ; ")
                coords, endpts, flags = glyf[order[gid]].getCoordinates(glyf)
                want = [(round(x), round(y), flags[i] & 1) for i, (x, y) in enumerate(coords)]
                mine = [tuple(map(int, p.split(","))) for p in pts.split()]
                if status != "ok" or [int(e) for e in ends.split()] != [e + 1 for e in endpts] or mine != want:
                    bad.append(gid)
            self.assertEqual(bad, [], name)
            print(f"{name}: outlines of {len(order)} glyphs equal (composites resolved)")

    # The reference rasteriser: the sampling rule of raster.rs (4×4 samples at (i+½)/4,
    # non-zero winding, edges half-open in y, coordinates floored to 1/64 px) with fontTools'
    # contour walk (implied on-curve points) and 64-segment float flattening.
    @staticmethod
    def reference(font, gname, px, segs=64):
        from fontTools.pens.basePen import decomposeQuadraticSegment
        from fontTools.pens.recordingPen import DecomposingRecordingPen
        gs = font.getGlyphSet()
        pen = DecomposingRecordingPen(gs)
        gs[gname].draw(pen)
        upem = font["head"].unitsPerEm

        def T(p):
            return (math.floor(p[0] * px * 64 / upem) / 64, -math.floor(p[1] * px * 64 / upem) / 64)

        edges, cur, start = [], None, None
        for op, args in pen.value:
            if op == "moveTo":
                cur = start = T(args[0])
            elif op == "lineTo":
                p = T(args[0]); edges.append((cur, p)); cur = p
            elif op == "qCurveTo":
                pts = [a for a in args if a is not None]
                for c, e in decomposeQuadraticSegment(pts):
                    p0, c1, p2 = cur, T(c), T(e)
                    prev = p0
                    for k in range(1, segs + 1):
                        t = k / segs; mt = 1 - t
                        q = (mt * mt * p0[0] + 2 * mt * t * c1[0] + t * t * p2[0], mt * mt * p0[1] + 2 * mt * t * c1[1] + t * t * p2[1])
                        edges.append((prev, q)); prev = q
                    cur = p2
            elif op in ("closePath", "endPath"):
                if cur != start:
                    edges.append((cur, start))
                cur = start
        cov = {}
        if not edges:
            return cov
        xs = [p[0] for e in edges for p in e]; ys = [p[1] for e in edges for p in e]
        for py in range(math.floor(min(ys)) - 1, math.ceil(max(ys)) + 1):
            for j in range(4):
                sy = py + (j + 0.5) / 4
                cr = []
                for a, b in edges:
                    if a[1] == b[1]:
                        continue
                    lo, hi, d = (a[1], b[1], 1) if a[1] < b[1] else (b[1], a[1], -1)
                    if lo <= sy < hi:
                        cr.append((a[0] + (b[0] - a[0]) * (sy - a[1]) / (b[1] - a[1]), d))
                cr.sort()
                for pxl in range(math.floor(min(xs)) - 1, math.ceil(max(xs)) + 1):
                    for i in range(4):
                        sx = pxl + (i + 0.5) / 4
                        if sum(d for x, d in cr if x <= sx) != 0:
                            cov[(pxl, py)] = cov.get((pxl, py), 0) + 1
        return cov

    def test_rasteriser(self):
        sizes = (12, 16, 24, 48)
        sets = {"latin": "agR@&8%Wxyz", "arabic": "شعكهلبيحسصط"}
        cmds, keys = [], []
        for name, chars in sets.items():
            cmap = self.fonts[name].getBestCmap()
            for ch in chars:
                for px in sizes:
                    cmds.append("raster %s %d %d" % (name, self.fonts[name].getGlyphID(cmap[ord(ch)]), px))
                    keys.append((name, cmap[ord(ch)], px))
        answers = textdump(cmds)
        total_ref = total_mine = differing = flips = worst = 0
        for (name, gname, px), line in zip(keys, answers):
            f = line.split()
            self.assertNotEqual(f[0], "bad", (name, gname, px))
            w, h, left, top = map(int, f[:4])
            vals = list(map(int, f[4].split(","))) if len(f) > 4 else []
            mine = {(left + x, -top + y): vals[y * w + x] for y in range(h) for x in range(w) if vals[y * w + x]}
            ref = self.reference(self.fonts[name], gname, px)
            for k in set(ref) | set(mine):
                a, b = ref.get(k, 0), mine.get(k, 0)
                if a != b:
                    differing += 1
                    worst = max(worst, abs(a - b))
                    if a in (0, 16) and b in (0, 16):
                        flips += 1
            total_ref += sum(ref.values()); total_mine += sum(mine.values())
        rel = abs(total_ref - total_mine) / total_ref
        print(f"rasteriser: {len(keys)} bitmaps, {differing} edge pixels differ, worst {worst}/16, "
              f"full/empty flips {flips}, coverage {total_mine} vs {total_ref} ({rel:.4%})")
        # Differences may only come from where the flattening (1/64 px tolerance) and the
        # crossing rounding (1/64 px) put an edge on the other side of a sample point: never a
        # whole pixel, at most a quarter of one, and the ink within 1%.
        self.assertEqual(flips, 0)
        self.assertLessEqual(worst, 4)
        self.assertLess(rel, 0.01)


class Shaping(unittest.TestCase):
    LETTERS = [chr(c) for c in range(0x621, 0x64B)] + ["پ", "چ", "ژ", "ک", "گ", "ی"]
    MARKS = ["َ", "ُ", "ِ", "ّ", "ْ", "ً"]

    @staticmethod
    def harfbuzz(texts):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as t:
            t.write("\n".join(texts) + "\n")
            name = t.name
        try:
            r = subprocess.run(["hb-shape", "--font-file", str(ARABIC), "--direction=rtl", "--script=arab", "--language=ar",
                                "--no-glyph-names", "--no-positions", "--no-clusters", "--text-file", name],
                               capture_output=True, text=True, check=True)
        finally:
            os.unlink(name)
        # hb-shape prints right-to-left runs in visual order: back to logical.
        return [list(reversed(x.strip().strip("[]").split("|"))) for x in r.stdout.splitlines()]

    def cases(self):
        rng = random.Random(17)
        L = self.LETTERS
        words = ["السلام", "عليكم", "مرحبا", "بالعالم", "لا", "الله", "مستشفى", "يكتبون", "مسؤول", "لأن", "إلى", "آمن",
                 "لإ", "فلاح", "مصطفى", "موسيقى", "شيء", "ماء", "ه", "اه", "هه", "ﻻ"]
        words += [a + b for a in L for b in L]
        words += ["".join(rng.choice(L) for _ in range(rng.randint(3, 7))) for _ in range(1500)]
        words += [" ".join("".join(rng.choice(L) for _ in range(rng.randint(1, 5))) for _ in range(4)) for _ in range(200)]
        with_marks = ["".join(rng.choice(L) + (rng.choice(self.MARKS) if rng.random() < 0.5 else "") for _ in range(4))
                      for _ in range(300)]
        return words, with_marks

    def test_glyphs_equal_harfbuzz(self):
        words, with_marks = self.cases()
        for label, texts in (("letters", words), ("letters+marks", with_marks)):
            mine = [x.split() for x in textdump(["shape " + hexes(t) for t in texts])]
            ref = self.harfbuzz(texts)
            bad = [(t, a, b) for t, a, b in zip(texts, mine, ref) if a != b]
            print(f"shaping {label}: {len(texts) - len(bad)}/{len(texts)} equal to HarfBuzz")
            self.assertEqual(bad[:5], [])

    @staticmethod
    def harfbuzz_clusters(texts, direction="rtl"):
        """Per text, {cluster: glyph id} from hb-shape (the first glyph of each cluster)."""
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as t:
            t.write("\n".join(texts) + "\n")
            name = t.name
        try:
            r = subprocess.run(["hb-shape", "--font-file", str(ARABIC), f"--direction={direction}", "--script=arab",
                                "--language=ar", "--no-glyph-names", "--no-positions", "--text-file", name],
                               capture_output=True, text=True, check=True)
        finally:
            os.unlink(name)
        out = []
        for line in r.stdout.splitlines():
            m = {}
            items = line.strip().strip("[]").split("|")
            # hb-shape prints right-to-left runs in visual order: back to logical, so the
            # first glyph of a cluster is its letter, not a mark HarfBuzz merged into it.
            if direction == "rtl":
                items.reverse()
            for item in items:
                gid, cluster = item.split("=")
                # HarfBuzz draws joiners and spaces as glyph 3 and may put a joiner in the
                # letter's cluster: only the letter's own glyph is kept.
                if gid != "3":
                    m.setdefault(int(cluster), gid)
            out.append(m)
        return out

    @staticmethod
    def arabic_letters(text):
        """Indices of the characters whose glyph is compared: Arabic letters (not joiners, marks, spaces)."""
        return [i for i, c in enumerate(text) if 0x620 <= ord(c) <= 0x64A or ord(c) in (0x67E, 0x686, 0x698, 0x6A9, 0x6AF, 0x6CC)]

    def all_joiner_pairs(self):
        return [a + z + b for z in ("\u200d", "\u200c") for a in self.LETTERS for b in self.LETTERS]

    def test_joiners(self):
        # ZWJ/ZWNJ in the shaper: the forms around them equal HarfBuzz's for every letter pair
        # (2 × 48 × 48; review M6 found the 50-pair samples missed cases). HarfBuzz draws the
        # joiner itself as a glyph the layout drops (X9), so position 1 is not compared.
        texts = self.all_joiner_pairs()
        mine = [x.split() for x in textdump(["shape " + hexes(t) for t in texts])]
        ref = self.harfbuzz(texts)
        bad = [(t, a, b) for t, a, b in zip(texts, mine, ref) if len(a) != 3 or len(b) != 3 or (a[0], a[2]) != (b[0], b[2])]
        print(f"shaper joiners: {len(texts) - len(bad)}/{len(texts)} equal to HarfBuzz")
        self.assertEqual(bad[:5], [])

    def test_layout_joiners(self):
        # The line layout — the path every drawn text takes — keeps a joiner inside its Arabic
        # run, so the forms around it equal HarfBuzz's: ZWJ joins, ZWNJ separates, for every
        # letter pair. Review M6: the joiner took the Latin font and split the run, so a ZWJ
        # pair was drawn isolated. The joiner itself is removed (X9) and draws nothing.
        texts = self.all_joiner_pairs()
        lines = textdump(["layout rtl 16 " + hexes(t) for t in texts])
        mine = [[g.split(":")[1] for g in reversed(x.split(" | ")[1].split())] for x in lines]
        ref = self.harfbuzz(texts)
        bad = [(t, a, b) for t, a, b in zip(texts, mine, ref) if len(b) != 3 or a != [b[0], b[2]]]
        print(f"layout joiners: {len(texts) - len(bad)}/{len(texts)} equal to HarfBuzz")
        self.assertEqual(bad[:5], [])

    def test_layout_joiner_edges(self):
        # A joiner with no Arabic letter before it — first in the line, after a space, a digit
        # or a Latin letter — still joins the letter after it (review M6: the letter stayed
        # isolated), and the usual combinations hold: consecutive joiners, a joiner with a mark,
        # at the end, lam-joiner-alef, tatweel, a Persian ZWNJ word, both paragraph directions.
        # Compared: the glyph of every Arabic letter, by its character index, with HarfBuzz's.
        lines = ["\u200dب", "ب \u200dب", "\u200d\u200dب", "a\u200dب", "1\u200dب", "\u200dب\u200d", "ب \u200dب\u200d ب",
                 "ب\u200d", "ب\u200d\u200dب", "ب\u200c\u200dب", "ب\u200d\u200cب", "بَ\u200dب", "ب\u200dَب", "ل\u200dا",
                 "ل\u200cا", "ب\u200da", "ب\u200dـب", "می\u200cخواهم", "\u200cب", "ب\u200c"]
        bad = []
        for base, direction in (("rtl", "rtl"), ("ltr", "rtl")):
            out = textdump([f"layout {base} 16 " + hexes(t) for t in lines])
            ref = self.harfbuzz_clusters(lines, direction)
            for t, x, hb in zip(lines, out, ref):
                mine = {}
                for g in x.split(" | ")[1].split():
                    font, gid, _x, cluster = g.split(":")
                    mine.setdefault(int(cluster), gid)
                for i in self.arabic_letters(t):
                    if mine.get(i) != hb.get(i):
                        bad.append((base, t, i, mine.get(i), hb.get(i)))
        print(f"layout joiner edges: {2 * len(lines) - len({(b[0], b[1]) for b in bad})}/{2 * len(lines)} lines equal to HarfBuzz")
        self.assertEqual(bad[:6], [])

    def test_forms(self):
        # Joining types from DerivedJoiningType.txt: beh is dual-joining, alef right-joining
        # only, hamza non-joining; tatweel (U+0640) joins both sides; marks are transparent.
        cases = {
            "ببب": "init medi fina",
            "باب": "init fina isol",
            "اب": "isol isol",
            "بءب": "isol none isol",
            "بـب": "init none fina",
            "بَب": "init none fina",
            "ب‌ب": "isol none isol",
            "ب‍b": "init none none",
        }
        got = textdump(["forms " + hexes(t) for t in cases])
        self.assertEqual(got, list(cases.values()))

    def test_guest_vectors_current(self):
        # The guest's sample (TST-M5-TEXT-GUEST) regenerated from the same sources is what
        # textprobe embeds.
        r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "text_vectors.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_layout_unit_tests(self):
        r = subprocess.run(["cargo", "test", "--offline", "--release", "-p", "nawah-text", "--target", "x86_64-unknown-linux-gnu"],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertIn("test result: ok. 6 passed; 0 failed", r.stdout)


if __name__ == "__main__":
    unittest.main()
