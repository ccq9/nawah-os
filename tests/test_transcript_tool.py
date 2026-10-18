"""TST-M5-UI-TOOL (host): tools/transcript.py — the narrator lines are taken from the serial
log's trace lines and must equal the expected file exactly in every serial log (a missing, an
extra or a reordered line fails, each phase is checked); `dims` accepts only the same origin
with the size multiplied by the factor."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "transcript.py"


def run(*args):
    return subprocess.run([sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True)


def trace(text):
    return f"OSX|abc|user|trace|len={len(text) + 9}|text=narrator|{text}\n"


class Transcript(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self.dir.name)
        (self.d / "expect.txt").write_text("# comment\nwindow \"A\" focused\nfocus role=button label=\"OK\" state=focused\ncancel\n")

    def tearDown(self):
        self.dir.cleanup()

    def log(self, name, lines, noise=True):
        body = "".join(("OSX|abc|kernel|other|x=1\n" if noise else "") + trace(l) for l in lines)
        (self.d / name).write_text(body)

    def test_exact_transcript_passes(self):
        self.log("serial.log", ['window "A" focused', 'focus role=button label="OK" state=focused', "cancel"])
        r = run("check", str(self.d), str(self.d / "expect.txt"))
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_missing_extra_reordered_fail(self):
        good = ['window "A" focused', 'focus role=button label="OK" state=focused', "cancel"]
        for bad in (good[:2], good + ["cancel"], [good[1], good[0], good[2]]):
            self.log("serial.log", bad)
            self.assertEqual(run("check", str(self.d), str(self.d / "expect.txt")).returncode, 1, bad)

    def test_every_phase_is_checked(self):
        good = ['window "A" focused', 'focus role=button label="OK" state=focused', "cancel"]
        self.log("serial-1.log", good)
        self.log("serial-2.log", good[:2])
        r = run("check", str(self.d), str(self.d / "expect.txt"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("serial-2.log: transcript differs", r.stdout)
        self.log("serial-2.log", good)
        self.assertEqual(run("check", str(self.d), str(self.d / "expect.txt")).returncode, 0)

    def test_dims(self):
        self.assertEqual(run("dims", "21,45,260,242", "21,45,520,484", "2").returncode, 0)
        self.assertEqual(run("dims", "21,45,260,242", "21,45,520,483", "2").returncode, 1)
        self.assertEqual(run("dims", "21,45,260,242", "22,45,520,484", "2").returncode, 1)


if __name__ == "__main__":
    unittest.main()
