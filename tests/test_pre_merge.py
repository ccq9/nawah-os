#!/usr/bin/env python3
"""TST-M0-004: tools/pre-merge.sh is the gate a records commit passes before it is merged.

On 2026-10-27 and 2026-10-28 two records commits were pushed with 11 strict errors each: the
chain `validate-records --strict | tail -1 && git commit` lost the validator's exit code in
the pipe. The script runs the strict validation under `set -euo pipefail` and exits with the
validator's own code, so a chain `tools/pre-merge.sh && git commit` cannot commit over errors.

Both cases run the real script on a copy of the repository: one with the records as they are
(0 errors expected), one with an input of four host tests edited after their run, so their
verdicts are stale (errors expected). The
script is also read as text: the three shell options must be set, the strict flag used, and
no pipe may stand between the validator and the script's exit."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "pre-merge.sh"
sys.path.insert(0, str(ROOT / "tools"))
import project  # noqa: E402


def copy_repo(dst: pathlib.Path):
    """Every file git tracks, as a CI checkout has them (the records and schemas, the evidence
    they cite, the tools, and every source a verdict's digests cover), without .git: the
    validator then reads an unknown revision, a warning only, as on a detached CI head."""
    # Tracked files plus untracked ones git would add (not the ignored build outputs): what
    # the next commit holds.
    files = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                           cwd=ROOT, capture_output=True, check=True).stdout.split(b"\0")
    for rel in files:
        if not rel:
            continue
        src = ROOT / os.fsdecode(rel)
        if not src.is_file():
            continue
        out = dst / os.fsdecode(rel)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)


def run(cwd: pathlib.Path):
    return subprocess.run(["bash", str(cwd / "tools" / "pre-merge.sh")], cwd=cwd, capture_output=True, text=True,
                          env=dict(os.environ, NAWAH_ROOT=str(cwd)))


class PreMerge(unittest.TestCase):
    def test_script_is_strict_and_loses_no_exit_code(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", text)
        self.assertIn("validate-records --strict", text)
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            if "validate-records" in code:
                self.assertNotIn("|", code, "a pipe after the validator hides its exit code")
        self.assertTrue(os.access(SCRIPT, os.X_OK), "tools/pre-merge.sh is not executable")

    def test_valid_records_pass(self):
        with tempfile.TemporaryDirectory(prefix="nawah-premerge-") as tmp:
            dst = pathlib.Path(tmp)
            copy_repo(dst)
            r = run(dst)
            self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
            self.assertIn("0 error(s)", r.stdout)
            self.assertIn("pre-merge: OK", r.stdout)

    def test_stale_evidence_fails(self):
        with tempfile.TemporaryDirectory(prefix="nawah-premerge-") as tmp:
            dst = pathlib.Path(tmp)
            copy_repo(dst)
            # A test whose inputs are the records tools: changing one of its inputs after its
            # run makes its verdict stale, which --strict counts as an error (2026-10-27:
            # tools/project.py changed, TST-M0-001 and three more went stale: 11 errors).
            tool = dst / "tools" / "project.py"
            tool.write_text(tool.read_text(encoding="utf-8") + "\n# stale-making edit\n", encoding="utf-8")
            r = run(dst)
            self.assertNotEqual(r.returncode, 0, "the script passed stale evidence")
            self.assertEqual(r.returncode, project.E_VALIDATION, r.stdout[-2000:] + r.stderr[-2000:])
            self.assertRegex(r.stdout, r"\n(?!0 )\d+ error\(s\)|validate-records: (?!0 )\d+ error")
            self.assertNotIn("pre-merge: OK", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=1)
