#!/usr/bin/env python3
"""TST-M0-004: tools/pre-merge.sh is the gate a records commit passes before it is merged.

On 2026-10-27 and 2026-10-28 two records commits were pushed with 11 strict errors each: the
chain `validate-records --strict | tail -1 && git commit` lost the validator's exit code in
the pipe. The script runs the strict validation under `set -euo pipefail` and exits with the
validator's own code, so a chain `tools/pre-merge.sh && git commit` cannot commit over errors.

The behaviour is tested on a records set of its own (the minimal valid set of
tests/test_validate_records.py, with the real schemas and tools), never on the checkout's
live records: on a branch whose code commit precedes its evidence those are stale by design
(CI run 40639095840 failed the first version of this test for that reason). One case: the
set with a PASS verdict whose input digest matches, exit 0 and 'pre-merge: OK'. The other:
the same set after its input file changed, so the verdict is stale, exit 50 and no OK. The
script is also read as text: the three shell options set, the strict flag used, and no pipe
between the validator and the script's exit."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "pre-merge.sh"
SV = "1.0.0"
sys.path.insert(0, str(ROOT / "tools"))
import project  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_repo(dst: pathlib.Path, verdict_matches_input=True):
    """A minimal repository: the real tools and schemas, one requirement, stage, work item and
    test, one PASS run whose single input is docs/ENVIRONMENT.md. `verdict_matches_input`
    False changes that file after the run, which leaves the verdict stale."""
    shutil.copytree(ROOT / "tools", dst / "tools", ignore=shutil.ignore_patterns("__pycache__"))
    docs = dst / "docs"
    shutil.copytree(ROOT / "docs" / "schemas", docs / "schemas")
    (docs / "ENVIRONMENT.md").write_text("environment\n")
    run_name = "20260101T000000Z-deadbeef-001"
    req = {"id": "REQ-M0-001", "statement": "s", "rationale": "r", "source": "prompt 3.2 §1", "origin": "user_requirement",
           "priority": "must", "release": "R1", "stage": "M0", "dependencies": [], "contract_refs": [], "failure_cases": ["f"],
           "acceptance": "a", "test_ids": ["TST-M0-001"], "implementation_status": "verified_in_scope", "evidence_refs": [f"evidence/{run_name}"]}
    stage = {"id": "M0", "name": "bootstrap decisions", "depends_on": [], "entry_conditions": ["e"], "exit_conditions": ["x"], "gate_status": "open"}
    wi = {"id": "WP-00", "stage": "M0", "requirement_ids": ["REQ-M0-001"], "depends_on": [], "inputs": ["i"], "files": ["docs/ENVIRONMENT.md"],
          "contract_refs": [], "actions": ["a"], "acceptance": "a", "test_ids": ["TST-M0-001"], "commands": ["python3 tools/project.py validate-records"],
          "status": "done", "status_history": ["planned", "active", "done"], "evidence_refs": [f"evidence/{run_name}"], "blocker": None}
    tst = {"id": "TST-M0-001", "requirement_ids": ["REQ-M0-001"], "layer": "host_unit", "oracle": "exit 0", "command": "x",
           "verdict": "PASS", "evidence_refs": [f"evidence/{run_name}"]}
    for name, lst in {"requirements": [req], "stages": [stage], "work-items": [wi], "tests": [tst]}.items():
        (docs / f"{name}.json").write_text(json.dumps({"schema_version": SV, "records": lst}, ensure_ascii=False, indent=1))
    d = dst / "evidence" / run_name
    d.mkdir(parents=True)
    inputs = {"docs/ENVIRONMENT.md": sha((docs / "ENVIRONMENT.md").read_bytes())}
    combined = sha("\n".join(f"{k}={v}" for k, v in sorted(inputs.items())).encode())
    run = {"schema_version": SV, "run_id": run_name, "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:00:01+00:00",
           "source_revision": "deadbeef", "dirty_state": False, "host": {}, "target": "host", "worker": "test", "purpose": "unit", "commands": ["x"], "exit_code": 0}
    v = {"schema_version": SV, "run_id": run_name, "test_id": "TST-M0-001", "verdict": "PASS", "oracle": "o", "expected": "e", "observed": "o",
         "inputs_digest": combined, "inputs": inputs, "claim_tag": "source_backed_fact"}
    (d / "run.json").write_text(json.dumps(run)); (d / "verdict.json").write_text(json.dumps(v)); (d / "digests.json").write_text(json.dumps(inputs))
    for f in ("command.txt", "stdout.log", "stderr.log"):
        (d / f).write_text("")
    (d / "exit_code").write_text("0\n")
    if not verdict_matches_input:
        (docs / "ENVIRONMENT.md").write_text("environment, changed after the run\n")


def run(cwd: pathlib.Path):
    env = dict(os.environ, NAWAH_ROOT=str(cwd))
    env.pop("NAWAH_SCRATCH_EVIDENCE", None)
    return subprocess.run(["bash", str(cwd / "tools" / "pre-merge.sh")], cwd=cwd, capture_output=True, text=True, env=env)


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
            make_repo(dst)
            r = run(dst)
            self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
            self.assertIn("0 error(s)", r.stdout)
            self.assertIn("pre-merge: OK", r.stdout)

    def test_stale_evidence_fails(self):
        with tempfile.TemporaryDirectory(prefix="nawah-premerge-") as tmp:
            dst = pathlib.Path(tmp)
            make_repo(dst, verdict_matches_input=False)
            r = run(dst)
            self.assertEqual(r.returncode, project.E_VALIDATION, r.stdout[-2000:] + r.stderr[-2000:])
            self.assertIn("inputs changed since verdict", r.stdout)
            self.assertNotIn("0 error(s)", r.stdout)
            self.assertNotIn("pre-merge: OK", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=1)
