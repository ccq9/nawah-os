#!/usr/bin/env python3
"""Acceptance tests for `project.py validate-records` (OS-EXEC-AR 3.2, section 7.1):
rejects a missing required field, a duplicate id, a missing reference, a dependency cycle,
an illegal state transition and a stale/mismatched evidence verdict; accepts a valid set."""
import copy, hashlib, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="nawah-validate-"))
os.environ["NAWAH_ROOT"] = str(TMP)
sys.path.insert(0, str(REPO / "tools"))
import project  # noqa: E402

SV = "1.0.0"

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def base_records():
    req = {"id": "REQ-M0-001", "statement": "s", "rationale": "r", "source": "prompt 3.2 §1", "origin": "user_requirement",
           "priority": "must", "release": "R1", "stage": "M0", "dependencies": [], "contract_refs": [], "failure_cases": ["f"],
           "acceptance": "a", "test_ids": ["TST-M0-001"], "implementation_status": "planned", "evidence_refs": []}
    stage = {"id": "M0", "name": "bootstrap decisions", "depends_on": [], "entry_conditions": ["e"], "exit_conditions": ["x"], "gate_status": "open"}
    wi = {"id": "WP-00", "stage": "M0", "requirement_ids": ["REQ-M0-001"], "depends_on": [], "inputs": ["i"], "files": ["docs/ENVIRONMENT.md"],
          "contract_refs": [], "actions": ["a"], "acceptance": "a", "test_ids": ["TST-M0-001"], "commands": ["python3 tools/project.py validate-records"],
          "status": "planned", "status_history": ["planned"], "evidence_refs": [], "blocker": None}
    tst = {"id": "TST-M0-001", "requirement_ids": ["REQ-M0-001"], "layer": "host_unit", "oracle": "exit 0", "command": "x", "verdict": "NOT_RUN", "evidence_refs": []}
    return {"requirements": [req], "stages": [stage], "work-items": [wi], "tests": [tst]}

def write_all(recs):
    docs = TMP / "docs"
    if docs.exists(): shutil.rmtree(docs)
    shutil.copytree(REPO / "docs" / "schemas", docs / "schemas")
    for name, lst in recs.items():
        (docs / f"{name}.json").write_text(json.dumps({"schema_version": SV, "records": lst}, ensure_ascii=False, indent=1))
    (TMP / "docs" / "ENVIRONMENT.md").write_text("x")

def make_evidence(recs, test_id, verdict="PASS", input_rel="docs/ENVIRONMENT.md", corrupt_digest=False):
    d = TMP / "evidence" / "20260101T000000Z-deadbeef-001"
    if d.exists(): shutil.rmtree(d)
    d.mkdir(parents=True)
    dig = sha((TMP / input_rel).read_bytes())
    if corrupt_digest: dig = "0" * 64
    inputs = {input_rel: dig}
    combined = sha("\n".join(f"{k}={v}" for k, v in sorted(inputs.items())).encode())
    run = {"schema_version": SV, "run_id": d.name, "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:00:01+00:00",
           "source_revision": "deadbeef", "dirty_state": False, "host": {}, "target": "host", "worker": "test", "purpose": "unit", "commands": ["x"], "exit_code": 0}
    v = {"schema_version": SV, "run_id": d.name, "test_id": test_id, "verdict": verdict, "oracle": "o", "expected": "e", "observed": "o",
         "inputs_digest": combined, "inputs": inputs, "claim_tag": "source_backed_fact"}
    (d / "run.json").write_text(json.dumps(run)); (d / "verdict.json").write_text(json.dumps(v)); (d / "digests.json").write_text(json.dumps(inputs))
    for f in ("command.txt", "stdout.log", "stderr.log"): (d / f).write_text("")
    (d / "exit_code").write_text("0\n")
    return f"evidence/{d.name}"

class ValidateRecords(unittest.TestCase):
    def run_validate(self, recs):
        write_all(recs)
        return project.validate_records(verbose=False)

    def test_valid_set_passes(self):
        self.assertEqual(self.run_validate(base_records()), 0)

    def test_missing_required_field(self):
        r = base_records(); del r["requirements"][0]["acceptance"]
        self.assertEqual(self.run_validate(r), 50)

    def test_duplicate_id(self):
        r = base_records(); r["tests"].append(copy.deepcopy(r["tests"][0]))
        self.assertEqual(self.run_validate(r), 50)

    def test_missing_reference(self):
        r = base_records(); r["work-items"][0]["requirement_ids"] = ["REQ-M0-999"]
        self.assertEqual(self.run_validate(r), 50)

    def test_dependency_cycle(self):
        r = base_records()
        w2 = copy.deepcopy(r["work-items"][0]); w2["id"] = "WP-01"; w2["depends_on"] = ["WP-00"]
        r["work-items"][0]["depends_on"] = ["WP-01"]; r["work-items"].append(w2)
        self.assertEqual(self.run_validate(r), 50)

    def test_illegal_transition(self):
        r = base_records(); r["work-items"][0]["status"] = "done"; r["work-items"][0]["status_history"] = ["planned", "done"]
        self.assertEqual(self.run_validate(r), 50)

    def test_done_requires_passing_tests_and_evidence(self):
        r = base_records(); r["work-items"][0]["status"] = "done"; r["work-items"][0]["status_history"] = ["planned", "active", "done"]
        self.assertEqual(self.run_validate(r), 50)

    def test_evidence_mismatch_is_rejected(self):
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001", corrupt_digest=True)
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        write_all(r)  # rewrite records; evidence dir stays
        # Policy (ADR-0001 §evidence, project.py): a verdict whose inputs no longer match is
        # suspended (warning, exit 0) by default and an error under --strict (gates, CI).
        self.assertEqual(project.validate_records(verbose=False), 0)
        self.assertEqual(project.validate_records(verbose=False, strict=True), 50)

    def test_valid_evidence_accepted_and_done_allowed(self):
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        w = r["work-items"][0]; w["status"] = "done"; w["status_history"] = ["planned", "active", "done"]; w["evidence_refs"] = [ev]
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 0)

    def test_stale_input_requires_reevaluation(self):
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        write_all(r)
        (TMP / "docs" / "ENVIRONMENT.md").write_text("changed")
        self.assertEqual(project.validate_records(verbose=False), 0)
        self.assertEqual(project.validate_records(verbose=False, strict=True), 50)

if __name__ == "__main__":
    unittest.main(verbosity=2)
