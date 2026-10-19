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

    def test_superseded_requires_superseder_and_blocks_dependants(self):
        r = base_records()
        w2 = copy.deepcopy(r["work-items"][0]); w2["id"] = "WP-01"; w2["depends_on"] = []
        r["work-items"][0]["status"] = "superseded"; r["work-items"][0]["status_history"] = ["planned", "superseded"]
        r["work-items"].append(w2)
        self.assertEqual(self.run_validate(r), 50)  # no superseded_by
        r["work-items"][0]["superseded_by"] = "WP-01"
        self.assertEqual(self.run_validate(r), 0)
        w2["depends_on"] = ["WP-00"]
        self.assertEqual(self.run_validate(r), 50)  # depending on a superseded item

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

    def test_active_or_done_needs_done_dependencies(self):
        # §2.1: a work item becomes active only when its dependencies are done, and so can it
        # become done (arena review ع2: a done item with an active dependency passed).
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        w0 = r["work-items"][0]; w0["status"] = "active"; w0["status_history"] = ["planned", "active"]
        w1 = copy.deepcopy(w0); w1["id"] = "WP-01"; w1["depends_on"] = ["WP-00"]
        r["work-items"].append(w1)
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 50)  # active, dependency active
        w1["status"] = "done"; w1["status_history"] = ["planned", "active", "done"]; w1["evidence_refs"] = [ev]
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 50)  # done, dependency active
        w0["status"] = "done"; w0["status_history"] = ["planned", "active", "done"]; w0["evidence_refs"] = [ev]
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 0)  # both done

    def test_reopened_dependency_is_recorded_not_cascaded(self):
        # §2.1: a done item reopened for a defect (its history holds done) does not reopen
        # everything built on it; the effect on its dependants is a warning to record (DEC-004:
        # WP-32 reopened for K-3 while WP-33..WP-35 stay done).
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        w0 = r["work-items"][0]; w0["status"] = "active"; w0["status_history"] = ["planned", "active", "done", "planned", "active"]
        w1 = copy.deepcopy(w0); w1["id"] = "WP-01"; w1["depends_on"] = ["WP-00"]
        w1["status"] = "done"; w1["status_history"] = ["planned", "active", "done"]; w1["evidence_refs"] = [ev]
        r["work-items"].append(w1)
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 0)

    def test_stale_policy_warn_survives_strict(self):
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]; r["tests"][0]["stale_policy"] = "warn"
        write_all(r)
        (TMP / "docs" / "ENVIRONMENT.md").write_text("changed")
        self.assertEqual(project.validate_records(verbose=False, strict=True), 0)

    def test_stale_input_requires_reevaluation(self):
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        write_all(r)
        (TMP / "docs" / "ENVIRONMENT.md").write_text("changed")
        self.assertEqual(project.validate_records(verbose=False), 0)
        self.assertEqual(project.validate_records(verbose=False, strict=True), 50)

    def test_pass_with_planned_oracle_is_rejected(self):
        # A passing test's oracle must say what it checks, not what was planned.
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        r["tests"][0]["oracle"] = "planned (WP-00): exit 0 and five more checks"
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 50)
        r["tests"][0]["oracle"] = "exit 0"
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 0)

    def test_done_work_item_cannot_promise_a_newer_contract(self):
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        w = r["work-items"][0]; w["status"] = "done"; w["status_history"] = ["planned", "active", "done"]; w["evidence_refs"] = [ev]
        w["actions"] = ["x.md v1.1: one more request"]

        def write_with_contract(version):
            write_all(r)  # recreates docs/, so the contract is written after it
            contracts = TMP / "docs" / "contracts"; contracts.mkdir(exist_ok=True)
            (contracts / "x.md").write_text(f"# عقد x — الإصدار {version} (WP-00)\n", encoding="utf-8")

        write_with_contract("1")
        self.assertEqual(project.validate_records(verbose=False), 50)       # done, contract still v1
        w["status"] = "active"; w["status_history"] = ["planned", "active"]; w["evidence_refs"] = []
        write_with_contract("1")
        self.assertEqual(project.validate_records(verbose=False), 0)        # active: a warning only
        w["status"] = "done"; w["status_history"] = ["planned", "active", "done"]; w["evidence_refs"] = [ev]
        write_with_contract("1.1")
        self.assertEqual(project.validate_records(verbose=False), 0)        # the promised version exists

    def test_requirement_evidence_its_test_dropped_is_rejected(self):
        # CI run 39196967624: the test was reset (NOT_RUN, no evidence) but its requirement kept
        # citing the old run, which went stale and failed --strict after every suite had passed.
        r = base_records(); write_all(r)
        ev = make_evidence(r, "TST-M0-001")
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [ev]
        r["requirements"][0]["evidence_refs"] = [ev]
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 0)
        r["tests"][0]["verdict"] = "NOT_RUN"; r["tests"][0]["evidence_refs"] = []
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 50)
        r["requirements"][0]["evidence_refs"] = []
        write_all(r)
        self.assertEqual(project.validate_records(verbose=False), 0)

    def test_checkpoint_position_follows_the_records(self):
        # Review 2026-10-19 (T-8): project-state said M2/WP-07 during M5.
        r = base_records()
        w0 = r["work-items"][0]
        w1 = copy.deepcopy(w0); w1["id"] = "WP-01"; w1["depends_on"] = ["WP-00"]; w1["actions"] = ["next one"]
        pos = project.derive_position([w0, w1], r["requirements"])
        self.assertEqual((pos["current_task"], pos["current_stage"]), ("WP-00", "M0"))  # first ready planned
        w0["status"] = "done"
        self.assertEqual(project.derive_position([w0, w1], r["requirements"])["current_task"], "WP-01")
        w1["status"] = "active"
        pos = project.derive_position([w0, w1], r["requirements"])
        self.assertEqual(pos["current_task"], "WP-01"); self.assertEqual(pos["next_action"], "WP-01: next one")
        r["requirements"][0]["implementation_status"] = "verified_in_scope"
        self.assertEqual(project.derive_position([w0, w1], r["requirements"])["completed_requirement_ids"], ["REQ-M0-001"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
