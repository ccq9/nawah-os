#!/usr/bin/env python3
"""Acceptance tests for `project.py validate-records` (OS-EXEC-AR 3.2, section 7.1):
rejects a missing required field, a duplicate id, a missing reference, a dependency cycle,
an illegal state transition and a stale/mismatched evidence verdict; accepts a valid set."""
import contextlib, copy, unittest.mock, hashlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="nawah-validate-"))
# A private copy of project.py rooted at TMP. Under `unittest discover` another module has
# usually imported `project` already (rooted at the repo), and NAWAH_ROOT must not leak into
# the environment the other modules' subprocesses inherit.
_prev_root = os.environ.get("NAWAH_ROOT")
os.environ["NAWAH_ROOT"] = str(TMP)
_spec = importlib.util.spec_from_file_location("project_validate_tmp", REPO / "tools" / "project.py")
project = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(project)
if _prev_root is None:
    del os.environ["NAWAH_ROOT"]
else:
    os.environ["NAWAH_ROOT"] = _prev_root
# The copy writes its records and evidence under TMP. A preflight's NAWAH_SCRATCH_EVIDENCE,
# inherited from the suite runner, would switch off its evidence registry and fail the cases
# that check it (2026-10-25: two cases failed under preflight, passed under CI).
project.SCRATCH = None
# The copy's oracle source (WP-92): one host case whose text equals base_records' TST-M0-001,
# so the oracle-equality rule holds on the base set; the repository's own suites stay theirs.
project.HOST_SUITES = {"M0": [{"id": "TST-M0-001", "command": ["true"], "oracle": "exit 0", "inputs": [], "input_globs": []}]}

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

def make_evidence(recs, test_id, verdict="PASS", input_rel="docs/ENVIRONMENT.md", corrupt_digest=False, oracle="exit 0"):
    d = TMP / "evidence" / "20260101T000000Z-deadbeef-001"
    if d.exists(): shutil.rmtree(d)
    d.mkdir(parents=True)
    dig = sha((TMP / input_rel).read_bytes())
    if corrupt_digest: dig = "0" * 64
    inputs = {input_rel: dig}
    combined = sha("\n".join(f"{k}={v}" for k, v in sorted(inputs.items())).encode())
    run = {"schema_version": SV, "run_id": d.name, "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:00:01+00:00",
           "source_revision": "deadbeef", "dirty_state": False, "host": {}, "target": "host", "worker": "test", "purpose": "unit", "commands": ["x"], "exit_code": 0}
    v = {"schema_version": SV, "run_id": d.name, "test_id": test_id, "verdict": verdict, "oracle": oracle, "expected": "e", "observed": "o",
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

    def test_an_earlier_schema_error_does_not_skip_later_evidence(self):
        # One evidence directory's schema error must not switch off the exit-code, digest and
        # staleness checks of every directory validated after it.
        r = base_records(); t2 = copy.deepcopy(r["tests"][0]); t2["id"] = "TST-M0-002"; r["tests"].append(t2)
        r["requirements"][0]["test_ids"].append("TST-M0-002"); write_all(r)
        bad = TMP / "evidence" / "20260101T000000Z-deadbeef-009"
        if bad.exists(): shutil.rmtree(bad)
        (TMP / make_evidence(r, "TST-M0-001")).rename(bad)
        v = json.loads((bad / "verdict.json").read_text()); v["verdict"] = "BOGUS"; (bad / "verdict.json").write_text(json.dumps(v))
        later = make_evidence(r, "TST-M0-002")
        (TMP / later / "exit_code").write_text("1\n")  # disagrees with run.json
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [f"evidence/{bad.name}"]
        r["tests"][1]["verdict"] = "PASS"; r["tests"][1]["evidence_refs"] = [later]
        write_all(r)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(project.validate_records(verbose=True), 50)
        self.assertIn("schema", out.getvalue())
        self.assertIn(f"evidence {later}: exit_code file (1) != run.json (0)", out.getvalue())

    def test_environment_failures_are_errors_not_failures(self):
        # A command missing from the host and a toolchain that could not be downloaded are
        # environment errors (ERROR), never product failures (FAIL).
        log = TMP / "env.log"
        self.assertEqual(project.run_logged(["/nonexistent/nawah-tool"], TMP, log, log, 10), project.E_NOT_FOUND)
        self.assertIn("NOT_FOUND: /nonexistent/nawah-tool", log.read_text())
        self.assertTrue(project.env_failed(project.E_NOT_FOUND, ""))
        self.assertTrue(project.env_failed(1, "info: syncing\nerror: could not download file from 'https://static.rust-lang.org/x'"))
        self.assertTrue(project.env_failed(1, "error: toolchain '1.97.0-x86_64-unknown-linux-gnu' is not installed"))
        self.assertFalse(project.env_failed(1, "FAILED (failures=1)\nAssertionError: 2 != 3"))
        # A product test that only quotes the words (a traceback shows its source line indented)
        # keeps its FAIL.
        self.assertFalse(project.env_failed(1, '  File "t.py", line 9\n    check("error: could not download")\nAssertionError'))

    def test_a_missing_host_command_is_recorded_as_error(self):
        r = base_records(); write_all(r)
        case = {"id": "TST-M0-001", "command": ["/nonexistent/nawah-tool"], "oracle": "o", "inputs": []}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(project.cmd_test_host_case(case), 1)
        runs = sorted((TMP / "evidence").glob("*-host-test*")) or sorted(d for d in (TMP / "evidence").iterdir() if d.is_dir())
        self.assertEqual(json.loads((runs[-1] / "verdict.json").read_text())["verdict"], "ERROR")
        self.assertEqual(json.loads((TMP / "docs" / "tests.json").read_text())["records"][0]["verdict"], "ERROR")

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

    def test_a_new_run_repoints_every_older_run_of_the_same_test(self):
        # CI run 40213361352: every suite passed, then --strict failed with 71 errors. Done work
        # items still cited runs of 2026-10-23 that were not their test's latest run when the new
        # verdict arrived, so attach_evidence (which re-pointed only the immediately previous
        # run) left them on stale evidence forever.
        r = base_records(); write_all(r)

        def run_named(name):
            d = TMP / "evidence" / name
            if d.exists(): shutil.rmtree(d)
            (TMP / make_evidence(r, "TST-M0-001")).rename(d)
            for f in ("run.json", "verdict.json"):
                j = json.loads((d / f).read_text()); j["run_id"] = name; (d / f).write_text(json.dumps(j))
            return f"evidence/{name}"

        oldest, previous = run_named("20260101T000000Z-aaaaaaaa-001"), run_named("20260102T000000Z-bbbbbbbb-001")
        other = run_named("20260102T000000Z-cccccccc-001")
        v = json.loads((TMP / other / "verdict.json").read_text()); v["test_id"] = "TST-M0-002"
        (TMP / other / "verdict.json").write_text(json.dumps(v))
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [previous]
        w = r["work-items"][0]; w["status"] = "done"; w["status_history"] = ["planned", "active", "done"]
        w["evidence_refs"] = [oldest, previous, other, "docs/ENVIRONMENT.md"]
        write_all(r)
        newest = run_named("20260103T000000Z-dddddddd-001")
        project.attach_evidence("TST-M0-001", newest.split("/", 1)[1], "PASS")
        refs = json.loads((TMP / "docs" / "work-items.json").read_text())["records"][0]["evidence_refs"]
        # both older runs of this test become the newest, once; another test's run and a plain
        # file ref are left alone
        self.assertEqual(refs, [newest, other, "docs/ENVIRONMENT.md"])
        self.assertEqual(json.loads((TMP / "docs" / "tests.json").read_text())["records"][0]["evidence_refs"], [newest])

    def test_two_runners_in_the_same_second_get_distinct_run_ids(self):
        # WP-81: three verify jobs build the same revision; two of them starting a run in the same
        # second wrote the same <stamp>-<rev>-001 and their evidence collided when merged. The
        # job slot (NAWAH_RUN_SLOT) is appended to the id; the schemas still accept it.
        from unittest import mock
        fixed = project.datetime.datetime(2026, 1, 1, tzinfo=project.datetime.timezone.utc)
        saved_scratch, saved_slot = project.SCRATCH, os.environ.get("NAWAH_RUN_SLOT")
        ids = []
        try:
            with mock.patch.object(project, "datetime") as dt:
                dt.datetime.now.return_value = fixed
                for slot in ("a", "b"):
                    project.SCRATCH = TMP / f"runner-{slot}"
                    if project.SCRATCH.exists(): shutil.rmtree(project.SCRATCH)
                    os.environ["NAWAH_RUN_SLOT"] = slot
                    rid, d = project.new_run_dir("unit")
                    self.assertTrue(d.is_dir()); self.assertEqual(d.name, rid)
                    ids.append(rid)
                for bad in ("A", "a/b", "..", "a b", "ab"):
                    os.environ["NAWAH_RUN_SLOT"] = bad
                    with self.assertRaises(ValueError, msg=bad):
                        project.new_run_dir("unit")
                os.environ.pop("NAWAH_RUN_SLOT")
                rid, _ = project.new_run_dir("unit")
                self.assertTrue(rid.endswith("-001"), rid)  # no slot: the id as before
        finally:
            project.SCRATCH = saved_scratch
            if saved_slot is None: os.environ.pop("NAWAH_RUN_SLOT", None)
            else: os.environ["NAWAH_RUN_SLOT"] = saved_slot
        self.assertNotEqual(ids[0], ids[1])
        self.assertEqual([i[-2:] for i in ids], ["-a", "-b"])
        # the slotted id is a valid evidence run (evidence-run and evidence-verdict run_id)
        r = base_records(); write_all(r)
        d = TMP / "evidence" / ids[0]
        if d.exists(): shutil.rmtree(d)
        (TMP / make_evidence(r, "TST-M0-001")).rename(d)
        for f in ("run.json", "verdict.json"):
            j = json.loads((d / f).read_text()); j["run_id"] = ids[0]; (d / f).write_text(json.dumps(j))
        r["tests"][0]["verdict"] = "PASS"; r["tests"][0]["evidence_refs"] = [f"evidence/{ids[0]}"]
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

class OracleSingleSource(unittest.TestCase):
    """WP-92: a host suite's oracle (HOST_SUITES) or a guest case's (target.json) is the one
    source of the record's `oracle`; validate-records names a difference as an error and
    `sync-oracles` rewrites the record from its source (2026-11-14: 31 records had drifted)."""

    def records(self, oracle="exit 0", extra=()):
        r = base_records(); r["tests"][0]["oracle"] = oracle
        r["requirements"][0]["test_ids"] += [t["id"] for t in extra]
        r["tests"] += [dict(t) for t in extra]
        write_all(r)
        tests = TMP / "docs" / "tests.json"
        project.write_json(tests, project.load_json(tests))  # the repository's own format (indent=1)
        return tests

    def guest_target(self, oracle):
        p = TMP / "platform" / "unit-qemu" / "target.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"suites": {"M1": [{"test_id": "TST-M1-BOOT", "oracle": oracle}]},
                                 "boot_oracle": {"test_id": "TST-M1-BOOT", "oracle": "fallback, not the source"},
                                 "build": {"test_id": "TST-M1-BUILD"}}))
        self.addCleanup(shutil.rmtree, TMP / "platform", True)

    def validate(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = project.validate_records(verbose=True)
        return rc, out.getvalue()

    def sync(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = project.main(["sync-oracles", *args])
        return rc, out.getvalue()

    def oracles(self, tests):
        return {t["id"]: t for t in project.load_json(tests)["records"]}

    def test_an_oracle_that_differs_from_its_source_is_an_error_naming_the_test(self):
        self.records(oracle="exit 0 and twelve cases it never runs")
        rc, out = self.validate()
        self.assertEqual(rc, 50, out)
        self.assertIn("tests/TST-M0-001", out); self.assertIn("sync-oracles", out)
        # a guest case: the suite case of target.json is the source, boot_oracle only a fallback
        # and a target's build: the one text cmd_build writes into every build verdict
        guest = {"id": "TST-M1-BOOT", "requirement_ids": ["REQ-M0-001"], "layer": "guest", "oracle": "the suite case's text",
                 "command": "x", "verdict": "NOT_RUN", "evidence_refs": []}
        build = dict(guest, id="TST-M1-BUILD", oracle="all build steps exit 0 and artifact exists")
        self.records(extra=[guest, build]); self.guest_target("the suite case's text")
        self.assertEqual(self.validate()[0], 0)
        self.guest_target("the suite case's text, rewritten")
        rc, out = self.validate()
        self.assertEqual(rc, 50, out); self.assertIn("tests/TST-M1-BOOT", out); self.assertNotIn("tests/TST-M1-BUILD", out)
        self.records(extra=[guest, dict(build, oracle="a PE32+ artifact the build never checks")])
        rc, out = self.validate()
        self.assertIn("tests/TST-M1-BUILD", out)

    def test_sync_rewrites_from_the_source_and_leaves_a_record_without_one(self):
        own = {"id": "TST-M0-099", "requirement_ids": ["REQ-M0-001"], "layer": "host_unit", "oracle": "a hand-written oracle",
               "command": "x", "verdict": "NOT_RUN", "evidence_refs": []}
        tests = self.records(oracle="exit 0, and a stale sentence", extra=[own])
        rc, out = self.sync()
        self.assertEqual(rc, 0, out); self.assertIn("TST-M0-001", out)
        recs = self.oracles(tests)
        self.assertEqual(recs["TST-M0-001"]["oracle"], "exit 0")
        self.assertEqual(recs["TST-M0-099"]["oracle"], "a hand-written oracle")
        self.assertEqual(self.validate()[0], 0)

    def test_a_dated_note_survives_a_sync_and_an_undated_one_is_refused(self):
        tests = self.records(oracle="exit 0 2026-11-10 (WP-64): a note appended by hand")
        r = project.load_json(tests)
        r["records"][0]["oracle_notes"] = ["2026-11-10 (WP-64): a contract-driven change, not a weakened gate"]
        project.write_json(tests, r)
        self.assertEqual(self.sync()[0], 0)
        t = self.oracles(tests)["TST-M0-001"]
        self.assertEqual(t["oracle"], "exit 0")
        self.assertEqual(t["oracle_notes"], ["2026-11-10 (WP-64): a contract-driven change, not a weakened gate"])
        self.assertEqual(self.validate()[0], 0)
        r = project.load_json(tests); r["records"][0]["oracle_notes"] = ["a note without its date"]; project.write_json(tests, r)
        self.assertEqual(self.validate()[0], 50)

    def test_sync_check_writes_nothing_and_fails_on_a_difference(self):
        tests = self.records(oracle="exit 0 and more")
        before = tests.read_bytes()
        rc, out = self.sync("--check")
        self.assertNotEqual(rc, 0, out); self.assertIn("TST-M0-001", out)
        self.assertEqual(tests.read_bytes(), before)
        self.assertEqual(self.sync()[0], 0)
        self.assertEqual(self.sync("--check")[0], 0)

    def test_sync_writes_the_oracle_field_alone(self):
        # source to record, never the verdict, its evidence, the stale policy or the notes
        tests = self.records(oracle="exit 0 and more")
        ev = make_evidence(None, "TST-M0-001")
        r = project.load_json(tests); t = r["records"][0]
        t.update(verdict="PASS", evidence_refs=[ev], stale_policy="warn", verdict_reason="r", oracle_notes=["2026-11-14 (WP-92): kept"])
        project.write_json(tests, r)
        before = project.load_json(tests)
        self.assertEqual(self.sync()[0], 0)
        after = project.load_json(tests)
        before["records"][0]["oracle"] = "exit 0"
        self.assertEqual(after, before)

    def test_strict_a_pass_oracle_must_equal_the_one_its_evidence_ran_with(self):
        # A source edited to say less, then synced, must not validate until CI re-runs the test:
        # the runner wrote the oracle it ran with into verdict.json (write_verdict). No exemption
        # for stale_policy warn (the mutation gates).
        for policy in (None, "warn"):
            tests = self.records()
            ev = make_evidence(None, "TST-M0-001", oracle="exit 0")
            r = project.load_json(tests); r["records"][0].update(verdict="PASS", evidence_refs=[ev])
            if policy: r["records"][0]["stale_policy"] = policy
            project.write_json(tests, r)
            self.assertEqual(project.validate_records(verbose=False, strict=True), 0)
            weaker = {"M0": [dict(project.HOST_SUITES["M0"][0], oracle="exit 0 (says less)")]}
            with unittest.mock.patch.object(project, "HOST_SUITES", weaker):
                self.assertEqual(self.sync()[0], 0)
                self.assertEqual(project.validate_records(verbose=False), 0)  # committed state: not strict
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = project.validate_records(verbose=True, strict=True)
                self.assertEqual(rc, 50, policy); self.assertIn("tests/TST-M0-001", out.getvalue())

    def test_two_sources_with_different_texts_for_one_id_are_an_error(self):
        # A host case and a guest case (or two guest cases) that both run under one id must
        # state one text; the first source winning silently hid such a split. A boot_oracle
        # shadowed by a suite case is never run (cmd_boot) and is no source.
        tests = self.records()
        p = TMP / "platform" / "unit-qemu" / "target.json"; p.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, TMP / "platform", True)
        p.write_text(json.dumps({"suites": {"M1": [{"test_id": "TST-M0-001", "oracle": "exit 0"}]}}))
        self.assertEqual(self.validate()[0], 0)
        p.write_text(json.dumps({"suites": {"M1": [{"test_id": "TST-M0-001", "oracle": "exit 0 and a second text"}]}}))
        rc, out = self.validate()
        self.assertEqual(rc, 50, out); self.assertIn("tests/TST-M0-001", out); self.assertIn("two sources", out)
        before = tests.read_bytes()
        rc, out = self.sync()
        self.assertEqual(rc, 50, out); self.assertIn("TST-M0-001", out)
        self.assertEqual(tests.read_bytes(), before)

    def test_a_boot_oracle_is_shadowed_only_by_its_own_targets_suite_case(self):
        # Target A runs TST-M9-X as a suite case; target B has no suite case for it, so B's
        # boot_oracle is run and is a second source: different texts are an error.
        tests = self.records()
        self.addCleanup(shutil.rmtree, TMP / "platform", True)
        for name, body in (("unit-a", {"suites": {"M1": [{"test_id": "TST-M9-X", "oracle": "a"}]}}),
                           ("unit-b", {"suites": {}, "boot_oracle": {"test_id": "TST-M9-X", "oracle": "b"}})):
            p = TMP / "platform" / name / "target.json"; p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(body))
        rc, out = self.validate()
        self.assertEqual(rc, 50, out); self.assertIn("tests/TST-M9-X", out); self.assertIn("two sources", out)
        before = tests.read_bytes()
        rc, out = self.sync()
        self.assertEqual(rc, 50, out); self.assertEqual(tests.read_bytes(), before)

    def test_sync_keeps_the_file_format_one_line_changes(self):
        tests = self.records(oracle="exit 0 and more")
        before = tests.read_text(encoding="utf-8").splitlines()
        self.assertEqual(self.sync()[0], 0)
        after = tests.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(before), len(after))
        self.assertEqual([(a, b) for a, b in zip(before, after) if a != b], [('   "oracle": "exit 0 and more",', '   "oracle": "exit 0",')])
        self.assertTrue(tests.read_text(encoding="utf-8").endswith("}\n"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
