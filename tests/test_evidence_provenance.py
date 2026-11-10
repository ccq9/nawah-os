#!/usr/bin/env python3
"""TST-M0-007 (REQ-M0-006, WP-65): evidence provenance and the checked import.

Every CI-imported PASS verdict before 2026-11-09 carried worker="interactive-agent" and
dirty_state=true, and two cancelled verify runs had published evidence branches that
`import-ci-evidence` would have adopted (docs/PLAN-ANSWER.md §2.8). This test pins:

  - evidence-run 1.1.0: a closed worker enumeration, an optional `ci` object the runner writes,
    `dirty_paths`; 1.0.0 stays valid (the 149 existing verdicts);
  - write_run under GITHUB_ACTIONS=true records worker=verification-runner and the run's `ci`
    identity; source_identity ignores evidence/, build/ and state/ and names the dirty paths;
  - the validator: a 1.1.0 PASS verdict without import.json is an error under --strict (a warning
    otherwise) whatever worker the run declares, unless the evidence is native to the validating
    CI run; a present import.json is a complete receipt (its own schema) matching the run's ci
    identity on run id, attempt, head sha and workflow, for every worker and verdict, and a
    malformed receipt is a named error; 1.0.0 evidence without import.json is one aggregated
    warning, never an error;
  - the writer: dirty_state and dirty_paths are taken once when the run begins, so the records a
    run writes while attaching its own verdicts never make it dirty; paths with spaces or
    non-ASCII letters are named as they are;
  - the import: the GitHub run must be completed/success, from verify or mutants, with a head
    that is an ancestor of HEAD, and the id well-formed; anything else, or a missing gh, imports
    nothing and leaves no directory; a successful import writes import.json beside an
    untouched run.json.
"""
import contextlib, copy, hashlib, importlib.util, io, json, os, shutil, stat, subprocess, sys, tempfile, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="nawah-provenance-"))
_prev_root = os.environ.get("NAWAH_ROOT")
os.environ["NAWAH_ROOT"] = str(TMP)
_spec = importlib.util.spec_from_file_location("project_provenance_tmp", REPO / "tools" / "project.py")
project = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(project)
if _prev_root is None:
    del os.environ["NAWAH_ROOT"]
else:
    os.environ["NAWAH_ROOT"] = _prev_root
project.SCRATCH = None
SV = "1.0.0"
RUN_SV = "1.1.0"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def base_records():
    req = {"id": "REQ-M0-001", "statement": "s", "rationale": "r", "source": "prompt 3.2 §1", "origin": "user_requirement",
           "priority": "must", "release": "R1", "stage": "M0", "dependencies": [], "contract_refs": [], "failure_cases": ["f"],
           "acceptance": "a", "test_ids": ["TST-M0-001"], "implementation_status": "planned", "evidence_refs": []}
    stage = {"id": "M0", "name": "bootstrap", "depends_on": [], "entry_conditions": ["e"], "exit_conditions": ["x"], "gate_status": "open"}
    wi = {"id": "WP-00", "stage": "M0", "requirement_ids": ["REQ-M0-001"], "depends_on": [], "inputs": ["i"], "files": ["docs/ENVIRONMENT.md"],
          "contract_refs": [], "actions": ["a"], "acceptance": "a", "test_ids": ["TST-M0-001"], "commands": ["x"],
          "status": "planned", "status_history": ["planned"], "evidence_refs": [], "blocker": None}
    tst = {"id": "TST-M0-001", "requirement_ids": ["REQ-M0-001"], "layer": "host_unit", "oracle": "exit 0", "command": "x", "verdict": "NOT_RUN", "evidence_refs": []}
    return {"requirements": [req], "stages": [stage], "work-items": [wi], "tests": [tst]}


def write_all(recs):
    docs = TMP / "docs"
    if docs.exists():
        shutil.rmtree(docs)
    shutil.copytree(REPO / "docs" / "schemas", docs / "schemas")
    for name, lst in recs.items():
        (docs / f"{name}.json").write_text(json.dumps({"schema_version": SV, "records": lst}, ensure_ascii=False, indent=1))
    (docs / "ENVIRONMENT.md").write_text("x")
    shutil.copy(REPO / "docs" / "automation.json", docs / "automation.json")


def make_evidence(run_sv=RUN_SV, worker="test", ci=None, import_json=None, verdict="PASS"):
    d = TMP / "evidence" / "20260101T000000Z-deadbeef-001"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    inputs = {"docs/ENVIRONMENT.md": sha((TMP / "docs/ENVIRONMENT.md").read_bytes())}
    combined = sha("\n".join(f"{k}={v}" for k, v in sorted(inputs.items())).encode())
    run = {"schema_version": run_sv, "run_id": d.name, "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:00:01+00:00",
           "source_revision": "deadbeef", "dirty_state": False, "host": {}, "target": "host", "worker": worker, "purpose": "unit",
           "commands": ["x"], "exit_code": 0}
    if ci is not None:
        run["ci"] = ci
    v = {"schema_version": SV, "run_id": d.name, "test_id": "TST-M0-001", "verdict": verdict, "oracle": "o", "expected": "e", "observed": "o",
         "inputs_digest": combined, "inputs": inputs, "claim_tag": "source_backed_fact"}
    (d / "run.json").write_text(json.dumps(run)); (d / "verdict.json").write_text(json.dumps(v)); (d / "digests.json").write_text(json.dumps(inputs))
    for f in ("command.txt", "stdout.log", "stderr.log"):
        (d / f).write_text("")
    (d / "exit_code").write_text("0\n")
    if import_json is not None:
        (d / "import.json").write_text(json.dumps(import_json))
    return f"evidence/{d.name}"


CI = {"run_id": "42", "run_attempt": 1, "workflow": "verify", "event": "pull_request", "sha": "cafe", "head_sha": "deadbeef", "ref": "refs/pull/1/merge"}
IMPORT = {"ci_run_id": "42", "conclusion": "success", "head_sha": "deadbeef", "event": "pull_request", "run_attempt": 1, "workflow": "verify",
          "evidence_branch_commit": "feed", "imported_at": "2026-01-02T00:00:00+00:00", "importer": {"worker": "test", "identity": "t"}}


import contextlib


@contextlib.contextmanager
def ci_env(**values):
    """GITHUB_ACTIONS=true plus the given GitHub variables; the others unset. Restored on exit."""
    keys = ("GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    os.environ["GITHUB_ACTIONS"] = "true"
    defaults = {"GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "cafe"} if "GITHUB_RUN_ID" in values and values["GITHUB_RUN_ID"] else {}
    for k, v in {**defaults, **values}.items():
        os.environ[k] = v
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def done_records(ref):
    recs = base_records()
    recs["tests"][0].update(verdict="PASS", evidence_refs=[ref])
    recs["work-items"][0].update(status="done", status_history=["planned", "active", "done"], evidence_refs=[ref])
    recs["requirements"][0].update(implementation_status="verified_in_scope", evidence_refs=[ref])
    return recs


def cited_records(ref, verdict):
    """The test cites the run with the given verdict; the work item stays planned."""
    recs = base_records()
    recs["tests"][0].update(verdict=verdict, evidence_refs=[ref])
    return recs


class RunSchema(unittest.TestCase):
    def validate(self, recs):
        write_all(recs)
        return project.validate_records(verbose=False)

    def validate_strict(self, recs):
        write_all(recs)
        return project.validate_records(verbose=False, strict=True)

    def test_1_1_0_run_with_ci_object_is_valid(self):
        write_all(base_records())
        ref = make_evidence(worker="verification-runner", ci=CI, import_json=IMPORT)
        self.assertEqual(self.validate(done_records(ref)), project.E_OK)

    def test_the_schema_ties_ci_to_the_runner_and_to_1_1_0(self):
        """PLAN-ANSWER §2.8 REL-1 promised the version pattern with if/then (the audit of 77d48c91
        found none): a verification-runner run must carry ci, and a 1.0.0 run cannot."""
        write_all(base_records())
        ref = make_evidence(worker="verification-runner", import_json=IMPORT)  # the runner, no ci
        self.assertNotEqual(self.validate(done_records(ref)), project.E_OK)
        write_all(base_records())
        ref = make_evidence(run_sv=SV, worker="interactive-agent", ci=CI)  # 1.0.0 with ci
        self.assertNotEqual(self.validate(done_records(ref)), project.E_OK)
        write_all(base_records())
        ref = make_evidence(worker="interactive-agent")  # 1.1.0 off the runner: ci optional
        self.assertEqual(self.validate(done_records(ref)), project.E_OK)

    def test_1_0_0_run_stays_valid(self):
        write_all(base_records())
        ref = make_evidence(run_sv=SV, worker="interactive-agent")
        self.assertEqual(self.validate_strict(done_records(ref)), project.E_OK)

    def test_worker_outside_the_enumeration_is_rejected(self):
        write_all(base_records())
        ref = make_evidence(worker="somebody")
        self.assertNotEqual(self.validate(done_records(ref)), project.E_OK)
        # at 1.0.0 too, where nothing but the enumeration can reject it (at 38df3fe2 this test
        # passed because 1.1.0 itself was rejected; the audit of 77d48c91 found it never red
        # for its own reason)
        ref = make_evidence(run_sv=SV, worker="somebody")
        self.assertNotEqual(self.validate(done_records(ref)), project.E_OK)
        ref = make_evidence(run_sv=SV, worker="interactive-agent")
        self.assertEqual(self.validate(done_records(ref)), project.E_OK)

    def test_a_1_1_0_pass_from_any_worker_without_import_json_is_a_strict_error(self):
        """The rule binds the evidence, not the worker's own word (ADR-0026 rejected REL-1 B, the
        self-claim): a 1.1.0 PASS that was not adopted through the checked import is a strict
        error whether run.json says interactive-agent, test or verification-runner. Local runs
        belong in scratch evidence; a committed one must come through the import."""
        for worker in ("interactive-agent", "test"):
            write_all(base_records())
            ref = make_evidence(worker=worker)
            self.assertEqual(self.validate(done_records(ref)), project.E_OK, worker)  # a warning
            self.assertNotEqual(self.validate_strict(done_records(ref)), project.E_OK, worker)  # an error
            self.assertNotEqual(self.validate_strict(cited_records(ref, "PASS")), project.E_OK, worker)
        # a FAIL needs no receipt: it adopts nothing
        write_all(base_records())
        ref = make_evidence(worker="interactive-agent", verdict="FAIL")
        self.assertEqual(self.validate_strict(cited_records(ref, "FAIL")), project.E_OK)

    def test_a_mismatching_receipt_is_an_error_for_any_worker_and_verdict(self):
        """A present import.json is checked whatever the worker and the verdict (the audit of
        77d48c91: an interactive-agent run with ci.run_id 42 and a receipt naming 99, and a
        runner FAIL with the same receipt, both passed)."""
        write_all(base_records())
        ref = make_evidence(worker="interactive-agent", ci=CI, import_json=dict(IMPORT, ci_run_id="99"))
        self.assertNotEqual(self.validate(cited_records(ref, "PASS")), project.E_OK)
        write_all(base_records())
        ref = make_evidence(worker="verification-runner", ci=CI, import_json=dict(IMPORT, ci_run_id="99"), verdict="FAIL")
        self.assertNotEqual(self.validate(cited_records(ref, "FAIL")), project.E_OK)
        write_all(base_records())
        ref = make_evidence(worker="interactive-agent", import_json=IMPORT)  # a receipt for a run with no ci identity
        self.assertNotEqual(self.validate(cited_records(ref, "PASS")), project.E_OK)

    def test_a_receipt_is_a_complete_record_matching_the_runs_attempt_head_and_workflow(self):
        """import.json has a schema of its own (docs/schemas/evidence-import.schema.json): every field
        the importer writes is required, the conclusion is success, the workflow is verify or
        mutants, and the attempt, head sha and workflow equal the run's ci identity."""
        write_all(base_records())
        good = make_evidence(worker="verification-runner", ci=CI, import_json=IMPORT)
        self.assertEqual(self.validate_strict(done_records(good)), project.E_OK)
        bad = [
            {k: v for k, v in IMPORT.items() if k != "importer"},
            {k: v for k, v in IMPORT.items() if k != "workflow"},
            dict(IMPORT, conclusion="cancelled"),
            dict(IMPORT, workflow="release"),
            dict(IMPORT, run_attempt=2),
            dict(IMPORT, head_sha="beef"),
            dict(IMPORT, importer={"worker": "somebody", "identity": "t"}),
            {"ci_run_id": "42"},
        ]
        for imp in bad:
            write_all(base_records())
            ref = make_evidence(worker="verification-runner", ci=CI, import_json=imp)
            self.assertNotEqual(self.validate(done_records(ref)), project.E_OK, json.dumps(imp))

    def test_a_malformed_or_non_object_import_json_is_a_named_error_not_a_crash(self):
        """A file that is not a receipt must not stand in for one: broken JSON, and JSON that is
        not an object (null above all, which a naive 'is not None' check would wave through and
        thereby exempt a non-native PASS from the missing-receipt rule)."""
        for text in ("{", "null", "[]", '"x"', "1"):
            write_all(base_records())
            ref = make_evidence(worker="verification-runner", ci=CI)
            (TMP / ref / "import.json").write_text(text)
            self.assertEqual(self.validate(done_records(ref)), project.E_VALIDATION, text)
            self.assertEqual(self.validate_strict(done_records(ref)), project.E_VALIDATION, text)

    def test_runner_pass_without_import_json_is_a_strict_error(self):
        write_all(base_records())
        ref = make_evidence(worker="verification-runner", ci=CI)
        self.assertEqual(self.validate(done_records(ref)), project.E_OK)  # a warning
        self.assertNotEqual(self.validate_strict(done_records(ref)), project.E_OK)  # an error

    def test_native_evidence_of_the_current_ci_run_needs_no_import_json(self):
        """On the runner the evidence is produced, not adopted: the strict step of verify runs on the
        same tree before any import exists. The exemption holds only while GITHUB_RUN_ID equals the
        run's own ci.run_id; a committed verification-runner PASS without import.json fails on CI,
        because that CI run has another id."""
        write_all(base_records())
        ref = make_evidence(worker="verification-runner", ci=CI)  # ci.run_id "42", no import.json
        with ci_env(GITHUB_RUN_ID="42"):
            self.assertEqual(self.validate_strict(done_records(ref)), project.E_OK)
        with ci_env(GITHUB_RUN_ID="43"):
            self.assertNotEqual(self.validate_strict(done_records(ref)), project.E_OK)
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="2"):  # same number, another attempt
            self.assertNotEqual(self.validate_strict(done_records(ref)), project.E_OK)
        with ci_env(GITHUB_RUN_ID="42", GITHUB_SHA="beef"):  # same number, another commit
            self.assertNotEqual(self.validate_strict(done_records(ref)), project.E_OK)

    def test_a_mismatching_receipt_is_an_error_even_inside_the_same_run(self):
        """A present import.json is always checked: the native exemption covers only its absence
        (the independent auditor's finding on 68d72a5e: a receipt naming 43 passed under run 42)."""
        write_all(base_records())
        ref = make_evidence(worker="verification-runner", ci=CI, import_json=dict(IMPORT, ci_run_id="43"))
        with ci_env(GITHUB_RUN_ID="42"):
            self.assertNotEqual(self.validate_strict(done_records(ref)), project.E_OK)
            self.assertNotEqual(self.validate(done_records(ref)), project.E_OK)

    def test_a_missing_identity_is_never_native(self):
        """GITHUB_ACTIONS=true with no run id, and a run.json with no ci: two empty strings are not
        a match, so the runner PASS without import.json stays a strict error."""
        write_all(base_records())
        ref = make_evidence(worker="verification-runner", ci=dict(CI, run_id=""))  # an empty run id
        with ci_env():
            self.assertNotEqual(self.validate_strict(done_records(ref)), project.E_OK)
        with ci_env(GITHUB_RUN_ID=""):
            self.assertNotEqual(self.validate_strict(done_records(ref)), project.E_OK)

    def test_import_run_id_must_match_the_runs_ci_identity(self):
        write_all(base_records())
        ref = make_evidence(worker="verification-runner", ci=CI, import_json=dict(IMPORT, ci_run_id="43"))
        self.assertNotEqual(self.validate(done_records(ref)), project.E_OK)


class RunWriter(unittest.TestCase):
    def setUp(self):
        self.d = TMP / "runs" / "w"
        if self.d.exists():
            shutil.rmtree(self.d)
        self.d.mkdir(parents=True)

    def test_write_run_on_github_actions_records_the_runner_and_its_ci_identity(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_WORKFLOW": "verify",
               "GITHUB_EVENT_NAME": "pull_request", "GITHUB_SHA": "cafe", "GITHUB_REF": "refs/pull/1/merge"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            project.write_run(self.d, "rid", "host", "unit", ["x"], 0, "2026-01-01T00:00:00+00:00")
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        run = json.loads((self.d / "run.json").read_text())
        self.assertEqual(run["schema_version"], RUN_SV)
        self.assertEqual(run["worker"], "verification-runner")
        self.assertEqual(run["ci"]["run_id"], "4242")
        self.assertEqual(run["ci"]["run_attempt"], 2)
        self.assertEqual(run["ci"]["workflow"], "verify")
        self.assertEqual(run["ci"]["event"], "pull_request")
        self.assertEqual(run["ci"]["sha"], "cafe")
        self.assertIn("dirty_paths", run)

    def test_write_run_off_the_runner_is_the_interactive_agent(self):
        os.environ.pop("GITHUB_ACTIONS", None)
        project.write_run(self.d, "rid", "host", "unit", ["x"], 0, "2026-01-01T00:00:00+00:00")
        run = json.loads((self.d / "run.json").read_text())
        self.assertEqual(run["worker"], "interactive-agent")
        self.assertNotIn("ci", run)


class SourceIdentity(unittest.TestCase):
    """source_identity in a scratch repository rooted at TMP/ident."""

    def setUp(self):
        self.root = TMP / "ident"
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir()
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(TMP), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        self.git("init", "-q")
        (self.root / "kernel").mkdir(); (self.root / "kernel" / "a.rs").write_text("fn a() {}\n")
        (self.root / ".gitignore").write_text("build/\n")
        self.git("add", "-A"); self.git("commit", "-q", "-m", "base")
        self.old_root = project.ROOT
        project.ROOT = self.root

    def tearDown(self):
        project.ROOT = self.old_root
        project.RUN_TREE = None

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, env=self.env, check=True, capture_output=True)

    def test_a_run_is_not_dirty_on_the_records_it_writes_itself(self):
        """attach_evidence rewrites docs/tests.json, requirements.json and work-items.json while a
        suite runs, so a tree clean at the start would read dirty from the second case on (the
        audit of 77d48c91, gap 3). The run's identity is taken once, when the run begins."""
        (self.root / "docs").mkdir(); (self.root / "docs" / "tests.json").write_text("{}\n")
        self.git("add", "-A"); self.git("commit", "-q", "-m", "records")
        d = TMP / "runs" / "baseline"
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        project.RUN_TREE = None
        project.begin_run()
        (self.root / "docs" / "tests.json").write_text('{"verdict": "PASS"}\n')  # what attach_evidence does
        project.write_run(d, "rid", "host", "unit", ["x"], 0, "2026-01-01T00:00:00+00:00")
        run = json.loads((d / "run.json").read_text())
        self.assertFalse(run["dirty_state"])
        self.assertEqual(run["dirty_paths"], [])
        # a source change before the run begins is dirty and named
        project.RUN_TREE = None
        (self.root / "kernel" / "a.rs").write_text("fn a() { b() }\n")
        project.begin_run()
        project.write_run(d, "rid", "host", "unit", ["x"], 0, "2026-01-01T00:00:00+00:00")
        run = json.loads((d / "run.json").read_text())
        self.assertTrue(run["dirty_state"])
        self.assertEqual(run["dirty_paths"], ["docs/tests.json", "kernel/a.rs"])

    def test_paths_with_spaces_or_arabic_letters_are_named_unquoted(self):
        """git status without -z quotes such paths ("kernel/a b.rs", octal escapes for Arabic), so
        the exclusion and the names were wrong for them (the audit of 77d48c91, gap 10)."""
        (self.root / "kernel" / "a b.rs").write_text("fn b() {}\n")
        (self.root / "kernel" / "ملف.rs").write_text("fn c() {}\n")
        (self.root / "evidence" / "a b").mkdir(parents=True); (self.root / "evidence" / "a b" / "run.json").write_text("{}")
        self.assertEqual(project.dirty_paths(), ["kernel/a b.rs", "kernel/ملف.rs"])
        self.git("mv", "kernel/a.rs", "kernel/renamed.rs")
        self.assertEqual(project.dirty_paths(), ["kernel/a b.rs", "kernel/renamed.rs", "kernel/ملف.rs"])

    def test_untracked_evidence_does_not_make_the_tree_dirty(self):
        (self.root / "evidence" / "r1").mkdir(parents=True); (self.root / "evidence" / "r1" / "run.json").write_text("{}")
        (self.root / "state").mkdir(); (self.root / "state" / "x").write_text("x")
        rev, dirty = project.source_identity()
        self.assertFalse(dirty)
        self.assertEqual(project.dirty_paths(), [])

    def test_a_modified_tracked_file_or_a_new_source_file_is_dirty_and_named(self):
        (self.root / "kernel" / "a.rs").write_text("fn a() { b() }\n")
        (self.root / "kernel" / "b.rs").write_text("fn b() {}\n")
        rev, dirty = project.source_identity()
        self.assertTrue(dirty)
        self.assertEqual(project.dirty_paths(), ["kernel/a.rs", "kernel/b.rs"])


class CheckedImport(unittest.TestCase):
    """import-ci-evidence against a fake origin and a fake gh on PATH."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="nawah-import-"))
        self.addCleanup(shutil.rmtree, self.base, True)
        base = self.base
        self.bin = base / "bin"; self.bin.mkdir()
        self.env = {"PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(base), "TMPDIR": str(base / "tmp"),
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        (base / "tmp").mkdir()
        self.git(base, "init", "-q", "--bare", "origin")
        # the project root with one commit; the runner's head is that commit
        self.root = base / "root"
        self.git(base, "init", "-q", "root")
        (self.root / "evidence").mkdir(); (self.root / "README").write_text("r")
        self.git(self.root, "add", "-A"); self.git(self.root, "commit", "-q", "-m", "base")
        self.head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.root, env=self.env, capture_output=True, text=True, check=True).stdout.strip()
        self.git(self.root, "remote", "add", "origin", str(base / "origin"))
        # the runner's evidence branch
        work = base / "work"
        self.git(base, "init", "-q", "work")
        self.run_dir = work / "evidence" / "20260101T000000Z-deadbeef-001"
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "verdict.json").write_text(json.dumps({"test_id": "TST-X", "verdict": "PASS"}))
        self.run_json = json.dumps({"run_id": self.run_dir.name, "worker": "verification-runner",
                                    "ci": {"run_id": "42", "run_attempt": 1, "workflow": "verify", "event": "pull_request", "sha": "cafe", "head_sha": self.head, "ref": "x"}})
        (self.run_dir / "run.json").write_text(self.run_json)
        self.git(work, "checkout", "-q", "-b", "ci-evidence/42")
        self.git(work, "add", "-A"); self.git(work, "commit", "-q", "-m", "evidence")
        self.git(work, "push", "-q", str(base / "origin"), "ci-evidence/42")

    def git(self, cwd, *args):
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True, capture_output=True, text=True)

    def fake_gh(self, status="completed", conclusion="success", workflow="verify", head=None, event="pull_request", attempt=1):
        head = head or self.head
        body = json.dumps({"status": status, "conclusion": conclusion, "headSha": head, "event": event, "workflowName": workflow, "attempt": attempt})
        gh = self.bin / "gh"
        gh.write_text("#!/bin/sh\ncat <<'JSON'\n" + body + "\nJSON\n")
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)

    def run_import(self, run="42"):
        return subprocess.run([sys.executable, "-I", str(REPO / "tools" / "project.py"), "import-ci-evidence", "--run", run],
                              env={**self.env, "NAWAH_ROOT": str(self.root)}, capture_output=True, text=True)

    def imported(self):
        return (self.root / "evidence" / self.run_dir.name).exists()

    def test_a_successful_verify_run_is_imported_with_import_json_and_an_untouched_run_json(self):
        self.fake_gh()
        r = self.run_import()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(self.imported())
        d = self.root / "evidence" / self.run_dir.name
        self.assertEqual(d.joinpath("run.json").read_text(), self.run_json)
        imp = json.loads(d.joinpath("import.json").read_text())
        self.assertEqual(imp["ci_run_id"], "42")
        self.assertEqual(imp["conclusion"], "success")
        self.assertEqual(imp["head_sha"], self.head)
        for k in ("event", "run_attempt", "evidence_branch_commit", "imported_at"):
            self.assertIn(k, imp)
        # the importer's identity (REQ-M0-006: who adopted the evidence), never a free string
        self.assertIn(imp["importer"]["worker"], ("verification-runner", "interactive-agent", "test"))
        self.assertTrue(imp["importer"]["identity"])

    def test_a_cancelled_or_failed_run_imports_nothing(self):
        for conclusion in ("cancelled", "failure"):
            self.fake_gh(conclusion=conclusion)
            r = self.run_import()
            self.assertNotEqual(r.returncode, 0, conclusion)
            self.assertFalse(self.imported(), conclusion)

    def test_another_workflow_imports_nothing(self):
        self.fake_gh(workflow="release")
        self.assertNotEqual(self.run_import().returncode, 0)
        self.assertFalse(self.imported())

    def test_a_head_that_is_not_an_ancestor_of_HEAD_imports_nothing(self):
        self.fake_gh(head="0123456789abcdef0123456789abcdef01234567")
        self.assertNotEqual(self.run_import().returncode, 0)
        self.assertFalse(self.imported())

    def test_a_malformed_run_id_imports_nothing(self):
        self.fake_gh()
        self.assertNotEqual(self.run_import("42;rm").returncode, 0)
        self.assertFalse(self.imported())

    def test_without_gh_the_import_is_blocked(self):
        """PATH holds git alone (the audit of 77d48c91: the system's gh stayed on PATH and the test
        passed through the 'gh run view failed' branch, not the one it names)."""
        only_git = self.base / "only-git"; only_git.mkdir()
        os.symlink(shutil.which("git", path=os.environ.get("PATH", "/usr/bin:/bin")), only_git / "git")
        self.env["PATH"] = str(only_git)
        r = self.run_import()
        self.assertEqual(r.returncode, project.E_BLOCKED, r.stdout + r.stderr)
        self.assertIn("gh is not on PATH", r.stdout)
        self.assertFalse(self.imported())

    def add_foreign_dir(self, run_id="41", attempt=1):
        """The evidence branch also holds a run directory of another run or attempt (WP-81: three
        jobs' evidence merged; a stray directory would receive this run's receipt and fail the
        validator only later)."""
        work = self.base / "work"
        foreign = work / "evidence" / "20260101T000000Z-deadbeef-001-b"
        foreign.mkdir(parents=True)
        (foreign / "verdict.json").write_text(json.dumps({"test_id": "TST-Y", "verdict": "PASS"}))
        (foreign / "run.json").write_text(json.dumps({"run_id": foreign.name, "worker": "verification-runner",
                                                      "ci": {"run_id": run_id, "run_attempt": attempt, "workflow": "verify", "event": "pull_request",
                                                             "sha": "cafe", "head_sha": self.head, "ref": "x"}}))
        self.git(work, "add", "-A"); self.git(work, "commit", "-q", "-m", "foreign")
        self.git(work, "push", "-q", "-f", str(self.base / "origin"), "ci-evidence/42")
        return foreign.name

    def assert_refused_whole(self, r, name):
        self.assertEqual(r.returncode, project.E_VALIDATION, r.stdout + r.stderr)
        self.assertIn(name, r.stdout)
        self.assertEqual(sorted(p.name for p in (self.root / "evidence").iterdir()), [])
        self.assertEqual(list((self.base / "tmp").iterdir()), [], "a temporary copy was left behind")

    def test_a_run_dir_of_another_run_is_refused_and_nothing_is_imported(self):
        name = self.add_foreign_dir(run_id="41")
        self.fake_gh()
        self.assert_refused_whole(self.run_import(), name)

    def test_a_run_dir_of_another_attempt_is_refused_and_nothing_is_imported(self):
        name = self.add_foreign_dir(attempt=2)
        self.fake_gh()
        self.assert_refused_whole(self.run_import(), name)

    def test_a_run_dir_without_ci_identity_is_refused_and_nothing_is_imported(self):
        work = self.base / "work"
        bare = work / "evidence" / "20260101T000000Z-deadbeef-001-c"
        bare.mkdir(parents=True)
        (bare / "verdict.json").write_text(json.dumps({"test_id": "TST-Z", "verdict": "PASS"}))
        (bare / "run.json").write_text(json.dumps({"run_id": bare.name, "worker": "verification-runner"}))
        self.git(work, "add", "-A"); self.git(work, "commit", "-q", "-m", "no ci")
        self.git(work, "push", "-q", "-f", str(self.base / "origin"), "ci-evidence/42")
        self.fake_gh()
        self.assert_refused_whole(self.run_import(), bare.name)

    def add_committed_dirs(self):
        """The real evidence branch holds the whole committed evidence tree (verify.yml, mutants.yml:
        `git add -f evidence/` on the full checkout): older directories, 1.0.0 without a ci object or
        naming other runs, that HEAD already carries under evidence/. They are skipped, never checked
        against this run's identity (the audit of WP-81, C1: refs/remotes/ci/42775276374 holds 7367
        such directories)."""
        work = self.base / "work"
        names = []
        for name, ci in (("20251017T210133Z-c049336e-001", None), ("20251018T000000Z-c049336e-001", {"run_id": "41", "run_attempt": 1, "sha": "beef"})):
            run = {"run_id": name, "worker": "test"}
            if ci:
                run["ci"] = ci
            for parent in (work / "evidence", self.root / "evidence"):
                d = parent / name
                d.mkdir(parents=True)
                (d / "verdict.json").write_text(json.dumps({"test_id": "TST-OLD", "verdict": "PASS"}))
                (d / "run.json").write_text(json.dumps(run))
            names.append(name)
        self.git(work, "add", "-A"); self.git(work, "commit", "-q", "-m", "committed tree")
        self.git(work, "push", "-q", "-f", str(self.base / "origin"), "ci-evidence/42")
        self.git(self.root, "add", "-A"); self.git(self.root, "commit", "-q", "-m", "committed evidence")
        self.head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.root, env=self.env, capture_output=True, text=True, check=True).stdout.strip()
        return names

    def test_committed_dirs_without_this_runs_identity_are_skipped_and_this_runs_imported(self):
        old = self.add_committed_dirs()
        before = {n: (self.root / "evidence" / n / "run.json").read_text() for n in old}
        self.fake_gh()
        r = self.run_import()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("imported 1 run(s) from CI run 42", r.stdout)
        self.assertTrue((self.root / "evidence" / self.run_dir.name / "import.json").exists())
        for n in old:
            self.assertFalse((self.root / "evidence" / n / "import.json").exists(), n)
            self.assertEqual((self.root / "evidence" / n / "run.json").read_text(), before[n], n)
        self.assertEqual(list((self.base / "tmp").iterdir()), [], "a temporary copy was left behind")

    def test_a_new_foreign_dir_next_to_committed_ones_is_refused_and_nothing_is_written(self):
        old = self.add_committed_dirs()
        name = self.add_foreign_dir(run_id="41")
        self.fake_gh()
        r = self.run_import()
        self.assertEqual(r.returncode, project.E_VALIDATION, r.stdout + r.stderr)
        self.assertIn(name, r.stdout)
        self.assertEqual(sorted(p.name for p in (self.root / "evidence").iterdir()), sorted(old))
        for n in old:
            self.assertFalse((self.root / "evidence" / n / "import.json").exists(), n)
        self.assertEqual(list((self.base / "tmp").iterdir()), [], "a temporary copy was left behind")

    def test_gh_naming_another_attempt_than_the_run_dirs_is_refused(self):
        self.fake_gh(attempt=2)
        self.assert_refused_whole(self.run_import(), self.run_dir.name)

    def test_a_run_id_with_a_trailing_newline_is_refused(self):
        """re.match with $ accepts '42\\n' (the audit of 77d48c91, gap 6); the id must match whole."""
        self.fake_gh()
        r = self.run_import("42\n")
        self.assertEqual(r.returncode, project.E_VALIDATION, r.stdout + r.stderr)
        self.assertIn("not <digits>", r.stdout)
        self.assertFalse(self.imported())


def native_dir(parent, name, test_id, run_id="42", attempt=1, sha_="cafe", with_ci=True):
    """A run directory as a verify job writes it (worker verification-runner, ci identity), named
    with its job slot, valid against the records written by write_all."""
    d = parent / name
    d.mkdir(parents=True)
    inputs = {"docs/ENVIRONMENT.md": sha((TMP / "docs/ENVIRONMENT.md").read_bytes())}
    combined = sha("\n".join(f"{k}={v}" for k, v in sorted(inputs.items())).encode())
    run = {"schema_version": RUN_SV, "run_id": name, "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:00:01+00:00",
           "source_revision": "deadbeef", "dirty_state": False, "dirty_paths": [], "host": {}, "target": "host", "worker": "verification-runner",
           "purpose": "unit", "commands": ["x"], "exit_code": 0}
    if with_ci:
        run["ci"] = {**CI, "run_id": run_id, "run_attempt": attempt, "sha": sha_}
    v = {"schema_version": SV, "run_id": name, "test_id": test_id, "verdict": "PASS", "oracle": "o", "expected": "e", "observed": "o",
         "inputs_digest": combined, "inputs": inputs, "claim_tag": "source_backed_fact"}
    (d / "run.json").write_text(json.dumps(run)); (d / "verdict.json").write_text(json.dumps(v)); (d / "digests.json").write_text(json.dumps(inputs))
    for f in ("command.txt", "stdout.log", "stderr.log"):
        (d / f).write_text("")
    (d / "exit_code").write_text("0\n")
    return d


class AdoptNative(unittest.TestCase):
    """`adopt-native --from <dir>` (WP-81, ADR-0026 rule 5): the merge job adopts the run
    directories its own verify jobs wrote, without gh and without import.json, only when every
    directory carries the same run id and attempt (and the environment's, when present)."""
    STAMP = "20260101T000000Z-deadbeef-001"

    def setUp(self):
        recs = base_records()
        for n in ("002", "003"):
            t = copy.deepcopy(recs["tests"][0]); t["id"] = f"TST-M0-{n}"; recs["tests"].append(t)
        write_all(recs)
        for sub in ("evidence", "artifacts", "artifacts2"):
            if (TMP / sub).exists():
                shutil.rmtree(TMP / sub)
        (TMP / "evidence").mkdir()
        self.src = TMP / "artifacts"
        for slot, n in zip("abc", ("001", "002", "003")):
            native_dir(self.src, f"{self.STAMP}-{slot}", f"TST-M0-{n}")
        self.tests_before = (TMP / "docs" / "tests.json").read_bytes()
        self.saved = {k: os.environ.pop(k) for k in ("GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA") if k in os.environ}
        self.addCleanup(os.environ.update, self.saved)

    def adopt(self, *dirs):
        args = ["adopt-native"]
        for d in dirs or (self.src,):
            args += ["--from", str(d)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = project.main(args)
        return rc, out.getvalue()

    def assert_unchanged(self, rc, out):
        self.assertEqual(rc, project.E_VALIDATION, out)
        self.assertEqual(list((TMP / "evidence").iterdir()), [])
        self.assertEqual((TMP / "docs" / "tests.json").read_bytes(), self.tests_before)

    def test_three_slots_of_one_run_are_adopted_and_their_verdicts_re_pointed(self):
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt()
            self.assertEqual(rc, project.E_OK, out)
            names = sorted(p.name for p in (TMP / "evidence").iterdir())
            self.assertEqual(names, [f"{self.STAMP}-{s}" for s in "abc"])
            for n in names:
                self.assertFalse((TMP / "evidence" / n / "import.json").exists(), n)
            tests = {t["id"]: t for t in json.loads((TMP / "docs" / "tests.json").read_text())["records"]}
            for slot, n in zip("abc", ("001", "002", "003")):
                self.assertEqual(tests[f"TST-M0-{n}"]["verdict"], "PASS")
                self.assertEqual(tests[f"TST-M0-{n}"]["evidence_refs"], [f"evidence/{self.STAMP}-{slot}"])
            # native to this very run: strict validation accepts them without a receipt
            self.assertEqual(project.validate_records(verbose=False, strict=True), project.E_OK)
        self.assertIn("adopted 3 run(s)", out)

    def test_off_the_runner_nothing_is_adopted(self):
        """Fail closed like the validator's native rule: no GITHUB_ACTIONS, or any of the run id,
        attempt and sha missing from the environment, and nothing is native."""
        self.assert_unchanged(*self.adopt())
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1", GITHUB_SHA=""):
            self.assert_unchanged(*self.adopt())
        with ci_env(GITHUB_RUN_ID="", GITHUB_RUN_ATTEMPT="1", GITHUB_SHA="cafe"):
            self.assert_unchanged(*self.adopt())

    def test_a_set_mixing_another_sha_is_refused_whole(self):
        native_dir(self.src, f"{self.STAMP}-d", "TST-M0-001", sha_="beef")
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1", GITHUB_SHA="cafe"):
            rc, out = self.adopt()
        self.assert_unchanged(rc, out)
        self.assertIn(f"{self.STAMP}-d", out)

    def test_a_set_of_another_sha_than_the_environments_is_refused(self):
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1", GITHUB_SHA="beef"):
            self.assert_unchanged(*self.adopt())

    def test_an_empty_set_is_refused(self):
        empty = TMP / "artifacts2"; empty.mkdir()
        (empty / "stray").mkdir()  # a directory with no verdict.json is no run
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt(empty)
            self.assert_unchanged(rc, out)
            self.assertIn("no run director", out)
            rc, out = self.adopt(self.src, empty)  # one --from holding no run dir
            self.assert_unchanged(rc, out)
            self.assertIn(str(empty), out)

    def test_a_set_mixing_another_attempt_is_refused_whole(self):
        native_dir(self.src, f"{self.STAMP}-d", "TST-M0-001", attempt=2)
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt()
        self.assert_unchanged(rc, out)
        self.assertIn(f"{self.STAMP}-d", out)

    def test_a_set_mixing_another_run_is_refused_whole(self):
        native_dir(self.src, f"{self.STAMP}-d", "TST-M0-001", run_id="41")
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt()
        self.assert_unchanged(rc, out)
        self.assertIn(f"{self.STAMP}-d", out)

    def test_a_set_of_another_run_than_the_environments_is_refused(self):
        with ci_env(GITHUB_RUN_ID="43", GITHUB_RUN_ATTEMPT="1"):
            self.assert_unchanged(*self.adopt())
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="2"):
            self.assert_unchanged(*self.adopt())

    def test_a_dir_without_ci_identity_is_refused(self):
        native_dir(self.src, f"{self.STAMP}-d", "TST-M0-001", with_ci=False)
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            self.assert_unchanged(*self.adopt())

    def test_a_duplicate_run_id_is_refused(self):
        other = TMP / "artifacts2"
        native_dir(other, f"{self.STAMP}-a", "TST-M0-001")
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt(self.src, other)
        self.assert_unchanged(rc, out)
        self.assertIn(f"{self.STAMP}-a", out)

    def test_a_run_id_already_in_evidence_is_skipped_and_the_new_ones_adopted(self):
        """Each job's evidence/ artifact and the merge job's checkout hold every committed directory
        (verify.yml upload-artifact path: evidence/): a directory already under evidence/ is skipped
        and counted, never adopted again (the audit of WP-81, C2)."""
        native_dir(TMP / "evidence", f"{self.STAMP}-a", "TST-M0-001")
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt()
        self.assertEqual(rc, project.E_OK, out)
        self.assertEqual(sorted(p.name for p in (TMP / "evidence").iterdir()), [f"{self.STAMP}-{s}" for s in "abc"])
        tests = {t["id"]: t for t in json.loads((TMP / "docs" / "tests.json").read_text())["records"]}
        before = {t["id"]: t for t in json.loads(self.tests_before)["records"]}
        self.assertEqual(tests["TST-M0-001"], before["TST-M0-001"])  # the skipped one is not re-attached
        self.assertEqual(tests["TST-M0-002"]["evidence_refs"], [f"evidence/{self.STAMP}-b"])
        self.assertIn("skipped 1 run(s) already under evidence/", out)
        self.assertIn("adopted 2 run(s)", out)

    def test_committed_dirs_of_other_runs_are_skipped_and_this_runs_adopted(self):
        """The mixed artifact: older committed directories (no ci identity, or another run's) next
        to this run's slots, in one source and repeated in a second source: the old ones are
        skipped wherever they appear (a skipped directory is no duplicate), the new ones adopted."""
        old = ["20251017T210133Z-c049336e-001", "20251018T000000Z-c049336e-001"]
        other = TMP / "artifacts2"
        for parent in (TMP / "evidence", self.src, other):
            native_dir(parent, old[0], "TST-M0-001", with_ci=False)
            native_dir(parent, old[1], "TST-M0-002", run_id="41", sha_="beef")
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt(self.src, other)
            self.assertEqual(rc, project.E_OK, out)
            self.assertEqual(sorted(p.name for p in (TMP / "evidence").iterdir()), sorted(old + [f"{self.STAMP}-{s}" for s in "abc"]))
            tests = {t["id"]: t for t in json.loads((TMP / "docs" / "tests.json").read_text())["records"]}
            for slot, n in zip("abc", ("001", "002", "003")):
                self.assertEqual(tests[f"TST-M0-{n}"]["evidence_refs"], [f"evidence/{self.STAMP}-{slot}"])
        self.assertIn("skipped 4 run(s) already under evidence/", out)
        self.assertIn("adopted 3 run(s)", out)

    def test_a_new_dir_of_another_run_next_to_committed_ones_is_refused_whole(self):
        native_dir(TMP / "evidence", f"{self.STAMP}-a", "TST-M0-001")
        native_dir(self.src, f"{self.STAMP}-d", "TST-M0-001", run_id="41")
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt()
        self.assertEqual(rc, project.E_VALIDATION, out)
        self.assertIn(f"{self.STAMP}-d", out)
        self.assertEqual(sorted(p.name for p in (TMP / "evidence").iterdir()), [f"{self.STAMP}-a"])
        self.assertEqual((TMP / "docs" / "tests.json").read_bytes(), self.tests_before)

    def test_nothing_new_to_adopt_is_refused(self):
        for slot, n in zip("abc", ("001", "002", "003")):
            native_dir(TMP / "evidence", f"{self.STAMP}-{slot}", f"TST-M0-{n}")
        with ci_env(GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1"):
            rc, out = self.adopt()
        self.assertEqual(rc, project.E_VALIDATION, out)
        self.assertIn("nothing new to adopt", out)
        self.assertEqual((TMP / "docs" / "tests.json").read_bytes(), self.tests_before)

if __name__ == "__main__":
    unittest.main(verbosity=2)
