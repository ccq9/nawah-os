#!/usr/bin/env python3
"""Acceptance tests for the §20 task interface (tools/orchestrator.py), on an ISOLATED trial
project — never the real records (OS-EXEC-AR 3.2 §20: "اختبر المشغّل على مشروع تجريبي معزول قبل
إسناد العمل الطويل إليه"). Each test builds a tiny git repo with valid records and drives the
real next/report/resume/run/cancel code.

Covered, one test each:
  - next hands out and activates exactly the ready package, under the lease;
  - report accepts a matching result and moves the package; a checkpoint follows;
  - report rejects a corrupt result, a stale fencing token, phantom/unclaimed files, and
    evidence that predates the package — and nothing moves;
  - a worker interrupted before its effect / after its effect / before the result is saved is
    reconciled by resume (idempotent: a found result is reported once, a missing one re-hands);
  - two writers cannot both hold the state (flock) and the fenced one is refused;
  - the retry limit halts a package after repeated worker failure; cancel stops the run and does
    not reschedule, and only --clear with a new authorisation resumes.
"""
import copy, json, os, subprocess, sys, tempfile, unittest, importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SV = "1.0.0"


def jload(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def jdump(p, obj):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)


def load_project(root):
    """Import tools/project.py bound to an isolated NAWAH_ROOT, plus its orchestrator."""
    os.environ["NAWAH_ROOT"] = str(root)
    for name in ("nawah_project_test", "nawah_orch_test"):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("nawah_project_test", REPO / "tools" / "project.py")
    P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
    ospec = importlib.util.spec_from_file_location("nawah_orch_test", REPO / "tools" / "orchestrator.py")
    orch = importlib.util.module_from_spec(ospec); ospec.loader.exec_module(orch)
    return P, orch


def req(i, stage, status="verified_in_scope", tests=(), ev=()):
    return {"id": i, "statement": "s", "rationale": "r", "source": "prompt 3.2", "origin": "derived",
            "priority": "must", "release": "R1", "stage": stage, "dependencies": [], "contract_refs": [],
            "failure_cases": ["f"], "acceptance": "a", "test_ids": list(tests),
            "implementation_status": status, "evidence_refs": list(ev)}


def wi(i, stage, status="planned", deps=(), reqs=(), tests=(), ev=(), blocker=None):
    hist = {"planned": ["planned"], "active": ["planned", "active"], "done": ["planned", "active", "done"],
            "blocked": ["planned", "active", "blocked"]}[status]
    return {"id": i, "stage": stage, "requirement_ids": list(reqs), "depends_on": list(deps), "inputs": ["i"],
            "files": [], "contract_refs": [], "actions": ["do the thing"], "acceptance": "a", "test_ids": list(tests),
            "commands": ["python3 tools/project.py validate-records"], "status": status, "status_history": hist,
            "evidence_refs": list(ev), "blocker": blocker}


def tst(i, reqs, verdict="NOT_RUN", ev=()):
    return {"id": i, "requirement_ids": list(reqs), "layer": "guest", "oracle": "o", "command": "x",
            "verdict": verdict, "evidence_refs": list(ev)}


def automation(worker_command=None):
    return {"schema_version": SV, "mode": "interactive",
            "verification_runner": {"mode": "durable"}, "development_worker": {"mode": "interactive"},
            "worker_command": worker_command, "worker_version": None, "supervisor": None,
            "persistent_store": {"type": "git"}, "persistence_verified_by": None,
            "lease_policy": {"ttl_s": 900}, "workspace_root": "x", "allowed_targets": ["host"],
            "permission_refs": ["test"], "retry_policy": {}, "operation_timeouts": {"work_package": {"minutes": 90}},
            "budgets": {"max_packages_per_run": 4}, "concurrency_limit": 1, "checkpoint_policy": {},
            "cancellation_policy": {}, "restart_policy": {"max_restarts_per_round": 2}, "context_policy": {}}


def project_state(recs):
    return {"schema_version": SV, "project_id": "trial", "prompt_version": "test", "prompt_digest": "unknown",
            "project_root": "x", "source_revision": "0" * 40, "dirty_state": False, "current_stage": "M0",
            "current_task": None, "completed_requirement_ids": sorted(r["id"] for r in recs["requirements"]
            if r["implementation_status"] == "verified_in_scope"), "last_run_id": None, "blockers": [],
            "next_action": "start", "required_inputs": [], "runner_status": "running", "checkpoint_generation": 1,
            "event_sequence": 1, "pending_operations": [], "budget_counters": {}, "next_retry_at": None,
            "cancellation_state": "none", "lease": None, "host_fingerprint": "x", "errata_version": "1",
            "pending_decision_ids": [], "unknown_fields": {}}


class Trial:
    """An isolated trial project: a git repo with the schemas and a small valid record set."""
    def __init__(self, recs):
        self.dir = Path(tempfile.mkdtemp(prefix="nawah-orch-"))
        docs = self.dir / "docs"
        (docs / "schemas").mkdir(parents=True)
        for s in (REPO / "docs" / "schemas").glob("*.json"):
            (docs / "schemas" / s.name).write_text(s.read_text())
        for name in ("requirements", "stages", "work-items", "tests", "risks", "sources", "hardware", "decisions-pending"):
            (docs / f"{name}.json").write_text(json.dumps({"schema_version": SV, "records": recs.get(name, [])}, ensure_ascii=False, indent=1))
        (docs / "automation.json").write_text(json.dumps(recs["automation"], ensure_ascii=False, indent=1))
        (docs / "project-state.json").write_text(json.dumps(project_state(recs), ensure_ascii=False, indent=1))
        (docs / "PROJECT.md").write_text("# trial\n")
        (docs / "prompt").mkdir()
        (docs / "prompt" / "OS-EXEC-AR-vtest.md").write_text("trial prompt\n")
        (self.dir / "work").mkdir()
        (self.dir / ".gitignore").write_text("build/\nstate/\n__pycache__/\n")
        self.git("init", "-q"); self.git("add", "-A")
        self.git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "trial")
        self.P, self.orch = load_project(self.dir)

    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.dir, capture_output=True, text=True, check=True).stdout.strip()

    def head(self):
        return self.git("rev-parse", "HEAD")

    def commit(self, msg="change"):
        self.git("add", "-A"); self.git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", msg)
        return self.head()

    def mark_test_pass(self, test_id, ev):
        """What a worker's `project.py test` run does to the records: set the test PASS with its
        evidence. docs/tests.json is tool-written, so the worker does not claim it."""
        p = self.dir / "docs" / "tests.json"
        data = jload((p))
        for t in data["records"]:
            if t["id"] == test_id:
                t["verdict"] = "PASS"; t["evidence_refs"] = [ev]
        jdump(p, data)

    def make_evidence(self, rid, test_id, verdict="PASS", inputs=("work/f.txt",)):
        d = self.dir / "evidence" / rid
        d.mkdir(parents=True, exist_ok=True)
        digs = {p: self.P.sha256_file(self.dir / p) for p in inputs}
        combined = self.P.sha256_text("\n".join(f"{k}={v}" for k, v in sorted(digs.items())))
        run = {"schema_version": SV, "run_id": rid, "started_at": "2026-01-01T00:00:00+00:00",
               "finished_at": "2026-01-01T00:00:01+00:00", "source_revision": self.head(), "dirty_state": False,
               "host": {}, "target": "host", "worker": "t", "purpose": "u", "commands": ["x"], "exit_code": 0}
        v = {"schema_version": SV, "run_id": rid, "test_id": test_id, "verdict": verdict, "oracle": "o",
             "expected": "e", "observed": "o", "inputs_digest": combined, "inputs": digs, "claim_tag": "source_backed_fact"}
        (d / "run.json").write_text(json.dumps(run)); (d / "verdict.json").write_text(json.dumps(v))
        (d / "digests.json").write_text(json.dumps(digs))
        for f in ("command.txt", "stdout.log", "stderr.log"):
            (d / f).write_text("")
        (d / "exit_code").write_text("0\n")
        return f"evidence/{rid}"

    def result(self, task, token, head, outcome="done", changed=(), ev=(), **extra):
        r = {"schema_version": SV, "task_id": task, "input_revision": head, "fencing_token": token,
             "changed_files": list(changed), "command_results": [{"command": "x", "exit_code": 0}],
             "evidence_refs": list(ev), "outcome": outcome, "blocker": None, "next_action": "next"}
        r.update(extra); return r

    def write_result(self, path, obj):
        p = self.dir / path; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, ensure_ascii=False)); return path


def base(worker_command=None):
    return {
        "requirements": [req("REQ-M0-001", "M0", "partial", tests=["TST-A"]), req("REQ-M0-002", "M0", "partial", tests=["TST-B"])],
        "stages": [{"id": "M0", "name": "n", "depends_on": [], "entry_conditions": ["e"], "exit_conditions": ["x"], "gate_status": "open"}],
        "work-items": [wi("WP-01", "M0", reqs=["REQ-M0-001"], tests=["TST-A"]),
                       wi("WP-02", "M0", deps=["WP-01"], reqs=["REQ-M0-002"], tests=["TST-B"])],
        "tests": [tst("TST-A", ["REQ-M0-001"]), tst("TST-B", ["REQ-M0-002"])],
        "decisions-pending": [], "automation": automation(worker_command)}


class NextAndReport(unittest.TestCase):
    def setUp(self):
        self.t = Trial(base())

    def test_next_hands_out_ready_and_activates_under_lease(self):
        rc, out = self.t.orch.hand_out(self.t.P, "alice")
        self.assertEqual(rc, self.t.P.E_OK)
        self.assertEqual(out["task"]["id"], "WP-01")  # WP-02 depends on it, so not ready
        self.assertEqual(out["lease"]["holder_id"], "alice")
        data = jload((self.t.dir / "docs" / "work-items.json"))
        self.assertEqual([w for w in data["records"] if w["id"] == "WP-01"][0]["status"], "active")
        st = jload((self.t.dir / "docs" / "project-state.json"))
        self.assertEqual(st["current_task"], "WP-01")
        self.assertIn("WP-01", st["next_action"])

    def test_report_accepts_matching_result_and_moves_package(self):
        self.t.orch.hand_out(self.t.P, "alice")
        rev0 = self.t.head()  # the pack's input_revision: before the worker's effect
        (self.t.dir / "work" / "f.txt").write_text("done")
        ev = self.t.make_evidence("20260101T000000Z-" + rev0[:8] + "-001", "TST-A")
        self.t.mark_test_pass("TST-A", ev)  # the worker's test run
        self.t.commit("WP-01 work + evidence")
        tok = jload((self.t.dir / "docs" / "project-state.json"))["lease"]["fencing_token"]
        res = self.t.result("WP-01", tok, rev0, changed=["work/f.txt"], ev=[ev])
        rc = self.t.orch.apply_report(self.t.P, "alice", res)
        self.assertEqual(rc, self.t.P.E_OK)
        data = jload((self.t.dir / "docs" / "work-items.json"))
        self.assertEqual([w for w in data["records"] if w["id"] == "WP-01"][0]["status"], "done")
        self.assertEqual([w for w in data["records"] if w["id"] == "WP-02"][0]["status"], "planned")  # report does not auto-activate
        st = jload((self.t.dir / "docs" / "project-state.json"))
        self.assertEqual(st["current_task"], "WP-02")  # current points at the next ready package

    def test_report_rejects_stale_token_and_nothing_moves(self):
        self.t.orch.hand_out(self.t.P, "alice")
        head = self.t.head()
        res = self.t.result("WP-01", 999, head)
        rc = self.t.orch.apply_report(self.t.P, "alice", res)
        self.assertEqual(rc, self.t.P.E_BLOCKED)
        data = jload((self.t.dir / "docs" / "work-items.json"))
        self.assertEqual([w for w in data["records"] if w["id"] == "WP-01"][0]["status"], "active")

    def test_report_rejects_phantom_and_unclaimed_files(self):
        self.t.orch.hand_out(self.t.P, "alice")
        (self.t.dir / "work" / "real.txt").write_text("x")
        head = self.t.commit("unrelated change the worker did not declare")
        tok = jload((self.t.dir / "docs" / "project-state.json"))["lease"]["fencing_token"]
        # claims a file it did not touch, and left one unclaimed
        res = self.t.result("WP-01", tok, self.t.git("rev-parse", "HEAD~1"), changed=["work/phantom.txt"])
        rc = self.t.orch.apply_report(self.t.P, "alice", res)
        self.assertEqual(rc, self.t.P.E_VALIDATION)
        self.assertEqual(jload((self.t.dir / "docs" / "work-items.json"))["records"][0]["status"], "active")

    def test_report_rejects_corrupt_result(self):
        self.t.orch.hand_out(self.t.P, "alice")
        rc = self.t.orch.apply_report(self.t.P, "alice", {"not": "a result"})
        self.assertEqual(rc, self.t.P.E_VALIDATION)

    def test_report_rejects_evidence_predating_the_package(self):
        # evidence committed BEFORE the package was handed out: nothing under it changed since
        (self.t.dir / "work" / "f.txt").write_text("x")
        head0 = self.t.commit("pre-work")
        ev = self.t.make_evidence("20260101T000000Z-" + head0[:8] + "-001", "TST-A")
        self.t.git("add", "-A"); head = self.t.commit("old evidence")
        self.t.orch.hand_out(self.t.P, "alice")
        tok = jload((self.t.dir / "docs" / "project-state.json"))["lease"]["fencing_token"]
        res = self.t.result("WP-01", tok, head, ev=[ev])
        rc = self.t.orch.apply_report(self.t.P, "alice", res)
        self.assertEqual(rc, self.t.P.E_VALIDATION)


class LeaseAndConcurrency(unittest.TestCase):
    def setUp(self):
        self.t = Trial(base())

    def test_second_holder_is_refused_while_lease_live(self):
        self.t.orch.hand_out(self.t.P, "alice")
        rc, out = self.t.orch.hand_out(self.t.P, "bob")
        self.assertEqual(rc, self.t.P.E_BLOCKED)
        self.assertIn("alice", out["blocked"])

    def test_flock_excludes_two_writers_at_once(self):
        with self.t.orch.state_lock(self.t.P):
            with self.assertRaises(self.t.P.LeaseHeld):
                with self.t.orch.state_lock(self.t.P):
                    pass

    def test_report_after_takeover_is_fenced_out(self):
        self.t.orch.hand_out(self.t.P, "alice")
        tok = jload((self.t.dir / "docs" / "project-state.json"))["lease"]["fencing_token"]
        # alice's lease expires; bob takes over at the next checkpoint (new token)
        st = jload((self.t.dir / "docs" / "project-state.json"))
        st["lease"]["heartbeat_at"] = "2000-01-01T00:00:00+00:00"
        jdump(self.t.dir / "docs" / "project-state.json", st)
        self.t.P.checkpoint(note="bob takeover", holder="bob")
        (self.t.dir / "work" / "f.txt").write_text("x"); head = self.t.commit("w")
        res = self.t.result("WP-01", tok, head, changed=["work/f.txt"])  # alice's old token
        rc = self.t.orch.apply_report(self.t.P, "alice", res)
        self.assertEqual(rc, self.t.P.E_BLOCKED)


class WorkerReconcile(unittest.TestCase):
    """A durable worker: a fake command writes (or does not write) the result file."""
    def _worker(self, body):
        p = self.dir / "worker.py"
        p.write_text("#!/usr/bin/env python3\nimport sys, json\n" + body + "\n")
        return f"{sys.executable} {p}"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="nawah-worker-"))

    def _trial(self, body):
        # a worker that does its effect (a commit) and writes a matching result
        cmd = self._worker(body)
        t = Trial(base(worker_command=cmd))
        self.t = t
        return t

    def test_worker_finishes_and_result_is_reported(self):
        body = r"""
ctx = json.load(open(sys.argv[1]))
tok = ctx["lease"]["fencing_token"]; task = ctx["task"]["id"]
import subprocess, pathlib
root = pathlib.Path(ctx["goal"]["ref"]).resolve().parents[1]
(root / "work" / "f.txt").write_text("worker did this")
subprocess.run(["git","-C",str(root),"add","-A"],check=True)
subprocess.run(["git","-C",str(root),"-c","user.email=w@w","-c","user.name=w","commit","-qm","worker"],check=True)
json.dump({"schema_version":"1.0.0","task_id":task,"input_revision":ctx["input_revision"],"fencing_token":tok,
 "changed_files":["work/f.txt"],"command_results":[{"command":"x","exit_code":0}],"evidence_refs":[],
 "outcome":"blocked","blocker":"needs a decision","next_action":"n"}, open(sys.argv[2],"w"))
"""
        t = self._trial(body)
        rc, info = t.orch.resume_once(t.P, "alice")
        self.assertEqual(rc, t.P.E_OK, info)
        self.assertEqual(jload((t.dir / "docs" / "work-items.json"))["records"][0]["status"], "blocked")
        self.assertEqual(jload((t.dir / "docs" / "project-state.json"))["pending_operations"], [])

    def test_worker_interrupted_before_saving_result_rehands(self):
        # the worker makes its effect but writes NO result (interrupted before saving)
        body = r"""
ctx = json.load(open(sys.argv[1]))
import subprocess, pathlib
root = pathlib.Path(ctx["goal"]["ref"]).resolve().parents[1]
(root / "work" / "f.txt").write_text("effect without a result")
subprocess.run(["git","-C",str(root),"add","-A"],check=True)
subprocess.run(["git","-C",str(root),"-c","user.email=w@w","-c","user.name=w","commit","-qm","effect"],check=True)
"""
        t = self._trial(body)
        rc, info = t.orch.resume_once(t.P, "alice")
        self.assertEqual(info.get("worker_failed"), "WP-01")
        self.assertEqual(jload((t.dir / "docs" / "project-state.json"))["pending_operations"], [])
        # the package stays active and is handed out again
        self.assertEqual(jload((t.dir / "docs" / "work-items.json"))["records"][0]["status"], "active")

    def test_pending_result_found_on_resume_is_reported_once(self):
        # simulate an interruption AFTER the worker saved a result but BEFORE report: a pending
        # operation whose result file exists. reconcile must report it, not re-run the worker.
        t = self._trial("pass")
        t.orch.hand_out(t.P, "alice")
        rev0 = t.head()  # before the worker's effect
        tok = jload((t.dir / "docs" / "project-state.json"))["lease"]["fencing_token"]
        (t.dir / "work" / "f.txt").write_text("x")
        ev = t.make_evidence("20260101T000000Z-" + rev0[:8] + "-001", "TST-A")
        t.mark_test_pass("TST-A", ev); t.commit("worker effect + evidence")
        op = {"id": "op-worker-WP-01-g9", "type": "worker", "task_id": "WP-01", "started_at": "2026-01-01T00:00:00+00:00",
              "context_digest": "x", "result_path": "build/orchestrator/WP-01.result.json"}
        t.P.checkpoint(note="pending op", holder="alice", mutate=lambda st: st["pending_operations"].append(op))
        t.write_result(op["result_path"], t.result("WP-01", tok, rev0, changed=["work/f.txt"], ev=[ev]))
        rc, info = t.orch.reconcile(t.P, "alice")
        self.assertEqual(rc, t.P.E_OK, info)
        self.assertEqual(jload((t.dir / "docs" / "work-items.json"))["records"][0]["status"], "done")
        self.assertEqual(jload((t.dir / "docs" / "project-state.json"))["pending_operations"], [])

    def test_retry_limit_halts_the_package(self):
        # a worker that always makes an effect but never writes a result: fails every time
        body = r"""
ctx = json.load(open(sys.argv[1]))
import subprocess, pathlib, time
root = pathlib.Path(ctx["goal"]["ref"]).resolve().parents[1]
(root / "work" / "f.txt").write_text("attempt " + str(time.time()))
subprocess.run(["git","-C",str(root),"add","-A"],check=True)
subprocess.run(["git","-C",str(root),"-c","user.email=w@w","-c","user.name=w","commit","-qm","attempt"],check=True)
"""
        t = self._trial(body)  # max_restarts_per_round = 2
        rc = t.orch.cmd_run(t.P, "alice")
        self.assertEqual(rc, t.P.E_BLOCKED)  # halted, not an endless loop
        halted = jload((t.dir / "docs" / "project-state.json"))["budget_counters"].get("halted_tasks", [])
        self.assertIn("WP-01", halted)


class Cancel(unittest.TestCase):
    def setUp(self):
        self.t = Trial(base())

    def test_cancel_stops_handing_out_and_does_not_reschedule(self):
        self.t.P.checkpoint(note="init", holder="alice")
        self.assertEqual(self.t.orch.cmd_cancel(self.t.P, "alice", clear=False, note="user stop"), self.t.P.E_OK)
        rc, out = self.t.orch.hand_out(self.t.P, "alice")
        self.assertEqual(rc, self.t.P.E_CANCELLED)
        rc, out = self.t.orch.resume_once(self.t.P, "alice")
        self.assertEqual(rc, self.t.P.E_CANCELLED)

    def test_clear_needs_a_new_authorisation(self):
        self.t.orch.cmd_cancel(self.t.P, "alice", clear=False, note="stop")
        self.assertEqual(self.t.orch.cmd_cancel(self.t.P, "alice", clear=True, note=None), self.t.P.E_VALIDATION)
        self.assertEqual(self.t.orch.cmd_cancel(self.t.P, "alice", clear=True, note="authorised by user 2026-10-19"), self.t.P.E_OK)
        rc, out = self.t.orch.hand_out(self.t.P, "alice")
        self.assertEqual(rc, self.t.P.E_OK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
