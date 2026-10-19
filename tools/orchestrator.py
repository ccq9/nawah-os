#!/usr/bin/env python3
"""The task interface of tools/project.py (OS-EXEC-AR 3.2 §20): next, report, resume, run, cancel.

  next --json --holder H   hand out the context pack of the next ready work package
                           (docs/schemas/context-pack.schema.json). Its only state change is
                           marking that package active, and only while H holds the lease.
  report --result F --holder H
                           accept a worker's result (docs/schemas/worker-result.schema.json)
                           only when its fencing token is current and its claims (changed
                           files, evidence, outcome) match the tree and the records; then the
                           package moves and a checkpoint is written. A rejected result changes
                           nothing but the event log.
  resume --once --holder H reconcile the saved state (records, cancellation, retry window,
                           pending operations, lease) and hand out one package. With no worker
                           configured (automation.json worker_command null: the interactive
                           mode) it stops there with 70, and the interactive worker does the
                           work and reports. With one, it runs the worker once and reports for it.
  run --until blocked-or-complete --holder H
                           repeat resume within the run budget, carrying on with independent
                           packages when one blocks; 0 only when the whole scope is accepted.
  cancel [--clear --note REF] --holder H
                           a user stop: nothing is handed out or rescheduled until a new
                           authorisation (REF) clears it.

Exit codes are project.py's (§20). Every state write goes through project.checkpoint, which
validates the state it would write; one process at a time holds state/.lock (flock), and the
lease (§2.4) fences writers across processes and sessions.
"""
import contextlib, fcntl, hashlib, json, os, re, shlex, subprocess
from pathlib import Path

COMMANDS = ("next", "report", "resume", "run", "cancel")
OUTCOMES = ("done", "blocked", "partial", "failed")
# Paths the interface and project.py own, so a worker does not claim them in changed_files: the
# state, the event log, the lease, and the JSON record files (a worker's `project.py test` writes
# docs/tests.json through attach_evidence; the package transition writes docs/work-items.json).
# A worker still owns code, evidence/<run> directories, and the prose docs (contracts, ADRs).
def is_tool_written(P, path):
    return (path in ("docs/project-state.json", "evidence/automation/events.jsonl", "state/lease.json", "state/.lock")
            or path in {f"docs/{n}.json" for n in P.RECORD_FILES})
DEFAULT_MAX_PACKAGES = 10
DEFAULT_WORKER_RESTARTS = 3


def add_parsers(sub):
    s = sub.add_parser("next", help="hand out the next ready work package's context pack")
    s.add_argument("--json", action="store_true"); s.add_argument("--holder")
    s = sub.add_parser("report", help="accept a worker's structured result")
    s.add_argument("--result", required=True); s.add_argument("--holder")
    s = sub.add_parser("resume", help="reconcile the saved state, then hand out (or run) one package")
    s.add_argument("--once", action="store_true", required=True); s.add_argument("--holder"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("run", help="repeat resume within the run budget")
    s.add_argument("--until", required=True, choices=["blocked-or-complete"]); s.add_argument("--holder")
    s = sub.add_parser("cancel", help="stop handing out and rescheduling; --clear needs a new authorisation")
    s.add_argument("--clear", action="store_true"); s.add_argument("--note"); s.add_argument("--holder")


def emit(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=1))


@contextlib.contextmanager
def state_lock(P):
    """One writing process at a time in this workspace. The lease fences writers over time;
    this excludes two at the same instant."""
    p = P.ROOT / "state" / ".lock"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a+") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise P.LeaseHeld("another process holds state/.lock") from None
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def load_state(P):
    return P.load_json(P.DOCS / "project-state.json")


def check_lease(P, ps, holder):
    """Raise LeaseHeld when another holder's lease is live (no state change)."""
    lease = ps.get("lease")
    if lease and lease.get("holder_id") != holder and P.lease_live(lease, P.utc_now()):
        raise P.LeaseHeld(f"lease held by {lease['holder_id']} (token {lease['fencing_token']})")


# ----------------------------------------------------------------------------- selection
def blocking_reasons(P, ps, recs):
    """Why nothing can be handed out: each open work item's reason, and the requirements no work
    item carries. An empty queue is not completion (§2.1)."""
    wis = recs.get("work-items", [])
    by_id = {w["id"]: w for w in wis}
    held = {t: d["id"] for d in recs.get("decisions-pending", []) if d["status"] == "open" for t in d["blocked_task_ids"]}
    halted = set(ps["budget_counters"].get("halted_tasks", []))
    reasons = {}
    for w in wis:
        if w["status"] in ("done", "superseded"):
            continue
        why = []
        if w["id"] in halted:
            why.append("automatic retry halted: the same failure fingerprint twice (§2.2)")
        if w["status"] == "blocked":
            why.append(f"blocked: {w['blocker']}")
        if w["id"] in held:
            why.append(f"decision {held[w['id']]} is open")
        why += [f"depends on {d} ({by_id[d]['status'] if d in by_id else 'missing'})"
                for d in w["depends_on"] if by_id.get(d, {}).get("status") != "done"]
        if why:
            reasons[w["id"]] = "; ".join(why)
    carried = {q for w in wis if w["status"] != "superseded" for q in w["requirement_ids"]}
    open_reqs = sorted(r["id"] for r in recs.get("requirements", []) if r["implementation_status"] not in ("verified_in_scope", "out_of_scope"))
    return {"work_items": reasons, "open_requirements": len(open_reqs),
            "requirements_without_work_item": [q for q in open_reqs if q not in carried],
            "stages_not_passed": [s["id"] for s in recs.get("stages", []) if s["gate_status"] != "passed"]}


def no_work_code(P, info):
    """0 only when the whole scope is accepted; 20 when a recorded blocker holds the queue;
    otherwise 10 (nothing ready now, or requirements wait for a work item)."""
    if not info["open_requirements"] and not info["stages_not_passed"] and not info["work_items"]:
        return P.E_OK
    return P.E_BLOCKED if info["work_items"] else P.E_NO_WORK


def select(P, ps, recs, automatic):
    """The package to hand out: the current active one, another active one, else the first
    ready one. Automatic runs skip packages whose retries were halted."""
    wis = recs.get("work-items", [])
    halted = set(ps["budget_counters"].get("halted_tasks", [])) if automatic else set()
    active = [w["id"] for w in wis if w["status"] == "active" and w["id"] not in halted]
    if ps["current_task"] in active:
        return ps["current_task"]
    if active:
        return active[0]
    ready = [t for t in P.ready_work_items(wis, recs.get("decisions-pending", [])) if t not in halted]
    return ready[0] if ready else None


def file_entry(P, rel):
    try:
        p = P.safe_rel(rel)
    except ValueError:
        return {"path": rel, "sha256": None}
    return {"path": rel, "sha256": P.sha256_file(p) if p.is_file() else None}


def context_pack(P, ps, recs, wi):
    """The package's context, generated from the records rather than a conversation's memory (§2)."""
    reqs = {r["id"]: r for r in recs.get("requirements", [])}
    tests = {t["id"]: t for t in recs.get("tests", [])}
    auto = P.load_json(P.DOCS / "automation.json")
    rev, dirty = P.source_identity()
    contracts = sorted(set(wi["contract_refs"]) | {c for q in wi["requirement_ids"] if q in reqs for c in reqs[q]["contract_refs"]})
    last_failure = None
    for t in wi["test_ids"]:
        tr = tests.get(t)
        if tr and tr["verdict"] in ("FAIL", "ERROR") and tr["evidence_refs"]:
            ref = tr["evidence_refs"][0]
            vp = P.safe_rel(ref) / "verdict.json"
            observed = P.load_json(vp).get("observed") if vp.exists() else None
            last_failure = {"test_id": t, "verdict": tr["verdict"], "evidence_ref": ref, "observed": observed}
            break
    goal = P.DOCS / "PROJECT.md"
    return {
        "schema_version": P.SCHEMA_VERSION, "generated_at": P.iso(P.utc_now()), "project_id": ps["project_id"],
        "prompt": {"version": ps["prompt_version"], "digest": ps["prompt_digest"]},
        "goal": {"ref": "docs/PROJECT.md", "sha256": P.sha256_file(goal) if goal.exists() else None},
        "authorization": {"permission_refs": auto["permission_refs"], "allowed_targets": auto["allowed_targets"],
                          "concurrency_limit": auto["concurrency_limit"]},
        "task": wi,
        "requirements": [{k: reqs[q][k] for k in ("id", "statement", "acceptance", "failure_cases", "implementation_status", "contract_refs")}
                         for q in wi["requirement_ids"] if q in reqs],
        "contracts": [dict(file_entry(P, c), version=P.contract_version(Path(c).name) if c.startswith("docs/contracts/") else None)
                      for c in contracts],
        "tests": [{k: tests[t][k] for k in ("id", "layer", "oracle", "command", "verdict", "evidence_refs")} for t in wi["test_ids"] if t in tests],
        "files": [file_entry(P, f) for f in wi["files"]],
        "last_failure": last_failure,
        "budgets": {"operation_timeouts": auto["operation_timeouts"], "budgets": auto["budgets"], "counters": ps["budget_counters"]},
        "lease": {"holder_id": ps["lease"]["holder_id"], "fencing_token": ps["lease"]["fencing_token"]},
        "input_revision": rev, "dirty_state": dirty,
        "result_schema": "docs/schemas/worker-result.schema.json",
    }


def hand_out(P, holder, automatic=False):
    """Select a package, mark it active under the lease, checkpoint. Returns (rc, pack or info)."""
    ps, recs = load_state(P), P.load_state_records()
    try:
        check_lease(P, ps, holder)  # nothing is handed out to a non-holder of a live lease
    except P.LeaseHeld as ex:
        return P.E_BLOCKED, {"blocked": str(ex)}
    if ps["cancellation_state"] != "none":
        return P.E_CANCELLED, {"cancelled": True, "clear_with": "cancel --clear --note <new authorisation>"}
    task = select(P, ps, recs, automatic)
    if task is None:
        info = blocking_reasons(P, ps, recs)
        return no_work_code(P, info), info
    wi_path = P.DOCS / "work-items.json"
    before = wi_path.read_text(encoding="utf-8")
    data = P.load_json(wi_path)
    wi = next(w for w in data["records"] if w["id"] == task)
    activated = wi["status"] == "planned"
    if activated:
        wi["status"] = "active"
        wi["status_history"].append("active")
        P.write_json_atomic(wi_path, data)
    rc, msg = P.checkpoint(note=f"handed out {task}", task=task, holder=holder,
                           extra_events=[("handed_out", f"{task} ({'activated' if activated else 'already active'})")])
    if rc != P.E_OK:
        if activated:
            wi_path.write_text(before, encoding="utf-8")  # roll the activation back
        return rc, {"refused": msg}
    ps, recs = load_state(P), P.load_state_records()
    return P.E_OK, context_pack(P, ps, recs, next(w for w in recs["work-items"] if w["id"] == task))


# ----------------------------------------------------------------------------- report
def normalize_command(cmd):
    """§2.2: a failure's command without its temporary paths, times and run numbers."""
    cmd = re.sub(r"/tmp/\S*", "<tmp>", cmd)
    cmd = re.sub(r"\d{8}T\d{6}Z(-[0-9a-f]{8}-\d{3})?", "<run>", cmd)
    cmd = re.sub(r"\b\d{9,}\b", "<id>", cmd)
    return " ".join(cmd.split())


def failure_fingerprint(res):
    f = res["failure"]
    return hashlib.sha256("\n".join([normalize_command(f["command"]), res["input_revision"], f["category"], f["first_location"]]).encode()).hexdigest()


def changed_paths(P, base):
    """Every path that differs from `base` in the tree (committed, staged, unstaged, untracked)."""
    out = P.git("diff", "--name-only", base)
    untracked = P.git("ls-files", "--others", "--exclude-standard")
    return {l.strip() for l in (out + "\n" + untracked).splitlines() if l.strip()}


def reject(P, reason, rc, task_id=None):
    P.append_event("report_rejected", "rejected", task_id=task_id, result=reason[:500])
    emit({"rejected": reason})
    return rc


def apply_report(P, holder, res):
    """Check a worker's claims against the tree and the records, then move the package."""
    pb = P.Problems()
    P.validate_schema("worker-result", res, pb, "result")
    if pb.errors:
        return reject(P, "; ".join(pb.errors[:5]), P.E_VALIDATION, res.get("task_id") if isinstance(res, dict) else None)
    task = res["task_id"]
    ps = load_state(P)
    lease = ps.get("lease") or {}
    if lease.get("holder_id") != holder or res["fencing_token"] != lease.get("fencing_token"):
        return reject(P, f"fencing: result token {res['fencing_token']} from {holder} but the lease is "
                         f"{lease.get('holder_id')} token {lease.get('fencing_token')} (ownership lost)", P.E_BLOCKED, task)
    recs = P.load_state_records()
    wi = next((w for w in recs.get("work-items", []) if w["id"] == task), None)
    if not wi or wi["status"] != "active":
        return reject(P, f"{task} is not an active work item", P.E_VALIDATION, task)
    rev = res["input_revision"]
    if subprocess.run(["git", "merge-base", "--is-ancestor", rev, "HEAD"], cwd=P.ROOT, capture_output=True).returncode != 0:
        return reject(P, f"input_revision {rev} is not an ancestor of HEAD", P.E_VALIDATION, task)
    evidence = [e.rstrip("/") for e in res["evidence_refs"]]
    actual = {f for f in changed_paths(P, rev) if not is_tool_written(P, f)}

    def under_evidence(f):
        return any(f == e or f.startswith(e + "/") for e in evidence)

    claimed = set(res["changed_files"])
    unclaimed = sorted(f for f in actual if not under_evidence(f) and f not in claimed)
    phantom = sorted(f for f in claimed if f not in actual)
    if unclaimed or phantom:
        return reject(P, f"changed_files do not match the tree: unclaimed {unclaimed[:10]}, claimed but unchanged {phantom[:10]}", P.E_VALIDATION, task)
    for e in evidence:
        P.check_evidence_dir(e, pb, f"result/{e}")
        if not any(f.startswith(e + "/") for f in actual):
            pb.err(f"result/{e}", "evidence predates the package (nothing under it changed since input_revision)")
        vp = P.safe_rel(e) / "verdict.json"
        if vp.exists() and P.load_json(vp)["test_id"] not in wi["test_ids"]:
            pb.err(f"result/{e}", f"evidence is for {P.load_json(vp)['test_id']}, not a test of {task}")
    if pb.errors:
        return reject(P, "; ".join(pb.errors[:5]), P.E_VALIDATION, task)
    outcome = res["outcome"]
    if outcome == "blocked" and not (res["blocker"] or "").strip():
        return reject(P, "outcome blocked without blocker text", P.E_VALIDATION, task)
    if outcome == "failed" and "failure" not in res:
        return reject(P, "outcome failed without its failure (category, first_location, command)", P.E_VALIDATION, task)

    wi_path = P.DOCS / "work-items.json"
    before = wi_path.read_text(encoding="utf-8")
    data = P.load_json(wi_path)
    w = next(x for x in data["records"] if x["id"] == task)
    if outcome in ("done", "blocked"):
        w["status"] = outcome
        w["status_history"].append(outcome)
    if outcome == "done":
        w["evidence_refs"] = sorted(set(w["evidence_refs"]) | set(evidence))
    if outcome == "blocked":
        w["blocker"] = res["blocker"]
    P.write_json_atomic(wi_path, data)
    events = [("report_accepted", f"{task} {outcome}")]
    halted = False

    def mutate(st):
        nonlocal halted
        bc = st["budget_counters"]
        if outcome == "failed":
            fps = bc.setdefault("failure_fingerprints", {}).setdefault(task, [])
            fp = failure_fingerprint(res)
            if fp in fps and task not in bc.setdefault("halted_tasks", []):
                bc["halted_tasks"].append(task)
                halted = True
            fps.append(fp)
            del fps[:-5]
        elif outcome in ("done", "blocked"):
            bc.get("failure_fingerprints", {}).pop(task, None)
            bc.get("worker_restarts", {}).pop(task, None)
            if task in bc.get("halted_tasks", []):
                bc["halted_tasks"].remove(task)

    still_active = outcome in ("partial", "failed")
    rc, msg = P.checkpoint(note=f"report {task} {outcome}", task=task if still_active else None, holder=holder,
                           next_action=f"{task}: {res['next_action']}" if still_active else None,
                           extra_events=events, mutate=mutate)
    if rc != P.E_OK:
        wi_path.write_text(before, encoding="utf-8")  # nothing moves when the state would be invalid
        return reject(P, msg, rc, task)
    if halted:
        P.append_event("retry_halted", "recorded", task_id=task, result="the same failure fingerprint twice; collect a different diagnosis (§2.2)")
    emit({"accepted": task, "outcome": outcome, "retry_halted": halted, "checkpoint": msg})
    return P.E_OK


def cmd_report(P, holder, result_path):
    try:
        res = json.loads(Path(result_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as ex:
        return reject(P, f"result unreadable: {ex}", P.E_VALIDATION)
    with state_lock(P):
        return apply_report(P, holder, res)


# ----------------------------------------------------------------------------- resume / run
def reconcile(P, holder):
    """The first steps of §23 resume: the saved state re-derived and validated under the lease
    (a checkpoint, which also repairs a state left behind by an interruption between a records
    write and the state write), then the pending operations checked against the tree."""
    ps = load_state(P)
    if ps["cancellation_state"] != "none":
        return P.E_CANCELLED, {"cancelled": True, "clear_with": "cancel --clear --note <new authorisation>"}
    if ps.get("next_retry_at") and P.parse_time(ps["next_retry_at"]) > P.utc_now():
        return P.E_NO_WORK, {"waiting_retry_until": ps["next_retry_at"]}
    rc, msg = P.checkpoint(note="resume: reconciled", holder=holder)
    if rc != P.E_OK:
        return rc, {"refused": msg}
    notes = []
    for op in list(load_state(P)["pending_operations"]):
        if op.get("type") != "worker":
            return P.E_BLOCKED, {"pending_operation": op, "reason": "unknown operation type: check its effect by hand"}
        result = P.ROOT / op["result_path"]
        if result.exists():
            # the worker finished and its result was never reported: report it now
            try:
                res = json.loads(result.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                res = None
            rc = apply_report(P, holder, res) if isinstance(res, dict) else reject(P, "pending worker result unreadable", P.E_VALIDATION, op["task_id"])
            notes.append(f"{op['id']}: result found and reported (exit {rc})")
        else:
            notes.append(f"{op['id']}: no result; {op['task_id']} stays active and is handed out again")
        drop_operation(P, holder, op, "op_reconciled", notes[-1])
    return P.E_OK, {"reconciled": notes}


def drop_operation(P, holder, op, etype, result):
    def mutate(st):
        st["pending_operations"] = [o for o in st["pending_operations"] if o.get("id") != op["id"]]
    P.checkpoint(note=result, holder=holder, extra_events=[(etype, result)], mutate=mutate)


def worker_budget(auto):
    wp = auto["operation_timeouts"].get("work_package", {})
    return (int(wp.get("minutes", 90)) * 60, int(auto["budgets"].get("max_packages_per_run", DEFAULT_MAX_PACKAGES)),
            int(auto["restart_policy"].get("max_restarts_per_round", DEFAULT_WORKER_RESTARTS)))


def start_worker_op(P, holder, pack):
    """Record the intent before the worker runs (§2.4): a pending operation names the result
    file, so an interruption after the worker's effect is found and reported by resume."""
    task = pack["task"]["id"]
    g = load_state(P)["checkpoint_generation"] + 1
    op = {"id": f"op-worker-{task}-g{g}", "type": "worker", "task_id": task, "started_at": P.iso(P.utc_now()),
          "context_digest": hashlib.sha256(json.dumps(pack, sort_keys=True).encode()).hexdigest(),
          "result_path": f"build/orchestrator/{task}-g{g}.result.json"}
    rc, msg = P.checkpoint(note=f"worker started on {task}", holder=holder, extra_events=[("worker_started", op["id"])],
                           mutate=lambda st: st["pending_operations"].append(op))
    return rc, (op if rc == P.E_OK else {"refused": msg})


def invoke_worker(P, worker, pack, op, timeout_s):
    """Run `<worker_command> <context.json> <result.json>` (argv, no shell) outside the state
    lock, so that a cancel can be recorded meanwhile. Returns a status string."""
    d = P.ROOT / "build" / "orchestrator"
    d.mkdir(parents=True, exist_ok=True)
    ctx = d / f"{op['id']}.context.json"
    ctx.write_text(json.dumps(pack, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    try:
        r = subprocess.run(shlex.split(worker) + [str(ctx), str(P.ROOT / op["result_path"])], cwd=P.ROOT,
                           timeout=timeout_s, capture_output=True, text=True)
        return f"exit {r.returncode}"
    except subprocess.TimeoutExpired:
        return "timeout"
    except OSError as ex:
        return f"unavailable: {ex}"


def finish_worker_op(P, holder, op, status, timeout_s, max_restarts):
    """Report the worker's result, or account for its failure; the operation is then closed."""
    task = op["task_id"]
    res_path = P.ROOT / op["result_path"]
    if status == "timeout":
        drop_operation(P, holder, op, "worker_timeout", f"{task}: worker exceeded {timeout_s}s; the package stays active")
        return P.E_BUDGET, {"timeout": task, "limit_s": timeout_s}
    if status.startswith("unavailable"):
        drop_operation(P, holder, op, "worker_unavailable", f"{task}: {status}")
        return P.E_NO_WORKER, {"worker_unavailable": status}
    rc = None
    if res_path.exists():
        try:
            res = json.loads(res_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            res = None
        rc = apply_report(P, holder, res) if isinstance(res, dict) else reject(P, "worker result unreadable", P.E_VALIDATION, task)
        if rc != P.E_VALIDATION:
            drop_operation(P, holder, op, "worker_finished", f"{task}: {status}, report exit {rc}")
            return rc, {"worker_finished": task, "report_exit": rc}
    # no result, or one whose claims were refused: a failed attempt, within the restart limit
    why = "no result" if rc is None else "result refused"
    restarts = {}

    def count(st):
        n = st["budget_counters"].setdefault("worker_restarts", {})
        n[task] = n.get(task, 0) + 1
        restarts["n"] = n[task]
        if n[task] >= max_restarts and task not in st["budget_counters"].setdefault("halted_tasks", []):
            st["budget_counters"]["halted_tasks"].append(task)
        st["pending_operations"] = [o for o in st["pending_operations"] if o.get("id") != op["id"]]
    P.checkpoint(note=f"worker on {task}: {status}, {why}", holder=holder,
                 extra_events=[("worker_failed", f"{task}: {status}, {why}")], mutate=count)
    if restarts["n"] >= max_restarts:
        return P.E_BLOCKED, {"worker_failed": task, "why": why, "restarts": restarts["n"], "halted": True}
    return P.E_OK, {"worker_failed": task, "why": why, "restarts": restarts["n"]}


def resume_once(P, holder):
    auto = P.load_json(P.DOCS / "automation.json")
    worker = auto.get("worker_command")
    with state_lock(P):
        rc, info = reconcile(P, holder)
        if rc != P.E_OK:
            return rc, info
        rc, pack = hand_out(P, holder, automatic=bool(worker))
        if rc != P.E_OK:
            return rc, pack
        if not worker:
            return P.E_NO_WORKER, {"handed_out": pack["task"]["id"], "worker": "interactive", "awaiting": "report", "context": pack}
        timeout_s, _, max_restarts = worker_budget(auto)
        rc, op = start_worker_op(P, holder, pack)
        if rc != P.E_OK:
            return rc, op
    status = invoke_worker(P, worker, pack, op, timeout_s)
    with state_lock(P):
        return finish_worker_op(P, holder, op, status, timeout_s, max_restarts)


def cmd_run(P, holder):
    auto = P.load_json(P.DOCS / "automation.json")
    _, max_packages, _ = worker_budget(auto)
    worked = 0
    while True:
        rc, info = resume_once(P, holder)
        if rc != P.E_OK or not auto.get("worker_command"):
            emit(info)
            return rc
        worked += 1
        if worked >= max_packages:
            emit({"budget": f"max_packages_per_run={max_packages} reached", "last": info})
            return P.E_BUDGET


def cmd_cancel(P, holder, clear, note):
    if clear and not note:
        emit({"refused": "cancel --clear needs --note <the new authorisation>"})
        return P.E_VALIDATION

    def mutate(st):
        if clear:
            st["cancellation_state"], st["runner_status"] = "none", "idle"
        else:
            st["cancellation_state"], st["runner_status"], st["next_retry_at"] = "cancelled", "cancelled", None

    with state_lock(P):
        rc, msg = P.checkpoint(note=note or "cancelled by the user", holder=holder, mutate=mutate,
                               extra_events=[("cancel_cleared" if clear else "cancelled", note or "user stop")])
    emit({"cancelled": not clear, "checkpoint": msg})
    return rc


def main(P, a):
    holder = a.holder or os.environ.get("NAWAH_HOLDER")
    if not holder:
        emit({"refused": "a lease holder is needed: --holder <id> or NAWAH_HOLDER"})
        return P.E_NO_WORKER
    try:
        if a.cmd == "next":
            with state_lock(P):
                rc, out = hand_out(P, holder)
            emit(out)
            return rc
        if a.cmd == "report":
            return cmd_report(P, holder, a.result)
        if a.cmd == "resume":
            rc, out = resume_once(P, holder)
            emit(out)
            return rc
        if a.cmd == "run":
            return cmd_run(P, holder)
        if a.cmd == "cancel":
            return cmd_cancel(P, holder, a.clear, a.note)
    except P.LeaseHeld as ex:
        emit({"blocked": str(ex)})
        return P.E_BLOCKED
    return P.E_INTERNAL
