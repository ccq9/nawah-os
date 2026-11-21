#!/usr/bin/env python3
"""nawah-os project interface (OS-EXEC-AR 3.2, section 20).

Exit codes (section 20): 0 ok | 10 no ready work package | 20 recorded blocker |
30 budget exhausted | 40 cancelled | 50 record validation failure | 60 internal error |
70 no worker configured.
"""
import argparse, shutil, hashlib, json, os, subprocess, sys, time, datetime, re
from pathlib import Path

ROOT = Path(os.environ.get("NAWAH_ROOT", Path(__file__).resolve().parents[1])).resolve()
DOCS = ROOT / "docs"
SCHEMAS = DOCS / "schemas"
EVIDENCE = ROOT / "evidence"
# Scratch mode (mutation runs, experiments): run directories go to this directory instead of
# evidence/ and verdicts are never attached to the records.
SCRATCH = Path(os.environ["NAWAH_SCRATCH_EVIDENCE"]).resolve() if os.environ.get("NAWAH_SCRATCH_EVIDENCE") else None
SCHEMA_VERSION = "1.0.0"
# evidence-run 1.1.0 (ADR-0026): a closed worker enumeration, the runner's `ci` identity, dirty_paths.
RUN_SCHEMA_VERSION = "1.1.0"
WORKERS = ("verification-runner", "interactive-agent", "test")
DIRTY_EXCLUDED = ("evidence/", "build/", "state/")
RUN_ID_RE = re.compile(r"^(mutants-)?[0-9]+$")
ACCEPTED_WORKFLOWS = ("verify", "mutants")
RECORD_FILES = ["requirements", "stages", "work-items", "tests", "risks", "sources", "hardware", "decisions-pending"]
SINGLE_FILES = ["project-state", "automation"]
LEGAL_TRANSITIONS = {("planned", "active"), ("active", "blocked"), ("active", "done"), ("blocked", "planned"), ("done", "planned"), ("active", "planned"),
                     ("planned", "superseded"), ("blocked", "superseded")}
EVIDENCE_REQUIRED = ["run.json", "command.txt", "stdout.log", "stderr.log", "exit_code", "digests.json", "verdict.json"]

E_OK, E_NO_WORK, E_BLOCKED, E_BUDGET, E_CANCELLED, E_VALIDATION, E_INTERNAL, E_NO_WORKER = 0, 10, 20, 30, 40, 50, 60, 70


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def load_json(p: Path):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def write_json(p: Path, data):
    """Write a record atomically: a crash or a concurrent reader never sees half a file
    (a unique temporary in the same directory, its data flushed, then renamed over `p`)."""
    text = json.dumps(data, ensure_ascii=False, indent=1) + "\n"
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, p)  # atomic on POSIX
    finally:
        tmp.unlink(missing_ok=True)


def safe_rel(rel: str) -> Path:
    """Resolve a repo-relative path; reject escapes and symlinks leaving ROOT."""
    if rel.startswith("/") or ".." in Path(rel).parts:
        raise ValueError(f"path escapes root: {rel}")
    p = (ROOT / rel).resolve()
    if ROOT != p and ROOT not in p.parents:
        raise ValueError(f"path escapes root: {rel}")
    return p


def git(*args) -> str:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return r.stdout.strip()


def dirty_paths(limit=50):
    """Tracked files changed and untracked files outside evidence/, build/ and state/, sorted, at
    most `limit` of them (ADR-0026, REL-3 B): the evidence a run writes, the build it produces and
    the lab's state must not make the run dirty; a changed source file must. Files .gitignore
    hides (target/, build/) are not seen at all. Read with -z, so a path with a space or a
    non-ASCII letter comes as it is, never quoted or octal-escaped."""
    r = subprocess.run(["git", "status", "--porcelain", "-z", "--untracked-files=all"], cwd=ROOT, capture_output=True, text=True)
    fields = r.stdout.split("\0")
    out, i = [], 0
    while i < len(fields):
        entry = fields[i]; i += 1
        if len(entry) < 4:
            continue
        xy, path = entry[:2], entry[3:]  # porcelain v1: two status letters, a space, the path (the first letter may be a space)
        if "R" in xy or "C" in xy:
            i += 1  # a rename or copy: the original path follows as a field of its own
        if path.startswith(DIRTY_EXCLUDED):
            continue
        out.append(path)
    return sorted(out)[:limit]


def source_identity():
    rev = git("rev-parse", "HEAD") or "unknown"
    return rev, bool(dirty_paths(limit=1))


# The tree identity of the run in progress: (revision, dirty paths), taken once when a build, a
# boot or a suite begins (ADR-0026 rule 2). attach_evidence rewrites docs/tests.json,
# requirements.json and work-items.json while a suite runs, so a tree clean at the start would
# read dirty from the second case on if every run.json measured afresh.
RUN_TREE = None


def begin_run():
    global RUN_TREE
    if RUN_TREE is None:
        RUN_TREE = (git("rev-parse", "HEAD") or "unknown", dirty_paths())
    return RUN_TREE


def runner_identity():
    """The worker and the run's CI identity from the environment (ADR-0026): on GitHub Actions the
    verification runner with its run id, attempt, workflow, event, sha, head sha (the pull
    request's head when the event carries one) and ref; anywhere else the interactive agent and
    no `ci` object."""
    e = os.environ
    if e.get("GITHUB_ACTIONS") != "true":
        return "interactive-agent", None
    head = e.get("GITHUB_SHA", "")
    ev_path = e.get("GITHUB_EVENT_PATH")
    if ev_path and Path(ev_path).exists():
        try:
            head = json.loads(Path(ev_path).read_text(encoding="utf-8")).get("pull_request", {}).get("head", {}).get("sha") or head
        except (OSError, ValueError, AttributeError):
            pass
    try:
        attempt = int(e.get("GITHUB_RUN_ATTEMPT", "1"))
    except ValueError:
        attempt = 1
    return "verification-runner", {"run_id": e.get("GITHUB_RUN_ID", ""), "run_attempt": attempt, "workflow": e.get("GITHUB_WORKFLOW", ""),
                                   "event": e.get("GITHUB_EVENT_NAME", ""), "sha": e.get("GITHUB_SHA", ""), "head_sha": head, "ref": e.get("GITHUB_REF", "")}


# ----------------------------------------------------------------------------- validation
# The only tests whose stale verdict may stay a warning under --strict: the four mutation gates
# verify does not run (mutants.yml, hours of runner time). The M6 gate is not among them: verify
# runs it in every run (the owner's DEC-029, WP-96; in the shard jobs and job g since WP-152 and
# WP-153). stale_policy "warn" on any other
# test is an error, so a strict rule is never relaxed by a records edit alone (the edit of
# 2026-11-14 on TST-M6-MUTANTS; PLAN-ANSWER.md §"بوابة التقادم عند الإغلاق").
STALE_WARN_TESTS = ("TST-M2-MUTANTS", "TST-M3-MUTANTS", "TST-M4-MUTANTS", "TST-M5-MUTANTS")


class Problems:
    def __init__(self, strict=False):
        # Tests whose stale verdicts stay a warning even under --strict (stale_policy: warn in
        # docs/tests.json): long gate-time runs such as mutation testing, re-run at gates.
        self.warn_only_tests = set()
        self.errors, self.warnings, self.stale = [], [], []
        self.legacy_runs = set()  # evidence-run 1.0.0 without import.json: one aggregated warning (ADR-0026)
        self.strict = strict

    def err(self, where, msg):
        self.errors.append(f"{where}: {msg}")

    def warn(self, where, msg):
        self.warnings.append(f"{where}: {msg}")


def detect_cycles(ids, edges, where, pb: Problems):
    state = {}

    def visit(n, stack):
        state[n] = 1
        for m in edges.get(n, []):
            if m not in ids:
                continue
            if state.get(m) == 1:
                pb.err(where, f"dependency cycle: {' -> '.join(stack + [n, m])}")
                return
            if state.get(m) is None:
                visit(m, stack + [n])
        state[n] = 2

    for n in ids:
        if state.get(n) is None:
            visit(n, [])


def validate_schema(name, data, pb: Problems, where):
    try:
        import jsonschema
    except ImportError:
        pb.err(where, "jsonschema package not installed (pip install jsonschema)")
        return
    sp = SCHEMAS / f"{name}.schema.json"
    if not sp.exists():
        pb.err(where, f"schema missing: {sp.relative_to(ROOT)}")
        return
    v = jsonschema.Draft202012Validator(load_json(sp))
    for e in sorted(v.iter_errors(data), key=lambda e: list(e.path)):
        loc = "/".join(str(x) for x in e.path) or "<root>"
        pb.err(where, f"schema: {loc}: {e.message[:160]}")


def check_evidence_dir(rel, pb: Problems, where, expect_test_id=None, current_digests=None):
    try:
        p = safe_rel(rel)
    except ValueError as ex:
        pb.err(where, str(ex)); return None
    if not p.exists():
        pb.err(where, f"evidence missing: {rel}"); return None
    if p.is_file():
        return None  # plain file evidence (log, image) — existence is enough
    missing = [f for f in EVIDENCE_REQUIRED if not (p / f).exists()]
    if missing:
        pb.err(where, f"evidence {rel} incomplete, missing {missing}"); return None
    run = load_json(p / "run.json"); verdict = load_json(p / "verdict.json")
    before = len(pb.errors)
    validate_schema("evidence-run", run, pb, f"{rel}/run.json")
    validate_schema("evidence-verdict", verdict, pb, f"{rel}/verdict.json")
    if len(pb.errors) > before:  # this directory's own schema errors; earlier ones elsewhere must not skip its checks
        return verdict
    if expect_test_id and verdict["test_id"] != expect_test_id:
        pb.err(where, f"evidence {rel} is for test {verdict['test_id']}, not {expect_test_id}")
    # recorded exit code must match run.json
    ec = (p / "exit_code").read_text().strip()
    if str(run["exit_code"]) != ec:
        pb.err(where, f"evidence {rel}: exit_code file ({ec}) != run.json ({run['exit_code']})")
    # provenance (ADR-0026): a 1.1.0 PASS is adopted only through the checked import, whose
    # import.json is a complete receipt naming the same CI run as the run's own identity. The rule
    # binds the evidence, not the worker's own word: a run.json saying interactive-agent or test
    # is a self-claim (REL-1 B, rejected), so it earns no exemption (audit of 77d48c91).
    imp_p = p / "import.json"
    ci = run.get("ci") or {}
    if imp_p.exists():
        # A present receipt is checked for every worker and verdict: its own schema, then its
        # identity against the run's (id, attempt, head sha, workflow). A malformed file is a
        # named error, not a crash of the validator.
        readable = True
        try:
            receipt = load_json(imp_p)  # may be null or any JSON value: the schema decides, never this code
        except ValueError as ex:
            readable = False
            pb.err(where, f"evidence {rel}: import.json is not valid JSON ({str(ex)[:80]})")
        if readable:
            before_imp = len(pb.errors)
            validate_schema("evidence-import", receipt, pb, f"{rel}/import.json")
            if len(pb.errors) == before_imp:
                for key, ci_key in (("ci_run_id", "run_id"), ("run_attempt", "run_attempt"), ("head_sha", "head_sha"), ("workflow", "workflow")):
                    have, want = receipt.get(key), ci.get(ci_key)
                    if not want or str(have) != str(want):
                        pb.err(where, f"evidence {rel}: import.json {key} {have!r} does not match run.json ci.{ci_key} {want!r}")
    elif run.get("schema_version") == "1.0.0":
        pb.legacy_runs.add(rel)
    elif verdict["verdict"] == "PASS":
        # Evidence native to the CI run that is validating (verify's strict step runs on the
        # runner's own tree before any import exists) is produced, not adopted: no import.json
        # yet. Native means the run's own identity equals this run's: id, attempt and commit all
        # match and none is empty (an empty string is no identity). The exemption covers only a
        # missing receipt (audit of 68d72a5e, 2026-11-09).
        env = os.environ

        def same(a, b):
            return bool(a) and bool(b) and str(a) == str(b)

        native = (env.get("GITHUB_ACTIONS") == "true" and same(ci.get("run_id"), env.get("GITHUB_RUN_ID"))
                  and same(ci.get("run_attempt"), env.get("GITHUB_RUN_ATTEMPT")) and same(ci.get("sha"), env.get("GITHUB_SHA")))
        if not native:
            msg = f"evidence {rel}: a {run.get('schema_version')} PASS by {run.get('worker')} without import.json (not adopted through the checked import)"
            if pb.strict:
                pb.err(where, msg)
            else:
                pb.warn(where, msg)
    # staleness: recompute digests of declared inputs
    stale = []
    for inp, dig in verdict["inputs"].items():
        try:
            ip = safe_rel(inp)
        except ValueError as ex:
            pb.err(where, str(ex)); continue
        if not ip.exists():
            stale.append(f"{inp} (missing)"); continue
        if sha256_file(ip) != dig:
            stale.append(inp)
    combined = sha256_text("\n".join(f"{k}={v}" for k, v in sorted(verdict["inputs"].items())))
    if combined != verdict["inputs_digest"]:
        pb.err(where, f"evidence {rel}: inputs_digest does not match inputs map")
    if stale and verdict["verdict"] not in ("NEEDS_REEVALUATION",):
        msg = f"evidence {rel}: inputs changed since verdict ({', '.join(stale)}); needs re-evaluation (re-run or impact analysis)"
        if pb.strict and verdict.get("test_id") not in pb.warn_only_tests:
            pb.err(where, msg)
        else:
            pb.warn(where, msg)
            pb.stale.append(rel)
    return verdict


PLANNED_WORD = re.compile(r"\bplanned\b", re.IGNORECASE)
CONTRACT_PROMISE = re.compile(r"\b([a-z0-9-]+\.md)\s+v([0-9]+(?:\.[0-9]+)?)\b")


def contract_version(name):
    """The version in a contract's first line (`… الإصدار 1.7 …`), or None when the file is
    absent or its header carries no version."""
    p = DOCS / "contracts" / name
    if not p.is_file():
        return None
    m = re.search(r"الإصدار\s*([0-9]+(?:\.[0-9]+)?)", p.read_text(encoding="utf-8").split("\n", 1)[0])
    return m.group(1) if m else None


def version_tuple(v):
    return tuple(int(x) for x in (v if "." in v else v + ".0").split("."))


def validate_records(stage_scope=None, verbose=True, strict=False) -> int:
    """Structural and semantic validation. Stale verdicts (inputs changed since the run) are
    warnings — the verdict is suspended, 'needs re-evaluation' — unless strict=True (gates, CI
    after fresh evidence), where they are errors."""
    pb = Problems(strict=strict)
    recs = {}
    for name in RECORD_FILES:
        p = DOCS / f"{name}.json"
        if not p.exists():
            continue
        try:
            data = load_json(p)
        except json.JSONDecodeError as ex:
            pb.err(name, f"invalid JSON: {ex}"); continue
        validate_schema(name, data, pb, name)
        recs[name] = data.get("records", []) if isinstance(data, dict) else []
    for name in SINGLE_FILES:
        p = DOCS / f"{name}.json"
        if p.exists():
            try:
                validate_schema(name, load_json(p), pb, name)
            except json.JSONDecodeError as ex:
                pb.err(name, f"invalid JSON: {ex}")
    if pb.errors:
        return report(pb, verbose)

    ids = {n: [r["id"] for r in recs.get(n, [])] for n in RECORD_FILES}
    for n, lst in ids.items():
        dups = sorted({i for i in lst if lst.count(i) > 1})
        if dups:
            pb.err(n, f"duplicate ids: {dups}")
    idset = {n: set(v) for n, v in ids.items()}
    by_id = {n: {r["id"]: r for r in recs.get(n, [])} for n in RECORD_FILES}
    pb.warn_only_tests = set()
    for t in recs.get("tests", []):
        if t.get("stale_policy") == "warn":
            if t.get("id") in STALE_WARN_TESTS:
                pb.warn_only_tests.add(t["id"])
            else:
                pb.err(f"tests/{t.get('id')}", "stale_policy warn is accepted only on " + ", ".join(STALE_WARN_TESTS)
                       + " (the gates verify does not run); a stale verdict of this test is a strict error")

    def ref(where, kind, value):
        if value not in idset.get(kind, set()):
            pb.err(where, f"missing reference to {kind}: {value}")

    for r in recs.get("requirements", []):
        w = f"requirements/{r['id']}"
        ref(w, "stages", r["stage"])
        for d in r["dependencies"]: ref(w, "requirements", d)
        for t in r["test_ids"]: ref(w, "tests", t)
        deferred = r.get("detail_status") == "deferred"
        for c in r["contract_refs"]:
            try:
                if not safe_rel(c).exists() and not deferred:
                    pb.err(w, f"contract file missing: {c}")
            except ValueError as ex:
                pb.err(w, str(ex))
        for e in r["evidence_refs"]:
            check_evidence_dir(e, pb, w)
            # A requirement's evidence is its tests' evidence. A run its test no longer cites was
            # left behind when the test was reset or re-run (CI run 39196967624 failed --strict:
            # REQ-M5-010 still cited three runs its tests had dropped).
            try:
                tid = load_json(safe_rel(e) / "verdict.json").get("test_id")
            except (ValueError, OSError, json.JSONDecodeError):
                tid = None  # check_evidence_dir has reported it
            t = by_id["tests"].get(tid)
            if t is not None and e not in t["evidence_refs"]:
                pb.err(w, f"cites evidence {e} for {tid}, which that test's record no longer cites "
                          f"({', '.join(t['evidence_refs']) or 'none'}); refresh it with the test's")
        if r["implementation_status"] == "verified_in_scope" and not r["evidence_refs"]:
            pb.err(w, "verified_in_scope without evidence_refs")
    detect_cycles(idset["requirements"], {r["id"]: r["dependencies"] for r in recs.get("requirements", [])}, "requirements", pb)

    for s in recs.get("stages", []):
        for d in s["depends_on"]: ref(f"stages/{s['id']}", "stages", d)
        if s["gate_status"] == "passed" and not s.get("gate_evidence_refs"):
            pb.err(f"stages/{s['id']}", "gate passed without gate_evidence_refs")
    detect_cycles(idset["stages"], {s["id"]: s["depends_on"] for s in recs.get("stages", [])}, "stages", pb)

    for t in recs.get("tests", []):
        w = f"tests/{t['id']}"
        for q in t["requirement_ids"]: ref(w, "requirements", q)
        for e in t["evidence_refs"]:
            v = check_evidence_dir(e, pb, w, expect_test_id=t["id"])
            if v and v["verdict"] != t["verdict"]:
                pb.err(w, f"registry verdict {t['verdict']} != evidence verdict {v['verdict']} ({e})")
            # A PASS stands for the oracle its run checked (write_verdict stores it): an oracle
            # changed since, at its source and synced, waits for a new run (WP-92; no stale_policy
            # exemption). Strict only: on a branch the code commit precedes its evidence.
            if pb.strict and v and t["verdict"] == "PASS" and v.get("oracle") != t["oracle"]:
                pb.err(w, f"oracle differs from the one its evidence ran with ({e}); re-run the test")
        if t["verdict"] == "PASS" and not t["evidence_refs"]:
            pb.err(w, "PASS without evidence_refs")
        # A passing test's oracle states what the test checks, not what was planned: three
        # oracles kept their plan text after PASS and claimed steps the tests never ran
        # (WINDOW-A11Y, ARABIC-UI, PROCESS-KILL; audit 2026-10-19).
        if t["verdict"] == "PASS" and PLANNED_WORD.search(t["oracle"]):
            pb.err(w, "PASS while the oracle still describes the plan ('planned'); state what the test checks")
    # One source per oracle (WP-92): the record's copy must equal the text the runner writes.
    for tid, where in oracle_conflicts().items():
        pb.err(f"tests/{tid}", f"two sources with different oracle texts ({', '.join(where)}); make them one")
    for t, _ in oracle_differences(recs.get("tests", [])):
        pb.err(f"tests/{t['id']}", "oracle differs from its source (HOST_SUITES or target.json); "
               "change the source, then run `project.py sync-oracles` (a dated note goes to oracle_notes)")

    for wi in recs.get("work-items", []):
        w = f"work-items/{wi['id']}"
        ref(w, "stages", wi["stage"])
        for q in wi["requirement_ids"]: ref(w, "requirements", q)
        for d in wi["depends_on"]: ref(w, "work-items", d)
        for t in wi["test_ids"]: ref(w, "tests", t)
        hist = wi["status_history"]
        if hist[0] != "planned":
            pb.err(w, f"status_history must start with planned, got {hist[0]}")
        for a, b in zip(hist, hist[1:]):
            if (a, b) not in LEGAL_TRANSITIONS:
                pb.err(w, f"illegal status transition {a} -> {b}")
        if hist[-1] != wi["status"]:
            pb.err(w, f"status {wi['status']} != last of status_history {hist[-1]}")
        # A contract version a work item promises must exist (audit 2026-10-19: WP-30 closed
        # promising files.md v1.1 and WP-40 planned session.md v1.1; both contracts stayed v1).
        # Done: an error. Active: a warning — the work is in progress.
        if wi["status"] in ("done", "active"):
            for action in wi["actions"]:
                for name, ver in CONTRACT_PROMISE.findall(action):
                    have = contract_version(name)
                    if have is not None and version_tuple(have) < version_tuple(ver):
                        (pb.err if wi["status"] == "done" else pb.warn)(
                            w, f"promises {name} v{ver} but the contract is v{have}")
        if wi["status"] == "done":
            if not wi["evidence_refs"]:
                pb.err(w, "done without evidence_refs")
            for t in wi["test_ids"]:
                tv = by_id["tests"].get(t, {}).get("verdict")
                if tv not in ("PASS", "N/A"):
                    pb.err(w, f"done but test {t} verdict is {tv}")
            for e in wi["evidence_refs"]:
                check_evidence_dir(e, pb, w)
        if wi["status"] == "blocked" and not wi["blocker"]:
            pb.err(w, "blocked without blocker text")
        # WP-165: a blocker that names a decision waits for it; once the decision is answered the
        # blocker is a line of history, not a reason (WP-69 named DEC-027 for two days after).
        for dec in re.findall(r"DEC-\d+", wi["blocker"] or ""):
            if by_id["decisions-pending"].get(dec, {}).get("status") != "open":
                pb.err(w, f"blocker names {dec}, which is not an open decision")
        if wi["status"] == "superseded":
            sb = wi.get("superseded_by")
            if not sb:
                pb.err(w, "superseded without superseded_by")
            elif sb not in idset["work-items"] or sb == wi["id"]:
                pb.err(w, f"superseded_by {sb} is not another work item")
        elif wi.get("superseded_by"):
            pb.err(w, "superseded_by set on a work item that is not superseded")
        for d in wi["depends_on"]:
            if by_id["work-items"].get(d, {}).get("status") == "superseded":
                pb.err(w, f"depends on superseded {d}; depend on {by_id['work-items'][d].get('superseded_by')} instead")
        # §2.1: active only when every dependency is done, and done likewise (arena review ع2:
        # a done item with an active dependency passed).
        if wi["status"] in ("active", "done"):
            for d in wi["depends_on"]:
                if by_id["work-items"].get(d, {}).get("status") != "done":
                    pb.err(w, f"{wi['status']} while dependency {d} is not done")
    detect_cycles(idset["work-items"], {w["id"]: w["depends_on"] for w in recs.get("work-items", [])}, "work-items", pb)

    for dp in recs.get("decisions-pending", []):
        for t in dp["blocked_task_ids"]: ref(f"decisions-pending/{dp['id']}", "work-items", t)

    # project-state consistency
    ps = DOCS / "project-state.json"
    if ps.exists():
        st = load_json(ps)
        prompt = DOCS / "prompt" / f"OS-EXEC-AR-v{st['prompt_version']}.md"
        if not prompt.exists():
            pb.err("project-state", f"prompt file missing for version {st['prompt_version']}")
        elif st["prompt_digest"] not in ("unknown",) and sha256_file(prompt) != st["prompt_digest"]:
            pb.err("project-state", "prompt_digest does not match docs/prompt file")
        ref("project-state", "stages", st["current_stage"])
        if st["current_task"]: ref("project-state", "work-items", st["current_task"])
        for q in st["completed_requirement_ids"]: ref("project-state", "requirements", q)
        for d in st["pending_decision_ids"]: ref("project-state", "decisions-pending", d)
        # WP-165: what the file says of the next step and of the waiting decisions is what the
        # records and the owner's order give. A checkpoint writes both, and is refused on
        # errors, so between checkpoints a difference is a warning; under --strict (what a
        # pushed tree must satisfy) it is an error.
        order = read_plan_order()
        if order is None:
            pb.err("project-state", f"the owner's order is not readable: section 7, item 5 of {ORDER_POLICY.relative_to(ROOT)}")
        for wid in order or []: ref("project-state (the owner's order)", "work-items", wid)
        pos = derive_position(recs.get("work-items", []), recs.get("requirements", []), order)
        late = []
        if (st["current_task"], st["next_action"]) != (pos["current_task"], pos["next_action"]):
            late.append(f"current_task {st['current_task']} ({st['next_action']}) but the records and the owner's order give "
                        f"{pos['current_task']} ({pos['next_action']})")
        waiting = open_decisions(recs.get("decisions-pending", []))
        if st["pending_decision_ids"] != waiting:
            late.append(f"pending_decision_ids {st['pending_decision_ids']} but the open decisions are {waiting}")
        for msg in late:
            (pb.err if strict else pb.warn)("project-state", msg + " (checkpoint pending)")
        rev, dirty = source_identity()
        if st["source_revision"] != rev:
            pb.warn("project-state", f"source_revision {st['source_revision'][:8]} != HEAD {rev[:8]} (checkpoint pending)")
    return report(pb, verbose)


def report(pb: Problems, verbose) -> int:
    if pb.legacy_runs:
        pb.warnings.append(f"evidence: {len(pb.legacy_runs)} run(s) at evidence-run 1.0.0 without import.json (imported before ADR-0026; provenance not verifiable)")
        pb.legacy_runs = set()
    if verbose:
        for w in pb.warnings: print("WARN", w)
        for e in pb.errors: print("ERROR", e)
        print(f"validate-records: {len(pb.errors)} error(s), {len(pb.warnings)} warning(s), {len(pb.stale)} stale verdict(s){' [strict]' if pb.strict else ''}")
    return E_VALIDATION if pb.errors else E_OK


# ----------------------------------------------------------------------------- status
def cmd_status(as_json: bool) -> int:
    rev, dirty = source_identity()
    out = {"source_revision": rev, "dirty_state": dirty, "stages": [], "work_items": {}, "blockers": [], "next_task": None,
           "decisions_pending": [], "validation": None}
    for n in ("stages", "work-items", "decisions-pending"):
        p = DOCS / f"{n}.json"
        if not p.exists():
            continue
        recs = load_json(p)["records"]
        if n == "stages":
            out["stages"] = [{"id": s["id"], "gate_status": s["gate_status"]} for s in recs]
        elif n == "work-items":
            for w in recs:
                out["work_items"].setdefault(w["status"], []).append(w["id"])
                if w["status"] == "blocked":
                    out["blockers"].append({"task": w["id"], "blocker": w["blocker"]})
            out["next_task"] = derive_position(recs, [], read_plan_order())["current_task"]
        else:
            out["decisions_pending"] = open_decisions(recs)
    ps = DOCS / "project-state.json"
    if ps.exists():
        st = load_json(ps)
        out.update({"current_stage": st["current_stage"], "runner_status": st["runner_status"],
                    "checkpoint_generation": st["checkpoint_generation"], "budget_counters": st["budget_counters"]})
    out["validation"] = "ok" if validate_records(verbose=False) == 0 else "errors"
    print(json.dumps(out, ensure_ascii=False, indent=1) if as_json else out)
    return E_OK


# ----------------------------------------------------------------------------- build / boot / test
def load_target(name):
    p = ROOT / "platform" / name / "target.json"
    if not p.exists():
        raise SystemExit(f"unknown target {name}: {p.relative_to(ROOT)} missing")
    return load_json(p)


# A run that never got to exercise the product (a tool missing from the host, a toolchain that
# could not be downloaded, QEMU killed) is ERROR, never FAIL: a broken environment is not a
# product defect (§2.2, §19). 127 is the shell's "command not found".
E_NOT_FOUND = 127
# Anchored at the start of a line: a product test's traceback quotes source lines indented, so
# a test that merely mentions these words never turns its own failure into ERROR.
ENV_FAILURE = re.compile(r"^(?:NOT_FOUND: |error: (?:could not|failed to) download|"
                         r"error: toolchain '[^']*' is not installed)", re.M)


def env_failed(rc, text):
    return rc == E_NOT_FOUND or bool(ENV_FAILURE.search(text))


def run_logged(cmd, cwd, log_out, log_err, timeout):
    with open(log_out, "ab") as o, open(log_err, "ab") as e:
        o.write(f"$ {' '.join(cmd)}\n".encode()); o.flush()
        try:
            r = subprocess.run(cmd, cwd=cwd, stdout=o, stderr=e, timeout=timeout)
            return r.returncode
        except subprocess.TimeoutExpired:
            e.write(b"TIMEOUT\n"); return 124
        except OSError as ex:
            e.write(f"NOT_FOUND: {cmd[0]}: {ex}\n".encode()); return E_NOT_FOUND


class HostServices:
    """Host-side peers a case needs while the guest runs (WP-28/WP-29): UDP and TCP echo
    servers bound to the loopback, reached from the guest through SLIRP's host address
    10.0.2.2 (SLIRP connects to 127.0.0.1:<port>; a port with no listener is refused, which
    the guest sees as RST)."""

    def __init__(self, specs):
        import socket
        import threading
        self.threads, self.socks, self.stop = [], [], threading.Event()
        for spec in specs or []:
            if spec["type"] == "udp_echo":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", int(spec["port"])))
                sock.settimeout(0.2)
                self.socks.append(sock)
                t = threading.Thread(target=self._echo, args=(sock,), daemon=True)
                t.start(); self.threads.append(t)
            elif spec["type"] == "tcp_echo":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", int(spec["port"])))
                sock.listen(4)
                sock.settimeout(0.2)
                self.socks.append(sock)
                t = threading.Thread(target=self._tcp_accept, args=(sock,), daemon=True)
                t.start(); self.threads.append(t)
            else:
                raise SystemExit(f"unknown host service type {spec['type']!r}")

    def _echo(self, sock):
        while not self.stop.is_set():
            try:
                data, peer = sock.recvfrom(2048)
            except OSError:
                continue
            try:
                sock.sendto(data, peer)
            except OSError:
                pass

    def _tcp_accept(self, sock):
        import threading
        while not self.stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            t = threading.Thread(target=self._tcp_echo, args=(conn,), daemon=True)
            t.start(); self.threads.append(t)

    def _tcp_echo(self, conn):
        """Echoes every byte until the peer closes its side, then closes (FIN to the guest)."""
        import socket
        conn.settimeout(0.2)
        with conn:
            while not self.stop.is_set():
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not data:
                    return
                try:
                    conn.sendall(data)
                except OSError:
                    return

    def close(self):
        self.stop.set()
        for t in self.threads:
            t.join(timeout=2)
        for s in self.socks:
            s.close()


class ConsoleSession:
    """The lab's side of the diagnostic console (WP-30, shell.md §4): a TCP client of QEMU's
    second serial port (COM2, `-serial tcp:127.0.0.1:<port>,server=on,wait=off`) that drives the
    `sh` service with a script of commands. It connects as soon as QEMU listens, waits for the
    first prompt (and, when `after` is given, for that serial marker, so the services are all
    ready before the first command), then sends each step's `send` line and collects the
    output up to the next prompt. Expectations are judged after the guest exits, with the
    complete serial log at hand (`expect_serial` compares the shell's values with the
    kernel's own lines); the transcript is evidence (console.log). `received` is the guest's
    bytes alone (the transcript without the lab's own `>>> ` lines): the case's forbidden
    markers are checked on it as on the serial log (WP-82)."""

    PROMPT = re.compile(rb"(?:^|\n)(?:[A-Za-z0-9_]+@)?nawah> $")

    def __init__(self, spec, transcript_path, serial_path, timeout):
        import threading
        self.spec, self.transcript_path, self.serial_path, self.timeout = spec, transcript_path, serial_path, timeout
        self.steps = []          # (step, output bytes, prompt bytes)
        self.errors = []
        self.transcript = bytearray()
        self.received = bytearray()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def _connect(self, deadline):
        import socket
        import time
        while time.monotonic() < deadline:
            try:
                sock = socket.create_connection(("127.0.0.1", int(self.spec["port"])), timeout=2)
                sock.settimeout(0.5)
                return sock
            except OSError:
                time.sleep(0.2)
        return None

    def _read_until_prompt(self, sock, deadline):
        """Bytes up to and including the next prompt; None at the deadline or when the peer
        closed."""
        import socket
        import time
        buf = bytearray()
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
            self.transcript += chunk
            self.received += chunk
            if self.PROMPT.search(bytes(buf)):
                return bytes(buf)
        return None

    def _run(self):
        import time
        deadline = time.monotonic() + self.timeout
        sock = self._connect(min(deadline, time.monotonic() + 30))
        if sock is None:
            self.errors.append("console: could not connect to the guest's second serial port")
            return
        try:
            first = self._read_until_prompt(sock, deadline)
            if first is None:
                self.errors.append("console: no prompt from the shell")
                return
            after = self.spec.get("after")
            if after:
                marker = after.encode()
                while time.monotonic() < deadline:
                    if self.serial_path.exists() and marker in self.serial_path.read_bytes():
                        break
                    time.sleep(0.2)
                else:
                    self.errors.append(f"console: serial marker {after!r} never appeared")
                    return
            for step in self.spec["script"]:
                line = step["send"].encode()
                self.transcript += b">>> " + line + b"\n"
                try:
                    sock.sendall(line + b"\n")
                except OSError as ex:
                    self.errors.append(f"console: send failed at {step['send']!r}: {ex}")
                    return
                if step.get("final"):
                    # The session ends here (`exit`): the shell prints its farewell and leaves.
                    time.sleep(0.5)
                    try:
                        tail = sock.recv(4096)
                    except OSError:
                        tail = b""
                    self.transcript += tail
                    self.received += tail
                    self.steps.append((step, tail, b""))
                    return
                out = self._read_until_prompt(sock, min(deadline, time.monotonic() + float(step.get("timeout_s", 60))))
                if out is None:
                    self.errors.append(f"console: no prompt after {step['send']!r}")
                    return
                m = self.PROMPT.search(out)
                # The match starts at the newline before the prompt (part of the output) or
                # at the very start when the command printed nothing.
                cut = m.start() + (1 if out[m.start():m.start() + 1] == b"\n" else 0)
                self.steps.append((step, out[:cut], out[cut:]))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def finish(self):
        """Joins the session and judges every step; the failures (strings) come back."""
        self.thread.join(timeout=5)
        self.transcript_path.write_bytes(bytes(self.transcript))
        failures = list(self.errors)
        serial = self.serial_path.read_bytes() if self.serial_path.exists() else b""
        done = {id(st) for st, _, _ in self.steps}
        for st in self.spec["script"]:
            if id(st) not in done:
                failures.append(f"console step {st['send']!r} never ran")
        for st, out, prompt in self.steps:
            tag = f"console step {st['send']!r}"
            for exp in st.get("expect", []):
                if exp.encode() not in out:
                    failures.append(f"{tag}: expected {exp!r} in output {out[:200]!r}")
            for exp in st.get("absent", []):
                if exp.encode() in out:
                    failures.append(f"{tag}: forbidden {exp!r} in output")
            for prefix, marker, terminator in st.get("expect_serial", []):
                i = serial.find(marker.encode())
                if i < 0:
                    failures.append(f"{tag}: serial marker {marker!r} absent")
                    continue
                v = serial[i + len(marker):]
                v = v[:v.find(terminator.encode())] if terminator and terminator.encode() in v else v.split(b"\n")[0]
                if prefix.encode() + v not in out:
                    failures.append(f"{tag}: expected {prefix + v.decode(errors='replace')!r} (from the serial log) in output {out[:200]!r}")
            if "prompt" in st and prompt != st["prompt"].encode():
                failures.append(f"{tag}: prompt {prompt!r} != {st['prompt']!r}")
        return failures


def qmp_socket_path(monitor_path):
    """The QMP socket beside a case's HMP monitor socket (WP-38)."""
    monitor_path = Path(monitor_path)
    return monitor_path.with_name(monitor_path.stem + "-qmp.sock")


QMP_KEY_COMMANDS = ("key-down ", "key-up ")


class QmpLink:
    """One QMP connection for a whole run (WP-38), opened on the first `key-down`/`key-up`
    command and kept, so a step that releases a key costs no connect or handshake: HMP's
    `sendkey` presses and releases on a fixed timer, while a lab step must release a key a
    bounded time after a marker (the session's RELEASE_WAIT counts from auth's answer, whose
    PBKDF2 time differs between runners)."""

    def __init__(self, path):
        self.path, self.sock, self.buf = path, None, b""

    def _reply(self):
        import time
        end = time.monotonic() + 5
        while time.monotonic() < end:
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                if not line.strip():
                    continue
                msg = json.loads(line)
                if "return" in msg:
                    return msg
                if "error" in msg:
                    raise OSError(f"qmp: {msg['error']}")
            d = self.sock.recv(4096)
            if not d:
                raise OSError("qmp: connection closed")
            self.buf += d
        raise OSError("qmp: no reply")

    def _execute(self, command, arguments=None):
        msg = {"execute": command}
        if arguments is not None:
            msg["arguments"] = arguments
        try:
            self.sock.sendall((json.dumps(msg) + "\n").encode())
            return self._reply()
        except (OSError, ValueError):
            # A failed exchange leaves the link in an unknown state (a late reply would be read
            # as the next command's): drop it, so the next command reconnects from scratch.
            self.close()
            raise

    def key(self, line):
        """`key-down <qcode>` or `key-up <qcode>` (QEMU's QKeyCode names: `ret`, `a`, …)."""
        import socket
        verb, code = line.split(None, 1)
        if self.sock is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5)
            try:
                s.connect(str(self.path))
            except OSError:
                s.close()
                raise
            self.sock, self.buf = s, b""
            self._execute("qmp_capabilities")
        event = {"type": "key", "data": {"down": verb == "key-down", "key": {"type": "qcode", "data": code.strip()}}}
        self._execute("input-send-event", {"events": [event]})

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock, self.buf = None, b""


def run_qemu_monitored(cmd, cwd, log_out, log_err, timeout, serial_path, monitor_path, actions, sent=None):
    """`run_logged` for a QEMU case that drives the guest through the monitor (WP-27): once
    `actions["after"]` appears in the serial log, every line of `actions["commands"]` goes to
    the monitor socket (`sendkey a`, …), then QEMU runs to its end as usual. A case may need
    several such steps (WP-33: keys after one marker, more keys after a later one):
    `actions["steps"]` is a list of `{after, commands}` sent in order, each once its marker
    has appeared after the previous step was sent. `${SCREEN}` in a command names the run's
    screendump, `${SCREEN:tag}` one of several (WP-37: `screen-<tag>.ppm`, same directory).
    `key-down <qcode>` / `key-up <qcode>` go through QMP instead (WP-38, QmpLink): a key held
    from one step to a later one. A step with `since_previous` matches its marker only in what
    the serial log gained after the previous step fired (WP-38: a state the guest prints more
    than once, such as `state=unlocked`, means its next occurrence). `sent`, when a list, gets
    the index of every step whose commands all went out (WP-45: `ends_by_failures`)."""
    import socket
    import time
    steps = actions.get("steps") or [actions]
    qmp = QmpLink(qmp_socket_path(monitor_path))
    with open(log_out, "ab") as o, open(log_err, "ab") as e:
        o.write(f"$ {' '.join(cmd)}\n".encode()); o.flush()
        p = subprocess.Popen(cmd, cwd=cwd, stdout=o, stderr=e)
        deadline = time.monotonic() + timeout
        next_step = 0
        fired_at = 0  # the serial log's length when the previous step fired
        try:
            while p.poll() is None and time.monotonic() < deadline:
                if next_step < len(steps) and serial_path.exists():
                    step = steps[next_step]
                    text = serial_path.read_bytes()
                    if step["after"].encode() in (text[fired_at:] if step.get("since_previous") else text):
                        fired_at = len(text)
                        m = None
                        try:
                            for line in step["commands"]:
                                if line.startswith(QMP_KEY_COMMANDS):
                                    qmp.key(line)
                                else:
                                    if m is None:
                                        m = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                                        m.settimeout(5)
                                        m.connect(str(monitor_path))
                                        time.sleep(0.3)
                                        try:
                                            m.recv(4096)
                                        except OSError:
                                            pass
                                    # `${SCREEN}`: the screendump file of this run (WP-32), kept
                                    # as evidence next to the serial log.
                                    line = screen_paths(line, serial_path.parent / "screen.ppm")
                                    m.sendall((line + "\n").encode())
                                time.sleep(float(step.get("gap_s", actions.get("gap_s", 0.2))))
                            o.write(f"# monitor: sent {len(step['commands'])} command(s) after {step['after']!r}\n".encode()); o.flush()
                            if sent is not None:
                                sent.append(next_step)
                        except (OSError, ValueError) as ex:
                            e.write(f"monitor: {ex}\n".encode()); e.flush()
                        finally:
                            if m is not None:
                                m.close()
                        next_step += 1
                time.sleep(0.1)
        finally:
            qmp.close()
        if p.poll() is None:
            p.kill(); p.wait()
            e.write(b"TIMEOUT\n"); return 124
        return p.returncode


def ends_by_failures(ends_by, actions, sent):
    """How a case that never exits by itself must end (WP-45, PLAN-ANSWER §2.5 D2-Q2):
    `ends_by: "monitor"` passes only if every monitor step was sent and the last one ends with
    `quit` — QEMU's status for `quit` (0) is also its status for a guest reset under
    -no-reboot, so the status alone proves nothing. No `ends_by`: nothing to check."""
    if ends_by is None:
        return []
    if ends_by != "monitor":
        return [f"ends_by {ends_by!r} is not a known ending (monitor)"]
    if not actions:
        return ["ends_by monitor: the case has no monitor steps"]
    steps = actions.get("steps") or [actions]
    if not steps[-1].get("commands") or steps[-1]["commands"][-1] != "quit":
        return ["ends_by monitor: the last monitor step does not end with `quit`"]
    if list(sent) != list(range(len(steps))):
        return [f"ends_by monitor: steps sent {list(sent)} of {len(steps)}: the run ended before the lab's `quit`"]
    return []


# The fonts on the system volume (8.3 names): text.md.
FONT_FILES = {"NotoSans-Regular.ttf": "NOTOSANS.TTF", "NotoSansArabic-Regular.ttf": "NOTOARAB.TTF", "OFL.txt": "OFL.TXT"}


def serial_value(text, key, first=False):
    """The value the guest printed after the last (or, with `first`, the first) `key` in its
    serial output, up to the next `|` or end of line (WP-34: a hash or a rectangle the host
    must recompute); '' when absent."""
    i = text.find(key) if first else text.rfind(key)
    if i < 0:
        return ""
    rest = text[i + len(key):]
    end = len(rest)
    for stop in ("|", "\n", "\r"):
        j = rest.find(stop)
        if j >= 0:
            end = min(end, j)
    return rest[:end]


def screen_paths(text, screen_path):
    """`${SCREEN:tag}` → `screen-<tag>.ppm` next to `screen_path` (several screendumps in one
    run, WP-37), then `${SCREEN}` → `screen_path`."""
    text = re.sub(r"\$\{SCREEN:([A-Za-z0-9_-]+)\}",
                  lambda m: str(Path(screen_path).parent / f"screen-{m.group(1)}.ppm"), text)
    return text.replace("${SCREEN}", str(screen_path))


def substitute_host_arg(arg, disk_path, build_id, screen_path, serial_text, evidence_dir=None):
    """`${DISK}`, `${BUILD_ID}`, `${SCREEN}` and `${SCREEN:tag}` (screen_paths), `${EVIDENCE}`
    (the run's evidence directory, WP-36), `${SERIAL:key}` and `${SERIAL_FIRST:key}` (the value
    after the last / first `key` in the serial log, serial_value) in a host_checks argument."""
    out = screen_paths(arg.replace("${DISK}", str(disk_path)).replace("${BUILD_ID}", build_id), screen_path)
    if evidence_dir is not None:
        out = out.replace("${EVIDENCE}", str(evidence_dir))
    for tag, first in (("${SERIAL_FIRST:", True), ("${SERIAL:", False)):
        while tag in out:
            i = out.index(tag)
            j = out.index("}", i)
            out = out[:i] + serial_value(serial_text, out[i + len(tag):j], first) + out[j + 1:]
    return out


RUN_SLOT_RE = re.compile(r"[a-z]")


def new_run_dir(purpose_slug):
    """A fresh run directory <UTC second>-<rev[:8]>-<nnn>[-<slot>]. The slot (env NAWAH_RUN_SLOT,
    one lowercase letter, WP-81) names the CI job that wrote the run: three jobs building the same
    revision in the same second would otherwise each write <stamp>-<rev>-001, and their evidence
    collides when the merge job adopts it."""
    rev, _ = source_identity()
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slot = os.environ.get("NAWAH_RUN_SLOT", "")
    if slot and not RUN_SLOT_RE.fullmatch(slot):
        raise ValueError(f"NAWAH_RUN_SLOT {slot!r} is not one lowercase letter")
    suffix = f"-{slot}" if slot else ""
    n = 1
    while True:
        rid = f"{ts}-{rev[:8]}-{n:03d}{suffix}"
        d = (SCRATCH or EVIDENCE) / rid
        if not d.exists():
            d.mkdir(parents=True); return rid, d
        n += 1


# L-023 (WP-152): with this variable set a mutation gate's unchanged command merges its shard
# reports (tests/mutants.py GATE_SHARDS_ENV, set on verify's job g gate step alone), so a run
# written under it says so in its notes, whatever its value.
GATE_SHARDS_ENV = "NAWAH_GATE_SHARDS"


def write_run(d, rid, target, purpose, commands, exit_code, started, worker=None, notes=None):
    shards = os.environ.get(GATE_SHARDS_ENV)
    if shards is not None:
        seen = f"environment {GATE_SHARDS_ENV}={shards} (a mutation gate's command merges its shard reports, tests/mutants.py; L-023)"
        notes = f"{notes}; {seen}" if notes else seen
    rev, paths = RUN_TREE or (git("rev-parse", "HEAD") or "unknown", dirty_paths())
    env_worker, ci = runner_identity()
    run = {"schema_version": RUN_SCHEMA_VERSION, "run_id": rid, "started_at": started,
           "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "source_revision": rev, "dirty_state": bool(paths), "dirty_paths": paths,
           "host": {"os": os.uname().sysname + " " + os.uname().release, "machine": os.uname().machine},
           "target": target, "worker": worker or env_worker, "purpose": purpose, "commands": commands, "exit_code": exit_code}
    if ci:
        run["ci"] = ci
    if notes: run["notes"] = notes
    (d / "run.json").write_text(json.dumps(run, ensure_ascii=False, indent=1) + "\n")
    (d / "command.txt").write_text("\n".join(commands) + "\n")
    (d / "exit_code").write_text(f"{exit_code}\n")
    for f in ("stdout.log", "stderr.log"):
        (d / f).touch()


def digests_for(paths, globs=()):
    paths = list(paths)
    for g in globs:
        paths += sorted(str(x.relative_to(ROOT)) for x in ROOT.glob(g) if x.is_file())
    return {p: sha256_file(safe_rel(p)) for p in paths if safe_rel(p).exists()}


def rust_env():
    """Local fallback (docs/ENVIRONMENT.md): the pinned toolchain name may be uninstallable where
    static.rust-lang.org is blocked; if the default toolchain is the same rustc version, use it."""
    pin = "1.97.0"
    ok = subprocess.run(["rustup", "run", pin, "rustc", "--version"], capture_output=True, text=True)
    if ok.returncode == 0:
        return {}
    default = subprocess.run(["rustup", "default"], capture_output=True, text=True).stdout.split()[0:1]
    ver = subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout
    if default and pin in ver:
        return {"RUSTUP_TOOLCHAIN": default[0]}
    return {}


BUILD_ORACLE = "all build steps exit 0 and artifact exists"  # every target's build test (cmd_build)


def write_verdict(d, rid, test_id, verdict, oracle, expected, observed, inputs, claim_tag="source_backed_fact", reason=None):
    combined = sha256_text("\n".join(f"{k}={v}" for k, v in sorted(inputs.items())))
    v = {"schema_version": SCHEMA_VERSION, "run_id": rid, "test_id": test_id, "verdict": verdict, "oracle": oracle,
         "expected": expected, "observed": observed, "inputs_digest": combined, "inputs": inputs, "claim_tag": claim_tag}
    if reason: v["reason"] = reason
    (d / "verdict.json").write_text(json.dumps(v, ensure_ascii=False, indent=1) + "\n")
    (d / "digests.json").write_text(json.dumps(inputs, indent=1) + "\n")
    return v


def cmd_build(target_name) -> int:
    begin_run()
    t = load_target(target_name)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    rid, d = new_run_dir("build")
    rev, _ = source_identity()
    build_id = f"{rev[:12]}"
    env = dict(os.environ, NAWAH_BUILD_ID=build_id, NAWAH_OUT=str(ROOT / "build" / target_name),
               NAWAH_APPS_DIR=str(ROOT / "build" / target_name / "apps"))
    env.update(rust_env())
    (ROOT / "build" / target_name / "apps").mkdir(parents=True, exist_ok=True)
    cmds, rc = [], 0
    for step in t["build"]["steps"]:
        cmd = [x.replace("${OUT}", env["NAWAH_OUT"]).replace("${BUILD_ID}", build_id) for x in step]
        cmds.append(" ".join(cmd))
        with open(d / "stdout.log", "ab") as o, open(d / "stderr.log", "ab") as e:
            o.write(f"$ {' '.join(cmd)}\n".encode()); o.flush()
            try:
                rc = subprocess.run(cmd, cwd=ROOT, stdout=o, stderr=e, env=env, timeout=t["build"]["timeout_s"]).returncode
            except subprocess.TimeoutExpired:
                e.write(b"TIMEOUT\n"); rc = 124
            except OSError as ex:
                e.write(f"NOT_FOUND: {cmd[0]}: {ex}\n".encode()); rc = E_NOT_FOUND
        if rc != 0:
            break
    write_run(d, rid, target_name, "build", cmds, rc, started)
    inputs = digests_for(t["build"]["inputs"], t["build"].get("input_globs", ()))
    art = t["build"]["artifact"].replace("${OUT}", f"build/{target_name}")
    observed = f"exit={rc}"
    if rc == 0 and safe_rel(art).exists():
        observed += f" artifact={art} sha256={sha256_file(safe_rel(art))}"
        (ROOT / "build" / target_name / "build-id.txt").write_text(build_id + "\n")
    verdict = "PASS" if rc == 0 and safe_rel(art).exists() else \
        ("ERROR" if env_failed(rc, (d / "stderr.log").read_text(errors="replace")) else "FAIL")
    if verdict == "PASS":
        inputs[keep_artifact(d, rid, safe_rel(art))] = sha256_file(safe_rel(art))
        for extra in t["build"].get("extra_artifacts", []):
            ep = safe_rel(extra.replace("${OUT}", f"build/{target_name}"))
            if ep.exists():
                inputs[keep_artifact(d, rid, ep)] = sha256_file(ep)
    write_verdict(d, rid, t["build"]["test_id"], verdict, BUILD_ORACLE, "exit 0 + artifact", observed, inputs)
    attach_evidence(t["build"]["test_id"], rid, verdict)
    print(f"build {target_name}: {verdict} run={rid} build_id={build_id}")
    return 0 if verdict == "PASS" else 1


def keep_artifact(d, rid, art: Path) -> str:
    """Copy the built artifact into the evidence dir so the verdict's inputs survive `build/` cleanup."""
    import shutil
    (d / "artifact").mkdir(exist_ok=True)
    shutil.copy(art, d / "artifact" / art.name)
    return f"evidence/{rid}/artifact/{art.name}"


def qemu_cmd(t, target_name, esp_dir, serial_log, extra=(), disk=None, smp=None, monitor=None, console_port=None):
    q = t["qemu"]
    # Per-target exit device: isa-debug-exit on the PC, semihosting on the Arm virt board.
    exit_args = q.get("extra_args", ["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
    disk_args = []
    if disk is not None:
        disk_args = ["-drive", f"if=none,id=vd0,format=raw,file={disk}", "-device", q["disk"]["device"]]
    # The lab network (WP-27): QEMU user-mode networking (SLIRP) on a modern virtio-net function.
    if q.get("net"):
        disk_args += ["-netdev", q["net"]["netdev"], "-device", q["net"]["device"]]
    # A monitor socket when a case drives the guest (keys through `sendkey`, WP-27).
    if monitor is not None:
        disk_args += ["-monitor", f"unix:{monitor},server,nowait"]
        # QMP beside it (WP-38): `key-down`/`key-up` lab commands hold a key across a marker.
        disk_args += ["-qmp", f"unix:{qmp_socket_path(monitor)},server,nowait"]
    # The second serial port (COM2) is the diagnostic console (WP-30): a TCP server the lab
    # connects to when the case has a `console` script, otherwise a null sink so the port
    # exists in every run (the kernel probes it at boot: kernel|diag).
    console_args = ["-serial", f"tcp:127.0.0.1:{console_port},server=on,wait=off" if console_port else "null"]
    # A case (or phase) may ask for its own CPU count (`smp`, WP-20); the target's is the default.
    cmd = [q["binary"], "-machine", q["machine"], "-cpu", q["cpu"], "-m", q["memory"], "-smp", str(smp or q["smp"]),
           "-drive", f"if=pflash,format=raw,readonly=on,file={q['ovmf_code']}",
           "-drive", f"if=pflash,format=raw,file={ROOT / 'build' / target_name / 'OVMF_VARS.fd'}",
           "-drive", f"format=raw,file=fat:rw:{esp_dir}",
           "-serial", f"file:{serial_log}", *console_args, "-display", "none", "-no-reboot",
           *exit_args, *disk_args, *extra]
    return cmd


def disk_file_args(files, out):
    """`--add` pairs for a case's `disk_files` (WP-84): {volume path: source}. The volume path is
    a plain relative path (no `..`, not absolute); the source is a file under the tree, `${OUT}`
    naming the target's build directory. A wrong entry stops the run before any image is made."""
    adds, seen = [], set()
    for dst, src in (files or {}).items():
        src_s = src.replace("${OUT}", str(out.relative_to(ROOT)))
        # A plain volume path: components separated by `/`, none empty, `.` or `..`, none with
        # a backslash or a colon (the audit of WP-84: such a path reached the formatter).
        plain = bool(dst) and all(p not in ("", ".", "..") and "\\" not in p and ":" not in p for p in dst.split("/"))
        if not plain or src_s.startswith("/") or ".." in src_s.split("/"):
            raise SystemExit(f"disk_files: {dst!r} <- {src!r}: paths must be plain and relative, without '..'")
        path = ROOT / src_s
        if not path.is_file():
            raise SystemExit(f"disk_files: {dst!r} <- {src!r}: no such file under the tree")
        # A link inside the tree to a file outside it is no file under the tree.
        if ROOT.resolve() not in path.resolve().parents:
            raise SystemExit(f"disk_files: {dst!r} <- {src!r}: the source leaves the tree")
        if dst.upper() in seen:
            raise SystemExit(f"disk_files: {dst!r}: the volume file is named twice")
        seen.add(dst.upper())
        adds.append((dst.upper(), path))
    return adds


def prepare_disk(t, target_name, fresh=True, files=None):
    """The lab's virtio disk (WP-18): a raw FAT32 image of `qemu.disk.size_mib` MiB made by
    tools/fat32.py (an implementation independent of the kernel's) with the lab files
    (/HELLO.TXT, /PATTERN.BIN of 20480 bytes `(i*31 + (i>>8)) & 0xFF`, /DIR/INNER.TXT), the
    built applications under /SYSTEM (WP-23) and the raw pattern `(sector*7+i)&0xFF` in its
    last `pattern_tail` sectors. Rebuilt for every run
    unless `fresh` is false (a multi-phase case keeps what earlier phases wrote). Targets without
    `qemu.disk` get none. `files` (a case's `disk_files`, WP-84: disk_file_args) replace the
    volume file of the same path or are added: a damaged manifest, a manager that never answers."""
    spec = t["qemu"].get("disk")
    if not spec:
        return None
    out = ROOT / "build" / target_name
    img = out / "disk.img"
    overrides = disk_file_args(files, out)
    if fresh or not img.exists():
        sectors = int(spec["size_mib"]) * 2048
        hello = out / "lab-hello.txt"
        hello.write_bytes(b"hello from the lab disk\n")
        pattern = out / "lab-pattern.bin"
        pattern.write_bytes(bytes(((i * 31 + (i >> 8)) & 0xFF) for i in range(20480)))
        cmd = ["python3", "-I", str(ROOT / "tools" / "fat32.py"), "format", str(img), "--sectors", str(sectors),
               "--mkdir", "DIR", "--mkdir", "SYSTEM", "--add", f"HELLO.TXT={hello}", "--add", f"PATTERN.BIN={pattern}",
               "--add", f"DIR/INNER.TXT={hello}", "--pattern-tail", str(int(spec.get("pattern_tail", 8)))]
        # System volume (WP-23, ADR-0016 §1): every built application with an 8.3-compatible
        # name as /SYSTEM/<NAME>.ELF, where `process_spawn` finds the images of M4's services.
        for elf in sorted((out / "apps").glob("*.elf")) if (out / "apps").is_dir() else []:
            if len(elf.stem) <= 8:
                cmd += ["--add", f"SYSTEM/{elf.stem.upper()}.ELF={elf}"]
        # Fonts (WP-35, text.md): the shipped OFL fonts and their licence in /SYSTEM/FONTS.
        cmd += ["--mkdir", "SYSTEM/FONTS"]
        for src, dst in FONT_FILES.items():
            cmd += ["--add", f"SYSTEM/FONTS/{dst}={ROOT / 'platform' / 'assets' / 'fonts' / src}"]
        # The applications' registry (WP-101, ADR-0023 item 2, apps.md v1): platform/<target>/apps/*.APP
        # as /SYSTEM/APPS/<ID>.APP, written by the build and by nothing at run time.
        apps_dir = ROOT / "platform" / target_name / "apps"
        if apps_dir.is_dir():
            cmd += ["--mkdir", "SYSTEM/APPS"]
            for app in sorted(apps_dir.glob("*.APP")):
                cmd += ["--add", f"SYSTEM/APPS/{app.name}={app}"]
        # Service manifests (WP-24): platform/<target>/manifests/*.txt as /SYSTEM/<NAME>.TXT.
        for man in sorted((ROOT / "platform" / target_name / "manifests").glob("*.txt")):
            cmd += ["--add", f"SYSTEM/{man.stem.upper()}.TXT={man}"]
        # The lab's users (WP-25, auth.md §3): PBKDF2-HMAC-SHA-256 by Python's hashlib — an
        # implementation independent of the guest's — with a fixed per-name salt so the image
        # is reproducible (lab fixture; real users get random salts, SP 800-132 §5.1).
        users = t.get("lab", {}).get("users", [])
        if users:
            import hashlib
            lines = ["NAWAH-USERS 1", "# lab users: generated by tools/project.py prepare_disk; no plaintext anywhere"]
            for u in users:
                salt = hashlib.sha256(b"nawah-lab-salt:" + u["name"].encode()).digest()[:16]
                dk = hashlib.pbkdf2_hmac("sha256", u["password"].encode(), salt, int(u["iterations"]), 32)
                lines.append(f"{u['uid']}:{u['gid']}:{u['name']}:{u['perms']}:{u['iterations']}:{salt.hex()}:{dk.hex()}")
            db = out / "lab-users.db"
            db.write_text("\n".join(lines) + "\n")
            cmd += ["--add", f"SYSTEM/USERS.DB={db}"]
        # The case's own files last, each replacing a volume file of the same path.
        replaced = {dst for dst, _ in overrides}
        kept = []
        i = 0
        while i < len(cmd):
            if cmd[i] == "--add" and cmd[i + 1].split("=", 1)[0].upper() in replaced:
                i += 2
                continue
            kept.append(cmd[i])
            i += 1
        cmd = kept + [x for dst, path in overrides for x in ("--add", f"{dst}={path}")]
        subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return img


def prepare_esp(t, target_name, artifact):
    import shutil
    esp = ROOT / "build" / target_name / "esp"
    if esp.exists(): shutil.rmtree(esp)
    (esp / "EFI" / "BOOT").mkdir(parents=True)
    # Removable-media boot file name per UEFI 2.11 §3.5.1.1: BOOTX64.EFI / BOOTAA64.EFI.
    shutil.copy(artifact, esp / "EFI" / "BOOT" / t["qemu"].get("esp_file", "BOOTX64.EFI"))
    shutil.copy(t["qemu"]["ovmf_vars"], ROOT / "build" / target_name / "OVMF_VARS.fd")
    return esp


def select_boot_case(t):
    """One oracle per boot test (docs/PLAN-ANSWER.md §2.6 D1-A): the suite case carrying the
    boot test id is the oracle, QEMU arguments included — TST-M1-BOOT runs behind the lab
    self-test key (WP-45), and skipping it would boot the release image interactively against
    the weaker `boot_oracle` until the timeout. `boot_oracle` is only the fallback for targets
    without such a case; two cases with the boot test id are ambiguous and refused."""
    boot_id = t["boot_oracle"]["test_id"]
    found = [c for cases in t.get("suites", {}).values() for c in cases if c["test_id"] == boot_id]
    if len(found) > 1:
        raise ValueError(f"{len(found)} suite cases carry the boot test {boot_id}: {[c['id'] for c in found]}")
    return found[0] if found else None


def cmd_boot(target_name, test_id=None, suite_case=None) -> int:
    begin_run()
    t = load_target(target_name)
    if suite_case is None:
        try:
            c = select_boot_case(t)
        except ValueError as e:
            print(f"boot: {e}"); return E_INTERNAL
        if c is not None:
            suite_case = dict(c, _plain_boot=True)
    art_rel = (suite_case or {}).get("artifact") or t["build"]["artifact"]
    art = safe_rel(art_rel.replace("${OUT}", f"build/{target_name}"))
    if not art.exists():
        print("no artifact; run build first"); return E_BLOCKED
    build_id = (ROOT / "build" / target_name / "build-id.txt").read_text().strip()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    rid, d = new_run_dir("boot")
    esp = prepare_esp(t, target_name, art)
    # A case may need longer than the target's default (the auth cases derive keys at TCG
    # speed), and a phase may carry its own `timeout_s` (WP-45: the step cap bounds the sum of
    # the phases); the environment variable still overrides everything (mutation runs).
    case_timeout = (suite_case or {}).get("timeout_s", t["qemu"]["boot_timeout_s"])
    plain_boot = suite_case is None or suite_case.get("_plain_boot")
    case = suite_case or t["boot_oracle"]
    # A case is one QEMU run, or several `phases` in sequence on the same disk image (the
    # persistence test): each phase has its own qemu_extra and markers; the case's own markers
    # and equal_values are checked against the concatenated serial output of all phases.
    phases = case.get("phases") or [{}]
    cmds, texts, rcs, phase_failures, lab_errors = [], [], [], [], []
    console_failures, received = [], []
    for i, ph in enumerate(phases):
        timeout_s = int(os.environ.get("NAWAH_QEMU_TIMEOUT_S", ph.get("timeout_s", case_timeout)))
        serial = d / ("serial.log" if len(phases) == 1 else f"serial-{i + 1}.log")
        # A phase with its own `disk_files` (WP-84) starts from a fresh disk with them.
        disk_files = ph.get("disk_files", case.get("disk_files"))
        fresh = i == 0 or "disk_files" in ph
        disk = prepare_disk(t, target_name, fresh=fresh, files=disk_files)
        extra = ph.get("qemu_extra", case.get("qemu_extra", []))
        actions = ph.get("monitor", case.get("monitor"))
        peers = HostServices(ph.get("host_services", case.get("host_services")))
        # A short socket path (AF_UNIX paths are limited to 107 bytes).
        monitor = (ROOT / "build" / target_name / f"mon{i + 1}.sock") if actions else None
        if monitor is not None:
            monitor.unlink(missing_ok=True)
            qmp_socket_path(monitor).unlink(missing_ok=True)
        console_spec = ph.get("console", case.get("console"))
        cmd = qemu_cmd(t, target_name, esp, serial, extra, disk, ph.get("smp", case.get("smp")), monitor,
                       console_spec and console_spec["port"])
        sent = []
        run = (lambda: run_qemu_monitored(cmd, ROOT, d / "stdout.log", d / "stderr.log", timeout_s, serial, monitor, actions, sent)) if actions \
            else (lambda: run_logged(cmd, ROOT, d / "stdout.log", d / "stderr.log", timeout_s))
        # One transcript per phase (console-<i>.log beside serial-<i>.log): a later phase's
        # session never overwrites an earlier one's (security review M5).
        console_log = d / ("console.log" if len(phases) == 1 else f"console-{i + 1}.log")

        def attempt():
            # One console session per QEMU attempt: a retry after QEMU died is judged by its own
            # session, never by the dead attempt's transcript or failures (WP-82, the auditor).
            con = ConsoleSession(console_spec, console_log, serial, timeout_s) if console_spec else None
            if con:
                con.start()
            try:
                code = run()
            finally:
                peers.close()
                fails = con.finish() if con else []
            return code, con, fails
        rc, console, cfails = attempt()
        if rc < 0:
            # QEMU itself died (signal): a lab failure, not a verdict on the kernel. One retry on
            # a fresh image; if it dies again the case fails and says why (LAB_ERROR), so a
            # mutation run never counts it as a kill (mutants run 39116036466: 4 SIGSEGVs).
            lab_errors.append(f"phase {i + 1}: qemu died with signal {-rc}, retried")
            sent.clear()
            serial.unlink(missing_ok=True)
            disk = prepare_disk(t, target_name, fresh=fresh, files=disk_files)
            peers = HostServices(ph.get("host_services", case.get("host_services")))
            rc, console, cfails = attempt()
        # Every phase's console verdict is kept (a later phase's session must not overwrite an
        # earlier one's failures).
        console_failures += [f"phase {i + 1}: {f}" if len(phases) > 1 else f for f in cfails]
        # What the guest sent on the console (WP-82): forbidden markers are checked on it too.
        got = bytes(console.received).decode(errors="replace") if console else ""
        received.append((console_log.name, got))
        text = serial.read_text(errors="replace") if serial.exists() else ""
        cmds.append(" ".join(cmd)); texts.append(text); rcs.append(rc)
        ended = [f"phase {i + 1}: {f}" for f in ends_by_failures(ph.get("ends_by", case.get("ends_by")), actions, sent)]
        if len(phases) > 1:
            exp = ph.get("expected_exit_code", case["expected_exit_code"])
            req = [m.replace("${BUILD_ID}", build_id) for m in ph.get("required_markers", [])]
            fb = ph.get("forbidden_markers", [])
            miss = [m for m in req if m not in text]
            forb = [m for m in fb if m in text] + [f"{m} ({console_log.name})" for m in fb if m in got]
            if rc != exp or miss or forb or ended:
                phase_failures.append(f"phase {i + 1}: exit {rc} (expected {exp}); missing {miss}; forbidden {forb}; {ended}")
                break
        else:
            phase_failures += ended
    if len(phases) > 1:
        (d / "serial.log").write_text("".join(f"=== phase {i + 1} ===\n{t_}" for i, t_ in enumerate(texts)))
    text = "".join(texts)
    rc = rcs[-1]
    write_run(d, rid, target_name, "boot" if plain_boot else f"test:{suite_case['id']}", cmds, rc, started)
    inputs = digests_for(t["build"]["inputs"], t["build"].get("input_globs", ())) | {keep_artifact(d, rid, art): sha256_file(art)}
    expected_rc = case["expected_exit_code"]
    required = [m.replace("${BUILD_ID}", build_id) for m in case["required_markers"]]
    forbidden = case.get("forbidden_markers", [])
    missing = [m for m in required if m not in text]
    present_forbidden = [m for m in forbidden if m in text]
    present_forbidden += [f"{m} ({name})" for name, r in received for m in forbidden if m in r]
    over = [f"{m}x{text.count(m)}>{mx}" for m, mx in case.get("max_counts", {}).items() if text.count(m) > mx]
    present_forbidden += over
    missing += [f"{m}x{text.count(m)}<{mn}" for m, mn in case.get("min_counts", {}).items() if text.count(m) < mn]
    for pat_a, pat_b in case.get("equal_values", []):
        ma, mb = re.search(pat_a, text), re.search(pat_b, text)
        if not ma or not mb or ma.group(1) != mb.group(1):
            missing.append(f"equal_values({pat_a} vs {pat_b}): {ma and ma.group(1)} != {mb and mb.group(1)}")
    missing += phase_failures
    missing += console_failures
    # Host checks (WP-18): commands run on the host against the disk image after the guest
    # run(s) — independent readers (tools/fat32.py, fsck.fat) confirm what the kernel wrote.
    disk_path = ROOT / "build" / target_name / "disk.img"
    host_failures, host_check_lab = [], []
    with open(d / "host-check.log", "w") as hc:
        for check in case.get("host_checks", []):
            cmd = [substitute_host_arg(x, disk_path, build_id, d / "screen.ppm", text, d) for x in check]
            try:
                r = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
            except OSError as ex:
                hc.write(f"$ {' '.join(cmd)}\n{ex}\n"); host_check_lab.append(f"host_check could not run: {' '.join(cmd)}: {ex}")
                continue
            except subprocess.TimeoutExpired:
                hc.write(f"$ {' '.join(cmd)}\nTIMEOUT\n"); host_failures.append(f"host_check timed out: {' '.join(cmd)}")
                continue
            hc.write(f"$ {' '.join(cmd)}\n{r.stdout}\n[exit {r.returncode}]\n")
            if r.returncode != 0:
                host_failures.append(f"host_check failed: {' '.join(cmd)} -> {r.returncode}")
    lab_errors += host_check_lab
    # The guest's own verdict comes first: a host tool missing never hides a guest failure.
    if rc < 0:
        verdict, reason = "ERROR", f"LAB_ERROR: qemu died with signal {-rc} twice"
        print(f"LAB_ERROR qemu died with signal {-rc} twice ({case['test_id']})")
    elif rc == E_NOT_FOUND and env_failed(rc, (d / "stderr.log").read_text(errors="replace")):
        verdict, reason = "ERROR", "LAB_ERROR: qemu could not be started"
        print(f"LAB_ERROR qemu could not be started ({case['test_id']})")
    elif rc == 124:
        verdict, reason = "FAIL", "timeout (hang)"
    elif rc != expected_rc:
        verdict, reason = "FAIL", f"exit {rc} != expected {expected_rc}"
    elif missing or present_forbidden:
        verdict, reason = "FAIL", f"missing markers {missing}; forbidden present {present_forbidden}"
    elif host_check_lab:
        verdict, reason = "ERROR", "LAB_ERROR: a host check could not run"
        print(f"LAB_ERROR a host check could not run ({case['test_id']})")
    elif host_failures:
        verdict, reason = "FAIL", f"host checks {host_failures}"
    else:
        verdict, reason = "PASS", "exit code and serial markers match oracle"
    if lab_errors:
        reason += "; " + "; ".join(lab_errors)
    write_verdict(d, rid, case["test_id"], verdict, case["oracle"], f"exit={expected_rc}; markers={required}; forbidden={forbidden}; phases={len(phases)}",
                  f"exit={rc}; serial_lines={len(text.splitlines())}; missing={missing + host_failures}; forbidden_present={present_forbidden}",
                  inputs, reason=reason)
    attach_evidence(case["test_id"], rid, verdict)
    print(f"{'boot' if plain_boot else case['id']} {target_name}: {verdict} ({reason}) run={rid}")
    for line in text.splitlines()[:40]:
        print("  serial|", line)
    return 0 if verdict == "PASS" else 1


HOST_SUITES = {
    "M0": [
        {"id": "TST-M0-001", "command": ["python3", "-I", "tests/test_validate_records.py"], "oracle": "unittest exit 0 and 'OK' in output; 40 cases incl. 6 required rejections, the dependency rule for active and done items, a new run re-pointing every older run of its test, two runners in the same second getting distinct run ids through the job slot NAWAH_RUN_SLOT (one lowercase letter appended as -<slot>, anything else refused, no slot the id as before) that the evidence schemas accept, an earlier schema error that must not skip later evidence checks, and environment failures (a missing command, a failed toolchain download) recorded as ERROR, not FAIL; each oracle has one source (WP-92): a record whose oracle differs from its source (a HOST_SUITES case, a target.json suite case or boot_oracle, the build's own text) is an error naming the test, as are two sources giving one id different texts (a boot_oracle shadowed by a suite case of its own target is no source, another target's is; sync-oracles then writes nothing), sync-oracles writes the oracle field alone from the source and leaves a record without one, its --check writes nothing and fails on a difference, the file keeps its format, a dated note lives in oracle_notes (an undated one is refused), and under --strict a PASS record's oracle must equal the oracle its evidence's verdict.json records, stale_policy warn included; stale_policy warn is accepted only on the four mutation gates verify does not run (TST-M2-MUTANTS to TST-M5-MUTANTS, which the real records carry it on and no other): on any other test it is an error also without --strict and never softens that test's stale verdict (the owner's DEC-029, WP-96); and what docs/project-state.json says of where the project stands (WP-165, the owner's note of 2026-11-19): the next step is the first active item, else the next step of the owner's order, read from item 5 of section 7 of docs/policies/team-methodology.md: its first item that is not done or, while that one waits, its first dependency that is not done, looked at the same way, and never the file's first ready item (without an order, or with all of it done, there is none and the text says so; a superseded item stands for the one that took its place, an id the records do not hold is passed over, a cycle ends where it closes instead of running on, and a blocked item's text says it is blocked and by what); a checkpoint writes that step, clears a task that is no longer one, and writes the waiting decisions from their records (those whose status is open); with a state file present an order that cannot be read or names an unknown work item is an error, a file that names another step or other waiting decisions than the records give is a warning naming both and an error under --strict, and every decision a blocker names must be an open one",
         "inputs": ["tools/project.py", "tools/schemas_gen.py", "tests/test_validate_records.py"], "input_globs": ["docs/schemas/*.schema.json"]},
        {"id": "TST-M0-002", "command": ["python3", "-I", "tests/test_m0_records.py"], "oracle": "required M0 documents and contract sections exist; every tracked path checks out on Windows (no reserved device name, invalid character, trailing dot or space, or case-only collision); every file ADR-0002 item 4 ports from Sol OS names its origin (commit d54f0a5 or the Sol ADR) in its header; the twelve-role team methodology is in place (docs/policies/team-methodology.md names every role, .claude/workflows/nawah-team.js opens with its meta literal, the twelve agent definitions carry name/description/tools/model; docs/PLAN-REVERSE.md exists with its seven sections, the fifth listing refuted and unverified claims; docs/PLAN-ANSWER.md exists with its eight sections)",
         "inputs": ["tests/test_m0_records.py", "docs/contracts/boot.md", "docs/adr/0001-bootstrap.md", "docs/PROJECT.md", "docs/ENVIRONMENT.md", "docs/security/threat-model.md",
                    "docs/adr/0002-rust-and-sol-os-reuse.md", "kernel/src/arch/x86_64/gdt.rs", "kernel/src/arch/x86_64/idt.rs", "kernel/src/arch/x86_64/trap.rs",
                    "kernel/src/arch/x86_64/serial.rs", "kernel/src/arch/x86_64/port.rs", "kernel/src/arch/x86_64/qemu.rs", "kernel/src/arch/x86_64/ktest.rs",
                    "kernel/src/cell.rs", "kernel/src/ktest.rs", "tests/mutants.py", "tools/check-unsafe.sh",
                    "docs/policies/team-methodology.md", ".claude/workflows/nawah-team.js", "CLAUDE.md", "docs/PLAN-REVERSE.md", "docs/PLAN-ANSWER.md"], "input_globs": [".claude/agents/*.md"]},
        {"id": "TST-M0-003", "command": ["python3", "-I", "tests/test_ci_workflows.py"],
         "oracle": "every workflow file parses as YAML with a name, triggers and jobs (each with a runner and steps) and pins every action it uses to a commit; no checkout keeps the token and only the evidence push is given it; verify runs on pushes to main, pull requests and by hand, limits its job's time and cancels the run a newer push to the same ref supersedes (concurrency group per ref, cancel-in-progress); every Toolchain step ends within 15 minutes and retries each download with a per-attempt timeout (three runs of 2026-10-23 hung there to the job's limit), each call naming its own limit; its fallback's one sed line, applied for real to copies of /etc/apt/apt-mirrors.txt and /etc/apt/sources.list.d/ubuntu.sources (both edited in place), turns every regional *.archive.ubuntu.com host (us-east-2.ec2, azure, eu-west-1.ec2, de) into archive.ubuntu.com, scheme and path kept, and leaves archive.ubuntu.com, security.ubuntu.com, packages.microsoft.com, mirror+file: and the comment byte for byte; the tries of the runner's mirror before it (the update and the fetch, each try longer than apt's Acquire::http::Timeout) take at worst, pauses included, at most half of the step's cap, and every other try (the fallback, the install, rustup) at least 300 s (WP-152, verify run 44218469147); mutants never runs on a push; every guest suite of target.json has its verify step and vice versa, and every host suite outside the gates and M2 is non-empty and run (ADR-0026, D5); every verify job has one Toolchain step capped at 15 and its own limit (test job a 62, test job b 40, merge 20; WP-83, 83a; 58 until WP-88), the M6 guest step of job a and the M5 guest step of job b carry their own caps {M6 18, M5 18; M6 15 until WP-88; M5 in job a until WP-153} and in every job the step caps with a 20 % margin fit that job's limit (D4-V2), and M6, bounded by its own timeouts, fits its cap in the worst case (the sum over its cases of each phase's timeout_s, the case's or target.json's default, stays under the cap: 895 s against 900 on 2026-11-14; M5's cap is a measured hang guard, outside that rule; uncapped steps are not budgeted); the suite case carrying the boot test id is the oracle of `project.py boot` even with QEMU arguments, two such cases are refused, boot_oracle carries the same lab self-test key as TST-M1-BOOT, and a kernel source other than ktest.rs names that key (PLAN-ANSWER §2.6, WP-45); every phase of TST-M6-INTERACTIVE-BOOT and TST-M1-BOOT require the kernel's whole boot-mode line with the build id (OSX|${BUILD_ID}|kernel|boot_mode|mode=…|source=…|key=…|hv=…, the values per phase), never a fragment a process could print through SYS_TRACE, and the case caps `|kernel|boot_mode|` at one per boot (6); fw_cfg is reached only from bootmode.rs, ktest.rs and fwcfg.rs itself (exact identifiers of fwcfg.rs's public entries, the module name outside its two declaring files, the ports 0x510/0x511), and the guard reports a planted caller, an aliased import and a direct port write while ignoring a lookalike name (PLAN-ANSWER §3.4 item 3); the local pre-flight adds scratch evidence to the caller's environment with build-std for the guest build only (never for the test step, whose host tools link the host's std) and accepts the library source only at the compiler's own commit (missing / ok / mismatch); the mutation harness builds every app the kernel embeds; import-ci-evidence copies the runner's new runs, skips a committed directory without ci identity already under evidence/ (no refusal, no receipt) and leaves no temporary copy behind, also when the checkout fails, and leaves what the user staged staged; check-commit rejects a head commit naming an unknown work item or one that is neither active nor done, and verify runs it (DEC-004); a re-run replaces its evidence branch; TST-M6-HOLD-FAIL-CLOSED is one case of the M6 suite on NAWAH-KTEST.EFI with the ktest key hold_fail_closed, exit 33 and 60 s, requires the ktest start line, its five verdict lines (reply and too_long held with keys=0 of keys_in=2, closed exit 0xe6, manifest locked=0 and locked_with_session=1, nothing left behind), displayd's held trace for each LIST failure branch (reply, too_long, closed) and both manifest decisions, forbids `holds=OK locked=0` and the unheld line of the reply and too_long branches, and no required marker of it is forbidden (WP-67); the mutants workflow runs the gates M2, M3, M4, M5, M6 in order, checks the records non-strictly before them and strictly after the last one (always(), before Publish; audit of WP-92) and publishes and uploads every gate's report, and the M6 gate step carries its own cap, above TST-M6-MUTANTS's timeout_s; the job's limit (345, within a hosted job's 360) fits every capped step at its cap (Toolchain, the M6 gate, the host suites, the upload), the four uncapped older gates at their measured 127.8 min with the 20 % margin and 20 for the rest (WP-95); after the last gate (after a red one too, never after a failed baseline nor in a cancelled run) and right before its strict check it runs a Host suites step with verify's own script, which runs every host suite once and fails at the end when any failed, under a cap of its own, and its Toolchain step is verify's job a's (WP-95, option B: the strict check is the import's condition and a head changing tools/project.py or the harness leaves the host tests that read them stale); its artifact upload, capped and always(), takes this run's directories alone, `evidence/*-${{ steps.rev.outputs.sha8 }}-*/` after an always() step rev, beside the reports so that the artifact stays rooted at the workspace, while Publish still adds evidence/ to the ci-evidence branch (the WP-95 review: `evidence/` took the whole 14.4 GB tree); the gates a run executes are chosen by the workflow_dispatch input `stages` (a string, default and schedule exactly `M2 M3 M4 M5`, the gates of STALE_WARN_TESTS, M6 outside it because verify runs the M6 gate in every run: DEC-029, WP-96, sharded since WP-152 and WP-153; WP-95), each gate step's `if` `${{ !cancelled() && steps.baseline.outcome == 'success' && contains(…, ' <stage> ') }}`, so no gate runs after a failed baseline (the baseline step has id baseline, no if and no continue-on-error) nor in a cancelled run and a red gate does not skip the next (WP-90, WP-95); a step `stages` before the Toolchain reads the input through the environment with the same default, never spliced into its script, and, run as GitHub runs it (bash -e), accepts any set of the gates and refuses with an ::error a selection naming no gate, any word that is not a gate or any character other than M, 2 to 6 and a plain space (a blank, M7, m2, M2,M3, M1, M3 M7, *, all, M2<tab>M3, M2<newline>M5, M6<newline>: a tab or newline split the shell's words but not the gates' contains()) (WP-95); the Host suites step, found in whichever verify job holds it and run as GitHub runs a step without `shell:` (bash -e, no pipefail) with a stub project.py, runs every host suite but the gates and M2 once whatever fails and exits non-zero when any failed, zero when none did, and the check reports a loop that pipes a suite into tee and the six bare commands (WP-91); the interactive LOAD budget (WP-82, boot.md) is read from the kernel's code with comments dropped and string and char literals emptied: across kernel/src exactly one declaration of LOAD_BUDGET_TICKS at any indentation and under any attribute, `const LOAD_BUDGET_TICKS: u64 = 10_000;`; start_at_boot defined once, in services.rs, and named once elsewhere, by one call in kmain.rs whose first argument is the identifier LOAD_BUDGET_TICKS; inside start_at_boot its tick parameter used once, as the deadline `t0 + timeout_ticks`; exactly one TIMER_HZ in the kernel, `const TIMER_HZ: u32 = 1000;` in arch/x86_64/irq.rs; the guard reports a wrong value, a literal call, a missing constant and each decoy: an indented shadowing const, a second declaration under another cfg or as a static in another file, a call on another constant beside a commented, block-commented or quoted call, a `use … as` alias, a function pointer, a second call outside kmain.rs, a clamp or a literal deadline inside start_at_boot, a second definition, another TIMER_HZ value, a second TIMER_HZ or none; outside the guard: a const generated by a macro, a function-local `use … as` alias, a rebinding of the start tick and a clamp inside request(); verify's token reads at the top level and only the job holding the Publish step may write; every job other than `merge` and the shard jobs sets NAWAH_RUN_SLOT to its own lowercase letter and uploads as `evidence-<slot>` exactly one evidence path, this run's directories of the slot `evidence/*-${{ steps.rev.outputs.sha8 }}-*-<slot>/`, after an always() step `rev` writing the first 8 characters of `git rev-parse HEAD` (always, continue-on-error; `evidence/*`, `evidence`, `evidence/**`, another slot added beside it, the former `evidence/*-<slot>/` that took every committed directory of the slot (WP-153, run 44229918866), a step rev changed, dropped or not always() are refused), and that step run for real prints the 8 characters project.py names run directories with, whose pattern takes a directory of this run in its slot and none of another sha, another slot or the directories committed under evidence/, and none of them validates strictly, runs pre-merge, adopts or publishes; the `merge` job needs every other job and runs unless the run is cancelled (`!cancelled()`, never always()), and runs in order a pinned download-artifact of `evidence-*` (each artifact in its own directory), the adopt step, `validate-records --strict`, tools/pre-merge.sh and Publish evidence, then fails the run when any test job did not succeed; every slot's artifact is rooted at the workspace by the pinned upload-artifact's rule (ea165f8d search.ts: each path line's literal prefix before its first `*`, `?` or `[` segment, one under another dropped, the lowest common ancestor of two or more, that path itself for one, a single plain file's parent; WP-153 review: job b's one evidence line rooted it at evidence/), a build file a slot other than a carries beside a's comes from the same checkout and the same build command, and the adopt step names every expected slot (one per test job) in both its loops, the adoption and the build-file copy, and, run as GitHub runs a step without `shell:` (bash -e) in a scratch tree whose artifacts hold the workspace files under each slot's computed root, fails with an error naming the slot and adopts nothing when a slot's artifact is missing or holds no run directory, passes `--from incoming/evidence-<slot>/evidence` for each slot otherwise, fails when adopt-native refuses (so `|| true` after it is caught), and still succeeds when a source carries no build/ files; Publish runs only when the adopt step succeeded and the run is not cancelled, with GIT_CONFIG_GLOBAL=/dev/null and GIT_CONFIG_NOSYSTEM=1, every git call `/usr/bin/git -c core.hooksPath=/dev/null`, the token's header masked (`::add-mask::`) on the line after it is computed and GIT_TRACE, GIT_TRACE_CURL, GIT_CURL_VERBOSE, GIT_TRACE_REDACT, GIT_TRACE_PACKET, GIT_TRACE2, GIT_TRACE2_EVENT and GIT_TRACE2_PERF unset before the push (WP-83, 83a; a publish job running no repository code is WP-89); verify runs the M6 mutation gate in every run (the owner's DEC-029, WP-96) in twelve shard jobs shard-1 to shard-12 (six until WP-153) and a merge-gate job g, job m gone (WP-152): each shard job has the test job's checkout and Toolchain step, a baseline build and boot of the unmutated kernel first into a scratch root, runs TST-M6-MUTANTS's own command with --shard k/12 (k from its name, 1 to 12 each once) capped and continue-on-error, needs nothing and writes no evidence or verdict (no NAWAH_RUN_SLOT, no project.py test), and uploads its report alone as mutants-m6-shard-<k>; that exception to the slot rule is refused for a run slot, an evidence path or name, a verdict step, a baseline outside scratch, a second upload, write permission, needs, a failing step or another k; g has slot g, needs every shard job and nothing else, runs unless the run is cancelled (!cancelled(), never always()), downloads this run's mutants-m6-shard-* into build/mutants-m6-report.shards (no run-id), and runs the gate suite and no other with NAWAH_GATE_SHARDS equal to the number of shard jobs, named once in verify.yml, on that step alone, under the cap mutants.yml gives the same step, above TST-M6-MUTANTS's timeout_s; mutants.yml names neither NAWAH_GATE_SHARDS nor --shard; the report and the shard reports are uploaded with slot g and published on the run's evidence branch, the merge job naming slots a, b and g in both loops; the M5 guest suite runs in job b (slot b, WP-153) with the test job's checkout and Toolchain step, needing nothing, its images built into a scratch root first, and no other suite, job a no longer runs it, every guest suite runs in exactly one job, and outside job a every build or boot of pc-qemu writes to a scratch root; the M6 gate is counted among the suites verify runs, no other job runs it, the per-job budget is b 40 (Toolchain 15 + M5 18), shard 90 (Toolchain 15 + 60) and g 180 (15 + 135), and no stale_policy on TST-M6-MUTANTS (71 cases, OK)",
         "inputs": ["tests/test_ci_workflows.py", "tools/project.py", "tests/mutants.py", "platform/pc-qemu/target.json", "kernel/build.rs"], "input_globs": [".github/workflows/*.yml", "kernel/src/**/*.rs"]},
        {"id": "TST-M0-004", "command": ["python3", "-I", "tests/test_pre_merge.py"],
         "oracle": "tools/pre-merge.sh runs validate-records --strict under set -euo pipefail with no pipe after the validator and exits with its code: on a copy of the repository as committed it exits 0 and prints 'pre-merge: OK'; with one input of a host test edited after its run (a stale verdict) it exits 50 and prints no OK (3 cases, OK)",
         "inputs": ["tests/test_pre_merge.py", "tools/pre-merge.sh", "tools/project.py"], "input_globs": []},
        {"id": "TST-M0-005", "command": ["python3", "-I", "tests/test_mutants_harness.py"],
         "oracle": "the mutation harness counts a kill only for a real one: a mutant's build id is all hex so TST-M5-DISPLAY-BOOT's bar decodes (not `mutm94`), the per-case QEMU timeout exceeds the slowest clean case (156 s start to finish in the slowest committed TST-M5-ELEVATE run, evidence 20261109T104517Z-dece70c2-001), and run_killers stops the fairness sweep at the first FAIL while declared killers run to the end; a partial report is written as each mutant is decided; stage_of maps M129 to M5 and M130 onwards to M6, and every mutant's anchor occurs exactly once in its file; WP-45's boot-mode mutants M130 (hypervisor_present forced true), M131 (any key value is ok) and M132 (the interactive boot takes the self-test exit) are registered as SECURITY mutants of the M6 stage killed by TST-M6-INTERACTIVE-BOOT, run by the M6 gate (TST-M6-MUTANTS, WP-90), and a mutant whose declared killer boots the release image NAWAH.EFI gets that image built before its killers run; WP-67's mutant M147 (displayd's start-up hold held only for a listing naming `session`, so every LIST failure starts unheld while the trace still says locked=1) is a SECURITY mutant of the M6 stage on displayd killed by TST-M6-HOLD-FAIL-CLOSED, a case of the M6 suite on the test image, and changes the decision only, never a trace line; every stage a registered mutant maps to has exactly one gate suite running `tests/mutants.py --stage <stage>` that mutants.yml runs (a stage without a gate is an error), the M6 gate is TST-M6-MUTANTS of M6-GATE writing build/mutants-m6-report.json and no two gates share a report; reset() restores kernel/, user/, tools/, tests/ and .github/; a mutant of tools/, tests/ or .github/ is a tooling mutant that builds no image and runs its host killers only, and a kernel or user mutant builds its image before its declared killers only when one of them is a guest case, and before the fairness sweep otherwise (main() on a scratch repository: a tooling mutant, even with a guest killer, calls no build step and no guest case; a source mutant its host killers miss calls the build first); reset() fails the run when a tracked change under those trees survives it; host-suite-of and every killer run through the clean checkout's tools/project.py, never the worktree's (a worktree project.py printing OK does not judge); a host killer's FAIL is a kill only when its runner reported failing tests (unittest `FAILED (`, cargo `test result: FAILED`) and the case passes on the clean checkout, otherwise ERROR (a test file that does not compile is no kill); a guest killer's FAIL is a kill only when project.py returned 1 and printed that case's own `<id> <target>: FAIL (…) run=` line, so an internal error (rc 60) or rc 1 without the line is ERROR; the verdict needs ratio >= 0.95 over a non-empty valid set, no surviving and no invalid SECURITY mutant (a SECURITY mutant whose anchor is missing exits 1, report invalid_security); every stage of argparse's --stage has a gate; every mutant's file is an input of this case and of its stage's gate, and a tooling mutant names host killers only (WP-90, the assurance review's conditions); the killers' environment drops CARGO_TARGET_DIR, so the worktree and the clean checkout never share a build, and NAWAH_GATE_SHARDS (L-023); every killer that FAILs keeps its kill evidence before the scratch evidence is emptied (the owner's audit of WP-138): the driver's reason and run id from its verdict line and, for a guest case, the test kernel's own lines of that run's serial log, those starting `OSX|<hex id>|ktest|` (a ring-3 SYS_TRACE line carrying `|ktest|fail|` or a field in its text is not kept; serial-N.log per boot of a multi-phase case; the last 12 per boot, each cut at 600 characters; a missing log, or a run id `..` or with `/`, gives no lines), a host killer its run id and a fixed reason written by the harness, no lines, written to the mutant's report entry as `kills` and printed indented under its unchanged first line; EXPECT declares for a mutant the substrings each named killer's reason and kept lines must show (M219, M261, M262, M265, M268 on the FAT32 create fault cases; M270, M271, M272, M273, M274, M275 on TST-M3-FAT32-BPB, WP-106; M276, M277, M278, M279, M280 on TST-M3-FAT32-BAD-FIRST, WP-147; M281 on TST-M3-VMO-MAP-RIGHTS, WP-149), and a killer that did not FAIL or a missing substring (a field with another value, a timeout or another exit code even with the field and the message in the log, a failure before the case's sweep, a later mutant whose kill lacks what an earlier mutant's showed) makes the mutant `expected_missed`, named in the report and the summary line, and fails the run whatever the ratio, as does a mutant with an expectation that ends invalid (anchor gone or not building), while a mutant without EXPECT is judged as before; EXPECT naming an unregistered mutant, a killer the mutant does not declare or an empty substring list fails `--check` and the gate, naming it; the content of the expectations of M262, M265 and M268 is pinned (their killers, `exit 37`, one `|ktest|fail|` message, `|writes=8|` and `|filled=8|` on the two older create cases, `|calls=8|` on TST-M3-FAT32-FAULT-CREATE-COPIES, as for M219 and M261), every message occurring literally in kernel/src/ktest.rs and every field named in the case's pinned marker in platform/pc-qemu/target.json; the content of the expectations of M270, M272, M273, M274 and M275 on TST-M3-FAT32-BPB is pinned too (that killer alone, `exit 37`, one `|ktest|fail|` message occurring as a failure in ktest.rs, the summary's fields that differ, each a field of the case's pinned summary line with another value, and the sector lines each mutant changes, each differing from its pinned line and among the case's last ten sector lines, inside the gate's kept window), and M271's (`exit 35` and the pinned line printed before the sector total0, at which it panics); and those of M276, M277, M278, M279 and M280 on TST-M3-FAT32-BAD-FIRST (that killer alone, `exit 37`, one `|ktest|fail|` message occurring as a failure in ktest.rs and being the one that mutant reaches, and the fields of the case's one line that differ, each in the pinned line with another value: for M276 the five disk writes, the write into /HELLO.TXT's cluster and the disk-full answer, for M277 the two empty writes past the end, for M278 the empty write on the first number past the end, for M279 the empty write on the volume's last cluster number, for M280 the range error for an offset past the stored size; of the five M276 alone is a SECURITY mutant); and M281's on TST-M3-VMO-MAP-RIGHTS (WP-149, K-3: a SECURITY mutant whose anchor is the fix's line in kernel/src/syscall/mod.rs, that killer alone, `exit 37`, one `|ktest|fail|` message occurring as a failure in ktest.rs, and the two fields of the case's one line that change, write_noread=mapped and leak=1, each in the pinned line with another value); and M323's on TST-M4-CONFIG-RETRY (WP-107, RSK-028, config.md v1.3: a SECURITY mutant of the M6 stage whose anchor, once in user/apps/configd/src/main.rs, is configd's one close of the handle a request carried, that killer alone, `exit 37`, the one `|ktest|fail|` message of kept replay handles occurring as a failure in ktest.rs, and the three growths of the case's live line, body_grew=6, replays_grew=20 and unwritable_grew=2, each in the pinned line with another value); and M324's on TST-M4-SVC-CONNECT-NOREAD (WP-156, RSK-028, the services.md v1.13 note: a SECURITY mutant of the M6 stage whose anchor, once in user/apps/svcmgr/src/main.rs, is the manager's write-or-close of a service's CONNECT reply and whose replacement is the reply without the close, declared on that killer alone by `exit 37`, one `|ktest|fail|` message occurring as a failure in ktest.rs, and the two growths of the case's line, mgr_grew=3 and cfg_grew=3, each in the pinned line with another value); and M325's on TST-M4-CONFIG-STORE-AUTHZ (WP-157, RSK-028, config.md v1.4: a SECURITY mutant of the M6 stage, its anchor once in user/apps/configd/src/main.rs and its replacement the same call creating the user store whatever the token of a modifying request, declared on that killer alone by `exit 37`, its own `|ktest|fail|` message occurring as a failure in ktest.rs and fields of the case's line, other_export=OK and import_export=OK, each in the pinned line with another value; M326, which created a store for SUBSCRIBE, is retired with WP-112 and stays unregistered (config.md v1.6: SUBSCRIBE refuses every user store before it looks one up); and, not SECURITY mutants but M328, declared the same way: M327, which takes ADMIN out of the tokens a store is created for (admin_set=ERR ACCESS), and from the review round M328, SECURITY, which lets any token modify a loaded user store (loaded_other=OK 2, loaded_kept=0), M329 and M330, the bounds of the uid a store name may carry (sub_zero=ERR ACCESS; sub_big=ERR ACCESS: since v1.6 the name each lets through is a user store, which SUBSCRIBE refuses), and M331, ERR ACCESS for ERR INVALID when no slot is free (full_set=ERR ACCESS); no two of the six share message and fields); and M332's to M335's on TST-M4-NET-CLIENT-DROP (WP-108, RSK-028, net.md parts B and C: four SECURITY mutants of the M6 stage, each anchor once in user/apps/netd/src/main.rs: M332 and M333 put back the two paths that free a client's slot as they were, the slot freed and nothing else, M334 leaves the connections out of the one cleanup and M335 resets every client's connections; declared on that killer alone by `exit 37`, a `|ktest|fail|` message occurring as a failure in ktest.rs and fields of the case's line, tcp_a=OK state=ESTABLISHED and reopen=ERR EXISTS for M332, idle_reopen=ERR EXISTS for M333, tcp_a=OK state=ESTABLISHED for M334 and tcp_b=ERR CLOSED for M335, each in the pinned line with another value, no two sharing message and fields, and none resting on the echo of a datagram); and M336's to M341's on TST-M4-CONFIG-SUBS (WP-158, RSK-028, config.md v1.5: six SECURITY mutants of the M6 stage, each anchor once in user/apps/configd/src/main.rs: M336 gives every SUBSCRIBE of one client another slot, M337 leaves the subscriptions out of the one cleanup, M339 and M340 put back the two paths that free a client's slot as they were, M338 accepts SUBSCRIBE session and M341 ends the cleanup after the first store; declared on that killer alone by `exit 37`, a `|ktest|fail|` message occurring as a failure in ktest.rs and fields of the case's two lines: those that change, each in the pinned lines with another value (x_grew=9 and y_sub=ERR FULL for M336; x_gone=0, z_gone=0 and z_end_closed=0 for M337; sess_sub=OK and sess_heard=CHANGED session subs.s 1 for M338; z_gone=0 and z_end_closed=0 for M339; x_gone=0 and x_end_closed=0 for M340; x_gone=0 and x_pol_closed=0 for M341) and, for M339, M340 and M341, one that holds with its pinned value (x_gone=1; z_end_closed=1; x_end_closed=1); no two sharing message and fields, none a part of another under the same message); and M342's to M345's on TST-M6-LAUNCH-DENIED (WP-101, REQ-M6-004, services.md v1.14: each anchor once in user/apps/svcmgr/src/main.rs: M342, SECURITY, drops the check of who asks APPS or LAUNCH, M344 takes desktop out of the vouched names, M343 drops the reply to an unknown request and M345 registers an entry whatever its file is named (the case's disk carries the lab entry ZED.APP whose id is `other`); declared on that killer alone by `exit 37`, a `|ktest|fail|` message occurring as a failure in ktest.rs and the lab services' exit codes in the case's line, plain_launch=0x51 and plain_apps=0x51 for M342, unknown=0x61 for M343, desktop_launch=0x51 for M344 and session_apps=0x51 for M345, each in the pinned line with another value, no two sharing message and fields); and M346's to M361's on TST-M6-APP-SPAWN (WP-161, REQ-M6-004, services.md v1.15: each anchor once in user/apps/svcmgr/src/main.rs: M346 starts the application in the manager's own job, M347 hands it a copy of the root job, M348 leaves its job running at its exit, M349 lets a ninth run, M350 gives a number a running application carries, M354 keeps a handle it sent and M357 answers what it asks with the services' listing, and from the review round M358 leaves the place's channel set after an application closed it (the manager then waits on a closed handle and ends), M360 gives the place of an application that closed its boot channel to another and M361 reads a request carrying two handles and keeps both, those ten SECURITY; M351 ends the circle of numbers at 100, M352 and M353 keep the channel's end and the job of a launch that failed, M355 closes the boot channel on a message larger than a request, M356 keeps the job's handle after the exit and M359 keeps the manager's end of a boot channel its application closed; declared on that killer alone by `exit 37`, a `|ktest|fail|` message occurring as a failure in ktest.rs and fields of the case's one line, those that change each with another value than the pinned line's (as WP-102 re-derived them for the session's job: in_session=0, jobs=1 and orphans=1 for M346; handles=16 for M347; live_jobs=10 and orphans=1 for M348; session=0x590c for M349, session=0x5301 for M350 and session=0x5364 for M351, each with apps=0 since WP-172 (the launcher that saw another reply exits, and the session's exit ends its job); mgr_handles=27 for M352; live_jobs=11 and mgr_handles=27 for M353; mgr_handles=33 for M354; waiting=0 and handles=40 for M355; live_jobs=110 and mgr_handles=126 for M356; waiting=0 and handles=56 for M357; mgr_handles=26 for M359; live_jobs=10 and mgr_handles=27 for M360; mgr_handles=41 for M361) and those that hold beside them with the pinned value, the fields of one substring standing together in the line's order, and M358, under which the manager is gone, by the failed listing's line and message; no two sharing message and changed fields; the case's volume, its lab entries and its one manifest line are pinned with them); and M140's, M142's and M378's to M384's on TST-M6-APP-CONNECT-DENIED (WP-162, REQ-M6-004, services.md v1.16: each anchor once in user/apps/svcmgr/src/main.rs; M140 tells the service the application's identity without its app: prefix, M142 takes a name outside the allow-list for config's place, M378 grants an allowed service the entry does not declare, M381 counts no grant, M382 lets a grant replace the one before, M383 takes every entry to declare config alone and M384 keeps the client end an application could not take, those seven SECURITY, M379 grants a second connection to one service and M380 five to a service; declared on that killer alone: M142, M379, M380, M381 and M384 by `exit 37`, a `|ktest|fail|` message occurring as a failure in ktest.rs and fields of the case's one line with another value than the pinned one, M140, M378, M382 and M383, which leave that line as it is, by the case's missing markers, each a required marker of the case; no two sharing their evidence; the case's volume and its five lab entries, each with what it declares, pinned with them); and M141's, M385's to M387's and M392's to M395's on TST-M6-SESSION-JOB (WP-102, REQ-M6-004, services.md v1.17: each anchor once in user/apps/svcmgr/src/main.rs; M141 lets the session's job go unkilled, M385 makes an application's job under the root job, M386 lets any vouched service end the session, M392 every one but the desktop, M393 ends it after refusing, M395 makes a session job for each LAUNCH, those six SECURITY, M387 keeps the ended session's dead job and M394 tells two applications whatever ran; each known by exit 37, a `|ktest|fail|` message occurring as a failure in ktest.rs and fields of the case's one line with another value than the pinned one, no two sharing their evidence, M385 and M395 on TST-M6-APP-SPAWN too; the lab manifest's two roles and the case's two lab entries pinned with them; and the launch and connect pins carry the session's job in their lines); and M388's, M389's and M396's on TST-M6-LOGOUT-KILLS (WP-167, REQ-M6-004, session.md v1.8: each anchor once in user/apps/sessiond/src/main.rs; M388 sends no END_SESSION at Sign out, SECURITY, M389 traces apps=0 and M396 takes the manager's answer for a CONNECT's; M388 known by exit 37, the case's message and the counts of its phase-2 line with other values than the pinned ones, M389 by the forbidden apps=0 trace, M396 by the missing apps=2 trace with no forbidden marker present; the case's manifest, its relay and its two lab entries pinned with them); and M397's to M400's on TST-M6-JOB-BOUND (WP-164, RSK-050, syscall.md v1.15: each anchor once in its kernel file; M397 bounds no job and M398 counts every process in the root, those two SECURITY, M399 keeps a place given back and M400 gives 33; each known by exit 37, one message occurring as a failure in ktest.rs and fields of the case's count line or jobs' line with other values than the pinned ones, no two sharing their evidence; the case's manifest and its two lab entries pinned with them); and M401's to M405's on TST-M6-LAUNCH-RATE (WP-163, REQ-M6-004, services.md v1.18: each anchor once in user/apps/svcmgr/src/main.rs; M401 keeps no attempt and M405 does not count a failed launch, those two SECURITY, M402 counts a full table's refusal, M403 a refusal, and M404 answers an unknown id ERR BUSY in a full window; each known by exit 37, the case's one failure message and the session's exit code at the step it breaks, 0x5711, 0x5400, 0x5a00, 0x5900 and 0x5710, no two sharing their evidence; the limit's two constants (16 attempts in any 1000 ticks), the case's line, timeout, manifest and volume pinned with them); and M406's to M409's, M411's and M412's on TST-M6-SESSION-GATE (WP-169, REQ-M6-004, services.md v1.19: each anchor once in user/apps/svcmgr/src/main.rs: M406 answers LAUNCH with no session open, M407 lets the desktop open the gate, M408 leaves it open after END_SESSION, M409 after the session service's clean exit and M411 after an END_SESSION with no application, those five SECURITY, and M412 counts a refusal for no session as a launch attempt; each known by exit 37, one of the case's failure messages and the session's and desktop's exit codes at the step it breaks, 0x5100 with 0x5200, 0x0 with 0x5100, 0x5600, 0x0 with 0x5200, 0x5900 and 0x5300; and from WP-172 (services.md v1.20) M415, SECURITY, which leaves the session's job alive at the session service's exit (stays=1, live_jobs=2, mgr_handles=4), and M416, which kills it but keeps it (live_jobs=1, mgr_handles=1), known by the case's message for what outlived the session; no two sharing their evidence; the case's line, timeout, manifest and volume and LAUNCH-DENIED's ERR NO_SESSION pinned with them), and M410's, M413's and M414's on TST-M6-LOGOUT-KILLS (session.md v1.9, each anchor once in user/apps/sessiond/src/main.rs: M410 a sign-in that begins no session, by exit 37, the case's message for its steps and both launches refused ERR NO_SESSION; M413 a session begun at boot and M414 one begun again by Sign out, both SECURITY, by exit 37, a message of the case and the desktop's launch before the first sign-in or after the sign-out answered OK; the gate line before=ERR NO_SESSION|after=ERR NO_SESSION a required marker, a refused or unsent BEGIN_SESSION a forbidden one); and M417's to M421's on TST-M6-SESSION-RESTART (WP-173, REQ-M6-004, services.md v1.20: each anchor once in user/apps/svcmgr/src/main.rs: M417 ends the session's job only at a clean exit, M419 only at a clean exit or a stop, M420 leaves the gate open after an unclean exit and M421 knows the session by its place in the manifest, those four SECURITY, and M418 ends the job and closes its handle but keeps it; each known by exit 37, the failure message of the phase it breaks (the restart's for M417, M418, M420 and M421, the crash's for M419) and the fields of that phase's line with other values than the pinned ones: exit=0x40, stays=2, new_job=0, live_jobs=3 and mgr_handles=7 for M417; exit=0x5100, restarts=3, held=0 and the counts 0 for M418; exit=0x20000, restarts=2, stays=2, new_job=0, live_jobs=3 and mgr_handles=7 for M419; exit=0xe4, restarts=3, held=0 and the counts 0 for M420; exit=0xe4, restarts=3, held=0, stays=4, live_jobs=5 and mgr_handles=13 for M421; no two sharing their evidence; the case's lines (the restart, the crash and the stop), timeout, manifest (a lab service before the session) and volume and the role's failure trace forbidden pinned with them); and M422's to M437's on TST-M4-CONFIG-READ-LOAD (WP-112, REQ-M4-004, config.md v1.6: each anchor once in user/apps/configd/src/main.rs: M422 lets any request read and load any user store, M424 a revoked token read, M425 a read of a store no volume holds keep its slot, M427 a refused GET or EXPORT read a loaded store, M429 a refused EXPORT list one, M430 an administrator's unusable token read, M431 a refused reader be told the table is full, M432 CONFIG_WRITE read, M433 a group of that uid read and M437 SUBSCRIBE take a loaded user store, those ten SECURITY, M423 refuses the administrator, M426 lets RESOLVE load nothing, M428 answers a full table not found, M434 refuses a loaded store when the table is full, M435 loads before policy and M436 forgets the slots' generations after a read-load; each known by exit 37, one of the case's four failure messages (not loaded, read without the token, a slot taken, a full table in the way) and fields of its three lines that differ from the pinned ones (each field's name in those lines, not every value the pinned one; a line's head is no field), and M436, under which the guest passes, by the host check that finds no slot B of generation 2 and slot A no longer holding the read line; no two sharing their evidence; the case's lines, its three host checks and its volume pinned with them, and each of its three lab stores a NAWAH-CFG 1 slot whose digest covers its one line); the run's worktree holds every top-level tree of HEAD but evidence/ while the run holds its lock, a failing `worktree add` leaves nothing, and at start the worktree and temporary directory of a stopped run (under TMP_ROOT, prefix nawah-mutants-, lock not held, its directory gone or not) are removed while a live run's and every other worktree stay (WP-130; M282-M286 on tests/mutants.py); `--shard k/N` (1 <= k <= N, else refused before a run) runs the stage's mutants numbered k-1 mod N (each M6 mutant in exactly one shard for N 1..16) and writes <report stem>.shards/shard-k-of-N.json with k, N, its ids and the run's identity (CI run id, attempt and sha, else the git HEAD), and with NAWAH_GATE_SHARDS=N the gate's unchanged command runs no mutant and merges the N reports, refusing with exit 3, a named reason and no verdict or report a bad N, a missing shard, a report of another shard, run, attempt, sha or target, a selection other than the rule's, an id outside it or decided twice, a truncated shard, a shard whose report does not say it finished (written only after its run ends; M299) and a union other than the stage's, else judging the union by gate_verdict on summed counts (never the shards' ratios or verdicts) and printing every mutant's line and kept kill evidence (WP-98; M288-M295, M298, M299; M289 and M293 SECURITY, L-021); what docs/project-state.json says of the next step and of the waiting decisions is mutated on tools/project.py by M362-M377, killed by TST-M0-001 (WP-165); the gate's shard wiring in verify.yml is mutated by M300-M303, killed by TST-M0-003, M302 SECURITY, each anchor once in the file, as M189's, and the run.json note of the shard count by M304 on tools/project.py, killed by TST-M0-007 (WP-152, L-023); the Toolchain step's fallback mirror and the runner mirror's budget are mutated in mutants.yml by M305-M308, killed by TST-M0-003, each anchor once in that file; WP-153's job b, the slots' uploads of this run's directories and the merge's slots are mutated in verify.yml by M309-M315, killed by TST-M0-003, each anchor once in that file; mutants.yml's gates after the baseline alone and its refusal of a dispatch naming no gate are mutated by M316 and M317, its host suites and its job's limit by M318 and M319, its stages step's character check, its artifact of this run's directories alone and its host suites after the baseline alone by M320, M321 and M322, all killed by TST-M0-003, each anchor once in that file; a note starts with SECURITY exactly when its mutant is in the SECURITY set, both ways, every id of the set registered, and the nine authority mutants M34, M53, M62, M67, M68, M69, M70, M73 and M77 are in it (WP-95, the audit of 2026-11-16); and the oracle of every gate, TST-M2-MUTANTS to TST-M6-MUTANTS, names what its verdict enforces: the 0.95 ratio over a non-empty valid set, a surviving and an invalid SECURITY mutant, a guest killer's own FAIL verdict line, a host killer's `FAILED (` or `test result: FAILED` with the case passing on the clean checkout, ERROR never a kill, expected_missed and an EXPECT error, in the words `a kill ratio of at least 0.95 over a non-empty set of valid mutants`, `every survivor named in the report`, `no surviving or invalid SECURITY mutant`, a declared killer and the sweep, and claims none of `every seeded`, `is killed by at least one`, `written as each mutant is decided` or `decided so far` (WP-95 and its review) (104 cases, OK)",
         "inputs": ["tests/test_mutants_harness.py", "tests/mutants.py", "platform/pc-qemu/target.json", "tools/project.py", ".github/workflows/mutants.yml"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs", "tools/**/*.py", "tests/**/*.py", ".github/workflows/*.yml"]},
        {"id": "TST-M0-007", "command": ["python3", "-I", "tests/test_evidence_provenance.py"],
         "oracle": "evidence provenance and the checked import (ADR-0026): evidence-run 1.1.0 carries a closed worker enumeration, the runner's ci identity (required for verification-runner, forbidden at 1.0.0) and dirty_paths while 1.0.0 stays valid; write_run on GitHub Actions records worker=verification-runner and the run's ci identity; a run written under NAWAH_GATE_SHARDS, whatever its value, says so in run.json's notes after the caller's own note, its command unchanged, and a run without it has no note (L-023, WP-152; M304); the run's tree identity is taken once when the run begins, so the records attach_evidence writes never make it dirty; source_identity ignores evidence/, build/ and state/ and names the dirty paths as they are, spaces and non-ASCII letters included; a 1.1.0 PASS without import.json is a strict error whatever worker run.json declares, unless the evidence is native to the validating CI run (run id, attempt and sha all equal its ci identity, none empty); a present import.json is checked for every worker and verdict against its own schema (evidence-import: every field required, conclusion success, workflow verify or mutants, importer from the enumeration) and must match the run's ci identity on run id, attempt, head sha and workflow, and a malformed receipt is a named error; 1.0.0 evidence without import.json one aggregated warning; import-ci-evidence refuses a run that is not completed/success, not from verify or mutants, whose head is not an ancestor of HEAD or whose id is not <digits> or mutants-<digits> matched whole, is blocked when gh is not on PATH, skips every directory of the branch already under evidence/ whatever its identity (the branch holds the whole committed tree: older 1.0.0 directories without a ci object and directories of other runs are skipped, never checked, never given a receipt), checks out of the branch the new run directories alone, listed from its tree (WP-151, M287: a skipped directory that cannot be checked out stops nothing), refuses the whole run, writing nothing and leaving no temporary copy, when any NEW run directory's run.json carries no ci identity or a ci run id or attempt that differs from gh's answer for the run (the directory named; committed directories beside it stay untouched), and on success writes import.json (naming the importer's worker and identity) beside an untouched run.json of each new directory only; adopt-native --from <dir> (repeatable; WP-81, rule 5's native exemption) adopts a set of run directories without gh and without import.json, re-pointing their tests' verdicts as a native run does, skipping and counting every directory already under evidence/ (each job's artifact holds the whole committed tree; a skipped directory is never re-attached and is no duplicate, also when it repeats across sources) and failing closed like the validator's native rule: only with GITHUB_ACTIONS=true and GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT and GITHUB_SHA all non-empty, every NEW directory carrying a ci identity equal to them on run id, attempt and sha, every --from holding at least one run directory, no new run id repeating across the sources, and at least one new directory; off the runner or with any of the three unset, a set mixing another run, attempt or sha, a set whose sha differs from GITHUB_SHA, an environment naming another run or attempt, a new directory without ci identity, a new directory of another run next to committed ones, a duplicate, an empty set (named) or nothing new to adopt adopts nothing and leaves docs/tests.json unchanged; a set of three slots -a/-b/-c passes strict validation inside its own run, and a set mixing committed older directories (no ci identity, or another run's) with this run's slots adopts the slots alone; adopt-native and import-ci-evidence refuse, writing nothing, two new run directories of one test id (directories already under evidence/ are skipped, never compared; WP-98, M296, M297); the evaluator-outside-inputs staleness gap is not covered here (WP-66 and TST-M6-STALE-GATE are proposals of PLAN-ANSWER §1.3, not records yet) (51 cases, OK)",
         "inputs": ["tests/test_evidence_provenance.py", "tools/project.py", "docs/automation.json"], "input_globs": ["docs/schemas/*.schema.json"]},
    ],
}


HOST_SUITES["M2"] = [
    {"id": "TST-M2-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M2", "--report", "build/mutants-report.json"],
     "oracle": "seeded M2 defects (M01 to M29), declared against M1 and M2 cases: a kill ratio of at least 0.95 over a non-empty set of valid mutants, every survivor named in the report, no surviving or invalid SECURITY mutant (an anchor gone or a mutant that does not build fails the gate like a surviving one; the stage has no SECURITY mutant), no mutant expected_missed and no EXPECT error; a mutant is killed by one of its declared killers (guest or host cases) or, when they all miss and its image builds, by any guest case of the target in the sweep (all_cases: TST-M1-BOOT and every case of target.json's suites, stopping at the first FAIL), and one its declared killers miss keeps its scratch evidence under build/mutants-scratch/<id>; a kill counts only by its cause: a guest killer's FAIL only when project.py returned 1 with that case's own FAIL verdict line, a host killer's only when its runner printed its failing-tests line (unittest `FAILED (`, cargo `test result: FAILED`) and the case passes on the clean checkout, every killer judged through the clean checkout's tools/project.py on the mutated worktree (every tree of HEAD but evidence/); a missing artifact or an unknown host case is SKIPPED, a lab failure (LAB_ERROR), an internal error and anything else is ERROR, never a kill; every mutant named in stdout and in build/mutants-report.json (WP-90, WP-95)",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json"], "input_globs": ["kernel/src/**/*.rs"], "timeout_s": 6000},
]
# The M3 gate's mutation run (WP-22) is its own suite so the verify workflow's quick host suite
# M3 stays quick; the mutants workflow runs it.
HOST_SUITES["M3-GATE"] = [
    {"id": "TST-M3-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M3", "--report", "build/mutants-m3-report.json"],
     "oracle": "seeded M3 defects (scheduler, objects, syscalls, loader, MMIO window, TLB shootdown, SMP placement, virtio-blk, FAT32, VFS), declared against M3 cases, host checks included: a kill ratio of at least 0.95 over a non-empty set of valid mutants, every survivor named in the report, no surviving or invalid SECURITY mutant (an anchor gone or a mutant that does not build fails the gate like a surviving one; of the stage M34, channel_write's WRITE right, since WP-95), no mutant expected_missed and no EXPECT error; a mutant is killed by one of its declared killers (guest or host cases) or, when they all miss and its image builds, by any guest case of the target in the sweep (all_cases: TST-M1-BOOT and every case of target.json's suites, stopping at the first FAIL), and one its declared killers miss keeps its scratch evidence under build/mutants-scratch/<id>; a kill counts only by its cause: a guest killer's FAIL only when project.py returned 1 with that case's own FAIL verdict line, a host killer's only when its runner printed its failing-tests line (unittest `FAILED (`, cargo `test result: FAILED`) and the case passes on the clean checkout, every killer judged through the clean checkout's tools/project.py on the mutated worktree (every tree of HEAD but evidence/); a missing artifact or an unknown host case is SKIPPED, a lab failure (LAB_ERROR), an internal error and anything else is ERROR, never a kill; every mutant named in stdout and in build/mutants-m3-report.json (WP-90, WP-95)",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json", "tools/fat32.py"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs"], "timeout_s": 7200},
]
# The M4 gate's mutation run (WP-31): its own suite, run by the mutants workflow after M2 and
# M3-GATE; the verify workflow's quick host suite M4 stays quick.
HOST_SUITES["M4-GATE"] = [
    {"id": "TST-M4-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M4", "--report", "build/mutants-m4-report.json"],
     "oracle": "seeded M4 defects (process/wait syscalls, tokens, device objects and polling, system_info, dir_list, svcmgr ordering/timeouts/restarts/authority, authd verification and sessions, configd CAS/retry/precedence/notify/authorization, netd checksums/policy/retransmission, sh token hand-over and prompt), declared against M4 cases, console sessions included: a kill ratio of at least 0.95 over a non-empty set of valid mutants, every survivor named in the report, no surviving or invalid SECURITY mutant (an anchor gone or a mutant that does not build fails the gate like a surviving one; of the stage the authority checks M53, M62, M67, M68, M69, M70, M73 and M77, since WP-95), no mutant expected_missed and no EXPECT error; a mutant is killed by one of its declared killers (guest or host cases) or, when they all miss and its image builds, by any guest case of the target in the sweep (all_cases: TST-M1-BOOT and every case of target.json's suites, stopping at the first FAIL), and one its declared killers miss keeps its scratch evidence under build/mutants-scratch/<id>; a kill counts only by its cause: a guest killer's FAIL only when project.py returned 1 with that case's own FAIL verdict line, a host killer's only when its runner printed its failing-tests line (unittest `FAILED (`, cargo `test result: FAILED`) and the case passes on the clean checkout, every killer judged through the clean checkout's tools/project.py on the mutated worktree (every tree of HEAD but evidence/); a missing artifact or an unknown host case is SKIPPED, a lab failure (LAB_ERROR), an internal error and anything else is ERROR, never a kill; every mutant named in stdout and in build/mutants-m4-report.json (WP-90, WP-95)",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs"], "timeout_s": 10800},
]
# The M5 gate's mutation run (WP-38): M82 onwards against the M5 suite (guest cases and the host
# suites: libui's unit tests, the text conformance suites); a surviving mutant that undoes a
# security fix fails the run whatever the ratio (tests/mutants.py SECURITY).
HOST_SUITES["M5-GATE"] = [
    {"id": "TST-M5-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M5", "--report", "build/mutants-m5-report.json"],
     "oracle": "seeded M5 defects (displayd: narrator authority, client limits and the session's reserve, LIST hash and STATUS composed= of a held screen; sessiond: the password field's announcements, the elevation prompt after the keys; inputd: the name `display`; libui: password bullets; kernel: process_kill authority, kill wake-up, K1 at block, K2 at exit, frame clear on release, mouse routing; svcmgr: PONG and the watchdog's kill), declared against M5 cases, host suites included: a kill ratio of at least 0.95 over a non-empty set of valid mutants, every survivor named in the report, no surviving or invalid SECURITY mutant (an anchor gone or a mutant that does not build fails the gate like a surviving one; of the stage the SECURITY set's M5 mutants), no mutant expected_missed and no EXPECT error; a mutant is killed by one of its declared killers (guest or host cases) or, when they all miss and its image builds, by any guest case of the target in the sweep (all_cases: TST-M1-BOOT and every case of target.json's suites, stopping at the first FAIL), and one its declared killers miss keeps its scratch evidence under build/mutants-scratch/<id>; a kill counts only by its cause: a guest killer's FAIL only when project.py returned 1 with that case's own FAIL verdict line, a host killer's only when its runner printed its failing-tests line (unittest `FAILED (`, cargo `test result: FAILED`) and the case passes on the clean checkout, every killer judged through the clean checkout's tools/project.py on the mutated worktree (every tree of HEAD but evidence/); a missing artifact or an unknown host case is SKIPPED, a lab failure (LAB_ERROR), an internal error and anything else is ERROR, never a kill; every mutant named in stdout and in build/mutants-m5-report.json (WP-90, WP-95)",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs"], "timeout_s": 10800},
]
# The M6 gate's mutation run (WP-90; H2 of the 2026-11-10 assurance review): M130 onwards against
# the M6 suite, every guest case and the host suites (tooling mutants of tools/, tests/ and
# .github/ run host killers only, without an image). Time-boxed: its timeout_s ends the run with
# a verdict and the partial report before mutants.yml's step cap; a surviving SECURITY mutant
# fails the run whatever the ratio (tests/mutants.py SECURITY).
HOST_SUITES["M6-GATE"] = [
    {"id": "TST-M6-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M6", "--report", "build/mutants-m6-report.json"],
     "oracle": "seeded M6 defects (kernel: the boot-mode gate, jobs and their bound of 32 processes (M397 to M400, WP-164), config's WRITE scope, the LOAD budget, a wait's deadline beside a spinning thread, the disk's stop after a timed-out request, the order of delete, truncate and write against the directory entry, vmo_map's READ for a mapping for writing (M281, WP-149); displayd: the fail-closed hold and its boot channel, a window title's naming in the compositor's narrator lines; sessiond: the purge, and Sign out ending the session's job, the boot channel's answers matched to their requests in order (M388, M389, M396, WP-167); authd: token revocation; configd: the close of the handle every request carries, a replay's included (M323, WP-107), a user store created only for a token that may modify it, ADMIN's included, and never for a subscriber, the check of a loaded user store, the uid a store name may carry and the reply when no slot is free (M325 to M331, WP-157), a subscription owned by its client, one per client and store, gone with the client on both paths and in every store, and no session subscription without a token (M336 to M341, WP-158); svcmgr: the close of the client end when a CONNECT reply to a service cannot be written (M324, WP-156), APPS and LAUNCH answered to the vouched session and desktop alone, an unknown request on a boot channel answered and a registry entry taken under its own file's name alone (M342 to M345, WP-101), the launch: an application in a job of its own under the root job with its boot channel alone, under a number no running application carries, eight at most, refused whatever it asks, its job ended at its exit, nothing kept of a launch that failed nor of a boot channel its application closed (M346 to M361, WP-161), an application's CONNECT granted for its declared services alone, vouched as app:<id>#<n>, one to a service for an application and four for all, the client end an application cannot take closed (M140, M142, M378 to M384, WP-162), the session's applications in one job that END_SESSION from the session alone kills (M141, M385 to M387, M392 to M395, WP-102), the manifest errors and LOAD under /SYSTEM/; netd: a closed client's sockets freed and its connections reset on every path that frees its slot, and no other client's (M332 to M335, WP-108); nawah-apps: the registry parser's reserved ids; libui: pointer hit-testing, menus, confirm, the list view, a described value's escaping): a kill ratio of at least 0.95 over a non-empty set of valid mutants, every survivor named in the report, no surviving or invalid SECURITY mutant, each mutant named in stdout and in build/mutants-m6-report.json; a mutant is killed by one of its declared killers (guest or host cases) or, when they all miss and its image builds, by any guest case of the target in the sweep (all_cases); the stage includes tooling mutants (the lab tool's console-transcript check, adopt-native, the verify workflow's token permissions and merge job, the host image checker's two strict findings, the harness's own worktree without evidence/ and its removal of a stopped run's leftovers: M282 to M286, WP-130; the evidence import's staging of new run directories alone: M287, WP-151), run on host killers only without an image; a host killer's FAIL is a kill only when its runner printed its failing-tests line (unittest `FAILED (`, cargo `test result: FAILED`) and the case passes on the clean checkout, a guest killer's only when project.py returned 1 with that case's own FAIL verdict line, anything else is ERROR and never a kill; an invalid SECURITY mutant (anchor gone or not building) fails the gate like a surviving one; the verdict also needs no mutant `expected_missed` (a declared kill that does not show the substrings EXPECT names for it) and no EXPECT error; on verify the verdict is computed over the union of twelve shard jobs' reports (--shard k/12), merged by job g under NAWAH_GATE_SHARDS=12, which refuses a missing, foreign or unfinished shard; on mutants.yml over the whole run, bounded by this timeout_s; tooling mutants include the shard wiring of verify.yml (M300-M303, WP-152) and the run.json note of the shard count (M304, L-023), and the Toolchain step's fallback mirror and the runner mirror's budget (M305-M308), and job b, the slots' uploads of this run's directories and the merge's slots (M309-M315, WP-153), and mutants.yml's gates after the baseline alone, its refusal of a dispatch naming no gate, its host suites, its job's limit, its stages step's character check, its artifact and its host suites' condition (M316-M322, WP-95)",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json", "user/nawah-apps/Cargo.toml", "docs/contracts/apps.md", "platform/pc-qemu/manifests/services.txt"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs", "tools/**/*.py", "tests/**/*.py", ".github/workflows/*.yml", "platform/pc-qemu/apps/*.APP"], "timeout_s": 7800},
]

HOST_SUITES["M4"] = [
    {"id": "TST-M4-HASH-VECTORS", "command": ["cargo", "test", "--offline", "--release", "-p", "nawah-crypto", "--target", "x86_64-unknown-linux-gnu"],
     "oracle": "nawah-crypto's SHA-256 (FIPS 180-4 examples incl. the two-block message and the empty message, incremental = one-shot), HMAC-SHA-256 (RFC 4231 test cases 1, 2, 6, 7) and PBKDF2-HMAC-SHA-256 (RFC 7914 §11, 1 and 80000 iterations) known answers pass on the host (4 tests, 0 failed); the guest repeats them in the auth service (TST-M4-LOGIN)",
     "pass_marker": "test result: ok. 4 passed; 0 failed",
     "inputs": ["user/nawah-crypto/src/lib.rs", "user/nawah-crypto/Cargo.toml"], "input_globs": []},
    {"id": "TST-M4-SHELL-TOOL", "command": ["python3", "-I", "tests/test_console_session.py"],
     "oracle": "the lab's console session (ConsoleSession) against a fake shell over TCP: waits for the serial marker, splits output at the prompt, judges expect/absent/prompt/expect_serial, reports misses by step, a missing marker sends nothing (3 cases, OK)",
     "inputs": ["tests/test_console_session.py", "tools/project.py"], "input_globs": []},
]
HOST_SUITES["M5"] = [
    {"id": "TST-M5-LAB-TOOL", "command": ["python3", "-I", "tests/test_monitor_steps.py"],
     "oracle": "the lab's monitor driver (run_qemu_monitored) against a fake QEMU that writes serial markers over time and serves a monitor socket: a single-step case sends its commands once its marker appears with ${SCREEN} and ${SCREEN:tag} (screen-<tag>.ppm beside it) resolved; ordered steps are each sent once their own marker appears, in order, and a later step never fires on an earlier marker; a marker that never appears sends nothing and the run is killed at the timeout; host-check arguments take ${SERIAL:key} (last value), ${SERIAL_FIRST:key} (first value), ${EVIDENCE} (the run's directory) and ${SCREEN:tag}; key-down/key-up go through QMP on one connection kept for the run (handshake once): a key pressed in one step is released by a later step after that step's marker and within 0.5 s of it; a step with since_previous ignores its marker printed before the previous step fired; a key command with no QMP socket is reported and the run goes on, and the link reconnects after a failed connect; a case with ends_by=monitor (WP-45) ends by the lab's `quit` (QEMU status 0): every step sent and the last one ending with `quit`, while a run that ended before the last step (a guest reset is status 0 too), a last step without `quit`, a case without steps or an unknown ending is a failure; driven through cmd_boot itself on the fake QEMU (target, image preparation and records stubbed), a case ending by the monitor passes when the lab quits and fails when the guest exits 0 before the last step, in a single run and in a later phase, each phase's console failures are all reported (a later phase does not overwrite them) and a phase's own timeout_s ends that phase; a forbidden marker of the case, or of a phase in a multi-phase case, fails it when it appears only in the guest's received console transcript (named in the reason by its file) and the case passes when it is absent, and the real ConsoleSession's received transcript holds every byte read from the guest while the session runs (output after the last step or the socket's close is not checked), a guest line starting `>>> ` included (provenance, not prefix), and none of the lab's own `>>> ` lines, which stay in console.log (WP-82); a case of several phases writes console-<i>.log per phase (as serial-<i>.log), so both transcripts of a two-phase case stay on disk and a forbidden marker's reason names the file it was found in, while a single-phase case keeps console.log; when QEMU dies by a signal and the phase is retried, the retry gets its own console session, so neither the dead attempt's transcript nor its console failures judge the case; a case's or a phase's disk_files (WP-84) reach prepare_disk: a phase with its own disk_files gets a fresh disk with them, a phase without keeps the earlier phase's disk unchanged (the case's disk_files apply only when a fresh disk is built); prepare_disk's files on a real image read back by tools/fat32.py replace the volume's manifest and manager image and add a new file, no files keep the volume as built, and a missing source, an absolute or `..` source or destination, a destination with an empty or dot component, a backslash or a colon, a source that is a link out of the tree and a volume file named twice (whatever its letters' case) are refused before any image is made (23 cases, OK)",
     "inputs": ["tests/test_monitor_steps.py", "tools/project.py"], "input_globs": []},
    {"id": "TST-M5-BIDI", "command": ["python3", "-I", "tests/test_text.py", "Bidi"],
     "oracle": "nawah-text's UAX #9 reproduces every line of the Unicode conformance file BidiCharacterTest-17.0.0 (91707 lines: paragraph level, resolved levels with X9-removed characters, visual order after L2), and tables.rs is what tools/unicode_tables.py generates from the UCD files (DerivedBidiClass, DerivedJoiningType, BidiBrackets 17.0.0)",
     "inputs": ["tests/test_text.py", "tools/unicode_tables.py", "user/libnawah-text/ucd/BidiCharacterTest.txt.xz"], "input_globs": ["user/libnawah-text/src/*.rs", "user/libnawah-text/examples/*.rs", "user/libnawah-text/ucd/*.txt"]},
    {"id": "TST-M5-SHAPING", "command": ["python3", "-I", "tests/test_text.py", "Shaping"],
     "oracle": "Arabic shaping with the shipped NotoSansArabic-Regular.ttf gives the glyph ids HarfBuzz (hb-shape) gives for 4026 letter cases (every pair of 48 Arabic letters, 1500 random words, 200 phrases) and 300 cases with marks; around ZWJ and ZWNJ the forms equal HarfBuzz's for every pair of the 48 letters with each joiner (4608 cases) in the shaper and in the line layout every drawn text takes, and on 26 edge lines in both paragraph directions (a joiner first, after a space, a digit, a Latin letter, an Arabic-Indic digit (also with a mark) or an Arabic comma, a letter-joiner-Arabic-Indic digit or comma, consecutive joiners, alef-ZWJ-ZWNJ-heh, with a mark, at the end, lam-joiner-alef, tatweel, a Persian ZWNJ word) — text.md v1.1, review M6; the joining forms follow DerivedJoiningType (dual, right-joining, non-joining, join-causing, transparent); the guest sample is current; the library's mixed-direction lines (digits in Arabic, Arabic in Latin, mirrored brackets, lam-alef) pass (6 unit tests)",
     "inputs": ["tests/test_text.py", "tools/text_vectors.py", "user/apps/textprobe/src/vectors.rs", "platform/assets/fonts/NotoSansArabic-Regular.ttf"], "input_globs": ["user/libnawah-text/src/*.rs", "user/libnawah-text/examples/*.rs"]},
    {"id": "TST-M5-GLYPHS", "command": ["python3", "-I", "tests/test_text.py", "Glyphs"],
     "oracle": "the OpenType reader equals fontTools on both shipped fonts: every cmap entry (2840 + 1161 code points, absent ones .notdef), every glyph's advance and left side bearing (3748 + 1661), every glyph's outline points, on-curve flags and contour ends with composites resolved; the rasteriser against the reference in the test (same 4×4 non-zero sampling, independent contour walk and flattening) on 22 glyphs × 4 sizes: no pixel full in one and empty in the other, at most 4/16 apart on edge pixels, total ink within 1%",
     "inputs": ["tests/test_text.py", "platform/assets/fonts/NotoSans-Regular.ttf", "platform/assets/fonts/NotoSansArabic-Regular.ttf"], "input_globs": ["user/libnawah-text/src/*.rs", "user/libnawah-text/examples/*.rs"]},
    {"id": "TST-M5-UI-UNIT", "command": ["cargo", "test", "--offline", "--release", "-p", "libui", "--target", "x86_64-unknown-linux-gnu"],
     "oracle": "libui on the host (19 tests): an element without a label (or a list without items) is refused when built; the focus order is the declared order without labels; Tab/Shift+Tab cycle it, Esc cancels, presses only; the text field takes characters (Arabic too), Backspace and the cursor keys, the list moves its selection with the arrows within bounds, Space/Enter toggle the checkbox and activate buttons; the descriptions read role, label, state and value/item exactly; ui.scale/ui.contrast map to the theme; 2x doubles every rectangle and the largest dialog fits one surface VMO; painting uses the theme's background and focus colours; v1.1 (WP-37): the password field edits like a text field, is described by role, label and state without its value, is drawn as one bullet per character (pixel-equal to a field of bullets, unlike the characters), and the application reads, wipes (zeroed slots) and sets values and moves the focus only where it can go; v1.2 (WP-39): in a right-to-left field Left and Right swap direction (set_rtl flips it live), and relabel/set_items switch an element's language in place with the selection clamped and bad arguments refused; v1.3 (WP-41): a value element shows text the application sets, is never focused, is described with its value as static and keeps at most TEXT_MAX (48) characters, and a password is never filled by the application; v1.5 (WP-38): Painter::fits measures a label or value through the painter's own line layout (font size, direction) against its row and refuses the 15+1+32 W prompt and config SET device MMMMMMMM 0 901 off but keeps the lab's requests (lab.elev, lab.elev7, lab.elev8), in both directions and at 2x, and never fits more than TEXT_MAX characters; (v1.9, WP-94) a described value cannot forge its line: a typed quote and a set value with a newline, a line or paragraph separator, a control character or a bidi formatting character are written [U+XXXX] (one line, four quotes), a value that fits the 256-byte line exactly is written whole, one that does not is cut in order at a whole character or escape, closed, and marked ` cut=<k>` with the number of characters left out, and values without those characters read as before (19 passed)",
     "pass_marker": "test result: ok. 19 passed; 0 failed",
     "inputs": ["user/libui/Cargo.toml"], "input_globs": ["user/libui/src/*.rs", "user/libui/tests/*.rs", "user/libnawah-text/src/*.rs"]},
    {"id": "TST-M5-UI-TOOL", "command": ["python3", "-I", "tests/test_transcript_tool.py"],
     "oracle": "tools/transcript.py takes the narrator lines from trace lines and requires them to equal the expected file exactly in every serial log (a missing, extra or reordered line, or one bad phase, fails); dims accepts only the same origin with the size times the factor; streams (WP-37) checks every stream the file names exactly and in order whatever the interleaving, ignores other streams and non-user lines, and checks every phase (7 cases, OK)",
     "inputs": ["tests/test_transcript_tool.py", "tools/transcript.py"], "input_globs": []},
    {"id": "TST-M5-SCREEN-TOOL", "command": ["python3", "-I", "tests/test_screen_tool.py"],
     "oracle": "tools/screen.py desktop against a synthetic PPM: a pixel check passes on its colour and fails on another; a window hash equals the FNV-1a 64 of the rectangle's R,G,B bytes and fails when a pixel differs; a rectangle outside the image fails without crashing; an ink check finds a field's text against the side asked and fails for the other side, an empty field and a rectangle outside the image (3 cases, OK)",
     "inputs": ["tests/test_screen_tool.py", "tools/screen.py"], "input_globs": []},
]
HOST_SUITES["M3"] = [
    {"id": "TST-M3-FAT32-TOOL", "command": ["python3", "-I", "tests/test_fat32_tool.py"],
     "oracle": "the host FAT32 tool formats the lab volume (128992 clusters, 44 used), lists DIR/HELLO.TXT/PATTERN.BIN, reads files back exactly (cat/verify/expect), keeps the raw pattern tail, makes nested directories in their parent (SYSTEM/FONTS, a missing parent refused), and fsck.fat -n accepts the images; and (WP-105) its `check` is the judge of the images guest cases leave: on images corrupted by the test, a name whose chain runs into a free cluster and two names on one cluster are problems with and without --faulted, a cluster free in the second FAT copy alone is a problem with --faulted, a lost cluster and FAT copies that differ are problems without --faulted and counted with it, a chain longer than its size is a problem unless --faulted --allow-longer N names the exact number of them, and --expect-lost K the exact number of lost clusters (one more or one fewer is a problem), a directory whose chain runs into a free cluster and two directories on one cluster are problems, broken FSInfo signatures are a problem, a tree ten levels deep is healthy and one past the walk's limit (128) is named so and not called lost; fsck.fat's messages are named one by one (lost clusters, the free count and differing copies allowed; shared clusters, a free cluster in a chain, a chain shorter or longer than its size failing; a line with no name, or a path line that says more than a path, unnamed), and `fsck-faulted` accepts an image with a lost cluster and refuses one with a free cluster in a chain, and takes chains longer than their size only in the exact number given; and (WP-126), each with and without --faulted: an entry whose first cluster is no cluster of the volume is a named problem (for a directory 0, 1, an end mark and the first number past the volume, and 0 under attributes that are a directory's and more; for a file 1, an end mark and the first number past the volume, whatever its size), while an empty file, whose first cluster is 0, is healthy; the reserved value 1, a reserved number, the first number past the volume and the bad-cluster mark in a chain name the file or the directory along whichever FAT copy holds them; and a reserved or out-of-range value outside every chain is a problem in the second copy and in the first (1, two reserved values, the first number past the volume, at a free cluster and at the volume's last entry); and (WP-127), with --faulted: the files whose chain is longer than their size are named with their extra clusters (--expect-longer), so two images with the same counts, one the state a case expects and one another, get opposite verdicts, and each copy is judged by its own pin; a chain longer than its size along the second FAT copy alone is a problem unless --expect-longer-second names it; clusters marked in the second copy alone are counted on the line and pinned by --expect-lost-second; the clusters lost in both copies are pinned by --expect-lost-both, so one cluster marked in each copy alone does not pass for one lost in both; the three numbers of the lost clusters are given together, --allow-longer with --expect-longer and --expect-longer with --expect-longer-second, or the call is refused (exit 2), while --expect-longer-second alone is taken and leaves the first copy with no longer file allowed; each copy's longer files are compared with that copy's pin (one file longer in each copy alone, and two in the second alone against --allow-longer); two names are met in any order, and one file whose name holds a comma and `:+` is not read as two; a name reached along one copy only, whichever copy it is, is a problem with and without --faulted; a pin on the second copy of a volume with one FAT copy is a problem; a chain that loops is named; and `check` on a file that takes every free cluster of the volume ends within 30 s; 38 cases",
     "inputs": ["tests/test_fat32_tool.py", "tools/fat32.py"], "input_globs": []},
]
# M6's first host case (WP-45, PLAN-ANSWER §2.5 D3: a host suite comes with its first case,
# never empty): the system manifest and the self-test manifest linted against services.md §2.
HOST_SUITES["M6"] = [
    {"id": "TST-M6-MANIFEST-LINT", "command": ["python3", "-I", "tests/test_m6_manifest.py"],
     "oracle": "a host lint of platform/pc-qemu/manifests/services.txt (services.md v1.11) and the lab manifest selftest.txt, read as svcmgr's parser reads them (user/apps/svcmgr/src/main.rs load and Fields: lines split on newline only, each cut at its first `#`, fields split on spaces only; only bytes 0x20-0x7E and newline, a Tab, a CR or any other byte refused by name): the system manifest is ASCII and parses by services.md §2 (fields, restart policy, decimal numbers, watchdog= before arg, an arg of at most 64 bytes, names of [A-Za-z0-9_-] up to 15 bytes, no duplicate, at most 16 services) and is under MANIFEST_MAX (4096 bytes); by the table of services.md §0.000 it names exactly auth, config, net, input, display, narrator, session, sh in that order, each with exactly the table's dependencies, every one declared on an earlier line, each on-failure, with a readiness timeout no shorter than 60000 for auth and 30000 for session, and watchdog= on input and display; every image path is /SYSTEM/<8.3 name>.ELF of an application the build makes (target.json extra_artifacts); watchdog= only on a service whose source sends PONG through channel_write (a textual check: whether that write answers the manager's PING is not checked, the guest case TST-M5-LOCK-HANG is; a compare with PONG, as in svcmgr, does not count); selftest.txt is ASCII, has no service line and its comment names mode=selftest; the lint itself rejects one manifest per rule: a non-ASCII byte, 4096 bytes or more, never instead of on-failure, a timeout below the minimum (auth, session), session without config, a dependency set other than the table's (narrator, sh), no watchdog on input or display, a self-test manifest with a service or without mode=selftest, a line of 6 fields, a non-decimal watchdog, an arg over 64 bytes, a bad name, an unknown restart policy, a non-decimal number, more than 16 services, a service missing, two services swapped, a dependency on a later line, a duplicate, a watchdog on a service that never answers PONG, a non-8.3 image, an image the build does not make, a Tab, a CRLF line end, a control byte, and a `#` inside a line that cuts a field or a watchdog= (while a trailing comment longer than an arg is accepted, as svcmgr accepts it) (20 cases, OK)",
     "inputs": ["tests/test_m6_manifest.py", "platform/pc-qemu/target.json"], "input_globs": ["platform/pc-qemu/manifests/*.txt", "user/apps/*/src/main.rs"]},
    {"id": "TST-M6-UI-UNIT", "command": ["cargo", "test", "--offline", "--release", "-p", "libui", "--target", "x86_64-unknown-linux-gnu", "--test", "pointer_menu"],
     "oracle": "libui v1.6 (WP-49, ui.md §3.6) on the host, user/libui/tests/pointer_menu.rs (9 tests): a left press focuses the focusable element under it (a label never; the rectangle's last column is inside and the next is not) and the release over the same element activates a button or toggles a checkbox, a release elsewhere or without a press does nothing and holding is not a new press; a list row press selects the row, the header selects nothing, and a second click on the same row within DOUBLE_CLICK_MS (400, nawah's own) activates the list while a later one, another row or the header does not; the focus order and Tab/Shift+Tab are unchanged after pointer use; the context menu (at most 8 entries, an unlabelled item or separators only refused) opens by Shift+F10, the menu key 0xdd and a right press on a focusable element (not a label, not by F10 alone; without a menu none of the three opens anything and the right press does not move the focus) with its first item focused and the dialog focus empty; Up/Down wrap over separators, a disabled item is focused and described disabled but never chosen by Enter or a left release, Enter or a left release on the pressed item chooses, closes and returns the focus; Tab is ignored while open, Esc closes the menu without cancelling the dialog and an outside press closes it, both returning the focus to the opener; the menu opens from the start edge and toward the reading direction in LTR and RTL, flips at the surface's edge, stays inside the surface, which grows to hold it and still fits one VMO at 2x; menu items are described role=menuitem label=\"...\" state=focused[,disabled] index=k/n, and describe_menu_item returns None and writes nothing with no menu or an entry out of range (9 passed)",
     "pass_marker": "test result: ok. 9 passed; 0 failed",
     "inputs": ["user/libui/Cargo.toml", "user/libui/tests/pointer_menu.rs"], "input_globs": ["user/libui/src/*.rs", "user/libnawah-text/src/*.rs"]},
    {"id": "TST-M6-UI-CONFIRM", "command": ["cargo", "test", "--offline", "--release", "-p", "libui", "--target", "x86_64-unknown-linux-gnu", "--test", "confirm"],
     "oracle": "libui v1.7 (WP-80, ui.md §3.7) on the host, user/libui/tests/confirm.rs (5 tests): Dialog::confirm(prompt, yes, no, cancel, default) on an empty dialog builds the prompt label (element 0) and three buttons (1 yes, 2 no, 3 cancel), refuses a blank prompt or label (NoLabel, nothing built), a non-empty dialog and any later element (Confirm), and drops a menu set before it (menu_len() 0, set_menu false after); the default button takes the first focus and start() returns to it; Enter or Space answers the focused button (Activate and answer()), also while a left press is held on it, Esc answers Cancel (Event::Cancel, answer() = Cancel) whatever has the focus, the default Yes included; Tab/Shift+Tab cycle only the three buttons; characters, arrows, Backspace, Shift+F10 and the menu key do nothing and set_menu is refused; an answer is final (later keys and clicks return None and leave it); the narrator strings are exactly confirm role=dialog label=\"<prompt>\", focus <default button description>, answer yes|no|cancel, in English and in Arabic (the tokens English), and a plain dialog writes no confirm line and has no answer; the layout is the column: the prompt's row then each button a full row, yes-no-cancel from the top, every row its own mirror so RTL equals LTR (also after set_rtl) and Tab order stays logical; the prompt fits its row (Painter::fits) and every button label is narrower than its button (Painter::text_width) in English and Arabic at 1x and 2x; text_width agrees with fits (the prompt at most 241 px at 1x, a longer question over 241 and not fitting), gives the exact 1x widths (English prompt 184 and widest label 128, Arabic 218 and 79), about double at 2x, every label above 0, and measures as many characters as paint draws (TEXT_PAINT 64: 64 characters wider than 49, 70 the same as 64); a left press and release on a button answers it through the v1.6 pointer path, a release elsewhere answers nothing and gives the focus back to what it was before the press only if the press moved it and it is still on the pressed button (Tab to Cancel, press Cancel, release elsewhere keeps Cancel; press No from Cancel, release elsewhere returns to Cancel; a Tab while held stands), so the next Enter never answers a button only pressed, a click on the prompt and a right click answer nothing (5 passed)",
     "pass_marker": "test result: ok. 5 passed; 0 failed",
     "inputs": ["user/libui/Cargo.toml", "user/libui/tests/confirm.rs", "platform/assets/fonts/NotoSans-Regular.ttf", "platform/assets/fonts/NotoSansArabic-Regular.ttf"], "input_globs": ["user/libui/src/*.rs", "user/libnawah-text/src/*.rs"]},
    {"id": "TST-M6-LISTVIEW-UNIT", "command": ["cargo", "test", "--offline", "--release", "-p", "libui", "--target", "x86_64-unknown-linux-gnu", "--test", "listview"],
     "oracle": "libui v1.8 (WP-50 50a, ui.md §3.8) on the host, user/libui/tests/listview.rs (11 tests): the list view asks the application's RowSource for no position or row id at or beyond rows() with 0, 1 and 10,000 rows (every key and type-ahead do nothing at 0 rows; End shows rows 9990-9999 of ten visible; 1,200 Shift+PgDn keep top+count <= rows and select all 10,000), and refuses MAX_ROWS+1 rows keeping its own and its focus, while exactly MAX_ROWS are taken (End focuses and selects id 16383); Home/End/PgUp/PgDn/Up/Down move to the exact positions with a page of visible rows less one and the first visible row follows, a key release does nothing, Enter activates the focused row by its id in the application's order; stable_sort keeps equal keys in order both ways and returns false leaving the ids untouched when its scratch is short, and a sort the application reports undone (false) is neither announced (ListEvent::None) nor described, Ctrl+2 sorts by the second column ascending then descending (Ctrl+9 without such a column nothing; MAX_COLUMNS 8) and the selected ids, the focused id and Enter's id stay the same rows while their positions change, and the description ends sort=\"<column>\" ascending|descending; the anchor stays on its row across a sort (Shift+Down after it selects ids 3 and 4); reset and deny end the sort and set the current column back to the first, so no sort= is described for rows nothing sorted; a plain move selects the focused row alone, Shift ranges from the anchor, Ctrl moves the focus only, Ctrl+Space toggles and sets the anchor (a later Shift ranges from it), Space selects the focused row alone (also out of several; nothing when already alone), select count=<m>; a single-selection list treats Shift and Ctrl as plain; selection is by row id in a reversed order and a reset clears it; type-ahead: a repeated letter cycles (case-folded), a pause over TYPEAHEAD_MS (1000, nawah's own) starts anew while exactly 1000 still extends (b then l at +1000 finds blue), characters past TYPEAHEAD_MAX (16) are dropped, a longer prefix searches from the focused row wrapping, Arabic prefixes match, a typed move sets the anchor, a space (KEY_SPACE) selects and never enters the search, no match moves nothing, Ctrl+letter is not type-ahead, typing never activates and selects the row alone, the search is in the current column; the narrator lines exactly: role=list label=\"...\" rows=<n> columns=<c>, row <k>/<n> state=focused|selected|focused,selected|enabled with \"<column>\"=\"<value>\" pairs in English and Arabic (n all rows: row 500/500), a column the 256-byte line cannot hold whole (also a value longer than the buffer, and a 222-byte name that would leave no room for more=) left out and counted as more=<j>, never half a value; Text::put cuts at a UTF-8 character boundary (two-, three- and four-byte characters) so every line is valid UTF-8; state=empty for no rows and state=denied reason=\"<sentence>\" (never empty) after deny, with no rows, no selection and keys doing nothing until a reset; blank labels, blank column names, no columns and MAX_COLUMNS+1 columns refused (exactly 8 taken); the header rectangles from the left edge in LTR and mirrored from the right in RTL (also after set_rtl, and doubled at 2x), text at the reading start and numbers at the trailing edge, Left/Right move the current column visually; explicit bidi formatting characters in a cell (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069) and control characters (U+0000-U+001F, U+007F-U+009F, U+2028, U+2029) are written [U+XXXX] in the line and drawn as U+FFFD, so a name keeps level 0 in LTR and never starts a second line, and a quote in a value is written [U+0022] so it cannot end the value and forge a column (drawn as itself); the focused row stays visible (top <= focus < top+count <= rows) after every move, type-ahead, sort, set_area and set_theme (focus 9: a 3-row area shows 7-9, then 2x shows 9 alone), a page is at least one row even in an area shorter than the header, and 0 rows give (0, 0) (11 passed)",
     "pass_marker": "test result: ok. 11 passed; 0 failed",
     "inputs": ["user/libui/Cargo.toml", "user/libui/tests/listview.rs"], "input_globs": ["user/libui/src/*.rs", "user/libnawah-text/src/*.rs"]},
    # WP-100 (apps.md v1, ADR-0023 proposed): the application registry's entry parser, a
    # seeded fuzz on the host; the manager that will use it is WP-101's.
    {"id": "TST-M6-APP-REGISTRY-FUZZ", "command": ["cargo", "test", "--offline", "--release", "-p", "nawah-apps", "--target", "x86_64-unknown-linux-gnu", "--test", "registry"],
     "oracle": "apps.md v1 (WP-100, ADR-0023 proposed) on the host, user/nawah-apps/tests/registry.rs (9 tests): the registry entry parser refuses 143 hand-written malformed entries each by its contract name (TOO_LARGE, TRUNCATED, BAD_UTF8, CONTROL_BYTE incl. CR and CRLF, SYNTAX, UNKNOWN_KEY, DUP_KEY, MISSING_KEY incl. a missing ELF path, BAD_ID, RESERVED_ID, BAD_ELF, BAD_DEPS, DEP_NOT_ALLOWED for auth, session, input, narrator and sh, and BAD_NAME for a name over 32 bytes (33 Latin bytes, 17 Arabic letters, 16 Arabic letters and a space), for 20 code points apps.md §2 forbids anywhere (the C1 range U+0080-U+009F by its two ends alone, and each of U+061C, U+200B-U+200F, U+2028, U+2029, U+202A-U+202E, U+2066-U+2069, U+FEFF) and for each of the 17 white spaces it forbids at either end), and a seeded deterministic corpus of 2000 rounds of generated malformed entries in 14 classes (a round whose random base id is reserved is skipped) each by its named error; 30000 seeded mutations of well-formed entries never panic and get exactly the verdict and fields of a reference model of apps.md written in the test with its own literal lists (more than 100 accepted and 10000 refused); the reserved ids and the allowed dependencies listed in apps.md §3 equal the crate's RESERVED and ALLOWED_DEPS and the model's lists in both directions, and the names of apps.md §5's table equal the Error enum's, checked by a match without a wildcard; the well-formed examples (no dependency, every allowed dependency, the 8-byte id, a 32-byte Latin name, a 16-letter Arabic name of 32 bytes, inner white space, comments, blank lines, keys in any order, a file of exactly 1024 bytes) and the samples platform/pc-qemu/apps/*.APP are accepted with their fields exactly; the registry refuses a repeated id (DUP_ID), a 17th entry (TOO_MANY) and a file not named <ID>.APP (FILE_NAME) and a refused entry changes nothing; every service of platform/pc-qemu/manifests/services.txt is a reserved id",
     "pass_marker": "test result: ok. 9 passed; 0 failed",
     "inputs": ["user/nawah-apps/Cargo.toml", "user/nawah-apps/tests/registry.rs", "platform/pc-qemu/manifests/services.txt", "docs/contracts/apps.md"], "input_globs": ["user/nawah-apps/src/*.rs", "platform/pc-qemu/apps/*.APP"]},
]
HOST_SUITES["M1"] = [
    {"id": "TST-M1-NOBS", "command": ["python3", "-I", "tests/test_m1_nobs.py"],
     "oracle": "static: kmain.rs is safe-only (no unsafe allowed by main.rs), names no firmware table/efi symbol; boot::efi is private; BootInfo carries no function pointers; kernel_main takes &BootInfo only",
     "inputs": ["tests/test_m1_nobs.py", "kernel/src/main.rs", "kernel/src/kmain.rs", "kernel/src/bootinfo.rs", "kernel/src/boot/mod.rs", "kernel/src/boot/stub.rs"], "input_globs": []},
]


def oracle_candidates():
    """(test id, oracle, where) for every text the runner writes into verdict.json: HOST_SUITES,
    each target.json suite case, a target's boot_oracle when no suite case of that target carries
    its id (a shadowed boot_oracle is never run: cmd_boot), every target's build (BUILD_ORACLE)."""
    for suite, cases in HOST_SUITES.items():
        for c in cases:
            yield c["id"], c["oracle"], f"HOST_SUITES[{suite}]"
    for tp in sorted((ROOT / "platform").glob("*/target.json")):
        t, where = load_json(tp), tp.relative_to(ROOT).as_posix()
        ids = set()
        for cases in t.get("suites", {}).values():
            for c in cases:
                if c.get("oracle"):
                    ids.add(c["test_id"]); yield c["test_id"], c["oracle"], where
        b = t.get("boot_oracle") or {}
        if b.get("oracle") and b["test_id"] not in ids:
            yield b["test_id"], b["oracle"], f"{where} boot_oracle"
        if t.get("build", {}).get("test_id"):
            yield t["build"]["test_id"], BUILD_ORACLE, f"{where} build"


def oracle_conflicts():
    """{test id: [where, ...]} for each id two sources give different texts."""
    seen, out = {}, {}
    for tid, oracle, where in oracle_candidates():
        seen.setdefault(tid, []).append((oracle, where))
    for tid, texts in seen.items():
        if len({o for o, _ in texts}) > 1:
            out[tid] = [w for _, w in texts]
    return out


def oracle_sources():
    """{test id: oracle} from oracle_candidates(); docs/tests.json keeps a copy of each for
    reading, checked by validate-records (WP-92). Ids with two different texts are reported
    by oracle_conflicts() and left out here, so nothing is synced from either."""
    conflicts = oracle_conflicts()
    return {tid: o for tid, o, _ in oracle_candidates() if tid not in conflicts}


def oracle_differences(tests):
    """[(record, source oracle)] for each test record whose `oracle` is not its source's text.
    Records without a source are not compared; dated notes live in `oracle_notes`, never here."""
    src = oracle_sources()
    return [(t, src[t["id"]]) for t in tests if t["id"] in src and t["oracle"] != src[t["id"]]]


def cmd_sync_oracles(check=False) -> int:
    """Write each record's oracle from its source (WP-92); --check writes nothing and exits
    E_VALIDATION when any record differs."""
    conflicts = oracle_conflicts()
    for tid, where in conflicts.items():
        print(f"two sources with different texts: {tid} ({', '.join(where)}); make them one")
    if conflicts:
        return E_VALIDATION
    path = DOCS / "tests.json"
    data = load_json(path)
    diffs = oracle_differences(data["records"])
    for t, oracle in diffs:
        print(f"{'differs' if check else 'synced'}: {t['id']}")
        t["oracle"] = oracle
    if check:
        return E_VALIDATION if diffs else E_OK
    if diffs:
        write_json(path, data)
    print(f"sync-oracles: {len(diffs)} record(s) {'rewritten' if diffs else 'already equal to their source'}")
    return E_OK

def cmd_test_host(suite, only=None) -> int:
    begin_run()
    if suite not in HOST_SUITES:
        print(f"host suite {suite} is not implemented; implemented: {sorted(HOST_SUITES)}"); return E_INTERNAL
    cases = HOST_SUITES[suite]
    if only:
        wanted = set(only)
        cases = [c for c in cases if c["id"] in wanted]
        missing = wanted - {c["id"] for c in cases}
        if missing:
            print(f"unknown case ids for host suite {suite}: {sorted(missing)}"); return E_INTERNAL
    rc_all = 0
    for case in cases:
        rc_all |= cmd_test_host_case(case)
    print(f"host suite {suite}: {'PASS' if rc_all == 0 else 'FAIL'}")
    return rc_all


def cmd_test_host_case(case) -> int:
    if True:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        rid, d = new_run_dir("host-test")
        rc = run_logged(case["command"], ROOT, d / "stdout.log", d / "stderr.log", case.get("timeout_s", 900))
        write_run(d, rid, "host", f"test:{case['id']}", [" ".join(case["command"])], rc, started)
        inputs = digests_for(case["inputs"], case.get("input_globs", ()))
        out = (d / "stdout.log").read_text(errors="replace") + (d / "stderr.log").read_text(errors="replace")
        # unittest prints "OK" on its own line; a cargo test case names its own marker.
        marker = case.get("pass_marker", "\nOK")
        verdict = "PASS" if rc == 0 and marker in out else ("ERROR" if rc == 124 or env_failed(rc, out) else "FAIL")
        write_verdict(d, rid, case["id"], verdict, case["oracle"], f"exit 0 + {marker.strip()!r}", f"exit={rc}; tail={out.strip().splitlines()[-1] if out.strip() else ''}", inputs)
        print(f"{case['id']}: {verdict} run={rid}")
        attach_evidence(case["id"], rid, verdict)
        return 0 if verdict == "PASS" else 1


def replace_evidence_ref(old_ref, new_ref, test_id, verdict):
    """Set the test's verdict and evidence, and re-point requirement/work-item/stage records that
    cited any earlier run directory of this test — not only its immediately previous one (CI run
    40213361352: done items citing an older run of the same test stayed on it and failed
    --strict). A ref is only re-pointed when it is a run directory whose verdict belongs to this
    very test — several tests may share a plain-file ref (e.g. a CI jobs.json) and that must
    never be rewritten on behalf of one of them. A record left citing the new run twice keeps
    one."""
    own_cache = {}

    def own(ref):
        if ref not in own_cache:
            try:
                op = safe_rel(ref)
                own_cache[ref] = op.is_dir() and (op / "verdict.json").exists() and load_json(op / "verdict.json")["test_id"] == test_id
            except (ValueError, json.JSONDecodeError, KeyError):
                own_cache[ref] = False
        return own_cache[ref]

    def repoint(refs):
        out = []
        for x in refs:
            y = new_ref if x != new_ref and own(x) else x
            if not (y == new_ref and new_ref in out):
                out.append(y)
        return out

    for name in RECORD_FILES:
        p = DOCS / f"{name}.json"
        if not p.exists():
            continue
        data = load_json(p); changed = False
        for r in data["records"]:
            if name == "tests":
                if r["id"] == test_id:
                    r["verdict"] = verdict
                    r["evidence_refs"] = [new_ref]
                    changed = True
                continue
            for key in ("evidence_refs", "gate_evidence_refs"):
                if key in r:
                    new = repoint(r[key])
                    if new != r[key]:
                        r[key] = new; changed = True
        if changed:
            write_json(p, data)


def attach_evidence(test_id, rid, verdict):
    """Registry update: the test's previous evidence ref is replaced everywhere by the new run."""
    if SCRATCH:
        return
    tests_p = DOCS / "tests.json"
    if not tests_p.exists():
        return
    old_refs = [t["evidence_refs"] for t in load_json(tests_p)["records"] if t["id"] == test_id]
    if not old_refs:
        return
    old_ref = old_refs[0][0] if old_refs[0] else None
    replace_evidence_ref(old_ref, f"evidence/{rid}", test_id, verdict)


def cmd_reverify_host() -> int:
    """Re-run every host suite case and re-attach fresh evidence (used after tool changes make verdicts stale)."""
    tests = {t["id"]: t for t in load_json(DOCS / "tests.json")["records"]} if (DOCS / "tests.json").exists() else {}
    rc_all = 0
    for suite in HOST_SUITES:
        for case in HOST_SUITES[suite]:
            rc = cmd_test_host_case(case)
            rc_all |= rc
    return rc_all


def cmd_test(target_name, suite, only=None) -> int:
    begin_run()
    if target_name == "host":
        return cmd_test_host(suite, only)
    t = load_target(target_name)
    suites = t.get("suites", {})
    if suite not in suites:
        print(f"suite {suite} is not implemented for target {target_name}; implemented: {sorted(suites)}"); return E_INTERNAL
    cases = suites[suite]
    if only:
        wanted = set(only)
        cases = [c for c in cases if c["id"] in wanted]
        missing = wanted - {c["id"] for c in cases}
        if missing:
            print(f"unknown case ids for suite {suite}: {sorted(missing)}"); return E_INTERNAL
    rc_all = 0
    for case in cases:
        rc = cmd_boot(target_name, suite_case=case)
        rc_all |= rc
    print(f"suite {suite}: {'PASS' if rc_all == 0 else 'FAIL'}")
    return 0 if rc_all == 0 else 1


# ----------------------------------------------------------------------------- checkpoint / events
def append_event(etype, state, task_id=None, run_id=None, result=None, evidence_ref=None, operation_id=None, inputs_digest=None):
    ps = load_json(DOCS / "project-state.json")
    ev = {"schema_version": SCHEMA_VERSION, "project_id": ps["project_id"], "run_id": run_id, "operation_id": operation_id or f"op-{int(time.time())}",
          "task_id": task_id, "seq": ps["event_sequence"] + 1, "type": etype, "inputs_digest": inputs_digest, "state": state,
          "result": result, "evidence_ref": evidence_ref, "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
          "fencing_token": (ps.get("lease") or {}).get("fencing_token", 0)}
    p = EVIDENCE / "automation" / "events.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return ev["seq"]


# The owner's order of work is written in one place (WP-165): item 5 of section 7 of this file.
ORDER_POLICY = DOCS / "policies" / "team-methodology.md"
NO_NEXT_STEP = ("no next step: every item of the owner's order (docs/policies/team-methodology.md, section 7, item 5) "
                "is done, or no order is written")


def plan_order(text):
    """The owner's order of work as the methodology writes it: the work item ids of item 5 of
    section 7 (`5. **الترتيب:** ...`), in the order they stand on that line. None when the
    section or the item is not found, or the item names no work item."""
    in_section = False
    for line in text.splitlines():
        if line.startswith("## "):
            in_section = line.startswith("## 7.")
        elif in_section and re.match(r"5\.\s+\*\*الترتيب:\*\*", line):
            return re.findall(r"WP-\d+", line) or None
    return None


def read_plan_order():
    """`plan_order` of the methodology file; None when the file cannot be read."""
    try:
        return plan_order(ORDER_POLICY.read_text(encoding="utf-8"))
    except OSError:
        return None


def open_decisions(decisions):
    """The decisions that wait for the owner: those whose record says `open`, in the file's order."""
    return [d["id"] for d in decisions if d["status"] == "open"]


def next_in_order(by_id, order):
    """The next step of `order`: its first item that is not done, or, while that item waits for a
    dependency, the first dependency that is not done, looked at the same way. A superseded item
    stands for the item that took its place. An id the records do not hold is passed over
    (validate-records names it). A path that comes back to an item it passed (a cycle, which
    validate-records reports) ends at the item before. None when every item of the order is done."""
    def standing(w):
        seen = set()
        while w is not None and w["status"] == "superseded" and w["id"] not in seen:
            seen.add(w["id"]); w = by_id.get(w.get("superseded_by"))
        return w
    unfinished = lambda w: w is not None and w["status"] != "done"
    for wid in order:
        w, path = standing(by_id.get(wid)), set()
        while unfinished(w):
            path.add(w["id"])
            dep = next((d for d in (standing(by_id.get(i)) for i in w["depends_on"]) if unfinished(d)), None)
            if dep is None or dep["id"] in path:
                return w
            w = dep
    return None


def step_text(task):
    """What the state file says of the step: its id and its first action; a blocked item says so,
    and by what."""
    head = f"blocked ({task['blocker']}): " if task["status"] == "blocked" else ""
    return f"{task['id']}: {head}{task['actions'][0] if task['actions'] else '(no action is written)'}"


def derive_position(work_items, requirements, order=None):
    """Where the project stands, from the records and the owner's order: the current task is the
    first active work item, else the next step of `order` (`next_in_order`); its stage is the
    current stage; completed requirements are those verified in scope. The file's order is not
    a plan: without an order, or with all of it done, there is no next step, and the text says
    so. (Review 2026-10-19, T-8: checkpoints never updated these fields. WP-165, the owner's
    note of 2026-11-19: the first ready item of the file, WP-69, was written as the next step at
    two closes while the order named another.)"""
    by_id = {w["id"]: w for w in work_items}
    task = next((w for w in work_items if w["status"] == "active"), None)
    if task is None:
        task = next_in_order(by_id, order or [])
    done = [r["id"] for r in requirements if r["implementation_status"] == "verified_in_scope"]
    return {
        "current_task": task["id"] if task else None,
        "current_stage": task["stage"] if task else None,
        "next_action": step_text(task) if task else NO_NEXT_STEP,
        "completed_requirement_ids": done,
    }


def cmd_checkpoint(note=None) -> int:
    rc = validate_records(verbose=False)
    if rc != 0:
        print("checkpoint refused: records invalid (run validate-records)"); return E_VALIDATION
    p = DOCS / "project-state.json"
    ps = load_json(p)
    rev, dirty = source_identity()
    ps["source_revision"], ps["dirty_state"] = rev, dirty
    pos = derive_position(load_json(DOCS / "work-items.json")["records"],
                          load_json(DOCS / "requirements.json")["records"], read_plan_order())
    # The task is written even when there is none: an older one must not stay (WP-165).
    for key, value in pos.items():
        if value is not None or key == "current_task":
            ps[key] = value
    decisions = DOCS / "decisions-pending.json"
    if decisions.exists():
        ps["pending_decision_ids"] = open_decisions(load_json(decisions)["records"])
    runs = sorted(d.name for d in EVIDENCE.iterdir() if d.is_dir() and d.name[:8].isdigit()) if EVIDENCE.is_dir() else []
    if runs:
        ps["last_run_id"] = runs[-1]
    ps["checkpoint_generation"] += 1
    if ps.get("lease"):
        ps["lease"]["fencing_token"] = ps["checkpoint_generation"]
    seq = append_event("checkpoint", "saved", task_id=ps.get("current_task"), result=note)
    ps["event_sequence"] = seq
    write_json(p, ps)
    print(f"checkpoint generation={ps['checkpoint_generation']} seq={seq} rev={rev[:8]} dirty={dirty}")
    return E_OK


# ----------------------------------------------------------------------------- commit discipline
WP_IN_SUBJECT = re.compile(r"^(?:WIP\s+)?(WP-\d+)\b")


def cmd_check_commit(rev: str = "HEAD") -> int:
    """DEC-004 (2026-10-19): a commit whose subject names a work item lands only while that item
    is active or done in the records at that commit (OS-EXEC-AR §2.1) — four WP-43 commits reached
    main while WP-43 was planned. CI checks the head commit only (its checkout has depth 1): a
    push of several commits is judged by its last one, a declared limit."""
    r = subprocess.run(["git", "log", "-1", "--format=%s", rev], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"check-commit: {r.stderr.strip()}"); return E_INTERNAL
    subject = r.stdout.strip()
    m = WP_IN_SUBJECT.match(subject)
    if not m:
        print("check-commit: the subject names no work item"); return E_OK
    wid = m.group(1)
    items = {w["id"]: w for w in load_json(DOCS / "work-items.json")["records"]}
    if wid not in items:
        print(f"check-commit: {wid} is not a work item"); return E_VALIDATION
    status = items[wid]["status"]
    if status not in ("active", "done"):
        print(f"check-commit: {wid} is {status}; its work may land only while it is active (§2.1, DEC-004)"); return E_VALIDATION
    print(f"check-commit: {wid} is {status}"); return E_OK


# ----------------------------------------------------------------------------- CI evidence import
def github_run(run_id: str):
    """The GitHub run's state through gh (`gh run view <id> --json ...`): (info, None), or
    (None, reason) when gh is missing or fails. `mutants-<n>` names run n of the mutants workflow."""
    gh = shutil.which("gh")
    if not gh:
        return None, "gh is not on PATH; the import needs the run's conclusion from GitHub"
    num = run_id.split("-")[-1]
    r = subprocess.run([gh, "run", "view", num, "--json", "status,conclusion,headSha,event,workflowName,attempt"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        return None, f"gh run view {num} failed: {(r.stderr or r.stdout).strip()[:200]}"
    try:
        return json.loads(r.stdout), None
    except ValueError:
        return None, "gh returned no JSON"


def importer_identity():
    """Who adopts the evidence (REQ-M0-006): the importing process's worker from the closed
    enumeration and the development worker's identity as docs/automation.json records it."""
    worker, _ = runner_identity()
    identity = "unknown"
    auto = DOCS / "automation.json"
    if auto.exists():
        try:
            identity = load_json(auto).get("development_worker", {}).get("identity") or identity
        except (OSError, ValueError):
            pass
    return {"worker": worker, "identity": identity}


def cmd_import_ci_evidence(run_id: str) -> int:
    """Fetch the ci-evidence/<run> branch pushed by the verification runner and adopt its run
    directories as evidence (their input digests must match the current tree, which
    validate-records checks). Each imported verdict is attached to its test in docs/tests.json."""
    import shutil, tempfile
    # The checked import (ADR-0026, REL-2 A): the GitHub run must have concluded with success,
    # come from verify or mutants and start from a head that is an ancestor of HEAD; two
    # cancelled runs of 2026-11-09 had published evidence branches this importer would have
    # adopted. Without gh the import is blocked, never guessed.
    if not RUN_ID_RE.fullmatch(run_id):
        print(f"import refused: run id {run_id!r} is not <digits> or mutants-<digits>"); return E_VALIDATION
    info, why = github_run(run_id)
    if info is None:
        print(f"import blocked: {why}"); return E_BLOCKED
    if info.get("status") != "completed" or info.get("conclusion") != "success":
        print(f"import refused: run {run_id} is {info.get('status')}/{info.get('conclusion')}, not completed/success"); return E_VALIDATION
    if info.get("workflowName") not in ACCEPTED_WORKFLOWS:
        print(f"import refused: workflow {info.get('workflowName')!r} is not one of {ACCEPTED_WORKFLOWS}"); return E_VALIDATION
    head = str(info.get("headSha", ""))
    if not head or subprocess.run(["git", "merge-base", "--is-ancestor", head, "HEAD"], cwd=ROOT, capture_output=True).returncode != 0:
        print(f"import refused: the run's head {head[:8]!r} is not an ancestor of HEAD"); return E_VALIDATION
    ref = f"refs/heads/ci-evidence/{run_id}"
    r = subprocess.run(["git", "fetch", "-q", "origin", f"{ref}:refs/remotes/ci/{run_id}"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"fetch failed: {r.stderr.strip()}"); return E_BLOCKED
    branch_commit = git("rev-parse", f"refs/remotes/ci/{run_id}")
    # The new run directories are checked out into a temporary copy, removed when the import ends
    # (left behind, 44 copies filled the workspace's disk on 2026-10-19), through an index of its
    # own inside the copy: the repository's index, and what the user has staged in it, stay as
    # they were.
    tmp = Path(tempfile.mkdtemp(prefix="ci-ev-"))
    imported = 0
    try:
        # The branch holds the whole committed evidence tree (verify.yml, mutants.yml: `git add -f
        # evidence/` on the full checkout; 13.7 GB on 2026-11-17, more than the disk had free): its
        # run directories are listed from its evidence tree (a branch without one fails here, as its
        # checkout did) and only the new ones are checked out (WP-151). A directory already under
        # evidence/ is skipped as before, whatever its identity. Every NEW directory must be this
        # run's, attempt included, before anything is written (WP-81): one of another run or
        # attempt would receive this run's receipt and fail the validator only later.
        listed = subprocess.run(["git", "ls-tree", "-r", "--name-only", "-z", f"refs/remotes/ci/{run_id}:evidence"],
                                cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True).stdout.split("\0")
        names = sorted({p.split("/")[0] for p in listed if p.count("/") == 1 and p.endswith("/verdict.json")})
        new = [n for n in names if not (EVIDENCE / n).exists()]
        if new:
            subprocess.run(["git", "--literal-pathspecs", f"--work-tree={tmp}", "checkout", "-q", f"ci/{run_id}",
                            "--pathspec-from-file=-", "--pathspec-file-nul"], cwd=ROOT, check=True, text=True,
                           input="".join(f"evidence/{n}\0" for n in new), env={**os.environ, "GIT_INDEX_FILE": str(tmp / ".index")})
        new = [tmp / "evidence" / n for n in new]
        want = (run_id.split("-")[-1], str(info.get("attempt")))
        for d in new:
            have = run_ci_identity(d)
            if have is None or have[:2] != want:
                print(f"import refused: {d.name} names run/attempt {have[:2] if have else None}, not {want} as gh reports for run {run_id}; nothing imported")
                return E_VALIDATION
        clash = test_id_clash(new)
        if clash:
            print(f"import refused: {clash}; nothing imported"); return E_VALIDATION
        if len(names) > len(new):
            print(f"skipped {len(names) - len(new)} run(s) already under evidence/")
        for d in new:
            dest = EVIDENCE / d.name
            shutil.copytree(d, dest)
            v = load_json(dest / "verdict.json")
            # run.json stays exactly as the runner wrote it; the import's own record is import.json
            imp = {"ci_run_id": run_id.split("-")[-1], "conclusion": info["conclusion"], "head_sha": head, "event": info.get("event"),
                   "run_attempt": info.get("attempt"), "workflow": info.get("workflowName"), "evidence_branch_commit": branch_commit,
                   "imported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                   "importer": importer_identity()}
            (dest / "import.json").write_text(json.dumps(imp, ensure_ascii=False, indent=1) + "\n")
            attach_evidence(v["test_id"], d.name, v["verdict"])
            imported += 1
            print(f"imported {d.name} {v['test_id']} {v['verdict']}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if tmp.exists():
            print(f"warning: the temporary copy {tmp} could not be removed")
    print(f"imported {imported} run(s) from CI run {run_id}")
    return E_OK


def test_id_clash(dirs):
    """The first two of `dirs` (new run directories) whose verdict.json names one test id, as a
    refusal reason, or None (WP-98, the audit of WP-96). attach_evidence replaces a test's
    reference, so of two new runs of one test the last attached would win: a PASS could cover a
    FAIL of the same test. An unreadable verdict.json is refused too, before anything is written."""
    seen = {}
    for d in dirs:
        try:
            tid = load_json(d / "verdict.json")["test_id"]
        except (OSError, ValueError, KeyError, TypeError):
            return f"{d.name} has no readable verdict.json with a test id"
        if tid in seen:
            return f"{seen[tid]} and {d.name} both carry {tid}"
        seen[tid] = d.name
    return None


def run_ci_identity(d):
    """(run id, attempt, sha) as strings from <d>/run.json's ci object, or None when the file is
    unreadable or carries no ci identity (an empty value is no identity)."""
    try:
        ci = load_json(d / "run.json").get("ci")
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(ci, dict):
        return None
    ident = tuple(str(ci.get(k) if ci.get(k) is not None else "") for k in ("run_id", "run_attempt", "sha"))
    return ident if all(ident) else None


def cmd_adopt_native(sources) -> int:
    """Adopt the run directories the verify jobs of this very CI run wrote (WP-81, ADR-0026 rule 5:
    native evidence carries no import.json). No gh, no receipt. Each job's evidence/ artifact holds
    the whole committed tree too: a directory already under evidence/ is skipped and counted, never
    adopted again, whatever its identity. It fails closed like the validator's native rule: only on
    GitHub Actions with GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT and GITHUB_SHA all set, every NEW
    directory naming exactly that run id, attempt and sha, every --from holding at least one run
    directory, no new run id repeating across the sources, no two new directories of one test id
    (WP-98), and at least one new directory.
    Anything else adopts nothing. Each verdict is attached like a native run's."""
    import shutil
    found, seen, skipped = [], {}, 0
    for src in sources:
        src = Path(src)
        if not src.is_dir():
            print(f"adopt refused: {src} is not a directory"); return E_VALIDATION
        runs = [d for d in sorted(src.iterdir()) if (d / "verdict.json").exists()]
        if not runs:
            print(f"adopt refused: {src} holds no run directory (an empty artifact adopts nothing)"); return E_VALIDATION
        for d in runs:
            if (EVIDENCE / d.name).exists():
                skipped += 1
                continue
            if d.name in seen:
                print(f"adopt refused: run id {d.name} appears in {seen[d.name]} and {src}"); return E_VALIDATION
            seen[d.name] = src
            found.append(d)
    if skipped:
        print(f"skipped {skipped} run(s) already under evidence/")
    if not found:
        print("adopt refused: nothing new to adopt (every run directory is already under evidence/)"); return E_VALIDATION
    env = os.environ
    names = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")
    expect = [env.get(k, "") for k in names]
    if env.get("GITHUB_ACTIONS") != "true" or not all(expect):
        print(f"adopt refused: not inside a CI run (GITHUB_ACTIONS=true and {', '.join(names)} all set); native evidence is adopted only by its own run")
        return E_VALIDATION
    first = None
    for d in found:
        have = run_ci_identity(d)
        if have is None:
            print(f"adopt refused: {d.name} carries no ci identity (run id, attempt, sha)"); return E_VALIDATION
        first = first or (have, d.name)
        if have != first[0]:
            print(f"adopt refused: {d.name} names run/attempt/sha {have}, {first[1]} names {first[0]}"); return E_VALIDATION
        for name, want, got in zip(("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"), expect, have):
            if want != got:
                print(f"adopt refused: {d.name} names {got!r} where {name} is {want!r}"); return E_VALIDATION
    clash = test_id_clash(found)
    if clash:
        print(f"adopt refused: {clash}; nothing adopted"); return E_VALIDATION
    for d in found:
        dest = EVIDENCE / d.name
        shutil.copytree(d, dest)
        v = load_json(dest / "verdict.json")
        attach_evidence(v["test_id"], d.name, v["verdict"])
        print(f"adopted {d.name} {v['test_id']} {v['verdict']}")
    print(f"adopted {len(found)} run(s) of CI run {first[0][0] if first else '-'} attempt {first[0][1] if first else '-'}")
    return E_OK


# ----------------------------------------------------------------------------- main
# Local pre-flight (after 59 red CI runs on 2026-10-18): the guest suites run in this workspace
# before a push. The precompiled core/alloc of the UEFI and bare-metal targets cannot be fetched
# here (static.rust-lang.org is unreachable), so cargo builds them from the standard library's own
# source at the compiler's exact commit (build-std), cloned from GitHub. Evidence goes to a scratch
# directory and is never attached: CI stays the only source of evidence.
BUILD_STD_ENV = {"RUSTC_BOOTSTRAP": "1", "CARGO_UNSTABLE_BUILD_STD": "core,alloc,compiler_builtins",
                 "CARGO_UNSTABLE_BUILD_STD_FEATURES": "compiler-builtins-mem"}
RUST_REPO = "https://github.com/rust-lang/rust.git"


def preflight_env(base, scratch, build_std):
    """The environment of a pre-flight step: `base` plus scratch evidence, and build-std for the
    build of the guest image only — a host tool that a test builds (tools/text_check.py's
    examples, the host suites' cargo tests) links the host's own std, and build-std there gives
    two `core`s (E0152: the first pre-flight's TST-M5-TEXT-GUEST)."""
    env = dict(base)
    if build_std:
        env.update(BUILD_STD_ENV)
    else:
        for k in BUILD_STD_ENV:
            env.pop(k, None)
    env["NAWAH_SCRATCH_EVIDENCE"] = str(scratch)
    return env


def rustc_identity(env=None):
    """(release, commit-hash) of the active rustc, from `rustc -vV`."""
    out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, env=env).stdout
    fields = dict(l.split(": ", 1) for l in out.splitlines() if ": " in l)
    return fields.get("release", ""), fields.get("commit-hash", "")


def rust_src_state(src: Path, commit: str) -> str:
    """'ok' when `src` (<sysroot>/lib/rustlib/src/rust) holds the standard library at the
    compiler's commit, 'missing' without it, 'mismatch:<head>' for another commit. A rust-src
    installed by rustup carries no git metadata and is trusted as the same release."""
    if not (src / "library" / "Cargo.lock").exists():
        return "missing"
    head = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if not head or not (src / ".git").exists():
        return "ok"
    return "ok" if head == commit else f"mismatch:{head}"


VERIFY_WORKFLOW = ROOT / ".github" / "workflows" / "verify.yml"
HYGIENE_STEP = "Rust hygiene"


def hygiene_commands(workflow=VERIFY_WORKFLOW):
    """(env, commands) of CI's hygiene step, read from the workflow itself so the local gate and
    CI cannot drift apart: CI run 39185115793 failed on clippy for the kernel built without
    `ktest` (dead test-only code), a configuration the local pre-flight never ran. Every line of
    the step's script that starts with `cargo ` or `sh tools/` is a command; the shell plumbing
    around them (`set`, `mkdir`, the `{ … } | tee` group) is not."""
    import yaml
    doc = yaml.safe_load(Path(workflow).read_text(encoding="utf-8"))
    for job in doc.get("jobs", {}).values():
        for step in job.get("steps", []):
            if str(step.get("name", "")).startswith(HYGIENE_STEP):
                cmds = [l.strip() for l in str(step.get("run", "")).splitlines()
                        if l.strip().startswith(("cargo ", "sh tools/"))]
                env = {str(k): str(v) for k, v in (step.get("env") or {}).items()}
                return env, cmds
    raise ValueError(f"{workflow}: no step named '{HYGIENE_STEP}…'")


def local_hygiene_argv(cmd):
    """A CI hygiene command as run here: `--offline` dropped (CI pre-fetches; the local registry
    differs), nothing else changed — the lint configuration is exactly CI's."""
    import shlex
    return [a for a in shlex.split(cmd) if a != "--offline"]


def cmd_hygiene() -> int:
    """CI's hygiene gate, locally: the same commands in the same order (fmt, clippy -D warnings on
    every crate and every kernel configuration, the unsafe policy). Cross targets are not
    installed here, so cargo builds `core` from the library source (build-std); one shared target
    directory keeps that to one build per target triple."""
    try:
        extra, cmds = hygiene_commands()
    except (OSError, ValueError) as e:
        print(f"hygiene: {e}")
        return E_INTERNAL
    env = dict(os.environ)
    env.update(extra)
    env.update(BUILD_STD_ENV)
    env["CARGO_TARGET_DIR"] = str(ROOT / "build" / "hygiene-target")
    t0 = time.time()
    for i, cmd in enumerate(cmds, 1):
        r = subprocess.run(local_hygiene_argv(cmd), cwd=ROOT, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"hygiene: FAIL [{i}/{len(cmds)}] {cmd}")
            print("\n".join((r.stdout + r.stderr).strip().splitlines()[-40:]))
            return E_VALIDATION
    print(f"hygiene: PASS — {len(cmds)} commands of CI's '{HYGIENE_STEP}' step ({time.time() - t0:.0f}s)")
    return E_OK


def cmd_preflight(suite, only) -> int:
    # The records first: CI's committed-state check runs validate-records, and a record error
    # (CI run 39196967624: a requirement citing evidence its tests had dropped) fails CI after
    # every suite has passed. It takes a second.
    if validate_records(verbose=False) != E_OK:
        print("preflight: validate-records failed (run `python3 tools/project.py validate-records`)")
        return E_INTERNAL
    # CI's hygiene gate runs `cargo fmt --all --check` before anything builds, and a formatting
    # miss there fails the whole run before the suites execute (CI run 39175302719). Catch it
    # here first: it needs only rustfmt and finishes in under a second.
    if subprocess.run(["cargo", "fmt", "--all", "--check"], cwd=ROOT).returncode != 0:
        print("preflight: cargo fmt --all --check failed (run `cargo fmt --all` and retry)")
        return E_INTERNAL
    # Then the rest of the same gate — every clippy configuration and the unsafe policy — read
    # from the workflow (CI run 39185115793: the kernel without `ktest` was never linted here).
    rc = cmd_hygiene()
    if rc != E_OK:
        return rc
    release, commit = rustc_identity()
    sysroot = Path(subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True).stdout.strip())
    src = sysroot / "lib" / "rustlib" / "src" / "rust"
    state = rust_src_state(src, commit)
    if state == "missing":
        cache = Path.home() / ".cache" / "nawah" / f"rust-src-{commit[:12]}"
        if not (cache / "library" / "Cargo.lock").exists():
            subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", release, "--filter=blob:none", "--sparse",
                            RUST_REPO, str(cache)], check=True)
            subprocess.run(["git", "-C", str(cache), "sparse-checkout", "set", "library"], check=True)
        src.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            src.unlink()
        src.symlink_to(cache)
        state = rust_src_state(src, commit)
    print(f"preflight: rustc {release} ({commit[:9]}), library source {state}")
    if state != "ok":
        return E_INTERNAL
    scratch = ROOT / "build" / "preflight-evidence"
    scratch.mkdir(parents=True, exist_ok=True)
    me = [sys.executable, str(Path(__file__).resolve())]
    rc = subprocess.run(me + ["build", "--target", "pc-qemu"], env=preflight_env(os.environ, scratch, True)).returncode
    if rc != 0:
        return rc
    return subprocess.run(me + ["test", "--target", "pc-qemu", "--suite", suite] + (["--only", only] if only else []),
                          env=preflight_env(os.environ, scratch, False)).returncode


def main(argv=None):
    ap = argparse.ArgumentParser(prog="project.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("validate-records"); s.add_argument("--strict", action="store_true"); sub.add_parser("reverify-host")
    s = sub.add_parser("import-ci-evidence"); s.add_argument("--run", required=True)
    s = sub.add_parser("adopt-native", help="adopt this CI run's own run directories (merge job; no gh, no import.json)")
    s.add_argument("--from", dest="sources", action="append", required=True, help="a directory of run directories; repeatable")
    s = sub.add_parser("check-commit", help="the head commit names only an active or done work item (DEC-004)"); s.add_argument("--rev", default="HEAD")
    s = sub.add_parser("sync-oracles", help="write each test record's oracle from its source (HOST_SUITES, target.json)")
    s.add_argument("--check", action="store_true", help="write nothing; exit 50 when a record differs")
    s = sub.add_parser("status"); s.add_argument("--json", action="store_true")
    for n in ("build", "boot"):
        s = sub.add_parser(n); s.add_argument("--target", required=True)
    s = sub.add_parser("test"); s.add_argument("--target", required=True); s.add_argument("--suite", required=True)
    s.add_argument("--only", help="comma-separated case ids")
    s = sub.add_parser("host-suite-of", help="print the host suite that holds a case id (tests/mutants.py asks)")
    s.add_argument("test_id")
    s = sub.add_parser("preflight", help="build and run a guest suite here before a push (build-std, scratch evidence)")
    s.add_argument("--suite", required=True); s.add_argument("--only", help="comma-separated case ids")
    sub.add_parser("hygiene", help="CI's hygiene step here: the same fmt/clippy/unsafe commands, read from verify.yml")
    for n in ("next", "report", "checkpoint", "resume", "run"):
        s = sub.add_parser(n); s.add_argument("--json", action="store_true"); s.add_argument("--result"); s.add_argument("--once", action="store_true"); s.add_argument("--until"); s.add_argument("--note")
    a = ap.parse_args(argv)
    if a.cmd == "validate-records": return validate_records(strict=a.strict)
    if a.cmd == "sync-oracles": return cmd_sync_oracles(a.check)
    if a.cmd == "status": return cmd_status(a.json)
    if a.cmd == "build": return cmd_build(a.target)
    if a.cmd == "boot": return cmd_boot(a.target)
    if a.cmd == "test": return cmd_test(a.target, a.suite, a.only.split(",") if a.only else None)
    if a.cmd == "host-suite-of":
        found = [name for name, cases in HOST_SUITES.items() if any(c["id"] == a.test_id for c in cases)]
        if not found:
            return 1
        print(found[0]); return 0
    if a.cmd == "checkpoint": return cmd_checkpoint(a.note)
    if a.cmd == "reverify-host": return cmd_reverify_host()
    if a.cmd == "import-ci-evidence": return cmd_import_ci_evidence(a.run)
    if a.cmd == "adopt-native": return cmd_adopt_native(a.sources)
    if a.cmd == "check-commit": return cmd_check_commit(a.rev)
    if a.cmd == "preflight": return cmd_preflight(a.suite, a.only)
    if a.cmd == "hygiene": return cmd_hygiene()
    print(f"{a.cmd}: not implemented yet in this work package (planned: M1); see docs/work-items.json")
    return E_INTERNAL


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as ex:  # internal error
        print(f"internal error: {type(ex).__name__}: {ex}", file=sys.stderr)
        sys.exit(E_INTERNAL)
