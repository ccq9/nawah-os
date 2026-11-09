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
    pb.warn_only_tests = {t["id"] for t in recs.get("tests", []) if t.get("stale_policy") == "warn"}

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
        if t["verdict"] == "PASS" and not t["evidence_refs"]:
            pb.err(w, "PASS without evidence_refs")
        # A passing test's oracle states what the test checks, not what was planned: three
        # oracles kept their plan text after PASS and claimed steps the tests never ran
        # (WINDOW-A11Y, ARABIC-UI, PROCESS-KILL; audit 2026-10-19).
        if t["verdict"] == "PASS" and PLANNED_WORD.search(t["oracle"]):
            pb.err(w, "PASS while the oracle still describes the plan ('planned'); state what the test checks")

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
            done = {w["id"] for w in recs if w["status"] == "done"}
            ready = [w["id"] for w in recs if w["status"] == "planned" and all(d in done for d in w["depends_on"])]
            out["next_task"] = ready[0] if ready else None
        else:
            out["decisions_pending"] = [d["id"] for d in recs if d["status"] == "open"]
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
    kernel's own lines); the transcript is evidence (console.log)."""

    PROMPT = re.compile(rb"(?:^|\n)(?:[A-Za-z0-9_]+@)?nawah> $")

    def __init__(self, spec, transcript_path, serial_path, timeout):
        import threading
        self.spec, self.transcript_path, self.serial_path, self.timeout = spec, transcript_path, serial_path, timeout
        self.steps = []          # (step, output bytes, prompt bytes)
        self.errors = []
        self.transcript = bytearray()
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


def new_run_dir(purpose_slug):
    rev, _ = source_identity()
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    n = 1
    while True:
        rid = f"{ts}-{rev[:8]}-{n:03d}"
        d = (SCRATCH or EVIDENCE) / rid
        if not d.exists():
            d.mkdir(parents=True); return rid, d
        n += 1


def write_run(d, rid, target, purpose, commands, exit_code, started, worker=None, notes=None):
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
    write_verdict(d, rid, t["build"]["test_id"], verdict, "all build steps exit 0 and artifact exists", "exit 0 + artifact", observed, inputs)
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


def prepare_disk(t, target_name, fresh=True):
    """The lab's virtio disk (WP-18): a raw FAT32 image of `qemu.disk.size_mib` MiB made by
    tools/fat32.py (an implementation independent of the kernel's) with the lab files
    (/HELLO.TXT, /PATTERN.BIN of 20480 bytes `(i*31 + (i>>8)) & 0xFF`, /DIR/INNER.TXT), the
    built applications under /SYSTEM (WP-23) and the raw pattern `(sector*7+i)&0xFF` in its
    last `pattern_tail` sectors. Rebuilt for every run
    unless `fresh` is false (a multi-phase case keeps what earlier phases wrote). Targets without
    `qemu.disk` get none."""
    spec = t["qemu"].get("disk")
    if not spec:
        return None
    out = ROOT / "build" / target_name
    img = out / "disk.img"
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
    console_failures = []
    for i, ph in enumerate(phases):
        timeout_s = int(os.environ.get("NAWAH_QEMU_TIMEOUT_S", ph.get("timeout_s", case_timeout)))
        serial = d / ("serial.log" if len(phases) == 1 else f"serial-{i + 1}.log")
        disk = prepare_disk(t, target_name, fresh=(i == 0))
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
        console = ConsoleSession(console_spec, d / "console.log", serial, timeout_s) if console_spec else None
        if console:
            console.start()
        try:
            rc = run()
        finally:
            peers.close()
            if console:
                # Every phase's console verdict is kept (a later phase's session must not
                # overwrite an earlier one's failures).
                console_failures += [f"phase {i + 1}: {f}" if len(phases) > 1 else f for f in console.finish()]
        if rc < 0:
            # QEMU itself died (signal): a lab failure, not a verdict on the kernel. One retry on
            # a fresh image; if it dies again the case fails and says why (LAB_ERROR), so a
            # mutation run never counts it as a kill (mutants run 39116036466: 4 SIGSEGVs).
            lab_errors.append(f"phase {i + 1}: qemu died with signal {-rc}, retried")
            sent.clear()
            serial.unlink(missing_ok=True)
            disk = prepare_disk(t, target_name, fresh=(i == 0))
            peers = HostServices(ph.get("host_services", case.get("host_services")))
            try:
                rc = run()
            finally:
                peers.close()
        text = serial.read_text(errors="replace") if serial.exists() else ""
        cmds.append(" ".join(cmd)); texts.append(text); rcs.append(rc)
        ended = [f"phase {i + 1}: {f}" for f in ends_by_failures(ph.get("ends_by", case.get("ends_by")), actions, sent)]
        if len(phases) > 1:
            exp = ph.get("expected_exit_code", case["expected_exit_code"])
            req = [m.replace("${BUILD_ID}", build_id) for m in ph.get("required_markers", [])]
            fb = ph.get("forbidden_markers", [])
            miss = [m for m in req if m not in text]
            forb = [m for m in fb if m in text]
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
        {"id": "TST-M0-001", "command": ["python3", "-I", "tests/test_validate_records.py"], "oracle": "unittest exit 0 and 'OK' in output; 21 cases incl. 6 required rejections, the dependency rule for active and done items, a new run re-pointing every older run of its test, an earlier schema error that must not skip later evidence checks, and environment failures (a missing command, a failed toolchain download) recorded as ERROR, not FAIL",
         "inputs": ["tools/project.py", "tools/schemas_gen.py", "tests/test_validate_records.py"], "input_globs": ["docs/schemas/*.schema.json"]},
        {"id": "TST-M0-002", "command": ["python3", "-I", "tests/test_m0_records.py"], "oracle": "required M0 documents and contract sections exist; every tracked path checks out on Windows (no reserved device name, invalid character, trailing dot or space, or case-only collision); every file ADR-0002 item 4 ports from Sol OS names its origin (commit d54f0a5 or the Sol ADR) in its header; the twelve-role team methodology is in place (docs/policies/team-methodology.md names every role, .claude/workflows/nawah-team.js opens with its meta literal, the twelve agent definitions carry name/description/tools/model; docs/PLAN-REVERSE.md exists with its seven sections, the fifth listing refuted and unverified claims; docs/PLAN-ANSWER.md exists with its eight sections)",
         "inputs": ["tests/test_m0_records.py", "docs/contracts/boot.md", "docs/adr/0001-bootstrap.md", "docs/PROJECT.md", "docs/ENVIRONMENT.md", "docs/security/threat-model.md",
                    "docs/adr/0002-rust-and-sol-os-reuse.md", "kernel/src/arch/x86_64/gdt.rs", "kernel/src/arch/x86_64/idt.rs", "kernel/src/arch/x86_64/trap.rs",
                    "kernel/src/arch/x86_64/serial.rs", "kernel/src/arch/x86_64/port.rs", "kernel/src/arch/x86_64/qemu.rs", "kernel/src/arch/x86_64/ktest.rs",
                    "kernel/src/cell.rs", "kernel/src/ktest.rs", "tests/mutants.py", "tools/check-unsafe.sh",
                    "docs/policies/team-methodology.md", ".claude/workflows/nawah-team.js", "CLAUDE.md", "docs/PLAN-REVERSE.md", "docs/PLAN-ANSWER.md"], "input_globs": [".claude/agents/*.md"]},
        {"id": "TST-M0-003", "command": ["python3", "-I", "tests/test_ci_workflows.py"],
         "oracle": "every workflow file parses as YAML with a name, triggers and jobs (each with a runner and steps) and pins every action it uses to a commit; no checkout keeps the token and only the evidence push is given it; verify runs on pushes to main, pull requests and by hand, limits its job's time and cancels the run a newer push to the same ref supersedes (concurrency group per ref, cancel-in-progress); every Toolchain step ends within 15 minutes and retries each download with a per-attempt timeout (three runs of 2026-10-23 hung there to the job's limit); mutants never runs on a push; every guest suite of target.json has its verify step and vice versa, and every host suite outside the gates and M2 is non-empty and run (ADR-0026, D5); the verify job's limit is 55 minutes, the M5 and M6 guest steps carry their own caps (18, 12) and every step cap with a 20 % margin fits the limit (D4-V2), and M6, bounded by its own timeouts, fits its cap in the worst case (the sum of each phase's timeout_s under 12 minutes; M5's cap is a measured hang guard, outside that rule; uncapped steps are not budgeted); the suite case carrying the boot test id is the oracle of `project.py boot` even with QEMU arguments, two such cases are refused, boot_oracle carries the same lab self-test key as TST-M1-BOOT, and a kernel source other than ktest.rs names that key (PLAN-ANSWER §2.6, WP-45); every phase of TST-M6-INTERACTIVE-BOOT and TST-M1-BOOT require the kernel's whole boot-mode line with the build id (OSX|${BUILD_ID}|kernel|boot_mode|mode=…|source=…|key=…|hv=…, the values per phase), never a fragment a process could print through SYS_TRACE, and the case caps `|kernel|boot_mode|` at one per boot (6); fw_cfg is reached only from bootmode.rs, ktest.rs and fwcfg.rs itself (exact identifiers of fwcfg.rs's public entries, the module name outside its two declaring files, the ports 0x510/0x511), and the guard reports a planted caller, an aliased import and a direct port write while ignoring a lookalike name (PLAN-ANSWER §3.4 item 3); the local pre-flight adds scratch evidence to the caller's environment with build-std for the guest build only (never for the test step, whose host tools link the host's std) and accepts the library source only at the compiler's own commit (missing / ok / mismatch); the mutation harness builds every app the kernel embeds; import-ci-evidence copies the runner's runs and leaves no temporary copy behind, also when the checkout fails, and leaves what the user staged staged; check-commit rejects a head commit naming an unknown work item or one that is neither active nor done, and verify runs it (DEC-004); a re-run replaces its evidence branch; the mutants workflow runs the gates M2, M3, M4, M5 in order, checks the records strictly first and publishes every gate's report (27 cases, OK)",
         "inputs": ["tests/test_ci_workflows.py", "tools/project.py", "platform/pc-qemu/target.json", "kernel/build.rs"], "input_globs": [".github/workflows/*.yml", "kernel/src/**/*.rs"]},
        {"id": "TST-M0-004", "command": ["python3", "-I", "tests/test_pre_merge.py"],
         "oracle": "tools/pre-merge.sh runs validate-records --strict under set -euo pipefail with no pipe after the validator and exits with its code: on a copy of the repository as committed it exits 0 and prints 'pre-merge: OK'; with one input of a host test edited after its run (a stale verdict) it exits 50 and prints no OK (3 cases, OK)",
         "inputs": ["tests/test_pre_merge.py", "tools/pre-merge.sh", "tools/project.py"], "input_globs": []},
        {"id": "TST-M0-005", "command": ["python3", "-I", "tests/test_mutants_harness.py"],
         "oracle": "the mutation harness counts a kill only for a real one: a mutant's build id is all hex so TST-M5-DISPLAY-BOOT's bar decodes (not `mutm94`), the per-case QEMU timeout exceeds the slowest clean case (156 s start to finish in the slowest committed TST-M5-ELEVATE run, evidence 20261109T104517Z-dece70c2-001), and run_killers stops the fairness sweep at the first FAIL while declared killers run to the end; a partial report is written as each mutant is decided; stage_of maps M129 to M5 and M130 onwards to M6, and every mutant's anchor occurs exactly once in its file; WP-45's boot-mode mutants M130 (hypervisor_present forced true), M131 (any key value is ok) and M132 (the interactive boot takes the self-test exit) are registered as SECURITY mutants of the M6 stage killed by TST-M6-INTERACTIVE-BOOT (no M6 gate runs them yet: WP-66 proposal), and a mutant whose declared killer boots the release image NAWAH.EFI gets that image built before its killers run (10 cases, OK)",
         "inputs": ["tests/test_mutants_harness.py", "tests/mutants.py", "platform/pc-qemu/target.json"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs"]},
        {"id": "TST-M0-007", "command": ["python3", "-I", "tests/test_evidence_provenance.py"],
         "oracle": "evidence provenance and the checked import (ADR-0026): evidence-run 1.1.0 carries a closed worker enumeration, the runner's ci identity (required for verification-runner, forbidden at 1.0.0) and dirty_paths while 1.0.0 stays valid; write_run on GitHub Actions records worker=verification-runner and the run's ci identity; the run's tree identity is taken once when the run begins, so the records attach_evidence writes never make it dirty; source_identity ignores evidence/, build/ and state/ and names the dirty paths as they are, spaces and non-ASCII letters included; a 1.1.0 PASS without import.json is a strict error whatever worker run.json declares, unless the evidence is native to the validating CI run (run id, attempt and sha all equal its ci identity, none empty); a present import.json is checked for every worker and verdict against its own schema (evidence-import: every field required, conclusion success, workflow verify or mutants, importer from the enumeration) and must match the run's ci identity on run id, attempt, head sha and workflow, and a malformed receipt is a named error; 1.0.0 evidence without import.json one aggregated warning; import-ci-evidence refuses a run that is not completed/success, not from verify or mutants, whose head is not an ancestor of HEAD or whose id is not <digits> or mutants-<digits> matched whole, is blocked when gh is not on PATH, and on success writes import.json (naming the importer's worker and identity) beside an untouched run.json; the evaluator-outside-inputs staleness gap is not covered here (WP-66 and TST-M6-STALE-GATE are proposals of PLAN-ANSWER §1.3, not records yet) (26 cases, OK)",
         "inputs": ["tests/test_evidence_provenance.py", "tools/project.py", "docs/automation.json"], "input_globs": ["docs/schemas/*.schema.json"]},
    ],
}


HOST_SUITES["M2"] = [
    {"id": "TST-M2-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M2", "--report", "build/mutants-report.json"],
     "oracle": "every seeded defect that compiles is killed by at least one M1/M2 case; kill ratio >= 0.95 (report in stdout and build/mutants-report.json)",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json"], "input_globs": ["kernel/src/**/*.rs"], "timeout_s": 6000},
]
# The M3 gate's mutation run (WP-22) is its own suite so the verify workflow's quick host suite
# M3 stays quick; the mutants workflow runs it.
HOST_SUITES["M3-GATE"] = [
    {"id": "TST-M3-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M3", "--report", "build/mutants-m3-report.json"],
     "oracle": "every seeded M3 defect that compiles (scheduler, objects, syscalls, loader, MMIO window, TLB shootdown, SMP placement, virtio-blk, FAT32, VFS) is killed by at least one M3 case, host checks included; kill ratio >= 0.95",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json", "tools/fat32.py"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs"], "timeout_s": 7200},
]
# The M4 gate's mutation run (WP-31): its own suite, run by the mutants workflow after M2 and
# M3-GATE; the verify workflow's quick host suite M4 stays quick.
HOST_SUITES["M4-GATE"] = [
    {"id": "TST-M4-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M4", "--report", "build/mutants-m4-report.json"],
     "oracle": "every seeded M4 defect that compiles (process/wait syscalls, tokens, device objects and polling, system_info, dir_list, svcmgr ordering/timeouts/restarts/authority, authd verification and sessions, configd CAS/retry/precedence/notify/authorization, netd checksums/policy/retransmission, sh token hand-over and prompt) is killed by at least one M4 case, console sessions included; kill ratio >= 0.95",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs"], "timeout_s": 10800},
]
# The M5 gate's mutation run (WP-38): M82 onwards against the M5 suite (guest cases and the host
# suites: libui's unit tests, the text conformance suites); a surviving mutant that undoes a
# security fix fails the run whatever the ratio (tests/mutants.py SECURITY).
HOST_SUITES["M5-GATE"] = [
    {"id": "TST-M5-MUTANTS", "command": ["python3", "-I", "tests/mutants.py", "--target", "pc-qemu", "--stage", "M5", "--report", "build/mutants-m5-report.json"],
     "oracle": "every seeded M5 defect that compiles (displayd: narrator authority, client limits and the session's reserve, LIST hash and STATUS composed= of a held screen; sessiond: the password field's announcements, the elevation prompt after the keys; inputd: the name `display`; libui: password bullets; kernel: process_kill authority, kill wake-up, K1 at block, K2 at exit, frame clear on release, mouse routing; svcmgr: PONG and the watchdog's kill) is killed by at least one M5 case, host suites included; kill ratio >= 0.95 and no surviving security mutant; report build/mutants-m5-report.json",
     "inputs": ["tests/mutants.py", "tools/project.py", "platform/pc-qemu/target.json"], "input_globs": ["kernel/src/**/*.rs", "user/**/*.rs"], "timeout_s": 10800},
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
     "oracle": "the lab's monitor driver (run_qemu_monitored) against a fake QEMU that writes serial markers over time and serves a monitor socket: a single-step case sends its commands once its marker appears with ${SCREEN} and ${SCREEN:tag} (screen-<tag>.ppm beside it) resolved; ordered steps are each sent once their own marker appears, in order, and a later step never fires on an earlier marker; a marker that never appears sends nothing and the run is killed at the timeout; host-check arguments take ${SERIAL:key} (last value), ${SERIAL_FIRST:key} (first value), ${EVIDENCE} (the run's directory) and ${SCREEN:tag}; key-down/key-up go through QMP on one connection kept for the run (handshake once): a key pressed in one step is released by a later step after that step's marker and within 0.5 s of it; a step with since_previous ignores its marker printed before the previous step fired; a key command with no QMP socket is reported and the run goes on, and the link reconnects after a failed connect; a case with ends_by=monitor (WP-45) ends by the lab's `quit` (QEMU status 0): every step sent and the last one ending with `quit`, while a run that ended before the last step (a guest reset is status 0 too), a last step without `quit`, a case without steps or an unknown ending is a failure; driven through cmd_boot itself on the fake QEMU (target, image preparation and records stubbed), a case ending by the monitor passes when the lab quits and fails when the guest exits 0 before the last step, in a single run and in a later phase, each phase's console failures are all reported (a later phase does not overwrite them) and a phase's own timeout_s ends that phase (14 cases, OK)",
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
     "oracle": "libui on the host (14 tests): an element without a label (or a list without items) is refused when built; the focus order is the declared order without labels; Tab/Shift+Tab cycle it, Esc cancels, presses only; the text field takes characters (Arabic too), Backspace and the cursor keys, the list moves its selection with the arrows within bounds, Space/Enter toggle the checkbox and activate buttons; the descriptions read role, label, state and value/item exactly; ui.scale/ui.contrast map to the theme; 2x doubles every rectangle and the largest dialog fits one surface VMO; painting uses the theme's background and focus colours; v1.1 (WP-37): the password field edits like a text field, is described by role, label and state without its value, is drawn as one bullet per character (pixel-equal to a field of bullets, unlike the characters), and the application reads, wipes (zeroed slots) and sets values and moves the focus only where it can go; v1.2 (WP-39): in a right-to-left field Left and Right swap direction (set_rtl flips it live), and relabel/set_items switch an element's language in place with the selection clamped and bad arguments refused; v1.3 (WP-41): a value element shows text the application sets, is never focused, is described with its value as static and keeps at most TEXT_MAX (48) characters, and a password is never filled by the application; v1.5 (WP-38): Painter::fits measures a label or value through the painter's own line layout (font size, direction) against its row and refuses the 15+1+32 W prompt and config SET device MMMMMMMM 0 901 off but keeps the lab's requests (lab.elev, lab.elev7, lab.elev8), in both directions and at 2x, and never fits more than TEXT_MAX characters",
     "pass_marker": "test result: ok. 14 passed; 0 failed",
     "inputs": ["user/libui/Cargo.toml"], "input_globs": ["user/libui/src/*.rs", "user/libnawah-text/src/*.rs"]},
    {"id": "TST-M5-UI-TOOL", "command": ["python3", "-I", "tests/test_transcript_tool.py"],
     "oracle": "tools/transcript.py takes the narrator lines from trace lines and requires them to equal the expected file exactly in every serial log (a missing, extra or reordered line, or one bad phase, fails); dims accepts only the same origin with the size times the factor; streams (WP-37) checks every stream the file names exactly and in order whatever the interleaving, ignores other streams and non-user lines, and checks every phase (7 cases, OK)",
     "inputs": ["tests/test_transcript_tool.py", "tools/transcript.py"], "input_globs": []},
    {"id": "TST-M5-SCREEN-TOOL", "command": ["python3", "-I", "tests/test_screen_tool.py"],
     "oracle": "tools/screen.py desktop against a synthetic PPM: a pixel check passes on its colour and fails on another; a window hash equals the FNV-1a 64 of the rectangle's R,G,B bytes and fails when a pixel differs; a rectangle outside the image fails without crashing; an ink check finds a field's text against the side asked and fails for the other side, an empty field and a rectangle outside the image (3 cases, OK)",
     "inputs": ["tests/test_screen_tool.py", "tools/screen.py"], "input_globs": []},
]
HOST_SUITES["M3"] = [
    {"id": "TST-M3-FAT32-TOOL", "command": ["python3", "-I", "tests/test_fat32_tool.py"],
     "oracle": "the host FAT32 tool formats the lab volume (128992 clusters, 44 used), lists DIR/HELLO.TXT/PATTERN.BIN, reads files back exactly (cat/verify/expect), keeps the raw pattern tail, makes nested directories in their parent (SYSTEM/FONTS, a missing parent refused), and fsck.fat -n accepts the images",
     "inputs": ["tests/test_fat32_tool.py", "tools/fat32.py"], "input_globs": []},
]
# M6's first host case (WP-45, PLAN-ANSWER §2.5 D3: a host suite comes with its first case,
# never empty): the system manifest and the self-test manifest linted against services.md §2.
HOST_SUITES["M6"] = [
    {"id": "TST-M6-MANIFEST-LINT", "command": ["python3", "-I", "tests/test_m6_manifest.py"],
     "oracle": "a host lint of platform/pc-qemu/manifests/services.txt (services.md v1.11) and the lab manifest selftest.txt, read as svcmgr's parser reads them (user/apps/svcmgr/src/main.rs load and Fields: lines split on newline only, each cut at its first `#`, fields split on spaces only; only bytes 0x20-0x7E and newline, a Tab, a CR or any other byte refused by name): the system manifest is ASCII and parses by services.md §2 (fields, restart policy, decimal numbers, watchdog= before arg, an arg of at most 64 bytes, names of [A-Za-z0-9_-] up to 15 bytes, no duplicate, at most 16 services) and is under MANIFEST_MAX (4096 bytes); by the table of services.md §0.000 it names exactly auth, config, net, input, display, narrator, session, sh in that order, each with exactly the table's dependencies, every one declared on an earlier line, each on-failure, with a readiness timeout no shorter than 60000 for auth and 30000 for session, and watchdog= on input and display; every image path is /SYSTEM/<8.3 name>.ELF of an application the build makes (target.json extra_artifacts); watchdog= only on a service whose source sends PONG through channel_write (a textual check: whether that write answers the manager's PING is not checked, the guest case TST-M5-LOCK-HANG is; a compare with PONG, as in svcmgr, does not count); selftest.txt is ASCII, has no service line and its comment names mode=selftest; the lint itself rejects one manifest per rule: a non-ASCII byte, 4096 bytes or more, never instead of on-failure, a timeout below the minimum (auth, session), session without config, a dependency set other than the table's (narrator, sh), no watchdog on input or display, a self-test manifest with a service or without mode=selftest, a line of 6 fields, a non-decimal watchdog, an arg over 64 bytes, a bad name, an unknown restart policy, a non-decimal number, more than 16 services, a service missing, two services swapped, a dependency on a later line, a duplicate, a watchdog on a service that never answers PONG, a non-8.3 image, an image the build does not make, a Tab, a CRLF line end, a control byte, and a `#` inside a line that cuts a field or a watchdog= (while a trailing comment longer than an arg is accepted, as svcmgr accepts it) (20 cases, OK)",
     "inputs": ["tests/test_m6_manifest.py", "platform/pc-qemu/target.json"], "input_globs": ["platform/pc-qemu/manifests/*.txt", "user/apps/*/src/main.rs"]},
]
HOST_SUITES["M1"] = [
    {"id": "TST-M1-NOBS", "command": ["python3", "-I", "tests/test_m1_nobs.py"],
     "oracle": "static: kmain.rs is safe-only (no unsafe allowed by main.rs), names no firmware table/efi symbol; boot::efi is private; BootInfo carries no function pointers; kernel_main takes &BootInfo only",
     "inputs": ["tests/test_m1_nobs.py", "kernel/src/main.rs", "kernel/src/kmain.rs", "kernel/src/bootinfo.rs", "kernel/src/boot/mod.rs", "kernel/src/boot/stub.rs"], "input_globs": []},
]


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


def derive_position(work_items, requirements):
    """Where the project stands, from the records alone: the current task is the first active
    work item, else the first planned one whose dependencies are all done; its stage is the
    current stage; completed requirements are those verified in scope. (Review 2026-10-19,
    T-8: checkpoints never updated these fields, so project-state still said M2/WP-07 in M5.)"""
    by_id = {w["id"]: w for w in work_items}
    task = next((w for w in work_items if w["status"] == "active"), None)
    if task is None:
        task = next((w for w in work_items if w["status"] == "planned"
                     and all(by_id.get(d, {}).get("status") == "done" for d in w["depends_on"])), None)
    done = [r["id"] for r in requirements if r["implementation_status"] == "verified_in_scope"]
    return {
        "current_task": task["id"] if task else None,
        "current_stage": task["stage"] if task else None,
        "next_action": f"{task['id']}: {task['actions'][0]}" if task and task["actions"] else None,
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
                          load_json(DOCS / "requirements.json")["records"])
    for key, value in pos.items():
        if value is not None:
            ps[key] = value
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
    # The branch is checked out into a temporary copy, removed when the import ends (left
    # behind, 44 copies filled the workspace's disk on 2026-10-19), through an index of its own
    # inside the copy: the repository's index, and what the user has staged in it, stay as
    # they were.
    tmp = Path(tempfile.mkdtemp(prefix="ci-ev-"))
    imported = 0
    try:
        subprocess.run(["git", f"--work-tree={tmp}", "checkout", "-q", f"ci/{run_id}", "--", "evidence"], cwd=ROOT, check=True,
                       env={**os.environ, "GIT_INDEX_FILE": str(tmp / ".index")})
        for d in sorted((tmp / "evidence").iterdir()):
            if not (d / "verdict.json").exists():
                continue
            dest = EVIDENCE / d.name
            if dest.exists():
                continue
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
    s = sub.add_parser("check-commit", help="the head commit names only an active or done work item (DEC-004)"); s.add_argument("--rev", default="HEAD")
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
