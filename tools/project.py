#!/usr/bin/env python3
"""nawah-os project interface (OS-EXEC-AR 3.2, section 20).

Exit codes (section 20): 0 ok | 10 no ready work package | 20 recorded blocker |
30 budget exhausted | 40 cancelled | 50 record validation failure | 60 internal error |
70 no worker configured.
"""
import argparse, hashlib, json, os, subprocess, sys, time, datetime, re
from pathlib import Path

ROOT = Path(os.environ.get("NAWAH_ROOT", Path(__file__).resolve().parents[1])).resolve()
DOCS = ROOT / "docs"
SCHEMAS = DOCS / "schemas"
EVIDENCE = ROOT / "evidence"
SCHEMA_VERSION = "1.0.0"
RECORD_FILES = ["requirements", "stages", "work-items", "tests", "risks", "sources", "hardware", "decisions-pending"]
SINGLE_FILES = ["project-state", "automation"]
LEGAL_TRANSITIONS = {("planned", "active"), ("active", "blocked"), ("active", "done"), ("blocked", "planned"), ("done", "planned"), ("active", "planned")}
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


def source_identity():
    rev = git("rev-parse", "HEAD") or "unknown"
    dirty = bool(git("status", "--porcelain"))
    return rev, dirty


# ----------------------------------------------------------------------------- validation
class Problems:
    def __init__(self):
        self.errors, self.warnings = [], []

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
    validate_schema("evidence-run", run, pb, f"{rel}/run.json")
    validate_schema("evidence-verdict", verdict, pb, f"{rel}/verdict.json")
    if pb.errors:
        return verdict
    if expect_test_id and verdict["test_id"] != expect_test_id:
        pb.err(where, f"evidence {rel} is for test {verdict['test_id']}, not {expect_test_id}")
    # recorded exit code must match run.json
    ec = (p / "exit_code").read_text().strip()
    if str(run["exit_code"]) != ec:
        pb.err(where, f"evidence {rel}: exit_code file ({ec}) != run.json ({run['exit_code']})")
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
        pb.err(where, f"evidence {rel}: inputs changed since verdict ({', '.join(stale)}); verdict must be NEEDS_REEVALUATION or re-run")
    return verdict


def validate_records(stage_scope=None, verbose=True) -> int:
    pb = Problems()
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
        if wi["status"] == "active":
            for d in wi["depends_on"]:
                if by_id["work-items"].get(d, {}).get("status") != "done":
                    pb.err(w, f"active while dependency {d} is not done")
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
    if verbose:
        for w in pb.warnings: print("WARN", w)
        for e in pb.errors: print("ERROR", e)
        print(f"validate-records: {len(pb.errors)} error(s), {len(pb.warnings)} warning(s)")
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


def run_logged(cmd, cwd, log_out, log_err, timeout):
    with open(log_out, "ab") as o, open(log_err, "ab") as e:
        o.write(f"$ {' '.join(cmd)}\n".encode()); o.flush()
        try:
            r = subprocess.run(cmd, cwd=cwd, stdout=o, stderr=e, timeout=timeout)
            return r.returncode
        except subprocess.TimeoutExpired:
            e.write(b"TIMEOUT\n"); return 124


def new_run_dir(purpose_slug):
    rev, _ = source_identity()
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    n = 1
    while True:
        rid = f"{ts}-{rev[:8]}-{n:03d}"
        d = EVIDENCE / rid
        if not d.exists():
            d.mkdir(parents=True); return rid, d
        n += 1


def write_run(d, rid, target, purpose, commands, exit_code, started, worker="interactive-agent", notes=None):
    rev, dirty = source_identity()
    run = {"schema_version": SCHEMA_VERSION, "run_id": rid, "started_at": started,
           "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "source_revision": rev, "dirty_state": dirty,
           "host": {"os": os.uname().sysname + " " + os.uname().release, "machine": os.uname().machine},
           "target": target, "worker": worker, "purpose": purpose, "commands": commands, "exit_code": exit_code}
    if notes: run["notes"] = notes
    (d / "run.json").write_text(json.dumps(run, ensure_ascii=False, indent=1) + "\n")
    (d / "command.txt").write_text("\n".join(commands) + "\n")
    (d / "exit_code").write_text(f"{exit_code}\n")
    for f in ("stdout.log", "stderr.log"):
        (d / f).touch()


def digests_for(paths):
    return {p: sha256_file(safe_rel(p)) for p in paths if safe_rel(p).exists()}


def write_verdict(d, rid, test_id, verdict, oracle, expected, observed, inputs, claim_tag="source_backed_fact", reason=None):
    combined = sha256_text("\n".join(f"{k}={v}" for k, v in sorted(inputs.items())))
    v = {"schema_version": SCHEMA_VERSION, "run_id": rid, "test_id": test_id, "verdict": verdict, "oracle": oracle,
         "expected": expected, "observed": observed, "inputs_digest": combined, "inputs": inputs, "claim_tag": claim_tag}
    if reason: v["reason"] = reason
    (d / "verdict.json").write_text(json.dumps(v, ensure_ascii=False, indent=1) + "\n")
    (d / "digests.json").write_text(json.dumps(inputs, indent=1) + "\n")
    return v


def cmd_build(target_name) -> int:
    t = load_target(target_name)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    rid, d = new_run_dir("build")
    rev, _ = source_identity()
    build_id = f"{rev[:12]}"
    env = dict(os.environ, NAWAH_BUILD_ID=build_id, NAWAH_OUT=str(ROOT / "build" / target_name))
    (ROOT / "build" / target_name).mkdir(parents=True, exist_ok=True)
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
        if rc != 0:
            break
    write_run(d, rid, target_name, "build", cmds, rc, started)
    inputs = digests_for(t["build"]["inputs"])
    art = t["build"]["artifact"].replace("${OUT}", f"build/{target_name}")
    observed = f"exit={rc}"
    if rc == 0 and safe_rel(art).exists():
        observed += f" artifact={art} sha256={sha256_file(safe_rel(art))}"
        (ROOT / "build" / target_name / "build-id.txt").write_text(build_id + "\n")
    verdict = "PASS" if rc == 0 and safe_rel(art).exists() else "FAIL"
    write_verdict(d, rid, t["build"]["test_id"], verdict, "all build steps exit 0 and artifact exists", "exit 0 + artifact", observed, inputs)
    print(f"build {target_name}: {verdict} run={rid} build_id={build_id}")
    return 0 if verdict == "PASS" else 1


def qemu_cmd(t, target_name, esp_dir, serial_log, extra=()):
    q = t["qemu"]
    cmd = [q["binary"], "-machine", q["machine"], "-cpu", q["cpu"], "-m", q["memory"], "-smp", str(q["smp"]),
           "-drive", f"if=pflash,format=raw,readonly=on,file={q['ovmf_code']}",
           "-drive", f"if=pflash,format=raw,file={ROOT / 'build' / target_name / 'OVMF_VARS.fd'}",
           "-drive", f"format=raw,file=fat:rw:{esp_dir}",
           "-serial", f"file:{serial_log}", "-display", "none", "-no-reboot",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", *extra]
    return cmd


def prepare_esp(t, target_name, artifact):
    import shutil
    esp = ROOT / "build" / target_name / "esp"
    if esp.exists(): shutil.rmtree(esp)
    (esp / "EFI" / "BOOT").mkdir(parents=True)
    shutil.copy(artifact, esp / "EFI" / "BOOT" / "BOOTX64.EFI")
    shutil.copy(t["qemu"]["ovmf_vars"], ROOT / "build" / target_name / "OVMF_VARS.fd")
    return esp


def cmd_boot(target_name, test_id=None, suite_case=None) -> int:
    t = load_target(target_name)
    art = safe_rel(t["build"]["artifact"].replace("${OUT}", f"build/{target_name}"))
    if not art.exists():
        print("no artifact; run build first"); return E_BLOCKED
    build_id = (ROOT / "build" / target_name / "build-id.txt").read_text().strip()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    rid, d = new_run_dir("boot")
    esp = prepare_esp(t, target_name, art)
    serial = d / "serial.log"
    extra = suite_case.get("qemu_extra", []) if suite_case else []
    cmd = qemu_cmd(t, target_name, esp, serial, extra)
    rc = run_logged(cmd, ROOT, d / "stdout.log", d / "stderr.log", t["qemu"]["boot_timeout_s"])
    write_run(d, rid, target_name, "boot" if not suite_case else f"test:{suite_case['id']}", [" ".join(cmd)], rc, started)
    text = serial.read_text(errors="replace") if serial.exists() else ""
    inputs = digests_for(t["build"]["inputs"]) | {t["build"]["artifact"].replace("${OUT}", f"build/{target_name}"): sha256_file(art)}
    case = suite_case or t["boot_oracle"]
    expected_rc = case["expected_exit_code"]
    required = [m.replace("${BUILD_ID}", build_id) for m in case["required_markers"]]
    forbidden = case.get("forbidden_markers", [])
    missing = [m for m in required if m not in text]
    present_forbidden = [m for m in forbidden if m in text]
    if rc == 124:
        verdict, reason = "FAIL", "timeout (hang)"
    elif rc != expected_rc:
        verdict, reason = "FAIL", f"exit {rc} != expected {expected_rc}"
    elif missing or present_forbidden:
        verdict, reason = "FAIL", f"missing markers {missing}; forbidden present {present_forbidden}"
    else:
        verdict, reason = "PASS", "exit code and serial markers match oracle"
    write_verdict(d, rid, case["test_id"], verdict, case["oracle"], f"exit={expected_rc}; markers={required}; forbidden={forbidden}",
                  f"exit={rc}; serial_lines={len(text.splitlines())}; missing={missing}; forbidden_present={present_forbidden}",
                  inputs, reason=reason)
    print(f"{'boot' if not suite_case else case['id']} {target_name}: {verdict} ({reason}) run={rid}")
    for line in text.splitlines()[:40]:
        print("  serial|", line)
    return 0 if verdict == "PASS" else 1


def cmd_test(target_name, suite) -> int:
    t = load_target(target_name)
    suites = t.get("suites", {})
    if suite not in suites:
        print(f"suite {suite} is not implemented for target {target_name}; implemented: {sorted(suites)}"); return E_INTERNAL
    rc_all = 0
    for case in suites[suite]:
        rc = cmd_boot(target_name, suite_case=case)
        rc_all |= rc
    print(f"suite {suite}: {'PASS' if rc_all == 0 else 'FAIL'}")
    return 0 if rc_all == 0 else 1


# ----------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(prog="project.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate-records")
    s = sub.add_parser("status"); s.add_argument("--json", action="store_true")
    for n in ("build", "boot"):
        s = sub.add_parser(n); s.add_argument("--target", required=True)
    s = sub.add_parser("test"); s.add_argument("--target", required=True); s.add_argument("--suite", required=True)
    for n in ("next", "report", "checkpoint", "resume", "run"):
        s = sub.add_parser(n); s.add_argument("--json", action="store_true"); s.add_argument("--result"); s.add_argument("--once", action="store_true"); s.add_argument("--until")
    a = ap.parse_args(argv)
    if a.cmd == "validate-records": return validate_records()
    if a.cmd == "status": return cmd_status(a.json)
    if a.cmd == "build": return cmd_build(a.target)
    if a.cmd == "boot": return cmd_boot(a.target)
    if a.cmd == "test": return cmd_test(a.target, a.suite)
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
