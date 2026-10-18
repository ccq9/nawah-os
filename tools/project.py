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
# Scratch mode (mutation runs, experiments): run directories go to this directory instead of
# evidence/ and verdicts are never attached to the records.
SCRATCH = Path(os.environ["NAWAH_SCRATCH_EVIDENCE"]).resolve() if os.environ.get("NAWAH_SCRATCH_EVIDENCE") else None
SCHEMA_VERSION = "1.0.0"
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
    def __init__(self, strict=False):
        # Tests whose stale verdicts stay a warning even under --strict (stale_policy: warn in
        # docs/tests.json): long gate-time runs such as mutation testing, re-run at gates.
        self.warn_only_tests = set()
        self.errors, self.warnings, self.stale = [], [], []
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
        msg = f"evidence {rel}: inputs changed since verdict ({', '.join(stale)}); needs re-evaluation (re-run or impact analysis)"
        if pb.strict and verdict.get("test_id") not in pb.warn_only_tests:
            pb.err(where, msg)
        else:
            pb.warn(where, msg)
            pb.stale.append(rel)
    return verdict


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


def run_logged(cmd, cwd, log_out, log_err, timeout):
    with open(log_out, "ab") as o, open(log_err, "ab") as e:
        o.write(f"$ {' '.join(cmd)}\n".encode()); o.flush()
        try:
            r = subprocess.run(cmd, cwd=cwd, stdout=o, stderr=e, timeout=timeout)
            return r.returncode
        except subprocess.TimeoutExpired:
            e.write(b"TIMEOUT\n"); return 124


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


def run_qemu_monitored(cmd, cwd, log_out, log_err, timeout, serial_path, monitor_path, actions):
    """`run_logged` for a QEMU case that drives the guest through the monitor (WP-27): once
    `actions["after"]` appears in the serial log, every line of `actions["commands"]` goes to
    the monitor socket (`sendkey a`, …), then QEMU runs to its end as usual."""
    import socket
    import time
    with open(log_out, "ab") as o, open(log_err, "ab") as e:
        o.write(f"$ {' '.join(cmd)}\n".encode()); o.flush()
        p = subprocess.Popen(cmd, cwd=cwd, stdout=o, stderr=e)
        deadline = time.monotonic() + timeout
        sent = False
        marker = actions["after"].encode()
        while p.poll() is None and time.monotonic() < deadline:
            if not sent and serial_path.exists() and marker in serial_path.read_bytes():
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as m:
                        m.settimeout(5)
                        m.connect(str(monitor_path))
                        time.sleep(0.3)
                        try:
                            m.recv(4096)
                        except OSError:
                            pass
                        for line in actions["commands"]:
                            m.sendall((line + "\n").encode())
                            time.sleep(float(actions.get("gap_s", 0.2)))
                    o.write(f"# monitor: sent {len(actions['commands'])} command(s) after {actions['after']!r}\n".encode()); o.flush()
                except OSError as ex:
                    e.write(f"monitor: {ex}\n".encode()); e.flush()
                sent = True
            time.sleep(0.1)
        if p.poll() is None:
            p.kill(); p.wait()
            e.write(b"TIMEOUT\n"); return 124
        return p.returncode


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
        if rc != 0:
            break
    write_run(d, rid, target_name, "build", cmds, rc, started)
    inputs = digests_for(t["build"]["inputs"], t["build"].get("input_globs", ()))
    art = t["build"]["artifact"].replace("${OUT}", f"build/{target_name}")
    observed = f"exit={rc}"
    if rc == 0 and safe_rel(art).exists():
        observed += f" artifact={art} sha256={sha256_file(safe_rel(art))}"
        (ROOT / "build" / target_name / "build-id.txt").write_text(build_id + "\n")
    verdict = "PASS" if rc == 0 and safe_rel(art).exists() else "FAIL"
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


def cmd_boot(target_name, test_id=None, suite_case=None) -> int:
    t = load_target(target_name)
    if suite_case is None:
        # One oracle per boot test: when a suite case carries the boot test id, it is the oracle
        # (`boot_oracle` is only the fallback for targets without suites).
        boot_id = t["boot_oracle"]["test_id"]
        for cases in t.get("suites", {}).values():
            for c in cases:
                if c["test_id"] == boot_id and not c.get("qemu_extra"):
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
    # speed); the environment variable still overrides everything (mutation runs).
    case_timeout = (suite_case or {}).get("timeout_s", t["qemu"]["boot_timeout_s"])
    timeout_s = int(os.environ.get("NAWAH_QEMU_TIMEOUT_S", case_timeout))
    plain_boot = suite_case is None or suite_case.get("_plain_boot")
    case = suite_case or t["boot_oracle"]
    # A case is one QEMU run, or several `phases` in sequence on the same disk image (the
    # persistence test): each phase has its own qemu_extra and markers; the case's own markers
    # and equal_values are checked against the concatenated serial output of all phases.
    phases = case.get("phases") or [{}]
    cmds, texts, rcs, phase_failures, lab_errors = [], [], [], [], []
    console_failures = []
    for i, ph in enumerate(phases):
        serial = d / ("serial.log" if len(phases) == 1 else f"serial-{i + 1}.log")
        disk = prepare_disk(t, target_name, fresh=(i == 0))
        extra = ph.get("qemu_extra", case.get("qemu_extra", []))
        actions = ph.get("monitor", case.get("monitor"))
        peers = HostServices(ph.get("host_services", case.get("host_services")))
        # A short socket path (AF_UNIX paths are limited to 107 bytes).
        monitor = (ROOT / "build" / target_name / f"mon{i + 1}.sock") if actions else None
        if monitor is not None:
            monitor.unlink(missing_ok=True)
        console_spec = ph.get("console", case.get("console"))
        cmd = qemu_cmd(t, target_name, esp, serial, extra, disk, ph.get("smp", case.get("smp")), monitor,
                       console_spec and console_spec["port"])
        run = (lambda: run_qemu_monitored(cmd, ROOT, d / "stdout.log", d / "stderr.log", timeout_s, serial, monitor, actions)) if actions \
            else (lambda: run_logged(cmd, ROOT, d / "stdout.log", d / "stderr.log", timeout_s))
        console = ConsoleSession(console_spec, d / "console.log", serial, timeout_s) if console_spec else None
        if console:
            console.start()
        try:
            rc = run()
        finally:
            peers.close()
            if console:
                console_failures = console.finish()
        if rc < 0:
            # QEMU itself died (signal): a lab failure, not a verdict on the kernel. One retry on
            # a fresh image; if it dies again the case fails and says why (LAB_ERROR), so a
            # mutation run never counts it as a kill (mutants run 39116036466: 4 SIGSEGVs).
            lab_errors.append(f"phase {i + 1}: qemu died with signal {-rc}, retried")
            serial.unlink(missing_ok=True)
            disk = prepare_disk(t, target_name, fresh=(i == 0))
            peers = HostServices(ph.get("host_services", case.get("host_services")))
            try:
                rc = run()
            finally:
                peers.close()
        text = serial.read_text(errors="replace") if serial.exists() else ""
        cmds.append(" ".join(cmd)); texts.append(text); rcs.append(rc)
        if len(phases) > 1:
            exp = ph.get("expected_exit_code", case["expected_exit_code"])
            req = [m.replace("${BUILD_ID}", build_id) for m in ph.get("required_markers", [])]
            fb = ph.get("forbidden_markers", [])
            miss = [m for m in req if m not in text]
            forb = [m for m in fb if m in text]
            if rc != exp or miss or forb:
                phase_failures.append(f"phase {i + 1}: exit {rc} (expected {exp}); missing {miss}; forbidden {forb}")
                break
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
    with open(d / "host-check.log", "w") as hc:
        for check in case.get("host_checks", []):
            cmd = [x.replace("${DISK}", str(disk_path)).replace("${BUILD_ID}", build_id) for x in check]
            r = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            hc.write(f"$ {' '.join(cmd)}\n{r.stdout}\n[exit {r.returncode}]\n")
            if r.returncode != 0:
                missing.append(f"host_check failed: {' '.join(cmd)} -> {r.returncode}")
    if rc < 0:
        verdict, reason = "FAIL", f"LAB_ERROR: qemu died with signal {-rc} twice"
        print(f"LAB_ERROR qemu died with signal {-rc} twice ({case['test_id']})")
    elif rc == 124:
        verdict, reason = "FAIL", "timeout (hang)"
    elif rc != expected_rc:
        verdict, reason = "FAIL", f"exit {rc} != expected {expected_rc}"
    elif missing or present_forbidden:
        verdict, reason = "FAIL", f"missing markers {missing}; forbidden present {present_forbidden}"
    else:
        verdict, reason = "PASS", "exit code and serial markers match oracle"
    if lab_errors:
        reason += "; " + "; ".join(lab_errors)
    write_verdict(d, rid, case["test_id"], verdict, case["oracle"], f"exit={expected_rc}; markers={required}; forbidden={forbidden}; phases={len(phases)}",
                  f"exit={rc}; serial_lines={len(text.splitlines())}; missing={missing}; forbidden_present={present_forbidden}",
                  inputs, reason=reason)
    attach_evidence(case["test_id"], rid, verdict)
    print(f"{'boot' if plain_boot else case['id']} {target_name}: {verdict} ({reason}) run={rid}")
    for line in text.splitlines()[:40]:
        print("  serial|", line)
    return 0 if verdict == "PASS" else 1


HOST_SUITES = {
    "M0": [
        {"id": "TST-M0-001", "command": ["python3", "-I", "tests/test_validate_records.py"], "oracle": "unittest exit 0 and 'OK' in output; 10 cases incl. 6 required rejections",
         "inputs": ["tools/project.py", "tools/schemas_gen.py", "tests/test_validate_records.py"], "input_globs": ["docs/schemas/*.schema.json"]},
        {"id": "TST-M0-002", "command": ["python3", "-I", "tests/test_m0_records.py"], "oracle": "required M0 documents and contract sections exist",
         "inputs": ["tests/test_m0_records.py", "docs/contracts/boot.md", "docs/adr/0001-bootstrap.md", "docs/PROJECT.md", "docs/ENVIRONMENT.md", "docs/security/threat-model.md"], "input_globs": []},
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
HOST_SUITES["M4"] = [
    {"id": "TST-M4-HASH-VECTORS", "command": ["cargo", "test", "--offline", "--release", "-p", "nawah-crypto", "--target", "x86_64-unknown-linux-gnu"],
     "oracle": "nawah-crypto's SHA-256 (FIPS 180-4 examples incl. the two-block message and the empty message, incremental = one-shot), HMAC-SHA-256 (RFC 4231 test cases 1, 2, 6, 7) and PBKDF2-HMAC-SHA-256 (RFC 7914 §11, 1 and 80000 iterations) known answers pass on the host (4 tests, 0 failed); the guest repeats them in the auth service (TST-M4-LOGIN)",
     "pass_marker": "test result: ok. 4 passed; 0 failed",
     "inputs": ["user/nawah-crypto/src/lib.rs", "user/nawah-crypto/Cargo.toml"], "input_globs": []},
    {"id": "TST-M4-SHELL-TOOL", "command": ["python3", "-I", "tests/test_console_session.py"],
     "oracle": "the lab's console session (ConsoleSession) against a fake shell over TCP: waits for the serial marker, splits output at the prompt, judges expect/absent/prompt/expect_serial, reports misses by step, a missing marker sends nothing (3 cases, OK)",
     "inputs": ["tests/test_console_session.py", "tools/project.py"], "input_globs": []},
]
HOST_SUITES["M3"] = [
    {"id": "TST-M3-FAT32-TOOL", "command": ["python3", "-I", "tests/test_fat32_tool.py"],
     "oracle": "the host FAT32 tool formats the lab volume (128992 clusters, 44 used), lists DIR/HELLO.TXT/PATTERN.BIN, reads files back exactly (cat/verify/expect), keeps the raw pattern tail, and fsck.fat -n accepts the image",
     "inputs": ["tests/test_fat32_tool.py", "tools/fat32.py"], "input_globs": []},
]
HOST_SUITES["M1"] = [
    {"id": "TST-M1-NOBS", "command": ["python3", "-I", "tests/test_m1_nobs.py"],
     "oracle": "static: kmain.rs is safe-only (no unsafe allowed by main.rs), names no firmware table/efi symbol; boot::efi is private; BootInfo carries no function pointers; kernel_main takes &BootInfo only",
     "inputs": ["tests/test_m1_nobs.py", "kernel/src/main.rs", "kernel/src/kmain.rs", "kernel/src/bootinfo.rs", "kernel/src/boot/mod.rs", "kernel/src/boot/stub.rs"], "input_globs": []},
]


def cmd_test_host(suite) -> int:
    if suite not in HOST_SUITES:
        print(f"host suite {suite} is not implemented; implemented: {sorted(HOST_SUITES)}"); return E_INTERNAL
    rc_all = 0
    for case in HOST_SUITES[suite]:
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
        verdict = "PASS" if rc == 0 and marker in out else ("ERROR" if rc == 124 else "FAIL")
        write_verdict(d, rid, case["id"], verdict, case["oracle"], f"exit 0 + {marker.strip()!r}", f"exit={rc}; tail={out.strip().splitlines()[-1] if out.strip() else ''}", inputs)
        print(f"{case['id']}: {verdict} run={rid}")
        attach_evidence(case["id"], rid, verdict)
        return 0 if verdict == "PASS" else 1


def replace_evidence_ref(old_ref, new_ref, test_id, verdict):
    """Set the test's verdict and evidence, and re-point requirement/work-item/stage records that
    cited the test's previous run directory. A previous ref is only re-pointed when it is a run
    directory whose verdict belongs to this very test — several tests may share a plain-file ref
    (e.g. a CI jobs.json) and that must never be rewritten on behalf of one of them."""
    own_old = False
    if old_ref:
        try:
            op = safe_rel(old_ref)
            own_old = op.is_dir() and (op / "verdict.json").exists() and load_json(op / "verdict.json")["test_id"] == test_id
        except (ValueError, json.JSONDecodeError, KeyError):
            own_old = False
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
            if own_old:
                for key in ("evidence_refs", "gate_evidence_refs"):
                    if key in r and old_ref in r[key]:
                        r[key] = [new_ref if x == old_ref else x for x in r[key]]; changed = True
        if changed:
            p.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


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
    if target_name == "host":
        return cmd_test_host(suite)
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


def cmd_checkpoint(note=None) -> int:
    rc = validate_records(verbose=False)
    if rc != 0:
        print("checkpoint refused: records invalid (run validate-records)"); return E_VALIDATION
    p = DOCS / "project-state.json"
    ps = load_json(p)
    rev, dirty = source_identity()
    ps["source_revision"], ps["dirty_state"] = rev, dirty
    ps["checkpoint_generation"] += 1
    if ps.get("lease"):
        ps["lease"]["fencing_token"] = ps["checkpoint_generation"]
    seq = append_event("checkpoint", "saved", task_id=ps.get("current_task"), result=note)
    ps["event_sequence"] = seq
    tmp = p.with_suffix(".json.tmp")
    data = json.dumps(ps, ensure_ascii=False, indent=1) + "\n"
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, p)  # atomic on POSIX
    print(f"checkpoint generation={ps['checkpoint_generation']} seq={seq} rev={rev[:8]} dirty={dirty}")
    return E_OK


# ----------------------------------------------------------------------------- CI evidence import
def cmd_import_ci_evidence(run_id: str) -> int:
    """Fetch the ci-evidence/<run> branch pushed by the verification runner and adopt its run
    directories as evidence (their input digests must match the current tree, which
    validate-records checks). Each imported verdict is attached to its test in docs/tests.json."""
    import shutil, tempfile
    ref = f"refs/heads/ci-evidence/{run_id}"
    r = subprocess.run(["git", "fetch", "-q", "origin", f"{ref}:refs/remotes/ci/{run_id}"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"fetch failed: {r.stderr.strip()}"); return E_BLOCKED
    tmp = Path(tempfile.mkdtemp(prefix="ci-ev-"))
    subprocess.run(["git", f"--work-tree={tmp}", "checkout", "-q", f"ci/{run_id}", "--", "evidence"], cwd=ROOT, check=True)
    imported = 0
    for d in sorted((tmp / "evidence").iterdir()):
        if not (d / "verdict.json").exists():
            continue
        dest = EVIDENCE / d.name
        if dest.exists():
            continue
        shutil.copytree(d, dest)
        v = load_json(dest / "verdict.json")
        run = load_json(dest / "run.json")
        run["notes"] = (run.get("notes", "") + f" imported from CI run {run_id} (verification runner)").strip()
        (dest / "run.json").write_text(json.dumps(run, ensure_ascii=False, indent=1) + "\n")
        attach_evidence(v["test_id"], d.name, v["verdict"])
        imported += 1
        print(f"imported {d.name} {v['test_id']} {v['verdict']}")
    # the runner's `git checkout` may have left the index pointing at the evidence tree; restore
    subprocess.run(["git", "reset", "-q"], cwd=ROOT)
    print(f"imported {imported} run(s) from CI run {run_id}")
    return E_OK


# ----------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(prog="project.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("validate-records"); s.add_argument("--strict", action="store_true"); sub.add_parser("reverify-host")
    s = sub.add_parser("import-ci-evidence"); s.add_argument("--run", required=True)
    s = sub.add_parser("status"); s.add_argument("--json", action="store_true")
    for n in ("build", "boot"):
        s = sub.add_parser(n); s.add_argument("--target", required=True)
    s = sub.add_parser("test"); s.add_argument("--target", required=True); s.add_argument("--suite", required=True)
    s.add_argument("--only", help="comma-separated case ids (guest suites)")
    for n in ("next", "report", "checkpoint", "resume", "run"):
        s = sub.add_parser(n); s.add_argument("--json", action="store_true"); s.add_argument("--result"); s.add_argument("--once", action="store_true"); s.add_argument("--until"); s.add_argument("--note")
    a = ap.parse_args(argv)
    if a.cmd == "validate-records": return validate_records(strict=a.strict)
    if a.cmd == "status": return cmd_status(a.json)
    if a.cmd == "build": return cmd_build(a.target)
    if a.cmd == "boot": return cmd_boot(a.target)
    if a.cmd == "test": return cmd_test(a.target, a.suite, a.only.split(",") if a.only else None)
    if a.cmd == "checkpoint": return cmd_checkpoint(a.note)
    if a.cmd == "reverify-host": return cmd_reverify_host()
    if a.cmd == "import-ci-evidence": return cmd_import_ci_evidence(a.run)
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
