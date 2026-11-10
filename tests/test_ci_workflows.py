"""TST-M0-003 (host, REQ-M0-005): the verification runner's workflow files — every file under
.github/workflows parses as YAML with a name, triggers and jobs (a malformed file is a failed run
on every push: five such runs on 2026-10-18); `verify` runs on pushes to main, pull requests and
by hand, gives its job a time limit, and cancels the run a newer push to the same ref supersedes
(42 of the 59 failed verify runs that day had been superseded within ten minutes and still ran
to their end and mailed the account); `mutants` never runs on a push. The local pre-flight
(`project.py preflight`) builds with build-std from the library source at the compiler's own
commit, with scratch evidence only. `project.py import-ci-evidence` leaves no temporary copy of
the runner's evidence behind."""

import json
import re
import os
import shutil
import pathlib
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
sys.path.insert(0, str(ROOT / "tools"))
import project  # noqa: E402


def load(name):
    doc = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    # YAML 1.1 reads the bare key `on` as the boolean true.
    doc["on"] = doc.pop(True, doc.get("on"))
    return doc


class Workflows(unittest.TestCase):
    def test_every_workflow_parses(self):
        files = sorted(WORKFLOWS.glob("*.yml"))
        self.assertGreaterEqual(len(files), 2)
        for f in files:
            doc = load(f.name)
            for key in ("name", "on", "jobs"):
                self.assertIn(key, doc, f"{f.name}: no `{key}`")
            for job, body in doc["jobs"].items():
                self.assertIn("runs-on", body, f"{f.name}: job {job} has no runner")
                self.assertTrue(body.get("steps"), f"{f.name}: job {job} has no steps")

    def test_verify_triggers_limit_and_cancellation(self):
        doc = load("verify.yml")
        on = doc["on"]
        self.assertEqual(on["push"]["branches"], ["main"])
        self.assertIn("pull_request", on)
        self.assertIn("workflow_dispatch", on)
        self.assertTrue(all("timeout-minutes" in j for j in doc["jobs"].values()))
        group = doc.get("concurrency", {})
        self.assertIn("${{ github.ref }}", str(group.get("group", "")),
                      "runs of one ref share a concurrency group")
        self.assertIs(group.get("cancel-in-progress"), True,
                      "a newer push cancels the run it supersedes")

    def test_every_action_is_pinned_to_a_commit(self):
        # A tag can be moved to other code; a commit cannot (the audit of 2026-10-19). The
        # comment after the pin names the release it was taken from.
        for f in sorted(WORKFLOWS.glob("*.yml")):
            for job, body in load(f.name)["jobs"].items():
                for step in body["steps"]:
                    uses = step.get("uses")
                    if uses is None:
                        continue
                    ref = uses.rpartition("@")[2]
                    self.assertRegex(ref, r"^[0-9a-f]{40}$", f"{f.name}: {job} uses {uses}")

    def test_only_the_publish_step_holds_the_token(self):
        # The code under test runs in the same job: the checkout keeps no credentials in
        # .git/config, and the token reaches the evidence push alone.
        for f in sorted(WORKFLOWS.glob("*.yml")):
            text = (WORKFLOWS / f.name).read_text(encoding="utf-8")
            for job, body in load(f.name)["jobs"].items():
                for step in body["steps"]:
                    if step.get("uses", "").startswith("actions/checkout@"):
                        self.assertIs(step.get("with", {}).get("persist-credentials"), False,
                                      f"{f.name}: {job}: checkout keeps the token")
                holders = [s.get("name") for s in body["steps"] if "github.token" in str(s)
                           or "secrets." in str(s)]
                self.assertLessEqual(len(holders), 1, f"{f.name}: {job}: {holders}")
                if holders:
                    self.assertTrue(holders[0].startswith("Publish evidence"), holders)
            self.assertNotIn("secrets.", text, f"{f.name} reads a secret")

    def test_mutants_never_on_push(self):
        on = load("mutants.yml")["on"]
        self.assertNotIn("push", on)
        self.assertIn("workflow_dispatch", on)

    def test_toolchain_downloads_are_bounded_and_retried(self):
        # Runs 39960346156, 39966156761 and 39966899234 (2026-10-23): the Toolchain step, about
        # 80 s on a good day, hung for 34-40 minutes and the job hit its 40-minute limit before
        # any test ran. A download that hangs must fail fast and be tried again, and the step
        # must end long before the job's limit.
        downloads = ("apt-get ", "rustup toolchain install", "rustup target add")
        for name in ("verify.yml", "mutants.yml"):
            for job, body in load(name)["jobs"].items():
                steps = [s for s in body["steps"] if s.get("name", "").startswith("Toolchain")]
                self.assertEqual(len(steps), 1, f"{name}: {job}: one Toolchain step")
                step = steps[0]
                self.assertLessEqual(step.get("timeout-minutes", 10**6), 15,
                                     f"{name}: {job}: the Toolchain step has no short limit")
                run = step["run"]
                self.assertRegex(run, r"retry\(\) \{[^}]*timeout \d+ ",
                                 f"{name}: {job}: no retry with a per-attempt timeout")
                # Run 40362082749's healthy Toolchain step took 5 minutes; in run 40367178852 a
                # 240 s attempt limit killed one download three times and failed the job. An
                # attempt must outlast a slow download, all attempts must end inside the step's
                # limit, and each failed attempt leaves an annotation (the logs may be
                # unreadable, the check-run annotations are not).
                m = re.search(r"retry\(\) \{ for i in ([\d ]+); do (?:s=\$SECONDS; )?timeout (\d+) [^}]*sleep (\d+)", run)
                self.assertIsNotNone(m, f"{name}: {job}: retry() not in the expected form")
                attempts, limit, pause = len(m.group(1).split()), int(m.group(2)), int(m.group(3))
                self.assertGreaterEqual(limit, 300, f"{name}: {job}: an attempt dies before a slow download ends")
                self.assertGreaterEqual(attempts, 2, f"{name}: {job}: no second attempt")
                self.assertLessEqual(attempts * limit + (attempts - 1) * pause, step["timeout-minutes"] * 60,
                                     f"{name}: {job}: the attempts outlast the step")
                self.assertIn("::warning", run, f"{name}: {job}: a failed attempt leaves no annotation")
                for line in (l.strip() for l in run.splitlines()):
                    if any(d in line for d in downloads) and not line.startswith("retry() {"):
                        self.assertTrue(line.startswith(("retry ", "if ! retry ")),
                                        f"{name}: {job}: download not retried: {line}")
                # Runs 40397445659 and 40397458355 (2026-10-26, 20:38-21:11): `apt-get install`
                # hit its limit in all four attempts while the same commit's step had taken a
                # minute at 20:10. Each failed attempt says how it ended and how much it had
                # fetched; packages are fetched apart from their installation so a second attempt
                # keeps what the first one got; when the runner's mirror fails twice the packages
                # come from Canonical's archive; nothing may wait for an answer on a terminal.
                self.assertRegex(run, r"rc=\$rc", f"{name}: {job}: the annotation omits the exit code")
                self.assertIn("/var/cache/apt/archives", run,
                              f"{name}: {job}: the annotation omits how much was fetched")
                lines = [l.strip() for l in run.splitlines()]
                fetch = [i for i, l in enumerate(lines) if "apt-get " in l and " install --download-only " in l]
                install = [i for i, l in enumerate(lines) if "apt-get " in l and " install " in l
                           and "--download-only" not in l]
                self.assertTrue(fetch and install and max(fetch) < min(install),
                                f"{name}: {job}: packages are not fetched before they are installed")
                self.assertIn("archive.ubuntu.com", run, f"{name}: {job}: no fallback mirror")
                for i in fetch + install:
                    self.assertIn("DEBIAN_FRONTEND=noninteractive", lines[i],
                                  f"{name}: {job}: apt may wait for an answer: {lines[i]}")

    def test_a_rerun_replaces_the_published_evidence(self):
        # Run 40397458355, attempt 2: the evidence branch of the first attempt already existed and
        # the plain push was refused, so the step failed. A re-run's evidence replaces it.
        step = next(s for j in load("verify.yml")["jobs"].values() for s in j["steps"]
                    if str(s.get("name", "")).startswith("Publish evidence"))
        push = [l for l in step["run"].splitlines() if " push " in l]
        self.assertEqual(len(push), 1)
        self.assertRegex(push[0], r" push (-q )?(-f|--force) ", "a re-run cannot replace the evidence branch")


class Suites(unittest.TestCase):
    """The lab and the workflow name the same suites (docs/PLAN-ANSWER.md §2.5 D5): every guest
    suite of platform/pc-qemu/target.json has its verify step and every verify step names a
    suite that exists; every host suite the workflow does not run by design (the mutation gates,
    M2 whose host suite is its gate) is excluded by name, every other one is non-empty and run."""

    def steps(self):
        return [s for job in load("verify.yml")["jobs"].values() for s in job["steps"]]

    def suite_args(self, kind):
        found = set()
        for s in self.steps():
            for line in str(s.get("run", "")).splitlines():
                m = re.search(rf"--target {kind} --suite (\S+)", line)
                if m:
                    found.add(m.group(1))
        return found

    def test_every_guest_suite_runs_in_verify(self):
        target = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(target["suites"]), sorted(self.suite_args("pc-qemu")))

    def test_every_host_suite_is_nonempty_and_runs_in_verify(self):
        excluded = {"M2"}  # its host suite is the M2 mutation gate, run by the mutants workflow
        expected = {k for k in project.HOST_SUITES if not k.endswith("-GATE") and k not in excluded}
        self.assertEqual([k for k in expected if not project.HOST_SUITES[k]], [])
        self.assertEqual(sorted(expected), sorted(self.suite_args("host")))


class StepBudget(unittest.TestCase):
    """The verify job's time budget (docs/PLAN-ANSWER.md §2.5 D4-V2): the guest suites that can
    hang until the job's limit carry their own cap (M5: 11m34s measured, cap 18; M6: cap 15 since WP-64) and
    the sum of every step cap with a 20 % margin stays within the job's limit (55: 12+18+15 = 45,
    x1.2 = 54), so a hung step ends with its own name instead of the job's timeout. A capped
    suite whose cases are bounded by their own timeouts (M6) must fit its cap in the worst case:
    the sum over its cases of each phase's timeout_s stays below the cap. M5 is outside that
    rule: its cap is a hang guard set from a measured run (its worst case is 33 cases of up to
    300 s each), not a bound on its timeouts. The budget only sees steps that carry a cap: an
    uncapped step (the build, M1-M4, the host suites) runs until the job's limit (G9)."""

    BOUNDED = ("M6",)

    def caps(self):
        job = load("verify.yml")["jobs"]["verify"]
        caps = {}
        for s in job["steps"]:
            for line in str(s.get("run", "")).splitlines():
                m = re.search(r"--target pc-qemu --suite (\S+)", line)
                if m and s.get("timeout-minutes") is not None:
                    caps[m.group(1)] = s["timeout-minutes"]
        return job, caps

    def test_guest_steps_are_capped_within_the_job_limit(self):
        job, caps = self.caps()
        self.assertEqual(job["timeout-minutes"], 55)
        # M6 12 -> 15 (WP-64, 2026-11-10): PURGE-FAIL-CLOSED, TOKEN-REVOKE and WP-46's JOB-KILL
        # bring its worst case to 755 s (test_a_bounded_suite_fits_its_cap_in_the_worst_case).
        self.assertEqual(caps, {"M5": 18, "M6": 15})
        total = sum(int(s["timeout-minutes"]) for s in job["steps"] if "timeout-minutes" in s)
        self.assertLessEqual(total * 1.2, job["timeout-minutes"], f"step caps {total} min + 20 % exceed the job's limit")

    def test_a_bounded_suite_fits_its_cap_in_the_worst_case(self):
        _, caps = self.caps()
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        default = t["qemu"]["boot_timeout_s"]
        for suite in self.BOUNDED:
            worst = sum(p.get("timeout_s", c.get("timeout_s", default))
                        for c in t["suites"][suite] for p in (c.get("phases") or [{}]))
            self.assertLess(worst, caps[suite] * 60, f"{suite}: worst case {worst} s, cap {caps[suite]} min")


class HoldFailClosed(unittest.TestCase):
    """WP-67 (display.md v1.12): TST-M6-HOLD-FAIL-CLOSED runs in the M6 verify step on the test
    image with its ktest key, inside the step's cap (StepBudget), and judges each failure branch
    of displayd's LIST by the compositor's own trace and by the held screen: every branch named
    by the contract is required held (locked=1) and its unheld line is forbidden, so a fail-open
    regression (mutant M147) fails the case."""

    CASE = "TST-M6-HOLD-FAIL-CLOSED"
    KEY = ["-fw_cfg", "name=opt/nawah/test,string=hold_fail_closed"]
    HELD = ["display|hold|source=list_failure|reason=reply|locked=1",
            "display|hold|source=list_failure|reason=too_long|locked=1",
            "display|hold|source=list_failure|reason=closed|locked=1",
            "display|hold|source=manifest|reason=-|locked=0",
            "display|hold|source=manifest|reason=-|locked=1"]
    # The ktest's own verdict lines (kernel/src/ktest.rs hold_fail_closed): the kernel cannot see
    # SYS_TRACE output, so these judge the screen (HOLDS, keys at the client) and the trace lines
    # above judge displayd's decision.
    VERDICTS = ["|ktest|hold_fail_closed|case=reply|holds=OK locked=1 releases=0|keys=0|keys_in=2|",
                "|ktest|hold_fail_closed|case=too_long|holds=OK locked=1 releases=0|keys=0|keys_in=2|",
                "|ktest|hold_fail_closed|case=closed|holds=none_no_ready|exit=0xe6|ok=1",
                "|ktest|hold_fail_closed|case=manifest|locked=0|locked_with_session=1|",
                "|ktest|hold_fail_closed|failed=|processes_after=0|clean=1|frames_delta=0"]
    UNHELD = ["holds=OK locked=0", "reason=reply|locked=0", "reason=too_long|locked=0"]

    def test_the_hold_case_runs_on_the_test_image_in_m6(self):
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        cases = [c for c in t["suites"]["M6"] if c["id"] == self.CASE]
        self.assertEqual(len(cases), 1, f"{self.CASE} is not one case of suites.M6")
        c = cases[0]
        self.assertEqual(c["test_id"], self.CASE)
        self.assertEqual(c["artifact"], "${OUT}/NAWAH-KTEST.EFI")
        self.assertEqual(c["qemu_extra"], self.KEY)
        self.assertEqual(c["expected_exit_code"], 33)
        self.assertEqual(c["timeout_s"], 60)  # measured 8 s on CI; WP-64 moved 120 s of the M6 cap to PURGE-FAIL-CLOSED
        self.assertIn("OSX|${BUILD_ID}|ktest|start|name=hold_fail_closed", c["required_markers"])
        for m in self.HELD + self.VERDICTS + ["|ktest|pass|"]:
            self.assertIn(m, c["required_markers"])
        for m in self.UNHELD + ["|ktest|fail|", "|kernel|panic|"]:
            self.assertIn(m, c["forbidden_markers"])
        # No required marker may also be forbidden (a case that can never pass).
        self.assertEqual([m for m in c["required_markers"] if any(f in m for f in c["forbidden_markers"])], [])


class BootCase(unittest.TestCase):
    """`project.py boot` and the suite judge one boot test by one oracle (docs/PLAN-ANSWER.md
    §2.6 D1-A): the suite case carrying the boot test id is the oracle even when it carries
    QEMU arguments (the lab self-test key, WP-45); two such cases are ambiguous and refused;
    `boot_oracle` carries the same key; the key's name is the one the kernel reads."""

    KEY = ["-fw_cfg", "name=opt/nawah/selftest,string=1"]

    def target(self):
        return json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))

    def test_the_suite_case_with_qemu_args_is_the_boot_oracle(self):
        t = {"boot_oracle": {"test_id": "B"}, "suites": {"S": [{"id": "x", "test_id": "A"},
                                                                {"id": "b", "test_id": "B", "qemu_extra": self.KEY}]}}
        self.assertEqual(project.select_boot_case(t)["id"], "b")
        self.assertIsNone(project.select_boot_case({"boot_oracle": {"test_id": "B"}}))

    def test_two_cases_of_the_boot_test_are_refused(self):
        t = {"boot_oracle": {"test_id": "B"}, "suites": {"S": [{"id": "b1", "test_id": "B"}],
                                                         "T": [{"id": "b2", "test_id": "B", "qemu_extra": self.KEY}]}}
        with self.assertRaises(ValueError):
            project.select_boot_case(t)

    def test_boot_oracle_carries_the_suite_cases_key(self):
        t = self.target()
        case = project.select_boot_case(t)
        self.assertEqual(case["test_id"], "TST-M1-BOOT")
        self.assertEqual(case.get("qemu_extra"), self.KEY)
        self.assertEqual(t["boot_oracle"].get("qemu_extra"), case["qemu_extra"])

    def test_the_kernel_reads_the_key_the_lab_passes(self):
        name = self.KEY[1].split(",", 1)[0].split("=", 1)[1]
        # The test kernel's own sources (ktest.rs) do not count: the release kernel must read it.
        hits = [p for p in (ROOT / "kernel" / "src").rglob("*.rs")
                if p.name != "ktest.rs" and name in p.read_text(encoding="utf-8")]
        self.assertTrue(hits, f"no kernel source outside ktest.rs names the fw_cfg key {name!r}")

    # The boot-mode line as the kernel prints it (kernel/src/kmain.rs: `OSX|<build id>|kernel|
    # boot_mode|<BootMode>`; kernel/src/bootmode.rs Display: source=fw_cfg only for selftest,
    # so an invalid key and a missing signature both print source=none).
    LINE = "OSX|${BUILD_ID}|kernel|boot_mode|mode=%s|source=%s|key=%s|hv=%d"
    PHASES = [("interactive", "none", "absent", 1),    # 1: no key
              ("interactive", "none", "invalid", 1),   # 2: selftest=0
              ("interactive", "none", "absent", 1),    # 3: the ktest key alone
              ("interactive", "none", "invalid", 1),   # 4: selftest=svc-sh
              ("interactive", "none", "absent", 0),    # 5: -hypervisor with the key
              ("interactive", "none", "invalid", 1)]   # 6: selftest=10

    def test_every_boot_requires_its_whole_boot_mode_line(self):
        """Anti-spoofing (WP-45 red team): SYS_TRACE needs no right, so a process can print any
        fragment (`|key=invalid|`, `|hv=0`). Each phase requires the kernel's whole line with the
        build id instead, and the case caps `|kernel|boot_mode|` at one per boot: a traced copy of
        the whole line contains that marker, so it makes a seventh occurrence and fails the case
        (a traced line cannot hold a newline either: syscall/mod.rs prints 0x0A as '?')."""
        t = self.target()
        case = next(c for c in t["suites"]["M6"] if c["id"] == "TST-M6-INTERACTIVE-BOOT")
        self.assertEqual(len(case["phases"]), len(self.PHASES))
        for i, (ph, want) in enumerate(zip(case["phases"], self.PHASES), 1):
            line = self.LINE % want
            mode_markers = [m for m in ph["required_markers"] if "boot_mode" in m or "|key=" in m or "|hv=" in m]
            self.assertEqual(mode_markers, [line], f"phase {i}")
        self.assertEqual(case["max_counts"].get("|kernel|boot_mode|"), len(self.PHASES))
        self.assertEqual(case["min_counts"].get("|kernel|boot_mode|"), len(self.PHASES))
        boot = project.select_boot_case(t)
        mode_markers = [m for m in boot["required_markers"] if "boot_mode" in m]
        self.assertEqual(mode_markers, [self.LINE % ("selftest", "fw_cfg", "ok", 1)])
        # The lab resolves ${BUILD_ID} in a phase's markers and in the case's (cmd_boot).
        src = (ROOT / "tools" / "project.py").read_text(encoding="utf-8")
        self.assertIn('req = [m.replace("${BUILD_ID}", build_id) for m in ph.get("required_markers", [])]', src)
        self.assertIn('required = [m.replace("${BUILD_ID}", build_id) for m in case["required_markers"]]', src)


# PLAN-ANSWER §3.4 item 3: fw_cfg is host-controlled input, so the only kernel code that may
# reach it is the boot-mode decision (bootmode.rs), the test kernel's case selector (ktest.rs)
# and the driver itself (fwcfg.rs). A new caller would widen what the host can steer on a
# release boot; this guard makes that a reviewed change of the allowed set, not a silent one.
FWCFG_CALLERS = {"kernel/src/bootmode.rs", "kernel/src/ktest.rs", "kernel/src/arch/x86_64/fwcfg.rs"}
# Files that may name the module (declare or re-export it) without calling into it.
FWCFG_DECLARERS = {"kernel/src/arch/mod.rs", "kernel/src/arch/x86_64/mod.rs"}
FWCFG_FILE = "kernel/src/arch/x86_64/fwcfg.rs"


def fwcfg_violations(root):
    """Kernel sources that reach fw_cfg outside the allowed set: an exact identifier match
    (word boundaries, so `read_file_x` or `my_read_file` do not count) on every public entry of
    fwcfg.rs (read_file, hypervisor_present, any later one), on the module name `fwcfg`, and on
    the fw_cfg ports 0x510/0x511 (a second driver poking the ports directly)."""
    root = pathlib.Path(root)
    entries = re.findall(r"^pub fn (\w+)", (root / FWCFG_FILE).read_text(encoding="utf-8"), re.M)
    bad = []
    for p in sorted((root / "kernel" / "src").rglob("*.rs")):
        rel = p.relative_to(root).as_posix()
        if rel in FWCFG_CALLERS:
            continue
        text = p.read_text(encoding="utf-8")
        for ident in entries:
            if re.search(rf"\b{ident}\b", text):
                bad.append(f"{rel}: {ident}")
        if rel not in FWCFG_DECLARERS and re.search(r"\bfwcfg\b", text):
            bad.append(f"{rel}: fwcfg")
        if re.search(r"\b0x51[01]\b", text, re.I):
            bad.append(f"{rel}: fw_cfg port")
    return entries, bad


class FwCfgCallers(unittest.TestCase):
    def test_fw_cfg_is_reached_only_from_the_boot_mode_and_the_test_kernel(self):
        entries, bad = fwcfg_violations(ROOT)
        self.assertIn("read_file", entries)
        self.assertEqual(bad, [])

    def test_the_guard_sees_a_new_caller(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            for rel in FWCFG_CALLERS | FWCFG_DECLARERS:
                (d / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / rel, d / rel)
            (d / "kernel/src/net.rs").write_text("use crate::arch::fwcfg::read_file as rf;\nfn x() { rf(\"a\", &mut []); }\n")
            (d / "kernel/src/disk.rs").write_text("fn y() { unsafe { outw(0x510, 0) } }\n")
            (d / "kernel/src/vfs.rs").write_text("fn read_file_at() {}\n")
            self.assertEqual(fwcfg_violations(d)[1], ["kernel/src/disk.rs: fw_cfg port",
                                                      "kernel/src/net.rs: read_file", "kernel/src/net.rs: fwcfg"])


class Preflight(unittest.TestCase):
    def test_preflight_runs_the_ci_hygiene_commands(self):
        # The local gate is CI's hygiene step itself, read from verify.yml (CI run 39185115793
        # failed on a clippy configuration the local pre-flight never ran).
        env, cmds = project.hygiene_commands()
        step = next(s for j in load("verify.yml")["jobs"].values() for s in j["steps"]
                    if str(s.get("name", "")).startswith(project.HYGIENE_STEP))
        script = [l.strip() for l in step["run"].splitlines()]
        expected = [l for l in script if l.startswith(("cargo ", "sh tools/"))]
        self.assertEqual(cmds, expected)
        self.assertEqual(env, {str(k): str(v) for k, v in (step.get("env") or {}).items()})
        self.assertIn("cargo fmt --all --check", cmds)
        kernel = [c for c in cmds if "kernel/Cargo.toml" in c]
        self.assertTrue(any("--features" not in c and "x86_64-unknown-uefi" in c for c in kernel),
                        "the production kernel (no ktest) must be linted")
        self.assertTrue(any("--features ktest" in c for c in kernel))
        self.assertTrue(any("aarch64-unknown-uefi" in c for c in kernel))
        self.assertTrue(all("-D warnings" in c for c in cmds if c.startswith("cargo clippy")))
        self.assertIn("sh tools/check-unsafe.sh", cmds)
        # Locally only --offline is dropped; the lint configuration is unchanged.
        c = "cargo clippy --manifest-path kernel/Cargo.toml --target x86_64-unknown-uefi --offline -- -D warnings"
        self.assertEqual(project.local_hygiene_argv(c),
                         ["cargo", "clippy", "--manifest-path", "kernel/Cargo.toml", "--target",
                          "x86_64-unknown-uefi", "--", "-D", "warnings"])
        # And pre-flight runs it, after fmt and before the build.
        import inspect
        src = inspect.getsource(project.cmd_preflight)
        self.assertLess(src.index('"fmt"'), src.index("cmd_hygiene()"))
        # The records come first (CI run 39196967624 failed on a record error alone).
        self.assertLess(src.index("validate_records("), src.index('"fmt"'))
        self.assertLess(src.index("cmd_hygiene()"), src.index('"build"'))
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "w.yml"
            p.write_text("name: x\njobs:\n  a:\n    runs-on: u\n    steps:\n      - run: echo\n")
            with self.assertRaises(ValueError):
                project.hygiene_commands(p)

    def test_environment(self):
        env = project.preflight_env({"PATH": "/bin", "RUSTUP_TOOLCHAIN": "t"}, "/tmp/scratch", True)
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "t")
        self.assertEqual(env["RUSTC_BOOTSTRAP"], "1")
        self.assertEqual(env["CARGO_UNSTABLE_BUILD_STD"], "core,alloc,compiler_builtins")
        self.assertEqual(env["CARGO_UNSTABLE_BUILD_STD_FEATURES"], "compiler-builtins-mem")
        # Evidence of a pre-flight never reaches the records.
        self.assertEqual(env["NAWAH_SCRATCH_EVIDENCE"], "/tmp/scratch")
        # The test step builds host tools: no build-std there, even when the caller had it.
        test_env = project.preflight_env(env, "/tmp/scratch", False)
        for k in ("RUSTC_BOOTSTRAP", "CARGO_UNSTABLE_BUILD_STD", "CARGO_UNSTABLE_BUILD_STD_FEATURES"):
            self.assertNotIn(k, test_env)
        self.assertEqual(test_env["NAWAH_SCRATCH_EVIDENCE"], "/tmp/scratch")
        self.assertEqual(test_env["PATH"], "/bin")

    def test_library_source_must_match_the_compiler(self):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "rust"
            self.assertEqual(project.rust_src_state(src, "abc"), "missing")
            (src / "library").mkdir(parents=True)
            (src / "library" / "Cargo.lock").write_text("# lock\n")
            # rustup's rust-src has no git metadata: the same release, trusted.
            self.assertEqual(project.rust_src_state(src, "abc"), "ok")
            run = lambda *a: subprocess.run(["git", "-C", str(src), *a], check=True, capture_output=True, text=True)
            run("init", "-q")
            run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x")
            head = run("rev-parse", "HEAD").stdout.strip()
            self.assertEqual(project.rust_src_state(src, head), "ok")
            self.assertEqual(project.rust_src_state(src, "0" * 40), f"mismatch:{head}")


class CiEvidenceImport(unittest.TestCase):
    """import-ci-evidence checks the runner's evidence branch out into a temporary directory and
    copies the runs from there: the copy goes when the import ends, whether it succeeds or not
    (2026-10-19: 44 left-over copies, 21 GB, filled the workspace's disk), and the repository's
    index is not touched (work the user had staged stays staged)."""

    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="nawah-import-"))
        self.addCleanup(shutil.rmtree, self.base, True)
        base = self.base
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(base), "TMPDIR": str(base / "tmp"),
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        (base / "tmp").mkdir()
        self.git(base, "init", "-q", "--bare", "origin")
        work = base / "work"
        self.git(base, "init", "-q", "work")
        self.run_dir = work / "evidence" / "20260101T000000Z-deadbeef-001"
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "verdict.json").write_text(json.dumps({"test_id": "TST-X", "verdict": "PASS"}))
        (self.run_dir / "run.json").write_text(json.dumps({"run_id": self.run_dir.name}))
        self.git(work, "checkout", "-q", "-b", "ci-evidence/42")
        self.git(work, "add", "-A")
        self.git(work, "commit", "-q", "-m", "evidence")
        self.git(work, "push", "-q", str(base / "origin"), "ci-evidence/42")
        # A runner branch without the evidence directory: the import's checkout fails.
        self.git(work, "checkout", "-q", "--orphan", "ci-evidence/43")
        self.git(work, "rm", "-q", "-r", "--cached", "evidence")
        (work / "other").write_text("x")
        self.git(work, "add", "other")
        self.git(work, "commit", "-q", "-m", "no evidence")
        self.git(work, "push", "-q", str(base / "origin"), "ci-evidence/43")
        self.root = base / "root"
        self.git(base, "init", "-q", "root")
        self.git(self.root, "remote", "add", "origin", str(base / "origin"))
        (self.root / "evidence").mkdir()
        (self.root / "base.txt").write_text("the committed base")
        self.git(self.root, "add", "base.txt")
        self.git(self.root, "commit", "-q", "-m", "base")
        head = self.git(self.root, "rev-parse", "HEAD").stdout.strip()
        (self.root / "staged.txt").write_text("the user's work")
        self.git(self.root, "add", "staged.txt")
        # The checked import (ADR-0026) asks gh for the run: a fake gh on PATH answers success
        # for a verify run whose head is the root's HEAD.
        bindir = base / "bin"; bindir.mkdir()
        gh = bindir / "gh"
        gh.write_text("#!/bin/sh\ncat <<'JSON'\n" + json.dumps({"status": "completed", "conclusion": "success", "headSha": head,
                                                                   "event": "pull_request", "workflowName": "verify", "attempt": 1}) + "\nJSON\n")
        gh.chmod(0o755)
        self.env["PATH"] = f"{bindir}:{self.env['PATH']}"

    def git(self, cwd, *args):
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True, capture_output=True, text=True)

    def run_import(self, run):
        return subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "project.py"), "import-ci-evidence", "--run", run],
                              env={**self.env, "NAWAH_ROOT": str(self.root)}, capture_output=True, text=True)

    def staged(self):
        return self.git(self.root, "diff", "--cached", "--name-only").stdout.split()

    def test_import_leaves_no_temporary_copy(self):
        r = self.run_import("42")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("imported 1 run(s) from CI run 42", r.stdout)
        self.assertTrue((self.root / "evidence" / self.run_dir.name / "verdict.json").exists())
        self.assertEqual(sorted(p.name for p in (self.base / "tmp").iterdir()), [])
        self.assertEqual(self.staged(), ["staged.txt"])

    def test_failed_import_leaves_no_temporary_copy(self):
        r = self.run_import("43")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("fetch failed", r.stdout)  # the checkout, not the fetch, failed
        self.assertEqual(sorted(p.name for p in (self.base / "tmp").iterdir()), [])
        self.assertEqual(self.staged(), ["staged.txt"])


class CheckCommit(unittest.TestCase):
    """DEC-004: a commit whose subject names a work item lands only while that item is active or
    done (OS-EXEC-AR §2.1). The breach it guards against: four WP-43 commits reached main while
    WP-43 was planned (21a979f9, f74a43c9, 1abd1f94, 41224c20). CI runs it on the head commit."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="nawah-commit-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.root), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "NAWAH_ROOT": str(self.root)}
        subprocess.run(["git", "init", "-q"], cwd=self.root, env=self.env, check=True)
        (self.root / "docs").mkdir()
        items = [{"id": "WP-01", "status": "active"}, {"id": "WP-02", "status": "planned"}, {"id": "WP-03", "status": "done"}]
        (self.root / "docs" / "work-items.json").write_text(json.dumps({"schema_version": "1.0.0", "records": items}))

    def check(self, subject):
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", subject], cwd=self.root, env=self.env, check=True)
        return subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "project.py"), "check-commit"],
                              env=self.env, capture_output=True, text=True)

    def test_a_commit_for_a_planned_item_is_rejected(self):
        for subject, rc in (("WP-01: work", 0), ("WIP WP-01 (1/n): work", 0), ("WP-03 records", 0),
                            ("records: CI run imported", 0), ("checkpoint: x", 0),
                            ("WP-02 M6: early work", 50), ("WIP WP-02 (1/n): early", 50), ("WP-99: unknown", 50)):
            r = self.check(subject)
            self.assertEqual(r.returncode, rc, subject + "\n" + r.stdout + r.stderr)

    def test_ci_runs_it(self):
        steps = [s.get("run", "") for j in load("verify.yml")["jobs"].values() for s in j["steps"]]
        self.assertTrue(any("project.py check-commit" in s for s in steps))


class MutationHarness(unittest.TestCase):
    def test_mutants_runs_the_gates_in_order_and_publishes_every_report(self):
        # WP-38 phase 1 (2026-10-28): the M5 step was added but its report was left out of the
        # evidence branch's `git add`, and no test held the gate order; the records check
        # before the runs was not strict.
        steps = next(iter(load("mutants.yml")["jobs"].values()))["steps"]
        names = [str(s.get("name", "")) for s in steps]
        gates = [n for n in names if n.startswith("Mutation run, ")]
        self.assertEqual([g.split(",")[1].strip()[:2] for g in gates], ["M2", "M3", "M4", "M5"],
                         "the gates run in order M2, M3, M4, M5")
        runs = [s["run"] for s in steps if str(s.get("name", "")).startswith("Mutation run, ")]
        self.assertEqual(runs, [f"python3 tools/project.py test --target host --suite {x}" for x in ("M2", "M3-GATE", "M4-GATE", "M5-GATE")])
        for s in steps[1:]:
            if str(s.get("name", "")).startswith("Mutation run, ") and not s["name"].startswith("Mutation run, M2"):
                self.assertEqual(s.get("if"), "always()", f"{s['name']}: a failed gate must not skip the next")
        validate = [s for s in steps if str(s.get("name", "")).startswith("validate-records")]
        self.assertEqual(len(validate), 1)
        self.assertIn("--strict", validate[0]["run"], "the records check before the runs is strict")
        publish = next(s for s in steps if str(s.get("name", "")).startswith("Publish evidence"))
        run = publish["run"]
        self.assertIn("git add -f evidence/", run)
        # Run 42481065666: one `git add` of every report failed when M2 had none, and the M5
        # report was lost with it; each report is added on its own, if it exists.
        self.assertNotRegex(run, r"git add -f evidence/ build/", "one missing report must not drop the others")
        loop = next(l for l in run.splitlines() if l.strip().startswith("for r in "))
        self.assertIn('if [ -f "$r" ]; then git add -f "$r"; fi', run)
        for rep in ("build/mutants-report.json", "build/mutants-m3-report.json", "build/mutants-m4-report.json", "build/mutants-m5-report.json"):
            self.assertIn(rep, loop, f"{rep} is not published on the evidence branch")

    def test_mutants_build_every_app_the_kernel_embeds_and_the_build_compiles(self):
        # Review 2026-10-19 (M8): the harness kept its own app list; WP-40 added exiter to the
        # kernel's embedded apps and the list did not follow, so every mutant build would fail.
        import re
        sys.path.insert(0, str(ROOT / "tests"))
        import mutants  # noqa: E402
        target = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        built = set(re.findall(r"user/apps/([a-z0-9_]+)/Cargo.toml", json.dumps(target["build"])))
        embedded = set(re.findall(r'^\s*"([a-z0-9_]+)",\s*$', (ROOT / "kernel" / "build.rs").read_text(encoding="utf-8"), re.M))
        self.assertTrue(embedded, "no embedded app list found in kernel/build.rs")
        self.assertEqual(set(mutants.APPS), built)
        self.assertLessEqual(embedded, set(mutants.APPS), "an app the kernel embeds is not built by the harness")
        self.assertEqual(len(mutants.APPS), len(set(mutants.APPS)))


if __name__ == "__main__":
    unittest.main()
