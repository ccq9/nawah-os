#!/usr/bin/env python3
"""TST-M0-005: the mutation harness reports a kill only for a real one.

The M5 gate of 2026-10-31 (run 41232332567) timed out after three hours and, before it did,
its fairness sweep had read two infrastructure failures as kills on every surviving mutant:

  - TST-M5-DISPLAY-BOOT decodes the frame's build-id bar one hex digit per cell. The harness
    stamped each mutant `mutm94`, whose non-hex letters decoded to `000094` (bar_ok=0), so the
    case failed on every mutant for a reason that is not the mutant.
  - TST-M5-ELEVATE needs ~124 s on the clean tree, but the harness forced a 90 s QEMU timeout
    on every case, so ELEVATE timed out (exit 124) on every mutant.

Both would have been counted as kills of M93/M94/M97/M103/M106 — three of them security
mutants that in truth survive every real test. This test pins the three properties that keep a
sweep honest and bounded, without booting QEMU: the build id is hex, the per-case timeout
clears the slowest real case, and run_killers stops at the first genuine kill."""
import json
import pathlib
import re
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import mutants  # noqa: E402

# The slowest M5 case on the clean tree, start to finish of its committed run (a number in a test
# cites a record, not a run outside the records): TST-M5-ELEVATE,
# evidence/20261109T104517Z-dece70c2-001, 2026-11-09, 156 s.
SLOWEST_CLEAN_CASE_S = 156


class Stages(unittest.TestCase):
    """stage_of maps every mutant id to its gate; M6 opens at M130 (docs/PLAN-ANSWER.md §2.5 D6)."""

    def test_stage_of_m129_is_m5_and_m130_is_m6(self):
        self.assertEqual(mutants.stage_of("M129"), "M5")
        self.assertEqual(mutants.stage_of("M130"), "M6")

    def test_every_anchor_occurs_exactly_once_in_its_file(self):
        """Each mutant's search text is an anchor that must match its file exactly once; a
        drifted anchor would make the mutant inapplicable, and a duplicated one ambiguous."""
        bad = []
        for m in mutants.MUTANTS:
            text = (ROOT / m[1]).read_text(encoding="utf-8")
            n = text.count(m[2])
            if n != 1:
                bad.append(f"{m[0]} {m[1]}: {n} occurrences")
        self.assertEqual(bad, [])


class M6Mutants(unittest.TestCase):
    """WP-45's red-team mutants (M130-M132): each undoes one step of the boot-mode gate, is a
    SECURITY mutant of the M6 stage and names TST-M6-INTERACTIVE-BOOT as its killer. The M6 gate
    (TST-M6-MUTANTS, WP-90) runs them; the anchor guard above keeps them applicable."""

    WANT = {"M130": "kernel/src/arch/x86_64/fwcfg.rs", "M131": "kernel/src/bootmode.rs", "M132": "kernel/src/kmain.rs"}

    def test_the_boot_mode_mutants_are_registered(self):
        by_id = {m[0]: m for m in mutants.MUTANTS}
        for mid, rel in self.WANT.items():
            self.assertIn(mid, by_id)
            self.assertEqual(by_id[mid][1], rel)
            self.assertEqual(mutants.stage_of(mid), "M6")
            self.assertTrue(mutants.security_of(mid), mid)
            self.assertIn("TST-M6-INTERACTIVE-BOOT", by_id[mid][4])

    def test_a_killer_on_the_release_image_gets_it_built(self):
        """A mutant is built for the image its killers boot: TST-M6-INTERACTIVE-BOOT runs
        NAWAH.EFI, so the release kernel is built before the declared killers run (otherwise
        the case is SKIPPED, the fairness sweep excludes it as a declared killer, and M131/M132
        would be reported as survivors)."""
        self.assertTrue(mutants.needs_release("pc-qemu", ["TST-M6-INTERACTIVE-BOOT"]))
        self.assertTrue(mutants.needs_release("pc-qemu", ["TST-M1-BOOT"]))
        self.assertFalse(mutants.needs_release("pc-qemu", ["TST-M5-SVC-WATCHDOG"]))
        self.assertFalse(mutants.needs_release("pc-qemu", ["TST-M5-TEXT-CONFORMANCE"]))


class HoldMutant(unittest.TestCase):
    """WP-67's mutant (M147: the first id outside PLAN-ANSWER §3.3's table, whose M133-M146 are reserved for WP-64, WP-47, WP-48 and WP-52): displayd's start-up hold opens
    on a LIST failure while its trace still says locked=1, the pre-v1.12 behaviour behind a
    truthful-looking line. A SECURITY mutant of the M6 stage, killed by TST-M6-HOLD-FAIL-CLOSED,
    which boots the test image, so no release build is needed."""

    def test_the_hold_mutant_is_registered(self):
        by_id = {m[0]: m for m in mutants.MUTANTS}
        self.assertIn("M147", by_id)
        mid, rel, old, new, killers, _ = by_id["M147"]
        self.assertEqual(rel, "user/apps/displayd/src/main.rs")
        self.assertEqual(mutants.stage_of(mid), "M6")
        self.assertTrue(mutants.security_of(mid))
        self.assertEqual(killers, ["TST-M6-HOLD-FAIL-CLOSED"])
        self.assertEqual(mutants.suite_of("pc-qemu", "TST-M6-HOLD-FAIL-CLOSED"), "M6")
        self.assertFalse(mutants.needs_release("pc-qemu", killers))
        # The mutant leaves every trace line as it is: only the decision changes, so the case
        # must judge the held screen (HOLDS, keys=0), not the trace alone.
        self.assertNotIn("locked=0", new)
        self.assertNotIn("trace", new)


class BuildId(unittest.TestCase):
    def test_build_id_is_all_hex(self):
        for n in (1, 82, 94, 103, 121, 999):
            bid = mutants.mutant_build_id(f"M{n}")
            self.assertRegex(bid, r"^[0-9a-f]+$", f"M{n} build id {bid!r} is not all hex")

    def test_build_ids_are_distinct(self):
        ids = [mutants.mutant_build_id(f"M{n}") for n in range(1, 200)]
        self.assertEqual(len(ids), len(set(ids)))


class CaseTimeout(unittest.TestCase):
    def test_case_timeout_clears_the_slowest_clean_case(self):
        # A mutant's per-case QEMU timeout must exceed the slowest case on the clean tree, or
        # that case times out on every mutant and the sweep reads it as a kill.
        self.assertGreater(mutants.MUTANT_CASE_TIMEOUT_S, SLOWEST_CLEAN_CASE_S)


class EarlyExit(unittest.TestCase):
    def _run(self, verdicts, early_exit):
        """run_killers over three cases with stubbed suite lookup and command runner; `verdicts`
        maps a test id to the return code sh should report (0 PASS, else FAIL)."""
        calls = []

        class R:
            def __init__(self, rc, tid):
                self.returncode = rc
                # project.py's own verdict line for a failing guest case (rule of WP-90).
                self.stdout = f"{tid} pc-qemu: FAIL (marker missing) run=R1\n" if rc == 1 else ""

        orig_suite, orig_sh = mutants.suite_of, mutants.sh
        mutants.suite_of = lambda target, tid: "M5-GATE"
        mutants.sh = lambda cmd, cwd, env=None: (calls.append(cmd[-1]), R(verdicts[cmd[-1]], cmd[-1]))[1]
        try:
            killed, results = mutants.run_killers(
                pathlib.Path("/nonexistent"), {}, "pc-qemu",
                ["T1", "T2", "T3"], early_exit=early_exit)
        finally:
            mutants.suite_of, mutants.sh = orig_suite, orig_sh
        return killed, results, calls

    def test_sweep_stops_at_the_first_kill(self):
        # T2 fails (a kill). With early_exit the run must not go on to T3.
        killed, results, calls = self._run({"T1": 0, "T2": 1, "T3": 0}, early_exit=True)
        self.assertEqual(killed, ["T2"])
        self.assertEqual(calls, ["T1", "T2"])
        self.assertNotIn("T3", results)

    def test_declared_killers_run_to_the_end(self):
        # Without early_exit every case runs, so the report records them all.
        killed, results, calls = self._run({"T1": 0, "T2": 1, "T3": 1}, early_exit=False)
        self.assertEqual(killed, ["T2", "T3"])
        self.assertEqual(calls, ["T1", "T2", "T3"])


class GateMapping(unittest.TestCase):
    """WP-90 (H2 of the 2026-11-10 assurance review): stage_of sent M130 onwards to an M6 gate that
    did not exist, so every M6 mutant was registered and never run. Every stage a registered
    mutant maps to must have a host suite running `tests/mutants.py --stage <stage>` and the
    mutants workflow must run that suite; a stage without a gate is an error here."""

    @staticmethod
    def gate_suites():
        sys.path.insert(0, str(ROOT / "tools"))
        import project  # noqa: E402
        found = {}
        for suite, cases in project.HOST_SUITES.items():
            for c in cases:
                cmd = c["command"]
                if "tests/mutants.py" in cmd and "--stage" in cmd:
                    found.setdefault(cmd[cmd.index("--stage") + 1], []).append((suite, c))
        return found

    def test_every_registered_stage_has_one_gate_run_by_the_mutants_workflow(self):
        gates = self.gate_suites()
        workflow = (ROOT / ".github" / "workflows" / "mutants.yml").read_text(encoding="utf-8")
        stages = sorted({mutants.stage_of(m[0]) for m in mutants.MUTANTS} | set(mutants.STAGES))
        missing = [s for s in stages if len(gates.get(s, [])) != 1]
        self.assertEqual(missing, [], "a registered mutant's stage has no gate suite (or more than one)")
        unrun = [gates[s][0][0] for s in stages
                 if f"python3 tools/project.py test --target host --suite {gates[s][0][0]}\n" not in workflow]
        self.assertEqual(unrun, [], "a gate suite the mutants workflow does not run")

    def test_the_m6_gate_reports_ratio_and_live_security_mutants(self):
        gates = self.gate_suites()
        self.assertIn("M6", sorted(gates), "no gate suite runs `tests/mutants.py --stage M6`")
        suite, case = gates["M6"][0]
        self.assertEqual((suite, case["id"]), ("M6-GATE", "TST-M6-MUTANTS"))
        self.assertEqual(case["command"][case["command"].index("--report") + 1], "build/mutants-m6-report.json")
        reports = [c["command"][c["command"].index("--report") + 1] for g in gates.values() for _, c in g]
        self.assertEqual(len(reports), len(set(reports)), "two gates write the same report")


class ToolingMutants(unittest.TestCase):
    """WP-90 harness item: reset() restored only kernel/ and user/, so a mutant of tools/, tests/
    or .github/ would leak into every later mutant of the run (M174, M185-M190 waited for this).
    A tooling mutant is killed by host cases only: it skips the image build and the guest sweep;
    a kernel or user mutant whose declared killers are all host cases builds the image only if
    the fairness sweep needs it."""

    def test_reset_restores_tooling_and_sources(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            wt = pathlib.Path(tmp)
            files = ["kernel/a.rs", "user/b.rs", "tools/c.py", "tests/d.py", ".github/workflows/e.yml"]
            for f in files:
                (wt / f).parent.mkdir(parents=True, exist_ok=True)
                (wt / f).write_text("clean\n")
            g = ["git", "-c", "user.name=t", "-c", "user.email=t@t.invalid", "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "init", "-q"], cwd=wt, check=True)
            subprocess.run(g + ["add", "-A"], cwd=wt, check=True)
            subprocess.run(g + ["commit", "-qm", "base"], cwd=wt, check=True)
            for f in files:
                (wt / f).write_text("mutated\n")
            mutants.reset(wt)
            self.assertEqual({f: (wt / f).read_text() for f in files}, {f: "clean\n" for f in files})

    def test_a_tooling_mutant_is_host_only(self):
        for rel in ("tools/project.py", "tests/test_ci_workflows.py", ".github/workflows/verify.yml"):
            self.assertTrue(mutants.is_tooling(rel), rel)
            self.assertFalse(mutants.needs_image("pc-qemu", rel, ["TST-M0-003"]), rel)
        for rel in ("kernel/src/kmain.rs", "user/libui/src/lib.rs"):
            self.assertFalse(mutants.is_tooling(rel), rel)

    def test_the_image_is_built_for_guest_killers_only(self):
        self.assertTrue(mutants.needs_image("pc-qemu", "kernel/src/kmain.rs", ["TST-M6-INTERACTIVE-BOOT"]))
        self.assertTrue(mutants.needs_image("pc-qemu", "user/libui/src/lib.rs", ["TST-M6-UI-UNIT", "TST-M5-SVC-WATCHDOG"]))
        self.assertFalse(mutants.needs_image("pc-qemu", "user/libui/src/lib.rs", ["TST-M6-UI-UNIT"]))
        self.assertFalse(mutants.needs_image("pc-qemu", "kernel/src/kmain.rs", ["TST-M0-003"]))


def scratch_repo(tmp):
    """A git repository holding one file in each tree reset() restores."""
    import subprocess
    wt = pathlib.Path(tmp)
    files = ["kernel/a.rs", "user/b.rs", "tools/c.py", "tests/d.py", ".github/workflows/e.yml"]
    for f in files:
        (wt / f).parent.mkdir(parents=True, exist_ok=True)
        (wt / f).write_text("clean\n")
    g = ["git", "-c", "user.name=t", "-c", "user.email=t@t.invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q"], cwd=wt, check=True)
    subprocess.run(g + ["add", "-A"], cwd=wt, check=True)
    subprocess.run(g + ["commit", "-qm", "base"], cwd=wt, check=True)
    return wt, files


class ResetIsVerified(unittest.TestCase):
    def test_a_change_reset_cannot_undo_fails_the_run(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            wt, files = scratch_repo(tmp)
            (wt / "tools/c.py").write_text("mutated\n")
            subprocess.run(["git", "add", "tools/c.py"], cwd=wt, check=True)
            with self.assertRaises(RuntimeError):
                mutants.reset(wt)


class CleanDriver(unittest.TestCase):
    """WP-90 condition 1: the driver that judges a killer is the clean checkout's project.py, so a
    mutated cmd_test_host_case that always prints OK in the worktree cannot pass itself."""

    def test_killers_and_suite_lookup_run_the_clean_project_py(self):
        with tempfile.TemporaryDirectory() as tmp:
            wt, _ = scratch_repo(tmp)
            (wt / "tools" / "project.py").write_text('print("\\nOK")\n')  # the self-judging mutant
            calls = []

            class R:
                returncode, stdout = 0, ""

            orig = mutants.suite_of, mutants.sh
            mutants.suite_of = lambda target, tid: None
            mutants.sh = lambda cmd, cwd, env=None: (calls.append(cmd), R())[1]
            try:
                self.assertEqual(mutants.host_suite_of(wt, "TST-M0-005"), "M0")
                killed, results = mutants.run_killers(wt, {"NAWAH_ROOT": str(wt)}, "pc-qemu", ["TST-M0-005"])
            finally:
                mutants.suite_of, mutants.sh = orig
            self.assertEqual(calls[0][:2], ["python3", str(ROOT / "tools" / "project.py")])
            self.assertNotIn(str(wt), " ".join(calls[0]))


class KillCause(unittest.TestCase):
    """WP-90 condition 2. Rule: a host killer's FAIL is a kill only when its test runner reported
    failing tests (unittest `FAILED (`, cargo `test result: FAILED`) and the same case passes on
    the clean checkout; otherwise (the test file does not compile or import, the case fails
    unmutated too) it is ERROR, never a kill."""

    def _run(self, log, clean_rc):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = pathlib.Path(tmp)
            (scratch / "R1").mkdir()
            (scratch / "R1" / "stderr.log").write_text(log)
            calls = []

            class R:
                def __init__(self, rc, out):
                    self.returncode, self.stdout = rc, out

            def fake_sh(cmd, cwd, env=None):
                calls.append(env.get("NAWAH_ROOT"))
                if env.get("NAWAH_ROOT") == str(mutants.REPO):
                    return R(clean_rc, "")
                return R(1, "TST-X: FAIL run=R1\n")

            orig = mutants.suite_of, mutants.sh, mutants.host_suite_of, dict(mutants._CLEAN_HOST)
            mutants.suite_of, mutants.sh = (lambda target, tid: None), fake_sh
            mutants.host_suite_of = lambda wt, tid: "M0"
            mutants._CLEAN_HOST.clear()
            try:
                return mutants.run_killers(pathlib.Path("/wt"), {"NAWAH_ROOT": "/wt", "NAWAH_SCRATCH_EVIDENCE": str(scratch)},
                                           "pc-qemu", ["TST-X"])[1]["TST-X"]
            finally:
                mutants.suite_of, mutants.sh, mutants.host_suite_of = orig[:3]
                mutants._CLEAN_HOST.clear(); mutants._CLEAN_HOST.update(orig[3])

    def test_failing_tests_that_pass_clean_are_a_kill(self):
        self.assertEqual(self._run("Ran 3 tests\n\nFAILED (failures=1)\n", 0), "FAIL")
        self.assertEqual(self._run("test result: FAILED. 7 passed; 1 failed\n", 0), "FAIL")

    def test_a_test_file_that_does_not_compile_is_no_kill(self):
        self.assertEqual(self._run('  File "tests/t.py", line 3\nSyntaxError: invalid syntax\n', 0), "ERROR")

    def test_a_case_failing_on_the_clean_tree_is_no_kill(self):
        self.assertEqual(self._run("Ran 3 tests\n\nFAILED (failures=1)\n", 1), "ERROR")


class GuestKillCause(unittest.TestCase):
    """WP-90 audit: a guest case is a kill only when project.py returned 1 AND printed its own FAIL
    verdict line for that case (`<tid> <target>: FAIL (...) run=<id>`). An internal error (rc 60:
    no QEMU, no OVMF, unknown case ids) or rc 1 without the line is ERROR, never a kill: in a lab
    without QEMU, M147 and M159 read `killed` from `internal error: FileNotFoundError`."""

    def _one(self, rc, out):
        class R:
            returncode, stdout = rc, out

        orig = mutants.suite_of, mutants.sh
        mutants.suite_of, mutants.sh = (lambda target, tid: "M6"), (lambda cmd, cwd, env=None: R())
        try:
            return mutants.run_killers(pathlib.Path("/wt"), {}, "pc-qemu", ["TST-M6-X"])[1]["TST-M6-X"]
        finally:
            mutants.suite_of, mutants.sh = orig

    def test_an_internal_error_is_no_kill(self):
        self.assertEqual(self._one(60, "internal error: FileNotFoundError: /usr/share/OVMF/OVMF_VARS_4M.fd\n"), "ERROR")

    def test_rc_1_without_the_case_verdict_line_is_no_kill(self):
        self.assertEqual(self._one(1, "TST-M6-OTHER pc-qemu: FAIL (x) run=R1\n"), "ERROR")

    def test_rc_1_with_the_case_verdict_line_is_a_kill(self):
        self.assertEqual(self._one(1, "TST-M6-X pc-qemu: FAIL (required marker missing) run=R1\n"), "FAIL")


class ToolingMain(unittest.TestCase):
    """WP-90 audit: main() itself keeps a tooling mutant host-only (no image build, no guest sweep,
    even when a killer were a guest case), and a source mutant its host killers miss builds its
    image before the fairness sweep."""

    def _main(self, rel, killers):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = scratch_repo(tmp)
            built, swept = [], []

            class R:
                returncode, stdout = 1, "build failed"

            names = ("REPO", "MUTANTS", "EXPECT", "sh", "run_killers", "all_cases", "suite_of", "needs_release")
            orig = {n: getattr(mutants, n) for n in names}
            argv = sys.argv
            mutants.REPO = repo
            mutants.MUTANTS = [("M998", rel, "clean", "mutated", killers, "synthetic")]
            mutants.EXPECT = {}
            mutants.sh = lambda cmd, cwd, env=None, timeout=0: (built.append(cmd), R())[1]
            mutants.run_killers = lambda wt, env, target, ks, early_exit=False: ([], {k: "PASS" for k in ks})
            mutants.all_cases = lambda target: swept.append(target) or []
            mutants.suite_of = lambda target, tid: "M6" if tid == "TST-GUEST" else None
            mutants.needs_release = lambda target, ks: False
            sys.argv = ["mutants.py", "--report", "build/r.json"]
            try:
                mutants.main()
            finally:
                for n, v in orig.items():
                    setattr(mutants, n, v)
                sys.argv = argv
                subprocess.run(["git", "worktree", "prune"], cwd=repo)
            entry = json.loads((repo / "build" / "r.json").read_text())["mutants"][0]
            return built, swept, entry

    def test_a_tooling_mutant_builds_nothing_and_sweeps_no_guest_case(self):
        built, swept, entry = self._main("tools/c.py", ["TST-GUEST"])
        self.assertEqual((built, swept, entry["status"]), ([], [], "survived"))

    def test_a_source_mutant_its_host_killers_miss_is_built_before_the_sweep(self):
        built, swept, entry = self._main("user/b.rs", ["TST-HOST"])
        self.assertTrue(built and built[0][:2] == ["cargo", "build"], built)
        self.assertEqual(entry["status"], "invalid", "the image does not build here, so no sweep and no survivor")


class InvalidSecurity(unittest.TestCase):
    """WP-90 condition 3: an invalid SECURITY mutant (its anchor gone, or it does not build) fails
    the gate; before, it left both the ratio and the SECURITY rule."""

    def test_the_verdict_counts_invalid_security_mutants(self):
        base = {"ratio": 1.0, "valid": 20, "survived": [], "invalid": []}
        self.assertTrue(mutants.gate_verdict(dict(base)))
        self.assertFalse(mutants.gate_verdict(dict(base, invalid=["M130"])))
        self.assertTrue(mutants.gate_verdict(dict(base, invalid=["M158"])), "a non-SECURITY invalid mutant is reported, not fatal")
        self.assertFalse(mutants.gate_verdict(dict(base, survived=["M171"])))
        self.assertFalse(mutants.gate_verdict(dict(base, ratio=0.9)))
        self.assertFalse(mutants.gate_verdict(dict(base, valid=0)))

    def test_a_security_mutant_with_a_missing_anchor_exits_1(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = scratch_repo(tmp)
            orig = mutants.REPO, mutants.MUTANTS, sys.argv, mutants.EXPECT
            mutants.REPO = repo
            mutants.EXPECT = {}
            mutants.MUTANTS = [("M999", "kernel/a.rs", "no such anchor", "x", ["TST-X"], "synthetic")]
            mutants.SECURITY.add("M999")
            sys.argv = ["mutants.py", "--report", "build/r.json"]
            try:
                rc = mutants.main()
            finally:
                mutants.REPO, mutants.MUTANTS, sys.argv, mutants.EXPECT = orig
                mutants.SECURITY.discard("M999")
                subprocess.run(["git", "worktree", "prune"], cwd=repo)
            self.assertEqual(rc, 1)
            got = json.loads((repo / "build" / "r.json").read_text())
            self.assertEqual(got["invalid_security"], ["M999"])


class Inputs(unittest.TestCase):
    """WP-90 condition 5: every registered mutant's file is an input of TST-M0-005 (its anchor
    guard) and of its stage's gate, so a change there makes both stale; a tooling mutant (by path
    alone) names host cases only as killers."""

    def test_every_mutant_file_is_an_input_of_the_guard_and_of_its_gate(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import project  # noqa: E402

        def covered(case):
            got = set(case.get("inputs", []))
            for g in case.get("input_globs", []):
                got |= {p.relative_to(ROOT).as_posix() for p in ROOT.glob(g)}
            return got

        guard = next(c for cs in project.HOST_SUITES.values() for c in cs if c["id"] == "TST-M0-005")
        gates = GateMapping.gate_suites()
        g_in, s_in = covered(guard), {s: covered(v[0][1]) for s, v in gates.items()}
        bad = [m[0] for m in mutants.MUTANTS if m[1] not in g_in or m[1] not in s_in.get(mutants.stage_of(m[0]), set())]
        self.assertEqual(bad, [])

    def test_tooling_mutants_have_host_killers_only(self):
        bad = [(m[0], k) for m in mutants.MUTANTS if mutants.is_tooling(m[1]) for k in m[4]
               if mutants.suite_of("pc-qemu", k) is not None or mutants.host_suite_of(ROOT, k) is None]
        self.assertEqual(bad, [])


class SeparateBuilds(unittest.TestCase):
    """WP-90, found on the first local M6 sample (scratch, 2026-11-14): with a CARGO_TARGET_DIR
    shared by the worktree and the clean checkout, the clean run of TST-M6-UI-CONFIRM reused
    M171's mutated libui build (cargo judged it fresh) and failed, so the kill-cause check read a
    real kill as ERROR. The harness drops CARGO_TARGET_DIR: each tree builds in its own target/."""

    def test_the_harness_env_has_no_shared_cargo_target(self):
        env = mutants.harness_env({"CARGO_TARGET_DIR": "/shared", "PATH": "/bin"}, pathlib.Path("/wt"), pathlib.Path("/s"))
        self.assertNotIn("CARGO_TARGET_DIR", env)
        self.assertEqual((env["NAWAH_ROOT"], env["NAWAH_SCRATCH_EVIDENCE"], env["PATH"]), ("/wt", "/s", "/bin"))
        self.assertEqual(env["NAWAH_QEMU_TIMEOUT_S"], str(mutants.MUTANT_CASE_TIMEOUT_S))


class PartialReport(unittest.TestCase):
    def test_write_report_persists_what_is_decided(self):
        report = {"threshold": 0.95, "mutants": [{"id": "M82", "status": "killed"}]}
        with tempfile.TemporaryDirectory() as tmp:
            rel = "build/x/part.json"
            orig = mutants.REPO
            mutants.REPO = pathlib.Path(tmp)
            try:
                mutants._write_report(rel, report)
                got = json.loads((pathlib.Path(tmp) / rel).read_text())
            finally:
                mutants.REPO = orig
            self.assertEqual(got["mutants"][0]["id"], "M82")


class KillEvidence(unittest.TestCase):
    """The owner's audit of WP-138: the harness recorded only that a declared killer FAILED, not
    why, so a timeout or a setup failure read "killed" like the failure of the field the mutant is
    about, and the scratch serial logs were deleted right after. Each failed killer now keeps its
    kill evidence before the scratch is emptied (the driver's reason, the run id and the test
    kernel's `|ktest|` lines of that run, bounded per boot), in the report and on stdout; EXPECT
    declares the substrings a mutant's kill must show, and a kill that does not show them fails
    the run whatever the ratio. main() runs on a scratch repository with the driver stubbed."""

    MID = "M997"
    NAMES = "|ktest|fail|after a create under the hook the two FAT copies do not list the same names"

    def _main(self, cases, expect=None, check=False, killers=None, mutants_list=None, unbuilt=()):
        """`cases` maps a killer id to (rc, verdict stdout, {file under the run dir: text}) for a
        guest killer, to ("host", rc) for a host killer, or to a list of those taken one per run
        (one mutant after the other). A mutant whose file is in `unbuilt` gets its image built,
        and the build fails. Returns (rc, report, stdout, entry)."""
        import contextlib
        import io
        import subprocess
        killers = killers if killers is not None else list(cases)
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = scratch_repo(tmp)

            class R:
                def __init__(self, rc, out):
                    self.returncode, self.stdout = rc, out

            def fake_sh(cmd, cwd, env=None, timeout=0):
                if cmd[0] == "cargo":
                    return R(1 if unbuilt and not check else 0, "")
                tid = cmd[-1]
                spec = cases[tid]
                if isinstance(spec, list):
                    spec = spec.pop(0)
                scratch = pathlib.Path(env["NAWAH_SCRATCH_EVIDENCE"])
                if spec[0] == "host":
                    if env.get("NAWAH_ROOT") == str(mutants.REPO):
                        return R(0, "")
                    (scratch / "RH").mkdir(exist_ok=True)
                    (scratch / "RH" / "stderr.log").write_text("Ran 2 tests\n\nFAILED (failures=1)\n")
                    return R(spec[1], f"{tid}: FAIL run=RH\n")
                rc, out, files = spec
                for name, text in files.items():
                    run = re.search(r" run=(\S+)", out).group(1)
                    (scratch / run).mkdir(parents=True, exist_ok=True)
                    (scratch / run / name).write_text(text)
                return R(rc, out)

            names = ("REPO", "MUTANTS", "sh", "all_cases", "suite_of", "host_suite_of", "needs_release", "needs_image")
            orig = {n: getattr(mutants, n) for n in names}
            orig_expect = getattr(mutants, "EXPECT", None)
            orig_clean = dict(mutants._CLEAN_HOST)
            argv = sys.argv
            mutants.REPO = repo
            mutants.MUTANTS = mutants_list if mutants_list is not None else [(self.MID, "kernel/a.rs", "clean", "mutated", killers, "synthetic")]
            mutants.EXPECT = expect or {}
            mutants.sh = fake_sh
            mutants.all_cases = lambda target: []
            mutants.suite_of = lambda target, tid: None if cases.get(tid, ("",))[0] == "host" else "M3"
            mutants.host_suite_of = lambda wt, tid: "M0"
            mutants.needs_release = lambda target, ks: False
            mutants.needs_image = lambda target, rel, ks: rel in unbuilt
            mutants._CLEAN_HOST.clear()
            sys.argv = ["mutants.py", "--report", "build/r.json"] + (["--check"] if check else [])
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    rc = mutants.main()
            finally:
                for n, v in orig.items():
                    setattr(mutants, n, v)
                if orig_expect is None:
                    del mutants.EXPECT
                else:
                    mutants.EXPECT = orig_expect
                mutants._CLEAN_HOST.clear(); mutants._CLEAN_HOST.update(orig_clean)
                sys.argv = argv
                subprocess.run(["git", "worktree", "prune"], cwd=repo)
            p = repo / "build" / "r.json"
            report = json.loads(p.read_text()) if p.exists() else {}
            entry = report["mutants"][0] if report.get("mutants") else {}
            return rc, report, buf.getvalue(), entry

    @staticmethod
    def guest(tid, reason, serial, run="R1", rc=1):
        files = serial if isinstance(serial, dict) else {"serial.log": serial}
        return (rc, f"{tid} pc-qemu: FAIL ({reason}) run={run}\n  serial| ...\n", files)

    FIELD = "OSX|00000000003e5|ktest|fat32_fault_create|calls=8|second_names=1|second_free=0\n"

    def test_a_failed_guest_killer_keeps_reason_run_and_ktest_lines(self):
        serial = "boot noise\n" + self.FIELD + "OSX|b|kernel|other\nOSX|b" + self.NAMES + "\n"
        rc, report, out, entry = self._main({"TST-G1": self.guest("TST-G1", "exit 37 != expected 33", serial),
                                             "TST-G2": (0, "", {})})
        self.assertEqual(rc, 0)
        self.assertEqual(entry["status"], "killed")
        self.assertEqual(entry["kills"], {"TST-G1": {"reason": "exit 37 != expected 33", "run": "R1",
                                                     "lines": [self.FIELD.strip(), "OSX|b" + self.NAMES]}})
        lines = out.splitlines()
        first = next(i for i, l in enumerate(lines) if l.startswith(f"{self.MID}: killed by TST-G1 ["))
        self.assertRegex(lines[first], r"^M997: killed by TST-G1 \[[0-9.]+s\] \(synthetic\)$")
        below = "\n".join(lines[first + 1:first + 4])
        self.assertIn("exit 37 != expected 33", below)
        self.assertIn("R1", below)
        self.assertIn("|second_names=1|", below)
        self.assertIn(self.NAMES, below)
        self.assertTrue(all(l.startswith("  ") for l in lines[first + 1:first + 4]), lines[first + 1:first + 4])
        self.assertEqual(report["expected_missed"], [])

    def test_multi_boot_logs_are_bounded_per_boot_and_a_missing_log_is_no_error(self):
        many = "".join(f"OSX|b|ktest|n|{i}\n" for i in range(20)) + "OSX|b|ktest|long|" + "x" * 1000 + "\n"
        rc, _, _, entry = self._main({
            "TST-G1": self.guest("TST-G1", "exit 37 != expected 33",
                                 {"serial-1.log": "OSX|b|ktest|phase1|ok\n", "serial-2.log": many,
                                  "serial.log": "=== phase 1 ===\nOSX|b|ktest|phase1|ok\n=== phase 2 ===\n" + many}),
            "TST-G2": self.guest("TST-G2", "timeout (hang)", {}, run="R2")})
        got = entry["kills"]["TST-G1"]["lines"]
        self.assertEqual(got[0], "OSX|b|ktest|phase1|ok")
        self.assertEqual(len(got), 1 + 12)
        self.assertEqual(got[1], "OSX|b|ktest|n|9")
        self.assertEqual(len(got[-1]), 600)
        self.assertEqual(entry["kills"]["TST-G2"], {"reason": "timeout (hang)", "run": "R2", "lines": []})

    def test_a_host_killer_keeps_its_reason_and_no_lines(self):
        rc, _, _, entry = self._main({"TST-H": ("host", 1)})
        self.assertEqual(entry["status"], "killed")
        self.assertEqual(entry["kills"]["TST-H"]["run"], "RH")
        self.assertEqual(entry["kills"]["TST-H"]["lines"], [])
        self.assertTrue(entry["kills"]["TST-H"]["reason"])

    def test_a_met_expectation_passes(self):
        rc, report, out, entry = self._main(
            {"TST-G1": self.guest("TST-G1", "exit 37 != expected 33", self.FIELD + "OSX|b" + self.NAMES + "\n")},
            expect={self.MID: {"TST-G1": ["exit 37", "|calls=8|", "|second_names=1|", self.NAMES]}})
        self.assertEqual(rc, 0)
        self.assertNotIn("expected_missed", entry)
        self.assertEqual(report["expected_missed"], [])

    def _missed(self, cases, expect, killer, substring):
        rc, report, out, entry = self._main(cases, expect={self.MID: expect})
        self.assertEqual(rc, 1, out)
        self.assertEqual(entry["status"], "killed", "the kill itself is still decided as before")
        self.assertEqual(report["ratio"], 1.0)
        self.assertEqual(report["expected_missed"], [self.MID])
        self.assertTrue(any(killer in m and substring in m for m in entry["expected_missed"]), entry["expected_missed"])
        last = out.strip().splitlines()[-1]
        self.assertTrue(last.startswith("FAIL:"), last)
        self.assertIn(self.MID, last.split("expected_missed=")[1])
        return entry

    def test_a_field_with_another_value_misses_the_expectation(self):
        self._missed({"TST-G1": self.guest("TST-G1", "exit 37 != expected 33",
                                           self.FIELD.replace("second_names=1", "second_names=0") + "OSX|b|ktest|fail|another check\n")},
                     {"TST-G1": ["exit 37", "|second_names=1|"]}, "TST-G1", "|second_names=1|")

    def test_a_timeout_is_not_the_declared_kill(self):
        self._missed({"TST-G1": self.guest("TST-G1", "timeout (hang)", "OSX|b|ktest|start|fat32_fault_create\n")},
                     {"TST-G1": ["|second_names=1|"]}, "TST-G1", "|second_names=1|")

    def test_a_setup_failure_before_the_sweep_is_not_the_declared_kill(self):
        self._missed({"TST-G1": self.guest("TST-G1", "exit 37 != expected 33",
                                           "OSX|b|ktest|start|fat32_fault_create\nOSX|b|ktest|fail|could not format the volume\n")},
                     {"TST-G1": ["exit 37", "|second_names=1|"]}, "TST-G1", "|second_names=1|")

    def test_an_expected_killer_that_did_not_fail_is_missed(self):
        rc, report, out, entry = self._main(
            {"TST-G1": self.guest("TST-G1", "exit 37 != expected 33", self.FIELD), "TST-G2": (0, "", {})},
            expect={self.MID: {"TST-G2": ["exit 37"]}})
        self.assertEqual(rc, 1)
        self.assertEqual(report["expected_missed"], [self.MID])
        self.assertTrue(any("TST-G2" in m for m in entry["expected_missed"]), entry["expected_missed"])

    def test_check_refuses_an_expectation_that_names_nothing_real(self):
        for expect, named in (({"M996": {"TST-G1": ["x"]}}, "M996"),
                              ({self.MID: {"TST-OTHER": ["x"]}}, "TST-OTHER"),
                              ({self.MID: {"TST-G1": []}}, "TST-G1")):
            rc, _, out, _ = self._main({"TST-G1": (0, "", {})}, expect=expect, check=True)
            self.assertEqual(rc, 1, (expect, out))
            self.assertIn(named, out.strip().splitlines()[-1] + "\n" + out, expect)
            self.assertIn("EXPECT", out, expect)

    def test_a_mutant_without_expectation_is_judged_as_before(self):
        rc, report, out, entry = self._main(
            {"TST-G1": self.guest("TST-G1", "missing markers ['x']; forbidden present []", "OSX|b|ktest|fail|y\n")},
            expect={})
        self.assertEqual((rc, entry["status"], entry["killed_by"]), (0, "killed", ["TST-G1"]))
        self.assertNotIn("expected_missed", entry)
        self.assertEqual(entry["kills"]["TST-G1"]["reason"], "missing markers ['x']; forbidden present []")
        self.assertEqual(report["expected_missed"], [])

    def test_the_declared_expectations_name_registered_mutants_and_declared_killers(self):
        by_id = {m[0]: m for m in mutants.MUTANTS}
        self.assertEqual(mutants.expect_errors(), [])
        for mid in ("M262", "M265", "M268", "M219", "M261"):
            self.assertIn(mid, mutants.EXPECT)
            for k, subs in mutants.EXPECT[mid].items():
                self.assertIn(k, by_id[mid][4])
                self.assertIn("exit 37", subs)

    # The audit and red-team pass on 6af4ad009.

    def test_a_user_trace_line_carrying_the_message_is_not_kept(self):
        """H1 (red team B1): a ring-3 program prints through SYS_TRACE `OSX|<id>|user|trace|...`,
        whose text may carry the judgement's message and the field: only the test kernel's own
        lines (`OSX|<hex>|ktest|...`) are kept, so that line cannot meet an expectation."""
        forged = "OSX|00000000003e5|user|trace|len=120|text=OSX|0|ktest|fat32_fault_create|second_names=1|x" + self.NAMES + "\r\n"
        entry = self._missed({"TST-G1": self.guest("TST-G1", "exit 37 != expected 33",
                                                   "OSX|00000000003e5|ktest|start|name=fat32_fault_create\n" + forged)},
                             {"TST-G1": ["exit 37", "|second_names=1|", self.NAMES]}, "TST-G1", "|second_names=1|")
        self.assertEqual(entry["kills"]["TST-G1"]["lines"], ["OSX|00000000003e5|ktest|start|name=fat32_fault_create"])

    def _invalid_with_expect(self, unbuilt):
        killed = ("M996", "kernel/a.rs", "clean", "mutated", ["TST-G1"], "killed")
        bad = (self.MID, "user/b.rs", "no such anchor" if not unbuilt else "clean", "mutated", ["TST-G1"], "invalid")
        rc, report, out, _ = self._main(
            {"TST-G1": self.guest("TST-G1", "exit 37 != expected 33", self.FIELD)},
            expect={self.MID: {"TST-G1": ["exit 37"]}}, mutants_list=[killed, bad],
            unbuilt=("user/b.rs",) if unbuilt else ())
        entry = next(m for m in report["mutants"] if m["id"] == self.MID)
        self.assertEqual(entry["status"], "invalid")
        self.assertEqual(report["ratio"], 1.0, "the ratio alone would pass")
        self.assertEqual(rc, 1, out)
        self.assertEqual(report["expected_missed"], [self.MID])
        self.assertTrue(any("invalid" in m for m in entry["expected_missed"]), entry["expected_missed"])

    def test_an_invalid_mutant_with_an_expectation_is_expected_missed(self):
        """H2 (red team B3): a non-SECURITY mutant with EXPECT that ends invalid (anchor gone)
        would leave its expectation unjudged while the ratio passes."""
        self._invalid_with_expect(unbuilt=False)

    def test_a_mutant_with_an_expectation_that_does_not_build_is_expected_missed(self):
        self._invalid_with_expect(unbuilt=True)

    def test_the_owner_case_a_timeout_with_the_field_in_the_log_is_missed(self):
        """H4a: the reason is a timeout (or another exit) while the log carries the case line with
        the expected field and the judgement's message: "exit 37" is not shown, so the
        expectation is missed and the gate fails."""
        log = self.FIELD + "OSX|b" + self.NAMES + "\n"
        for reason in ("timeout (hang)", "exit 35 != expected 33"):
            self._missed({"TST-G1": self.guest("TST-G1", reason, log)},
                         {"TST-G1": ["exit 37", "|second_names=1|", self.NAMES]}, "TST-G1", "exit 37")

    def test_a_later_mutant_cannot_borrow_an_earlier_mutants_evidence(self):
        """H4b: two mutants, the same killer: the first fails with the field, the second
        without; the second is expected_missed."""
        ms = [("M996", "kernel/a.rs", "clean", "mutated", ["TST-G1"], "first"),
              (self.MID, "user/b.rs", "clean", "mutated", ["TST-G1"], "second")]
        exp = ["exit 37", "|second_names=1|"]
        rc, report, out, _ = self._main(
            {"TST-G1": [self.guest("TST-G1", "exit 37 != expected 33", self.FIELD, run="R1"),
                        self.guest("TST-G1", "exit 37 != expected 33", "OSX|b|ktest|fail|another check\n", run="R2")]},
            expect={"M996": {"TST-G1": exp}, self.MID: {"TST-G1": exp}}, mutants_list=ms)
        self.assertEqual(rc, 1, out)
        self.assertEqual(report["expected_missed"], [self.MID])

    def test_an_expect_error_fails_the_gate_itself(self):
        """H4c: not only --check: a gate run with EXPECT naming an unregistered mutant exits 1."""
        rc, report, out, entry = self._main({"TST-G1": self.guest("TST-G1", "exit 37 != expected 33", self.FIELD)},
                                            expect={"M996": {"TST-G1": ["exit 37"]}})
        self.assertEqual(entry["status"], "killed")
        self.assertEqual(rc, 1, out)
        self.assertTrue(any("M996" in e for e in report["expect_errors"]))

    def test_a_run_id_leaving_the_scratch_reads_no_lines(self):
        """H4d: a run id `..` or one with `/` in the verdict line: no line is read (a log planted
        where it points is ignored), no exception."""
        for run in ("..", "a/b"):
            rc, _, _, entry = self._main({"TST-G1": self.guest("TST-G1", "exit 37 != expected 33", self.FIELD, run=run)})
            self.assertEqual(entry["status"], "killed", run)
            self.assertEqual(entry["kills"]["TST-G1"], {"reason": "exit 37 != expected 33", "run": run, "lines": []})

    CREATE = ("TST-M3-FAT32-FAULT-CREATE", "TST-M3-FAT32-FAULT-ONE-CREATE")
    COPIES = "TST-M3-FAT32-FAULT-CREATE-COPIES"

    def test_the_expectations_content_is_pinned(self):
        """H4e (red team B2): deleting or weakening an expectation, or renaming the message or a
        field it names, fails here (verify's host suite) rather than in the long gate."""
        E = mutants.EXPECT
        self.assertEqual(set(E["M262"]), {*self.CREATE, self.COPIES})
        self.assertEqual(set(E["M268"]), {*self.CREATE, self.COPIES})
        self.assertEqual(set(E["M265"]), {"TST-M3-FAT32-FAULT-ONE-CREATE", self.COPIES})
        for mid in ("M219", "M261"):
            self.assertIn("|calls=8|", E[mid][self.COPIES])
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        cases = {c["id"]: c for cs in t["suites"].values() for c in cs}
        for mid in ("M262", "M265", "M268", "M219", "M261"):
            for k, subs in E[mid].items():
                where = f"{mid} {k}"
                self.assertIn("exit 37", subs, where)
                fails = [s for s in subs if s.startswith("|ktest|fail|")]
                self.assertEqual(len(fails), 1, where)
                self.assertIn(fails[0][len("|ktest|fail|"):], src, where)
                fields = [m.group(1) for s in subs for m in [re.fullmatch(r"\|(\w+)=[^|]*\|", s)] if m]
                self.assertTrue(fields, where)
                c = cases[k]
                pinned = [m for m in list(c["required_markers"]) + [m for p in c.get("phases", []) for m in p.get("required_markers", [])]
                          if re.match(r"OSX\|\$\{BUILD_ID\}\|ktest\|fat32_fault_create", m) and "=" in m]
                for f in fields:
                    self.assertTrue(any(f"|{f}=" in m for m in pinned), f"{where}: field {f} not in the case's pinned marker")
                if k == self.COPIES:
                    self.assertIn("|calls=8|", subs, where)
                else:
                    self.assertIn("|writes=8|", subs, where)
                    self.assertIn("|filled=8|", subs, where)

    BPB = "TST-M3-FAT32-BPB"

    def test_the_boot_sector_expectations_are_pinned(self):
        """WP-106 (audit and red team on 6673854b3): the mount's bounds' mutants are declared by
        what the case prints under them: M270, M272, M273, M274 and M275 by exit 37, the kernel's own
        failure message (in ktest.rs), the summary's fields that differ (each a field of the
        case's pinned summary line) and every sector line they change, each a sector among the
        last ten of the case (the gate keeps a boot's last 12 test-kernel lines: ten sectors,
        the summary and the failure); M271 by exit 35 and the pinned line printed last before
        its panic."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.BPB)
        prefix = "OSX|${BUILD_ID}"
        sectors = [m[len(prefix):] for m in case["required_markers"] if "|ktest|fat32_bpb|sector=" in m]
        summary = next(m for m in case["required_markers"] if "|ktest|fat32_bpb|sectors=" in m)
        kept = [re.search(r"\|sector=(\w+)\|", s).group(1) for s in sectors[-10:]]
        changed = {"M270": {"mul_wrap", "add_wrap", "zero_start"}, "M272": {"over_max", "too_many"},
                   "M273": {"fat_small"}, "M274": {"spc8", "big_fat", "max_ok"}, "M275": {"big_fat"}}
        for mid, names in changed.items():
            self.assertEqual(set(E.get(mid, {})), {self.BPB}, mid)
            subs = E[mid][self.BPB]
            self.assertIn("exit 37", subs, mid)
            fails = [s for s in subs if s.startswith("|ktest|fail|")]
            self.assertEqual(len(fails), 1, mid)
            self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src, mid)
            fields = [m.group(1) for s in subs for m in [re.fullmatch(r"\|(\w+)=\d+\|?", s)] if m]
            self.assertTrue(fields, mid)
            for f in fields:
                self.assertIn(f"|{f}=", summary, f"{mid}: {f}")
                self.assertNotIn(next(s for s in subs if s.startswith(f"|{f}=")), summary, f"{mid}: {f} as pinned")
            lines = [s for s in subs if s.startswith("|ktest|fat32_bpb|sector=")]
            self.assertEqual({re.search(r"\|sector=(\w+)\|", s).group(1) for s in lines}, names, mid)
            for s in lines:
                name = re.search(r"\|sector=(\w+)\|", s).group(1)
                self.assertIn(name, kept, f"{mid}: {name} outside the kept window")
                self.assertNotIn(s, sectors, f"{mid}: {s} is the pinned line")
        subs = E.get("M271", {}).get(self.BPB, [])
        self.assertIn("exit 35", subs)
        last = [s for s in subs if s.startswith("|ktest|fat32_bpb|sector=")]
        self.assertEqual(len(last), 1)
        self.assertIn(last[0], sectors)
        after = sectors[sectors.index(last[0]) + 1]
        self.assertIn("|sector=total0|", after, "the sector after the last line is the first one whose data start is past its total")


    BAD = "TST-M3-FAT32-BAD-FIRST"

    def test_the_bad_first_expectations_are_pinned(self):
        """WP-147: the guard of a write call on a stored first cluster that is no cluster of the
        volume. M276 (no test for 1), M277 (no test for the end), M278 (the end's test one number
        too high) and M279 (one number too low) are declared by exit 37, the kernel's own failure
        message (a failure in ktest.rs) and the fields of the case's one line that differ from its
        pinned line: each field is in that line with another value. M276 shows the five disk
        writes, the write into /HELLO.TXT's cluster and the disk-full answer; M277 the empty
        writes past the end, answered 0; M278 the empty write on the first number past the end
        alone; M279 the empty write on the volume's last cluster number, refused."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.BAD)
        line = next(m for m in case["required_markers"] if "|ktest|fat32_bad_first|" in m) + "|"
        must = {"M276": {"|one_writes=5|", "|one_link=512|", "|one_link_writes=2|", "|hello_ok=0|",
                         "|one_full=K_E_FS_DISK_FULL|", "|one_empty=0|"},
                "M277": {"|past_end_empty=0|", "|far_empty=0|"},
                "M278": {"|past_end_empty=0|"},
                "M279": {"|last_empty=K_E_FS_CORRUPT|"}}
        for mid, fields in must.items():
            self.assertEqual(set(E.get(mid, {})), {self.BAD}, mid)
            subs = E[mid][self.BAD]
            self.assertIn("exit 37", subs, mid)
            fails = [x for x in subs if x.startswith("|ktest|fail|")]
            self.assertEqual(len(fails), 1, mid)
            self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src, mid)
            got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
            self.assertTrue(fields <= got, f"{mid}: {fields - got}")
            for x in got:
                self.assertIn("|" + x[1:].split("=")[0] + "=", line, f"{mid}: {x}")
                self.assertNotIn(x, line, f"{mid}: {x} is the pinned value")

if __name__ == "__main__":
    unittest.main(verbosity=1)
