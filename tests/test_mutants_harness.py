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
import os
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

    def test_the_harness_env_drops_the_shard_count(self):
        # L-023 (WP-152): NAWAH_GATE_SHARDS turns the gate's command into the merge of its shards;
        # a killer that runs the harness or a gate (this case's own) never inherits it.
        env = mutants.harness_env({"NAWAH_GATE_SHARDS": "6", "PATH": "/bin"}, pathlib.Path("/wt"), pathlib.Path("/s"))
        self.assertNotIn("NAWAH_GATE_SHARDS", env)
        self.assertEqual(env["PATH"], "/bin")


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
        too high), M279 (one number too low) and M280 (the guard silent when the offset is past
        the stored size) are declared by exit 37, the kernel's own failure message (a failure in
        ktest.rs, and the one that mutant reaches) and the fields of the case's one line that
        differ from its pinned line: each field is in that line with another value. M276 shows
        the five disk writes, the write into /HELLO.TXT's cluster and the disk-full answer; M277
        the empty writes past the end, answered 0; M278 the empty write on the first number past
        the end alone; M279 the empty write on the volume's last cluster number, refused; M280
        the range error in place of the corrupt-volume error. M276 alone is a SECURITY mutant."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.BAD)
        line = next(m for m in case["required_markers"] if "|ktest|fat32_bad_first|" in m) + "|"
        must = {"M276": {"|one_writes=5|", "|one_link=512|", "|one_link_writes=2|", "|hello_ok=0|",
                         "|one_full=K_E_FS_DISK_FULL|", "|one_empty=0|"},
                "M277": {"|past_end_empty=0|", "|far_empty=0|"},
                "M278": {"|past_end_empty=0|"},
                "M279": {"|last_empty=K_E_FS_CORRUPT|"},
                "M280": {"|one_past=K_E_FS_RANGE|"}}
        message = {"M276": mutants._UNREFUSED, "M277": mutants._UNREFUSED, "M278": mutants._UNREFUSED,
                   "M279": mutants._LAST, "M280": getattr(mutants, "_PAST", None)}
        self.assertEqual(len({message[m] for m in ("M276", "M279", "M280")}), 3, "three different failures")
        self.assertEqual({m for m in must if m in mutants.SECURITY}, {"M276"})
        for mid, fields in must.items():
            self.assertEqual(set(E.get(mid, {})), {self.BAD}, mid)
            subs = E[mid][self.BAD]
            self.assertIn("exit 37", subs, mid)
            fails = [x for x in subs if x.startswith("|ktest|fail|")]
            self.assertEqual(len(fails), 1, mid)
            self.assertEqual(fails[0], message[mid], mid)
            self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src, mid)
            got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
            self.assertTrue(fields <= got, f"{mid}: {fields - got}")
            for x in got:
                self.assertIn("|" + x[1:].split("=")[0] + "=", line, f"{mid}: {x}")
                self.assertNotIn(x, line, f"{mid}: {x} is the pinned value")

    VMO = "TST-M3-VMO-MAP-RIGHTS"

    def test_the_vmo_map_rights_expectation_is_pinned(self):
        """WP-149 (K-3, RSK-040): M281 drops READ from what vmo_map asks for a mapping for
        writing. It is a SECURITY mutant declared on TST-M3-VMO-MAP-RIGHTS alone by exit 37, the
        kernel's own failure message (a failure in ktest.rs) and the two fields of the case's one
        line that change, write_noread=mapped and leak=1, each in the pinned line with another
        value; its anchor is the fix's own line in kernel/src/syscall/mod.rs."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.VMO)
        line = next(m for m in case["required_markers"] if "|ktest|vmo_map_rights|" in m) + "|"
        m = next(m for m in mutants.MUTANTS if m[0] == "M281")
        self.assertEqual(m[1], "kernel/src/syscall/mod.rs")
        self.assertEqual(m[4], [self.VMO])
        self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
        self.assertIn("M281", mutants.SECURITY)
        self.assertEqual(set(E.get("M281", {})), {self.VMO})
        subs = E["M281"][self.VMO]
        self.assertIn("exit 37", subs)
        fails = [x for x in subs if x.startswith("|ktest|fail|")]
        self.assertEqual(fails, [getattr(mutants, "_K3", None)])
        self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src)
        got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
        self.assertEqual(got, {"|write_noread=mapped|", "|leak=1|"})
        for x in got:
            self.assertIn("|" + x[1:].split("=")[0] + "=", line, x)
            self.assertNotIn(x, line, f"{x} is the pinned value")

    RETRY = "TST-M4-CONFIG-RETRY"

    def test_the_config_handle_close_expectation_is_pinned(self):
        """WP-107 (RSK-028, config.md v1.3): M323 removes configd's one exit that closes the
        handle a request carried. It is a SECURITY mutant whose anchor is that close, once in
        user/apps/configd/src/main.rs, declared on TST-M4-CONFIG-RETRY alone by exit 37, the
        kernel's own failure message for kept replay handles (a failure in ktest.rs) and the three
        growths of the case's live line, each in the pinned line with another value: the body's
        six tokens, the 20 replays and the second client's two."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.RETRY)
        line = next(m for m in case["required_markers"] if "|ktest|config_retry|live|" in m)
        m = next((m for m in mutants.MUTANTS if m[0] == "M323"), None)
        self.assertIsNotNone(m, "M323 is registered")
        self.assertEqual(m[1], "user/apps/configd/src/main.rs")
        self.assertEqual(m[4], [self.RETRY])
        self.assertIn("handle_close", m[2])
        self.assertNotIn("handle_close", m[3])
        self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
        self.assertIn("M323", mutants.SECURITY)
        self.assertEqual(mutants.stage_of("M323"), "M6")
        self.assertEqual(set(E.get("M323", {})), {self.RETRY})
        subs = E["M323"][self.RETRY]
        self.assertIn("exit 37", subs)
        fails = [x for x in subs if x.startswith("|ktest|fail|")]
        # The text itself: a name compared with the module's own name passes when a later
        # definition replaces it (verify run 44483593342: expected_missed=[M323]).
        self.assertEqual(fails, ["|ktest|fail|configd kept the handles its replayed requests carried"])
        self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src)
        got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
        self.assertEqual(got, {"|body_grew=6|", "|replays_grew=20|", "|unwritable_grew=2|"})
        for x in got:
            self.assertIn("|" + x[1:].split("=")[0] + "=", line, x)
            self.assertNotIn(x, line, f"{x} is the pinned value")

    NOREAD = "TST-M4-SVC-CONNECT-NOREAD"

    def test_the_manager_reply_close_expectation_is_pinned(self):
        """WP-156 (RSK-028; services.md v1.13 note): M324 puts back the manager's CONNECT reply
        to a service as it was, its write result ignored. It is a SECURITY mutant whose anchor
        is the write-or-close, once in user/apps/svcmgr/src/main.rs, its replacement the reply
        without the close, declared on TST-M4-SVC-CONNECT-NOREAD alone by exit 37, the kernel's
        own failure message (a failure in ktest.rs) and the two growths of the case's line,
        each in the pinned line with another value: three client ends, three slots."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.NOREAD)
        line = next(m for m in case["required_markers"] if "|mgr_grew=" in m)
        m = next((m for m in mutants.MUTANTS if m[0] == "M324"), None)
        self.assertIsNotNone(m, "M324 is registered")
        self.assertEqual(m[1], "user/apps/svcmgr/src/main.rs")
        self.assertEqual(m[4], [self.NOREAD])
        self.assertIn("handle_close(client)", m[2])
        self.assertNotIn("handle_close", m[3])
        self.assertIn('channel_write(c, b"OK", &[client])', m[3])
        self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
        self.assertIn("M324", mutants.SECURITY)
        self.assertTrue(m[5].startswith("SECURITY: "), m[5])
        self.assertEqual(mutants.stage_of("M324"), "M6")
        self.assertEqual(set(E.get("M324", {})), {self.NOREAD})
        subs = E["M324"][self.NOREAD]
        self.assertIn("exit 37", subs)
        fails = [x for x in subs if x.startswith("|ktest|fail|")]
        self.assertEqual(fails, [getattr(mutants, "_HELD", None)])
        self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src)
        got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
        self.assertEqual(got, {"|mgr_grew=3|", "|cfg_grew=3|"})
        for x in got:
            self.assertIn("|" + x[1:].split("=")[0] + "=", line, x)
            self.assertNotIn(x, line, f"{x} is the pinned value")

    AUTHZ = "TST-M4-CONFIG-STORE-AUTHZ"

    def test_the_user_store_creation_expectations_are_pinned(self):
        """WP-157 (RSK-028; config.md v1.4): configd creates a user store only for a token that
        may modify it. M325 puts the creation back before the token is judged (a refused SET
        or IMPORT leaves the store behind): a SECURITY mutant. M326, which let SUBSCRIBE create
        one, is retired with WP-112 (config.md v1.6: SUBSCRIBE refuses every user store before
        it looks one up; M437 guards that refusal) and must stay unregistered. M327 takes ADMIN
        out of the tokens a store is created for (an administrator's SET on a store that is
        not loaded is refused): no hole, so not a SECURITY mutant. From the review round:
        M328 (SECURITY) lets any token modify a loaded user store, the check the refusals
        above no longer reach; M329 and M330 take the lower and move the upper bound of the
        uid a store name may carry; M331 answers ERR ACCESS, not ERR INVALID, to a token that
        may create when no slot is free. Each anchor is once in
        user/apps/configd/src/main.rs, declared on TST-M4-CONFIG-STORE-AUTHZ alone by exit 37,
        the kernel's own failure message (a failure in ktest.rs) and fields of the case's two
        lines, each in the pinned lines with another value; no two mutants are declared by
        the same message and fields."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.AUTHZ)
        lines = [m for m in case["required_markers"] if "|ktest|config_store_authz|" in m and "=" in m]
        self.assertTrue(any("|subs_ok=" in m for m in lines) and any("|full_set=" in m for m in lines))
        line = "".join(lines)
        bound = "uid != 0 && uid <= u64::from(UID_MAX_PERSISTENT)"
        self.assertNotIn("M326", {m[0] for m in mutants.MUTANTS} | set(mutants.EXPECT) | mutants.SECURITY)
        want = {
            "M325": ("store_index(name, create)", "store_index(name, true)", "_LEFT",
                     {"|other_export=OK|", "|import_export=OK|"}, True),
            "M327": ("token.perms & perm::ADMIN != 0 || uid == token.uid", "uid == token.uid", "_ADMIN",
                     {"|admin_set=ERR ACCESS|"}, False),
            "M328": ("admin || self.stores[i].uid == token.uid", "true", "_LOADED",
                     {"|loaded_other=OK 2|", "|loaded_kept=0|"}, True),
            # since v1.6 a name these let through is a user store, which SUBSCRIBE refuses
            "M329": (bound, "uid <= u64::from(UID_MAX_PERSISTENT)", "_NONAME", {"|sub_zero=ERR ACCESS|"}, False),
            "M330": (bound, "uid != 0 && uid <= u64::from(UID_MAX_PERSISTENT) * 10", "_NONAME",
                     {"|sub_big=ERR ACCESS|"}, False),
            "M331": ("create || user_uid(name).is_none()", "user_uid(name).is_none()", "_FULLTAB",
                     {"|full_set=ERR ACCESS|"}, False),
        }
        seen = []
        for mid, (old, new, const, fields, security) in want.items():
            with self.subTest(mutant=mid):
                m = next((m for m in mutants.MUTANTS if m[0] == mid), None)
                self.assertIsNotNone(m, f"{mid} is registered")
                self.assertEqual(m[1], "user/apps/configd/src/main.rs")
                self.assertEqual(m[4], [self.AUTHZ])
                self.assertEqual(m[2].count(old), 1)
                self.assertEqual(m[3], m[2].replace(old, new))
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(set(E.get(mid, {})), {self.AUTHZ})
                subs = E[mid][self.AUTHZ]
                self.assertIn("exit 37", subs)
                fails = [x for x in subs if x.startswith("|ktest|fail|")]
                self.assertEqual(fails, [getattr(mutants, const, None)])
                self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src)
                seen.append((fails[0], tuple(sorted(fields))))
                got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
                self.assertEqual(got, fields)
                for x in got:
                    self.assertIn("|" + x[1:].split("=")[0] + "=", line, x)
                    self.assertNotIn(x, line, f"{x} is the pinned value")
        self.assertEqual(len(set(seen)), 6, "each mutant is known by its own message and fields")

    DROP = "TST-M4-NET-CLIENT-DROP"

    def test_the_net_client_drop_expectations_are_pinned(self):
        """WP-108 (RSK-028; net.md parts B and C): netd frees a client's sockets and resets its
        connections wherever it frees the client's slot, in one function. M332 puts the
        reply-failure path back as it was (the slot freed, nothing else); M333 does the same
        to the path of a peer closed while idle; M334 leaves the connections out of the one
        cleanup; M335 (the review round) resets every client's connections when one client
        closes. All four are SECURITY mutants, each anchor once in
        user/apps/netd/src/main.rs, declared on TST-M4-NET-CLIENT-DROP alone by exit 37, the
        kernel's own failure message (a failure in ktest.rs) and fields of the case's line,
        each in the pinned line with another value; no two are declared by the same message
        and fields. No expectation rests on the echo of a datagram (the review round): what
        the second client reads from the first client's socket is in the line, not declared."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.DROP)
        line = next(m for m in case["required_markers"] if "|inherit_recv=" in m)
        want = {
            "M332": ("st.drop_client(ci)", "_USED", {"|tcp_a=OK state=ESTABLISHED|", "|reopen=ERR EXISTS|"}),
            "M333": ("st.drop_client(ci)", "_IDLE", {"|idle_reopen=ERR EXISTS|"}),
            "M334": ("self.tcp_abort(cn)", "_USED", {"|tcp_a=OK state=ESTABLISHED|"}),
            "M335": ("self.tcp_abort(cn)", "_OTHER", {"|tcp_b=ERR CLOSED|"}),
        }
        seen = []
        for mid, (must, const, fields) in want.items():
            with self.subTest(mutant=mid):
                m = next((m for m in mutants.MUTANTS if m[0] == mid), None)
                self.assertIsNotNone(m, f"{mid} is registered")
                self.assertEqual(m[1], "user/apps/netd/src/main.rs")
                self.assertEqual(m[4], [self.DROP])
                self.assertIn(must, m[2])
                if mid == "M334":
                    self.assertEqual(m[3], m[2].replace("owner == ci {", "owner == ci && false {"))
                elif mid == "M335":
                    self.assertEqual(m[3], m[2].replace("self.conns[cn].owner == ci", "true"))
                else:
                    self.assertNotIn("drop_client", m[3])
                    self.assertIn("libnawah::handle_close(c);", m[3])
                    self.assertIn("st.clients[ci] = 0;", m[3])
                    self.assertNotIn("NO_SOCKET", m[3])
                    self.assertNotIn("tcp_abort", m[3])
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertIn(mid, mutants.SECURITY)
                self.assertTrue(m[5].startswith("SECURITY: "), m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(set(E.get(mid, {})), {self.DROP})
                subs = E[mid][self.DROP]
                self.assertIn("exit 37", subs)
                fails = [x for x in subs if x.startswith("|ktest|fail|")]
                self.assertEqual(fails, [getattr(mutants, const, None)])
                self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src)
                seen.append((fails[0], tuple(sorted(fields))))
                got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
                self.assertEqual(got, fields)
                for x in got:
                    self.assertIn("|" + x[1:].split("=")[0] + "=", line, x)
                    self.assertNotIn(x, line, f"{x} is the pinned value")
        self.assertEqual(len(set(seen)), 4, "each mutant is known by its own message and fields")
        self.assertFalse(any("from-a" in x for mid in want for x in E[mid][self.DROP]), "no expectation rests on an echo")

    SUBS = "TST-M4-CONFIG-SUBS"

    def test_the_subscription_ownership_expectations_are_pinned(self):
        """WP-158 (RSK-028; config.md v1.5): a subscription belongs to the client that asked for
        it, one per client and store, and goes with the client; SUBSCRIBE session is refused.
        M336 lets a client's second SUBSCRIBE take another slot (eight fill the store and the
        next client is refused); M337 leaves the subscriptions out of the one cleanup; M339
        and M340 put back the two paths that free a client's slot as they were (the reply that
        cannot be written; the peer closed while idle); M338 accepts SUBSCRIBE session, so a
        subscriber without a token hears another user's session key; M341 (the review round)
        ends the cleanup after the first store. All six are SECURITY mutants, each anchor once
        in user/apps/configd/src/main.rs, declared on TST-M4-CONFIG-SUBS alone by exit 37, the
        kernel's own failure message (a failure in ktest.rs) and fields of the case's two
        lines: those that change, each in the pinned lines with another value, and, where two
        mutants would share them, one that holds, with its pinned value (the path or the
        store the mutant leaves right). No two are declared by the same message and fields,
        and none's fields are a part of another's with the same message."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.SUBS)
        lines = [m for m in case["required_markers"] if "|ktest|config_subs|" in m and "=" in m]
        self.assertTrue(any("|x_grew=" in m for m in lines) and any("|sess_sub=" in m for m in lines))
        line = "".join(lines)
        want = {
            "M336": ("usize::from(st.sub_client[s]) == ci)", "_MANY", {"|x_grew=9|", "|y_sub=ERR FULL|"}, set()),
            "M337": ("libnawah::handle_close(st.subs[s]);", "_SUBSTAY",
                     {"|x_gone=0|", "|z_gone=0|", "|z_end_closed=0|"}, set()),
            "M338": ('if store == b"session" {', "_SESS",
                     {"|sess_sub=OK|", "|sess_heard=CHANGED session subs.s 1|"}, set()),
            "M339": ("st.drop_client(ci)", "_ZSTAY", {"|z_gone=0|", "|z_end_closed=0|"}, {"|x_gone=1|"}),
            "M340": ("st.drop_client(ci)", "_SUBSTAY", {"|x_gone=0|", "|x_end_closed=0|"}, {"|z_end_closed=1|"}),
            "M341": ("for st in self.stores.iter_mut()", "_SUBSTAY",
                     {"|x_gone=0|", "|x_pol_closed=0|"}, {"|x_end_closed=1|"}),
        }
        seen = []
        for mid, (must, const, fields, held) in want.items():
            with self.subTest(mutant=mid):
                m = next((m for m in mutants.MUTANTS if m[0] == mid), None)
                self.assertIsNotNone(m, f"{mid} is registered")
                self.assertEqual(m[1], "user/apps/configd/src/main.rs")
                self.assertEqual(m[4], [self.SUBS])
                self.assertIn(must, m[2])
                if mid in ("M339", "M340"):
                    self.assertNotIn("drop_client", m[3])
                    self.assertIn("libnawah::handle_close(c);", m[3])
                    self.assertIn("st.clients[ci].chan = 0;", m[3])
                elif mid == "M338":
                    self.assertEqual(m[3], "")
                elif mid == "M341":
                    self.assertEqual(m[3], m[2].replace("self.stores.iter_mut()", "self.stores.iter_mut().take(1)"))
                else:
                    self.assertEqual(m[3], m[2].replace("usize::from(st.sub_client[s]) == ci", "false"))
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertIn(mid, mutants.SECURITY)
                self.assertTrue(m[5].startswith("SECURITY: "), m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(set(E.get(mid, {})), {self.SUBS})
                subs = E[mid][self.SUBS]
                self.assertIn("exit 37", subs)
                fails = [x for x in subs if x.startswith("|ktest|fail|")]
                self.assertEqual(fails, [getattr(mutants, const, None)])
                self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src)
                seen.append((fails[0], frozenset(fields | held)))
                got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
                self.assertEqual(got, fields | held)
                for x in fields:
                    self.assertIn("|" + x[1:].split("=")[0] + "=", line, x)
                    self.assertNotIn(x, line, f"{x} is the pinned value")
                for x in held:
                    self.assertIn(x, line, f"{x} is not the pinned value")
        self.assertEqual(len(set(seen)), 6, "each mutant is known by its own message and fields")
        for a, fa in seen:
            for b, fb in seen:
                if (a, fa) != (b, fb) and a == b:
                    self.assertFalse(fa < fb, f"{sorted(fa)} is a part of {sorted(fb)} under the same message")


    LAUNCH = "TST-M6-LAUNCH-DENIED"

    def test_the_launch_requester_expectations_are_pinned(self):
        """WP-101 (REQ-M6-004; services.md v1.14, ADR-0023): APPS and LAUNCH on a service's boot
        channel are for the vouched session and desktop. M342 (SECURITY) drops the check of
        the requester, so a plain service is given the registry and its LAUNCH is taken; M344
        takes desktop out of the vouched names; M343 drops the reply to an unknown request; M345
        (the review round) registers an entry whatever its file is named, so the lab entry
        ZED.APP, whose id is `other`, enters the registry.
        Each anchor is once in user/apps/svcmgr/src/main.rs, declared on TST-M6-LAUNCH-DENIED
        alone by exit 37, the kernel's own failure message (a failure in ktest.rs) and fields
        of the case's line, each in the pinned line with another value; no two are declared by
        the same message and fields."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.LAUNCH)
        line = next(m for m in case["required_markers"] if "|plain_launch=" in m)
        check = 'who != b"session" && who != b"desktop"'
        want = {
            "M342": (check, "false", "_PLAIN", {"|plain_launch=0x51|", "|plain_apps=0x51|"}, True),
            "M343": ('libnawah::channel_write(c, b"ERR BAD_REQUEST", &[]);', None, "_NOBAD", {"|unknown=0x61|"}, False),
            "M344": (check, 'who != b"session"', "_DESK", {"|desktop_launch=0x51|"}, False),
            "M345": ("one.add(file, &bytes[..n])", "nawah_apps::parse(&bytes[..n])", "_REG", {"|session_apps=0x51|"}, False),
        }
        self.assertEqual(case.get("disk_files"), {"SYSTEM/APPS/ZED.APP": "platform/pc-qemu/lab/zed.app"})
        zed = (ROOT / "platform" / "pc-qemu" / "lab" / "zed.app").read_text(encoding="utf-8")
        self.assertIn("\nid=other\n", zed, "the lab entry's id is not its file's name")
        seen = []
        for mid, (old, new, const, fields, security) in want.items():
            with self.subTest(mutant=mid):
                m = next((m for m in mutants.MUTANTS if m[0] == mid), None)
                self.assertIsNotNone(m, f"{mid} is registered")
                self.assertEqual(m[1], "user/apps/svcmgr/src/main.rs")
                self.assertEqual(m[4], [self.LAUNCH])
                self.assertEqual(m[2].count(old), 1)
                if new is None:
                    self.assertNotIn("channel_write", m[3])
                    self.assertTrue(m[2].startswith(m[3]) and m[3], "the reply's line alone is taken out")
                else:
                    self.assertEqual(m[3], m[2].replace(old, new))
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(set(E.get(mid, {})), {self.LAUNCH})
                subs = E[mid][self.LAUNCH]
                self.assertIn("exit 37", subs)
                fails = [x for x in subs if x.startswith("|ktest|fail|")]
                self.assertEqual(fails, [getattr(mutants, const, None)])
                self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src)
                seen.append((fails[0], frozenset(fields)))
                got = {x for x in subs if re.fullmatch(r"\|\w+=[^|]*\|", x)}
                self.assertEqual(got, fields)
                for x in got:
                    self.assertIn("|" + x[1:].split("=")[0] + "=", line, x)
                    self.assertNotIn(x, line, f"{x} is the pinned value")
        self.assertEqual(len(set(seen)), 4, "each mutant is known by its own message and fields")

    SPAWN = "TST-M6-APP-SPAWN"

    def test_the_launch_expectations_are_pinned(self):
        """WP-161 (REQ-M6-004; services.md v1.15, ADR-0023 item 1): LAUNCH starts an application
        in a job of its own (under the session's job since v1.17, WP-102) with its boot channel alone, under a number no
        running application carries, eight at most; whatever it asks is refused; its job ends
        with it; a launch that failed keeps nothing. M346 to M361 (M358 to M361 from the review
        round: an application that closes its boot channel and stays, and a request carrying
        two handles), each anchor once in
        user/apps/svcmgr/src/main.rs, are declared on TST-M6-APP-SPAWN alone by exit 37, one
        `|ktest|fail|` message occurring as a failure in ktest.rs, and fields of the case's one
        line: those that change, each with another value than the pinned line's, and those
        that hold beside them with the pinned value; M358 alone, under which the manager is
        gone, by the line of the listing that failed. No two share message and changed fields.
        The case's volume carries the lab entries and images the launcher's steps need."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.SPAWN)
        line = next(m for m in case["required_markers"] if "|session=" in m)
        pinned = dict(f.split("=", 1) for f in line.strip("|").split("|")[2:])
        self.assertEqual(pinned, {"load": "OK 1", "session": "0x40", "apps": "8", "waiting": "8", "handles": "8", "under_root": "0",
                                  "in_session": "8", "parents": "1", "jobs": "8", "live_jobs": "9", "orphans": "0", "mgr_handles": "25"})
        want = {  # id: (message, SECURITY, the fields that change, the fields that hold)
            "M346": ("_NOJOB", True, {"in_session": "0", "jobs": "1", "orphans": "1"}, {"session": "0x40", "parents": "1", "live_jobs": "9"}),
            "M347": ("_MORE", True, {"handles": "16"}, {"apps": "8", "waiting": "8", "under_root": "0"}),
            "M348": ("_ORPHAN", True, {"live_jobs": "10", "orphans": "1"}, {"in_session": "8", "parents": "1", "jobs": "8"}),
            "M349": ("_LAUNCH", True, {"session": "0x590c", "apps": "0"}, {}),
            "M350": ("_LAUNCH", True, {"session": "0x5301", "apps": "0"}, {}),
            "M351": ("_LAUNCH", False, {"session": "0x5364", "apps": "0"}, {}),
            "M352": ("_APP_KEPT", False, {"mgr_handles": "27"}, {"live_jobs": "9", "orphans": "0"}),
            "M353": ("_JOBLEFT", False, {"live_jobs": "11", "mgr_handles": "27"}, {"orphans": "0"}),
            "M354": ("_APP_KEPT", True, {"mgr_handles": "33"}, {"live_jobs": "9", "orphans": "0"}),
            "M355": ("_REFUSED", False, {"waiting": "0", "handles": "40"}, {"session": "0x40", "apps": "8"}),
            "M356": ("_JOBLEFT", False, {"live_jobs": "110", "mgr_handles": "126"}, {"orphans": "0"}),
            "M357": ("_REFUSED", True, {"waiting": "0", "handles": "56"}, {"session": "0x40", "apps": "8"}),
            "M358": ("_NOLIST", True, None, None),
            "M359": ("_APP_KEPT", False, {"mgr_handles": "26"}, {"live_jobs": "9", "orphans": "0"}),
            "M360": ("_JOBLEFT", True, {"live_jobs": "10", "mgr_handles": "27"}, {"orphans": "0"}),
            "M361": ("_APP_KEPT", True, {"mgr_handles": "41"}, {"live_jobs": "9", "orphans": "0"}),
        }
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if m[4] == [self.SPAWN]), sorted(want))
        seen = []
        for mid, (const, security, changed, held) in want.items():
            with self.subTest(mutant=mid):
                m = next((m for m in mutants.MUTANTS if m[0] == mid), None)
                self.assertIsNotNone(m, f"{mid} is registered")
                self.assertEqual(m[1], "user/apps/svcmgr/src/main.rs")
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(set(E.get(mid, {})), {self.SPAWN})
                subs = E[mid][self.SPAWN]
                self.assertIn("exit 37", subs)
                fails = [x for x in subs if x.startswith("|ktest|fail|")]
                self.assertEqual(fails, [getattr(mutants, const, None)])
                if mid in ("M352", "M354", "M359", "M361"):
                    self.assertEqual(fails, ["|ktest|fail|the manager kept a handle of a launch that failed or of an application that exited"])
                self.assertIn(f'fail("{fails[0][len("|ktest|fail|"):]}")', src)
                rest = [x for x in subs if x != "exit 37" and x not in fails]
                if changed is None:
                    # The manager is gone: the harness's poller prints the listing's error.
                    self.assertEqual(rest, ["|ktest|app_spawn|list_error="])
                    self.assertIn('"OSX|{}|ktest|{}|list_error={}"', src)
                    seen.append((fails[0], frozenset()))
                    continue
                self.assertTrue(rest and all(x.startswith("|") and x.endswith("|") for x in rest), rest)
                got = dict(f.split("=", 1) for x in rest for f in x.strip("|").split("|"))
                self.assertEqual(got, {**changed, **held})
                for k, v in changed.items():
                    self.assertNotEqual(pinned[k], v, f"{k}={v} is the pinned value")
                for k, v in held.items():
                    self.assertEqual(pinned[k], v, f"{k}={v} is not the pinned value")
                # Fields declared in one substring stand next to each other in the line, in order.
                order = list(pinned)
                for x in rest:
                    ks = [f.split("=", 1)[0] for f in x.strip("|").split("|")]
                    at = order.index(ks[0])
                    self.assertEqual(ks, order[at:at + len(ks)], x)
                seen.append((fails[0], frozenset(changed.items())))
        self.assertEqual(len(set(seen)), len(want), "each mutant is known by its own message and changed fields")
        self.assertEqual(case["timeout_s"], 30)
        self.assertEqual(case.get("disk_files"), {
            "SYSTEM/APPS/EXIT.APP": "platform/pc-qemu/lab/exit.app", "SYSTEM/APPS/ORPHAN.APP": "platform/pc-qemu/lab/orphan.app",
            "SYSTEM/APPS/CLOSER.APP": "platform/pc-qemu/lab/closer.app", "SYSTEM/APPS/BAD.APP": "platform/pc-qemu/lab/bad.app",
            "SYSTEM/APPS/CLOCK.ELF": "${OUT}/apps/svc.elf", "SYSTEM/APPS/EXIT.ELF": "${OUT}/apps/exiter.elf",
            "SYSTEM/APPS/ORPHAN.ELF": "${OUT}/apps/svc.elf", "SYSTEM/APPS/CLOSER.ELF": "${OUT}/apps/svc.elf",
            "SYSTEM/APPS/BAD.ELF": "platform/pc-qemu/lab/bad.app", "SYSTEM/LABSES.ELF": "${OUT}/apps/svc.elf"})
        for name in ("exit", "orphan", "closer", "bad"):
            entry = (ROOT / "platform" / "pc-qemu" / "lab" / f"{name}.app").read_text(encoding="utf-8")
            self.assertIn(f"\nid={name}\nelf=/SYSTEM/APPS/{name.upper()}.ELF\n", entry)
        manifest = (ROOT / "platform" / "pc-qemu" / "manifests" / "svc-as.txt").read_text(encoding="utf-8")
        self.assertEqual([l for l in manifest.splitlines() if l and not l.startswith("#")],
                         ["session /SYSTEM/LABSES.ELF - 3000 never 0 0 launcher"])
        # The other launch case begins no session: a registered id is refused by the gate before
        # any image is looked for (WP-169; ERR NOT_FOUND, its reply until then, is APP-SPAWN's).
        denied = (ROOT / "platform" / "pc-qemu" / "manifests" / "svc-ld.txt").read_text(encoding="utf-8")
        self.assertIn("LAUNCH clock=ERR NO_SESSION", denied)
        self.assertNotIn("BEGIN_SESSION", denied)

    CONNECT = "TST-M6-APP-CONNECT-DENIED"

    def test_the_connect_expectations_are_pinned(self):
        """WP-162 (REQ-M6-004; services.md v1.16): an application's CONNECT. M140 and M142
        (reserved since WP-101), M378 to M384, each anchor once in user/apps/svcmgr/src/main.rs,
        are declared on TST-M6-APP-CONNECT-DENIED alone. Five are known by the test kernel's
        line, exit 37 and one message occurring as a failure in ktest.rs, the fields that change
        each with another value than the pinned line's; M140, M378, M382 and M383 leave that
        line as it is and are known by the case's own missing markers, each a required marker
        of the case. The case's volume carries the five lab entries with what each declares."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.CONNECT)
        line = next(m for m in case["required_markers"] if m.startswith("|ktest|app_connect|load="))
        self.assertEqual(line, "|ktest|app_connect|load=OK 3|session=0x40|apps=5|waiting=5|handles=9|mgr_handles=20|")
        want = {  # id: (SECURITY, message constant or None, substrings besides exit 37 and the message)
            "M140": (True, None, ["'|text=svc|connect|app:connx#1', '|text=svc|connect|app:both#2', '|text=svc|connect|app:stuck#4', '|text=svc|connect|app:conn#8'"]),
            "M142": (True, "_CLAUNCH", ["|session=0x5300|apps=0|"]),
            "M378": (True, None, ["'|text=app:connx#1|net=ERR ACCESS|session=ERR ACCESS|config=OK|ping=OK served|again=ERR LIMIT', '|text=app:netonly#3|config=ERR ACCESS'"]),
            "M379": (False, "_CHAND", ["|waiting=5|handles=12|mgr_handles=20|"]),
            "M380": (False, "_CHAND", ["|waiting=5|handles=10|mgr_handles=20|"]),
            "M381": (True, "_CHAND", ["|waiting=5|handles=15|mgr_handles=20|"]),
            "M382": (True, None, ["'|text=app:both#2|config=OK|display=OK|again=ERR LIMIT'"]),
            "M383": (True, None, ["'|text=app:both#2|config=OK|display=OK|again=ERR LIMIT', '|text=app:netonly#3|config=ERR ACCESS'"]),
            "M384": (True, "_CKEPT", ["|handles=9|mgr_handles=21|"]),
        }
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if m[4] == [self.CONNECT]), sorted(want))
        seen = set()
        for mid, (security, const, rest) in want.items():
            with self.subTest(mutant=mid):
                m = next(m for m in mutants.MUTANTS if m[0] == mid)
                self.assertEqual(m[1], "user/apps/svcmgr/src/main.rs")
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(set(E.get(mid, {})), {self.CONNECT})
                subs = E[mid][self.CONNECT]
                if const is None:
                    # Known by the missing markers alone: each named one is a required marker.
                    self.assertEqual(len(subs), 1)
                    self.assertTrue(subs[0].startswith("missing markers ["), subs[0])
                    for marker in re.findall(r"'([^']+)'", subs[0]):
                        self.assertIn(marker, case["required_markers"])
                else:
                    msg = getattr(mutants, const)
                    self.assertEqual(sorted(subs), sorted(["exit 37", msg] + rest))
                    self.assertIn(f'fail("{msg[len("|ktest|fail|"):]}")', src)
                    for x in rest:
                        self.assertNotIn(x, line, f"{x} is the pinned line")
                        for f in x.strip("|").split("|"):
                            self.assertIn("|" + f.split("=")[0] + "=", line, f)
                seen.add((const, tuple(rest)))
        self.assertEqual(len(seen), len(want), "each mutant is known by its own evidence")
        declares = {"conn": "config", "connx": "config", "both": "display,config", "netonly": "net", "stuck": "config"}
        self.assertEqual(case.get("disk_files"), {
            f"SYSTEM/APPS/{n.upper()}.{x}": (f"platform/pc-qemu/lab/{n}.app" if x == "APP" else "${OUT}/apps/svc.elf")
            for n in declares for x in ("APP", "ELF")} | {"SYSTEM/LABSES.ELF": "${OUT}/apps/svc.elf"})
        for name, deps in declares.items():
            entry = (ROOT / "platform" / "pc-qemu" / "lab" / f"{name}.app").read_text(encoding="utf-8")
            self.assertIn(f"\nid={name}\nelf=/SYSTEM/APPS/{name.upper()}.ELF\n", entry)
            self.assertIn(f"\ndeps={deps}\n", entry)
        # Refused CONNECTs the services must never hear of.
        for name in ("conn#9", "netonly"):
            self.assertIn(f"|text=svc|connect|app:{name}", case["forbidden_markers"])

    SESSION_JOB = "TST-M6-SESSION-JOB"

    def test_the_session_job_expectations_are_pinned(self):
        """WP-102 (REQ-M6-004; services.md v1.17, ADR-0023 item 1): the session's job. M141,
        M385 to M387 and M392 to M395, each anchor once in user/apps/svcmgr/src/main.rs, are
        declared on TST-M6-SESSION-JOB (M385 and M395 on TST-M6-APP-SPAWN too), each known there
        by exit 37, the case's message for END_SESSION's replies (the session's step, 0x5k00,
        in the line) and fields of the case's one line with another value than the pinned
        line's, no two sharing their evidence; M141, M385, M386, M392, M393 and M395 are
        SECURITY. The case's lab manifest gives the session the role `ender` and `desktop` and
        `sessions`, started once it is READY, END_SESSION expecting ERR ACCESS; its volume
        carries the two lab entries."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.SESSION_JOB)
        line = next(m for m in case["required_markers"] if m.startswith("|ktest|session_job|load="))
        self.assertEqual(line, "|ktest|session_job|load=OK 3|session=0x40|desktop=0x40|sessions=0x40|stay=1|waiting=1|nest=0|idle=0|"
                               "under_root=0|in_session=1|live_jobs=2|mgr_handles=4|")
        want = {  # id: (SECURITY, the substrings besides exit 37 and the message)
            "M141": (True, ["|session=0x5400|", "|nest=1|idle=1|under_root=0|in_session=1|live_jobs=3|"]),
            "M385": (True, ["|session=0x5400|", "|nest=1|idle=1|under_root=1|in_session=0|"]),
            "M386": (True, ["|session=0x5300|desktop=0x51|sessions=0x51|"]),
            "M387": (False, ["|session=0x5500|desktop=0x40|sessions=0x40|"]),
            "M392": (True, ["|session=0x5300|desktop=0x40|sessions=0x51|"]),
            "M393": (True, ["|session=0x5300|desktop=0x40|sessions=0x40|"]),
            "M394": (False, ["|session=0x5400|desktop=0x40|sessions=0x40|stay=0|"]),
            "M395": (True, ["|session=0x5400|", "|nest=1|idle=1|under_root=0|in_session=1|live_jobs=4|"]),
        }
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if self.SESSION_JOB in m[4]), sorted(want))
        msg = mutants._SJANS
        self.assertIn(f'fail("{msg[len("|ktest|fail|"):]}")', src)
        seen = set()
        for mid, (security, rest) in want.items():
            with self.subTest(mutant=mid):
                m = next(m for m in mutants.MUTANTS if m[0] == mid)
                self.assertEqual(m[1], "user/apps/svcmgr/src/main.rs")
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                both = mid in ("M385", "M395")
                self.assertEqual(m[4], [self.SESSION_JOB] + ([self.SPAWN] if both else []))
                self.assertEqual(sorted(E[mid]), sorted([self.SESSION_JOB] + ([self.SPAWN] if both else [])))
                self.assertEqual(sorted(E[mid][self.SESSION_JOB]), sorted(["exit 37", msg] + rest))
                for x in rest:
                    self.assertNotIn(x, line, f"{x} is the pinned line")
                    for f in x.strip("|").split("|"):
                        self.assertIn("|" + f.split("=")[0] + "=", line, f)
                seen.add(tuple(rest))
        self.assertEqual(len(seen), len(want), "each mutant is known by its own evidence")
        self.assertEqual(E["M385"][self.SPAWN], ["exit 37", "|under_root=8|in_session=0|parents=1|", mutants._NOJOB])
        self.assertEqual(E["M395"][self.SPAWN], ["exit 37", "|in_session=8|parents=8|", mutants._NOJOB])
        manifest = (ROOT / "platform" / "pc-qemu" / "manifests" / "svc-sj.txt").read_text(encoding="utf-8")
        self.assertIn("\nsession /SYSTEM/LABSES.ELF - 3000 never 0 0 ender\n", manifest)
        for name in ("desktop", "sessions"):
            self.assertIn(f"\n{name} /SYSTEM/SVC.ELF session 3000 never 0 0 ask END_SESSION=ERR ACCESS\n", manifest)
        self.assertEqual(case.get("disk_files"), {
            f"SYSTEM/APPS/{n.upper()}.{x}": (f"platform/pc-qemu/lab/{n}.app" if x == "APP" else "${OUT}/apps/svc.elf")
            for n in ("stay", "nest") for x in ("APP", "ELF")} | {"SYSTEM/LABSES.ELF": "${OUT}/apps/svc.elf"})

    LOGOUT_KILLS = "TST-M6-LOGOUT-KILLS"

    def test_the_logout_expectations_are_pinned(self):
        """WP-167 (REQ-M6-004; session.md v1.8): Sign out ends the session's job. M388, M389 and
        M396, each anchor once in user/apps/sessiond/src/main.rs, are declared on
        TST-M6-LOGOUT-KILLS alone: M388 (SECURITY, no END_SESSION) by exit 37, the case's message
        for what outlived the sign-out and the counts of its phase-2 line, each another value than
        the pinned line's; M389 (the count traced as 0) by the forbidden `apps=0` trace; M396
        (the answer taken for a CONNECT's) by the missing `apps=2` trace with no
        forbidden marker present; and, from WP-169 (session.md v1.9), M410 (a sign-in that begins no
        session) by exit 37, the case's message for its steps and both launches refused ERR
        NO_SESSION, and M413 and M414 (SECURITY: a session begun at boot, or again by Sign out) by
        exit 37, a message of the case and the desktop's launch before the first sign-in or after
        the sign-out answered OK. The case's manifest runs the real session with the lab image as `desktop` in
        the role `relay`, and its volume carries deaf (winapp, declaring display) and nest; a
        refused or unsent BEGIN_SESSION is a forbidden marker."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.LOGOUT_KILLS)
        line = next(m for m in case["required_markers"] if m.startswith("|ktest|logout_kills|back="))
        self.assertEqual(line, "|ktest|logout_kills|back=OK no_session user=- changes=3 display=1 input=1 focus=session|deaf=0|nest=0|idle=0|"
                               "jobs=0|mgr_handles=0|phase=2")
        self.assertIn("|text=session|jobs=ended|apps=2", case["required_markers"])
        for bad in ("|text=session|jobs=ended|apps=0", "|text=session|jobs=unsent", "|text=session|jobs=refused", "lab-admin-1",
                    "|text=session|begin=refused", "|text=session|begin=unsent"):
            self.assertIn(bad, case["forbidden_markers"])
        want = {  # id: (SECURITY, the expected substrings)
            "M388": (True, ["exit 37", "|deaf=1|nest=1|idle=1|jobs=3|mgr_handles=7|", mutants._LKALIVE]),
            "M389": (False, ["forbidden present ['|text=session|jobs=ended|apps=0']"]),
            "M396": (False, ["missing markers ['|text=session|jobs=ended|apps=2']; forbidden present []"]),
            "M410": (False, ["exit 37", "|launched=ERR NO_SESSION,ERR NO_SESSION|", mutants._LKSTEPS]),
            "M413": (True, ["exit 37", "|gate|before=OK app:deaf#1|", mutants._LKALIVE]),
            "M414": (True, ["exit 37", "|gate|before=ERR NO_SESSION|after=OK app:deaf#3|", mutants._LKSTEPS]),
        }
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if self.LOGOUT_KILLS in m[4]), sorted(want))
        for msg in (mutants._LKALIVE, mutants._LKSTEPS):
            self.assertIn(f'fail("{msg[len("|ktest|fail|"):]}")', src)
        self.assertIn("|launched=OK app:deaf#1,OK app:nest#2|", " ".join(case["required_markers"]))
        self.assertIn("|ktest|logout_kills|gate|before=ERR NO_SESSION|after=ERR NO_SESSION|", case["required_markers"])
        for mid, (security, subs) in want.items():
            with self.subTest(mutant=mid):
                m = next(m for m in mutants.MUTANTS if m[0] == mid)
                self.assertEqual(m[1], "user/apps/sessiond/src/main.rs")
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(m[4], [self.LOGOUT_KILLS])
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(E[mid], {self.LOGOUT_KILLS: subs})
        for x in want["M388"][1][1].strip("|").split("|"):
            self.assertIn("|" + x.split("=")[0] + "=", line, x)
        self.assertNotIn(want["M388"][1][1], line)
        manifest = (ROOT / "platform" / "pc-qemu" / "manifests" / "svc-lk.txt").read_text(encoding="utf-8")
        self.assertIn("\nsession /SYSTEM/SESSIOND.ELF auth,input,display 5000 never 0 0\n", manifest)
        self.assertIn("\ndesktop /SYSTEM/SVC.ELF session 3000 never 0 0 relay\n", manifest)
        self.assertEqual(case.get("disk_files"), {
            "SYSTEM/APPS/DEAF.APP": "platform/pc-qemu/lab/deaf.app", "SYSTEM/APPS/DEAF.ELF": "${OUT}/apps/winapp.elf",
            "SYSTEM/APPS/NEST.APP": "platform/pc-qemu/lab/nest.app", "SYSTEM/APPS/NEST.ELF": "${OUT}/apps/svc.elf"})
        self.assertIn("\ndeps=display\n", (ROOT / "platform" / "pc-qemu" / "lab" / "deaf.app").read_text(encoding="utf-8"))

    JOB_BOUND = "TST-M6-JOB-BOUND"

    def test_the_job_bound_expectations_are_pinned(self):
        """WP-164 (RSK-050; syscall.md v1.15): a job holds 32 live processes at most. M397 to
        M400, each anchor once in its kernel file, are declared on TST-M6-JOB-BOUND alone, each
        known by exit 37, one message occurring as a failure in ktest.rs and fields of one of the
        case's two lines (the count's own check, `unit|`, or the jobs' line) with other values
        than the pinned ones, no two sharing their evidence; M397 (no bound) and M398 (counted
        in the root) are SECURITY. The case's manifest and its two lab entries are pinned."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.JOB_BOUND)
        unit = "|ktest|job_bound|unit|taken=32|refused=1|again=1|counted=32|back=0|root=40|"
        line = "|ktest|job_bound|load=OK 1|session=0x40|hog_live=32|hog_count=32|peer_live=3|peer_count=3|clocks=1|"
        self.assertIn(unit, case["required_markers"])
        self.assertIn(line, case["required_markers"])
        want = {  # id: (file, SECURITY, message constant, the substring of changed fields)
            "M397": ("kernel/src/object/job.rs", True, "_JBUNIT", "|unit|taken=40|refused=0|"),
            "M398": ("kernel/src/sched/mod.rs", True, "_JBNOT", "|hog_live=65|hog_count=0|"),
            "M399": ("kernel/src/object/job.rs", False, "_JBUNIT", "|again=0|counted=32|back=32|"),
            "M400": ("kernel/src/object/job.rs", False, "_JBUNIT", "|unit|taken=33|"),
        }
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if self.JOB_BOUND in m[4]), sorted(want))
        for mid, (path, security, const, fields) in want.items():
            with self.subTest(mutant=mid):
                m = next(m for m in mutants.MUTANTS if m[0] == mid)
                self.assertEqual(m[1], path)
                self.assertEqual((ROOT / m[1]).read_text(encoding="utf-8").count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(m[4], [self.JOB_BOUND])
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                msg = getattr(mutants, const)
                self.assertEqual(E[mid], {self.JOB_BOUND: ["exit 37", fields, msg]})
                self.assertIn(f'fail("{msg[len("|ktest|fail|"):]}")', src)
                pinned = unit if const == "_JBUNIT" else line
                self.assertNotIn(fields, pinned)
                for f in fields.strip("|").split("|"):
                    if "=" in f:
                        self.assertIn("|" + f.split("=")[0] + "=", pinned, f)
        manifest = (ROOT / "platform" / "pc-qemu" / "manifests" / "svc-jb.txt").read_text(encoding="utf-8")
        self.assertIn("\nsession /SYSTEM/LABSES.ELF - 3000 never 0 0 bounder\n", manifest)
        for n in ("hog", "peer"):
            self.assertIn(f"\nid={n}\nelf=/SYSTEM/APPS/{n.upper()}.ELF\n", (ROOT / "platform" / "pc-qemu" / "lab" / f"{n}.app").read_text(encoding="utf-8"))

    LAUNCH_RATE = "TST-M6-LAUNCH-RATE"

    def test_the_launch_rate_expectations_are_pinned(self):
        """WP-163 (services.md v1.18): LAUNCH is bounded in rate, 16 attempts in any 1000 ticks.
        M401 to M405, each anchoring once in the manager, are declared on TST-M6-LAUNCH-RATE alone,
        each known by exit 37, the case's one failure message and the session's exit code at the
        step it breaks (the rater's (0x50 + k) * 256 + its last number), no two sharing their
        evidence; M401 (no attempt kept) and M405 (a failed launch not counted) are SECURITY. The
        limit's two constants, the case's manifest, line and timeout, and its volume are pinned."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        mgr = (ROOT / "user" / "apps" / "svcmgr" / "src" / "main.rs").read_text(encoding="utf-8")
        self.assertIn("\nconst LAUNCH_RATE_MAX: usize = 16;\nconst LAUNCH_WINDOW: u64 = 1000;\n", mgr)
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.LAUNCH_RATE)
        line = "|ktest|launch_rate|load=OK 1|session=0x40|stays=0|exits=0|live_jobs=1|mgr_handles=1|"
        self.assertIn(line, case["required_markers"])
        self.assertIn("|text=rater|step=", case["forbidden_markers"])
        self.assertEqual(case["timeout_s"], 30)
        msg = "|ktest|fail|a LAUNCH was not answered as the rate limit states"
        self.assertEqual(mutants._LRANS, msg)
        self.assertIn(f'fail("{msg[len("|ktest|fail|"):]}")', src)
        want = {  # id: (SECURITY, the session's exit code)
            "M401": (True, "0x5711"),   # step 7: three more let through, #15 to #17
            "M402": (False, "0x5400"),  # step 4: refused ERR BUSY after the full table's refusals
            "M403": (False, "0x5a00"),  # step 10: still ERR BUSY, step 8's refusals counted
            "M404": (False, "0x5900"),  # step 9: the unknown id answered ERR BUSY
            "M405": (True, "0x5710"),   # step 7: two more let through, the two failed not counted
        }
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if self.LAUNCH_RATE in m[4]), sorted(want))
        for mid, (security, code) in want.items():
            with self.subTest(mutant=mid):
                m = next(m for m in mutants.MUTANTS if m[0] == mid)
                self.assertEqual(m[1], "user/apps/svcmgr/src/main.rs")
                self.assertEqual(mgr.count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(m[4], [self.LAUNCH_RATE])
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(E[mid], {self.LAUNCH_RATE: ["exit 37", f"|session={code}|", msg]})
        manifest = (ROOT / "platform" / "pc-qemu" / "manifests" / "svc-lr.txt").read_text(encoding="utf-8")
        self.assertIn("\nsession /SYSTEM/LABSES.ELF - 3000 never 0 0 rater\n", manifest)
        self.assertEqual(case.get("disk_files"), {
            "SYSTEM/APPS/STAY.APP": "platform/pc-qemu/lab/stay.app", "SYSTEM/APPS/EXIT.APP": "platform/pc-qemu/lab/exit.app",
            "SYSTEM/APPS/BAD.APP": "platform/pc-qemu/lab/bad.app", "SYSTEM/APPS/STAY.ELF": "${OUT}/apps/svc.elf",
            "SYSTEM/APPS/EXIT.ELF": "${OUT}/apps/exiter.elf", "SYSTEM/APPS/BAD.ELF": "platform/pc-qemu/lab/bad.app",
            "SYSTEM/LABSES.ELF": "${OUT}/apps/svc.elf"})
        # notes is registered by the volume's sample NOTES.APP, whose image no build places.
        self.assertIn("\nid=notes\n", (ROOT / "platform" / "pc-qemu" / "apps" / "NOTES.APP").read_text(encoding="utf-8"))
        self.assertNotIn("SYSTEM/APPS/NOTES.ELF", case["disk_files"])

    SESSION_GATE = "TST-M6-SESSION-GATE"

    def test_the_session_gate_expectations_are_pinned(self):
        """WP-169 (services.md v1.19): LAUNCH needs an open session. M406 to M409, M411 and M412,
        each anchoring once in the manager, are declared on TST-M6-SESSION-GATE alone, each known by
        exit 37, one of the case's two failure messages and the exit codes of the session and the
        desktop at the step each breaks, no two sharing their evidence; all but M412 (a refusal
        counted as an attempt) are SECURITY (M410, M413 and M414, the session's side, are pinned with
        TST-M6-LOGOUT-KILLS). The case's manifest, line, timeout and volume, and
        the gate's reply in LAUNCH-DENIED's manifest are pinned."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        mgr = (ROOT / "user" / "apps" / "svcmgr" / "src" / "main.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.SESSION_GATE)
        line = "|ktest|session_gate|load=OK 2|session=0x0|desktop=0x40|stays=0|waiting=0|live_jobs=0|mgr_handles=0|"
        self.assertIn(line, case["required_markers"])
        for bad in ("|text=gater|step=", "|text=ungated|step="):
            self.assertIn(bad, case["forbidden_markers"])
        self.assertEqual(case["timeout_s"], 30)
        self.assertIn('out.put(b"ERR NO_SESSION")', mgr)
        msgs = {"_SGSES": "|ktest|fail|a LAUNCH or BEGIN_SESSION of the session was not answered as the gate states",
                "_SGDESK": "|ktest|fail|the desktop opened the gate, or the session's exit did not close it",
                "_SGEXIT": "|ktest|fail|an application or a job of the session outlived the session service"}
        for const, msg in msgs.items():
            self.assertEqual(getattr(mutants, const), msg)
            self.assertIn(f'fail("{msg[len("|ktest|fail|"):]}")', src)
        want = {  # id: (message constant, the exit codes, SECURITY)
            "M406": ("_SGSES", "|session=0x5100|desktop=0x5200|", True),  # step 1 answered OK; the desktop's step 2 too
            "M407": ("_SGDESK", "|session=0x0|desktop=0x5100|", True),    # the desktop's BEGIN_SESSION answered BEGUN
            "M408": ("_SGSES", "|session=0x5600|", True),                 # step 6, after END_SESSION, answered OK
            "M409": ("_SGDESK", "|session=0x0|desktop=0x5200|", True),    # the desktop's LAUNCH after the session's clean exit
            "M411": ("_SGSES", "|session=0x5900|", True),                 # step 9, after an END_SESSION with no application
            "M412": ("_SGSES", "|session=0x5300|", False),                # step 3 refused ERR BUSY after seventeen refusals
            # WP-172 (services.md v1.20): the session's exit ends its job.
            "M415": ("_SGEXIT", "|stays=1|waiting=1|live_jobs=2|mgr_handles=4|", True),   # stay#2 outlives the session
            "M416": ("_SGEXIT", "|stays=0|waiting=0|live_jobs=1|mgr_handles=1|", False),  # its killed job kept
        }
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if self.SESSION_GATE in m[4]), sorted(want))
        for mid, (const, codes, security) in want.items():
            with self.subTest(mutant=mid):
                m = next(m for m in mutants.MUTANTS if m[0] == mid)
                self.assertEqual(m[1], "user/apps/svcmgr/src/main.rs")
                self.assertEqual(mgr.count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(m[4], [self.SESSION_GATE])
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(E[mid], {self.SESSION_GATE: ["exit 37", codes, getattr(mutants, const)]})
                self.assertNotIn(codes, line)
        manifest = (ROOT / "platform" / "pc-qemu" / "manifests" / "svc-gt.txt").read_text(encoding="utf-8")
        self.assertEqual([l for l in manifest.splitlines() if l and not l.startswith("#")],
                         ["session /SYSTEM/SVC.ELF - 3000 never 0 0 gater", "desktop /SYSTEM/SVC.ELF session 3000 never 0 0 ungated"])
        self.assertEqual(case.get("disk_files"), {"SYSTEM/APPS/STAY.APP": "platform/pc-qemu/lab/stay.app",
                                                  "SYSTEM/APPS/STAY.ELF": "${OUT}/apps/svc.elf"})

    SESSION_RESTART = "TST-M6-SESSION-RESTART"

    def test_the_session_restart_expectations_are_pinned(self):
        """WP-173 (services.md v1.20): the session's exit ends its job however it comes. M417 (the
        job ended only at a clean exit), M418 (ended and its handle closed but kept), M419 (ended
        only at a clean exit or a stop), M420 (the gate left open after an unclean exit) and M421
        (the session known by its place in the manifest), each anchoring once in the manager, are
        declared on TST-M6-SESSION-RESTART alone, each known by exit 37, the failure message of the
        phase it breaks and the fields of that phase's line that differ from the pinned ones, no
        two sharing their evidence; all but M418 are SECURITY. The case's lines, timeout, manifest
        (a lab service before the session) and volume, and the role's failure trace forbidden, are
        pinned."""
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        mgr = (ROOT / "user" / "apps" / "svcmgr" / "src" / "main.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.SESSION_RESTART)
        lines = {
            "restart": ("|ktest|session_restart|restart|restart=OK|exit=0x40|restarts=1|held=1|stays=1|new_job=1|"
                        "live_jobs=2|mgr_handles=4|"),
            "crash": ("|ktest|session_restart|crash|killed=1|exit=0x20000|restarts=2|held=1|stays=1|new_job=1|"
                      "live_jobs=2|mgr_handles=4|"),
            "stop": "|ktest|session_restart|stop|stop=OK|state=stopped|exit=0x40|stays=0|live_jobs=0|mgr_handles=0|",
        }
        for line in ("|ktest|session_restart|load=OK 2|session=0x40|first=1|", *lines.values(),
                     "|ktest|session_restart|frames_delta=0"):
            self.assertIn(line, case["required_markers"])
        self.assertIn("|text=launcher|step=", case["forbidden_markers"])
        self.assertEqual(case["timeout_s"], 45)
        msgs = {"_SRKEPT": "|ktest|fail|an application of the restarted session outlived it, or the new session could not launch",
                "_SRCRASH": ("|ktest|fail|an application of the crashed session outlived it, or the session started again "
                             "could not launch")}
        for const, msg in msgs.items():
            self.assertEqual(getattr(mutants, const), msg)
            self.assertIn(f'fail("{msg[len("|ktest|fail|"):]}")', src)
        want = {  # id: (the phase it breaks, its message constant, the fields that differ, SECURITY)
            # the old job lives on: the first stay and the new one in it, its job and handles kept
            "M417": ("restart", "_SRKEPT", "|exit=0x40|restarts=1|held=1|stays=2|new_job=0|live_jobs=3|mgr_handles=7|", True),
            # every LAUNCH of the session started again goes to the closed handle, until given up
            "M418": ("restart", "_SRKEPT", "|exit=0x5100|restarts=3|held=0|stays=0|new_job=0|live_jobs=0|mgr_handles=0|", False),
            # the crashed session's job lives on, and the next session launches into it
            "M419": ("crash", "_SRCRASH", "|exit=0x20000|restarts=2|held=1|stays=2|new_job=0|live_jobs=3|mgr_handles=7|", True),
            # the gate stays open: each session started again is answered its first LAUNCH and exits 0xE4
            "M420": ("restart", "_SRKEPT", "|exit=0xe4|restarts=3|held=0|stays=0|new_job=0|live_jobs=0|mgr_handles=0|", True),
            # nothing is closed or killed for the session after the lab service: four stays in the first job
            "M421": ("restart", "_SRKEPT", "|exit=0xe4|restarts=3|held=0|stays=4|new_job=0|live_jobs=5|mgr_handles=13|", True),
        }
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if self.SESSION_RESTART in m[4]), sorted(want))
        seen = set()
        for mid, (phase, const, fields, security) in want.items():
            with self.subTest(mutant=mid):
                m = next(m for m in mutants.MUTANTS if m[0] == mid)
                self.assertEqual(m[1], "user/apps/svcmgr/src/main.rs")
                self.assertEqual(mgr.count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(m[4], [self.SESSION_RESTART])
                self.assertEqual(mid in mutants.SECURITY, security)
                self.assertEqual(m[5].startswith("SECURITY: "), security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                self.assertEqual(E[mid], {self.SESSION_RESTART: ["exit 37", fields, getattr(mutants, const)]})
                self.assertNotIn(fields, lines[phase])
                self.assertNotIn((fields, const), seen)
                seen.add((fields, const))
        manifest = (ROOT / "platform" / "pc-qemu" / "manifests" / "svc-sx.txt").read_text(encoding="utf-8")
        self.assertEqual([l for l in manifest.splitlines() if l and not l.startswith("#")],
                         ["lab /SYSTEM/SVC.ELF - 3000 never 0 0 ready",
                          "session /SYSTEM/LABSES.ELF - 3000 on-failure 3 10 stayer"])
        self.assertEqual(case.get("disk_files"), {"SYSTEM/APPS/STAY.APP": "platform/pc-qemu/lab/stay.app",
                                                  "SYSTEM/APPS/STAY.ELF": "${OUT}/apps/svc.elf",
                                                  "SYSTEM/LABSES.ELF": "${OUT}/apps/svc.elf"})

    READ_LOAD = "TST-M4-CONFIG-READ-LOAD"

    def test_the_read_load_expectations_are_pinned(self):
        """WP-112 (config.md v1.6): a user store is read for its owner's or an administrator's usable
        token alone and loaded on that read. M422 to M437, each anchoring once in configd, are
        declared on TST-M4-CONFIG-READ-LOAD alone; the SECURITY ones are M422 (any request reads
        and loads), M424 (a revoked token reads), M425 (a read of a store no volume holds keeps its
        slot), M427 and M429 (a refused GET or EXPORT reads a loaded store), M430 (an unusable
        administrator's token reads), M431 (a refused reader is told the table is full), M432
        (CONFIG_WRITE reads), M433 (a group of that uid reads) and M437 (SUBSCRIBE of a loaded user
        store accepted). Each is known by exit 37, one of the case's four failure messages and
        fields of its three lines that differ from the pinned ones (each field's name in those
        lines, not every value the pinned one), except M436, under which the guest passes and the
        host check on the volume fails (no slot B of generation 2, slot A no longer holding the
        read line); no two share their evidence. The case's lines, host checks and volume are
        pinned, and each lab store a NAWAH-CFG 1 slot whose digest covers its one line."""
        import hashlib
        E = mutants.EXPECT
        src = (ROOT / "kernel" / "src" / "ktest.rs").read_text(encoding="utf-8")
        cfg = (ROOT / "user" / "apps" / "configd" / "src" / "main.rs").read_text(encoding="utf-8")
        t = json.loads((ROOT / "platform" / "pc-qemu" / "target.json").read_text(encoding="utf-8"))
        case = next(c for cs in t["suites"].values() for c in cs if c["id"] == self.READ_LOAD)
        pinned = [
            ("|ktest|config_read_load|bare=ERR NOT_FOUND|resolve=OK user 1 mine|bare_loaded=ERR NOT_FOUND|own=OK 1 mine|"
             "own_export=OK;lab.read 1 mine|admin=OK 1 theirs|"),
            ("|ktest|config_read_load|more|other_loaded=ERR NOT_FOUND|other_loaded_export=ERR NOT_FOUND|other=ERR NOT_FOUND|"
             "other_export=ERR NOT_FOUND|absent=6|filled=6|full_set=ERR INVALID|full_read=ERR INVALID|revoked=ERR NOT_FOUND|"
             "revoked_export=ERR NOT_FOUND|"),
            ("|ktest|config_read_load|full|sub_loaded=ERR ACCESS|pol=OK 1|refused_full=ERR NOT_FOUND|bare_full=ERR NOT_FOUND|"
             "loaded_full=OK 1 theirs|resolve_full=OK user 1 mine|policy_full=OK policy 1 locked|stranger_full=ERR INVALID|"
             "cw=ERR NOT_FOUND|grp=ERR NOT_FOUND|admin_expired=ERR NOT_FOUND|write=OK 2|admin_revoked=ERR NOT_FOUND|"),
        ]
        for line in (*pinned, "|ktest|config_read_load|frames_delta=0"):
            self.assertIn(line, case["required_markers"])
        lines = "".join(pinned)
        checks = [c for c in case["host_checks"] if c[:4] == ["python3", "-I", "tools/fat32.py", "grep"]]
        self.assertEqual([c[5:] for c in checks], [["/SYSTEM/CFGU1001.B", "NAWAH-CFG 1 2 "],
                                                  ["/SYSTEM/CFGU1001.B", "lab.read 2 new\n"],
                                                  ["/SYSTEM/CFGU1001.A", "lab.read 1 mine\n"]])
        msgs = {"_RLLOAD": "|ktest|fail|a user store was not loaded on a read of its owner or an administrator",
                "_RLAUTH": "|ktest|fail|a user store was read without its owner's or an administrator's usable token",
                "_RLSLOT": "|ktest|fail|a refused read or a store no volume holds took a slot of the table",
                "_RLFULL": "|ktest|fail|a full table stood before a policy value or a loaded store"}
        for const, msg in msgs.items():
            self.assertEqual(getattr(mutants, const), msg)
            self.assertIn(f'fail("{msg[len("|ktest|fail|"):]}")', src)
        security = {"M422", "M424", "M425", "M427", "M429", "M430", "M431", "M432", "M433", "M437"}
        want = {"M422": "_RLAUTH", "M423": "_RLLOAD", "M424": "_RLAUTH", "M425": "_RLSLOT", "M426": "_RLLOAD",
                "M427": "_RLAUTH", "M428": "_RLSLOT", "M429": "_RLAUTH", "M430": "_RLAUTH", "M431": "_RLAUTH",
                "M432": "_RLAUTH", "M433": "_RLAUTH", "M434": "_RLFULL", "M435": "_RLFULL", "M436": None,
                "M437": "_RLAUTH"}
        self.assertEqual(sorted(m[0] for m in mutants.MUTANTS if self.READ_LOAD in m[4]), sorted(want))
        found = set()
        for mid, const in want.items():
            with self.subTest(mutant=mid):
                m = next(m for m in mutants.MUTANTS if m[0] == mid)
                self.assertEqual(m[1], "user/apps/configd/src/main.rs")
                self.assertEqual(cfg.count(m[2]), 1)
                self.assertNotEqual(m[2], m[3])
                self.assertEqual(m[4], [self.READ_LOAD])
                self.assertEqual(mid in mutants.SECURITY, mid in security)
                self.assertEqual(m[5].startswith("SECURITY: "), mid in security, m[5])
                self.assertEqual(mutants.stage_of(mid), "M6")
                exp = E[mid][self.READ_LOAD]
                if const is None:  # M436: the host check fails, the guest passing
                    self.assertEqual(exp, ["host checks", "/SYSTEM/CFGU1001.B NAWAH-CFG 1 2  -> 2",
                                           "/SYSTEM/CFGU1001.A lab.read 1 mine\\n -> 1"])
                    fields = tuple(exp)
                else:
                    self.assertEqual((exp[0], exp[-1]), ("exit 37", getattr(mutants, const)))
                    fields = tuple(exp[1:-1])
                    self.assertTrue(fields)
                    for f in fields:  # fields of the pinned lines, not all with their pinned values
                        self.assertNotIn(f, lines)
                        items = [x for x in f.strip("|").split("|") if "=" in x]  # a line's head is no field
                        self.assertTrue(items, (mid, f))
                        for item in items:
                            self.assertIn("|" + item.split("=")[0] + "=", lines, (mid, item))
                        self.assertTrue(any("|" + item + "|" not in lines for item in items), (mid, f))
                self.assertNotIn((fields, const), found)
                found.add((fields, const))
        stores = {"SYSTEM/CFGU1001.A": "mine", "SYSTEM/CFGU1002.A": "theirs", "SYSTEM/CFGU1003.A": "hidden"}
        self.assertEqual(case.get("disk_files"), {k: f"platform/pc-qemu/lab/{k[7:].lower()}" for k in stores})
        for name, value in stores.items():
            data = (ROOT / case["disk_files"][name]).read_bytes()
            head, body = data.split(b"\n", 1)
            self.assertEqual(body, f"lab.read 1 {value}\n".encode())
            self.assertEqual(head, b"NAWAH-CFG 1 1 " + hashlib.sha256(body).hexdigest().encode())

def lock_held(path) -> bool:
    """Whether another open file holds `path`'s flock (False when the file is missing)."""
    import fcntl
    try:
        f = open(path, "rb")
    except OSError:
        return False
    with f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


class EvidenceFreeWorktree(unittest.TestCase):
    """WP-130 (RSK-038): the harness's worktree held the whole checkout, evidence/ included (11 GB
    on disk on 2026-11-15), and a harness killed before its cleanup left that worktree behind.
    The worktree a run gives its killers holds every top-level tree of HEAD but evidence/, and the
    run holds a lock for its life; at start the harness removes the worktree and temporary
    directory of an earlier run of this repository under its own root (TMP_ROOT, prefix
    nawah-mutants-) when no live run holds that run's lock, and never another worktree; a failing
    `worktree add` leaves nothing. main() runs on a scratch repository with a tracked evidence
    run; TMP_ROOT and the temporary directory are the test's own, never the system's."""

    FILES = ["kernel/a.rs", "user/b.rs", "tools/c.py", "tests/d.py", ".github/workflows/e.yml", "README"]

    def setUp(self):
        import shutil
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="wp130-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / "root"
        self.root.mkdir()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        scratch_repo(self.repo)
        (self.repo / "evidence" / "r").mkdir(parents=True)
        (self.repo / "evidence" / "r" / "run.json").write_text('{"run_id": "r"}\n')
        (self.repo / "README").write_text("top level\n")
        self.git("add", "-A")
        self.git("-c", "user.name=t", "-c", "user.email=t@t.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "evidence")

    def git(self, *args, cwd=None):
        import subprocess
        return subprocess.run(["git", *args], cwd=cwd or self.repo, check=True, capture_output=True, text=True).stdout

    def listed(self):
        return [pathlib.Path(l[len("worktree "):]).resolve() for l in self.git("worktree", "list", "--porcelain").splitlines()
                if l.startswith("worktree ")]

    def add_wt(self, tmpdir):
        tmpdir.mkdir(parents=True)
        self.git("worktree", "add", "-q", "--detach", str(tmpdir / "wt"), "HEAD")
        return tmpdir / "wt"

    def main(self, repo=None):
        """main() on one tooling mutant with run_killers stubbed; returns what each killer run saw
        of its worktree."""
        seen = []

        def killers(wt, env, target, ks, early_exit=False):
            seen.append({"evidence": (wt / "evidence").exists(), "files": {f: (wt / f).exists() for f in self.FILES},
                         "mutated": (wt / "tools/c.py").read_text(), "locked": lock_held(wt.parent / "lock")})
            return [], {k: "PASS" for k in ks}

        missing = object()
        names = ("REPO", "MUTANTS", "EXPECT", "run_killers", "all_cases", "suite_of", "needs_release", "TMP_ROOT")
        orig = {n: getattr(mutants, n, missing) for n in names}
        argv, tempdir = sys.argv, tempfile.tempdir
        mutants.REPO = repo or self.repo
        mutants.MUTANTS = [("M996", "tools/c.py", "clean", "mutated", ["TST-HOST"], "synthetic")]
        mutants.EXPECT = {}
        mutants.run_killers = killers
        mutants.all_cases = lambda target: []
        mutants.suite_of = lambda target, tid: None
        mutants.needs_release = lambda target, ks: False
        mutants.TMP_ROOT = self.root
        tempfile.tempdir = str(self.root)  # the run's temporary directory is the test's, before and after the change
        sys.argv = ["mutants.py", "--report", "build/r.json"]
        try:
            mutants.main()
        finally:
            for n, v in orig.items():
                if v is missing:
                    delattr(mutants, n)
                else:
                    setattr(mutants, n, v)
            sys.argv, tempfile.tempdir = argv, tempdir
        return seen

    def test_the_worktree_holds_every_tree_but_evidence_and_the_run_holds_its_lock(self):
        seen = self.main()
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0]["evidence"], "the run's worktree holds evidence/")
        self.assertEqual(seen[0]["files"], {f: True for f in self.FILES})
        self.assertEqual(seen[0]["mutated"], "mutated\n")
        self.assertTrue(seen[0]["locked"], "no live lock while the run's killers run")
        self.assertEqual((self.repo / "evidence" / "r" / "run.json").read_text(), '{"run_id": "r"}\n')
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), "")
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.listed(), [self.repo])

    def test_a_dead_runs_worktree_is_removed_at_the_next_start(self):
        import shutil
        old = self.add_wt(self.root / "nawah-mutants-old")
        (old.parent / "lock").write_text("")  # a lock no live run holds
        (old.parent / "scratch-evidence" / "R1").mkdir(parents=True)
        gone = self.add_wt(self.root / "nawah-mutants-gone")
        shutil.rmtree(gone.parent)  # its directory deleted, its registration left
        self.main()
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.listed(), [self.repo])

    def test_a_live_runs_worktree_and_foreign_worktrees_stay(self):
        import fcntl
        import shutil
        live = self.add_wt(self.root / "nawah-mutants-live")
        review = self.add_wt(self.root / "review-1")  # under the root, without the prefix
        other = self.add_wt(self.tmp / "other" / "nawah-mutants-x")  # the prefix, under another root
        lost = self.add_wt(self.root / "review-lost")  # foreign, its directory gone: no prune for it
        shutil.rmtree(lost.parent)
        with open(live.parent / "lock", "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.main()
            listed = self.listed()
        for wt in (live, review, other, lost):
            self.assertIn(wt, listed)
        for wt in (live, review, other):
            self.assertEqual((wt / "tools" / "c.py").read_text(), "clean\n", wt)

    def test_a_failing_worktree_add_leaves_nothing(self):
        import subprocess
        empty = self.tmp / "empty"
        empty.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=empty, check=True)  # no commit: HEAD names nothing
        with self.assertRaises(subprocess.CalledProcessError):
            self.main(repo=empty)
        self.assertEqual(list(self.root.iterdir()), [])


class ShardSelection(unittest.TestCase):
    """WP-98: `--shard k/N` runs the gate's mutants by the stable rule int(id[1:]) mod N == k-1, so
    the gate can run in N jobs side by side. Every mutant of the stage is in exactly one shard, in
    the harness's own order, and a spec outside 1 <= k <= N (or not two plain numbers) is refused
    before anything runs."""

    def test_every_m6_mutant_is_in_exactly_one_shard_for_n_1_to_16(self):
        # 1..16 since WP-153 (verify runs twelve shards).
        stage = [m[0] for m in mutants.MUTANTS if mutants.stage_of(m[0]) == "M6"]
        self.assertGreater(len(stage), 100)
        for n in range(1, 17):
            shards = {k: [m[0] for m in mutants.selection("M6", None, (k, n))] for k in range(1, n + 1)}
            got = [mid for ids in shards.values() for mid in ids]
            self.assertEqual(len(got), len(set(got)), f"N={n}: a mutant in two shards")
            self.assertEqual(sorted(got), sorted(stage), f"N={n}: the shards' union is not the stage")
            for k, ids in shards.items():
                self.assertEqual(ids, [mid for mid in stage if int(mid[1:]) % n == k - 1], f"shard {k}/{n}")

    def test_bad_shard_specs_are_refused(self):
        for good, want in (("1/1", (1, 1)), ("3/8", (3, 8)), ("6/6", (6, 6)), ("12/12", (12, 12))):
            self.assertEqual(mutants.parse_shard(good), want)
        for bad in ("0/6", "7/6", "1/0", "0/0", "-1/6", "1/-6", "a/6", "1/b", "1/6/6", "6", "", " 1/6", "1/6 ",
                    "1/6\n", "01/6", "1/06", "1.0/6", "１/6", "١/6"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                mutants.parse_shard(bad)

    def test_main_refuses_a_bad_spec_before_any_run(self):
        import contextlib
        import io
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = scratch_repo(tmp)
            orig, argv, err = (mutants.REPO, mutants.MUTANTS), sys.argv, io.StringIO()
            mutants.REPO, mutants.MUTANTS = repo, []
            try:
                for bad in ("0/6", "7/6", "1/0"):
                    sys.argv = ["mutants.py", "--stage", "M6", "--report", "build/r.json", "--shard", bad]
                    with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
                        mutants.main()
                    self.assertEqual(cm.exception.code, 2, bad)
            finally:
                mutants.REPO, mutants.MUTANTS = orig
                sys.argv = argv
                subprocess.run(["git", "worktree", "prune"], cwd=repo)
            self.assertIn("1 <= k <= N", err.getvalue())
            self.assertFalse((repo / "build").exists(), "a refused spec wrote a report")


GATE_SHARDS = "NAWAH_GATE_SHARDS"


class ShardMerge(unittest.TestCase):
    """WP-98: each shard writes its report with its identity (k, N, its selected ids, the run: the
    CI run id, attempt and sha when set, else the git HEAD) beside the gate's report; with
    NAWAH_GATE_SHARDS=N the gate's unchanged command runs no mutant and merges the N reports
    instead. The merge refuses, with a named reason, exit MERGE_REFUSED, no verdict line and no
    report, a missing shard, a duplicate id, an id outside its shard's selection or the stage, a
    selection other than the rule's, a truncated report, a report of another run, attempt, sha or
    target, and a union that is not exactly the stage; otherwise it judges the union with
    gate_verdict (counts summed, never ratios averaged) and prints every mutant's line and kept
    kill evidence as a full run does. main() runs on a scratch repository over synthetic tooling
    mutants (killers stubbed: KILL fails, LIVE passes, a missing anchor is invalid)."""

    REPORT = "build/r.json"

    def setUp(self):
        import shutil
        import subprocess
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="wp98-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        scratch_repo(self.repo)
        (self.tmp / "root").mkdir()
        missing = object()
        names = ("REPO", "MUTANTS", "EXPECT", "sh", "run_killers", "all_cases", "suite_of", "needs_release", "TMP_ROOT",
                 "in_shard", "run_identity")
        orig = {n: getattr(mutants, n, missing) for n in names}
        security, argv, env = set(mutants.SECURITY), sys.argv, os.environ.pop(GATE_SHARDS, None)

        def restore():
            for n, v in orig.items():
                if v is missing:
                    if hasattr(mutants, n):
                        delattr(mutants, n)
                else:
                    setattr(mutants, n, v)
            mutants.SECURITY.clear(); mutants.SECURITY.update(security)
            sys.argv = argv
            os.environ.pop(GATE_SHARDS, None)
            if env is not None:
                os.environ[GATE_SHARDS] = env
            subprocess.run(["git", "worktree", "prune"], cwd=self.repo)
        self.addCleanup(restore)
        self.calls = []

        def no_driver(cmd, cwd, env=None, timeout=0):
            raise AssertionError(f"a tooling mutant called the driver or a build: {cmd}")

        def killers(wt, env, target, ks, early_exit=False):
            self.calls.append(list(ks))
            if ks == ["KILL"]:
                mutants.KILLS["KILL"] = {"reason": "exit 37 != expected 33", "run": "R1", "lines": ["OSX|1|ktest|fail|synthetic"]}
                return ["KILL"], {"KILL": "FAIL"}
            return [], {k: "PASS" for k in ks}

        mutants.REPO = self.repo
        mutants.EXPECT = {}
        mutants.sh = no_driver
        mutants.run_killers = killers
        mutants.all_cases = lambda target: []
        mutants.suite_of = lambda target, tid: None
        mutants.needs_release = lambda target, ks: False
        mutants.TMP_ROOT = self.tmp / "root"

    def define(self, count, survived=(), invalid=()):
        """`count` synthetic M6 mutants M900.. on tools/c.py; returns their ids."""
        ids = [f"M{900 + i}" for i in range(count)]
        mutants.MUTANTS = [(mid, "tools/c.py", "no such anchor" if mid in invalid else "clean", "mutated",
                            ["LIVE"] if mid in survived else ["KILL"], "synthetic") for mid in ids]
        return ids

    def main(self, *args):
        import contextlib
        import io
        sys.argv = ["mutants.py", "--stage", "M6", "--report", self.REPORT, *args]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = mutants.main()
        return rc, buf.getvalue()

    def run_shards(self, n):
        got = [self.main("--shard", f"{k}/{n}") for k in range(1, n + 1)]
        for k, (rc, out) in enumerate(got, 1):
            self.assertTrue(self.path(k, n).is_file(), out)
        return got

    def merge(self, n, raw=None):
        os.environ[GATE_SHARDS] = str(n) if raw is None else raw
        before = len(self.calls)
        try:
            rc, out = self.main()
        finally:
            os.environ.pop(GATE_SHARDS, None)
        self.assertEqual(len(self.calls), before, "the merge ran a killer")
        p = self.repo / self.REPORT
        return rc, out, (json.loads(p.read_text()) if p.exists() else None)

    def path(self, k, n):
        return self.repo / "build" / "r.shards" / f"shard-{k}-of-{n}.json"

    def shard(self, k, n):
        return json.loads(self.path(k, n).read_text())

    def put(self, k, n, report):
        self.path(k, n).write_text(json.dumps(report))

    def assert_refused(self, merged, *needles):
        rc, out, report = merged
        self.assertEqual(rc, mutants.MERGE_REFUSED, out)
        self.assertIn("merge refused: ", out)
        for s in needles:
            self.assertIn(s, out)
        self.assertNotRegex(out, r"(?m)^(OK|FAIL): ", "a refused merge printed a verdict")
        self.assertIsNone(report, "a refused merge left a report")

    # -- the shard runs

    def test_a_shard_runs_its_own_mutants_and_writes_its_identity(self):
        ids = self.define(10)
        rc, out = self.main("--shard", "2/3")
        want = [mid for mid in ids if int(mid[1:]) % 3 == 1]
        self.assertEqual(rc, 0, out)
        r = self.shard(2, 3)
        self.assertEqual({k: r["shard"][k] for k in ("k", "n", "stage", "only", "selected")},
                         {"k": 2, "n": 3, "stage": "M6", "only": None, "selected": want})
        self.assertEqual([e["id"] for e in r["mutants"]], want)
        self.assertEqual(self.calls, [["KILL"]] * len(want), "a shard ran another shard's mutant")
        self.assertEqual(r["run"], mutants.run_identity())
        self.assertTrue(r["run"] and all(r["run"].values()), r["run"])
        self.assertFalse((self.repo / self.REPORT).exists(), "a shard wrote the gate's report")
        self.assertIn(f"\nshard 2/3: OK: {len(want)}/{len(want)} valid mutants killed", out)
        self.assertNotRegex(out, r"(?m)^OK", "a shard's line reads as the gate's PASS (project.py's marker)")

    def test_the_run_identity_is_the_ci_runs_when_set_else_the_git_head(self):
        import subprocess
        keys = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")
        saved = {k: os.environ.pop(k, None) for k in keys}
        try:
            os.environ.update(GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="2", GITHUB_SHA="abc")
            self.assertEqual(mutants.run_identity(), {"github_run_id": "7", "github_run_attempt": "2", "github_sha": "abc"})
            for k in keys:
                os.environ.pop(k)
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, capture_output=True, text=True).stdout.strip()
            self.assertEqual(mutants.run_identity(), {"git_head": head})
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v

    # -- the merge

    def test_the_merge_of_every_shard_judges_the_union_and_prints_every_mutant(self):
        ids = self.define(10, invalid={"M903"})
        self.run_shards(2)
        rc, out, rep = self.merge(2)
        self.assertEqual(rc, 0, out)
        self.assertEqual([e["id"] for e in rep["mutants"]], ids)
        self.assertEqual((rep["valid"], rep["killed"], rep["invalid"], rep["ratio"], rep["survived"]), (9, 9, ["M903"], 1.0, []))
        self.assertEqual([s["k"] for s in rep["merged"]["shards"]], [1, 2])
        self.assertEqual(rep["merged"]["n"], 2)
        self.assertEqual(rep["run"], mutants.run_identity())
        for mid in ids:
            if mid != "M903":
                self.assertRegex(out, rf"(?m)^{mid}: killed by KILL \[[0-9.]+s\] \(synthetic\)\n  KILL: exit 37 != expected 33 run=R1\n    OSX\|1\|ktest\|fail\|synthetic$")
        self.assertRegex(out, r"(?m)^M903: INVALID ")
        self.assertIn("\nOK: 9/9 valid mutants killed (100.0%, threshold 95%)", out)
        self.assertIn(f"{GATE_SHARDS}=2", out)

    def test_the_variable_without_shards_is_refused_never_a_full_run(self):
        self.define(4)
        self.assert_refused(self.merge(2), "shard 1/2 is missing")
        self.assertEqual(self.calls, [], "the merge fell back to a full run")

    def test_a_bad_count_or_a_shard_option_in_the_merge_is_refused(self):
        self.define(4)
        self.run_shards(2)
        for raw in ("0", "", "two", "-1", "2 ", "02", "1/2"):
            self.assert_refused(self.merge(2, raw), GATE_SHARDS)
        for args in (("--shard", "1/2"), ("--check",)):
            os.environ[GATE_SHARDS] = "2"
            try:
                rc, out = self.main(*args)
            finally:
                os.environ.pop(GATE_SHARDS, None)
            self.assert_refused((rc, out, None), GATE_SHARDS)
        self.assertEqual(len(self.calls), 4)

    def test_a_missing_shard_is_refused(self):
        self.define(9)
        self.run_shards(3)
        self.assertEqual(self.merge(3)[0], 0)
        self.path(2, 3).unlink()
        self.assert_refused(self.merge(3), "shard 2/3 is missing")  # and the report of the merge before is gone

    def test_a_duplicate_inside_a_shard_is_refused(self):
        self.define(6)
        self.run_shards(2)
        s1 = self.shard(1, 2)
        s1["mutants"].append(dict(s1["mutants"][0]))
        self.put(1, 2, s1)
        self.assert_refused(self.merge(2), f"{s1['mutants'][0]['id']} is decided twice")

    def test_a_duplicate_across_shards_is_refused(self):
        self.define(6)
        self.run_shards(2)
        s1, s2 = self.shard(1, 2), self.shard(2, 2)
        s2["mutants"].append(s1["mutants"][0])
        self.put(2, 2, s2)
        self.assert_refused(self.merge(2), s1["mutants"][0]["id"])

    def test_an_id_outside_its_selection_or_the_stage_is_refused(self):
        self.define(6)
        self.run_shards(2)
        s1, s2 = self.shard(1, 2), self.shard(2, 2)
        self.put(1, 2, dict(s1, mutants=s1["mutants"] + [dict(s1["mutants"][0], id="M999")]))
        self.assert_refused(self.merge(2), "M999 in shard 1/2 is not in its selection")
        moved = s2["mutants"][-1]
        self.put(1, 2, dict(s1, mutants=s1["mutants"] + [moved]))
        self.put(2, 2, dict(s2, mutants=s2["mutants"][:-1]))
        self.assert_refused(self.merge(2), f"{moved['id']} in shard 1/2 is not in its selection")

    def test_a_selection_other_than_the_rules_is_refused(self):
        self.define(6)
        self.run_shards(2)
        s1 = self.shard(1, 2)
        s1["shard"]["selected"] = s1["shard"]["selected"][:-1]
        s1["mutants"] = s1["mutants"][:-1]
        self.put(1, 2, s1)
        self.assert_refused(self.merge(2), "shard 1/2 selected")

    def test_a_truncated_shard_is_refused(self):
        self.define(6)
        self.run_shards(2)
        s2 = self.shard(2, 2)
        self.put(2, 2, dict(s2, mutants=s2["mutants"][:-1]))
        self.assert_refused(self.merge(2), "shard 2/2 is truncated: 2 of its 3 mutants decided")
        s2["mutants"][-1]["status"] = "compiles"
        self.put(2, 2, s2)
        self.assert_refused(self.merge(2), "shard 2/2 is truncated: 2 of its 3 mutants decided")

    def test_a_shard_that_did_not_finish_is_refused_though_every_mutant_is_decided(self):
        """A shard writes its report after every decided mutant; one that raised or was stopped
        after its last mutant (the final reset, a kill) leaves every entry decided but never
        finished. Its report must not reach a verdict (security assurance, WP-98 review)."""
        self.define(6)
        self.run_shards(2)
        s2 = self.shard(2, 2)
        self.assertIs(s2["shard"].get("complete"), True, "a finished shard says so")
        s2["shard"].pop("complete")
        self.put(2, 2, s2)
        self.assert_refused(self.merge(2), "shard 2/2 did not finish")

    def test_a_report_of_another_shard_or_no_shard_report_is_refused(self):
        self.define(6)
        self.run_shards(2)
        self.put(2, 2, self.shard(1, 2))
        self.assert_refused(self.merge(2), "names shard 1/2, not 2/2")
        for text in ("{}", "[]", "not json", '{"shard": {"k": 2, "n": 2}, "mutants": 3}'):
            self.path(2, 2).write_text(text)
            self.assert_refused(self.merge(2), "is not a shard report")

    def test_an_identity_mismatch_is_refused(self):
        self.define(6)
        self.run_shards(2)
        s1, s2 = self.shard(1, 2), self.shard(2, 2)
        other = {k: v + "0" for k, v in s2["run"].items()}
        self.put(2, 2, dict(s2, run=other))
        self.assert_refused(self.merge(2), "shard 2/2 names run")
        self.put(1, 2, dict(s1, run=other))  # both of another run: they agree, the merging run does not
        self.assert_refused(self.merge(2), "shard 1/2 names run")
        self.put(1, 2, s1)
        self.put(2, 2, s2)
        ident = mutants.run_identity
        mutants.run_identity = lambda: {"github_run_id": "1", "github_run_attempt": "2", "github_sha": "f00"}
        self.assert_refused(self.merge(2), "shard 1/2 names run")
        mutants.run_identity = lambda: {"git_head": ""}
        self.assert_refused(self.merge(2), "no run identity")
        mutants.run_identity = ident
        self.put(2, 2, dict(s2, target="other"))
        self.assert_refused(self.merge(2), "shard 2/2 names target 'other'")

    def test_a_union_that_is_not_the_stage_is_refused_though_every_shard_passes(self):
        """Every shard alone passes, and the union fails: under a rule that leaves a mutant in no
        shard, each shard's selection agrees with the rule, so only the union's check sees it.
        (With counts summed, the union's ratio lies between the shards' ratios, so a union of
        shards that each pass on their own can fail by these checks alone.)"""
        ids = self.define(6)
        rule = mutants.in_shard
        mutants.in_shard = lambda mid, k, n: mid != ids[-1] and rule(mid, k, n)
        for k, (rc, out) in enumerate(self.run_shards(2), 1):
            self.assertEqual(rc, 0, out)
            self.assertIn(f"\nshard {k}/2: OK: ", out)
        self.assert_refused(self.merge(2), f"the shards' union is not the stage's mutants (missing ['{ids[-1]}']")

    def test_the_ratio_is_over_the_unions_counts_never_the_mean_of_the_shards_ratios(self):
        ids = self.define(42, survived={"M901", "M903"}, invalid={f"M{n}" for n in range(902, 942, 2)} | {"M941"})
        (rc1, out1), (rc2, out2) = self.run_shards(2)
        self.assertEqual((rc1, self.shard(1, 2)["ratio"]), (0, 1.0), out1)
        self.assertEqual((rc2, self.shard(2, 2)["ratio"]), (1, 0.9), out2)
        rc, out, rep = self.merge(2)
        self.assertEqual((rc, rep["valid"], rep["killed"], rep["ratio"]), (1, 21, 19, 0.9048), out)
        self.assertIn("\nFAIL: 19/21 valid mutants killed (90.5%", out)

    def test_a_shard_failing_alone_does_not_fail_a_union_that_passes(self):
        self.define(40, survived={"M902"}, invalid={"M904"})
        (rc1, out1), (rc2, out2) = self.run_shards(2)
        self.assertEqual((rc1, rc2), (1, 0), out1 + out2)
        rc, out, rep = self.merge(2)
        self.assertEqual((rc, rep["valid"], rep["killed"], rep["survived"]), (0, 39, 38, ["M902"]), out)
        self.assertIn("\nOK: 38/39 valid mutants killed", out)

    def test_a_security_survivor_of_one_shard_fails_the_union(self):
        mutants.SECURITY.add("M900")
        self.define(40, survived={"M900"})
        (rc1, _), (rc2, _) = self.run_shards(2)
        self.assertEqual((rc1, rc2), (1, 0))
        rc, out, rep = self.merge(2)
        self.assertEqual((rc, rep["ratio"], rep["surviving_security"]), (1, 0.975, ["M900"]), out)

    def test_the_union_carries_every_shards_findings(self):
        mutants.SECURITY.add("M904")
        self.define(40, survived={"M902", "M903"})
        self.run_shards(2)
        s1, s2 = self.shard(1, 2), self.shard(2, 2)
        s1["mutants"][2]["status"] = "invalid"  # M904
        s2["mutants"][0]["expected_missed"] = ["KILL: 'x' not in its reason or kept lines"]  # M901
        s2["expect_errors"] = ["EXPECT names M1, which is not a registered mutant"]
        self.put(1, 2, s1)
        self.put(2, 2, s2)
        rc, out, rep = self.merge(2)
        self.assertEqual(rc, 1, out)
        self.assertEqual(rep["invalid_security"], ["M904"])
        self.assertEqual(rep["expected_missed"], ["M901"])
        self.assertEqual(rep["expect_errors"], ["EXPECT names M1, which is not a registered mutant"])
        self.assertEqual(rep["declared_killers_missed"], ["M902", "M903"])
        self.assertIn("  expected_missed KILL: 'x' not in its reason or kept lines", out)


class ShardMutants(unittest.TestCase):
    """WP-98's mutants: the merge's checks and the shard rule on tests/mutants.py (M288 to M295,
    M298) killed by TST-M0-005, the refusal of two new runs of one test id on tools/project.py
    (M296 adopt-native, M297 import-ci-evidence) killed by TST-M0-007; M290, M291, M292, M296 and
    M297 are SECURITY mutants of the M6 stage, and each new text keeps its anchor."""

    def test_the_merge_and_clash_mutants_are_registered(self):
        by_id = {m[0]: m for m in mutants.MUTANTS}
        ids = [f"M{n}" for n in range(288, 299)]
        for mid in ids:
            self.assertIn(mid, by_id)
            self.assertEqual(mutants.stage_of(mid), "M6")
            want = ("tools/project.py", ["TST-M0-007"]) if mid in ("M296", "M297") else ("tests/mutants.py", ["TST-M0-005"])
            self.assertEqual((by_id[mid][1], by_id[mid][4]), want, mid)
            self.assertIn(by_id[mid][2], by_id[mid][3], f"{mid}: the new text drops its anchor")
        # L-021 (WP-152): M289 (a survivor hidden behind a later entry) and M293 (a union that
        # skips a SECURITY mutant) fail the gate whatever the ratio.
        self.assertEqual(set(ids) & mutants.SECURITY, {"M289", "M290", "M291", "M292", "M293", "M296", "M297"})


class WorkflowShardMutants(unittest.TestCase):
    """WP-152's mutants of the gate's wiring in .github/workflows/verify.yml, tooling mutants of
    the M6 stage killed by TST-M0-003 alone: job g without one shard in its needs (M300), a shard
    count other than the number of shard jobs (M301), g run on a cancelled run, always() for
    !cancelled() (M302, SECURITY), a shard job running the gate suite as a case (M303); each
    anchor occurs once in the clean file, and M189's anchor names the merge job's needs so g's
    own condition does not make it ambiguous."""

    IDS = ("M300", "M301", "M302", "M303")

    def test_the_wiring_mutants_are_registered(self):
        by_id = {m[0]: m for m in mutants.MUTANTS}
        text = (ROOT / ".github" / "workflows" / "verify.yml").read_text(encoding="utf-8")
        for mid in self.IDS + ("M189",):
            self.assertIn(mid, by_id)
            m = by_id[mid]
            self.assertEqual(mutants.stage_of(mid), "M6")
            self.assertEqual((m[1], m[4]), (".github/workflows/verify.yml", ["TST-M0-003"]), mid)
            self.assertTrue(mutants.is_tooling(m[1]), mid)
            self.assertEqual(text.count(m[2]), 1, f"{mid}: its anchor is not once in verify.yml")
            self.assertNotEqual(m[2], m[3], mid)
        self.assertEqual(set(self.IDS) & mutants.SECURITY, {"M302"})
        self.assertIn("M189", mutants.SECURITY)

    def test_the_critical_path_mutants_are_registered(self):
        # WP-153: job b builds into the evidence (M309), job a uploads every -a directory again
        # (M310), job g's step `rev` keeps 7 characters (M311), the merge adopts without slot b
        # (M312), job b waits for job a (M313), the M5 guest suite runs in job a too (M314), job b's
        # upload back to its one evidence line, rooted at evidence/ (M315, the WP-153 review); each
        # anchor once in verify.yml, TST-M0-003 kills them.
        by_id = {m[0]: m for m in mutants.MUTANTS}
        text = (ROOT / ".github" / "workflows" / "verify.yml").read_text(encoding="utf-8")
        for mid in ("M309", "M310", "M311", "M312", "M313", "M314", "M315"):
            self.assertIn(mid, by_id, f"{mid} is not registered")
            m = by_id[mid]
            self.assertEqual((m[1], m[4], mutants.stage_of(mid)), (".github/workflows/verify.yml", ["TST-M0-003"], "M6"), mid)
            self.assertTrue(mutants.is_tooling(m[1]), mid)
            self.assertEqual(text.count(m[2]), 1, f"{mid}: its anchor is not once in verify.yml")
            self.assertNotEqual(m[2], m[3], mid)
            self.assertNotIn(mid, mutants.SECURITY)

    def test_the_fallback_mirror_mutants_are_registered(self):
        # WP-152's follow-up (verify run 44218469147): the Toolchain step's fallback mirror and the
        # runner mirror's budget, mutated in mutants.yml, where each anchor is once (verify.yml
        # repeats the step in nine jobs): the Azure-only rewrite back (M305), a rewrite that edits
        # apt-mirrors.txt alone (M306), 300 s tries of the runner's mirror again (M307) and a
        # fallback fetch whose try dies before a slow download ends (M308); TST-M0-003 kills them.
        by_id = {m[0]: m for m in mutants.MUTANTS}
        text = (ROOT / ".github" / "workflows" / "mutants.yml").read_text(encoding="utf-8")
        for mid in ("M305", "M306", "M307", "M308"):
            self.assertIn(mid, by_id, f"{mid} is not registered")
            m = by_id[mid]
            self.assertEqual((m[1], m[4], mutants.stage_of(mid)), (".github/workflows/mutants.yml", ["TST-M0-003"], "M6"), mid)
            self.assertTrue(mutants.is_tooling(m[1]), mid)
            self.assertEqual(text.count(m[2]), 1, f"{mid}: its anchor is not once in mutants.yml")
            self.assertNotEqual(m[2], m[3], mid)
            self.assertNotIn(mid, mutants.SECURITY)
        self.assertIn("azure", by_id["M305"][3])

    def test_the_run_json_record_of_the_shard_count_is_mutated(self):
        # L-023 (WP-152): M304 drops the note write_run adds under NAWAH_GATE_SHARDS, so job g's
        # run.json of TST-M6-MUTANTS would read as a whole run of the gate; TST-M0-007 kills it.
        m = {x[0]: x for x in mutants.MUTANTS}.get("M304")
        self.assertIsNotNone(m, "M304 is not registered")
        self.assertEqual((m[1], m[4], mutants.stage_of("M304")), ("tools/project.py", ["TST-M0-007"], "M6"))
        self.assertTrue(mutants.is_tooling(m[1]))
        self.assertEqual((ROOT / "tools" / "project.py").read_text(encoding="utf-8").count(m[2]), 1)
        self.assertIn(m[2], m[3])
        self.assertNotIn("M304", mutants.SECURITY)



class SecuritySet(unittest.TestCase):
    """WP-95 (the audit the owner ordered, 2026-11-16): a mutant is SECURITY by the set alone
    (gate_verdict reads mutants.SECURITY), yet 36 ids of the set had notes without the prefix and
    nine authority mutants carried neither. The prefix of a note and membership of the set are
    equal both ways, and the nine are in it."""

    NINE = ("M34", "M53", "M62", "M67", "M68", "M69", "M70", "M73", "M77")

    def test_the_security_prefix_and_the_set_are_equal(self):
        by_id = {m[0]: m for m in mutants.MUTANTS}
        prefixed = {mid for mid, m in by_id.items() if m[5].startswith("SECURITY")}
        key = lambda mid: int(mid[1:])
        self.assertEqual(sorted(mutants.SECURITY - prefixed, key=key), [], "in the set, the note does not say SECURITY")
        self.assertEqual(sorted(prefixed - mutants.SECURITY, key=key), [], "the note says SECURITY, the set does not hold it")
        self.assertEqual(sorted(mutants.SECURITY - set(by_id), key=key), [], "the set names an unregistered mutant")

    def test_the_nine_authority_mutants_are_security(self):
        self.assertEqual([m for m in self.NINE if m not in mutants.SECURITY], [])


class MutantsWorkflowMutants(unittest.TestCase):
    """WP-95's wiring of mutants.yml, killed by TST-M0-003: the M3 gate runs again after a failed
    baseline (always(), M316), a dispatch naming no gate passes the stages check (M317), the host
    suites step drops a suite verify runs (M318) and the job's limit falls back to 300, under what
    a run of all five gates needs (M319), the stages step lets a tab or a newline through (M320),
    the artifact takes the whole evidence tree again (M321) and the host suites run after a failed
    baseline (M322) (the WP-95 review); each anchor once in mutants.yml."""

    def test_the_wiring_mutants_are_registered(self):
        by_id = {m[0]: m for m in mutants.MUTANTS}
        text = (ROOT / ".github" / "workflows" / "mutants.yml").read_text(encoding="utf-8")
        for mid in ("M316", "M317", "M318", "M319", "M320", "M321", "M322"):
            self.assertIn(mid, by_id, f"{mid} is not registered")
            m = by_id[mid]
            self.assertEqual((m[1], m[4], mutants.stage_of(mid)), (".github/workflows/mutants.yml", ["TST-M0-003"], "M6"), mid)
            self.assertTrue(mutants.is_tooling(m[1]), mid)
            self.assertEqual(text.count(m[2]), 1, f"{mid}: its anchor is not once in mutants.yml")
            self.assertNotEqual(m[2], m[3], mid)
            self.assertNotIn(mid, mutants.SECURITY)


class GateOracles(unittest.TestCase):
    """WP-95: every gate's oracle text (TST-M2-MUTANTS to TST-M6-MUTANTS) says what its verdict
    enforces (gate_verdict and run_killers' cause rules): the ratio, the SECURITY rule for a
    surviving and for an invalid mutant, a kill only by its cause (a guest killer's own FAIL
    verdict line, a host killer's failing-tests line with the case passing on the clean
    checkout, anything else ERROR), expected_missed and an EXPECT error. The four older texts
    predated WP-90 and said none of the new rules."""

    MUST = ("a kill ratio of at least 0.95 over a non-empty set of valid mutants", "every survivor named in the report",
            "no surviving or invalid SECURITY mutant", "declared killers", "sweep", "own FAIL verdict line", "`FAILED (`",
            "`test result: FAILED`", "clean checkout", "ERROR", "never a kill", "expected_missed", "EXPECT error")
    # The WP-95 review (auditor A-L01, assurance F2): the gate never checks that every seeded defect
    # is killed (the ratio is 0.95), a kill comes from a declared killer or the sweep, and an
    # invalid mutant is not written to the report when it is decided (tests/mutants.py: two
    # INVALID paths `continue` without _write_report).
    FORBID = ("every seeded", "is killed by at least one", "written as each mutant is decided", "decided so far")

    def test_every_gate_oracle_names_what_the_gate_enforces(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import project  # noqa: E402
        gates = [c for cs in project.HOST_SUITES.values() for c in cs
                 if c["command"][:3] == ["python3", "-I", "tests/mutants.py"] and "--stage" in c["command"]]
        self.assertEqual(sorted(c["id"] for c in gates), [f"TST-M{n}-MUTANTS" for n in range(2, 7)])
        missing = {c["id"]: [w for w in self.MUST if w not in c["oracle"]] for c in gates}
        self.assertEqual({k: v for k, v in missing.items() if v}, {})
        claims = {c["id"]: [w for w in self.FORBID if w in c["oracle"]] for c in gates}
        self.assertEqual({k: v for k, v in claims.items() if v}, {}, "a gate's oracle claims what the gate does not check")


if __name__ == "__main__":
    unittest.main(verbosity=1)
