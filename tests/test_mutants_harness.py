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

# The slowest M5 case measured on the clean tree (CI verify 42600548943, 2026-11-09: ELEVATE 137 s).
SLOWEST_CLEAN_CASE_S = 137


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
            def __init__(self, rc):
                self.returncode = rc
                self.stdout = ""

        orig_suite, orig_sh = mutants.suite_of, mutants.sh
        mutants.suite_of = lambda target, tid: "M5-GATE"
        mutants.sh = lambda cmd, cwd, env=None: (calls.append(cmd[-1]), R(verdicts[cmd[-1]]))[1]
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


if __name__ == "__main__":
    unittest.main(verbosity=1)
