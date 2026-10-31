# Mutation-run policy (M5 gate and the other gates)

This file is the pre-approved policy of the mutation harness (`tests/mutants.py`). The M5 run of
2026-10-29 hit the 3 h step limit with no per-mutant ceiling; the rules below are the package that
makes a run bounded, observable and resumable.

## Exit codes

| code | meaning |
|------|---------|
| `0` | the gate passes: the selected mutants were all evaluated, the kill ratio is at least 0.95 over the valid mutants, and no `SECURITY` mutant survived |
| `1` | a gate failure: a mutant survived (including a surviving `SECURITY` mutant) or the ratio is below the threshold |
| `2` | budget or infrastructure: a build step, a missing/empty serial log, a crash or QEMU/lab signal, a harness failure, an unreadable/duplicated merge report, or the worktree/driver failed. Never a gate verdict |

A `--check` run (apply + type-check only) keeps its historical codes: `0` when every patch applies
and type-checks, `1` otherwise.

## `timeout-killed` in the SECURITY policy

`timeout-killed` is a verdict of its own, written as `status: "timeout-killed"` and counted with
the kills (`killed`), never with the survivors:

- It is assigned when **any test of the mutant** (a declared killer or one in the fairness sweep)
  exceeds the per-mutant watchdog *and* the interrupted test left a serial log whose last recorded
  line is kernel activity. The overrun is then attributed to the mutated kernel exactly like a
  failing assertion: the mutant is killed. A sweep overrun records a `sweep_timeouts` event with
  the test id, the seconds spent on that test and the serial-log path.
- It is **not** assigned when the serial log is missing or empty, when the log shows a crash, when
  the child reports a QEMU/lab signal, or when a build step/the harness fails. Those are
  `infra-error`, are excluded from the ratio and force exit code `2`: no verdict without evidence.
- A `SECURITY` mutant that is `timeout-killed` is therefore **killed**, not a surviving security
  defect: `surviving_security` only lists `survived` mutants. A run with an `infra-error` on a
  `SECURITY` mutant has no verdict at all (exit `2`), because an infrastructure failure can hide
  either outcome.
- The report keeps the attribution (`killed_by`, `results[tid] = "TIMEOUT"`, `timed_out: true`,
  `timeout_event`, and `sweep_timeouts` for a fairness overrun) so the verdict can be audited.

## Watchdog

Every mutant gets one deadline, `--watchdog-seconds` (default and preparatory safety net: `600`
s). The final ceiling of a later revision is derived from a preparatory run's measurements as
`max(300 s, 2 x p95)`; it is a measurement, not a round number chosen to fit a gate.

- The deadline covers the mutant's whole work: reset/apply, the artifacts its killers need, the
  declared killers and (when they all pass) the fairness sweep.
- It is passed to every subprocess as `min(step's hard limit, remaining budget)`.
- Any overrun in a test is classified from the interrupted test's serial log, declared killer or
  fairness sweep alike: kernel activity as the last recorded line is a `timeout-killed` (the
  fairness case also logs a `sweep_timeouts` event); a missing/empty log, a crash line or a
  QEMU/lab signal is `infra-error` (exit `2`), never a false kill. A build overrun is
  infrastructure as well.

## Serial-log safety net

Before any overrun becomes `timeout-killed`, the harness reads the serial log the interrupted test
just wrote (the newest `evidence-run/serial*.log` under the mutation scratch since the test
started):

- no log written since the test started, or an unreadable/empty log: `infra-error` (no evidence);
- a crash marker in the log (`PANIC`, `panic:`, `EXCEPTION`, `unhandled`, `fatal`) or a QEMU/lab
  error in the child output (`qemu died with signal`, `LAB_ERROR`): `infra-error`;
- otherwise the last non-empty serial line is the kernel activity of the mutated system: the
  verdict is `timeout-killed`, and the event `{test, seconds, phase, serial_log, last_line}` is
  written to the mutant's entry (and therefore to the progress JSONL); a fairness overrun also
  lands in the report's `sweep_timeouts` list.

## Reports and progress

- One report per gate: `build/mutants-m2-report.json`, `mutants-m3-report.json`,
  `mutants-m4-report.json`, `mutants-m5-report.json`. The bare `mutants-report.json` remains only
  for a run that selects no gate.
- `build/mutants-m5-progress.jsonl` (derived from the report name): one JSON line appended after
  every mutant, flushed and `fsync`ed. The partial gate report is rewritten at the same point and
  in every exit path, including `SIGINT`/`SIGTERM` and an internal error; it is always valid JSON
  with `partial: true` until the run completes.
- A later run reads the progress lines (or the partial report when the progress file is absent)
  and skips mutants with a terminal verdict (`killed`, `survived`, `timeout-killed`, `invalid`).
  `infra-error` is not terminal and is retried. Every printed completion line carries the id,
  the seconds and the verdict, with `flush=True`.

## Shards

The M5 gate is split in `.github/workflows/mutants.yml` into four shards
(`M82-M91`, `M92-M101`, `M102-M111`, `M112-M121`), ten mutants each. Each shard writes its own
report and the merge job combines them with `tests/mutants.py --merge` into
`build/mutants-m5-report.json` and the gate's final ratio/security verdict.

A shard's step limit is documented next to the matrix: ten mutants at the 600 s safety net is
`6000 s`, at most 80% of the `130`-minute (`7800 s`) step limit (`6000 <= 0.8 x 7800 = 6240`).
The per-mutant ceiling, not the step limit, is what ends a hung mutant.

## Test-side ceiling

`TST-M5-LOCK-AUTH-HANG` must not park a hung mutant in a 600 000-tick wait: its waits are
`2 x REQUEST_DEADLINE` (`10 000` ticks) with `REQUEST_DEADLINE` fixed to the session's unmutated
value (`5 000`, `user/apps/sessiond/src/main.rs`). The unmutated package passes this stricter
ceiling; a hung mutant fails in two real deadlines instead of a round 600 000-tick wait.
