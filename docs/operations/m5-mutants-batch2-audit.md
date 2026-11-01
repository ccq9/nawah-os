# M5 mutation gate, batch 2 (M92–M121): audit

Run audited: mutants **41232332567** on commit `178f9193` (PR #19). Evidence branch:
`ci-evidence/mutants-41232332567`. The run **timed out** at the gate's 3-hour limit
(TST-M5-MUTANTS, `timeout_s=10800`): verdict ERROR, `exit=124; tail=TIMEOUT`. M2 (29/29),
M3 (20/20) and M4 (32/32) passed in the same run.

## What the harness was doing wrong

The gate did not fail on a mutant; it ran out of time, and on the way it was about to count two
infrastructure failures as kills. In the fairness sweep (every case run after a mutant escapes
its declared killers) only two cases ever failed, and for reasons that are not the mutant:

- **TST-M5-DISPLAY-BOOT** decodes the frame's build-id bar one hex digit per cell. The harness
  stamped each mutant `mutm94`; its non-hex letters decoded to `000094`, `bar_ok=0`, so the
  case failed on every mutant.
- **TST-M5-ELEVATE** needs ~124 s on the clean tree (verify 41232334352), but the harness forced
  a 90 s QEMU timeout on every case, so ELEVATE timed out (exit 124) on every mutant.

Had the run finished, those two would have been reported as kills of every surviving mutant —
a false 95 %+. The sweep is also what made the run take three hours: ~23 min per surviving
mutant × six.

Fixed in `tests/mutants.py` (commit on this branch), guarded by **TST-M0-005**
(`tests/test_mutants_harness.py`, M0 host suite): hex build ids, a 180 s per-case timeout that
clears the slowest clean case, early-exit of the sweep at the first real kill, and a partial
report written as each mutant is decided. Once every mutant is genuinely killed, no sweep runs
and the gate is fast again.

## True result per mutant (from the published evidence, not the timed-out report)

M82–M92, M95, M96, M98–M102, M105, M107–M121: killed by their declared killers before the
sweep (no scratch kept). Five escaped every declared killer; the sweep then ran the full suite
and nothing real killed them:

| id | security | declared killer(s) → verdict | diagnosis |
|---|---|---|---|
| M93 | yes | TST-M5-LOCK-SURVIVES → PASS | **equivalent**: `cyclable()`'s lock guard is only reached from the Alt+Tab handler, which runs only when displayd holds the keyboard — i.e. while unlocked, where the guard is always true. No test can distinguish it. → replace. |
| M94 | no | TST-M5-LIST-HASH-HELD → PASS | **equivalent**: `(0..k)` → `(0..=k)` adds the window itself, for which `ow.owner == w.owner` holds. → replaced with `(1..k)` (skips the topmost window; a covered client area reads as its own). |
| M97 | yes | TST-M5-LOGIN-SCREEN → PASS | **real test gap**: on LOGOUT without `locked=true` first, `destroy_window` of a focused client calls `top_visible()` → `set_focus` to another client's still-visible window and announces it to the narrator before destroying it. LOGIN-SCREEN checks only the final window count and that the spy stopped, never the transient focus/announce. |
| M106 | yes | TST-M5-SESSION-LOSS → PASS | **real test gap**: `inputd.forget()` drops the `b"session"` block that clears the keyboard focus when the session dies. The first guard only clears when the *session* held focus; it misses the case where a *non-session* client (a window focused before the crash) held it, leaving it able to receive a password typed for the restarted session. SESSION-LOSS checks the compositor's focus, not inputd's keyboard focus, and types no key during the loss. |
| M103 | no | FOCUS-AFTER-RESTART, LOCK-DISPLAY-DOWN → PASS | **gap (non-security)**: `RELEASE_WAIT=0` removes the wait for every key to be released before the keyboard is handed to the display after unlock; no test holds a key across the unlock. Pre-registered 2026-10-28 as a possible survivor. |

M104 (non-security) was killed in the sweep by **TST-M5-SESSION-DEADLINE** and
**TST-M5-SESSION-HANG**, not by its declared LOCK/UNLOCK-AUTH-HANG cases (those stopped
measuring the request deadline when auth went async, session.md v1.2). Its declared killers are
corrected to the two that bite.

## Security reading

M93 is equivalent (a dead guard); the lock-holds-windows property is enforced by `visible()`,
which M86 and M92 already cover. **M97 and M106 are genuine security test-coverage gaps** —
exactly what mutation testing exists to find. The right response is to strengthen the two tests
so they kill the mutants, not to reshape the mutants around weak tests.

## Status and the honest limit

Landed on the PR-#19 branch and validated where it can be: the harness fix, M94 (equivalent →
real boundary shift), M104 (declared killers corrected), and TST-M0-005 (6 host cases, run on
CI by verify). These are host-testable or code-reasoned and CI is their judge.

What cannot be finished from here: M97 and M106 survive their declared killers (evidence), but
whether each is a genuinely exploitable hole or is already defended elsewhere — and what exact
observable (a narrator announcement for M97, an inputd `STATUS focus=` read in the no-session
transient for M106) reliably kills it — cannot be decided without running mutated kernels in
QEMU, which this container has no bare-metal target for. Writing the two guest security tests
blind would be guessing, which is the one thing not to do in a security suite.

M93 is a proven equivalent (a dead guard); it is dropped from the active set rather than padded
with a redundant mutant. M103 (non-security) survives and is pre-registered.

So the gate does not close this turn. The correct next step is the project's own TDD-CI loop,
one candidate test at a time: draft → verify proves it passes on the clean tree (~25 min) →
a targeted M5 run proves it kills the mutant. M97, M106 and M103 are recorded as findings for
that work. No merge of PR #19 before the gate closes, the owner reviews CI, and the random
challenge is run.
