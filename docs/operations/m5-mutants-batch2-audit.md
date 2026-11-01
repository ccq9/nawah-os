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
| M93 | yes | TST-M5-LOCK-SURVIVES → PASS | **equivalent**: `cyclable()`'s lock guard is reached only from the Alt+Tab handler, which runs only while displayd holds the keyboard — i.e. while unlocked, where the guard is always true. → **dropped**. |
| M94 | no | TST-M5-LIST-HASH-HELD → PASS | **equivalent**: `(0..k)` → `(0..=k)` adds the window itself, for which `ow.owner == w.owner` holds. → **replaced** with `(1..k)` (skips the topmost window; a covered client area reads as its own). |
| M97 | yes | TST-M5-LOGIN-SCREEN → PASS | **equivalent** (corrected — a first reading of 2026-11-01 called it a test gap; that was wrong). Every writer of displayd's `locked`: start (`session_in_manifest` → true), session lost (main.rs 1102 → true), `LOCKED`/`UNLOCKED` (session-only verbs), and LOGOUT itself. The session sends LOGOUT only from the lock screen (both `sign_out` callers run in `State::Locked`), after `LOCKED` on the same channel (re-sent first on a reconnect). So `locked` is already true whenever LOGOUT arrives; the removed line is defence in depth with no reachable effect. → **dropped**. |
| M106 | yes | TST-M5-SESSION-LOSS → PASS | **real test gap**: `inputd.forget()` loses the block that clears the keyboard focus when the session goes. The first guard clears only when the *session* held the focus; while unlocked the *compositor* holds it (`focus=display`), so with the mutant the input service keeps routing to it after the session is gone — a reachable, observable break of input.md v2.2 ("nobody gets keys until it is back"). Phases 1–4 only observe the compositor's focus (the spy's). → **test strengthened**: phase 5 signs in once more, stops the session for good (STOP, no restart; sessiond exits on STOP without touching the keyboard) and requires the input service's own `STATUS` to read `focus=-` once the manager lists the session stopped (`…input_focus_cleared=1|phase=6`). Clean tree: must pass (verify); M106: `focus=<display id>` → fail. |
| M103 | no | FOCUS-AFTER-RESTART, LOCK-DISPLAY-DOWN → PASS | **gap (non-security)**: `RELEASE_WAIT=0` hands the keyboard to the compositor without waiting for keys still held on the session's screen. It is observable only when a key is held across the auth round-trip and released before 1000 ticks (a timing-sensitive test). Pre-registered 2026-10-28 as a possible survivor; left as the one accepted survivor. |

M104 (non-security) was killed in the sweep by **TST-M5-SESSION-DEADLINE** and
**TST-M5-SESSION-HANG**, not by its declared LOCK/UNLOCK-AUTH-HANG cases (those stopped
measuring the request deadline when auth went async, session.md v1.2). Its declared killers are
corrected to the two that bite.

## Security reading

Of the three security survivors, two were equivalent mutants (M93, M97): the property each
seemed to guard is enforced elsewhere (`visible()`; the lock that always precedes LOGOUT), so no
test can or should kill them. One was a real coverage gap (M106) and the test that owns the
property (SESSION-LOSS) now checks it directly at the input service.

## Status

On the PR-#19 branch: the harness fix and TST-M0-005 (PASS on CI, verify 41277195786), M94
replaced, M104's killers corrected, M93 and M97 dropped as equivalents (batch 2: 28 mutants, 11
security; M5 gate: 38), and SESSION-LOSS's phase 5. Expected M5 result: 37/38 killed (97.4 %),
M103 the only survivor, no surviving security mutant. Next: verify must show SESSION-LOSS still
PASS on the clean tree; then import that evidence (strict records on the committed state are a
precondition of the mutants workflow); then one mutants run. No merge of PR #19 before the gate
closes, the owner reviews CI, and the random challenge is run.
