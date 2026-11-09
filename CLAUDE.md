# nawah-os: the standing method for every session and every sub-agent

Read `docs/policies/team-methodology.md` before any work. It fixes the twelve-role team the owner set (1 manager, 3 planners, 2 code engineers, 2 security engineers, 2 UI designers, 2 auditors), the mandatory cycle for every work package (open only when dependencies are done → plan backwards → engineer test-first in parallel with security and UI → audit every claim → close through CI and the records), and the rules no role may lift. The agent definitions live under `.claude/agents/`, the reference workflow is `.claude/workflows/nawah-team.js` (name `nawah-team`), and its product is `docs/PLAN-REVERSE.md`.

Non-negotiable in every turn:

- CI is the judge. A local run is scratch, never evidence; never claim a pass without the command output. Evidence enters the records only through `python3 tools/project.py import-ci-evidence --run <id>`, then `validate-records --strict` must report 0 errors, then `checkpoint`.
- Test first. No code change without a test that fails before the fix and passes after; show the failing output. Never skip, disable or quarantine a test to go green.
- Clean room (ADR-0022). Never port or paraphrase Microsoft code, UI text, icons, images, fonts or pixel layouts; behaviour and organisation only, from `docs/reference/` and published specifications.
- Records. A commit subject names an active or done work item or none (DEC-004: `python3 tools/project.py check-commit`). Done needs CI evidence. A done item may not promise a contract version that does not exist.
- Honesty to the owner, in Arabic: outcome first, then the evidence (CI run ids, evidence paths), then what was refuted or unverifiable, then what is blocked with the exact unblocking action, then the next step. No praise, no padding. Merging to `main` is the owner's fast-forward of the CI-verified commit, never ours.

Local checks before every push, in order: `python3 tools/project.py validate-records`, `cargo fmt --all --check`, `python3 tools/project.py hygiene`, `python3 tools/project.py preflight --suite <M?> [--only <ids>]`.
