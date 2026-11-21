# WP-92 reconciliation of record oracles against their source (2026-11-14)

Census: `sync-oracles --check` on the worktree at 459e27592 (sources: HOST_SUITES, every
platform/*/target.json suite case, boot_oracle when no suite case has the id, BUILD_ORACLE for
every target's build test): 162 test ids have a source; 36 records differed before WP-92 changed
TST-M0-001's own text (37 after). The brief's "32 of 157" counted pc-qemu + host only (157 ids
with an oracle text) and TST-M1-BUILD (no text in target.json) among the 32: 31 real + 1.
Added by the wider source: TST-M0-E0-BOOT, TST-M3-A64-BOOT (boot_oracle of the other targets),
TST-M0-E0-BUILD, TST-M3-A64-BUILD, TST-M1-BUILD (cmd_build's literal, tools/project.py:1098 before).
Split: host 10, guest pc-qemu 21, other-target boot 2, build 3.

Deciding fact, checked for every row: the oracle stored in the verdict.json of the record's cited
evidence (main tree /home/user/nawah-os at c7c7ac962, read only) EQUALS THE SOURCE TEXT for all
162 PASS records, the 36 differing ones included. The source is the text the run checked and
recorded; the record is the hand copy that drifted. Hence source wins in all 36; the record's
extra content is either a dated note (moved to oracle_notes by wp92_move_notes.py) or dropped
(listed below so nothing is lost silently). No HOST_SUITES text was found wrong, so there is
no c3: editing a source now would also make its evidence differ (strict error until re-run).

| test id | what differs (short) | wins | why | note kept (oracle_notes) |
|---|---|---|---|---|
| TST-M0-005 | record lacks ", OK" in "(11 cases, OK)" | source | evidence = source; WP-90 rewrites the text anyway, sync carries it | - |
| TST-M1-NOBS | record is an abbreviation | source | evidence = source; same claims, longer | - |
| TST-M2-MUTANTS | record: "29 seeded defects ... detached worktree"; source: kill ratio >= 0.95, report path | source | evidence = source; the "29" count is checked by nothing | - (dropped: "29 seeded defects", unverified count) |
| TST-M3-MUTANTS | record "M30 onwards" wording | source | evidence = source | - |
| TST-M4-MUTANTS | record "M50-M81", report path; source lists module classes | source | evidence = source | - (dropped: "M50-M81" range, unverified) |
| TST-M5-MUTANTS | record: "45 valid mutants", "23 SECURITY"; source: per-module defect list | source | evidence = source; the counts are checked by nothing | - (dropped: 45 / 23 counts, unverified) |
| TST-M4-HASH-VECTORS | "(4 tests, 0 failed)" vs "(cargo test)" + guest trace line | source | evidence = source | - (dropped: guest trace text, belongs to TST-M4-LOGIN) |
| TST-M4-SHELL-TOOL | record more verbose (shell.md protocol, "before the first command") | source | evidence = source; same 3 cases | - |
| TST-M5-UI-UNIT | v1.2 sentence reworded | source | evidence = source; same claims | - |
| TST-M6-MANIFEST-LINT | record lacks ", OK" | source | evidence = source | - |
| TST-M1-BOOT | record: "4 initial handles (v1.1)", no WP-30/WP-32; source: 6 handles, COM2, GOP | source CORRECTED (41550d2a0 on wp92-train), then source | AUDIT: both sides wrong: the required marker is handles=9 (target.json :801, services.md:15, services.rs:54-96); the source also lacked m1_done, exit 33 and the single boot_mode line (max/min_counts 1). Source rewritten clause per marker group | yes: the "declared path change, not a weakened oracle (boot.md v1.1)" statement, dated 2026-11-14 as carried |
| TST-M1-NEG | record shorter paraphrase | source | evidence = source | - |
| TST-M2-IDT-LAYOUT | record: "all 256 gates", "IST only on #DF" | source CORRECTED (c3), then source | re-check: the record's dropped sentence was a tested fact: idt_layout_mismatches (kernel/src/arch/x86_64/ktest.rs:355-400) checks the 256-gate limit, the selector, the reserved bytes and IST only on vector 8 | - |
| TST-M2-PMM-COUNTS | paraphrase | source | evidence = source | - |
| TST-M2-PMM-EXHAUST | paraphrase | source | evidence = source | - |
| TST-M2-PMM-DOUBLE-FREE | paraphrase | source | evidence = source | - |
| TST-M2-VMM-WP | paraphrase; source adds "exit 173" | source | evidence = source | - |
| TST-M3-USER-BAD-PTR | paraphrase | source | evidence = source | - |
| TST-M4-TCP-ECHO | record much shorter | source | evidence = source; source is richer | - |
| TST-M4-TCP-RETRANSMIT | record much shorter | source | evidence = source; source richer (RFC 6298, Karn) | - |
| TST-M5-DISPLAY-BOOT | record shorter | source | evidence = source | - |
| TST-M5-INPUT-ROUTE | record shorter | source | evidence = source | - |
| TST-M5-MOUSE | record shorter | source | evidence = source | - |
| TST-M5-ALT-TAB-CYCLE | record prefix "REQ-M5-008 display.md v1.6 (M5 pre-gate review, M7): " | source | evidence = source; source ends "(display.md v1.6; S77; M5 pre-gate review, M7)"; REQ id is in requirement_ids | - |
| TST-M5-AUTH-INPUT-ISOLATED | record adds "no announcement per keystroke in a password field (ui.md v1.4)" | source | evidence = source; covered by the transcript equality with expect/auth-input-isolated.txt and the pass line "no announcement" | - (dropped; covered) |
| TST-M5-LOCK-DISPLAY-DOWN | record prefix "REQ-M5-010, REQ-M5-006, display.md v1.5 (M5 pre-gate review, M5): " | source | evidence = source; source names display.md v1.5 and the review | - |
| TST-M5-SESSION-LOSS | record = source + dated note (2026-11-10, WP-64) | source + note | evidence = source | yes, verbatim |
| TST-M5-WINDOW-A11Y | record = source + ". Not exercised: moving a window by keyboard and a scale change" | source + note | evidence = source; the limitation is not in the source | yes, dated 2026-11-14 as carried (its truth not re-checked) |
| TST-M6-INTERACTIVE-BOOT | record = source + dated note (2026-11-10, WP-64) | source + note | evidence = source; `reason=list_failure` is in the case's top-level forbidden_markers (target.json) | yes, verbatim |
| TST-M6-HOLD-FAIL-CLOSED | record = source + note "Timeout 180 s -> 60 s on 2026-11-10" | source + note | evidence = source; case timeout_s is 60 | yes, reworded to start with its date |
| TST-M6-TOKEN-REVOKE | record = source + dated note (2026-11-10, WP-73) | source + note | evidence = source | yes, verbatim |
| TST-M0-E0-BOOT | record "QEMU exit 33 ... (OVMF 2024.02, QEMU 8.2.2)" vs boot_oracle text | source | evidence = source | - (dropped: firmware/QEMU versions, an environment fact) |
| TST-M3-A64-BOOT | record lists cpu_tables / a64 el line; source shorter | source CORRECTED (c3), then source | AUDIT: the record was right: cpu_tables|vbar=firmware|mmu=firmware, kernel|a64|el= and |paging=firmware|exit=0x10 are required markers (virt-qemu-aarch64/target.json:63 on) | - |
| TST-M1-BUILD | record "build_id recorded" | source | evidence = BUILD_ORACLE literal; the build verdict checks exit codes and the artifact only | - |
| TST-M0-E0-BUILD | record "clang+lld-link ... PE32+ artifact" | source | as above; "PE32+" is checked by nothing in cmd_build (refuted as a build-verdict claim) | - |
| TST-M3-A64-BUILD | record "cargo build for aarch64-unknown-uefi (release) ... NAWAH-A64.EFI" | source | as above | - |

Totals (after the audit): source as it was 28, source corrected from the tested facts then synced 3 (TST-M1-BOOT, TST-M2-IDT-LAYOUT, TST-M3-A64-BOOT; TST-M1-BOOT also keeps its note), source + dated note 6 (incl. TST-M1-BOOT), record wins as text 0.
My first claim "no source text is wrong, so no c3" was REFUTED by the audit (TST-M1-BOOT, TST-M3-A64-BOOT); evidence = source only proves which text ran, not that the text states what the markers check.
Re-check of the other guest and boot rows (record-only tokens against required/forbidden markers, max_counts and the ktest code): TST-M1-NEG, PMM-COUNTS/EXHAUST/DOUBLE-FREE, VMM-WP, USER-BAD-PTR (len=8 is forbidden and in the source), TCP-ECHO, TCP-RETRANSMIT (the record's "host-side drop" is wrong: TCP_INJECT drop_next=1 in the service), DISPLAY-BOOT ("only user fault" = source's "one user_fault", max_counts 1), INPUT-ROUTE, MOUSE, ALT-TAB, AUTH-INPUT-ISOLATED, LOCK-DISPLAY-DOWN, TST-M0-E0-BOOT (markers start, conout ok=1, done exit=0x10 all in the source): no further dropped tested fact. Host rows were not re-checked against the test files.
Two sources: pc-qemu's boot_oracle (target.json:722) differs from the TST-M1-BOOT suite case; it is not a candidate because cmd_boot never runs it when a suite case carries the id (now explicit in oracle_candidates); any two RUN sources with different texts are a validate-records error and stop sync-oracles (final train: test 57cafa8db, fix baf342137; texts 41550d2a0).

## Manager, in the main tree, after WP-90 and WP-50 have landed and the WP-92 commits are in
1. `python3 /tmp/claude-0/-home-user-nawah-os/689b5e5b-a7fe-59ea-b1b2-3cb89de28fc5/scratchpad/wp92_move_notes.py` (NAWAH_ROOT defaults to /home/user/nawah-os; adds 6 notes, idempotent)
2. `python3 tools/project.py sync-oracles` (expect about 37 rewritten, plus whatever WP-90/WP-50 changed)
3. `python3 tools/project.py sync-oracles --check` -> exit 0
4. `python3 tools/project.py validate-records` -> 0 errors; commit docs/tests.json with the WP-92 train (the code alone makes the committed tree fail the non-strict oracle rule)
5. after CI: import / adopt as usual, `validate-records --strict`, `checkpoint`
Trial in the worktree at wp92-train baf342137 (final train; supersedes wp92-prep): steps 1-3 gave 6 notes added, 37 rewritten (the same 37 ids; the texts of TST-M1-BOOT, TST-M2-IDT-LAYOUT and TST-M3-A64-BOOT are now the corrected ones), check exit 0, tests schema 0 errors; diff saved at /tmp/claude-0/-home-user-nawah-os/689b5e5b-a7fe-59ea-b1b2-3cb89de28fc5/scratchpad/wp92_tests_json_sync.diff (56+/38-, not committed).
