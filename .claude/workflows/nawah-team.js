export const meta = {
  name: 'nawah-team',
  description: 'nawah-os twelve-role team: 3 planners, 2 code, 2 security, 2 UI, 2 auditors, 1 manager produce the audited reverse plan',
  phases: [
    { title: 'Planning', detail: 'end-state ladder, M6 dependency chain, decisions and risks' },
    { title: 'Engineering', detail: 'code (kernel, apps), security (threat, assurance), UI (shell, settings)' },
    { title: 'Audit', detail: 'plan audit and engineering audit against the records and code' },
    { title: 'Manager', detail: 'integrate audited findings into the reverse plan' },
  ],
}

const STR = { type: 'array', items: { type: 'string' } }
const LEVELS = { type: 'object', required: ['levels', 'summary'], properties: {
  levels: { type: 'array', items: { type: 'object',
    required: ['name', 'exit_conditions', 'preconditions', 'delivered_by', 'judged_by', 'open_decisions', 'sources'],
    properties: { name: { type: 'string' }, exit_conditions: STR, preconditions: STR, delivered_by: STR, judged_by: STR, open_decisions: STR, sources: STR } } },
  summary: { type: 'string' } } }
const CHAIN = { type: 'object', required: ['work_items', 'critical_path', 'parallel_tracks', 'first_step', 'sources', 'summary'], properties: {
  work_items: { type: 'array', items: { type: 'object',
    required: ['id', 'title', 'depends_on', 'blocks', 'tests', 'requirements', 'readiness'],
    properties: { id: { type: 'string' }, title: { type: 'string' }, depends_on: STR, blocks: STR, tests: STR, requirements: STR, readiness: { type: 'string' } } } },
  critical_path: STR, parallel_tracks: { type: 'array', items: STR }, first_step: { type: 'string' }, sources: STR, summary: { type: 'string' } } }
const RISKS = { type: 'object', required: ['decisions', 'risks', 'unknowns', 'sources', 'summary'], properties: {
  decisions: { type: 'array', items: { type: 'object', required: ['id', 'gates', 'recommendation', 'owner_action'],
    properties: { id: { type: 'string' }, gates: STR, recommendation: { type: 'string' }, owner_action: { type: 'string' } } } },
  risks: { type: 'array', items: { type: 'object', required: ['id', 'affects', 'mitigation'],
    properties: { id: { type: 'string' }, affects: STR, mitigation: { type: 'string' } } } },
  unknowns: STR, sources: STR, summary: { type: 'string' } } }
const FINDINGS = { type: 'object', required: ['findings', 'prerequisites', 'tests_to_add', 'sources', 'summary'], properties: {
  findings: { type: 'array', maxItems: 30, items: { type: 'object', required: ['area', 'claim', 'evidence', 'severity', 'recommendation'],
    properties: { area: { type: 'string' }, claim: { type: 'string' }, evidence: { type: 'string' }, severity: { enum: ['info', 'low', 'medium', 'high', 'critical'] }, recommendation: { type: 'string' } } } },
  prerequisites: STR, tests_to_add: STR, sources: STR, summary: { type: 'string' } } }
const AUDIT = { type: 'object', required: ['verdicts', 'gaps', 'summary'], properties: {
  verdicts: { type: 'array', items: { type: 'object', required: ['target', 'claim', 'verdict', 'evidence', 'correction'],
    properties: { target: { type: 'string' }, claim: { type: 'string' }, verdict: { enum: ['confirmed', 'refuted', 'unverifiable'] }, evidence: { type: 'string' }, correction: { type: 'string' } } } },
  gaps: STR, summary: { type: 'string' } } }

const COMMON = `You are one of twelve specialists on nawah-os (repository /home/user/nawah-os, GitHub ccq9/nawah-os): an original Rust/UEFI operating system for x86-64 whose organisation and behaviour follow the documented Windows 10 Pro 22H2 reference under a clean-room rule (docs/adr/0022-reference-media-clean-room.md). The project's records are Arabic JSON and Markdown under docs/: project-state.json, stages.json, work-items.json, requirements.json, tests.json, risks.json, decisions-pending.json, sources.json, PLAN.md, PROJECT.md, ENVIRONMENT.md, adr/, contracts/, operations/, security/threat-model.md, and prompt/OS-EXEC-AR-v3.2.md (the governing prompt: section 19 critical scenarios, section 20 stage exit conditions M0-M15, section 22 acceptance wording). Stages M0-M5 passed their gates; M6 (desktop and tools) is open with WP-45..WP-63 planned, 21 REQ-M6 requirements and 68 TST-M6 tests; M7-M15 are not started and stages.json only points at the prompt's section 20 for their exit conditions.

Hard rules. (1) Read-only: do not modify, create or delete files; do not run git commands that write; do not push. Return data only. (2) Evidence: every claim cites a file path with line numbers or a record id (REQ-/WP-/TST-/ADR-/DEC-/RSK-/S-); a claim you could not verify is marked "unverified" in its evidence field, never stated as fact. (3) Clean room (ADR-0022): never propose copying Microsoft code, UI text, icons, images, fonts or pixel layouts; behaviour and organisation only, from the project's own reference docs. (4) CI is the judge: local runs are scratch; evidence lives in evidence/<run>/ and docs/tests.json. (5) Plain, exact language; no praise, no padding; state the limits of your analysis explicitly. (6) You may spawn at most 2 helper sub-agents with the Agent tool, passing model: "sonnet", for parallel reading only; verify their claims yourself before using them. (7) Write user-facing prose fields (summary, claim, recommendation, correction, readiness) in Arabic; keep ids, paths, symbols and code in Latin script. (8) Your final text is a data return, not a message to a person.`

phase('Planning')
log('Planning: 3 cartographers (end-state ladder, M6 chain, decisions and risks)')
const [levels, chain, risks] = await parallel([
  () => agent(`${COMMON}

Role: end-state cartographer (planning team 1 of 3).
Objective: derive the backward chain of acceptance levels from the final product down to the current gate. Levels, from the END to the BEGINNING: Release Candidate, Beta, Alpha, MVP (definitions: docs/PROJECT.md "تعريفات الإصدارات" and "حدود القبول"), then the stage gates M15, M14, M13, M12, M11, M10, M9, M8, M7 (exit conditions only in docs/prompt/OS-EXEC-AR-v3.2.md section 20; also read section 22 acceptance clause and section 19 critical scenarios), then M6 as it stands today (docs/stages.json M6 exit_conditions; docs/PLAN.md sections 6-9 lines 76-138).
For each level give: exit conditions (quoted or closely paraphrased, with file:line); preconditions (what the previous level must already deliver); delivered_by (stage or work item ids); judged_by (test ids, evidence kinds, or "no judge named yet"); open_decisions (DEC ids from docs/decisions-pending.json that gate it). Where the prompt leaves a stage's exit conditions generic or missing, say so in that level; never invent conditions. Order the levels array from the end (RC) to the beginning (M6).`,
    { label: 'plan:endstate', phase: 'Planning', schema: LEVELS, model: 'opus', effort: 'high' }),
  () => agent(`${COMMON}

Role: M6 dependency cartographer (planning team 2 of 3).
Objective: map the dependency graph inside M6 down to the first actionable step. Read docs/work-items.json WP-45..WP-63 (depends_on, test_ids, requirement_ids, actions, acceptance, budget lines), docs/requirements.json REQ-M6-*, docs/tests.json TST-M6-* oracles, docs/stages.json M6 exit_conditions, docs/PLAN.md M6 table (section 6), docs/decisions-pending.json DEC-005..DEC-010, and the records rules in tools/project.py (cmd_check_commit; the work-item status rules: active or done only when every depends_on is done).
Produce: one entry per work item with its dependencies, what it blocks (reverse edges you compute), its tests and requirements, and a readiness verdict in Arabic (ready now; blocked by <ids>; needs decision <DEC id>; budget note). The critical path from WP-45 to the M6 gate item; parallel tracks that can run concurrently without shared files or contracts; the first step with its concrete prerequisites (contract versions named in the WP actions, files, tests, the budget line). Report any inconsistency you find in the records (a dependency on an item that does not exist, a test id with no record, a requirement with no work item).`,
    { label: 'plan:chain', phase: 'Planning', schema: CHAIN, model: 'opus', effort: 'high' }),
  () => agent(`${COMMON}

Role: risk and decision cartographer (planning team 3 of 3).
Objective: map every open decision and risk onto the backward chain. Read docs/decisions-pending.json (all records; note which are open: at least DEC-002 reference capture and DEC-010 Sol OS archive; and the conditions attached to answered ones DEC-005..DEC-009), docs/risks.json RSK-001..RSK-011, docs/security/threat-model.md, the limits sections of docs/adr/0019..0022, docs/operations/m5-review.md declared exceptions (REQ-M5-010, scenario 7 screens, DEC-007 ACPI S5), docs/hardware.json (Beta needs one real machine with evidence), docs/PROJECT.md release definitions, docs/sources.json S09 S10 S11 (SSDF, TUF, Secure Boot) as RC inputs.
For each decision: id, the levels or gates it blocks (RC, Beta, Alpha, MVP, M6..M15 or specific WP ids), recommendation, and the exact owner action in one sentence. For each risk: id, what levels it affects, mitigation present (cite) or missing. List unknowns that no record measures yet (for example real-hardware drivers, installer, in-place update, SBOM and licence inventory, independent review).`,
    { label: 'plan:risk', phase: 'Planning', schema: RISKS, model: 'opus', effort: 'high' }),
])
const plan = { levels, chain, risks }
log(`Planning done: levels=${levels ? levels.levels.length : 'null'} work_items=${chain ? chain.work_items.length : 'null'} decisions=${risks ? risks.decisions.length : 'null'}`)
const PLAN_JSON = JSON.stringify(plan)

phase('Engineering')
log('Engineering: 2 code, 2 security, 2 UI specialists')
const ENG_COMMON = `${COMMON}

The planning team's maps (JSON; treat as input to check, not as truth): ${PLAN_JSON}`
const [codeKernel, codeApps, secThreat, secAssurance, uiShell, uiSettings] = await parallel([
  () => agent(`${ENG_COMMON}

Role: code engineer, kernel and system services (code team 1 of 2).
Objective: technical readiness of WP-45..WP-52 (session screens and interactive boot manifest, session watchdog, launch broker, shell role, taskbar and window management from keyboard, logs, task manager data, start menu). Read each work item's actions and files, the contracts they must bump (docs/contracts/services.md, session.md, boot.md, display.md, input.md, syscall.md, shell.md) and the code: kernel/src/services.rs, kernel/src/syscall/mod.rs, kernel/src/object/*.rs, kernel/src/display.rs, user/apps/svcmgr, sessiond, displayd, inputd, sh, user/libnawah, user/libui. For each WP: what already exists (cite), what is missing, the contract version bump implied, hidden coupling with other WPs, size (small/medium/large with a reason), and the guest or host tests it needs per the project's TDD loop (guest: a function in kernel/src/ktest.rs plus its case in platform/pc-qemu/target.json; host: tests/*.py registered in HOST_SUITES in tools/project.py). Severity means impact on the critical path.`,
    { label: 'code:kernel', phase: 'Engineering', schema: FINDINGS, model: 'opus' }),
  () => agent(`${ENG_COMMON}

Role: code engineer, files and applications (code team 2 of 2).
Objective: technical readiness of WP-53..WP-63 (user homes and *_at interfaces, clipboard and drag, files application chain, trash, rename and long file names, editor modify and reboot, disk-full and out-of-memory failure paths, device list, asset provenance, end-to-end scenario, M6 mutants, the M6 gate). Read kernel/src/fs/fat32.rs, kernel/src/fs/vfs.rs, kernel/src/block/mod.rs, kernel/src/drivers/virtio_blk.rs, docs/contracts/files.md, docs/adr/0014-files.md, docs/adr/0020-system-files-authority.md, user/apps/fileauth, user/apps/configd, user/libnawah, tools/fat32.py, tests/test_fat32_tool.py. Same per-WP output as the kernel engineer: exists (cite) / missing / contract bump / coupling / size / tests. Give special attention to REQ-M6-001 (Arabic and mixed long file names on disk: FAT LFN, UCS-2, case folding), trash index persistence and reconciliation at start, and the DISK-FULL path through FAT32 allocation.`,
    { label: 'code:apps', phase: 'Engineering', schema: FINDINGS, model: 'opus' }),
  () => agent(`${ENG_COMMON}

Role: security engineer, threat model (security team 1 of 2).
Objective: the M6 threat model and the authority-layer tests it requires. Read docs/security/threat-model.md, docs/adr/0016-services-and-authority.md, 0020-system-files-authority.md, 0021-elevation-trusted-path.md, 0019-graphics-platform.md section 12, docs/contracts/session.md, services.md, shell.md, files.md, the M6 exit condition on authority (docs/stages.json M6: الصلاحيات تُرفض عند طبقة السلطة لا عند الواجهة) and the DENIED and isolation tests in docs/tests.json (LAUNCH-DENIED, POWER-DENIED, END-TASK-DENIED, SVC-TOOL-DENIED, FILES-DENIED, HOME-ISOLATION, DIR-ESCAPE, CLIPBOARD-ISOLATION, NOTIFY-LOCKED, SHELL-AUTHORITY, LOG-AUTHORITY), plus the SECURITY list in tests/mutants.py. For each M6 component (shell role, launch broker, clipboard, logs, trash, user homes, notifications under lock): assets, threat, existing control (cite), required test, and a SECURITY mutant candidate (file, the defect to seed, the killer test). Flag any planned item whose authority check sits in the UI instead of the authority layer, and any gap between threat-model.md and the M6 plan.`,
    { label: 'sec:threat', phase: 'Engineering', schema: FINDINGS, model: 'opus' }),
  () => agent(`${ENG_COMMON}

Role: security engineer, assurance and supply chain (security team 2 of 2).
Objective: the assurance path from M6 to Release Candidate. Read .github/workflows/*.yml (action pins, token scopes, the evidence branch push), tools/project.py (import-ci-evidence, validate-records --strict and stale_policy, checkpoint, cmd_check_commit DEC-004), tools/pre-merge.sh, tests/test_ci_workflows.py, tests/mutants.py (SECURITY list, kill rule, gates), tools/check-unsafe.sh with tools/unsafe-baseline.txt, docs/sources.json S09 S10 S11, docs/PROJECT.md RC definition (independent reviewer package, no critical or high defects open, manifest, SBOM, licences), RSK-006 in docs/risks.json, docs/prompt/OS-EXEC-AR-v3.2.md section 22. Produce: the gaps between today's assurance and the RC bar, each with the record that would close it (a new REQ, TST, ADR or DEC, named), and any present weakness in CI or evidence integrity with evidence (for example an unpinned action, a token with write scope on a checkout, a stale verdict path that strict mode does not catch).`,
    { label: 'sec:assurance', phase: 'Engineering', schema: FINDINGS, model: 'opus' }),
  () => agent(`${ENG_COMMON}

Role: UI designer, desktop shell and session screens (UI team 1 of 2).
Objective: a design brief, Arabic and English, for the M6 shell surfaces: sign-in, lock and elevation screens with input-language indicator (WP-45), desktop background and session watchdog visibility, taskbar and window management from keyboard and desktop (WP-46, WP-47), Start and launch (WP-48), notifications and the locked state (scenario 8, NOTIFY-LOCKED). Inputs: docs/contracts/ui.md, display.md, input.md, text.md, session.md section 8, user/libui/src/*.rs (available elements, focus order, RTL, descriptions for the narrator, theme scale and contrast), user/libnawah-text (bidi and shaping), docs/adr/0019-graphics-platform.md, docs/reference/windows10.json and windows10-media.md (behaviour and organisation only), ADR-0022 and DEC-009 (original assets; TST-M6-ASSET-PROVENANCE), the expect files under platform/pc-qemu/expect and tools/screen.py, tools/transcript.py (what the lab can judge). Output as findings: per surface the elements and states, keyboard navigation order, narrator string policy (whole sentences in both languages, no password values), RTL mirroring rules, and the lab-judgeable acceptance checks. Flag every libui element the brief needs that does not exist yet, with the contract bump it implies.`,
    { label: 'ui:shell', phase: 'Engineering', schema: FINDINGS, model: 'opus' }),
  () => agent(`${ENG_COMMON}

Role: UI designer, files, dialogs and settings (UI team 2 of 2).
Objective: a design brief for the files application (create, copy, rename, delete, restore; conflicts; Arabic and mixed names; long file names), trash, editor save and unsaved-changes dialogs, task manager and device list data views (real data, no synthetic values), and the three R1 settings pages M7 will need (docs/PROJECT.md R1 definition; docs/reference/windows10.json organisation; DEC-002 open so reference matching is unjudged; DEC-009). Inputs as for the shell designer plus docs/contracts/files.md, docs/adr/0014-files.md, docs/adr/0020-system-files-authority.md, and the M6 exit conditions on files and failure paths (FILES-CONFLICT, TRASH-CONFLICT, EDITOR-UNSAVED, DISK-FULL, FILES-DISK-FULL, EDITOR-SAVE-FAIL, FILES-A11Y-AR, LISTVIEW-RTL). Output as findings: per view the elements, list and column behaviour in RTL, error presentation that never reports false success (scenario 6), keyboard-only operation, narrator descriptions, and lab-judgeable acceptance checks. Flag missing libui elements (for example a list view with columns, a tree, a menu, a progress indicator) with the contract bump each implies.`,
    { label: 'ui:settings', phase: 'Engineering', schema: FINDINGS, model: 'opus' }),
])
const eng = { codeKernel, codeApps, secThreat, secAssurance, uiShell, uiSettings }
const engCount = Object.values(eng).filter(Boolean).length
log(`Engineering done: ${engCount}/6 reports`)

phase('Audit')
log('Audit: 2 auditors verify claims against the records and the code')
const [auditPlan, auditEng] = await parallel([
  () => agent(`${COMMON}

Role: auditor of the plan (audit team 1 of 2).
You receive the three planners' outputs (JSON): ${PLAN_JSON}
Verify every level, dependency and decision claim against the records yourself: open the cited files and lines. Give a verdict per claim (confirmed, refuted, unverifiable) with evidence and the correction in Arabic. Hunt for: levels with no judge named; dependencies that contradict docs/work-items.json depends_on; exit conditions invented beyond docs/prompt/OS-EXEC-AR-v3.2.md section 20 and docs/stages.json; decisions whose owner action is vague; ordering errors in the backward chain; a first step whose prerequisites are not all met. List the gaps the planners missed. Cover at least every level and every work item WP-45..WP-63.`,
    { label: 'audit:plan', phase: 'Audit', schema: AUDIT, model: 'opus', effort: 'high' }),
  () => agent(`${COMMON}

Role: auditor of engineering, security and UI (audit team 2 of 2).
You receive the six specialists' outputs (JSON): ${JSON.stringify(eng)}
Verify at least 24 claims against the code and the records, all high and critical severities first, then a sample of the rest: open the cited files and lines. Give a verdict per claim (confirmed, refuted, unverifiable) with evidence and the correction in Arabic. Hunt for: clean-room violations (ADR-0022); tests proposed at the wrong layer; contract version promises that do not exist (docs/contracts/*.md version history); phantom claims (a file, symbol or record that does not exist); contradictions between the six outputs; recommendations that would weaken an existing test or gate. List the gaps the specialists missed.`,
    { label: 'audit:eng', phase: 'Audit', schema: AUDIT, model: 'opus', effort: 'high' }),
])
log(`Audit done: plan verdicts=${auditPlan ? auditPlan.verdicts.length : 'null'} eng verdicts=${auditEng ? auditEng.verdicts.length : 'null'}`)

phase('Manager')
log('Manager: integrating the audited findings into the reverse plan')
const manager = await agent(`${COMMON}

Role: team manager and integrator. You receive the planners' maps, the six specialists' findings and both audits (JSON below). Produce the final text, in Arabic, of docs/PLAN-REVERSE.md titled "الخطة العكسية: من قبول الإصدار إلى الخطوة التالية".
Structure, in this order with these headings:
0. الغاية والمنهج — one paragraph: backward chaining from acceptance to the next step; CI is the judge; clean room; the twelve-role team that produced and audited this (3 planners, 2 code, 2 security, 2 UI, 2 auditors, 1 manager).
1. سلّم القبول من النهاية إلى البداية — a table from RC down to M6 as it stands: level | exit conditions (with file:line) | preconditions | delivered by | judged by | gating decisions. Keep the planners' levels, corrected by the audit.
2. داخل M6: من البوابة إلى الخطوة الأولى — a table (WP | depends_on | blocks | tests | readiness), then the critical path, the parallel tracks, and the first step with its prerequisites.
3. القرارات والمخاطر الحاكمة — table: decision or risk | what it gates | recommendation | owner action.
4. توصيات الهندسة والأمن والواجهة — only audit-confirmed findings, grouped by team (code, security, UI), each with its evidence and the record it should become (REQ/TST/ADR/DEC/RSK), ordered by severity.
5. ما رفضه التدقيق أو لم يتحقق — every refuted or unverifiable claim, with the auditor's reason.
6. حدود هذه الخطة — what the team could not verify, what depends on the owner, and the date 2026-11-09.
Rules: apply every auditor correction; move refuted claims out of section 4 into section 5; keep every citation; add no facts of your own; no praise; Arabic prose, Latin ids and paths. Return only the Markdown document.

Planners: ${PLAN_JSON}
Specialists: ${JSON.stringify(eng)}
Audits: ${JSON.stringify({ auditPlan, auditEng })}`,
  { label: 'manager', phase: 'Manager', model: 'opus', effort: 'high' })
log('Manager done')
return { plan, eng, audits: { auditPlan, auditEng }, manager }