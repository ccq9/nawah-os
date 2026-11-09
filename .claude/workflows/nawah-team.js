export const meta = {
  name: 'nawah-team',
  description: 'nawah-os fourteen-role team (DEC-011): 2 planners, 3 software, 3 systems, 3 security engineers, 1 auditor, 1 assistant manager, 1 manager answer the plan',
  phases: [
    { title: 'Planning', detail: 'acceptance ladder with decisions and risks; dependency chain with first-step options' },
    { title: 'Engineering', detail: 'software (kernel, services, apps), systems (lab, platform, release), security (threat, assurance, red team)' },
    { title: 'Audit', detail: 'the auditor verifies every claim against the records and the code' },
    { title: 'Steward', detail: 'the assistant manager checks records compliance and builds the change checklist' },
    { title: 'Manager', detail: 'integrate the audited, records-checked answer' },
  ],
}

const STR = { type: 'array', items: { type: 'string' } }
const LEVELS = { type: 'object', required: ['levels', 'decisions', 'risks', 'unknowns', 'sources', 'summary'], properties: {
  levels: { type: 'array', items: { type: 'object', required: ['name', 'exit_conditions', 'preconditions', 'delivered_by', 'judged_by', 'open_decisions', 'sources'],
    properties: { name: { type: 'string' }, exit_conditions: STR, preconditions: STR, delivered_by: STR, judged_by: STR, open_decisions: STR, sources: STR } } },
  decisions: { type: 'array', items: { type: 'object', required: ['id', 'gates', 'recommendation', 'owner_action'],
    properties: { id: { type: 'string' }, gates: STR, recommendation: { type: 'string' }, owner_action: { type: 'string' } } } },
  risks: { type: 'array', items: { type: 'object', required: ['id', 'affects', 'mitigation'], properties: { id: { type: 'string' }, affects: STR, mitigation: { type: 'string' } } } },
  unknowns: STR, sources: STR, summary: { type: 'string' } } }
const OPTION = { type: 'object', required: ['name', 'pros', 'cons'], properties: { name: { type: 'string' }, pros: STR, cons: STR } }
const DECISION = { type: 'object', required: ['topic', 'options', 'recommendation', 'rationale', 'failure_modes', 'reversibility', 'tests_first', 'files'],
  properties: { topic: { type: 'string' }, options: { type: 'array', minItems: 2, items: OPTION }, recommendation: { type: 'string' }, rationale: { type: 'string' },
    failure_modes: STR, reversibility: { type: 'string' }, tests_first: STR, files: STR } }
const CHAIN = { type: 'object', required: ['work_items', 'critical_path', 'parallel_tracks', 'first_step', 'activation_sequence', 'sources', 'summary'], properties: {
  work_items: { type: 'array', items: { type: 'object', required: ['id', 'title', 'depends_on', 'blocks', 'tests', 'requirements', 'readiness'],
    properties: { id: { type: 'string' }, title: { type: 'string' }, depends_on: STR, blocks: STR, tests: STR, requirements: STR, readiness: { type: 'string' } } } },
  critical_path: STR, parallel_tracks: { type: 'array', items: STR }, first_step: DECISION, activation_sequence: STR, sources: STR, summary: { type: 'string' } } }
const FINDING = { type: 'object', required: ['area', 'claim', 'evidence', 'severity', 'recommendation'],
  properties: { area: { type: 'string' }, claim: { type: 'string' }, evidence: { type: 'string' }, severity: { enum: ['info', 'low', 'medium', 'high', 'critical'] }, recommendation: { type: 'string' } } }
const DESIGN = { type: 'object', required: ['decisions', 'findings', 'prerequisites', 'tests_to_add', 'sources', 'summary'], properties: {
  decisions: { type: 'array', minItems: 1, items: DECISION }, findings: { type: 'array', maxItems: 25, items: FINDING }, prerequisites: STR, tests_to_add: STR, sources: STR, summary: { type: 'string' } } }
const FINDINGS = { type: 'object', required: ['findings', 'prerequisites', 'tests_to_add', 'sources', 'summary'], properties: {
  findings: { type: 'array', maxItems: 30, items: FINDING }, prerequisites: STR, tests_to_add: STR, sources: STR, summary: { type: 'string' } } }
const ATTACKS = { type: 'object', required: ['attacks', 'sources', 'summary'], properties: {
  attacks: { type: 'array', maxItems: 25, items: { type: 'object', required: ['target', 'adversary', 'path', 'precondition', 'control', 'test', 'status'],
    properties: { target: { type: 'string' }, adversary: { type: 'string' }, path: { type: 'string' }, precondition: { type: 'string' }, control: { type: 'string' }, test: { type: 'string' }, status: { enum: ['demonstrated', 'hypothesis'] } } } },
  sources: STR, summary: { type: 'string' } } }
const AUDIT = { type: 'object', required: ['verdicts', 'gaps', 'summary'], properties: {
  verdicts: { type: 'array', items: { type: 'object', required: ['target', 'claim', 'verdict', 'evidence', 'correction'],
    properties: { target: { type: 'string' }, claim: { type: 'string' }, verdict: { enum: ['confirmed', 'refuted', 'unverifiable'] }, evidence: { type: 'string' }, correction: { type: 'string' } } } },
  gaps: STR, summary: { type: 'string' } } }
const STEWARD = { type: 'object', required: ['records_changes', 'contradictions', 'budget_check', 'local_checks', 'summary'], properties: {
  records_changes: { type: 'array', items: { type: 'object', required: ['record', 'change', 'reason', 'blocked_by'],
    properties: { record: { type: 'string' }, change: { type: 'string' }, reason: { type: 'string' }, blocked_by: { type: 'string' } } } },
  contradictions: STR, budget_check: { type: 'string' }, local_checks: { type: 'string' }, summary: { type: 'string' } } }

const COMMON = `You are one of fourteen specialists on nawah-os (repository /home/user/nawah-os, GitHub ccq9/nawah-os): an original Rust/UEFI operating system for x86-64 whose organisation and behaviour follow the documented Windows 10 Pro 22H2 reference under a clean-room rule (docs/adr/0022-reference-media-clean-room.md). Records are Arabic JSON and Markdown under docs/ (project-state.json, stages.json, work-items.json, requirements.json, tests.json, risks.json, decisions-pending.json, sources.json, PLAN.md, PLAN-REVERSE.md, PROJECT.md, ENVIRONMENT.md, adr/, contracts/, operations/, policies/team-methodology.md, security/threat-model.md, prompt/OS-EXEC-AR-v3.2.md: the governing prompt, section 19 critical scenarios, section 20 stage exit conditions, section 22 acceptance). Stages M0-M5 passed; M6 is open with WP-45..WP-63 planned; docs/PLAN-REVERSE.md (2026-11-09) is the audited reverse plan whose section 2 names the first step, WP-45, with eight preconditions.

Your task today, as a team: ANSWER THE PLAN. Not another plan: the concrete engineering answer to docs/PLAN-REVERSE.md: what is built first and how, with options and trade-offs, tests first, contracts before code, records compliance, and the attacks each design must survive.

Hard rules. (1) Read-only in this run: do not modify, create or delete files; do not run git commands that write; do not push. Return data only. (2) Evidence: every claim cites a file path with line numbers or a record id; what you could not verify is marked "unverified". (3) Clean room (ADR-0022). (4) CI is the judge; local runs are scratch. (5) Design method: every decision you own has 2-3 options with trade-offs, a recommendation with rationale, failure modes, reversibility, the tests that fail first and the files touched; the simplest viable option is one of the options. (6) Quality: risk first; tests at the right layer. (7) Plain, exact language; no praise; state your limits. (8) You may spawn at most 2 helper sub-agents with the Agent tool, model "sonnet", for parallel reading only; verify their claims. (9) Arabic for prose fields; Latin for ids, paths, symbols. (10) Your final text is a data return, not a message to a person.`

phase('Planning')
log('Planning: ladder with decisions and risks; chain with first-step options')
const [ladder, chain] = await parallel([
  () => agent(`${COMMON}

Role: nawah-plan-ladder (planning 1 of 2). Refresh the acceptance ladder of docs/PLAN-REVERSE.md section 1 and the decisions and risks of section 3 against the records at HEAD (docs/PROJECT.md, docs/prompt/OS-EXEC-AR-v3.2.md sections 19/20/22, docs/stages.json, docs/decisions-pending.json including DEC-011, docs/risks.json, docs/hardware.json, docs/security/threat-model.md). Keep what still holds, correct what changed, and for each owner decision write the exact owner action in one sentence. Then answer: which items of the ladder can the team advance NOW without an owner decision (records to create: REQ/TST/ADR proposals for M7..M10 judges, severity standard draft, independent-review schema fields), and which cannot. Levels from the END to the BEGINNING.`,
    { label: 'plan:ladder', phase: 'Planning', schema: LEVELS, model: 'opus', effort: 'high' }),
  () => agent(`${COMMON}

Role: nawah-plan-chain (planning 2 of 2). Refresh docs/PLAN-REVERSE.md section 2 against HEAD: docs/work-items.json WP-45..WP-63, docs/tests.json TST-M6-*, docs/requirements.json REQ-M6-*, docs/stages.json M6, tools/project.py records rules (activation only when every depends_on is done; cmd_check_commit; the transitions table; the dependency-on-superseded rule). Then design the first step: 2-3 options for splitting WP-45 (budget line: 90 min or 120 tool calls; its actions name 'watchdog and Arabic screens can split off the boot-mode change') each with its exact records consequences (new WP id, depends_on, test_ids and requirement_ids moved, REQ-M6-002 linkage, WP-62 depends_on), trade-offs, and your recommendation; the activation sequence as an ordered list of record edits and the commit each lands in (DEC-004). Report every record inconsistency you find.`,
    { label: 'plan:chain', phase: 'Planning', schema: CHAIN, model: 'opus', effort: 'high' }),
])
const PLAN_JSON = JSON.stringify({ ladder, chain })
log(`Planning done: levels=${ladder ? ladder.levels.length : 'null'} first_step options=${chain ? chain.first_step.options.length : 'null'}`)

phase('Engineering')
log('Engineering: 3 software, 3 systems, 3 security')
const ENG = `${COMMON}

The planners' refreshed maps and first-step options (JSON; input to check, not truth): ${PLAN_JSON}

Also read docs/PLAN-REVERSE.md sections 2 and 4 for the confirmed findings that concern your domain.`
const [swKernel, swServices, swApps, sysLab, sysPlatform, sysRelease, secThreat, secAssurance, secRedteam] = await parallel([
  () => agent(`${ENG}

Role: nawah-sw-kernel (software 1 of 3: kernel and boot path). Decide the boot-mode design of WP-45: today the release kernel always exits after the self-test (kernel/src/kmain.rs around lines 558-572) and fw_cfg is compiled only under ktest (kernel/src/arch/x86_64/mod.rs around lines 29-30); ADR-0019:48 and the oracle of TST-M6-INTERACTIVE-BOOT make the interactive boot the default and the lab self-test the keyed path; tools/project.py around lines 1049-1054 picks the boot case as the one without qemu_extra. Give 2-3 options for the kernel side (where the mode is decided, how the key is read in a release build without widening unsafe, how TST-M1-BOOT/NEG/NOBS keep their oracles), failure modes (a key that leaks into a release image; a missing key on real hardware), reversibility, the exact files and the ktest/host tests that fail first, and the unsafe-baseline impact (tools/unsafe-baseline.txt, ADR-0002 item 6). Add findings on any other kernel item the plan's first step touches.`,
    { label: 'sw:kernel', phase: 'Engineering', schema: DESIGN, model: 'opus' }),
  () => agent(`${ENG}

Role: nawah-sw-services (software 2 of 3: system services). Decide the services side of WP-45: the system manifest SERVICES.TXT with eight services (auth, config, net, input, display, session, narrator, sh) versus ADR-0019:48's seven (record the difference: narrator), services.md v1.10 -> v1.11, the session watchdog (session.md v1.7: watchdog ticks > REQUEST_DEADLINE; REQ-M5-010 limit; svcmgr PING/PONG in user/apps/svcmgr), and the session screens reading ui.lang/ui.scale/ui.contrast through config GET + SUBSCRIBE (user/apps/sessiond, user/apps/configd, docs/contracts/config.md). 2-3 options per decision, failure modes (watchdog killing a session legitimately waiting on auth; manifest order and timeouts), tests first (guest cases in platform/pc-qemu/target.json with monitor steps; host tests), contract bumps named with versions and enforcement tests.`,
    { label: 'sw:services', phase: 'Engineering', schema: DESIGN, model: 'opus' }),
  () => agent(`${ENG}

Role: nawah-sw-apps (software 3 of 3: applications, UI toolkit, text; the team's UI designer by DEC-011). Decide the screen side of WP-45: whole-sentence string tables in Arabic and English for sign-in, lock and elevation (user/apps/sessiond, user/libui, user/libnawah-text; docs/contracts/ui.md, text.md, session.md section 8), the input-language indicator next to the user and password fields versus input.md section 3.2 ('no event on layout switch') and the libui element limit the plan's section 4/5 records; the narrator policy (no password values; TST-M5 narrator tests unregressed); RTL mirroring; the lab checks (tools/screen.py, tools/transcript.py, platform/pc-qemu/expect/*.txt) that judge them. 2-3 options per decision; failure modes (a string that does not fit its row: Painter::fits; a layout-switch indicator with no event source); tests first; libui contract bumps named. Original assets only (ADR-0022, DEC-009).`,
    { label: 'sw:apps', phase: 'Engineering', schema: DESIGN, model: 'opus' }),
  () => agent(`${ENG}

Role: nawah-sys-lab (systems 1 of 3: lab and CI plumbing). Decide the M6 suite infrastructure the plan's first step requires: suites['M6'] in platform/pc-qemu/target.json, HOST_SUITES['M6'] in tools/project.py, the verify.yml steps (guest and host) and their timeouts, tests/test_ci_workflows.py updates (TST-M0-003), the boot-case selection in tools/project.py around lines 1049-1054 when the default boot becomes interactive and the self-test needs a fw_cfg key (how 'project.py boot' and TST-M1-BOOT/NEG/NOBS keep working), the mutants stage mapping in tests/mutants.py (n < 130 -> M5; M6 missing) and mutants.yml. 2-3 options per decision; failure modes (CI time budget; a step that passes on CI and fails in preflight); tests first (host tests that pin the plumbing).`,
    { label: 'sys:lab', phase: 'Engineering', schema: DESIGN, model: 'opus' }),
  () => agent(`${ENG}

Role: nawah-sys-platform (systems 2 of 3: hardware platform). Answer the platform items the plan raises on the M6 critical path and toward Beta: rtc_read and system_reset for WP-51 (kernel/src/arch/x86_64/acpi.rs has find_table for APIC and MCFG but no FADT/FACP; CMOS RTC; ACPI 6.5 S27/S33; ICH9 S34; QEMU models S35), ACPI S5 deferred by DEC-007, the fw_cfg key on real hardware (fw_cfg is a QEMU device: what replaces it off the emulator), and the measurements-first path to one real machine (docs/hardware.json schema, RSK-007, scenario 12 DMA policy). 2-3 options per decision with specification citations; emulator behaviour named as such; failure modes; tests first.`,
    { label: 'sys:platform', phase: 'Engineering', schema: DESIGN, model: 'opus' }),
  () => agent(`${ENG}

Role: nawah-sys-release (systems 3 of 3: build, image, evidence tooling, release path). Decide the tooling answers to the plan's confirmed assurance findings: evidence provenance (every CI-imported run.json carries worker="interactive-agent" and dirty_state=true: fields, schema version docs/schemas/evidence-run.schema.json, how import-ci-evidence records the GitHub run id and conclusion, and the host test), import-ci-evidence verifying the run concluded success before adopting evidence (tools/project.py cmd_import_ci_evidence), the lab users and fixed salts prepare_disk bakes into /SYSTEM/USERS.DB (release image versus lab image), the stale project-state lease, and the manifest/SBOM/licence/signing path as records (REQ/TST/ADR) before tools. 2-3 options per decision; failure modes; tests first (tests/test_validate_records.py, tests/test_ci_workflows.py).`,
    { label: 'sys:release', phase: 'Engineering', schema: DESIGN, model: 'opus' }),
  () => agent(`${ENG}

Role: nawah-sec-threat (security 1 of 3: threat model). Write the M6 section the threat model lacks (docs/security/threat-model.md ends at M5 limits, lines 81-95): per component of WP-45..WP-48 first (boot mode and manifest, session watchdog, session screens and string tables, launch broker, shell role) then the rest of M6 briefly: assets, adversaries and capabilities, trust boundaries, existing control (cited), gap, the authority-layer test, and a SECURITY mutant candidate (file, seeded defect, killer test). Flag any first-step design option from the planners whose authority check would sit in the UI. Output as findings; the section text goes in the summary field, ready to paste.`,
    { label: 'sec:threat', phase: 'Engineering', schema: FINDINGS, model: 'opus' }),
  () => agent(`${ENG}

Role: nawah-sec-assurance (security 2 of 3: assurance and supply chain). Prioritise the assurance fixes the plan confirmed into an ordered list for the first commits: CI workflow pins and token scopes (.github/workflows/*.yml), import-ci-evidence run-conclusion check, evidence provenance fields, strict validation and stale_policy, the mutants M6 stage and its SECURITY list, the unsafe policy baseline impact of the boot-mode change, and the records that take the RC bar items (severity standard, independent reviewer, SBOM, signing: DEC/REQ/TST names). For each: the exact weakness with evidence, the fix, the host test that pins it, and whether it needs an owner decision. Never weaken a gate.`,
    { label: 'sec:assurance', phase: 'Engineering', schema: FINDINGS, model: 'opus' }),
  () => agent(`${ENG}

Role: nawah-sec-redteam (security 3 of 3: adversarial). Attack the first-step designs the planners propose and the confirmed plan items: a lab self-test key or lab users reaching a release image; the boot-mode switch on real hardware; the session watchdog as a denial-of-service or as a bypass of REQUEST_DEADLINE; Arabic and mixed string tables and paths as injection or confusion vectors (normalisation, length, Painter::fits); the launch broker's /APPS registry outside /SYSTEM; evidence tampering (digests, worker identity, run ids); authority checked at the UI. For each attack: adversary, entry point, path, the precondition the design leaves open, the control, the test or SECURITY mutant, and whether you demonstrated it against the code at HEAD or it stays a hypothesis.`,
    { label: 'sec:redteam', phase: 'Engineering', schema: ATTACKS, model: 'opus' }),
])
const eng = { swKernel, swServices, swApps, sysLab, sysPlatform, sysRelease, secThreat, secAssurance, secRedteam }
log(`Engineering done: ${Object.values(eng).filter(Boolean).length}/9 reports`)
const ENG_JSON = JSON.stringify(eng)

phase('Audit')
log('Audit: the auditor verifies every claim')
const audit = await agent(`${COMMON}

Role: nawah-auditor. You receive the planners' outputs ${PLAN_JSON} and the nine engineers' outputs ${ENG_JSON}.
Verify every high and critical claim and at least 30 others by opening the cited files and lines at HEAD. Verdict per claim: confirmed, refuted or unverifiable, with evidence and the correction in Arabic. Hunt for: clean-room violations; tests at the wrong layer; contract versions promised that do not exist; phantom files, symbols or records; exit conditions beyond the prompt section 20 and stages.json; dependency errors against docs/work-items.json; contradictions between roles (especially the boot-mode design across sw:kernel, sys:lab, sys:platform and sec:redteam); designs with a single option; anything that would weaken a gate. List the gaps the team missed.`,
  { label: 'audit', phase: 'Audit', schema: AUDIT, model: 'opus', effort: 'high' })
log(`Audit done: verdicts=${audit ? audit.verdicts.length : 'null'}`)

phase('Steward')
log('Steward: records compliance and the change checklist')
const steward = await agent(`${COMMON}

Role: nawah-assistant-manager. You receive the planners' outputs ${PLAN_JSON}, the engineers' outputs ${ENG_JSON} and the audit ${JSON.stringify(audit)}.
Check every surviving proposal against the records rules: DEC-004 (commit subjects), the activation rule (every depends_on done; budget line read), contract-version promises (docs/contracts/*.md histories), test and requirement linkage (docs/tests.json, docs/requirements.json), the transitions table and the dependency-on-superseded rule in tools/project.py. Run \`python3 tools/project.py validate-records\` and \`python3 tools/project.py check-commit\` as scratch checks and report their output verbatim in local_checks. Produce the ordered records-change checklist (record id, exact change, reason, blocker or none) that would implement the recommended first step, and the list of contradictions between roles the manager must resolve. budget_check: whether the recommended first step fits the budget lines involved.`,
  { label: 'steward', phase: 'Steward', schema: STEWARD, model: 'opus', effort: 'high' })
log('Steward done')

phase('Manager')
log('Manager: integrating the answer')
const manager = await agent(`${COMMON}

Role: nawah-manager, integrator. Inputs: planners ${PLAN_JSON}; engineers ${ENG_JSON}; audit ${JSON.stringify(audit)}; steward ${JSON.stringify(steward)}.
Produce the final text, in Arabic, of docs/PLAN-ANSWER.md titled "إجابة الفريق على الخطة: ما نبنيه أولًا وكيف". Structure with these headings in this order:
0. الإجابة في صفحة — what is done first, in what order, by whom, judged by which tests; the fourteen roles that produced and audited it (DEC-011).
1. الخطوة الأولى WP-45: القرار — the chosen split and activation sequence (from plan:chain, corrected by the audit and the steward), the alternatives rejected and why.
2. التصاميم المختارة — per decision (boot mode and key, manifest and watchdog, screens and strings, M6 suite plumbing, boot-case selection, platform items, evidence provenance and import check, release image): chosen option, rejected options with the reason, failure modes, reversibility, files, tests first. Only audit-confirmed content.
3. الأمن — the threat-model M6 section text (from sec:threat summary), the authority-layer tests, the SECURITY mutants, the attacks the designs must survive with their tests (demonstrated versus hypothesis), and the assurance fixes in priority order.
4. تغييرات السجلات — the steward's ordered checklist (record, change, reason, blocker) and the commits each lands in (DEC-004).
5. ما رفضه التدقيق أو لم يتحقق — every refuted or unverifiable claim with the auditor's reason, and the contradictions the manager resolved with the resolution.
6. ما يتوقف على المالك — decisions only the owner can take, each with the exact action.
7. حدود هذه الإجابة — what was not read or measured; the date 2026-11-09.
Rules: apply every auditor correction and every steward blocker; move refuted claims into section 5; keep every citation; add no facts of your own; no praise; Arabic prose, Latin ids and paths. Return only the Markdown document.`,
  { label: 'manager', phase: 'Manager', model: 'opus', effort: 'high' })
log('Manager done')
return { plan: { ladder, chain }, eng, audit, steward, manager }
