#!/usr/bin/env python3
"""TST-M0-002: the M0 documents required by prompt 3.2 section 7 exist and the boot contract carries the sections of section 7 (inputs/outputs, ownership, states, errors, trace contract, timeouts, versioning, enforcement tests); every file ADR-0002 item 4 ports from Sol OS names its origin in its header; the twelve-role team methodology (docs/policies/team-methodology.md) is in place: its agent definitions, its workflow and the reverse plan it produces."""
import re, subprocess, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ["docs/ENVIRONMENT.md", "docs/PROJECT.md", "docs/requirements.json", "docs/stages.json", "docs/work-items.json",
            "docs/tests.json", "docs/adr/0001-bootstrap.md", "docs/contracts/boot.md", "docs/security/threat-model.md",
            "docs/risks.json", "docs/reference/windows10.json", "docs/hardware.json", "docs/sources.json",
            "docs/project-state.json", "docs/automation.json", "docs/schemas/requirements.schema.json",
            "docs/prompt-errata.md", "docs/decisions-pending.json", "evidence/automation/events.jsonl", "tools/project.py"]
# Windows refuses these names (with any extension) and characters, and folds case: a tracked path
# that breaks one of these rules makes `git clone` fail on Windows (kernel/src/arch/x86_64/com2.rs did).
WIN_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.IGNORECASE)
WIN_INVALID = re.compile(r'[<>:"|?*\\\x00-\x1f]')
# ADR-0002 item 4: every file ported from Sol OS (S32, commit d54f0a5) carries an origin line, so a
# reader knows it was reviewed and adapted here rather than written here. Code files cite the
# commit; files that carry over a design cite the Sol ADR (ktest.rs: ADR-010, check-unsafe.sh: ADR-008).
SOL_PORTED = ["kernel/src/arch/x86_64/gdt.rs", "kernel/src/arch/x86_64/idt.rs", "kernel/src/arch/x86_64/trap.rs",
              "kernel/src/arch/x86_64/serial.rs", "kernel/src/arch/x86_64/port.rs", "kernel/src/arch/x86_64/qemu.rs",
              "kernel/src/arch/x86_64/ktest.rs", "kernel/src/cell.rs", "kernel/src/ktest.rs", "tests/mutants.py",
              "tools/check-unsafe.sh"]
SOL_ORIGIN = re.compile(r"Sol OS\b.*?\b(d54f0a5|ADR-\d{3})\b", re.S)
HEADER_LINES = 10
# The team methodology (docs/policies/team-methodology.md, 2026-11-09): the roles the owner fixed
# (DEC-011, fourteen since 2026-11-09 13:30Z), each an
# agent definition under .claude/agents/, run by the workflow .claude/workflows/nawah-team.js, whose
# product is docs/PLAN-REVERSE.md. The method is enforced here so it cannot drift silently.
TEAM_DOC = "docs/policies/team-methodology.md"
TEAM_WORKFLOW = ".claude/workflows/nawah-team.js"
TEAM_PLAN = "docs/PLAN-REVERSE.md"
TEAM_ANSWER = "docs/PLAN-ANSWER.md"  # the team's execution answer to the plan (DEC-011 run)
TEAM_ENTRY = "CLAUDE.md"  # loaded by every session and sub-agent; it must point at the methodology
# DEC-011 (2026-11-09): fourteen roles — manager, assistant manager, 2 planners, 3 software
# engineers, 3 systems engineers, 3 cybersecurity engineers, 1 auditor.
TEAM_AGENTS = ["nawah-manager", "nawah-assistant-manager",
               "nawah-plan-ladder", "nawah-plan-chain",
               "nawah-sw-kernel", "nawah-sw-services", "nawah-sw-apps",
               "nawah-sys-lab", "nawah-sys-platform", "nawah-sys-release",
               "nawah-sec-threat", "nawah-sec-assurance", "nawah-sec-redteam",
               "nawah-auditor"]
AGENT_FIELDS = ("name:", "description:", "model:", "tools:")
SECTIONS = ["المدخلات والمخرجات", "الملكية", "الحالات والانتقالات", "الأخطاء", "عقد الأثر", "المهلات", "التوافق والإصدار", "اختبارات الإنفاذ"]

class M0Records(unittest.TestCase):
    def test_required_files_exist(self):
        missing = [f for f in REQUIRED if not (ROOT / f).exists()]
        self.assertEqual(missing, [])
    def test_boot_contract_sections(self):
        text = (ROOT / "docs/contracts/boot.md").read_text(encoding="utf-8")
        self.assertEqual([s for s in SECTIONS if s not in text], [])
    def test_adr_cites_e0_evidence(self):
        text = (ROOT / "docs/adr/0001-bootstrap.md").read_text(encoding="utf-8")
        self.assertIn("evidence/", text)
        for ev in [l.split("evidence/")[1].split(" ")[0].rstrip(")") for l in text.splitlines() if "evidence/" in l]:
            self.assertTrue((ROOT / "evidence" / ev.split("/")[0]).exists(), ev)
    def test_every_path_checks_out_on_windows(self):
        paths = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout.decode().split("\0")
        paths = [p for p in paths if p]
        self.assertTrue(paths)
        bad = [p for p in paths if any(WIN_RESERVED.match(c) or WIN_INVALID.search(c) or c.endswith((".", " ")) for c in p.split("/"))]
        self.assertEqual(bad, [])
        folded = {}
        for p in paths:
            folded.setdefault(p.lower(), []).append(p)
        self.assertEqual([v for v in folded.values() if len(v) > 1], [])

    def test_sol_os_ported_files_name_their_origin(self):
        missing = []
        for f in SOL_PORTED:
            head = "\n".join((ROOT / f).read_text(encoding="utf-8").splitlines()[:HEADER_LINES])
            if not SOL_ORIGIN.search(head):
                missing.append(f)
        self.assertEqual(missing, [], "ADR-0002 item 4: a ported file without its Sol OS origin line")

    def test_team_methodology_is_in_place(self):
        missing = [f for f in (TEAM_DOC, TEAM_WORKFLOW, TEAM_ENTRY, TEAM_PLAN, TEAM_ANSWER) if not (ROOT / f).exists()]
        self.assertEqual(missing, [], "team methodology files")
        workflow = (ROOT / TEAM_WORKFLOW).read_text(encoding="utf-8")
        self.assertTrue(workflow.startswith("export const meta = {"), "the workflow must open with its meta literal")
        self.assertIn("name: 'nawah-team'", workflow)
        bad = []
        for name in TEAM_AGENTS:
            f = ROOT / ".claude" / "agents" / f"{name}.md"
            if not f.exists():
                bad.append(f"{name}: missing"); continue
            text = f.read_text(encoding="utf-8")
            if not text.startswith("---\n"):
                bad.append(f"{name}: no frontmatter"); continue
            front = text.split("---\n", 2)[1]
            if f"name: {name}\n" not in front:
                bad.append(f"{name}: frontmatter name differs from the file name")
            bad += [f"{name}: {field} missing" for field in AGENT_FIELDS if field not in front]
        self.assertEqual(bad, [])
        doc = (ROOT / TEAM_DOC).read_text(encoding="utf-8")
        self.assertEqual([a for a in TEAM_AGENTS if a not in doc], [], "every role is named in the methodology")
        self.assertIn(TEAM_WORKFLOW, doc)
        self.assertIn(TEAM_PLAN, doc)
        self.assertIn(TEAM_DOC, (ROOT / TEAM_ENTRY).read_text(encoding="utf-8"), "CLAUDE.md points at the methodology")
        plan = (ROOT / TEAM_PLAN).read_text(encoding="utf-8")
        for heading in ("## 0.", "## 1.", "## 2.", "## 3.", "## 4.", "## 5.", "## 6."):
            self.assertIn(heading, plan, f"the reverse plan carries its section {heading}")
        self.assertIn("## 5.", plan)  # refuted and unverified claims are listed openly, never dropped
        answer = (ROOT / TEAM_ANSWER).read_text(encoding="utf-8")
        for heading in ("## 0.", "## 1.", "## 2.", "## 3.", "## 4.", "## 5.", "## 6.", "## 7."):
            self.assertIn(heading, answer, f"the plan answer carries its section {heading}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
