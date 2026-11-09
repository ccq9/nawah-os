#!/usr/bin/env python3
"""TST-M0-002: the M0 documents required by prompt 3.2 section 7 exist and the boot contract carries the sections of section 7 (inputs/outputs, ownership, states, errors, trace contract, timeouts, versioning, enforcement tests); every file ADR-0002 item 4 ports from Sol OS names its origin in its header."""
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

if __name__ == "__main__":
    unittest.main(verbosity=2)
