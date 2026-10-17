#!/usr/bin/env python3
"""TST-M0-002: the M0 documents required by prompt 3.2 section 7 exist and the boot contract carries the sections of section 7 (inputs/outputs, ownership, states, errors, trace contract, timeouts, versioning, enforcement tests)."""
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ["docs/ENVIRONMENT.md", "docs/PROJECT.md", "docs/requirements.json", "docs/stages.json", "docs/work-items.json",
            "docs/tests.json", "docs/adr/0001-bootstrap.md", "docs/contracts/boot.md", "docs/security/threat-model.md",
            "docs/risks.json", "docs/reference/windows10.json", "docs/hardware.json", "docs/sources.json",
            "docs/project-state.json", "docs/automation.json", "docs/schemas/requirements.schema.json",
            "docs/prompt-errata.md", "docs/decisions-pending.json", "evidence/automation/events.jsonl", "tools/project.py"]
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

if __name__ == "__main__":
    unittest.main(verbosity=2)
