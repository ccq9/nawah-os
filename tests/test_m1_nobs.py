#!/usr/bin/env python3
"""TST-M1-NOBS (REQ-M1-003): proof by construction that no Boot Services can be called after
ExitBootServices — the post-EBS code (kmain) has no way to name or reach them, and the compiler
forbids it any unsafe code at all."""
import re, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
K = ROOT / "kernel/src"
FORBIDDEN = ["boot::", "efi", "SystemTable", "BootServices", "exit_boot_services", "get_memory_map", "unsafe"]

def code(path):  # strip comments so prose cannot trip the check
    return re.sub(r"//.*", "", (path).read_text(encoding="utf-8"))

class NoBootServicesAfterEBS(unittest.TestCase):
    def test_kmain_names_no_firmware_and_no_unsafe(self):
        text = code(K / "kmain.rs")
        self.assertEqual([w for w in FORBIDDEN if w in text], [])

    def test_main_does_not_allow_unsafe_in_kmain(self):
        text = (K / "main.rs").read_text(encoding="utf-8")
        self.assertIn("#![deny(unsafe_code)]", text)
        self.assertRegex(text, r"\n\nmod kmain;")  # no #[allow(unsafe_code)] attribute precedes it

    def test_kernel_entry_takes_bootinfo_only(self):
        self.assertRegex(code(K / "kmain.rs"), r"pub fn kernel_main\(\w+: &BootInfo\) -> !")

    def test_boot_efi_module_is_private(self):
        self.assertRegex(code(K / "boot/mod.rs"), r"(^|\n)mod efi;")
        self.assertNotIn("pub mod efi", code(K / "boot/mod.rs"))

    def test_bootinfo_has_no_function_pointers(self):
        text = code(K / "bootinfo.rs")
        body = text[text.index("pub struct BootInfo {"):text.index("}", text.index("pub struct BootInfo {"))]
        self.assertNotIn("fn(", body)
        self.assertNotIn("efi", body)

    def test_stub_keeps_tables_inside_one_block(self):
        text = code(K / "boot/stub.rs")
        i = text.index("let (final_size, accepted_key, desc_size, desc_ver, attempts, runtime_services) = {")
        j = text.index("crate::kmain::kernel_main(info)")
        end = re.search(r"\n    \};\n", text[i:]).end() + i  # closing of the 4-space-indented let-block
        tail = text[end:j]
        self.assertNotIn("bs.", tail); self.assertNotIn("st.", tail)

if __name__ == "__main__":
    unittest.main(verbosity=2)
