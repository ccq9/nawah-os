#!/usr/bin/env python3
"""TST-M1-NOBS (REQ-M1-003): proof by construction that no Boot Services can be called after
ExitBootServices — the post-EBS code (kernel/) has no way to name or reach them."""
import re, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ["efi.h", "EFI_BOOT_SERVICES", "EFI_SYSTEM_TABLE", "SystemTable", "BootServices", "ConOut", "efi_main", "ExitBootServices", "AllocatePool", "GetMemoryMap"]

class NoBootServicesAfterEBS(unittest.TestCase):
    def kernel_sources(self):
        return list((ROOT / "kernel").rglob("*.c")) + list((ROOT / "kernel").rglob("*.h"))

    def test_kernel_has_sources(self):
        self.assertTrue(self.kernel_sources())

    def test_kernel_never_names_firmware(self):
        for f in self.kernel_sources():
            text = f.read_text(encoding="utf-8")
            code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)  # ignore comments
            hits = [w for w in FORBIDDEN if w in code]
            self.assertEqual(hits, [], f"{f}: {hits}")

    def test_kernel_entry_takes_bootinfo_only(self):
        text = (ROOT / "kernel/main.c").read_text(encoding="utf-8")
        self.assertRegex(text, r"void kernel_main\(const struct nawah_boot_info \*\w+\)")

    def test_bootinfo_has_no_function_pointers(self):
        text = (ROOT / "boot/common/bootinfo.h").read_text(encoding="utf-8")
        body = text[text.index("struct nawah_boot_info {"):text.index("};", text.index("struct nawah_boot_info {"))]
        self.assertNotIn("(*", body)
        self.assertNotIn("EFI_BOOT_SERVICES", text)

    def test_stub_drops_table_pointers_before_kernel(self):
        text = (ROOT / "boot/stub/main.c").read_text(encoding="utf-8")
        i = text.index("bs = 0; st = 0;"); j = text.index("kernel_main(bi);")
        self.assertLess(i, j)
        self.assertNotIn("bs->", text[i:j]); self.assertNotIn("st->", text[i:j])

if __name__ == "__main__":
    unittest.main(verbosity=2)
