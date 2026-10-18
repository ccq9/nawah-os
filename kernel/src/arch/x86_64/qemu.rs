//! QEMU `isa-debug-exit` (lab only): the host sees exit status `(value << 1) | 1`
//! (QEMU hw/misc/debugexit.c, verified 2026-10-18). The lab passes iobase=0xf4,iosize=4.
//! Origin: Sol OS (d54f0a5) `qemu.rs`, codes re-assigned for nawah-os.

use super::port::outb;

const DEBUG_EXIT_PORT: u16 = 0xF4;

/// Success (QEMU exit 33).
pub const EXIT_OK: u8 = 0x10;
/// Kernel panic (QEMU exit 35).
pub const EXIT_PANIC: u8 = 0x11;
/// Boot handoff failure (QEMU exit 97) — docs/contracts/boot.md.
pub const EXIT_BOOT_FAIL: u8 = 0x30;
// Reserved (added with the test kernel in M2): 0x12 test failed, 0x13 unknown test,
// 0x48 + vector for a fatal exception (QEMU exit 145 + 2v, 145..207 — away from `timeout`
// codes 124..127/137 and common signal codes).

/// Ends the emulation with `code`; halts if the device is absent.
pub fn exit(code: u8) -> ! {
    // SAFETY: port 0xF4 belongs to isa-debug-exit which the lab adds to QEMU; writing to it ends
    // the emulation and touches no other device.
    unsafe { outb(DEBUG_EXIT_PORT, code) };
    super::halt()
}
