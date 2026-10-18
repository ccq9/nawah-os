//! Ending a lab run on QEMU `virt`: Arm semihosting SYS_EXIT (0x18) with the A64 parameter block
//! {ADP_Stopped_ApplicationExit = 0x20026, status}; QEMU exits with `status` when started with
//! `-semihosting-config enable=on,target=native` (QEMU semihosting/arm-compat-semi.c; Arm
//! "Semihosting for AArch32 and AArch64", §SYS_EXIT). Unlike isa-debug-exit the code is not
//! transformed, so the exit codes are the same numbers the x86_64 lab sees before shifting.

use core::arch::asm;

pub const EXIT_OK: u8 = 0x10;
pub const EXIT_PANIC: u8 = 0x11;
pub const EXIT_BOOT_FAIL: u8 = 0x30;

const SYS_EXIT: u32 = 0x18;
const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x20026;

/// Ends the emulation with `code`; halts if semihosting is not enabled.
pub fn exit(code: u8) -> ! {
    let block: [u64; 2] = [ADP_STOPPED_APPLICATION_EXIT, u64::from(code)];
    // SAFETY: the semihosting trap reads the two-word block at x1; without semihosting QEMU
    // raises an exception the firmware vectors catch — the halt below is never reached in the
    // lab and is the fallback elsewhere.
    unsafe {
        asm!("hlt #0xF000", in("w0") SYS_EXIT, in("x1") block.as_ptr(), options(nostack));
    }
    super::halt()
}
