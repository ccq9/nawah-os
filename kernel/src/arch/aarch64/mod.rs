//! AArch64 (WP-21, ADR-0008): the early port experiment. Enough of the architecture interface
//! to build the same single UEFI image for `aarch64-unknown-uefi`, boot it on QEMU `virt` under
//! AAVMF (EDK2), leave boot services and print the kernel's post-EBS trace. No exception
//! vectors, no paging changes, no interrupt controller yet: the firmware's MMU tables and VBAR
//! stay in place, which is recorded as an assumption, not a result.

use core::arch::asm;

use crate::cell::BootCell;

pub mod qemu;
mod serial;

pub use serial::Serial;

/// Interrupt masking through DAIF (Arm ARM D13.2.42 / C5.2.2: bit 7 I masks IRQ).
pub mod interrupts {
    use core::arch::asm;

    const DAIF_I: u64 = 1 << 7;

    pub fn enable() {
        // SAFETY: clears the IRQ mask bit only; no handler is installed in the experiment, but
        // the firmware's vectors remain and nothing routes interrupts to the core.
        unsafe { asm!("msr daifclr, #2", options(nomem, nostack)) };
    }

    pub fn disable() {
        // SAFETY: sets the IRQ mask bit only.
        unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
    }

    pub fn enabled() -> bool {
        let daif: u64;
        // SAFETY: reading DAIF has no side effects.
        unsafe { asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack, preserves_flags)) };
        daif & DAIF_I == 0
    }

    pub fn save_and_disable() -> bool {
        let was = enabled();
        disable();
        was
    }

    pub fn restore(was_enabled: bool) {
        if was_enabled {
            enable();
        }
    }
}

/// One core in the experiment.
pub fn cpu_id() -> u32 {
    0
}

pub fn init_console() {
    Serial::init();
}

/// Current exception level (CurrentEL bits 3:2), for the trace.
pub fn current_el() -> u64 {
    let v: u64;
    // SAFETY: reading CurrentEL has no side effects.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) v, options(nomem, nostack, preserves_flags)) };
    (v >> 2) & 0b11
}

/// Nothing is installed yet: the experiment keeps the firmware's VBAR and MMU state. Returns the
/// description the boot trace prints.
pub fn init_cpu() -> &'static str {
    "vbar=firmware|mmu=firmware|stack=kernel"
}

pub const KERNEL_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
pub struct Stack<const N: usize>(pub [u8; N]);

static KERNEL_STACK: BootCell<Stack<KERNEL_STACK_SIZE>> =
    BootCell::new(Stack([0; KERNEL_STACK_SIZE]));

/// Switches to the kernel-owned stack and jumps to `entry(arg)`, never returning.
///
/// # Safety
/// `entry` must never return; `arg` must stay valid for the kernel's lifetime.
pub unsafe fn jump_on_kernel_stack(entry: extern "C" fn(*const u8) -> !, arg: *const u8) -> ! {
    let top = KERNEL_STACK.get() as u64 + KERNEL_STACK_SIZE as u64;
    // SAFETY: the stack is a static owned by the kernel; the target follows the AAPCS64 with the
    // argument in x0 and never returns.
    unsafe {
        asm!(
            "mov sp, {top}",
            "mov x0, {arg}",
            "br {entry}",
            top = in(reg) top,
            arg = in(reg) arg,
            entry = in(reg) entry,
            options(noreturn),
        );
    }
}

/// Stops the core for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: masks all exceptions and waits; stopping is the point.
        unsafe { asm!("msr daifset, #0xf", "wfi", options(nomem, nostack)) };
    }
}
