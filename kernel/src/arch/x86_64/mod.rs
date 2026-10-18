//! x86_64.

use core::arch::asm;
use core::arch::x86_64::__cpuid;

use crate::bootinfo::BootInfo;

pub mod acpi;
pub mod apic;
mod gdt;
mod idt;
pub mod ioapic;
pub mod irq;
pub mod paging;
mod pic;
pub mod pit;
mod port;
pub mod qemu;
mod serial;
mod trap;

#[cfg(feature = "ktest")]
pub mod fwcfg;
#[cfg(feature = "ktest")]
pub mod ktest;

pub use serial::Serial;

/// CPUID.01H:EDX bit 7: the CPU supports the machine-check exception (SDM Vol. 3B §18.8).
const CPUID_EDX_MCE: u32 = 1 << 7;
/// CR4 bit 6: machine-check enable (SDM Vol. 3A §2.5).
const CR4_MCE: u64 = 1 << 6;

/// Initialises the diagnostic channel (COM1).
pub fn init_console() {
    Serial::init();
}

/// Loads the kernel's own CPU tables: GDT and TSS, then IDT, then enables #MC.
/// After this, a CPU exception is a printed diagnostic instead of a silent reset.
/// Called once, early in the kernel, with interrupts disabled. Prints nothing.
pub fn init_cpu() {
    gdt::init();
    idt::init();
    enable_machine_check();
}

/// Without CR4.MCE the CPU enters shutdown on a hardware error instead of raising #MC
/// (SDM Vol. 3A "Event 18"). Only the bit is set; full MCA bank initialisation is deferred.
fn enable_machine_check() {
    // `__cpuid` is a safe intrinsic on x86_64 (leaf 1 exists on every x86-64 CPU).
    let features = __cpuid(1);
    if features.edx & CPUID_EDX_MCE == 0 {
        return;
    }
    // SAFETY: the CPU reports MCE, so CR4 bit 6 is not reserved. Only that bit changes, and the
    // #MC gate (vector 18) is loaded before this point.
    unsafe {
        asm!(
            "mov {tmp}, cr4",
            "or {tmp}, {mce}",
            "mov cr4, {tmp}",
            tmp = out(reg) _,
            mce = in(reg) CR4_MCE,
            options(nomem, nostack),
        );
    }
}

/// Switches to the kernel-owned stack and jumps to `entry(arg)`, never returning. Used once by
/// the boot stub after ExitBootServices so the kernel no longer runs on firmware memory.
///
/// # Safety
/// `entry` must never return; `arg` must stay valid for the kernel's lifetime.
pub unsafe fn jump_on_kernel_stack(entry: extern "sysv64" fn(*const u8) -> !, arg: *const u8) -> ! {
    // Entry alignment: RSP == top - 8 mimics the state after a `call` (16-byte aligned before it).
    let rsp = gdt::kernel_stack_top() - 8;
    // SAFETY: the kernel stack is a static owned by the kernel; nothing else uses it; the jump
    // target follows the sysv64 ABI with `arg` in rdi and never returns.
    unsafe {
        asm!(
            "mov rsp, {rsp}",
            "xor ebp, ebp",
            "jmp {entry}",
            rsp = in(reg) rsp,
            entry = in(reg) entry,
            in("rdi") arg,
            options(noreturn),
        );
    }
}

/// Adopts the stacks the VMM mapped with guard pages (`(base, size)` each): the double-fault
/// gate's IST1 points at the new emergency stack from now on, and exception diagnostics name
/// both stacks. Called once, before `continue_on_stack`.
pub fn adopt_stacks(kernel: (u64, u64), df: (u64, u64)) {
    gdt::adopt_stacks(kernel, df);
}

/// Moves to `stack_top` and jumps to `entry(bi)`, never returning. Used once after the kernel
/// address space is active, so the rest of the kernel runs on a guarded stack.
pub fn continue_on_stack<'a>(
    stack_top: u64,
    entry: extern "sysv64" fn(&'a BootInfo) -> !,
    bi: &'a BootInfo,
) -> ! {
    // Entry alignment: RSP == top - 8 mimics the state after a `call` (16-byte aligned before it).
    let rsp = (stack_top & !0xF) - 8;
    // SAFETY: the caller hands over a mapped, unused stack; the jump target follows the sysv64
    // ABI with `bi` in rdi and never returns, so nothing on the old stack is needed again.
    unsafe {
        asm!(
            "mov rsp, {rsp}",
            "xor ebp, ebp",
            "jmp {entry}",
            rsp = in(reg) rsp,
            entry = in(reg) entry,
            in("rdi") bi as *const BootInfo,
            options(noreturn),
        );
    }
}

/// Interrupt flag control. Enabling is safe once `irq::init` has run: every vector has a gate
/// and a counting handler, so no interrupt can fault the kernel.
pub mod interrupts {
    use core::arch::asm;

    pub fn enable() {
        // SAFETY: sti; the IDT covers all 256 vectors (idt::init) and the dispatcher counts
        // unexpected ones.
        unsafe { asm!("sti", options(nomem, nostack)) };
    }

    pub fn disable() {
        // SAFETY: cli only clears IF.
        unsafe { asm!("cli", options(nomem, nostack)) };
    }

    /// RFLAGS.IF.
    pub fn enabled() -> bool {
        let flags: u64;
        // SAFETY: pushfq/pop into a register; no memory beyond the stack slot is touched.
        unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags)) };
        flags & (1 << 9) != 0
    }
}

/// Stops the CPU for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: cli then hlt touch neither memory nor the stack; stopping the CPU is the point.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
