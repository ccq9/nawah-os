//! Ring 3 entry and exit on x86_64 (WP-14, ADR-0009): SYSCALL/SYSRET, the per-CPU block
//! reached through GS, the trap stack, user-memory access windows, and the executive's
//! "enter user / come back" pair that WP-15's scheduler generalises.
//!
//! References (Intel SDM, docs/sources.json S26): Vol. 3A §5.8.8 SYSCALL/SYSRET (CS/SS from
//! IA32_STAR, RIP from IA32_LSTAR, RFLAGS masked by IA32_FMASK, RCX/R11 carry RIP/RFLAGS);
//! Vol. 4 Table 2-2 (IA32_EFER bit 0 SCE, IA32_STAR C0000081H, IA32_LSTAR C0000082H,
//! IA32_FMASK C0000084H, IA32_GS_BASE C0000101H, IA32_KERNEL_GS_BASE C0000102H); Vol. 2B
//! SWAPGS; Vol. 3A §4.6 and §2.5 (CR4.SMEP bit 20, CR4.SMAP bit 21, STAC/CLAC); Vol. 2A CPUID
//! leaf 7 EBX bit 7 SMEP, bit 20 SMAP; §7.14.2 (an interrupt taken in ring 3 loads RSP from
//! TSS.RSP0).
//!
//! GS convention (as Linux): in kernel mode GS.base = this CPU's `PerCpu`; on the way to ring 3
//! `swapgs` parks it in IA32_KERNEL_GS_BASE and gives the user a zero base; the SYSCALL entry
//! swaps it back. Exception handlers never use GS, so they need no swap.

use core::arch::x86_64::__cpuid_count;
use core::arch::{asm, global_asm};

use super::gdt::{self, KERNEL_CODE_SELECTOR, SYSRET_SELECTOR_BASE};
use crate::cell::BootCell;

const IA32_EFER: u32 = 0xC000_0080;
const EFER_SCE: u64 = 1 << 0;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
/// C0000100H is IA32_FS_BASE; GS_BASE is the next one (SDM Vol. 4 Table 2-2).
const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
/// RFLAGS bits cleared on SYSCALL entry: CF(0) PF(2) AF(4) ZF(6) SF(7) TF(8) IF(9) DF(10)
/// OF(11) AC(18).
const FMASK: u64 = 0x4_0FD5;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
/// RFLAGS handed to ring 3 by `enter_user`: IF set, reserved bit 1 set.
const USER_RFLAGS: u64 = 0x202;

/// Per-CPU block, reached as GS:[offset] by the entry stub. Offsets are fixed by the assembly.
#[repr(C)]
pub struct PerCpu {
    /// +0: user RSP saved by the SYSCALL entry.
    pub user_rsp: u64,
    /// +8: top of the trap stack (SYSCALL entry; also TSS.RSP0 for ring-3 interrupts).
    pub kernel_rsp: u64,
    /// +16: the kernel's own RSP parked by `enter_user`, restored by `exit_to_kernel`.
    pub saved_kernel_rsp: u64,
    /// +24: CPU index.
    pub cpu_id: u64,
}

static PERCPU: BootCell<PerCpu> = BootCell::new(PerCpu {
    user_rsp: 0,
    kernel_rsp: 0,
    saved_kernel_rsp: 0,
    cpu_id: 0,
});

/// Registers as the entry stub leaves them on the trap stack (lowest address first).
#[repr(C)]
pub struct SyscallFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    /// Number in, result out.
    pub rax: u64,
    /// User RIP (from RCX).
    pub rip: u64,
    /// User RFLAGS (from R11).
    pub rflags: u64,
    pub user_rsp: u64,
}

const _: () = assert!(core::mem::size_of::<SyscallFrame>() == 16 * 8);

global_asm!(
    r#"
    .text
    .global syscall_entry
syscall_entry:
    swapgs
    mov gs:[0], rsp
    mov rsp, gs:[8]
    push qword ptr gs:[0]
    push r11
    push rcx
    push rax
    push rdi
    push rsi
    push rdx
    push r10
    push r8
    push r9
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    mov rbx, rsp
    and rsp, -16
    call {dispatch}
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r9
    pop r8
    pop r10
    pop rdx
    pop rsi
    pop rdi
    pop rax
    pop rcx
    pop r11
    mov rsp, [rsp]
    swapgs
    sysretq

    # enter_user(rip = rdi, rsp = rsi) -> u64: parks the callee-saved registers and RSP, then
    # drops to ring 3 with SYSRET. Returns (through exit_to_kernel) with the exit code in rax.
    .global enter_user
enter_user:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rip + {percpu} + 16], rsp
    mov rcx, rdi
    mov r11, {user_rflags}
    mov rsp, rsi
    swapgs
    sysretq

    # exit_to_kernel(code = rdi) -> !: back to enter_user's caller with rax = code.
    .global exit_to_kernel
exit_to_kernel:
    mov rsp, [rip + {percpu} + 16]
    mov rax, rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
"#,
    dispatch = sym dispatch_entry,
    percpu = sym PERCPU,
    user_rflags = const USER_RFLAGS,
);

extern "sysv64" {
    fn enter_user(rip: u64, rsp: u64) -> u64;
    fn exit_to_kernel(code: u64) -> !;
    static syscall_entry: u8;
}

/// Called by the entry stub with the frame; the arch-neutral dispatcher does the work.
extern "sysv64" fn dispatch_entry(frame: &mut SyscallFrame) {
    let args = [
        frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
    ];
    frame.rax = crate::syscall::dispatch(frame.rax, args) as u64;
}

/// Exit code of a ring-3 run ended by an exception: this base plus the vector (trap.rs).
pub const USER_FAULT_EXIT_BASE: u64 = super::trap::USER_FAULT_EXIT_BASE;

#[derive(Clone, Copy, Debug)]
pub struct SyscallInfo {
    pub smep: bool,
    pub smap: bool,
    pub lstar: u64,
}

static SMAP_ENABLED: BootCell<bool> = BootCell::new(false);

fn wrmsr(msr: u32, value: u64) {
    // SAFETY: wrmsr at CPL 0 of the architectural MSRs named by the callers.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nomem, nostack))
    };
}

fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdmsr at CPL 0 of an architectural MSR.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Programs SYSCALL/SYSRET, GS bases, TSS.RSP0 and (when the CPU has them) SMEP/SMAP.
/// `trap_stack_top`: a mapped kernel stack used by SYSCALL entry and by interrupts taken in
/// ring 3; it must not be the stack the caller is running on.
pub fn init(trap_stack_top: u64) -> SyscallInfo {
    let percpu = PERCPU.get();
    // SAFETY: boot path, single CPU (BootCell contract); the block is read by the entry stub
    // only after the MSRs below point at it.
    unsafe {
        (*percpu).kernel_rsp = trap_stack_top;
        (*percpu).cpu_id = u64::from(super::cpu_id());
    }
    gdt::set_rsp0(trap_stack_top);
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SCE);
    let star = (u64::from(SYSRET_SELECTOR_BASE) << 48) | (u64::from(KERNEL_CODE_SELECTOR) << 32);
    wrmsr(IA32_STAR, star);
    // Taking the address of the extern static is safe; it is never dereferenced.
    let lstar = &raw const syscall_entry as u64;
    wrmsr(IA32_LSTAR, lstar);
    wrmsr(IA32_FMASK, FMASK);
    wrmsr(IA32_GS_BASE, percpu as u64);
    wrmsr(IA32_KERNEL_GS_BASE, 0);
    // `__cpuid_count` is a safe intrinsic; leaf 7 exists when the maximum basic leaf reaches it.
    let (smep, smap) = if core::arch::x86_64::__cpuid(0).eax >= 7 {
        let ebx = __cpuid_count(7, 0).ebx;
        (ebx & (1 << 7) != 0, ebx & (1 << 20) != 0)
    } else {
        (false, false)
    };
    let mut cr4_bits = 0;
    if smep {
        cr4_bits |= CR4_SMEP;
    }
    if smap {
        cr4_bits |= CR4_SMAP;
    }
    if cr4_bits != 0 {
        // SAFETY: CR4 read-modify-write at CPL 0 setting only bits CPUID reported as supported.
        unsafe {
            asm!(
                "mov {t}, cr4",
                "or {t}, {bits}",
                "mov cr4, {t}",
                t = out(reg) _,
                bits = in(reg) cr4_bits,
                options(nomem, nostack),
            );
        }
    }
    // SAFETY: boot path write (BootCell contract).
    unsafe { SMAP_ENABLED.get().write(smap) };
    SyscallInfo { smep, smap, lstar }
}

/// Runs ring-3 code at `rip` with stack `rsp` in the active address space; returns the exit
/// code the program (or a fault on its behalf) ends with. Interrupts are enabled in ring 3 and
/// disabled again by the time this returns.
pub fn run_user(rip: u64, rsp: u64) -> u64 {
    // SAFETY: the caller mapped `rip`/`rsp` with USER in the active space and `init` ran; the
    // assembly parks this stack and comes back through exit_to_kernel.
    let code = unsafe { enter_user(rip, rsp) };
    super::interrupts::disable();
    code
}

/// Ends the current ring-3 run from a syscall handler (kernel mode, GS = PerCpu).
pub fn exit_user(code: u64) -> ! {
    // SAFETY: a ring-3 run is in progress (only syscall handlers call this), so enter_user's
    // frame is parked in PERCPU.
    unsafe { exit_to_kernel(code) }
}

/// Ends the current ring-3 run from an exception taken in ring 3 (GS still the user's: swap it
/// back first so the kernel convention holds again).
pub fn exit_user_from_fault(code: u64) -> ! {
    // SAFETY: called only for an exception whose saved CS has RPL 3, i.e. GS was not swapped
    // by the entry path; after swapgs the kernel block is current again.
    unsafe {
        asm!("swapgs", options(nomem, nostack));
        exit_to_kernel(code)
    }
}

/// Whether a value may be used as a ring-3 instruction pointer: canonical, inside the user
/// range. SYSRET to a non-canonical RCX raises #GP in ring 0 (SDM §5.8.8) and must never be
/// attempted.
pub fn user_rip_ok(rip: u64) -> bool {
    (crate::mm::addrspace::USER_BASE..crate::mm::addrspace::USER_END).contains(&rip)
}

/// Copies `dst.len()` bytes from the user address `src` (already range- and page-checked by
/// the caller) into `dst`, opening the SMAP window when SMAP is on.
pub fn copy_in(dst: &mut [u8], src: u64) {
    // SAFETY: the caller verified every page of [src, src+len) is present with USER in the
    // active space; STAC/CLAC are valid only with CR4.SMAP set, hence the flag.
    unsafe {
        let smap = *SMAP_ENABLED.get();
        if smap {
            asm!("stac", options(nomem, nostack));
        }
        core::ptr::copy_nonoverlapping(src as *const u8, dst.as_mut_ptr(), dst.len());
        if smap {
            asm!("clac", options(nomem, nostack));
        }
    }
}
