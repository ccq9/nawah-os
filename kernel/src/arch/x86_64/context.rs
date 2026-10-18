//! Kernel context switch and thread trampolines (WP-15, ADR-0010). A switch saves the callee-
//! saved registers of the System V ABI (rbx, rbp, r12-r15) and the stack pointer; everything
//! else is caller-saved and already spilled by the compiler around the call to `switch_to`.
//! A new thread's kernel stack is pre-built so that the first switch into it "returns" into a
//! trampoline with the entry point and argument in r12/r13.
//!
//! References: System V AMD64 ABI §3.2.1 (callee-saved registers), §3.2.2 (16-byte stack
//! alignment at a call); Intel SDM Vol. 3A §5.8.8 (SYSRET into ring 3 from the user trampoline),
//! Vol. 2B SWAPGS; Rust Reference, inline assembly, options (`nomem` lets the compiler cache
//! memory across the block — hence no `nomem` on sti/hlt/cli, which bracket interrupt handlers).

use core::arch::{asm, global_asm};

/// Body of a kernel thread: `entry(arg)`; the returned value is the thread's exit code.
pub type KernelEntry = extern "sysv64" fn(u64) -> u64;

global_asm!(
    r#"
    .text
    # switch_to(prev_rsp_slot = rdi, next_rsp = rsi)
    .global ctx_switch_to
ctx_switch_to:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

    # First code of a kernel thread: r12 = entry (KernelEntry), r13 = argument. Interrupts come
    # on here; the stack is aligned for the call; the return value ends the thread.
    .global ctx_kernel_thread_start
ctx_kernel_thread_start:
    and rsp, -16
    sti
    mov rdi, r13
    call r12
    mov rdi, rax
    call {exit}
    ud2

    # First code of a user thread: r12 = user rip, r13 = user rsp. The scheduler already pointed
    # the trap stack at this thread's kernel stack and made its address space current. RFLAGS
    # for ring 3: IF set (0x202); swapgs hands GS over to the user convention (ADR-0009).
    .global ctx_user_thread_start
ctx_user_thread_start:
    mov rcx, r12
    mov rsp, r13
    mov r11, 0x202
    swapgs
    sysretq
"#,
    exit = sym kernel_thread_exit,
);

extern "sysv64" {
    fn ctx_switch_to(prev_rsp_slot: *mut u64, next_rsp: u64);
    static ctx_kernel_thread_start: u8;
    static ctx_user_thread_start: u8;
}

/// Reached when a kernel thread's entry returns: its result is the exit code.
extern "sysv64" fn kernel_thread_exit(code: u64) -> ! {
    crate::sched::exit_current(code)
}

/// Saves the current context into `*prev_rsp_slot` and resumes the context whose stack pointer
/// is `next_rsp`. Returns when some other thread switches back to this one.
///
/// # Safety
/// `next_rsp` must be a stack pointer saved by an earlier `switch_to` or built by `prepare_stack`
/// on a mapped kernel stack nobody else runs on; `prev_rsp_slot` must stay valid until the
/// switch has written it; interrupts must be disabled; no lock or reference that another thread
/// could need may be held across the call.
pub unsafe fn switch_to(prev_rsp_slot: *mut u64, next_rsp: u64) {
    // SAFETY: as documented; the assembly follows the sysv64 ABI with its two arguments.
    unsafe { ctx_switch_to(prev_rsp_slot, next_rsp) }
}

/// Builds the initial frame on a fresh kernel stack ending at `top` (16-byte aligned) so that
/// `switch_to` into the returned stack pointer starts `kind` with `r12 = a`, `r13 = b`.
pub fn prepare_stack(top: u64, kind: Start, a: u64, b: u64) -> u64 {
    let tramp = match kind {
        // Taking the address of an extern static is safe; it is never dereferenced.
        Start::Kernel => &raw const ctx_kernel_thread_start as u64,
        Start::User => &raw const ctx_user_thread_start as u64,
    };
    // Frame (low to high): r15, r14, r13, r12, rbx, rbp, return address.
    let regs: [u64; 7] = [0, 0, b, a, 0, 0, tramp];
    let rsp = top - 8 * regs.len() as u64;
    // SAFETY: `top` is the end of a mapped kernel stack owned by the caller; the seven words
    // lie inside it.
    unsafe {
        let p = rsp as *mut u64;
        for (i, v) in regs.iter().enumerate() {
            p.add(i).write(*v);
        }
    }
    rsp
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Kernel,
    User,
}

/// Halts until the next interrupt with interrupts enabled (idle loop body), then puts IF back
/// the way the caller had it.
pub fn idle_wait() {
    let was = super::interrupts::enabled();
    // SAFETY: sti;hlt is the documented idle idiom (the interrupt shadow makes hlt wait for the
    // first interrupt after enabling). Handlers run in between and change memory, so the block
    // is a full compiler barrier (no `nomem`).
    unsafe { asm!("sti", "hlt", options(nostack)) };
    if !was {
        super::interrupts::disable();
    }
}
