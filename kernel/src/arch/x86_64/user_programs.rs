//! Ring-3 programs assembled into the kernel image and copied into a user code page by
//! `user::spawn` (WP-14/WP-15). Position-independent, no data references, ABI v1.x (SYSCALL:
//! rax number, rdi/rsi/rdx arguments, rax result). The boot self-check uses `PING`; the others
//! are test kernel programs. Each ends with SYS_EXIT (0) carrying its result in rdi.

use core::arch::global_asm;

global_asm!(
    r#"
    .text
    .balign 16
    .global user_prog_ping
    .global user_prog_ping_end
user_prog_ping:
    mov eax, 1              # SYS_PING
    mov edi, 0x1234
    syscall
    mov rdi, rax            # exit code = ping result (0x1235)
    mov eax, 0              # SYS_EXIT
    syscall
    ud2
user_prog_ping_end:

    # SYS_TRACE with an unmapped user pointer (ERR_FAULT) then with a kernel pointer (ERR_RANGE);
    # exit code = (first & 0xff) << 8 | (second & 0xff) = 0xfdfc.
    .balign 16
    .global user_prog_bad_ptr
    .global user_prog_bad_ptr_end
user_prog_bad_ptr:
    mov eax, 2              # SYS_TRACE
    movabs rdi, 0x8000100000   # USER_BASE + 1 MiB: user range, unmapped
    mov esi, 8
    syscall
    mov r12, rax
    mov eax, 2
    movabs rdi, 0xffff800000000000   # kernel direct map: outside the user range
    mov esi, 8
    syscall
    and r12, 0xff
    shl r12, 8
    and rax, 0xff
    or r12, rax
    mov rdi, r12
    mov eax, 0
    syscall
    ud2
user_prog_bad_ptr_end:

    # Reads kernel memory from ring 3: #PF with U/S set; the kernel ends the run.
    .balign 16
    .global user_prog_kernel_access
    .global user_prog_kernel_access_end
user_prog_kernel_access:
    movabs rax, 0xffff800000000000
    mov rax, qword ptr [rax]
    mov rdi, 0x77           # never reached
    mov eax, 0
    syscall
    ud2
user_prog_kernel_access_end:

    # Asks the kernel to accept a non-canonical instruction pointer: must be refused (ERR_RANGE),
    # never attempted with SYSRET. Exit code = the (negative) result as u64.
    .balign 16
    .global user_prog_bad_rip
    .global user_prog_bad_rip_end
user_prog_bad_rip:
    mov eax, 3              # SYS_CHECK_RIP
    movabs rdi, 0x8000000000000000
    syscall
    mov rdi, rax
    mov eax, 0
    syscall
    ud2
user_prog_bad_rip_end:

    # SYS_TRACE with a valid message, then exit with the returned length (13).
    .balign 16
    .global user_prog_trace
    .global user_prog_trace_end
user_prog_trace:
    lea rdi, [rip + 1f]
    mov esi, 13
    mov eax, 2
    syscall
    mov rdi, rax
    mov eax, 0
    syscall
    ud2
1:  .ascii "hello from r3"
user_prog_trace_end:

    # ABI v1.1: SYS_SLEEP(3 ticks) then SYS_YIELD; exit 0x51 when both returned 0, else 0x50.
    .balign 16
    .global user_prog_sleep
    .global user_prog_sleep_end
user_prog_sleep:
    mov eax, 5              # SYS_SLEEP
    mov edi, 3
    syscall
    mov r12, rax
    mov eax, 4              # SYS_YIELD
    syscall
    or r12, rax
    mov edi, 0x51
    test r12, r12
    jz 1f
    mov edi, 0x50
1:  mov eax, 0              # SYS_EXIT
    syscall
    ud2
user_prog_sleep_end:
"#
);

extern "C" {
    static user_prog_ping: u8;
    static user_prog_ping_end: u8;
}

#[cfg(feature = "ktest")]
extern "C" {
    static user_prog_bad_ptr: u8;
    static user_prog_bad_ptr_end: u8;
    static user_prog_kernel_access: u8;
    static user_prog_kernel_access_end: u8;
    static user_prog_bad_rip: u8;
    static user_prog_bad_rip_end: u8;
    static user_prog_trace: u8;
    static user_prog_trace_end: u8;
    static user_prog_sleep: u8;
    static user_prog_sleep_end: u8;
}

fn bytes(start: *const u8, end: *const u8) -> &'static [u8] {
    let len = end as usize - start as usize;
    // SAFETY: both labels are defined by the assembly above in the kernel's .text, start < end,
    // and the bytes between them are the program, which is never written.
    unsafe { core::slice::from_raw_parts(start, len) }
}

/// Ping round trip; exit code 0x1235.
pub fn ping() -> &'static [u8] {
    bytes(&raw const user_prog_ping, &raw const user_prog_ping_end)
}

/// Bad user pointers; exit code 0xfdfc.
#[cfg(feature = "ktest")]
pub fn bad_ptr() -> &'static [u8] {
    bytes(
        &raw const user_prog_bad_ptr,
        &raw const user_prog_bad_ptr_end,
    )
}

/// Kernel memory read from ring 3; ends by #PF (exit code USER_FAULT_EXIT_BASE | 14).
#[cfg(feature = "ktest")]
pub fn kernel_access() -> &'static [u8] {
    bytes(
        &raw const user_prog_kernel_access,
        &raw const user_prog_kernel_access_end,
    )
}

/// Non-canonical RIP refused; exit code ERR_RANGE as u64.
#[cfg(feature = "ktest")]
pub fn bad_rip() -> &'static [u8] {
    bytes(
        &raw const user_prog_bad_rip,
        &raw const user_prog_bad_rip_end,
    )
}

/// Valid trace; exit code 13.
#[cfg(feature = "ktest")]
pub fn trace() -> &'static [u8] {
    bytes(&raw const user_prog_trace, &raw const user_prog_trace_end)
}

/// Sleep then yield through the ABI v1.1 calls; exit code 0x51.
#[cfg(feature = "ktest")]
pub fn sleep() -> &'static [u8] {
    bytes(&raw const user_prog_sleep, &raw const user_prog_sleep_end)
}
