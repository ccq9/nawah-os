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

    # ---- WP-16 (ABI v1.2) programs. Convention: r14 = data page (USER_BASE + 0x40_0000,
    # 4 KiB RW), r15 = current step; a failed check exits with the step number so the test
    # kernel reports where the contract was broken. Numbers: 6 channel_create, 7 channel_write,
    # 8 channel_read, 9 handle_close, 10 handle_duplicate, 11 vmo_create, 12 handle_rights.

    .macro STEP n
    mov r15d, \n
    .endm
    .macro EXPECT val
    cmp rax, \val
    jne 9f
    .endm
    .macro SYSCALL6 nr, a1, a2, a3, a4, a5
    mov r10, \a4
    mov r8, \a5
    mov rdx, \a3
    mov rsi, \a2
    mov rdi, \a1
    mov eax, \nr
    syscall
    .endm

    # Message + VMO handle over a channel: bytes intact, handle consumed on the sender's side
    # and usable on the receiver's; empty queue -> ERR_SHOULD_WAIT; double close refused.
    # Exit 0x1C.
    .balign 16
    .global user_prog_ipc_roundtrip
    .global user_prog_ipc_roundtrip_end
user_prog_ipc_roundtrip:
    movabs r14, 0x8000400000
    STEP 1
    mov rdi, r14
    mov eax, 6
    syscall
    EXPECT 0
    mov r12d, dword ptr [r14]
    mov r13d, dword ptr [r14 + 4]
    STEP 2
    mov edi, 4096
    mov eax, 11
    syscall
    test rax, rax
    js 9f
    mov ebx, eax
    STEP 3
    movabs rax, 0x1122334455667788
    mov qword ptr [r14 + 16], rax
    movabs rax, 0x99aabbccddeeff00
    mov qword ptr [r14 + 24], rax
    mov dword ptr [r14 + 32], ebx
    lea rsi, [r14 + 16]
    lea r10, [r14 + 32]
    mov r8d, 1
    mov edx, 16
    mov edi, r12d
    mov eax, 7
    syscall
    EXPECT 0
    STEP 4
    xor r9d, r9d
    lea rsi, [r14 + 64]
    lea r10, [r14 + 128]
    mov r8d, 4
    mov edx, 64
    mov edi, r13d
    mov eax, 8
    syscall
    EXPECT 0x10010
    STEP 5
    mov rax, qword ptr [r14 + 64]
    movabs rcx, 0x1122334455667788
    cmp rax, rcx
    jne 9f
    mov rax, qword ptr [r14 + 72]
    movabs rcx, 0x99aabbccddeeff00
    cmp rax, rcx
    jne 9f
    STEP 6
    mov ebp, dword ptr [r14 + 128]
    test ebp, ebp
    jz 9f
    cmp ebp, ebx
    je 9f
    STEP 7
    mov edi, ebp
    mov eax, 12
    syscall
    EXPECT 0x1f
    STEP 8
    mov edi, ebx
    mov eax, 12
    syscall
    EXPECT -5
    STEP 9
    xor r9d, r9d
    lea rsi, [r14 + 64]
    lea r10, [r14 + 128]
    mov r8d, 4
    mov edx, 64
    mov edi, r13d
    mov eax, 8
    syscall
    EXPECT -8
    STEP 10
    mov edi, ebp
    mov eax, 9
    syscall
    EXPECT 0
    mov edi, ebp
    mov eax, 9
    syscall
    EXPECT -5
    mov edi, 0x1C
    mov eax, 0
    syscall
    ud2
9:  mov edi, r15d
    mov eax, 0
    syscall
    ud2
user_prog_ipc_roundtrip_end:

    # Rights: a READ-only duplicate cannot write, rights never escalate, a WRITE-only duplicate
    # cannot read, a handle without TRANSFER cannot be sent (and stays owned), undefined right
    # bits and sending a channel's own ends are ERR_INVALID. Exit 0x2D.
    .balign 16
    .global user_prog_rights_denied
    .global user_prog_rights_denied_end
user_prog_rights_denied:
    movabs r14, 0x8000400000
    STEP 1
    mov rdi, r14
    mov eax, 6
    syscall
    EXPECT 0
    mov r12d, dword ptr [r14]
    mov r13d, dword ptr [r14 + 4]
    STEP 2
    mov esi, 1
    mov edi, r12d
    mov eax, 10
    syscall
    test rax, rax
    js 9f
    mov ebx, eax
    STEP 3
    SYSCALL6 7, rbx, r14, 1, r14, 0
    EXPECT -6
    STEP 4
    mov esi, 3
    mov edi, ebx
    mov eax, 10
    syscall
    EXPECT -6
    STEP 5
    mov esi, 2
    mov edi, r12d
    mov eax, 10
    syscall
    test rax, rax
    js 9f
    mov ebp, eax
    xor r9d, r9d
    SYSCALL6 8, rbp, r14, 64, r14, 0
    EXPECT -6
    STEP 6
    mov edi, 4096
    mov eax, 11
    syscall
    test rax, rax
    js 9f
    mov dword ptr [r14 + 256], eax
    mov esi, 1
    mov edi, eax
    mov eax, 10
    syscall
    test rax, rax
    js 9f
    mov dword ptr [r14 + 260], eax
    lea rax, [r14 + 260]
    SYSCALL6 7, r12, r14, 8, rax, 1
    EXPECT -6
    mov edi, dword ptr [r14 + 260]
    mov eax, 12
    syscall
    EXPECT 1
    STEP 7
    mov esi, 0x40
    mov edi, r12d
    mov eax, 10
    syscall
    EXPECT -2
    STEP 8
    mov dword ptr [r14 + 264], r12d
    lea rax, [r14 + 264]
    SYSCALL6 7, r12, r14, 8, rax, 1
    EXPECT -2
    mov dword ptr [r14 + 264], r13d
    lea rax, [r14 + 264]
    SYSCALL6 7, r12, r14, 8, rax, 1
    EXPECT -2
    STEP 9
    xor esi, esi
    mov edi, r12d
    mov eax, 10
    syscall
    test rax, rax
    js 9f
    mov ebx, eax
    mov edi, ebx
    mov eax, 12
    syscall
    EXPECT 0
    xor r9d, r9d
    SYSCALL6 8, rbx, r14, 64, r14, 0
    EXPECT -6
    mov edi, 0x2D
    mov eax, 0
    syscall
    ud2
9:  mov edi, r15d
    mov eax, 0
    syscall
    ud2
user_prog_rights_denied_end:

    # Closed handles: every call on a closed handle is ERR_BAD_HANDLE; a message queued before
    # the close is still delivered, then the peer sees ERR_PEER_CLOSED both ways; a reused slot
    # carries a new generation. Exit 0x3E.
    .balign 16
    .global user_prog_closed_handle
    .global user_prog_closed_handle_end
user_prog_closed_handle:
    movabs r14, 0x8000400000
    STEP 1
    mov rdi, r14
    mov eax, 6
    syscall
    EXPECT 0
    mov r12d, dword ptr [r14]
    mov r13d, dword ptr [r14 + 4]
    STEP 2
    SYSCALL6 7, r12, r14, 4, r14, 0
    EXPECT 0
    STEP 3
    mov edi, r12d
    mov eax, 9
    syscall
    EXPECT 0
    STEP 4
    SYSCALL6 7, r12, r14, 4, r14, 0
    EXPECT -5
    xor r9d, r9d
    SYSCALL6 8, r12, r14, 64, r14, 0
    EXPECT -5
    mov esi, 1
    mov edi, r12d
    mov eax, 10
    syscall
    EXPECT -5
    mov edi, r12d
    mov eax, 9
    syscall
    EXPECT -5
    mov edi, r12d
    mov eax, 12
    syscall
    EXPECT -5
    STEP 5
    xor r9d, r9d
    lea rax, [r14 + 64]
    SYSCALL6 8, r13, rax, 64, r14, 0
    EXPECT 4
    STEP 6
    xor r9d, r9d
    lea rax, [r14 + 64]
    SYSCALL6 8, r13, rax, 64, r14, 0
    EXPECT -7
    SYSCALL6 7, r13, r14, 4, r14, 0
    EXPECT -7
    STEP 7
    lea rdi, [r14 + 8]
    mov eax, 6
    syscall
    EXPECT 0
    mov eax, dword ptr [r14 + 8]
    cmp eax, r12d
    je 9f
    mov ecx, eax
    xor ecx, r12d
    test ecx, 0xffff
    jnz 9f
    mov edi, 0x3E
    mov eax, 0
    syscall
    ud2
9:  mov edi, r15d
    mov eax, 0
    syscall
    ud2
user_prog_closed_handle_end:

    # Limits: 4097 bytes or 5 handles -> ERR_INVALID with nothing sent; exactly 4096 bytes go
    # through; a buffer one byte short -> ERR_BUFFER_TOO_SMALL with the message kept; a handle
    # capacity too small is refused the same way. Exit 0x4F.
    .balign 16
    .global user_prog_oversize
    .global user_prog_oversize_end
user_prog_oversize:
    movabs r14, 0x8000400000
    movabs r13, 0x8000000000
    STEP 1
    mov rdi, r14
    mov eax, 6
    syscall
    EXPECT 0
    mov r12d, dword ptr [r14]
    mov ebx, dword ptr [r14 + 4]
    STEP 2
    SYSCALL6 7, r12, r13, 4097, r14, 0
    EXPECT -2
    STEP 3
    SYSCALL6 7, r12, r13, 16, r14, 5
    EXPECT -2
    xor r9d, r9d
    SYSCALL6 8, rbx, r14, 4096, r14, 0
    EXPECT -8
    STEP 4
    SYSCALL6 7, r12, r13, 4096, r14, 0
    EXPECT 0
    STEP 5
    xor r9d, r9d
    SYSCALL6 8, rbx, r14, 4095, r14, 0
    EXPECT -9
    STEP 6
    xor r9d, r9d
    SYSCALL6 8, rbx, r14, 4096, r14, 0
    EXPECT 4096
    mov rax, qword ptr [r14]
    cmp rax, qword ptr [r13]
    jne 9f
    STEP 7
    xor r9d, r9d
    SYSCALL6 8, rbx, r14, 4096, r14, 0
    EXPECT -8
    STEP 8
    mov edi, 4096
    mov eax, 11
    syscall
    test rax, rax
    js 9f
    mov dword ptr [r14 + 8], eax
    lea rax, [r14 + 8]
    SYSCALL6 7, r12, r14, 0, rax, 1
    EXPECT 0
    xor r9d, r9d
    SYSCALL6 8, rbx, r14, 64, r14, 0
    EXPECT -9
    xor r9d, r9d
    lea rax, [r14 + 16]
    SYSCALL6 8, rbx, r14, 64, rax, 1
    EXPECT 0x10000
    mov edi, 0x4F
    mov eax, 0
    syscall
    ud2
9:  mov edi, r15d
    mov eax, 0
    syscall
    ud2
user_prog_oversize_end:

    # Leaves everything open: two channels, a 64 KiB VMO, messages in transit carrying a VMO
    # handle and a channel end (whose own queue carries the VMO's original handle). The test
    # kernel checks that exit frees it all. Exit 0x5A.
    .balign 16
    .global user_prog_ipc_no_leak
    .global user_prog_ipc_no_leak_end
user_prog_ipc_no_leak:
    movabs r14, 0x8000400000
    movabs r13, 0x8000000000
    STEP 1
    mov rdi, r14
    mov eax, 6
    syscall
    EXPECT 0
    lea rdi, [r14 + 8]
    mov eax, 6
    syscall
    EXPECT 0
    STEP 2
    mov edi, 65536
    mov eax, 11
    syscall
    test rax, rax
    js 9f
    mov dword ptr [r14 + 16], eax
    mov esi, 0x1f
    mov edi, eax
    mov eax, 10
    syscall
    test rax, rax
    js 9f
    mov dword ptr [r14 + 32], eax
    mov eax, dword ptr [r14 + 12]
    mov dword ptr [r14 + 36], eax
    STEP 3
    mov edi, dword ptr [r14]
    lea rax, [r14 + 32]
    SYSCALL6 7, rdi, r13, 100, rax, 2
    EXPECT 0
    mov edi, dword ptr [r14]
    SYSCALL6 7, rdi, r13, 4096, r14, 0
    EXPECT 0
    STEP 4
    mov edi, dword ptr [r14 + 8]
    lea rax, [r14 + 16]
    SYSCALL6 7, rdi, r13, 8, rax, 1
    EXPECT 0
    mov edi, 0x5A
    mov eax, 0
    syscall
    ud2
9:  mov edi, r15d
    mov eax, 0
    syscall
    ud2
user_prog_ipc_no_leak_end:

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

    # Isolation (WP-22, TST-M3-ISOLATION): reads the qword at the data page, writes its own
    # pattern there, sleeps 20 ticks (another process runs meanwhile, at the same virtual
    # address), reads the page back, and exits with (first read) | (page still holds the
    # pattern) << 63. A process must find a zeroed page and keep its own contents.
    .balign 16
    .global user_prog_isolation
    .global user_prog_isolation_end
user_prog_isolation:
    movabs r14, 0x8000400000
    mov r12, [r14]                 # first read: 0 for a fresh page
    movabs r13, 0x5A5A5A5A5A5A5A5A
    mov [r14], r13
    mov eax, 5                     # SYS_SLEEP
    mov edi, 20
    syscall
    mov rax, [r14]
    cmp rax, r13
    jne 1f
    movabs rax, 0x8000000000000000
    or r12, rax
1:  mov rdi, r12
    mov eax, 0                     # SYS_EXIT
    syscall
    ud2
user_prog_isolation_end:
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
    static user_prog_isolation: u8;
    static user_prog_isolation_end: u8;
    static user_prog_ipc_roundtrip: u8;
    static user_prog_ipc_roundtrip_end: u8;
    static user_prog_rights_denied: u8;
    static user_prog_rights_denied_end: u8;
    static user_prog_closed_handle: u8;
    static user_prog_closed_handle_end: u8;
    static user_prog_oversize: u8;
    static user_prog_oversize_end: u8;
    static user_prog_ipc_no_leak: u8;
    static user_prog_ipc_no_leak_end: u8;
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

/// Two of these at once prove address-space isolation (WP-22).
#[cfg(feature = "ktest")]
pub fn isolation() -> &'static [u8] {
    bytes(
        &raw const user_prog_isolation,
        &raw const user_prog_isolation_end,
    )
}

/// Channel round trip with a VMO handle; exit code 0x1C (else the failing step).
#[cfg(feature = "ktest")]
pub fn ipc_roundtrip() -> &'static [u8] {
    bytes(
        &raw const user_prog_ipc_roundtrip,
        &raw const user_prog_ipc_roundtrip_end,
    )
}

/// Rights checks; exit code 0x2D.
#[cfg(feature = "ktest")]
pub fn rights_denied() -> &'static [u8] {
    bytes(
        &raw const user_prog_rights_denied,
        &raw const user_prog_rights_denied_end,
    )
}

/// Closed handle and peer-closed semantics; exit code 0x3E.
#[cfg(feature = "ktest")]
pub fn closed_handle() -> &'static [u8] {
    bytes(
        &raw const user_prog_closed_handle,
        &raw const user_prog_closed_handle_end,
    )
}

/// Message and handle limits; exit code 0x4F.
#[cfg(feature = "ktest")]
pub fn oversize() -> &'static [u8] {
    bytes(
        &raw const user_prog_oversize,
        &raw const user_prog_oversize_end,
    )
}

/// Exits with channels, messages and a VMO still open; exit code 0x5A.
#[cfg(feature = "ktest")]
pub fn ipc_no_leak() -> &'static [u8] {
    bytes(
        &raw const user_prog_ipc_no_leak,
        &raw const user_prog_ipc_no_leak_end,
    )
}
