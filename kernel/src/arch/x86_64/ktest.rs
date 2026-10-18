//! Deliberate CPU fault injection for the exception path. Test kernel only.
//! Origin: Sol OS (d54f0a5) `arch/x86_64/ktest.rs`, adapted (identity-mapped UEFI environment:
//! fault addresses are chosen beyond the physical address space; `extern "sysv64"` on the one
//! function that returns a value in RAX so the host-side oracle reasoning is ABI-independent).
//!
//! Each small assembly function exports a label on the instruction the saved RIP must point at;
//! the test prints that address as `expect_rip=` and the exception handler prints `rip=`, and
//! the host oracle checks they are equal.

use core::arch::{asm, global_asm};
use core::sync::atomic::Ordering;

use super::gdt::{TablePointer, DOUBLE_FAULT_IST, KERNEL_CODE_SELECTOR};
use super::idt::INTERRUPT_GATE;
use super::trap::{EXCEPTION_VECTORS, KTEST_FAULT_IN_HANDLER};
use crate::cell::BootCell;

/// Canonical address far above any physical memory the lab maps (512 MiB RAM, 4-level paging):
/// writing to it gives #PF with error code 2 (not present, write, supervisor: SDM Fig. 7-11).
pub const PF_TEST_ADDR: u64 = 0x0000_6000_0000_1000;
/// Corrupt (unmapped) RSP for the double-fault test.
pub const DF_TEST_BAD_RSP: u64 = 0x0000_6000_0000_2000;

global_asm!(
    r#"
    .text

    .global ktest_trigger_de
    .global ktest_de_insn
ktest_trigger_de:
    xor edx, edx
    mov eax, 1
    xor ecx, ecx
ktest_de_insn:
    div ecx
    ret

    .global ktest_trigger_ud
    .global ktest_ud_insn
ktest_trigger_ud:
ktest_ud_insn:
    ud2
    ret

    # #DB by single-step: set TF (RFLAGS bit 8) with popfq; the CPU raises #DB after the next
    # instruction (nop). It is a trap, so the saved RIP points past the nop (SDM "Event 1").
    .global ktest_trigger_db
    .global ktest_db_after
ktest_trigger_db:
    pushfq
    or qword ptr [rsp], 0x100
    popfq
    nop
ktest_db_after:
    ret

    .global ktest_trigger_bp
    .global ktest_bp_after
ktest_trigger_bp:
    int3
ktest_bp_after:
    ret

    # Loads the 15 registers with known patterns, sets CF and DF, executes int3 and checks after
    # the return that every register and both flags are back. Returns 0 on success, 1 otherwise.
    .global ktest_bp_preserves_state
ktest_bp_preserves_state:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rax, qword ptr [rip + ktest_reg_patterns]
    mov rbx, qword ptr [rip + ktest_reg_patterns + 8]
    mov rcx, qword ptr [rip + ktest_reg_patterns + 16]
    mov rdx, qword ptr [rip + ktest_reg_patterns + 24]
    mov rsi, qword ptr [rip + ktest_reg_patterns + 32]
    mov rdi, qword ptr [rip + ktest_reg_patterns + 40]
    mov rbp, qword ptr [rip + ktest_reg_patterns + 48]
    mov r8, qword ptr [rip + ktest_reg_patterns + 56]
    mov r9, qword ptr [rip + ktest_reg_patterns + 64]
    mov r10, qword ptr [rip + ktest_reg_patterns + 72]
    mov r11, qword ptr [rip + ktest_reg_patterns + 80]
    mov r12, qword ptr [rip + ktest_reg_patterns + 88]
    mov r13, qword ptr [rip + ktest_reg_patterns + 96]
    mov r14, qword ptr [rip + ktest_reg_patterns + 104]
    mov r15, qword ptr [rip + ktest_reg_patterns + 112]
    std
    stc
    int3
    pushfq
    cld
    cmp rax, qword ptr [rip + ktest_reg_patterns]
    jne 7f
    cmp rbx, qword ptr [rip + ktest_reg_patterns + 8]
    jne 7f
    cmp rcx, qword ptr [rip + ktest_reg_patterns + 16]
    jne 7f
    cmp rdx, qword ptr [rip + ktest_reg_patterns + 24]
    jne 7f
    cmp rsi, qword ptr [rip + ktest_reg_patterns + 32]
    jne 7f
    cmp rdi, qword ptr [rip + ktest_reg_patterns + 40]
    jne 7f
    cmp rbp, qword ptr [rip + ktest_reg_patterns + 48]
    jne 7f
    cmp r8, qword ptr [rip + ktest_reg_patterns + 56]
    jne 7f
    cmp r9, qword ptr [rip + ktest_reg_patterns + 64]
    jne 7f
    cmp r10, qword ptr [rip + ktest_reg_patterns + 72]
    jne 7f
    cmp r11, qword ptr [rip + ktest_reg_patterns + 80]
    jne 7f
    cmp r12, qword ptr [rip + ktest_reg_patterns + 88]
    jne 7f
    cmp r13, qword ptr [rip + ktest_reg_patterns + 96]
    jne 7f
    cmp r14, qword ptr [rip + ktest_reg_patterns + 104]
    jne 7f
    cmp r15, qword ptr [rip + ktest_reg_patterns + 112]
    jne 7f
    pop rax
    and eax, 0x401
    cmp eax, 0x401
    jne 6f
    xor eax, eax
    jmp 8f
7:  add rsp, 8
6:  mov eax, 1
8:  pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

    .global ktest_trigger_gp
    .global ktest_gp_insn
ktest_trigger_gp:
    movabs rax, 0x8000000000000000
ktest_gp_insn:
    mov rax, qword ptr [rax]
    ret

    .global ktest_trigger_pf
    .global ktest_pf_insn
ktest_trigger_pf:
    movabs rax, {pf_addr}
ktest_pf_insn:
    mov qword ptr [rax], 0
    ret

    # Writes 0 to the address in rdi (used against read-only pages once WP-09 maps them).
    .global ktest_trigger_write
    .global ktest_write_insn
ktest_trigger_write:
ktest_write_insn:
    mov qword ptr [rdi], 0
    ret

    .global ktest_trigger_df
ktest_trigger_df:
    movabs rsp, {bad_rsp}
    push rax
    ud2

    .global ktest_trigger_triple
ktest_trigger_triple:
    sub rsp, 16
    mov word ptr [rsp], 0
    mov qword ptr [rsp + 2], 0
    lidt [rsp]
    ud2

    # Pushes until the stack runs into its guard page. The #PF frame cannot be pushed there
    # either, so the CPU raises #DF (SDM Table 7-5), delivered on the IST1 stack.
    .global ktest_trigger_stack_overflow
ktest_trigger_stack_overflow:
    push rax
    jmp ktest_trigger_stack_overflow

    .balign 8
ktest_reg_patterns:
    .quad 0x1111111111111111
    .quad 0x2222222222222222
    .quad 0x3333333333333333
    .quad 0x4444444444444444
    .quad 0x5555555555555555
    .quad 0x6666666666666666
    .quad 0x7777777777777777
    .quad 0x8888888888888888
    .quad 0x9999999999999999
    .quad 0xaaaaaaaaaaaaaaaa
    .quad 0xbbbbbbbbbbbbbbbb
    .quad 0xcccccccccccccccc
    .quad 0xdddddddddddddddd
    .quad 0xeeeeeeeeeeeeeeee
    .quad 0xf0f0f0f0f0f0f0f0
"#,
    pf_addr = const PF_TEST_ADDR,
    bad_rsp = const DF_TEST_BAD_RSP,
);

extern "sysv64" {
    fn ktest_trigger_de();
    fn ktest_trigger_ud();
    fn ktest_trigger_bp();
    fn ktest_bp_preserves_state() -> u64;
    fn ktest_trigger_gp();
    fn ktest_trigger_pf();
    fn ktest_trigger_write(address: u64);
    fn ktest_trigger_df() -> !;
    fn ktest_trigger_db();
    fn ktest_trigger_triple() -> !;
    fn ktest_trigger_stack_overflow() -> !;
    static ktest_de_insn: u8;
    static ktest_ud_insn: u8;
    static ktest_db_after: u8;
    static ktest_bp_after: u8;
    static ktest_gp_insn: u8;
    static ktest_pf_insn: u8;
    static ktest_write_insn: u8;
}

/// Address the saved RIP must show for each fault (the label on the faulting instruction, or
/// the instruction after it for traps).
pub fn expected_rip(which: &str) -> u64 {
    // Taking the address of an extern static is safe; it is never dereferenced.
    match which {
        "de" => &raw const ktest_de_insn as u64,
        "ud" => &raw const ktest_ud_insn as u64,
        "db" => &raw const ktest_db_after as u64,
        "bp" => &raw const ktest_bp_after as u64,
        "gp" => &raw const ktest_gp_insn as u64,
        "pf" => &raw const ktest_pf_insn as u64,
        "write" => &raw const ktest_write_insn as u64,
        _ => 0,
    }
}

/// #DE: integer division by zero.
pub fn divide_error() {
    // SAFETY: the assembly function above follows the ABI and clobbers only caller-saved
    // registers; the exception it raises is intended and caught by the loaded IDT.
    unsafe { ktest_trigger_de() }
}

/// #UD: ud2.
pub fn invalid_opcode() {
    // SAFETY: as in divide_error.
    unsafe { ktest_trigger_ud() }
}

/// #DB: single-step with the trap flag. Kernel policy makes #DB fatal; no return expected.
pub fn debug_exception() {
    // SAFETY: as in divide_error.
    unsafe { ktest_trigger_db() }
}

/// #BP: int3; returns once the handler returns.
pub fn breakpoint() {
    // SAFETY: as in divide_error; the CPU resumes at the next instruction (ret).
    unsafe { ktest_trigger_bp() }
}

/// Checks that returning from #BP restores the 15 registers and the CF/DF flags.
pub fn breakpoint_preserves_state() -> bool {
    // SAFETY: the assembly function follows the ABI (saves and restores callee-saved registers,
    // clears DF before returning).
    unsafe { ktest_bp_preserves_state() == 0 }
}

/// #GP: load from a non-canonical address.
pub fn general_protection() {
    // SAFETY: as in divide_error; the load never happens because the CPU rejects the address.
    unsafe { ktest_trigger_gp() }
}

/// #PF: store to an unmapped address.
pub fn page_fault() {
    // SAFETY: as in divide_error; the store never happens because the page is not present.
    unsafe { ktest_trigger_pf() }
}

/// Stores 0 at `address`; the caller picks an address whose page rejects writes (vmm_wp).
pub fn write_fault(address: u64) {
    // SAFETY: as in divide_error; with CR0.WP the store never happens because the page is
    // read-only, and the #PF is caught by the loaded IDT.
    unsafe { ktest_trigger_write(address) }
}

/// Sixteen `ret` instructions in writable data: a static with interior mutability lands in
/// .data, which the kernel address space maps RW + NX (vmm_nx).
static DATA_CODE: BootCell<[u8; 16]> = BootCell::new([0xC3; 16]);

pub fn data_code_address() -> u64 {
    DATA_CODE.get() as u64
}

/// Calls into `DATA_CODE`: under EFER.NXE the instruction fetch faults (#PF, error code bit 4);
/// without NX the `ret` would simply return.
pub fn execute_from_data() {
    // SAFETY: a direct call to writable data; the fault is intended and caught by the loaded
    // IDT. clobber_abi marks every caller-saved register as clobbered in case it returned.
    unsafe {
        asm!("call {}", in(reg) data_code_address(), clobber_abi("sysv64"));
    }
}

/// Overflows the current stack by pushing until the guard page stops it (vmm_guard).
pub fn stack_overflow() -> ! {
    // SAFETY: overflowing the stack is the point; the #DF handler ends the run on IST1.
    unsafe { ktest_trigger_stack_overflow() }
}

/// Makes the exception handler raise #UD on every entry, then raises the first exception. The
/// expected outcome is the nesting limit, not an infinite loop.
pub fn nested_fault() {
    KTEST_FAULT_IN_HANDLER.store(true, Ordering::Relaxed);
    invalid_opcode();
}

/// Vectors with an error code, listed independently of trap.rs (SDM Table 7-1 plus AMD 29/30)
/// so that this check catches a divergence between the two lists.
const ERROR_CODE_VECTORS: [usize; 10] = [8, 10, 11, 12, 13, 14, 17, 21, 29, 30];

/// Walks the IDT the CPU actually has (via `sidt`, not the kernel's variables) gate by gate:
/// 0..=31 are present interrupt gates whose code pushes the same vector number, with a dummy 0
/// before it exactly when the CPU pushes no error code; 32..=255 are empty. Returns the number of
/// mismatches (each printed).
pub fn idt_layout_mismatches() -> u32 {
    let mut pointer = TablePointer { limit: 0, base: 0 };
    // SAFETY: sidt writes 10 bytes into the local struct; allowed at CPL 0.
    unsafe {
        asm!("sidt [{}]", in(reg) &raw mut pointer, options(nostack, preserves_flags));
    }
    let (limit, base) = (pointer.limit, pointer.base);

    let mut mismatches = 0;
    let mut report = |vector: usize, what: &str| {
        kprintln!(
            "OSX|{}|ktest|idt_layout|vector={}|mismatch={}",
            crate::BUILD_ID,
            vector,
            what
        );
        mismatches += 1;
    };

    if usize::from(limit) != 256 * 16 - 1 {
        report(0, "limit_not_256_gates");
        return mismatches;
    }

    for vector in 0..256usize {
        // SAFETY: the IDTR limit covers 256 gates of 16 bytes in mapped kernel memory; unaligned
        // read as a precaution.
        let gate = unsafe { (base as *const [u8; 16]).add(vector).read_unaligned() };

        if vector >= EXCEPTION_VECTORS {
            if gate != [0; 16] {
                report(vector, "gate_above_31_not_empty");
            }
            continue;
        }

        let selector = u16::from_le_bytes([gate[2], gate[3]]);
        let ist = gate[4];
        let type_attr = gate[5];
        let target = u64::from(u16::from_le_bytes([gate[0], gate[1]]))
            | u64::from(u16::from_le_bytes([gate[6], gate[7]])) << 16
            | u64::from(u32::from_le_bytes([gate[8], gate[9], gate[10], gate[11]])) << 32;
        let reserved = u32::from_le_bytes([gate[12], gate[13], gate[14], gate[15]]);

        if selector != KERNEL_CODE_SELECTOR {
            report(vector, "wrong_code_selector");
        }
        if type_attr != INTERRUPT_GATE {
            report(vector, "not_present_64bit_interrupt_gate");
        }
        if ist != if vector == 8 { DOUBLE_FAULT_IST } else { 0 } {
            report(vector, "wrong_ist");
        }
        if reserved != 0 {
            report(vector, "reserved_not_zero");
        }

        // SAFETY: the target of a present gate is mapped kernel code; we read its first 4 bytes.
        let code = unsafe { (target as *const [u8; 4]).read_unaligned() };
        // `push imm8` encodes as 6A nn. No-error-code entry: 6A 00 6A nn. Error-code entry: 6A nn.
        let (pushes_dummy, pushed) = if code[0] == 0x6A && code[1] == 0 && code[2] == 0x6A {
            (true, usize::from(code[3]))
        } else if code[0] == 0x6A {
            (false, usize::from(code[1]))
        } else {
            report(vector, "stub_not_push_imm8");
            continue;
        };
        if pushed != vector {
            report(vector, "stub_pushes_other_vector");
        }
        if pushes_dummy == ERROR_CODE_VECTORS.contains(&vector) {
            report(vector, "dummy_error_code_mismatch");
        }
    }

    mismatches
}

/// #DF: corrupt RSP then push. The page fault cannot be delivered on the corrupt stack, so it
/// becomes a double fault delivered on the IST stack (SDM Table 7-5).
pub fn double_fault() -> ! {
    // SAFETY: corrupting the stack is the point; the #DF handler ends the run.
    unsafe { ktest_trigger_df() }
}

/// Deliberate triple fault: load an empty IDT, then fault. Proves the host runner detects a
/// reset, not a kernel property.
pub fn triple_fault() -> ! {
    // SAFETY: crashing the machine is the point of this one test.
    unsafe { ktest_trigger_triple() }
}
