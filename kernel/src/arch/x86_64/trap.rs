//! CPU exception entries and the diagnostic path. Origin: Sol OS (d54f0a5) `trap.rs`, adapted:
//! the Rust handler is `extern "sysv64"` because the common stub passes the frame in RDI (the
//! UEFI target's default ABI is the Windows one).
//!
//! Each of the 32 exceptions has its own assembly entry that pushes its vector, then a common
//! path saves the registers and calls [`exception_handler`]. Result: any CPU fault prints a
//! diagnostic line instead of resetting silently.
//!
//! References (Intel SDM Vol. 3A, rev. 093):
//! - Table 7-1: vectors, and which push an error code (8, 10, 11, 12, 13, 14, 17, 21).
//! - §7.13: IRET does not pop the error code; the handler removes it.
//! - §7.14.2: in 64-bit mode SS, RSP, RFLAGS, CS, RIP are always pushed and RSP is aligned to 16.
//! - §7.15 "Event 3": #BP is a trap; the saved RIP points past the instruction, so returning works.
//! - §7.15 "Event 8": #DF is not resumable; its saved RIP is undefined.
//!
//! Unverified: vectors 29 and 30 push an error code on AMD (SEV-ES/SVM features we do not enable).

use core::arch::{asm, global_asm};
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

use super::gdt;
use crate::BUILD_ID;

pub const EXCEPTION_VECTORS: usize = 32;
const BREAKPOINT: u64 = 3;

/// Maximum nesting of exceptions inside the handler. At the limit a fixed message is written
/// without the formatting machinery, then the CPU stops; beyond it, no output at all.
const MAX_NESTING: u32 = 3;

/// Test kernel only: when set, the handler raises #UD on every entry (nesting-limit test).
#[cfg(feature = "ktest")]
pub static KTEST_FAULT_IN_HANDLER: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// What the handler finds on the stack, lowest address first: the registers saved by the common
/// path, then vector and error code, then what the CPU pushed.
#[repr(C)]
pub struct TrapFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = assert!(size_of::<TrapFrame>() == 22 * 8);

// One entry per exception. Where the CPU pushes no error code we push 0 so the frame is uniform.
macro_rules! stub {
    (noerr, $n:literal) => {
        concat!(
            "exc_stub_",
            $n,
            ":\n    push 0\n    push ",
            $n,
            "\n    jmp exc_common\n"
        )
    };
    (err, $n:literal) => {
        concat!(
            "exc_stub_",
            $n,
            ":\n    push ",
            $n,
            "\n    jmp exc_common\n"
        )
    };
}

// Generates the entries and a table of their addresses in the same order, so the table index is
// the vector number.
macro_rules! exception_stubs {
    ($(($kind:ident, $n:literal)),* $(,)?) => {
        global_asm!(concat!(
            // `.text` only: the directive is valid for both COFF (uefi) and ELF (host checks).
            // The address table lives in .text as read-only data (execute-only pages are not a
            // thing on x86; WP-09 maps .text RX, so writes to the table fault — a ktest relies on it).
            ".text\n",
            $(stub!($kind, $n),)*
            ".balign 8\n",
            ".global EXC_STUB_TABLE\n",
            "EXC_STUB_TABLE:\n",
            $(concat!("    .quad exc_stub_", $n, "\n"),)*
            ".if (. - EXC_STUB_TABLE) != 256\n",
            ".error \"EXC_STUB_TABLE must hold exactly 32 entries\"\n",
            ".endif\n",
        ));
    };
}

exception_stubs!(
    (noerr, 0),
    (noerr, 1),
    (noerr, 2),
    (noerr, 3),
    (noerr, 4),
    (noerr, 5),
    (noerr, 6),
    (noerr, 7),
    (err, 8),
    (noerr, 9),
    (err, 10),
    (err, 11),
    (err, 12),
    (err, 13),
    (err, 14),
    (noerr, 15),
    (noerr, 16),
    (err, 17),
    (noerr, 18),
    (noerr, 19),
    (noerr, 20),
    (err, 21),
    (noerr, 22),
    (noerr, 23),
    (noerr, 24),
    (noerr, 25),
    (noerr, 26),
    (noerr, 27),
    (noerr, 28),
    (err, 29),
    (err, 30),
    (noerr, 31),
);

// Common path. Push order is the reverse of the TrapFrame fields because the stack grows down.
// RBX is callee-saved in both ABIs, so it keeps the frame address across the call.
global_asm!(
    r#"
    .text
    .global exc_common
exc_common:
    cld
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    mov rdi, rsp
    mov rbx, rsp
    and rsp, -16
    call {handler}
    mov rsp, rbx
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    add rsp, 16
    iretq
"#,
    handler = sym exception_handler,
);

// Interrupt entries 32..=255 (WP-10): identical shape, generated with `.rept`; each entry is
// 16-byte aligned so its address is IRQ_STUBS + (vector - 32) * 16. The encodings are fixed
// (`push 0` = 6A 00, `push imm32` = 68 nn nn nn nn) so the IDT layout test can decode them.
global_asm!(
    r#"
    .text
    .balign 16
    .global IRQ_STUBS
IRQ_STUBS:
    .set irq_vec, 32
    .rept 224
    .balign 16
    .byte 0x6a, 0x00, 0x68
    .long irq_vec
    jmp exc_common
    .set irq_vec, irq_vec + 1
    .endr
"#
);

pub const IRQ_STUB_STRIDE: usize = 16;

extern "C" {
    /// Addresses of the 32 entries, defined by the assembly above (read-only data in .text).
    static EXC_STUB_TABLE: [u64; EXCEPTION_VECTORS];
    /// First interrupt entry (vector 32); the others follow at IRQ_STUB_STRIDE.
    static IRQ_STUBS: u8;
}

/// Address of the assembly entry for `vector` (0..=255). Panics beyond that.
pub fn stub_address(vector: usize) -> u64 {
    assert!(vector < 256, "vector out of range");
    if vector < EXCEPTION_VECTORS {
        // SAFETY: the table is defined by this file's assembly with 32 8-byte entries, 8-aligned
        // and never written; indexing is bounds-checked.
        unsafe { EXC_STUB_TABLE[vector] }
    } else {
        // Taking the address of the extern static is safe; it is never dereferenced.
        (&raw const IRQ_STUBS as u64) + ((vector - EXCEPTION_VECTORS) * IRQ_STUB_STRIDE) as u64
    }
}

static NESTING: AtomicU32 = AtomicU32::new(0);

fn name(vector: u64) -> &'static str {
    match vector {
        0 => "#DE",
        1 => "#DB",
        2 => "NMI",
        3 => "#BP",
        4 => "#OF",
        5 => "#BR",
        6 => "#UD",
        7 => "#NM",
        8 => "#DF",
        10 => "#TS",
        11 => "#NP",
        12 => "#SS",
        13 => "#GP",
        14 => "#PF",
        16 => "#MF",
        17 => "#AC",
        18 => "#MC",
        19 => "#XM",
        20 => "#VE",
        21 => "#CP",
        _ => "reserved",
    }
}

/// Address of the last page fault; meaningful with #PF and with a #DF caused by one.
fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: reading CR2 is allowed at CPL 0 and touches neither memory nor the stack. Flags
    // are undefined afterwards (SDM Vol. 2, MOV from control registers), so no preserves_flags.
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Prints the diagnostic. Returns only for #BP; every other exception in the kernel is fatal.
/// Vectors >= 32 are interrupts: dispatched to `irq`, never printed here.
extern "sysv64" fn exception_handler(frame: &TrapFrame) {
    if frame.vector >= EXCEPTION_VECTORS as u64 {
        super::irq::dispatch((frame.vector & 0xFF) as u8);
        return;
    }
    let depth = NESTING.fetch_add(1, Ordering::Relaxed);
    if depth > MAX_NESTING {
        fatal(frame.vector);
    }
    if depth == MAX_NESTING {
        use core::fmt::Write as _;
        let _ = crate::arch::Serial.write_str("OSX|?|exc|nesting_limit|stopping\n");
        fatal(frame.vector);
    }

    let marker = 0u8;
    let handler_stack = gdt::stack_name(&raw const marker as u64);

    kprintln!(
        "OSX|{}|exc|vector={}|name={}|error={:#x}|rip={:#x}|cs={:#x}|rflags={:#x}|rsp={:#x}|ss={:#x}|cr2={:#x}|stack={}",
        BUILD_ID,
        frame.vector,
        name(frame.vector),
        frame.error_code,
        frame.rip,
        frame.cs,
        frame.rflags,
        frame.rsp,
        frame.ss,
        read_cr2(),
        handler_stack,
    );
    kprintln!(
        "OSX|{}|exc|regs1|rax={:#x}|rbx={:#x}|rcx={:#x}|rdx={:#x}|rsi={:#x}|rdi={:#x}|rbp={:#x}",
        BUILD_ID,
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx,
        frame.rsi,
        frame.rdi,
        frame.rbp,
    );
    kprintln!(
        "OSX|{}|exc|regs2|r8={:#x}|r9={:#x}|r10={:#x}|r11={:#x}|r12={:#x}|r13={:#x}|r14={:#x}|r15={:#x}",
        BUILD_ID, frame.r8, frame.r9, frame.r10, frame.r11, frame.r12, frame.r13, frame.r14, frame.r15,
    );

    #[cfg(feature = "ktest")]
    if KTEST_FAULT_IN_HANDLER.load(Ordering::Relaxed) {
        // SAFETY: a deliberate fault inside the handler, requested by the exc_nested test only.
        unsafe { asm!("ud2", options(nomem, nostack)) };
    }

    if frame.vector == BREAKPOINT {
        NESTING.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    fatal(frame.vector);
}

/// End of the line for a non-resumable exception. In the lab, QEMU exits with a code that
/// carries the vector (qemu.rs).
fn fatal(vector: u64) -> ! {
    super::qemu::exit(super::qemu::EXIT_EXCEPTION_BASE + (vector & 0x1F) as u8)
}
