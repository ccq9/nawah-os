//! Global Descriptor Table (GDT) and 64-bit Task State Segment (TSS), plus the kernel-owned
//! stacks. Origin: Sol OS (d54f0a5) `gdt.rs`, adapted for the UEFI single-image kernel.
//!
//! Why: firmware hands us its own GDT in EfiBootServicesData memory (reclaimed later) and no
//! TSS. The TSS is the only place the CPU reads the emergency stack (IST) for #DF from.
//!
//! References (Intel SDM Vol. 3A, rev. 093 — see docs/sources.json S26):
//! - §6.2.1: a 64-bit code segment needs L=1, D=0.      - Fig. 6-1: code/data descriptor fields.
//! - Table 3-2: type 9 = available 64-bit TSS.           - Fig. 10-4: 64-bit TSS descriptor (16 bytes).
//! - Fig. 10-11: 64-bit TSS layout (104 bytes).          - §7.14.5: Interrupt Stack Table.

use core::arch::asm;
use core::mem::size_of;

use crate::cell::BootCell;

pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
const TSS_SELECTOR: u16 = 0x18;

/// IST slot (1..=7) used by the double-fault gate.
pub const DOUBLE_FAULT_IST: u8 = 1;

pub const KERNEL_STACK_SIZE: usize = 64 * 1024;
const DF_STACK_SIZE: usize = 16 * 1024;

/// A 16-byte aligned stack as the ABI requires.
#[repr(C, align(16))]
pub struct Stack<const N: usize>(pub [u8; N]);

/// Main kernel stack (used by the CPU through RSP only; no Rust code touches it directly).
/// Guard pages come with the kernel's own page tables (WP-09); until then overflow is undetected.
pub static KERNEL_STACK: BootCell<Stack<KERNEL_STACK_SIZE>> =
    BootCell::new(Stack([0; KERNEL_STACK_SIZE]));

/// Emergency stack for #DF (IST1).
static DF_STACK: BootCell<Stack<DF_STACK_SIZE>> = BootCell::new(Stack([0; DF_STACK_SIZE]));

/// Kernel code segment: present, DPL=0, execute/read, L=1, D=0 (64-bit mode).
const KERNEL_CODE_DESCRIPTOR: u64 = 0x00AF_9B00_0000_FFFF;
/// Kernel data segment: present, DPL=0, writable.
const KERNEL_DATA_DESCRIPTOR: u64 = 0x00CF_9300_0000_FFFF;
/// TSS descriptor access byte: present (P=1), DPL=0, type 9.
const TSS_ACCESS: u64 = 0x89;

/// 64-bit TSS. Offsets follow Fig. 10-11; fields are unaligned so the struct is packed.
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

const TSS_SIZE: usize = 104;
const _: () = assert!(size_of::<Tss>() == TSS_SIZE);

/// Table pointer as `lgdt`/`lidt` expect: 16-bit limit then 64-bit base.
#[repr(C, packed)]
pub struct TablePointer {
    pub limit: u16,
    pub base: u64,
}

const GDT_ENTRIES: usize = 5;
const GDT_TSS_INDEX: usize = 3;

/// Order: null, kernel code, kernel data, then the TSS descriptor in two slots (filled at run time).
static GDT: BootCell<[u64; GDT_ENTRIES]> =
    BootCell::new([0, KERNEL_CODE_DESCRIPTOR, KERNEL_DATA_DESCRIPTOR, 0, 0]);

/// `iomap_base == TSS size` means no I/O permission bitmap.
static TSS: BootCell<Tss> = BootCell::new(Tss {
    reserved0: 0,
    rsp: [0; 3],
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iomap_base: TSS_SIZE as u16,
});

/// Builds the two TSS descriptor slots (Fig. 10-4): low slot then high slot.
const fn tss_descriptor(base: u64, limit: u64) -> (u64, u64) {
    let low = (limit & 0xFFFF)
        | ((base & 0x00FF_FFFF) << 16)
        | (TSS_ACCESS << 40)
        | (((limit >> 16) & 0xF) << 48)
        | (((base >> 24) & 0xFF) << 56);
    let high = base >> 32;
    (low, high)
}

// Compile-time check of the descriptor packing with a known value: every address byte lands in
// its slot.
const _: () = {
    let (low, high) = tss_descriptor(0x1122_3344_5566_7788, 0x67);
    assert!(low == 0x5500_8966_7788_0067);
    assert!(high == 0x1122_3344);
};

/// Top of the kernel stack (16-byte aligned).
pub fn kernel_stack_top() -> u64 {
    KERNEL_STACK.get() as u64 + KERNEL_STACK_SIZE as u64
}

/// Fills the TSS and its descriptor, loads the GDT, reloads the segment registers and TR.
pub fn init() {
    let df_stack_top = DF_STACK.get() as u64 + DF_STACK_SIZE as u64;
    let (tss_low, tss_high) = tss_descriptor(TSS.get() as u64, (TSS_SIZE - 1) as u64);
    let gdt = GDT.get().cast::<u64>();
    let pointer = TablePointer {
        limit: (size_of::<[u64; GDT_ENTRIES]>() - 1) as u16,
        base: gdt as u64,
    };

    // SAFETY: boot path only (BootCell contract). Pointers to statics are valid; indices 3 and 4
    // are inside GDT_ENTRIES. `ist` is unaligned (packed) so it is written with write_unaligned
    // through a raw pointer, never through a reference.
    unsafe {
        (&raw mut (*TSS.get()).ist)
            .cast::<u64>()
            .add(usize::from(DOUBLE_FAULT_IST) - 1)
            .write_unaligned(df_stack_top);
        gdt.add(GDT_TSS_INDEX).write(tss_low);
        gdt.add(GDT_TSS_INDEX + 1).write(tss_high);
    }

    // SAFETY: the table is complete and lives for the kernel's lifetime (static). After lgdt, CS
    // still holds the old cached descriptor, so it is reloaded with a far return (retfq) to the
    // next instruction using the kernel code selector; then SS/DS/ES get the kernel data selector,
    // FS/GS the null selector, LDTR is cleared and TR loaded. `ltr` writes to the GDT (type 9 ->
    // 11, busy); the table is in writable memory. The two pushes are consumed by retfq.
    unsafe {
        asm!(
            "lgdt [{pointer}]",
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ss, {data:x}",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov fs, {null:x}",
            "mov gs, {null:x}",
            "lldt {null:x}",
            "ltr {tss:x}",
            pointer = in(reg) &raw const pointer,
            code = in(reg) u64::from(KERNEL_CODE_SELECTOR),
            data = in(reg) u64::from(KERNEL_DATA_SELECTOR),
            null = in(reg) 0u64,
            tss = in(reg) u64::from(TSS_SELECTOR),
            tmp = out(reg) _,
            options(preserves_flags),
        );
    }
}

/// Names the stack an address falls in, for diagnostics.
pub fn stack_name(address: u64) -> &'static str {
    let within = |base: u64, size: usize| address >= base && address < base + size as u64;
    if within(DF_STACK.get() as u64, DF_STACK_SIZE) {
        "df"
    } else if within(KERNEL_STACK.get() as u64, KERNEL_STACK_SIZE) {
        "kernel"
    } else {
        "unknown"
    }
}
