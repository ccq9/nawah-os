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
/// User segments (WP-14), ordered for SYSRET (SDM Vol. 3A §5.8.8): SYSRET loads SS from
/// IA32_STAR[63:48] + 8 and CS from IA32_STAR[63:48] + 16, so with STAR[63:48] = 0x20 the user
/// data selector is 0x28 and the user code selector 0x30 (RPL 3: 0x2B and 0x33).
pub const SYSRET_SELECTOR_BASE: u16 = 0x20;
pub const USER_DATA_SELECTOR: u16 = 0x28 | 3;
pub const USER_CODE_SELECTOR: u16 = 0x30 | 3;

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

/// Emergency stack for #DF (IST1) until the VMM's guarded stacks are adopted.
static DF_STACK: BootCell<Stack<DF_STACK_SIZE>> = BootCell::new(Stack([0; DF_STACK_SIZE]));

/// Stacks adopted after the kernel address space is active (`(base, size)`: kernel, then #DF).
static ADOPTED_STACKS: BootCell<[(u64, u64); 2]> = BootCell::new([(0, 0); 2]);

/// Kernel code segment: present, DPL=0, execute/read, L=1, D=0 (64-bit mode).
const KERNEL_CODE_DESCRIPTOR: u64 = 0x00AF_9B00_0000_FFFF;
/// Kernel data segment: present, DPL=0, writable.
const KERNEL_DATA_DESCRIPTOR: u64 = 0x00CF_9300_0000_FFFF;
/// User data segment: present, DPL=3, writable (SYSRET's SS; base/limit ignored in 64-bit mode).
const USER_DATA_DESCRIPTOR: u64 = 0x00CF_F300_0000_FFFF;
/// User code segment: present, DPL=3, execute/read, L=1, D=0.
const USER_CODE_DESCRIPTOR: u64 = 0x00AF_FB00_0000_FFFF;
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

const GDT_ENTRIES: usize = 7;
const GDT_TSS_INDEX: usize = 3;
const GDT_USER_DATA_INDEX: usize = 5;
const GDT_USER_CODE_INDEX: usize = 6;
const _: () = assert!(GDT_USER_DATA_INDEX * 8 == (USER_DATA_SELECTOR & !3) as usize);
const _: () = assert!(GDT_USER_CODE_INDEX * 8 == (USER_CODE_SELECTOR & !3) as usize);
const _: () = assert!(SYSRET_SELECTOR_BASE + 8 == USER_DATA_SELECTOR & !3);
const _: () = assert!(SYSRET_SELECTOR_BASE + 16 == USER_CODE_SELECTOR & !3);

/// Order: null, kernel code, kernel data, TSS (two slots, filled at run time), user data, user
/// code.
static GDT: BootCell<[u64; GDT_ENTRIES]> = BootCell::new([
    0,
    KERNEL_CODE_DESCRIPTOR,
    KERNEL_DATA_DESCRIPTOR,
    0,
    0,
    USER_DATA_DESCRIPTOR,
    USER_CODE_DESCRIPTOR,
]);

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

/// Points IST1 at the adopted #DF stack and records both adopted stacks for `stack_name`.
/// The CPU reads the TSS at exception time, so the new IST1 is in effect at once.
pub fn adopt_stacks(kernel: (u64, u64), df: (u64, u64)) {
    // SAFETY: boot path, single CPU (BootCell contract); `ist` is packed, hence write_unaligned
    // through a raw pointer; slot DOUBLE_FAULT_IST - 1 is inside the 7-entry array.
    unsafe {
        ADOPTED_STACKS.get().write([kernel, df]);
        (&raw mut (*TSS.get()).ist)
            .cast::<u64>()
            .add(usize::from(DOUBLE_FAULT_IST) - 1)
            .write_unaligned(df.0 + df.1);
    }
}

/// Sets TSS.RSP0: the stack the CPU switches to for an interrupt or exception taken in ring 3
/// (SDM Vol. 3A §7.14.2, §8.7). The CPU reads the TSS at the event, so it is in effect at once.
pub fn set_rsp0(top: u64) {
    // SAFETY: boot path/single CPU (BootCell contract); `rsp` is packed, hence write_unaligned
    // through a raw pointer; slot 0 is inside the 3-entry array.
    unsafe {
        (&raw mut (*TSS.get()).rsp)
            .cast::<u64>()
            .write_unaligned(top);
    }
}

/// Names the stack an address falls in, for diagnostics: the adopted stacks first, then the
/// static boot-time ones.
pub fn stack_name(address: u64) -> &'static str {
    let within = |base: u64, size: u64| size != 0 && address >= base && address < base + size;
    // SAFETY: read of a BootCell written on the boot path only (zeros before adoption).
    let [kernel, df] = unsafe { ADOPTED_STACKS.get().read() };
    if within(df.0, df.1) || within(DF_STACK.get() as u64, DF_STACK_SIZE as u64) {
        "df"
    } else if within(kernel.0, kernel.1)
        || within(KERNEL_STACK.get() as u64, KERNEL_STACK_SIZE as u64)
    {
        "kernel"
    } else {
        "unknown"
    }
}
