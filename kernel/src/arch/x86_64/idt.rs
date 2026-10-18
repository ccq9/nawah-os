//! Interrupt Descriptor Table (IDT). Origin: Sol OS (d54f0a5) `idt.rs`, re-reviewed here.
//!
//! Why: firmware leaves its own IDT behind (in memory we will reclaim). Without a kernel IDT the
//! first CPU fault becomes a silent reset (triple fault).
//!
//! References (Intel SDM Vol. 3A, rev. 093):
//! - §7.14.1, Fig. 7-8: 64-bit gate is 16 bytes; IST index in the low 3 bits of byte 4.
//! - Table 3-2: type 14 = 64-bit interrupt gate.
//! - §7.14.5: a non-zero IST makes the CPU switch to that stack unconditionally.

use core::arch::asm;
use core::mem::size_of;

use super::gdt::{TablePointer, DOUBLE_FAULT_IST, KERNEL_CODE_SELECTOR};
use super::trap;
use crate::cell::BootCell;

const IDT_ENTRIES: usize = 256;
const DOUBLE_FAULT_VECTOR: usize = 8;

/// Present (P=1), DPL=0, type 14: interrupt gate — interrupts stay disabled in the handler.
pub const INTERRUPT_GATE: u8 = 0x8E;

/// 64-bit gate; field order follows Fig. 7-8. Alignment 16 keeps the table base 8-byte aligned
/// as §7.10 recommends, without changing the size.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

const _: () = assert!(size_of::<Gate>() == 16);

impl Gate {
    /// Not present (P=0): using it raises an exception caught by a present gate.
    const MISSING: Gate = Gate {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    const fn interrupt(handler: u64, ist: u8) -> Gate {
        Gate {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            ist: ist & 0x7,
            type_attr: INTERRUPT_GATE,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

// Compile-time check of the address split with a known value.
const _: () = {
    let gate = Gate::interrupt(0x1122_3344_5566_7788, 1);
    assert!(gate.offset_low == 0x7788);
    assert!(gate.offset_mid == 0x5566);
    assert!(gate.offset_high == 0x1122_3344);
    assert!(gate.selector == KERNEL_CODE_SELECTOR);
    assert!(gate.ist == 1);
    assert!(gate.type_attr == INTERRUPT_GATE);
};

static IDT: BootCell<[Gate; IDT_ENTRIES]> = BootCell::new([Gate::MISSING; IDT_ENTRIES]);

/// Fills the 32 exception gates and the 224 interrupt gates (WP-10), then loads the table.
/// Every vector is present: an unexpected interrupt is counted, never a #GP/#NP.
pub fn init() {
    let idt = IDT.get().cast::<Gate>();

    for vector in 0..IDT_ENTRIES {
        let ist = if vector == DOUBLE_FAULT_VECTOR {
            DOUBLE_FAULT_IST
        } else {
            0
        };
        let gate = Gate::interrupt(trap::stub_address(vector), ist);
        // SAFETY: boot path only (BootCell contract); index < IDT_ENTRIES; pointer to a valid,
        // aligned static.
        unsafe { idt.add(vector).write(gate) };
    }

    let pointer = TablePointer {
        limit: (size_of::<[Gate; IDT_ENTRIES]>() - 1) as u16,
        base: idt as u64,
    };
    // SAFETY: the static table is valid for the kernel's lifetime and its present gates point at
    // real assembly stubs in kernel code. `lidt` only reads the pointer.
    unsafe {
        asm!("lidt [{}]", in(reg) &raw const pointer, options(readonly, nostack, preserves_flags));
    }
}
