//! Legacy dual 8259A PIC: remapped away from the exception vectors and fully masked. ACPI
//! requires exactly this before APIC operation when PCAT_COMPAT is set (ACPI 6.5 Table 5.20).
//!
//! References: Intel 8259A datasheet (ICW1..ICW4 initialisation sequence, OCW1 mask register);
//! Intel ICH9 datasheet §13.4 (8259 at I/O ports 20h/21h master, A0h/A1h slave; the same
//! registers on the ICH9 that QEMU's q35 models). docs/sources.json S34.

use super::port::{inb, outb};

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;
/// Unused POST diagnostic port; a write gives the slow controller time between ICW writes.
const IO_WAIT: u16 = 0x80;

/// Vector base for the 16 legacy IRQs after remapping (gates 0x20..=0x2F exist and only count).
pub const PIC_VECTOR_BASE: u8 = 0x20;

const ICW1_INIT_ICW4: u8 = 0x11; // edge triggered, cascade, ICW4 follows
const ICW3_MASTER_SLAVE_ON_IRQ2: u8 = 0x04;
const ICW3_SLAVE_ID: u8 = 0x02;
const ICW4_8086: u8 = 0x01;

fn io_wait() {
    // SAFETY: port 80h is the POST code port; writing it has no effect on any device we use.
    unsafe { outb(IO_WAIT, 0) }
}

/// Re-initialises both controllers with vectors 0x20..=0x2F and masks every line.
/// Returns the mask registers read back (expected 0xFF, 0xFF).
pub fn remap_and_mask_all() -> (u8, u8) {
    // SAFETY: the documented ICW1..ICW4 sequence on the standard PIC ports, then OCW1 = 0xFF;
    // interrupts are disabled while this runs and no other code touches these ports.
    unsafe {
        outb(MASTER_CMD, ICW1_INIT_ICW4);
        io_wait();
        outb(SLAVE_CMD, ICW1_INIT_ICW4);
        io_wait();
        outb(MASTER_DATA, PIC_VECTOR_BASE);
        io_wait();
        outb(SLAVE_DATA, PIC_VECTOR_BASE + 8);
        io_wait();
        outb(MASTER_DATA, ICW3_MASTER_SLAVE_ON_IRQ2);
        io_wait();
        outb(SLAVE_DATA, ICW3_SLAVE_ID);
        io_wait();
        outb(MASTER_DATA, ICW4_8086);
        io_wait();
        outb(SLAVE_DATA, ICW4_8086);
        io_wait();
        outb(MASTER_DATA, 0xFF);
        outb(SLAVE_DATA, 0xFF);
        (inb(MASTER_DATA), inb(SLAVE_DATA))
    }
}
