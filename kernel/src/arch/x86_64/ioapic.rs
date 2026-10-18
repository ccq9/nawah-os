//! I/O APIC: mapped from the MADT, every redirection entry masked until a driver asks for a line
//! (M3/M4). Indirect register access: IOREGSEL at base+00h selects, IOWIN at base+10h reads or
//! writes the 32-bit register.
//!
//! References: Intel 82093AA I/O APIC datasheet §3.1/§3.2 (IOREGSEL, IOWIN, IOAPICID 00h,
//! IOAPICVER 01h with bits 16-23 = maximum redirection entry, IOREDTBL at 10h + 2n low/high,
//! bit 16 of the low dword = mask); the same programming interface in the ICH9 datasheet §13.5.
//! docs/sources.json S34, S36.

use crate::mm::vmm;

const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;
const REG_VERSION: u32 = 0x01;
const REG_REDTBL: u32 = 0x10;
const REDIR_MASKED: u32 = 1 << 16;

#[derive(Clone, Copy, Debug)]
pub struct IoApic {
    pub base: u64,
    #[allow(dead_code)] // consumed by the IRQ routing of M3/M4
    pub gsi_base: u32,
    pub version: u8,
    pub entries: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoApicError {
    Mmio,
}

fn read(base: u64, reg: u32) -> u32 {
    // SAFETY: the 4 KiB page at `base` was mapped uncacheable by `init`; IOREGSEL/IOWIN are the
    // documented 32-bit windows.
    unsafe {
        ((base + IOREGSEL) as *mut u32).write_volatile(reg);
        ((base + IOWIN) as *const u32).read_volatile()
    }
}

fn write(base: u64, reg: u32, value: u32) {
    // SAFETY: as in `read`.
    unsafe {
        ((base + IOREGSEL) as *mut u32).write_volatile(reg);
        ((base + IOWIN) as *mut u32).write_volatile(value);
    }
}

/// Maps the controller, reads its version and entry count, and masks every entry.
pub fn init(address: u32, gsi_base: u32) -> Result<IoApic, IoApicError> {
    let base = vmm::map_mmio(u64::from(address), 4096).map_err(|_| IoApicError::Mmio)?;
    let ver = read(base, REG_VERSION);
    let entries = ((ver >> 16) & 0xFF) + 1;
    for i in 0..entries {
        let low = REG_REDTBL + 2 * i;
        write(base, low, read(base, low) | REDIR_MASKED);
    }
    Ok(IoApic {
        base,
        gsi_base,
        version: (ver & 0xFF) as u8,
        entries,
    })
}

/// Number of entries whose mask bit is set (read back after `init`: must equal `entries`).
pub fn masked_entries(io: &IoApic) -> u32 {
    (0..io.entries)
        .filter(|i| read(io.base, REG_REDTBL + 2 * i) & REDIR_MASKED != 0)
        .count() as u32
}
