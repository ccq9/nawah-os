//! PCI configuration space through ECAM (WP-18, ADR-0013). The MCFG table (ACPI) gives the
//! memory-mapped window of each segment group; a function's 4 KiB configuration page sits at
//! `base + (bus << 20 | device << 15 | function << 12)` (PCI Express Base Specification §7.2.2,
//! "Enhanced Configuration Access Mechanism"). Pages are mapped uncacheable on first use.
//!
//! Configuration header (PCI Local Bus Specification 3.0 §6.1, type 0): Vendor ID at 0,
//! Device ID at 2, Command at 4 (bit 1 Memory Space, bit 2 Bus Master), Status at 6 (bit 4
//! Capabilities List), Revision at 8, Class Code at 9..=11 (prog-if, subclass, base class),
//! Header Type at 0xE (bit 7 multi-function), BAR0..5 at 0x10 + 4i (bit 0 I/O space; bits 2:1
//! memory type, 10b = 64-bit; bit 3 prefetchable), Capabilities Pointer at 0x34. Capability
//! entries: ID at 0, next pointer at 1 (§6.7).

use alloc::vec::Vec;

use super::acpi::Mcfg;
use super::mmio::{read16 as rd16, read32 as rd32, read8 as rd8, write16 as wr16, write32 as wr32};
use crate::mm::vmm;

pub const VENDOR_NONE: u16 = 0xFFFF;
const CMD_MEMORY: u16 = 1 << 1;
const CMD_BUS_MASTER: u16 = 1 << 2;
/// Command bit 10: INTx disable (the kernel polls; no line interrupt is wanted).
const CMD_INTX_DISABLE: u16 = 1 << 10;
const STATUS_CAPS: u16 = 1 << 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    None,
    Io(u32),
    Memory {
        base: u64,
        size: u64,
        is_64: bool,
        prefetchable: bool,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct Device {
    pub bdf: Bdf,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    /// ECAM address of the configuration page.
    cfg: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub id: u8,
    /// Offset of the capability inside configuration space.
    pub offset: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciError {
    NoEcam,
    Map,
}

/// Maps (once) and returns the configuration page of `bdf` in the ECAM window `base`.
fn config_page(base: u64, bdf: Bdf) -> Result<u64, PciError> {
    let phys = base
        + ((u64::from(bdf.bus) << 20)
            | (u64::from(bdf.device) << 15)
            | (u64::from(bdf.function) << 12));
    vmm::map_mmio(phys, 4096).map_err(|_| PciError::Map)
}

impl Device {
    pub fn read8(&self, off: u16) -> u8 {
        rd8(self.cfg + u64::from(off))
    }

    pub fn read16(&self, off: u16) -> u16 {
        rd16(self.cfg + u64::from(off & !1))
    }

    pub fn read32(&self, off: u16) -> u32 {
        rd32(self.cfg + u64::from(off & !3))
    }

    /// Memory space and bus mastering on (needed before MMIO BAR access and DMA), INTx off.
    pub fn enable(&self) {
        let cmd = self.read16(4);
        wr16(
            self.cfg + 4,
            cmd | CMD_MEMORY | CMD_BUS_MASTER | CMD_INTX_DISABLE,
        );
    }

    /// Decodes BAR `i` (0..=5) and probes its size (writing all-ones, reading back, restoring).
    pub fn bar(&self, i: u8) -> Bar {
        if i > 5 {
            return Bar::None;
        }
        let off = self.cfg + 0x10 + 4 * u64::from(i);
        let lo = rd32(off);
        if lo == 0 {
            return Bar::None;
        }
        if lo & 1 == 1 {
            return Bar::Io(lo & !0x3);
        }
        let is_64 = (lo >> 1) & 0x3 == 0b10;
        let prefetchable = lo & 0x8 != 0;
        let hi = if is_64 && i < 5 { rd32(off + 4) } else { 0 };
        let base = (u64::from(hi) << 32) | u64::from(lo & !0xF);
        // Size probe: all ones in, read the mask back, restore.
        wr32(off, 0xFFFF_FFFF);
        let mask_lo = rd32(off) & !0xF;
        wr32(off, lo);
        let mut size = u64::from(!mask_lo).wrapping_add(1) & 0xFFFF_FFFF;
        if is_64 && i < 5 {
            wr32(off + 4, 0xFFFF_FFFF);
            let mask_hi = rd32(off + 4);
            wr32(off + 4, hi);
            let mask = (u64::from(mask_hi) << 32) | u64::from(mask_lo);
            size = (!mask).wrapping_add(1);
        }
        Bar::Memory {
            base,
            size,
            is_64,
            prefetchable,
        }
    }

    /// The capability list (empty when the Status register says there is none). Bounded to
    /// 48 entries so a looping list cannot hang the walk.
    pub fn capabilities(&self) -> Vec<Capability> {
        let mut out = Vec::new();
        if self.read16(6) & STATUS_CAPS == 0 {
            return out;
        }
        let mut ptr = self.read8(0x34) & !0x3;
        while ptr >= 0x40 && out.len() < 48 {
            let id = self.read8(u16::from(ptr));
            out.push(Capability { id, offset: ptr });
            ptr = self.read8(u16::from(ptr) + 1) & !0x3;
        }
        out
    }
}

/// Enumerates every function on the first bus of the first ECAM window (vendor != 0xFFFF).
/// Bridges are not followed: the lab's q35 root bus carries the devices the kernel drives
/// (ADR-0013).
pub fn enumerate(mcfg: &Mcfg) -> Result<Vec<Device>, PciError> {
    if mcfg.n == 0 {
        return Err(PciError::NoEcam);
    }
    let w = mcfg.entries[0];
    let mut out = Vec::new();
    let bus = w.start_bus;
    {
        for device in 0..32u8 {
            let bdf0 = Bdf {
                bus,
                device,
                function: 0,
            };
            let cfg0 = config_page(w.base, bdf0)?;
            if rd16(cfg0) == VENDOR_NONE {
                continue;
            }
            let multi = rd8(cfg0 + 0xE) & 0x80 != 0;
            let functions = if multi { 8 } else { 1 };
            for function in 0..functions {
                let bdf = Bdf {
                    bus,
                    device,
                    function,
                };
                let cfg = if function == 0 {
                    cfg0
                } else {
                    config_page(w.base, bdf)?
                };
                let vendor = rd16(cfg);
                if vendor == VENDOR_NONE {
                    continue;
                }
                out.push(Device {
                    bdf,
                    vendor,
                    device: rd16(cfg + 2),
                    subclass: rd8(cfg + 0xA),
                    class: rd8(cfg + 0xB),
                    cfg,
                });
            }
        }
    }
    Ok(out)
}
