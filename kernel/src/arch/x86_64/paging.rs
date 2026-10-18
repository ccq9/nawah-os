//! 4-level paging primitives. References (Intel SDM, docs/sources.json S26): Vol. 3A §4.5
//! "4-Level Paging" (table walk, entry formats in Tables 4-15..4-20), §4.6 access rights (the
//! XD bit needs IA32_EFER.NXE, CR0.WP makes read-only pages read-only for supervisor writes),
//! §2.5 control registers, Vol. 4 Table 2-2 (IA32_EFER, bit 11 NXE), Vol. 2A CPUID
//! 80000001H:EDX bit 20 (execute-disable support).
//!
//! The mapper allocates table frames from `mm::pmm` and writes them through the identity
//! mapping of RAM, which both the firmware's tables and the kernel's own tables provide.

use core::arch::asm;
use core::arch::x86_64::__cpuid;

use crate::mm::pmm::{self, FRAME_SIZE};

pub const PAGE_4K: u64 = 4096;
pub const PAGE_2M: u64 = 2 * 1024 * 1024;

/// Page-table entry bits (SDM Vol. 3A Tables 4-15..4-20).
pub const PRESENT: u64 = 1 << 0;
pub const WRITE: u64 = 1 << 1;
/// Page-level write-through and cache-disable; PCD|PWT selects PAT entry 3, which is UC with
/// the power-on PAT (SDM Vol. 3A §13.12.2/Table 13-11): the right memory type for MMIO.
pub const PWT: u64 = 1 << 3;
pub const PCD: u64 = 1 << 4;
/// Page size (PS) in a page-directory entry: the entry maps a 2 MiB page.
pub const HUGE: u64 = 1 << 7;
/// Execute-disable (XD); reserved unless IA32_EFER.NXE = 1.
pub const NX: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Where the direct map of physical memory lives (higher half, PML4 slot 256).
pub const DIRECT_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapError {
    OutOfFrames,
    /// A 2 MiB page already covers this range, or a page table exists where a 2 MiB page is
    /// wanted.
    Conflict,
    Unaligned,
}

/// A root page table (PML4) under construction or in use.
#[derive(Clone, Copy)]
pub struct AddressSpace {
    /// Physical address of the PML4 frame.
    pub pml4: u64,
    /// Whether the CPU supports XD; when it does not, NX is dropped from every leaf because the
    /// bit is reserved and would make the walk fault.
    nx: bool,
}

fn zero_frame(phys: u64) {
    // SAFETY: a frame freshly handed out by the allocator (RAM, identity-mapped), used by nobody
    // else; FRAME_SIZE bytes are in bounds.
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, FRAME_SIZE as usize) }
}

fn entry(table: u64, index: u64) -> *mut u64 {
    (table + index * 8) as *mut u64
}

fn read_entry(table: u64, index: u64) -> u64 {
    // SAFETY: `table` is a page-table frame (ours, or the active one being walked for
    // diagnostics), identity-mapped RAM; index < 512 by construction (9-bit indices).
    unsafe { entry(table, index).read_volatile() }
}

fn write_entry(table: u64, index: u64, value: u64) {
    // SAFETY: as in read_entry, on a table frame the kernel owns.
    unsafe { entry(table, index).write_volatile(value) }
}

/// Returns the physical address of the next-level table for `index`, allocating a zeroed one
/// when absent. Fails on a 2 MiB-page entry (there is no table behind it).
fn next_table(table: u64, index: u64) -> Result<u64, MapError> {
    let e = read_entry(table, index);
    if e & PRESENT != 0 {
        if e & HUGE != 0 {
            return Err(MapError::Conflict);
        }
        return Ok(e & ADDR_MASK);
    }
    let f = pmm::alloc_frame().ok_or(MapError::OutOfFrames)?;
    zero_frame(f.0);
    // Intermediate entries are permissive (present, writable, executable): the effective
    // permission is the AND over the walk, so the leaf carries the real one (SDM §4.6.2).
    write_entry(table, index, f.0 | PRESENT | WRITE);
    Ok(f.0)
}

const fn idx(virt: u64, level: u32) -> u64 {
    (virt >> (12 + 9 * level)) & 0x1FF
}

/// CPUID 80000001H:EDX bit 20: execute-disable bit available (SDM Vol. 2A, CPUID).
pub fn nx_supported() -> bool {
    // `__cpuid` is a safe intrinsic on x86_64; the extended leaf exists when the maximum
    // extended leaf reported by 80000000H reaches it.
    if __cpuid(0x8000_0000).eax < 0x8000_0001 {
        return false;
    }
    __cpuid(0x8000_0001).edx & (1 << 20) != 0
}

impl AddressSpace {
    /// A fresh, empty address space.
    pub fn new() -> Result<Self, MapError> {
        let f = pmm::alloc_frame().ok_or(MapError::OutOfFrames)?;
        zero_frame(f.0);
        Ok(Self {
            pml4: f.0,
            nx: nx_supported(),
        })
    }

    /// The address space the CPU is using now (for diagnostics and tests).
    pub fn current() -> Self {
        Self {
            pml4: read_cr3(),
            nx: nx_supported(),
        }
    }

    fn leaf(&self, phys: u64, flags: u64) -> u64 {
        let flags = if self.nx { flags } else { flags & !NX };
        (phys & ADDR_MASK) | flags | PRESENT
    }

    /// Maps one 4 KiB page. `flags` are the leaf flags; PRESENT is added.
    pub fn map_4k(&self, virt: u64, phys: u64, flags: u64) -> Result<(), MapError> {
        if !virt.is_multiple_of(PAGE_4K) || !phys.is_multiple_of(PAGE_4K) {
            return Err(MapError::Unaligned);
        }
        let pdpt = next_table(self.pml4, idx(virt, 3))?;
        let pd = next_table(pdpt, idx(virt, 2))?;
        let pt = next_table(pd, idx(virt, 1))?;
        write_entry(pt, idx(virt, 0), self.leaf(phys, flags));
        Ok(())
    }

    /// Maps one 2 MiB page (PD entry with PS). Fails if a page table already sits there.
    pub fn map_2m(&self, virt: u64, phys: u64, flags: u64) -> Result<(), MapError> {
        if !virt.is_multiple_of(PAGE_2M) || !phys.is_multiple_of(PAGE_2M) {
            return Err(MapError::Unaligned);
        }
        let pdpt = next_table(self.pml4, idx(virt, 3))?;
        let pd = next_table(pdpt, idx(virt, 2))?;
        let e = read_entry(pd, idx(virt, 1));
        if e & PRESENT != 0 && e & HUGE == 0 {
            return Err(MapError::Conflict);
        }
        write_entry(pd, idx(virt, 1), self.leaf(phys, flags | HUGE));
        Ok(())
    }

    /// Maps `[phys, phys + len)` at `virt`: 2 MiB pages where both addresses are aligned and the
    /// remaining length allows it (never beyond `len`), 4 KiB pages otherwise.
    pub fn map_range(&self, virt: u64, phys: u64, len: u64, flags: u64) -> Result<(), MapError> {
        let mut off = 0u64;
        while off < len {
            let (v, p) = (virt + off, phys + off);
            if v.is_multiple_of(PAGE_2M) && p.is_multiple_of(PAGE_2M) && len - off >= PAGE_2M {
                match self.map_2m(v, p, flags) {
                    Ok(()) => {
                        off += PAGE_2M;
                        continue;
                    }
                    Err(MapError::Conflict) => {} // a 4 KiB table exists here: use it
                    Err(e) => return Err(e),
                }
            }
            self.map_4k(v, p, flags)?;
            off += PAGE_4K;
        }
        Ok(())
    }

    /// Walks this space's tables for `virt`: (physical address, leaf flags) when mapped.
    pub fn translate(&self, virt: u64) -> Option<(u64, u64)> {
        let e3 = read_entry(self.pml4, idx(virt, 3));
        if e3 & PRESENT == 0 {
            return None;
        }
        let e2 = read_entry(e3 & ADDR_MASK, idx(virt, 2));
        if e2 & PRESENT == 0 {
            return None;
        }
        let e1 = read_entry(e2 & ADDR_MASK, idx(virt, 1));
        if e1 & PRESENT == 0 {
            return None;
        }
        if e1 & HUGE != 0 {
            let base = e1 & ADDR_MASK & !(PAGE_2M - 1);
            return Some((base + (virt & (PAGE_2M - 1)), e1 & !ADDR_MASK));
        }
        let e0 = read_entry(e1 & ADDR_MASK, idx(virt, 0));
        if e0 & PRESENT == 0 {
            return None;
        }
        Some(((e0 & ADDR_MASK) + (virt & (PAGE_4K - 1)), e0 & !ADDR_MASK))
    }

    /// Installs this space: enables NXE (when supported) and WP first, then loads CR3, which
    /// flushes the TLB (no global pages are used).
    ///
    /// # Safety
    /// Everything the kernel executes from, its stack and its data must be mapped in this space
    /// at their current addresses, or the next instruction faults with no way to report it.
    pub unsafe fn activate(&self) {
        if self.nx {
            enable_nxe();
        }
        enable_wp();
        // SAFETY: the caller guarantees the space is complete; loading CR3 is the point.
        unsafe { asm!("mov cr3, {}", in(reg) self.pml4, options(nostack, preserves_flags)) };
    }
}

const IA32_EFER: u32 = 0xC000_0080;
const EFER_NXE: u64 = 1 << 11;
const CR0_WP: u64 = 1 << 16;

fn enable_nxe() {
    // SAFETY: IA32_EFER read-modify-write at CPL 0; only bit 11 (NXE) changes, and the caller
    // checked CPUID 80000001H:EDX[20] so the bit is not reserved.
    unsafe {
        let (lo, hi): (u32, u32);
        asm!("rdmsr", in("ecx") IA32_EFER, out("eax") lo, out("edx") hi, options(nomem, nostack));
        let v = ((u64::from(hi) << 32) | u64::from(lo)) | EFER_NXE;
        asm!(
            "wrmsr",
            in("ecx") IA32_EFER,
            in("eax") v as u32,
            in("edx") (v >> 32) as u32,
            options(nomem, nostack),
        );
    }
}

/// Sets CR0.WP: supervisor writes to read-only pages fault. Public so the test kernel can prove
/// the kernel's own control of the bit independently of what the firmware left in CR0.
pub fn enable_wp() {
    // SAFETY: CR0 read-modify-write at CPL 0; only bit 16 (WP) changes.
    unsafe {
        asm!(
            "mov {t}, cr0",
            "or {t}, {wp}",
            "mov cr0, {t}",
            t = out(reg) _,
            wp = in(reg) CR0_WP,
            options(nomem, nostack),
        );
    }
}

/// Clears CR0.WP (test kernel only: the vmm_wp test starts from a known state).
#[cfg(feature = "ktest")]
pub fn disable_wp() {
    // SAFETY: CR0 read-modify-write at CPL 0; only bit 16 (WP) changes.
    unsafe {
        asm!(
            "mov {t}, cr0",
            "and {t}, {mask}",
            "mov cr0, {t}",
            t = out(reg) _,
            mask = in(reg) !CR0_WP,
            options(nomem, nostack),
        );
    }
}

/// Physical address of the active PML4.
pub fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: reading CR3 at CPL 0 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v & ADDR_MASK
}

/// CR0.WP: supervisor writes to read-only pages fault.
pub fn wp_enabled() -> bool {
    let v: u64;
    // SAFETY: reading CR0 at CPL 0 has no side effects.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v & CR0_WP != 0
}

/// IA32_EFER.NXE: the XD bit is honoured.
pub fn nxe_enabled() -> bool {
    let (lo, hi): (u32, u32);
    // SAFETY: rdmsr of IA32_EFER at CPL 0 (the MSR exists on every x86-64 CPU).
    unsafe {
        asm!("rdmsr", in("ecx") IA32_EFER, out("eax") lo, out("edx") hi, options(nomem, nostack))
    };
    ((u64::from(hi) << 32) | u64::from(lo)) & EFER_NXE != 0
}
