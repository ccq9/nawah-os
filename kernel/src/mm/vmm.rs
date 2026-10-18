//! Kernel address space (WP-09, ADR-0004): built from the boot memory map and the in-memory PE
//! headers of the kernel image, then activated; the firmware's page tables are never used again.
//!
//! Layout:
//! - Identity map of every RAM descriptor of the UEFI memory map, RW + NX, except frame 0 (so a
//!   null dereference faults) and the kernel image.
//! - Direct map of the same physical ranges at `DIRECT_MAP_BASE + phys`, RW + NX.
//! - Kernel image at its load address with per-section permissions from the PE section table
//!   (PE/COFF spec, section flags IMAGE_SCN_MEM_EXECUTE/WRITE): .text RX, .rdata R + NX,
//!   .data/.bss RW + NX, headers R + NX.
//! - Kernel stacks in a dedicated area (`STACK_AREA_BASE`), each with an unmapped guard page
//!   below it; the frames come from the allocator.
//!
//! MMIO is not mapped here; WP-10 maps the LAPIC/IOAPIC pages explicitly.
//!
//! The image stays at the (low) address the firmware loaded it at: moving it to the higher half
//! would need the base relocations re-applied and every runtime-computed address (IDT gates,
//! GDT/TSS bases, static buffers) recomputed. Consequence recorded in ADR-0004: the image's
//! physical range is a supervisor-only hole in every later user address space.

use crate::arch::paging::{
    self, AddressSpace, MapError, DIRECT_MAP_BASE, NX, PAGE_4K, PCD, PWT, WRITE,
};
use crate::bootinfo::BootInfo;
use crate::cell::BootCell;
use crate::mm::pmm;

/// Virtual area for kernel stacks (PML4 slot 288): each slot is `STACK_SLOT` bytes and starts
/// with an unmapped guard page.
pub const STACK_AREA_BASE: u64 = 0xFFFF_9000_0000_0000;
pub const KERNEL_STACK_SIZE: u64 = 64 * 1024;
pub const DF_STACK_SIZE: u64 = 16 * 1024;
const STACK_SLOT: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct StackInfo {
    /// First mapped byte; the guard page is `[guard, base)`.
    pub base: u64,
    pub size: u64,
    pub guard: u64,
}

impl StackInfo {
    pub const fn top(&self) -> u64 {
        self.base + self.size
    }
}

#[derive(Clone, Copy, Debug)]
pub struct KernelSpace {
    pub cr3: u64,
    pub image_base: u64,
    pub image_size: u64,
    pub sections_rx: u32,
    pub sections_ro: u32,
    pub sections_rw: u32,
    pub kernel_stack: StackInfo,
    pub df_stack: StackInfo,
    pub ram_bytes_mapped: u64,
    pub reclaimed_frames: u64,
    pub wp: bool,
    pub nxe: bool,
    /// A fresh frame written through the direct map reads back through the identity map.
    pub direct_ok: bool,
    /// The page holding `init` is executable and read-only; the page holding the kernel-space
    /// record is writable and non-executable (section permissions took effect).
    pub text_rx: bool,
    pub data_rw_nx: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum VmmError {
    Map(MapError),
    BadImage,
    /// A translation that must hold before the switch does not.
    Unmapped,
}

impl From<MapError> for VmmError {
    fn from(e: MapError) -> Self {
        VmmError::Map(e)
    }
}

impl VmmError {
    /// Stable code for the panic trace.
    pub fn code(&self) -> &'static str {
        match self {
            VmmError::Map(MapError::OutOfFrames) => "K_E_VMM_OUT_OF_FRAMES",
            VmmError::Map(MapError::Conflict) => "K_E_VMM_MAP_CONFLICT",
            VmmError::Map(MapError::Unaligned) => "K_E_VMM_UNALIGNED",
            VmmError::BadImage => "K_E_VMM_BAD_IMAGE",
            VmmError::Unmapped => "K_E_VMM_UNMAPPED",
        }
    }
}

static KERNEL_SPACE: BootCell<Option<KernelSpace>> = BootCell::new(None);

extern "C" {
    /// Absolute symbol the linker (lld-link) defines at the image base; the firmware loader
    /// relocates the image as a whole, so a RIP-relative reference yields the load address.
    static __ImageBase: u8;
}

fn image_base() -> u64 {
    // Taking the address of an extern static is safe; it is never dereferenced as a `u8`.
    &raw const __ImageBase as u64
}

fn rd32(addr: u64) -> u32 {
    // SAFETY: `addr` lies inside the loaded kernel image (the caller derives it from the PE
    // headers and bounds it by SizeOfImage); the read is unaligned-safe.
    unsafe { (addr as *const u32).read_unaligned() }
}

fn rd16(addr: u64) -> u16 {
    // SAFETY: as in rd32.
    unsafe { (addr as *const u16).read_unaligned() }
}

const SCN_EXECUTE: u32 = 0x2000_0000;
const SCN_WRITE: u32 = 0x8000_0000;

/// Maps the kernel image with per-section permissions from its PE headers (PE/COFF: DOS stub
/// e_lfanew at 0x3C, "PE\0\0", COFF header, optional header PE32+ magic 0x20B, section table).
/// Returns (base, SizeOfImage, #RX, #R, #RW).
fn map_image(space: &AddressSpace) -> Result<(u64, u64, u32, u32, u32), VmmError> {
    let base = image_base();
    if rd16(base) != 0x5A4D {
        return Err(VmmError::BadImage); // "MZ"
    }
    let pe = base + u64::from(rd32(base + 0x3C));
    if rd32(pe) != 0x0000_4550 {
        return Err(VmmError::BadImage); // "PE\0\0"
    }
    let nsections = u64::from(rd16(pe + 6));
    let opt_size = u64::from(rd16(pe + 20));
    let opt = pe + 24;
    if rd16(opt) != 0x20B {
        return Err(VmmError::BadImage); // PE32+
    }
    let section_align = u64::from(rd32(opt + 32));
    let size_of_image = u64::from(rd32(opt + 56));
    let size_of_headers = u64::from(rd32(opt + 60));
    if section_align < PAGE_4K || !section_align.is_multiple_of(PAGE_4K) || nsections > 64 {
        return Err(VmmError::BadImage);
    }
    let image_end = base + size_of_image.next_multiple_of(PAGE_4K);
    // Headers: read-only.
    let hdr_len = size_of_headers.next_multiple_of(PAGE_4K);
    if base + hdr_len > image_end {
        return Err(VmmError::BadImage);
    }
    space.map_range(base, base, hdr_len, NX)?;
    let (mut rx, mut ro, mut rw) = (0u32, 0u32, 0u32);
    let sect = opt + opt_size;
    for i in 0..nsections {
        let s = sect + i * 40;
        let vsize = u64::from(rd32(s + 8));
        let vaddr = u64::from(rd32(s + 12));
        let chars = rd32(s + 36);
        if vsize == 0 {
            continue;
        }
        let start = base + vaddr;
        let len = vsize.next_multiple_of(PAGE_4K);
        if !vaddr.is_multiple_of(PAGE_4K) || start + len > image_end {
            return Err(VmmError::BadImage);
        }
        let flags = if chars & SCN_EXECUTE != 0 {
            rx += 1;
            0 // present, read-only, executable
        } else if chars & SCN_WRITE != 0 {
            rw += 1;
            WRITE | NX
        } else {
            ro += 1;
            NX
        };
        space.map_range(start, start, len, flags)?;
    }
    if rx == 0 {
        return Err(VmmError::BadImage);
    }
    Ok((base, size_of_image, rx, ro, rw))
}

/// Maps every RAM descriptor in the direct map (RW + NX) and identity (RW + NX, minus frame 0
/// and the image pages, which carry section permissions). Returns the bytes of RAM mapped.
fn map_ram(space: &AddressSpace, bi: &BootInfo, image: (u64, u64)) -> Result<u64, VmmError> {
    let (i0, i1) = (image.0, image.0 + image.1.next_multiple_of(PAGE_4K));
    let mut total = 0u64;
    for d in bi.memmap() {
        if !d.is_ram() || d.pages == 0 {
            continue;
        }
        let start = d.phys_start;
        let len = d.pages * PAGE_4K;
        let end = start + len;
        total += len;
        space.map_range(DIRECT_MAP_BASE + start, start, len, WRITE | NX)?;
        // Identity: skip frame 0 and the image.
        let mut lo = start.max(PAGE_4K);
        if lo < i1 && end > i0 {
            if lo < i0 {
                space.map_range(lo, lo, i0 - lo, WRITE | NX)?;
            }
            lo = i1;
        }
        if end > lo {
            space.map_range(lo, lo, end - lo, WRITE | NX)?;
        }
    }
    Ok(total)
}

/// Allocates a stack of `size` bytes in stack slot `slot`, mapped page by page below the slot's
/// unmapped guard page.
fn map_stack(space: &AddressSpace, slot: u64, size: u64) -> Result<StackInfo, VmmError> {
    let guard = STACK_AREA_BASE + slot * STACK_SLOT;
    let base = guard + PAGE_4K;
    let mut off = 0;
    while off < size {
        let f = pmm::alloc_frame().ok_or(MapError::OutOfFrames)?;
        space.map_4k(base + off, f.0, WRITE | NX)?;
        off += PAGE_4K;
    }
    Ok(StackInfo { base, size, guard })
}

/// Writes a pattern to a fresh frame through the direct map and reads it back through the
/// identity map; the frame is returned to the allocator.
fn probe_direct_map() -> bool {
    let Some(f) = pmm::alloc_frame() else {
        return false;
    };
    let pattern = 0xD1EC_7A11_0000_0000 ^ f.0;
    let ok = {
        let via_direct = direct(f.0) as *mut u64;
        let via_identity = f.0 as *const u64;
        // SAFETY: the frame was just handed out by the allocator and both aliases of it are
        // mapped RW in the active kernel space.
        unsafe {
            via_direct.write_volatile(pattern);
            via_identity.read_volatile() == pattern
        }
    };
    let _ = pmm::free_frame(f);
    ok
}

/// Builds and activates the kernel address space. On return the CPU runs on the new tables but
/// still on the boot stack inside the image; the caller moves to `kernel_stack` (guarded) and
/// adopts `df_stack` as IST1.
pub fn init(bi: &BootInfo) -> Result<KernelSpace, VmmError> {
    let space = AddressSpace::new()?;
    let (image_base, image_size, rx, ro, rw) = map_image(&space)?;
    let ram = map_ram(&space, bi, (image_base, image_size))?;
    let kernel_stack = map_stack(&space, 0, KERNEL_STACK_SIZE)?;
    let df_stack = map_stack(&space, 1, DF_STACK_SIZE)?;
    // What the very next instructions need must be mapped: the code (this function), the boot
    // stack and data (inside the image), the memory map buffer, and the new stacks.
    let bitmap = pmm::bitmap_address();
    let here = init as *const () as u64;
    for probe in [
        image_base,
        here,
        bi.memmap as u64,
        bitmap,
        kernel_stack.base,
        df_stack.base,
    ] {
        if space.translate(probe).is_none() {
            return Err(VmmError::Unmapped);
        }
    }
    // SAFETY: the image (all sections), all RAM (identity and direct) and the new stacks are
    // mapped above, and the translations the switch depends on were just verified.
    unsafe { space.activate() };
    // Firmware tables are no longer in use: boot-services memory becomes ours.
    let image_end = image_base + image_size.next_multiple_of(PAGE_4K);
    let reclaimed_frames = pmm::reclaim_boot_services(bi, (image_base, image_end));
    let ks = KernelSpace {
        cr3: space.pml4,
        image_base,
        image_size,
        sections_rx: rx,
        sections_ro: ro,
        sections_rw: rw,
        kernel_stack,
        df_stack,
        ram_bytes_mapped: ram,
        reclaimed_frames,
        wp: paging::wp_enabled(),
        nxe: paging::nxe_enabled(),
        direct_ok: probe_direct_map(),
        text_rx: flags_of(here).is_some_and(|f| !is_writable(f) && !is_nx(f)),
        data_rw_nx: flags_of(KERNEL_SPACE.get() as u64).is_some_and(|f| is_writable(f) && is_nx(f)),
    };
    // SAFETY: written once on the boot path before any reader (BootCell contract).
    unsafe { KERNEL_SPACE.get().write(Some(ks)) };
    Ok(ks)
}

/// The active kernel space, once `init` succeeded.
pub fn kernel_space() -> Option<KernelSpace> {
    // SAFETY: read after the single boot-path write (BootCell contract); the value is Copy.
    unsafe { (*KERNEL_SPACE.get()).as_ref().copied() }
}

/// Direct-map address of a physical address.
pub const fn direct(phys: u64) -> u64 {
    DIRECT_MAP_BASE + phys
}

/// Maps `[phys, phys + len)` of device memory (MMIO) at its own address, uncacheable (PCD|PWT),
/// RW + NX, in the active kernel space; returns the virtual address. Pages are 4 KiB; a range
/// already covered by a RAM mapping is refused (`Conflict`) rather than remapped. New entries
/// need no TLB flush: not-present translations are never cached (SDM Vol. 3A §4.10.2.3).
pub fn map_mmio(phys: u64, len: u64) -> Result<u64, VmmError> {
    if kernel_space().is_none() {
        return Err(VmmError::Unmapped);
    }
    let space = AddressSpace::current();
    let start = phys & !(PAGE_4K - 1);
    let end = (phys + len).next_multiple_of(PAGE_4K);
    let mut page = start;
    while page < end {
        match space.translate(page) {
            Some((p, flags)) if p == page && flags & PCD != 0 => {} // already mapped as MMIO
            Some(_) => return Err(VmmError::Map(MapError::Conflict)),
            None => space.map_4k(page, page, WRITE | NX | PCD | PWT)?,
        }
        page += PAGE_4K;
    }
    Ok(phys)
}

/// Leaf flags of a virtual address in the active space, `None` when unmapped.
pub fn flags_of(virt: u64) -> Option<u64> {
    AddressSpace::current().translate(virt).map(|(_, f)| f)
}

pub const fn is_writable(flags: u64) -> bool {
    flags & WRITE != 0
}
pub const fn is_nx(flags: u64) -> bool {
    flags & NX != 0
}
