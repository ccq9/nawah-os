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
//! - Device registers (MMIO) in their own window (`MMIO_BASE`, PML4 slot 336), mapped
//!   uncacheable by `map_mmio` on demand (LAPIC/IOAPIC in WP-10, ECAM and virtio BARs in
//!   WP-18). The window is a kernel slot, so every user space shares it: a BAR that lives in
//!   the lower half (OVMF puts the 64-bit aperture at 0xC0_0000_0000, PML4 slot 1 = the user
//!   range) must not be mapped at its own address — CI run 39110182649 faulted on the first
//!   file syscall exactly that way.
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
use crate::sync::IrqSpinLock;

/// Virtual area for kernel stacks (PML4 slot 288): each slot is `STACK_SLOT` bytes and starts
/// with an unmapped guard page.
pub const STACK_AREA_BASE: u64 = 0xFFFF_9000_0000_0000;
/// Kernel dynamic mappings (PML4 slot 320): page-granular `map_page`/`unmap_page` users.
pub const SCRATCH_BASE: u64 = 0xFFFF_A000_0000_0000;
pub const SCRATCH_END: u64 = 0xFFFF_A080_0000_0000;
/// Device registers (PML4 slot 336): `map_mmio` hands out page-aligned ranges from here, in
/// order, never reused (devices are not unmapped in this kernel).
pub const MMIO_BASE: u64 = 0xFFFF_A800_0000_0000;
pub const MMIO_END: u64 = 0xFFFF_A880_0000_0000;
/// Distinct physical ranges `map_mmio` can hold (ECAM pages, LAPIC, IOAPIC, BARs).
const MMIO_RANGES: usize = 64;
/// PML4 slots whose tables exist in the kernel space from the start, so every space derived from
/// it shares them by table and kernel mappings never create a PML4 entry later: 256 direct map,
/// 288 stacks, 320 scratch, 336 MMIO (slot 0, the identity map, exists too).
pub const KERNEL_PML4_SLOTS: [u64; 4] = [256, 288, 320, 336];
pub const KERNEL_STACK_SIZE: u64 = 64 * 1024;
pub const DF_STACK_SIZE: u64 = 16 * 1024;
const STACK_SLOT: u64 = 128 * 1024;
/// Stack slots handed out (a bitmap: slot i = word i/64, bit i%64); freed slots are reused so
/// a thread that comes and goes leaves the page tables as they were (WP-15).
const STACK_SLOTS: usize = 1024;

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
    /// Every stack slot is in use.
    NoStackSlot,
    /// The MMIO window's range table is full, or the window itself is exhausted.
    NoMmioRange,
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
            VmmError::NoStackSlot => "K_E_VMM_NO_STACK_SLOT",
            VmmError::NoMmioRange => "K_E_VMM_NO_MMIO_RANGE",
        }
    }
}

static KERNEL_SPACE: BootCell<Option<KernelSpace>> = BootCell::new(None);

struct StackSlots {
    used: [u64; STACK_SLOTS / 64],
}

impl StackSlots {
    /// Slots 0 and 1 are the kernel and #DF stacks (mapped by `init`).
    const fn boot() -> Self {
        let mut used = [0u64; STACK_SLOTS / 64];
        used[0] = 0b11;
        Self { used }
    }

    fn alloc(&mut self) -> Option<u64> {
        for (w, word) in self.used.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = word.trailing_ones();
                *word |= 1 << bit;
                return Some(w as u64 * 64 + u64::from(bit));
            }
        }
        None
    }

    fn free(&mut self, slot: u64) {
        let (w, bit) = ((slot / 64) as usize, slot % 64);
        if w < self.used.len() {
            self.used[w] &= !(1 << bit);
        }
    }
}

/// Stack slots in use; taken from thread context and from the scheduler's reaper.
static STACK_SLOTS_USED: IrqSpinLock<StackSlots> =
    IrqSpinLock::new("stack_slots", StackSlots::boot());

/// One physical range mapped in the MMIO window (page-aligned ends).
#[derive(Clone, Copy)]
struct MmioRange {
    phys: u64,
    len: u64,
    virt: u64,
}

/// The MMIO window: a bump pointer and the ranges handed out, so a second request for a range
/// already mapped (the same BAR for several capabilities) yields the same address.
struct MmioWindow {
    next: u64,
    n: usize,
    ranges: [MmioRange; MMIO_RANGES],
}

impl MmioWindow {
    const fn boot() -> Self {
        Self {
            next: MMIO_BASE,
            n: 0,
            ranges: [MmioRange {
                phys: 0,
                len: 0,
                virt: 0,
            }; MMIO_RANGES],
        }
    }

    /// `Ok(Some(virt))` when `[start, end)` lies inside a mapped range, `Err` when it overlaps
    /// one partially (never remapped), `Ok(None)` when it is new.
    fn find(&self, start: u64, end: u64) -> Result<Option<u64>, VmmError> {
        for r in &self.ranges[..self.n] {
            let r_end = r.phys + r.len;
            if start >= r.phys && end <= r_end {
                return Ok(Some(r.virt + (start - r.phys)));
            }
            if start < r_end && end > r.phys {
                return Err(VmmError::Map(MapError::Conflict));
            }
        }
        Ok(None)
    }
}

static MMIO_WINDOW: IrqSpinLock<MmioWindow> = IrqSpinLock::new("mmio", MmioWindow::boot());

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
/// unmapped guard page. On failure the pages mapped so far are unmapped and freed again.
fn map_stack(space: &AddressSpace, slot: u64, size: u64) -> Result<StackInfo, VmmError> {
    let guard = STACK_AREA_BASE + slot * STACK_SLOT;
    let base = guard + PAGE_4K;
    let mut off = 0;
    while off < size {
        let Some(f) = pmm::alloc_frame() else {
            unmap_stack_pages(space, base, off);
            return Err(MapError::OutOfFrames.into());
        };
        if let Err(e) = space.map_4k(base + off, f.0, WRITE | NX) {
            let _ = pmm::free_frame(f);
            unmap_stack_pages(space, base, off);
            return Err(e.into());
        }
        off += PAGE_4K;
    }
    Ok(StackInfo { base, size, guard })
}

/// Unmaps `[base, base + len)` page by page, flushing each entry, and frees the frames.
fn unmap_stack_pages(space: &AddressSpace, base: u64, len: u64) {
    let mut va = base;
    while va < base + len {
        if let Ok(Some(phys)) = space.unmap_4k(va) {
            paging::invlpg(va);
            let _ = pmm::free_frame(pmm::Frame(phys));
        }
        va += PAGE_4K;
    }
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
    for slot in KERNEL_PML4_SLOTS {
        space.ensure_pdpt(slot)?;
    }
    // The first 2 MiB of the scratch area get their tables now: page-granular mappings there
    // (self-check, tests, early drivers) then allocate no table frames, and unmap leaves none
    // behind. Tables for the rest of the area are allocated on first use and retained.
    space.ensure_pt(SCRATCH_BASE)?;
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

/// Maps another guarded kernel stack of `size` bytes (page multiple) in a free stack slot;
/// visible in every address space because the stack area's PML4 slot is shared.
pub fn alloc_kernel_stack(size: u64) -> Result<StackInfo, VmmError> {
    if size == 0 || !size.is_multiple_of(PAGE_4K) || size + PAGE_4K > STACK_SLOT {
        return Err(VmmError::Map(MapError::Unaligned));
    }
    let space = kernel_as()?;
    let slot = STACK_SLOTS_USED
        .lock()
        .alloc()
        .ok_or(VmmError::NoStackSlot)?;
    match map_stack(&space, slot, size) {
        Ok(info) => Ok(info),
        Err(e) => {
            STACK_SLOTS_USED.lock().free(slot);
            Err(e)
        }
    }
}

/// Unmaps a kernel stack made by `alloc_kernel_stack`, frees its frames and returns its slot
/// for reuse. The stack must not be in use (not the caller's, not a live thread's).
pub fn free_kernel_stack(stack: StackInfo) {
    let Ok(space) = kernel_as() else {
        return;
    };
    unmap_stack_pages(&space, stack.base, stack.size);
    let slot = (stack.guard - STACK_AREA_BASE) / STACK_SLOT;
    if slot >= 2 {
        STACK_SLOTS_USED.lock().free(slot);
    }
}

/// Direct-map address of a physical address.
pub const fn direct(phys: u64) -> u64 {
    DIRECT_MAP_BASE + phys
}

/// Maps `[phys, phys + len)` of device memory (MMIO) in the kernel's MMIO window, uncacheable
/// (PCD|PWT), RW + NX, through the kernel space's tables (the window's PML4 slot is shared, so
/// the mapping is visible under every CR3); returns the virtual address of `phys`. Pages are
/// 4 KiB; a range already mapped is returned again, a range overlapping one partially is
/// refused (`Conflict`) rather than remapped. New entries need no TLB flush: not-present
/// translations are never cached (SDM Vol. 3A §4.10.2.3).
pub fn map_mmio(phys: u64, len: u64) -> Result<u64, VmmError> {
    if len == 0 {
        return Err(VmmError::Map(MapError::Unaligned));
    }
    let space = kernel_as()?;
    let start = phys & !(PAGE_4K - 1);
    let end = (phys + len).next_multiple_of(PAGE_4K);
    let mut w = MMIO_WINDOW.lock();
    if let Some(virt) = w.find(start, end)? {
        return Ok(virt + (phys - start));
    }
    if w.n == MMIO_RANGES || w.next + (end - start) > MMIO_END {
        return Err(VmmError::NoMmioRange);
    }
    let virt = w.next;
    let mut page = start;
    while page < end {
        if let Err(e) = space.map_4k(virt + (page - start), page, WRITE | NX | PCD | PWT) {
            // Leave nothing behind: the pages mapped so far go away again.
            let mut done = start;
            while done < page {
                let _ = space.unmap_4k(virt + (done - start));
                done += PAGE_4K;
            }
            return Err(e.into());
        }
        page += PAGE_4K;
    }
    let n = w.n;
    w.ranges[n] = MmioRange {
        phys: start,
        len: end - start,
        virt,
    };
    w.n = n + 1;
    w.next += end - start;
    Ok(virt + (phys - start))
}

/// Where the MMIO window stands: `(ranges, bytes)` handed out so far.
pub fn mmio_usage() -> (usize, u64) {
    let w = MMIO_WINDOW.lock();
    (w.n, w.next - MMIO_BASE)
}

/// Leaf flags of a virtual address in the active space, `None` when unmapped.
pub fn flags_of(virt: u64) -> Option<u64> {
    AddressSpace::current().translate(virt).map(|(_, f)| f)
}

fn kernel_as() -> Result<AddressSpace, VmmError> {
    let ks = kernel_space().ok_or(VmmError::Unmapped)?;
    Ok(AddressSpace::from_pml4(ks.cr3, paging::nx_supported()))
}

fn in_scratch(virt: u64) -> Result<(), VmmError> {
    if (SCRATCH_BASE..SCRATCH_END).contains(&virt) && virt.is_multiple_of(PAGE_4K) {
        Ok(())
    } else {
        Err(VmmError::Map(MapError::Unaligned))
    }
}

/// Maps `phys` at the scratch address `virt` in the kernel space (shared by every address
/// space through its PML4 slot). `flags`: WRITE/NX as wanted; PRESENT is added.
pub fn map_page(virt: u64, phys: u64, flags: u64) -> Result<(), VmmError> {
    in_scratch(virt)?;
    kernel_as()?.map_4k(virt, phys, flags)?;
    Ok(())
}

/// Removes the scratch mapping at `virt` and invalidates it on this CPU; returns the physical
/// address that was mapped (the frame stays the caller's).
pub fn unmap_page(virt: u64) -> Result<Option<u64>, VmmError> {
    in_scratch(virt)?;
    let phys = kernel_as()?.unmap_4k(virt)?;
    paging::invlpg(virt);
    Ok(phys)
}

/// Changes the flags of the scratch mapping at `virt` and invalidates it on this CPU.
pub fn protect_page(virt: u64, flags: u64) -> Result<(), VmmError> {
    in_scratch(virt)?;
    kernel_as()?.protect_4k(virt, flags)?;
    paging::invlpg(virt);
    Ok(())
}

pub const fn is_writable(flags: u64) -> bool {
    flags & WRITE != 0
}
pub const fn is_nx(flags: u64) -> bool {
    flags & NX != 0
}
