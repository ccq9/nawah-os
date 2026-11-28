//! User address spaces (WP-13, ADR-0007). A user space is its own PML4 whose entries 256..=511
//! (direct map, kernel stacks) and entry 0 (the identity map of RAM with the kernel image, all
//! supervisor-only) are copied from the kernel space; user mappings live in PML4 slots 1..=255
//! (`USER_BASE..USER_END`), so every table below those slots belongs to the space and is freed
//! with it. Switching CR3 therefore keeps the kernel runnable and leaves ring 3 no view of
//! kernel memory (no U/S bit anywhere on the shared paths).

use alloc::vec::Vec;

use alloc::sync::Arc;

use crate::arch::paging::{self, AddressSpace, MapError, NX, PAGE_4K, PCD, PWT, USER, WRITE};
use crate::mm::pmm::{self, Frame};
use crate::mm::vmm;
use crate::object::job::{self, Charge, Job};
use crate::object::Vmo;

/// User mappings of VMOs (WP-32, ipc.md v1.1 / syscall.md §7): the region above the
/// application window and the stack, one page directory's 512 slots of 2 MiB (WP-177). A
/// mapping takes the lowest run of free slots it fits in, so it has page tables of its own,
/// freed with it, and its slots are free again once it goes; at most `MAX_MAPPINGS` per process.
pub const MAP_BASE: u64 = USER_BASE + 0x4000_0000;
pub const MAP_END: u64 = USER_BASE + 0x8000_0000;
pub const MAX_MAPPINGS: usize = 64;
/// One slot of the mapping region: the 2 MiB one page table maps.
const SLOT: u64 = paging::PAGE_2M;
const SLOTS: usize = ((MAP_END - MAP_BASE) / SLOT) as usize;

/// One mapped VMO: the object stays alive (its frames with it) as long as the mapping does —
/// the `Arc` is held for that alone — and so does the charge of its page tables, one per slot
/// (WP-177), given back after they are freed.
struct Mapping {
    virt: u64,
    pages: u64,
    #[allow(dead_code)]
    vmo: Arc<Vmo>,
    #[allow(dead_code)]
    tables: Charge,
}

/// The slots a mapping of `pages` pages takes (WP-177).
const fn slots_for(pages: u64) -> usize {
    pages.div_ceil(SLOT / PAGE_4K) as usize
}

/// Lowest user address: PML4 slot 1.
pub const USER_BASE: u64 = 0x80_0000_0000;
/// One past the highest user address: end of PML4 slot 255 (lower canonical half).
pub const USER_END: u64 = 0x8000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsError {
    Map(MapError),
    /// Address outside `USER_BASE..USER_END` or not page-aligned.
    Range,
    KernelSpaceNotActive,
    /// The space is the active one; it cannot be destroyed.
    Active,
    /// No thread could be created for the space (kernel stack or scheduler refusal).
    Spawn,
    /// The image's pages, or a mapping's page tables (WP-177), are beyond its job's quota or
    /// the system's limit (syscall.md v1.16).
    Quota,
}

impl From<MapError> for AsError {
    fn from(e: MapError) -> Self {
        AsError::Map(e)
    }
}

impl AsError {
    pub fn code(&self) -> &'static str {
        match self {
            AsError::Map(MapError::OutOfFrames) => "K_E_AS_OUT_OF_FRAMES",
            AsError::Map(MapError::Conflict) => "K_E_AS_MAP_CONFLICT",
            AsError::Map(MapError::Unaligned) => "K_E_AS_UNALIGNED",
            AsError::Range => "K_E_AS_RANGE",
            AsError::KernelSpaceNotActive => "K_E_AS_NO_KERNEL_SPACE",
            AsError::Active => "K_E_AS_ACTIVE",
            AsError::Spawn => "K_E_SPAWN_FAILED",
            AsError::Quota => "K_E_AS_QUOTA",
        }
    }
}

pub struct UserSpace {
    space: AddressSpace,
    /// Frames mapped as user pages, returned to the allocator on destroy.
    pages: Vec<Frame>,
    /// VMO mappings (their frames belong to the objects, not to this space).
    mappings: Vec<Mapping>,
    /// The mapping region's slots in use, one bit each (WP-177).
    slots: [u64; SLOTS / 64],
    /// The charges of the tables above the region's page tables — its page directory, and the
    /// page-directory-pointer table when a mapping made it — one page each, taken by the mapping
    /// that made them and given back in `destroy` after they are freed (WP-177).
    upper: Vec<Charge>,
    /// The image's pages charged to the process's job (syscall.md v1.16), given back in
    /// `destroy` after the pages are freed.
    charge: Option<crate::object::job::Charge>,
}

impl UserSpace {
    /// A new, empty user space sharing the kernel entries.
    pub fn new() -> Result<Self, AsError> {
        let ks = vmm::kernel_space().ok_or(AsError::KernelSpaceNotActive)?;
        let kernel = AddressSpace::from_pml4(ks.cr3, paging::nx_supported());
        let space = AddressSpace::new()?;
        space.set_pml4_entry(0, kernel.pml4_entry(0));
        for i in 256..512 {
            space.set_pml4_entry(i, kernel.pml4_entry(i));
        }
        Ok(Self {
            space,
            pages: Vec::new(),
            mappings: Vec::new(),
            slots: [0; SLOTS / 64],
            upper: Vec::new(),
            charge: None,
        })
    }

    /// Keeps the image's charge (v1.16) until `destroy` has freed the pages it stands for.
    pub fn hold(&mut self, charge: crate::object::job::Charge) {
        self.charge = Some(charge);
    }

    /// The job this space's tables are charged to (WP-177): its image's (v1.16), or the root
    /// (counted, never refused) for a space without a charged image.
    fn job(&self) -> Arc<Job> {
        self.charge
            .as_ref()
            .map_or_else(job::root, |c| c.job().clone())
    }

    fn used(&self, s: usize) -> bool {
        self.slots[s / 64] & (1 << (s % 64)) != 0
    }

    /// The lowest run of `k` free slots of the mapping region.
    fn free_run(&self, k: usize) -> Option<usize> {
        (0..=SLOTS.checked_sub(k)?).find(|&s| (s..s + k).all(|i| !self.used(i)))
    }

    fn mark(&mut self, s: usize, k: usize, on: bool) {
        for i in s..s + k {
            if on {
                self.slots[i / 64] |= 1 << (i % 64);
            } else {
                self.slots[i / 64] &= !(1 << (i % 64));
            }
        }
    }

    /// Frees the page tables of the `k` slots from `virt` (WP-177). Each is unhooked from the
    /// page directory first; the space's translations are then dropped when it is the active one
    /// (no other CPU holds them: a process has one thread, and the scheduler loads CR3 on every
    /// switch to another space); only then are the frames given back.
    fn free_tables(&self, virt: u64, k: usize) {
        let taken: Vec<u64> = (0..k as u64)
            .filter_map(|i| self.space.take_pt(virt + i * SLOT))
            .collect();
        if paging::read_cr3() == self.space.pml4 {
            paging::switch_cr3(self.space.pml4);
        }
        for pt in taken {
            let _ = pmm::free_frame(Frame(pt));
        }
    }

    /// Maps every frame of `vmo` at the lowest free slots of the mapping region, read-only or
    /// writable, cached (RAM) or uncacheable (a physical VMO over device memory), never
    /// executable; returns the address. The object is held until the mapping goes.
    pub fn map_vmo(&mut self, vmo: Arc<Vmo>, writable: bool, cached: bool) -> Result<u64, AsError> {
        let pages = vmo.size() / PAGE_4K;
        if pages == 0 || self.mappings.len() >= MAX_MAPPINGS {
            return Err(AsError::Range);
        }
        let k = slots_for(pages);
        let s = self.free_run(k).ok_or(AsError::Range)?;
        let virt = MAP_BASE + s as u64 * SLOT;
        // The tables are charged before any frame is taken (WP-177): a page table per slot, held
        // by the mapping, and the tables above them that this mapping makes, held by the space.
        let job = self.job();
        let upper = self.space.missing_upper(virt);
        let mut above = Vec::new();
        for _ in 0..upper {
            above.push(job.charge(1).ok_or(AsError::Quota)?);
        }
        let tables = job.charge(k as u64).ok_or(AsError::Quota)?;
        let mut flags = USER | NX;
        if writable {
            flags |= WRITE;
        }
        if !cached {
            flags |= PCD | PWT;
        }
        for (i, f) in vmo.frames().iter().enumerate() {
            let page = virt + i as u64 * PAGE_4K;
            if let Err(e) = self.space.map_4k(page, f.0, flags) {
                // Nothing stays behind: the pages mapped so far go away again, and the page
                // tables with them; the tables above that were made stay until `destroy`, and
                // their charges with them.
                for j in 0..i {
                    let _ = self.space.unmap_4k(virt + j as u64 * PAGE_4K);
                }
                self.free_tables(virt, k);
                let made = upper.saturating_sub(self.space.missing_upper(virt));
                above.truncate(made as usize);
                self.upper.append(&mut above);
                return Err(e.into());
            }
        }
        self.upper.append(&mut above);
        self.mark(s, k, true);
        self.mappings.push(Mapping {
            virt,
            pages,
            vmo,
            tables,
        });
        Ok(virt)
    }

    /// Removes the mapping that starts at `virt` (its pages are invalidated on this CPU, the
    /// one the process's thread runs on) and releases the object reference.
    pub fn unmap_vmo(&mut self, virt: u64) -> Result<(), AsError> {
        let Some(i) = self.mappings.iter().position(|m| m.virt == virt) else {
            return Err(AsError::Range);
        };
        let m = self.mappings.swap_remove(i);
        for j in 0..m.pages {
            let page = m.virt + j * PAGE_4K;
            let _ = self.space.unmap_4k(page);
            paging::invlpg(page);
        }
        // Its page tables are freed and its slots free again (WP-177); its object and the
        // tables' charge go with it.
        let (s, k) = (((m.virt - MAP_BASE) / SLOT) as usize, slots_for(m.pages));
        self.free_tables(m.virt, k);
        self.mark(s, k, false);
        drop(m);
        Ok(())
    }

    pub const fn cr3(&self) -> u64 {
        self.space.pml4
    }

    fn check(virt: u64) -> Result<(), AsError> {
        if !virt.is_multiple_of(PAGE_4K) || !(USER_BASE..USER_END).contains(&virt) {
            return Err(AsError::Range);
        }
        Ok(())
    }

    /// Maps a fresh zeroed frame at `virt` with `flags` (USER is added) and returns its physical
    /// address.
    pub fn map_new_page(&mut self, virt: u64, flags: u64) -> Result<u64, AsError> {
        Self::check(virt)?;
        let f = pmm::alloc_frame().ok_or(MapError::OutOfFrames)?;
        // Zero through the direct map before the page is visible anywhere.
        let p = vmm::direct(f.0) as *mut u8;
        // SAFETY: a fresh frame, reached through the direct map, owned by this space from now on.
        unsafe { core::ptr::write_bytes(p, 0, PAGE_4K as usize) };
        if let Err(e) = self.space.map_4k(virt, f.0, flags | USER) {
            let _ = pmm::free_frame(f);
            return Err(e.into());
        }
        self.pages.push(f);
        Ok(f.0)
    }

    /// Test-only (WP-177): the mapping region's page tables now, its page directory counted.
    #[cfg(feature = "ktest")]
    pub fn region_tables(&self) -> u64 {
        self.space.tables_under(MAP_BASE)
    }

    /// Test-only (WP-177): the mapping region's free 2 MiB slots now, as the next `map_vmo`
    /// sees them.
    #[cfg(feature = "ktest")]
    pub fn free_slots(&self) -> u64 {
        (0..SLOTS).filter(|&s| !self.used(s)).count() as u64
    }

    /// Leaf flags of `virt` in this space, `None` when unmapped.
    pub fn flags_of(&self, virt: u64) -> Option<u64> {
        self.space.translate(virt).map(|(_, f)| f)
    }

    /// Makes this space the active one. The kernel keeps running (shared entries).
    pub fn activate(&self) {
        // SAFETY: entries 0 and 256..=511 were copied from the kernel space in `new`, so the
        // kernel's code, stacks and data stay mapped.
        unsafe { self.space.switch_to() };
    }

    /// Frees every table and page the space owns. Refused while the space is active.
    pub fn destroy(mut self) -> Result<u64, AsError> {
        if paging::read_cr3() == self.space.pml4 {
            return Err(AsError::Active);
        }
        // The shared entries must not be torn down: clear them first.
        self.space.set_pml4_entry(0, 0);
        for i in 256..512 {
            self.space.set_pml4_entry(i, 0);
        }
        let pages = self.pages.len() as u64;
        // Leaves were recorded in `pages`; teardown frees tables only, then the pages. VMO
        // mappings' frames are the objects' (released with the last reference), so only their
        // tables go here (teardown frees tables, never leaves).
        let mut freed = self.space.teardown(1, 256, false);
        for f in self.pages {
            if pmm::free_frame(f).is_ok() {
                freed += 1;
            }
        }
        // The mappings' objects go once no table maps their frames, and the region's tables'
        // charges once those tables are free (WP-177).
        self.mappings.clear();
        self.upper.clear();
        // The image's pages come back to the job once its frames are free (v1.16).
        drop(self.charge.take());
        debug_assert!(freed >= pages);
        Ok(freed)
    }
}

/// Copies `bytes` to the start of the frame `phys` through the direct map (loading code or data
/// into a page before the space runs).
pub fn write_frame(phys: u64, bytes: &[u8]) {
    let n = bytes.len().min(PAGE_4K as usize);
    // SAFETY: `phys` is a frame this kernel allocated and mapped in the direct map; at most one
    // page is written.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), vmm::direct(phys) as *mut u8, n) };
}

/// Copies `bytes` into the frame `phys` starting at byte `offset` through the direct map; the
/// range must end within the frame (loader segments are page-sliced by the caller).
pub fn write_frame_at(phys: u64, offset: usize, bytes: &[u8]) {
    assert!(
        offset + bytes.len() <= PAGE_4K as usize,
        "write past the frame"
    );
    // SAFETY: `phys` is a frame this kernel allocated and mapped in the direct map; the range
    // stays inside it (asserted).
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (vmm::direct(phys) as *mut u8).add(offset),
            bytes.len(),
        )
    };
}

/// Switches back to the kernel's own space.
pub fn activate_kernel() {
    if let Some(ks) = vmm::kernel_space() {
        let kernel = AddressSpace::from_pml4(ks.cr3, paging::nx_supported());
        // SAFETY: the kernel space maps everything the kernel needs by construction.
        unsafe { kernel.switch_to() };
    }
}

/// Zeroes the frame `phys` through the direct map (a VMO frame before it can be mapped by a
/// user process: no stale contents ever reach user space).
pub fn zero_frame(phys: u64) {
    let p = vmm::direct(phys) as *mut u8;
    // SAFETY: a frame the caller owns, reached through the direct map, not mapped anywhere yet.
    unsafe { core::ptr::write_bytes(p, 0, PAGE_4K as usize) };
}
