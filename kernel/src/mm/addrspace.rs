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
use crate::object::Vmo;

/// User mappings of VMOs (WP-32, ipc.md v1.1 / syscall.md §7): the region above the
/// application window and the stack, handed out upwards; at most `MAX_MAPPINGS` per process.
pub const MAP_BASE: u64 = USER_BASE + 0x4000_0000;
pub const MAP_END: u64 = USER_BASE + 0x8000_0000;
pub const MAX_MAPPINGS: usize = 64;

/// One mapped VMO: the object stays alive (its frames with it) as long as the mapping does —
/// the `Arc` is held for that alone.
struct Mapping {
    virt: u64,
    pages: u64,
    #[allow(dead_code)]
    vmo: Arc<Vmo>,
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
        }
    }
}

pub struct UserSpace {
    space: AddressSpace,
    /// Frames mapped as user pages, returned to the allocator on destroy.
    pages: Vec<Frame>,
    /// VMO mappings (their frames belong to the objects, not to this space).
    mappings: Vec<Mapping>,
    next_map: u64,
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
            next_map: MAP_BASE,
        })
    }

    /// Maps every frame of `vmo` at the next free place of the mapping region, read-only or
    /// writable, cached (RAM) or uncacheable (a physical VMO over device memory), never
    /// executable; returns the address. The object is held until the mapping goes.
    pub fn map_vmo(&mut self, vmo: Arc<Vmo>, writable: bool, cached: bool) -> Result<u64, AsError> {
        let pages = vmo.size() / PAGE_4K;
        if pages == 0 || self.mappings.len() >= MAX_MAPPINGS {
            return Err(AsError::Range);
        }
        let virt = self.next_map;
        if virt + pages * PAGE_4K > MAP_END {
            return Err(AsError::Range);
        }
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
                // Nothing stays behind: the pages mapped so far go away again.
                for j in 0..i {
                    let _ = self.space.unmap_4k(virt + j as u64 * PAGE_4K);
                }
                return Err(e.into());
            }
        }
        self.next_map = virt + pages * PAGE_4K;
        self.mappings.push(Mapping { virt, pages, vmo });
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
        // VMO mappings: their frames are the objects' (released with the last reference), so
        // only the leaves go (teardown frees tables, never leaves).
        self.mappings.clear();
        // Leaves were recorded in `pages`; teardown frees tables only, then the pages.
        let mut freed = self.space.teardown(1, 256, false);
        for f in self.pages {
            if pmm::free_frame(f).is_ok() {
                freed += 1;
            }
        }
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
