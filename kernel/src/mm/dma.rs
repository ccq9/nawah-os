//! Access to frames a driver owns for DMA (WP-18): volatile reads/writes and byte views
//! through the direct map. The frames come from `pmm::alloc_frames`, belong to one driver and
//! are shared with a device, so every access is volatile and the compiler never caches them.

use crate::mm::vmm;

/// Reads a 16-bit value at physical address `phys` (2-byte aligned) inside an owned frame.
pub fn read16(phys: u64) -> u16 {
    // SAFETY: `phys` lies in a frame the caller owns and the direct map covers all RAM.
    unsafe { (vmm::direct(phys) as *const u16).read_volatile() }
}

/// Reads a 32-bit value (4-byte aligned).
pub fn read32(phys: u64) -> u32 {
    // SAFETY: as read16.
    unsafe { (vmm::direct(phys) as *const u32).read_volatile() }
}

pub fn write16(phys: u64, v: u16) {
    // SAFETY: as read16; the frame is the caller's to write.
    unsafe { (vmm::direct(phys) as *mut u16).write_volatile(v) }
}

pub fn write32(phys: u64, v: u32) {
    // SAFETY: as write16, 4-byte aligned.
    unsafe { (vmm::direct(phys) as *mut u32).write_volatile(v) }
}

pub fn write64(phys: u64, v: u64) {
    // SAFETY: as write16, 8-byte aligned.
    unsafe { (vmm::direct(phys) as *mut u64).write_volatile(v) }
}

/// A byte view of `[phys, phys + len)` inside owned frames. The caller holds the device lock
/// while the view lives, so the device does not write the range meanwhile.
pub fn bytes_mut<'a>(phys: u64, len: usize) -> &'a mut [u8] {
    // SAFETY: owned, mapped frames (caller's contract); the view is unique while the device
    // lock is held and `len` stays inside the owned range.
    unsafe { core::slice::from_raw_parts_mut(vmm::direct(phys) as *mut u8, len) }
}
