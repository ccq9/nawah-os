//! Volatile accessors for memory-mapped I/O (WP-18). The addresses come from `vmm::map_mmio`
//! (identity-mapped, uncacheable); callers pass register offsets that respect each register's
//! natural alignment. These are the only `unsafe` lines the PCI and virtio code needs.

/// Reads a byte register at `addr` (a mapped MMIO address).
pub fn read8(addr: u64) -> u8 {
    // SAFETY: the address was returned by map_mmio (mapped, uncacheable) by the caller's
    // contract; a byte read has no alignment requirement.
    unsafe { (addr as *const u8).read_volatile() }
}

/// Reads a 16-bit register at `addr` (2-byte aligned).
pub fn read16(addr: u64) -> u16 {
    // SAFETY: mapped MMIO address (caller's contract), naturally aligned.
    unsafe { (addr as *const u16).read_volatile() }
}

/// Reads a 32-bit register at `addr` (4-byte aligned).
pub fn read32(addr: u64) -> u32 {
    // SAFETY: mapped MMIO address (caller's contract), naturally aligned.
    unsafe { (addr as *const u32).read_volatile() }
}

/// Writes a byte register.
pub fn write8(addr: u64, v: u8) {
    // SAFETY: mapped MMIO address (caller's contract); writes reach the device, not memory
    // the compiler reasons about.
    unsafe { (addr as *mut u8).write_volatile(v) }
}

/// Writes a 16-bit register (2-byte aligned).
pub fn write16(addr: u64, v: u16) {
    // SAFETY: as write8, naturally aligned.
    unsafe { (addr as *mut u16).write_volatile(v) }
}

/// Writes a 32-bit register (4-byte aligned).
pub fn write32(addr: u64, v: u32) {
    // SAFETY: as write8, naturally aligned.
    unsafe { (addr as *mut u32).write_volatile(v) }
}
