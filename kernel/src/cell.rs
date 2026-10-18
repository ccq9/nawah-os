//! A cell for `static` data written only during boot.
//! Origin: Sol OS (commit d54f0a5) `src/cell.rs`, re-reviewed here.

use core::cell::UnsafeCell;

/// Container for `static` data that is written during the boot path and read-only afterwards.
///
/// Replaces `static mut`: access always goes through the raw pointer from [`BootCell::get`],
/// so no overlapping references are created by accident.
///
/// Contract every user must keep:
/// 1. Writes happen on the boot path only: one CPU, interrupts disabled.
/// 2. After initialisation nobody writes to the cell, except hardware/firmware where a
///    comment says so.
#[repr(transparent)]
pub struct BootCell<T>(UnsafeCell<T>);

// SAFETY: the contract above rules out two concurrent accesses of which one is a write: writes
// happen before any second execution path exists, and everything after that is a read.
unsafe impl<T> Sync for BootCell<T> {}

impl<T> BootCell<T> {
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// Raw pointer to the contents. Reading or writing through it is an unsafe operation the
    /// caller documents.
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}
