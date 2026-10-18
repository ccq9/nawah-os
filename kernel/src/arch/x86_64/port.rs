//! I/O ports (`in` and `out`). Origin: Sol OS (d54f0a5) `port.rs`, re-reviewed here.

use core::arch::asm;

/// Writes a byte to an I/O port.
///
/// # Safety
/// The caller guarantees that writing to `port` does not corrupt device state the kernel relies on.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out` touches neither memory nor the stack; port validity is the caller's duty.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

/// Reads a byte from an I/O port.
///
/// # Safety
/// The caller guarantees that reading `port` has no side effect that corrupts device state.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in` touches neither memory nor the stack; port validity is the caller's duty.
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Writes a 16-bit word to an I/O port (fw_cfg selector, test kernel).
///
/// # Safety
/// As for [`outb`].
#[cfg(feature = "ktest")]
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    // SAFETY: `out` touches neither memory nor the stack; port validity is the caller's duty.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags));
    }
}
