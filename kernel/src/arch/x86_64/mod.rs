//! x86_64.

use core::arch::asm;

mod port;
pub mod qemu;
mod serial;

pub use serial::Serial;

/// Initialises the diagnostic channel (COM1).
pub fn init_console() {
    Serial::init();
}

/// Stops the CPU for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: cli then hlt touch neither memory nor the stack; stopping the CPU is the point.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
