//! Diagnostic output. ASCII only on the serial channel (prompt 3.2 §5). One lock around each
//! line (ADR-0006): lines from different contexts never interleave. Paths that never return
//! (panic, fatal exception) break the lock first (`CONSOLE.force_unlock`), so a fault inside a
//! print still produces its diagnostic.

use core::fmt::{Arguments, Write as _};

use crate::arch::Serial;
use crate::sync::IrqSpinLock;

pub static CONSOLE: IrqSpinLock<()> = IrqSpinLock::new("console", ());

/// Writes one line to COM1. Never blocks the kernel: if the device is absent the bytes are
/// dropped (see `arch::x86_64::serial`).
pub fn println(args: Arguments<'_>) {
    let _guard = CONSOLE.lock();
    let _ = Serial.write_fmt(args);
    let _ = Serial.write_str("\n");
}

macro_rules! kprintln {
    ($($arg:tt)*) => {
        $crate::console::println(format_args!($($arg)*))
    };
}
