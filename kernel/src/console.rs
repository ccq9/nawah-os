//! Diagnostic output. ASCII only on the serial channel (prompt 3.2 §5).

/// Writes one line to COM1 with `format_args!` formatting. Never blocks the kernel: if the
/// device is absent the bytes are dropped (see `arch::x86_64::serial`).
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = writeln!($crate::arch::Serial, $($arg)*);
    }};
}
