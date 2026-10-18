//! hello — the first ELF application (WP-17): says hello on the diagnostic channel, checks a
//! round trip through the kernel, and exits 7 (TST-M3-APP-EXIT-CODE).

#![no_std]
#![no_main]

libnawah::entry!(main);

/// Holds data in .data and .bss so the loader's zero-fill and copy paths are exercised.
static mut COUNTER: u64 = 0;
static GREETING: &[u8] = b"hello from elf";

fn main() -> u64 {
    if libnawah::trace(GREETING) != GREETING.len() as i64 {
        return 0xE0;
    }
    if libnawah::ping(41) != 42 {
        return 0xE1;
    }
    // SAFETY: single-threaded program; the static is touched only here.
    unsafe {
        COUNTER += 7;
        COUNTER
    }
}
