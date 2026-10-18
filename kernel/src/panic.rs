//! Panic policy (ADR-0006, docs/policies/panic.md): a panic is an invariant violation. It prints
//! one line `OSX|<build>|kernel|panic|loc=<file:line:col>|msg=<message>` and ends the run with
//! the lab exit code 0x11 (QEMU 35); without the lab device the CPU halts. A panic while already
//! panicking writes a fixed line without the formatting machinery and stops.

use core::fmt::Write as _;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch;
use crate::BUILD_ID;

static PANICKING: AtomicBool = AtomicBool::new(false);

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    arch::interrupts::disable();
    if PANICKING.swap(true, Ordering::Relaxed) {
        let _ = arch::Serial.write_str("OSX|?|kernel|panic|nested|stopping\n");
        arch::qemu::exit(arch::qemu::EXIT_PANIC)
    }
    let console_was_locked = crate::console::CONSOLE.is_locked();
    // SAFETY: this path never returns to the code that may hold the console lock.
    unsafe { crate::console::CONSOLE.force_unlock() };
    match info.location() {
        Some(l) => kprintln!(
            "OSX|{}|kernel|panic|loc={}:{}:{}|console_was_locked={}|msg={}",
            BUILD_ID,
            l.file(),
            l.line(),
            l.column(),
            u8::from(console_was_locked),
            info.message()
        ),
        None => kprintln!(
            "OSX|{}|kernel|panic|loc=?|console_was_locked={}|msg={}",
            BUILD_ID,
            u8::from(console_was_locked),
            info.message()
        ),
    }
    arch::qemu::exit(arch::qemu::EXIT_PANIC)
}

/// Boot-critical failure with a classified code (`K_E_*`): same line shape and exit code as a
/// panic, used where continuing would mean running on guesses.
pub fn fatal(code: &str) -> ! {
    panic!("{}", code)
}
