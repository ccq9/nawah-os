//! spin — a process that never leaves ring 3 (WP-40, TST-M5-PROCESS-KILL): an infinite busy
//! loop making no system call, so it is ended only by `process_kill` reaching it through the
//! timer preemption. Never exits on its own.
#![no_std]
#![no_main]
libnawah::entry!(main);
fn main() -> u64 {
    loop {
        core::hint::spin_loop();
    }
}
