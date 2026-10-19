//! exiter — a process whose very first system call is `exit` (review 2026-10-19,
//! TST-M5-KILL-EDGES): `main` returns at once, so the entry stub's `exit(0x55)` is the first time
//! it enters the kernel. Killed before it ever ran, it must still report EXIT_KILLED, not 0x55 —
//! a kill is not undone by the process exiting before it reaches a safe point (defect K2).

#![no_std]
#![no_main]

libnawah::entry!(main);

fn main() -> u64 {
    0x55
}
