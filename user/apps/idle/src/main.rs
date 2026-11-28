//! idle — a process that blocks forever in object_wait_many (WP-40, TST-M5-PROCESS-KILL): it
//! waits on its bootstrap channel, whose peer the parent keeps open and silent, so only
//! `process_kill` ends it — through the wait returning to the kill safe point. Never exits on
//! its own; 0xE0 if it has no bootstrap handle. It waits for the peer's close alone, never for
//! a message (WP-84, TST-M6-BOOT-HALT: placed as the service manager it is a manager that never
//! answers and stays blocked; woken by a message it never reads it would spin: the case of a
//! manager that spins is the `spin` application's, in that test's third phase, since WP-99).
#![no_std]
#![no_main]
use libnawah::{WaitEntry, SIGNAL_PEER_CLOSED, TIMEOUT_FOREVER};
libnawah::entry!(main);
fn main() -> u64 {
    let ch = libnawah::bootstrap_handle();
    if ch == 0 {
        return 0xE0;
    }
    loop {
        let _ = libnawah::object_wait_many(
            &[WaitEntry {
                handle: ch,
                signals: SIGNAL_PEER_CLOSED,
            }],
            TIMEOUT_FOREVER,
        );
    }
}
