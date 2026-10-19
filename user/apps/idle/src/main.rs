//! idle — a process that blocks forever in object_wait_many (WP-40, TST-M5-PROCESS-KILL): it
//! waits on its bootstrap channel, whose peer the parent keeps open and silent, so only
//! `process_kill` ends it — through the wait returning to the kill safe point. Never exits on
//! its own; 0xE0 if it has no bootstrap handle.
#![no_std]
#![no_main]
use libnawah::{WaitEntry, SIGNAL_PEER_CLOSED, SIGNAL_READABLE, TIMEOUT_FOREVER};
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
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            }],
            TIMEOUT_FOREVER,
        );
    }
}
