//! waiter — `object_wait_many` and the clock (WP-23, TST-M4-WAIT-TIMEOUT): a wait with no
//! signal times out after its ticks (measured with `clock_ticks`, never early), a zero
//! timeout polls, invalid entries are refused (no signal, unknown signal, zero or too many
//! entries, a VMO, a stale handle, a handle without WAIT, an unmapped pointer), a queued
//! message answers at once with the first asserted index, and a closed peer asserts
//! PEER_CLOSED. Exits `0x71 | measured_ticks << 8`; otherwise the failing step (0xE0..).

#![no_std]
#![no_main]

use libnawah::{
    rights, WaitEntry, ERR_ACCESS, ERR_BAD_HANDLE, ERR_FAULT, ERR_INVALID, ERR_TIMED_OUT,
    ERR_WRONG_TYPE, SIGNAL_PEER_CLOSED, SIGNAL_READABLE, TIMEOUT_FOREVER,
};

libnawah::entry!(main);

const WAIT_TICKS: u64 = 25;

fn entry(handle: u32, signals: u32) -> WaitEntry {
    WaitEntry { handle, signals }
}

fn main() -> u64 {
    let Ok((a, b)) = libnawah::channel_create() else {
        return 0xE0;
    };
    let t0 = libnawah::clock_ticks();
    if libnawah::object_wait_many(&[entry(a, SIGNAL_READABLE)], WAIT_TICKS) != Err(ERR_TIMED_OUT) {
        return 0xE1;
    }
    let t1 = libnawah::clock_ticks();
    let dt = t1.wrapping_sub(t0);
    if dt < WAIT_TICKS {
        return 0xE2;
    }
    if dt > 1000 {
        return 0xE3;
    }
    // A zero timeout polls.
    if libnawah::object_wait_many(&[entry(a, SIGNAL_READABLE)], 0) != Err(ERR_TIMED_OUT) {
        return 0xE4;
    }
    // Invalid entries.
    if libnawah::object_wait_many(&[entry(a, 0)], 0) != Err(ERR_INVALID) {
        return 0xE5;
    }
    if libnawah::object_wait_many(&[entry(a, 8)], 0) != Err(ERR_INVALID) {
        return 0xE6;
    }
    if libnawah::object_wait_many(&[], 0) != Err(ERR_INVALID) {
        return 0xE7;
    }
    let many = [entry(a, SIGNAL_READABLE); 17];
    if libnawah::object_wait_many(&many, 0) != Err(ERR_INVALID) {
        return 0xE8;
    }
    let Ok(vmo) = libnawah::vmo_create(4096) else {
        return 0xE9;
    };
    if libnawah::object_wait_many(&[entry(vmo, SIGNAL_READABLE)], 0) != Err(ERR_WRONG_TYPE) {
        return 0xEA;
    }
    if libnawah::object_wait_many(&[entry(0xDEAD_0000, SIGNAL_READABLE)], 0) != Err(ERR_BAD_HANDLE)
    {
        return 0xEB;
    }
    let Ok(a_nowait) = libnawah::handle_duplicate(a, rights::READ | rights::WRITE) else {
        return 0xEC;
    };
    if libnawah::object_wait_many(&[entry(a_nowait, SIGNAL_READABLE)], 0) != Err(ERR_ACCESS) {
        return 0xED;
    }
    // Entries at an unmapped address.
    let r = libnawah::syscall6(
        libnawah::SYS_OBJECT_WAIT_MANY,
        0x7000_0000_0000,
        1,
        0,
        0,
        0,
        0,
    );
    if r != ERR_FAULT {
        return 0xEE;
    }
    // A queued message answers at once, with the first entry that is asserted.
    if libnawah::channel_write(b, b"x", &[]) != 1 {
        return 0xEF;
    }
    if libnawah::object_wait_many(&[entry(a, SIGNAL_READABLE)], 0) != Ok((0, SIGNAL_READABLE)) {
        return 0xF0;
    }
    let both = [entry(b, SIGNAL_READABLE), entry(a, SIGNAL_READABLE)];
    if libnawah::object_wait_many(&both, TIMEOUT_FOREVER) != Ok((1, SIGNAL_READABLE)) {
        return 0xF1;
    }
    let mut buf = [0u8; 8];
    let mut hs = [0u32; 1];
    if libnawah::channel_read(a, &mut buf, &mut hs, false) != Ok((1, 0)) {
        return 0xF2;
    }
    // The peer closes: PEER_CLOSED, and READABLE stays clear.
    if libnawah::handle_close(b) != 0 {
        return 0xF3;
    }
    if libnawah::object_wait_many(
        &[entry(a, SIGNAL_READABLE | SIGNAL_PEER_CLOSED)],
        TIMEOUT_FOREVER,
    ) != Ok((0, SIGNAL_PEER_CLOSED))
    {
        return 0xF4;
    }
    let t2 = libnawah::clock_ticks();
    if t2 < t1 {
        return 0xF5;
    }
    for h in [a, a_nowait, vmo] {
        if libnawah::handle_close(h) != 0 {
            return 0xF6;
        }
    }
    0x71 | (dt << 8)
}
