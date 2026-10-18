//! child — the process object (WP-23, TST-M4-CHILD-EXIT): `process_status` answers
//! ERR_SHOULD_WAIT while the child runs, a wait for EXITED times out while it is blocked and
//! returns at once after it exits, duplicates of the handle see the same exit, the exit code
//! is the child's, a wait on an already exited process does not block, and a child whose
//! process handle was closed early still runs to its end (seen through PEER_CLOSED). Exits
//! 0x72 at the end; otherwise the failing step (0xE0..).

#![no_std]
#![no_main]

use libnawah::{
    rights, WaitEntry, ERR_BAD_HANDLE, ERR_SHOULD_WAIT, ERR_TIMED_OUT, SIGNAL_EXITED,
    SIGNAL_PEER_CLOSED, SIGNAL_READABLE, TIMEOUT_FOREVER,
};

libnawah::entry!(main);

const ECHO: &[u8] = b"/SYSTEM/ECHO.ELF";
const MSG: &[u8] = b"hello child";

fn wait_one(h: u32, signals: u32, timeout: u64) -> Result<(usize, u32), i64> {
    libnawah::object_wait_many(&[WaitEntry { handle: h, signals }], timeout)
}

fn main() -> u64 {
    let Ok((a, b)) = libnawah::channel_create() else {
        return 0xE0;
    };
    let Ok(p) = libnawah::process_spawn(ECHO, &[b]) else {
        return 0xE1;
    };
    // The child blocks in its read: not exited.
    if libnawah::process_status(p) != Err(ERR_SHOULD_WAIT) {
        return 0xE2;
    }
    let Ok(p2) = libnawah::handle_duplicate(p, rights::WAIT) else {
        return 0xE3;
    };
    if wait_one(p, SIGNAL_EXITED, 30) != Err(ERR_TIMED_OUT) {
        return 0xE4;
    }
    if libnawah::channel_write(a, MSG, &[]) != MSG.len() as i64 {
        return 0xE5;
    }
    if wait_one(p2, SIGNAL_EXITED, TIMEOUT_FOREVER) != Ok((0, SIGNAL_EXITED)) {
        return 0xE6;
    }
    let code = Ok(MSG.len() as u64);
    if libnawah::process_status(p) != code || libnawah::process_status(p2) != code {
        return 0xE7;
    }
    // Already exited: a zero timeout still answers.
    if wait_one(p, SIGNAL_EXITED, 0) != Ok((0, SIGNAL_EXITED)) {
        return 0xE8;
    }
    let mut buf = [0u8; 64];
    let mut hs = [0u32; 1];
    match libnawah::channel_read(a, &mut buf, &mut hs, false) {
        Ok((n, 0)) if &buf[..n] == MSG => {}
        _ => return 0xE9,
    }
    if wait_one(a, SIGNAL_PEER_CLOSED, 0) != Ok((0, SIGNAL_PEER_CLOSED)) {
        return 0xEA;
    }
    if libnawah::handle_close(p) != 0 || libnawah::handle_close(p2) != 0 {
        return 0xEB;
    }
    if libnawah::process_status(p) != Err(ERR_BAD_HANDLE) {
        return 0xEC;
    }
    // A child nobody holds a process handle for still runs to its end.
    let Ok((c, d)) = libnawah::channel_create() else {
        return 0xED;
    };
    let Ok(q) = libnawah::process_spawn(ECHO, &[d]) else {
        return 0xEE;
    };
    if libnawah::handle_close(q) != 0 {
        return 0xEF;
    }
    if libnawah::channel_write(c, b"bye", &[]) != 3 {
        return 0xF0;
    }
    match wait_one(c, SIGNAL_READABLE, TIMEOUT_FOREVER) {
        Ok((0, s)) if s & SIGNAL_READABLE != 0 => {}
        _ => return 0xF1,
    }
    match libnawah::channel_read(c, &mut buf, &mut hs, false) {
        Ok((3, 0)) if &buf[..3] == b"bye" => {}
        _ => return 0xF2,
    }
    if wait_one(c, SIGNAL_PEER_CLOSED, 500) != Ok((0, SIGNAL_PEER_CLOSED)) {
        return 0xF3;
    }
    if libnawah::handle_close(a) != 0 || libnawah::handle_close(c) != 0 {
        return 0xF4;
    }
    0x72
}
