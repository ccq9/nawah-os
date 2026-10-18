//! launch — exercises `process_spawn` (WP-23, TST-M4-SPAWN-VOLUME): starts `/SYSTEM/ECHO.ELF`
//! from the volume with a channel endpoint as its bootstrap handle, checks the handle left the
//! caller's table, does the round trip, waits for the exit, and checks the refusals (missing
//! file, a file that is no ELF, a handle without TRANSFER — which must stay usable). Exits
//! 0x70 at the end; otherwise the failing step (0xE0..).

#![no_std]
#![no_main]

use libnawah::{rights, WaitEntry, ERR_ACCESS, ERR_BAD_HANDLE, ERR_INVALID, ERR_NOT_FOUND};

libnawah::entry!(main);

const ECHO: &[u8] = b"/SYSTEM/ECHO.ELF";
const MSG: &[u8] = b"ping from launch";

fn main() -> u64 {
    let Ok((a, b)) = libnawah::channel_create() else {
        return 0xE0;
    };
    let p = match libnawah::process_spawn(ECHO, &[b]) {
        Ok(p) => p,
        Err(_) => return 0xE1,
    };
    // The moved endpoint is no longer ours.
    if libnawah::channel_write(b, b"x", &[]) != ERR_BAD_HANDLE {
        return 0xE2;
    }
    if libnawah::channel_write(a, MSG, &[]) != 0 {
        return 0xE3;
    }
    let want = [WaitEntry {
        handle: a,
        signals: libnawah::SIGNAL_READABLE | libnawah::SIGNAL_PEER_CLOSED,
    }];
    match libnawah::object_wait_many(&want, libnawah::TIMEOUT_FOREVER) {
        Ok((0, s)) if s & libnawah::SIGNAL_READABLE != 0 => {}
        _ => return 0xE4,
    }
    let mut buf = [0u8; 64];
    let mut hs = [0u32; 1];
    match libnawah::channel_read(a, &mut buf, &mut hs, false) {
        Ok((n, 0)) if &buf[..n] == MSG => {}
        _ => return 0xE5,
    }
    let exited = [WaitEntry {
        handle: p,
        signals: libnawah::SIGNAL_EXITED,
    }];
    if libnawah::object_wait_many(&exited, libnawah::TIMEOUT_FOREVER)
        != Ok((0, libnawah::SIGNAL_EXITED))
    {
        return 0xE6;
    }
    if libnawah::process_status(p) != Ok(MSG.len() as u64) {
        return 0xE7;
    }
    // The child's table is gone: our endpoint sees the peer closed.
    let closed = [WaitEntry {
        handle: a,
        signals: libnawah::SIGNAL_PEER_CLOSED,
    }];
    if libnawah::object_wait_many(&closed, 0) != Ok((0, libnawah::SIGNAL_PEER_CLOSED)) {
        return 0xE8;
    }
    // Refusals: no such file, a file that is not an ELF image, a handle without TRANSFER.
    if libnawah::process_spawn(b"/SYSTEM/NOPE.ELF", &[]) != Err(ERR_NOT_FOUND) {
        return 0xE9;
    }
    if libnawah::process_spawn(b"/HELLO.TXT", &[]) != Err(ERR_INVALID) {
        return 0xEA;
    }
    let Ok((c, d)) = libnawah::channel_create() else {
        return 0xEB;
    };
    let Ok(d2) = libnawah::handle_duplicate(d, rights::READ | rights::WRITE) else {
        return 0xEC;
    };
    if libnawah::process_spawn(ECHO, &[d2]) != Err(ERR_ACCESS) {
        return 0xED;
    }
    // Nothing was moved: d2 still writes, c still reads.
    if libnawah::channel_write(d2, b"still here", &[]) != 0 {
        return 0xEE;
    }
    match libnawah::channel_read(c, &mut buf, &mut hs, false) {
        Ok((10, 0)) if &buf[..10] == b"still here" => {}
        _ => return 0xEF,
    }
    for h in [a, p, c, d, d2] {
        if libnawah::handle_close(h) != 0 {
            return 0xF0;
        }
    }
    if libnawah::process_status(p) != Err(ERR_BAD_HANDLE) {
        return 0xF1;
    }
    0x70
}
