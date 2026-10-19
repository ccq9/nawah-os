//! killer — the process_kill contract (WP-40, TST-M5-PROCESS-KILL). Every child is given time to
//! reach the state it is killed in: after each spawn the killer sleeps 20 ticks, and since its
//! children run on its own CPU and have nothing else to do, each is by then blocked (or, for SPIN,
//! running in ring 3) — the kill lands on that state, not on a child that has not started (that
//! edge is TST-M5-KILL-EDGES). Steps:
//! - ECHO, blocked in its bootstrap `channel_read`: a read-only duplicate of the process handle
//!   cannot kill it (ERR_ACCESS) and it is verifiably still alive afterwards (its exit is awaited
//!   for 20 ticks and does not come); a non-process handle is ERR_WRONG_TYPE; the owner's handle
//!   (WRITE) kills it — EXIT_KILLED — and our end of its channel then sees PEER_CLOSED (its
//!   resources were released); killing it again is a no-op.
//! - SPIN, never leaving ring 3: killed through the timer interrupt's return to ring 3.
//! - IDLE, blocked in `object_wait_many`: killed through the wait returning to the safe point.
//! - SVC in role `sleeper`, inside `sleep`: killed through the sleep returning to the safe point.
//!
//! Every wait for an exit is bounded (5000 ticks), so a lost kill fails here instead of hanging.
//! Exits 0x6B on success; otherwise the failing step (0xE0..).

#![no_std]
#![no_main]

use libnawah::{
    rights, Handle, WaitEntry, ERR_ACCESS, ERR_SHOULD_WAIT, ERR_TIMED_OUT, ERR_WRONG_TYPE,
    SIGNAL_EXITED, SIGNAL_PEER_CLOSED,
};

libnawah::entry!(main);

const ECHO: &[u8] = b"/SYSTEM/ECHO.ELF";
/// syscall.md v1.11: a process ended by process_kill.
const EXIT_KILLED: u64 = 0x2_0000;
/// Time a freshly spawned child gets to reach its blocking point (or its ring-3 loop).
const SETTLE: u64 = 20;
/// The longest a kill may take to show as an exit.
const EXIT_WAIT: u64 = 5000;

/// Waits (bounded) for `h` to assert `signal`.
fn wait_for(h: Handle, signal: u32, ticks: u64) -> Result<(), i64> {
    match libnawah::object_wait_many(
        &[WaitEntry {
            handle: h,
            signals: signal,
        }],
        ticks,
    ) {
        Ok((0, s)) if s & signal != 0 => Ok(()),
        Ok(_) => Err(0),
        Err(e) => Err(e),
    }
}

/// Waits (bounded) for process `p` to exit and returns whether it ended with EXIT_KILLED.
fn killed_exit(p: Handle) -> bool {
    wait_for(p, SIGNAL_EXITED, EXIT_WAIT).is_ok() && libnawah::process_status(p) == Ok(EXIT_KILLED)
}

fn main() -> u64 {
    // Our end `a` stays open and silent, so the child blocks forever on its end `b`.
    let Ok((a, b)) = libnawah::channel_create() else {
        return 0xE0;
    };
    let Ok(p) = libnawah::process_spawn(ECHO, &[b]) else {
        return 0xE1;
    };
    let _ = libnawah::sleep(SETTLE);
    if libnawah::process_status(p) != Err(ERR_SHOULD_WAIT) {
        return 0xE2;
    }
    // A watcher's duplicate (no WRITE) cannot kill, and the child really is still alive.
    let Ok(p_ro) = libnawah::handle_duplicate(p, rights::WAIT) else {
        return 0xE3;
    };
    if libnawah::process_kill(p_ro) != ERR_ACCESS {
        return 0xE4;
    }
    if wait_for(p, SIGNAL_EXITED, SETTLE) != Err(ERR_TIMED_OUT) {
        return 0xE5;
    }
    // A non-process handle is the wrong type (whatever its rights).
    if libnawah::process_kill(a) != ERR_WRONG_TYPE {
        return 0xE6;
    }
    // The owner's handle kills the child blocked in channel_read.
    if libnawah::process_kill(p) != 0 {
        return 0xE7;
    }
    if !killed_exit(p) {
        return 0xE8;
    }
    // Its end of the channel went with it.
    if wait_for(a, SIGNAL_PEER_CLOSED, EXIT_WAIT).is_err() {
        return 0xE9;
    }
    // Killing an exited process is a no-op.
    if libnawah::process_kill(p) != 0 {
        return 0xEA;
    }
    let _ = libnawah::handle_close(p);
    let _ = libnawah::handle_close(p_ro);
    let _ = libnawah::handle_close(a);

    // A spinner that never leaves ring 3: killed through the timer interrupt's return.
    let Ok(sp) = libnawah::process_spawn(b"/SYSTEM/SPIN.ELF", &[]) else {
        return 0xEB;
    };
    let _ = libnawah::sleep(SETTLE);
    if libnawah::process_kill(sp) != 0 || !killed_exit(sp) {
        return 0xEC;
    }
    let _ = libnawah::handle_close(sp);

    // A process blocked in object_wait_many on a channel we keep open and silent.
    let Ok((ia, ib)) = libnawah::channel_create() else {
        return 0xED;
    };
    let Ok(idl) = libnawah::process_spawn(b"/SYSTEM/IDLE.ELF", &[ib]) else {
        return 0xEE;
    };
    let _ = libnawah::sleep(SETTLE);
    if libnawah::process_status(idl) != Err(ERR_SHOULD_WAIT) {
        return 0xEF;
    }
    if libnawah::process_kill(idl) != 0 || !killed_exit(idl) {
        return 0xF0;
    }
    let _ = libnawah::handle_close(idl);
    let _ = libnawah::handle_close(ia);

    // A process asleep for a million ticks (svc's `sleeper` role).
    let Ok((sa, sb)) = libnawah::channel_create() else {
        return 0xF1;
    };
    let Ok(sl) = libnawah::process_spawn(b"/SYSTEM/SVC.ELF", &[sb]) else {
        return 0xF2;
    };
    if libnawah::channel_write(sa, b"START sleeper", &[]) != 0 {
        return 0xF3;
    }
    let _ = libnawah::sleep(SETTLE);
    if libnawah::process_status(sl) != Err(ERR_SHOULD_WAIT) {
        return 0xF4;
    }
    if libnawah::process_kill(sl) != 0 || !killed_exit(sl) {
        return 0xF5;
    }
    let _ = libnawah::handle_close(sl);
    let _ = libnawah::handle_close(sa);
    0x6B
}
