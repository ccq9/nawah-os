//! killer — the process_kill contract (WP-40, TST-M5-PROCESS-KILL): spawns an ECHO child that
//! blocks forever in its bootstrap read, then checks that a read-only duplicate of the process
//! handle cannot kill it (ERR_ACCESS), a non-process handle is ERR_WRONG_TYPE, the owner's
//! handle (WRITE) kills it so it exits EXIT_KILLED while blocked, and killing an already-exited
//! process is a no-op. Then it kills a SPIN child (never leaves ring 3) and an IDLE child
//! (blocked in object_wait_many), each exiting EXIT_KILLED — the three kill safe points. Exits
//! 0x6B on success; otherwise the failing step (0xE0..).

#![no_std]
#![no_main]

use libnawah::{
    rights, Handle, WaitEntry, ERR_ACCESS, ERR_SHOULD_WAIT, ERR_WRONG_TYPE, SIGNAL_EXITED,
    TIMEOUT_FOREVER,
};

libnawah::entry!(main);

const ECHO: &[u8] = b"/SYSTEM/ECHO.ELF";
/// syscall.md v1.11: a process ended by process_kill.
const EXIT_KILLED: u64 = 0x2_0000;

/// Waits for process `p` to exit and returns whether it ended with EXIT_KILLED.
fn killed_exit(p: Handle) -> bool {
    matches!(
        libnawah::object_wait_many(
            &[WaitEntry {
                handle: p,
                signals: SIGNAL_EXITED,
            }],
            TIMEOUT_FOREVER,
        ),
        Ok((0, s)) if s & SIGNAL_EXITED != 0
    ) && libnawah::process_status(p) == Ok(EXIT_KILLED)
}

fn main() -> u64 {
    // Our end `a` stays open, so the child blocks forever on its end `b`.
    let Ok((a, b)) = libnawah::channel_create() else {
        return 0xE0;
    };
    let Ok(p) = libnawah::process_spawn(ECHO, &[b]) else {
        return 0xE1;
    };
    if libnawah::process_status(p) != Err(ERR_SHOULD_WAIT) {
        return 0xE2;
    }
    // A watcher's duplicate (no WRITE) cannot kill.
    let Ok(p_ro) = libnawah::handle_duplicate(p, rights::WAIT) else {
        return 0xE3;
    };
    if libnawah::process_kill(p_ro) != ERR_ACCESS {
        return 0xE4;
    }
    if libnawah::process_status(p) != Err(ERR_SHOULD_WAIT) {
        return 0xE5; // still running
    }
    // A non-process handle is the wrong type (whatever its rights).
    if libnawah::process_kill(a) != ERR_WRONG_TYPE {
        return 0xE6;
    }
    // The owner's handle kills the blocked child (it was in channel_read).
    if libnawah::process_kill(p) != 0 {
        return 0xE7;
    }
    if !killed_exit(p) {
        return 0xE8;
    }
    // Killing an exited process is a no-op.
    if libnawah::process_kill(p) != 0 {
        return 0xEA;
    }
    let _ = libnawah::handle_close(p);
    let _ = libnawah::handle_close(p_ro);
    let _ = libnawah::handle_close(a);

    // A spinner that never leaves ring 3: killed through the timer preemption.
    let Ok(sp) = libnawah::process_spawn(b"/SYSTEM/SPIN.ELF", &[]) else {
        return 0xEB;
    };
    if libnawah::process_kill(sp) != 0 || !killed_exit(sp) {
        return 0xEC;
    }
    let _ = libnawah::handle_close(sp);

    // A process blocked in object_wait_many: killed through the wait returning to the safe
    // point. Our end `ia` stays open and silent, so it never wakes on its own.
    let Ok((ia, ib)) = libnawah::channel_create() else {
        return 0xED;
    };
    let Ok(idl) = libnawah::process_spawn(b"/SYSTEM/IDLE.ELF", &[ib]) else {
        return 0xEE;
    };
    if libnawah::process_status(idl) != Err(ERR_SHOULD_WAIT) {
        return 0xEF;
    }
    if libnawah::process_kill(idl) != 0 || !killed_exit(idl) {
        return 0xF0;
    }
    let _ = libnawah::handle_close(idl);
    let _ = libnawah::handle_close(ia);
    0x6B
}
