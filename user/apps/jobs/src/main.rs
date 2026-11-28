//! jobs — the job contract (WP-46, syscall.md v1.13 §5, TST-M6-JOB-KILL). Started by the test
//! kernel with a channel as its bootstrap handle (slot 0) and a handle to the root job (WRITE)
//! right after it (slot 1, initial handles are consecutive, syscall.md §5); it runs in the root
//! itself. Phase 1 probes the channel before it looks at slot 1, so on a kernel without jobs it
//! fails there (syscall 43 answers ERR_NOSYS, not ERR_WRONG_TYPE: exit 0xE2). Every child is given SETTLE ticks to reach its blocking point before a kill (they run
//! on this CPU with nothing else to do), and every wait for an exit is bounded (EXIT_WAIT), so a
//! lost kill fails here instead of hanging. Each phase ends with one console line,
//! `jobs|phase=<n>|<name>=ok` (or `=fail` for the phase that failed, before the exit):
//! 1. types (0xE0..0xE7): a bootstrap handle (0xE0); `job_create` on it, a channel, is
//!    ERR_WRONG_TYPE (0xE2); slot 1 is a job (0xE1); a duplicate without WRITE can neither create, kill nor spawn into
//!    (ERR_ACCESS) and the handle a refused spawn named stays ours; `process_spawn_in` on a
//!    channel is ERR_WRONG_TYPE.
//! 2. contain (0xE8): killing the root, which contains the caller, is ERR_INVALID.
//! 3. tree (0xE9..0xEA): job A under the root, job B under A.
//! 4. spawn (0xEB..0xF2): IDLE into A and into B with `process_spawn_in`; a copy of this app
//!    into A in its child role, given A's handle too: there `job_kill(A)` — a job containing the
//!    caller, not the root — must be ERR_INVALID, and it starts IDLE with plain `process_spawn`,
//!    so in A, the caller's job, and sends that grandchild's handle back; an outsider IDLE in
//!    the root with `process_spawn`. All alive after SETTLE.
//! 5. kill (0xF3..0xF7): `job_kill(A)` is 0; the IDLE in A, the IDLE in B (below A), the child
//!    and its grandchild all end with EXIT_KILLED; our ends of the IDLEs' channels in A and B see
//!    PEER_CLOSED; the outsider is still alive; killing A again is a no-op (0).
//! 6. dead (0xF8..0xFC): `job_create` on A and on B is ERR_PEER_CLOSED; `process_spawn_in`
//!    into A and into B is ERR_PEER_CLOSED and the handle named stays ours.
//! 7. depth (0xFD..0xFF): eight nested jobs below the root are made, a ninth level is
//!    ERR_NO_RESOURCES; everything is closed and the outsider killed with `process_kill`.
//!
//! Exits 0x4A on success. The child role is chosen by a `C` message already waiting on the
//! bootstrap channel (the parent writes it before the spawn; the test kernel writes nothing):
//! there it never exits on its own; 0xD0.. if a step of that role fails. 0xDD..0xDF are the
//! parent's other failures: the child's report malformed (phase 4), a channel not made (phase
//! 1), the role mark not written (phase 4).

#![no_std]
#![no_main]

use libnawah::{
    object_type, rights, Handle, WaitEntry, ERR_ACCESS, ERR_INVALID, ERR_NO_RESOURCES,
    ERR_PEER_CLOSED, ERR_SHOULD_WAIT, ERR_TIMED_OUT, ERR_WRONG_TYPE, SIGNAL_EXITED,
    SIGNAL_PEER_CLOSED, SIGNAL_READABLE,
};

libnawah::entry!(main);

const IDLE: &[u8] = b"/SYSTEM/IDLE.ELF";
const SELF: &[u8] = b"/SYSTEM/JOBS.ELF";
/// syscall.md v1.11: a process ended by process_kill (and by job_kill, v1.13).
const EXIT_KILLED: u64 = 0x2_0000;
/// Time a freshly spawned child gets to reach its blocking point.
const SETTLE: u64 = 20;
/// The longest a kill may take to show as an exit, and the child role's report.
const EXIT_WAIT: u64 = 5000;
/// syscall.md v1.13 §5: the deepest job below the root.
const DEPTH_MAX: usize = 8;
const OK: u64 = 0x4A;

/// The phase running: its number and name, for its verdict line.
struct Phase {
    n: u8,
    name: &'static [u8],
}

/// `jobs|phase=<n>|<name>=<ok|fail>` on the console.
fn verdict(p: &Phase, ok: bool) {
    let mut line = [0u8; 48];
    let mut len = 0;
    let digit = [b'0' + p.n];
    let result: &[u8] = if ok { b"ok" } else { b"fail" };
    for part in [b"jobs|phase=" as &[u8], &digit, b"|", p.name, b"=", result] {
        line[len..len + part.len()].copy_from_slice(part);
        len += part.len();
    }
    libnawah::trace(&line[..len]);
}

/// Closes the phase running with an `ok` line and starts the next.
fn next(p: &mut Phase, n: u8, name: &'static [u8]) {
    verdict(p, true);
    *p = Phase { n, name };
}

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

fn alive(p: Handle) -> bool {
    libnawah::process_status(p) == Err(ERR_SHOULD_WAIT)
}

/// An IDLE child blocked on a channel whose other end (returned) we keep open and silent.
fn idle_in(job: Option<Handle>) -> Result<(Handle, Handle), i64> {
    let (keep, give) = libnawah::channel_create()?;
    let p = match job {
        Some(j) => libnawah::process_spawn_in(j, IDLE, &[give]),
        None => libnawah::process_spawn(IDLE, &[give]),
    };
    match p {
        Ok(p) => Ok((p, keep)),
        Err(e) => {
            let _ = libnawah::handle_close(keep);
            let _ = libnawah::handle_close(give);
            Err(e)
        }
    }
}

/// The child role, in job A with A's handle right after its bootstrap channel: `job_kill(A)` must be ERR_INVALID (A contains us); then
/// start IDLE with plain `process_spawn` (so in A), send `G` with its process handle — or `X`
/// when the kill was not refused — and sleep until killed.
fn child(boot: Handle) -> u64 {
    let job = boot + 1;
    if libnawah::handle_type(job) != object_type::JOB {
        return 0xD0;
    }
    if libnawah::job_kill(job) != ERR_INVALID {
        let _ = libnawah::channel_write(boot, b"X", &[]);
        return 0xD1;
    }
    let Ok((g, _keep)) = idle_in(None) else {
        return 0xD2;
    };
    if libnawah::channel_write(boot, b"G", &[g]) != 0 {
        return 0xD3;
    }
    loop {
        let _ = libnawah::sleep(1_000_000);
    }
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    let mut role = [0u8; 4];
    let mut none = [0u32; 1];
    if boot != 0
        && libnawah::channel_read(boot, &mut role, &mut none, false) == Ok((1, 0))
        && role[0] == b'C'
    {
        return child(boot);
    }
    let mut phase = Phase {
        n: 1,
        name: b"types",
    };
    let code = run(boot, &mut phase);
    if code != OK {
        verdict(&phase, false);
    }
    code
}

fn run(boot: Handle, phase: &mut Phase) -> u64 {
    // 1. Types and rights: the channel first, so a kernel without jobs fails here (0xE2).
    if boot == 0 {
        return 0xE0;
    }
    if libnawah::job_create(boot) != Err(ERR_WRONG_TYPE) {
        return 0xE2;
    }
    let root = boot + 1;
    if libnawah::handle_type(root) != object_type::JOB {
        return 0xE1;
    }
    let Ok((ca, cb)) = libnawah::channel_create() else {
        return 0xDE;
    };
    let Ok(ro) = libnawah::handle_duplicate(root, rights::READ | rights::DUPLICATE) else {
        return 0xE3;
    };
    if libnawah::job_create(ro) != Err(ERR_ACCESS) {
        return 0xE4;
    }
    if libnawah::job_kill(ro) != ERR_ACCESS {
        return 0xE5;
    }
    if libnawah::process_spawn_in(ro, IDLE, &[cb]) != Err(ERR_ACCESS)
        || libnawah::handle_type(cb) != object_type::CHANNEL
    {
        return 0xE6;
    }
    if libnawah::process_spawn_in(ca, IDLE, &[cb]) != Err(ERR_WRONG_TYPE)
        || libnawah::handle_type(cb) != object_type::CHANNEL
    {
        return 0xE7;
    }
    let _ = libnawah::handle_close(ro);
    next(phase, 2, b"contain");

    // 2. A job that contains the caller cannot be killed.
    if libnawah::job_kill(root) != ERR_INVALID {
        return 0xE8;
    }
    next(phase, 3, b"tree");

    // 3. The tree: A under the root, B under A.
    let a = match libnawah::job_create(root) {
        Ok(a) if libnawah::handle_type(a) == object_type::JOB => a,
        _ => return 0xE9,
    };
    let Ok(b) = libnawah::job_create(a) else {
        return 0xEA;
    };
    next(phase, 4, b"spawn");

    // 4. Spawning into it, containment seen from inside, and inheriting the caller's job.
    let Ok((pa, ka)) = idle_in(Some(a)) else {
        return 0xEB;
    };
    let Ok((pb, kb)) = idle_in(Some(b)) else {
        return 0xEC;
    };
    let Ok(a_for_child) = libnawah::handle_duplicate(a, rights::WRITE | rights::TRANSFER) else {
        return 0xED;
    };
    // The child role's mark, waiting on its bootstrap channel when it starts.
    if libnawah::channel_write(ca, b"C", &[]) != 0 {
        return 0xDF;
    }
    let Ok(pc) = libnawah::process_spawn_in(a, SELF, &[cb, a_for_child]) else {
        return 0xEE;
    };
    if wait_for(ca, SIGNAL_READABLE, EXIT_WAIT).is_err() {
        return 0xEF;
    }
    let mut msg = [0u8; 4];
    let mut got = [0u32; 1];
    let g = match libnawah::channel_read(ca, &mut msg, &mut got, false) {
        Ok((1, 1)) if msg[0] == b'G' => got[0],
        Ok((1, 0)) if msg[0] == b'X' => return 0xF0,
        _ => return 0xDD,
    };
    let Ok((po, ko)) = idle_in(None) else {
        return 0xF1;
    };
    let _ = libnawah::sleep(SETTLE);
    if !(alive(pa) && alive(pb) && alive(pc) && alive(g) && alive(po)) {
        return 0xF2;
    }
    next(phase, 5, b"kill");

    // 5. The kill reaches A, B below it and what A's member started; nothing outside.
    if libnawah::job_kill(a) != 0 {
        return 0xF3;
    }
    if !(killed_exit(pa) && killed_exit(pb) && killed_exit(pc) && killed_exit(g)) {
        return 0xF4;
    }
    if wait_for(ka, SIGNAL_PEER_CLOSED, EXIT_WAIT).is_err()
        || wait_for(kb, SIGNAL_PEER_CLOSED, EXIT_WAIT).is_err()
    {
        return 0xF5;
    }
    if wait_for(po, SIGNAL_EXITED, SETTLE) != Err(ERR_TIMED_OUT) {
        return 0xF6;
    }
    if libnawah::job_kill(a) != 0 {
        return 0xF7;
    }
    next(phase, 6, b"dead");

    // 6. A killed job, and every job below it, refuses new jobs and new processes.
    if libnawah::job_create(a) != Err(ERR_PEER_CLOSED) {
        return 0xF8;
    }
    if libnawah::job_create(b) != Err(ERR_PEER_CLOSED) {
        return 0xF9;
    }
    let Ok((x, y)) = libnawah::channel_create() else {
        return 0xFA;
    };
    if libnawah::process_spawn_in(a, IDLE, &[y]) != Err(ERR_PEER_CLOSED)
        || libnawah::handle_type(y) != object_type::CHANNEL
    {
        return 0xFB;
    }
    if libnawah::process_spawn_in(b, IDLE, &[y]) != Err(ERR_PEER_CLOSED)
        || libnawah::handle_type(y) != object_type::CHANNEL
    {
        return 0xFC;
    }
    next(phase, 7, b"depth");

    // 7. Depth: eight levels below the root, not nine.
    let mut chain = [0 as Handle; DEPTH_MAX];
    let mut parent = root;
    for slot in chain.iter_mut() {
        match libnawah::job_create(parent) {
            Ok(j) => {
                *slot = j;
                parent = j;
            }
            Err(_) => return 0xFD,
        }
    }
    if libnawah::job_create(parent) != Err(ERR_NO_RESOURCES) {
        return 0xFE;
    }
    for h in chain.iter().rev() {
        let _ = libnawah::handle_close(*h);
    }
    if libnawah::process_kill(po) != 0 || !killed_exit(po) {
        return 0xFF;
    }
    for h in [a, b, pa, pb, pc, g, po, ka, kb, ko, ca, x, y] {
        let _ = libnawah::handle_close(h);
    }
    verdict(phase, true);
    OK
}
