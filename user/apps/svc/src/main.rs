//! svc — a test service for the service manager (WP-24, services.md §4): its first message
//! `START <arg>` picks the role: `ready` answers READY and waits for STOP (or the channel's
//! close) then exits 0; `mute` never answers and exits 0 once the channel closes; `crash`
//! exits 1 at once; (WP-31) `serve` answers READY and serves clients the manager connects
//! (`PING` → `OK served`); `crash_once` serves the same way but dies (exit 3, no reply) on
//! the first request of its life on this volume — it leaves `/CRASHED.TXT` behind (outside
//! `/SYSTEM`, which it cannot write: WP-44) so the instance the manager restarts serves
//! normally (TST-M4-PEER-LOSS). (WP-40) `ready` also answers the watchdog's `PING` with `PONG`
//! (traced `svc|pong`); `hang` answers READY then stops servicing its channel, so the watchdog
//! finds it hung and kills it (TST-M5-SVC-WATCHDOG). (Review
//! 2026-10-19) `closer` answers READY then closes its boot channel and stays alive; `early_hang`
//! hangs before READY without reading its channel; `ticker` writes `T` every 5 ticks from a timed
//! wait; `sleeper` sleeps a million ticks; `loud` sends 100 junk bytes, then acts as `ready`; `silent <lo> <hi>` serves clients like `serve` but
//! never answers (TST-M5-SESSION-DEADLINE). (WP-161, TST-M6-APP-SPAWN) `launcher` is the vouched
//! session's side of the launch case; started by the manager as an application (`START
//! app:<id>#<n>`) the image is `clock`, which asks and stays, `orphan`, which leaves a child
//! behind, or `closer`, which closes its boot channel and stays a while. Anything else exits 2; a missing bootstrap handle 0xE0.

#![no_std]
#![no_main]

use libnawah::{WaitEntry, ERR_PEER_CLOSED, SIGNAL_PEER_CLOSED, SIGNAL_READABLE};

libnawah::entry!(main);

const MAX_CLIENTS: usize = 4;

/// What `serve` does with a client's request.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// `PING` → `OK served`.
    Serve,
    /// As `Serve`, but the first request of this volume's life kills it (exit 3).
    CrashOnce,
    /// As `Serve`, and traces `svc|connect|<name>` for the name each client arrives with
    /// (WP-162, TST-M6-APP-CONNECT-DENIED: the name the manager vouches for).
    Names,
    /// Never answers. When a client whose request went unanswered closes its channel, traces
    /// `svc|silent|held=<ticks>|in_window=<0|1>`: the ticks from the request's arrival to the
    /// close, and whether they fall within [lo, hi] (the test's expected deadline window).
    Silent { lo: u64, hi: u64 },
    /// WP-167 (TST-M6-LOGOUT-KILLS): a client's `LAUNCH <id>` is asked on the boot channel and
    /// the manager's reply passed back, so the test kernel launches as the vouched `desktop`.
    Relay,
}

/// `n` in decimal into `out` at `at`; the new end.
fn put_num(out: &mut [u8], mut at: usize, n: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut k = 0;
    let mut v = n;
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 && at < out.len() {
        k -= 1;
        out[at] = digits[k];
        at += 1;
    }
    at
}

fn parse_num(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 19 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(s.iter().fold(0, |v, &c| v * 10 + u64::from(c - b'0')))
}

/// `svc|silent|held=<n>|in_window=<0|1>`.
fn trace_held(held: u64, lo: u64, hi: u64) {
    let mut t = [0u8; 64];
    let head = b"svc|silent|held=";
    t[..head.len()].copy_from_slice(head);
    let mut at = put_num(&mut t, head.len(), held);
    let tail: &[u8] = if (lo..=hi).contains(&held) {
        b"|in_window=1"
    } else {
        b"|in_window=0"
    };
    t[at..at + tail.len()].copy_from_slice(tail);
    at += tail.len();
    libnawah::trace(&t[..at]);
}
const CRASH_MARK: &[u8] = b"/CRASHED.TXT";

/// One request on the boot channel, with the handles `sent`, and its reply (WP-161): the
/// reply's length, or None when the request could not be written or no reply came within 1500
/// ticks.
fn ask(ch: u32, req: &[u8], sent: &[u32], reply: &mut [u8; 128]) -> Option<usize> {
    if libnawah::channel_write(ch, req, sent) != 0 {
        return None;
    }
    libnawah::object_wait_many(
        &[WaitEntry {
            handle: ch,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        }],
        1500,
    )
    .ok()?;
    let mut hs = [0u32; 1];
    libnawah::channel_read(ch, reply, &mut hs, false)
        .ok()
        .map(|(n, _)| n)
}

/// Replies [`launch`] repeats its request on: `ERR FULL` (applications that exited are still
/// leaving the manager's table) and `ERR BUSY` (the window of LAUNCH's rate is full, WP-163).
const RETRY_FULL: u8 = 1;
const RETRY_BUSY: u8 = 2;

/// `LAUNCH <id>` (WP-161): the number of `OK app:<id>#<n>` (0 for any other reply, or none) and
/// the reply's length. The request is repeated every 2 ticks while the answer is one that
/// `retry` names.
fn launch(ch: u32, id: &[u8], retry: u8, reply: &mut [u8; 128]) -> (u64, usize) {
    let mut req = [0u8; 32];
    let head = b"LAUNCH ";
    let len = head.len() + id.len();
    req[..head.len()].copy_from_slice(head);
    req[head.len()..len].copy_from_slice(id);
    for _ in 0..2000 {
        let Some(n) = ask(ch, &req[..len], &[], reply) else {
            return (0, 0);
        };
        let full = retry & RETRY_FULL != 0 && reply[..n] == *b"ERR FULL";
        let busy = retry & RETRY_BUSY != 0 && reply[..n] == *b"ERR BUSY";
        if full || busy {
            let _ = libnawah::sleep(2);
            continue;
        }
        let num = reply[..n]
            .strip_prefix(b"OK app:")
            .and_then(|r| r.strip_prefix(id))
            .and_then(|r| r.strip_prefix(b"#"))
            .filter(|d| d.first() != Some(&b'0'))
            .and_then(parse_num);
        return (num.unwrap_or(0), n);
    }
    (0, 0)
}

/// A step of the launcher that saw another reply than the stated one: traced
/// `launcher|step=<k>|got=<reply>`; its exit code is (0x50 + k) * 256 + the number `num` of the
/// reply (0 when it was not `OK app:<id>#<n>`), so the test kernel's line says what came back.
fn missed(step: u8, num: u64, reply: &[u8]) -> u64 {
    let mut t = [0u8; 96];
    let head = b"launcher|step=0|got=";
    let n = reply.len().min(64);
    t[..head.len()].copy_from_slice(head);
    t[14] = b'0' + step;
    t[head.len()..head.len() + n].copy_from_slice(&reply[..n]);
    libnawah::trace(&t[..head.len() + n]);
    (0x50 + u64::from(step)) << 8 | (num & 0xff)
}

/// The vouched session's side of TST-M6-APP-SPAWN (WP-161): READY, then nine steps (a launch
/// answered ERR FULL or, from WP-163, ERR BUSY is asked again in all but the first and last); 0x40 when
/// every reply was the one services.md v1.15 states, `missed`'s code at the first step k that saw
/// another.
fn launcher(ch: u32) -> u64 {
    if libnawah::channel_write(ch, b"READY", &[]) != 0 {
        return 0xE2;
    }
    if !begin(ch) {
        return 0xE3;
    }
    let mut r = [0u8; 128];
    // 1: the first application carries number 1, and stays.
    let (num, n) = launch(ch, b"clock", 0, &mut r);
    if num != 1 {
        return missed(1, num, &r[..n]);
    }
    // 2: ninety-eight that exit at once, through the table's eight places: 2 to 99, in order.
    for want in 2..=99 {
        let (num, n) = launch(ch, b"exit", RETRY_FULL | RETRY_BUSY, &mut r);
        if num != want {
            return missed(2, num, &r[..n]);
        }
    }
    // 3: the circle is back at 1, which the first application still carries: 2.
    let (num, n) = launch(ch, b"exit", RETRY_FULL | RETRY_BUSY, &mut r);
    if num != 2 {
        return missed(3, num, &r[..n]);
    }
    // 4: a registered entry whose image is not on the volume.
    let (num, n) = launch(ch, b"notes", RETRY_FULL | RETRY_BUSY, &mut r);
    if r[..n] != *b"ERR NOT_FOUND" {
        return missed(4, num, &r[..n]);
    }
    // 5: one whose image is not an image.
    let (num, n) = launch(ch, b"bad", RETRY_FULL | RETRY_BUSY, &mut r);
    if r[..n] != *b"ERR FAILED" {
        return missed(5, num, &r[..n]);
    }
    // 6: one that leaves a child behind and exits; the failed launches took no number.
    let (num, n) = launch(ch, b"orphan", RETRY_FULL | RETRY_BUSY, &mut r);
    if num != 3 {
        return missed(6, num, &r[..n]);
    }
    // 7: one that closes its boot channel and stays 200 ticks. The manager has taken the close
    // well before the next request, which comes while that application still runs.
    let (num, n) = launch(ch, b"closer", RETRY_FULL | RETRY_BUSY, &mut r);
    if num != 4 {
        return missed(7, num, &r[..n]);
    }
    let _ = libnawah::sleep(100);
    // 8: seven more that stay; the last of them waits for the closer's place. Eight run.
    for want in 5..=11 {
        let (num, n) = launch(ch, b"clock", RETRY_FULL | RETRY_BUSY, &mut r);
        if num != want {
            return missed(8, num, &r[..n]);
        }
    }
    // 9: the ninth. The closer is gone by now whatever the table's size (it had to go for the
    // last clock to start; were the table larger than eight it would still be running, and
    // these 300 ticks outlast it), so eight that stay are all that run.
    let _ = libnawah::sleep(300);
    let (num, n) = launch(ch, b"clock", 0, &mut r);
    if r[..n] != *b"ERR FULL" {
        return missed(9, num, &r[..n]);
    }
    0x40
}

/// A step of `ender`: the trace field, the request (END_SESSION, or an id to LAUNCH), the stated
/// reply (the number, for a LAUNCH) and the step's number for `missed`.
type Step = (&'static [u8], &'static [u8], &'static [u8], u8);

/// The application `hog` of TST-M6-JOB-BOUND (WP-164): starts IDLE children in its own job, 64
/// at most, keeping the process handle of the last alone, until a start is refused; then kills
/// that last child, waits for its exit, starts one again (its place came back) and one more
/// (refused again). Traced `app:hog#<n>|spawned=<k>|err=<-e>|again=<0|1>|again_err=<-e>`
/// (err=0 when none of the 64 was refused); then waits on its boot channel.
fn hog(ch: u32, who: &[u8]) -> u64 {
    let spawn = || {
        libnawah::channel_create()
            .and_then(|(a, b)| libnawah::process_spawn(b"/SYSTEM/IDLE.ELF", &[b, a]))
    };
    let mut spawned = 0u64;
    let mut err = 0i64;
    let mut last: Option<u32> = None;
    for _ in 0..64 {
        match spawn() {
            Ok(p) => {
                spawned += 1;
                if let Some(h) = last.replace(p) {
                    libnawah::handle_close(h);
                }
            }
            Err(e) => {
                err = e;
                break;
            }
        }
    }
    let (mut again, mut again_err) = (0u64, 0i64);
    if err != 0 {
        if let Some(h) = last.take() {
            libnawah::process_kill(h);
            for _ in 0..500 {
                if libnawah::process_status(h) != Err(libnawah::ERR_SHOULD_WAIT) {
                    break;
                }
                let _ = libnawah::sleep(2);
            }
            libnawah::handle_close(h);
        }
        // The handle of this one is kept: the child stays.
        if spawn().is_ok() {
            again = 1;
        }
        if let Err(e) = spawn() {
            again_err = e;
        }
    }
    let mut t = [0u8; 128];
    let mut at = 0;
    let mut put = |t: &mut [u8; 128], s: &[u8]| {
        let k = s.len().min(t.len() - at);
        t[at..at + k].copy_from_slice(&s[..k]);
        at += k;
        at
    };
    put(&mut t, b"app:");
    put(&mut t, &who[..who.len().min(16)]);
    let mut num = [0u8; 20];
    for (field, v) in [
        (&b"|spawned="[..], spawned),
        (b"|err=", err.unsigned_abs()),
        (b"|again=", again),
        (b"|again_err=", again_err.unsigned_abs()),
    ] {
        put(&mut t, field);
        let n = put_num(&mut num, 0, v);
        put(&mut t, &num[..n]);
    }
    libnawah::trace(&t[..at]);
    let mut reply = [0u8; 128];
    let mut hs = [0u32; 1];
    loop {
        if libnawah::channel_read(ch, &mut reply, &mut hs, true).is_err() {
            return 0;
        }
    }
}

/// The vouched session's side of TST-M6-JOB-BOUND (WP-164): READY; LAUNCH peer (#1), 100 ticks;
/// LAUNCH hog (#2), 1500 ticks for it to fill its job; LAUNCH clock (#3), which a full system
/// would refuse. 0x40 when each was answered as stated, `missed`'s code at the first step that saw
/// another.
fn bounder(ch: u32) -> u64 {
    if libnawah::channel_write(ch, b"READY", &[]) != 0 {
        return 0xE2;
    }
    if !begin(ch) {
        return 0xE3;
    }
    let mut r = [0u8; 128];
    for (step, id, want, pause) in [
        (1u8, &b"peer"[..], 1u64, 100u64),
        (2, b"hog", 2, 1500),
        (3, b"clock", 3, 0),
    ] {
        let (num, n) = launch(ch, id, 0, &mut r);
        if num != want {
            return missed(step, num, &r[..n]);
        }
        let _ = libnawah::sleep(pause);
    }
    0x40
}

/// The vouched session's side of TST-M6-LAUNCH-RATE (WP-163, services.md v1.18): READY; from
/// tick t0, (1) eight LAUNCH stay (#1 to #8), (2) four more answered ERR FULL (not attempts),
/// (3) END_SESSION answered `ENDED 8`, BEGIN_SESSION (WP-169), (4) six LAUNCH exit (#9 to #14), (5) LAUNCH notes, whose
/// image is not on the volume, ERR NOT_FOUND, (6) LAUNCH bad, whose image is not one, ERR FAILED:
/// sixteen attempts; (7) LAUNCH exit answered ERR BUSY, asked up to three times while answered OK
/// so the step's code tells how many got through; (8) at t0 + 600 sixteen LAUNCH exit, each
/// ERR BUSY; (9) an unknown id, ERR UNKNOWN; (10) at t0 + 1100, when the first attempt is more
/// than a window old, LAUNCH exit is #15. Every LAUNCH but step 2's is asked again while answered
/// ERR FULL (the ended session's places come back). Traced
/// `rater|step=<k>|busy_at=<ticks after t0 at step 7>|got=<reply>`, or `rater|busy_at=<ticks>`;
/// 0x40 when each reply was the stated one, `missed`'s code at the first step that saw another.
fn rater(ch: u32) -> u64 {
    if libnawah::channel_write(ch, b"READY", &[]) != 0 {
        return 0xE2;
    }
    if !begin(ch) {
        return 0xE3;
    }
    let mut r = [0u8; 128];
    let t0 = libnawah::clock_ticks();
    let mut busy_at = 0;
    let steps: [RateStep; 10] = [
        (1, b"LAUNCH stay", b"1", 8),
        (2, b"LAUNCH stay", b"ERR FULL", 4),
        (3, b"END_SESSION", b"ENDED 8", 1),
        (4, b"LAUNCH exit", b"9", 6),
        (5, b"LAUNCH notes", b"ERR NOT_FOUND", 1),
        (6, b"LAUNCH bad", b"ERR FAILED", 1),
        (7, b"LAUNCH exit", b"ERR BUSY", 1),
        (8, b"LAUNCH exit", b"ERR BUSY", 16),
        (9, b"LAUNCH none", b"ERR UNKNOWN", 1),
        (10, b"LAUNCH exit", b"15", 1),
    ];
    for (step, req, want, times) in steps {
        let at = match step {
            7 => {
                busy_at = libnawah::clock_ticks().saturating_sub(t0);
                0
            }
            8 => 600,
            10 => 1100,
            _ => 0,
        };
        if at > 0 {
            let _ = libnawah::sleep((t0 + at).saturating_sub(libnawah::clock_ticks()));
        }
        // END_SESSION closed the gate (WP-169): a new session begins before step 4's launches.
        if step == 4 && !begin(ch) {
            return 0xE3;
        }
        let retry = if step == 2 { 0 } else { RETRY_FULL };
        for k in 0..times {
            let (ok, n, num) = match req.strip_prefix(b"LAUNCH ") {
                Some(id) if step == 7 => {
                    // Up to three asks: a limit that lets one or two more through is told
                    // apart from one that lets every one through by the last number.
                    let mut last = (0, 0);
                    for _ in 0..3 {
                        let (num, n) = launch(ch, id, retry, &mut r);
                        if num == 0 {
                            last.1 = n;
                            break;
                        }
                        last = (num, n);
                    }
                    (last.0 == 0 && r[..last.1] == *want, last.1, last.0)
                }
                Some(id) => {
                    let (num, n) = launch(ch, id, retry, &mut r);
                    let ok = match parse_num(want) {
                        Some(first) => num == first + k,
                        None => r[..n] == *want,
                    };
                    (ok, n, num)
                }
                None => {
                    let n = ask(ch, req, &[], &mut r).unwrap_or(0);
                    (r[..n] == *want, n, 0)
                }
            };
            if !ok {
                let mut t = [0u8; 120];
                let head = b"rater|step=";
                t[..head.len()].copy_from_slice(head);
                let mut at = put_num(&mut t, head.len(), u64::from(step));
                let field = b"|busy_at=";
                t[at..at + field.len()].copy_from_slice(field);
                at = put_num(&mut t, at + field.len(), busy_at);
                let got = b"|got=";
                t[at..at + got.len()].copy_from_slice(got);
                at += got.len();
                let m = n.min(t.len() - at);
                t[at..at + m].copy_from_slice(&r[..m]);
                libnawah::trace(&t[..at + m]);
                // `missed`'s code, without its launcher trace.
                return (0x50 + u64::from(step)) << 8 | (num & 0xff);
            }
        }
    }
    let mut t = [0u8; 48];
    let head = b"rater|busy_at=";
    t[..head.len()].copy_from_slice(head);
    let at = put_num(&mut t, head.len(), busy_at);
    libnawah::trace(&t[..at]);
    0x40
}

/// A step of `rater`: its number, the request, the stated reply (the first number, for a LAUNCH
/// answered OK) and how many times it is asked.
type RateStep = (u8, &'static [u8], &'static [u8], u64);

/// The end of a vouched session's role (WP-172, services.md v1.20): a code other than 0x40 is
/// the exit code at once; 0x40 holds the session, waiting on its boot channel without a deadline,
/// until the manager stops it or closes the channel, and is the exit code then. The session's
/// exit ends its job, so the test kernel reads the applications while the role holds.
fn hold(ch: u32, code: u64) -> u64 {
    if code != 0x40 {
        return code;
    }
    let mut buf = [0u8; 128];
    let mut hs = [0u32; 4];
    loop {
        match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
            Ok((n, k)) => {
                for &h in &hs[..k] {
                    libnawah::handle_close(h);
                }
                if &buf[..n] == b"STOP" {
                    return code;
                }
            }
            Err(_) => return code,
        }
    }
}

/// The vouched session's side of TST-M6-SESSION-RESTART (WP-173, services.md v1.20): READY,
/// LAUNCH stay before any session (it must be answered ERR NO_SESSION: the gate is closed at boot
/// and by the exit of the incarnation before, however it went; otherwise it exits 0xE4), then
/// BEGIN_SESSION and LAUNCH stay (any number), then holds; a refused BEGIN_SESSION exits 0xE3,
/// a LAUNCH answered otherwise (0x51 << 8) + its number. Each incarnation does the same, so the
/// session the manager starts again launches again into a job of its own.
fn stayer(ch: u32) -> u64 {
    if libnawah::channel_write(ch, b"READY", &[]) != 0 {
        return 0xE2;
    }
    let mut r = [0u8; 128];
    if !matches!(ask(ch, b"LAUNCH stay", &[], &mut r), Some(n) if r[..n] == *b"ERR NO_SESSION") {
        return 0xE4;
    }
    if !begin(ch) {
        return 0xE3;
    }
    let (num, n) = launch(ch, b"stay", RETRY_FULL, &mut r);
    if num == 0 {
        return missed(1, num, &r[..n]);
    }
    0x40
}

/// `BEGIN_SESSION` (WP-169, services.md v1.19): whether the manager answered `BEGUN`, opening
/// the gate LAUNCH needs. A launcher that is not answered so exits 0xE3.
fn begin(ch: u32) -> bool {
    let mut r = [0u8; 128];
    matches!(ask(ch, b"BEGIN_SESSION", &[], &mut r), Some(n) if r[..n] == *b"BEGUN")
}

/// A step of `gater` and `ungated`: its number (0: sleep 300 ticks), the request, the stated reply
/// (the number, for a LAUNCH answered OK), the replies its LAUNCH repeats on, and how many times
/// it is asked.
type GateStep = (u8, &'static [u8], &'static [u8], u8, u8);

/// The steps of `gater` or `ungated` in turn, each traced `<who>|step=<k>|got=<reply>` at the
/// first that saw another reply; 0x40, or (0x50 + k) * 256 + the number of that reply.
fn gate_steps(ch: u32, who: &[u8], steps: &[GateStep]) -> u64 {
    let mut r = [0u8; 128];
    for &(step, req, want, retry, times) in steps {
        if step == 0 {
            let _ = libnawah::sleep(300);
            continue;
        }
        for _ in 0..times {
            let (ok, n, num) = match (req.strip_prefix(b"LAUNCH "), parse_num(want)) {
                (Some(id), Some(first)) => {
                    let (num, n) = launch(ch, id, retry, &mut r);
                    (num == first, n, num)
                }
                _ => {
                    let n = ask(ch, req, &[], &mut r).unwrap_or(0);
                    (r[..n] == *want, n, 0)
                }
            };
            if !ok {
                let mut t = [0u8; 120];
                t[..who.len()].copy_from_slice(who);
                let head = b"|step=";
                t[who.len()..who.len() + head.len()].copy_from_slice(head);
                let mut at = put_num(&mut t, who.len() + head.len(), u64::from(step));
                let got = b"|got=";
                t[at..at + got.len()].copy_from_slice(got);
                at += got.len();
                let m = n.min(t.len() - at);
                t[at..at + m].copy_from_slice(&r[..m]);
                libnawah::trace(&t[..at + m]);
                return (0x50 + u64::from(step)) << 8 | (num & 0xff);
            }
        }
    }
    0x40
}

/// The vouched session's side of TST-M6-SESSION-GATE (WP-169, services.md v1.19): (1) seventeen
/// LAUNCH stay before any BEGIN_SESSION, each ERR NO_SESSION (refusals that are not attempts);
/// (2) BEGIN_SESSION, BEGUN; (3) LAUNCH stay, #1; (4) BEGIN_SESSION again, BEGUN; (5) END_SESSION,
/// `ENDED 1`; (6) LAUNCH stay, ERR NO_SESSION; (7) BEGIN_SESSION, BEGUN; 300 ticks for stay#1's
/// exit to be seen; (8) END_SESSION with no application, `ENDED 0`; (9) LAUNCH stay, ERR
/// NO_SESSION; (10) BEGIN_SESSION, BEGUN; (11) LAUNCH stay, #2 (repeated while ERR FULL); then
/// READY, so the desktop starts, and exit 0 (a clean exit closes the gate too), or the code of
/// the first step that saw another reply.
fn gater(ch: u32) -> u64 {
    let code = gate_steps(
        ch,
        b"gater",
        &[
            (1, b"LAUNCH stay", b"ERR NO_SESSION", 0, 17),
            (2, b"BEGIN_SESSION", b"BEGUN", 0, 1),
            (3, b"LAUNCH stay", b"1", 0, 1),
            (4, b"BEGIN_SESSION", b"BEGUN", 0, 1),
            (5, b"END_SESSION", b"ENDED 1", 0, 1),
            (6, b"LAUNCH stay", b"ERR NO_SESSION", 0, 1),
            (7, b"BEGIN_SESSION", b"BEGUN", 0, 1),
            (0, b"", b"", 0, 1),
            (8, b"END_SESSION", b"ENDED 0", 0, 1),
            (9, b"LAUNCH stay", b"ERR NO_SESSION", 0, 1),
            (10, b"BEGIN_SESSION", b"BEGUN", 0, 1),
            (11, b"LAUNCH stay", b"2", RETRY_FULL, 1),
        ],
    );
    if libnawah::channel_write(ch, b"READY", &[]) != 0 {
        return 0xE2;
    }
    if code == 0x40 {
        0
    } else {
        code
    }
}

/// The vouched desktop's side of TST-M6-SESSION-GATE (WP-169): READY; (1) BEGIN_SESSION, refused
/// ERR ACCESS; 300 ticks, by which the session that opened the gate has exited; (2) LAUNCH stay,
/// ERR NO_SESSION: the session's exit closed the gate.
fn ungated(ch: u32) -> u64 {
    if libnawah::channel_write(ch, b"READY", &[]) != 0 {
        return 0xE2;
    }
    gate_steps(
        ch,
        b"ungated",
        &[
            (1, b"BEGIN_SESSION", b"ERR ACCESS", 0, 1),
            (0, b"", b"", 0, 1),
            (2, b"LAUNCH stay", b"ERR NO_SESSION", 0, 1),
        ],
    )
}

/// The vouched session's side of TST-M6-SESSION-JOB (WP-102): LAUNCH stay (#1) and nest (#2)
/// before READY, so the services that depend on the session start once both run; 300 ticks
/// for nest's child to start and for those services' END_SESSION to be refused; END_SESSION,
/// answered `ENDED 2`; 300 ticks for the ended session's exits to be seen, and END_SESSION again,
/// `ENDED 0` (no place is taken); LAUNCH stay (#3), in a new session job; END_SESSION, `ENDED 1`;
/// 300 ticks, and LAUNCH stay (#4), which stays. Traced
/// `ender|end=..|again=..|after=..|end2=..|last=..` as far as it went; 0x40 when each reply was
/// the stated one, `missed`'s code at the first step that saw another. BEGIN_SESSION opens the
/// gate first and again before steps 5 and 7, after END_SESSION closed it (WP-169).
fn ender(ch: u32) -> u64 {
    if !begin(ch) {
        return 0xE3;
    }
    let mut r = [0u8; 128];
    let (num, n) = launch(ch, b"stay", 0, &mut r);
    if num != 1 {
        return missed(1, num, &r[..n]);
    }
    let (num, n) = launch(ch, b"nest", 0, &mut r);
    if num != 2 {
        return missed(2, num, &r[..n]);
    }
    if libnawah::channel_write(ch, b"READY", &[]) != 0 {
        return 0xE2;
    }
    let _ = libnawah::sleep(300);
    let mut t = [0u8; 160];
    let mut at = 0;
    let mut put = |t: &mut [u8; 160], s: &[u8]| {
        let k = s.len().min(t.len() - at);
        t[at..at + k].copy_from_slice(&s[..k]);
        at += k;
        at
    };
    put(&mut t, b"ender");
    // (field, request, the stated reply, or the number of a LAUNCH's, step)
    let steps: [Step; 5] = [
        (b"|end=", b"END_SESSION", b"ENDED 2", 3),
        (b"|again=", b"END_SESSION", b"ENDED 0", 4),
        (b"|after=", b"stay", b"3", 5),
        (b"|end2=", b"END_SESSION", b"ENDED 1", 6),
        (b"|last=", b"stay", b"4", 7),
    ];
    for (field, req, want, step) in steps {
        if step == 4 || step == 7 {
            let _ = libnawah::sleep(300);
        }
        // END_SESSION closed the gate (v1.19): a new session begins before the next LAUNCH.
        if (step == 5 || step == 7) && !begin(ch) {
            return 0xE3;
        }
        let (ok, n, num) = if req == b"END_SESSION" {
            let n = ask(ch, req, &[], &mut r).unwrap_or(0).min(40);
            (r[..n] == *want, n, 0)
        } else {
            let (num, n) = launch(ch, req, 0, &mut r);
            (Some(num) == parse_num(want), n.min(40), num)
        };
        put(&mut t, field);
        let end = put(&mut t, &r[..n]);
        if !ok {
            libnawah::trace(&t[..end]);
            return missed(step, num, &r[..n]);
        }
    }
    libnawah::trace(&t[..at]);
    0x40
}

/// The application of TST-M6-APP-CONNECT-DENIED (WP-162), ids `conn` and `connx`, both
/// declaring `config`: asks the manager for `net` (allowed, not declared), `session` (not
/// allowed), `config` (declared), a `PING` on what `config` gave, and `config` again, and traces
/// `app:<id>#<n>|net=<reply>|session=<reply>|config=<reply>[|ping=<reply>|again=<reply>]`. `connx`
/// then exits 0x44; `conn` stays, waiting on its boot channel.
fn connecting(ch: u32, who: &[u8]) -> u64 {
    let mut t = [0u8; 160];
    let mut at = 0;
    let mut put = |t: &mut [u8; 160], s: &[u8]| {
        let n = s.len().min(t.len() - at);
        t[at..at + n].copy_from_slice(&s[..n]);
        at += n;
        at
    };
    put(&mut t, b"app:");
    put(&mut t, &who[..who.len().min(16)]);
    let mut reply = [0u8; 128];
    for (field, req) in [
        (&b"|net="[..], &b"CONNECT net"[..]),
        (b"|session=", b"CONNECT session"),
    ] {
        put(&mut t, field);
        let n = ask(ch, req, &[], &mut reply).unwrap_or(0);
        put(&mut t, if n == 0 { b"-" } else { &reply[..n] });
    }
    // `config`: the reply carries the client end of a channel to the service.
    put(&mut t, b"|config=");
    let mut hs = [0u32; 1];
    let mut got = None;
    if libnawah::channel_write(ch, b"CONNECT config", &[]) == 0
        && libnawah::object_wait_many(
            &[WaitEntry {
                handle: ch,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            }],
            1500,
        )
        .is_ok()
    {
        if let Ok((n, nh)) = libnawah::channel_read(ch, &mut reply, &mut hs, false) {
            put(&mut t, &reply[..n]);
            if nh == 1 {
                got = Some(hs[0]);
            }
        }
    }
    if let Some(cfg) = got {
        put(&mut t, b"|ping=");
        let n = ask(cfg, b"PING", &[], &mut reply).unwrap_or(0);
        put(&mut t, if n == 0 { b"-" } else { &reply[..n] });
        put(&mut t, b"|again=");
        let n = ask(ch, b"CONNECT config", &[], &mut reply).unwrap_or(0);
        let end = put(&mut t, if n == 0 { b"-" } else { &reply[..n] });
        libnawah::trace(&t[..end]);
    } else {
        let end = at;
        libnawah::trace(&t[..end]);
    }
    if who.starts_with(b"connx#") {
        return 0x44;
    }
    loop {
        if libnawah::channel_read(ch, &mut reply, &mut hs, true).is_err() {
            return 0;
        }
    }
}

/// The three applications the review round added to TST-M6-APP-CONNECT-DENIED (WP-162), each
/// of which traces what it was answered and exits: `both` (declares display and config) asks
/// for config, display and config again (`app:both#<n>|config=..|display=..|again=..`, exit
/// 0x45); `netonly` (declares net) asks for config (`app:netonly#<n>|config=..`, exit 0x46);
/// `stuck` (declares config) first asks 64 times for LIST without reading the replies, so its
/// queue is full when it asks for config, then reads what came and counts any reply that is
/// not ERR ACCESS (`app:stuck#<n>|asked=64|other=<k>`, exit 0x47).
fn connecting_more(ch: u32, who: &[u8]) -> u64 {
    let mut t = [0u8; 128];
    let mut at = 0;
    let mut put = |t: &mut [u8; 128], s: &[u8]| {
        let n = s.len().min(t.len() - at);
        t[at..at + n].copy_from_slice(&s[..n]);
        at += n;
        at
    };
    put(&mut t, b"app:");
    put(&mut t, &who[..who.len().min(16)]);
    let mut reply = [0u8; 128];
    let mut hs = [0u32; 1];
    let mut ask_one = |t: &mut [u8; 128], field: &[u8], req: &[u8]| {
        put(t, field);
        if libnawah::channel_write(ch, req, &[]) != 0
            || libnawah::object_wait_many(
                &[WaitEntry {
                    handle: ch,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                }],
                1500,
            )
            .is_err()
        {
            return put(t, b"-");
        }
        match libnawah::channel_read(ch, &mut reply, &mut hs, false) {
            Ok((n, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                put(t, &reply[..n])
            }
            Err(_) => put(t, b"-"),
        }
    };
    let (end, code) = if who.starts_with(b"both#") {
        ask_one(&mut t, b"|config=", b"CONNECT config");
        ask_one(&mut t, b"|display=", b"CONNECT display");
        (ask_one(&mut t, b"|again=", b"CONNECT config"), 0x45)
    } else if who.starts_with(b"netonly#") {
        (ask_one(&mut t, b"|config=", b"CONNECT config"), 0x46)
    } else {
        // 64 requests whose replies stay unread fill this side's queue (QUEUE_MAX).
        for _ in 0..64 {
            loop {
                match libnawah::channel_write(ch, b"LIST", &[]) {
                    0 => break,
                    libnawah::ERR_SHOULD_WAIT => {
                        let _ = libnawah::sleep(1);
                    }
                    _ => return 0xE5,
                }
            }
        }
        let _ = libnawah::sleep(200);
        loop {
            match libnawah::channel_write(ch, b"CONNECT config", &[]) {
                0 => break,
                libnawah::ERR_SHOULD_WAIT => {
                    let _ = libnawah::sleep(1);
                }
                _ => return 0xE5,
            }
        }
        let _ = libnawah::sleep(200);
        let mut other = 0u8;
        while let Ok((n, nh)) = libnawah::channel_read(ch, &mut reply, &mut hs, false) {
            if nh == 1 {
                libnawah::handle_close(hs[0]);
            }
            if reply[..n] != *b"ERR ACCESS" {
                other += 1;
            }
        }
        put(&mut t, b"|asked=64|other=");
        (put(&mut t, &[b'0' + other.min(9)]), 0x47)
    };
    libnawah::trace(&t[..end]);
    code
}

/// The vouched session's side of TST-M6-APP-CONNECT-DENIED (WP-162): READY, then `connx`,
/// which takes a connection to `config` and exits, the review round's `both`, `netonly` and
/// `stuck`, each of which exits, then five of `conn` 150 ticks apart, so that each has asked
/// before the next starts. 0x40 when every launch was answered `OK app:<id>#<n>` with the
/// numbers 1 to 9 in order; `missed`'s code otherwise.
fn connector(ch: u32) -> u64 {
    if libnawah::channel_write(ch, b"READY", &[]) != 0 {
        return 0xE2;
    }
    if !begin(ch) {
        return 0xE3;
    }
    let mut r = [0u8; 128];
    let (num, n) = launch(ch, b"connx", 0, &mut r);
    if num != 1 {
        return missed(1, num, &r[..n]);
    }
    let _ = libnawah::sleep(300);
    for (want, id) in [(2, &b"both"[..]), (3, b"netonly"), (4, b"stuck")] {
        let (num, n) = launch(ch, id, 0, &mut r);
        if num != want {
            return missed(3, num, &r[..n]);
        }
        let _ = libnawah::sleep(700);
    }
    for want in 5..=9 {
        let (num, n) = launch(ch, b"conn", 0, &mut r);
        if num != want {
            return missed(2, num, &r[..n]);
        }
        let _ = libnawah::sleep(150);
    }
    0x40
}

/// The image started as an application (WP-161): `who` is `<id>#<n>` of `START app:<id>#<n>`.
/// `orphan` gives a child that never exits both ends of a channel, so nothing ever wakes it,
/// and exits 0x42; `closer` closes its boot channel, stays 200 ticks and exits 0x43. Any other
/// id asks six requests on its boot channel, one of them larger than any the manager reads, one
/// carrying a handle and one carrying two, and stays: waiting on its channel until it
/// closes when each was refused `ERR ACCESS`; asleep, and holding one handle more for each
/// request that was not, otherwise (the test kernel reads both of the process). Traced
/// `app:<id>#<n>|...`.
fn application(ch: u32, who: &[u8]) -> u64 {
    let mut t = [0u8; 64];
    let head = b"app:";
    let who = &who[..who.len().min(16)];
    t[..head.len()].copy_from_slice(head);
    t[head.len()..head.len() + who.len()].copy_from_slice(who);
    let mut at = head.len() + who.len();
    let mut put = |t: &mut [u8; 64], s: &[u8]| {
        t[at..at + s.len()].copy_from_slice(s);
        at += s.len();
        at
    };
    if who.starts_with(b"conn#") || who.starts_with(b"connx#") {
        return connecting(ch, who);
    }
    if who.starts_with(b"both#") || who.starts_with(b"netonly#") || who.starts_with(b"stuck#") {
        return connecting_more(ch, who);
    }
    if who.starts_with(b"closer#") {
        libnawah::handle_close(ch);
        let _ = libnawah::sleep(200);
        let end = put(&mut t, b"|closed=1");
        libnawah::trace(&t[..end]);
        return 0x43;
    }
    if who.starts_with(b"hog#") {
        return hog(ch, who);
    }
    if who.starts_with(b"peer#") {
        // WP-164: a child now, and another once `hog` has filled its own job.
        let spawn = || {
            libnawah::channel_create()
                .and_then(|(a, b)| libnawah::process_spawn(b"/SYSTEM/IDLE.ELF", &[b, a]))
        };
        let first = spawn().is_ok();
        let _ = libnawah::sleep(1000);
        let late = spawn().is_ok();
        put(&mut t, if first { b"|child=1" } else { b"|child=0" });
        let end = put(&mut t, if late { b"|late=1" } else { b"|late=0" });
        libnawah::trace(&t[..end]);
        let mut reply = [0u8; 128];
        let mut hs = [0u32; 1];
        loop {
            if libnawah::channel_read(ch, &mut reply, &mut hs, true).is_err() {
                return 0;
            }
        }
    }
    if who.starts_with(b"nest#") {
        // WP-102: a child of its own in its job, then it waits on its boot channel.
        let child = libnawah::channel_create()
            .and_then(|(a, b)| libnawah::process_spawn(b"/SYSTEM/IDLE.ELF", &[b, a]));
        let end = put(
            &mut t,
            if child.is_ok() {
                b"|child=1"
            } else {
                b"|child=0"
            },
        );
        libnawah::trace(&t[..end]);
        let mut reply = [0u8; 128];
        let mut hs = [0u32; 1];
        loop {
            if libnawah::channel_read(ch, &mut reply, &mut hs, true).is_err() {
                return 0;
            }
        }
    }
    if who.starts_with(b"orphan#") {
        let child = libnawah::channel_create()
            .and_then(|(a, b)| libnawah::process_spawn(b"/SYSTEM/IDLE.ELF", &[b, a]));
        let end = put(
            &mut t,
            if child.is_ok() {
                b"|child=1"
            } else {
                b"|child=0"
            },
        );
        libnawah::trace(&t[..end]);
        return 0x42;
    }
    if who.starts_with(b"stay#") {
        // WP-102: an application's END_SESSION is refused as anything else it asks.
        let mut reply = [0u8; 128];
        let n = ask(ch, b"END_SESSION", &[], &mut reply)
            .unwrap_or(0)
            .min(16);
        put(&mut t, b"|end=");
        put(&mut t, &reply[..n]);
    }
    let big = [b'x'; 100];
    let asks: [&[u8]; 6] = [
        b"READY",
        b"LIST",
        b"CONNECT session",
        b"APPS",
        b"LAUNCH clock",
        &big,
    ];
    let mut reply = [0u8; 128];
    let mut refused = 0u8;
    for (i, req) in asks.iter().enumerate() {
        // Two requests carry handles: one end of a channel, then both ends of another. The
        // application keeps none of them (an end that went with a request is a number that
        // names nothing here, and closing it does nothing).
        let pair = (i == 1 || i == 2)
            .then(libnawah::channel_create)
            .and_then(Result::ok);
        let ends = pair.map(|(a, b)| [b, a]);
        let sent: &[u32] = match &ends {
            Some(e) if i == 1 => &e[..1],
            Some(e) => &e[..],
            None => &[],
        };
        if ask(ch, req, sent, &mut reply).is_some_and(|n| reply[..n] == *b"ERR ACCESS") {
            refused += 1;
        } else if let Ok((_kept, other)) = libnawah::channel_create() {
            libnawah::handle_close(other);
        }
        for h in ends.into_iter().flatten() {
            libnawah::handle_close(h);
        }
    }
    put(&mut t, b"|asked=6|refused=");
    let end = put(&mut t, &[b'0' + refused]);
    libnawah::trace(&t[..end]);
    if refused != 6 {
        loop {
            let _ = libnawah::sleep(1_000_000);
        }
    }
    let mut hs = [0u32; 1];
    loop {
        if libnawah::channel_read(ch, &mut reply, &mut hs, true).is_err() {
            return 0;
        }
    }
}

/// The `serve`/`crash_once`/`silent` roles: clients arrive as `CONNECT` + handle on the boot
/// channel.
fn serve(ch: u32, mode: Mode) -> u64 {
    if libnawah::channel_write(ch, b"READY", &[]) < 0 {
        return 0xE2;
    }
    let mut clients = [0u32; MAX_CLIENTS];
    // When each client's first unanswered request arrived (`silent`).
    let mut asked: [Option<u64>; MAX_CLIENTS] = [None; MAX_CLIENTS];
    let mut buf = [0u8; 128];
    let mut hs = [0u32; 1];
    loop {
        let mut entries = [WaitEntry {
            handle: ch,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        }; 1 + MAX_CLIENTS];
        let mut owner = [0usize; 1 + MAX_CLIENTS];
        let mut k = 1;
        for (i, &c) in clients.iter().enumerate() {
            if c != 0 {
                entries[k] = WaitEntry {
                    handle: c,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                };
                owner[k] = i;
                k += 1;
            }
        }
        let Ok((idx, _)) = libnawah::object_wait_many(&entries[..k], libnawah::TIMEOUT_FOREVER)
        else {
            return 0xE5;
        };
        if idx == 0 {
            match libnawah::channel_read(ch, &mut buf, &mut hs, false) {
                Ok((n, nh)) => {
                    if &buf[..n] == b"STOP" {
                        return 0;
                    }
                    if (buf[..n] == *b"CONNECT" || buf[..n].starts_with(b"CONNECT ")) && nh == 1 {
                        if mode == Mode::Names {
                            let mut t = [0u8; 64];
                            let head = b"svc|connect|";
                            let name = &buf[8.min(n)..n];
                            let name = &name[..name.len().min(t.len() - head.len())];
                            t[..head.len()].copy_from_slice(head);
                            t[head.len()..head.len() + name.len()].copy_from_slice(name);
                            libnawah::trace(&t[..head.len() + name.len()]);
                        }
                        match clients.iter().position(|&c| c == 0) {
                            Some(slot) => {
                                clients[slot] = hs[0];
                                asked[slot] = None;
                            }
                            None => {
                                libnawah::handle_close(hs[0]);
                            }
                        }
                    } else if nh == 1 {
                        libnawah::handle_close(hs[0]);
                    }
                }
                Err(ERR_PEER_CLOSED) => return 0,
                Err(_) => {}
            }
            continue;
        }
        let ci = owner[idx];
        let c = clients[ci];
        match libnawah::channel_read(c, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                if let Mode::Silent { .. } = mode {
                    // Taken, never answered.
                    if asked[ci].is_none() {
                        asked[ci] = Some(libnawah::clock_ticks());
                    }
                    continue;
                }
                if mode == Mode::CrashOnce && libnawah::stat(CRASH_MARK).is_err() {
                    // The first request of this volume's life: leave the mark and die
                    // without answering (the client sees its channel close).
                    if let Ok(f) = libnawah::open(
                        CRASH_MARK,
                        libnawah::O_WRITE | libnawah::O_CREATE | libnawah::O_TRUNCATE,
                    ) {
                        let _ = libnawah::write(f, b"crashed once\n");
                        libnawah::handle_close(f);
                        let _ = libnawah::sync();
                    }
                    return 3;
                }
                let mut relayed = [0u8; 128];
                let reply: &[u8] = if &buf[..n] == b"PING" {
                    b"OK served"
                } else if mode == Mode::Relay && buf[..n].starts_with(b"LAUNCH ") {
                    match ask(ch, &buf[..n], &[], &mut relayed) {
                        Some(k) => &relayed[..k],
                        None => b"ERR UNAVAILABLE",
                    }
                } else {
                    b"ERR BAD_REQUEST"
                };
                if libnawah::channel_write(c, reply, &[]) == ERR_PEER_CLOSED {
                    // The client vanished between its request and the reply: nothing to do
                    // but release its channel; other clients are unaffected.
                    libnawah::handle_close(c);
                    clients[ci] = 0;
                }
            }
            Err(ERR_PEER_CLOSED) => {
                if let (Mode::Silent { lo, hi }, Some(t)) = (mode, asked[ci]) {
                    trace_held(libnawah::clock_ticks().saturating_sub(t), lo, hi);
                }
                libnawah::handle_close(c);
                clients[ci] = 0;
                asked[ci] = None;
            }
            Err(_) => {}
        }
    }
}

fn main() -> u64 {
    let ch = libnawah::bootstrap_handle();
    if ch == 0 {
        return 0xE0;
    }
    let mut buf = [0u8; 128];
    let mut hs = [0u32; 1];
    let n = match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
        Ok((n, _)) => n,
        Err(_) => return 0xE1,
    };
    let role = buf[..n].strip_prefix(b"START ").unwrap_or(b"");
    // `silent <lo> <hi>`: the expected window for how long a client holds an unanswered request.
    if let Some(window) = role.strip_prefix(b"silent ") {
        let mut it = window.split(|&c| c == b' ').filter(|w| !w.is_empty());
        let (Some(lo), Some(hi)) = (it.next().and_then(parse_num), it.next().and_then(parse_num))
        else {
            return 2;
        };
        return serve(ch, Mode::Silent { lo, hi });
    }
    // `ask <request>=<expected>[;<request>=<expected>]` (WP-101, TST-M6-LAUNCH-DENIED): READY,
    // then each request on the boot channel in turn. The exit code tells the test kernel what
    // came back: 0x40 when every reply was the expected one, 0x50 + k when the k-th reply was
    // another, 0x60 + k when the k-th request got no reply within 1500 ticks.
    if let Some(script) = role.strip_prefix(b"ask ") {
        if libnawah::channel_write(ch, b"READY", &[]) != 0 {
            return 0xE2;
        }
        let mut k = 0u64;
        for pair in script.split(|&c| c == b';') {
            k += 1;
            let Some(eq) = pair.iter().position(|&c| c == b'=') else {
                return 2;
            };
            if libnawah::channel_write(ch, &pair[..eq], &[]) != 0 {
                return 0xE5;
            }
            let waited = libnawah::object_wait_many(
                &[WaitEntry {
                    handle: ch,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                }],
                1500,
            );
            if waited.is_err() {
                return 0x60 + k;
            }
            let mut reply = [0u8; 128];
            match libnawah::channel_read(ch, &mut reply, &mut hs, false) {
                Ok((n, _)) if reply[..n] == pair[eq + 1..] => {}
                Ok(_) => return 0x50 + k,
                Err(_) => return 0x60 + k,
            }
        }
        return 0x40;
    }
    if let Some(who) = role.strip_prefix(b"app:") {
        return application(ch, who);
    }
    match role {
        b"launcher" => hold(ch, launcher(ch)),
        // `loud` (review 2026-10-19, M1): first a message larger than any request the manager
        // reads, then behaves as `ready` — the manager must discard it and still see READY.
        b"ready" | b"loud" => {
            if role == b"loud" && libnawah::channel_write(ch, &[b'x'; 100], &[]) < 0 {
                return 0xE2;
            }
            if libnawah::channel_write(ch, b"READY", &[]) < 0 {
                return 0xE2;
            }
            loop {
                match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
                    Ok((n, _)) if &buf[..n] == b"STOP" => return 0,
                    // Watchdog (services.md v1.7): answer the manager's PING so it knows we
                    // are alive; each answer is traced so the test can count them.
                    Ok((n, _)) if &buf[..n] == b"PING" => {
                        if libnawah::channel_write(ch, b"PONG", &[]) == ERR_PEER_CLOSED {
                            return 0;
                        }
                        libnawah::trace(b"svc|pong");
                    }
                    Ok(_) => {}
                    Err(ERR_PEER_CLOSED) => return 0,
                    Err(_) => return 0xE3,
                }
            }
        }
        // Answers READY, then never services its boot channel again — it never PONGs (and never
        // sees STOP), so the watchdog finds it hung and kills it, and STOP must force it
        // (services.md v1.7, TST-M5-SVC-WATCHDOG). It blocks on a channel nobody signals rather
        // than spinning, so it consumes no CPU and does not starve the rest of the system.
        b"hang" => {
            if libnawah::channel_write(ch, b"READY", &[]) < 0 {
                return 0xE2;
            }
            let Ok((a, _keep)) = libnawah::channel_create() else {
                return 0xE3;
            };
            loop {
                let _ = libnawah::object_wait_many(
                    &[WaitEntry {
                        handle: a,
                        signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                    }],
                    libnawah::TIMEOUT_FOREVER,
                );
            }
        }
        // Review 2026-10-19 (S1): answers READY, then closes its boot channel and stays alive,
        // blocked on a channel nobody signals. A watchdog-monitored manager can no longer PING
        // it and must treat it as hung — not leave a deadline in the past and spin.
        b"closer" => {
            if libnawah::channel_write(ch, b"READY", &[]) < 0 {
                return 0xE2;
            }
            let Ok((a, _keep)) = libnawah::channel_create() else {
                return 0xE3;
            };
            libnawah::handle_close(ch);
            loop {
                let _ = libnawah::object_wait_many(
                    &[WaitEntry {
                        handle: a,
                        signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                    }],
                    libnawah::TIMEOUT_FOREVER,
                );
            }
        }
        // Review 2026-10-19 (S2): hangs before READY without reading its channel, so closing
        // the channel at the readiness timeout does not end it; the manager must force it.
        b"early_hang" => {
            let Ok((a, _keep)) = libnawah::channel_create() else {
                return 0xE3;
            };
            loop {
                let _ = libnawah::object_wait_many(
                    &[WaitEntry {
                        handle: a,
                        signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                    }],
                    libnawah::TIMEOUT_FOREVER,
                );
            }
        }
        // Review 2026-10-19 (TST-M5-KILL-EDGES, K3): writes `T` on its boot channel every 5
        // ticks from a timed wait on a channel nobody signals. Frozen, it must stop ticking —
        // its timed waits do not expire — and process_kill must still end it.
        b"ticker" => {
            let Ok((a, _keep)) = libnawah::channel_create() else {
                return 0xE3;
            };
            loop {
                let _ = libnawah::object_wait_many(
                    &[WaitEntry {
                        handle: a,
                        signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                    }],
                    5,
                );
                if libnawah::channel_write(ch, b"T", &[]) == ERR_PEER_CLOSED {
                    return 0;
                }
            }
        }
        // Review 2026-10-19 (TST-M5-PROCESS-KILL): asleep for a million ticks, so only
        // process_kill ends it — through the sleep returning to the kill safe point.
        b"sleeper" => {
            let _ = libnawah::sleep(1_000_000);
            0
        }
        b"mute" => loop {
            match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
                Ok(_) => {}
                Err(ERR_PEER_CLOSED) => return 0,
                Err(_) => return 0xE4,
            }
        },
        // WP-156 (RSK-028; TST-M4-SVC-CONNECT-NOREAD): a requester that never reads. Before
        // READY it asks the manager 64 times for LIST, whose unread replies fill its queue, then
        // three times for a connection to `config`: the manager cannot write those replies.
        // READY goes last on the same channel, so a manager that shows this service ready has
        // handled every request before it. Then it blocks, still reading nothing.
        b"noread" => {
            let send = |req: &[u8]| loop {
                match libnawah::channel_write(ch, req, &[]) {
                    0 => break true,
                    libnawah::ERR_SHOULD_WAIT => {
                        let _ = libnawah::sleep(1);
                    }
                    _ => break false,
                }
            };
            for _ in 0..64 {
                if !send(b"LIST") {
                    return 0xE5;
                }
            }
            for _ in 0..3 {
                if !send(b"CONNECT config") {
                    return 0xE5;
                }
            }
            if !send(b"READY") {
                return 0xE2;
            }
            let Ok((a, _keep)) = libnawah::channel_create() else {
                return 0xE3;
            };
            loop {
                let _ = libnawah::object_wait_many(
                    &[WaitEntry {
                        handle: a,
                        signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                    }],
                    libnawah::TIMEOUT_FOREVER,
                );
            }
        }
        b"crash" => 1,
        b"serve" => serve(ch, Mode::Serve),
        b"names" => serve(ch, Mode::Names),
        b"relay" => serve(ch, Mode::Relay),
        b"connector" => hold(ch, connector(ch)),
        b"ender" => hold(ch, ender(ch)),
        b"bounder" => hold(ch, bounder(ch)),
        b"rater" => hold(ch, rater(ch)),
        b"gater" => gater(ch),
        b"stayer" => hold(ch, stayer(ch)),
        b"ungated" => ungated(ch),
        b"crash_once" => serve(ch, Mode::CrashOnce),
        _ => 2,
    }
}
