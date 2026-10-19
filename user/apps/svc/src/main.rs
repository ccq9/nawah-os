//! svc — a test service for the service manager (WP-24, services.md §4): its first message
//! `START <arg>` picks the role: `ready` answers READY and waits for STOP (or the channel's
//! close) then exits 0; `mute` never answers and exits 0 once the channel closes; `crash`
//! exits 1 at once; (WP-31) `serve` answers READY and serves clients the manager connects
//! (`PING` → `OK served`); `crash_once` serves the same way but dies (exit 3, no reply) on
//! the first request of its life on this volume — it leaves `/SYSTEM/CRASHED.TXT` behind so
//! the instance the manager restarts serves normally (TST-M4-PEER-LOSS). (WP-40) `ready` also
//! answers the watchdog's `PING` with `PONG` (traced `svc|pong`); `hang` answers READY then stops servicing its
//! channel, so the watchdog finds it hung and kills it (TST-M5-SVC-WATCHDOG). (Review
//! 2026-10-19) `closer` answers READY then closes its boot channel and stays alive; `early_hang`
//! hangs before READY without reading its channel; `ticker` writes `T` every 5 ticks from a timed
//! wait; `sleeper` sleeps a million ticks; `silent <lo> <hi>` serves clients like `serve` but
//! never answers (TST-M5-SESSION-DEADLINE). Anything else exits 2; a missing bootstrap handle
//! 0xE0.

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
    /// Never answers. When a client whose request went unanswered closes its channel, traces
    /// `svc|silent|held=<ticks>|in_window=<0|1>`: the ticks from the request's arrival to the
    /// close, and whether they fall within [lo, hi] (the test's expected deadline window).
    Silent { lo: u64, hi: u64 },
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
const CRASH_MARK: &[u8] = b"/SYSTEM/CRASHED.TXT";

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
                let reply: &[u8] = if &buf[..n] == b"PING" {
                    b"OK served"
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
    match role {
        b"ready" => {
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
        b"crash" => 1,
        b"serve" => serve(ch, Mode::Serve),
        b"crash_once" => serve(ch, Mode::CrashOnce),
        _ => 2,
    }
}
