//! svc — a test service for the service manager (WP-24, services.md §4): its first message
//! `START <arg>` picks the role: `ready` answers READY and waits for STOP (or the channel's
//! close) then exits 0; `mute` never answers and exits 0 once the channel closes; `crash`
//! exits 1 at once; (WP-31) `serve` answers READY and serves clients the manager connects
//! (`PING` → `OK served`); `crash_once` serves the same way but dies (exit 3, no reply) on
//! the first request of its life on this volume — it leaves `/SYSTEM/CRASHED.TXT` behind so
//! the instance the manager restarts serves normally (TST-M4-PEER-LOSS). (WP-40) `ready` also
//! answers the watchdog's `PING` with `PONG`; `hang` answers READY then stops servicing its
//! channel, so the watchdog finds it hung and kills it (TST-M5-SVC-WATCHDOG). Anything else
//! exits 2; a missing bootstrap handle 0xE0.

#![no_std]
#![no_main]

use libnawah::{WaitEntry, ERR_PEER_CLOSED, SIGNAL_PEER_CLOSED, SIGNAL_READABLE};

libnawah::entry!(main);

const MAX_CLIENTS: usize = 4;
const CRASH_MARK: &[u8] = b"/SYSTEM/CRASHED.TXT";

/// The `serve`/`crash_once` roles: clients arrive as `CONNECT` + handle on the boot channel.
fn serve(ch: u32, crash_once: bool) -> u64 {
    if libnawah::channel_write(ch, b"READY", &[]) < 0 {
        return 0xE2;
    }
    let mut clients = [0u32; MAX_CLIENTS];
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
                            Some(slot) => clients[slot] = hs[0],
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
                if crash_once && libnawah::stat(CRASH_MARK).is_err() {
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
                libnawah::handle_close(c);
                clients[ci] = 0;
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
    match role {
        b"ready" => {
            if libnawah::channel_write(ch, b"READY", &[]) < 0 {
                return 0xE2;
            }
            loop {
                match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
                    Ok((n, _)) if &buf[..n] == b"STOP" => return 0,
                    // Watchdog (services.md v1.7): answer the manager's PING so it knows we
                    // are alive.
                    Ok((n, _)) if &buf[..n] == b"PING" => {
                        if libnawah::channel_write(ch, b"PONG", &[]) == ERR_PEER_CLOSED {
                            return 0;
                        }
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
        b"mute" => loop {
            match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
                Ok(_) => {}
                Err(ERR_PEER_CLOSED) => return 0,
                Err(_) => return 0xE4,
            }
        },
        b"crash" => 1,
        b"serve" => serve(ch, false),
        b"crash_once" => serve(ch, true),
        _ => 2,
    }
}
