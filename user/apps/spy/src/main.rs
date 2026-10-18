//! spy — a test client of the display service (WP-37, session.md §9): one window, moved to
//! (100, 100) and filled with one colour, that writes every event it gets from the compositor
//! to the diagnostic channel (`spy|key=…`, `spy|focus=…`), so a test can prove what reached
//! an application — and what did not (the keys typed for the session). It comes back with a
//! new window after the compositor restarts, and ends on `LOGGED_OUT` once it has checked that
//! its windows are gone. Clients (tests) ask `COUNT`.
//!
//! Initial handle: the boot channel. Dependency: `display`.

#![no_std]
#![no_main]

use libnawah::display::Surface;
use libnawah::{
    Handle, WaitEntry, ERR_PEER_CLOSED, ERR_SHOULD_WAIT, ERR_TIMED_OUT, SIGNAL_PEER_CLOSED,
    SIGNAL_READABLE,
};

libnawah::entry!(main);

const W: u32 = 200;
const H: u32 = 120;
const AT: (i64, i64) = (100, 100);
const COLOUR: u32 = 0x2E8B57;
const MSG_MAX: usize = 512;
const EV_MAX: usize = 128;
const PENDING: usize = 32;
const MAX_CLIENTS: usize = 4;
const RECONNECT: u64 = 50;

struct Out {
    buf: [u8; MSG_MAX],
    len: usize,
}

impl Out {
    fn new() -> Out {
        Out {
            buf: [0; MSG_MAX],
            len: 0,
        }
    }
    fn put(&mut self, s: &[u8]) -> &mut Self {
        let n = s.len().min(MSG_MAX - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
        self
    }
    fn num(&mut self, v: i64) -> &mut Self {
        if v < 0 {
            self.put(b"-");
        }
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        let mut v = v.unsigned_abs();
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&tmp[i..])
    }
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

fn parse_i64(s: &[u8]) -> Option<i64> {
    if s.is_empty() || s.len() > 12 {
        return None;
    }
    let mut v = 0i64;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + i64::from(c - b'0');
    }
    Some(v)
}

/// The display channel; events that arrive while a request waits are kept in order.
struct Conn {
    chan: Handle,
    pending: [[u8; EV_MAX]; PENDING],
    pending_len: [usize; PENDING],
    head: usize,
    count: usize,
}

impl Conn {
    fn new(chan: Handle) -> Conn {
        Conn {
            chan,
            pending: [[0; EV_MAX]; PENDING],
            pending_len: [0; PENDING],
            head: 0,
            count: 0,
        }
    }

    fn request(&mut self, req: &[u8], handles: &[Handle], reply: &mut [u8]) -> Result<usize, i64> {
        if libnawah::channel_write(self.chan, req, handles) != 0 {
            for &h in handles {
                libnawah::handle_close(h);
            }
            return Err(ERR_PEER_CLOSED);
        }
        loop {
            let mut msg = [0u8; MSG_MAX];
            let mut hs = [0u32; 1];
            match libnawah::channel_read(self.chan, &mut msg, &mut hs, false) {
                Ok((n, nh)) => {
                    if nh == 1 {
                        libnawah::handle_close(hs[0]);
                    }
                    if msg[..n].starts_with(b"OK") || msg[..n].starts_with(b"ERR") {
                        let k = n.min(reply.len());
                        reply[..k].copy_from_slice(&msg[..k]);
                        return Ok(k);
                    }
                    if self.count < PENDING {
                        let slot = (self.head + self.count) % PENDING;
                        let k = n.min(EV_MAX);
                        self.pending[slot][..k].copy_from_slice(&msg[..k]);
                        self.pending_len[slot] = k;
                        self.count += 1;
                    }
                }
                Err(ERR_SHOULD_WAIT) => {
                    let _ = libnawah::object_wait_many(
                        &[WaitEntry {
                            handle: self.chan,
                            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                        }],
                        5000,
                    );
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn next_pending(&mut self, out: &mut [u8; EV_MAX]) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let slot = self.head;
        let n = self.pending_len[slot];
        out[..n].copy_from_slice(&self.pending[slot][..n]);
        self.head = (self.head + 1) % PENDING;
        self.count -= 1;
        Some(n)
    }
}

struct Spy {
    display: Option<Conn>,
    asked: bool,
    retry: u64,
    surface: Option<Surface>,
    keys: i64,
    focused: bool,
    connections: i64,
    clients: [Handle; MAX_CLIENTS],
}

impl Spy {
    /// The window: a surface of one colour in a window titled `Spy` at (100, 100).
    fn setup(&mut self) -> bool {
        let Some(d) = self.display.as_mut() else {
            return false;
        };
        let mut reply = [0u8; MSG_MAX];
        let Ok(n) = d.request(b"STATUS", &[], &mut reply) else {
            return false;
        };
        let Some(i) = reply[..n].windows(7).position(|w| w == b"format=") else {
            return false;
        };
        let format = u32::from(reply[i + 7].wrapping_sub(b'0'));
        if let Some(old) = self.surface.take() {
            old.destroy();
        }
        let Ok(s) = Surface::new(W, H, format) else {
            return false;
        };
        s.fill(COLOUR);
        let Ok(share) = s.share() else {
            s.destroy();
            return false;
        };
        self.surface = Some(s);
        let Ok(n) = d.request(b"CREATE_SURFACE 200 120", &[share], &mut reply) else {
            return false;
        };
        let Some(sid) = reply[..n].strip_prefix(b"OK ").and_then(parse_i64) else {
            return false;
        };
        let mut req = Out::new();
        req.put(b"CREATE_WINDOW ").num(sid).put(b" Spy");
        let Ok(n) = d.request(req.bytes(), &[], &mut reply) else {
            return false;
        };
        let Some(wid) = reply[..n].strip_prefix(b"OK ").and_then(parse_i64) else {
            return false;
        };
        let mut req = Out::new();
        req.put(b"MOVE ")
            .num(wid)
            .put(b" ")
            .num(AT.0)
            .put(b" ")
            .num(AT.1);
        if d.request(req.bytes(), &[], &mut reply).is_err() {
            return false;
        }
        let mut req = Out::new();
        req.put(b"COMMIT ").num(sid).put(b" 0 0 200 120");
        d.request(req.bytes(), &[], &mut reply).is_ok()
    }

    fn display_lost(&mut self, now: u64) {
        if let Some(c) = self.display.take() {
            libnawah::handle_close(c.chan);
        }
        self.focused = false;
        self.retry = now;
    }

    /// One event from the compositor; `false` ends the program (logged out).
    fn on_event(&mut self, msg: &[u8], now: u64) -> bool {
        let mut t = Out::new();
        if let Some(rest) = msg.strip_prefix(b"KEY ") {
            // KEY <code> <down|up> <mods> <char>
            let mut f = rest.split(|&c| c == b' ').filter(|x| !x.is_empty());
            let (code, dir, _, ch) = (f.next(), f.next(), f.next(), f.next());
            self.keys += 1;
            t.put(b"spy|key=")
                .put(code.unwrap_or(b"?"))
                .put(b",")
                .put(dir.unwrap_or(b"?"))
                .put(b",");
            let ch = ch.unwrap_or(b"?");
            if ch.iter().all(|&b| (0x21..0x7F).contains(&b)) {
                t.put(ch);
            } else if let Some(c) = core::str::from_utf8(ch).ok().and_then(|s| s.chars().next()) {
                t.put(b"u+").num(c as i64);
            }
        } else if msg.starts_with(b"FOCUS ") {
            self.focused = true;
            t.put(b"spy|focus=1");
        } else if msg.starts_with(b"UNFOCUS ") {
            self.focused = false;
            t.put(b"spy|focus=0");
        } else if msg == b"LOGGED_OUT" {
            // Our windows are gone: LIST must say so, then a well-behaved app ends.
            let mut reply = [0u8; MSG_MAX];
            let windows = match self
                .display
                .as_mut()
                .map(|d| d.request(b"LIST", &[], &mut reply))
            {
                Some(Ok(n)) => reply[..n]
                    .split(|&c| c == b'\n')
                    .filter(|l| l.starts_with(b"W "))
                    .count() as i64,
                _ => {
                    self.display_lost(now);
                    -1
                }
            };
            t.put(b"spy|logged_out|windows=").num(windows);
            libnawah::trace(t.bytes());
            return false;
        } else {
            return true;
        }
        libnawah::trace(t.bytes());
        true
    }

    fn on_client(&mut self, k: usize) {
        let c = self.clients[k];
        let mut buf = [0u8; 64];
        let mut hs = [0u32; 1];
        match libnawah::channel_read(c, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                let mut out = Out::new();
                if &buf[..n] == b"COUNT" {
                    out.put(b"OK keys=")
                        .num(self.keys)
                        .put(b" focus=")
                        .num(i64::from(self.focused))
                        .put(b" connections=")
                        .num(self.connections);
                } else {
                    out.put(b"ERR BAD_REQUEST");
                }
                if libnawah::channel_write(c, out.bytes(), &[]) == ERR_PEER_CLOSED {
                    libnawah::handle_close(c);
                    self.clients[k] = 0;
                }
            }
            Err(ERR_PEER_CLOSED) => {
                libnawah::handle_close(c);
                self.clients[k] = 0;
            }
            Err(_) => {}
        }
    }
}

fn manager_connect(boot: Handle, name: &[u8]) -> Option<Handle> {
    let mut req = Out::new();
    req.put(b"CONNECT ").put(name);
    if libnawah::channel_write(boot, req.bytes(), &[]) != 0 {
        return None;
    }
    let mut buf = [0u8; 64];
    let mut hs = [0u32; 1];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((2, 1)) if &buf[..2] == b"OK" => Some(hs[0]),
        _ => None,
    }
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let mut buf = [0u8; MSG_MAX];
    let mut hs = [0u32; 1];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((n, _)) if buf[..n].starts_with(b"START") => {}
        _ => return 0xE1,
    }
    let Some(chan) = manager_connect(boot, b"display") else {
        return 0xE2;
    };
    let mut spy = Spy {
        display: Some(Conn::new(chan)),
        asked: false,
        retry: 0,
        surface: None,
        keys: 0,
        focused: false,
        connections: 1,
        clients: [0; MAX_CLIENTS],
    };
    if !spy.setup() {
        return 0xE3;
    }
    let mut t = Out::new();
    t.put(b"spy|window=created|at=")
        .num(AT.0)
        .put(b",")
        .num(AT.1)
        .put(b",")
        .num(i64::from(W))
        .put(b",")
        .num(i64::from(H));
    libnawah::trace(t.bytes());
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE4;
    }
    loop {
        let now = libnawah::clock_ticks();
        // Events kept while a request waited come first.
        let mut ev = [0u8; EV_MAX];
        while let Some(n) = spy.display.as_mut().and_then(|d| d.next_pending(&mut ev)) {
            if !spy.on_event(&ev[..n], now) {
                return 0;
            }
        }
        if spy.display.is_none() && !spy.asked && now >= spy.retry {
            if libnawah::channel_write(boot, b"CONNECT display", &[]) == 0 {
                spy.asked = true;
            } else {
                spy.retry = now + RECONNECT;
            }
        }
        let mut entries = [WaitEntry {
            handle: 0,
            signals: 0,
        }; 2 + MAX_CLIENTS];
        let mut kind = [0usize; 2 + MAX_CLIENTS];
        entries[0] = WaitEntry {
            handle: boot,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        };
        kind[0] = 100;
        let mut k = 1;
        if let Some(d) = spy.display.as_ref() {
            entries[k] = WaitEntry {
                handle: d.chan,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            };
            kind[k] = 101;
            k += 1;
        }
        for (j, &c) in spy.clients.iter().enumerate() {
            if c != 0 {
                entries[k] = WaitEntry {
                    handle: c,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                };
                kind[k] = j;
                k += 1;
            }
        }
        let timeout = if spy.display.is_none() && !spy.asked {
            spy.retry.saturating_sub(now).max(1)
        } else {
            libnawah::TIMEOUT_FOREVER
        };
        let r = libnawah::object_wait_many(&entries[..k], timeout);
        let now = libnawah::clock_ticks();
        match r {
            Ok((idx, _)) => match kind[idx] {
                100 => match libnawah::channel_read(boot, &mut buf, &mut hs, false) {
                    Ok((n, nh)) => {
                        let msg = &buf[..n];
                        if (msg == b"CONNECT" || msg.starts_with(b"CONNECT ")) && nh == 1 {
                            match spy.clients.iter().position(|&c| c == 0) {
                                Some(j) => spy.clients[j] = hs[0],
                                None => {
                                    libnawah::handle_close(hs[0]);
                                }
                            }
                        } else if msg == b"STOP" {
                            return 0;
                        } else if spy.asked && msg == b"OK" && nh == 1 {
                            spy.asked = false;
                            spy.display = Some(Conn::new(hs[0]));
                            if spy.setup() {
                                spy.connections += 1;
                                let mut t = Out::new();
                                t.put(b"spy|reconnected|n=").num(spy.connections);
                                libnawah::trace(t.bytes());
                            } else {
                                spy.display_lost(now);
                                spy.retry = now + RECONNECT;
                            }
                        } else if spy.asked && msg.starts_with(b"ERR") {
                            spy.asked = false;
                            spy.retry = now + RECONNECT;
                            if nh == 1 {
                                libnawah::handle_close(hs[0]);
                            }
                        } else if nh == 1 {
                            libnawah::handle_close(hs[0]);
                        }
                    }
                    Err(ERR_PEER_CLOSED) => return 0,
                    Err(_) => {}
                },
                101 => {
                    let chan = spy.display.as_ref().map_or(0, |d| d.chan);
                    match libnawah::channel_read(chan, &mut buf, &mut hs, false) {
                        Ok((n, nh)) => {
                            if nh == 1 {
                                libnawah::handle_close(hs[0]);
                            }
                            let mut m = [0u8; EV_MAX];
                            let n = n.min(EV_MAX);
                            m[..n].copy_from_slice(&buf[..n]);
                            if !spy.on_event(&m[..n], now) {
                                return 0;
                            }
                        }
                        Err(ERR_PEER_CLOSED) => spy.display_lost(now),
                        Err(_) => {}
                    }
                }
                j => spy.on_client(j),
            },
            Err(ERR_TIMED_OUT) => {}
            Err(_) => return 0xE5,
        }
    }
}
