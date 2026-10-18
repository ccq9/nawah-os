//! `sh` — the diagnostic shell (WP-30, shell.md v1, ADR-0018): a line-oriented command
//! interpreter on the diagnostic console (COM2, reached by the lab through a TCP socket).
//! Every command shows state from its owner, never from a cache of its own: services from
//! the manager (`LIST` on the boot channel), the network from the `net` service, the
//! kernel's counters from `system_info`, files from the volume. Protected commands carry the
//! session token obtained by `login` from the `auth` service; the services check it.
//!
//! Initial handles: the boot channel (rdi) and the console (rdi + 1).

#![no_std]
#![no_main]

use libnawah::{WaitEntry, ERR_PEER_CLOSED, SIGNAL_PEER_CLOSED, SIGNAL_READABLE};

libnawah::entry!(main);

const LINE_MAX: usize = 256;
const OUT_MAX: usize = 4096;
const NAME_MAX: usize = 32;
/// Bounded wait for a reply from a service or the manager.
const REPLY_TICKS: u64 = 10_000;

struct Shell {
    boot: u32,
    console: u32,
    line: [u8; LINE_MAX],
    line_len: usize,
    too_long: bool,
    token: Option<u32>,
    user: [u8; NAME_MAX],
    user_len: usize,
    /// The manager said STOP while a reply was awaited: exit after the current command.
    stop_requested: bool,
}

struct Out {
    buf: [u8; OUT_MAX],
    len: usize,
}

impl Out {
    fn put(&mut self, s: &[u8]) {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
    fn num(&mut self, mut v: u64) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&tmp[i..]);
    }
    fn err(&mut self, code: i64) {
        self.put(b"ERR ");
        self.put(match code {
            libnawah::ERR_NOT_FOUND => b"NOT_FOUND",
            libnawah::ERR_IS_DIR => b"IS_DIR",
            libnawah::ERR_NOT_DIR => b"NOT_DIR",
            libnawah::ERR_BAD_PATH => b"BAD_PATH",
            libnawah::ERR_RANGE => b"TOO_LARGE",
            libnawah::ERR_ACCESS => b"ACCESS",
            _ => b"IO",
        });
        self.put(b"\n");
    }
}

fn field(s: &[u8], i: usize) -> Option<&[u8]> {
    s.split(|c| *c == b' ').filter(|f| !f.is_empty()).nth(i)
}

impl Shell {
    fn write_all(&self, mut data: &[u8]) {
        let mut tries = 0;
        while !data.is_empty() {
            match libnawah::serial_write(self.console, data) {
                Ok(n) if n > 0 => {
                    data = &data[n..];
                    tries = 0;
                }
                Ok(_) | Err(libnawah::ERR_SHOULD_WAIT) => {
                    tries += 1;
                    if tries == 100 {
                        return;
                    }
                    libnawah::sleep(1);
                }
                Err(_) => return,
            }
        }
    }

    fn prompt(&self) {
        let mut out = [0u8; NAME_MAX + 16];
        let mut n = 0;
        if self.token.is_some() {
            out[..self.user_len].copy_from_slice(&self.user[..self.user_len]);
            n = self.user_len;
            out[n] = b'@';
            n += 1;
        }
        out[n..n + 7].copy_from_slice(b"nawah> ");
        n += 7;
        self.write_all(&out[..n]);
    }

    /// A request to the manager on the boot channel; the reply (and one handle, if any). A
    /// `STOP` that arrives instead is honoured once the command finishes.
    fn manager(&mut self, req: &[u8], reply: &mut [u8]) -> Result<(usize, Option<u32>), i64> {
        if libnawah::channel_write(self.boot, req, &[]) != 0 {
            return Err(libnawah::ERR_PEER_CLOSED);
        }
        match wait_reply(self.boot, reply) {
            Ok((4, h)) if &reply[..4] == b"STOP" => {
                if let Some(h) = h {
                    libnawah::handle_close(h);
                }
                self.stop_requested = true;
                Err(ERR_PEER_CLOSED)
            }
            Err(ERR_PEER_CLOSED) => {
                self.stop_requested = true;
                Err(ERR_PEER_CLOSED)
            }
            other => other,
        }
    }

    /// A client channel to a service the manifest lets us reach (`CONNECT` on the boot
    /// channel), or the manager's refusal.
    fn connect(&mut self, name: &[u8], out: &mut Out) -> Option<u32> {
        let mut req = [0u8; 8 + NAME_MAX];
        req[..8].copy_from_slice(b"CONNECT ");
        let n = name.len().min(NAME_MAX);
        req[8..8 + n].copy_from_slice(&name[..n]);
        let mut reply = [0u8; 64];
        match self.manager(&req[..8 + n], &mut reply) {
            Ok((len, Some(h))) if &reply[..len] == b"OK" => Some(h),
            Ok((len, h)) => {
                if let Some(h) = h {
                    libnawah::handle_close(h);
                }
                out.put(&reply[..len]);
                out.put(b"\n");
                None
            }
            Err(_) => {
                out.put(b"ERR MANAGER\n");
                None
            }
        }
    }

    /// One request/reply on a service channel; the reply text goes to `out` (with the
    /// trailing newline) and the handle it carried comes back.
    fn ask(&self, chan: u32, req: &[u8], handles: &[u32], out: &mut Out) -> Option<u32> {
        if libnawah::channel_write(chan, req, handles) != 0 {
            out.put(b"ERR SERVICE\n");
            return None;
        }
        let mut reply = [0u8; 2048];
        match wait_reply(chan, &mut reply) {
            Ok((n, h)) => {
                out.put(&reply[..n]);
                out.put(b"\n");
                h
            }
            Err(_) => {
                out.put(b"ERR SERVICE\n");
                None
            }
        }
    }

    fn run(&mut self, line: &[u8], out: &mut Out) -> bool {
        let Some(cmd) = field(line, 0) else {
            return true;
        };
        match cmd {
            b"help" => out.put(
                b"commands: help svc cpu mem net [dhcp|policy internet=0|1] ls [path] cat <path> login <user> <password> whoami logout exit\n",
            ),
            b"svc" => {
                let mut reply = [0u8; 2048];
                match self.manager(b"LIST", &mut reply) {
                    Ok((n, h)) => {
                        if let Some(h) = h {
                            libnawah::handle_close(h);
                        }
                        out.put(&reply[..n]);
                    }
                    Err(_) => out.put(b"ERR MANAGER\n"),
                }
            }
            b"cpu" => match libnawah::system_info() {
                Ok(i) => {
                    out.put(b"cpus=");
                    out.num(u64::from(i.cpus));
                    out.put(b" ticks=");
                    out.num(i.ticks);
                    out.put(b" processes=");
                    out.num(u64::from(i.processes));
                    out.put(b" threads=");
                    out.num(u64::from(i.threads));
                    out.put(b"\n");
                }
                Err(e) => out.err(e),
            },
            b"mem" => match libnawah::system_info() {
                Ok(i) => {
                    out.put(b"frames_total=");
                    out.num(i.frames_total);
                    out.put(b" frames_free=");
                    out.num(i.frames_free);
                    out.put(b" heap_live_bytes=");
                    out.num(i.heap_live_bytes);
                    out.put(b" heap_pages=");
                    out.num(i.heap_pages);
                    out.put(b" handles=");
                    out.num(u64::from(i.handles));
                    out.put(b" channels=");
                    out.num(u64::from(i.channels));
                    out.put(b"\n");
                }
                Err(e) => out.err(e),
            },
            b"net" => {
                let Some(chan) = self.connect(b"net", out) else {
                    return true;
                };
                match field(line, 1) {
                    None => {
                        self.ask(chan, b"STATUS", &[], out);
                    }
                    Some(b"dhcp") => {
                        self.ask(chan, b"DHCP", &[], out);
                    }
                    Some(b"policy") => match (field(line, 2), self.token) {
                        (Some(arg), Some(t)) => {
                            let mut req = [0u8; 64];
                            req[..7].copy_from_slice(b"POLICY ");
                            let n = arg.len().min(57);
                            req[7..7 + n].copy_from_slice(&arg[..n]);
                            self.ask(chan, &req[..7 + n], &[t], out);
                        }
                        (Some(_), None) => out.put(b"ERR NO_SESSION\n"),
                        (None, _) => out.put(b"usage: net policy internet=0|1\n"),
                    },
                    Some(_) => out.put(b"usage: net [dhcp|policy internet=0|1]\n"),
                }
                libnawah::handle_close(chan);
            }
            b"ls" => {
                let path = field(line, 1).unwrap_or(b"/");
                let mut listing = [0u8; OUT_MAX];
                match libnawah::dir_list(path, &mut listing) {
                    Ok(n) => out.put(&listing[..n]),
                    Err(e) => out.err(e),
                }
            }
            b"cat" => {
                let Some(path) = field(line, 1) else {
                    out.put(b"usage: cat <path>\n");
                    return true;
                };
                match libnawah::open(path, libnawah::O_READ) {
                    Ok(f) => {
                        let mut buf = [0u8; OUT_MAX - 1];
                        let mut total = 0;
                        while total < buf.len() {
                            match libnawah::read(f, &mut buf[total..]) {
                                Ok(0) => break,
                                Ok(n) => total += n,
                                Err(e) => {
                                    out.err(e);
                                    break;
                                }
                            }
                        }
                        libnawah::handle_close(f);
                        out.put(&buf[..total]);
                        if total > 0 && buf[total - 1] != b'\n' {
                            out.put(b"\n");
                        }
                    }
                    Err(e) => out.err(e),
                }
            }
            b"login" => {
                let (Some(user), Some(password)) = (field(line, 1), field(line, 2)) else {
                    out.put(b"usage: login <user> <password>\n");
                    return true;
                };
                if self.token.is_some() {
                    out.put(b"ERR SESSION_OPEN\n");
                    return true;
                }
                let Some(auth) = self.connect(b"auth", out) else {
                    return true;
                };
                // `LOGIN <user> <password>`: both fields come from one line of LINE_MAX.
                let mut req = [0u8; 8 + LINE_MAX];
                let mut n = 0;
                for part in [&b"LOGIN "[..], user, b" ", password] {
                    req[n..n + part.len()].copy_from_slice(part);
                    n += part.len();
                }
                let mark = out.len;
                let token = self.ask(auth, &req[..n], &[], out);
                libnawah::handle_close(auth);
                let reply_ok = out.buf[mark..out.len].starts_with(b"OK ");
                match (token, reply_ok) {
                    (Some(t), true) => {
                        self.token = Some(t);
                        let n = user.len().min(NAME_MAX);
                        self.user[..n].copy_from_slice(&user[..n]);
                        self.user_len = n;
                        out.len = mark;
                        out.put(b"logged in as ");
                        out.put(user);
                        out.put(b"\n");
                    }
                    (t, _) => {
                        if let Some(t) = t {
                            libnawah::handle_close(t);
                        }
                        let mut reply = [0u8; 64];
                        let k = (out.len - mark).min(reply.len());
                        reply[..k].copy_from_slice(&out.buf[mark..mark + k]);
                        out.len = mark;
                        out.put(b"login failed: ");
                        out.put(&reply[..k]);
                    }
                }
            }
            b"whoami" => match self.token {
                None => out.put(b"not logged in\n"),
                Some(t) => {
                    let Some(auth) = self.connect(b"auth", out) else {
                        return true;
                    };
                    out.put(&self.user[..self.user_len]);
                    out.put(b" ");
                    self.ask(auth, b"WHOAMI", &[t], out);
                    libnawah::handle_close(auth);
                }
            },
            b"logout" => match self.token.take() {
                None => out.put(b"not logged in\n"),
                Some(t) => {
                    if let Some(auth) = self.connect(b"auth", out) {
                        let mark = out.len;
                        self.ask(auth, b"LOGOUT", &[t], out);
                        out.len = mark;
                        libnawah::handle_close(auth);
                    }
                    libnawah::handle_close(t);
                    self.user_len = 0;
                    out.put(b"logged out\n");
                }
            },
            b"exit" => {
                out.put(b"bye\n");
                return false;
            }
            _ => out.put(b"ERR UNKNOWN_COMMAND\n"),
        }
        true
    }

    /// Console bytes: lines end with LF (CR ignored); an over-long line is refused whole.
    /// Returns false when a command asked to exit.
    fn feed(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            match b {
                b'\r' => {}
                b'\n' => {
                    let mut out = Out {
                        buf: [0; OUT_MAX],
                        len: 0,
                    };
                    let keep = if self.too_long {
                        out.put(b"ERR LINE_TOO_LONG\n");
                        true
                    } else {
                        let mut line = [0u8; LINE_MAX];
                        line[..self.line_len].copy_from_slice(&self.line[..self.line_len]);
                        let len = self.line_len;
                        self.run(&line[..len], &mut out)
                    };
                    self.line_len = 0;
                    self.too_long = false;
                    self.write_all(&out.buf[..out.len]);
                    if !keep || self.stop_requested {
                        return false;
                    }
                    self.prompt();
                }
                _ => {
                    if self.line_len == LINE_MAX {
                        self.too_long = true;
                    } else {
                        self.line[self.line_len] = b;
                        self.line_len += 1;
                    }
                }
            }
        }
        true
    }
}

/// The next message on `chan` within REPLY_TICKS: its length and the handle it carried.
fn wait_reply(chan: u32, reply: &mut [u8]) -> Result<(usize, Option<u32>), i64> {
    let deadline = libnawah::clock_ticks() + REPLY_TICKS;
    loop {
        let mut hs = [0u32; 1];
        match libnawah::channel_read(chan, reply, &mut hs, false) {
            Ok((n, nh)) => return Ok((n, if nh == 1 { Some(hs[0]) } else { None })),
            Err(libnawah::ERR_SHOULD_WAIT) => {}
            Err(e) => return Err(e),
        }
        let now = libnawah::clock_ticks();
        if now >= deadline {
            return Err(libnawah::ERR_TIMED_OUT);
        }
        let _ = libnawah::object_wait_many(
            &[WaitEntry {
                handle: chan,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            }],
            deadline - now,
        );
    }
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let console = boot + 1;
    if libnawah::handle_type(console) != libnawah::object_type::SERIAL {
        return 0xE1;
    }
    let mut hs = [0u32; 1];
    let mut buf = [0u8; 256];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((n, _)) if buf[..n].starts_with(b"START") => {}
        _ => return 0xE3,
    }
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE4;
    }
    let mut sh = Shell {
        boot,
        console,
        line: [0; LINE_MAX],
        line_len: 0,
        too_long: false,
        token: None,
        user: [0; NAME_MAX],
        user_len: 0,
        stop_requested: false,
    };
    sh.write_all(b"nawah sh 1 (help)\n");
    sh.prompt();
    let entries = [
        WaitEntry {
            handle: boot,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        },
        WaitEntry {
            handle: console,
            signals: SIGNAL_READABLE,
        },
    ];
    loop {
        let Ok((idx, _)) = libnawah::object_wait_many(&entries, libnawah::TIMEOUT_FOREVER) else {
            return 0xE5;
        };
        if idx == 0 {
            // The manager: STOP (or the close) ends the shell; a client channel is refused;
            // a stray reply is dropped.
            match libnawah::channel_read(boot, &mut buf, &mut hs, false) {
                Ok((n, nh)) => {
                    if nh == 1 {
                        libnawah::handle_close(hs[0]);
                    }
                    if &buf[..n] == b"STOP" {
                        return 0;
                    }
                }
                Err(ERR_PEER_CLOSED) => return 0,
                Err(_) => {}
            }
            continue;
        }
        let mut bytes = [0u8; 256];
        match libnawah::serial_read(console, &mut bytes) {
            Ok(n) => {
                if !sh.feed(&bytes[..n]) {
                    return 0;
                }
            }
            Err(libnawah::ERR_SHOULD_WAIT) => {}
            Err(_) => return 0xE6,
        }
    }
}
