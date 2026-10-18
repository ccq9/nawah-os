//! authd — the authentication service `auth` (WP-25, docs/contracts/auth.md §4, ADR-0016
//! §3/§5): verifies passwords against `/SYSTEM/USERS.DB` (PBKDF2-HMAC-SHA-256, constant-time
//! compare), mints session tokens with the authority the service manager hands it, limits
//! failed attempts, and locks/unlocks/ends sessions. Clients arrive through the manager's
//! `CONNECT auth`. No password, salt or hash is ever written to the trace. No allocation.

#![no_std]
#![no_main]

use libnawah::{
    rights, Handle, WaitEntry, ERR_PEER_CLOSED, SIGNAL_PEER_CLOSED, SIGNAL_READABLE,
    TIMEOUT_FOREVER,
};
use nawah_crypto::{ct_eq, kat, pbkdf2_hmac_sha256};

libnawah::entry!(main);

const USERS_DB: &[u8] = b"/SYSTEM/USERS.DB";
const MAX_USERS: usize = 16;
const MAX_SESSIONS: usize = 16;
const MAX_CLIENTS: usize = 8;
const NAME_MAX: usize = 16;
const PASSWORD_MAX: usize = 64;
const DB_MAX: usize = 4096;
/// A session token lives this long (ticks, 1 kHz): one hour.
const SESSION_TICKS: u64 = 3_600_000;
/// Consecutive failures before a name is delayed, and the delay.
const MAX_FAILS: u32 = 5;
const DELAY_TICKS: u64 = 2000;

#[derive(Clone, Copy)]
struct User {
    uid: u32,
    gid: u32,
    perms: u32,
    iterations: u32,
    name: [u8; NAME_MAX],
    name_len: usize,
    salt: [u8; 16],
    hash: [u8; 32],
    /// Consecutive failed attempts and the tick of the last one.
    fails: u32,
    last_fail: u64,
}

const NO_USER: User = User {
    uid: 0,
    gid: 0,
    perms: 0,
    iterations: 0,
    name: [0; NAME_MAX],
    name_len: 0,
    salt: [0; 16],
    hash: [0; 32],
    fails: 0,
    last_fail: 0,
};

#[derive(Clone, Copy)]
struct Session {
    /// The minter's handle (WRITE: can revoke).
    token: Handle,
    token_id: u64,
    user: usize,
    locked: bool,
}

const NO_SESSION: Session = Session {
    token: 0,
    token_id: 0,
    user: 0,
    locked: false,
};

struct Out {
    buf: [u8; 256],
    len: usize,
}

impl Out {
    const fn new() -> Self {
        Out {
            buf: [0; 256],
            len: 0,
        }
    }
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
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u64::from(c - b'0');
    }
    u32::try_from(v).ok()
}

fn unhex(s: &[u8], out: &mut [u8]) -> bool {
    if s.len() != out.len() * 2 {
        return false;
    }
    for (i, o) in out.iter_mut().enumerate() {
        let v = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        match (v(s[2 * i]), v(s[2 * i + 1])) {
            (Some(h), Some(l)) => *o = (h << 4) | l,
            _ => return false,
        }
    }
    true
}

fn field<'a>(it: &mut impl Iterator<Item = &'a [u8]>) -> Option<&'a [u8]> {
    it.next()
}

struct Auth {
    users: [User; MAX_USERS],
    n_users: usize,
    sessions: [Session; MAX_SESSIONS],
    authority: Handle,
}

enum Verdict {
    Ok,
    Access,
    Delayed(u64),
}

impl Auth {
    /// Parses `/SYSTEM/USERS.DB` (auth.md §3); returns the user count or an error code for
    /// the trace.
    fn load(&mut self) -> Result<usize, &'static str> {
        let f = libnawah::open(USERS_DB, libnawah::O_READ).map_err(|_| "missing")?;
        let mut text = [0u8; DB_MAX];
        let mut len = 0;
        while len < DB_MAX {
            match libnawah::read(f, &mut text[len..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => len += n,
            }
        }
        libnawah::handle_close(f);
        let mut lines = text[..len].split(|c| *c == b'\n');
        let header = lines.next().unwrap_or(b"");
        if header.strip_suffix(b"\r").unwrap_or(header) != b"NAWAH-USERS 1" {
            return Err("schema");
        }
        let mut n = 0;
        for line in lines {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            if n == MAX_USERS {
                return Err("too_many");
            }
            let mut it = line.split(|c| *c == b':');
            let (
                Some(uid),
                Some(gid),
                Some(name),
                Some(perms),
                Some(iters),
                Some(salt),
                Some(hash),
            ) = (
                field(&mut it),
                field(&mut it),
                field(&mut it),
                field(&mut it),
                field(&mut it),
                field(&mut it),
                field(&mut it),
            )
            else {
                return Err("syntax");
            };
            let u = &mut self.users[n];
            let (Some(uid), Some(gid), Some(perms), Some(iters)) = (
                parse_u32(uid),
                parse_u32(gid),
                parse_u32(perms),
                parse_u32(iters),
            ) else {
                return Err("syntax");
            };
            if name.is_empty() || name.len() > NAME_MAX || iters == 0 {
                return Err("syntax");
            }
            u.uid = uid;
            u.gid = gid;
            u.perms = perms;
            u.iterations = iters;
            u.name[..name.len()].copy_from_slice(name);
            u.name_len = name.len();
            if !unhex(salt, &mut u.salt) || !unhex(hash, &mut u.hash) {
                return Err("syntax");
            }
            n += 1;
        }
        self.n_users = n;
        Ok(n)
    }

    fn find_user(&self, name: &[u8]) -> Option<usize> {
        (0..self.n_users).find(|&i| &self.users[i].name[..self.users[i].name_len] == name)
    }

    /// Checks `password` for user `i` with the attempt limit (auth.md §4).
    fn verify(&mut self, i: usize, password: &[u8], now: u64) -> Verdict {
        let u = &mut self.users[i];
        if u.fails >= MAX_FAILS {
            let since = now.saturating_sub(u.last_fail);
            if since < DELAY_TICKS {
                return Verdict::Delayed(DELAY_TICKS - since);
            }
        }
        let mut dk = [0u8; 32];
        pbkdf2_hmac_sha256(password, &u.salt, u.iterations, &mut dk);
        if ct_eq(&dk, &u.hash) {
            u.fails = 0;
            Verdict::Ok
        } else {
            u.fails = u.fails.saturating_add(1);
            u.last_fail = now;
            Verdict::Access
        }
    }

    /// Mints a session token for user `i`; returns the client's copy (no WRITE) and the slot.
    fn open_session(&mut self, i: usize, now: u64) -> Option<(Handle, usize)> {
        let slot = (0..MAX_SESSIONS).find(|&s| self.sessions[s].token == 0)?;
        let u = &self.users[i];
        let token = libnawah::token_create(
            self.authority,
            u.uid,
            u.gid,
            u.perms,
            now.saturating_add(SESSION_TICKS),
        )
        .ok()?;
        let info = libnawah::token_info(token).ok()?;
        let client = match libnawah::handle_duplicate(token, rights::DUPLICATE | rights::TRANSFER) {
            Ok(h) => h,
            Err(_) => {
                libnawah::handle_close(token);
                return None;
            }
        };
        self.sessions[slot] = Session {
            token,
            token_id: info.id,
            user: i,
            locked: false,
        };
        Some((client, slot))
    }

    fn session_by_id(&self, id: u64) -> Option<usize> {
        (0..MAX_SESSIONS).find(|&s| self.sessions[s].token != 0 && self.sessions[s].token_id == id)
    }

    fn close_session(&mut self, slot: usize) {
        let s = &mut self.sessions[slot];
        libnawah::token_revoke(s.token);
        libnawah::handle_close(s.token);
        *s = NO_SESSION;
    }

    fn put_identity(&self, out: &mut Out, i: usize) {
        let u = &self.users[i];
        out.put(b"OK ");
        out.num(u64::from(u.uid));
        out.put(b" ");
        out.num(u64::from(u.gid));
        out.put(b" ");
        out.num(u64::from(u.perms));
    }

    /// One client request: `req` bytes and the handle it carried (if any); the reply bytes
    /// and the handle to send back (a token for the client).
    fn handle(
        &mut self,
        req: &[u8],
        token: Option<Handle>,
        now: u64,
        out: &mut Out,
    ) -> Option<Handle> {
        // The handle the client sent is ours now: close it when done.
        let info = token.and_then(|h| libnawah::token_info(h).ok());
        let result = self.dispatch(req, token.is_some(), info, now, out);
        if let Some(h) = token {
            libnawah::handle_close(h);
        }
        result
    }

    fn dispatch(
        &mut self,
        req: &[u8],
        has_handle: bool,
        info: Option<libnawah::TokenInfo>,
        now: u64,
        out: &mut Out,
    ) -> Option<Handle> {
        let mut words = req.split(|c| *c == b' ');
        let verb = words.next().unwrap_or(b"");
        match verb {
            b"LOGIN" => {
                let (Some(name), Some(password)) = (words.next(), words.next()) else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                if password.len() > PASSWORD_MAX || words.next().is_some() {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                }
                let Some(i) = self.find_user(name) else {
                    out.put(b"ERR ACCESS");
                    return None;
                };
                match self.verify(i, password, now) {
                    Verdict::Ok => match self.open_session(i, now) {
                        Some((client, _)) => {
                            self.put_identity(out, i);
                            Some(client)
                        }
                        None => {
                            out.put(b"ERR BUSY");
                            None
                        }
                    },
                    Verdict::Access => {
                        out.put(b"ERR ACCESS");
                        None
                    }
                    Verdict::Delayed(t) => {
                        out.put(b"ERR DELAYED ");
                        out.num(t);
                        None
                    }
                }
            }
            b"WHOAMI" => {
                let Some(info) = info.filter(|i| i.usable()) else {
                    out.put(if has_handle {
                        b"ERR ACCESS"
                    } else {
                        b"ERR BAD_REQUEST"
                    });
                    return None;
                };
                match self.session_by_id(info.id) {
                    Some(slot) if !self.sessions[slot].locked => {
                        let i = self.sessions[slot].user;
                        self.put_identity(out, i);
                    }
                    _ => out.put(b"ERR ACCESS"),
                }
                None
            }
            b"LOCK" => {
                let Some(info) = info.filter(|i| i.usable()) else {
                    out.put(if has_handle {
                        b"ERR ACCESS"
                    } else {
                        b"ERR BAD_REQUEST"
                    });
                    return None;
                };
                match self.session_by_id(info.id) {
                    Some(slot) if !self.sessions[slot].locked => {
                        libnawah::token_revoke(self.sessions[slot].token);
                        self.sessions[slot].locked = true;
                        out.put(b"OK");
                    }
                    _ => out.put(b"ERR ACCESS"),
                }
                None
            }
            b"UNLOCK" => {
                let Some(info) = info else {
                    out.put(if has_handle {
                        b"ERR ACCESS"
                    } else {
                        b"ERR BAD_REQUEST"
                    });
                    return None;
                };
                let Some(password) = words.next() else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                let Some(slot) = self
                    .session_by_id(info.id)
                    .filter(|&s| self.sessions[s].locked)
                else {
                    out.put(b"ERR ACCESS");
                    return None;
                };
                let i = self.sessions[slot].user;
                match self.verify(i, password, now) {
                    Verdict::Ok => {
                        // The locked token is finished; the session continues with a new one.
                        self.close_session(slot);
                        match self.open_session(i, now) {
                            Some((client, _)) => {
                                self.put_identity(out, i);
                                Some(client)
                            }
                            None => {
                                out.put(b"ERR BUSY");
                                None
                            }
                        }
                    }
                    Verdict::Access => {
                        out.put(b"ERR ACCESS");
                        None
                    }
                    Verdict::Delayed(t) => {
                        out.put(b"ERR DELAYED ");
                        out.num(t);
                        None
                    }
                }
            }
            b"LOGOUT" => {
                let Some(info) = info else {
                    out.put(if has_handle {
                        b"ERR ACCESS"
                    } else {
                        b"ERR BAD_REQUEST"
                    });
                    return None;
                };
                match self.session_by_id(info.id) {
                    Some(slot) => {
                        self.close_session(slot);
                        out.put(b"OK");
                    }
                    None => out.put(b"ERR ACCESS"),
                }
                None
            }
            _ => {
                out.put(b"ERR BAD_REQUEST");
                None
            }
        }
    }
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let authority = boot + 1;
    if libnawah::handle_rights(authority) < 0 {
        return 0xE1;
    }
    // Known answers first (FIPS 180-4, RFC 4231, RFC 7914): a wrong primitive stops here.
    let fails = kat::self_test();
    let long_ok = kat::pbkdf2_long();
    let mut line = Out::new();
    line.put(b"auth|kat|fails=");
    line.num(u64::from(fails));
    line.put(b"|pbkdf2_80000=");
    line.num(u64::from(long_ok));
    libnawah::trace(line.bytes());
    if fails != 0 || !long_ok {
        return 0xE2;
    }
    let mut auth = Auth {
        users: [NO_USER; MAX_USERS],
        n_users: 0,
        sessions: [NO_SESSION; MAX_SESSIONS],
        authority,
    };
    let mut line = Out::new();
    match auth.load() {
        Ok(n) => {
            line.put(b"auth|users|schema=1|count=");
            line.num(n as u64);
        }
        Err(e) => {
            line.put(b"auth|users|error=");
            line.put(e.as_bytes());
        }
    }
    libnawah::trace(line.bytes());
    // The manager's START, then READY.
    let mut buf = [0u8; 256];
    let mut hs = [0u32; 1];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((n, _)) if buf[..n].starts_with(b"START") => {}
        _ => return 0xE3,
    }
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE4;
    }
    let mut clients = [0u32; MAX_CLIENTS];
    let mut entries = [WaitEntry {
        handle: 0,
        signals: 0,
    }; 1 + MAX_CLIENTS];
    loop {
        entries[0] = WaitEntry {
            handle: boot,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        };
        let mut k = 1;
        let mut owner = [0usize; 1 + MAX_CLIENTS];
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
        let Ok((idx, _)) = libnawah::object_wait_many(&entries[..k], TIMEOUT_FOREVER) else {
            return 0xE5;
        };
        let now = libnawah::clock_ticks();
        if idx == 0 {
            match libnawah::channel_read(boot, &mut buf, &mut hs, false) {
                Ok((n, nh)) => {
                    if (buf[..n] == *b"CONNECT" || buf[..n].starts_with(b"CONNECT ")) && nh == 1 {
                        match clients.iter().position(|&c| c == 0) {
                            Some(slot) => clients[slot] = hs[0],
                            None => {
                                libnawah::handle_close(hs[0]);
                            }
                        }
                    } else if &buf[..n] == b"STOP" {
                        return 0;
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
                let token = if nh == 1 { Some(hs[0]) } else { None };
                let mut out = Out::new();
                let reply_handle = auth.handle(&buf[..n], token, now, &mut out);
                let sent = match reply_handle {
                    Some(h) => {
                        let r = libnawah::channel_write(c, out.bytes(), &[h]);
                        if r != 0 {
                            libnawah::handle_close(h);
                        }
                        r
                    }
                    None => libnawah::channel_write(c, out.bytes(), &[]),
                };
                if sent == ERR_PEER_CLOSED {
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
