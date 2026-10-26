//! sessiond — the session service `session` (WP-37, session.md, ADR-0019 §5): owns the state
//! of the user's session (no session, unlocked, locked), the user's token from `auth`, the
//! sign-in and lock screens (libui dialogs in its own windows of the display service) and the
//! keyboard focus at the input service. Keys for the screens come straight from `input` — the
//! compositor never sees them — and the password goes nowhere but to `auth`, then is wiped.
//! The secure attention sequence (Ctrl+Alt+Del, input.md v2.2) locks an unlocked session.
//! A lost `input` or `display` is reconnected through the manager and given the state again;
//! both start holding everything back until the session says otherwise. One that does not
//! answer a request within REQUEST_DEADLINE is lost too (session.md v1.1). The session never
//! waits on `auth` (v1.2): a lock or a sign-out takes effect at once, and a sign-in or unlock
//! waits for its answer while the session keeps serving.
//!
//! (v1.3, WP-41) An application may ask `ELEVATE <service> <request…>`: the session holds the
//! screen and shows, on its own surface, who asks (the name the manager vouched for when it
//! connected the client) and the request in full; an administrator's name and password go to
//! `auth` alone, and only then does the session send exactly that request to the service with the
//! administrator's token, have auth end the token at once, and answer the application with the
//! service's reply. The token and the password never reach the application; no approval
//! happens without the prompt on the screen.
//!
//! Initial handle: the boot channel. Dependencies: `auth`, `input`, `display`, and the services
//! elevations may reach (declared in the manifest). Clients ask `STATE`, `AUTH`, `ELEVATION`
//! and `ELEVATE`.

#![no_std]
#![no_main]

use libnawah::display::{Surface, FORMAT_RGBX};
use libnawah::{
    Handle, WaitEntry, ERR_BUFFER_TOO_SMALL, ERR_PEER_CLOSED, ERR_SHOULD_WAIT, ERR_TIMED_OUT,
    SIGNAL_PEER_CLOSED, SIGNAL_READABLE,
};
use libui::{Dialog, Event, Painter, Rect, Role, Text, MAX_ELEMENTS, TEXT_MAX};
use nawah_text::font::Font;
use nawah_text::layout::Fonts;

libnawah::entry!(main);

const MSG_MAX: usize = 512;
const EV_MAX: usize = 128;
const PENDING: usize = 32;
const MAX_CLIENTS: usize = 4;
const NAME_MAX: usize = 16;
/// Ticks between two attempts to reach a dependency (session.md §5).
const RECONNECT: u64 = 50;
/// The longest a request to `display` or `input` waits for its reply (session.md v1.1): past
/// it the component is treated as lost, never waited on for ever.
const REQUEST_DEADLINE: u64 = 5000;
/// How long the focus stays with the session after an unlock while a key is still held
/// (its release would otherwise reach an application).
const RELEASE_WAIT: u64 = 1000;

const AUTH: usize = 0;
const INPUT: usize = 1;
const DISPLAY: usize = 2;
const DEPS: [&[u8]; 3] = [b"auth", b"input", b"display"];
/// `asked` while the manager's answer to an elevation's `CONNECT <service>` is awaited.
const ELEV: usize = 3;
/// The longest request an elevation carries (v1.3): it must fit the prompt in full.
const ELEVATE_REQUEST_MAX: usize = 32;
/// The administrator permission (auth.md §1, `PERM_ADMIN`).
const PERM_ADMIN: i64 = 1;

static mut PAINTER: Painter = Painter::new();

/// A request sent to `auth` whose answer has not come yet (session.md v1.2). auth answers each
/// request in order and sends nothing else, so the answers match these front to back.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthOp {
    Login {
        name: [u8; NAME_MAX],
        len: usize,
    },
    Unlock,
    Lock,
    Logout,
    /// An administrator's name and password for the elevation on the prompt (v1.3). `n` names
    /// the elevation it was typed for: an answer that arrives after that elevation ended
    /// approves nothing, whatever prompt is on the screen by then.
    Elevate {
        n: u64,
    },
}

/// An elevation a client asked for (session.md v1.3).
#[derive(Clone, Copy)]
struct Elevation {
    client: usize,
    from: [u8; NAME_MAX],
    from_len: usize,
    service: [u8; NAME_MAX],
    service_len: usize,
    request: [u8; ELEVATE_REQUEST_MAX],
    request_len: usize,
    /// The channel to the service, once the manager connected it.
    chan: Handle,
    /// The `CONNECT <service>` is still to be sent (the manager answers one request at a time).
    connect: bool,
    /// This elevation's number (1, 2, …): the auth answer it waits for carries the same one.
    n: u64,
}

const NO_ELEVATION: Elevation = Elevation {
    client: usize::MAX,
    from: [0; NAME_MAX],
    from_len: 0,
    service: [0; NAME_MAX],
    service_len: 0,
    request: [0; ELEVATE_REQUEST_MAX],
    request_len: 0,
    chan: 0,
    connect: false,
    n: 0,
};

/// Requests to `auth` that may wait for their answers at once.
const AUTH_OPS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    NoSession,
    Unlocked,
    Locked,
}

impl State {
    fn name(self) -> &'static [u8] {
        match self {
            State::NoSession => b"no_session",
            State::Unlocked => b"unlocked",
            State::Locked => b"locked",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    None,
    Login,
    Lock,
    /// The administrator's approval of an elevation (v1.3).
    Elevate,
}

/// Who the session last gave the keyboard to (STATE `focus=`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    Nobody,
    Session,
    Display,
}

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
    /// Printable ASCII only (an answer from another service, in a trace).
    fn ascii(&mut self, s: &[u8]) -> &mut Self {
        for &b in s {
            self.put(&[if (0x20..0x7F).contains(&b) { b } else { b'?' }]);
        }
        self
    }
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    /// Zeroes the buffer (it held a password).
    fn wipe(&mut self) {
        wipe(&mut self.buf);
        self.len = 0;
    }
}

/// Zeroes a buffer that held a secret; `black_box` keeps the stores from being dropped as
/// dead (best effort: copies the compiler made on the stack are not reached).
fn wipe(b: &mut [u8]) {
    b.fill(0);
    core::hint::black_box(&*b);
}

fn parse_i64(s: &[u8]) -> Option<i64> {
    let (neg, d) = match s.strip_prefix(b"-") {
        Some(d) => (true, d),
        None => (false, s),
    };
    if d.is_empty() || d.len() > 12 {
        return None;
    }
    let mut v = 0i64;
    for &c in d {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + i64::from(c - b'0');
    }
    Some(if neg { -v } else { v })
}

fn parse_hex(s: &[u8]) -> Option<u32> {
    let h = s.strip_prefix(b"0x")?;
    let mut v = 0u32;
    for &c in h {
        v = (v << 4) | (c as char).to_digit(16)?;
    }
    Some(v)
}

/// The value after `key` in a reply (up to the next space).
fn field<'a>(reply: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let i = reply.windows(key.len()).position(|w| w == key)?;
    let rest = &reply[i + key.len()..];
    let end = rest.iter().position(|&c| c == b' ').unwrap_or(rest.len());
    Some(&rest[..end])
}

fn load_font(path: &[u8]) -> Option<&'static [u8]> {
    let st = libnawah::stat(path).ok()?;
    let size = st.size as usize;
    let vmo = libnawah::vmo_create(st.size.max(1).next_multiple_of(4096)).ok()?;
    let addr = libnawah::vmo_map(vmo, libnawah::PROT_READ | libnawah::PROT_WRITE).ok()?;
    // SAFETY: the mapping is this process's, `size` bytes fit the VMO, never unmapped.
    let buf: &'static mut [u8] = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size) };
    let f = libnawah::open(path, libnawah::O_READ).ok()?;
    let mut total = 0;
    while total < size {
        match libnawah::read(f, &mut buf[total..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    libnawah::handle_close(f);
    (total == size).then_some(&*buf)
}

/// A channel to a service that also sends events (input, display): events that arrive while
/// a request waits for its reply are kept, in order, for the main loop.
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

    fn keep(&mut self, msg: &[u8]) {
        if self.count < PENDING {
            let slot = (self.head + self.count) % PENDING;
            let k = msg.len().min(EV_MAX);
            self.pending[slot][..k].copy_from_slice(&msg[..k]);
            self.pending_len[slot] = k;
            self.count += 1;
        }
    }

    /// One request and its reply (`OK…` or `ERR…`); a closed peer is an error, and so is a
    /// reply that does not come within REQUEST_DEADLINE (`ERR_TIMED_OUT`, session.md v1.1).
    /// Events that arrive meanwhile are kept; they do not extend the deadline.
    fn request(&mut self, req: &[u8], handles: &[Handle], reply: &mut [u8]) -> Result<usize, i64> {
        if libnawah::channel_write(self.chan, req, handles) != 0 {
            for &h in handles {
                libnawah::handle_close(h);
            }
            return Err(ERR_PEER_CLOSED);
        }
        let deadline = libnawah::clock_ticks().saturating_add(REQUEST_DEADLINE);
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
                    self.keep(&msg[..n]);
                }
                Err(ERR_SHOULD_WAIT) => {
                    let now = libnawah::clock_ticks();
                    if now >= deadline {
                        return Err(ERR_TIMED_OUT);
                    }
                    let _ = libnawah::object_wait_many(
                        &[WaitEntry {
                            handle: self.chan,
                            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                        }],
                        deadline - now,
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

/// The elements of the shown dialog that act (indices into it; `usize::MAX` when absent).
#[derive(Clone, Copy)]
struct Ids {
    user: usize,
    password: usize,
    submit: usize,
    sign_out: usize,
}

const NO_IDS: Ids = Ids {
    user: usize::MAX,
    password: usize::MAX,
    submit: usize::MAX,
    sign_out: usize::MAX,
};

/// The message of a refusal (session.md §2): the auth service's answer decides.
fn refusal(answer: &[u8], unlocking: bool) -> &'static str {
    if answer.starts_with(b"ERR DELAYED") {
        "Too many attempts. Try again later."
    } else if answer.starts_with(b"ERR ACCESS") || answer.starts_with(b"ERR BAD_REQUEST") {
        if unlocking {
            "The password is incorrect."
        } else {
            "Wrong user name or password."
        }
    } else {
        "Sign-in is not available."
    }
}

struct Session {
    boot: Handle,
    state: State,
    screen: Screen,
    user: [u8; NAME_MAX],
    user_len: usize,
    uid: i64,
    token: Handle,
    auth: Handle,
    /// Requests to `auth` waiting for their answers, oldest first.
    auth_ops: [Option<AuthOp>; AUTH_OPS],
    /// Locked here but not (yet) at auth: auth was away or lost the request. Sent again when
    /// auth is back.
    lock_unsent: bool,
    input: Option<Conn>,
    display: Option<Conn>,
    connected: [bool; 3],
    conn_n: [i64; 3],
    asked: Option<usize>,
    retry: [u64; 3],
    format: u32,
    screen_w: i64,
    screen_h: i64,
    dialog: Dialog,
    ids: Ids,
    surface: Surface,
    sid: i64,
    wid: i64,
    rects: [Rect; MAX_ELEMENTS],
    fonts: Fonts<'static>,
    painter: &'static mut Painter,
    owner: Owner,
    /// The keyboard is to go to the display once no key is held (after an unlock).
    want_display: bool,
    focus_retry: u64,
    release_deadline: u64,
    /// Keys pressed and not yet released while the session owns the keyboard.
    held: [u64; 4],
    handovers: i64,
    changes: i64,
    clients: [Handle; MAX_CLIENTS],
    /// The name the manager vouched for with each client (`CONNECT <name>`; `-` for control).
    client_names: [([u8; NAME_MAX], usize); MAX_CLIENTS],
    elevation: Option<Elevation>,
    elevations: i64,
    /// Elevations asked so far; numbers the next one.
    elevate_seq: u64,
}

impl Session {
    // ---- the services ------------------------------------------------------------------

    /// Sends a request to `auth` with an optional copy of the token and queues what its answer
    /// is for (session.md v1.2): the session never waits for auth, so a hung auth holds back only
    /// what needs its answer. `false` when auth is away or the request could not be sent.
    fn auth_send(&mut self, req: &[u8], with_token: bool, op: AuthOp) -> bool {
        let Some(slot) = self.auth_ops.iter().position(Option::is_none) else {
            return false;
        };
        if self.auth == 0 {
            return false;
        }
        let mut handles = [0u32; 1];
        let mut nh = 0;
        if with_token && self.token != 0 {
            let rights = libnawah::handle_rights(self.token);
            if let Some(copy) = u32::try_from(rights)
                .ok()
                .and_then(|r| libnawah::handle_duplicate(self.token, r).ok())
            {
                handles[0] = copy;
                nh = 1;
            }
        }
        if libnawah::channel_write(self.auth, req, &handles[..nh]) != 0 {
            if nh == 1 {
                libnawah::handle_close(handles[0]);
            }
            self.auth_lost(libnawah::clock_ticks());
            return false;
        }
        self.auth_ops[slot] = Some(op);
        true
    }

    /// Whether a sign-in or an unlock is waiting for auth's answer (one at a time).
    /// An administrator's name and password sent for an elevation, not yet answered.
    fn elevate_answer_pending(&self) -> bool {
        self.auth_ops
            .iter()
            .any(|o| matches!(o, Some(AuthOp::Elevate { .. })))
    }

    fn auth_waiting(&self) -> bool {
        self.auth_ops.iter().any(|o| {
            matches!(
                o,
                Some(AuthOp::Login { .. } | AuthOp::Unlock | AuthOp::Elevate { .. })
            )
        })
    }

    /// auth's answer to the oldest request still waiting, with the handle it carried.
    fn auth_reply(&mut self, op: AuthOp, answer: &[u8], extra: Option<Handle>, now: u64) {
        match op {
            AuthOp::Login { name, len } if self.state == State::NoSession => match extra {
                Some(t) if answer.starts_with(b"OK ") => {
                    self.user[..len].copy_from_slice(&name[..len]);
                    self.user_len = len;
                    self.opened(answer, t, now);
                }
                other => {
                    if let Some(t) = other {
                        libnawah::handle_close(t);
                    }
                    let mut tr = Out::new();
                    tr.put(b"session|login=refused|answer=").ascii(answer);
                    libnawah::trace(tr.bytes());
                    self.show(Screen::Login, Some(refusal(answer, false)));
                }
            },
            AuthOp::Unlock if self.state == State::Locked => match extra {
                Some(t) if answer.starts_with(b"OK ") => self.opened(answer, t, now),
                other => {
                    if let Some(t) = other {
                        libnawah::handle_close(t);
                    }
                    let mut tr = Out::new();
                    tr.put(b"session|unlock=refused|answer=").ascii(answer);
                    libnawah::trace(tr.bytes());
                    self.show(Screen::Lock, Some(refusal(answer, true)));
                }
            },
            AuthOp::Elevate { n } => self.elevate_answer(n, answer, extra, now),
            // A token auth will not lock ends the session (it is locked here already).
            AuthOp::Lock => {
                if let Some(h) = extra {
                    libnawah::handle_close(h);
                }
                if answer != b"OK" && self.state == State::Locked {
                    self.sign_out(now);
                }
            }
            // Logout, or an answer the state has moved past (signed out meanwhile).
            _ => {
                if let Some(h) = extra {
                    libnawah::handle_close(h);
                }
            }
        }
    }

    /// A request to the display service (nothing when it is away: the state is applied
    /// again when it is back).
    fn display_call(&mut self, req: &[u8], handles: &[Handle], reply: &mut [u8]) -> Option<usize> {
        let Some(d) = self.display.as_mut() else {
            for &h in handles {
                libnawah::handle_close(h);
            }
            return None;
        };
        let sent = libnawah::clock_ticks();
        match d.request(req, handles, reply) {
            Ok(n) => Some(n),
            Err(e) => {
                let now = libnawah::clock_ticks();
                self.display_lost(now);
                if e == ERR_TIMED_OUT {
                    timed_out(b"display", sent);
                    // A hung component is not asked again at once (v1.2): the clients that
                    // waited meanwhile are answered first.
                    self.retry[DISPLAY] = now + RECONNECT;
                }
                None
            }
        }
    }

    fn input_call(&mut self, req: &[u8], reply: &mut [u8]) -> Option<usize> {
        let sent = libnawah::clock_ticks();
        let r = self.input.as_mut()?.request(req, &[], reply);
        match r {
            Ok(n) => Some(n),
            Err(e) => {
                let now = libnawah::clock_ticks();
                self.input_lost(now);
                if e == ERR_TIMED_OUT {
                    timed_out(b"input", sent);
                    self.retry[INPUT] = now + RECONNECT;
                }
                None
            }
        }
    }

    /// auth is gone: what waited for it is refused as unavailable (a lock stays, and is sent
    /// again when auth is back); then it is reconnected through the manager.
    fn auth_lost(&mut self, now: u64) {
        if self.auth != 0 {
            libnawah::handle_close(self.auth);
        }
        self.auth = 0;
        self.connected[AUTH] = false;
        self.retry[AUTH] = now;
        let ops = core::mem::replace(&mut self.auth_ops, [None; AUTH_OPS]);
        for op in ops.into_iter().flatten() {
            match op {
                AuthOp::Lock => self.lock_unsent = true,
                AuthOp::Logout => {}
                _ => self.auth_reply(op, b"ERR UNAVAILABLE", None, now),
            }
        }
    }

    fn input_lost(&mut self, now: u64) {
        if let Some(c) = self.input.take() {
            libnawah::handle_close(c.chan);
        }
        self.connected[INPUT] = false;
        self.retry[INPUT] = now;
        self.owner = Owner::Nobody;
    }

    fn display_lost(&mut self, now: u64) {
        if let Some(c) = self.display.take() {
            libnawah::handle_close(c.chan);
        }
        self.connected[DISPLAY] = false;
        self.retry[DISPLAY] = now;
        // The window and the surface died with the compositor; our VMO goes too.
        self.wid = 0;
        self.sid = 0;
        self.drop_surface();
        // No approval without the prompt on the screen (v1.3): the elevation ends unanswered.
        if self.screen == Screen::Elevate {
            self.screen = Screen::None;
            self.elevate_end(b"ERR UNAVAILABLE", now);
        }
    }

    /// Asks the manager for the next missing dependency when it is time (one at a time; the
    /// answer arrives on the boot channel).
    fn ask(&mut self, now: u64) {
        if self.asked.is_some() {
            return;
        }
        if let Some(e) = self.elevation.as_mut().filter(|e| e.connect) {
            e.connect = false;
            let mut req = Out::new();
            req.put(b"CONNECT ").put(&e.service[..e.service_len]);
            if libnawah::channel_write(self.boot, req.bytes(), &[]) == 0 {
                self.asked = Some(ELEV);
            } else {
                self.elevate_end(b"ERR UNAVAILABLE", now);
            }
            return;
        }
        for (i, dep) in DEPS.iter().enumerate() {
            if !self.connected[i] && now >= self.retry[i] {
                let mut req = Out::new();
                req.put(b"CONNECT ").put(dep);
                if libnawah::channel_write(self.boot, req.bytes(), &[]) == 0 {
                    self.asked = Some(i);
                } else {
                    self.retry[i] = now + RECONNECT;
                }
                return;
            }
        }
    }

    /// The manager's answer to the asked `CONNECT`: a channel, or a refusal to retry later
    /// (`ERR NOT_READY` while the service restarts).
    fn answer(&mut self, chan: Option<Handle>, now: u64) {
        let Some(i) = self.asked.take() else {
            if let Some(h) = chan {
                libnawah::handle_close(h);
            }
            return;
        };
        if i == ELEV {
            self.elevate_connected(chan, now);
            return;
        }
        let Some(h) = chan else {
            self.retry[i] = now + RECONNECT;
            return;
        };
        self.connected[i] = true;
        self.conn_n[i] += 1;
        match i {
            AUTH => {
                self.auth = h;
                if self.state == State::Locked && self.lock_unsent {
                    self.lock_unsent = !self.auth_send(b"LOCK", true, AuthOp::Lock);
                }
            }
            INPUT => self.input_up(h, now),
            _ => self.display_up(h, now),
        }
    }

    /// A new channel to `input`: register as `session`, then take the keyboard or (unlocked)
    /// give it to the display once it has registered again.
    fn input_up(&mut self, h: Handle, now: u64) {
        self.input = Some(Conn::new(h));
        let mut reply = [0u8; 64];
        let registered = self
            .input_call(b"REGISTER session", &mut reply)
            .is_some_and(|n| reply[..n].starts_with(b"OK "));
        if !registered {
            self.input_lost(now);
            self.retry[INPUT] = now + RECONNECT;
            return;
        }
        self.held = [0; 4];
        if self.state == State::Unlocked && self.screen != Screen::Elevate {
            self.want_display = true;
            self.focus_retry = now;
            self.release_deadline = now;
        } else {
            self.take_keyboard();
        }
        if self.conn_n[INPUT] > 1 {
            let mut t = Out::new();
            t.put(b"session|input=reconnected|n=")
                .num(self.conn_n[INPUT])
                .put(b"|state=")
                .put(self.state.name());
            libnawah::trace(t.bytes());
        }
    }

    /// A new channel to `display`: the pixel format and screen size, then the state again
    /// (the compositor started holding the screen; session.md §5).
    fn display_up(&mut self, h: Handle, _now: u64) {
        self.display = Some(Conn::new(h));
        let mut reply = [0u8; MSG_MAX];
        let Some(n) = self.display_call(b"STATUS", &[], &mut reply) else {
            return;
        };
        let st = &reply[..n];
        self.format = field(st, b"format=")
            .and_then(parse_i64)
            .map_or(1, |f| f as u32);
        if let Some(scr) = field(st, b"screen=") {
            let mut it = scr.split(|&c| c == b'x');
            self.screen_w = it.next().and_then(parse_i64).unwrap_or(0);
            self.screen_h = it.next().and_then(parse_i64).unwrap_or(0);
        }
        match self.state {
            State::Unlocked => {
                let mut r = [0u8; 64];
                self.display_call(b"UNLOCKED", &[], &mut r);
            }
            State::Locked => {
                let mut r = [0u8; 64];
                self.display_call(b"LOCKED", &[], &mut r);
                self.show(Screen::Lock, None);
            }
            State::NoSession => self.show(Screen::Login, None),
        }
        if self.conn_n[DISPLAY] > 1 {
            let mut t = Out::new();
            t.put(b"session|display=reconnected|n=")
                .num(self.conn_n[DISPLAY])
                .put(b"|state=")
                .put(self.state.name());
            self.put_window(&mut t);
            libnawah::trace(t.bytes());
        }
    }

    /// The keyboard to the session itself (sign-in and lock screens).
    fn take_keyboard(&mut self) {
        self.want_display = false;
        let mut reply = [0u8; 64];
        if self
            .input_call(b"FOCUS session", &mut reply)
            .is_some_and(|n| &reply[..n] == b"OK")
        {
            self.owner = Owner::Session;
        }
    }

    /// After an unlock: the keyboard goes to the display once every key the user pressed on
    /// our screen is released (or RELEASE_WAIT passed), retried until the compositor has
    /// registered with the input service.
    fn try_handover(&mut self, now: u64) {
        if !self.want_display
            || self.state != State::Unlocked
            || self.screen == Screen::Elevate
            || self.input.is_none()
        {
            return;
        }
        if now < self.focus_retry {
            return;
        }
        if self.held.iter().any(|&w| w != 0) && now < self.release_deadline {
            return;
        }
        let mut reply = [0u8; 64];
        match self.input_call(b"FOCUS display", &mut reply) {
            Some(n) if &reply[..n] == b"OK" => {
                self.want_display = false;
                self.owner = Owner::Display;
                self.held = [0; 4];
                self.handovers += 1;
                let mut t = Out::new();
                t.put(b"session|focus=display|n=").num(self.handovers);
                libnawah::trace(t.bytes());
            }
            Some(_) => self.focus_retry = now + RECONNECT,
            None => {}
        }
    }

    // ---- the screens -----------------------------------------------------------------

    fn build(&mut self, screen: Screen, message: Option<&'static str>) {
        let title = match screen {
            Screen::Lock => "Locked",
            Screen::Elevate => "Administrator approval",
            _ => "Sign in",
        };
        let mut d = Dialog::new(title, false);
        let mut ids = NO_IDS;
        // Static labels, at most five elements: `add` cannot refuse them.
        let add = |d: &mut Dialog, role: Role, label: &'static str| -> usize {
            d.add(role, label).unwrap_or(usize::MAX)
        };
        if screen == Screen::Elevate {
            let e = self.elevation.unwrap_or(NO_ELEVATION);
            add(
                &mut d,
                Role::Label,
                "An application asks to act as an administrator.",
            );
            if let Some(m) = message {
                add(&mut d, Role::Label, m);
            }
            add(&mut d, Role::Label, "Requested by:");
            let from = add(&mut d, Role::Value, "Requested by");
            let who: &[u8] = if &e.from[..e.from_len] == b"-" {
                b"control"
            } else {
                &e.from[..e.from_len]
            };
            d.set_value(from, core::str::from_utf8(who).unwrap_or("?"));
            add(&mut d, Role::Label, "Request:");
            let what = add(&mut d, Role::Value, "Request");
            let mut text = [0u8; NAME_MAX + 1 + ELEVATE_REQUEST_MAX];
            let n = e.service_len + 1 + e.request_len;
            text[..e.service_len].copy_from_slice(&e.service[..e.service_len]);
            text[e.service_len] = b' ';
            text[e.service_len + 1..n].copy_from_slice(&e.request[..e.request_len]);
            d.set_value(what, core::str::from_utf8(&text[..n]).unwrap_or("?"));
            ids.user = add(&mut d, Role::TextField, "Administrator");
            ids.password = add(&mut d, Role::Password, "Password");
            ids.submit = add(&mut d, Role::Button, "Allow");
            ids.sign_out = add(&mut d, Role::Button, "Cancel");
        } else if screen == Screen::Lock {
            add(&mut d, Role::Label, "This computer is locked.");
            if let Some(m) = message {
                add(&mut d, Role::Label, m);
            }
            ids.password = add(&mut d, Role::Password, "Password");
            ids.submit = add(&mut d, Role::Button, "Unlock");
            ids.sign_out = add(&mut d, Role::Button, "Sign out");
        } else {
            add(&mut d, Role::Label, "Nawah");
            if let Some(m) = message {
                add(&mut d, Role::Label, m);
            }
            ids.user = add(&mut d, Role::TextField, "User name");
            ids.password = add(&mut d, Role::Password, "Password");
            ids.submit = add(&mut d, Role::Button, "Sign in");
        }
        // The old dialog (and any character typed into it) is overwritten here.
        self.dialog = d;
        self.ids = ids;
    }

    fn drop_surface(&mut self) {
        let old = core::mem::replace(
            &mut self.surface,
            Surface {
                vmo: 0,
                addr: 0,
                w: 0,
                h: 0,
                format: self.format,
            },
        );
        if old.addr != 0 {
            old.destroy();
        }
    }

    /// Removes our window and surface from the display (unlocked: nothing of ours is shown).
    fn hide(&mut self) {
        let mut reply = [0u8; 64];
        if self.wid != 0 {
            let mut req = Out::new();
            req.put(b"CLOSE ").num(self.wid);
            self.display_call(req.bytes(), &[], &mut reply);
        }
        if self.sid != 0 {
            let mut req = Out::new();
            req.put(b"DESTROY_SURFACE ").num(self.sid);
            self.display_call(req.bytes(), &[], &mut reply);
        }
        self.wid = 0;
        self.sid = 0;
        self.drop_surface();
        self.dialog = Dialog::new("", false);
        self.ids = NO_IDS;
        self.screen = Screen::None;
    }

    /// Shows `screen` (a fresh dialog, with the refusal `message` if any) in a new window
    /// in the middle of the screen; the narrator hears its tree and its first focus.
    fn show(&mut self, screen: Screen, message: Option<&'static str>) {
        let keep_user = if matches!(screen, Screen::Login | Screen::Elevate) && message.is_some() {
            let mut name = [0u8; 4 * TEXT_MAX];
            let n = self.dialog.value(self.ids.user, &mut name);
            Some((name, n))
        } else {
            None
        };
        self.hide();
        self.build(screen, message);
        self.screen = screen;
        if let Some((name, n)) = keep_user {
            if let Ok(s) = core::str::from_utf8(&name[..n]) {
                self.dialog.set_value(self.ids.user, s);
            }
        }
        if self.display.is_none() {
            return;
        }
        let (w, h) = self.dialog.layout(&mut self.rects);
        let Ok(s) = Surface::new(w as u32, h as u32, self.format) else {
            return;
        };
        let Ok(share) = s.share() else {
            s.destroy();
            return;
        };
        self.surface = s;
        let mut reply = [0u8; MSG_MAX];
        let mut req = Out::new();
        req.put(b"CREATE_SURFACE ")
            .num(i64::from(w))
            .put(b" ")
            .num(i64::from(h));
        let Some(n) = self.display_call(req.bytes(), &[share], &mut reply) else {
            return;
        };
        let Some(sid) = reply[..n].strip_prefix(b"OK ").and_then(parse_i64) else {
            return;
        };
        self.sid = sid;
        let mut req = Out::new();
        req.put(b"CREATE_WINDOW ")
            .num(sid)
            .put(b" ")
            .put(self.dialog.title.as_bytes());
        let Some(n) = self.display_call(req.bytes(), &[], &mut reply) else {
            return;
        };
        let Some(wid) = reply[..n].strip_prefix(b"OK ").and_then(parse_i64) else {
            return;
        };
        self.wid = wid;
        let mut req = Out::new();
        req.put(b"MOVE ")
            .num(wid)
            .put(b" ")
            .num((self.screen_w - i64::from(w)) / 2)
            .put(b" ")
            .num((self.screen_h - i64::from(h)) / 2);
        self.display_call(req.bytes(), &[], &mut reply);
        let count = self.dialog.len();
        for i in 0..count {
            let mut what = Out::new();
            what.put(b"tree ")
                .num(i as i64 + 1)
                .put(b"/")
                .num(count as i64);
            let mut tmp = [0u8; 32];
            let k = what.bytes().len();
            tmp[..k].copy_from_slice(what.bytes());
            self.announce(&tmp[..k], Some(i));
        }
        let first = if matches!(screen, Screen::Login | Screen::Elevate) && message.is_some() {
            self.dialog.focus_on(self.ids.password)
        } else {
            self.dialog.start()
        };
        if let Event::Focus(_, to) = first {
            self.announce(b"focus", Some(to));
        }
        self.repaint();
    }

    /// `|window=x,y,w,h` (the window's client area as the display reports it) or `|window=-`.
    fn put_window(&mut self, t: &mut Out) {
        t.put(b"|window=");
        let mut reply = [0u8; MSG_MAX];
        let origin = if self.wid != 0 {
            self.display_call(b"LIST", &[], &mut reply).and_then(|n| {
                let line = reply[..n]
                    .split(|&c| c == b'\n')
                    .find(|l| l.starts_with(b"W "))?;
                let mut f = line.split(|&c| c == b' ').skip(3);
                Some((f.next().and_then(parse_i64)?, f.next().and_then(parse_i64)?))
            })
        } else {
            None
        };
        match origin {
            Some((x, y)) => {
                t.num(x)
                    .put(b",")
                    .num(y)
                    .put(b",")
                    .num(i64::from(self.surface.w))
                    .put(b",")
                    .num(i64::from(self.surface.h));
            }
            None => {
                t.put(b"-");
            }
        }
    }

    /// Paints the dialog into the surface and commits it.
    fn repaint(&mut self) {
        if self.sid == 0 || self.surface.addr == 0 {
            return;
        }
        let (w, h) = (self.surface.w as usize, self.surface.h as usize);
        // SAFETY: the surface mapping holds at least w*h pixels (Surface::new) and is this
        // process's for as long as the surface lives.
        let buf: &mut [u32] =
            unsafe { core::slice::from_raw_parts_mut(self.surface.addr as *mut u32, w * h) };
        self.painter.paint(&self.dialog, &self.fonts, buf, w, h);
        if self.format == FORMAT_RGBX {
            for p in buf.iter_mut() {
                *p = ((*p & 0xFF) << 16) | (*p & 0xFF00) | ((*p >> 16) & 0xFF);
            }
        }
        let mut req = Out::new();
        req.put(b"COMMIT ")
            .num(self.sid)
            .put(b" 0 0 ")
            .num(w as i64)
            .put(b" ")
            .num(h as i64);
        let mut reply = [0u8; 64];
        self.display_call(req.bytes(), &[], &mut reply);
    }

    /// `A11Y <wid> <what> [description]` (ui.md §3); a password element is described
    /// without its value (ui.md v1.1).
    fn announce(&mut self, what: &[u8], element: Option<usize>) {
        if self.wid == 0 {
            return;
        }
        let mut t = Text::new();
        if let Some(i) = element {
            self.dialog.describe(i, &mut t);
        }
        let mut req = Out::new();
        req.put(b"A11Y ").num(self.wid).put(b" ").put(what);
        if element.is_some() {
            req.put(b" ").put(t.as_bytes());
        }
        let mut reply = [0u8; 64];
        self.display_call(req.bytes(), &[], &mut reply);
    }

    // ---- the state -------------------------------------------------------------------

    fn trace_state(&mut self, with_window: bool) {
        let mut t = Out::new();
        t.put(b"session|state=").put(self.state.name());
        if self.state != State::NoSession {
            t.put(b"|user=").put(&self.user[..self.user_len]);
        }
        if self.state == State::Unlocked {
            let usable = libnawah::token_info(self.token).is_ok_and(|i| i.usable());
            t.put(b"|uid=").num(self.uid).put(if usable {
                b"|token=usable"
            } else {
                b"|token=none"
            });
        }
        if with_window {
            self.put_window(&mut t);
        }
        libnawah::trace(t.bytes());
    }

    /// The session became usable (`OK <uid> <gid> <perms>` + a new token from auth).
    fn opened(&mut self, answer: &[u8], token: Handle, now: u64) {
        if self.token != 0 {
            libnawah::handle_close(self.token);
        }
        self.token = token;
        self.lock_unsent = false;
        self.uid = answer
            .strip_prefix(b"OK ")
            .and_then(|r| r.split(|&c| c == b' ').next())
            .and_then(parse_i64)
            .unwrap_or(-1);
        self.state = State::Unlocked;
        self.changes += 1;
        self.trace_state(false);
        // The screen first, then our window goes: the focus falls on the user's window.
        let mut reply = [0u8; 64];
        self.display_call(b"UNLOCKED", &[], &mut reply);
        self.hide();
        // `now` is when the key that submitted was read; auth's answer took time since.
        let now = now.max(libnawah::clock_ticks());
        self.want_display = true;
        self.focus_retry = now;
        self.release_deadline = now + RELEASE_WAIT;
    }

    fn submit_login(&mut self, now: u64) {
        if self.auth_waiting() {
            return;
        }
        let mut name = [0u8; NAME_MAX];
        let nn = self.dialog.value(self.ids.user, &mut name);
        let mut pw = [0u8; 4 * TEXT_MAX];
        let np = self.dialog.value(self.ids.password, &mut pw);
        // The secret leaves the element at once; it lives in `pw` and the request only.
        self.dialog.clear_value(self.ids.password);
        let mut req = Out::new();
        req.put(b"LOGIN ").put(&name[..nn]).put(b" ").put(&pw[..np]);
        wipe(&mut pw);
        let op = AuthOp::Login { name, len: nn };
        let sent = self.auth_send(req.bytes(), false, op);
        req.wipe();
        if !sent {
            self.auth_reply(op, b"ERR UNAVAILABLE", None, now);
        }
    }

    fn submit_unlock(&mut self, now: u64) {
        if self.auth_waiting() {
            return;
        }
        let mut pw = [0u8; 4 * TEXT_MAX];
        let np = self.dialog.value(self.ids.password, &mut pw);
        self.dialog.clear_value(self.ids.password);
        let mut req = Out::new();
        req.put(b"UNLOCK ").put(&pw[..np]);
        wipe(&mut pw);
        let sent = self.auth_send(req.bytes(), true, AuthOp::Unlock);
        req.wipe();
        if !sent {
            self.auth_reply(AuthOp::Unlock, b"ERR UNAVAILABLE", None, now);
        }
    }

    /// The secure attention sequence while unlocked: the screen is held and the lock screen
    /// shown at once, then auth is told to lock the token (session.md v1.2: never waited on, so a
    /// hung auth cannot leave the desktop open). A token auth will not lock ends the session.
    fn lock(&mut self, now: u64) {
        // The secure attention sequence ends a prompt too: nothing is approved (v1.3). The
        // state is locked first, so that ending the prompt never shows the desktop in between.
        self.state = State::Locked;
        if self.elevation.is_some() {
            self.elevate_end(b"ERR CANCELLED", now);
            self.want_display = false;
        }
        self.changes += 1;
        let mut r = [0u8; 64];
        self.display_call(b"LOCKED", &[], &mut r);
        self.show(Screen::Lock, None);
        self.trace_state(true);
        self.lock_unsent = !self.auth_send(b"LOCK", true, AuthOp::Lock);
    }

    /// Ends the session: auth forgets the token, the display removes every other client's
    /// windows and surfaces, and the sign-in screen comes back.
    fn sign_out(&mut self, _now: u64) {
        if self.token != 0 {
            // auth forgets the token; not waited on (v1.2): a hung auth never holds the sign-out.
            let _ = self.auth_send(b"LOGOUT", true, AuthOp::Logout);
            libnawah::handle_close(self.token);
            self.token = 0;
        }
        self.lock_unsent = false;
        let mut r = [0u8; 64];
        self.display_call(b"LOGOUT", &[], &mut r);
        let mut t = Out::new();
        t.put(b"session|state=logged_out|user=")
            .put(&self.user[..self.user_len]);
        libnawah::trace(t.bytes());
        self.state = State::NoSession;
        self.changes += 1;
        self.user = [0; NAME_MAX];
        self.user_len = 0;
        self.uid = 0;
        self.show(Screen::Login, None);
        self.trace_state(true);
    }

    // ---- elevation (v1.3) -------------------------------------------------------------

    /// `ELEVATE <service> <request…>` from client `k`: refused at once (the refusal is
    /// returned), or accepted (`None`): the service is connected, then the prompt shown, and
    /// the client is answered when it ends.
    fn elevate_request(&mut self, k: usize, rest: &[u8], now: u64) -> Option<&'static [u8]> {
        if self.state != State::Unlocked {
            return Some(b"ERR NOT_READY");
        }
        // One at a time: a prompt on the screen, or an administrator's answer still awaited
        // for an elevation that ended meanwhile (the client left, Esc, the secure attention
        // sequence) — that answer must not find a new prompt to approve.
        if self.elevation.is_some() || self.elevate_answer_pending() {
            return Some(b"ERR BUSY");
        }
        let Some(sp) = rest.iter().position(|&c| c == b' ') else {
            return Some(b"ERR BAD_REQUEST");
        };
        let (service, request) = (&rest[..sp], &rest[sp + 1..]);
        // The manifest's own name charset (services.md §2: [A-Za-z0-9_-], ≤ 15): anything the
        // manager can name is forwarded to it, so an undeclared one is refused by the manager
        // (ERR ACCESS) rather than rejected here as malformed (review S7). The reserved names
        // (the session's own channels) stay case-sensitive, as the manager resolves them.
        let name_ok = !service.is_empty()
            && service.len() < NAME_MAX
            && service
                .iter()
                .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            && !DEPS.contains(&service)
            && service != b"session";
        let request_ok = !request.is_empty()
            && request.len() <= ELEVATE_REQUEST_MAX
            && request.iter().all(|&c| (0x20..0x7F).contains(&c))
            && request[0] != b' ';
        if !name_ok || !request_ok {
            return Some(b"ERR BAD_REQUEST");
        }
        let (from, from_len) = self.client_names[k];
        let mut e = Elevation {
            client: k,
            from,
            from_len,
            connect: true,
            ..NO_ELEVATION
        };
        e.service[..service.len()].copy_from_slice(service);
        e.service_len = service.len();
        e.request[..request.len()].copy_from_slice(request);
        e.request_len = request.len();
        self.elevate_seq += 1;
        e.n = self.elevate_seq;
        self.elevation = Some(e);
        let mut t = Out::new();
        t.put(b"session|elevate=asked|from=")
            .put(&from[..from_len])
            .put(b"|service=")
            .put(service);
        libnawah::trace(t.bytes());
        self.ask(now);
        None
    }

    /// The manager's answer to the elevation's `CONNECT <service>`: a refusal (the service is
    /// not one the manifest lets the session reach) ends it; a channel brings the prompt.
    fn elevate_connected(&mut self, chan: Option<Handle>, now: u64) {
        let Some(h) = chan else {
            self.elevate_end(b"ERR ACCESS", now);
            return;
        };
        let Some(e) = self.elevation.as_mut() else {
            libnawah::handle_close(h);
            return;
        };
        e.chan = h;
        let e = *e;
        // The keys first, then the screen: no application hears a key once the prompt is on
        // its way, and no prompt without the keys (the input lost: ERR UNAVAILABLE).
        self.take_keyboard();
        if self.owner != Owner::Session {
            self.elevate_end(b"ERR UNAVAILABLE", now);
            return;
        }
        let mut r = [0u8; 64];
        self.display_call(b"LOCKED", &[], &mut r);
        self.show(Screen::Elevate, None);
        if self.screen != Screen::Elevate || self.wid == 0 {
            self.screen = Screen::None;
            self.elevate_end(b"ERR UNAVAILABLE", now);
            return;
        }
        let mut t = Out::new();
        t.put(b"session|elevate=prompt|from=")
            .put(&e.from[..e.from_len])
            .put(b"|request=")
            .put(&e.service[..e.service_len])
            .put(b" ")
            .put(&e.request[..e.request_len]);
        self.put_window(&mut t);
        libnawah::trace(t.bytes());
    }

    fn submit_elevate(&mut self, now: u64) {
        if self.auth_waiting() {
            return;
        }
        let mut name = [0u8; NAME_MAX];
        let nn = self.dialog.value(self.ids.user, &mut name);
        let mut pw = [0u8; 4 * TEXT_MAX];
        let np = self.dialog.value(self.ids.password, &mut pw);
        self.dialog.clear_value(self.ids.password);
        let mut req = Out::new();
        req.put(b"LOGIN ").put(&name[..nn]).put(b" ").put(&pw[..np]);
        wipe(&mut pw);
        let n = self.elevation.map_or(0, |e| e.n);
        let sent = self.auth_send(req.bytes(), false, AuthOp::Elevate { n });
        req.wipe();
        if !sent {
            self.elevate_answer(n, b"ERR UNAVAILABLE", None, now);
        }
    }

    /// auth's answer to the administrator's name and password.
    fn elevate_answer(&mut self, n: u64, answer: &[u8], token: Option<Handle>, now: u64) {
        let perms = answer
            .strip_prefix(b"OK ")
            .and_then(|r| r.split(|&c| c == b' ').nth(2))
            .and_then(parse_i64);
        // Only the elevation the password was typed for: an answer to an elevation that ended
        // (its client left, Esc, the secure attention sequence) approves nothing, and its token
        // is ended at once — whatever prompt is on the screen now.
        let same = self.elevation.is_some_and(|e| e.n == n);
        let prompting = same && self.screen == Screen::Elevate;
        if !same {
            let mut tr = Out::new();
            tr.put(b"session|elevate=stale|n=")
                .num(i64::try_from(n).unwrap_or(-1));
            libnawah::trace(tr.bytes());
        }
        match (token, perms) {
            (Some(t), Some(p)) if prompting && p & PERM_ADMIN != 0 => self.elevate_run(t, now),
            (token, perms) => {
                // A token that approves nothing is ended at once.
                if let Some(t) = token {
                    self.auth_logout(t);
                }
                if !prompting {
                    return;
                }
                // auth did not answer (lost, or the request never left): the elevation ends
                // with ERR UNAVAILABLE (§0ب) — a prompt that cannot be checked is no prompt.
                if answer == b"ERR UNAVAILABLE" {
                    self.elevate_end(b"ERR UNAVAILABLE", now);
                    return;
                }
                let mut tr = Out::new();
                tr.put(b"session|elevate=refused|answer=");
                if perms.is_some() {
                    tr.put(b"NOT_ADMIN");
                } else {
                    tr.ascii(answer);
                }
                libnawah::trace(tr.bytes());
                let message = if perms.is_some() {
                    "This account cannot approve."
                } else {
                    refusal(answer, false)
                };
                self.show(Screen::Elevate, Some(message));
                // The compositor lost while the refusal was drawn: the elevation ended
                // (display_lost); the screen must not stay `Elevate` with no elevation, or
                // the keyboard would never return to the desktop (try_handover).
                if self.elevation.is_none() && self.screen == Screen::Elevate {
                    self.screen = Screen::None;
                }
            }
        }
    }

    /// The approval: exactly the shown request goes to the service with a copy of the
    /// administrator's token; auth ends the token at once, whatever the reply.
    fn elevate_run(&mut self, token: Handle, now: u64) {
        let Some(e) = self.elevation else {
            self.auth_logout(token);
            return;
        };
        let rights = libnawah::handle_rights(token);
        let copy = u32::try_from(rights)
            .ok()
            .and_then(|r| libnawah::handle_duplicate(token, r).ok());
        // The service's reply, whole: a reply longer than this buffer would fail the read
        // and report ERR UNAVAILABLE for a request that ran (review S4).
        let mut reply = [0u8; MSG_MAX - 9];
        let mut got = None;
        if let Some(copy) = copy {
            if libnawah::channel_write(e.chan, &e.request[..e.request_len], &[copy]) == 0 {
                let wait = [WaitEntry {
                    handle: e.chan,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                }];
                if libnawah::object_wait_many(&wait, REQUEST_DEADLINE).is_ok() {
                    let mut hs = [0u32; 1];
                    if let Ok((n, nh)) = libnawah::channel_read(e.chan, &mut reply, &mut hs, false)
                    {
                        if nh == 1 {
                            libnawah::handle_close(hs[0]);
                        }
                        got = Some(n);
                    }
                }
            } else {
                libnawah::handle_close(copy);
            }
        }
        self.auth_logout(token);
        match got {
            Some(n) => {
                let mut out = Out::new();
                out.put(b"ELEVATED ").put(&reply[..n]);
                let mut a = [0u8; MSG_MAX];
                let k = out.bytes().len();
                a[..k].copy_from_slice(out.bytes());
                self.elevate_end(&a[..k], now);
            }
            None => self.elevate_end(b"ERR UNAVAILABLE", now),
        }
    }

    /// The elevation ends with `result` to its client: the service's channel goes, the prompt
    /// goes and the screen and the keyboard return to the user's windows.
    fn elevate_end(&mut self, result: &[u8], now: u64) {
        let Some(e) = self.elevation.take() else {
            return;
        };
        if e.chan != 0 {
            libnawah::handle_close(e.chan);
        }
        // A `CONNECT` still awaited stays `asked`: its answer finds no elevation and its
        // channel is closed (elevate_connected), never taken for another dependency's.
        self.elevations += 1;
        let mut t = Out::new();
        t.put(b"session|elevate=ended|n=")
            .num(self.elevations)
            .put(b"|result=")
            .ascii(result);
        libnawah::trace(t.bytes());
        if e.client < MAX_CLIENTS && self.clients[e.client] != 0 {
            libnawah::channel_write(self.clients[e.client], result, &[]);
        }
        if self.screen == Screen::Elevate {
            // The screen is released only to an unlocked desktop; a lock keeps it held.
            if self.state == State::Unlocked {
                let mut r = [0u8; 64];
                self.display_call(b"UNLOCKED", &[], &mut r);
            }
            self.hide();
        }
        if self.state == State::Unlocked {
            let now = now.max(libnawah::clock_ticks());
            self.want_display = true;
            self.focus_retry = now;
            self.release_deadline = now + RELEASE_WAIT;
        }
    }

    /// auth ends `token` (the handle goes with the request).
    fn auth_logout(&mut self, token: Handle) {
        let Some(slot) = self.auth_ops.iter().position(Option::is_none) else {
            libnawah::handle_close(token);
            return;
        };
        if self.auth == 0 || libnawah::channel_write(self.auth, b"LOGOUT", &[token]) != 0 {
            libnawah::handle_close(token);
            return;
        }
        self.auth_ops[slot] = Some(AuthOp::Logout);
    }

    /// Client `k` went away: an elevation it asked for ends (nobody to answer).
    fn client_gone(&mut self, k: usize, now: u64) {
        libnawah::handle_close(self.clients[k]);
        self.clients[k] = 0;
        self.client_names[k] = ([0; NAME_MAX], 0);
        if self.elevation.is_some_and(|e| e.client == k) {
            self.elevate_end(b"ERR CANCELLED", now);
        }
    }

    // ---- events ----------------------------------------------------------------------

    fn on_input(&mut self, msg: &[u8], now: u64) {
        if msg == b"SAK" {
            // input.md v2.2: the keyboard is ours from the sequence on.
            self.owner = Owner::Session;
            self.want_display = false;
            self.held = [0; 4];
            if self.state == State::Unlocked {
                self.lock(now);
            }
        } else if msg.starts_with(b"KEY ") {
            self.on_key(msg, now);
        }
        // PTR: the screens are keyboard-only in v1 (session.md §4).
    }

    fn on_key(&mut self, msg: &[u8], now: u64) {
        let mut f = msg.split(|&c| c == b' ').filter(|x| !x.is_empty());
        let _ = f.next();
        let (Some(code), Some(dir), Some(mods)) = (
            f.next().and_then(parse_hex),
            f.next(),
            f.next().and_then(parse_i64),
        ) else {
            return;
        };
        let down = dir == b"down";
        let (w, bit) = ((code as usize & 0xFF) / 64, 1u64 << (code & 63));
        if down {
            self.held[w] |= bit;
        } else {
            self.held[w] &= !bit;
        }
        if self.screen == Screen::None {
            return;
        }
        let ch = match f.next().unwrap_or(b"-") {
            b"space" => Some(' '),
            b"minus" => Some('-'),
            b"-" | b"enter" | b"tab" | b"backspace" => None,
            t => core::str::from_utf8(t).ok().and_then(|s| {
                let mut it = s.chars();
                let c = it.next()?;
                it.next().is_none().then_some(c)
            }),
        };
        match self.dialog.key(code, down, mods as u32, ch) {
            Event::Focus(_, to) => {
                self.announce(b"focus", Some(to));
                self.repaint();
            }
            Event::Edit(i) => {
                // A password field announces no change (ui.md v1.4, WP-43 finding M2): one
                // announcement per keystroke told the listener the password's length and
                // the rhythm it was typed in.
                if self.dialog.element(i).role != Role::Password {
                    self.announce(b"change", Some(i));
                }
                self.repaint();
            }
            Event::Activate(i) => {
                self.announce(b"activate", Some(i));
                self.activate(i, now);
            }
            // Esc on the prompt is Cancel (v1.3); the other screens have nothing to cancel.
            Event::Cancel if self.screen == Screen::Elevate => {
                self.elevate_end(b"ERR CANCELLED", now)
            }
            _ => {}
        }
    }

    fn activate(&mut self, i: usize, now: u64) {
        let ids = self.ids;
        match self.screen {
            Screen::Login if i == ids.user => {
                if let Event::Focus(_, to) = self.dialog.focus_on(ids.password) {
                    self.announce(b"focus", Some(to));
                    self.repaint();
                }
            }
            Screen::Login if i == ids.password || i == ids.submit => self.submit_login(now),
            Screen::Lock if i == ids.password || i == ids.submit => self.submit_unlock(now),
            Screen::Lock if i == ids.sign_out => self.sign_out(now),
            Screen::Elevate if i == ids.user => {
                if let Event::Focus(_, to) = self.dialog.focus_on(ids.password) {
                    self.announce(b"focus", Some(to));
                    self.repaint();
                }
            }
            Screen::Elevate if i == ids.password || i == ids.submit => self.submit_elevate(now),
            Screen::Elevate if i == ids.sign_out => self.elevate_end(b"ERR CANCELLED", now),
            _ => {}
        }
    }

    /// One request of a client (STATE, session.md §6).
    fn on_client(&mut self, k: usize, now: u64) {
        let c = self.clients[k];
        let mut buf = [0u8; 64];
        let mut hs = [0u32; 1];
        match libnawah::channel_read(c, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                let mut out = Out::new();
                if &buf[..n] == b"STATE" {
                    out.put(b"OK ").put(self.state.name()).put(b" user=");
                    if self.user_len == 0 {
                        out.put(b"-");
                    } else {
                        out.put(&self.user[..self.user_len]);
                    }
                    out.put(b" changes=")
                        .num(self.changes)
                        .put(b" display=")
                        .num(self.conn_n[DISPLAY])
                        .put(b" input=")
                        .num(self.conn_n[INPUT])
                        .put(b" focus=")
                        .put(match self.owner {
                            Owner::Session => b"session" as &[u8],
                            Owner::Display => b"display",
                            Owner::Nobody => b"-",
                        });
                } else if &buf[..n] == b"AUTH" {
                    // v1.2: how many requests wait for auth's answer, and whether a lock is
                    // still to be told to it.
                    let waiting = self.auth_ops.iter().filter(|o| o.is_some()).count();
                    out.put(b"OK waiting=")
                        .num(waiting as i64)
                        .put(b" lock_unsent=")
                        .num(i64::from(self.lock_unsent));
                } else if &buf[..n] == b"ELEVATION" {
                    // v1.3: where the elevation in progress is.
                    out.put(b"OK ").put(match self.elevation {
                        None => b"none" as &[u8],
                        Some(_) if self.screen == Screen::Elevate => b"prompt",
                        Some(_) => b"connecting",
                    });
                    out.put(b" done=").num(self.elevations);
                } else if let Some(rest) = buf[..n].strip_prefix(b"ELEVATE ") {
                    let mut req = [0u8; 64];
                    req[..rest.len()].copy_from_slice(rest);
                    match self.elevate_request(k, &req[..rest.len()], now) {
                        // Answered once the prompt ends.
                        None => return,
                        Some(refusal) => {
                            out.put(refusal);
                        }
                    }
                } else {
                    out.put(b"ERR BAD_REQUEST");
                }
                if libnawah::channel_write(c, out.bytes(), &[]) == ERR_PEER_CLOSED {
                    self.client_gone(k, now);
                }
            }
            Err(ERR_PEER_CLOSED) => self.client_gone(k, now),
            // Larger than any request, or carrying handles no request takes: discarded and
            // refused, so this client's next request is read and the clients after it are not
            // starved behind a message that never fits (review 2026-10-19, as svcmgr does).
            Err(ERR_BUFFER_TOO_SMALL) => {
                if libnawah::channel_discard(c) {
                    libnawah::channel_write(c, b"ERR BAD_REQUEST", &[]);
                }
            }
            Err(_) => {}
        }
    }

    /// One message on the boot channel; `false` ends the service.
    fn on_boot(&mut self, now: u64) -> bool {
        let mut buf = [0u8; 64];
        let mut hs = [0u32; 1];
        match libnawah::channel_read(self.boot, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                let msg = &buf[..n];
                if (msg == b"CONNECT" || msg.starts_with(b"CONNECT ")) && nh == 1 {
                    match self.clients.iter().position(|&c| c == 0) {
                        Some(k) => {
                            self.clients[k] = hs[0];
                            // The manager vouches for the name (services.md v1.6); `-` is the
                            // control side, and an old manager's bare CONNECT counts as it.
                            let name = msg.strip_prefix(b"CONNECT ").unwrap_or(b"-");
                            let len = name.len().min(NAME_MAX);
                            let mut n = [0u8; NAME_MAX];
                            n[..len].copy_from_slice(&name[..len]);
                            self.client_names[k] = (n, len);
                        }
                        None => {
                            libnawah::handle_close(hs[0]);
                        }
                    }
                } else if msg == b"STOP" {
                    return false;
                } else if self.asked.is_some() && msg == b"OK" && nh == 1 {
                    self.answer(Some(hs[0]), now);
                } else if self.asked.is_some() && msg.starts_with(b"ERR") {
                    if nh == 1 {
                        libnawah::handle_close(hs[0]);
                    }
                    self.answer(None, now);
                } else if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                true
            }
            Err(ERR_PEER_CLOSED) => false,
            Err(_) => true,
        }
    }

    /// Events kept while a request waited, in arrival order.
    fn drain(&mut self, now: u64) {
        let mut msg = [0u8; EV_MAX];
        while let Some(n) = self.input.as_mut().and_then(|c| c.next_pending(&mut msg)) {
            self.on_input(&msg[..n], now);
        }
        // Display events (FOCUS, UNFOCUS, CLOSE_REQUESTED, …) need nothing from the session.
        while self
            .display
            .as_mut()
            .and_then(|c| c.next_pending(&mut msg))
            .is_some()
        {}
    }

    /// Reads one message from the input channel (an event); a closed peer is a lost service.
    fn read_input(&mut self, now: u64) {
        let Some(c) = self.input.as_ref() else {
            return;
        };
        let chan = c.chan;
        let mut buf = [0u8; EV_MAX];
        let mut hs = [0u32; 1];
        match libnawah::channel_read(chan, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                let mut m = [0u8; EV_MAX];
                m[..n].copy_from_slice(&buf[..n]);
                self.on_input(&m[..n], now);
            }
            Err(ERR_PEER_CLOSED) => self.input_lost(now),
            Err(_) => {}
        }
    }

    fn read_display(&mut self, now: u64) {
        let Some(c) = self.display.as_ref() else {
            return;
        };
        let chan = c.chan;
        let mut buf = [0u8; MSG_MAX];
        let mut hs = [0u32; 1];
        match libnawah::channel_read(chan, &mut buf, &mut hs, false) {
            Ok((_, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
            }
            Err(ERR_PEER_CLOSED) => self.display_lost(now),
            Err(_) => {}
        }
    }

    /// One message from auth: the answer to the oldest request still waiting (auth sends
    /// nothing else; an answer nothing waits for is dropped).
    fn read_auth(&mut self, now: u64) {
        let mut buf = [0u8; 128];
        let mut hs = [0u32; 1];
        match libnawah::channel_read(self.auth, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                let extra = (nh == 1).then_some(hs[0]);
                let op = self.auth_ops[0].take();
                self.auth_ops.rotate_left(1);
                match op {
                    Some(op) => {
                        let mut a = [0u8; 128];
                        a[..n].copy_from_slice(&buf[..n]);
                        self.auth_reply(op, &a[..n], extra, now);
                    }
                    None => {
                        if let Some(h) = extra {
                            libnawah::handle_close(h);
                        }
                    }
                }
            }
            // An answer larger than any auth gives: the channel is not trusted any more.
            Err(ERR_PEER_CLOSED | ERR_BUFFER_TOO_SMALL) => self.auth_lost(now),
            Err(_) => {}
        }
    }

    /// The ticks until the next timed action (a reconnection or the keyboard handover).
    fn timeout(&self, now: u64) -> u64 {
        let mut t = libnawah::TIMEOUT_FOREVER;
        if self.asked.is_none() {
            for i in 0..DEPS.len() {
                if !self.connected[i] {
                    t = t.min(self.retry[i].saturating_sub(now).max(1));
                }
            }
        }
        if self.want_display && self.input.is_some() {
            let at = if self.held.iter().any(|&w| w != 0) {
                self.focus_retry.max(self.release_deadline)
            } else {
                self.focus_retry
            };
            t = t.min(at.saturating_sub(now).max(1));
        }
        t
    }
}

/// `CONNECT <name>` before READY (no client can be routed to us yet, so the first message
/// on the boot channel is the answer).
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

/// `session|<who>=timed_out|waited=<ticks>` (session.md v1.1 §7): a request to `who` got no
/// reply within REQUEST_DEADLINE.
fn timed_out(who: &[u8], sent: u64) {
    let mut t = Out::new();
    t.put(b"session|")
        .put(who)
        .put(b"=timed_out|waited=")
        .num(libnawah::clock_ticks().saturating_sub(sent) as i64);
    libnawah::trace(t.bytes());
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let mut buf = [0u8; 64];
    let mut hs = [0u32; 1];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((n, _)) if buf[..n].starts_with(b"START") => {}
        _ => return 0xE1,
    }
    let (Some(latin), Some(arabic)) = (
        load_font(b"/SYSTEM/FONTS/NOTOSANS.TTF").and_then(Font::parse),
        load_font(b"/SYSTEM/FONTS/NOTOARAB.TTF").and_then(Font::parse),
    ) else {
        return 0xE2;
    };
    let Some(auth) = manager_connect(boot, b"auth") else {
        return 0xE3;
    };
    let (Some(input), Some(display)) = (
        manager_connect(boot, b"input"),
        manager_connect(boot, b"display"),
    ) else {
        return 0xE3;
    };
    // SAFETY: the painter is taken once, here, for the life of the process.
    let painter: &'static mut Painter = unsafe { &mut *core::ptr::addr_of_mut!(PAINTER) };
    let mut s = Session {
        boot,
        state: State::NoSession,
        screen: Screen::None,
        user: [0; NAME_MAX],
        user_len: 0,
        uid: 0,
        token: 0,
        auth,
        auth_ops: [None; AUTH_OPS],
        lock_unsent: false,
        input: None,
        display: None,
        connected: [true, true, true],
        conn_n: [1, 0, 0],
        asked: None,
        retry: [0; 3],
        format: 1,
        screen_w: 0,
        screen_h: 0,
        dialog: Dialog::new("", false),
        ids: NO_IDS,
        surface: Surface {
            vmo: 0,
            addr: 0,
            w: 0,
            h: 0,
            format: 1,
        },
        sid: 0,
        wid: 0,
        rects: [Rect::default(); MAX_ELEMENTS],
        fonts: Fonts { latin, arabic },
        painter,
        owner: Owner::Nobody,
        want_display: false,
        focus_retry: 0,
        release_deadline: 0,
        held: [0; 4],
        handovers: 0,
        changes: 0,
        clients: [0; MAX_CLIENTS],
        client_names: [([0; NAME_MAX], 0); MAX_CLIENTS],
        elevation: None,
        elevations: 0,
        elevate_seq: 0,
    };
    let now = libnawah::clock_ticks();
    // The keyboard first (nobody gets a key before the sign-in screen exists), then the
    // screen.
    s.conn_n[INPUT] = 1;
    s.input_up(input, now);
    s.conn_n[DISPLAY] = 1;
    s.display_up(display, now);
    if s.owner != Owner::Session || s.wid == 0 {
        return 0xE4;
    }
    s.trace_state(true);
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE5;
    }
    loop {
        let now = libnawah::clock_ticks();
        s.drain(now);
        s.ask(now);
        s.try_handover(now);
        s.drain(now);
        let mut entries = [WaitEntry {
            handle: 0,
            signals: 0,
        }; 4 + MAX_CLIENTS];
        let mut kind = [0usize; 4 + MAX_CLIENTS];
        let mut k = 0;
        let mut push = |entries: &mut [WaitEntry], kind: &mut [usize], h: Handle, what: usize| {
            entries[k] = WaitEntry {
                handle: h,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            };
            kind[k] = what;
            k += 1;
        };
        push(&mut entries, &mut kind, s.boot, 100);
        if s.auth != 0 {
            push(&mut entries, &mut kind, s.auth, 100 + AUTH + 1);
        }
        if let Some(c) = s.input.as_ref() {
            push(&mut entries, &mut kind, c.chan, 100 + INPUT + 1);
        }
        if let Some(c) = s.display.as_ref() {
            push(&mut entries, &mut kind, c.chan, 100 + DISPLAY + 1);
        }
        for (j, &c) in s.clients.iter().enumerate() {
            if c != 0 {
                push(&mut entries, &mut kind, c, j);
            }
        }
        let n = k;
        let r = libnawah::object_wait_many(&entries[..n], s.timeout(now));
        let now = libnawah::clock_ticks();
        match r {
            Ok((idx, _)) => match kind[idx] {
                100 => {
                    if !s.on_boot(now) {
                        return 0;
                    }
                }
                101 => s.read_auth(now),
                102 => s.read_input(now),
                103 => s.read_display(now),
                j => s.on_client(j, now),
            },
            Err(ERR_TIMED_OUT) => {}
            Err(_) => return 0xE6,
        }
    }
}
