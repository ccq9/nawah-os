//! svcmgr — the service manager (WP-24, docs/contracts/services.md v1, ADR-0016 §4): the
//! first process the kernel starts. Its bootstrap handle is the control channel; `LOAD <path>`
//! reads a manifest and starts the services in dependency order, each with a boot channel on
//! which it must answer `READY` within its timeout; failures restart with exponential backoff
//! up to a limit; `LIST` reports every service; `STOP <name>` closes a service's channel.
//! No allocation: fixed tables, at most 16 services. Exits 0 when the control channel closes.

#![no_std]
#![no_main]

use libnawah::{
    Handle, WaitEntry, ERR_PEER_CLOSED, ERR_TIMED_OUT, SIGNAL_EXITED, SIGNAL_PEER_CLOSED,
    SIGNAL_READABLE, TIMEOUT_FOREVER,
};

libnawah::entry!(main);

const MAX_SERVICES: usize = 16;
const NAME_MAX: usize = 15;
const PATH_MAX: usize = 64;
const ARG_MAX: usize = 64;
/// The raw dependency list of one manifest line (`A,B,C`).
const DEPS_MAX: usize = 64;
const MANIFEST_MAX: usize = 4096;
const MSG_MAX: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Starting,
    Ready,
    Failed,
    GivenUp,
    Stopping,
    Stopped,
    Blocked,
}

impl State {
    fn name(self) -> &'static [u8] {
        match self {
            State::Pending => b"pending",
            State::Starting => b"starting",
            State::Ready => b"ready",
            State::Failed => b"failed",
            State::GivenUp => b"given_up",
            State::Stopping => b"stopping",
            State::Stopped => b"stopped",
            State::Blocked => b"blocked",
        }
    }
}

#[derive(Clone, Copy)]
struct Service {
    name: [u8; NAME_MAX],
    name_len: usize,
    path: [u8; PATH_MAX],
    path_len: usize,
    arg: [u8; ARG_MAX],
    arg_len: usize,
    /// Bit i set: depends on service i.
    deps: u16,
    timeout: u64,
    restart_on_failure: bool,
    max_restarts: u64,
    backoff: u64,
    state: State,
    restarts: u64,
    first_start: Option<u64>,
    last_start: Option<u64>,
    ready_tick: Option<u64>,
    exit: Option<u64>,
    chan: Option<Handle>,
    process: Option<Handle>,
    /// `Starting`: the readiness deadline; `Failed` with restarts left: the next start.
    deadline: Option<u64>,
}

const EMPTY: Service = Service {
    name: [0; NAME_MAX],
    name_len: 0,
    path: [0; PATH_MAX],
    path_len: 0,
    arg: [0; ARG_MAX],
    arg_len: 0,
    deps: 0,
    timeout: 0,
    restart_on_failure: false,
    max_restarts: 0,
    backoff: 0,
    state: State::Pending,
    restarts: 0,
    first_start: None,
    last_start: None,
    ready_tick: None,
    exit: None,
    chan: None,
    process: None,
    deadline: None,
};

impl Service {
    fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
    fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// A growing text buffer for replies.
struct Out {
    buf: [u8; MSG_MAX],
    len: usize,
}

impl Out {
    const fn new() -> Self {
        Out {
            buf: [0; MSG_MAX],
            len: 0,
        }
    }
    fn put(&mut self, s: &[u8]) {
        let n = s.len().min(MSG_MAX - self.len);
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
    fn opt(&mut self, v: Option<u64>) {
        match v {
            Some(x) => self.num(x),
            None => self.put(b"-"),
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 19 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u64::from(c - b'0');
    }
    Some(v)
}

fn name_ok(s: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= NAME_MAX
        && s.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

/// Splits on spaces; `at_most` fields, the last one taking the rest of the line (the `arg`).
struct Fields<'a> {
    line: &'a [u8],
}

impl<'a> Fields<'a> {
    fn next(&mut self) -> Option<&'a [u8]> {
        let mut s = self.line;
        while let [b' ', rest @ ..] = s {
            s = rest;
        }
        if s.is_empty() {
            self.line = s;
            return None;
        }
        let end = s.iter().position(|c| *c == b' ').unwrap_or(s.len());
        self.line = &s[end..];
        Some(&s[..end])
    }
    fn rest(&mut self) -> &'a [u8] {
        let mut s = self.line;
        while let [b' ', rest @ ..] = s {
            s = rest;
        }
        let mut end = s.len();
        while end > 0 && (s[end - 1] == b' ' || s[end - 1] == b'\r') {
            end -= 1;
        }
        &s[..end]
    }
}

struct Manager {
    services: [Service; MAX_SERVICES],
    n: usize,
    loaded: bool,
    ctl: Handle,
}

enum LoadError {
    Missing,
    Syntax(u64),
    UnknownDep([u8; NAME_MAX], usize),
    Cycle,
    TooMany,
}

impl Manager {
    fn find(&self, name: &[u8]) -> Option<usize> {
        (0..self.n).find(|&i| self.services[i].name() == name)
    }

    /// Reads and parses the manifest; the table is replaced only when the whole file parses.
    fn load(&mut self, path: &[u8]) -> Result<usize, LoadError> {
        let f = libnawah::open(path, libnawah::O_READ).map_err(|_| LoadError::Missing)?;
        let mut text = [0u8; MANIFEST_MAX];
        let mut len = 0;
        loop {
            match libnawah::read(f, &mut text[len..]) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(_) => break,
            }
            if len == MANIFEST_MAX {
                break;
            }
        }
        libnawah::handle_close(f);
        let mut table = [EMPTY; MAX_SERVICES];
        let mut n = 0;
        let mut dep_names = [[0u8; DEPS_MAX]; MAX_SERVICES]; // raw dep lists, resolved after parsing
        let mut dep_lens = [0usize; MAX_SERVICES];
        let mut line_no = 0u64;
        for line in text[..len].split(|c| *c == b'\n') {
            line_no += 1;
            let line = match line.iter().position(|c| *c == b'#') {
                Some(p) => &line[..p],
                None => line,
            };
            let mut f = Fields { line };
            let Some(name) = f.next() else {
                continue; // blank or comment line
            };
            if n == MAX_SERVICES {
                return Err(LoadError::TooMany);
            }
            let syntax = LoadError::Syntax(line_no);
            if !name_ok(name) || (0..n).any(|i| table[i].name() == name) {
                return Err(syntax);
            }
            let (Some(path), Some(deps), Some(timeout), Some(restart), Some(max), Some(backoff)) =
                (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                return Err(syntax);
            };
            if path.is_empty() || path.len() > PATH_MAX || path[0] != b'/' || deps.len() > DEPS_MAX
            {
                return Err(syntax);
            }
            let restart_on_failure = match restart {
                b"never" => false,
                b"on-failure" => true,
                _ => return Err(syntax),
            };
            let (Some(timeout), Some(max), Some(backoff)) =
                (parse_u64(timeout), parse_u64(max), parse_u64(backoff))
            else {
                return Err(syntax);
            };
            let arg = f.rest();
            if arg.len() > ARG_MAX {
                return Err(syntax);
            }
            let s = &mut table[n];
            s.name[..name.len()].copy_from_slice(name);
            s.name_len = name.len();
            s.path[..path.len()].copy_from_slice(path);
            s.path_len = path.len();
            s.arg[..arg.len()].copy_from_slice(arg);
            s.arg_len = arg.len();
            s.timeout = timeout;
            s.restart_on_failure = restart_on_failure;
            s.max_restarts = max;
            s.backoff = backoff;
            dep_names[n][..deps.len()].copy_from_slice(deps);
            dep_lens[n] = deps.len();
            n += 1;
        }
        // Resolve dependencies.
        for i in 0..n {
            let deps = &dep_names[i][..dep_lens[i]];
            if deps == b"-" {
                continue;
            }
            for d in deps.split(|c| *c == b',') {
                let Some(j) = (0..n).find(|&j| table[j].name() == d) else {
                    let mut nm = [0u8; NAME_MAX];
                    let l = d.len().min(NAME_MAX);
                    nm[..l].copy_from_slice(&d[..l]);
                    return Err(LoadError::UnknownDep(nm, l));
                };
                table[i].deps |= 1 << j;
            }
        }
        // A cycle: Kahn's algorithm leaves something unordered.
        let mut done: u16 = 0;
        loop {
            let mut progressed = false;
            for (i, s) in table.iter().enumerate().take(n) {
                if done & (1 << i) == 0 && s.deps & !done == 0 {
                    done |= 1 << i;
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        if done.count_ones() as usize != n {
            return Err(LoadError::Cycle);
        }
        self.services = table;
        self.n = n;
        self.loaded = true;
        Ok(n)
    }

    fn ready_mask(&self) -> u16 {
        (0..self.n)
            .filter(|&i| self.services[i].state == State::Ready)
            .fold(0, |m, i| m | (1 << i))
    }

    /// Services that will not become ready: given up, blocked, or failed with no restart due.
    fn dead_mask(&self) -> u16 {
        (0..self.n)
            .filter(|&i| {
                let s = &self.services[i];
                match s.state {
                    State::GivenUp | State::Blocked => true,
                    State::Failed => s.deadline.is_none(),
                    _ => false,
                }
            })
            .fold(0, |m, i| m | (1 << i))
    }

    /// Starts every pending service whose dependencies are all ready; blocks those with a
    /// dead dependency (transitively, by repeating until nothing changes).
    fn advance(&mut self, now: u64) {
        loop {
            let ready = self.ready_mask();
            let dead = self.dead_mask();
            let mut changed = false;
            for i in 0..self.n {
                if self.services[i].state != State::Pending {
                    continue;
                }
                if self.services[i].deps & dead != 0 {
                    self.services[i].state = State::Blocked;
                    changed = true;
                } else if self.services[i].deps & !ready == 0 {
                    self.start(i, now);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn start(&mut self, i: usize, now: u64) {
        let s = &mut self.services[i];
        if s.first_start.is_none() {
            s.first_start = Some(now);
        }
        s.last_start = Some(now);
        s.ready_tick = None;
        let Ok((ours, theirs)) = libnawah::channel_create() else {
            s.state = State::Failed;
            s.deadline = None;
            return;
        };
        match libnawah::process_spawn(s.path(), &[theirs]) {
            Ok(p) => {
                let mut msg = Out::new();
                msg.put(b"START");
                if s.arg_len > 0 {
                    msg.put(b" ");
                    let (arg, len) = (s.arg, s.arg_len);
                    msg.put(&arg[..len]);
                }
                libnawah::channel_write(ours, msg.bytes(), &[]);
                s.chan = Some(ours);
                s.process = Some(p);
                s.state = State::Starting;
                s.deadline = Some(now.saturating_add(s.timeout));
            }
            Err(_) => {
                libnawah::handle_close(ours);
                s.state = State::Failed;
                s.deadline = None;
                self.schedule_restart(i, now);
            }
        }
    }

    fn close_chan(&mut self, i: usize) {
        if let Some(c) = self.services[i].chan.take() {
            libnawah::handle_close(c);
        }
    }

    /// After a failure: the next start after `backoff << k` ticks, or give up.
    fn schedule_restart(&mut self, i: usize, now: u64) {
        let s = &mut self.services[i];
        if s.restart_on_failure && s.restarts < s.max_restarts {
            let shift = s.restarts.min(32) as u32;
            s.deadline = Some(now.saturating_add(s.backoff << shift));
        } else {
            s.state = if s.restart_on_failure {
                State::GivenUp
            } else {
                State::Failed
            };
            s.deadline = None;
        }
    }

    /// A message (or the close) on service `i`'s boot channel.
    fn on_boot_channel(&mut self, i: usize, now: u64) {
        let Some(c) = self.services[i].chan else {
            return;
        };
        let mut buf = [0u8; 64];
        let mut hs = [0u32; 1];
        match libnawah::channel_read(c, &mut buf, &mut hs, false) {
            Ok((n, _)) => {
                if &buf[..n] == b"READY" && self.services[i].state == State::Starting {
                    let s = &mut self.services[i];
                    s.state = State::Ready;
                    s.ready_tick = Some(now);
                    s.deadline = None;
                }
            }
            Err(ERR_PEER_CLOSED) => self.close_chan(i),
            Err(_) => {}
        }
    }

    /// Service `i`'s process exited.
    fn on_exit(&mut self, i: usize, now: u64) {
        let Some(p) = self.services[i].process else {
            return;
        };
        let code = match libnawah::process_status(p) {
            Ok(c) => c,
            Err(_) => return, // not exited yet (spurious): keep waiting
        };
        libnawah::handle_close(p);
        self.services[i].process = None;
        self.close_chan(i);
        let s = &mut self.services[i];
        s.exit = Some(code);
        match s.state {
            State::Starting | State::Ready => {
                if code == 0 {
                    s.state = State::Stopped;
                    s.deadline = None;
                } else {
                    s.state = State::Failed;
                    self.schedule_restart(i, now);
                }
            }
            State::Stopping => {
                s.state = State::Stopped;
                s.deadline = None;
            }
            _ => {} // a timed-out or abandoned service finally went away: nothing changes
        }
    }

    /// Deadlines that passed: readiness timeouts (final) and restarts.
    fn on_time(&mut self, now: u64) {
        for i in 0..self.n {
            let Some(d) = self.services[i].deadline else {
                continue;
            };
            if d > now {
                continue;
            }
            match self.services[i].state {
                State::Starting => {
                    self.services[i].state = State::Failed;
                    self.services[i].deadline = None;
                    self.close_chan(i);
                }
                State::Failed => {
                    self.services[i].restarts += 1;
                    self.services[i].deadline = None;
                    self.start(i, now);
                }
                _ => self.services[i].deadline = None,
            }
        }
    }

    fn next_deadline(&self) -> Option<u64> {
        (0..self.n).filter_map(|i| self.services[i].deadline).min()
    }

    fn list(&self, out: &mut Out) {
        for i in 0..self.n {
            let s = &self.services[i];
            out.put(s.name());
            out.put(b" ");
            out.put(s.state.name());
            out.put(b" ");
            out.num(s.restarts);
            out.put(b" ");
            out.opt(s.first_start);
            out.put(b" ");
            out.opt(s.last_start);
            out.put(b" ");
            out.opt(s.ready_tick);
            out.put(b" ");
            out.opt(s.exit);
            out.put(b"\n");
        }
    }

    /// One request on the control channel; false when the controller closed it.
    fn on_control(&mut self, now: u64) -> bool {
        let mut buf = [0u8; 256];
        let mut hs = [0u32; 1];
        let n = match libnawah::channel_read(self.ctl, &mut buf, &mut hs, false) {
            Ok((n, _)) => n,
            Err(ERR_PEER_CLOSED) => return false,
            Err(_) => return true,
        };
        let req = &buf[..n];
        let mut out = Out::new();
        if let Some(path) = req.strip_prefix(b"LOAD ") {
            if self.loaded {
                out.put(b"ERR LOADED");
            } else {
                match self.load(path) {
                    Ok(count) => {
                        out.put(b"OK ");
                        out.num(count as u64);
                        self.advance(now);
                    }
                    Err(LoadError::Missing) => out.put(b"ERR MANIFEST_MISSING"),
                    Err(LoadError::Syntax(line)) => {
                        out.put(b"ERR MANIFEST_SYNTAX ");
                        out.num(line);
                    }
                    Err(LoadError::UnknownDep(name, len)) => {
                        out.put(b"ERR MANIFEST_UNKNOWN_DEP ");
                        out.put(&name[..len]);
                    }
                    Err(LoadError::Cycle) => out.put(b"ERR MANIFEST_CYCLE"),
                    Err(LoadError::TooMany) => out.put(b"ERR TOO_MANY"),
                }
            }
        } else if req == b"LIST" {
            self.list(&mut out);
        } else if let Some(name) = req.strip_prefix(b"STOP ") {
            match self.find(name) {
                Some(i) => {
                    if let Some(c) = self.services[i].chan {
                        libnawah::channel_write(c, b"STOP", &[]);
                    }
                    self.close_chan(i);
                    if matches!(self.services[i].state, State::Starting | State::Ready) {
                        self.services[i].state = State::Stopping;
                        self.services[i].deadline = None;
                    }
                    out.put(b"OK");
                }
                None => out.put(b"ERR UNKNOWN"),
            }
        } else {
            out.put(b"ERR BAD_REQUEST");
        }
        libnawah::channel_write(self.ctl, out.bytes(), &[]);
        true
    }
}

fn main() -> u64 {
    let ctl = libnawah::bootstrap_handle();
    if ctl == 0 {
        return 0xE0;
    }
    let mut m = Manager {
        services: [EMPTY; MAX_SERVICES],
        n: 0,
        loaded: false,
        ctl,
    };
    // Wait-set slots: 0 = control; then per service (boot channel, process).
    let mut entries = [WaitEntry {
        handle: 0,
        signals: 0,
    }; 1 + 2 * MAX_SERVICES];
    let mut owner = [(0usize, 0u8); 1 + 2 * MAX_SERVICES];
    loop {
        let now = libnawah::clock_ticks();
        m.on_time(now);
        m.advance(now);
        entries[0] = WaitEntry {
            handle: ctl,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        };
        owner[0] = (0, 0);
        let mut k = 1;
        for i in 0..m.n {
            if let Some(c) = m.services[i].chan {
                entries[k] = WaitEntry {
                    handle: c,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                };
                owner[k] = (i, 1);
                k += 1;
            }
            if let Some(p) = m.services[i].process {
                entries[k] = WaitEntry {
                    handle: p,
                    signals: SIGNAL_EXITED,
                };
                owner[k] = (i, 2);
                k += 1;
            }
        }
        let timeout = match m.next_deadline() {
            Some(d) => d.saturating_sub(now),
            None => TIMEOUT_FOREVER,
        };
        match libnawah::object_wait_many(&entries[..k], timeout) {
            Ok((idx, _)) => {
                let now = libnawah::clock_ticks();
                match owner[idx] {
                    (_, 0) => {
                        if !m.on_control(now) {
                            break;
                        }
                    }
                    (i, 1) => m.on_boot_channel(i, now),
                    (i, _) => m.on_exit(i, now),
                }
            }
            Err(ERR_TIMED_OUT) => {}
            Err(_) => return 0xE1,
        }
    }
    0
}
