//! configd — the configuration and policy service `config` (WP-26, docs/contracts/config.md,
//! ADR-0016 §6): separate stores (device, policy, user/<uid>, session) of versioned keys,
//! compare-and-set, idempotent request ids, change notifications over channels, policy
//! precedence, two-slot persistence with a hash (no rename in files.md v1). Authority is the
//! token on every modifying request, checked here with `token_info` (REQ-M4-004). The large
//! tables live in a static (the user stack is 64 KiB); the process is single-threaded.

#![no_std]
#![no_main]

use libnawah::{
    perm, Handle, TokenInfo, WaitEntry, ERR_BUFFER_TOO_SMALL, ERR_PEER_CLOSED, SIGNAL_PEER_CLOSED,
    SIGNAL_READABLE, TIMEOUT_FOREVER,
};
use nawah_crypto::Sha256;

libnawah::entry!(main);

const KEY_MAX: usize = 64;
const VALUE_MAX: usize = 256;
const KEYS_PER_STORE: usize = 64;
const USER_STORES: usize = 8;
const STORES: usize = 3 + USER_STORES;
const MAX_CLIENTS: usize = 8;
const MAX_SUBS: usize = 8;
const RID_CACHE: usize = 16;
const REPLY_MAX: usize = 64;
const FILE_MAX: usize = 32 * 1024;
const MSG_MAX: usize = 4096;
const UID_MAX_PERSISTENT: u32 = 9999;

const DEVICE: usize = 0;
const POLICY: usize = 1;
const SESSION: usize = 2;

#[derive(Clone, Copy)]
struct Entry {
    used: bool,
    key: [u8; KEY_MAX],
    key_len: u8,
    value: [u8; VALUE_MAX],
    value_len: u16,
    version: u64,
    /// Session store only: the owning uid (values are kept apart per user).
    uid: u32,
}

const NO_ENTRY: Entry = Entry {
    used: false,
    key: [0; KEY_MAX],
    key_len: 0,
    value: [0; VALUE_MAX],
    value_len: 0,
    version: 0,
    uid: 0,
};

#[derive(Clone, Copy)]
struct Store {
    /// User stores: loaded for this uid; 0 = free slot.
    uid: u32,
    loaded: bool,
    /// Generation of the slot files; the next write goes to the lower one.
    slot_gen: [u64; 2],
    slot_bad: [bool; 2],
    entries: [Entry; KEYS_PER_STORE],
    subs: [Handle; MAX_SUBS],
    /// The client slot each subscription belongs to (meaningful where `subs` is not 0).
    sub_client: [u8; MAX_SUBS],
}

const NO_STORE: Store = Store {
    uid: 0,
    loaded: false,
    slot_gen: [0; 2],
    slot_bad: [false; 2],
    entries: [NO_ENTRY; KEYS_PER_STORE],
    subs: [0; MAX_SUBS],
    sub_client: [0; MAX_SUBS],
};

#[derive(Clone, Copy)]
struct Cached {
    rid: u64,
    reply: [u8; REPLY_MAX],
    len: u8,
}

const NO_CACHED: Cached = Cached {
    rid: 0,
    reply: [0; REPLY_MAX],
    len: 0,
};

#[derive(Clone, Copy)]
struct Client {
    chan: Handle,
    cache: [Cached; RID_CACHE],
    next: usize,
}

const NO_CLIENT: Client = Client {
    chan: 0,
    cache: [NO_CACHED; RID_CACHE],
    next: 0,
};

struct State {
    stores: [Store; STORES],
    clients: [Client; MAX_CLIENTS],
    file: [u8; FILE_MAX],
    msg: [u8; MSG_MAX],
}

static mut STATE: State = State {
    stores: [NO_STORE; STORES],
    clients: [NO_CLIENT; MAX_CLIENTS],
    file: [0; FILE_MAX],
    msg: [0; MSG_MAX],
};

/// The single-threaded process's state (the program never holds two references to it: every
/// function takes it once from `main`).
fn state() -> &'static mut State {
    // SAFETY: one thread, and `main` is the only caller, once, keeping the reference for the
    // program's whole life (no second reference is ever created).
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Out<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Out { buf, len: 0 }
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
    fn hex(&mut self, bytes: &[u8]) {
        const H: &[u8; 16] = b"0123456789abcdef";
        for b in bytes {
            self.put(&[H[(b >> 4) as usize], H[(b & 15) as usize]]);
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

fn key_ok(k: &[u8]) -> bool {
    !k.is_empty()
        && k.len() <= KEY_MAX
        && k.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'.')
}

fn value_ok(v: &[u8]) -> bool {
    v.len() <= VALUE_MAX && v.iter().all(|c| c.is_ascii_graphic() || *c == b' ')
}

fn hex_ok(s: &[u8], out: &mut [u8]) -> bool {
    if s.len() != out.len() * 2 {
        return false;
    }
    for (i, o) in out.iter_mut().enumerate() {
        let v = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        match (v(s[2 * i]), v(s[2 * i + 1])) {
            (Some(h), Some(l)) => *o = (h << 4) | l,
            _ => return false,
        }
    }
    true
}

/// Space-separated fields; `rest` gives the remainder of the line (values may hold spaces).
struct Fields<'a> {
    s: &'a [u8],
}

impl<'a> Fields<'a> {
    fn next(&mut self) -> Option<&'a [u8]> {
        while let [b' ', rest @ ..] = self.s {
            self.s = rest;
        }
        if self.s.is_empty() {
            return None;
        }
        let end = self
            .s
            .iter()
            .position(|c| *c == b' ')
            .unwrap_or(self.s.len());
        let f = &self.s[..end];
        self.s = &self.s[end..];
        Some(f)
    }
    fn rest(&mut self) -> &'a [u8] {
        while let [b' ', rest @ ..] = self.s {
            self.s = rest;
        }
        self.s
    }
}

/// The slot file name of a persistent store (`CFGDEV.A`, `CFGPOL.B`, `CFGU1000.A`).
fn slot_path(store: usize, uid: u32, slot: usize, buf: &mut [u8; 24]) -> &[u8] {
    let mut o = Out::new(buf);
    o.put(b"/SYSTEM/");
    match store {
        DEVICE => o.put(b"CFGDEV"),
        POLICY => o.put(b"CFGPOL"),
        _ => {
            o.put(b"CFGU");
            o.num(u64::from(uid));
        }
    }
    o.put(if slot == 0 { b".A" } else { b".B" });
    let n = o.len;
    &buf[..n]
}

enum Access {
    Ok,
    Denied,
}

const REPLY_INVALID: &[u8] = b"ERR INVALID";
const REPLY_ACCESS: &[u8] = b"ERR ACCESS";
const REPLY_NOT_FOUND: &[u8] = b"ERR NOT_FOUND";

/// The uid a `user/<uid>` store name carries, when it is one a store may have (config.md §1).
fn user_uid(name: &[u8]) -> Option<u32> {
    let uid = parse_u64(name.strip_prefix(b"user/")?)?;
    (uid != 0 && uid <= u64::from(UID_MAX_PERSISTENT)).then_some(uid as u32)
}

impl State {
    /// The store a modifying request names. A user store that is not loaded is created only
    /// for a token that may modify it, decided from the name before any slot is taken, so a
    /// refused request leaves no store behind (config.md v1.4, WP-157). ERR INVALID for a name
    /// that is no store, or when no slot is free; ERR ACCESS for a token that may not modify it.
    fn store_for_write(&mut self, name: &[u8], token: &TokenInfo) -> Result<usize, &'static [u8]> {
        let create =
            user_uid(name).is_some_and(|uid| token.perms & perm::ADMIN != 0 || uid == token.uid);
        let Some(i) = self.store_index(name, create) else {
            return Err(if create || user_uid(name).is_none() {
                REPLY_INVALID
            } else {
                REPLY_ACCESS
            });
        };
        match self.access(i, token) {
            Access::Ok => Ok(i),
            Access::Denied => Err(REPLY_ACCESS),
        }
    }

    fn store_index(&mut self, name: &[u8], create_user: bool) -> Option<usize> {
        match name {
            b"device" => Some(DEVICE),
            b"policy" => Some(POLICY),
            b"session" => Some(SESSION),
            _ => {
                let uid = user_uid(name)?;
                if let Some(i) = (3..STORES).find(|&i| self.stores[i].uid == uid) {
                    return Some(i);
                }
                if !create_user {
                    return None;
                }
                let i = (3..STORES).find(|&i| self.stores[i].uid == 0)?;
                self.stores[i] = NO_STORE;
                self.stores[i].uid = uid;
                self.load(i);
                Some(i)
            }
        }
    }

    /// The store a GET or EXPORT names (config.md v1.6, WP-112): a user store through
    /// `user_store_for_read`, the others as before (ERR NOT_FOUND for a name that is no store).
    fn store_for_read(
        &mut self,
        name: &[u8],
        token: Option<TokenInfo>,
    ) -> Result<usize, &'static [u8]> {
        match user_uid(name) {
            Some(uid) => self.user_store_for_read(uid, token),
            None => self.store_index(name, false).ok_or(REPLY_NOT_FOUND),
        }
    }

    /// User store `uid` for a read (config.md v1.6, WP-112). It is read with a usable token of
    /// that uid or with ADMIN alone: to any other reader it is not found, loaded or not, and
    /// nothing is loaded for it, so a read tells no one else whether the store exists and takes
    /// no slot. For an allowed reader a store that is not loaded is loaded, as for a write; one with
    /// no intact slot on the volume is not found and leaves its slot free, and when no slot is
    /// free the read is answered ERR INVALID, as a write is (v1.4).
    fn user_store_for_read(
        &mut self,
        uid: u32,
        token: Option<TokenInfo>,
    ) -> Result<usize, &'static [u8]> {
        let reader = token.filter(|t| t.usable());
        if !reader.is_some_and(|t| t.perms & perm::ADMIN != 0 || t.uid == uid) {
            return Err(REPLY_NOT_FOUND);
        }
        if let Some(i) = (3..STORES).find(|&i| self.stores[i].uid == uid) {
            return Ok(i);
        }
        let i = (3..STORES)
            .find(|&i| self.stores[i].uid == 0)
            .ok_or(REPLY_INVALID)?;
        self.stores[i] = NO_STORE;
        self.stores[i].uid = uid;
        if self.load(i) {
            Ok(i)
        } else {
            self.stores[i] = NO_STORE;
            Err(REPLY_NOT_FOUND)
        }
    }

    /// Reads both slots of a persistent store and adopts the newest intact one (config.md §2);
    /// whether one was adopted (the in-memory session store always is).
    fn load(&mut self, i: usize) -> bool {
        if i == SESSION {
            self.stores[i].loaded = true;
            return true;
        }
        let uid = self.stores[i].uid;
        let mut best: Option<(usize, u64)> = None;
        let mut gens = [0u64; 2];
        let mut bad = [false; 2];
        for slot in 0..2 {
            let mut name = [0u8; 24];
            let path = slot_path(i, uid, slot, &mut name);
            let Ok(f) = libnawah::open(path, libnawah::O_READ) else {
                continue;
            };
            let mut len = 0;
            while len < FILE_MAX {
                match libnawah::read(f, &mut self.file[len..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => len += n,
                }
            }
            libnawah::handle_close(f);
            match slot_generation(&self.file[..len]) {
                Some(g) => {
                    gens[slot] = g;
                    if best.is_none_or(|(_, bg)| g > bg) {
                        best = Some((slot, g));
                    }
                }
                None => bad[slot] = true,
            }
        }
        let st = &mut self.stores[i];
        st.slot_gen = gens;
        st.slot_bad = bad;
        st.loaded = true;
        let Some((slot, _)) = best else {
            return false;
        };
        // Re-read the chosen slot into the table.
        let mut name = [0u8; 24];
        let path = slot_path(i, uid, slot, &mut name);
        let Ok(f) = libnawah::open(path, libnawah::O_READ) else {
            return false;
        };
        let mut len = 0;
        while len < FILE_MAX {
            match libnawah::read(f, &mut self.file[len..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => len += n,
            }
        }
        libnawah::handle_close(f);
        let mut n = 0;
        for line in self.file[..len].split(|c| *c == b'\n').skip(1) {
            if line.is_empty() || n == KEYS_PER_STORE {
                continue;
            }
            let mut f = Fields { s: line };
            let (Some(key), Some(ver)) = (f.next(), f.next()) else {
                continue;
            };
            let value = f.rest();
            let Some(ver) = parse_u64(ver) else {
                continue;
            };
            if !key_ok(key) || !value_ok(value) {
                continue;
            }
            let e = &mut self.stores[i].entries[n];
            e.used = true;
            e.key[..key.len()].copy_from_slice(key);
            e.key_len = key.len() as u8;
            e.value[..value.len()].copy_from_slice(value);
            e.value_len = value.len() as u16;
            e.version = ver;
            n += 1;
        }
        true
    }

    /// Writes the store to the slot with the lower generation, then syncs (config.md §2).
    fn save(&mut self, i: usize) -> bool {
        if i == SESSION {
            return true;
        }
        let uid = self.stores[i].uid;
        let gens = self.stores[i].slot_gen;
        let slot = if gens[0] <= gens[1] { 0 } else { 1 };
        let generation = gens[0].max(gens[1]) + 1;
        // Body first (hashed), then the header.
        let body_len;
        {
            let mut body = Out::new(&mut self.file[64..]);
            for e in self.stores[i].entries.iter().filter(|e| e.used) {
                body.put(&e.key[..usize::from(e.key_len)]);
                body.put(b" ");
                body.num(e.version);
                body.put(b" ");
                body.put(&e.value[..usize::from(e.value_len)]);
                body.put(b"\n");
            }
            body_len = body.len;
        }
        let digest = Sha256::digest(&self.file[64..64 + body_len]);
        let mut header = [0u8; 96];
        let header_len = {
            let mut h = Out::new(&mut header);
            h.put(b"NAWAH-CFG 1 ");
            h.num(generation);
            h.put(b" ");
            h.hex(&digest);
            h.put(b"\n");
            h.len
        };
        let mut name = [0u8; 24];
        let path = slot_path(i, uid, slot, &mut name);
        let Ok(f) = libnawah::open(
            path,
            libnawah::O_WRITE | libnawah::O_CREATE | libnawah::O_TRUNCATE,
        ) else {
            return false;
        };
        let ok = libnawah::write(f, &header[..header_len]) == Ok(header_len)
            && libnawah::write(f, &self.file[64..64 + body_len]) == Ok(body_len);
        libnawah::handle_close(f);
        if !ok || libnawah::sync() != 0 {
            return false;
        }
        self.stores[i].slot_gen[slot] = generation;
        self.stores[i].slot_bad[slot] = false;
        true
    }

    fn find(&self, i: usize, key: &[u8], uid: u32) -> Option<usize> {
        self.stores[i].entries.iter().position(|e| {
            e.used && &e.key[..usize::from(e.key_len)] == key && (i != SESSION || e.uid == uid)
        })
    }

    /// Who may modify store `i` (config.md §1).
    fn access(&self, i: usize, token: &TokenInfo) -> Access {
        let admin = token.perms & perm::ADMIN != 0;
        let ok = match i {
            DEVICE => admin || token.perms & perm::CONFIG_WRITE != 0,
            POLICY => admin,
            SESSION => true,
            _ => admin || self.stores[i].uid == token.uid,
        };
        if ok {
            Access::Ok
        } else {
            Access::Denied
        }
    }

    /// The slot of store `i` a subscription of client `ci` takes: the one it holds there,
    /// else a free one.
    fn sub_slot(&self, i: usize, ci: usize) -> Option<usize> {
        let st = &self.stores[i];
        (0..MAX_SUBS)
            .find(|&s| st.subs[s] != 0 && usize::from(st.sub_client[s]) == ci)
            .or_else(|| st.subs.iter().position(|s| *s == 0))
    }

    /// A client is gone: its channel end is closed and its slot freed, and its subscriptions
    /// go with it. The one place a client slot is freed (config.md v1.5, WP-158).
    fn drop_client(&mut self, ci: usize) {
        libnawah::handle_close(self.clients[ci].chan);
        self.clients[ci].chan = 0;
        for st in self.stores.iter_mut() {
            for s in 0..MAX_SUBS {
                if st.subs[s] != 0 && usize::from(st.sub_client[s]) == ci {
                    libnawah::handle_close(st.subs[s]);
                    st.subs[s] = 0;
                }
            }
        }
    }

    fn notify(&mut self, i: usize, key: &[u8], version: u64) {
        let name: &[u8] = match i {
            DEVICE => b"device",
            POLICY => b"policy",
            SESSION => b"session",
            _ => b"user",
        };
        let mut msg = [0u8; 128];
        let len = {
            let mut o = Out::new(&mut msg);
            o.put(b"CHANGED ");
            o.put(name);
            if i >= 3 {
                o.put(b"/");
                o.num(u64::from(self.stores[i].uid));
            }
            o.put(b" ");
            o.put(key);
            o.put(b" ");
            o.num(version);
            o.len
        };
        for s in 0..MAX_SUBS {
            let h = self.stores[i].subs[s];
            if h != 0 && libnawah::channel_write(h, &msg[..len], &[]) != 0 {
                libnawah::handle_close(h);
                self.stores[i].subs[s] = 0;
            }
        }
    }

    /// `SET`/`DEL`: the compare-and-set on one key; `Ok(new_version)` or a reply code.
    fn modify(
        &mut self,
        i: usize,
        key: &[u8],
        expected: u64,
        value: Option<&[u8]>,
        uid: u32,
        out: &mut Out,
    ) {
        let pos = self.find(i, key, uid);
        let current = pos.map_or(0, |p| self.stores[i].entries[p].version);
        if current != expected {
            out.put(b"ERR VERSION ");
            out.num(current);
            return;
        }
        // Apply in the table, persist, and roll back the table when the save fails.
        let backup = pos.map(|p| self.stores[i].entries[p]);
        let new_version;
        let slot_used;
        match value {
            Some(v) => {
                let p = match pos {
                    Some(p) => p,
                    None => match self.stores[i].entries.iter().position(|e| !e.used) {
                        Some(p) => p,
                        None => {
                            out.put(b"ERR FULL");
                            return;
                        }
                    },
                };
                let e = &mut self.stores[i].entries[p];
                e.used = true;
                e.key = [0; KEY_MAX];
                e.key[..key.len()].copy_from_slice(key);
                e.key_len = key.len() as u8;
                e.value = [0; VALUE_MAX];
                e.value[..v.len()].copy_from_slice(v);
                e.value_len = v.len() as u16;
                e.version = current + 1;
                e.uid = uid;
                new_version = current + 1;
                slot_used = p;
            }
            None => {
                let Some(p) = pos else {
                    out.put(b"ERR NOT_FOUND");
                    return;
                };
                self.stores[i].entries[p] = NO_ENTRY;
                new_version = 0;
                slot_used = p;
            }
        }
        if !self.save(i) {
            match backup {
                Some(b) => self.stores[i].entries[slot_used] = b,
                None => self.stores[i].entries[slot_used] = NO_ENTRY,
            }
            out.put(b"ERR IO");
            return;
        }
        self.notify(i, key, new_version);
        out.put(b"OK ");
        out.num(if value.is_some() {
            new_version
        } else {
            current
        });
    }

    fn get(&self, i: usize, key: &[u8], uid: u32, out: &mut Out) -> bool {
        match self.find(i, key, uid) {
            Some(p) => {
                let e = &self.stores[i].entries[p];
                out.put(b"OK ");
                out.num(e.version);
                out.put(b" ");
                out.put(&e.value[..usize::from(e.value_len)]);
                true
            }
            None => false,
        }
    }

    /// One request; `handle` is the handle it carried (token or subscriber channel): the caller
    /// closes it after this returns unless SUBSCRIBE took it (left `None`; config.md v1.3).
    /// Returns the request id the reply is cached under (modifying requests).
    fn request(
        &mut self,
        ci: usize,
        req: &[u8],
        handle: &mut Option<Handle>,
        out: &mut Out,
    ) -> Option<u64> {
        // The first line is the request; IMPORT carries its lines after it.
        let head = match req.iter().position(|c| *c == b'\n') {
            Some(p) => &req[..p],
            None => req,
        };
        let mut f = Fields { s: head };
        let verb = f.next().unwrap_or(b"");
        let token = handle.and_then(|h| libnawah::token_info(h).ok());
        match verb {
            b"GET" => {
                let (Some(store), Some(key)) = (f.next(), f.next()) else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                // Only a usable token names whose session values are read: a revoked or
                // expired one reads as no token (config.md v1.1); a user store is read for its
                // owner or ADMIN alone, and loaded on that read (v1.6).
                let uid = token.filter(|t| t.usable()).map_or(0, |t| t.uid);
                match self.store_for_read(store, token) {
                    Ok(i) if self.get(i, key, uid, out) => {}
                    Ok(_) => out.put(REPLY_NOT_FOUND),
                    Err(reply) => out.put(reply),
                }
                None
            }
            b"SET" | b"DEL" => {
                let (Some(store), Some(key), Some(expected), Some(rid)) =
                    (f.next(), f.next(), f.next(), f.next())
                else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                let value = if verb == b"SET" { Some(f.rest()) } else { None };
                let (Some(expected), Some(rid)) = (parse_u64(expected), parse_u64(rid)) else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                let Some(token) = token else {
                    out.put(if handle.is_some() {
                        b"ERR ACCESS"
                    } else {
                        b"ERR BAD_REQUEST"
                    });
                    return Some(rid);
                };
                if !token.usable() {
                    out.put(b"ERR ACCESS");
                    return Some(rid);
                }
                if !key_ok(key) || value.is_some_and(|v| !value_ok(v)) {
                    out.put(b"ERR INVALID");
                    return Some(rid);
                }
                let i = match self.store_for_write(store, &token) {
                    Ok(i) => i,
                    Err(reply) => {
                        out.put(reply);
                        return Some(rid);
                    }
                };
                self.modify(i, key, expected, value, token.uid, out);
                Some(rid)
            }
            b"RESOLVE" => {
                let Some(key) = f.next() else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                let Some(token) = token.filter(|t| t.usable()) else {
                    out.put(if handle.is_some() {
                        b"ERR ACCESS"
                    } else {
                        b"ERR BAD_REQUEST"
                    });
                    return None;
                };
                // The token's own user store, loaded on this read (config.md v1.6, WP-112); none
                // for a uid no store may carry or none on the volume; no free slot: ERR INVALID.
                let persistent = token.uid != 0 && token.uid <= UID_MAX_PERSISTENT;
                // Policy beats every user value: a key it holds is answered without loading the
                // token's store, so a full table does not stand in its way (WP-112's review round).
                let load = persistent && self.find(POLICY, key, token.uid).is_none();
                let user_store = if load {
                    match self.user_store_for_read(token.uid, Some(token)) {
                        Ok(i) => Some(i),
                        Err(reply) if reply == REPLY_INVALID => {
                            out.put(reply);
                            return None;
                        }
                        Err(_) => None,
                    }
                } else {
                    (3..STORES).find(|&i| persistent && self.stores[i].uid == token.uid)
                };
                for (i, source) in [
                    (Some(POLICY), &b"policy"[..]),
                    (user_store, b"user"),
                    (Some(DEVICE), b"device"),
                ] {
                    if let Some(i) = i {
                        if let Some(p) = self.find(i, key, token.uid) {
                            let e = &self.stores[i].entries[p];
                            out.put(b"OK ");
                            out.put(source);
                            out.put(b" ");
                            out.num(e.version);
                            out.put(b" ");
                            out.put(&e.value[..usize::from(e.value_len)]);
                            return None;
                        }
                    }
                }
                out.put(b"ERR NOT_FOUND");
                None
            }
            b"SUBSCRIBE" => {
                let (Some(store), Some(h)) = (f.next(), *handle) else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                // A subscriber shows no token, and session values are kept apart per user: no
                // session subscription until a form carries the token (config.md v1.5, WP-158).
                if store == b"session" {
                    out.put(b"ERR ACCESS");
                    return None;
                }
                // Nor a user store's (v1.6, WP-112): it is read for its owner or ADMIN alone, and
                // a subscriber that shows no token would learn that it is loaded and its keys.
                if user_uid(store).is_some() {
                    out.put(REPLY_ACCESS);
                    return None;
                }
                match self.store_index(store, false) {
                    // One subscription per client and store: a second replaces the first,
                    // whose end is closed, so no client holds a store's slots against the
                    // others (config.md v1.5, WP-158).
                    Some(i) => match self.sub_slot(i, ci) {
                        Some(slot) => {
                            let old = self.stores[i].subs[slot];
                            if old != 0 {
                                libnawah::handle_close(old);
                            }
                            // The subscription takes the handle: the caller does not close it.
                            self.stores[i].subs[slot] = h;
                            self.stores[i].sub_client[slot] = ci as u8;
                            *handle = None;
                            out.put(b"OK");
                            return None;
                        }
                        None => out.put(b"ERR FULL"),
                    },
                    // A subscriber shows no token, so it never creates a user store: one that
                    // is not loaded is not found, as for GET and EXPORT (config.md v1.4, WP-157).
                    None if user_uid(store).is_some() => out.put(b"ERR NOT_FOUND"),
                    None => out.put(b"ERR INVALID"),
                }
                None
            }
            b"EXPORT" => {
                let Some(store) = f.next() else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                let uid = token.filter(|t| t.usable()).map_or(0, |t| t.uid);
                match self.store_for_read(store, token) {
                    Ok(i) => {
                        out.put(b"OK");
                        for e in self.stores[i]
                            .entries
                            .iter()
                            .filter(|e| e.used && (i != SESSION || e.uid == uid))
                        {
                            out.put(b"\n");
                            out.put(&e.key[..usize::from(e.key_len)]);
                            out.put(b" ");
                            out.num(e.version);
                            out.put(b" ");
                            out.put(&e.value[..usize::from(e.value_len)]);
                        }
                    }
                    Err(reply) => out.put(reply),
                }
                None
            }
            b"IMPORT" => {
                let (Some(store), Some(rid)) = (f.next(), f.next()) else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                let Some(rid) = parse_u64(rid) else {
                    out.put(b"ERR BAD_REQUEST");
                    return None;
                };
                let Some(token) = token.filter(|t| t.usable()) else {
                    out.put(if handle.is_some() {
                        b"ERR ACCESS"
                    } else {
                        b"ERR BAD_REQUEST"
                    });
                    return Some(rid);
                };
                let i = match self.store_for_write(store, &token) {
                    Ok(i) => i,
                    Err(reply) => {
                        out.put(reply);
                        return Some(rid);
                    }
                };
                // Validate every line first; then apply all.
                let body = match req.iter().position(|c| *c == b'\n') {
                    Some(p) => &req[p + 1..],
                    None => b"",
                };
                let mut line_no = 0u64;
                for line in body.split(|c| *c == b'\n') {
                    line_no += 1;
                    if line.is_empty() {
                        continue;
                    }
                    let mut lf = Fields { s: line };
                    let Some(key) = lf.next() else {
                        continue;
                    };
                    let value = lf.rest();
                    if !key_ok(key) || !value_ok(value) {
                        out.put(b"ERR INVALID ");
                        out.num(line_no);
                        return Some(rid);
                    }
                }
                let mut count = 0u64;
                for line in body.split(|c| *c == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    let mut lf = Fields { s: line };
                    let Some(key) = lf.next() else {
                        continue;
                    };
                    let value = lf.rest();
                    let current = self
                        .find(i, key, token.uid)
                        .map_or(0, |p| self.stores[i].entries[p].version);
                    let mut scratch = [0u8; 64];
                    let mut tmp = Out::new(&mut scratch);
                    self.modify(i, key, current, Some(value), token.uid, &mut tmp);
                    if tmp.bytes().starts_with(b"OK") {
                        count += 1;
                    }
                }
                out.put(b"OK ");
                out.num(count);
                Some(rid)
            }
            _ => {
                out.put(b"ERR BAD_REQUEST");
                None
            }
        }
    }
}

/// Parses a slot file's header and checks the body hash; the generation when intact.
fn slot_generation(data: &[u8]) -> Option<u64> {
    let nl = data.iter().position(|c| *c == b'\n')?;
    let mut f = Fields { s: &data[..nl] };
    if f.next()? != b"NAWAH-CFG" || f.next()? != b"1" {
        return None;
    }
    let gen = parse_u64(f.next()?)?;
    let mut expected = [0u8; 32];
    if !hex_ok(f.next()?, &mut expected) {
        return None;
    }
    let digest = Sha256::digest(&data[nl + 1..]);
    if !nawah_crypto::ct_eq(&digest, &expected) {
        return None;
    }
    Some(gen)
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let st = state();
    for i in [DEVICE, POLICY, SESSION] {
        st.load(i);
    }
    // Diagnostics: which slots were adopted (no values are printed).
    let mut line = [0u8; 160];
    let len = {
        let mut o = Out::new(&mut line);
        o.put(b"config|store|device_gen=");
        o.num(st.stores[DEVICE].slot_gen[0].max(st.stores[DEVICE].slot_gen[1]));
        o.put(b"|device_bad=");
        o.num(u64::from(st.stores[DEVICE].slot_bad[0]) + u64::from(st.stores[DEVICE].slot_bad[1]));
        o.put(b"|policy_gen=");
        o.num(st.stores[POLICY].slot_gen[0].max(st.stores[POLICY].slot_gen[1]));
        o.put(b"|device_keys=");
        o.num(st.stores[DEVICE].entries.iter().filter(|e| e.used).count() as u64);
        o.len
    };
    libnawah::trace(&line[..len]);
    let mut hs = [0u32; 1];
    match libnawah::channel_read(boot, &mut st.msg, &mut hs, true) {
        Ok((n, _)) if st.msg[..n].starts_with(b"START") => {}
        _ => return 0xE3,
    }
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE4;
    }
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
        for (i, c) in st.clients.iter().enumerate() {
            if c.chan != 0 {
                entries[k] = WaitEntry {
                    handle: c.chan,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                };
                owner[k] = i;
                k += 1;
            }
        }
        let Ok((idx, _)) = libnawah::object_wait_many(&entries[..k], TIMEOUT_FOREVER) else {
            return 0xE5;
        };
        if idx == 0 {
            match libnawah::channel_read(boot, &mut st.msg, &mut hs, false) {
                Ok((n, nh)) => {
                    if (st.msg[..n] == *b"CONNECT" || st.msg[..n].starts_with(b"CONNECT "))
                        && nh == 1
                    {
                        match st.clients.iter().position(|c| c.chan == 0) {
                            Some(slot) => {
                                st.clients[slot] = NO_CLIENT;
                                st.clients[slot].chan = hs[0];
                            }
                            None => {
                                libnawah::handle_close(hs[0]);
                            }
                        }
                    } else if &st.msg[..n] == b"STOP" {
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
        let c = st.clients[ci].chan;
        match libnawah::channel_read(c, &mut st.msg, &mut hs, false) {
            Ok((n, nh)) => {
                // The handle the request carried: closed at the one exit below, whatever the
                // request and whether its reply can be written, unless SUBSCRIBE took it
                // (config.md v1.3, WP-107).
                let mut handle = if nh == 1 { Some(hs[0]) } else { None };
                // A repeated request id: the stored reply, nothing applied (config.md §3).
                let rid_of = |req: &[u8]| -> Option<u64> {
                    let head = match req.iter().position(|c| *c == b'\n') {
                        Some(p) => &req[..p],
                        None => req,
                    };
                    let mut f = Fields { s: head };
                    match f.next()? {
                        b"SET" | b"DEL" => {
                            f.next()?;
                            f.next()?;
                            f.next()?;
                            parse_u64(f.next()?)
                        }
                        b"IMPORT" => {
                            f.next()?;
                            parse_u64(f.next()?)
                        }
                        _ => None,
                    }
                };
                // The reply, stored or built, is put on the stack; it is written after the close.
                let mut out_buf = [0u8; MSG_MAX];
                let mut reply_len = 0;
                let mut handled = false;
                if let Some(rid) = rid_of(&st.msg[..n]).filter(|r| *r != 0) {
                    if let Some(cached) = st.clients[ci].cache.iter().find(|e| e.rid == rid) {
                        reply_len = usize::from(cached.len);
                        out_buf[..reply_len].copy_from_slice(&cached.reply[..reply_len]);
                        handled = true;
                    }
                }
                if !handled {
                    // The request is copied out of the state so the handler may borrow the
                    // state mutably.
                    let mut req_copy = [0u8; MSG_MAX];
                    req_copy[..n].copy_from_slice(&st.msg[..n]);
                    let mut out = Out::new(&mut out_buf);
                    let keep = st.request(ci, &req_copy[..n], &mut handle, &mut out);
                    reply_len = out.len;
                    if let Some(rid) = keep.filter(|r| *r != 0) {
                        let l = reply_len.min(REPLY_MAX);
                        let mut reply = [0u8; REPLY_MAX];
                        reply[..l].copy_from_slice(&out_buf[..l]);
                        let cl = &mut st.clients[ci];
                        let slot = cl.next % RID_CACHE;
                        cl.cache[slot] = Cached {
                            rid,
                            reply,
                            len: l as u8,
                        };
                        cl.next += 1;
                    }
                }
                // The one exit for the handle the request carried (WP-107): a replay, a refusal
                // and a reply that cannot be written all leave it closed.
                if let Some(h) = handle.take() {
                    libnawah::handle_close(h);
                }
                let sent = libnawah::channel_write(c, &out_buf[..reply_len], &[]);
                if sent == ERR_PEER_CLOSED {
                    st.drop_client(ci);
                }
            }
            Err(ERR_PEER_CLOSED) => st.drop_client(ci),
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
}
