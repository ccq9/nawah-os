//! inputd — the trusted input service (WP-33, input.md v2, ADR-0019 §4): decodes the
//! keyboard's set-1 scancodes into key events with a layout (US or Arabic 101) and the PS/2
//! mouse's packets into pointer events, and delivers them to one client only — the focus
//! owner named by whoever holds an ADMIN token (the session service in WP-37) — never to the
//! others. The secure attention sequence (Ctrl+Alt+Del) goes to the client registered as
//! `session` and to nobody else; the Delete that forms it is never reported, and (v2.2,
//! WP-37) the focus moves to the session with it, so the keys that follow are the session's.
//! The manager names every client (`CONNECT <service>`, services.md v1.6): only the service
//! `session` (or the controller) may register as `session`, and that service may move the
//! focus without a token.
//!
//! Initial handles: the boot channel (rdi), then the keyboard and the mouse objects (any
//! order, recognised by `handle_type`). Clients arrive through the manager (`CONNECT` on the
//! boot channel) and speak the requests of input.md §3.

#![no_std]
#![no_main]

use libnawah::{
    perm, Handle, WaitEntry, ERR_PEER_CLOSED, ERR_SHOULD_WAIT, SIGNAL_PEER_CLOSED, SIGNAL_READABLE,
};

libnawah::entry!(main);

const MAX_CLIENTS: usize = 8;
const NAME_MAX: usize = 16;
const MSG_MAX: usize = 256;

const MOD_SHIFT: u8 = 1;
const MOD_CTRL: u8 = 2;
const MOD_ALT: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    Us,
    Ar,
}

#[derive(Clone, Copy)]
struct Client {
    chan: Handle,
    id: u32,
    name: [u8; NAME_MAX],
    name_len: usize,
    /// Who the manager says the client is (services.md v1.6: the requesting service's
    /// name, `-` for the controller); empty when the manager did not say.
    ident: [u8; NAME_MAX],
    ident_len: usize,
}

const NO_CLIENT: Client = Client {
    chan: 0,
    id: 0,
    name: [0; NAME_MAX],
    name_len: 0,
    ident: [0; NAME_MAX],
    ident_len: 0,
};

impl Client {
    fn ident(&self) -> &[u8] {
        &self.ident[..self.ident_len]
    }
}

struct Input {
    kbd: Handle,
    mouse: Handle,
    clients: [Client; MAX_CLIENTS],
    next_id: u32,
    focus: Option<u32>,
    layout: Layout,
    mods: u8,
    extended: bool,
    /// Ctrl+Alt+Del was seen: the Delete break code that follows is swallowed.
    sak_pending: bool,
    /// Shift+Alt are held together with nothing else pressed since: releasing either one then
    /// toggles the layout (v2.3). Any other key press clears it, so a shortcut that carries
    /// Shift+Alt+key never switches the layout.
    combo_armed: bool,
    packet: [u8; 3],
    packet_len: usize,
    buttons: u8,
    keys: u64,
    packets: u64,
    dropped: u64,
    saks: u64,
}

struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Out<'_> {
    fn put(&mut self, s: &[u8]) {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
    fn num(&mut self, v: i64) {
        if v < 0 {
            self.put(b"-");
        }
        let mut v = v.unsigned_abs();
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
    fn hex(&mut self, v: u32) {
        self.put(b"0x");
        let digits = b"0123456789abcdef";
        let mut started = false;
        for shift in (0..8).rev() {
            let d = ((v >> (shift * 4)) & 0xF) as usize;
            if d != 0 || started || shift == 0 {
                started = true;
                self.put(&digits[d..d + 1]);
            }
        }
    }
}

/// US layout: (unshifted, shifted) ASCII for the set-1 make codes 0x02..=0x35, plus space.
fn us_char(code: u8, shift: bool) -> Option<char> {
    const ROW: &[(u8, u8, u8)] = &[
        (0x02, b'1', b'!'),
        (0x03, b'2', b'@'),
        (0x04, b'3', b'#'),
        (0x05, b'4', b'$'),
        (0x06, b'5', b'%'),
        (0x07, b'6', b'^'),
        (0x08, b'7', b'&'),
        (0x09, b'8', b'*'),
        (0x0A, b'9', b'('),
        (0x0B, b'0', b')'),
        (0x0C, b'-', b'_'),
        (0x0D, b'=', b'+'),
        (0x0E, 0x08, 0x08),
        (0x0F, b'\t', b'\t'),
        (0x10, b'q', b'Q'),
        (0x11, b'w', b'W'),
        (0x12, b'e', b'E'),
        (0x13, b'r', b'R'),
        (0x14, b't', b'T'),
        (0x15, b'y', b'Y'),
        (0x16, b'u', b'U'),
        (0x17, b'i', b'I'),
        (0x18, b'o', b'O'),
        (0x19, b'p', b'P'),
        (0x1A, b'[', b'{'),
        (0x1B, b']', b'}'),
        (0x1C, b'\n', b'\n'),
        (0x1E, b'a', b'A'),
        (0x1F, b's', b'S'),
        (0x20, b'd', b'D'),
        (0x21, b'f', b'F'),
        (0x22, b'g', b'G'),
        (0x23, b'h', b'H'),
        (0x24, b'j', b'J'),
        (0x25, b'k', b'K'),
        (0x26, b'l', b'L'),
        (0x27, b';', b':'),
        (0x28, b'\'', b'"'),
        (0x29, b'`', b'~'),
        (0x2B, b'\\', b'|'),
        (0x2C, b'z', b'Z'),
        (0x2D, b'x', b'X'),
        (0x2E, b'c', b'C'),
        (0x2F, b'v', b'V'),
        (0x30, b'b', b'B'),
        (0x31, b'n', b'N'),
        (0x32, b'm', b'M'),
        (0x33, b',', b'<'),
        (0x34, b'.', b'>'),
        (0x35, b'/', b'?'),
        (0x39, b' ', b' '),
    ];
    ROW.iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, u, s)| char::from(if shift { *s } else { *u }))
}

/// Arabic (101) layout: the letters on the three letter rows and the symbol keys, unshifted;
/// digits and the Enter/Tab/Backspace/Space keys as in the US layout. Shift states of the
/// letter keys (tashkeel and the Arabic punctuation) are not provided in v2 (input.md).
fn ar_char(code: u8, shift: bool) -> Option<char> {
    const ROW: &[(u8, char)] = &[
        (0x29, 'ذ'),
        (0x10, 'ض'),
        (0x11, 'ص'),
        (0x12, 'ث'),
        (0x13, 'ق'),
        (0x14, 'ف'),
        (0x15, 'غ'),
        (0x16, 'ع'),
        (0x17, 'ه'),
        (0x18, 'خ'),
        (0x19, 'ح'),
        (0x1A, 'ج'),
        (0x1B, 'د'),
        (0x1E, 'ش'),
        (0x1F, 'س'),
        (0x20, 'ي'),
        (0x21, 'ب'),
        (0x22, 'ل'),
        (0x23, 'ا'),
        (0x24, 'ت'),
        (0x25, 'ن'),
        (0x26, 'م'),
        (0x27, 'ك'),
        (0x28, 'ط'),
        (0x2C, 'ئ'),
        (0x2D, 'ء'),
        (0x2E, 'ؤ'),
        (0x2F, 'ر'),
        (0x31, 'ى'),
        (0x32, 'ة'),
        (0x33, 'و'),
        (0x34, 'ز'),
        (0x35, 'ظ'),
    ];
    if let Some((_, c)) = ROW.iter().find(|(c, _)| *c == code) {
        return if shift { None } else { Some(*c) };
    }
    // Digits, punctuation of the number row, Enter, Tab, Backspace, Space: as the US layout.
    if (0x02..=0x0F).contains(&code) || code == 0x1C || code == 0x39 {
        return us_char(code, shift);
    }
    None
}

impl Input {
    fn client_by_id(&self, id: u32) -> Option<usize> {
        (0..MAX_CLIENTS).find(|&i| self.clients[i].chan != 0 && self.clients[i].id == id)
    }

    fn client_by_name(&self, name: &[u8]) -> Option<usize> {
        (0..MAX_CLIENTS).find(|&i| {
            let c = &self.clients[i];
            c.chan != 0 && &c.name[..c.name_len] == name
        })
    }

    fn session_client(&self) -> Option<usize> {
        self.client_by_name(b"session")
    }

    /// Delivers one event to client `ci`; a full queue drops it (counted), a closed peer
    /// forgets the client.
    fn deliver(&mut self, ci: usize, msg: &[u8]) {
        let c = self.clients[ci].chan;
        if c == 0 {
            return;
        }
        match libnawah::channel_write(c, msg, &[]) {
            0 => {}
            ERR_PEER_CLOSED => self.forget(ci),
            _ => self.dropped += 1,
        }
    }

    fn forget(&mut self, ci: usize) {
        let c = self.clients[ci];
        if c.chan != 0 {
            libnawah::handle_close(c.chan);
        }
        if self.focus == Some(c.id) {
            self.focus = None;
        }
        // The session went away (crash or restart): nobody gets keys until it is back
        // (input.md v2.2), so a client focused before cannot receive a password typed for
        // the restarted session.
        if &c.name[..c.name_len] == b"session" {
            self.focus = None;
        }
        self.clients[ci] = NO_CLIENT;
    }

    fn deliver_to_focus(&mut self, msg: &[u8]) {
        match self.focus.and_then(|id| self.client_by_id(id)) {
            Some(ci) => self.deliver(ci, msg),
            None => self.dropped += 1,
        }
    }

    /// `LAYOUT us`/`LAYOUT ar` to the current focus owner (v2.3): the layout is not authority,
    /// only news, so the owner learns the writing direction without a token.
    fn announce_layout(&mut self) {
        let msg: &[u8] = match self.layout {
            Layout::Us => b"LAYOUT us",
            Layout::Ar => b"LAYOUT ar",
        };
        self.deliver_to_focus(msg);
    }

    fn toggle_layout(&mut self) {
        self.layout = match self.layout {
            Layout::Us => Layout::Ar,
            Layout::Ar => Layout::Us,
        };
        self.announce_layout();
    }

    /// One scancode byte from the keyboard.
    fn on_scancode(&mut self, b: u8) {
        if b == 0xE0 {
            self.extended = true;
            return;
        }
        let extended = core::mem::replace(&mut self.extended, false);
        let down = b & 0x80 == 0;
        let base = b & 0x7F;
        let code = if extended { 0x80 | base } else { base };
        // Modifiers (left and right): the state after this key.
        let bit = match (extended, base) {
            (false, 0x2A) | (false, 0x36) => MOD_SHIFT,
            (_, 0x1D) => MOD_CTRL,
            (_, 0x38) => MOD_ALT,
            _ => 0,
        };
        if bit != 0 {
            if down {
                self.mods |= bit;
                // Armed when exactly Shift+Alt are now held (the second of the pair arms it);
                // a third modifier (Ctrl) makes the mask differ, so it disarms.
                self.combo_armed = self.mods == (MOD_SHIFT | MOD_ALT);
            } else {
                self.mods &= !bit;
                // Releasing either half of an armed Shift+Alt toggles the layout (v2.3). The
                // released modifier is still reported as a key below; the LAYOUT event precedes
                // it to the focus owner.
                if self.combo_armed && (bit == MOD_SHIFT || bit == MOD_ALT) {
                    self.combo_armed = false;
                    self.toggle_layout();
                }
            }
        } else if down {
            // A real key press: not a clean Shift+Alt sequence.
            self.combo_armed = false;
        }
        // Secure attention: Ctrl+Alt+Del (Delete is E0 53). Never reported as a key.
        if extended && base == 0x53 {
            if down && self.mods & (MOD_CTRL | MOD_ALT) == MOD_CTRL | MOD_ALT {
                self.sak_pending = true;
                self.saks += 1;
                if let Some(s) = self.session_client() {
                    // v2.2: the session owns the keyboard from here (the releases of Ctrl
                    // and Alt included) until it names another owner — a window that
                    // imitates the sign-in screen never sees the sequence or what follows.
                    self.focus = Some(self.clients[s].id);
                    self.deliver(s, b"SAK");
                }
                return;
            }
            if !down && core::mem::replace(&mut self.sak_pending, false) {
                return;
            }
        }
        self.keys += 1;
        let ch = if extended {
            None
        } else {
            match self.layout {
                Layout::Us => us_char(base, self.mods & MOD_SHIFT != 0),
                Layout::Ar => ar_char(base, self.mods & MOD_SHIFT != 0),
            }
        };
        let mut buf = [0u8; 64];
        let len = {
            let mut o = Out {
                buf: &mut buf,
                len: 0,
            };
            o.put(b"KEY ");
            o.hex(u32::from(code));
            o.put(if down { b" down " } else { b" up " });
            o.num(i64::from(self.mods));
            o.put(b" ");
            match ch {
                // v2.2: `-` means "no character", so the minus character has a name of its
                // own (WP-37: a password with a minus could not be typed).
                Some('-') => o.put(b"minus"),
                Some(c) if c != '\n' && c != '\t' && c != '\x08' && c != ' ' => {
                    let mut utf8 = [0u8; 4];
                    o.put(c.encode_utf8(&mut utf8).as_bytes());
                }
                Some('\n') => o.put(b"enter"),
                Some('\t') => o.put(b"tab"),
                Some('\x08') => o.put(b"backspace"),
                Some(' ') => o.put(b"space"),
                _ => o.put(b"-"),
            }
            o.len
        };
        self.deliver_to_focus(&buf[..len]);
    }

    /// One byte of the mouse's stream: packets of three, re-synchronised on bit 3 of the
    /// first byte (always set in a PS/2 packet's first byte).
    fn on_mouse_byte(&mut self, b: u8) {
        if self.packet_len == 0 && b & 0x08 == 0 {
            return; // not a first byte: stay in sync
        }
        self.packet[self.packet_len] = b;
        self.packet_len += 1;
        if self.packet_len < 3 {
            return;
        }
        self.packet_len = 0;
        let [flags, x, y] = self.packet;
        self.packets += 1;
        if flags & 0xC0 != 0 {
            return; // overflow: the packet is unusable
        }
        let dx = i32::from(x) - if flags & 0x10 != 0 { 256 } else { 0 };
        // PS/2 reports y upwards; the screen's y grows downwards.
        let dy = -(i32::from(y) - if flags & 0x20 != 0 { 256 } else { 0 });
        self.buttons = flags & 0x07;
        let mut buf = [0u8; 48];
        let len = {
            let mut o = Out {
                buf: &mut buf,
                len: 0,
            };
            o.put(b"PTR ");
            o.num(i64::from(dx));
            o.put(b" ");
            o.num(i64::from(dy));
            o.put(b" ");
            o.num(i64::from(self.buttons));
            o.len
        };
        self.deliver_to_focus(&buf[..len]);
    }

    /// One request from client `ci`.
    fn request(&mut self, ci: usize, req: &[u8], token: Option<Handle>, out: &mut Out) {
        let mut fields = req.split(|c| *c == b' ').filter(|f| !f.is_empty());
        let verb = fields.next().unwrap_or(b"");
        let admin = token.is_some_and(|t| {
            libnawah::token_info(t).is_ok_and(|i| i.usable() && i.perms & perm::ADMIN != 0)
        });
        // The session service itself needs no token (input.md v2.2): the manager vouches
        // for its identity.
        let session = self.clients[ci].ident() == b"session";
        let admin = admin || session;
        match verb {
            b"REGISTER" => {
                let Some(name) = fields.next().filter(|n| n.len() <= NAME_MAX) else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                // `session` is reserved (input.md v2.2): only the session service or the
                // controller may take the name that receives the secure attention sequence.
                if name == b"session" && !matches!(self.clients[ci].ident(), b"session" | b"-") {
                    out.put(b"ERR ACCESS");
                    return;
                }
                let c = &mut self.clients[ci];
                c.name[..name.len()].copy_from_slice(name);
                c.name_len = name.len();
                out.put(b"OK ");
                out.num(i64::from(c.id));
            }
            b"FOCUS" => {
                // By id, or (v2.1, WP-34) by registered name.
                let Some(target) = fields.next() else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                if !admin {
                    out.put(b"ERR ACCESS");
                    return;
                }
                let found = match parse_u32(target) {
                    Some(id) => self.client_by_id(id),
                    None => self.client_by_name(target),
                };
                let Some(ci) = found else {
                    out.put(b"ERR UNKNOWN");
                    return;
                };
                self.focus = Some(self.clients[ci].id);
                out.put(b"OK");
            }
            b"LAYOUT" => {
                let layout = match fields.next() {
                    Some(b"us") => Layout::Us,
                    Some(b"ar") => Layout::Ar,
                    _ => {
                        out.put(b"ERR BAD_REQUEST");
                        return;
                    }
                };
                if !admin {
                    out.put(b"ERR ACCESS");
                    return;
                }
                if self.layout != layout {
                    self.layout = layout;
                    self.announce_layout();
                }
                out.put(b"OK");
            }
            b"STATUS" => {
                out.put(b"OK focus=");
                match self.focus {
                    Some(id) => out.num(i64::from(id)),
                    None => out.put(b"-"),
                }
                out.put(b" layout=");
                out.put(match self.layout {
                    Layout::Us => b"us",
                    Layout::Ar => b"ar",
                });
                out.put(b" keys=");
                out.num(self.keys as i64);
                out.put(b" packets=");
                out.num(self.packets as i64);
                out.put(b" saks=");
                out.num(self.saks as i64);
                out.put(b" dropped=");
                out.num(self.dropped as i64);
                out.put(b" buttons=");
                out.num(i64::from(self.buttons));
            }
            _ => out.put(b"ERR BAD_REQUEST"),
        }
    }
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 9 {
        return None;
    }
    let mut v = 0u32;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    Some(v)
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let (mut kbd, mut mouse) = (0, 0);
    for h in boot + 1..boot + 3 {
        match libnawah::handle_type(h) {
            libnawah::object_type::KEYBOARD => kbd = h,
            libnawah::object_type::MOUSE => mouse = h,
            _ => {}
        }
    }
    if kbd == 0 || mouse == 0 {
        return 0xE1;
    }
    let mut hs = [0u32; 1];
    let mut buf = [0u8; MSG_MAX];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((n, _)) if buf[..n].starts_with(b"START") => {}
        _ => return 0xE3,
    }
    let mut st = Input {
        kbd,
        mouse,
        clients: [NO_CLIENT; MAX_CLIENTS],
        next_id: 1,
        focus: None,
        layout: Layout::Us,
        mods: 0,
        extended: false,
        sak_pending: false,
        combo_armed: false,
        packet: [0; 3],
        packet_len: 0,
        buttons: 0,
        keys: 0,
        packets: 0,
        dropped: 0,
        saks: 0,
    };
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE4;
    }
    loop {
        let mut entries = [WaitEntry {
            handle: 0,
            signals: 0,
        }; 3 + MAX_CLIENTS];
        entries[0] = WaitEntry {
            handle: boot,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        };
        entries[1] = WaitEntry {
            handle: st.kbd,
            signals: SIGNAL_READABLE,
        };
        entries[2] = WaitEntry {
            handle: st.mouse,
            signals: SIGNAL_READABLE,
        };
        let mut owner = [0usize; 3 + MAX_CLIENTS];
        let mut k = 3;
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
        let Ok((idx, _)) = libnawah::object_wait_many(&entries[..k], libnawah::TIMEOUT_FOREVER)
        else {
            return 0xE5;
        };
        match idx {
            0 => match libnawah::channel_read(boot, &mut buf, &mut hs, false) {
                Ok((n, nh)) => {
                    if (buf[..n] == *b"CONNECT" || buf[..n].starts_with(b"CONNECT ")) && nh == 1 {
                        match st.clients.iter().position(|c| c.chan == 0) {
                            Some(slot) => {
                                let who = buf[..n].strip_prefix(b"CONNECT ").unwrap_or(b"");
                                let k = who.len().min(NAME_MAX);
                                let mut ident = [0u8; NAME_MAX];
                                ident[..k].copy_from_slice(&who[..k]);
                                st.clients[slot] = Client {
                                    chan: hs[0],
                                    id: st.next_id,
                                    name: [0; NAME_MAX],
                                    name_len: 0,
                                    ident,
                                    ident_len: k,
                                };
                                st.next_id += 1;
                            }
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
            },
            1 => {
                let mut bytes = [0u8; 64];
                match libnawah::kbd_read(st.kbd, &mut bytes) {
                    Ok(n) => {
                        for &b in &bytes[..n] {
                            st.on_scancode(b);
                        }
                    }
                    Err(ERR_SHOULD_WAIT) => {}
                    Err(_) => return 0xE6,
                }
            }
            2 => {
                let mut bytes = [0u8; 192];
                match libnawah::mouse_read(st.mouse, &mut bytes) {
                    Ok(n) => {
                        for &b in &bytes[..n] {
                            st.on_mouse_byte(b);
                        }
                    }
                    Err(ERR_SHOULD_WAIT) => {}
                    Err(_) => return 0xE7,
                }
            }
            _ => {
                let ci = owner[idx];
                let c = st.clients[ci].chan;
                match libnawah::channel_read(c, &mut buf, &mut hs, false) {
                    Ok((n, nh)) => {
                        let token = if nh == 1 { Some(hs[0]) } else { None };
                        let mut req = [0u8; MSG_MAX];
                        req[..n].copy_from_slice(&buf[..n]);
                        let mut out_buf = [0u8; MSG_MAX];
                        let mut out = Out {
                            buf: &mut out_buf,
                            len: 0,
                        };
                        st.request(ci, &req[..n], token, &mut out);
                        if let Some(t) = token {
                            libnawah::handle_close(t);
                        }
                        let len = out.len;
                        if libnawah::channel_write(c, &out_buf[..len], &[]) == ERR_PEER_CLOSED {
                            st.forget(ci);
                        }
                    }
                    Err(ERR_PEER_CLOSED) => st.forget(ci),
                    Err(_) => {}
                }
            }
        }
    }
}
