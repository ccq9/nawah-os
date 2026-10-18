//! dialog — the sample dialog of the accessibility tests (WP-36, ui.md): a label, a text
//! field, a list, a checkbox and two buttons built with libui, shown in a window of the
//! display service, driven by the keyboard events it forwards. Every element's description
//! goes to the narrator through the compositor at start (`tree k/n …`), and every focus move
//! or change after a key (`focus …`, `change …`, `activate …`, `cancel`). The text scale and
//! contrast come from the config service (`device` store, keys `ui.scale` and `ui.contrast`)
//! at start and on every change (SUBSCRIBE). Esc or a close request ends it (exit 0).
//!
//! Initial handle: the boot channel. Dependencies: `display`, `config`, `narrator`.

#![no_std]
#![no_main]

use libnawah::display::{Surface, FORMAT_RGBX};
use libnawah::{
    Handle, WaitEntry, ERR_PEER_CLOSED, ERR_SHOULD_WAIT, SIGNAL_PEER_CLOSED, SIGNAL_READABLE,
};
use libui::{Dialog, Event, Painter, Rect, Role, Text, Theme, MAX_ELEMENTS};
use nawah_text::font::Font;
use nawah_text::layout::Fonts;

libnawah::entry!(main);

const LANGS: &[&str] = &["English", "العربية", "Français"];
const LANGS_AR: &[&str] = &["الإنجليزية", "العربية", "الفرنسية"];
// The dialog's two languages, element by element (ui.md v1.2 / WP-39): title, label, field,
// list label, checkbox, two buttons. Switched live from `ui.lang` without rebuilding.
const EN: [&str; 7] = ["Sign in", "Sign in", "Name", "Language", "Remember me", "OK", "Cancel"];
const AR: [&str; 7] = ["دخول", "دخول", "الاسم", "اللغة", "تذكّرني", "موافق", "إلغاء"];
const MSG_MAX: usize = 512;
const PENDING: usize = 16;

static mut PAINTER: Painter = Painter::new();

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

/// A display channel whose events are kept while a request waits for its reply.
struct Display {
    chan: Handle,
    pending: [[u8; 128]; PENDING],
    pending_len: [usize; PENDING],
    head: usize,
    count: usize,
}

impl Display {
    fn request(&mut self, req: &[u8], handles: &[Handle], reply: &mut [u8]) -> Result<usize, i64> {
        if libnawah::channel_write(self.chan, req, handles) != 0 {
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
                        let k = n.min(128);
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

    fn next_pending(&mut self, out: &mut [u8; 128]) -> Option<usize> {
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

/// `GET device <key>` → the value (empty when absent).
fn config_get(cfg: Handle, key: &[u8], value: &mut [u8; 16]) -> usize {
    let mut req = Out::new();
    req.put(b"GET device ").put(key);
    if libnawah::channel_write(cfg, req.bytes(), &[]) != 0 {
        return 0;
    }
    let mut buf = [0u8; 128];
    let mut hs = [0u32; 1];
    let Ok((n, _)) = libnawah::channel_read(cfg, &mut buf, &mut hs, true) else {
        return 0;
    };
    // OK <version> <value>
    let reply = &buf[..n];
    let Some(rest) = reply.strip_prefix(b"OK ") else {
        return 0;
    };
    let Some(sp) = rest.iter().position(|&c| c == b' ') else {
        return 0;
    };
    let v = &rest[sp + 1..];
    let k = v.len().min(16);
    value[..k].copy_from_slice(&v[..k]);
    k
}

fn read_theme(cfg: Handle) -> Theme {
    let (mut s, mut c) = ([0u8; 16], [0u8; 16]);
    let ns = config_get(cfg, b"ui.scale", &mut s);
    let nc = config_get(cfg, b"ui.contrast", &mut c);
    Theme::from_config(&s[..ns], &c[..nc])
}

/// Switches the dialog's strings and direction (ui.md v1.2); no I/O, no announcement. The
/// six elements are: 0 label, 1 text field, 2 list, 3 checkbox, 4 OK, 5 Cancel.
fn set_dialog_lang(d: &mut Dialog, ar: bool) {
    let s = if ar { &AR } else { &EN };
    d.title = s[0];
    d.relabel(0, s[1]);
    d.relabel(1, s[2]);
    d.relabel(2, s[3]);
    d.set_items(2, if ar { LANGS_AR } else { LANGS });
    d.relabel(3, s[4]);
    d.relabel(4, s[5]);
    d.relabel(5, s[6]);
    d.set_rtl(ar);
}

struct App {
    boot: Handle,
    display: Display,
    format: u32,
    dialog: Dialog,
    fonts: Fonts<'static>,
    surface: Surface,
    sid: i64,
    wid: i64,
    rects: [Rect; MAX_ELEMENTS],
    painter: &'static mut Painter,
    /// Whether this window currently holds the focus; a FOCUS after a loss re-announces the
    /// focused element so the reader knows where it is (ui.md v1.2 / WP-39).
    focused: bool,
    /// The current language, so a repeated `ui.lang` change is a no-op.
    lang_ar: bool,
}

impl App {
    fn announce(&mut self, what: &[u8], element: Option<usize>) {
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
        let _ = self.display.request(req.bytes(), &[], &mut reply);
    }

    /// Paints the dialog into the surface (0xRRGGBB is the BGRX frame format; RGBX frames
    /// get their red and blue swapped) and commits it.
    fn repaint(&mut self) {
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
        let _ = self.display.request(req.bytes(), &[], &mut reply);
    }

    /// A surface of the dialog's current size, attached to the window (or the first one).
    fn make_surface(&mut self) -> bool {
        let (w, h) = self.dialog.layout(&mut self.rects);
        let Ok(s) = Surface::new(w as u32, h as u32, self.format) else {
            return false;
        };
        let Ok(share) = s.share() else {
            return false;
        };
        let mut req = Out::new();
        req.put(b"CREATE_SURFACE ")
            .num(w as i64)
            .put(b" ")
            .num(h as i64);
        let mut reply = [0u8; 64];
        let Ok(n) = self.display.request(req.bytes(), &[share], &mut reply) else {
            return false;
        };
        let Some(sid) = reply[..n].strip_prefix(b"OK ").and_then(parse_i64) else {
            return false;
        };
        let old = core::mem::replace(&mut self.surface, s);
        let old_sid = core::mem::replace(&mut self.sid, sid);
        if self.wid != 0 {
            let mut req = Out::new();
            req.put(b"ATTACH ").num(self.wid).put(b" ").num(sid);
            let _ = self.display.request(req.bytes(), &[], &mut reply);
            let mut req = Out::new();
            req.put(b"DESTROY_SURFACE ").num(old_sid);
            let _ = self.display.request(req.bytes(), &[], &mut reply);
        }
        if old.addr != 0 {
            old.destroy();
        }
        true
    }

    /// The window's client origin from LIST: `W <wid> <sid> <x> <y> <w> <h> …`.
    fn window_origin(&mut self) -> Option<(i64, i64)> {
        let mut reply = [0u8; MSG_MAX];
        let n = self.display.request(b"LIST", &[], &mut reply).ok()?;
        let line = reply[..n]
            .split(|&c| c == b'\n')
            .find(|l| l.starts_with(b"W "))?;
        let mut f = line.split(|&c| c == b' ').skip(3);
        Some((f.next().and_then(parse_i64)?, f.next().and_then(parse_i64)?))
    }

    /// `dialog|theme=<scale>,<contrast>|window=x,y,w,h|probe_bg=x,y|probe_focus=x,y` for the
    /// lab: a background pixel and a pixel of the focus ring, on the screen.
    fn report(&mut self) {
        let Some((x, y)) = self.window_origin() else {
            return;
        };
        let (w, h) = (self.surface.w as i64, self.surface.h as i64);
        let mut o = Out::new();
        o.put(b"dialog|theme=")
            .num(i64::from(self.dialog.theme.scale))
            .put(if self.dialog.theme.high_contrast {
                b",high"
            } else {
                b",normal"
            });
        o.put(b"|window=")
            .num(x)
            .put(b",")
            .num(y)
            .put(b",")
            .num(w)
            .put(b",")
            .num(h);
        o.put(b"|probe_bg=").num(x + 2).put(b",").num(y + 2);
        if let Some(f) = self.dialog.focused() {
            let r = self.rects[f];
            o.put(b"|probe_focus=")
                .num(x + i64::from(r.x + r.w / 2))
                .put(b",")
                .num(y + i64::from(r.y - 1));
        }
        libnawah::trace(o.bytes());
    }

    /// One key event from the display (`KEY <code> <down|up> <mods> <char>`); `false` ends.
    fn on_key(&mut self, msg: &[u8]) -> bool {
        let mut f = msg.split(|&c| c == b' ').filter(|x| !x.is_empty());
        let _ = f.next();
        let (Some(code), Some(dir), Some(mods)) = (
            f.next().and_then(parse_hex),
            f.next(),
            f.next().and_then(parse_i64),
        ) else {
            return true;
        };
        let ch_tok = f.next().unwrap_or(b"-");
        let ch = match ch_tok {
            b"space" => Some(' '),
            b"minus" => Some('-'),
            b"-" | b"enter" | b"tab" | b"backspace" => None,
            t => core::str::from_utf8(t).ok().and_then(|s| {
                let mut it = s.chars();
                let c = it.next()?;
                it.next().is_none().then_some(c)
            }),
        };
        let ev = self.dialog.key(code, dir == b"down", mods as u32, ch);
        match ev {
            Event::None => return true,
            Event::Focus(_, to) => self.announce(b"focus", Some(to)),
            Event::Toggle(i, _) | Event::Select(i, _) | Event::Edit(i) => {
                self.announce(b"change", Some(i))
            }
            Event::Activate(i) => self.announce(b"activate", Some(i)),
            Event::Cancel => {
                self.announce(b"cancel", None);
                return false;
            }
        }
        self.repaint();
        true
    }

    /// Switches language live from `ui.lang` (ui.md v1.2): new strings and direction, a renamed
    /// window, a repaint, and announcements of the switch and the focused element.
    fn set_lang(&mut self, ar: bool) {
        if self.lang_ar == ar {
            return;
        }
        self.lang_ar = ar;
        set_dialog_lang(&mut self.dialog, ar);
        let mut req = Out::new();
        req.put(b"TITLE ")
            .num(self.wid)
            .put(b" ")
            .put(self.dialog.title.as_bytes());
        let mut reply = [0u8; 64];
        let _ = self.display.request(req.bytes(), &[], &mut reply);
        self.repaint();
        self.report();
        self.announce(if ar { b"lang ar" } else { b"lang en" }, None);
        let f = self.dialog.focused();
        self.announce(b"focus", f);
    }

    fn on_display(&mut self, msg: &[u8]) -> bool {
        if msg.starts_with(b"KEY ") {
            return self.on_key(msg);
        }
        if msg.starts_with(b"UNFOCUS ") {
            self.focused = false;
        } else if msg.starts_with(b"FOCUS ") && !self.focused {
            // The window regained the focus: re-announce where the focus is (ui.md v1.2).
            self.focused = true;
            let f = self.dialog.focused();
            self.announce(b"focus", f);
        }
        !msg.starts_with(b"CLOSE_REQUESTED")
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
    let (Some(latin), Some(arabic)) = (
        load_font(b"/SYSTEM/FONTS/NOTOSANS.TTF").and_then(Font::parse),
        load_font(b"/SYSTEM/FONTS/NOTOARAB.TTF").and_then(Font::parse),
    ) else {
        return 0xE2;
    };
    let (Some(dchan), Some(cfg)) = (
        manager_connect(boot, b"display"),
        manager_connect(boot, b"config"),
    ) else {
        return 0xE3;
    };
    // Config changes arrive on a channel of our own.
    let Ok((sub_mine, sub_theirs)) = libnawah::channel_create() else {
        return 0xE4;
    };
    if libnawah::channel_write(cfg, b"SUBSCRIBE device", &[sub_theirs]) != 0 {
        return 0xE4;
    }
    match libnawah::channel_read(cfg, &mut buf, &mut hs, true) {
        Ok((2, _)) if &buf[..2] == b"OK" => {}
        _ => return 0xE4,
    }
    let mut dialog = Dialog::new("Sign in", false);
    let built = dialog.add(Role::Label, "Sign in").is_ok()
        && dialog.add(Role::TextField, "Name").is_ok()
        && dialog.add_list("Language", LANGS).is_ok()
        && dialog.add(Role::Checkbox, "Remember me").is_ok()
        && dialog.add(Role::Button, "OK").is_ok()
        && dialog.add(Role::Button, "Cancel").is_ok();
    if !built {
        return 0xE5;
    }
    dialog.theme = read_theme(cfg);
    // A saved `ui.lang=ar` makes the dialog start Arabic (silently: the tree below is then
    // announced in Arabic). The tests leave it unset at boot, so they start English.
    let mut lv = [0u8; 16];
    let lk = config_get(cfg, b"ui.lang", &mut lv);
    let lang_ar = &lv[..lk] == b"ar";
    if lang_ar {
        set_dialog_lang(&mut dialog, true);
    }
    let mut display = Display {
        chan: dchan,
        pending: [[0; 128]; PENDING],
        pending_len: [0; PENDING],
        head: 0,
        count: 0,
    };
    let mut reply = [0u8; MSG_MAX];
    let Ok(n) = display.request(b"STATUS", &[], &mut reply) else {
        return 0xE6;
    };
    let Some(i) = reply[..n].windows(7).position(|w| w == b"format=") else {
        return 0xE6;
    };
    let format = u32::from(reply[i + 7] - b'0');
    // SAFETY: the painter is taken once, here, for the life of the process.
    let painter: &'static mut Painter = unsafe { &mut *core::ptr::addr_of_mut!(PAINTER) };
    let mut app = App {
        boot,
        display,
        format,
        dialog,
        fonts: Fonts { latin, arabic },
        surface: Surface {
            vmo: 0,
            addr: 0,
            w: 0,
            h: 0,
            format,
        },
        sid: 0,
        wid: 0,
        rects: [Rect::default(); MAX_ELEMENTS],
        painter,
        focused: true,
        lang_ar,
    };
    if !app.make_surface() {
        return 0xE7;
    }
    let mut req = Out::new();
    req.put(b"CREATE_WINDOW ")
        .num(app.sid)
        .put(b" ")
        .put(app.dialog.title.as_bytes());
    let Ok(n) = app.display.request(req.bytes(), &[], &mut reply) else {
        return 0xE8;
    };
    let Some(wid) = reply[..n].strip_prefix(b"OK ").and_then(parse_i64) else {
        return 0xE8;
    };
    app.wid = wid;
    // The tree, in declared order, then the first focus.
    let count = app.dialog.len();
    for i in 0..count {
        let mut what = Out::new();
        what.put(b"tree ")
            .num(i as i64 + 1)
            .put(b"/")
            .num(count as i64);
        let w = what.bytes();
        let mut tmp = [0u8; 32];
        tmp[..w.len()].copy_from_slice(w);
        app.announce(&tmp[..w.len()], Some(i));
    }
    if let Event::Focus(_, to) = app.dialog.start() {
        app.announce(b"focus", Some(to));
    }
    app.repaint();
    app.report();
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE9;
    }
    loop {
        // Events kept while a request waited come first.
        let mut msg = [0u8; 128];
        while let Some(n) = app.display.next_pending(&mut msg) {
            if !app.on_display(&msg[..n]) {
                return 0;
            }
        }
        let entries = [
            WaitEntry {
                handle: app.boot,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            },
            WaitEntry {
                handle: app.display.chan,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            },
            WaitEntry {
                handle: sub_mine,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            },
        ];
        let Ok((idx, _)) = libnawah::object_wait_many(&entries, libnawah::TIMEOUT_FOREVER) else {
            return 0xEA;
        };
        let chan = entries[idx].handle;
        match libnawah::channel_read(chan, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                match idx {
                    0 => {
                        if &buf[..n] == b"STOP" {
                            return 0;
                        }
                    }
                    1 => {
                        let mut m = [0u8; MSG_MAX];
                        m[..n].copy_from_slice(&buf[..n]);
                        if !app.on_display(&m[..n]) {
                            return 0;
                        }
                    }
                    _ => {
                        // CHANGED device <key> <version>: a UI key changed the theme.
                        // Only the key that changed is read again, so two quick changes
                        // give two themes in their order.
                        if let Some(rest) = buf[..n].strip_prefix(b"CHANGED device ") {
                            let key = rest.split(|&c| c == b' ').next().unwrap_or(b"");
                            let mut theme = app.dialog.theme;
                            let mut v = [0u8; 16];
                            let k = config_get(cfg, key, &mut v);
                            if key == b"ui.lang" {
                                app.set_lang(&v[..k] == b"ar");
                                continue;
                            }
                            match key {
                                b"ui.scale" => theme.scale = Theme::from_config(&v[..k], b"").scale,
                                b"ui.contrast" => theme.high_contrast = &v[..k] == b"high",
                                _ => {}
                            }
                            if theme != app.dialog.theme {
                                app.dialog.theme = theme;
                                if app.make_surface() {
                                    app.repaint();
                                    let mut what = Out::new();
                                    what.put(b"theme scale=").num(i64::from(theme.scale)).put(
                                        if theme.high_contrast {
                                            b" contrast=high"
                                        } else {
                                            b" contrast=normal"
                                        },
                                    );
                                    let w = what.bytes();
                                    let mut tmp = [0u8; 48];
                                    tmp[..w.len()].copy_from_slice(w);
                                    app.announce(&tmp[..w.len()], None);
                                    app.report();
                                }
                            }
                        }
                    }
                }
            }
            Err(ERR_PEER_CLOSED) => return 0,
            Err(_) => {}
        }
    }
}
