//! displayd — the compositor and window manager (WP-34, display.md §ب, ADR-0019 §3): clients
//! hand it surfaces (VMOs of pixels) and it composes their windows, with decorations, into a
//! back buffer, then copies the changed parts to the frame at most every BLIT_PERIOD ticks.
//! It never waits on a client: events are written without blocking and dropped (counted) when
//! a client's queue is full; a client whose queue stays full for HANG_TICKS is marked
//! unresponsive. Keys and pointer packets come from the input service, whose focus owner this
//! service is whenever the session says so (input.md §3).
//!
//! Initial handles: the boot channel (rdi) and the display object. Dependency: `input`.
//! Since WP-36 (display.md v1.1): titles drawn as text with the shipped fonts, and a narrator
//! client that hears the focused window's accessibility announcements.

#![no_std]
#![no_main]

use libnawah::display::pixel;
use libnawah::{
    Handle, WaitEntry, ERR_PEER_CLOSED, ERR_SHOULD_WAIT, ERR_TIMED_OUT, SIGNAL_PEER_CLOSED,
    SIGNAL_READABLE,
};
use nawah_text::bidi::{self, Base};
use nawah_text::font::Font;
use nawah_text::layout::{Canvas, Fonts, Glyph, Layout};

libnawah::entry!(main);

const MAX_CLIENTS: usize = 8;
const MAX_SURFACES: usize = 32;
const MAX_WINDOWS: usize = 16;
const MAX_PIXELS: usize = 2 * 1024 * 1024;
const TITLE_MAX: usize = 32;
const MSG_MAX: usize = 1024;

const BORDER: i32 = 1;
const TITLE_H: i32 = 24;
const BTN: i32 = 20;
const GRIP: i32 = 12;
const ORIGIN: i32 = 20;
const CASCADE: i32 = 40;
const MIN_SIZE: i32 = 32;
const MAX_SIZE: i32 = 4096;
const KEY_STEP: i32 = 16;
const CURSOR: i32 = 9;

const BLIT_PERIOD: u64 = 16;
const HANG_TICKS: u64 = 2000;
const HANG_POLL: u64 = 100;

const BG: u32 = 0x1E2A38;
const EMPTY: u32 = 0x404850;
const BORDER_RGB: u32 = 0x202020;
const TITLE_FOCUS: u32 = 0x3A6EA5;
const TITLE_BLUR: u32 = 0x6B7B8C;
const TITLE_HANG: u32 = 0xB03030;
const BTN_CLOSE: u32 = 0xD9534F;
const BTN_MIN: u32 = 0xF0AD4E;
const GRIP_RGB: u32 = 0xC0C8D0;
const CURSOR_RGB: u32 = 0xFFFFFF;
const CURSOR_EDGE: u32 = 0x000000;

const MOD_SHIFT: u32 = 1;
const MOD_ALT: u32 = 4;
const KEY_TAB: u32 = 0x0f;
const KEY_F4: u32 = 0x3e;
const KEY_UP: u32 = 0xc8;
const KEY_DOWN: u32 = 0xd0;
const KEY_LEFT: u32 = 0xcb;
const KEY_RIGHT: u32 = 0xcd;

/// The back buffer: taken once by `main`, never aliased afterwards.
static mut BACK: [u32; MAX_PIXELS] = [0; MAX_PIXELS];

/// Window titles as text (WP-36, display.md v1.1): the layout state, taken once by `main`.
struct TextState {
    layout: Layout,
    glyphs: [Glyph; TITLE_MAX],
    chars: [u32; TITLE_MAX],
}

static mut TEXT: TextState = TextState {
    layout: Layout::new(),
    glyphs: [Glyph {
        font: 0,
        gid: 0,
        x: 0,
        advance: 0,
        cluster: 0,
    }; TITLE_MAX],
    chars: [0; TITLE_MAX],
};

const TITLE_PX: u32 = 13;
const TITLE_RGB: u32 = 0xFFFFFF;

/// The frame's pixel back to `0xRRGGBB` (the inverse of `pixel`).
fn unpixel(format: u32, p: u32) -> u32 {
    let (a, g, b) = (p & 0xFF, (p >> 8) & 0xFF, (p >> 16) & 0xFF);
    if format == libnawah::display::FORMAT_RGBX {
        (a << 16) | (g << 8) | b
    } else {
        p & 0xFF_FFFF
    }
}

/// Blends glyph coverage into the back buffer (frame format) inside `clip`.
struct BackCanvas<'b> {
    back: &'b mut [u32],
    sw: usize,
    clip: Rect,
    format: u32,
    fg: u32,
}

impl Canvas for BackCanvas<'_> {
    fn blend(&mut self, x: i32, y: i32, coverage: u8) {
        if !self.clip.contains(x, y) {
            return;
        }
        let i = y as usize * self.sw + x as usize;
        let old = unpixel(self.format, self.back[i]);
        let c = u32::from(coverage.min(16));
        let mut rgb = 0;
        for shift in [16u32, 8, 0] {
            let (o, f) = ((old >> shift) & 0xFF, (self.fg >> shift) & 0xFF);
            rgb |= ((o * (16 - c) + f * c + 8) / 16) << shift;
        }
        self.back[i] = pixel(self.format, rgb);
    }
}

/// Reads a font file into a fresh VMO mapping (kept for the life of the process).
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

/// UTF-8 to code points (malformed bytes are skipped).
fn decode_utf8(bytes: &[u8], out: &mut [u32]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < bytes.len() && n < out.len() {
        let b = bytes[i];
        let (len, init) = match b {
            0x00..=0x7F => (1, u32::from(b)),
            0xC0..=0xDF => (2, u32::from(b & 0x1F)),
            0xE0..=0xEF => (3, u32::from(b & 0x0F)),
            0xF0..=0xF7 => (4, u32::from(b & 0x07)),
            _ => {
                i += 1;
                continue;
            }
        };
        if i + len > bytes.len() {
            break;
        }
        let mut cp = init;
        let mut ok = true;
        for &c in &bytes[i + 1..i + len] {
            if c & 0xC0 != 0x80 {
                ok = false;
                break;
            }
            cp = (cp << 6) | u32::from(c & 0x3F);
        }
        i += if ok { len } else { 1 };
        if ok {
            out[n] = cp;
            n += 1;
        }
    }
    n
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Rect {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

impl Rect {
    const NONE: Rect = Rect {
        x: 0,
        y: 0,
        w: 0,
        h: 0,
    };
    fn new(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }
    fn is_empty(self) -> bool {
        self.w <= 0 || self.h <= 0
    }
    fn x1(self) -> i32 {
        self.x + self.w
    }
    fn y1(self) -> i32 {
        self.y + self.h
    }
    fn intersect(self, o: Rect) -> Rect {
        let (x, y) = (self.x.max(o.x), self.y.max(o.y));
        let (x1, y1) = (self.x1().min(o.x1()), self.y1().min(o.y1()));
        if x1 <= x || y1 <= y {
            Rect::NONE
        } else {
            Rect::new(x, y, x1 - x, y1 - y)
        }
    }
    fn union(self, o: Rect) -> Rect {
        if self.is_empty() {
            return o;
        }
        if o.is_empty() {
            return self;
        }
        let (x, y) = (self.x.min(o.x), self.y.min(o.y));
        Rect::new(x, y, self.x1().max(o.x1()) - x, self.y1().max(o.y1()) - y)
    }
    fn contains(self, px: i32, py: i32) -> bool {
        px >= self.x && py >= self.y && px < self.x1() && py < self.y1()
    }
}

#[derive(Clone, Copy)]
struct Client {
    chan: Handle,
    full_since: Option<u64>,
    unresponsive: bool,
    dropped: u64,
}

const NO_CLIENT: Client = Client {
    chan: 0,
    full_since: None,
    unresponsive: false,
    dropped: 0,
};

#[derive(Clone, Copy)]
struct Surface {
    used: bool,
    owner: usize,
    id: u32,
    vmo: Handle,
    addr: u64,
    w: i32,
    h: i32,
}

const NO_SURFACE: Surface = Surface {
    used: false,
    owner: 0,
    id: 0,
    vmo: 0,
    addr: 0,
    w: 0,
    h: 0,
};

#[derive(Clone, Copy)]
struct Window {
    used: bool,
    owner: usize,
    id: u32,
    surface: Option<usize>,
    /// The client area on the screen.
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    minimized: bool,
    title: [u8; TITLE_MAX],
    title_len: usize,
}

const NO_WINDOW: Window = Window {
    used: false,
    owner: 0,
    id: 0,
    surface: None,
    x: 0,
    y: 0,
    w: 0,
    h: 0,
    minimized: false,
    title: [0; TITLE_MAX],
    title_len: 0,
};

impl Window {
    fn client(&self) -> Rect {
        Rect::new(self.x, self.y, self.w, self.h)
    }
    fn outer(&self) -> Rect {
        Rect::new(
            self.x - BORDER,
            self.y - BORDER - TITLE_H,
            self.w + 2 * BORDER,
            self.h + 2 * BORDER + TITLE_H,
        )
    }
    fn title_bar(&self) -> Rect {
        Rect::new(self.x, self.y - TITLE_H, self.w, TITLE_H)
    }
    fn close_btn(&self) -> Rect {
        Rect::new(self.x + self.w - BTN - 2, self.y - TITLE_H + 2, BTN, BTN)
    }
    fn min_btn(&self) -> Rect {
        Rect::new(
            self.x + self.w - 2 * BTN - 4,
            self.y - TITLE_H + 2,
            BTN,
            BTN,
        )
    }
    fn grip(&self) -> Rect {
        Rect::new(self.x + self.w - GRIP, self.y + self.h - GRIP, GRIP, GRIP)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DragMode {
    Move,
    Resize,
}

#[derive(Clone, Copy)]
struct Drag {
    win: usize,
    mode: DragMode,
    /// Pointer offset from the window's client origin (move) or the size at press (resize).
    ax: i32,
    ay: i32,
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
    fn hex64(&mut self, v: u64) {
        let digits = b"0123456789abcdef";
        let mut tmp = [0u8; 16];
        for (i, d) in tmp.iter_mut().enumerate() {
            *d = digits[((v >> (60 - 4 * i)) & 0xF) as usize];
        }
        self.put(&tmp);
    }
}

fn parse_i32(s: &[u8]) -> Option<i32> {
    let (neg, digits) = match s.strip_prefix(b"-") {
        Some(d) => (true, d),
        None => (false, s),
    };
    if digits.is_empty() || digits.len() > 9 {
        return None;
    }
    let mut v: i32 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + i32::from(c - b'0');
    }
    Some(if neg { -v } else { v })
}

/// The text after the first `n` space-separated fields, trimmed.
fn after_fields(req: &[u8], n: usize) -> &[u8] {
    let mut i = 0;
    let mut seen = 0;
    while seen < n && i < req.len() {
        while i < req.len() && req[i] == b' ' {
            i += 1;
        }
        while i < req.len() && req[i] != b' ' {
            i += 1;
        }
        seen += 1;
    }
    req[i.min(req.len())..].trim_ascii()
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    parse_i32(s).filter(|v| *v >= 0).map(|v| v as u32)
}

/// Hex `0x…` or decimal.
fn parse_code(s: &[u8]) -> Option<u32> {
    if let Some(h) = s.strip_prefix(b"0x") {
        let mut v = 0u32;
        if h.is_empty() || h.len() > 8 {
            return None;
        }
        for &c in h {
            let d = (c as char).to_digit(16)?;
            v = (v << 4) | d;
        }
        Some(v)
    } else {
        parse_u32(s)
    }
}

struct Compositor {
    boot: Handle,
    input: Handle,
    fb: u64,
    stride: usize,
    format: u32,
    screen: Rect,
    back: &'static mut [u32],
    clients: [Client; MAX_CLIENTS],
    surfaces: [Surface; MAX_SURFACES],
    windows: [Window; MAX_WINDOWS],
    /// Window slots from the top of the stack downwards.
    order: [usize; MAX_WINDOWS],
    n_order: usize,
    next_id: u32,
    created: u32,
    focus: Option<usize>,
    px: i32,
    py: i32,
    buttons: u32,
    drag: Option<Drag>,
    cursor_rect: Rect,
    dirty: Rect,
    last_blit: u64,
    composed: u64,
    unresponsive: u32,
    /// A key whose press was a shortcut: its release is swallowed too, so no client sees
    /// half of it.
    consumed_key: Option<u32>,
    /// The narrator client (display.md v1.1 §ب-1): announcements of the focused window go
    /// to it.
    narrator: Option<usize>,
    fonts: Option<Fonts<'static>>,
    text: &'static mut TextState,
}

impl Compositor {
    // ---- pixels -------------------------------------------------------------------------

    fn rgb(&self, rgb: u32) -> u32 {
        pixel(self.format, rgb)
    }

    fn fill_back(&mut self, r: Rect, rgb: u32) {
        let r = r.intersect(self.screen);
        if r.is_empty() {
            return;
        }
        let px = self.rgb(rgb);
        let w = self.screen.w as usize;
        for y in r.y..r.y1() {
            let row = y as usize * w;
            self.back[row + r.x as usize..row + r.x1() as usize].fill(px);
        }
    }

    /// Copies the surface's pixels into the back buffer for the part of the window's client
    /// area inside `clip`.
    fn draw_surface(&mut self, wi: usize, clip: Rect) {
        let win = self.windows[wi];
        let area = win.client().intersect(clip).intersect(self.screen);
        if area.is_empty() {
            return;
        }
        let Some(si) = win.surface else {
            self.fill_back(area, EMPTY);
            return;
        };
        let s = self.surfaces[si];
        let sw = self.screen.w as usize;
        let sx0 = area.x - win.x;
        if sx0 >= s.w {
            return;
        }
        // A window larger than its surface (between RESIZE and ATTACH) shows the surface's
        // part only; the rest keeps the background.
        let n = area.w.min(s.w - sx0) as usize;
        for y in area.y..area.y1() {
            let sy = y - win.y;
            if sy >= s.h {
                break;
            }
            let src = (s.addr as *const u32).wrapping_add((sy * s.w + sx0) as usize);
            let row = y as usize * sw + area.x as usize;
            // SAFETY: `src..src+n` lies inside the surface mapping (`sy < h`, `sx0+n <= w`,
            // both checked above); the destination is a slice of the back buffer.
            unsafe { core::ptr::copy_nonoverlapping(src, self.back[row..row + n].as_mut_ptr(), n) };
        }
    }

    fn draw_window(&mut self, wi: usize, clip: Rect) {
        let win = self.windows[wi];
        let outer = win.outer().intersect(clip);
        if outer.is_empty() {
            return;
        }
        let hang = self.clients[win.owner].unresponsive;
        let title = if hang {
            TITLE_HANG
        } else if self.focus == Some(wi) {
            TITLE_FOCUS
        } else {
            TITLE_BLUR
        };
        self.fill_back(win.outer().intersect(clip), BORDER_RGB);
        self.fill_back(win.title_bar().intersect(clip), title);
        self.fill_back(win.close_btn().intersect(clip), BTN_CLOSE);
        self.fill_back(win.min_btn().intersect(clip), BTN_MIN);
        self.draw_title(wi, clip);
        self.draw_surface(wi, clip);
        self.fill_back(win.grip().intersect(clip), GRIP_RGB);
    }

    /// The window's title as text in its title bar (left of the buttons; right-aligned when
    /// the title's first strong character is right-to-left, UAX #9 P2).
    fn draw_title(&mut self, wi: usize, clip: Rect) {
        let Some(fonts) = self.fonts.as_ref() else {
            return;
        };
        let win = self.windows[wi];
        let bar = win.title_bar();
        let area = Rect::new(bar.x + 4, bar.y, win.min_btn().x - 4 - (bar.x + 4), bar.h);
        let area = area.intersect(clip).intersect(self.screen);
        if area.is_empty() {
            return;
        }
        let text = &mut *self.text;
        let n = decode_utf8(&win.title[..win.title_len], &mut text.chars);
        let rtl = text.chars[..n]
            .iter()
            .map(|&c| bidi::class_of(c))
            .find(|&c| c == bidi::L || c == bidi::R || c == bidi::AL)
            .is_some_and(|c| c != bidi::L);
        let (count, width) = text.layout.line(
            fonts,
            &text.chars[..n],
            Base::Auto,
            TITLE_PX,
            &mut text.glyphs,
        );
        let tw = (width + 32) / 64;
        let x0 = if rtl {
            win.min_btn().x - 6 - tw
        } else {
            bar.x + 6
        };
        let mut canvas = BackCanvas {
            back: &mut *self.back,
            sw: self.screen.w as usize,
            clip: area,
            format: self.format,
            fg: TITLE_RGB,
        };
        let glyphs = text.glyphs;
        text.layout.draw(
            fonts,
            &glyphs[..count],
            TITLE_PX,
            x0,
            bar.y + 17,
            &mut canvas,
        );
    }

    /// Composes `r` into the back buffer (background, then windows bottom-up) and copies it
    /// to the frame; the cursor is redrawn when it overlaps.
    fn compose(&mut self, r: Rect) {
        let r = r.intersect(self.screen);
        if r.is_empty() {
            return;
        }
        self.fill_back(r, BG);
        for k in (0..self.n_order).rev() {
            let wi = self.order[k];
            if !self.windows[wi].minimized {
                self.draw_window(wi, r);
            }
        }
        self.blit(r);
        if !self.cursor_rect.intersect(r).is_empty() {
            self.draw_cursor();
        }
        self.composed += 1;
    }

    /// Back buffer → frame for `r` (volatile device memory, row by row).
    fn blit(&self, r: Rect) {
        let r = r.intersect(self.screen);
        if r.is_empty() {
            return;
        }
        let sw = self.screen.w as usize;
        for y in r.y..r.y1() {
            let row = y as usize * sw + r.x as usize;
            let dst = (self.fb as *mut u32).wrapping_add(y as usize * self.stride + r.x as usize);
            // SAFETY: the destination row lies inside the frame mapping (`y < h`,
            // `x + w <= width <= stride`); the source is a slice of the back buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.back[row..row + r.w as usize].as_ptr(),
                    dst,
                    r.w as usize,
                )
            };
        }
    }

    fn put_fb(&self, x: i32, y: i32, rgb: u32) {
        if self.screen.contains(x, y) {
            let p = (self.fb as *mut u32).wrapping_add(y as usize * self.stride + x as usize);
            // SAFETY: inside the frame mapping (checked against the screen).
            unsafe { p.write_volatile(self.rgb(rgb)) };
        }
    }

    /// A 9×9 cross at the pointer, drawn on the frame only.
    fn draw_cursor(&mut self) {
        let half = CURSOR / 2;
        let (cx, cy) = (self.px, self.py);
        for d in -half..=half {
            self.put_fb(cx + d, cy - 1, CURSOR_EDGE);
            self.put_fb(cx + d, cy + 1, CURSOR_EDGE);
            self.put_fb(cx - 1, cy + d, CURSOR_EDGE);
            self.put_fb(cx + 1, cy + d, CURSOR_EDGE);
        }
        for d in -half..=half {
            self.put_fb(cx + d, cy, CURSOR_RGB);
            self.put_fb(cx, cy + d, CURSOR_RGB);
        }
        self.cursor_rect = Rect::new(cx - half - 1, cy - half - 1, CURSOR + 2, CURSOR + 2);
    }

    fn move_cursor(&mut self, x: i32, y: i32) {
        let old = self.cursor_rect;
        self.px = x.clamp(0, self.screen.w - 1);
        self.py = y.clamp(0, self.screen.h - 1);
        self.blit(old);
        self.draw_cursor();
    }

    fn damage(&mut self, r: Rect) {
        self.dirty = self.dirty.union(r.intersect(self.screen));
    }

    fn flush_if_due(&mut self, now: u64) {
        if !self.dirty.is_empty() && now.saturating_sub(self.last_blit) >= BLIT_PERIOD {
            let r = self.dirty;
            self.dirty = Rect::NONE;
            self.compose(r);
            self.last_blit = now;
        }
    }

    // ---- clients and events -----------------------------------------------------------------

    /// One event to client `ci`: never blocks; a full queue drops it and starts the hang
    /// clock, a closed peer forgets the client.
    fn send(&mut self, ci: usize, msg: &[u8], now: u64) {
        let c = self.clients[ci].chan;
        if c == 0 {
            return;
        }
        match libnawah::channel_write(c, msg, &[]) {
            0 => {
                self.clients[ci].full_since = None;
                if self.clients[ci].unresponsive {
                    self.clients[ci].unresponsive = false;
                    self.unresponsive -= 1;
                    self.damage_client_windows(ci);
                }
            }
            ERR_PEER_CLOSED => self.forget_client(ci),
            _ => {
                self.clients[ci].dropped += 1;
                if self.clients[ci].full_since.is_none() {
                    self.clients[ci].full_since = Some(now);
                }
            }
        }
    }

    fn check_hangs(&mut self, now: u64) {
        for ci in 0..MAX_CLIENTS {
            let c = self.clients[ci];
            if c.chan != 0 && !c.unresponsive {
                if let Some(t0) = c.full_since {
                    if now.saturating_sub(t0) >= HANG_TICKS {
                        self.clients[ci].unresponsive = true;
                        self.unresponsive += 1;
                        self.damage_client_windows(ci);
                    }
                }
            }
        }
    }

    fn damage_client_windows(&mut self, ci: usize) {
        for wi in 0..MAX_WINDOWS {
            if self.windows[wi].used && self.windows[wi].owner == ci && !self.windows[wi].minimized
            {
                let r = self.windows[wi].outer();
                self.damage(r);
            }
        }
    }

    fn event(&mut self, wi: usize, kind: &[u8], args: &[i64], now: u64) {
        let mut buf = [0u8; 64];
        let len = {
            let mut o = Out {
                buf: &mut buf,
                len: 0,
            };
            o.put(kind);
            o.put(b" ");
            o.num(i64::from(self.windows[wi].id));
            for a in args {
                o.put(b" ");
                o.num(*a);
            }
            o.len
        };
        let owner = self.windows[wi].owner;
        self.send(owner, &buf[..len], now);
    }

    // ---- windows ------------------------------------------------------------------------

    fn window_by_id(&self, id: u32) -> Option<usize> {
        (0..MAX_WINDOWS).find(|&i| self.windows[i].used && self.windows[i].id == id)
    }

    fn surface_by_id(&self, id: u32) -> Option<usize> {
        (0..MAX_SURFACES).find(|&i| self.surfaces[i].used && self.surfaces[i].id == id)
    }

    fn z_of(&self, wi: usize) -> usize {
        (0..self.n_order)
            .find(|&k| self.order[k] == wi)
            .unwrap_or(0)
    }

    fn raise(&mut self, wi: usize) {
        let k = self.z_of(wi);
        for j in (1..=k).rev() {
            self.order[j] = self.order[j - 1];
        }
        self.order[0] = wi;
    }

    /// Moves the focus (events to both sides, decorations redrawn).
    fn set_focus(&mut self, wi: Option<usize>, now: u64) {
        if self.focus == wi {
            return;
        }
        if let Some(old) = self.focus {
            if self.windows[old].used {
                self.event(old, b"UNFOCUS", &[], now);
                let r = self.windows[old].title_bar();
                self.damage(r);
            }
        }
        self.focus = wi;
        if let Some(new) = wi {
            self.event(new, b"FOCUS", &[], now);
            let r = self.windows[new].title_bar();
            self.damage(r);
            // The narrator hears which window has the focus (display.md v1.1).
            let w = self.windows[new];
            let mut buf = [0u8; 64];
            let len = {
                let mut o = Out {
                    buf: &mut buf,
                    len: 0,
                };
                o.put(b"SAY window \"");
                o.put(&w.title[..w.title_len]);
                o.put(b"\" focused");
                o.len
            };
            self.say(&buf[..len], now);
        }
    }

    /// One message to the narrator, if one is registered.
    fn say(&mut self, msg: &[u8], now: u64) {
        if let Some(n) = self.narrator {
            self.send(n, msg, now);
        }
    }

    /// The top-most visible window, if any.
    fn top_visible(&self) -> Option<usize> {
        (0..self.n_order)
            .map(|k| self.order[k])
            .find(|&wi| !self.windows[wi].minimized)
    }

    fn focus_and_raise(&mut self, wi: usize, now: u64) {
        let r0 = self.windows[wi].outer();
        self.raise(wi);
        self.damage(r0);
        self.set_focus(Some(wi), now);
    }

    fn create_window(&mut self, ci: usize, si: usize, title: &[u8], now: u64) -> Option<u32> {
        let wi = (0..MAX_WINDOWS).find(|&i| !self.windows[i].used)?;
        let k = (self.created % 8) as i32;
        self.created += 1;
        let s = self.surfaces[si];
        let mut w = NO_WINDOW;
        w.used = true;
        w.owner = ci;
        w.id = self.next_id;
        self.next_id += 1;
        w.surface = Some(si);
        w.x = ORIGIN + k * CASCADE + BORDER;
        w.y = ORIGIN + k * CASCADE + BORDER + TITLE_H;
        w.w = s.w;
        w.h = s.h;
        let n = title.len().min(TITLE_MAX);
        w.title[..n].copy_from_slice(&title[..n]);
        w.title_len = n;
        self.windows[wi] = w;
        // On top of the stack, focused.
        for j in (1..=self.n_order).rev() {
            self.order[j] = self.order[j - 1];
        }
        self.order[0] = wi;
        self.n_order += 1;
        self.damage(w.outer());
        self.set_focus(Some(wi), now);
        Some(w.id)
    }

    fn destroy_window(&mut self, wi: usize, now: u64) {
        let r = self.windows[wi].outer();
        let k = self.z_of(wi);
        for j in k..self.n_order.saturating_sub(1) {
            self.order[j] = self.order[j + 1];
        }
        self.n_order -= 1;
        self.windows[wi].used = false;
        if self.drag.is_some_and(|d| d.win == wi) {
            self.drag = None;
        }
        self.damage(r);
        if self.focus == Some(wi) {
            self.focus = None;
            let next = self.top_visible();
            self.set_focus(next, now);
        }
    }

    fn set_minimized(&mut self, wi: usize, minimized: bool, now: u64) {
        if self.windows[wi].minimized == minimized {
            return;
        }
        self.windows[wi].minimized = minimized;
        let r = self.windows[wi].outer();
        self.damage(r);
        if minimized {
            if self.focus == Some(wi) {
                // The minimised window is told UNFOCUS, the next visible one FOCUS (CI run
                // 39156535478 cleared the focus first and sent no UNFOCUS).
                let next = self.top_visible();
                self.set_focus(next, now);
            }
        } else {
            self.focus_and_raise(wi, now);
        }
    }

    fn move_window(&mut self, wi: usize, x: i32, y: i32) {
        let r0 = self.windows[wi].outer();
        self.windows[wi].x = x.clamp(-self.windows[wi].w + MIN_SIZE, self.screen.w - MIN_SIZE);
        self.windows[wi].y = y.clamp(TITLE_H + BORDER, self.screen.h - 1);
        let r1 = self.windows[wi].outer();
        self.damage(r0);
        self.damage(r1);
    }

    /// A new client-area size: the client is told and attaches a surface of that size.
    fn resize_window(&mut self, wi: usize, w: i32, h: i32, now: u64) {
        let (w, h) = (w.clamp(MIN_SIZE, MAX_SIZE), h.clamp(MIN_SIZE, MAX_SIZE));
        if (w, h) == (self.windows[wi].w, self.windows[wi].h) {
            return;
        }
        let r0 = self.windows[wi].outer();
        self.windows[wi].w = w;
        self.windows[wi].h = h;
        let r1 = self.windows[wi].outer();
        self.damage(r0);
        self.damage(r1);
        self.event(wi, b"RESIZED", &[i64::from(w), i64::from(h)], now);
    }

    fn close_requested(&mut self, wi: usize, now: u64) {
        if self.clients[self.windows[wi].owner].unresponsive {
            self.destroy_window(wi, now);
        } else {
            self.event(wi, b"CLOSE_REQUESTED", &[], now);
        }
    }

    fn forget_client(&mut self, ci: usize) {
        if self.clients[ci].chan == 0 {
            return;
        }
        let now = libnawah::clock_ticks();
        for wi in 0..MAX_WINDOWS {
            if self.windows[wi].used && self.windows[wi].owner == ci {
                self.destroy_window(wi, now);
            }
        }
        for si in 0..MAX_SURFACES {
            if self.surfaces[si].used && self.surfaces[si].owner == ci {
                self.destroy_surface(si);
            }
        }
        if self.clients[ci].unresponsive {
            self.unresponsive -= 1;
        }
        if self.narrator == Some(ci) {
            self.narrator = None;
        }
        libnawah::handle_close(self.clients[ci].chan);
        self.clients[ci] = NO_CLIENT;
    }

    fn destroy_surface(&mut self, si: usize) {
        let s = self.surfaces[si];
        for wi in 0..MAX_WINDOWS {
            if self.windows[wi].used && self.windows[wi].surface == Some(si) {
                self.windows[wi].surface = None;
                let r = self.windows[wi].client();
                self.damage(r);
            }
        }
        libnawah::vmo_unmap(s.addr);
        libnawah::handle_close(s.vmo);
        self.surfaces[si] = NO_SURFACE;
    }

    /// FNV-1a 64 over the client area's pixels in the back buffer (R, G, B per pixel).
    fn hash_window(&self, wi: usize) -> u64 {
        let area = self.windows[wi].client().intersect(self.screen);
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let sw = self.screen.w as usize;
        for y in area.y..area.y1() {
            for x in area.x..area.x1() {
                let p = self.back[y as usize * sw + x as usize];
                let (r, g, b) = if self.format == libnawah::display::FORMAT_RGBX {
                    (p & 0xFF, (p >> 8) & 0xFF, (p >> 16) & 0xFF)
                } else {
                    ((p >> 16) & 0xFF, (p >> 8) & 0xFF, p & 0xFF)
                };
                for byte in [r, g, b] {
                    h ^= u64::from(byte);
                    h = h.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
        }
        h
    }

    // ---- input ------------------------------------------------------------------------

    fn window_at(&self, x: i32, y: i32) -> Option<usize> {
        (0..self.n_order)
            .map(|k| self.order[k])
            .find(|&wi| !self.windows[wi].minimized && self.windows[wi].outer().contains(x, y))
    }

    fn on_pointer(&mut self, dx: i32, dy: i32, buttons: u32, now: u64) {
        let (nx, ny) = (self.px + dx, self.py + dy);
        self.move_cursor(nx, ny);
        let pressed = buttons & !self.buttons;
        let released = self.buttons & !buttons;
        self.buttons = buttons;
        if let Some(d) = self.drag {
            match d.mode {
                DragMode::Move => self.move_window(d.win, self.px - d.ax, self.py - d.ay),
                DragMode::Resize => {
                    let (w, h) = (
                        self.px - self.windows[d.win].x,
                        self.py - self.windows[d.win].y,
                    );
                    let r0 = self.windows[d.win].outer();
                    self.windows[d.win].w = w.clamp(MIN_SIZE, MAX_SIZE);
                    self.windows[d.win].h = h.clamp(MIN_SIZE, MAX_SIZE);
                    let r1 = self.windows[d.win].outer();
                    self.damage(r0);
                    self.damage(r1);
                }
            }
            if released & 1 != 0 {
                if d.mode == DragMode::Resize {
                    let (w, h) = (self.windows[d.win].w, self.windows[d.win].h);
                    self.event(d.win, b"RESIZED", &[i64::from(w), i64::from(h)], now);
                }
                self.drag = None;
            }
            return;
        }
        let Some(wi) = self.window_at(self.px, self.py) else {
            return;
        };
        let win = self.windows[wi];
        if pressed & 1 != 0 {
            self.focus_and_raise(wi, now);
            if win.close_btn().contains(self.px, self.py) {
                self.close_requested(wi, now);
            } else if win.min_btn().contains(self.px, self.py) {
                self.set_minimized(wi, true, now);
            } else if win.title_bar().contains(self.px, self.py) {
                self.drag = Some(Drag {
                    win: wi,
                    mode: DragMode::Move,
                    ax: self.px - win.x,
                    ay: self.py - win.y,
                });
            } else if win.grip().contains(self.px, self.py) {
                self.drag = Some(Drag {
                    win: wi,
                    mode: DragMode::Resize,
                    ax: 0,
                    ay: 0,
                });
            }
        }
        if win.client().contains(self.px, self.py) {
            let (x, y) = (self.px - win.x, self.py - win.y);
            self.event(
                wi,
                b"POINTER",
                &[i64::from(x), i64::from(y), i64::from(buttons)],
                now,
            );
        }
    }

    fn on_key(&mut self, msg: &[u8], now: u64) {
        let mut f = msg.split(|c| *c == b' ').filter(|f| !f.is_empty());
        let (Some(code), Some(dir), Some(mods)) = (
            f.nth(1).and_then(parse_code),
            f.next(),
            f.next().and_then(parse_u32),
        ) else {
            return;
        };
        let down = dir == b"down";
        if !down && self.consumed_key == Some(code) {
            self.consumed_key = None;
            return;
        }
        if down && mods & MOD_ALT != 0 {
            match code {
                KEY_TAB => {
                    if let Some(cur) = self.focus {
                        let k = self.z_of(cur);
                        for step in 1..=self.n_order {
                            let wi = self.order[(k + step) % self.n_order];
                            if !self.windows[wi].minimized {
                                self.focus_and_raise(wi, now);
                                break;
                            }
                        }
                    } else if let Some(wi) = self.top_visible() {
                        self.focus_and_raise(wi, now);
                    }
                    self.consumed_key = Some(code);
                    return;
                }
                KEY_F4 => {
                    if let Some(wi) = self.focus {
                        self.close_requested(wi, now);
                    }
                    self.consumed_key = Some(code);
                    return;
                }
                KEY_UP | KEY_DOWN | KEY_LEFT | KEY_RIGHT => {
                    if let Some(wi) = self.focus {
                        let (dx, dy) = match code {
                            KEY_UP => (0, -KEY_STEP),
                            KEY_DOWN => (0, KEY_STEP),
                            KEY_LEFT => (-KEY_STEP, 0),
                            _ => (KEY_STEP, 0),
                        };
                        let w = self.windows[wi];
                        if mods & MOD_SHIFT != 0 {
                            self.resize_window(wi, w.w + dx, w.h + dy, now);
                        } else {
                            self.move_window(wi, w.x + dx, w.y + dy);
                        }
                    }
                    self.consumed_key = Some(code);
                    return;
                }
                _ => {}
            }
        }
        if let Some(wi) = self.focus {
            let owner = self.windows[wi].owner;
            self.send(owner, msg, now);
        }
    }

    fn on_input(&mut self, msg: &[u8], now: u64) {
        if msg.starts_with(b"KEY ") {
            self.on_key(msg, now);
        } else if let Some(rest) = msg.strip_prefix(b"PTR ") {
            let mut f = rest.split(|c| *c == b' ').filter(|f| !f.is_empty());
            if let (Some(dx), Some(dy), Some(b)) = (
                f.next().and_then(parse_i32),
                f.next().and_then(parse_i32),
                f.next().and_then(parse_u32),
            ) {
                self.on_pointer(dx, dy, b, now);
            }
        }
    }

    // ---- requests ---------------------------------------------------------------------

    /// One request; `true` when the handle it carried was taken (a surface's VMO).
    fn request(
        &mut self,
        ci: usize,
        req: &[u8],
        handle: Option<Handle>,
        now: u64,
        out: &mut Out,
    ) -> bool {
        let mut f = req.split(|c| *c == b' ').filter(|f| !f.is_empty());
        let verb = f.next().unwrap_or(b"");
        let owns = |me: &Self, wi: usize| me.windows[wi].owner == ci;
        match verb {
            b"CREATE_SURFACE" => {
                let (Some(w), Some(h)) =
                    (f.next().and_then(parse_i32), f.next().and_then(parse_i32))
                else {
                    out.put(b"ERR BAD_REQUEST");
                    return false;
                };
                let Some(vmo) = handle else {
                    out.put(b"ERR BAD_REQUEST");
                    return false;
                };
                if !(1..=MAX_SIZE).contains(&w) || !(1..=MAX_SIZE).contains(&h) {
                    out.put(b"ERR INVALID");
                    return false;
                }
                let Some(si) = (0..MAX_SURFACES).find(|&i| !self.surfaces[i].used) else {
                    out.put(b"ERR FULL");
                    return false;
                };
                if libnawah::handle_type(vmo) != libnawah::object_type::VMO {
                    out.put(b"ERR WRONG_TYPE");
                    return false;
                }
                let addr = match libnawah::vmo_map(vmo, libnawah::PROT_READ) {
                    Ok(a) => a,
                    Err(_) => {
                        out.put(b"ERR ACCESS");
                        return false;
                    }
                };
                // The mapping must hold the pixels the client declares, or composing would
                // read past it: the VMO's size bounds w*h*4.
                let bytes = u64::from(w as u32) * u64::from(h as u32) * 4;
                if !libnawah::vmo_size(vmo).is_ok_and(|s| s >= bytes) {
                    libnawah::vmo_unmap(addr);
                    out.put(b"ERR INVALID");
                    return false;
                }
                self.surfaces[si] = Surface {
                    used: true,
                    owner: ci,
                    id: self.next_id,
                    vmo,
                    addr,
                    w,
                    h,
                };
                self.next_id += 1;
                out.put(b"OK ");
                out.num(i64::from(self.surfaces[si].id));
                return true;
            }
            b"DESTROY_SURFACE" => {
                match f
                    .next()
                    .and_then(parse_u32)
                    .and_then(|id| self.surface_by_id(id))
                {
                    Some(si) if self.surfaces[si].owner == ci => {
                        self.destroy_surface(si);
                        out.put(b"OK");
                    }
                    _ => out.put(b"ERR UNKNOWN"),
                }
            }
            b"COMMIT" => {
                let Some(si) = f
                    .next()
                    .and_then(parse_u32)
                    .and_then(|id| self.surface_by_id(id))
                else {
                    out.put(b"ERR UNKNOWN");
                    return false;
                };
                if self.surfaces[si].owner != ci {
                    out.put(b"ERR UNKNOWN");
                    return false;
                }
                let (Some(x), Some(y), Some(w), Some(h)) = (
                    f.next().and_then(parse_i32),
                    f.next().and_then(parse_i32),
                    f.next().and_then(parse_i32),
                    f.next().and_then(parse_i32),
                ) else {
                    out.put(b"ERR BAD_REQUEST");
                    return false;
                };
                let s = self.surfaces[si];
                let area = Rect::new(x, y, w, h).intersect(Rect::new(0, 0, s.w, s.h));
                for wi in 0..MAX_WINDOWS {
                    let win = self.windows[wi];
                    if win.used && win.surface == Some(si) && !win.minimized {
                        self.damage(Rect::new(win.x + area.x, win.y + area.y, area.w, area.h));
                    }
                }
                out.put(b"OK");
            }
            b"CREATE_WINDOW" => {
                let Some(si) = f
                    .next()
                    .and_then(parse_u32)
                    .and_then(|id| self.surface_by_id(id))
                else {
                    out.put(b"ERR UNKNOWN");
                    return false;
                };
                if self.surfaces[si].owner != ci {
                    out.put(b"ERR UNKNOWN");
                    return false;
                }
                let title = after_fields(req, 2);
                match self.create_window(ci, si, title, now) {
                    Some(id) => {
                        out.put(b"OK ");
                        out.num(i64::from(id));
                    }
                    None => out.put(b"ERR FULL"),
                }
            }
            b"ATTACH" => {
                let (Some(wi), Some(si)) = (
                    f.next()
                        .and_then(parse_u32)
                        .and_then(|id| self.window_by_id(id)),
                    f.next()
                        .and_then(parse_u32)
                        .and_then(|id| self.surface_by_id(id)),
                ) else {
                    out.put(b"ERR UNKNOWN");
                    return false;
                };
                if !owns(self, wi) || self.surfaces[si].owner != ci {
                    out.put(b"ERR UNKNOWN");
                    return false;
                }
                let r0 = self.windows[wi].outer();
                self.windows[wi].surface = Some(si);
                self.windows[wi].w = self.surfaces[si].w;
                self.windows[wi].h = self.surfaces[si].h;
                let r1 = self.windows[wi].outer();
                self.damage(r0);
                self.damage(r1);
                out.put(b"OK");
            }
            b"MOVE" | b"RESIZE" | b"RAISE" | b"MINIMIZE" | b"RESTORE" | b"CLOSE" => {
                let Some(wi) = f
                    .next()
                    .and_then(parse_u32)
                    .and_then(|id| self.window_by_id(id))
                else {
                    out.put(b"ERR UNKNOWN");
                    return false;
                };
                if !owns(self, wi) {
                    out.put(b"ERR UNKNOWN");
                    return false;
                }
                match verb {
                    b"MOVE" | b"RESIZE" => {
                        let (Some(a), Some(b)) =
                            (f.next().and_then(parse_i32), f.next().and_then(parse_i32))
                        else {
                            out.put(b"ERR BAD_REQUEST");
                            return false;
                        };
                        if verb == b"MOVE" {
                            self.move_window(wi, a, b);
                        } else {
                            if !(MIN_SIZE..=MAX_SIZE).contains(&a)
                                || !(MIN_SIZE..=MAX_SIZE).contains(&b)
                            {
                                out.put(b"ERR INVALID");
                                return false;
                            }
                            self.resize_window(wi, a, b, now);
                        }
                    }
                    b"RAISE" => {
                        if self.windows[wi].minimized {
                            self.set_minimized(wi, false, now);
                        } else {
                            self.focus_and_raise(wi, now);
                        }
                    }
                    b"MINIMIZE" => self.set_minimized(wi, true, now),
                    b"RESTORE" => self.set_minimized(wi, false, now),
                    _ => self.destroy_window(wi, now),
                }
                out.put(b"OK");
            }
            b"LIST" => {
                // The back buffer must be current for the hashes.
                if !self.dirty.is_empty() {
                    let r = self.dirty;
                    self.dirty = Rect::NONE;
                    self.compose(r);
                    self.last_blit = now;
                }
                out.put(b"OK");
                for k in 0..self.n_order {
                    let wi = self.order[k];
                    let w = self.windows[wi];
                    if w.owner != ci {
                        continue;
                    }
                    out.put(b"\nW ");
                    out.num(i64::from(w.id));
                    out.put(b" ");
                    match w.surface {
                        Some(si) => out.num(i64::from(self.surfaces[si].id)),
                        None => out.put(b"-"),
                    }
                    for v in [w.x, w.y, w.w, w.h] {
                        out.put(b" ");
                        out.num(i64::from(v));
                    }
                    out.put(if w.minimized {
                        b" minimized "
                    } else {
                        b" normal "
                    });
                    out.num(k as i64);
                    out.put(if self.focus == Some(wi) {
                        b" 1 "
                    } else {
                        b" 0 "
                    });
                    let h = self.hash_window(wi);
                    out.hex64(h);
                }
            }
            b"NARRATOR" => {
                // The first client to ask becomes the narrator (display.md v1.1); the
                // manifest decides who may connect at all.
                if self.narrator.is_some_and(|n| n != ci) {
                    out.put(b"ERR BUSY");
                } else {
                    self.narrator = Some(ci);
                    out.put(b"OK");
                }
            }
            b"A11Y" => {
                // An announcement of the focused window's owner goes to the narrator as
                // `SAY <text>`; other windows are refused (no client speaks over another).
                let Some(wi) = f
                    .next()
                    .and_then(parse_u32)
                    .and_then(|id| self.window_by_id(id))
                else {
                    out.put(b"ERR UNKNOWN");
                    return false;
                };
                if !owns(self, wi) {
                    out.put(b"ERR UNKNOWN");
                    return false;
                }
                if self.focus != Some(wi) {
                    out.put(b"ERR NOT_FOCUSED");
                    return false;
                }
                let Some(n) = self.narrator else {
                    out.put(b"ERR NO_NARRATOR");
                    return false;
                };
                let text = after_fields(req, 2);
                let mut buf = [0u8; MSG_MAX];
                buf[..4].copy_from_slice(b"SAY ");
                let len = 4 + text.len().min(MSG_MAX - 4);
                buf[4..len].copy_from_slice(&text[..len - 4]);
                self.send(n, &buf[..len], now);
                out.put(b"OK");
            }
            b"STATUS" => {
                out.put(b"OK format=");
                out.num(i64::from(self.format));
                out.put(b" screen=");
                out.num(i64::from(self.screen.w));
                out.put(b"x");
                out.num(i64::from(self.screen.h));
                out.put(b" windows=");
                out.num(self.n_order as i64);
                out.put(b" focus=");
                match self.focus {
                    Some(wi) => out.num(i64::from(self.windows[wi].id)),
                    None => out.put(b"-"),
                }
                out.put(b" pointer=");
                out.num(i64::from(self.px));
                out.put(b",");
                out.num(i64::from(self.py));
                out.put(b" composed=");
                out.num(self.composed as i64);
                out.put(b" dropped=");
                let dropped: u64 = self.clients.iter().map(|c| c.dropped).sum();
                out.num(dropped as i64);
                out.put(b" unresponsive=");
                out.num(i64::from(self.unresponsive));
            }
            _ => out.put(b"ERR BAD_REQUEST"),
        }
        false
    }

    /// Reads every pending message of client `ci`.
    fn serve_client(&mut self, ci: usize, now: u64) {
        loop {
            let c = self.clients[ci].chan;
            if c == 0 {
                return;
            }
            let mut buf = [0u8; MSG_MAX];
            let mut hs = [0u32; 1];
            match libnawah::channel_read(c, &mut buf, &mut hs, false) {
                Ok((n, nh)) => {
                    let handle = if nh == 1 { Some(hs[0]) } else { None };
                    let mut out_buf = [0u8; MSG_MAX];
                    let mut out = Out {
                        buf: &mut out_buf,
                        len: 0,
                    };
                    let taken = self.request(ci, &buf[..n], handle, now, &mut out);
                    // A handle that was not taken by a surface is closed (moved to us).
                    if let (Some(h), false) = (handle, taken) {
                        libnawah::handle_close(h);
                    }
                    let len = out.len;
                    self.send(ci, &out_buf[..len], now);
                }
                Err(ERR_PEER_CLOSED) => {
                    self.forget_client(ci);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn serve_input(&mut self, now: u64) {
        loop {
            let mut buf = [0u8; 128];
            let mut hs = [0u32; 1];
            match libnawah::channel_read(self.input, &mut buf, &mut hs, false) {
                Ok((n, nh)) => {
                    if nh == 1 {
                        libnawah::handle_close(hs[0]);
                    }
                    let mut msg = [0u8; 128];
                    msg[..n].copy_from_slice(&buf[..n]);
                    self.on_input(&msg[..n], now);
                }
                Err(_) => return,
            }
        }
    }
}

/// A request to the manager on the boot channel; the reply and one handle, if any.
fn manager(boot: Handle, req: &[u8], reply: &mut [u8]) -> Result<(usize, Option<Handle>), i64> {
    if libnawah::channel_write(boot, req, &[]) != 0 {
        return Err(ERR_PEER_CLOSED);
    }
    loop {
        let mut hs = [0u32; 1];
        match libnawah::channel_read(boot, reply, &mut hs, false) {
            Ok((n, nh)) => return Ok((n, if nh == 1 { Some(hs[0]) } else { None })),
            Err(ERR_SHOULD_WAIT) => {}
            Err(e) => return Err(e),
        }
        let _ = libnawah::object_wait_many(
            &[WaitEntry {
                handle: boot,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            }],
            5000,
        );
    }
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let display = boot + 1;
    if libnawah::handle_type(display) != libnawah::object_type::DISPLAY {
        return 0xE1;
    }
    let Ok(info) = libnawah::display_info(display) else {
        return 0xE1;
    };
    if info.width as usize * info.height as usize > MAX_PIXELS || info.stride < info.width {
        return 0xE2;
    }
    let Ok(frame) = libnawah::display_map(display) else {
        return 0xE3;
    };
    let Ok(fb) = libnawah::vmo_map(frame, libnawah::PROT_READ | libnawah::PROT_WRITE) else {
        return 0xE3;
    };
    let mut buf = [0u8; 64];
    let mut hs = [0u32; 1];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((n, _)) if buf[..n].starts_with(b"START") => {}
        _ => return 0xE4,
    }
    // The input service: our declared dependency; we register as `display`.
    let mut reply = [0u8; 64];
    let input = match manager(boot, b"CONNECT input", &mut reply) {
        Ok((n, Some(h))) if &reply[..n] == b"OK" => h,
        _ => return 0xE5,
    };
    if libnawah::channel_write(input, b"REGISTER display", &[]) != 0 {
        return 0xE5;
    }
    // SAFETY: the back buffer is taken exactly once, here, for the life of the process.
    let back: &'static mut [u32] = unsafe { &mut *core::ptr::addr_of_mut!(BACK) };
    // SAFETY: as above, the text state.
    let text: &'static mut TextState = unsafe { &mut *core::ptr::addr_of_mut!(TEXT) };
    // The fonts for the titles (text.md §1); without them the titles stay blank.
    let fonts = match (
        load_font(b"/SYSTEM/FONTS/NOTOSANS.TTF").and_then(Font::parse),
        load_font(b"/SYSTEM/FONTS/NOTOARAB.TTF").and_then(Font::parse),
    ) {
        (Some(latin), Some(arabic)) => Some(Fonts { latin, arabic }),
        _ => None,
    };
    libnawah::trace(if fonts.is_some() {
        b"display|fonts=1"
    } else {
        b"display|fonts=0"
    });
    let screen = Rect::new(0, 0, info.width as i32, info.height as i32);
    let mut c = Compositor {
        boot,
        input,
        fb,
        stride: info.stride as usize,
        format: info.pixel_format,
        screen,
        back,
        clients: [NO_CLIENT; MAX_CLIENTS],
        surfaces: [NO_SURFACE; MAX_SURFACES],
        windows: [NO_WINDOW; MAX_WINDOWS],
        order: [0; MAX_WINDOWS],
        n_order: 0,
        next_id: 1,
        created: 0,
        focus: None,
        px: screen.w / 2,
        py: screen.h / 2,
        buttons: 0,
        drag: None,
        cursor_rect: Rect::NONE,
        dirty: Rect::NONE,
        last_blit: 0,
        composed: 0,
        unresponsive: 0,
        consumed_key: None,
        narrator: None,
        fonts,
        text,
    };
    c.compose(screen);
    c.draw_cursor();
    c.last_blit = libnawah::clock_ticks();
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE6;
    }
    loop {
        let mut entries = [WaitEntry {
            handle: 0,
            signals: 0,
        }; 2 + MAX_CLIENTS];
        entries[0] = WaitEntry {
            handle: c.boot,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        };
        entries[1] = WaitEntry {
            handle: c.input,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        };
        let mut owner = [0usize; 2 + MAX_CLIENTS];
        let mut k = 2;
        for (i, cl) in c.clients.iter().enumerate() {
            if cl.chan != 0 {
                entries[k] = WaitEntry {
                    handle: cl.chan,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                };
                owner[k] = i;
                k += 1;
            }
        }
        let now = libnawah::clock_ticks();
        let timeout = if !c.dirty.is_empty() {
            BLIT_PERIOD
                .saturating_sub(now.saturating_sub(c.last_blit))
                .max(1)
        } else if c
            .clients
            .iter()
            .any(|cl| cl.chan != 0 && cl.full_since.is_some())
        {
            HANG_POLL
        } else {
            libnawah::TIMEOUT_FOREVER
        };
        let r = libnawah::object_wait_many(&entries[..k], timeout);
        let now = libnawah::clock_ticks();
        match r {
            Ok((0, _)) => match libnawah::channel_read(c.boot, &mut buf, &mut hs, false) {
                Ok((n, nh)) => {
                    if &buf[..n] == b"CONNECT" && nh == 1 {
                        match c.clients.iter().position(|cl| cl.chan == 0) {
                            Some(slot) => {
                                c.clients[slot] = NO_CLIENT;
                                c.clients[slot].chan = hs[0];
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
            Ok((1, _)) => c.serve_input(now),
            Ok((idx, _)) => {
                let ci = owner[idx];
                c.serve_client(ci, now);
            }
            Err(ERR_TIMED_OUT) => {}
            Err(_) => return 0xE7,
        }
        c.check_hangs(now);
        c.flush_if_due(now);
    }
}
