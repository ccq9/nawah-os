//! libui — dialog elements with a fixed focus order, keyboard navigation and accessibility
//! descriptions (WP-36, ui.md, ADR-0019 §7). `no_std`, no allocation, no `unsafe`; the
//! application owns the surface and the channels, this crate owns the elements, the focus,
//! the key handling, the descriptions the narrator reads and the drawing into a `0xRRGGBB`
//! buffer with the text layer (nawah-text).
//!
//! Every element has a role and a non-empty label (an element without one is refused when it
//! is added: the "build error" of ui.md); labels, values and list items are UTF-8.
//!
//! v1.1 (WP-37, ui.md §3.1): the `password` role — a text field drawn as bullets whose
//! description never carries its value — and the application's access to a field's value
//! (`value`, `clear_value`, `set_value`) and to the focus (`focus_on`).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use nawah_text::bidi::Base;
use nawah_text::layout::{Fonts, Glyph, Layout, RgbCanvas};

pub const MAX_ELEMENTS: usize = 12;
pub const MAX_ITEMS: usize = 6;
pub const TEXT_MAX: usize = 32;

// Set-1 key codes (input.md §3: extended keys as 0x80 | code).
pub const KEY_ESC: u32 = 0x01;
pub const KEY_BACKSPACE: u32 = 0x0e;
pub const KEY_TAB: u32 = 0x0f;
pub const KEY_ENTER: u32 = 0x1c;
pub const KEY_SPACE: u32 = 0x39;
pub const KEY_UP: u32 = 0xc8;
pub const KEY_DOWN: u32 = 0xd0;
pub const KEY_LEFT: u32 = 0xcb;
pub const KEY_RIGHT: u32 = 0xcd;
pub const MOD_SHIFT: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Label,
    Button,
    TextField,
    List,
    Checkbox,
    /// A text field whose characters are drawn as bullets and never described (v1.1).
    Password,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Label => "label",
            Role::Button => "button",
            Role::TextField => "textfield",
            Role::List => "list",
            Role::Checkbox => "checkbox",
            Role::Password => "password",
        }
    }
    pub fn focusable(self) -> bool {
        self != Role::Label
    }
    /// Roles that hold editable text (the keys of ui.md §2 for fields).
    pub fn is_text(self) -> bool {
        matches!(self, Role::TextField | Role::Password)
    }
}

/// U+2022 BULLET: how a password field shows each of its characters.
pub const BULLET: u32 = 0x2022;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UiError {
    /// An element without a label (ui.md: refused when built).
    NoLabel,
    /// A list without items.
    NoItems,
    Full,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    None,
    /// The focus moved from the first element (if any) to the second.
    Focus(Option<usize>, usize),
    Activate(usize),
    Toggle(usize, bool),
    Select(usize, usize),
    Edit(usize),
    Cancel,
}

#[derive(Clone, Copy)]
pub struct Element {
    pub role: Role,
    pub label: &'static str,
    pub checked: bool,
    pub items: &'static [&'static str],
    pub selected: usize,
    pub text: [u32; TEXT_MAX],
    pub text_len: usize,
    pub cursor: usize,
}

const EMPTY: Element = Element {
    role: Role::Label,
    label: "",
    checked: false,
    items: &[],
    selected: 0,
    text: [0; TEXT_MAX],
    text_len: 0,
    cursor: 0,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// Text scale in quarters (4 = 1×, 6 = 1.5×, 8 = 2×) and contrast (ui.md: `ui.scale`,
/// `ui.contrast` from config).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Theme {
    pub scale: u32,
    pub high_contrast: bool,
}

impl Theme {
    pub const DEFAULT: Theme = Theme {
        scale: 4,
        high_contrast: false,
    };

    /// `ui.scale` values "1", "1.5", "2" (anything else is 1×); `ui.contrast` "high".
    pub fn from_config(scale: &[u8], contrast: &[u8]) -> Theme {
        Theme {
            scale: match scale {
                b"1.5" => 6,
                b"2" => 8,
                _ => 4,
            },
            high_contrast: contrast == b"high",
        }
    }

    fn u(&self, v: i32) -> i32 {
        v * self.scale as i32 / 4
    }

    pub fn palette(&self) -> Palette {
        if self.high_contrast {
            Palette {
                bg: 0x000000,
                fg: 0xFFFFFF,
                control: 0x000000,
                border: 0xFFFFFF,
                focus: 0xFFFF00,
                button: 0x000000,
                check: 0xFFFF00,
                selected_bg: 0xFFFF00,
                selected_fg: 0x000000,
                placeholder: 0xC0C0C0,
            }
        } else {
            Palette {
                bg: 0xF0F0F0,
                fg: 0x101010,
                control: 0xFFFFFF,
                border: 0x808080,
                focus: 0x1E64C8,
                button: 0xDDE4EE,
                check: 0x1E64C8,
                selected_bg: 0xC8DCF8,
                selected_fg: 0x101010,
                placeholder: 0x808080,
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Palette {
    pub bg: u32,
    pub fg: u32,
    pub control: u32,
    pub border: u32,
    pub focus: u32,
    pub button: u32,
    pub check: u32,
    pub selected_bg: u32,
    pub selected_fg: u32,
    pub placeholder: u32,
}

/// A fixed-capacity string for descriptions.
pub struct Text {
    pub buf: [u8; 256],
    pub len: usize,
}

impl Default for Text {
    fn default() -> Self {
        Self::new()
    }
}

impl Text {
    pub const fn new() -> Text {
        Text {
            buf: [0; 256],
            len: 0,
        }
    }
    pub fn clear(&mut self) {
        self.len = 0;
    }
    pub fn put(&mut self, s: &[u8]) {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
    pub fn num(&mut self, v: usize) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        let mut v = v;
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
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

pub struct Dialog {
    pub title: &'static str,
    elements: [Element; MAX_ELEMENTS],
    n: usize,
    focus: Option<usize>,
    pub rtl: bool,
    pub theme: Theme,
}

fn utf8_chars(s: &str, out: &mut [u32]) -> usize {
    let mut n = 0;
    for c in s.chars() {
        if n == out.len() {
            break;
        }
        out[n] = c as u32;
        n += 1;
    }
    n
}

impl Dialog {
    pub const fn new(title: &'static str, rtl: bool) -> Dialog {
        Dialog {
            title,
            elements: [EMPTY; MAX_ELEMENTS],
            n: 0,
            focus: None,
            rtl,
            theme: Theme::DEFAULT,
        }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn element(&self, i: usize) -> &Element {
        &self.elements[i]
    }

    /// Adds an element; its index comes back.
    pub fn add(&mut self, role: Role, label: &'static str) -> Result<usize, UiError> {
        if label.trim().is_empty() {
            return Err(UiError::NoLabel);
        }
        if role == Role::List {
            return Err(UiError::NoItems);
        }
        self.push(Element {
            role,
            label,
            ..EMPTY
        })
    }

    pub fn add_list(
        &mut self,
        label: &'static str,
        items: &'static [&'static str],
    ) -> Result<usize, UiError> {
        if label.trim().is_empty() || items.iter().any(|i| i.trim().is_empty()) {
            return Err(UiError::NoLabel);
        }
        if items.is_empty() || items.len() > MAX_ITEMS {
            return Err(UiError::NoItems);
        }
        self.push(Element {
            role: Role::List,
            label,
            items,
            ..EMPTY
        })
    }

    fn push(&mut self, e: Element) -> Result<usize, UiError> {
        if self.n == MAX_ELEMENTS {
            return Err(UiError::Full);
        }
        self.elements[self.n] = e;
        self.n += 1;
        Ok(self.n - 1)
    }

    /// The focusable elements in declared order (the focus order).
    pub fn focus_order(&self, out: &mut [usize]) -> usize {
        let mut k = 0;
        for i in 0..self.n {
            if self.elements[i].role.focusable() && k < out.len() {
                out[k] = i;
                k += 1;
            }
        }
        k
    }

    pub fn focused(&self) -> Option<usize> {
        self.focus
    }

    /// Moves the focus to element `i` if it can take it (v1.1).
    pub fn focus_on(&mut self, i: usize) -> Event {
        if i >= self.n || !self.elements[i].role.focusable() {
            return Event::None;
        }
        self.move_focus(i)
    }

    /// The text of field `i` (a text field or a password) as UTF-8 in `out`; its length
    /// (0 for other roles or when `out` is too small for the next character).
    pub fn value(&self, i: usize, out: &mut [u8]) -> usize {
        if i >= self.n || !self.elements[i].role.is_text() {
            return 0;
        }
        let e = &self.elements[i];
        let mut n = 0;
        let mut tmp = [0u8; 4];
        for &cp in &e.text[..e.text_len] {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            let b = c.encode_utf8(&mut tmp).as_bytes();
            if n + b.len() > out.len() {
                break;
            }
            out[n..n + b.len()].copy_from_slice(b);
            n += b.len();
        }
        n
    }

    /// Wipes field `i`: every character slot to zero, empty, cursor at the start (v1.1).
    pub fn clear_value(&mut self, i: usize) {
        if i >= self.n || !self.elements[i].role.is_text() {
            return;
        }
        let e = &mut self.elements[i];
        e.text = [0; TEXT_MAX];
        e.text_len = 0;
        e.cursor = 0;
    }

    /// Puts `text` into text field `i` (not a password: an application never fills one);
    /// `false` when refused. Characters beyond the field's capacity are dropped.
    pub fn set_value(&mut self, i: usize, text: &str) -> bool {
        if i >= self.n || self.elements[i].role != Role::TextField {
            return false;
        }
        let e = &mut self.elements[i];
        e.text = [0; TEXT_MAX];
        e.text_len = utf8_chars(text, &mut e.text);
        e.cursor = e.text_len;
        true
    }

    /// Sets the dialog's reading direction (v1.2); the layout and the field arrows follow it.
    pub fn set_rtl(&mut self, rtl: bool) {
        self.rtl = rtl;
    }

    /// Replaces element `i`'s label (v1.2): an application switches language without rebuilding.
    /// An empty or blank label is refused.
    pub fn relabel(&mut self, i: usize, label: &'static str) -> bool {
        if i >= self.n || label.trim().is_empty() {
            return false;
        }
        self.elements[i].label = label;
        true
    }

    /// Replaces list `i`'s items (v1.2); the selection is clamped into the new range. Only a
    /// list, and only a non-empty set of non-blank items within `MAX_ITEMS`.
    pub fn set_items(&mut self, i: usize, items: &'static [&'static str]) -> bool {
        if i >= self.n
            || self.elements[i].role != Role::List
            || items.is_empty()
            || items.len() > MAX_ITEMS
            || items.iter().any(|t| t.trim().is_empty())
        {
            return false;
        }
        let e = &mut self.elements[i];
        e.items = items;
        if e.selected >= items.len() {
            e.selected = items.len() - 1;
        }
        true
    }

    /// Puts the focus on the first focusable element.
    pub fn start(&mut self) -> Event {
        let mut order = [0usize; MAX_ELEMENTS];
        if self.focus_order(&mut order) == 0 {
            return Event::None;
        }
        self.move_focus(order[0])
    }

    fn move_focus(&mut self, to: usize) -> Event {
        let from = self.focus;
        self.focus = Some(to);
        Event::Focus(from, to)
    }

    fn step(&mut self, back: bool) -> Event {
        let mut order = [0usize; MAX_ELEMENTS];
        let n = self.focus_order(&mut order);
        if n == 0 {
            return Event::None;
        }
        let pos = self
            .focus
            .and_then(|f| order[..n].iter().position(|&i| i == f))
            .unwrap_or(0);
        let next = if back {
            (pos + n - 1) % n
        } else {
            (pos + 1) % n
        };
        self.move_focus(order[next])
    }

    /// One key event (input.md: the code, down or up, the modifiers, the character if any);
    /// only presses act.
    pub fn key(&mut self, code: u32, down: bool, mods: u32, ch: Option<char>) -> Event {
        if !down {
            return Event::None;
        }
        match code {
            KEY_TAB => return self.step(mods & MOD_SHIFT != 0),
            KEY_ESC => return Event::Cancel,
            _ => {}
        }
        let Some(i) = self.focus else {
            return Event::None;
        };
        let rtl = self.rtl;
        let e = &mut self.elements[i];
        match (e.role, code) {
            (Role::Button, KEY_ENTER | KEY_SPACE) => Event::Activate(i),
            (Role::Checkbox, KEY_ENTER | KEY_SPACE) => {
                e.checked = !e.checked;
                Event::Toggle(i, e.checked)
            }
            (Role::List, KEY_UP) if e.selected > 0 => {
                e.selected -= 1;
                Event::Select(i, e.selected)
            }
            (Role::List, KEY_DOWN) if e.selected + 1 < e.items.len() => {
                e.selected += 1;
                Event::Select(i, e.selected)
            }
            (Role::List, KEY_ENTER) => Event::Activate(i),
            (r, KEY_ENTER) if r.is_text() => Event::Activate(i),
            (r, KEY_BACKSPACE) if r.is_text() && e.cursor > 0 => {
                e.text.copy_within(e.cursor..e.text_len, e.cursor - 1);
                e.cursor -= 1;
                e.text_len -= 1;
                // The character that left is not kept behind the length.
                e.text[e.text_len] = 0;
                Event::Edit(i)
            }
            (r, KEY_LEFT | KEY_RIGHT) if r.is_text() => {
                // Logical motion: Right is forward in LTR, Left is forward in RTL (v1.2).
                let forward = (code == KEY_RIGHT) != rtl;
                if forward {
                    if e.cursor < e.text_len {
                        e.cursor += 1;
                    }
                } else if e.cursor > 0 {
                    e.cursor -= 1;
                }
                Event::None
            }
            (r, _) if r.is_text() => match ch {
                Some(c) if e.text_len < TEXT_MAX && !c.is_control() => {
                    e.text.copy_within(e.cursor..e.text_len, e.cursor + 1);
                    e.text[e.cursor] = c as u32;
                    e.cursor += 1;
                    e.text_len += 1;
                    Event::Edit(i)
                }
                _ => Event::None,
            },
            _ => Event::None,
        }
    }

    /// The accessibility description of element `i` (ui.md §2):
    /// `role=<role> label="<label>" state=<states>` plus the value or the selected item.
    pub fn describe(&self, i: usize, out: &mut Text) {
        let e = &self.elements[i];
        out.put(b"role=");
        out.put(e.role.name().as_bytes());
        out.put(b" label=\"");
        out.put(e.label.as_bytes());
        out.put(b"\" state=");
        let focused = self.focus == Some(i);
        let mut states = 0;
        let mut state = |out: &mut Text, s: &[u8]| {
            if states > 0 {
                out.put(b",");
            }
            out.put(s);
            states += 1;
        };
        if focused {
            state(out, b"focused");
        }
        match e.role {
            Role::Label => state(out, b"static"),
            Role::Checkbox => state(out, if e.checked { b"checked" } else { b"unchecked" }),
            _ => {
                if !focused {
                    state(out, b"enabled");
                }
            }
        }
        match e.role {
            Role::List => {
                out.put(b" item=\"");
                out.put(e.items[e.selected].as_bytes());
                out.put(b"\" index=");
                out.num(e.selected + 1);
                out.put(b"/");
                out.num(e.items.len());
            }
            // A password field is described without its value (v1.1).
            Role::TextField => {
                out.put(b" value=\"");
                let mut tmp = [0u8; 4];
                for &cp in &e.text[..e.text_len] {
                    if let Some(c) = char::from_u32(cp) {
                        out.put(c.encode_utf8(&mut tmp).as_bytes());
                    }
                }
                out.put(b"\"");
            }
            _ => {}
        }
    }

    fn row_height(&self, e: &Element) -> i32 {
        let t = &self.theme;
        match e.role {
            Role::Label => t.u(20),
            Role::Button | Role::TextField | Role::Password => t.u(26),
            Role::Checkbox => t.u(22),
            Role::List => t.u(20) * (1 + e.items.len() as i32),
        }
    }

    /// The dialog's size and every element's rectangle (a column with 6-unit padding,
    /// 260 units wide; units scale with the theme).
    pub fn layout(&self, rects: &mut [Rect]) -> (i32, i32) {
        let t = &self.theme;
        let pad = t.u(6);
        let w = t.u(260);
        let mut y = pad;
        for i in 0..self.n {
            let h = self.row_height(&self.elements[i]);
            if i < rects.len() {
                rects[i] = Rect {
                    x: pad,
                    y,
                    w: w - 2 * pad,
                    h,
                };
            }
            y += h + pad;
        }
        (w, y)
    }

    pub fn font_px(&self) -> u32 {
        14 * self.theme.scale / 4
    }
}

/// Drawing state (the text layout and its glyph buffer), owned by the application.
pub struct Painter {
    pub layout: Layout,
    glyphs: [Glyph; 64],
    text: [u32; 64],
}

impl Default for Painter {
    fn default() -> Self {
        Self::new()
    }
}

fn fill(buf: &mut [u32], w: usize, h: usize, r: Rect, rgb: u32) {
    let x0 = r.x.max(0) as usize;
    let y0 = r.y.max(0) as usize;
    let x1 = ((r.x + r.w).max(0) as usize).min(w);
    let y1 = ((r.y + r.h).max(0) as usize).min(h);
    for y in y0..y1 {
        buf[y * w + x0.min(x1)..y * w + x1].fill(rgb);
    }
}

fn frame(buf: &mut [u32], w: usize, h: usize, r: Rect, t: i32, rgb: u32) {
    fill(buf, w, h, Rect { h: t, ..r }, rgb);
    fill(
        buf,
        w,
        h,
        Rect {
            y: r.y + r.h - t,
            h: t,
            ..r
        },
        rgb,
    );
    fill(buf, w, h, Rect { w: t, ..r }, rgb);
    fill(
        buf,
        w,
        h,
        Rect {
            x: r.x + r.w - t,
            w: t,
            ..r
        },
        rgb,
    );
}

impl Painter {
    pub const fn new() -> Painter {
        Painter {
            layout: Layout::new(),
            glyphs: [Glyph {
                font: 0,
                gid: 0,
                x: 0,
                advance: 0,
                cluster: 0,
            }; 64],
            text: [0; 64],
        }
    }

    /// Draws one string inside `r` (start-aligned by the dialog's direction, or centred),
    /// vertically centred.
    #[allow(clippy::too_many_arguments)]
    fn string(
        &mut self,
        fonts: &Fonts,
        s: &[u32],
        px: u32,
        r: Rect,
        rtl: bool,
        centred: bool,
        fg: u32,
        buf: &mut [u32],
        w: usize,
        h: usize,
    ) {
        let base = if rtl { Base::Rtl } else { Base::Ltr };
        let (n, width) = self.layout.line(fonts, s, base, px, &mut self.glyphs);
        let tw = (width + 32) / 64;
        let inset = (px as i32) / 2;
        let x0 = if centred {
            r.x + (r.w - tw) / 2
        } else if rtl {
            r.x + r.w - inset - tw
        } else {
            r.x + inset
        };
        let baseline = r.y + (r.h + px as i32 * 7 / 10) / 2;
        let mut canvas = RgbCanvas { buf, w, h, fg };
        let glyphs = self.glyphs;
        self.layout
            .draw(fonts, &glyphs[..n], px, x0, baseline, &mut canvas);
    }

    fn str_chars(&mut self, s: &str) -> usize {
        utf8_chars(s, &mut self.text)
    }

    /// Draws the dialog into `buf` (`w × h` pixels of `0xRRGGBB`, the size `layout` gave).
    pub fn paint(&mut self, d: &Dialog, fonts: &Fonts, buf: &mut [u32], w: usize, h: usize) {
        let p = d.theme.palette();
        let t = &d.theme;
        let px = d.font_px();
        let ring = t.u(2).max(2);
        fill(
            buf,
            w,
            h,
            Rect {
                x: 0,
                y: 0,
                w: w as i32,
                h: h as i32,
            },
            p.bg,
        );
        let mut rects = [Rect::default(); MAX_ELEMENTS];
        d.layout(&mut rects);
        for (i, &r) in rects.iter().enumerate().take(d.n) {
            let e = d.elements[i];
            let focused = d.focus == Some(i);
            match e.role {
                Role::Label => {
                    let n = self.str_chars(e.label);
                    let s = self.text;
                    self.string(fonts, &s[..n], px, r, d.rtl, false, p.fg, buf, w, h);
                }
                Role::Button => {
                    fill(buf, w, h, r, p.button);
                    frame(buf, w, h, r, 1, p.border);
                    let n = self.str_chars(e.label);
                    let s = self.text;
                    self.string(fonts, &s[..n], px, r, d.rtl, true, p.fg, buf, w, h);
                }
                Role::TextField | Role::Password => {
                    fill(buf, w, h, r, p.control);
                    frame(buf, w, h, r, 1, p.border);
                    if e.text_len == 0 {
                        let n = self.str_chars(e.label);
                        let s = self.text;
                        self.string(
                            fonts,
                            &s[..n],
                            px,
                            r,
                            d.rtl,
                            false,
                            p.placeholder,
                            buf,
                            w,
                            h,
                        );
                    } else {
                        // A password shows one bullet per character, never the characters.
                        let mut s = e.text;
                        if e.role == Role::Password {
                            s[..e.text_len].fill(BULLET);
                        }
                        self.string(
                            fonts,
                            &s[..e.text_len],
                            px,
                            r,
                            d.rtl,
                            false,
                            p.fg,
                            buf,
                            w,
                            h,
                        );
                    }
                }
                Role::Checkbox => {
                    let side = r.h - t.u(8);
                    let bx = if d.rtl {
                        r.x + r.w - side - t.u(2)
                    } else {
                        r.x + t.u(2)
                    };
                    let bxr = Rect {
                        x: bx,
                        y: r.y + t.u(4),
                        w: side,
                        h: side,
                    };
                    fill(buf, w, h, bxr, p.control);
                    frame(buf, w, h, bxr, 1, p.border);
                    if e.checked {
                        let inner = t.u(3);
                        fill(
                            buf,
                            w,
                            h,
                            Rect {
                                x: bx + inner,
                                y: bxr.y + inner,
                                w: side - 2 * inner,
                                h: side - 2 * inner,
                            },
                            p.check,
                        );
                    }
                    let text_r = if d.rtl {
                        Rect {
                            w: r.w - side - t.u(6),
                            ..r
                        }
                    } else {
                        Rect {
                            x: r.x + side + t.u(6),
                            w: r.w - side - t.u(6),
                            ..r
                        }
                    };
                    let n = self.str_chars(e.label);
                    let s = self.text;
                    self.string(fonts, &s[..n], px, text_r, d.rtl, false, p.fg, buf, w, h);
                }
                Role::List => {
                    let row = t.u(20);
                    let head = Rect { h: row, ..r };
                    let n = self.str_chars(e.label);
                    let s = self.text;
                    self.string(fonts, &s[..n], px, head, d.rtl, false, p.fg, buf, w, h);
                    let body = Rect {
                        y: r.y + row,
                        h: r.h - row,
                        ..r
                    };
                    fill(buf, w, h, body, p.control);
                    frame(buf, w, h, body, 1, p.border);
                    for (k, item) in e.items.iter().enumerate() {
                        let ir = Rect {
                            x: body.x + 1,
                            y: body.y + row * k as i32,
                            w: body.w - 2,
                            h: row,
                        };
                        let fg = if k == e.selected {
                            fill(
                                buf,
                                w,
                                h,
                                Rect {
                                    y: ir.y + 1,
                                    h: ir.h - 1,
                                    ..ir
                                },
                                p.selected_bg,
                            );
                            p.selected_fg
                        } else {
                            p.fg
                        };
                        let n = self.str_chars(item);
                        let s = self.text;
                        self.string(fonts, &s[..n], px, ir, d.rtl, false, fg, buf, w, h);
                    }
                }
            }
            if focused {
                let fr = Rect {
                    x: r.x - ring,
                    y: r.y - ring,
                    w: r.w + 2 * ring,
                    h: r.h + 2 * ring,
                };
                frame(buf, w, h, fr, ring, p.focus);
            }
        }
    }
}

#[cfg(test)]
mod tests;
