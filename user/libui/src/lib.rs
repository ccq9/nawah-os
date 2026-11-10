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
//!
//! v1.5 (WP-38, ui.md §3.5): `Painter::fits` — whether a label or value fits its row as
//! painted, for an application that must not show a text cut by the surface's edge.
//!
//! v1.6 (WP-49, ui.md §3.6): the pointer (`Dialog::pointer`: hit-testing every element from
//! the layout, press focuses, release over the same element activates, a list row selects and
//! a second click within `DOUBLE_CLICK_MS` activates) and one context menu per dialog
//! (`set_menu`, `open_menu`; Shift+F10, the menu key or a right press), drawn as an overlay in
//! the dialog's own surface. Menu outcomes come from `take_menu_event` so that `Event` keeps
//! its v1 variants. Behaviour follows the W3C WAI-ARIA Authoring Practices menu pattern.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use nawah_text::bidi::Base;
use nawah_text::layout::{Fonts, Glyph, Layout, RgbCanvas};

pub const MAX_ELEMENTS: usize = 12;
pub const MAX_ITEMS: usize = 6;
pub const TEXT_MAX: usize = 48;

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
/// F10 (Shift+F10 opens the context menu, v1.6).
pub const KEY_F10: u32 = 0x44;
/// The menu key: extended scancode 0x5d, sent by inputd as 0x80 | 0x5d (v1.6).
pub const KEY_MENU: u32 = 0xdd;
/// Pointer buttons as input.md `PTR` sends them: bit 0 left, bit 1 right (v1.6).
pub const BUTTON_LEFT: u32 = 1;
pub const BUTTON_RIGHT: u32 = 2;
/// At most this many menu entries, separators included (v1.6).
pub const MAX_MENU: usize = 8;
/// Two left clicks on the same list row this close (ms, release to release) activate the list
/// (v1.6). nawah's own value, not taken from any reference system (ui.md §3.6).
pub const DOUBLE_CLICK_MS: u64 = 400;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Label,
    Button,
    TextField,
    List,
    Checkbox,
    /// A text field whose characters are drawn as bullets and never described (v1.1).
    Password,
    /// Text the application sets and the user only reads (v1.3): drawn like a label, described
    /// with its value, never focused — the session shows who asks and what is asked with it.
    Value,
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
            Role::Value => "value",
        }
    }
    pub fn focusable(self) -> bool {
        !matches!(self, Role::Label | Role::Value)
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

/// One entry of a context menu (v1.6): a labelled item, enabled or not, or a separator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MenuItem {
    pub label: &'static str,
    pub enabled: bool,
    pub separator: bool,
}

impl MenuItem {
    pub const SEPARATOR: MenuItem = MenuItem {
        label: "",
        enabled: false,
        separator: true,
    };
    pub const fn item(label: &'static str, enabled: bool) -> MenuItem {
        MenuItem {
            label,
            enabled,
            separator: false,
        }
    }
}

/// What a key or pointer event did to the context menu (v1.6), read with `take_menu_event`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MenuEvent {
    /// The menu opened for this element; its first item has the focus.
    Open(usize),
    /// The focus moved to this menu entry.
    Focus(usize),
    /// The menu closed without a choice; the focus is back on this element.
    Close(usize),
    /// The element's menu entry was chosen; the menu closed and the focus is back on it.
    Choose(usize, usize),
}

#[derive(Clone, Copy)]
struct OpenMenu {
    owner: usize,
    focus: usize,
    ax: i32,
    ay: i32,
}

fn contains(r: Rect, x: i32, y: i32) -> bool {
    x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h
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
    menu: &'static [MenuItem],
    open: Option<OpenMenu>,
    buttons: u32,
    press: Option<(usize, Option<usize>)>,
    menu_press: Option<usize>,
    last_click: Option<(usize, usize, u64)>,
    pending: Option<MenuEvent>,
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
            menu: &[],
            open: None,
            buttons: 0,
            press: None,
            menu_press: None,
            last_click: None,
            pending: None,
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
        if self.open.is_some() || i >= self.n || !self.elements[i].role.focusable() {
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

    /// Puts `text` into text field or value `i` (not a password: an application never fills
    /// one); `false` when refused. Characters beyond the field's capacity are dropped.
    pub fn set_value(&mut self, i: usize, text: &str) -> bool {
        if i >= self.n || !matches!(self.elements[i].role, Role::TextField | Role::Value) {
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
        self.pending = None;
        if !down {
            return Event::None;
        }
        if self.open.is_some() {
            self.menu_key(code);
            return Event::None;
        }
        if (code == KEY_F10 && mods & MOD_SHIFT != 0) || code == KEY_MENU {
            if let Some(i) = self.focus {
                if self.open_menu(i) {
                    return Event::None;
                }
            }
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
            Role::Label | Role::Value => state(out, b"static"),
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
            Role::TextField | Role::Value => {
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
            Role::Label | Role::Value => t.u(20),
            Role::Button | Role::TextField | Role::Password => t.u(26),
            Role::Checkbox => t.u(22),
            Role::List => t.u(20) * (1 + e.items.len() as i32),
        }
    }

    /// The width of every row (the dialog's width less its padding on both sides).
    fn row_width(&self) -> i32 {
        let t = &self.theme;
        t.u(260) - 2 * t.u(6)
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
                    w: self.row_width(),
                    h,
                };
            }
            y += h + pad;
        }
        // v1.6: the surface holds the dialog's menu, which is drawn inside it.
        if !self.menu.is_empty() {
            y = y.max(self.menu_height() + 2 * pad);
        }
        (w, y)
    }

    pub fn font_px(&self) -> u32 {
        14 * self.theme.scale / 4
    }

    // ---- v1.6: the pointer -------------------------------------------------------------

    /// The element under `(x, y)` (surface coordinates), from the layout.
    fn hit(&self, x: i32, y: i32) -> Option<usize> {
        let mut rects = [Rect::default(); MAX_ELEMENTS];
        self.layout(&mut rects);
        (0..self.n).find(|&i| contains(rects[i], x, y))
    }

    /// The list row under `y` in list `i`; `None` for the header and for other roles.
    fn list_row(&self, i: usize, y: i32) -> Option<usize> {
        let e = &self.elements[i];
        if e.role != Role::List {
            return None;
        }
        let mut rects = [Rect::default(); MAX_ELEMENTS];
        self.layout(&mut rects);
        let k = (y - rects[i].y) / self.theme.u(20);
        if k >= 1 && ((k - 1) as usize) < e.items.len() {
            Some((k - 1) as usize)
        } else {
            None
        }
    }

    /// One pointer report (v1.6): the position in the surface, the buttons held (bit 0 left,
    /// bit 1 right) and the time. Only changes of the buttons act: a left press focuses the
    /// focusable element under it (a list row is selected, the header selects nothing), a left
    /// release over the element pressed activates a button, toggles a checkbox, and on the
    /// same list row a second time within `DOUBLE_CLICK_MS` activates the list; a right press
    /// on a focusable element opens the context menu there. While the menu is open every
    /// press and release is the menu's (see `take_menu_event`).
    pub fn pointer(&mut self, x: i32, y: i32, buttons: u32, now_ms: u64) -> Event {
        self.pending = None;
        let pressed = buttons & !self.buttons;
        let released = self.buttons & !buttons;
        self.buttons = buttons;
        if self.open.is_some() {
            if pressed & (BUTTON_LEFT | BUTTON_RIGHT) != 0 {
                self.menu_press = None;
                if !self.menu_rect().is_some_and(|m| contains(m, x, y)) {
                    self.close_menu();
                    return Event::None;
                }
                if let Some(k) = self.menu_hit(x, y) {
                    if pressed & BUTTON_LEFT != 0 {
                        self.menu_press = Some(k);
                    }
                    self.menu_focus(k);
                }
            } else if released & BUTTON_LEFT != 0 {
                if let Some(k) = self.menu_press.take() {
                    if self.menu_hit(x, y) == Some(k) {
                        self.choose(k);
                    }
                }
            }
            return Event::None;
        }
        if pressed & BUTTON_LEFT != 0 {
            return self.press_left(x, y);
        }
        if released & BUTTON_LEFT != 0 {
            return self.release_left(x, y, now_ms);
        }
        if pressed & BUTTON_RIGHT != 0 {
            self.press_right(x, y);
        }
        Event::None
    }

    fn press_left(&mut self, x: i32, y: i32) -> Event {
        self.press = None;
        let Some(i) = self
            .hit(x, y)
            .filter(|&i| self.elements[i].role.focusable())
        else {
            return Event::None;
        };
        let row = self.list_row(i, y);
        if self
            .last_click
            .is_some_and(|(j, k, _)| (j, Some(k)) != (i, row))
        {
            self.last_click = None;
        }
        self.press = Some((i, row));
        let ev = if self.focus != Some(i) {
            self.move_focus(i)
        } else {
            Event::None
        };
        if let Some(k) = row {
            let e = &mut self.elements[i];
            if e.selected != k {
                e.selected = k;
                if ev == Event::None {
                    return Event::Select(i, k);
                }
            }
        }
        ev
    }

    fn release_left(&mut self, x: i32, y: i32, now_ms: u64) -> Event {
        let Some((i, row)) = self.press.take() else {
            return Event::None;
        };
        if self.hit(x, y) != Some(i) || self.list_row(i, y) != row {
            return Event::None;
        }
        match self.elements[i].role {
            Role::Button => Event::Activate(i),
            Role::Checkbox => {
                let e = &mut self.elements[i];
                e.checked = !e.checked;
                Event::Toggle(i, e.checked)
            }
            Role::List => {
                let Some(k) = row else {
                    return Event::None;
                };
                if let Some((j, kk, t)) = self.last_click.take() {
                    if (j, kk) == (i, k) && now_ms.saturating_sub(t) <= DOUBLE_CLICK_MS {
                        return Event::Activate(i);
                    }
                }
                self.last_click = Some((i, k, now_ms));
                Event::None
            }
            _ => Event::None,
        }
    }

    fn press_right(&mut self, x: i32, y: i32) {
        let Some(i) = self.hit(x, y) else {
            return;
        };
        if !self.elements[i].role.focusable() || self.menu.is_empty() {
            return;
        }
        // A right press on a list row is a context menu for that row.
        if let Some(k) = self.list_row(i, y) {
            self.elements[i].selected = k;
        }
        self.open_at(i, x, y);
    }

    // ---- v1.6: the context menu --------------------------------------------------------

    /// Sets the dialog's context menu (v1.6): 1 to `MAX_MENU` entries with at least one item;
    /// every item has a non-blank label. `false` when refused. An open menu keeps open with
    /// the focus on its first item (an application switching language).
    pub fn set_menu(&mut self, items: &'static [MenuItem]) -> bool {
        if items.is_empty()
            || items.len() > MAX_MENU
            || items.iter().all(|m| m.separator)
            || items
                .iter()
                .any(|m| !m.separator && m.label.trim().is_empty())
        {
            return false;
        }
        self.menu = items;
        let first = self.first_item();
        if let Some(m) = self.open.as_mut() {
            m.focus = first;
        }
        true
    }

    fn first_item(&self) -> usize {
        self.menu.iter().position(|m| !m.separator).unwrap_or(0)
    }

    /// Opens the context menu for focusable element `i` below it, from its start edge (the
    /// left in LTR, the right in RTL). `false` without a menu, for a label or a value, or
    /// when a menu is already open.
    pub fn open_menu(&mut self, i: usize) -> bool {
        if i >= self.n
            || !self.elements[i].role.focusable()
            || self.menu.is_empty()
            || self.open.is_some()
        {
            return false;
        }
        let mut rects = [Rect::default(); MAX_ELEMENTS];
        self.layout(&mut rects);
        let r = rects[i];
        let ax = if self.rtl { r.x + r.w } else { r.x };
        self.open_at(i, ax, r.y + r.h);
        true
    }

    fn open_at(&mut self, owner: usize, ax: i32, ay: i32) {
        self.press = None;
        self.menu_press = None;
        self.open = Some(OpenMenu {
            owner,
            focus: self.first_item(),
            ax,
            ay,
        });
        self.focus = None;
        self.pending = Some(MenuEvent::Open(owner));
    }

    /// Closes the menu; the focus returns to the element it was opened for.
    fn close_menu(&mut self) -> usize {
        let Some(m) = self.open.take() else {
            return 0;
        };
        let owner = m.owner;
        self.focus = Some(owner);
        self.pending = Some(MenuEvent::Close(owner));
        owner
    }

    /// Chooses entry `k` if it is an enabled item; a disabled item is never chosen.
    fn choose(&mut self, k: usize) {
        let it = self.menu[k];
        if it.separator || !it.enabled {
            return;
        }
        let owner = self.close_menu();
        self.pending = Some(MenuEvent::Choose(owner, k));
    }

    fn menu_focus(&mut self, k: usize) {
        if let Some(m) = self.open.as_mut() {
            if m.focus != k {
                m.focus = k;
                self.pending = Some(MenuEvent::Focus(k));
            }
        }
    }

    /// Keys while the menu is open: Up/Down move (wrapping, over separators), Enter chooses,
    /// Esc closes; every other key (Tab included) is ignored.
    fn menu_key(&mut self, code: u32) {
        let Some(m) = self.open else {
            return;
        };
        let n = self.menu.len();
        match code {
            KEY_ESC => {
                self.close_menu();
            }
            KEY_ENTER => self.choose(m.focus),
            KEY_UP | KEY_DOWN => {
                let mut k = m.focus;
                for _ in 0..n {
                    k = if code == KEY_UP {
                        (k + n - 1) % n
                    } else {
                        (k + 1) % n
                    };
                    if !self.menu[k].separator {
                        break;
                    }
                }
                self.menu_focus(k);
            }
            _ => {}
        }
    }

    /// What the last `key` or `pointer` call did to the menu, once (v1.6).
    pub fn take_menu_event(&mut self) -> Option<MenuEvent> {
        self.pending.take()
    }

    /// The focused menu entry while the menu is open.
    pub fn menu_focused(&self) -> Option<usize> {
        self.open.map(|m| m.focus)
    }

    /// The number of menu items (separators not counted): the `n` of `index=k/n`.
    pub fn menu_len(&self) -> usize {
        self.menu.iter().filter(|m| !m.separator).count()
    }

    fn menu_width(&self) -> i32 {
        self.theme.u(160)
    }

    fn menu_entry_h(&self, m: &MenuItem) -> i32 {
        if m.separator {
            self.theme.u(8)
        } else {
            self.theme.u(20)
        }
    }

    fn menu_height(&self) -> i32 {
        2 * self.theme.u(2) + self.menu.iter().map(|m| self.menu_entry_h(m)).sum::<i32>()
    }

    /// The open menu's rectangle in the dialog's surface. It opens toward the reading
    /// direction from its anchor (rightwards in LTR, leftwards in RTL), flips to the other
    /// side when it would cross the surface's edge, and is clamped inside the surface.
    pub fn menu_rect(&self) -> Option<Rect> {
        let m = self.open?;
        let (sw, sh) = self.layout(&mut []);
        let (w, h) = (self.menu_width(), self.menu_height());
        let x = if self.rtl {
            let opened = m.ax - w;
            if opened < 0 {
                m.ax
            } else {
                opened
            }
        } else if m.ax + w > sw {
            m.ax - w
        } else {
            m.ax
        };
        Some(Rect {
            x: x.min(sw - w).max(0),
            y: m.ay.min(sh - h).max(0),
            w,
            h,
        })
    }

    /// Entry `k`'s rectangle while the menu is open.
    pub fn menu_item_rect(&self, k: usize) -> Option<Rect> {
        let m = self.menu_rect()?;
        if k >= self.menu.len() {
            return None;
        }
        let y = m.y
            + self.theme.u(2)
            + self.menu[..k]
                .iter()
                .map(|e| self.menu_entry_h(e))
                .sum::<i32>();
        Some(Rect {
            x: m.x + 1,
            y,
            w: m.w - 2,
            h: self.menu_entry_h(&self.menu[k]),
        })
    }

    /// The menu item (not a separator) under `(x, y)`.
    fn menu_hit(&self, x: i32, y: i32) -> Option<usize> {
        (0..self.menu.len()).find(|&k| {
            !self.menu[k].separator && self.menu_item_rect(k).is_some_and(|r| contains(r, x, y))
        })
    }

    /// Menu entry `k`'s description (ui.md §3.6):
    /// `role=menuitem label="<label>" state=<focused|enabled>[,disabled] index=<k>/<n>`;
    /// the number of bytes written, or `None` (nothing written) when `k` is no entry of the
    /// menu (no menu set, or `k` out of range).
    pub fn describe_menu_item(&self, k: usize, out: &mut Text) -> Option<usize> {
        let it = self.menu.get(k)?;
        let start = out.len;
        out.put(b"role=menuitem label=\"");
        out.put(it.label.as_bytes());
        out.put(b"\" state=");
        let focused = self.menu_focused() == Some(k);
        if focused {
            out.put(b"focused");
            if !it.enabled {
                out.put(b",disabled");
            }
        } else {
            out.put(if it.enabled { b"enabled" } else { b"disabled" });
        }
        out.put(b" index=");
        out.num(self.menu[..k].iter().filter(|m| !m.separator).count() + 1);
        out.put(b"/");
        out.num(self.menu_len());
        Some(out.len - start)
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
        let (n, tw) = self.measure(fonts, s, px, rtl);
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

    /// Lays `s` out into the glyph buffer as `string` draws it: the glyph count and the
    /// width in whole pixels.
    fn measure(&mut self, fonts: &Fonts, s: &[u32], px: u32, rtl: bool) -> (usize, i32) {
        let base = if rtl { Base::Rtl } else { Base::Ltr };
        let (n, width) = self.layout.line(fonts, s, base, px, &mut self.glyphs);
        (n, (width + 32) / 64)
    }

    /// Whether `s`, drawn as a label or a value of `d`, fits its row in full (v1.5): measured
    /// by the same layout `paint` draws with (the dialog's font size and direction), from the
    /// start inset to no further than the row's other end. The surface drops what falls
    /// outside it without a trace (`RgbCanvas`), so an application that must show a text in
    /// full (session.md v1.5: the elevation prompt) asks this before it shows it. The row's
    /// end, not a second inset, is the bound: the dialog's padding already lies between it
    /// and the surface's edge, and a second inset would refuse text of which nothing is cut
    /// (the lab's `config SET device lab.elev2 0 902 on` is 235 of 241 pixels at 1×). More
    /// than TEXT_MAX characters never fits: a value keeps no more.
    pub fn fits(&mut self, d: &Dialog, fonts: &Fonts, s: &str) -> bool {
        let mut chars = [0u32; TEXT_MAX + 1];
        let n = utf8_chars(s, &mut chars);
        if n > TEXT_MAX {
            return false;
        }
        let px = d.font_px();
        let (_, tw) = self.measure(fonts, &chars[..n], px, d.rtl);
        tw <= d.row_width() - (px as i32) / 2
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
                // The value alone is drawn; its label names it for the narrator (a label
                // element above it says the same on the screen).
                Role::Value => {
                    let s = e.text;
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
        // v1.6: the open context menu, over the elements in the same surface.
        if let Some(m) = d.menu_rect() {
            fill(buf, w, h, m, p.control);
            frame(buf, w, h, m, 1, p.border);
            let inset = t.u(6);
            for (k, it) in d.menu.iter().enumerate() {
                let Some(ir) = d.menu_item_rect(k) else {
                    continue;
                };
                if it.separator {
                    let line = Rect {
                        x: ir.x + inset,
                        y: ir.y + ir.h / 2,
                        w: ir.w - 2 * inset,
                        h: 1,
                    };
                    fill(buf, w, h, line, p.border);
                    continue;
                }
                let focused = d.menu_focused() == Some(k);
                if focused {
                    fill(buf, w, h, ir, p.selected_bg);
                }
                let fg = if !it.enabled {
                    p.placeholder
                } else if focused {
                    p.selected_fg
                } else {
                    p.fg
                };
                let tr = Rect {
                    x: ir.x + inset,
                    w: ir.w - 2 * inset,
                    ..ir
                };
                let n = self.str_chars(it.label);
                let s = self.text;
                self.string(fonts, &s[..n], px, tr, d.rtl, false, fg, buf, w, h);
            }
        }
    }
}

#[cfg(test)]
mod tests;
