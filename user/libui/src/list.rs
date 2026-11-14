//! v1.8 (WP-50, 50a; ui.md §3.8): the virtualised list view. The application owns the rows,
//! their values and their order (`RowSource`); the view keeps only its own state: the row
//! count, the first visible position, the focused position and the anchor, the current column,
//! the sort the application last applied, and the selection as a set of row ids. So a sort
//! moves the rows, never the selection. No allocation, no `unsafe`.
//!
//! Keys follow the W3C WAI-ARIA Authoring Practices grid and listbox patterns (S81, unverified
//! until read); the type-ahead window, `Ctrl+<digit>` for sorting, the narrator line format and
//! the layout units are nawah's own (ADR-0022).

use crate::{
    Rect, Text, Theme, KEY_DOWN, KEY_END, KEY_ENTER, KEY_HOME, KEY_LEFT, KEY_PGDN, KEY_PGUP,
    KEY_RIGHT, KEY_SPACE, KEY_UP, MOD_CTRL, MOD_SHIFT,
};

/// The most columns of one view.
pub const MAX_COLUMNS: usize = 8;
/// The most rows of one view (row ids are below it; the selection is a bit per id).
pub const MAX_ROWS: usize = 16_384;
/// Characters typed within this many milliseconds of the previous one extend the search.
pub const TYPEAHEAD_MS: u64 = 1_000;
/// Characters typed past this many in one search are dropped.
pub const TYPEAHEAD_MAX: usize = 16;
/// Layout units (x the scale): the header and each row are 20 high, a cell's text is 4 in.
const ROW_UNITS: i32 = 20;
const PAD_UNITS: i32 = 4;
/// Room kept at the end of a row line for ` more=<j>` (j <= MAX_COLUMNS).
const MORE_ROOM: usize = 7;

/// One column: its name (the application's whole word or phrase), width in layout units, and
/// whether its values are numbers (drawn at the trailing edge).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Column {
    pub name: &'static str,
    pub width: i32,
    pub numeric: bool,
}

/// The application's rows. `order(pos)` is the id at a display position (`pos < rows()`),
/// `cell` writes a value (UTF-8) of a row id, `sort` reorders the rows stably (see
/// `stable_sort`) and returns false when it did not. The view asks for nothing at or beyond
/// `rows()`.
pub trait RowSource {
    fn rows(&self) -> usize;
    fn order(&self, pos: usize) -> usize;
    fn cell(&self, id: usize, col: usize, out: &mut Text);
    fn sort(&mut self, col: usize, ascending: bool) -> bool;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ListError {
    /// A blank list label or column name.
    NoLabel,
    NoColumns,
    /// More than `MAX_COLUMNS` columns.
    TooManyColumns,
    /// More than `MAX_ROWS` rows.
    TooManyRows,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ListEvent {
    None,
    /// The focus moved to this row id.
    Focus(usize),
    /// The selection changed; this many rows are selected.
    Select(usize),
    /// Enter on this row id.
    Activate(usize),
    /// The application sorted by this column, ascending or not.
    Sort(usize, bool),
    /// The current column changed.
    Column(usize),
}

/// Sorts `ids` stably by `before` (a strict "comes before"), with `scratch` at least as long;
/// a bottom-up merge, no allocation. False, and `ids` untouched, when `scratch` is shorter.
#[must_use]
pub fn stable_sort(
    ids: &mut [u16],
    scratch: &mut [u16],
    mut before: impl FnMut(u16, u16) -> bool,
) -> bool {
    let n = ids.len();
    if scratch.len() < n {
        return false;
    }
    let mut width = 1;
    while width < n {
        let mut lo = 0;
        while lo < n {
            let mid = (lo + width).min(n);
            let hi = (lo + 2 * width).min(n);
            let (mut i, mut j, mut k) = (lo, mid, lo);
            while i < mid && j < hi {
                // Equal keys: the left one first, so the sort is stable.
                if before(ids[j], ids[i]) {
                    scratch[k] = ids[j];
                    j += 1;
                } else {
                    scratch[k] = ids[i];
                    i += 1;
                }
                k += 1;
            }
            scratch[k..k + (mid - i)].copy_from_slice(&ids[i..mid]);
            k += mid - i;
            scratch[k..k + (hi - j)].copy_from_slice(&ids[j..hi]);
            lo = hi;
        }
        ids.copy_from_slice(&scratch[..n]);
        width *= 2;
    }
    true
}

/// An explicit bidi formatting character (UAX #9: ALM, LRM, RLM, LRE..RLO, LRI..PDI). In a
/// cell it is shown and named, never obeyed: a name cannot reorder its own extension.
fn is_bidi_control(c: u32) -> bool {
    matches!(c, 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

/// A control character (C0, DEL, C1) or the line and paragraph separators U+2028/U+2029: in a
/// cell it would end a narrator line, split a paragraph or draw nothing.
fn is_control(c: u32) -> bool {
    c < 0x20 || (0x7F..=0x9F).contains(&c) || c == 0x2028 || c == 0x2029
}

/// The characters to draw for a cell value: each bidi formatting character and each control
/// character replaced by U+FFFD.
pub fn cell_chars(s: &str, out: &mut [u32]) -> usize {
    let mut n = 0;
    for c in s.chars() {
        if n == out.len() {
            break;
        }
        let c = c as u32;
        out[n] = if is_bidi_control(c) || is_control(c) {
            0xFFFD
        } else {
            c
        };
        n += 1;
    }
    n
}

fn hex(out: &mut Text, v: u32) {
    let d = b"0123456789ABCDEF";
    let mut b = [0u8; 6];
    let mut len = 0;
    let mut v = v;
    loop {
        b[len] = d[(v & 15) as usize];
        len += 1;
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    while len < 4 {
        b[len] = b'0';
        len += 1;
    }
    for i in (0..len).rev() {
        out.put(&b[i..i + 1]);
    }
}

/// The value as the narrator line carries it: bidi formatting characters, control characters
/// and the quote written `[U+XXXX]`, so a value never ends itself, its line or its direction.
fn put_value(out: &mut Text, v: &[u8]) {
    let s = match core::str::from_utf8(v) {
        Ok(s) => s,
        Err(e) => core::str::from_utf8(&v[..e.valid_up_to()]).unwrap_or(""),
    };
    let mut buf = [0u8; 4];
    for c in s.chars() {
        let u = c as u32;
        if is_bidi_control(u) || is_control(u) || c == '"' {
            out.put(b"[U+");
            hex(out, c as u32);
            out.put(b"]");
        } else {
            out.put(c.encode_utf8(&mut buf).as_bytes());
        }
    }
}

fn blank(s: &str) -> bool {
    s.chars().all(char::is_whitespace)
}

pub struct ListView {
    label: &'static str,
    columns: &'static [Column],
    multi: bool,
    rtl: bool,
    theme: Theme,
    area: Rect,
    n: usize,
    top: usize,
    focus: usize,
    anchor: usize,
    col: usize,
    sort: Option<(usize, bool)>,
    denied: Option<&'static str>,
    sel: [u64; MAX_ROWS / 64],
    count: usize,
    typed: [char; TYPEAHEAD_MAX],
    typed_len: usize,
    typed_at: u64,
}

impl ListView {
    /// A view with no rows yet (`reset` gives them). A blank label or column name is refused.
    pub fn new(
        label: &'static str,
        columns: &'static [Column],
        multi: bool,
        rtl: bool,
    ) -> Result<ListView, ListError> {
        if blank(label) {
            return Err(ListError::NoLabel);
        }
        if columns.is_empty() {
            return Err(ListError::NoColumns);
        }
        if columns.len() > MAX_COLUMNS {
            return Err(ListError::TooManyColumns);
        }
        if columns.iter().any(|c| blank(c.name)) {
            return Err(ListError::NoLabel);
        }
        Ok(ListView {
            label,
            columns,
            multi,
            rtl,
            theme: Theme::DEFAULT,
            area: Rect::default(),
            n: 0,
            top: 0,
            focus: 0,
            anchor: 0,
            col: 0,
            sort: None,
            denied: None,
            sel: [0; MAX_ROWS / 64],
            count: 0,
            typed: ['\0'; TYPEAHEAD_MAX],
            typed_len: 0,
            typed_at: 0,
        })
    }

    pub fn set_theme(&mut self, theme: Theme) {
        self.theme = theme;
        self.scroll_to_focus();
    }

    pub fn set_rtl(&mut self, rtl: bool) {
        self.rtl = rtl;
    }

    /// The view's rectangle in the surface: the header, then the rows.
    pub fn set_area(&mut self, area: Rect) {
        self.area = area;
        self.scroll_to_focus();
    }

    /// New rows from the application: the first focused, nothing selected, a denial ended.
    pub fn reset(&mut self, src: &dyn RowSource) -> Result<(), ListError> {
        let n = src.rows();
        if n > MAX_ROWS {
            return Err(ListError::TooManyRows);
        }
        self.n = n;
        self.denied = None;
        self.clear_rows();
        Ok(())
    }

    /// The application could not read the rows: no rows, and the reason (its whole sentence)
    /// is described instead. Never described as empty.
    pub fn deny(&mut self, reason: &'static str) {
        self.n = 0;
        self.denied = Some(reason);
        self.clear_rows();
    }

    /// Also ends the sort and the current column: new rows (or none) are in the application's
    /// order until it sorts again, and the narrator never says otherwise.
    fn clear_rows(&mut self) {
        self.sort = None;
        self.col = 0;
        self.top = 0;
        self.focus = 0;
        self.anchor = 0;
        self.sel = [0; MAX_ROWS / 64];
        self.count = 0;
        self.typed_len = 0;
    }

    pub fn rows(&self) -> usize {
        self.n
    }

    /// The first visible position and how many rows are visible (`top + count <= rows()`).
    pub fn visible(&self) -> (usize, usize) {
        (self.top, self.page().min(self.n - self.top))
    }

    pub fn focus_pos(&self) -> Option<usize> {
        (self.n > 0).then_some(self.focus)
    }

    pub fn focused_id(&self, src: &dyn RowSource) -> Option<usize> {
        (self.n > 0).then(|| src.order(self.focus))
    }

    pub fn column(&self) -> usize {
        self.col
    }

    pub fn sorted(&self) -> Option<(usize, bool)> {
        self.sort
    }

    pub fn is_selected(&self, id: usize) -> bool {
        id < self.n && self.sel[id / 64] & (1 << (id % 64)) != 0
    }

    pub fn selected_count(&self) -> usize {
        self.count
    }

    fn set_sel(&mut self, id: usize, on: bool) {
        if id >= self.n || self.is_selected(id) == on {
            return;
        }
        if on {
            self.sel[id / 64] |= 1 << (id % 64);
            self.count += 1;
        } else {
            self.sel[id / 64] &= !(1 << (id % 64));
            self.count -= 1;
        }
    }

    fn clear_sel(&mut self) {
        self.sel = [0; MAX_ROWS / 64];
        self.count = 0;
    }

    /// Rows that fit under the header (at least one).
    fn page(&self) -> usize {
        let row = self.theme.u(ROW_UNITS);
        (((self.area.h - row) / row).max(1)) as usize
    }

    fn scroll_to_focus(&mut self) {
        let page = self.page();
        if self.n == 0 {
            self.top = 0;
            return;
        }
        if self.focus < self.top {
            self.top = self.focus;
        } else if self.focus >= self.top + page {
            self.top = self.focus + 1 - page;
        }
        self.top = self.top.min(self.n.saturating_sub(page));
    }

    /// Moves the focus to `pos`: plain (the row alone selected), extending (the range from the
    /// anchor) or focus only.
    fn move_to(&mut self, src: &dyn RowSource, pos: usize, mods: u32) -> ListEvent {
        if pos == self.focus {
            return ListEvent::None;
        }
        self.focus = pos;
        self.scroll_to_focus();
        if self.multi && mods & MOD_SHIFT != 0 {
            self.clear_sel();
            let (a, b) = if self.anchor <= pos {
                (self.anchor, pos)
            } else {
                (pos, self.anchor)
            };
            for p in a..=b {
                self.set_sel(src.order(p), true);
            }
            return ListEvent::Select(self.count);
        }
        let id = src.order(pos);
        if !(self.multi && mods & MOD_CTRL != 0) {
            self.clear_sel();
            self.set_sel(id, true);
            self.anchor = pos;
        }
        ListEvent::Focus(id)
    }

    /// Sorts by `col` through the application: ascending, or the other way when it is already
    /// the sort column. The focus and the anchor stay on their rows.
    pub fn sort_by(&mut self, src: &mut dyn RowSource, col: usize) -> ListEvent {
        if col >= self.columns.len() || self.n == 0 {
            return ListEvent::None;
        }
        let ascending = !matches!(self.sort, Some((c, true)) if c == col);
        let (f, a) = (src.order(self.focus), src.order(self.anchor));
        if !src.sort(col, ascending) {
            // Nothing sorted: nothing announced, nothing described.
            return ListEvent::None;
        }
        self.sort = Some((col, ascending));
        for p in 0..self.n {
            let id = src.order(p);
            if id == f {
                self.focus = p;
            }
            if id == a {
                self.anchor = p;
            }
        }
        self.scroll_to_focus();
        ListEvent::Sort(col, ascending)
    }

    pub fn key(
        &mut self,
        src: &mut dyn RowSource,
        code: u32,
        down: bool,
        mods: u32,
        ch: Option<char>,
        now_ms: u64,
    ) -> ListEvent {
        if !down || self.n == 0 {
            return ListEvent::None;
        }
        let last = self.n - 1;
        let step = self.page().saturating_sub(1).max(1);
        let target = match code {
            KEY_UP => Some(self.focus.saturating_sub(1)),
            KEY_DOWN => Some((self.focus + 1).min(last)),
            KEY_HOME => Some(0),
            KEY_END => Some(last),
            KEY_PGUP => Some(self.focus.saturating_sub(step)),
            KEY_PGDN => Some((self.focus + step).min(last)),
            _ => None,
        };
        if let Some(pos) = target {
            return self.move_to(src, pos, mods);
        }
        match code {
            KEY_ENTER => return ListEvent::Activate(src.order(self.focus)),
            KEY_SPACE => {
                let id = src.order(self.focus);
                self.anchor = self.focus;
                if self.multi && mods & MOD_CTRL != 0 {
                    let on = !self.is_selected(id);
                    self.set_sel(id, on);
                    return ListEvent::Select(self.count);
                }
                if self.count == 1 && self.is_selected(id) {
                    return ListEvent::None;
                }
                self.clear_sel();
                self.set_sel(id, true);
                return ListEvent::Select(self.count);
            }
            KEY_LEFT | KEY_RIGHT => {
                // Visual: Right goes right, which in RTL is toward the first column.
                let next = (code == KEY_RIGHT) != self.rtl;
                let c = if next {
                    (self.col + 1).min(self.columns.len() - 1)
                } else {
                    self.col.saturating_sub(1)
                };
                if c == self.col {
                    return ListEvent::None;
                }
                self.col = c;
                return ListEvent::Column(c);
            }
            // Ctrl+1 .. Ctrl+9 (set 1 codes 0x02..0x0a) sort by that column.
            0x02..=0x0a if mods & MOD_CTRL != 0 => return self.sort_by(src, (code - 2) as usize),
            _ => {}
        }
        match ch {
            Some(c) if mods & MOD_CTRL == 0 && !c.is_control() => self.type_ahead(src, c, now_ms),
            _ => ListEvent::None,
        }
    }

    fn type_ahead(&mut self, src: &dyn RowSource, c: char, now: u64) -> ListEvent {
        if self.typed_len == 0 || now.saturating_sub(self.typed_at) > TYPEAHEAD_MS {
            self.typed_len = 0;
        }
        self.typed_at = now;
        if self.typed_len < TYPEAHEAD_MAX {
            self.typed[self.typed_len] = c.to_ascii_lowercase();
            self.typed_len += 1;
        }
        let typed = self.typed;
        let len = self.typed_len;
        // One letter repeated cycles through the rows starting with it; a longer prefix
        // searches from the focused row itself.
        let repeat = typed[..len].iter().all(|&x| x == typed[0]);
        let (prefix, from) = if repeat {
            (&typed[..1], self.focus + 1)
        } else {
            (&typed[..len], self.focus)
        };
        for k in 0..self.n {
            let pos = (from + k) % self.n;
            let mut t = Text::new();
            src.cell(src.order(pos), self.col, &mut t);
            let s = core::str::from_utf8(t.as_bytes()).unwrap_or("");
            let mut chars = s.chars().map(|x| x.to_ascii_lowercase());
            if prefix.iter().all(|&p| chars.next() == Some(p)) {
                return self.move_to(src, pos, 0);
            }
        }
        ListEvent::None
    }

    /// `role=list label="<label>" rows=<n> columns=<c>`, then ` sort="<column>" ascending|
    /// descending` once sorted, then ` state=empty` or ` state=denied reason="<sentence>"`.
    pub fn describe(&self, out: &mut Text) {
        out.clear();
        out.put(b"role=list label=\"");
        out.put(self.label.as_bytes());
        out.put(b"\" rows=");
        out.num(self.n);
        out.put(b" columns=");
        out.num(self.columns.len());
        if let Some((c, asc)) = self.sort {
            out.put(b" sort=\"");
            out.put(self.columns[c].name.as_bytes());
            out.put(if asc {
                b"\" ascending" as &[u8]
            } else {
                b"\" descending"
            });
        }
        if let Some(r) = self.denied {
            out.put(b" state=denied reason=\"");
            out.put(r.as_bytes());
            out.put(b"\"");
        } else if self.n == 0 {
            out.put(b" state=empty");
        }
    }

    /// `row <k>/<n> state=<focused|selected|focused,selected|enabled>` then
    /// ` "<column>"="<value>"` for each column that fits the line whole; the rest is counted
    /// as ` more=<j>`. False (and nothing written) for a position outside the rows.
    pub fn describe_row(&self, src: &dyn RowSource, pos: usize, out: &mut Text) -> bool {
        if pos >= self.n {
            return false;
        }
        let id = src.order(pos);
        out.clear();
        // n is every row, not the visible ones.
        let total = self.n;
        out.put(b"row ");
        out.num(pos + 1);
        out.put(b"/");
        out.num(total);
        out.put(match (pos == self.focus, self.is_selected(id)) {
            (true, true) => b" state=focused,selected" as &[u8],
            (true, false) => b" state=focused",
            (false, true) => b" state=selected",
            (false, false) => b" state=enabled",
        });
        let cap = out.buf.len();
        for (c, col) in self.columns.iter().enumerate() {
            let mut v = Text::new();
            src.cell(id, c, &mut v);
            let mut piece = Text::new();
            piece.put(b" \"");
            piece.put(col.name.as_bytes());
            piece.put(b"\"=\"");
            put_value(&mut piece, v.as_bytes());
            piece.put(b"\"");
            let room = if c + 1 < self.columns.len() {
                MORE_ROOM
            } else {
                0
            };
            // A value the line cannot hold whole (or that filled its own buffer) is left out.
            let whole = piece.len < cap && v.len + 4 < cap;
            if !whole || out.len + piece.len + room > cap {
                out.put(b" more=");
                out.num(self.columns.len() - c);
                return true;
            }
            out.put(piece.as_bytes());
        }
        true
    }

    /// `select count=<m>`.
    pub fn describe_selection(&self, out: &mut Text) {
        out.clear();
        out.put(b"select count=");
        out.num(self.count);
    }

    /// The header rectangle of each column, in the reading direction; returns how many.
    pub fn layout(&self, out: &mut [Rect]) -> usize {
        let t = &self.theme;
        let a = self.area;
        let mut used = 0;
        let mut k = 0;
        for col in self.columns {
            let w = t.u(col.width);
            let x = if self.rtl {
                a.x + a.w - used - w
            } else {
                a.x + used
            };
            if k < out.len() {
                out[k] = Rect {
                    x,
                    y: a.y,
                    w,
                    h: t.u(ROW_UNITS),
                };
            }
            used += w;
            k += 1;
        }
        k
    }

    /// The rectangle of the `k`-th visible row.
    pub fn row_rect(&self, k: usize) -> Rect {
        let row = self.theme.u(ROW_UNITS);
        Rect {
            x: self.area.x,
            y: self.area.y + row * (1 + k as i32),
            w: self.area.w,
            h: row,
        }
    }

    /// Where a value `text_w` wide starts in its column: text at the reading start, numbers at
    /// the trailing edge (right in LTR, left in RTL).
    pub fn cell_x(&self, col: usize, text_w: i32) -> i32 {
        let mut rects = [Rect::default(); MAX_COLUMNS];
        self.layout(&mut rects);
        let r = rects[col.min(MAX_COLUMNS - 1)];
        let pad = self.theme.u(PAD_UNITS);
        let numeric = self.columns.get(col).is_some_and(|c| c.numeric);
        if numeric != self.rtl {
            r.x + r.w - pad - text_w
        } else {
            r.x + pad
        }
    }
}
