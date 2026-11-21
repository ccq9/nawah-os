//! TST-M6-LISTVIEW-UNIT (WP-50, 50a; ui.md v1.8 §3.8): the virtualised list view on the host.
//! The application owns the rows and their order (a `RowSource`); libui keeps the view state
//! only. Behaviour follows the W3C WAI-ARIA Authoring Practices grid and listbox patterns
//! (S81, unverified until read); the type-ahead window, the narrator line format and the
//! layout units are nawah's own. Every label, column name and value here is nawah's own.

use libui::list::*;
use libui::*;
use nawah_text::bidi::{Base, Bidi};

const T0: u64 = 1_000;

static COLS: [Column; 2] = [
    Column {
        name: "Name",
        width: 120,
        numeric: false,
    },
    Column {
        name: "Size",
        width: 60,
        numeric: true,
    },
];
static COLS_AR: [Column; 2] = [
    Column {
        name: "الاسم",
        width: 120,
        numeric: false,
    },
    Column {
        name: "الحجم",
        width: 60,
        numeric: true,
    },
];

/// The application's side: names and sizes by row id, and its current order of ids. Asking
/// for a position or an id outside the rows panics, so a view that does is caught.
struct Src {
    names: Vec<String>,
    sizes: Vec<u32>,
    perm: Vec<u16>,
    /// The scratch the application gives stable_sort is one short: no sort happens.
    short: bool,
}

impl Src {
    fn new(names: Vec<String>, sizes: Vec<u32>) -> Src {
        let perm = (0..names.len() as u16).collect();
        Src {
            names,
            sizes,
            perm,
            short: false,
        }
    }
    fn numbered(n: usize) -> Src {
        Src::new(
            (0..n).map(|i| format!("row {i:05}")).collect(),
            (0..n).map(|i| i as u32).collect(),
        )
    }
    fn of(names: &[&str], sizes: &[u32]) -> Src {
        Src::new(
            names.iter().map(|s| s.to_string()).collect(),
            sizes.to_vec(),
        )
    }
}

impl RowSource for Src {
    fn rows(&self) -> usize {
        self.names.len()
    }
    fn order(&self, pos: usize) -> usize {
        assert!(
            pos < self.names.len(),
            "position {pos} of {} asked",
            self.names.len()
        );
        self.perm[pos] as usize
    }
    fn cell(&self, id: usize, col: usize, out: &mut Text) {
        assert!(
            id < self.names.len(),
            "row id {id} of {} asked",
            self.names.len()
        );
        match col {
            0 => out.put(self.names[id].as_bytes()),
            1 => out.num(self.sizes[id] as usize),
            _ => panic!("column {col} asked"),
        }
    }
    fn sort(&mut self, col: usize, ascending: bool) -> bool {
        let n = self.names.len();
        let mut ids: Vec<u16> = (0..n as u16).collect();
        let mut scratch = vec![0u16; n.saturating_sub(self.short as usize)];
        let (names, sizes) = (&self.names, &self.sizes);
        let done = stable_sort(&mut ids, &mut scratch, |a, b| {
            let o = if col == 0 {
                names[a as usize].cmp(&names[b as usize])
            } else {
                sizes[a as usize].cmp(&sizes[b as usize])
            };
            if ascending {
                o.is_lt()
            } else {
                o.is_gt()
            }
        });
        if done {
            self.perm = ids;
        }
        done
    }
}

/// A view of `src` whose area holds exactly ten rows at 1x (header 20 + 10 x 20).
fn view(cols: &'static [Column], multi: bool, rtl: bool, src: &Src) -> ListView {
    let mut v = ListView::new("Files", cols, multi, rtl).unwrap();
    v.set_area(Rect {
        x: 10,
        y: 0,
        w: 400,
        h: 220,
    });
    v.reset(src).unwrap();
    v
}

fn key(v: &mut ListView, s: &mut Src, code: u32, mods: u32) -> ListEvent {
    v.key(s, code, true, mods, None, T0)
}

/// A typed character with a plausible code: Space is KEY_SPACE (it selects, never searches).
fn typed(v: &mut ListView, s: &mut Src, c: char, t: u64) -> ListEvent {
    let code = if c == ' ' { KEY_SPACE } else { 0x30 };
    v.key(s, code, true, 0, Some(c), t)
}

fn line(t: &Text) -> String {
    String::from_utf8(t.as_bytes().to_vec()).expect("a narrator line is valid UTF-8")
}

fn row(v: &ListView, s: &Src, pos: usize) -> String {
    let mut t = Text::new();
    assert!(v.describe_row(s, pos, &mut t), "row {pos} not described");
    line(&t)
}

fn whole(v: &ListView) -> String {
    let mut t = Text::new();
    v.describe(&mut t);
    line(&t)
}

#[test]
fn visible_rows_bounded_0_1_10000() {
    let keys = [
        KEY_DOWN, KEY_UP, KEY_HOME, KEY_END, KEY_PGUP, KEY_PGDN, KEY_ENTER, KEY_SPACE,
    ];
    // No rows: nothing is asked of the application, nothing moves.
    let mut s = Src::numbered(0);
    let mut v = view(&COLS, true, false, &s);
    for &k in &keys {
        assert_eq!(key(&mut v, &mut s, k, 0), ListEvent::None);
    }
    assert_eq!(typed(&mut v, &mut s, 'r', T0), ListEvent::None);
    assert_eq!(v.visible(), (0, 0));
    assert_eq!(v.focus_pos(), None);
    assert!(!v.describe_row(&s, 0, &mut Text::new()));
    // One row: every key keeps it.
    let mut s = Src::numbered(1);
    let mut v = view(&COLS, true, false, &s);
    for &k in &[KEY_END, KEY_PGDN, KEY_DOWN, KEY_UP, KEY_PGUP, KEY_HOME] {
        key(&mut v, &mut s, k, 0);
        assert_eq!(v.focus_pos(), Some(0));
        assert_eq!(v.visible(), (0, 1));
    }
    assert!(v.describe_row(&s, 0, &mut Text::new()));
    assert!(!v.describe_row(&s, 1, &mut Text::new()));
    // 10,000 rows, ten visible: the window never passes the last row.
    let mut s = Src::numbered(10_000);
    let mut v = view(&COLS, true, false, &s);
    assert_eq!(v.visible(), (0, 10));
    assert_eq!(key(&mut v, &mut s, KEY_END, 0), ListEvent::Focus(9_999));
    assert_eq!(v.visible(), (9_990, 10));
    assert_eq!(key(&mut v, &mut s, KEY_DOWN, 0), ListEvent::None);
    assert_eq!(key(&mut v, &mut s, KEY_PGDN, 0), ListEvent::None);
    assert_eq!(key(&mut v, &mut s, KEY_PGDN, MOD_SHIFT), ListEvent::None);
    key(&mut v, &mut s, KEY_HOME, 0);
    for _ in 0..1_200 {
        key(&mut v, &mut s, KEY_PGDN, MOD_SHIFT);
        let (top, n) = v.visible();
        assert!(top + n <= 10_000 && v.focus_pos().unwrap() < 10_000);
        for k in 0..n {
            assert!(v.describe_row(&s, top + k, &mut Text::new()));
        }
    }
    assert_eq!(v.focus_pos(), Some(9_999));
    assert_eq!(v.selected_count(), 10_000);
    assert!(!v.describe_row(&s, 10_000, &mut Text::new()));
    // More rows than the view can hold are refused, and the view keeps its rows.
    let big = Src::numbered(MAX_ROWS + 1);
    assert_eq!(v.reset(&big), Err(ListError::TooManyRows));
    assert_eq!(v.rows(), 10_000);
    assert_eq!(v.focus_pos(), Some(9_999));
    // Exactly MAX_ROWS are taken; the last id has its selection bit.
    let mut most = Src::numbered(MAX_ROWS);
    v.reset(&most).unwrap();
    assert_eq!(
        key(&mut v, &mut most, KEY_END, 0),
        ListEvent::Focus(MAX_ROWS - 1)
    );
    assert!(v.is_selected(MAX_ROWS - 1));
    assert_eq!(v.selected_count(), 1);
    assert_eq!(v.visible(), (MAX_ROWS - 10, 10));
}

#[test]
fn home_end_pgup_pgdn_exact() {
    let mut s = Src::numbered(100);
    let mut v = view(&COLS, false, false, &s);
    let mut step = |code: u32, ev: ListEvent, focus: usize, top: usize| {
        assert_eq!(key(&mut v, &mut s, code, 0), ev, "key {code:#x}");
        assert_eq!(v.focus_pos(), Some(focus), "focus after {code:#x}");
        assert_eq!(v.visible().0, top, "top after {code:#x}");
    };
    // A page is the visible rows less one (10 - 1 = 9).
    step(KEY_DOWN, ListEvent::Focus(1), 1, 0);
    step(KEY_PGDN, ListEvent::Focus(10), 10, 1);
    step(KEY_PGDN, ListEvent::Focus(19), 19, 10);
    step(KEY_PGUP, ListEvent::Focus(10), 10, 10);
    step(KEY_PGUP, ListEvent::Focus(1), 1, 1);
    step(KEY_PGUP, ListEvent::Focus(0), 0, 0);
    step(KEY_UP, ListEvent::None, 0, 0);
    step(KEY_END, ListEvent::Focus(99), 99, 90);
    step(KEY_UP, ListEvent::Focus(98), 98, 90);
    step(KEY_PGDN, ListEvent::Focus(99), 99, 90);
    step(KEY_HOME, ListEvent::Focus(0), 0, 0);
    // Key releases do nothing.
    assert_eq!(v.key(&mut s, KEY_DOWN, false, 0, None, T0), ListEvent::None);
    assert_eq!(v.focus_pos(), Some(0));
    // Enter activates the focused row by its id, in the application's order.
    let mut r = Src::numbered(5);
    r.perm.reverse();
    let mut w = view(&COLS, false, false, &r);
    assert_eq!(key(&mut w, &mut r, KEY_DOWN, 0), ListEvent::Focus(3));
    assert_eq!(key(&mut w, &mut r, KEY_ENTER, 0), ListEvent::Activate(3));
}

#[test]
fn sort_stable_and_selection_follows_identity() {
    // The helper keeps equal keys in their order, both ways.
    let keys = [3u8, 1, 3, 2, 1, 3];
    let mut ids: Vec<u16> = (0..6).collect();
    let mut scratch = [0u16; 6];
    assert!(stable_sort(&mut ids, &mut scratch, |a, b| {
        keys[a as usize] < keys[b as usize]
    }));
    assert_eq!(ids, [1, 4, 3, 0, 2, 5]);
    let mut ids: Vec<u16> = (0..6).collect();
    assert!(stable_sort(&mut ids, &mut scratch, |a, b| {
        keys[a as usize] > keys[b as usize]
    }));
    assert_eq!(ids, [0, 2, 5, 3, 1, 4]);
    let mut big: Vec<u16> = (0..1_000).rev().collect();
    let mut scratch = vec![0u16; 1_000];
    assert!(stable_sort(&mut big, &mut scratch, |a, b| a % 7 < b % 7));
    assert!(big
        .windows(2)
        .all(|w| w[0] % 7 < w[1] % 7 || (w[0] % 7 == w[1] % 7 && w[0] > w[1])));
    // The view: select ids 1 and 4, focus id 4, then sort by size.
    let mut s = Src::of(
        &["delta", "alpha", "echo", "bravo", "charlie", "foxtrot"],
        &[3, 1, 3, 2, 1, 3],
    );
    let mut v = view(&COLS, true, false, &s);
    key(&mut v, &mut s, KEY_DOWN, 0);
    key(&mut v, &mut s, KEY_DOWN, MOD_CTRL);
    key(&mut v, &mut s, KEY_DOWN, MOD_CTRL);
    assert_eq!(key(&mut v, &mut s, KEY_DOWN, MOD_CTRL), ListEvent::Focus(4));
    assert_eq!(
        key(&mut v, &mut s, KEY_SPACE, MOD_CTRL),
        ListEvent::Select(2)
    );
    // Ctrl+2 sorts by the second column, ascending; again, descending.
    assert_eq!(
        key(&mut v, &mut s, 0x03, MOD_CTRL),
        ListEvent::Sort(1, true)
    );
    assert_eq!(s.perm, [1, 4, 3, 0, 2, 5]);
    assert_eq!(v.sorted(), Some((1, true)));
    let chosen: Vec<usize> = (0..6).filter(|&id| v.is_selected(id)).collect();
    assert_eq!(
        chosen,
        [1, 4],
        "the selection is the same rows, not the same positions"
    );
    assert_eq!(v.focus_pos(), Some(1));
    assert_eq!(v.focused_id(&s), Some(4));
    assert!(
        whole(&v).ends_with(" sort=\"Size\" ascending"),
        "{}",
        whole(&v)
    );
    assert_eq!(
        key(&mut v, &mut s, 0x03, MOD_CTRL),
        ListEvent::Sort(1, false)
    );
    assert_eq!(s.perm, [0, 2, 5, 3, 1, 4]);
    assert_eq!(v.focused_id(&s), Some(4));
    assert_eq!(v.focus_pos(), Some(5));
    let chosen: Vec<usize> = (0..6).filter(|&id| v.is_selected(id)).collect();
    assert_eq!(chosen, [1, 4]);
    assert!(whole(&v).ends_with(" sort=\"Size\" descending"));
    // Enter after the sort activates the row the user sees focused.
    assert_eq!(key(&mut v, &mut s, KEY_ENTER, 0), ListEvent::Activate(4));
    // Ctrl+1 by name; a column that does not exist sorts nothing.
    assert_eq!(
        key(&mut v, &mut s, 0x02, MOD_CTRL),
        ListEvent::Sort(0, true)
    );
    assert_eq!(s.perm, [1, 3, 4, 0, 2, 5]);
    assert_eq!(key(&mut v, &mut s, 0x0a, MOD_CTRL), ListEvent::None);
    assert_eq!(v.sorted(), Some((0, true)));
    // The anchor stays on its row across a sort: Shift ranges from it, by position after.
    let mut s = Src::of(
        &["delta", "alpha", "echo", "bravo", "charlie", "foxtrot"],
        &[3, 1, 3, 2, 1, 3],
    );
    let mut v = view(&COLS, true, false, &s);
    for _ in 0..4 {
        key(&mut v, &mut s, KEY_DOWN, 0);
    }
    key(&mut v, &mut s, 0x03, MOD_CTRL);
    assert_eq!(
        key(&mut v, &mut s, KEY_DOWN, MOD_SHIFT),
        ListEvent::Select(2)
    );
    let chosen: Vec<usize> = (0..6).filter(|&id| v.is_selected(id)).collect();
    assert_eq!(chosen, [3, 4]);
    // A reset or a denial ends the sort and the current column: the narrator never says a
    // list is sorted when nothing sorted it.
    key(&mut v, &mut s, KEY_RIGHT, 0);
    assert_eq!(v.column(), 1);
    let mut t = Src::numbered(3);
    v.reset(&t).unwrap();
    assert_eq!(v.sorted(), None);
    assert_eq!(v.column(), 0);
    assert_eq!(whole(&v), "role=list label=\"Files\" rows=3 columns=2");
    key(&mut v, &mut t, 0x03, MOD_CTRL);
    key(&mut v, &mut t, KEY_RIGHT, 0);
    assert_eq!((v.sorted(), v.column()), (Some((1, true)), 1));
    v.deny("You do not have permission to open this folder.");
    assert_eq!((v.sorted(), v.column()), (None, 0));
    assert!(!whole(&v).contains("sort="), "{}", whole(&v));
    // A sort that did not happen is neither announced nor described: stable_sort with a short
    // scratch sorts nothing and says so.
    let mut ids: Vec<u16> = vec![2, 0, 1];
    assert!(!stable_sort(&mut ids, &mut [0u16; 2], |a, b| a < b));
    assert_eq!(ids, [2, 0, 1]);
    let mut f = Src::of(&["b", "a", "c"], &[2, 1, 3]);
    f.short = true;
    let mut v = view(&COLS, true, false, &f);
    assert_eq!(key(&mut v, &mut f, 0x02, MOD_CTRL), ListEvent::None);
    assert_eq!(v.sorted(), None);
    assert_eq!(whole(&v), "role=list label=\"Files\" rows=3 columns=2");
    assert_eq!(v.focused_id(&f), Some(0));
}

#[test]
fn single_and_multi_selection() {
    let sel = |v: &ListView| -> Vec<usize> { (0..20).filter(|&id| v.is_selected(id)).collect() };
    let mut s = Src::numbered(20);
    let mut v = view(&COLS, true, false, &s);
    assert_eq!(sel(&v), Vec::<usize>::new());
    assert_eq!(key(&mut v, &mut s, KEY_DOWN, 0), ListEvent::Focus(1));
    assert_eq!(sel(&v), [1]);
    key(&mut v, &mut s, KEY_DOWN, MOD_SHIFT);
    assert_eq!(
        key(&mut v, &mut s, KEY_DOWN, MOD_SHIFT),
        ListEvent::Select(3)
    );
    assert_eq!(sel(&v), [1, 2, 3]);
    assert_eq!(
        key(&mut v, &mut s, KEY_HOME, MOD_SHIFT),
        ListEvent::Select(2)
    );
    assert_eq!(sel(&v), [0, 1], "a range runs from the anchor");
    for _ in 0..3 {
        key(&mut v, &mut s, KEY_DOWN, MOD_CTRL);
    }
    assert_eq!(v.focus_pos(), Some(3));
    assert_eq!(sel(&v), [0, 1], "Ctrl moves the focus only");
    assert_eq!(
        key(&mut v, &mut s, KEY_SPACE, MOD_CTRL),
        ListEvent::Select(3)
    );
    assert_eq!(sel(&v), [0, 1, 3]);
    assert_eq!(
        key(&mut v, &mut s, KEY_SPACE, MOD_CTRL),
        ListEvent::Select(2)
    );
    assert_eq!(sel(&v), [0, 1]);
    let mut t = Text::new();
    v.describe_selection(&mut t);
    assert_eq!(line(&t), "select count=2");
    // Ctrl+Space set the anchor at 3: Shift ranges from there.
    key(&mut v, &mut s, KEY_DOWN, MOD_CTRL);
    assert_eq!(
        key(&mut v, &mut s, KEY_DOWN, MOD_SHIFT),
        ListEvent::Select(3)
    );
    assert_eq!(sel(&v), [3, 4, 5]);
    // Space with several selected selects the focused row alone.
    assert_eq!(key(&mut v, &mut s, KEY_SPACE, 0), ListEvent::Select(1));
    assert_eq!(sel(&v), [5]);
    key(&mut v, &mut s, KEY_HOME, MOD_CTRL);
    key(&mut v, &mut s, KEY_SPACE, MOD_CTRL);
    for _ in 0..3 {
        key(&mut v, &mut s, KEY_DOWN, MOD_CTRL);
    }
    assert_eq!(sel(&v), [0, 5]);
    assert_eq!(key(&mut v, &mut s, KEY_DOWN, 0), ListEvent::Focus(4));
    assert_eq!(sel(&v), [4], "a plain move selects the focused row alone");
    assert_eq!(key(&mut v, &mut s, KEY_SPACE, 0), ListEvent::None);
    // Shift from the new anchor (4) to End.
    assert_eq!(
        key(&mut v, &mut s, KEY_END, MOD_SHIFT),
        ListEvent::Select(16)
    );
    assert_eq!(v.selected_count(), 16);
    // A single-selection list: Shift and Ctrl move like plain keys, Ctrl+Space selects one.
    let mut v = view(&COLS, false, false, &s);
    key(&mut v, &mut s, KEY_DOWN, 0);
    assert_eq!(
        key(&mut v, &mut s, KEY_DOWN, MOD_SHIFT),
        ListEvent::Focus(2)
    );
    assert_eq!(sel(&v), [2]);
    assert_eq!(key(&mut v, &mut s, KEY_DOWN, MOD_CTRL), ListEvent::Focus(3));
    assert_eq!(sel(&v), [3]);
    key(&mut v, &mut s, KEY_SPACE, MOD_CTRL);
    assert_eq!(sel(&v), [3]);
    // Selection is by row id: in a reversed order the first move selects id 18.
    let mut r = Src::numbered(20);
    r.perm.reverse();
    let mut w = view(&COLS, true, false, &r);
    assert_eq!(key(&mut w, &mut r, KEY_DOWN, 0), ListEvent::Focus(18));
    assert_eq!(sel(&w), [18]);
    assert_eq!(
        key(&mut w, &mut r, KEY_DOWN, MOD_SHIFT),
        ListEvent::Select(2)
    );
    assert_eq!(sel(&w), [17, 18], "a range selects the rows shown, by id");
    // A reset clears the selection.
    w.reset(&r).unwrap();
    assert_eq!(w.selected_count(), 0);
}

#[test]
fn typeahead_latin_and_arabic() {
    let mut s = Src::of(
        &[
            "apple", "Banana", "berry", "blue", "cherry", "تفاح", "توت", "موز",
        ],
        &[1, 2, 3, 4, 5, 6, 7, 8],
    );
    let mut v = view(&COLS, true, false, &s);
    let go = |v: &mut ListView, s: &mut Src, c: char, t: u64, want: ListEvent| {
        let ev = typed(v, s, c, t);
        assert_eq!(ev, want, "'{c}' at {t}");
        assert!(
            !matches!(ev, ListEvent::Activate(_)),
            "typing never activates"
        );
    };
    go(&mut v, &mut s, 'b', T0, ListEvent::Focus(1));
    go(&mut v, &mut s, 'b', T0 + 100, ListEvent::Focus(2));
    go(&mut v, &mut s, 'B', T0 + 200, ListEvent::Focus(3));
    go(&mut v, &mut s, 'b', T0 + 300, ListEvent::Focus(1));
    // After the window (TYPEAHEAD_MS) a new search starts.
    go(
        &mut v,
        &mut s,
        'c',
        T0 + 300 + TYPEAHEAD_MS + 1,
        ListEvent::Focus(4),
    );
    // Exactly TYPEAHEAD_MS later still extends: "ch" from cherry finds cherry itself.
    go(
        &mut v,
        &mut s,
        'h',
        T0 + 1_301 + TYPEAHEAD_MS,
        ListEvent::None,
    );
    assert_eq!(v.focus_pos(), Some(4));
    // Exactly TYPEAHEAD_MS after the previous letter still extends the prefix.
    let mut w = view(&COLS, true, false, &s);
    assert_eq!(typed(&mut w, &mut s, 'b', T0), ListEvent::Focus(1));
    assert_eq!(
        typed(&mut w, &mut s, 'l', T0 + TYPEAHEAD_MS),
        ListEvent::Focus(3)
    );
    // A typed move sets the anchor: Shift ranges from the found row.
    let mut w = view(&COLS, true, false, &s);
    assert_eq!(typed(&mut w, &mut s, 'c', T0), ListEvent::Focus(4));
    assert_eq!(
        key(&mut w, &mut s, KEY_DOWN, MOD_SHIFT),
        ListEvent::Select(2)
    );
    assert!(w.is_selected(4) && w.is_selected(5) && w.selected_count() == 2);
    // A space never enters the search: it selects, and the prefix goes on without it.
    let mut w = view(&COLS, true, false, &s);
    assert_eq!(typed(&mut w, &mut s, 'b', T0), ListEvent::Focus(1));
    assert_eq!(typed(&mut w, &mut s, ' ', T0 + 10), ListEvent::None);
    assert_eq!(typed(&mut w, &mut s, 'e', T0 + 20), ListEvent::Focus(2));
    // A prefix of two letters searches from the focused row, wrapping.
    go(&mut v, &mut s, 'b', T0 + 5_000, ListEvent::Focus(1));
    go(&mut v, &mut s, 'l', T0 + 5_100, ListEvent::Focus(3));
    // Arabic.
    go(&mut v, &mut s, 'ت', T0 + 9_000, ListEvent::Focus(5));
    go(&mut v, &mut s, 'و', T0 + 9_100, ListEvent::Focus(6));
    // No match: nothing moves.
    go(&mut v, &mut s, 'z', T0 + 20_000, ListEvent::None);
    assert_eq!(v.focus_pos(), Some(6));
    // Ctrl with a letter is not type-ahead; a typed move selects the row alone.
    assert_eq!(
        v.key(&mut s, 0x30, true, MOD_CTRL, Some('b'), T0 + 30_000),
        ListEvent::None
    );
    assert_eq!(v.selected_count(), 1);
    assert!(v.is_selected(6));
    // What is typed past TYPEAHEAD_MAX (16) characters is dropped: the 17th letter does not
    // narrow the search.
    let mut l = Src::of(&["x", "abcdefghijklmnopq", "abcdefghijklmnopz"], &[1, 2, 3]);
    let mut lv = view(&COLS, true, false, &l);
    let mut last = ListEvent::None;
    for (i, c) in "abcdefghijklmnopz".chars().enumerate() {
        last = typed(&mut lv, &mut l, c, T0 + i as u64);
    }
    assert_eq!(TYPEAHEAD_MAX, 16);
    assert_eq!(last, ListEvent::None);
    assert_eq!(lv.focus_pos(), Some(1));
    // The search is in the current column: by size, '4' finds blue.
    key(&mut v, &mut s, KEY_RIGHT, 0);
    assert_eq!(v.column(), 1);
    go(&mut v, &mut s, '4', T0 + 40_000, ListEvent::Focus(3));
}

#[test]
fn row_narrator_lines_en_ar() {
    let mut s = Src::of(&["notes.txt", "plan.txt"], &[12, 7]);
    let mut v = view(&COLS, true, false, &s);
    assert_eq!(whole(&v), "role=list label=\"Files\" rows=2 columns=2");
    assert_eq!(
        row(&v, &s, 0),
        "row 1/2 state=focused \"Name\"=\"notes.txt\" \"Size\"=\"12\""
    );
    key(&mut v, &mut s, KEY_DOWN, 0);
    assert_eq!(
        row(&v, &s, 1),
        "row 2/2 state=focused,selected \"Name\"=\"plan.txt\" \"Size\"=\"7\""
    );
    assert_eq!(
        row(&v, &s, 0),
        "row 1/2 state=enabled \"Name\"=\"notes.txt\" \"Size\"=\"12\""
    );
    key(&mut v, &mut s, KEY_UP, MOD_CTRL);
    assert_eq!(
        row(&v, &s, 1),
        "row 2/2 state=selected \"Name\"=\"plan.txt\" \"Size\"=\"7\""
    );
    // Arabic: the tokens stay English, the names and values are the application's.
    let mut a = Src::of(&["ملاحظات.txt", "الخطة.txt"], &[12, 7]);
    let mut w = ListView::new("الملفات", &COLS_AR, true, true).unwrap();
    w.set_area(Rect {
        x: 0,
        y: 0,
        w: 400,
        h: 220,
    });
    w.reset(&a).unwrap();
    key(&mut w, &mut a, KEY_DOWN, 0);
    assert_eq!(whole(&w), "role=list label=\"الملفات\" rows=2 columns=2");
    assert_eq!(
        row(&w, &a, 1),
        "row 2/2 state=focused,selected \"الاسم\"=\"الخطة.txt\" \"الحجم\"=\"7\""
    );
    // n is all the rows, not the visible ones.
    let mut s = Src::numbered(500);
    let mut v = view(&COLS, true, false, &s);
    key(&mut v, &mut s, KEY_END, 0);
    assert_eq!(
        row(&v, &s, 499),
        "row 500/500 state=focused,selected \"Name\"=\"row 00499\" \"Size\"=\"499\""
    );
    // A column that does not fit the line is left out whole and counted: never half a value.
    let mut x = Src::of(&[&"b".repeat(180)], &[7]);
    let v = view(&COLS, true, false, &x);
    let l = row(&v, &x, 0);
    assert_eq!(
        l,
        format!(
            "row 1/1 state=focused \"Name\"=\"{}\" \"Size\"=\"7\"",
            "b".repeat(180)
        )
    );
    x.names[0] = "b".repeat(240);
    assert_eq!(row(&v, &x, 0), "row 1/1 state=focused more=2");
    // Room is kept for " more=<j>": a name that would leave none is left out.
    x.names[0] = "b".repeat(222);
    assert_eq!(row(&v, &x, 0), "row 1/1 state=focused more=2");
    x.names[0] = "b".repeat(300);
    assert_eq!(row(&v, &x, 0), "row 1/1 state=focused more=2");
    x.names[0] = format!("a{}", "ب".repeat(200));
    let l = row(&v, &x, 0);
    assert_eq!(l, "row 1/1 state=focused more=2");
    x.names[0] = "b".repeat(215);
    x.sizes[0] = 1234567;
    let l = row(&v, &x, 0);
    assert_eq!(
        l,
        format!(
            "row 1/1 state=focused \"Name\"=\"{}\" more=1",
            "b".repeat(215)
        )
    );
}

#[test]
fn empty_and_denied_states_text() {
    let mut s = Src::numbered(0);
    let mut v = view(&COLS, true, false, &s);
    assert_eq!(
        whole(&v),
        "role=list label=\"Files\" rows=0 columns=2 state=empty"
    );
    let mut s3 = Src::numbered(3);
    v.reset(&s3).unwrap();
    key(&mut v, &mut s3, KEY_DOWN, MOD_SHIFT);
    assert_eq!(v.selected_count(), 2);
    // Denied: never shown as empty, no rows, no selection, keys do nothing.
    v.deny("You do not have permission to open this folder.");
    assert_eq!(
        whole(&v),
        "role=list label=\"Files\" rows=0 columns=2 state=denied reason=\"You do not have permission to open this folder.\""
    );
    assert!(!whole(&v).contains("empty"));
    assert_eq!(v.rows(), 0);
    assert_eq!(v.selected_count(), 0);
    assert_eq!(v.visible(), (0, 0));
    assert!(!v.describe_row(&s3, 0, &mut Text::new()));
    for &k in &[KEY_DOWN, KEY_END, KEY_ENTER, KEY_SPACE] {
        assert_eq!(key(&mut v, &mut s, k, 0), ListEvent::None);
    }
    assert_eq!(key(&mut v, &mut s, 0x02, MOD_CTRL), ListEvent::None);
    let mut w = ListView::new("الملفات", &COLS_AR, true, true).unwrap();
    w.deny("ليس لديك إذن بفتح هذا المجلد.");
    assert_eq!(
        whole(&w),
        "role=list label=\"الملفات\" rows=0 columns=2 state=denied reason=\"ليس لديك إذن بفتح هذا المجلد.\""
    );
    // A reset with rows ends the denial.
    v.reset(&s3).unwrap();
    assert_eq!(whole(&v), "role=list label=\"Files\" rows=3 columns=2");
    // Building: a blank label or no columns is refused.
    assert_eq!(
        ListView::new("  ", &COLS, true, false).err(),
        Some(ListError::NoLabel)
    );
    assert_eq!(
        ListView::new("Files", &[], true, false).err(),
        Some(ListError::NoColumns)
    );
    const C: Column = Column {
        name: "Column",
        width: 10,
        numeric: false,
    };
    static EIGHT: [Column; MAX_COLUMNS] = [C; MAX_COLUMNS];
    static NINE: [Column; MAX_COLUMNS + 1] = [C; MAX_COLUMNS + 1];
    assert!(ListView::new("Files", &EIGHT, true, false).is_ok());
    assert_eq!(
        ListView::new("Files", &NINE, true, false).err(),
        Some(ListError::TooManyColumns)
    );
    static BLANK: [Column; 1] = [Column {
        name: " ",
        width: 10,
        numeric: false,
    }];
    assert_eq!(
        ListView::new("Files", &BLANK, true, false).err(),
        Some(ListError::NoLabel)
    );
}

#[test]
fn rtl_column_order_and_trailing_numeric() {
    let mut s = Src::numbered(3);
    let r = |x, w| Rect { x, y: 0, w, h: 20 };
    let mut cols = [Rect::default(); MAX_COLUMNS];
    // LTR: from the left edge; text at the start, numbers at the trailing (right) edge.
    let mut v = view(&COLS, true, false, &s);
    assert_eq!(v.layout(&mut cols), 2);
    assert_eq!(cols[..2], [r(10, 120), r(130, 60)]);
    assert_eq!(v.cell_x(0, 50), 14);
    assert_eq!(v.cell_x(1, 20), 166);
    assert_eq!(
        v.row_rect(0),
        Rect {
            x: 10,
            y: 20,
            w: 400,
            h: 20
        }
    );
    assert_eq!(key(&mut v, &mut s, KEY_RIGHT, 0), ListEvent::Column(1));
    assert_eq!(key(&mut v, &mut s, KEY_RIGHT, 0), ListEvent::None);
    assert_eq!(key(&mut v, &mut s, KEY_LEFT, 0), ListEvent::Column(0));
    // RTL: the first column at the right edge; text at its right, numbers at the left.
    let mut v = view(&COLS, true, true, &s);
    v.layout(&mut cols);
    assert_eq!(cols[..2], [r(290, 120), r(230, 60)]);
    assert_eq!(v.cell_x(0, 50), 356);
    assert_eq!(v.cell_x(1, 20), 234);
    assert_eq!(
        v.row_rect(9),
        Rect {
            x: 10,
            y: 200,
            w: 400,
            h: 20
        }
    );
    // Horizontal arrows move visually: Left goes to the next column in RTL.
    assert_eq!(key(&mut v, &mut s, KEY_RIGHT, 0), ListEvent::None);
    assert_eq!(key(&mut v, &mut s, KEY_LEFT, 0), ListEvent::Column(1));
    assert_eq!(key(&mut v, &mut s, KEY_RIGHT, 0), ListEvent::Column(0));
    // set_rtl flips the same view; 2x doubles the units.
    v.set_rtl(false);
    v.layout(&mut cols);
    assert_eq!(cols[..2], [r(10, 120), r(130, 60)]);
    v.set_theme(Theme::from_config(b"2", b""));
    v.set_area(Rect {
        x: 10,
        y: 0,
        w: 800,
        h: 440,
    });
    assert_eq!(v.visible(), (0, 3));
    v.set_rtl(true);
    v.layout(&mut cols);
    assert_eq!(
        cols[0],
        Rect {
            x: 570,
            y: 0,
            w: 240,
            h: 40
        }
    );
    assert_eq!(
        cols[1],
        Rect {
            x: 450,
            y: 0,
            w: 120,
            h: 40
        }
    );
    assert_eq!(v.cell_x(1, 20), 458);
}

#[test]
fn bidi_controls_in_cells_shown_not_obeyed() {
    let spoof = "photo\u{202E}gpj.exe";
    let mut s = Src::of(&[spoof], &[1]);
    let v = view(&COLS, true, false, &s);
    let l = row(&v, &s, 0);
    assert_eq!(
        l,
        "row 1/1 state=focused \"Name\"=\"photo[U+202E]gpj.exe\" \"Size\"=\"1\""
    );
    // For drawing: every bidi formatting character becomes U+FFFD, the rest is kept.
    let mut out = [0u32; 32];
    let n = cell_chars(spoof, &mut out);
    assert_eq!(n, spoof.chars().count());
    assert_eq!(out[5], 0xFFFD);
    assert_eq!(out[6], 'g' as u32);
    // The raw name would reorder (an odd level); the shown one stays left to right.
    let raw: Vec<u32> = spoof.chars().map(|c| c as u32).collect();
    let mut bidi = Box::new(Bidi::new());
    let mut levels = [0u8; 32];
    bidi.resolve(&raw, Base::Ltr, &mut levels[..raw.len()]);
    assert!(levels[6..raw.len()].iter().any(|l| l % 2 == 1));
    bidi.resolve(&out[..n], Base::Ltr, &mut levels[..n]);
    assert!(levels[..n].iter().all(|l| l % 2 == 0), "{:?}", &levels[..n]);
    // Every explicit formatting character, both in lines and in drawing.
    for c in [
        '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
        '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ] {
        s.names[0] = format!("a{c}b");
        let l = row(&v, &s, 0);
        assert!(!l.contains(c), "{l}");
        assert!(l.contains(&format!("a[U+{:04X}]b", c as u32)), "{l}");
        assert_eq!(cell_chars(&s.names[0], &mut out), 3);
        assert_eq!(out[..3], ['a' as u32, 0xFFFD, 'b' as u32]);
    }
    // A quote or a control character in a value cannot end the value or the line: a name
    // never forges a column, a state or a second narrator line.
    s.names[0] = "x\" \"Size\"=\"0".to_string();
    assert_eq!(
        row(&v, &s, 0),
        "row 1/1 state=focused \"Name\"=\"x[U+0022] [U+0022]Size[U+0022]=[U+0022]0\" \"Size\"=\"1\""
    );
    for c in [
        '\n', '\r', '\u{0}', '\u{1B}', '\u{7F}', '\u{85}', '\u{9F}', '\u{2028}', '\u{2029}',
    ] {
        s.names[0] = format!("a{c}b");
        let l = row(&v, &s, 0);
        assert!(l.contains(&format!("a[U+{:04X}]b", c as u32)), "{l:?}");
        assert!(!l.chars().any(|x| x.is_control()), "{l:?}");
        assert_eq!(cell_chars(&s.names[0], &mut out), 3);
        assert_eq!(out[..3], ['a' as u32, 0xFFFD, 'b' as u32]);
    }
    assert_eq!(cell_chars("a\"b", &mut out), 3);
    assert_eq!(out[1], '"' as u32, "a quote is drawn as itself");
    // Arabic text and its digits are not controls.
    assert_eq!(cell_chars("ملف ١٢", &mut out), 6);
    assert!(!out[..6].contains(&0xFFFD));
}

#[test]
fn text_put_cuts_at_char_boundary() {
    // (v1.8) A cut never splits a character: the line stays valid UTF-8.
    let mut t = Text::new();
    t.put(&[b'a'; 255]);
    t.put("بب".as_bytes());
    assert_eq!(t.len, 255, "a two-byte character does not fit one byte");
    assert!(
        core::str::from_utf8(t.as_bytes()).is_ok(),
        "Text::put split a character"
    );
    let mut t = Text::new();
    t.put("a".as_bytes());
    t.put("ب".repeat(200).as_bytes());
    assert!(
        core::str::from_utf8(t.as_bytes()).is_ok(),
        "Text::put split a character"
    );
    assert_eq!(t.len, 255);
    // Three- and four-byte characters, and a whole fit unchanged.
    let mut t = Text::new();
    t.put(&[b'a'; 254]);
    t.put("\u{2066}".as_bytes());
    assert_eq!(t.len, 254);
    t.put("\u{1F600}".as_bytes());
    assert_eq!(t.len, 254);
    t.put(b"zz");
    assert_eq!(t.len, 256);
    assert!(core::str::from_utf8(t.as_bytes()).is_ok());
}

#[test]
fn focus_stays_visible() {
    // After every move, sort, type-ahead, resize and scale the focused row is on screen and the
    // window never passes the last row.
    fn seen(v: &ListView) {
        let (top, n) = v.visible();
        let f = v.focus_pos().unwrap();
        assert!(top <= f && f < top + n, "focus {f} outside {top}+{n}");
        assert!(top + n <= v.rows());
    }
    let mut s = Src::numbered(100);
    let mut v = view(&COLS, true, false, &s);
    for _ in 0..30 {
        key(&mut v, &mut s, KEY_DOWN, 0);
        seen(&v);
    }
    for &k in &[KEY_PGDN, KEY_END, KEY_PGUP, KEY_UP, KEY_HOME, KEY_PGDN] {
        key(&mut v, &mut s, k, MOD_CTRL);
        seen(&v);
    }
    // Type-ahead to a far row, in the size column.
    assert_eq!(key(&mut v, &mut s, KEY_RIGHT, 0), ListEvent::Column(1));
    assert_eq!(
        "78".chars()
            .enumerate()
            .fold(ListEvent::None, |_, (i, c)| typed(
                &mut v,
                &mut s,
                c,
                T0 + i as u64
            )),
        ListEvent::Focus(78)
    );
    assert_eq!(v.focus_pos(), Some(78));
    seen(&v);
    // A descending sort moves the focused row (id 78) to position 21.
    key(&mut v, &mut s, 0x03, MOD_CTRL);
    key(&mut v, &mut s, 0x03, MOD_CTRL);
    assert_eq!(v.sorted(), Some((1, false)));
    assert_eq!((v.focused_id(&s), v.focus_pos()), (Some(78), Some(21)));
    seen(&v);
    // A smaller area, a larger scale, then the end.
    v.set_area(Rect {
        x: 10,
        y: 0,
        w: 400,
        h: 80,
    });
    seen(&v);
    assert_eq!(v.visible().1, 3);
    v.set_theme(Theme::from_config(b"2", b""));
    seen(&v);
    assert_eq!(v.visible().1, 1);
    key(&mut v, &mut s, KEY_END, 0);
    seen(&v);
    assert_eq!(v.visible(), (99, 1));
    // An area shorter than the header still shows the focused row (a page is at least one).
    v.set_area(Rect::default());
    key(&mut v, &mut s, KEY_PGUP, 0);
    seen(&v);
    // set_area and set_theme scroll to the focus themselves.
    let mut s = Src::numbered(100);
    let mut v = view(&COLS, true, false, &s);
    for _ in 0..9 {
        key(&mut v, &mut s, KEY_DOWN, 0);
    }
    v.set_area(Rect {
        x: 10,
        y: 0,
        w: 400,
        h: 80,
    });
    assert_eq!(v.visible(), (7, 3));
    v.set_theme(Theme::from_config(b"2", b""));
    assert_eq!(v.visible(), (9, 1));
    // No rows: nothing to show, nothing underflows.
    let e = Src::numbered(0);
    v.reset(&e).unwrap();
    v.set_area(Rect::default());
    assert_eq!(v.visible(), (0, 0));
}
