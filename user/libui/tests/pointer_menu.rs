//! TST-M6-UI-UNIT (WP-49, ui.md v1.6 §3.6): pointer hit-testing and the context menu, on the
//! host. Behaviour follows the W3C WAI-ARIA Authoring Practices menu pattern; every label here
//! is nawah's own.

use libui::*;

const T0: u64 = 1_000;
const LEFT: u32 = BUTTON_LEFT;
const RIGHT: u32 = BUTTON_RIGHT;

static MENU: [MenuItem; 4] = [
    MenuItem::item("Open the file", true),
    MenuItem::item("Rename the file", true),
    MenuItem::SEPARATOR,
    MenuItem::item("Delete the file", false),
];
static MENU_AR: [MenuItem; 2] = [
    MenuItem::item("افتح الملف", true),
    MenuItem::item("احذف الملف", false),
];
static FILES: [&str; 3] = ["notes.txt", "plan.txt", "todo.txt"];

/// 0 label, 1 text field, 2 checkbox, 3 list, 4 button, 5 button.
fn sample(rtl: bool) -> Dialog {
    let mut d = Dialog::new("Files", rtl);
    d.add(Role::Label, "Choose a file to open.").unwrap();
    d.add(Role::TextField, "File name").unwrap();
    d.add(Role::Checkbox, "Open it read-only").unwrap();
    d.add_list("Recent files", &FILES).unwrap();
    d.add(Role::Button, "Open").unwrap();
    d.add(Role::Button, "Close").unwrap();
    d.start();
    d
}

fn rects(d: &Dialog) -> [Rect; MAX_ELEMENTS] {
    let mut r = [Rect::default(); MAX_ELEMENTS];
    d.layout(&mut r);
    r
}

fn mid(r: Rect) -> (i32, i32) {
    (r.x + r.w / 2, r.y + r.h / 2)
}

trait Click {
    /// A press then a release of `b` at the same point; both events.
    fn click(&mut self, at: (i32, i32), b: u32, t: u64) -> (Event, Event);
}

impl Click for Dialog {
    fn click(&mut self, (x, y): (i32, i32), b: u32, t: u64) -> (Event, Event) {
        let p = self.pointer(x, y, b, t);
        let r = self.pointer(x, y, 0, t);
        (p, r)
    }
}

fn row_mid(d: &Dialog, list: usize, k: usize) -> (i32, i32) {
    let r = rects(d)[list];
    let row = r.h / (1 + d.element(list).items.len() as i32);
    (r.x + r.w / 2, r.y + row * (1 + k as i32) + row / 2)
}

fn item_text(d: &Dialog, k: usize) -> String {
    let mut t = Text::default();
    let n = d.describe_menu_item(k, &mut t).expect("an entry in range");
    assert_eq!(n, t.as_bytes().len());
    String::from_utf8(t.as_bytes().to_vec()).unwrap()
}

#[test]
fn pointer_focuses_and_activates_the_element_under_it() {
    let mut d = sample(false);
    let r = rects(&d);
    assert_eq!(d.focused(), Some(1));
    // A press focuses the button, the release over it activates it.
    assert_eq!(
        d.pointer(mid(r[4]).0, mid(r[4]).1, LEFT, T0),
        Event::Focus(Some(1), 4)
    );
    // Holding the button while moving inside is not a new press.
    assert_eq!(
        d.pointer(mid(r[4]).0 + 3, mid(r[4]).1, LEFT, T0),
        Event::None
    );
    assert_eq!(
        d.pointer(mid(r[4]).0, mid(r[4]).1, 0, T0),
        Event::Activate(4)
    );
    // The checkbox toggles on release, not on press.
    assert_eq!(
        d.pointer(mid(r[2]).0, mid(r[2]).1, LEFT, T0),
        Event::Focus(Some(4), 2)
    );
    assert!(!d.element(2).checked);
    assert_eq!(
        d.pointer(mid(r[2]).0, mid(r[2]).1, 0, T0),
        Event::Toggle(2, true)
    );
    // A label is never focused nor activated by the pointer.
    assert_eq!(d.click(mid(r[0]), LEFT, T0), (Event::None, Event::None));
    assert_eq!(d.focused(), Some(2));
    // The rectangle's last column is inside, the next one is not (the row's right edge).
    let edge_y = mid(r[5]).1;
    assert_eq!(
        d.click((r[5].x + r[5].w, edge_y), LEFT, T0),
        (Event::None, Event::None)
    );
    assert_eq!(d.focused(), Some(2));
    assert_eq!(
        d.click((r[5].x + r[5].w - 1, edge_y), LEFT, T0),
        (Event::Focus(Some(2), 5), Event::Activate(5))
    );
    // A press on the focused text field keeps the focus there and activates nothing.
    assert_eq!(
        d.pointer(mid(r[1]).0, mid(r[1]).1, LEFT, T0),
        Event::Focus(Some(5), 1)
    );
    assert_eq!(d.pointer(mid(r[1]).0, mid(r[1]).1, 0, T0), Event::None);
    // Outside every element (the padding above the first one) nothing happens.
    assert_eq!(d.click((1, 1), LEFT, T0), (Event::None, Event::None));
    assert_eq!(d.focused(), Some(1));
}

#[test]
fn release_outside_cancels() {
    let mut d = sample(false);
    let r = rects(&d);
    assert_eq!(
        d.pointer(mid(r[4]).0, mid(r[4]).1, LEFT, T0),
        Event::Focus(Some(1), 4)
    );
    // Released over the other button: nothing is activated, the focus stays where pressed.
    assert_eq!(d.pointer(mid(r[5]).0, mid(r[5]).1, 0, T0), Event::None);
    assert_eq!(d.focused(), Some(4));
    // Pressed on the checkbox, released outside the dialog: not toggled.
    d.pointer(mid(r[2]).0, mid(r[2]).1, LEFT, T0);
    assert_eq!(d.pointer(-5, -5, 0, T0), Event::None);
    assert!(!d.element(2).checked);
    // A release with no press before it activates nothing.
    assert_eq!(d.pointer(mid(r[4]).0, mid(r[4]).1, 0, T0), Event::None);
}

#[test]
fn list_click_selects_the_row_and_double_click_activates() {
    let mut d = sample(false);
    let r = rects(&d);
    // The header (the list's label row) focuses the list and selects nothing.
    assert_eq!(
        d.click((mid(r[3]).0, r[3].y + 2), LEFT, T0),
        (Event::Focus(Some(1), 3), Event::None)
    );
    assert_eq!(d.element(3).selected, 0);
    // A row selects it; one click activates nothing.
    assert_eq!(
        d.click(row_mid(&d, 3, 2), LEFT, T0),
        (Event::Select(3, 2), Event::None)
    );
    // The second click on the same row within DOUBLE_CLICK_MS activates the list.
    assert_eq!(
        d.click(row_mid(&d, 3, 2), LEFT, T0 + DOUBLE_CLICK_MS),
        (Event::None, Event::Activate(3))
    );
    // Too late: two single clicks.
    let t = T0 + 10_000;
    d.click(row_mid(&d, 3, 1), LEFT, t);
    assert_eq!(
        d.click(row_mid(&d, 3, 1), LEFT, t + DOUBLE_CLICK_MS + 1).1,
        Event::None
    );
    // Two rows in quick succession: no activation.
    let t = t + 20_000;
    d.click(row_mid(&d, 3, 0), LEFT, t);
    assert_eq!(d.click(row_mid(&d, 3, 1), LEFT, t + 1).1, Event::None);
    // The header twice is never a double-click.
    let t = t + 20_000;
    let head = (mid(r[3]).0, r[3].y + 2);
    d.click(head, LEFT, t);
    assert_eq!(d.click(head, LEFT, t + 1).1, Event::None);
    // From another element a row press focuses the list with that row selected.
    d.focus_on(4);
    assert_eq!(
        d.pointer(row_mid(&d, 3, 2).0, row_mid(&d, 3, 2).1, LEFT, t + 50_000),
        Event::Focus(Some(4), 3)
    );
    assert_eq!(d.element(3).selected, 2);
    // The window is nawah's own constant (ui.md §3.6).
    assert_eq!(DOUBLE_CLICK_MS, 400);
}

#[test]
fn focus_order_unchanged_after_pointer() {
    let mut d = sample(false);
    let mut before = [0usize; MAX_ELEMENTS];
    let n = d.focus_order(&mut before);
    let r = rects(&d);
    d.click(mid(r[4]), LEFT, T0);
    d.click(row_mid(&d, 3, 1), LEFT, T0 + 5_000);
    let mut after = [0usize; MAX_ELEMENTS];
    assert_eq!(d.focus_order(&mut after), n);
    assert_eq!(before[..n], after[..n]);
    assert_eq!(&after[..n], &[1, 2, 3, 4, 5]);
    // Tab continues from where the pointer put the focus, in the declared order.
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(3), 4));
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(4), 5));
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(5), 1));
    assert_eq!(
        d.key(KEY_TAB, true, MOD_SHIFT, None),
        Event::Focus(Some(1), 5)
    );
}

#[test]
fn context_menu_opens_by_three_ways() {
    let mut d = sample(false);
    // Refused menus: none, too many, an unlabelled item, separators only.
    static NINE: [MenuItem; 9] = [MenuItem::item("One choice", true); 9];
    static BLANK: [MenuItem; 1] = [MenuItem::item("  ", true)];
    static SEPS: [MenuItem; 1] = [MenuItem::SEPARATOR];
    assert!(!d.set_menu(&[]));
    assert!(!d.set_menu(&NINE));
    assert!(!d.set_menu(&BLANK));
    assert!(!d.set_menu(&SEPS));
    // Without a menu, the three ways open nothing; the right press does not even focus.
    d.focus_on(3);
    assert_eq!(d.key(KEY_F10, true, MOD_SHIFT, None), Event::None);
    assert_eq!(d.take_menu_event(), None);
    assert_eq!(d.key(KEY_MENU, true, 0, None), Event::None);
    assert_eq!(d.take_menu_event(), None);
    let b = rects(&d)[4];
    assert_eq!(d.click(mid(b), RIGHT, T0), (Event::None, Event::None));
    assert_eq!(d.take_menu_event(), None);
    assert_eq!(d.focused(), Some(3));
    assert!(d.menu_rect().is_none());
    assert!(d.set_menu(&MENU));
    assert_eq!(d.menu_len(), 3);
    // 1. Shift+F10 on the focused element; the first item takes the focus.
    assert_eq!(d.key(KEY_F10, true, MOD_SHIFT, None), Event::None);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Open(3)));
    assert_eq!(d.menu_focused(), Some(0));
    assert_eq!(d.focused(), None);
    assert_eq!(
        item_text(&d, 0),
        "role=menuitem label=\"Open the file\" state=focused index=1/3"
    );
    d.key(KEY_ESC, true, 0, None);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Close(3)));
    // F10 alone is not the menu.
    assert_eq!(d.key(KEY_F10, true, 0, None), Event::None);
    assert_eq!(d.take_menu_event(), None);
    // 2. The menu key (extended 0x5d, sent as 0x80 | 0x5d by inputd).
    assert_eq!(KEY_MENU, 0xdd);
    assert_eq!(d.key(KEY_MENU, true, 0, None), Event::None);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Open(3)));
    d.key(KEY_ESC, true, 0, None);
    d.take_menu_event();
    // 3. A right press on another element focuses it and opens the menu for it there.
    let r = rects(&d);
    let (x, y) = (r[4].x + 4, mid(r[4]).1);
    assert_eq!(d.pointer(x, y, RIGHT, T0), Event::None);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Open(4)));
    let m = d.menu_rect().unwrap();
    // At the pointer, clamped up into the surface near the dialog's bottom.
    assert_eq!(m.x, x);
    assert!(m.y <= y && m.y + m.h <= d.layout(&mut []).1);
    // Its release chooses nothing; the menu stays open.
    assert_eq!(d.pointer(x, y, 0, T0), Event::None);
    assert_eq!(d.take_menu_event(), None);
    assert!(d.menu_rect().is_some());
    d.key(KEY_ESC, true, 0, None);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Close(4)));
    assert_eq!(d.focused(), Some(4));
    // A right press on a label opens nothing.
    assert_eq!(d.click(mid(r[0]), RIGHT, T0), (Event::None, Event::None));
    assert_eq!(d.take_menu_event(), None);
    // The application can open it itself.
    assert!(d.open_menu(5));
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Open(5)));
    assert!(!d.open_menu(0));
}

#[test]
fn menu_wraps_skips_separators_and_disabled_never_chooses() {
    let mut d = sample(false);
    assert!(d.set_menu(&MENU));
    d.focus_on(3);
    d.key(KEY_MENU, true, 0, None);
    d.take_menu_event();
    let down = |d: &mut Dialog, code| {
        assert_eq!(d.key(code, true, 0, None), Event::None);
        d.take_menu_event()
    };
    assert_eq!(down(&mut d, KEY_DOWN), Some(MenuEvent::Focus(1)));
    // The separator is skipped; the disabled item takes the focus and says so.
    assert_eq!(down(&mut d, KEY_DOWN), Some(MenuEvent::Focus(3)));
    assert_eq!(
        item_text(&d, 3),
        "role=menuitem label=\"Delete the file\" state=focused,disabled index=3/3"
    );
    assert_eq!(
        item_text(&d, 1),
        "role=menuitem label=\"Rename the file\" state=enabled index=2/3"
    );
    // Enter on a disabled item chooses nothing and the menu stays open.
    assert_eq!(down(&mut d, KEY_ENTER), None);
    assert_eq!(d.menu_focused(), Some(3));
    // Wrap both ways.
    assert_eq!(down(&mut d, KEY_DOWN), Some(MenuEvent::Focus(0)));
    assert_eq!(down(&mut d, KEY_UP), Some(MenuEvent::Focus(3)));
    assert_eq!(down(&mut d, KEY_UP), Some(MenuEvent::Focus(1)));
    // Enter chooses an enabled item, closes the menu and returns the focus.
    assert_eq!(down(&mut d, KEY_ENTER), Some(MenuEvent::Choose(3, 1)));
    assert!(d.menu_rect().is_none());
    assert_eq!(d.focused(), Some(3));
    // By the pointer: the disabled item is focused by a press but never chosen.
    d.key(KEY_MENU, true, 0, None);
    d.take_menu_event();
    let dis = d.menu_item_rect(3).unwrap();
    assert_eq!(d.pointer(mid(dis).0, mid(dis).1, LEFT, T0), Event::None);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Focus(3)));
    assert_eq!(d.pointer(mid(dis).0, mid(dis).1, 0, T0), Event::None);
    assert_eq!(d.take_menu_event(), None);
    assert!(d.menu_rect().is_some());
    // The separator takes no press.
    let sep = d.menu_item_rect(2).unwrap();
    assert_eq!(d.click(mid(sep), LEFT, T0), (Event::None, Event::None));
    assert_eq!(d.take_menu_event(), None);
    assert_eq!(d.menu_focused(), Some(3));
    // A left release on the item it was pressed on chooses it.
    let first = d.menu_item_rect(0).unwrap();
    d.pointer(mid(first).0, mid(first).1, LEFT, T0);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Focus(0)));
    d.pointer(mid(first).0, mid(first).1, 0, T0);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Choose(3, 0)));
    assert_eq!(d.focused(), Some(3));
}

#[test]
fn esc_and_outside_click_close_and_return_focus() {
    let mut d = sample(false);
    assert!(d.set_menu(&MENU));
    d.focus_on(3);
    d.key(KEY_F10, true, MOD_SHIFT, None);
    d.take_menu_event();
    // Tab is ignored while the menu is open.
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::None);
    assert_eq!(d.take_menu_event(), None);
    assert_eq!(d.menu_focused(), Some(0));
    // Esc closes the menu (not the dialog) and the focus returns to its element.
    assert_eq!(d.key(KEY_ESC, true, 0, None), Event::None);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Close(3)));
    assert_eq!(d.focused(), Some(3));
    assert!(d.menu_rect().is_none());
    assert_eq!(d.menu_focused(), None);
    // A press outside the menu closes it; the focus returns to the opener, not the
    // element under the press, and the release does nothing.
    d.key(KEY_F10, true, MOD_SHIFT, None);
    d.take_menu_event();
    let r = rects(&d);
    let m = d.menu_rect().unwrap();
    let (x, y) = mid(r[1]);
    assert!(y < m.y);
    assert_eq!(d.pointer(x, y, LEFT, T0), Event::None);
    assert_eq!(d.take_menu_event(), Some(MenuEvent::Close(3)));
    assert_eq!(d.focused(), Some(3));
    assert_eq!(d.pointer(x, y, 0, T0), Event::None);
    assert_eq!(d.focused(), Some(3));
    // After it, Esc is the dialog's cancel again.
    assert_eq!(d.key(KEY_ESC, true, 0, None), Event::Cancel);
}

#[test]
fn menu_mirrors_in_rtl() {
    for rtl in [false, true] {
        let mut d = sample(rtl);
        assert!(d.set_menu(&MENU_AR));
        let r = rects(&d);
        let (sw, sh) = d.layout(&mut []);
        // From the keyboard it opens below the element, from its start edge.
        d.focus_on(1);
        d.key(KEY_MENU, true, 0, None);
        let m = d.menu_rect().unwrap();
        assert_eq!(m.y, r[1].y + r[1].h);
        if rtl {
            assert_eq!(m.x + m.w, r[1].x + r[1].w, "rtl opens leftwards");
        } else {
            assert_eq!(m.x, r[1].x);
        }
        assert_eq!(
            item_text(&d, 0),
            "role=menuitem label=\"افتح الملف\" state=focused index=1/2"
        );
        d.key(KEY_ESC, true, 0, None);
        // From the pointer it opens toward the reading direction and flips at the edge.
        let y = mid(r[4]).1;
        let (left, right) = (r[4].x + 2, r[4].x + r[4].w - 2);
        let (near_start, near_end) = if rtl { (right, left) } else { (left, right) };
        d.pointer(near_start, y, RIGHT, T0);
        d.pointer(near_start, y, 0, T0);
        let m = d.menu_rect().unwrap();
        if rtl {
            assert_eq!(m.x + m.w, near_start);
        } else {
            assert_eq!(m.x, near_start);
        }
        d.key(KEY_ESC, true, 0, None);
        d.pointer(near_end, y, RIGHT, T0);
        d.pointer(near_end, y, 0, T0);
        let m = d.menu_rect().unwrap();
        if rtl {
            assert_eq!(m.x, near_end, "flipped at the left edge");
        } else {
            assert_eq!(m.x + m.w, near_end, "flipped at the right edge");
        }
        d.key(KEY_ESC, true, 0, None);
        // Low in the dialog it is clamped inside the surface.
        let low = r[5].y + r[5].h - 1;
        d.pointer(sw / 2, low, RIGHT, T0);
        d.pointer(sw / 2, low, 0, T0);
        let m = d.menu_rect().unwrap();
        assert!(m.x >= 0 && m.y >= 0 && m.x + m.w <= sw && m.y + m.h <= sh);
        d.key(KEY_ESC, true, 0, None);
    }
    // At 2x, the smallest dialog with the largest menu: the surface grows to hold the menu
    // and still fits one surface VMO (1 MiB: 262144 pixels).
    static EIGHT: [MenuItem; 8] = [MenuItem::item("One choice", true); 8];
    let mut d = Dialog::new("Small", true);
    d.theme = Theme {
        scale: 8,
        high_contrast: false,
    };
    d.add(Role::Button, "Close").unwrap();
    d.start();
    assert!(d.set_menu(&EIGHT));
    d.key(KEY_MENU, true, 0, None);
    let (w, h) = d.layout(&mut []);
    let m = d.menu_rect().unwrap();
    assert!(
        m.x >= 0 && m.y >= 0 && m.x + m.w <= w && m.y + m.h <= h,
        "{m:?} in {w}x{h}"
    );
    assert!(w * h <= 262_144, "{w}x{h}");
    for k in 0..8 {
        let ir = d.menu_item_rect(k).unwrap();
        assert!(ir.y >= m.y && ir.y + ir.h <= m.y + m.h);
    }
}

#[test]
fn describe_menu_item_out_of_range_is_none() {
    let mut d = sample(false);
    let mut t = Text::default();
    // No menu: no entry to describe, nothing written.
    assert_eq!(d.describe_menu_item(0, &mut t), None);
    assert!(d.set_menu(&MENU));
    assert_eq!(d.describe_menu_item(MENU.len(), &mut t), None);
    assert_eq!(d.describe_menu_item(usize::MAX, &mut t), None);
    assert!(t.as_bytes().is_empty());
    // In range, closed: described without focus.
    assert!(d.describe_menu_item(3, &mut t).is_some());
    assert_eq!(
        t.as_bytes(),
        "role=menuitem label=\"Delete the file\" state=disabled index=3/3".as_bytes()
    );
}
