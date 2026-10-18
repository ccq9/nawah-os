//! libui's unit tests (TST-M5-KEYBOARD-NAV/A11Y-TREE host part): build refusals, the focus
//! order, the keys of ui.md §2, the descriptions, and the drawing's theme.

use super::*;
use nawah_text::font::Font;

const LATIN_TTF: &[u8] = include_bytes!("../../../platform/assets/fonts/NotoSans-Regular.ttf");
const ARABIC_TTF: &[u8] =
    include_bytes!("../../../platform/assets/fonts/NotoSansArabic-Regular.ttf");
const LANGS: &[&str] = &["English", "العربية", "Français"];

fn sample() -> Dialog {
    let mut d = Dialog::new("Sign in", false);
    d.add(Role::Label, "Sign in").unwrap();
    d.add(Role::TextField, "Name").unwrap();
    d.add_list("Language", LANGS).unwrap();
    d.add(Role::Checkbox, "Remember me").unwrap();
    d.add(Role::Button, "OK").unwrap();
    d.add(Role::Button, "Cancel").unwrap();
    d
}

fn describe(d: &Dialog, i: usize) -> String {
    let mut t = Text::new();
    d.describe(i, &mut t);
    String::from_utf8(t.as_bytes().to_vec()).unwrap()
}

#[test]
fn elements_without_labels_are_refused() {
    let mut d = Dialog::new("x", false);
    assert_eq!(d.add(Role::Button, ""), Err(UiError::NoLabel));
    assert_eq!(d.add(Role::Button, "   "), Err(UiError::NoLabel));
    assert_eq!(d.add_list("", LANGS), Err(UiError::NoLabel));
    assert_eq!(d.add_list("L", &["a", ""]), Err(UiError::NoLabel));
    assert_eq!(d.add_list("L", &[]), Err(UiError::NoItems));
    assert_eq!(d.add(Role::List, "L"), Err(UiError::NoItems));
    assert!(d.is_empty());
    for _ in 0..MAX_ELEMENTS {
        d.add(Role::Button, "b").unwrap();
    }
    assert_eq!(d.add(Role::Button, "b"), Err(UiError::Full));
}

#[test]
fn focus_order_is_declared_order_without_labels() {
    let d = sample();
    let mut order = [0usize; MAX_ELEMENTS];
    let n = d.focus_order(&mut order);
    assert_eq!(&order[..n], &[1, 2, 3, 4, 5]);
}

#[test]
fn tab_and_shift_tab_cycle() {
    let mut d = sample();
    assert_eq!(d.start(), Event::Focus(None, 1));
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(1), 2));
    assert_eq!(d.key(KEY_TAB, false, 0, None), Event::None);
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(2), 3));
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(3), 4));
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(4), 5));
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(5), 1));
    assert_eq!(
        d.key(KEY_TAB, true, MOD_SHIFT, None),
        Event::Focus(Some(1), 5)
    );
    assert_eq!(d.key(KEY_ESC, true, 0, None), Event::Cancel);
}

#[test]
fn keys_act_on_the_focused_element() {
    let mut d = sample();
    d.start();
    // Text field: characters (Arabic too), backspace, cursor.
    assert_eq!(d.key(0x1e, true, 0, Some('a')), Event::Edit(1));
    assert_eq!(d.key(0x1e, true, 0, Some('ش')), Event::Edit(1));
    assert_eq!(
        describe(&d, 1),
        "role=textfield label=\"Name\" state=focused value=\"aش\""
    );
    assert_eq!(d.key(KEY_BACKSPACE, true, 0, None), Event::Edit(1));
    assert_eq!(d.key(KEY_LEFT, true, 0, None), Event::None);
    assert_eq!(d.key(0x30, true, 1, Some('B')), Event::Edit(1));
    assert_eq!(
        describe(&d, 1),
        "role=textfield label=\"Name\" state=focused value=\"Ba\""
    );
    // List: arrows inside, clamped.
    d.key(KEY_TAB, true, 0, None);
    assert_eq!(d.key(KEY_UP, true, 0, None), Event::None);
    assert_eq!(d.key(KEY_DOWN, true, 0, None), Event::Select(2, 1));
    assert_eq!(d.key(KEY_DOWN, true, 0, None), Event::Select(2, 2));
    assert_eq!(d.key(KEY_DOWN, true, 0, None), Event::None);
    assert_eq!(
        describe(&d, 2),
        "role=list label=\"Language\" state=focused item=\"Français\" index=3/3"
    );
    // Checkbox: space and enter toggle.
    d.key(KEY_TAB, true, 0, None);
    assert_eq!(d.key(KEY_SPACE, true, 0, None), Event::Toggle(3, true));
    assert_eq!(
        describe(&d, 3),
        "role=checkbox label=\"Remember me\" state=focused,checked"
    );
    assert_eq!(d.key(KEY_ENTER, true, 0, None), Event::Toggle(3, false));
    // Button: enter activates.
    d.key(KEY_TAB, true, 0, None);
    assert_eq!(d.key(KEY_ENTER, true, 0, None), Event::Activate(4));
    assert_eq!(describe(&d, 4), "role=button label=\"OK\" state=focused");
    assert_eq!(
        describe(&d, 5),
        "role=button label=\"Cancel\" state=enabled"
    );
    assert_eq!(describe(&d, 0), "role=label label=\"Sign in\" state=static");
}

#[test]
fn theme_from_config() {
    assert_eq!(
        Theme::from_config(b"2", b"high"),
        Theme {
            scale: 8,
            high_contrast: true
        }
    );
    assert_eq!(
        Theme::from_config(b"1.5", b"normal"),
        Theme {
            scale: 6,
            high_contrast: false
        }
    );
    assert_eq!(Theme::from_config(b"x", b""), Theme::DEFAULT);
}

#[test]
fn scale_doubles_the_layout_and_contrast_changes_the_palette() {
    let mut d = sample();
    let mut r1 = [Rect::default(); MAX_ELEMENTS];
    let (w1, h1) = d.layout(&mut r1);
    d.theme = Theme {
        scale: 8,
        high_contrast: true,
    };
    let mut r2 = [Rect::default(); MAX_ELEMENTS];
    let (w2, h2) = d.layout(&mut r2);
    assert_eq!((w2, h2), (2 * w1, 2 * h1));
    for i in 0..d.len() {
        assert_eq!(
            r2[i],
            Rect {
                x: 2 * r1[i].x,
                y: 2 * r1[i].y,
                w: 2 * r1[i].w,
                h: 2 * r1[i].h
            }
        );
    }
    // The largest dialog fits one surface VMO (1 MiB: 262144 pixels).
    assert!(w2 * h2 <= 262_144, "{}x{}", w2, h2);
}

#[test]
fn paint_uses_the_theme_and_marks_the_focus() {
    let fonts = Fonts {
        latin: Font::parse(LATIN_TTF).unwrap(),
        arabic: Font::parse(ARABIC_TTF).unwrap(),
    };
    let mut painter = Box::new(Painter::new());
    for (theme, focus_rgb, bg) in [
        (Theme::DEFAULT, 0x1E64C8, 0xF0F0F0),
        (
            Theme {
                scale: 8,
                high_contrast: true,
            },
            0xFFFF00,
            0x000000,
        ),
    ] {
        let mut d = sample();
        d.theme = theme;
        d.start();
        let mut rects = [Rect::default(); MAX_ELEMENTS];
        let (w, h) = d.layout(&mut rects);
        let (w, h) = (w as usize, h as usize);
        let mut buf = vec![0u32; w * h];
        painter.paint(&d, &fonts, &mut buf, w, h);
        assert_eq!(buf[0], bg);
        // The focus ring sits just outside the focused element (the text field).
        let r = rects[1];
        let ring = (2 * theme.scale as i32 / 4).max(2);
        assert_eq!(
            buf[(r.y - ring) as usize * w + (r.x + r.w / 2) as usize],
            focus_rgb
        );
        // Text was drawn: label pixels left the background, and the darkest/brightest of
        // them is the foreground colour (fully covered samples).
        let lr = rects[0];
        let fg = theme.palette().fg;
        let mut ink = 0;
        let mut full = 0;
        for y in lr.y..lr.y + lr.h {
            for x in lr.x..lr.x + lr.w {
                let p = buf[y as usize * w + x as usize];
                if p != bg {
                    ink += 1;
                }
                if p == fg {
                    full += 1;
                }
            }
        }
        assert!(ink > 40 && full > 0, "label ink {} full {}", ink, full);
    }
}

// ---- v1.1 (WP-37): the password field and the application's access to values ----------

fn login() -> Dialog {
    let mut d = Dialog::new("Sign in", false);
    d.add(Role::Label, "Nawah").unwrap();
    d.add(Role::TextField, "User name").unwrap();
    d.add(Role::Password, "Password").unwrap();
    d.add(Role::Button, "Sign in").unwrap();
    d
}

fn value(d: &Dialog, i: usize) -> String {
    let mut buf = [0u8; 4 * TEXT_MAX];
    let n = d.value(i, &mut buf);
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

#[test]
fn password_is_edited_like_a_field_and_never_described() {
    let mut d = login();
    assert_eq!(d.start(), Event::Focus(None, 1));
    assert_eq!(d.key(KEY_TAB, true, 0, None), Event::Focus(Some(1), 2));
    for (code, c) in [(0x19, 'p'), (0x11, 'w'), (0x02, '1')] {
        assert_eq!(d.key(code, true, 0, Some(c)), Event::Edit(2));
    }
    assert_eq!(value(&d, 2), "pw1");
    // The description has the role, the label and the state, never the value or its length.
    assert_eq!(
        describe(&d, 2),
        "role=password label=\"Password\" state=focused"
    );
    d.key(KEY_TAB, true, 0, None);
    assert_eq!(
        describe(&d, 2),
        "role=password label=\"Password\" state=enabled"
    );
    d.key(KEY_TAB, true, MOD_SHIFT, None);
    // Backspace deletes before the cursor and leaves no character behind the length.
    assert_eq!(d.key(KEY_BACKSPACE, true, 0, None), Event::Edit(2));
    assert_eq!(value(&d, 2), "pw");
    assert_eq!(d.element(2).text[2], 0);
    assert_eq!(d.key(KEY_LEFT, true, 0, None), Event::None);
    assert_eq!(d.key(0x1e, true, 0, Some('a')), Event::Edit(2));
    assert_eq!(value(&d, 2), "paw");
    assert_eq!(d.key(KEY_ENTER, true, 0, None), Event::Activate(2));
}

#[test]
fn clear_set_value_and_focus_on() {
    let mut d = login();
    d.start();
    d.key(0x1e, true, 0, Some('a'));
    d.focus_on(2);
    d.key(0x1e, true, 0, Some('x'));
    d.clear_value(2);
    assert_eq!(value(&d, 2), "");
    assert_eq!(d.element(2).text, [0; TEXT_MAX]);
    assert_eq!((d.element(2).text_len, d.element(2).cursor), (0, 0));
    // A text field takes a value from the application; a password never does.
    assert!(d.set_value(1, "admin"));
    assert_eq!(value(&d, 1), "admin");
    assert_eq!(d.element(1).cursor, 5);
    assert!(!d.set_value(2, "secret"));
    assert_eq!(value(&d, 2), "");
    assert!(!d.set_value(0, "label"));
    // The focus goes only where it can.
    assert_eq!(d.focus_on(2), Event::Focus(Some(2), 2));
    assert_eq!(d.focus_on(3), Event::Focus(Some(2), 3));
    assert_eq!(d.focus_on(0), Event::None);
    assert_eq!(d.focus_on(9), Event::None);
    assert_eq!(d.focused(), Some(3));
    // Other roles have no value.
    assert_eq!(value(&d, 0), "");
    assert_eq!(value(&d, 3), "");
}

#[test]
fn password_is_drawn_as_bullets() {
    let fonts = Fonts {
        latin: Font::parse(LATIN_TTF).unwrap(),
        arabic: Font::parse(ARABIC_TTF).unwrap(),
    };
    let mut painter = Box::new(Painter::new());
    let render = |d: &Dialog, painter: &mut Painter| {
        let mut rects = [Rect::default(); MAX_ELEMENTS];
        let (w, h) = d.layout(&mut rects);
        let (w, h) = (w as usize, h as usize);
        let mut buf = vec![0u32; w * h];
        painter.paint(d, &fonts, &mut buf, w, h);
        (buf, rects[2], w)
    };
    // The same dialog with a password "abc" and with a text field holding three bullets.
    let mut secret = login();
    secret.focus_on(2);
    for (code, c) in [(0x1e, 'a'), (0x30, 'b'), (0x2e, 'c')] {
        secret.key(code, true, 0, Some(c));
    }
    let mut shown = Dialog::new("Sign in", false);
    shown.add(Role::Label, "Nawah").unwrap();
    shown.add(Role::TextField, "User name").unwrap();
    shown.add(Role::TextField, "Password").unwrap();
    shown.add(Role::Button, "Sign in").unwrap();
    shown.focus_on(2);
    for _ in 0..3 {
        shown.key(0x09, true, 0, Some('\u{2022}'));
    }
    let mut plain = Dialog::new("Sign in", false);
    plain.add(Role::Label, "Nawah").unwrap();
    plain.add(Role::TextField, "User name").unwrap();
    plain.add(Role::TextField, "Password").unwrap();
    plain.add(Role::Button, "Sign in").unwrap();
    plain.focus_on(2);
    for (code, c) in [(0x1e, 'a'), (0x30, 'b'), (0x2e, 'c')] {
        plain.key(code, true, 0, Some(c));
    }
    let (a, r, w) = render(&secret, &mut painter);
    let (b, _, _) = render(&shown, &mut painter);
    let (c, _, _) = render(&plain, &mut painter);
    let field = |buf: &[u32]| -> Vec<u32> {
        let mut v = Vec::new();
        for y in r.y..r.y + r.h {
            for x in r.x..r.x + r.w {
                v.push(buf[y as usize * w + x as usize]);
            }
        }
        v
    };
    assert_eq!(
        field(&a),
        field(&b),
        "a password field draws one bullet per character"
    );
    assert_ne!(
        field(&a),
        field(&c),
        "the characters themselves are not drawn"
    );
    let bg = Theme::DEFAULT.palette().control;
    assert!(field(&a).iter().filter(|&&p| p != bg).count() > 20);
}

// ---- v1.2 (WP-39): reading direction and live relabelling --------------------------------

/// In a left-to-right field Right is forward and Left is back; in a right-to-left field they
/// swap, so the same keys put the inserted character on opposite sides (ui.md v1.2 §3.2).
#[test]
fn rtl_field_arrows_follow_reading_direction() {
    let type_ab = |d: &mut Dialog| {
        d.focus_on(1);
        d.key(0x1e, true, 0, Some('a')); // "a", cursor 1
        d.key(0x30, true, 0, Some('b')); // "ab", cursor 2
    };
    // Left to right: Left steps back, then an insert lands before 'b'.
    let mut ltr = sample();
    type_ab(&mut ltr);
    assert_eq!(ltr.key(KEY_LEFT, true, 0, None), Event::None);
    ltr.key(0x2e, true, 0, Some('x'));
    assert_eq!(
        describe(&ltr, 1),
        "role=textfield label=\"Name\" state=focused value=\"axb\""
    );

    // Right to left: Right is the one that steps back now.
    let mut rtl = Dialog::new("دخول", true);
    rtl.add(Role::Label, "دخول").unwrap();
    rtl.add(Role::TextField, "الاسم").unwrap();
    type_ab(&mut rtl);
    // Left is forward at the end: it cannot move, so the insert stays at the end.
    assert_eq!(rtl.key(KEY_LEFT, true, 0, None), Event::None);
    rtl.key(0x2e, true, 0, Some('x'));
    assert_eq!(
        describe(&rtl, 1),
        "role=textfield label=\"الاسم\" state=focused value=\"abx\""
    );
    // Right steps back, so the next insert lands inside.
    assert_eq!(rtl.key(KEY_RIGHT, true, 0, None), Event::None);
    rtl.key(0x15, true, 0, Some('y'));
    assert_eq!(
        describe(&rtl, 1),
        "role=textfield label=\"الاسم\" state=focused value=\"abyx\""
    );

    // set_rtl flips an existing dialog's behaviour.
    let mut d = sample();
    d.set_rtl(true);
    type_ab(&mut d);
    assert_eq!(d.key(KEY_RIGHT, true, 0, None), Event::None);
    d.key(0x2e, true, 0, Some('x'));
    assert_eq!(
        describe(&d, 1),
        "role=textfield label=\"Name\" state=focused value=\"axb\""
    );
}

/// relabel and set_items change an element in place for a language switch, with the selection
/// clamped and bad arguments refused (ui.md v1.2 §3.2).
#[test]
fn relabel_and_set_items_switch_language() {
    const AR: &[&str] = &["الإنجليزية", "العربية"];
    let mut d = sample();
    // Move the list selection to the last item, then shrink the list under it.
    d.focus_on(2);
    d.key(KEY_DOWN, true, 0, None);
    d.key(KEY_DOWN, true, 0, None); // Français (index 3/3)
    assert!(d.relabel(0, "دخول"));
    assert!(d.relabel(1, "الاسم"));
    assert!(d.relabel(2, "اللغة"));
    assert!(d.set_items(2, AR));
    d.set_rtl(true);
    assert_eq!(describe(&d, 0), "role=label label=\"دخول\" state=static");
    assert_eq!(
        describe(&d, 2),
        "role=list label=\"اللغة\" state=focused item=\"العربية\" index=2/2"
    );
    // Refusals: empty label, a non-list, too many items, a blank item.
    const SEVEN: &[&str] = &["1", "2", "3", "4", "5", "6", "7"];
    assert!(!d.relabel(1, "   "));
    assert!(!d.set_items(1, AR));
    assert!(!d.set_items(2, SEVEN));
    assert!(!d.set_items(2, &["x", "  "]));
    assert!(!d.relabel(99, "x"));
}
