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

/// A value (ui.md v1.3) holds text the application sets and the user only reads: it is never
/// focused, it is described with its value and as static, and a key cannot change it.
#[test]
fn a_value_is_read_only_and_described() {
    let mut d = Dialog::new("Approve", false);
    d.add(Role::Label, "Request").unwrap();
    let v = d.add(Role::Value, "Request").unwrap();
    let f = d.add(Role::TextField, "Administrator").unwrap();
    assert!(d.set_value(v, "config SET device lab.elev 0 901 on"));
    assert_eq!(
        describe(&d, v),
        "role=value label=\"Request\" state=static value=\"config SET device lab.elev 0 901 on\""
    );
    // The focus skips it: the first focus is the field after it, and Tab never lands on it.
    assert_eq!(d.start(), Event::Focus(None, f));
    let mut order = [0usize; MAX_ELEMENTS];
    assert_eq!(d.focus_order(&mut order), 1);
    d.key(0x1e, true, 0, Some('a'));
    assert_eq!(
        describe(&d, v),
        "role=value label=\"Request\" state=static value=\"config SET device lab.elev 0 901 on\""
    );
    // A request longer than TEXT_MAX characters keeps only the first TEXT_MAX.
    let long: String = core::iter::repeat_n('x', TEXT_MAX + 5).collect();
    assert!(d.set_value(v, &long));
    assert_eq!(d.element(v).text_len, TEXT_MAX);
    // A password is never filled by the application.
    let p = d.add(Role::Password, "Password").unwrap();
    assert!(!d.set_value(p, "secret"));
}

/// v1.5 (WP-38): `fits` measures a label or value as `paint` lays it out, so an application
/// can refuse a text the surface would clip instead of showing part of it.
#[test]
fn fits_measures_the_row_as_painted() {
    let fonts = Fonts {
        latin: Font::parse(LATIN_TTF).unwrap(),
        arabic: Font::parse(ARABIC_TTF).unwrap(),
    };
    let mut p = Box::new(Painter::new());
    for rtl in [false, true] {
        let d = Dialog::new("Administrator approval", rtl);
        // The widest prompt the session's limits allow (15 + 1 + 32 characters), and a
        // 32-character request of wide letters (279 pixels at 14 px): neither fits the row (241 pixels at 1x).
        assert!(!p.fits(
            &d,
            &fonts,
            "WWWWWWWWWWWWWWW WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"
        ));
        assert!(!p.fits(&d, &fonts, "config SET device MMMMMMMM 0 901 off"));
        // The lab's requests fit, the widest of them (lab.elev2…8, 235 pixels) too.
        assert!(p.fits(&d, &fonts, "config SET device lab.elev 0 901 on"));
        assert!(p.fits(&d, &fonts, "config SET device lab.elev7 0 907 on"));
        assert!(p.fits(&d, &fonts, "config SET device lab.elev8 0 908 on"));
        // The session's prompt label, split in two rows because it is wider than one.
        assert!(!p.fits(
            &d,
            &fonts,
            "An application asks to act as an administrator."
        ));
        assert!(p.fits(&d, &fonts, "An application asks to act"));
        assert!(p.fits(&d, &fonts, "as an administrator."));
        // More characters than a value keeps never fits, however narrow.
        let long: String = core::iter::repeat_n('.', TEXT_MAX + 1).collect();
        assert!(!p.fits(&d, &fonts, &long));
    }
    // The bound follows the theme: twice the scale, twice the row and the font.
    let mut d = Dialog::new("Administrator approval", false);
    d.theme.scale = 8;
    assert!(p.fits(&d, &fonts, "config SET device lab.elev7 0 907 on"));
    assert!(!p.fits(&d, &fonts, "config SET device MMMMMMMM 0 901 off"));
}

/// WP-94 (ui.md v1.9, RSK-022): the value of a text field or value element is data (typed by
/// the user, or set by the application from a request it received), and the description puts
/// it between quotes. A quote, a control character, a line or paragraph separator or a bidi
/// formatting character in it is written `[U+XXXX]`, as the list view writes its cells, so a
/// value never ends itself, its line or its direction.
#[test]
fn a_quote_in_a_typed_value_cannot_forge_an_attribute() {
    let mut d = sample();
    d.start();
    for c in "x\" label=\"Password".chars() {
        assert_eq!(d.key(0x1e, true, 0, Some(c)), Event::Edit(1));
    }
    assert_eq!(
        describe(&d, 1),
        "role=textfield label=\"Name\" state=focused value=\"x[U+0022] label=[U+0022]Password\""
    );
}

#[test]
fn a_set_value_with_a_newline_stays_one_line() {
    let mut d = Dialog::new("Approve", false);
    d.add(Role::Label, "Request").unwrap();
    let v = d.add(Role::Value, "Request").unwrap();
    assert!(d.set_value(v, "a\" state=focused\nfocus role=button label=\"Del\""));
    let line = describe(&d, v);
    assert_eq!(
        line,
        "role=value label=\"Request\" state=static value=\"a[U+0022] state=focused[U+000A]focus role=button label=[U+0022]Del[U+0022]\""
    );
    assert!(!line.contains('\n'));
    // Exactly the quotes of the format: around the label and around the value.
    assert_eq!(line.matches('"').count(), 4);
}

#[test]
fn separators_and_bidi_controls_in_a_value_are_named_not_obeyed() {
    let mut d = Dialog::new("Approve", false);
    d.add(Role::Label, "Request").unwrap();
    let v = d.add(Role::Value, "Request").unwrap();
    assert!(d.set_value(
        v,
        "a\u{202E}b\u{2028}c\u{2029}d\u{200F}e\u{7F}f\u{85}g\u{0}h"
    ));
    assert_eq!(
        describe(&d, v),
        "role=value label=\"Request\" state=static value=\"a[U+202E]b[U+2028]c[U+2029]d[U+200F]e[U+007F]f[U+0085]g[U+0000]h\""
    );
}

#[test]
fn a_long_escaped_value_is_cut_at_a_whole_character_and_still_closed() {
    // The line holds 256 bytes. A value that does not fit with its closing quote is cut before
    // the first character or `[U+XXXX]` that would not leave room for the quote and for the
    // cut's own mark, ` cut=<k>`: k characters of the value are not in the line, so a listener
    // is never read a shortened request as if it were whole (the audit of WP-94).
    let value = |label: &'static str, text: &str| {
        let mut d = Dialog::new("Approve", false);
        d.add(Role::Label, "x").unwrap();
        let v = d.add(Role::Value, label).unwrap();
        assert!(d.set_value(v, text));
        describe(&d, v)
    };
    let quotes = |n: usize| -> String { core::iter::repeat_n('"', n).collect() };
    let head = "role=value label=\"Request\" state=static value=\""; // 47 bytes
    assert_eq!(head.len(), 47);
    // 48 quotes need 384 bytes: 25 fit with the quote and the mark, 23 are counted.
    assert_eq!(
        value("Request", &quotes(TEXT_MAX)),
        format!("{head}{}\" cut=23", "[U+0022]".repeat(25))
    );
    // Exactly full: 47 + 26 x 8 + the closing quote = 256. Nothing is cut, nothing is marked.
    let full = value("Request", &quotes(26));
    assert_eq!(full, format!("{head}{}\"", "[U+0022]".repeat(26)));
    assert_eq!(full.len(), 256);
    // One byte more does not fit: the cut is at the 26th quote, and the `z` after it is not
    // slipped in although it would fit by itself (the order of the value is kept).
    assert_eq!(
        value("Request", &format!("{}z", quotes(26))),
        format!("{head}{}\" cut=2", "[U+0022]".repeat(25))
    );
    // 48 four-byte characters fit (47 + 192 + 1 = 240): written whole, no mark.
    let wide: String = core::iter::repeat_n('\u{10348}', TEXT_MAX).collect();
    assert_eq!(value("Request", &wide), format!("{head}{wide}\""));
    // Behind a long label they do not: 28 whole characters, 20 counted, the line closed.
    let long_label: &'static str = "Lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll";
    let head = format!("role=value label=\"{long_label}\" state=static value=\"");
    assert_eq!(head.len(), 135);
    let line = value(long_label, &wide);
    assert_eq!(line, format!("{head}{}\" cut=20", "\u{10348}".repeat(28)));
    assert!(line.len() <= 256);
}

#[test]
fn plain_values_read_as_before() {
    // The frozen lines of v1 to v1.8 are unchanged for values without those characters.
    let mut d = Dialog::new("Approve", false);
    d.add(Role::Label, "Request").unwrap();
    let v = d.add(Role::Value, "Request").unwrap();
    assert!(d.set_value(v, "config SET device lab.elev 0 901 on [x] 'q' \\ ش"));
    assert_eq!(
        describe(&d, v),
        "role=value label=\"Request\" state=static value=\"config SET device lab.elev 0 901 on [x] 'q' \\ ش\""
    );
}
