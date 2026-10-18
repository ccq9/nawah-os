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
