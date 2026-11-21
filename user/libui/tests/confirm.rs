//! TST-M6-UI-CONFIRM (WP-80, ui.md v1.7 §3.7): the confirm dialog on the host. Every prompt and
//! button label here is nawah's own whole sentence; the machine tokens are English (ui.md §3).

use libui::*;
use nawah_text::font::Font;
use nawah_text::layout::Fonts;

const LATIN_TTF: &[u8] = include_bytes!("../../../platform/assets/fonts/NotoSans-Regular.ttf");
const ARABIC_TTF: &[u8] =
    include_bytes!("../../../platform/assets/fonts/NotoSansArabic-Regular.ttf");

const T0: u64 = 1_000;

const PROMPT: &str = "Move notes.txt to the trash?";
const YES: &str = "Move it to the trash";
const NO: &str = "Keep the file";
const CANCEL: &str = "Decide later";
const PROMPT_AR: &str = "هل تنقل notes.txt إلى سلة المهملات؟";
const YES_AR: &str = "انقله إلى السلة";
const NO_AR: &str = "أبقِ الملف";
const CANCEL_AR: &str = "قرّر لاحقًا";
static MENU: [MenuItem; 1] = [MenuItem::item("Rename the file", true)];

fn confirm(rtl: bool, default: Answer) -> (Dialog, Event) {
    let mut d = Dialog::new("Trash", rtl);
    let ev = d.confirm(PROMPT, YES, NO, CANCEL, default).unwrap();
    (d, ev)
}

fn rects(d: &Dialog) -> ([Rect; MAX_ELEMENTS], (i32, i32)) {
    let mut r = [Rect::default(); MAX_ELEMENTS];
    let size = d.layout(&mut r);
    (r, size)
}

fn mid(r: Rect) -> (i32, i32) {
    (r.x + r.w / 2, r.y + r.h / 2)
}

fn press(d: &mut Dialog, code: u32, mods: u32) -> Event {
    let ev = d.key(code, true, mods, None);
    d.key(code, false, mods, None);
    ev
}

fn line(prefix: &str, f: impl FnOnce(&mut Text)) -> String {
    let mut t = Text::new();
    t.put(prefix.as_bytes());
    f(&mut t);
    String::from_utf8(t.as_bytes().to_vec()).unwrap()
}

#[test]
fn confirm_default_esc_enter() {
    // The composition: element 0 the prompt (a label), then the three buttons in this order.
    let (mut d, ev) = confirm(false, Answer::No);
    assert_eq!(d.len(), 4);
    assert_eq!(d.element(0).role, Role::Label);
    assert_eq!(d.element(0).label, PROMPT);
    for (a, label) in [
        (Answer::Yes, YES),
        (Answer::No, NO),
        (Answer::Cancel, CANCEL),
    ] {
        assert_eq!(d.element(a.element()).role, Role::Button);
        assert_eq!(d.element(a.element()).label, label);
    }
    assert_eq!((Answer::Yes.element(), Answer::No.element()), (1, 2));
    assert_eq!(Answer::Cancel.element(), 3);
    // The default takes the first focus, and start() puts it back there.
    assert_eq!(ev, Event::Focus(None, Answer::No.element()));
    assert_eq!(d.focused(), Some(2));
    assert_eq!(d.answer(), None);
    assert_eq!(d.start(), Event::Focus(Some(2), 2));
    // Characters and arrows do nothing; the context menu never opens on a confirm.
    assert_eq!(d.key(0x15, true, 0, Some('y')), Event::None);
    for k in [KEY_LEFT, KEY_RIGHT, KEY_UP, KEY_DOWN, KEY_BACKSPACE] {
        assert_eq!(press(&mut d, k, 0), Event::None);
        assert_eq!(d.focused(), Some(2));
    }
    assert!(!d.set_menu(&MENU));
    assert_eq!(press(&mut d, KEY_F10, MOD_SHIFT), Event::None);
    assert_eq!(press(&mut d, KEY_MENU, 0), Event::None);
    assert_eq!(d.take_menu_event(), None);
    assert_eq!((d.focused(), d.answer()), (Some(2), None));
    // Enter answers the focused (default) button.
    assert_eq!(press(&mut d, KEY_ENTER, 0), Event::Activate(2));
    assert_eq!(d.answer(), Some(Answer::No));
    // An answer is final: later keys and clicks change nothing.
    assert_eq!(press(&mut d, KEY_TAB, 0), Event::None);
    assert_eq!(press(&mut d, KEY_ESC, 0), Event::None);
    assert_eq!(press(&mut d, KEY_ENTER, 0), Event::None);
    assert_eq!(d.answer(), Some(Answer::No));

    // Tab cycles only the three buttons, in both directions; the prompt is never focused.
    let (mut d, _) = confirm(false, Answer::Yes);
    assert_eq!(d.focused(), Some(1));
    let mut seen = Vec::new();
    for _ in 0..6 {
        match press(&mut d, KEY_TAB, 0) {
            Event::Focus(_, to) => seen.push(to),
            other => panic!("Tab gave {other:?}"),
        }
    }
    assert_eq!(seen, [2, 3, 1, 2, 3, 1]);
    assert_eq!(press(&mut d, KEY_TAB, MOD_SHIFT), Event::Focus(Some(1), 3));
    assert_eq!(press(&mut d, KEY_TAB, MOD_SHIFT), Event::Focus(Some(3), 2));
    // Space answers the focused button too (a button's keys, ui.md §2).
    assert_eq!(press(&mut d, KEY_SPACE, 0), Event::Activate(2));
    assert_eq!(d.answer(), Some(Answer::No));

    // Esc answers Cancel whatever has the focus, the default Yes included.
    for k in 0..3 {
        let (mut d, _) = confirm(false, Answer::Yes);
        for _ in 0..k {
            press(&mut d, KEY_TAB, 0);
        }
        assert_eq!(d.focused(), Some(1 + k));
        assert_eq!(press(&mut d, KEY_ESC, 0), Event::Cancel);
        assert_eq!(d.answer(), Some(Answer::Cancel), "focus on {}", 1 + k);
    }
    // Enter on each button answers that button.
    for (k, a) in [Answer::Yes, Answer::No, Answer::Cancel]
        .into_iter()
        .enumerate()
    {
        let (mut d, _) = confirm(false, Answer::Cancel);
        assert_eq!(d.focused(), Some(3));
        for _ in 0..(k + 1) {
            press(&mut d, KEY_TAB, 0);
        }
        assert_eq!(press(&mut d, KEY_ENTER, 0), Event::Activate(a.element()));
        assert_eq!(d.answer(), Some(a));
    }

    // Refusals: a blank prompt or label builds nothing; a confirm takes an empty dialog only and
    // no other element afterwards.
    for (p, y, n, c) in [
        (" ", YES, NO, CANCEL),
        (PROMPT, "", NO, CANCEL),
        (PROMPT, YES, " ", CANCEL),
        (PROMPT, YES, NO, ""),
    ] {
        let mut d = Dialog::new("Trash", false);
        assert_eq!(d.confirm(p, y, n, c, Answer::No), Err(UiError::NoLabel));
        assert!(d.is_empty());
        assert_eq!(d.answer(), None);
    }
    let mut d = Dialog::new("Trash", false);
    d.add(Role::Label, "Already here.").unwrap();
    assert_eq!(
        d.confirm(PROMPT, YES, NO, CANCEL, Answer::No),
        Err(UiError::Confirm)
    );
    assert_eq!(d.len(), 1);
    let (mut d, _) = confirm(false, Answer::No);
    assert_eq!(d.add(Role::Button, "One more"), Err(UiError::Confirm));
    assert_eq!(d.add_list("Files", &["a.txt"]), Err(UiError::Confirm));
    assert_eq!(d.len(), 4);
    // A menu set before confirm is dropped: a confirm has no context menu, then or later.
    let mut d = Dialog::new("Trash", false);
    assert!(d.set_menu(&MENU));
    assert_eq!(d.menu_len(), 1);
    d.confirm(PROMPT, YES, NO, CANCEL, Answer::No).unwrap();
    assert_eq!(d.menu_len(), 0);
    assert!(!d.set_menu(&MENU));
    assert_eq!(press(&mut d, KEY_F10, MOD_SHIFT), Event::None);
    assert_eq!(d.take_menu_event(), None);
    // A plain dialog has no answer, and its Esc stays a plain cancel.
    let mut p = Dialog::new("Plain", false);
    p.add(Role::Button, "Close").unwrap();
    p.start();
    assert_eq!(press(&mut p, KEY_ESC, 0), Event::Cancel);
    assert_eq!(p.answer(), None);
}

#[test]
fn confirm_narrator_lines() {
    let (mut d, ev) = confirm(false, Answer::No);
    let Event::Focus(_, to) = ev else {
        panic!("{ev:?}");
    };
    assert_eq!(
        line("confirm ", |t| assert!(d.describe_confirm(t))),
        "confirm role=dialog label=\"Move notes.txt to the trash?\""
    );
    assert_eq!(
        line("focus ", |t| d.describe(to, t)),
        "focus role=button label=\"Keep the file\" state=focused"
    );
    if let Event::Focus(_, to) = press(&mut d, KEY_TAB, 0) {
        assert_eq!(
            line("focus ", |t| d.describe(to, t)),
            "focus role=button label=\"Decide later\" state=focused"
        );
    } else {
        panic!("Tab did not move the focus");
    }
    assert_eq!(press(&mut d, KEY_ESC, 0), Event::Cancel);
    let a = d.answer().unwrap();
    assert_eq!(
        line("answer ", |t| t.put(a.name().as_bytes())),
        "answer cancel"
    );
    assert_eq!(
        [Answer::Yes.name(), Answer::No.name(), Answer::Cancel.name()],
        ["yes", "no", "cancel"]
    );

    // Arabic: the sentences are the application's, the tokens stay English.
    let mut d = Dialog::new("السلة", true);
    let ev = d
        .confirm(PROMPT_AR, YES_AR, NO_AR, CANCEL_AR, Answer::Yes)
        .unwrap();
    assert_eq!(ev, Event::Focus(None, 1));
    assert_eq!(
        line("confirm ", |t| assert!(d.describe_confirm(t))),
        format!("confirm role=dialog label=\"{PROMPT_AR}\"")
    );
    assert_eq!(
        line("focus ", |t| d.describe(1, t)),
        format!("focus role=button label=\"{YES_AR}\" state=focused")
    );
    assert_eq!(press(&mut d, KEY_ENTER, 0), Event::Activate(1));
    let a = d.answer().unwrap();
    assert_eq!(
        line("answer ", |t| t.put(a.name().as_bytes())),
        "answer yes"
    );

    // A plain dialog is not a confirm: no line, nothing written.
    let mut p = Dialog::new("Plain", false);
    p.add(Role::Button, "Close").unwrap();
    let mut t = Text::new();
    assert!(!p.describe_confirm(&mut t));
    assert_eq!(t.as_bytes(), b"");
}

#[test]
fn confirm_rtl_order() {
    let (l, _) = confirm(false, Answer::No);
    let (r, _) = confirm(true, Answer::No);
    let (lr, (w, h)) = rects(&l);
    let (rr, size) = rects(&r);
    assert_eq!(size, (w, h));
    let [y, n, c] = [Answer::Yes, Answer::No, Answer::Cancel].map(|a| a.element());
    // A column: the prompt's row, then each button a full row of its own, yes, no, cancel
    // from the top, inside the surface; every row is its own mirror, so RTL equals LTR.
    for rs in [&lr, &rr] {
        assert!(rs[0].y + rs[0].h <= rs[y].y);
        assert!(rs[y].y + rs[y].h <= rs[n].y && rs[n].y + rs[n].h <= rs[c].y);
        for k in [0, y, n, c] {
            assert_eq!((rs[k].x, rs[k].w), (rs[0].x, rs[0].w), "element {k}");
            assert!(rs[k].x >= 0 && rs[k].x + rs[k].w <= w && rs[k].y + rs[k].h <= h);
            assert_eq!(
                rs[k].x,
                w - (rs[k].x + rs[k].w),
                "element {k} is its own mirror"
            );
        }
    }
    assert_eq!(lr[..4], rr[..4]);
    // The logical order (Tab) is the same in RTL.
    let (mut r, _) = confirm(true, Answer::Yes);
    assert_eq!(press(&mut r, KEY_TAB, 0), Event::Focus(Some(y), n));
    assert_eq!(press(&mut r, KEY_TAB, 0), Event::Focus(Some(n), c));
    // A live switch of direction keeps the column.
    let (mut l, _) = confirm(false, Answer::No);
    l.set_rtl(true);
    assert_eq!(rects(&l).0[..4], rr[..4]);
}

/// Every word of a confirm is readable: the prompt fits its row (`fits`) and every button
/// label is narrower than its button, measured by the layout `paint` draws with, in both
/// languages and at 1x and 2x. `text_width` is that measure: it agrees with `fits`, gives
/// the exact widths at 1x and measures as many characters as `paint` draws (`TEXT_PAINT`).
#[test]
fn confirm_labels_fit() {
    let fonts = Fonts {
        latin: Font::parse(LATIN_TTF).unwrap(),
        arabic: Font::parse(ARABIC_TTF).unwrap(),
    };
    let mut p = Box::new(Painter::new());
    // A longer question does not fit one row (more than 241 px at 1x): the application checks
    // `fits` and words its question shorter rather than show part of it; `text_width` agrees.
    let (d, _) = confirm(false, Answer::No);
    let (r, _) = rects(&d);
    let bound = r[0].w - d.font_px() as i32 / 2;
    assert_eq!(bound, 241);
    let longer = "Do you want to move notes.txt to the trash?";
    assert!(!p.fits(&d, &fonts, longer));
    assert!(p.text_width(&d, &fonts, longer) > bound);
    // (rtl, texts, exact 1x widths of the prompt and of the widest label)
    let sets = [
        (false, [PROMPT, YES, NO, CANCEL], (184, 128)),
        (true, [PROMPT_AR, YES_AR, NO_AR, CANCEL_AR], (218, 79)),
    ];
    for (rtl, [q, y, n, c], (q1, l1)) in sets {
        let mut at1 = (0, 0);
        for scale in [b"1".as_slice(), b"2"] {
            let mut d = Dialog::new("Trash", rtl);
            d.theme = Theme::from_config(scale, b"normal");
            d.confirm(q, y, n, c, Answer::No).unwrap();
            let (r, _) = rects(&d);
            let bound = r[0].w - d.font_px() as i32 / 2;
            let qw = p.text_width(&d, &fonts, q);
            eprintln!("rtl={rtl} scale={scale:?} prompt {qw} of {bound}");
            assert!(p.fits(&d, &fonts, q), "prompt {q:?} is {qw} px");
            assert!(qw <= bound, "fits and text_width disagree: {qw} of {bound}");
            let mut widest = 0;
            for (k, label) in [(1, y), (2, n), (3, c)] {
                let tw = p.text_width(&d, &fonts, label);
                eprintln!(
                    "rtl={rtl} scale={scale:?} {label:?} {tw} of button {}",
                    r[k].w
                );
                assert!(tw > 0, "{label:?} measured {tw} px");
                assert!(
                    tw < r[k].w,
                    "{label:?} is {tw} px in a {} px button",
                    r[k].w
                );
                widest = widest.max(tw);
            }
            if scale == b"1" {
                assert_eq!((qw, widest), (q1, l1), "rtl={rtl} at 1x");
                at1 = (qw, widest);
            } else {
                // 2x draws at twice the font size: wider than 1x, within rounding of double.
                assert!(qw > at1.0 && (qw - 2 * at1.0).abs() <= 2, "{qw} at 2x");
                assert!(widest > at1.1 && (widest - 2 * at1.1).abs() <= 2);
            }
        }
    }
    // text_width measures what paint draws: up to TEXT_PAINT characters, the rest dropped.
    let d = Dialog::new("Trash", false);
    let many: String = "n".repeat(TEXT_PAINT + 6);
    let w = |p: &mut Painter, k: usize| p.text_width(&d, &fonts, &many[..k]);
    let (w49, w64, w70) = (
        w(&mut p, 49),
        w(&mut p, TEXT_PAINT),
        w(&mut p, TEXT_PAINT + 6),
    );
    assert_eq!(TEXT_PAINT, 64);
    assert!(w64 > w49, "{w64} for {TEXT_PAINT} characters, {w49} for 49");
    assert_eq!(w70, w64, "beyond TEXT_PAINT nothing is drawn nor measured");
}

#[test]
fn confirm_pointer() {
    // A left press and release on a button answers it (the v1.6 pointer path).
    let (mut d, _) = confirm(false, Answer::No);
    let (r, _) = rects(&d);
    let (x, y) = mid(r[Answer::Yes.element()]);
    assert_eq!(d.pointer(x, y, BUTTON_LEFT, T0), Event::Focus(Some(2), 1));
    assert_eq!(d.answer(), None);
    assert_eq!(d.pointer(x, y, 0, T0), Event::Activate(1));
    assert_eq!(d.answer(), Some(Answer::Yes));
    // Answered: a later click on another button changes nothing.
    let (cx, cy) = mid(r[Answer::Cancel.element()]);
    assert_eq!(d.pointer(cx, cy, BUTTON_LEFT, T0 + 10), Event::None);
    assert_eq!(d.pointer(cx, cy, 0, T0 + 10), Event::None);
    assert_eq!(d.answer(), Some(Answer::Yes));

    // A press on a button released elsewhere answers nothing and gives the focus back to
    // where it was before the press (else the next Enter would answer the button only
    // pressed); a click on the prompt or a right click answers nothing and leaves the focus.
    let (mut d, _) = confirm(false, Answer::No);
    let (yx, yy) = mid(r[1]);
    let (px, py) = mid(r[0]);
    assert_eq!(d.pointer(yx, yy, BUTTON_LEFT, T0), Event::Focus(Some(2), 1));
    assert_eq!(d.pointer(px, py, 0, T0), Event::Focus(Some(1), 2));
    assert_eq!((d.focused(), d.answer()), (Some(2), None));
    assert_eq!(d.pointer(px, py, BUTTON_LEFT, T0), Event::None);
    assert_eq!(d.pointer(px, py, 0, T0), Event::None);
    let (nx, ny) = mid(r[2]);
    assert_eq!(d.pointer(nx, ny, BUTTON_RIGHT, T0), Event::None);
    assert_eq!(d.pointer(nx, ny, 0, T0), Event::None);
    assert_eq!(d.take_menu_event(), None);
    assert_eq!((d.focused(), d.answer()), (Some(2), None));
    // A press on the default itself released elsewhere keeps the focus there.
    d.pointer(px, py + r[2].y - r[0].y, BUTTON_LEFT, T0);
    assert_eq!(d.pointer(px, py, 0, T0), Event::None);
    assert_eq!(d.focused(), Some(2));
    // Enter after all this answers the default, not the button once pressed.
    assert_eq!(press(&mut d, KEY_ENTER, 0), Event::Activate(2));
    assert_eq!(d.answer(), Some(Answer::No));

    // Tab to Cancel, press Cancel, release elsewhere: the press did not move the focus, so a
    // deliberate Tab survives a slipped click (the focus stays on Cancel, not the default).
    let (mut d, _) = confirm(false, Answer::No);
    let (cx, cy) = mid(r[3]);
    assert_eq!(press(&mut d, KEY_TAB, 0), Event::Focus(Some(2), 3));
    assert_eq!(d.pointer(cx, cy, BUTTON_LEFT, T0), Event::None);
    assert_eq!(d.pointer(px, py, 0, T0), Event::None);
    assert_eq!((d.focused(), d.answer()), (Some(3), None));
    // From Cancel, press No (the default), release elsewhere: the focus goes back to Cancel,
    // what it was before the press, not to the default.
    assert_eq!(d.pointer(nx, ny, BUTTON_LEFT, T0), Event::Focus(Some(3), 2));
    assert_eq!(d.pointer(px, py, 0, T0), Event::Focus(Some(2), 3));
    assert_eq!((d.focused(), d.answer()), (Some(3), None));
    // A press that moved the focus, then a Tab while held: the Tab stands at the release.
    assert_eq!(d.pointer(yx, yy, BUTTON_LEFT, T0), Event::Focus(Some(3), 1));
    assert_eq!(press(&mut d, KEY_TAB, 0), Event::Focus(Some(1), 2));
    assert_eq!(d.pointer(px, py, 0, T0), Event::None);
    assert_eq!((d.focused(), d.answer()), (Some(2), None));
    assert_eq!(press(&mut d, KEY_ENTER, 0), Event::Activate(2));
    assert_eq!(d.answer(), Some(Answer::No));
    // While a left press is held on a button, Enter answers that pressed (focused) button,
    // as for any focused button; the release then changes nothing.
    let (mut d, _) = confirm(false, Answer::No);
    assert_eq!(d.pointer(yx, yy, BUTTON_LEFT, T0), Event::Focus(Some(2), 1));
    assert_eq!(press(&mut d, KEY_ENTER, 0), Event::Activate(1));
    assert_eq!(d.answer(), Some(Answer::Yes));
    assert_eq!(d.pointer(yx, yy, 0, T0), Event::None);
    assert_eq!(d.answer(), Some(Answer::Yes));

    let (mut d, _) = confirm(false, Answer::No);
    // Then a left click on Cancel answers Cancel.
    d.pointer(cx, cy, BUTTON_LEFT, T0);
    assert_eq!(d.pointer(cx, cy, 0, T0), Event::Activate(3));
    assert_eq!(d.answer(), Some(Answer::Cancel));

    // RTL: the lowest button is Cancel, as in LTR.
    let (mut d, _) = confirm(true, Answer::No);
    let (rr, _) = rects(&d);
    let low = (1..4).max_by_key(|&k| rr[k].y).unwrap();
    assert_eq!(low, Answer::Cancel.element());
    let (x, y) = mid(rr[low]);
    d.pointer(x, y, BUTTON_LEFT, T0);
    assert_eq!(d.pointer(x, y, 0, T0), Event::Activate(3));
    assert_eq!(d.answer(), Some(Answer::Cancel));
}
