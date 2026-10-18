//! Renders the sample dialog to PPM files (a development aid): dialog_ppm <out-dir>.
use libui::*;
use nawah_text::font::Font;
use nawah_text::layout::Fonts;

const LANGS: &[&str] = &["English", "العربية", "Français"];

fn main() {
    let out = std::env::args().nth(1).expect("out dir");
    let latin = std::fs::read("platform/assets/fonts/NotoSans-Regular.ttf").unwrap();
    let arabic = std::fs::read("platform/assets/fonts/NotoSansArabic-Regular.ttf").unwrap();
    let fonts = Fonts {
        latin: Font::parse(&latin).unwrap(),
        arabic: Font::parse(&arabic).unwrap(),
    };
    let mut painter = Box::new(Painter::new());
    for (name, rtl, theme) in [
        ("ltr-normal", false, Theme::DEFAULT),
        (
            "ltr-hc2",
            false,
            Theme {
                scale: 8,
                high_contrast: true,
            },
        ),
        ("rtl-normal", true, Theme::DEFAULT),
    ] {
        let mut d = if rtl {
            Dialog::new("تسجيل الدخول", true)
        } else {
            Dialog::new("Sign in", false)
        };
        if rtl {
            d.add(Role::Label, "تسجيل الدخول").unwrap();
            d.add(Role::TextField, "الاسم").unwrap();
            d.add_list("اللغة", LANGS).unwrap();
            d.add(Role::Checkbox, "تذكرني").unwrap();
            d.add(Role::Button, "موافق").unwrap();
            d.add(Role::Button, "إلغاء").unwrap();
        } else {
            d.add(Role::Label, "Sign in").unwrap();
            d.add(Role::TextField, "Name").unwrap();
            d.add_list("Language", LANGS).unwrap();
            d.add(Role::Checkbox, "Remember me").unwrap();
            d.add(Role::Button, "OK").unwrap();
            d.add(Role::Button, "Cancel").unwrap();
        }
        d.theme = theme;
        d.start();
        d.key(KEY_TAB, true, 0, None);
        d.key(KEY_DOWN, true, 0, None);
        d.key(KEY_TAB, true, 0, None);
        d.key(KEY_SPACE, true, 0, None);
        let mut rects = [Rect::default(); MAX_ELEMENTS];
        let (w, h) = d.layout(&mut rects);
        let (w, h) = (w as usize, h as usize);
        let mut buf = vec![0u32; w * h];
        painter.paint(&d, &fonts, &mut buf, w, h);
        let mut data = format!("P6\n{} {}\n255\n", w, h).into_bytes();
        for p in &buf {
            data.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, *p as u8]);
        }
        std::fs::write(format!("{}/{}.ppm", out, name), data).unwrap();
    }
}
