//! The host side of the text tests (tests/test_text.py): reads commands from stdin, one per
//! line, and answers each with one line, so an independent implementation (fontTools,
//! HarfBuzz, a reference rasteriser) can be compared with this library on the same fonts.
//!
//!   cmap <font> <cp-hex>...            → gid...
//!   metrics <font> <gid>...            → adv,lsb...
//!   outline <font> <gid>               → ok|bad ; contour ends ; x,y,on ...
//!   raster <font> <gid> <px>           → w h left top <coverage 0..16, comma separated>
//!   hash <font> <gid> <px>             → FNV-1a 64 of the bitmap (Bitmap::hash)
//!   forms <cp-hex>...                  → isol|init|medi|fina|none ...
//!   shape <cp-hex>...                  → gid... (Arabic font, logical order)
//!   layout <ltr|rtl|auto> <px> <cp-hex>... → font:gid:x ... (visual order)
//!   render <ltr|rtl|auto> <px> <w> <h> <fg> <bg> <cp-hex>... → FNV-1a of the rendered box
//!
//! <font> is `latin` or `arabic`; the font files are the arguments: textdump LATIN ARABIC.

use nawah_text::bidi::Base;
use nawah_text::font::{Font, Outline};
use nawah_text::layout::{Fonts, Glyph, Layout};
use nawah_text::raster::{Bitmap, Rasterizer};
use nawah_text::shape::{self, Form};
use std::io::{BufRead, Write};

fn hex_list<'a>(it: impl Iterator<Item = &'a str>) -> Vec<u32> {
    it.map(|h| u32::from_str_radix(h, 16).expect("hex"))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let latin_bytes = std::fs::read(&args[1]).expect("latin font");
    let arabic_bytes = std::fs::read(&args[2]).expect("arabic font");
    let fonts = Fonts {
        latin: Font::parse(&latin_bytes).expect("parse latin"),
        arabic: Font::parse(&arabic_bytes).expect("parse arabic"),
    };
    let mut outline = Box::new(Outline::new());
    let mut raster = Box::new(Rasterizer::new());
    let mut bitmap = Box::new(Bitmap::new());
    let mut layout = Box::new(Layout::new());
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let mut f = line.split_whitespace();
        let cmd = f.next().unwrap_or("");
        let pick = |name: &str| {
            if name == "arabic" {
                &fonts.arabic
            } else {
                &fonts.latin
            }
        };
        match cmd {
            "cmap" => {
                let font = pick(f.next().unwrap());
                let r: Vec<String> = hex_list(f)
                    .iter()
                    .map(|&cp| font.glyph_id(cp).to_string())
                    .collect();
                writeln!(out, "{}", r.join(" ")).unwrap();
            }
            "metrics" => {
                let font = pick(f.next().unwrap());
                let r: Vec<String> = f
                    .map(|g| g.parse::<u16>().unwrap())
                    .map(|g| format!("{},{}", font.advance(g), font.left_side_bearing(g)))
                    .collect();
                writeln!(out, "{}", r.join(" ")).unwrap();
            }
            "outline" => {
                let font = pick(f.next().unwrap());
                let gid: u16 = f.next().unwrap().parse().unwrap();
                outline.clear();
                let ok = font.outline(gid, &mut outline);
                let ends: Vec<String> = outline.contour_end[..outline.n_contours]
                    .iter()
                    .map(|e| e.to_string())
                    .collect();
                let pts: Vec<String> = outline.points[..outline.n_points]
                    .iter()
                    .map(|p| format!("{},{},{}", p.x, p.y, u8::from(p.on_curve)))
                    .collect();
                writeln!(
                    out,
                    "{} ; {} ; {}",
                    if ok { "ok" } else { "bad" },
                    ends.join(" "),
                    pts.join(" ")
                )
                .unwrap();
            }
            "raster" | "hash" => {
                let font = pick(f.next().unwrap());
                let gid: u16 = f.next().unwrap().parse().unwrap();
                let px: u32 = f.next().unwrap().parse().unwrap();
                outline.clear();
                let ok = font.outline(gid, &mut outline)
                    && raster.render(&outline, font.units_per_em, px, &mut bitmap);
                if !ok {
                    writeln!(out, "bad").unwrap();
                } else if cmd == "hash" {
                    writeln!(out, "{:016x}", bitmap.hash()).unwrap();
                } else {
                    let raw: Vec<String> = bitmap.coverage[..bitmap.w * bitmap.h]
                        .iter()
                        .map(|c| c.to_string())
                        .collect();
                    writeln!(
                        out,
                        "{} {} {} {} {}",
                        bitmap.w,
                        bitmap.h,
                        bitmap.left,
                        bitmap.top,
                        raw.join(",")
                    )
                    .unwrap();
                }
            }
            "forms" => {
                let text = hex_list(f);
                let mut forms = vec![Form::None; text.len()];
                shape::forms(&text, &mut forms);
                let r: Vec<&str> = forms
                    .iter()
                    .map(|f| match f {
                        Form::Isol => "isol",
                        Form::Init => "init",
                        Form::Medi => "medi",
                        Form::Fina => "fina",
                        Form::None => "none",
                    })
                    .collect();
                writeln!(out, "{}", r.join(" ")).unwrap();
            }
            "shape" => {
                let text = hex_list(f);
                let mut glyphs = vec![0u16; text.len()];
                let mut clusters = vec![0u16; text.len()];
                let n = shape::shape(&fonts.arabic, &text, &mut glyphs, &mut clusters);
                let r: Vec<String> = glyphs[..n].iter().map(|g| g.to_string()).collect();
                writeln!(out, "{}", r.join(" ")).unwrap();
            }
            "layout" => {
                let base = match f.next().unwrap() {
                    "ltr" => Base::Ltr,
                    "rtl" => Base::Rtl,
                    _ => Base::Auto,
                };
                let px: u32 = f.next().unwrap().parse().unwrap();
                let text = hex_list(f);
                let mut glyphs = vec![Glyph::default(); text.len()];
                let (n, w) = layout.line(&fonts, &text, base, px, &mut glyphs);
                let r: Vec<String> = glyphs[..n]
                    .iter()
                    .map(|g| format!("{}:{}:{}:{}", g.font, g.gid, g.x, g.cluster))
                    .collect();
                writeln!(out, "{} | {}", w, r.join(" ")).unwrap();
            }
            "render" | "renderppm" => {
                // render <base> <px> <w> <h> <fg-hex> <bg-hex> <cp-hex>... → FNV-1a of the box;
                // renderppm <path> <same>... also writes the box as a binary PPM.
                let ppm = if cmd == "renderppm" {
                    Some(f.next().unwrap().to_string())
                } else {
                    None
                };
                let base = match f.next().unwrap() {
                    "ltr" => Base::Ltr,
                    "rtl" => Base::Rtl,
                    _ => Base::Auto,
                };
                let px: u32 = f.next().unwrap().parse().unwrap();
                let w: usize = f.next().unwrap().parse().unwrap();
                let h: usize = f.next().unwrap().parse().unwrap();
                let fg = u32::from_str_radix(f.next().unwrap(), 16).unwrap();
                let bg = u32::from_str_radix(f.next().unwrap(), 16).unwrap();
                let text = hex_list(f);
                let mut buf = vec![0u32; w * h];
                let mut glyphs = vec![Glyph::default(); text.len()];
                let n = layout.render_line(
                    &fonts,
                    &text,
                    base,
                    px,
                    &mut buf,
                    w,
                    h,
                    fg,
                    bg,
                    &mut glyphs,
                );
                if let Some(path) = ppm {
                    let mut data = format!("P6\n{} {}\n255\n", w, h).into_bytes();
                    for p in &buf {
                        data.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, *p as u8]);
                    }
                    std::fs::write(path, data).unwrap();
                }
                writeln!(
                    out,
                    "{:016x} glyphs={}",
                    nawah_text::layout::rgb_hash(&buf, w, h),
                    n
                )
                .unwrap();
            }
            "" => {}
            other => writeln!(out, "unknown {}", other).unwrap(),
        }
    }
}
