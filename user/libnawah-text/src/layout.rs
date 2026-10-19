//! One line of text to positioned glyphs (WP-35, text.md): UAX #9 levels, runs of one level
//! and one font (Arabic script → the Arabic font, everything else → the Latin font, with a
//! fallback to the other font for a missing glyph), Arabic shaping per run, paired brackets
//! mirrored in right-to-left runs (BidiBrackets.txt; other mirrored characters are not), the
//! runs in visual order (L2) and advances from `hmtx`. Positions are 26.6 fixed point.

use crate::bidi::{self, Base, Bidi, REMOVED};
use crate::font::{Font, Outline};
use crate::raster::{Bitmap, Rasterizer};
use crate::shape::{self, JT_T};

pub const MAX_CHARS: usize = 512;
pub const LATIN: u8 = 0;
pub const ARABIC: u8 = 1;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Glyph {
    /// LATIN or ARABIC.
    pub font: u8,
    pub gid: u16,
    /// Pen position of the glyph's origin, 26.6 pixels from the line's start.
    pub x: i32,
    /// Advance, 26.6 pixels.
    pub advance: i32,
    /// The first character (logical index) the glyph came from.
    pub cluster: u16,
}

pub struct Fonts<'a> {
    pub latin: Font<'a>,
    pub arabic: Font<'a>,
}

impl<'a> Fonts<'a> {
    pub fn get(&self, which: u8) -> &Font<'a> {
        if which == ARABIC {
            &self.arabic
        } else {
            &self.latin
        }
    }
}

fn is_arabic_script(cp: u32) -> bool {
    matches!(cp, 0x0600..=0x06FF | 0x0750..=0x077F | 0x0870..=0x08FF | 0xFB50..=0xFDFF | 0xFE70..=0xFEFF)
}

/// The working state of a line, owned by the caller.
pub struct Layout {
    bidi: Bidi,
    levels: [u8; MAX_CHARS],
    order: [u16; MAX_CHARS],
    font_of: [u8; MAX_CHARS],
    text: [u32; MAX_CHARS],
    run_glyphs: [u16; MAX_CHARS],
    run_clusters: [u16; MAX_CHARS],
    pub raster: Rasterizer,
    pub outline: Outline,
    pub bitmap: Bitmap,
}

impl Default for Layout {
    fn default() -> Self {
        Self::new()
    }
}

/// Where glyph coverage goes: `blend(x, y, coverage 0..=16)` in canvas pixels.
pub trait Canvas {
    fn blend(&mut self, x: i32, y: i32, coverage: u8);
}

/// A canvas of `0xRRGGBB` pixels: coverage c mixes `fg` into the pixel per channel as
/// (old·(16 − c) + fg·c + 8) / 16 — the rule host and guest both apply.
pub struct RgbCanvas<'b> {
    pub buf: &'b mut [u32],
    pub w: usize,
    pub h: usize,
    pub fg: u32,
}

impl Canvas for RgbCanvas<'_> {
    fn blend(&mut self, x: i32, y: i32, coverage: u8) {
        if x < 0 || y < 0 || x as usize >= self.w || y as usize >= self.h {
            return;
        }
        let c = u32::from(coverage.min(16));
        let i = y as usize * self.w + x as usize;
        let old = self.buf[i];
        let mut px = 0u32;
        for shift in [16u32, 8, 0] {
            let (o, f) = ((old >> shift) & 0xFF, (self.fg >> shift) & 0xFF);
            px |= ((o * (16 - c) + f * c + 8) / 16) << shift;
        }
        self.buf[i] = px;
    }
}

/// FNV-1a 64 over the R, G, B bytes of `buf` (`w × h`, row by row): the window hash of
/// display.md §ب and tools/screen.py.
pub fn rgb_hash(buf: &[u32], w: usize, h: usize) -> u64 {
    let mut v: u64 = 0xcbf2_9ce4_8422_2325;
    for &p in &buf[..w * h] {
        for shift in [16u32, 8, 0] {
            v ^= u64::from((p >> shift) & 0xFF);
            v = v.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    v
}

impl Layout {
    pub const fn new() -> Layout {
        Layout {
            bidi: Bidi::new(),
            levels: [0; MAX_CHARS],
            order: [0; MAX_CHARS],
            font_of: [0; MAX_CHARS],
            text: [0; MAX_CHARS],
            run_glyphs: [0; MAX_CHARS],
            run_clusters: [0; MAX_CHARS],
            raster: Rasterizer::new(),
            outline: Outline::new(),
            bitmap: Bitmap::new(),
        }
    }

    /// Lays out `text` at `px` pixels per em into `out` (visual order, left to right); the
    /// glyph count and the line's width (26.6) come back.
    pub fn line(
        &mut self,
        fonts: &Fonts,
        text: &[u32],
        base: Base,
        px: u32,
        out: &mut [crate::layout::Glyph],
    ) -> (usize, i32) {
        let n = text.len().min(MAX_CHARS);
        self.text[..n].copy_from_slice(&text[..n]);
        self.bidi
            .resolve(&self.text[..n], base, &mut self.levels[..n]);
        // Fonts: Arabic script, marks with their base, a missing glyph from the other font.
        for i in 0..n {
            let cp = self.text[i];
            let mut f = if is_arabic_script(cp) { ARABIC } else { LATIN };
            if shape::joining_type(cp) == JT_T && i > 0 {
                f = self.font_of[i - 1];
            }
            // ZWNJ and ZWJ stay in the run of the character before them, whatever font has a
            // glyph for them: they draw nothing (X9 removes them) and only steer the joining
            // inside the run. In the Latin font they split an Arabic word in two runs and a
            // ZWJ pair was shaped isolated (review M6).
            if matches!(cp, 0x200C | 0x200D) && i > 0 {
                self.font_of[i] = self.font_of[i - 1];
                continue;
            }
            if fonts.get(f).glyph_id(cp) == 0 {
                let other = if f == ARABIC { LATIN } else { ARABIC };
                if fonts.get(other).glyph_id(cp) != 0 {
                    f = other;
                }
            }
            self.font_of[i] = f;
        }
        // Removed characters (X9) take the level of the character before them so they do not
        // split a run (a ZWJ inside an Arabic word still joins).
        let mut run_level = [0u8; MAX_CHARS];
        let mut prev = self.levels.first().copied().unwrap_or(0);
        for (rl, &lv) in run_level.iter_mut().zip(&self.levels[..n]) {
            if lv != REMOVED {
                prev = lv;
            }
            *rl = prev;
        }
        let count = bidi::reorder(&self.levels[..n], &mut self.order[..n]);
        // Walk the visual order; each run (same level and font, contiguous in logical order)
        // is emitted once, at its first visual character.
        let mut emitted = [false; MAX_CHARS];
        let mut g = 0usize;
        let mut pen = 0i32;
        let upem_scale = |font: &Font, units: u16| -> i32 {
            ((i64::from(units) * i64::from(px) * 64) / i64::from(font.units_per_em.max(1))) as i32
        };
        for k in 0..count {
            let c = self.order[k] as usize;
            if emitted[c] {
                continue;
            }
            // The run containing c.
            let (lv, f) = (run_level[c], self.font_of[c]);
            let mut s = c;
            while s > 0 && run_level[s - 1] == lv && self.font_of[s - 1] == f {
                s -= 1;
            }
            let mut e = c + 1;
            while e < n && run_level[e] == lv && self.font_of[e] == f {
                e += 1;
            }
            for item in &mut emitted[s..e] {
                *item = true;
            }
            let rtl = lv & 1 == 1;
            let font = fonts.get(f);
            // Mirrored brackets in right-to-left runs.
            let mut chars = [0u32; MAX_CHARS];
            for (i, ch) in chars[..e - s].iter_mut().enumerate() {
                let cp = self.text[s + i];
                *ch = match (rtl, bidi::bracket_of(cp)) {
                    (true, Some((pair, _))) => pair,
                    _ => cp,
                };
            }
            let len = if f == ARABIC {
                shape::shape(
                    font,
                    &chars[..e - s],
                    &mut self.run_glyphs,
                    &mut self.run_clusters,
                )
            } else {
                for (i, &ch) in chars[..e - s].iter().enumerate() {
                    self.run_glyphs[i] = font.glyph_id(ch);
                    self.run_clusters[i] = i as u16;
                }
                e - s
            };
            for j in 0..len {
                let jj = if rtl { len - 1 - j } else { j };
                let cluster = s + self.run_clusters[jj] as usize;
                if self.levels[cluster] == REMOVED || g >= out.len() {
                    continue;
                }
                let gid = self.run_glyphs[jj];
                let adv = upem_scale(font, font.advance(gid));
                out[g] = Glyph {
                    font: f,
                    gid,
                    x: pen,
                    advance: adv,
                    cluster: cluster as u16,
                };
                pen += adv;
                g += 1;
            }
        }
        (g, pen)
    }

    /// One line on a `w × h` box of `0xRRGGBB` pixels: filled with `bg`, the text in `fg`
    /// with its baseline at 3/4 of the height, 8 pixels from the left edge for a
    /// left-to-right paragraph and from the right edge for a right-to-left one.
    #[allow(clippy::too_many_arguments)]
    pub fn render_line(
        &mut self,
        fonts: &Fonts,
        text: &[u32],
        base: Base,
        px: u32,
        buf: &mut [u32],
        w: usize,
        h: usize,
        fg: u32,
        bg: u32,
        glyphs: &mut [Glyph],
    ) -> usize {
        buf[..w * h].fill(bg);
        let (n, width) = self.line(fonts, text, base, px, glyphs);
        let x0 = if self.bidi.para_level() & 1 == 1 {
            w as i32 - 8 - (width + 32) / 64
        } else {
            8
        };
        let mut canvas = RgbCanvas { buf, w, h, fg };
        self.draw(fonts, &glyphs[..n], px, x0, (h * 3 / 4) as i32, &mut canvas);
        n
    }

    /// Rasterises `glyphs` with their origins at (`x0`, `baseline`) canvas pixels.
    pub fn draw(
        &mut self,
        fonts: &Fonts,
        glyphs: &[Glyph],
        px: u32,
        x0: i32,
        baseline: i32,
        canvas: &mut dyn Canvas,
    ) {
        for gl in glyphs {
            let font = fonts.get(gl.font);
            self.outline.clear();
            if !font.outline(gl.gid, &mut self.outline) {
                continue;
            }
            if !self
                .raster
                .render(&self.outline, font.units_per_em, px, &mut self.bitmap)
            {
                continue;
            }
            let ox = x0 + (gl.x + 32) / 64 + self.bitmap.left;
            let oy = baseline - self.bitmap.top;
            for y in 0..self.bitmap.h {
                for x in 0..self.bitmap.w {
                    let c = self.bitmap.at(x, y);
                    if c != 0 {
                        canvas.blend(ox + x as i32, oy + y as i32, c);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Mixed-direction lines (TST-M5-SHAPING): the visual order of the glyphs' clusters,
    //! worked out by hand from UAX #9 (rules quoted per case).
    use super::*;

    const LATIN_TTF: &[u8] = include_bytes!("../../../platform/assets/fonts/NotoSans-Regular.ttf");
    const ARABIC_TTF: &[u8] =
        include_bytes!("../../../platform/assets/fonts/NotoSansArabic-Regular.ttf");

    fn run(text: &str, base: Base) -> (std::vec::Vec<u16>, std::vec::Vec<Glyph>, Fonts<'static>) {
        let fonts = Fonts {
            latin: Font::parse(LATIN_TTF).unwrap(),
            arabic: Font::parse(ARABIC_TTF).unwrap(),
        };
        let cps: std::vec::Vec<u32> = text.chars().map(|c| c as u32).collect();
        let mut layout = std::boxed::Box::new(Layout::new());
        let mut out = std::vec![Glyph::default(); cps.len()];
        let (n, _) = layout.line(&fonts, &cps, base, 16, &mut out);
        out.truncate(n);
        (out.iter().map(|g| g.cluster).collect(), out, fonts)
    }

    #[test]
    fn latin_and_number_in_rtl_paragraph() {
        // W7 makes 123 L after "abc"; the space between them is L (N1), the space before the
        // Arabic word takes the embedding direction (N2, R): abc␠123 at level 2, the rest 1.
        let (clusters, _, _) = run("abc 123 أبج", Base::Rtl);
        assert_eq!(clusters, [10, 9, 8, 7, 0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn arabic_in_ltr_paragraph() {
        // "!" between R and eos (L) takes the embedding direction (N2, L).
        let (clusters, _, _) = run("Hello مرحبا!", Base::Ltr);
        assert_eq!(clusters, [0, 1, 2, 3, 4, 5, 10, 9, 8, 7, 6, 11]);
    }

    #[test]
    fn digits_keep_their_order_in_arabic() {
        // W2: EN after AL is AN; I1/I2 put AN at level 2; the spaces between R and AN are R
        // (N1): the number reads left to right inside the right-to-left line.
        let (clusters, _, _) = run("عدد 25 كتاب", Base::Rtl);
        assert_eq!(clusters, [10, 9, 8, 7, 6, 4, 5, 3, 2, 1, 0]);
    }

    #[test]
    fn brackets_are_mirrored_in_rtl() {
        // N0: the pair encloses a strong R matching the embedding direction, so both are R;
        // in the reversed run the closing bracket comes first and is drawn as "(".
        let (clusters, glyphs, fonts) = run("(أ)", Base::Rtl);
        assert_eq!(clusters, [2, 1, 0]);
        assert_eq!(glyphs[0].gid, fonts.latin.glyph_id('(' as u32));
        assert_eq!(glyphs[2].gid, fonts.latin.glyph_id(')' as u32));
    }

    #[test]
    fn lam_alef_is_one_glyph_and_words_join() {
        let (clusters, glyphs, fonts) = run("لا", Base::Auto);
        assert_eq!(clusters.len(), 1);
        assert_ne!(glyphs[0].gid, fonts.arabic.glyph_id(0x644));
        // A medial beh in a word is not the isolated form.
        let (_, glyphs, fonts) = run("ببب", Base::Auto);
        let isolated = fonts.arabic.glyph_id(0x628);
        assert!(glyphs.iter().all(|g| g.gid != isolated));
        assert_eq!(glyphs.len(), 3);
    }

    #[test]
    fn advances_accumulate_left_to_right() {
        let (_, glyphs, _) = run("ab", Base::Ltr);
        assert_eq!(glyphs[0].x, 0);
        assert_eq!(glyphs[1].x, glyphs[0].advance);
    }
}
