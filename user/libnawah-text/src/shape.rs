//! Arabic shaping (WP-35, ADR-0019 §6): the joining form of every character from the Unicode
//! joining types (DerivedJoiningType.txt, Unicode 17.0; ArabicShaping rules R1–R7: a
//! character joins its neighbour when both sides allow it, transparent characters are
//! skipped), then the font's `GSUB` features applied in the OpenType order for the Arabic
//! script: the form features `isol`, `fina`, `medi`, `init` (single substitutions) and the
//! required ligatures `rlig` (lam-alef); in the form features, chaining contextual lookups of
//! format 3 (coverage based) are applied too, the context skipping marks when the lookup says
//! so (GDEF classes). Contextual formats 1/2 and type 5 are not: the declared limit of
//! text.md. Verified against HarfBuzz (TST-M5-SHAPING).

use crate::font::Font;
use crate::tables::JOINING;

/// Joining types (tables::JOINING): U is 0.
pub const JT_U: u8 = 0;
pub const JT_R: u8 = 1;
pub const JT_L: u8 = 2;
pub const JT_D: u8 = 3;
pub const JT_C: u8 = 4;
pub const JT_T: u8 = 5;

/// The joining form of a character.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    None,
    Isol,
    Init,
    Medi,
    Fina,
}

pub fn joining_type(cp: u32) -> u8 {
    let (mut lo, mut hi) = (0usize, JOINING.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (first, last, t) = JOINING[mid];
        if cp < first {
            hi = mid;
        } else if cp > last {
            lo = mid + 1;
        } else {
            return t;
        }
    }
    JT_U
}

fn joins_before(t: u8) -> bool {
    // Has a connection on the side of the preceding character (right side in RTL).
    matches!(t, JT_R | JT_D | JT_C)
}

fn joins_after(t: u8) -> bool {
    matches!(t, JT_L | JT_D | JT_C)
}

/// The form of every character of `text` (logical order) into `forms`.
pub fn forms(text: &[u32], forms: &mut [Form]) {
    let n = text.len().min(forms.len());
    for i in 0..n {
        let t = joining_type(text[i]);
        if t == JT_U || t == JT_T || t == JT_C {
            forms[i] = Form::None;
            continue;
        }
        let prev = (0..i)
            .rev()
            .map(|k| joining_type(text[k]))
            .find(|&t| t != JT_T);
        let next = (i + 1..n)
            .map(|k| joining_type(text[k]))
            .find(|&t| t != JT_T);
        let to_prev = joins_before(t) && prev.is_some_and(joins_after);
        let to_next = joins_after(t) && next.is_some_and(joins_before);
        forms[i] = match (to_prev, to_next) {
            (true, true) => Form::Medi,
            (true, false) => Form::Fina,
            (false, true) => Form::Init,
            (false, false) => Form::Isol,
        };
    }
}

/// Glyph ids for `text` (one Arabic run, logical order): `glyphs` and, for each glyph, the
/// index of the first character it came from (`clusters`); the glyph count comes back.
pub fn shape(font: &Font, text: &[u32], glyphs: &mut [u16], clusters: &mut [u16]) -> usize {
    const MAX: usize = 512;
    let n = text.len().min(MAX).min(glyphs.len()).min(clusters.len());
    let mut f = [Form::None; MAX];
    forms(&text[..n], &mut f[..n]);
    for i in 0..n {
        glyphs[i] = font.glyph_id(text[i]);
        clusters[i] = i as u16;
    }
    // Form features, each through its own lookups, on the characters of that form.
    let mut lookups = [0u16; 16];
    // The joiners act through their joining types (above); in context matching both are
    // skipped as HarfBuzz does, so a letter's form does not depend on them (review M6).
    let joiners = [font.glyph_id(0x200C), font.glyph_id(0x200D)];
    for (feature, form) in [
        (b"isol", Form::Isol),
        (b"fina", Form::Fina),
        (b"medi", Form::Medi),
        (b"init", Form::Init),
    ] {
        let count = font.feature_lookups(b"arab", feature, &mut lookups);
        for &l in &lookups[..count] {
            let kind = font.lookup_kind(l);
            let skip_marks = font.lookup_flag(l) & 0x0008 != 0;
            for i in 0..n {
                if f[i] != form {
                    continue;
                }
                match kind {
                    1 => {
                        if let Some(g) = font.substitute_single(l, glyphs[i]) {
                            glyphs[i] = g;
                        }
                    }
                    6 => {
                        // Chaining context (format 3): the nested single substitutions at
                        // their sequence positions (marks are not skipped for those).
                        let mut records = [(0u16, 0u16); 8];
                        if let Some(k) = font.chain_context(
                            l,
                            &glyphs[..n],
                            i,
                            skip_marks,
                            joiners,
                            &mut records,
                        ) {
                            for &(seq, nested) in &records[..k] {
                                let at = i + seq as usize;
                                if at < n {
                                    if let Some(g) = font.substitute_single(nested, glyphs[at]) {
                                        glyphs[at] = g;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // Required ligatures (lam-alef).
    let mut len = n;
    let count = font.feature_lookups(b"arab", b"rlig", &mut lookups);
    for &l in &lookups[..count] {
        let mut i = 0;
        while i < len {
            if let Some((lig, consumed)) = font.substitute_ligature(l, &glyphs[i..len]) {
                glyphs[i] = lig;
                // Remove the consumed components after the first.
                let k = consumed - 1;
                for j in i + 1..len - k {
                    glyphs[j] = glyphs[j + k];
                    clusters[j] = clusters[j + k];
                }
                len -= k;
            }
            i += 1;
        }
    }
    len
}
