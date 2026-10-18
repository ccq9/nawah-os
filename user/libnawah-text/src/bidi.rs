//! The Unicode Bidirectional Algorithm, UAX #9 (WP-35, ADR-0019 §6): paragraph level (P2–P3),
//! explicit embeddings, overrides and isolates (X1–X10), weak types (W1–W7), bracket pairs
//! (N0), neutrals (N1–N2), implicit levels (I1–I2), line resets (L1) and reordering (L2).
//! Rules L3 and L4 (combining marks, mirroring) and P1 (paragraph splitting) are the
//! caller's. Verified against the Unicode Character Database's BidiCharacterTest.txt
//! (TST-M5-BIDI); classes come from `tables.rs`, generated from DerivedBidiClass.txt.
//!
//! No allocation: the caller gives the text as code points and the buffers that hold the
//! result; the working state lives in a `Bidi` the caller owns (`MAX` characters).

use crate::tables::{BIDI, BRACKETS};

/// The most characters one call handles.
pub const MAX: usize = 1024;
/// The level of a character removed by rule X9 (explicit formatting characters and BN).
pub const REMOVED: u8 = 0xFF;
const MAX_DEPTH: u8 = 125;

// Class indices as `tables::CLASS_NAMES` orders them.
pub const L: u8 = 0;
pub const R: u8 = 1;
pub const AL: u8 = 2;
pub const EN: u8 = 3;
pub const ES: u8 = 4;
pub const ET: u8 = 5;
pub const AN: u8 = 6;
pub const CS: u8 = 7;
pub const NSM: u8 = 8;
pub const BN: u8 = 9;
pub const B: u8 = 10;
pub const S: u8 = 11;
pub const WS: u8 = 12;
pub const ON: u8 = 13;
pub const LRE: u8 = 14;
pub const LRO: u8 = 15;
pub const RLE: u8 = 16;
pub const RLO: u8 = 17;
pub const PDF: u8 = 18;
pub const LRI: u8 = 19;
pub const RLI: u8 = 20;
pub const FSI: u8 = 21;
pub const PDI: u8 = 22;

/// The paragraph direction the caller asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Base {
    Ltr,
    Rtl,
    /// Rules P2–P3: the first strong character decides, left-to-right when there is none.
    Auto,
}

/// The bidi class of a code point (DerivedBidiClass.txt, defaults included).
pub fn class_of(cp: u32) -> u8 {
    let mut lo = 0usize;
    let mut hi = BIDI.len();
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if BIDI[mid].0 <= cp {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    BIDI[lo].1
}

fn is_isolate_initiator(c: u8) -> bool {
    matches!(c, LRI | RLI | FSI)
}

fn is_removed_class(c: u8) -> bool {
    matches!(c, LRE | LRO | RLE | RLO | PDF | BN)
}

fn is_ni(c: u8) -> bool {
    matches!(c, B | S | WS | ON | LRI | RLI | FSI | PDI)
}

/// Directional override status: neutral, or a class to force.
const OVERRIDE_NONE: u8 = 0;
const OVERRIDE_L: u8 = 1;
const OVERRIDE_R: u8 = 2;

#[derive(Clone, Copy)]
struct Status {
    level: u8,
    override_: u8,
    isolate: bool,
}

impl Status {
    /// The class an override forces, if any (`L` is class 0, so the status is encoded apart).
    fn forced(self) -> Option<u8> {
        match self.override_ {
            OVERRIDE_L => Some(L),
            OVERRIDE_R => Some(R),
            _ => None,
        }
    }
}

/// The working state of one paragraph.
pub struct Bidi {
    /// Original classes (P/L rules look at these).
    orig: [u8; MAX],
    /// Current classes (rewritten by the X/W/N rules).
    cls: [u8; MAX],
    levels: [u8; MAX],
    /// Matching PDI of each isolate initiator (BD9), or `u16::MAX`.
    matching_pdi: [u16; MAX],
    /// Isolating run sequence under construction: indices into the paragraph.
    seq: [u16; MAX],
    /// Which level run each character belongs to, and the runs' first characters.
    run_of: [u16; MAX],
    run_start: [u16; MAX],
    run_len: [u16; MAX],
    run_used: [bool; MAX],
    n: usize,
    para_level: u8,
}

impl Default for Bidi {
    fn default() -> Self {
        Self::new()
    }
}

impl Bidi {
    pub const fn new() -> Bidi {
        Bidi {
            orig: [0; MAX],
            cls: [0; MAX],
            levels: [0; MAX],
            matching_pdi: [0; MAX],
            seq: [0; MAX],
            run_of: [0; MAX],
            run_start: [0; MAX],
            run_len: [0; MAX],
            run_used: [false; MAX],
            n: 0,
            para_level: 0,
        }
    }

    /// Resolves `text` (at most `MAX` code points): the paragraph level comes back, the
    /// level of every character is in `levels` (`REMOVED` for X9-removed characters).
    pub fn resolve(&mut self, text: &[u32], base: Base, levels: &mut [u8]) -> u8 {
        let n = text.len().min(MAX).min(levels.len());
        self.n = n;
        for (i, &cp) in text.iter().take(n).enumerate() {
            self.orig[i] = class_of(cp);
            self.cls[i] = self.orig[i];
        }
        self.match_isolates();
        self.para_level = match base {
            Base::Ltr => 0,
            Base::Rtl => 1,
            Base::Auto => self.first_strong_level(0, n, 0),
        };
        self.explicit();
        self.resolve_sequences(text);
        self.implicit();
        self.line_reset();
        levels[..n].copy_from_slice(&self.levels[..n]);
        self.para_level
    }

    /// The paragraph level of the last `resolve`.
    pub fn para_level(&self) -> u8 {
        self.para_level
    }

    /// The resolved classes of the last paragraph (diagnostics).
    pub fn classes(&self) -> &[u8] {
        &self.cls[..self.n]
    }

    /// BD9: the matching PDI of every isolate initiator.
    fn match_isolates(&mut self) {
        let n = self.n;
        for i in 0..n {
            self.matching_pdi[i] = u16::MAX;
        }
        // A stack of open initiators.
        let mut stack = [0u16; MAX];
        let mut depth = 0usize;
        for i in 0..n {
            let c = self.orig[i];
            if is_isolate_initiator(c) {
                stack[depth] = i as u16;
                depth += 1;
            } else if c == PDI && depth > 0 {
                depth -= 1;
                self.matching_pdi[stack[depth] as usize] = i as u16;
            }
        }
    }

    /// P2–P3 over `[from, to)`: the level of the first strong character outside isolates;
    /// `default` when there is none.
    fn first_strong_level(&self, from: usize, to: usize, default: u8) -> u8 {
        let mut i = from;
        while i < to {
            match self.orig[i] {
                L => return 0,
                R | AL => return 1,
                c if is_isolate_initiator(c) => {
                    let m = self.matching_pdi[i];
                    if m == u16::MAX {
                        return default;
                    }
                    i = m as usize;
                }
                _ => {}
            }
            i += 1;
        }
        default
    }

    /// X1–X9.
    fn explicit(&mut self) {
        let n = self.n;
        let mut stack = [Status {
            level: 0,
            override_: OVERRIDE_NONE,
            isolate: false,
        }; MAX_DEPTH as usize + 2];
        let mut depth = 1usize;
        stack[0] = Status {
            level: self.para_level,
            override_: OVERRIDE_NONE,
            isolate: false,
        };
        let mut overflow_isolate = 0u32;
        let mut overflow_embedding = 0u32;
        let mut valid_isolate = 0u32;
        for i in 0..n {
            let c = self.orig[i];
            let top = stack[depth - 1];
            match c {
                RLE | LRE | RLO | LRO => {
                    let rtl = matches!(c, RLE | RLO);
                    let new_level = if rtl {
                        (top.level + 1) | 1
                    } else {
                        (top.level + 2) & !1
                    };
                    self.levels[i] = top.level;
                    if new_level <= MAX_DEPTH && overflow_isolate == 0 && overflow_embedding == 0 {
                        stack[depth] = Status {
                            level: new_level,
                            override_: match c {
                                RLO => OVERRIDE_R,
                                LRO => OVERRIDE_L,
                                _ => OVERRIDE_NONE,
                            },
                            isolate: false,
                        };
                        depth += 1;
                    } else if overflow_isolate == 0 {
                        overflow_embedding += 1;
                    }
                }
                RLI | LRI | FSI => {
                    self.levels[i] = top.level;
                    if let Some(f) = top.forced() {
                        self.cls[i] = f;
                    }
                    let rtl = match c {
                        RLI => true,
                        LRI => false,
                        _ => {
                            let end = if self.matching_pdi[i] == u16::MAX {
                                n
                            } else {
                                self.matching_pdi[i] as usize
                            };
                            self.first_strong_level(i + 1, end, 0) == 1
                        }
                    };
                    let new_level = if rtl {
                        (top.level + 1) | 1
                    } else {
                        (top.level + 2) & !1
                    };
                    if new_level <= MAX_DEPTH && overflow_isolate == 0 && overflow_embedding == 0 {
                        valid_isolate += 1;
                        stack[depth] = Status {
                            level: new_level,
                            override_: OVERRIDE_NONE,
                            isolate: true,
                        };
                        depth += 1;
                    } else {
                        overflow_isolate += 1;
                    }
                }
                PDI => {
                    if overflow_isolate > 0 {
                        overflow_isolate -= 1;
                    } else if valid_isolate > 0 {
                        overflow_embedding = 0;
                        while depth > 1 && !stack[depth - 1].isolate {
                            depth -= 1;
                        }
                        if depth > 1 {
                            depth -= 1;
                        }
                        valid_isolate -= 1;
                    }
                    let top = stack[depth - 1];
                    self.levels[i] = top.level;
                    if let Some(f) = top.forced() {
                        self.cls[i] = f;
                    }
                }
                PDF => {
                    self.levels[i] = top.level;
                    if overflow_isolate > 0 {
                        // Nothing.
                    } else if overflow_embedding > 0 {
                        overflow_embedding -= 1;
                    } else if !top.isolate && depth >= 2 {
                        depth -= 1;
                    }
                }
                B => {
                    self.levels[i] = self.para_level;
                }
                BN => {
                    self.levels[i] = top.level;
                }
                _ => {
                    self.levels[i] = top.level;
                    if let Some(f) = top.forced() {
                        self.cls[i] = f;
                    }
                }
            }
        }
        // X9: removed characters keep no level.
        for i in 0..n {
            if is_removed_class(self.orig[i]) {
                self.levels[i] = REMOVED;
            }
        }
    }

    /// X10: builds every isolating run sequence and applies W1–W7, N0–N2 to it.
    fn resolve_sequences(&mut self, text: &[u32]) {
        let n = self.n;
        // Level runs over the non-removed characters.
        let mut n_runs = 0usize;
        let mut prev_level = REMOVED;
        for i in 0..n {
            let lv = self.levels[i];
            if lv == REMOVED {
                self.run_of[i] = u16::MAX;
                continue;
            }
            if lv != prev_level || n_runs == 0 {
                self.run_start[n_runs] = i as u16;
                self.run_len[n_runs] = 0;
                n_runs += 1;
                prev_level = lv;
            }
            self.run_of[i] = (n_runs - 1) as u16;
            self.run_len[n_runs - 1] += 1;
        }
        for r in 0..n_runs {
            self.run_used[r] = false;
        }
        for r in 0..n_runs {
            if self.run_used[r] {
                continue;
            }
            // Chain runs through isolate initiators and their matching PDIs.
            let mut len = 0usize;
            let mut run = r;
            loop {
                self.run_used[run] = true;
                let start = self.run_start[run] as usize;
                let mut i = start;
                let mut count = 0usize;
                while i < n && count < self.run_len[run] as usize {
                    if self.levels[i] != REMOVED {
                        self.seq[len] = i as u16;
                        len += 1;
                        count += 1;
                    }
                    i += 1;
                }
                let last = self.seq[len - 1] as usize;
                let c = self.orig[last];
                if is_isolate_initiator(c) && self.matching_pdi[last] != u16::MAX {
                    let pdi = self.matching_pdi[last] as usize;
                    let next = self.run_of[pdi];
                    if next != u16::MAX && !self.run_used[next as usize] {
                        run = next as usize;
                        continue;
                    }
                }
                break;
            }
            self.resolve_one_sequence(len, text);
        }
    }

    fn strong_dir(level: u8) -> u8 {
        if level & 1 == 1 {
            R
        } else {
            L
        }
    }

    /// W1–W7 and N0–N2 over the sequence `seq[..len]`.
    fn resolve_one_sequence(&mut self, len: usize, text: &[u32]) {
        let n = self.n;
        let first = self.seq[0] as usize;
        let last = self.seq[len - 1] as usize;
        let level = self.levels[first];
        // sos: the preceding non-removed character's level, or the paragraph level.
        let mut prev = None;
        let mut i = first;
        while i > 0 {
            i -= 1;
            if self.levels[i] != REMOVED {
                prev = Some(self.levels[i]);
                break;
            }
        }
        let sos = Self::strong_dir(level.max(prev.unwrap_or(self.para_level)));
        // eos: the following non-removed character's level, or the paragraph level when there
        // is none or the sequence ends with an unmatched isolate initiator.
        let mut next = None;
        if !(is_isolate_initiator(self.orig[last]) && self.matching_pdi[last] == u16::MAX) {
            let mut j = last + 1;
            while j < n {
                if self.levels[j] != REMOVED {
                    next = Some(self.levels[j]);
                    break;
                }
                j += 1;
            }
        }
        let eos = Self::strong_dir(level.max(next.unwrap_or(self.para_level)));
        let e = Self::strong_dir(level);

        // W1: NSM takes the class of the previous character (ON after an isolate boundary).
        for k in 0..len {
            let i = self.seq[k] as usize;
            if self.cls[i] == NSM {
                self.cls[i] = if k == 0 {
                    sos
                } else {
                    let p = self.cls[self.seq[k - 1] as usize];
                    if is_isolate_initiator(p) || p == PDI {
                        ON
                    } else {
                        p
                    }
                };
            }
        }
        // W2: EN after AL (searching back for the first strong) becomes AN.
        let mut last_strong = sos;
        for k in 0..len {
            let i = self.seq[k] as usize;
            match self.cls[i] {
                L | R | AL => last_strong = self.cls[i],
                EN if last_strong == AL => self.cls[i] = AN,
                _ => {}
            }
        }
        // W3: AL → R.
        for k in 0..len {
            let i = self.seq[k] as usize;
            if self.cls[i] == AL {
                self.cls[i] = R;
            }
        }
        // W4: a single ES between ENs → EN; a single CS between equal numbers → that number.
        for k in 1..len.saturating_sub(1) {
            let (a, i, b) = (
                self.seq[k - 1] as usize,
                self.seq[k] as usize,
                self.seq[k + 1] as usize,
            );
            let (ca, ci, cb) = (self.cls[a], self.cls[i], self.cls[b]);
            if ci == ES && ca == EN && cb == EN {
                self.cls[i] = EN;
            } else if ci == CS && ca == cb && (ca == EN || ca == AN) {
                self.cls[i] = ca;
            }
        }
        // W5: ETs adjacent to EN → EN.
        let mut k = 0;
        while k < len {
            if self.cls[self.seq[k] as usize] == ET {
                let start = k;
                while k < len && self.cls[self.seq[k] as usize] == ET {
                    k += 1;
                }
                let before = start > 0 && self.cls[self.seq[start - 1] as usize] == EN;
                let after = k < len && self.cls[self.seq[k] as usize] == EN;
                if before || after {
                    for item in &self.seq[start..k] {
                        self.cls[*item as usize] = EN;
                    }
                }
            } else {
                k += 1;
            }
        }
        // W6: remaining separators and terminators → ON.
        for k in 0..len {
            let i = self.seq[k] as usize;
            if matches!(self.cls[i], ES | ET | CS) {
                self.cls[i] = ON;
            }
        }
        // W7: EN after L (first strong searching back) → L.
        let mut last_strong = sos;
        for k in 0..len {
            let i = self.seq[k] as usize;
            match self.cls[i] {
                L | R => last_strong = self.cls[i],
                EN if last_strong == L => self.cls[i] = L,
                _ => {}
            }
        }
        // N0: bracket pairs.
        self.brackets(len, text, sos, e);
        // N1–N2: neutrals between strong types of the same direction take it (EN/AN count as
        // R); the rest take the embedding direction.
        let mut k = 0;
        while k < len {
            if is_ni(self.cls[self.seq[k] as usize]) {
                let start = k;
                while k < len && is_ni(self.cls[self.seq[k] as usize]) {
                    k += 1;
                }
                let before = if start == 0 {
                    sos
                } else {
                    Self::as_strong(self.cls[self.seq[start - 1] as usize])
                };
                let after = if k == len {
                    eos
                } else {
                    Self::as_strong(self.cls[self.seq[k] as usize])
                };
                let dir = if before == after { before } else { e };
                for item in &self.seq[start..k] {
                    self.cls[*item as usize] = dir;
                }
            } else {
                k += 1;
            }
        }
    }

    fn as_strong(c: u8) -> u8 {
        match c {
            L => L,
            R | AL | EN | AN => R,
            other => other,
        }
    }

    /// N0 (BD14–BD16): pairs brackets within the sequence and resolves them.
    fn brackets(&mut self, len: usize, text: &[u32], sos: u8, e: u8) {
        const STACK: usize = 63;
        let mut open_pos = [0u16; STACK];
        let mut open_pair = [0u32; STACK];
        let mut depth = 0usize;
        // Pairs as (opening k, closing k) in the sequence.
        let mut pairs = [(0u16, 0u16); MAX];
        let mut n_pairs = 0usize;
        for k in 0..len {
            let i = self.seq[k] as usize;
            if self.cls[i] != ON {
                continue;
            }
            let Some((pair, is_open)) = bracket_of(text[i]) else {
                continue;
            };
            if is_open {
                if depth == STACK {
                    // BD16: an overflow stops the pairing for this sequence.
                    n_pairs = 0;
                    break;
                }
                open_pos[depth] = k as u16;
                open_pair[depth] = canonical(pair);
                depth += 1;
            } else {
                let me = canonical(text[i]);
                let mut d = depth;
                while d > 0 {
                    d -= 1;
                    if open_pair[d] == me {
                        pairs[n_pairs] = (open_pos[d], k as u16);
                        n_pairs += 1;
                        depth = d;
                        break;
                    }
                }
            }
        }
        // Sort pairs by the opening position (insertion sort; few pairs).
        for a in 1..n_pairs {
            let mut b = a;
            while b > 0 && pairs[b - 1].0 > pairs[b].0 {
                pairs.swap(b - 1, b);
                b -= 1;
            }
        }
        for &(po, pc) in &pairs[..n_pairs] {
            let (ko, kc) = (po as usize, pc as usize);
            let mut found_e = false;
            let mut found_o = false;
            for k in ko + 1..kc {
                match Self::as_strong(self.cls[self.seq[k] as usize]) {
                    c if c == e => found_e = true,
                    L | R => found_o = true,
                    _ => {}
                }
            }
            let dir = if found_e {
                e
            } else if found_o {
                // The context before the opening bracket.
                let mut ctx = sos;
                let mut k = ko;
                while k > 0 {
                    k -= 1;
                    let c = Self::as_strong(self.cls[self.seq[k] as usize]);
                    if c == L || c == R {
                        ctx = c;
                        break;
                    }
                }
                if ctx != e {
                    ctx
                } else {
                    e
                }
            } else {
                continue;
            };
            for &k in &[ko, kc] {
                let i = self.seq[k] as usize;
                self.cls[i] = dir;
                // NSMs that followed the bracket (W1 made them ON) take its new class.
                let mut j = k + 1;
                while j < len {
                    let idx = self.seq[j] as usize;
                    if self.orig[idx] == NSM {
                        self.cls[idx] = dir;
                        j += 1;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    /// I1–I2.
    fn implicit(&mut self) {
        for i in 0..self.n {
            let lv = self.levels[i];
            if lv == REMOVED {
                continue;
            }
            let c = self.cls[i];
            self.levels[i] = if lv & 1 == 0 {
                match c {
                    R => lv + 1,
                    AN | EN => lv + 2,
                    _ => lv,
                }
            } else {
                match c {
                    L | EN | AN => lv + 1,
                    _ => lv,
                }
            };
        }
    }

    /// L1: separators, and whitespace/isolate runs before them or at the end of the line,
    /// go back to the paragraph level (original classes; removed characters stay removed).
    fn line_reset(&mut self) {
        let n = self.n;
        let mut k = n;
        let mut trailing = true;
        while k > 0 {
            k -= 1;
            let c = self.orig[k];
            if matches!(c, B | S) {
                if self.levels[k] != REMOVED {
                    self.levels[k] = self.para_level;
                }
                trailing = true;
            } else if trailing && (matches!(c, WS | LRI | RLI | FSI | PDI) || is_removed_class(c)) {
                if self.levels[k] != REMOVED {
                    self.levels[k] = self.para_level;
                }
            } else {
                trailing = false;
            }
        }
    }
}

fn canonical(cp: u32) -> u32 {
    // The angle brackets U+2329/U+232A are canonically equivalent to U+3008/U+3009.
    match cp {
        0x2329 => 0x3008,
        0x232A => 0x3009,
        other => other,
    }
}

/// `(pair, is_open)` for a bracket character (BidiBrackets.txt).
pub fn bracket_of(cp: u32) -> Option<(u32, bool)> {
    let mut lo = 0usize;
    let mut hi = BRACKETS.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (c, pair, open) = BRACKETS[mid];
        if c == cp {
            return Some((pair, open));
        }
        if c < cp {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    None
}

/// L2: the visual order of the non-removed characters whose levels are given, as logical
/// indices written to `order`; the count comes back.
pub fn reorder(levels: &[u8], order: &mut [u16]) -> usize {
    let mut n = 0usize;
    let mut max = 0u8;
    let mut min_odd = REMOVED;
    for (i, &lv) in levels.iter().enumerate() {
        if lv == REMOVED || n >= order.len() {
            continue;
        }
        order[n] = i as u16;
        n += 1;
        max = max.max(lv);
        if lv & 1 == 1 && lv < min_odd {
            min_odd = lv;
        }
    }
    if min_odd == REMOVED {
        return n;
    }
    let mut lv = max;
    while lv >= min_odd {
        let mut k = 0;
        while k < n {
            if levels[order[k] as usize] >= lv {
                let start = k;
                while k < n && levels[order[k] as usize] >= lv {
                    k += 1;
                }
                order[start..k].reverse();
            } else {
                k += 1;
            }
        }
        if lv == 0 {
            break;
        }
        lv -= 1;
    }
    n
}
