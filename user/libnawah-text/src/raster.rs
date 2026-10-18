//! The rasteriser (WP-35, ADR-0019 §6): a TrueType outline (quadratic contours, implied
//! on-curve midpoints between consecutive off-curve points) scaled to a pixel size, flattened
//! into line edges and sampled on a 4×4 grid per pixel with the non-zero winding rule. A
//! pixel's coverage is the number of its 16 sample points inside the outline (0..=16); no
//! hinting. Integer arithmetic only: positions are 26.6 fixed point (1/64 pixel).
//!
//! Sample points of pixel (px, py) — y grows downwards in the bitmap — sit at
//! (px + (i + ½)/4, py + (j + ½)/4) for i, j in 0..4; an edge covers sample rows in
//! [y_min, y_max) (half-open), and a sample at x is inside when the winding of the crossings
//! at x' <= x is non-zero. The host reference (tests/test_text.py) uses the same definition
//! with an independent flattening.

use crate::font::{Outline, Point};

/// One pixel = 64 units.
const ONE: i64 = 64;
/// Sub-sample step (1/4 pixel) and offset to its centre (1/8 pixel).
const STEP: i64 = ONE / 4;
const HALF: i64 = ONE / 8;
/// Flattening tolerance: 1/16 pixel.
const TOL: i64 = ONE / 64;

pub const MAX_EDGES: usize = 4096;
/// The largest bitmap side.
pub const MAX_SIDE: usize = 256;

#[derive(Clone, Copy, Default)]
struct Edge {
    x0: i64,
    y0: i64,
    x1: i64,
    y1: i64,
}

/// A rendered glyph: `w × h` coverage values (0..=16), row 0 at the top; the bitmap's
/// top-left corner sits at (`left`, -`top`) pixels from the glyph origin on the baseline
/// (`top` = pixels above the baseline).
pub struct Bitmap {
    pub w: usize,
    pub h: usize,
    pub left: i32,
    pub top: i32,
    pub coverage: [u8; MAX_SIDE * MAX_SIDE],
}

impl Default for Bitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl Bitmap {
    pub const fn new() -> Bitmap {
        Bitmap {
            w: 0,
            h: 0,
            left: 0,
            top: 0,
            coverage: [0; MAX_SIDE * MAX_SIDE],
        }
    }

    pub fn at(&self, x: usize, y: usize) -> u8 {
        self.coverage[y * self.w + x]
    }

    /// FNV-1a 64 over `w`, `h`, `left`, `top` (little endian) and the coverage bytes: what
    /// host and guest compare.
    pub fn hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |b: u8| {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        };
        for v in [
            self.w as u32,
            self.h as u32,
            self.left as u32,
            self.top as u32,
        ] {
            for b in v.to_le_bytes() {
                eat(b);
            }
        }
        for &c in &self.coverage[..self.w * self.h] {
            eat(c);
        }
        h
    }
}

/// The rasteriser's working state (edges), owned by the caller.
pub struct Rasterizer {
    edges: [Edge; MAX_EDGES],
    n: usize,
    overflow: bool,
    /// Crossings of one sample row: (x, winding) — here, not on the stack (a user process
    /// has 64 KiB of stack).
    xs: [(i64, i8); MAX_EDGES],
}

impl Default for Rasterizer {
    fn default() -> Self {
        Self::new()
    }
}

fn isqrt(v: i64) -> i64 {
    if v <= 0 {
        return 0;
    }
    let mut x = v;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + v / x) / 2;
    }
    x
}

impl Rasterizer {
    pub const fn new() -> Rasterizer {
        Rasterizer {
            edges: [Edge {
                x0: 0,
                y0: 0,
                x1: 0,
                y1: 0,
            }; MAX_EDGES],
            n: 0,
            overflow: false,
            xs: [(0, 0); MAX_EDGES],
        }
    }

    fn line(&mut self, x0: i64, y0: i64, x1: i64, y1: i64) {
        if y0 == y1 {
            return; // horizontal edges cross no sample row
        }
        if self.n == MAX_EDGES {
            self.overflow = true;
            return;
        }
        self.edges[self.n] = Edge { x0, y0, x1, y1 };
        self.n += 1;
    }

    fn quad(&mut self, p0: (i64, i64), p1: (i64, i64), p2: (i64, i64)) {
        // Deviation of the control point from the chord's midpoint bounds the error of n
        // segments by dev / (4 n²) (|p0 - 2 p1 + p2| / 8 per unit parameter squared).
        let dx = p0.0 - 2 * p1.0 + p2.0;
        let dy = p0.1 - 2 * p1.1 + p2.1;
        let dev = isqrt(dx * dx + dy * dy);
        let n = (isqrt(dev / (4 * TOL).max(1)) + 1).clamp(1, 64);
        let mut prev = p0;
        for k in 1..=n {
            // B(t) with t = k/n, exact in integers: ((n-k)² p0 + 2k(n-k) p1 + k² p2) / n².
            let (a, b, c) = ((n - k) * (n - k), 2 * k * (n - k), k * k);
            let nn = n * n;
            let x = (a * p0.0 + b * p1.0 + c * p2.0 + nn / 2).div_euclid(nn);
            let y = (a * p0.1 + b * p1.1 + c * p2.1 + nn / 2).div_euclid(nn);
            self.line(prev.0, prev.1, x, y);
            prev = (x, y);
        }
    }

    /// Renders `outline` (font units, y up) at `px` pixels per em into `out`. Returns false
    /// when the glyph does not fit `MAX_SIDE` or has more edges than `MAX_EDGES`.
    pub fn render(
        &mut self,
        outline: &Outline,
        units_per_em: u16,
        px: u32,
        out: &mut Bitmap,
    ) -> bool {
        self.n = 0;
        self.overflow = false;
        out.w = 0;
        out.h = 0;
        out.left = 0;
        out.top = 0;
        if outline.n_points == 0 {
            return true;
        }
        let upem = i64::from(units_per_em.max(1));
        let scale = |v: i32| -> i64 { (i64::from(v) * i64::from(px) * ONE).div_euclid(upem) };
        // To 26.6 with y flipped (down).
        let tp = |p: &Point| -> (i64, i64) { (scale(p.x), -scale(p.y)) };
        let mut start = 0usize;
        for c in 0..outline.n_contours {
            let end = outline.contour_end[c] as usize;
            if end <= start || end > outline.n_points {
                start = end;
                continue;
            }
            let pts = &outline.points[start..end];
            let n = pts.len();
            // The first on-curve point (or the midpoint of the first two off-curve ones).
            let first_on = pts.iter().position(|p| p.on_curve);
            let (origin, first_idx) = match first_on {
                Some(i) => (tp(&pts[i]), i),
                None => {
                    let (a, b) = (tp(&pts[0]), tp(&pts[1 % n]));
                    (((a.0 + b.0) / 2, (a.1 + b.1) / 2), 0)
                }
            };
            let mut cur = origin;
            let mut ctrl: Option<(i64, i64)> = None;
            for k in 1..=n {
                let p = &pts[(first_idx + k) % n];
                let q = tp(p);
                if p.on_curve {
                    match ctrl.take() {
                        Some(c1) => self.quad(cur, c1, q),
                        None => self.line(cur.0, cur.1, q.0, q.1),
                    }
                    cur = q;
                } else {
                    if let Some(c1) = ctrl {
                        let mid = ((c1.0 + q.0) / 2, (c1.1 + q.1) / 2);
                        self.quad(cur, c1, mid);
                        cur = mid;
                    }
                    ctrl = Some(q);
                }
            }
            match ctrl {
                Some(c1) => self.quad(cur, c1, origin),
                None => {
                    if cur != origin {
                        self.line(cur.0, cur.1, origin.0, origin.1);
                    }
                }
            }
            start = end;
        }
        if self.overflow {
            return false;
        }
        if self.n == 0 {
            return true;
        }
        // Bounding box in whole pixels.
        let (mut x0, mut y0, mut x1, mut y1) = (i64::MAX, i64::MAX, i64::MIN, i64::MIN);
        for e in &self.edges[..self.n] {
            x0 = x0.min(e.x0.min(e.x1));
            x1 = x1.max(e.x0.max(e.x1));
            y0 = y0.min(e.y0.min(e.y1));
            y1 = y1.max(e.y0.max(e.y1));
        }
        let px0 = x0.div_euclid(ONE);
        let py0 = y0.div_euclid(ONE);
        let px1 = (x1 + ONE - 1).div_euclid(ONE);
        let py1 = (y1 + ONE - 1).div_euclid(ONE);
        let (w, h) = ((px1 - px0) as usize, (py1 - py0) as usize);
        if w == 0 || h == 0 {
            return true;
        }
        if w > MAX_SIDE || h > MAX_SIDE {
            return false;
        }
        out.w = w;
        out.h = h;
        out.left = px0 as i32;
        out.top = -py0 as i32;
        out.coverage[..w * h].fill(0);
        let xs = &mut self.xs;
        for row in 0..h {
            for j in 0..4 {
                let sy = (py0 + row as i64) * ONE + HALF + STEP * j as i64;
                let mut n = 0usize;
                for e in &self.edges[..self.n] {
                    let (ya, yb, dir) = if e.y0 < e.y1 {
                        (e.y0, e.y1, 1i8)
                    } else {
                        (e.y1, e.y0, -1i8)
                    };
                    if sy < ya || sy >= yb {
                        continue;
                    }
                    // x at sy, rounded towards -inf on the 1/64 grid × (y1 - y0) exactly.
                    let num = (e.x1 - e.x0) * (sy - e.y0);
                    let x = e.x0 + num.div_euclid(e.y1 - e.y0);
                    xs[n] = (x, dir);
                    n += 1;
                }
                // Insertion sort by x (few crossings per row).
                for a in 1..n {
                    let mut b = a;
                    while b > 0 && xs[b - 1].0 > xs[b].0 {
                        xs.swap(b - 1, b);
                        b -= 1;
                    }
                }
                // Sweep the sample columns.
                let mut wind = 0i32;
                let mut k = 0usize;
                for col in 0..w {
                    for i in 0..4 {
                        let sx = (px0 + col as i64) * ONE + HALF + STEP * i as i64;
                        while k < n && xs[k].0 <= sx {
                            wind += i32::from(xs[k].1);
                            k += 1;
                        }
                        if wind != 0 {
                            out.coverage[row * w + col] += 1;
                        }
                    }
                }
            }
        }
        true
    }
}
