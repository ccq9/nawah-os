//! An OpenType/TrueType reader (WP-35, ADR-0019 §6): the table directory, `head`, `maxp`,
//! `hhea`/`hmtx`, `cmap` (formats 4 and 12), `loca`/`glyf` (simple and composite outlines)
//! and the parts of `GSUB` Arabic shaping needs (single substitutions of `init`/`medi`/`fina`
//! and the `rlig` ligatures; lookup types 1, 4 and 7, coverage formats 1 and 2). Every read
//! is bounds-checked and a malformed table answers "absent" rather than panicking. The
//! reader keeps only offsets: the font's bytes stay where the caller loaded them.
//!
//! References: OpenType specification (docs/sources.json S71): 'head', 'hhea', 'hmtx',
//! 'maxp', 'cmap', 'loca', 'glyf', 'GSUB'.

/// Outline coordinates are font units (`units_per_em` per em).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
    pub on_curve: bool,
}

/// An outline: points and the index past each contour's last point.
pub const MAX_POINTS: usize = 1024;
pub const MAX_CONTOURS: usize = 64;

pub struct Outline {
    pub points: [Point; MAX_POINTS],
    pub n_points: usize,
    pub contour_end: [u16; MAX_CONTOURS],
    pub n_contours: usize,
}

impl Default for Outline {
    fn default() -> Self {
        Self::new()
    }
}

impl Outline {
    pub const fn new() -> Outline {
        Outline {
            points: [Point {
                x: 0,
                y: 0,
                on_curve: false,
            }; MAX_POINTS],
            n_points: 0,
            contour_end: [0; MAX_CONTOURS],
            n_contours: 0,
        }
    }

    pub fn clear(&mut self) {
        self.n_points = 0;
        self.n_contours = 0;
    }
}

fn u8_at(d: &[u8], o: usize) -> Option<u8> {
    d.get(o).copied()
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(o)?, *d.get(o + 1)?]))
}

fn i16_at(d: &[u8], o: usize) -> Option<i16> {
    u16_at(d, o).map(|v| v as i16)
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

fn tag(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

/// A parsed font: offsets into `data`.
#[derive(Clone, Copy)]
pub struct Font<'a> {
    data: &'a [u8],
    pub units_per_em: u16,
    pub ascender: i16,
    pub descender: i16,
    num_glyphs: u16,
    num_hmetrics: u16,
    long_loca: bool,
    hmtx: (usize, usize),
    loca: (usize, usize),
    glyf: (usize, usize),
    cmap_sub: usize,
    cmap_format: u16,
    gsub: Option<(usize, usize)>,
    gdef: Option<(usize, usize)>,
}

impl<'a> Font<'a> {
    /// Parses the table directory; `None` when a required table is missing or malformed.
    pub fn parse(data: &'a [u8]) -> Option<Font<'a>> {
        let version = u32_at(data, 0)?;
        if version != 0x0001_0000 && version != tag(b"true") {
            return None;
        }
        let num_tables = u16_at(data, 4)? as usize;
        let find = |want: &[u8; 4]| -> Option<(usize, usize)> {
            for i in 0..num_tables {
                let rec = 12 + i * 16;
                if u32_at(data, rec)? == tag(want) {
                    let off = u32_at(data, rec + 8)? as usize;
                    let len = u32_at(data, rec + 12)? as usize;
                    if off.checked_add(len)? <= data.len() {
                        return Some((off, len));
                    }
                    return None;
                }
            }
            None
        };
        let head = find(b"head")?;
        let maxp = find(b"maxp")?;
        let hhea = find(b"hhea")?;
        let hmtx = find(b"hmtx")?;
        let cmap = find(b"cmap")?;
        let loca = find(b"loca")?;
        let glyf = find(b"glyf")?;
        let gsub = find(b"GSUB");
        let gdef = find(b"GDEF");
        let units_per_em = u16_at(data, head.0 + 18)?;
        let long_loca = i16_at(data, head.0 + 50)? != 0;
        let num_glyphs = u16_at(data, maxp.0 + 4)?;
        let ascender = i16_at(data, hhea.0 + 4)?;
        let descender = i16_at(data, hhea.0 + 6)?;
        let num_hmetrics = u16_at(data, hhea.0 + 34)?;
        // cmap: a Unicode subtable (platform 3/1, 3/10 or 0/x) of format 4 or 12.
        let n_sub = u16_at(data, cmap.0 + 2)? as usize;
        let mut best: Option<(usize, u16, u8)> = None;
        for i in 0..n_sub {
            let rec = cmap.0 + 4 + i * 8;
            let platform = u16_at(data, rec)?;
            let encoding = u16_at(data, rec + 2)?;
            let off = cmap.0 + u32_at(data, rec + 4)? as usize;
            let format = u16_at(data, off)?;
            let rank = match (platform, encoding, format) {
                (3, 10, 12) | (0, 4, 12) | (0, 6, 12) => 3,
                (3, 1, 4) => 2,
                (0, _, 4) => 1,
                _ => continue,
            };
            if best.is_none_or(|b| rank > b.2) {
                best = Some((off, format, rank));
            }
        }
        let (cmap_sub, cmap_format, _) = best?;
        Some(Font {
            data,
            units_per_em,
            ascender,
            descender,
            num_glyphs,
            num_hmetrics,
            long_loca,
            hmtx,
            loca,
            glyf,
            cmap_sub,
            cmap_format,
            gsub,
            gdef,
        })
    }

    pub fn num_glyphs(&self) -> u16 {
        self.num_glyphs
    }

    /// The glyph of a code point; 0 (.notdef) when the font lacks it.
    pub fn glyph_id(&self, cp: u32) -> u16 {
        self.lookup_cmap(cp).unwrap_or(0)
    }

    fn lookup_cmap(&self, cp: u32) -> Option<u16> {
        let d = self.data;
        let o = self.cmap_sub;
        match self.cmap_format {
            4 => {
                if cp > 0xFFFF {
                    return Some(0);
                }
                let seg_x2 = u16_at(d, o + 6)? as usize;
                let segs = seg_x2 / 2;
                let ends = o + 14;
                let starts = ends + seg_x2 + 2;
                let deltas = starts + seg_x2;
                let range_offsets = deltas + seg_x2;
                // Binary search on the sorted end codes.
                let (mut lo, mut hi) = (0usize, segs);
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    if (u16_at(d, ends + mid * 2)? as u32) < cp {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                if lo == segs {
                    return Some(0);
                }
                let start = u16_at(d, starts + lo * 2)? as u32;
                if cp < start {
                    return Some(0);
                }
                let delta = u16_at(d, deltas + lo * 2)?;
                let range_offset = u16_at(d, range_offsets + lo * 2)? as usize;
                if range_offset == 0 {
                    return Some((cp as u16).wrapping_add(delta));
                }
                let addr = range_offsets + lo * 2 + range_offset + (cp - start) as usize * 2;
                let g = u16_at(d, addr)?;
                Some(if g == 0 { 0 } else { g.wrapping_add(delta) })
            }
            12 => {
                let n_groups = u32_at(d, o + 12)? as usize;
                let (mut lo, mut hi) = (0usize, n_groups);
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    let g = o + 16 + mid * 12;
                    if u32_at(d, g + 4)? < cp {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                if lo == n_groups {
                    return Some(0);
                }
                let g = o + 16 + lo * 12;
                let start = u32_at(d, g)?;
                if cp < start {
                    return Some(0);
                }
                let gid = u32_at(d, g + 8)? + (cp - start);
                Some(if gid > 0xFFFF { 0 } else { gid as u16 })
            }
            _ => None,
        }
    }

    /// The advance width of a glyph in font units.
    pub fn advance(&self, gid: u16) -> u16 {
        let i = gid.min(self.num_hmetrics.saturating_sub(1)) as usize;
        u16_at(self.data, self.hmtx.0 + i * 4).unwrap_or(0)
    }

    /// The left side bearing of a glyph in font units.
    pub fn left_side_bearing(&self, gid: u16) -> i16 {
        let n = self.num_hmetrics as usize;
        let g = gid as usize;
        let o = if g < n {
            self.hmtx.0 + g * 4 + 2
        } else {
            self.hmtx.0 + n * 4 + (g - n) * 2
        };
        i16_at(self.data, o).unwrap_or(0)
    }

    fn glyph_range(&self, gid: u16) -> Option<(usize, usize)> {
        if gid >= self.num_glyphs {
            return None;
        }
        let d = self.data;
        let (start, end) = if self.long_loca {
            (
                u32_at(d, self.loca.0 + gid as usize * 4)? as usize,
                u32_at(d, self.loca.0 + gid as usize * 4 + 4)? as usize,
            )
        } else {
            (
                u16_at(d, self.loca.0 + gid as usize * 2)? as usize * 2,
                u16_at(d, self.loca.0 + gid as usize * 2 + 2)? as usize * 2,
            )
        };
        if end < start || end > self.glyf.1 {
            return None;
        }
        Some((self.glyf.0 + start, end - start))
    }

    /// Appends the outline of `gid` to `out` (font units), transformed by the 2×2 matrix
    /// `m` (16.16 fixed point, identity = [1<<16, 0, 0, 1<<16]) and offset `(dx, dy)`;
    /// composites recurse at most 4 levels. Returns false when the glyph is malformed.
    pub fn outline(&self, gid: u16, out: &mut Outline) -> bool {
        self.outline_into(gid, out, [1 << 16, 0, 0, 1 << 16], 0, 0, 0)
    }

    fn outline_into(
        &self,
        gid: u16,
        out: &mut Outline,
        m: [i32; 4],
        dx: i32,
        dy: i32,
        depth: u8,
    ) -> bool {
        let Some((o, len)) = self.glyph_range(gid) else {
            return false;
        };
        if len == 0 {
            return true; // empty glyph (space)
        }
        let d = self.data;
        let Some(n_contours) = i16_at(d, o) else {
            return false;
        };
        if n_contours >= 0 {
            self.simple(o, n_contours as usize, out, m, dx, dy)
        } else if depth < 4 {
            self.composite(o, out, m, dx, dy, depth)
        } else {
            false
        }
    }

    fn transform(m: [i32; 4], dx: i32, dy: i32, x: i32, y: i32) -> (i32, i32) {
        let tx = ((m[0] as i64 * x as i64 + m[2] as i64 * y as i64) >> 16) as i32 + dx;
        let ty = ((m[1] as i64 * x as i64 + m[3] as i64 * y as i64) >> 16) as i32 + dy;
        (tx, ty)
    }

    fn simple(
        &self,
        o: usize,
        n_contours: usize,
        out: &mut Outline,
        m: [i32; 4],
        dx: i32,
        dy: i32,
    ) -> bool {
        let d = self.data;
        if out.n_contours + n_contours > MAX_CONTOURS {
            return false;
        }
        let ends = o + 10;
        let n_points = match u16_at(d, ends + (n_contours.max(1) - 1) * 2) {
            Some(last) if n_contours > 0 => last as usize + 1,
            _ => 0,
        };
        if n_points == 0 || out.n_points + n_points > MAX_POINTS {
            return n_points == 0;
        }
        let Some(instr_len) = u16_at(d, ends + n_contours * 2) else {
            return false;
        };
        let mut p = ends + n_contours * 2 + 2 + instr_len as usize;
        // Flags, with repeats.
        let base = out.n_points;
        let mut flags = [0u8; MAX_POINTS];
        let mut i = 0;
        while i < n_points {
            let Some(f) = u8_at(d, p) else {
                return false;
            };
            p += 1;
            flags[i] = f;
            i += 1;
            if f & 0x08 != 0 {
                let Some(r) = u8_at(d, p) else {
                    return false;
                };
                p += 1;
                for _ in 0..r {
                    if i < n_points {
                        flags[i] = f;
                        i += 1;
                    }
                }
            }
        }
        // X coordinates then Y coordinates, both delta-encoded.
        let mut x = 0i32;
        for (i, f) in flags.iter().enumerate().take(n_points) {
            let dxv = if f & 0x02 != 0 {
                let Some(v) = u8_at(d, p) else {
                    return false;
                };
                p += 1;
                if f & 0x10 != 0 {
                    v as i32
                } else {
                    -(v as i32)
                }
            } else if f & 0x10 != 0 {
                0
            } else {
                let Some(v) = i16_at(d, p) else {
                    return false;
                };
                p += 2;
                v as i32
            };
            x += dxv;
            out.points[base + i] = Point {
                x,
                y: 0,
                on_curve: f & 0x01 != 0,
            };
        }
        let mut y = 0i32;
        for (i, f) in flags.iter().enumerate().take(n_points) {
            let dyv = if f & 0x04 != 0 {
                let Some(v) = u8_at(d, p) else {
                    return false;
                };
                p += 1;
                if f & 0x20 != 0 {
                    v as i32
                } else {
                    -(v as i32)
                }
            } else if f & 0x20 != 0 {
                0
            } else {
                let Some(v) = i16_at(d, p) else {
                    return false;
                };
                p += 2;
                v as i32
            };
            y += dyv;
            out.points[base + i].y = y;
        }
        for pt in out.points[base..base + n_points].iter_mut() {
            let (tx, ty) = Self::transform(m, dx, dy, pt.x, pt.y);
            pt.x = tx;
            pt.y = ty;
        }
        for c in 0..n_contours {
            let Some(end) = u16_at(d, ends + c * 2) else {
                return false;
            };
            out.contour_end[out.n_contours] = (base + end as usize + 1) as u16;
            out.n_contours += 1;
        }
        out.n_points += n_points;
        true
    }

    fn composite(
        &self,
        o: usize,
        out: &mut Outline,
        m: [i32; 4],
        dx: i32,
        dy: i32,
        depth: u8,
    ) -> bool {
        let d = self.data;
        let mut p = o + 10;
        loop {
            let (Some(flags), Some(cgid)) = (u16_at(d, p), u16_at(d, p + 2)) else {
                return false;
            };
            p += 4;
            let (a1, a2) = if flags & 0x0001 != 0 {
                let (Some(a), Some(b)) = (i16_at(d, p), i16_at(d, p + 2)) else {
                    return false;
                };
                p += 4;
                (a as i32, b as i32)
            } else {
                let (Some(a), Some(b)) = (u8_at(d, p), u8_at(d, p + 1)) else {
                    return false;
                };
                p += 2;
                (a as i8 as i32, b as i8 as i32)
            };
            // Component transform (2.14 fixed point → 16.16).
            let f2dot14 = |o: usize| i16_at(d, o).map(|v| (v as i32) << 2);
            let mut cm = [1 << 16, 0, 0, 1 << 16];
            if flags & 0x0008 != 0 {
                let Some(s) = f2dot14(p) else {
                    return false;
                };
                p += 2;
                cm = [s, 0, 0, s];
            } else if flags & 0x0040 != 0 {
                let (Some(sx), Some(sy)) = (f2dot14(p), f2dot14(p + 2)) else {
                    return false;
                };
                p += 4;
                cm = [sx, 0, 0, sy];
            } else if flags & 0x0080 != 0 {
                let (Some(a), Some(b), Some(c), Some(dd)) =
                    (f2dot14(p), f2dot14(p + 2), f2dot14(p + 4), f2dot14(p + 6))
                else {
                    return false;
                };
                p += 8;
                cm = [a, b, c, dd];
            }
            // Only offsets are supported (ARGS_ARE_XY_VALUES); point matching is rare and
            // treated as a zero offset.
            let (ox, oy) = if flags & 0x0002 != 0 {
                (a1, a2)
            } else {
                (0, 0)
            };
            // Compose: this component's points p' = cm·p + (ox, oy), then the parent's
            // transform.
            let mm = [
                ((m[0] as i64 * cm[0] as i64 + m[2] as i64 * cm[1] as i64) >> 16) as i32,
                ((m[1] as i64 * cm[0] as i64 + m[3] as i64 * cm[1] as i64) >> 16) as i32,
                ((m[0] as i64 * cm[2] as i64 + m[2] as i64 * cm[3] as i64) >> 16) as i32,
                ((m[1] as i64 * cm[2] as i64 + m[3] as i64 * cm[3] as i64) >> 16) as i32,
            ];
            let (tdx, tdy) = Self::transform(m, dx, dy, ox, oy);
            if !self.outline_into(cgid, out, mm, tdx, tdy, depth + 1) {
                return false;
            }
            if flags & 0x0020 == 0 {
                return true;
            }
        }
    }

    // ---- GSUB ---------------------------------------------------------------------------

    /// The lookups of `feature` under `script` (its default language system), as lookup
    /// indices written to `out`; the count comes back (0 when absent).
    pub fn feature_lookups(&self, script: &[u8; 4], feature: &[u8; 4], out: &mut [u16]) -> usize {
        self.feature_lookups_opt(script, feature, out).unwrap_or(0)
    }

    fn feature_lookups_opt(
        &self,
        script: &[u8; 4],
        feature: &[u8; 4],
        out: &mut [u16],
    ) -> Option<usize> {
        let (g, _) = self.gsub?;
        let d = self.data;
        let script_list = g + u16_at(d, g + 4)? as usize;
        let feature_list = g + u16_at(d, g + 6)? as usize;
        let n_scripts = u16_at(d, script_list)? as usize;
        let mut script_off = None;
        for i in 0..n_scripts {
            let rec = script_list + 2 + i * 6;
            if u32_at(d, rec)? == tag(script) {
                script_off = Some(script_list + u16_at(d, rec + 4)? as usize);
            }
        }
        let s = script_off?;
        let default_lang = u16_at(d, s)? as usize;
        if default_lang == 0 {
            return None;
        }
        let lang = s + default_lang;
        let n_feat = u16_at(d, lang + 4)? as usize;
        let n_features = u16_at(d, feature_list)? as usize;
        let mut count = 0;
        for i in 0..n_feat {
            let fi = u16_at(d, lang + 6 + i * 2)? as usize;
            if fi >= n_features {
                continue;
            }
            let rec = feature_list + 2 + fi * 6;
            if u32_at(d, rec)? != tag(feature) {
                continue;
            }
            let f = feature_list + u16_at(d, rec + 4)? as usize;
            let n_lookups = u16_at(d, f + 2)? as usize;
            for k in 0..n_lookups {
                if count < out.len() {
                    out[count] = u16_at(d, f + 4 + k * 2)?;
                    count += 1;
                }
            }
        }
        Some(count)
    }

    /// Coverage index of `gid` in the coverage table at `o`.
    fn coverage(&self, o: usize, gid: u16) -> Option<u16> {
        let d = self.data;
        match u16_at(d, o)? {
            1 => {
                let n = u16_at(d, o + 2)? as usize;
                let (mut lo, mut hi) = (0usize, n);
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    let g = u16_at(d, o + 4 + mid * 2)?;
                    if g < gid {
                        lo = mid + 1;
                    } else if g > gid {
                        hi = mid;
                    } else {
                        return Some(mid as u16);
                    }
                }
                None
            }
            2 => {
                let n = u16_at(d, o + 2)? as usize;
                for i in 0..n {
                    let r = o + 4 + i * 6;
                    let (start, end, si) = (u16_at(d, r)?, u16_at(d, r + 2)?, u16_at(d, r + 4)?);
                    if gid >= start && gid <= end {
                        return Some(si + (gid - start));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// The glyph's class in `GDEF` (1 base, 2 ligature, 3 mark, 4 component; 0 unknown).
    pub fn glyph_class(&self, gid: u16) -> u16 {
        self.gdef
            .and_then(|(g, _)| {
                let off = u16_at(self.data, g + 4)? as usize;
                if off == 0 {
                    return None;
                }
                self.class_def(g + off, gid)
            })
            .unwrap_or(0)
    }

    /// Class of `gid` in the class definition table at `o` (formats 1 and 2).
    fn class_def(&self, o: usize, gid: u16) -> Option<u16> {
        let d = self.data;
        match u16_at(d, o)? {
            1 => {
                let start = u16_at(d, o + 2)?;
                let n = u16_at(d, o + 4)?;
                if gid < start || gid - start >= n {
                    return Some(0);
                }
                u16_at(d, o + 6 + (gid - start) as usize * 2)
            }
            2 => {
                let n = u16_at(d, o + 2)? as usize;
                let (mut lo, mut hi) = (0usize, n);
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    let r = o + 4 + mid * 6;
                    let (start, end) = (u16_at(d, r)?, u16_at(d, r + 2)?);
                    if gid < start {
                        hi = mid;
                    } else if gid > end {
                        lo = mid + 1;
                    } else {
                        return u16_at(d, r + 4);
                    }
                }
                Some(0)
            }
            _ => None,
        }
    }

    /// The flag word of lookup `index` (bit 3: ignore marks).
    pub fn lookup_flag(&self, index: u16) -> u16 {
        self.lookup_table(index)
            .and_then(|l| u16_at(self.data, l + 2))
            .unwrap_or(0)
    }

    fn lookup_table(&self, index: u16) -> Option<usize> {
        let (g, _) = self.gsub?;
        let d = self.data;
        let lookup_list = g + u16_at(d, g + 8)? as usize;
        let n = u16_at(d, lookup_list)? as usize;
        if index as usize >= n {
            return None;
        }
        Some(lookup_list + u16_at(d, lookup_list + 2 + index as usize * 2)? as usize)
    }

    /// The kind of lookup `index` (its subtables' type; 7 resolved).
    pub fn lookup_kind(&self, index: u16) -> u16 {
        let mut subs = [(0u16, 0usize); 16];
        match self.lookup_subtables(index, &mut subs) {
            Some(n) if n > 0 => subs[0].0,
            _ => 0,
        }
    }

    /// Chaining contextual substitution (lookup type 6, format 3 — coverage based) at
    /// `pos` of `glyphs`, skipping marks when `skip_marks` and the glyph `ignore` (ZWNJ's,
    /// as HarfBuzz skips ZWNJ in context matching; 0 for none): for the first subtable that
    /// matches, its (sequence index, lookup) records are written to `records` and their count
    /// comes back; `None` when no subtable matches.
    pub fn chain_context(
        &self,
        index: u16,
        glyphs: &[u16],
        pos: usize,
        skip_marks: bool,
        ignore: u16,
        records: &mut [(u16, u16); 8],
    ) -> Option<usize> {
        let mut subs = [(0u16, 0usize); 16];
        let n = self.lookup_subtables(index, &mut subs)?;
        let d = self.data;
        let skip =
            |g: u16| (skip_marks && self.glyph_class(g) == 3) || (ignore != 0 && g == ignore);
        for &(kind, st) in &subs[..n] {
            if kind != 6 || u16_at(d, st)? != 3 {
                continue;
            }
            let n_back = u16_at(d, st + 2)? as usize;
            let back = st + 4;
            let n_in = u16_at(d, back + n_back * 2)? as usize;
            let input = back + n_back * 2 + 2;
            let n_ahead = u16_at(d, input + n_in * 2)? as usize;
            let ahead = input + n_in * 2 + 2;
            let n_rec = u16_at(d, ahead + n_ahead * 2)? as usize;
            let rec = ahead + n_ahead * 2 + 2;
            if n_in == 0 {
                continue;
            }
            // Input sequence from pos (marks skipped after the first glyph).
            let mut ok = true;
            let mut idx = pos;
            let mut last = pos;
            for k in 0..n_in {
                if k > 0 {
                    idx += 1;
                    while idx < glyphs.len() && skip(glyphs[idx]) {
                        idx += 1;
                    }
                }
                let cov = st + u16_at(d, input + k * 2)? as usize;
                if idx >= glyphs.len() || self.coverage(cov, glyphs[idx]).is_none() {
                    ok = false;
                    break;
                }
                last = idx;
            }
            if !ok {
                continue;
            }
            // Backtrack, nearest first.
            let mut idx = pos;
            for k in 0..n_back {
                let mut found = None;
                while idx > 0 {
                    idx -= 1;
                    if !skip(glyphs[idx]) {
                        found = Some(idx);
                        break;
                    }
                }
                let cov = st + u16_at(d, back + k * 2)? as usize;
                match found {
                    Some(i) if self.coverage(cov, glyphs[i]).is_some() => {}
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            let mut idx = last;
            for k in 0..n_ahead {
                idx += 1;
                while idx < glyphs.len() && skip(glyphs[idx]) {
                    idx += 1;
                }
                let cov = st + u16_at(d, ahead + k * 2)? as usize;
                if idx >= glyphs.len() || self.coverage(cov, glyphs[idx]).is_none() {
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }
            let count = n_rec.min(records.len());
            for (r, slot) in records.iter_mut().enumerate().take(count) {
                *slot = (u16_at(d, rec + r * 4)?, u16_at(d, rec + r * 4 + 2)?);
            }
            return Some(count);
        }
        None
    }

    /// The subtables of lookup `index`: (type, offset) written to `out`.
    fn lookup_subtables(&self, index: u16, out: &mut [(u16, usize); 16]) -> Option<usize> {
        let (g, _) = self.gsub?;
        let d = self.data;
        let lookup_list = g + u16_at(d, g + 8)? as usize;
        let n = u16_at(d, lookup_list)? as usize;
        if index as usize >= n {
            return None;
        }
        let l = lookup_list + u16_at(d, lookup_list + 2 + index as usize * 2)? as usize;
        let kind = u16_at(d, l)?;
        let n_sub = u16_at(d, l + 4)? as usize;
        let mut count = 0;
        for i in 0..n_sub.min(out.len()) {
            let mut st = l + u16_at(d, l + 6 + i * 2)? as usize;
            let mut k = kind;
            if k == 7 {
                // Extension: the real subtable follows a 32-bit offset.
                k = u16_at(d, st + 2)?;
                st += u32_at(d, st + 4)? as usize;
            }
            out[count] = (k, st);
            count += 1;
        }
        Some(count)
    }

    /// Single substitution (lookup type 1) of `gid` through lookup `index`.
    pub fn substitute_single(&self, index: u16, gid: u16) -> Option<u16> {
        let mut subs = [(0u16, 0usize); 16];
        let n = self.lookup_subtables(index, &mut subs)?;
        let d = self.data;
        for &(kind, st) in &subs[..n] {
            if kind != 1 {
                continue;
            }
            let format = u16_at(d, st)?;
            let cov = st + u16_at(d, st + 2)? as usize;
            let Some(ci) = self.coverage(cov, gid) else {
                continue;
            };
            return match format {
                1 => Some(gid.wrapping_add(u16_at(d, st + 4)?)),
                2 => {
                    let n = u16_at(d, st + 4)?;
                    if ci < n {
                        u16_at(d, st + 6 + ci as usize * 2)
                    } else {
                        None
                    }
                }
                _ => None,
            };
        }
        None
    }

    /// Ligature substitution (lookup type 4) starting at `glyphs[0]` through lookup
    /// `index`: `(ligature glyph, components consumed)` for the longest match.
    pub fn substitute_ligature(&self, index: u16, glyphs: &[u16]) -> Option<(u16, usize)> {
        let mut subs = [(0u16, 0usize); 16];
        let n = self.lookup_subtables(index, &mut subs)?;
        let d = self.data;
        let first = *glyphs.first()?;
        for &(kind, st) in &subs[..n] {
            if kind != 4 {
                continue;
            }
            let cov = st + u16_at(d, st + 2)? as usize;
            let Some(ci) = self.coverage(cov, first) else {
                continue;
            };
            let n_sets = u16_at(d, st + 4)?;
            if ci >= n_sets {
                continue;
            }
            let set = st + u16_at(d, st + 6 + ci as usize * 2)? as usize;
            let n_lig = u16_at(d, set)? as usize;
            let mut best: Option<(u16, usize)> = None;
            for li in 0..n_lig {
                let lig = set + u16_at(d, set + 2 + li * 2)? as usize;
                let lig_glyph = u16_at(d, lig)?;
                let comp_count = u16_at(d, lig + 2)? as usize;
                if comp_count == 0 || comp_count > glyphs.len() {
                    continue;
                }
                let mut ok = true;
                for (c, &g) in glyphs.iter().enumerate().take(comp_count).skip(1) {
                    if u16_at(d, lig + 4 + (c - 1) * 2)? != g {
                        ok = false;
                        break;
                    }
                }
                if ok && best.is_none_or(|b| comp_count > b.1) {
                    best = Some((lig_glyph, comp_count));
                }
            }
            if best.is_some() {
                return best;
            }
        }
        None
    }
}
