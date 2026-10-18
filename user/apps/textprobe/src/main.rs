//! textprobe — the text layer in the guest (WP-35, TST-M5-TEXT-GUEST): loads the shipped
//! fonts from /SYSTEM/FONTS through the file calls into VMO mappings, reproduces the sample
//! of the host tests (vectors.rs: UAX #9 lines of BidiCharacterTest, HarfBuzz's glyphs for
//! Arabic words, the host's bitmap hashes), then renders one mixed Arabic/Latin line and
//! copies it to the frame through the display object (its only initial handle). The line's
//! rectangle and the FNV-1a hash of its pixels go to the trace, so the lab compares them with
//! its screendump and with the host's rendering of the same line. Exit 0x7E when every
//! vector matched.

#![no_std]
#![no_main]

#[rustfmt::skip]
mod vectors;

use libnawah::display::pixel;
use nawah_text::bidi::{reorder, Base, Bidi, REMOVED};
use nawah_text::font::Font;
use nawah_text::layout::{rgb_hash, Fonts, Glyph, Layout};
use nawah_text::shape;

libnawah::entry!(main);

const LINE_W: usize = 640;
const LINE_H: usize = 56;
const LINE_X: usize = 100;
const LINE_Y: usize = 300;
const LINE_PX: u32 = 28;
const LINE_FG: u32 = 0xFFFFFF;
const LINE_BG: u32 = 0x202830;
/// "نواة Nawah 2026 — مرحبا بالعالم (لا إله)", paragraph direction from its first strong
/// character (right to left).
const LINE: &[u32] = &[
    0x646, 0x648, 0x627, 0x629, 0x20, 0x4E, 0x61, 0x77, 0x61, 0x68, 0x20, 0x32, 0x30, 0x32, 0x36,
    0x20, 0x2014, 0x20, 0x645, 0x631, 0x62D, 0x628, 0x627, 0x20, 0x628, 0x627, 0x644, 0x639, 0x627,
    0x644, 0x645, 0x20, 0x28, 0x644, 0x627, 0x20, 0x625, 0x644, 0x647, 0x29,
];

struct State {
    bidi: Bidi,
    layout: Layout,
    line: [u32; LINE_W * LINE_H],
    glyphs: [Glyph; 64],
}

static mut STATE: State = State {
    bidi: Bidi::new(),
    layout: Layout::new(),
    line: [0; LINE_W * LINE_H],
    glyphs: [Glyph {
        font: 0,
        gid: 0,
        x: 0,
        advance: 0,
        cluster: 0,
    }; 64],
};

struct Out {
    buf: [u8; 256],
    len: usize,
}

impl Out {
    fn put(&mut self, s: &[u8]) {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
    fn num(&mut self, v: u64) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        let mut v = v;
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&tmp[i..]);
    }
    fn hex(&mut self, v: u64) {
        let d = b"0123456789abcdef";
        for k in (0..16).rev() {
            self.put(&d[((v >> (k * 4)) & 0xF) as usize..][..1]);
        }
    }
}

/// Reads the file at `path` into a fresh VMO mapping; the bytes as a slice.
fn load(path: &[u8]) -> Result<&'static [u8], u64> {
    let st = libnawah::stat(path).map_err(|_| 0xE1u64)?;
    let size = st.size as usize;
    let vmo = libnawah::vmo_create((st.size.max(1)).next_multiple_of(4096)).map_err(|_| 0xE2u64)?;
    let addr =
        libnawah::vmo_map(vmo, libnawah::PROT_READ | libnawah::PROT_WRITE).map_err(|_| 0xE2u64)?;
    // SAFETY: the mapping is this process's, `size` bytes fit the VMO (rounded up), and it is
    // never unmapped: the slice lives as long as the process.
    let buf: &'static mut [u8] = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size) };
    let f = libnawah::open(path, libnawah::O_READ).map_err(|_| 0xE1u64)?;
    let mut total = 0;
    while total < size {
        match libnawah::read(f, &mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => return Err(0xE3),
        }
    }
    libnawah::handle_close(f);
    if total != size {
        return Err(0xE3);
    }
    Ok(buf)
}

fn main() -> u64 {
    let display = libnawah::bootstrap_handle();
    if libnawah::handle_type(display) != libnawah::object_type::DISPLAY {
        return 0xE0;
    }
    let (latin, arabic) = match (
        load(b"/SYSTEM/FONTS/NOTOSANS.TTF"),
        load(b"/SYSTEM/FONTS/NOTOARAB.TTF"),
    ) {
        (Ok(l), Ok(a)) => (l, a),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let (Some(latin), Some(arabic)) = (Font::parse(latin), Font::parse(arabic)) else {
        return 0xE4;
    };
    let fonts = Fonts { latin, arabic };
    // SAFETY: the state is taken once, here, for the life of the process.
    let st: &'static mut State = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };

    // UAX #9 sample.
    let mut bidi_ok = 0u64;
    for v in vectors::BIDI.iter() {
        let base = match v.base {
            0 => Base::Ltr,
            1 => Base::Rtl,
            _ => Base::Auto,
        };
        let mut levels = [0u8; 32];
        let n = v.text.len();
        let para = st.bidi.resolve(v.text, base, &mut levels[..n]);
        let mut order = [0u16; 32];
        let k = reorder(&levels[..n], &mut order[..n]);
        let levels_ok = levels[..n]
            .iter()
            .zip(v.levels)
            .all(|(&a, &b)| a == b || (a == REMOVED && b == 255));
        if para == v.para && levels_ok && &order[..k] == v.order {
            bidi_ok += 1;
        }
    }
    // Shaping sample.
    let mut shape_ok = 0u64;
    for v in vectors::SHAPE.iter() {
        let mut glyphs = [0u16; 32];
        let mut clusters = [0u16; 32];
        let n = shape::shape(&fonts.arabic, v.text, &mut glyphs, &mut clusters);
        if &glyphs[..n] == v.glyphs {
            shape_ok += 1;
        }
    }
    // Bitmap sample.
    let mut raster_ok = 0u64;
    for v in vectors::RASTER.iter() {
        let font = fonts.get(v.font);
        let l = &mut st.layout;
        l.outline.clear();
        if font.outline(v.gid, &mut l.outline)
            && l.raster
                .render(&l.outline, font.units_per_em, v.px, &mut l.bitmap)
            && l.bitmap.hash() == v.hash
        {
            raster_ok += 1;
        }
    }
    // The line, rendered and copied to the frame.
    let n = st.layout.render_line(
        &fonts,
        LINE,
        Base::Auto,
        LINE_PX,
        &mut st.line,
        LINE_W,
        LINE_H,
        LINE_FG,
        LINE_BG,
        &mut st.glyphs,
    );
    let hash = rgb_hash(&st.line, LINE_W, LINE_H);
    let Ok(info) = libnawah::display_info(display) else {
        return 0xE5;
    };
    let Ok(frame) = libnawah::display_map(display) else {
        return 0xE5;
    };
    let Ok(fb) = libnawah::vmo_map(frame, libnawah::PROT_READ | libnawah::PROT_WRITE) else {
        return 0xE5;
    };
    if (LINE_X + LINE_W) as u32 > info.width || (LINE_Y + LINE_H) as u32 > info.height {
        return 0xE6;
    }
    for y in 0..LINE_H {
        for x in 0..LINE_W {
            let p = (fb as *mut u32).wrapping_add((LINE_Y + y) * info.stride as usize + LINE_X + x);
            // SAFETY: inside the frame mapping (the rectangle was checked against the mode).
            unsafe { p.write_volatile(pixel(info.pixel_format, st.line[y * LINE_W + x])) };
        }
    }
    libnawah::vmo_unmap(fb);
    libnawah::handle_close(frame);
    let mut o = Out {
        buf: [0; 256],
        len: 0,
    };
    o.put(b"text|bidi=");
    o.num(bidi_ok);
    o.put(b"/");
    o.num(vectors::BIDI.len() as u64);
    o.put(b"|shape=");
    o.num(shape_ok);
    o.put(b"/");
    o.num(vectors::SHAPE.len() as u64);
    o.put(b"|raster=");
    o.num(raster_ok);
    o.put(b"/");
    o.num(vectors::RASTER.len() as u64);
    o.put(b"|glyphs=");
    o.num(n as u64);
    o.put(b"|text_rect=");
    for (i, v) in [LINE_X, LINE_Y, LINE_W, LINE_H].iter().enumerate() {
        if i > 0 {
            o.put(b",");
        }
        o.num(*v as u64);
    }
    o.put(b"|text_hash=");
    o.hex(hash);
    let len = o.len;
    libnawah::trace(&o.buf[..len]);
    let all = bidi_ok == vectors::BIDI.len() as u64
        && shape_ok == vectors::SHAPE.len() as u64
        && raster_ok == vectors::RASTER.len() as u64;
    if all {
        0x7E
    } else {
        0xEF
    }
}
