//! The display (WP-32, ADR-0019 §1, display.md part A): the linear frame buffer firmware left
//! behind (GOP, captured before ExitBootServices into `BootInfo.fb`), mapped uncacheable in
//! the kernel's MMIO window. The kernel draws one diagnostic pattern at boot — four coloured
//! corners and a bar that encodes the build id — which the lab reads back through QEMU's
//! `screendump` (tools/screen.py); it is not a desktop (OS-EXEC-AR §9). Everything else is
//! drawn by the `display` service through the display object (display.md part B).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::mmio;
use crate::bootinfo::Framebuffer;
use crate::mm::vmm;
use crate::sync::IrqSpinLock;

/// Largest frame buffer mapped (a 4096×2160 32-bit frame is 35 MiB).
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Side of the corner squares of the diagnostic pattern.
pub const CORNER: u32 = 32;
/// Cell width and height of the build-id bar (one cell per hex digit, at x = 2·CORNER).
pub const CELL: u32 = 16;

/// Pixel format codes as GOP names them.
pub const FORMAT_RGBX: u32 = 0;
pub const FORMAT_BGRX: u32 = 1;

/// The 16 colours of the build-id bar (one per hex digit), as 0x00RRGGBB.
pub const DIGIT_COLOURS: [u32; 16] = [
    0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080, 0x008080, 0xC0C0C0, 0x808080,
    0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF,
];
/// Corner colours: top-left, top-right, bottom-left, bottom-right (0x00RRGGBB).
pub const CORNER_COLOURS: [u32; 4] = [0xFF0000, 0x00FF00, 0x0000FF, 0xFFFFFF];

#[derive(Clone, Copy, Debug)]
pub struct DisplayInfo {
    pub base: u64,
    pub width: u32,
    pub height: u32,
    pub pitch_px: u32,
    pub pixel_format: u32,
    /// Bytes from the base to the end of the last line.
    pub bytes: u64,
    /// Virtual address of the base in the MMIO window.
    pub virt: u64,
}

/// The display object (display.md part A): the information the `display` service reads
/// through `display_info`; the frame itself reaches the service as a physical VMO.
pub struct DisplayObject {
    pub info: DisplayInfo,
}

static DISPLAY: IrqSpinLock<Option<DisplayInfo>> = IrqSpinLock::new("display", None);
static DISPLAY_OBJECT: IrqSpinLock<Option<Arc<DisplayObject>>> =
    IrqSpinLock::new("display-object", None);

pub fn info() -> Option<DisplayInfo> {
    *DISPLAY.lock()
}

/// The display object, created at the first call once `init` found a frame.
pub fn display_object() -> Option<Arc<DisplayObject>> {
    let info = info()?;
    let mut g = DISPLAY_OBJECT.lock();
    Some(
        g.get_or_insert_with(|| Arc::new(DisplayObject { info }))
            .clone(),
    )
}

/// VMOs over the frame that `display_map` handed out and that are still alive (held by a
/// handle or a mapping). display.md v1.5.
static FRAME_REFS: AtomicU32 = AtomicU32::new(0);
/// Times the frame was cleared because nothing held it any more (diagnostics, tests).
static CLEARS: AtomicU32 = AtomicU32::new(0);

/// A VMO over the frame was created (`display_map`).
pub fn frame_acquired() {
    FRAME_REFS.fetch_add(1, Ordering::SeqCst);
}

/// A VMO over the frame is gone. When it was the last one — the compositor exited, crashed or
/// was killed, and its process released its handles and mappings — the frame is cleared to
/// black: the last picture it drew (the user's windows) must not stay on the screen while
/// nobody draws, for instance while the session locks with the compositor down (display.md
/// v1.5; M5 pre-gate review, M5). The release runs before the process's exit is published, so
/// a restarted compositor maps the frame only after this clear. Returns whether it cleared.
pub fn frame_released() -> bool {
    if FRAME_REFS.fetch_sub(1, Ordering::SeqCst) != 1 {
        return false;
    }
    let Some(i) = info() else {
        return false;
    };
    fill(&i, 0, 0, i.width, i.height, 0x000000);
    CLEARS.fetch_add(1, Ordering::SeqCst);
    true
}

/// How many times the frame was cleared on release (read by the test kernel).
#[cfg(feature = "ktest")]
pub fn clears() -> u32 {
    CLEARS.load(Ordering::SeqCst)
}

/// Test kernel only: holds one more reference on the frame for the rest of the test, so a
/// probe's exit does not clear what the test and the lab's screendump still read
/// (TST-M5-DISPLAY-BOOT, TST-M5-TEXT-GUEST).
#[cfg(feature = "ktest")]
pub fn pin_frame() {
    frame_acquired();
}

/// Converts 0x00RRGGBB to the frame's pixel layout.
pub fn pixel(format: u32, rgb: u32) -> u32 {
    let (r, g, b) = ((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF);
    if format == FORMAT_RGBX {
        r | (g << 8) | (b << 16)
    } else {
        b | (g << 8) | (r << 16)
    }
}

/// Maps the frame firmware described (when present and sane) and draws the diagnostic
/// pattern. Returns the information line's fields: present, and the pattern's pixel count.
pub fn init(fb: &Framebuffer, build_id: &str) -> Result<Option<(DisplayInfo, u64)>, &'static str> {
    if fb.present == 0 {
        return Ok(None);
    }
    if fb.pixel_format > FORMAT_BGRX || fb.width == 0 || fb.height == 0 || fb.pitch_px < fb.width {
        return Err("K_E_DISPLAY_FORMAT");
    }
    let bytes = u64::from(fb.pitch_px) * u64::from(fb.height) * 4;
    if bytes > MAX_BYTES || fb.base == 0 {
        return Err("K_E_DISPLAY_RANGE");
    }
    let virt = vmm::map_mmio(fb.base, bytes).map_err(|_| "K_E_DISPLAY_MAP")?;
    let info = DisplayInfo {
        base: fb.base,
        width: fb.width,
        height: fb.height,
        pitch_px: fb.pitch_px,
        pixel_format: fb.pixel_format,
        bytes,
        virt,
    };
    let drawn = draw_pattern(&info, build_id);
    *DISPLAY.lock() = Some(info);
    Ok(Some((info, drawn)))
}

/// The fields of the kernel's display line for what `init` returned. A frame the kernel
/// refused (an unsupported pixel format, a geometry it cannot draw on) is no display at all:
/// `present=0` with the reason (REQ-M5-001, TST-M5-DISPLAY-BOOT).
pub fn boot_line(r: &Result<Option<(DisplayInfo, u64)>, &str>) -> alloc::string::String {
    match r {
        Ok(Some((d, drawn))) => alloc::format!(
            "present=1|w={}|h={}|stride={}|format={}|bytes={}|base={:#x}|drawn={}|corner={}|cell={}|code=ok|selfcheck=1",
            d.width, d.height, d.pitch_px, d.pixel_format, d.bytes, d.base, drawn, CORNER, CELL
        ),
        Ok(None) => alloc::string::String::from("present=0|code=ok|selfcheck=0"),
        Err(code) => alloc::format!("present=0|code={code}|selfcheck=0"),
    }
}

fn fill(info: &DisplayInfo, x0: u32, y0: u32, w: u32, h: u32, rgb: u32) -> u64 {
    let px = pixel(info.pixel_format, rgb);
    let x1 = (x0 + w).min(info.width);
    let y1 = (y0 + h).min(info.height);
    let mut n = 0;
    for y in y0..y1 {
        let line = info.virt + u64::from(y) * u64::from(info.pitch_px) * 4;
        for x in x0..x1 {
            mmio::write32(line + u64::from(x) * 4, px);
            n += 1;
        }
    }
    n
}

/// Black background, the four corners, and the build-id bar (one 16×16 cell per hex digit,
/// starting at x = 2·CORNER on the top edge); returns the pixels written.
fn draw_pattern(info: &DisplayInfo, build_id: &str) -> u64 {
    let mut n = fill(info, 0, 0, info.width, info.height, 0x000000);
    let (w, h) = (info.width, info.height);
    n += fill(info, 0, 0, CORNER, CORNER, CORNER_COLOURS[0]);
    n += fill(
        info,
        w.saturating_sub(CORNER),
        0,
        CORNER,
        CORNER,
        CORNER_COLOURS[1],
    );
    n += fill(
        info,
        0,
        h.saturating_sub(CORNER),
        CORNER,
        CORNER,
        CORNER_COLOURS[2],
    );
    n += fill(
        info,
        w.saturating_sub(CORNER),
        h.saturating_sub(CORNER),
        CORNER,
        CORNER,
        CORNER_COLOURS[3],
    );
    for (i, c) in build_id.bytes().enumerate() {
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => continue,
        };
        n += fill(
            info,
            2 * CORNER + i as u32 * CELL,
            0,
            CELL,
            CELL,
            DIGIT_COLOURS[usize::from(digit)],
        );
    }
    n
}
