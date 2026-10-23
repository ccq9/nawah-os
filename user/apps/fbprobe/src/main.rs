//! fbprobe — the user side of the display (WP-32, TST-M5-DISPLAY-BOOT): with the display
//! handle as its bootstrap handle it reads the description, maps the frame buffer through a
//! physical VMO (`display_map` + `vmo_map`), paints a 64×64 magenta square at (96, 96) and a
//! 64×64 cyan one at (192, 96) straight into the frame, reads them back through the mapping,
//! probes the refusals (a read-only mapping cannot be written to by the kernel on the
//! process's behalf, an unmapped address is refused, a channel is not a VMO) and unmaps. Then
//! (WP-42, REQ-M5-001) nothing may land past the frame: it maps the frame once more — the last
//! mapping, so the page after it is not mapped — has the kernel write a record across its end
//! (refused with ERR_FAULT, the frame's last pixels untouched), traces `fbprobe|bounds|…|end=`
//! with the first address past the frame, and writes a pixel there: the page fault ends the
//! process (exit 0x10000 + 14), which the test expects. The lab's screendump then shows the
//! squares. Failing step 0xE0..0xF3 is the exit code.
//!
//! The frame is written through volatile pointer accesses: it is device memory the
//! compositor will own in WP-34; here the kernel's own pattern stays around the squares.

#![no_std]
#![no_main]

use libnawah::{
    object_type, ERR_ACCESS, ERR_FAULT, ERR_INVALID, ERR_WRONG_TYPE, PROT_READ, PROT_WRITE,
};

libnawah::entry!(main);

const SQUARE: u32 = 64;
const MAGENTA: u32 = 0xFF00FF;
const CYAN: u32 = 0x00FFFF;

fn pixel(format: u32, rgb: u32) -> u32 {
    let (r, g, b) = ((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF);
    if format == 0 {
        r | (g << 8) | (b << 16)
    } else {
        b | (g << 8) | (r << 16)
    }
}

fn paint(base: u64, info: &libnawah::DisplayInfo, x0: u32, y0: u32, rgb: u32) -> bool {
    let px = pixel(info.pixel_format, rgb);
    for y in y0..y0 + SQUARE {
        for x in x0..x0 + SQUARE {
            let addr = base + (u64::from(y) * u64::from(info.stride) + u64::from(x)) * 4;
            // SAFETY: inside the mapping the kernel returned (stride × height × 4 bytes), a
            // 4-byte aligned pixel; device memory, hence volatile.
            unsafe { (addr as *mut u32).write_volatile(px) };
        }
    }
    // Read back the centre of the square through the same mapping.
    let c = base
        + (u64::from(y0 + SQUARE / 2) * u64::from(info.stride) + u64::from(x0 + SQUARE / 2)) * 4;
    // SAFETY: as above.
    unsafe { (c as *const u32).read_volatile() == px }
}

fn main() -> u64 {
    let display = libnawah::bootstrap_handle();
    if display == 0 || libnawah::handle_type(display) != object_type::DISPLAY {
        return 0xE0;
    }
    let Ok(info) = libnawah::display_info(display) else {
        return 0xE1;
    };
    if info.width < 320 || info.height < 240 || info.stride < info.width || info.pixel_format > 1 {
        return 0xE2;
    }
    let Ok(vmo) = libnawah::display_map(display) else {
        return 0xE3;
    };
    if libnawah::handle_type(vmo) != object_type::VMO {
        return 0xE4;
    }
    let Ok(base) = libnawah::vmo_map(vmo, PROT_READ | PROT_WRITE) else {
        return 0xE5;
    };
    if !paint(base, &info, 96, 96, MAGENTA) || !paint(base, &info, 192, 96, CYAN) {
        return 0xE6;
    }
    // A second, read-only mapping of the same object sees the paint.
    let Ok(ro) = libnawah::vmo_map(vmo, PROT_READ) else {
        return 0xE7;
    };
    let centre =
        ro + (u64::from(96 + SQUARE / 2) * u64::from(info.stride) + u64::from(96 + SQUARE / 2)) * 4;
    // SAFETY: inside the read-only mapping; volatile device memory.
    if unsafe { (centre as *const u32).read_volatile() } != pixel(info.pixel_format, MAGENTA) {
        return 0xE8;
    }
    // Refusals: a handle without WRITE cannot be mapped writable; a bad protection; a
    // channel is not a VMO; an address that is not a mapping cannot be unmapped.
    let Ok(ro_handle) =
        libnawah::handle_duplicate(vmo, libnawah::rights::READ | libnawah::rights::MAP)
    else {
        return 0xE9;
    };
    if libnawah::vmo_map(ro_handle, PROT_READ | PROT_WRITE) != Err(ERR_ACCESS) {
        return 0xEA;
    }
    if libnawah::vmo_map(vmo, 0) != Err(ERR_INVALID)
        || libnawah::vmo_map(vmo, 4) != Err(ERR_INVALID)
    {
        return 0xEB;
    }
    let Ok((a, b)) = libnawah::channel_create() else {
        return 0xEC;
    };
    if libnawah::vmo_map(a, PROT_READ) != Err(ERR_WRONG_TYPE) {
        return 0xED;
    }
    libnawah::handle_close(a);
    libnawah::handle_close(b);
    if libnawah::vmo_unmap(base + 4096) != ERR_INVALID {
        return 0xEE;
    }
    if libnawah::vmo_unmap(ro) != 0
        || libnawah::vmo_unmap(base) != 0
        || libnawah::vmo_unmap(base) != ERR_INVALID
    {
        return 0xEF;
    }
    libnawah::handle_close(ro_handle);
    bounds(display, &info, vmo)
}

/// The frame's end (REQ-M5-001): returns only through a failing step; success is the fault.
fn bounds(display: libnawah::Handle, info: &libnawah::DisplayInfo, vmo: libnawah::Handle) -> u64 {
    let Ok(base) = libnawah::vmo_map(vmo, PROT_READ | PROT_WRITE) else {
        return 0xF0;
    };
    let end = base + u64::from(info.stride) * u64::from(info.height) * 4;
    // The display record is 32 bytes: half of it would land past the frame.
    let tail = end - 16;
    let last = |a: u64| {
        // SAFETY: the last 16 bytes of the mapping; volatile device memory.
        unsafe { [0, 4, 8, 12].map(|o| ((a + o) as *const u32).read_volatile()) }
    };
    let before = last(tail);
    let r = libnawah::syscall6(
        libnawah::SYS_DISPLAY_INFO,
        u64::from(display),
        tail,
        0,
        0,
        0,
        0,
    );
    if r != ERR_FAULT {
        return 0xF1;
    }
    if last(tail) != before {
        return 0xF2;
    }
    let mut line = [0u8; 64];
    let head = b"fbprobe|bounds|kernel_write=refused|end=0x";
    line[..head.len()].copy_from_slice(head);
    let mut n = head.len();
    let digits = (64 - end.leading_zeros()).div_ceil(4).max(1);
    for i in (0..digits).rev() {
        line[n] = b"0123456789abcdef"[((end >> (i * 4)) & 0xF) as usize];
        n += 1;
    }
    libnawah::trace(&line[..n]);
    // SAFETY: deliberately the first address past the mapping, which is not mapped: the MMU
    // refuses the write and the kernel ends this process. Nothing follows.
    unsafe { (end as *mut u32).write_volatile(pixel(info.pixel_format, MAGENTA)) };
    0xF3
}
