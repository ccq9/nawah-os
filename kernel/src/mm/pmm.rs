//! Physical frame allocator (4 KiB frames) built from the UEFI memory map in `BootInfo`.
//!
//! Policy (ADR-0004): free = EfiConventionalMemory only, at or above 1 MiB (the first MiB is kept
//! for the SMP trampoline and legacy regions). Everything else — loader code/data (our image and
//! its static buffers), boot-services memory (still holding the firmware page tables we run on
//! until WP-09), runtime services, ACPI, MMIO — stays reserved. One bit per frame: 1 = reserved or
//! allocated, 0 = free. The bitmap itself is carved from the first free region that fits.
//!
//! Single-CPU, interrupts disabled: no lock yet (WP-11 wraps the allocator in an irqsave lock).
//! Failure policy: exhaustion returns `None`; freeing a free frame returns an error — never a panic.

use crate::bootinfo::{BootInfo, MEM_CONVENTIONAL};
use crate::cell::BootCell;

pub const FRAME_SIZE: u64 = 4096;
const LOW_RESERVED: u64 = 1 << 20; // 1 MiB

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Frame(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PmmError {
    /// The frame is not managed by the allocator (outside the bitmap or misaligned).
    Unmanaged,
    /// The frame is already free (double free) or was never allocated.
    NotAllocated,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub managed_frames: u64,
    pub free_frames: u64,
    pub allocated_frames: u64,
    pub bitmap_frames: u64,
}

struct Pmm {
    bits: *mut u64,
    words: usize,
    /// Number of frames covered by the bitmap (frame 0 .. frames).
    frames: u64,
    free: u64,
    managed: u64,
    bitmap_frames: u64,
    hint: usize,
    ready: bool,
}

static PMM: BootCell<Pmm> = BootCell::new(Pmm {
    bits: core::ptr::null_mut(),
    words: 0,
    frames: 0,
    free: 0,
    managed: 0,
    bitmap_frames: 0,
    hint: 0,
    ready: false,
});

fn pmm() -> &'static mut Pmm {
    // SAFETY: single CPU with interrupts disabled during M2 (ADR-0004); every access to the
    // allocator state goes through this function and no reference escapes a call. WP-11 replaces
    // this with a lock before interrupts are enabled.
    unsafe { &mut *PMM.get() }
}

impl Pmm {
    fn get_bit(&self, frame: u64) -> bool {
        let (w, b) = ((frame / 64) as usize, frame % 64);
        // SAFETY: `w < words` is checked by every caller; `bits` points at a kernel-owned region
        // of `words` u64s carved in `init`.
        unsafe { (*self.bits.add(w) >> b) & 1 == 1 }
    }
    fn set_bit(&mut self, frame: u64, allocated: bool) {
        let (w, b) = ((frame / 64) as usize, frame % 64);
        // SAFETY: as in get_bit.
        unsafe {
            let p = self.bits.add(w);
            if allocated {
                *p |= 1 << b;
            } else {
                *p &= !(1 << b);
            }
        }
    }
}

/// Builds the allocator from the boot memory map. Must run once, before any allocation.
pub fn init(bi: &BootInfo) {
    let p = pmm();
    assert!(!p.ready, "pmm::init called twice");

    // Highest frame of any conventional region bounds the bitmap.
    let mut end: u64 = 0;
    for d in bi.memmap() {
        if d.typ == MEM_CONVENTIONAL {
            end = end.max(d.phys_start + d.pages * FRAME_SIZE);
        }
    }
    let frames = end / FRAME_SIZE;
    let words = frames.div_ceil(64) as usize;
    let bitmap_bytes = (words * 8) as u64;
    let bitmap_frames = bitmap_bytes.div_ceil(FRAME_SIZE);

    // Carve the bitmap from the first conventional region (>= 1 MiB) that holds it.
    let mut bitmap_at: Option<u64> = None;
    for d in bi.memmap() {
        if d.typ != MEM_CONVENTIONAL {
            continue;
        }
        let start = d.phys_start.max(LOW_RESERVED);
        let region_end = d.phys_start + d.pages * FRAME_SIZE;
        if region_end > start && region_end - start >= bitmap_frames * FRAME_SIZE {
            bitmap_at = Some(start);
            break;
        }
    }
    let bitmap_at = bitmap_at.expect("no conventional region can hold the frame bitmap");

    p.bits = bitmap_at as *mut u64;
    p.words = words;
    p.frames = frames;
    // SAFETY: the region [bitmap_at, bitmap_at + words*8) is conventional memory that nothing
    // else uses (firmware is gone, the kernel image is loader memory), identity-mapped by the
    // firmware page tables we still run on.
    unsafe { core::ptr::write_bytes(p.bits, 0xFF, words) }; // everything reserved first

    let mut managed = 0u64;
    for d in bi.memmap() {
        if d.typ != MEM_CONVENTIONAL {
            continue;
        }
        let first = (d.phys_start.max(LOW_RESERVED)) / FRAME_SIZE;
        let last = (d.phys_start + d.pages * FRAME_SIZE) / FRAME_SIZE; // exclusive
        let mut f = first;
        while f < last {
            p.set_bit(f, false);
            managed += 1;
            f += 1;
        }
    }
    // The bitmap's own frames are allocated.
    let first = bitmap_at / FRAME_SIZE;
    for f in first..first + bitmap_frames {
        p.set_bit(f, true);
    }
    p.managed = managed;
    p.free = managed - bitmap_frames;
    p.bitmap_frames = bitmap_frames;
    p.hint = 0;
    p.ready = true;
}

/// Allocates one free frame, or `None` when exhausted (never panics).
pub fn alloc_frame() -> Option<Frame> {
    let p = pmm();
    if !p.ready || p.free == 0 {
        return None;
    }
    let words = p.words;
    for i in 0..words {
        let w = (p.hint + i) % words;
        // SAFETY: w < words.
        let word = unsafe { *p.bits.add(w) };
        if word != u64::MAX {
            let bit = (!word).trailing_zeros() as u64;
            let frame = w as u64 * 64 + bit;
            if frame >= p.frames {
                continue; // padding bits past the last frame stay unused
            }
            p.set_bit(frame, true);
            p.free -= 1;
            p.hint = w;
            return Some(Frame(frame * FRAME_SIZE));
        }
    }
    None
}

/// Returns a frame to the pool. Detects double frees and unmanaged frames.
pub fn free_frame(frame: Frame) -> Result<(), PmmError> {
    let p = pmm();
    if !p.ready || !frame.0.is_multiple_of(FRAME_SIZE) {
        return Err(PmmError::Unmanaged);
    }
    let f = frame.0 / FRAME_SIZE;
    if f >= p.frames || f < LOW_RESERVED / FRAME_SIZE {
        return Err(PmmError::Unmanaged);
    }
    if !p.get_bit(f) {
        return Err(PmmError::NotAllocated);
    }
    // Reserved (non-conventional) frames are marked allocated too; refuse to free the bitmap's
    // own frames so a bogus free cannot release allocator storage.
    let bm_first = p.bits as u64 / FRAME_SIZE;
    if (bm_first..bm_first + p.bitmap_frames).contains(&f) {
        return Err(PmmError::Unmanaged);
    }
    p.set_bit(f, false);
    p.free += 1;
    p.hint = (f / 64) as usize;
    Ok(())
}

pub fn stats() -> Stats {
    let p = pmm();
    Stats {
        managed_frames: p.managed,
        free_frames: p.free,
        allocated_frames: p.managed - p.free,
        bitmap_frames: p.bitmap_frames,
    }
}

/// Writes a pattern into the frame and reads it back (the frame is identity-mapped while the
/// firmware page tables are in use; WP-09 moves this to the direct map). Test kernel helper.
#[cfg(feature = "ktest")]
pub fn probe_rw(frame: Frame) -> bool {
    let ptr = frame.0 as *mut u64;
    // SAFETY: the frame was handed out by alloc_frame, so it is conventional memory owned by the
    // caller and mapped 1:1 by the active (firmware) page tables.
    unsafe {
        ptr.write_volatile(0x5A5A_0000_0000_A5A5 ^ frame.0);
        ptr.add(511).write_volatile(frame.0);
        ptr.read_volatile() == 0x5A5A_0000_0000_A5A5 ^ frame.0
            && ptr.add(511).read_volatile() == frame.0
    }
}

/// First frame of the bitmap storage (test kernel: must be unfreeable).
#[cfg(feature = "ktest")]
pub fn bitmap_frame() -> Frame {
    Frame(pmm().bits as u64 & !(FRAME_SIZE - 1))
}
