//! Kernel heap (WP-13, ADR-0007): a slab allocator for small blocks and whole frames for large
//! ones, all reached through the direct map, behind an irqsave lock. Registered as the global
//! allocator so `alloc::{boxed, vec, collections}` work in the kernel.
//!
//! Small blocks: eight power-of-two classes (16..=2048 bytes). Each slab page is one 4 KiB frame
//! with a header at its start and an intrusive free list of block indices; a class keeps a
//! doubly linked list of pages that still have a free block. A page whose blocks are all free
//! goes back to the frame allocator at once, so the heap never hoards memory and a leak shows up
//! as a frame-count difference.
//!
//! Large blocks (> 2048 bytes, or alignment > their class): `n` physically contiguous frames
//! (contiguous in the direct map too). Alignment above 4 KiB is not offered; a request for it
//! fails like exhaustion does.
//!
//! Failure policy (docs/policies/panic.md §3): exhaustion returns null from `alloc`; the `alloc`
//! crate turns that into a panic at the call site that could not continue (handle_alloc_error),
//! which is the documented behaviour for the kernel's own infallible allocations. Code that must
//! survive exhaustion uses the fallible `try_*` constructors.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::arch::paging::DIRECT_MAP_BASE;
use crate::mm::pmm::{self, Frame, FRAME_SIZE};
use crate::mm::vmm;
use crate::sync::IrqSpinLock;

const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
const MAX_SMALL: usize = 2048;
const PAGE: usize = FRAME_SIZE as usize;
const NONE: u16 = u16::MAX;

/// Slab page header, at the start of the page (24 bytes; blocks start at `first_block`).
#[repr(C)]
struct PageHeader {
    class: u8,
    _pad: u8,
    free_count: u16,
    total: u16,
    free_head: u16,
    next: *mut PageHeader,
    prev: *mut PageHeader,
}

const _: () = assert!(core::mem::size_of::<PageHeader>() == 24);

const fn first_block(class: usize) -> usize {
    if class < 32 {
        32
    } else {
        class
    }
}

const fn blocks_per_page(class: usize) -> usize {
    (PAGE - first_block(class)) / class
}

struct ClassList {
    partial: *mut PageHeader,
    pages: u64,
}

struct Heap {
    classes: [ClassList; 8],
    live_blocks: u64,
    live_bytes: u64,
    large_frames: u64,
    ready: bool,
}

// SAFETY: the raw pointers address direct-map memory the heap owns; all access is under the lock.
unsafe impl Send for Heap {}

static HEAP: IrqSpinLock<Heap> = IrqSpinLock::new(
    "heap",
    Heap {
        classes: [const {
            ClassList {
                partial: ptr::null_mut(),
                pages: 0,
            }
        }; 8],
        live_blocks: 0,
        live_bytes: 0,
        large_frames: 0,
        ready: false,
    },
);

fn class_index(size: usize, align: usize) -> Option<usize> {
    let need = size.max(align).max(1);
    if need > MAX_SMALL {
        return None;
    }
    CLASSES.iter().position(|&c| c >= need)
}

impl Heap {
    /// Takes a block from class `ci`, growing the class by one page when needed.
    fn alloc_small(&mut self, ci: usize) -> *mut u8 {
        let class = CLASSES[ci];
        if self.classes[ci].partial.is_null() {
            let Some(f) = pmm::alloc_frame() else {
                return ptr::null_mut();
            };
            let page = vmm::direct(f.0) as *mut PageHeader;
            let total = blocks_per_page(class) as u16;
            // SAFETY: a fresh frame mapped in the direct map, owned by the heap from now on.
            unsafe {
                page.write(PageHeader {
                    class: ci as u8,
                    _pad: 0,
                    free_count: total,
                    total,
                    free_head: 0,
                    next: ptr::null_mut(),
                    prev: ptr::null_mut(),
                });
                // Thread the free list through the blocks: block i -> i + 1, last -> NONE.
                let base = (page as *mut u8).add(first_block(class));
                for i in 0..total {
                    let next = if i + 1 == total { NONE } else { i + 1 };
                    base.add(usize::from(i) * class).cast::<u16>().write(next);
                }
            }
            self.classes[ci].partial = page;
            self.classes[ci].pages += 1;
        }
        let page = self.classes[ci].partial;
        // SAFETY: `page` is a slab page header the heap owns, with at least one free block.
        unsafe {
            let h = &mut *page;
            let idx = h.free_head;
            let block = (page as *mut u8).add(first_block(class) + usize::from(idx) * class);
            h.free_head = block.cast::<u16>().read();
            h.free_count -= 1;
            if h.free_count == 0 {
                // Full: leave the partial list.
                self.classes[ci].partial = h.next;
                if !h.next.is_null() {
                    (*h.next).prev = ptr::null_mut();
                }
                h.next = ptr::null_mut();
            }
            self.live_blocks += 1;
            self.live_bytes += class as u64;
            block
        }
    }

    fn free_small(&mut self, p: *mut u8, ci: usize) {
        let class = CLASSES[ci];
        let page = ((p as usize) & !(PAGE - 1)) as *mut PageHeader;
        // SAFETY: `p` came from alloc_small of this class, so its page is a slab page the heap
        // owns and the header is intact.
        unsafe {
            let h = &mut *page;
            debug_assert_eq!(
                usize::from(h.class),
                ci,
                "heap: block freed with the wrong class"
            );
            let idx = ((p as usize - page as usize - first_block(class)) / class) as u16;
            p.cast::<u16>().write(h.free_head);
            h.free_head = idx;
            h.free_count += 1;
            self.live_blocks -= 1;
            self.live_bytes -= class as u64;
            if h.free_count == 1 {
                // Was full: back onto the partial list (at the head).
                h.prev = ptr::null_mut();
                h.next = self.classes[ci].partial;
                if !h.next.is_null() {
                    (*h.next).prev = page;
                }
                self.classes[ci].partial = page;
            }
            if h.free_count == h.total {
                // Empty: unlink and return the frame.
                if !h.prev.is_null() {
                    (*h.prev).next = h.next;
                } else {
                    self.classes[ci].partial = h.next;
                }
                if !h.next.is_null() {
                    (*h.next).prev = h.prev;
                }
                self.classes[ci].pages -= 1;
                let phys = page as u64 - DIRECT_MAP_BASE;
                let _ = pmm::free_frame(Frame(phys));
            }
        }
    }

    fn alloc_large(&mut self, size: usize, align: usize) -> *mut u8 {
        if align > PAGE {
            return ptr::null_mut();
        }
        let n = size.div_ceil(PAGE) as u64;
        match pmm::alloc_frames(n) {
            Some(f) => {
                self.large_frames += n;
                self.live_blocks += 1;
                self.live_bytes += n * FRAME_SIZE;
                vmm::direct(f.0) as *mut u8
            }
            None => ptr::null_mut(),
        }
    }

    fn free_large(&mut self, p: *mut u8, size: usize) {
        let n = size.div_ceil(PAGE) as u64;
        let phys = p as u64 - DIRECT_MAP_BASE;
        let _ = pmm::free_frames(Frame(phys), n);
        self.large_frames -= n;
        self.live_blocks -= 1;
        self.live_bytes -= n * FRAME_SIZE;
    }
}

pub struct KernelHeap;

// SAFETY: every allocation hands out memory nobody else owns (fresh frames through the direct
// map), blocks never overlap, and `dealloc` is only given pointers from `alloc` with the same
// layout (GlobalAlloc contract), which selects the same class or frame count.
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut h = HEAP.lock();
        if !h.ready {
            return ptr::null_mut();
        }
        match class_index(layout.size(), layout.align()) {
            Some(ci) => h.alloc_small(ci),
            None => h.alloc_large(layout.size(), layout.align()),
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        let mut h = HEAP.lock();
        match class_index(layout.size(), layout.align()) {
            Some(ci) => h.free_small(p, ci),
            None => h.free_large(p, layout.size()),
        }
    }
}

#[global_allocator]
static GLOBAL: KernelHeap = KernelHeap;

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub live_blocks: u64,
    pub live_bytes: u64,
    pub slab_pages: u64,
    pub large_frames: u64,
}

/// Opens the heap: nothing is pre-allocated; the first allocation takes a frame.
pub fn init() {
    HEAP.lock().ready = true;
}

pub fn stats() -> Stats {
    let h = HEAP.lock();
    Stats {
        live_blocks: h.live_blocks,
        live_bytes: h.live_bytes,
        slab_pages: h.classes.iter().map(|c| c.pages).sum(),
        large_frames: h.large_frames,
    }
}
