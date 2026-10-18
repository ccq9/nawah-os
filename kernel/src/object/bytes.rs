//! Byte-stream objects (WP-27 input.md, WP-30 shell.md): a ring of bytes the timer tick fills
//! from a device (the i8042 output buffer for `Object::Keyboard`, COM2 for `Object::Serial`),
//! read by one user process. READABLE while bytes wait; overflow drops the newest byte and
//! counts it. The variant of `Object` says which device the ring belongs to.

use alloc::vec::Vec;

use crate::sync::IrqSpinLock;

/// The largest ring (the console's); the keyboard uses the first `KBD_RING` bytes.
pub const MAX: usize = 256;
pub const KBD_RING: usize = 64;
pub const CONSOLE_RING: usize = 256;

struct Ring {
    buf: [u8; MAX],
    head: usize,
    len: usize,
    overflow: u32,
    waiters: Vec<u32>,
}

pub struct ByteObject {
    ring: IrqSpinLock<Ring>,
    cap: usize,
}

impl ByteObject {
    pub fn new(name: &'static str, cap: usize) -> Self {
        ByteObject {
            ring: IrqSpinLock::new(
                name,
                Ring {
                    buf: [0; MAX],
                    head: 0,
                    len: 0,
                    overflow: 0,
                    waiters: Vec::new(),
                },
            ),
            cap: cap.min(MAX),
        }
    }

    /// Pushes a byte (interrupt context); returns the waiters to wake when the ring was empty.
    pub fn push(&self, byte: u8) -> Vec<u32> {
        let mut r = self.ring.lock();
        if r.len == self.cap {
            r.overflow = r.overflow.saturating_add(1);
            return Vec::new();
        }
        let i = (r.head + r.len) % self.cap;
        r.buf[i] = byte;
        r.len += 1;
        if r.len == 1 {
            core::mem::take(&mut r.waiters)
        } else {
            Vec::new()
        }
    }

    /// Takes up to `out.len()` bytes; 0 when the ring is empty.
    pub fn read(&self, out: &mut [u8]) -> usize {
        let mut r = self.ring.lock();
        let n = out.len().min(r.len);
        for o in out.iter_mut().take(n) {
            *o = r.buf[r.head];
            r.head = (r.head + 1) % self.cap;
            r.len -= 1;
        }
        n
    }

    pub fn pending(&self) -> usize {
        self.ring.lock().len
    }

    pub fn overflow(&self) -> u32 {
        self.ring.lock().overflow
    }

    pub fn poll(&self, wanted: u32, waiter: Option<u32>) -> u32 {
        let mut r = self.ring.lock();
        let asserted = if r.len > 0 {
            crate::object::channel::SIGNAL_READABLE
        } else {
            0
        };
        let hit = asserted & wanted;
        if hit == 0 {
            if let Some(tid) = waiter {
                if !r.waiters.contains(&tid) {
                    r.waiters.push(tid);
                }
            }
        }
        hit
    }

    /// Removes `tid`; an emptied list gives its storage back (the object lives as long as the
    /// kernel; see `NicObject::forget_waiter`).
    pub fn forget_waiter(&self, tid: u32) {
        let mut r = self.ring.lock();
        r.waiters.retain(|t| *t != tid);
        if r.waiters.is_empty() {
            r.waiters = Vec::new();
        }
    }
}
