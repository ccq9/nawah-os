//! The keyboard object (WP-27, input.md): a ring of scancode bytes the timer tick fills from
//! the i8042 output buffer, read by one user process (the `input` service, or the console of
//! M5). READABLE while bytes wait; overflow drops the newest byte and counts it.

use alloc::vec::Vec;

use crate::sync::IrqSpinLock;

pub const RING: usize = 64;

struct Ring {
    buf: [u8; RING],
    head: usize,
    len: usize,
    overflow: u32,
    waiters: Vec<u32>,
}

pub struct KeyboardObject {
    ring: IrqSpinLock<Ring>,
}

impl KeyboardObject {
    pub fn new() -> Self {
        KeyboardObject {
            ring: IrqSpinLock::new(
                "kbd",
                Ring {
                    buf: [0; RING],
                    head: 0,
                    len: 0,
                    overflow: 0,
                    waiters: Vec::new(),
                },
            ),
        }
    }

    /// Pushes a byte (interrupt context); returns the waiters to wake when the ring was empty.
    pub fn push(&self, byte: u8) -> Vec<u32> {
        let mut r = self.ring.lock();
        if r.len == RING {
            r.overflow = r.overflow.saturating_add(1);
            return Vec::new();
        }
        let i = (r.head + r.len) % RING;
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
            r.head = (r.head + 1) % RING;
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

    pub fn forget_waiter(&self, tid: u32) {
        self.ring.lock().waiters.retain(|t| *t != tid);
    }
}

impl Default for KeyboardObject {
    fn default() -> Self {
        Self::new()
    }
}
