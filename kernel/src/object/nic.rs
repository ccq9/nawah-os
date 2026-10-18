//! The network interface object (WP-27, net.md §2): the capability through which one user
//! process (the `net` service) sends and receives raw frames. The kernel creates one and hands
//! it to the service manager; READABLE is asserted while a received frame waits, and the timer
//! tick wakes the waiters it finds registered when a frame arrives.

use alloc::vec::Vec;

use crate::sync::IrqSpinLock;

pub struct NicObject {
    waiters: IrqSpinLock<Vec<u32>>,
}

impl NicObject {
    pub fn new() -> Self {
        NicObject {
            waiters: IrqSpinLock::new("nic", Vec::new()),
        }
    }

    /// READABLE while a frame waits; otherwise registers `waiter` for the next arrival.
    pub fn poll(&self, wanted: u32, waiter: Option<u32>) -> u32 {
        let readable = crate::net::rx_pending();
        let asserted = if readable {
            crate::object::channel::SIGNAL_READABLE
        } else {
            0
        };
        let hit = asserted & wanted;
        if hit == 0 {
            if let Some(tid) = waiter {
                let mut w = self.waiters.lock();
                if !w.contains(&tid) {
                    w.push(tid);
                }
            }
        }
        hit
    }

    pub fn forget_waiter(&self, tid: u32) {
        self.waiters.lock().retain(|t| *t != tid);
    }

    /// Takes the registered waiters (the tick wakes them when a frame has arrived).
    pub fn take_waiters(&self) -> Vec<u32> {
        core::mem::take(&mut *self.waiters.lock())
    }
}

impl Default for NicObject {
    fn default() -> Self {
        Self::new()
    }
}
