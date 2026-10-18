//! Interrupt-safe spinlock (ADR-0006). `lock()` disables interrupts on this CPU, acquires, and
//! the guard restores the previous interrupt state when dropped, so a lock can be taken from
//! thread context and (later) from interrupt context without a lost-wakeup or a self-deadlock
//! through an interrupt. Re-acquiring a lock this CPU already holds is a programming error that
//! would hang forever; it is detected and turned into a panic (`K_E_LOCK_REENTRY`).
//!
//! The holder is recorded as `cpu_id + 1`; since WP-20 `arch::cpu_id` is the real CPU index and
//! the spin loop calls `arch::spin_hint` (ADR-0015 §8).

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch;

const FREE: u32 = 0;

pub struct IrqSpinLock<T> {
    name: &'static str,
    /// FREE, or holder cpu_id + 1.
    holder: AtomicU32,
    data: UnsafeCell<T>,
}

// SAFETY: the data is reachable only through a guard, and a guard exists only while this CPU
// holds the lock with interrupts disabled; other CPUs spin on `holder`.
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

pub struct IrqGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    interrupts_were_enabled: bool,
}

impl<T> IrqSpinLock<T> {
    pub const fn new(name: &'static str, value: T) -> Self {
        Self {
            name,
            holder: AtomicU32::new(FREE),
            data: UnsafeCell::new(value),
        }
    }

    fn me() -> u32 {
        arch::cpu_id() + 1
    }

    /// Disables interrupts and acquires the lock; spins while another CPU holds it; panics if
    /// this CPU already holds it (re-entry = certain deadlock).
    pub fn lock(&self) -> IrqGuard<'_, T> {
        let interrupts_were_enabled = arch::interrupts::save_and_disable();
        let me = Self::me();
        loop {
            match self
                .holder
                .compare_exchange_weak(FREE, me, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(holder) if holder == me => {
                    panic!("K_E_LOCK_REENTRY|lock={}|cpu={}", self.name, me - 1)
                }
                // Another CPU holds it: wait, serving TLB-shootdown requests meanwhile so a
                // holder that waits for this CPU's acknowledgement is not waited on in turn.
                Err(_) => arch::spin_hint(),
            }
        }
        IrqGuard {
            lock: self,
            interrupts_were_enabled,
        }
    }

    /// Acquires without spinning: `None` if anyone (including this CPU) holds the lock.
    /// Interrupts are left as they were when it fails. Test kernel for now; M3 gives it callers.
    #[cfg(feature = "ktest")]
    pub fn try_lock(&self) -> Option<IrqGuard<'_, T>> {
        let interrupts_were_enabled = arch::interrupts::save_and_disable();
        match self
            .holder
            .compare_exchange(FREE, Self::me(), Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => Some(IrqGuard {
                lock: self,
                interrupts_were_enabled,
            }),
            Err(_) => {
                arch::interrupts::restore(interrupts_were_enabled);
                None
            }
        }
    }

    /// Whether some CPU holds the lock right now (diagnostics).
    pub fn is_locked(&self) -> bool {
        self.holder.load(Ordering::Relaxed) != FREE
    }

    /// Breaks the lock without a guard, for a path that never returns (panic, fatal exception)
    /// and must print even if the interrupted code held the console.
    ///
    /// # Safety
    /// The caller must never return to the code that held the lock, and must not rely on the
    /// protected data being consistent.
    pub unsafe fn force_unlock(&self) {
        self.holder.store(FREE, Ordering::Release);
    }
}

impl<T> Deref for IrqGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves this CPU holds the lock with interrupts disabled; no other
        // reference to the data exists.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, with the guard borrowed mutably.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for IrqGuard<'_, T> {
    fn drop(&mut self) {
        // Release first, then restore IF: an interrupt taken after this point finds the lock
        // free.
        self.lock.holder.store(FREE, Ordering::Release);
        arch::interrupts::restore(self.interrupts_were_enabled);
    }
}
