//! The diagnostic console `diag` (WP-30, ADR-0018, shell.md): COM2 polled from the timer tick into a
//! kernel-lifetime byte object that the service manager receives as an initial handle and
//! routes to the `sh` service. Reads come from the ring (`serial_read`); writes go straight to
//! the UART from the syscall (`serial_write`), serialised by a lock, with a bounded wait per
//! byte so a stuck line never holds the kernel.

use alloc::sync::Arc;

use crate::object::bytes::{ByteObject, CONSOLE_RING};
use crate::sync::IrqSpinLock;

static SERIAL_OBJECT: IrqSpinLock<Option<Arc<ByteObject>>> =
    IrqSpinLock::new("console-object", None);
static WRITER: IrqSpinLock<()> = IrqSpinLock::new("console-writer", ());

/// The console object (created at the first call; `init` makes that call before the tick
/// can see bytes).
pub fn serial_object() -> Arc<ByteObject> {
    let mut g = SERIAL_OBJECT.lock();
    g.get_or_insert_with(|| Arc::new(ByteObject::new("console", CONSOLE_RING)))
        .clone()
}

/// Probes COM2 (loopback) and creates the object; true when the UART answered.
pub fn init() -> bool {
    let present = crate::arch::serial2::init();
    let _ = serial_object();
    present
}

pub fn present() -> bool {
    crate::arch::serial2::present()
}

/// Timer tick (CPU 0): up to 16 bytes (the UART FIFO) into the ring; waiters woken when the
/// ring was empty.
pub fn tick_poll() {
    if !present() {
        return;
    }
    let obj = SERIAL_OBJECT.lock().clone();
    let Some(obj) = obj else {
        return;
    };
    for _ in 0..16 {
        let Some(byte) = crate::arch::serial2::poll_byte() else {
            break;
        };
        for tid in obj.push(byte) {
            crate::sched::wake(tid);
        }
    }
}

/// Writes `bytes` to the UART in order; returns how many went out before the device stopped
/// draining (all of them on a healthy line).
pub fn write(bytes: &[u8]) -> usize {
    let _g = WRITER.lock();
    let mut n = 0;
    for &b in bytes {
        if !crate::arch::serial2::write_byte(b) {
            break;
        }
        n += 1;
    }
    n
}
