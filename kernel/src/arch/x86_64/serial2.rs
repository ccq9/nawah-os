//! COM2 (16550 UART, I/O port 0x2F8): the diagnostic console channel of the `sh` service
//! (WP-30, ADR-0018, shell.md). Polled from the timer tick like the keyboard (ADR-0017), no
//! interrupts. The kernel never prints here: it only moves bytes between the UART and the
//! console object. Rule as for COM1: a dead or absent device never hangs the kernel.

use core::sync::atomic::{AtomicBool, Ordering};

use super::port::{inb, outb};

const COM2: u16 = 0x2F8;
const DATA: u16 = COM2;
const INTERRUPT_ENABLE: u16 = COM2 + 1;
const FIFO_CONTROL: u16 = COM2 + 2;
const LINE_CONTROL: u16 = COM2 + 3;
const MODEM_CONTROL: u16 = COM2 + 4;
const LINE_STATUS: u16 = COM2 + 5;

/// Line status: received byte ready.
const LSR_DATA_READY: u8 = 0x01;
/// Line status: transmit holding register empty.
const LSR_TX_EMPTY: u8 = 0x20;
/// Modem control: DTR, RTS, OUT2.
const MCR_NORMAL: u8 = 0x0B;
/// Modem control: internal loopback (bit 4) with RTS, OUT1, OUT2.
const MCR_LOOPBACK: u8 = 0x1E;
const PROBE_BYTE: u8 = 0x5A;
/// Bounded wait before a byte is dropped.
const SPIN_LIMIT: u32 = 100_000;

/// Set once in `init` when the loopback probe succeeds.
static PRESENT: AtomicBool = AtomicBool::new(false);

/// 115200 baud, 8N1, FIFO on; the loopback probe decides whether the device exists.
pub fn init() -> bool {
    // SAFETY: ports COM2..COM2+5 belong to the second 16550 alone; single execution path
    // during boot, nothing else touches the device.
    let echoed = unsafe {
        outb(INTERRUPT_ENABLE, 0x00);
        outb(LINE_CONTROL, 0x80); // DLAB on
        outb(DATA, 0x01); // divisor 1 -> 115200
        outb(INTERRUPT_ENABLE, 0x00);
        outb(LINE_CONTROL, 0x03); // 8N1, DLAB off
        outb(FIFO_CONTROL, 0xC7); // FIFO on, cleared
        outb(MODEM_CONTROL, MCR_LOOPBACK);
        outb(DATA, PROBE_BYTE);
        let mut echoed = None;
        for _ in 0..SPIN_LIMIT {
            if inb(LINE_STATUS) & LSR_DATA_READY != 0 {
                echoed = Some(inb(DATA));
                break;
            }
        }
        outb(MODEM_CONTROL, MCR_NORMAL);
        echoed
    };
    let present = echoed == Some(PROBE_BYTE);
    PRESENT.store(present, Ordering::Relaxed);
    present
}

pub fn present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

/// One received byte, if any waits (timer tick, CPU 0).
pub fn poll_byte() -> Option<u8> {
    if !present() {
        return None;
    }
    // SAFETY: status read then one data read on a device whose presence `init` proved; the
    // tick on CPU 0 is the only reader.
    unsafe {
        if inb(LINE_STATUS) & LSR_DATA_READY != 0 {
            Some(inb(DATA))
        } else {
            None
        }
    }
}

/// Writes one byte once the holding register is empty; false when the device is absent or
/// did not drain within the bound (the byte is not written).
pub fn write_byte(byte: u8) -> bool {
    if !present() {
        return false;
    }
    for _ in 0..SPIN_LIMIT {
        // SAFETY: status read then one data write on a device whose presence `init` proved;
        // writers are serialised by the console lock.
        unsafe {
            if inb(LINE_STATUS) & LSR_TX_EMPTY != 0 {
                outb(DATA, byte);
                return true;
            }
        }
    }
    false
}
