//! COM1 (16550 UART, I/O port 0x3F8): the kernel's diagnostic channel. Works before and after
//! ExitBootServices because it touches hardware directly, not firmware.
//! Origin: Sol OS (d54f0a5) `serial.rs`, re-reviewed here.
//!
//! Rule: the diagnostic channel never hangs the kernel. If the device is absent or stops
//! answering, bytes are dropped.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use super::port::{inb, outb};

const COM1: u16 = 0x3F8;
const DATA: u16 = COM1;
const INTERRUPT_ENABLE: u16 = COM1 + 1;
const FIFO_CONTROL: u16 = COM1 + 2;
const LINE_CONTROL: u16 = COM1 + 3;
const MODEM_CONTROL: u16 = COM1 + 4;
const LINE_STATUS: u16 = COM1 + 5;

/// Line status: received byte ready.
const LSR_DATA_READY: u8 = 0x01;
/// Line status: transmit holding register empty.
const LSR_TX_EMPTY: u8 = 0x20;
/// Modem control: DTR, RTS, OUT2.
const MCR_NORMAL: u8 = 0x0B;
/// Modem control: internal loopback (bit 4) with RTS, OUT1, OUT2.
const MCR_LOOPBACK: u8 = 0x1E;
const PROBE_BYTE: u8 = 0xAE;
/// Bounded wait before a byte is dropped: never spin forever on a dead device.
const SPIN_LIMIT: u32 = 100_000;

/// Set once in `init` when the loopback probe succeeds.
static PRESENT: AtomicBool = AtomicBool::new(false);

/// Stateless handle for COM1. No lock: single execution path in this stage.
pub struct Serial;

impl Serial {
    /// 115200 baud, 8N1; then a loopback probe decides whether the device exists.
    pub fn init() {
        // SAFETY: ports COM1..COM1+5 belong to the 16550 alone; single execution path, no one
        // else touches the device at this stage.
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
        PRESENT.store(echoed == Some(PROBE_BYTE), Ordering::Relaxed);
    }

    fn write_byte(byte: u8) {
        if !PRESENT.load(Ordering::Relaxed) {
            return;
        }
        for _ in 0..SPIN_LIMIT {
            // SAFETY: status read then one data write on a device whose presence `init` proved;
            // no other code shares the device.
            unsafe {
                if inb(LINE_STATUS) & LSR_TX_EMPTY != 0 {
                    outb(DATA, byte);
                    return;
                }
            }
        }
    }
}

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            Self::write_byte(b);
        }
        Ok(())
    }
}
