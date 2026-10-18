//! i8042 PS/2 controller (WP-27, ADR-0017; the auxiliary port since WP-33, ADR-0019 §4): the
//! keyboard's and the mouse's bytes are taken from the output buffer by polling the status
//! port from the timer tick (no IRQ 1/12: the I/O APIC stays masked, ADR-0005). The controller
//! is used as the firmware left it (keyboard enabled, scancode translation on: set 1 codes
//! reach the driver); the auxiliary interface is enabled at boot and the mouse is asked to
//! report its movements (stream mode, 3-byte packets).
//!
//! References: Intel 8042 / PS/2 controller register model (docs/sources.json S52): data port
//! 60h, status/command port 64h; status bit 0 output buffer full, bit 1 input buffer full,
//! bit 5 "mouse data" (auxiliary device) on PS/2-compatible controllers; a byte read from 60h
//! while bit 0 is set clears the buffer; command D4h sends the next data byte to the auxiliary
//! device; mouse commands F6h (set defaults) and F4h (enable data reporting) answer FAh.

use super::port::{inb, outb};

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const STATUS_OUTPUT_FULL: u8 = 1;
const STATUS_INPUT_FULL: u8 = 2;
const STATUS_AUX: u8 = 0x20;
/// Command: enable the auxiliary (mouse) interface.
const CMD_ENABLE_AUX: u8 = 0xA8;
/// Command: the next byte written to the data port goes to the auxiliary device.
const CMD_WRITE_AUX: u8 = 0xD4;
/// Mouse commands and its acknowledgement.
const MOUSE_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_ENABLE_REPORTING: u8 = 0xF4;
const MOUSE_ACK: u8 = 0xFA;
/// Bounded waits on the controller (status polls).
const SPIN_LIMIT: u32 = 100_000;

/// One byte from the output buffer, tagged by its source (`true` = mouse).
pub fn poll() -> Option<(u8, bool)> {
    // SAFETY: status and data ports of the controller; reading data with bit 0 set is the
    // documented way to take the byte, and has no other effect.
    let status = unsafe { inb(STATUS) };
    if status & STATUS_OUTPUT_FULL == 0 {
        return None;
    }
    // SAFETY: the data port; bit 0 of the status says a byte waits, and reading it is the
    // documented way to take it.
    let byte = unsafe { inb(DATA) };
    Some((byte, status & STATUS_AUX != 0))
}

/// Drains whatever the output buffer holds (bounded); returns the count.
fn drain() -> u32 {
    let mut drained = 0;
    while drained < 64 && poll().is_some() {
        drained += 1;
    }
    drained
}

/// Waits until the controller accepts a command/data byte (input buffer empty); false on a
/// dead controller.
fn wait_input_empty() -> bool {
    for _ in 0..SPIN_LIMIT {
        // SAFETY: the status port, read only.
        if unsafe { inb(STATUS) } & STATUS_INPUT_FULL == 0 {
            return true;
        }
    }
    false
}

/// Sends one byte to the mouse (D4h then the byte) and waits for its FAh; false when the
/// controller or the mouse does not answer within the bound (no mouse attached).
fn mouse_command(cmd: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    // SAFETY: command then data on the controller's ports, the documented way to address the
    // auxiliary device; nothing else uses the controller during boot.
    unsafe { outb(STATUS, CMD_WRITE_AUX) };
    if !wait_input_empty() {
        return false;
    }
    // SAFETY: as above.
    unsafe { outb(DATA, cmd) };
    for _ in 0..SPIN_LIMIT {
        if let Some((b, aux)) = poll() {
            if aux && b == MOUSE_ACK {
                return true;
            }
        }
    }
    false
}

/// Drains the buffer, enables the auxiliary interface and puts the mouse in stream mode
/// (defaults, then data reporting). Returns (stale bytes drained, mouse answered).
pub fn init() -> (u32, bool) {
    let drained = drain();
    if !wait_input_empty() {
        return (drained, false);
    }
    // SAFETY: the controller's command port; the command only switches the auxiliary
    // interface on.
    unsafe { outb(STATUS, CMD_ENABLE_AUX) };
    let mouse = mouse_command(MOUSE_SET_DEFAULTS) && mouse_command(MOUSE_ENABLE_REPORTING);
    drain();
    (drained, mouse)
}
