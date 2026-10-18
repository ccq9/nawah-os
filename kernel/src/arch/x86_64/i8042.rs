//! i8042 PS/2 controller (WP-27, ADR-0017): the keyboard's bytes are taken from the output
//! buffer by polling the status port from the timer tick (no IRQ 1 yet: the I/O APIC stays
//! masked, ADR-0005). The controller is used as the firmware left it (keyboard enabled,
//! scancode translation on: set 1 codes reach the driver).
//!
//! References: Intel 8042 / PS/2 controller register model (docs/sources.json S52): data port
//! 60h, status/command port 64h; status bit 0 output buffer full, bit 1 input buffer full,
//! bit 5 "mouse data" (auxiliary device) on PS/2-compatible controllers; a byte read from 60h
//! while bit 0 is set clears the buffer.

use super::port::{inb, outb};

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const STATUS_OUTPUT_FULL: u8 = 1;
const STATUS_AUX: u8 = 0x20;
/// Command: disable the auxiliary (mouse) interface, so only keyboard bytes arrive.
const CMD_DISABLE_AUX: u8 = 0xA7;

/// Disables the mouse interface and drains whatever the output buffer holds; returns how many
/// stale bytes were drained (bounded).
pub fn init() -> u32 {
    // SAFETY: the controller's command and data ports; the command only switches the auxiliary
    // interface off, and the drained bytes belong to nobody yet.
    unsafe { outb(STATUS, CMD_DISABLE_AUX) };
    let mut drained = 0;
    while drained < 64 && poll_byte().is_some() {
        drained += 1;
    }
    drained
}

/// One keyboard byte if the output buffer holds one (mouse bytes are discarded).
pub fn poll_byte() -> Option<u8> {
    // SAFETY: status and data ports of the controller; reading data with bit 0 set is the
    // documented way to take the byte, and has no other effect.
    let status = unsafe { inb(STATUS) };
    if status & STATUS_OUTPUT_FULL == 0 {
        return None;
    }
    // SAFETY: the data port; bit 0 of the status says a byte waits, and reading it is the
    // documented way to take it.
    let byte = unsafe { inb(DATA) };
    if status & STATUS_AUX != 0 {
        return None;
    }
    Some(byte)
}
