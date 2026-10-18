//! kbdprobe — the user side of the keyboard (WP-27, TST-M4-KBD-SCANCODES): with the keyboard
//! handle as its bootstrap handle it waits for READABLE and collects six scancode bytes (the
//! lab injects a, b and Enter through the QEMU monitor: make and break codes of set 1), then
//! exits with the bytes packed little-endian into the exit code. Failing step 0xE0.. (the
//! bytes never arrived: 0xE3).

#![no_std]
#![no_main]

use libnawah::{WaitEntry, ERR_SHOULD_WAIT, SIGNAL_READABLE};

libnawah::entry!(main);

const WANT: usize = 6;

fn main() -> u64 {
    let kbd = libnawah::bootstrap_handle();
    if kbd == 0 || libnawah::handle_type(kbd) != libnawah::object_type::KEYBOARD {
        return 0xE0;
    }
    let mut bytes = [0u8; 8];
    let mut n = 0;
    let deadline = libnawah::clock_ticks() + 20_000;
    while n < WANT && libnawah::clock_ticks() < deadline {
        if libnawah::object_wait_many(
            &[WaitEntry {
                handle: kbd,
                signals: SIGNAL_READABLE,
            }],
            500,
        )
        .is_err()
        {
            continue;
        }
        let mut chunk = [0u8; 8];
        match libnawah::kbd_read(kbd, &mut chunk) {
            Ok(k) => {
                for &b in &chunk[..k] {
                    if n < WANT {
                        bytes[n] = b;
                        n += 1;
                    }
                }
            }
            Err(ERR_SHOULD_WAIT) => {}
            Err(_) => return 0xE1,
        }
    }
    if n < WANT {
        return 0xE3;
    }
    u64::from_le_bytes(bytes) & 0xFFFF_FFFF_FFFF
}
