//! echo — the first program started from the system volume (WP-23, `/SYSTEM/ECHO.ELF`):
//! reads one message on its bootstrap channel, writes it back on the same channel and exits
//! with the message length. Failing step = exit code 0xE0.. (no bootstrap handle, read or
//! write refused).

#![no_std]
#![no_main]

libnawah::entry!(main);

fn main() -> u64 {
    let ch = libnawah::bootstrap_handle();
    if ch == 0 {
        return 0xE0;
    }
    let mut buf = [0u8; 256];
    let mut handles = [0u32; 1];
    let (n, _) = match libnawah::channel_read(ch, &mut buf, &mut handles, true) {
        Ok(r) => r,
        Err(_) => return 0xE1,
    };
    if libnawah::channel_write(ch, &buf[..n], &[]) < 0 {
        return 0xE2;
    }
    n as u64
}
