//! narrator — the text screen reader of M5 (WP-36, ui.md §3, ADR-0019 §7): registers with
//! the display service as its narrator and writes every announcement it is given (`SAY
//! <text>`: the focused window's accessibility descriptions, and which window has the focus)
//! to the kernel's diagnostic channel as `narrator|<text>`; speech comes later. The channel
//! is ASCII, so every other character is written as `\u{XXXX}`.
//!
//! Initial handle: the boot channel. Dependency: `display`.

#![no_std]
#![no_main]

use libnawah::{
    Handle, WaitEntry, ERR_PEER_CLOSED, ERR_SHOULD_WAIT, SIGNAL_PEER_CLOSED, SIGNAL_READABLE,
};

libnawah::entry!(main);

const TRACE_MAX: usize = 256;

fn wait_reply(chan: Handle, buf: &mut [u8], hs: &mut [u32]) -> Result<(usize, usize), i64> {
    loop {
        match libnawah::channel_read(chan, buf, hs, false) {
            Err(ERR_SHOULD_WAIT) => {
                let _ = libnawah::object_wait_many(
                    &[WaitEntry {
                        handle: chan,
                        signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                    }],
                    5000,
                );
            }
            other => return other,
        }
    }
}

/// `narrator|<text>` with non-ASCII characters as `\u{XXXX}` (UTF-8 decoded).
fn speak(text: &[u8]) {
    let mut out = [0u8; TRACE_MAX];
    out[..9].copy_from_slice(b"narrator|");
    let mut n = 9;
    let put = |out: &mut [u8; TRACE_MAX], n: &mut usize, b: &[u8]| {
        let k = b.len().min(TRACE_MAX - *n);
        out[*n..*n + k].copy_from_slice(&b[..k]);
        *n += k;
    };
    let mut i = 0;
    while i < text.len() {
        let b = text[i];
        if (0x20..0x7F).contains(&b) {
            put(&mut out, &mut n, &[b]);
            i += 1;
            continue;
        }
        let (len, init) = match b {
            0xC0..=0xDF => (2, u32::from(b & 0x1F)),
            0xE0..=0xEF => (3, u32::from(b & 0x0F)),
            0xF0..=0xF7 => (4, u32::from(b & 0x07)),
            _ => (1, u32::from(b)),
        };
        let mut cp = init;
        for k in 1..len {
            cp = (cp << 6) | u32::from(text.get(i + k).copied().unwrap_or(0) & 0x3F);
        }
        i += len;
        let digits = b"0123456789ABCDEF";
        let mut esc = [0u8; 10];
        esc[..3].copy_from_slice(b"\\u{");
        let mut e = 3;
        let mut started = false;
        for shift in (0..6).rev() {
            let d = ((cp >> (shift * 4)) & 0xF) as usize;
            if d != 0 || started || shift < 4 {
                started = true;
                esc[e] = digits[d];
                e += 1;
            }
        }
        esc[e] = b'}';
        put(&mut out, &mut n, &esc[..e + 1]);
    }
    libnawah::trace(&out[..n]);
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let mut buf = [0u8; 1024];
    let mut hs = [0u32; 1];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((n, _)) if buf[..n].starts_with(b"START") => {}
        _ => return 0xE1,
    }
    if libnawah::channel_write(boot, b"CONNECT display", &[]) != 0 {
        return 0xE2;
    }
    let display = match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((2, 1)) if &buf[..2] == b"OK" => hs[0],
        _ => return 0xE2,
    };
    if libnawah::channel_write(display, b"NARRATOR", &[]) != 0 {
        return 0xE3;
    }
    match wait_reply(display, &mut buf, &mut hs) {
        Ok((2, _)) if &buf[..2] == b"OK" => {}
        _ => return 0xE3,
    }
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE4;
    }
    loop {
        let entries = [
            WaitEntry {
                handle: boot,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            },
            WaitEntry {
                handle: display,
                signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
            },
        ];
        let Ok((idx, _)) = libnawah::object_wait_many(&entries, libnawah::TIMEOUT_FOREVER) else {
            return 0xE5;
        };
        let chan = if idx == 0 { boot } else { display };
        match libnawah::channel_read(chan, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                if idx == 0 {
                    if &buf[..n] == b"STOP" {
                        return 0;
                    }
                } else if let Some(text) = buf[..n].strip_prefix(b"SAY ") {
                    speak(text);
                }
            }
            Err(ERR_PEER_CLOSED) => return 0,
            Err(_) => {}
        }
    }
}
