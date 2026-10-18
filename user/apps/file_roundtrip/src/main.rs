//! file_roundtrip (WP-19, TST-M3-FILE-ROUNDTRIP): create a file, write it in two pieces, close,
//! reopen read-only, read it back, stat it, then rewrite from an offset and verify; exit 0x60
//! on success, else the failing step.

#![no_std]
#![no_main]

use libnawah::{O_CREATE, O_READ, O_TRUNCATE, O_WRITE};

libnawah::entry!(main);

const PATH: &[u8] = b"/APP.TXT";
const PART1: &[u8] = b"written by file_roundtrip: ";
const PART2: &[u8] = b"second part\n";

fn main() -> u64 {
    let Ok(h) = libnawah::open(PATH, O_READ | O_WRITE | O_CREATE | O_TRUNCATE) else {
        return 1;
    };
    if libnawah::write(h, PART1) != Ok(PART1.len()) {
        return 2;
    }
    if libnawah::write(h, PART2) != Ok(PART2.len()) {
        return 3;
    }
    if libnawah::handle_close(h) != 0 {
        return 4;
    }
    let Ok(r) = libnawah::open(PATH, O_READ) else {
        return 5;
    };
    let mut buf = [0u8; 64];
    let total = PART1.len() + PART2.len();
    if libnawah::read(r, &mut buf) != Ok(total) {
        return 6;
    }
    if &buf[..PART1.len()] != PART1 || &buf[PART1.len()..total] != PART2 {
        return 7;
    }
    if libnawah::read(r, &mut buf) != Ok(0) {
        return 8;
    }
    // A read-only handle cannot write.
    if libnawah::write(r, b"x") != Err(libnawah::ERR_ACCESS) {
        return 9;
    }
    match libnawah::stat(PATH) {
        Ok(st) if st.size == total as u64 && !st.is_dir => {}
        _ => return 10,
    }
    if libnawah::handle_close(r) != 0 {
        return 11;
    }
    // Overwrite in the middle through seek, then verify.
    let Ok(w) = libnawah::open(PATH, O_READ | O_WRITE) else {
        return 12;
    };
    if libnawah::seek(w, 11) != 11 || libnawah::write(w, b"BY") != Ok(2) {
        return 13;
    }
    if libnawah::seek(w, 0) != 0 || libnawah::read(w, &mut buf) != Ok(total) {
        return 14;
    }
    if &buf[11..13] != b"BY" || buf[13..PART1.len()] != PART1[13..] {
        return 15;
    }
    if libnawah::handle_close(w) != 0 || libnawah::sync() != 0 {
        return 16;
    }
    libnawah::trace(b"file roundtrip ok");
    0x60
}
