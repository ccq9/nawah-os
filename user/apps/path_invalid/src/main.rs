//! path_invalid (WP-19, TST-M3-PATH-INVALID): every documented refusal of the file calls, with
//! nothing created; exit 0x61 on success, else the failing step.

#![no_std]
#![no_main]

use libnawah::*;

libnawah::entry!(main);

/// A readable handle for the read-only-buffer probe (opened once, leaked on purpose: the
/// process exit must close it — fd_leak covers that path too).
fn h_ro_probe() -> u32 {
    open(b"/HELLO.TXT", O_READ).unwrap_or_default()
}

fn main() -> u64 {
    if open(b"/NOPE.TXT", O_READ) != Err(ERR_NOT_FOUND) {
        return 1;
    }
    if open(b"RELATIVE.TXT", O_READ) != Err(ERR_BAD_PATH) {
        return 2;
    }
    if open(b"/toolongname.txt", O_READ) != Err(ERR_BAD_PATH) {
        return 3;
    }
    if open(b"/DIR", O_READ) != Err(ERR_IS_DIR) {
        return 4;
    }
    if open(b"/HELLO.TXT/X.TXT", O_READ) != Err(ERR_NOT_DIR) {
        return 5;
    }
    if open(b"/HELLO.TXT", 0) != Err(ERR_INVALID) {
        return 6;
    }
    // An unknown flag bit is refused even next to a valid one (mutant M49 would accept it).
    if open(b"/HELLO.TXT", O_READ | 0x40) != Err(ERR_INVALID) {
        return 7;
    }
    if open(b"/NODIR/X.TXT", O_READ | O_WRITE | O_CREATE) != Err(ERR_NOT_FOUND) {
        return 8;
    }
    if stat(b"/MISSING.TXT") != Err(ERR_NOT_FOUND) {
        return 9;
    }
    if unlink(b"/DIR") != ERR_IS_DIR {
        return 10;
    }
    if unlink(b"/MISSING.TXT") != ERR_NOT_FOUND {
        return 11;
    }
    // An empty path, a path with a NUL and an overlong path.
    if open(b"", O_READ) != Err(ERR_BAD_PATH) {
        return 12;
    }
    if open(b"/HEL\0O.TXT", O_READ) != Err(ERR_BAD_PATH) {
        return 13;
    }
    let long = [b'A'; 300];
    if open(&long, O_READ) != Err(ERR_BAD_PATH) {
        return 14;
    }
    // A pointer outside user memory is refused, never dereferenced.
    if syscall6(SYS_OPEN, 0xffff_8000_0000_0000, 8, O_READ, 0, 0, 0) != ERR_RANGE {
        return 15;
    }
    // Reads through a bad handle and a wrong-type handle.
    let mut b = [0u8; 8];
    if read(0x7777, &mut b) != Err(ERR_BAD_HANDLE) {
        return 16;
    }
    let Ok((c0, _c1)) = channel_create() else {
        return 17;
    };
    if read(c0, &mut b) != Err(ERR_WRONG_TYPE) {
        return 18;
    }
    // A buffer in a read-only user page (this function's code) is refused for a read: the
    // kernel must never write where the process may not (mutant M37 would).
    let entry: fn() -> u64 = main;
    let code_page = entry as *const () as u64 & !0xFFF;
    if syscall6(SYS_READ, u64::from(h_ro_probe()), code_page, 8, 0, 0, 0) != ERR_FAULT {
        return 21;
    }
    // A valid file still works after all that.
    let Ok(h) = open(b"/hello.txt", O_READ) else {
        return 19;
    };
    let mut buf = [0u8; 32];
    if read(h, &mut buf) != Ok(24) || &buf[..5] != b"hello" {
        return 20;
    }
    0x61
}
