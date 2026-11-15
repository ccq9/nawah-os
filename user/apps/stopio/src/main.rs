//! stopio (WP-117, TST-M3-FAT32-STOP): started by the test kernel with a hook armed that
//! withholds from the device the second disk write from then on, the first FAT write of this
//! process's delete. The process opens /STOP2.TXT, reads it to its end, deletes /STOP1.TXT
//! (the disk stops inside that call) and then asks the file system six more things through
//! the system-call layer: every answer from the delete on must be ERR_IO. Exits 0x5709, or
//! the number of the first step that answered something else.

#![no_std]
#![no_main]

use libnawah::*;

libnawah::entry!(main);

fn main() -> u64 {
    let Ok(h) = open(b"/STOP2.TXT", O_READ | O_WRITE) else {
        return 1;
    };
    let mut buf = [0u8; 512];
    let mut total = 0usize;
    loop {
        match read(h, &mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => return 2,
        }
    }
    if total != 1024 {
        return 3;
    }
    if unlink(b"/STOP1.TXT") != ERR_IO {
        return 4;
    }
    // The position of `h` is at the end of its file: before WP-117 the next three calls were
    // answered from memory.
    if read(h, &mut buf) != Err(ERR_IO) {
        return 5;
    }
    if seek(h, 0) != ERR_IO {
        return 6;
    }
    if write(h, &buf[..0]) != Err(ERR_IO) {
        return 7;
    }
    if !matches!(stat(b"/STOP2.TXT"), Err(ERR_IO)) {
        return 8;
    }
    if !matches!(
        open(b"/STOP3.TXT", O_READ | O_WRITE | O_CREATE),
        Err(ERR_IO)
    ) {
        return 9;
    }
    if sync() != ERR_IO {
        return 10;
    }
    0x5709
}
