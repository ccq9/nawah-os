//! fd_leak (WP-19, TST-M3-FD-LEAK): opens many files (creating some), duplicates handles,
//! writes, and exits without closing anything; the test kernel checks that the process's exit
//! released every file object, handle, cluster and frame. Exit 0x62.

#![no_std]
#![no_main]

use libnawah::*;

libnawah::entry!(main);

fn main() -> u64 {
    let mut opened = 0u64;
    for _ in 0..20 {
        let Ok(h) = open(b"/HELLO.TXT", O_READ) else {
            return 1;
        };
        if handle_duplicate(h, rights::READ).is_err() {
            return 2;
        }
        opened += 2;
    }
    let names: [&[u8]; 4] = [
        b"/LEAK0.TXT",
        b"/LEAK1.TXT",
        b"/LEAK2.TXT",
        b"/DIR/LEAK3.TXT",
    ];
    for (i, name) in names.iter().enumerate() {
        let Ok(h) = open(name, O_READ | O_WRITE | O_CREATE) else {
            return 3;
        };
        let data = [b'0' + i as u8; 1500];
        if write(h, &data) != Ok(1500) {
            return 4;
        }
        opened += 1;
    }
    if sync() != 0 {
        return 5;
    }
    if opened != 44 {
        return 6;
    }
    0x62
}
