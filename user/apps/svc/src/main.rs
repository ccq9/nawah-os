//! svc — a test service for the service manager (WP-24, services.md §4): its first message
//! `START <arg>` picks the role: `ready` answers READY and waits for STOP (or the channel's
//! close) then exits 0; `mute` never answers and exits 0 once the channel closes; `crash`
//! exits 1 at once. Anything else exits 2; a missing bootstrap handle 0xE0.

#![no_std]
#![no_main]

use libnawah::ERR_PEER_CLOSED;

libnawah::entry!(main);

fn main() -> u64 {
    let ch = libnawah::bootstrap_handle();
    if ch == 0 {
        return 0xE0;
    }
    let mut buf = [0u8; 128];
    let mut hs = [0u32; 1];
    let n = match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
        Ok((n, _)) => n,
        Err(_) => return 0xE1,
    };
    let role = buf[..n].strip_prefix(b"START ").unwrap_or(b"");
    match role {
        b"ready" => {
            if libnawah::channel_write(ch, b"READY", &[]) < 0 {
                return 0xE2;
            }
            loop {
                match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
                    Ok((n, _)) if &buf[..n] == b"STOP" => return 0,
                    Ok(_) => {}
                    Err(ERR_PEER_CLOSED) => return 0,
                    Err(_) => return 0xE3,
                }
            }
        }
        b"mute" => loop {
            match libnawah::channel_read(ch, &mut buf, &mut hs, true) {
                Ok(_) => {}
                Err(ERR_PEER_CLOSED) => return 0,
                Err(_) => return 0xE4,
            }
        },
        b"crash" => 1,
        _ => 2,
    }
}
