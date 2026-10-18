//! netprobe — the user side of the network interface (WP-27, TST-M4-NET-LINK): with the NIC
//! handle as its bootstrap handle it reads the interface description, sends an ARP request
//! for the lab gateway, waits for READABLE and reads frames until the ARP reply arrives, then
//! checks the refusals (bad lengths, a small receive buffer, a copy without WRITE). Exits
//! 0x73; otherwise the failing step (0xE0..).

#![no_std]
#![no_main]

use libnawah::{rights, WaitEntry, ERR_ACCESS, ERR_INVALID, ERR_SHOULD_WAIT, SIGNAL_READABLE};

libnawah::entry!(main);

const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

fn arp_request(mac: [u8; 6]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[..6].copy_from_slice(&[0xFF; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..16].copy_from_slice(&[0, 1]);
    f[16..18].copy_from_slice(&[0x08, 0x00]);
    f[18] = 6;
    f[19] = 4;
    f[20..22].copy_from_slice(&[0, 1]);
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&GUEST_IP);
    f[38..42].copy_from_slice(&GATEWAY_IP);
    f
}

fn is_arp_reply(frame: &[u8]) -> bool {
    frame.len() >= 42
        && frame[12..14] == [0x08, 0x06]
        && frame[20..22] == [0, 2]
        && frame[28..32] == GATEWAY_IP
}

fn main() -> u64 {
    let nic = libnawah::bootstrap_handle();
    if nic == 0 || libnawah::handle_type(nic) != libnawah::object_type::NIC {
        return 0xE0;
    }
    let Ok(info) = libnawah::nic_info(nic) else {
        return 0xE1;
    };
    if info.mac == [0; 6] || info.frame_max != 1514 || info.queue_size == 0 {
        return 0xE2;
    }
    let req = arp_request(info.mac);
    if libnawah::nic_send(nic, &req) != 0 {
        return 0xE3;
    }
    let mut buf = [0u8; 1514];
    let mut got_reply = false;
    let deadline = libnawah::clock_ticks() + 1000;
    while !got_reply && libnawah::clock_ticks() < deadline {
        let wait = libnawah::object_wait_many(
            &[WaitEntry {
                handle: nic,
                signals: SIGNAL_READABLE,
            }],
            200,
        );
        if wait.is_err() {
            continue;
        }
        loop {
            match libnawah::nic_recv(nic, &mut buf) {
                Ok(n) => {
                    if is_arp_reply(&buf[..n]) {
                        got_reply = true;
                        break;
                    }
                }
                Err(ERR_SHOULD_WAIT) => break,
                Err(_) => return 0xE4,
            }
        }
    }
    if !got_reply {
        return 0xE5;
    }
    // Refusals: too short, too long, a receive buffer below the frame maximum.
    if libnawah::nic_send(nic, &req[..13]) != ERR_INVALID {
        return 0xE6;
    }
    let big = [0u8; 1515];
    if libnawah::nic_send(nic, &big) != ERR_INVALID {
        return 0xE7;
    }
    let mut small = [0u8; 100];
    if libnawah::nic_recv(nic, &mut small) != Err(ERR_INVALID) {
        return 0xE8;
    }
    // A copy without WRITE cannot send; without READ cannot receive.
    let Ok(ro) = libnawah::handle_duplicate(nic, rights::READ | rights::WAIT) else {
        return 0xE9;
    };
    if libnawah::nic_send(ro, &req) != ERR_ACCESS {
        return 0xEA;
    }
    let Ok(wo) = libnawah::handle_duplicate(nic, rights::WRITE) else {
        return 0xEB;
    };
    if libnawah::nic_recv(wo, &mut buf) != Err(ERR_ACCESS) {
        return 0xEC;
    }
    // A wait on a handle without WAIT is refused.
    if libnawah::object_wait_many(
        &[WaitEntry {
            handle: wo,
            signals: SIGNAL_READABLE,
        }],
        0,
    ) != Err(ERR_ACCESS)
    {
        return 0xED;
    }
    0x73
}
