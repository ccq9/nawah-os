//! netd — the network service `net` (WP-28, docs/contracts/net.md part B, ADR-0016 §8): a
//! small stack of its own over the kernel's interface handle — Ethernet, ARP (RFC 826), IPv4
//! without fragments (RFC 791), ICMP echo (RFC 792), UDP (RFC 768), a DHCP client (RFC 2131/
//! 2132) — with three separate states (link, configured, internet) and a "no internet by
//! default" policy applied here, at the service. Clients arrive through `CONNECT net`.
//! No allocation; the tables live in a static (the user stack is 64 KiB).

#![no_std]
#![no_main]

use libnawah::{
    perm, Handle, WaitEntry, ERR_PEER_CLOSED, ERR_SHOULD_WAIT, SIGNAL_PEER_CLOSED, SIGNAL_READABLE,
};

libnawah::entry!(main);

const FRAME_MAX: usize = 1514;
const MAX_CLIENTS: usize = 8;
const ARP_ENTRIES: usize = 8;
const MAX_SOCKETS: usize = 16;
const SOCKET_QUEUE: usize = 4;
const DATAGRAM_MAX: usize = 1024;
const MSG_MAX: usize = 2048;
const ARP_WAIT_TICKS: u64 = 300;
const DHCP_TRIES: u32 = 3;
const DHCP_WAIT_TICKS: u64 = 1500;
const ICMP_ID: u16 = 0x4E57; // "NW"

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const PROTO_ICMP: u8 = 1;
const PROTO_UDP: u8 = 17;

type Ip = [u8; 4];
type Mac = [u8; 6];
const BROADCAST_MAC: Mac = [0xFF; 6];
const UNSPECIFIED: Ip = [0; 4];
const BROADCAST_IP: Ip = [255; 4];

#[derive(Clone, Copy)]
struct ArpEntry {
    ip: Ip,
    mac: Mac,
    valid: bool,
}

#[derive(Clone, Copy)]
struct Datagram {
    from: Ip,
    port: u16,
    len: u16,
    data: [u8; DATAGRAM_MAX],
}

const NO_DATAGRAM: Datagram = Datagram {
    from: UNSPECIFIED,
    port: 0,
    len: 0,
    data: [0; DATAGRAM_MAX],
};

#[derive(Clone, Copy)]
struct Socket {
    port: u16,
    owner: usize,
    queue: [Datagram; SOCKET_QUEUE],
    head: usize,
    len: usize,
    dropped: u32,
}

const NO_SOCKET: Socket = Socket {
    port: 0,
    owner: 0,
    queue: [NO_DATAGRAM; SOCKET_QUEUE],
    head: 0,
    len: 0,
    dropped: 0,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Internet {
    Unknown,
    None,
    Reachable,
}

struct Net {
    nic: Handle,
    mac: Mac,
    link: bool,
    configured: bool,
    ip: Ip,
    mask: Ip,
    gateway: Ip,
    dns: Ip,
    lease_s: u32,
    internet: Internet,
    allow_internet: bool,
    arp: [ArpEntry; ARP_ENTRIES],
    sockets: [Socket; MAX_SOCKETS],
    clients: [Handle; MAX_CLIENTS],
    ip_id: u16,
    icmp_seq: u16,
    /// An echo reply awaited by `ping`: (id, seq) and its arrival tick.
    echo_wait: Option<(u16, u16)>,
    echo_got: Option<u64>,
    /// A DHCP exchange in progress: the transaction id and the offer (server, yiaddr).
    dhcp_xid: u32,
    dhcp_offer: Option<(Ip, Ip)>,
    dhcp_ack: bool,
    rx_frame: [u8; FRAME_MAX],
    tx_frame: [u8; FRAME_MAX],
    msg: [u8; MSG_MAX],
    stats_rx: u32,
    stats_rx_bad: u32,
    stats_tx: u32,
}

static mut NET: Net = Net {
    nic: 0,
    mac: [0; 6],
    link: false,
    configured: false,
    ip: UNSPECIFIED,
    mask: UNSPECIFIED,
    gateway: UNSPECIFIED,
    dns: UNSPECIFIED,
    lease_s: 0,
    internet: Internet::Unknown,
    allow_internet: false,
    arp: [ArpEntry {
        ip: UNSPECIFIED,
        mac: [0; 6],
        valid: false,
    }; ARP_ENTRIES],
    sockets: [NO_SOCKET; MAX_SOCKETS],
    clients: [0; MAX_CLIENTS],
    ip_id: 1,
    icmp_seq: 1,
    echo_wait: None,
    echo_got: None,
    dhcp_xid: 0,
    dhcp_offer: None,
    dhcp_ack: false,
    rx_frame: [0; FRAME_MAX],
    tx_frame: [0; FRAME_MAX],
    msg: [0; MSG_MAX],
    stats_rx: 0,
    stats_rx_bad: 0,
    stats_tx: 0,
};

/// The single-threaded process's state (`main` takes it once and keeps it).
fn state() -> &'static mut Net {
    // SAFETY: one thread; the reference is created once in `main` and never a second time.
    unsafe { &mut *core::ptr::addr_of_mut!(NET) }
}

struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Out<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Out { buf, len: 0 }
    }
    fn put(&mut self, s: &[u8]) {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
    fn num(&mut self, mut v: u64) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&tmp[i..]);
    }
    fn ip(&mut self, ip: Ip) {
        for (i, b) in ip.iter().enumerate() {
            if i > 0 {
                self.put(b".");
            }
            self.num(u64::from(*b));
        }
    }
}

fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 19 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u64::from(c - b'0');
    }
    Some(v)
}

fn parse_ip(s: &[u8]) -> Option<Ip> {
    let mut ip = [0u8; 4];
    let mut parts = s.split(|c| *c == b'.');
    for b in ip.iter_mut() {
        let p = parse_u64(parts.next()?)?;
        if p > 255 {
            return None;
        }
        *b = p as u8;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(ip)
}

struct Fields<'a> {
    s: &'a [u8],
}

impl<'a> Fields<'a> {
    fn next(&mut self) -> Option<&'a [u8]> {
        while let [b' ', rest @ ..] = self.s {
            self.s = rest;
        }
        if self.s.is_empty() {
            return None;
        }
        let end = self
            .s
            .iter()
            .position(|c| *c == b' ')
            .unwrap_or(self.s.len());
        let f = &self.s[..end];
        self.s = &self.s[end..];
        Some(f)
    }
    fn rest(&mut self) -> &'a [u8] {
        while let [b' ', rest @ ..] = self.s {
            self.s = rest;
        }
        self.s
    }
}

/// RFC 1071 one's complement sum over `data` (odd trailing byte padded), folded.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry: Option<u8> = None;
    for part in parts {
        let mut data = *part;
        if let Some(c) = carry.take() {
            if let [first, rest @ ..] = data {
                sum += u32::from(u16::from_be_bytes([c, *first]));
                data = rest;
            } else {
                carry = Some(c);
                continue;
            }
        }
        let mut chunks = data.chunks_exact(2);
        for ch in &mut chunks {
            sum += u32::from(u16::from_be_bytes([ch[0], ch[1]]));
        }
        if let [last] = chunks.remainder() {
            carry = Some(*last);
        }
    }
    if let Some(c) = carry {
        sum += u32::from(u16::from_be_bytes([c, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

impl Net {
    fn arp_lookup(&self, ip: Ip) -> Option<Mac> {
        self.arp
            .iter()
            .find(|e| e.valid && e.ip == ip)
            .map(|e| e.mac)
    }

    fn arp_learn(&mut self, ip: Ip, mac: Mac) {
        if let Some(e) = self.arp.iter_mut().find(|e| e.valid && e.ip == ip) {
            e.mac = mac;
            return;
        }
        let slot = self.arp.iter().position(|e| !e.valid).unwrap_or(0);
        self.arp[slot] = ArpEntry {
            ip,
            mac,
            valid: true,
        };
    }

    /// Writes an Ethernet header into `tx_frame`; returns the payload offset (14).
    fn eth_header(&mut self, dst: Mac, ethertype: u16) -> usize {
        self.tx_frame[..6].copy_from_slice(&dst);
        self.tx_frame[6..12].copy_from_slice(&self.mac);
        self.tx_frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        14
    }

    fn transmit(&mut self, len: usize) -> bool {
        // Ethernet minimum frame: the padding is zeroed, never stale bytes.
        if len < 60 {
            self.tx_frame[len..60].fill(0);
        }
        let len = len.max(60);
        let mut tries = 0;
        loop {
            let r = libnawah::nic_send(self.nic, &self.tx_frame[..len]);
            if r == 0 {
                self.stats_tx += 1;
                return true;
            }
            if r != ERR_SHOULD_WAIT || tries == 50 {
                return false;
            }
            tries += 1;
            libnawah::sleep(1);
        }
    }

    fn send_arp(&mut self, op: u16, target_mac: Mac, target_ip: Ip, dst: Mac) -> bool {
        let o = self.eth_header(dst, ETHERTYPE_ARP);
        let f = &mut self.tx_frame[o..o + 28];
        f[0..2].copy_from_slice(&1u16.to_be_bytes());
        f[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f[4] = 6;
        f[5] = 4;
        f[6..8].copy_from_slice(&op.to_be_bytes());
        let mac = self.mac;
        let ip = self.ip;
        let f = &mut self.tx_frame[o..o + 28];
        f[8..14].copy_from_slice(&mac);
        f[14..18].copy_from_slice(&ip);
        f[18..24].copy_from_slice(&target_mac);
        f[24..28].copy_from_slice(&target_ip);
        self.tx_frame[o + 28..o + 46].fill(0);
        self.transmit(o + 28)
    }

    /// The MAC for `ip` (on-link) or the gateway's, resolving with ARP (bounded wait during
    /// which other frames are still processed).
    fn resolve(&mut self, ip: Ip) -> Option<Mac> {
        let on_link = self.on_link(ip);
        let next_hop = if on_link { ip } else { self.gateway };
        if next_hop == BROADCAST_IP {
            return Some(BROADCAST_MAC);
        }
        if let Some(m) = self.arp_lookup(next_hop) {
            return Some(m);
        }
        let deadline = libnawah::clock_ticks() + ARP_WAIT_TICKS;
        let mut next_request = 0;
        while libnawah::clock_ticks() < deadline {
            if libnawah::clock_ticks() >= next_request {
                self.send_arp(1, [0; 6], next_hop, BROADCAST_MAC);
                next_request = libnawah::clock_ticks() + 100;
            }
            self.pump(20);
            if let Some(m) = self.arp_lookup(next_hop) {
                return Some(m);
            }
        }
        None
    }

    fn on_link(&self, ip: Ip) -> bool {
        if ip == BROADCAST_IP || !self.configured {
            return true;
        }
        (0..4).all(|i| (ip[i] & self.mask[i]) == (self.ip[i] & self.mask[i]))
    }

    /// Policy (net.md ب): off-link destinations need `allow_internet`.
    fn policy_allows(&self, ip: Ip) -> bool {
        self.allow_internet || self.on_link(ip) || ip == self.gateway
    }

    /// Sends an IPv4 packet with `payload` already in `tx_frame[34..34+len]`.
    fn send_ipv4(&mut self, dst: Ip, proto: u8, payload_len: usize, dst_mac: Mac) -> bool {
        let o = self.eth_header(dst_mac, ETHERTYPE_IPV4);
        let total = (20 + payload_len) as u16;
        let id = self.ip_id;
        self.ip_id = self.ip_id.wrapping_add(1);
        let src = self.ip;
        let h = &mut self.tx_frame[o..o + 20];
        h[0] = 0x45;
        h[1] = 0;
        h[2..4].copy_from_slice(&total.to_be_bytes());
        h[4..6].copy_from_slice(&id.to_be_bytes());
        h[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        h[8] = 64;
        h[9] = proto;
        h[10..12].copy_from_slice(&[0, 0]);
        h[12..16].copy_from_slice(&src);
        h[16..20].copy_from_slice(&dst);
        let c = checksum(&[&self.tx_frame[o..o + 20]]);
        self.tx_frame[o + 10..o + 12].copy_from_slice(&c.to_be_bytes());
        self.transmit(o + 20 + payload_len)
    }

    /// UDP datagram: payload copied to its place, checksum with the pseudo header (RFC 768).
    fn send_udp(
        &mut self,
        dst: Ip,
        src_port: u16,
        dst_port: u16,
        data: &[u8],
        dst_mac: Mac,
    ) -> bool {
        if data.len() > DATAGRAM_MAX {
            return false;
        }
        let ulen = (8 + data.len()) as u16;
        let o = 34;
        self.tx_frame[o + 8..o + 8 + data.len()].copy_from_slice(data);
        let h = &mut self.tx_frame[o..o + 8];
        h[0..2].copy_from_slice(&src_port.to_be_bytes());
        h[2..4].copy_from_slice(&dst_port.to_be_bytes());
        h[4..6].copy_from_slice(&ulen.to_be_bytes());
        h[6..8].copy_from_slice(&[0, 0]);
        let mut pseudo = [0u8; 12];
        pseudo[..4].copy_from_slice(&self.ip);
        pseudo[4..8].copy_from_slice(&dst);
        pseudo[9] = PROTO_UDP;
        pseudo[10..12].copy_from_slice(&ulen.to_be_bytes());
        let mut c = checksum(&[&pseudo, &self.tx_frame[o..o + usize::from(ulen)]]);
        if c == 0 {
            c = 0xFFFF;
        }
        self.tx_frame[o + 6..o + 8].copy_from_slice(&c.to_be_bytes());
        self.send_ipv4(dst, PROTO_UDP, usize::from(ulen), dst_mac)
    }

    fn send_icmp_echo(
        &mut self,
        dst: Ip,
        dst_mac: Mac,
        typ: u8,
        id: u16,
        seq: u16,
        data: &[u8],
    ) -> bool {
        let o = 34;
        let n = data.len().min(64);
        self.tx_frame[o + 8..o + 8 + n].copy_from_slice(&data[..n]);
        let h = &mut self.tx_frame[o..o + 8];
        h[0] = typ;
        h[1] = 0;
        h[2..4].copy_from_slice(&[0, 0]);
        h[4..6].copy_from_slice(&id.to_be_bytes());
        h[6..8].copy_from_slice(&seq.to_be_bytes());
        let c = checksum(&[&self.tx_frame[o..o + 8 + n]]);
        self.tx_frame[o + 2..o + 4].copy_from_slice(&c.to_be_bytes());
        self.send_ipv4(dst, PROTO_ICMP, 8 + n, dst_mac)
    }

    /// Reads and handles every waiting frame; waits up to `ticks` for the first one.
    fn pump(&mut self, ticks: u64) {
        let deadline = libnawah::clock_ticks() + ticks;
        loop {
            let mut frame = [0u8; FRAME_MAX];
            match libnawah::nic_recv(self.nic, &mut frame) {
                Ok(n) => {
                    self.rx_frame[..n].copy_from_slice(&frame[..n]);
                    self.handle_frame(n);
                }
                Err(_) => {
                    let now = libnawah::clock_ticks();
                    if now >= deadline {
                        return;
                    }
                    let _ = libnawah::object_wait_many(
                        &[WaitEntry {
                            handle: self.nic,
                            signals: SIGNAL_READABLE,
                        }],
                        deadline - now,
                    );
                }
            }
        }
    }

    fn handle_frame(&mut self, n: usize) {
        self.stats_rx += 1;
        if n < 14 {
            self.stats_rx_bad += 1;
            return;
        }
        let dst = &self.rx_frame[..6];
        if dst != self.mac && dst != BROADCAST_MAC {
            return;
        }
        match u16_at(&self.rx_frame, 12) {
            ETHERTYPE_ARP => self.handle_arp(n),
            ETHERTYPE_IPV4 => self.handle_ipv4(n),
            _ => {}
        }
    }

    fn handle_arp(&mut self, n: usize) {
        if n < 42 || u16_at(&self.rx_frame, 14) != 1 || u16_at(&self.rx_frame, 16) != ETHERTYPE_IPV4
        {
            self.stats_rx_bad += 1;
            return;
        }
        let op = u16_at(&self.rx_frame, 20);
        let mut sha = [0u8; 6];
        sha.copy_from_slice(&self.rx_frame[22..28]);
        let mut spa = [0u8; 4];
        spa.copy_from_slice(&self.rx_frame[28..32]);
        let mut tpa = [0u8; 4];
        tpa.copy_from_slice(&self.rx_frame[38..42]);
        if spa != UNSPECIFIED {
            self.arp_learn(spa, sha);
        }
        if op == 1 && self.configured && tpa == self.ip {
            self.send_arp(2, sha, spa, sha);
        }
    }

    fn handle_ipv4(&mut self, n: usize) {
        let f = &self.rx_frame[14..n];
        if f.len() < 20 || f[0] >> 4 != 4 {
            self.stats_rx_bad += 1;
            return;
        }
        let ihl = usize::from(f[0] & 0xF) * 4;
        let total = usize::from(u16_at(f, 2));
        if ihl < 20 || total < ihl || total > f.len() || checksum(&[&f[..ihl]]) != 0 {
            self.stats_rx_bad += 1;
            return;
        }
        if u16_at(f, 6) & 0x3FFF != 0 {
            // Fragments are not supported (MF set or an offset): dropped and counted.
            self.stats_rx_bad += 1;
            return;
        }
        let proto = f[9];
        let mut src = [0u8; 4];
        src.copy_from_slice(&f[12..16]);
        let mut dst = [0u8; 4];
        dst.copy_from_slice(&f[16..20]);
        let for_us =
            dst == self.ip || dst == BROADCAST_IP || (!self.configured && dst != UNSPECIFIED);
        if !for_us {
            return;
        }
        let (start, end) = (14 + ihl, 14 + total);
        match proto {
            PROTO_ICMP => self.handle_icmp(src, start, end),
            PROTO_UDP => self.handle_udp(src, dst, start, end),
            _ => {}
        }
    }

    fn handle_icmp(&mut self, src: Ip, start: usize, end: usize) {
        let m = &self.rx_frame[start..end];
        if m.len() < 8 || checksum(&[m]) != 0 {
            self.stats_rx_bad += 1;
            return;
        }
        let (typ, id, seq) = (m[0], u16_at(m, 4), u16_at(m, 6));
        if typ == 8 {
            // Echo request: reply with the same id/seq/data to the sender's MAC.
            let mut data = [0u8; 64];
            let n = (m.len() - 8).min(64);
            data[..n].copy_from_slice(&m[8..8 + n]);
            let mut smac = [0u8; 6];
            smac.copy_from_slice(&self.rx_frame[6..12]);
            self.send_icmp_echo(src, smac, 0, id, seq, &data[..n]);
        } else if typ == 0 && self.echo_wait == Some((id, seq)) {
            self.echo_got = Some(libnawah::clock_ticks());
        }
    }

    fn handle_udp(&mut self, src: Ip, dst: Ip, start: usize, end: usize) {
        let u = &self.rx_frame[start..end];
        if u.len() < 8 {
            self.stats_rx_bad += 1;
            return;
        }
        let (sport, dport, ulen) = (u16_at(u, 0), u16_at(u, 2), usize::from(u16_at(u, 4)));
        if ulen < 8 || ulen > u.len() {
            self.stats_rx_bad += 1;
            return;
        }
        if u16_at(u, 6) != 0 {
            let mut pseudo = [0u8; 12];
            pseudo[..4].copy_from_slice(&src);
            pseudo[4..8].copy_from_slice(&dst);
            pseudo[9] = PROTO_UDP;
            pseudo[10..12].copy_from_slice(&(ulen as u16).to_be_bytes());
            if checksum(&[&pseudo, &u[..ulen]]) != 0 {
                self.stats_rx_bad += 1;
                return;
            }
        }
        let data_start = start + 8;
        let data_end = start + ulen;
        if dport == 68 {
            self.handle_dhcp(data_start, data_end);
            return;
        }
        let Some(si) = self
            .sockets
            .iter()
            .position(|s| s.port != 0 && s.port == dport)
        else {
            return;
        };
        let s = &mut self.sockets[si];
        if s.len == SOCKET_QUEUE {
            s.dropped += 1;
            return;
        }
        let n = (data_end - data_start).min(DATAGRAM_MAX);
        let slot = (s.head + s.len) % SOCKET_QUEUE;
        let d = &mut s.queue[slot];
        d.from = src;
        d.port = sport;
        d.len = n as u16;
        d.data[..n].copy_from_slice(&self.rx_frame[data_start..data_start + n]);
        s.len += 1;
    }

    // ---- DHCP client (RFC 2131 §3.1, options RFC 2132) ----------------------------------

    fn send_dhcp(&mut self, msg_type: u8, requested: Option<Ip>, server: Option<Ip>) -> bool {
        let mut p = [0u8; 300];
        p[0] = 1; // BOOTREQUEST
        p[1] = 1; // Ethernet
        p[2] = 6;
        p[4..8].copy_from_slice(&self.dhcp_xid.to_be_bytes());
        p[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // BROADCAST flag
        p[28..34].copy_from_slice(&self.mac);
        p[236..240].copy_from_slice(&[99, 130, 83, 99]);
        let mut o = 240;
        p[o..o + 3].copy_from_slice(&[53, 1, msg_type]);
        o += 3;
        if let Some(r) = requested {
            p[o..o + 2].copy_from_slice(&[50, 4]);
            p[o + 2..o + 6].copy_from_slice(&r);
            o += 6;
        }
        if let Some(s) = server {
            p[o..o + 2].copy_from_slice(&[54, 4]);
            p[o + 2..o + 6].copy_from_slice(&s);
            o += 6;
        }
        p[o..o + 5].copy_from_slice(&[55, 3, 1, 3, 6]); // mask, router, dns
        o += 5;
        p[o] = 255;
        o += 1;
        let src_ip = self.ip;
        self.ip = UNSPECIFIED;
        let ok = self.send_udp(BROADCAST_IP, 68, 67, &p[..o], BROADCAST_MAC);
        self.ip = src_ip;
        ok
    }

    fn handle_dhcp(&mut self, start: usize, end: usize) {
        let d = &self.rx_frame[start..end];
        if d.len() < 244
            || d[0] != 2
            || u32::from_be_bytes([d[4], d[5], d[6], d[7]]) != self.dhcp_xid
        {
            return;
        }
        if d[236..240] != [99, 130, 83, 99] {
            return;
        }
        let mut yiaddr = [0u8; 4];
        yiaddr.copy_from_slice(&d[16..20]);
        let (mut msg_type, mut mask, mut router, mut dns, mut server, mut lease) = (
            0u8,
            UNSPECIFIED,
            UNSPECIFIED,
            UNSPECIFIED,
            UNSPECIFIED,
            0u32,
        );
        let mut i = 240;
        while i < d.len() {
            let code = d[i];
            if code == 255 {
                break;
            }
            if code == 0 {
                i += 1;
                continue;
            }
            if i + 1 >= d.len() {
                break;
            }
            let len = usize::from(d[i + 1]);
            let v = &d[(i + 2).min(d.len())..(i + 2 + len).min(d.len())];
            if v.len() == len {
                match code {
                    53 if len == 1 => msg_type = v[0],
                    1 if len == 4 => mask.copy_from_slice(v),
                    3 if len >= 4 => router.copy_from_slice(&v[..4]),
                    6 if len >= 4 => dns.copy_from_slice(&v[..4]),
                    54 if len == 4 => server.copy_from_slice(v),
                    51 if len == 4 => lease = u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
                    _ => {}
                }
            }
            i += 2 + len;
        }
        match msg_type {
            2 => self.dhcp_offer = Some((server, yiaddr)),
            5 => {
                self.ip = yiaddr;
                self.mask = mask;
                self.gateway = router;
                self.dns = dns;
                self.lease_s = lease;
                self.configured = true;
                self.dhcp_ack = true;
            }
            _ => {}
        }
    }

    /// The whole exchange with retries; `Some(())` once configured.
    fn dhcp(&mut self) -> bool {
        for attempt in 0..DHCP_TRIES {
            self.dhcp_xid =
                0x4E41_5741 ^ (libnawah::clock_ticks() as u32).wrapping_mul(2654435761) ^ attempt;
            self.dhcp_offer = None;
            self.dhcp_ack = false;
            if !self.send_dhcp(1, None, None) {
                continue;
            }
            let deadline = libnawah::clock_ticks() + DHCP_WAIT_TICKS;
            while libnawah::clock_ticks() < deadline && self.dhcp_offer.is_none() {
                self.pump(50);
            }
            let Some((server, offered)) = self.dhcp_offer else {
                continue;
            };
            if !self.send_dhcp(3, Some(offered), Some(server)) {
                continue;
            }
            let deadline = libnawah::clock_ticks() + DHCP_WAIT_TICKS;
            while libnawah::clock_ticks() < deadline && !self.dhcp_ack {
                self.pump(50);
            }
            if self.dhcp_ack {
                let mut line = [0u8; 160];
                let len = {
                    let mut o = Out::new(&mut line);
                    o.put(b"net|dhcp|ip=");
                    o.ip(self.ip);
                    o.put(b"|mask=");
                    o.ip(self.mask);
                    o.put(b"|gw=");
                    o.ip(self.gateway);
                    o.put(b"|dns=");
                    o.ip(self.dns);
                    o.put(b"|lease=");
                    o.num(u64::from(self.lease_s));
                    o.put(b"|attempt=");
                    o.num(u64::from(attempt + 1));
                    o.len
                };
                libnawah::trace(&line[..len]);
                return true;
            }
        }
        false
    }

    /// ICMP echo to `dst`; the round trip in ticks.
    fn ping(&mut self, dst: Ip, timeout: u64) -> Result<u64, &'static str> {
        let mac = self.resolve(dst).ok_or("ARP")?;
        let seq = self.icmp_seq;
        self.icmp_seq = self.icmp_seq.wrapping_add(1);
        self.echo_wait = Some((ICMP_ID, seq));
        self.echo_got = None;
        let t0 = libnawah::clock_ticks();
        if !self.send_icmp_echo(dst, mac, 8, ICMP_ID, seq, b"nawah-ping-payload") {
            self.echo_wait = None;
            return Err("SEND");
        }
        let deadline = t0 + timeout;
        while libnawah::clock_ticks() < deadline && self.echo_got.is_none() {
            self.pump(20);
        }
        self.echo_wait = None;
        self.echo_got.take().map(|t| t - t0).ok_or("TIMEOUT")
    }

    fn status(&self, out: &mut Out) {
        out.put(b"OK link=");
        out.num(u64::from(self.link));
        out.put(b" configured=");
        out.num(u64::from(self.configured));
        out.put(b" ip=");
        out.ip(self.ip);
        out.put(b" mask=");
        out.ip(self.mask);
        out.put(b" gw=");
        out.ip(self.gateway);
        out.put(b" dns=");
        out.ip(self.dns);
        out.put(b" internet=");
        out.put(match self.internet {
            Internet::Unknown => b"unknown",
            Internet::None => b"none",
            Internet::Reachable => b"reachable",
        });
        out.put(b" allow_internet=");
        out.num(u64::from(self.allow_internet));
        out.put(b" rx=");
        out.num(u64::from(self.stats_rx));
        out.put(b" rx_bad=");
        out.num(u64::from(self.stats_rx_bad));
        out.put(b" tx=");
        out.num(u64::from(self.stats_tx));
    }

    /// One client request (text + optional token handle).
    fn request(&mut self, ci: usize, req: &[u8], handle: Option<Handle>, out: &mut Out) {
        let mut f = Fields { s: req };
        let verb = f.next().unwrap_or(b"");
        match verb {
            b"STATUS" => {
                self.link = libnawah::nic_info(self.nic)
                    .map(|i| i.link_up)
                    .unwrap_or(false);
                self.status(out);
            }
            b"DHCP" => {
                if self.dhcp() {
                    out.put(b"OK ip=");
                    out.ip(self.ip);
                    out.put(b" mask=");
                    out.ip(self.mask);
                    out.put(b" gw=");
                    out.ip(self.gateway);
                    out.put(b" dns=");
                    out.ip(self.dns);
                } else {
                    out.put(b"ERR TIMEOUT");
                }
            }
            b"PING" | b"PROBE" => {
                let Some(ip) = f.next().and_then(parse_ip) else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                let timeout = f.next().and_then(parse_u64).unwrap_or(1000).min(10_000);
                if verb == b"PING" && !self.policy_allows(ip) {
                    out.put(b"ERR POLICY");
                    return;
                }
                match self.ping(ip, timeout) {
                    Ok(rtt) => {
                        if verb == b"PROBE" {
                            self.internet = Internet::Reachable;
                        }
                        out.put(b"OK rtt=");
                        out.num(rtt);
                    }
                    Err(e) => {
                        if verb == b"PROBE" {
                            self.internet = Internet::None;
                        }
                        out.put(b"ERR ");
                        out.put(e.as_bytes());
                    }
                }
            }
            b"POLICY" => {
                let Some(setting) = f.next() else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                let admin = handle
                    .and_then(|h| libnawah::token_info(h).ok())
                    .is_some_and(|t| t.usable() && t.perms & perm::ADMIN != 0);
                if !admin {
                    out.put(if handle.is_some() {
                        b"ERR ACCESS"
                    } else {
                        b"ERR BAD_REQUEST"
                    });
                    return;
                }
                match setting {
                    b"internet=1" => self.allow_internet = true,
                    b"internet=0" => self.allow_internet = false,
                    _ => {
                        out.put(b"ERR BAD_REQUEST");
                        return;
                    }
                }
                out.put(b"OK");
            }
            b"UDP_OPEN" => {
                let Some(port) = f
                    .next()
                    .and_then(parse_u64)
                    .filter(|p| *p > 0 && *p < 65536)
                else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                if self.sockets.iter().any(|s| s.port == port as u16) {
                    out.put(b"ERR EXISTS");
                    return;
                }
                let Some(si) = self.sockets.iter().position(|s| s.port == 0) else {
                    out.put(b"ERR FULL");
                    return;
                };
                self.sockets[si] = NO_SOCKET;
                self.sockets[si].port = port as u16;
                self.sockets[si].owner = ci;
                out.put(b"OK ");
                out.num(si as u64);
            }
            b"UDP_CLOSE" => match f.next().and_then(parse_u64).map(|s| s as usize) {
                Some(si)
                    if si < MAX_SOCKETS
                        && self.sockets[si].port != 0
                        && self.sockets[si].owner == ci =>
                {
                    self.sockets[si] = NO_SOCKET;
                    out.put(b"OK");
                }
                _ => out.put(b"ERR BAD_REQUEST"),
            },
            b"UDP_SEND" => {
                let (Some(si), Some(ip), Some(port)) = (
                    f.next().and_then(parse_u64).map(|s| s as usize),
                    f.next().and_then(parse_ip),
                    f.next().and_then(parse_u64).filter(|p| *p < 65536),
                ) else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                let data = f.rest();
                if si >= MAX_SOCKETS
                    || self.sockets[si].port == 0
                    || self.sockets[si].owner != ci
                    || data.len() > DATAGRAM_MAX
                {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                }
                if !self.policy_allows(ip) {
                    out.put(b"ERR POLICY");
                    return;
                }
                let Some(mac) = self.resolve(ip) else {
                    out.put(b"ERR ARP");
                    return;
                };
                let sport = self.sockets[si].port;
                let mut copy = [0u8; DATAGRAM_MAX];
                copy[..data.len()].copy_from_slice(data);
                if self.send_udp(ip, sport, port as u16, &copy[..data.len()], mac) {
                    out.put(b"OK ");
                    out.num(data.len() as u64);
                } else {
                    out.put(b"ERR BUSY");
                }
            }
            b"UDP_RECV" => {
                let (Some(si), timeout) = (
                    f.next().and_then(parse_u64).map(|s| s as usize),
                    f.next().and_then(parse_u64).unwrap_or(0).min(10_000),
                ) else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                if si >= MAX_SOCKETS || self.sockets[si].port == 0 || self.sockets[si].owner != ci {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                }
                let deadline = libnawah::clock_ticks() + timeout;
                while self.sockets[si].len == 0 && libnawah::clock_ticks() < deadline {
                    self.pump(20);
                }
                let s = &mut self.sockets[si];
                if s.len == 0 {
                    out.put(b"ERR TIMEOUT");
                    return;
                }
                let d = s.queue[s.head];
                s.head = (s.head + 1) % SOCKET_QUEUE;
                s.len -= 1;
                out.put(b"OK ");
                out.ip(d.from);
                out.put(b" ");
                out.num(u64::from(d.port));
                out.put(b" ");
                out.put(&d.data[..usize::from(d.len)]);
            }
            _ => out.put(b"ERR BAD_REQUEST"),
        }
    }
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let nic = boot + 1;
    if libnawah::handle_type(nic) != libnawah::object_type::NIC {
        return 0xE1;
    }
    let st = state();
    st.nic = nic;
    match libnawah::nic_info(nic) {
        Ok(i) => {
            st.mac = i.mac;
            st.link = i.link_up;
        }
        Err(_) => return 0xE2,
    }
    let mut hs = [0u32; 1];
    let mut buf = [0u8; 256];
    match libnawah::channel_read(boot, &mut buf, &mut hs, true) {
        Ok((n, _)) if buf[..n].starts_with(b"START") => {}
        _ => return 0xE3,
    }
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE4;
    }
    let mut entries = [WaitEntry {
        handle: 0,
        signals: 0,
    }; 2 + MAX_CLIENTS];
    loop {
        // The main wait: the manager, the interface, every client.
        entries[0] = WaitEntry {
            handle: boot,
            signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
        };
        entries[1] = WaitEntry {
            handle: nic,
            signals: SIGNAL_READABLE,
        };
        let mut k = 2;
        let mut owner = [0usize; 2 + MAX_CLIENTS];
        for (i, &c) in st.clients.iter().enumerate() {
            if c != 0 {
                entries[k] = WaitEntry {
                    handle: c,
                    signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                };
                owner[k] = i;
                k += 1;
            }
        }
        let Ok((idx, _)) = libnawah::object_wait_many(&entries[..k], libnawah::TIMEOUT_FOREVER)
        else {
            return 0xE5;
        };
        if idx == 1 {
            st.pump(0);
            continue;
        }
        if idx == 0 {
            match libnawah::channel_read(boot, &mut st.msg, &mut hs, false) {
                Ok((n, nh)) => {
                    if &st.msg[..n] == b"CONNECT" && nh == 1 {
                        match st.clients.iter().position(|&c| c == 0) {
                            Some(slot) => st.clients[slot] = hs[0],
                            None => {
                                libnawah::handle_close(hs[0]);
                            }
                        }
                    } else if &st.msg[..n] == b"STOP" {
                        return 0;
                    } else if nh == 1 {
                        libnawah::handle_close(hs[0]);
                    }
                }
                Err(ERR_PEER_CLOSED) => return 0,
                Err(_) => {}
            }
            continue;
        }
        let ci = owner[idx];
        let c = st.clients[ci];
        match libnawah::channel_read(c, &mut st.msg, &mut hs, false) {
            Ok((n, nh)) => {
                let handle = if nh == 1 { Some(hs[0]) } else { None };
                let mut req_copy = [0u8; MSG_MAX];
                req_copy[..n].copy_from_slice(&st.msg[..n]);
                let mut out_buf = [0u8; MSG_MAX];
                let mut out = Out::new(&mut out_buf);
                st.request(ci, &req_copy[..n], handle, &mut out);
                if let Some(h) = handle {
                    libnawah::handle_close(h);
                }
                let len = out.len;
                if libnawah::channel_write(c, &out_buf[..len], &[]) == ERR_PEER_CLOSED {
                    libnawah::handle_close(c);
                    st.clients[ci] = 0;
                }
            }
            Err(ERR_PEER_CLOSED) => {
                libnawah::handle_close(c);
                st.clients[ci] = 0;
                for s in st
                    .sockets
                    .iter_mut()
                    .filter(|s| s.port != 0 && s.owner == ci)
                {
                    *s = NO_SOCKET;
                }
            }
            Err(_) => {}
        }
    }
}
