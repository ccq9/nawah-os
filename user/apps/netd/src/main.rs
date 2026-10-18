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
const PROTO_TCP: u8 = 6;
const MAX_CONNS: usize = 8;
/// One segment in flight at a time (stop-and-wait); its payload bound.
const TCP_SEG_MAX: usize = 1024;
const TCP_RX_MAX: usize = 2048;
/// RFC 6298: initial RTO 1 s, minimum 1 s, maximum here 60 s. Six retransmissions with the
/// doubling RTO put the abort at about 123 s after the first transmission: RFC 9293 §3.8.3
/// asks R2 to be at least 100 s for data segments.
const RTO_INITIAL: u64 = 1000;
const RTO_MIN: u64 = 1000;
const RTO_MAX: u64 = 60_000;
const TCP_MAX_RETRIES: u32 = 6;
/// RFC 6298 (5.7): after a retransmitted SYN the RTO for data starts at 3 s at least.
const RTO_AFTER_SYN_LOSS: u64 = 3000;
/// TIME-WAIT linger (2 × MSL with the lab's MSL of 1 s).
const TIME_WAIT_TICKS: u64 = 2000;
const TCP_DEFAULT_MSS: u16 = 536;
const TCP_WINDOW: u16 = TCP_RX_MAX as u16;

/// A connection slot nobody holds.
const NO_OWNER: usize = usize::MAX;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

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
enum TcpState {
    Closed,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closing,
    TimeWait,
}

impl TcpState {
    fn name(self) -> &'static [u8] {
        match self {
            TcpState::Closed => b"CLOSED",
            TcpState::SynSent => b"SYN-SENT",
            TcpState::Established => b"ESTABLISHED",
            TcpState::FinWait1 => b"FIN-WAIT-1",
            TcpState::FinWait2 => b"FIN-WAIT-2",
            TcpState::CloseWait => b"CLOSE-WAIT",
            TcpState::LastAck => b"LAST-ACK",
            TcpState::Closing => b"CLOSING",
            TcpState::TimeWait => b"TIME-WAIT",
        }
    }
}

/// Why a connection ended without the client's close.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// The peer answered with RST (a refused connection, or an abort).
    Reset,
    /// The retransmission limit was reached (RFC 9293 §3.8.3).
    Timeout,
}

/// A TCP connection (RFC 9293) with one segment in flight: `unacked` holds the bytes between
/// `snd_una` and `snd_nxt`; the retransmission timer follows RFC 6298 (SRTT/RTTVAR in ticks,
/// Karn's rule: no sample from a retransmitted segment, back-off on expiry). `id` names the
/// connection to its client and is never reused; a slot is free when nobody owns it and it
/// is CLOSED (TIME-WAIT lingers unowned).
#[derive(Clone, Copy)]
struct TcpConn {
    id: u32,
    state: TcpState,
    owner: usize,
    local_port: u16,
    remote_ip: Ip,
    remote_port: u16,
    remote_mac: Mac,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    snd_wnd: u16,
    mss: u16,
    unacked: [u8; TCP_SEG_MAX],
    unacked_len: usize,
    /// The in-flight segment carries FIN (1) or SYN (1) sequence space beyond its data.
    unacked_flags: u8,
    sent_at: u64,
    retransmitted: bool,
    timer_due: Option<u64>,
    rto: u64,
    srtt: Option<u64>,
    rttvar: u64,
    retransmits: u32,
    rx: [u8; TCP_RX_MAX],
    rx_len: usize,
    fin_received: bool,
    fault: Fault,
    /// Test hook (net.md ب): drop the next data transmission once, so the timer must act.
    drop_next: bool,
    time_wait_until: u64,
}

const NO_CONN: TcpConn = TcpConn {
    id: 0,
    state: TcpState::Closed,
    owner: NO_OWNER,
    local_port: 0,
    remote_ip: UNSPECIFIED,
    remote_port: 0,
    remote_mac: [0; 6],
    snd_una: 0,
    snd_nxt: 0,
    rcv_nxt: 0,
    snd_wnd: 0,
    mss: TCP_DEFAULT_MSS,
    unacked: [0; TCP_SEG_MAX],
    unacked_len: 0,
    unacked_flags: 0,
    sent_at: 0,
    retransmitted: false,
    timer_due: None,
    rto: RTO_INITIAL,
    srtt: None,
    rttvar: 0,
    retransmits: 0,
    rx: [0; TCP_RX_MAX],
    rx_len: 0,
    fin_received: false,
    fault: Fault::None,
    drop_next: false,
    time_wait_until: 0,
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
    conns: [TcpConn; MAX_CONNS],
    next_port: u16,
    next_conn: u32,
    isn: u32,
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
    conns: [NO_CONN; MAX_CONNS],
    next_port: 49152,
    next_conn: 1,
    isn: 0x1234_5678,
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
            PROTO_TCP => self.handle_tcp(src, dst, start, end),
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

    // ---- TCP (RFC 9293, timer RFC 6298) ----------------------------------------------------

    fn tcp_checksum(&self, src: Ip, dst: Ip, seg: &[u8]) -> u16 {
        let mut pseudo = [0u8; 12];
        pseudo[..4].copy_from_slice(&src);
        pseudo[4..8].copy_from_slice(&dst);
        pseudo[9] = PROTO_TCP;
        pseudo[10..12].copy_from_slice(&(seg.len() as u16).to_be_bytes());
        checksum(&[&pseudo, seg])
    }

    /// Sends one segment of connection `ci` with `flags`, `seq`, the current `rcv_nxt` as
    /// the acknowledgment, `data`, and an MSS option on SYN.
    fn tcp_send_segment(&mut self, ci: usize, flags: u8, seq: u32, data: &[u8]) -> bool {
        let c = self.conns[ci];
        let o = 34;
        let with_mss = flags & TCP_SYN != 0;
        let hlen = if with_mss { 24 } else { 20 };
        let h = &mut self.tx_frame[o..o + hlen];
        h.fill(0);
        h[0..2].copy_from_slice(&c.local_port.to_be_bytes());
        h[2..4].copy_from_slice(&c.remote_port.to_be_bytes());
        h[4..8].copy_from_slice(&seq.to_be_bytes());
        h[8..12].copy_from_slice(&c.rcv_nxt.to_be_bytes());
        h[12] = ((hlen / 4) as u8) << 4;
        h[13] = flags;
        let window = TCP_WINDOW.saturating_sub(c.rx_len as u16);
        h[14..16].copy_from_slice(&window.to_be_bytes());
        if with_mss {
            h[20..24].copy_from_slice(&[
                2,
                4,
                (TCP_SEG_MAX >> 8) as u8,
                (TCP_SEG_MAX & 0xFF) as u8,
            ]);
        }
        self.tx_frame[o + hlen..o + hlen + data.len()].copy_from_slice(data);
        let total = hlen + data.len();
        let csum = self.tcp_checksum(self.ip, c.remote_ip, &self.tx_frame[o..o + total]);
        self.tx_frame[o + 16..o + 18].copy_from_slice(&csum.to_be_bytes());
        self.send_ipv4(c.remote_ip, PROTO_TCP, total, c.remote_mac)
    }

    /// Starts the retransmission timer for the in-flight segment (RFC 6298 §5.1).
    fn tcp_arm(&mut self, ci: usize, now: u64) {
        let c = &mut self.conns[ci];
        c.sent_at = now;
        c.timer_due = Some(now + c.rto);
    }

    /// Transmits (or re-transmits) the in-flight segment of `ci`.
    fn tcp_transmit_unacked(&mut self, ci: usize, now: u64) {
        let c = self.conns[ci];
        if c.drop_next {
            // The injected loss: the segment is not put on the wire; the timer runs anyway.
            self.conns[ci].drop_next = false;
            self.tcp_arm(ci, now);
            return;
        }
        let mut flags = TCP_ACK | c.unacked_flags;
        if c.unacked_flags & TCP_SYN != 0 {
            flags = TCP_SYN; // the first SYN carries no ACK
        }
        if c.unacked_len > 0 {
            flags |= TCP_PSH;
        }
        let mut data = [0u8; TCP_SEG_MAX];
        data[..c.unacked_len].copy_from_slice(&c.unacked[..c.unacked_len]);
        self.tcp_send_segment(ci, flags, c.snd_una, &data[..c.unacked_len]);
        self.tcp_arm(ci, now);
    }

    /// Puts `data` (and/or control flags) in flight: `snd_nxt` advances by its sequence
    /// space; the caller then waits for the acknowledgment.
    fn tcp_queue(&mut self, ci: usize, flags: u8, data: &[u8], now: u64) {
        let c = &mut self.conns[ci];
        c.unacked[..data.len()].copy_from_slice(data);
        c.unacked_len = data.len();
        c.unacked_flags = flags;
        c.retransmitted = false;
        let space =
            data.len() as u32 + u32::from(flags & TCP_SYN != 0) + u32::from(flags & TCP_FIN != 0);
        c.snd_nxt = c.snd_una.wrapping_add(space);
        self.tcp_transmit_unacked(ci, now);
    }

    /// Expired timers: retransmit the earliest unacknowledged segment with the RTO doubled
    /// (RFC 6298 §5.5–5.6); after TCP_MAX_RETRIES the connection is reset locally.
    fn tcp_timers(&mut self, now: u64) {
        for ci in 0..MAX_CONNS {
            let c = self.conns[ci];
            if c.state == TcpState::TimeWait && now >= c.time_wait_until {
                self.conns[ci] = NO_CONN;
                continue;
            }
            let Some(due) = c.timer_due else {
                continue;
            };
            if now < due || c.snd_una == c.snd_nxt {
                continue;
            }
            if c.retransmits >= TCP_MAX_RETRIES {
                self.conns[ci].fault = Fault::Timeout;
                self.conns[ci].state = TcpState::Closed;
                self.conns[ci].timer_due = None;
                self.tcp_send_segment(ci, TCP_RST | TCP_ACK, c.snd_una, &[]);
                continue;
            }
            self.conns[ci].retransmits += 1;
            self.conns[ci].retransmitted = true;
            self.conns[ci].rto = (c.rto * 2).min(RTO_MAX);
            self.tcp_transmit_unacked(ci, now);
        }
    }

    fn next_timer(&self) -> Option<u64> {
        self.conns
            .iter()
            .filter_map(|c| match c.state {
                TcpState::Closed => None,
                TcpState::TimeWait => Some(c.time_wait_until),
                _ => c.timer_due,
            })
            .min()
    }

    /// An RTT sample (RFC 6298 §2.2–2.4; granularity 1 tick, K = 4, bounds applied).
    fn tcp_rtt_sample(&mut self, ci: usize, r: u64) {
        let c = &mut self.conns[ci];
        match c.srtt {
            None => {
                c.srtt = Some(r);
                c.rttvar = r / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(r);
                c.rttvar = (c.rttvar * 3 + diff) / 4;
                c.srtt = Some((srtt * 7 + r) / 8);
            }
        }
        let rto = c.srtt.unwrap_or(r) + (4 * c.rttvar).max(1);
        c.rto = rto.clamp(RTO_MIN, RTO_MAX);
    }

    fn handle_tcp(&mut self, src: Ip, dst: Ip, start: usize, end: usize) {
        let seg_len = end - start;
        if seg_len < 20 {
            self.stats_rx_bad += 1;
            return;
        }
        let mut seg = [0u8; FRAME_MAX];
        seg[..seg_len].copy_from_slice(&self.rx_frame[start..end]);
        let seg = &seg[..seg_len];
        if self.tcp_checksum(src, dst, seg) != 0 {
            self.stats_rx_bad += 1;
            return;
        }
        let (sport, dport) = (u16_at(seg, 0), u16_at(seg, 2));
        let seq = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
        let ack = u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]);
        let hlen = usize::from(seg[12] >> 4) * 4;
        let flags = seg[13];
        let window = u16_at(seg, 14);
        if hlen < 20 || hlen > seg_len {
            self.stats_rx_bad += 1;
            return;
        }
        let Some(ci) = (0..MAX_CONNS).find(|&i| {
            let c = &self.conns[i];
            c.state != TcpState::Closed
                && c.local_port == dport
                && c.remote_port == sport
                && c.remote_ip == src
        }) else {
            // No connection (CLOSED): a reset answers anything but a reset (RFC 9293 §3.10.7.1).
            if flags & TCP_RST == 0 {
                let mut smac = [0u8; 6];
                smac.copy_from_slice(&self.rx_frame[6..12]);
                self.tcp_send_reset(src, smac, dport, sport, seq, ack, flags, seg_len - hlen);
            }
            return;
        };
        let now = libnawah::clock_ticks();
        let data = &seg[hlen..];
        let c = self.conns[ci];
        if flags & TCP_RST != 0 {
            self.conns[ci].fault = Fault::Reset;
            self.conns[ci].state = TcpState::Closed;
            self.conns[ci].timer_due = None;
            return;
        }
        // MSS option on SYN segments.
        if flags & TCP_SYN != 0 {
            let mut i = 20;
            while i + 1 < hlen {
                match seg[i] {
                    0 => break,
                    1 => i += 1,
                    2 if i + 4 <= hlen => {
                        let mss = u16_at(seg, i + 2);
                        self.conns[ci].mss = mss.clamp(64, TCP_SEG_MAX as u16);
                        i += 4;
                    }
                    _ => {
                        let l = usize::from(seg[i + 1]).max(2);
                        i += l;
                    }
                }
            }
        }
        match c.state {
            TcpState::SynSent => {
                if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 && ack == c.snd_nxt {
                    let cc = &mut self.conns[ci];
                    cc.rcv_nxt = seq.wrapping_add(1);
                    cc.snd_una = ack;
                    cc.snd_wnd = window;
                    cc.timer_due = None;
                    cc.unacked_len = 0;
                    cc.unacked_flags = 0;
                    cc.state = TcpState::Established;
                    if c.retransmitted {
                        cc.rto = cc.rto.max(RTO_AFTER_SYN_LOSS);
                    } else {
                        let r = now.saturating_sub(c.sent_at);
                        self.tcp_rtt_sample(ci, r);
                    }
                    self.tcp_send_segment(ci, TCP_ACK, self.conns[ci].snd_nxt, &[]);
                }
                return;
            }
            TcpState::TimeWait => {
                // The peer's FIN again (our last ACK was lost): acknowledge it once more.
                if flags & TCP_FIN != 0 {
                    let nxt = c.snd_nxt;
                    self.tcp_send_segment(ci, TCP_ACK, nxt, &[]);
                }
                return;
            }
            TcpState::Closed => return,
            _ => {}
        }
        // Acknowledgments of our in-flight data (RFC 9293 §3.10.7.4).
        if flags & TCP_ACK != 0 && c.snd_una != c.snd_nxt {
            let acked_all =
                ack.wrapping_sub(c.snd_una) as i32 > 0 && ack.wrapping_sub(c.snd_nxt) as i32 >= 0;
            if acked_all {
                let cc = &mut self.conns[ci];
                cc.snd_una = cc.snd_nxt;
                cc.unacked_len = 0;
                let had_fin = cc.unacked_flags & TCP_FIN != 0;
                cc.unacked_flags = 0;
                cc.timer_due = None;
                cc.snd_wnd = window;
                if !c.retransmitted {
                    let r = now.saturating_sub(c.sent_at);
                    self.tcp_rtt_sample(ci, r);
                }
                if had_fin {
                    let cc = &mut self.conns[ci];
                    cc.state = match cc.state {
                        TcpState::FinWait1 => TcpState::FinWait2,
                        TcpState::Closing => TcpState::TimeWait,
                        TcpState::LastAck => TcpState::Closed,
                        s => s,
                    };
                    if cc.state == TcpState::TimeWait {
                        cc.time_wait_until = now + TIME_WAIT_TICKS;
                    }
                }
            }
        }
        // In-order data and FIN; anything else is dropped and the current ACK repeated.
        let mut advanced = false;
        if seq == self.conns[ci].rcv_nxt {
            let room = TCP_RX_MAX - self.conns[ci].rx_len;
            let n = data.len().min(room);
            if n == data.len() {
                let cc = &mut self.conns[ci];
                cc.rx[cc.rx_len..cc.rx_len + n].copy_from_slice(&data[..n]);
                cc.rx_len += n;
                cc.rcv_nxt = cc.rcv_nxt.wrapping_add(n as u32);
                advanced = n > 0;
                if flags & TCP_FIN != 0 && !cc.fin_received {
                    cc.fin_received = true;
                    cc.rcv_nxt = cc.rcv_nxt.wrapping_add(1);
                    advanced = true;
                    cc.state = match cc.state {
                        TcpState::Established => TcpState::CloseWait,
                        TcpState::FinWait1 => TcpState::Closing,
                        TcpState::FinWait2 => TcpState::TimeWait,
                        s => s,
                    };
                    if cc.state == TcpState::TimeWait {
                        cc.time_wait_until = now + TIME_WAIT_TICKS;
                    }
                }
            }
        } else if !data.is_empty() || flags & TCP_FIN != 0 {
            advanced = true; // out of order: acknowledge what we have
        }
        if advanced {
            let nxt = self.conns[ci].snd_nxt;
            self.tcp_send_segment(ci, TCP_ACK, nxt, &[]);
        }
    }

    /// RST for a segment that reached no connection (RFC 9293 §3.10.7.1).
    #[allow(clippy::too_many_arguments)]
    fn tcp_send_reset(
        &mut self,
        dst: Ip,
        dst_mac: Mac,
        local_port: u16,
        remote_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        data_len: usize,
    ) {
        let o = 34;
        let h = &mut self.tx_frame[o..o + 20];
        h.fill(0);
        h[0..2].copy_from_slice(&local_port.to_be_bytes());
        h[2..4].copy_from_slice(&remote_port.to_be_bytes());
        if flags & TCP_ACK != 0 {
            h[4..8].copy_from_slice(&ack.to_be_bytes());
            h[13] = TCP_RST;
        } else {
            let space =
                data_len as u32 + u32::from(flags & TCP_SYN != 0) + u32::from(flags & TCP_FIN != 0);
            h[8..12].copy_from_slice(&seq.wrapping_add(space).to_be_bytes());
            h[13] = TCP_RST | TCP_ACK;
        }
        h[12] = 5 << 4;
        let csum = self.tcp_checksum(self.ip, dst, &self.tx_frame[o..o + 20]);
        self.tx_frame[o + 16..o + 18].copy_from_slice(&csum.to_be_bytes());
        self.send_ipv4(dst, PROTO_TCP, 20, dst_mac);
    }

    /// Pumps frames and timers until `done` holds or `deadline` passes.
    fn tcp_wait(&mut self, deadline: u64, done: impl Fn(&TcpConn) -> bool, ci: usize) -> bool {
        loop {
            let now = libnawah::clock_ticks();
            self.tcp_timers(now);
            if done(&self.conns[ci]) {
                return true;
            }
            if now >= deadline {
                return false;
            }
            let next = self.next_timer().map_or(deadline, |t| t.min(deadline));
            self.pump(next.saturating_sub(now).clamp(1, 50));
        }
    }

    /// Active open: SYN, SYN+ACK, ACK (RFC 9293 §3.5), with the policy and ARP first.
    fn tcp_connect(&mut self, owner: usize, ip: Ip, port: u16, timeout: u64, out: &mut Out) {
        if !self.policy_allows(ip) {
            out.put(b"ERR POLICY");
            return;
        }
        let Some(ci) = self
            .conns
            .iter()
            .position(|c| c.owner == NO_OWNER && c.state == TcpState::Closed)
        else {
            out.put(b"ERR FULL");
            return;
        };
        let Some(mac) = self.resolve(ip) else {
            out.put(b"ERR ARP");
            return;
        };
        let local_port = self.next_port;
        self.next_port = if self.next_port == 65535 {
            49152
        } else {
            self.next_port + 1
        };
        self.isn = self.isn.wrapping_mul(1_103_515_245).wrapping_add(12345)
            ^ (libnawah::clock_ticks() as u32);
        let mut c = NO_CONN;
        c.id = self.next_conn;
        self.next_conn = self.next_conn.wrapping_add(1).max(1);
        c.state = TcpState::SynSent;
        c.owner = owner;
        c.local_port = local_port;
        c.remote_ip = ip;
        c.remote_port = port;
        c.remote_mac = mac;
        c.snd_una = self.isn;
        c.snd_nxt = self.isn;
        self.conns[ci] = c;
        let now = libnawah::clock_ticks();
        self.tcp_queue(ci, TCP_SYN, &[], now);
        self.tcp_wait(
            now + timeout,
            |c| c.state == TcpState::Established || c.state == TcpState::Closed,
            ci,
        );
        let c = self.conns[ci];
        if c.state == TcpState::Established {
            out.put(b"OK ");
            out.num(u64::from(c.id));
        } else {
            // A SYN still in flight is abandoned: a late SYN+ACK meets no connection and
            // is answered with RST.
            self.conns[ci] = NO_CONN;
            out.put(if c.fault == Fault::Reset {
                b"ERR REFUSED"
            } else {
                b"ERR TIMEOUT"
            });
        }
    }

    /// Sends `data` in segments of at most MSS, each acknowledged before the next.
    fn tcp_send(&mut self, ci: usize, data: &[u8], out: &mut Out) {
        let mut sent = 0;
        while sent < data.len() {
            let c = self.conns[ci];
            if c.state != TcpState::Established && c.state != TcpState::CloseWait {
                out.put(b"ERR CLOSED");
                return;
            }
            let n = (data.len() - sent).min(usize::from(c.mss)).min(TCP_SEG_MAX);
            let now = libnawah::clock_ticks();
            self.tcp_queue(ci, 0, &data[sent..sent + n], now);
            // Bounded by the retransmission limit, not by a deadline of its own.
            self.tcp_wait(
                u64::MAX,
                |c| c.snd_una == c.snd_nxt || c.state == TcpState::Closed,
                ci,
            );
            let c = self.conns[ci];
            if c.snd_una != c.snd_nxt || c.state == TcpState::Closed {
                out.put(match c.fault {
                    Fault::Reset => b"ERR RESET",
                    Fault::Timeout => b"ERR TIMEOUT",
                    Fault::None => b"ERR CLOSED",
                });
                return;
            }
            sent += n;
        }
        out.put(b"OK ");
        out.num(sent as u64);
    }

    fn tcp_recv(&mut self, ci: usize, timeout: u64, out: &mut Out) {
        let now = libnawah::clock_ticks();
        self.tcp_wait(
            now + timeout,
            |c| c.rx_len > 0 || c.fin_received || c.state == TcpState::Closed,
            ci,
        );
        let c = &mut self.conns[ci];
        if c.rx_len > 0 {
            out.put(b"OK ");
            let n = c.rx_len.min(1500);
            let mut data = [0u8; 1500];
            data[..n].copy_from_slice(&c.rx[..n]);
            c.rx.copy_within(n..c.rx_len, 0);
            c.rx_len -= n;
            out.put(&data[..n]);
        } else if c.fault == Fault::Reset {
            out.put(b"ERR RESET");
        } else if c.fin_received || c.state == TcpState::Closed {
            out.put(b"ERR CLOSED");
        } else {
            out.put(b"ERR TIMEOUT");
        }
    }

    /// Active (or passive after the peer's FIN) close: FIN, then the handshake to TIME-WAIT
    /// or CLOSED (RFC 9293 §3.6), bounded.
    fn tcp_close(&mut self, ci: usize, out: &mut Out) {
        let c = self.conns[ci];
        let now = libnawah::clock_ticks();
        match c.state {
            TcpState::Established | TcpState::CloseWait => {
                self.conns[ci].state = if c.state == TcpState::Established {
                    TcpState::FinWait1
                } else {
                    TcpState::LastAck
                };
                self.tcp_queue(ci, TCP_FIN, &[], now);
                self.tcp_wait(
                    now + 5000,
                    |c| matches!(c.state, TcpState::TimeWait | TcpState::Closed),
                    ci,
                );
            }
            TcpState::Closed => {}
            _ => {
                self.tcp_wait(
                    now + 5000,
                    |c| matches!(c.state, TcpState::TimeWait | TcpState::Closed),
                    ci,
                );
            }
        }
        let c = self.conns[ci];
        if c.state == TcpState::TimeWait {
            self.conns[ci].owner = NO_OWNER; // lingers for 2 MSL, held by nobody
        } else if c.state == TcpState::Closed {
            self.conns[ci] = NO_CONN;
        } else {
            // The close handshake did not finish in time: abort (RST) rather than linger.
            self.tcp_abort(ci);
        }
        out.put(b"OK");
    }

    fn tcp_status(&self, ci: usize, out: &mut Out) {
        let c = &self.conns[ci];
        out.put(b"OK state=");
        out.put(c.state.name());
        out.put(b" retransmits=");
        out.num(u64::from(c.retransmits));
        out.put(b" rto=");
        out.num(c.rto);
        out.put(b" srtt=");
        out.num(c.srtt.unwrap_or(0));
        out.put(b" mss=");
        out.num(u64::from(c.mss));
        out.put(b" unacked=");
        out.num(c.snd_nxt.wrapping_sub(c.snd_una) as u64);
        out.put(b" rx_pending=");
        out.num(c.rx_len as u64);
    }

    /// Drops a connection with a reset to the peer.
    fn tcp_abort(&mut self, ci: usize) {
        let c = self.conns[ci];
        if matches!(
            c.state,
            TcpState::SynSent
                | TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
        ) {
            self.tcp_send_segment(ci, TCP_RST | TCP_ACK, c.snd_nxt, &[]);
        }
        self.conns[ci] = NO_CONN;
    }

    /// The slot of the connection `id` held by `owner`.
    fn find_conn(&self, id: u64, owner: usize) -> Option<usize> {
        (0..MAX_CONNS).find(|&i| self.conns[i].owner == owner && u64::from(self.conns[i].id) == id)
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
            b"TCP_CONNECT" => {
                let (Some(ip), Some(port)) = (
                    f.next().and_then(parse_ip),
                    f.next()
                        .and_then(parse_u64)
                        .filter(|p| *p > 0 && *p < 65536),
                ) else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                let timeout = f.next().and_then(parse_u64).unwrap_or(5000).min(60_000);
                self.tcp_connect(ci, ip, port as u16, timeout, out);
            }
            b"TCP_SEND" | b"TCP_RECV" | b"TCP_CLOSE" | b"TCP_STATUS" | b"TCP_INJECT" => {
                let Some(id) = f.next().and_then(parse_u64) else {
                    out.put(b"ERR BAD_REQUEST");
                    return;
                };
                let Some(conn) = self.find_conn(id, ci) else {
                    // Released by TCP_CLOSE (identifiers are never reused) or never this
                    // client's.
                    out.put(b"ERR CLOSED");
                    return;
                };
                match verb {
                    b"TCP_SEND" => {
                        let data = f.rest();
                        if data.is_empty() || data.len() > 1500 {
                            out.put(b"ERR BAD_REQUEST");
                            return;
                        }
                        let mut copy = [0u8; 1500];
                        copy[..data.len()].copy_from_slice(data);
                        self.tcp_send(conn, &copy[..data.len()], out);
                    }
                    b"TCP_RECV" => {
                        let timeout = f.next().and_then(parse_u64).unwrap_or(0).min(60_000);
                        self.tcp_recv(conn, timeout, out);
                    }
                    b"TCP_CLOSE" => self.tcp_close(conn, out),
                    b"TCP_STATUS" => self.tcp_status(conn, out),
                    _ => {
                        // Diagnostic (net.md ب): `drop_next=1` loses the connection's next
                        // transmission once, so the retransmission timer is exercised in the lab.
                        if f.next() != Some(b"drop_next=1") {
                            out.put(b"ERR BAD_REQUEST");
                            return;
                        }
                        self.conns[conn].drop_next = true;
                        out.put(b"OK");
                    }
                }
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
        let now = libnawah::clock_ticks();
        st.tcp_timers(now);
        let timeout = st
            .next_timer()
            .map_or(libnawah::TIMEOUT_FOREVER, |t| t.saturating_sub(now).max(1));
        let wait = libnawah::object_wait_many(&entries[..k], timeout);
        let Ok((idx, _)) = wait else {
            if wait == Err(libnawah::ERR_TIMED_OUT) {
                continue;
            }
            return 0xE5;
        };
        if idx == 1 {
            st.pump(0);
            continue;
        }
        if idx == 0 {
            match libnawah::channel_read(boot, &mut st.msg, &mut hs, false) {
                Ok((n, nh)) => {
                    if (st.msg[..n] == *b"CONNECT" || st.msg[..n].starts_with(b"CONNECT "))
                        && nh == 1
                    {
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
                // The client's connections are reset (no graceful close for a vanished client).
                for cn in 0..MAX_CONNS {
                    if st.conns[cn].owner == ci {
                        st.tcp_abort(cn);
                    }
                }
            }
            Err(_) => {}
        }
    }
}
