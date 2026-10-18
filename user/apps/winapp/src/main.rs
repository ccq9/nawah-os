//! winapp — a window client of the display service (WP-34, display.md §ب): one surface filled
//! orange with a blue square, shown in a window; a resize makes a new surface of the new size
//! (same picture, scaled square); a close request or the manager's STOP ends it. Started by
//! the manager as a service with the dependency `display`.

#![no_std]
#![no_main]

use libnawah::display::Surface;
use libnawah::{
    Handle, WaitEntry, ERR_PEER_CLOSED, ERR_SHOULD_WAIT, SIGNAL_PEER_CLOSED, SIGNAL_READABLE,
};

libnawah::entry!(main);

const W: u32 = 240;
const H: u32 = 160;
const ORANGE: u32 = 0xFF8800;
const BLUE: u32 = 0x2255CC;

fn paint(s: &Surface) {
    s.fill(ORANGE);
    let side = (s.w.min(s.h) / 4).max(1);
    s.fill_rect(s.w - side, s.h - side, side, side, BLUE);
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 9 {
        return None;
    }
    let mut v = 0u32;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    Some(v)
}

/// Sends a request and returns its reply, handling (ignoring) events that arrive first.
fn request(chan: Handle, req: &[u8], handles: &[Handle], reply: &mut [u8]) -> Result<usize, i64> {
    if libnawah::channel_write(chan, req, handles) != 0 {
        return Err(ERR_PEER_CLOSED);
    }
    loop {
        let mut hs = [0u32; 1];
        match libnawah::channel_read(chan, reply, &mut hs, false) {
            Ok((n, _)) if reply[..n].starts_with(b"OK") || reply[..n].starts_with(b"ERR") => {
                return Ok(n)
            }
            Ok(_) => {}
            Err(ERR_SHOULD_WAIT) => {
                let _ = libnawah::object_wait_many(
                    &[WaitEntry {
                        handle: chan,
                        signals: SIGNAL_READABLE | SIGNAL_PEER_CLOSED,
                    }],
                    5000,
                );
            }
            Err(e) => return Err(e),
        }
    }
}

fn main() -> u64 {
    let boot = libnawah::bootstrap_handle();
    if boot == 0 {
        return 0xE0;
    }
    let mut buf = [0u8; 256];
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
    // The frame's pixel format comes from the service (`STATUS … format=<n>`): clients do
    // not hold the display object.
    let Ok(n) = request(display, b"STATUS", &[], &mut buf) else {
        return 0xE3;
    };
    let Some(i) = buf[..n].windows(7).position(|w| w == b"format=") else {
        return 0xE3;
    };
    let Some(format) = parse_u32(&buf[i + 7..i + 8]) else {
        return 0xE3;
    };
    let Ok(mut surface) = Surface::new(W, H, format) else {
        return 0xE4;
    };
    paint(&surface);
    let Ok(share) = surface.share() else {
        return 0xE4;
    };
    let n = match request(display, b"CREATE_SURFACE 240 160", &[share], &mut buf) {
        Ok(n) => n,
        Err(_) => return 0xE5,
    };
    let Some(sid) = buf[..n].strip_prefix(b"OK ").and_then(parse_u32) else {
        return 0xE5;
    };
    let mut req = [0u8; 64];
    let mut out = Out {
        buf: &mut req,
        len: 0,
    };
    out.put(b"CREATE_WINDOW ");
    out.num(sid);
    out.put(b" winapp");
    let len = out.len;
    let n = match request(display, &req[..len], &[], &mut buf) {
        Ok(n) => n,
        Err(_) => return 0xE6,
    };
    let Some(wid) = buf[..n].strip_prefix(b"OK ").and_then(parse_u32) else {
        return 0xE6;
    };
    let mut req = [0u8; 64];
    let mut out = Out {
        buf: &mut req,
        len: 0,
    };
    out.put(b"COMMIT ");
    out.num(sid);
    out.put(b" 0 0 240 160");
    let len = out.len;
    if request(display, &req[..len], &[], &mut buf).is_err() {
        return 0xE7;
    }
    if libnawah::channel_write(boot, b"READY", &[]) != 0 {
        return 0xE8;
    }
    let mut cur_sid = sid;
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
            return 0xE9;
        };
        if idx == 0 {
            match libnawah::channel_read(boot, &mut buf, &mut hs, false) {
                Ok((n, nh)) => {
                    if nh == 1 {
                        libnawah::handle_close(hs[0]);
                    }
                    if &buf[..n] == b"STOP" {
                        return 0;
                    }
                }
                Err(ERR_PEER_CLOSED) => return 0,
                Err(_) => {}
            }
            continue;
        }
        let n = match libnawah::channel_read(display, &mut buf, &mut hs, false) {
            Ok((n, nh)) => {
                if nh == 1 {
                    libnawah::handle_close(hs[0]);
                }
                n
            }
            Err(ERR_PEER_CLOSED) => return 0,
            Err(_) => continue,
        };
        let msg = &buf[..n];
        let mut f = msg.split(|c| *c == b' ').filter(|f| !f.is_empty());
        match f.next().unwrap_or(b"") {
            b"CLOSE_REQUESTED" => return 0,
            b"RESIZED" => {
                let (Some(w), Some(h)) =
                    (f.nth(1).and_then(parse_u32), f.next().and_then(parse_u32))
                else {
                    continue;
                };
                let Ok(new) = Surface::new(w, h, format) else {
                    continue;
                };
                paint(&new);
                let Ok(share) = new.share() else {
                    new.destroy();
                    continue;
                };
                let mut req = [0u8; 64];
                let mut out = Out {
                    buf: &mut req,
                    len: 0,
                };
                out.put(b"CREATE_SURFACE ");
                out.num(w);
                out.put(b" ");
                out.num(h);
                let len = out.len;
                let mut reply = [0u8; 64];
                let Ok(n) = request(display, &req[..len], &[share], &mut reply) else {
                    return 0;
                };
                let Some(nsid) = reply[..n].strip_prefix(b"OK ").and_then(parse_u32) else {
                    new.destroy();
                    continue;
                };
                let mut req = [0u8; 64];
                let mut out = Out {
                    buf: &mut req,
                    len: 0,
                };
                out.put(b"ATTACH ");
                out.num(wid);
                out.put(b" ");
                out.num(nsid);
                let len = out.len;
                let _ = request(display, &req[..len], &[], &mut reply);
                let mut req = [0u8; 64];
                let mut out = Out {
                    buf: &mut req,
                    len: 0,
                };
                out.put(b"DESTROY_SURFACE ");
                out.num(cur_sid);
                let len = out.len;
                let _ = request(display, &req[..len], &[], &mut reply);
                let old = core::mem::replace(&mut surface, new);
                old.destroy();
                cur_sid = nsid;
                let mut req = [0u8; 64];
                let mut out = Out {
                    buf: &mut req,
                    len: 0,
                };
                out.put(b"COMMIT ");
                out.num(nsid);
                out.put(b" 0 0 ");
                out.num(w);
                out.put(b" ");
                out.num(h);
                let len = out.len;
                let _ = request(display, &req[..len], &[], &mut reply);
            }
            _ => {}
        }
    }
}

struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Out<'_> {
    fn put(&mut self, s: &[u8]) {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
        self.len += n;
    }
    fn num(&mut self, v: u32) {
        let mut v = v;
        let mut tmp = [0u8; 10];
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
}
