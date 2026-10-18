//! The network interface layer (WP-27, ADR-0017): one virtio-net device behind a lock, raw
//! Ethernet frames in and out, polled from the timer tick for arrivals. Protocols live in the
//! `net` service (netd, WP-28); the kernel only moves frames and keeps the DMA buffers.

use alloc::sync::Arc;

use crate::arch::pci::Device;
use crate::drivers::virtio_net::{NetError, NetInfo, NetStats, VirtioNet};
use crate::object::kbd::KeyboardObject;
use crate::object::nic::NicObject;
use crate::sync::IrqSpinLock;

static DEVICE: IrqSpinLock<Option<VirtioNet>> = IrqSpinLock::new("net", None);
/// The objects the timer tick feeds: created once, handed to the service manager at boot
/// (and to the test kernel's cases).
static NIC_OBJECT: IrqSpinLock<Option<Arc<NicObject>>> = IrqSpinLock::new("nic-object", None);
static KBD_OBJECT: IrqSpinLock<Option<Arc<KeyboardObject>>> = IrqSpinLock::new("kbd-object", None);

pub fn nic_object() -> Arc<NicObject> {
    let mut g = NIC_OBJECT.lock();
    g.get_or_insert_with(|| Arc::new(NicObject::new())).clone()
}

pub fn keyboard_object() -> Arc<KeyboardObject> {
    let mut g = KBD_OBJECT.lock();
    g.get_or_insert_with(|| Arc::new(KeyboardObject::new()))
        .clone()
}

/// Timer tick on CPU 0 (interrupt context, ADR-0017): a waiting received frame wakes the NIC
/// object's waiters; keyboard bytes move from the controller into the ring and wake its
/// waiters. Nothing here takes a lock an interrupted thread could hold (irqsave locks mask
/// the timer).
pub fn tick_poll() {
    if rx_pending() {
        let nic = NIC_OBJECT.lock().clone();
        if let Some(n) = nic {
            for tid in n.take_waiters() {
                crate::sched::wake(tid);
            }
        }
    }
    let mut polled = 0;
    while polled < 8 {
        let Some(byte) = crate::arch::i8042::poll_byte() else {
            break;
        };
        polled += 1;
        let kbd = KBD_OBJECT.lock().clone();
        if let Some(k) = kbd {
            for tid in k.push(byte) {
                crate::sched::wake(tid);
            }
        }
    }
}

/// Brings up the first virtio-net function among `devices`; `Ok(None)` when there is none.
pub fn init(devices: &[Device]) -> Result<Option<NetInfo>, &'static str> {
    match VirtioNet::init(devices) {
        Ok(dev) => {
            let info = dev.info();
            *DEVICE.lock() = Some(dev);
            Ok(Some(info))
        }
        Err(NetError::NoDevice) => Ok(None),
        Err(e) => Err(e.code()),
    }
}

pub fn info() -> Option<NetInfo> {
    DEVICE.lock().as_ref().map(|d| d.info())
}

pub fn stats() -> NetStats {
    DEVICE
        .lock()
        .as_ref()
        .map(|d| d.stats())
        .unwrap_or_default()
}

pub fn link_up() -> bool {
    DEVICE.lock().as_ref().is_some_and(|d| d.link_up())
}

pub fn frames() -> usize {
    DEVICE.lock().as_ref().map_or(0, |d| d.frames())
}

pub fn tx_in_flight() -> u32 {
    DEVICE.lock().as_mut().map_or(0, |d| d.tx_in_flight())
}

/// Slots in flight as the driver currently records them (no reclaim; diagnostics).
#[cfg(feature = "ktest")]
pub fn tx_in_flight_raw() -> u32 {
    DEVICE.lock().as_ref().map_or(0, |d| d.tx_in_flight_raw())
}

/// Test hook: marks every transmit slot in flight (or releases them), so the refusal path is
/// exercised whatever the device's speed (TST-M4-NET-LIMITS).
#[cfg(feature = "ktest")]
pub fn inject_tx_full(full: bool) {
    if let Some(d) = DEVICE.lock().as_mut() {
        d.inject_tx_full(full);
    }
}

pub fn send(frame: &[u8]) -> Result<(), NetError> {
    DEVICE
        .lock()
        .as_mut()
        .ok_or(NetError::NoDevice)?
        .send(frame)
}

/// One received frame into `out`, or `None`.
pub fn recv(out: &mut [u8]) -> Option<usize> {
    DEVICE.lock().as_mut().and_then(|d| d.recv(out))
}

pub fn rx_pending() -> bool {
    DEVICE.lock().as_ref().is_some_and(|d| d.rx_pending())
}

/// Ethernet/ARP constants for the self-check (RFC 826 / IEEE 802.3, docs/sources.json S53).
const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

/// Builds an ARP request for `target_ip` from `mac`/`sender_ip` (a 42-byte frame).
pub fn arp_request(mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[..6].copy_from_slice(&[0xFF; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // hardware type Ethernet
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // protocol IPv4
    f[18] = 6;
    f[19] = 4;
    f[20..22].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&sender_ip);
    f[38..42].copy_from_slice(&target_ip);
    f
}

/// Whether `frame` is an ARP reply from `target_ip`; the replying MAC.
pub fn arp_reply_from(frame: &[u8], target_ip: [u8; 4]) -> Option<[u8; 6]> {
    if frame.len() < 42
        || u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_ARP
        || u16::from_be_bytes([frame[20], frame[21]]) != ARP_REPLY
        || frame[28..32] != target_ip
    {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[22..28]);
    Some(mac)
}

/// The lab's user-mode network (QEMU SLIRP): the guest is 10.0.2.15, the gateway 10.0.2.2.
pub const LAB_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
pub const LAB_GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

/// ARP round trip with the gateway: `Ok(gateway mac, ticks waited)`.
pub fn arp_probe(timeout_ticks: u64) -> Result<([u8; 6], u64), NetError> {
    let info = info().ok_or(NetError::NoDevice)?;
    let req = arp_request(info.mac, LAB_GUEST_IP, LAB_GATEWAY_IP);
    send(&req)?;
    let t0 = crate::sched::ticks();
    let mut buf = alloc::vec![0u8; crate::drivers::virtio_net::FRAME_MAX];
    let mut found = None;
    crate::sched::poll_until(t0 + timeout_ticks, || {
        while let Some(n) = recv(&mut buf) {
            if let Some(mac) = arp_reply_from(&buf[..n], LAB_GATEWAY_IP) {
                found = Some(mac);
                return true;
            }
        }
        false
    });
    found
        .map(|mac| (mac, crate::sched::ticks() - t0))
        .ok_or(NetError::Busy)
}

/// The `kernel|net|…` boot line: device, MAC, link, queues, DMA frames, and the ARP
/// self-check against the lab gateway.
pub fn boot_line(devices: &[Device]) -> alloc::string::String {
    use core::fmt::Write as _;
    let mut line = alloc::string::String::with_capacity(200);
    match init(devices) {
        Ok(Some(info)) => {
            let probe = arp_probe(500);
            let (gw, waited, code) = match probe {
                Ok((mac, t)) => (mac, t, "ok"),
                Err(e) => ([0; 6], 0, e.code()),
            };
            let st = stats();
            let _ = write!(
                line,
                "device={:#x}|bdf={:#x}|mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}|link={}|features={:#x}|queue_size={}|dma_frames={}|gateway={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}|arp_ticks={}|rx_frames={}|tx_frames={}|rx_bad={}|tx_in_flight={}|mmio={:#x}|code={}|selfcheck={}",
                info.device_id,
                (u32::from(info.bdf.bus) << 16) | (u32::from(info.bdf.device) << 8) | u32::from(info.bdf.function),
                info.mac[0], info.mac[1], info.mac[2], info.mac[3], info.mac[4], info.mac[5],
                u8::from(link_up()),
                info.features,
                info.queue_size,
                frames(),
                gw[0], gw[1], gw[2], gw[3], gw[4], gw[5],
                waited,
                st.rx_frames,
                st.tx_frames,
                st.rx_bad,
                tx_in_flight(),
                info.mmio,
                code,
                u8::from(code == "ok")
            );
        }
        Ok(None) => {
            let _ = write!(line, "device=none|code=K_E_NET_NO_DEVICE|selfcheck=0");
        }
        Err(code) => {
            let _ = write!(line, "code={code}|selfcheck=0");
        }
    }
    line
}
