//! virtio-net over modern virtio-pci with two split virtqueues (WP-27, ADR-0017). Frames are
//! moved through driver-owned DMA buffers (the DMA trust model of the threat model: the device
//! is only ever given addresses of frames the driver allocated, with fixed lengths); receive
//! completion is observed by polling the used ring from the timer tick (no device interrupt
//! yet: the I/O APIC stays masked, ADR-0005, R-23).
//!
//! References (Virtio 1.3, docs/sources.json S42 and S51): transport and split virtqueue as in
//! `virtio_blk.rs`; §5.1 network device: Device ID 1 (PCI 0x1041 modern, 0x1000
//! transitional), virtqueues receiveq1 = 0 and transmitq1 = 1, VIRTIO_NET_F_MAC = bit 5,
//! VIRTIO_NET_F_STATUS = bit 16 (config: u8 mac[6], le16 status — bit 0 LINK_UP),
//! struct virtio_net_hdr {u8 flags; u8 gso_type; le16 hdr_len; le16 gso_size; le16 csum_start;
//! le16 csum_offset; le16 num_buffers} = 12 bytes (num_buffers always present for a
//! non-legacy driver; the device sets it to 1 without MRG_RXBUF); a transmitted packet without
//! offloads has flags 0 and gso_type NONE (0); receive buffers of at least 1526 bytes and one
//! descriptor per packet when MRG_RXBUF is not negotiated.

use core::sync::atomic::{fence, Ordering};

use crate::arch::mmio::{
    read16 as rd16, read32 as rd32, read8 as rd8, write16 as wr16, write32 as wr32, write8 as wr8,
};
use crate::arch::pci::{self, Bar, Device};
use crate::mm::dma;
use crate::mm::pmm::{self, Frame};

pub const VENDOR_VIRTIO: u16 = 0x1AF4;
pub const DEVICE_NET_MODERN: u16 = 0x1041;
pub const DEVICE_NET_TRANSITIONAL: u16 = 0x1000;

const CAP_VENDOR: u8 = 0x09;
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_DEVICE: u8 = 4;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_NEEDS_RESET: u8 = 64;
const STATUS_FAILED: u8 = 128;

const F_VERSION_1: u64 = 1 << 32;
const NET_F_MAC: u64 = 1 << 5;
const NET_F_STATUS: u64 = 1 << 16;

const DESC_F_WRITE: u16 = 2;

/// virtio_net_hdr size for a non-legacy driver (§5.1.6).
pub const HDR_LEN: usize = 12;
/// Largest Ethernet frame carried (no jumbo frames, no offloads).
pub const FRAME_MAX: usize = 1514;
/// Shortest frame the driver accepts from a sender (Ethernet header).
pub const FRAME_MIN: usize = 14;
/// Each buffer slot: header + frame, rounded to 2 KiB (two slots per page).
const SLOT: usize = 2048;
/// Queue size (descriptors) for each of the two queues; the device's maximum when smaller.
const QUEUE_SIZE: u16 = 16;
const RX: u16 = 0;
const TX: u16 = 1;
/// Frames: one queue page per queue, then the RX slots, then the TX slots.
const SLOT_PAGES: usize = (QUEUE_SIZE as usize) * SLOT / 4096;
pub const DMA_FRAMES: usize = 2 + 2 * SLOT_PAGES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    NoDevice,
    NoCommonCfg,
    NoNotifyCfg,
    NoDeviceCfg,
    BadBar,
    Map,
    FeaturesRejected,
    NoVersion1,
    NoMac,
    QueueUnavailable,
    OutOfFrames,
    DeviceNeedsReset,
    /// Every transmit slot is in flight.
    Busy,
    /// The frame length is outside FRAME_MIN..=FRAME_MAX.
    Range,
}

impl NetError {
    pub fn code(&self) -> &'static str {
        match self {
            NetError::NoDevice => "K_E_NET_NO_DEVICE",
            NetError::NoCommonCfg => "K_E_NET_NO_COMMON_CFG",
            NetError::NoNotifyCfg => "K_E_NET_NO_NOTIFY_CFG",
            NetError::NoDeviceCfg => "K_E_NET_NO_DEVICE_CFG",
            NetError::BadBar => "K_E_NET_BAD_BAR",
            NetError::Map => "K_E_NET_MAP",
            NetError::FeaturesRejected => "K_E_NET_FEATURES_REJECTED",
            NetError::NoVersion1 => "K_E_NET_NO_VERSION_1",
            NetError::NoMac => "K_E_NET_NO_MAC",
            NetError::QueueUnavailable => "K_E_NET_QUEUE_UNAVAILABLE",
            NetError::OutOfFrames => "K_E_NET_OUT_OF_FRAMES",
            NetError::DeviceNeedsReset => "K_E_NET_NEEDS_RESET",
            NetError::Busy => "K_E_NET_BUSY",
            NetError::Range => "K_E_NET_RANGE",
        }
    }
}

fn wr64(a: u64, v: u64) {
    wr32(a, v as u32);
    wr32(a + 4, (v >> 32) as u32);
}

#[derive(Clone, Copy, Debug)]
pub struct NetInfo {
    pub bdf: pci::Bdf,
    pub device_id: u16,
    pub mac: [u8; 6],
    pub features: u64,
    pub queue_size: u16,
    pub mmio: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NetStats {
    pub rx_frames: u64,
    pub tx_frames: u64,
    /// Received packets longer than FRAME_MAX or shorter than FRAME_MIN (dropped).
    pub rx_bad: u64,
    /// `send` calls refused because every transmit slot was in flight.
    pub tx_busy: u64,
}

struct Queue {
    desc: u64,
    avail: u64,
    used: u64,
    notify_addr: u64,
    size: u16,
    avail_idx: u16,
    last_used: u16,
    /// Physical address of slot 0 (slot i at `slots + i * SLOT`).
    slots: u64,
}

pub struct VirtioNet {
    common: u64,
    device_cfg: u64,
    rx: Queue,
    tx: Queue,
    /// TX slots whose descriptor is in flight (bit i = descriptor/slot i).
    tx_in_flight: u32,
    first_frame: Frame,
    info: NetInfo,
    stats: NetStats,
}

struct Caps {
    common: Option<(u8, u32)>,
    notify: Option<(u8, u32, u32)>,
    device: Option<(u8, u32)>,
}

fn find_caps(dev: &Device) -> Caps {
    let mut caps = Caps {
        common: None,
        notify: None,
        device: None,
    };
    for c in dev.capabilities() {
        if c.id != CAP_VENDOR {
            continue;
        }
        let o = u16::from(c.offset);
        let cfg_type = dev.read8(o + 3);
        let bar = dev.read8(o + 4);
        let offset = dev.read32(o + 8);
        match cfg_type {
            CFG_COMMON if caps.common.is_none() => caps.common = Some((bar, offset)),
            CFG_NOTIFY if caps.notify.is_none() => {
                let mult = dev.read32(o + 16);
                caps.notify = Some((bar, offset, mult));
            }
            CFG_DEVICE if caps.device.is_none() => caps.device = Some((bar, offset)),
            _ => {}
        }
    }
    caps
}

fn map_bar(dev: &Device, bar: u8) -> Result<u64, NetError> {
    match dev.bar(bar) {
        Bar::Memory { base, size, .. } if base != 0 && size != 0 => {
            crate::mm::vmm::map_mmio(base, size.min(1 << 20)).map_err(|_| NetError::Map)
        }
        _ => Err(NetError::BadBar),
    }
}

/// Selects queue `n` and sets it up at `page` (desc at 0, avail at 0x400, used at 0x800).
fn setup_queue(
    common: u64,
    notify_base: u64,
    nmult: u32,
    n: u16,
    page: u64,
    slots: u64,
) -> Result<Queue, NetError> {
    wr16(common + 22, n);
    let max = rd16(common + 24);
    if max == 0 {
        return Err(NetError::QueueUnavailable);
    }
    let size = QUEUE_SIZE.min(max);
    wr16(common + 24, size);
    dma::bytes_mut(page, 4096).fill(0);
    let (desc, avail, used) = (page, page + 0x400, page + 0x800);
    wr64(common + 32, desc);
    wr64(common + 40, avail);
    wr64(common + 48, used);
    let notify_off = rd16(common + 30);
    let notify_addr = notify_base + u64::from(notify_off) * u64::from(nmult);
    wr16(common + 28, 1);
    Ok(Queue {
        desc,
        avail,
        used,
        notify_addr,
        size,
        avail_idx: 0,
        last_used: 0,
        slots,
    })
}

impl Queue {
    fn desc_at(&self, i: u16) -> u64 {
        self.desc + u64::from(i) * 16
    }

    fn slot(&self, i: u16) -> u64 {
        self.slots + u64::from(i) * SLOT as u64
    }

    /// Writes descriptor `i` (one buffer, no chain) and makes it available.
    fn post(&mut self, i: u16, len: u32, device_writes: bool, queue_index: u16) {
        let d = self.desc_at(i);
        dma::write64(d, self.slot(i));
        dma::write32(d + 8, len);
        dma::write16(d + 12, if device_writes { DESC_F_WRITE } else { 0 });
        dma::write16(d + 14, 0);
        let ring_slot = u64::from(self.avail_idx % self.size);
        dma::write16(self.avail + 4 + ring_slot * 2, i);
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        dma::write16(self.avail + 2, self.avail_idx);
        fence(Ordering::SeqCst);
        wr16(self.notify_addr, queue_index);
    }

    /// The next used element (descriptor id, written length), if any.
    fn take_used(&mut self) -> Option<(u16, u32)> {
        fence(Ordering::SeqCst);
        if dma::read16(self.used + 2) == self.last_used {
            return None;
        }
        let elem = self.used + 4 + u64::from(self.last_used % self.size) * 8;
        let id = dma::read32(elem) as u16;
        let len = dma::read32(elem + 4);
        self.last_used = self.last_used.wrapping_add(1);
        Some((id, len))
    }

    fn has_used(&self) -> bool {
        fence(Ordering::SeqCst);
        dma::read16(self.used + 2) != self.last_used
    }
}

impl VirtioNet {
    /// Finds the first virtio network function among `devices` and brings it up (§3.1.1):
    /// VERSION_1 + MAC (+ STATUS when offered), both queues, every receive slot posted.
    pub fn init(devices: &[Device]) -> Result<VirtioNet, NetError> {
        let dev = devices
            .iter()
            .find(|d| {
                d.vendor == VENDOR_VIRTIO
                    && (d.device == DEVICE_NET_MODERN || d.device == DEVICE_NET_TRANSITIONAL)
            })
            .ok_or(NetError::NoDevice)?;
        dev.enable();
        let caps = find_caps(dev);
        let (cbar, coff) = caps.common.ok_or(NetError::NoCommonCfg)?;
        let (nbar, noff, nmult) = caps.notify.ok_or(NetError::NoNotifyCfg)?;
        let (dbar, doff) = caps.device.ok_or(NetError::NoDeviceCfg)?;
        let common = map_bar(dev, cbar)? + u64::from(coff);
        let notify_base = map_bar(dev, nbar)? + u64::from(noff);
        let device_cfg = map_bar(dev, dbar)? + u64::from(doff);

        wr8(common + 20, 0);
        while rd8(common + 20) != 0 {
            core::hint::spin_loop();
        }
        wr8(common + 20, STATUS_ACKNOWLEDGE);
        wr8(common + 20, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        wr32(common, 0);
        let f_lo = u64::from(rd32(common + 4));
        wr32(common, 1);
        let f_hi = u64::from(rd32(common + 4));
        let offered = f_lo | (f_hi << 32);
        if offered & F_VERSION_1 == 0 {
            wr8(common + 20, STATUS_FAILED);
            return Err(NetError::NoVersion1);
        }
        if offered & NET_F_MAC == 0 {
            wr8(common + 20, STATUS_FAILED);
            return Err(NetError::NoMac);
        }
        let accepted = offered & (F_VERSION_1 | NET_F_MAC | NET_F_STATUS);
        wr32(common + 8, 0);
        wr32(common + 12, accepted as u32);
        wr32(common + 8, 1);
        wr32(common + 12, (accepted >> 32) as u32);
        wr8(
            common + 20,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        if rd8(common + 20) & STATUS_FEATURES_OK == 0 {
            wr8(common + 20, STATUS_FAILED);
            return Err(NetError::FeaturesRejected);
        }
        let first = pmm::alloc_frames(DMA_FRAMES as u64).ok_or(NetError::OutOfFrames)?;
        let page = |i: usize| first.0 + (i as u64) * 4096;
        let rx_slots = page(2);
        let tx_slots = page(2 + SLOT_PAGES);
        for i in 0..2 * SLOT_PAGES {
            dma::bytes_mut(page(2 + i), 4096).fill(0);
        }
        let mut rx = setup_queue(common, notify_base, nmult, RX, page(0), rx_slots)?;
        let tx = setup_queue(common, notify_base, nmult, TX, page(1), tx_slots)?;
        wr8(
            common + 20,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
        let mut mac = [0u8; 6];
        for (i, m) in mac.iter_mut().enumerate() {
            *m = rd8(device_cfg + i as u64);
        }
        // Every receive slot is handed to the device from the start.
        for i in 0..rx.size {
            rx.post(i, SLOT as u32, true, RX);
        }
        let info = NetInfo {
            bdf: dev.bdf,
            device_id: dev.device,
            mac,
            features: accepted,
            queue_size: rx.size,
            mmio: common,
        };
        Ok(VirtioNet {
            common,
            device_cfg,
            rx,
            tx,
            tx_in_flight: 0,
            first_frame: first,
            info,
            stats: NetStats::default(),
        })
    }

    pub fn info(&self) -> NetInfo {
        self.info
    }

    pub fn stats(&self) -> NetStats {
        self.stats
    }

    /// Link state from the device configuration (always up when STATUS was not offered).
    pub fn link_up(&self) -> bool {
        if self.info.features & NET_F_STATUS == 0 {
            return true;
        }
        rd16(self.device_cfg + 6) & 1 != 0
    }

    pub fn frames(&self) -> usize {
        let _ = self.first_frame;
        DMA_FRAMES
    }

    /// Returns transmit slots the device has finished with.
    fn reclaim_tx(&mut self) {
        while let Some((id, _)) = self.tx.take_used() {
            if id < self.tx.size {
                self.tx_in_flight &= !(1 << id);
            }
        }
    }

    /// Queues one Ethernet frame for transmission (copied into a driver slot behind a zeroed
    /// virtio_net_hdr); `Busy` when every slot is in flight.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if frame.len() < FRAME_MIN || frame.len() > FRAME_MAX {
            return Err(NetError::Range);
        }
        if rd8(self.common + 20) & STATUS_NEEDS_RESET != 0 {
            return Err(NetError::DeviceNeedsReset);
        }
        self.reclaim_tx();
        let Some(slot) = (0..self.tx.size).find(|i| self.tx_in_flight & (1 << i) == 0) else {
            self.stats.tx_busy += 1;
            return Err(NetError::Busy);
        };
        let buf = dma::bytes_mut(self.tx.slot(slot), HDR_LEN + frame.len());
        buf[..HDR_LEN].fill(0);
        buf[HDR_LEN..].copy_from_slice(frame);
        self.tx_in_flight |= 1 << slot;
        self.tx
            .post(slot, (HDR_LEN + frame.len()) as u32, false, TX);
        self.stats.tx_frames += 1;
        Ok(())
    }

    /// Whether a received frame is waiting (cheap: one DMA-memory read; the tick polls it).
    pub fn rx_pending(&self) -> bool {
        self.rx.has_used()
    }

    /// Takes one received frame into `out` (without the virtio header); the frame length, or
    /// `None` when nothing is waiting. The slot goes straight back to the device. Frames
    /// outside the accepted sizes or larger than `out` are dropped and counted.
    pub fn recv(&mut self, out: &mut [u8]) -> Option<usize> {
        loop {
            let (id, written) = self.rx.take_used()?;
            let written = written as usize;
            let id = if id < self.rx.size { id } else { 0 };
            let result = if (HDR_LEN + FRAME_MIN..=HDR_LEN + FRAME_MAX).contains(&written)
                && written - HDR_LEN <= out.len()
            {
                let n = written - HDR_LEN;
                out[..n].copy_from_slice(&dma::bytes_mut(self.rx.slot(id) + HDR_LEN as u64, n)[..]);
                self.stats.rx_frames += 1;
                Some(n)
            } else {
                self.stats.rx_bad += 1;
                None
            };
            self.rx.post(id, SLOT as u32, true, RX);
            if result.is_some() {
                return result;
            }
        }
    }

    /// Transmit slots currently in flight after reclaiming finished ones (diagnostics).
    pub fn tx_in_flight(&mut self) -> u32 {
        self.reclaim_tx();
        self.tx_in_flight.count_ones()
    }

    #[cfg(feature = "ktest")]
    pub fn tx_in_flight_raw(&self) -> u32 {
        self.tx_in_flight.count_ones()
    }

    /// Test hook: pretends every slot is in flight (nothing is posted to the device, so no
    /// used entry will ever clear the marks until released).
    #[cfg(feature = "ktest")]
    pub fn inject_tx_full(&mut self, full: bool) {
        self.tx_in_flight = if full { (1u32 << self.tx.size) - 1 } else { 0 };
    }
}
