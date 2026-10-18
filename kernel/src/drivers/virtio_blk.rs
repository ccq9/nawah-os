//! virtio-blk over modern virtio-pci with a split virtqueue (WP-18, ADR-0013). Synchronous:
//! one request at a time, completion by polling the used ring (no interrupt is enabled; the
//! I/O APIC is masked, ADR-0005), data moved through a kernel-owned DMA buffer.
//!
//! References (Virtio 1.3, docs/sources.json S42): §4.1.2 PCI Device Discovery (Vendor
//! 0x1AF4, Device ID 0x1040 + 2 for block; transitional 0x1001); §4.1.4 virtio_pci_cap
//! (cap_vndr, cap_next, cap_len, cfg_type, bar, id, padding[2], le32 offset, le32 length;
//! cfg_type 1 common, 2 notify (+ le32 notify_off_multiplier), 3 ISR, 4 device);
//! §4.1.4.3 virtio_pci_common_cfg (device_feature_select 0, device_feature 4,
//! driver_feature_select 8, driver_feature 12, config_msix_vector 16, num_queues 18,
//! device_status 20, config_generation 21, queue_select 22, queue_size 24, queue_msix_vector 26,
//! queue_enable 28, queue_notify_off 30, queue_desc 32, queue_driver 40, queue_device 48);
//! §4.1.4.4 notification address = cap.offset + queue_notify_off * notify_off_multiplier;
//! §2.1 status bits (ACKNOWLEDGE 1, DRIVER 2, DRIVER_OK 4, FEATURES_OK 8, NEEDS_RESET 64,
//! FAILED 128); §3.1.1 initialization order; §6 VIRTIO_F_VERSION_1 = bit 32; §2.7 split
//! virtqueue (virtq_desc {le64 addr, le32 len, le16 flags, le16 next}, NEXT 1, WRITE 2;
//! virtq_avail {le16 flags, le16 idx, le16 ring[]}; virtq_used {le16 flags, le16 idx,
//! {le32 id, le32 len} ring[]}; alignment 16/2/4; power-of-two size); §5.2 block device
//! (virtio_blk_config.capacity le64 in 512-byte sectors; VIRTIO_BLK_F_FLUSH = 9;
//! virtio_blk_req {le32 type, le32 reserved, le64 sector, data[], u8 status};
//! VIRTIO_BLK_T_IN 0, OUT 1, FLUSH 4; status OK 0, IOERR 1, UNSUPP 2).

use core::sync::atomic::{fence, Ordering};

use crate::arch::mmio::{
    read16 as rd16, read32 as rd32, read8 as rd8, write16 as wr16, write32 as wr32, write8 as wr8,
};
use crate::arch::pci::{self, Bar, Device};
use crate::mm::dma;
use crate::mm::pmm::{self, Frame};

pub const VENDOR_VIRTIO: u16 = 0x1AF4;
pub const DEVICE_BLK_MODERN: u16 = 0x1042;
pub const DEVICE_BLK_TRANSITIONAL: u16 = 0x1001;
pub const SECTOR: usize = 512;

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
const BLK_F_FLUSH: u64 = 1 << 9;

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;

const T_IN: u32 = 0;
#[cfg_attr(not(feature = "ktest"), allow(dead_code))]
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const S_OK: u8 = 0;

/// Queue size used (the device's maximum is honoured when smaller).
const QUEUE_SIZE: u16 = 16;
/// Largest transfer per request: 64 KiB bounce buffer.
pub const MAX_SECTORS: usize = 128;
/// Polling bound per request (iterations of a PIT-free spin; the lab completes in microseconds).
const POLL_LIMIT: u64 = 50_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlkError {
    NoDevice,
    NoCommonCfg,
    NoNotifyCfg,
    NoDeviceCfg,
    BadBar,
    Map,
    FeaturesRejected,
    NoVersion1,
    QueueUnavailable,
    OutOfFrames,
    DeviceNeedsReset,
    /// The device returned a non-OK status (IOERR or UNSUPP).
    Io(u8),
    Timeout,
    /// Out of range or oversized request from the caller.
    Range,
}

impl BlkError {
    pub fn code(&self) -> &'static str {
        match self {
            BlkError::NoDevice => "K_E_BLK_NO_DEVICE",
            BlkError::NoCommonCfg => "K_E_BLK_NO_COMMON_CFG",
            BlkError::NoNotifyCfg => "K_E_BLK_NO_NOTIFY_CFG",
            BlkError::NoDeviceCfg => "K_E_BLK_NO_DEVICE_CFG",
            BlkError::BadBar => "K_E_BLK_BAD_BAR",
            BlkError::Map => "K_E_BLK_MAP",
            BlkError::FeaturesRejected => "K_E_BLK_FEATURES_REJECTED",
            BlkError::NoVersion1 => "K_E_BLK_NO_VERSION_1",
            BlkError::QueueUnavailable => "K_E_BLK_QUEUE_UNAVAILABLE",
            BlkError::OutOfFrames => "K_E_BLK_OUT_OF_FRAMES",
            BlkError::DeviceNeedsReset => "K_E_BLK_NEEDS_RESET",
            BlkError::Io(_) => "K_E_BLK_IO",
            BlkError::Timeout => "K_E_BLK_TIMEOUT",
            BlkError::Range => "K_E_BLK_RANGE",
        }
    }
}

/// 64-bit fields are written as two 32-bit halves (§4.1.4.3).
fn wr64(a: u64, v: u64) {
    wr32(a, v as u32);
    wr32(a + 4, (v >> 32) as u32);
}

#[derive(Clone, Copy, Debug)]
pub struct BlkInfo {
    pub bdf: pci::Bdf,
    pub device_id: u16,
    pub capacity_sectors: u64,
    pub queue_size: u16,
    pub features: u64,
    pub flush: bool,
    /// Where the common configuration registers are reached: inside `vmm::MMIO_BASE..MMIO_END`
    /// (shared by every address space), never at the BAR's physical address.
    pub mmio: u64,
}

pub struct VirtioBlk {
    common: u64,
    notify_addr: u64,
    /// Physical addresses of the queue parts and the DMA area.
    desc: u64,
    avail: u64,
    used: u64,
    /// Request header (16 bytes) and status byte live in one frame; data in `data_frames`.
    hdr: u64,
    data: u64,
    frames: [Frame; 1 + 1 + MAX_SECTORS * SECTOR / 4096],
    queue_size: u16,
    avail_idx: u16,
    last_used: u16,
    info: BlkInfo,
}

/// Capability bodies of the modern layout found in configuration space.
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

/// Maps BAR `bar` of `dev` (memory BAR) in the kernel's MMIO window and returns its address.
fn map_bar(dev: &Device, bar: u8) -> Result<u64, BlkError> {
    match dev.bar(bar) {
        Bar::Memory { base, size, .. } if base != 0 && size != 0 => {
            crate::mm::vmm::map_mmio(base, size.min(1 << 20)).map_err(|_| BlkError::Map)
        }
        _ => Err(BlkError::BadBar),
    }
}

impl VirtioBlk {
    /// Finds the first virtio block function among `devices` and brings it up (§3.1.1).
    pub fn init(devices: &[Device]) -> Result<VirtioBlk, BlkError> {
        let dev = devices
            .iter()
            .find(|d| {
                d.vendor == VENDOR_VIRTIO
                    && (d.device == DEVICE_BLK_MODERN || d.device == DEVICE_BLK_TRANSITIONAL)
            })
            .ok_or(BlkError::NoDevice)?;
        dev.enable();
        let caps = find_caps(dev);
        let (cbar, coff) = caps.common.ok_or(BlkError::NoCommonCfg)?;
        let (nbar, noff, nmult) = caps.notify.ok_or(BlkError::NoNotifyCfg)?;
        let (dbar, doff) = caps.device.ok_or(BlkError::NoDeviceCfg)?;
        let common = map_bar(dev, cbar)? + u64::from(coff);
        let notify_base = map_bar(dev, nbar)? + u64::from(noff);
        let device_cfg = map_bar(dev, dbar)? + u64::from(doff);

        // 1. Reset, then ACKNOWLEDGE and DRIVER.
        wr8(common + 20, 0);
        while rd8(common + 20) != 0 {
            core::hint::spin_loop();
        }
        wr8(common + 20, STATUS_ACKNOWLEDGE);
        wr8(common + 20, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        // 2. Features: read both halves, accept VERSION_1 and FLUSH only.
        wr32(common, 0);
        let f_lo = u64::from(rd32(common + 4));
        wr32(common, 1);
        let f_hi = u64::from(rd32(common + 4));
        let offered = f_lo | (f_hi << 32);
        if offered & F_VERSION_1 == 0 {
            wr8(common + 20, STATUS_FAILED);
            return Err(BlkError::NoVersion1);
        }
        let accepted = offered & (F_VERSION_1 | BLK_F_FLUSH);
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
            return Err(BlkError::FeaturesRejected);
        }
        // 3. Queue 0: size, memory, enable.
        wr16(common + 22, 0);
        let max = rd16(common + 24);
        if max == 0 {
            return Err(BlkError::QueueUnavailable);
        }
        let queue_size = QUEUE_SIZE.min(max);
        wr16(common + 24, queue_size);
        let n_frames = 1 + 1 + MAX_SECTORS * SECTOR / 4096;
        let first = pmm::alloc_frames(n_frames as u64).ok_or(BlkError::OutOfFrames)?;
        let mut frames = [Frame(0); 1 + 1 + MAX_SECTORS * SECTOR / 4096];
        for (i, f) in frames.iter_mut().enumerate() {
            *f = Frame(first.0 + (i as u64) * 4096);
        }
        let queue_phys = frames[0].0;
        let hdr = frames[1].0;
        let data = frames[2].0;
        // Zero the queue page and the header page.
        dma::bytes_mut(queue_phys, 4096).fill(0);
        dma::bytes_mut(hdr, 4096).fill(0);
        // Layout inside the queue page: desc at 0 (16 B each), avail at 0x400, used at 0x800.
        let desc = queue_phys;
        let avail = queue_phys + 0x400;
        let used = queue_phys + 0x800;
        wr64(common + 32, desc);
        wr64(common + 40, avail);
        wr64(common + 48, used);
        let notify_off = rd16(common + 30);
        let notify_addr = notify_base + u64::from(notify_off) * u64::from(nmult);
        wr16(common + 28, 1);
        // 4. Live.
        wr8(
            common + 20,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
        let capacity = u64::from(rd32(device_cfg)) | (u64::from(rd32(device_cfg + 4)) << 32);
        let info = BlkInfo {
            bdf: dev.bdf,
            device_id: dev.device,
            capacity_sectors: capacity,
            queue_size,
            features: accepted,
            flush: accepted & BLK_F_FLUSH != 0,
            mmio: common,
        };
        Ok(VirtioBlk {
            common,
            notify_addr,
            desc,
            avail,
            used,
            hdr,
            data,
            frames,
            queue_size,
            avail_idx: 0,
            last_used: 0,
            info,
        })
    }

    pub fn info(&self) -> BlkInfo {
        self.info
    }

    /// Submits one request (header, optional data, status) and waits for its completion.
    fn request(
        &mut self,
        typ: u32,
        sector: u64,
        data_len: usize,
        device_writes: bool,
    ) -> Result<(), BlkError> {
        if rd8(self.common + 20) & STATUS_NEEDS_RESET != 0 {
            return Err(BlkError::DeviceNeedsReset);
        }
        // Header: type, reserved, sector. Status byte at hdr + 16, preset to a non-OK value.
        dma::write32(self.hdr, typ);
        dma::write32(self.hdr + 4, 0);
        dma::write64(self.hdr + 8, sector);
        dma::bytes_mut(self.hdr + 16, 1)[0] = 0xFF;
        // Descriptors 0 (header), 1 (data, optional), 2 (status).
        let d = |i: u64| self.desc + i * 16;
        let has_data = data_len > 0;
        dma::write64(d(0), self.hdr);
        dma::write32(d(0) + 8, 16);
        dma::write16(d(0) + 12, DESC_F_NEXT);
        dma::write16(d(0) + 14, if has_data { 1 } else { 2 });
        if has_data {
            dma::write64(d(1), self.data);
            dma::write32(d(1) + 8, data_len as u32);
            dma::write16(
                d(1) + 12,
                DESC_F_NEXT | if device_writes { DESC_F_WRITE } else { 0 },
            );
            dma::write16(d(1) + 14, 2);
        }
        dma::write64(d(2), self.hdr + 16);
        dma::write32(d(2) + 8, 1);
        dma::write16(d(2) + 12, DESC_F_WRITE);
        dma::write16(d(2) + 14, 0);
        // Available ring: ring[idx % size] = head 0; then idx += 1; then notify (§2.7.13).
        let slot = u64::from(self.avail_idx % self.queue_size);
        dma::write16(self.avail + 4 + slot * 2, 0);
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        dma::write16(self.avail + 2, self.avail_idx);
        fence(Ordering::SeqCst);
        wr16(self.notify_addr, 0);
        // Completion: used.idx advances past our last seen value.
        let mut spins = 0u64;
        loop {
            fence(Ordering::SeqCst);
            if dma::read16(self.used + 2) != self.last_used {
                break;
            }
            spins += 1;
            if spins > POLL_LIMIT {
                return Err(BlkError::Timeout);
            }
            core::hint::spin_loop();
        }
        // The used element names the chain head it completed: ours is always descriptor 0.
        let elem = self.used + 4 + u64::from(self.last_used % self.queue_size) * 8;
        self.last_used = self.last_used.wrapping_add(1);
        if dma::read32(elem) != 0 {
            return Err(BlkError::Io(0xFE));
        }
        let status = dma::bytes_mut(self.hdr + 16, 1)[0];
        if status != S_OK {
            return Err(BlkError::Io(status));
        }
        Ok(())
    }

    fn check_range(&self, sector: u64, len: usize) -> Result<(), BlkError> {
        let n = len / SECTOR;
        if len == 0 || !len.is_multiple_of(SECTOR) || n > MAX_SECTORS {
            return Err(BlkError::Range);
        }
        if sector
            .checked_add(n as u64)
            .is_none_or(|e| e > self.info.capacity_sectors)
        {
            return Err(BlkError::Range);
        }
        Ok(())
    }

    /// Reads `buf.len()` bytes (a multiple of 512, at most 64 KiB) from `sector`.
    pub fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlkError> {
        self.check_range(sector, buf.len())?;
        self.request(T_IN, sector, buf.len(), true)?;
        buf.copy_from_slice(dma::bytes_mut(self.data, buf.len()));
        Ok(())
    }

    /// Writes `buf` (a multiple of 512, at most 64 KiB) at `sector`.
    #[cfg_attr(not(feature = "ktest"), allow(dead_code))]
    pub fn write(&mut self, sector: u64, buf: &[u8]) -> Result<(), BlkError> {
        self.check_range(sector, buf.len())?;
        dma::bytes_mut(self.data, buf.len()).copy_from_slice(buf);
        self.request(T_OUT, sector, buf.len(), false)
    }

    /// Makes completed writes stable (VIRTIO_BLK_T_FLUSH); a no-op when the device did not
    /// offer FLUSH (its writes are then already stable per §5.2.6.2).
    pub fn flush(&mut self) -> Result<(), BlkError> {
        if !self.info.flush {
            return Ok(());
        }
        self.request(T_FLUSH, 0, 0, false)
    }

    pub fn frames(&self) -> usize {
        self.frames.len()
    }
}
