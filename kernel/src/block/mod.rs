//! Block layer (WP-18, ADR-0013): one device behind a lock, sector-granular synchronous
//! reads/writes bounded to 64 KiB per call, and `flush` for durability. Callers are the file
//! system and the tests; the device is brought up once at boot (`init`) and may be absent
//! (`BlkError::NoDevice` on every call).

use alloc::vec::Vec;

use crate::arch::pci::{self, Device};
use crate::drivers::virtio_blk::{BlkError, BlkInfo, VirtioBlk};
use crate::sync::IrqSpinLock;

static DEVICE: IrqSpinLock<Option<VirtioBlk>> = IrqSpinLock::new("blk", None);

#[derive(Clone, Debug)]
pub struct InitInfo {
    pub ecam_base: u64,
    pub segment: u16,
    pub functions: Vec<Device>,
    pub blk: Option<BlkInfo>,
    pub frames: usize,
}

/// Enumerates PCI and brings up the first virtio-blk function. `Err` only for a PCI/ECAM
/// failure or a device that failed its initialisation; a missing block device is reported
/// through `blk: None`.
pub fn init(rsdp: u64) -> Result<InitInfo, &'static str> {
    let mcfg = crate::arch::acpi::parse_mcfg(rsdp).map_err(|e| e.code())?;
    let devices: Vec<Device> = pci::enumerate(&mcfg).map_err(|_| "K_E_PCI_ENUMERATE")?;
    let mut info = InitInfo {
        ecam_base: mcfg.entries[0].base,
        segment: mcfg.entries[0].segment,
        functions: devices.clone(),
        blk: None,
        frames: 0,
    };
    match VirtioBlk::init(&devices) {
        Ok(dev) => {
            info.blk = Some(dev.info());
            info.frames = dev.frames();
            *DEVICE.lock() = Some(dev);
        }
        Err(BlkError::NoDevice) => {}
        Err(e) => return Err(e.code()),
    }
    Ok(info)
}

pub fn present() -> bool {
    DEVICE.lock().is_some()
}

/// The device's description, `None` without a device.
pub fn info() -> Option<BlkInfo> {
    DEVICE.lock().as_ref().map(|d| d.info())
}

pub fn capacity_sectors() -> u64 {
    DEVICE
        .lock()
        .as_ref()
        .map_or(0, |d| d.info().capacity_sectors)
}

/// The visible sign of a stopped disk (ADR-0013 decision 9). The request that timed out is the
/// only one that answers `Timeout` (the driver refuses every later one with `DeviceNeedsReset`),
/// so the line is written once in a boot; it is written after the device lock is released.
fn report(op: &'static str, sector: u64, r: Result<(), BlkError>) -> Result<(), BlkError> {
    if matches!(r, Err(BlkError::Timeout)) {
        kprintln!(
            "OSX|{}|kernel|blk|stopped|op={}|sector={}|code={}",
            crate::BUILD_ID,
            op,
            sector,
            BlkError::Timeout.code()
        );
    }
    r
}

pub fn read(sector: u64, buf: &mut [u8]) -> Result<(), BlkError> {
    let r = DEVICE
        .lock()
        .as_mut()
        .ok_or(BlkError::NoDevice)?
        .read(sector, buf);
    report("read", sector, r)
}

/// Used by the test kernel until the file system (WP-18 part 2) writes through it.
#[cfg_attr(not(feature = "ktest"), allow(dead_code))]
pub fn write(sector: u64, buf: &[u8]) -> Result<(), BlkError> {
    let r = DEVICE
        .lock()
        .as_mut()
        .ok_or(BlkError::NoDevice)?
        .write(sector, buf);
    report("write", sector, r)
}

/// Test kernel only (TST-M3-BLK-TIMEOUT): the first bytes of the driver's shared data buffer.
#[cfg(feature = "ktest")]
pub fn peek_data(out: &mut [u8]) {
    if let Some(d) = DEVICE.lock().as_ref() {
        d.peek_data(out);
    }
}

/// Test kernel only: the next request times out (TST-M3-BLK-TIMEOUT; see the driver's hook).
#[cfg(feature = "ktest")]
pub fn arm_timeout() {
    crate::drivers::virtio_blk::arm_timeout();
}

/// Test kernel only (TST-M3-BLK-TIMEOUT): how many requests the driver has published.
#[cfg(feature = "ktest")]
pub fn submitted() -> u16 {
    DEVICE.lock().as_ref().map_or(0, |d| d.submitted())
}

pub fn flush() -> Result<(), BlkError> {
    let r = DEVICE.lock().as_mut().ok_or(BlkError::NoDevice)?.flush();
    report("flush", 0, r)
}
