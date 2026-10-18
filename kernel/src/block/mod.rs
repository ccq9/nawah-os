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

pub fn capacity_sectors() -> u64 {
    DEVICE
        .lock()
        .as_ref()
        .map_or(0, |d| d.info().capacity_sectors)
}

pub fn read(sector: u64, buf: &mut [u8]) -> Result<(), BlkError> {
    DEVICE
        .lock()
        .as_mut()
        .ok_or(BlkError::NoDevice)?
        .read(sector, buf)
}

/// Used by the test kernel until the file system (WP-18 part 2) writes through it.
#[cfg_attr(not(feature = "ktest"), allow(dead_code))]
pub fn write(sector: u64, buf: &[u8]) -> Result<(), BlkError> {
    DEVICE
        .lock()
        .as_mut()
        .ok_or(BlkError::NoDevice)?
        .write(sector, buf)
}

pub fn flush() -> Result<(), BlkError> {
    DEVICE.lock().as_mut().ok_or(BlkError::NoDevice)?.flush()
}
