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

/// Test kernel only (WP-105, the FAT32 fault cases): disk writes are counted, and from a chosen
/// write on every write is refused with `Io(0xEE)` before it reaches the driver (nothing is
/// published), while reads keep working. The disk then holds, to the sector, what a power cut
/// after the earlier writes would leave. A second mode (WP-124) refuses the chosen write alone
/// and takes every write after it: a disk that fails one request and serves the next. Not
/// imitated: writes reordered in a device cache, a torn sector, and a request whose outcome is
/// unknown (the driver's timeout).
#[cfg(feature = "ktest")]
mod fault {
    use core::sync::atomic::{AtomicU32, Ordering};

    static WRITES: AtomicU32 = AtomicU32::new(0);
    static FAIL_FROM: AtomicU32 = AtomicU32::new(u32::MAX);
    /// The last write that is refused; `u32::MAX` while every write from `FAIL_FROM` on is.
    static FAIL_TO: AtomicU32 = AtomicU32::new(u32::MAX);
    static TIMEOUT_AT: AtomicU32 = AtomicU32::new(u32::MAX);

    /// True, once, when the write just counted is the one chosen to time out.
    pub fn times_out() -> bool {
        let hit = WRITES.load(Ordering::SeqCst) == TIMEOUT_AT.load(Ordering::SeqCst);
        if hit {
            TIMEOUT_AT.store(u32::MAX, Ordering::SeqCst);
        }
        hit
    }

    pub fn arm_timeout_at(nth: u32) {
        TIMEOUT_AT.store(writes().saturating_add(nth), Ordering::SeqCst);
    }

    /// Counts one write; true when it is refused.
    pub fn refuses() -> bool {
        let n = WRITES.fetch_add(1, Ordering::SeqCst) + 1;
        n >= FAIL_FROM.load(Ordering::SeqCst) && n <= FAIL_TO.load(Ordering::SeqCst)
    }

    pub fn writes() -> u32 {
        WRITES.load(Ordering::SeqCst)
    }

    pub fn arm(nth: u32) {
        FAIL_TO.store(u32::MAX, Ordering::SeqCst);
        FAIL_FROM.store(writes().saturating_add(nth), Ordering::SeqCst);
    }

    /// The `nth` write from now is refused and no other.
    pub fn arm_once(nth: u32) {
        let at = writes().saturating_add(nth);
        FAIL_TO.store(at, Ordering::SeqCst);
        FAIL_FROM.store(at, Ordering::SeqCst);
    }

    pub fn disarm() {
        FAIL_FROM.store(u32::MAX, Ordering::SeqCst);
        FAIL_TO.store(u32::MAX, Ordering::SeqCst);
    }
}

/// Test kernel only: how many disk writes were asked for since boot (refused ones included).
#[cfg(feature = "ktest")]
pub fn writes() -> u32 {
    fault::writes()
}

/// Test kernel only: the `nth` write from now (1 is the next one) and every write after it is
/// refused until `disarm_write_fault`.
#[cfg(feature = "ktest")]
pub fn arm_write_fault(nth: u32) {
    fault::arm(nth);
}

/// Test kernel only (WP-124): the `nth` write from now (1 is the next one) is refused and
/// every write after it is taken, until `disarm_write_fault`.
#[cfg(feature = "ktest")]
pub fn arm_write_fault_once(nth: u32) {
    fault::arm_once(nth);
}

#[cfg(feature = "ktest")]
pub fn disarm_write_fault() {
    fault::disarm();
}

/// Test kernel only (TST-M3-FAT32-STOP): the `nth` write from now (1 is the next one) is
/// withheld from the device, so the driver's own timeout branch answers it and stops the disk
/// in the middle of a file-system call.
#[cfg(feature = "ktest")]
pub fn arm_timeout_at_write(nth: u32) {
    fault::arm_timeout_at(nth);
}

/// Used by the test kernel until the file system (WP-18 part 2) writes through it.
#[cfg_attr(not(feature = "ktest"), allow(dead_code))]
pub fn write(sector: u64, buf: &[u8]) -> Result<(), BlkError> {
    #[cfg(feature = "ktest")]
    if fault::refuses() {
        return Err(BlkError::Io(0xEE));
    }
    #[cfg(feature = "ktest")]
    if fault::times_out() {
        crate::drivers::virtio_blk::arm_timeout();
    }
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

/// True once the disk has stopped (ADR-0013 decision 9): a request timed out and the driver
/// refuses every later one. The driver's flag is read; no lock is taken.
pub fn stopped() -> bool {
    crate::drivers::virtio_blk::disk_stopped()
}

pub fn flush() -> Result<(), BlkError> {
    let r = DEVICE.lock().as_mut().ok_or(BlkError::NoDevice)?.flush();
    report("flush", 0, r)
}
