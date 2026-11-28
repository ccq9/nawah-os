//! File systems (WP-18 part 2, WP-19). One FAT32 volume on the block device, mounted at boot
//! and reached through `with` (the file-system lock nests the block lock inside it, never the
//! reverse); `vfs` is the handle-based interface processes use.

pub mod fat32;
pub mod vfs;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::drivers::virtio_blk::BlkError;
use crate::sync::IrqSpinLock;
use fat32::{Fat32, FsError};

static VOLUME: IrqSpinLock<Option<Fat32>> = IrqSpinLock::new("fs", None);
/// Set by the first file call that finds the disk stopped: the stop is told once.
static STOP_TOLD: AtomicBool = AtomicBool::new(false);

/// What every file call answers once the disk has stopped.
pub(crate) fn stop_error() -> FsError {
    FsError::Io(BlkError::DeviceNeedsReset)
}

/// True once the disk has stopped (ADR-0013 decision 9; files.md v1.9). The file system stops
/// with it: `with` and `vfs::seek`, the two ways into a file call, ask this before they look
/// at anything held in memory, so no call answers from memory what the disk can no longer
/// back. `with` asks once it holds the volume's lock: every disk request of the file system
/// is made under that lock, so a call that waited for it while the disk stopped finds it
/// stopped. The driver's flag is read each time (one flag, no lock); the first call that
/// finds the disk stopped writes the file system's own line.
pub(crate) fn stopped() -> bool {
    if !crate::block::stopped() {
        return false;
    }
    if !STOP_TOLD.swap(true, Ordering::SeqCst) {
        kprintln!(
            "OSX|{}|kernel|fs|stopped|code={}",
            crate::BUILD_ID,
            stop_error().code()
        );
    }
    true
}

/// Mounts the volume (idempotent) and returns its geometry.
pub fn mount() -> Result<Fat32, FsError> {
    let mut g = VOLUME.lock();
    if let Some(v) = *g {
        return Ok(v);
    }
    let v = Fat32::mount()?;
    *g = Some(v);
    Ok(v)
}

/// Runs `f` on the mounted volume.
pub fn with<R>(f: impl FnOnce(&Fat32) -> Result<R, FsError>) -> Result<R, FsError> {
    let g = VOLUME.lock();
    if stopped() {
        return Err(stop_error());
    }
    match g.as_ref() {
        Some(v) => f(v),
        None => Err(FsError::NotMounted),
    }
}
