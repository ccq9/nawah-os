//! File systems (WP-18 part 2, WP-19). One FAT32 volume on the block device, mounted at boot
//! and reached through `with` (the file-system lock nests the block lock inside it, never the
//! reverse); `vfs` is the handle-based interface processes use.

pub mod fat32;
pub mod vfs;

use crate::sync::IrqSpinLock;
use fat32::{Fat32, FsError};

static VOLUME: IrqSpinLock<Option<Fat32>> = IrqSpinLock::new("fs", None);

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
    match g.as_ref() {
        Some(v) => f(v),
        None => Err(FsError::NotMounted),
    }
}
