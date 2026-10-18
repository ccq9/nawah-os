//! Program loaders (WP-17). Only ELF64 static executables; images come from the kernel's
//! embedded applications (tests) or from a file on the system volume (WP-23).

pub mod elf;

use alloc::vec::Vec;

use crate::fs::fat32::FsError;
use crate::fs::vfs;

/// Largest image `read_image` accepts (a service binary is tens of KiB; this bounds the heap a
/// spawn may take).
pub const IMAGE_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Reads a whole file from the volume (for `elf::load`): `Range` when it exceeds the bound.
pub fn read_image(path: &[u8]) -> Result<Vec<u8>, FsError> {
    let file = vfs::open(path, vfs::O_READ)?;
    let size = file.lock().entry.size as usize;
    if size > IMAGE_MAX_BYTES {
        return Err(FsError::Range);
    }
    let mut image = alloc::vec![0u8; size];
    let mut done = 0;
    while done < size {
        let n = vfs::read(&file, &mut image[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    image.truncate(done);
    Ok(image)
}
