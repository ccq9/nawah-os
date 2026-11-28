//! Program loaders (WP-17). Only ELF64 static executables; images come from the kernel's
//! embedded applications (tests) or from a file on the system volume (WP-23).

pub mod elf;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::fat32::FsError;
use crate::fs::vfs;
use crate::object::job::{Charge, Job};

/// Largest image `read_image` accepts (a service binary is tens of KiB; this bounds the heap a
/// spawn may take).
pub const IMAGE_MAX_BYTES: usize = 4 * 1024 * 1024;

/// An image read from the volume, and the pages its buffer is charged to the job that read it
/// (WP-176): the fields drop in order, so the bytes are freed before the charge comes back.
pub struct Image {
    bytes: Vec<u8>,
    _charge: Option<Charge>,
}

impl core::ops::Deref for Image {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Why an image was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    Fs(FsError),
    /// The buffer's pages are beyond the job's quota or the system's limit.
    Quota,
    /// The kernel's heap had no room for the buffer.
    NoMemory,
}

impl ImageError {
    pub fn code(&self) -> &'static str {
        match self {
            ImageError::Fs(e) => e.code(),
            ImageError::Quota => "K_E_IMAGE_QUOTA",
            ImageError::NoMemory => "K_E_IMAGE_NO_MEMORY",
        }
    }
}

impl From<FsError> for ImageError {
    fn from(e: FsError) -> Self {
        ImageError::Fs(e)
    }
}

/// Reads a whole file from the volume (for `elf::load`): `Range` when it exceeds the bound.
pub fn read_image(path: &[u8], job: &Arc<Job>) -> Result<Image, ImageError> {
    let file = vfs::open(path, vfs::O_READ)?;
    read_open_image(&file, job)
}

/// `read_image` of a file already open.
pub fn read_open_image(file: &vfs::FileRef, job: &Arc<Job>) -> Result<Image, ImageError> {
    let size = file.lock().node.lock().size as usize;
    if size > IMAGE_MAX_BYTES {
        return Err(FsError::Range.into());
    }
    // WP-176: the buffer's pages are charged to the reading job for its life (the root counted,
    // never refused) before it is taken, and it is taken fallibly; no disk read before.
    let charge = job
        .charge((size as u64).div_ceil(4096))
        .ok_or(ImageError::Quota)?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(size)
        .map_err(|_| ImageError::NoMemory)?;
    image.resize(size, 0);
    let mut done = 0;
    while done < size {
        let n = vfs::read(file, &mut image[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    image.truncate(done);
    Ok(Image {
        bytes: image,
        _charge: Some(charge),
    })
}
