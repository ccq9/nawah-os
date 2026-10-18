//! The file interface processes see (WP-19, ADR-0014, docs/contracts/files.md): open files are
//! kernel objects reached through handles with READ/WRITE rights; every operation validates
//! the path or the handle first, and the file system (fs::fat32) does the rest. One volume,
//! absolute paths, 8.3 names.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use super::fat32::{Entry, FsError};
use crate::sync::IrqSpinLock;

static LIVE_FILES: AtomicU32 = AtomicU32::new(0);

/// Open file objects alive (leak checks).
pub fn live_files() -> u32 {
    LIVE_FILES.load(Ordering::Relaxed)
}

/// `open` flags (contract §2).
pub const O_READ: u64 = 1;
pub const O_WRITE: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNCATE: u64 = 8;
pub const O_VALID: u64 = O_READ | O_WRITE | O_CREATE | O_TRUNCATE;
/// Longest path accepted (bytes).
pub const PATH_MAX: usize = 256;

/// An open file: its directory entry (size and first cluster are refreshed on write) and the
/// position shared by every handle to it.
pub struct FileObject {
    pub entry: Entry,
    pub pos: u64,
}

impl FileObject {
    fn new(entry: Entry) -> FileObject {
        LIVE_FILES.fetch_add(1, Ordering::Relaxed);
        FileObject { entry, pos: 0 }
    }
}

impl Drop for FileObject {
    fn drop(&mut self) {
        LIVE_FILES.fetch_sub(1, Ordering::Relaxed);
    }
}

pub type FileRef = Arc<IrqSpinLock<FileObject>>;

/// What `stat` reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
    pub size: u64,
    pub is_dir: bool,
    pub first_cluster: u32,
}

fn check_path(path: &[u8]) -> Result<(), FsError> {
    if path.is_empty() || path.len() > PATH_MAX || path[0] != b'/' || !path.is_ascii() {
        return Err(FsError::BadName);
    }
    Ok(())
}

/// Opens (or creates) `path`; the returned object starts at position 0 (a writer that wants
/// to append seeks to the size first).
pub fn open(path: &[u8], flags: u64) -> Result<FileRef, FsError> {
    check_path(path)?;
    if flags & !O_VALID != 0 || flags & (O_READ | O_WRITE) == 0 {
        return Err(FsError::Range);
    }
    let entry = super::with(|fs| {
        let found = match fs.lookup(path) {
            Ok(e) => Some(e),
            Err(FsError::NotFound) => None,
            Err(e) => return Err(e),
        };
        let mut e = match found {
            Some(e) => e,
            None if flags & O_CREATE != 0 => fs.create(path)?,
            None => return Err(FsError::NotFound),
        };
        if e.is_dir() {
            return Err(FsError::IsADirectory);
        }
        if flags & O_TRUNCATE != 0 && e.size > 0 {
            // Truncate to empty: free the chain, keep the entry.
            fs.truncate(&mut e)?;
        }
        Ok(e)
    })?;
    Ok(Arc::new(IrqSpinLock::new("file", FileObject::new(entry))))
}

/// Reads at the shared position; returns the count (0 at end of file).
pub fn read(file: &FileRef, buf: &mut [u8]) -> Result<usize, FsError> {
    let mut f = file.lock();
    let pos = f.pos;
    if pos >= u64::from(u32::MAX) {
        return Ok(0);
    }
    let n = super::with(|fs| fs.read(&f.entry, pos as u32, buf))?;
    f.pos += n as u64;
    Ok(n)
}

/// Writes at the shared position (which may be at most the size: append or overwrite).
pub fn write(file: &FileRef, data: &[u8]) -> Result<usize, FsError> {
    let mut f = file.lock();
    let pos = f.pos;
    if pos > u64::from(f.entry.size) {
        return Err(FsError::Range);
    }
    let mut entry = f.entry;
    let n = super::with(|fs| fs.write(&mut entry, pos as u32, data))?;
    f.entry = entry;
    f.pos += n as u64;
    Ok(n)
}

/// Moves the shared position (absolute; at most the current size).
pub fn seek(file: &FileRef, pos: u64) -> Result<u64, FsError> {
    let mut f = file.lock();
    if pos > u64::from(f.entry.size) {
        return Err(FsError::Range);
    }
    f.pos = pos;
    Ok(pos)
}

pub fn stat(path: &[u8]) -> Result<Stat, FsError> {
    check_path(path)?;
    super::with(|fs| {
        let e = fs.lookup(path)?;
        Ok(Stat {
            size: u64::from(e.size),
            is_dir: e.is_dir(),
            first_cluster: e.first,
        })
    })
}

pub fn unlink(path: &[u8]) -> Result<(), FsError> {
    check_path(path)?;
    super::with(|fs| fs.unlink(path).map(|_| ()))
}

/// Makes everything written so far stable on the device.
pub fn sync() -> Result<(), FsError> {
    super::with(|fs| fs.sync())
}
