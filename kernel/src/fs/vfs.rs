//! The file interface processes see (WP-19, ADR-0014, docs/contracts/files.md): open files are
//! kernel objects reached through handles with READ/WRITE rights; every operation validates
//! the path or the handle first, and the file system (fs::fat32) does the rest. One volume,
//! absolute paths, 8.3 names.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::fat32::{Entry, EntryLoc, FsError};
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

/// The directory entry of an open file, one per file however often it is open (review
/// 2026-10-19): every open reads and writes through it, so a write or a truncation through one
/// is seen by all and none writes back a stale size or first cluster — each open used to keep
/// its own copy, and a write through an old one cross-linked clusters another file had taken.
pub type NodeRef = Arc<IrqSpinLock<Entry>>;

/// The nodes of the files open now, by the place of their directory entry. Weak: a node goes
/// with the last open file over it. Lock order: this, then a node, then the volume.
static NODES: IrqSpinLock<Vec<(EntryLoc, Weak<IrqSpinLock<Entry>>)>> =
    IrqSpinLock::new("file_nodes", Vec::new());

/// An open file: its file's shared node and the position shared by every handle to this open.
pub struct FileObject {
    pub node: NodeRef,
    pub pos: u64,
}

impl FileObject {
    fn new(node: NodeRef) -> FileObject {
        LIVE_FILES.fetch_add(1, Ordering::Relaxed);
        FileObject { node, pos: 0 }
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

/// Where a path falls for the system-files authority (files.md v1.3, WP-44): under /SYSTEM,
/// under its world-readable /SYSTEM/FONTS, or elsewhere. Components are compared as the 8.3
/// names the volume resolves (`/system/`, `/SYSTEM./` are /SYSTEM too); `.` and `..` are not
/// names there (`short_name` refuses them), so no path reaches /SYSTEM through another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathClass {
    Open,
    Fonts,
    System,
}

pub fn classify(path: &[u8]) -> PathClass {
    // A malformed path needs no authority: the file call refuses it as before (ERR_BAD_PATH).
    if check_path(path).is_err() {
        return PathClass::Open;
    }
    let mut parts = path
        .strip_prefix(b"/")
        .unwrap_or(path)
        .split(|&c| c == b'/');
    let first = parts.next().and_then(|c| super::fat32::short_name(c).ok());
    if first != Some(*b"SYSTEM     ") {
        return PathClass::Open;
    }
    match parts.next().and_then(|c| super::fat32::short_name(c).ok()) {
        Some(n) if n == *b"FONTS      " => PathClass::Fonts,
        _ => PathClass::System,
    }
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
    let mut nodes = NODES.lock();
    let entry = super::with(|fs| {
        let found = match fs.lookup(path) {
            Ok(e) => Some(e),
            Err(FsError::NotFound) => None,
            Err(e) => return Err(e),
        };
        let e = match found {
            Some(e) => e,
            None if flags & O_CREATE != 0 => fs.create(path)?,
            None => return Err(FsError::NotFound),
        };
        if e.is_dir() {
            return Err(FsError::IsADirectory);
        }
        Ok(e)
    })?;
    nodes.retain(|(_, n)| n.strong_count() > 0);
    let node = match nodes
        .iter()
        .find(|(loc, _)| *loc == entry.loc)
        .and_then(|(_, n)| n.upgrade())
    {
        Some(n) => n,
        None => {
            let n = Arc::new(IrqSpinLock::new("file_node", entry));
            nodes.push((entry.loc, Arc::downgrade(&n)));
            n
        }
    };
    if flags & O_TRUNCATE != 0 {
        let mut e = node.lock();
        if e.size > 0 {
            // Truncate to empty: free the chain, keep the entry (every open sees it).
            super::with(|fs| fs.truncate(&mut e))?;
        }
    }
    drop(nodes);
    Ok(Arc::new(IrqSpinLock::new("file", FileObject::new(node))))
}

/// Reads at the shared position; returns the count (0 at end of file).
pub fn read(file: &FileRef, buf: &mut [u8]) -> Result<usize, FsError> {
    let mut f = file.lock();
    let pos = f.pos;
    if pos >= u64::from(u32::MAX) {
        return Ok(0);
    }
    let n = {
        let e = f.node.lock();
        super::with(|fs| fs.read(&e, pos as u32, buf))?
    };
    f.pos += n as u64;
    Ok(n)
}

/// Writes at the shared position (which may be at most the size: append or overwrite).
pub fn write(file: &FileRef, data: &[u8]) -> Result<usize, FsError> {
    let mut f = file.lock();
    let pos = f.pos;
    let n = {
        let mut e = f.node.lock();
        if pos > u64::from(e.size) {
            return Err(FsError::Range);
        }
        super::with(|fs| fs.write(&mut e, pos as u32, data))?
    };
    f.pos += n as u64;
    Ok(n)
}

/// Moves the shared position (absolute; at most the current size).
pub fn seek(file: &FileRef, pos: u64) -> Result<u64, FsError> {
    let mut f = file.lock();
    if pos > u64::from(f.node.lock().size) {
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

/// Lists the directory at `path` (files.md §2, `dir_list`): one line per entry, `D <NAME>` for
/// a directory and `F <size> <NAME>` for a file, 8.3 names as `NAME.EXT`; `Err(Range)` when
/// the listing does not fit `out`. Returns the number of bytes written.
pub fn dir_list(path: &[u8], out: &mut [u8]) -> Result<usize, FsError> {
    check_path(path)?;
    super::with(|fs| {
        let mut n = 0;
        let mut overflow = false;
        fs.list(path, |e| {
            if overflow {
                return;
            }
            let mut line = [0u8; 32];
            let mut k = 0;
            let mut put = |b: &[u8]| {
                line[k..k + b.len()].copy_from_slice(b);
                k += b.len();
            };
            if e.is_dir() {
                put(b"D ");
            } else {
                put(b"F ");
                let mut num = [0u8; 10];
                let mut i = num.len();
                let mut v = e.size;
                loop {
                    i -= 1;
                    num[i] = b'0' + (v % 10) as u8;
                    v /= 10;
                    if v == 0 {
                        break;
                    }
                }
                put(&num[i..]);
                put(b" ");
            }
            let base = &e.name[..8];
            let ext = &e.name[8..];
            let base_len = base.iter().rposition(|c| *c != b' ').map_or(0, |p| p + 1);
            let ext_len = ext.iter().rposition(|c| *c != b' ').map_or(0, |p| p + 1);
            put(&base[..base_len]);
            if ext_len > 0 {
                put(b".");
                put(&ext[..ext_len]);
            }
            put(b"\n");
            if n + k > out.len() {
                overflow = true;
                return;
            }
            out[n..n + k].copy_from_slice(&line[..k]);
            n += k;
        })?;
        if overflow {
            return Err(FsError::Range);
        }
        Ok(n)
    })
}

/// Removes a file; refused (`Busy`) while any open file is over it (files.md v1.2).
pub fn unlink(path: &[u8]) -> Result<(), FsError> {
    check_path(path)?;
    let mut nodes = NODES.lock();
    nodes.retain(|(_, n)| n.strong_count() > 0);
    super::with(|fs| {
        let e = fs.lookup(path)?;
        if nodes.iter().any(|(loc, _)| *loc == e.loc) {
            return Err(FsError::Busy);
        }
        fs.unlink(path).map(|_| ())
    })
}

/// Makes everything written so far stable on the device.
pub fn sync() -> Result<(), FsError> {
    super::with(|fs| fs.sync())
}
