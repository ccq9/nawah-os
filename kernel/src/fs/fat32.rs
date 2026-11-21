//! FAT32 (WP-18 part 2, ADR-0013): read, create, write (append/overwrite), unlink and listing
//! with 8.3 names, on the block layer. Sector-at-a-time, no cache, every structure field
//! validated before use; both FAT copies are kept equal.
//!
//! Reference: Microsoft FAT32 File System Specification (S44) — BPB fields (BytsPerSec at 11,
//! SecPerClus 13, RsvdSecCnt 14, NumFATs 16, RootEntCnt 17, TotSec16 19, FATSz16 22,
//! TotSec32 32, FATSz32 36, RootClus 44, FSInfo 48, BkBootSec 50, BootSig 66 = 0x29, VolLab 71,
//! signature 0x55AA at 510); FirstDataSector = RsvdSecCnt + NumFATs * FATSz32;
//! FirstSectorOfCluster(N) = (N - 2) * SecPerClus + FirstDataSector; FAT32 entries use the low
//! 28 bits (free 0, EOC >= 0x0FFFFFF8, bad 0x0FFFFFF7), the high 4 bits are preserved on write;
//! directory entries of 32 bytes (Name 0..11, Attr 11, FstClusHI 20, FstClusLO 26, FileSize 28;
//! 0xE5 free, 0x00 end; ATTR_DIRECTORY 0x10, ATTR_ARCHIVE 0x20, ATTR_LONG_NAME 0x0F skipped).

// The mutating half (create/write/unlink) is reached by the test kernel until the VFS of
// WP-19 exposes it through system calls.
#![cfg_attr(not(feature = "ktest"), allow(dead_code))]

use crate::block;
use crate::drivers::virtio_blk::BlkError;

const SECTOR: usize = 512;
const EOC: u32 = 0x0FFF_FFFF;
const EOC_MIN: u32 = 0x0FFF_FFF8;
const BAD: u32 = 0x0FFF_FFF7;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LONG_NAME: u8 = 0x0F;
/// Longest chain walked (loops and corruption cannot spin forever).
const CHAIN_MAX: u32 = 1 << 20;
/// Largest file this implementation writes (a kernel-side bound, not the format's).
pub const FILE_MAX: u32 = 64 * 1024 * 1024;

/// Test kernel only (WP-121, TST-M3-FAT32-DISK-FULL): the allocator looks no further than a
/// chosen cluster, as a volume that ends there would (filling the lab volume for real is too
/// slow: every allocation scans the FAT from its start). Nothing answers in the allocator's
/// place: its own scan runs to that end, finds no free cluster and answers `DiskFull`, and a
/// cluster freed below that end is found again.
#[cfg(feature = "ktest")]
mod full {
    use core::sync::atomic::{AtomicU32, Ordering};

    static END: AtomicU32 = AtomicU32::new(u32::MAX);

    pub fn set(end: u32) {
        END.store(end, Ordering::SeqCst);
    }

    pub fn end() -> u32 {
        END.load(Ordering::SeqCst)
    }
}

/// Test kernel only: the allocator sees the whole volume again.
#[cfg(feature = "ktest")]
pub fn disarm_disk_full() {
    full::set(u32::MAX);
}

/// The cluster the test kernel's hook ends the allocator's range at; no end outside it.
fn full_end() -> u32 {
    #[cfg(feature = "ktest")]
    {
        full::end()
    }
    #[cfg(not(feature = "ktest"))]
    {
        u32::MAX
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    NotMounted,
    Io(BlkError),
    BadBpb,
    NotFound,
    NotADirectory,
    IsADirectory,
    Exists,
    BadName,
    DiskFull,
    Corrupt,
    Range,
    /// The file is open: it cannot be removed (files.md v1.2).
    Busy,
}

impl From<BlkError> for FsError {
    fn from(e: BlkError) -> Self {
        FsError::Io(e)
    }
}

impl FsError {
    pub fn code(&self) -> &'static str {
        match self {
            FsError::NotMounted => "K_E_FS_NOT_MOUNTED",
            FsError::Io(_) => "K_E_FS_IO",
            FsError::BadBpb => "K_E_FS_BAD_BPB",
            FsError::NotFound => "K_E_FS_NOT_FOUND",
            FsError::NotADirectory => "K_E_FS_NOT_A_DIRECTORY",
            FsError::IsADirectory => "K_E_FS_IS_A_DIRECTORY",
            FsError::Exists => "K_E_FS_EXISTS",
            FsError::BadName => "K_E_FS_BAD_NAME",
            FsError::DiskFull => "K_E_FS_DISK_FULL",
            FsError::Corrupt => "K_E_FS_CORRUPT",
            FsError::Range => "K_E_FS_RANGE",
            FsError::Busy => "K_E_FS_BUSY",
        }
    }
}

/// Where a directory entry lives: the directory cluster holding it and its index in that
/// cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryLoc {
    pub cluster: u32,
    pub index: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub name: [u8; 11],
    pub attr: u8,
    pub first: u32,
    pub size: u32,
    pub loc: EntryLoc,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }

    /// The root directory as a pseudo-entry (cluster = root cluster, no location).
    fn root(root: u32) -> Entry {
        Entry {
            name: *b"           ",
            attr: ATTR_DIRECTORY,
            first: root,
            size: 0,
            loc: EntryLoc {
                cluster: 0,
                index: 0,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fat32 {
    pub sectors_per_cluster: u32,
    pub reserved: u32,
    pub fats: u32,
    pub fat_sectors: u32,
    pub root_cluster: u32,
    pub data_start: u32,
    pub clusters: u32,
    pub label: [u8; 11],
    /// FSInfo sector, 0 when absent; its copy follows the backup boot sector (`bk_boot + 1`).
    pub fsinfo: u32,
    pub bk_boot: u32,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Turns one path component into an 8.3 name: ASCII letters, digits, `_` and `-`, base 1..=8,
/// extension 0..=3, uppercased.
pub fn short_name(component: &[u8]) -> Result<[u8; 11], FsError> {
    let (base, ext) = match component.iter().position(|&c| c == b'.') {
        Some(p) => (&component[..p], &component[p + 1..]),
        None => (component, &component[..0]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return Err(FsError::BadName);
    }
    let ok = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-';
    if !base.iter().all(ok) || !ext.iter().all(ok) {
        return Err(FsError::BadName);
    }
    let mut out = [b' '; 11];
    for (i, c) in base.iter().enumerate() {
        out[i] = c.to_ascii_uppercase();
    }
    for (i, c) in ext.iter().enumerate() {
        out[8 + i] = c.to_ascii_uppercase();
    }
    Ok(out)
}

impl Fat32 {
    /// Reads and validates the BPB of the block device.
    pub fn mount() -> Result<Fat32, FsError> {
        if !block::present() {
            return Err(FsError::NotMounted);
        }
        let mut b = [0u8; SECTOR];
        block::read(0, &mut b)?;
        Self::from_boot_sector(&b, block::capacity_sectors())
    }

    /// Validates a boot sector against a device of `capacity` sectors and returns the volume's
    /// geometry; touches no disk, so the test kernel can give it crafted sectors.
    pub fn from_boot_sector(b: &[u8; SECTOR], capacity: u64) -> Result<Fat32, FsError> {
        if le16(b, 510) != 0xAA55 || b[66] != 0x29 {
            return Err(FsError::BadBpb);
        }
        let bps = le16(b, 11);
        let spc = u32::from(b[13]);
        let reserved = u32::from(le16(b, 14));
        let fats = u32::from(b[16]);
        let root_entries = le16(b, 17);
        let tot16 = le16(b, 19);
        let fatsz16 = le16(b, 22);
        let total = le32(b, 32);
        let fat_sectors = le32(b, 36);
        let root_cluster = le32(b, 44);
        let fsinfo = u32::from(le16(b, 48));
        let bk_boot = u32::from(le16(b, 50));
        let fat32_shape = bps as usize == SECTOR
            && spc.is_power_of_two()
            && (1..=128).contains(&spc)
            && reserved >= 1
            && (1..=2).contains(&fats)
            && root_entries == 0
            && tot16 == 0
            && fatsz16 == 0
            && fat_sectors > 0
            && root_cluster >= 2;
        if !fat32_shape {
            return Err(FsError::BadBpb);
        }
        // Every bound in 64 bits, where no field value can wrap (at most 65535 + 2 * (2^32 - 1)),
        // and narrowed to 32 bits only after them: the data region starts inside the volume, the
        // volume lies inside the device, and the cluster count stays below the numbers the FAT
        // reserves for its marks.
        let data_start = u64::from(reserved) + u64::from(fats) * u64::from(fat_sectors);
        let total = u64::from(total);
        if data_start >= total || total > capacity {
            return Err(FsError::BadBpb);
        }
        let clusters = (total - data_start) / u64::from(spc);
        // At most 0x0FFFFFF5 clusters: their numbers run from 2 to 0x0FFFFFF6, below the bad mark
        // 0x0FFFFFF7 and the end-of-chain marks from 0x0FFFFFF8.
        if !(65525..=0x0FFF_FFF5).contains(&clusters)
            || u64::from(root_cluster) >= clusters + 2
            || (clusters + 2) * 4 > u64::from(fat_sectors) * SECTOR as u64
        {
            return Err(FsError::BadBpb);
        }
        // data_start < total <= u32::MAX and clusters <= 0x0FFFFFF5: both fit in 32 bits.
        let (data_start, clusters) = (data_start as u32, clusters as u32);
        let mut label = [0u8; 11];
        label.copy_from_slice(&b[71..82]);
        Ok(Fat32 {
            sectors_per_cluster: spc,
            reserved,
            fats,
            fat_sectors,
            root_cluster,
            data_start,
            clusters,
            label,
            fsinfo: if fsinfo != 0 && fsinfo < reserved {
                fsinfo
            } else {
                0
            },
            bk_boot: if bk_boot != 0 && bk_boot + 1 < reserved {
                bk_boot
            } else {
                0
            },
        })
    }

    /// Keeps the advisory FSInfo counters (free count, next-free hint; the specification's
    /// FSI_Free_Count / FSI_Nxt_Free) in step with allocations, in the primary sector and its
    /// backup copy, so repair tools see a consistent volume (dosfstools flagged a stale count in
    /// CI run 39109529224). `delta` is the change in free clusters; `hint` the next-free hint.
    fn fsinfo_adjust(&self, delta: i64, hint: u32) -> Result<(), FsError> {
        if self.fsinfo == 0 {
            return Ok(());
        }
        let mut s = [0u8; SECTOR];
        let copies = [
            u64::from(self.fsinfo),
            if self.bk_boot != 0 {
                u64::from(self.bk_boot) + 1
            } else {
                0
            },
        ];
        for sector in copies.into_iter().filter(|&x| x != 0) {
            block::read(sector, &mut s)?;
            if le32(&s, 0) != 0x4161_5252
                || le32(&s, 484) != 0x6141_7272
                || le32(&s, 508) != 0xAA55_0000
            {
                continue;
            }
            let free = le32(&s, 488);
            let new_free = if free == 0xFFFF_FFFF || free > self.clusters {
                0xFFFF_FFFF
            } else {
                (i64::from(free) + delta).clamp(0, i64::from(self.clusters)) as u32
            };
            s[488..492].copy_from_slice(&new_free.to_le_bytes());
            s[492..496].copy_from_slice(&hint.to_le_bytes());
            block::write(sector, &s)?;
        }
        Ok(())
    }

    fn cluster_sector(&self, c: u32) -> Result<u64, FsError> {
        if c < 2 || c >= self.clusters + 2 {
            return Err(FsError::Corrupt);
        }
        Ok(u64::from(self.data_start) + u64::from(c - 2) * u64::from(self.sectors_per_cluster))
    }

    fn fat_get(&self, c: u32) -> Result<u32, FsError> {
        if c >= self.clusters + 2 {
            return Err(FsError::Corrupt);
        }
        let off = c as usize * 4;
        let mut s = [0u8; SECTOR];
        block::read(u64::from(self.reserved) + (off / SECTOR) as u64, &mut s)?;
        Ok(le32(&s, off % SECTOR) & 0x0FFF_FFFF)
    }

    /// Writes entry `c` in every FAT copy, keeping the high 4 bits. The copies are written from
    /// the last to the first, so the copy the kernel reads, the first, is written last (files.md
    /// v1.8): a call that fails between the copies leaves what the kernel sees unchanged, and
    /// the next `fat_set` of that entry writes every copy again. A copy after the first may
    /// then be ahead of it (a link, a mark or a free the first copy does not have), never
    /// behind.
    fn fat_set(&self, c: u32, v: u32) -> Result<(), FsError> {
        if c < 2 || c >= self.clusters + 2 {
            return Err(FsError::Corrupt);
        }
        let off = c as usize * 4;
        let mut s = [0u8; SECTOR];
        for k in (0..self.fats).rev() {
            let sector = u64::from(self.reserved + k * self.fat_sectors) + (off / SECTOR) as u64;
            block::read(sector, &mut s)?;
            let old = le32(&s, off % SECTOR);
            let new = (old & 0xF000_0000) | (v & 0x0FFF_FFFF);
            s[off % SECTOR..off % SECTOR + 4].copy_from_slice(&new.to_le_bytes());
            block::write(sector, &s)?;
        }
        Ok(())
    }

    fn next_cluster(&self, c: u32) -> Result<Option<u32>, FsError> {
        let v = self.fat_get(c)?;
        if v >= EOC_MIN {
            Ok(None)
        } else if v == BAD || v < 2 || v >= self.clusters + 2 {
            Err(FsError::Corrupt)
        } else {
            Ok(Some(v))
        }
    }

    /// One past the last cluster the allocator may take.
    fn alloc_end(&self) -> u32 {
        (self.clusters + 2).min(full_end())
    }

    /// The `n`th free cluster (from 1), lowest first, below `end`, by scanning the first FAT;
    /// `None` when fewer are free there.
    fn nth_free(&self, n: u32, end: u32) -> Result<Option<u32>, FsError> {
        let mut s = [0u8; SECTOR];
        let mut seen = 0u32;
        let mut c = 2u32;
        while c < end {
            let sector_index = (c as usize * 4) / SECTOR;
            block::read(u64::from(self.reserved) + sector_index as u64, &mut s)?;
            let stop = (((sector_index + 1) * SECTOR / 4) as u32).min(end);
            while c < stop {
                if le32(&s, (c as usize * 4) % SECTOR) & 0x0FFF_FFFF == 0 {
                    seen += 1;
                    if seen == n {
                        return Ok(Some(c));
                    }
                }
                c += 1;
            }
        }
        Ok(None)
    }

    /// True when the allocator can take `want` more clusters (the scan stops at the last one
    /// it needs).
    fn has_free(&self, want: u32) -> Result<bool, FsError> {
        Ok(want == 0 || self.nth_free(want, self.alloc_end())?.is_some())
    }

    /// How many clusters the chain from `first` holds, counted no further than `cap`.
    fn chain_len(&self, first: u32, cap: u32) -> Result<u32, FsError> {
        let (mut c, mut n) = (first, 0u32);
        while c >= 2 && n < cap {
            n += 1;
            match self.next_cluster(c)? {
                Some(x) => c = x,
                None => break,
            }
        }
        Ok(n)
    }

    /// Test kernel only (TST-M3-FAT32-DISK-FULL): from now the allocator sees `left` free
    /// clusters and no more (it stops before the next free one).
    #[cfg(feature = "ktest")]
    pub fn arm_disk_full(&self, left: u32) -> Result<(), FsError> {
        let end = self.nth_free(left + 1, self.clusters + 2)?;
        full::set(end.unwrap_or(u32::MAX));
        Ok(())
    }

    /// Finds a free cluster (lowest first), marks it EOC and zeroes it.
    fn alloc_cluster(&self) -> Result<u32, FsError> {
        let mut s = [0u8; SECTOR];
        let fat0 = u64::from(self.reserved);
        let last = self.alloc_end();
        let mut c = 2u32;
        while c < last {
            let sector_index = (c as usize * 4) / SECTOR;
            block::read(fat0 + sector_index as u64, &mut s)?;
            let first_in_sector = (sector_index * SECTOR / 4) as u32;
            let end = (first_in_sector + (SECTOR / 4) as u32).min(last);
            let mut k = c.max(first_in_sector);
            while k < end {
                if le32(&s, (k as usize * 4) % SECTOR) & 0x0FFF_FFFF == 0 {
                    self.fat_set(k, EOC)?;
                    let zero = [0u8; SECTOR];
                    let base = self.cluster_sector(k)?;
                    for i in 0..self.sectors_per_cluster {
                        block::write(base + u64::from(i), &zero)?;
                    }
                    self.fsinfo_adjust(-1, k + 1)?;
                    return Ok(k);
                }
                k += 1;
            }
            c = end;
        }
        Err(FsError::DiskFull)
    }

    fn free_chain(&self, first: u32) -> Result<u32, FsError> {
        let mut c = first;
        let mut n = 0;
        let mut lowest = u32::MAX;
        while c >= 2 && n < CHAIN_MAX {
            let next = self.next_cluster(c)?;
            self.fat_set(c, 0)?;
            lowest = lowest.min(c);
            n += 1;
            match next {
                Some(x) => c = x,
                None => break,
            }
        }
        if n > 0 {
            self.fsinfo_adjust(i64::from(n), lowest)?;
        }
        Ok(n)
    }

    /// Test kernel only (TST-M3-FAT32-DISK-FULL): how many clusters the chain from `first`
    /// holds, so a case can compare it with what the file's size needs.
    #[cfg(feature = "ktest")]
    pub fn chain_clusters(&self, first: u32) -> Result<u32, FsError> {
        self.chain_len(first, CHAIN_MAX)
    }

    /// Free clusters, by scanning the first FAT.
    pub fn free_clusters(&self) -> Result<u32, FsError> {
        let mut s = [0u8; SECTOR];
        let mut free = 0u32;
        let last = self.clusters + 2;
        let mut c = 2u32;
        while c < last {
            let sector_index = (c as usize * 4) / SECTOR;
            block::read(u64::from(self.reserved) + sector_index as u64, &mut s)?;
            let end = ((sector_index + 1) * SECTOR / 4) as u32;
            while c < end && c < last {
                if le32(&s, (c as usize * 4) % SECTOR) & 0x0FFF_FFFF == 0 {
                    free += 1;
                }
                c += 1;
            }
        }
        Ok(free)
    }

    /// Calls `f` for every slot of the directory chain starting at `dir` with (loc, raw entry);
    /// stops when `f` returns true or at the end-of-directory marker.
    fn walk_dir(
        &self,
        dir: u32,
        mut f: impl FnMut(EntryLoc, &[u8]) -> bool,
    ) -> Result<bool, FsError> {
        let mut c = dir;
        let mut hops = 0;
        let mut s = [0u8; SECTOR];
        loop {
            let base = self.cluster_sector(c)?;
            for i in 0..self.sectors_per_cluster {
                block::read(base + u64::from(i), &mut s)?;
                for k in 0..(SECTOR / 32) {
                    let e = &s[k * 32..k * 32 + 32];
                    let loc = EntryLoc {
                        cluster: c,
                        index: i * 16 + k as u32,
                    };
                    if e[0] == 0 {
                        return Ok(false);
                    }
                    if f(loc, e) {
                        return Ok(true);
                    }
                }
            }
            hops += 1;
            match self.next_cluster(c)? {
                Some(n) if hops < CHAIN_MAX => c = n,
                _ => return Ok(false),
            }
        }
    }

    fn parse_entry(loc: EntryLoc, e: &[u8]) -> Entry {
        let mut name = [0u8; 11];
        name.copy_from_slice(&e[..11]);
        Entry {
            name,
            attr: e[11],
            first: (u32::from(le16(e, 20)) << 16) | u32::from(le16(e, 26)),
            size: le32(e, 28),
            loc,
        }
    }

    /// Looks `name` (8.3, padded) up in directory `dir`.
    fn lookup_in(&self, dir: u32, name: &[u8; 11]) -> Result<Option<Entry>, FsError> {
        let mut found = None;
        self.walk_dir(dir, |loc, e| {
            if e[0] == 0xE5
                || e[11] & ATTR_LONG_NAME == ATTR_LONG_NAME
                || e[11] & ATTR_VOLUME_ID != 0
            {
                return false;
            }
            if &e[..11] == name {
                found = Some(Self::parse_entry(loc, e));
                return true;
            }
            false
        })?;
        Ok(found)
    }

    /// Splits `path` into (parent directory entry, last component) and resolves the parent.
    fn resolve_parent(&self, path: &[u8]) -> Result<(Entry, [u8; 11]), FsError> {
        let trimmed = path.strip_prefix(b"/").unwrap_or(path);
        let trimmed = trimmed.strip_suffix(b"/").unwrap_or(trimmed);
        if trimmed.is_empty() {
            return Err(FsError::BadName);
        }
        let mut dir = Entry::root(self.root_cluster);
        let mut parts = trimmed.split(|&c| c == b'/').peekable();
        while let Some(part) = parts.next() {
            let name = short_name(part)?;
            if parts.peek().is_none() {
                return Ok((dir, name));
            }
            match self.lookup_in(dir.first, &name)? {
                Some(e) if e.is_dir() => dir = e,
                Some(_) => return Err(FsError::NotADirectory),
                None => return Err(FsError::NotFound),
            }
        }
        Err(FsError::BadName)
    }

    /// Resolves `path` (`/A/B.TXT`; `/` is the root directory).
    pub fn lookup(&self, path: &[u8]) -> Result<Entry, FsError> {
        let trimmed = path.strip_prefix(b"/").unwrap_or(path);
        if trimmed.is_empty() || trimmed == b"/" {
            return Ok(Entry::root(self.root_cluster));
        }
        let (dir, name) = self.resolve_parent(path)?;
        self.lookup_in(dir.first, &name)?.ok_or(FsError::NotFound)
    }

    /// Lists directory `path`: `f(entry)` per real entry (no `.`/`..`, no labels, no LFN parts).
    pub fn list(&self, path: &[u8], mut f: impl FnMut(&Entry)) -> Result<u32, FsError> {
        let dir = self.lookup(path)?;
        if !dir.is_dir() {
            return Err(FsError::NotADirectory);
        }
        let mut n = 0;
        self.walk_dir(dir.first, |loc, e| {
            if e[0] != 0xE5
                && e[11] & ATTR_LONG_NAME != ATTR_LONG_NAME
                && e[11] & ATTR_VOLUME_ID == 0
                && e[0] != b'.'
            {
                f(&Self::parse_entry(loc, e));
                n += 1;
            }
            false
        })?;
        Ok(n)
    }

    /// Reads up to `buf.len()` bytes of the file at byte `offset`; returns the count (short at
    /// end of file).
    pub fn read(&self, file: &Entry, offset: u32, buf: &mut [u8]) -> Result<usize, FsError> {
        if file.is_dir() {
            return Err(FsError::IsADirectory);
        }
        if offset >= file.size {
            return Ok(0);
        }
        let want = buf.len().min((file.size - offset) as usize);
        let cluster_bytes = self.sectors_per_cluster as usize * SECTOR;
        // Skip whole clusters.
        let mut c = file.first;
        let mut skip = offset as usize / cluster_bytes;
        while skip > 0 {
            c = self.next_cluster(c)?.ok_or(FsError::Corrupt)?;
            skip -= 1;
        }
        let mut pos = offset as usize % cluster_bytes;
        let mut done = 0;
        let mut s = [0u8; SECTOR];
        while done < want {
            if c < 2 {
                return Err(FsError::Corrupt);
            }
            let base = self.cluster_sector(c)?;
            let sector = base + (pos / SECTOR) as u64;
            block::read(sector, &mut s)?;
            let in_sector = pos % SECTOR;
            let n = (SECTOR - in_sector).min(want - done);
            buf[done..done + n].copy_from_slice(&s[in_sector..in_sector + n]);
            done += n;
            pos += n;
            if pos == cluster_bytes {
                pos = 0;
                if done < want {
                    c = self.next_cluster(c)?.ok_or(FsError::Corrupt)?;
                }
            }
        }
        Ok(done)
    }

    /// Writes the raw 32-byte entry at `loc` back (size/first cluster updates).
    fn store_entry(&self, e: &Entry) -> Result<(), FsError> {
        if e.loc.cluster == 0 {
            return Err(FsError::Range); // the root pseudo-entry
        }
        let base = self.cluster_sector(e.loc.cluster)?;
        let sector = base + u64::from(e.loc.index / 16);
        let mut s = [0u8; SECTOR];
        block::read(sector, &mut s)?;
        let o = (e.loc.index % 16) as usize * 32;
        s[o..o + 11].copy_from_slice(&e.name);
        s[o + 11] = e.attr;
        s[o + 20..o + 22].copy_from_slice(&((e.first >> 16) as u16).to_le_bytes());
        s[o + 26..o + 28].copy_from_slice(&((e.first & 0xFFFF) as u16).to_le_bytes());
        s[o + 28..o + 32].copy_from_slice(&e.size.to_le_bytes());
        block::write(sector, &s)?;
        Ok(())
    }

    /// Creates an empty file at `path` (parent must exist; name must be 8.3 and new).
    pub fn create(&self, path: &[u8]) -> Result<Entry, FsError> {
        let (dir, name) = self.resolve_parent(path)?;
        if self.lookup_in(dir.first, &name)?.is_some() {
            return Err(FsError::Exists);
        }
        // A free slot in the directory, or a new cluster at the end of its chain.
        let mut slot = None;
        self.walk_dir(dir.first, |loc, e| {
            if e[0] == 0xE5 {
                slot = Some(loc);
                return true;
            }
            false
        })?;
        if slot.is_none() {
            // walk_dir stopped at the 0x00 marker (slot free) or at the end of the chain.
            slot = self.first_zero_slot(dir.first)?;
        }
        let loc = match slot {
            Some(l) => l,
            None => {
                let mut tail = dir.first;
                let mut hops = 0;
                while let Some(n) = self.next_cluster(tail)? {
                    tail = n;
                    hops += 1;
                    if hops > CHAIN_MAX {
                        return Err(FsError::Corrupt);
                    }
                }
                let n = self.alloc_cluster()?;
                self.fat_set(tail, n)?;
                EntryLoc {
                    cluster: n,
                    index: 0,
                }
            }
        };
        let e = Entry {
            name,
            attr: ATTR_ARCHIVE,
            first: 0,
            size: 0,
            loc,
        };
        self.store_entry(&e)?;
        Ok(e)
    }

    /// The first 0x00 (end marker) slot of a directory chain, if it has one.
    fn first_zero_slot(&self, dir: u32) -> Result<Option<EntryLoc>, FsError> {
        let mut c = dir;
        let mut hops = 0;
        let mut s = [0u8; SECTOR];
        loop {
            let base = self.cluster_sector(c)?;
            for i in 0..self.sectors_per_cluster {
                block::read(base + u64::from(i), &mut s)?;
                for k in 0..(SECTOR / 32) {
                    if s[k * 32] == 0 {
                        return Ok(Some(EntryLoc {
                            cluster: c,
                            index: i * 16 + k as u32,
                        }));
                    }
                }
            }
            hops += 1;
            match self.next_cluster(c)? {
                Some(n) if hops < CHAIN_MAX => c = n,
                _ => return Ok(None),
            }
        }
    }

    /// Writes `data` at byte `offset` (at most the current size: append or overwrite),
    /// allocating clusters as needed; updates the entry's size on disk and in `file`.
    pub fn write(&self, file: &mut Entry, offset: u32, data: &[u8]) -> Result<usize, FsError> {
        if file.is_dir() {
            return Err(FsError::IsADirectory);
        }
        // A stored first cluster that is no cluster of the volume (1, or at or past its end) is
        // a damaged entry: every write call on it, the empty one included, is refused before
        // the volume is asked anything, so no cluster is taken and no other file's chain is
        // followed from FAT entry 1.
        if file.first == 1 || file.first >= self.clusters + 2 {
            return Err(FsError::Corrupt);
        }
        if offset > file.size || data.len() as u64 + u64::from(offset) > u64::from(FILE_MAX) {
            return Err(FsError::Range);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let cluster_bytes = self.sectors_per_cluster as usize * SECTOR;
        // The volume must hold the whole call before any of it is written (files.md v1.7): the
        // clusters the bytes need beyond the chain the file has are counted, and when the
        // allocator cannot take that many the call answers DiskFull with nothing written and
        // nothing taken. The volume's lock is held to the end of the call, so the clusters
        // counted here are the ones the allocations below find.
        let need = (offset + data.len() as u32).div_ceil(cluster_bytes as u32);
        let have = self.chain_len(file.first, need)?;
        if need > have && !self.has_free(need - have)? {
            return Err(FsError::DiskFull);
        }
        // The call works on a copy of the entry, and the node every open shares takes it only
        // after the entry is stored (files.md v1.6): a failure at any write below leaves the
        // node equal to the stored entry. What the failed call allocated then stays allocated
        // with no owner, except a cluster already linked to an existing file's chain in the
        // first FAT copy, which stays on the chain past the size; bytes the call wrote inside
        // the old size stay written.
        let mut staged = *file;
        if staged.first == 0 {
            staged.first = self.alloc_cluster()?;
        }
        // Walk to the cluster holding `offset`, extending the chain when the offset is exactly
        // at the end of the last cluster.
        let mut c = staged.first;
        let mut skip = offset as usize / cluster_bytes;
        while skip > 0 {
            c = match self.next_cluster(c)? {
                Some(n) => n,
                None => {
                    let n = self.alloc_cluster()?;
                    self.fat_set(c, n)?;
                    n
                }
            };
            skip -= 1;
        }
        let mut pos = offset as usize % cluster_bytes;
        let mut done = 0;
        let mut s = [0u8; SECTOR];
        while done < data.len() {
            let base = self.cluster_sector(c)?;
            let sector = base + (pos / SECTOR) as u64;
            let in_sector = pos % SECTOR;
            let n = (SECTOR - in_sector).min(data.len() - done);
            if n < SECTOR {
                block::read(sector, &mut s)?;
            }
            s[in_sector..in_sector + n].copy_from_slice(&data[done..done + n]);
            block::write(sector, &s)?;
            done += n;
            pos += n;
            if pos == cluster_bytes && done < data.len() {
                pos = 0;
                c = match self.next_cluster(c)? {
                    Some(n) => n,
                    None => {
                        let n = self.alloc_cluster()?;
                        self.fat_set(c, n)?;
                        n
                    }
                };
            }
        }
        let end = offset + done as u32;
        if end > staged.size {
            staged.size = end;
        }
        self.store_entry(&staged)?;
        *file = staged;
        Ok(done)
    }

    /// Empties a file (size 0, no first cluster; the entry stays). The order is the entry, the
    /// node, the frees (files.md v1.5): the emptied entry is stored first, then the node every
    /// open shares follows it, then the old chain is freed. A failure before the entry is
    /// stored changes nothing; a failure after it leaves the file empty on the disk and in the
    /// node alike, with clusters of the old chain lost, the FSInfo count stale, or both, and
    /// is answered as an error. At no failure point of these writes does a name point at a freed
    /// cluster, given that the writes reach the disk in the order they are made (no flush
    /// separates the steps: a device cache that reorders them is not covered).
    pub fn truncate(&self, file: &mut Entry) -> Result<u32, FsError> {
        if file.is_dir() {
            return Err(FsError::IsADirectory);
        }
        let old_first = file.first;
        let mut emptied = *file;
        emptied.first = 0;
        emptied.size = 0;
        self.store_entry(&emptied)?;
        *file = emptied;
        if old_first >= 2 {
            self.free_chain(old_first)
        } else {
            Ok(0)
        }
    }

    /// Removes a file (not a directory). The entry is marked free first and its chain is freed
    /// after it (files.md v1.5): a failure before the entry is written changes nothing; a
    /// failure after it leaves no name, with clusters of the chain lost, the FSInfo count
    /// stale, or both, and is answered as an error (a second delete then answers that the name does not
    /// exist). At no failure point of these writes does a name point at a freed cluster, given
    /// that the writes reach the disk in the order they are made (no flush separates the
    /// steps: a device cache that reorders them is not covered).
    pub fn unlink(&self, path: &[u8]) -> Result<u32, FsError> {
        let e = self.lookup(path)?;
        if e.is_dir() {
            return Err(FsError::IsADirectory);
        }
        let mut dead = e;
        dead.name[0] = 0xE5;
        self.store_entry(&dead)?;
        let freed = if e.first >= 2 {
            self.free_chain(e.first)?
        } else {
            0
        };
        Ok(freed)
    }

    /// Makes the device's writes stable.
    pub fn sync(&self) -> Result<(), FsError> {
        block::flush().map_err(FsError::Io)
    }
}
