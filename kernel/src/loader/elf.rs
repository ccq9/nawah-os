//! ELF64 loader (WP-17, ADR-0012): static executables (ET_EXEC, x86-64, little-endian) whose
//! PT_LOAD segments lie inside the application window, each segment W^X, into a fresh user
//! address space, plus a guarded stack. Every field is bounds-checked before use; a malformed
//! image is refused with a stable error and nothing is left mapped.
//!
//! Reference: ELF-64 Object File Format / System V gABI (S41): ELF header (e_ident, e_type,
//! e_machine, e_entry, e_phoff, e_phentsize, e_phnum), program header (p_type, p_flags,
//! p_offset, p_vaddr, p_filesz, p_memsz, p_align), PT_LOAD = 1, PF_X = 1, PF_W = 2, PF_R = 4.

use crate::arch::paging::{NX, PAGE_4K, WRITE};
use crate::mm::addrspace::{self, AsError, UserSpace, USER_BASE};

/// Application window: segments must lie in `[APP_BASE, APP_END)`.
pub const APP_BASE: u64 = USER_BASE + 0x1000_0000;
pub const APP_END: u64 = USER_BASE + 0x2000_0000;
/// Stack: `STACK_PAGES` pages ending at `STACK_TOP`, guard page below.
pub const STACK_TOP: u64 = USER_BASE + 0x3000_0000;
pub const STACK_PAGES: u64 = 16;
const PH_MAX: usize = 64;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    NotElf64,
    NotLittleEndian,
    NotExecutable,
    WrongMachine,
    BadProgramHeaders,
    SegmentOutsideWindow,
    SegmentOverlap,
    FileRangeOutside,
    MemSmallerThanFile,
    /// A PT_LOAD segment is both writable and executable (W^X).
    WritableExecutable,
    EntryOutsideSegments,
    Space(AsError),
}

impl ElfError {
    pub fn code(&self) -> &'static str {
        match self {
            ElfError::TooShort => "K_E_ELF_TOO_SHORT",
            ElfError::BadMagic => "K_E_ELF_BAD_MAGIC",
            ElfError::NotElf64 => "K_E_ELF_NOT_64",
            ElfError::NotLittleEndian => "K_E_ELF_NOT_LE",
            ElfError::NotExecutable => "K_E_ELF_NOT_EXEC",
            ElfError::WrongMachine => "K_E_ELF_MACHINE",
            ElfError::BadProgramHeaders => "K_E_ELF_PHDRS",
            ElfError::SegmentOutsideWindow => "K_E_ELF_SEGMENT_RANGE",
            ElfError::SegmentOverlap => "K_E_ELF_SEGMENT_OVERLAP",
            ElfError::FileRangeOutside => "K_E_ELF_FILE_RANGE",
            ElfError::MemSmallerThanFile => "K_E_ELF_MEMSZ",
            ElfError::WritableExecutable => "K_E_ELF_WX",
            ElfError::EntryOutsideSegments => "K_E_ELF_ENTRY",
            ElfError::Space(_) => "K_E_ELF_SPACE",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Loaded {
    pub entry: u64,
    /// Initial user RSP: 8 below the 16-aligned stack top, as after a `call` (SysV ABI).
    pub rsp: u64,
    pub segments: u32,
    pub pages: u32,
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

/// A PT_LOAD entry after validation.
#[derive(Clone, Copy, Debug)]
pub struct Segment {
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    /// PF_X = 1, PF_W = 2, PF_R = 4.
    pub flags: u32,
}

impl Segment {
    pub fn executable(&self) -> bool {
        self.flags & 0x1 != 0
    }

    pub fn writable(&self) -> bool {
        self.flags & 0x2 != 0
    }
}

/// Parses and checks the image without touching any address space: the PT_LOAD segments (in
/// file order), their count and the entry point.
pub fn parse(image: &[u8]) -> Result<([Option<Segment>; PH_MAX], usize, u64), ElfError> {
    if image.len() < EHDR_SIZE {
        return Err(ElfError::TooShort);
    }
    if image[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::BadMagic);
    }
    if image[4] != 2 {
        return Err(ElfError::NotElf64);
    }
    if image[5] != 1 {
        return Err(ElfError::NotLittleEndian);
    }
    if u16_at(image, 16) != 2 {
        return Err(ElfError::NotExecutable);
    }
    if u16_at(image, 18) != 0x3E {
        return Err(ElfError::WrongMachine);
    }
    let entry = u64_at(image, 24);
    let phoff = u64_at(image, 32);
    let phentsize = usize::from(u16_at(image, 54));
    let phnum = usize::from(u16_at(image, 56));
    if phentsize != PHDR_SIZE || phnum == 0 || phnum > PH_MAX {
        return Err(ElfError::BadProgramHeaders);
    }
    let table_end = phoff
        .checked_add((phentsize * phnum) as u64)
        .ok_or(ElfError::BadProgramHeaders)?;
    if table_end > image.len() as u64 {
        return Err(ElfError::BadProgramHeaders);
    }
    let mut segs: [Option<Segment>; PH_MAX] = [None; PH_MAX];
    let mut n = 0;
    let mut entry_in_segment = false;
    for i in 0..phnum {
        let ph = phoff as usize + i * PHDR_SIZE;
        if u32_at(image, ph) != 1 {
            continue; // not PT_LOAD
        }
        let s = Segment {
            flags: u32_at(image, ph + 4),
            offset: u64_at(image, ph + 8),
            vaddr: u64_at(image, ph + 16),
            filesz: u64_at(image, ph + 32),
            memsz: u64_at(image, ph + 40),
        };
        if s.memsz == 0 {
            continue;
        }
        if s.filesz > s.memsz {
            return Err(ElfError::MemSmallerThanFile);
        }
        let file_end = s
            .offset
            .checked_add(s.filesz)
            .ok_or(ElfError::FileRangeOutside)?;
        if file_end > image.len() as u64 {
            return Err(ElfError::FileRangeOutside);
        }
        let mem_end = s
            .vaddr
            .checked_add(s.memsz)
            .ok_or(ElfError::SegmentOutsideWindow)?;
        if s.vaddr < APP_BASE || mem_end > APP_END {
            return Err(ElfError::SegmentOutsideWindow);
        }
        if s.flags & 0x3 == 0x3 {
            return Err(ElfError::WritableExecutable);
        }
        // Page-granular overlap with the segments seen so far (each PT_LOAD must start on its
        // own page: the linker is run with -z separate-loadable-segments).
        let (lo, hi) = (s.vaddr & !(PAGE_4K - 1), mem_end.next_multiple_of(PAGE_4K));
        for other in segs.iter().flatten() {
            let (olo, ohi) = (
                other.vaddr & !(PAGE_4K - 1),
                (other.vaddr + other.memsz).next_multiple_of(PAGE_4K),
            );
            if lo < ohi && olo < hi {
                return Err(ElfError::SegmentOverlap);
            }
        }
        if s.flags & 0x1 != 0 && (s.vaddr..mem_end).contains(&entry) {
            entry_in_segment = true;
        }
        segs[n] = Some(s);
        n += 1;
    }
    if n == 0 {
        return Err(ElfError::BadProgramHeaders);
    }
    if !entry_in_segment {
        return Err(ElfError::EntryOutsideSegments);
    }
    Ok((segs, n, entry))
}

/// Loads `image` into `space`: segments with W^X permissions, file bytes copied, the rest
/// zero, and the stack. On any error the caller destroys the space (nothing else to undo).
pub fn load(space: &mut UserSpace, image: &[u8]) -> Result<Loaded, ElfError> {
    let (segs, n, entry) = parse(image)?;
    let mut pages = 0u32;
    for s in segs.iter().take(n).flatten() {
        let mut flags = 0;
        if s.writable() {
            flags |= WRITE;
        }
        if !s.executable() {
            flags |= NX;
        }
        let mem_end = s.vaddr + s.memsz;
        let mut page = s.vaddr & !(PAGE_4K - 1);
        while page < mem_end {
            let phys = space.map_new_page(page, flags).map_err(ElfError::Space)?;
            pages += 1;
            // Bytes of the file that land in this page: [max(page, vaddr), min(page+4K, vaddr+filesz)).
            let copy_lo = page.max(s.vaddr);
            let copy_hi = (page + PAGE_4K).min(s.vaddr + s.filesz);
            if copy_lo < copy_hi {
                let file_lo = (s.offset + (copy_lo - s.vaddr)) as usize;
                let file_hi = file_lo + (copy_hi - copy_lo) as usize;
                addrspace::write_frame_at(
                    phys,
                    (copy_lo - page) as usize,
                    &image[file_lo..file_hi],
                );
            }
            page += PAGE_4K;
        }
    }
    let stack_base = STACK_TOP - STACK_PAGES * PAGE_4K;
    let mut page = stack_base;
    while page < STACK_TOP {
        space
            .map_new_page(page, WRITE | NX)
            .map_err(ElfError::Space)?;
        pages += 1;
        page += PAGE_4K;
    }
    Ok(Loaded {
        entry,
        rsp: STACK_TOP - 8,
        segments: n as u32,
        pages,
    })
}
