//! `BootInfo` — the only thing the pre-ExitBootServices stage (`boot`) hands to the kernel
//! (`kmain`). Contract: docs/contracts/boot.md, version 1.
//! Deliberately contains no firmware function tables: the kernel cannot reach Boot Services
//! through it (REQ-M1-003, enforced statically by TST-M1-NOBS).

/// "WNBTNIFO" little-endian.
pub const MAGIC: u64 = 0x4F46_494E_5442_4E57;
pub const VERSION: u32 = 1;
pub const BUILD_ID_LEN: usize = 32;
/// Largest UEFI memory map accepted in M1 (docs/contracts/boot.md).
pub const MAX_MEMMAP_BYTES: usize = 64 * 1024;

/// EfiConventionalMemory (UEFI 2.11 §7.2.1, EFI_MEMORY_TYPE).
pub const MEM_CONVENTIONAL: u32 = 7;

/// Mirrors EFI_MEMORY_DESCRIPTOR (UEFI 2.11 §7.2.3) without naming firmware types.
/// The firmware's `descriptor_size` may be larger than this struct; iterate with it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemDesc {
    pub typ: u32,
    pub pad: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub pages: u64,
    pub attribute: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Framebuffer {
    pub base: u64,
    pub width: u32,
    pub height: u32,
    pub pitch_px: u32,
    pub pixel_format: u32,
    pub present: u8,
}

#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub build_id: [u8; BUILD_ID_LEN],
    /// Kernel-owned buffer holding the final memory map (handed over after EBS).
    pub memmap: *const u8,
    pub memmap_bytes: usize,
    pub descriptor_size: usize,
    pub descriptor_version: u32,
    pub ebs_attempts: u32,
    /// The key accepted by ExitBootServices.
    pub map_key: usize,
    /// Not populated in M1 (`present == 0`).
    pub fb: Framebuffer,
    /// 0 in M1.
    pub rsdp: u64,
    /// EFI_RUNTIME_SERVICES*, opaque to the kernel in M1.
    pub runtime_services: *const u8,
}

// SAFETY: BootInfo is written once on the boot path (BootCell contract) and only read after.
unsafe impl Sync for BootInfo {}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic: 0,
            version: 0,
            size: 0,
            build_id: [0; BUILD_ID_LEN],
            memmap: core::ptr::null(),
            memmap_bytes: 0,
            descriptor_size: 0,
            descriptor_version: 0,
            ebs_attempts: 0,
            map_key: 0,
            fb: Framebuffer {
                base: 0,
                width: 0,
                height: 0,
                pitch_px: 0,
                pixel_format: 0,
                present: 0,
            },
            rsdp: 0,
            runtime_services: core::ptr::null(),
        }
    }

    /// Structural validity: magic, version and size as the contract defines them.
    pub fn is_valid(&self) -> bool {
        self.magic == MAGIC
            && self.version == VERSION
            && self.size as usize == core::mem::size_of::<Self>()
            && !self.memmap.is_null()
            && self.descriptor_size >= core::mem::size_of::<MemDesc>()
            && self.memmap_bytes <= MAX_MEMMAP_BYTES
    }

    pub fn build_id(&self) -> &str {
        let end = self
            .build_id
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(BUILD_ID_LEN);
        core::str::from_utf8(&self.build_id[..end]).unwrap_or("?")
    }

    /// Safe iterator over the memory map; the only place that dereferences it.
    pub fn memmap(&self) -> MemMapIter<'_> {
        MemMapIter {
            info: self,
            offset: 0,
        }
    }
}

pub struct MemMapIter<'a> {
    info: &'a BootInfo,
    offset: usize,
}

impl Iterator for MemMapIter<'_> {
    type Item = MemDesc;
    fn next(&mut self) -> Option<MemDesc> {
        if !self.info.is_valid()
            || self.offset + core::mem::size_of::<MemDesc>() > self.info.memmap_bytes
        {
            return None;
        }
        // SAFETY: is_valid() guarantees a non-null map of memmap_bytes with descriptor_size >=
        // size_of::<MemDesc>(); the bounds check above keeps the read inside the map. The buffer
        // is kernel-owned and never written after boot, so an unaligned copy-read is sound.
        let desc = unsafe {
            self.info
                .memmap
                .add(self.offset)
                .cast::<MemDesc>()
                .read_unaligned()
        };
        self.offset += self.info.descriptor_size;
        Some(desc)
    }
}
