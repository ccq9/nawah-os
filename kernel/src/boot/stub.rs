//! Pre-ExitBootServices stage of the single-image kernel (ADR-0001 item 4, docs/contracts/boot.md).
//!
//! Responsibilities: validate the system table, obtain a fresh memory map into a kernel-owned
//! buffer, call ExitBootServices with its key — one retry with a fresh map on
//! EFI_INVALID_PARAMETER (UEFI 2.11 §7.4.6: "GetMemoryMap() with ExitBootServices() must be
//! called again"; after the first call only Memory Allocation Services may be used) — then hand
//! `BootInfo` to `kmain::kernel_main`. On failure: diagnostic line, lab exit code, halt. No reboot.
//!
//! Feature `inject_ebs_fail` (TST-M1-NEG): passes a deliberately stale key so the firmware must
//! reject it twice and the failure path is exercised.

use super::efi::{self, BootServices, Handle, Status, SystemTable};
use crate::arch;
use crate::bootinfo::{BootInfo, Framebuffer, BUILD_ID_LEN, MAGIC, MAX_MEMMAP_BYTES, VERSION};
use crate::cell::BootCell;
use crate::BUILD_ID;

/// Kernel-owned buffer for the firmware memory map (stays valid after EBS: it is image memory).
#[repr(C, align(16))]
struct MapBuffer([u8; MAX_MEMMAP_BYTES]);

static MEMMAP: BootCell<MapBuffer> = BootCell::new(MapBuffer([0; MAX_MEMMAP_BYTES]));
static BOOT_INFO: BootCell<BootInfo> = BootCell::new(BootInfo::empty());

#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x86_64";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "aarch64";

fn fail(code: &str, status: Status) -> ! {
    kprintln!(
        "OSX|{}|boot|error|code={}|status={:#x}",
        BUILD_ID,
        code,
        status
    );
    kprintln!("OSX|{}|boot|halt|reboot=0", BUILD_ID);
    arch::qemu::exit(arch::qemu::EXIT_BOOT_FAIL)
}

/// UEFI entry point (PE subsystem efi_application, entry `efi_main` — rustc target spec).
#[no_mangle]
pub extern "efiapi" fn efi_main(image: Handle, st: *const SystemTable) -> ! {
    arch::init_console();
    kprintln!(
        "OSX|{}|boot|start|arch={}|boot=uefi|stage=pre_ebs",
        BUILD_ID,
        ARCH
    );

    if st.is_null() {
        fail("BOOT_E_BAD_TABLE", efi::INVALID_PARAMETER);
    }
    let buf = MEMMAP.get().cast::<u8>();
    // ACPI: the RSDP address comes from the EFI configuration table (UEFI 2.11 §4.6; ACPI 6.5
    // §5.2.5.2), ACPI 2.0+ GUID first, ACPI 1.0 GUID as fallback; 0 when absent. Only the
    // physical address leaves this block.
    let rsdp: u64 = {
        // SAFETY: as below — a live, non-null EFI_SYSTEM_TABLE, read only.
        let st = unsafe { &*st };
        efi::find_configuration_table(st, &efi::ACPI_20_TABLE_GUID)
            .or_else(|| efi::find_configuration_table(st, &efi::ACPI_10_TABLE_GUID))
            .unwrap_or(0)
    };
    kprintln!("OSX|{}|boot|acpi|rsdp={:#x}", BUILD_ID, rsdp);
    // Everything that can see firmware tables lives in this block; nothing from it reaches the
    // kernel except plain numbers and the kernel-owned map buffer (REQ-M1-003).
    let fb;
    let (final_size, accepted_key, desc_size, desc_ver, attempts, runtime_services) = {
        // SAFETY: firmware passes a pointer to a live EFI_SYSTEM_TABLE for the lifetime of the
        // image; we checked it is non-null and we only read it.
        let st = unsafe { &*st };
        if st.hdr.signature != efi::SYSTEM_TABLE_SIGNATURE || st.boot_services.is_null() {
            fail("BOOT_E_BAD_TABLE", efi::INVALID_PARAMETER);
        }
        // SAFETY: non-null Boot Services table owned by firmware, valid until EBS succeeds.
        let bs: &BootServices = unsafe { &*st.boot_services };

        // Graphics (WP-32, ADR-0019 §1): the linear frame buffer as firmware set it up, 32-bit
        // RGBX/BGRX only; anything else is reported absent. Numbers only (REQ-M1-003).
        fb = match efi::graphics_mode(bs) {
            Some((base, w, h, stride, format, size))
                if format <= 1
                    && base != 0
                    && w > 0
                    && h > 0
                    && stride >= w
                    && u64::from(stride) * u64::from(h) * 4 <= size =>
            {
                Framebuffer {
                    base,
                    width: w,
                    height: h,
                    pitch_px: stride,
                    pixel_format: format,
                    present: 1,
                }
            }
            _ => Framebuffer {
                base: 0,
                width: 0,
                height: 0,
                pitch_px: 0,
                pixel_format: 0,
                present: 0,
            },
        };
        kprintln!(
            "OSX|{}|boot|gop|present={}|w={}|h={}|stride={}|format={}|base={:#x}",
            BUILD_ID,
            fb.present,
            fb.width,
            fb.height,
            fb.pitch_px,
            fb.pixel_format,
            fb.base
        );

        // Probe the size first (EFI_BUFFER_TOO_SMALL returns the needed size, §7.2.3).
        let mut map_size: usize = 0;
        let mut map_key: usize = 0;
        let mut desc_size: usize = 0;
        let mut desc_ver: u32 = 0;
        // SAFETY: a zero-size probe with a null buffer is the documented way to query the size.
        let s = unsafe {
            (bs.get_memory_map)(
                &mut map_size,
                core::ptr::null_mut(),
                &mut map_key,
                &mut desc_size,
                &mut desc_ver,
            )
        };
        if s != efi::BUFFER_TOO_SMALL {
            fail("BOOT_E_MAP_PROBE", s);
        }
        // The map may still grow before the real call (§7.2.3 warns about allocations; we allocate
        // nothing but keep the slack). It must fit the kernel-owned buffer.
        if map_size + 2 * desc_size > MAX_MEMMAP_BYTES {
            fail("BOOT_E_MAP_TOO_LARGE", map_size);
        }

        let mut attempts: u32 = 0;
        loop {
            let mut sz = MAX_MEMMAP_BYTES;
            // SAFETY: `buf` points at a static buffer of MAX_MEMMAP_BYTES bytes, 16-byte aligned,
            // written only here on the boot path (BootCell contract).
            let s = unsafe {
                (bs.get_memory_map)(&mut sz, buf, &mut map_key, &mut desc_size, &mut desc_ver)
            };
            if efi::is_error(s) {
                fail("BOOT_E_MAP_GET", s);
            }
            kprintln!(
                "OSX|{}|boot|memmap|bytes={}|desc_size={}|key={:#x}",
                BUILD_ID,
                sz,
                desc_size,
                map_key
            );
            let key = if cfg!(feature = "inject_ebs_fail") {
                map_key ^ 1
            } else {
                map_key
            };
            attempts += 1;
            // SAFETY: ExitBootServices with the key of the map just fetched (UEFI 2.11 §7.4.6).
            // After success no boot service may be used; the tables die with this block.
            let s = unsafe { (bs.exit_boot_services)(image, key) };
            if !efi::is_error(s) {
                break (
                    sz,
                    key,
                    desc_size,
                    desc_ver,
                    attempts,
                    st.runtime_services.cast::<u8>(),
                );
            }
            if s == efi::INVALID_PARAMETER && attempts < 2 {
                kprintln!("OSX|{}|boot|ebs|retry=1|status={:#x}", BUILD_ID, s);
                continue;
            }
            fail("BOOT_E_EBS_FAILED", s);
        }
    };

    let mut id = [0u8; BUILD_ID_LEN];
    for (dst, src) in id.iter_mut().zip(BUILD_ID.bytes()) {
        *dst = src;
    }
    let info = BootInfo {
        magic: MAGIC,
        version: VERSION,
        size: core::mem::size_of::<BootInfo>() as u32,
        build_id: id,
        memmap: buf,
        memmap_bytes: final_size,
        descriptor_size: desc_size,
        descriptor_version: desc_ver,
        ebs_attempts: attempts,
        map_key: accepted_key,
        fb,
        rsdp,
        runtime_services,
    };
    // SAFETY: single write on the boot path before any reader exists (BootCell contract).
    unsafe { BOOT_INFO.get().write(info) };
    kprintln!("OSX|{}|boot|ebs|ok=1|attempts={}", BUILD_ID, attempts);
    // SAFETY: BOOT_INFO was fully written above and is never written again; the shared
    // reference lives for the rest of the kernel's life.
    let info: *const BootInfo = BOOT_INFO.get();
    // SAFETY: `kernel_entry` never returns; BOOT_INFO is a static that lives for the kernel's life.
    unsafe { arch::jump_on_kernel_stack(kernel_entry, info.cast::<u8>()) }
}

/// First function on the kernel-owned stack (`bi` arrives in the first argument register).
#[cfg(target_arch = "x86_64")]
extern "sysv64" fn kernel_entry(bi: *const u8) -> ! {
    kernel_entry_inner(bi)
}

#[cfg(target_arch = "aarch64")]
extern "C" fn kernel_entry(bi: *const u8) -> ! {
    kernel_entry_inner(bi)
}

fn kernel_entry_inner(bi: *const u8) -> ! {
    // SAFETY: `bi` is BOOT_INFO, fully written before the jump and never written again.
    let info: &'static BootInfo = unsafe { &*bi.cast::<BootInfo>() };
    crate::kmain::kernel_main(info)
}
