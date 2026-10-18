//! Minimal raw UEFI definitions for the pre-ExitBootServices stage, written from UEFI 2.11
//! (§4.3 System Table, §4.4 Boot Services table layout, §7.2.3 GetMemoryMap, §7.4.6
//! ExitBootServices). Only the slots we call are typed; the others keep the table layout.
//! This module must never be visible to `kmain` (REQ-M1-003).

use core::ffi::c_void;

pub type Status = usize;
pub type Handle = *mut c_void;

pub const ERROR_BIT: usize = 1 << 63;
pub const INVALID_PARAMETER: Status = ERROR_BIT | 2;
pub const BUFFER_TOO_SMALL: Status = ERROR_BIT | 5;
pub const SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;

pub fn is_error(s: Status) -> bool {
    (s as isize) < 0
}

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

pub type GetMemoryMapFn = unsafe extern "efiapi" fn(
    memory_map_size: *mut usize,
    memory_map: *mut u8,
    map_key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> Status;

pub type ExitBootServicesFn =
    unsafe extern "efiapi" fn(image_handle: Handle, map_key: usize) -> Status;

/// EFI_BOOT_SERVICES (UEFI 2.11 §4.4). Slot order is the ABI; do not reorder.
#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
    pub raise_tpl: *const c_void,
    pub restore_tpl: *const c_void,
    pub allocate_pages: *const c_void,
    pub free_pages: *const c_void,
    pub get_memory_map: GetMemoryMapFn,
    pub allocate_pool: *const c_void,
    pub free_pool: *const c_void,
    pub create_event: *const c_void,
    pub set_timer: *const c_void,
    pub wait_for_event: *const c_void,
    pub signal_event: *const c_void,
    pub close_event: *const c_void,
    pub check_event: *const c_void,
    pub install_protocol_interface: *const c_void,
    pub reinstall_protocol_interface: *const c_void,
    pub uninstall_protocol_interface: *const c_void,
    pub handle_protocol: *const c_void,
    pub reserved: *const c_void,
    pub register_protocol_notify: *const c_void,
    pub locate_handle: *const c_void,
    pub locate_device_path: *const c_void,
    pub install_configuration_table: *const c_void,
    pub load_image: *const c_void,
    pub start_image: *const c_void,
    pub exit: *const c_void,
    pub unload_image: *const c_void,
    pub exit_boot_services: ExitBootServicesFn,
    pub get_next_monotonic_count: *const c_void,
    pub stall: *const c_void,
    pub set_watchdog_timer: *const c_void,
    pub connect_controller: *const c_void,
    pub disconnect_controller: *const c_void,
    pub open_protocol: *const c_void,
    pub close_protocol: *const c_void,
    pub open_protocol_information: *const c_void,
    pub protocols_per_handle: *const c_void,
    pub locate_handle_buffer: *const c_void,
    pub locate_protocol: *const c_void,
    pub install_multiple_protocol_interfaces: *const c_void,
    pub uninstall_multiple_protocol_interfaces: *const c_void,
    pub calculate_crc32: *const c_void,
    pub copy_mem: *const c_void,
    pub set_mem: *const c_void,
    pub create_event_ex: *const c_void,
}

/// EFI_SYSTEM_TABLE (UEFI 2.11 §4.3).
#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *const c_void,
    pub console_out_handle: Handle,
    pub con_out: *const c_void,
    pub standard_error_handle: Handle,
    pub std_err: *const c_void,
    pub runtime_services: *const c_void,
    pub boot_services: *const BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *const c_void,
}

// Layout checks against the C definitions that booted in M1 (and UEFI 2.11 figures).
const _: () = assert!(core::mem::size_of::<TableHeader>() == 24);
const _: () = assert!(core::mem::size_of::<SystemTable>() == 24 + 12 * 8);
const _: () = assert!(core::mem::size_of::<BootServices>() == 24 + 44 * 8);
