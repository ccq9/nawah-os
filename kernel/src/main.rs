//! nawah-os kernel (single UEFI image: ADR-0001 item 4, ADR-0002).
//!
//! Flow: firmware -> `boot::stub::efi_main` (pre-ExitBootServices) -> `kmain::kernel_main`
//! (post-ExitBootServices, receives `BootInfo` only — docs/contracts/boot.md).
//!
//! unsafe policy (ADR-0002 item 6, after Sol OS ADR-008): forbidden everywhere except the
//! modules listed below; every block carries a SAFETY comment (clippy enforces it).
#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]

use core::panic::PanicInfo;

#[macro_use]
mod console;

#[allow(unsafe_code)]
mod arch;
#[allow(unsafe_code)]
mod boot;
#[allow(unsafe_code)]
mod bootinfo;
#[allow(unsafe_code)]
mod cell;

mod kmain;

/// Build identity from tools/project.py (ASCII, < 32 bytes; see kernel/build.rs).
pub const BUILD_ID: &str = env!("NAWAH_BUILD_ID");

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("OSX|{}|kernel|panic|{}", BUILD_ID, info);
    arch::qemu::exit(arch::qemu::EXIT_PANIC)
}
