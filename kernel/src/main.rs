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

#[cfg(target_arch = "x86_64")]
extern crate alloc;

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
#[allow(unsafe_code)]
mod mm;
#[allow(unsafe_code)]
mod panic;
#[allow(unsafe_code)]
mod sync;

mod kmain;
#[cfg(target_arch = "x86_64")]
mod object;
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod sched;
#[cfg(target_arch = "x86_64")]
mod syscall;
#[cfg(target_arch = "x86_64")]
mod user;

#[cfg(feature = "ktest")]
mod ktest;

/// Build identity from tools/project.py (ASCII, < 32 bytes; see kernel/build.rs).
pub const BUILD_ID: &str = env!("NAWAH_BUILD_ID");
