//! Memory management. `pmm`: physical frames (WP-08). `vmm`: the kernel address space (WP-09).
//! `heap`: kernel heap (WP-13). `addrspace`: user address spaces (WP-13).
#[cfg(target_arch = "x86_64")]
pub mod addrspace;
#[cfg(target_arch = "x86_64")]
pub mod heap;
pub mod pmm;
#[cfg(target_arch = "x86_64")]
pub mod vmm;
