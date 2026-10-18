//! Memory management. `pmm`: physical frames (WP-08). `vmm`: the kernel address space (WP-09).
//! `heap`: kernel heap (WP-13). `addrspace`: user address spaces (WP-13).
pub mod addrspace;
pub mod heap;
pub mod pmm;
pub mod vmm;
