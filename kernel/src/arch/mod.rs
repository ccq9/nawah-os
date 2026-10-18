//! Architecture-specific code. Everything that touches hardware directly lives here
//! (ADR-0002 item 6). The rest of the kernel uses only the re-exported interface.

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    adopt_stacks, continue_on_stack, halt, init_console, init_cpu, jump_on_kernel_stack, paging,
    qemu, Serial,
};

#[cfg(all(target_arch = "x86_64", feature = "ktest"))]
pub use x86_64::{fwcfg, ktest};
