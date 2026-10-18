//! Architecture-specific code. Everything that touches hardware directly lives here
//! (ADR-0002 item 6). The rest of the kernel uses only the re-exported interface.

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    adopt_stacks, continue_on_stack, cpu_id, init_console, init_cpu, interrupts, irq,
    jump_on_kernel_stack, paging, pit, qemu, syscall, user_programs, Serial,
};

#[cfg(all(target_arch = "x86_64", feature = "ktest"))]
pub use x86_64::{apic, fwcfg, ktest};

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    cpu_id, current_el, init_console, init_cpu, interrupts, jump_on_kernel_stack, qemu, Serial,
};
