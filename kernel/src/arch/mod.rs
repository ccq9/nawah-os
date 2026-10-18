//! Architecture-specific code. Everything that touches hardware directly lives here
//! (ADR-0002 item 6). The rest of the kernel uses only the re-exported interface.

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    acpi, adopt_stacks, apic, com2, context, continue_on_stack, cpu_id, i8042, init_console,
    init_cpu, interrupts, irq, jump_on_kernel_stack, mmio, paging, pci, pit, qemu, smp, spin_hint,
    syscall, tlb, user_programs, Serial,
};

#[cfg(all(target_arch = "x86_64", feature = "ktest"))]
pub use x86_64::{fwcfg, ktest};

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    cpu_id, current_el, init_console, init_cpu, interrupts, jump_on_kernel_stack, qemu, spin_hint,
    Serial,
};
