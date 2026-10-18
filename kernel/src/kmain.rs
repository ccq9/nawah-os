//! Post-ExitBootServices kernel entry. Receives `BootInfo` only (docs/contracts/boot.md);
//! this module must never name firmware tables (TST-M1-NOBS). Safe Rust only.

use crate::arch;
use crate::bootinfo::{BootInfo, MEM_CONVENTIONAL};

/// Stage M1: validate the handoff, account the memory map, emit the trace the oracle checks,
/// then end the lab run. Later stages continue into M2 initialisation instead of exiting.
pub fn kernel_main(bi: &BootInfo) -> ! {
    // CPU tables first: from here on a fault is a diagnostic line, not a silent reset.
    arch::init_cpu();
    kprintln!(
        "OSX|{}|kernel|cpu_tables|gdt=1|tss=1|idt=1|stack=kernel",
        bi.build_id()
    );
    if !bi.is_valid() {
        kprintln!("OSX|?|kernel|panic|code=K_E_BAD_BOOTINFO");
        arch::halt();
    }
    let build_id = bi.build_id();
    let mut descriptors: u64 = 0;
    let mut conventional_pages: u64 = 0;
    for d in bi.memmap() {
        descriptors += 1;
        if d.typ == MEM_CONVENTIONAL {
            conventional_pages += d.pages;
        }
    }
    kprintln!(
        "OSX|{}|kernel|post_ebs|map_key={:#x}|descriptors={}|conventional_pages={}|ebs_attempts={}",
        build_id,
        bi.map_key,
        descriptors,
        conventional_pages,
        bi.ebs_attempts
    );
    #[cfg(feature = "ktest")]
    crate::ktest::run();
    #[cfg(not(feature = "ktest"))]
    {
        kprintln!("OSX|{}|kernel|m1_done|exit=0x10", build_id);
        arch::qemu::exit(arch::qemu::EXIT_OK)
    }
}
