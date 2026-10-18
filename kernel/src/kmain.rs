//! Post-ExitBootServices kernel entry. Receives `BootInfo` only (docs/contracts/boot.md);
//! this module must never name firmware tables (TST-M1-NOBS). Safe Rust only.

use crate::arch;
use crate::bootinfo::{BootInfo, MEM_CONVENTIONAL};
use crate::mm;

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
    mm::pmm::init(bi);
    let st = mm::pmm::stats();
    // Self-check in every build: one frame out, one frame back, counters unchanged.
    let selfcheck = match mm::pmm::alloc_frame() {
        Some(f) => mm::pmm::free_frame(f).is_ok() && mm::pmm::stats().free_frames == st.free_frames,
        None => false,
    };
    kprintln!(
        "OSX|{}|kernel|pmm|managed_frames={}|free_frames={}|allocated_frames={}|bitmap_frames={}|selfcheck={}",
        build_id,
        st.managed_frames,
        st.free_frames,
        st.allocated_frames,
        st.bitmap_frames,
        u8::from(selfcheck)
    );
    #[cfg(feature = "ktest")]
    crate::ktest::run();
    #[cfg(not(feature = "ktest"))]
    {
        kprintln!("OSX|{}|kernel|m1_done|exit=0x10", build_id);
        arch::qemu::exit(arch::qemu::EXIT_OK)
    }
}
