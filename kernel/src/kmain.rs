//! Post-ExitBootServices kernel entry. Receives `BootInfo` only (docs/contracts/boot.md);
//! this module must never name firmware tables (TST-M1-NOBS). Safe Rust only.

use crate::arch;
use crate::bootinfo::{BootInfo, MEM_CONVENTIONAL};
use crate::mm;

/// M1/M2 boot path: own CPU tables, validate the handoff, account the memory map, bring up the
/// frame allocator and the kernel address space, then continue on a guarded stack.
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

    // Kernel-owned page tables (WP-09). Failure here is unrecoverable: the firmware tables are
    // the only alternative and they are about to be reclaimed.
    let ks = match mm::vmm::init(bi) {
        Ok(ks) => ks,
        Err(e) => {
            kprintln!("OSX|{}|kernel|panic|code={}", build_id, e.code());
            arch::halt()
        }
    };
    kprintln!(
        "OSX|{}|kernel|vmm|cr3={:#x}|image={:#x}+{:#x}|wp={}|nxe={}|text_rx={}|data_rw_nx={}|sections_rx={}|sections_ro={}|sections_rw={}|ram_mib={}|reclaimed_frames={}|direct_ok={}",
        build_id,
        ks.cr3,
        ks.image_base,
        ks.image_size,
        u8::from(ks.wp),
        u8::from(ks.nxe),
        u8::from(ks.text_rx),
        u8::from(ks.data_rw_nx),
        ks.sections_rx,
        ks.sections_ro,
        ks.sections_rw,
        ks.ram_bytes_mapped >> 20,
        ks.reclaimed_frames,
        u8::from(ks.direct_ok)
    );
    arch::adopt_stacks(
        (ks.kernel_stack.base, ks.kernel_stack.size),
        (ks.df_stack.base, ks.df_stack.size),
    );
    arch::continue_on_stack(ks.kernel_stack.top(), kernel_main_guarded, bi)
}

/// Continues on the guarded kernel stack with IST1 on the guarded #DF stack.
extern "sysv64" fn kernel_main_guarded(bi: &BootInfo) -> ! {
    let build_id = bi.build_id();
    match mm::vmm::kernel_space() {
        Some(ks) => kprintln!(
            "OSX|{}|kernel|stack|guarded=1|base={:#x}|guard={:#x}|ist1_guard={:#x}",
            build_id,
            ks.kernel_stack.base,
            ks.kernel_stack.guard,
            ks.df_stack.guard
        ),
        None => {
            kprintln!("OSX|{}|kernel|panic|code=K_E_VMM_NOT_ACTIVE", build_id);
            arch::halt()
        }
    }

    // Interrupts (WP-10): ACPI MADT -> PIC remapped and masked, local APIC enabled with a
    // calibrated timer, every I/O APIC masked. Interrupts are still off here.
    let irq = match arch::irq::init(bi.rsdp) {
        Ok(i) => i,
        Err(e) => {
            kprintln!("OSX|{}|kernel|panic|code={}", build_id, e.code());
            arch::halt()
        }
    };
    kprintln!(
        "OSX|{}|kernel|irq|pic_masks={:#x},{:#x}|lapic_mode={:?}|lapic_id={}|lapic_version={:#x}|lapic_hz={}|svr={:#x}|cpus={}|ioapics={}|ioapic_entries={}|ioapic_masked={}|ioapic_version={:#x}|overrides={}|pcat_compat={}|timer_hz={}",
        build_id,
        irq.pic_masks.0,
        irq.pic_masks.1,
        irq.lapic.mode,
        irq.lapic.id,
        irq.lapic.version,
        irq.lapic.timer_hz,
        irq.svr,
        irq.cpus,
        irq.ioapics,
        irq.ioapic_entries,
        irq.ioapic_masked,
        irq.ioapic_version,
        irq.overrides,
        u8::from(irq.pcat_compat),
        irq.timer_hz
    );
    // Timer self-check in every build: interrupts on for a PIT-measured 50 ms window, then off
    // again. At 1000 Hz the window holds ~50 ticks; the band below tolerates emulator jitter.
    arch::interrupts::enable();
    let pit_ok = arch::pit::wait_ms(50);
    arch::interrupts::disable();
    let c = arch::irq::counters();
    let timer_ok = pit_ok
        && (25..=100).contains(&c.ticks)
        && c.total == c.ticks
        && c.unexpected == 0
        && c.max_depth == 1
        && !arch::interrupts::enabled();
    kprintln!(
        "OSX|{}|kernel|timer|window_ms=50|pit_ok={}|ticks={}|total={}|unexpected={}|last_unexpected={:#x}|spurious={}|max_depth={}|selfcheck={}",
        build_id,
        u8::from(pit_ok),
        c.ticks,
        c.total,
        c.unexpected,
        c.last_unexpected_vector,
        c.spurious,
        c.max_depth,
        u8::from(timer_ok)
    );
    #[cfg(feature = "ktest")]
    crate::ktest::run();
    #[cfg(not(feature = "ktest"))]
    {
        // Nothing waits on the timer yet; stop it so the shutdown is quiet.
        arch::irq::timer_stop();
        kprintln!("OSX|{}|kernel|m1_done|exit=0x10", build_id);
        arch::qemu::exit(arch::qemu::EXIT_OK)
    }
}
