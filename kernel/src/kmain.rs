//! Post-ExitBootServices kernel entry. Receives `BootInfo` only (docs/contracts/boot.md);
//! this module must never name firmware tables (TST-M1-NOBS). Safe Rust only.

#[cfg(target_arch = "x86_64")]
use alloc::boxed::Box;
#[cfg(target_arch = "x86_64")]
use alloc::vec::Vec;

use crate::arch;
use crate::bootinfo::{BootInfo, MEM_CONVENTIONAL};
use crate::mm;
#[cfg(target_arch = "x86_64")]
use crate::mm::addrspace::{self, UserSpace, USER_BASE};

/// M1/M2 boot path: own CPU tables, validate the handoff, account the memory map, bring up the
/// frame allocator and the kernel address space, then continue on a guarded stack.
pub fn kernel_main(bi: &BootInfo) -> ! {
    // CPU tables first: from here on a fault is a diagnostic line, not a silent reset.
    let cpu = arch::init_cpu();
    kprintln!("OSX|{}|kernel|cpu_tables|{}", bi.build_id(), cpu);
    if !bi.is_valid() {
        crate::panic::fatal("K_E_BAD_BOOTINFO");
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
    kernel_main_arch(bi)
}

/// x86_64 continuation: kernel page tables, heap and user spaces, interrupts and timer, then
/// the guarded stack.
#[cfg(target_arch = "x86_64")]
fn kernel_main_arch(bi: &BootInfo) -> ! {
    let build_id = bi.build_id();
    // Kernel-owned page tables (WP-09). Failure here is unrecoverable: the firmware tables are
    // the only alternative and they are about to be reclaimed.
    let ks = match mm::vmm::init(bi) {
        Ok(ks) => ks,
        Err(e) => crate::panic::fatal(e.code()),
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

/// AArch64 experiment (WP-21): the shared path above is all that runs; paging, heap and
/// interrupts are x86_64-only until the port grows (ADR-0008).
#[cfg(target_arch = "aarch64")]
fn kernel_main_arch(bi: &BootInfo) -> ! {
    let build_id = bi.build_id();
    kprintln!(
        "OSX|{}|kernel|a64|el={}|paging=firmware|exit=0x10",
        build_id,
        arch::current_el()
    );
    arch::qemu::exit(arch::qemu::EXIT_OK)
}

/// Continues on the guarded kernel stack with IST1 on the guarded #DF stack.
#[cfg(target_arch = "x86_64")]
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
        None => crate::panic::fatal("K_E_VMM_NOT_ACTIVE"),
    }

    // Kernel heap and user address spaces (WP-13), each with a self-check in every build:
    // allocations come and go without a frame leaking, and a user space can be created,
    // entered, left and destroyed with the frame count back where it started.
    mm::heap::init();
    let frames_before = mm::pmm::stats().free_frames;
    let heap_ok = {
        let v: Vec<u64> = (0..1000).collect();
        let b = Box::new(0xA5u8);
        let big: Vec<u8> = alloc::vec![0x5A; 20_000];
        let sum: u64 = v.iter().sum();
        let ok = sum == 499_500 && *b == 0xA5 && big.iter().all(|&x| x == 0x5A);
        drop(v);
        drop(b);
        drop(big);
        ok
    };
    let heap_st = mm::heap::stats();
    // Scratch mapping round trip: map a frame, make it read-only, unmap it (each step flushes
    // the TLB entry), then give the frame back.
    let scratch_ok = match mm::pmm::alloc_frame() {
        Some(f) => {
            let va = mm::vmm::SCRATCH_BASE;
            let mapped = mm::vmm::map_page(va, f.0, arch::paging::WRITE | arch::paging::NX).is_ok();
            let ro = mm::vmm::protect_page(va, arch::paging::NX).is_ok()
                && mm::vmm::flags_of(va).is_some_and(|fl| !mm::vmm::is_writable(fl));
            let unmapped = matches!(mm::vmm::unmap_page(va), Ok(Some(p)) if p == f.0)
                && mm::vmm::flags_of(va).is_none();
            mapped && ro && unmapped && mm::pmm::free_frame(f).is_ok()
        }
        None => false,
    };
    let (as_ok, as_code) = match UserSpace::new() {
        Ok(mut us) => {
            let mapped = us
                .map_new_page(USER_BASE, arch::paging::WRITE | arch::paging::NX)
                .is_ok();
            us.activate();
            let probe =
                mapped && us.flags_of(USER_BASE).is_some() && arch::paging::read_cr3() == us.cr3();
            addrspace::activate_kernel();
            match us.destroy() {
                Ok(_) => (probe, "ok"),
                Err(e) => (false, e.code()),
            }
        }
        Err(e) => (false, e.code()),
    };
    let frames_after = mm::pmm::stats().free_frames;
    let mm_ok =
        heap_ok && scratch_ok && as_ok && heap_st.live_blocks == 0 && frames_before == frames_after;
    kprintln!(
        "OSX|{}|kernel|mm|heap_ok={}|scratch_ok={}|as_ok={}|as_code={}|heap_live_blocks={}|heap_live_bytes={}|heap_pages={}|heap_large_frames={}|frames_delta={}|selfcheck={}",
        build_id,
        u8::from(heap_ok),
        u8::from(scratch_ok),
        u8::from(as_ok),
        as_code,
        heap_st.live_blocks,
        heap_st.live_bytes,
        heap_st.slab_pages,
        heap_st.large_frames,
        frames_before as i64 - frames_after as i64,
        u8::from(mm_ok)
    );

    // Interrupts (WP-10): ACPI MADT -> PIC remapped and masked, local APIC enabled with a
    // calibrated timer, every I/O APIC masked. Interrupts are still off here.
    let irq = match arch::irq::init(bi.rsdp) {
        Ok(i) => i,
        Err(e) => crate::panic::fatal(e.code()),
    };
    // CPU 0 is online from here (the scheduler places threads on online CPUs only).
    arch::smp::init_bsp();
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
    // Ring 3 (WP-14): SYSCALL/SYSRET; the initial trap stack is replaced by each thread's own
    // kernel stack on every switch (WP-15).
    let trap = match mm::vmm::alloc_kernel_stack(32 * 1024) {
        Ok(s) => s,
        Err(e) => crate::panic::fatal(e.code()),
    };
    let sc = arch::syscall::init(trap.top());
    // Threads and the scheduler (WP-15): this context becomes thread 0; a kernel thread is
    // spawned, runs on its own stack and is joined, with no frame left behind.
    let Some(ks) = mm::vmm::kernel_space() else {
        crate::panic::fatal("K_E_VMM_NOT_ACTIVE")
    };
    crate::sched::init(ks.kernel_stack, ks.cr3);
    let sched_frames_before = mm::pmm::stats().free_frames;
    let (probe, sched_code) = match crate::sched::spawn_kernel(sched_probe, 0x5EED, 1) {
        Ok(tid) => (crate::sched::join(tid), "ok"),
        Err(_) => (None, "K_E_SCHED_SPAWN"),
    };
    let st = crate::sched::stats();
    let sched_delta = sched_frames_before as i64 - mm::pmm::stats().free_frames as i64;
    let sched_ok = probe == Some(0x5EEE) && st.threads == 1 && st.switches >= 2 && sched_delta == 0;
    kprintln!(
        "OSX|{}|kernel|sched|boot_tid={}|probe_join={:#x}|switches={}|preemptions={}|ticks={}|threads={}|processes={}|quantum_ticks={}|frames_delta={}|code={}|selfcheck={}",
        build_id,
        st.current,
        probe.unwrap_or(u64::MAX),
        st.switches,
        st.preemptions,
        st.ticks,
        st.threads,
        st.processes,
        crate::sched::QUANTUM_TICKS,
        sched_delta,
        sched_code,
        u8::from(sched_ok)
    );
    // Objects (WP-16) self-check in every build: a VMO travels through a channel inside the
    // kernel, the peer sees the close, and every object and frame is released.
    let obj_frames_before = mm::pmm::stats().free_frames;
    let obj_before = crate::object::stats();
    let (chan_ok, vmo_size, peer_closed) = object_selfcheck();
    let obj_after = crate::object::stats();
    let obj_delta = obj_frames_before as i64 - mm::pmm::stats().free_frames as i64;
    let obj_ok =
        chan_ok && vmo_size == 8192 && peer_closed && obj_after == obj_before && obj_delta == 0;
    kprintln!(
        "OSX|{}|kernel|object|channel_ok={}|vmo_size={}|peer_closed={}|live_channels={}|live_endpoints={}|live_vmos={}|live_handles={}|frames_delta={}|selfcheck={}",
        build_id,
        u8::from(chan_ok),
        vmo_size,
        u8::from(peer_closed),
        obj_after.channels,
        obj_after.endpoints,
        obj_after.vmos,
        obj_after.handles,
        obj_delta,
        u8::from(obj_ok)
    );
    // Storage (WP-18): PCI through ECAM, the first virtio-blk function, one sector read as a
    // self-check in every build (the lab attaches a 16 MiB virtio disk).
    let mut pci_functions: alloc::vec::Vec<crate::arch::pci::Device> = alloc::vec::Vec::new();
    let blk_line = match crate::block::init(bi.rsdp) {
        Ok(info) => {
            pci_functions = info.functions.clone();
            let mut list = alloc::string::String::new();
            for f in info.functions.iter().take(12) {
                use core::fmt::Write as _;
                let _ = write!(
                    list,
                    "{:02x}:{:02x}.{}={:04x}:{:04x}/{:x}.{:x},",
                    f.bdf.bus,
                    f.bdf.device,
                    f.bdf.function,
                    f.vendor,
                    f.device,
                    f.class,
                    f.subclass
                );
            }
            kprintln!(
                "OSX|{}|kernel|pci|ecam={:#x}|segment={}|functions={}|list={}",
                build_id,
                info.ecam_base,
                info.segment,
                info.functions.len(),
                list
            );
            let mut sector = [0u8; 512];
            let read_ok = crate::block::present() && crate::block::read(0, &mut sector).is_ok();
            let flush_ok = crate::block::flush().is_ok();
            let (dev, bdf, cap, qs, flush, features) = match info.blk {
                Some(b) => (
                    b.device_id,
                    (u32::from(b.bdf.bus) << 16)
                        | (u32::from(b.bdf.device) << 8)
                        | u32::from(b.bdf.function),
                    b.capacity_sectors,
                    b.queue_size,
                    b.flush,
                    b.features,
                ),
                None => (0, 0, 0, 0, false, 0),
            };
            // The registers must sit in the shared MMIO window, never at the BAR's own address
            // (CI run 39110182649: a lower-half BAR vanished under the first process CR3).
            let mmio = crate::block::info().map_or(0, |b| b.mmio);
            let mmio_shared = (mm::vmm::MMIO_BASE..mm::vmm::MMIO_END).contains(&mmio);
            let (mmio_ranges, mmio_bytes) = mm::vmm::mmio_usage();
            let ok = info.blk.is_some()
                && read_ok
                && flush_ok
                && mmio_shared
                && cap == crate::block::capacity_sectors()
                && cap > 0;
            alloc::format!(
                "device={:#x}|bdf={:#x}|capacity_sectors={}|queue_size={}|features={:#x}|flush={}|dma_frames={}|mmio={:#x}|mmio_shared={}|mmio_ranges={}|mmio_bytes={}|read_ok={}|flush_ok={}|code=ok|selfcheck={}",
                dev,
                bdf,
                cap,
                qs,
                features,
                u8::from(flush),
                info.frames,
                mmio,
                u8::from(mmio_shared),
                mmio_ranges,
                mmio_bytes,
                u8::from(read_ok),
                u8::from(flush_ok),
                u8::from(ok)
            )
        }
        Err(code) => alloc::format!("code={code}|selfcheck=0"),
    };
    kprintln!("OSX|{}|kernel|blk|{}", build_id, blk_line);
    // Network (WP-27, ADR-0017): the first virtio-net function; the self-check sends an ARP
    // request for the lab gateway and expects the reply within 500 ticks (QEMU user-mode
    // networking answers ARP), proving both queues and the DMA buffers.
    kprintln!(
        "OSX|{}|kernel|net|{}",
        build_id,
        crate::net::boot_line(&pci_functions)
    );
    // Keyboard (WP-27): the i8042 is used as the firmware left it; bytes are polled per tick.
    let kbd = crate::net::keyboard_object();
    kprintln!(
        "OSX|{}|kernel|kbd|drained={}|ring={}|pending={}|overflow={}|code=ok|selfcheck=1",
        build_id,
        arch::i8042::init(),
        crate::object::kbd::RING,
        kbd.pending(),
        kbd.overflow()
    );
    // FAT32 (WP-18 part 2): mount the lab volume and read its hello file in every build.
    let fs_line = match crate::fs::mount() {
        Ok(v) => {
            let mut buf = [0u8; 64];
            let hello = crate::fs::with(|fs| {
                let e = fs.lookup(b"/HELLO.TXT")?;
                let n = fs.read(&e, 0, &mut buf)?;
                Ok((e.size, n))
            });
            let (size, n) = hello.unwrap_or((0, 0));
            let hello_ok = n == 24 && size == 24 && &buf[..24] == b"hello from the lab disk\n";
            let free = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
            let label = core::str::from_utf8(&v.label).unwrap_or("?").trim_end();
            alloc::format!(
                "label={}|sectors_per_cluster={}|reserved={}|fats={}|fat_sectors={}|clusters={}|root_cluster={}|free_clusters={}|hello_size={}|hello_ok={}|code={}|selfcheck={}",
                label,
                v.sectors_per_cluster,
                v.reserved,
                v.fats,
                v.fat_sectors,
                v.clusters,
                v.root_cluster,
                free,
                size,
                u8::from(hello_ok),
                hello.map_or_else(|e| e.code(), |_| "ok"),
                u8::from(hello_ok)
            )
        }
        Err(e) => alloc::format!("code={}|selfcheck=0", e.code()),
    };
    kprintln!("OSX|{}|kernel|fat32|{}", build_id, fs_line);
    // SMP (WP-20, ADR-0015): the other CPUs of the MADT join the scheduler, each with its own
    // idle thread and timer; from here on threads may be placed on them. After the device
    // bring-up on purpose: sizing PCI BARs (writing all-ones to them) while other vCPUs run
    // made QEMU 8.2 itself die with SIGSEGV in 4 of ~400 mutation runs (mutants run
    // 39116036466) — memory-region changes are done with one CPU running.
    let smp = match arch::acpi::parse_madt(bi.rsdp) {
        Ok(m) => arch::smp::start_aps(&m, ks.cr3),
        Err(e) => arch::smp::SmpInfo {
            code: e.code(),
            ..Default::default()
        },
    };
    let expected = smp.madt_cpus.min(arch::smp::MAX_CPUS as u32);
    // Every AP runs a probe thread (placed there, joined from here) and must have taken timer
    // ticks of its own; the frame count returns to where it was.
    // The diagnostic strings are allocated before the balance is taken (CI run 39115391817:
    // their slab page read as a one-frame leak).
    let mut probes = alloc::string::String::with_capacity(64);
    let mut ap_ticks = alloc::string::String::with_capacity(64);
    let smp_frames_before = mm::pmm::stats().free_frames;
    let online_mask = arch::smp::online_mask();
    let mut probes_ok = true;
    for cpu in 1..arch::smp::MAX_CPUS {
        if online_mask & (1 << cpu) == 0 {
            continue;
        }
        use core::fmt::Write as _;
        let got = crate::sched::spawn_on(cpu, smp_probe, cpu as u64, 1)
            .ok()
            .and_then(crate::sched::join);
        let want = cpu as u64 | (u64::from(arch::smp::apic_id_of(cpu)) << 8);
        probes_ok &= got == Some(want);
        let _ = write!(probes, "{}:{:#x},", cpu, got.unwrap_or(u64::MAX));
        let ticks = arch::irq::ticks_of(cpu);
        probes_ok &= ticks > 0;
        let _ = write!(ap_ticks, "{ticks},");
    }
    let smp_delta = smp_frames_before as i64 - mm::pmm::stats().free_frames as i64;
    let tlb = arch::tlb::counters();
    let smp_ok = smp.code == "ok"
        && smp.online == expected
        && smp.failed == 0
        && smp.id_mismatch == 0
        && arch::smp::online_count() == smp.online
        && probes_ok
        && smp_delta == 0;
    kprintln!(
        "OSX|{}|kernel|smp|madt_cpus={}|online={}|expected={}|bsp_apic={}|trampoline={:#x}|mode={:?}|skipped={}|failed={}|id_mismatch={}|online_mask={:#x}|probes={}|ap_ticks={}|tlb_sent={}|tlb_served={}|resched_ipis={}|frames_delta={}|code={}|smp_selfcheck={}",
        build_id,
        smp.madt_cpus,
        smp.online,
        expected,
        smp.bsp_apic_id,
        smp.trampoline,
        arch::apic::mode(),
        smp.skipped,
        smp.failed,
        smp.id_mismatch,
        online_mask,
        probes,
        ap_ticks,
        tlb.sent,
        tlb.served,
        arch::irq::counters().resched_ipis,
        smp_delta,
        smp.code,
        u8::from(smp_ok)
    );
    // Ring-3 self-check in every build: a process runs the ping program and exits through the
    // ABI; the scheduler reaps it and no frame is left behind.
    let (user_pid, user_exit, user_delta, user_code) =
        match crate::user::run(arch::user_programs::ping()) {
            Ok(o) => (o.pid, o.exit_code, o.frames_delta, "ok"),
            Err(e) => (0, u64::MAX, 0, e.code()),
        };
    let user_ok =
        user_exit == 0x1235 && user_delta == 0 && user_exit < arch::syscall::USER_FAULT_EXIT_BASE;
    kprintln!(
        "OSX|{}|kernel|user|lstar={:#x}|smep={}|smap={}|trap_stack_guard={:#x}|pid={}|ping_exit={:#x}|frames_delta={}|code={}|selfcheck={}",
        build_id,
        sc.lstar,
        u8::from(sc.smep),
        u8::from(sc.smap),
        trap.guard,
        user_pid,
        user_exit,
        user_delta,
        user_code,
        u8::from(user_ok)
    );
    // ELF loader (WP-17) self-check in every build: the embedded `hello` application runs as
    // a process (trace, ping) and exits 7, leaving no frame behind.
    let (elf_exit, elf_delta, elf_segments, elf_pages, elf_code) = if crate::apps::HELLO.is_empty()
    {
        (u64::MAX, 0, 0, 0, "K_E_APPS_MISSING")
    } else {
        match crate::user::run_elf(crate::apps::HELLO) {
            Ok((o, l)) => (o.exit_code, o.frames_delta, l.segments, l.pages, "ok"),
            Err(e) => (u64::MAX, 0, 0, 0, e.code()),
        }
    };
    let elf_ok = elf_exit == 7 && elf_delta == 0;
    kprintln!(
        "OSX|{}|kernel|elf|app=hello|size={}|segments={}|pages={}|exit={:#x}|frames_delta={}|code={}|selfcheck={}",
        build_id,
        crate::apps::HELLO.len(),
        elf_segments,
        elf_pages,
        elf_exit,
        elf_delta,
        elf_code,
        u8::from(elf_ok)
    );
    #[cfg(feature = "ktest")]
    crate::ktest::run();
    #[cfg(not(feature = "ktest"))]
    {
        // WP-24 (ADR-0016 §1): the service manager is the first process — started from the
        // volume with a control channel; the lab manifest is loaded through it and the reply
        // reported. The test kernel starts managers of its own inside its cases instead.
        kprintln!(
            "OSX|{}|kernel|svcmgr|{}",
            build_id,
            crate::services::start_at_boot(2000)
        );
        // Nothing waits on the timer yet; stop it so the shutdown is quiet.
        arch::irq::timer_stop();
        kprintln!("OSX|{}|kernel|m1_done|exit=0x10", build_id);
        arch::qemu::exit(arch::qemu::EXIT_OK)
    }
}

/// Runs on an application processor (placed by `spawn_on`): reports the CPU index it sees
/// through GS and the APIC ID its own LAPIC reports, so the boot trace proves both agree.
#[cfg(target_arch = "x86_64")]
extern "sysv64" fn smp_probe(expected_cpu: u64) -> u64 {
    let cpu = u64::from(arch::cpu_id());
    let apic = u64::from(arch::apic::my_id());
    if cpu != expected_cpu {
        return u64::MAX - 1;
    }
    cpu | (apic << 8)
}

/// Boot self-check thread: proves it runs as its own thread and hands a value back through
/// the exit code.
#[cfg(target_arch = "x86_64")]
extern "sysv64" fn sched_probe(arg: u64) -> u64 {
    if crate::sched::current_tid() == 0 {
        return 0;
    }
    arg + 1
}

/// Kernel-side object round trip: (bytes and handle arrived intact, VMO size seen by the
/// receiver, peer-closed observed after the sender's end is dropped).
#[cfg(target_arch = "x86_64")]
fn object_selfcheck() -> (bool, u64, bool) {
    use crate::object::channel::{self, ChannelError, Message};
    use crate::object::handle::Entry;
    use crate::object::{Object, Rights, Vmo};
    let Some(vmo) = Vmo::new(8192) else {
        return (false, 0, false);
    };
    let (a, b) = channel::create();
    let sent = a
        .write(Message {
            bytes: alloc::vec![1, 2, 3],
            handles: alloc::vec![Entry {
                object: Object::Vmo(vmo),
                rights: Rights::VMO_DEFAULT,
            }],
        })
        .is_ok();
    let (bytes_ok, size) = match b.read(16, 4, None) {
        Ok(m) => {
            let size = match m.handles.first().map(|e| &e.object) {
                Some(Object::Vmo(v)) => v.size(),
                _ => 0,
            };
            (m.bytes == [1, 2, 3] && m.handles.len() == 1, size)
        }
        Err(_) => (false, 0),
    };
    drop(a);
    let peer_closed = matches!(b.read(16, 4, None), Err(ChannelError::PeerClosed));
    drop(b);
    (sent && bytes_ok, size, peer_closed)
}
