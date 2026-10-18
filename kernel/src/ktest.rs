//! In-kernel tests (test kernel only, feature `ktest`). Origin of the design: Sol OS ADR-010.
//!
//! The host runner passes the test name through QEMU fw_cfg (`opt/nawah/test`) and runs each test
//! in its own QEMU boot, because most tests end in a fatal exception. The result reaches the host
//! as the QEMU exit code plus serial markers (`platform/pc-qemu/target.json`, suite M2).
//! A missing or unknown name is an explicit failure, so a lost name cannot pass by accident.

use crate::arch::{apic, fwcfg, interrupts, irq, ktest as inject, paging, pit, qemu};
use crate::mm::pmm::{self, Frame, PmmError};
use crate::mm::vmm;
use crate::sync::IrqSpinLock;
use crate::BUILD_ID;

static TEST_LOCK: IrqSpinLock<u64> = IrqSpinLock::new("ktest_lock", 0);

fn fail(what: &str) -> ! {
    kprintln!("OSX|{}|ktest|fail|{}", BUILD_ID, what);
    qemu::exit(qemu::EXIT_TEST_FAILED)
}

fn pass(what: &str) -> ! {
    kprintln!("OSX|{}|ktest|pass|{}", BUILD_ID, what);
    qemu::exit(qemu::EXIT_OK)
}

fn expect_rip(which: &str) {
    kprintln!(
        "OSX|{}|ktest|expect_rip={:#x}",
        BUILD_ID,
        inject::expected_rip(which)
    );
}

/// Runs the test named by fw_cfg, then ends the emulation.
pub fn run() -> ! {
    let mut buf = [0u8; 64];
    let name = match fwcfg::read_file("opt/nawah/test", &mut buf) {
        Some(n) => core::str::from_utf8(&buf[..n]).unwrap_or(""),
        None => "",
    };
    if name.is_empty() {
        kprintln!("OSX|{}|ktest|missing_test_name", BUILD_ID);
        qemu::exit(qemu::EXIT_UNKNOWN_TEST)
    }
    kprintln!("OSX|{}|ktest|start|name={}", BUILD_ID, name);

    match name {
        "exc_de" => {
            expect_rip("de");
            inject::divide_error();
            fail("returned from #DE")
        }
        "exc_ud" => {
            expect_rip("ud");
            inject::invalid_opcode();
            fail("returned from #UD")
        }
        "exc_db" => {
            expect_rip("db");
            inject::debug_exception();
            fail("returned from #DB")
        }
        "exc_gp" => {
            expect_rip("gp");
            inject::general_protection();
            fail("returned from #GP")
        }
        "exc_pf" => {
            expect_rip("pf");
            inject::page_fault();
            fail("returned from #PF")
        }
        "exc_bp" => {
            expect_rip("bp");
            inject::breakpoint();
            pass("resumed after #BP")
        }
        "exc_bp_state" => {
            if inject::breakpoint_preserves_state() {
                pass("registers and flags preserved across #BP")
            } else {
                fail("state not preserved across #BP")
            }
        }
        "exc_df" => inject::double_fault(),
        "exc_nested" => {
            inject::nested_fault();
            fail("returned from nested fault")
        }
        "exc_triple" => inject::triple_fault(),
        "pmm_counts" => pmm_counts(),
        "pmm_exhaust" => pmm_exhaust(),
        "pmm_double_free" => pmm_double_free(),
        "vmm_switch" => vmm_switch(),
        "timer_ticks" => timer_ticks(),
        "irq_eoi" => irq_eoi(),
        "spurious" => spurious(),
        "lock_irqsave" => lock_irqsave(),
        "lock_reentry" => {
            let _held = TEST_LOCK.lock();
            kprintln!("OSX|{}|ktest|lock_reentry|held=1|reacquiring=1", BUILD_ID);
            let _again = TEST_LOCK.lock(); // must panic with K_E_LOCK_REENTRY
            fail("re-entrant lock acquisition did not panic")
        }
        "panic_code" => {
            kprintln!("OSX|{}|ktest|panic_code|about_to_panic=1", BUILD_ID);
            panic!("K_T_PANIC deliberate test panic");
        }
        "vmm_wp" => {
            // Writing to .text: the target is the store instruction itself, so RIP, CR2 and the
            // expected address are all the same value.
            let target = inject::expected_rip("write");
            kprintln!("OSX|{}|ktest|vmm_wp|target={:#x}", BUILD_ID, target);
            expect_rip("write");
            inject::write_fault(target);
            fail("write to .text did not fault")
        }
        "vmm_nx" => {
            let target = inject::data_code_address();
            kprintln!(
                "OSX|{}|ktest|vmm_nx|target={:#x}|expect_rip={:#x}",
                BUILD_ID,
                target,
                target
            );
            inject::execute_from_data();
            fail("execution from .data did not fault")
        }
        "vmm_guard" => {
            let Some(ks) = vmm::kernel_space() else {
                fail("kernel space not active")
            };
            // The first push below the mapped stack lands 8 bytes under its base, inside the
            // guard page; the CPU then fails to push the #PF frame there and raises #DF.
            kprintln!(
                "OSX|{}|ktest|vmm_guard|stack_base={:#x}|guard={:#x}|expect_cr2={:#x}",
                BUILD_ID,
                ks.kernel_stack.base,
                ks.kernel_stack.guard,
                ks.kernel_stack.base - 8
            );
            inject::stack_overflow()
        }
        "idt_layout" => {
            let mismatches = inject::idt_layout_mismatches();
            if mismatches == 0 {
                pass("idt layout matches SDM table 7-1")
            } else {
                fail("idt layout mismatches")
            }
        }
        _ => {
            kprintln!("OSX|{}|ktest|unknown_test|name={}", BUILD_ID, name);
            qemu::exit(qemu::EXIT_UNKNOWN_TEST)
        }
    }
}

/// irqsave lock: IF is cleared while held and restored to its previous value (both from the
/// enabled and the disabled state); a real interrupt source (the timer) is held off while the
/// lock is held and resumes afterwards; try_lock fails while held; the data is reachable.
fn lock_irqsave() -> ! {
    interrupts::enable();
    let (if_inside, if_after, if_inside_disabled, if_after_disabled);
    {
        let mut g = TEST_LOCK.lock();
        if_inside = interrupts::enabled();
        *g += 1;
    }
    if_after = interrupts::enabled();
    interrupts::disable();
    {
        let mut g = TEST_LOCK.lock();
        if_inside_disabled = interrupts::enabled();
        *g += 1;
    }
    if_after_disabled = interrupts::enabled();
    interrupts::enable();
    // Timer held off while the lock is held, resumes after release. The baseline is read inside
    // the critical section: a tick between reading it and the lock's cli would not be "held".
    let (ticks_while_held, try_while_held) = {
        let g = TEST_LOCK.lock();
        let t0 = irq::counters().ticks;
        pit::wait_ms(20);
        let t = irq::counters().ticks - t0;
        let tried = TEST_LOCK.try_lock().is_some();
        drop(g);
        (t, tried)
    };
    let t1 = irq::counters().ticks;
    pit::wait_ms(20);
    let ticks_after = irq::counters().ticks - t1;
    let try_when_free = TEST_LOCK.try_lock().is_some();
    interrupts::disable();
    let value = *TEST_LOCK.lock();
    kprintln!(
        "OSX|{}|ktest|lock_irqsave|if_inside={}|if_after={}|if_inside_disabled={}|if_after_disabled={}|ticks_while_held={}|ticks_after={}|try_while_held={}|try_when_free={}|value={}",
        BUILD_ID,
        u8::from(if_inside),
        u8::from(if_after),
        u8::from(if_inside_disabled),
        u8::from(if_after_disabled),
        ticks_while_held,
        ticks_after,
        u8::from(try_while_held),
        u8::from(try_when_free),
        value
    );
    if if_inside || !if_after {
        fail("IF not cleared inside the lock or not restored after it")
    }
    if if_inside_disabled || if_after_disabled {
        fail("IF changed by a lock taken with interrupts disabled")
    }
    if ticks_while_held != 0 || ticks_after < 10 {
        fail("timer not held off while locked, or did not resume")
    }
    if try_while_held || !try_when_free {
        fail("try_lock semantics wrong")
    }
    if value != 2 {
        fail("protected data not updated")
    }
    pass("irqsave lock clears and restores IF, holds off interrupts, try_lock consistent")
}

/// Periodic timer: two consecutive PIT-measured 50 ms windows each deliver 25..=100 ticks, the
/// count is monotonic across them, no unexpected vector arrives, and no handler re-enters.
fn timer_ticks() -> ! {
    let c0 = irq::counters();
    interrupts::enable();
    let ok1 = pit::wait_ms(50);
    let c1 = irq::counters();
    let ok2 = pit::wait_ms(50);
    interrupts::disable();
    let c2 = irq::counters();
    let w1 = c1.ticks - c0.ticks;
    let w2 = c2.ticks - c1.ticks;
    kprintln!(
        "OSX|{}|ktest|timer_ticks|window1={}|window2={}|unexpected={}|max_depth={}|if={}",
        BUILD_ID,
        w1,
        w2,
        c2.unexpected,
        c2.max_depth,
        u8::from(interrupts::enabled())
    );
    if !ok1 || !ok2 {
        fail("PIT reference missing")
    }
    if !(25..=100).contains(&w1) || !(25..=100).contains(&w2) {
        fail("tick count outside 25..=100 per 50 ms")
    }
    if c2.ticks < c1.ticks || c1.ticks < c0.ticks {
        fail("tick count not monotonic")
    }
    if c2.unexpected != 0 || c2.max_depth != 1 {
        fail("unexpected vector or handler re-entry")
    }
    if interrupts::enabled() {
        fail("IF still set after disable")
    }
    pass("periodic timer ticks, monotonic, no re-entry")
}

/// Spins until `pred` holds or the PIT says `ms` elapsed; returns whether it held.
fn wait_until(ms: u64, pred: impl Fn() -> bool) -> bool {
    // Coarse: check between 1 ms PIT waits so the bound is real time, not iterations.
    let mut elapsed = 0;
    while elapsed < ms {
        if pred() {
            return true;
        }
        pit::wait_ms(1);
        elapsed += 1;
    }
    pred()
}

/// EOI: a self-IPI is delivered and handled; after its EOI a second one on the same vector is
/// delivered too (without EOI the ISR bit would block it); handlers never nest.
fn irq_eoi() -> ! {
    irq::timer_stop();
    let before = irq::counters();
    interrupts::enable();
    apic::send_self_ipi(irq::TEST_IPI_VECTOR);
    let first = wait_until(20, || irq::counters().test_ipis == before.test_ipis + 1);
    apic::send_self_ipi(irq::TEST_IPI_VECTOR);
    let second = wait_until(20, || irq::counters().test_ipis == before.test_ipis + 2);
    interrupts::disable();
    let c = irq::counters();
    kprintln!(
        "OSX|{}|ktest|irq_eoi|first={}|second={}|test_ipis={}|unexpected={}|max_depth={}",
        BUILD_ID,
        u8::from(first),
        u8::from(second),
        c.test_ipis,
        c.unexpected,
        c.max_depth
    );
    if !first {
        fail("first self-IPI not delivered")
    }
    if !second {
        fail("second self-IPI not delivered after EOI")
    }
    if c.unexpected != 0 || c.max_depth != 1 {
        fail("unexpected vector or handler re-entry")
    }
    pass("EOI acknowledged, next interrupt delivered, no re-entry")
}

/// Spurious and masked vectors: software interrupts on the spurious vector (no EOI), a masked
/// PIC vector and an unassigned vector are counted and return; with the timer stopped and
/// interrupts enabled for 20 ms nothing else arrives.
fn spurious() -> ! {
    // timer_stop also delivers a tick the APIC accepted while IF was clear (it stays pending
    // after the LVT is masked), so the silent window below measures only new arrivals.
    irq::timer_stop();
    let before = irq::counters();
    inject::software_interrupt::<{ irq::SPURIOUS_VECTOR }>();
    inject::software_interrupt::<0x20>();
    inject::software_interrupt::<0xF0>();
    let mid = irq::counters();
    interrupts::enable();
    let ok = pit::wait_ms(20);
    interrupts::disable();
    let after = irq::counters();
    kprintln!(
        "OSX|{}|ktest|spurious|spurious={}|unexpected={}|last_unexpected={:#x}|total_after_window={}|svr={:#x}",
        BUILD_ID,
        mid.spurious - before.spurious,
        mid.unexpected - before.unexpected,
        mid.last_unexpected_vector,
        after.total - mid.total,
        apic::svr()
    );
    if mid.spurious - before.spurious != 1 {
        fail("spurious vector not counted exactly once")
    }
    if mid.unexpected - before.unexpected != 2 || mid.last_unexpected_vector != 0xF0 {
        fail("masked/unassigned vectors not counted as unexpected")
    }
    if !ok || after.total != mid.total {
        fail("interrupts arrived while everything was masked")
    }
    if apic::svr() & 0x1FF != 0x1FF {
        fail("spurious vector register not 0x1FF")
    }
    pass("spurious and masked vectors are counted, never fault")
}

/// Positive checks of the active kernel address space: CR3 is ours, WP/NXE are on, section
/// permissions took effect, the direct map works, guard pages and the null page are unmapped,
/// boot-services memory was reclaimed and the allocator still works afterwards.
fn vmm_switch() -> ! {
    let Some(ks) = vmm::kernel_space() else {
        fail("kernel space not active")
    };
    if paging::read_cr3() != ks.cr3 {
        fail("CR3 is not the kernel PML4")
    }
    if !ks.wp || !ks.nxe {
        fail("CR0.WP or EFER.NXE not set")
    }
    if !ks.text_rx
        || !ks.data_rw_nx
        || ks.sections_rx == 0
        || ks.sections_ro == 0
        || ks.sections_rw == 0
    {
        fail("section permissions not applied")
    }
    if !ks.direct_ok {
        fail("direct map does not alias physical memory")
    }
    let header = match vmm::flags_of(ks.image_base) {
        Some(f) => !vmm::is_writable(f) && vmm::is_nx(f),
        None => false,
    };
    if !header {
        fail("image headers not mapped read-only")
    }
    if vmm::flags_of(0).is_some() {
        fail("null page is mapped")
    }
    if vmm::flags_of(ks.kernel_stack.guard).is_some() || vmm::flags_of(ks.df_stack.guard).is_some()
    {
        fail("a stack guard page is mapped")
    }
    if vmm::flags_of(ks.kernel_stack.base).is_none()
        || vmm::flags_of(ks.df_stack.top() - 8).is_none()
    {
        fail("a stack is not mapped")
    }
    if ks.reclaimed_frames == 0 {
        fail("no boot-services memory reclaimed")
    }
    let alloc_ok = match pmm::alloc_frame() {
        Some(f) => pmm::probe_rw(f) && pmm::free_frame(f).is_ok(),
        None => false,
    };
    if !alloc_ok {
        fail("allocator broken after reclaim")
    }
    kprintln!(
        "OSX|{}|ktest|vmm_switch|cr3={:#x}|ram_mib={}|reclaimed_frames={}|free_frames={}",
        BUILD_ID,
        ks.cr3,
        ks.ram_bytes_mapped >> 20,
        ks.reclaimed_frames,
        pmm::stats().free_frames
    );
    pass("kernel address space active with WP, NXE, section permissions, direct map, guards")
}

const PMM_N: usize = 1024;

/// Allocates 1024 frames: all distinct, 4 KiB aligned, at/above 1 MiB, writable; counters move by
/// exactly N and return to the initial values after freeing.
fn pmm_counts() -> ! {
    let before = pmm::stats();
    let mut frames = [Frame(0); PMM_N];
    for (i, slot) in frames.iter_mut().enumerate() {
        match pmm::alloc_frame() {
            Some(f) => *slot = f,
            None => {
                kprintln!("OSX|{}|ktest|pmm_counts|exhausted_at={}", BUILD_ID, i);
                fail("allocator exhausted before 1024 frames")
            }
        }
    }
    for (i, f) in frames.iter().enumerate() {
        if f.0 % 4096 != 0 || f.0 < (1 << 20) {
            fail("frame misaligned or below 1 MiB")
        }
        if frames[..i].contains(f) {
            fail("frame handed out twice")
        }
        if !pmm::probe_rw(*f) {
            fail("frame not writable/readable")
        }
    }
    let mid = pmm::stats();
    if mid.free_frames != before.free_frames - PMM_N as u64
        || mid.allocated_frames != before.allocated_frames + PMM_N as u64
    {
        fail("counters did not move by N after alloc")
    }
    for f in frames.iter() {
        if pmm::free_frame(*f).is_err() {
            fail("free of an allocated frame failed")
        }
    }
    let after = pmm::stats();
    if after.free_frames != before.free_frames || after.allocated_frames != before.allocated_frames
    {
        fail("counters did not return after free")
    }
    kprintln!(
        "OSX|{}|ktest|pmm_counts|managed={}|free={}",
        BUILD_ID,
        before.managed_frames,
        before.free_frames
    );
    pass("pmm counters consistent across 1024 alloc/free")
}

/// Stress, limit and recovery: allocates until None (the count equals the free count, further
/// allocations keep returning None, no panic), then gives every frame back through an intrusive
/// list stored in the frames themselves, and checks the allocator is whole again (counters back
/// to the start, a new allocation succeeds).
fn pmm_exhaust() -> ! {
    let before = pmm::stats();
    let mut count: u64 = 0;
    let mut head: u64 = 0; // 0 = end of list (frame 0 is never handed out)
    while let Some(f) = pmm::alloc_frame() {
        pmm::link_frame(f, head);
        head = f.0;
        count += 1;
    }
    let after = pmm::stats();
    if count != before.free_frames || after.free_frames != 0 || pmm::alloc_frame().is_some() {
        kprintln!(
            "OSX|{}|ktest|pmm_exhaust|count={}|free_before={}|free_after={}",
            BUILD_ID,
            count,
            before.free_frames,
            after.free_frames
        );
        fail("exhaustion accounting wrong")
    }
    let mut freed: u64 = 0;
    while head != 0 {
        let f = Frame(head);
        head = pmm::read_link(f);
        if pmm::free_frame(f).is_err() {
            fail("free of an exhausted-run frame failed")
        }
        freed += 1;
    }
    let recovered = pmm::stats();
    let again = pmm::alloc_frame();
    if let Some(f) = again {
        let _ = pmm::free_frame(f);
    }
    kprintln!(
        "OSX|{}|ktest|pmm_exhaust|count={}|freed={}|free_recovered={}|alloc_again={}",
        BUILD_ID,
        count,
        freed,
        recovered.free_frames,
        u8::from(again.is_some())
    );
    if freed != count || recovered.free_frames != before.free_frames || again.is_none() {
        fail("allocator did not recover after exhaustion")
    }
    pass("exhaustion returns None without panic and the allocator recovers fully")
}

/// Double free, unmanaged, misaligned and bitmap-storage frees are all rejected.
fn pmm_double_free() -> ! {
    let f = match pmm::alloc_frame() {
        Some(f) => f,
        None => fail("no frame"),
    };
    if pmm::free_frame(f) != Ok(()) {
        fail("first free failed")
    }
    if pmm::free_frame(f) != Err(PmmError::NotAllocated) {
        fail("double free not detected")
    }
    if pmm::free_frame(Frame(0x1000)) != Err(PmmError::Unmanaged) {
        fail("free below 1 MiB accepted")
    }
    if pmm::free_frame(Frame(f.0 + 1)) != Err(PmmError::Unmanaged) {
        fail("misaligned free accepted")
    }
    if pmm::free_frame(pmm::bitmap_frame()) != Err(PmmError::Unmanaged) {
        fail("bitmap storage free accepted")
    }
    pass("double/unmanaged/misaligned/bitmap frees rejected")
}
