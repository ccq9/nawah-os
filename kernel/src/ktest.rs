//! In-kernel tests (test kernel only, feature `ktest`). Origin of the design: Sol OS ADR-010.
//!
//! The host runner passes the test name through QEMU fw_cfg (`opt/nawah/test`) and runs each test
//! in its own QEMU boot, because most tests end in a fatal exception. The result reaches the host
//! as the QEMU exit code plus serial markers (`platform/pc-qemu/target.json`, suite M2).
//! A missing or unknown name is an explicit failure, so a lost name cannot pass by accident.

use alloc::vec::Vec;

use crate::arch::{apic, fwcfg, interrupts, irq, ktest as inject, paging, pit, qemu};
use crate::mm::addrspace::{self, UserSpace, USER_BASE};
use crate::mm::heap;
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
        "heap_stress" => heap_stress(),
        "vmm_unmap" => vmm_unmap(),
        "vmm_protect" => vmm_protect(),
        "as_switch" => as_switch(),
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
            // Firmware-independent: OVMF may enter the kernel with CR0.WP already set, so first
            // clear WP and show that a supervisor write to the read-only PE header page goes
            // through (value restored), then re-enable WP with the kernel's own routine; the
            // write to .text below must then fault. The target is the store instruction itself,
            // so RIP, CR2 and the expected address are all the same value.
            let Some(ks) = vmm::kernel_space() else {
                fail("kernel space not active")
            };
            let header = ks.image_base + 8; // inside the read-only header page, past "MZ"
            paging::disable_wp();
            let saved = inject::read_qword(header);
            inject::write_qword(header, saved ^ 0x5A5A_5A5A_5A5A_5A5A);
            let wp_off_write_ok = inject::read_qword(header) != saved;
            inject::write_qword(header, saved);
            paging::enable_wp();
            let target = inject::expected_rip("write");
            kprintln!(
                "OSX|{}|ktest|vmm_wp|wp_off_write_ok={}|wp_now={}|target={:#x}",
                BUILD_ID,
                u8::from(wp_off_write_ok),
                u8::from(paging::wp_enabled()),
                target
            );
            if !wp_off_write_ok {
                fail("write with WP clear did not go through")
            }
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

/// Deterministic pseudo-random sequence for the stress tests (LCG, Numerical Recipes constants).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

/// Heap stress: 10,000 mixed allocations and frees (small, medium, large) with content checks;
/// afterwards no live block, no slab page, and the frame count back to the start.
fn heap_stress() -> ! {
    let frames_before = pmm::stats().free_frames;
    let mut slots: Vec<Option<Vec<u8>>> = (0..256).map(|_| None).collect();
    let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);
    let (mut allocs, mut frees, mut bytes) = (0u64, 0u64, 0u64);
    for _ in 0..10_000 {
        let i = (rng.next() % 256) as usize;
        if let Some(v) = slots[i].take() {
            let tag = (i as u8) ^ (v.len() as u8);
            if !v.iter().all(|&b| b == tag) {
                fail("heap block content corrupted")
            }
            frees += 1;
            drop(v);
        } else {
            let r = rng.next() % 100;
            let len = if r < 70 {
                1 + (rng.next() % 2048) as usize
            } else if r < 95 {
                2049 + (rng.next() % 14336) as usize
            } else {
                16385 + (rng.next() % 180_000) as usize
            };
            let tag = (i as u8) ^ (len as u8);
            slots[i] = Some(alloc::vec![tag; len]);
            allocs += 1;
            bytes += len as u64;
        }
    }
    let live_mid = heap::stats().live_blocks;
    for s in slots.iter_mut() {
        if let Some(v) = s.take() {
            frees += 1;
            drop(v);
        }
    }
    drop(slots);
    let st = heap::stats();
    let frames_after = pmm::stats().free_frames;
    kprintln!(
        "OSX|{}|ktest|heap_stress|allocs={}|frees={}|bytes={}|live_mid={}|live_after={}|slab_pages={}|large_frames={}|frames_before={}|frames_after={}",
        BUILD_ID,
        allocs,
        frees,
        bytes,
        live_mid,
        st.live_blocks,
        st.slab_pages,
        st.large_frames,
        frames_before,
        frames_after
    );
    if allocs != frees {
        fail("alloc/free count mismatch")
    }
    if st.live_blocks != 0 || st.slab_pages != 0 || st.large_frames != 0 {
        fail("heap not empty after freeing everything")
    }
    if frames_before != frames_after {
        fail("frames leaked through the heap")
    }
    pass("heap: 10k mixed allocations, contents intact, no leak")
}

const SCRATCH_PAGE: u64 = vmm::SCRATCH_BASE + 0x10_0000;

/// Maps a frame at the scratch page RW, writes through it, reads back through the direct map.
fn scratch_map_rw() -> Frame {
    let Some(f) = pmm::alloc_frame() else {
        fail("no frame")
    };
    if vmm::map_page(SCRATCH_PAGE, f.0, paging::WRITE | paging::NX).is_err() {
        fail("map_page failed")
    }
    inject::write_qword(SCRATCH_PAGE, 0xC0FF_EE00_0000_0001 ^ f.0);
    if inject::read_qword(vmm::direct(f.0)) != 0xC0FF_EE00_0000_0001 ^ f.0 {
        fail("write through scratch mapping not visible through the direct map")
    }
    f
}

/// After unmap (and invlpg) a write to the page faults: #PF error code 2, CR2 = the page.
fn vmm_unmap() -> ! {
    let f = scratch_map_rw();
    match vmm::unmap_page(SCRATCH_PAGE) {
        Ok(Some(p)) if p == f.0 => {}
        other => {
            kprintln!(
                "OSX|{}|ktest|vmm_unmap|unmap_result={:?}",
                BUILD_ID,
                other.is_ok()
            );
            fail("unmap did not return the mapped frame")
        }
    }
    if vmm::flags_of(SCRATCH_PAGE).is_some() {
        fail("page still mapped after unmap")
    }
    kprintln!(
        "OSX|{}|ktest|vmm_unmap|target={:#x}|unmapped=1",
        BUILD_ID,
        SCRATCH_PAGE
    );
    expect_rip("write");
    inject::write_fault(SCRATCH_PAGE);
    fail("write to an unmapped page did not fault (stale TLB entry?)")
}

/// After protect to read-only (and invlpg) a write faults: #PF error code 3, CR2 = the page.
fn vmm_protect() -> ! {
    let _f = scratch_map_rw();
    if vmm::protect_page(SCRATCH_PAGE, paging::NX).is_err() {
        fail("protect_page failed")
    }
    let ro = vmm::flags_of(SCRATCH_PAGE).is_some_and(|fl| !vmm::is_writable(fl));
    if !ro {
        fail("page not read-only after protect")
    }
    if inject::read_qword(SCRATCH_PAGE) == 0 {
        fail("read-only page lost its content")
    }
    kprintln!(
        "OSX|{}|ktest|vmm_protect|target={:#x}|readonly=1",
        BUILD_ID,
        SCRATCH_PAGE
    );
    expect_rip("write");
    inject::write_fault(SCRATCH_PAGE);
    fail("write to a read-only page did not fault (stale TLB entry?)")
}

/// User address space: pages mapped with USER, invisible from the kernel space, readable and
/// writable from the kernel while the space is active, destroyed without leaking a frame.
fn as_switch() -> ! {
    let frames_before = pmm::stats().free_frames;
    let Ok(mut us) = UserSpace::new() else {
        fail("UserSpace::new failed")
    };
    let addrs = [USER_BASE, USER_BASE + 0x1000, USER_BASE + 0x10_0000];
    let mut phys = [0u64; 3];
    for (i, &va) in addrs.iter().enumerate() {
        match us.map_new_page(va, paging::WRITE | paging::NX) {
            Ok(p) => phys[i] = p,
            Err(_) => fail("map_new_page failed"),
        }
    }
    if us.map_new_page(0x1000, paging::WRITE).is_ok()
        || us.map_new_page(vmm::SCRATCH_BASE, paging::WRITE).is_ok()
    {
        fail("mapping outside the user range was accepted")
    }
    if vmm::flags_of(USER_BASE).is_some() {
        fail("user page visible in the kernel space")
    }
    let user_flag = us
        .flags_of(USER_BASE)
        .is_some_and(|fl| fl & paging::USER != 0);
    inject::write_qword(vmm::direct(phys[0]), 0x1111_2222_3333_4444);
    us.activate();
    let seen = inject::read_qword(USER_BASE);
    inject::write_qword(USER_BASE + 0x1000, 0xAAAA_BBBB_CCCC_DDDD);
    let active_is_user = paging::read_cr3() == us.cr3();
    addrspace::activate_kernel();
    let back = inject::read_qword(vmm::direct(phys[1]));
    let destroy_ok = us.destroy().is_ok();
    let frames_after = pmm::stats().free_frames;
    kprintln!(
        "OSX|{}|ktest|as_switch|user_flag={}|seen_ok={}|back_ok={}|destroy_ok={}|frames_before={}|frames_after={}|cr3_kernel={}",
        BUILD_ID,
        u8::from(user_flag),
        u8::from(seen == 0x1111_2222_3333_4444),
        u8::from(back == 0xAAAA_BBBB_CCCC_DDDD),
        u8::from(destroy_ok),
        frames_before,
        frames_after,
        u8::from(vmm::kernel_space().is_some_and(|ks| ks.cr3 == paging::read_cr3()))
    );
    if !user_flag
        || !active_is_user
        || seen != 0x1111_2222_3333_4444
        || back != 0xAAAA_BBBB_CCCC_DDDD
        || !destroy_ok
    {
        fail("user space semantics wrong")
    }
    if frames_after != frames_before {
        fail("frames leaked by the user space")
    }
    pass("user address space created, entered, left and destroyed without leaks")
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
