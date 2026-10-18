//! In-kernel tests (test kernel only, feature `ktest`). Origin of the design: Sol OS ADR-010.
//!
//! The host runner passes the test name through QEMU fw_cfg (`opt/nawah/test`) and runs each test
//! in its own QEMU boot, because most tests end in a fatal exception. The result reaches the host
//! as the QEMU exit code plus serial markers (`platform/pc-qemu/target.json`, suite M2).
//! A missing or unknown name is an explicit failure, so a lost name cannot pass by accident.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::{
    apic, context, fwcfg, interrupts, irq, ktest as inject, paging, pit, qemu, user_programs,
};
use crate::mm::addrspace::{self, UserSpace, USER_BASE};
use crate::mm::heap;
use crate::mm::pmm::{self, Frame, PmmError};
use crate::mm::vmm;
use crate::object::channel::{ChannelError, Message};
use crate::object::handle::{Entry, HandleError};
use crate::object::{self, channel, Endpoint, HandleTable, Object, Rights, Vmo, HANDLES_MAX};
use crate::sched;
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
        "user_syscall" => user_syscall(),
        "user_bad_ptr" => user_program_case("user_bad_ptr", user_programs::bad_ptr(), 0xfdfc),
        "user_kernel_access" => user_program_case(
            "user_kernel_access",
            user_programs::kernel_access(),
            crate::arch::syscall::USER_FAULT_EXIT_BASE | 14,
        ),
        "sysret_canonical" => user_program_case(
            "sysret_canonical",
            user_programs::bad_rip(),
            crate::syscall::ERR_RANGE as u64,
        ),
        "vmm_unmap" => vmm_unmap(),
        "vmm_protect" => vmm_protect(),
        "as_switch" => as_switch(),
        "threads_alternate" => threads_alternate(),
        "preempt" => preempt(),
        "exit_cleanup" => exit_cleanup(),
        "user_sleep" => user_sleep(),
        "ipc_roundtrip" => user_program_case("ipc_roundtrip", user_programs::ipc_roundtrip(), 0x1C),
        "rights_denied" => user_program_case("rights_denied", user_programs::rights_denied(), 0x2D),
        "closed_handle" => user_program_case("closed_handle", user_programs::closed_handle(), 0x3E),
        "oversize_rejected" => {
            user_program_case("oversize_rejected", user_programs::oversize(), 0x4F)
        }
        "ipc_no_leak" => ipc_no_leak(),
        "handle_table" => handle_table(),
        "block_wake" => block_wake(),
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

/// Runs a ring-3 program and checks its exit code and that no frame leaked.
fn user_program_case(name: &str, program: &[u8], expected_exit: u64) -> ! {
    match crate::user::run(program) {
        Ok(o) => {
            kprintln!(
                "OSX|{}|ktest|{}|exit={:#x}|expected={:#x}|frames_delta={}",
                BUILD_ID,
                name,
                o.exit_code,
                expected_exit,
                o.frames_delta
            );
            if o.exit_code != expected_exit {
                fail("ring-3 program ended with an unexpected exit code")
            }
            if o.frames_delta != 0 {
                fail("frames leaked by the ring-3 run")
            }
            pass("ring-3 program behaved as the ABI contract says")
        }
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|error={}", BUILD_ID, name, e.code());
            fail("could not run the ring-3 program")
        }
    }
}

/// Two ring-3 programs: ping (result handed back through SYS_EXIT) and a trace message copied
/// from user memory after validation.
fn user_syscall() -> ! {
    let ping = match crate::user::run(user_programs::ping()) {
        Ok(o) => o,
        Err(e) => {
            kprintln!("OSX|{}|ktest|user_syscall|error={}", BUILD_ID, e.code());
            fail("ping program did not run")
        }
    };
    let trace = match crate::user::run(user_programs::trace()) {
        Ok(o) => o,
        Err(e) => {
            kprintln!("OSX|{}|ktest|user_syscall|error={}", BUILD_ID, e.code());
            fail("trace program did not run")
        }
    };
    kprintln!(
        "OSX|{}|ktest|user_syscall|ping_exit={:#x}|trace_exit={}|frames_delta={}",
        BUILD_ID,
        ping.exit_code,
        trace.exit_code,
        ping.frames_delta + trace.frames_delta
    );
    if ping.exit_code != 0x1235
        || trace.exit_code != 13
        || ping.frames_delta != 0
        || trace.frames_delta != 0
    {
        fail("ring-3 syscalls did not return the documented results")
    }
    pass("ring-3 programs call the kernel and exit through the ABI")
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
/// afterwards the heap is back where it started — live blocks, slab pages and large frames
/// equal to the counts before (the scheduler owns a few live blocks since WP-15) — and the
/// frame count too.
fn heap_stress() -> ! {
    let frames_before = pmm::stats().free_frames;
    let before = heap::stats();
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
        "OSX|{}|ktest|heap_stress|allocs={}|frees={}|bytes={}|live_mid={}|live_before={}|live_after={}|slab_before={}|slab_after={}|large_before={}|large_after={}|frames_before={}|frames_after={}",
        BUILD_ID,
        allocs,
        frees,
        bytes,
        live_mid,
        before.live_blocks,
        st.live_blocks,
        before.slab_pages,
        st.slab_pages,
        before.large_frames,
        st.large_frames,
        frames_before,
        frames_after
    );
    if allocs != frees {
        fail("alloc/free count mismatch")
    }
    if st.live_blocks != before.live_blocks
        || st.slab_pages != before.slab_pages
        || st.large_frames != before.large_frames
    {
        fail("heap not back to its state before the stress")
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

// ---- WP-15: threads, preemption, cleanup -------------------------------------------------

/// Order in which the alternating threads logged (ids), filled under a lock.
static LOG: IrqSpinLock<([u8; 64], usize)> = IrqSpinLock::new("ktest_log", ([0; 64], 0));
static STOP: AtomicBool = AtomicBool::new(false);
static SPINS: AtomicU64 = AtomicU64::new(0);

const ALTERNATE_ROUNDS: usize = 8;

/// Logs its id then yields, `ALTERNATE_ROUNDS` times; exit code = id.
extern "sysv64" fn alternator(id: u64) -> u64 {
    for _ in 0..ALTERNATE_ROUNDS {
        {
            let mut g = LOG.lock();
            let n = g.1;
            if n < g.0.len() {
                g.0[n] = id as u8;
                g.1 = n + 1;
            }
        }
        sched::yield_now();
    }
    id
}

/// Sleeps `ticks`; exit code = ticks actually elapsed.
extern "sysv64" fn sleeper(ticks: u64) -> u64 {
    let t0 = sched::stats().ticks;
    sched::sleep_ticks(ticks);
    sched::stats().ticks - t0
}

/// Never yields, never sleeps: only the timer can take the CPU away. Exit code = iterations.
extern "sysv64" fn spinner(_: u64) -> u64 {
    let mut n = 0u64;
    while !STOP.load(Ordering::Acquire) {
        n += 1;
        SPINS.store(n, Ordering::Relaxed);
    }
    n
}

/// Returns its argument (a thread that comes and goes).
extern "sysv64" fn trivial(arg: u64) -> u64 {
    arg
}

fn spawn_or_fail(entry: context::KernelEntry, arg: u64, prio: u8) -> u32 {
    match sched::spawn_kernel(entry, arg, prio) {
        Ok(t) => t,
        Err(_) => fail("spawn_kernel failed"),
    }
}

/// Two kernel threads of the same (higher) priority yield to each other: the log alternates
/// strictly A,B,A,B for 2 × ALTERNATE_ROUNDS entries, each exit code is handed back by join,
/// a third thread sleeps 5 ticks and measures at least 5, and the stacks go back to the
/// allocator (frame count equal after a warm-up thread).
fn threads_alternate() -> ! {
    let warm = spawn_or_fail(trivial, 1, 0);
    if sched::join(warm) != Some(1) {
        fail("warm-up thread did not return its code")
    }
    let frames_before = pmm::stats().free_frames;
    let s0 = sched::stats();
    let a = spawn_or_fail(alternator, u64::from(b'A'), 0);
    let b = spawn_or_fail(alternator, u64::from(b'B'), 0);
    let ra = sched::join(a);
    let rb = sched::join(b);
    let c = spawn_or_fail(sleeper, 5, 0);
    let rc = sched::join(c);
    let s1 = sched::stats();
    let frames_after = pmm::stats().free_frames;
    let (log, n) = {
        let g = LOG.lock();
        (g.0, g.1)
    };
    let expected_n = 2 * ALTERNATE_ROUNDS;
    let alternates = n == expected_n
        && log[..n]
            .iter()
            .enumerate()
            .all(|(i, &id)| id == if i % 2 == 0 { b'A' } else { b'B' });
    let text = core::str::from_utf8(&log[..n]).unwrap_or("?");
    kprintln!(
        "OSX|{}|ktest|threads_alternate|log={}|entries={}|join_a={:#x}|join_b={:#x}|slept_ticks={}|switches={}|threads_after={}|frames_before={}|frames_after={}",
        BUILD_ID,
        text,
        n,
        ra.unwrap_or(u64::MAX),
        rb.unwrap_or(u64::MAX),
        rc.unwrap_or(u64::MAX),
        s1.switches - s0.switches,
        s1.threads,
        frames_before,
        frames_after
    );
    if !alternates {
        fail("threads did not alternate strictly")
    }
    if ra != Some(u64::from(b'A')) || rb != Some(u64::from(b'B')) {
        fail("join did not return the thread exit codes")
    }
    if !matches!(rc, Some(t) if (5..=50).contains(&t)) {
        fail("sleep_ticks did not sleep at least 5 ticks (or far more)")
    }
    if s1.switches - s0.switches < (2 * ALTERNATE_ROUNDS as u64) + 2 || s1.threads != 1 {
        fail("switch count or thread count wrong")
    }
    if frames_after != frames_before {
        fail("thread stacks leaked")
    }
    pass("threads alternate, join returns codes, sleep waits, stacks return")
}

/// A spinning thread of the boot thread's priority never yields; the boot thread never yields
/// either (it halts between ticks). Both still make progress: the timer preempts each in turn,
/// seen as the spin counter moving between the boot thread's observations.
fn preempt() -> ! {
    let c0 = irq::counters();
    let s0 = sched::stats();
    let tid = spawn_or_fail(spinner, 0, 1);
    let start = sched::stats().ticks;
    let mut handovers = 0u32;
    let mut last = SPINS.load(Ordering::Relaxed);
    let mut observations = 0u64;
    while handovers < 3 && sched::stats().ticks - start < 400 {
        context::idle_wait();
        observations += 1;
        let now = SPINS.load(Ordering::Relaxed);
        if now != last {
            handovers += 1;
            last = now;
        }
    }
    let elapsed = sched::stats().ticks - start;
    STOP.store(true, Ordering::Release);
    let spins = sched::join(tid);
    let s1 = sched::stats();
    let c1 = irq::counters();
    kprintln!(
        "OSX|{}|ktest|preempt|handovers={}|observations={}|elapsed_ticks={}|spins={}|preemptions={}|switches={}|max_depth={}|unexpected={}",
        BUILD_ID,
        handovers,
        observations,
        elapsed,
        spins.unwrap_or(0),
        s1.preemptions - s0.preemptions,
        s1.switches - s0.switches,
        c1.max_depth,
        c1.unexpected - c0.unexpected
    );
    if handovers < 3 {
        fail("spinner and boot thread did not alternate under the timer")
    }
    if !matches!(spins, Some(n) if n > 0) {
        fail("spinner did not run or did not exit with its count")
    }
    if s1.preemptions - s0.preemptions < 2 * u64::from(handovers) {
        fail("fewer preemptions than handovers imply")
    }
    if c1.max_depth != 1 || c1.unexpected != c0.unexpected {
        fail("handler re-entry or unexpected vector during preemption")
    }
    pass("timer preemption shares the CPU between a spinner and a non-yielding thread")
}

/// After a warm-up, processes that exit normally and by a ring-3 fault, and a kernel thread,
/// leave the frame count, the heap's live blocks and slab pages, and the thread/process counts
/// exactly as they were.
fn exit_cleanup() -> ! {
    // Warm-up: containers reach their steady capacity, page tables for the stack area exist.
    if crate::user::run(user_programs::ping()).is_err() {
        fail("warm-up process did not run")
    }
    let w = spawn_or_fail(trivial, 2, 1);
    if sched::join(w) != Some(2) {
        fail("warm-up thread did not return its code")
    }
    let frames0 = pmm::stats().free_frames;
    let heap0 = heap::stats();
    let s0 = sched::stats();
    let normal = match crate::user::run(user_programs::ping()) {
        Ok(o) => o,
        Err(_) => fail("ping process did not run"),
    };
    let faulting = match crate::user::run(user_programs::kernel_access()) {
        Ok(o) => o,
        Err(_) => fail("faulting process did not run"),
    };
    let t = spawn_or_fail(trivial, 7, 1);
    let rt = sched::join(t);
    let frames1 = pmm::stats().free_frames;
    let heap1 = heap::stats();
    let s1 = sched::stats();
    kprintln!(
        "OSX|{}|ktest|exit_cleanup|normal_exit={:#x}|fault_exit={:#x}|thread_join={:#x}|frames_before={}|frames_after={}|live_before={}|live_after={}|slab_before={}|slab_after={}|threads_before={}|threads_after={}|processes_after={}",
        BUILD_ID,
        normal.exit_code,
        faulting.exit_code,
        rt.unwrap_or(u64::MAX),
        frames0,
        frames1,
        heap0.live_blocks,
        heap1.live_blocks,
        heap0.slab_pages,
        heap1.slab_pages,
        s0.threads,
        s1.threads,
        s1.processes
    );
    if normal.exit_code != 0x1235
        || faulting.exit_code != (crate::arch::syscall::USER_FAULT_EXIT_BASE | 14)
        || rt != Some(7)
    {
        fail("exit codes wrong")
    }
    if frames1 != frames0 || normal.frames_delta != 0 || faulting.frames_delta != 0 {
        fail("frames leaked by process or thread exit")
    }
    if heap1.live_blocks != heap0.live_blocks || heap1.slab_pages != heap0.slab_pages {
        fail("heap blocks leaked by process or thread exit")
    }
    if s1.threads != 1 || s0.threads != 1 || s1.processes != 0 {
        fail("thread or process records not cleaned up")
    }
    pass("process and thread exit return every frame, heap block and record")
}

/// ABI v1.1 from ring 3: SYS_SLEEP(3) blocks the thread for at least 3 ticks, SYS_YIELD returns
/// 0, the program exits 0x51; no frame leaked.
fn user_sleep() -> ! {
    let t0 = sched::stats().ticks;
    let o = match crate::user::run(user_programs::sleep()) {
        Ok(o) => o,
        Err(e) => {
            kprintln!("OSX|{}|ktest|user_sleep|error={}", BUILD_ID, e.code());
            fail("sleep program did not run")
        }
    };
    let elapsed = sched::stats().ticks - t0;
    kprintln!(
        "OSX|{}|ktest|user_sleep|exit={:#x}|elapsed_ticks={}|frames_delta={}",
        BUILD_ID,
        o.exit_code,
        elapsed,
        o.frames_delta
    );
    if o.exit_code != 0x51 {
        fail("sleep/yield did not return 0 to the program")
    }
    if !(3..=100).contains(&elapsed) {
        fail("SYS_SLEEP did not block for the asked ticks")
    }
    if o.frames_delta != 0 {
        fail("frames leaked by the sleeping process")
    }
    pass("ring-3 sleep and yield go through the scheduler")
}

// ---- WP-16: handles, channels, VMOs ------------------------------------------------------

/// A process that exits with two channels, messages in transit (carrying a VMO handle and a
/// channel end) and a 64 KiB VMO all still open: afterwards no object, handle, frame or heap
/// block remains (after a warm-up run).
fn ipc_no_leak() -> ! {
    if crate::user::run(user_programs::ipc_no_leak()).is_err() {
        fail("warm-up process did not run")
    }
    let frames0 = pmm::stats().free_frames;
    let heap0 = heap::stats();
    let obj0 = object::stats();
    let o = match crate::user::run(user_programs::ipc_no_leak()) {
        Ok(o) => o,
        Err(_) => fail("process did not run"),
    };
    let frames1 = pmm::stats().free_frames;
    let heap1 = heap::stats();
    let obj1 = object::stats();
    let st = sched::stats();
    kprintln!(
        "OSX|{}|ktest|ipc_no_leak|exit={:#x}|frames_before={}|frames_after={}|live_before={}|live_after={}|slab_before={}|slab_after={}|channels={}|endpoints={}|vmos={}|handles={}|processes_after={}",
        BUILD_ID,
        o.exit_code,
        frames0,
        frames1,
        heap0.live_blocks,
        heap1.live_blocks,
        heap0.slab_pages,
        heap1.slab_pages,
        obj1.channels,
        obj1.endpoints,
        obj1.vmos,
        obj1.handles,
        st.processes
    );
    if o.exit_code != 0x5A {
        fail("program did not reach its end (exit code = failing step)")
    }
    if obj1 != obj0 || obj1.channels != 0 || obj1.vmos != 0 || obj1.handles != 0 {
        fail("objects or handles survived the process")
    }
    if frames1 != frames0 || o.frames_delta != 0 {
        fail("frames leaked through objects left open at exit")
    }
    if heap1.live_blocks != heap0.live_blocks || heap1.slab_pages != heap0.slab_pages {
        fail("heap blocks leaked through objects left open at exit")
    }
    if st.processes != 0 {
        fail("process record not cleaned up")
    }
    pass("process exit releases channels, messages in transit, VMOs and handles")
}

/// Handle table semantics: generation-checked values, slot reuse with a new generation, rights
/// subsets on duplicate, table limit, live counts.
fn handle_table() -> ! {
    let obj0 = object::stats();
    let mut t = HandleTable::new();
    let (a, b) = channel::create();
    let ins = |t: &mut HandleTable, object: Object, rights: Rights| -> u32 {
        match t.insert(Entry { object, rights }) {
            Ok(h) => h,
            Err(_) => fail("insert failed"),
        }
    };
    let h1 = ins(&mut t, Object::Channel(a), Rights::CHANNEL_DEFAULT);
    let h2 = ins(&mut t, Object::Channel(b), Rights::CHANNEL_DEFAULT);
    let first_values_ok = h1 == 0x1_0000 && h2 == 0x1_0001;
    let removed = t.remove(h1).is_ok();
    let stale = matches!(t.remove(h1), Err(HandleError::BadHandle))
        && matches!(t.get(h1, Rights::NONE), Err(HandleError::BadHandle));
    let Some(vmo) = Vmo::new(4096) else {
        fail("Vmo::new failed")
    };
    let h3 = ins(&mut t, Object::Vmo(vmo), Rights::VMO_DEFAULT);
    let reuse_ok = h3 != h1 && (h3 & 0xffff) == (h1 & 0xffff) && h3 == 0x2_0000;
    let dup = match t.duplicate(h3, Rights::READ) {
        Ok(d) => d,
        Err(_) => fail("duplicate with a subset failed"),
    };
    let dup_rights_ok = t.get(dup, Rights::READ).is_ok()
        && matches!(t.get(dup, Rights::WRITE), Err(HandleError::Access));
    let escalation_refused = t.duplicate(dup, Rights::VMO_DEFAULT) == Err(HandleError::Access)
        && t.duplicate(h2, Rights(0x40)) == Err(HandleError::Access)
        && t.get(0, Rights::NONE).is_err()
        && t.get(h2 ^ 0x8_0000, Rights::NONE).is_err();
    let live_ok = t.len() == 3 && object::stats().handles == obj0.handles + 3;
    // Fill up to the limit: the next insert is refused with NoResources, and nothing breaks.
    let mut added = 0;
    while t.len() < HANDLES_MAX {
        match t.duplicate(h2, Rights::READ) {
            Ok(_) => added += 1,
            Err(_) => break,
        }
    }
    let limit_ok =
        t.len() == HANDLES_MAX && t.duplicate(h2, Rights::READ) == Err(HandleError::NoResources);
    drop(t);
    let obj1 = object::stats();
    kprintln!(
        "OSX|{}|ktest|handle_table|h1={:#x}|h2={:#x}|h3={:#x}|dup={:#x}|removed={}|stale_refused={}|reuse_ok={}|dup_rights_ok={}|escalation_refused={}|live_ok={}|added={}|limit_ok={}|handles_after={}|channels_after={}|vmos_after={}",
        BUILD_ID,
        h1,
        h2,
        h3,
        dup,
        u8::from(removed),
        u8::from(stale),
        u8::from(reuse_ok),
        u8::from(dup_rights_ok),
        u8::from(escalation_refused),
        u8::from(live_ok),
        added,
        u8::from(limit_ok),
        obj1.handles,
        obj1.channels,
        obj1.vmos
    );
    if !(first_values_ok && removed && stale && reuse_ok) {
        fail("handle values or generations wrong")
    }
    if !(dup_rights_ok && escalation_refused) {
        fail("rights not enforced on duplicate/get")
    }
    if !(live_ok && limit_ok) {
        fail("live count or table limit wrong")
    }
    if obj1 != obj0 {
        fail("objects survived the table")
    }
    pass("handle table: generations, slot reuse, rights subsets, limit, counts")
}

/// Endpoint handed to `blocking_reader` (one reader at a time).
static BLOCK_EP: IrqSpinLock<Option<alloc::sync::Arc<Endpoint>>> =
    IrqSpinLock::new("ktest_block_ep", None);
static BLOCK_LOOPS: AtomicU64 = AtomicU64::new(0);

/// Sleeps `arg` ticks, then reads its endpoint, blocking until a message or the peer's close.
/// Exit code: the first byte, or 0xC105ED on peer close. Counts the times it came back from
/// `block_current` without a message (a wake token or a spurious wake-up).
extern "sysv64" fn blocking_reader(arg: u64) -> u64 {
    if arg > 0 {
        sched::sleep_ticks(arg);
    }
    let Some(ep) = BLOCK_EP.lock().clone() else {
        return 0xBAD0;
    };
    let tid = sched::current_tid();
    loop {
        match ep.read(16, 4, Some(tid)) {
            Ok(m) => return u64::from(m.bytes.first().copied().unwrap_or(0)),
            Err(ChannelError::ShouldWait) => {
                sched::block_current();
                BLOCK_LOOPS.fetch_add(1, Ordering::Relaxed);
            }
            Err(ChannelError::PeerClosed) => return 0xC105ED,
            Err(ChannelError::BufferTooSmall { .. }) => return 0xBAD1,
        }
    }
}

fn msg(byte: u8) -> Message {
    Message {
        bytes: alloc::vec![byte],
        handles: Vec::new(),
    }
}

/// Blocking read and wake-ups: a reader blocked on an empty channel is woken by a write; a
/// wake-up that arrives before the thread blocks is kept as a token (one extra loop, no hang);
/// closing the peer wakes a blocked reader with PeerClosed. No object or frame survives.
fn block_wake() -> ! {
    let obj0 = object::stats();
    let frames0 = pmm::stats().free_frames;
    // 1. Block, then a write wakes.
    let (a, b) = channel::create();
    *BLOCK_EP.lock() = Some(b);
    BLOCK_LOOPS.store(0, Ordering::Relaxed);
    let k1 = spawn_or_fail(blocking_reader, 0, 0);
    sched::yield_now(); // k1 runs first (priority 0) until it blocks
    sched::sleep_ticks(5);
    let t_write = sched::stats().ticks;
    if a.write(msg(0x42)).is_err() {
        fail("write to the blocked reader's channel failed")
    }
    let r1 = sched::join(k1);
    let loops1 = BLOCK_LOOPS.load(Ordering::Relaxed);
    let t_done = sched::stats().ticks;
    drop(a);
    *BLOCK_EP.lock() = None;
    // 2. Token: wake before the reader blocks (it sleeps 3 ticks first), then write later.
    let (a2, b2) = channel::create();
    *BLOCK_EP.lock() = Some(b2);
    BLOCK_LOOPS.store(0, Ordering::Relaxed);
    let k2 = spawn_or_fail(blocking_reader, 3, 0);
    sched::yield_now(); // k2 runs until its 3-tick sleep
    sched::wake(k2); // k2 is sleeping: the wake-up becomes a token
    sched::sleep_ticks(8);
    if a2.write(msg(0x43)).is_err() {
        fail("second write failed")
    }
    let r2 = sched::join(k2);
    let loops2 = BLOCK_LOOPS.load(Ordering::Relaxed);
    drop(a2);
    *BLOCK_EP.lock() = None;
    // 3. Peer close wakes a blocked reader.
    let (a3, b3) = channel::create();
    *BLOCK_EP.lock() = Some(b3);
    BLOCK_LOOPS.store(0, Ordering::Relaxed);
    let k3 = spawn_or_fail(blocking_reader, 0, 0);
    sched::yield_now(); // k3 blocks
    sched::sleep_ticks(3);
    drop(a3);
    let r3 = sched::join(k3);
    *BLOCK_EP.lock() = None;
    let obj1 = object::stats();
    let frames1 = pmm::stats().free_frames;
    kprintln!(
        "OSX|{}|ktest|block_wake|r1={:#x}|loops1={}|woken_within_ticks={}|r2={:#x}|loops2={}|r3={:#x}|channels_after={}|endpoints_after={}|frames_before={}|frames_after={}",
        BUILD_ID,
        r1.unwrap_or(u64::MAX),
        loops1,
        t_done - t_write,
        r2.unwrap_or(u64::MAX),
        loops2,
        r3.unwrap_or(u64::MAX),
        obj1.channels,
        obj1.endpoints,
        frames0,
        frames1
    );
    if r1 != Some(0x42) || loops1 != 1 || t_done - t_write > 10 {
        fail("blocked reader not woken by the write as expected")
    }
    if r2 != Some(0x43) || loops2 != 2 {
        fail("wake token not kept across sleep/block")
    }
    if r3 != Some(0xC105ED) {
        fail("peer close did not wake the blocked reader")
    }
    if obj1 != obj0 || frames1 != frames0 {
        fail("objects or frames leaked")
    }
    pass("blocking read: woken by write, by token, by peer close; nothing leaked")
}
