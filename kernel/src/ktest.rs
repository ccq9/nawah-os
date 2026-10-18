//! In-kernel tests (test kernel only, feature `ktest`). Origin of the design: Sol OS ADR-010.
//!
//! The host runner passes the test name through QEMU fw_cfg (`opt/nawah/test`) and runs each test
//! in its own QEMU boot, because most tests end in a fatal exception. The result reaches the host
//! as the QEMU exit code plus serial markers (`platform/pc-qemu/target.json`, suite M2).
//! A missing or unknown name is an explicit failure, so a lost name cannot pass by accident.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::{
    self, apic, context, fwcfg, interrupts, irq, ktest as inject, paging, pit, qemu, user_programs,
};
use crate::fs::fat32::FsError;
use crate::loader::elf::{self, ElfError};
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
        "app_exit_code" => app_exit_code(),
        "elf_malformed" => elf_malformed(),
        "elf_wx" => elf_wx(),
        "isolation" => isolation(),
        "priority_order" => priority_order(),
        "smp_online" => smp_online(),
        "lock_contention" => lock_contention(),
        "tlb_shootdown" => tlb_shootdown(),
        "blk_read_pattern" => blk_read_pattern(),
        "blk_user_cr3" => blk_user_cr3(),
        "blk_persist_write" => blk_persist(true),
        "blk_persist_read" => blk_persist(false),
        "fat32_read" => fat32_read(),
        "fat32_write" => fat32_write(),
        "fat32_persist_write" => fat32_persist(true),
        "fat32_persist_read" => fat32_persist(false),
        "file_roundtrip" => file_app("file_roundtrip", crate::apps::FILE_ROUNDTRIP, 0x60),
        "path_invalid" => file_app("path_invalid", crate::apps::PATH_INVALID, 0x61),
        "fd_leak" => fd_leak(),
        "spawn_volume" => volume_app("spawn_volume", crate::apps::LAUNCH, 0x70),
        "wait_timeout" => wait_timeout(),
        "child_exit" => volume_app("child_exit", crate::apps::CHILD, 0x72),
        "svc_order" => svc_order(),
        "svc_timeout" => svc_timeout(),
        "svc_restart" => svc_restart(),
        "token_objects" => token_objects(),
        "login" => login(),
        "session_lock" => session_lock(),
        "authz_denied" => authz_denied(),
        "config_cas" => config_cas(),
        "config_retry" => config_retry(),
        "config_notify" => config_notify(),
        "policy_precedence" => policy_precedence(),
        "config_persist_write" => config_persist(true),
        "config_persist_read" => config_persist(false),
        "net_link" => net_link(),
        "net_dhcp" => net_dhcp(),
        "net_icmp" => net_icmp(),
        "net_udp_echo" => net_udp_echo(),
        "net_no_internet" => net_no_internet(),
        "net_tcp_echo" => net_tcp_echo(),
        "net_tcp_retransmit" => net_tcp_retransmit(),
        "shell_svc" => shell_session("shell_svc"),
        "peer_loss" => peer_loss(),
        "shell_login" => shell_session("shell_login"),
        "net_limits" => net_limits(),
        "kbd_scancodes" => kbd_scancodes(),
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
    // Only the idle threads remain: one per online CPU (thread 0 and the APs', WP-20).
    if s1.switches - s0.switches < (2 * ALTERNATE_ROUNDS as u64) + 2
        || s1.threads != arch::smp::online_count() as usize
    {
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
    let idle = arch::smp::online_count() as usize;
    if s1.threads != idle || s0.threads != idle || s1.processes != 0 {
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

// ---- WP-17: ELF loader -----------------------------------------------------------------------

fn hello_image() -> &'static [u8] {
    if crate::apps::HELLO.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    crate::apps::HELLO
}

/// Byte offsets of the PT_LOAD program headers of a (valid) image.
fn pt_load_offsets(image: &[u8]) -> Vec<usize> {
    let phoff = u64::from_le_bytes(image[32..40].try_into().unwrap_or([0; 8])) as usize;
    let phnum = usize::from(u16::from_le_bytes([image[56], image[57]]));
    (0..phnum)
        .map(|i| phoff + i * 56)
        .filter(|&ph| u32::from_le_bytes(image[ph..ph + 4].try_into().unwrap_or([0; 4])) == 1)
        .collect()
}

fn put_u16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put_u32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put_u64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// The embedded `hello` ELF runs as a process: trace line, ping, exit code 7, no frame left.
fn app_exit_code() -> ! {
    let image = hello_image();
    let Ok((segs, n, entry)) = elf::parse(image) else {
        fail("hello image does not parse")
    };
    let (o, l) = match crate::user::run_elf(image) {
        Ok(r) => r,
        Err(e) => {
            kprintln!("OSX|{}|ktest|app_exit_code|error={}", BUILD_ID, e.code());
            fail("hello did not load")
        }
    };
    let exec_segments = segs
        .iter()
        .take(n)
        .flatten()
        .filter(|s| s.executable())
        .count();
    kprintln!(
        "OSX|{}|ktest|app_exit_code|size={}|segments={}|exec_segments={}|entry={:#x}|pages={}|exit={:#x}|frames_delta={}",
        BUILD_ID,
        image.len(),
        l.segments,
        exec_segments,
        entry,
        l.pages,
        o.exit_code,
        o.frames_delta
    );
    if o.exit_code != 7 {
        fail("hello did not exit 7")
    }
    if o.frames_delta != 0 {
        fail("frames leaked by the application")
    }
    if exec_segments != 1 || l.segments < 2 || entry != l.entry {
        fail("unexpected segment layout")
    }
    pass("ELF application loaded, ran and exited with its code")
}

/// Thirteen corruptions of the hello image, each refused with its own stable code before
/// anything runs, and no frame left mapped after any of them.
fn elf_malformed() -> ! {
    let image = hello_image();
    let loads = pt_load_offsets(image);
    if loads.len() < 2 {
        fail("hello has fewer than two PT_LOAD segments")
    }
    // The results table is reserved before the baseline: its growth is heap memory from the
    // frame allocator and would be counted against the refused images (CI run 39143549498:
    // one frame, once the scheduler's reserved tables changed the slab layout).
    let mut results: Vec<(&str, &str, bool)> = Vec::with_capacity(16);
    let frames0 = pmm::stats().free_frames;
    let mut check = |name: &'static str, img: Vec<u8>, expected: ElfError| {
        let got = match crate::user::spawn_elf(&img, 1) {
            Ok((pid, _)) => {
                // Must not happen: let the process finish so nothing dangles, then fail.
                let _ = sched::wait_process(pid);
                None
            }
            Err(e) => Some(e),
        };
        let ok = got == Some(expected);
        results.push((name, got.map(|e| e.code()).unwrap_or("LOADED"), ok));
    };
    let fresh = || image.to_vec();
    let (p0, p1) = (loads[0], loads[1]);
    let mut v = fresh();
    v[0] = 0;
    check("magic", v, ElfError::BadMagic);
    let mut v = fresh();
    v[4] = 1;
    check("class32", v, ElfError::NotElf64);
    let mut v = fresh();
    v[5] = 2;
    check("bigendian", v, ElfError::NotLittleEndian);
    let mut v = fresh();
    put_u16(&mut v, 16, 3);
    check("et_dyn", v, ElfError::NotExecutable);
    let mut v = fresh();
    put_u16(&mut v, 18, 0xB7);
    check("aarch64", v, ElfError::WrongMachine);
    let mut v = fresh();
    put_u16(&mut v, 56, 0);
    check("phnum0", v, ElfError::BadProgramHeaders);
    let mut v = fresh();
    put_u64(&mut v, 32, image.len() as u64);
    check("phoff_out", v, ElfError::BadProgramHeaders);
    let mut v = fresh();
    put_u64(&mut v, p0 + 16, 0x1000);
    check("vaddr_low", v, ElfError::SegmentOutsideWindow);
    let mut v = fresh();
    let memsz = u64::from_le_bytes(image[p0 + 40..p0 + 48].try_into().unwrap_or([0; 8]));
    put_u64(&mut v, p0 + 32, memsz + 1);
    check("filesz_gt_memsz", v, ElfError::MemSmallerThanFile);
    let mut v = fresh();
    put_u64(&mut v, p0 + 8, image.len() as u64);
    check("offset_out", v, ElfError::FileRangeOutside);
    let mut v = fresh();
    put_u64(&mut v, 24, elf::APP_END - 8);
    check("entry_out", v, ElfError::EntryOutsideSegments);
    let mut v = fresh();
    let vaddr0 = u64::from_le_bytes(image[p0 + 16..p0 + 24].try_into().unwrap_or([0; 8]));
    put_u64(&mut v, p1 + 16, vaddr0);
    check("overlap", v, ElfError::SegmentOverlap);
    check("truncated", image[..32].to_vec(), ElfError::TooShort);
    let frames1 = pmm::stats().free_frames;
    let all_ok = results.iter().all(|r| r.2);
    let mut line = alloc::string::String::new();
    for (name, code, ok) in &results {
        line.push_str(name);
        line.push('=');
        line.push_str(code);
        line.push(if *ok { '+' } else { '!' });
        line.push(',');
    }
    kprintln!(
        "OSX|{}|ktest|elf_malformed|cases={}|all_refused_as_expected={}|frames_before={}|frames_after={}|detail={}",
        BUILD_ID,
        results.len(),
        u8::from(all_ok),
        frames0,
        frames1,
        line
    );
    if !all_ok {
        fail("a malformed image was accepted or refused with the wrong code")
    }
    if frames1 != frames0 {
        fail("frames leaked by refused images")
    }
    pass("malformed ELF images are refused with stable codes and leave nothing mapped")
}

/// W^X: a segment marked writable and executable is refused; the valid image's pages carry
/// exactly the permissions of their segment (executable pages read-only, writable pages NX).
fn elf_wx() -> ! {
    let image = hello_image();
    let loads = pt_load_offsets(image);
    let frames0 = pmm::stats().free_frames;
    let mut v = image.to_vec();
    let flags = u32::from_le_bytes(v[loads[0] + 4..loads[0] + 8].try_into().unwrap_or([0; 4]));
    put_u32(&mut v, loads[0] + 4, flags | 0x3);
    let wx_refused = matches!(
        crate::user::spawn_elf(&v, 1),
        Err(ElfError::WritableExecutable)
    );
    // The copy is heap memory taken from the frame allocator: give it back before the balance
    // is measured (CI run 39107509833: four frames "leaked" were this vector).
    drop(v);
    let Ok((segs, n, _)) = elf::parse(image) else {
        fail("hello image does not parse")
    };
    let Ok(mut us) = UserSpace::new() else {
        fail("UserSpace::new failed")
    };
    let loaded = match elf::load(&mut us, image) {
        Ok(l) => l,
        Err(_) => fail("load of the valid image failed"),
    };
    let mut perms_ok = true;
    let (mut x_pages, mut w_pages, mut r_pages) = (0, 0, 0);
    for s in segs.iter().take(n).flatten() {
        let mut page = s.vaddr & !0xFFF;
        while page < s.vaddr + s.memsz {
            let Some(f) = us.flags_of(page) else {
                perms_ok = false;
                break;
            };
            let w = f & paging::WRITE != 0;
            let nx = f & paging::NX != 0;
            match (s.executable(), s.writable()) {
                (true, false) => {
                    perms_ok &= !w && !nx;
                    x_pages += 1;
                }
                (false, true) => {
                    perms_ok &= w && nx;
                    w_pages += 1;
                }
                (false, false) => {
                    perms_ok &= !w && nx;
                    r_pages += 1;
                }
                (true, true) => perms_ok = false,
            }
            page += 0x1000;
        }
    }
    let stack_flags = us.flags_of(elf::STACK_TOP - 0x1000);
    let stack_ok = stack_flags.is_some_and(|f| f & paging::WRITE != 0 && f & paging::NX != 0)
        && us
            .flags_of(elf::STACK_TOP - (elf::STACK_PAGES + 1) * 0x1000)
            .is_none();
    let destroyed = us.destroy().is_ok();
    let frames1 = pmm::stats().free_frames;
    kprintln!(
        "OSX|{}|ktest|elf_wx|wx_refused={}|perms_ok={}|x_pages={}|w_pages={}|r_pages={}|stack_ok={}|pages={}|frames_before={}|frames_after={}",
        BUILD_ID,
        u8::from(wx_refused),
        u8::from(perms_ok),
        x_pages,
        w_pages,
        r_pages,
        u8::from(stack_ok),
        loaded.pages,
        frames0,
        frames1
    );
    if !wx_refused {
        fail("a writable+executable segment was accepted")
    }
    if !perms_ok || x_pages == 0 || w_pages == 0 {
        fail("segment pages do not carry W^X permissions")
    }
    if !stack_ok || !destroyed || frames1 != frames0 {
        fail("stack layout or cleanup wrong")
    }
    pass("W^X enforced: RWX segment refused, pages carry their segment's permissions")
}

// ---- WP-18: block device ---------------------------------------------------------------------

/// The lab's disk image (tools/fat32.py, driven by tools/project.py `prepare_disk`) carries
/// `(sector * 7 + i) & 0xFF` in its last `PATTERN_TAIL` sectors, outside every FAT32 cluster
/// the file system allocates; the raw persistence pair uses the 8 sectors before them.
const PATTERN_TAIL: u64 = 8;
const PATTERN_SECTORS: usize = 8;
const PERSIST_TAIL: u64 = 16;
const PERSIST_SECTORS: usize = 8;
const PERSIST_TAG: &[u8] = b"NAWAH-PERSIST|";

fn pattern_byte(sector: u64, i: usize) -> u8 {
    (sector.wrapping_mul(7).wrapping_add(i as u64) & 0xFF) as u8
}

/// virtio-blk read: the device is present with the lab's capacity, an 8-sector read returns
/// the harness pattern exactly, a read past the end and an unaligned length are refused, and
/// the DMA path leaves the frame count alone.
fn blk_read_pattern() -> ! {
    let present = crate::block::present();
    let capacity = crate::block::capacity_sectors();
    // The buffer is heap memory (a frame): take it before measuring the balance (CI run
    // 39108867621 counted it as a leak).
    let mut buf = alloc::vec![0u8; PATTERN_SECTORS * 512];
    let first = capacity.saturating_sub(PATTERN_TAIL);
    let frames0 = pmm::stats().free_frames;
    let read = crate::block::read(first, &mut buf);
    let mut mismatches = 0u32;
    for (k, b) in buf.iter().enumerate() {
        let sector = first + (k / 512) as u64;
        if *b != pattern_byte(sector, k % 512) {
            mismatches += 1;
        }
    }
    let mut one = [0u8; 512];
    let past_end = crate::block::read(capacity, &mut one);
    let mut odd = [0u8; 100];
    let unaligned = crate::block::read(0, &mut odd);
    let frames1 = pmm::stats().free_frames;
    kprintln!(
        "OSX|{}|ktest|blk_read_pattern|present={}|capacity_sectors={}|read={}|mismatches={}|first_bytes={:02x}{:02x}{:02x}{:02x}|past_end={}|unaligned={}|frames_before={}|frames_after={}",
        BUILD_ID,
        u8::from(present),
        capacity,
        read.map_or_else(|e| e.code(), |_| "ok"),
        mismatches,
        buf[0],
        buf[1],
        buf[2],
        buf[3],
        past_end.map_or_else(|e| e.code(), |_| "ok"),
        unaligned.map_or_else(|e| e.code(), |_| "ok"),
        frames0,
        frames1
    );
    if !present || capacity == 0 {
        fail("no virtio-blk device")
    }
    if read.is_err() || mismatches != 0 {
        fail("pattern sectors not read back exactly")
    }
    if past_end.is_ok() || unaligned.is_ok() {
        fail("out-of-range or unaligned request accepted")
    }
    if frames1 != frames0 {
        fail("frames leaked by block reads")
    }
    pass("virtio-blk reads the harness pattern exactly and refuses bad requests")
}

// ---- Priority order (WP-22, mutant M31) ------------------------------------------------

static PRIO_SPINS: AtomicU64 = AtomicU64::new(0);
static PRIO_STOP: AtomicBool = AtomicBool::new(false);
const HIGH_RUN_TICKS: u64 = 15;

/// Lowest priority: counts while it has the CPU.
extern "sysv64" fn low_spinner(_: u64) -> u64 {
    let mut n = 0u64;
    while !PRIO_STOP.load(Ordering::Acquire) {
        n += 1;
        PRIO_SPINS.store(n, Ordering::Relaxed);
    }
    n
}

/// Highest priority: runs for longer than a quantum without yielding; a lower-priority thread
/// must not get the CPU meanwhile. Returns 1 if the spinner advanced during the run.
extern "sysv64" fn high_runner(_: u64) -> u64 {
    let before = PRIO_SPINS.load(Ordering::Relaxed);
    let t0 = sched::stats().ticks;
    while sched::stats().ticks - t0 < HIGH_RUN_TICKS {
        core::hint::spin_loop();
    }
    u64::from(PRIO_SPINS.load(Ordering::Relaxed) != before)
}

/// Middle priority: starts the spinner and the high runner, then sleeps so the spinner gets
/// the CPU once the runner is done; returns (spinner advanced during the runner) | (spinner
/// ran at all) << 1.
extern "sysv64" fn prio_driver(_: u64) -> u64 {
    let Ok(low) = sched::spawn_kernel(low_spinner, 0, 3) else {
        return 0xFF;
    };
    let Ok(high) = sched::spawn_kernel(high_runner, 0, 0) else {
        return 0xFE;
    };
    let during = sched::join(high).unwrap_or(0xFD);
    sched::sleep_ticks(20);
    PRIO_STOP.store(true, Ordering::Release);
    let spins = sched::join(low).unwrap_or(0);
    during | (u64::from(spins > 0) << 1)
}

/// Fixed priorities are honoured across a quantum boundary: while a priority-0 thread runs for
/// 15 ticks (> QUANTUM_TICKS = 10) a priority-3 spinner never advances; afterwards it does.
fn priority_order() -> ! {
    let frames0 = pmm::stats().free_frames;
    let drv = spawn_or_fail(prio_driver, 0, 1);
    let r = sched::join(drv).unwrap_or(u64::MAX);
    let frames1 = pmm::stats().free_frames;
    kprintln!(
        "OSX|{}|ktest|priority_order|high_run_ticks={}|quantum_ticks={}|spinner_advanced_during_high={}|spinner_ran_after={}|spins={}|frames_before={}|frames_after={}",
        BUILD_ID,
        HIGH_RUN_TICKS,
        sched::QUANTUM_TICKS,
        r & 1,
        (r >> 1) & 1,
        PRIO_SPINS.load(Ordering::Relaxed),
        frames0,
        frames1
    );
    if r >= 0xFD {
        fail("threads did not spawn or join")
    }
    if r & 1 != 0 {
        fail("a lower-priority thread ran while a higher-priority thread was runnable")
    }
    if (r >> 1) & 1 == 0 {
        fail("the low-priority spinner never ran (test not meaningful)")
    }
    if frames0 != frames1 {
        fail("frames leaked")
    }
    pass("priorities decide who runs, not the quantum")
}

// ---- Isolation (WP-22) -----------------------------------------------------------------

/// Two processes run the same program at the same virtual addresses at the same time: each
/// finds its data page zeroed (first read 0), writes a pattern, sleeps while the other runs,
/// and still finds its own pattern (bit 63 set in the exit code). Neither frame is shared,
/// neither process sees the other's write, and both spaces go away without a frame left.
fn isolation() -> ! {
    let frames0 = pmm::stats().free_frames;
    let code = user_programs::isolation();
    let a = match crate::user::spawn(code, 1) {
        Ok(p) => p,
        Err(e) => {
            kprintln!("OSX|{}|ktest|isolation|error={}", BUILD_ID, e.code());
            fail("first process did not spawn")
        }
    };
    let b = match crate::user::spawn(code, 1) {
        Ok(p) => p,
        Err(e) => {
            kprintln!("OSX|{}|ktest|isolation|error={}", BUILD_ID, e.code());
            fail("second process did not spawn")
        }
    };
    let ra = sched::wait_process(a).unwrap_or(u64::MAX);
    let rb = sched::wait_process(b).unwrap_or(u64::MAX);
    let frames1 = pmm::stats().free_frames;
    let st = sched::stats();
    kprintln!(
        "OSX|{}|ktest|isolation|pid_a={}|pid_b={}|exit_a={:#x}|exit_b={:#x}|processes_after={}|frames_before={}|frames_after={}",
        BUILD_ID,
        a,
        b,
        ra,
        rb,
        st.processes,
        frames0,
        frames1
    );
    // Exit code: first read in bits 0..62 (must be 0: a fresh, zeroed page), bit 63 = the own
    // pattern survived the other process's run at the same address.
    if ra != 1 << 63 || rb != 1 << 63 {
        fail("a process saw another process's memory (or lost its own)")
    }
    if st.processes != 0 || frames0 != frames1 {
        fail("process records or frames leaked")
    }
    pass("two processes at the same virtual addresses are isolated")
}

// ---- SMP (WP-20, ADR-0015) --------------------------------------------------------------

/// Per-CPU probe: records the CPU index (GS) and APIC ID it runs with, spins briefly so timer
/// ticks accrue on that CPU, and returns both packed.
extern "sysv64" fn smp_where(expected: u64) -> u64 {
    let t0 = arch::irq::ticks_of(expected as usize);
    // Hold the CPU for a few of its own timer ticks (the slice expires and it is picked
    // again: round-robin against the idle thread proves the AP timer preempts).
    while arch::irq::ticks_of(expected as usize) < t0 + 3 {
        core::hint::spin_loop();
    }
    u64::from(arch::cpu_id()) | (u64::from(apic::my_id()) << 8)
}

/// Every CPU the MADT lists is online, answers to its index on its own stack, reports a
/// distinct APIC ID, and takes its own timer ticks; nothing leaks after the threads are joined.
fn smp_online() -> ! {
    let online = arch::smp::online_mask();
    let count = arch::smp::online_count();
    let warm = spawn_or_fail(trivial, 1, 0);
    let _ = sched::join(warm);
    let frames0 = pmm::stats().free_frames;
    let mut seen = alloc::vec::Vec::new();
    let mut ids = alloc::vec::Vec::new();
    let mut ok = true;
    for cpu in 0..arch::smp::MAX_CPUS {
        if online & (1 << cpu) == 0 {
            continue;
        }
        let tid = match sched::spawn_on(cpu, smp_where, cpu as u64, 1) {
            Ok(t) => t,
            Err(_) => fail("spawn_on failed for an online CPU"),
        };
        let r = sched::join(tid).unwrap_or(u64::MAX);
        let got_cpu = r & 0xFF;
        let got_apic = r >> 8;
        ok &= got_cpu == cpu as u64 && !ids.contains(&got_apic);
        seen.push(got_cpu);
        ids.push(got_apic);
    }
    let frames1 = pmm::stats().free_frames;
    let mut ticks = alloc::string::String::new();
    let mut all_tick = true;
    for cpu in 0..arch::smp::MAX_CPUS {
        if online & (1 << cpu) != 0 {
            use core::fmt::Write as _;
            let t = arch::irq::ticks_of(cpu);
            let _ = write!(ticks, "{t},");
            all_tick &= t > 0;
        }
    }
    let st = sched::stats();
    kprintln!(
        "OSX|{}|ktest|smp_online|online_mask={:#x}|online={}|seen={:?}|apic_ids={:?}|ticks={}|all_tick={}|threads={}|frames_before={}|frames_after={}",
        BUILD_ID,
        online,
        count,
        seen,
        ids,
        ticks,
        u8::from(all_tick),
        st.threads,
        frames0,
        frames1
    );
    if count < 2 {
        fail("fewer than two CPUs online (is the lab running -smp 4?)")
    }
    if !ok || seen.len() != count as usize {
        fail("a CPU did not run its probe or reported a wrong index/APIC ID")
    }
    if !all_tick {
        fail("a CPU took no timer ticks")
    }
    if frames0 != frames1 {
        fail("frames leaked across cross-CPU spawn/join")
    }
    pass("every MADT CPU is online, runs placed threads and ticks")
}

static CONTENDED: IrqSpinLock<u64> = IrqSpinLock::new("ktest_contended", 0);
static ATOMIC_SUM: AtomicU64 = AtomicU64::new(0);
static GO: AtomicBool = AtomicBool::new(false);
const CONTENTION_ROUNDS: u64 = 100_000;

/// One contender: waits for the start flag, then increments the locked counter and the atomic
/// counter CONTENTION_ROUNDS times each; returns the ticks it took on its CPU.
extern "sysv64" fn contender(cpu: u64) -> u64 {
    while !GO.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let t0 = arch::irq::ticks_of(cpu as usize);
    for _ in 0..CONTENTION_ROUNDS {
        {
            let mut g = CONTENDED.lock();
            *g += 1;
        }
        ATOMIC_SUM.fetch_add(1, Ordering::Relaxed);
    }
    arch::irq::ticks_of(cpu as usize) - t0
}

/// One thread per online CPU hammers one `IrqSpinLock` and one atomic at the same time: both
/// totals are exactly CPUs × ROUNDS (a lost update would show), the threads overlapped in time
/// (parallel=1 when the whole run took fewer boot-CPU ticks than the sum of per-CPU ticks).
fn lock_contention() -> ! {
    let online = arch::smp::online_mask();
    let count = arch::smp::online_count();
    let mut tids = alloc::vec::Vec::new();
    for cpu in 0..arch::smp::MAX_CPUS {
        if online & (1 << cpu) != 0 {
            match sched::spawn_on(cpu, contender, cpu as u64, 1) {
                Ok(t) => tids.push(t),
                Err(_) => fail("spawn_on failed"),
            }
        }
    }
    let start = sched::stats().ticks;
    GO.store(true, Ordering::Release);
    let mut cpu_ticks = 0u64;
    for t in tids {
        cpu_ticks += sched::join(t).unwrap_or(0);
    }
    let elapsed = sched::stats().ticks - start;
    let locked = *CONTENDED.lock();
    let atomic = ATOMIC_SUM.load(Ordering::Relaxed);
    let expected = u64::from(count) * CONTENTION_ROUNDS;
    let parallel = count >= 2 && cpu_ticks > elapsed + elapsed / 2;
    kprintln!(
        "OSX|{}|ktest|lock_contention|cpus={}|rounds={}|locked={}|atomic={}|expected={}|elapsed_ticks={}|cpu_ticks={}|parallel={}",
        BUILD_ID,
        count,
        CONTENTION_ROUNDS,
        locked,
        atomic,
        expected,
        elapsed,
        cpu_ticks,
        u8::from(parallel)
    );
    if count < 2 {
        fail("fewer than two CPUs online")
    }
    if locked != expected || atomic != expected {
        fail("a counter lost updates under contention")
    }
    pass("the lock serialises every CPU: counters exact")
}

/// Inside the scratch area's first 2 MiB, whose tables exist from boot (a page elsewhere would
/// keep a page-table frame and read as a leak).
const SHOOT_PAGE: u64 = vmm::SCRATCH_BASE + 0x12_0000;
static SHOOT_STEP: AtomicU64 = AtomicU64::new(0);
static SHOOT_SEEN: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Reader on another CPU: reads the page (caching its translation), reports, waits for the
/// remap, reads again, reports; the third read follows a protect-to-read-only round.
extern "sysv64" fn shoot_reader(_: u64) -> u64 {
    while SHOOT_STEP.load(Ordering::Acquire) < 1 {
        core::hint::spin_loop();
    }
    SHOOT_SEEN[0].store(inject::read_qword(SHOOT_PAGE), Ordering::Release);
    SHOOT_STEP.store(2, Ordering::Release);
    while SHOOT_STEP.load(Ordering::Acquire) < 3 {
        core::hint::spin_loop();
    }
    SHOOT_SEEN[1].store(inject::read_qword(SHOOT_PAGE), Ordering::Release);
    SHOOT_STEP.store(4, Ordering::Release);
    u64::from(arch::cpu_id())
}

/// TLB shootdown: a CPU that cached a scratch translation sees the new frame after the boot
/// CPU unmaps (shootdown) and remaps the page; the served-request counter moved; frames balance.
fn tlb_shootdown() -> ! {
    if arch::smp::online_count() < 2 {
        fail("fewer than two CPUs online")
    }
    let reader_cpu = (1..arch::smp::MAX_CPUS)
        .find(|c| arch::smp::online_mask() & (1 << c) != 0)
        .unwrap_or(1);
    let (Some(a), Some(b)) = (pmm::alloc_frame(), pmm::alloc_frame()) else {
        fail("no frame")
    };
    let frames0 = pmm::stats().free_frames;
    inject::write_qword(vmm::direct(a.0), 0xAAAA_0000_0000_000A);
    inject::write_qword(vmm::direct(b.0), 0xBBBB_0000_0000_000B);
    if vmm::map_page(SHOOT_PAGE, a.0, paging::WRITE | paging::NX).is_err() {
        fail("map_page failed")
    }
    let served0 = arch::tlb::counters().served;
    let tid = match sched::spawn_on(reader_cpu, shoot_reader, 0, 1) {
        Ok(t) => t,
        Err(_) => fail("spawn_on failed"),
    };
    SHOOT_STEP.store(1, Ordering::Release);
    while SHOOT_STEP.load(Ordering::Acquire) < 2 {
        sched::yield_now();
    }
    // Remap: unmap (local invlpg + shootdown to the reader's CPU), then map frame B.
    let unmapped = vmm::unmap_page(SHOOT_PAGE);
    if vmm::map_page(SHOOT_PAGE, b.0, paging::WRITE | paging::NX).is_err() {
        fail("remap failed")
    }
    SHOOT_STEP.store(3, Ordering::Release);
    while SHOOT_STEP.load(Ordering::Acquire) < 4 {
        sched::yield_now();
    }
    let reader = sched::join(tid);
    let served1 = arch::tlb::counters().served;
    let first = SHOOT_SEEN[0].load(Ordering::Acquire);
    let second = SHOOT_SEEN[1].load(Ordering::Acquire);
    let _ = vmm::unmap_page(SHOOT_PAGE);
    let frames1 = pmm::stats().free_frames;
    let _ = pmm::free_frame(a);
    let _ = pmm::free_frame(b);
    kprintln!(
        "OSX|{}|ktest|tlb_shootdown|reader_cpu={}|reader={:?}|first={:#x}|second={:#x}|unmapped_ok={}|served_before={}|served_after={}|frames_before={}|frames_after={}",
        BUILD_ID,
        reader_cpu,
        reader,
        first,
        second,
        u8::from(matches!(unmapped, Ok(Some(p)) if p == a.0)),
        served0,
        served1,
        frames0,
        frames1
    );
    if reader != Some(reader_cpu as u64) {
        fail("the reader did not run on the chosen CPU")
    }
    if first != 0xAAAA_0000_0000_000A || second != 0xBBBB_0000_0000_000B {
        fail("the reader saw a stale translation after the remap")
    }
    if served1 <= served0 {
        fail("no shootdown request was served")
    }
    if frames0 != frames1 {
        fail("frames leaked")
    }
    pass("a remapped kernel page is seen fresh on another CPU")
}

/// Block I/O under a process address space, which is what every file syscall does: the device
/// registers live in the kernel's MMIO window (`vmm::MMIO_BASE`, a PML4 slot every space
/// shares) and the DMA frames in the direct map, so a sector read with a user CR3 active equals
/// the kernel's and leaves no frame behind. CI run 39110182649: the BAR had been identity-mapped
/// at 0xC0_0000_0000 (PML4 slot 1, the user range) and the first `open` faulted in the kernel.
fn blk_user_cr3() -> ! {
    let Some(info) = crate::block::info() else {
        fail("no virtio-blk device")
    };
    let mut kernel_buf = alloc::vec![0u8; 512];
    let mut user_buf = alloc::vec![0u8; 512];
    let Ok(us) = UserSpace::new() else {
        fail("UserSpace::new failed")
    };
    let frames0 = pmm::stats().free_frames;
    let kernel_read = crate::block::read(0, &mut kernel_buf);
    us.activate();
    let user_active = paging::read_cr3() == us.cr3();
    let user_read = crate::block::read(0, &mut user_buf);
    let user_flush = crate::block::flush();
    addrspace::activate_kernel();
    let frames1 = pmm::stats().free_frames;
    let destroy_ok = us.destroy().is_ok();
    let in_window = (vmm::MMIO_BASE..vmm::MMIO_END).contains(&info.mmio);
    let (ranges, bytes) = vmm::mmio_usage();
    let equal = kernel_buf == user_buf;
    let signature = kernel_buf[510] == 0x55 && kernel_buf[511] == 0xAA;
    kprintln!(
        "OSX|{}|ktest|blk_user_cr3|mmio={:#x}|in_window={}|mmio_ranges={}|mmio_bytes={}|user_active={}|kernel_read={}|user_read={}|user_flush={}|equal={}|signature={}|destroy_ok={}|frames_before={}|frames_after={}",
        BUILD_ID,
        info.mmio,
        u8::from(in_window),
        ranges,
        bytes,
        u8::from(user_active),
        kernel_read.map_or_else(|e| e.code(), |_| "ok"),
        user_read.map_or_else(|e| e.code(), |_| "ok"),
        user_flush.map_or_else(|e| e.code(), |_| "ok"),
        u8::from(equal),
        u8::from(signature),
        u8::from(destroy_ok),
        frames0,
        frames1
    );
    if !in_window {
        fail("device registers are not in the shared MMIO window")
    }
    if !user_active || kernel_read.is_err() || user_read.is_err() || user_flush.is_err() {
        fail("block I/O failed under the user address space")
    }
    if !equal || !signature {
        fail("the sector read under the user CR3 differs from the kernel's")
    }
    if !destroy_ok || frames0 != frames1 {
        fail("frames leaked")
    }
    pass("block I/O works under a process address space (shared MMIO window)")
}

/// Persistence across a QEMU restart on the same image: the write phase stores a tag with the
/// build id and a pattern in sectors 100..=107, flushes, and reads them back; the read phase
/// (a fresh boot) finds the same tag, build id and pattern.
fn blk_persist(write: bool) -> ! {
    let name = if write {
        "blk_persist_write"
    } else {
        "blk_persist_read"
    };
    let mut buf = alloc::vec![0u8; PERSIST_SECTORS * 512];
    let first = crate::block::capacity_sectors().saturating_sub(PERSIST_TAIL);
    if write {
        for (k, b) in buf.iter_mut().enumerate() {
            let sector = first + (k / 512) as u64;
            *b = pattern_byte(sector, k % 512) ^ 0xA5;
        }
        let tag_len = PERSIST_TAG.len() + BUILD_ID.len();
        buf[..PERSIST_TAG.len()].copy_from_slice(PERSIST_TAG);
        buf[PERSIST_TAG.len()..tag_len].copy_from_slice(BUILD_ID.as_bytes());
        let written = crate::block::write(first, &buf);
        let flushed = crate::block::flush();
        if written.is_err() || flushed.is_err() {
            kprintln!(
                "OSX|{}|ktest|{}|written={}|flushed={}",
                BUILD_ID,
                name,
                written.map_or_else(|e| e.code(), |_| "ok"),
                flushed.map_or_else(|e| e.code(), |_| "ok")
            );
            fail("write or flush failed")
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }
    let read = crate::block::read(first, &mut buf);
    let tag_len = PERSIST_TAG.len() + BUILD_ID.len();
    let tag_ok = buf.starts_with(PERSIST_TAG);
    let build_id_match = &buf[PERSIST_TAG.len()..tag_len] == BUILD_ID.as_bytes();
    let mut mismatches = 0u32;
    for (k, b) in buf.iter().enumerate().skip(tag_len) {
        let sector = first + (k / 512) as u64;
        if *b != pattern_byte(sector, k % 512) ^ 0xA5 {
            mismatches += 1;
        }
    }
    let found_id = core::str::from_utf8(&buf[PERSIST_TAG.len()..tag_len]).unwrap_or("?");
    kprintln!(
        "OSX|{}|ktest|{}|sectors={}..{}|read={}|tag_ok={}|build_id_found={}|build_id_match={}|mismatches={}|flushed={}",
        BUILD_ID,
        name,
        first,
        first + PERSIST_SECTORS as u64 - 1,
        read.map_or_else(|e| e.code(), |_| "ok"),
        u8::from(tag_ok),
        found_id,
        u8::from(build_id_match),
        mismatches,
        u8::from(write)
    );
    if read.is_err() || !tag_ok || !build_id_match || mismatches != 0 {
        fail(if write {
            "written sectors do not read back"
        } else {
            "data written before the restart is gone or changed"
        })
    }
    pass(if write {
        "sectors written, flushed and read back"
    } else {
        "sectors written before the QEMU restart are intact"
    })
}

// ---- WP-18 part 2: FAT32 --------------------------------------------------------------------

/// The lab volume (tools/fat32.py): /HELLO.TXT (24 bytes), /PATTERN.BIN (20480 bytes of
/// `(i*31 + (i>>8)) & 0xFF`), /DIR/INNER.TXT (= HELLO.TXT).
const LAB_HELLO: &[u8] = b"hello from the lab disk\n";
const LAB_PATTERN_LEN: usize = 20480;

fn lab_pattern(i: usize) -> u8 {
    ((i * 31 + (i >> 8)) & 0xFF) as u8
}

/// Reading what the host tool wrote: a small file, a multi-cluster file byte for byte (also
/// from an offset), a file in a subdirectory, a listing, and the documented refusals.
fn fat32_read() -> ! {
    let v = match crate::fs::mount() {
        Ok(v) => v,
        Err(e) => {
            kprintln!("OSX|{}|ktest|fat32_read|mount={}", BUILD_ID, e.code());
            fail("volume did not mount")
        }
    };
    let mut small = [0u8; 64];
    let hello = crate::fs::with(|fs| {
        let e = fs.lookup(b"/HELLO.TXT")?;
        Ok((e.size, fs.read(&e, 0, &mut small)?))
    });
    let hello_ok = matches!(hello, Ok((24, 24))) && &small[..24] == LAB_HELLO;
    let mut big = alloc::vec![0u8; LAB_PATTERN_LEN];
    let pattern = crate::fs::with(|fs| {
        let e = fs.lookup(b"/pattern.bin")?; // case-insensitive 8.3 lookup
        let n = fs.read(&e, 0, &mut big)?;
        let mut tail = [0u8; 600];
        let m = fs.read(&e, 20000, &mut tail)?;
        Ok((e.size, n, m, tail))
    });
    let (pattern_ok, tail_ok) = match &pattern {
        Ok((size, n, m, tail)) => (
            *size == LAB_PATTERN_LEN as u32
                && *n == LAB_PATTERN_LEN
                && big.iter().enumerate().all(|(i, b)| *b == lab_pattern(i)),
            *m == 480
                && tail[..480]
                    .iter()
                    .enumerate()
                    .all(|(i, b)| *b == lab_pattern(20000 + i)),
        ),
        Err(_) => (false, false),
    };
    let mut inner = [0u8; 64];
    let inner_ok = crate::fs::with(|fs| {
        let e = fs.lookup(b"/DIR/INNER.TXT")?;
        fs.read(&e, 0, &mut inner)
    })
    .is_ok_and(|n| n == 24 && &inner[..24] == LAB_HELLO);
    let mut names = alloc::string::String::new();
    let listed = crate::fs::with(|fs| {
        fs.list(b"/", |e| {
            // 8.3 display form: base and extension trimmed, joined by a dot.
            names.push_str(core::str::from_utf8(&e.name[..8]).unwrap_or("?").trim_end());
            let ext = core::str::from_utf8(&e.name[8..]).unwrap_or("").trim_end();
            if !ext.is_empty() {
                names.push('.');
                names.push_str(ext);
            }
            names.push(if e.is_dir() { '/' } else { ',' });
        })
    })
    .unwrap_or(0);
    let missing = crate::fs::with(|fs| fs.lookup(b"/NOPE.TXT").map(|_| ())).err();
    let through_file = crate::fs::with(|fs| fs.lookup(b"/HELLO.TXT/X.TXT").map(|_| ())).err();
    let bad_name = crate::fs::with(|fs| fs.lookup(b"/toolongname.txt").map(|_| ())).err();
    let dir_read = crate::fs::with(|fs| {
        let d = fs.lookup(b"/DIR")?;
        fs.read(&d, 0, &mut small)
    })
    .err();
    kprintln!(
        "OSX|{}|ktest|fat32_read|clusters={}|spc={}|hello_ok={}|pattern_ok={}|tail_ok={}|inner_ok={}|listed={}|names={}|missing={}|through_file={}|bad_name={}|dir_read={}",
        BUILD_ID,
        v.clusters,
        v.sectors_per_cluster,
        u8::from(hello_ok),
        u8::from(pattern_ok),
        u8::from(tail_ok),
        u8::from(inner_ok),
        listed,
        names,
        missing.map_or("ok", |e| e.code()),
        through_file.map_or("ok", |e| e.code()),
        bad_name.map_or("ok", |e| e.code()),
        dir_read.map_or("ok", |e| e.code())
    );
    if !(hello_ok && pattern_ok && tail_ok && inner_ok) {
        fail("file contents did not match what the host tool wrote")
    }
    // The host tool writes DIR, SYSTEM (the built applications, WP-23), HELLO.TXT, PATTERN.BIN.
    if listed != 4 {
        fail("root listing wrong")
    }
    if missing != Some(FsError::NotFound)
        || through_file != Some(FsError::NotADirectory)
        || bad_name != Some(FsError::BadName)
        || dir_read != Some(FsError::IsADirectory)
    {
        fail("refusals do not carry the documented codes")
    }
    pass("FAT32 reads the host-written volume exactly and refuses bad paths")
}

/// Create, write across clusters, read back, append, refuse a duplicate, unlink: the free
/// cluster count returns to its start and the host tool can verify the image afterwards.
fn fat32_write() -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let free0 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    let data: Vec<u8> = (0..3000usize).map(|i| lab_pattern(i * 3)).collect();
    let created = crate::fs::with(|fs| {
        let mut e = fs.create(b"/NEW.TXT")?;
        let n1 = fs.write(&mut e, 0, &data)?;
        let n2 = fs.write(&mut e, 3000, b"-tail-")?;
        fs.sync()?;
        Ok((e.size, n1, n2))
    });
    let free1 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    let mut back = alloc::vec![0u8; 3100];
    let read = crate::fs::with(|fs| {
        let e = fs.lookup(b"/NEW.TXT")?;
        Ok((e.size, fs.read(&e, 0, &mut back)?))
    });
    let read_ok = matches!(read, Ok((3006, 3006)))
        && back[..3000] == data[..]
        && &back[3000..3006] == b"-tail-";
    let dup = crate::fs::with(|fs| fs.create(b"/NEW.TXT").map(|_| ())).err();
    let in_dir = crate::fs::with(|fs| {
        let mut e = fs.create(b"/DIR/SECOND.TXT")?;
        fs.write(&mut e, 0, b"second")?;
        let e2 = fs.lookup(b"/dir/second.txt")?;
        let mut b = [0u8; 16];
        let n = fs.read(&e2, 0, &mut b)?;
        Ok(n == 6 && &b[..6] == b"second")
    })
    .unwrap_or(false);
    let overwrite = crate::fs::with(|fs| {
        let mut e = fs.lookup(b"/NEW.TXT")?;
        fs.write(&mut e, 1000, b"XYZ")?;
        let mut b = [0u8; 8];
        let n = fs.read(&e, 998, &mut b)?;
        Ok(n == 8
            && &b[2..5] == b"XYZ"
            && b[0] == data[998]
            && b[5] == data[1003]
            && e.size == 3006)
    })
    .unwrap_or(false);
    let unlinked = crate::fs::with(|fs| {
        let a = fs.unlink(b"/NEW.TXT")?;
        let b = fs.unlink(b"/DIR/SECOND.TXT")?;
        fs.sync()?;
        Ok((a, b))
    });
    let gone = crate::fs::with(|fs| fs.lookup(b"/NEW.TXT").map(|_| ())).err();
    let free2 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    kprintln!(
        "OSX|{}|ktest|fat32_write|created={}|free_before={}|free_during={}|free_after={}|taken_during={}|restored={}|read_ok={}|dup={}|in_dir_ok={}|overwrite_ok={}|unlinked={}|gone={}",
        BUILD_ID,
        created.map_or_else(|e| e.code().into(), |(s, a, b)| alloc::format!("size{}+{}+{}", s, a, b)),
        free0,
        free1,
        free2,
        free0 as i64 - free1 as i64,
        u8::from(free2 == free0),
        u8::from(read_ok),
        dup.map_or("ok", |e| e.code()),
        u8::from(in_dir),
        u8::from(overwrite),
        unlinked.map_or_else(|e| e.code().into(), |(a, b)| alloc::format!("{}+{}", a, b)),
        gone.map_or("ok", |e| e.code())
    );
    if !matches!(created, Ok((3006, 3000, 6))) || !read_ok {
        fail("create/write/read back failed")
    }
    if free0 - free1 != 6 || free2 != free0 {
        fail("cluster accounting wrong (3006 bytes = 6 clusters of 512)")
    }
    if dup != Some(FsError::Exists) || !in_dir || !overwrite {
        fail("duplicate refusal, subdirectory create or overwrite wrong")
    }
    if !matches!(unlinked, Ok((6, 1))) || gone != Some(FsError::NotFound) {
        fail("unlink did not free the chain or the entry")
    }
    pass("FAT32 create/write/overwrite/unlink keep the volume consistent")
}

/// File-level persistence across a QEMU restart: the write phase creates /PERSIST.TXT with the
/// build id (and syncs); the read phase finds it unchanged. The host tool verifies the image
/// after each phase (independent implementation).
fn fat32_persist(write: bool) -> ! {
    let name = if write {
        "fat32_persist_write"
    } else {
        "fat32_persist_read"
    };
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let expected = alloc::format!("NAWAH-FS-PERSIST|{}\n", BUILD_ID);
    if write {
        let r = crate::fs::with(|fs| {
            let mut e = fs.create(b"/PERSIST.TXT")?;
            fs.write(&mut e, 0, expected.as_bytes())?;
            fs.sync()
        });
        if let Err(e) = r {
            kprintln!("OSX|{}|ktest|{}|create={}", BUILD_ID, name, e.code());
            fail("could not create the persistence file")
        }
    }
    let mut buf = [0u8; 64];
    let read = crate::fs::with(|fs| {
        let e = fs.lookup(b"/PERSIST.TXT")?;
        Ok((e.size, fs.read(&e, 0, &mut buf)?))
    });
    let ok = matches!(read, Ok((s, n)) if s as usize == expected.len() && n == expected.len())
        && &buf[..expected.len()] == expected.as_bytes();
    kprintln!(
        "OSX|{}|ktest|{}|size={}|content_ok={}|written={}",
        BUILD_ID,
        name,
        read.map_or(0, |(s, _)| s),
        u8::from(ok),
        u8::from(write)
    );
    if !ok {
        fail(if write {
            "persistence file does not read back"
        } else {
            "persistence file written before the restart is gone or changed"
        })
    }
    pass(if write {
        "persistence file written and synced"
    } else {
        "persistence file survived the QEMU restart"
    })
}

// ---- WP-19: files through system calls ---------------------------------------------------

/// Runs an embedded file-test application and checks its exit code, that no object or handle
/// outlived it and that the frame balance holds.
fn file_app(name: &str, image: &[u8], expected: u64) -> ! {
    if image.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let obj0 = object::stats();
    let (o, _l) = match crate::user::run_elf(image) {
        Ok(r) => r,
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|error={}", BUILD_ID, name, e.code());
            fail("application did not load")
        }
    };
    let obj1 = object::stats();
    kprintln!(
        "OSX|{}|ktest|{}|exit={:#x}|expected={:#x}|frames_delta={}|files_after={}|handles_after={}|channels_after={}",
        BUILD_ID,
        name,
        o.exit_code,
        expected,
        o.frames_delta,
        obj1.files,
        obj1.handles,
        obj1.channels
    );
    if o.exit_code != expected {
        fail("application did not reach its end (exit code = failing step)")
    }
    if o.frames_delta != 0 || obj1 != obj0 {
        fail("frames, objects or handles leaked by the application")
    }
    pass("file application behaved as the files contract says")
}

// ---- WP-23: processes from the volume, waiting, the clock ------------------------------------

/// Runs an embedded application that starts `/SYSTEM/ECHO.ELF` from the volume (the lab image
/// carries every built application there) and checks its exit code and that nothing it or its
/// children created survives: processes, process objects, channels, handles, frames.
fn volume_app(name: &str, image: &[u8], expected: u64) -> ! {
    if image.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let obj0 = object::stats();
    let (o, _l) = match crate::user::run_elf(image) {
        Ok(r) => r,
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|error={}", BUILD_ID, name, e.code());
            fail("application did not load")
        }
    };
    let obj1 = object::stats();
    let st = sched::stats();
    kprintln!(
        "OSX|{}|ktest|{}|exit={:#x}|expected={:#x}|frames_delta={}|processes_after={}|process_objects_after={}|channels_after={}|handles_after={}|files_after={}",
        BUILD_ID,
        name,
        o.exit_code,
        expected,
        o.frames_delta,
        st.processes,
        obj1.processes,
        obj1.channels,
        obj1.handles,
        obj1.files
    );
    if o.exit_code != expected {
        fail("application did not reach its end (exit code = failing step)")
    }
    if o.frames_delta != 0 || obj1 != obj0 || st.processes != 0 {
        fail("frames, objects, handles or process records leaked")
    }
    pass("processes from the volume behaved as the syscall contract v1.4 says")
}

/// The `waiter` application: `object_wait_many` timeouts, polling, refusals and the clock; the
/// exit code carries the measured ticks of a 25-tick wait in its upper bits.
fn wait_timeout() -> ! {
    let image = crate::apps::WAITER;
    if image.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    let obj0 = object::stats();
    let t0 = sched::ticks();
    let (o, _l) = match crate::user::run_elf(image) {
        Ok(r) => r,
        Err(e) => {
            kprintln!("OSX|{}|ktest|wait_timeout|error={}", BUILD_ID, e.code());
            fail("application did not load")
        }
    };
    let elapsed = sched::ticks() - t0;
    let obj1 = object::stats();
    let measured = o.exit_code >> 8;
    kprintln!(
        "OSX|{}|ktest|wait_timeout|exit={:#x}|expected=0x71|measured_ticks={}|elapsed_ticks={}|frames_delta={}|channels_after={}|handles_after={}",
        BUILD_ID,
        o.exit_code & 0xFF,
        measured,
        elapsed,
        o.frames_delta,
        obj1.channels,
        obj1.handles
    );
    if o.exit_code & 0xFF != 0x71 {
        fail("application did not reach its end (exit code = failing step)")
    }
    if measured < 25 || elapsed < measured {
        fail("the wait returned before its timeout")
    }
    if o.frames_delta != 0 || obj1 != obj0 {
        fail("frames, objects or handles leaked by the application")
    }
    pass("object_wait_many times out, polls, refuses bad entries; the clock is monotonic")
}

// ---- WP-24: the service manager -------------------------------------------------------------

/// One line of the manager's `LIST` reply (services.md §3).
#[derive(Clone, Default)]
struct SvcLine {
    name: String,
    state: String,
    restarts: u64,
    first_start: Option<u64>,
    last_start: Option<u64>,
    ready: Option<u64>,
    exit: Option<u64>,
}

fn svc_field(f: Option<&str>) -> Option<u64> {
    f.and_then(|x| x.parse().ok())
}

fn parse_list(reply: &[u8]) -> Vec<SvcLine> {
    core::str::from_utf8(reply)
        .unwrap_or("")
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut f = l.split(' ');
            SvcLine {
                name: f.next().unwrap_or("").into(),
                state: f.next().unwrap_or("").into(),
                restarts: svc_field(f.next()).unwrap_or(u64::MAX),
                first_start: svc_field(f.next()),
                last_start: svc_field(f.next()),
                ready: svc_field(f.next()),
                exit: svc_field(f.next()),
            }
        })
        .collect()
}

/// A manager started for one test with `manifest` loaded: the balance before it, the
/// `LOAD` reply, and a `LIST` poller.
struct SvcHarness {
    name: &'static str,
    m: crate::services::Manager,
    obj0: object::Stats,
    frames0: u64,
    load_reply: String,
}

impl SvcHarness {
    fn start(name: &'static str, manifest: &[u8]) -> Self {
        if crate::fs::mount().is_err() {
            fail("volume did not mount")
        }
        let obj0 = object::stats();
        let frames0 = pmm::stats().free_frames;
        let m = match crate::services::spawn_manager() {
            Ok(m) => m,
            Err(e) => {
                kprintln!("OSX|{}|ktest|{}|spawn_error={}", BUILD_ID, name, e);
                fail("service manager did not start")
            }
        };
        let deadline = sched::ticks() + 500;
        let load_reply = match crate::services::request(
            &m.ctl,
            &crate::services::load_request(manifest),
            deadline,
        ) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => e.into(),
        };
        SvcHarness {
            name,
            m,
            obj0,
            frames0,
            load_reply,
        }
    }

    /// Asks `LIST` every 10 ticks until `done(lines)` holds or `deadline`; the last listing.
    fn poll_list(&self, deadline: u64, mut done: impl FnMut(&[SvcLine]) -> bool) -> Vec<SvcLine> {
        loop {
            let last = match crate::services::request(&self.m.ctl, b"LIST", sched::ticks() + 200) {
                Ok(b) => parse_list(&b),
                Err(e) => {
                    kprintln!("OSX|{}|ktest|{}|list_error={}", BUILD_ID, self.name, e);
                    fail("LIST request failed")
                }
            };
            if done(&last) || sched::ticks() >= deadline {
                return last;
            }
            let t = sched::ticks() + 10;
            sched::poll_until(t, || false);
        }
    }

    fn list_text(lines: &[SvcLine]) -> String {
        let mut s = String::new();
        for l in lines {
            s.push_str(&alloc::format!(
                "{}:{}:{}:{}:{}:{}:{};",
                l.name,
                l.state,
                l.restarts,
                l.first_start.map_or(-1, |x| x as i64),
                l.last_start.map_or(-1, |x| x as i64),
                l.ready.map_or(-1, |x| x as i64),
                l.exit.map_or(-1, |x| x as i64)
            ));
        }
        s
    }

    /// Closes the control channel (the manager exits 0, its services see their channels
    /// close and exit) and waits until no process is left; the object balance afterwards.
    /// Frames are compared by `frames_delta` once the test has dropped its own strings
    /// (heap pages come from the frame allocator: CI run 39128972130 counted them).
    fn finish(self) -> (u64, usize, u64, bool) {
        let SvcHarness {
            m, obj0, frames0, ..
        } = self;
        let object = m.object.clone();
        drop(m);
        let deadline = sched::ticks() + 1000;
        let gone = sched::poll_until(deadline, || sched::stats().processes == 0);
        let code = object.exit_code().unwrap_or(u64::MAX);
        drop(object);
        let obj1 = object::stats();
        (
            code,
            sched::stats().processes,
            frames0,
            gone && obj1 == obj0,
        )
    }

    fn frames_delta(frames0: u64) -> i64 {
        frames0 as i64 - pmm::stats().free_frames as i64
    }
}

/// The last line of a manager test: printed after every allocation of the test is gone.
fn svc_balance(name: &str, frames0: u64) -> ! {
    let delta = SvcHarness::frames_delta(frames0);
    kprintln!("OSX|{}|ktest|{}|frames_delta={}", BUILD_ID, name, delta);
    if delta != 0 {
        fail("frames leaked by the manager or its services")
    }
    match name {
        "svc_order" => {
            pass("services start in dependency order, each after its dependencies are ready")
        }
        "svc_timeout" => pass(
            "a silent service fails at its timeout, its dependent stays blocked, the manager answers",
        ),
        _ => pass("a crashing service is restarted with backoff up to its limit, then given up"),
    }
}

fn svc_order() -> ! {
    let h = SvcHarness::start("svc_order", b"/SYSTEM/SVC-ORD.TXT");
    let lines = h.poll_list(sched::ticks() + 1000, |l| {
        l.len() == 3 && l.iter().all(|x| x.state == "ready")
    });
    let get = |n: &str| {
        lines
            .iter()
            .find(|l| l.name == n)
            .cloned()
            .unwrap_or_default()
    };
    let (a, b, c) = (get("A"), get("B"), get("C"));
    let all_ready = [&a, &b, &c].iter().all(|l| l.state == "ready");
    let b_after_a = b.first_start >= a.ready && a.ready.is_some();
    let c_after_ab = c.first_start >= a.ready.max(b.ready) && b.ready.is_some();
    let text = SvcHarness::list_text(&lines);
    let load = h.load_reply.clone();
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|svc_order|load={}|list={}|all_ready={}|b_after_a={}|c_after_ab={}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        load,
        text,
        u8::from(all_ready),
        u8::from(b_after_a),
        u8::from(c_after_ab),
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 3" || !all_ready {
        fail("manifest not loaded or services not ready")
    }
    if !b_after_a || !c_after_ab {
        fail("a dependent started before its dependency was ready")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    drop((lines, a, b, c, text, load));
    svc_balance("svc_order", frames0)
}

fn svc_timeout() -> ! {
    let h = SvcHarness::start("svc_timeout", b"/SYSTEM/SVC-TMO.TXT");
    let lines = h.poll_list(sched::ticks() + 1000, |l| {
        l.iter().any(|x| x.name == "M" && x.state == "failed")
    });
    let get = |n: &str| {
        lines
            .iter()
            .find(|l| l.name == n)
            .cloned()
            .unwrap_or_default()
    };
    let (m, d) = (get("M"), get("D"));
    let failed_after_timeout = m.state == "failed" && m.ready.is_none();
    let dependent_blocked = d.state == "blocked" && d.first_start.is_none();
    // The manager still answers after the failure.
    let again = crate::services::request(&h.m.ctl, b"LIST", sched::ticks() + 200).is_ok();
    let text = SvcHarness::list_text(&lines);
    let load = h.load_reply.clone();
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|svc_timeout|load={}|list={}|failed_after_timeout={}|dependent_blocked={}|list_after={}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        load,
        text,
        u8::from(failed_after_timeout),
        u8::from(dependent_blocked),
        u8::from(again),
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 2" || !failed_after_timeout || !dependent_blocked || !again {
        fail("timeout handling wrong")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    drop((lines, m, d, text, load));
    svc_balance("svc_timeout", frames0)
}

fn svc_restart() -> ! {
    let h = SvcHarness::start("svc_restart", b"/SYSTEM/SVC-RST.TXT");
    let t0 = sched::ticks();
    let lines = h.poll_list(sched::ticks() + 1000, |l| {
        l.iter().any(|x| x.name == "X" && x.state == "given_up")
    });
    let x = lines
        .iter()
        .find(|l| l.name == "X")
        .cloned()
        .unwrap_or_default();
    // Backoff 10, 20, 40 between the four starts: at least 70 ticks from first to last.
    let span = x
        .last_start
        .unwrap_or(0)
        .saturating_sub(x.first_start.unwrap_or(u64::MAX));
    let backoff_ok = span >= 70;
    let elapsed = sched::ticks() - t0;
    let again = crate::services::request(&h.m.ctl, b"LIST", sched::ticks() + 200).is_ok();
    let text = SvcHarness::list_text(&lines);
    let load = h.load_reply.clone();
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|svc_restart|load={}|list={}|state={}|restarts={}|exit={}|span={}|backoff_ok={}|elapsed={}|list_after={}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        load,
        text,
        x.state,
        x.restarts,
        x.exit.map_or(-1, |e| e as i64),
        span,
        u8::from(backoff_ok),
        elapsed,
        u8::from(again),
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 1" || x.state != "given_up" || x.restarts != 3 || x.exit != Some(1) {
        fail("restart policy wrong")
    }
    if !backoff_ok || !again {
        fail("backoff too short or the manager stopped answering")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    drop((lines, x, text, load));
    svc_balance("svc_restart", frames0)
}

// ---- WP-25: tokens, authority, the auth service --------------------------------------------

/// Tokens and the authority (auth.md §1–§2) through the syscall layer's rules, exercised on
/// kernel objects: minting needs an authority, `token_info` reports identity and flags, a copy
/// without WRITE cannot revoke, revocation shows through every copy, expiry follows the clock.
fn token_objects() -> ! {
    use crate::object::token::{Authority, Token, FLAG_EXPIRED, FLAG_REVOKED, PERM_ADMIN};
    let obj0 = object::stats();
    let authority = Arc::new(Authority::new());
    let now = sched::ticks();
    let t = Arc::new(Token::new(1000, 1000, PERM_ADMIN, now + 5));
    let copy = t.clone();
    let distinct_ids = t.id != Token::new(1, 1, 0, 0).id;
    let fresh = t.flags(now) == 0 && copy.flags(now) == 0;
    // A handle table: the minter's entry (WRITE) and a client copy (no WRITE); revocation is
    // gated by the WRITE right of the handle used, as sys_token_revoke does.
    let mut table = HandleTable::new();
    let minter = table
        .insert(Entry {
            object: Object::Token(t.clone()),
            rights: Rights::TOKEN_MINTER,
        })
        .unwrap_or(0);
    let client = table
        .duplicate(minter, Rights(Rights::DUPLICATE.0 | Rights::TRANSFER.0))
        .unwrap_or(0);
    let client_cannot_revoke = !table
        .get(client, Rights::NONE)
        .map(|e| e.rights.contains(Rights::WRITE))
        .unwrap_or(true);
    let authority_entry = table
        .insert(Entry {
            object: Object::Authority(authority.clone()),
            rights: Rights::AUTHORITY_DEFAULT,
        })
        .unwrap_or(0);
    let is_authority = matches!(
        table.get(authority_entry, Rights::NONE).map(|e| &e.object),
        Ok(Object::Authority(_))
    );
    let channel_is_not_authority = {
        let (a, _b) = channel::create();
        let h = table
            .insert(Entry {
                object: Object::Channel(a),
                rights: Rights::CHANNEL_DEFAULT,
            })
            .unwrap_or(0);
        !matches!(
            table.get(h, Rights::NONE).map(|e| &e.object),
            Ok(Object::Authority(_))
        )
    };
    t.revoke();
    let revoked_everywhere = copy.flags(now) & FLAG_REVOKED != 0;
    let expires_later =
        t.flags(now + 5) & FLAG_EXPIRED != 0 && t.flags(now + 4) & FLAG_EXPIRED == 0;
    let live_tokens = object::stats().tokens;
    drop(table);
    drop(copy);
    drop(t);
    drop(authority);
    let obj1 = object::stats();
    kprintln!(
        "OSX|{}|ktest|token_objects|distinct_ids={}|fresh={}|client_cannot_revoke={}|is_authority={}|channel_is_not_authority={}|revoked_everywhere={}|expires_later={}|live_tokens={}|tokens_after={}|authorities_after={}",
        BUILD_ID,
        u8::from(distinct_ids),
        u8::from(fresh),
        u8::from(client_cannot_revoke),
        u8::from(is_authority),
        u8::from(channel_is_not_authority),
        u8::from(revoked_everywhere),
        u8::from(expires_later),
        live_tokens,
        obj1.tokens,
        obj1.authorities
    );
    if !(distinct_ids && fresh && client_cannot_revoke && is_authority && channel_is_not_authority)
    {
        fail("token minting, identity or rights wrong")
    }
    if !revoked_everywhere || !expires_later || live_tokens != 1 {
        fail("revocation, expiry or accounting wrong")
    }
    if obj1 != obj0 {
        fail("token or authority objects leaked")
    }
    pass(
        "tokens carry identity, expire by the clock, revoke through every copy; only WRITE revokes",
    )
}

/// Starts the `auth` service through a manager and connects to it; the client endpoint.
fn auth_connect(h: &SvcHarness) -> Arc<Endpoint> {
    // The service runs the 80000-iteration known answer before READY: generous deadline.
    let lines = h.poll_list(sched::ticks() + 60_000, |l| {
        l.iter()
            .any(|x| x.name == "auth" && x.state != "starting" && x.state != "pending")
    });
    let state = lines
        .iter()
        .find(|l| l.name == "auth")
        .map(|l| l.state.clone())
        .unwrap_or_default();
    if state != "ready" {
        kprintln!("OSX|{}|ktest|{}|auth_state={}", BUILD_ID, h.name, state);
        fail("auth service did not become ready")
    }
    match crate::services::request_with(&h.m.ctl, b"CONNECT auth", Vec::new(), sched::ticks() + 500)
    {
        Ok(m) if m.bytes == b"OK" && m.handles.len() == 1 => match &m.handles[0].object {
            Object::Channel(ep) => ep.clone(),
            _ => fail("CONNECT answered with a non-channel handle"),
        },
        Ok(m) => {
            kprintln!(
                "OSX|{}|ktest|{}|connect_reply={}|handles={}",
                BUILD_ID,
                h.name,
                String::from_utf8_lossy(&m.bytes),
                m.handles.len()
            );
            fail("CONNECT refused")
        }
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|connect_error={}", BUILD_ID, h.name, e);
            fail("CONNECT failed")
        }
    }
}

/// One request to the auth service, with an optional token; the reply text and token.
fn auth_request(
    ep: &Endpoint,
    req: &[u8],
    token: Option<&Arc<crate::object::token::Token>>,
) -> (String, Option<Arc<crate::object::token::Token>>) {
    let handles = match token {
        Some(t) => alloc::vec![Entry {
            object: Object::Token(t.clone()),
            rights: Rights(Rights::DUPLICATE.0 | Rights::TRANSFER.0),
        }],
        None => Vec::new(),
    };
    match crate::services::request_with(ep, req, handles, sched::ticks() + 30_000) {
        Ok(m) => {
            let text = String::from_utf8_lossy(&m.bytes).into_owned();
            let tok = m.handles.into_iter().find_map(|e| match e.object {
                Object::Token(t) => Some(t),
                _ => None,
            });
            (text, tok)
        }
        Err(e) => (alloc::format!("error:{}", e), None),
    }
}

fn login() -> ! {
    use crate::object::token::PERM_ALL;
    let h = SvcHarness::start("login", b"/SYSTEM/SVC-AUTH.TXT");
    let ep = auth_connect(&h);
    let now = sched::ticks();
    // Right password: a usable token with the user's identity and permissions.
    let (r1, t1) = auth_request(&ep, b"LOGIN admin lab-admin-1", None);
    let token_ok = t1.as_ref().is_some_and(|t| {
        t.uid == 1000 && t.perms == PERM_ALL && t.flags(now) == 0 && t.expires > now
    });
    let (r_user, t_user) = auth_request(&ep, b"LOGIN user lab-user-1", None);
    let user_ok = t_user
        .as_ref()
        .is_some_and(|t| t.uid == 1001 && t.perms == 8);
    // Wrong password and unknown name: the same refusal, no token.
    let (r2, t2) = auth_request(&ep, b"LOGIN admin wrong-password", None);
    let (r3, t3) = auth_request(&ep, b"LOGIN nobody lab-admin-1", None);
    // Four more failures reach the limit; the right password is then delayed.
    let mut refused = 0;
    for _ in 0..4 {
        if auth_request(&ep, b"LOGIN admin wrong-password", None).0 == "ERR ACCESS" {
            refused += 1;
        }
    }
    let (r_delayed, t_delayed) = auth_request(&ep, b"LOGIN admin lab-admin-1", None);
    let delayed = r_delayed.starts_with("ERR DELAYED ") && t_delayed.is_none();
    // The other user is not delayed.
    let (r_other, t_other) = auth_request(&ep, b"LOGIN user lab-user-1", None);
    // After the delay the right password works again.
    let t = sched::ticks() + 2100;
    sched::poll_until(t, || false);
    let (r_after, t_after) = auth_request(&ep, b"LOGIN admin lab-admin-1", None);
    let whoami = match &t_after {
        Some(tk) => auth_request(&ep, b"WHOAMI", Some(tk)).0,
        None => String::new(),
    };
    let bad = auth_request(&ep, b"WHATEVER", None).0;
    let load = h.load_reply.clone();
    // Tokens are objects: release them before the balance is taken.
    let no_token = t2.is_none() && t3.is_none();
    let other_ok = t_other.is_some();
    drop((ep, t1, t_user, t2, t3, t_delayed, t_other, t_after));
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|login|load={}|login={}|token_ok={}|user={}|user_ok={}|wrong={}|unknown={}|no_token={}|refused={}|delayed={}|other={}|after_delay={}|whoami={}|bad={}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        load,
        r1,
        u8::from(token_ok),
        r_user,
        u8::from(user_ok),
        r2,
        r3,
        u8::from(no_token),
        refused,
        delayed,
        r_other,
        r_after,
        whoami,
        bad,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if r1 != "OK 1000 1000 15" || !token_ok || r_user != "OK 1001 1001 8" || !user_ok {
        fail("login with the right password did not give the user's token")
    }
    if r2 != "ERR ACCESS" || r3 != "ERR ACCESS" || !no_token || refused != 4 {
        fail("wrong credentials were not refused the documented way")
    }
    if !delayed || r_other != "OK 1001 1001 8" || !other_ok {
        fail("the attempt limit did not delay the right name only")
    }
    if r_after != "OK 1000 1000 15" || whoami != "OK 1000 1000 15" || bad != "ERR BAD_REQUEST" {
        fail("login after the delay, WHOAMI or the bad request answer wrong")
    }
    drop((
        r1, r_user, r2, r3, r_delayed, r_other, r_after, whoami, bad, load,
    ));
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    let delta = SvcHarness::frames_delta(frames0);
    kprintln!("OSX|{}|ktest|login|frames_delta={}", BUILD_ID, delta);
    if delta != 0 {
        fail("frames leaked")
    }
    pass("login gives a session token, refuses bad credentials, delays after 5 failures")
}

fn session_lock() -> ! {
    let h = SvcHarness::start("session_lock", b"/SYSTEM/SVC-AUTH.TXT");
    let ep = auth_connect(&h);
    let (r1, t1) = auth_request(&ep, b"LOGIN admin lab-admin-1", None);
    let Some(t1) = t1 else { fail("login failed") };
    let id1 = t1.id;
    let (lock, _) = auth_request(&ep, b"LOCK", Some(&t1));
    let locked_token_revoked = t1.flags(sched::ticks()) & crate::object::token::FLAG_REVOKED != 0;
    let (whoami_locked, _) = auth_request(&ep, b"WHOAMI", Some(&t1));
    let (unlock_wrong, _) = auth_request(&ep, b"UNLOCK wrong-password", Some(&t1));
    let (unlock, t2) = auth_request(&ep, b"UNLOCK lab-admin-1", Some(&t1));
    let new_token = t2
        .as_ref()
        .is_some_and(|t| t.uid == 1000 && t.id != id1 && t.flags(sched::ticks()) == 0);
    let (whoami_new, _) = match &t2 {
        Some(t) => auth_request(&ep, b"WHOAMI", Some(t)),
        None => (String::new(), None),
    };
    let (old_after_unlock, _) = auth_request(&ep, b"WHOAMI", Some(&t1));
    let (logout, _) = match &t2 {
        Some(t) => auth_request(&ep, b"LOGOUT", Some(t)),
        None => (String::new(), None),
    };
    // LOGOUT revokes the token itself (auth.md §2), not only the service's session record:
    // every other service judging it by `token_info` must see it dead (WP-31, mutant M70).
    let logged_out_revoked = t2
        .as_ref()
        .is_some_and(|t| t.flags(sched::ticks()) & crate::object::token::FLAG_REVOKED != 0);
    let (whoami_out, _) = match &t2 {
        Some(t) => auth_request(&ep, b"WHOAMI", Some(t)),
        None => (String::new(), None),
    };
    let (unlock_out, t3) = match &t2 {
        Some(t) => auth_request(&ep, b"UNLOCK lab-admin-1", Some(t)),
        None => (String::new(), None),
    };
    let (no_handle, _) = auth_request(&ep, b"WHOAMI", None);
    let load = h.load_reply.clone();
    let no_third = t3.is_none();
    drop((ep, t1, t2, t3));
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|session_lock|load={}|login={}|lock={}|locked_token_revoked={}|whoami_locked={}|unlock_wrong={}|unlock={}|new_token={}|whoami_new={}|old_after_unlock={}|logout={}|logged_out_revoked={}|whoami_out={}|unlock_out={}|no_handle={}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        load,
        r1,
        lock,
        u8::from(locked_token_revoked),
        whoami_locked,
        unlock_wrong,
        unlock,
        u8::from(new_token),
        whoami_new,
        old_after_unlock,
        logout,
        u8::from(logged_out_revoked),
        whoami_out,
        unlock_out,
        no_handle,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if r1 != "OK 1000 1000 15"
        || lock != "OK"
        || !locked_token_revoked
        || whoami_locked != "ERR ACCESS"
    {
        fail("lock did not revoke the token")
    }
    if unlock_wrong != "ERR ACCESS"
        || unlock != "OK 1000 1000 15"
        || !new_token
        || whoami_new != "OK 1000 1000 15"
        || old_after_unlock != "ERR ACCESS"
    {
        fail("unlock did not continue the session with a new token")
    }
    if logout != "OK"
        || !logged_out_revoked
        || whoami_out != "ERR ACCESS"
        || unlock_out != "ERR ACCESS"
        || !no_third
        || no_handle != "ERR BAD_REQUEST"
    {
        fail("logout did not end the session")
    }
    drop((
        r1,
        lock,
        whoami_locked,
        unlock_wrong,
        unlock,
        whoami_new,
        old_after_unlock,
        logout,
        whoami_out,
        unlock_out,
        no_handle,
        load,
    ));
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    let delta = SvcHarness::frames_delta(frames0);
    kprintln!("OSX|{}|ktest|session_lock|frames_delta={}", BUILD_ID, delta);
    if delta != 0 {
        fail("frames leaked")
    }
    pass("lock revokes, unlock with the password continues the session, logout ends it")
}

// ---- WP-26: the config service ---------------------------------------------------------------

/// Waits until every named service is `ready` (fails on any other final state).
fn svc_wait_ready(h: &SvcHarness, names: &[&str], deadline: u64) {
    let lines = h.poll_list(deadline, |l| {
        names.iter().all(|n| {
            l.iter()
                .any(|x| x.name == *n && x.state != "starting" && x.state != "pending")
        })
    });
    for n in names {
        let state = lines
            .iter()
            .find(|l| l.name == *n)
            .map(|l| l.state.clone())
            .unwrap_or_default();
        if state != "ready" {
            kprintln!(
                "OSX|{}|ktest|{}|service={}|state={}",
                BUILD_ID,
                h.name,
                n,
                state
            );
            fail("a service did not become ready")
        }
    }
}

/// `CONNECT <name>`: the client endpoint.
fn svc_connect(h: &SvcHarness, name: &str) -> Arc<Endpoint> {
    let req = alloc::format!("CONNECT {}", name);
    match crate::services::request_with(&h.m.ctl, req.as_bytes(), Vec::new(), sched::ticks() + 500)
    {
        Ok(m) if m.bytes == b"OK" && m.handles.len() == 1 => match &m.handles[0].object {
            Object::Channel(ep) => ep.clone(),
            _ => fail("CONNECT answered with a non-channel handle"),
        },
        Ok(m) => {
            kprintln!(
                "OSX|{}|ktest|{}|connect={}|reply={}",
                BUILD_ID,
                h.name,
                name,
                String::from_utf8_lossy(&m.bytes)
            );
            fail("CONNECT refused")
        }
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|connect_error={}", BUILD_ID, h.name, e);
            fail("CONNECT failed")
        }
    }
}

/// The config tests' setting: manager with auth + config, both connected, admin and user
/// tokens from real logins.
struct CfgEnv {
    h: SvcHarness,
    cfg: Arc<Endpoint>,
    admin: Arc<crate::object::token::Token>,
    user: Arc<crate::object::token::Token>,
}

fn cfg_env(name: &'static str) -> CfgEnv {
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-CFG.TXT");
    svc_wait_ready(&h, &["auth", "config"], sched::ticks() + 60_000);
    let auth = svc_connect(&h, "auth");
    let (ra, admin) = auth_request(&auth, b"LOGIN admin lab-admin-1", None);
    let (ru, user) = auth_request(&auth, b"LOGIN user lab-user-1", None);
    let (Some(admin), Some(user)) = (admin, user) else {
        kprintln!("OSX|{}|ktest|{}|admin={}|user={}", BUILD_ID, name, ra, ru);
        fail("logins failed")
    };
    drop(auth);
    let cfg = svc_connect(&h, "config");
    CfgEnv {
        h,
        cfg,
        admin,
        user,
    }
}

/// One config request with an optional token or channel handle; the reply text.
fn cfg_request(ep: &Endpoint, req: &[u8], handle: Option<Entry>) -> String {
    let handles = handle.map_or_else(Vec::new, |e| alloc::vec![e]);
    match crate::services::request_with(ep, req, handles, sched::ticks() + 30_000) {
        Ok(m) => String::from_utf8_lossy(&m.bytes).into_owned(),
        Err(e) => alloc::format!("error:{}", e),
    }
}

fn token_entry(t: &Arc<crate::object::token::Token>) -> Entry {
    Entry {
        object: Object::Token(t.clone()),
        rights: Rights(Rights::DUPLICATE.0 | Rights::TRANSFER.0),
    }
}

/// Closes a config test's manager and services and checks the object balance; the frame
/// baseline comes back for `cfg_balance`, which the test calls once its own strings are gone
/// (the test body lives in a block so they drop before the frames are counted).
fn cfg_close(env: CfgEnv, name: &str) -> u64 {
    let CfgEnv {
        h,
        cfg,
        admin,
        user,
    } = env;
    drop((cfg, admin, user));
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|{}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        name,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    frames0
}

fn cfg_balance(name: &str, frames0: u64, pass_msg: &str) -> ! {
    let delta = SvcHarness::frames_delta(frames0);
    kprintln!("OSX|{}|ktest|{}|frames_delta={}", BUILD_ID, name, delta);
    if delta != 0 {
        fail("frames leaked")
    }
    pass(pass_msg)
}

/// REQ-M4-004: the config service itself refuses a write whose token lacks the permission.
fn authz_denied() -> ! {
    let env = cfg_env("authz_denied");
    let frames0 = {
        let ep = &env.cfg;
        let denied = cfg_request(
            ep,
            b"SET device lab.key 0 101 user-tried",
            Some(token_entry(&env.user)),
        );
        let unchanged = cfg_request(ep, b"GET device lab.key", None);
        let no_handle = cfg_request(ep, b"SET device lab.key 0 102 nobody", None);
        let allowed = cfg_request(
            ep,
            b"SET device lab.key 0 103 admin-set",
            Some(token_entry(&env.admin)),
        );
        let now = cfg_request(ep, b"GET device lab.key", None);
        // The user may write its own store but not another user's, nor the policy.
        let own = cfg_request(
            ep,
            b"SET user/1001 theme 0 104 dark",
            Some(token_entry(&env.user)),
        );
        let other = cfg_request(
            ep,
            b"SET user/1000 theme 0 105 dark",
            Some(token_entry(&env.user)),
        );
        let policy_user = cfg_request(
            ep,
            b"SET policy lab.key 0 106 forced",
            Some(token_entry(&env.user)),
        );
        // A revoked token is refused even with every permission.
        env.admin.revoke();
        let revoked = cfg_request(
            ep,
            b"SET device lab.key 1 107 after-revoke",
            Some(token_entry(&env.admin)),
        );
        let still = cfg_request(ep, b"GET device lab.key", None);
        kprintln!(
            "OSX|{}|ktest|authz_denied|denied={}|unchanged={}|no_handle={}|allowed={}|now={}|own={}|other={}|policy_user={}|revoked={}|still={}",
            BUILD_ID,
            denied,
            unchanged,
            no_handle,
            allowed,
            now,
            own,
            other,
            policy_user,
            revoked,
            still
        );
        if denied != "ERR ACCESS" || unchanged != "ERR NOT_FOUND" || no_handle != "ERR BAD_REQUEST"
        {
            fail("a write without the permission was not refused at the authority layer")
        }
        if allowed != "OK 1"
            || now != "OK 1 admin-set"
            || own != "OK 1"
            || other != "ERR ACCESS"
            || policy_user != "ERR ACCESS"
        {
            fail("the permitted writes or the user-store rules are wrong")
        }
        if revoked != "ERR ACCESS" || still != "OK 1 admin-set" {
            fail("a revoked token was accepted")
        }
        cfg_close(env, "authz_denied")
    };
    cfg_balance(
        "authz_denied",
        frames0,
        "the config service refuses writes whose token lacks the permission",
    )
}

fn config_cas() -> ! {
    let env = cfg_env("config_cas");
    let frames0 = {
        let ep = &env.cfg;
        let a = token_entry(&env.admin);
        let first = cfg_request(ep, b"SET device cas.key 0 201 one", Some(a.clone()));
        let read1 = cfg_request(ep, b"GET device cas.key", None);
        // Two writers read version 1 and both try to replace it: the second loses.
        let w1 = cfg_request(ep, b"SET device cas.key 1 202 two", Some(a.clone()));
        let w2 = cfg_request(ep, b"SET device cas.key 1 203 three", Some(a.clone()));
        let read2 = cfg_request(ep, b"GET device cas.key", None);
        let create_existing = cfg_request(ep, b"SET device cas.key 0 204 four", Some(a.clone()));
        let del_wrong = cfg_request(ep, b"DEL device cas.key 1 205", Some(a.clone()));
        let del = cfg_request(ep, b"DEL device cas.key 2 206", Some(a.clone()));
        let gone = cfg_request(ep, b"GET device cas.key", None);
        let recreate = cfg_request(ep, b"SET device cas.key 0 207 five", Some(a.clone()));
        let bad_key = cfg_request(ep, b"SET device Bad/Key 0 208 x", Some(a));
        kprintln!(
            "OSX|{}|ktest|config_cas|first={}|read1={}|w1={}|w2={}|read2={}|create_existing={}|del_wrong={}|del={}|gone={}|recreate={}|bad_key={}",
            BUILD_ID, first, read1, w1, w2, read2, create_existing, del_wrong, del, gone, recreate, bad_key
        );
        if first != "OK 1"
            || read1 != "OK 1 one"
            || w1 != "OK 2"
            || w2 != "ERR VERSION 2"
            || read2 != "OK 2 two"
        {
            fail("compare-and-set did not refuse the stale writer")
        }
        if create_existing != "ERR VERSION 2"
            || del_wrong != "ERR VERSION 2"
            || del != "OK 2"
            || gone != "ERR NOT_FOUND"
            || recreate != "OK 1"
            || bad_key != "ERR INVALID"
        {
            fail("create/delete versioning wrong")
        }
        cfg_close(env, "config_cas")
    };
    cfg_balance(
        "config_cas",
        frames0,
        "compare-and-set keeps the first writer's value and refuses the stale one",
    )
}

fn config_retry() -> ! {
    let env = cfg_env("config_retry");
    let frames0 = {
        let ep = &env.cfg;
        let a = token_entry(&env.admin);
        let r1 = cfg_request(ep, b"SET device retry.key 0 301 v1", Some(a.clone()));
        let r1b = cfg_request(ep, b"SET device retry.key 0 301 v1", Some(a.clone()));
        let read = cfg_request(ep, b"GET device retry.key", None);
        // A refused request is replayed as refused too.
        let bad = cfg_request(ep, b"SET device retry.key 0 302 v2", Some(a.clone()));
        let bad_again = cfg_request(ep, b"SET device retry.key 1 302 v2", Some(a.clone()));
        let read2 = cfg_request(ep, b"GET device retry.key", None);
        // Id 0 is never cached: the second call is a real (now stale) attempt.
        let z1 = cfg_request(ep, b"SET device retry.key 1 0 v3", Some(a.clone()));
        let z2 = cfg_request(ep, b"SET device retry.key 1 0 v3", Some(a));
        let read3 = cfg_request(ep, b"GET device retry.key", None);
        kprintln!(
            "OSX|{}|ktest|config_retry|r1={}|r1b={}|read={}|bad={}|bad_again={}|read2={}|z1={}|z2={}|read3={}",
            BUILD_ID, r1, r1b, read, bad, bad_again, read2, z1, z2, read3
        );
        if r1 != "OK 1" || r1b != "OK 1" || read != "OK 1 v1" {
            fail("a repeated request id was applied twice or answered differently")
        }
        if bad != "ERR VERSION 1" || bad_again != "ERR VERSION 1" || read2 != "OK 1 v1" {
            fail("a refused request was not replayed as refused")
        }
        if z1 != "OK 2" || z2 != "ERR VERSION 2" || read3 != "OK 2 v3" {
            fail("request id 0 was cached")
        }
        cfg_close(env, "config_retry")
    };
    cfg_balance(
        "config_retry",
        frames0,
        "a repeated request id applies once and replays its stored reply",
    )
}

fn config_notify() -> ! {
    let env = cfg_env("config_notify");
    let frames0 = {
        let ep = &env.cfg;
        let a = token_entry(&env.admin);
        let (sub_k, sub_s) = channel::create();
        let sub = cfg_request(
            ep,
            b"SUBSCRIBE device",
            Some(Entry {
                object: Object::Channel(sub_s),
                rights: Rights::CHANNEL_DEFAULT,
            }),
        );
        let set = cfg_request(ep, b"SET device note.key 0 401 first", Some(a.clone()));
        let n1 = recv_text(&sub_k, 500);
        let refused = cfg_request(ep, b"SET device note.key 0 402 second", Some(a.clone()));
        let n2 = recv_text(&sub_k, 50);
        let set2 = cfg_request(ep, b"SET device note.key 1 403 third", Some(a.clone()));
        let n3 = recv_text(&sub_k, 500);
        let other_store = cfg_request(ep, b"SET policy note.key 0 404 pol", Some(a.clone()));
        let n4 = recv_text(&sub_k, 50);
        let del = cfg_request(ep, b"DEL device note.key 2 405", Some(a));
        let n5 = recv_text(&sub_k, 500);
        kprintln!(
            "OSX|{}|ktest|config_notify|sub={}|set={}|n1={}|refused={}|n2={}|set2={}|n3={}|other_store={}|n4={}|del={}|n5={}",
            BUILD_ID, sub, set, n1, refused, n2, set2, n3, other_store, n4, del, n5
        );
        if sub != "OK" || set != "OK 1" || n1 != "CHANGED device note.key 1" {
            fail("no notification for a successful write")
        }
        if refused != "ERR VERSION 1" || n2 != "-" || other_store != "OK 1" || n4 != "-" {
            fail("a notification arrived for a refused write or another store")
        }
        if set2 != "OK 2"
            || n3 != "CHANGED device note.key 2"
            || del != "OK 2"
            || n5 != "CHANGED device note.key 0"
        {
            fail("later notifications wrong")
        }
        drop(sub_k);
        cfg_close(env, "config_notify")
    };
    cfg_balance(
        "config_notify",
        frames0,
        "subscribers hear every successful change of their store and nothing else",
    )
}

/// Reads one message from `ep` within `ticks`, or "-".
fn recv_text(ep: &Endpoint, ticks: u64) -> String {
    let mut got: Option<Vec<u8>> = None;
    sched::poll_until(sched::ticks() + ticks, || match ep.read(4096, 4, None) {
        Ok(m) => {
            got = Some(m.bytes);
            true
        }
        Err(ChannelError::ShouldWait) => false,
        Err(_) => true,
    });
    got.map_or_else(|| "-".into(), |b| String::from_utf8_lossy(&b).into_owned())
}

fn policy_precedence() -> ! {
    let env = cfg_env("policy_precedence");
    let frames0 = {
        let ep = &env.cfg;
        let a = token_entry(&env.admin);
        let u = token_entry(&env.user);
        let none = cfg_request(ep, b"RESOLVE ui.theme", Some(u.clone()));
        let dev = cfg_request(ep, b"SET device ui.theme 0 501 light", Some(a.clone()));
        let r_dev = cfg_request(ep, b"RESOLVE ui.theme", Some(u.clone()));
        let usr = cfg_request(ep, b"SET user/1001 ui.theme 0 502 dark", Some(u.clone()));
        let r_usr = cfg_request(ep, b"RESOLVE ui.theme", Some(u.clone()));
        let r_admin = cfg_request(ep, b"RESOLVE ui.theme", Some(a.clone()));
        let pol = cfg_request(ep, b"SET policy ui.theme 0 503 corporate", Some(a.clone()));
        let r_pol = cfg_request(ep, b"RESOLVE ui.theme", Some(u.clone()));
        let del_pol = cfg_request(ep, b"DEL policy ui.theme 1 504", Some(a.clone()));
        let r_back = cfg_request(ep, b"RESOLVE ui.theme", Some(u.clone()));
        let export = cfg_request(ep, b"EXPORT user/1001", None);
        let import = cfg_request(
            ep,
            b"IMPORT user/1001 505
    ui.font mono
    ui.size 14",
            Some(u.clone()),
        );
        let imported = cfg_request(ep, b"GET user/1001 ui.size", None);
        let import_bad = cfg_request(
            ep,
            b"IMPORT user/1001 506
    ui.ok yes
    BAD KEY x",
            Some(u),
        );
        let not_applied = cfg_request(ep, b"GET user/1001 ui.ok", None);
        kprintln!(
            "OSX|{}|ktest|policy_precedence|none={}|dev={}|r_dev={}|usr={}|r_usr={}|r_admin={}|pol={}|r_pol={}|del_pol={}|r_back={}|export={}|import={}|imported={}|import_bad={}|not_applied={}",
            BUILD_ID, none, dev, r_dev, usr, r_usr, r_admin, pol, r_pol, del_pol, r_back,
            export.replace('\n', ";"), import, imported, import_bad, not_applied
        );
        if none != "ERR NOT_FOUND" || dev != "OK 1" || r_dev != "OK device 1 light" {
            fail("device default not resolved")
        }
        if usr != "OK 1" || r_usr != "OK user 1 dark" || r_admin != "OK device 1 light" {
            fail("user value does not take precedence over the device default for its user only")
        }
        if pol != "OK 1"
            || r_pol != "OK policy 1 corporate"
            || del_pol != "OK 1"
            || r_back != "OK user 1 dark"
        {
            fail("policy precedence or its removal wrong")
        }
        if export != "OK\nui.theme 1 dark"
            || import != "OK 2"
            || imported != "OK 1 14"
            || import_bad != "ERR INVALID 2"
            || not_applied != "ERR NOT_FOUND"
        {
            fail("export/import wrong")
        }
        // The entries hold token objects: release them before the balance.
        drop(a);
        cfg_close(env, "policy_precedence")
    };
    cfg_balance("policy_precedence", frames0, "policy beats the user value, which beats the device default; removing the policy restores the user value")
}

/// Two phases on one image: phase 1 writes a device value through the service; phase 2 (a
/// fresh boot) reads it back with the same version from the adopted slot.
fn config_persist(write: bool) -> ! {
    let name = if write {
        "config_persist_write"
    } else {
        "config_persist_read"
    };
    let env = cfg_env(name);
    let frames0 = {
        let ep = &env.cfg;
        let result = if write {
            cfg_request(
                ep,
                b"SET device lab.persist 0 601 kept-across-reboot",
                Some(token_entry(&env.admin)),
            )
        } else {
            cfg_request(ep, b"GET device lab.persist", None)
        };
        kprintln!("OSX|{}|ktest|{}|result={}", BUILD_ID, name, result);
        if write && result != "OK 1" {
            fail("the value was not written")
        }
        if !write && result != "OK 1 kept-across-reboot" {
            fail("the value did not survive the restart")
        }
        cfg_close(env, name)
    };
    cfg_balance(
        name,
        frames0,
        if write {
            "config value written and persisted"
        } else {
            "config value survived the QEMU restart"
        },
    )
}

// ---- WP-28: the network service ------------------------------------------------------------

/// The net tests' setting: manager with auth + net, both connected, the net service
/// configured by DHCP, admin and user tokens from real logins.
struct NetEnv {
    h: SvcHarness,
    net: Arc<Endpoint>,
    admin: Arc<crate::object::token::Token>,
    user: Arc<crate::object::token::Token>,
}

fn net_env(name: &'static str) -> (NetEnv, String) {
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-NET.TXT");
    svc_wait_ready(&h, &["auth", "net"], sched::ticks() + 60_000);
    let auth = svc_connect(&h, "auth");
    let (ra, admin) = auth_request(&auth, b"LOGIN admin lab-admin-1", None);
    let (ru, user) = auth_request(&auth, b"LOGIN user lab-user-1", None);
    let (Some(admin), Some(user)) = (admin, user) else {
        kprintln!("OSX|{}|ktest|{}|admin={}|user={}", BUILD_ID, name, ra, ru);
        fail("logins failed")
    };
    drop(auth);
    let net = svc_connect(&h, "net");
    let dhcp = cfg_request(&net, b"DHCP", None);
    (
        NetEnv {
            h,
            net,
            admin,
            user,
        },
        dhcp,
    )
}

fn net_close(env: NetEnv, name: &str) -> u64 {
    let NetEnv {
        h,
        net,
        admin,
        user,
    } = env;
    drop((net, admin, user));
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|{}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        name,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    frames0
}

const LAB_DHCP: &str = "OK ip=10.0.2.15 mask=255.255.255.0 gw=10.0.2.2 dns=10.0.2.3";

fn net_dhcp() -> ! {
    let (env, dhcp) = net_env("net_dhcp");
    let frames0 = {
        let status = cfg_request(&env.net, b"STATUS", None);
        kprintln!(
            "OSX|{}|ktest|net_dhcp|dhcp={}|status={}",
            BUILD_ID,
            dhcp,
            status
        );
        if dhcp != LAB_DHCP {
            fail("DHCP did not configure the lab addresses")
        }
        if !status.starts_with("OK link=1 configured=1 ip=10.0.2.15 mask=255.255.255.0 gw=10.0.2.2 dns=10.0.2.3 internet=unknown allow_internet=0") {
            fail("STATUS does not show the configuration")
        }
        // The DHCP reply string lives outside the block: release it before the balance.
        drop(dhcp);
        net_close(env, "net_dhcp")
    };
    cfg_balance(
        "net_dhcp",
        frames0,
        "the service configures itself by DHCP from the lab network",
    )
}

fn net_icmp() -> ! {
    let (env, dhcp) = net_env("net_icmp");
    let frames0 = {
        let ping = cfg_request(&env.net, b"PING 10.0.2.2 1000", None);
        let ping2 = cfg_request(&env.net, b"PING 10.0.2.2 1000", None);
        let rtt_ok = ping.starts_with("OK rtt=") && ping2.starts_with("OK rtt=");
        let bad = cfg_request(&env.net, b"PING nowhere", None);
        let status = cfg_request(&env.net, b"STATUS", None);
        kprintln!(
            "OSX|{}|ktest|net_icmp|dhcp_ok={}|ping={}|ping2={}|rtt_ok={}|bad={}|status={}",
            BUILD_ID,
            u8::from(dhcp == LAB_DHCP),
            ping,
            ping2,
            u8::from(rtt_ok),
            bad,
            status
        );
        if dhcp != LAB_DHCP || !rtt_ok || bad != "ERR BAD_REQUEST" {
            fail("ICMP echo to the gateway did not round-trip")
        }
        // The DHCP reply string lives outside the block: release it before the balance.
        drop(dhcp);
        net_close(env, "net_icmp")
    };
    cfg_balance(
        "net_icmp",
        frames0,
        "ICMP echo requests to the gateway are answered and timed",
    )
}

fn net_udp_echo() -> ! {
    let (env, dhcp) = net_env("net_udp_echo");
    let frames0 = {
        let n = &env.net;
        let open = cfg_request(n, b"UDP_OPEN 40000", None);
        let dup = cfg_request(n, b"UDP_OPEN 40000", None);
        let sent = cfg_request(n, b"UDP_SEND 0 10.0.2.2 17007 nawah udp echo one", None);
        let got = cfg_request(n, b"UDP_RECV 0 2000", None);
        let sent2 = cfg_request(n, b"UDP_SEND 0 10.0.2.2 17007 second datagram", None);
        let got2 = cfg_request(n, b"UDP_RECV 0 2000", None);
        let empty = cfg_request(n, b"UDP_RECV 0 50", None);
        let closed = cfg_request(n, b"UDP_CLOSE 0", None);
        let after = cfg_request(n, b"UDP_SEND 0 10.0.2.2 17007 x", None);
        kprintln!(
            "OSX|{}|ktest|net_udp_echo|dhcp_ok={}|open={}|dup={}|sent={}|got={}|sent2={}|got2={}|empty={}|closed={}|after={}",
            BUILD_ID,
            u8::from(dhcp == LAB_DHCP),
            open, dup, sent, got, sent2, got2, empty, closed, after
        );
        if dhcp != LAB_DHCP || open != "OK 0" || dup != "ERR EXISTS" || sent != "OK 18" {
            fail("socket open/send wrong")
        }
        if got != "OK 10.0.2.2 17007 nawah udp echo one"
            || sent2 != "OK 15"
            || got2 != "OK 10.0.2.2 17007 second datagram"
        {
            fail("the host's echo did not come back through UDP")
        }
        if empty != "ERR TIMEOUT" || closed != "OK" || after != "ERR BAD_REQUEST" {
            fail("receive timeout or close wrong")
        }
        // The DHCP reply string lives outside the block: release it before the balance.
        drop(dhcp);
        net_close(env, "net_udp_echo")
    };
    cfg_balance(
        "net_udp_echo",
        frames0,
        "UDP datagrams reach the host's echo server and come back",
    )
}

fn net_no_internet() -> ! {
    let (env, dhcp) = net_env("net_no_internet");
    let frames0 = {
        let n = &env.net;
        // Off-link destinations are refused by the service's policy; the gateway is on-link.
        let ping_off = cfg_request(n, b"PING 192.0.2.1 200", None);
        let open = cfg_request(n, b"UDP_OPEN 40001", None);
        let send_off = cfg_request(n, b"UDP_SEND 0 192.0.2.1 9 hello", None);
        let status1 = cfg_request(n, b"STATUS", None);
        // The explicit probe decides `internet`: TEST-NET-1 never answers.
        let probe = cfg_request(n, b"PROBE 192.0.2.1 300", None);
        let status2 = cfg_request(n, b"STATUS", None);
        // Policy change needs an admin token: the user's is refused, the admin's accepted.
        let pol_user = cfg_request(n, b"POLICY internet=1", Some(token_entry(&env.user)));
        let pol_none = cfg_request(n, b"POLICY internet=1", None);
        let pol_admin = cfg_request(n, b"POLICY internet=1", Some(token_entry(&env.admin)));
        let send_allowed = cfg_request(n, b"UDP_SEND 0 192.0.2.1 9 hello", None);
        let ping_allowed = cfg_request(n, b"PING 192.0.2.1 200", None);
        let status3 = cfg_request(n, b"STATUS", None);
        let pol_back = cfg_request(n, b"POLICY internet=0", Some(token_entry(&env.admin)));
        let ping_again = cfg_request(n, b"PING 192.0.2.1 200", None);
        kprintln!(
            "OSX|{}|ktest|net_no_internet|dhcp_ok={}|ping_off={}|open={}|send_off={}|internet1={}|probe={}|internet2={}|pol_user={}|pol_none={}|pol_admin={}|send_allowed={}|ping_allowed={}|internet3={}|pol_back={}|ping_again={}",
            BUILD_ID,
            u8::from(dhcp == LAB_DHCP),
            ping_off, open, send_off,
            status1.contains(" internet=unknown allow_internet=0"),
            probe,
            status2.contains(" internet=none allow_internet=0"),
            pol_user, pol_none, pol_admin, send_allowed, ping_allowed,
            status3.contains(" internet=none allow_internet=1"),
            pol_back, ping_again
        );
        if dhcp != LAB_DHCP
            || ping_off != "ERR POLICY"
            || open != "OK 0"
            || send_off != "ERR POLICY"
            || !status1.contains(" internet=unknown allow_internet=0")
        {
            fail("the no-internet policy did not refuse off-link traffic")
        }
        if probe != "ERR TIMEOUT" || !status2.contains(" internet=none allow_internet=0") {
            fail("the explicit probe did not settle internet=none")
        }
        if pol_user != "ERR ACCESS" || pol_none != "ERR BAD_REQUEST" || pol_admin != "OK" {
            fail("the policy change was not gated by the admin token")
        }
        if send_allowed != "OK 5"
            || ping_allowed != "ERR TIMEOUT"
            || !status3.contains(" internet=none allow_internet=1")
            || pol_back != "OK"
            || ping_again != "ERR POLICY"
        {
            fail("the allowed off-link attempt or the policy restore went wrong")
        }
        // The DHCP reply string lives outside the block: release it before the balance.
        drop(dhcp);
        net_close(env, "net_no_internet")
    };
    cfg_balance(
        "net_no_internet",
        frames0,
        "link, configured and internet are separate; off-link traffic needs an explicit policy",
    )
}

// ---- WP-29: TCP in the network service ------------------------------------------------------

/// A TCP connection to the host's echo server through SLIRP: the three-way handshake, data
/// both ways with acknowledgments, the orderly close, a released identifier, and a refused
/// connection (RST from a port nobody listens on).
fn net_tcp_echo() -> ! {
    let (env, dhcp) = net_env("net_tcp_echo");
    let frames0 = {
        let n = &env.net;
        let conn = cfg_request(n, b"TCP_CONNECT 10.0.2.2 17008 5000", None);
        let sent = cfg_request(n, b"TCP_SEND 1 hello tcp", None);
        let got = cfg_request(n, b"TCP_RECV 1 3000", None);
        let sent2 = cfg_request(n, b"TCP_SEND 1 second round through tcp", None);
        let got2 = cfg_request(n, b"TCP_RECV 1 3000", None);
        let empty = cfg_request(n, b"TCP_RECV 1 50", None);
        let status = cfg_request(n, b"TCP_STATUS 1", None);
        let closed = cfg_request(n, b"TCP_CLOSE 1", None);
        let after = cfg_request(n, b"TCP_RECV 1 50", None);
        let refused = cfg_request(n, b"TCP_CONNECT 10.0.2.2 17009 5000", None);
        let bad = cfg_request(n, b"TCP_SEND x y", None);
        kprintln!(
            "OSX|{}|ktest|net_tcp_echo|dhcp_ok={}|conn={}|sent={}|got={}|sent2={}|got2={}|empty={}|status={}|closed={}|after={}|refused={}|bad={}",
            BUILD_ID,
            u8::from(dhcp == LAB_DHCP),
            conn, sent, got, sent2, got2, empty, status, closed, after, refused, bad
        );
        if dhcp != LAB_DHCP || conn != "OK 1" || sent != "OK 9" || got != "OK hello tcp" {
            fail("the handshake or the first exchange with the host's TCP echo failed")
        }
        if sent2 != "OK 24" || got2 != "OK second round through tcp" || empty != "ERR TIMEOUT" {
            fail("the second exchange or the receive timeout went wrong")
        }
        if !status.starts_with("OK state=ESTABLISHED retransmits=0 rto=1000 srtt=") {
            fail("the connection status is not the expected one")
        }
        if closed != "OK"
            || after != "ERR CLOSED"
            || refused != "ERR REFUSED"
            || bad != "ERR BAD_REQUEST"
        {
            fail("close, the released identifier, or the refused port went wrong")
        }
        // The DHCP reply string lives outside the block: release it before the balance.
        drop(dhcp);
        net_close(env, "net_tcp_echo")
    };
    cfg_balance(
        "net_tcp_echo",
        frames0,
        "TCP connects to the host's echo server, exchanges data both ways and closes in order",
    )
}

/// The retransmission timer (RFC 6298): the service drops its next transmission on request,
/// so the segment goes out only when the RTO (1000 ticks) expires, with the RTO doubled and
/// no RTT sample taken from it (Karn); the next acknowledged send restores the RTO.
fn net_tcp_retransmit() -> ! {
    let (env, dhcp) = net_env("net_tcp_retransmit");
    let frames0 = {
        let n = &env.net;
        let conn = cfg_request(n, b"TCP_CONNECT 10.0.2.2 17008 5000", None);
        let inject = cfg_request(n, b"TCP_INJECT 1 drop_next=1", None);
        let t0 = sched::ticks();
        let sent = cfg_request(n, b"TCP_SEND 1 retransmit me", None);
        let waited = sched::ticks() - t0;
        let status = cfg_request(n, b"TCP_STATUS 1", None);
        let got = cfg_request(n, b"TCP_RECV 1 3000", None);
        let sent2 = cfg_request(n, b"TCP_SEND 1 again", None);
        let status2 = cfg_request(n, b"TCP_STATUS 1", None);
        let got2 = cfg_request(n, b"TCP_RECV 1 3000", None);
        let closed = cfg_request(n, b"TCP_CLOSE 1", None);
        kprintln!(
            "OSX|{}|ktest|net_tcp_retransmit|dhcp_ok={}|conn={}|inject={}|sent={}|waited={}|status={}|got={}|sent2={}|status2={}|got2={}|closed={}",
            BUILD_ID,
            u8::from(dhcp == LAB_DHCP),
            conn, inject, sent, waited, status, got, sent2, status2, got2, closed
        );
        if dhcp != LAB_DHCP || conn != "OK 1" || inject != "OK" {
            fail("the connection or the injected loss was refused")
        }
        if sent != "OK 13" || waited < 1000 {
            fail("the dropped segment was not delivered by the retransmission timer")
        }
        if !status.starts_with("OK state=ESTABLISHED retransmits=1 rto=2000 srtt=")
            || got != "OK retransmit me"
        {
            fail("the retransmission did not double the RTO without an RTT sample")
        }
        if sent2 != "OK 5"
            || !status2.starts_with("OK state=ESTABLISHED retransmits=1 rto=1000 srtt=")
            || got2 != "OK again"
            || closed != "OK"
        {
            fail("the next acknowledged send did not restore the RTO")
        }
        // The DHCP reply string lives outside the block: release it before the balance.
        drop(dhcp);
        net_close(env, "net_tcp_retransmit")
    };
    cfg_balance(
        "net_tcp_retransmit",
        frames0,
        "a lost segment is retransmitted when the RTO expires, with exponential back-off and Karn's rule",
    )
}

// ---- WP-30: the diagnostic shell --------------------------------------------------------

/// The shell cases (shell.md §4): the manager starts auth, net and sh from SVC-SH.TXT; the
/// lab drives the shell over the console socket (tools/project.py `console`) and ends the
/// session with `exit`, which the manager sees as the service stopping; the kernel then checks
/// what the services left behind. The kernel's own counters go to the serial log so the lab
/// can compare them with what `cpu` and `mem` printed.
fn shell_session(name: &'static str) -> ! {
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-SH.TXT");
    svc_wait_ready(&h, &["auth", "net", "sh"], sched::ticks() + 60_000);
    kprintln!(
        "OSX|{}|ktest|{}|cpus={}|frames_total={}|console_present={}|ready=1",
        BUILD_ID,
        name,
        crate::arch::smp::online_count(),
        pmm::stats().managed_frames,
        u8::from(crate::diag::present())
    );
    if !crate::diag::present() {
        fail("the diagnostic console is absent")
    }
    // The lab's session; `exit` stops the shell (state `stopped`, exit code 0).
    let lines = h.poll_list(sched::ticks() + 180_000, |l| {
        l.iter().any(|x| x.name == "sh" && x.state == "stopped")
    });
    let sh = lines.iter().find(|l| l.name == "sh");
    let (state, exit) = sh.map_or(("-".into(), None), |l| (l.state.clone(), l.exit));
    kprintln!(
        "OSX|{}|ktest|{}|sh_state={}|sh_exit={}|listing={}",
        BUILD_ID,
        name,
        state,
        exit.map_or(-1, |x| x as i64),
        SvcHarness::list_text(&lines)
    );
    if state != "stopped" || exit != Some(0) {
        fail("the shell did not end its session with exit 0")
    }
    drop((lines, state));
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|{}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        name,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    cfg_balance(
        name,
        frames0,
        "the shell served the lab's session from the owners of each state and ended cleanly",
    )
}

// ---- WP-31: the M4 gate ------------------------------------------------------------------

/// TST-M4-PEER-LOSS (REQ-M4-010): a client that vanishes mid-request leaves the service
/// serving others; a service that dies mid-request leaves its client with the channel closed
/// (K_E_SVC_PEER_CLOSED) and the manager restarts it after its backoff, after which it serves
/// again; the other service is unaffected; nothing is left behind.
fn peer_loss() -> ! {
    let h = SvcHarness::start("peer_loss", b"/SYSTEM/SVC-PL.TXT");
    svc_wait_ready(&h, &["config", "victim"], sched::ticks() + 60_000);
    let frames0 = {
        // (a) The vanishing client: a request is written and the endpoint dropped before any
        // reply could be read; the service's reply meets a closed peer.
        {
            let gone = svc_connect(&h, "config");
            let _ = gone.write(Message {
                bytes: b"GET device lab.key".to_vec(),
                handles: Vec::new(),
            });
            drop(gone);
        }
        let cfg = svc_connect(&h, "config");
        let after_client_loss = cfg_request(&cfg, b"GET device nokey", None);
        // (b) The dying service: its first request is never answered — the channel closes.
        let victim = svc_connect(&h, "victim");
        let t_crash = sched::ticks();
        let lost = cfg_request(&victim, b"PING", None);
        drop(victim);
        // The manager restarts it once the backoff has passed; the new instance serves.
        let lines = h.poll_list(sched::ticks() + 5000, |l| {
            l.iter()
                .any(|x| x.name == "victim" && x.state == "ready" && x.restarts == 1)
        });
        let restarted = lines
            .iter()
            .find(|l| l.name == "victim")
            .map(|l| (l.state.clone(), l.restarts, l.exit, l.last_start));
        let victim2 = svc_connect(&h, "victim");
        let served = cfg_request(&victim2, b"PING", None);
        let served_again = cfg_request(&victim2, b"PING", None);
        // (c) The config service never noticed.
        let after_service_loss = cfg_request(&cfg, b"GET device nokey", None);
        let (state, restarts, exit, last_start) = restarted
            .clone()
            .unwrap_or_else(|| ("-".into(), u64::MAX, None, None));
        kprintln!(
            "OSX|{}|ktest|peer_loss|after_client_loss={}|lost={}|victim_state={}|restarts={}|exit={}|restart_after_ticks={}|served={}|served_again={}|after_service_loss={}",
            BUILD_ID,
            after_client_loss,
            lost,
            state,
            restarts,
            exit.map_or(-1, |x| x as i64),
            last_start.map_or(-1, |t| t as i64 - t_crash as i64),
            served,
            served_again,
            after_service_loss
        );
        if after_client_loss != "ERR NOT_FOUND" {
            fail("the config service stopped serving after a client vanished")
        }
        if lost != "error:K_E_SVC_PEER_CLOSED" {
            fail("the dying service did not leave its client with a closed channel")
        }
        if state != "ready" || restarts != 1 || exit != Some(3) {
            fail("the manager did not restart the dead service once")
        }
        if last_start.is_none_or(|t| t < t_crash + 10) {
            fail("the restart came before the backoff")
        }
        if served != "OK served" || served_again != "OK served" {
            fail("the restarted service does not serve")
        }
        if after_service_loss != "ERR NOT_FOUND" {
            fail("the config service was disturbed by the other service's death")
        }
        drop((
            after_client_loss,
            lost,
            served,
            served_again,
            after_service_loss,
            lines,
            restarted,
            state,
            cfg,
            victim2,
        ));
        let (mgr_exit, procs, frames0, clean) = h.finish();
        kprintln!(
            "OSX|{}|ktest|peer_loss|mgr_exit={:#x}|processes_after={}|clean={}",
            BUILD_ID,
            mgr_exit,
            procs,
            u8::from(clean)
        );
        if mgr_exit != 0 || procs != 0 || !clean {
            fail("manager or services left something behind")
        }
        frames0
    };
    cfg_balance(
        "peer_loss",
        frames0,
        "a vanished client and a dead service are each contained: the others keep serving and the dead one is restarted",
    )
}

// ---- WP-27: the network interface and the keyboard ----------------------------------------

/// Runs an embedded application with one kernel object as its bootstrap handle.
fn run_with_object(name: &str, image: &[u8], entry: Entry) -> crate::user::Outcome {
    if image.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    // The baseline precedes every allocation of the spawn (the process object included):
    // CI run 39133924555 counted the object's block as a frame freed by the process.
    let frames0 = pmm::stats().free_frames;
    let object = Arc::new(crate::object::process::ProcessObject::new());
    let pid = match crate::user::spawn_elf_with(image, 1, alloc::vec![entry], object) {
        Ok(p) => p,
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|error={}", BUILD_ID, name, e.code());
            fail("application did not load")
        }
    };
    let exit_code = sched::wait_process(pid).unwrap_or(u64::MAX);
    crate::user::Outcome {
        pid,
        exit_code,
        frames_delta: frames0 as i64 - pmm::stats().free_frames as i64,
    }
}

/// The interface from the kernel (ARP round trip with the lab gateway) and from a process
/// (netprobe through the NIC handle: info, send, wait, receive, refusals).
fn net_link() -> ! {
    let Some(info) = crate::net::info() else {
        fail("no network interface")
    };
    let probe = crate::net::arp_probe(500);
    let (gw, waited, code) = match probe {
        Ok((mac, t)) => (mac, t, "ok"),
        Err(e) => ([0; 6], 0, e.code()),
    };
    let st0 = crate::net::stats();
    let o = run_with_object(
        "net_link",
        crate::apps::NETPROBE,
        Entry {
            object: Object::Nic(crate::net::nic_object()),
            rights: Rights::NIC_DEFAULT,
        },
    );
    let st1 = crate::net::stats();
    kprintln!(
        "OSX|{}|ktest|net_link|mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}|link={}|gateway={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}|arp_ticks={}|kernel_code={}|user_exit={:#x}|user_tx={}|user_rx={}|rx_bad={}|frames_delta={}|dma_frames={}",
        BUILD_ID,
        info.mac[0], info.mac[1], info.mac[2], info.mac[3], info.mac[4], info.mac[5],
        u8::from(crate::net::link_up()),
        gw[0], gw[1], gw[2], gw[3], gw[4], gw[5],
        waited,
        code,
        o.exit_code,
        st1.tx_frames - st0.tx_frames,
        st1.rx_frames - st0.rx_frames,
        st1.rx_bad,
        o.frames_delta,
        crate::net::frames()
    );
    if code != "ok" || gw == [0; 6] {
        fail("the kernel's ARP probe got no reply from the gateway")
    }
    if o.exit_code != 0x73 || o.frames_delta != 0 {
        fail("netprobe did not reach its end (exit code = failing step)")
    }
    if st1.tx_frames - st0.tx_frames < 1 || st1.rx_frames - st0.rx_frames < 1 {
        fail("the process's frames were not counted")
    }
    pass("the interface sends and receives from the kernel and from a process")
}

/// Fixed resources under pressure: 64 sends back to back never put more than the 16 slots in
/// flight and are either queued or refused with Busy (never dropped silently, never more
/// slots — the lab's device drains so fast that the refusal is also forced by marking every
/// slot in flight); every slot comes back; the DMA frames never change; oversized and
/// undersized frames are refused.
fn net_limits() -> ! {
    use crate::drivers::virtio_net::{NetError, DMA_FRAMES, FRAME_MAX};
    let Some(info) = crate::net::info() else {
        fail("no network interface")
    };
    let frames_before = pmm::stats().free_frames;
    let req = crate::net::arp_request(
        info.mac,
        crate::net::LAB_GUEST_IP,
        crate::net::LAB_GATEWAY_IP,
    );
    let (mut sent, mut busy, mut other, mut peak) = (0u32, 0u32, 0u32, 0u32);
    for _ in 0..64 {
        match crate::net::send(&req) {
            Ok(()) => sent += 1,
            Err(NetError::Busy) => busy += 1,
            Err(_) => other += 1,
        }
        peak = peak.max(crate::net::tx_in_flight_raw());
    }
    // Wait for the device to drain the ring, then every slot is free again.
    let t = sched::ticks() + 200;
    sched::poll_until(t, || crate::net::tx_in_flight() == 0);
    let in_flight_after = crate::net::tx_in_flight();
    // The refusal path, forced: every slot marked in flight (the device has nothing to
    // return for them), so a send must answer Busy and count it; released, it sends again.
    let busy0 = crate::net::stats().tx_busy;
    crate::net::inject_tx_full(true);
    let forced_busy = crate::net::send(&req) == Err(NetError::Busy);
    let busy_counted = crate::net::stats().tx_busy == busy0 + 1;
    crate::net::inject_tx_full(false);
    let after_release = crate::net::send(&req).is_ok();
    let (mut sent2, mut busy2) = (0u32, 0u32);
    for _ in 0..16 {
        match crate::net::send(&req) {
            Ok(()) => sent2 += 1,
            Err(NetError::Busy) => busy2 += 1,
            Err(_) => other += 1,
        }
    }
    let short = crate::net::send(&req[..13]) == Err(NetError::Range);
    let long = crate::net::send(&[0u8; FRAME_MAX + 1]) == Err(NetError::Range);
    // Drain whatever came back (ARP replies to the flood) and count.
    let t = sched::ticks() + 300;
    sched::poll_until(t, || false);
    let received = {
        let mut buf = alloc::vec![0u8; FRAME_MAX];
        let mut n = 0u32;
        while crate::net::recv(&mut buf).is_some() {
            n += 1;
        }
        n
    };
    let st = crate::net::stats();
    let frames_delta = frames_before as i64 - pmm::stats().free_frames as i64;
    kprintln!(
        "OSX|{}|ktest|net_limits|queue_size={}|sent={}|busy={}|other={}|in_flight_peak={}|in_flight_after={}|forced_busy={}|busy_counted={}|after_release={}|sent2={}|busy2={}|short_refused={}|long_refused={}|received={}|tx_busy_counted={}|rx_bad={}|dma_frames={}|frames_delta={}",
        BUILD_ID,
        info.queue_size,
        sent,
        busy,
        other,
        peak,
        in_flight_after,
        u8::from(forced_busy),
        u8::from(busy_counted),
        u8::from(after_release),
        sent2,
        busy2,
        u8::from(short),
        u8::from(long),
        received,
        st.tx_busy,
        st.rx_bad,
        crate::net::frames(),
        frames_delta
    );
    let q = u32::from(info.queue_size);
    if sent + busy != 64 || other != 0 || peak > q {
        fail("the transmit ring did not keep to its slots")
    }
    if in_flight_after != 0
        || !forced_busy
        || !busy_counted
        || !after_release
        || sent2 + busy2 != 16
        || busy2 > 0
    {
        fail("transmit slots were not reclaimed or the refusal path is wrong")
    }
    if !short || !long || crate::net::frames() != DMA_FRAMES || frames_delta != 0 {
        fail("length limits or resource accounting wrong")
    }
    pass("the interface's fixed resources hold under pressure and come back")
}

/// Scancodes from the i8042 through the keyboard object and a process (kbdprobe): the test
/// reports readiness, the lab injects a, b and Enter through the QEMU monitor, and the process
/// exits with the six set-1 make/break bytes it collected.
fn kbd_scancodes() -> ! {
    let kbd = crate::net::keyboard_object();
    kprintln!(
        "OSX|{}|ktest|kbd_scancodes|ready=1|pending={}|overflow={}",
        BUILD_ID,
        kbd.pending(),
        kbd.overflow()
    );
    let o = run_with_object(
        "kbd_scancodes",
        crate::apps::KBDPROBE,
        Entry {
            object: Object::Keyboard(kbd.clone()),
            rights: Rights::KBD_DEFAULT,
        },
    );
    kprintln!(
        "OSX|{}|ktest|kbd_scancodes|exit={:#x}|overflow={}|pending_after={}|frames_delta={}",
        BUILD_ID,
        o.exit_code,
        kbd.overflow(),
        kbd.pending(),
        o.frames_delta
    );
    // a: 1E/9E, b: 30/B0, Enter: 1C/9C, packed little-endian.
    if o.exit_code != 0x9c1c_b030_9e1e || o.frames_delta != 0 {
        fail("the injected keys did not arrive as set-1 scancodes")
    }
    pass("keyboard scancodes reach a process through the keyboard object")
}

/// A process that exits with 44 file handles open (20 files + 20 duplicates, 4 created and
/// written): afterwards no file object or handle remains, the created files hold their 1500
/// bytes (3 clusters each), frames balance; the host tool verifies the image.
fn fd_leak() -> ! {
    let image = crate::apps::FD_LEAK;
    if image.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let obj0 = object::stats();
    let free0 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    let (o, _l) = match crate::user::run_elf(image) {
        Ok(r) => r,
        Err(e) => {
            kprintln!("OSX|{}|ktest|fd_leak|error={}", BUILD_ID, e.code());
            fail("application did not load")
        }
    };
    let obj1 = object::stats();
    let free1 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    let mut sizes = [0u64; 4];
    for (i, p) in [
        &b"/LEAK0.TXT"[..],
        b"/LEAK1.TXT",
        b"/LEAK2.TXT",
        b"/DIR/LEAK3.TXT",
    ]
    .iter()
    .enumerate()
    {
        sizes[i] = crate::fs::vfs::stat(p).map_or(0, |st| st.size);
    }
    let st = sched::stats();
    kprintln!(
        "OSX|{}|ktest|fd_leak|exit={:#x}|files_before={}|files_after={}|handles_after={}|free_before={}|free_after={}|sizes={},{},{},{}|frames_delta={}|processes_after={}",
        BUILD_ID,
        o.exit_code,
        obj0.files,
        obj1.files,
        obj1.handles,
        free0,
        free1,
        sizes[0],
        sizes[1],
        sizes[2],
        sizes[3],
        o.frames_delta,
        st.processes
    );
    if o.exit_code != 0x62 {
        fail("application did not reach its end (exit code = failing step)")
    }
    if obj1.files != 0 || obj1.handles != 0 || obj1 != obj0 {
        fail("file objects or handles survived the process")
    }
    if sizes != [1500; 4] || free0 - free1 != 12 {
        fail("created files or cluster accounting wrong")
    }
    if o.frames_delta != 0 || st.processes != 0 {
        fail("frames or process records leaked")
    }
    pass("a process exiting with 44 open file handles leaks nothing")
}
