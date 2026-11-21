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
        "wait_deadline" => wait_deadline(),
        "exit_cleanup" => exit_cleanup(),
        "user_sleep" => user_sleep(),
        "ipc_roundtrip" => user_program_case("ipc_roundtrip", user_programs::ipc_roundtrip(), 0x1C),
        "rights_denied" => user_program_case("rights_denied", user_programs::rights_denied(), 0x2D),
        "vmo_map_rights" => vmo_map_rights(),
        "closed_handle" => user_program_case("closed_handle", user_programs::closed_handle(), 0x3E),
        "oversize_rejected" => {
            user_program_case("oversize_rejected", user_programs::oversize(), 0x4F)
        }
        "ipc_no_leak" => ipc_no_leak(),
        "handle_table" => handle_table(),
        "block_wake" => block_wake(),
        "channel_chain" => channel_chain(),
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
        "blk_timeout" => blk_timeout(),
        "blk_persist_write" => blk_persist(true),
        "blk_persist_read" => blk_persist(false),
        "fat32_read" => fat32_read(),
        "fat32_write" => fat32_write(),
        "file_shared" => file_shared(),
        "fat32_persist_write" => fat32_persist(true),
        "fat32_persist_read" => fat32_persist(false),
        "fat32_fault_unlink" => fat32_fault_unlink(false),
        "fat32_fault_unlink_check" => fat32_fault_check(b'U', "fat32_fault_unlink_check"),
        "fat32_fault_unlink_one" => fat32_fault_unlink(true),
        "fat32_fault_unlink_one_check" => fat32_fault_check(b'U', "fat32_fault_unlink_one_check"),
        "fat32_fault_truncate" => fat32_fault_truncate(false),
        "fat32_fault_truncate_check" => fat32_fault_check(b'T', "fat32_fault_truncate_check"),
        "fat32_fault_truncate_one" => fat32_fault_truncate(true),
        "fat32_fault_truncate_one_check" => {
            fat32_fault_check(b'T', "fat32_fault_truncate_one_check")
        }
        "fat32_fault_write" => fat32_fault_write(false),
        "fat32_fault_write_check" => fat32_fault_write_check("fat32_fault_write_check"),
        "fat32_fault_write_one" => fat32_fault_write(true),
        "fat32_fault_write_one_check" => fat32_fault_write_check("fat32_fault_write_one_check"),
        "fat32_fault_create" => fat32_fault_create(false, false),
        "fat32_fault_create_check" => fat32_fault_create_check("fat32_fault_create_check", false),
        "fat32_fault_create_one" => fat32_fault_create(true, false),
        "fat32_fault_create_copies" => fat32_fault_create(true, true),
        "fat32_fault_create_one_check" => {
            fat32_fault_create_check("fat32_fault_create_one_check", true)
        }
        "fat32_disk_full" => fat32_disk_full(),
        "fat32_stop" => fat32_stop(),
        "fat32_stop_check" => fat32_stop_check(),
        "fat32_bpb" => fat32_bpb(),
        "fat32_bad_first" => fat32_bad_first(),
        "file_roundtrip" => file_app("file_roundtrip", crate::apps::FILE_ROUNDTRIP, 0x60),
        "path_invalid" => file_app("path_invalid", crate::apps::PATH_INVALID, 0x61),
        "fd_leak" => fd_leak(),
        "spawn_volume" => volume_app("spawn_volume", crate::apps::LAUNCH, 0x70),
        "wait_timeout" => wait_timeout(),
        "child_exit" => volume_app("child_exit", crate::apps::CHILD, 0x72),
        "svc_order" => svc_order(),
        "svc_timeout" => svc_timeout(),
        "svc_restart" => svc_restart(),
        "svc_connect_noread" => svc_connect_noread(),
        "token_objects" => token_objects(),
        "login" => login(),
        "session_lock" => session_lock(),
        "authz_denied" => authz_denied(),
        "file_authority" => file_authority(),
        "config_write_scope" => config_write_scope(),
        "config_cas" => config_cas(),
        "config_retry" => config_retry(),
        "config_notify" => config_notify(),
        "config_store_authz" => config_store_authz(),
        "config_read_load" => config_read_load(),
        "config_subs" => config_subs(),
        "launch_denied" => launch_denied(),
        "app_spawn" => app_spawn(),
        "app_connect" => app_connect(),
        "session_job" => session_job(),
        "job_bound" => job_bound(),
        "launch_rate" => launch_rate(),
        "session_gate" => session_gate(),
        "session_restart" => session_restart(),
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
        "net_client_drop" => net_client_drop(),
        "shell_svc" => shell_session("shell_svc"),
        "peer_loss" => peer_loss(),
        "display_boot" => display_boot(),
        "input_route" => input_route(),
        "mouse" => mouse(),
        "screen" => screen(),
        "window_states" => window_states(),
        "alt_tab_cycle" => alt_tab_cycle(),
        "app_hang" => app_hang(),
        "app_oversize" => app_oversize(),
        "text_layer" => text_layer(),
        "keyboard_nav" => keyboard_nav("keyboard_nav"),
        "keyboard_nav2" => keyboard_nav("keyboard_nav2"),
        "window_a11y" => keyboard_nav("window_a11y"),
        "a11y_tree" => a11y_tree(),
        "arabic_ui" => arabic_ui(),
        "process_kill" => process_kill(),
        "job_kill_all" => job_kill_all(),
        "kill_edges" => kill_edges(),
        "svc_watchdog" => svc_watchdog(),
        "session_deadline" => session_deadline(),
        "login_screen" => login_screen(),
        "auth_input_isolated" => auth_input_isolated(),
        "lock_survives" => lock_survives(),
        "narrator_authority" => narrator_authority(),
        "window_title" => window_title(),
        "window_title_resize" => window_title_resize(),
        "client_limits" => client_limits(),
        "input_name_reserved" => input_name_reserved(),
        "focus_after_restart" => focus_after_restart(),
        "session_loss" => session_loss(),
        "list_hash_held" => list_hash_held(),
        "lock_hang" => lock_hang(),
        "lock_auth_hang" => lock_auth_hang(),
        "unlock_auth_hang" => unlock_auth_hang(),
        "session_hang" => session_hang(),
        "lock_display_down" => lock_display_down(),
        "hold_fail_closed" => hold_fail_closed(),
        "displayd_boot_loop" => displayd_boot_loop(),
        "manifest_too_large" => manifest_too_large(),
        "load_outside_system" => load_outside_system(),
        "token_revoke" => token_revoke(),
        "logout_kills" => logout_kills(),
        "purge_fail_closed" => purge_fail_closed(),
        "elevate" => elevate(),
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

/// vmo_map's rights (WP-149, K-3, TST-M3-VMO-MAP-RIGHTS): a writable page on x86 is
/// readable, so a mapping for writing needs READ as well as WRITE and MAP. The ring-3 program
/// packs each answer into its exit code (user_programs.rs); one line names them.
fn vmo_map_rights() -> ! {
    let o = match crate::user::run(user_programs::vmo_map_rights()) {
        Ok(o) => o,
        Err(e) => {
            kprintln!("OSX|{}|ktest|vmo_map_rights|error={}", BUILD_ID, e.code());
            fail("could not run the ring-3 program")
        }
    };
    if o.exit_code >> 32 != 0xA5 {
        kprintln!(
            "OSX|{}|ktest|vmo_map_rights|setup_step={:#x}|frames_delta={}",
            BUILD_ID,
            o.exit_code,
            o.frames_delta
        );
        fail("the vmo_map rights program stopped before its mappings")
    }
    let answer = |shift: u32| match i64::from((o.exit_code >> shift) as u8 as i8) {
        0 => "mapped",
        crate::syscall::ERR_ACCESS => "ERR_ACCESS",
        crate::syscall::ERR_INVALID => "ERR_INVALID",
        crate::syscall::ERR_BAD_HANDLE => "ERR_BAD_HANDLE",
        crate::syscall::ERR_WRONG_TYPE => "ERR_WRONG_TYPE",
        crate::syscall::ERR_NO_RESOURCES => "ERR_NO_RESOURCES",
        _ => "other",
    };
    let (write_read, write_noread, read_noread) = (answer(0), answer(8), answer(16));
    let leak = (o.exit_code >> 24) & 0xFF;
    kprintln!(
        "OSX|{}|ktest|vmo_map_rights|write_noread={}|read_noread={}|write_read={}|leak={}|frames_delta={}",
        BUILD_ID,
        write_noread,
        read_noread,
        write_read,
        leak,
        o.frames_delta
    );
    if write_noread != "ERR_ACCESS" {
        fail("a handle without READ was not refused a mapping for writing with ERR_ACCESS")
    }
    if read_noread != "ERR_ACCESS" {
        fail("a handle without READ was not refused a mapping for reading with ERR_ACCESS")
    }
    if leak != 0 {
        fail("the object's bytes were read through a mapping of a handle without READ")
    }
    if write_read != "mapped" {
        fail("a handle with MAP, READ and WRITE was not given a mapping for writing")
    }
    if o.frames_delta != 0 {
        fail("frames leaked by the ring-3 run")
    }
    pass("vmo_map asks READ for a mapping for writing as for one for reading")
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

/// A chain of channels, each one's end carried in the next one's queue, tears down with no
/// more kernel stack than one link: dropping it used to recurse once per link and overflow the
/// kernel stack (32 KiB per thread; 4096 links also overflow the 64 KiB boot stack this case runs
/// on) (review 2026-10-19). Nothing survives the teardown.
fn channel_chain() -> ! {
    const LINKS: usize = 4096;
    let obj0 = object::stats();
    let (first_a, mut tail) = channel::create();
    drop(first_a);
    for _ in 1..LINKS {
        let (a, b) = channel::create();
        let carried = Entry {
            object: Object::Channel(tail),
            rights: Rights::CHANNEL_DEFAULT,
        };
        let m = Message {
            bytes: Vec::new(),
            handles: alloc::vec![carried],
        };
        if a.write(m).is_err() {
            fail("write of the previous link failed")
        }
        drop(a);
        tail = b;
    }
    let obj_held = object::stats();
    drop(tail);
    let obj1 = object::stats();
    kprintln!(
        "OSX|{}|ktest|channel_chain|links={}|channels_held={}|channels_after={}|endpoints_after={}|channels_before={}",
        BUILD_ID,
        LINKS,
        obj_held.channels - obj0.channels,
        obj1.channels,
        obj1.endpoints,
        obj0.channels
    );
    if obj1.channels != obj0.channels || obj1.endpoints != obj0.endpoints {
        fail("channels or endpoints survived the teardown")
    }
    pass("a chain of channels tears down without recursion")
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

/// TST-M3-BLK-TIMEOUT (REQ-M3-007; WP-104, RSK-026; ADR-0013 decision 9): after a request
/// times out the driver publishes nothing more. Every request shares one header, one status
/// byte, one data buffer and the same descriptors, and a completion is taken by its position: a
/// request that was given up may still complete later, so the next request's result could be
/// the old one's, and a write's bytes could reach the old request's sector.
///
/// The case reads one pattern sector (served, so the shared buffer holds that sector), fills
/// its own buffer with a guard byte, and makes the next read time out through the test
/// kernel's hook: the read answers K_E_BLK_TIMEOUT and hands back nothing (the caller's buffer
/// keeps the guard). Then a read, a write, a flush and a read past the end are each refused
/// with K_E_BLK_NEEDS_RESET; the caller's buffer still keeps the guard, the shared buffer still
/// holds the first sector (the refused write did not copy its bytes in), and the driver's
/// available index did not move (nothing was published). The write carries the bytes its
/// sector already holds, so a kernel that serves it leaves the image as it was.
fn blk_timeout() -> ! {
    const GUARD: u8 = 0xA5;
    let capacity = crate::block::capacity_sectors();
    let mut buf = alloc::vec![0u8; 512];
    let mut held = alloc::vec![0u8; 512];
    let target = capacity.saturating_sub(PATTERN_TAIL);
    let first = target + 1;
    let frames0 = pmm::stats().free_frames;
    let before = crate::block::read(first, &mut buf);
    let pattern_ok = buf
        .iter()
        .enumerate()
        .all(|(k, b)| *b == pattern_byte(first, k));
    buf.fill(GUARD);
    crate::block::arm_timeout();
    let timed = crate::block::read(target, &mut buf);
    let published0 = crate::block::submitted();
    let after_read = crate::block::read(target, &mut buf);
    let caller_kept = buf.iter().all(|b| *b == GUARD);
    let mut same = [0u8; 512];
    for (k, b) in same.iter_mut().enumerate() {
        *b = pattern_byte(target, k);
    }
    let after_write = crate::block::write(target, &same);
    crate::block::peek_data(&mut held);
    let buffer_kept = held
        .iter()
        .enumerate()
        .all(|(k, b)| *b == pattern_byte(first, k));
    let after_flush = crate::block::flush();
    let past_end = crate::block::read(capacity, &mut buf);
    let published = crate::block::submitted().wrapping_sub(published0);
    let frames1 = pmm::stats().free_frames;
    let code = |r: &Result<(), crate::drivers::virtio_blk::BlkError>| match r {
        Ok(()) => "ok",
        Err(e) => e.code(),
    };
    kprintln!(
        "OSX|{}|ktest|blk_timeout|before={}|pattern={}|timed={}|caller_kept={}|after_read={}|after_write={}|buffer_kept={}|after_flush={}|past_end={}|published={}|frames_delta={}",
        BUILD_ID,
        code(&before),
        u8::from(pattern_ok),
        code(&timed),
        u8::from(caller_kept),
        code(&after_read),
        code(&after_write),
        u8::from(buffer_kept),
        code(&after_flush),
        code(&past_end),
        published,
        frames0 as i64 - frames1 as i64
    );
    if before.is_err() || !pattern_ok {
        fail("the pattern sector was not read before the timeout")
    }
    if code(&timed) != "K_E_BLK_TIMEOUT" {
        fail("the withheld request did not time out")
    }
    if [&after_read, &after_write, &after_flush, &past_end]
        .iter()
        .any(|r| code(r) != "K_E_BLK_NEEDS_RESET")
    {
        fail("a request was served after a timed-out one")
    }
    if !caller_kept {
        fail("a failed read changed the caller's buffer")
    }
    if !buffer_kept {
        fail("a refused write changed the shared buffer")
    }
    if published != 0 {
        fail("a refused request was published to the device")
    }
    if frames0 != frames1 {
        fail("frames leaked")
    }
    pass("after a timed-out request the disk serves nothing more")
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

// ---- A wait's deadline against a spinning thread (WP-99, RSK-024) ----------------------

static WD_STOP: AtomicBool = AtomicBool::new(false);
static WD_SPINS: AtomicU64 = AtomicU64::new(0);
static WD_UNTIL: AtomicU64 = AtomicU64::new(0);
/// Ticks after which the waiter's `poll_until` must end.
const WD_DEADLINE_TICKS: u64 = 50;
/// The spinner gives up by itself this long after the start: a kernel that never runs the
/// waiter still ends the case, as a failure with its lateness measured.
const WD_SPIN_TICKS: u64 = 400;
/// How late the waiter may come back: two time slices.
const WD_LATE_LIMIT: u64 = 2 * sched::QUANTUM_TICKS as u64;

/// Never yields and never blocks once it spins: `head_sleep` ticks asleep first (so the case's
/// thread is inside its wait before a spinner of better priority takes the CPU), then a busy
/// loop until the case stops it or its own limit.
extern "sysv64" fn wd_spinner(head_sleep: u64) -> u64 {
    if head_sleep > 0 {
        sched::sleep_ticks(head_sleep);
    }
    let mut n = 0u64;
    while !WD_STOP.load(Ordering::Acquire)
        && sched::stats().ticks < WD_UNTIL.load(Ordering::Relaxed)
    {
        n += 1;
        WD_SPINS.store(n, Ordering::Relaxed);
    }
    n
}

/// One wait of `WD_DEADLINE_TICKS` beside a spinner of priority `prio`: returns whether the
/// waiter came back within `WD_LATE_LIMIT` of its deadline and, when `starved_before` is set,
/// was not run before it (at most three polls: on entry, once more, at the deadline). With
/// `yields_after` (a spinner of better priority than the case's own) the case's thread then
/// keeps busy without yielding, with interrupts on for that stretch (the boot thread runs with
/// them off outside its waits, so the timer could not preempt it otherwise): back at its own
/// priority it loses the CPU to the spinner and runs again only when the spinner gives up,
/// `WD_SPIN_TICKS` after the start (`resumed`); a kernel that leaves the waiter boosted after
/// its wait lets it run on beside the spinner. The wait leaves the interrupt flag as it found
/// it (`irq_before`, `irq_after`).
fn wd_round(prio: u8, head_sleep: u64, starved_before: bool, yields_after: bool) -> bool {
    WD_STOP.store(false, Ordering::Release);
    WD_SPINS.store(0, Ordering::Relaxed);
    let t0 = sched::ticks();
    WD_UNTIL.store(t0 + WD_SPIN_TICKS, Ordering::Relaxed);
    let deadline = t0 + WD_DEADLINE_TICKS;
    let tid = spawn_or_fail(wd_spinner, head_sleep, prio);
    let mut polls = 0u64;
    let irq_before = arch::interrupts::enabled();
    let held = sched::poll_until(deadline, || {
        polls += 1;
        false
    });
    let late = sched::ticks().saturating_sub(deadline);
    let irq_after = arch::interrupts::enabled();
    let spins_at_return = WD_SPINS.load(Ordering::Relaxed);
    let mut resumed = 0;
    if yields_after {
        arch::interrupts::enable();
        while sched::ticks() < deadline + 2 * WD_LATE_LIMIT {
            core::hint::spin_loop();
        }
        resumed = sched::ticks() - t0;
        if !irq_after {
            arch::interrupts::disable();
        }
    }
    WD_STOP.store(true, Ordering::Release);
    let joined = sched::join(tid).is_some();
    let ok = !held
        && joined
        && late <= WD_LATE_LIMIT
        && spins_at_return > 0
        && (!starved_before || polls <= 3)
        && (!yields_after || resumed >= WD_SPIN_TICKS)
        && irq_after == irq_before;
    kprintln!(
        "OSX|{}|ktest|wait_deadline|spinner_prio={}|ok={}|deadline_ticks={}|late={}|limit={}|polls={}|held={}|spins={}|joined={}|resumed={}|spin_ticks={}|irq_before={}|irq_after={}",
        BUILD_ID,
        prio,
        u8::from(ok),
        WD_DEADLINE_TICKS,
        late,
        WD_LATE_LIMIT,
        polls,
        u8::from(held),
        spins_at_return,
        u8::from(joined),
        resumed,
        WD_SPIN_TICKS,
        u8::from(irq_before),
        u8::from(irq_after)
    );
    ok
}

/// A wait with a deadline ends at its deadline whatever spins beside it (WP-99): the case's
/// thread (priority 1) waits 50 ticks in `poll_until` while a kernel thread on the same CPU
/// spins without yielding, first at priority 0 (better than the waiter's own), then at
/// priority 1 (the service manager's). The waiter comes back within two slices of the deadline
/// both times; beside the priority-1 spinner it is not run before the deadline (a waiter
/// competes at the lowest priority until then), and the spinner did run. Beside the priority-0
/// spinner the boost ends with the wait: the case's thread, busy at its own priority 1, runs
/// again only when the spinner has given up.
fn wait_deadline() -> ! {
    let frames0 = pmm::stats().free_frames;
    let better = wd_round(0, 5, false, true);
    let equal = wd_round(1, 0, true, false);
    let frames1 = pmm::stats().free_frames;
    kprintln!(
        "OSX|{}|ktest|wait_deadline|frames_delta={}",
        BUILD_ID,
        frames0 as i64 - frames1 as i64
    );
    if !better {
        fail("beside a spinner of better priority the wait did not end at its deadline, or its boost outlived it")
    }
    if !equal {
        fail("the wait did not end at its deadline beside a spinner of the manager's priority, or ran before it")
    }
    if frames0 != frames1 {
        fail("frames leaked")
    }
    pass("a wait's deadline holds against a spinning thread")
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

/// Two opens of one file share its directory entry (files.md v1.2, review 2026-10-19). A
/// truncation through the second is seen by the first: its stale position is refused instead of
/// writing into the freed chain, and after a seek it reads what the second wrote. Removing the
/// file is refused while it is open. A file created meanwhile takes clusters of its own and the
/// shared file keeps its content. After both closes the removal works and every cluster comes
/// back; fsck.fat and tools/fat32.py then find the volume consistent. Before v1.2 each open
/// kept its own copy of the entry, and a write through the stale one cross-linked the clusters
/// another file had taken.
fn file_shared() -> ! {
    use crate::fs::vfs;
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let free0 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    let rw = vfs::O_READ | vfs::O_WRITE;
    let Ok(a) = vfs::open(b"/SHARED.TXT", rw | vfs::O_CREATE) else {
        fail("open A failed")
    };
    let old = alloc::vec![b'A'; 2000];
    let wrote_a = vfs::write(&a, &old);
    let Ok(b) = vfs::open(b"/SHARED.TXT", rw | vfs::O_TRUNCATE) else {
        fail("open B with truncation failed")
    };
    let size_seen_by_a = a.lock().node.lock().size;
    let wrote_b = vfs::write(&b, b"fresh-data");
    // A's position (2000) is past the new end: refused, not written into freed clusters.
    let stale_write = vfs::write(&a, b"stale").err();
    let busy = vfs::unlink(b"/SHARED.TXT").err();
    // A file created now takes clusters of its own (the freed ones, very likely).
    let Ok(c) = vfs::open(b"/OTHER.TXT", rw | vfs::O_CREATE) else {
        fail("open C failed")
    };
    let wrote_c = vfs::write(&c, &alloc::vec![b'C'; 1500]);
    let _ = vfs::seek(&a, 0);
    let mut back = [0u8; 32];
    let read_a = vfs::read(&a, &mut back);
    let shared_ok = matches!(read_a, Ok(10)) && &back[..10] == b"fresh-data";
    drop((a, b, c));
    let mut other = alloc::vec![0u8; 1600];
    let other_ok = vfs::open(b"/OTHER.TXT", vfs::O_READ)
        .and_then(|f| vfs::read(&f, &mut other))
        .is_ok_and(|n| n == 1500 && other[..1500].iter().all(|&x| x == b'C'));
    let removed = vfs::unlink(b"/SHARED.TXT").is_ok() && vfs::unlink(b"/OTHER.TXT").is_ok();
    let synced = vfs::sync().is_ok();
    let free1 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    let live = vfs::live_files();
    kprintln!(
        "OSX|{}|ktest|file_shared|wrote_a={}|size_seen_by_a={}|wrote_b={}|stale_write={}|busy={}|wrote_c={}|shared_ok={}|other_ok={}|removed={}|synced={}|clusters_restored={}|live_files={}",
        BUILD_ID,
        wrote_a.map_or(-1, |n| n as i64),
        size_seen_by_a,
        wrote_b.map_or(-1, |n| n as i64),
        stale_write.map_or("ok", |e| e.code()),
        busy.map_or("ok", |e| e.code()),
        wrote_c.map_or(-1, |n| n as i64),
        u8::from(shared_ok),
        u8::from(other_ok),
        u8::from(removed),
        u8::from(synced),
        u8::from(free1 == free0),
        live
    );
    if size_seen_by_a != 0 || stale_write != Some(FsError::Range) || !shared_ok {
        fail("the first open did not see the truncation through the second")
    }
    if busy != Some(FsError::Busy) || !removed {
        fail("an open file was removable, or a closed one was not")
    }
    if !other_ok || free1 != free0 || live != 0 || !synced {
        fail("the other file's clusters or the volume's accounting were wrong")
    }
    pass("opens of one file share its entry; an open file cannot be removed")
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

// ---- WP-105: delete and truncate under a failing disk --------------------------------------

/// Bytes of a fault-case file: three clusters, every byte a function of the file and the offset.
const FAULT_LEN: usize = 1536;

fn fault_bytes(n: u32) -> alloc::vec::Vec<u8> {
    (0..FAULT_LEN)
        .map(|i| (n as usize * 37 + i * 7 + i / 512) as u8)
        .collect()
}

fn fault_path(kind: u8, n: u32) -> alloc::vec::Vec<u8> {
    alloc::format!("/{}{:02}.TXT", kind as char, n).into_bytes()
}

/// What the volume holds under `path`, read through a fresh lookup (the stored entry and the
/// FAT, not an open file's node): 0 no such name, 1 the whole file with the bytes `want`,
/// 2 an empty file (size 0, no first cluster), 3 anything else (a name whose chain or bytes are
/// not its own).
fn fault_state(path: &[u8], want: &[u8]) -> u8 {
    crate::fs::with(|fs| {
        let e = match fs.lookup(path) {
            Ok(e) => e,
            Err(FsError::NotFound) => return Ok(0),
            Err(_) => return Ok(3),
        };
        if e.size == 0 && e.first == 0 {
            return Ok(2);
        }
        let mut buf = alloc::vec![0u8; want.len() + 1];
        Ok(match fs.read(&e, 0, &mut buf) {
            Ok(n) if n == want.len() && e.size as usize == n && buf[..n] == *want => 1,
            _ => 3,
        })
    })
    .unwrap_or(3)
}

/// WP-124: the hook's once mode, shown before a sweep leans on it. With the next disk write
/// refused and no other, a write to a new, empty file answers an I/O error (its first disk
/// write is the one refused); the same call made again, the hook still armed, is taken whole.
/// Returns (refused, next_taken). Were the mode to refuse every later write too, the sweeps
/// that follow would leave the images of the older cases and show nothing of their own.
fn fault_once_shown() -> (bool, bool) {
    use crate::fs::vfs;
    let bytes = [0x4Fu8; 64];
    let Ok(a) = vfs::open(b"/ONCE.TXT", vfs::O_READ | vfs::O_WRITE | vfs::O_CREATE) else {
        fail("could not create the file that shows the once mode")
    };
    if vfs::sync().is_err() {
        fail("could not sync before the once mode is shown")
    }
    crate::block::arm_write_fault_once(1);
    let first = vfs::write(&a, &bytes);
    let second = vfs::write(&a, &bytes);
    crate::block::disarm_write_fault();
    drop(a);
    let whole = fault_state(b"/ONCE.TXT", &bytes) == 1;
    (
        matches!(first, Err(FsError::Io(_))),
        matches!(second, Ok(64)) && whole,
    )
}

/// The fields a once-mode sweep adds to its line: whether the mode was shown, and how many of
/// the sweep's calls asked for exactly N disk writes (the refused one was their last).
fn fault_once_tail(shown: (bool, bool), stopped: u32) -> String {
    alloc::format!(
        "|once_refused={}|once_next_ok={}|stopped={}",
        u8::from(shown.0),
        u8::from(shown.1),
        stopped
    )
}

/// A once-mode sweep's own conditions, judged after its line is printed so the line is there
/// to read when one of them fails.
fn fault_once_judge(shown: (bool, bool), stopped: u32, writes: u32) {
    if !shown.0 {
        fail("with its first disk write refused alone, a write did not answer an I/O error")
    }
    if !shown.1 {
        fail("the write after the refused one was not taken")
    }
    if stopped != writes {
        fail("a call did not ask for exactly N disk writes: it wrote after the refused one or ended before it")
    }
}

/// TST-M3-FAT32-FAULT-UNLINK, first boot (WP-105, RSK-027; files.md v1.5): a delete that fails
/// at any of its disk writes leaves either the whole file or no name, never a name whose chain
/// runs into free clusters. A control delete counts the writes of one delete (W); then for
/// every N from 1 to W a fresh three-cluster file is deleted with the test kernel's hook
/// refusing write N and all after it, and the volume is read back. With `once`
/// (TST-M3-FAT32-FAULT-ONE-UNLINK, WP-124) the hook refuses write N alone.
fn fat32_fault_unlink(once: bool) -> ! {
    use crate::fs::vfs;
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let name = if once {
        "fat32_fault_unlink_one"
    } else {
        "fat32_fault_unlink"
    };
    let shown = if once {
        fault_once_shown()
    } else {
        (true, true)
    };
    let mut stopped = 0u32;
    let make = |n: u32| {
        let path = fault_path(b'U', n);
        crate::fs::with(|fs| {
            let mut e = fs.create(&path)?;
            fs.write(&mut e, 0, &fault_bytes(n))?;
            fs.sync()
        })
        .is_ok()
    };
    if !make(0) {
        fail("could not create the control file")
    }
    let w0 = crate::block::writes();
    let control = vfs::unlink(&fault_path(b'U', 0));
    let writes = crate::block::writes() - w0;
    let (mut failed, mut io, mut gone, mut retry_gone, mut kept, mut bad) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    for n in 1..=writes {
        if !make(n) {
            fail("could not create a file of the sweep")
        }
        let path = fault_path(b'U', n);
        let w1 = crate::block::writes();
        if once {
            crate::block::arm_write_fault_once(n);
        } else {
            crate::block::arm_write_fault(n);
        }
        let r = vfs::unlink(&path);
        stopped += u32::from(crate::block::writes() - w1 == n);
        crate::block::disarm_write_fault();
        failed += u32::from(r.is_err());
        io += u32::from(matches!(r, Err(FsError::Io(_))));
        match fault_state(&path, &fault_bytes(n)) {
            0 => {
                gone += 1;
                // The name is gone: a second delete says so (files.md v1.5).
                retry_gone += u32::from(vfs::unlink(&path) == Err(FsError::NotFound));
            }
            1 => kept += 1,
            _ => bad += 1,
        }
    }
    let synced = vfs::sync().is_ok();
    let tail = if once {
        fault_once_tail(shown, stopped)
    } else {
        String::new()
    };
    kprintln!(
        "OSX|{}|ktest|{}|control={}|writes={}|failed={}|io={}|gone={}|retry_gone={}|kept={}|bad={}|synced={}|live_files={}{}",
        BUILD_ID,
        name,
        control.map_or_else(|e| e.code(), |_| "ok"),
        writes,
        failed,
        io,
        gone,
        retry_gone,
        kept,
        bad,
        u8::from(synced),
        vfs::live_files(),
        tail
    );
    if once {
        fault_once_judge(shown, stopped, writes);
    }
    if control.is_err() || writes < 3 || failed != writes || io != writes || !synced {
        fail("the sweep did not run as planned")
    }
    if bad != 0 || gone + kept != writes {
        fail("a failed delete left a name that is neither whole nor gone")
    }
    if retry_gone != gone {
        fail("a second delete of a name that is gone did not answer not found")
    }
    pass("a failed delete leaves the whole file or no name")
}

/// TST-M3-FAT32-FAULT-TRUNCATE, first boot (WP-105, RSK-027; files.md v1.5): a truncation that
/// fails at any of its disk writes leaves the file whole or empty, on the disk and in the node
/// every open shares alike. For every N a file is written through one open, and a second open
/// with O_TRUNCATE runs with write N and all after it refused. With `once`
/// (TST-M3-FAT32-FAULT-ONE-TRUNCATE, WP-124) the hook refuses write N alone.
fn fat32_fault_truncate(once: bool) -> ! {
    use crate::fs::vfs;
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let name = if once {
        "fat32_fault_truncate_one"
    } else {
        "fat32_fault_truncate"
    };
    let shown = if once {
        fault_once_shown()
    } else {
        (true, true)
    };
    let mut stopped = 0u32;
    let rw = vfs::O_READ | vfs::O_WRITE;
    let (mut writes, mut failed, mut io, mut kept, mut emptied, mut bad, mut node_differs) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    // What the first open sees afterwards and what a second attempt does.
    let (mut a_whole, mut a_refused, mut a_empty, mut retry_ok) = (0u32, 0u32, 0u32, 0u32);
    let mut control_ok = false;
    let mut n = 0u32;
    // n = 0 is the control: no fault, it counts the writes of one truncation.
    while n == 0 || n <= writes {
        let path = fault_path(b'T', n);
        let Ok(a) = vfs::open(&path, rw | vfs::O_CREATE) else {
            fail("could not create a file of the sweep")
        };
        if !matches!(vfs::write(&a, &fault_bytes(n)), Ok(FAULT_LEN)) || vfs::sync().is_err() {
            fail("could not write a file of the sweep")
        }
        let w0 = crate::block::writes();
        if n > 0 && once {
            crate::block::arm_write_fault_once(n);
        } else if n > 0 {
            crate::block::arm_write_fault(n);
        }
        let b = vfs::open(&path, rw | vfs::O_TRUNCATE);
        stopped += u32::from(n > 0 && crate::block::writes() - w0 == n);
        crate::block::disarm_write_fault();
        let node = {
            let f = a.lock();
            let e = f.node.lock();
            (e.first, e.size)
        };
        let stored = crate::fs::with(|fs| fs.lookup(&path)).map(|e| (e.first, e.size));
        let state = fault_state(&path, &fault_bytes(n));
        if n == 0 {
            writes = crate::block::writes() - w0;
            control_ok = b.is_ok() && state == 2 && stored == Ok(node);
        } else {
            failed += u32::from(b.is_err());
            io += u32::from(matches!(b, Err(FsError::Io(_))));
            node_differs += u32::from(stored != Ok(node));
            match state {
                1 => {
                    kept += 1;
                    // Nothing changed: the first open reads its bytes back.
                    let mut back = alloc::vec![0u8; FAULT_LEN + 1];
                    let _ = vfs::seek(&a, 0);
                    a_whole += u32::from(
                        matches!(vfs::read(&a, &mut back), Ok(FAULT_LEN))
                            && back[..FAULT_LEN] == fault_bytes(n)[..],
                    );
                }
                2 => {
                    emptied += 1;
                    // The first open's position (the old end) is past the new end: a write
                    // there is refused, not sent into the freed clusters; from 0 it reads
                    // nothing; and a second truncating open succeeds (files.md v1.5).
                    a_refused += u32::from(vfs::write(&a, b"stale").err() == Some(FsError::Range));
                    let mut one = [0u8; 16];
                    let _ = vfs::seek(&a, 0);
                    a_empty += u32::from(matches!(vfs::read(&a, &mut one), Ok(0)));
                    retry_ok += u32::from(vfs::open(&path, rw | vfs::O_TRUNCATE).is_ok());
                }
                _ => bad += 1,
            }
        }
        drop(b);
        drop(a);
        n += 1;
    }
    let synced = vfs::sync().is_ok();
    let tail = if once {
        fault_once_tail(shown, stopped)
    } else {
        String::new()
    };
    kprintln!(
        "OSX|{}|ktest|{}|control={}|writes={}|failed={}|io={}|kept={}|a_whole={}|emptied={}|a_refused={}|a_empty={}|retry_ok={}|bad={}|node_differs={}|synced={}|live_files={}{}",
        BUILD_ID,
        name,
        u8::from(control_ok),
        writes,
        failed,
        io,
        kept,
        a_whole,
        emptied,
        a_refused,
        a_empty,
        retry_ok,
        bad,
        node_differs,
        u8::from(synced),
        vfs::live_files(),
        tail
    );
    if once {
        fault_once_judge(shown, stopped, writes);
    }
    if !control_ok || writes < 3 || failed != writes || io != writes || !synced {
        fail("the sweep did not run as planned")
    }
    if bad != 0 || node_differs != 0 || kept + emptied != writes {
        fail("a failed truncation left a file that is neither whole nor empty")
    }
    if a_whole != kept || a_refused != emptied || a_empty != emptied || retry_ok != emptied {
        fail("the first open or a second attempt did not see the file as the disk holds it")
    }
    pass("a failed truncation leaves the file whole or empty, on disk and in its node")
}

/// How many names `/<kind>NN.TXT` (NN below 32) hold the whole file of `len` bytes, how many
/// are empty, and how many are neither.
fn fault_count(kind: u8, len: usize) -> (u32, u32, u32) {
    let (mut kept, mut empty, mut bad) = (0u32, 0u32, 0u32);
    for n in 0..32 {
        match fault_state(&fault_path(kind, n), &fault_bytes(n)[..len]) {
            1 => kept += 1,
            2 => empty += 1,
            3 => bad += 1,
            _ => {}
        }
    }
    (kept, empty, bad)
}

/// The second boot of the two fault cases: a kernel with no memory of the first boot reads the
/// image. Every name of the sweep is whole, empty or gone; then a new file is written (it takes
/// the lowest free clusters) and the names are read again: none of them reads the new bytes.
fn fat32_fault_check(kind: u8, name: &'static str) -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let count = || fault_count(kind, FAULT_LEN);
    let (kept, empty, bad) = count();
    let fresh = alloc::vec![0x5Au8; FAULT_LEN];
    let after_ok = crate::fs::with(|fs| {
        let mut e = fs.create(b"/AFTER.TXT")?;
        fs.write(&mut e, 0, &fresh)?;
        fs.sync()
    })
    .is_ok()
        && fault_state(b"/AFTER.TXT", &fresh) == 1;
    let (kept_after, empty_after, bad_after) = count();
    kprintln!(
        "OSX|{}|ktest|{}|kept={}|empty={}|bad={}|after_ok={}|kept_after={}|empty_after={}|bad_after={}",
        BUILD_ID,
        name,
        kept,
        empty,
        bad,
        u8::from(after_ok),
        kept_after,
        empty_after,
        bad_after
    );
    if bad != 0 || bad_after != 0 || !after_ok {
        fail("a name of the sweep is not its own file after the restart")
    }
    if (kept, empty) != (kept_after, empty_after) {
        fail("a new file changed a name of the sweep")
    }
    pass("after the restart every name of the sweep is whole, empty or gone")
}

// ---- WP-118: a write under a failing disk ----------------------------------------------------

/// One sweep of TST-M3-FAT32-FAULT-WRITE: for N = 0 (the control: no fault, it counts the
/// writes of the call) and every N up to that count, a file `/<kind>NN.TXT` holding `before`
/// bytes is written `add` more bytes through one open with disk write N and all after it
/// refused. Returns (writes, control_ok, failed, io, node_differs, unchanged, bad, ghost,
/// retry_ok, pos_moved, stale_sync): after a failed call the node every open shares must equal
/// the stored entry (`node_differs`), the open's position must not have moved (`pos_moved`),
/// the name must still hold its `before` bytes (`unchanged`), a sync must answer success and
/// leave `stat` and the node agreeing on the size (`stale_sync` counts the others), and a read
/// through the same
/// open from 0 must return those bytes and no more (`ghost` counts the reads that returned
/// anything else). With `retry`, the same call is made again and must leave the whole file.
/// With `once` (WP-131) the hook refuses write N alone; the last number returned, `stopped`,
/// counts the calls that asked for exactly N disk writes (the refused one was their last).
fn fault_write_sweep(kind: u8, before: usize, add: usize, retry: bool, once: bool) -> [u32; 12] {
    use crate::fs::vfs;
    let rw = vfs::O_READ | vfs::O_WRITE;
    let (mut writes, mut control_ok) = (0u32, 0u32);
    let (mut failed, mut io, mut node_differs, mut unchanged, mut bad, mut ghost, mut retry_ok) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    let (mut pos_moved, mut stale_sync, mut stopped) = (0u32, 0u32, 0u32);
    let mut n = 0u32;
    while n == 0 || n <= writes {
        let path = fault_path(kind, n);
        let all = fault_bytes(n);
        let Ok(a) = vfs::open(&path, rw | vfs::O_CREATE) else {
            fail("could not create a file of the sweep")
        };
        if before > 0 && !matches!(vfs::write(&a, &all[..before]), Ok(k) if k == before) {
            fail("could not write the first part of a file of the sweep")
        }
        if vfs::sync().is_err() {
            fail("could not sync before the sweep's write")
        }
        let w0 = crate::block::writes();
        if n > 0 && once {
            crate::block::arm_write_fault_once(n);
        } else if n > 0 {
            crate::block::arm_write_fault(n);
        }
        let r = vfs::write(&a, &all[before..before + add]);
        stopped += u32::from(n > 0 && crate::block::writes() - w0 == n);
        crate::block::disarm_write_fault();
        let node = {
            let f = a.lock();
            let e = f.node.lock();
            (e.first, e.size)
        };
        let stored = crate::fs::with(|fs| fs.lookup(&path)).map(|e| (e.first, e.size));
        if n == 0 {
            writes = crate::block::writes() - w0;
            control_ok = u32::from(
                matches!(r, Ok(k) if k == add)
                    && stored == Ok(node)
                    && fault_state(&path, &all[..before + add]) == 1,
            );
        } else {
            failed += u32::from(r.is_err());
            io += u32::from(matches!(r, Err(FsError::Io(_))));
            node_differs += u32::from(stored != Ok(node));
            pos_moved += u32::from(a.lock().pos != before as u64);
            // The sync must answer success (the disk works again) and leave `stat` and the
            // node agreeing on the size.
            let synced = vfs::sync().is_ok();
            let stat_size = vfs::stat(&path).map(|st| st.size);
            stale_sync += u32::from(!synced || stat_size != Ok(u64::from(node.1)));
            let state = fault_state(&path, &all[..before]);
            if (before == 0 && state == 2) || (before > 0 && state == 1) {
                unchanged += 1;
            } else {
                bad += 1;
            }
            // Through the same open, from 0: the bytes the name holds and no more.
            let mut back = alloc::vec![0u8; before + add + 1];
            let pos = a.lock().pos;
            let _ = vfs::seek(&a, 0);
            let got = vfs::read(&a, &mut back);
            ghost += u32::from(!matches!(got, Ok(k) if k == before && back[..k] == all[..k]));
            if retry {
                let _ = vfs::seek(&a, pos.min(before as u64));
                retry_ok += u32::from(
                    matches!(vfs::write(&a, &all[before..before + add]), Ok(k) if k == add)
                        && fault_state(&path, &all[..before + add]) == 1,
                );
            }
        }
        drop(a);
        n += 1;
    }
    [
        writes,
        control_ok,
        failed,
        io,
        node_differs,
        unchanged,
        bad,
        ghost,
        retry_ok,
        pos_moved,
        stale_sync,
        stopped,
    ]
}

/// Bytes of the second sweep's files before the append, and the append: one cluster each.
const FAULT_HALF: usize = 512;

/// TST-M3-FAT32-FAULT-WRITE, first boot (WP-118, RSK-027): a write that fails at any of its
/// disk writes leaves the file as it was, in its stored entry and in the node every open
/// shares alike. Three sweeps: three clusters written to a new file (and the same write made
/// again, which must succeed), one cluster appended to a file of one cluster, and (WP-120)
/// that append made again after each failure, which must succeed too. With `once`
/// (TST-M3-FAT32-FAULT-ONE-WRITE, WP-131) the hook refuses write N alone: the mode is shown
/// first, and every failed call must have asked for exactly N disk writes.
fn fat32_fault_write(once: bool) -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let case = if once {
        "fat32_fault_write_one"
    } else {
        "fat32_fault_write"
    };
    let shown = if once {
        fault_once_shown()
    } else {
        (true, true)
    };
    let w = fault_write_sweep(b'W', 0, FAULT_LEN, true, once);
    let x = fault_write_sweep(b'X', FAULT_HALF, FAULT_HALF, false, once);
    // WP-120: the same append, made again after each failure through the same open.
    let y = fault_write_sweep(b'Y', FAULT_HALF, FAULT_HALF, true, once);
    let synced = crate::fs::vfs::sync().is_ok();
    for (name, v) in [("new", &w), ("append", &x), ("again", &y)] {
        let stopped = if once {
            alloc::format!("|stopped={}", v[11])
        } else {
            String::new()
        };
        kprintln!(
            "OSX|{}|ktest|{}|sweep={}|control={}|writes={}|failed={}|io={}|node_differs={}|pos_moved={}|stale_sync={}|unchanged={}|bad={}|ghost={}|retry_ok={}{}",
            BUILD_ID,
            case,
            name,
            v[1],
            v[0],
            v[2],
            v[3],
            v[4],
            v[9],
            v[10],
            v[5],
            v[6],
            v[7],
            v[8],
            stopped
        );
    }
    let mode = if once {
        alloc::format!(
            "|once_refused={}|once_next_ok={}",
            u8::from(shown.0),
            u8::from(shown.1)
        )
    } else {
        String::new()
    };
    kprintln!(
        "OSX|{}|ktest|{}|synced={}|live_files={}{}",
        BUILD_ID,
        case,
        u8::from(synced),
        crate::fs::vfs::live_files(),
        mode
    );
    if once {
        for v in [&w, &x, &y] {
            fault_once_judge(shown, v[11], v[0]);
        }
    }
    for v in [&w, &x, &y] {
        if v[1] != 1 || v[0] < 3 || v[2] != v[0] || v[3] != v[0] {
            fail("the sweep did not run as planned")
        }
        if v[4] != 0 || v[6] != 0 || v[7] != 0 || v[5] != v[0] || v[9] != 0 || v[10] != 0 {
            fail("a failed write left the file, its node or the open's position changed")
        }
    }
    if w[8] != w[0] || y[8] != y[0] || !synced {
        fail("the same write made again did not leave the whole file")
    }
    pass("a failed write leaves the file as it was, on disk and in its node")
}

/// The second boot of TST-M3-FAT32-FAULT-WRITE: a kernel with no memory of the first boot
/// reads the image: every file of the first sweep is whole (its write was made again), every
/// file of the second sweep holds its first cluster (the control both), every file of the
/// third holds both clusters (its append was made again), none is anything else; a new file
/// changes none of them.
fn fat32_fault_write_check(case: &'static str) -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let count = || {
        let w = fault_count(b'W', FAULT_LEN);
        let x1 = fault_count(b'X', FAULT_HALF);
        let x2 = fault_count(b'X', 2 * FAULT_HALF);
        // A file of the second sweep is its first cluster, or (the control) both clusters;
        // every file of the third, whose append was made again, is both.
        let y = fault_count(b'Y', 2 * FAULT_HALF);
        (w.0, x1.0, x2.0, y.0, w.2, x1.2 - x2.0 + y.1 + y.2)
    };
    let (w_whole, x_first, x_both, y_both, w_bad, x_bad) = count();
    let fresh = alloc::vec![0x5Au8; FAULT_LEN];
    let after_ok = crate::fs::with(|fs| {
        let mut e = fs.create(b"/AFTER.TXT")?;
        fs.write(&mut e, 0, &fresh)?;
        fs.sync()
    })
    .is_ok()
        && fault_state(b"/AFTER.TXT", &fresh) == 1;
    let after = count();
    kprintln!(
        "OSX|{}|ktest|{}|new_whole={}|append_first={}|append_both={}|again_both={}|bad={}|after_ok={}|same_after={}",
        BUILD_ID,
        case,
        w_whole,
        x_first,
        x_both,
        y_both,
        w_bad + x_bad,
        u8::from(after_ok),
        u8::from(after == (w_whole, x_first, x_both, y_both, w_bad, x_bad))
    );
    if w_bad + x_bad != 0 || !after_ok || after != (w_whole, x_first, x_both, y_both, w_bad, x_bad)
    {
        fail("a name of the sweeps is not its own file after the restart")
    }
    if w_whole == 0 || x_first == 0 || x_both != 1 || y_both == 0 {
        fail("a whole sweep, or the control of the second, is missing after the restart")
    }
    pass("after the restart every file of the write sweeps is its own")
}

// ---- WP-133: a create that must grow its directory, under a failing disk -------------------

/// Entries one cluster of the lab's volume holds (a cluster is one sector).
const DIR_SLOTS: u32 = 16;

/// The names `/DIR` holds and the clusters of its chain along the first FAT copy.
fn fault_dir_state() -> Option<(u32, u32)> {
    crate::fs::with(|fs| {
        let names = fs.list(b"/DIR", |_| {})?;
        let first = fs.lookup(b"/DIR")?.first;
        Ok((names, fs.chain_clusters(first)?))
    })
    .ok()
}

/// Fills `/DIR` to the end of its last cluster with empty files `/DIR/Gnnn.TXT`, so that the
/// next create must grow the directory (the two dot entries take two slots of the first
/// cluster; nothing in this directory is ever deleted). False when a create fails or the
/// directory is not exactly full afterwards.
fn fault_dir_fill(next: &mut u32) -> bool {
    let Some((names, clusters)) = fault_dir_state() else {
        return false;
    };
    let free = (clusters * DIR_SLOTS).saturating_sub(names + 2);
    for _ in 0..free {
        let path = alloc::format!("/DIR/G{:03}.TXT", *next).into_bytes();
        *next += 1;
        if crate::fs::with(|fs| fs.create(&path).map(|_| ())).is_err() {
            return false;
        }
    }
    fault_dir_state() == Some((names + free, clusters))
}

/// Clusters dirtied before the create sweep: more than the growths of both boots take.
const DIRTY_CLUSTERS: u32 = 24;

/// Dirties the lowest free clusters, which the growths of the sweep then take: a file whose
/// every 32 bytes read as the live entry of an empty file (`STRAYnnn.TXT`) is written and
/// deleted. On the lab's image the free clusters are zeros, and a new directory cluster that
/// was not zeroed would read as an empty one all the same; after this it lists names no create
/// made. True when the file took exactly `DIRTY_CLUSTERS` clusters and deleting it gave every
/// one of them back.
fn fault_dirty() -> bool {
    let mut bytes = alloc::vec![0u8; DIRTY_CLUSTERS as usize * 512];
    for (i, slot) in bytes.chunks_mut(32).enumerate() {
        slot[..11].copy_from_slice(alloc::format!("STRAY{:03}TXT", i).as_bytes());
        slot[11] = 0x20;
    }
    crate::fs::with(|fs| {
        let free = fs.free_clusters()?;
        let mut e = fs.create(b"/DIRTY.BIN")?;
        fs.write(&mut e, 0, &bytes)?;
        let took = free - fs.free_clusters()?;
        fs.unlink(b"/DIRTY.BIN")?;
        Ok(took == DIRTY_CLUSTERS && fs.free_clusters()? == free)
    })
    .unwrap_or(false)
}

/// The names `/DIR` lists that no create made: the entries `fault_dirty` left in the free
/// clusters read as `STRAYnnn.TXT`.
fn fault_dir_strays() -> u32 {
    let mut n = 0u32;
    let _ =
        crate::fs::with(|fs| fs.list(b"/DIR", |e| n += u32::from(e.name.starts_with(b"STRAY"))));
    n
}

/// `/DIR` as one FAT copy gives it (copy 0 is the copy the kernel reads): the clusters of its
/// chain, the names a reader of that copy would list, whether the chain is sound there, and a
/// print of those names (FNV-1a over the 11 bytes of each, in the order read). The chain and
/// the names are read by the test itself from the disk and not through the file system's
/// reader; the directory's first cluster is the one the file system's lookup gives, and the
/// volume's numbers are the ones its mount parsed. The chain is not sound when it stands on a
/// cluster that is free, reserved or bad in that copy, leaves the volume or does not end.
/// Names are counted as `list` counts them, up to the first end mark; the chain is followed in
/// the FAT alone, past any end mark (WP-138).
fn fault_dir_in_copy(copy: u32) -> Option<(u32, u32, bool, u64)> {
    crate::fs::with(|fs| {
        if copy >= fs.fats {
            return Err(FsError::Corrupt);
        }
        let entry = |c: u32| -> Result<u32, FsError> {
            let mut s = [0u8; 512];
            let off = c as usize * 4;
            let sector = u64::from(fs.reserved + copy * fs.fat_sectors) + (off / 512) as u64;
            crate::block::read(sector, &mut s)?;
            let o = off % 512;
            Ok(u32::from_le_bytes([s[o], s[o + 1], s[o + 2], s[o + 3]]) & 0x0FFF_FFFF)
        };
        let mut c = fs.lookup(b"/DIR")?.first;
        let (mut clusters, mut names, mut ended) = (0u32, 0u32, false);
        let mut print = 0xcbf2_9ce4_8422_2325u64;
        while clusters < 4096 && c >= 2 && c < fs.clusters + 2 {
            let next = entry(c)?;
            if next == 0 || next == 1 || next == 0x0FFF_FFF7 {
                break;
            }
            clusters += 1;
            let base =
                u64::from(fs.data_start) + u64::from(c - 2) * u64::from(fs.sectors_per_cluster);
            for i in 0..fs.sectors_per_cluster {
                if ended {
                    break;
                }
                let mut s = [0u8; 512];
                crate::block::read(base + u64::from(i), &mut s)?;
                for e in s.chunks(32) {
                    if e[0] == 0 {
                        ended = true;
                        break;
                    }
                    if e[0] != 0xE5 && e[11] & 0x0F != 0x0F && e[11] & 0x08 == 0 && e[0] != b'.' {
                        names += 1;
                        for b in &e[..11] {
                            print = (print ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
                        }
                    }
                }
            }
            if next >= 0x0FFF_FFF8 {
                return Ok((clusters, names, true, print));
            }
            c = next;
        }
        Ok((clusters, names, false, print))
    })
    .ok()
}

/// The two FAT copies compared whole by the test itself, entry by entry (the two reserved
/// entries left out): the clusters marked in the second copy and free in the first, the
/// clusters marked in the first and free in the second, and the clusters marked in both with
/// different values (a link one copy holds and the other does not). An entry that differs
/// between the copies in its 28 low bits is one of the three (the 4 high bits are left out). The second copy is written first, so a refusal
/// between the two writes of a mark leaves one cluster of the first kind and a refusal between
/// the two writes of a link one of the third; a create frees nothing, so after one a cluster
/// of the second kind says the second copy is behind the first (WP-138).
fn fault_fat_diff() -> Option<(u32, u32, u32)> {
    const CHUNK: u32 = 32;
    crate::fs::with(|fs| {
        if fs.fats < 2 {
            return Err(FsError::Corrupt);
        }
        let mut a = alloc::vec![0u8; CHUNK as usize * 512];
        let mut b = alloc::vec![0u8; CHUNK as usize * 512];
        let (mut ahead, mut behind, mut links) = (0u32, 0u32, 0u32);
        let mut s = 0u32;
        while s < fs.fat_sectors {
            let n = CHUNK.min(fs.fat_sectors - s) as usize * 512;
            crate::block::read(u64::from(fs.reserved + s), &mut a[..n])?;
            crate::block::read(u64::from(fs.reserved + fs.fat_sectors + s), &mut b[..n])?;
            for (i, (x, y)) in a[..n].chunks(4).zip(b[..n].chunks(4)).enumerate() {
                let c = s * 128 + i as u32;
                if c < 2 || c >= fs.clusters + 2 {
                    continue;
                }
                let first = u32::from_le_bytes([x[0], x[1], x[2], x[3]]) & 0x0FFF_FFFF;
                let second = u32::from_le_bytes([y[0], y[1], y[2], y[3]]) & 0x0FFF_FFFF;
                ahead += u32::from(first == 0 && second != 0);
                behind += u32::from(first != 0 && second == 0);
                links += u32::from(first != 0 && second != 0 && first != second);
            }
            s += CHUNK;
        }
        Ok((ahead, behind, links))
    })
    .ok()
}

/// The judgements on what is read along the second FAT copy after every create under the hook,
/// the same for the three create cases (WP-138).
fn fault_second_judge(free: u32, names: u32, shorter: u32, first_marks: u32) {
    if free != 0 {
        fail("after a create under the hook the directory's chain along the second FAT copy stands on a cluster that is free there, or does not end")
    }
    if names != 0 {
        fail("after a create under the hook the two FAT copies do not list the same names in the directory")
    }
    if shorter != 0 || first_marks != 0 {
        fail("after a create under the hook the second FAT copy is behind the first: the directory's chain is shorter along it, or a cluster is marked in the first copy and free in the second")
    }
}

fn fault_create_path(n: u32) -> alloc::vec::Vec<u8> {
    alloc::format!("/DIR/C{:02}.TXT", n).into_bytes()
}

/// TST-M3-FAT32-FAULT-CREATE, first boot (WP-133, RSK-027; files.md v1.12): a create that must
/// grow its directory and fails at any of its disk writes leaves no name and no entry that is
/// not a name's own, and the same create made again succeeds. The free clusters the growths
/// will take are dirtied with bytes that read as entries; `/DIR` is filled to its cluster's
/// end; a control create counts the writes of a growth (W); then for every N from 1
/// to W the directory is filled again and a create runs with the test kernel's hook refusing
/// write N and all after it, then once more with the disk working.
///
/// TST-M3-FAT32-FAULT-ONE-CREATE (WP-134; files.md v1.13) is the same sweep with write N alone
/// refused (`once`). There a create that swallows a refusal goes on and answers success, and
/// the case judges by what is read: the names the directory lists that no create made (strays)
/// and the creates that answered success for a name no lookup finds (ghost). The mode is shown
/// first, before the clusters are dirtied, so that its file takes none of them.
///
/// TST-M3-FAT32-FAULT-CREATE-COPIES (WP-138, after its close audit) is the sweep under one
/// refused write once more (`copies`): once the sweep has started it prints the count of the
/// sweep's calls and what is read along the second FAT copy after every create under the hook,
/// and judges nothing but the latter (the checks before the sweep stop it as in the other
/// create cases).
fn fat32_fault_create(once: bool, copies: bool) -> ! {
    use crate::fs::vfs;
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let case = if once {
        "fat32_fault_create_one"
    } else {
        "fat32_fault_create"
    };
    let shown = if once {
        fault_once_shown()
    } else {
        (true, true)
    };
    let open_new =
        |path: &[u8]| vfs::open(path, vfs::O_READ | vfs::O_WRITE | vfs::O_CREATE).map(|_| ());
    let absent =
        |path: &[u8]| crate::fs::with(|fs| fs.lookup(path)).err() == Some(FsError::NotFound);
    let dirty = fault_dirty();
    let mut filler = 0u32;
    if !fault_dir_fill(&mut filler) {
        fail("could not fill the directory before the control")
    }
    let Some((names0, clusters0)) = fault_dir_state() else {
        fail("could not read the directory")
    };
    let w0 = crate::block::writes();
    let control = open_new(&fault_create_path(0));
    let writes = crate::block::writes() - w0;
    let control_ok = control.is_ok() && fault_dir_state() == Some((names0 + 1, clusters0 + 1));
    let (mut failed, mut io, mut stopped, mut gone, mut grown) = (0u32, 0u32, 0u32, 0u32, 0u32);
    let (mut retry_ok, mut retry_grew, mut filled) = (0u32, 0u32, 0u32);
    let (mut strays, mut ghost) = (0u32, 0u32);
    let (mut first_same, mut second_free, mut second_longer, mut second_names) =
        (0u32, 0u32, 0u32, 0u32);
    let (mut second_marks, mut second_shorter, mut first_marks) = (0u32, 0u32, 0u32);
    let mut second_links = 0u32;
    let mut calls = 0u32;
    for n in 1..=writes {
        filled += u32::from(fault_dir_fill(&mut filler));
        let path = fault_create_path(n);
        let before = fault_dir_state();
        let w1 = crate::block::writes();
        if once {
            crate::block::arm_write_fault_once(n);
        } else {
            crate::block::arm_write_fault(n);
        }
        let r = open_new(&path);
        stopped += u32::from(crate::block::writes() - w1 == n);
        if !once {
            crate::block::disarm_write_fault();
        }
        failed += u32::from(r.is_err());
        io += u32::from(matches!(r, Err(FsError::Io(_))));
        let after = fault_dir_state();
        strays += fault_dir_strays();
        ghost += u32::from(r.is_ok() && absent(&path));
        // WP-138: the directory as each FAT copy gives it, before the create is made again
        // (the create made again writes over what a failed one left along the second copy).
        let (one, two) = (fault_dir_in_copy(0), fault_dir_in_copy(1));
        first_same += u32::from(one.is_some_and(|d| d.2) && one.map(|d| (d.1, d.0)) == after);
        second_free += u32::from(!two.is_some_and(|d| d.2));
        second_longer += u32::from(matches!((one, two), (Some(a), Some(b)) if b.0 > a.0));
        second_shorter += u32::from(matches!((one, two), (Some(a), Some(b)) if b.0 < a.0));
        // The names of the two copies are compared by their prints: the 11 bytes of every
        // name, in the order read.
        second_names += u32::from(one.map(|d| d.3) != two.map(|d| d.3));
        // Every FAT entry that differs between the copies is of one of three kinds.
        let diff = fault_fat_diff();
        second_marks += u32::from(diff.is_some_and(|d| d.0 > 0));
        first_marks += u32::from(!diff.is_some_and(|d| d.1 == 0));
        second_links += u32::from(diff.is_some_and(|d| d.2 > 0));
        // No name of the failed create, and no other name either: the listing counts what it
        // counted before (an entry read from a new cluster that was not zeroed would add to
        // it: the free clusters were dirtied with entries).
        gone += u32::from(
            absent(&path) && before.is_some() && after.map(|s| s.0) == before.map(|s| s.0),
        );
        grown += u32::from(matches!((before, after), (Some(b), Some(a)) if a.1 > b.1));
        // Under the once mode the create is made again with the hook still armed, past its
        // one refused write: a hook that refused every later write too would refuse this
        // create (the mode is shown beforehand for its first write only, on another file, and
        // the sweep's own numbers are the same under both modes).
        let again = open_new(&path);
        if once {
            crate::block::disarm_write_fault();
        }
        let last = fault_dir_state();
        retry_ok += u32::from(
            again.is_ok()
                && fault_state(&path, &[]) == 2
                && last.map(|s| s.0) == before.map(|s| s.0 + 1),
        );
        retry_grew += u32::from(matches!((after, last), (Some(a), Some(l)) if l.1 > a.1));
        calls += 1;
    }
    let synced = vfs::sync().is_ok();
    let (names, clusters) = fault_dir_state().unwrap_or((0, 0));
    if copies {
        kprintln!(
            "OSX|{}|ktest|fat32_fault_create_copies|calls={}|second_free={}|second_longer={}|second_shorter={}|second_names={}|second_marks={}|second_links={}|first_marks={}",
            BUILD_ID,
            calls,
            second_free,
            second_longer,
            second_shorter,
            second_names,
            second_marks,
            second_links,
            first_marks
        );
        fault_second_judge(second_free, second_names, second_shorter, first_marks);
        pass("between a failed create and the create made again the second FAT copy is as pinned")
    }
    // Both cases' lines carry the second copy's fields (WP-138); the once case adds its own.
    let mode = if once {
        alloc::format!(
            "|strays={}|ghost={}|once_refused={}|once_next_ok={}",
            strays,
            ghost,
            u8::from(shown.0),
            u8::from(shown.1)
        )
    } else {
        String::new()
    };
    kprintln!(
        "OSX|{}|ktest|{}|dirty={}|control={}|writes={}|filled={}|failed={}|io={}|stopped={}|absent={}|grown={}|retry_ok={}|retry_grew={}|names={}|dir_clusters={}|synced={}|live_files={}|first_same={}|second_free={}|second_longer={}|second_names={}|second_marks={}|second_shorter={}|first_marks={}|second_links={}{}",
        BUILD_ID,
        case,
        u8::from(dirty),
        u8::from(control_ok),
        writes,
        filled,
        failed,
        io,
        stopped,
        gone,
        grown,
        retry_ok,
        retry_grew,
        names,
        clusters,
        u8::from(synced),
        vfs::live_files(),
        first_same,
        second_free,
        second_longer,
        second_names,
        second_marks,
        second_shorter,
        first_marks,
        second_links,
        mode
    );
    if !dirty {
        fail("the free clusters were not dirtied before the sweep")
    }
    if first_same != writes {
        fail("the test's own reader of the first FAT copy does not read the directory as the file system does")
    }
    fault_second_judge(second_free, second_names, second_shorter, first_marks);
    if once {
        // strays and ghost are judged before the count of disk writes: under one refused write
        // a swallowed refusal shows in the directory too, not only in that count.
        if strays != 0 {
            fail("after a failed create the directory lists a name that no create made")
        }
        if ghost != 0 {
            fail("a create answered success for a name no lookup finds")
        }
        fault_once_judge(shown, stopped, writes);
    }
    if !control_ok || writes < 3 || filled != writes || !synced {
        fail("the sweep did not run as planned: the control did not add one name and one cluster, or the directory was not filled")
    }
    if failed != writes || io != writes {
        fail("a create whose disk write was refused did not answer an I/O error")
    }
    if stopped != writes {
        fail("a failed create did not ask for exactly N disk writes")
    }
    if gone != writes {
        fail("a failed create left its name, or a name that is not its own")
    }
    if retry_ok != writes {
        fail("the same create made again did not leave the new empty file")
    }
    pass("a failed create leaves no name, and the same create made again succeeds")
}

/// The second boot of TST-M3-FAT32-FAULT-CREATE: a kernel with no memory of the first boot
/// lists the directory: every name of the sweep (the control and one per N) is an empty file,
/// the directory holds the names and the clusters the first boot left, and a new file changes
/// none of them.
fn fat32_fault_create_check(case: &'static str, once: bool) -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let count = || {
        let (mut empty, mut bad) = (0u32, 0u32);
        for n in 0..32 {
            match fault_state(&fault_create_path(n), &[]) {
                2 => empty += 1,
                0 => {}
                _ => bad += 1,
            }
        }
        (empty, bad)
    };
    let (created, bad) = count();
    let (names, clusters) = fault_dir_state().unwrap_or((0, 0));
    let fresh = alloc::vec![0x5Au8; FAULT_LEN];
    let after_ok = crate::fs::with(|fs| {
        let mut e = fs.create(b"/DIR/AFTER.TXT")?;
        fs.write(&mut e, 0, &fresh)?;
        fs.sync()
    })
    .is_ok()
        && fault_state(b"/DIR/AFTER.TXT", &fresh) == 1;
    let (created_after, bad_after) = count();
    let names_after = fault_dir_state().map_or(0, |s| s.0);
    let strays = fault_dir_strays();
    let mode = if once {
        alloc::format!("|strays={}", strays)
    } else {
        String::new()
    };
    kprintln!(
        "OSX|{}|ktest|{}|created={}|bad={}|names={}|dir_clusters={}|after_ok={}|created_after={}|bad_after={}|names_after={}{}",
        BUILD_ID,
        case,
        created,
        bad,
        names,
        clusters,
        u8::from(after_ok),
        created_after,
        bad_after,
        names_after,
        mode
    );
    if once && strays != 0 {
        fail("after the restart the directory lists a name that no create made")
    }
    if bad != 0 || bad_after != 0 || !after_ok {
        fail("a name of the sweep is not its own empty file after the restart")
    }
    if created == 0 || created_after != created || names_after != names + 1 {
        fail("the directory does not hold the names the first boot left, and one more")
    }
    pass("after the restart every created name is an empty file of its own")
}

// ---- WP-121: a write on a volume that runs out ------------------------------------------------

/// TST-M3-FAT32-DISK-FULL (WP-121, RSK-033; files.md v1.7): a write the volume cannot hold
/// whole answers no space and changes nothing: no sector is written, no cluster taken, and
/// the file, its node and the open's position are what they were; a write that fits is made
/// whole, down to the volume's last cluster. The test kernel's hook ends the volume, for the
/// allocator, just before a chosen free cluster: the allocator's own scan finds nothing past
/// it. Four files: A, empty, is refused three clusters with two left, takes the two, is
/// refused one byte more and a write that overwrites one cluster and needs a third, and is
/// overwritten in place with nothing left; B, half a cluster, is refused a write that needs
/// a second cluster and filled to the end of its own; C, empty, is refused one byte; D, whose
/// chain is one cluster longer than its size (an append whose entry write was refused before
/// the volume was ended), is written into that cluster with nothing left. A's removal gives
/// two clusters back: C takes one, B is extended by the other, and C is refused one more.
/// Then the files are removed and the free count is what it was: the host's ordinary checks
/// judge the image.
fn fat32_disk_full() -> ! {
    use crate::fs::vfs;
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let rw = vfs::O_READ | vfs::O_WRITE;
    let (all, other) = (fault_bytes(1), fault_bytes(2));
    let (half, one, two) = (FAULT_HALF / 2, FAULT_HALF, 2 * FAULT_HALF);
    let size_of = |path: &[u8]| vfs::stat(path).map_or(u64::MAX, |st| st.size);
    // How many clusters the stored entry's chain holds (u32::MAX when it cannot be walked).
    let chain_of = |path: &[u8]| {
        vfs::stat(path)
            .and_then(|st| crate::fs::with(|fs| fs.chain_clusters(st.first_cluster)))
            .unwrap_or(u32::MAX)
    };
    let node_size = |f: &vfs::FileRef| f.lock().node.lock().size;
    // One write through an open: its answer, the sectors it wrote to the device, and how far
    // the open's position moved.
    let attempt = |f: &vfs::FileRef, data: &[u8]| {
        let (w0, p0) = (crate::block::writes(), f.lock().pos);
        let r = vfs::write(f, data);
        (r, crate::block::writes() - w0, f.lock().pos - p0)
    };
    let show = |r: &Result<usize, FsError>| match r {
        Ok(n) => alloc::format!("{}", n),
        Err(e) => alloc::string::String::from(e.code()),
    };
    // A refused seek would leave the next write somewhere else than the case says.
    let seek_to = |f: &vfs::FileRef, pos: usize| {
        if vfs::seek(f, pos as u64) != Ok(pos as u64) {
            fail("could not move an open's position inside its file")
        }
    };

    let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
        vfs::open(b"/FULL1.TXT", rw | vfs::O_CREATE),
        vfs::open(b"/FULL2.TXT", rw | vfs::O_CREATE),
        vfs::open(b"/FULL3.TXT", rw | vfs::O_CREATE),
        vfs::open(b"/FULL4.TXT", rw | vfs::O_CREATE),
    ) else {
        fail("could not create the case's files")
    };
    // Counted once the names exist: a directory that grew for them is not the case's matter.
    let free0 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    if !matches!(vfs::write(&b, &all[..half]), Ok(n) if n == half) {
        fail("could not write the second file's half cluster")
    }
    // D: one cluster, then an append whose last write, the entry, is refused by the block
    // layer's hook (the ninth write of such a call: TST-M3-FAT32-FAULT-WRITE counts them). The
    // new cluster stays linked past the size (files.md v1.6).
    if !matches!(vfs::write(&d, &all[..one]), Ok(n) if n == one) {
        fail("could not write the fourth file's first cluster")
    }
    crate::block::arm_write_fault(9);
    let d_fault = vfs::write(&d, &all[one..two]);
    crate::block::disarm_write_fault();
    let d_long = size_of(b"/FULL4.TXT") == one as u64
        && node_size(&d) == one as u32
        && chain_of(b"/FULL4.TXT") == 2;
    if crate::fs::with(|fs| fs.arm_disk_full(2)).is_err() {
        fail("could not end the volume two free clusters ahead")
    }

    // A: three clusters with two left; the two; one byte more; one cluster over and one new.
    let a_big = attempt(&a, &all);
    let (a_big_size, a_big_node, a_big_chain) = (
        size_of(b"/FULL1.TXT"),
        node_size(&a),
        chain_of(b"/FULL1.TXT"),
    );
    let a_fit = attempt(&a, &all[..two]);
    let a_more = attempt(&a, b"x");
    seek_to(&a, one);
    let a_span = attempt(&a, &other[..two]);
    let (a_size, a_node, a_chain) = (
        size_of(b"/FULL1.TXT"),
        node_size(&a),
        chain_of(b"/FULL1.TXT"),
    );
    let a_whole = fault_state(b"/FULL1.TXT", &all[..two]) == 1;
    // What the same open reads from 0: the bytes the name holds, and no more.
    let a_read = {
        let mut back = alloc::vec![0u8; all.len() + 1];
        seek_to(&a, 0);
        match vfs::read(&a, &mut back) {
            Ok(k) if back[..k] == all[..k] => k as i64,
            _ => -1,
        }
    };
    seek_to(&a, 0);
    let a_over = attempt(&a, &other[..two]);
    let a_over_whole =
        fault_state(b"/FULL1.TXT", &other[..two]) == 1 && chain_of(b"/FULL1.TXT") == 2;

    // B: from the middle of its cluster into a second one; then to the end of its own.
    let b_span = attempt(&b, &all[half..half + one]);
    let b_size = size_of(b"/FULL2.TXT");
    let b_whole = fault_state(b"/FULL2.TXT", &all[..half]) == 1 && node_size(&b) == half as u32;
    let b_fill = attempt(&b, &all[half..one]);
    let b_chain = chain_of(b"/FULL2.TXT");
    let b_filled = fault_state(b"/FULL2.TXT", &all[..one]) == 1;

    // C: one byte with nothing left; then the clusters a removed file gives back.
    let c_none = attempt(&c, b"x");
    let (c_node, c_chain) = (node_size(&c), chain_of(b"/FULL3.TXT"));
    let c_empty = fault_state(b"/FULL3.TXT", &[]) == 2;
    // D: its second cluster's bytes again, with nothing left: the chain already holds the
    // cluster, so the call needs none.
    let d_into = attempt(&d, &all[one..two]);
    let d_chain = chain_of(b"/FULL4.TXT");
    let d_whole = fault_state(b"/FULL4.TXT", &all[..two]) == 1;

    // A's removal gives two clusters back: one to C, the other to B's chain.
    drop(a);
    let a_removed = vfs::unlink(b"/FULL1.TXT").is_ok();
    let c_after = attempt(&c, &all[..one]);
    let b_grow = attempt(&b, &all[one..two]);
    let c_more = attempt(&c, b"x");
    let c_whole = fault_state(b"/FULL3.TXT", &all[..one]) == 1 && chain_of(b"/FULL3.TXT") == 1;
    let b_grown = fault_state(b"/FULL2.TXT", &all[..two]) == 1 && chain_of(b"/FULL2.TXT") == 2;

    crate::fs::fat32::disarm_disk_full();
    let refused = [&a_big, &a_more, &a_span, &b_span, &c_none, &c_more];
    let refused_writes: u32 = refused.iter().map(|x| x.1).sum();
    let pos_moved = refused.iter().filter(|x| x.2 != 0).count();
    drop((b, c, d));
    let removed = a_removed
        && vfs::unlink(b"/FULL2.TXT").is_ok()
        && vfs::unlink(b"/FULL3.TXT").is_ok()
        && vfs::unlink(b"/FULL4.TXT").is_ok();
    let synced = vfs::sync().is_ok();
    let free1 = crate::fs::with(|fs| fs.free_clusters()).unwrap_or(0);
    kprintln!(
        "OSX|{}|ktest|fat32_disk_full|d_fault={}|d_long={}|a_big={}|a_big_size={}|a_big_node={}|a_big_chain={}|a_fit={}|a_more={}|a_span={}|a_size={}|a_node={}|a_chain={}|a_whole={}|a_read={}|a_over={}|a_over_whole={}|b_span={}|b_size={}|b_whole={}|b_fill={}|b_chain={}|b_filled={}|c_none={}|c_node={}|c_chain={}|c_empty={}|d_into={}|d_chain={}|d_whole={}|c_after={}|b_grow={}|c_more={}|c_whole={}|b_grown={}|refused_writes={}|pos_moved={}|removed={}|free_delta={}|synced={}|live_files={}",
        BUILD_ID,
        show(&d_fault),
        u8::from(d_long),
        show(&a_big.0),
        a_big_size,
        a_big_node,
        a_big_chain,
        show(&a_fit.0),
        show(&a_more.0),
        show(&a_span.0),
        a_size,
        a_node,
        a_chain,
        u8::from(a_whole),
        a_read,
        show(&a_over.0),
        u8::from(a_over_whole),
        show(&b_span.0),
        b_size,
        u8::from(b_whole),
        show(&b_fill.0),
        b_chain,
        u8::from(b_filled),
        show(&c_none.0),
        c_node,
        c_chain,
        u8::from(c_empty),
        show(&d_into.0),
        d_chain,
        u8::from(d_whole),
        show(&c_after.0),
        show(&b_grow.0),
        show(&c_more.0),
        u8::from(c_whole),
        u8::from(b_grown),
        refused_writes,
        pos_moved,
        u8::from(removed),
        i64::from(free0) - i64::from(free1),
        u8::from(synced),
        vfs::live_files()
    );
    if !matches!(d_fault, Err(FsError::Io(_))) || !d_long {
        fail("the fourth file's chain is not one cluster longer than its size")
    }
    if refused.iter().any(|x| x.0 != Err(FsError::DiskFull)) {
        fail("a write the volume could not hold whole was not answered with no space")
    }
    if refused_writes != 0 || pos_moved != 0 {
        fail("a refused write wrote to the device or moved the open's position")
    }
    if (a_big_size, a_big_node, a_big_chain) != (0, 0, 0) || c_node != 0 || c_chain != 0 || !c_empty
    {
        fail("a refused write to an empty file left it something")
    }
    if a_fit.0 != Ok(two) || a_over.0 != Ok(two) || b_fill.0 != Ok(one - half) {
        fail("a write the volume could hold whole was not made whole")
    }
    if d_into.0 != Ok(one) || d_chain != 2 || !d_whole {
        fail("a write into a cluster the chain already holds was refused or took another")
    }
    if c_after.0 != Ok(one) || b_grow.0 != Ok(one) || !c_whole || !b_grown {
        fail("the clusters a removed file gave back were not taken, one each")
    }
    if (a_size, a_node, a_chain) != (two as u64, two as u32, 2) || !a_whole || a_read != two as i64
    {
        fail("a refused write changed the file, its node or what its open reads")
    }
    if !a_over_whole || b_size != half as u64 || !b_whole || b_chain != 1 || !b_filled {
        fail("a file does not hold the bytes and the clusters its writes gave it")
    }
    if !removed || !synced || free1 != free0 {
        fail("clusters were lost on a volume that ran out of space")
    }
    pass("a write the volume cannot hold whole changes nothing, and one that fits is whole")
}

// ---- WP-117: the file system stops with the disk -----------------------------------------------

/// TST-M3-FAT32-STOP, first boot (WP-117, RSK-027; ADR-0013 decision 9): once the disk has
/// stopped, every file call answers an I/O error and none answers from memory. File A, three
/// clusters, is closed; file B, two clusters, is open twice, one position at its end and one
/// at 0; file T was written two clusters through one open and then emptied through another,
/// so the first open's position is past the size. The test kernel's hook is armed to withhold
/// from the device the second disk write from then on, and the `stopio` application is run:
/// it reads B to its end and deletes A, whose first FAT write is that second write, so the
/// driver's own timeout branch answers it and stops the disk inside the process's call; the
/// application then makes thirteen more calls of the files contract, five of them with
/// arguments a working disk would refuse, and exits 0x5709 only if the delete and every one
/// of them answered ERR_IO through the system-call layer. Then the kernel asks ten things of its
/// own opens: a read at the end of B, a seek and a write of no bytes (the three that ask
/// nothing of the disk), a read inside B, a stat of B and of the root, a create, a sync, the
/// count of free clusters, and a write through T's open whose position is past its size.
fn fat32_stop() -> ! {
    use crate::fs::vfs;
    let image = crate::apps::STOPIO;
    if image.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let rw = vfs::O_READ | vfs::O_WRITE;
    let all = fault_bytes(1);
    let two = 2 * FAULT_HALF;
    let made = (|| {
        let a = vfs::open(b"/STOP1.TXT", rw | vfs::O_CREATE).ok()?;
        if vfs::write(&a, &all) != Ok(all.len()) {
            return None;
        }
        drop(a);
        let b = vfs::open(b"/STOP2.TXT", rw | vfs::O_CREATE).ok()?;
        if vfs::write(&b, &all[..two]) != Ok(two) {
            return None;
        }
        let b0 = vfs::open(b"/STOP2.TXT", vfs::O_READ).ok()?;
        let t = vfs::open(b"/STOP4.TXT", rw | vfs::O_CREATE).ok()?;
        if vfs::write(&t, &all[..two]) != Ok(two) {
            return None;
        }
        drop(vfs::open(b"/STOP4.TXT", rw | vfs::O_TRUNCATE).ok()?);
        vfs::sync().ok()?;
        Some((b, b0, t))
    })();
    let Some((b, b0, t)) = made else {
        fail("could not prepare the case's files")
    };
    let pos_of = |f: &vfs::FileRef| f.lock().pos;
    if pos_of(&b) != two as u64 || pos_of(&t) != two as u64 || t.lock().node.lock().size != 0 {
        fail("the case's opens are not where it needs them")
    }
    crate::block::arm_timeout_at_write(2);
    let app_exit = match crate::user::run_elf(image) {
        Ok((o, _l)) => o.exit_code,
        Err(e) => {
            kprintln!("OSX|{}|ktest|fat32_stop|error={}", BUILD_ID, e.code());
            fail("application did not load")
        }
    };
    let mut buf = alloc::vec![0u8; 16];
    let end_read = vfs::read(&b, &mut buf).map(|_| ());
    let seek = vfs::seek(&b, 0).map(|_| ());
    let pos_moved = u8::from(pos_of(&b) != two as u64);
    let empty_write = vfs::write(&b, &[]).map(|_| ());
    let inner_read = vfs::read(&b0, &mut buf).map(|_| ());
    let stat = vfs::stat(b"/STOP2.TXT").map(|_| ());
    let root_stat = vfs::stat(b"/").map(|_| ());
    let create = vfs::open(b"/STOP3.TXT", rw | vfs::O_CREATE).map(|_| ());
    let sync = vfs::sync();
    let free = crate::fs::with(|fs| fs.free_clusters()).map(|_| ());
    let stale_write = vfs::write(&t, b"x").map(|_| ());
    drop((b, b0, t));
    let code = |r: &Result<(), FsError>| match r {
        Ok(()) => "ok",
        Err(e) => e.code(),
    };
    kprintln!(
        "OSX|{}|ktest|fat32_stop|app_exit={:#x}|end_read={}|seek={}|pos_moved={}|empty_write={}|inner_read={}|stat={}|root_stat={}|create={}|sync={}|free={}|stale_write={}|live_files={}",
        BUILD_ID,
        app_exit,
        code(&end_read),
        code(&seek),
        pos_moved,
        code(&empty_write),
        code(&inner_read),
        code(&stat),
        code(&root_stat),
        code(&create),
        code(&sync),
        code(&free),
        code(&stale_write),
        vfs::live_files()
    );
    if app_exit != 0x5709 {
        fail("a call of the process did not answer ERR_IO once the disk had stopped (exit code = its step)")
    }
    let later = [
        &end_read,
        &seek,
        &empty_write,
        &inner_read,
        &stat,
        &root_stat,
        &create,
        &sync,
        &free,
        &stale_write,
    ];
    if later.iter().any(|r| !matches!(r, Err(FsError::Io(_)))) {
        fail("a file call answered something else than an I/O error after the disk stopped")
    }
    if pos_moved != 0 {
        fail("a refused seek moved the open's position")
    }
    pass("after the disk stops every file call answers an I/O error")
}

/// The second boot of TST-M3-FAT32-STOP: a kernel with no memory of the first reads the image.
/// A's name is gone (its entry was written before the write that timed out), B holds its two
/// clusters' bytes, and a new three-cluster file reads back its own bytes and changes neither.
fn fat32_stop_check() -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let all = fault_bytes(1);
    let two = 2 * FAULT_HALF;
    let state = || {
        (
            fault_state(b"/STOP1.TXT", &all),
            fault_state(b"/STOP2.TXT", &all[..two]),
        )
    };
    let (a, b) = state();
    let fresh = alloc::vec![0x5Au8; FAULT_LEN];
    let after_ok = crate::fs::with(|fs| {
        let mut e = fs.create(b"/AFTER.TXT")?;
        fs.write(&mut e, 0, &fresh)?;
        fs.sync()
    })
    .is_ok()
        && fault_state(b"/AFTER.TXT", &fresh) == 1;
    let same_after = state() == (a, b);
    kprintln!(
        "OSX|{}|ktest|fat32_stop_check|a_gone={}|b_whole={}|after_ok={}|same_after={}",
        BUILD_ID,
        u8::from(a == 0),
        u8::from(b == 1),
        u8::from(after_ok),
        u8::from(same_after)
    );
    if a != 0 || b != 1 || !after_ok || !same_after {
        fail("after the restart a name of the case is not what the stop left")
    }
    pass("after the restart the stopped delete left no name and the other file whole")
}

/// One crafted boot sector of TST-M3-FAT32-BPB: its name, the fields written over the lab's
/// sector 0 as (byte offset, width in bytes, value), the capacity it is validated against
/// (`None`: the lab disk's own) and the geometry expected (clusters, data start), `None` for a
/// refusal.
type BpbCase = (
    &'static str,
    &'static [(usize, usize, u64)],
    Option<u64>,
    Option<(u32, u32)>,
);

/// The lab volume's boot sector (tools/fat32.py: 131072 sectors, 32 reserved, 2 FATs of 1024
/// sectors, one sector per cluster, root cluster 2) with fields changed, each refused or accepted
/// for one reason. BPB offsets: BytsPerSec 11, SecPerClus 13, RsvdSecCnt 14, NumFATs 16,
/// RootEntCnt 17, TotSec16 19, FATSz16 22, TotSec32 32, FATSz32 36, RootClus 44, the signature
/// at 510. The edges a mutant of the bounds moves come last (the mutation gate keeps the last 12
/// test-kernel lines of a boot): the eight-sector clusters, a FAT whose size in bytes does not fit
/// 32 bits, the FAT's size, the cluster count's upper bound and the three sectors whose data
/// start wraps a 32-bit sum.
const BPB_CASES: &[BpbCase] = &[
    ("lab", &[], None, Some((128992, 2080))),
    ("min_ok", &[(32, 4, 67605)], None, Some((65525, 2080))),
    ("root_last", &[(44, 4, 128993)], None, Some((128992, 2080))),
    ("sig", &[(510, 2, 0)], None, None),
    ("bps0", &[(11, 2, 0)], None, None),
    ("bps4096", &[(11, 2, 4096)], None, None),
    ("spc0", &[(13, 1, 0)], None, None),
    ("spc3", &[(13, 1, 3)], None, None),
    ("rsvd0", &[(14, 2, 0)], None, None),
    ("fats0", &[(16, 1, 0)], None, None),
    ("fats3", &[(16, 1, 3)], None, None),
    ("fatsz0", &[(36, 4, 0)], None, None),
    ("root_entries", &[(17, 2, 512)], None, None),
    ("tot16", &[(19, 2, 1)], None, None),
    ("fatsz16", &[(22, 2, 1)], None, None),
    ("total0", &[(32, 4, 0)], None, None),
    ("root1", &[(44, 4, 1)], None, None),
    ("root_end", &[(44, 4, 128994)], None, None),
    ("past_cap", &[], Some(131071), None),
    ("few", &[(32, 4, 67604)], None, None),
    ("total_max", &[(32, 4, 0xFFFF_FFFF)], None, None),
    (
        "all_max",
        &[
            (14, 2, 0xFFFF),
            (16, 1, 2),
            (36, 4, 0xFFFF_FFFF),
            (32, 4, 0xFFFF_FFFF),
        ],
        Some(u64::MAX),
        None,
    ),
    (
        "spc8_few",
        &[(13, 1, 8), (32, 4, 526279)],
        Some(526279),
        None,
    ),
    (
        "spc8",
        &[(13, 1, 8), (32, 4, 526280)],
        Some(526280),
        Some((65525, 2080)),
    ),
    (
        "big_fat",
        &[(16, 1, 1), (36, 4, 16777216), (32, 4, 16842773)],
        Some(16842773),
        Some((65525, 16777248)),
    ),
    (
        "fat_exact",
        &[(36, 4, 1008), (32, 4, 131070)],
        None,
        Some((129022, 2048)),
    ),
    ("fat_small", &[(36, 4, 1008), (32, 4, 131071)], None, None),
    (
        "max_ok",
        &[(16, 1, 1), (36, 4, 2097152), (32, 4, 270532629)],
        Some(270532629),
        Some((268435445, 2097184)),
    ),
    (
        "over_max",
        &[(16, 1, 1), (36, 4, 2097152), (32, 4, 270532630)],
        Some(270532630),
        None,
    ),
    (
        "too_many",
        &[(32, 4, 0xFFFF_FFFF), (16, 1, 1), (36, 4, 0x8000_0000)],
        Some(0xFFFF_FFFF),
        None,
    ),
    ("mul_wrap", &[(16, 1, 2), (36, 4, 0x8000_0010)], None, None),
    ("add_wrap", &[(16, 1, 2), (36, 4, 0x7FFF_FFF8)], None, None),
    (
        "zero_start",
        &[(14, 2, 1), (16, 1, 1), (36, 4, 0xFFFF_FFFF)],
        None,
        None,
    ),
];

/// The whole geometry of two answers of the mount, or the same error.
fn bpb_same(
    a: Result<crate::fs::fat32::Fat32, FsError>,
    b: Result<crate::fs::fat32::Fat32, FsError>,
) -> bool {
    let key = |v: &crate::fs::fat32::Fat32| {
        (
            v.sectors_per_cluster,
            v.reserved,
            v.fats,
            v.fat_sectors,
            v.root_cluster,
            v.data_start,
            v.clusters,
            v.fsinfo,
            v.bk_boot,
        )
    };
    match (a, b) {
        (Ok(x), Ok(y)) => key(&x) == key(&y),
        (Err(x), Err(y)) => x == y,
        _ => false,
    }
}

/// TST-M3-FAT32-BPB (WP-106, RSK-027): the mount's validation, given crafted boot sectors made
/// from the lab's own sector 0, refuses every malformed one with K_E_FS_BAD_BPB and accepts the
/// well-formed ones with their geometry; no sector panics the test kernel (32-bit sums that wrap
/// did). Each sector is then written to sector 0 and the mount itself (`Fat32::mount`, not the
/// volume the kernel keeps) must answer what the validation answers with the device's own
/// capacity (`mount=1`). Each sector's line is printed before the next is tried, so a panic
/// names the sector after the last line. The lab's sector 0 is written back before the case
/// judges.
fn fat32_bpb() -> ! {
    use crate::fs::fat32::Fat32;
    let mut lab = [0u8; 512];
    if crate::block::read(0, &mut lab).is_err() {
        fail("the lab disk's sector 0 could not be read")
    }
    let capacity = crate::block::capacity_sectors();
    let (mut refused, mut accepted, mut wrong, mut mount_same) = (0u32, 0u32, 0u32, 0u32);
    for (name, fields, cap, want) in BPB_CASES {
        let mut b = lab;
        for &(off, width, value) in fields.iter() {
            b[off..off + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
        let got = Fat32::from_boot_sector(&b, cap.unwrap_or(capacity));
        let agrees = crate::block::write(0, &b).is_ok()
            && bpb_same(Fat32::mount(), Fat32::from_boot_sector(&b, capacity));
        mount_same += u32::from(agrees);
        match got {
            Ok(v) => {
                accepted += 1;
                kprintln!(
                    "OSX|{}|ktest|fat32_bpb|sector={}|clusters={}|data_start={}|mount={}",
                    BUILD_ID,
                    name,
                    v.clusters,
                    v.data_start,
                    u8::from(agrees)
                );
            }
            Err(e) => {
                refused += 1;
                kprintln!(
                    "OSX|{}|ktest|fat32_bpb|sector={}|refused={}|mount={}",
                    BUILD_ID,
                    name,
                    e.code(),
                    u8::from(agrees)
                );
            }
        }
        let right = match (got, want) {
            (Ok(v), Some((c, d))) => v.clusters == *c && v.data_start == *d,
            (Err(e), None) => e == FsError::BadBpb,
            _ => false,
        };
        wrong += u32::from(!right);
    }
    // The lab's sector 0 back, and the mount sees the lab volume again.
    let restored = crate::block::write(0, &lab).is_ok()
        && bpb_same(Fat32::mount(), Fat32::from_boot_sector(&lab, capacity))
        && Fat32::mount().is_ok_and(|v| v.clusters == 128992 && v.data_start == 2080);
    kprintln!(
        "OSX|{}|ktest|fat32_bpb|sectors={}|refused={}|accepted={}|wrong={}|restored={}|mount_same={}",
        BUILD_ID,
        BPB_CASES.len(),
        refused,
        accepted,
        wrong,
        u8::from(restored),
        mount_same
    );
    if !restored {
        fail("the lab's sector 0 was not written back")
    }
    if wrong != 0 {
        fail("a boot sector was not judged as expected")
    }
    if mount_same as usize != BPB_CASES.len() {
        fail("the mount did not answer a boot sector as its validation does")
    }
    pass("every malformed boot sector is refused and the well-formed ones keep their geometry")
}

/// The bytes of /BADF.TXT in TST-M3-FAT32-BAD-FIRST.
fn bad_first_bytes() -> Vec<u8> {
    (0..1024usize).map(|i| lab_pattern(i * 5 + 3)).collect()
}

/// Writes `first` as the stored first cluster of the entry at `loc` (FstClusHI at 20, FstClusLO
/// at 26), straight on the disk; false when the disk refused.
fn bad_first_patch(
    v: &crate::fs::fat32::Fat32,
    loc: crate::fs::fat32::EntryLoc,
    first: u32,
) -> bool {
    let sector = u64::from(v.data_start)
        + u64::from(loc.cluster - 2) * u64::from(v.sectors_per_cluster)
        + u64::from(loc.index / 16);
    let o = (loc.index % 16) as usize * 32;
    let mut s = [0u8; 512];
    if crate::block::read(sector, &mut s).is_err() {
        return false;
    }
    s[o + 20..o + 22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    s[o + 26..o + 28].copy_from_slice(&((first & 0xFFFF) as u16).to_le_bytes());
    crate::block::write(sector, &s).is_ok()
}

/// Writes FAT entry 1 of the FAT copy that starts at `sec`: its four bytes alone, in the sector
/// as the disk holds it at that moment, so no other entry of the sector is touched.
fn bad_first_fat1(sec: u64, entry: [u8; 4]) -> bool {
    let mut s = [0u8; 512];
    if crate::block::read(sec, &mut s).is_err() {
        return false;
    }
    s[4..8].copy_from_slice(&entry);
    crate::block::write(sec, &s).is_ok()
}

/// One write call on /BADF.TXT as stored now, through a new open, at offset 512: 512 bytes, or
/// none when `empty`. Returns the answer (the count, or the error's code) and the disk writes
/// the call asked for.
fn bad_first_write(empty: bool) -> (String, u32) {
    use crate::fs::vfs;
    let Ok(f) = vfs::open(b"/BADF.TXT", vfs::O_READ | vfs::O_WRITE) else {
        fail("the made-up entry could not be opened")
    };
    if vfs::seek(&f, 512) != Ok(512) {
        fail("the made-up entry's open could not move to 512")
    }
    let data = [b'Z'; 512];
    let w0 = crate::block::writes();
    let r = vfs::write(&f, if empty { &data[..0] } else { &data[..] });
    let n = crate::block::writes() - w0;
    drop(f);
    (
        r.map_or_else(|e| e.code().into(), |k| alloc::format!("{}", k)),
        n,
    )
}

/// TST-M3-FAT32-BAD-FIRST (WP-147, RSK-033): a stored entry whose first cluster is no cluster of
/// the volume (1, the first number past the last cluster, a number far past it) is refused by a
/// write call with K_E_FS_CORRUPT before any disk write, the empty write included: with the
/// first FAT entry 1 as the format left it (an end mark), with it pointing at /HELLO.TXT's
/// cluster (which then stays whole) and with the allocator seeing no free cluster. A call whose
/// offset is past the stored size is answered by the same error, not the range error. The volume's
/// last cluster number is not refused: an empty write on it answers 0. The entry is made up on
/// the disk by the case (a block write over /BADF.TXT's entry) and put back after.
fn fat32_bad_first() -> ! {
    use crate::fs::vfs;
    let v = match crate::fs::mount() {
        Ok(v) => v,
        Err(_) => fail("volume did not mount"),
    };
    let all = bad_first_bytes();
    {
        let Ok(f) = vfs::open(b"/BADF.TXT", vfs::O_READ | vfs::O_WRITE | vfs::O_CREATE) else {
            fail("could not create /BADF.TXT")
        };
        if !matches!(vfs::write(&f, &all), Ok(1024)) || vfs::sync().is_err() {
            fail("could not write /BADF.TXT")
        }
    }
    let Ok(e) = crate::fs::with(|fs| fs.lookup(b"/BADF.TXT")) else {
        fail("/BADF.TXT not found after its write")
    };
    let Ok(hello) = crate::fs::with(|fs| fs.lookup(b"/HELLO.TXT")) else {
        fail("/HELLO.TXT not found")
    };
    // FAT entry 1 in each copy: (sector, byte offset 4).
    let fat_sectors: alloc::vec::Vec<u64> = (0..v.fats)
        .map(|k| u64::from(v.reserved) + u64::from(k) * u64::from(v.fat_sectors))
        .collect();
    let mut saved: alloc::vec::Vec<[u8; 4]> = alloc::vec::Vec::new();
    for &sec in &fat_sectors {
        let mut s = [0u8; 512];
        if crate::block::read(sec, &mut s).is_err() {
            fail("a FAT sector could not be read")
        }
        saved.push([s[4], s[5], s[6], s[7]]);
    }
    let mut out = String::new();
    let mut refused_all = true;
    let mut writes_total = 0u32;
    let mut empty_writes = 0u32;
    let mut take = |name: &str, first: u32, out: &mut String| {
        if !bad_first_patch(&v, e.loc, first) {
            fail("the made-up entry could not be written")
        }
        let (r, n) = bad_first_write(false);
        let (r0, n0) = bad_first_write(true);
        refused_all &= r == "K_E_FS_CORRUPT" && r0 == "K_E_FS_CORRUPT";
        writes_total += n + n0;
        empty_writes += n0;
        out.push_str(&alloc::format!(
            "|{name}={r}|{name}_writes={n}|{name}_empty={r0}"
        ));
    };
    take("one", 1, &mut out);
    // A call the range check alone would refuse (its offset is past the stored size) is
    // answered by the guard first: the corrupt-volume error, not the range error. The call is
    // made on the volume itself, with the entry as the disk stores it now (first cluster 1).
    let (one_past, one_past_writes) = {
        let Ok(mut stored) = crate::fs::with(|fs| fs.lookup(b"/BADF.TXT")) else {
            fail("the made-up entry could not be looked up")
        };
        let past = stored.size + 1;
        let w0 = crate::block::writes();
        let r = crate::fs::with(|fs| fs.write(&mut stored, past, b"Z"));
        let n = crate::block::writes() - w0;
        let r: String = r.map_or_else(|e| e.code().into(), |k| alloc::format!("{}", k));
        (r, n)
    };
    out.push_str(&alloc::format!(
        "|one_past={one_past}|one_past_writes={one_past_writes}"
    ));
    // FAT entry 1 pointing at /HELLO.TXT's first cluster, in every copy.
    for (i, &sec) in fat_sectors.iter().enumerate() {
        let old = u32::from_le_bytes(saved[i]);
        let new = (old & 0xF000_0000) | (hello.first & 0x0FFF_FFFF);
        if !bad_first_fat1(sec, new.to_le_bytes()) {
            fail("FAT entry 1 could not be written")
        }
    }
    take("one_link", 1, &mut out);
    for (i, &sec) in fat_sectors.iter().enumerate() {
        if !bad_first_fat1(sec, saved[i]) {
            fail("FAT entry 1 could not be put back")
        }
    }
    let hello_ok = fault_state(b"/HELLO.TXT", LAB_HELLO) == 1;
    out.push_str(&alloc::format!("|hello_ok={}", u8::from(hello_ok)));
    if crate::fs::with(|fs| fs.arm_disk_full(0)).is_err() {
        fail("the allocator's end could not be set")
    }
    take("one_full", 1, &mut out);
    crate::fs::fat32::disarm_disk_full();
    take("past_end", v.clusters + 2, &mut out);
    take("far", 0x0FFF_FFF0, &mut out);
    // The volume's last cluster number is one of its clusters, so the guard lets a write call
    // on it through. Only the empty write is made: it asks the volume nothing and answers 0,
    // which shows the end's test is not one number too low.
    if !bad_first_patch(&v, e.loc, v.clusters + 1) {
        fail("the made-up entry could not be written")
    }
    let (last_empty, last_writes) = bad_first_write(true);
    out.push_str(&alloc::format!(
        "|last_empty={last_empty}|last_empty_writes={last_writes}"
    ));
    let put_back = bad_first_patch(&v, e.loc, e.first);
    let restored_ok = put_back && fault_state(b"/BADF.TXT", &all) == 1;
    let synced = vfs::sync().is_ok();
    kprintln!(
        "OSX|{}|ktest|fat32_bad_first|clusters={}{}|empty_writes={}|restored_ok={}|synced={}|live_files={}",
        BUILD_ID,
        v.clusters,
        out,
        empty_writes,
        u8::from(restored_ok),
        u8::from(synced),
        vfs::live_files()
    );
    if !refused_all || writes_total != 0 {
        fail("a write on an entry whose first cluster is no cluster of the volume was not refused before any disk write")
    }
    if one_past != "K_E_FS_CORRUPT" || one_past_writes != 0 {
        fail("a write past the stored size on an entry whose first cluster is 1 was not answered by the corrupt-volume error with no disk write")
    }
    if last_empty != "0" || last_writes != 0 {
        fail("an empty write on an entry whose first cluster is the volume's last was not answered 0 with no disk write")
    }
    if !hello_ok || !restored_ok || !synced || vfs::live_files() != 0 {
        fail("the other file, the made-up entry or the opens were not left as they were")
    }
    pass("a stored first cluster of 1 or past the volume's end is refused before any disk write")
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
    /// The manager's handle count before `LOAD`: what the kernel handed it (WP-161).
    handles0: i64,
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
        let handles0 = sched::handles_pid(m.pid).map_or(-1, |n| n as i64);
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
            handles0,
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
        let gone = sched::poll_until(sched::ticks() + 1000, || sched::stats().processes == 0);
        let code = object.exit_code().unwrap_or(u64::MAX);
        // Drop our own reference first: `object::stats().processes` counts process objects, so
        // the manager's would otherwise never let the counts return to the baseline.
        drop(object);
        // Then wait for the service objects to be reclaimed. Reap removes a process from the
        // table before dropping its handles (outside the scheduler lock, WP-20), so on SMP the
        // channels/surfaces it owned are freed a few ticks after `processes == 0` — a single
        // snapshot there read a mid-reap count and flaked TST-M5-WINDOW-A11Y with clean=0 (CI
        // run 39177067037) though the transcript matched. A genuine leak still never settles.
        let settled = sched::poll_until(sched::ticks() + 1000, || object::stats() == obj0);
        (code, sched::stats().processes, frames0, gone && settled)
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
        "session_deadline" => pass(
            "the session gave each silent component its request deadline, closed it, and exited instead of hanging",
        ),
        "launch_denied" => pass(
            "APPS and LAUNCH are for the vouched session and desktop, and the registry comes from the volume",
        ),
        "app_connect" => pass(
            "an application connects to its declared services alone, vouched by its identity and within the bounds",
        ),
        "logout_kills" => pass(
            "Sign out ended the session's job: no application of it lived, and the next sign-in launched into a new one",
        ),
        "session_restart" => pass(
            "the session's restart, crash and stop each ended its job with its application, and each session started again launched into a job of its own",
        ),
        "session_gate" => pass(
            "LAUNCH needs an open session: closed at boot, by END_SESSION and by the session's exit, which ends the session's job, opened by BEGIN_SESSION from the vouched session alone",
        ),
        "launch_rate" => pass(
            "LAUNCH is bounded in rate: the attempt beyond sixteen in any 1000 ticks is refused ERR BUSY, failed launches count, a full table and an unknown id do not, and launching resumes as the attempts age",
        ),
        "job_bound" => pass(
            "a job's processes are bounded: the start beyond the bound is refused, its place comes back at an exit, and other jobs and LAUNCH are unaffected",
        ),
        "session_job" => pass(
            "the session's applications run in one job, which END_SESSION from the session alone ends, and the next launch makes a new one",
        ),
        "app_spawn" => pass(
            "a launched application runs in a job of its own with its boot channel alone, is refused every request, and leaves nothing behind",
        ),
        "svc_watchdog" => pass(
            "the watchdog ends a hung service and gives it up, leaves a healthy one, kills one that closed its channel, forces one hung before READY after the grace, and STOP force-kills a stubborn one",
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

/// TST-M6-LAUNCH-DENIED (REQ-M6-004, services.md v1.14, ADR-0023, WP-101): APPS and LAUNCH on a
/// service's boot channel are for the vouched session and desktop. Five lab services each
/// answer READY, ask what their manifest line says and exit with what came back (0x40: every
/// reply as expected; 0x50 + k: the k-th reply was another; 0x60 + k: no reply to the k-th).
/// `session` asks APPS and is given the registry the build put under /SYSTEM/APPS; `desktop`
/// asks LAUNCH for an id that is not registered and for one that is (nothing is launched in
/// this version); three plain services ask LAUNCH, APPS and a request the manager does not
/// know.
fn launch_denied() -> ! {
    let name = "launch_denied";
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-LD.TXT");
    let names = ["session", "desktop", "plain1", "plain2", "plain3"];
    let lines = h.poll_list(sched::ticks() + 20_000, |l| {
        names
            .iter()
            .all(|n| l.iter().any(|x| x.name == *n && x.exit.is_some()))
    });
    let code = |n: &str| svc_find(&lines, n).exit.unwrap_or(u64::MAX);
    let (s, d, p1, p2, p3) = (
        code("session"),
        code("desktop"),
        code("plain1"),
        code("plain2"),
        code("plain3"),
    );
    let load = h.load_reply.clone();
    kprintln!(
        "OSX|{}|ktest|launch_denied|load={}|session_apps={:#x}|desktop_launch={:#x}|plain_launch={:#x}|plain_apps={:#x}|unknown={:#x}|",
        BUILD_ID,
        load,
        s,
        d,
        p1,
        p2,
        p3
    );
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|launch_denied|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 5" {
        fail("the lab manifest did not load")
    }
    if p1 != 0x40 || p2 != 0x40 {
        fail("a plain service's LAUNCH or APPS was not refused ERR ACCESS by the manager")
    }
    if s != 0x40 {
        fail("the vouched session was not given the registry of /SYSTEM/APPS")
    }
    if d != 0x40 {
        fail("LAUNCH from the vouched desktop was not answered as the contract says")
    }
    if p3 != 0x40 {
        fail("an unknown request on a service's boot channel was not answered ERR BAD_REQUEST")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    drop((lines, load));
    svc_balance(name, frames0)
}

/// TST-M6-APP-SPAWN (REQ-M6-004, services.md v1.15, ADR-0023 item 1; WP-161): `LAUNCH` from the
/// vouched session starts a registered application in a job of its own (under the session's
/// job since WP-102), with its boot channel and nothing else. The lab manifest SVC-AS.TXT has one service, named
/// `session`, whose role is the launcher: eight steps, the exit code saying which reply was not
/// the stated one (0x40: none). When it has exited eight applications of the lab image stay,
/// each waiting on its boot channel because all it asked there was refused, and holding that
/// channel alone; an application that exited left nothing of its job behind, and the manager
/// kept no handle of what failed or ended.
/// WP-172 (services.md v1.20): the session's exit ends its job, so a lab session's role holds
/// after its steps (the lab image `hold`), waiting on its boot channel without a deadline, while
/// the test kernel reads. Its image is /SYSTEM/LABSES.ELF, so its process is known by name.
/// Waits, until `by`, for the session to have exited (a step saw another reply: its exit code) or
/// to hold (0x40), and for `also` of the listing; the listing and that code. Holding is the
/// session listed ready (it answers READY only after reading START, which it waits for without a
/// deadline too) and its process waiting without a deadline, which no step does.
fn session_held(h: &SvcHarness, by: u64, also: impl Fn(&[SvcLine]) -> bool) -> (Vec<SvcLine>, u64) {
    let held = |l: &[SvcLine]| {
        let (p, n) = sched::live_named(b"LABSES.ELF");
        svc_find(l, "session").state == "ready" && n == 1 && p[0].waiting
    };
    let lines = h.poll_list(by, |l| {
        (l.iter().any(|x| x.name == "session" && x.exit.is_some()) || held(l)) && also(l)
    });
    let code = match svc_find(&lines, "session").exit {
        Some(c) => c,
        None if held(&lines) => 0x40,
        None => u64::MAX,
    };
    (lines, code)
}

fn app_spawn() -> ! {
    let name = "app_spawn";
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-AS.TXT");
    let (lines, session) = session_held(&h, sched::ticks() + 25_000, |_| true);
    // The held session's process and channel, which the manager keeps while it runs.
    let held_extra = if session == 0x40 { 2 } else { 0 };
    // The eight that stay have asked their requests once each waits without a deadline; the
    // child the exited application left is ended with its job.
    sched::poll_until(sched::ticks() + 5000, || {
        let (apps, n) = sched::live_named(b"CLOCK.ELF");
        n == 8 && apps[..n].iter().all(|a| a.waiting) && sched::live_named(b"IDLE.ELF").1 == 0
    });
    let (apps, n) = sched::live_named(b"CLOCK.ELF");
    let apps = &apps[..n];
    let count = |f: fn(&sched::LiveNamed) -> bool| apps.iter().filter(|a| f(a)).count();
    let waiting = count(|a| a.waiting);
    let handles: usize = apps.iter().map(|a| a.handles).sum();
    let under_root = count(|a| a.under_root);
    let in_session = count(|a| a.parent_under_root);
    let jobs = (0..n)
        .filter(|&i| apps[..i].iter().all(|b| b.job != apps[i].job))
        .count();
    let parents = (0..n)
        .filter(|&i| apps[..i].iter().all(|b| b.parent != apps[i].parent))
        .count();
    let live_jobs = i64::from(object::stats().jobs) - i64::from(h.obj0.jobs);
    let orphans = sched::live_named(b"IDLE.ELF").1;
    let kept = mgr_handles(&h) - h.handles0 - held_extra;
    let load = h.load_reply.clone();
    kprintln!(
        "OSX|{}|ktest|app_spawn|load={}|session={:#x}|apps={}|waiting={}|handles={}|under_root={}|in_session={}|parents={}|jobs={}|live_jobs={}|orphans={}|mgr_handles={}|",
        BUILD_ID,
        load,
        session,
        n,
        waiting,
        handles,
        under_root,
        in_session,
        parents,
        jobs,
        live_jobs,
        orphans,
        kept
    );
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|app_spawn|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 1" {
        fail("the lab manifest did not load")
    }
    if session != 0x40 {
        fail("a LAUNCH of the vouched session was not answered as the contract states")
    }
    if n != 8 || waiting != 8 {
        fail("an application was not refused every request on its boot channel")
    }
    if handles != 8 {
        fail("an application holds more than its boot channel")
    }
    // v1.17: each in a job of its own, all of them children of the one session job, which is a
    // child of the root job.
    if under_root != 0 || in_session != 8 || parents != 1 || jobs != 8 {
        fail("an application is not in a job of its own under the session's job")
    }
    if orphans != 0 {
        fail("an application that exited left a process of its job behind")
    }
    // The eight applications' jobs and the session's.
    if live_jobs != 9 {
        fail("a job was left of a launch that failed or of an application that exited")
    }
    // Eight applications' process, channel and job, and the session's job, and nothing else since
    // before LOAD: the launcher's own two, which the manager keeps while it holds, are subtracted.
    if kept != 25 {
        fail("the manager kept a handle of a launch that failed or of an application that exited")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or applications left something behind")
    }
    drop((lines, load));
    svc_balance(name, frames0)
}

/// TST-M6-APP-CONNECT-DENIED (REQ-M6-004, services.md v1.16, ADR-0023 item 1; WP-162): an
/// application's CONNECT. The lab manifest SVC-AC.TXT runs the lab image as `config`, tracing the
/// name each client is vouched by (and as `display`, the same), and as the vouched `session`,
/// whose launcher starts `connx` (declares config, connects, exits), the review round's `both`,
/// `netonly` and `stuck` (each exits), and five of `conn` (declares config, connects, stays).
/// Each application traces what the manager answered; the test kernel waits for the five to
/// stay and checks the manager kept nothing of what was refused.
fn app_connect() -> ! {
    let name = "app_connect";
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-AC.TXT");
    let (lines, session) = session_held(&h, sched::ticks() + 20_000, |_| true);
    // The held session's process and channel, which the manager keeps while it runs.
    let held_extra = if session == 0x40 { 2 } else { 0 };
    sched::poll_until(sched::ticks() + 5000, || {
        let (apps, n) = sched::live_named(b"CONN.ELF");
        n == 5 && apps[..n].iter().all(|a| a.waiting)
    });
    let (apps, n) = sched::live_named(b"CONN.ELF");
    let waiting = apps[..n].iter().filter(|a| a.waiting).count();
    let handles: usize = apps[..n].iter().map(|a| a.handles).sum();
    let kept = mgr_handles(&h) - h.handles0 - held_extra;
    let load = h.load_reply.clone();
    kprintln!(
        "OSX|{}|ktest|app_connect|load={}|session={:#x}|apps={}|waiting={}|handles={}|mgr_handles={}|",
        BUILD_ID,
        load,
        session,
        n,
        waiting,
        handles,
        kept
    );
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|app_connect|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 3" {
        fail("the lab manifest did not load")
    }
    if session != 0x40 {
        fail("a LAUNCH of the connection case was not answered as the contract states")
    }
    if n != 5 || waiting != 5 {
        fail("an application of the connection case did not stay")
    }
    // Each of the four granted holds its boot channel and its connection; the fifth, refused,
    // its boot channel alone.
    if handles != 9 {
        fail("an application holds another number of handles than its grants give")
    }
    // Since before LOAD: the five applications' process, channel and job, the config and
    // display services' channel and process, and the session's job (v1.17); nothing of the
    // launcher, of the four that exited, of a refused CONNECT nor of the client end `stuck`
    // could not take.
    if kept != 15 + 4 + 1 {
        fail("the manager kept a handle of a CONNECT it refused or of an application that exited")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or applications left something behind")
    }
    drop((lines, load));
    svc_balance(name, frames0)
}

/// TST-M6-SESSION-JOB (REQ-M6-004, services.md v1.17, ADR-0023 item 1; WP-102): the session's
/// job. The lab manifest SVC-SJ.TXT runs the lab image as the vouched `session`, whose role
/// `ender` launches `stay` (asks END_SESSION and its six requests and waits) and `nest` (starts a
/// child of its own and waits) before READY, then asks END_SESSION twice, 300 ticks apart (ENDED 2,
/// ENDED 0),
/// launches `stay`, ends that session (ENDED 1) and launches `stay` again; and as the vouched
/// `desktop` and as `sessions`, both started once the session is READY, whose END_SESSION is
/// refused ERR ACCESS. When both have exited the test kernel waits
/// for the ended session's processes to be gone and reads, while the manager runs, what is left.
fn session_job() -> ! {
    let name = "session_job";
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-SJ.TXT");
    let (lines, session) = session_held(&h, sched::ticks() + 20_000, |l| {
        ["desktop", "sessions"]
            .iter()
            .all(|s| l.iter().any(|x| x.name == *s && x.exit.is_some()))
    });
    // The held session's process and channel, which the manager keeps while it runs.
    let held_extra = if session == 0x40 { 2 } else { 0 };
    let desktop = svc_find(&lines, "desktop").exit.unwrap_or(u64::MAX);
    let sessions = svc_find(&lines, "sessions").exit.unwrap_or(u64::MAX);
    let jobs_now = || i64::from(object::stats().jobs) - i64::from(h.obj0.jobs);
    sched::poll_until(sched::ticks() + 5000, || {
        let (stay, n) = sched::live_named(b"STAY.ELF");
        n == 1
            && stay[0].waiting
            && sched::live_named(b"NEST.ELF").1 == 0
            && sched::live_named(b"IDLE.ELF").1 == 0
            && jobs_now() == 2
    });
    let (stay, n) = sched::live_named(b"STAY.ELF");
    let waiting = stay[..n].iter().filter(|a| a.waiting).count();
    let nest = sched::live_named(b"NEST.ELF").1;
    let idle = sched::live_named(b"IDLE.ELF").1;
    let under_root = stay[..n].iter().filter(|a| a.under_root).count();
    let in_session = stay[..n].iter().filter(|a| a.parent_under_root).count();
    let live_jobs = jobs_now();
    let kept = mgr_handles(&h) - h.handles0 - held_extra;
    let load = h.load_reply.clone();
    kprintln!(
        "OSX|{}|ktest|session_job|load={}|session={:#x}|desktop={:#x}|sessions={:#x}|stay={}|waiting={}|nest={}|idle={}|under_root={}|in_session={}|live_jobs={}|mgr_handles={}|",
        BUILD_ID,
        load,
        session,
        desktop,
        sessions,
        n,
        waiting,
        nest,
        idle,
        under_root,
        in_session,
        live_jobs,
        kept
    );
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|session_job|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 3" {
        fail("the lab manifest did not load")
    }
    if session != 0x40 {
        fail("END_SESSION or the LAUNCH after it was not answered as the contract states")
    }
    if desktop != 0x40 || sessions != 0x40 {
        fail("another service's END_SESSION was not refused")
    }
    if n != 1 || nest != 0 || idle != 0 {
        fail("an application of the ended session is still alive")
    }
    if waiting != 1 {
        fail("the application launched after END_SESSION does not wait on its boot channel")
    }
    if under_root != 0 || in_session != 1 {
        fail("the application launched after END_SESSION is not in a new session job")
    }
    // The new session's job and its one application's.
    if live_jobs != 2 {
        fail("a job of the ended session was left")
    }
    // The one application's process, channel and job, and the new session's job: nothing of the
    // ended session, nor of the two services, which exited.
    if kept != 4 {
        fail("the manager kept a handle of the ended session")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or applications left something behind")
    }
    drop((lines, load));
    svc_balance(name, frames0)
}

/// TST-M6-JOB-BOUND (REQ-M6-003, REQ-M6-004, syscall.md v1.15; WP-164, RSK-050): a job holds 32
/// live processes at most. The lab manifest SVC-JB.TXT runs the lab image as the vouched `session`,
/// whose role `bounder` launches `peer` (a child now and one later), `hog` (starts IDLE children
/// in its own job until refused, 64 at most) and `clock`; the test kernel reads, while the manager
/// runs, how many processes live in hog's and in peer's job.
fn job_bound() -> ! {
    let name = "job_bound";
    // The count itself, deterministically, before any process runs: of 40 places asked of a new
    // job, 32 are given; a place given back admits one more; the root refuses none of 40.
    let unit = {
        use crate::object::job::{root, Job};
        let job = Job::new_child(&root()).unwrap_or_else(|_| fail("no job for the count"));
        let mut held: Vec<_> = (0..40).map_while(|_| job.admit()).collect();
        let taken = held.len();
        let refused = job.admit().is_none();
        drop(held.pop());
        held.extend(job.admit());
        let again = held.len() == taken;
        let counted = job.processes();
        drop(held);
        let back = job.processes();
        let root = root();
        let root_held: Vec<_> = (0..40).map_while(|_| root.admit()).collect();
        let root_all = root_held.len();
        drop((root_held, job));
        alloc::format!(
            "taken={}|refused={}|again={}|counted={}|back={}|root={}",
            taken,
            u8::from(refused),
            u8::from(again),
            counted,
            back,
            root_all
        )
    };
    kprintln!("OSX|{}|ktest|job_bound|unit|{}|", BUILD_ID, unit);
    if unit != "taken=32|refused=1|again=1|counted=32|back=0|root=40" {
        fail("a job's count does not hold its bound")
    }
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-JB.TXT");
    let (lines, session) = session_held(&h, sched::ticks() + 20_000, |_| true);
    let job_of = |img: &[u8]| {
        let (a, n) = sched::live_named(img);
        (n == 1).then(|| a[0].job)
    };
    let live = |img: &[u8]| job_of(img).map_or(0, sched::live_in_job);
    // hog, peer and clock each wait on their boot channel once their work is done.
    let settled = |img: &[u8]| {
        let (a, n) = sched::live_named(img);
        n == 1 && a[0].waiting
    };
    sched::poll_until(sched::ticks() + 5000, || {
        settled(b"CLOCK.ELF") && settled(b"HOG.ELF") && settled(b"PEER.ELF")
    });
    let (hog_live, peer_live) = (live(b"HOG.ELF"), live(b"PEER.ELF"));
    let count = |img: &[u8]| job_of(img).and_then(sched::job_count).unwrap_or(u32::MAX);
    let (hog_count, peer_count) = (count(b"HOG.ELF"), count(b"PEER.ELF"));
    let clocks = sched::live_named(b"CLOCK.ELF").1;
    // The children of hog and peer never exit, and the manager does not end its applications'
    // jobs when it stops (services.md v1.17's limits): their two jobs are killed here, as job_kill
    // would, and their processes waited for, before the manager is.
    for job in [job_of(b"HOG.ELF"), job_of(b"PEER.ELF")]
        .into_iter()
        .flatten()
    {
        sched::kill_job_id(job, 0x2_0000);
    }
    sched::poll_until(sched::ticks() + 5000, || {
        live(b"HOG.ELF") == 0 && live(b"PEER.ELF") == 0 && sched::live_named(b"IDLE.ELF").1 == 0
    });
    let load = h.load_reply.clone();
    kprintln!(
        "OSX|{}|ktest|job_bound|load={}|session={:#x}|hog_live={}|hog_count={}|peer_live={}|peer_count={}|clocks={}|",
        BUILD_ID,
        load,
        session,
        hog_live,
        hog_count,
        peer_live,
        peer_count,
        clocks
    );
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|job_bound|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 1" {
        fail("the lab manifest did not load")
    }
    // hog and the 31 children it may keep, each counted in hog's job.
    if hog_live != 32 || hog_count != 32 {
        fail("a job's processes are not bounded")
    }
    // peer and its two children: the second came after hog's job was full.
    if peer_live != 3 || peer_count != 3 {
        fail("another job was refused a start a full job holds")
    }
    if session != 0x40 || clocks != 1 {
        fail("a LAUNCH after a full job was not answered as the contract states")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or applications left something behind")
    }
    drop((lines, load));
    svc_balance(name, frames0)
}

/// TST-M6-LAUNCH-RATE (REQ-M6-004, services.md v1.18; WP-163): LAUNCH is bounded in rate. The
/// lab manifest SVC-LR.TXT runs the lab image as the vouched `session`, whose role `rater` makes
/// sixteen attempts, two of them failed, with full-table refusals among them, is refused ERR BUSY
/// seventeen times and ERR UNKNOWN once, and launches again once its first attempt is a window old.
fn launch_rate() -> ! {
    let name = "launch_rate";
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-LR.TXT");
    let (lines, session) = session_held(&h, sched::ticks() + 25_000, |_| true);
    // The held session's process and channel, which the manager keeps while it runs.
    let held_extra = if session == 0x40 { 2 } else { 0 };
    // The ended session's applications are killed and the last one exits at once; the manager
    // has seen every exit when only the last session's job is left of what it made.
    let jobs_now = || i64::from(object::stats().jobs) - i64::from(h.obj0.jobs);
    sched::poll_until(sched::ticks() + 5000, || {
        sched::live_named(b"STAY.ELF").1 == 0
            && sched::live_named(b"EXIT.ELF").1 == 0
            && jobs_now() == 1
            && mgr_handles(&h) - h.handles0 - held_extra == 1
    });
    let stays = sched::live_named(b"STAY.ELF").1;
    let exits = sched::live_named(b"EXIT.ELF").1;
    let live_jobs = jobs_now();
    let kept = mgr_handles(&h) - h.handles0 - held_extra;
    let load = h.load_reply.clone();
    kprintln!(
        "OSX|{}|ktest|launch_rate|load={}|session={:#x}|stays={}|exits={}|live_jobs={}|mgr_handles={}|",
        BUILD_ID,
        load,
        session,
        stays,
        exits,
        live_jobs,
        kept
    );
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|launch_rate|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 1" {
        fail("the lab manifest did not load")
    }
    if session != 0x40 {
        fail("a LAUNCH was not answered as the rate limit states")
    }
    if stays != 0 || exits != 0 {
        fail("an application of the case is still alive")
    }
    // The last session's job alone: its one application exited.
    if live_jobs != 1 || kept != 1 {
        fail("the manager kept something of a launch that was refused or that exited")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or applications left something behind")
    }
    drop((lines, load));
    svc_balance(name, frames0)
}

/// TST-M6-SESSION-GATE (REQ-M6-004, services.md v1.19; WP-169): LAUNCH needs an open session.
/// The lab manifest SVC-GT.TXT runs the lab image as the vouched `session` (role `gater`: refused
/// before BEGIN_SESSION, opens, launches, ends, is refused, opens, launches, exits) and the vouched
/// `desktop` (role `ungated`: refused BEGIN_SESSION, then refused LAUNCH after the session's exit).
fn session_gate() -> ! {
    let name = "session_gate";
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-GT.TXT");
    let lines = h.poll_list(sched::ticks() + 25_000, |l| {
        ["session", "desktop"]
            .iter()
            .all(|n| l.iter().any(|x| x.name == *n && x.exit.is_some()))
    });
    let session = svc_find(&lines, "session").exit.unwrap_or(u64::MAX);
    let desktop = svc_find(&lines, "desktop").exit.unwrap_or(u64::MAX);
    // stay#1 went with the ended session's job, stay#2 with the session's at its exit (WP-172).
    let jobs_now = || i64::from(object::stats().jobs) - i64::from(h.obj0.jobs);
    sched::poll_until(sched::ticks() + 5000, || {
        sched::live_named(b"STAY.ELF").1 == 0
            && jobs_now() == 0
            && mgr_handles(&h) - h.handles0 == 0
    });
    let (stay, n) = sched::live_named(b"STAY.ELF");
    let waiting = stay[..n].iter().filter(|a| a.waiting).count();
    let live_jobs = jobs_now();
    let kept = mgr_handles(&h) - h.handles0;
    let load = h.load_reply.clone();
    kprintln!(
        "OSX|{}|ktest|session_gate|load={}|session={:#x}|desktop={:#x}|stays={}|waiting={}|live_jobs={}|mgr_handles={}|",
        BUILD_ID,
        load,
        session,
        desktop,
        n,
        waiting,
        live_jobs,
        kept
    );
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|session_gate|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 2" {
        fail("the lab manifest did not load")
    }
    // The session exits 0 (a clean exit closes the gate as any other does).
    if session != 0 {
        fail("a LAUNCH or BEGIN_SESSION of the session was not answered as the gate states")
    }
    if desktop != 0x40 {
        fail("the desktop opened the gate, or the session's exit did not close it")
    }
    // The session's exit ended its job with stay#2 (services.md v1.20): nothing is left of it.
    if n != 0 || waiting != 0 || live_jobs != 0 || kept != 0 {
        fail("an application or a job of the session outlived the session service")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or applications left something behind")
    }
    drop((lines, load));
    svc_balance(name, frames0)
}

/// TST-M6-SESSION-RESTART (REQ-M6-004, services.md v1.20; WP-173): the session's exit ends its
/// job whatever its code and however it comes: a RESTART, a crash and a STOP (TST-M6-SESSION-GATE
/// shows the clean exit). The lab manifest SVC-SX.TXT runs a lab service (`lab`, role `ready`),
/// so the session is not the manifest's first, then the lab image as the vouched `session` (role
/// `stayer`: LAUNCH refused ERR NO_SESSION, BEGIN_SESSION, LAUNCH stay, hold), on-failure. The
/// test kernel asks the manager to RESTART it (it exits 0x40, the manager's state stopping), then
/// kills it while it is ready (a crash: EXIT_KILLED, started again on failure), then asks STOP.
/// After each it reads that the application went with the job and, but after the stop, that the
/// session started again launched into a job of its own; after the stop, that nothing is left.
fn session_restart() -> ! {
    struct Phase {
        restarts: u64,
        exit: u64,
        stopped: bool,
        held: bool,
        stays: usize,
        waiting: bool,
        new_job: usize,
        live_jobs: i64,
        kept: i64,
        job: u64,
    }
    let name = "session_restart";
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-SX.TXT");
    let load = h.load_reply.clone();
    if load != "OK 2" {
        fail("the lab manifest did not load")
    }
    let (_, session) = session_held(&h, sched::ticks() + 20_000, |_| true);
    // The lab service's process and channel, which the manager keeps while it runs.
    const LAB: i64 = 2;
    let jobs_now = || i64::from(object::stats().jobs) - i64::from(h.obj0.jobs);
    let held = || {
        let (p, n) = sched::live_named(b"LABSES.ELF");
        n == 1 && p[0].waiting
    };
    // What the manager keeps beside the lab service and a held session's process and channel.
    let kept = || mgr_handles(&h) - h.handles0 - LAB - if held() { 2 } else { 0 };
    // The one live STAY.ELF, waiting, in a session job under the root that is none of `old`.
    let one_new_stay = |old: &[u64]| {
        let (stay, n) = sched::live_named(b"STAY.ELF");
        n == 1 && stay[0].waiting && stay[0].parent_under_root && !old.contains(&stay[0].parent)
    };
    let read = |lines: &[SvcLine], old: &[u64]| {
        let s = svc_find(lines, "session");
        let (stay, n) = sched::live_named(b"STAY.ELF");
        Phase {
            restarts: s.restarts,
            exit: s.exit.unwrap_or(u64::MAX),
            stopped: s.state == "stopped",
            held: held(),
            stays: n,
            waiting: n == 1 && stay[0].waiting,
            new_job: stay[..n]
                .iter()
                .filter(|a| a.parent_under_root && !old.contains(&a.parent))
                .count(),
            live_jobs: jobs_now(),
            kept: kept(),
            job: if n == 1 { stay[0].parent } else { 0 },
        }
    };
    let ask = |req: &[u8]| {
        crate::services::request(&h.m.ctl, req, sched::ticks() + 500).is_ok_and(|r| r == b"OK")
    };
    let said = |ok: bool| if ok { "OK" } else { "refused" };
    sched::poll_until(sched::ticks() + 5000, || one_new_stay(&[]));
    let (stay, first) = sched::live_named(b"STAY.ELF");
    let j1 = if first == 1 && stay[0].waiting {
        stay[0].parent
    } else {
        0
    };
    kprintln!(
        "OSX|{}|ktest|session_restart|load={}|session={:#x}|first={}|",
        BUILD_ID,
        load,
        session,
        first
    );
    if session != 0x40 || j1 == 0 {
        fail("the session did not launch and hold as the case states")
    }
    // A RESTART: the session exits 0x40 with the manager's state stopping, and starts again.
    let restart = ask(b"RESTART session");
    let lines = h.poll_list(sched::ticks() + 5000, |l| {
        svc_find(l, "session").restarts == 1
            && held()
            && one_new_stay(&[j1])
            && jobs_now() == 2
            && kept() == 4
    });
    let r = read(&lines, &[j1]);
    drop(lines);
    kprintln!(
        "OSX|{}|ktest|session_restart|restart|restart={}|exit={:#x}|restarts={}|held={}|stays={}|new_job={}|live_jobs={}|mgr_handles={}|",
        BUILD_ID,
        said(restart),
        r.exit,
        r.restarts,
        u8::from(r.held),
        r.stays,
        r.new_job,
        r.live_jobs,
        r.kept
    );
    if !restart
        || r.exit != 0x40
        || r.restarts != 1
        || !r.held
        || r.stays != 1
        || !r.waiting
        || r.new_job != 1
        || r.live_jobs != 2
        || r.kept != 4
    {
        fail("an application of the restarted session outlived it, or the new session could not launch")
    }
    let j2 = r.job;
    // A crash: the session is killed while ready, and the manager starts it again on failure.
    let killed = sched::kill_named(b"LABSES.ELF", crate::syscall::EXIT_KILLED);
    let lines = h.poll_list(sched::ticks() + 5000, |l| {
        svc_find(l, "session").restarts == 2
            && held()
            && one_new_stay(&[j1, j2])
            && jobs_now() == 2
            && kept() == 4
    });
    let r = read(&lines, &[j1, j2]);
    drop(lines);
    kprintln!(
        "OSX|{}|ktest|session_restart|crash|killed={}|exit={:#x}|restarts={}|held={}|stays={}|new_job={}|live_jobs={}|mgr_handles={}|",
        BUILD_ID,
        u8::from(killed),
        r.exit,
        r.restarts,
        u8::from(r.held),
        r.stays,
        r.new_job,
        r.live_jobs,
        r.kept
    );
    if !killed
        || r.exit != crate::syscall::EXIT_KILLED
        || r.restarts != 2
        || !r.held
        || r.stays != 1
        || !r.waiting
        || r.new_job != 1
        || r.live_jobs != 2
        || r.kept != 4
    {
        fail("an application of the crashed session outlived it, or the session started again could not launch")
    }
    // A STOP: the session exits 0x40 and stays stopped; nothing of it is left.
    let stop = ask(b"STOP session");
    let lines = h.poll_list(sched::ticks() + 5000, |l| {
        svc_find(l, "session").state == "stopped"
            && sched::live_named(b"STAY.ELF").1 == 0
            && jobs_now() == 0
            && kept() == 0
    });
    let r = read(&lines, &[]);
    drop(lines);
    kprintln!(
        "OSX|{}|ktest|session_restart|stop|stop={}|state={}|exit={:#x}|stays={}|live_jobs={}|mgr_handles={}|",
        BUILD_ID,
        said(stop),
        if r.stopped { "stopped" } else { "other" },
        r.exit,
        r.stays,
        r.live_jobs,
        r.kept
    );
    if !stop || !r.stopped || r.exit != 0x40 || r.stays != 0 || r.live_jobs != 0 || r.kept != 0 {
        fail("an application of the stopped session outlived it")
    }
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|session_restart|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or applications left something behind")
    }
    // Every value of this case on the kernel's heap goes before the balance, which never returns:
    // a String left alive keeps a heap page and reads as a frame leaked (WP-173's narrowing).
    drop(load);
    svc_balance(name, frames0)
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

/// The manager's live handle count, read while it runs (WP-156); -1 when it is not live.
fn mgr_handles(h: &SvcHarness) -> i64 {
    sched::handles_pid(h.m.pid).map_or(-1, |n| n as i64)
}

/// TST-M4-SVC-CONNECT-NOREAD (REQ-M4-002, services.md v1.13 note of WP-156; RSK-028): a
/// requester that never reads cannot leave the manager holding the client ends of the
/// connections it asked for, nor config holding their slots. N (svc role `noread`) fills its
/// own queue with unread LIST replies and asks three times for a connection to config before
/// READY, so the manager cannot write those replies. The counts are taken across a RESTART of
/// N, which repeats the three requests: the manager's and config's live handle counts are the
/// same before and after. The manager's is exact once N is ready again (READY is the last
/// message of one channel, read in order). config's is read once it is back at its baseline or
/// at a deadline: config takes one channel per wake, lowest slot first, and the test's own
/// connection may sit below N's new ones, so an answered GET does not mean the closed peers
/// were seen; a kept slot never comes back.
fn svc_connect_noread() -> ! {
    let name = "svc_connect_noread";
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-NR.TXT");
    svc_wait_ready(&h, &["config", "N"], sched::ticks() + 60_000);
    let frames0 = {
        let cfg = svc_connect(&h, "config");
        let base_get = cfg_request(&cfg, b"GET device nr.key", None);
        let (m1, c1) = (mgr_handles(&h), cfg_handles());
        let restart = match crate::services::request(&h.m.ctl, b"RESTART N", sched::ticks() + 500) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => alloc::format!("error:{}", e),
        };
        let lines = h.poll_list(sched::ticks() + 10_000, |l| {
            l.iter()
                .any(|x| x.name == "N" && x.restarts == 1 && x.state == "ready")
        });
        let n = svc_find(&lines, "N");
        let sync_get = cfg_request(&cfg, b"GET device nr.key", None);
        let m2 = mgr_handles(&h);
        let settled = sched::poll_until(sched::ticks() + 3_000, || cfg_handles() == c1);
        let c2 = cfg_handles();
        let load = h.load_reply.clone();
        drop(cfg);
        // N reads nothing, so it would outlive the manager: it is stopped (forced at the grace).
        let stop = match crate::services::request(&h.m.ctl, b"STOP N", sched::ticks() + 500) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => alloc::format!("error:{}", e),
        };
        let ended = h.poll_list(sched::ticks() + 5_000, |l| {
            l.iter().any(|x| x.name == "N" && x.state == "stopped")
        });
        let end = svc_find(&ended, "N").state;
        let (mgr_exit, procs, frames0, clean) = h.finish();
        kprintln!(
            "OSX|{}|ktest|svc_connect_noread|load={}|base_get={}|restart={}|state={}|restarts={}|sync_get={}|mgr_grew={}|cfg_grew={}|settled={}|mgr_base={}|cfg_base={}",
            BUILD_ID,
            load,
            base_get,
            restart,
            n.state,
            n.restarts,
            sync_get,
            m2 - m1,
            c2 - c1,
            u8::from(settled),
            m1,
            c1
        );
        kprintln!(
            "OSX|{}|ktest|svc_connect_noread|stop={}|end={}|mgr_exit={:#x}|processes_after={}|clean={}",
            BUILD_ID,
            stop,
            end,
            mgr_exit,
            procs,
            u8::from(clean)
        );
        if load != "OK 2"
            || base_get != "ERR NOT_FOUND"
            || sync_get != "ERR NOT_FOUND"
            || restart != "OK"
            || n.state != "ready"
            || n.restarts != 1
            || m1 < 0
            || c1 < 0
        {
            fail("the requester that never reads was not started, restarted and answered as expected")
        }
        if m2 != m1 {
            fail("the manager kept the client ends whose CONNECT replies it could not write")
        }
        if c2 != c1 {
            fail("config kept the slots of connections whose requester never got them")
        }
        if stop != "OK" || end != "stopped" {
            fail("the requester that never reads could not be stopped")
        }
        if mgr_exit != 0 || procs != 0 || !clean {
            fail("manager or services left something behind")
        }
        frames0
    };
    cfg_balance(
        name,
        frames0,
        "a requester that never reads leaves the manager and config holding nothing of its connections",
    )
}

/// The named line of a `LIST` reply (empty when absent).
fn svc_find(lines: &[SvcLine], name: &str) -> SvcLine {
    lines
        .iter()
        .find(|l| l.name == name)
        .cloned()
        .unwrap_or_default()
}

/// TST-M5-SVC-WATCHDOG (REQ-M5-010, services.md v1.7, v1.8, §8.7): a hung service is detected
/// and ended, a healthy one is not, and a service that ignores STOP is force-killed after the
/// grace. `hung` (watchdog=50, role hang) answers READY then stops servicing, so the watchdog
/// kills it; with max_restarts=1 it is restarted once, hangs again and is given up (restarts=1,
/// EXIT_KILLED). `pong` (watchdog=50, role ready, two spaces before its arg) answers every PING
/// and stays ready; each PONG is traced and counted by the case. `stubborn` (no watchdog, role
/// hang) ignores STOP: 150 ticks after the STOP it is still stopping, then the grace ends in
/// process_kill. v1.8: `closer` (watchdog=50) closes its boot channel after READY — it can no
/// longer be asked, so it is killed as hung; `early` (timeout 50) hangs before READY — failed at
/// the timeout, still alive 200 ticks after its start (the grace runs from the timeout), then
/// forced. The manager keeps answering LIST throughout.
fn svc_watchdog() -> ! {
    const EXIT_KILLED: u64 = 0x2_0000;
    let h = SvcHarness::start("svc_watchdog", b"/SYSTEM/SVC-WD.TXT");
    // `early` fails at its readiness timeout (start + 50); the force comes a STOP grace (200)
    // later, so at start + 200 it must be failed and still alive.
    let first = h.poll_list(sched::ticks() + 2000, |l| {
        l.iter().any(|x| x.name == "early" && x.state == "failed")
    });
    let early_alive = match svc_find(&first, "early").last_start {
        Some(start) if sched::ticks() < start + 200 => {
            sched::poll_until(start + 200, || false);
            let e = svc_find(&h.poll_list(sched::ticks(), |_| true), "early");
            e.state == "failed" && e.exit.is_none()
        }
        _ => false,
    };
    // The watchdog kills the hung service, restarts it once, then gives up; the channel closer
    // is killed as hung and the early hanger is forced — while the healthy one stays ready.
    let lines = h.poll_list(sched::ticks() + 6000, |l| {
        l.iter().any(|x| x.name == "hung" && x.state == "given_up")
            && l.iter().any(|x| x.name == "closer" && x.exit.is_some())
            && l.iter().any(|x| x.name == "early" && x.exit.is_some())
    });
    let hung = svc_find(&lines, "hung");
    let pong = svc_find(&lines, "pong");
    let closer = svc_find(&lines, "closer");
    let early = svc_find(&lines, "early");
    let loud = svc_find(&lines, "loud");
    // The stubborn service (no watchdog) ignores STOP; the grace then force-kills it — not
    // before: 150 ticks after the request it is still stopping.
    let t0 = sched::ticks();
    let stop = match crate::services::request(&h.m.ctl, b"STOP stubborn", sched::ticks() + 500) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => e.into(),
    };
    sched::poll_until(t0 + 150, || false);
    let mid = svc_find(&h.poll_list(sched::ticks(), |_| true), "stubborn");
    let lines2 = h.poll_list(sched::ticks() + 2000, |l| {
        l.iter()
            .any(|x| x.name == "stubborn" && x.state == "stopped")
    });
    let stubborn = svc_find(&lines2, "stubborn");
    let again = crate::services::request(&h.m.ctl, b"LIST", sched::ticks() + 200).is_ok();
    let text = SvcHarness::list_text(&lines2);
    let load = h.load_reply.clone();
    let (mgr_exit, procs, frames0, clean) = h.finish();
    let code = |l: &SvcLine| l.exit.map_or(-1, |e| e as i64);
    kprintln!(
        "OSX|{}|ktest|svc_watchdog|load={}|list={}|hung={}:{}:{}|pong={}:{}|closer={}:{}|early={}:{}|early_alive_at_200={}|loud={}:{}|stop={}|stubborn_at_150={}|stubborn={}:{}|list_after={}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        load,
        text,
        hung.state,
        hung.restarts,
        code(&hung),
        pong.state,
        pong.restarts,
        closer.state,
        code(&closer),
        early.state,
        code(&early),
        u8::from(early_alive),
        loud.state,
        loud.restarts,
        stop,
        mid.state,
        stubborn.state,
        code(&stubborn),
        u8::from(again),
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 6"
        || hung.state != "given_up"
        || hung.restarts != 1
        || hung.exit != Some(EXIT_KILLED)
    {
        fail("the watchdog did not kill and give up the hung service as services.md v1.7 says")
    }
    if pong.state != "ready" || pong.restarts != 0 {
        fail("a service that answered the watchdog was not left alone")
    }
    if closer.state != "failed" || closer.exit != Some(EXIT_KILLED) {
        fail("a service that closed its boot channel was not killed as hung (services.md v1.8)")
    }
    if !early_alive || early.state != "failed" || early.exit != Some(EXIT_KILLED) {
        fail("a service hung before READY was not forced after the grace (services.md v1.8)")
    }
    if loud.state != "ready" || loud.restarts != 0 {
        fail("a message larger than any request kept the manager from reading READY (services.md v1.9)")
    }
    if stop != "OK"
        || mid.state != "stopping"
        || stubborn.state != "stopped"
        || stubborn.exit != Some(EXIT_KILLED)
    {
        fail("a service that ignored STOP was not force-killed after the grace")
    }
    if !again {
        fail("the manager stopped answering LIST")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    drop((
        first, lines, lines2, hung, pong, closer, early, loud, mid, stubborn, text, load, stop,
    ));
    svc_balance("svc_watchdog", frames0)
}

/// TST-M5-SESSION-DEADLINE (REQ-M5-010, session.md v1.1): the session waits on no component for
/// ever. `input` and `display` are svc `silent`: each takes the session's request (REGISTER,
/// then STATUS) and never answers. The session must give each its REQUEST_DEADLINE, treat it as
/// lost and close its channel (each silent service traces how long the request was held and
/// whether that falls in [4900, 6000] ticks), then exit 0xE4 — without the deadline it would
/// block in its first request for ever. The silent services stay ready; nothing leaks.
fn session_deadline() -> ! {
    let h = SvcHarness::start("session_deadline", b"/SYSTEM/SVC-SD.TXT");
    let lines = h.poll_list(sched::ticks() + 120_000, |l| {
        l.iter().any(|x| x.name == "session" && x.exit.is_some())
    });
    let session = svc_find(&lines, "session");
    let input = svc_find(&lines, "input");
    let display = svc_find(&lines, "display");
    let text = SvcHarness::list_text(&lines);
    let load = h.load_reply.clone();
    let (mgr_exit, procs, frames0, clean) = h.finish();
    let code = |l: &SvcLine| l.exit.map_or(-1, |e| e as i64);
    kprintln!(
        "OSX|{}|ktest|session_deadline|load={}|list={}|session={}:{}|input={}:{}|display={}:{}|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        load,
        text,
        session.state,
        code(&session),
        input.state,
        code(&input),
        display.state,
        code(&display),
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if load != "OK 4" {
        fail("the manifest did not load")
    }
    if session.state != "failed" || session.exit != Some(0xE4) {
        fail("the session did not give up on components that never answer (session.md v1.1)")
    }
    if input.state != "ready" || display.state != "ready" {
        fail("a silent component did not stay ready")
    }
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    drop((lines, session, input, display, text, load));
    svc_balance("session_deadline", frames0)
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
    // Wrong password and unknown name: the same refusal, no token, after the same derivation
    // (auth.md v1.1: the unknown name's refusal is not the quicker one).
    let t0 = sched::ticks();
    let (r2, t2) = auth_request(&ep, b"LOGIN admin wrong-password", None);
    let wrong_ticks = sched::ticks() - t0;
    let t0 = sched::ticks();
    let (r3, t3) = auth_request(&ep, b"LOGIN nobody lab-admin-1", None);
    let unknown_ticks = sched::ticks() - t0;
    // Four more failures reach the limit; the right password is then delayed.
    let mut refused = 0;
    for _ in 0..4 {
        if auth_request(&ep, b"LOGIN admin wrong-password", None).0 == "ERR ACCESS" {
            refused += 1;
        }
    }
    let (r_delayed, t_delayed) = auth_request(&ep, b"LOGIN admin lab-admin-1", None);
    let delayed = r_delayed.starts_with("ERR DELAYED ") && t_delayed.is_none();
    // An unknown name reaches the same limit (v1.1), so the delay does not tell names apart.
    for _ in 0..4 {
        auth_request(&ep, b"LOGIN nobody wrong-password", None);
    }
    let unknown_delayed = auth_request(&ep, b"LOGIN nobody lab-admin-1", None)
        .0
        .starts_with("ERR DELAYED ");
    // The other user is not delayed.
    let (r_other, t_other) = auth_request(&ep, b"LOGIN user lab-user-1", None);
    // After the delay the right password works again.
    let t = sched::ticks() + 2100;
    sched::poll_until(t, || false);
    let (r_after, t_after) = auth_request(&ep, b"LOGIN admin lab-admin-1", None);
    // A sixth failure doubles the delay (v1.1): the next attempt waits more than 2000 ticks.
    let sixth = auth_request(&ep, b"LOGIN nobody wrong-password", None).0;
    let doubled = auth_request(&ep, b"LOGIN nobody wrong-password", None).0;
    let doubled_wait = doubled
        .strip_prefix("ERR DELAYED ")
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(0);
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
    kprintln!(
        "OSX|{}|ktest|login|unknown_delayed={}|sixth={}|doubled_wait_over_2000={}|wrong_ticks={}|unknown_ticks={}|unknown_as_slow={}",
        BUILD_ID,
        unknown_delayed,
        sixth,
        doubled_wait > 2000 && doubled_wait <= 4000,
        wrong_ticks,
        unknown_ticks,
        unknown_ticks * 2 >= wrong_ticks
    );
    if !unknown_delayed || sixth != "ERR ACCESS" || !(2001..=4000).contains(&doubled_wait) {
        fail("an unknown name was not limited like a user, or the delay did not double")
    }
    if unknown_ticks * 2 < wrong_ticks {
        fail("an unknown name was refused quicker than a wrong password")
    }
    if r_after != "OK 1000 1000 15" || whoami != "OK 1000 1000 15" || bad != "ERR BAD_REQUEST" {
        fail("login after the delay, WHOAMI or the bad request answer wrong")
    }
    drop((
        r1, r_user, r2, r3, r_delayed, r_other, r_after, whoami, bad, load, sixth, doubled,
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

/// TST-M5-FILE-AUTHORITY (REQ-M5-006, RSK-008; files.md v1.3, WP-44): /SYSTEM belongs to the
/// holders of the system-files authority. `fileauth` with no handle finds every read and every
/// change under /SYSTEM refused, however the path is spelled, the fonts readable but not
/// writable, and the rest of the volume as before (exit 0x44); with a READ-only authority it
/// reads /SYSTEM but still changes nothing (0x45). The kernel reads back that neither run
/// changed /SYSTEM. The services the manager hands the authority to still work: auth signs the
/// lab in, and config, holding WRITE, stores an admin setting on /SYSTEM.
fn file_authority() -> ! {
    use crate::fs::vfs;
    let name = "file_authority";
    if crate::apps::FILEAUTH.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let size = |p: &[u8]| vfs::stat(p).map_or(-1, |s| s.size as i64);
    let (inputd0, users0) = (size(b"/SYSTEM/INPUTD.ELF"), size(b"/SYSTEM/USERS.DB"));
    let obj0 = object::stats();
    let probe = match crate::user::run_elf(crate::apps::FILEAUTH) {
        Ok((o, _)) => o,
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|error={}", BUILD_ID, name, e.code());
            fail("application did not load")
        }
    };
    // The authority outlives the run, so its own allocation does not count in the probe's
    // frame balance (CI run 39294977208: frames -1 when the probe's exit freed it).
    let authority = Arc::new(crate::object::token::SystemFiles::new());
    let reader = run_with_object(
        name,
        crate::apps::FILEAUTH,
        Entry {
            object: Object::SystemFiles(authority.clone()),
            rights: Rights::READ,
        },
    );
    drop(authority);
    let obj1 = object::stats();
    let inputd_same = inputd0 > 0 && size(b"/SYSTEM/INPUTD.ELF") == inputd0;
    let users_same = users0 > 0 && size(b"/SYSTEM/USERS.DB") == users0;
    let created = vfs::stat(b"/SYSTEM/NEW.TXT").is_ok();
    kprintln!(
        "OSX|{}|ktest|{}|probe={:#x}|probe_ro={:#x}|frames={}+{}|inputd_same={}|usersdb_same={}|created={}|objects_same={}",
        BUILD_ID,
        name,
        probe.exit_code,
        reader.exit_code,
        probe.frames_delta,
        reader.frames_delta,
        u8::from(inputd_same),
        u8::from(users_same),
        u8::from(created),
        u8::from(obj1 == obj0)
    );
    if probe.exit_code != 0x44 || reader.exit_code != 0x45 {
        fail("an ordinary process reached /SYSTEM (exit code = failing step)")
    }
    if !inputd_same
        || !users_same
        || created
        || probe.frames_delta != 0
        || reader.frames_delta != 0
        || obj1 != obj0
    {
        fail("/SYSTEM changed, or the probes left something behind")
    }
    // The services the manager hands the authority to: auth reads USERS.DB (the logins of
    // cfg_env), config writes its store on /SYSTEM.
    let env = cfg_env(name);
    let set = cfg_request(
        &env.cfg,
        b"SET device lab.fauth 0 201 kept",
        Some(token_entry(&env.admin)),
    );
    let get = cfg_request(&env.cfg, b"GET device lab.fauth", None);
    kprintln!(
        "OSX|{}|ktest|{}|services=auth,config|set={}|get={}",
        BUILD_ID,
        name,
        set,
        get
    );
    if set != "OK 1" || get != "OK 1 kept" {
        fail("a service holding the authority could not use /SYSTEM")
    }
    drop((set, get));
    let frames0 = cfg_close(env, name);
    cfg_balance(
        name,
        frames0,
        "an ordinary process cannot read or change /SYSTEM; the services holding the authority can",
    )
}

/// TST-M6-CONFIG-WRITE-SCOPE (REQ-M6-002, RSK-019; files.md v1.4, config.md v1.2, WP-78):
/// config's authority, READ|WRITE|TRANSFER, changes only config's stores. `fileauth` given
/// that mask finds every other change under /SYSTEM refused (SERVICES.TXT in three spellings,
/// USERS.DB, INPUTD.ELF, a new file, a non-CFG `.A`, a CFG name with another extension, an
/// unlink, the fonts) and then creates, writes and removes /SYSTEM/CFGPRB.A (exit 0x46; else the
/// failing step). The kernel reads back SERVICES.TXT, USERS.DB and INPUTD.ELF unchanged and none
/// of the probe's names left behind; config still stores a device setting; the matcher's table.
fn config_write_scope() -> ! {
    use crate::fs::vfs;
    let name = "config_write_scope";
    if crate::apps::FILEAUTH.is_empty() {
        fail("embedded application missing (kernel built without NAWAH_APPS_DIR)")
    }
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let size = |p: &[u8]| vfs::stat(p).map_or(-1, |s| s.size as i64);
    let (svc0, users0, inputd0) = (
        size(b"/SYSTEM/SERVICES.TXT"),
        size(b"/SYSTEM/USERS.DB"),
        size(b"/SYSTEM/INPUTD.ELF"),
    );
    let obj0 = object::stats();
    // The authority outlives the run (as in file_authority: its block is not the probe's).
    let authority = Arc::new(crate::object::token::SystemFiles::new());
    let probe = run_with_object(
        name,
        crate::apps::FILEAUTH,
        Entry {
            object: Object::SystemFiles(authority.clone()),
            rights: Rights(Rights::READ.0 | Rights::WRITE.0 | Rights::TRANSFER.0),
        },
    );
    drop(authority);
    let obj1 = object::stats();
    let services_same = svc0 > 0 && size(b"/SYSTEM/SERVICES.TXT") == svc0;
    let users_same = users0 > 0 && size(b"/SYSTEM/USERS.DB") == users0;
    let inputd_same = inputd0 > 0 && size(b"/SYSTEM/INPUTD.ELF") == inputd0;
    let created = [
        &b"/SYSTEM/NEW.TXT"[..],
        b"/SYSTEM/AUTHD.A",
        b"/SYSTEM/CFGPRB.C",
        b"/SYSTEM/CFGPRB.A",
        b"/SYSTEM/FONTS/CFGPRB.A",
    ]
    .iter()
    .any(|p| vfs::stat(p).is_ok());
    kprintln!(
        "OSX|{}|ktest|{}|probe={:#x}|services_same={}|usersdb_same={}|inputd_same={}|created={}|frames={}|objects_same={}",
        BUILD_ID,
        name,
        probe.exit_code,
        u8::from(services_same),
        u8::from(users_same),
        u8::from(inputd_same),
        u8::from(created),
        probe.frames_delta,
        u8::from(obj1 == obj0)
    );
    if probe.exit_code != 0x46 {
        fail("config's authority changed /SYSTEM outside its stores (exit code = failing step)")
    }
    if !services_same
        || !users_same
        || !inputd_same
        || created
        || probe.frames_delta != 0
        || obj1 != obj0
    {
        fail("/SYSTEM changed, or the probe left something behind")
    }
    // The matcher over the spellings a path can take (compared as the volume's short names).
    let table: [(&[u8], bool); 8] = [
        (b"/SYSTEM/CFGDEV.A", true),
        (b"/system/cfgdev.a", true),
        (b"/SYSTEM./CFGU1000.B", true),
        (b"/SYSTEM/CFGPOL.C", false),
        (b"/SYSTEM/AUTHD.A", false),
        (b"/SYSTEM/FONTS/CFGDEV.A", false),
        (b"/SYSTEM/../SYSTEM/CFGDEV.A", false),
        (b"/SYSTEM/SERVICES.TXT", false),
    ];
    let mut right = 0;
    for (path, want) in table {
        let got = vfs::is_config_store(path);
        if got == want {
            right += 1;
        } else {
            kprintln!(
                "OSX|{}|ktest|{}|path={}|got={}",
                BUILD_ID,
                name,
                String::from_utf8_lossy(path),
                u8::from(got)
            );
        }
    }
    kprintln!(
        "OSX|{}|ktest|{}|table={}/{}",
        BUILD_ID,
        name,
        right,
        table.len()
    );
    if right != table.len() {
        fail("the store matcher answered a spelling wrongly")
    }
    // Config itself still writes its stores through the same authority.
    let env = cfg_env(name);
    let set = cfg_request(
        &env.cfg,
        b"SET device lab.cwscope 0 201 kept",
        Some(token_entry(&env.admin)),
    );
    let get = cfg_request(&env.cfg, b"GET device lab.cwscope", None);
    kprintln!(
        "OSX|{}|ktest|{}|services=auth,config|set={}|get={}",
        BUILD_ID,
        name,
        set,
        get
    );
    if set != "OK 1" || get != "OK 1 kept" {
        fail("config could not write its own store")
    }
    drop((set, get));
    let frames0 = cfg_close(env, name);
    cfg_balance(
        name,
        frames0,
        "config's authority changes only its own stores",
    )
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
        // Session values are read with the token that wrote them (config.md v1.1).
        let session_set = cfg_request(
            ep,
            b"SET session lab.s 0 108 secret",
            Some(token_entry(&env.admin)),
        );
        let session_live = cfg_request(ep, b"GET session lab.s", Some(token_entry(&env.admin)));
        // A revoked token is refused even with every permission.
        env.admin.revoke();
        let revoked = cfg_request(
            ep,
            b"SET device lab.key 1 107 after-revoke",
            Some(token_entry(&env.admin)),
        );
        let still = cfg_request(ep, b"GET device lab.key", None);
        // ... and no longer reads its session values.
        let session_revoked = cfg_request(ep, b"GET session lab.s", Some(token_entry(&env.admin)));
        let export_revoked = cfg_request(ep, b"EXPORT session", Some(token_entry(&env.admin)));
        kprintln!(
            "OSX|{}|ktest|authz_denied|session_set={}|session_live={}|session_revoked={}|export_revoked={}|",
            BUILD_ID,
            session_set,
            session_live,
            session_revoked,
            export_revoked
        );
        if session_set != "OK 1"
            || session_live != "OK 1 secret"
            || session_revoked != "ERR NOT_FOUND"
            || export_revoked != "OK"
        {
            fail("a revoked token still read its session values")
        }
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

/// configd's live handle count, read while it runs (WP-107); -1 when no live configd matches.
fn cfg_handles() -> i64 {
    sched::handles_named(b"CONFIGD.ELF").map_or(-1, |n| n as i64)
}

/// TST-M4-CONFIG-RETRY (REQ-M4-005, config.md v1.3, WP-107): a repeated request id applies once
/// and replays its stored reply; and configd's own handle count, read while it lives, does not
/// grow: not by the replays of the body, nor by 20 more replays carrying a token, nor by a
/// replay whose reply cannot be written (its sender closed its end before reading).
fn config_retry() -> ! {
    let env = cfg_env("config_retry");
    let frames0 = {
        let ep = &env.cfg;
        let a = token_entry(&env.admin);
        // An answered request shows configd has read this client's CONNECT: the client end is
        // in its table before the count is taken (the boot channel is served first).
        let _ = cfg_request(ep, b"GET device sync.key", None);
        let h0 = cfg_handles();
        let r1 = cfg_request(ep, b"SET device retry.key 0 301 v1", Some(a.clone()));
        let r1b = cfg_request(ep, b"SET device retry.key 0 301 v1", Some(a.clone()));
        let read = cfg_request(ep, b"GET device retry.key", None);
        // A refused request is replayed as refused too.
        let bad = cfg_request(ep, b"SET device retry.key 0 302 v2", Some(a.clone()));
        let bad_again = cfg_request(ep, b"SET device retry.key 1 302 v2", Some(a.clone()));
        let read2 = cfg_request(ep, b"GET device retry.key", None);
        // Id 0 is never cached: the second call is a real (now stale) attempt.
        let z1 = cfg_request(ep, b"SET device retry.key 1 0 v3", Some(a.clone()));
        let z2 = cfg_request(ep, b"SET device retry.key 1 0 v3", Some(a.clone()));
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
        // WP-107: the balance is taken while configd lives. The body's two replays (r1b,
        // bad_again) carried a token; so do 20 more replays of request 301.
        let h1 = cfg_handles();
        const REPLAYS: usize = 20;
        let mut same = 0;
        for _ in 0..REPLAYS {
            if cfg_request(ep, b"SET device retry.key 0 301 v1", Some(a.clone())) == "OK 1" {
                same += 1;
            }
        }
        let h2 = cfg_handles();
        // A reply configd cannot write: a second client stores request 311, then, while configd
        // is held (frozen, so it cannot read or write in between), queues its replay with a
        // token and closes its end. Released, configd reads the queued replay, its write meets
        // the closed peer and it closes the client; the endpoint count coming back to its value
        // before the connection shows that it did.
        let e0 = channel::live_endpoints();
        let ep2 = svc_connect(&env.h, "config");
        let first = cfg_request(&ep2, b"SET device retry.key2 0 311 w1", Some(a.clone()));
        let frozen = sched::freeze_named(b"CONFIGD.ELF");
        // Parked, it reads nothing until the thaw: the replay is read after the close.
        let parked = sched::poll_until(sched::ticks() + 5_000, || {
            sched::parked_named(b"CONFIGD.ELF")
        });
        let queued = ep2
            .write(Message {
                bytes: b"SET device retry.key2 0 311 w1".to_vec(),
                handles: alloc::vec![a],
            })
            .is_ok();
        drop(ep2);
        let thawed = sched::thaw_named(b"CONFIGD.ELF");
        let released =
            sched::poll_until(sched::ticks() + 5_000, || channel::live_endpoints() == e0);
        let h3 = cfg_handles();
        kprintln!(
            "OSX|{}|ktest|config_retry|live|body_grew={}|replays={}|same={}|replays_grew={}|unwritable_first={}|frozen={}|parked={}|queued={}|thawed={}|released={}|unwritable_grew={}|base={}",
            BUILD_ID,
            h1 - h0,
            REPLAYS,
            same,
            h2 - h1,
            first,
            u8::from(frozen),
            u8::from(parked),
            u8::from(queued),
            u8::from(thawed),
            u8::from(released),
            h3 - h2,
            h0
        );
        if h0 < 0 || same != REPLAYS || first != "OK 1" || !queued {
            fail("the live balance's requests were not answered as stored")
        }
        if !frozen || !parked || !thawed {
            fail("configd was not held while the reply it cannot write was set up")
        }
        if h1 != h0 || h2 != h1 {
            fail("configd kept the handles its replayed requests carried")
        }
        if !released || h3 != h2 {
            fail("configd kept the handle of a request whose reply it could not write")
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

/// TST-M4-CONFIG-STORE-AUTHZ (REQ-M4-004, config.md v1.4, WP-157; RSK-028): a request that is
/// refused, or that shows no token, takes no user-store slot. The user's SET and IMPORT on the
/// stores of other uids are refused and leave no store behind (EXPORT finds none); eight
/// SUBSCRIBE to eight more user stores, each carrying a channel end and no token, find no
/// store, and two with a uid no store may carry (0 and 10000) are invalid; then the user's own
/// SET is accepted (with the eight slots free) and his own store, now loaded, can be subscribed
/// to; an administrator's SET creates the store the user was refused, and the user's SET on
/// that store, now loaded, is refused and changes nothing. Last the administrator fills the
/// eight slots: a ninth store is ERR INVALID and the user's loaded store still takes his SET.
/// configd's live handle count grew by the one subscription.
fn config_store_authz() -> ! {
    let env = cfg_env("config_store_authz");
    let frames0 = {
        let ep = &env.cfg;
        let u = token_entry(&env.user);
        let a = token_entry(&env.admin);
        let end = |s: Arc<Endpoint>| Entry {
            object: Object::Channel(s),
            rights: Rights::CHANNEL_DEFAULT,
        };
        // An answered request first: configd has read this client's CONNECT (see config_retry).
        let _ = cfg_request(ep, b"GET device sync.key", None);
        let h0 = cfg_handles();
        let set_other = cfg_request(ep, b"SET user/3001 k 0 801 v", Some(u.clone()));
        // The administrator reads (a user store is read for its owner or ADMIN alone, config.md
        // v1.6): no slot was taken and no store is on the volume, so it is not found.
        let other_export = cfg_request(ep, b"EXPORT user/3001", Some(a.clone()));
        let import_other = cfg_request(ep, b"IMPORT user/3002 802\nk v", Some(u.clone()));
        let import_export = cfg_request(ep, b"EXPORT user/3002", Some(a.clone()));
        // No user store is subscribed to (config.md v1.6): SUBSCRIBE shows no token.
        let (mut subs_ok, mut subs_refused) = (0, 0);
        let mut kept = Vec::new();
        for k in 1..=8 {
            let (mine, theirs) = channel::create();
            let req = alloc::format!("SUBSCRIBE user/200{}", k);
            match cfg_request(ep, req.as_bytes(), Some(end(theirs))).as_str() {
                "OK" => subs_ok += 1,
                "ERR ACCESS" => subs_refused += 1,
                _ => {}
            }
            kept.push(mine);
        }
        // A uid no store may carry is no store name (config.md §1: 1 to 9999).
        let (zero_k, zero_s) = channel::create();
        let sub_zero = cfg_request(ep, b"SUBSCRIBE user/0", Some(end(zero_s)));
        let (big_k, big_s) = channel::create();
        let sub_big = cfg_request(ep, b"SUBSCRIBE user/10000", Some(end(big_s)));
        let own_set = cfg_request(ep, b"SET user/1001 wp.k 0 803 v", Some(u.clone()));
        let (own_k, own_s) = channel::create();
        let own_sub = cfg_request(ep, b"SUBSCRIBE user/1001", Some(end(own_s)));
        // ADMIN may modify any user's store (config.md §1): the store the user was refused.
        let admin_set = cfg_request(ep, b"SET user/3001 k 0 804 v", Some(a.clone()));
        // That store is loaded now: the user is refused by the store's own check.
        let loaded_other = cfg_request(ep, b"SET user/3001 k 1 805 x", Some(u.clone()));
        let loaded_kept = cfg_request(ep, b"EXPORT user/3001", Some(a.clone())) == "OK\nk 1 v";
        // The administrator fills the eight slots (1001, 3001 and six more).
        let mut filled = 0;
        for k in 2..=7 {
            let req = alloc::format!("SET user/300{} k 0 {} v", k, 804 + k);
            if cfg_request(ep, req.as_bytes(), Some(a.clone())) == "OK 1" {
                filled += 1;
            }
        }
        let full_set = cfg_request(ep, b"SET user/3008 k 0 812 v", Some(a));
        let own_again = cfg_request(ep, b"SET user/1001 wp.k 1 813 w", Some(u));
        let h1 = cfg_handles();
        kprintln!(
            "OSX|{}|ktest|config_store_authz|set_other={}|other_export={}|import_other={}|import_export={}|subs_ok={}|subs_refused={}|own_set={}|own_sub={}|admin_set={}|cfg_grew={}|base={}",
            BUILD_ID,
            set_other,
            other_export,
            import_other,
            import_export,
            subs_ok,
            subs_refused,
            own_set,
            own_sub,
            admin_set,
            h1 - h0,
            h0
        );
        kprintln!(
            "OSX|{}|ktest|config_store_authz|more|sub_zero={}|sub_big={}|loaded_other={}|loaded_kept={}|filled={}|full_set={}|own_again={}|",
            BUILD_ID,
            sub_zero,
            sub_big,
            loaded_other,
            loaded_kept as u8,
            filled,
            full_set,
            own_again
        );
        if h0 < 0 {
            fail("configd's live handle count could not be read")
        }
        if set_other != "ERR ACCESS" || import_other != "ERR ACCESS" {
            fail("a write on another user's store was not refused")
        }
        if other_export != "ERR NOT_FOUND" || import_export != "ERR NOT_FOUND" {
            fail("a refused write left a user store behind")
        }
        if subs_ok != 0 || subs_refused != 8 || own_sub != "ERR ACCESS" {
            fail("a subscriber without a token took a user store")
        }
        if sub_zero != "ERR INVALID" || sub_big != "ERR INVALID" {
            fail("a name that is no user store was not answered ERR INVALID")
        }
        if own_set != "OK 1" {
            fail("the user's own store was refused")
        }
        if admin_set != "OK 1" {
            fail("an administrator was refused a user's store")
        }
        if loaded_other != "ERR ACCESS" || !loaded_kept {
            fail("a write on another user's loaded store was not refused")
        }
        if filled != 6 || full_set != "ERR INVALID" || own_again != "OK 2" {
            fail("a full table of user stores was not answered as the contract says")
        }
        if h1 - h0 != 0 {
            fail("configd kept a handle of a request it refused")
        }
        drop((kept, zero_k, big_k, own_k));
        cfg_close(env, "config_store_authz")
    };
    cfg_balance(
        "config_store_authz",
        frames0,
        "a refused or token-less request takes no user store, and the user's own store is his",
    )
}

/// TST-M4-CONFIG-READ-LOAD (REQ-M4-004, REQ-M4-005, config.md v1.6, WP-112; with WP-168): a user
/// store is read for its owner's or an administrator's usable token alone, and loaded on such a
/// read. The lab volume carries three user stores no request has loaded, as after a restart:
/// CFGU1001.A (the lab user's own, `lab.read 1 mine`), CFGU1002.A (`theirs`) and CFGU1003.A
/// (`hidden`). Without a token, GET of the user's store is not found, loaded or not; RESOLVE with
/// the user's token loads it; GET and EXPORT with that token read it; the administrator's GET
/// loads 1002; SUBSCRIBE of a loaded user store is refused. The user's GET and EXPORT of 1002
/// (loaded) and of 1003 (not loaded) are not found and load nothing; six reads of stores no
/// volume holds take no slot, so the administrator fills the six slots left. With the table
/// full: a refused reader still learns nothing, a loaded store is still read, a key policy holds
/// is answered without the reader's store and another key is ERR INVALID; CONFIG_WRITE, a group
/// of that uid and an expired administrator's token read nothing; a write on a store a read
/// loaded goes to its other slot (the host check reads CFGU1001.B). Revoked tokens read nothing.
fn config_read_load() -> ! {
    let name = "config_read_load";
    let env = cfg_env(name);
    let frames0 = {
        let ep = &env.cfg;
        let u = token_entry(&env.user);
        let a = token_entry(&env.admin);
        let nf = "ERR NOT_FOUND";
        let bare = cfg_request(ep, b"GET user/1001 lab.read", None);
        let resolve = cfg_request(ep, b"RESOLVE lab.read", Some(u.clone()));
        let bare_loaded = cfg_request(ep, b"GET user/1001 lab.read", None);
        let own = cfg_request(ep, b"GET user/1001 lab.read", Some(u.clone()));
        let own_export = cfg_request(ep, b"EXPORT user/1001", Some(u.clone())).replace('\n', ";");
        let admin = cfg_request(ep, b"GET user/1002 lab.read", Some(a.clone()));
        // SUBSCRIBE carries no token: a user store, loaded or not, is not subscribed to (v1.6), so
        // a subscriber learns neither that the store is loaded nor its keys.
        let (sub_kept, sub_end) = channel::create();
        let sub_end = Entry {
            object: Object::Channel(sub_end),
            rights: Rights::CHANNEL_DEFAULT,
        };
        let sub_loaded = cfg_request(ep, b"SUBSCRIBE user/1002", Some(sub_end));
        let other_loaded = cfg_request(ep, b"GET user/1002 lab.read", Some(u.clone()));
        let other_loaded_export =
            cfg_request(ep, b"EXPORT user/1002", Some(u.clone())).replace('\n', ";");
        let other = cfg_request(ep, b"GET user/1003 lab.read", Some(u.clone()));
        let other_export = cfg_request(ep, b"EXPORT user/1003", Some(u.clone())).replace('\n', ";");
        // Stores no volume holds: none of them may take a slot.
        let mut absent = 0;
        for k in 1..=6 {
            let req = alloc::format!("GET user/200{} lab.read", k);
            if cfg_request(ep, req.as_bytes(), Some(a.clone())) == nf {
                absent += 1;
            }
        }
        let pol = cfg_request(ep, b"SET policy lab.pol 0 899 locked", Some(a.clone()));
        // 1001 and 1002 hold two of the eight slots: the administrator fills the six left.
        let mut filled = 0;
        for k in 1..=6 {
            let req = alloc::format!("SET user/300{} k 0 {} v", k, 900 + k);
            if cfg_request(ep, req.as_bytes(), Some(a.clone())) == "OK 1" {
                filled += 1;
            }
        }
        let full_set = cfg_request(ep, b"SET user/3007 k 0 907 v", Some(a.clone()));
        let full_read = cfg_request(ep, b"GET user/1003 lab.read", Some(a.clone()));
        // The full table (WP-112's review round): a refused reader still learns nothing of it, a
        // loaded store is still read, a key policy holds is answered without the reader's store
        // (policy beats every user value), and another key needs that store: no slot, ERR INVALID.
        let refused_full = cfg_request(ep, b"GET user/1003 lab.read", Some(u.clone()));
        let bare_full = cfg_request(ep, b"GET user/1003 lab.read", None);
        let loaded_full = cfg_request(ep, b"GET user/1002 lab.read", Some(a.clone()));
        let resolve_full = cfg_request(ep, b"RESOLVE lab.read", Some(u.clone()));
        let mint = |uid: u32, gid: u32, perms: u32, expires: u64| {
            token_entry(&Arc::new(crate::object::token::Token::new(
                uid, gid, perms, expires,
            )))
        };
        use crate::object::token::{PERM_ADMIN, PERM_CONFIG_WRITE, PERM_SHELL};
        let stranger = mint(1004, 1004, PERM_SHELL, 0);
        let policy_full = cfg_request(ep, b"RESOLVE lab.pol", Some(stranger.clone()));
        let stranger_full = cfg_request(ep, b"RESOLVE lab.read", Some(stranger));
        // CONFIG_WRITE writes the device store, it reads no user's; nor does a group of that uid.
        let cw = cfg_request(
            ep,
            b"GET user/1002 lab.read",
            Some(mint(1004, 1004, PERM_CONFIG_WRITE, 0)),
        );
        let grp = cfg_request(
            ep,
            b"GET user/1002 lab.read",
            Some(mint(1005, 1002, PERM_SHELL, 0)),
        );
        // An expired administrator's token reads as no token.
        let admin_expired = cfg_request(
            ep,
            b"GET user/1002 lab.read",
            Some(mint(1000, 1000, PERM_ADMIN, 1)),
        );
        // A write on a store a read loaded goes to its other slot (generation 2 into CFGU1001.B,
        // read on the volume by the case's host check): the read kept the slots' generations.
        let write = cfg_request(ep, b"SET user/1001 lab.read 1 908 new", Some(u.clone()));
        // A revoked token reads as no token, on the user's own loaded store too.
        env.user.revoke();
        let revoked = cfg_request(ep, b"GET user/1001 lab.read", Some(u.clone()));
        let revoked_export = cfg_request(ep, b"EXPORT user/1001", Some(u)).replace('\n', ";");
        env.admin.revoke();
        let admin_revoked = cfg_request(ep, b"GET user/1002 lab.read", Some(a));
        kprintln!(
            "OSX|{}|ktest|config_read_load|bare={}|resolve={}|bare_loaded={}|own={}|own_export={}|admin={}|",
            BUILD_ID,
            bare,
            resolve,
            bare_loaded,
            own,
            own_export,
            admin
        );
        kprintln!(
            "OSX|{}|ktest|config_read_load|more|other_loaded={}|other_loaded_export={}|other={}|other_export={}|absent={}|filled={}|full_set={}|full_read={}|revoked={}|revoked_export={}|",
            BUILD_ID,
            other_loaded,
            other_loaded_export,
            other,
            other_export,
            absent,
            filled,
            full_set,
            full_read,
            revoked,
            revoked_export
        );
        kprintln!(
            "OSX|{}|ktest|config_read_load|full|sub_loaded={}|pol={}|refused_full={}|bare_full={}|loaded_full={}|resolve_full={}|policy_full={}|stranger_full={}|cw={}|grp={}|admin_expired={}|write={}|admin_revoked={}|",
            BUILD_ID,
            sub_loaded,
            pol,
            refused_full,
            bare_full,
            loaded_full,
            resolve_full,
            policy_full,
            stranger_full,
            cw,
            grp,
            admin_expired,
            write,
            admin_revoked
        );
        if resolve != "OK user 1 mine"
            || own != "OK 1 mine"
            || own_export != "OK;lab.read 1 mine"
            || admin != "OK 1 theirs"
        {
            fail("a user store was not loaded on a read of its owner or an administrator")
        }
        if [
            &bare,
            &bare_loaded,
            &other_loaded,
            &other_loaded_export,
            &other,
            &other_export,
            &revoked,
            &revoked_export,
        ]
        .iter()
        .any(|r| r.as_str() != nf)
        {
            fail("a user store was read without its owner's or an administrator's usable token")
        }
        if absent != 6 || filled != 6 || full_set != "ERR INVALID" || full_read != "ERR INVALID" {
            fail("a refused read or a store no volume holds took a slot of the table")
        }
        if [
            &refused_full,
            &bare_full,
            &cw,
            &grp,
            &admin_expired,
            &admin_revoked,
        ]
        .iter()
        .any(|r| r.as_str() != nf)
            || sub_loaded != "ERR ACCESS"
        {
            fail("a user store was read without its owner's or an administrator's usable token")
        }
        if pol != "OK 1"
            || loaded_full != "OK 1 theirs"
            || resolve_full != "OK user 1 mine"
            || policy_full != "OK policy 1 locked"
            || stranger_full != "ERR INVALID"
        {
            fail("a full table stood before a policy value or a loaded store")
        }
        if write != "OK 2" {
            fail("a store a read loaded was not written as the contract says")
        }
        drop(sub_kept);
        cfg_close(env, name)
    };
    cfg_balance(
        name,
        frames0,
        "a user store is read for its owner or an administrator alone, loaded on that read, and a refused read takes no slot",
    )
}

/// TST-M4-CONFIG-SUBS (REQ-M4-004, REQ-M4-005, config.md v1.5, WP-158; RSK-028): a subscription
/// belongs to the client that asked for it. Client X sends eight SUBSCRIBE device, each with a
/// new channel end: it holds one subscription, the last, and the service has closed the
/// seven earlier ends; it subscribes to policy too. Client Y's SUBSCRIBE device is then
/// accepted, and a change of the store is heard by Y and by X's last end alone. X closes its
/// channel: its two subscriptions go with it (the service's live handle count drops by
/// three) and Y still hears the next change.
/// Client Z subscribes, then, with the service held and parked, queues a request and closes:
/// its reply cannot be written, and its subscription goes with it too. SUBSCRIBE session is
/// refused (it shows no token, and session values are kept apart per user) and a change of a
/// session key is heard by nobody.
fn config_subs() -> ! {
    let env = cfg_env("config_subs");
    let frames0 = {
        let y = &env.cfg;
        let a = token_entry(&env.admin);
        let end = |s: Arc<Endpoint>| Entry {
            object: Object::Channel(s),
            rights: Rights::CHANNEL_DEFAULT,
        };
        let closed = |e: &Endpoint| matches!(e.read(4096, 4, None), Err(ChannelError::PeerClosed));
        let x = svc_connect(&env.h, "config");
        // An answered request on X: configd has read both clients' CONNECT, so their ends are
        // in its table before the count is taken (the boot channel is served first).
        let _ = cfg_request(&x, b"GET device sync.key", None);
        let h0 = cfg_handles();
        let mut x_ok = 0;
        let mut x_ends = Vec::new();
        for _ in 0..8 {
            let (mine, theirs) = channel::create();
            if cfg_request(&x, b"SUBSCRIBE device", Some(end(theirs))) == "OK" {
                x_ok += 1;
            }
            x_ends.push(mine);
        }
        // A second store: X's subscriptions go with it wherever they are.
        let (x_pol_k, x_pol_s) = channel::create();
        let x_pol = cfg_request(&x, b"SUBSCRIBE policy", Some(end(x_pol_s)));
        let x_grew = cfg_handles() - h0;
        let (y_k, y_s) = channel::create();
        let y_sub = cfg_request(y, b"SUBSCRIBE device", Some(end(y_s)));
        let set = cfg_request(y, b"SET device subs.key 0 901 v", Some(a.clone()));
        let y_heard = recv_text(&y_k, 500);
        let x_last = recv_text(&x_ends[7], 500);
        let x_first = (0..7).filter(|&i| recv_text(&x_ends[i], 20) != "-").count();
        let x_closed = (0..7).filter(|&i| closed(&x_ends[i])).count();
        // X goes: its client end and its two subscriptions.
        let h2 = cfg_handles();
        drop(x);
        let x_gone = sched::poll_until(sched::ticks() + 3_000, || cfg_handles() == h2 - 3);
        let x_end_closed = closed(&x_ends[7]);
        let x_pol_closed = closed(&x_pol_k);
        let set2 = cfg_request(y, b"SET device subs.key 1 902 w", Some(a.clone()));
        let y_heard2 = recv_text(&y_k, 500);
        // Z's reply cannot be written: held and parked, the service reads the request only
        // after Z's end is closed.
        let z = svc_connect(&env.h, "config");
        let (z_k, z_s) = channel::create();
        let z_sub = cfg_request(&z, b"SUBSCRIBE device", Some(end(z_s)));
        let h3 = cfg_handles();
        let frozen = sched::freeze_named(b"CONFIGD.ELF");
        let parked = sched::poll_until(sched::ticks() + 5_000, || {
            sched::parked_named(b"CONFIGD.ELF")
        });
        let queued = z
            .write(Message {
                bytes: b"GET device subs.key".to_vec(),
                handles: Vec::new(),
            })
            .is_ok();
        drop(z);
        let thawed = sched::thaw_named(b"CONFIGD.ELF");
        let z_gone = sched::poll_until(sched::ticks() + 3_000, || cfg_handles() == h3 - 2);
        let z_end_closed = closed(&z_k);
        // A session subscriber shows no token: refused, and nobody hears a session key.
        let (s_k, s_s) = channel::create();
        let sess_sub = cfg_request(y, b"SUBSCRIBE session", Some(end(s_s)));
        let sess_set = cfg_request(y, b"SET session subs.s 0 903 secret", Some(a));
        let sess_heard = recv_text(&s_k, 50);
        let end_grew = cfg_handles() - h0;
        kprintln!(
            "OSX|{}|ktest|config_subs|x_ok={}|x_pol={}|x_grew={}|y_sub={}|set={}|y_heard={}|x_last={}|x_first={}|x_closed={}|x_gone={}|x_end_closed={}|x_pol_closed={}|set2={}|y_heard2={}|base={}",
            BUILD_ID,
            x_ok,
            x_pol,
            x_grew,
            y_sub,
            set,
            y_heard,
            x_last,
            x_first,
            x_closed,
            u8::from(x_gone),
            u8::from(x_end_closed),
            u8::from(x_pol_closed),
            set2,
            y_heard2,
            h0
        );
        kprintln!(
            "OSX|{}|ktest|config_subs|more|z_sub={}|frozen={}|parked={}|queued={}|thawed={}|z_gone={}|z_end_closed={}|sess_sub={}|sess_set={}|sess_heard={}|end_grew={}|",
            BUILD_ID,
            z_sub,
            u8::from(frozen),
            u8::from(parked),
            u8::from(queued),
            u8::from(thawed),
            u8::from(z_gone),
            u8::from(z_end_closed),
            sess_sub,
            sess_set,
            sess_heard,
            end_grew
        );
        if h0 < 0 {
            fail("configd's live handle count could not be read")
        }
        if x_ok != 8 || x_pol != "OK" || x_grew != 2 || x_first != 0 || x_closed != 7 {
            fail("one client held more than one subscription of a store")
        }
        if y_sub != "OK"
            || set != "OK 1"
            || y_heard != "CHANGED device subs.key 1"
            || x_last != "CHANGED device subs.key 1"
        {
            fail("a second client's subscription was refused or a subscriber missed the change")
        }
        if !x_gone || !x_end_closed || !x_pol_closed {
            fail("a closed client's subscription stayed")
        }
        if set2 != "OK 2" || y_heard2 != "CHANGED device subs.key 2" {
            fail("the remaining subscriber missed a change")
        }
        if z_sub != "OK" || !frozen || !parked || !queued || !thawed {
            fail("the reply that cannot be written was not set up")
        }
        if !z_gone || !z_end_closed {
            fail("the subscription of a client whose reply could not be written stayed")
        }
        if sess_sub != "ERR ACCESS" || sess_set != "OK 1" || sess_heard != "-" {
            fail("a subscriber without a token heard a session key")
        }
        if end_grew != 0 {
            fail("configd kept a handle of a client that had gone")
        }
        drop((x_ends, x_pol_k, y_k, z_k, s_k));
        cfg_close(env, "config_subs")
    };
    cfg_balance(
        "config_subs",
        frames0,
        "a subscription belongs to its client and goes with it, and a session key is heard by nobody without a token",
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
        // The user's store is read with the user's token (config.md v1.6, WP-112).
        let export = cfg_request(ep, b"EXPORT user/1001", Some(u.clone()));
        let import = cfg_request(
            ep,
            b"IMPORT user/1001 505
    ui.font mono
    ui.size 14",
            Some(u.clone()),
        );
        let imported = cfg_request(ep, b"GET user/1001 ui.size", Some(u.clone()));
        let import_bad = cfg_request(
            ep,
            b"IMPORT user/1001 506
    ui.ok yes
    BAD KEY x",
            Some(u.clone()),
        );
        let not_applied = cfg_request(ep, b"GET user/1001 ui.ok", Some(u));
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

/// The net service's live handle count, or -1 when it does not run (test kernel only).
fn net_handles() -> i64 {
    sched::handles_named(b"NETD.ELF").map_or(-1, |n| n as i64)
}

/// TST-M4-NET-CLIENT-DROP (REQ-M4-007, REQ-M4-008, net.md ب and ج, WP-108; RSK-028): a client's
/// sockets and connections go with it on every path that frees its slot. Client A opens a UDP
/// socket, sends a datagram whose echo it never reads and opens a TCP connection; then, while
/// the service is held, it queues one more request and closes its end. Released, the service
/// answers into the closed channel and frees A's slot (its live handle count drops by one).
/// Client B then takes that slot: A's socket is not B's, A's connection is closed, and A's
/// port is free again. Client C opens a port and closes while idle (the service reads the
/// closed peer): that port is free again too, and the connection B opened meanwhile is
/// still B's.
fn net_client_drop() -> ! {
    let (env, dhcp) = net_env("net_client_drop");
    let frames0 = {
        let a = svc_connect(&env.h, "net");
        let open = cfg_request(&a, b"UDP_OPEN 40001", None);
        let sent = cfg_request(&a, b"UDP_SEND 0 10.0.2.2 17007 from-a", None);
        let conn = cfg_request(&a, b"TCP_CONNECT 10.0.2.2 17008 5000", None);
        let n0 = net_handles();
        // Held and parked (a frozen process's blocked threads stay blocked until the thaw),
        // the service cannot read the request before A's end is closed: its reply is the one
        // that cannot be written.
        let frozen = sched::freeze_named(b"NETD.ELF");
        let parked = sched::poll_until(sched::ticks() + 5_000, || sched::parked_named(b"NETD.ELF"));
        let queued = a
            .write(Message {
                bytes: b"STATUS".to_vec(),
                handles: Vec::new(),
            })
            .is_ok();
        drop(a);
        let thawed = sched::thaw_named(b"NETD.ELF");
        let dropped = sched::poll_until(sched::ticks() + 5_000, || net_handles() == n0 - 1);
        // B connects once A's slot is free, so it takes that slot.
        let b = svc_connect(&env.h, "net");
        let inherit_recv = cfg_request(&b, b"UDP_RECV 0 2000", None);
        let tcp_a = cfg_request(&b, b"TCP_STATUS 1", None)
            .split(' ')
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let reopen = cfg_request(&b, b"UDP_OPEN 40001", None);
        // B's own connection must outlive another client's close.
        let conn_b = cfg_request(&b, b"TCP_CONNECT 10.0.2.2 17008 5000", None);
        // C closes while idle: the service reads the closed peer.
        let c = svc_connect(&env.h, "net");
        let open_c = cfg_request(&c, b"UDP_OPEN 40002", None);
        let n1 = net_handles();
        drop(c);
        let idle_dropped = sched::poll_until(sched::ticks() + 5_000, || net_handles() == n1 - 1);
        let idle_reopen = cfg_request(&b, b"UDP_OPEN 40002", None);
        let tcp_b = cfg_request(&b, b"TCP_STATUS 2", None)
            .split(' ')
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        kprintln!(
            "OSX|{}|ktest|net_client_drop|dhcp_ok={}|open={}|sent={}|conn={}|frozen={}|parked={}|queued={}|thawed={}|dropped={}|inherit_recv={}|tcp_a={}|reopen={}|conn_b={}|open_c={}|idle_dropped={}|idle_reopen={}|tcp_b={}|net_base={}",
            BUILD_ID,
            u8::from(dhcp == LAB_DHCP),
            open,
            sent,
            conn,
            u8::from(frozen),
            u8::from(parked),
            u8::from(queued),
            u8::from(thawed),
            u8::from(dropped),
            inherit_recv,
            tcp_a,
            reopen,
            conn_b,
            open_c,
            u8::from(idle_dropped),
            idle_reopen,
            tcp_b,
            n0
        );
        if dhcp != LAB_DHCP || open != "OK 0" || sent != "OK 6" || conn != "OK 1" || n0 < 0 {
            fail("the first client's socket, datagram or connection was not set up")
        }
        if !frozen || !parked || !queued || !thawed || !dropped {
            fail("the reply that cannot be written did not free the client's slot")
        }
        if inherit_recv != "ERR BAD_REQUEST" || tcp_a != "ERR CLOSED" {
            fail("a later client used the socket or the connection of a client that had closed")
        }
        if reopen != "OK 0" {
            fail("a closed client's socket was left behind")
        }
        if conn_b != "OK 2" || open_c != "OK 1" || !idle_dropped || idle_reopen != "OK 1" {
            fail("an idle client's close left its socket behind")
        }
        if tcp_b != "OK state=ESTABLISHED" {
            fail("a client's close reset another client's connection")
        }
        // The DHCP reply string lives outside the block: release it before the balance.
        drop((b, dhcp));
        net_close(env, "net_client_drop")
    };
    cfg_balance(
        "net_client_drop",
        frames0,
        "a closed client's sockets and connections are freed on every path and no later client uses them",
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

// ---- WP-32: the display -------------------------------------------------------------------

/// TST-M5-DISPLAY-BOOT: the frame firmware left (GOP) carries the kernel's diagnostic pattern
/// (read back through the kernel mapping: the four corners and the build-id bar), a process
/// (fbprobe) maps the frame through the display object and paints two squares, then the lab
/// takes a screendump and presses Enter; the host checks the picture against what was printed.
fn display_boot() -> ! {
    let Some(d) = crate::display::info() else {
        fail("no display (firmware left no linear frame buffer)")
    };
    let at = |x: u32, y: u32| {
        crate::arch::mmio::read32(
            d.virt + (u64::from(y) * u64::from(d.pitch_px) + u64::from(x)) * 4,
        )
    };
    let px = |rgb: u32| crate::display::pixel(d.pixel_format, rgb);
    let corners = [
        at(1, 1),
        at(d.width - 2, 1),
        at(1, d.height - 2),
        at(d.width - 2, d.height - 2),
    ];
    let expected: Vec<u32> = crate::display::CORNER_COLOURS
        .iter()
        .map(|c| px(*c))
        .collect();
    let corners_ok = corners.iter().zip(expected.iter()).all(|(a, b)| a == b);
    // The bar: one cell per hex digit of the build id, decoded back from the frame.
    let mut decoded = String::new();
    for i in 0..BUILD_ID.len() as u32 {
        let v = at(2 * crate::display::CORNER + i * crate::display::CELL + 2, 2);
        let digit = crate::display::DIGIT_COLOURS
            .iter()
            .position(|c| px(*c) == v)
            .map_or('?', |k| char::from_digit(k as u32, 16).unwrap_or('?'));
        decoded.push(digit);
    }
    let bar_ok = decoded == BUILD_ID;
    // REQ-M5-001: a frame the kernel cannot draw on is refused before anything is mapped or
    // drawn, and the boot line says there is no display; the frame in use stays the display.
    let fb = |pixel_format, width, pitch_px, base| crate::bootinfo::Framebuffer {
        base,
        width,
        height: d.height,
        pitch_px,
        pixel_format,
        present: 1,
    };
    let refusals = [
        (fb(2, d.width, d.pitch_px, d.base), "K_E_DISPLAY_FORMAT"), // GOP PixelBitMask
        (fb(3, d.width, d.pitch_px, d.base), "K_E_DISPLAY_FORMAT"), // GOP PixelBltOnly
        (fb(1, 0, d.pitch_px, d.base), "K_E_DISPLAY_FORMAT"),
        (fb(1, d.width, d.width - 1, d.base), "K_E_DISPLAY_FORMAT"),
        (fb(1, d.width, d.pitch_px, 0), "K_E_DISPLAY_RANGE"),
        (fb(1, 65_535, 65_535, d.base), "K_E_DISPLAY_RANGE"),
    ];
    let before = at(d.width / 2, d.height / 2);
    let refused = refusals
        .iter()
        .filter(|(f, code)| {
            let r = crate::display::init(f, BUILD_ID);
            matches!(r, Err(c) if c == *code)
                && crate::display::boot_line(&r).starts_with("present=0|")
        })
        .count();
    let kept = crate::display::info().is_some_and(|i| i.base == d.base && i.virt == d.virt)
        && at(d.width / 2, d.height / 2) == before;
    kprintln!(
        "OSX|{}|ktest|display_boot|refused={}/{}|kept={}",
        BUILD_ID,
        refused,
        refusals.len(),
        u8::from(kept)
    );
    if refused != refusals.len() || !kept {
        fail("a frame the kernel cannot draw on was not refused, or it disturbed the display")
    }
    // The probe's squares must outlive its exit: the test reads them back and the lab's
    // screendump comes later (display.md v1.5 clears the frame when its last VMO goes).
    crate::display::pin_frame();
    let o = run_with_object(
        "display_boot",
        crate::apps::FBPROBE,
        Entry {
            object: Object::Display(
                crate::display::display_object().unwrap_or_else(|| fail("no display object")),
            ),
            rights: Rights::DISPLAY_DEFAULT,
        },
    );
    let magenta = at(96 + 32, 96 + 32) == px(0xFF00FF);
    let cyan = at(192 + 32, 96 + 32) == px(0x00FFFF);
    kprintln!(
        "OSX|{}|ktest|display_boot|w={}|h={}|stride={}|format={}|corners_ok={}|bar={}|bar_ok={}|probe_exit={:#x}|magenta={}|cyan={}|frames_delta={}|ready=1",
        BUILD_ID,
        d.width,
        d.height,
        d.pitch_px,
        d.pixel_format,
        u8::from(corners_ok),
        decoded,
        u8::from(bar_ok),
        o.exit_code,
        u8::from(magenta),
        u8::from(cyan),
        o.frames_delta
    );
    if !corners_ok || !bar_ok {
        fail("the diagnostic pattern is not on the frame")
    }
    // The probe ends on a write one pixel past the frame's mapping (REQ-M5-001): the page
    // fault ends it (0x10000 + vector 14) and nothing else is touched.
    if o.exit_code != 0x1000E || !magenta || !cyan || o.frames_delta != 0 {
        fail("the process could not map and paint the frame through the display object")
    }
    // The lab takes its screendump now and presses Enter when done.
    let kbd = crate::net::keyboard_object();
    let mut byte = [0u8; 1];
    let pressed = sched::poll_until(sched::ticks() + 60_000, || kbd.read(&mut byte) > 0);
    kprintln!(
        "OSX|{}|ktest|display_boot|lab_key={}|byte={:#x}",
        BUILD_ID,
        u8::from(pressed),
        byte[0]
    );
    if !pressed {
        fail("the lab never pressed a key after its screendump")
    }
    drop((decoded, expected));
    pass("the frame carries the kernel's pattern and a process's paint through the display object")
}

// ---- WP-33: trusted input --------------------------------------------------------------------

/// Reads up to `count` messages from `ep` until `deadline`; their texts in order.
fn read_events(ep: &Endpoint, count: usize, deadline: u64) -> Vec<String> {
    let mut out = Vec::with_capacity(count.max(1));
    sched::poll_until(deadline, || {
        while out.len() < count {
            match ep.read(256, 0, None) {
                Ok(m) => out.push(String::from_utf8_lossy(&m.bytes).into_owned()),
                Err(_) => break,
            }
        }
        out.len() >= count
    });
    out
}

/// The input tests' setting: manager with auth + input (SVC-IN.TXT), an admin token from a
/// real login, and `n` client channels to the input service.
fn input_env(
    name: &'static str,
    n: usize,
) -> (
    SvcHarness,
    Arc<crate::object::token::Token>,
    Vec<Arc<Endpoint>>,
) {
    let h = SvcHarness::start(name, b"/SYSTEM/SVC-IN.TXT");
    svc_wait_ready(&h, &["auth", "input"], sched::ticks() + 60_000);
    let auth = svc_connect(&h, "auth");
    let (ra, admin) = auth_request(&auth, b"LOGIN admin lab-admin-1", None);
    let Some(admin) = admin else {
        kprintln!("OSX|{}|ktest|{}|admin={}", BUILD_ID, name, ra);
        fail("admin login failed")
    };
    drop(auth);
    let mut clients = Vec::with_capacity(n);
    for _ in 0..n {
        clients.push(svc_connect(&h, "input"));
    }
    (h, admin, clients)
}

/// TST-M5-INPUT-ROUTE (REQ-M5-002): key events reach the focus owner only, with the layout
/// applied; focus and layout need an ADMIN token; the secure attention sequence goes to the
/// `session` client alone and is never reported as keys. The lab presses the keys through the
/// QEMU monitor after each `ready=1` line.
fn input_route() -> ! {
    let (h, admin, clients) = input_env("input_route", 3);
    let auth = svc_connect(&h, "auth");
    let (ru, user) = auth_request(&auth, b"LOGIN user lab-user-1", None);
    let Some(user) = user else {
        kprintln!("OSX|{}|ktest|input_route|user={}", BUILD_ID, ru);
        fail("user login failed")
    };
    drop(auth);
    let (a, b, s) = (&clients[0], &clients[1], &clients[2]);
    let reg_a = cfg_request(a, b"REGISTER a", None);
    let reg_b = cfg_request(b, b"REGISTER b", None);
    let reg_s = cfg_request(s, b"REGISTER session", None);
    // Authority: no token, a user's token and an unknown client are refused; the admin's
    // token moves the focus.
    let f_none = cfg_request(a, b"FOCUS 1", None);
    let f_user = cfg_request(a, b"FOCUS 1", Some(token_entry(&user)));
    let f_unknown = cfg_request(a, b"FOCUS 99", Some(token_entry(&admin)));
    let l_user = cfg_request(b, b"LAYOUT ar", Some(token_entry(&user)));
    let f_a = cfg_request(s, b"FOCUS 1", Some(token_entry(&admin)));
    let status0 = cfg_request(a, b"STATUS", None);
    kprintln!(
        "OSX|{}|ktest|input_route|reg={}/{}/{}|focus_none={}|focus_user={}|focus_unknown={}|layout_user={}|focus_a={}|status={}|phase=1|ready=1",
        BUILD_ID, reg_a, reg_b, reg_s, f_none, f_user, f_unknown, l_user, f_a, status0
    );
    if reg_a != "OK 1"
        || reg_b != "OK 2"
        || reg_s != "OK 3"
        || f_none != "ERR ACCESS"
        || f_user != "ERR ACCESS"
        || f_unknown != "ERR UNKNOWN"
        || l_user != "ERR ACCESS"
        || f_a != "OK"
        || !status0.starts_with("OK focus=1 layout=us keys=0 packets=0 saks=0 dropped=0")
    {
        fail("registration or the authority checks did not answer as input.md says")
    }
    // Phase 1: the lab sends `a`, `shift-b` and `ctrl-alt-delete` (QEMU presses in order and
    // releases in reverse order): eight key events to A up to the Alt press, then the focus
    // moves to S with the SAK (input.md v2.2), so S gets the SAK and the two releases;
    // nothing to B.
    let ev_a = read_events(a, 8, sched::ticks() + 60_000);
    let ev_s = read_events(s, 3, sched::ticks() + 5_000);
    let ev_b = read_events(b, 1, sched::ticks() + 200);
    kprintln!(
        "OSX|{}|ktest|input_route|a={}|s={}|b={}",
        BUILD_ID,
        ev_a.join(";"),
        ev_s.join(";"),
        ev_b.join(";")
    );
    let expected_a = [
        "KEY 0x1e down 0 a",
        "KEY 0x1e up 0 a",
        "KEY 0x2a down 1 -",
        "KEY 0x30 down 1 B",
        "KEY 0x30 up 1 B",
        "KEY 0x2a up 0 -",
        "KEY 0x1d down 2 -",
        "KEY 0x38 down 6 -",
    ];
    let expected_s = ["SAK", "KEY 0x38 up 2 -", "KEY 0x1d up 0 -"];
    if ev_a != expected_a || ev_s != expected_s || !ev_b.is_empty() {
        fail("key events were decoded wrongly or reached the wrong client")
    }
    // Phase 2: the focus moves to B with the Arabic layout; the lab sends `a` again.
    let f_b = cfg_request(s, b"FOCUS 2", Some(token_entry(&admin)));
    let l_ar = cfg_request(s, b"LAYOUT ar", Some(token_entry(&admin)));
    kprintln!(
        "OSX|{}|ktest|input_route|focus_b={}|layout_ar={}|phase=2|ready=1",
        BUILD_ID,
        f_b,
        l_ar
    );
    if f_b != "OK" || l_ar != "OK" {
        fail("the admin could not move the focus or change the layout")
    }
    let ev_b2 = read_events(b, 2, sched::ticks() + 60_000);
    let ev_a2 = read_events(a, 1, sched::ticks() + 200);
    let status = cfg_request(a, b"STATUS", None);
    kprintln!(
        "OSX|{}|ktest|input_route|b2={}|a2={}|status={}",
        BUILD_ID,
        ev_b2.join(";"),
        ev_a2.join(";"),
        status
    );
    if ev_b2 != ["KEY 0x1e down 0 ش", "KEY 0x1e up 0 ش"]
        || !ev_a2.is_empty()
        || status
            != "OK focus=2 layout=ar keys=12 packets=0 saks=1 dropped=0 buttons=0 sak_pending=0"
    {
        fail("the Arabic layout or the moved focus did not take effect")
    }
    // Phase 3 (input.md v2.3, WP-38 mutants M108/M109): Shift+Alt with a third key between
    // is a shortcut, not the layout chord: the lab presses `shift-alt-x` (Shift, Alt, X down,
    // then up in reverse), then `a`. The layout stays Arabic, so `a` is still ش — neither the
    // press of the second modifier nor the release after a third key toggles it.
    kprintln!(
        "OSX|{}|ktest|input_route|chord=armed|phase=3|ready=1",
        BUILD_ID
    );
    let ev_b3 = read_events(b, 8, sched::ticks() + 60_000);
    let status3 = cfg_request(a, b"STATUS", None);
    kprintln!(
        "OSX|{}|ktest|input_route|b3={}|status3={}",
        BUILD_ID,
        ev_b3.join(";"),
        status3
    );
    if ev_b3.len() != 8
        || ev_b3[6..] != ["KEY 0x1e down 0 ش", "KEY 0x1e up 0 ش"]
        || !status3.starts_with("OK focus=2 layout=ar keys=20 ")
    {
        fail("a Shift+Alt shortcut with a third key toggled the layout")
    }
    // Every allocation of the test goes before the balance (CI run 39151988275 counted the
    // page of the user login's reply string, `ru`, as a leaked frame).
    drop((ev_b3, status3));
    drop((ev_a, ev_s, ev_b, ev_b2, ev_a2, status, status0, ru));
    drop((
        reg_a, reg_b, reg_s, f_none, f_user, f_unknown, l_user, f_a, f_b, l_ar,
    ));
    drop((clients, admin, user));
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|input_route|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    cfg_balance(
        "input_route",
        frames0,
        "key events reach the focus owner only, with the layout applied, and the secure attention sequence reaches the session alone",
    )
}

/// TST-M5-MOUSE (REQ-M5-002): the PS/2 mouse answers at boot; its packets reach the focus
/// owner as pointer events with the screen's orientation and the button state. The lab moves
/// the pointer and clicks through the QEMU monitor after the `ready=1` line.
fn mouse() -> ! {
    let (h, admin, clients) = input_env("mouse", 1);
    let a = &clients[0];
    let reg = cfg_request(a, b"REGISTER a", None);
    let focus = cfg_request(a, b"FOCUS 1", Some(token_entry(&admin)));
    let present = crate::net::MOUSE_PRESENT.load(core::sync::atomic::Ordering::Relaxed);
    kprintln!(
        "OSX|{}|ktest|mouse|present={}|reg={}|focus={}|ready=1",
        BUILD_ID,
        u8::from(present),
        reg,
        focus
    );
    if !present || reg != "OK 1" || focus != "OK" {
        fail("no mouse answered at boot, or the client could not take the focus")
    }
    // The lab: `mouse_move 10 5`, `mouse_button 1`, `mouse_button 0`.
    let ev = read_events(a, 3, sched::ticks() + 60_000);
    let status = cfg_request(a, b"STATUS", None);
    kprintln!(
        "OSX|{}|ktest|mouse|events={}|status={}",
        BUILD_ID,
        ev.join(";"),
        status
    );
    if ev != ["PTR 10 5 0", "PTR 0 0 1", "PTR 0 0 0"]
        || status
            != "OK focus=1 layout=us keys=0 packets=3 saks=0 dropped=0 buttons=0 sak_pending=0"
    {
        fail("pointer events did not carry the lab's motion and button state")
    }
    drop((ev, status, reg, focus, clients, admin));
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|mouse|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    cfg_balance(
        "mouse",
        frames0,
        "the mouse's packets reach the focus owner as pointer events in the screen's orientation",
    )
}

// ---- WP-34: the compositor ------------------------------------------------------------------

/// Window geometry of display.md §ب: the k-th window's client origin and decoration.
const WIN_ORIGIN: i64 = 20;
const WIN_CASCADE: i64 = 40;
const WIN_BORDER: i64 = 1;
const WIN_TITLE: i64 = 24;
const WIN_BTN: i64 = 20;

fn client_origin(k: i64) -> (i64, i64) {
    (
        WIN_ORIGIN + k * WIN_CASCADE + WIN_BORDER,
        WIN_ORIGIN + k * WIN_CASCADE + WIN_BORDER + WIN_TITLE,
    )
}

/// A request to the display service: events that arrive before the reply (the service sends
/// FOCUS before answering CREATE_WINDOW, say) go to `events`.
fn drequest(ep: &Endpoint, req: &[u8], handles: Vec<Entry>, events: &mut Vec<String>) -> String {
    drequest_within(ep, req, handles, events, 30_000)
}

/// `drequest` with its own deadline (`ticks` from now): `error:K_E_SVC_TIMEOUT` past it.
fn drequest_within(
    ep: &Endpoint,
    req: &[u8],
    handles: Vec<Entry>,
    events: &mut Vec<String>,
    ticks: u64,
) -> String {
    if ep
        .write(Message {
            bytes: req.to_vec(),
            handles,
        })
        .is_err()
    {
        return String::from("error:K_E_SVC_WRITE");
    }
    let deadline = sched::ticks() + ticks;
    let mut reply: Option<String> = None;
    sched::poll_until(deadline, || loop {
        match ep.read(4096, 4, None) {
            Ok(m) => {
                let text = String::from_utf8_lossy(&m.bytes).into_owned();
                if text.starts_with("OK") || text.starts_with("ERR") {
                    reply = Some(text);
                    return true;
                }
                events.push(text);
            }
            Err(ChannelError::PeerClosed) => {
                reply = Some(String::from("error:K_E_SVC_PEER_CLOSED"));
                return true;
            }
            Err(_) => return false,
        }
    });
    reply.unwrap_or_else(|| String::from("error:K_E_SVC_TIMEOUT"))
}

/// A surface for the kernel-side client: a VMO of `w×h` pixels in the frame's `format`
/// filled with `rgb`, and the entry that `CREATE_SURFACE` moves to the service.
fn kernel_surface(w: u32, h: u32, format: u32, rgb: u32) -> (Arc<Vmo>, Entry) {
    let bytes = (u64::from(w) * u64::from(h) * 4).next_multiple_of(4096);
    let vmo = Vmo::new(bytes).unwrap_or_else(|| fail("surface VMO"));
    let px = crate::display::pixel(format, rgb).to_le_bytes();
    let mut page = [0u8; 4096];
    for (i, b) in page.iter_mut().enumerate() {
        *b = px[i % 4];
    }
    for f in vmo.frames() {
        addrspace::write_frame(f.0, &page);
    }
    let entry = Entry {
        object: Object::Vmo(vmo.clone()),
        rights: Rights(Rights::READ.0 | Rights::MAP.0 | Rights::TRANSFER.0),
    };
    (vmo, entry)
}

/// One `W` line of `LIST`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WinLine {
    id: u32,
    sid: Option<u32>,
    x: i64,
    y: i64,
    w: i64,
    h: i64,
    minimized: bool,
    z: u32,
    focused: bool,
    hash: String,
}

fn parse_windows(reply: &str) -> Vec<WinLine> {
    reply
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            if f.len() != 11 || f[0] != "W" {
                return None;
            }
            Some(WinLine {
                id: f[1].parse().ok()?,
                sid: f[2].parse().ok(),
                x: f[3].parse().ok()?,
                y: f[4].parse().ok()?,
                w: f[5].parse().ok()?,
                h: f[6].parse().ok()?,
                minimized: f[7] == "minimized",
                z: f[8].parse().ok()?,
                focused: f[9] == "1",
                hash: f[10].into(),
            })
        })
        .collect()
}

fn status_field<'a>(status: &'a str, key: &str) -> &'a str {
    status
        .split(' ')
        .find_map(|f| f.strip_prefix(key))
        .unwrap_or("?")
}

/// The display tests' setting: manager with the manifest's services, the admin's token, the
/// input focus on the display service, and `n` clients of it.
fn display_env(
    name: &'static str,
    manifest: &'static [u8],
    services: &[&str],
    n: usize,
) -> (
    SvcHarness,
    Arc<crate::object::token::Token>,
    Vec<Arc<Endpoint>>,
    u32,
) {
    let h = SvcHarness::start(name, manifest);
    svc_wait_ready(&h, services, sched::ticks() + 60_000);
    let auth = svc_connect(&h, "auth");
    let (ra, admin) = auth_request(&auth, b"LOGIN admin lab-admin-1", None);
    let Some(admin) = admin else {
        kprintln!("OSX|{}|ktest|{}|admin={}", BUILD_ID, name, ra);
        fail("admin login failed")
    };
    drop(auth);
    // The session's role in M5 before WP-37: the compositor owns the keyboard focus.
    let input = svc_connect(&h, "input");
    let focus = cfg_request(&input, b"FOCUS display", Some(token_entry(&admin)));
    drop(input);
    if focus != "OK" {
        kprintln!("OSX|{}|ktest|{}|input_focus={}", BUILD_ID, name, focus);
        fail("the input service did not give the display the focus")
    }
    let mut clients = Vec::with_capacity(n);
    for _ in 0..n {
        clients.push(svc_connect(&h, "display"));
    }
    let mut ev = Vec::new();
    let status = drequest(&clients[0], b"STATUS", Vec::new(), &mut ev);
    let format: u32 = status_field(&status, "format=").parse().unwrap_or(99);
    if format > 1 {
        kprintln!("OSX|{}|ktest|{}|status={}", BUILD_ID, name, status);
        fail("the display service did not report its pixel format")
    }
    (h, admin, clients, format)
}

/// Ends a display test: everything the test holds is dropped by the caller first.
fn display_finish(name: &'static str, h: SvcHarness, pass_msg: &'static str) -> ! {
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
    cfg_balance(name, frames0, pass_msg)
}

/// TST-M5-SCREEN (REQ-M5-001, REQ-M5-003): a client's surface appears on the frame where the
/// compositor says, with the hash the host recomputes from the screendump; the demo app's
/// window is there too; a key from the lab travels input → display → the focused client.
fn screen() -> ! {
    let (h, admin, clients, format) = display_env(
        "screen",
        b"/SYSTEM/SVC-DA.TXT",
        &["auth", "input", "display", "app"],
        1,
    );
    let d = &clients[0];
    let mut ev = Vec::new();
    let status0 = drequest(d, b"STATUS", Vec::new(), &mut ev);
    let (vmo, entry) = kernel_surface(320, 200, format, 0x3C8CFF);
    let r_surface = drequest(d, b"CREATE_SURFACE 320 200", alloc::vec![entry], &mut ev);
    let sid = r_surface.strip_prefix("OK ").unwrap_or("0");
    let r_window = drequest(
        d,
        alloc::format!("CREATE_WINDOW {} test window", sid).as_bytes(),
        Vec::new(),
        &mut ev,
    );
    let wid = r_window.strip_prefix("OK ").unwrap_or("0");
    let r_commit = drequest(
        d,
        alloc::format!("COMMIT {} 0 0 320 200", sid).as_bytes(),
        Vec::new(),
        &mut ev,
    );
    // Past the blit period, the composed picture is on the frame.
    sched::poll_until(sched::ticks() + 40, || false);
    let list = parse_windows(&drequest(d, b"LIST", Vec::new(), &mut ev));
    let status = drequest(d, b"STATUS", Vec::new(), &mut ev);
    let win = list.first().cloned().unwrap_or(WinLine {
        id: 0,
        sid: None,
        x: -1,
        y: -1,
        w: 0,
        h: 0,
        minimized: true,
        z: 9,
        focused: false,
        hash: String::new(),
    });
    // The demo app's window came first (k = 0), ours second (k = 1).
    let (ex, ey) = client_origin(1);
    kprintln!(
        "OSX|{}|ktest|screen|status0={}|surface={}|window={}|commit={}|events={}|rect={},{},{},{}|hash={}|status={}|ready=1",
        BUILD_ID,
        status0,
        r_surface,
        r_window,
        r_commit,
        ev.join(";"),
        win.x,
        win.y,
        win.w,
        win.h,
        win.hash,
        status
    );
    if status_field(&status0, "windows=") != "1"
        || !r_surface.starts_with("OK ")
        || !r_window.starts_with("OK ")
        || r_commit != "OK"
        || (win.x, win.y, win.w, win.h) != (ex, ey, 320, 200)
        || !win.focused
        || win.z != 0
        || status_field(&status, "windows=") != "2"
        || ev != [alloc::format!("FOCUS {}", wid)]
    {
        fail("the window is not where display.md says, or the demo app's is missing")
    }
    // The lab takes its screendump and presses Enter: the key reaches us through input and
    // display, as the focused window's owner.
    let keys = read_events(d, 2, sched::ticks() + 60_000);
    kprintln!("OSX|{}|ktest|screen|keys={}", BUILD_ID, keys.join(";"));
    if keys != ["KEY 0x1c down 0 enter", "KEY 0x1c up 0 enter"] {
        fail("the lab's key did not reach the focused client through input and display")
    }
    let r_close = drequest(
        d,
        alloc::format!("CLOSE {}", wid).as_bytes(),
        Vec::new(),
        &mut ev,
    );
    let r_destroy = drequest(
        d,
        alloc::format!("DESTROY_SURFACE {}", sid).as_bytes(),
        Vec::new(),
        &mut ev,
    );
    let status2 = drequest(d, b"STATUS", Vec::new(), &mut ev);
    kprintln!(
        "OSX|{}|ktest|screen|close={}|destroy={}|status={}",
        BUILD_ID,
        r_close,
        r_destroy,
        status2
    );
    if r_close != "OK" || r_destroy != "OK" || status_field(&status2, "windows=") != "1" {
        fail("closing the window did not leave the demo app's alone")
    }
    drop((
        status0, r_surface, r_window, r_commit, list, status, keys, win,
    ));
    drop((r_close, r_destroy, status2, ev, vmo, clients, admin));
    display_finish(
        "screen",
        h,
        "a client's surface is on the frame where the compositor says, hashed as the host sees it, and the lab's key reached the focused client",
    )
}

/// TST-M5-ALT-TAB-CYCLE (REQ-M5-008; M5 pre-gate review, M7): Alt+Tab with Alt held walks
/// every window (display.md v1.6; S77). One kernel-side client (SVC-DP.TXT) creates three
/// windows in order (the newest focused) and minimises the oldest. The test types its keys
/// into the keyboard ring itself (Alt held across Tabs, which the lab's `sendkey` cannot do),
/// waiting for each focus move. (1) Three Tabs walk the windows as stacked at the first Tab,
/// the most recently used first — 5, 4 (restored while reached), 6 — and at Alt's release the
/// walk is undone but for the window it ended on: the oldest is minimised again, the newest on
/// top. Before v1.6 each Tab worked from the stacking its predecessor had just changed (5, 6,
/// 5) and the minimised window was never reached. (2) Two Tabs end the walk on the oldest
/// window: restored, on top. (3) The lab's single Alt+Tab (Alt released between presses) goes
/// back to the window used before that walk, the newest. (4) A window closed and one opened
/// (taking the focus) during a walk: the new window stays on top and the walk's last window
/// goes just under it. (5) A window opened in a closed window's slot during a walk is one
/// created during it, not the closed one. (6) A window its client restored during a walk stays
/// restored. (7) The input service restarted with Alt held ends the walk as a release does:
/// the window the walk restored and passed over is minimised again.
fn alt_tab_cycle() -> ! {
    const ALT: u8 = 0x38;
    const TAB: u8 = 0x0F;
    const RELEASE: u8 = 0x80;
    let name = "alt_tab_cycle";
    let (h, admin, clients, format) = display_env(
        name,
        b"/SYSTEM/SVC-DP.TXT",
        &["auth", "input", "display"],
        1,
    );
    let c = &clients[0];
    let mut ev = Vec::new();
    let mut vmos = Vec::new();
    let mut sids = Vec::new();
    for colour in [0xD04040, 0x40B060, 0x4060D0] {
        let (vmo, entry) = kernel_surface(120, 80, format, colour);
        vmos.push(vmo);
        let r = drequest(c, b"CREATE_SURFACE 120 80", alloc::vec![entry], &mut ev);
        sids.push(String::from(r.strip_prefix("OK ").unwrap_or("0")));
    }
    let mut wins = Vec::new();
    for (i, sid) in sids.iter().enumerate() {
        let r = drequest(
            c,
            alloc::format!("CREATE_WINDOW {} w{}", sid, i + 1).as_bytes(),
            Vec::new(),
            &mut ev,
        );
        wins.push(String::from(r.strip_prefix("OK ").unwrap_or("0")));
    }
    let minimize = drequest(
        c,
        alloc::format!("MINIMIZE {}", wins[0]).as_bytes(),
        Vec::new(),
        &mut ev,
    );
    let focus_of = |ev: &mut Vec<String>| -> String {
        String::from(status_field(
            &drequest(c, b"STATUS", Vec::new(), ev),
            "focus=",
        ))
    };
    // Waits for the focus to leave `from` (at most `wait` ticks); the focus then. The test's
    // own keys are handled within moments; the lab's key gets the suite's 60 s.
    let moved = |from: &str, wait: u64, ev: &mut Vec<String>| -> String {
        let until = sched::ticks() + wait;
        let mut f = focus_of(ev);
        while f == from && sched::ticks() < until {
            let t = sched::ticks() + 10;
            sched::poll_until(t, || false);
            f = focus_of(ev);
        }
        f
    };
    // The window `id` in LIST: (minimised, z), polled until `done` holds (at most 2000 ticks).
    let window =
        |id: &str, ev: &mut Vec<String>, done: &dyn Fn(bool, u32) -> bool| -> (bool, u32) {
            let until = sched::ticks() + 2_000;
            loop {
                let list = parse_windows(&drequest(c, b"LIST", Vec::new(), ev));
                let w = list
                    .iter()
                    .find(|w| alloc::format!("{}", w.id) == id)
                    .map_or((false, u32::MAX), |w| (w.minimized, w.z));
                if done(w.0, w.1) || sched::ticks() >= until {
                    return w;
                }
                let t = sched::ticks() + 10;
                sched::poll_until(t, || false);
            }
        };
    // The stacking in LIST, top first, and the minimised windows, polled until it is `want`
    // (at most `wait` ticks).
    let stack = |want: &str, wait: u64, ev: &mut Vec<String>| -> String {
        let until = sched::ticks() + wait;
        loop {
            let mut list = parse_windows(&drequest(c, b"LIST", Vec::new(), ev));
            list.sort_by_key(|w| w.z);
            let ids: Vec<String> = list.iter().map(|w| alloc::format!("{}", w.id)).collect();
            let min: Vec<String> = list
                .iter()
                .filter(|w| w.minimized)
                .map(|w| alloc::format!("{}", w.id))
                .collect();
            let got = alloc::format!("{}/{}", ids.join(","), min.join(","));
            if got == want || sched::ticks() >= until {
                return got;
            }
            let t = sched::ticks() + 10;
            sched::poll_until(t, || false);
        }
    };
    // The compositor's count of key events, polled until it reaches `n`: a release has been
    // handled before the state after it is read.
    let keys_reach = |n: i64, wait: u64| -> i64 {
        let until = sched::ticks() + wait;
        loop {
            let k = display_keys(c);
            if k >= n || sched::ticks() >= until {
                return k;
            }
            let t = sched::ticks() + 10;
            sched::poll_until(t, || false);
        }
    };
    let keys0 = display_keys(c);
    let focus0 = focus_of(&mut ev);
    // 1. Alt held across three Tabs: the whole loop, the minimised window restored while it is
    //    reached; at Alt's release the walk is undone but for its last window (the start), so
    //    the passed-over window is minimised again and the newest is back on top.
    crate::net::inject_keyboard(&[ALT]);
    let mut visits = Vec::new();
    let mut last = focus0.clone();
    let mut restored = false;
    for k in 0..3 {
        crate::net::inject_keyboard(&[TAB, TAB | RELEASE]);
        last = moved(&last, 2_000, &mut ev);
        visits.push(last.clone());
        if k == 1 {
            restored = !window(&wins[0], &mut ev, &|_, _| true).0;
        }
    }
    crate::net::inject_keyboard(&[ALT | RELEASE]);
    let keys1 = keys_reach(keys0 + 8, 2_000);
    let (oldest_min, _) = window(&wins[0], &mut ev, &|m, _| m);
    let (_, newest_z) = window(&wins[2], &mut ev, &|_, z| z == 0);
    let rewound = oldest_min && newest_z == 0;
    // 2. Alt held across two Tabs: the walk ends on the oldest window, which stays restored and
    //    goes on top.
    crate::net::inject_keyboard(&[ALT]);
    let mut partial = Vec::new();
    for _ in 0..2 {
        crate::net::inject_keyboard(&[TAB, TAB | RELEASE]);
        last = moved(&last, 2_000, &mut ev);
        partial.push(last.clone());
    }
    crate::net::inject_keyboard(&[ALT | RELEASE]);
    let keys2 = keys_reach(keys0 + 14, 2_000);
    let (end_min, end_z) = window(&wins[0], &mut ev, &|m, z| !m && z == 0);
    let ended_on = !end_min && end_z == 0;
    let want: Vec<String> = alloc::vec![wins[1].clone(), wins[0].clone(), wins[2].clone()];
    let want_partial: Vec<String> = alloc::vec![wins[1].clone(), wins[0].clone()];
    kprintln!(
        "OSX|{}|ktest|{}|windows={}|minimize={}|focus0={}|held_visits={}|restored={}|rewound={}|partial={}|ended_on_top={}|quick=1|ready=1",
        BUILD_ID,
        name,
        wins.join(","),
        minimize,
        focus0,
        visits.join(","),
        u8::from(restored),
        u8::from(rewound),
        partial.join(","),
        u8::from(ended_on)
    );
    if keys1 < keys0 + 8 || keys2 < keys0 + 14 {
        fail("the compositor did not handle the test's keys in time")
    }
    if minimize != "OK" || focus0 != wins[2] || visits != want || !restored {
        fail("with Alt held, three Tabs did not visit every window and come back")
    }
    if !rewound || partial != want_partial || !ended_on {
        fail("a walk moved or restored the windows it only passed over")
    }
    // 3. The lab's single Alt+Tab press: back to the window used before the second walk.
    let quick = moved(&last, 60_000, &mut ev);
    // The lab's key is Alt, Tab, Tab up, Alt up: the walk is over once all four are handled.
    let lab_keys = keys_reach(keys2 + 4, 60_000) - keys2;
    kprintln!(
        "OSX|{}|ktest|{}|quick_to={}|lab_keys={}",
        BUILD_ID,
        name,
        quick,
        lab_keys
    );
    if quick != wins[2] || lab_keys != 4 {
        fail("a single Alt+Tab did not go back to the window used just before")
    }
    // Phases 4 to 7 each start from a stacking set by requests (RAISE, bottom first), so each
    // checks its own rule whatever an earlier phase left; every marker is printed before any
    // check fails.
    let arrange = |top_first: &[&String], ev: &mut Vec<String>| {
        for id in top_first.iter().rev() {
            let _ = drequest(c, alloc::format!("RAISE {}", id).as_bytes(), Vec::new(), ev);
        }
    };
    let request = |what: String, ev: &mut Vec<String>| -> String {
        drequest(c, what.as_bytes(), Vec::new(), ev)
    };
    let mut keys = keys2 + 4;
    let mut keys_ok = true;
    // 4. During a walk (4, then 5) the client closes 4 and opens window 7 on 4's surface, which
    //    takes the focus: at Alt's release 7 stays on top, focused, and the walk's last window,
    //    5, is just under it (the end is where the walk is, not the focus).
    arrange(&[&wins[2], &wins[0], &wins[1]], &mut ev);
    last = focus_of(&mut ev);
    crate::net::inject_keyboard(&[ALT]);
    let mut churn_visits = Vec::new();
    for _ in 0..2 {
        crate::net::inject_keyboard(&[TAB, TAB | RELEASE]);
        last = moved(&last, 2_000, &mut ev);
        churn_visits.push(last.clone());
    }
    let close = request(alloc::format!("CLOSE {}", wins[0]), &mut ev);
    let r_new = request(alloc::format!("CREATE_WINDOW {} w4", sids[0]), &mut ev);
    let new_win = String::from(r_new.strip_prefix("OK ").unwrap_or("0"));
    crate::net::inject_keyboard(&[ALT | RELEASE]);
    keys += 6;
    keys_ok &= keys_reach(keys, 2_000) >= keys;
    let want_churn = alloc::format!("{},{},{}/", new_win, wins[1], wins[2]);
    let churn = stack(&want_churn, 2_000, &mut ev);
    let churn_focus = focus_of(&mut ev);
    kprintln!(
        "OSX|{}|ktest|{}|visits={}|close={}|new={}|churn={}|churn_focus={}",
        BUILD_ID,
        name,
        churn_visits.join(","),
        close,
        new_win,
        churn,
        churn_focus
    );
    // 5. From 7, 5, 6: the walk reaches 5, the client closes 6 (the bottom) and opens 8 in its
    //    slot, which takes the focus, and the walk goes on to 7: at the release 8 is a window
    //    created during the walk — just under 7 — not the closed window's place (7, 5, 8).
    arrange(&[&new_win, &wins[1], &wins[2]], &mut ev);
    last = focus_of(&mut ev);
    crate::net::inject_keyboard(&[ALT, TAB, TAB | RELEASE]);
    last = moved(&last, 2_000, &mut ev);
    let mut slot_visits = alloc::vec![last.clone()];
    let close6 = request(alloc::format!("CLOSE {}", wins[2]), &mut ev);
    let r_new2 = request(alloc::format!("CREATE_WINDOW {} w6", sids[2]), &mut ev);
    let new2 = String::from(r_new2.strip_prefix("OK ").unwrap_or("0"));
    last = focus_of(&mut ev);
    crate::net::inject_keyboard(&[TAB, TAB | RELEASE]);
    last = moved(&last, 2_000, &mut ev);
    slot_visits.push(last.clone());
    crate::net::inject_keyboard(&[ALT | RELEASE]);
    keys += 6;
    keys_ok &= keys_reach(keys, 2_000) >= keys;
    let want_slot = alloc::format!("{},{},{}/", new_win, new2, wins[1]);
    let slot = stack(&want_slot, 2_000, &mut ev);
    kprintln!(
        "OSX|{}|ktest|{}|visits={}|close={}|new={}|slot={}",
        BUILD_ID,
        name,
        slot_visits.join(","),
        close6,
        new2,
        slot
    );
    // 6. From 7, 8, 5 with 5 minimised: the walk reaches 8, the client restores 5 itself (it
    //    takes the focus) and the walk goes on to 7: at the release 5 stays restored — only a
    //    window the walk itself restored is minimised again.
    arrange(&[&new_win, &new2, &wins[1]], &mut ev);
    let min5 = request(alloc::format!("MINIMIZE {}", wins[1]), &mut ev);
    last = focus_of(&mut ev);
    crate::net::inject_keyboard(&[ALT, TAB, TAB | RELEASE]);
    last = moved(&last, 2_000, &mut ev);
    let mut own_visits = alloc::vec![last.clone()];
    let restore5 = request(alloc::format!("RESTORE {}", wins[1]), &mut ev);
    last = focus_of(&mut ev);
    crate::net::inject_keyboard(&[TAB, TAB | RELEASE]);
    last = moved(&last, 2_000, &mut ev);
    own_visits.push(last.clone());
    crate::net::inject_keyboard(&[ALT | RELEASE]);
    keys += 6;
    keys_ok &= keys_reach(keys, 2_000) >= keys;
    let want_own = alloc::format!("{},{},{}/", new_win, new2, wins[1]);
    let own = stack(&want_own, 2_000, &mut ev);
    kprintln!(
        "OSX|{}|ktest|{}|visits={}|minimize={}|restore={}|own_restore={}",
        BUILD_ID,
        name,
        own_visits.join(","),
        min5,
        restore5,
        own
    );
    // 7. From 7, 8, 5 with 5 minimised: a walk goes 8, 5 (restored), 7 and the manager
    //    restarts the input service with Alt still held: the walk ends there as at a release —
    //    5 is minimised again and 7 is on top (before, the walk was dropped and 5 stayed
    //    restored, 7, 5, 8).
    arrange(&[&new_win, &new2, &wins[1]], &mut ev);
    let min5b = request(alloc::format!("MINIMIZE {}", wins[1]), &mut ev);
    last = focus_of(&mut ev);
    crate::net::inject_keyboard(&[ALT]);
    let mut lost_visits = Vec::new();
    for _ in 0..3 {
        crate::net::inject_keyboard(&[TAB, TAB | RELEASE]);
        last = moved(&last, 2_000, &mut ev);
        lost_visits.push(last.clone());
    }
    keys += 7;
    keys_ok &= keys_reach(keys, 2_000) >= keys;
    let restart = match crate::services::request(&h.m.ctl, b"RESTART input", sched::ticks() + 500) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => e.into(),
    };
    let want_lost = alloc::format!("{},{},{}/{}", new_win, new2, wins[1], wins[1]);
    let lost = stack(&want_lost, 60_000, &mut ev);
    let lines = h.poll_list(sched::ticks() + 60_000, |l| {
        l.iter()
            .any(|x| x.name == "input" && x.state == "ready" && x.restarts == 1)
    });
    let (input_state, input_restarts, _) = svc_state(&lines, "input");
    kprintln!(
        "OSX|{}|ktest|{}|minimize={}|lost_visits={}|restart={}|lost={}|input={}:{}|keys={}",
        BUILD_ID,
        name,
        min5b,
        lost_visits.join(","),
        restart,
        lost,
        input_state,
        input_restarts,
        u8::from(keys_ok)
    );
    if !keys_ok {
        fail("the compositor did not handle the test's keys in time")
    }
    if close != "OK" || churn != want_churn || churn_focus != new_win {
        fail("a walk ended on a window other than its last, or under a window opened during it")
    }
    if close6 != "OK" || slot != want_slot {
        fail("a window opened during a walk in a closed window's slot was taken for the closed one")
    }
    if min5 != "OK" || restore5 != "OK" || own != want_own {
        fail("a window its client restored during a walk was minimised again at the release")
    }
    if min5b != "OK" || restart != "OK" || lost != want_lost || input_restarts != 1 {
        fail("a walk interrupted by the loss of the input service left the windows it passed over moved")
    }
    // Everything the test holds goes before the balance: a test function never returns, so
    // a binding left out stays allocated and its slab page shows as a lost frame.
    drop((
        ev,
        vmos,
        sids,
        wins,
        minimize,
        visits,
        partial,
        focus0,
        last,
        want,
        want_partial,
        quick,
        close,
        r_new,
        new_win,
        want_churn,
        churn,
        churn_focus,
        churn_visits,
        slot_visits,
        own_visits,
        close6,
        r_new2,
        new2,
        want_slot,
        slot,
        min5,
        restore5,
        want_own,
        own,
        min5b,
        lost_visits,
        restart,
        want_lost,
        lost,
        lines,
        input_state,
        admin,
        clients,
    ));
    display_finish(
        name,
        h,
        "with Alt held Tab visits every window in most-recent order, and one Alt+Tab goes back to the last one",
    )
}

/// TST-M5-WINDOW-STATES (REQ-M5-003): focus by request, by Alt+Tab and by click; z-order
/// after a raise; resize (the client is told and attaches a new surface); minimise and
/// restore; close; nothing left behind.
fn window_states() -> ! {
    let (h, admin, mut clients, format) = display_env(
        "window_states",
        b"/SYSTEM/SVC-DP.TXT",
        &["auth", "input", "display"],
        2,
    );
    // b is held apart: in step 6 its client goes away without a word.
    let b_client = clients
        .pop()
        .unwrap_or_else(|| fail("the display setting gave fewer than two clients"));
    let (a, b) = (&clients[0], &b_client);
    let (mut ev_a, mut ev_b) = (Vec::new(), Vec::new());
    let status0 = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    if status_field(&status0, "screen=") != "1280x800" {
        kprintln!("OSX|{}|ktest|window_states|status={}", BUILD_ID, status0);
        fail("the lab's pointer steps are written for a 1280x800 frame")
    }
    let (vmo_a, entry_a) = kernel_surface(300, 200, format, 0xD04040);
    let (vmo_b, entry_b) = kernel_surface(300, 200, format, 0x40B060);
    let sa = drequest(
        a,
        b"CREATE_SURFACE 300 200",
        alloc::vec![entry_a],
        &mut ev_a,
    );
    let sb = drequest(
        b,
        b"CREATE_SURFACE 300 200",
        alloc::vec![entry_b],
        &mut ev_b,
    );
    let (sa_id, sb_id): (String, String) = (
        sa.strip_prefix("OK ").unwrap_or("0").into(),
        sb.strip_prefix("OK ").unwrap_or("0").into(),
    );
    let wa = drequest(
        a,
        alloc::format!("CREATE_WINDOW {} a", sa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let wb = drequest(
        b,
        alloc::format!("CREATE_WINDOW {} b", sb_id).as_bytes(),
        Vec::new(),
        &mut ev_b,
    );
    let (wa_id, wb_id): (String, String) = (
        wa.strip_prefix("OK ").unwrap_or("0").into(),
        wb.strip_prefix("OK ").unwrap_or("0").into(),
    );
    // Creating b took the focus from a.
    let _ = read_events(a, 1, sched::ticks() + 200)
        .into_iter()
        .map(|e| ev_a.push(e))
        .count();
    // 1. a raises itself: focus and the top of the stack.
    let r_raise = drequest(
        a,
        alloc::format!("RAISE {}", wa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let _ = read_events(a, 1, sched::ticks() + 200)
        .into_iter()
        .map(|e| ev_a.push(e))
        .count();
    let _ = read_events(b, 1, sched::ticks() + 200)
        .into_iter()
        .map(|e| ev_b.push(e))
        .count();
    let la = parse_windows(&drequest(a, b"LIST", Vec::new(), &mut ev_a));
    let lb = parse_windows(&drequest(b, b"LIST", Vec::new(), &mut ev_b));
    let (oa, ob) = (client_origin(0), client_origin(1));
    kprintln!(
        "OSX|{}|ktest|window_states|surfaces={}/{}|windows={}/{}|raise={}|ev_a={}|ev_b={}|a={}|b={}|phase=1|ready=1",
        BUILD_ID,
        sa,
        sb,
        wa,
        wb,
        r_raise,
        ev_a.join(";"),
        ev_b.join(";"),
        la.first().map_or(String::new(), |w| alloc::format!("{},{},{},{},{},{},{}", w.x, w.y, w.w, w.h, w.z, u8::from(w.focused), u8::from(w.minimized))),
        lb.first().map_or(String::new(), |w| alloc::format!("{},{},{},{},{},{},{}", w.x, w.y, w.w, w.h, w.z, u8::from(w.focused), u8::from(w.minimized))),
    );
    let geom = |l: &[WinLine], o: (i64, i64)| {
        l.len() == 1 && (l[0].x, l[0].y, l[0].w, l[0].h) == (o.0, o.1, 300, 200)
    };
    if !geom(&la, oa)
        || !geom(&lb, ob)
        || r_raise != "OK"
        || !(la[0].z == 0 && la[0].focused && lb[0].z == 1 && !lb[0].focused)
        || ev_a
            != [
                alloc::format!("FOCUS {}", wa_id),
                alloc::format!("UNFOCUS {}", wa_id),
                alloc::format!("FOCUS {}", wa_id),
            ]
        || ev_b
            != [
                alloc::format!("FOCUS {}", wb_id),
                alloc::format!("UNFOCUS {}", wb_id),
            ]
    {
        fail("creation, raise or the focus events did not follow display.md")
    }
    ev_a.clear();
    ev_b.clear();
    // 2. The lab presses Alt+Tab: the Alt press reaches a (focused), the Tab is the
    // shortcut (swallowed with its release), the focus moves to b, which then sees the Alt
    // release.
    let fb = read_events(b, 2, sched::ticks() + 60_000);
    let ua = read_events(a, 2, sched::ticks() + 2_000);
    let status1 = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    kprintln!(
        "OSX|{}|ktest|window_states|alt_tab_b={}|alt_tab_a={}|status={}|phase=2|ready=1",
        BUILD_ID,
        fb.join(";"),
        ua.join(";"),
        status1
    );
    if fb
        != [
            alloc::format!("FOCUS {}", wb_id),
            String::from("KEY 0x38 up 0 -"),
        ]
        || ua
            != [
                String::from("KEY 0x38 down 4 -"),
                alloc::format!("UNFOCUS {}", wa_id),
            ]
        || status_field(&status1, "focus=") != wb_id
    {
        fail("Alt+Tab did not move the focus to the next window")
    }
    // 3. The lab moves the pointer onto a's title bar and clicks: a is focused again.
    let fa = read_events(a, 1, sched::ticks() + 60_000);
    let ub = read_events(b, 1, sched::ticks() + 2_000);
    let status2 = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    kprintln!(
        "OSX|{}|ktest|window_states|click_a={}|click_b={}|status={}",
        BUILD_ID,
        fa.join(";"),
        ub.join(";"),
        status2
    );
    if fa != [alloc::format!("FOCUS {}", wa_id)]
        || ub != [alloc::format!("UNFOCUS {}", wb_id)]
        || status_field(&status2, "focus=") != wa_id
        || status_field(&status2, "pointer=") != "170,32"
    {
        fail("the click on the title bar did not focus the window, or the pointer is elsewhere")
    }
    // 4. Resize: a is told, attaches a new surface of the new size.
    let r_resize = drequest(
        a,
        alloc::format!("RESIZE {} 200 100", wa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    // The service sends the event before its reply: drequest collected it (CI run 39155828636).
    let resized = core::mem::take(&mut ev_a);
    let (vmo_a2, entry_a2) = kernel_surface(200, 100, format, 0xD04040);
    let sa2 = drequest(
        a,
        b"CREATE_SURFACE 200 100",
        alloc::vec![entry_a2],
        &mut ev_a,
    );
    let sa2_id: String = sa2.strip_prefix("OK ").unwrap_or("0").into();
    let r_attach = drequest(
        a,
        alloc::format!("ATTACH {} {}", wa_id, sa2_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let r_destroy = drequest(
        a,
        alloc::format!("DESTROY_SURFACE {}", sa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let la2 = parse_windows(&drequest(a, b"LIST", Vec::new(), &mut ev_a));
    // 5. Minimise: the focus goes to b; restore: back to a.
    let r_min = drequest(
        a,
        alloc::format!("MINIMIZE {}", wa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let min_a = core::mem::take(&mut ev_a);
    let min_b = read_events(b, 1, sched::ticks() + 2_000);
    let la3 = parse_windows(&drequest(a, b"LIST", Vec::new(), &mut ev_a));
    let status3 = drequest(b, b"STATUS", Vec::new(), &mut ev_b);
    let r_restore = drequest(
        a,
        alloc::format!("RESTORE {}", wa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let res_a = core::mem::take(&mut ev_a);
    let res_b = read_events(b, 1, sched::ticks() + 2_000);
    let la4 = parse_windows(&drequest(a, b"LIST", Vec::new(), &mut ev_a));
    kprintln!(
        "OSX|{}|ktest|window_states|resize={}|resized={}|surface2={}|attach={}|destroy={}|a2={}|minimize={}|min_a={}|min_b={}|a3={}|status_b={}|restore={}|res_a={}|res_b={}|a4={}",
        BUILD_ID,
        r_resize,
        resized.join(";"),
        sa2,
        r_attach,
        r_destroy,
        la2.first().map_or(String::new(), |w| alloc::format!("{},{},{},{},{:?},{}", w.x, w.y, w.w, w.h, w.sid, u8::from(w.minimized))),
        r_min,
        min_a.join(";"),
        min_b.join(";"),
        la3.first().map_or(String::new(), |w| alloc::format!("{},{},{}", u8::from(w.minimized), u8::from(w.focused), w.z)),
        status3,
        r_restore,
        res_a.join(";"),
        res_b.join(";"),
        la4.first().map_or(String::new(), |w| alloc::format!("{},{},{}", u8::from(w.minimized), u8::from(w.focused), w.z)),
    );
    let sa2_num: u32 = sa2_id.parse().unwrap_or(0);
    if r_resize != "OK"
        || resized != [alloc::format!("RESIZED {} 200 100", wa_id)]
        || !sa2.starts_with("OK ")
        || r_attach != "OK"
        || r_destroy != "OK"
        || !(la2.len() == 1 && (la2[0].w, la2[0].h, la2[0].sid) == (200, 100, Some(sa2_num)))
        || r_min != "OK"
        || min_a != [alloc::format!("UNFOCUS {}", wa_id)]
        || min_b != [alloc::format!("FOCUS {}", wb_id)]
        || !(la3.len() == 1 && la3[0].minimized && !la3[0].focused)
        || status_field(&status3, "focus=") != wb_id
        || r_restore != "OK"
        || res_a != [alloc::format!("FOCUS {}", wa_id)]
        || res_b != [alloc::format!("UNFOCUS {}", wb_id)]
        || !(la4.len() == 1 && !la4[0].minimized && la4[0].focused && la4[0].z == 0)
    {
        fail("resize, minimise or restore did not do what display.md says")
    }
    // 6. b's client goes away while its window lies over a's (REQ-M5-003: a surface is never
    // read after its client is gone). b raises itself over a, then its channel closes with
    // no CLOSE: the compositor forgets the window and the surface on its own — windows=1, the
    // focus comes back to a, a's client area hashes as it did alone on top (step 5), and the
    // compositor no longer holds b's surface (only the test's own reference is left).
    let r_raise_b = drequest(
        b,
        alloc::format!("RAISE {}", wb_id).as_bytes(),
        Vec::new(),
        &mut ev_b,
    );
    let raise_b_a = read_events(a, 1, sched::ticks() + 2_000);
    let la5 = parse_windows(&drequest(a, b"LIST", Vec::new(), &mut ev_a));
    let held_before = Arc::strong_count(&vmo_b);
    drop(b_client);
    let deadline = sched::ticks() + 5_000;
    let mut status5 = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    while status_field(&status5, "windows=") != "1" && sched::ticks() < deadline {
        sched::poll_until(sched::ticks() + 20, || false);
        status5 = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    }
    let mut gone_a = core::mem::take(&mut ev_a);
    gone_a.extend(read_events(a, 1, sched::ticks() + 500));
    let la6 = parse_windows(&drequest(a, b"LIST", Vec::new(), &mut ev_a));
    let held_after = Arc::strong_count(&vmo_b);
    let hash = |l: &Vec<WinLine>| l.first().map_or(String::new(), |w| w.hash.clone());
    let covered_differs = la5.len() == 1 && hash(&la5) != hash(&la4);
    let uncovered = la6.len() == 1 && hash(&la6) == hash(&la4);
    kprintln!(
        "OSX|{}|ktest|window_states|gone=raise:{}|raise_a={}|covered_differs={}|status={}|gone_a={}|uncovered={}|surface_held={}>{}|",
        BUILD_ID,
        r_raise_b,
        raise_b_a.join(";"),
        u8::from(covered_differs),
        status5,
        gone_a.join(";"),
        u8::from(uncovered),
        held_before,
        held_after
    );
    if r_raise_b != "OK"
        || raise_b_a != [alloc::format!("UNFOCUS {}", wa_id)]
        || !covered_differs
        || status_field(&status5, "windows=") != "1"
        || status_field(&status5, "focus=") != wa_id
        || gone_a != [alloc::format!("FOCUS {}", wa_id)]
        || !uncovered
        || held_before < 2
        || held_after != 1
    {
        fail("a client's surface was still shown or held after the client was gone")
    }
    // 7. a closes; nothing remains.
    let ca = drequest(
        a,
        alloc::format!("CLOSE {}", wa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let da = drequest(
        a,
        alloc::format!("DESTROY_SURFACE {}", sa2_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let status4 = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    kprintln!(
        "OSX|{}|ktest|window_states|close={}|destroy={}|status={}",
        BUILD_ID,
        ca,
        da,
        status4
    );
    if ca != "OK" || da != "OK" || status_field(&status4, "windows=") != "0" {
        fail("closing did not remove the windows")
    }
    drop((status0, sa, sb, sa_id, sb_id, wa, wb, wa_id, wb_id, r_raise));
    drop((
        la, lb, fb, ua, status1, fa, ub, status2, r_resize, resized, sa2, sa2_id, r_attach,
    ));
    drop((
        r_destroy, la2, r_min, min_a, min_b, la3, status3, r_restore, res_a, res_b, la4,
    ));
    drop((r_raise_b, raise_b_a, la5, status5, gone_a, la6));
    drop((
        ca, da, status4, ev_a, ev_b, vmo_a, vmo_b, vmo_a2, clients, admin,
    ));
    display_finish(
        "window_states",
        h,
        "focus by request, Alt+Tab and click, z-order, resize with a new surface, minimise and restore all follow display.md",
    )
}

/// A request and how many ticks its reply took.
fn timed_request(
    ep: &Endpoint,
    req: &[u8],
    handles: Vec<Entry>,
    ev: &mut Vec<String>,
) -> (String, u64) {
    let t0 = sched::ticks();
    let r = drequest(ep, req, handles, ev);
    (r, sched::ticks() - t0)
}

/// TST-M5-APP-OVERSIZE (REQ-M5-003, display.md v1.4, input.md v2.4; review 2026-10-19, M1):
/// a message too large for a server's buffer is discarded and answered `ERR BAD_REQUEST` —
/// never left at the head of the queue, where the server would find it on every wake and
/// serve no client after it. Client `a` (connected first, the lower slot) sends 2000 bytes,
/// then a request carrying two handles; after each, client `b` is answered within 500 ticks,
/// and `a` itself still is. The input service the same, with 300 bytes from the controller.
fn app_oversize() -> ! {
    let (h, admin, clients, _format) = display_env(
        "app_oversize",
        b"/SYSTEM/SVC-DP.TXT",
        &["auth", "input", "display"],
        2,
    );
    let (a, b) = (&clients[0], &clients[1]);
    let (mut ev_a, mut ev_b, mut ev_i) = (Vec::new(), Vec::new(), Vec::new());
    let ok = |r: &str| r.starts_with("OK ");
    let big = drequest(a, &[b'x'; 2000], Vec::new(), &mut ev_a);
    let (b1, t1) = timed_request(b, b"STATUS", Vec::new(), &mut ev_b);
    let entry = |ep: Arc<Endpoint>| Entry {
        object: Object::Channel(ep),
        rights: Rights::CHANNEL_DEFAULT,
    };
    let (e1, k1) = channel::create();
    let (e2, k2) = channel::create();
    let two = drequest(a, b"STATUS", alloc::vec![entry(e1), entry(e2)], &mut ev_a);
    let (b2, t2) = timed_request(b, b"STATUS", Vec::new(), &mut ev_b);
    let a_after = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    // The handles moved with the refused request were closed by the compositor.
    let gone = crate::object::channel::SIGNAL_PEER_CLOSED;
    let closed = k1.poll(gone, None) == gone && k2.poll(gone, None) == gone;
    let input = svc_connect(&h, "input");
    let ibig = drequest(&input, &[b'y'; 300], Vec::new(), &mut ev_i);
    let iafter = drequest(&input, b"STATUS", Vec::new(), &mut ev_i);
    kprintln!(
        "OSX|{}|ktest|app_oversize|took_after_big={}|took_after_two={}",
        BUILD_ID,
        t1,
        t2
    );
    kprintln!(
        "OSX|{}|ktest|app_oversize|big={}|two={}|b_after_big={}|b_after_two={}|a_after={}|handles_closed={}|input_big={}|input_after={}",
        BUILD_ID,
        big,
        two,
        u8::from(ok(&b1) && t1 < 500),
        u8::from(ok(&b2) && t2 < 500),
        u8::from(ok(&a_after)),
        u8::from(closed),
        ibig,
        u8::from(ok(&iafter))
    );
    if big != "ERR BAD_REQUEST" || two != "ERR BAD_REQUEST" || ibig != "ERR BAD_REQUEST" {
        fail("an oversized message was not refused")
    }
    if !(ok(&b1) && t1 < 500 && ok(&b2) && t2 < 500) {
        fail("an oversized message from one client stalled the compositor for another")
    }
    if !ok(&a_after) || !ok(&iafter) || !closed {
        fail("a server stopped serving the sender, or kept the handles of a refused message")
    }
    // Everything this test allocated goes before the heap is measured.
    drop((admin, clients, input, k1, k2, ev_a, ev_b, ev_i));
    drop((big, two, b1, b2, a_after, ibig, iafter));
    display_finish(
        "app_oversize",
        h,
        "a message too large for the compositor or the input service is refused and stalls nobody",
    )
}

/// TST-M5-APP-HANG (REQ-M5-003): a client that stops reading never blocks the compositor;
/// its events are dropped and counted; after HANG_TICKS it is unresponsive (red title bar in
/// the lab's screendump); the lab's click on its close button removes the window at once.
fn app_hang() -> ! {
    let (h, admin, clients, format) = display_env(
        "app_hang",
        b"/SYSTEM/SVC-DP.TXT",
        &["auth", "input", "display"],
        2,
    );
    let (a, b) = (&clients[0], &clients[1]);
    let (mut ev_a, mut ev_b) = (Vec::new(), Vec::new());
    let status0 = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    if status_field(&status0, "screen=") != "1280x800" {
        kprintln!("OSX|{}|ktest|app_hang|status={}", BUILD_ID, status0);
        fail("the lab's pointer steps are written for a 1280x800 frame")
    }
    let (vmo_a, entry_a) = kernel_surface(300, 200, format, 0x4060D0);
    let sa = drequest(
        a,
        b"CREATE_SURFACE 300 200",
        alloc::vec![entry_a],
        &mut ev_a,
    );
    let sa_id: String = sa.strip_prefix("OK ").unwrap_or("0").into();
    let wa = drequest(
        a,
        alloc::format!("CREATE_WINDOW {} hung", sa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let wa_id: String = wa.strip_prefix("OK ").unwrap_or("0").into();
    // a stops reading and floods its own queue with requests: 64 replies fit, the rest of
    // the compositor's writes are dropped — and b is still served at once.
    // The compositor's own queue holds 64: each write waits for room (CI run 39154824943
    // wrote 64 of 70 in a burst and nothing was dropped).
    let mut written = 0;
    for _ in 0..70 {
        let ok = sched::poll_until(sched::ticks() + 2_000, || {
            a.write(Message {
                bytes: b"STATUS".to_vec(),
                handles: Vec::new(),
            })
            .is_ok()
        });
        if ok {
            written += 1;
        }
    }
    let t0 = sched::ticks();
    let status_b = drequest(b, b"STATUS", Vec::new(), &mut ev_b);
    let took = sched::ticks() - t0;
    kprintln!(
        "OSX|{}|ktest|app_hang|surface={}|window={}|written={}|status_b={}|took={}",
        BUILD_ID,
        sa,
        wa,
        written,
        status_b,
        took
    );
    if !sa.starts_with("OK ")
        || !wa.starts_with("OK ")
        || written != 70
        || status_field(&status_b, "dropped=") != "6"
        || status_field(&status_b, "unresponsive=") != "0"
        || took >= 500
    {
        fail("the compositor waited on the hung client, or did not count the drops")
    }
    // After HANG_TICKS of a full queue the client is unresponsive.
    sched::poll_until(sched::ticks() + 2_200, || false);
    let status_b2 = drequest(b, b"STATUS", Vec::new(), &mut ev_b);
    // The close button of the first window (k = 0, 300 wide): its centre on the screen.
    let (ox, oy) = client_origin(0);
    let (bx, by) = (
        ox + 300 - WIN_BTN - 2 + WIN_BTN / 2,
        oy - WIN_TITLE + 2 + WIN_BTN / 2,
    );
    kprintln!(
        "OSX|{}|ktest|app_hang|status_b={}|close_button={},{}|title_probe={},{}|phase=1|ready=1",
        BUILD_ID,
        status_b2,
        bx,
        by,
        ox + 100,
        oy - WIN_TITLE / 2
    );
    if status_field(&status_b2, "unresponsive=") != "1" {
        fail("the hung client was not marked unresponsive after HANG_TICKS")
    }
    // The lab takes its screendump (red title bar) and clicks the close button: the window
    // goes at once, no CLOSE_REQUESTED for a client that cannot read it.
    let gone = sched::poll_until(sched::ticks() + 60_000, || {
        let s = drequest(b, b"STATUS", Vec::new(), &mut ev_b);
        status_field(&s, "windows=") == "0"
    });
    let status_b3 = drequest(b, b"STATUS", Vec::new(), &mut ev_b);
    kprintln!(
        "OSX|{}|ktest|app_hang|gone={}|status_b={}",
        BUILD_ID,
        u8::from(gone),
        status_b3
    );
    if !gone || status_field(&status_b3, "pointer=") != alloc::format!("{},{}", bx, by) {
        fail("the click on the close button did not remove the unresponsive window")
    }
    // a wakes up: its 64 queued replies are still there, then it is served again (the first
    // accepted write clears the mark, so the second STATUS shows it).
    let backlog = read_events(a, 64, sched::ticks() + 5_000);
    let status_a1 = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    let status_a = drequest(a, b"STATUS", Vec::new(), &mut ev_a);
    let r_destroy = drequest(
        a,
        alloc::format!("DESTROY_SURFACE {}", sa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    kprintln!(
        "OSX|{}|ktest|app_hang|backlog={}|status_a1={}|status_a={}|destroy={}",
        BUILD_ID,
        backlog.len(),
        status_a1,
        status_a,
        r_destroy
    );
    if backlog.len() != 64
        || status_field(&status_a1, "unresponsive=") != "1"
        || status_field(&status_a, "unresponsive=") != "0"
        || r_destroy != "OK"
    {
        fail("the client that read again was not served again")
    }
    drop((
        status0, sa, sa_id, wa, wa_id, status_b, status_b2, status_b3, backlog, status_a1,
    ));
    drop((status_a, r_destroy));
    drop((ev_a, ev_b, vmo_a, clients, admin));
    display_finish(
        "app_hang",
        h,
        "a client that stops reading never blocks the compositor, is marked unresponsive and can be closed from its decoration",
    )
}

// ---- WP-35: the text layer ----------------------------------------------------------------

/// TST-M5-TEXT-GUEST (REQ-M5-004): the textprobe process loads the fonts from /SYSTEM/FONTS,
/// reproduces the host tests' sample (UAX #9 lines, HarfBuzz glyphs, bitmap hashes) and draws
/// a mixed Arabic/Latin line on the frame; its trace carries the line's rectangle and hash,
/// which the lab compares with its screendump and with the host's rendering of the line.
fn text_layer() -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let display = crate::display::display_object().unwrap_or_else(|| fail("no display object"));
    // The line must outlive the probe's exit for the lab's screendump (display.md v1.5).
    crate::display::pin_frame();
    let o = run_with_object(
        "text_layer",
        crate::apps::TEXTPROBE,
        Entry {
            object: Object::Display(display),
            rights: Rights::DISPLAY_DEFAULT,
        },
    );
    kprintln!(
        "OSX|{}|ktest|text_layer|probe_exit={:#x}|frames_delta={}|ready=1",
        BUILD_ID,
        o.exit_code,
        o.frames_delta
    );
    if o.exit_code != 0x7E || o.frames_delta != 0 {
        fail("the text probe did not reproduce the host's results")
    }
    // The lab takes its screendump now and presses Enter when done.
    let kbd = crate::net::keyboard_object();
    let mut byte = [0u8; 1];
    let pressed = sched::poll_until(sched::ticks() + 60_000, || kbd.read(&mut byte) > 0);
    kprintln!(
        "OSX|{}|ktest|text_layer|lab_key={}|byte={:#x}",
        BUILD_ID,
        u8::from(pressed),
        byte[0]
    );
    if !pressed {
        fail("the lab never pressed a key after its screendump")
    }
    pass("the guest's text layer matches the host's on bidi, shaping, bitmaps and the drawn line")
}

// ---- WP-36: elements and accessibility -------------------------------------------------------

/// Waits until the dialog service has stopped; its exit code (or -1) and the listing text.
fn wait_dialog_stopped(h: &SvcHarness, deadline: u64) -> (String, i64, String) {
    let lines = h.poll_list(deadline, |l| {
        l.iter().any(|x| x.name == "dialog" && x.state == "stopped")
    });
    let d = lines.iter().find(|l| l.name == "dialog");
    let state = d.map_or(String::from("-"), |l| l.state.clone());
    let exit = d.and_then(|l| l.exit).map_or(-1, |x| x as i64);
    (state, exit, SvcHarness::list_text(&lines))
}

/// TST-M5-KEYBOARD-NAV (REQ-M5-005): the sample dialog (SVC-UI.TXT) driven only by the
/// keyboard: the lab's keys after `ready=1` move the focus in the declared order and act on
/// each element; the narrator's transcript (checked on the host against the expected file,
/// identical in both runs of the case) is the oracle. Esc ends the dialog with exit 0.
fn keyboard_nav(name: &'static str) -> ! {
    let (h, admin, clients, _format) = display_env(
        name,
        b"/SYSTEM/SVC-UI.TXT",
        &["auth", "input", "config", "display", "narrator", "dialog"],
        1,
    );
    kprintln!("OSX|{}|ktest|{}|services=6|ready=1", BUILD_ID, name);
    let (state, exit, listing) = wait_dialog_stopped(&h, sched::ticks() + 120_000);
    kprintln!(
        "OSX|{}|ktest|{}|dialog_state={}|dialog_exit={}|listing={}",
        BUILD_ID,
        name,
        state,
        exit,
        listing
    );
    if state != "stopped" || exit != 0 {
        fail("the dialog did not end with Esc")
    }
    drop((state, listing, clients, admin));
    display_finish(
        name,
        h,
        "the dialog was driven by the keyboard alone and announced every focus and change",
    )
}

/// TST-M5-A11Y-TREE (REQ-M5-005): every element of the sample dialog is announced with a
/// label, a role and a state in focus order; changing `ui.scale` to 2 and `ui.contrast` to
/// high in the config service re-renders it twice the size with the high-contrast palette
/// (the lab's screendump checks a background and a focus-ring pixel).
fn a11y_tree() -> ! {
    let (h, admin, clients, _format) = display_env(
        "a11y_tree",
        b"/SYSTEM/SVC-UI.TXT",
        &["auth", "input", "config", "display", "narrator", "dialog"],
        1,
    );
    let cfg = svc_connect(&h, "config");
    let scale = cfg_request(
        &cfg,
        b"SET device ui.scale 0 201 2",
        Some(token_entry(&admin)),
    );
    let contrast = cfg_request(
        &cfg,
        b"SET device ui.contrast 0 202 high",
        Some(token_entry(&admin)),
    );
    kprintln!(
        "OSX|{}|ktest|a11y_tree|scale={}|contrast={}|ready=1",
        BUILD_ID,
        scale,
        contrast
    );
    if scale != "OK 1" || contrast != "OK 1" {
        fail("the config service refused the UI settings")
    }
    let (state, exit, listing) = wait_dialog_stopped(&h, sched::ticks() + 120_000);
    kprintln!(
        "OSX|{}|ktest|a11y_tree|dialog_state={}|dialog_exit={}|listing={}",
        BUILD_ID,
        state,
        exit,
        listing
    );
    if state != "stopped" || exit != 0 {
        fail("the dialog did not end with Esc")
    }
    drop((state, listing, scale, contrast, cfg, clients, admin));
    display_finish(
        "a11y_tree",
        h,
        "every element was announced with label, role and state, and the UI settings re-rendered the dialog",
    )
}

/// TST-M5-ARABIC-UI (REQ-M5-009, §20 scenario 11): the dialog starts English, then `ui.lang=ar`
/// in the config service turns it Arabic and right-to-left in place (the narrator hears `lang ar`
/// and the focused element with its Arabic label); the lab toggles the keyboard layout with
/// Alt+Shift and types two Arabic letters into the field, then navigates to the list and moves
/// its selection — all announced in Arabic. The lab's screendump shows the Arabic dialog where
/// it reported. Esc ends it with exit 0.
fn arabic_ui() -> ! {
    let (h, admin, clients, _format) = display_env(
        "arabic_ui",
        b"/SYSTEM/SVC-UI.TXT",
        &["auth", "input", "config", "display", "narrator", "dialog"],
        1,
    );
    let cfg = svc_connect(&h, "config");
    let lang = cfg_request(
        &cfg,
        b"SET device ui.lang 0 211 ar",
        Some(token_entry(&admin)),
    );
    kprintln!("OSX|{}|ktest|arabic_ui|lang={}|ready=1", BUILD_ID, lang);
    if lang != "OK 1" {
        fail("the config service refused ui.lang")
    }
    let (state, exit, listing) = wait_dialog_stopped(&h, sched::ticks() + 120_000);
    kprintln!(
        "OSX|{}|ktest|arabic_ui|dialog_state={}|dialog_exit={}|listing={}",
        BUILD_ID,
        state,
        exit,
        listing
    );
    if state != "stopped" || exit != 0 {
        fail("the dialog did not end with Esc")
    }
    drop((state, listing, lang, cfg, clients, admin));
    display_finish(
        "arabic_ui",
        h,
        "the dialog switched to Arabic and took Arabic input and keyboard navigation in right-to-left",
    )
}

// ---- WP-37: the session and the lock --------------------------------------------------------

/// The session tests' setting: a manager with `manifest`, every service in `services` ready,
/// and a channel to the session service. The test kernel logs nobody in: the session does.
fn session_env(
    name: &'static str,
    manifest: &'static [u8],
    services: &[&str],
) -> (SvcHarness, Arc<Endpoint>) {
    let h = SvcHarness::start(name, manifest);
    svc_wait_ready(&h, services, sched::ticks() + 120_000);
    let session = svc_connect(&h, "session");
    (h, session)
}

/// Asks `req` of a service every 20 ticks until `done(reply)` holds or `deadline`; the last
/// reply (the session's `STATE`, the spy's `COUNT`).
fn poll_reply(
    ep: &Endpoint,
    req: &[u8],
    deadline: u64,
    mut done: impl FnMut(&str) -> bool,
) -> String {
    loop {
        let r = cfg_request(ep, req, None);
        if done(&r) || sched::ticks() >= deadline {
            return r;
        }
        let t = sched::ticks() + 20;
        sched::poll_until(t, || false);
    }
}

/// `STATE` says `state` after exactly `changes` transitions (session.md §6).
fn state_is(reply: &str, state: &str, changes: u32) -> bool {
    reply.starts_with(&alloc::format!("OK {} ", state))
        && reply.contains(&alloc::format!(" changes={} ", changes))
}

/// The compositor's count of key events it received from the input service (display.md
/// v1.2 `KEYS`), or -1.
fn display_keys(ep: &Endpoint) -> i64 {
    let mut ev = Vec::new();
    let r = drequest(ep, b"KEYS", Vec::new(), &mut ev);
    r.strip_prefix("OK ")
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1)
}

/// One service's line in the manager's listing: (state, restarts, exit or -1).
fn svc_state(lines: &[SvcLine], name: &str) -> (String, u64, i64) {
    lines.iter().find(|l| l.name == name).map_or_else(
        || (String::from("-"), 0, -1),
        |l| (l.state.clone(), l.restarts, l.exit.map_or(-1, |x| x as i64)),
    )
}

/// TST-M5-LOGIN-SCREEN (REQ-M5-006): from boot the sign-in screen is the only surface shown
/// (the spy's window exists but the compositor holds it back); the lab's wrong password is
/// refused with auth's answer and the right one opens the session; the secure attention
/// sequence locks it and Sign out on the lock screen returns to a fresh sign-in screen while
/// the spy's window and surface are gone (it hears `LOGGED_OUT`, finds no window left and
/// exits 0). The session's and the spy's traces are checked on the host, the screen through
/// three screendumps.
fn login_screen() -> ! {
    let name = "login_screen";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let display = svc_connect(&h, "display");
    let mut ev = Vec::new();
    let state0 = cfg_request(&session, b"STATE", None);
    let status0 = drequest(&display, b"STATUS", Vec::new(), &mut ev);
    let windows0 = String::from(status_field(&status0, "windows="));
    kprintln!(
        "OSX|{}|ktest|login_screen|state0={}|windows0={}|services=5|ready=1",
        BUILD_ID,
        state0,
        windows0
    );
    if state0 != "OK no_session user=- changes=0 display=1 input=1 focus=session" || windows0 != "2"
    {
        fail("the session did not start at the sign-in screen holding the keyboard")
    }
    // The lab: a wrong password, the right one, a key for the spy, the secure attention
    // sequence, then Sign out on the lock screen.
    let back = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "no_session", 3)
    });
    let status1 = drequest(&display, b"STATUS", Vec::new(), &mut ev);
    let windows1 = String::from(status_field(&status1, "windows="));
    let lines = h.poll_list(sched::ticks() + 10_000, |l| {
        l.iter().any(|x| x.name == "spy" && x.state == "stopped")
    });
    let (spy_state, _, spy_exit) = svc_state(&lines, "spy");
    kprintln!(
        "OSX|{}|ktest|login_screen|back={}|windows1={}|spy={}:{}",
        BUILD_ID,
        back,
        windows1,
        spy_state,
        spy_exit
    );
    if back != "OK no_session user=- changes=3 display=1 input=1 focus=session" {
        fail("signing in, locking and signing out did not take the session back to the sign-in screen")
    }
    if windows1 != "1" || spy_state != "stopped" || spy_exit != 0 {
        fail("the previous client's windows survived the sign-out")
    }
    drop((
        state0, status0, windows0, back, status1, windows1, lines, spy_state, ev, display, session,
    ));
    display_finish(
        name,
        h,
        "the sign-in screen came first, refused a wrong password, opened the session, and signing out removed the user's windows",
    )
}

/// Writes `req` to a session client and waits until `deadline` for its one reply (an
/// elevation is answered when its prompt ends).
fn session_ask(ep: &Endpoint, req: &[u8], deadline: u64) -> String {
    if ep
        .write(Message {
            bytes: req.to_vec(),
            handles: Vec::new(),
        })
        .is_err()
    {
        return String::from("error:K_E_SVC_WRITE");
    }
    session_reply(ep, deadline)
}

/// The `keys=<n>` of a spy `COUNT` reply (its focus and connection counts vary with the
/// compositor's life; the key count is the leak check).
fn spy_keys(reply: &str) -> &str {
    reply
        .split(' ')
        .find(|f| f.starts_with("keys="))
        .unwrap_or(reply)
}

/// The key count of a spy `COUNT` reply as a number (-1 when absent).
fn spy_count(reply: &str) -> i64 {
    spy_keys(reply)
        .strip_prefix("keys=")
        .and_then(|n| n.parse().ok())
        .unwrap_or(-1)
}

fn session_reply(ep: &Endpoint, deadline: u64) -> String {
    let mut reply = String::from("error:timeout");
    sched::poll_until(deadline, || match ep.read(256, 0, None) {
        Ok(m) => {
            reply = String::from_utf8_lossy(&m.bytes).into_owned();
            true
        }
        Err(_) => false,
    });
    reply
}

/// TST-M5-ELEVATE (REQ-M5-011, session.md v1.3): an application's `ELEVATE` is approved only on
/// the session's own prompt, by an administrator's name and password, and then exactly the
/// shown request runs with the administrator's token, which no application ever holds and
/// which auth ends at once. The lab signs in as `user` (no administrator), types on the
/// prompt — a wrong password, then admin's; then user's own credentials and Esc; and a name
/// while the compositor is frozen — while the spy, the focused application, counts every key
/// it receives (none from a prompt). Refusals: before a session, a second request while one is
/// pending, the compositor frozen or gone during the prompt.
fn elevate() -> ! {
    let name = "elevate";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-EL.TXT",
        &["auth", "input", "display", "config", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    let config = svc_connect(&h, "config");
    let other = svc_connect(&h, "session");
    let long = sched::ticks() + 600_000;
    // 0. No session yet: refused at once.
    let not_ready = session_ask(
        &session,
        b"ELEVATE config SET device lab.elev 0 901 on",
        sched::ticks() + 5_000,
    );
    kprintln!(
        "OSX|{}|ktest|elevate|not_ready={}|services=6|ready=1",
        BUILD_ID,
        not_ready
    );
    if not_ready != "ERR NOT_READY" {
        fail("an elevation was accepted with no session open")
    }
    // The lab signs in as `user`; the keyboard goes to the spy.
    let opened = poll_reply(&session, b"STATE", long, |r| {
        r.starts_with("OK unlocked user=user changes=1 ") && r.ends_with(" focus=display")
    });
    let spy0 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r.contains(" focus=1 ")
    });
    let tokens0 = object::stats().tokens;
    // A service the manifest does not let the session reach, and a request too long to show
    // in full on the prompt, are refused before any prompt.
    let undeclared = session_ask(&session, b"ELEVATE net STATUS", sched::ticks() + 10_000);
    let too_long = session_ask(
        &session,
        b"ELEVATE config SET device lab.elev 0 901 0123456789abcdef",
        sched::ticks() + 5_000,
    );
    // Review S7: a name in the manifest's charset but unknown (uppercase `SPY`, the manager
    // has `spy`) reaches the manager and is refused ERR ACCESS, not rejected here as malformed;
    // a name outside the charset (`a.b`) is ERR BAD_REQUEST before the manager is asked.
    let uppercase = session_ask(&session, b"ELEVATE SPY STATUS", sched::ticks() + 10_000);
    let bad_char = session_ask(&session, b"ELEVATE a.b x", sched::ticks() + 5_000);
    kprintln!(
        "OSX|{}|ktest|elevate|undeclared={}|too_long={}|uppercase={}|bad_char={}|",
        BUILD_ID,
        undeclared,
        too_long,
        uppercase,
        bad_char
    );
    if undeclared != "ERR ACCESS" || too_long != "ERR BAD_REQUEST" {
        fail("an elevation to an undeclared service or too long to show was not refused")
    }
    if uppercase != "ERR ACCESS" || bad_char != "ERR BAD_REQUEST" {
        fail("the service-name charset did not match the manifest (review S7)")
    }
    drop((undeclared, too_long, uppercase, bad_char));
    // session.md v1.5: a request within 32 characters but wider than the prompt's row (wide
    // letters: 279 of 241 pixels at 1×) is refused at once, before any prompt — the screen
    // would have cut it after "0 9" while every byte of it ran. Nothing was set, and the
    // session is not elevating (`OK none`, no `elevate=prompt` for it: forbidden marker).
    let wide = session_ask(
        &session,
        b"ELEVATE config SET device MMMMMMMM 0 901 off",
        sched::ticks() + 5_000,
    );
    let wide_state = session_ask(&session, b"ELEVATION", sched::ticks() + 5_000);
    let wide_set = cfg_request(&config, b"GET device MMMMMMMM", None);
    kprintln!(
        "OSX|{}|ktest|elevate|wide={}|wide_state={}|wide_set={}|",
        BUILD_ID,
        wide,
        wide_state,
        wide_set
    );
    if wide != "ERR BAD_REQUEST"
        || !wide_state.starts_with("OK none ")
        || wide_set != "ERR NOT_FOUND"
    {
        fail("a request wider than the prompt shows was not refused before the prompt")
    }
    drop((wide, wide_state, wide_set));
    // 1. The approved elevation; a second one meanwhile is refused at once.
    if session
        .write(Message {
            bytes: b"ELEVATE config SET device lab.elev 0 901 on".to_vec(),
            handles: Vec::new(),
        })
        .is_err()
    {
        fail("the session's client channel is closed")
    }
    let prompt1 = poll_reply(&session, b"ELEVATION", sched::ticks() + 30_000, |r| {
        r.starts_with("OK prompt ")
    });
    let busy = session_ask(
        &other,
        b"ELEVATE config SET device lab.other 0 990 x",
        sched::ticks() + 5_000,
    );
    kprintln!(
        "OSX|{}|ktest|elevate|opened={}|spy0={}|prompt={}|busy={}|phase=1|ready=1",
        BUILD_ID,
        opened,
        spy0,
        prompt1,
        busy
    );
    if !opened.starts_with("OK unlocked user=user ")
        || !prompt1.starts_with("OK prompt ")
        || busy != "ERR BUSY"
    {
        fail("the prompt did not come up, or a second elevation was not refused")
    }
    // The lab: admin with a wrong password (refused on the prompt), then the right one.
    let approved = session_reply(&session, long);
    let set1 = cfg_request(&config, b"GET device lab.elev", None);
    let tokens1 = {
        let mut t = object::stats().tokens;
        let until = sched::ticks() + 10_000;
        while t != tokens0 && sched::ticks() < until {
            sched::poll_until(sched::ticks() + 20, || false);
            t = object::stats().tokens;
        }
        t
    };
    let back1 = poll_reply(&session, b"STATE", sched::ticks() + 10_000, |r| {
        r.ends_with(" focus=display")
    });
    let spy1 = cfg_request(&spy, b"COUNT", None);
    kprintln!(
        "OSX|{}|ktest|elevate|approved={}|set={}|tokens={}->{}|back={}|spy1={}|phase=2|ready=1",
        BUILD_ID,
        approved,
        set1,
        tokens0,
        tokens1,
        back1,
        spy1
    );
    if approved != "ELEVATED OK 1" || set1 != "OK 1 on" {
        fail("the approved request did not run exactly as shown")
    }
    if tokens1 != tokens0 {
        fail("the administrator's token outlived the elevation")
    }
    if !back1.ends_with(" focus=display") || spy1 != spy0 {
        fail("a key typed on the prompt reached an application, or the keyboard did not come back")
    }
    // 2. user's own credentials are not an administrator's; Esc cancels.
    let cancelled = session_ask(
        &session,
        b"ELEVATE config SET device lab.elev2 0 902 on",
        long,
    );
    let set2 = cfg_request(&config, b"GET device lab.elev2", None);
    let back2 = poll_reply(&session, b"STATE", sched::ticks() + 10_000, |r| {
        r.ends_with(" focus=display")
    });
    let spy2 = cfg_request(&spy, b"COUNT", None);
    kprintln!(
        "OSX|{}|ktest|elevate|cancelled={}|set2={}|spy2={}|phase=3|ready=1",
        BUILD_ID,
        cancelled,
        set2,
        spy2
    );
    if cancelled != "ERR CANCELLED"
        || set2 != "ERR NOT_FOUND"
        || spy2 != spy0
        || !back2.ends_with(" focus=display")
    {
        fail("a refused or cancelled elevation ran, or its keys reached an application")
    }
    // 3. The compositor freezes while the prompt is up: the session's next request to it
    // (the redraw after the lab's first key) waits out its deadline, and the elevation ends
    // unanswered — nothing runs.
    if session
        .write(Message {
            bytes: b"ELEVATE config SET device lab.elev3 0 903 on".to_vec(),
            handles: Vec::new(),
        })
        .is_err()
    {
        fail("the session's client channel is closed")
    }
    let prompt3 = poll_reply(&session, b"ELEVATION", sched::ticks() + 30_000, |r| {
        r.starts_with("OK prompt ")
    });
    let frozen = sched::freeze_named(b"DISPLAYD.ELF");
    kprintln!(
        "OSX|{}|ktest|elevate|prompt3={}|frozen=1|phase=4|ready=1",
        BUILD_ID,
        prompt3
    );
    let unavailable = session_reply(&session, long);
    let thawed = sched::thaw_named(b"DISPLAYD.ELF");
    let set3 = cfg_request(&config, b"GET device lab.elev3", None);
    let reconnected = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        r.contains(" display=") && !r.contains(" display=1 ") && r.ends_with(" focus=display")
    });
    // 3b. A stale answer approves nothing (review C1), on the compositor back from its freeze.
    // `other` asks; auth is frozen; the lab types an administrator's name and password (the
    // LOGIN waits at auth); `other` closes its
    // channel, which ends its elevation; a new elevation is refused BUSY while that answer is
    // still awaited; auth thaws and answers with an administrator's token — for an elevation
    // that ended: the token is ended at once and nothing runs. Then the same request, asked
    // again, is approved the ordinary way: the refusal was for the pending answer only.
    let back5 = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        r.starts_with("OK unlocked ") && r.ends_with(" focus=display")
    });
    if other
        .write(Message {
            bytes: b"ELEVATE config SET device lab.elev5 0 905 on".to_vec(),
            handles: Vec::new(),
        })
        .is_err()
    {
        fail("the other client channel is closed")
    }
    let prompt5 = poll_reply(&session, b"ELEVATION", sched::ticks() + 30_000, |r| {
        r.starts_with("OK prompt ")
    });
    let frozen5 = sched::freeze_named(b"AUTHD.ELF");
    kprintln!(
        "OSX|{}|ktest|elevate|back5={}|prompt5={}|auth_frozen={}|phase=3b|ready=1",
        BUILD_ID,
        back5,
        prompt5,
        frozen5
    );
    if !prompt5.starts_with("OK prompt ") || !frozen5 {
        fail("the fifth prompt did not come up, or auth could not be frozen")
    }
    // The administrator's LOGIN is on its way to a frozen auth.
    let waiting5 = poll_reply(&session, b"AUTH", sched::ticks() + 60_000, |r| {
        r.starts_with("OK waiting=1 ")
    });
    drop(other);
    let ended5 = poll_reply(&session, b"ELEVATION", sched::ticks() + 30_000, |r| {
        r.starts_with("OK none ")
    });
    let busy5 = session_ask(
        &session,
        b"ELEVATE config SET device lab.elev6 0 906 on",
        sched::ticks() + 5_000,
    );
    let thawed5 = sched::thaw_named(b"AUTHD.ELF");
    let settled5 = poll_reply(&session, b"AUTH", sched::ticks() + 60_000, |r| {
        r.starts_with("OK waiting=0 ")
    });
    let tokens5 = {
        let mut t = object::stats().tokens;
        let until = sched::ticks() + 10_000;
        while t != tokens0 && sched::ticks() < until {
            sched::poll_until(sched::ticks() + 20, || false);
            t = object::stats().tokens;
        }
        t
    };
    let set5 = cfg_request(&config, b"GET device lab.elev5", None);
    let set6 = cfg_request(&config, b"GET device lab.elev6", None);
    kprintln!(
        "OSX|{}|ktest|elevate|waiting5={}|ended5={}|busy5={}|thawed5={}|settled5={}|tokens5={}|set5={}|set6={}|phase=3c|ready=1",
        BUILD_ID,
        waiting5,
        ended5,
        busy5,
        thawed5,
        settled5,
        tokens5,
        set5,
        set6
    );
    if !waiting5.starts_with("OK waiting=1 ") || !ended5.starts_with("OK none ") {
        fail("the elevation did not end when its client left with the answer pending")
    }
    if busy5 != "ERR BUSY" {
        fail("an elevation was accepted while an administrator's answer was still awaited")
    }
    if tokens5 != tokens0 || set5 != "ERR NOT_FOUND" || set6 != "ERR NOT_FOUND" {
        fail("a stale administrator's answer approved something, or its token survived")
    }
    // The same request again, approved on its own prompt by the lab.
    let approved6 = session_ask(
        &session,
        b"ELEVATE config SET device lab.elev6 0 906 on",
        long,
    );
    let set6b = cfg_request(&config, b"GET device lab.elev6", None);
    let tokens6 = {
        let mut t = object::stats().tokens;
        let until = sched::ticks() + 10_000;
        while t != tokens0 && sched::ticks() < until {
            sched::poll_until(sched::ticks() + 20, || false);
            t = object::stats().tokens;
        }
        t
    };
    let spy6 = cfg_request(&spy, b"COUNT", None);
    kprintln!(
        "OSX|{}|ktest|elevate|approved6={}|set6b={}|tokens6={}|spy6={}|phase=3d",
        BUILD_ID,
        approved6,
        set6b,
        tokens6,
        spy6
    );
    if approved6 != "ELEVATED OK 1"
        || set6b != "OK 1 on"
        || tokens6 != tokens0
        || spy_keys(&spy6) != spy_keys(&spy0)
    {
        fail("the elevation after the stale answer did not run as shown, or leaked")
    }
    drop((
        back5, prompt5, waiting5, ended5, busy5, settled5, set5, set6, approved6, set6b, spy6,
    ));
    // The compositor counts every release of its held screen (display.md v1.11 `HOLDS`): a
    // prompt that ends must never release the screen when the session is not unlocked.
    let display = svc_connect(&h, "display");
    let mut dev = Vec::new();
    let releases = |r: &str| String::from(r.split(" releases=").nth(1).unwrap_or("?"));
    // 3e (WP-38, mutant M89). The keys before the screen: with the input service frozen the
    // session cannot take the keyboard, so the elevation ends ERR UNAVAILABLE before any
    // prompt; the screen is never held for it, so it is never released either.
    let holds_a = drequest(&display, b"HOLDS", Vec::new(), &mut dev);
    let frozen_in = sched::freeze_named(b"INPUTD.ELF");
    let no_keys = session_ask(
        &session,
        b"ELEVATE config SET device lab.elev8 0 908 on",
        sched::ticks() + 30_000,
    );
    let thawed_in = sched::thaw_named(b"INPUTD.ELF");
    let holds_b = drequest(&display, b"HOLDS", Vec::new(), &mut dev);
    let set8 = cfg_request(&config, b"GET device lab.elev8", None);
    let back8 = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        r.starts_with("OK unlocked ") && !r.contains(" input=1 ") && r.ends_with(" focus=display")
    });
    kprintln!(
        "OSX|{}|ktest|elevate|frozen_in={}|no_keys={}|thawed_in={}|holds={}->{}|set8={}|back8={}|phase=3e",
        BUILD_ID,
        frozen_in,
        no_keys,
        thawed_in,
        holds_a,
        holds_b,
        set8,
        back8
    );
    if no_keys != "ERR UNAVAILABLE"
        || holds_b != holds_a
        || set8 != "ERR NOT_FOUND"
        || !back8.ends_with(" focus=display")
    {
        fail("an elevation without the keyboard showed a prompt or released the screen")
    }
    // 3f (WP-38, mutants M98 and M101). The secure attention sequence while the prompt is up:
    // the elevation ends ERR CANCELLED, the session locks, and the screen stays held from the
    // prompt to the lock screen — not one release in between. Then the lab unlocks.
    if session
        .write(Message {
            bytes: b"ELEVATE config SET device lab.elev7 0 907 on".to_vec(),
            handles: Vec::new(),
        })
        .is_err()
    {
        fail("the session's client channel is closed")
    }
    let prompt7 = poll_reply(&session, b"ELEVATION", sched::ticks() + 30_000, |r| {
        r.starts_with("OK prompt ")
    });
    let holds_c = drequest(&display, b"HOLDS", Vec::new(), &mut dev);
    kprintln!(
        "OSX|{}|ktest|elevate|prompt7={}|holds_c={}|sak=armed|phase=3f|ready=1",
        BUILD_ID,
        prompt7,
        holds_c
    );
    let sak7 = session_reply(&session, long);
    let locked7 = poll_reply(&session, b"STATE", sched::ticks() + 30_000, |r| {
        r.starts_with("OK locked ")
    });
    let holds_d = drequest(&display, b"HOLDS", Vec::new(), &mut dev);
    let set7 = cfg_request(&config, b"GET device lab.elev7", None);
    let back7 = poll_reply(&session, b"STATE", long, |r| {
        r.starts_with("OK unlocked ") && r.ends_with(" focus=display")
    });
    kprintln!(
        "OSX|{}|ktest|elevate|sak7={}|locked7={}|holds_d={}|set7={}|back7={}|phase=3g",
        BUILD_ID,
        sak7,
        locked7,
        holds_d,
        set7,
        back7
    );
    if sak7 != "ERR CANCELLED"
        || !locked7.starts_with("OK locked user=user ")
        || !holds_c.starts_with("OK locked=1 ")
        || !holds_d.starts_with("OK locked=1 ")
        || releases(&holds_d) != releases(&holds_c)
        || set7 != "ERR NOT_FOUND"
    {
        fail("the secure attention sequence did not end the prompt into the lock, screen held")
    }
    // M103: the lab's Enter went down with the unlock (QMP `key-down`) and comes up only once
    // the session's answer is in the serial log, well inside RELEASE_WAIT whatever auth's
    // PBKDF2 took: the session keeps the keyboard until that release, which reaches no
    // application. The lab then types `f` as a fence: it travels the same queue after the
    // release, so once the spy has it, a leaked release would have been counted first. The spy
    // gets exactly the fence's press and release.
    if !back7.starts_with("OK unlocked user=user ") {
        fail("the lab's unlock after the secure attention sequence did not open the session")
    }
    let keys0 = spy_count(&spy0);
    kprintln!(
        "OSX|{}|ktest|elevate|fence=armed|phase=3h|ready=1",
        BUILD_ID
    );
    let fenced = poll_reply(&spy, b"COUNT", sched::ticks() + 30_000, |r| {
        spy_count(r) >= keys0 + 2
    });
    // A third key, if any, is the fence's release after a leaked one: give it time to land.
    let spy7 = poll_reply(&spy, b"COUNT", sched::ticks() + 1_500, |r| {
        spy_count(r) > keys0 + 2
    });
    kprintln!(
        "OSX|{}|ktest|elevate|fenced={}|spy7={}|phase=3h",
        BUILD_ID,
        fenced,
        spy7
    );
    if spy_count(&fenced) < keys0 + 2 {
        fail("the lab's fence key never reached the application")
    }
    if spy_count(&spy7) != keys0 + 2 {
        fail("the release of the key that unlocked reached an application")
    }
    drop((
        holds_a, no_keys, holds_b, set8, back8, prompt7, holds_c, sak7, locked7, holds_d,
    ));
    drop((set7, back7, fenced, dev, display));
    // 3i (WP-38, input.md v2.6, session.md v1.6). The secure attention sequence while an
    // approved request waits at its service. config is frozen, so once the lab has typed
    // admin's password the session sits in the wait for config's answer (it traces
    // `elevate=running`); the lab then floods the pointer (100 packets: more than the input
    // channel's 64 and the session's 32 kept events) and presses Ctrl+Alt+Del. The sequence is
    // never lost: the elevation ends ERR CANCELLED, the session locks, and the input service owes
    // nothing (`sak_pending=0`). auth ends the token before config, thawed, reads the request:
    // nothing is set. Then the lab unlocks as in 3g, and no key reaches the spy.
    let input = svc_connect(&h, "input");
    let frozen9 = sched::freeze_named(b"CONFIGD.ELF");
    if session
        .write(Message {
            bytes: b"ELEVATE config SET device lab.elev9 0 909 on".to_vec(),
            handles: Vec::new(),
        })
        .is_err()
    {
        fail("the session's client channel is closed")
    }
    let prompt9 = poll_reply(&session, b"ELEVATION", sched::ticks() + 30_000, |r| {
        r.starts_with("OK prompt ")
    });
    kprintln!(
        "OSX|{}|ktest|elevate|prompt9={}|config_frozen={}|phase=3i|ready=1",
        BUILD_ID,
        prompt9,
        frozen9
    );
    if !prompt9.starts_with("OK prompt ") || !frozen9 {
        fail("the ninth prompt did not come up, or config could not be frozen")
    }
    // The session answers nothing while it waits for config: the answer comes when the
    // sequence ends the wait (without it, REQUEST_DEADLINE later, ERR UNAVAILABLE).
    let sak9 = session_reply(&session, long);
    let locked9 = poll_reply(&session, b"STATE", sched::ticks() + 30_000, |r| {
        r.starts_with("OK locked ")
    });
    let status9 = poll_reply(&input, b"STATUS", sched::ticks() + 10_000, |r| {
        r.ends_with(" sak_pending=0")
    });
    // auth has answered the token's LOGOUT (and the LOCK) before config may read the request.
    let settled9 = poll_reply(&session, b"AUTH", sched::ticks() + 60_000, |r| {
        r.starts_with("OK waiting=0 ")
    });
    let thawed9 = sched::thaw_named(b"CONFIGD.ELF");
    let tokens9 = {
        let mut t = object::stats().tokens;
        let until = sched::ticks() + 10_000;
        while t != tokens0 && sched::ticks() < until {
            sched::poll_until(sched::ticks() + 20, || false);
            t = object::stats().tokens;
        }
        t
    };
    let set9 = cfg_request(&config, b"GET device lab.elev9", None);
    let back9 = poll_reply(&session, b"STATE", long, |r| {
        r.starts_with("OK unlocked ") && r.ends_with(" focus=display")
    });
    let spy9 = cfg_request(&spy, b"COUNT", None);
    kprintln!(
        "OSX|{}|ktest|elevate|sak9={}|locked9={}|status9={}|settled9={}|thawed9={}|tokens9={}|set9={}|back9={}|spy9={}|phase=3j",
        BUILD_ID,
        sak9,
        locked9,
        status9,
        settled9,
        thawed9,
        tokens9,
        set9,
        back9,
        spy9
    );
    if sak9 != "ERR CANCELLED" || !locked9.starts_with("OK locked user=user ") {
        fail("the secure attention sequence was lost while an approved request waited")
    }
    if !status9.ends_with(" sak_pending=0") {
        fail("the input service still owes the session its secure attention sequence")
    }
    if !settled9.starts_with("OK waiting=0 ")
        || !thawed9
        || tokens9 != tokens0
        || set9 != "ERR NOT_FOUND"
    {
        fail("the request cut off by the secure attention sequence ran, or its token survived")
    }
    if !back9.starts_with("OK unlocked user=user ") || spy_count(&spy9) != spy_count(&spy7) {
        fail("the lab's unlock after the sequence failed, or a key reached the application")
    }
    drop((
        prompt9, sak9, locked9, status9, settled9, set9, back9, spy9, input,
    ));
    // 4. The compositor goes while the prompt is up: the elevation ends unanswered too.
    if session
        .write(Message {
            bytes: b"ELEVATE config SET device lab.elev4 0 904 on".to_vec(),
            handles: Vec::new(),
        })
        .is_err()
    {
        fail("the session's client channel is closed")
    }
    let prompt4 = poll_reply(&session, b"ELEVATION", sched::ticks() + 30_000, |r| {
        r.starts_with("OK prompt ")
    });
    let r_stop = match crate::services::request(&h.m.ctl, b"STOP display", sched::ticks() + 500) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => String::from(e),
    };
    let gone = session_reply(&session, sched::ticks() + 60_000);
    let set4 = cfg_request(&config, b"GET device lab.elev4", None);
    let tokens4 = object::stats().tokens;
    // The spy's window is new on the new compositor: its focus comes back with the
    // session's handover, within a bound; its key count is what must not have moved.
    let spy4 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r.contains(" focus=1 ")
    });
    kprintln!(
        "OSX|{}|ktest|elevate|frozen_n={}|unavailable={}|thawed={}|set3={}|reconnected={}|prompt4={}|stop={}|gone={}|set4={}|tokens4={}|spy4={}|phase=5",
        BUILD_ID,
        frozen,
        unavailable,
        thawed,
        set3,
        reconnected,
        prompt4,
        r_stop,
        gone,
        set4,
        tokens4,
        spy4
    );
    if unavailable != "ERR UNAVAILABLE" || set3 != "ERR NOT_FOUND" {
        fail("an elevation was approved while the compositor did not answer")
    }
    if !prompt4.starts_with("OK prompt ")
        || r_stop != "OK"
        || gone != "ERR UNAVAILABLE"
        || set4 != "ERR NOT_FOUND"
    {
        fail("an elevation survived the compositor's end")
    }
    // The fence of phase 3h is the only key the spy has had since spy0.
    if tokens4 != tokens0 || spy_count(&spy4) != spy_count(&spy7) {
        fail("a token or a key leaked out of a failed elevation")
    }
    drop((
        not_ready, opened, spy0, prompt1, busy, approved, set1, back1, spy1, cancelled, set2,
        back2, spy2,
    ));
    drop((
        prompt3,
        unavailable,
        set3,
        reconnected,
        prompt4,
        r_stop,
        gone,
        set4,
        spy4,
        spy,
        config,
        session,
    ));
    display_finish(
        name,
        h,
        "an elevation ran only as shown on the session's prompt, after an administrator's password, with a token no application held",
    )
}

/// TST-M5-AUTH-INPUT-ISOLATED (REQ-M5-006): with the spy's window focused, the secure
/// attention sequence locks the session; the password typed on the lock screen reaches no
/// client — the spy's key count does not move and the compositor's own count of key events
/// (`KEYS`) stays the same from the lock to the unlock — and no announcement or trace carries
/// it (the narrator hears the password field without a value; the host checks every stream and
/// that the password text appears nowhere in the serial log). A key after the unlock reaches
/// the spy again.
fn auth_input_isolated() -> ! {
    let name = "auth_input_isolated";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SA.TXT",
        &["auth", "input", "display", "narrator", "session", "spy"],
    );
    let display = svc_connect(&h, "display");
    let spy = svc_connect(&h, "spy");
    kprintln!(
        "OSX|{}|ktest|auth_input_isolated|services=6|ready=1",
        BUILD_ID
    );
    // The lab signs in, types `a` and `b` for the spy, then Ctrl+Alt+Del.
    let locked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "locked", 2)
    });
    let spy1 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=6 focus=0 connections=1"
    });
    let keys1 = display_keys(&display);
    kprintln!(
        "OSX|{}|ktest|auth_input_isolated|locked={}|keys={}|spy={}|phase=2|ready=1",
        BUILD_ID,
        locked,
        keys1,
        spy1
    );
    if !locked.starts_with("OK locked user=admin changes=2 ")
        || spy1 != "OK keys=6 focus=0 connections=1"
        || keys1 != 6
    {
        fail("the secure attention sequence did not lock the session with the spy's keys counted")
    }
    // The lab types the password on the lock screen, then Enter.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 3) && r.ends_with(" focus=display")
    });
    let spy2 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=6 focus=1 connections=1"
    });
    let keys2 = display_keys(&display);
    kprintln!(
        "OSX|{}|ktest|auth_input_isolated|unlocked={}|keys_while_locked={}|spy={}|phase=3|ready=1",
        BUILD_ID,
        unlocked,
        keys2 - keys1,
        spy2
    );
    if unlocked != "OK unlocked user=admin changes=3 display=1 input=1 focus=display"
        || keys2 != keys1
        || spy2 != "OK keys=6 focus=1 connections=1"
    {
        fail("a key typed on the lock screen reached the compositor or a client")
    }
    // The lab types `c`: the spy hears it again, through the compositor.
    let spy3 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r.starts_with("OK keys=8 ")
    });
    let keys3 = display_keys(&display);
    kprintln!(
        "OSX|{}|ktest|auth_input_isolated|spy={}|keys={}",
        BUILD_ID,
        spy3,
        keys3
    );
    if spy3 != "OK keys=8 focus=1 connections=1" || keys3 != keys2 + 2 {
        fail("keys did not reach the spy after the unlock")
    }
    drop((locked, spy1, unlocked, spy2, spy3, spy, display, session));
    display_finish(
        name,
        h,
        "the password typed on the lock screen reached the session alone: no client, no compositor, no announcement",
    )
}

/// TST-M5-LIST-HASH-HELD (REQ-M5-006; WP-43 finding M3): `LIST` gives a client the hash of
/// its window's client area only where those pixels are its own on the screen (display.md
/// v1.10); held by the lock, minimised, or under another client's window it reads `-`, so no
/// client learns what the screen shows in its place.
fn list_hash_held() -> ! {
    let name = "list_hash_held";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let a = svc_connect(&h, "display");
    let b = svc_connect(&h, "display");
    let (mut ev_a, mut ev_b) = (Vec::new(), Vec::new());
    let status0 = drequest(&a, b"STATUS", Vec::new(), &mut ev_a);
    let format: u32 = status_field(&status0, "format=").parse().unwrap_or(99);
    if format > 1 {
        kprintln!("OSX|{}|ktest|{}|status={}", BUILD_ID, name, status0);
        fail("the display service did not report its pixel format")
    }
    kprintln!("OSX|{}|ktest|list_hash_held|services=5|ready=1", BUILD_ID);
    let own_hash = |c: &Arc<Endpoint>, ev: &mut Vec<String>| -> String {
        parse_windows(&drequest(c, b"LIST", Vec::new(), ev))
            .first()
            .map_or(String::from("none"), |w| w.hash.clone())
    };
    let is_hex = |s: &str| s.len() == 16 && s.bytes().all(|c| c.is_ascii_hexdigit());
    // Phase 1: the sign-in screen holds the display; a's window is created and not shown.
    let state0 = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        state_is(r, "no_session", 0)
    });
    let (vmo_a, entry_a) = kernel_surface(200, 100, format, 0xD04040);
    let sa = drequest(
        &a,
        b"CREATE_SURFACE 200 100",
        alloc::vec![entry_a],
        &mut ev_a,
    );
    let sa_id: String = sa.strip_prefix("OK ").unwrap_or("0").into();
    let wa = drequest(
        &a,
        alloc::format!("CREATE_WINDOW {} a", sa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let wa_id: String = wa.strip_prefix("OK ").unwrap_or("0").into();
    let held = own_hash(&a, &mut ev_a);
    kprintln!(
        "OSX|{}|ktest|list_hash_held|state={}|surface={}|window={}|held_hash={}|phase=1|ready=1",
        BUILD_ID,
        state0,
        sa,
        wa,
        held
    );
    if !state_is(&state0, "no_session", 0) || !sa.starts_with("OK ") || !wa.starts_with("OK ") {
        fail("the held screen or a's window was not set up")
    }
    if held != "-" {
        fail("LIST gave the hash of a window the lock holds back")
    }
    // Phase 1b: the lab types the user name (not a secret) into the sign-in dialog; while
    // the screen is held, its redraws do not show in a client's STATUS (`composed=`).
    let composed = |ev: &mut Vec<String>| -> String {
        status_field(&drequest(&a, b"STATUS", Vec::new(), ev), "composed=").into()
    };
    let before = composed(&mut ev_a);
    sched::poll_until(sched::ticks() + 15_000, || false);
    let after = composed(&mut ev_a);
    kprintln!(
        "OSX|{}|ktest|list_hash_held|held_composed_same={}|phase=1b|ready=1",
        BUILD_ID,
        u8::from(before == after && !before.is_empty())
    );
    if before != after || before.is_empty() {
        kprintln!(
            "OSX|{}|ktest|list_hash_held|composed={}>{}",
            BUILD_ID,
            before,
            after
        );
        fail("STATUS counted the redraws of the held screen")
    }
    // Phase 2: the lab signs in; a's window is shown on top and its hash is its own.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 1)
    });
    // The compositor learns of the unlock from the session: until then a's window stays held.
    let deadline = sched::ticks() + 10_000;
    let mut open = own_hash(&a, &mut ev_a);
    while !is_hex(&open) && sched::ticks() < deadline {
        sched::poll_until(sched::ticks() + 20, || false);
        open = own_hash(&a, &mut ev_a);
    }
    kprintln!(
        "OSX|{}|ktest|list_hash_held|unlocked={}|open_hex={}|phase=2",
        BUILD_ID,
        unlocked,
        u8::from(is_hex(&open))
    );
    if !state_is(&unlocked, "unlocked", 1) || !is_hex(&open) {
        fail("a's shown window did not get its own hash")
    }
    // Phase 3: b's window is moved over a's client area.
    let la = parse_windows(&drequest(&a, b"LIST", Vec::new(), &mut ev_a));
    let (ax, ay) = la.first().map_or((0, 0), |w| (w.x, w.y));
    let (vmo_b, entry_b) = kernel_surface(200, 100, format, 0x40B060);
    let sb = drequest(
        &b,
        b"CREATE_SURFACE 200 100",
        alloc::vec![entry_b],
        &mut ev_b,
    );
    let sb_id: String = sb.strip_prefix("OK ").unwrap_or("0").into();
    let wb = drequest(
        &b,
        alloc::format!("CREATE_WINDOW {} b", sb_id).as_bytes(),
        Vec::new(),
        &mut ev_b,
    );
    let wb_id: String = wb.strip_prefix("OK ").unwrap_or("0").into();
    let mv = drequest(
        &b,
        alloc::format!("MOVE {} {} {}", wb_id, ax, ay).as_bytes(),
        Vec::new(),
        &mut ev_b,
    );
    let covered = own_hash(&a, &mut ev_a);
    let cover_own = own_hash(&b, &mut ev_b);
    let cb = drequest(
        &b,
        alloc::format!("CLOSE {}", wb_id).as_bytes(),
        Vec::new(),
        &mut ev_b,
    );
    let uncovered = own_hash(&a, &mut ev_a);
    kprintln!(
        "OSX|{}|ktest|list_hash_held|move={}|covered_hash={}|cover_own_hex={}|close={}|uncovered_same={}|phase=3",
        BUILD_ID,
        mv,
        covered,
        u8::from(is_hex(&cover_own)),
        cb,
        u8::from(uncovered == open)
    );
    if mv != "OK" || cb != "OK" || covered != "-" || !is_hex(&cover_own) || uncovered != open {
        fail("LIST gave a the hash of pixels under another client's window")
    }
    // Phase 4: a minimises its window, then restores it.
    let mn = drequest(
        &a,
        alloc::format!("MINIMIZE {}", wa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let minimized = own_hash(&a, &mut ev_a);
    let rs = drequest(
        &a,
        alloc::format!("RESTORE {}", wa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let restored = own_hash(&a, &mut ev_a);
    kprintln!(
        "OSX|{}|ktest|list_hash_held|minimize={}|minimized_hash={}|restore={}|restored_same={}|phase=4",
        BUILD_ID,
        mn,
        minimized,
        rs,
        u8::from(restored == open)
    );
    if mn != "OK" || rs != "OK" || minimized != "-" || restored != open {
        fail("LIST gave the hash of a minimised window's place")
    }
    let ca = drequest(
        &a,
        alloc::format!("CLOSE {}", wa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let da = drequest(
        &a,
        alloc::format!("DESTROY_SURFACE {}", sa_id).as_bytes(),
        Vec::new(),
        &mut ev_a,
    );
    let db = drequest(
        &b,
        alloc::format!("DESTROY_SURFACE {}", sb_id).as_bytes(),
        Vec::new(),
        &mut ev_b,
    );
    if ca != "OK" || da != "OK" || db != "OK" {
        kprintln!(
            "OSX|{}|ktest|list_hash_held|close={}|destroy={},{}",
            BUILD_ID,
            ca,
            da,
            db
        );
        fail("the test's windows and surfaces were not removed")
    }
    drop((
        ev_a, ev_b, state0, sa, wa, held, unlocked, open, la, sb, wb, mv,
    ));
    drop((
        covered, cover_own, cb, uncovered, mn, minimized, rs, restored,
    ));
    drop((
        ca, da, db, sa_id, wa_id, sb_id, wb_id, status0, before, after,
    ));
    drop((vmo_a, vmo_b, a, b, session));
    display_finish(
        name,
        h,
        "a client got the hash of its window only where the pixels were its own",
    )
}

/// TST-M5-SESSION-LOSS (REQ-M5-006; WP-43 finding M9; rewritten for session.md v1.7, WP-64):
/// the session service itself is lost — once after the sign-in (unlocked), once while locked
/// (the manager's RESTART: its process ends and its channels close, as in a crash). Each time
/// the compositor holds the screen, no key reaches the compositor, and the new session starts
/// at `no_session` with its own count of changes, never in the state the lost one had. Since
/// v1.7 the restarted session also ends what the lost one left on the screen before its
/// sign-in screen (`LOGOUT` to the compositor): the spy's window is gone (`LOGGED_OUT`; the
/// spy, a well-behaved application, exits) and the compositor counts the sign-in window alone.
/// The phases after that use a client that connects anew — the test's own window `w` — which
/// is purged the same way by the second restart. A contract-driven change (session.md v1.7,
/// PLAN-ANSWER §2.3 D5-B), not a weakening: every assertion of the earlier case is kept except
/// the spy's own focus after the loss, which the spy's exit makes moot (its window is gone).
fn session_loss() -> ! {
    /// The test's window after the first loss: colour and place on the screen (the open
    /// desktop's screendump finds it at (650,170), and the spy's place (150,150) shows the
    /// desktop, so no window of the lost session came back).
    const W_COLOUR: u32 = 0xD04040;
    const W_AT: (i64, i64) = (600, 100);
    let name = "session_loss";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    let display = svc_connect(&h, "display");
    kprintln!("OSX|{}|ktest|session_loss|services=5|ready=1", BUILD_ID);
    // The manager's RESTART, then its list until the new session process is ready (a CONNECT
    // before that is refused with ERR NOT_READY).
    let restart_session = |n: u64| -> String {
        let r = match crate::services::request(&h.m.ctl, b"RESTART session", sched::ticks() + 500) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => e.into(),
        };
        let lines = h.poll_list(sched::ticks() + 60_000, |l| {
            l.iter()
                .any(|x| x.name == "session" && x.state == "ready" && x.restarts == n)
        });
        if !lines
            .iter()
            .any(|x| x.name == "session" && x.state == "ready" && x.restarts == n)
        {
            fail("the manager did not bring the session service back")
        }
        r
    };
    // Phase 1: the lab signs in; the session is lost while unlocked.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 1) && r.ends_with(" focus=display")
    });
    let spy0 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=0 focus=1 connections=1"
    });
    let r1 = restart_session(1);
    drop(session);
    let session = svc_connect(&h, "session");
    let fresh1 = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        state_is(r, "no_session", 0)
    });
    // v1.7: the purge came before the sign-in screen, so the compositor counts one window
    // (the sign-in dialog), and the spy, told LOGGED_OUT, ended (exit 0, stopped: `never`).
    let mut ev_d = Vec::new();
    let windows1 = String::from(status_field(
        &drequest(&display, b"STATUS", Vec::new(), &mut ev_d),
        "windows=",
    ));
    let spy_lines = h.poll_list(sched::ticks() + 10_000, |l| {
        svc_find(l, "spy").state == "stopped"
    });
    let spy_gone = svc_find(&spy_lines, "spy");
    let spy1 = alloc::format!(
        "{}:{:#x}",
        spy_gone.state,
        spy_gone.exit.unwrap_or(u64::MAX)
    );
    drop(spy);
    let keys1 = display_keys(&display);
    kprintln!(
        "OSX|{}|ktest|session_loss|unlocked={}|spy={}|restart={}|fresh={}|spy_after={}|windows={}|phase=2|ready=1",
        BUILD_ID,
        unlocked,
        spy0,
        r1,
        fresh1,
        spy1,
        windows1
    );
    if !state_is(&unlocked, "unlocked", 1) || spy0 != "OK keys=0 focus=1 connections=1" {
        fail("the lab's sign-in did not unlock the session with the spy focused")
    }
    if r1 != "OK" || fresh1 != "OK no_session user=- changes=0 display=1 input=1 focus=session" {
        fail("the session lost while unlocked did not leave a held screen and a fresh session")
    }
    if spy1 != "stopped:0x0" || windows1 != "1" {
        fail("the restarted session did not end the lost session's windows before its sign-in screen (session.md v1.7)")
    }
    // Phase 2: a client connects anew and makes its window while the screen is held; the lab
    // signs in to the new session; every key of it reaches that session alone (the compositor
    // counts none), and the new window is shown and focused.
    let w = svc_connect(&h, "display");
    let mut ev_w = Vec::new();
    let format: u32 = status_field(&drequest(&w, b"STATUS", Vec::new(), &mut ev_w), "format=")
        .parse()
        .unwrap_or(99);
    let (vmo_w, entry_w) = kernel_surface(200, 120, format, W_COLOUR);
    let sw = drequest(
        &w,
        b"CREATE_SURFACE 200 120",
        alloc::vec![entry_w],
        &mut ev_w,
    );
    let sw_id: String = sw.strip_prefix("OK ").unwrap_or("0").into();
    let ww = drequest(
        &w,
        alloc::format!("CREATE_WINDOW {} w", sw_id).as_bytes(),
        Vec::new(),
        &mut ev_w,
    );
    let ww_id: String = ww.strip_prefix("OK ").unwrap_or("0").into();
    let mw = drequest(
        &w,
        alloc::format!("MOVE {} {} {}", ww_id, W_AT.0, W_AT.1).as_bytes(),
        Vec::new(),
        &mut ev_w,
    );
    let cw = drequest(
        &w,
        alloc::format!("COMMIT {} 0 0 200 120", sw_id).as_bytes(),
        Vec::new(),
        &mut ev_w,
    );
    if format > 1 || !sw.starts_with("OK ") || !ww.starts_with("OK ") || mw != "OK" || cw != "OK" {
        kprintln!(
            "OSX|{}|ktest|session_loss|format={}|surface={}|window={}|move={}|commit={}",
            BUILD_ID,
            format,
            sw,
            ww,
            mw,
            cw
        );
        fail("the reconnecting client's window was not set up")
    }
    let unlocked2 = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 1) && r.ends_with(" focus=display")
    });
    let keys2 = display_keys(&display);
    let w_focused = {
        let deadline = sched::ticks() + 10_000;
        loop {
            let f = parse_windows(&drequest(&w, b"LIST", Vec::new(), &mut ev_w))
                .first()
                .is_some_and(|x| x.focused);
            if f || sched::ticks() >= deadline {
                break f;
            }
            sched::poll_until(sched::ticks() + 20, || false);
        }
    };
    // Past the blit period, the composed picture is on the frame for the lab's screendump.
    sched::poll_until(sched::ticks() + 40, || false);
    kprintln!(
        "OSX|{}|ktest|session_loss|unlocked2={}|keys_during_signin={}|w_focused={}|phase=3|ready=1",
        BUILD_ID,
        unlocked2,
        keys2 - keys1,
        u8::from(w_focused)
    );
    if !state_is(&unlocked2, "unlocked", 1) || keys2 != keys1 {
        fail("the sign-in to the new session did not reach it alone")
    }
    if !w_focused {
        fail("the reconnecting client's window was not focused after the sign-in")
    }
    // Phase 3: the lab presses Ctrl+Alt+Del; the session is lost while locked.
    let locked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "locked", 2)
    });
    let keys3 = display_keys(&display);
    let r2 = restart_session(2);
    drop(session);
    let session = svc_connect(&h, "session");
    let fresh2 = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        state_is(r, "no_session", 0)
    });
    // v1.7: the second restart purged again: `w` was told LOGGED_OUT (queued before the reply
    // to its LIST) and has no window left.
    let w_list = drequest(&w, b"LIST", Vec::new(), &mut ev_w);
    let w_windows = parse_windows(&w_list).len();
    let w_logged_out = ev_w.iter().any(|e| e == "LOGGED_OUT");
    let keys4 = display_keys(&display);
    kprintln!(
        "OSX|{}|ktest|session_loss|locked={}|restart={}|fresh={}|w_logged_out={}|w_windows={}|keys_after_loss={}|phase=4",
        BUILD_ID,
        locked,
        r2,
        fresh2,
        u8::from(w_logged_out),
        w_windows,
        keys4 - keys3
    );
    if !locked.starts_with("OK locked user=admin changes=2 ") {
        fail("the new session did not take the lab's Ctrl+Alt+Del")
    }
    if r2 != "OK"
        || fresh2 != "OK no_session user=- changes=0 display=1 input=1 focus=session"
        || keys4 != keys3
    {
        fail("the session lost while locked did not leave a held screen and a fresh session")
    }
    if !w_logged_out || w_windows != 0 || !w_list.starts_with("OK") {
        fail("the session restarted while locked did not end the open windows before its sign-in screen (session.md v1.7)")
    }
    // Phase 5 (input.md v2.2; WP-38 mutant M106): the lab signs in once more, so the keyboard
    // is the compositor's — the input service's focus is `display`, not the session's. The
    // session is then stopped for good. Its loss must leave the keyboard with nobody, as the
    // input service itself reports (`STATUS` → `focus=-`). Clearing the focus only when the
    // lost client held it is not enough here: at this moment the compositor holds it, and a
    // window it routes to would receive what is typed before a fresh session takes over.
    // Phases 1–4 observe the compositor's side (the spy's focus, then `w`), never the input
    // service's.
    kprintln!("OSX|{}|ktest|session_loss|phase=5|ready=1", BUILD_ID);
    let unlocked3 = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 1) && r.ends_with(" focus=display")
    });
    let input = svc_connect(&h, "input");
    let r3 = match crate::services::request(&h.m.ctl, b"STOP session", sched::ticks() + 500) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => String::from(e),
    };
    drop(session);
    let lines = h.poll_list(sched::ticks() + 60_000, |l| {
        l.iter()
            .any(|x| x.name == "session" && x.state == "stopped")
    });
    let stopped = lines
        .iter()
        .any(|x| x.name == "session" && x.state == "stopped");
    let input_after = poll_reply(&input, b"STATUS", sched::ticks() + 5_000, |r| {
        r.starts_with("OK focus=- ")
    });
    kprintln!(
        "OSX|{}|ktest|session_loss|unlocked3={}|stop={}|stopped={}|input_focus_cleared={}|phase=6",
        BUILD_ID,
        unlocked3,
        r3,
        u8::from(stopped),
        u8::from(input_after.starts_with("OK focus=- "))
    );
    if !state_is(&unlocked3, "unlocked", 1)
        || !unlocked3.ends_with(" focus=display")
        || r3 != "OK"
        || !stopped
        || !input_after.starts_with("OK focus=- ")
    {
        fail("the session lost while the compositor held the keyboard left the keyboard with it")
    }
    // Phase 7 (display.md v1.2 rescue): stopped for good, no session restarts and none purges,
    // so what holds the screen now is the compositor's own reaction to the session's loss.
    let holds = poll_reply(&display, b"HOLDS", sched::ticks() + 5_000, |r| {
        r.starts_with("OK locked=1 ")
    });
    let held_after_stop = holds.starts_with("OK locked=1 ");
    kprintln!(
        "OSX|{}|ktest|session_loss|holds={}|held_after_stop={}|phase=7",
        BUILD_ID,
        holds,
        u8::from(held_after_stop)
    );
    if !held_after_stop {
        fail("the compositor did not hold the screen once the session was gone")
    }
    drop(holds);
    drop((
        unlocked, spy0, r1, fresh1, spy1, windows1, unlocked2, locked, r2, fresh2,
    ));
    drop((
        spy_lines, spy_gone, ev_d, ev_w, sw, sw_id, ww, ww_id, mw, cw, w_list,
    ));
    drop((unlocked3, r3, lines, input_after));
    drop((vmo_w, w, input, display));
    display_finish(
        name,
        h,
        "a lost session left the screen held and the keyboard with nobody until a fresh session",
    )
}

/// TST-M5-FOCUS-AFTER-RESTART (REQ-M5-002; WP-43 finding S-6): the compositor is restarted
/// while the session is unlocked; the session reconnects and hands the keyboard back to the
/// new compositor (session.md v1.4), so the key the lab types afterwards reaches the new
/// compositor and the focused application (the spy's new window) instead of a client that
/// no longer exists.
fn focus_after_restart() -> ! {
    let name = "focus_after_restart";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    kprintln!(
        "OSX|{}|ktest|focus_after_restart|services=5|ready=1",
        BUILD_ID
    );
    // The lab signs in; the keyboard goes to the compositor.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 1) && r.ends_with(" focus=display")
    });
    if !state_is(&unlocked, "unlocked", 1) {
        kprintln!(
            "OSX|{}|ktest|focus_after_restart|state={}",
            BUILD_ID,
            unlocked
        );
        fail("the lab's sign-in did not unlock the session")
    }
    let r_display =
        match crate::services::request(&h.m.ctl, b"RESTART display", sched::ticks() + 500) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => e.into(),
        };
    let after = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        r.contains(" display=2 ")
    });
    let spy1 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r.ends_with(" connections=2")
    });
    kprintln!(
        "OSX|{}|ktest|focus_after_restart|restarted={}|state={}|spy={}|phase=2|ready=1",
        BUILD_ID,
        r_display,
        after,
        spy1
    );
    if r_display != "OK" || !after.contains(" display=2 ") {
        fail("the compositor did not come back to the session")
    }
    // The lab types `z` once the session has handed the keyboard back.
    let spy2 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r.starts_with("OK keys=2 ")
    });
    let display = svc_connect(&h, "display");
    let keys = display_keys(&display);
    kprintln!(
        "OSX|{}|ktest|focus_after_restart|spy={}|display_keys={}",
        BUILD_ID,
        spy2,
        keys
    );
    if !spy2.starts_with("OK keys=2 ") || keys != 2 {
        fail("a key typed after the compositor's restart did not reach it")
    }
    drop((
        unlocked, r_display, after, spy1, spy2, display, spy, session,
    ));
    display_finish(
        name,
        h,
        "the keyboard went back to the restarted compositor",
    )
}

/// TST-M5-INPUT-NAME-RESERVED (REQ-M5-002; WP-43 finding S-5): the input service keeps the
/// name `display` for the client the manager names `display` (input.md v2.5). The compositor
/// holds it (the setting's `FOCUS display` answered OK); another client — here the test
/// kernel — asks for the same name and is refused, so `FOCUS display` can never hand the
/// keyboard to an impostor; any other name is still granted.
fn input_name_reserved() -> ! {
    let (h, admin, clients, _format) = display_env(
        "input_name_reserved",
        b"/SYSTEM/SVC-DP.TXT",
        &["auth", "input", "display"],
        1,
    );
    let input = svc_connect(&h, "input");
    let taken = cfg_request(&input, b"REGISTER display", None);
    let other = cfg_request(&input, b"REGISTER lab", None);
    kprintln!(
        "OSX|{}|ktest|input_name_reserved|display={}|other_ok={}",
        BUILD_ID,
        taken,
        u8::from(other.starts_with("OK "))
    );
    if taken != "ERR ACCESS" {
        fail("a client the manager does not name display took the name display")
    }
    if !other.starts_with("OK ") {
        fail("the input service refused an ordinary name")
    }
    drop((taken, other, input, clients, admin));
    display_finish(
        "input_name_reserved",
        h,
        "the name display belongs to the compositor alone",
    )
}

/// TST-M5-CLIENT-LIMITS (REQ-M5-003; WP-43 finding S-7): one client holds at most 8 surfaces
/// and 4 windows (`ERR LIMIT` beyond), and clients other than the session never take the last
/// 2 windows or the last 2 surfaces of the compositor (`ERR FULL`), so no application can leave
/// the session without room for its sign-in, lock or elevation screen (display.md v1.9).
fn client_limits() -> ! {
    let (h, admin, clients, format) = display_env(
        "client_limits",
        b"/SYSTEM/SVC-DP.TXT",
        &["auth", "input", "display"],
        4,
    );
    let mut ev = Vec::new();
    let mut vmos = Vec::new();
    // A new 32x32 surface for client `c`; its id, or the refusal.
    let mut surface = |c: &Endpoint, ev: &mut Vec<String>| -> String {
        let (vmo, entry) = kernel_surface(32, 32, format, 0x808080);
        vmos.push(vmo);
        let r = drequest(c, b"CREATE_SURFACE 32 32", alloc::vec![entry], ev);
        String::from(r.strip_prefix("OK ").unwrap_or(&r))
    };
    let window = |c: &Endpoint, sid: &str, ev: &mut Vec<String>| -> String {
        let r = drequest(
            c,
            alloc::format!("CREATE_WINDOW {} w", sid).as_bytes(),
            Vec::new(),
            ev,
        );
        String::from(if r.starts_with("OK ") { "OK" } else { &r })
    };
    let (a, b, c, d) = (&clients[0], &clients[1], &clients[2], &clients[3]);
    // 1. One client: 8 surfaces, then the 9th is refused.
    let sa: Vec<String> = (0..8).map(|_| surface(a, &mut ev)).collect();
    let ninth = surface(a, &mut ev);
    // 2. One client: 4 windows, then the 5th is refused.
    let wa: Vec<String> = sa[..5].iter().map(|s| window(a, s, &mut ev)).collect();
    // 3. The window reserve: b and c take 4 windows each, d takes 2 (14 of 16 in all); d's
    // third, within its own limit, finds only the session's reserve.
    let mut w_rest = Vec::new();
    for (cl, k) in [(b, 4), (c, 4), (d, 3)] {
        for _ in 0..k {
            let s = surface(cl, &mut ev);
            w_rest.push(window(cl, &s, &mut ev));
        }
    }
    // 4. The surface reserve: 8 (a) + 4 + 4 + 3 = 19 surfaces so far; b and c take 4 more each,
    // d 3 more (30 of 32); d's next, its 7th, finds only the session's reserve.
    let mut s_rest = Vec::new();
    for (cl, k) in [(b, 4), (c, 4), (d, 4)] {
        for _ in 0..k {
            s_rest.push(surface(cl, &mut ev));
        }
    }
    let ok_ids = |v: &[String]| v.iter().filter(|s| s.parse::<u32>().is_ok()).count();
    let surfaces_a = ok_ids(&sa);
    let windows_a = wa[..4].iter().filter(|r| *r == "OK").count();
    let fifth = wa[4].clone();
    let windows_rest = w_rest[..10].iter().filter(|r| *r == "OK").count();
    let reserve_window = w_rest[10].clone();
    let surfaces_rest = ok_ids(&s_rest[..11]);
    let reserve_surface = s_rest[11].clone();
    kprintln!(
        "OSX|{}|ktest|client_limits|surfaces_a={}|ninth={}|windows_a={}|fifth={}|windows_rest={}|reserve_window={}|surfaces_rest={}|reserve_surface={}",
        BUILD_ID,
        surfaces_a,
        ninth,
        windows_a,
        fifth,
        windows_rest,
        reserve_window,
        surfaces_rest,
        reserve_surface
    );
    if surfaces_a != 8 || ninth != "ERR LIMIT" || windows_a != 4 || fifth != "ERR LIMIT" {
        fail("one client went past its own limit of surfaces or windows")
    }
    if windows_rest != 10
        || reserve_window != "ERR FULL"
        || surfaces_rest != 11
        || reserve_surface != "ERR FULL"
    {
        fail("clients other than the session took the session's reserve")
    }
    drop((
        sa,
        ninth,
        wa,
        fifth,
        w_rest,
        s_rest,
        reserve_window,
        reserve_surface,
        ev,
    ));
    drop((vmos, clients, admin));
    display_finish(
        "client_limits",
        h,
        "a client holds a bounded share of windows and surfaces, and the session keeps its reserve",
    )
}

/// TST-M5-NARRATOR-AUTHORITY (REQ-M5-005, REQ-M5-006; WP-43 finding M2): the narrator role
/// belongs to the service the manifest names `narrator` (display.md v1.8). In a manifest with
/// no narrator, a client the manager names otherwise (here the test kernel) asks for it and is
/// refused: no application can make itself the listener of the session's announcements. The
/// other half of M2 (no announcement per keystroke in a password field) is checked by
/// TST-M5-AUTH-INPUT-ISOLATED's narrator stream.
fn narrator_authority() -> ! {
    let name = "narrator_authority";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    kprintln!(
        "OSX|{}|ktest|narrator_authority|services=5|ready=1",
        BUILD_ID
    );
    let display = svc_connect(&h, "display");
    let mut ev = Vec::new();
    let asked = drequest(&display, b"NARRATOR", Vec::new(), &mut ev);
    let again = drequest(&display, b"NARRATOR", Vec::new(), &mut ev);
    kprintln!(
        "OSX|{}|ktest|narrator_authority|asked={}|again={}",
        BUILD_ID,
        asked,
        again
    );
    if asked != "ERR ACCESS" || again != "ERR ACCESS" {
        fail("a client the manifest does not name took the narrator role")
    }
    // Everything the test holds goes before the frame balance (the strings live on the heap).
    drop((asked, again, ev, display, session));
    display_finish(
        name,
        h,
        "only the service the manifest names narrator may hear the announcements",
    )
}

/// TST-M5-WINDOW-TITLE (REQ-M5-005; WP-97, display.md v1.14): a window title is the client's
/// data, and the compositor's own narrator line `window "<title>" focused` names in it what
/// would end the title, the line or its direction. SVC-NT.TXT starts auth, input, the
/// compositor and the narrator and no client of the compositor, so every narrator line is the
/// compositor's; the host checks the transcript (platform/pc-qemu/expect/window-title.txt)
/// line for line. One client opens four windows (each focused when created, each announced
/// once), then renames and raises them in turn, each raise announced once; the last focused
/// window is closed last, after the others, so no close moves the focus to a window that
/// would be announced again.
fn window_title() -> ! {
    let name = "window_title";
    let (h, admin, clients, format) = display_env(
        name,
        b"/SYSTEM/SVC-NT.TXT",
        &["auth", "input", "display", "narrator"],
        1,
    );
    kprintln!("OSX|{}|ktest|window_title|services=4|ready=1", BUILD_ID);
    let d = &clients[0];
    let mut ev = Vec::new();
    let mut vmos = Vec::new();
    // A quote that tries to close the title and add an attribute; a control byte and a
    // newline; a bidi override and a line separator; 32 quotes, whose names do not fit.
    let created: [&[u8]; 4] = [
        b"x\" focused role=\"button",
        b"a\x07b\nc",
        "abc\u{202E}def\u{2028}g".as_bytes(),
        &[b'"'; 32],
    ];
    let mut wids = Vec::new();
    let mut replies = Vec::new();
    for t in created {
        let (vmo, entry) = kernel_surface(32, 32, format, 0x808080);
        vmos.push(vmo);
        let r = drequest(d, b"CREATE_SURFACE 32 32", alloc::vec![entry], &mut ev);
        let sid = String::from(r.strip_prefix("OK ").unwrap_or("0"));
        let mut req = alloc::format!("CREATE_WINDOW {} ", sid).into_bytes();
        req.extend_from_slice(t);
        let r = drequest(d, &req, Vec::new(), &mut ev);
        replies.push(if r.starts_with("OK ") { "OK" } else { "ERR" });
        wids.push(String::from(r.strip_prefix("OK ").unwrap_or("0")));
    }
    // Renamed in turn (window k % 4): a lead byte with nothing after it, which a reader
    // decoding UTF-8 would join to the closing quote; an ASCII letter and 16 Arabic letters
    // (33 bytes, cut at TITLE_MAX before the last letter); a plain title, spoken as it always
    // was; DEL, a C1 control (C2 85), U+2029, ALM, RLM, LRE and RLI between letters; 33
    // continuation bytes; `abc` and 40 continuation bytes; exactly 32 ASCII bytes (no cut);
    // 33 ASCII bytes (one cut). Then the storage cut where a whole character ends exactly at
    // TITLE_MAX and a stray byte follows: 30 ASCII bytes, `é` and a continuation byte (the `é`
    // stays); 31 letters and two continuation bytes (the letters and the first stray byte stay);
    // the rest of the bidi set (LRM, RLE, PDF, LRO, LRI, FSI, PDI) between letters; 30 letters,
    // a lead byte, a letter and a continuation byte (the letter stays).
    let mut arabic = alloc::vec![b'A'];
    for _ in 0..16 {
        arabic.extend_from_slice("\u{0628}".as_bytes());
    }
    let mut abc = b"abc".to_vec();
    abc.extend_from_slice(&[0x80; 40]);
    let mut e_acute = b"0123456789abcdefghijklmnopqrst".to_vec();
    e_acute.extend_from_slice(&[0xC3, 0xA9, 0x80]);
    let mut stray = alloc::vec![b'a'; 31];
    stray.extend_from_slice(&[0x80, 0x80]);
    let mut lead = alloc::vec![b'a'; 30];
    lead.extend_from_slice(&[0xE2, b'b', 0x80]);
    let renamed: [&[u8]; 12] = [
        b"ab\xC2",
        &arabic,
        b"Sign in",
        "a\u{7F}b\u{85}c\u{2029}d\u{061C}e\u{200F}f\u{202A}g\u{2067}h".as_bytes(),
        &[0x80; 33],
        &abc,
        b"0123456789abcdefghijklmnopqrstuv",
        b"0123456789abcdefghijklmnopqrstuvw",
        &e_acute,
        &stray,
        "a\u{200E}b\u{202B}c\u{202C}d\u{202D}e\u{2066}f\u{2068}g\u{2069}h".as_bytes(),
        &lead,
    ];
    let mut again = Vec::new();
    for (k, t) in renamed.iter().enumerate() {
        let wid = &wids[k % 4];
        let mut req = alloc::format!("TITLE {} ", wid).into_bytes();
        req.extend_from_slice(t);
        let r1 = drequest(d, &req, Vec::new(), &mut ev);
        let r2 = drequest(
            d,
            alloc::format!("RAISE {}", wid).as_bytes(),
            Vec::new(),
            &mut ev,
        );
        again.push(if r1 == "OK" && r2 == "OK" {
            "OK"
        } else {
            "ERR"
        });
    }
    // The focused window (the fourth) goes last: closing the others moves no focus.
    let mut closed = Vec::new();
    for k in [0, 1, 2, 3] {
        let r = drequest(
            d,
            alloc::format!("CLOSE {}", wids[k]).as_bytes(),
            Vec::new(),
            &mut ev,
        );
        closed.push(if r == "OK" { "OK" } else { "ERR" });
    }
    kprintln!(
        "OSX|{}|ktest|window_title|created={}|renamed={}|closed={}",
        BUILD_ID,
        replies.join(","),
        again.join(","),
        closed.join(",")
    );
    if replies
        .iter()
        .chain(&again)
        .chain(&closed)
        .any(|r| *r != "OK")
    {
        fail("the compositor refused a window, a title, a raise or a close")
    }
    // The narrator writes its lines on its own time: let the last ones reach the serial log
    // before the manager stops it.
    sched::poll_until(sched::ticks() + 1_000, || false);
    drop((
        replies, again, closed, wids, ev, arabic, abc, e_acute, stray, lead,
    ));
    drop((vmos, clients, admin));
    display_finish(
        name,
        h,
        "a window title is spoken between its quotes and never ends its line",
    )
}

/// TST-M5-WINDOW-TITLE-RESIZE (REQ-M5-005, REQ-M5-008; WP-97, display.md v1.14): the other
/// line that carries the title, `window "<title>" resized <w>x<h>` (v1.7), names it too. On
/// SVC-NT.TXT one client opens a 32x32 window titled `x" resized 9x9 role="button` (announced
/// focused); after the ready marker the lab sends Alt+Shift+Right, which widens the focused
/// window by 16 px; the test waits until LIST shows 48x32, closes the window and lets the
/// narrator write. The host checks the transcript (expect/window-title-resize.txt).
fn window_title_resize() -> ! {
    let name = "window_title_resize";
    let (h, admin, clients, format) = display_env(
        name,
        b"/SYSTEM/SVC-NT.TXT",
        &["auth", "input", "display", "narrator"],
        1,
    );
    let d = &clients[0];
    let mut ev = Vec::new();
    let (vmo, entry) = kernel_surface(32, 32, format, 0x808080);
    let surface = drequest(d, b"CREATE_SURFACE 32 32", alloc::vec![entry], &mut ev);
    let sid = String::from(surface.strip_prefix("OK ").unwrap_or("0"));
    let r = drequest(
        d,
        alloc::format!("CREATE_WINDOW {} x\" resized 9x9 role=\"button", sid).as_bytes(),
        Vec::new(),
        &mut ev,
    );
    let wid = String::from(r.strip_prefix("OK ").unwrap_or("0"));
    kprintln!(
        "OSX|{}|ktest|window_title_resize|window={}|services=4|ready=1",
        BUILD_ID,
        if r.starts_with("OK ") { "OK" } else { "ERR" }
    );
    if !r.starts_with("OK ") {
        fail("the compositor refused the window")
    }
    // The lab's Alt+Shift+Right: the window's client area becomes 48x32.
    let deadline = sched::ticks() + 30_000;
    let mut list = String::new();
    while sched::ticks() < deadline {
        list = drequest(d, b"LIST", Vec::new(), &mut ev);
        if list.contains(" 48 32 normal ") {
            break;
        }
        let t = sched::ticks() + 20;
        sched::poll_until(t, || false);
    }
    let resized = list.contains(" 48 32 normal ");
    let closed = drequest(
        d,
        alloc::format!("CLOSE {}", wid).as_bytes(),
        Vec::new(),
        &mut ev,
    );
    kprintln!(
        "OSX|{}|ktest|window_title_resize|resized={}|closed={}",
        BUILD_ID,
        u8::from(resized),
        closed
    );
    if !resized || closed != "OK" {
        fail("the window was not widened by the keyboard or not closed")
    }
    sched::poll_until(sched::ticks() + 1_000, || false);
    // Every reply is dropped before the balance: display_finish never returns, so a value
    // still in scope here would be counted as a frame the test left behind.
    drop((list, closed, wid, sid, surface, r, ev));
    drop((vmo, clients, admin));
    display_finish(
        name,
        h,
        "a window title is spoken between its quotes when the window is resized",
    )
}

/// TST-M5-LOCK-SURVIVES (REQ-M5-006): while locked the compositor is restarted (the
/// manager's RESTART, which closes every channel of the old process as a crash would) and
/// then the input service: the session stays locked and reconnects to both, the restarted
/// compositor shows the lock screen (the lab's screendump) with the spy's new window held
/// back, the spy — focused before the lock — gets no key, the restarted compositor sees no
/// key while locked, a wrong password is refused, and only the right one unlocks; a key
/// after the unlock reaches the spy through the new input service and compositor.
fn lock_survives() -> ! {
    let name = "lock_survives";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    kprintln!("OSX|{}|ktest|lock_survives|services=5|ready=1", BUILD_ID);
    // The lab signs in, then Ctrl+Alt+Del.
    let locked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "locked", 2)
    });
    let spy1 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=2 focus=0 connections=1"
    });
    if !locked.starts_with("OK locked user=admin changes=2 ")
        || spy1 != "OK keys=2 focus=0 connections=1"
    {
        kprintln!(
            "OSX|{}|ktest|lock_survives|locked={}|spy={}",
            BUILD_ID,
            locked,
            spy1
        );
        fail("the secure attention sequence did not lock the session")
    }
    // The compositor goes while locked, then the input service.
    let restart = |what: &[u8]| -> String {
        match crate::services::request(&h.m.ctl, what, sched::ticks() + 500) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => e.into(),
        }
    };
    let r_display = restart(b"RESTART display");
    let after_display = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        r.contains(" display=2 ")
    });
    let r_input = restart(b"RESTART input");
    let after_input = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        r.contains(" input=2 ") && r.ends_with(" focus=session")
    });
    let spy2 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r == "OK keys=2 focus=0 connections=2"
    });
    let lines = h.poll_list(sched::ticks() + 10_000, |l| {
        ["display", "input"].iter().all(|n| {
            l.iter()
                .any(|x| x.name == *n && x.state == "ready" && x.restarts == 1)
        })
    });
    let (d_state, d_restarts, _) = svc_state(&lines, "display");
    let (i_state, i_restarts, _) = svc_state(&lines, "input");
    let display = svc_connect(&h, "display");
    let mut ev = Vec::new();
    let status = drequest(&display, b"STATUS", Vec::new(), &mut ev);
    let windows = String::from(status_field(&status, "windows="));
    kprintln!(
        "OSX|{}|ktest|lock_survives|restarted=display:{}:{}:{},input:{}:{}:{}|state={}|spy={}|windows={}|phase=2|ready=1",
        BUILD_ID,
        r_display,
        d_state,
        d_restarts,
        r_input,
        i_state,
        i_restarts,
        after_input,
        spy2,
        windows
    );
    if r_display != "OK"
        || r_input != "OK"
        || !after_display.starts_with("OK locked ")
        || after_input != "OK locked user=admin changes=2 display=2 input=2 focus=session"
        || spy2 != "OK keys=2 focus=0 connections=2"
        || d_state != "ready"
        || i_state != "ready"
        || d_restarts != 1
        || i_restarts != 1
        || windows != "2"
    {
        fail("the lock did not survive the restart of the compositor and of the input service")
    }
    // The lab: a screendump, a wrong password (refused: still locked), the right one.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 3) && r.ends_with(" focus=display")
    });
    let keys_locked = display_keys(&display);
    let spy3 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=2 focus=1 connections=2"
    });
    kprintln!(
        "OSX|{}|ktest|lock_survives|unlocked={}|display_keys={}|spy={}|phase=3|ready=1",
        BUILD_ID,
        unlocked,
        keys_locked,
        spy3
    );
    if unlocked != "OK unlocked user=admin changes=3 display=2 input=2 focus=display"
        || keys_locked != 0
        || spy3 != "OK keys=2 focus=1 connections=2"
    {
        fail("the passwords typed on the lock screen reached the compositor or the spy")
    }
    // The lab types `z`: through the new input service and compositor to the spy.
    let spy4 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r.starts_with("OK keys=4 ")
    });
    kprintln!("OSX|{}|ktest|lock_survives|spy={}", BUILD_ID, spy4);
    if spy4 != "OK keys=4 focus=1 connections=2" {
        fail("keys did not reach the spy after the unlock")
    }
    drop((
        locked,
        spy1,
        r_display,
        after_display,
        r_input,
        after_input,
        spy2,
        lines,
        d_state,
        i_state,
        status,
        windows,
        ev,
        unlocked,
        spy3,
        spy4,
        display,
        spy,
        session,
    ));
    display_finish(
        name,
        h,
        "the lock survived the restart of the compositor and of the input service, and only the right password opened it",
    )
}

/// TST-M5-LOCK-HANG (REQ-M5-010, services.md v1.7, §8.7, §20 scenario 8): the compositor and
/// the input service are watchdog-monitored (`watchdog=200`, `on-failure`). While the session is
/// locked the test wedges the live compositor — `sched::freeze_named(b"DISPLAYD.ELF")`, after
/// which its threads are never woken, as a deadlocked compositor that stops turning its event
/// loop — and, once it is back, the live input service the same way (`INPUTD.ELF`). For each,
/// the manager's watchdog alone (no RESTART driven by the test) must miss the PONG, force-kill
/// it (EXIT_KILLED) and restart it once (restarts=1). Throughout, the lock holds: the session
/// reconnects to the new compositor (`display=2`) and to the new input service (`input=2`) still
/// locked with the keyboard (`focus=session`), the spy focused before the lock gets no key, the
/// restarted compositor sees none while locked, a wrong password typed through the restarted
/// input service is refused and only the right one unlocks, and a key after the unlock reaches
/// the spy through both new services. The session's and the spy's traces equal
/// platform/pc-qemu/expect/lock-hang.txt; the password never reaches the log.
fn lock_hang() -> ! {
    const EXIT_KILLED: u64 = 0x2_0000;
    let name = "lock_hang";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-LH.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    kprintln!("OSX|{}|ktest|lock_hang|services=5|ready=1", BUILD_ID);
    // The lab signs in, then Ctrl+Alt+Del (the spy, focused, counts the Ctrl and Alt presses).
    let locked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "locked", 2)
    });
    let spy1 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=2 focus=0 connections=1"
    });
    if !locked.starts_with("OK locked user=admin changes=2 ")
        || spy1 != "OK keys=2 focus=0 connections=1"
    {
        kprintln!(
            "OSX|{}|ktest|lock_hang|locked={}|spy={}",
            BUILD_ID,
            locked,
            spy1
        );
        fail("the secure attention sequence did not lock the session")
    }
    // Healthy so far: the watchdog has touched neither component, so each restart counted below
    // is the freeze's own, not a spurious one (review 2026-10-19, T2).
    let pre = h.poll_list(sched::ticks(), |_| true);
    let (pd, pi) = (svc_find(&pre, "display"), svc_find(&pre, "input"));
    kprintln!(
        "OSX|{}|ktest|lock_hang|before_freeze=display:{}:{}|input:{}:{}",
        BUILD_ID,
        pd.state,
        pd.restarts,
        pi.state,
        pi.restarts
    );
    if pd.state != "ready" || pd.restarts != 0 || pi.state != "ready" || pi.restarts != 0 {
        fail("a watchdog-monitored component was restarted before any freeze")
    }
    drop((pre, pd, pi));
    // Wedge the live compositor: it stays blocked in `object_wait_many`, so it never answers the
    // watchdog's PING. The manager — not the test — must notice and restart it.
    let frozen = sched::freeze_named(b"DISPLAYD.ELF");
    // The watchdog force-kills the hung compositor and the restart policy brings it back once.
    let lines = h.poll_list(sched::ticks() + 120_000, |l| {
        l.iter()
            .any(|x| x.name == "display" && x.state == "ready" && x.restarts == 1)
    });
    let dline = lines
        .iter()
        .find(|l| l.name == "display")
        .cloned()
        .unwrap_or_default();
    // The session reconnects to the new compositor while still locked; input is untouched so far.
    let after = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        r.contains(" display=2 ") && r.ends_with(" focus=session")
    });
    let spy2 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r == "OK keys=2 focus=0 connections=2"
    });
    let display = svc_connect(&h, "display");
    let mut ev = Vec::new();
    let status = drequest(&display, b"STATUS", Vec::new(), &mut ev);
    let windows = String::from(status_field(&status, "windows="));
    kprintln!(
        "OSX|{}|ktest|lock_hang|frozen={}|killed=display:{}:{}:{:#x}|state={}|spy={}|windows={}|phase=2|ready=1",
        BUILD_ID,
        u8::from(frozen),
        dline.state,
        dline.restarts,
        dline.exit.unwrap_or(0),
        after,
        spy2,
        windows
    );
    if !frozen
        || dline.state != "ready"
        || dline.restarts != 1
        || dline.exit != Some(EXIT_KILLED)
        || after != "OK locked user=admin changes=2 display=2 input=1 focus=session"
        || spy2 != "OK keys=2 focus=0 connections=2"
        || windows != "2"
    {
        fail(
            "the watchdog did not force-kill and restart the wedged compositor while the lock held",
        )
    }
    // Now wedge the live input service the same way. While it is frozen no key can be routed;
    // the watchdog must notice, force-kill it and restart it, and the session must take the
    // keyboard back from the new input service while still locked.
    let frozen_in = sched::freeze_named(b"INPUTD.ELF");
    let lines_in = h.poll_list(sched::ticks() + 120_000, |l| {
        l.iter()
            .any(|x| x.name == "input" && x.state == "ready" && x.restarts == 1)
    });
    let iline = lines_in
        .iter()
        .find(|l| l.name == "input")
        .cloned()
        .unwrap_or_default();
    let dline2 = lines_in
        .iter()
        .find(|l| l.name == "display")
        .cloned()
        .unwrap_or_default();
    let after_in = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        r.contains(" input=2 ") && r.ends_with(" focus=session")
    });
    let spy_in = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=2 focus=0 connections=2"
    });
    kprintln!(
        "OSX|{}|ktest|lock_hang|frozen={}|killed=input:{}:{}:{:#x}|display_restarts={}|state={}|spy={}|phase=3|ready=1",
        BUILD_ID,
        u8::from(frozen_in),
        iline.state,
        iline.restarts,
        iline.exit.unwrap_or(0),
        dline2.restarts,
        after_in,
        spy_in
    );
    if !frozen_in
        || iline.state != "ready"
        || iline.restarts != 1
        || iline.exit != Some(EXIT_KILLED)
        || dline2.restarts != 1
        || after_in != "OK locked user=admin changes=2 display=2 input=2 focus=session"
        || spy_in != "OK keys=2 focus=0 connections=2"
    {
        fail("the watchdog did not force-kill and restart the wedged input service while the lock held")
    }
    // The lab, through the restarted input service: a wrong password (refused: still locked),
    // then the right one.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 3) && r.ends_with(" focus=display")
    });
    let keys_locked = display_keys(&display);
    let spy3 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=2 focus=1 connections=2"
    });
    kprintln!(
        "OSX|{}|ktest|lock_hang|unlocked={}|display_keys={}|spy={}|phase=4|ready=1",
        BUILD_ID,
        unlocked,
        keys_locked,
        spy3
    );
    if unlocked != "OK unlocked user=admin changes=3 display=2 input=2 focus=display"
        || keys_locked != 0
        || spy3 != "OK keys=2 focus=1 connections=2"
    {
        fail("the passwords typed on the lock screen reached the compositor or the spy")
    }
    // The lab types `z`: through the new input service and the new compositor to the spy.
    let spy4 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r.starts_with("OK keys=4 ")
    });
    kprintln!("OSX|{}|ktest|lock_hang|spy={}", BUILD_ID, spy4);
    if spy4 != "OK keys=4 focus=1 connections=2" {
        fail("keys did not reach the spy after the unlock")
    }
    drop((
        locked, spy1, lines, dline, after, spy2, status, windows, ev, lines_in, iline, dline2,
        after_in, spy_in, unlocked, spy3, spy4, display, spy, session,
    ));
    display_finish(
        name,
        h,
        "the watchdog force-killed and restarted the wedged compositor and input service while the lock held, and only the right password opened it",
    )
}

/// TST-M5-LOCK-AUTH-HANG (REQ-M5-010, REQ-M5-006; session.md v1.2, arena review ع3): the lock
/// never waits on auth. Signed in, with the spy's window on the frame, the test freezes the live
/// auth service; the lab's Ctrl+Alt+Del then locks the session at once (STATE answers `locked`
/// within 500 ticks and the frame holds no pixel of the spy's window) while the LOCK the session
/// sent stays unanswered (`AUTH`: waiting=1). Sign out on the lock screen brings the sign-in screen
/// back with auth still frozen (waiting=2: LOCK, LOGOUT). Released, auth answers both and the lab
/// signs in again. Before v1.2 the session waited on auth's answer to LOCK with no deadline, and
/// the desktop stayed on the screen.
fn lock_auth_hang() -> ! {
    const SPY_COLOUR: u32 = 0x2E8B57;
    // The spy's 200×120 client area less the compositor's 12×12 resize grip in its corner.
    const SPY_PIXELS: u64 = 200 * 120 - 12 * 12;
    let name = "lock_auth_hang";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    kprintln!("OSX|{}|ktest|{}|services=5|ready=1", BUILD_ID, name);
    // The lab signs in; the spy's window takes the focus and is composed onto the frame.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 1) && r.ends_with(" focus=display")
    });
    let mut census = frame_census(SPY_COLOUR);
    let until = sched::ticks() + 2_000;
    while census.1 != SPY_PIXELS && sched::ticks() < until {
        let t = sched::ticks() + 20;
        sched::poll_until(t, || false);
        census = frame_census(SPY_COLOUR);
    }
    if !unlocked.starts_with("OK unlocked user=admin changes=1 ") || census.1 != SPY_PIXELS {
        kprintln!(
            "OSX|{}|ktest|{}|unlocked={}|spy_px={}",
            BUILD_ID,
            name,
            unlocked,
            census.1
        );
        fail("the spy's window was not on the screen after the sign-in")
    }
    // Wedge the live auth service: it never reads its channel again until released.
    let frozen = sched::freeze_named(b"AUTHD.ELF");
    kprintln!(
        "OSX|{}|ktest|{}|auth_frozen={}|spy_px_before={}|phase=1|ready=1",
        BUILD_ID,
        name,
        u8::from(frozen),
        census.1
    );
    if !frozen {
        fail("no live auth service to freeze")
    }
    // The lab: Ctrl+Alt+Del. The session locks without auth's answer.
    let locked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "locked", 2)
    });
    let t0 = sched::ticks();
    let again = poll_reply(&session, b"STATE", t0 + 500, |r| state_is(r, "locked", 2));
    let in_time = again == locked && sched::ticks() - t0 < 500;
    let waiting = poll_reply(&session, b"AUTH", sched::ticks() + 500, |r| {
        r == "OK waiting=1 lock_unsent=0"
    });
    let mut at_lock = frame_census(SPY_COLOUR);
    let until = sched::ticks() + 2_000;
    while at_lock.1 != 0 && sched::ticks() < until {
        let t = sched::ticks() + 20;
        sched::poll_until(t, || false);
        at_lock = frame_census(SPY_COLOUR);
    }
    kprintln!(
        "OSX|{}|ktest|{}|locked={}|in_time={}|auth={}|lit={}|spy_px={}|phase=2|ready=1",
        BUILD_ID,
        name,
        locked,
        u8::from(in_time),
        waiting,
        u8::from(at_lock.0 > 0),
        at_lock.1
    );
    if !locked.starts_with("OK locked user=admin changes=2 ")
        || !locked.ends_with(" focus=session")
        || !in_time
        || waiting != "OK waiting=1 lock_unsent=0"
        || at_lock.0 == 0
        || at_lock.1 != 0
    {
        fail("the session did not lock at once while auth hung, or the desktop stayed visible")
    }
    // The lab: Tab, Tab, Enter — Sign out on the lock screen, auth still frozen.
    let out = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "no_session", 3)
    });
    let waiting2 = poll_reply(&session, b"AUTH", sched::ticks() + 500, |r| {
        r == "OK waiting=2 lock_unsent=0"
    });
    kprintln!(
        "OSX|{}|ktest|{}|signed_out={}|auth={}|phase=3",
        BUILD_ID,
        name,
        out,
        waiting2
    );
    if out != "OK no_session user=- changes=3 display=1 input=1 focus=session"
        || waiting2 != "OK waiting=2 lock_unsent=0"
    {
        fail("the sign-out waited on the frozen auth")
    }
    // Released, auth answers the LOCK and the LOGOUT; the session waits for nothing more.
    let thawed = sched::thaw_named(b"AUTHD.ELF");
    let drained = poll_reply(&session, b"AUTH", sched::ticks() + 60_000, |r| {
        r == "OK waiting=0 lock_unsent=0"
    });
    kprintln!(
        "OSX|{}|ktest|{}|auth_released={}|auth={}|phase=4|ready=1",
        BUILD_ID,
        name,
        u8::from(thawed),
        drained
    );
    if !thawed || drained != "OK waiting=0 lock_unsent=0" {
        fail("the released auth did not answer what waited")
    }
    // The lab signs in again through the same auth.
    let back = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 4) && r.ends_with(" focus=display")
    });
    kprintln!("OSX|{}|ktest|{}|signed_in_again={}", BUILD_ID, name, back);
    if !back.starts_with("OK unlocked user=admin changes=4 ") {
        fail("the lab could not sign in again after auth was released")
    }
    drop((
        unlocked, locked, again, waiting, out, waiting2, drained, back, spy, session,
    ));
    display_finish(
        name,
        h,
        "the session locked and signed out at once while auth hung, and auth answered once released",
    )
}

/// TST-M5-UNLOCK-AUTH-HANG (REQ-M5-010, REQ-M5-006; session.md v1.2): an unlock waits for auth's
/// answer without holding anything else. Locked (auth answers the LOCK), the test freezes auth;
/// the lab types the right password: the UNLOCK waits (`AUTH`: waiting=1) for longer than the
/// session's request deadline — the session keeps answering STATE `locked` within 500 ticks, no
/// key reaches the compositor or the spy, and the password is not refused for slowness. Released,
/// auth answers and the same password unlocks; `z` then reaches the spy.
fn unlock_auth_hang() -> ! {
    let name = "unlock_auth_hang";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    let display = svc_connect(&h, "display");
    kprintln!("OSX|{}|ktest|{}|services=5|ready=1", BUILD_ID, name);
    // The lab signs in, then Ctrl+Alt+Del with auth answering: an ordinary lock.
    let locked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "locked", 2)
    });
    let settled = poll_reply(&session, b"AUTH", sched::ticks() + 60_000, |r| {
        r == "OK waiting=0 lock_unsent=0"
    });
    let spy1 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r.starts_with("OK ")
    });
    if !locked.starts_with("OK locked user=admin changes=2 ")
        || settled != "OK waiting=0 lock_unsent=0"
    {
        kprintln!(
            "OSX|{}|ktest|{}|locked={}|auth={}",
            BUILD_ID,
            name,
            locked,
            settled
        );
        fail("the secure attention sequence did not lock the session")
    }
    let keys0 = display_keys(&display);
    let frozen = sched::freeze_named(b"AUTHD.ELF");
    kprintln!(
        "OSX|{}|ktest|{}|auth_frozen={}|phase=1|ready=1",
        BUILD_ID,
        name,
        u8::from(frozen)
    );
    if !frozen {
        fail("no live auth service to freeze")
    }
    // The lab types the right password; the UNLOCK waits on the frozen auth.
    let waiting = poll_reply(&session, b"AUTH", sched::ticks() + 600_000, |r| {
        r == "OK waiting=1 lock_unsent=0"
    });
    // Longer than REQUEST_DEADLINE (5000): the session neither gives up nor stops serving.
    let held_until = sched::ticks() + 6_000;
    let mut slow = 0u32;
    let mut still = String::new();
    while sched::ticks() < held_until {
        let t0 = sched::ticks();
        still = poll_reply(&session, b"STATE", t0 + 500, |r| state_is(r, "locked", 2));
        if !state_is(&still, "locked", 2) || sched::ticks() - t0 >= 500 {
            slow += 1;
        }
        let t = sched::ticks() + 250;
        sched::poll_until(t, || false);
    }
    let waiting_after = poll_reply(&session, b"AUTH", sched::ticks() + 500, |r| {
        r == "OK waiting=1 lock_unsent=0"
    });
    let keys_held = display_keys(&display) - keys0;
    let spy2 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r.starts_with("OK ")
    });
    kprintln!(
        "OSX|{}|ktest|{}|auth={}|held_ticks=6000|slow={}|state={}|auth_after={}|display_keys={}|spy_same={}|phase=2|ready=1",
        BUILD_ID,
        name,
        waiting,
        slow,
        still,
        waiting_after,
        keys_held,
        u8::from(spy2 == spy1)
    );
    if waiting != "OK waiting=1 lock_unsent=0"
        || slow != 0
        || waiting_after != "OK waiting=1 lock_unsent=0"
        || keys_held != 0
        || spy2 != spy1
    {
        fail("the unlock waiting on auth held the session back, or a key left the lock screen")
    }
    // Released, auth answers the waiting UNLOCK: the same password opens the session.
    let thawed = sched::thaw_named(b"AUTHD.ELF");
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        state_is(r, "unlocked", 3) && r.ends_with(" focus=display")
    });
    kprintln!(
        "OSX|{}|ktest|{}|auth_released={}|unlocked={}|phase=3|ready=1",
        BUILD_ID,
        name,
        u8::from(thawed),
        unlocked
    );
    if !thawed || !unlocked.starts_with("OK unlocked user=admin changes=3 ") {
        fail("the released auth's answer did not unlock the session")
    }
    // The lab types `z`: it reaches the spy (its key count grows; the focus alone changed at
    // the unlock).
    let keys = |r: &str| -> i64 {
        r.split(' ')
            .find_map(|f| f.strip_prefix("keys="))
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1)
    };
    let keys2 = keys(&spy2);
    let spy3 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| keys(r) > keys2);
    kprintln!("OSX|{}|ktest|{}|spy_after={}", BUILD_ID, name, spy3);
    if keys(&spy3) <= keys2 {
        fail("keys did not reach the spy after the unlock")
    }
    drop((
        locked,
        settled,
        spy1,
        waiting,
        still,
        waiting_after,
        spy2,
        unlocked,
        spy3,
        display,
        spy,
        session,
    ));
    display_finish(
        name,
        h,
        "the unlock waited for the frozen auth without holding the session, and the same password opened it once auth was released",
    )
}

/// TST-M5-SESSION-HANG (REQ-M5-010, REQ-M5-006; session.md v1.1/v1.2, arena review ع4): a
/// component hangs with the session's request to it in flight. Locked, the test freezes the live
/// compositor (SVC-SG.TXT: watchdog=8000, longer than REQUEST_DEADLINE); the lab's wrong password
/// makes the session redraw its lock screen through it, and that request stays unanswered until
/// the session's deadline (`session|display=timed_out`). Meanwhile the session keeps answering
/// STATE (never later than one deadline), the frame keeps the lock screen and no pixel of the
/// spy's window, and no key reaches the spy. The watchdog then force-kills and restarts the
/// compositor; the session reconnects still locked, and only the right password opens it.
fn session_hang() -> ! {
    const EXIT_KILLED: u64 = 0x2_0000;
    const SPY_COLOUR: u32 = 0x2E8B57;
    let name = "session_hang";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SG.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    kprintln!("OSX|{}|ktest|{}|services=5|ready=1", BUILD_ID, name);
    // The lab signs in, then Ctrl+Alt+Del (the spy, focused, counts the Ctrl and Alt presses).
    let locked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "locked", 2)
    });
    let spy1 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=2 focus=0 connections=1"
    });
    let pre = h.poll_list(sched::ticks(), |_| true);
    let pd = svc_find(&pre, "display");
    if !locked.starts_with("OK locked user=admin changes=2 ")
        || spy1 != "OK keys=2 focus=0 connections=1"
        || pd.state != "ready"
        || pd.restarts != 0
    {
        kprintln!(
            "OSX|{}|ktest|{}|locked={}|spy={}|display={}:{}",
            BUILD_ID,
            name,
            locked,
            spy1,
            pd.state,
            pd.restarts
        );
        fail("the secure attention sequence did not lock a healthy session")
    }
    drop((pre, pd));
    // Wedge the live compositor; the lab then types a wrong password on the lock screen.
    let frozen = sched::freeze_named(b"DISPLAYD.ELF");
    kprintln!(
        "OSX|{}|ktest|{}|display_frozen={}|phase=1|ready=1",
        BUILD_ID,
        name,
        u8::from(frozen)
    );
    if !frozen {
        fail("no live compositor to freeze")
    }
    // Until the watchdog restarts it: every STATE is answered, never later than one request
    // deadline (5000) plus slack, and always `locked`; the frame keeps the lock screen.
    let mut max_rtt = 0u64;
    let mut unlocked_seen = false;
    let mut spy_px = 0u64;
    let until = sched::ticks() + 120_000;
    let restarted = loop {
        let t0 = sched::ticks();
        let st = poll_reply(&session, b"STATE", t0 + 10_000, |r| r.starts_with("OK "));
        max_rtt = max_rtt.max(sched::ticks() - t0);
        if !st.starts_with("OK locked ") {
            unlocked_seen = true;
        }
        spy_px = spy_px.max(frame_census(SPY_COLOUR).1);
        let l = h.poll_list(sched::ticks(), |_| true);
        let d = svc_find(&l, "display");
        if d.state == "ready" && d.restarts == 1 {
            break Some(d);
        }
        if sched::ticks() >= until {
            break None;
        }
        let t = sched::ticks() + 200;
        sched::poll_until(t, || false);
    };
    let Some(dline) = restarted else {
        fail("the watchdog did not restart the wedged compositor")
    };
    // The session reconnects to the new compositor still locked; it holds the lock screen and
    // the spy's window, and has received no key.
    let after = poll_reply(&session, b"STATE", sched::ticks() + 60_000, |r| {
        state_is(r, "locked", 2) && r.ends_with(" focus=session")
    });
    let display = svc_connect(&h, "display");
    let mut ev = Vec::new();
    let mut windows = String::new();
    let until = sched::ticks() + 60_000;
    while sched::ticks() < until {
        let status = drequest(&display, b"STATUS", Vec::new(), &mut ev);
        windows = String::from(status_field(&status, "windows="));
        if windows == "2" {
            break;
        }
        let t = sched::ticks() + 100;
        sched::poll_until(t, || false);
    }
    let keys_new = display_keys(&display);
    let spy2 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r.starts_with("OK ")
    });
    let in_time = max_rtt <= 7_000;
    kprintln!(
        "OSX|{}|ktest|{}|killed=display:{}:{}:{:#x}|state_rtt_ok={}|always_locked={}|spy_px_frozen={}|state={}|windows={}|display_keys={}|spy={}|phase=2|ready=1",
        BUILD_ID,
        name,
        dline.state,
        dline.restarts,
        dline.exit.unwrap_or(0),
        u8::from(in_time),
        u8::from(!unlocked_seen),
        spy_px,
        after,
        windows,
        keys_new,
        spy2
    );
    if dline.exit != Some(EXIT_KILLED)
        || !in_time
        || unlocked_seen
        || spy_px != 0
        || !state_is(&after, "locked", 2)
        || windows != "2"
        || keys_new != 0
        || spy2 != "OK keys=2 focus=0 connections=2"
    {
        kprintln!("OSX|{}|ktest|{}|max_rtt={}", BUILD_ID, name, max_rtt);
        fail("the session did not keep serving and keep the lock while the compositor hung")
    }
    // The lab types the right password: the session opens, through the new compositor.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 3) && r.ends_with(" focus=display")
    });
    let spy3 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=2 focus=1 connections=2"
    });
    kprintln!(
        "OSX|{}|ktest|{}|unlocked_ok={}|spy={}|phase=3|ready=1",
        BUILD_ID,
        name,
        u8::from(unlocked.starts_with("OK unlocked user=admin changes=3 ")),
        spy3
    );
    if !unlocked.starts_with("OK unlocked user=admin changes=3 ")
        || spy3 != "OK keys=2 focus=1 connections=2"
    {
        fail("only the right password was to open the session, and no typed key was to reach the spy")
    }
    // The lab types `z`: it reaches the spy through the new compositor.
    let spy4 = poll_reply(&spy, b"COUNT", sched::ticks() + 60_000, |r| {
        r.starts_with("OK keys=4 ")
    });
    kprintln!("OSX|{}|ktest|{}|spy={}", BUILD_ID, name, spy4);
    if spy4 != "OK keys=4 focus=1 connections=2" {
        fail("keys did not reach the spy after the unlock")
    }
    drop((
        dline, locked, spy1, after, display, ev, windows, spy2, unlocked, spy3, spy4, spy, session,
    ));
    display_finish(
        name,
        h,
        "with its request to the hung compositor in flight the session kept serving and the lock held; only the right password opened it",
    )
}

/// The frame as the kernel reads it back: (pixels not black, pixels of `rgb`) over the visible
/// area (the stride's padding is skipped).
fn frame_census(rgb: u32) -> (u64, u64) {
    let Some(d) = crate::display::info() else {
        return (0, 0);
    };
    let want = crate::display::pixel(d.pixel_format, rgb) & 0x00FF_FFFF;
    let (mut lit, mut of) = (0u64, 0u64);
    for y in 0..d.height {
        let line = d.virt + u64::from(y) * u64::from(d.pitch_px) * 4;
        for x in 0..d.width {
            let v = crate::arch::mmio::read32(line + u64::from(x) * 4) & 0x00FF_FFFF;
            if v != 0 {
                lit += 1;
            }
            if v == want {
                of += 1;
            }
        }
    }
    (lit, of)
}

/// TST-M5-LOCK-DISPLAY-DOWN (REQ-M5-010, REQ-M5-006; M5 pre-gate review, M5): the session locks
/// while the compositor is down and never comes back (SVC-SS.TXT: `never`). The lab signs in and
/// the spy's window is on the frame; the test stops the compositor (the manager's STOP: its
/// process ends, no restart). Nothing draws any more, and the kernel clears the frame when the
/// last VMO over it goes (display.md v1.5): no pixel is lit, the spy's window is gone from the
/// screen. Ctrl+Alt+Del then locks the session — input alone carries it — and the frame stays
/// black; the lab's screendump shows black at the spy's place and where the lock dialog would be,
/// and a second Ctrl+Alt+Del (the input service counts it) leaves it locked and black. Without the
/// clear, the stopped compositor's last picture — the user's windows — stays on the screen
/// through the lock.
fn lock_display_down() -> ! {
    const SPY_COLOUR: u32 = 0x2E8B57;
    // The spy's 200×120 client area less the compositor's 12×12 resize grip in its corner.
    const SPY_PIXELS: u64 = 200 * 120 - 12 * 12;
    let name = "lock_display_down";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let spy = svc_connect(&h, "spy");
    kprintln!("OSX|{}|ktest|{}|services=5|ready=1", BUILD_ID, name);
    // The lab signs in; the spy's window takes the focus and is composed onto the frame.
    let unlocked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "unlocked", 1) && r.ends_with(" focus=display")
    });
    let spy1 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r == "OK keys=0 focus=1 connections=1"
    });
    let mut census = frame_census(SPY_COLOUR);
    let until = sched::ticks() + 2_000;
    while census.1 != SPY_PIXELS && sched::ticks() < until {
        let t = sched::ticks() + 20;
        sched::poll_until(t, || false);
        census = frame_census(SPY_COLOUR);
    }
    kprintln!(
        "OSX|{}|ktest|{}|unlocked={}|spy={}|lit_before={}|spy_px_before={}|phase=1",
        BUILD_ID,
        name,
        unlocked,
        spy1,
        u8::from(census.0 > 0),
        census.1
    );
    if !unlocked.starts_with("OK unlocked user=admin changes=1 ")
        || spy1 != "OK keys=0 focus=1 connections=1"
        || census.1 != SPY_PIXELS
    {
        fail("the spy's window was not on the screen after the sign-in")
    }
    // The compositor goes for good: its process ends and the manager does not start it again.
    let clears0 = crate::display::clears();
    let r_stop = match crate::services::request(&h.m.ctl, b"STOP display", sched::ticks() + 500) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => String::from(e),
    };
    let lines = h.poll_list(sched::ticks() + 10_000, |l| {
        l.iter()
            .any(|x| x.name == "display" && x.state == "stopped")
    });
    let d = svc_find(&lines, "display");
    let stopped = frame_census(SPY_COLOUR);
    let clears = crate::display::clears() - clears0;
    kprintln!(
        "OSX|{}|ktest|{}|stopped={}|display={}:{}|clears={}|lit={}|spy_px={}|phase=2|ready=1",
        BUILD_ID,
        name,
        r_stop,
        d.state,
        d.restarts,
        clears,
        stopped.0,
        stopped.1
    );
    if r_stop != "OK" || d.state != "stopped" || clears != 1 || stopped != (0, 0) {
        fail("the stopped compositor's last picture stayed on the screen")
    }
    // The lab: Ctrl+Alt+Del. The input service gives the sequence to the session, which locks
    // with no compositor to tell; nothing may draw the user's windows again.
    let locked = poll_reply(&session, b"STATE", sched::ticks() + 600_000, |r| {
        state_is(r, "locked", 2)
    });
    let spy2 = poll_reply(&spy, b"COUNT", sched::ticks() + 10_000, |r| {
        r.starts_with("OK ")
    });
    let at_lock = frame_census(SPY_COLOUR);
    kprintln!(
        "OSX|{}|ktest|{}|locked={}|spy_keys0={}|lit={}|spy_px={}|phase=3|ready=1",
        BUILD_ID,
        name,
        locked,
        u8::from(spy2.starts_with("OK keys=0 ")),
        at_lock.0,
        at_lock.1
    );
    if !locked.starts_with("OK locked user=admin changes=2 ")
        || !locked.ends_with(" focus=session")
        || !spy2.starts_with("OK keys=0 ")
        || at_lock != (0, 0)
    {
        fail("the session did not lock with the compositor down, or the screen showed something")
    }
    // The lab's screendump, then Ctrl+Alt+Del once more: the input service counts the second
    // sequence (`saks=2`), so the screendump is taken; the session stays locked, the frame black.
    let input = svc_connect(&h, "input");
    let mut status = cfg_request(&input, b"STATUS", None);
    let until = sched::ticks() + 600_000;
    while !status.contains(" saks=2") && sched::ticks() < until {
        let t = sched::ticks() + 20;
        sched::poll_until(t, || false);
        status = cfg_request(&input, b"STATUS", None);
    }
    let still = cfg_request(&session, b"STATE", None);
    let after = frame_census(SPY_COLOUR);
    kprintln!(
        "OSX|{}|ktest|{}|saks2={}|state={}|lit={}|spy_px={}|phase=4",
        BUILD_ID,
        name,
        u8::from(status.contains(" saks=2")),
        still,
        after.0,
        after.1
    );
    if !status.contains(" saks=2") || still != locked || after != (0, 0) {
        fail("the lock did not hold with the compositor down, or something drew on the screen")
    }
    drop((
        unlocked, spy1, r_stop, lines, d, locked, spy2, status, still, input, spy, session,
    ));
    display_finish(
        name,
        h,
        "with the compositor stopped the frame went black and the session locked with nothing on the screen",
    )
}

// ---- WP-67: the compositor's hold fails closed ----------------------------------------------

/// What one sub-case of `hold_fail_closed` saw: the `HOLDS` reply (`-` when the compositor
/// never said READY), the `CREATE_WINDOW` reply, the keys the compositor counted (`KEYS`) and
/// those that reached the application (-1: not asked), and the exit code — 0 after `STOP`,
/// EXIT_KILLED when the compositor no longer read its boot channel and had to be killed.
struct HoldCase {
    holds: String,
    window: String,
    keys_in: i64,
    keys_at_client: i64,
    exit: u64,
    /// Whether the compositor said READY after the `LIST` answer (WP-77).
    ready: bool,
    /// Whether a `PING` sent after READY was answered `PONG` (-1: not asked; WP-77).
    pong: i64,
}

/// What a sub-case of `hold_run` adds to the plain start-up (WP-77, display.md v1.13), and the
/// test whose lines it prints: `before_answer` goes on the boot channel after `LIST` and before
/// its answer; with `answer_ends` the answer is the manager's last message (a `STOP` in place
/// of the listing), and the sub-case only waits for the compositor to end, seeing whether it
/// said READY first; `after_ready` goes on the boot channel once READY has come, and with
/// `ping` a `PING` follows, whose `PONG` must come back before the application connects.
struct HoldInject<'a> {
    test: &'a str,
    before_answer: Option<&'a [u8]>,
    answer_ends: bool,
    after_ready: Option<&'a [u8]>,
    ping: bool,
    /// `STOP` in place of the answer to `CONNECT input`; the sub-case then only waits for the
    /// compositor to end, seeing whether it said READY first.
    stop_at_connect: bool,
}

/// `hold_fail_closed`'s sub-cases: the start-up as the manager runs it, nothing added.
const HOLD_PLAIN: HoldInject<'static> = HoldInject {
    test: "hold_fail_closed",
    before_answer: None,
    answer_ends: false,
    after_ready: None,
    ping: false,
    stop_at_connect: false,
};

impl HoldCase {
    /// Started held: `HOLDS` says so, the window exists, both keys reached the compositor and
    /// none reached the application, and `STOP` ended it.
    fn held(&self) -> bool {
        self.holds == "OK locked=1 releases=0"
            && self.window.starts_with("OK ")
            && self.keys_in == 2
            && self.keys_at_client == 0
            && self.exit == 0
    }
}

/// Ticks one sub-case may take up to its `STOP`; then at most `HOLD_STOP` for `STOP` and as
/// much again for a kill. Five sub-cases: at most 5 × 9 s = 45 s, inside the lab's 60 s
/// (WP-64, 2026-11-10: 23 s -> 9 s per sub-case with the lab's 180 s -> 60 s; the whole case
/// took 8 s on CI run 42696067096; a hang guard of a done test, no oracle change).
const HOLD_BUDGET: u64 = 5000;
const HOLD_STOP: u64 = 2000;
/// The longest any single request waits for its reply (capped by the sub-case's budget).
const HOLD_REQUEST: u64 = 5000;

/// Waits until `pred` holds or `deadline`, competing at the boot thread's own priority 1, the
/// compositor's: `sched::poll_until` demotes the waiter to the lowest priority until its
/// deadline, and a compositor spinning on a jammed boot channel (the fault before display.md
/// v1.12) then starves it on their shared CPU until that deadline (before WP-99: for ever; CI
/// run 42685537720 hung in `too_long`), so `pred` would be read once, at the end. At equal
/// priority the timer's slices alternate the two (TST-M2-PREEMPT): `pred` is polled all along.
fn hold_wait(deadline: u64, mut pred: impl FnMut() -> bool) -> bool {
    loop {
        if pred() {
            return true;
        }
        if sched::ticks() >= deadline {
            return false;
        }
        if !sched::yield_now() {
            context::idle_wait();
        }
    }
}

/// Reads the next message on `ep` until `deadline`; `None` on a timeout or a closed peer.
fn hold_recv(ep: &Endpoint, deadline: u64) -> Option<Message> {
    let mut got = None;
    hold_wait(deadline, || {
        match ep.read(channel::MSG_MAX_BYTES, channel::MSG_MAX_HANDLES, None) {
            Ok(m) => {
                got = Some(m);
                true
            }
            Err(ChannelError::PeerClosed) => true,
            Err(_) => false,
        }
    });
    got
}

/// A request to the compositor as an application, answered by `deadline` (events that come
/// first go to `events`); `error:K_E_SVC_TIMEOUT` past it.
fn hold_request(
    ep: &Endpoint,
    req: &[u8],
    handles: Vec<Entry>,
    events: &mut Vec<String>,
    deadline: u64,
) -> String {
    let msg = Message {
        bytes: req.to_vec(),
        handles,
    };
    if ep.write(msg).is_err() {
        return String::from("error:K_E_SVC_WRITE");
    }
    loop {
        match hold_recv(ep, deadline) {
            Some(m) => {
                let text = String::from_utf8_lossy(&m.bytes).into_owned();
                if text.starts_with("OK") || text.starts_with("ERR") {
                    return text;
                }
                events.push(text);
            }
            None if sched::ticks() >= deadline => return String::from("error:K_E_SVC_TIMEOUT"),
            None => return String::from("error:K_E_SVC_PEER_CLOSED"),
        }
    }
}

/// The substitute manager's side of one compositor start-up: a fresh /SYSTEM/DISPLAYD.ELF with
/// the boot channel and the display as its first two handles (as the manager hands them,
/// services.md), `START`, then `CONNECT input` answered with a channel the test keeps (the
/// fake input service, which must see `REGISTER display`); then `answer` goes back for `LIST`
/// — or, with `None`, the boot channel is closed instead. When the compositor says READY, the
/// test connects as an application (`CONNECT app` with the server end, as the manager hands
/// clients), asks `HOLDS`, creates a window and sends two key events on the fake input
/// channel; the keys the compositor counted and those that reached the application are
/// recorded. Last, `STOP`. Every wait is bounded (`HOLD_BUDGET`, `HOLD_REQUEST`, `HOLD_STOP`):
/// a step that times out is recorded as `error:K_E_STUCK_<step>` or `error:K_E_SVC_TIMEOUT`,
/// and a compositor that has not ended after `STOP` is killed (EXIT_KILLED), so a jammed
/// compositor costs the sub-case its verdict, never the run. `inj` adds WP-77's injections
/// (`HoldInject`; `HOLD_PLAIN` for none) and names the test whose lines are printed.
fn hold_run(case: &str, image: &[u8], answer: Option<&[u8]>, inj: &HoldInject) -> HoldCase {
    let display = crate::display::display_object().unwrap_or_else(|| fail("no display object"));
    let chan_entry = |ep: Arc<Endpoint>| Entry {
        object: Object::Channel(ep),
        rights: Rights::CHANNEL_DEFAULT,
    };
    let note = |bytes: &[u8]| Message {
        bytes: bytes.to_vec(),
        handles: Vec::new(),
    };
    let (ours, theirs) = channel::create();
    let object = Arc::new(crate::object::process::ProcessObject::new());
    let initial = alloc::vec![
        chan_entry(theirs),
        Entry {
            object: Object::Display(display),
            rights: Rights::DISPLAY_DEFAULT,
        },
    ];
    let pid = match crate::user::spawn_elf_with(image, 1, initial, object.clone()) {
        Ok(p) => p,
        Err(e) => {
            kprintln!(
                "OSX|{}|ktest|{}|case={}|error={}",
                BUILD_ID,
                inj.test,
                case,
                e.code()
            );
            fail("the compositor did not load")
        }
    };
    let budget = sched::ticks() + HOLD_BUDGET;
    let within = |cap: u64| (sched::ticks() + cap).min(budget);
    let mut out = HoldCase {
        holds: String::from("-"),
        window: String::from("-"),
        keys_in: -1,
        keys_at_client: -1,
        exit: u64::MAX,
        ready: false,
        pong: -1,
    };
    let (input, input_far) = channel::create();
    let (client, client_far) = channel::create();
    let mut ev = Vec::new();
    let mut surface = None;
    // The start-up, up to LIST; the first step that does not happen in time names the sub-case.
    let stuck = if ours.write(note(b"START")).is_err() {
        Some("start")
    } else if !hold_recv(&ours, budget).is_some_and(|m| m.bytes == b"CONNECT input") {
        Some("connect_input")
    } else if inj.stop_at_connect {
        None
    } else if ours
        .write(Message {
            bytes: b"OK".to_vec(),
            handles: alloc::vec![chan_entry(input_far)],
        })
        .is_err()
    {
        Some("input_answer")
    } else if !hold_recv(&input, budget).is_some_and(|m| m.bytes == b"REGISTER display") {
        Some("register")
    } else if !hold_recv(&ours, budget).is_some_and(|m| m.bytes == b"LIST") {
        // The fonts load between the registration and LIST (display.md, text.md §1).
        Some("list")
    } else {
        None
    };
    let mut ours = Some(ours);
    if let Some(step) = stuck {
        kprintln!(
            "OSX|{}|ktest|{}|case={}|stuck_at={}",
            BUILD_ID,
            inj.test,
            case,
            step
        );
        out.holds = alloc::format!("error:K_E_STUCK_{}", step);
    } else if inj.stop_at_connect {
        // STOP in place of the CONNECT input answer: no READY may follow, only the end.
        let boot = ours.as_ref().expect("boot channel kept");
        out.ready = boot.write(note(b"STOP")).is_ok()
            && hold_recv(boot, budget).is_some_and(|m| m.bytes == b"READY");
    } else if let Some(answer) = answer {
        let boot = ours.as_ref().expect("boot channel kept");
        let sent = inj
            .before_answer
            .is_none_or(|m| boot.write(note(m)).is_ok())
            && boot.write(note(answer)).is_ok();
        let ready = sent && hold_recv(boot, within(10_000)).is_some_and(|m| m.bytes == b"READY");
        out.ready = ready;
        if ready && !inj.answer_ends {
            // After READY: the injected message, then the watchdog's PING (services.md v1.7).
            let injected = inj.after_ready.is_none_or(|m| boot.write(note(m)).is_ok());
            if inj.ping {
                out.pong = i64::from(
                    injected
                        && boot.write(note(b"PING")).is_ok()
                        && hold_recv(boot, within(HOLD_REQUEST))
                            .is_some_and(|m| m.bytes == b"PONG"),
                );
            }
        }
        let connect = Message {
            bytes: b"CONNECT app".to_vec(),
            handles: alloc::vec![chan_entry(client_far)],
        };
        out.holds = if inj.answer_ends {
            // The answer was the last word: no CONNECT, no STOP; the compositor ends by itself.
            String::from("-")
        } else if !ready {
            String::from("error:K_E_STUCK_ready")
        } else if boot.write(connect).is_err() {
            String::from("error:K_E_SVC_WRITE")
        } else {
            hold_request(&client, b"HOLDS", Vec::new(), &mut ev, within(HOLD_REQUEST))
        };
    } else {
        // Branch (2): the channel closes with LIST unanswered; READY cannot be said (0xE6).
        drop(ours.take());
        hold_wait(budget, || object.exit_code().is_some());
    }
    if out.holds.starts_with("OK ") {
        let status = hold_request(
            &client,
            b"STATUS",
            Vec::new(),
            &mut ev,
            within(HOLD_REQUEST),
        );
        let format: u32 = status_field(&status, "format=").parse().unwrap_or(1);
        let (vmo, entry) = kernel_surface(64, 48, format, 0x3366CC);
        surface = Some(vmo);
        let r = hold_request(
            &client,
            b"CREATE_SURFACE 64 48",
            alloc::vec![entry],
            &mut ev,
            within(HOLD_REQUEST),
        );
        let sid = String::from(r.strip_prefix("OK ").unwrap_or("0"));
        out.window = hold_request(
            &client,
            alloc::format!("CREATE_WINDOW {} hold", sid).as_bytes(),
            Vec::new(),
            &mut ev,
            within(HOLD_REQUEST),
        );
        // Two key events from the fake input service (input.md's `KEY` form). The compositor
        // forwards a key to the focused window's owner as it counts it, so once `KEYS` says 2
        // any forwarded key is already queued ahead of that reply on the client's channel.
        for k in [&b"KEY 0x1e down 0 a"[..], &b"KEY 0x1e up 0 a"[..]] {
            let _ = input.write(note(k));
        }
        let keys_by = within(HOLD_REQUEST);
        loop {
            let r = hold_request(&client, b"KEYS", Vec::new(), &mut ev, keys_by);
            out.keys_in = r
                .strip_prefix("OK ")
                .and_then(|v| v.parse().ok())
                .unwrap_or(-1);
            if out.keys_in >= 2 || !r.starts_with("OK") || sched::ticks() >= keys_by {
                break;
            }
            hold_wait((sched::ticks() + 20).min(keys_by), || false);
        }
        while let Ok(m) = client.read(channel::MSG_MAX_BYTES, channel::MSG_MAX_HANDLES, None) {
            ev.push(String::from_utf8_lossy(&m.bytes).into_owned());
        }
        out.keys_at_client = ev.iter().filter(|e| e.starts_with("KEY ")).count() as i64;
    }
    if let Some(boot) = ours
        .as_ref()
        .filter(|_| !inj.answer_ends && !inj.stop_at_connect)
    {
        let _ = boot.write(note(b"STOP"));
    }
    if !hold_wait(sched::ticks() + HOLD_STOP, || object.exit_code().is_some()) {
        // A compositor that left an oversized message at the head of its boot channel (the
        // fault before v1.12) never reads STOP; one stuck in its start-up never got that far.
        sched::kill_process(pid, crate::syscall::EXIT_KILLED);
        hold_wait(sched::ticks() + HOLD_STOP, || object.exit_code().is_some());
    }
    out.exit = object.exit_code().unwrap_or(u64::MAX);
    drop((client, input, ours, ev, surface, object));
    out
}

/// TST-M6-HOLD-FAIL-CLOSED (REQ-M6-002, display.md v1.12): the compositor's hold fails
/// closed. The test kernel plays the service manager for a fresh /SYSTEM/DISPLAYD.ELF per
/// sub-case and answers its `LIST`: (a) `reply` — with `ERR TEST`; (b) `too_long` — with 2000
/// bytes (a `display` line, no `session` line) that cannot fit the compositor's 1024-byte
/// buffer; (c) `closed` — by closing the boot channel; (d) `manifest` — with a listing naming
/// `display` and no `session` (starts unheld, v1.2, and a key reaches the application, which
/// shows the key check can see one), then one naming `session` too (starts held). In (a) and
/// (b) the screen must start held (`HOLDS` → `OK locked=1 releases=0`) and no key may reach
/// the application; in (c) the compositor exits 0xE6. The compositor's own trace line
/// (`display|hold|…`) is on the serial log before each sub-case's line; the host checks it.
/// Every compositor is gone at the end, with the object and frame balance restored.
fn hold_fail_closed() -> ! {
    let name = "hold_fail_closed";
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    // The display object is created once and kept by the kernel; take it before the balance.
    if crate::display::display_object().is_none() {
        fail("no display object (firmware left no linear frame buffer)")
    }
    let obj0 = object::stats();
    let frames0 = pmm::stats().free_frames;
    let image = match crate::loader::read_image(b"/SYSTEM/DISPLAYD.ELF") {
        Ok(i) => i,
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|image_error={}", BUILD_ID, name, e.code());
            fail("the compositor's image is not on the volume")
        }
    };
    // (b): longer than the compositor's 1024-byte buffer, shorter than a message's 4096.
    let mut long = Vec::from(&b"display ready 0 1 1 - -\n"[..]);
    let mut k = 0;
    while long.len() < 2000 {
        long.extend_from_slice(alloc::format!("fill{:02} ready 0 1 1 - -\n", k).as_bytes());
        k += 1;
    }
    let reply = hold_run("reply", &image, Some(b"ERR TEST"), &HOLD_PLAIN);
    let reply_ok = reply.held();
    kprintln!(
        "OSX|{}|ktest|{}|case=reply|holds={}|keys={}|keys_in={}|window={}|exit={:#x}|ok={}",
        BUILD_ID,
        name,
        reply.holds,
        reply.keys_at_client,
        reply.keys_in,
        reply.window,
        reply.exit,
        u8::from(reply_ok)
    );
    drop(reply);
    let too_long = hold_run("too_long", &image, Some(&long), &HOLD_PLAIN);
    let too_long_ok = too_long.held();
    kprintln!(
        "OSX|{}|ktest|{}|case=too_long|holds={}|keys={}|keys_in={}|window={}|bytes={}|exit={:#x}|ok={}",
        BUILD_ID,
        name,
        too_long.holds,
        too_long.keys_at_client,
        too_long.keys_in,
        too_long.window,
        long.len(),
        too_long.exit,
        u8::from(too_long_ok)
    );
    drop((too_long, long));
    let closed = hold_run("closed", &image, None, &HOLD_PLAIN);
    let closed_ok = closed.exit == 0xE6;
    kprintln!(
        "OSX|{}|ktest|{}|case=closed|holds=none_no_ready|exit={:#x}|ok={}",
        BUILD_ID,
        name,
        closed.exit,
        u8::from(closed_ok)
    );
    drop(closed);
    let open = hold_run(
        "manifest",
        &image,
        Some(b"auth ready 0 1 1 - -\ninput ready 0 1 1 - -\ndisplay ready 0 1 1 - -\n"),
        &HOLD_PLAIN,
    );
    let held = hold_run(
        "manifest_session",
        &image,
        Some(b"auth ready 0 1 1 - -\ninput ready 0 1 1 - -\ndisplay ready 0 1 1 - -\nsession starting 0 1 - - -\n"),
        &HOLD_PLAIN,
    );
    let open_ok = open.holds == "OK locked=0 releases=0"
        && open.window.starts_with("OK ")
        && open.keys_in == 2
        && open.keys_at_client == 2
        && open.exit == 0;
    let manifest_ok = open_ok && held.held();
    kprintln!(
        "OSX|{}|ktest|{}|case=manifest|locked={}|locked_with_session={}|keys={}|keys_with_session={}|exit={:#x}:{:#x}|ok={}",
        BUILD_ID,
        name,
        status_field(&open.holds, "locked="),
        status_field(&held.holds, "locked="),
        open.keys_at_client,
        held.keys_at_client,
        open.exit,
        held.exit,
        u8::from(manifest_ok)
    );
    drop((open, held, image));
    // Every compositor has ended; its handles and the process objects go a few ticks later.
    let gone = sched::poll_until(sched::ticks() + 1000, || sched::stats().processes == 0);
    let settled = sched::poll_until(sched::ticks() + 1000, || object::stats() == obj0);
    let procs = sched::stats().processes;
    let frames = frames0 as i64 - pmm::stats().free_frames as i64;
    kprintln!(
        "OSX|{}|ktest|{}|failed={}{}{}{}|processes_after={}|clean={}|frames_delta={}",
        BUILD_ID,
        name,
        if reply_ok { "" } else { "reply," },
        if too_long_ok { "" } else { "too_long," },
        if closed_ok { "" } else { "closed," },
        if manifest_ok { "" } else { "manifest," },
        procs,
        u8::from(gone && settled),
        frames
    );
    if !reply_ok || !too_long_ok {
        fail("the screen did not start held after a failed LIST (display.md v1.12)")
    }
    if !closed_ok {
        fail("the compositor did not exit 0xE6 when its boot channel closed before LIST was answered")
    }
    if !manifest_ok {
        fail("a listing decided the hold wrongly (display.md v1.2: no session, unheld; session, held)")
    }
    if !gone || procs != 0 || !settled || frames != 0 {
        fail("the compositors left a process, an object or a frame behind")
    }
    pass("a LIST the compositor cannot have starts the screen held; a listing still decides it as before")
}

// ---- WP-77: the compositor's boot channel keeps serving ---------------------------------------

/// TST-M6-DISPLAYD-BOOT-LOOP (REQ-M6-002, display.md v1.13): the compositor's boot channel
/// keeps serving the manager. As in `hold_fail_closed`, the test kernel plays the manager for a
/// fresh /SYSTEM/DISPLAYD.ELF per sub-case and answers `LIST` with a listing naming `display`
/// and no `session` (unheld): (a) `control` — nothing injected; after READY a `PING` is answered
/// `PONG`, an application connects (`HOLDS` → `OK locked=0 releases=0`) and `STOP` ends it 0;
/// (b) `too_long_msg` — after READY a 200-byte message, longer than the compositor's 64-byte
/// boot buffer: it must be discarded (`display|boot|discard=too_long`) and the `PING`, the
/// `CONNECT` and the `STOP` behind it still served; before v1.13 the message stayed at the head
/// of the queue and the loop spun on it, so nothing behind it was read and the compositor had
/// to be killed (EXIT_KILLED); (c) `stop_first` — `STOP` in place of the listing: the compositor
/// exits 0 without READY (`display|boot|stop=before_ready`); before v1.13 it took the STOP for a
/// failed LIST, said READY and never ended; (d) `ping_first` — a `PING` before the listing: it
/// is ignored while LIST waits (no PONG before READY) and the listing still decides the hold
/// (locked=0); before v1.13 the PING was taken for the LIST answer and the screen held; (e)
/// `stop_at_connect` — `STOP` in place of the `CONNECT input` answer: the compositor exits 0
/// without READY (the same stop trace); before v1.13 it exited 0xE5. Every
/// compositor is gone at the end, with the object and frame balance restored.
fn displayd_boot_loop() -> ! {
    let name = "displayd_boot_loop";
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    if crate::display::display_object().is_none() {
        fail("no display object (firmware left no linear frame buffer)")
    }
    let obj0 = object::stats();
    let frames0 = pmm::stats().free_frames;
    let image = match crate::loader::read_image(b"/SYSTEM/DISPLAYD.ELF") {
        Ok(i) => i,
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|image_error={}", BUILD_ID, name, e.code());
            fail("the compositor's image is not on the volume")
        }
    };
    let listing = &b"auth ready 0 1 1 - -\ninput ready 0 1 1 - -\ndisplay ready 0 1 1 - -\n"[..];
    let plain = HoldInject {
        test: name,
        before_answer: None,
        answer_ends: false,
        after_ready: None,
        ping: true,
        stop_at_connect: false,
    };
    let unheld = |c: &HoldCase| c.holds == "OK locked=0 releases=0" && c.exit == 0;
    let control = hold_run("control", &image, Some(listing), &plain);
    let control_ok = control.ready && control.pong == 1 && unheld(&control);
    kprintln!(
        "OSX|{}|ktest|{}|case=control|ready={}|pong={}|holds={}|exit={:#x}|ok={}",
        BUILD_ID,
        name,
        u8::from(control.ready),
        control.pong,
        control.holds,
        control.exit,
        u8::from(control_ok)
    );
    drop(control);
    // (b): longer than the boot buffer (64 bytes), far shorter than a message's 4096.
    let mut long = Vec::from(&b"NOTICE "[..]);
    long.resize(200, b'x');
    let too_long = hold_run(
        "too_long_msg",
        &image,
        Some(listing),
        &HoldInject {
            after_ready: Some(&long),
            ..plain
        },
    );
    let too_long_ok = too_long.ready && too_long.pong == 1 && unheld(&too_long);
    kprintln!(
        "OSX|{}|ktest|{}|case=too_long_msg|bytes={}|ready={}|pong={}|holds={}|exit={:#x}|ok={}",
        BUILD_ID,
        name,
        long.len(),
        u8::from(too_long.ready),
        too_long.pong,
        too_long.holds,
        too_long.exit,
        u8::from(too_long_ok)
    );
    drop((too_long, long));
    let stop_first = hold_run(
        "stop_first",
        &image,
        Some(b"STOP"),
        &HoldInject {
            answer_ends: true,
            ping: false,
            ..plain
        },
    );
    let stop_first_ok = !stop_first.ready && stop_first.exit == 0;
    kprintln!(
        "OSX|{}|ktest|{}|case=stop_first|ready={}|exit={:#x}|ok={}",
        BUILD_ID,
        name,
        u8::from(stop_first.ready),
        stop_first.exit,
        u8::from(stop_first_ok)
    );
    drop(stop_first);
    let ping_first = hold_run(
        "ping_first",
        &image,
        Some(listing),
        &HoldInject {
            before_answer: Some(b"PING"),
            ping: false,
            ..plain
        },
    );
    let ping_first_ok = ping_first.ready && unheld(&ping_first);
    kprintln!(
        "OSX|{}|ktest|{}|case=ping_first|ready={}|holds={}|exit={:#x}|ok={}",
        BUILD_ID,
        name,
        u8::from(ping_first.ready),
        ping_first.holds,
        ping_first.exit,
        u8::from(ping_first_ok)
    );
    drop(ping_first);
    let stop_at_connect = hold_run(
        "stop_at_connect",
        &image,
        None,
        &HoldInject {
            ping: false,
            stop_at_connect: true,
            ..plain
        },
    );
    let stop_at_connect_ok = !stop_at_connect.ready && stop_at_connect.exit == 0;
    kprintln!(
        "OSX|{}|ktest|{}|case=stop_at_connect|ready={}|exit={:#x}|ok={}",
        BUILD_ID,
        name,
        u8::from(stop_at_connect.ready),
        stop_at_connect.exit,
        u8::from(stop_at_connect_ok)
    );
    drop((stop_at_connect, image));
    let gone = sched::poll_until(sched::ticks() + 1000, || sched::stats().processes == 0);
    let settled = sched::poll_until(sched::ticks() + 1000, || object::stats() == obj0);
    let procs = sched::stats().processes;
    let frames = frames0 as i64 - pmm::stats().free_frames as i64;
    kprintln!(
        "OSX|{}|ktest|{}|failed={}{}{}{}{}|processes_after={}|frames_delta={}|clean={}",
        BUILD_ID,
        name,
        if control_ok { "" } else { "control," },
        if too_long_ok { "" } else { "too_long_msg," },
        if stop_first_ok { "" } else { "stop_first," },
        if ping_first_ok { "" } else { "ping_first," },
        if stop_at_connect_ok {
            ""
        } else {
            "stop_at_connect,"
        },
        procs,
        frames,
        u8::from(gone && settled)
    );
    if !control_ok {
        fail("the compositor did not serve PING, CONNECT and STOP on its boot channel")
    }
    if !too_long_ok {
        fail("a boot message longer than the buffer stopped the compositor's boot channel (display.md v1.13)")
    }
    if !stop_first_ok {
        fail("a STOP before the LIST answer did not end the compositor without READY (display.md v1.13)")
    }
    if !ping_first_ok {
        fail("a PING before the LIST answer was taken for the answer (display.md v1.13)")
    }
    if !stop_at_connect_ok {
        fail("a STOP before the CONNECT input answer did not end the compositor without READY (display.md v1.13)")
    }
    if !gone || procs != 0 || !settled || frames != 0 {
        fail("the compositors left a process, an object or a frame behind")
    }
    pass("the compositor's boot channel discards what does not fit, and STOP or PING before LIST are not taken for its answer")
}

/// Writes `data` as the whole of `path` on the volume (the test kernel writes through the VFS
/// directly; the system-files authority is checked at the syscall layer, not here).
fn manifest_write(path: &[u8], data: &[u8]) -> bool {
    use crate::fs::vfs;
    vfs::open(path, vfs::O_WRITE | vfs::O_CREATE | vfs::O_TRUNCATE)
        .and_then(|f| vfs::write(&f, data))
        .is_ok_and(|n| n == data.len())
}

/// A manifest of exactly `size` bytes: one service line (`A`, the test service) and comment
/// lines up to the size, so a prefix of it still parses as one service.
fn manifest_of(size: usize) -> Vec<u8> {
    let mut v = Vec::from(&b"A /SYSTEM/SVC.ELF - 200 never 0 0 ready\n"[..]);
    while v.len() < size {
        v.extend_from_slice(b"# padding to the manifest limit (services.md v1.13, WP-68) ......\n");
    }
    v.truncate(size);
    if let Some(last) = v.last_mut() {
        *last = b'\n';
    }
    v
}

/// TST-M6-MANIFEST-TOO-LARGE (negative; services.md v1.13, WP-68): a manifest the manager cannot
/// read whole is refused whole. The test kernel writes /SYSTEM/BIGMAN.TXT at run time and a real
/// manager (SvcHarness) loads it: 4097 and 4096 bytes answer `ERR MANIFEST_TOO_LARGE`, 4095 bytes
/// (the largest accepted) `OK 1`; a read that fails midway (the ktest read hook in fs/vfs.rs, armed
/// for one file size) answers `ERR MANIFEST_IO`. A refused file starts nothing (LIST empty) and
/// the refused LOAD does not count (a second LOAD is answered on its own, not `ERR LOADED`).
fn manifest_too_large() -> ! {
    use crate::fs::vfs;
    let name = "manifest_too_large";
    const PATH: &[u8] = b"/SYSTEM/BIGMAN.TXT";
    const IO_SIZE: usize = 3001;
    const IO_AT: u64 = 1024;
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    // The largest file first, so the balance below is taken after the volume code warmed up.
    if !manifest_write(PATH, &manifest_of(4097)) {
        fail("could not write /SYSTEM/BIGMAN.TXT")
    }
    let obj0 = object::stats();
    let frames0 = pmm::stats().free_frames;
    // A verdict per sub-case, no string: the frame balance below must not see the test's own heap.
    let mut verdict = [false; 4];
    for (k, (case, size)) in [
        ("4097", 4097usize),
        ("4096", 4096),
        ("4095", 4095),
        ("io", IO_SIZE),
    ]
    .into_iter()
    .enumerate()
    {
        if size != 4097 && !manifest_write(PATH, &manifest_of(size)) {
            fail("could not rewrite /SYSTEM/BIGMAN.TXT")
        }
        if case == "io" {
            vfs::arm_read_fault(IO_SIZE as u32, IO_AT);
        }
        let h = SvcHarness::start(name, PATH);
        let fired = case == "io" && !vfs::read_fault_armed();
        vfs::disarm_read_fault();
        let reply = h.load_reply.clone();
        let (line, ok) = if case == "4095" {
            let lines = h.poll_list(sched::ticks() + 1000, |l| {
                l.len() == 1 && l[0].state == "ready"
            });
            let ready = lines.len() == 1 && lines[0].name == "A" && lines[0].state == "ready";
            let ok = reply == "OK 1" && ready;
            (
                alloc::format!(
                    "case={}|reply={}|ready={}",
                    case,
                    crate::services::reply_field(&reply),
                    u8::from(ready)
                ),
                ok,
            )
        } else {
            let lines = h.poll_list(sched::ticks(), |_| true);
            let list = SvcHarness::list_text(&lines);
            let again = match crate::services::request(
                &h.m.ctl,
                b"LOAD /SYSTEM/NONE.TXT",
                sched::ticks() + 500,
            ) {
                Ok(b) => String::from_utf8_lossy(&b).into_owned(),
                Err(e) => e.into(),
            };
            let want = if case == "io" {
                "ERR MANIFEST_IO"
            } else {
                "ERR MANIFEST_TOO_LARGE"
            };
            let ok = reply == want
                && lines.is_empty()
                && again == "ERR MANIFEST_MISSING"
                && (case != "io" || fired);
            (
                alloc::format!(
                    "case={}|reply={}|list={}|again={}|fired={}",
                    case,
                    crate::services::reply_field(&reply),
                    list,
                    crate::services::reply_field(&again),
                    u8::from(fired)
                ),
                ok,
            )
        };
        let (mgr_exit, procs, _, clean) = h.finish();
        let ok = ok && mgr_exit == 0 && procs == 0 && clean;
        kprintln!(
            "OSX|{}|ktest|{}|{}|bytes={}|mgr_exit={:#x}|ok={}",
            BUILD_ID,
            name,
            line,
            size,
            mgr_exit,
            u8::from(ok)
        );
        verdict[k] = ok;
    }
    let removed = vfs::unlink(PATH).is_ok();
    let gone = sched::poll_until(sched::ticks() + 1000, || sched::stats().processes == 0);
    let settled = sched::poll_until(sched::ticks() + 1000, || object::stats() == obj0);
    let procs = sched::stats().processes;
    let frames = frames0 as i64 - pmm::stats().free_frames as i64;
    kprintln!(
        "OSX|{}|ktest|{}|failed={}{}{}{}|processes_after={}|frames_delta={}|clean={}|removed={}",
        BUILD_ID,
        name,
        if verdict[0] { "" } else { "4097," },
        if verdict[1] { "" } else { "4096," },
        if verdict[2] { "" } else { "4095," },
        if verdict[3] { "" } else { "io," },
        procs,
        frames,
        u8::from(gone && settled),
        u8::from(removed)
    );
    if verdict.contains(&false) {
        fail(
            "a manifest the manager could not read whole was not refused whole (services.md v1.13)",
        )
    }
    if !gone || procs != 0 || !settled || frames != 0 || !removed {
        fail("the managers left a process, an object or a frame behind, or the file stayed")
    }
    pass("a manifest of 4096 bytes or more, or one whose read fails, is refused whole; 4095 bytes load")
}

/// TST-M6-LOAD-OUTSIDE-SYSTEM (negative; services.md v1.13, WP-68): `LOAD` reads only under
/// `/SYSTEM/`. One real manager: `LOAD /OUTSIDE.TXT` (a valid manifest written at run time) and
/// `LOAD /SYSTEM/../OUTSIDE.TXT` answer `ERR ACCESS` and start nothing; a dependency name the
/// grammar refuses (`a|b`) is a syntax error, not an echoed name; none of the three counts, so
/// `LOAD /SYSTEM/SVC-ORD.TXT` then answers `OK 3`. The kernel's boot verdict wants `OK <n>` with
/// n >= 1 for the interactive manifest and escapes `|`, `\` and control bytes in its trace field.
fn load_outside_system() -> ! {
    use crate::fs::vfs;
    let name = "load_outside_system";
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    if !manifest_write(
        b"/OUTSIDE.TXT",
        b"A /SYSTEM/SVC.ELF - 200 never 0 0 ready\n",
    ) || !manifest_write(
        b"/SYSTEM/BADDEP.TXT",
        b"A /SYSTEM/SVC.ELF a|b 200 never 0 0 ready\n",
    ) {
        fail("could not write the test manifests")
    }
    let obj0 = object::stats();
    let frames0 = pmm::stats().free_frames;
    let h = SvcHarness::start(name, b"/OUTSIDE.TXT");
    let lines = h.poll_list(sched::ticks() + 100, |l| !l.is_empty());
    let outside = h.load_reply.clone();
    let outside_ok = outside == "ERR ACCESS" && lines.is_empty();
    kprintln!(
        "OSX|{}|ktest|{}|case=outside|reply={}|started={}|ok={}",
        BUILD_ID,
        name,
        crate::services::reply_field(&outside),
        lines.len(),
        u8::from(outside_ok)
    );
    drop(lines);
    let load = |path: &[u8]| -> String {
        match crate::services::request(
            &h.m.ctl,
            &crate::services::load_request(path),
            sched::ticks() + 500,
        ) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => e.into(),
        }
    };
    let dotdot = load(b"/SYSTEM/../OUTSIDE.TXT");
    let lines = h.poll_list(sched::ticks(), |_| true);
    let dotdot_ok = dotdot == "ERR ACCESS" && lines.is_empty();
    kprintln!(
        "OSX|{}|ktest|{}|case=dotdot|reply={}|started={}|ok={}",
        BUILD_ID,
        name,
        crate::services::reply_field(&dotdot),
        lines.len(),
        u8::from(dotdot_ok)
    );
    drop(lines);
    let dep = load(b"/SYSTEM/BADDEP.TXT");
    let dep_ok = dep == "ERR MANIFEST_SYNTAX 1";
    kprintln!(
        "OSX|{}|ktest|{}|case=dep_name|reply={}|ok={}",
        BUILD_ID,
        name,
        crate::services::reply_field(&dep),
        u8::from(dep_ok)
    );
    let ord = load(b"/SYSTEM/SVC-ORD.TXT");
    let lines = h.poll_list(sched::ticks() + 1000, |l| {
        l.len() == 3 && l.iter().all(|x| x.state == "ready")
    });
    let ord_ok = ord == "OK 3" && lines.len() == 3 && lines.iter().all(|x| x.state == "ready");
    kprintln!(
        "OSX|{}|ktest|{}|case=system|reply={}|ready={}|ok={}",
        BUILD_ID,
        name,
        crate::services::reply_field(&ord),
        lines.iter().filter(|x| x.state == "ready").count(),
        u8::from(ord_ok)
    );
    drop(lines);
    let (mgr_exit, procs, _, clean) = h.finish();
    // The kernel's boot verdict and trace field (services.rs), on fixed replies.
    use crate::services::{boot_reply_ok, reply_field};
    let interactive_ok0 = boot_reply_ok(true, "OK 0");
    let selftest_ok0 = boot_reply_ok(false, "OK 0");
    let interactive_ok8 = boot_reply_ok(true, "OK 8");
    let bad_ok = boot_reply_ok(false, "OK x") || boot_reply_ok(true, "OK ");
    let escaped = reply_field("ERR MANIFEST_UNKNOWN_DEP a|b\\\u{1b}\n")
        == "ERR MANIFEST_UNKNOWN_DEP a\\x7cb\\x5c\\x1b;";
    let boot_ok = !interactive_ok0 && selftest_ok0 && interactive_ok8 && !bad_ok && escaped;
    kprintln!(
        "OSX|{}|ktest|{}|case=boot_reply|interactive_ok0={}|selftest_ok0={}|interactive_ok8={}|bad_ok={}|escaped={}|ok={}",
        BUILD_ID,
        name,
        u8::from(interactive_ok0),
        u8::from(selftest_ok0),
        u8::from(interactive_ok8),
        u8::from(bad_ok),
        u8::from(escaped),
        u8::from(boot_ok)
    );
    let all_ok = outside_ok && dotdot_ok && dep_ok && ord_ok && boot_ok;
    let manager_ok = mgr_exit == 0 && procs == 0 && clean;
    drop((outside, dotdot, dep, ord));
    let removed =
        vfs::unlink(b"/OUTSIDE.TXT").is_ok() && vfs::unlink(b"/SYSTEM/BADDEP.TXT").is_ok();
    let settled = sched::poll_until(sched::ticks() + 1000, || object::stats() == obj0);
    let procs = sched::stats().processes;
    let frames = frames0 as i64 - pmm::stats().free_frames as i64;
    kprintln!(
        "OSX|{}|ktest|{}|failed={}{}{}{}{}|processes_after={}|frames_delta={}|clean={}|mgr_exit={:#x}|removed={}",
        BUILD_ID,
        name,
        if outside_ok { "" } else { "outside," },
        if dotdot_ok { "" } else { "dotdot," },
        if dep_ok { "" } else { "dep_name," },
        if ord_ok { "" } else { "system," },
        if boot_ok { "" } else { "boot_reply," },
        procs,
        frames,
        u8::from(manager_ok && settled),
        mgr_exit,
        u8::from(removed)
    );
    if !all_ok {
        fail("LOAD read or started something outside /SYSTEM/, or a refused LOAD counted (services.md v1.13)")
    }
    if !manager_ok || !settled || procs != 0 || frames != 0 || !removed {
        fail("the manager left a process, an object or a frame behind, or a file stayed")
    }
    pass("LOAD outside /SYSTEM/ is refused with ERR ACCESS and starts nothing; LOAD under /SYSTEM/ still loads")
}

/// TST-M6-TOKEN-REVOKE (negative; auth.md v1.2, session.md v1.7 §5, WP-73): the session's
/// auth token dies with the session service. SVC-SS.TXT; the test first logs `user` in on its
/// own connection to `auth` and closes that connection at once, as `sh` does
/// (user/apps/sh/src/main.rs:362-374), keeping the token; the lab then signs in to the session
/// (`admin`). The live session process is frozen and the manager's STOP finds it unresponsive
/// and kills it (`process_kill` → `sched::kill_process`, EXIT_KILLED): a crash, no code of the
/// session runs after the freeze. Then `auth` must have revoked and closed the token it minted
/// for the client named `session` — the kernel's count of live tokens returns to its value
/// before the lab's sign-in (the session's handles died with its process; only `auth`'s could
/// keep it alive) — while the sh-like token, whose connection closed long before, still
/// answers `WHOAMI` with its identity. Each part prints its verdict and the case goes on after
/// a failed one, so a red run shows every part; waits are bounded and compete at the test
/// thread's own priority (`hold_wait`).
fn token_revoke() -> ! {
    const EXIT_KILLED: u64 = 0x2_0000;
    let name = "token_revoke";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-SS.TXT",
        &["auth", "input", "display", "session", "spy"],
    );
    let tokens = || i64::from(object::stats().tokens);
    let base = tokens();
    kprintln!("OSX|{}|ktest|token_revoke|services=5|ready=1", BUILD_ID);
    let within = |t: u64| sched::ticks() + t;
    // Bounded so that a red run still prints every verdict inside the lab's 85 s: the sh-like
    // login and the lab's sign-in share 35 s, then at most 5 s each for the kill, the count
    // and WHOAMI (WP-73 audit #11).
    let unlock_by = within(35_000);
    let mut ev = Vec::new();
    // Part 1: an sh-like client logs in, keeps the token, and closes its connection.
    let sh_auth = svc_connect(&h, "auth");
    let (sh_login, sh_token) = auth_request(&sh_auth, b"LOGIN user lab-user-1", None);
    drop(sh_auth);
    let sh_ok = sh_login == "OK 1001 1001 8" && sh_token.is_some();
    kprintln!(
        "OSX|{}|ktest|token_revoke|sh_login={}|sh_token={}|phase=1",
        BUILD_ID,
        sh_login,
        u8::from(sh_token.is_some())
    );
    // Part 2: the lab signs in to the session; its token is minted by `auth` for `session`.
    let unlocked = loop {
        let r = hold_request(
            &session,
            b"STATE",
            Vec::new(),
            &mut ev,
            within(5000).min(unlock_by),
        );
        if (state_is(&r, "unlocked", 1) && r.ends_with(" focus=display"))
            || sched::ticks() >= unlock_by
        {
            break r;
        }
        hold_wait(within(20).min(unlock_by), || false);
    };
    let signed_in = tokens() - base;
    let unlocked_ok = state_is(&unlocked, "unlocked", 1) && unlocked.ends_with(" focus=display");
    kprintln!(
        "OSX|{}|ktest|token_revoke|unlocked={}|tokens={}|phase=2",
        BUILD_ID,
        unlocked,
        signed_in
    );
    // Part 3: the session process is frozen, then killed by the manager's STOP. The session must
    // be idle (blocked) when it is frozen: freezing only stops wake-ups (sched::freeze_named), so
    // nothing may wake it first; the test's own channel to it is closed only after the freeze.
    // Closing it before woke the session, which then read STOP and exited 0 (CI run 42747260620,
    // WP-73, 2026-11-10).
    hold_wait(within(500), || false);
    let frozen = sched::freeze_named(b"SESSIOND.ELF");
    drop(session);
    let stop = match crate::services::request(&h.m.ctl, b"STOP session", within(500)) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => String::from(e),
    };
    let mut lines = Vec::new();
    let stopped = hold_wait(within(5000), || {
        lines = match crate::services::request(&h.m.ctl, b"LIST", within(200)) {
            Ok(b) => parse_list(&b),
            Err(_) => Vec::new(),
        };
        svc_find(&lines, "session").state == "stopped"
    });
    let gone = svc_find(&lines, "session");
    let killed = stopped && gone.exit == Some(EXIT_KILLED);
    kprintln!(
        "OSX|{}|ktest|token_revoke|frozen={}|stop={}|session={}:{:#x}|killed={}|phase=3",
        BUILD_ID,
        u8::from(frozen),
        stop,
        gone.state,
        gone.exit.unwrap_or(u64::MAX),
        u8::from(killed)
    );
    // Verdict (a): the session's token is gone — revoked and closed by `auth` — so the live
    // count is back to the sh-like token alone. Before auth.md v1.2 `auth` kept the session
    // (and its handle) until SESSION_TICKS, and the count stays one higher.
    let back = hold_wait(within(5000), || tokens() - base == 1);
    let after = tokens() - base;
    let revoked_ok = killed && signed_in == 2 && back && after == 1;
    kprintln!(
        "OSX|{}|ktest|token_revoke|case=session_token|tokens_before={}|tokens_after={}|revoked={}",
        BUILD_ID,
        signed_in,
        after,
        u8::from(back && after == 1)
    );
    // Verdict (b): the sh-like token survives the session's death (auth.md v1.2, V2).
    let whoami = match &sh_token {
        Some(t) => {
            let a = svc_connect(&h, "auth");
            let r = hold_request(
                &a,
                b"WHOAMI",
                alloc::vec![token_entry(t)],
                &mut ev,
                within(5000),
            );
            drop(a);
            r
        }
        None => String::from("-"),
    };
    let kept = whoami == "OK 1001 1001 8";
    kprintln!(
        "OSX|{}|ktest|token_revoke|case=sh_token|whoami={}|kept={}",
        BUILD_ID,
        whoami,
        u8::from(kept)
    );
    let failed = alloc::format!(
        "{}{}{}{}{}",
        if sh_ok { "" } else { "sh_login," },
        if unlocked_ok { "" } else { "unlocked," },
        if killed { "" } else { "kill," },
        if revoked_ok { "" } else { "session_token," },
        if kept { "" } else { "sh_token," }
    );
    kprintln!(
        "OSX|{}|ktest|token_revoke|failed={}",
        BUILD_ID,
        if failed.is_empty() { "none" } else { &failed }
    );
    drop((sh_login, sh_token, unlocked, stop, lines, gone, whoami, ev));
    if !failed.is_empty() {
        fail("the session's token outlived the session, or another client's token did not (auth.md v1.2)")
    }
    drop(failed);
    display_finish(
        name,
        h,
        "the token of a killed session was revoked; a token another client held survived",
    )
}

/// `STATE` of the session until it says `state` after `changes` transitions (and, when
/// `focus` is given, ends with that focus), or `by`; the last reply.
fn state_wait(
    session: &Endpoint,
    state: &str,
    changes: u32,
    focus: Option<&str>,
    by: u64,
) -> String {
    let mut ev = Vec::new();
    loop {
        let r = hold_request(
            session,
            b"STATE",
            Vec::new(),
            &mut ev,
            (sched::ticks() + 5000).min(by),
        );
        let focused = focus.is_none_or(|f| r.ends_with(&alloc::format!(" focus={}", f)));
        if (state_is(&r, state, changes) && focused) || sched::ticks() >= by {
            return r;
        }
        hold_wait((sched::ticks() + 20).min(by), || false);
    }
}

/// TST-M6-LOGOUT-KILLS (REQ-M6-004, session.md v1.8, services.md v1.17; WP-167): Sign out ends
/// the session's job. The real auth, input, display and session (SVC-LK.TXT) with the lab image as
/// the vouched `desktop`, whose role `relay` passes the test kernel's LAUNCH to the manager. After
/// the lab's sign-in the desktop launches `deaf` (winapp: a window, and it ignores LOGGED_OUT) and
/// `nest` (a child of its own, waiting); the secure attention sequence locks the session and Sign
/// out ends it; the test kernel reads that none of the three processes lives, no job is left and
/// the manager holds what it held before the launches; after a second sign-in a launch makes a
/// new session job.
fn logout_kills() -> ! {
    let name = "logout_kills";
    let (h, session) = session_env(
        name,
        b"/SYSTEM/SVC-LK.TXT",
        &["auth", "input", "display", "session", "desktop"],
    );
    // v1.19 (WP-169): before the first sign-in no session is open, so the desktop's launch is
    // refused (the monitor's typing of the name and password takes about nine seconds).
    let desk = svc_connect(&h, "desktop");
    let before = cfg_request(&desk, b"LAUNCH deaf", None);
    kprintln!("OSX|{}|ktest|logout_kills|services=5|ready=1", BUILD_ID);
    let within = |t: u64| sched::ticks() + t;
    let live = |img: &[u8]| sched::live_named(img).1;
    // Phase 1: signed in (the monitor types the lab's name and password), two launches.
    let unlocked = state_wait(&session, "unlocked", 1, Some("display"), within(40_000));
    let jobs0 = i64::from(object::stats().jobs);
    let mgr0 = mgr_handles(&h);
    let deaf = cfg_request(&desk, b"LAUNCH deaf", None);
    let nest = cfg_request(&desk, b"LAUNCH nest", None);
    sched::poll_until(within(5000), || {
        live(b"DEAF.ELF") == 1 && live(b"NEST.ELF") == 1 && live(b"IDLE.ELF") == 1
    });
    let running = (live(b"DEAF.ELF"), live(b"NEST.ELF"), live(b"IDLE.ELF"));
    kprintln!(
        "OSX|{}|ktest|logout_kills|unlocked={}|launched={},{}|deaf={}|nest={}|idle={}|phase=1",
        BUILD_ID,
        unlocked,
        deaf,
        nest,
        running.0,
        running.1,
        running.2
    );
    // Phase 2: the monitor locks the session and signs out on the lock screen.
    let out = state_wait(&session, "no_session", 3, None, within(40_000));
    let left = || {
        (
            live(b"DEAF.ELF"),
            live(b"NEST.ELF"),
            live(b"IDLE.ELF"),
            i64::from(object::stats().jobs) - jobs0,
            mgr_handles(&h) - mgr0,
        )
    };
    sched::poll_until(within(5000), || left() == (0, 0, 0, 0, 0));
    let after = left();
    // Sign out closed the gate (END_SESSION, v1.19): the desktop's launch is refused, before the
    // line below lets the monitor sign in again.
    let shut = cfg_request(&desk, b"LAUNCH deaf", None);
    kprintln!(
        "OSX|{}|ktest|logout_kills|gate|before={}|after={}|",
        BUILD_ID,
        before,
        shut
    );
    kprintln!(
        "OSX|{}|ktest|logout_kills|back={}|deaf={}|nest={}|idle={}|jobs={}|mgr_handles={}|phase=2",
        BUILD_ID,
        out,
        after.0,
        after.1,
        after.2,
        after.3,
        after.4
    );
    // Phase 3: a second sign-in, and a launch in a new session job.
    let again = state_wait(&session, "unlocked", 4, Some("display"), within(40_000));
    let relaunch = cfg_request(&desk, b"LAUNCH deaf", None);
    sched::poll_until(within(5000), || live(b"DEAF.ELF") == 1);
    let (d, n) = sched::live_named(b"DEAF.ELF");
    let in_session = d[..n].iter().filter(|a| a.parent_under_root).count();
    kprintln!(
        "OSX|{}|ktest|logout_kills|again={}|launch={}|deaf={}|in_session={}|phase=3",
        BUILD_ID,
        again,
        relaunch,
        n,
        in_session
    );
    let signed_in =
        |r: &str, changes: u32| state_is(r, "unlocked", changes) && r.ends_with(" focus=display");
    let failed = alloc::format!(
        "{}{}{}{}{}{}",
        if before == "ERR NO_SESSION" && shut == "ERR NO_SESSION" {
            ""
        } else {
            "gate,"
        },
        if signed_in(&unlocked, 1)
            && deaf == "OK app:deaf#1"
            && nest == "OK app:nest#2"
            && running == (1, 1, 1)
        {
            ""
        } else {
            "launch,"
        },
        if state_is(&out, "no_session", 3) {
            ""
        } else {
            "sign_out,"
        },
        if after == (0, 0, 0, 0, 0) {
            ""
        } else {
            "left,"
        },
        if signed_in(&again, 4) { "" } else { "again," },
        if relaunch == "OK app:deaf#3" && n == 1 && in_session == 1 {
            ""
        } else {
            "relaunch,"
        }
    );
    kprintln!(
        "OSX|{}|ktest|logout_kills|failed={}",
        BUILD_ID,
        if failed.is_empty() { "none" } else { &failed }
    );
    drop((
        before, shut, unlocked, deaf, nest, out, again, relaunch, desk, session,
    ));
    if failed.contains("left,") {
        fail("an application of the signed-out session is still alive")
    }
    if !failed.is_empty() {
        fail("the sign-in, a launch or the sign-out was not as the case states")
    }
    drop(failed);
    let (mgr_exit, procs, frames0, clean) = h.finish();
    kprintln!(
        "OSX|{}|ktest|logout_kills|mgr_exit={:#x}|processes_after={}|clean={}",
        BUILD_ID,
        mgr_exit,
        procs,
        u8::from(clean)
    );
    if mgr_exit != 0 || procs != 0 || !clean {
        fail("manager or services left something behind")
    }
    svc_balance(name, frames0)
}

/// What one sub-case of `purge_fail_closed` saw: the answer the substitute compositor gave to
/// the session's `LOGOUT` (`-`: never asked), where it came against the sign-in screen
/// (`logout_first`: before the first `CREATE_SURFACE`; `logout_only`: no screen after it;
/// `screen_only`: a screen with no `LOGOUT` before it; `none`), whether the session said
/// READY, and its exit code (0 after `STOP`; EXIT_KILLED when it had to be killed).
struct PurgeCase {
    logout: String,
    order: &'static str,
    ready: bool,
    exit: u64,
}

impl PurgeCase {
    /// Purged, then the sign-in screen, READY, and `STOP` ended it.
    fn purged(&self) -> bool {
        self.logout == "OK" && self.order == "logout_first" && self.ready && self.exit == 0
    }

    /// No sign-in screen after a refused or failed `LOGOUT`: exit 0xE4 before READY.
    fn closed(&self, answer: &str) -> bool {
        self.logout == answer && self.order == "logout_only" && !self.ready && self.exit == 0xE4
    }
}

/// One `purge_fail_closed` sub-case: its name, the answer to `LIST` (`None`: the boot channel
/// closes), the compositor's answer to `LOGOUT` (empty: its channel closes), what must happen.
type PurgeSpec<'a> = (&'a str, Option<&'a [u8]>, &'a [u8], &'a str);

/// Ticks one `purge_fail_closed` sub-case may take up to its `STOP`; then at most
/// `PURGE_STOP` for `STOP` and as much again for a kill. Eight sub-cases: at most
/// 8 × 10 s = 80 s, inside the lab's 100 s.
const PURGE_BUDGET: u64 = 8000;
const PURGE_STOP: u64 = 1000;

/// The substitute manager's side of one session start-up (session.md v1.7): a fresh
/// /SYSTEM/SESSIOND.ELF with the boot channel as its only handle, `START`, then every
/// `CONNECT` answered with a channel the test keeps — `auth` silent, `input` and `display`
/// played by the test: the input service answers `REGISTER` with `OK 1` and the rest with
/// `OK`; the compositor answers `STATUS` with a 1280×800 screen, `LOGOUT` with `logout` (empty:
/// its channel closes instead), `CREATE_SURFACE`/`CREATE_WINDOW` with `OK 1` and the rest with
/// `OK`, and logs each verb in order. The session's `LIST` is answered with `list` — or, with
/// `None`, the boot channel closes instead. On READY, `STOP`. Every wait is bounded
/// (`PURGE_BUDGET`, `PURGE_STOP`); a session still alive after `STOP` is killed.
fn purge_run(case: &str, image: &[u8], list: Option<&[u8]>, logout: &[u8]) -> PurgeCase {
    let chan_entry = |ep: Arc<Endpoint>| Entry {
        object: Object::Channel(ep),
        rights: Rights::CHANNEL_DEFAULT,
    };
    let note = |bytes: &[u8]| Message {
        bytes: bytes.to_vec(),
        handles: Vec::new(),
    };
    let (ours, theirs) = channel::create();
    let object = Arc::new(crate::object::process::ProcessObject::new());
    let pid = match crate::user::spawn_elf_with(
        image,
        1,
        alloc::vec![chan_entry(theirs)],
        object.clone(),
    ) {
        Ok(p) => p,
        Err(e) => {
            kprintln!(
                "OSX|{}|ktest|purge_fail_closed|case={}|error={}",
                BUILD_ID,
                case,
                e.code()
            );
            fail("the session's image did not load")
        }
    };
    let mut boot = Some(ours);
    let mut auth: Option<Arc<Endpoint>> = None;
    let mut input: Option<Arc<Endpoint>> = None;
    let mut display: Option<Arc<Endpoint>> = None;
    let mut verbs: Vec<String> = Vec::new();
    let mut answered = String::from("-");
    let mut ready = false;
    if let Some(b) = boot.as_ref() {
        let _ = b.write(note(b"START"));
    }
    let read = |ep: &Arc<Endpoint>| ep.read(channel::MSG_MAX_BYTES, channel::MSG_MAX_HANDLES, None);
    hold_wait(sched::ticks() + PURGE_BUDGET, || {
        let mut close_boot = false;
        if let Some(b) = boot.as_ref() {
            while let Ok(m) = read(b) {
                let req = m.bytes.as_slice();
                if let Some(name) = req.strip_prefix(b"CONNECT ") {
                    let (mine, far) = channel::create();
                    match name {
                        b"input" => input = Some(mine),
                        b"display" => display = Some(mine),
                        _ => auth = Some(mine),
                    }
                    let _ = b.write(Message {
                        bytes: b"OK".to_vec(),
                        handles: alloc::vec![chan_entry(far)],
                    });
                } else if req == b"LIST" {
                    match list {
                        Some(a) => {
                            let _ = b.write(note(a));
                        }
                        None => {
                            close_boot = true;
                            break;
                        }
                    }
                } else if req == b"READY" {
                    ready = true;
                }
            }
        }
        if close_boot {
            boot = None;
        }
        if let Some(i) = input.as_ref() {
            while let Ok(m) = read(i) {
                let r: &[u8] = if m.bytes.starts_with(b"REGISTER") {
                    b"OK 1"
                } else {
                    b"OK"
                };
                let _ = i.write(note(r));
            }
        }
        let mut close_display = false;
        if let Some(d) = display.as_ref() {
            while let Ok(m) = read(d) {
                let text = String::from_utf8_lossy(&m.bytes).into_owned();
                let verb: String = text.split(' ').next().unwrap_or("").into();
                let r: &[u8] = match verb.as_str() {
                    "STATUS" => b"OK format=1 screen=1280x800 windows=0 focus=- pointer=0,0 composed=0 dropped=0 unresponsive=0",
                    "LOGOUT" if logout.is_empty() => {
                        answered = String::from("closed");
                        close_display = true;
                        b""
                    }
                    "LOGOUT" => {
                        answered = String::from_utf8_lossy(logout).into_owned();
                        logout
                    }
                    "CREATE_SURFACE" | "CREATE_WINDOW" => b"OK 1",
                    _ => b"OK",
                };
                verbs.push(verb);
                if close_display {
                    break;
                }
                let _ = d.write(note(r));
            }
        }
        if close_display {
            display = None;
        }
        ready || object.exit_code().is_some()
    });
    if let Some(b) = boot.as_ref() {
        let _ = b.write(note(b"STOP"));
    }
    if !hold_wait(sched::ticks() + PURGE_STOP, || object.exit_code().is_some()) {
        sched::kill_process(pid, crate::syscall::EXIT_KILLED);
        hold_wait(sched::ticks() + PURGE_STOP, || object.exit_code().is_some());
    }
    let logout_at = verbs.iter().position(|v| v == "LOGOUT");
    let screen_at = verbs.iter().position(|v| v == "CREATE_SURFACE");
    let order = match (logout_at, screen_at) {
        (Some(l), Some(s)) if l < s => "logout_first",
        (Some(_), None) => "logout_only",
        (_, Some(_)) => "screen_only",
        (None, None) => "none",
    };
    let out = PurgeCase {
        logout: answered,
        order,
        ready,
        exit: object.exit_code().unwrap_or(u64::MAX),
    };
    drop((boot, auth, input, display, verbs, object));
    out
}

/// TST-M6-PURGE-FAIL-CLOSED (session.md v1.7, WP-64): a session that cannot tell whether it
/// was restarted purges anyway, and one whose purge is refused shows no sign-in screen. The
/// test kernel plays the service manager, the input service and the compositor for a fresh
/// /SYSTEM/SESSIOND.ELF per sub-case (`purge_run`) and answers its `LIST`: (a) `reply` — `ERR
/// TEST`; (b) `no_session_line` — a listing without `session`; (c) `bad_count` — a `session`
/// line whose restart count is not a number; (d) `too_long` — 2000 bytes, more than the
/// session's 1024-byte buffer; (e) `closed` — the boot channel closes instead: each of (a)–(d)
/// must send `LOGOUT` before the sign-in screen and then say READY; (e) purges and then cannot
/// say READY (0xE5). (f) `refused` — restarted (`restarts=1`) and the compositor answers
/// `LOGOUT` with `ERR ACCESS`; (g) `logout_closed` — the compositor's channel closes on
/// `LOGOUT`: no sign-in screen, exit 0xE4 before READY. (h) `first_start` — `restarts=0`, the
/// control: no `LOGOUT`, the screen, READY. The serial log must carry the list_failure trace
/// five times and the restarted one never (target.json). Each sub-case prints its verdict and
/// the case goes on after a failed one.
fn purge_fail_closed() -> ! {
    let name = "purge_fail_closed";
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let obj0 = object::stats();
    let frames0 = pmm::stats().free_frames;
    let image = match crate::loader::read_image(b"/SYSTEM/SESSIOND.ELF") {
        Ok(i) => i,
        Err(e) => {
            kprintln!("OSX|{}|ktest|{}|image_error={}", BUILD_ID, name, e.code());
            fail("the session's image is not on the volume")
        }
    };
    let deps: &[u8] = b"auth ready 0 1 1 1 -\ninput ready 0 1 1 1 -\ndisplay ready 0 1 1 1 -\n";
    let with = |session: &[u8]| {
        let mut v = Vec::from(deps);
        v.extend_from_slice(session);
        v
    };
    let mut long = with(b"session starting 1 1 1 - -\n");
    let mut k = 0;
    while long.len() < 2000 {
        long.extend_from_slice(alloc::format!("fill{:02} ready 0 1 1 1 -\n", k).as_bytes());
        k += 1;
    }
    let bad = with(b"session starting x 1 1 - -\n");
    let restarted = with(b"session starting 1 1 1 - -\n");
    let first = with(b"session starting 0 1 - - -\n");
    let cases: [PurgeSpec; 8] = [
        ("reply", Some(b"ERR TEST"), b"OK", "purged"),
        ("no_session_line", Some(deps), b"OK", "purged"),
        ("bad_count", Some(&bad), b"OK", "purged"),
        ("too_long", Some(&long), b"OK", "purged"),
        ("closed", None, b"OK", "no_ready"),
        ("refused", Some(&restarted), b"ERR ACCESS", "closed"),
        ("logout_closed", Some(&restarted), b"", "closed"),
        ("first_start", Some(&first), b"OK", "control"),
    ];
    let mut failed = String::new();
    for (case, list, logout, expect) in cases {
        let r = purge_run(case, &image, list, logout);
        let ok = match expect {
            "purged" => r.purged(),
            "no_ready" => {
                r.logout == "OK" && r.order == "logout_first" && !r.ready && r.exit == 0xE5
            }
            "closed" => r.closed(if logout.is_empty() {
                "closed"
            } else {
                "ERR ACCESS"
            }),
            _ => r.logout == "-" && r.order == "screen_only" && r.ready && r.exit == 0,
        };
        kprintln!(
            "OSX|{}|ktest|{}|case={}|logout={}|order={}|ready={}|exit={:#x}|ok={}",
            BUILD_ID,
            name,
            case,
            r.logout,
            r.order,
            u8::from(r.ready),
            r.exit,
            u8::from(ok)
        );
        if !ok {
            failed.push_str(case);
            failed.push(',');
        }
    }
    drop((image, long, bad, restarted, first));
    let gone = sched::poll_until(sched::ticks() + 1000, || sched::stats().processes == 0);
    let settled = sched::poll_until(sched::ticks() + 1000, || object::stats() == obj0);
    let procs = sched::stats().processes;
    let frames = frames0 as i64 - pmm::stats().free_frames as i64;
    kprintln!(
        "OSX|{}|ktest|{}|failed={}|processes_after={}|clean={}|frames_delta={}",
        BUILD_ID,
        name,
        if failed.is_empty() { "none" } else { &failed },
        procs,
        u8::from(gone && settled),
        frames
    );
    if !failed.is_empty() {
        fail("a session that could not tell it was restarted showed its sign-in screen without LOGOUT, or showed it after a refused LOGOUT (session.md v1.7)")
    }
    if !gone || procs != 0 || !settled || frames != 0 {
        fail("the sessions left a process, an object or a frame behind")
    }
    pass("a session purges whenever it cannot tell it was not restarted, and shows no sign-in screen when the purge fails")
}

// ---- WP-40: forced termination ---------------------------------------------------------------

/// TST-M5-PROCESS-KILL (REQ-M5-010, §8.7): the `killer` app proves the whole process_kill
/// contract in user space — a read-only process handle cannot kill (ERR_ACCESS), a non-process
/// handle is ERR_WRONG_TYPE, the owner's handle ends a child blocked in channel_read with
/// EXIT_KILLED, killing an exited process is a no-op, and a SPIN child (ring 3) and an IDLE
/// child (object_wait_many) are likewise ended with EXIT_KILLED. The test checks its exit and
/// that no frame leaked (the three children's resources all came back).
fn process_kill() -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let frames0 = pmm::stats().free_frames;
    let object = Arc::new(crate::object::process::ProcessObject::new());
    let pid = match crate::user::spawn_elf_with(crate::apps::KILLER, 1, Vec::new(), object) {
        Ok(p) => p,
        Err(e) => {
            kprintln!("OSX|{}|ktest|process_kill|error={}", BUILD_ID, e.code());
            fail("killer did not load")
        }
    };
    let code = sched::wait_process(pid).unwrap_or(u64::MAX);
    let frames = frames0 as i64 - pmm::stats().free_frames as i64;
    kprintln!(
        "OSX|{}|ktest|process_kill|killer_exit={:#x}|frames_delta={}",
        BUILD_ID,
        code,
        frames
    );
    if code != 0x6B {
        fail("the process_kill contract did not hold (see killer_exit)")
    }
    if frames != 0 {
        fail("process_kill leaked frames")
    }
    pass("process_kill ends a blocked, a spinning, a waiting and a sleeping process with EXIT_KILLED, and refuses a handle without WRITE")
}

/// TST-M5-KILL-EDGES (REQ-M5-010; review 2026-10-19, K1–K3): the edges of process_kill that the
/// first tests missed. (a) IDLE and (b) EXITER killed before they ever ran (spawn and kill with
/// interrupts off, pinned to this CPU) end with EXIT_KILLED — not a sleep for ever, not 0x55;
/// these hold whichever safe point delivers the kill. (d)–(f) pin the fixes down with the
/// test-kernel injection points: the kill lands while the child runs in the kernel past its last
/// safe point — before object_wait_many blocks (d), before sleep sleeps (e), inside exit(0x55)
/// (f) — and each must end in EXIT_KILLED (K1, K2). (c) SVC as `ticker` (a `T` every 5 ticks
/// from a timed wait) is frozen: it must stop ticking — a frozen process's timed waits do not
/// expire — and process_kill must still end it (K3). Everything comes back: no process left, no
/// frame leaked.
fn kill_edges() -> ! {
    use crate::object::process::ProcessObject;
    use crate::syscall::EXIT_KILLED;
    let frames0 = pmm::stats().free_frames;
    let chan_entry = |ep: Arc<Endpoint>| Entry {
        object: Object::Channel(ep),
        rights: Rights::CHANNEL_DEFAULT,
    };
    // Spawns `image` and marks it killed before it can run; then waits (bounded) for its exit.
    let kill_before_run = |name: &str, image: &[u8], handles: Vec<Entry>| -> (u64, bool) {
        let object = Arc::new(ProcessObject::new());
        let was = interrupts::save_and_disable();
        let spawned = crate::user::spawn_elf_with(image, 1, handles, object.clone());
        let marked = spawned
            .as_ref()
            .is_ok_and(|&pid| sched::kill_process(pid, EXIT_KILLED));
        interrupts::restore(was);
        if let Err(e) = spawned {
            kprintln!(
                "OSX|{}|ktest|kill_edges|{}_error={}",
                BUILD_ID,
                name,
                e.code()
            );
            fail("child did not load")
        }
        let exited = sched::poll_until(sched::ticks() + 5000, || object.exit_code().is_some());
        (object.exit_code().unwrap_or(u64::MAX), marked && exited)
    };
    // (a) A child marked before it ever ran dies with EXIT_KILLED. Our end `idle_peer` stays open
    // and silent, so nothing but the kill can end its wait.
    let (idle_end, idle_peer) = channel::create();
    let (idle_code, idle_ok) =
        kill_before_run("idle", crate::apps::IDLE, alloc::vec![chan_entry(idle_end)]);
    // (b) A child marked before it ran whose first call is exit(0x55) reports the kill. (a) and
    // (b) hold whichever safe point delivers the kill, so they do not pin K1 or K2 down: mutants
    // of either fix pass them. (d)–(f) do.
    let (exiter_code, exiter_ok) = kill_before_run("exiter", crate::apps::EXITER, Vec::new());
    // (d)–(f) K1, K2: the kill lands where one from another CPU can — while the child runs in
    // the kernel past its last safe point (test-kernel injection points, `sched::kill_point`):
    // just before object_wait_many blocks (d) or sleep sleeps (e), and in exit before the thread
    // ends (f). Without K1 the child would block or sleep for ever; without K2, (f) would report
    // 0x55. `start`, when given, is written to the child once its point is armed.
    let kill_at = |name: &str,
                   image: &[u8],
                   handles: Vec<Entry>,
                   point: u64,
                   start: Option<&Endpoint>|
     -> (u64, bool) {
        let object = Arc::new(ProcessObject::new());
        let was = interrupts::save_and_disable();
        let spawned = crate::user::spawn_elf_with(image, 1, handles, object.clone());
        if let Ok(pid) = spawned {
            sched::arm_kill_point(pid, point);
        }
        interrupts::restore(was);
        if let Err(e) = spawned {
            kprintln!(
                "OSX|{}|ktest|kill_edges|{}_error={}",
                BUILD_ID,
                name,
                e.code()
            );
            fail("child did not load")
        }
        if let Some(peer) = start {
            let _ = peer.write(Message {
                bytes: b"START sleeper".to_vec(),
                handles: Vec::new(),
            });
        }
        let exited = sched::poll_until(sched::ticks() + 5000, || object.exit_code().is_some());
        (object.exit_code().unwrap_or(u64::MAX), exited)
    };
    let (block_end, block_peer) = channel::create();
    let (at_block, at_block_ok) = kill_at(
        "block",
        crate::apps::IDLE,
        alloc::vec![chan_entry(block_end)],
        sched::KILL_AT_BLOCK,
        None,
    );
    let (sleep_end, sleep_peer) = channel::create();
    let (at_sleep, at_sleep_ok) = kill_at(
        "sleep",
        crate::apps::SVC,
        alloc::vec![chan_entry(sleep_end)],
        sched::KILL_AT_SLEEP,
        Some(&sleep_peer),
    );
    let (at_exit, at_exit_ok) = kill_at(
        "exit",
        crate::apps::EXITER,
        Vec::new(),
        sched::KILL_AT_EXIT,
        None,
    );
    drop((block_peer, sleep_peer));
    // (c) K3: a frozen process stops, whatever timeout it waits with, and can still be killed.
    let (tick_end, tick_peer) = channel::create();
    let tick_obj = Arc::new(ProcessObject::new());
    let tick_pid = match crate::user::spawn_elf_with(
        crate::apps::SVC,
        1,
        alloc::vec![chan_entry(tick_end)],
        tick_obj.clone(),
    ) {
        Ok(p) => p,
        Err(e) => {
            kprintln!(
                "OSX|{}|ktest|kill_edges|ticker_error={}",
                BUILD_ID,
                e.code()
            );
            fail("ticker did not load")
        }
    };
    let _ = tick_peer.write(Message {
        bytes: b"START ticker".to_vec(),
        handles: Vec::new(),
    });
    // Counts the `T`s that arrive during `ticks`.
    let count_ticks = |ticks: u64| -> usize {
        let end = sched::ticks() + ticks;
        let mut n = 0;
        loop {
            while let Ok(m) = tick_peer.read(16, 1, None) {
                n += usize::from(m.bytes == b"T");
            }
            if sched::ticks() >= end {
                return n;
            }
            sched::poll_until(sched::ticks() + 5, || false);
        }
    };
    let before = count_ticks(100);
    let frozen = sched::freeze_pid(tick_pid);
    // At most one `T` was already on its way (the ticker may have been running); let it land.
    let _ = count_ticks(20);
    let while_frozen = count_ticks(200);
    let tick_marked = sched::kill_process(tick_pid, EXIT_KILLED);
    let tick_exited = sched::poll_until(sched::ticks() + 5000, || tick_obj.exit_code().is_some());
    let tick_code = tick_obj.exit_code().unwrap_or(u64::MAX);
    drop((idle_peer, tick_peer, tick_obj));
    let gone = sched::poll_until(sched::ticks() + 2000, || sched::stats().processes == 0);
    let procs = sched::stats().processes;
    let frames = frames0 as i64 - pmm::stats().free_frames as i64;
    kprintln!(
        "OSX|{}|ktest|kill_edges|ticks_before={}|ticks_while_frozen={}",
        BUILD_ID,
        before,
        while_frozen
    );
    kprintln!(
        "OSX|{}|ktest|kill_edges|idle_before_run={:#x}:{}|exiter_before_run={:#x}:{}|kill_at_block={:#x}:{}|kill_at_sleep={:#x}:{}|kill_at_exit={:#x}:{}|ticker_ticked={}|frozen={}|ticker_stopped={}|ticker_killed={:#x}:{}|processes_after={}|frames_delta={}",
        BUILD_ID,
        idle_code,
        u8::from(idle_ok),
        exiter_code,
        u8::from(exiter_ok),
        at_block,
        u8::from(at_block_ok),
        at_sleep,
        u8::from(at_sleep_ok),
        at_exit,
        u8::from(at_exit_ok),
        u8::from(before >= 5),
        u8::from(frozen),
        u8::from(while_frozen == 0),
        tick_code,
        u8::from(tick_marked && tick_exited),
        procs,
        frames
    );
    if idle_code != EXIT_KILLED || !idle_ok || exiter_code != EXIT_KILLED || !exiter_ok {
        fail("a child killed before it ran did not end with EXIT_KILLED")
    }
    if at_block != EXIT_KILLED || !at_block_ok || at_sleep != EXIT_KILLED || !at_sleep_ok {
        fail("a kill that landed just before a block or a sleep was lost (K1)")
    }
    if at_exit != EXIT_KILLED || !at_exit_ok {
        fail("a process killed inside its exit did not report EXIT_KILLED (K2)")
    }
    if before < 5 || !frozen || while_frozen != 0 {
        fail("a frozen process kept running through its timed waits (K3)")
    }
    if tick_code != EXIT_KILLED || !tick_marked || !tick_exited {
        fail("process_kill did not end a frozen process")
    }
    if !gone || procs != 0 || frames != 0 {
        fail("kill_edges left a process or leaked frames")
    }
    pass("a kill before the first run, just before a block or a sleep, inside exit, and on a frozen timed wait all end in EXIT_KILLED")
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

// ---- WP-46: jobs ---------------------------------------------------------------------------

/// The exit code of the `jobs` app (user/apps/jobs) mapped to the number of its phases that
/// passed (it prints `jobs|phase=<n>|<name>=ok` for each; 0x4A = all seven).
fn jobs_phases_ok(code: u64) -> u32 {
    match code {
        0x4A => 7,
        0xE0..=0xE7 | 0xDE => 0,
        0xE8 => 1,
        0xE9..=0xEA => 2,
        0xEB..=0xF2 | 0xDD | 0xDF => 3,
        0xF3..=0xF7 => 4,
        0xF8..=0xFC => 5,
        0xFD..=0xFF => 6,
        _ => 0,
    }
}

/// Part 1 of TST-M6-JOB-KILL (mutant M153): the locked dead-job check in `spawn_user_with`
/// (sched/mod.rs:429), which `process_spawn_in`'s early check hides from user space. A process
/// object in a killed job must not start: the spawn is refused (`AsError::Spawn`), the object is
/// never bound and learns the stillborn exit (u64::MAX), the initial handle is closed (its peer
/// sees PEER_CLOSED), and nothing leaks.
fn job_spawn_dead() -> bool {
    use crate::object::job::{self, Job};
    use crate::object::process::ProcessObject;
    let image = match crate::loader::read_image(b"/SYSTEM/IDLE.ELF") {
        Ok(i) => i,
        Err(e) => {
            kprintln!(
                "OSX|{}|ktest|job_spawn_dead|image_error={}",
                BUILD_ID,
                e.code()
            );
            fail("IDLE.ELF is not on the volume")
        }
    };
    let obj0 = object::stats();
    let frames0 = pmm::stats().free_frames;
    let dead = match Job::new_child(&job::root()) {
        Ok(j) => j,
        Err(_) => fail("job_spawn_dead: no child job of the root"),
    };
    // No member yet: the pass only marks the job.
    let marked = sched::kill_job(&dead, crate::syscall::EXIT_KILLED);
    let (keep, give) = channel::create();
    let object = Arc::new(ProcessObject::new_in(dead.clone()));
    let r = crate::user::spawn_elf_with(
        &image,
        1,
        alloc::vec![Entry {
            object: Object::Channel(give),
            rights: Rights::CHANNEL_DEFAULT,
        }],
        object.clone(),
    );
    let refused = matches!(r, Err(ElfError::Space(addrspace::AsError::Spawn)));
    let closed = matches!(keep.read(16, 4, None), Err(ChannelError::PeerClosed));
    let unbound = object.pid().is_none() && object.exit_code() == Some(u64::MAX);
    drop((keep, object, dead));
    let frames_delta = frames0 as i64 - pmm::stats().free_frames as i64;
    let clean = object::stats() == obj0;
    let ok = marked && refused && closed && unbound && clean && frames_delta == 0;
    kprintln!(
        "OSX|{}|ktest|job_spawn_dead|marked={}|refused={}|peer_closed={}|unbound={}|clean={}|frames_delta={}|ok={}",
        BUILD_ID,
        u8::from(marked),
        u8::from(refused),
        u8::from(closed),
        u8::from(unbound),
        u8::from(clean),
        frames_delta,
        u8::from(ok)
    );
    ok
}

/// TST-M6-JOB-KILL (REQ-M6-003, WP-46, syscall.md v1.13 §5; mutants M151-M153). Part 1:
/// `job_spawn_dead` (the locked check). Part 2: `/SYSTEM/JOBS.ELF` from the volume, started with a
/// channel as its bootstrap handle and the root job (JOB_DEFAULT) right after it,
/// proves the contract from user space in seven phases and exits 0x4A. The test checks its
/// exit, that every process it started is gone, and that no frame and no object is left.
fn job_kill_all() -> ! {
    if crate::fs::mount().is_err() {
        fail("volume did not mount")
    }
    let dead_ok = job_spawn_dead();
    let image = match crate::loader::read_image(b"/SYSTEM/JOBS.ELF") {
        Ok(i) => i,
        Err(e) => {
            kprintln!(
                "OSX|{}|ktest|job_kill_all|image_error={}",
                BUILD_ID,
                e.code()
            );
            fail("JOBS.ELF is not on the volume")
        }
    };
    let obj0 = object::stats();
    let frames0 = pmm::stats().free_frames;
    let procs0 = sched::stats().processes;
    // Our end stays open and silent: the app reads no role mark on it, so it runs as the parent.
    let (keep, give) = channel::create();
    let mut initial = alloc::vec![Entry {
        object: Object::Channel(give),
        rights: Rights::CHANNEL_DEFAULT,
    }];
    // Slot 1: the root job (initial handles are consecutive, syscall.md §5).
    initial.push(Entry {
        object: Object::Job(crate::object::job::root()),
        rights: Rights::JOB_DEFAULT,
    });
    let object = Arc::new(crate::object::process::ProcessObject::new());
    let pid = match crate::user::spawn_elf_with(&image, 1, initial, object.clone()) {
        Ok(p) => p,
        Err(e) => {
            kprintln!("OSX|{}|ktest|job_kill_all|error={}", BUILD_ID, e.code());
            fail("jobs did not load")
        }
    };
    let code = sched::wait_process(pid).unwrap_or(u64::MAX);
    drop((object, keep));
    // Its children were all awaited by the app; give the reaper time to finish them anyway.
    let _ = sched::poll_until(sched::ticks() + 1000, || {
        sched::stats().processes == procs0 && object::stats() == obj0
    });
    let processes_after = sched::stats().processes.saturating_sub(procs0);
    let frames_delta = frames0 as i64 - pmm::stats().free_frames as i64;
    let clean = object::stats() == obj0;
    let ok = dead_ok && code == 0x4A && processes_after == 0 && frames_delta == 0 && clean;
    kprintln!(
        "OSX|{}|ktest|job_kill_all|exit={:#x}|phases={}|processes_after={}|frames_delta={}|clean={}|ok={}",
        BUILD_ID,
        code,
        jobs_phases_ok(code),
        processes_after,
        frames_delta,
        u8::from(clean),
        u8::from(ok)
    );
    if !dead_ok {
        fail("a process entered a killed job (the locked check in spawn_user_with)")
    }
    if code != 0x4A {
        fail("the job contract did not hold (see exit and the jobs|phase lines)")
    }
    if processes_after != 0 || frames_delta != 0 || !clean {
        fail("job_kill left a process, a frame or an object behind")
    }
    pass("job_kill ends every process in a job and below it, a killed job admits nothing, and a job containing the caller cannot be killed")
}
