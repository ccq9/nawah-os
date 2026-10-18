//! In-kernel tests (test kernel only, feature `ktest`). Origin of the design: Sol OS ADR-010.
//!
//! The host runner passes the test name through QEMU fw_cfg (`opt/nawah/test`) and runs each test
//! in its own QEMU boot, because most tests end in a fatal exception. The result reaches the host
//! as the QEMU exit code plus serial markers (`platform/pc-qemu/target.json`, suite M2).
//! A missing or unknown name is an explicit failure, so a lost name cannot pass by accident.

use crate::arch::{fwcfg, ktest as inject, qemu};
use crate::mm::pmm::{self, Frame, PmmError};
use crate::BUILD_ID;

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

/// Allocates until None: the count equals the free count, no panic, and further allocations keep
/// returning None.
fn pmm_exhaust() -> ! {
    let before = pmm::stats();
    let mut count: u64 = 0;
    while pmm::alloc_frame().is_some() {
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
    kprintln!("OSX|{}|ktest|pmm_exhaust|count={}", BUILD_ID, count);
    pass("exhaustion returns None without panic")
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
