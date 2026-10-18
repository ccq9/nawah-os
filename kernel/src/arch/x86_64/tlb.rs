//! TLB shootdown across CPUs (WP-20, ADR-0015 §8). A CPU that changes or removes a kernel
//! mapping other CPUs may have cached asks every other online CPU to invalidate it, and waits
//! until each one has. No lock is involved, and the wait cannot deadlock: a waiting sender keeps
//! servicing the requests addressed to it, and so does every CPU spinning on an `IrqSpinLock`
//! (`arch::spin_hint`), so a target that is itself waiting — on a lock or on its own shootdown —
//! still answers.
//!
//! Protocol: sender `s` writes its request slot `REQ[s]`, sets bit `s` in `PENDING[t]` of every
//! target `t`, sends the IPI, then spins until bit `s` is clear in all of them. A target reads
//! its mask, then every request named by it, invalidates, and clears exactly the bits it
//! served. `REQ[s]` changes only while no target holds bit `s`, so a served request is never
//! torn. User mappings need none of this: a process's threads run on one CPU (ADR-0015 §5).
//!
//! References: Intel SDM Vol. 3A §4.10.5 (propagation of page-table changes to multiple
//! processors: the modifying processor must make the others invalidate), §4.10.4.1 INVLPG.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::gdt::MAX_CPUS;
use super::{apic, irq, paging, smp};

/// Per target: bitmask of senders with an outstanding request for it.
static PENDING: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// Per sender: the range to invalidate (page-aligned start, byte length).
static REQ_ADDR: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static REQ_LEN: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Requests this kernel served on behalf of other CPUs (diagnostics, tests).
static SERVED: AtomicU64 = AtomicU64::new(0);
/// Shootdowns sent (diagnostics).
static SENT: AtomicU64 = AtomicU64::new(0);

/// Above this many pages a target reloads CR3 instead of invalidating page by page (no global
/// pages are used, so a CR3 write flushes everything).
const INVLPG_LIMIT: u64 = 16;

fn flush_range(addr: u64, len: u64) {
    let pages = len.div_ceil(paging::PAGE_4K);
    if pages > INVLPG_LIMIT {
        paging::switch_cr3(paging::read_cr3());
        return;
    }
    let mut p = addr;
    for _ in 0..pages {
        paging::invlpg(p);
        p += paging::PAGE_4K;
    }
}

/// Serves the requests addressed to this CPU, if any. Called from the IPI handler, from a
/// sender's wait loop and from every lock's spin loop.
pub fn service_pending() {
    let me = super::cpu_id() as usize;
    if me >= MAX_CPUS {
        return;
    }
    let mask = PENDING[me].load(Ordering::Acquire);
    if mask == 0 {
        return;
    }
    for s in 0..MAX_CPUS {
        if mask & (1 << s) != 0 {
            let addr = REQ_ADDR[s].load(Ordering::Acquire);
            let len = REQ_LEN[s].load(Ordering::Acquire);
            flush_range(addr, len);
            SERVED.fetch_add(1, Ordering::Relaxed);
        }
    }
    PENDING[me].fetch_and(!mask, Ordering::AcqRel);
}

/// Makes every other online CPU invalidate `[addr, addr + len)` (the caller already did so
/// locally) and returns once all of them have. Safe to call with interrupts disabled and with
/// locks held, for the reason given in the module comment.
pub fn shootdown(addr: u64, len: u64) {
    let me = super::cpu_id() as usize;
    let targets = smp::online_mask() & !(1u32 << me);
    if targets == 0 || len == 0 {
        return;
    }
    let addr = addr & !(paging::PAGE_4K - 1);
    REQ_ADDR[me].store(addr, Ordering::Release);
    REQ_LEN[me].store(len, Ordering::Release);
    for (t, pending) in PENDING.iter().enumerate() {
        if targets & (1 << t) != 0 {
            pending.fetch_or(1 << me, Ordering::AcqRel);
        }
    }
    for t in 0..MAX_CPUS {
        if targets & (1 << t) != 0 {
            apic::send_ipi(smp::apic_id_of(t), irq::TLB_VECTOR);
        }
    }
    SENT.fetch_add(1, Ordering::Relaxed);
    loop {
        service_pending();
        let outstanding = (0..MAX_CPUS).any(|t| {
            targets & (1 << t) != 0 && PENDING[t].load(Ordering::Acquire) & (1 << me) != 0
        });
        if !outstanding {
            break;
        }
        core::hint::spin_loop();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub sent: u64,
    pub served: u64,
}

pub fn counters() -> Counters {
    Counters {
        sent: SENT.load(Ordering::Relaxed),
        served: SERVED.load(Ordering::Relaxed),
    }
}
