//! Threads, processes and the scheduler (WP-15, ADR-0010). Fixed priorities 0 (highest) ..= 3,
//! round-robin within a priority (the thread picked least recently goes first), a time slice
//! counted in timer ticks and preemption from the timer interrupt's return path.
//!
//! State lives in one `IrqSpinLock`: every entry point takes it with interrupts disabled and
//! releases it *before* the context switch, so no lock and no reference to the state is held
//! across `switch_to` (the resumed thread takes the lock again to reap). One CPU; WP-20 adds the
//! per-CPU queues SMP needs.
//!
//! Thread 0 is the boot context (kmain): it owns the guarded kernel stack and acts as the idle
//! thread — it is always runnable and waits with `hlt` when nothing else is ready. Every other
//! thread gets its own guarded kernel stack, which is also its trap stack (TSS.RSP0 and the
//! SYSCALL entry stack) while it runs in ring 3. Exited threads are reaped by the next thread
//! that comes back from a switch: stack freed, exit code kept for `join`/`wait_process`; a
//! process whose last thread exited is destroyed then too, once its address space is no longer
//! the active one.

use alloc::vec::Vec;

use crate::arch;
use crate::arch::context::{self, Start};
use crate::mm::addrspace::UserSpace;
use crate::mm::vmm::{self, StackInfo};
use crate::sync::IrqSpinLock;

pub const PRIORITIES: u8 = 4;
/// Ticks a thread may run before the timer asks for a reschedule (1 kHz timer: 10 ms).
pub const QUANTUM_TICKS: u32 = 10;
pub const THREAD_STACK_SIZE: u64 = 32 * 1024;
/// Exit codes kept for `join`/`wait_process` (oldest dropped first).
const FINISHED_KEEP: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Running,
    Sleeping { until: u64 },
    Exited { code: u64 },
}

pub struct Thread {
    pub id: u32,
    pub process: Option<u32>,
    pub state: State,
    pub priority: u8,
    pub kstack: StackInfo,
    /// Kernel stack pointer saved by the last switch away from this thread.
    pub rsp: u64,
    pub slice: u32,
    /// Sequence number of the last time the thread was picked or gave the CPU up; the smallest
    /// wins a tie within a priority (round-robin).
    pub last_pick: u64,
    /// Whether the stack belongs to the thread (false for the boot thread, whose stack is the
    /// kernel's own).
    owns_stack: bool,
}

pub struct Process {
    pub id: u32,
    pub space: UserSpace,
    pub threads: u32,
    pub exit_code: Option<u64>,
}

struct Sched {
    threads: Vec<Thread>,
    processes: Vec<Process>,
    current: u32,
    next_tid: u32,
    next_pid: u32,
    seq: u64,
    need_resched: bool,
    ticks: u64,
    switches: u64,
    preemptions: u64,
    finished_threads: Vec<(u32, u64)>,
    finished_processes: Vec<(u32, u64)>,
    kernel_cr3: u64,
}

static SCHED: IrqSpinLock<Option<Sched>> = IrqSpinLock::new("sched", None);

/// A switch decided by `prepare_switch`, to be performed right away with interrupts disabled.
struct Switch {
    prev_slot: *mut u64,
    next_rsp: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SpawnError;

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub threads: usize,
    pub processes: usize,
    pub switches: u64,
    pub preemptions: u64,
    pub ticks: u64,
    pub current: u32,
}

/// Runs `f` on the scheduler state under its lock (interrupts disabled meanwhile).
fn with<R>(f: impl FnOnce(&mut Sched) -> R) -> R {
    let mut g = SCHED.lock();
    f(g.as_mut().expect("scheduler not initialised"))
}

/// Adopts the boot context as thread 0 (priority 1; the idle fallback) and turns the timer's
/// preemption on. `boot_stack` is the kernel stack kmain runs on.
pub fn init(boot_stack: StackInfo, kernel_cr3: u64) {
    let t0 = Thread {
        id: 0,
        process: None,
        state: State::Running,
        priority: 1,
        kstack: boot_stack,
        rsp: 0,
        slice: QUANTUM_TICKS,
        last_pick: 0,
        owns_stack: false,
    };
    // Capacities up front, so the first few spawns do not grow the vectors (keeps the boot
    // self-check's frame balance exact).
    let mut threads = Vec::with_capacity(8);
    threads.push(t0);
    let mut g = SCHED.lock();
    assert!(g.is_none(), "scheduler initialised twice");
    *g = Some(Sched {
        threads,
        processes: Vec::with_capacity(4),
        current: 0,
        next_tid: 1,
        next_pid: 1,
        seq: 1,
        need_resched: false,
        ticks: 0,
        switches: 0,
        preemptions: 0,
        finished_threads: Vec::with_capacity(16),
        finished_processes: Vec::with_capacity(16),
        kernel_cr3,
    });
}

fn new_thread(
    s: &mut Sched,
    process: Option<u32>,
    priority: u8,
    kind: Start,
    a: u64,
    b: u64,
) -> Result<u32, SpawnError> {
    let kstack = vmm::alloc_kernel_stack(THREAD_STACK_SIZE).map_err(|_| SpawnError)?;
    let rsp = context::prepare_stack(kstack.top(), kind, a, b);
    let id = s.next_tid;
    s.next_tid += 1;
    s.threads.push(Thread {
        id,
        process,
        state: State::Ready,
        priority: priority.min(PRIORITIES - 1),
        kstack,
        rsp,
        slice: QUANTUM_TICKS,
        last_pick: 0,
        owns_stack: true,
    });
    Ok(id)
}

/// Spawns a kernel thread running `entry(arg)`; its return value is the thread's exit code.
pub fn spawn_kernel(
    entry: context::KernelEntry,
    arg: u64,
    priority: u8,
) -> Result<u32, SpawnError> {
    with(|s| new_thread(s, None, priority, Start::Kernel, entry as usize as u64, arg))
}

/// Creates a process around `space` with one thread starting in ring 3 at `rip` with stack
/// `rsp`. Returns (pid, tid).
pub fn spawn_user(
    space: UserSpace,
    rip: u64,
    rsp: u64,
    priority: u8,
) -> Result<(u32, u32), SpawnError> {
    if !arch::syscall::user_rip_ok(rip) {
        let _ = space.destroy();
        return Err(SpawnError);
    }
    with(|s| {
        let pid = s.next_pid;
        s.next_pid += 1;
        s.processes.push(Process {
            id: pid,
            space,
            threads: 1,
            exit_code: None,
        });
        match new_thread(s, Some(pid), priority, Start::User, rip, rsp) {
            Ok(tid) => Ok((pid, tid)),
            Err(e) => {
                if let Some(p) = s.processes.pop() {
                    let _ = p.space.destroy();
                }
                Err(e)
            }
        }
    })
}

fn index_of(s: &Sched, tid: u32) -> Option<usize> {
    s.threads.iter().position(|t| t.id == tid)
}

/// The thread to run next: Ready (or the Running current) with the smallest priority value,
/// ties broken by the smallest `last_pick`, then by position.
fn pick_next(s: &Sched) -> usize {
    let mut best: Option<usize> = None;
    for (i, t) in s.threads.iter().enumerate() {
        let runnable = t.state == State::Ready || (t.id == s.current && t.state == State::Running);
        if !runnable {
            continue;
        }
        best = match best {
            None => Some(i),
            Some(b) => {
                let bt = &s.threads[b];
                if t.priority < bt.priority
                    || (t.priority == bt.priority && t.last_pick < bt.last_pick)
                {
                    Some(i)
                } else {
                    Some(b)
                }
            }
        };
    }
    best.unwrap_or_else(|| index_of(s, 0).expect("thread 0 exists"))
}

/// Books the switch to the best runnable thread: the current thread goes to the back of its
/// priority's round, the next one becomes Running, its trap stack and address space are made
/// current. Returns `None` when the current thread keeps the CPU. The caller performs the
/// returned switch immediately, after dropping the lock, with interrupts still disabled.
fn prepare_switch(s: &mut Sched) -> Option<Switch> {
    let cur_i = index_of(s, s.current).expect("current thread exists");
    s.need_resched = false;
    s.seq += 1;
    s.threads[cur_i].last_pick = s.seq;
    let next_i = pick_next(s);
    if next_i == cur_i {
        // Only a Running current thread can be picked again; it starts a fresh slice.
        s.threads[cur_i].slice = QUANTUM_TICKS;
        return None;
    }
    if s.threads[cur_i].state == State::Running {
        s.threads[cur_i].state = State::Ready;
    }
    s.seq += 1;
    let seq = s.seq;
    let next_tid = {
        let n = &mut s.threads[next_i];
        n.state = State::Running;
        n.slice = QUANTUM_TICKS;
        n.last_pick = seq;
        n.id
    };
    let target_cr3 = match s.threads[next_i].process {
        Some(pid) => s
            .processes
            .iter()
            .find(|p| p.id == pid)
            .map(|p| p.space.cr3())
            .unwrap_or(s.kernel_cr3),
        None => s.kernel_cr3,
    };
    arch::syscall::set_trap_stack(s.threads[next_i].kstack.top());
    if arch::paging::read_cr3() != target_cr3 {
        arch::paging::switch_cr3(target_cr3);
    }
    s.current = next_tid;
    s.switches += 1;
    Some(Switch {
        prev_slot: &mut s.threads[cur_i].rsp,
        next_rsp: s.threads[next_i].rsp,
    })
}

/// Performs a prepared switch (interrupts disabled, lock released) and, once this thread is
/// resumed, reaps what exited meanwhile.
fn perform(sw: Option<Switch>) -> bool {
    let Some(sw) = sw else {
        return false;
    };
    // SAFETY: both stacks are kernel stacks this module owns; `next_rsp` was saved by switch_to
    // or built by prepare_stack; interrupts are disabled, so between `prepare_switch` and here
    // nothing ran that could move the thread vector, and `prev_slot` is written by the switch
    // before any other code runs; nothing borrows the scheduler state across the call (the lock
    // was dropped).
    unsafe { context::switch_to(sw.prev_slot, sw.next_rsp) };
    with(reap);
    true
}

/// Frees exited threads (not the current one) and processes whose last thread exited and whose
/// address space is not the active one.
fn reap(s: &mut Sched) {
    let current = s.current;
    let mut i = 0;
    while i < s.threads.len() {
        let exited = match s.threads[i].state {
            State::Exited { code } if s.threads[i].id != current => Some(code),
            _ => None,
        };
        if let Some(code) = exited {
            let t = s.threads.swap_remove(i);
            if t.owns_stack {
                vmm::free_kernel_stack(t.kstack);
            }
            // Kernel threads are joined by id; a process's threads are accounted through the
            // process (wait_process), so no record is kept for them.
            if t.process.is_none() {
                if s.finished_threads.len() >= FINISHED_KEEP {
                    s.finished_threads.remove(0);
                }
                s.finished_threads.push((t.id, code));
            }
        } else {
            i += 1;
        }
    }
    let active_cr3 = arch::paging::read_cr3();
    let mut i = 0;
    while i < s.processes.len() {
        let p = &s.processes[i];
        if p.threads == 0 && p.exit_code.is_some() && p.space.cr3() != active_cr3 {
            let p = s.processes.swap_remove(i);
            let code = p.exit_code.unwrap_or(0);
            let _ = p.space.destroy();
            if s.finished_processes.len() >= FINISHED_KEEP {
                s.finished_processes.remove(0);
            }
            s.finished_processes.push((p.id, code));
        } else {
            i += 1;
        }
    }
}

/// Timer hook (interrupt context): advances time, wakes sleepers, expires the slice. Before
/// `init` it does nothing.
pub fn tick() {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else {
        return;
    };
    s.ticks += 1;
    let now = s.ticks;
    let cur_prio = index_of(s, s.current)
        .map(|i| s.threads[i].priority)
        .unwrap_or(PRIORITIES);
    let mut wake = false;
    for t in s.threads.iter_mut() {
        if let State::Sleeping { until } = t.state {
            if until <= now {
                t.state = State::Ready;
                wake |= t.priority <= cur_prio;
            }
        }
    }
    if let Some(i) = index_of(s, s.current) {
        let t = &mut s.threads[i];
        t.slice = t.slice.saturating_sub(1);
        if t.slice == 0 {
            s.need_resched = true;
        }
    }
    s.need_resched |= wake;
}

/// Called by the interrupt dispatcher after EOI, with interrupts disabled: switches if the
/// timer asked for it. The interrupted thread resumes here later and returns through its own
/// interrupt frame.
pub fn preempt_point() {
    let sw = {
        let mut g = SCHED.lock();
        let Some(s) = g.as_mut() else {
            return;
        };
        if !s.need_resched {
            return;
        }
        s.preemptions += 1;
        prepare_switch(s)
    };
    perform(sw);
}

/// Gives the CPU to another Ready thread of equal or better priority, if any; returns whether
/// a switch happened.
pub fn yield_now() -> bool {
    let was = arch::interrupts::save_and_disable();
    let sw = with(prepare_switch);
    let switched = perform(sw);
    arch::interrupts::restore(was);
    switched
}

/// Sleeps for at least `ticks` timer ticks. The boot thread, which must stay runnable, waits
/// by halting instead of blocking.
pub fn sleep_ticks(ticks: u64) {
    let was = arch::interrupts::save_and_disable();
    let (until, boot) = with(|s| (s.ticks + ticks, s.current == 0));
    if boot {
        while with(|s| s.ticks) < until {
            context::idle_wait();
        }
    } else {
        let sw = with(|s| {
            let i = index_of(s, s.current).expect("current thread exists");
            s.threads[i].state = State::Sleeping { until };
            prepare_switch(s)
        });
        perform(sw);
    }
    arch::interrupts::restore(was);
}

/// Ends the current thread (never returns). For the last thread of a process the exit code
/// becomes the process's.
pub fn exit_current(code: u64) -> ! {
    arch::interrupts::disable();
    let sw = with(|s| {
        assert!(s.current != 0, "the boot thread cannot exit");
        let i = index_of(s, s.current).expect("current thread exists");
        s.threads[i].state = State::Exited { code };
        if let Some(pid) = s.threads[i].process {
            if let Some(p) = s.processes.iter_mut().find(|p| p.id == pid) {
                p.threads -= 1;
                if p.threads == 0 {
                    p.exit_code = Some(code);
                }
            }
        }
        prepare_switch(s)
    });
    if sw.is_none() {
        panic!("K_E_SCHED_NO_NEXT");
    }
    perform(sw);
    unreachable!("an exited thread was resumed")
}

/// Waits until kernel thread `tid` has exited and returns its code (None for an unknown thread
/// or a process thread, which is waited for through its process).
pub fn join(tid: u32) -> Option<u64> {
    loop {
        let found = with(|s| {
            if let Some(pos) = s.finished_threads.iter().position(|(t, _)| *t == tid) {
                return Some(Some(s.finished_threads.remove(pos).1));
            }
            if index_of(s, tid).is_none() {
                return Some(None);
            }
            None
        });
        if let Some(r) = found {
            return r;
        }
        if !yield_now() {
            context::idle_wait();
        }
    }
}

/// Waits until process `pid` has exited (its last thread) and returns its exit code.
pub fn wait_process(pid: u32) -> Option<u64> {
    loop {
        let found = with(|s| {
            if let Some(pos) = s.finished_processes.iter().position(|(p, _)| *p == pid) {
                return Some(Some(s.finished_processes.remove(pos).1));
            }
            if !s.processes.iter().any(|p| p.id == pid) {
                return Some(None);
            }
            None
        });
        if let Some(r) = found {
            return r;
        }
        if !yield_now() {
            context::idle_wait();
        }
    }
}

pub fn current_tid() -> u32 {
    with(|s| s.current)
}

pub fn stats() -> Stats {
    with(|s| Stats {
        threads: s.threads.len(),
        processes: s.processes.len(),
        switches: s.switches,
        preemptions: s.preemptions,
        ticks: s.ticks,
        current: s.current,
    })
}
