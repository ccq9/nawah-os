//! Threads, processes and the scheduler (WP-15, ADR-0010). Fixed priorities 0 (highest) ..= 3,
//! round-robin within a priority (the thread picked least recently goes first), a time slice
//! counted in timer ticks and preemption from the timer interrupt's return path.
//!
//! State lives in one `IrqSpinLock`: every entry point takes it with interrupts disabled and
//! releases it *before* the context switch, so no lock and no reference to the state is held
//! across `switch_to` (the resumed thread takes the lock again to reap).
//!
//! SMP (WP-20, ADR-0015 §5-7): threads are pinned to the CPU that created them (`Thread::cpu`;
//! `spawn_on` for tests); each CPU has its own current thread, reschedule flag and idle thread
//! (CPU 0: thread 0; an AP: the context `adopt_ap` registers), all in the one table under the
//! one lock. Time (ticks, sleeps) advances on CPU 0 only; AP timers expire slices. A thread that
//! switched away is `on_cpu` until the next scheduling decision on its CPU proves its stack is
//! free, and only then may it be reaped — from any CPU. A thread made runnable on another CPU
//! gets that CPU a reschedule IPI.
//!
//! Blocking (WP-16): `block_current`/`wake` with a wake token per thread, so a wake-up that
//! arrives between the decision to block and the switch is kept, not lost.
//!
//! Thread 0 is the boot context (kmain): it owns the guarded kernel stack and acts as the idle
//! thread — it is always runnable and waits with `hlt` when nothing else is ready. Every other
//! thread gets its own guarded kernel stack, which is also its trap stack (TSS.RSP0 and the
//! SYSCALL entry stack) while it runs in ring 3. Exited threads are reaped by the next thread
//! that comes back from a switch: stack freed, exit code kept for `join`/`wait_process`; a
//! process whose last thread exited is destroyed then too, once its address space is no longer
//! the active one.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch;
use crate::arch::context::{self, Start};
use crate::arch::smp::MAX_CPUS;
use crate::mm::addrspace::UserSpace;
use crate::mm::vmm::{self, StackInfo};
use crate::object::handle::Entry;
use crate::object::process::ProcessObject;
use crate::object::HandleTable;
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
    Sleeping {
        until: u64,
    },
    /// Waiting for `wake` (channel read, WP-16); with a deadline (object_wait_many timeout,
    /// WP-23) the timer makes it Ready again at `until` as it does for sleepers.
    Blocked,
    BlockedUntil {
        until: u64,
    },
    Exited {
        code: u64,
    },
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
    /// Wake-ups that arrived while the thread was not blocked; `block_current` consumes one
    /// instead of blocking, so a wake-up that races the block is never lost.
    wake_tokens: u32,
    /// Whether the stack belongs to the thread (false for the boot thread, whose stack is the
    /// kernel's own, and for an AP's idle thread).
    owns_stack: bool,
    /// The CPU this thread runs on (WP-20: never migrates).
    pub cpu: u8,
    /// Inside `join`/`wait_process`: competes at the lowest priority until it returns, so a
    /// waiter never starves what it may be waiting for (WP-22, ADR-0010 amendment).
    waiting: bool,
    /// True from the moment the thread is picked until a later scheduling decision on its CPU
    /// shows its stack is no longer in use; an Exited thread is reaped only when false.
    on_cpu: bool,
}

pub struct Process {
    pub id: u32,
    pub space: UserSpace,
    pub threads: u32,
    pub exit_code: Option<u64>,
    /// Handle table (WP-16), shared with the syscall layer so operations run outside the
    /// scheduler lock.
    pub handles: Arc<IrqSpinLock<HandleTable>>,
    /// The waitable view a parent holds (WP-23); told the exit code once the process is gone.
    pub object: Option<Arc<ProcessObject>>,
}

impl Process {
    /// Releases everything the process owned: handles first (objects may hold frames and
    /// wake other threads — so this must run outside the scheduler lock), then the space;
    /// finally the parent's process object learns the exit (it wakes waiters: no lock held).
    fn finish(self, code: u64) {
        drop(self.handles);
        let _ = self.space.destroy();
        if let Some(o) = self.object {
            o.finish(code);
        }
    }
}

struct Sched {
    threads: Vec<Thread>,
    processes: Vec<Process>,
    /// Per CPU: the running thread, the thread that ran before it (still `on_cpu`), the idle
    /// thread, and whether a switch is wanted at the next preemption point.
    current: [u32; MAX_CPUS],
    prev: [Option<u32>; MAX_CPUS],
    idle: [u32; MAX_CPUS],
    need_resched: [bool; MAX_CPUS],
    next_tid: u32,
    next_pid: u32,
    seq: u64,
    ticks: u64,
    switches: u64,
    preemptions: u64,
    finished_threads: Vec<(u32, u64)>,
    finished_processes: Vec<(u32, u64)>,
    /// Removed from the tables but not yet published as finished: their stacks and address
    /// spaces are being released outside the lock (WP-20). `join`/`wait_process` keep waiting
    /// for these, so a waiter never measures before the resources are back.
    reaping_threads: Vec<u32>,
    reaping_processes: Vec<u32>,
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

/// This CPU's index (stable while the scheduler lock is held: interrupts are off and threads
/// never migrate).
fn me() -> usize {
    arch::cpu_id() as usize
}

/// The priority a thread competes with: its own, or the lowest while it waits.
fn effective_prio(t: &Thread) -> u8 {
    if t.waiting {
        PRIORITIES - 1
    } else {
        t.priority
    }
}

/// Effective priority of the thread running on `cpu` (PRIORITIES when unknown).
fn running_prio(s: &Sched, cpu: usize) -> u8 {
    index_of(s, s.current[cpu])
        .map(|i| effective_prio(&s.threads[i]))
        .unwrap_or(PRIORITIES)
}

/// Asks `cpu` to reschedule: the flag, plus an IPI when it is another CPU (it may be halted).
fn request_resched(s: &mut Sched, cpu: usize) {
    s.need_resched[cpu] = true;
    if cpu != me() {
        arch::apic::send_ipi(arch::smp::apic_id_of(cpu), arch::irq::RESCHED_VECTOR);
    }
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
        wake_tokens: 0,
        owns_stack: false,
        cpu: 0,
        waiting: false,
        on_cpu: true,
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
        current: [0; MAX_CPUS],
        prev: [None; MAX_CPUS],
        idle: [0; MAX_CPUS],
        need_resched: [false; MAX_CPUS],
        next_tid: 1,
        next_pid: 1,
        seq: 1,
        ticks: 0,
        switches: 0,
        preemptions: 0,
        finished_threads: Vec::with_capacity(16),
        finished_processes: Vec::with_capacity(16),
        reaping_threads: Vec::with_capacity(8),
        reaping_processes: Vec::with_capacity(8),
        kernel_cr3,
    });
}

/// Registers the calling context of application processor `cpu` as that CPU's idle thread
/// (priority 3, Running, never exits or blocks); `stack` is the boot stack it runs on (WP-20).
pub fn adopt_ap(cpu: usize, stack: StackInfo) {
    with(|s| {
        let id = s.next_tid;
        s.next_tid += 1;
        s.threads.push(Thread {
            id,
            process: None,
            state: State::Running,
            priority: PRIORITIES - 1,
            kstack: stack,
            rsp: 0,
            slice: QUANTUM_TICKS,
            last_pick: 0,
            wake_tokens: 0,
            owns_stack: false,
            cpu: cpu as u8,
            waiting: false,
            on_cpu: true,
        });
        s.current[cpu] = id;
        s.idle[cpu] = id;
        s.prev[cpu] = None;
        s.need_resched[cpu] = false;
    });
}

#[allow(clippy::too_many_arguments)]
fn new_thread(
    s: &mut Sched,
    process: Option<u32>,
    priority: u8,
    kind: Start,
    a: u64,
    b: u64,
    cpu: usize,
    c: u64,
) -> Result<u32, SpawnError> {
    if cpu >= MAX_CPUS || arch::smp::online_mask() & (1 << cpu) == 0 {
        return Err(SpawnError);
    }
    let kstack = vmm::alloc_kernel_stack(THREAD_STACK_SIZE).map_err(|_| SpawnError)?;
    let rsp = context::prepare_stack(kstack.top(), kind, a, b, c);
    let id = s.next_tid;
    s.next_tid += 1;
    let priority = priority.min(PRIORITIES - 1);
    s.threads.push(Thread {
        id,
        process,
        state: State::Ready,
        priority,
        kstack,
        rsp,
        slice: QUANTUM_TICKS,
        last_pick: 0,
        wake_tokens: 0,
        owns_stack: true,
        cpu: cpu as u8,
        waiting: false,
        on_cpu: false,
    });
    // A new thread of better or equal priority runs at its CPU's next preemption point or yield.
    if priority <= running_prio(s, cpu) {
        request_resched(s, cpu);
    }
    Ok(id)
}

/// Spawns a kernel thread running `entry(arg)` on this CPU; its return value is the thread's
/// exit code.
pub fn spawn_kernel(
    entry: context::KernelEntry,
    arg: u64,
    priority: u8,
) -> Result<u32, SpawnError> {
    with(|s| {
        let cpu = me();
        new_thread(
            s,
            None,
            priority,
            Start::Kernel,
            entry as usize as u64,
            arg,
            cpu,
            0,
        )
    })
}

/// Spawns a kernel thread pinned to `cpu` (an online CPU), WP-20.
pub fn spawn_on(
    cpu: usize,
    entry: context::KernelEntry,
    arg: u64,
    priority: u8,
) -> Result<u32, SpawnError> {
    with(|s| {
        new_thread(
            s,
            None,
            priority,
            Start::Kernel,
            entry as usize as u64,
            arg,
            cpu,
            0,
        )
    })
}

/// Creates a process around `space` with one thread starting in ring 3 at `rip` with stack
/// `rsp`. Returns (pid, tid).
pub fn spawn_user(
    space: UserSpace,
    rip: u64,
    rsp: u64,
    priority: u8,
) -> Result<(u32, u32), SpawnError> {
    spawn_user_with(space, rip, rsp, priority, Vec::new(), None).map(|(pid, tid, _)| (pid, tid))
}

/// `spawn_user` with initial handles (WP-23): `initial` goes into the new table in order and
/// the first one's handle value reaches the thread in `rdi`; `object` is the parent's waitable
/// view (created for pid 0, bound here). Returns (pid, tid, first handle value).
pub fn spawn_user_with(
    space: UserSpace,
    rip: u64,
    rsp: u64,
    priority: u8,
    initial: Vec<Entry>,
    object: Option<Arc<ProcessObject>>,
) -> Result<(u32, u32, u32), SpawnError> {
    if !arch::syscall::user_rip_ok(rip) {
        let _ = space.destroy();
        return Err(SpawnError);
    }
    let mut table = HandleTable::new();
    let mut first = 0u32;
    for (i, e) in initial.into_iter().enumerate() {
        match table.insert(e) {
            Ok(h) if i == 0 => first = h,
            Ok(_) => {}
            Err(_) => {
                let _ = space.destroy();
                return Err(SpawnError);
            }
        }
    }
    let (result, failed) = with(|s| {
        let pid = s.next_pid;
        s.next_pid += 1;
        if let Some(o) = &object {
            o.bind(pid);
        }
        s.processes.push(Process {
            id: pid,
            space,
            threads: 1,
            exit_code: None,
            handles: Arc::new(IrqSpinLock::new("handles", table)),
            object,
        });
        let cpu = me();
        match new_thread(
            s,
            Some(pid),
            priority,
            Start::User,
            rip,
            rsp,
            cpu,
            u64::from(first),
        ) {
            Ok(tid) => (Ok((pid, tid, first)), None),
            Err(e) => (Err(e), s.processes.pop()),
        }
    });
    // Finishing the stillborn process closes its initial handles, which may wake a peer's
    // reader (that takes the scheduler lock), so it happens outside the lock.
    if let Some(p) = failed {
        p.finish(u64::MAX);
    }
    result
}

fn index_of(s: &Sched, tid: u32) -> Option<usize> {
    s.threads.iter().position(|t| t.id == tid)
}

/// The thread to run next on `cpu`: one of its threads, Ready (or the Running current), with
/// the smallest effective priority value (a waiting thread counts as the lowest), ties broken
/// by the smallest `last_pick`, then by position.
fn pick_next(s: &Sched, cpu: usize) -> usize {
    let mut best: Option<(usize, u8)> = None;
    let current = s.current[cpu];
    for (i, t) in s.threads.iter().enumerate() {
        if usize::from(t.cpu) != cpu {
            continue;
        }
        let is_current = t.id == current;
        let runnable = t.state == State::Ready || (is_current && t.state == State::Running);
        if !runnable {
            continue;
        }
        let prio = effective_prio(t);
        best = match best {
            None => Some((i, prio)),
            Some((b, bp)) => {
                let bt = &s.threads[b];
                if prio < bp || (prio == bp && t.last_pick < bt.last_pick) {
                    Some((i, prio))
                } else {
                    Some((b, bp))
                }
            }
        };
    }
    best.map(|(i, _)| i)
        .unwrap_or_else(|| index_of(s, s.idle[cpu]).expect("the idle thread exists"))
}

/// Books the switch to the best runnable thread: the current thread goes to the back of its
/// priority's round, the next one becomes Running, its trap stack and address space are made
/// current. Returns `None` when the current thread keeps the CPU. The caller performs the
/// returned switch immediately, after dropping the lock, with interrupts still disabled.
/// Marks the thread that ran on `cpu` before its current one as off the CPU: called on that
/// CPU while running the current thread, so the previous thread's stack is no longer in use
/// (a resumed thread calls it right after the switch; a scheduling decision calls it too, for
/// a thread whose first run started in a trampoline and never came back through `perform`).
fn retire_prev(s: &mut Sched, cpu: usize) {
    if let Some(p) = s.prev[cpu].take() {
        if p != s.current[cpu] {
            if let Some(i) = index_of(s, p) {
                s.threads[i].on_cpu = false;
            }
        }
    }
}

fn prepare_switch(s: &mut Sched) -> Option<Switch> {
    let cpu = me();
    let cur = s.current[cpu];
    retire_prev(s, cpu);
    let cur_i = index_of(s, cur).expect("current thread exists");
    s.need_resched[cpu] = false;
    s.seq += 1;
    s.threads[cur_i].last_pick = s.seq;
    let next_i = pick_next(s, cpu);
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
        n.on_cpu = true;
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
    s.prev[cpu] = Some(cur);
    s.current[cpu] = next_tid;
    s.switches += 1;
    Some(Switch {
        prev_slot: &mut s.threads[cur_i].rsp,
        next_rsp: s.threads[next_i].rsp,
    })
}

/// Performs a prepared switch (interrupts disabled, lock released) and, once this thread is
/// resumed — or at once when there was nothing to switch to — reaps what exited meanwhile.
fn perform(sw: Option<Switch>) -> bool {
    let switched = match sw {
        Some(sw) => {
            // SAFETY: both stacks are kernel stacks this module owns; `next_rsp` was saved by
            // switch_to or built by prepare_stack; interrupts are disabled, so between
            // `prepare_switch` and here nothing ran that could move the thread vector, and
            // `prev_slot` is written by the switch before any other code runs; nothing borrows
            // the scheduler state across the call (the lock was dropped).
            unsafe { context::switch_to(sw.prev_slot, sw.next_rsp) };
            true
        }
        None => false,
    };
    let reaped = with(|s| {
        if switched {
            // Back on this stack: the thread that switched to us has left the CPU.
            retire_prev(s, me());
        }
        reap(s)
    });
    if reaped.is_empty() {
        return switched;
    }
    // Outside the lock: unmapping a stack tells the other CPUs (TLB shootdown), and releasing
    // handles may close channels and wake their readers (which takes this lock).
    for st in reaped.stacks {
        vmm::free_kernel_stack(st);
    }
    let mut processes = Vec::with_capacity(reaped.processes.len());
    for (p, code) in reaped.processes {
        processes.push((p.id, code));
        p.finish(code);
    }
    // Only now may a waiter learn the outcome: every frame is back. The lists are consumed
    // inside the lock so their own heap blocks are gone before the lock is released.
    let threads = reaped.threads;
    with(move |s| {
        for (tid, code) in threads {
            s.reaping_threads.retain(|t| *t != tid);
            if s.finished_threads.len() >= FINISHED_KEEP {
                s.finished_threads.remove(0);
            }
            s.finished_threads.push((tid, code));
        }
        for (pid, code) in processes {
            s.reaping_processes.retain(|p| *p != pid);
            if s.finished_processes.len() >= FINISHED_KEEP {
                s.finished_processes.remove(0);
            }
            s.finished_processes.push((pid, code));
        }
    });
    switched
}

/// What `reap` took out of the tables: stacks to free, kernel threads to publish as finished
/// (id, exit code) and processes to finish and publish.
struct Reaped {
    stacks: Vec<StackInfo>,
    threads: Vec<(u32, u64)>,
    processes: Vec<(Process, u64)>,
}

impl Reaped {
    fn is_empty(&self) -> bool {
        self.stacks.is_empty() && self.threads.is_empty() && self.processes.is_empty()
    }
}

/// Removes exited threads that are off their CPU and detaches processes whose last thread
/// exited and whose address space is not the active one; the caller frees the stacks,
/// finishes the processes and then publishes them as finished.
fn reap(s: &mut Sched) -> Reaped {
    let mut r = Reaped {
        stacks: Vec::new(),
        threads: Vec::new(),
        processes: Vec::new(),
    };
    let mut i = 0;
    while i < s.threads.len() {
        let exited = match s.threads[i].state {
            State::Exited { code } if !s.threads[i].on_cpu => Some(code),
            _ => None,
        };
        if let Some(code) = exited {
            let t = s.threads.swap_remove(i);
            if t.owns_stack {
                r.stacks.push(t.kstack);
            }
            // Kernel threads are joined by id; a process's threads are accounted through the
            // process (wait_process), so no record is kept for them.
            if t.process.is_none() {
                s.reaping_threads.push(t.id);
                r.threads.push((t.id, code));
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
            s.reaping_processes.push(p.id);
            r.processes.push((p, code));
        } else {
            i += 1;
        }
    }
    r
}

/// Timer hook (interrupt context): advances time, wakes sleepers, expires the slice. Before
/// `init` it does nothing.
pub fn tick() {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else {
        return;
    };
    let cpu = me();
    if cpu == 0 {
        // CPU 0 keeps the time: sleepers wake here, whichever CPU they belong to.
        s.ticks += 1;
        let now = s.ticks;
        let mut wake = [false; MAX_CPUS];
        for t in s.threads.iter_mut() {
            if let State::Sleeping { until } | State::BlockedUntil { until } = t.state {
                if until <= now {
                    t.state = State::Ready;
                    wake[usize::from(t.cpu)] = true;
                }
            }
        }
        for (c, w) in wake.iter().enumerate() {
            if *w {
                let prio = running_prio(s, c);
                let woke_better = s.threads.iter().any(|t| {
                    usize::from(t.cpu) == c && t.state == State::Ready && t.priority <= prio
                });
                if woke_better {
                    request_resched(s, c);
                }
            }
        }
    }
    if let Some(i) = index_of(s, s.current[cpu]) {
        let t = &mut s.threads[i];
        t.slice = t.slice.saturating_sub(1);
        if t.slice == 0 {
            s.need_resched[cpu] = true;
        }
    }
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
        if !s.need_resched[me()] {
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

/// Marks the current thread as waiting (or not): while waiting it competes at the lowest
/// priority, so it never starves what it waits for (CI run 39118752606: a priority-1 waiter
/// starved a priority-3 spinner; CI run 39119679600: two waiters at priority 1 kept handing
/// the CPU to each other — the demotion must be visible to every decision, not only the
/// waiter's own).
fn set_waiting(waiting: bool) {
    with(|s| {
        if let Some(i) = index_of(s, s.current[me()]) {
            s.threads[i].waiting = waiting;
        }
    });
}

/// Whether the running thread of this CPU is its idle thread (thread 0 on CPU 0).
fn current_is_idle(s: &Sched) -> bool {
    let cpu = me();
    s.current[cpu] == s.idle[cpu]
}

/// Sleeps for at least `ticks` timer ticks. An idle thread, which must stay runnable, waits
/// by halting instead of blocking.
pub fn sleep_ticks(ticks: u64) {
    let was = arch::interrupts::save_and_disable();
    let (until, idle) = with(|s| (s.ticks + ticks, current_is_idle(s)));
    if idle {
        while with(|s| s.ticks) < until {
            context::idle_wait();
        }
    } else {
        let sw = with(|s| {
            let i = index_of(s, s.current[me()]).expect("current thread exists");
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
        assert!(!current_is_idle(s), "an idle thread cannot exit");
        let i = index_of(s, s.current[me()]).expect("current thread exists");
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
    set_waiting(true);
    let r = join_loop(tid);
    set_waiting(false);
    r
}

fn join_loop(tid: u32) -> Option<u64> {
    loop {
        let found = with(|s| {
            if let Some(pos) = s.finished_threads.iter().position(|(t, _)| *t == tid) {
                return Some(Some(s.finished_threads.remove(pos).1));
            }
            if index_of(s, tid).is_none() && !s.reaping_threads.contains(&tid) {
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
    set_waiting(true);
    let r = wait_process_loop(pid);
    set_waiting(false);
    r
}

fn wait_process_loop(pid: u32) -> Option<u64> {
    loop {
        let found = with(|s| {
            if let Some(pos) = s.finished_processes.iter().position(|(p, _)| *p == pid) {
                return Some(Some(s.finished_processes.remove(pos).1));
            }
            if !s.processes.iter().any(|p| p.id == pid) && !s.reaping_processes.contains(&pid) {
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

/// Blocks the current thread until `wake` is called for it; returns at once when a wake-up
/// already arrived (token). Not for the boot thread.
pub fn block_current() {
    block_current_with(None);
}

/// `block_current` with a deadline in ticks (absolute, the time base of `stats().ticks`): the
/// timer makes the thread Ready at `deadline` if nobody woke it (WP-23 timeouts). The caller
/// tells a timeout from a wake-up by re-checking its condition and the clock.
pub fn block_current_until(deadline: u64) {
    block_current_with(Some(deadline));
}

fn block_current_with(deadline: Option<u64>) {
    let was = arch::interrupts::save_and_disable();
    let sw = with(|s| {
        assert!(!current_is_idle(s), "an idle thread cannot block");
        let i = index_of(s, s.current[me()]).expect("current thread exists");
        if s.threads[i].wake_tokens > 0 {
            s.threads[i].wake_tokens -= 1;
            return None;
        }
        if let Some(until) = deadline {
            if until <= s.ticks {
                return None;
            }
            s.threads[i].state = State::BlockedUntil { until };
        } else {
            s.threads[i].state = State::Blocked;
        }
        prepare_switch(s)
    });
    perform(sw);
    arch::interrupts::restore(was);
}

/// Makes a blocked thread Ready (or leaves it a token if it has not blocked yet). Unknown
/// threads are ignored. A woken thread of better or equal priority is scheduled at the next
/// preemption point or yield.
pub fn wake(tid: u32) {
    with(|s| {
        if let Some(i) = index_of(s, tid) {
            let cpu = usize::from(s.threads[i].cpu);
            let prio = running_prio(s, cpu);
            let t = &mut s.threads[i];
            match t.state {
                State::Blocked | State::BlockedUntil { .. } => {
                    t.state = State::Ready;
                    if t.priority <= prio {
                        request_resched(s, cpu);
                    }
                }
                State::Exited { .. } => {}
                _ => t.wake_tokens = t.wake_tokens.saturating_add(1),
            }
        }
    });
}

pub fn current_tid() -> u32 {
    with(|s| s.current[me()])
}

/// The time base (CPU 0's timer ticks since the scheduler started).
pub fn ticks() -> u64 {
    with(|s| s.ticks)
}

/// The current process's handle table (a shared reference; operate on it outside the
/// scheduler lock). None for kernel threads.
pub fn current_handles() -> Option<Arc<IrqSpinLock<HandleTable>>> {
    with(|s| {
        let pid = index_of(s, s.current[me()]).and_then(|i| s.threads[i].process)?;
        s.processes
            .iter()
            .find(|p| p.id == pid)
            .map(|p| p.handles.clone())
    })
}

pub fn stats() -> Stats {
    with(|s| Stats {
        threads: s.threads.len(),
        processes: s.processes.len(),
        switches: s.switches,
        preemptions: s.preemptions,
        ticks: s.ticks,
        current: s.current[me()],
    })
}
