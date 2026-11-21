//! Jobs (WP-46, syscall.md v1.13 §5, ipc.md §1): a tree of process groups, after the public
//! semantics of POSIX process groups (S78) and of the Fuchsia job concept (S79), both registered in
//! docs/sources.json and verified from their pages on 2026-11-10 — a reference for behaviour, not
//! for code. A job knows only its parent (pointers go upward, so nothing here owns a child and no
//! cycle can form); a process's job is fixed when its process object is created. Membership is
//! decided by walking upward under the scheduler lock (`sched::kill_job`), so a kill and a spawn
//! into the same subtree are ordered by that lock.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::sync::IrqSpinLock;

/// Deepest job below the root (the root is depth 0).
pub const JOB_DEPTH_MAX: u32 = 8;

/// Live processes a job other than the root holds of its own (syscall.md v1.15, WP-164): a
/// process started in a full job is refused, so no job takes every kernel stack (RSK-050).
pub const JOB_PROCESSES_MAX: u32 = 32;

/// Pages of memory a job other than the root holds of its own (syscall.md v1.16, WP-170,
/// RSK-051): its VMOs from `vmo_create` to their last reference, and each of its processes'
/// image and stack from the spawn to the reap. 8192 pages, 32 MiB.
pub const JOB_PAGES_MAX: u64 = 8192;

/// Frames kept for the kernel (v1.16): what every job together holds, the root's charge
/// counted, stops this many frames short of what was free at the boot point that
/// `fix_user_limit` names. 16384 frames, 64 MiB.
pub const KERNEL_RESERVE_FRAMES: u64 = 16384;

/// Pages charged to every job, the root's included (v1.16).
static CHARGED: AtomicU64 = AtomicU64::new(0);
/// The most every job together may hold (v1.16); no limit before `fix_user_limit`.
static USER_LIMIT: AtomicU64 = AtomicU64::new(u64::MAX);
/// The free frames `fix_user_limit` was given (0 before it).
static FIXED_AT: AtomicU64 = AtomicU64::new(0);

/// Fixes the system's user charge limit (v1.16) at `free_frames` less the kernel's reserve.
/// Called once, at the boot point kmain names: every self-check done, before the first process
/// of the system or of the test kernel's cases.
pub fn fix_user_limit(free_frames: u64) {
    FIXED_AT.store(free_frames, Ordering::SeqCst);
    USER_LIMIT.store(
        free_frames.saturating_sub(KERNEL_RESERVE_FRAMES),
        Ordering::SeqCst,
    );
}

/// Test-only (WP-170): pages charged to every job now.
#[cfg(feature = "ktest")]
pub fn charged() -> u64 {
    CHARGED.load(Ordering::SeqCst)
}

/// Test-only (WP-170): the system's user charge limit, `u64::MAX` before the boot point fixes it.
#[cfg(feature = "ktest")]
pub fn user_limit() -> u64 {
    USER_LIMIT.load(Ordering::SeqCst)
}

/// Test-only (WP-170): the free frames the limit was fixed at.
#[cfg(feature = "ktest")]
pub fn fixed_at() -> u64 {
    FIXED_AT.load(Ordering::SeqCst)
}

/// Test-only (WP-170): replaces the system's limit and returns the one before, so the test
/// kernel reaches it with a few pages and puts it back.
#[cfg(feature = "ktest")]
pub fn swap_user_limit(limit: u64) -> u64 {
    USER_LIMIT.swap(limit, Ordering::SeqCst)
}

/// Live jobs other than the root (object stats): the root lives for the whole boot, so leak
/// checks that compare stats before and after see only the jobs a test created.
static LIVE: AtomicU32 = AtomicU32::new(0);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static ROOT: IrqSpinLock<Option<Arc<Job>>> = IrqSpinLock::new("job_root", None);

pub fn live() -> u32 {
    LIVE.load(Ordering::Relaxed)
}

pub struct Job {
    /// Unique for the boot; the root is 1 once created. Read by the listing to come (WP-69).
    #[allow(dead_code)]
    pub id: u64,
    parent: Option<Arc<Job>>,
    killed: AtomicBool,
    depth: u32,
    /// Its live processes (v1.15), each counted by a `Member` from the scheduler's table to
    /// the reap.
    procs: AtomicU32,
    /// The pages it holds (v1.16), each counted by a `Charge` until the frames are freed.
    pages: AtomicU64,
}

/// Pages charged to a job (syscall.md v1.16): held by what owns the frames (a VMO, a process's
/// address space) and dropped after it freed them, so the job and the system count them back.
pub struct Charge {
    job: Arc<Job>,
    pages: u64,
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.job.pages.fetch_sub(self.pages, Ordering::SeqCst);
        CHARGED.fetch_sub(self.pages, Ordering::SeqCst);
    }
}

/// A process's place in its job (syscall.md v1.15): taken when it enters the scheduler's table,
/// given back when it is reaped, before its exit is told, so whoever sees EXITED finds the
/// place free.
pub struct Member(Arc<Job>);

impl Drop for Member {
    fn drop(&mut self) {
        self.0.procs.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Why a child job could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateError {
    /// The parent, or one of its ancestors, was killed.
    Dead,
    /// The child would be deeper than `JOB_DEPTH_MAX`.
    TooDeep,
}

/// Adds `n` to `count` unless the sum would pass `max` (v1.16); None, and nothing added, then.
fn take(count: &AtomicU64, n: u64, max: u64) -> Option<()> {
    let mut now = count.load(Ordering::SeqCst);
    loop {
        let next = now.checked_add(n).filter(|&t| t <= max)?;
        match count.compare_exchange_weak(now, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Some(()),
            Err(seen) => now = seen,
        }
    }
}

/// The root job, made on first use; every process without a job of its own belongs to it.
pub fn root() -> Arc<Job> {
    ROOT.lock()
        .get_or_insert_with(|| {
            Arc::new(Job {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                parent: None,
                killed: AtomicBool::new(false),
                depth: 0,
                procs: AtomicU32::new(0),
                pages: AtomicU64::new(0),
            })
        })
        .clone()
}

impl Job {
    /// A child of `parent`: refused when the parent is dead or the child would be too deep.
    pub fn new_child(parent: &Arc<Job>) -> Result<Arc<Job>, CreateError> {
        if parent.dead() {
            return Err(CreateError::Dead);
        }
        let depth = parent.depth + 1;
        if depth > JOB_DEPTH_MAX {
            return Err(CreateError::TooDeep);
        }
        LIVE.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(Job {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            parent: Some(parent.clone()),
            killed: AtomicBool::new(false),
            depth,
            procs: AtomicU32::new(0),
            pages: AtomicU64::new(0),
        }))
    }

    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// A place for one more process (v1.15), or None when this job, not the root, holds
    /// JOB_PROCESSES_MAX already. Called under the scheduler lock only, so the check and the
    /// count are one step.
    pub fn admit(self: &Arc<Self>) -> Option<Member> {
        if !self.is_root() && self.procs.load(Ordering::SeqCst) >= JOB_PROCESSES_MAX {
            return None;
        }
        self.procs.fetch_add(1, Ordering::SeqCst);
        Some(Member(self.clone()))
    }

    /// Charges `n` pages to this job (syscall.md v1.16) before its frames are taken: None when
    /// this job, not the root, would hold more than JOB_PAGES_MAX, or every job together more
    /// than the system's limit. The root is counted, never refused. Each count moves by
    /// compare-and-swap, so two charges never both take the last pages; a job's pages taken
    /// for a charge the system then refuses are given back at once.
    pub fn charge(self: &Arc<Self>, n: u64) -> Option<Charge> {
        if self.is_root() {
            self.pages.fetch_add(n, Ordering::SeqCst);
            CHARGED.fetch_add(n, Ordering::SeqCst);
        } else {
            take(&self.pages, n, JOB_PAGES_MAX)?;
            if take(&CHARGED, n, USER_LIMIT.load(Ordering::SeqCst)).is_none() {
                self.pages.fetch_sub(n, Ordering::SeqCst);
                return None;
            }
        }
        Some(Charge {
            job: self.clone(),
            pages: n,
        })
    }

    /// Test-only (WP-170): the pages this job holds now.
    #[cfg(feature = "ktest")]
    pub fn pages(&self) -> u64 {
        self.pages.load(Ordering::SeqCst)
    }

    /// Test-only (WP-164): the processes this job counts now.
    #[cfg(feature = "ktest")]
    pub fn processes(&self) -> u32 {
        self.procs.load(Ordering::SeqCst)
    }

    /// Test-only (WP-161): whether this job's parent is the root job itself.
    #[cfg(feature = "ktest")]
    pub fn child_of_root(&self) -> bool {
        self.parent.as_ref().is_some_and(|p| p.is_root())
    }

    /// Test-only (WP-102): the parent job's id (0 for the root) and whether that parent is
    /// itself a child of the root job — an application's job under the session's job.
    #[cfg(feature = "ktest")]
    pub fn parent_of(&self) -> (u64, bool) {
        self.parent
            .as_ref()
            .map_or((0, false), |p| (p.id, p.child_of_root()))
    }

    /// Whether this job itself was killed.
    pub fn killed(&self) -> bool {
        self.killed.load(Ordering::SeqCst)
    }

    /// Marks the job killed; returns whether it was not killed before. Called by
    /// `sched::kill_job` under the scheduler lock.
    pub fn mark_killed(&self) -> bool {
        !self.killed.swap(true, Ordering::SeqCst)
    }

    /// Whether this job or any ancestor was killed: nothing new may enter it.
    pub fn dead(&self) -> bool {
        let mut j = Some(self);
        while let Some(job) = j {
            if job.killed() {
                return true;
            }
            j = job.parent.as_deref();
        }
        false
    }

    /// Whether `self` is `ancestor` or lies below it.
    pub fn within(&self, ancestor: &Job) -> bool {
        let mut j = Some(self);
        while let Some(job) = j {
            if core::ptr::eq(job, ancestor) {
                return true;
            }
            j = job.parent.as_deref();
        }
        false
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // The root is never dropped (the static keeps it); every other job was counted.
        if self.parent.is_some() {
            LIVE.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
