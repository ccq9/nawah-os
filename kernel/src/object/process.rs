//! Process objects (WP-23, ADR-0016 §2): a handle to a process the holder created, carrying
//! its exit (the `EXITED` signal and the code) once the scheduler has finished it. The
//! scheduler owns the process itself; this object is the waitable view of it.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::sched;
use crate::sync::IrqSpinLock;

static LIVE: AtomicU32 = AtomicU32::new(0);

pub fn live() -> u32 {
    LIVE.load(Ordering::Relaxed)
}

struct State {
    exit: Option<u64>,
    /// Threads blocked in `object_wait_many` on this object.
    waiters: Vec<u32>,
    /// The spawn image's base name (e.g. `DISPLAYD.ELF`), for the test-only `freeze_named`
    /// (WP-40): the test kernel freezes a named service during the lock. Up to 16 bytes, set
    /// once at spawn. Test-only — compiled only under `ktest`, since nothing in the production
    /// kernel reads a process name yet.
    #[cfg(feature = "ktest")]
    name: [u8; 16],
    #[cfg(feature = "ktest")]
    name_len: usize,
}

pub struct ProcessObject {
    /// 0 until the scheduler binds the object to the process it created.
    pid: AtomicU32,
    state: IrqSpinLock<State>,
}

impl ProcessObject {
    pub fn new() -> Self {
        LIVE.fetch_add(1, Ordering::Relaxed);
        ProcessObject {
            pid: AtomicU32::new(0),
            state: IrqSpinLock::new(
                "process",
                State {
                    exit: None,
                    waiters: Vec::new(),
                    #[cfg(feature = "ktest")]
                    name: [0; 16],
                    #[cfg(feature = "ktest")]
                    name_len: 0,
                },
            ),
        }
    }

    pub fn bind(&self, pid: u32) {
        self.pid.store(pid, Ordering::Relaxed);
    }

    /// Records the spawn image's base name (WP-40): the last path component, up to 16 bytes.
    /// Test-only (`freeze_named`); see the `name` field.
    #[cfg(feature = "ktest")]
    pub fn set_name(&self, path: &[u8]) {
        let base = match path.iter().rposition(|&c| c == b'/') {
            Some(i) => &path[i + 1..],
            None => path,
        };
        let n = base.len().min(16);
        let mut s = self.state.lock();
        s.name[..n].copy_from_slice(&base[..n]);
        s.name_len = n;
    }

    /// Whether this process's recorded name equals `name` (WP-40, `freeze_named`). Test-only.
    #[cfg(feature = "ktest")]
    pub fn name_is(&self, name: &[u8]) -> bool {
        let s = self.state.lock();
        &s.name[..s.name_len] == name
    }

    /// The process id the scheduler bound, or None before binding (WP-40, for `process_kill`).
    pub fn pid(&self) -> Option<u32> {
        match self.pid.load(Ordering::Relaxed) {
            0 => None,
            p => Some(p),
        }
    }

    /// The exit code once the process has exited.
    pub fn exit_code(&self) -> Option<u64> {
        self.state.lock().exit
    }

    /// Records the exit and wakes every waiter. Called by the scheduler after the process's
    /// resources are released, with no scheduler lock held (wake takes it).
    pub fn finish(&self, code: u64) {
        let waiters = {
            let mut s = self.state.lock();
            s.exit = Some(code);
            core::mem::take(&mut s.waiters)
        };
        for tid in waiters {
            sched::wake(tid);
        }
    }

    /// Registers `tid` for a wake-up on exit unless the process already exited; returns
    /// whether it has (the caller then does not block).
    pub fn watch(&self, tid: u32) -> bool {
        let mut s = self.state.lock();
        if s.exit.is_some() {
            return true;
        }
        if !s.waiters.contains(&tid) {
            s.waiters.push(tid);
        }
        false
    }

    pub fn forget_waiter(&self, tid: u32) {
        self.state.lock().waiters.retain(|t| *t != tid);
    }
}

impl Default for ProcessObject {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProcessObject {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}
