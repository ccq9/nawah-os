//! Running a ring-3 program (WP-14/WP-15/WP-16): one code page, one stack page and one data
//! page in a fresh user address space, started as a process with one thread; the caller waits
//! for the process exit.
//! WP-17 replaces the raw code page with the ELF loader.

use crate::arch::paging::{NX, WRITE};
use crate::mm::addrspace::{self, AsError, UserSpace, USER_BASE};
use crate::sched;

/// Where a program is loaded, where its stack page sits, and a writable data page (WP-16
/// programs keep handles and message buffers there).
pub const CODE_BASE: u64 = USER_BASE;
pub const STACK_PAGE: u64 = USER_BASE + 0x20_0000;
pub const DATA_PAGE: u64 = USER_BASE + 0x40_0000;

#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    pub pid: u32,
    pub exit_code: u64,
    pub frames_delta: i64,
}

/// Builds a process from `code` (position-independent machine code, at most one page).
pub fn spawn(code: &[u8], priority: u8) -> Result<u32, AsError> {
    if code.len() > 4096 {
        return Err(AsError::Range);
    }
    let mut us = UserSpace::new()?;
    // Code page: present, user, executable, read-only. A failure after `new` gives the space
    // back instead of leaking its tables.
    let code_phys = match us
        .map_new_page(CODE_BASE, 0)
        .and_then(|p| us.map_new_page(STACK_PAGE, WRITE | NX).map(|_| p))
        .and_then(|p| us.map_new_page(DATA_PAGE, WRITE | NX).map(|_| p))
    {
        Ok(p) => p,
        Err(e) => {
            let _ = us.destroy();
            return Err(e);
        }
    };
    addrspace::write_frame(code_phys, code);
    // spawn_user destroys the space itself when it cannot create the thread.
    sched::spawn_user(us, CODE_BASE, STACK_PAGE + 4096 - 16, priority)
        .map(|(pid, _tid)| pid)
        .map_err(|_| AsError::Spawn)
}

/// Spawns `code` and waits for the process to exit; reports the frame balance.
pub fn run(code: &[u8]) -> Result<Outcome, AsError> {
    let frames_before = crate::mm::pmm::stats().free_frames;
    let pid = spawn(code, 1)?;
    let exit_code = sched::wait_process(pid).unwrap_or(u64::MAX);
    let frames_after = crate::mm::pmm::stats().free_frames;
    Ok(Outcome {
        pid,
        exit_code,
        frames_delta: frames_before as i64 - frames_after as i64,
    })
}
