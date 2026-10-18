//! Running a ring-3 program (WP-14): one code page and one stack page in a fresh user address
//! space, entered through `arch::syscall::run_user`, torn down afterwards. WP-15 turns this into
//! processes and threads; here it is the executive's smallest step and the boot self-check.

use crate::arch;
use crate::arch::paging::{NX, WRITE};
use crate::mm::addrspace::{self, AsError, UserSpace, USER_BASE};

/// Where a program is loaded and where its stack page sits.
pub const CODE_BASE: u64 = USER_BASE;
pub const STACK_PAGE: u64 = USER_BASE + 0x20_0000;

#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    pub exit_code: u64,
    pub frames_delta: i64,
}

/// Loads `code` (position-independent machine code, at most one page) and runs it in ring 3.
pub fn run(code: &[u8]) -> Result<Outcome, AsError> {
    if code.len() > 4096 {
        return Err(AsError::Range);
    }
    let frames_before = crate::mm::pmm::stats().free_frames;
    let mut us = UserSpace::new()?;
    let code_phys = us.map_new_page(CODE_BASE, 0)?; // present, user, executable, read-only
    us.map_new_page(STACK_PAGE, WRITE | NX)?;
    addrspace::write_frame(code_phys, code);
    us.activate();
    let exit_code = arch::syscall::run_user(CODE_BASE, STACK_PAGE + 4096 - 16);
    addrspace::activate_kernel();
    us.destroy()?;
    let frames_after = crate::mm::pmm::stats().free_frames;
    Ok(Outcome {
        exit_code,
        frames_delta: frames_before as i64 - frames_after as i64,
    })
}
