//! System call ABI v1.1 (docs/contracts/syscall.md: v1 frozen in WP-14, yield/sleep added in
//! WP-15) — the architecture-neutral
//! side: numbers, error codes, argument validation and dispatch. The register convention and
//! the entry instruction live in `arch` (x86_64: SYSCALL with rax = number, rdi/rsi/rdx/r10/r8/r9
//! arguments, rax result; AArch64 mapping reserved in the contract).

use crate::arch;
use crate::mm::addrspace::{USER_BASE, USER_END};
use crate::mm::vmm;
use crate::BUILD_ID;

pub const SYS_EXIT: u64 = 0;
pub const SYS_PING: u64 = 1;
pub const SYS_TRACE: u64 = 2;
/// Validates a would-be user instruction pointer (test kernel and later thread creation).
pub const SYS_CHECK_RIP: u64 = 3;
/// v1.1 (WP-15): give the CPU away; sleep for a number of timer ticks.
pub const SYS_YIELD: u64 = 4;
pub const SYS_SLEEP: u64 = 5;

/// Results are i64: >= 0 success, < 0 one of these.
pub const ERR_NOSYS: i64 = -1;
pub const ERR_INVALID: i64 = -2;
pub const ERR_FAULT: i64 = -3;
pub const ERR_RANGE: i64 = -4;

/// Largest trace message.
pub const TRACE_MAX: usize = 256;

/// Checks that `[addr, addr + len)` lies in the user range and every page of it is present with
/// the user bit in the active address space (so a kernel copy cannot touch kernel or unmapped
/// memory). `len` may be 0.
pub fn user_range_ok(addr: u64, len: u64) -> Result<(), i64> {
    let end = addr.checked_add(len).ok_or(ERR_RANGE)?;
    if addr < USER_BASE || end > USER_END {
        return Err(ERR_RANGE);
    }
    let mut page = addr & !0xFFF;
    while page < end {
        match vmm::flags_of(page) {
            Some(f) if f & arch::paging::USER != 0 => {}
            _ => return Err(ERR_FAULT),
        }
        page += 0x1000;
    }
    Ok(())
}

/// Copies `buf.len()` bytes from user memory after validating the range.
pub fn copy_from_user(buf: &mut [u8], addr: u64) -> Result<(), i64> {
    user_range_ok(addr, buf.len() as u64)?;
    arch::syscall::copy_in(buf, addr);
    Ok(())
}

/// Dispatches one call; never panics on bad input.
pub fn dispatch(nr: u64, args: [u64; 6]) -> i64 {
    match nr {
        SYS_EXIT => crate::sched::exit_current(args[0]),
        SYS_YIELD => {
            crate::sched::yield_now();
            0
        }
        SYS_SLEEP => {
            crate::sched::sleep_ticks(args[0].min(1_000_000));
            0
        }
        SYS_PING => (args[0].wrapping_add(1)) as i64,
        SYS_TRACE => {
            let len = args[1] as usize;
            if len > TRACE_MAX {
                return ERR_INVALID;
            }
            let mut buf = [0u8; TRACE_MAX];
            if let Err(e) = copy_from_user(&mut buf[..len], args[0]) {
                return e;
            }
            // ASCII only on the diagnostic channel: anything else is shown as '?'.
            for b in buf[..len].iter_mut() {
                if !(0x20..0x7F).contains(b) {
                    *b = b'?';
                }
            }
            let text = core::str::from_utf8(&buf[..len]).unwrap_or("?");
            kprintln!("OSX|{}|user|trace|len={}|text={}", BUILD_ID, len, text);
            len as i64
        }
        SYS_CHECK_RIP => {
            if arch::syscall::user_rip_ok(args[0]) {
                0
            } else {
                ERR_RANGE
            }
        }
        _ => ERR_NOSYS,
    }
}
