//! libnawah — the user-side ABI of nawah-os (docs/contracts/syscall.md v1.2,
//! docs/contracts/ipc.md v1). `#![no_std]`, no allocation: thin wrappers around the SYSCALL
//! instruction plus the program entry (`_start` -> `main() -> u64` -> `exit`).
//!
//! Register convention (contract §2): rax = number, rdi/rsi/rdx/r10/r8/r9 arguments, rax
//! result; rcx and r11 are clobbered by the instruction.

#![no_std]

use core::arch::asm;

pub const SYS_EXIT: u64 = 0;
pub const SYS_PING: u64 = 1;
pub const SYS_TRACE: u64 = 2;
pub const SYS_CHECK_RIP: u64 = 3;
pub const SYS_YIELD: u64 = 4;
pub const SYS_SLEEP: u64 = 5;
pub const SYS_CHANNEL_CREATE: u64 = 6;
pub const SYS_CHANNEL_WRITE: u64 = 7;
pub const SYS_CHANNEL_READ: u64 = 8;
pub const SYS_HANDLE_CLOSE: u64 = 9;
pub const SYS_HANDLE_DUPLICATE: u64 = 10;
pub const SYS_VMO_CREATE: u64 = 11;
pub const SYS_HANDLE_RIGHTS: u64 = 12;

pub const ERR_NOSYS: i64 = -1;
pub const ERR_INVALID: i64 = -2;
pub const ERR_FAULT: i64 = -3;
pub const ERR_RANGE: i64 = -4;
pub const ERR_BAD_HANDLE: i64 = -5;
pub const ERR_ACCESS: i64 = -6;
pub const ERR_PEER_CLOSED: i64 = -7;
pub const ERR_SHOULD_WAIT: i64 = -8;
pub const ERR_BUFFER_TOO_SMALL: i64 = -9;
pub const ERR_NO_RESOURCES: i64 = -10;
pub const ERR_WRONG_TYPE: i64 = -11;

pub const READ_BLOCK: u64 = 1;

/// Rights bits (ipc.md §1).
pub mod rights {
    pub const READ: u32 = 0x1;
    pub const WRITE: u32 = 0x2;
    pub const DUPLICATE: u32 = 0x4;
    pub const TRANSFER: u32 = 0x8;
    pub const MAP: u32 = 0x10;
    pub const WAIT: u32 = 0x20;
}

pub type Handle = u32;

/// Raw call with up to six arguments.
#[inline(always)]
pub fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    // SAFETY: the SYSCALL instruction with the documented register convention; the kernel
    // preserves every register except rax (result), rcx and r11 (declared clobbered).
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

pub fn exit(code: u64) -> ! {
    syscall6(SYS_EXIT, code, 0, 0, 0, 0, 0);
    // The kernel never returns from exit; this keeps the signature honest.
    loop {
        core::hint::spin_loop();
    }
}

pub fn ping(x: u64) -> i64 {
    syscall6(SYS_PING, x, 0, 0, 0, 0, 0)
}

/// Prints an ASCII message on the kernel's diagnostic channel (`user|trace|…`).
pub fn trace(msg: &[u8]) -> i64 {
    syscall6(SYS_TRACE, msg.as_ptr() as u64, msg.len() as u64, 0, 0, 0, 0)
}

pub fn yield_now() -> i64 {
    syscall6(SYS_YIELD, 0, 0, 0, 0, 0, 0)
}

pub fn sleep(ticks: u64) -> i64 {
    syscall6(SYS_SLEEP, ticks, 0, 0, 0, 0, 0)
}

/// Two endpoints of a new channel.
pub fn channel_create() -> Result<(Handle, Handle), i64> {
    let mut out = [0u32; 2];
    let r = syscall6(SYS_CHANNEL_CREATE, out.as_mut_ptr() as u64, 0, 0, 0, 0, 0);
    if r < 0 {
        return Err(r);
    }
    Ok((out[0], out[1]))
}

pub fn channel_write(h: Handle, bytes: &[u8], handles: &[Handle]) -> i64 {
    syscall6(
        SYS_CHANNEL_WRITE,
        u64::from(h),
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        handles.as_ptr() as u64,
        handles.len() as u64,
        0,
    )
}

/// Reads one message; on success returns (bytes, handles) counts.
pub fn channel_read(
    h: Handle,
    bytes: &mut [u8],
    handles: &mut [Handle],
    block: bool,
) -> Result<(usize, usize), i64> {
    let r = syscall6(
        SYS_CHANNEL_READ,
        u64::from(h),
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
        handles.as_mut_ptr() as u64,
        handles.len() as u64,
        if block { READ_BLOCK } else { 0 },
    );
    if r < 0 {
        return Err(r);
    }
    Ok(((r & 0xFFFF) as usize, ((r >> 16) & 0xFFFF) as usize))
}

pub fn handle_close(h: Handle) -> i64 {
    syscall6(SYS_HANDLE_CLOSE, u64::from(h), 0, 0, 0, 0, 0)
}

pub fn handle_duplicate(h: Handle, rights: u32) -> Result<Handle, i64> {
    let r = syscall6(
        SYS_HANDLE_DUPLICATE,
        u64::from(h),
        u64::from(rights),
        0,
        0,
        0,
        0,
    );
    if r < 0 {
        Err(r)
    } else {
        Ok(r as Handle)
    }
}

pub fn vmo_create(size: u64) -> Result<Handle, i64> {
    let r = syscall6(SYS_VMO_CREATE, size, 0, 0, 0, 0, 0);
    if r < 0 {
        Err(r)
    } else {
        Ok(r as Handle)
    }
}

pub fn handle_rights(h: Handle) -> i64 {
    syscall6(SYS_HANDLE_RIGHTS, u64::from(h), 0, 0, 0, 0, 0)
}

/// Declares the program entry for an application crate: `_start` (where the loader begins,
/// with RSP as after a `call`) runs `$main() -> u64` and exits with its result; a panic exits
/// with 0xDEAD. One invocation per application.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            let code: u64 = $main();
            $crate::exit(code)
        }

        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo) -> ! {
            $crate::exit(0xDEAD)
        }
    };
}
