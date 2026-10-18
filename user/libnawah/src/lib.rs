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
pub const SYS_OPEN: u64 = 13;
pub const SYS_READ: u64 = 14;
pub const SYS_WRITE: u64 = 15;
pub const SYS_STAT: u64 = 16;
pub const SYS_UNLINK: u64 = 17;
pub const SYS_SEEK: u64 = 18;
pub const SYS_SYNC: u64 = 19;
/// v1.4 (WP-23): processes from the volume, waiting with timeouts, the clock.
pub const SYS_PROCESS_SPAWN: u64 = 20;
pub const SYS_OBJECT_WAIT_MANY: u64 = 21;
pub const SYS_CLOCK_TICKS: u64 = 22;
pub const SYS_PROCESS_STATUS: u64 = 23;
/// v1.5 (WP-25): session tokens and the authority that mints them.
pub const SYS_TOKEN_CREATE: u64 = 24;
pub const SYS_TOKEN_INFO: u64 = 25;
pub const SYS_TOKEN_REVOKE: u64 = 26;

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
pub const ERR_NOT_FOUND: i64 = -12;
pub const ERR_EXISTS: i64 = -13;
pub const ERR_IS_DIR: i64 = -14;
pub const ERR_NOT_DIR: i64 = -15;
pub const ERR_BAD_PATH: i64 = -16;
pub const ERR_NO_SPACE: i64 = -17;
pub const ERR_IO: i64 = -18;
pub const ERR_TIMED_OUT: i64 = -19;

/// Signals for `object_wait_many`.
pub const SIGNAL_READABLE: u32 = 1;
pub const SIGNAL_PEER_CLOSED: u32 = 2;
pub const SIGNAL_EXITED: u32 = 4;
pub const TIMEOUT_FOREVER: u64 = u64::MAX;

/// `open` flags (docs/contracts/files.md).
pub const O_READ: u64 = 1;
pub const O_WRITE: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNCATE: u64 = 8;

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

/// One `object_wait_many` entry: a handle and the signals waited for.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WaitEntry {
    pub handle: Handle,
    pub signals: u32,
}

/// Spawns the ELF at `path` on the volume with `handles` moved into it (the first one is its
/// bootstrap handle, `bootstrap_handle()` there); returns a process handle.
pub fn process_spawn(path: &[u8], handles: &[Handle]) -> Result<Handle, i64> {
    let r = syscall6(
        SYS_PROCESS_SPAWN,
        path.as_ptr() as u64,
        path.len() as u64,
        handles.as_ptr() as u64,
        handles.len() as u64,
        0,
        0,
    );
    if r < 0 {
        Err(r)
    } else {
        Ok(r as Handle)
    }
}

/// Waits until one entry's signals are asserted: `Ok((index, asserted))`, or `Err(ERR_TIMED_OUT)`
/// after `timeout_ticks` (TIMEOUT_FOREVER = never).
pub fn object_wait_many(entries: &[WaitEntry], timeout_ticks: u64) -> Result<(usize, u32), i64> {
    let r = syscall6(
        SYS_OBJECT_WAIT_MANY,
        entries.as_ptr() as u64,
        entries.len() as u64,
        timeout_ticks,
        0,
        0,
        0,
    );
    if r < 0 {
        Err(r)
    } else {
        Ok(((r & 0xFF) as usize, (r >> 8) as u32))
    }
}

/// Monotonic time in timer ticks (1 kHz in the lab).
pub fn clock_ticks() -> u64 {
    syscall6(SYS_CLOCK_TICKS, 0, 0, 0, 0, 0, 0) as u64
}

/// Exit code of a spawned process, `Err(ERR_SHOULD_WAIT)` while it runs.
pub fn process_status(h: Handle) -> Result<u64, i64> {
    let r = syscall6(SYS_PROCESS_STATUS, u64::from(h), 0, 0, 0, 0, 0);
    if r < 0 {
        Err(r)
    } else {
        Ok(r as u64)
    }
}

/// The handle the process received at start (0 when it was started with none).
pub fn bootstrap_handle() -> Handle {
    BOOTSTRAP.load(core::sync::atomic::Ordering::Relaxed)
}

/// Token permission bits (auth.md §1).
pub mod perm {
    pub const ADMIN: u32 = 1;
    pub const CONFIG_WRITE: u32 = 2;
    pub const NET: u32 = 4;
    pub const SHELL: u32 = 8;
}

/// What `token_info` reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenInfo {
    pub uid: u32,
    pub gid: u32,
    pub perms: u32,
    /// bit 0 revoked, bit 1 expired.
    pub flags: u32,
    pub expires: u64,
    /// The token's identity: equal for two handles to the same token.
    pub id: u64,
}

impl TokenInfo {
    pub fn usable(&self) -> bool {
        self.flags == 0
    }
}

/// Mints a token with `authority` (ERR_ACCESS without one); the handle carries WRITE.
pub fn token_create(
    authority: Handle,
    uid: u32,
    gid: u32,
    perms: u32,
    expires: u64,
) -> Result<Handle, i64> {
    let r = syscall6(
        SYS_TOKEN_CREATE,
        u64::from(authority),
        u64::from(uid),
        u64::from(gid),
        u64::from(perms),
        expires,
        0,
    );
    if r < 0 {
        Err(r)
    } else {
        Ok(r as Handle)
    }
}

pub fn token_info(h: Handle) -> Result<TokenInfo, i64> {
    let mut buf = [0u8; 32];
    let r = syscall6(
        SYS_TOKEN_INFO,
        u64::from(h),
        buf.as_mut_ptr() as u64,
        0,
        0,
        0,
        0,
    );
    if r < 0 {
        return Err(r);
    }
    let w = |i: usize| u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
    Ok(TokenInfo {
        uid: w(0),
        gid: w(4),
        perms: w(8),
        flags: w(12),
        expires: u64::from_le_bytes(buf[16..24].try_into().unwrap_or([0; 8])),
        id: u64::from_le_bytes(buf[24..32].try_into().unwrap_or([0; 8])),
    })
}

/// Revokes a token through a handle with WRITE (the minter's).
pub fn token_revoke(h: Handle) -> i64 {
    syscall6(SYS_TOKEN_REVOKE, u64::from(h), 0, 0, 0, 0, 0)
}

#[doc(hidden)]
pub static BOOTSTRAP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

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

/// What `stat` returns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub is_dir: bool,
    pub first_cluster: u32,
}

pub fn open(path: &[u8], flags: u64) -> Result<Handle, i64> {
    let r = syscall6(
        SYS_OPEN,
        path.as_ptr() as u64,
        path.len() as u64,
        flags,
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

/// Reads into `buf` at the file's position; Ok(0) at end of file.
pub fn read(h: Handle, buf: &mut [u8]) -> Result<usize, i64> {
    let r = syscall6(
        SYS_READ,
        u64::from(h),
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
        0,
        0,
    );
    if r < 0 {
        Err(r)
    } else {
        Ok(r as usize)
    }
}

pub fn write(h: Handle, data: &[u8]) -> Result<usize, i64> {
    let r = syscall6(
        SYS_WRITE,
        u64::from(h),
        data.as_ptr() as u64,
        data.len() as u64,
        0,
        0,
        0,
    );
    if r < 0 {
        Err(r)
    } else {
        Ok(r as usize)
    }
}

pub fn stat(path: &[u8]) -> Result<Stat, i64> {
    let mut rec = [0u8; 16];
    let r = syscall6(
        SYS_STAT,
        path.as_ptr() as u64,
        path.len() as u64,
        rec.as_mut_ptr() as u64,
        0,
        0,
        0,
    );
    if r < 0 {
        return Err(r);
    }
    Ok(Stat {
        size: u64::from_le_bytes([
            rec[0], rec[1], rec[2], rec[3], rec[4], rec[5], rec[6], rec[7],
        ]),
        is_dir: u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]) != 0,
        first_cluster: u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]),
    })
}

pub fn unlink(path: &[u8]) -> i64 {
    syscall6(
        SYS_UNLINK,
        path.as_ptr() as u64,
        path.len() as u64,
        0,
        0,
        0,
        0,
    )
}

pub fn seek(h: Handle, pos: u64) -> i64 {
    syscall6(SYS_SEEK, u64::from(h), pos, 0, 0, 0, 0)
}

pub fn sync() -> i64 {
    syscall6(SYS_SYNC, 0, 0, 0, 0, 0, 0)
}

/// Declares the program entry for an application crate: `_start` (where the loader begins,
/// with RSP as after a `call`) runs `$main() -> u64` and exits with its result; a panic exits
/// with 0xDEAD. One invocation per application.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        /// The kernel enters here with the bootstrap handle in `rdi` (WP-23).
        #[no_mangle]
        pub extern "C" fn _start(bootstrap: u64) -> ! {
            $crate::BOOTSTRAP.store(bootstrap as u32, core::sync::atomic::Ordering::Relaxed);
            let code: u64 = $main();
            $crate::exit(code)
        }

        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo) -> ! {
            $crate::exit(0xDEAD)
        }
    };
}
