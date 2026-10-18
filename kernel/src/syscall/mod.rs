//! System call ABI (docs/contracts/syscall.md: v1 frozen in WP-14, v1.1 yield/sleep in WP-15,
//! v1.2 handles/channels/VMOs in WP-16 — docs/contracts/ipc.md, v1.3 files in WP-19 —
//! docs/contracts/files.md) — the architecture-neutral
//! side: numbers, error codes, argument validation and dispatch. The register convention and
//! the entry instruction live in `arch` (x86_64: SYSCALL with rax = number, rdi/rsi/rdx/r10/r8/r9
//! arguments, rax result; AArch64 mapping reserved in the contract).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch;
use crate::fs::fat32::FsError;
use crate::fs::vfs;
use crate::mm::addrspace::{USER_BASE, USER_END};
use crate::mm::vmm;
use crate::object::channel::{self, ChannelError, Message, MSG_MAX_BYTES, MSG_MAX_HANDLES};
use crate::object::handle::{Entry, Handle, HandleError};
use crate::object::{HandleTable, Object, Rights, Vmo, HANDLES_MAX};
use crate::sched;
use crate::sync::IrqSpinLock;
use crate::BUILD_ID;

pub const SYS_EXIT: u64 = 0;
pub const SYS_PING: u64 = 1;
pub const SYS_TRACE: u64 = 2;
/// Validates a would-be user instruction pointer (test kernel and later thread creation).
pub const SYS_CHECK_RIP: u64 = 3;
/// v1.1 (WP-15): give the CPU away; sleep for a number of timer ticks.
pub const SYS_YIELD: u64 = 4;
pub const SYS_SLEEP: u64 = 5;
/// v1.2 (WP-16): handles, channels, VMOs.
pub const SYS_CHANNEL_CREATE: u64 = 6;
pub const SYS_CHANNEL_WRITE: u64 = 7;
pub const SYS_CHANNEL_READ: u64 = 8;
pub const SYS_HANDLE_CLOSE: u64 = 9;
pub const SYS_HANDLE_DUPLICATE: u64 = 10;
pub const SYS_VMO_CREATE: u64 = 11;
pub const SYS_HANDLE_RIGHTS: u64 = 12;
/// v1.3 (WP-19): files (docs/contracts/files.md).
pub const SYS_OPEN: u64 = 13;
pub const SYS_READ: u64 = 14;
pub const SYS_WRITE: u64 = 15;
pub const SYS_STAT: u64 = 16;
pub const SYS_UNLINK: u64 = 17;
pub const SYS_SEEK: u64 = 18;
pub const SYS_SYNC: u64 = 19;

/// Results are i64: >= 0 success, < 0 one of these.
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
/// v1.3 file errors.
pub const ERR_NOT_FOUND: i64 = -12;
pub const ERR_EXISTS: i64 = -13;
pub const ERR_IS_DIR: i64 = -14;
pub const ERR_NOT_DIR: i64 = -15;
pub const ERR_BAD_PATH: i64 = -16;
pub const ERR_NO_SPACE: i64 = -17;
pub const ERR_IO: i64 = -18;

/// `channel_read` flag: block until a message arrives or the peer closes.
pub const READ_BLOCK: u64 = 1;

/// Largest trace message.
pub const TRACE_MAX: usize = 256;

/// Checks that `[addr, addr + len)` lies in the user range and every page of it is present with
/// the user bit (and, for `write`, the write bit) in the active address space, so a kernel copy
/// cannot touch kernel, unmapped or read-only memory. `len` may be 0.
pub fn user_range_ok(addr: u64, len: u64, write: bool) -> Result<(), i64> {
    let end = addr.checked_add(len).ok_or(ERR_RANGE)?;
    if addr < USER_BASE || end > USER_END {
        return Err(ERR_RANGE);
    }
    let mut page = addr & !0xFFF;
    while page < end {
        match vmm::flags_of(page) {
            Some(f) if f & arch::paging::USER != 0 && (!write || f & arch::paging::WRITE != 0) => {}
            _ => return Err(ERR_FAULT),
        }
        page += 0x1000;
    }
    Ok(())
}

/// Copies `buf.len()` bytes from user memory after validating the range.
pub fn copy_from_user(buf: &mut [u8], addr: u64) -> Result<(), i64> {
    user_range_ok(addr, buf.len() as u64, false)?;
    arch::syscall::copy_in(buf, addr);
    Ok(())
}

/// Copies `bytes` to user memory after validating the range for writing.
pub fn copy_to_user(addr: u64, bytes: &[u8]) -> Result<(), i64> {
    user_range_ok(addr, bytes.len() as u64, true)?;
    arch::syscall::copy_out(bytes, addr);
    Ok(())
}

fn handle_err(e: HandleError) -> i64 {
    match e {
        HandleError::BadHandle => ERR_BAD_HANDLE,
        HandleError::Access => ERR_ACCESS,
        HandleError::NoResources => ERR_NO_RESOURCES,
    }
}

fn channel_err(e: ChannelError) -> i64 {
    match e {
        ChannelError::PeerClosed => ERR_PEER_CLOSED,
        ChannelError::ShouldWait => ERR_SHOULD_WAIT,
        ChannelError::BufferTooSmall { .. } => ERR_BUFFER_TOO_SMALL,
    }
}

/// The calling process's handle table; a kernel thread has none.
fn table() -> Result<Arc<IrqSpinLock<HandleTable>>, i64> {
    sched::current_handles().ok_or(ERR_INVALID)
}

fn endpoint_of(entry: &Entry) -> Result<Arc<channel::Endpoint>, i64> {
    match &entry.object {
        Object::Channel(ep) => Ok(ep.clone()),
        _ => Err(ERR_WRONG_TYPE),
    }
}

fn channel_create(out: u64) -> Result<i64, i64> {
    user_range_ok(out, 8, true)?;
    let table = table()?;
    let (a, b) = channel::create();
    let (ha, hb) = {
        let mut t = table.lock();
        let ha = t
            .insert(Entry {
                object: Object::Channel(a),
                rights: Rights::CHANNEL_DEFAULT,
            })
            .map_err(handle_err)?;
        let hb = match t.insert(Entry {
            object: Object::Channel(b),
            rights: Rights::CHANNEL_DEFAULT,
        }) {
            Ok(h) => h,
            Err(e) => {
                let _ = t.remove(ha);
                return Err(handle_err(e));
            }
        };
        (ha, hb)
    };
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&ha.to_le_bytes());
    buf[4..].copy_from_slice(&hb.to_le_bytes());
    copy_to_user(out, &buf)?;
    Ok(0)
}

fn read_handles(hptr: u64, n: usize) -> Result<Vec<Handle>, i64> {
    let mut raw = alloc::vec![0u8; n * 4];
    copy_from_user(&mut raw, hptr)?;
    Ok(raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

fn channel_write(h: Handle, ptr: u64, len: u64, hptr: u64, nh: u64) -> Result<i64, i64> {
    if len > MSG_MAX_BYTES as u64 || nh > MSG_MAX_HANDLES as u64 {
        return Err(ERR_INVALID);
    }
    let (len, nh) = (len as usize, nh as usize);
    let mut bytes = alloc::vec![0u8; len];
    copy_from_user(&mut bytes, ptr)?;
    let handles = read_handles(hptr, nh)?;
    let table = table()?;
    let waiters = {
        let mut t = table.lock();
        let ep = endpoint_of(t.get(h, Rights::WRITE).map_err(handle_err)?)?;
        // Every transferred handle must exist with TRANSFER, be distinct, and not be an end of
        // this very channel (which would keep an endpoint alive through its own queue).
        for (i, &hv) in handles.iter().enumerate() {
            if handles[..i].contains(&hv) {
                return Err(ERR_BAD_HANDLE);
            }
            let e = t.get(hv, Rights::TRANSFER).map_err(handle_err)?;
            if let Object::Channel(other) = &e.object {
                if other.same_channel(&ep) {
                    return Err(ERR_INVALID);
                }
            }
        }
        // Peer open and room reserved before anything moves; the channel stays locked until
        // commit, so the table is left untouched on every failure path.
        let slot = ep.reserve().map_err(channel_err)?;
        let moved: Vec<Entry> = handles
            .iter()
            .map(|&hv| t.remove(hv).expect("checked above"))
            .collect();
        slot.commit(Message {
            bytes,
            handles: moved,
        })
    };
    for tid in waiters {
        sched::wake(tid);
    }
    Ok(0)
}

fn channel_read(
    h: Handle,
    ptr: u64,
    cap: u64,
    hptr: u64,
    hcap: u64,
    flags: u64,
) -> Result<i64, i64> {
    if flags & !READ_BLOCK != 0 {
        return Err(ERR_INVALID);
    }
    let block = flags & READ_BLOCK != 0;
    let cap_b = (cap as usize).min(MSG_MAX_BYTES);
    let cap_h = (hcap as usize).min(MSG_MAX_HANDLES);
    user_range_ok(ptr, cap_b as u64, true)?;
    user_range_ok(hptr, (cap_h * 4) as u64, true)?;
    let table = table()?;
    let ep = {
        let t = table.lock();
        let needed = if block {
            Rights(Rights::READ.0 | Rights::WAIT.0)
        } else {
            Rights::READ
        };
        let e = t.get(h, needed).map_err(handle_err)?;
        if t.len() + cap_h > HANDLES_MAX {
            return Err(ERR_NO_RESOURCES);
        }
        endpoint_of(e)?
    };
    let tid = sched::current_tid();
    let msg = loop {
        match ep.read(cap_b, cap_h, if block { Some(tid) } else { None }) {
            Ok(m) => break m,
            Err(ChannelError::ShouldWait) if block => sched::block_current(),
            Err(e) => return Err(channel_err(e)),
        }
    };
    let nbytes = msg.bytes.len();
    let nhandles = msg.handles.len();
    copy_to_user(ptr, &msg.bytes)?;
    let mut values = Vec::with_capacity(nhandles * 4);
    {
        let mut t = table.lock();
        for e in msg.handles {
            // Capacity was checked above; a table that still refuses drops the handle.
            let hv = t.insert(e).unwrap_or(crate::object::handle::HANDLE_INVALID);
            values.extend_from_slice(&hv.to_le_bytes());
        }
    }
    copy_to_user(hptr, &values)?;
    Ok((nbytes as i64) | ((nhandles as i64) << 16))
}

fn handle_close(h: Handle) -> Result<i64, i64> {
    let table = table()?;
    let entry = table.lock().remove(h).map_err(handle_err)?;
    // Dropped outside the table lock: closing a channel end may wake another thread.
    drop(entry);
    Ok(0)
}

fn handle_duplicate(h: Handle, rights: u64) -> Result<i64, i64> {
    if rights > u64::from(u32::MAX) || !Rights(rights as u32).valid() {
        return Err(ERR_INVALID);
    }
    let table = table()?;
    let nh = table
        .lock()
        .duplicate(h, Rights(rights as u32))
        .map_err(handle_err)?;
    Ok(i64::from(nh))
}

fn vmo_create(size: u64) -> Result<i64, i64> {
    if size == 0 || !size.is_multiple_of(4096) || size > crate::object::VMO_MAX_BYTES {
        return Err(ERR_INVALID);
    }
    let table = table()?;
    let vmo = Vmo::new(size).ok_or(ERR_NO_RESOURCES)?;
    let h = table
        .lock()
        .insert(Entry {
            object: Object::Vmo(vmo),
            rights: Rights::VMO_DEFAULT,
        })
        .map_err(handle_err)?;
    Ok(i64::from(h))
}

fn handle_rights(h: Handle) -> Result<i64, i64> {
    let table = table()?;
    let r = table
        .lock()
        .get(h, Rights::NONE)
        .map_err(handle_err)?
        .rights;
    Ok(i64::from(r.0))
}

fn fs_err(e: FsError) -> i64 {
    match e {
        FsError::NotFound => ERR_NOT_FOUND,
        FsError::Exists => ERR_EXISTS,
        FsError::IsADirectory => ERR_IS_DIR,
        FsError::NotADirectory => ERR_NOT_DIR,
        FsError::BadName => ERR_BAD_PATH,
        FsError::DiskFull => ERR_NO_SPACE,
        FsError::Range => ERR_INVALID,
        FsError::NotMounted | FsError::Io(_) | FsError::BadBpb | FsError::Corrupt => ERR_IO,
    }
}

/// Copies a user path (at most PATH_MAX bytes) into a kernel buffer.
fn user_path(ptr: u64, len: u64, buf: &mut [u8; vfs::PATH_MAX]) -> Result<usize, i64> {
    if len == 0 || len > vfs::PATH_MAX as u64 {
        return Err(ERR_BAD_PATH);
    }
    copy_from_user(&mut buf[..len as usize], ptr)?;
    Ok(len as usize)
}

fn file_of(entry: &Entry) -> Result<vfs::FileRef, i64> {
    match &entry.object {
        Object::File(f) => Ok(f.clone()),
        _ => Err(ERR_WRONG_TYPE),
    }
}

fn sys_open(ptr: u64, len: u64, flags: u64) -> Result<i64, i64> {
    let mut buf = [0u8; vfs::PATH_MAX];
    let n = user_path(ptr, len, &mut buf)?;
    if flags & !vfs::O_VALID != 0 || flags & (vfs::O_READ | vfs::O_WRITE) == 0 {
        return Err(ERR_INVALID);
    }
    let table = table()?;
    let file = vfs::open(&buf[..n], flags).map_err(fs_err)?;
    let mut rights = Rights::FILE_BASE;
    if flags & vfs::O_READ != 0 {
        rights = Rights(rights.0 | Rights::READ.0);
    }
    if flags & vfs::O_WRITE != 0 {
        rights = Rights(rights.0 | Rights::WRITE.0);
    }
    let h = table
        .lock()
        .insert(Entry {
            object: Object::File(file),
            rights,
        })
        .map_err(handle_err)?;
    Ok(i64::from(h))
}

/// Bounded transfer per call (the kernel buffer lives on the heap).
const FILE_IO_MAX: usize = 64 * 1024;

fn sys_read(h: Handle, ptr: u64, len: u64) -> Result<i64, i64> {
    let len = (len as usize).min(FILE_IO_MAX);
    user_range_ok(ptr, len as u64, true)?;
    let table = table()?;
    let file = file_of(table.lock().get(h, Rights::READ).map_err(handle_err)?)?;
    let mut buf = alloc::vec![0u8; len];
    let n = vfs::read(&file, &mut buf).map_err(fs_err)?;
    copy_to_user(ptr, &buf[..n])?;
    Ok(n as i64)
}

fn sys_write(h: Handle, ptr: u64, len: u64) -> Result<i64, i64> {
    let len = (len as usize).min(FILE_IO_MAX);
    let mut buf = alloc::vec![0u8; len];
    copy_from_user(&mut buf, ptr)?;
    let table = table()?;
    let file = file_of(table.lock().get(h, Rights::WRITE).map_err(handle_err)?)?;
    let n = vfs::write(&file, &buf).map_err(fs_err)?;
    Ok(n as i64)
}

fn sys_stat(ptr: u64, len: u64, out: u64) -> Result<i64, i64> {
    let mut buf = [0u8; vfs::PATH_MAX];
    let n = user_path(ptr, len, &mut buf)?;
    user_range_ok(out, 16, true)?;
    let st = vfs::stat(&buf[..n]).map_err(fs_err)?;
    let mut rec = [0u8; 16];
    rec[..8].copy_from_slice(&st.size.to_le_bytes());
    rec[8..12].copy_from_slice(&u32::from(st.is_dir).to_le_bytes());
    rec[12..16].copy_from_slice(&st.first_cluster.to_le_bytes());
    copy_to_user(out, &rec)?;
    Ok(0)
}

fn sys_unlink(ptr: u64, len: u64) -> Result<i64, i64> {
    let mut buf = [0u8; vfs::PATH_MAX];
    let n = user_path(ptr, len, &mut buf)?;
    vfs::unlink(&buf[..n]).map_err(fs_err)?;
    Ok(0)
}

fn sys_seek(h: Handle, pos: u64) -> Result<i64, i64> {
    let table = table()?;
    let file = file_of(table.lock().get(h, Rights::NONE).map_err(handle_err)?)?;
    let p = vfs::seek(&file, pos).map_err(fs_err)?;
    Ok(p as i64)
}

fn as_handle(v: u64) -> Result<Handle, i64> {
    u32::try_from(v).map_err(|_| ERR_BAD_HANDLE)
}

fn flat(r: Result<i64, i64>) -> i64 {
    match r {
        Ok(v) => v,
        Err(e) => e,
    }
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
        SYS_CHANNEL_CREATE => flat(channel_create(args[0])),
        SYS_CHANNEL_WRITE => flat(
            as_handle(args[0]).and_then(|h| channel_write(h, args[1], args[2], args[3], args[4])),
        ),
        SYS_CHANNEL_READ => flat(
            as_handle(args[0])
                .and_then(|h| channel_read(h, args[1], args[2], args[3], args[4], args[5])),
        ),
        SYS_HANDLE_CLOSE => flat(as_handle(args[0]).and_then(handle_close)),
        SYS_HANDLE_DUPLICATE => flat(as_handle(args[0]).and_then(|h| handle_duplicate(h, args[1]))),
        SYS_VMO_CREATE => flat(vmo_create(args[0])),
        SYS_HANDLE_RIGHTS => flat(as_handle(args[0]).and_then(handle_rights)),
        SYS_OPEN => flat(sys_open(args[0], args[1], args[2])),
        SYS_READ => flat(as_handle(args[0]).and_then(|h| sys_read(h, args[1], args[2]))),
        SYS_WRITE => flat(as_handle(args[0]).and_then(|h| sys_write(h, args[1], args[2]))),
        SYS_STAT => flat(sys_stat(args[0], args[1], args[2])),
        SYS_UNLINK => flat(sys_unlink(args[0], args[1])),
        SYS_SEEK => flat(as_handle(args[0]).and_then(|h| sys_seek(h, args[1]))),
        SYS_SYNC => flat(vfs::sync().map(|_| 0).map_err(fs_err)),
        _ => ERR_NOSYS,
    }
}
