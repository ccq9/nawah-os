//! Kernel objects, rights and the per-process handle table (WP-16, ADR-0011,
//! docs/contracts/ipc.md). Authority is a handle: a per-process (index, generation) pair that
//! names a reference-counted object together with the rights that handle carries. Nothing is
//! reachable without a handle, every operation checks handle, type and rights first, and the
//! last reference frees the object — so a process that exits with everything open leaks
//! nothing.

pub mod channel;
pub mod handle;
pub mod kbd;
pub mod nic;
pub mod process;
pub mod token;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::mm::pmm::{self, Frame};

pub use channel::Endpoint;
pub use handle::{HandleTable, HANDLES_MAX};

/// Rights carried by a handle (contract §1). A bit set means the operation is allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(pub u32);

impl Rights {
    pub const READ: Rights = Rights(0x1);
    pub const WRITE: Rights = Rights(0x2);
    pub const DUPLICATE: Rights = Rights(0x4);
    pub const TRANSFER: Rights = Rights(0x8);
    pub const MAP: Rights = Rights(0x10);
    pub const WAIT: Rights = Rights(0x20);
    pub const NONE: Rights = Rights(0);
    /// Every defined bit; anything else in a rights word is invalid.
    pub const ALL: Rights = Rights(0x3F);
    /// Rights of a fresh channel endpoint handle.
    pub const CHANNEL_DEFAULT: Rights =
        Rights(Self::READ.0 | Self::WRITE.0 | Self::DUPLICATE.0 | Self::TRANSFER.0 | Self::WAIT.0);
    /// Rights every open-file handle has besides READ/WRITE (which follow the open flags).
    pub const FILE_BASE: Rights = Rights(Self::DUPLICATE.0 | Self::TRANSFER.0);
    /// Rights of a fresh VMO handle.
    pub const VMO_DEFAULT: Rights =
        Rights(Self::READ.0 | Self::WRITE.0 | Self::DUPLICATE.0 | Self::TRANSFER.0 | Self::MAP.0);
    /// Rights of the handle `process_spawn` returns (WP-23).
    pub const PROCESS_DEFAULT: Rights = Rights(Self::WAIT.0 | Self::DUPLICATE.0 | Self::TRANSFER.0);
    /// Rights of the token handle its minter gets (WP-25): WRITE revokes; a client copy
    /// goes out without it.
    pub const TOKEN_MINTER: Rights = Rights(Self::WRITE.0 | Self::DUPLICATE.0 | Self::TRANSFER.0);
    /// Rights of the authority handle (WP-25).
    pub const AUTHORITY_DEFAULT: Rights = Rights(Self::DUPLICATE.0 | Self::TRANSFER.0);
    /// Rights of the network interface handle (WP-27): READ receives, WRITE sends.
    pub const NIC_DEFAULT: Rights =
        Rights(Self::READ.0 | Self::WRITE.0 | Self::WAIT.0 | Self::DUPLICATE.0 | Self::TRANSFER.0);
    /// Rights of the keyboard handle (WP-27).
    pub const KBD_DEFAULT: Rights =
        Rights(Self::READ.0 | Self::WAIT.0 | Self::DUPLICATE.0 | Self::TRANSFER.0);

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn valid(self) -> bool {
        self.0 & !Self::ALL.0 == 0
    }
}

/// What a handle can name.
#[derive(Clone)]
pub enum Object {
    Channel(Arc<Endpoint>),
    Vmo(Arc<Vmo>),
    /// An open file (WP-19); READ/WRITE rights gate the calls.
    File(crate::fs::vfs::FileRef),
    /// A process the holder spawned (WP-23); WAIT gates waiting for its exit.
    Process(Arc<process::ProcessObject>),
    /// A session token (WP-25); WRITE gates revocation.
    Token(Arc<token::Token>),
    /// The capability to mint tokens (WP-25); the value only exists to be held (its drop
    /// keeps the live count), nothing reads it.
    Authority(#[allow(dead_code)] Arc<token::Authority>),
    /// The network interface (WP-27): raw frames in and out.
    Nic(Arc<nic::NicObject>),
    /// The keyboard (WP-27): scancode bytes.
    Keyboard(Arc<kbd::KeyboardObject>),
}

impl Object {
    /// The type code `handle_type` reports (syscall.md §6).
    pub fn type_code(&self) -> u32 {
        match self {
            Object::Channel(_) => 1,
            Object::Vmo(_) => 2,
            Object::File(_) => 3,
            Object::Process(_) => 4,
            Object::Token(_) => 5,
            Object::Authority(_) => 6,
            Object::Nic(_) => 7,
            Object::Keyboard(_) => 8,
        }
    }
}

/// Largest VMO (contract §3).
pub const VMO_MAX_BYTES: u64 = 1024 * 1024;

/// A memory object: whole frames owned until the last reference goes.
pub struct Vmo {
    frames: Vec<Frame>,
}

impl Vmo {
    /// Allocates `size` bytes (a page multiple, at most `VMO_MAX_BYTES`) of zeroed frames.
    pub fn new(size: u64) -> Option<Arc<Vmo>> {
        if size == 0 || !size.is_multiple_of(4096) || size > VMO_MAX_BYTES {
            return None;
        }
        let n = (size / 4096) as usize;
        let mut frames = Vec::with_capacity(n);
        for _ in 0..n {
            match pmm::alloc_frame() {
                Some(f) => frames.push(f),
                None => {
                    for f in frames {
                        let _ = pmm::free_frame(f);
                    }
                    return None;
                }
            }
        }
        LIVE_VMOS.fetch_add(1, Ordering::Relaxed);
        Some(Arc::new(Vmo { frames }))
    }

    pub fn size(&self) -> u64 {
        self.frames.len() as u64 * 4096
    }
}

impl Drop for Vmo {
    fn drop(&mut self) {
        for f in self.frames.drain(..) {
            let _ = pmm::free_frame(f);
        }
        LIVE_VMOS.fetch_sub(1, Ordering::Relaxed);
    }
}

static LIVE_VMOS: AtomicU32 = AtomicU32::new(0);

/// Live object counts (leak checks in the test kernel and the boot self-check).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub channels: u32,
    pub endpoints: u32,
    pub vmos: u32,
    pub handles: u32,
    pub files: u32,
    pub processes: u32,
    pub tokens: u32,
    pub authorities: u32,
}

pub fn stats() -> Stats {
    Stats {
        channels: channel::live_channels(),
        endpoints: channel::live_endpoints(),
        vmos: LIVE_VMOS.load(Ordering::Relaxed),
        handles: handle::live_handles(),
        files: crate::fs::vfs::live_files(),
        processes: process::live(),
        tokens: token::live_tokens(),
        authorities: token::live_authorities(),
    }
}
