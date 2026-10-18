//! Channels (contract §2): two endpoints, each with a bounded queue of messages that carry
//! bytes and handles. One lock per channel covers both sides. An endpoint closes when its last
//! reference goes (the handle table entries and in-transit copies are the references), which
//! wakes a reader blocked on the other side so it sees `PeerClosed`.
//!
//! Known limitation (ADR-0011): a message in transit that carries a handle to an endpoint of
//! the channel it sits in would keep that endpoint alive through its own queue, so writing
//! either endpoint of a channel through that channel is refused by the caller; a cycle through
//! two channels is not detected (as in Zircon) and is left to WP-22's review.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::handle::Entry;
use crate::sched;
use crate::sync::{IrqGuard, IrqSpinLock};

pub const MSG_MAX_BYTES: usize = 4096;
pub const MSG_MAX_HANDLES: usize = 4;
pub const QUEUE_MAX: usize = 64;

pub struct Message {
    pub bytes: Vec<u8>,
    pub handles: Vec<Entry>,
}

struct Side {
    queue: VecDeque<Message>,
    open: bool,
    /// Threads blocked reading this side.
    waiters: Vec<u32>,
}

struct Shared {
    sides: IrqSpinLock<[Side; 2]>,
}

pub struct Endpoint {
    shared: Arc<Shared>,
    side: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    PeerClosed,
    ShouldWait,
    /// The next message needs this many bytes and handles; nothing was consumed.
    BufferTooSmall {
        bytes: usize,
        handles: usize,
    },
}

static LIVE_CHANNELS: AtomicU32 = AtomicU32::new(0);
static LIVE_ENDPOINTS: AtomicU32 = AtomicU32::new(0);

pub fn live_channels() -> u32 {
    LIVE_CHANNELS.load(Ordering::Relaxed)
}

pub fn live_endpoints() -> u32 {
    LIVE_ENDPOINTS.load(Ordering::Relaxed)
}

fn side() -> Side {
    Side {
        queue: VecDeque::new(),
        open: true,
        waiters: Vec::new(),
    }
}

/// A new channel: its two endpoints.
pub fn create() -> (Arc<Endpoint>, Arc<Endpoint>) {
    let shared = Arc::new(Shared {
        sides: IrqSpinLock::new("channel", [side(), side()]),
    });
    LIVE_CHANNELS.fetch_add(1, Ordering::Relaxed);
    LIVE_ENDPOINTS.fetch_add(2, Ordering::Relaxed);
    (
        Arc::new(Endpoint {
            shared: shared.clone(),
            side: 0,
        }),
        Arc::new(Endpoint { shared, side: 1 }),
    )
}

impl Endpoint {
    /// Whether `other` is the other end of this endpoint's channel (or this very endpoint).
    pub fn same_channel(&self, other: &Endpoint) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    /// Queues `msg` for the peer and wakes its blocked readers. The caller has already checked
    /// sizes and rights.
    pub fn write(&self, msg: Message) -> Result<(), ChannelError> {
        let waiters = self.reserve()?.commit(msg);
        for tid in waiters {
            sched::wake(tid);
        }
        Ok(())
    }

    /// First half of a write: checks that the peer is open and has room, and keeps the channel
    /// locked so the caller can finish its own bookkeeping (moving handles out of its table)
    /// before `commit`, with nothing able to change the channel in between.
    pub fn reserve(&self) -> Result<WriteSlot<'_>, ChannelError> {
        let sides = self.shared.sides.lock();
        let peer = &sides[1 - self.side];
        if !peer.open {
            return Err(ChannelError::PeerClosed);
        }
        if peer.queue.len() >= QUEUE_MAX {
            return Err(ChannelError::ShouldWait);
        }
        Ok(WriteSlot {
            sides,
            peer: 1 - self.side,
        })
    }

    /// Takes the next message if it fits `cap_bytes`/`cap_handles`. With `waiter`, an empty
    /// queue whose peer is still open registers that thread for a wake-up before returning
    /// `ShouldWait`, atomically with the emptiness check (no lost wake-up: the writer either
    /// sees the waiter or the waiter sees the message).
    pub fn read(
        &self,
        cap_bytes: usize,
        cap_handles: usize,
        waiter: Option<u32>,
    ) -> Result<Message, ChannelError> {
        let mut sides = self.shared.sides.lock();
        let peer_open = sides[1 - self.side].open;
        let me = &mut sides[self.side];
        match me.queue.front() {
            None if !peer_open => Err(ChannelError::PeerClosed),
            None => {
                if let Some(tid) = waiter {
                    if !me.waiters.contains(&tid) {
                        me.waiters.push(tid);
                    }
                }
                Err(ChannelError::ShouldWait)
            }
            Some(m) if m.bytes.len() > cap_bytes || m.handles.len() > cap_handles => {
                Err(ChannelError::BufferTooSmall {
                    bytes: m.bytes.len(),
                    handles: m.handles.len(),
                })
            }
            Some(_) => Ok(me.queue.pop_front().expect("front exists")),
        }
    }
}

/// A reserved place in the peer's queue (the channel lock is held until `commit` or drop).
pub struct WriteSlot<'a> {
    sides: IrqGuard<'a, [Side; 2]>,
    peer: usize,
}

impl WriteSlot<'_> {
    /// Queues the message and returns the threads to wake once the caller's locks are gone.
    #[must_use = "the returned threads must be woken"]
    pub fn commit(mut self, msg: Message) -> Vec<u32> {
        let peer = &mut self.sides[self.peer];
        peer.queue.push_back(msg);
        core::mem::take(&mut peer.waiters)
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        // Close this side; the peer's readers learn it once its queue is drained. Messages
        // waiting on this side die here with the handles they carry (after the lock is gone,
        // since those handles may close other channels).
        let (dead, waiters) = {
            let mut sides = self.shared.sides.lock();
            sides[self.side].open = false;
            let dead = core::mem::take(&mut sides[self.side].queue);
            let waiters = core::mem::take(&mut sides[1 - self.side].waiters);
            (dead, waiters)
        };
        drop(dead);
        for tid in waiters {
            sched::wake(tid);
        }
        LIVE_ENDPOINTS.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        LIVE_CHANNELS.fetch_sub(1, Ordering::Relaxed);
    }
}
