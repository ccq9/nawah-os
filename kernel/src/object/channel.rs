//! Channels (contract §2): two endpoints, each with a bounded queue of messages that carry
//! bytes and handles. One lock per channel covers both sides. An endpoint closes when its last
//! reference goes (the handle table entries and in-transit copies are the references), which
//! wakes a reader blocked on the other side so it sees `PeerClosed`.
//!
//! Known limitation (ADR-0011): a message in transit that carries a handle to an endpoint of
//! the channel it sits in would keep that endpoint alive through its own queue, so writing
//! either endpoint of a channel through that channel is refused by the caller. A cycle through
//! more channels is refused at transfer since WP-176 (`may_travel`, under `TRANSIT`): an endpoint
//! whose own queue holds a message carrying a channel endpoint does not travel.
//!
//! Charges (WP-176, syscall.md v1.17): a channel made for a process
//! (`create_in`) is charged `CHANNEL_PAGES` to that process's job until both endpoints are gone,
//! and a message a process writes is charged `message_pages` to the writer's job until it is
//! read or dropped. The kernel's own channels and messages are not charged.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::handle::Entry;
use super::job::{Charge, Job};
use super::Object;
use crate::sched;
use crate::sync::{IrqGuard, IrqSpinLock};

pub const MSG_MAX_BYTES: usize = 4096;
pub const MSG_MAX_HANDLES: usize = 4;
pub const QUEUE_MAX: usize = 64;

/// What a channel made for a process is charged to its job (WP-176): a page for each block it
/// takes from the kernel's heap, its state, its two endpoints and its two queues' buffers (each
/// at most a page: `QUEUE_MAX` places of `Queued`, asserted below).
pub const CHANNEL_PAGES: u64 = 5;

pub struct Message {
    pub bytes: Vec<u8>,
    pub handles: Vec<Entry>,
}

/// A queued message and what it is charged to its writer's job (None: the kernel wrote it, or it
/// carries nothing).
struct Queued {
    msg: Message,
    charge: Option<Charge>,
}

const _: () = assert!(core::mem::size_of::<Queued>() * QUEUE_MAX <= 4096);

struct Side {
    queue: VecDeque<Queued>,
    open: bool,
    /// Threads blocked reading this side.
    waiters: Vec<u32>,
}

struct Shared {
    sides: IrqSpinLock<[Side; 2]>,
    /// The pages charged for the channel itself (None for the kernel's own channels).
    charge: Option<Charge>,
}

pub struct Endpoint {
    shared: Arc<Shared>,
    side: usize,
    /// The next endpoint on `drop_messages`' list of endpoints to empty (only while it holds the
    /// last reference to this one).
    next_dead: IrqSpinLock<Option<Arc<Endpoint>>>,
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
    /// The kernel's heap had no room for the queue to grow (v1.17 draft): nothing was queued.
    NoMemory,
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

/// A new channel of the kernel's own (not charged): its two endpoints.
pub fn create() -> (Arc<Endpoint>, Arc<Endpoint>) {
    make(None)
}

/// A new channel for a process of `job` (WP-176): `CHANNEL_PAGES` charged to the job before
/// anything is taken from the heap, None (and nothing made) when its quota or the system's limit
/// refuses them. They come back once both endpoints are gone (see `Shared`'s drop).
pub fn create_in(job: &Arc<Job>) -> Option<(Arc<Endpoint>, Arc<Endpoint>)> {
    let charge = job.charge(CHANNEL_PAGES)?;
    Some(make(Some(charge)))
}

fn make(charge: Option<Charge>) -> (Arc<Endpoint>, Arc<Endpoint>) {
    let shared = Arc::new(Shared {
        sides: IrqSpinLock::new("channel", [side(), side()]),
        charge,
    });
    LIVE_CHANNELS.fetch_add(1, Ordering::Relaxed);
    LIVE_ENDPOINTS.fetch_add(2, Ordering::Relaxed);
    let end = |shared: Arc<Shared>, side: usize| {
        Arc::new(Endpoint {
            shared,
            side,
            next_dead: IrqSpinLock::new("channel_dead", None),
        })
    };
    (end(shared.clone(), 0), end(shared, 1))
}

/// The pages a message of `len` bytes and `nh` handles is charged to its writer (WP-176): one
/// for its bytes, one for its list of handles, none for an empty message.
pub fn message_pages(len: usize, nh: usize) -> u64 {
    u64::from(len > 0) + u64::from(nh > 0)
}

/// Charges a message to `job` before its buffers are taken: None when refused, Some(None) when
/// it costs nothing.
pub fn charge_message(job: &Arc<Job>, len: usize, nh: usize) -> Option<Option<Charge>> {
    match message_pages(len, nh) {
        0 => Some(None),
        n => job.charge(n).map(Some),
    }
}

/// A message's two buffers, for `len` bytes (zeroed) and `nh` handles (empty, with room), taken
/// before anything moves (WP-176): fallible, NoMemory when the heap has no room for either.
pub fn message_buffers(len: usize, nh: usize) -> Result<(Vec<u8>, Vec<Entry>), ChannelError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| ChannelError::NoMemory)?;
    bytes.resize(len, 0);
    let mut handles = Vec::new();
    handles
        .try_reserve_exact(nh)
        .map_err(|_| ChannelError::NoMemory)?;
    Ok((bytes, handles))
}

/// Held by every write that moves a channel end from the check of `may_travel` to its commit, so
/// two such writes never both pass the check against a queue the other is about to fill (WP-176).
/// Taken under the writer's handle table lock and before any channel's lock; writes that move no
/// channel end (VMOs, tokens) do not take it.
static TRANSIT: IrqSpinLock<()> = IrqSpinLock::new("channel_transit", ());

pub fn transit() -> IrqGuard<'static, ()> {
    TRANSIT.lock()
}

/// Whether the message carries an endpoint of a channel.
fn carries_channel(msg: &Message) -> bool {
    msg.handles
        .iter()
        .any(|e| matches!(e.object, Object::Channel(_)))
}

impl Endpoint {
    /// Closes this endpoint, which is about to be dropped, and takes the messages queued for it,
    /// so the live peer cannot queue another one in between; see `drop_messages`.
    fn take_queue(&self) -> VecDeque<Queued> {
        let mut sides = self.shared.sides.lock();
        sides[self.side].open = false;
        core::mem::take(&mut sides[self.side].queue)
    }

    /// Whether `other` is the other end of this endpoint's channel (or this very endpoint).
    pub fn same_channel(&self, other: &Endpoint) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    /// Whether this endpoint may be carried in a message (WP-176): not while its own queue holds
    /// a message that carries a channel endpoint, since queueing it could close a cycle of
    /// channels each holding the next, which nothing would ever drop. Checked under `transit()`.
    pub fn may_travel(&self) -> bool {
        let sides = self.shared.sides.lock();
        !sides[self.side]
            .queue
            .iter()
            .any(|q| carries_channel(&q.msg))
    }

    /// Queues `msg` for the peer and wakes its blocked readers. The caller has already checked
    /// sizes and rights. The kernel's messages are not charged.
    pub fn write(&self, msg: Message) -> Result<(), ChannelError> {
        let waiters = self.reserve()?.commit(msg, None);
        for tid in waiters {
            sched::wake(tid);
        }
        Ok(())
    }

    /// First half of a write: checks that the peer is open and has room, and keeps the channel
    /// locked so the caller can finish its own bookkeeping (moving handles out of its table)
    /// before `commit`, with nothing able to change the channel in between.
    pub fn reserve(&self) -> Result<WriteSlot<'_>, ChannelError> {
        let mut sides = self.shared.sides.lock();
        let peer = &mut sides[1 - self.side];
        if !peer.open {
            return Err(ChannelError::PeerClosed);
        }
        if peer.queue.len() >= QUEUE_MAX {
            return Err(ChannelError::ShouldWait);
        }
        // The place itself, taken now, so `commit` never allocates (WP-176).
        peer.queue
            .try_reserve(1)
            .map_err(|_| ChannelError::NoMemory)?;
        Ok(WriteSlot {
            sides,
            peer: 1 - self.side,
        })
    }

    /// Takes the next message if it fits `cap_bytes`/`cap_handles`. For the kernel's own reads:
    /// the message passes to the kernel, whose holdings are not charged, so its writer's charge
    /// comes back as it leaves the queue (`read_charged` lets a reader free it first, as
    /// channel_read does). With `waiter`, an empty
    /// queue whose peer is still open registers that thread for a wake-up before returning
    /// `ShouldWait`, atomically with the emptiness check (no lost wake-up: the writer either
    /// sees the waiter or the waiter sees the message).
    pub fn read(
        &self,
        cap_bytes: usize,
        cap_handles: usize,
        waiter: Option<u32>,
    ) -> Result<Message, ChannelError> {
        self.read_charged(cap_bytes, cap_handles, waiter)
            .map(|(charge, msg)| {
                drop(charge);
                msg
            })
    }

    /// As `read`, with the message's charge, for the reader to drop once it freed the message.
    pub fn read_charged(
        &self,
        cap_bytes: usize,
        cap_handles: usize,
        waiter: Option<u32>,
    ) -> Result<(Option<Charge>, Message), ChannelError> {
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
            Some(Queued { msg: m, .. })
                if m.bytes.len() > cap_bytes || m.handles.len() > cap_handles =>
            {
                Err(ChannelError::BufferTooSmall {
                    bytes: m.bytes.len(),
                    handles: m.handles.len(),
                })
            }
            Some(_) => {
                let q = me.queue.pop_front().expect("front exists");
                Ok((q.charge, q.msg))
            }
        }
    }
}

/// Signals `poll` reports (contract §5, WP-23): a message is waiting / the peer closed.
pub const SIGNAL_READABLE: u32 = 1;
pub const SIGNAL_PEER_CLOSED: u32 = 2;

impl Endpoint {
    /// The signals currently asserted among `wanted`; when none is, `waiter` is registered for
    /// a wake-up atomically with the check (as in `read`), so a message or close that arrives
    /// afterwards wakes it.
    pub fn poll(&self, wanted: u32, waiter: Option<u32>) -> u32 {
        let mut sides = self.shared.sides.lock();
        let peer_open = sides[1 - self.side].open;
        let me = &mut sides[self.side];
        let mut asserted = 0;
        if !me.queue.is_empty() {
            asserted |= SIGNAL_READABLE;
        }
        if !peer_open {
            asserted |= SIGNAL_PEER_CLOSED;
        }
        let hit = asserted & wanted;
        if hit == 0 {
            if let Some(tid) = waiter {
                if !me.waiters.contains(&tid) {
                    me.waiters.push(tid);
                }
            }
        }
        hit
    }

    /// Drops a registration left by `poll`/`read` (a waiter that gave up: timeout).
    pub fn forget_waiter(&self, tid: u32) {
        let mut sides = self.shared.sides.lock();
        sides[self.side].waiters.retain(|t| *t != tid);
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
    pub fn commit(mut self, msg: Message, charge: Option<Charge>) -> Vec<u32> {
        let peer = &mut self.sides[self.peer];
        // Its place was reserved by `reserve`: no allocation here.
        peer.queue.push_back(Queued { msg, charge });
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
        drop_messages(dead);
        for tid in waiters {
            sched::wake(tid);
        }
        LIVE_ENDPOINTS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Drops dead messages without recursing through the channels they carry. A message can hold
/// the last reference to an endpoint whose own queue holds the last reference to another, and
/// so on: dropped recursively, such a chain costs a few stack frames per link, and one a user
/// process builds in a loop overflows the kernel stack (review 2026-10-19). Each endpoint about
/// to die is kept on a list linked through the endpoints themselves (`next_dead`, so the list
/// takes nothing from the heap, WP-176), then closed and its queue taken before it is dropped,
/// so its own drop finds nothing to recurse into. Only the holder of the last reference can see a
/// count of 1 (there are no weak references to endpoints), so a queue is never taken from an
/// endpoint that lives on. Each message's charge comes back after its bytes and its list of
/// handles are freed.
fn drop_messages(dead: VecDeque<Queued>) {
    let mut list: Option<Arc<Endpoint>> = None;
    let mut work = dead;
    loop {
        while let Some(Queued { msg, charge }) = work.pop_front() {
            let Message { bytes, handles } = msg;
            drop(bytes);
            for entry in handles {
                match entry.object {
                    Object::Channel(ep) if Arc::strong_count(&ep) == 1 => {
                        *ep.next_dead.lock() = list.take();
                        list = Some(ep);
                    }
                    other => drop(other),
                }
            }
            drop(charge);
        }
        drop(work);
        let Some(ep) = list else { break };
        list = ep.next_dead.lock().take();
        work = ep.take_queue();
        drop(ep);
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        // Both endpoints are gone, and each took and freed its queue; what is left of the queues
        // goes first, then the charge, so the pages come back once the queues' buffers are freed
        // (this state's block and the last endpoint's are freed right after, by the Arcs).
        let left = {
            let mut sides = self.sides.lock();
            [
                core::mem::take(&mut sides[0].queue),
                core::mem::take(&mut sides[1].queue),
            ]
        };
        for q in left {
            drop_messages(q);
        }
        drop(self.charge.take());
        LIVE_CHANNELS.fetch_sub(1, Ordering::Relaxed);
    }
}
