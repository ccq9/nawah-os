//! Per-process handle table (contract §1): slots with a generation counter, so a closed
//! handle's value is refused even after its slot is reused.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{Object, Rights};

/// Handles a process may hold at once.
pub const HANDLES_MAX: usize = 1024;
const INDEX_BITS: u32 = 16;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;

/// A handle value: `(generation << 16) | index`, never 0.
pub type Handle = u32;
pub const HANDLE_INVALID: Handle = 0;

#[derive(Clone)]
pub struct Entry {
    pub object: Object,
    pub rights: Rights,
}

struct Slot {
    /// Generation of the entry now in the slot, or of the next entry if empty; starts at 1 and
    /// skips 0 when it wraps, so a value never becomes 0.
    generation: u16,
    entry: Option<Entry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleError {
    /// Unknown index, empty slot or a stale generation.
    BadHandle,
    /// The handle exists but lacks a required right.
    Access,
    /// The table is full.
    NoResources,
}

pub struct HandleTable {
    slots: Vec<Slot>,
    live: usize,
}

static LIVE_HANDLES: AtomicU32 = AtomicU32::new(0);

pub fn live_handles() -> u32 {
    LIVE_HANDLES.load(Ordering::Relaxed)
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleTable {
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            live: 0,
        }
    }

    /// Live entries (clippy's `len_without_is_empty` is moot: this is not a collection API).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.live
    }

    fn value(index: usize, generation: u16) -> Handle {
        (u32::from(generation) << INDEX_BITS) | (index as u32 & INDEX_MASK)
    }

    fn split(handle: Handle) -> (usize, u16) {
        (
            (handle & INDEX_MASK) as usize,
            (handle >> INDEX_BITS) as u16,
        )
    }

    /// Installs `entry` in the lowest free slot and returns its handle.
    pub fn insert(&mut self, entry: Entry) -> Result<Handle, HandleError> {
        if let Some(i) = self.slots.iter().position(|s| s.entry.is_none()) {
            let s = &mut self.slots[i];
            s.entry = Some(entry);
            self.live += 1;
            LIVE_HANDLES.fetch_add(1, Ordering::Relaxed);
            return Ok(Self::value(i, s.generation));
        }
        if self.slots.len() >= HANDLES_MAX {
            return Err(HandleError::NoResources);
        }
        self.slots.push(Slot {
            generation: 1,
            entry: Some(entry),
        });
        self.live += 1;
        LIVE_HANDLES.fetch_add(1, Ordering::Relaxed);
        Ok(Self::value(self.slots.len() - 1, 1))
    }

    fn slot_of(&self, handle: Handle) -> Result<usize, HandleError> {
        let (i, generation) = Self::split(handle);
        match self.slots.get(i) {
            Some(s) if s.entry.is_some() && s.generation == generation => Ok(i),
            _ => Err(HandleError::BadHandle),
        }
    }

    /// The entry behind `handle`, checked to carry `required` rights.
    pub fn get(&self, handle: Handle, required: Rights) -> Result<&Entry, HandleError> {
        let i = self.slot_of(handle)?;
        let e = self.slots[i].entry.as_ref().ok_or(HandleError::BadHandle)?;
        if !e.rights.contains(required) {
            return Err(HandleError::Access);
        }
        Ok(e)
    }

    /// Removes `handle` and returns its entry; the slot's generation moves on.
    pub fn remove(&mut self, handle: Handle) -> Result<Entry, HandleError> {
        let i = self.slot_of(handle)?;
        let s = &mut self.slots[i];
        let e = s.entry.take().ok_or(HandleError::BadHandle)?;
        s.generation = match s.generation.wrapping_add(1) {
            0 => 1,
            g => g,
        };
        self.live -= 1;
        LIVE_HANDLES.fetch_sub(1, Ordering::Relaxed);
        Ok(e)
    }

    /// A second handle to the same object with `rights`, which must be a subset of the
    /// source's; the source needs DUPLICATE.
    pub fn duplicate(&mut self, handle: Handle, rights: Rights) -> Result<Handle, HandleError> {
        let src = self.get(handle, Rights::DUPLICATE)?;
        if !rights.valid() || !src.rights.contains(rights) {
            return Err(HandleError::Access);
        }
        let entry = Entry {
            object: src.object.clone(),
            rights,
        };
        self.insert(entry)
    }
}

impl Drop for HandleTable {
    fn drop(&mut self) {
        // Entries drop with the vector; only the live count needs keeping honest.
        LIVE_HANDLES.fetch_sub(self.live as u32, Ordering::Relaxed);
        self.live = 0;
    }
}
