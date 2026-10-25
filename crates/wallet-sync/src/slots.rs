//! Service-wide transfer slots shared by the 004 sync engine and the 005 share engine
//! (research R8, FR-017): at most `max` wallet-copy transfers at once, sync and share
//! together. A slot is held by a [`SlotGuard`] and released when the guard is dropped, so
//! every abort path (error, early return, panic, drop of the transfer) frees it.

use std::sync::{Arc, Mutex, PoisonError};

#[derive(Debug)]
pub struct TransferSlots {
    max: usize,
    active: Mutex<usize>,
}

impl TransferSlots {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            active: Mutex::new(0),
        })
    }

    /// Takes a slot if one is free.
    pub fn try_take(self: &Arc<Self>) -> Option<SlotGuard> {
        let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        if *active >= self.max {
            return None;
        }
        *active += 1;
        Some(SlotGuard {
            slots: Arc::clone(self),
        })
    }

    /// Slots currently held.
    pub fn active(&self) -> usize {
        *self.active.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn max(&self) -> usize {
        self.max
    }
}

/// One held transfer slot; dropping it releases the slot.
#[derive(Debug)]
pub struct SlotGuard {
    slots: Arc<TransferSlots>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut active = self
            .slots
            .active
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *active = active.saturating_sub(1);
    }
}
