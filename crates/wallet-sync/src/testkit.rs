//! In-memory fakes of the ports (feature `testkit`).

use std::collections::{BTreeMap, VecDeque};
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use vault_core::WalletId;

use crate::ports::{
    IncomingCopy, MergeOutcome, MergeRequest, Merger, MonoClock, PeerId, StoreError, SyncStore,
    WallClock, WalletSource,
};
use crate::record::{SyncRecord, sha256};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where an injected failure strikes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    RecordWrite,
    IncomingAppend,
    IncomingFinish,
    PendingRead,
    PendingDelete,
}

#[derive(Default)]
struct StoreState {
    records: BTreeMap<WalletId, SyncRecord>,
    corrupt: Vec<WalletId>,
    pending: BTreeMap<(WalletId, PeerId), Vec<u8>>,
    partial: BTreeMap<(WalletId, PeerId), Vec<u8>>,
    failures: BTreeMap<Step, StoreError>,
    record_writes: usize,
}

impl StoreState {
    fn fail(&mut self, step: Step) -> Result<(), StoreError> {
        match self.failures.remove(&step) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// Sync store in memory. Clones share the same data.
#[derive(Clone, Default)]
pub struct MemorySyncStore(Arc<Mutex<StoreState>>);

impl MemorySyncStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The next operation at `step` fails with `error`.
    pub fn fail_once(&self, step: Step, error: StoreError) {
        lock(&self.0).failures.insert(step, error);
    }

    /// The record of `wallet` reads as corrupted until it is written again.
    pub fn corrupt(&self, wallet: &WalletId) {
        lock(&self.0).corrupt.push(*wallet);
    }

    pub fn has_partial(&self, wallet: &WalletId, peer: &PeerId) -> bool {
        lock(&self.0).partial.contains_key(&(*wallet, *peer))
    }

    pub fn partial_count(&self) -> usize {
        lock(&self.0).partial.len()
    }

    pub fn record_writes(&self) -> usize {
        lock(&self.0).record_writes
    }

    /// Puts raw pending bytes in place (e.g. a copy received earlier).
    pub fn put_pending(&self, wallet: &WalletId, peer: &PeerId, bytes: Vec<u8>) {
        lock(&self.0).pending.insert((*wallet, *peer), bytes);
    }
}

impl SyncStore for MemorySyncStore {
    fn wallets(&self) -> Result<Vec<WalletId>, StoreError> {
        Ok(lock(&self.0).records.keys().copied().collect())
    }

    fn load(&self, wallet: &WalletId) -> Result<Option<SyncRecord>, StoreError> {
        let state = lock(&self.0);
        if state.corrupt.contains(wallet) {
            return Err(StoreError::Corrupted);
        }
        Ok(state.records.get(wallet).cloned())
    }

    fn update(
        &self,
        wallet: &WalletId,
        f: &mut dyn FnMut(Option<SyncRecord>) -> Option<SyncRecord>,
    ) -> Result<Option<SyncRecord>, StoreError> {
        let mut state = lock(&self.0);
        if state.corrupt.contains(wallet) {
            return Err(StoreError::Corrupted);
        }
        let current = state.records.get(wallet).cloned();
        match f(current.clone()) {
            None => Ok(current),
            Some(next) => {
                state.fail(Step::RecordWrite)?;
                state.record_writes += 1;
                state.records.insert(*wallet, next.clone());
                Ok(Some(next))
            }
        }
    }

    fn begin_incoming(
        &self,
        wallet: &WalletId,
        peer: &PeerId,
    ) -> Result<Box<dyn IncomingCopy>, StoreError> {
        lock(&self.0).partial.insert((*wallet, *peer), Vec::new());
        Ok(Box::new(MemoryIncoming {
            store: self.clone(),
            key: (*wallet, *peer),
        }))
    }

    fn read_pending(&self, wallet: &WalletId, peer: &PeerId) -> Result<Vec<u8>, StoreError> {
        let mut state = lock(&self.0);
        state.fail(Step::PendingRead)?;
        state
            .pending
            .get(&(*wallet, *peer))
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    fn delete_pending(&self, wallet: &WalletId, peer: &PeerId) -> Result<(), StoreError> {
        let mut state = lock(&self.0);
        state.fail(Step::PendingDelete)?;
        state.pending.remove(&(*wallet, *peer));
        Ok(())
    }

    fn pending_peers(&self, wallet: &WalletId) -> Result<Vec<PeerId>, StoreError> {
        Ok(lock(&self.0)
            .pending
            .keys()
            .filter(|(w, _)| w == wallet)
            .map(|(_, p)| *p)
            .collect())
    }
}

struct MemoryIncoming {
    store: MemorySyncStore,
    key: (WalletId, PeerId),
}

impl IncomingCopy for MemoryIncoming {
    fn append(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        let mut state = lock(&self.store.0);
        state.fail(Step::IncomingAppend)?;
        state
            .partial
            .get_mut(&self.key)
            .ok_or(StoreError::Io)?
            .extend_from_slice(bytes);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<(), StoreError> {
        let mut state = lock(&self.store.0);
        let bytes = state.partial.remove(&self.key).ok_or(StoreError::Io)?;
        state.fail(Step::IncomingFinish)?;
        state.pending.insert(self.key, bytes);
        Ok(())
    }

    fn abort(self: Box<Self>) {
        lock(&self.store.0).partial.remove(&self.key);
    }
}

/// Settable monotonic clock.
#[derive(Default)]
pub struct FakeMonoClock(Mutex<Duration>);

impl FakeMonoClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn advance(&self, by: Duration) {
        *lock(&self.0) += by;
    }

    pub fn set(&self, now: Duration) {
        *lock(&self.0) = now;
    }
}

impl MonoClock for FakeMonoClock {
    fn now(&self) -> Duration {
        *lock(&self.0)
    }
}

/// Settable wall clock.
pub struct FakeWallClock(Mutex<u64>);

impl FakeWallClock {
    pub fn new(now: u64) -> Self {
        Self(Mutex::new(now))
    }

    pub fn set(&self, now: u64) {
        *lock(&self.0) = now;
    }
}

impl WallClock for FakeWallClock {
    fn unix_now(&self) -> u64 {
        *lock(&self.0)
    }
}

/// Stored wallet files in memory. Clones share the files.
#[derive(Clone, Default)]
pub struct FakeWalletSource(
    Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
);

impl FakeWalletSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, name: &str, bytes: Vec<u8>) {
        lock(&self.0).insert(name.to_string(), bytes);
    }

    pub fn get(&self, name: &str) -> Option<Vec<u8>> {
        lock(&self.0).get(name).cloned()
    }

    pub fn remove(&self, name: &str) {
        lock(&self.0).remove(name);
    }

    /// The next `open` of `name` streams `bytes` (the file changed after its digest was
    /// taken), while `digest` keeps reporting the stored bytes.
    pub fn change_on_open(&self, name: &str, bytes: Vec<u8>) {
        lock(&self.1).insert(name.to_string(), bytes);
    }
}

impl WalletSource for FakeWalletSource {
    fn open(&self, wallet_name: &str) -> Result<(u64, Box<dyn Read + Send>), StoreError> {
        let bytes = lock(&self.0)
            .get(wallet_name)
            .cloned()
            .ok_or(StoreError::NotFound)?;
        let size = bytes.len() as u64;
        let streamed = lock(&self.1).remove(wallet_name).unwrap_or(bytes);
        Ok((size, Box::new(Cursor::new(streamed))))
    }

    fn digest(&self, wallet_name: &str) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(lock(&self.0).get(wallet_name).map(|b| sha256(b)))
    }
}

/// Merger with scripted outcomes (default `Unchanged`); records every request.
#[derive(Default)]
pub struct FakeMerger {
    script: Mutex<VecDeque<MergeOutcome>>,
    requests: Mutex<Vec<MergeRequest>>,
}

impl FakeMerger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, outcome: MergeOutcome) {
        lock(&self.script).push_back(outcome);
    }

    pub fn requests(&self) -> Vec<MergeRequest> {
        lock(&self.requests).clone()
    }
}

impl Merger for FakeMerger {
    fn merge(&self, request: &MergeRequest) -> MergeOutcome {
        lock(&self.requests).push(request.clone());
        lock(&self.script)
            .pop_front()
            .unwrap_or(MergeOutcome::Unchanged)
    }
}
