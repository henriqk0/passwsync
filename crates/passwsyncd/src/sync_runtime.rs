//! Wallet sync inside the service (004): glue between `wallet-sync` (sans-IO engine),
//! `wallet-service` (merges under the wallet locks) and `device-link-net` (channel v2
//! frames). Runs only while networking is on (FR-001): with networking off there is no sync
//! thread, no sync file activity, and saves are plain saves.
//!
//! Threads: `sync-sched` (round starts, timeouts, sending frames, log) and `sync-merge`
//! (merging received copies into unlocked wallets).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use device_link::identity::DeviceId;
use device_link::wire::Payload;
use device_link_net::SyncFrameSink;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use vault_core::{SaveMeta, StateVector, StorageError, VaultStorage, WalletId};
use wallet_service::{
    CopyFacts, CopyVerdict, PeerRef, PendingCopies, PendingOutcome, PendingRef, Service,
    ServiceError, UnlockFacts, WalletDirectory, WalletName,
};
use wallet_sync::decide::jump_too_large;
use wallet_sync::journal::{Recovery, SaveRequest, journaled_save, recover};
use wallet_sync::ports::{
    MergeOutcome, MergeRequest, Merger, MonoClock, PeerId, StoreError, SyncStore, WallClock,
    WalletSource,
};
use wallet_sync::record::{SyncRecord, WarningKind, sha256};
use wallet_sync::round::{Engine, EngineConfig, EngineDeps, Frame, RoundClass, SyncEvent};
use wallet_sync::sched::{Scheduler, SyncTiming};
use wallet_sync::status::{RecordView, StatusInput, WalletSyncState, last_synced_at, wallet_state};

use crate::log::{Log, LogEvent, SyncRoundClass};
use crate::net_runtime::NetRuntime;
use crate::sync_store::FileSyncStore;

const THREAD_STACK: usize = 256 * 1024;
/// Frames sent per peer per pass (bounds memory and keeps peers interleaved).
const SEND_BATCH: usize = 64;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn device(peer: PeerId) -> DeviceId {
    DeviceId::from_bytes(peer.0)
}

pub(crate) fn peer_of(id: &DeviceId) -> PeerId {
    PeerId(*id.as_bytes())
}

struct StdMono(Instant);

impl MonoClock for StdMono {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

struct StdWall;

impl WallClock for StdWall {
    fn unix_now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// What a journaled save applies to the record besides the new digest and state: peer marks
/// raised by an accepted copy and the pending copies it consumed (research R12). Set on the
/// thread that performs the merge, taken by the save on that same thread.
#[derive(Default)]
pub(crate) struct SaveContext {
    pub peer_marks: BTreeMap<PeerId, StateVector>,
    pub consumed: BTreeSet<PeerId>,
}

thread_local! {
    static SAVE_CONTEXT: RefCell<Option<SaveContext>> = const { RefCell::new(None) };
}

fn add_context(peer: PeerId, state: StateVector) {
    SAVE_CONTEXT.with(|c| {
        let mut slot = c.borrow_mut();
        let ctx = slot.get_or_insert_with(SaveContext::default);
        ctx.peer_marks.insert(peer, state);
        ctx.consumed.insert(peer);
    });
}

/// Removes one peer's entry from this thread's pending save context.
fn take_context_peer(peer: PeerId) -> Option<StateVector> {
    SAVE_CONTEXT.with(|c| {
        let mut slot = c.borrow_mut();
        let ctx = slot.as_mut()?;
        ctx.consumed.remove(&peer);
        let mark = ctx.peer_marks.remove(&peer);
        if ctx.peer_marks.is_empty() && ctx.consumed.is_empty() {
            *slot = None;
        }
        mark
    })
}

fn take_context() -> Option<SaveContext> {
    SAVE_CONTEXT.with(|c| c.borrow_mut().take())
}

/// The device's own wallet files, read for offering (FR-006a). Digests are cached by
/// (size, mtime, inode) so idle rounds do not re-hash unchanged files.
/// `(size, mtime seconds, mtime nanoseconds, inode)` of a file whose digest is cached.
type FileKey = (u64, i64, i64, u64);

pub struct FsWalletSource {
    dir: PathBuf,
    cache: Mutex<HashMap<String, (FileKey, [u8; 32])>>,
}

impl FsWalletSource {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn path(&self, name: &str) -> Option<PathBuf> {
        WalletName::parse(name)
            .ok()
            .map(|n| self.dir.join(format!("{n}.pwsw")))
    }
}

impl WalletSource for FsWalletSource {
    fn open(&self, wallet_name: &str) -> Result<(u64, Box<dyn Read + Send>), StoreError> {
        let path = self.path(wallet_name).ok_or(StoreError::NotFound)?;
        let meta = fs::symlink_metadata(&path).map_err(|_| StoreError::NotFound)?;
        if !meta.is_file() {
            return Err(StoreError::NotFound);
        }
        let file = File::open(&path).map_err(|_| StoreError::Io)?;
        Ok((
            meta.len(),
            Box::new(io::BufReader::with_capacity(64 * 1024, file)),
        ))
    }

    fn digest(&self, wallet_name: &str) -> Result<Option<[u8; 32]>, StoreError> {
        let Some(path) = self.path(wallet_name) else {
            return Ok(None);
        };
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => m,
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Io),
        };
        let key = (meta.len(), meta.mtime(), meta.mtime_nsec(), meta.ino());
        if let Some((cached, digest)) = lock(&self.cache).get(wallet_name) {
            if *cached == key {
                return Ok(Some(*digest));
            }
        }
        let mut file = File::open(&path).map_err(|_| StoreError::Io)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(StoreError::Io),
            }
        }
        let digest: [u8; 32] = hasher.finalize().into();
        lock(&self.cache).insert(wallet_name.to_string(), (key, digest));
        Ok(Some(digest))
    }
}

#[derive(Default)]
struct Signals {
    stop: bool,
    work: bool,
}

/// State shared by the sync threads, the frame sink, the journaling storage and the
/// pending-copy port.
pub struct SyncShared {
    active: AtomicBool,
    engine: Mutex<Engine>,
    sched: Mutex<Scheduler>,
    epoch: Instant,
    signals: Mutex<Signals>,
    wake: Condvar,
    merge_queue: Mutex<Vec<MergeRequest>>,
    merge_wake: Condvar,
    pub(crate) store: Arc<FileSyncStore>,
    source: Arc<FsWalletSource>,
    net: Arc<NetRuntime>,
    service: Mutex<Weak<Service>>,
    log: Log,
    timing: SyncTiming,
    wall: Arc<dyn WallClock>,
}

impl SyncShared {
    pub fn active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    fn engine(&self) -> MutexGuard<'_, Engine> {
        lock(&self.engine)
    }

    fn service(&self) -> Option<Arc<Service>> {
        lock(&self.service).upgrade()
    }

    fn notify(&self) {
        lock(&self.signals).work = true;
        self.wake.notify_all();
    }

    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }

    fn sched(&self) -> MutexGuard<'_, Scheduler> {
        lock(&self.sched)
    }

    /// A wallet was saved locally: rounds start after the quiet period (FR-027 b).
    pub(crate) fn wallet_saved(&self) {
        let now = self.now();
        self.sched().wallet_saved(now);
        self.notify();
    }

    fn running_peers(&self) -> Vec<PeerId> {
        let engine = self.engine();
        engine
            .connected()
            .into_iter()
            .filter(|p| engine.round_running(*p))
            .collect()
    }

    /// (d) "Sync now" (coalesced while a round runs).
    pub(crate) fn sync_now(&self) {
        let running = self.running_peers();
        let now = self.now();
        self.sched().sync_now(now, &|p| running.contains(&p));
        self.notify();
    }

    /// Starts the rounds the scheduler says are due; returns the next deadline.
    fn schedule(&self) -> Option<Duration> {
        let running = self.running_peers();
        let now = self.now();
        let due = self.sched().due(now, &|p| running.contains(&p));
        for peer in due {
            let started = self.engine().start_round(peer);
            if !started {
                // Nothing to sync with this peer: counts as a round for the safety timer.
                self.sched().round_finished(peer, RoundClass::Ok, now);
            }
        }
        let engine_deadline = self.engine().tick();
        let sched_deadline = self.sched().next_deadline();
        [engine_deadline, sched_deadline]
            .into_iter()
            .flatten()
            .min()
    }

    fn warning_id() -> u64 {
        rand_core::RngCore::next_u64(&mut OsRng) & ((1 << 53) - 1)
    }

    /// A journaled save (research R12): prepare the record, write the wallet file through
    /// `write`, commit, delete consumed pending copies. A record write failure aborts the save
    /// before the wallet file is touched; a corrupted record (sync disabled for the wallet)
    /// never blocks a save.
    pub(crate) fn journaled_save(
        &self,
        name: &WalletName,
        meta: &SaveMeta<'_>,
        bytes: &[u8],
        ctx: SaveContext,
        write: &mut dyn FnMut(&[u8]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let existing = match self.store.load(&meta.wallet_id) {
            Ok(record) => record,
            Err(StoreError::Corrupted) => return write(bytes),
            Err(error) => return Err(error),
        };
        if existing
            .as_ref()
            .is_some_and(|r| r.flags.duplicate_wallet_id && r.wallet_name != name.as_str())
        {
            return write(bytes);
        }
        let was_flagged = existing.as_ref().is_some_and(|r| r.flags.rollback_state);
        let local = ctx.consumed.is_empty();
        let request = SaveRequest {
            wallet: meta.wallet_id,
            name: name.as_str(),
            bytes,
            state: meta.state,
            peer_marks: ctx.peer_marks,
            consumed: ctx.consumed,
        };
        journaled_save(self.store.as_ref(), &request, write)?;
        let after = self.store.update(&meta.wallet_id, &mut |r| {
            let mut r = r?;
            if local && r.flags.too_many_conflicts {
                // A local save (e.g. a resolution): pending copies are retried at unlock.
                r.flags.too_many_conflicts = false;
                return Some(r);
            }
            None
        });
        if let Ok(Some(r)) = after {
            if r.flags.rollback_state && !was_flagged {
                self.log
                    .emit(&LogEvent::SyncPossibleRollback { wallet: name });
            }
        }
        Ok(())
    }

    /// Start-up step 5c: recover every record's save journal against its wallet file and
    /// flag files changed outside the service. A corrupted record is reported and left as
    /// it is (sync stays disabled for that wallet; the service starts normally).
    fn recover_records(&self) {
        let Ok(wallets) = self.store.wallets() else {
            return;
        };
        for wallet in wallets {
            match self.store.load(&wallet) {
                Ok(Some(_)) => {}
                Err(StoreError::Corrupted) => {
                    if let Some(name) = self
                        .store
                        .raw_wallet_name(&wallet)
                        .and_then(|n| WalletName::parse(&n).ok())
                    {
                        self.log
                            .emit(&LogEvent::SyncRecordCorrupted { wallet: &name });
                    }
                    continue;
                }
                _ => continue,
            }
            let id = Self::warning_id();
            let at = self.wall.unix_now();
            let mut consumed = BTreeSet::new();
            let mut flagged = None;
            let _ = self.store.update(&wallet, &mut |r| {
                let mut r = r?;
                let digest = self.source.digest(&r.wallet_name).ok().flatten();
                let was = r.flags.rollback_digest;
                match recover(&mut r, digest) {
                    Recovery::Committed(c) => consumed = c,
                    Recovery::Flagged if !was => {
                        r.warn(id, WarningKind::PossibleRollback, None, at);
                        flagged = Some(r.wallet_name.clone());
                    }
                    Recovery::Missing => return None,
                    _ => {}
                }
                Some(r)
            });
            for peer in &consumed {
                let _ = self.store.delete_pending(&wallet, peer);
            }
            if let Some(name) = flagged.and_then(|n| WalletName::parse(&n).ok()) {
                self.log
                    .emit(&LogEvent::SyncPossibleRollback { wallet: &name });
            }
        }
    }

    /// The checks of a received copy (contracts/sync-protocol.md "Accepting a copy").
    fn verify(record: &SyncRecord, peer: PeerId, claimed: &StateVector, facts: &CopyFacts) -> bool {
        let mark = record.peers.get(&peer).and_then(|p| p.peer_mark.as_ref());
        facts.wallet_id == record.wallet_id
            && &facts.state == claimed
            && mark.is_none_or(|m| facts.state.dominates(m))
            && !jump_too_large(&facts.state, &record.state, mark)
    }

    fn log_event(&self, event: &SyncEvent) {
        let name = |n: &str| WalletName::parse(n).ok();
        match event {
            SyncEvent::RoundStarted { peer } => self.log.emit(&LogEvent::SyncRoundStart {
                fingerprint: &device(*peer).fingerprint(),
            }),
            SyncEvent::RoundEnded {
                peer,
                class,
                sent,
                received,
            } => self.log.emit(&LogEvent::SyncRoundEnd {
                fingerprint: &device(*peer).fingerprint(),
                class: match class {
                    RoundClass::Ok => SyncRoundClass::Ok,
                    RoundClass::Failed => SyncRoundClass::Failed,
                    RoundClass::Busy => SyncRoundClass::Busy,
                    RoundClass::Timeout => SyncRoundClass::Timeout,
                    RoundClass::Protocol => SyncRoundClass::Protocol,
                },
                sent: *sent,
                received: *received,
            }),
            SyncEvent::PendingStored { name: n, peer, .. } => {
                if let Some(wallet) = name(n) {
                    self.log.emit(&LogEvent::SyncPendingStored {
                        wallet: &wallet,
                        fingerprint: &device(*peer).fingerprint(),
                    });
                }
            }
            SyncEvent::OlderStateOffered { name: n, peer, .. } => {
                if let Some(wallet) = name(n) {
                    self.log.emit(&LogEvent::SyncOlderStateOffered {
                        wallet: &wallet,
                        fingerprint: &device(*peer).fingerprint(),
                    });
                }
            }
            SyncEvent::PossibleRollback { name: n, .. } => {
                if let Some(wallet) = name(n) {
                    self.log
                        .emit(&LogEvent::SyncPossibleRollback { wallet: &wallet });
                }
            }
            SyncEvent::InvalidCopy { name: n, peer, .. } => {
                if let Some(wallet) = name(n) {
                    self.log.emit(&LogEvent::SyncInvalidCopy {
                        wallet: &wallet,
                        fingerprint: &device(*peer).fingerprint(),
                    });
                }
            }
            SyncEvent::CannotOpen { name: n, peer, .. } => {
                if let Some(wallet) = name(n) {
                    self.log.emit(&LogEvent::SyncCannotOpenCopy {
                        wallet: &wallet,
                        fingerprint: &device(*peer).fingerprint(),
                    });
                }
            }
            SyncEvent::Merged {
                name: n,
                peer,
                conflicts,
                ..
            } => {
                if let Some(wallet) = name(n) {
                    self.log.emit(&LogEvent::SyncMerged {
                        wallet: &wallet,
                        fingerprint: &device(*peer).fingerprint(),
                        conflicts: *conflicts,
                    });
                }
            }
            SyncEvent::SelfRollbackRecovered { name: n, peer, .. } => {
                if let Some(wallet) = name(n) {
                    self.log.emit(&LogEvent::SyncSelfRollbackRecovered {
                        wallet: &wallet,
                        fingerprint: &device(*peer).fingerprint(),
                    });
                }
            }
            SyncEvent::CloseChannel { peer, conn } => self.net.close_channel(&device(*peer), *conn),
        }
    }

    /// Handles engine events and queues merge requests for the merge thread.
    fn drain_engine(&self) {
        let (events, merges) = {
            let mut engine = self.engine();
            (engine.take_events(), engine.take_merge_requests())
        };
        for event in &events {
            if let SyncEvent::RoundEnded { peer, class, .. } = event {
                let now = self.now();
                self.sched().round_finished(*peer, *class, now);
            }
            self.log_event(event);
        }
        if !merges.is_empty() {
            lock(&self.merge_queue).extend(merges);
            self.merge_wake.notify_all();
        }
    }

    /// Sends every queued frame (outside the engine lock, so readers never block on it).
    fn flush(&self) {
        loop {
            let batch: Vec<(PeerId, u64, Vec<Frame>)> = {
                let mut engine = self.engine();
                engine
                    .outgoing_peers()
                    .into_iter()
                    .map(|(peer, conn)| (peer, conn, engine.poll_outgoing(peer, SEND_BATCH)))
                    .filter(|(_, _, frames)| !frames.is_empty())
                    .collect()
            };
            if batch.is_empty() {
                break;
            }
            for (peer, conn, frames) in batch {
                let id = device(peer);
                for frame in frames {
                    let payload = match frame {
                        Frame::Ctl { more, fragment } => Payload::SyncCtl { more, fragment },
                        Frame::Data(bytes) => Payload::CopyData { bytes },
                    };
                    if self.net.send_sync(&id, conn, &payload).is_err() {
                        break;
                    }
                }
            }
            self.drain_engine();
        }
        self.drain_engine();
    }
}

/// Frames from the network threads (device-link-net calls these).
struct Sink(Arc<SyncShared>);

impl SyncFrameSink for Sink {
    fn channel_up(&self, peer: DeviceId, conn: u64, session: [u8; 32], dialer: bool) {
        self.0
            .engine()
            .channel_up(peer_of(&peer), conn, session, dialer);
        // A channel coming up starts a round (FR-027 a); simultaneous starts are resolved by
        // the dialer rule.
        let now = self.0.now();
        self.0.sched().channel_up(peer_of(&peer), now);
        self.0.notify();
    }

    fn frame(&self, peer: DeviceId, conn: u64, payload: Payload) {
        let frame = match payload {
            Payload::SyncCtl { more, fragment } => Frame::Ctl { more, fragment },
            Payload::CopyData { bytes } => Frame::Data(bytes),
            _ => return,
        };
        self.0.engine().on_frame(peer_of(&peer), conn, frame);
        self.0.notify();
    }

    fn channel_down(&self, peer: DeviceId, conn: u64) {
        self.0.engine().channel_down(peer_of(&peer), conn);
        self.0.drain_engine();
        self.0.sched().channel_down(peer_of(&peer));
        self.0.notify();
    }
}

/// Merges received copies through `wallet-service` (the save is journaled).
struct ServiceMerger(Arc<SyncShared>);

impl Merger for ServiceMerger {
    fn merge(&self, request: &MergeRequest) -> MergeOutcome {
        let shared = &self.0;
        let Some(service) = shared.service() else {
            return MergeOutcome::Locked;
        };
        let Ok(name) = WalletName::parse(&request.wallet_name) else {
            return MergeOutcome::Invalid;
        };
        let bytes = match shared.store.read_pending(&request.wallet, &request.peer) {
            Ok(bytes) => bytes,
            Err(StoreError::NotFound) => return MergeOutcome::Unchanged,
            Err(_) => return MergeOutcome::Invalid,
        };
        let Ok(Some(record)) = shared.store.load(&request.wallet) else {
            return MergeOutcome::Locked;
        };
        let accepted: RefCell<Option<StateVector>> = RefCell::new(None);
        let check = |facts: &CopyFacts| {
            if SyncShared::verify(&record, request.peer, &request.claimed, facts) {
                *accepted.borrow_mut() = Some(facts.state.clone());
                add_context(request.peer, facts.state.clone());
                CopyVerdict::Accept
            } else {
                CopyVerdict::Reject
            }
        };
        let result = service.merge_copy(&name, &bytes, &check);
        let left = take_context();
        match result {
            Ok(report) if report.changed => MergeOutcome::Merged {
                conflicts: report.conflicts_added,
                self_rollback: report.self_rollback_recovered,
                password_adopted: report.password_adopted,
            },
            Ok(_) => {
                // Nothing to save: raise the peer mark and drop the copy here.
                if let (Some(state), Some(_)) = (accepted.into_inner(), left) {
                    let peer = request.peer;
                    let _ = shared.store.update(&request.wallet, &mut |r| {
                        let mut r = r?;
                        r.raise_peer_mark(peer, &state);
                        r.pending.remove(&peer);
                        Some(r)
                    });
                    let _ = shared.store.delete_pending(&request.wallet, &peer);
                }
                MergeOutcome::Unchanged
            }
            Err(ServiceError::WalletLocked) => MergeOutcome::Locked,
            Err(ServiceError::CannotOpenCopy) => MergeOutcome::CannotOpen,
            Err(ServiceError::CopyRejected) => MergeOutcome::Invalid,
            Err(ServiceError::TooManyConflicts) => MergeOutcome::TooManyConflicts,
            Err(ServiceError::PasswordConflict) => MergeOutcome::PasswordConflict,
            Err(_) => MergeOutcome::StorageFailed,
        }
    }
}

/// The pending-copy port of `wallet-service` (unlock notification and pending merges).
struct SyncPort(Arc<SyncShared>);

impl SyncPort {
    fn wallet_of(&self, name: &WalletName) -> Option<SyncRecord> {
        let wallets = self.0.store.wallets().ok()?;
        wallets
            .into_iter()
            .filter_map(|w| self.0.store.load(&w).ok().flatten())
            .find(|r| r.wallet_name == name.as_str() && !r.flags.duplicate_wallet_id)
    }
}

impl PendingCopies for SyncPort {
    fn list(&self, wallet: &WalletName) -> Vec<PendingRef> {
        if !self.0.active() {
            return Vec::new();
        }
        self.wallet_of(wallet).map_or_else(Vec::new, |r| {
            r.pending
                .iter()
                .map(|(peer, p)| PendingRef {
                    peer: PeerRef(peer.0),
                    claimed_state: p.claimed.clone(),
                    size: p.size,
                })
                .collect()
        })
    }

    fn load(&self, wallet: &WalletName, peer: &PeerRef) -> Result<Vec<u8>, StorageError> {
        let record = self.wallet_of(wallet).ok_or(StorageError::NotFound)?;
        self.0
            .store
            .read_pending(&record.wallet_id, &PeerId(peer.0))
            .map_err(|_| StorageError::NotFound)
    }

    fn check(&self, wallet: &WalletName, peer: &PeerRef, facts: &CopyFacts) -> CopyVerdict {
        let Some(record) = self.wallet_of(wallet) else {
            return CopyVerdict::Reject;
        };
        let peer = PeerId(peer.0);
        let Some(pending) = record.pending.get(&peer) else {
            return CopyVerdict::Reject;
        };
        if SyncShared::verify(&record, peer, &pending.claimed, facts) {
            add_context(peer, facts.state.clone());
            CopyVerdict::Accept
        } else {
            CopyVerdict::Reject
        }
    }

    fn outcome(&self, wallet: &WalletName, peer: &PeerRef, outcome: PendingOutcome) {
        let Some(record) = self.wallet_of(wallet) else {
            return;
        };
        let peer_id = PeerId(peer.0);
        if outcome == PendingOutcome::Unchanged {
            // Accepted but nothing to save: raise the peer mark and drop the copy here.
            if let Some(state) = take_context_peer(peer_id) {
                let _ = self.0.store.update(&record.wallet_id, &mut |r| {
                    let mut r = r?;
                    r.raise_peer_mark(peer_id, &state);
                    r.pending.remove(&peer_id);
                    Some(r)
                });
                let _ = self.0.store.delete_pending(&record.wallet_id, &peer_id);
            }
        } else {
            let _ = take_context_peer(peer_id);
        }
        let request = MergeRequest {
            wallet: record.wallet_id,
            wallet_name: record.wallet_name.clone(),
            peer: PeerId(peer.0),
            claimed: StateVector::new(),
            peer_mark: None,
        };
        let mapped = match outcome {
            PendingOutcome::Merged {
                conflicts,
                self_rollback,
                password_adopted,
            } => MergeOutcome::Merged {
                conflicts,
                self_rollback,
                password_adopted,
            },
            PendingOutcome::Unchanged => MergeOutcome::Unchanged,
            PendingOutcome::CannotOpen => MergeOutcome::CannotOpen,
            PendingOutcome::PasswordConflict => MergeOutcome::PasswordConflict,
            PendingOutcome::TooManyConflicts => MergeOutcome::TooManyConflicts,
            PendingOutcome::Invalid => MergeOutcome::Invalid,
        };
        self.0.engine().merge_finished(&request, mapped);
        self.0.drain_engine();
        if matches!(mapped, MergeOutcome::Merged { .. }) {
            // (c) A wallet unlocked with pending copies: tell the peers soon.
            let now = self.0.now();
            self.0.sched().unlocked_with_pending(now);
            self.0.notify();
        }
    }

    fn unlocked(&self, wallet: &WalletName, file: &[u8], facts: &UnlockFacts) -> bool {
        if !self.0.active() {
            return false;
        }
        if facts.format_version == 1 {
            // Networking and pairing are the sync opt-in (research R3).
            return self.0.net.paired_count() > 0;
        }
        let digest = sha256(file);
        let id = SyncShared::warning_id();
        let at = self.0.wall.unix_now();
        let mut flagged = false;
        let _ = self.0.store.update(&facts.wallet_id, &mut |r| {
            let Some(mut r) = r else {
                return Some(SyncRecord::new(
                    facts.wallet_id,
                    wallet.to_string(),
                    digest,
                    facts.state.clone(),
                ));
            };
            if r.flags.duplicate_wallet_id {
                return None;
            }
            if r.wallet_name != wallet.as_str()
                && self
                    .0
                    .source
                    .digest(&r.wallet_name)
                    .ok()
                    .flatten()
                    .is_some()
            {
                // Another file with the same wallet id: sync is disabled for both.
                r.flags.duplicate_wallet_id = true;
                r.warn(id, WarningKind::DuplicateWalletId, None, at);
                return Some(r);
            }
            r.wallet_name = wallet.to_string();
            let was_flagged = r.flags.rollback_state;
            r.authenticated(digest, &facts.state);
            if r.flags.rollback_state {
                flagged = !was_flagged;
                r.warn(id, WarningKind::PossibleRollback, None, at);
            }
            Some(r)
        });
        if flagged {
            self.0.log.emit(&LogEvent::SyncPossibleRollback { wallet });
        }
        false
    }

    fn upgraded(&self, wallet: &WalletName) {
        self.0.log.emit(&LogEvent::WalletUpgraded { wallet });
    }
}

/// `WalletDirectory` whose storages journal every save into the sync record (all saves:
/// local edits, merges, resolutions, upgrades, password changes).
pub struct JournalingDirectory {
    inner: Arc<dyn WalletDirectory>,
    shared: Arc<SyncShared>,
}

impl JournalingDirectory {
    pub fn new(inner: Arc<dyn WalletDirectory>, shared: Arc<SyncShared>) -> Self {
        Self { inner, shared }
    }
}

impl WalletDirectory for JournalingDirectory {
    fn list(&self) -> Result<Vec<WalletName>, StorageError> {
        self.inner.list()
    }

    fn exists(&self, name: &WalletName) -> Result<bool, StorageError> {
        self.inner.exists(name)
    }

    fn storage(&self, name: &WalletName) -> Box<dyn VaultStorage + Send> {
        Box::new(JournalingStorage {
            inner: self.inner.storage(name),
            name: name.clone(),
            shared: Arc::clone(&self.shared),
        })
    }
}

struct JournalingStorage {
    inner: Box<dyn VaultStorage + Send>,
    name: WalletName,
    shared: Arc<SyncShared>,
}

impl VaultStorage for JournalingStorage {
    fn load(&self) -> Result<Vec<u8>, StorageError> {
        self.inner.load()
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.inner.store(bytes)
    }

    fn store_versioned(&mut self, bytes: &[u8], meta: &SaveMeta<'_>) -> Result<(), StorageError> {
        if !self.shared.active() {
            let _ = take_context();
            return self.inner.store(bytes);
        }
        let ctx = take_context().unwrap_or_default();
        let inner = &mut self.inner;
        let mut inner_error = None;
        let result = self
            .shared
            .journaled_save(&self.name, meta, bytes, ctx, &mut |b| {
                inner.store(b).map_err(|e| {
                    inner_error = Some(e);
                    StoreError::Io
                })
            });
        match (result, inner_error) {
            (Ok(()), _) => {
                self.shared.wallet_saved();
                Ok(())
            }
            (Err(_), Some(error)) => Err(error),
            (Err(_), None) => Err(StorageError::Io(io::Error::other(
                "sync record write failed",
            ))),
        }
    }
}

/// One warning as shown by `GET /api/sync`.
#[derive(Clone, Debug)]
pub struct WarningView {
    pub id: u64,
    pub kind: &'static str,
    pub wallet: String,
    pub peer: Option<PeerId>,
    pub at: u64,
}

/// The sync side of the service.
pub struct SyncRuntime {
    shared: Arc<SyncShared>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl SyncRuntime {
    pub fn new(
        sync_dir: PathBuf,
        wallets_dir: PathBuf,
        net: Arc<NetRuntime>,
        log: Log,
        safety: Duration,
    ) -> Self {
        let mut timing = net.sync_timing();
        timing.safety = safety;
        let store = Arc::new(FileSyncStore::new(sync_dir));
        let source = Arc::new(FsWalletSource::new(wallets_dir));
        let wall: Arc<dyn WallClock> = Arc::new(StdWall);
        let engine = Engine::new(
            EngineDeps {
                store: store.clone(),
                source: source.clone() as Arc<dyn WalletSource>,
                mono: Arc::new(StdMono(Instant::now())),
                wall: wall.clone(),
                rng: Box::new(OsRng),
            },
            EngineConfig {
                round_timeout: timing.round_timeout,
                ..EngineConfig::default()
            },
        );
        Self {
            shared: Arc::new(SyncShared {
                active: AtomicBool::new(false),
                engine: Mutex::new(engine),
                sched: Mutex::new(Scheduler::new(timing, Box::new(OsRng))),
                epoch: Instant::now(),
                signals: Mutex::new(Signals::default()),
                wake: Condvar::new(),
                merge_queue: Mutex::new(Vec::new()),
                merge_wake: Condvar::new(),
                store,
                source,
                net,
                service: Mutex::new(Weak::new()),
                log,
                timing,
                wall,
            }),
            threads: Mutex::new(Vec::new()),
        }
    }

    pub fn shared(&self) -> Arc<SyncShared> {
        Arc::clone(&self.shared)
    }

    /// Connects the service (weakly: the service owns the journaling directory).
    pub fn attach(&self, service: &Arc<Service>) {
        *lock(&self.shared.service) = Arc::downgrade(service);
        service.set_pending_copies(Arc::new(SyncPort(Arc::clone(&self.shared))));
    }

    pub fn active(&self) -> bool {
        self.shared.active()
    }

    /// Start-up step 5c/5d: only with networking on. Never fatal: a sync directory that
    /// cannot be used leaves sync off.
    pub fn start(&self) {
        let shared = &self.shared;
        if shared.store.prepare().is_err() {
            return;
        }
        shared.recover_records();
        let _ = shared.store.cleanup();
        shared.active.store(true, Ordering::SeqCst);
        shared.net.set_sync_sink(Arc::new(Sink(Arc::clone(shared))));
        let mut threads = lock(&self.threads);
        let sched = Arc::clone(shared);
        if let Ok(handle) = thread::Builder::new()
            .name("sync-sched".into())
            .stack_size(THREAD_STACK)
            .spawn(move || run_sched(&sched))
        {
            threads.push(handle);
        }
        let merge = Arc::clone(shared);
        if let Ok(handle) = thread::Builder::new()
            .name("sync-merge".into())
            .stack_size(THREAD_STACK)
            .spawn(move || run_merge(&merge))
        {
            threads.push(handle);
        }
    }

    /// Shutdown: rounds aborted (partial copies deleted), threads stopped, before the
    /// network closes.
    pub fn stop(&self) {
        let shared = &self.shared;
        if !shared.active.swap(false, Ordering::SeqCst) {
            return;
        }
        lock(&shared.signals).stop = true;
        shared.wake.notify_all();
        shared.merge_wake.notify_all();
        for handle in lock(&self.threads).drain(..) {
            let _ = handle.join();
        }
        shared.engine().abort_all();
        shared.drain_engine();
        shared.store.delete_partials();
    }

    /// Every warning of every record (local wallet names only), plus one synthesized
    /// "record corrupted" warning per unreadable record.
    pub fn warnings(&self) -> Vec<WarningView> {
        let store = &self.shared.store;
        let mut out = Vec::new();
        for wallet in store.wallets().unwrap_or_default() {
            match store.load(&wallet) {
                Ok(Some(r)) => {
                    for w in &r.warnings {
                        out.push(WarningView {
                            id: w.id,
                            kind: w.kind.word(),
                            wallet: r.wallet_name.clone(),
                            peer: w.peer,
                            at: w.at,
                        });
                    }
                }
                Err(StoreError::Corrupted) => {
                    if let Some(name) = store.raw_wallet_name(&wallet) {
                        let b = wallet.as_bytes();
                        let id = u64::from_be_bytes([0, 0, b[0], b[1], b[2], b[3], b[4], b[5]])
                            & ((1 << 53) - 1);
                        out.push(WarningView {
                            id,
                            kind: WarningKind::RecordCorrupted.word(),
                            wallet: name,
                            peer: None,
                            at: 0,
                        });
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Removes the warnings `ids`; never changes marks, flags or data (FR-036).
    pub fn dismiss(&self, ids: &[u64]) {
        let store = &self.shared.store;
        for wallet in store.wallets().unwrap_or_default() {
            let _ = store.update(&wallet, &mut |r| {
                let mut r = r?;
                let before = r.warnings.len();
                r.warnings.retain(|w| !ids.contains(&w.id));
                (r.warnings.len() != before).then_some(r)
            });
        }
    }

    /// "Accept this older state" (FR-021): the mark and this wallet's peer marks are reset
    /// to the authenticated current state. The wallet must be unlocked (the caller checks).
    pub fn accept_older(&self, name: &WalletName, wallet: WalletId, state: &StateVector) -> bool {
        let done = self.shared.store.update(&wallet, &mut |r| {
            let mut r = r?;
            if r.wallet_name != name.as_str() {
                return None;
            }
            r.mark = state.clone();
            r.state = state.clone();
            r.flags.rollback_state = false;
            r.flags.rollback_digest = false;
            for peer in r.peers.values_mut() {
                peer.peer_mark = None;
            }
            Some(r)
        });
        let ok = matches!(done, Ok(Some(ref r)) if r.wallet_name == name.as_str());
        if ok {
            self.shared
                .log
                .emit(&LogEvent::SyncAcceptedOlderState { wallet: name });
        }
        ok
    }

    /// "Reset sync state" (research R11): the record is rebuilt from the authenticated file
    /// (mark = state, peer marks cleared, pending lines kept when readable).
    pub fn reset(&self, name: &WalletName, wallet: WalletId, state: &StateVector) -> bool {
        let store = &self.shared.store;
        let Ok(Some(digest)) = self.shared.source.digest(name.as_str()) else {
            return false;
        };
        let mut record = SyncRecord::new(wallet, name.to_string(), digest, state.clone());
        if let Ok(Some(old)) = store.load(&wallet) {
            record.pending = old.pending;
        }
        if store.overwrite(&record).is_err() {
            return false;
        }
        self.shared
            .log
            .emit(&LogEvent::SyncStateReset { wallet: name });
        true
    }

    /// Peers with a running round.
    pub fn running(&self) -> Vec<PeerId> {
        self.shared.running_peers()
    }

    /// "Sync now" (FR-027 d). `false` while networking is off.
    pub fn sync_now(&self) -> bool {
        if !self.active() {
            return false;
        }
        self.shared.sync_now();
        true
    }

    /// The safety interval in minutes.
    pub fn interval_minutes(&self) -> u64 {
        self.shared.timing.safety.as_secs() / 60
    }

    /// Latest round time and outcome with `peer` over all records.
    pub fn peer_round(&self, peer: &DeviceId) -> (Option<u64>, Option<&'static str>) {
        let peer = peer_of(peer);
        let store = &self.shared.store;
        let mut best: (Option<u64>, Option<&'static str>) = (None, None);
        for wallet in store.wallets().unwrap_or_default() {
            if let Ok(Some(r)) = store.load(&wallet) {
                if let Some(p) = r.peers.get(&peer) {
                    if p.last_round_at > best.0 {
                        best = (
                            p.last_round_at,
                            (p.last_outcome != wallet_sync::record::Outcome::None)
                                .then(|| p.last_outcome.word()),
                        );
                    }
                }
            }
        }
        best
    }

    /// The record of `name` as the status sees it (duplicates included, corrupted by name).
    fn record_view(&self, name: &WalletName) -> (Option<SyncRecord>, bool) {
        let store = &self.shared.store;
        let mut corrupted = false;
        for wallet in store.wallets().unwrap_or_default() {
            match store.load(&wallet) {
                Ok(Some(r)) if r.wallet_name == name.as_str() => return (Some(r), false),
                Err(StoreError::Corrupted)
                    if store.raw_wallet_name(&wallet).as_deref() == Some(name.as_str()) =>
                {
                    corrupted = true;
                }
                _ => {}
            }
        }
        (None, corrupted)
    }

    /// The derived sync state of one wallet (data-model.md) and its last successful sync.
    pub fn wallet_status(
        &self,
        name: &WalletName,
        conflicts: u32,
    ) -> (WalletSyncState, Option<u64>, Option<SyncRecord>) {
        if !self.active() {
            return (WalletSyncState::SyncOff, None, None);
        }
        let (record, corrupted) = self.record_view(name);
        let format_version = if record.is_none() && !corrupted {
            self.shared
                .source
                .open(name.as_str())
                .ok()
                .and_then(|(_, mut reader)| {
                    let mut head = Vec::with_capacity(128);
                    reader.by_ref().take(128).read_to_end(&mut head).ok()?;
                    head.resize(head.len().max(79), 0);
                    vault_core::peek_format_version(&head).ok()
                })
        } else {
            None
        };
        let syncing = record.as_ref().is_some_and(|r| {
            self.shared
                .engine()
                .syncing_wallets()
                .contains(&r.wallet_id)
        });
        let view = match (&record, corrupted) {
            (Some(r), _) => RecordView::Present(r),
            (None, true) => RecordView::Corrupted,
            (None, false) => RecordView::Missing,
        };
        let state = wallet_state(&StatusInput {
            networking_on: true,
            record: view,
            format_version,
            conflicts,
            syncing,
        });
        let last = record.as_ref().and_then(last_synced_at);
        (state, last, record)
    }

    /// Whether `peer` currently has a sync channel.
    pub fn connected(&self, peer: &PeerId) -> bool {
        self.shared.engine().connected().contains(peer)
    }

    /// The record of the wallet named `name` (not a duplicate), if any.
    pub fn record_of(&self, name: &WalletName) -> Option<SyncRecord> {
        let store = &self.shared.store;
        store
            .wallets()
            .ok()?
            .into_iter()
            .filter_map(|w| store.load(&w).ok().flatten())
            .find(|r| r.wallet_name == name.as_str() && !r.flags.duplicate_wallet_id)
    }

    /// Discards a pending copy (file and record line). `false` when there is none.
    pub fn discard(&self, name: &WalletName, peer: &DeviceId) -> bool {
        let Some(record) = self.record_of(name) else {
            return false;
        };
        let peer = peer_of(peer);
        if !record.pending.contains_key(&peer) {
            return false;
        }
        let _ = self.shared.store.update(&record.wallet_id, &mut |r| {
            let mut r = r?;
            r.pending.remove(&peer);
            Some(r)
        });
        let _ = self.shared.store.delete_pending(&record.wallet_id, &peer);
        true
    }

    /// A peer was revoked: its rounds stop and its pending copies and peer lines go.
    pub fn revoke(&self, peer: &DeviceId) {
        if !self.active() {
            return;
        }
        self.shared.engine().revoke_peer(peer_of(peer));
        self.shared.drain_engine();
    }
}

fn run_sched(shared: &Arc<SyncShared>) {
    loop {
        let deadline = shared.schedule();
        shared.flush();
        let mut signals = lock(&shared.signals);
        if signals.stop {
            return;
        }
        if !signals.work {
            // Sleep until the next deadline or a signal; no timer at all when nothing is due.
            signals = match deadline {
                Some(at) => {
                    let wait = at
                        .saturating_sub(shared.now())
                        .max(Duration::from_millis(5));
                    shared
                        .wake
                        .wait_timeout(signals, wait)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => shared
                    .wake
                    .wait(signals)
                    .unwrap_or_else(PoisonError::into_inner),
            };
            if signals.stop {
                return;
            }
        }
        signals.work = false;
    }
}

fn run_merge(shared: &Arc<SyncShared>) {
    let merger = ServiceMerger(Arc::clone(shared));
    loop {
        let requests = {
            let mut queue = lock(&shared.merge_queue);
            loop {
                if lock(&shared.signals).stop {
                    return;
                }
                if !queue.is_empty() {
                    break std::mem::take(&mut *queue);
                }
                queue = shared
                    .merge_wake
                    .wait_timeout(queue, Duration::from_secs(1))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
        };
        for request in requests {
            let outcome = merger.merge(&request);
            shared.engine().merge_finished(&request, outcome);
            shared.drain_engine();
        }
        shared.notify();
    }
}
