//! Wallet sharing inside the service (005): glue between the sans-IO `wallet-sync` share
//! engine, `wallet-service` (opening a received wallet), `device-link-net` (channel v3 share
//! frames, `ensure_channel`) and the received-file store. Share frames arrive through the
//! 004 `SyncFrameSink` and leave through the 004 `sync-sched` flush; time-driven steps run on
//! the existing 15-second sweeper tick (no new thread or periodic wake, SC-007). The only
//! extra thread is a short-lived worker that opens the channel for a redemption.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use device_link::identity::DeviceId;
use device_link::wire::{HelloVersion, Payload};
use device_link_net::EnsureError;
use rand_core::OsRng;
use wallet_service::{AdoptVerdict, LockObserver, Service, ServiceError, UnlockFacts, WalletName};
use wallet_sync::ports::{MonoClock, PeerId, ReceivedStore, StoreError, WallClock};
use wallet_sync::share::codec::ShareMsg;
use wallet_sync::share::{
    AcceptError, CancelOutcome, CreateError, DeleteCause, DiscardError, Failure, InvitationEnd,
    InviteWallet, MAX_RECEIVED, NoticeKind, OutFrame, RECEIVED_FUTURE_SLACK_SECS,
    RECEIVED_RETENTION_SECS, RedeemError, Refusal, ShareDeps, ShareEngine, ShareEvent,
};
use wallet_sync::slots::TransferSlots;
use zeroize::Zeroizing;

use crate::log::{
    CleanClass, DiscardReason, InvitationEnd as LogEnd, Log, LogEvent, RedeemRefusal, ShareFailure,
};
use crate::net_runtime::{NetRuntime, NetState};
use crate::share_store::FsReceivedStore;
use crate::sync_runtime::{FsWalletSource, SyncShared, device, peer_of};
use crate::sync_store::FileSyncStore;

/// Frames sent per peer per pass (as 004).
const SEND_BATCH: usize = 64;
const WORKER_STACK: usize = 128 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Monotonic and wall clocks of the share engine; tests move them forward together.
pub struct ShareClock {
    epoch: Instant,
    offset: Mutex<Duration>,
}

impl ShareClock {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    pub fn advance(&self, by: Duration) {
        *lock(&self.offset) += by;
    }

    fn offset(&self) -> Duration {
        *lock(&self.offset)
    }
}

impl MonoClock for ShareClock {
    fn now(&self) -> Duration {
        self.epoch.elapsed() + self.offset()
    }
}

impl WallClock for ShareClock {
    fn unix_now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            + self.offset().as_secs()
    }
}

struct MonoOf(Arc<ShareClock>);

impl MonoClock for MonoOf {
    fn now(&self) -> Duration {
        MonoClock::now(self.0.as_ref())
    }
}

struct WallOf(Arc<ShareClock>);

impl WallClock for WallOf {
    fn unix_now(&self) -> u64 {
        WallClock::unix_now(self.0.as_ref())
    }
}

fn log_failure(reason: Failure) -> ShareFailure {
    match reason {
        Failure::Invalid => ShareFailure::Invalid,
        Failure::CancelledBySender => ShareFailure::Cancelled,
        Failure::Expired => ShareFailure::Expired,
        Failure::Rejected => ShareFailure::Rejected,
        Failure::Busy => ShareFailure::Busy,
        Failure::TooLarge => ShareFailure::TooLarge,
        Failure::Storage => ShareFailure::Storage,
        Failure::SenderError => ShareFailure::SenderError,
        Failure::Unreachable => ShareFailure::Unreachable,
        Failure::Unsupported => ShareFailure::Unsupported,
        Failure::ReceivedLimit => ShareFailure::ReceivedLimit,
        Failure::ChannelLost => ShareFailure::ChannelLost,
        Failure::Timeout => ShareFailure::Timeout,
        Failure::IdMismatch => ShareFailure::IdMismatch,
        Failure::RecipientCancelled => ShareFailure::RecipientCancelled,
    }
}

/// The share engine and its channel side, owned by the 004 sync runtime's shared state so
/// share frames use the same sink and send path.
pub struct ShareCore {
    engine: Mutex<ShareEngine>,
    pub(crate) received: Arc<FsReceivedStore>,
    net: Arc<NetRuntime>,
    log: Log,
    pub(crate) clock: Arc<ShareClock>,
    /// Hello version of every channel by `(peer, conn)` (from `channel_version`).
    conn_versions: Mutex<HashMap<(DeviceId, u64), HelloVersion>>,
    /// The last version seen per peer this run (`peers[].share` while disconnected).
    seen: Mutex<HashMap<DeviceId, HelloVersion>>,
}

impl ShareCore {
    pub(crate) fn new(
        store: Arc<FileSyncStore>,
        source: Arc<FsWalletSource>,
        received: Arc<FsReceivedStore>,
        slots: Arc<TransferSlots>,
        net: Arc<NetRuntime>,
        log: Log,
    ) -> Self {
        let clock = Arc::new(ShareClock::new());
        let own_id = net
            .this_device
            .as_ref()
            .map_or(PeerId([0; 32]), |d| peer_of(&d.id));
        let engine = ShareEngine::new(ShareDeps {
            store,
            received: received.clone(),
            source,
            mono: Arc::new(MonoOf(Arc::clone(&clock))),
            wall: Arc::new(WallOf(Arc::clone(&clock))),
            rng: Box::new(OsRng),
            slots,
            own_id,
        });
        Self {
            engine: Mutex::new(engine),
            received,
            net,
            log,
            clock,
            conn_versions: Mutex::new(HashMap::new()),
            seen: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn engine(&self) -> MutexGuard<'_, ShareEngine> {
        lock(&self.engine)
    }

    // --- channel side (called by the 004 sink) ---

    pub(crate) fn channel_version(&self, peer: DeviceId, conn: u64, version: HelloVersion) {
        lock(&self.conn_versions).insert((peer, conn), version);
        lock(&self.seen).insert(peer, version);
    }

    pub(crate) fn channel_up(&self, peer: DeviceId, conn: u64, session: [u8; 32]) {
        let share = lock(&self.conn_versions).get(&(peer, conn)) == Some(&HelloVersion::V3);
        self.engine()
            .channel_up(peer_of(&peer), conn, session, share);
    }

    pub(crate) fn frame(&self, peer: DeviceId, conn: u64, payload: Payload) {
        match payload {
            Payload::ShareMsg { body } => match ShareMsg::decode(&body) {
                Ok(msg) => self.engine().on_msg(peer_of(&peer), conn, msg),
                Err(_) => self.net.close_channel(&peer, conn),
            },
            Payload::ShareData { bytes } => self.engine().on_data(peer_of(&peer), conn, &bytes),
            _ => {}
        }
        self.drain();
    }

    pub(crate) fn channel_down(&self, peer: DeviceId, conn: u64) {
        self.engine().channel_down(peer_of(&peer), conn);
        lock(&self.conn_versions).remove(&(peer, conn));
        self.drain();
    }

    /// Sends every queued share frame (outside the engine lock).
    pub(crate) fn flush(&self) {
        loop {
            let batch: Vec<(PeerId, u64, Vec<OutFrame>)> = {
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
                        OutFrame::Msg(msg) => Payload::ShareMsg { body: msg.encode() },
                        OutFrame::Data(bytes) => Payload::ShareData { bytes },
                    };
                    if self.net.send_sync(&id, conn, &payload).is_err() {
                        break;
                    }
                }
            }
            self.drain();
        }
        self.drain();
    }

    /// Logs engine events and closes channels after protocol errors.
    pub(crate) fn drain(&self) {
        let events = self.engine().take_events();
        self.handle(events);
    }

    fn handle(&self, events: Vec<ShareEvent>) {
        for event in events {
            self.log_event(&event);
        }
    }

    fn log_event(&self, event: &ShareEvent) {
        let log = &self.log;
        let fp = |p: &PeerId| device(*p).fingerprint();
        match event {
            ShareEvent::InvitationCreated { recipient } => {
                log.emit(&LogEvent::ShareInvitationCreated {
                    fingerprint: &fp(recipient),
                })
            }
            ShareEvent::InvitationEnded { end } => {
                log.emit(&LogEvent::ShareInvitationEnded(match end {
                    InvitationEnd::Cancelled => LogEnd::Cancelled,
                    InvitationEnd::Replaced => LogEnd::Replaced,
                    InvitationEnd::Locked => LogEnd::Locked,
                    InvitationEnd::Revoked => LogEnd::Revoked,
                    InvitationEnd::Expired => LogEnd::Expired,
                    InvitationEnd::Rejected => LogEnd::Rejected,
                    InvitationEnd::Completed => LogEnd::Completed,
                    InvitationEnd::Failed => LogEnd::Failed,
                }))
            }
            ShareEvent::RedeemRefused { peer, why } => log.emit(&LogEvent::ShareRedeemRefused {
                fingerprint: &fp(peer),
                why: match why {
                    Refusal::WrongCode => RedeemRefusal::WrongCode,
                    Refusal::NotRecipient => RedeemRefusal::NotRecipient,
                    Refusal::NoInvitation => RedeemRefusal::NoInvitation,
                    Refusal::Expired => RedeemRefusal::Expired,
                    Refusal::Used => RedeemRefusal::Used,
                    Refusal::Cancelled => RedeemRefusal::Cancelled,
                },
            }),
            ShareEvent::Redeemed { peer } => log.emit(&LogEvent::ShareRedeemed {
                fingerprint: &fp(peer),
            }),
            ShareEvent::Accepted { peer } => log.emit(&LogEvent::ShareAccepted {
                fingerprint: &fp(peer),
            }),
            ShareEvent::TransferCompleted { peer, bytes } => {
                log.emit(&LogEvent::ShareTransferCompleted {
                    fingerprint: &fp(peer),
                    bytes: *bytes,
                })
            }
            ShareEvent::TransferAborted {
                peer,
                reason,
                bytes,
            } => log.emit(&LogEvent::ShareTransferAborted {
                fingerprint: &fp(peer),
                reason: log_failure(*reason),
                bytes: *bytes,
            }),
            ShareEvent::ReceiveStarted { peer } => log.emit(&LogEvent::ShareReceiveStarted {
                fingerprint: &fp(peer),
            }),
            ShareEvent::Received { peer, bytes } => log.emit(&LogEvent::ShareReceived {
                fingerprint: &fp(peer),
                bytes: *bytes,
            }),
            ShareEvent::ReceiveFailed { peer, reason } => log.emit(&LogEvent::ShareReceiveFailed {
                fingerprint: &fp(peer),
                reason: log_failure(*reason),
            }),
            ShareEvent::ReceivedDeleted { sender, why } => log.emit(&LogEvent::ReceivedDiscarded {
                fingerprint: &fp(sender),
                why: match why {
                    DeleteCause::Expired => DiscardReason::Expired,
                    DeleteCause::Revoked => DiscardReason::Revoked,
                },
            }),
            ShareEvent::CloseChannel { peer, conn } => {
                self.net.close_channel(&device(*peer), *conn)
            }
        }
    }

    /// The sweeper tick: expiry, waiting bounds, retention.
    pub(crate) fn tick(&self) {
        let events = self.engine().tick();
        self.handle(events);
    }

    /// `supported | unsupported | unknown` for `peer` (FR-024).
    pub fn peer_share(&self, peer: &DeviceId) -> &'static str {
        let word = |v: HelloVersion| {
            if v == HelloVersion::V3 {
                "supported"
            } else {
                "unsupported"
            }
        };
        if let Some(version) = self.net.channel_version(peer) {
            return word(version);
        }
        if let Some(version) = lock(&self.seen).get(peer) {
            return word(*version);
        }
        match self.net.max_version(peer) {
            Some(HelloVersion::V3) | None => "unknown",
            Some(_) => "unsupported",
        }
    }
}

/// Why a sharing action was refused (mapped to HTTP errors by `http::api_share`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareError {
    NetworkingOff,
    WalletNotFound,
    WalletLocked,
    NotEligible(&'static str),
    /// Accept found the wallet locked: the invitation was cancelled (409).
    LockedCancelled,
    DeviceNotFound,
    PeerUnsupported,
    Busy,
    TooManyInvitations,
    NothingPending,
    Mismatch,
    Expired,
    SenderError,
    SelfDevice,
    ReceivedLimit,
    ReceivedNotFound,
    /// The received wallet is already held under this local name.
    AlreadyPresent(String),
    Service(ServiceError),
    Internal,
}

/// The HTTP-facing side of sharing.
pub struct ShareRuntime {
    pub(crate) core: Arc<ShareCore>,
    sync: Arc<SyncShared>,
    service: Arc<Service>,
    net: Arc<NetRuntime>,
    log: Log,
    /// `received/` has the wrong owner or permissions: sharing is disabled.
    unusable: AtomicBool,
    /// Serializes open attempts per received wallet (002 unlock rule).
    attempts: Mutex<HashMap<[u8; 16], Arc<Mutex<()>>>>,
}

impl ShareRuntime {
    pub fn new(
        sync: Arc<SyncShared>,
        service: Arc<Service>,
        net: Arc<NetRuntime>,
        log: Log,
    ) -> Self {
        let core = Arc::clone(&sync.share);
        let unusable = core.received.prepare().is_err();
        Self {
            core,
            sync,
            service,
            net,
            log,
            unusable: AtomicBool::new(unusable),
            attempts: Mutex::new(HashMap::new()),
        }
    }

    pub fn core(&self) -> &Arc<ShareCore> {
        &self.core
    }

    pub fn received_unusable(&self) -> bool {
        self.unusable.load(Ordering::SeqCst)
    }

    /// `None` when sharing is available, else the reason.
    pub fn unavailable_reason(&self) -> Option<&'static str> {
        if !self.net.settings.enabled {
            Some("networking_off")
        } else if self.net.state() != NetState::On || !self.sync.active() {
            Some("network_unavailable")
        } else if self.received_unusable() {
            Some("received_unusable")
        } else {
            None
        }
    }

    fn available(&self) -> Result<(), ShareError> {
        match self.unavailable_reason() {
            None => Ok(()),
            Some(_) => Err(ShareError::NetworkingOff),
        }
    }

    fn pinned(&self, id: &DeviceId) -> bool {
        self.net
            .snapshot()
            .is_some_and(|s| s.paired.iter().any(|p| p.id == *id))
    }

    /// Runs `action` on the engine, then logs its events and wakes the sender thread.
    fn with_engine<T>(&self, action: impl FnOnce(&mut ShareEngine) -> T) -> T {
        let out = action(&mut self.core.engine());
        self.core.drain();
        self.sync.notify_work();
        out
    }

    /// The (unauthenticated) format version of the stored file `name` (1 or 2).
    fn format_of(&self, name: &WalletName) -> u16 {
        self.sync.file_format(name).unwrap_or(0)
    }

    /// `POST /api/wallets/{name}/share`.
    pub fn create(&self, name: &WalletName, recipient: &DeviceId) -> Result<(), ShareError> {
        self.available()?;
        match self.service.touch(name) {
            Ok(()) => {}
            Err(ServiceError::WalletNotFound) => return Err(ShareError::WalletNotFound),
            Err(ServiceError::WalletLocked) => return Err(ShareError::WalletLocked),
            Err(e) => return Err(ShareError::Service(e)),
        }
        if !self.pinned(recipient) {
            return Err(ShareError::DeviceNotFound);
        }
        if self.core.peer_share(recipient) == "unsupported" {
            return Err(ShareError::PeerUnsupported);
        }
        let Some((wallet_id, _)) = self.service.sync_facts(name) else {
            return Err(ShareError::WalletLocked);
        };
        let wallet = InviteWallet {
            name: name.to_string(),
            id: wallet_id,
            format: self.format_of(name),
        };
        let code = crate::qr::new_invite_code().ok_or(ShareError::Internal)?;
        self.with_engine(|engine| engine.create(wallet, peer_of(recipient), code))
            .map_err(|e| match e {
                CreateError::Ineligible(reason) => ShareError::NotEligible(reason.word()),
                CreateError::TooMany => ShareError::TooManyInvitations,
                CreateError::Busy => ShareError::Busy,
            })
    }

    /// `POST /api/share/accept`.
    pub fn accept(&self, recipient: &DeviceId) -> Result<(), ShareError> {
        let service = Arc::clone(&self.service);
        let eligible = move |name: &str| {
            WalletName::parse(name).is_ok_and(|n| service.sync_facts(&n).is_some())
        };
        self.with_engine(|engine| engine.accept(peer_of(recipient), &eligible))
            .map_err(|e| match e {
                AcceptError::NothingPending => ShareError::NothingPending,
                AcceptError::Mismatch => ShareError::Mismatch,
                AcceptError::Expired => ShareError::Expired,
                AcceptError::WalletLocked => ShareError::LockedCancelled,
                AcceptError::Busy => ShareError::Busy,
                AcceptError::SenderError => ShareError::SenderError,
            })
    }

    /// `POST /api/share/cancel`.
    pub fn cancel(&self) -> CancelOutcome {
        self.with_engine(ShareEngine::cancel)
    }

    /// `POST /api/share/reject`.
    pub fn reject(&self) -> Result<(), ShareError> {
        self.with_engine(ShareEngine::reject)
            .map_err(|_| ShareError::NothingPending)
    }

    /// `POST /api/receive/cancel`.
    pub fn cancel_redemption(&self) {
        self.with_engine(ShareEngine::cancel_redemption);
    }

    /// `POST /api/received/{id}/discard`.
    pub fn discard(&self, id: [u8; 16]) -> Result<(), ShareError> {
        let sender = self
            .with_engine(|engine| engine.discard(id))
            .map_err(|e| match e {
                DiscardError::NotFound => ShareError::ReceivedNotFound,
                DiscardError::Storage => ShareError::Service(ServiceError::Storage),
            })?;
        lock(&self.attempts).remove(&id);
        self.log.emit(&LogEvent::ReceivedDiscarded {
            fingerprint: &device(sender).fingerprint(),
            why: DiscardReason::Person,
        });
        Ok(())
    }

    /// `POST /api/share/notices/dismiss`.
    pub fn dismiss(&self, ids: &[u64]) {
        self.core.engine().dismiss(ids);
    }

    /// `POST /api/receive`: starts the redemption and opens the channel on a worker.
    pub fn redeem(
        self: &Arc<Self>,
        code: Zeroizing<String>,
        sender: Option<DeviceId>,
        hint: Option<SocketAddrV4>,
    ) -> Result<(), ShareError> {
        let own = self.net.this_device.as_ref().map(|d| d.id);
        if sender.is_some() && sender == own {
            return Err(ShareError::SelfDevice);
        }
        self.available()?;
        if let Some(id) = sender {
            if !self.pinned(&id) {
                return Err(ShareError::DeviceNotFound);
            }
        }
        let Some(opener) = self.net.opener() else {
            return Err(ShareError::NetworkingOff);
        };
        self.with_engine(|engine| engine.redeem(sender.map(|d| peer_of(&d)), code))
            .map_err(|e| match e {
                RedeemError::Busy => ShareError::Busy,
                RedeemError::ReceivedLimit => ShareError::ReceivedLimit,
            })?;
        let runtime = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("share-connect".into())
            .stack_size(WORKER_STACK)
            .spawn(move || {
                let outcome = opener.ensure_channel(sender, hint);
                runtime.with_engine(|engine| match outcome {
                    Ok((peer, conn)) => {
                        let version = runtime
                            .core
                            .conn_version(&peer, conn)
                            .or_else(|| runtime.net.channel_version(&peer));
                        if version == Some(HelloVersion::V3) {
                            engine.sender_channel(peer_of(&peer), conn);
                        } else {
                            engine.connect_failed(Failure::Unsupported);
                        }
                    }
                    Err(error) => engine.connect_failed(match error {
                        EnsureError::IdMismatch => Failure::IdMismatch,
                        EnsureError::SelfDevice => Failure::Invalid,
                        EnsureError::NotPaired
                        | EnsureError::Unreachable
                        | EnsureError::NetworkOff => Failure::Unreachable,
                    }),
                });
            });
        if spawned.is_err() {
            self.with_engine(|engine| engine.connect_failed(Failure::Unreachable));
        }
        Ok(())
    }

    /// `POST /api/received/{id}/open`.
    pub fn open(
        &self,
        id: [u8; 16],
        name: &str,
        password: Zeroizing<String>,
    ) -> Result<WalletName, ShareError> {
        let attempt = Arc::clone(lock(&self.attempts).entry(id).or_default());
        let _serialized = lock(&attempt);
        let received = &self.core.received;
        let meta = received
            .list()
            .ok()
            .and_then(|l| l.into_iter().find(|m| m.id == id))
            .ok_or(ShareError::ReceivedNotFound)?;
        let bytes = match received.read(id) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(StoreError::NotFound | StoreError::Corrupted) => {
                return Err(ShareError::ReceivedNotFound);
            }
            Err(_) => return Err(ShareError::Service(ServiceError::Storage)),
        };
        let facts_seen: Mutex<Option<UnlockFacts>> = Mutex::new(None);
        let existing: Mutex<Option<String>> = Mutex::new(None);
        let decide = |facts: &UnlockFacts| {
            *lock(&facts_seen) = Some(facts.clone());
            // FR-020: the same wallet (by wallet id) is already held here.
            match self
                .sync
                .held_wallet(&facts.wallet_id)
                .and_then(|n| WalletName::parse(&n).ok())
            {
                Some(held) => {
                    *lock(&existing) = Some(held.to_string());
                    AdoptVerdict::AlreadyPresent(held)
                }
                None => AdoptVerdict::Proceed,
            }
        };
        let adopted = self.service.adopt_received(name, &bytes, password, &decide);
        let wallet = match adopted {
            Ok(wallet) => wallet,
            Err(ServiceError::AlreadyPresent) => {
                let local = lock(&existing).take().unwrap_or_default();
                let _ = received.delete(id);
                lock(&self.attempts).remove(&id);
                self.log.emit(&LogEvent::ReceivedAlreadyPresent {
                    fingerprint: &device(meta.sender).fingerprint(),
                });
                self.core.engine().push_notice(NoticeKind::AlreadyPresent {
                    local_name: local.clone(),
                });
                // The held wallet now syncs with the sender as usual.
                self.sync.wallet_saved();
                return Err(ShareError::AlreadyPresent(local));
            }
            Err(e) => return Err(ShareError::Service(e)),
        };
        if let Some(facts) = lock(&facts_seen).take() {
            // The first 004 round with the sender then finds both equal (FR-021).
            self.sync
                .mark_received(&facts.wallet_id, meta.sender, &facts.state);
        }
        // A new wallet to sync: rounds start after the 004 quiet period (SC-005).
        self.sync.wallet_saved();
        let _ = received.delete(id);
        lock(&self.attempts).remove(&id);
        self.log.emit(&LogEvent::ReceivedOpened {
            fingerprint: &device(meta.sender).fingerprint(),
        });
        self.log.emit(&LogEvent::Unlocked { wallet: &wallet });
        Ok(wallet)
    }

    /// Start-up step 5e (contracts/host-runtime-share.md): deletes partial files, orphans,
    /// corrupted pairs, entries from unpinned senders, expired or future-dated entries, and the
    /// newest extras above 8. Each class is logged once with a count and shown as a notice.
    /// Never stops the service.
    pub fn startup_cleanup(&self) {
        if self.received_unusable() {
            return;
        }
        let received = &self.core.received;
        let Ok(scan) = received.scan() else {
            return;
        };
        let now = WallClock::unix_now(self.core.clock.as_ref());
        // Pins are known only while networking runs; otherwise that check waits.
        let pins: Option<HashSet<PeerId>> = self
            .net
            .snapshot()
            .map(|s| s.paired.iter().map(|p| peer_of(&p.id)).collect());
        let mut classes: Vec<(CleanClass, Vec<[u8; 16]>)> = vec![
            (CleanClass::Partial, scan.partial.clone()),
            (CleanClass::Orphan, scan.orphan.clone()),
            (CleanClass::Corrupted, scan.corrupted.clone()),
        ];
        let (mut unpinned, mut expired, mut kept) = (Vec::new(), Vec::new(), Vec::new());
        for meta in &scan.entries {
            if pins.as_ref().is_some_and(|p| !p.contains(&meta.sender)) {
                unpinned.push(meta.id);
            } else if meta.received_at.saturating_add(RECEIVED_RETENTION_SECS) <= now
                || meta.received_at > now.saturating_add(RECEIVED_FUTURE_SLACK_SECS)
            {
                expired.push(meta.id);
            } else {
                kept.push(meta.id);
            }
        }
        let excess = kept.split_off(kept.len().min(MAX_RECEIVED));
        classes.push((CleanClass::Unpinned, unpinned));
        classes.push((CleanClass::Expired, expired));
        classes.push((CleanClass::Excess, excess));
        for (class, ids) in classes {
            if ids.is_empty() {
                continue;
            }
            for id in &ids {
                received.remove_all(*id);
            }
            self.log.emit(&LogEvent::ReceivedCleaned {
                class,
                count: ids.len(),
            });
            self.core
                .engine()
                .push_notice(NoticeKind::ReceivedCleaned { count: ids.len() });
        }
    }

    /// Shutdown (before the 004 sync stops): aborts the exchange best effort, deletes a
    /// partial file, drops the invitation and wipes its code, releases transfer slots.
    pub fn shutdown(&self) {
        self.core.engine().shutdown();
        self.core.drain();
        self.core.flush();
        if let Ok(scan) = self.core.received.scan() {
            for id in scan.partial {
                self.core.received.remove_all(id);
            }
        }
    }

    /// A device was revoked (003): its invitation is cancelled, an exchange with it ends and
    /// its received wallets are deleted (FR-023).
    pub fn peer_revoked(&self, id: &DeviceId) {
        self.with_engine(|engine| engine.peer_revoked(peer_of(id)));
    }

    /// The `LockObserver` registered with the service (any lock cause, FR-009a).
    pub fn lock_observer(&self) -> Arc<dyn LockObserver> {
        Arc::new(ShareLockObserver {
            core: Arc::clone(&self.core),
            sync: Arc::clone(&self.sync),
        })
    }

    /// The sweeper tick hook.
    pub fn tick(&self) {
        self.core.tick();
        self.sync.notify_work();
    }

    /// Test hook: moves the share engine's clocks forward.
    pub fn advance_clock(&self, by: Duration) {
        self.core.clock.advance(by);
    }
}

impl ShareCore {
    pub(crate) fn conn_version(&self, peer: &DeviceId, conn: u64) -> Option<HelloVersion> {
        lock(&self.conn_versions).get(&(*peer, conn)).copied()
    }
}

/// Cancels a not-yet-transferring invitation for a wallet that was just locked.
struct ShareLockObserver {
    core: Arc<ShareCore>,
    sync: Arc<SyncShared>,
}

impl LockObserver for ShareLockObserver {
    fn locked(&self, name: &WalletName) {
        self.core.engine().wallet_locked(name.as_str());
        self.core.drain();
        self.sync.notify_work();
    }
}
