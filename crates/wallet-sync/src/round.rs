//! The sync engine: one round state machine per connected peer (contracts/sync-protocol.md
//! "Round"), sans-IO. Frames come in through [`Engine::on_frame`] and go out through
//! [`Engine::poll_outgoing`]; files and records go through the ports.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use rand_core::RngCore;
use vault_core::{StateVector, VersionOrdering, WalletId};

use crate::codec::{
    AbortReason, Ctl, MAX_COPY, MAX_FRAGMENT, MAX_TAGS, MIN_COPY, Reassembler, RefuseReason,
    decode, encode, fragment,
};
use crate::decide::{Decision, WantInput, decide};
use crate::error::ProtocolError;
use crate::ports::{
    MergeOutcome, MergeRequest, MonoClock, PeerId, SyncStore, WallClock, WalletSource,
};
use crate::record::{
    FileCheck, Outcome, PendingCopy, PendingStatus, Position, SyncRecord, WarningKind,
};
use crate::tags::{digest_matches, state_digest, tag, tag_matches};
use crate::transfer::{Incoming, ServeStep, Serving};

/// One frame of the peer channel's sync part (mirrors 003 v2 payloads 0x20 / 0x21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Ctl { more: bool, fragment: Vec<u8> },
    Data(Vec<u8>),
}

impl Frame {
    fn len(&self) -> u64 {
        match self {
            Self::Ctl { fragment, .. } => fragment.len() as u64 + 2,
            Self::Data(bytes) => bytes.len() as u64 + 1,
        }
    }
}

/// Outcome class of a round (log and per-peer status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundClass {
    Ok,
    Failed,
    Busy,
    Timeout,
    Protocol,
}

/// What happened, for the host's log and UI (local names only; ids never logged).
#[derive(Clone, PartialEq, Eq)]
pub enum SyncEvent {
    RoundStarted {
        peer: PeerId,
    },
    RoundEnded {
        peer: PeerId,
        class: RoundClass,
        sent: u64,
        received: u64,
    },
    PendingStored {
        wallet: WalletId,
        name: String,
        peer: PeerId,
    },
    OlderStateOffered {
        wallet: WalletId,
        name: String,
        peer: PeerId,
    },
    PossibleRollback {
        wallet: WalletId,
        name: String,
    },
    InvalidCopy {
        wallet: WalletId,
        name: String,
        peer: PeerId,
    },
    CannotOpen {
        wallet: WalletId,
        name: String,
        peer: PeerId,
    },
    Merged {
        wallet: WalletId,
        name: String,
        peer: PeerId,
        conflicts: u32,
    },
    SelfRollbackRecovered {
        wallet: WalletId,
        name: String,
        peer: PeerId,
    },
    /// A protocol error: the host closes this channel.
    CloseChannel {
        peer: PeerId,
        conn: u64,
    },
}

/// Shows the kind of event and the peer only (no wallet id or name).
impl std::fmt::Debug for SyncEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, peer) = match self {
            Self::RoundStarted { peer } => ("RoundStarted", peer),
            Self::RoundEnded { peer, .. } => ("RoundEnded", peer),
            Self::PendingStored { peer, .. } => ("PendingStored", peer),
            Self::OlderStateOffered { peer, .. } => ("OlderStateOffered", peer),
            Self::PossibleRollback { .. } => return f.write_str("PossibleRollback"),
            Self::InvalidCopy { peer, .. } => ("InvalidCopy", peer),
            Self::CannotOpen { peer, .. } => ("CannotOpen", peer),
            Self::Merged { peer, .. } => ("Merged", peer),
            Self::SelfRollbackRecovered { peer, .. } => ("SelfRollbackRecovered", peer),
            Self::CloseChannel { peer, .. } => ("CloseChannel", peer),
        };
        write!(f, "{kind}({peer:?})")
    }
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// No progress for this long fails a round (30 s).
    pub round_timeout: Duration,
    /// A round never lasts longer than this, progress or not (slow-loris bound; 64 MiB at
    /// 1 Mbit/s takes about 9 minutes).
    pub max_round: Duration,
    /// Transfers service-wide (2, FR-029).
    pub max_transfers: usize,
    /// Wallets per round (512, rotating window).
    pub window: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            round_timeout: Duration::from_secs(30),
            max_round: Duration::from_secs(15 * 60),
            max_transfers: 2,
            window: MAX_TAGS,
        }
    }
}

pub struct EngineDeps {
    pub store: Arc<dyn SyncStore>,
    pub source: Arc<dyn WalletSource>,
    pub mono: Arc<dyn MonoClock>,
    pub wall: Arc<dyn WallClock>,
    pub rng: Box<dyn RngCore + Send>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    Undecided,
    Wanted,
    Requested,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotOutcome {
    Normal,
    OlderStateOffered,
    Invalid,
}

/// One wallet of the round, addressed by its index in `Tags`.
struct Slot {
    wallet: Option<WalletId>,
    name: String,
    /// Our state and flag as summarized (initiator: as tagged).
    local: Option<(bool, StateVector)>,
    matched: bool,
    in_sync: bool,
    ours_sent: bool,
    theirs: Option<(bool, StateVector)>,
    want: Want,
    served: bool,
    outcome: SlotOutcome,
}

impl Slot {
    fn unmatched() -> Self {
        Self {
            wallet: None,
            name: String::new(),
            local: None,
            matched: false,
            in_sync: false,
            ours_sent: false,
            theirs: None,
            want: Want::Done,
            served: false,
            outcome: SlotOutcome::Normal,
        }
    }

    fn differs(&self) -> bool {
        self.matched && !self.in_sync
    }
}

struct Round {
    number: u32,
    initiator: bool,
    matched: bool,
    slots: Vec<Slot>,
    our_done: bool,
    peer_done: bool,
    /// Our `Want` in flight (holds a transfer slot until the copy ends or is refused).
    outstanding: Option<u16>,
    incoming: Option<Incoming>,
    serving: Option<Serving>,
    last_progress: Duration,
    started: Duration,
    sent: u64,
    received: u64,
}

/// Frames queued for one peer beyond this mean it does not read: the channel is closed.
const MAX_OUTBOX: usize = 256;
/// At most this many peers (the 003 pairing limit).
const MAX_LINKS: usize = 32;

struct Link {
    conn: u64,
    session: [u8; 32],
    dialer: bool,
    reasm: Reassembler,
    outbox: VecDeque<Frame>,
    round: Option<Round>,
    /// Highest round number used on this connection (either side).
    last_round: u32,
    closed: bool,
}

impl Link {
    fn send(&mut self, ctl: &Ctl) {
        for (more, fragment) in fragment(&encode(ctl)) {
            self.outbox.push_back(Frame::Ctl { more, fragment });
        }
    }
}

/// A syncable wallet as seen at the start of a round.
struct Syncable {
    wallet: WalletId,
    name: String,
    state: StateVector,
    no_offer: bool,
}

pub struct Engine {
    config: EngineConfig,
    store: Arc<dyn SyncStore>,
    source: Arc<dyn WalletSource>,
    mono: Arc<dyn MonoClock>,
    wall: Arc<dyn WallClock>,
    rng: Box<dyn RngCore + Send>,
    links: BTreeMap<PeerId, Link>,
    windows: BTreeMap<PeerId, usize>,
    transfers: usize,
    events: Vec<SyncEvent>,
    merges: VecDeque<MergeRequest>,
}

fn position(local: &StateVector, peer: &StateVector) -> Position {
    match local.compare(peer) {
        VersionOrdering::Equal => Position::InSync,
        VersionOrdering::Newer => Position::Ahead,
        VersionOrdering::Older => Position::Behind,
        VersionOrdering::Concurrent => Position::Diverged,
    }
}

impl Engine {
    pub fn new(deps: EngineDeps, config: EngineConfig) -> Self {
        Self {
            config,
            store: deps.store,
            source: deps.source,
            mono: deps.mono,
            wall: deps.wall,
            rng: deps.rng,
            links: BTreeMap::new(),
            windows: BTreeMap::new(),
            transfers: 0,
            events: Vec::new(),
            merges: VecDeque::new(),
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// A 53-bit random id (exact in JSON numbers).
    fn warning_id(&mut self) -> u64 {
        self.rng.next_u64() & ((1 << 53) - 1)
    }

    /// A sync-enabled channel came up (replacing any older one to the same peer).
    pub fn channel_up(&mut self, peer: PeerId, conn: u64, session: [u8; 32], dialer: bool) {
        if self.links.contains_key(&peer) {
            self.end_round(peer, RoundClass::Failed);
        } else if self.links.len() >= MAX_LINKS {
            return;
        }
        self.links.insert(
            peer,
            Link {
                conn,
                session,
                dialer,
                reasm: Reassembler::default(),
                outbox: VecDeque::new(),
                round: None,
                last_round: 0,
                closed: false,
            },
        );
    }

    /// The channel closed: a running round fails and its partial copy is deleted.
    pub fn channel_down(&mut self, peer: PeerId, conn: u64) {
        if self.links.get(&peer).is_some_and(|l| l.conn == conn) {
            self.end_round(peer, RoundClass::Failed);
            self.links.remove(&peer);
        }
    }

    pub fn connected(&self) -> Vec<PeerId> {
        self.links
            .iter()
            .filter(|(_, l)| !l.closed)
            .map(|(p, _)| *p)
            .collect()
    }

    pub fn round_running(&self, peer: PeerId) -> bool {
        self.links.get(&peer).is_some_and(|l| l.round.is_some())
    }

    /// Wallets matched in a running round (for the "syncing" status).
    pub fn syncing_wallets(&self) -> HashSet<WalletId> {
        self.links
            .values()
            .filter_map(|l| l.round.as_ref())
            .flat_map(|r| {
                r.slots
                    .iter()
                    .filter(|s| s.matched)
                    .filter_map(|s| s.wallet)
            })
            .collect()
    }

    pub fn take_events(&mut self) -> Vec<SyncEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn take_merge_requests(&mut self) -> Vec<MergeRequest> {
        self.merges.drain(..).collect()
    }

    /// Peers with frames waiting to be sent.
    pub fn outgoing_peers(&self) -> Vec<(PeerId, u64)> {
        self.links
            .iter()
            .filter(|(_, l)| {
                !l.outbox.is_empty() || l.round.as_ref().is_some_and(|r| r.serving.is_some())
            })
            .map(|(p, l)| (*p, l.conn))
            .collect()
    }

    /// Records not corrupted or disabled whose wallet file is present, sorted by wallet id.
    /// A file whose digest differs from its record is flagged "possible rollback" (FR-012).
    fn syncable(&mut self) -> Vec<Syncable> {
        let mut out = Vec::new();
        let Ok(wallets) = self.store.wallets() else {
            return out;
        };
        for wallet in wallets {
            let Ok(Some(record)) = self.store.load(&wallet) else {
                continue;
            };
            self.prune_dominated_pending(&record);
            if record.flags.disabled() {
                continue;
            }
            let Ok(Some(digest)) = self.source.digest(&record.wallet_name) else {
                continue;
            };
            let check = record.clone().check_file(Some(digest));
            if check == FileCheck::Changed && !record.flags.rollback_digest {
                self.flag_digest_rollback(&record);
            }
            out.push(Syncable {
                wallet,
                name: record.wallet_name.clone(),
                state: record.state.clone(),
                no_offer: record.flags.possible_rollback() || check != FileCheck::Unchanged,
            });
        }
        out
    }

    /// Pending copies that bring nothing the local state lacks are deleted (FR-029a).
    fn prune_dominated_pending(&mut self, record: &SyncRecord) {
        let stale: Vec<PeerId> = record
            .pending
            .iter()
            .filter(|(_, p)| record.state.dominates(&p.claimed))
            .map(|(peer, _)| *peer)
            .collect();
        if stale.is_empty() {
            return;
        }
        let updated = self.store.update(&record.wallet_id, &mut |r| {
            let mut r = r?;
            for peer in &stale {
                r.pending.remove(peer);
            }
            Some(r)
        });
        if updated.is_ok() {
            for peer in &stale {
                let _ = self.store.delete_pending(&record.wallet_id, peer);
            }
        }
    }

    fn flag_digest_rollback(&mut self, record: &SyncRecord) {
        let id = self.warning_id();
        let at = self.wall.unix_now();
        let _ = self.store.update(&record.wallet_id, &mut |r| {
            let mut r = r?;
            r.flags.rollback_digest = true;
            r.warn(id, WarningKind::PossibleRollback, None, at);
            Some(r)
        });
        self.events.push(SyncEvent::PossibleRollback {
            wallet: record.wallet_id,
            name: record.wallet_name.clone(),
        });
    }

    /// Starts a round with `peer` (one per peer). `false` when not connected, a round is
    /// running, or there is nothing to sync.
    pub fn start_round(&mut self, peer: PeerId) -> bool {
        let Some(link) = self.links.get(&peer) else {
            return false;
        };
        if link.round.is_some() || link.closed {
            return false;
        }
        let Some(number) = link.last_round.checked_add(1) else {
            return false;
        };
        let wallets = self.syncable();
        if wallets.is_empty() {
            return false;
        }
        let n = wallets.len();
        let k = n.min(self.config.window.min(MAX_TAGS));
        let offset = self.windows.get(&peer).copied().unwrap_or(0) % n;
        self.windows.insert(peer, (offset + k) % n);
        let now = self.mono.now();
        let Some(link) = self.links.get_mut(&peer) else {
            return false;
        };
        let role = if link.dialer { 0 } else { 1 };
        let mut entries = Vec::with_capacity(k);
        let mut slots = Vec::with_capacity(k);
        for i in 0..k {
            let w = &wallets[(offset + i) % n];
            entries.push((
                tag(&w.wallet, &link.session, number, role),
                state_digest(&w.wallet, &link.session, number, role, &w.state),
            ));
            let mut slot = Slot::unmatched();
            slot.wallet = Some(w.wallet);
            slot.name = w.name.clone();
            slot.local = Some((w.no_offer, w.state.clone()));
            slot.want = Want::Undecided;
            slots.push(slot);
        }
        link.last_round = number;
        link.send(&Ctl::Tags {
            round: number,
            entries,
        });
        link.round = Some(Round {
            number,
            initiator: true,
            matched: false,
            slots,
            our_done: false,
            peer_done: false,
            outstanding: None,
            incoming: None,
            serving: None,
            last_progress: now,
            started: now,
            sent: 0,
            received: 0,
        });
        self.events.push(SyncEvent::RoundStarted { peer });
        true
    }

    /// One frame from `peer` on connection `conn`.
    pub fn on_frame(&mut self, peer: PeerId, conn: u64, frame: Frame) {
        let Some(mut link) = self.links.remove(&peer) else {
            return;
        };
        if link.conn != conn || link.closed {
            self.links.insert(peer, link);
            return;
        }
        let size = frame.len();
        if let Some(round) = link.round.as_mut() {
            round.received += size;
            round.last_progress = self.mono.now();
        }
        let result = match frame {
            Frame::Ctl { more, fragment } => match link.reasm.push(more, &fragment) {
                Err(e) => Err(e),
                Ok(None) => Ok(()),
                Ok(Some(message)) => {
                    decode(&message).and_then(|ctl| self.handle_ctl(peer, &mut link, ctl))
                }
            },
            Frame::Data(bytes) => {
                if link.reasm.in_progress() || bytes.is_empty() || bytes.len() > MAX_FRAGMENT {
                    Err(ProtocolError)
                } else {
                    self.handle_data(peer, &mut link, &bytes)
                }
            }
        };
        let flooded = link.outbox.len() > MAX_OUTBOX;
        self.links.insert(peer, link);
        match result {
            Ok(()) if !flooded => self.evaluate(peer),
            _ => self.protocol_error(peer),
        }
    }

    fn protocol_error(&mut self, peer: PeerId) {
        self.end_round(peer, RoundClass::Protocol);
        if let Some(link) = self.links.get_mut(&peer) {
            link.closed = true;
            link.outbox.clear();
            link.reasm.reset();
            self.events.push(SyncEvent::CloseChannel {
                peer,
                conn: link.conn,
            });
        }
    }

    fn handle_ctl(&mut self, peer: PeerId, link: &mut Link, ctl: Ctl) -> Result<(), ProtocolError> {
        if let Ctl::Tags { round, entries } = ctl {
            return self.handle_tags(peer, link, round, entries);
        }
        let number = ctl.round();
        let Some(round) = link.round.as_mut() else {
            return Err(ProtocolError);
        };
        if round.number != number {
            return Err(ProtocolError);
        }
        match ctl {
            Ctl::Tags { .. } => Err(ProtocolError),
            Ctl::Busy { .. } => {
                if !round.initiator || round.matched {
                    return Err(ProtocolError);
                }
                self.finish_link_round(peer, link, RoundClass::Busy);
                Ok(())
            }
            Ctl::Matches { entries, .. } => Self::handle_matches(link, entries),
            Ctl::Summary {
                idx,
                no_offer,
                state,
                ..
            } => {
                let matched = round.matched;
                let slot = Self::slot_mut(round, idx)?;
                if !matched || !slot.differs() || slot.theirs.is_some() {
                    return Err(ProtocolError);
                }
                slot.theirs = Some((no_offer, state));
                Ok(())
            }
            Ctl::Want { idx, .. } => self.handle_want(link, idx),
            Ctl::Refuse { idx, .. } => {
                if round.outstanding != Some(idx) || round.incoming.is_some() {
                    return Err(ProtocolError);
                }
                round.outstanding = None;
                self.transfers = self.transfers.saturating_sub(1);
                Self::slot_mut(round, idx)?.want = Want::Done;
                Ok(())
            }
            Ctl::CopyStart { idx, size, .. } => self.handle_copy_start(peer, link, idx, size),
            Ctl::CopyEnd { idx, .. } => self.handle_copy_end(peer, link, idx),
            Ctl::CopyAbort { idx, .. } => {
                if round.outstanding == Some(idx) {
                    if let Some(mut incoming) = round.incoming.take() {
                        incoming.abort();
                    }
                    round.outstanding = None;
                    self.transfers = self.transfers.saturating_sub(1);
                    Self::slot_mut(round, idx)?.want = Want::Done;
                    Ok(())
                } else if round.serving.as_ref().is_some_and(|s| s.idx == idx) {
                    round.serving = None;
                    self.transfers = self.transfers.saturating_sub(1);
                    Ok(())
                } else {
                    Err(ProtocolError)
                }
            }
            Ctl::Done { .. } => {
                if round.peer_done || !round.matched {
                    return Err(ProtocolError);
                }
                round.peer_done = true;
                Ok(())
            }
        }
    }

    fn slot_mut(round: &mut Round, idx: u16) -> Result<&mut Slot, ProtocolError> {
        round.slots.get_mut(usize::from(idx)).ok_or(ProtocolError)
    }

    fn handle_tags(
        &mut self,
        _peer: PeerId,
        link: &mut Link,
        number: u32,
        entries: Vec<([u8; 16], [u8; 16])>,
    ) -> Result<(), ProtocolError> {
        if let Some(ours) = link.round.as_ref() {
            let simultaneous = ours.initiator && !ours.matched && ours.number == number;
            if simultaneous && link.dialer {
                return Ok(()); // our (the dialer's) round proceeds; the peer drops its own
            }
            if !simultaneous {
                link.send(&Ctl::Busy { round: number });
                return Ok(());
            }
            // The dialer's round wins: drop ours silently (nothing was exchanged yet; the
            // round we answer reports the outcome).
            link.round = None;
        } else if number <= link.last_round {
            return Err(ProtocolError);
        }
        link.last_round = link.last_round.max(number);
        let role = if link.dialer { 1 } else { 0 };
        let mut seen = HashSet::with_capacity(entries.len());
        if !entries.iter().all(|(t, _)| seen.insert(*t)) {
            return Err(ProtocolError);
        }
        let wallets = self.syncable();
        let by_tag: HashMap<[u8; 16], usize> = wallets
            .iter()
            .enumerate()
            .map(|(i, w)| (tag(&w.wallet, &link.session, number, role), i))
            .collect();
        let mut slots = Vec::with_capacity(entries.len());
        let mut matches = Vec::new();
        for (idx, (t, digest)) in entries.iter().enumerate() {
            let found = by_tag
                .get(t)
                .map(|i| &wallets[*i])
                .filter(|w| tag_matches(&w.wallet, &link.session, number, role, t));
            let Some(w) = found else {
                slots.push(Slot::unmatched());
                continue;
            };
            let in_sync = digest_matches(&w.wallet, &link.session, number, role, &w.state, digest);
            let idx = u16::try_from(idx).map_err(|_| ProtocolError)?;
            matches.push((idx, in_sync));
            slots.push(Slot {
                wallet: Some(w.wallet),
                name: w.name.clone(),
                local: Some((w.no_offer, w.state.clone())),
                matched: true,
                in_sync,
                ours_sent: false,
                theirs: None,
                want: if in_sync { Want::Done } else { Want::Undecided },
                served: false,
                outcome: SlotOutcome::Normal,
            });
        }
        link.send(&Ctl::Matches {
            round: number,
            entries: matches.clone(),
        });
        for (idx, in_sync) in matches {
            if in_sync {
                continue;
            }
            let slot = &mut slots[usize::from(idx)];
            if let Some((no_offer, state)) = slot.local.clone() {
                link.send(&Ctl::Summary {
                    round: number,
                    idx,
                    no_offer,
                    state,
                });
                slot.ours_sent = true;
            }
        }
        link.round = Some(Round {
            number,
            initiator: false,
            matched: true,
            slots,
            our_done: false,
            peer_done: false,
            outstanding: None,
            incoming: None,
            serving: None,
            last_progress: self.mono.now(),
            started: self.mono.now(),
            sent: 0,
            received: 0,
        });
        Ok(())
    }

    fn handle_matches(link: &mut Link, entries: Vec<(u16, bool)>) -> Result<(), ProtocolError> {
        let Some(round) = link.round.as_mut() else {
            return Err(ProtocolError);
        };
        if !round.initiator || round.matched {
            return Err(ProtocolError);
        }
        let mut seen = HashSet::with_capacity(entries.len());
        for (idx, in_sync) in &entries {
            let slot = Self::slot_mut(round, *idx)?;
            if !seen.insert(*idx) {
                return Err(ProtocolError);
            }
            slot.matched = true;
            slot.in_sync = *in_sync;
        }
        round.matched = true;
        let number = round.number;
        let mut summaries = Vec::new();
        for (i, slot) in round.slots.iter_mut().enumerate() {
            if !slot.matched {
                slot.want = Want::Done;
                continue;
            }
            if slot.in_sync {
                slot.want = Want::Done;
                continue;
            }
            if let Some((no_offer, state)) = slot.local.clone() {
                slot.ours_sent = true;
                summaries.push(Ctl::Summary {
                    round: number,
                    idx: i as u16,
                    no_offer,
                    state,
                });
            }
        }
        for summary in &summaries {
            link.send(summary);
        }
        Ok(())
    }

    fn handle_want(&mut self, link: &mut Link, idx: u16) -> Result<(), ProtocolError> {
        let Some(round) = link.round.as_mut() else {
            return Err(ProtocolError);
        };
        let number = round.number;
        if round.serving.is_some() {
            return Err(ProtocolError);
        }
        let slot = Self::slot_mut(round, idx)?;
        if !slot.differs() || !slot.ours_sent || slot.served {
            return Err(ProtocolError);
        }
        slot.served = true;
        let wallet = slot.wallet.ok_or(ProtocolError)?;
        let flagged_by_summary = slot.local.as_ref().is_some_and(|(no_offer, _)| *no_offer);
        let refuse = |link: &mut Link, reason| {
            link.send(&Ctl::Refuse {
                round: number,
                idx,
                reason,
            });
            Ok(())
        };
        if flagged_by_summary {
            return refuse(link, RefuseReason::NotOfferable);
        }
        // Only our own stored file, unchanged since its record was written (FR-006a).
        let record = match self.store.load(&wallet) {
            Ok(Some(r)) if !r.flags.possible_rollback() && !r.flags.disabled() => r,
            _ => return refuse(link, RefuseReason::NotOfferable),
        };
        match self.source.digest(&record.wallet_name) {
            Ok(Some(d)) if d == record.digest => {}
            Ok(_) => return refuse(link, RefuseReason::Changed),
            Err(_) => return refuse(link, RefuseReason::Storage),
        }
        if self.transfers >= self.config.max_transfers {
            return refuse(link, RefuseReason::Busy);
        }
        let Ok((size, reader)) = self.source.open(&record.wallet_name) else {
            return refuse(link, RefuseReason::Storage);
        };
        let Ok(size32) = u32::try_from(size) else {
            return refuse(link, RefuseReason::NotOfferable);
        };
        if !(MIN_COPY..=MAX_COPY).contains(&size32) {
            return refuse(link, RefuseReason::NotOfferable);
        }
        self.transfers += 1;
        link.send(&Ctl::CopyStart {
            round: number,
            idx,
            size: size32,
        });
        if let Some(round) = link.round.as_mut() {
            round.serving = Some(Serving::new(idx, size, reader, record.digest));
        }
        Ok(())
    }

    fn handle_copy_start(
        &mut self,
        peer: PeerId,
        link: &mut Link,
        idx: u16,
        size: u32,
    ) -> Result<(), ProtocolError> {
        let Some(round) = link.round.as_mut() else {
            return Err(ProtocolError);
        };
        if round.outstanding != Some(idx) || round.incoming.is_some() {
            return Err(ProtocolError);
        }
        let slot = Self::slot_mut(round, idx)?;
        let wallet = slot.wallet.ok_or(ProtocolError)?;
        let claimed = slot.theirs.as_ref().ok_or(ProtocolError)?.1.clone();
        match self.store.begin_incoming(&wallet, &peer) {
            Ok(writer) => {
                round.incoming = Some(Incoming {
                    idx,
                    wallet,
                    size: u64::from(size),
                    received: 0,
                    claimed,
                    writer: Some(writer),
                });
                Ok(())
            }
            Err(_) => {
                self.storage_failure(peer, link, idx);
                Ok(())
            }
        }
    }

    /// A store failure while receiving (e.g. disk full): nothing is kept, the round fails
    /// and is retried after the backoff (spec edge case "storage full").
    fn storage_failure(&mut self, peer: PeerId, link: &mut Link, idx: u16) {
        let number = link.round.as_ref().map_or(0, |r| r.number);
        link.send(&Ctl::CopyAbort {
            round: number,
            idx,
            reason: AbortReason::Storage,
        });
        self.finish_link_round(peer, link, RoundClass::Failed);
    }

    fn handle_data(
        &mut self,
        peer: PeerId,
        link: &mut Link,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        let Some(round) = link.round.as_mut() else {
            return Err(ProtocolError);
        };
        let Some(incoming) = round.incoming.as_mut() else {
            return Err(ProtocolError);
        };
        let received = incoming.received + bytes.len() as u64;
        if received > incoming.size {
            return Err(ProtocolError);
        }
        incoming.received = received;
        let idx = incoming.idx;
        let ok = incoming
            .writer
            .as_mut()
            .is_some_and(|w| w.append(bytes).is_ok());
        if !ok {
            if let Some(mut incoming) = round.incoming.take() {
                incoming.abort();
            }
            self.storage_failure(peer, link, idx);
        }
        Ok(())
    }

    fn handle_copy_end(
        &mut self,
        peer: PeerId,
        link: &mut Link,
        idx: u16,
    ) -> Result<(), ProtocolError> {
        let Some(round) = link.round.as_mut() else {
            return Err(ProtocolError);
        };
        let Some(mut incoming) = round.incoming.take() else {
            return Err(ProtocolError);
        };
        if incoming.idx != idx || incoming.received != incoming.size {
            return Err(ProtocolError);
        }
        round.outstanding = None;
        self.transfers = self.transfers.saturating_sub(1);
        Self::slot_mut(round, idx)?.want = Want::Done;
        let name = round.slots[usize::from(idx)].name.clone();
        let finished = incoming.writer.take().map(|w| w.finish());
        if !matches!(finished, Some(Ok(()))) {
            self.storage_failure(peer, link, idx);
            return Ok(());
        }
        let pending = PendingCopy {
            claimed: incoming.claimed.clone(),
            size: incoming.size,
            received_at: self.wall.unix_now(),
            status: PendingStatus::Waiting,
        };
        let mut peer_mark = None;
        let stored = self.store.update(&incoming.wallet, &mut |r| {
            let mut r = r?;
            peer_mark = r.peers.get(&peer).and_then(|p| p.peer_mark.clone());
            r.pending.insert(peer, pending.clone());
            Some(r)
        });
        if !matches!(stored, Ok(Some(_))) {
            let _ = self.store.delete_pending(&incoming.wallet, &peer);
            self.finish_link_round(peer, link, RoundClass::Failed);
            return Ok(());
        }
        self.events.push(SyncEvent::PendingStored {
            wallet: incoming.wallet,
            name: name.clone(),
            peer,
        });
        self.merges.push_back(MergeRequest {
            wallet: incoming.wallet,
            wallet_name: name,
            peer,
            claimed: incoming.claimed.clone(),
            peer_mark,
        });
        Ok(())
    }

    /// Decides wants, sends the next `Want`, `Done`, and ends the round when both are done.
    fn evaluate(&mut self, peer: PeerId) {
        let Some(mut link) = self.links.remove(&peer) else {
            return;
        };
        self.evaluate_link(peer, &mut link);
        self.links.insert(peer, link);
    }

    fn evaluate_link(&mut self, peer: PeerId, link: &mut Link) {
        let Some(round) = link.round.as_mut() else {
            return;
        };
        if !round.matched {
            return;
        }
        let number = round.number;
        let mut older = Vec::new();
        for slot in round.slots.iter_mut() {
            if slot.want != Want::Undecided || !slot.ours_sent {
                continue;
            }
            let (Some((no_offer, peer_state)), Some(wallet)) = (slot.theirs.as_ref(), slot.wallet)
            else {
                continue;
            };
            let Ok(Some(record)) = self.store.load(&wallet) else {
                slot.want = Want::Done;
                continue;
            };
            let mark = record.peers.get(&peer).and_then(|p| p.peer_mark.as_ref());
            let decision = decide(&WantInput {
                peer_state,
                no_offer: *no_offer,
                local_state: &record.state,
                peer_mark: mark,
                pending: record.pending.values().map(|p| &p.claimed).collect(),
                slot_free: true,
            });
            slot.want = match decision {
                Decision::Want => Want::Wanted,
                Decision::OlderStateOffered => {
                    slot.outcome = SlotOutcome::OlderStateOffered;
                    older.push((wallet, slot.name.clone()));
                    Want::Done
                }
                Decision::Invalid => {
                    slot.outcome = SlotOutcome::Invalid;
                    Want::Done
                }
                _ => Want::Done,
            };
        }
        if round.outstanding.is_none() && round.incoming.is_none() {
            if let Some(idx) = round.slots.iter().position(|s| s.want == Want::Wanted) {
                if self.transfers < self.config.max_transfers {
                    self.transfers += 1;
                    round.slots[idx].want = Want::Requested;
                    round.outstanding = Some(idx as u16);
                    link.send(&Ctl::Want {
                        round: number,
                        idx: idx as u16,
                    });
                } else {
                    // No free slot: retried in a later round (not a failure).
                    round.slots[idx].want = Want::Done;
                }
            }
        }
        let Some(round) = link.round.as_mut() else {
            return;
        };
        let waiting_for_summaries = round
            .slots
            .iter()
            .any(|s| s.differs() && s.ours_sent && s.theirs.is_none());
        let wants_left = round.slots.iter().any(|s| {
            matches!(s.want, Want::Wanted | Want::Requested | Want::Undecided) && s.differs()
        });
        let idle =
            round.outstanding.is_none() && round.incoming.is_none() && round.serving.is_none();
        if !round.our_done && !waiting_for_summaries && !wants_left && idle {
            round.our_done = true;
            link.send(&Ctl::Done { round: number });
        }
        for (wallet, name) in older {
            self.note_older_state(wallet, &name, peer);
        }
        let complete = link.round.as_ref().is_some_and(|r| {
            r.our_done
                && r.peer_done
                && r.outstanding.is_none()
                && r.incoming.is_none()
                && r.serving.is_none()
        });
        if complete {
            self.finish_link_round(peer, link, RoundClass::Ok);
        }
    }

    fn note_older_state(&mut self, wallet: WalletId, name: &str, peer: PeerId) {
        let id = self.warning_id();
        let at = self.wall.unix_now();
        let _ = self.store.update(&wallet, &mut |r| {
            let mut r = r?;
            r.warn(id, WarningKind::OlderStateOffered, Some(peer), at);
            let p = r.peer_mut(peer);
            p.last_outcome = Outcome::OlderStateOffered;
            p.position = Position::OlderStateOffered;
            Some(r)
        });
        self.events.push(SyncEvent::OlderStateOffered {
            wallet,
            name: name.to_string(),
            peer,
        });
    }

    /// Ends the round with `peer` (if any), cleaning up transfers and partial files.
    fn end_round(&mut self, peer: PeerId, class: RoundClass) {
        let Some(mut link) = self.links.remove(&peer) else {
            return;
        };
        self.finish_link_round(peer, &mut link, class);
        self.links.insert(peer, link);
    }

    fn finish_link_round(&mut self, peer: PeerId, link: &mut Link, class: RoundClass) {
        let Some(mut round) = link.round.take() else {
            return;
        };
        if let Some(mut incoming) = round.incoming.take() {
            incoming.abort();
        }
        if round.outstanding.take().is_some() {
            self.transfers = self.transfers.saturating_sub(1);
        }
        if round.serving.take().is_some() {
            self.transfers = self.transfers.saturating_sub(1);
        }
        let at = self.wall.unix_now();
        for slot in round.slots.iter().filter(|s| s.matched) {
            let Some(wallet) = slot.wallet else { continue };
            let local = slot.local.as_ref().map(|(_, s)| s.clone());
            let theirs = slot.theirs.as_ref().map(|(_, s)| s.clone());
            let in_sync = slot.in_sync;
            let outcome = slot.outcome;
            let _ = self.store.update(&wallet, &mut |r| {
                let mut r = r?;
                let p = r.peer_mut(peer);
                p.last_round_at = Some(at);
                match (outcome, class) {
                    (SlotOutcome::OlderStateOffered, _) => {
                        p.last_outcome = Outcome::OlderStateOffered;
                        p.position = Position::OlderStateOffered;
                    }
                    (SlotOutcome::Invalid, _) => {
                        p.last_outcome = Outcome::InvalidCopy;
                        p.position = Position::Error;
                    }
                    (_, RoundClass::Ok) => {
                        p.last_outcome = Outcome::Ok;
                        p.position = if in_sync {
                            Position::InSync
                        } else {
                            match (&local, &theirs) {
                                (Some(l), Some(t)) => position(l, t),
                                _ => Position::Unknown,
                            }
                        };
                    }
                    (_, RoundClass::Busy) => {}
                    _ => {
                        p.last_outcome = Outcome::Failed;
                        p.position = Position::Error;
                    }
                }
                Some(r)
            });
        }
        self.events.push(SyncEvent::RoundEnded {
            peer,
            class,
            sent: round.sent,
            received: round.received,
        });
    }

    /// Up to `max` frames for `peer`, pulling wallet bytes from a transfer being served.
    pub fn poll_outgoing(&mut self, peer: PeerId, max: usize) -> Vec<Frame> {
        let Some(mut link) = self.links.remove(&peer) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut serving_ended = false;
        while out.len() < max {
            if let Some(frame) = link.outbox.pop_front() {
                out.push(frame);
                continue;
            }
            let Some(round) = link.round.as_mut() else {
                break;
            };
            let Some(serving) = round.serving.as_mut() else {
                break;
            };
            let idx = serving.idx;
            let number = round.number;
            match serving.next() {
                ServeStep::Chunk(bytes) => out.push(Frame::Data(bytes)),
                step => {
                    round.serving = None;
                    self.transfers = self.transfers.saturating_sub(1);
                    serving_ended = true;
                    let ctl = match step {
                        ServeStep::End => Ctl::CopyEnd { round: number, idx },
                        ServeStep::Changed => Ctl::CopyAbort {
                            round: number,
                            idx,
                            reason: AbortReason::Changed,
                        },
                        _ => Ctl::CopyAbort {
                            round: number,
                            idx,
                            reason: AbortReason::ReadError,
                        },
                    };
                    link.send(&ctl);
                }
            }
        }
        if let Some(round) = link.round.as_mut() {
            if !out.is_empty() {
                round.sent += out.iter().map(Frame::len).sum::<u64>();
                round.last_progress = self.mono.now();
            }
        }
        self.links.insert(peer, link);
        if serving_ended {
            self.evaluate(peer);
            // Frames queued by the evaluation (e.g. `Done`) go out with the next poll.
        }
        out
    }

    /// Fails rounds without progress for `round_timeout`. Returns the next deadline.
    pub fn tick(&mut self) -> Option<Duration> {
        let now = self.mono.now();
        let timeout = self.config.round_timeout;
        let max_round = self.config.max_round;
        let expired: Vec<PeerId> = self
            .links
            .iter()
            .filter(|(_, l)| {
                l.round.as_ref().is_some_and(|r| {
                    now.saturating_sub(r.last_progress) >= timeout
                        || now.saturating_sub(r.started) >= max_round
                })
            })
            .map(|(p, _)| *p)
            .collect();
        for peer in expired {
            self.end_round(peer, RoundClass::Timeout);
        }
        self.links
            .values()
            .filter_map(|l| {
                l.round
                    .as_ref()
                    .map(|r| (r.last_progress + timeout).min(r.started + max_round))
            })
            .min()
    }

    /// The host merged (or tried to merge) a pending copy.
    pub fn merge_finished(&mut self, request: &MergeRequest, outcome: MergeOutcome) {
        let (wallet, peer, name) = (request.wallet, request.peer, request.wallet_name.clone());
        let id = self.warning_id();
        let at = self.wall.unix_now();
        let status = match outcome {
            MergeOutcome::Merged {
                conflicts,
                self_rollback,
                password_adopted,
            } => {
                self.events.push(SyncEvent::Merged {
                    wallet,
                    name: name.clone(),
                    peer,
                    conflicts,
                });
                if self_rollback || password_adopted {
                    let kind = if self_rollback {
                        WarningKind::SelfRollbackRecovered
                    } else {
                        WarningKind::PasswordAdopted
                    };
                    let _ = self.store.update(&wallet, &mut |r| {
                        let mut r = r?;
                        r.warn(id, kind, Some(peer), at);
                        Some(r)
                    });
                    if self_rollback {
                        self.events.push(SyncEvent::SelfRollbackRecovered {
                            wallet,
                            name: name.clone(),
                            peer,
                        });
                    }
                }
                return;
            }
            MergeOutcome::Unchanged | MergeOutcome::Locked | MergeOutcome::StorageFailed => return,
            MergeOutcome::CannotOpen => {
                self.events.push(SyncEvent::CannotOpen {
                    wallet,
                    name: name.clone(),
                    peer,
                });
                PendingStatus::CannotOpen
            }
            MergeOutcome::PasswordConflict => PendingStatus::PasswordConflict,
            MergeOutcome::TooManyConflicts => PendingStatus::TooManyConflicts,
            MergeOutcome::Invalid => {
                let _ = self.store.delete_pending(&wallet, &peer);
                let _ = self.store.update(&wallet, &mut |r| {
                    let mut r = r?;
                    r.pending.remove(&peer);
                    r.warn(id, WarningKind::InvalidCopy, Some(peer), at);
                    let p = r.peer_mut(peer);
                    p.last_outcome = Outcome::InvalidCopy;
                    p.position = Position::Error;
                    Some(r)
                });
                self.events
                    .push(SyncEvent::InvalidCopy { wallet, name, peer });
                return;
            }
        };
        let _ = self.store.update(&wallet, &mut |r| {
            let mut r = r?;
            if let Some(p) = r.pending.get_mut(&peer) {
                p.status = status;
            }
            match status {
                PendingStatus::CannotOpen => r.warn(id, WarningKind::CannotOpen, Some(peer), at),
                PendingStatus::TooManyConflicts => r.flags.too_many_conflicts = true,
                _ => {}
            }
            Some(r)
        });
    }

    /// Shutdown: every round is aborted (partial copies deleted) and every link dropped.
    pub fn abort_all(&mut self) {
        let peers: Vec<PeerId> = self.links.keys().copied().collect();
        for peer in peers {
            self.end_round(peer, RoundClass::Failed);
        }
        self.links.clear();
    }

    /// A peer was revoked (003): its rounds stop, its pending copies and peer lines go.
    pub fn revoke_peer(&mut self, peer: PeerId) {
        self.end_round(peer, RoundClass::Failed);
        self.links.remove(&peer);
        self.windows.remove(&peer);
        let Ok(wallets) = self.store.wallets() else {
            return;
        };
        for wallet in wallets {
            let _ = self.store.delete_pending(&wallet, &peer);
            let _ = self.store.update(&wallet, &mut |r| {
                let mut r = r?;
                let had = r.peers.remove(&peer).is_some() | r.pending.remove(&peer).is_some();
                let before = r.warnings.len();
                r.warnings.retain(|w| w.peer != Some(peer));
                (had || before != r.warnings.len()).then_some(r)
            });
        }
    }

    #[cfg(feature = "testkit")]
    pub fn transfers_active(&self) -> usize {
        self.transfers
    }
}
